//! Device key (spec §18.14, D42–D46): the per-install P-256 key that signs
//! session notices, so only the physical phone can trigger an automatic
//! resend (D38 guard 7).
//!
//! The private key never enters the core: the app signs through a
//! `DeviceSigner` (D45). The core only builds what is signed and verifies
//! the contact's signatures under the DK the user pinned by a scan or paste
//! (D44). Nothing here ever sets a DK pin.

/// Domain of the identity key's signature over the device key (D43).
pub const DK_DOMAIN: &[u8; 20] = b"rchat/device-key/v1\0";
/// Domain of the device key's signature over a session notice (D45).
pub const NOTICE_SIG_DOMAIN: &[u8; 24] = b"rchat/session-notice/v1\0";
/// Domain of the hash that binds a notice signature to one session (D45).
const SESSION_BINDING_DOMAIN: &[u8; 25] = b"rchat/session-binding/v1\0";

/// A contact's device key as pinned from their scanned card (D44): the
/// SEC1 uncompressed P-256 public key and whether it lives in secure hardware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePin {
    pub dk_pub: [u8; 65],
    pub hardware: bool,
}

/// Signs with this install's device key (D45). Called synchronously on the
/// core thread building a notice, with the client lock held: it must not
/// call back into rchat. `None` (no key, or the signature failed) sends
/// the notice unsigned, which never enables an automatic resend (D46).
pub trait DeviceSigner: Send + Sync {
    /// A raw `r || s` ECDSA P-256 SHA-256 signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Option<[u8; 64]>;
}

/// `SHA-256("rchat/session-binding/v1\0" || SK)`, where SK is the session's
/// X3DH v2 output. A hash, never SK itself: it is persisted with the session.
pub fn session_binding(sk: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SESSION_BINDING_DOMAIN);
    h.update(sk);
    h.finalize().into()
}

/// Whether `sig` is the pinned device key's signature over `tbs`. Low-S
/// and high-S forms both pass (S is normalised first: F17, D45); any other
/// failure, including a key or signature that does not parse, is false.
pub fn verify_notice(dk: &DevicePin, tbs: &[u8], sig: &[u8; 64]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let (Ok(key), Ok(sig)) = (
        VerifyingKey::from_sec1_bytes(&dk.dk_pub),
        Signature::from_slice(sig),
    ) else {
        return false;
    };
    // ecdsa 0.16 already accepts high-S for P-256; normalising keeps D45's
    // rule if a later version enforces low-S (DK9 pins the behaviour).
    let sig = sig.normalize_s().unwrap_or(sig);
    key.verify(tbs, &sig).is_ok()
}

/// Whether `dk_pub` is a valid SEC1 uncompressed P-256 point.
pub(crate) fn is_valid_dk_pub(dk_pub: &[u8; 65]) -> bool {
    dk_pub[0] == 0x04 && p256::PublicKey::from_sec1_bytes(dk_pub).is_ok()
}

#[cfg(test)]
pub(crate) mod test_keys {
    use super::*;
    use p256::ecdsa::SigningKey;

    /// A software device key from a one-byte seed, and its pin.
    pub(crate) fn soft_dk(seed: u8) -> (SigningKey, DevicePin) {
        let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
        let pub65: [u8; 65] = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        (
            sk,
            DevicePin {
                dk_pub: pub65,
                hardware: false,
            },
        )
    }

    /// A `DeviceSigner` backed by a software P-256 key (DK8, Task 8's
    /// callback stands in its place).
    pub(crate) struct SoftSigner(pub SigningKey);

    impl DeviceSigner for SoftSigner {
        fn sign(&self, msg: &[u8]) -> Option<[u8; 64]> {
            use p256::ecdsa::signature::Signer;
            let s: p256::ecdsa::Signature = self.0.sign(msg);
            Some(s.to_bytes().into())
        }
    }

    /// A signer whose key is missing: every notice goes out unsigned.
    pub(crate) struct FailingSigner;

    impl DeviceSigner for FailingSigner {
        fn sign(&self, _msg: &[u8]) -> Option<[u8; 64]> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature};

    /// DK1: binding round-trip against an independently built message
    /// (pins the format); every flipped field fails; a weak identity key is refused.
    #[test]
    fn dk1_binding_round_trip_and_format() {
        let id = crate::crypto::IdentityKeyPair::from_seed(&[0x31; 64]).unwrap();
        let ik = id.public_signing_key().to_bytes();
        let (_, pin) = soft_dk(7);
        let sig = crate::keyauth::sign_device_key(&id, &pin.dk_pub, false).unwrap();
        // Format: DK_DOMAIN || ik || dk_pub || 0, verified with dalek directly.
        let mut msg = DK_DOMAIN.to_vec();
        msg.extend_from_slice(&ik);
        msg.extend_from_slice(&pin.dk_pub);
        msg.push(0);
        assert_eq!(msg.len(), 118);
        id.public_signing_key()
            .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("exact message format");
        assert!(crate::keyauth::verify_device_key(&ik, &pin.dk_pub, false, &sig).is_ok());
        assert!(
            crate::keyauth::verify_device_key(&ik, &pin.dk_pub, true, &sig).is_err(),
            "hardware flag is signed"
        );
        let mut bad = pin.dk_pub;
        bad[10] ^= 1;
        assert!(crate::keyauth::verify_device_key(&ik, &bad, false, &sig).is_err());
        let mut bad_sig = sig;
        bad_sig[3] ^= 1;
        assert!(crate::keyauth::verify_device_key(&ik, &pin.dk_pub, false, &bad_sig).is_err());
        let mut weak = [0u8; 32];
        weak[0] = 1; // the identity point: a weak key
        assert!(crate::keyauth::verify_device_key(&weak, &pin.dk_pub, false, &sig).is_err());
        // Golden vector: Ed25519 is deterministic, so the fixed seed and DK
        // give exactly this signature.
        assert_eq!(hex::encode(sig), DK1_GOLDEN_SIG);
        // The hardware flag set gives a different, valid binding.
        let hw = crate::keyauth::sign_device_key(&id, &pin.dk_pub, true).unwrap();
        assert_ne!(hw, sig);
        assert!(crate::keyauth::verify_device_key(&ik, &pin.dk_pub, true, &hw).is_ok());
    }

    const DK1_GOLDEN_SIG: &str = "94d08fae4ad840932f9b19f55f0e8dad6849c28f991a70c1073455e6bdfef4b8411f8065f543de2404343a0df70a918a0391934f0cbb7d4d68692f4440ac3a0e";

    /// A DK that is not a P-256 point is neither signed nor verified.
    #[test]
    fn invalid_device_keys_are_refused() {
        let id = crate::crypto::IdentityKeyPair::from_seed(&[0x31; 64]).unwrap();
        let ik = id.public_signing_key().to_bytes();
        let (_, pin) = soft_dk(7);
        let sig = crate::keyauth::sign_device_key(&id, &pin.dk_pub, false).unwrap();
        let mut compressed_tag = pin.dk_pub;
        compressed_tag[0] = 0x02;
        let off_curve = {
            let mut k = pin.dk_pub;
            k[64] ^= 1;
            k
        };
        assert!(crate::keyauth::verify_device_key(&ik, &pin.dk_pub, false, &sig).is_ok());
        for bad in [[0u8; 65], compressed_tag, off_curve] {
            assert!(crate::keyauth::sign_device_key(&id, &bad, false).is_err());
            // A binding the identity really signed over the bad key: still refused.
            let forged = id
                .sign(&crate::keyauth::dk_bind_msg(&ik, &bad, false))
                .to_bytes();
            assert!(crate::keyauth::verify_device_key(&ik, &bad, false, &forged).is_err());
            let p = DevicePin {
                dk_pub: bad,
                hardware: false,
            };
            assert!(!verify_notice(&p, b"tbs", &[1; 64]));
        }
    }

    /// DK8: a software DK signs and verifies a notice.
    #[test]
    fn dk8_software_key_signs_and_verifies() {
        let (sk, pin) = soft_dk(9);
        let sig: Signature = sk.sign(b"tbs");
        assert!(!pin.hardware);
        assert!(verify_notice(&pin, b"tbs", &sig.to_bytes().into()));
        assert!(!verify_notice(&pin, b"other", &sig.to_bytes().into()));
        // Through the signer trait, as the core uses it.
        let raw = SoftSigner(sk).sign(b"tbs").unwrap();
        assert!(verify_notice(&pin, b"tbs", &raw));
        let (_, other) = soft_dk(10);
        assert!(!verify_notice(&other, b"tbs", &raw), "another key");
        assert!(!verify_notice(&pin, b"tbs", &[0; 64]), "zero r and s");
    }

    /// DK9: low-S and high-S forms of one signature both verify (F17).
    #[test]
    fn dk9_low_and_high_s_both_verify() {
        let (sk, pin) = soft_dk(5);
        let sig: Signature = sk.sign(b"tbs");
        let low = sig.normalize_s().unwrap_or(sig);
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap(); // s' = n - s
        assert!(high.normalize_s().is_some(), "really the high-S form");
        for form in [low, high] {
            assert!(verify_notice(&pin, b"tbs", &form.to_bytes().into()));
            assert!(!verify_notice(&pin, b"other", &form.to_bytes().into()));
        }
    }

    /// The binding is a domain-separated hash of SK, different per SK.
    #[test]
    fn session_binding_is_a_domain_separated_hash() {
        use sha2::{Digest, Sha256};
        let mut expected = Sha256::new();
        expected.update(b"rchat/session-binding/v1\0");
        expected.update([7u8; 32]);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(session_binding(&[7; 32]), expected);
        assert_ne!(session_binding(&[7; 32]), session_binding(&[8; 32]));
        assert_ne!(session_binding(&[7; 32]), [7; 32]);
    }
}
