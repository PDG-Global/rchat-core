//! Session-init packet (protocol v3 §A.4): the initiator's first relay
//! payload on a new circuit. It is a sealed envelope (`sealed.rs`) of kind
//! [`SESSION_INIT_TYPE`] whose plaintext is
//!
//! ```text
//! 0x08 || ct(1088) || confirm(32) || ratchet_message
//! ```
//!
//! - `ct` is the ML-KEM-768 ciphertext to the responder's ask KEM key;
//! - `confirm = HMAC-SHA256(HKDF(SK, "rchat/init-confirm/v3"), ct)`, so the
//!   responder knows it derived the same SK before it installs anything;
//! - `ratchet_message` is the initiator's first Double Ratchet message
//!   (`RatchetHeader || ciphertext`), a real message or a cover message.
//!
//! On the wire the bytes after the type byte travel as the sealed body,
//! padded to the ratchet buckets (`padding.rs`): a session-init lands in
//! the 4 KiB bucket.

use crate::crypto::RatchetHeader;
use crate::kem::KEM_CT_LEN;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Sealed kind and plaintext type of a session-init.
pub const SESSION_INIT_TYPE: u8 = 0x08;
/// HKDF info of the confirmation key.
pub const INIT_CONFIRM_INFO: &[u8] = b"rchat/init-confirm/v3";
/// Length of the confirmation tag.
pub const CONFIRM_LEN: usize = 32;
/// The smallest ratchet message: header, AEAD nonce (24) and tag (16).
pub const MIN_RATCHET_MSG_LEN: usize = RatchetHeader::LEN + 24 + 16;
/// The smallest well-formed session-init plaintext.
pub const MIN_SESSION_INIT_LEN: usize = 1 + KEM_CT_LEN + CONFIRM_LEN + MIN_RATCHET_MSG_LEN;

/// Why a session-init plaintext was refused. None carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionInitError {
    /// The first byte is not [`SESSION_INIT_TYPE`].
    #[error("not a session-init")]
    WrongType,
    /// Too short for `ct`, `confirm` and a ratchet message.
    #[error("session-init is truncated")]
    Truncated,
}

/// `HMAC-SHA256(HKDF-SHA256(salt = none, ikm = SK, info = "rchat/init-confirm/v3"), ct)`.
///
/// The `hmac` crate (0.12) implements no `Zeroize`, so the HMAC state,
/// which holds the key-derived pads, is built and dropped inside the
/// closure `with_hkdf` runs: that frame's stack is overwritten afterwards
/// (`scrub_stack`), as for the HKDF state. The derived key lives only in a
/// `Zeroizing` buffer. Best effort, like every stack wipe.
pub fn init_confirm(sk: &[u8; 32], ct: &[u8; KEM_CT_LEN]) -> [u8; 32] {
    crate::keyauth::with_hkdf(None, sk, |hk| {
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(INIT_CONFIRM_INFO, &mut key[..])
            .expect("32-byte HKDF output");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("any key length");
        mac.update(ct);
        mac.finalize().into_bytes().into()
    })
}

/// Whether `confirm` is the tag of `ct` under `sk` (constant time).
pub fn verify_init_confirm(sk: &[u8; 32], ct: &[u8; KEM_CT_LEN], confirm: &[u8; 32]) -> bool {
    let expected = Zeroizing::new(init_confirm(sk, ct));
    constant_time_eq::constant_time_eq(&expected[..], confirm)
}

/// `0x08 || ct || confirm || first_ratchet_msg` (unpadded).
pub fn build_session_init(
    sk: &[u8; 32],
    ct: &[u8; KEM_CT_LEN],
    first_ratchet_msg: &[u8],
) -> Vec<u8> {
    build_with_confirm(ct, &init_confirm(sk, ct), first_ratchet_msg)
}

/// [`build_session_init`] with a confirmation tag computed earlier (the
/// session keeps the tag, not SK).
pub(crate) fn build_with_confirm(
    ct: &[u8; KEM_CT_LEN],
    confirm: &[u8; 32],
    first_ratchet_msg: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + KEM_CT_LEN + CONFIRM_LEN + first_ratchet_msg.len());
    out.push(SESSION_INIT_TYPE);
    out.extend_from_slice(ct);
    out.extend_from_slice(confirm);
    out.extend_from_slice(first_ratchet_msg);
    out
}

/// Split a session-init plaintext into `(ct, confirm, ratchet_message)`.
/// Checks only the shape; the caller verifies `confirm` after deriving SK.
pub fn parse_session_init(
    pt: &[u8],
) -> Result<(&[u8; KEM_CT_LEN], &[u8; 32], &[u8]), SessionInitError> {
    match pt.first() {
        Some(&SESSION_INIT_TYPE) => {}
        Some(_) => return Err(SessionInitError::WrongType),
        None => return Err(SessionInitError::Truncated),
    }
    if pt.len() < MIN_SESSION_INIT_LEN {
        return Err(SessionInitError::Truncated);
    }
    let ct: &[u8; KEM_CT_LEN] = pt[1..1 + KEM_CT_LEN]
        .try_into()
        .map_err(|_| SessionInitError::Truncated)?;
    let confirm: &[u8; 32] = pt[1 + KEM_CT_LEN..1 + KEM_CT_LEN + CONFIRM_LEN]
        .try_into()
        .map_err(|_| SessionInitError::Truncated)?;
    Ok((ct, confirm, &pt[1 + KEM_CT_LEN + CONFIRM_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> Vec<u8> {
        (0..MIN_RATCHET_MSG_LEN + 5).map(|i| i as u8).collect()
    }

    #[test]
    fn session_init_round_trip() {
        let (sk, ct) = ([9u8; 32], [0x5au8; KEM_CT_LEN]);
        let pt = build_session_init(&sk, &ct, &msg());
        assert_eq!(pt[0], SESSION_INIT_TYPE);
        assert_eq!(pt.len(), 1 + KEM_CT_LEN + CONFIRM_LEN + msg().len());
        let (ct2, confirm, m) = parse_session_init(&pt).unwrap();
        assert_eq!(ct2, &ct);
        assert_eq!(m, &msg()[..]);
        assert!(verify_init_confirm(&sk, ct2, confirm));
    }

    /// The tag is HMAC-SHA256 under HKDF(SK, "rchat/init-confirm/v3"),
    /// rebuilt here from the primitives, and binds SK and ct.
    #[test]
    fn init_confirm_is_hmac_under_the_hkdf_key() {
        let (sk, ct) = ([3u8; 32], [4u8; KEM_CT_LEN]);
        let hk = hkdf::Hkdf::<Sha256>::new(None, &sk);
        let mut k = [0u8; 32];
        hk.expand(b"rchat/init-confirm/v3", &mut k).unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k).unwrap();
        mac.update(&ct);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(init_confirm(&sk, &ct), expected);
        let mut ct2 = ct;
        ct2[1087] ^= 1;
        assert_ne!(init_confirm(&sk, &ct2), expected, "ct is bound");
        assert_ne!(init_confirm(&[2u8; 32], &ct), expected, "SK is bound");
    }

    #[test]
    fn wrong_confirm_does_not_verify() {
        let (sk, ct) = ([9u8; 32], [0x5au8; KEM_CT_LEN]);
        let mut pt = build_session_init(&sk, &ct, &msg());
        pt[1 + KEM_CT_LEN] ^= 1;
        let (ct2, confirm, _) = parse_session_init(&pt).unwrap();
        assert!(!verify_init_confirm(&sk, ct2, confirm));
        let pt = build_session_init(&sk, &ct, &msg());
        let (ct2, confirm, _) = parse_session_init(&pt).unwrap();
        assert!(!verify_init_confirm(&[8u8; 32], ct2, confirm), "other SK");
    }

    #[test]
    fn truncated_and_mistyped_are_refused() {
        let pt = build_session_init(&[1; 32], &[2; KEM_CT_LEN], &msg());
        assert_eq!(parse_session_init(&[]), Err(SessionInitError::Truncated));
        for len in [1, 1 + KEM_CT_LEN, MIN_SESSION_INIT_LEN - 1] {
            assert_eq!(
                parse_session_init(&pt[..len]),
                Err(SessionInitError::Truncated),
                "{len} bytes"
            );
        }
        assert!(parse_session_init(&pt[..MIN_SESSION_INIT_LEN]).is_ok());
        let mut wrong = pt.clone();
        wrong[0] = 0x01;
        assert_eq!(parse_session_init(&wrong), Err(SessionInitError::WrongType));
    }
}
