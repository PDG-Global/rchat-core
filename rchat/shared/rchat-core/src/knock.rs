//! Knocks and intros (spec §6.3, §6.5): a fixed-size sealed request whose
//! sender is authenticated by a deniable MAC, optionally carrying a short
//! first message readable only by the recipient. Knock v3 (protocol v3
//! §A.5, ruling R10): 5120 bytes, version byte 0x03, sealed in the hybrid
//! knock envelope (`sealed::seal_knock_with`, `ct_k` in its clear header).
//! The knock keys combine the static X25519 DH with the same `ss_k`: that
//! is defence in depth and binds `ct_k`, not post-quantum sender
//! authentication (anyone can encapsulate to the recipient).

use crate::crypto::IdentityKeyPair;
use crate::kem::{KEM_CT_LEN, KEM_PK_LEN};
use crate::keyauth::{self, KeyAuthError, KnockRole, SignedBundle};
use crate::rotation::{self, RotationBlock};
use crate::sealed::{self, OpenedKnock, KNOCK_INNER_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ak(32), kem_pk(1184), sig(64), issued_hour(8), mac(32) and
/// flags(1) (`FLAG_INTRO`, `FLAG_NO_PRIOR_SESSION`), 1321 bytes: the sender's whole v3 bundle, so its
/// signature can be checked. (`ct_k` is in the envelope's clear header.)
pub const KNOCK_FIXED_LEN: usize = 32 + KEM_PK_LEN + 64 + 8 + 32 + 1;
const KEM_END: usize = 32 + KEM_PK_LEN;
const SIG_END: usize = KEM_END + 64;
const HOUR_END: usize = SIG_END + 8;
const MAC_END: usize = HOUR_END + 32;
/// Knock body length: the inner plaintext minus sender(32) and kind(1),
/// 3943 - 33 = 3910.
pub const KNOCK_BODY_LEN: usize = KNOCK_INNER_LEN - 33;
pub const MAX_INTRO_BYTES: usize = 1024;
/// Flags byte: an intro block follows the fixed part.
pub const FLAG_INTRO: u8 = 0x01;
/// Flags byte (ruling R35): the sender holds no session with the recipient
/// (first contact, a reinstall, a new identity after rotation). Covered by
/// the knock MAC (`keyauth::knock_mac_flagged`), so the relay cannot set or
/// clear it. The recipient re-pairs on the identity path for a pinned
/// contact's knock at most once per pair per 24 h, flagged or not (R35,
/// M-1); the flag tells it why the sender asks.
pub const FLAG_NO_PRIOR_SESSION: u8 = 0x02;
const INTRO_HEADER_LEN: usize = 24 + 2;
const INTRO_PT_FIXED: usize = 16 + 8 + 2;
/// Start of the reserved rotation block at the end of the knock body (spec
/// §4.8): 3910 - 594 = 3316. The fixed part and the largest intro block
/// end at 1321 + 1092 = 2413, so 903 bytes of zero padding sit between.
pub const ROTATION_TAIL_OFFSET: usize = KNOCK_BODY_LEN - rotation::BLOCK_LEN;
const MAX_INTRO_BLOCK: usize = INTRO_HEADER_LEN + INTRO_PT_FIXED + MAX_INTRO_BYTES + 16;
const _: () = assert!(KNOCK_FIXED_LEN + MAX_INTRO_BLOCK <= ROTATION_TAIL_OFFSET);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KnockError {
    #[error("malformed knock")]
    Malformed,
    #[error("knock authentication failed")]
    Auth(#[from] KeyAuthError),
    #[error("sealing failed")]
    Seal(#[from] sealed::SealError),
    #[error("knock is outside its validity window")]
    Stale,
    #[error("intro text must be 1..=1024 bytes of UTF-8 without NUL")]
    BadIntro,
    #[error("invalid rotation block")]
    BadRotation,
    /// The recipient's pinned ML-KEM key is not a valid ML-KEM-768 key.
    #[error("invalid recipient ML-KEM key")]
    BadKemKey,
}

/// A first message carried by a knock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intro {
    pub message_id: [u8; 16],
    pub sent_at_ms: u64,
    pub text: String,
}

impl Intro {
    pub fn validate_text(text: &str) -> Result<(), KnockError> {
        if text.is_empty() || text.len() > MAX_INTRO_BYTES || text.contains('\0') {
            return Err(KnockError::BadIntro);
        }
        Ok(())
    }
}

/// A verified knock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKnock {
    pub sender: SignedBundle,
    pub issued_hour: u64,
    pub intro: Option<Intro>,
    /// A rotation chain in the knock's tail (spec §4.8). Not covered by the
    /// knock MAC: it proves itself (signatures from the old key, ending at
    /// the sender's verified bundle keys) or is ignored. The tail is still
    /// inside the sealed envelope, whose AEAD key comes from `env_eph`, so
    /// the relay can't alter it without the whole knock failing to open.
    pub rotation: Option<RotationBlock>,
    /// `FLAG_NO_PRIOR_SESSION` was set (MAC-covered, R35).
    pub no_prior_session: bool,
}

/// Build a knock payload (always `KNOCK_PAYLOAD_LEN` bytes). The envelope
/// message id is fresh and independent of any intro id (L10). The knock
/// keys need `recipient_kem_pk`, the recipient's static ML-KEM key from
/// its pinned card: there is no X25519-only knock (§A.5).
// Global Constraints exception: validating constructor (fixed-size fields).
#[allow(clippy::too_many_arguments)]
pub fn build_knock(
    me: &IdentityKeyPair,
    my_bundle: &SignedBundle,
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    recipient_kem_pk: &[u8; KEM_PK_LEN],
    issued_hour: u64,
    intro: Option<&Intro>,
    rotation: Option<&RotationBlock>,
    no_prior_session: bool,
) -> Result<Vec<u8>, KnockError> {
    let env_eph = StaticSecret::random_from_rng(OsRng);
    let mut env_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut env_nonce);
    let mut message_id = [0u8; 16];
    OsRng.fill_bytes(&mut message_id);
    let mut intro_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut intro_nonce);
    let (kem_ct, kem_ss) =
        crate::kem::encapsulate(&recipient_kem_pk[..]).map_err(|_| KnockError::BadKemKey)?;
    build_knock_with(
        me,
        my_bundle,
        recipient_identity_key,
        recipient_agreement_key,
        issued_hour,
        intro,
        &env_eph,
        env_nonce,
        message_id,
        intro_nonce,
        &kem_ct,
        &kem_ss,
        rotation,
        no_prior_session,
    )
}

/// Deterministic form of `build_knock` (tests and vectors): the caller
/// supplies the encapsulation (`kem_ct`, `kem_ss`) to the recipient's key.
// Global Constraints exception: validating constructor (every input is a
// checked, fixed-size field); the only permitted new `allow` besides `sealed::seal_with`.
#[allow(clippy::too_many_arguments)]
pub fn build_knock_with(
    me: &IdentityKeyPair,
    my_bundle: &SignedBundle,
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    issued_hour: u64,
    intro: Option<&Intro>,
    env_eph: &StaticSecret,
    env_nonce: [u8; 24],
    message_id: [u8; 16],
    intro_nonce: [u8; 24],
    kem_ct: &[u8; KEM_CT_LEN],
    kem_ss: &[u8; 32],
    rotation: Option<&RotationBlock>,
    no_prior_session: bool,
) -> Result<Vec<u8>, KnockError> {
    let env_eph_pub = X25519PublicKey::from(env_eph).to_bytes();
    let keys = keyauth::knock_keys_v3(
        me.agreement_secret(),
        recipient_agreement_key,
        &env_eph_pub,
        kem_ss,
        &my_bundle.identity_key,
        recipient_identity_key,
        KnockRole::Sender,
    )?;
    let session_flag = if no_prior_session {
        FLAG_NO_PRIOR_SESSION
    } else {
        0
    };
    let mac = keyauth::knock_mac_flagged(
        &keys.k_mac,
        recipient_identity_key,
        my_bundle,
        issued_hour,
        session_flag,
    )?;
    let mut body = Vec::with_capacity(KNOCK_BODY_LEN);
    body.extend_from_slice(&my_bundle.identity_agreement_key);
    body.extend_from_slice(&my_bundle.kem_pk[..]);
    body.extend_from_slice(&my_bundle.bundle_signature);
    body.extend_from_slice(&issued_hour.to_be_bytes());
    body.extend_from_slice(&mac);
    match intro {
        None => body.push(session_flag),
        Some(intro) => {
            Intro::validate_text(&intro.text)?;
            body.push(FLAG_INTRO | session_flag);
            // Wiped on drop (final review L6); sized exactly, so it never
            // reallocates and leaves no copy behind.
            let mut pt =
                zeroize::Zeroizing::new(Vec::with_capacity(INTRO_PT_FIXED + intro.text.len()));
            pt.extend_from_slice(&intro.message_id);
            pt.extend_from_slice(&intro.sent_at_ms.to_be_bytes());
            pt.extend_from_slice(&(intro.text.len() as u16).to_be_bytes());
            pt.extend_from_slice(intro.text.as_bytes());
            let ct = XChaCha20Poly1305::new_from_slice(&keys.k_intro)
                .map_err(|_| KnockError::Malformed)?
                .encrypt(
                    XNonce::from_slice(&intro_nonce),
                    Payload {
                        msg: &pt,
                        aad: &intro_aad(&my_bundle.identity_key, recipient_identity_key, &mac),
                    },
                )
                .map_err(|_| KnockError::Malformed)?;
            body.extend_from_slice(&intro_nonce);
            body.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            body.extend_from_slice(&ct);
        }
    }
    body.resize(KNOCK_BODY_LEN, 0);
    if let Some(block) = rotation {
        let raw = block.encode().map_err(|_| KnockError::BadRotation)?;
        body[ROTATION_TAIL_OFFSET..].copy_from_slice(&raw);
    }
    Ok(sealed::seal_knock_with(
        env_eph,
        env_nonce,
        message_id,
        recipient_agreement_key,
        kem_ct,
        kem_ss,
        &my_bundle.identity_key,
        &body,
    )?)
}

fn intro_aad(sender: &[u8; 32], recipient: &[u8; 32], mac: &[u8; 32]) -> [u8; 96] {
    let mut a = [0u8; 96];
    a[..32].copy_from_slice(sender);
    a[32..64].copy_from_slice(recipient);
    a[64..].copy_from_slice(mac);
    a
}

/// Verify an opened knock addressed to `me`. Freshness (L2): issued at most
/// one hour in the future and at most `knock_ttl_hours + 1` in the past. A
/// bad intro is dropped (returned as `None`); the request survives.
/// `want_intro`: decrypt the intro (spec §6.3: only for a sender who isn't
/// pinned; a contact's intro is never opened, Task 15 minor).
/// Consumes `opened`, so its `ss_k` is wiped once both key derivations
/// (the envelope's in `open_knock`, the knock keys here) are done.
pub fn parse_knock(
    me: &IdentityKeyPair,
    opened: OpenedKnock,
    now_hour: u64,
    knock_ttl_hours: u32,
    want_intro: bool,
) -> Result<ParsedKnock, KnockError> {
    let OpenedKnock {
        env_eph_pub,
        sender_identity_key,
        body,
        kem_ss,
        ..
    } = opened;
    if body.len() < KNOCK_FIXED_LEN {
        return Err(KnockError::Malformed);
    }
    let b = &body;
    let sender = SignedBundle::from_wire(
        &sender_identity_key,
        &b[0..32],
        &b[32..KEM_END],
        &b[KEM_END..SIG_END],
    )?;
    let issued_hour = u64::from_be_bytes(
        b[SIG_END..HOUR_END]
            .try_into()
            .map_err(|_| KnockError::Malformed)?,
    );
    let mac: [u8; 32] = b[HOUR_END..MAC_END]
        .try_into()
        .map_err(|_| KnockError::Malformed)?;
    let flag = b[MAC_END];
    keyauth::verify_bundle(&sender)?;
    let my_ik = me.public_signing_key().to_bytes();
    let keys = keyauth::knock_keys_v3(
        me.agreement_secret(),
        &sender.identity_agreement_key,
        &env_eph_pub,
        &kem_ss,
        &sender.identity_key,
        &my_ik,
        KnockRole::Recipient,
    )?;
    // Both derivations that use `ss_k` are done: wipe it now.
    drop(kem_ss);
    if flag & !(FLAG_INTRO | FLAG_NO_PRIOR_SESSION) != 0 {
        return Err(KnockError::Malformed);
    }
    let session_flag = flag & FLAG_NO_PRIOR_SESSION;
    keyauth::verify_knock_mac_flagged(
        &keys.k_mac,
        &my_ik,
        &sender,
        issued_hour,
        session_flag,
        &mac,
    )?;
    if issued_hour > now_hour + 1
        || now_hour.saturating_sub(issued_hour) > u64::from(knock_ttl_hours) + 1
    {
        return Err(KnockError::Stale);
    }
    let intro = match flag & FLAG_INTRO {
        FLAG_INTRO if want_intro => open_intro(
            &keys.k_intro,
            &sender.identity_key,
            &my_ik,
            &mac,
            &b[KNOCK_FIXED_LEN..],
        ),
        _ => None,
    };
    let rotation = b
        .get(ROTATION_TAIL_OFFSET..KNOCK_BODY_LEN)
        .and_then(|tail| RotationBlock::decode(tail).ok().flatten());
    Ok(ParsedKnock {
        sender,
        issued_hour,
        intro,
        rotation,
        no_prior_session: session_flag != 0,
    })
}

fn open_intro(
    k_intro: &[u8; 32],
    sender: &[u8; 32],
    recipient: &[u8; 32],
    mac: &[u8; 32],
    block: &[u8],
) -> Option<Intro> {
    if block.len() < INTRO_HEADER_LEN {
        return None;
    }
    let nonce = &block[..24];
    let ct_len = u16::from_be_bytes([block[24], block[25]]) as usize;
    let ct = block.get(INTRO_HEADER_LEN..INTRO_HEADER_LEN + ct_len)?;
    // Wiped on drop, on every path (final review L6).
    let pt = zeroize::Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(k_intro)
            .ok()?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &intro_aad(sender, recipient, mac),
                },
            )
            .ok()?,
    );
    if pt.len() < INTRO_PT_FIXED {
        return None;
    }
    let message_id: [u8; 16] = pt[..16].try_into().ok()?;
    let sent_at_ms = u64::from_be_bytes(pt[16..24].try_into().ok()?);
    let text_len = u16::from_be_bytes([pt[24], pt[25]]) as usize;
    if text_len == 0 || text_len > MAX_INTRO_BYTES || pt.len() != INTRO_PT_FIXED + text_len {
        return None;
    }
    // Checked in place: a failed `String::from_utf8` would drop its own
    // unwiped copy. The one copy made is the text handed to the app.
    let text = std::str::from_utf8(&pt[INTRO_PT_FIXED..]).ok()?.to_owned();
    if text.contains('\0') {
        return None;
    }
    Some(Intro {
        message_id,
        sent_at_ms,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyauth::{golden, sign_bundle};
    use crate::sealed::{OpenedKnock, KNOCK_CT_OFFSET, KNOCK_NONCE_OFFSET, KNOCK_PAYLOAD_LEN};

    /// Open knock `k` as `b` (knock envelopes are consumed by `parse_knock`).
    fn op(b: &IdentityKeyPair, k: &[u8]) -> OpenedKnock {
        sealed::open_knock(b.agreement_secret(), b.kem(), k).unwrap()
    }

    fn ab() -> (IdentityKeyPair, SignedBundle, IdentityKeyPair, SignedBundle) {
        let a = IdentityKeyPair::from_seed(&golden::seed_a()).unwrap();
        let b = IdentityKeyPair::from_seed(&golden::seed_b()).unwrap();
        let (ba, bb) = (sign_bundle(&a).unwrap(), sign_bundle(&b).unwrap());
        (a, ba, b, bb)
    }

    /// N13 (L3, L10): every knock is exactly `KNOCK_PAYLOAD_LEN` (5120) bytes,
    /// with or without an intro, and the envelope id is never the intro id.
    #[test]
    fn n13_knock_is_fixed_size_and_ids_are_independent() {
        let (a, ba, _b, bb) = ab();
        let plain = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            None,
            None,
            false,
        )
        .unwrap();
        let intro = Intro {
            message_id: [9; 16],
            sent_at_ms: 1_700_000_000_000,
            text: "x".repeat(MAX_INTRO_BYTES),
        };
        let with = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            Some(&intro),
            None,
            false,
        )
        .unwrap();
        assert_eq!(plain.len(), KNOCK_PAYLOAD_LEN);
        assert_eq!(with.len(), KNOCK_PAYLOAD_LEN);
        assert_ne!(&with[1..17], &intro.message_id[..]);
    }

    #[test]
    fn knock_round_trip_and_freshness_window() {
        let (a, ba, b, bb) = ab();
        let intro = Intro {
            message_id: [3; 16],
            sent_at_ms: 42,
            text: "hello".into(),
        };
        let k = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            Some(&intro),
            None,
            false,
        )
        .unwrap();
        let p = parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR, 72, true).unwrap();
        assert_eq!(p.sender, ba);
        assert_eq!(p.intro, Some(intro));
        // Task 15 minor: a contact's intro is not opened at all.
        let contact = parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR, 72, false).unwrap();
        assert_eq!(contact.intro, None);
        assert_eq!(contact.sender, ba, "the knock itself still verifies");
        // L2: one hour of future skew allowed, ttl + 1 hours of age allowed.
        assert!(parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR - 1, 72, true).is_ok());
        assert_eq!(
            parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR - 2, 72, true),
            Err(KnockError::Stale)
        );
        assert!(parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR + 73, 72, true).is_ok());
        assert_eq!(
            parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR + 74, 72, true),
            Err(KnockError::Stale)
        );
    }

    /// K17 (knock part): a low-order sender agreement key is refused before
    /// any key is derived.
    #[test]
    fn k17_low_order_sender_agreement_key_is_refused() {
        let (a, mut ba, b, bb) = ab();
        let mut weak = [0u8; 32];
        weak[0] = 1;
        ba.identity_agreement_key = weak;
        let k = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR, 72, true),
            Err(KnockError::Auth(KeyAuthError::WeakKey))
        );
    }

    /// Deterministic knock A -> B with the given sender keys and KEM pair.
    fn det_knock(
        me: &IdentityKeyPair,
        ba: &SignedBundle,
        bb: &SignedBundle,
        kem_ct: &[u8; KEM_CT_LEN],
        kem_ss: &[u8; 32],
        intro: Option<&Intro>,
    ) -> Vec<u8> {
        build_knock_with(
            me,
            ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            golden::ISSUED_HOUR,
            intro,
            &StaticSecret::from(golden::ENV_EPH_SECRET),
            [0x4e; 24],
            [0x11; 16],
            [0x22; 24],
            kem_ct,
            kem_ss,
            None,
            false,
        )
        .unwrap()
    }

    /// §A.5, R10: a v3 knock round-trips (sender, intro), is exactly 5120
    /// bytes with version byte 0x03, and carries `ct_k` in its clear header,
    /// decapsulated by the recipient's identity KEM key.
    #[test]
    fn knock_v3_round_trip() {
        let (a, ba, b, bb) = ab();
        let intro = Intro {
            message_id: [3; 16],
            sent_at_ms: 42,
            text: "hello".into(),
        };
        let k = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            Some(&intro),
            None,
            false,
        )
        .unwrap();
        assert_eq!(k[0], sealed::KNOCK_VERSION);
        let ss = b
            .kem()
            .decapsulate(&k[KNOCK_CT_OFFSET..KNOCK_NONCE_OFFSET])
            .unwrap();
        let o = op(&b, &k);
        assert_eq!(*o.kem_ss, *ss);
        assert_eq!(o.body.len(), KNOCK_BODY_LEN);
        let p = parse_knock(&b, o, golden::ISSUED_HOUR, 72, true).unwrap();
        assert_eq!(p.sender, ba);
        assert_eq!(p.intro, Some(intro));
    }

    /// Final review L6: the intro plaintext (id, time and text) is wiped
    /// when building and when opening a knock: no buffer holding the text
    /// is freed unwiped (only the app's own copy, returned, remains).
    #[test]
    fn intro_plaintext_wipes_on_build_and_open() {
        let (a, ba, b, bb) = ab();
        let needle: [u8; 32] = std::array::from_fn(|_| b'a' + rand::random::<u8>() % 26);
        let intro = Intro {
            message_id: [3; 16],
            sent_at_ms: 42,
            text: String::from_utf8(needle.to_vec()).unwrap(),
        };
        let mut k = Vec::new();
        let hits = crate::alloc_probe::freed_containing(needle, || {
            k = build_knock(
                &a,
                &ba,
                &bb.identity_key,
                &bb.identity_agreement_key,
                &bb.kem_pk,
                golden::ISSUED_HOUR,
                Some(&intro),
                None,
                false,
            )
            .unwrap();
        });
        assert_eq!(hits, 0, "build");
        let mut got = None;
        let hits = crate::alloc_probe::freed_containing(needle, || {
            let o = op(&b, &k);
            got = Some(parse_knock(&b, o, golden::ISSUED_HOUR, 72, true).unwrap());
        });
        assert_eq!(hits, 0, "open");
        assert_eq!(got.unwrap().intro, Some(intro));
    }

    /// R35: the no-prior-session flag travels in the flags byte, with or
    /// without an intro, and is covered by the knock MAC: flags 0 is the
    /// old MAC, and a knock whose flag was flipped no longer verifies.
    #[test]
    fn no_prior_session_flag_round_trips_and_is_mac_covered() {
        let (a, ba, b, bb) = ab();
        let intro = Intro {
            message_id: [4; 16],
            sent_at_ms: 7,
            text: "hi".into(),
        };
        for (with_intro, flag) in [(false, false), (false, true), (true, true)] {
            let k = build_knock(
                &a,
                &ba,
                &bb.identity_key,
                &bb.identity_agreement_key,
                &bb.kem_pk,
                golden::ISSUED_HOUR,
                with_intro.then_some(&intro),
                None,
                flag,
            )
            .unwrap();
            let p = parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR, 72, true).unwrap();
            assert_eq!(p.no_prior_session, flag);
            assert_eq!(p.intro.is_some(), with_intro);
        }
        let mac0 = keyauth::knock_mac(&[5; 32], &bb.identity_key, &ba, 9).unwrap();
        let flagged0 = keyauth::knock_mac_flagged(&[5; 32], &bb.identity_key, &ba, 9, 0).unwrap();
        let flagged2 =
            keyauth::knock_mac_flagged(&[5; 32], &bb.identity_key, &ba, 9, FLAG_NO_PRIOR_SESSION)
                .unwrap();
        assert_eq!(mac0, flagged0, "flags 0 is the v3 MAC unchanged");
        assert_ne!(mac0, flagged2, "the flag is under the MAC");
        assert!(keyauth::verify_knock_mac_flagged(
            &[5; 32],
            &bb.identity_key,
            &ba,
            9,
            FLAG_NO_PRIOR_SESSION,
            &mac0
        )
        .is_err());
        // Flipping the flag in an opened body (as a relay would have to,
        // inside the envelope) fails the MAC.
        let k = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            &bb.kem_pk,
            golden::ISSUED_HOUR,
            None,
            None,
            false,
        )
        .unwrap();
        let mut o = op(&b, &k);
        o.body[KNOCK_FIXED_LEN - 1] = FLAG_NO_PRIOR_SESSION;
        assert!(parse_knock(&b, o, golden::ISSUED_HOUR, 72, true).is_err());
    }

    /// R10 sizes: body 3910, fixed part 1321, the largest intro ends at
    /// 2413, the rotation tail starts at 3316 (903 bytes of slack).
    #[test]
    fn knock_v3_is_exactly_5120() {
        let (a, ba, _b, bb) = ab();
        let (ct, ss) = crate::kem::encapsulate(&bb.kem_pk[..]).unwrap();
        let intro = Intro {
            message_id: [9; 16],
            sent_at_ms: 1,
            text: "x".repeat(MAX_INTRO_BYTES),
        };
        for i in [None, Some(&intro)] {
            let k = det_knock(&a, &ba, &bb, &ct, &ss, i);
            assert_eq!(k.len(), 5120);
            assert_eq!(k.len(), KNOCK_PAYLOAD_LEN);
            assert_eq!(k[0], 0x03);
        }
        assert_eq!(KNOCK_BODY_LEN, 5120 - 1161 - 16 - 33);
        assert_eq!(KNOCK_BODY_LEN, 3910);
        assert_eq!(KNOCK_FIXED_LEN, 32 + 1184 + 64 + 8 + 32 + 1);
        assert_eq!(KNOCK_FIXED_LEN, 1321);
        assert_eq!(MAX_INTRO_BLOCK, 1092);
        assert_eq!(KNOCK_FIXED_LEN + MAX_INTRO_BLOCK, 2413);
        assert_eq!(ROTATION_TAIL_OFFSET, 3316);
        assert_eq!(
            ROTATION_TAIL_OFFSET - (KNOCK_FIXED_LEN + MAX_INTRO_BLOCK),
            903
        );
    }

    /// The X25519 half is wrong (the knock's keys came from another
    /// agreement secret than the one A's signed bundle names), the ML-KEM
    /// half is right: refused by the MAC.
    #[test]
    fn knock_v3_tampered_x25519_half_refused() {
        let (_a, ba, b, bb) = ab();
        let c = IdentityKeyPair::from_seed(&[0x33; 64]).unwrap();
        let (ct, ss) = crate::kem::encapsulate(&bb.kem_pk[..]).unwrap();
        let k = det_knock(&c, &ba, &bb, &ct, &ss, None);
        let o = op(&b, &k);
        assert_eq!(o.sender_identity_key, ba.identity_key);
        assert_eq!(
            parse_knock(&b, o, golden::ISSUED_HOUR, 72, true),
            Err(KnockError::Auth(KeyAuthError::BadMac))
        );
    }

    /// The ML-KEM half is wrong. On the wire, a flipped `ct_k` decapsulates
    /// (implicit rejection) to another `ss_k` and fails the envelope AEAD;
    /// a `kem_ss` that doesn't match `ct_k` does too. Inside, the knock
    /// keys bind `ss_k` as well (defence in depth): another `ss_k` fails
    /// the MAC even when the envelope opened.
    #[test]
    fn knock_v3_tampered_kem_ct_refused() {
        let (a, ba, b, bb) = ab();
        let (ct, ss) = crate::kem::encapsulate(&bb.kem_pk[..]).unwrap();
        let k = det_knock(&a, &ba, &bb, &ct, &ss, None);
        assert!(parse_knock(&b, op(&b, &k), golden::ISSUED_HOUR, 72, true).is_ok());
        let mut bad_ct = k.clone();
        bad_ct[KNOCK_CT_OFFSET + 7] ^= 0x01;
        assert_eq!(
            sealed::open_knock(b.agreement_secret(), b.kem(), &bad_ct).map(|_| ()),
            Err(sealed::SealError::Aead)
        );
        let wrong_ss = det_knock(&a, &ba, &bb, &ct, &[0x4b; 32], None);
        assert_eq!(
            sealed::open_knock(b.agreement_secret(), b.kem(), &wrong_ss).map(|_| ()),
            Err(sealed::SealError::Aead)
        );
        let mut o = op(&b, &k);
        o.kem_ss = zeroize::Zeroizing::new([0x4b; 32]);
        assert_eq!(
            parse_knock(&b, o, golden::ISSUED_HOUR, 72, true),
            Err(KnockError::Auth(KeyAuthError::BadMac))
        );
    }

    /// A knock is never built to a recipient KEM key that isn't one.
    #[test]
    fn knock_to_an_invalid_kem_key_is_refused() {
        let (a, ba, _b, bb) = ab();
        let bad = [0xffu8; KEM_PK_LEN]; // coefficients >= q
        assert_eq!(
            build_knock(
                &a,
                &ba,
                &bb.identity_key,
                &bb.identity_agreement_key,
                &bad,
                golden::ISSUED_HOUR,
                None,
                None,
                false
            ),
            Err(KnockError::BadKemKey)
        );
    }

    #[test]
    fn intro_text_limits() {
        assert!(Intro::validate_text("hi").is_ok());
        assert_eq!(Intro::validate_text(""), Err(KnockError::BadIntro));
        assert_eq!(
            Intro::validate_text(&"x".repeat(1025)),
            Err(KnockError::BadIntro)
        );
        assert_eq!(Intro::validate_text("a\0b"), Err(KnockError::BadIntro));
    }
}
