//! Knocks and intros (spec §6.3, §6.5): a fixed-size sealed request whose
//! sender is authenticated by a deniable MAC, optionally carrying a short
//! first message readable only by the recipient.

use crate::crypto::IdentityKeyPair;
use crate::keyauth::{self, KeyAuthError, SignedBundle};
use crate::rotation::{self, RotationBlock};
use crate::sealed::{self, Opened, KIND_KNOCK, KNOCK_INNER_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ak(32) + spk(32) + sig(64) + issued_hour(8) + mac(32) + intro_flag(1).
pub const KNOCK_FIXED_LEN: usize = 169;
/// Knock body length: the inner plaintext minus sender(32) and kind(1).
pub const KNOCK_BODY_LEN: usize = KNOCK_INNER_LEN - 33;
pub const MAX_INTRO_BYTES: usize = 1024;
const INTRO_HEADER_LEN: usize = 24 + 2;
const INTRO_PT_FIXED: usize = 16 + 8 + 2;
/// Start of the reserved rotation block at the end of the knock body (spec §4.8).
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
}

/// Build a knock payload (always `KNOCK_PAYLOAD_LEN` bytes). The envelope
/// message id is fresh and independent of any intro id (L10).
pub fn build_knock(
    me: &IdentityKeyPair,
    my_bundle: &SignedBundle,
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    issued_hour: u64,
    intro: Option<&Intro>,
    rotation: Option<&RotationBlock>,
) -> Result<Vec<u8>, KnockError> {
    let env_eph = StaticSecret::random_from_rng(OsRng);
    let mut env_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut env_nonce);
    let mut message_id = [0u8; 16];
    OsRng.fill_bytes(&mut message_id);
    let mut intro_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut intro_nonce);
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
        rotation,
    )
}

/// Deterministic form of `build_knock` (tests and vectors).
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
    rotation: Option<&RotationBlock>,
) -> Result<Vec<u8>, KnockError> {
    let env_eph_pub = X25519PublicKey::from(env_eph).to_bytes();
    let keys = keyauth::knock_keys(
        me.agreement_secret(),
        recipient_agreement_key,
        &env_eph_pub,
        &my_bundle.identity_key,
        recipient_identity_key,
    )?;
    let mac = keyauth::knock_mac(&keys.k_mac, recipient_identity_key, my_bundle, issued_hour)?;
    let mut body = Vec::with_capacity(KNOCK_BODY_LEN);
    body.extend_from_slice(&my_bundle.identity_agreement_key);
    body.extend_from_slice(&my_bundle.signed_pre_key);
    body.extend_from_slice(&my_bundle.bundle_signature);
    body.extend_from_slice(&issued_hour.to_be_bytes());
    body.extend_from_slice(&mac);
    match intro {
        None => body.push(0x00),
        Some(intro) => {
            Intro::validate_text(&intro.text)?;
            body.push(0x01);
            let mut pt = Vec::with_capacity(INTRO_PT_FIXED + intro.text.len());
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
    Ok(sealed::seal_with(
        env_eph,
        env_nonce,
        message_id,
        recipient_identity_key,
        recipient_agreement_key,
        &my_bundle.identity_key,
        KIND_KNOCK,
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
pub fn parse_knock(
    me: &IdentityKeyPair,
    opened: &Opened,
    now_hour: u64,
    knock_ttl_hours: u32,
    want_intro: bool,
) -> Result<ParsedKnock, KnockError> {
    if opened.kind != KIND_KNOCK || opened.body.len() < KNOCK_FIXED_LEN {
        return Err(KnockError::Malformed);
    }
    let b = &opened.body;
    let sender = SignedBundle::from_slices(
        &opened.sender_identity_key,
        &b[0..32],
        &b[32..64],
        &b[64..128],
    )?;
    let issued_hour =
        u64::from_be_bytes(b[128..136].try_into().map_err(|_| KnockError::Malformed)?);
    let mac: [u8; 32] = b[136..168].try_into().map_err(|_| KnockError::Malformed)?;
    let flag = b[168];
    keyauth::verify_bundle(&sender)?;
    let my_ik = me.public_signing_key().to_bytes();
    let keys = keyauth::knock_keys(
        me.agreement_secret(),
        &sender.identity_agreement_key,
        &opened.env_eph_pub,
        &sender.identity_key,
        &my_ik,
    )?;
    keyauth::verify_knock_mac(&keys.k_mac, &my_ik, &sender, issued_hour, &mac)?;
    if issued_hour > now_hour + 1
        || now_hour.saturating_sub(issued_hour) > u64::from(knock_ttl_hours) + 1
    {
        return Err(KnockError::Stale);
    }
    let intro = match flag {
        0x01 if want_intro => open_intro(
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
    let pt = XChaCha20Poly1305::new_from_slice(k_intro)
        .ok()?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &intro_aad(sender, recipient, mac),
            },
        )
        .ok()?;
    if pt.len() < INTRO_PT_FIXED {
        return None;
    }
    let message_id: [u8; 16] = pt[..16].try_into().ok()?;
    let sent_at_ms = u64::from_be_bytes(pt[16..24].try_into().ok()?);
    let text_len = u16::from_be_bytes([pt[24], pt[25]]) as usize;
    if text_len == 0 || text_len > MAX_INTRO_BYTES || pt.len() != INTRO_PT_FIXED + text_len {
        return None;
    }
    let text = String::from_utf8(pt[INTRO_PT_FIXED..].to_vec()).ok()?;
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
    use crate::sealed::KNOCK_PAYLOAD_LEN;

    fn ab() -> (IdentityKeyPair, SignedBundle, IdentityKeyPair, SignedBundle) {
        let a = IdentityKeyPair::from_seed(&golden::seed_a()).unwrap();
        let b = IdentityKeyPair::from_seed(&golden::seed_b()).unwrap();
        let (ba, bb) = (sign_bundle(&a).unwrap(), sign_bundle(&b).unwrap());
        (a, ba, b, bb)
    }

    /// N13 (L3, L10): every knock is exactly 2048 bytes, with or without an
    /// intro, and the envelope id is never the intro id.
    #[test]
    fn n13_knock_is_2048_bytes_and_ids_are_independent() {
        let (a, ba, _b, bb) = ab();
        let plain = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            golden::ISSUED_HOUR,
            None,
            None,
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
            golden::ISSUED_HOUR,
            Some(&intro),
            None,
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
            golden::ISSUED_HOUR,
            Some(&intro),
            None,
        )
        .unwrap();
        let o = sealed::open(&bb.identity_key, b.agreement_secret(), &k).unwrap();
        let p = parse_knock(&b, &o, golden::ISSUED_HOUR, 72, true).unwrap();
        assert_eq!(p.sender, ba);
        assert_eq!(p.intro, Some(intro));
        // Task 15 minor: a contact's intro is not opened at all.
        let contact = parse_knock(&b, &o, golden::ISSUED_HOUR, 72, false).unwrap();
        assert_eq!(contact.intro, None);
        assert_eq!(contact.sender, ba, "the knock itself still verifies");
        // L2: one hour of future skew allowed, ttl + 1 hours of age allowed.
        assert!(parse_knock(&b, &o, golden::ISSUED_HOUR - 1, 72, true).is_ok());
        assert_eq!(
            parse_knock(&b, &o, golden::ISSUED_HOUR - 2, 72, true),
            Err(KnockError::Stale)
        );
        assert!(parse_knock(&b, &o, golden::ISSUED_HOUR + 73, 72, true).is_ok());
        assert_eq!(
            parse_knock(&b, &o, golden::ISSUED_HOUR + 74, 72, true),
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
        ba.signed_pre_key = weak;
        let k = build_knock(
            &a,
            &ba,
            &bb.identity_key,
            &bb.identity_agreement_key,
            golden::ISSUED_HOUR,
            None,
            None,
        )
        .unwrap();
        let o = sealed::open(&bb.identity_key, b.agreement_secret(), &k).unwrap();
        assert_eq!(
            parse_knock(&b, &o, golden::ISSUED_HOUR, 72, true),
            Err(KnockError::Auth(KeyAuthError::WeakKey))
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
