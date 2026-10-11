//! S1 envelope round trip and tampering; K17 low-order envelope key.

use super::*;
use crate::crypto::IdentityKeyPair;
use crate::keyauth::{golden, KeyAuthError};

struct Party {
    ik: [u8; 32],
    ak: [u8; 32],
    keys: IdentityKeyPair,
}

fn party(seed: [u8; 64]) -> Party {
    let keys = IdentityKeyPair::from_seed(&seed).unwrap();
    Party {
        ik: keys.public_signing_key().to_bytes(),
        ak: keys.public_agreement_key().to_bytes(),
        keys,
    }
}

fn sample() -> (Party, Party, Vec<u8>) {
    let a = party(golden::seed_a());
    let b = party(golden::seed_b());
    let payload = seal([5; 16], &b.ik, &b.ak, &a.ik, KIND_RATCHET, &[0x11; 60]).unwrap();
    (a, b, payload)
}

/// S1: the recipient learns sender, kind and id; the relay sees no sender.
#[test]
fn s1_round_trip_names_sender_kind_and_message_id() {
    let (a, b, payload) = sample();
    assert_eq!(payload[0], SEALED_VERSION);
    assert_eq!(peek_message_id(&payload), Some([5; 16]));
    let opened = open(&b.ik, b.keys.agreement_secret(), &payload).unwrap();
    assert_eq!(opened.message_id, [5; 16]);
    assert_eq!(opened.sender_identity_key, a.ik);
    assert_eq!(opened.kind, KIND_RATCHET);
    assert_eq!(opened.body, vec![0x11; 60]);
    assert!(
        !payload.windows(32).any(|w| w == a.ik),
        "sender identity never in clear"
    );
}

/// S1: tampering with message_id, env_eph_pub or the AAD recipient fails.
#[test]
fn s1_tampered_message_id_env_key_or_recipient_fails() {
    let (a, b, payload) = sample();
    let mut t = payload.clone();
    t[1] ^= 0x01;
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &t),
        Err(SealError::Aead)
    );
    let mut t = payload.clone();
    t[17..49].copy_from_slice(&a.ak); // another valid point
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &t),
        Err(SealError::Aead)
    );
    assert_eq!(
        open(&a.ik, b.keys.agreement_secret(), &payload),
        Err(SealError::Aead),
        "the AAD binds the recipient identity"
    );
    let mut t = payload.clone();
    let last = t.len() - 1;
    t[last] ^= 0x01;
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &t),
        Err(SealError::Aead)
    );
    let c = party([0x33; 64]);
    assert_eq!(
        open(&c.ik, c.keys.agreement_secret(), &payload),
        Err(SealError::Aead)
    );
}

/// K17 (envelope part): a low-order env_eph_pub is refused before any key
/// is derived; sealing to a low-order recipient key is refused too.
#[test]
fn k17_low_order_env_eph_pub_is_refused_before_key_derivation() {
    let (a, b, payload) = sample();
    let mut t = payload.clone();
    t[17..49].copy_from_slice(&[0u8; 32]);
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &t),
        Err(SealError::KeyAgreement(KeyAuthError::NonContributory))
    );
    assert_eq!(
        seal([1; 16], &b.ik, &[0u8; 32], &a.ik, KIND_RATCHET, &[0u8; 60]),
        Err(SealError::KeyAgreement(KeyAuthError::NonContributory))
    );
}

#[test]
fn v1_or_short_payloads_are_bad_format() {
    let (_, b, _) = sample();
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &[0x00; 200]),
        Err(SealError::BadFormat)
    );
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &[0x02; 161]),
        Err(SealError::BadFormat)
    );
    assert_eq!(peek_message_id(&[0x02; 161]), None);
    assert_eq!(peek_message_id(&[0x00; 200]), None);
}

#[test]
fn ratchet_minimum_is_162_bytes_and_a_knock_body_fills_2048() {
    let (a, b, _) = sample();
    let min = seal([1; 16], &b.ik, &b.ak, &a.ik, KIND_RATCHET, &[0u8; 40]).unwrap();
    assert_eq!(min.len(), MIN_SEALED_LEN);
    assert_eq!(KNOCK_INNER_LEN, 1959);
    let knock = seal(
        [2; 16],
        &b.ik,
        &b.ak,
        &a.ik,
        KIND_KNOCK,
        &[0u8; KNOCK_INNER_LEN - 33],
    )
    .unwrap();
    assert_eq!(knock.len(), KNOCK_PAYLOAD_LEN);
}
