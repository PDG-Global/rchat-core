//! S1 envelope round trip and tampering; K17 low-order envelope key.

use super::*;
use crate::crypto::IdentityKeyPair;
use crate::keyauth::{dh_checked, golden, KeyAuthError};

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
fn ratchet_minimum_is_162_bytes() {
    let (a, b, _) = sample();
    let min = seal([1; 16], &b.ik, &b.ak, &a.ik, KIND_RATCHET, &[0u8; 40]).unwrap();
    assert_eq!(min.len(), MIN_SEALED_LEN);
    assert_eq!(min[0], SEALED_VERSION, "ratchet envelopes stay 0x02");
}

// ---- Knock v3 envelope (§A.5, ruling R10) ------------------------------

/// Fixed knock-envelope inputs: env_eph 0x45.., ML-KEM secret 0x4b...
const KEM_SS: [u8; 32] = [0x4b; 32];
/// k_env for A -> B with the inputs above: checked against an independent
/// HKDF-SHA256 (Python stdlib, own RFC 7748 X25519).
const DH_ENV_B: &str = "db0bee3ae390dc23daf9283dbcfa3b2b897bd1701aa84f668336d4f1d388067b";
const K_ENV_AB: &str = "23a67c502387d52b16db5dbbd02f5ce63dda7309cd53271ab42da5d2af08f79a";

fn knock_to(
    b: &Party,
    from_ik: &[u8; 32],
    ct: &[u8; crate::kem::KEM_CT_LEN],
    ss: &[u8; 32],
) -> Vec<u8> {
    seal_knock_with(
        &StaticSecret::from([0x45; 32]),
        [0x4e; 24],
        [2; 16],
        &b.ak,
        ct,
        ss,
        from_ik,
        &[0x33; KNOCK_INNER_LEN - 33],
    )
    .unwrap()
}

/// R10 sizes: clear header 1161 (ver, id, env_eph_pub, ct_k, nonce), inner
/// 3943, the whole payload 5120 with version byte 0x03.
#[test]
fn knock_envelope_layout_is_1161_plus_3943_plus_16() {
    assert_eq!(KNOCK_PAYLOAD_LEN, 5120);
    assert_eq!(KNOCK_VERSION, 0x03);
    assert_eq!((KNOCK_CT_OFFSET, KNOCK_NONCE_OFFSET), (49, 1137));
    assert_eq!(KNOCK_HEADER_LEN, 1161);
    assert_eq!(KNOCK_INNER_LEN, 3943);
    let (a, b, _) = sample();
    let (ct, ss) = crate::kem::encapsulate(&b.keys.kem_public()[..]).unwrap();
    let k = knock_to(&b, &a.ik, &ct, &ss);
    assert_eq!(k.len(), KNOCK_PAYLOAD_LEN);
    assert_eq!(k[0], KNOCK_VERSION);
    assert_eq!(&k[1..17], &[2; 16]);
    assert_eq!(&k[KNOCK_CT_OFFSET..KNOCK_NONCE_OFFSET], &ct[..]);
    assert_eq!(
        peek_message_id(&k),
        Some([2; 16]),
        "relay-visible id unchanged"
    );
    let o = open_knock(b.keys.agreement_secret(), b.keys.kem(), &k).unwrap();
    assert_eq!(o.message_id, [2; 16]);
    assert_eq!(o.sender_identity_key, a.ik);
    assert_eq!(o.body, vec![0x33; KNOCK_INNER_LEN - 33]);
    assert_eq!(*o.kem_ss, *ss);
    assert!(!k.windows(32).any(|w| w == a.ik), "sender never in clear");
    // A body of any other length would not make a 5120-byte knock.
    assert_eq!(
        seal_knock_with(
            &StaticSecret::from([0x45; 32]),
            [0; 24],
            [0; 16],
            &b.ak,
            &ct,
            &ss,
            &a.ik,
            &[0; 10],
        ),
        Err(SealError::BadFormat)
    );
}

/// K1: k_env = HKDF(salt = env_eph_pub || recipient_ak,
/// ikm = DH(env_eph, recipient_ak) || ss_k, info = "rchat/knock-env/v3").
#[test]
fn k1_golden_knock_envelope_key() {
    let b = party(golden::seed_b());
    let env = StaticSecret::from([0x45; 32]);
    let env_pub = X25519PublicKey::from(&env).to_bytes();
    let dh = dh_checked(&env, &b.ak).unwrap();
    assert_eq!(hex::encode(*dh), DH_ENV_B);
    let k = knock_envelope_key(&env_pub, &b.ak, &dh, &KEM_SS);
    assert_eq!(hex::encode(*k), K_ENV_AB);
}

/// R10: a recorded knock does not open with the X25519 secrets alone. A
/// (future quantum) adversary holding the recipient's agreement secret
/// and the sender's envelope ephemeral, but not the recipient's ML-KEM
/// secret, gets neither the X25519-only key nor any key from a wrong
/// `ss_k`, nor a decapsulation under another ML-KEM key.
#[test]
fn recorded_knock_does_not_open_with_the_x25519_secrets_alone() {
    let (a, b, _) = sample();
    let (ct, ss) = crate::kem::encapsulate(&b.keys.kem_public()[..]).unwrap();
    let k = knock_to(&b, &a.ik, &ct, &ss);
    let sk = b.keys.agreement_secret();
    for guess in [[0u8; 32], [0x4b; 32]] {
        assert_eq!(
            open_knock_with_ss(sk, &guess, &k).map(|_| ()),
            Err(SealError::Aead)
        );
    }
    let other = party([0x33; 64]);
    assert_eq!(
        open_knock(sk, other.keys.kem(), &k).map(|_| ()),
        Err(SealError::Aead)
    );
    // The v2 construction (DH only) does not open it either.
    let env = StaticSecret::from([0x45; 32]);
    let env_pub = X25519PublicKey::from(&env).to_bytes();
    let dh = dh_checked(&env, &b.ak).unwrap();
    let x_only = envelope_key(&env_pub, &b.ak, &dh);
    let opened = XChaCha20Poly1305::new_from_slice(&x_only).unwrap().decrypt(
        XNonce::from_slice(&k[KNOCK_NONCE_OFFSET..KNOCK_HEADER_LEN]),
        Payload {
            msg: &k[KNOCK_HEADER_LEN..],
            aad: &k[..KNOCK_HEADER_LEN],
        },
    );
    assert!(opened.is_err());
    assert!(
        open_knock(sk, b.keys.kem(), &k).is_ok(),
        "the recipient opens it"
    );
}

/// R10: `ct_k`, `env_eph_pub` and the message id are all bound: tampering
/// with any of them on the wire fails the AEAD.
#[test]
fn tampered_knock_clear_header_fails() {
    let (a, b, _) = sample();
    let (ct, ss) = crate::kem::encapsulate(&b.keys.kem_public()[..]).unwrap();
    let k = knock_to(&b, &a.ik, &ct, &ss);
    let sk = b.keys.agreement_secret();
    for at in [
        1,
        16,
        KNOCK_CT_OFFSET,
        KNOCK_CT_OFFSET + 500,
        KNOCK_NONCE_OFFSET - 1,
    ] {
        let mut t = k.clone();
        t[at] ^= 0x01;
        assert_eq!(
            open_knock(sk, b.keys.kem(), &t).map(|_| ()),
            Err(SealError::Aead),
            "byte {at}"
        );
    }
    let mut t = k.clone();
    t[17..49].copy_from_slice(&a.ak); // another valid point
    assert_eq!(
        open_knock(sk, b.keys.kem(), &t).map(|_| ()),
        Err(SealError::Aead)
    );
    let mut t = k.clone();
    t[KNOCK_NONCE_OFFSET] ^= 0x01;
    assert_eq!(
        open_knock(sk, b.keys.kem(), &t).map(|_| ()),
        Err(SealError::Aead)
    );
    let mut short = k.clone();
    short.pop();
    assert_eq!(
        open_knock(sk, b.keys.kem(), &short).map(|_| ()),
        Err(SealError::BadFormat)
    );
    let mut v2 = k.clone();
    v2[0] = SEALED_VERSION;
    assert_eq!(
        open_knock(sk, b.keys.kem(), &v2).map(|_| ()),
        Err(SealError::BadFormat)
    );
}

/// R10: the generic envelope is never a knock. `open` refuses 0x03, `seal`
/// refuses the knock kind, and a 0x02 envelope carrying the knock kind
/// (which `seal` won't make) is refused when opened.
#[test]
fn generic_open_and_seal_refuse_knocks() {
    let (a, b, _) = sample();
    let (ct, ss) = crate::kem::encapsulate(&b.keys.kem_public()[..]).unwrap();
    let k = knock_to(&b, &a.ik, &ct, &ss);
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &k),
        Err(SealError::BadFormat)
    );
    assert_eq!(
        seal([2; 16], &b.ik, &b.ak, &a.ik, KIND_KNOCK, &[0u8; 100]),
        Err(SealError::BadFormat)
    );
    let forged = seal_unchecked(
        &StaticSecret::from([0x45; 32]),
        [0x4e; 24],
        [3; 16],
        &b.ik,
        &b.ak,
        &a.ik,
        KIND_KNOCK,
        &[0u8; 100],
    )
    .unwrap();
    assert_eq!(
        open(&b.ik, b.keys.agreement_secret(), &forged),
        Err(SealError::BadFormat)
    );
}
