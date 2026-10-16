//! K1 golden vectors, K2 bundle rejection, N12 deniability, K17 (keyauth part).

use super::*;
use crate::crypto::IdentityKeyPair;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const A_IK: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const A_AK: &str = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
const B_IK: &str = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d";
const B_AK: &str = "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f";
const BUNDLE_TRANSCRIPT_A_SHA256: &str =
    "fa77a71a019f424cc2dc6c6b90239a91579340cbb4e6ca5fba680d71d4eb8016";
const BUNDLE_SIG_A: &str = "4436fcdb8cac259b44b1cbe9c8e9af47284d4488d0880469c0ebb741d6c1db2c87c1cf920bffdb1f1973884156ae997d2065a218cecccaa8560492191b008e02";
const CONN_TRANSCRIPT_A: &str = "72636861742f636f6e6e2d617574682f7633004e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e424242424242424242424242424242424242424242424242424242424242424203a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662544436fcdb8cac259b44b1cbe9c8e9af47284d4488d0880469c0ebb741d6c1db2c87c1cf920bffdb1f1973884156ae997d2065a218cecccaa8560492191b008e02";
const CONN_SIG_A: &str = "3105f9d9d20a76d7324da8e1910f8d39395194f777eec8372a6e51876820bddafb00e12ae9ac9e7c5b58b15cfc5ad8205b0ae58538f864a5fad869caff24d000";
/// SHA-256 of identity A's ML-KEM-768 public key (derived from `seed_a`).
const A_KEM_PK_SHA256: &str = "035e068e5fe519242d2dced290348ab4e18cebe119ee9f64142034198b439ad1";
/// SHA-256 of the v3 transcript over the fixed inputs of `bundle_v3_golden_transcript`.
const FIXED_TRANSCRIPT_SHA256: &str =
    "842d65345fd33c39b4a0b8d604af656a73fd3b6103e01b549f74a451c49f1cfb";
const ENV_EPH_PUB: &str = "3286894cd2845a6db6a28fbf0677605f80e5a62385bf4e10a790ae5fde36736b";
/// Knock v3 (§A.5) vectors, with the fixed ML-KEM secret `KEM_SS`: checked
/// against an independent HKDF-SHA256 / HMAC-SHA256 computation (Python
/// stdlib, with its own RFC 7748 X25519 for `DH_STATIC_AB`).
const KEM_SS: [u8; 32] = [0x4b; 32];
const DH_STATIC_AB: &str = "7c79d7b5f31b9aac367477f5f7c7a68b5c44cac28ed5c902a59ec48c02956a6a";
const K_MAC: &str = "b67618c730d15f55b63736334f962c981b3cb5419e15e71e0153b57d8e6d817f";
const K_INTRO: &str = "31dab6442ff3383b315c4e41f154556f82bdd163de8dea5d2d2d397e1c254e56";
const KNOCK_MAC: &str = "4e5a8fa637222d55f7c8696fc6a03cf5d11066d4f85aecbf065b10c1ab9d7b63";
const DEV_BINDING_8443: &str = "dc0d2d9890cc672819a084e35d4f242202c9bb548e2f76d0fa3222b9a9475725";
/// u-coordinate of an order-8 point on Curve25519.
const ORDER_8_POINT: &str = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800";

fn identities() -> (IdentityKeyPair, IdentityKeyPair) {
    (
        IdentityKeyPair::from_seed(&golden::seed_a()).unwrap(),
        IdentityKeyPair::from_seed(&golden::seed_b()).unwrap(),
    )
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn low_order_points() -> Vec<[u8; 32]> {
    let mut one = [0u8; 32];
    one[0] = 1;
    vec![[0u8; 32], one, h32(ORDER_8_POINT)]
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(Sha256::digest(data))
}

/// K1 (v3): both transcripts (1264 B bundle, 211 B connection incl. the
/// binding) and both signatures.
#[test]
fn k1_golden_bundle_and_connection_vectors() {
    let (a, _) = identities();
    let bundle = sign_bundle(&a).unwrap();
    assert_eq!(hex::encode(bundle.identity_key), A_IK);
    assert_eq!(hex::encode(bundle.identity_agreement_key), A_AK);
    assert_eq!(sha256_hex(&bundle.kem_pk[..]), A_KEM_PK_SHA256);
    let t = bundle_transcript(
        &bundle.identity_key,
        &bundle.identity_agreement_key,
        &bundle.kem_pk,
    );
    assert_eq!(t.len(), BUNDLE_TRANSCRIPT_LEN_V3);
    assert_eq!(sha256_hex(&t), BUNDLE_TRANSCRIPT_A_SHA256);
    assert_eq!(hex::encode(bundle.bundle_signature), BUNDLE_SIG_A);
    let c = conn_transcript(&golden::NONCE, &golden::BINDING, &bundle).unwrap();
    assert_eq!(c.len(), CONN_TRANSCRIPT_LEN);
    assert_eq!(hex::encode(c), CONN_TRANSCRIPT_A);
    let sig = sign_conn(&a, &golden::NONCE, &golden::BINDING, &bundle).unwrap();
    assert_eq!(hex::encode(sig), CONN_SIG_A);
    verify_bundle(&bundle).unwrap();
    verify_conn(&golden::NONCE, &golden::BINDING, &bundle, &sig).unwrap();
}

/// Bundle v3 golden transcript over fixed bytes: the domain, ik, ak and
/// kem_pk in that order, 1264 bytes.
#[test]
fn bundle_v3_golden_transcript() {
    let ik = [0x11u8; 32];
    let ak = [0x22u8; 32];
    let mut kem_pk = [0u8; KEM_PK_LEN];
    for (i, b) in kem_pk.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let t = bundle_transcript(&ik, &ak, &kem_pk);
    assert_eq!(BUNDLE_TRANSCRIPT_LEN_V3, 1264);
    assert_eq!(t.len(), 1264);
    assert_eq!(&t[..16], b"rchat/bundle/v3\0");
    assert_eq!(hex::encode(&t[..16]), "72636861742f62756e646c652f763300");
    assert_eq!(&t[16..48], &ik);
    assert_eq!(&t[48..80], &ak);
    assert_eq!(&t[80..], &kem_pk[..]);
    assert_eq!(sha256_hex(&t), FIXED_TRANSCRIPT_SHA256);
}

#[test]
fn bundle_v3_sign_verify() {
    let (a, b) = identities();
    for id in [&a, &b] {
        let bundle = sign_bundle(id).unwrap();
        assert_eq!(&bundle.kem_pk[..], &id.kem_public()[..]);
        verify_bundle(&bundle).unwrap();
        let wire = SignedBundle::from_wire(
            &bundle.identity_key,
            &bundle.identity_agreement_key,
            &bundle.kem_pk[..],
            &bundle.bundle_signature,
        )
        .unwrap();
        assert_eq!(wire, bundle);
        verify_bundle(&wire).unwrap();
    }
}

/// A bit flip anywhere in `kem_pk` fails verification (the signature
/// covers it, and a flip may also break the FIPS 203 modulus check).
#[test]
fn bundle_v3_kem_bit_flip_fails() {
    let (a, _) = identities();
    let good = sign_bundle(&a).unwrap();
    // The encoded vector t (bytes 0..1152): a flip fails either the modulus
    // check or the signature.
    for i in 0..1152 {
        let mut b = good.clone();
        b.kem_pk[i] ^= 0x01;
        assert!(verify_bundle(&b).is_err(), "kem_pk byte {i}");
    }
    // rho (bytes 1152..1184) is not covered by the modulus check: only the
    // signature catches a flip there.
    for i in 1152..KEM_PK_LEN {
        let mut b = good.clone();
        b.kem_pk[i] ^= 0x01;
        assert_eq!(
            verify_bundle(&b),
            Err(KeyAuthError::BadSignature),
            "kem_pk byte {i}"
        );
    }
    // A coefficient raised to q or above (here 0xFFF = 4095) is a malformed
    // key, refused before the signature is looked at.
    let mut b = good.clone();
    b.kem_pk[0] = 0xFF;
    b.kem_pk[1] |= 0x0F;
    assert_eq!(verify_bundle(&b), Err(KeyAuthError::WeakKey));
}

/// Independent golden for the identity KEM seed (protocol v3 §A.1),
/// computed outside the crate with the Python standard library (RFC 5869,
/// salt None = 32 zero bytes):
///
/// python3 -c "import hmac,hashlib;s=bytes(range(64));p=hmac.new(b'\0'*32,s,hashlib.sha256).digest();t=b'';o=b''
/// exec('for i in (1,2):\n t=hmac.new(p,t+b\'rchat/kem-seed/v3\'+bytes([i]),hashlib.sha256).digest();o+=t');print(o.hex())"
#[test]
fn identity_kem_seed_golden_seed_a() {
    assert_eq!(crate::crypto::KEM_SEED_INFO, b"rchat/kem-seed/v3");
    assert_eq!(
        hex::encode(&crate::crypto::identity_kem_seed(&golden::seed_a())[..]),
        "2279e9f18db7c5c52be266bbc4fd666a9e447292128acae302a1be54b4a0fb3a\
         914c879a54a09cf157b89e43151ebdc50354784dbd911968e6d330432938d747"
    );
}

#[test]
fn bundle_v3_wrong_kem_len_refused() {
    let (a, _) = identities();
    let good = sign_bundle(&a).unwrap();
    for len in [0, 32, KEM_PK_LEN - 1, KEM_PK_LEN + 1, 2 * KEM_PK_LEN] {
        let kem = vec![0u8; len];
        assert_eq!(
            SignedBundle::from_wire(
                &good.identity_key,
                &good.identity_agreement_key,
                &kem,
                &good.bundle_signature,
            ),
            Err(KeyAuthError::BadLength),
            "kem_pk of {len} bytes"
        );
    }
}

/// Seed backup (§F.1): rebuilding the identity from its 64-byte seed
/// reproduces `kem_pk`; the KEM seed is HKDF(seed, "rchat/kem-seed/v3").
#[test]
fn identity_seed_reproduces_kem_pk() {
    let id = IdentityKeyPair::generate();
    let seed = zeroize::Zeroizing::new(id.seed_bytes());
    let again = IdentityKeyPair::from_seed(&seed[..]).unwrap();
    assert_eq!(&again.kem_public()[..], &id.kem_public()[..]);
    assert_eq!(sign_bundle(&again).unwrap(), sign_bundle(&id).unwrap());
    let expected = crate::kem::KemKeyPair::from_seed(&crate::crypto::identity_kem_seed(&seed));
    assert_eq!(&expected.public()[..], &id.kem_public()[..]);
    let (a, b) = identities();
    assert_ne!(&a.kem_public()[..], &b.kem_public()[..]);
    assert_eq!(sha256_hex(&a.kem_public()[..]), A_KEM_PK_SHA256);
}

/// K1: k_mac, k_intro and knock_mac (A knocks B), knock v3 (§A.5):
/// salt = env_eph_pub || recipient_ak, ikm = DH_static || kem_ss,
/// info = "rchat/knock/v3" || sender_ik || recipient_ik, 64 bytes split
/// into k_mac || k_intro.
#[test]
fn k1_golden_knock_v3_vectors() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    assert_eq!(hex::encode(bundle_b.identity_key), B_IK);
    assert_eq!(hex::encode(bundle_b.identity_agreement_key), B_AK);
    let env_pub = X25519PublicKey::from(&StaticSecret::from(golden::ENV_EPH_SECRET)).to_bytes();
    assert_eq!(hex::encode(env_pub), ENV_EPH_PUB);
    let dh = dh_checked(a.agreement_secret(), &bundle_b.identity_agreement_key).unwrap();
    assert_eq!(hex::encode(*dh), DH_STATIC_AB);
    let keys = knock_keys_v3(
        a.agreement_secret(),
        &bundle_b.identity_agreement_key,
        &env_pub,
        &KEM_SS,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
        KnockRole::Sender,
    )
    .unwrap();
    assert_eq!(hex::encode(keys.k_mac), K_MAC);
    assert_eq!(hex::encode(keys.k_intro), K_INTRO);
    assert_eq!(
        knock_mac_input(&bundle_b.identity_key, &bundle_a, golden::ISSUED_HOUR).len(),
        KNOCK_MAC_INPUT_LEN
    );
    let mac = knock_mac(
        &keys.k_mac,
        &bundle_b.identity_key,
        &bundle_a,
        golden::ISSUED_HOUR,
    )
    .unwrap();
    assert_eq!(hex::encode(mac), KNOCK_MAC);
}

/// §A.5: the knock keys need both halves. Changing only the ML-KEM secret,
/// or only the static DH (another recipient agreement key), changes both
/// keys, so a tampered X25519 half or a tampered `ct_k` fails the MAC.
#[test]
fn knock_v3_keys_depend_on_the_x25519_and_the_kem_half() {
    let (a, b) = identities();
    let (ba, bb) = (sign_bundle(&a).unwrap(), sign_bundle(&b).unwrap());
    let env_pub = X25519PublicKey::from(&StaticSecret::from(golden::ENV_EPH_SECRET)).to_bytes();
    let keys = |their_ak: &[u8; 32], ss: &[u8; 32]| {
        knock_keys_v3(
            a.agreement_secret(),
            their_ak,
            &env_pub,
            ss,
            &ba.identity_key,
            &bb.identity_key,
            KnockRole::Sender,
        )
        .unwrap()
    };
    let base = keys(&bb.identity_agreement_key, &KEM_SS);
    let other_kem = keys(&bb.identity_agreement_key, &[0x4c; 32]);
    let c = IdentityKeyPair::from_seed(&[0x33; 64]).unwrap();
    let other_dh = keys(&c.public_agreement_key().to_bytes(), &KEM_SS);
    for k in [&other_kem, &other_dh] {
        assert_ne!(k.k_mac, base.k_mac);
        assert_ne!(k.k_intro, base.k_intro);
    }
    assert_ne!(base.k_mac, base.k_intro);
}

/// K1: the --no-tls origin binding and origin normalisation.
#[test]
fn k1_golden_dev_origin_binding_and_relay_origin() {
    assert_eq!(
        hex::encode(dev_origin_binding("ws://127.0.0.1:8443").unwrap()),
        DEV_BINDING_8443
    );
    assert_eq!(dev_origin_binding(""), Err(KeyAuthError::BadOrigin));
    assert_eq!(
        relay_origin("WS://LocalHost/abc").unwrap(),
        "ws://localhost:80"
    );
    assert_eq!(
        relay_origin("wss://[::1]:9443/p").unwrap(),
        "wss://[::1]:9443"
    );
    assert_eq!(
        relay_origin("ws://127.0.0.1:8443/relay/path").unwrap(),
        "ws://127.0.0.1:8443"
    );
    assert_eq!(
        relay_origin("wss://chat.example.com/x").unwrap(),
        "wss://chat.example.com:443"
    );
    assert_eq!(
        relay_origin("ftp://example.com/"),
        Err(KeyAuthError::BadOrigin)
    );
    assert_eq!(relay_origin("127.0.0.1:8443"), Err(KeyAuthError::BadOrigin));
    assert_eq!(relay_origin("not a url"), Err(KeyAuthError::BadOrigin));
}

/// K2: a bit flip in any field of a signed bundle is rejected.
#[test]
fn k2_bit_flip_in_any_bundle_field_is_rejected() {
    let (a, _) = identities();
    let good = sign_bundle(&a).unwrap();
    for i in 0..32 {
        let mut b = good.clone();
        b.identity_key[i] ^= 0x01;
        assert!(verify_bundle(&b).is_err(), "identity_key byte {i}");
        let mut b = good.clone();
        b.identity_agreement_key[i] ^= 0x01;
        assert!(
            verify_bundle(&b).is_err(),
            "identity_agreement_key byte {i}"
        );
    }
    for i in (0..KEM_PK_LEN).step_by(37) {
        let mut b = good.clone();
        b.kem_pk[i] ^= 0x01;
        assert!(verify_bundle(&b).is_err(), "kem_pk byte {i}");
    }
    for i in 0..64 {
        let mut b = good.clone();
        b.bundle_signature[i] ^= 0x01;
        assert_eq!(
            verify_bundle(&b),
            Err(KeyAuthError::BadSignature),
            "signature byte {i}"
        );
    }
}

/// K2: a signature made by another identity over the same transcript is rejected.
#[test]
fn k2_signature_by_the_wrong_key_is_rejected() {
    let (a, b) = identities();
    let mut bundle = sign_bundle(&a).unwrap();
    let t = bundle_transcript(
        &bundle.identity_key,
        &bundle.identity_agreement_key,
        &bundle.kem_pk,
    );
    bundle.bundle_signature = b.sign(&t).to_bytes();
    assert_eq!(verify_bundle(&bundle), Err(KeyAuthError::BadSignature));
}

/// K2: a weak (small-order) Ed25519 identity key is rejected for bundles and proofs.
#[test]
fn k2_weak_identity_key_is_rejected() {
    let (a, _) = identities();
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1; // compressed neutral element (y = 1)
    for weak in [identity_point, [0u8; 32]] {
        let mut b = sign_bundle(&a).unwrap();
        b.identity_key = weak;
        assert_eq!(verify_bundle(&b), Err(KeyAuthError::WeakKey));
        assert_eq!(
            verify_conn(&golden::NONCE, &golden::BINDING, &b, &[0u8; 64]),
            Err(KeyAuthError::WeakKey)
        );
    }
}

/// K2: low-order or zero X25519 agreement keys are rejected (before the signature).
#[test]
fn k2_low_order_or_zero_x25519_keys_are_rejected() {
    let (a, _) = identities();
    assert!(!is_low_order_x25519(&h32(A_AK)));
    for p in low_order_points() {
        assert!(is_low_order_x25519(&p), "{}", hex::encode(p));
        let mut b = sign_bundle(&a).unwrap();
        b.identity_agreement_key = p;
        assert_eq!(verify_bundle(&b), Err(KeyAuthError::WeakKey));
    }
}

/// A proof made for another nonce or binding (a relayed proof, M3) fails.
#[test]
fn verify_conn_rejects_another_nonce_binding_or_short_signature() {
    let (a, _) = identities();
    let bundle = sign_bundle(&a).unwrap();
    let sig = sign_conn(&a, &golden::NONCE, &golden::BINDING, &bundle).unwrap();
    assert_eq!(
        verify_conn(&[0x4f; 32], &golden::BINDING, &bundle, &sig),
        Err(KeyAuthError::BadSignature)
    );
    assert_eq!(
        verify_conn(&golden::NONCE, &[0x43; 32], &bundle, &sig),
        Err(KeyAuthError::BadSignature)
    );
    assert_eq!(
        verify_conn(&golden::NONCE, &golden::BINDING, &bundle, &sig[..63]),
        Err(KeyAuthError::BadLength)
    );
}

#[test]
fn sign_conn_refuses_a_bundle_of_another_identity() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    assert_eq!(
        sign_conn(&b, &golden::NONCE, &golden::BINDING, &bundle_a),
        Err(KeyAuthError::IdentityMismatch)
    );
}

#[test]
fn wrong_lengths_are_bad_length() {
    assert_eq!(
        SignedBundle::from_wire(&[1u8; 32], &[2u8; 32], &[3u8; KEM_PK_LEN], &[4u8; 63]),
        Err(KeyAuthError::BadLength)
    );
    assert_eq!(
        SignedBundle::from_wire(&[1u8; 31], &[2u8; 32], &[3u8; KEM_PK_LEN], &[4u8; 64]),
        Err(KeyAuthError::BadLength)
    );
    let (a, _) = identities();
    let bundle = sign_bundle(&a).unwrap();
    assert_eq!(
        conn_transcript(&[0u8; 31], &golden::BINDING, &bundle),
        Err(KeyAuthError::BadLength)
    );
}

/// K17 (keyauth part): every DH refuses a non-contributory result.
#[test]
fn k17_dh_checked_and_knock_keys_refuse_low_order_points() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    let secret = StaticSecret::from([7u8; 32]);
    for p in low_order_points() {
        assert_eq!(dh_checked(&secret, &p), Err(KeyAuthError::NonContributory));
        for role in [KnockRole::Sender, KnockRole::Recipient] {
            assert!(matches!(
                knock_keys_v3(
                    a.agreement_secret(),
                    &p,
                    &[9u8; 32],
                    &KEM_SS,
                    &bundle_a.identity_key,
                    &bundle_b.identity_key,
                    role,
                ),
                Err(KeyAuthError::NonContributory)
            ));
        }
    }
}

/// N12: the recipient, using only its own secret, derives the same keys and MAC.
#[test]
fn n12_recipient_side_keys_and_mac_equal_the_senders() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    let env_pub = X25519PublicKey::from(&StaticSecret::from(golden::ENV_EPH_SECRET)).to_bytes();
    let sender = knock_keys_v3(
        a.agreement_secret(),
        &bundle_b.identity_agreement_key,
        &env_pub,
        &KEM_SS,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
        KnockRole::Sender,
    )
    .unwrap();
    let recipient = knock_keys_v3(
        b.agreement_secret(),
        &bundle_a.identity_agreement_key,
        &env_pub,
        &KEM_SS,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
        KnockRole::Recipient,
    )
    .unwrap();
    assert_eq!(sender.k_mac, recipient.k_mac);
    assert_eq!(sender.k_intro, recipient.k_intro);
    let by_sender = knock_mac(
        &sender.k_mac,
        &bundle_b.identity_key,
        &bundle_a,
        golden::ISSUED_HOUR,
    )
    .unwrap();
    let by_recipient = knock_mac(
        &recipient.k_mac,
        &bundle_b.identity_key,
        &bundle_a,
        golden::ISSUED_HOUR,
    )
    .unwrap();
    assert_eq!(
        by_sender, by_recipient,
        "the recipient could have produced the MAC: deniable"
    );
    verify_knock_mac(
        &recipient.k_mac,
        &bundle_b.identity_key,
        &bundle_a,
        golden::ISSUED_HOUR,
        &by_sender,
    )
    .unwrap();
    assert_eq!(
        verify_knock_mac(
            &recipient.k_mac,
            &bundle_b.identity_key,
            &bundle_a,
            golden::ISSUED_HOUR + 1,
            &by_sender
        ),
        Err(KeyAuthError::BadMac)
    );
}

/// N12: no knock field is an Ed25519 signature over recipient-specific data.
#[test]
fn n12_knock_mac_input_holds_no_recipient_bound_signature() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    let other_recipient = [0x77u8; 32];
    let for_b = knock_mac_input(&bundle_b.identity_key, &bundle_a, golden::ISSUED_HOUR);
    let for_c = knock_mac_input(&other_recipient, &bundle_a, golden::ISSUED_HOUR);
    assert_eq!(for_b[..15], for_c[..15]);
    assert_ne!(
        for_b[15..47],
        for_c[15..47],
        "only the recipient slot differs"
    );
    assert_eq!(for_b[47..], for_c[47..]);
    // The only signature inside is the sender's bundle signature, which covers
    // the 1264-byte v3 bundle transcript and nothing about the recipient.
    assert_eq!(&for_b[111..175], &bundle_a.bundle_signature[..]);
    verify_bundle(&bundle_a).unwrap();
}

/// Task 1 minor: a knock MAC tag of the wrong length is refused, never
/// truncated or padded; `ws:///x` (no host) is not an origin.
#[test]
fn k1_wrong_length_tag_and_hostless_origin_are_refused() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    let k_mac = h32(K_MAC);
    let tag = h32(KNOCK_MAC);
    let check = |t: &[u8]| {
        verify_knock_mac(
            &k_mac,
            &bundle_b.identity_key,
            &bundle_a,
            golden::ISSUED_HOUR,
            t,
        )
    };
    assert_eq!(check(&tag), Ok(()));
    assert_eq!(check(&tag[..31]), Err(KeyAuthError::BadMac));
    assert_eq!(
        check(&[tag.as_slice(), &[0]].concat()),
        Err(KeyAuthError::BadMac)
    );
    assert_eq!(check(&[]), Err(KeyAuthError::BadMac));
    assert_eq!(relay_origin("ws:///x"), Err(KeyAuthError::BadOrigin));
    assert_eq!(relay_origin("wss://"), Err(KeyAuthError::BadOrigin));
}

/// Task 1 minor: the HKDF state is wiped after use, without changing what
/// it derives.
#[test]
fn k1_hkdf_state_is_wiped_and_output_unchanged() {
    let mut direct = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"salt"), b"ikm")
        .expand(b"info", &mut direct)
        .unwrap();
    let mut wiped = [0u8; 32];
    with_hkdf(Some(b"salt"), b"ikm", |hk| {
        hk.expand(b"info", &mut wiped).unwrap()
    });
    assert_eq!(direct, wiped);

    let mut hk = Hkdf::<Sha256>::new(Some(b"salt"), b"ikm");
    let size = std::mem::size_of_val(&hk);
    let bytes = |hk: &Hkdf<Sha256>| -> Vec<u8> {
        let p = (hk as *const Hkdf<Sha256>).cast::<u8>();
        (0..size)
            .map(|i| unsafe { p.add(i).read_volatile() })
            .collect()
    };
    assert!(bytes(&hk).iter().any(|&b| b != 0));
    wipe_hkdf(&mut hk);
    assert!(
        bytes(&hk).iter().all(|&b| b == 0),
        "the PRK-keyed state is gone"
    );
    scrub_stack(); // runs without touching anything it doesn't own
}

/// Completion review L1: the zeroing is valid only for the reviewed layout;
/// a dependency bump that changes `Hkdf<Sha256>` fails here first.
#[test]
fn hkdf_layout_is_the_reviewed_one() {
    assert_eq!(
        std::mem::size_of::<Hkdf<Sha256>>(),
        HKDF_SHA256_REVIEWED_SIZE
    );
    assert!(!std::mem::needs_drop::<Hkdf<Sha256>>());
}
