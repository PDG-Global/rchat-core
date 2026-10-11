//! K1 golden vectors, K2 bundle rejection, N12 deniability, K17 (keyauth part).

use super::*;
use crate::crypto::IdentityKeyPair;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const A_IK: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const A_AK: &str = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
const B_IK: &str = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d";
const B_AK: &str = "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f";
const BUNDLE_TRANSCRIPT_A: &str = "72636861742f62756e646c652f76310003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
const BUNDLE_SIG_A: &str = "757d468b446b196d23b8bf1a1519df6c59460c127185f1c9cda4d0694eaeffc5801f480abe88e57d255de0a94e3af05bcce8490185423cbdce8f11e722c20202";
const CONN_TRANSCRIPT_A: &str = "72636861742f636f6e6e2d617574682f7631004e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e424242424242424242424242424242424242424242424242424242424242424203a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254757d468b446b196d23b8bf1a1519df6c59460c127185f1c9cda4d0694eaeffc5801f480abe88e57d255de0a94e3af05bcce8490185423cbdce8f11e722c20202";
const CONN_SIG_A: &str = "5706c4c3096a4fa75addb47103cfbe9b0ed489bf3216f6f85ee3d3d0d541e81e52b0e7c122b634e2461f7ee4e4a9a43e2061f6bcce4f9b3a6e4d7c4d02f2d20d";
const ENV_EPH_PUB: &str = "3286894cd2845a6db6a28fbf0677605f80e5a62385bf4e10a790ae5fde36736b";
const K_MAC: &str = "4a649bbf8ffdaac549ee4df04f3c16a67b520ce45a8f0f7b552b25f34b0ff63b";
const K_INTRO: &str = "026a515c2fd7cdab458c6b36f12e264b9b39d469242a6d5a757d9768f4e4bbd9";
const KNOCK_MAC: &str = "d1062fec33ae743591f1158f3b85f8c3b980dd906b33c8820754db8e0d0614fc";
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

/// K1: both transcripts (112 B, 243 B incl. the binding) and both signatures.
#[test]
fn k1_golden_bundle_and_connection_vectors() {
    let (a, _) = identities();
    let bundle = sign_bundle(&a).unwrap();
    assert_eq!(hex::encode(bundle.identity_key), A_IK);
    assert_eq!(hex::encode(bundle.identity_agreement_key), A_AK);
    assert_eq!(
        bundle.signed_pre_key, bundle.identity_agreement_key,
        "SPK is the identity agreement key in v2"
    );
    let t = bundle_transcript(
        &bundle.identity_key,
        &bundle.identity_agreement_key,
        &bundle.signed_pre_key,
    )
    .unwrap();
    assert_eq!(t.len(), BUNDLE_TRANSCRIPT_LEN);
    assert_eq!(hex::encode(t), BUNDLE_TRANSCRIPT_A);
    assert_eq!(hex::encode(bundle.bundle_signature), BUNDLE_SIG_A);
    let c = conn_transcript(&golden::NONCE, &golden::BINDING, &bundle).unwrap();
    assert_eq!(c.len(), CONN_TRANSCRIPT_LEN);
    assert_eq!(hex::encode(c), CONN_TRANSCRIPT_A);
    let sig = sign_conn(&a, &golden::NONCE, &golden::BINDING, &bundle).unwrap();
    assert_eq!(hex::encode(sig), CONN_SIG_A);
    verify_bundle(&bundle).unwrap();
    verify_conn(&golden::NONCE, &golden::BINDING, &bundle, &sig).unwrap();
}

/// K1: k_mac, k_intro and knock_mac (A knocks B).
#[test]
fn k1_golden_knock_vectors() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    assert_eq!(hex::encode(bundle_b.identity_key), B_IK);
    assert_eq!(hex::encode(bundle_b.identity_agreement_key), B_AK);
    let env_pub = X25519PublicKey::from(&StaticSecret::from(golden::ENV_EPH_SECRET)).to_bytes();
    assert_eq!(hex::encode(env_pub), ENV_EPH_PUB);
    let keys = knock_keys(
        a.agreement_secret(),
        &bundle_b.identity_agreement_key,
        &env_pub,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
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
        let mut b = good.clone();
        b.signed_pre_key[i] ^= 0x01;
        assert!(verify_bundle(&b).is_err(), "signed_pre_key byte {i}");
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
        &bundle.signed_pre_key,
    )
    .unwrap();
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

/// K2: low-order or zero X25519 agreement / pre-keys are rejected (before the signature).
#[test]
fn k2_low_order_or_zero_x25519_keys_are_rejected() {
    let (a, _) = identities();
    assert!(!is_low_order_x25519(&h32(A_AK)));
    for p in low_order_points() {
        assert!(is_low_order_x25519(&p), "{}", hex::encode(p));
        let mut b = sign_bundle(&a).unwrap();
        b.identity_agreement_key = p;
        assert_eq!(verify_bundle(&b), Err(KeyAuthError::WeakKey));
        let mut b = sign_bundle(&a).unwrap();
        b.signed_pre_key = p;
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
        bundle_transcript(&[0u8; 31], &[0u8; 32], &[0u8; 32]),
        Err(KeyAuthError::BadLength)
    );
    assert_eq!(
        SignedBundle::from_slices(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 63]),
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
        assert!(matches!(
            knock_keys(
                a.agreement_secret(),
                &p,
                &[9u8; 32],
                &bundle_a.identity_key,
                &bundle_b.identity_key
            ),
            Err(KeyAuthError::NonContributory)
        ));
    }
}

/// N12: the recipient, using only its own secret, derives the same keys and MAC.
#[test]
fn n12_recipient_side_keys_and_mac_equal_the_senders() {
    let (a, b) = identities();
    let bundle_a = sign_bundle(&a).unwrap();
    let bundle_b = sign_bundle(&b).unwrap();
    let env_pub = X25519PublicKey::from(&StaticSecret::from(golden::ENV_EPH_SECRET)).to_bytes();
    let sender = knock_keys(
        a.agreement_secret(),
        &bundle_b.identity_agreement_key,
        &env_pub,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
    )
    .unwrap();
    let recipient = knock_keys(
        b.agreement_secret(),
        &bundle_a.identity_agreement_key,
        &env_pub,
        &bundle_a.identity_key,
        &bundle_b.identity_key,
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
    // the 112-byte bundle transcript and nothing about the recipient.
    assert_eq!(&for_b[143..207], &bundle_a.bundle_signature[..]);
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
