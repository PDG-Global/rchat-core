//! Boundary validation of client-supplied protocol fields.
//!
//! Everything a client sends that names a key or an identity is checked here
//! before any handler stores it, uses it as a map key, or formats it. Invalid
//! input is refused with an error frame; the error text never echoes the
//! input. Downstream code may therefore assume identity strings are exactly
//! 64 lowercase hex characters (pure ASCII), so no string operation on them
//! can hit a UTF-8 boundary.

use crate::protocol::signaling::{
    ConnectionRequestPayload, IceCandidatePayload, KeyBundle, LookupKeyBundlePayload,
    PublishKeyBundlePayload, RelayRequestPayload, SignalingMessage, MSG_TYPE_CONNECTION_REQUEST,
    MSG_TYPE_ICE_CANDIDATE, MSG_TYPE_LOOKUP_KEY_BUNDLE, MSG_TYPE_PUBLISH_KEY_BUNDLE,
    MSG_TYPE_RELAY_REQUEST,
};
use crate::protocol::unified::ControlMessage;

/// Length of an X25519 / Ed25519 public key.
pub const KEY_BYTES: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;
/// Every knock is exactly this long (spec §5.3, L3): knock v3 is 5120
/// bytes (protocol v3 §A.5), carrying the sender's 1184-byte ML-KEM key and
/// the 1088-byte ML-KEM ciphertext to the recipient's static key. Equal to
/// `rchat_core::sealed::KNOCK_PAYLOAD_LEN` (compile-time check in
/// `codec_compat_tests`).
pub const KNOCK_BYTES: usize = 5120;
/// First byte of every knock v3 (§A.5); other sealed payloads keep
/// `SEALED_V2`.
pub const KNOCK_VERSION: u8 = 0x03;
/// Decoded length of the bundle's ML-KEM-768 public key (protocol v3 §A.2),
/// and of the ML-KEM-768 ephemeral every v3 ask carries (§A.3).
pub const KEM_PK_BYTES: usize = 1184;
/// Length of a blinded ask's pair token (protocol v3 §C.1).
pub const PAIR_TOKEN_BYTES: usize = 32;
/// bincode length prefix of a `Vec<u8>` (fixint: u64 LE).
const VEC_PREFIX: usize = 8;
/// Encoded length (bincode, without the 0x03 frame byte) of a v3
/// `CircuitAsk` as a client sends it: variant tag 4, target 8+32, EK 8+32,
/// KEM ephemeral 8+1184, ephemeral signature 8+64, knock 8+`KNOCK_BYTES`, resume `Some` 1+16 (the
/// core always sends `Some`, the all-zero id for none). Equal to
/// `rchat_core::protocol::ASK_WIRE_LEN` (pinned by a test).
pub const ASK_WIRE_LEN: usize = 4
    + (VEC_PREFIX + KEY_BYTES)
    + (VEC_PREFIX + KEY_BYTES)
    + (VEC_PREFIX + KEM_PK_BYTES)
    + (VEC_PREFIX + ASK_EPH_SIG_BYTES)
    + (VEC_PREFIX + KNOCK_BYTES)
    + (1 + 16);
/// `CircuitAskBlind.pad` length that makes a blinded ask exactly
/// `ASK_WIRE_LEN` bytes (§C.2): derived from `KNOCK_BYTES`, so it
/// re-balances when the knock size changes.
pub const BLIND_PAD_LEN: usize = ASK_WIRE_LEN
    - (4 + (VEC_PREFIX + PAIR_TOKEN_BYTES)
        + (VEC_PREFIX + KEY_BYTES)
        + (VEC_PREFIX + KEM_PK_BYTES)
        + (VEC_PREFIX + ASK_EPH_SIG_BYTES)
        + VEC_PREFIX);
/// An ask's Ed25519 signature over its ephemerals (ruling R7): the relay
/// checks the length only and forwards it.
pub const ASK_EPH_SIG_BYTES: usize = 64;
/// First byte of a sealed v2 relay payload.
pub const SEALED_V2: u8 = 0x02;
/// Longest signaling envelope id echoed back as `request_id`.
pub const MAX_REQUEST_ID_LEN: usize = 64;
/// Bounds on the Hello capability list.
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_LEN: usize = 64;

/// Content-free reason, safe to send to the client and to log.
pub type Invalid = &'static str;

/// Exactly `2 * bytes` lowercase hex characters.
pub fn is_lower_hex(s: &str, bytes: usize) -> bool {
    s.len() == 2 * bytes && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A 32-byte public key as 64 lowercase hex characters.
pub fn is_key_hex(s: &str) -> bool {
    is_lower_hex(s, KEY_BYTES)
}

/// The envelope id if it is short printable ASCII; otherwise `None`, so a
/// reply never echoes arbitrary client input.
pub fn safe_request_id(id: &str) -> Option<String> {
    (!id.is_empty() && id.len() <= MAX_REQUEST_ID_LEN && id.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| id.to_string())
}

/// Byte prefix of at most `n` bytes that never splits a UTF-8 character.
pub fn prefix(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Standard base64 decoding to exactly `KEM_PK_BYTES`; `None` otherwise.
/// The encoded form is bounded first, so nothing large is decoded.
pub fn decode_kem_pk(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if s.len() != KEM_PK_BYTES.div_ceil(3) * 4 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    (bytes.len() == KEM_PK_BYTES).then_some(bytes)
}

/// Shape of a v3 bundle. The signature is verified in `signaling::key_auth`
/// before anything is stored; here only its form is checked (the KEM key is
/// checked for size only, §A.2).
pub fn key_bundle(b: &KeyBundle) -> Result<(), Invalid> {
    if !is_key_hex(&b.identity_key) {
        return Err("identity_key must be 64 lowercase hex characters");
    }
    if !is_key_hex(&b.identity_agreement_key) {
        return Err("identity_agreement_key must be 64 lowercase hex characters");
    }
    if decode_kem_pk(&b.kem_pk).is_none() {
        return Err("kem_pk must be standard base64 of exactly 1184 bytes");
    }
    if !is_lower_hex(&b.bundle_signature, SIGNATURE_BYTES) {
        return Err("bundle_signature must be 128 lowercase hex characters");
    }
    if !b.one_time_pre_keys.is_empty() {
        return Err("one_time_pre_keys must be empty");
    }
    Ok(())
}

fn key_bytes(k: &[u8], what: Invalid) -> Result<(), Invalid> {
    if k.len() == KEY_BYTES {
        Ok(())
    } else {
        Err(what)
    }
}

/// Validate the identity material of a signaling message. Types that carry
/// no identity material, or that the server ignores, pass.
pub fn signaling(msg: &SignalingMessage) -> Result<(), Invalid> {
    match msg.msg_type.as_str() {
        MSG_TYPE_PUBLISH_KEY_BUNDLE => {
            let p: PublishKeyBundlePayload = msg
                .payload
                .deserialize_data()
                .map_err(|_| "malformed publish_key_bundle payload")?;
            key_bundle(&p.key_bundle)?;
            if !is_lower_hex(&p.conn_signature, SIGNATURE_BYTES) {
                return Err("conn_signature must be 128 lowercase hex characters");
            }
            Ok(())
        }
        MSG_TYPE_LOOKUP_KEY_BUNDLE => {
            let p: LookupKeyBundlePayload = msg
                .payload
                .deserialize_data()
                .map_err(|_| "malformed lookup_key_bundle payload")?;
            key_bytes(&p.identity_key, "identity_key must be 32 bytes")
        }
        MSG_TYPE_CONNECTION_REQUEST => {
            let p: ConnectionRequestPayload = msg
                .payload
                .deserialize_data()
                .map_err(|_| "malformed connection_request payload")?;
            key_bytes(&p.target_identity, "target_identity must be 32 bytes")
        }
        MSG_TYPE_ICE_CANDIDATE => {
            let p: IceCandidatePayload = msg
                .payload
                .deserialize_data()
                .map_err(|_| "malformed ice_candidate payload")?;
            key_bytes(&p.target_identity, "target_identity must be 32 bytes")
        }
        MSG_TYPE_RELAY_REQUEST => {
            let p: RelayRequestPayload = msg
                .payload
                .deserialize_data()
                .map_err(|_| "malformed relay_request payload")?;
            key_bytes(&p.target_identity, "target_identity must be 32 bytes")
        }
        _ => Ok(()),
    }
}

/// Validate the client-supplied fields of a control message.
pub fn control(msg: &ControlMessage) -> Result<(), Invalid> {
    match msg {
        ControlMessage::Hello { capabilities, .. } => {
            if capabilities.len() > MAX_CAPABILITIES
                || capabilities.iter().any(|c| c.len() > MAX_CAPABILITY_LEN)
            {
                return Err("too many or too long capabilities");
            }
            Ok(())
        }
        ControlMessage::CreateCircuit { .. } => {
            Err("CreateCircuit is not supported in protocol v2; use CircuitAsk")
        }
        ControlMessage::CircuitAsk {
            target_identity,
            ephemeral_key,
            kem_ephemeral_pk,
            ephemeral_sig,
            knock,
            resume_circuit,
        } => {
            // §C.2 equal sizes: an identity ask always carries `Some` (the
            // all-zero id for no resume), so it is exactly `ASK_WIRE_LEN`.
            if resume_circuit.is_none() {
                return Err("resume_circuit must be present (all-zero for none)");
            }
            key_bytes(target_identity, "target_identity must be 32 bytes")?;
            key_bytes(ephemeral_key, "ephemeral_key must be 32 bytes")?;
            if kem_ephemeral_pk.len() != KEM_PK_BYTES {
                return Err("kem_ephemeral_pk must be 1184 bytes");
            }
            if ephemeral_sig.len() != ASK_EPH_SIG_BYTES {
                return Err("ephemeral_sig must be 64 bytes");
            }
            if knock.len() != KNOCK_BYTES || knock[0] != KNOCK_VERSION {
                return Err("knock must be a fixed-size sealed payload");
            }
            Ok(())
        }
        ControlMessage::CircuitAskBlind {
            pair_token,
            ephemeral_key,
            kem_ephemeral_pk,
            ephemeral_sig,
            pad,
        } => {
            if pair_token.len() != PAIR_TOKEN_BYTES {
                return Err("pair_token must be 32 bytes");
            }
            key_bytes(ephemeral_key, "ephemeral_key must be 32 bytes")?;
            if kem_ephemeral_pk.len() != KEM_PK_BYTES {
                return Err("kem_ephemeral_pk must be 1184 bytes");
            }
            if ephemeral_sig.len() != ASK_EPH_SIG_BYTES {
                return Err("ephemeral_sig must be 64 bytes");
            }
            if pad.len() != BLIND_PAD_LEN {
                return Err("blinded ask has the wrong padding");
            }
            // All zero (ruling R17 M1): the pad carries nothing.
            if pad.iter().any(|b| *b != 0) {
                return Err("blinded ask padding must be zero");
            }
            Ok(())
        }
        ControlMessage::DeliveryReceipt { .. } | ControlMessage::ReadReceipt { .. } => {
            Err("receipts travel end-to-end; control receipts are not accepted")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::signaling::{
        Payload, PublishKeyBundlePayload, MSG_TYPE_PUBLISH_KEY_BUNDLE,
    };
    use crate::protocol::CircuitId;

    #[test]
    fn key_hex_is_exact() {
        let good = "ab".repeat(32);
        assert!(is_key_hex(&good));
        assert!(!is_key_hex(&good.to_uppercase()));
        assert!(!is_key_hex(&good[..62]));
        assert!(!is_key_hex(&(good.clone() + "a")));
        assert!(!is_key_hex(&format!(
            "{}\u{e9}{}",
            "a".repeat(15),
            "b".repeat(47)
        )));
        assert!(!is_key_hex(&"g".repeat(64)));
    }

    #[test]
    fn prefix_never_splits_a_character() {
        let s = format!("{}\u{e9}xyz", "a".repeat(7));
        assert_eq!(prefix(&s, 8), "aaaaaaa");
        assert_eq!(prefix(&s, 9), format!("{}\u{e9}", "a".repeat(7)));
        assert_eq!(prefix("abc", 8), "abc");
        assert_eq!(prefix("\u{1F600}", 2), "");
    }

    #[test]
    fn request_ids_are_echoed_only_when_safe() {
        assert_eq!(safe_request_id("abc").as_deref(), Some("abc"));
        assert_eq!(safe_request_id(&"a".repeat(65)), None);
        assert_eq!(safe_request_id("a\nb"), None);
        assert_eq!(safe_request_id(""), None);
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn good_bundle() -> KeyBundle {
        KeyBundle {
            identity_key: "11".repeat(32),
            identity_agreement_key: "22".repeat(32),
            kem_pk: b64(&[0x33; KEM_PK_BYTES]),
            bundle_signature: "44".repeat(64),
            one_time_pre_keys: Vec::new(),
        }
    }

    /// v3 (§A.2): the relay checks only the KEM key's size, exactly 1184
    /// decoded bytes of standard base64.
    #[test]
    fn kem_pk_must_decode_to_exactly_1184_bytes() {
        assert_eq!(b64(&[0u8; KEM_PK_BYTES]).len(), 1580);
        assert!(decode_kem_pk(&b64(&[7u8; KEM_PK_BYTES])).is_some());
        let url_safe = b64(&[0xFBu8; KEM_PK_BYTES])
            .replace('+', "-")
            .replace('/', "_");
        for (name, s) in [
            ("1183 bytes", b64(&[7u8; KEM_PK_BYTES - 1])),
            ("1185 bytes", b64(&[7u8; KEM_PK_BYTES + 1])),
            ("32 bytes", b64(&[7u8; 32])),
            ("empty", String::new()),
            ("hex", "33".repeat(KEM_PK_BYTES)),
            ("not base64", "!".repeat(1580)),
            ("url-safe alphabet", url_safe),
        ] {
            assert!(decode_kem_pk(&s).is_none(), "{name}");
            let b = KeyBundle {
                kem_pk: s,
                ..good_bundle()
            };
            assert!(key_bundle(&b).is_err(), "{name}");
        }
    }

    fn publish(b: KeyBundle, conn_signature: &str) -> SignalingMessage {
        SignalingMessage::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            Payload::new(
                MSG_TYPE_PUBLISH_KEY_BUNDLE,
                PublishKeyBundlePayload {
                    key_bundle: b,
                    conn_signature: conn_signature.to_string(),
                },
            ),
        )
    }

    /// A4: malformed bundles, asks and receipts are refused, and the reason
    /// never echoes the input.
    #[test]
    fn a4_validator_rejects_malformed_bundles_asks_and_receipts() {
        let good_sig = "55".repeat(64);
        assert!(signaling(&publish(good_bundle(), &good_sig)).is_ok());

        let bad_bundles: Vec<(&str, KeyBundle, String)> = vec![
            (
                "empty bundle signature",
                KeyBundle {
                    bundle_signature: String::new(),
                    ..good_bundle()
                },
                String::new(),
            ),
            (
                "127-character bundle signature",
                KeyBundle {
                    bundle_signature: "4".repeat(127),
                    ..good_bundle()
                },
                "4".repeat(127),
            ),
            (
                "uppercase bundle signature",
                KeyBundle {
                    bundle_signature: "AB".repeat(64),
                    ..good_bundle()
                },
                "AB".repeat(64),
            ),
            (
                "one-time pre-keys present",
                KeyBundle {
                    one_time_pre_keys: vec!["66".repeat(32)],
                    ..good_bundle()
                },
                "66".repeat(32),
            ),
        ];
        for (name, b, needle) in bad_bundles {
            let reason = signaling(&publish(b, &good_sig)).expect_err(name);
            if !needle.is_empty() {
                assert!(!reason.contains(&needle), "{name}: reason echoes input");
            }
        }

        for (name, conn_sig) in [
            ("empty conn_signature", String::new()),
            ("127-character conn_signature", "5".repeat(127)),
            ("non-hex conn_signature", "zz".repeat(64)),
        ] {
            let reason = signaling(&publish(good_bundle(), &conn_sig)).expect_err(name);
            if !conn_sig.is_empty() {
                assert!(!reason.contains(&conn_sig), "{name}: reason echoes input");
            }
        }

        let ask_kem = |target: Vec<u8>, ek: Vec<u8>, kem: Vec<u8>, knock: Vec<u8>| {
            ControlMessage::CircuitAsk {
                target_identity: target,
                ephemeral_key: ek,
                kem_ephemeral_pk: kem,
                ephemeral_sig: vec![0x5e; 64],
                knock,
                resume_circuit: Some(CircuitId([0; 16])),
            }
        };
        let ask = |target: Vec<u8>, ek: Vec<u8>, knock: Vec<u8>| {
            ask_kem(target, ek, vec![5; KEM_PK_BYTES], knock)
        };
        // Knock v3 (§A.5): exactly 5120 bytes, version byte 0x03.
        let mut v3_knock = vec![0u8; 5120];
        v3_knock[0] = 0x03;
        assert!(control(&ask(vec![1; 32], vec![2; 32], v3_knock.clone())).is_ok());
        let mut v1_knock = v3_knock.clone();
        v1_knock[0] = 0x00;
        let mut v2_prefix = v3_knock.clone();
        v2_prefix[0] = SEALED_V2;
        let mut v2_size = vec![0u8; 4096];
        v2_size[0] = 0x03;
        for (name, msg) in [
            (
                "short target",
                ask(vec![1; 31], vec![2; 32], v3_knock.clone()),
            ),
            (
                "short ephemeral",
                ask(vec![1; 32], vec![2; 31], v3_knock.clone()),
            ),
            (
                "knock 2047 bytes",
                ask(vec![1; 32], vec![2; 32], vec![SEALED_V2; 2047]),
            ),
            (
                "knock 2049 bytes",
                ask(vec![1; 32], vec![2; 32], vec![SEALED_V2; 2049]),
            ),
            (
                "knock with v1 prefix",
                ask(vec![1; 32], vec![2; 32], v1_knock),
            ),
            (
                "5120-byte knock with the sealed v2 prefix 0x02",
                ask(vec![1; 32], vec![2; 32], v2_prefix),
            ),
            (
                "4096-byte knock (pre-v3 size) with prefix 0x03",
                ask(vec![1; 32], vec![2; 32], v2_size),
            ),
            (
                "2048-byte knock (v2 size)",
                ask(vec![1; 32], vec![2; 32], vec![0x03; 2048]),
            ),
            (
                "knock 5119 bytes",
                ask(vec![1; 32], vec![2; 32], vec![0x03; 5119]),
            ),
            (
                "knock 5121 bytes",
                ask(vec![1; 32], vec![2; 32], vec![0x03; 5121]),
            ),
            ("empty knock", ask(vec![1; 32], vec![2; 32], Vec::new())),
        ] {
            assert!(control(&msg).is_err(), "{name} accepted");
        }
        // §C.2: an ask without a resume id (shorter on the wire) is refused.
        let mut no_resume = ask(vec![1; 32], vec![2; 32], v3_knock.clone());
        if let ControlMessage::CircuitAsk { resume_circuit, .. } = &mut no_resume {
            *resume_circuit = None;
        }
        assert_eq!(
            control(&no_resume),
            Err("resume_circuit must be present (all-zero for none)")
        );
        // Protocol v3 §A.3: the KEM ephemeral is exactly 1184 bytes.
        for len in [0, 32, KEM_PK_BYTES - 1, KEM_PK_BYTES + 1, 2 * KEM_PK_BYTES] {
            let msg = ask_kem(vec![1; 32], vec![2; 32], vec![5; len], v3_knock.clone());
            assert_eq!(
                control(&msg),
                Err("kem_ephemeral_pk must be 1184 bytes"),
                "kem_ephemeral_pk of {len} bytes"
            );
        }

        // Ruling R7: the ephemeral signature is exactly 64 bytes (length only;
        // the peer verifies it).
        for len in [0, 63, 65, 128] {
            let mut msg = ask(vec![1; 32], vec![2; 32], v3_knock.clone());
            if let ControlMessage::CircuitAsk { ephemeral_sig, .. } = &mut msg {
                *ephemeral_sig = vec![9; len];
            }
            assert_eq!(
                control(&msg),
                Err("ephemeral_sig must be 64 bytes"),
                "ephemeral_sig of {len} bytes"
            );
            let mut blinded = ControlMessage::CircuitAskBlind {
                pair_token: vec![1; 32],
                ephemeral_key: vec![2; 32],
                kem_ephemeral_pk: vec![3; KEM_PK_BYTES],
                ephemeral_sig: vec![9; len],
                pad: vec![0; BLIND_PAD_LEN],
            };
            assert_eq!(control(&blinded), Err("ephemeral_sig must be 64 bytes"));
            if let ControlMessage::CircuitAskBlind { ephemeral_sig, .. } = &mut blinded {
                *ephemeral_sig = vec![9; 64];
            }
            assert!(control(&blinded).is_ok());
        }

        let blind =
            |token: usize, ek: usize, kem: usize, pad: usize| ControlMessage::CircuitAskBlind {
                pair_token: vec![1; token],
                ephemeral_key: vec![2; ek],
                kem_ephemeral_pk: vec![3; kem],
                ephemeral_sig: vec![0x5e; 64],
                pad: vec![0; pad],
            };
        assert!(control(&blind(32, 32, KEM_PK_BYTES, BLIND_PAD_LEN)).is_ok());
        for (name, msg) in [
            ("short token", blind(31, 32, KEM_PK_BYTES, BLIND_PAD_LEN)),
            ("short ek", blind(32, 31, KEM_PK_BYTES, BLIND_PAD_LEN)),
            ("short kem", blind(32, 32, KEM_PK_BYTES - 1, BLIND_PAD_LEN)),
            ("short pad", blind(32, 32, KEM_PK_BYTES, BLIND_PAD_LEN - 1)),
            ("long pad", blind(32, 32, KEM_PK_BYTES, BLIND_PAD_LEN + 1)),
        ] {
            assert!(control(&msg).is_err(), "{name} accepted");
        }
        // R17 M1: a pad of the right length with any non-zero byte.
        for at in [0, BLIND_PAD_LEN / 2, BLIND_PAD_LEN - 1] {
            let mut msg = blind(32, 32, KEM_PK_BYTES, BLIND_PAD_LEN);
            if let ControlMessage::CircuitAskBlind { pad, .. } = &mut msg {
                pad[at] = 1;
            }
            assert_eq!(
                control(&msg),
                Err("blinded ask padding must be zero"),
                "non-zero pad byte at {at} accepted"
            );
        }

        for receipt in [
            ControlMessage::DeliveryReceipt {
                message_id: "abc".into(),
                delivered_at: 1,
                circuit_id: CircuitId([1; 16]),
            },
            ControlMessage::ReadReceipt {
                message_id: "abc".into(),
                read_at: 1,
                circuit_id: CircuitId([1; 16]),
            },
        ] {
            let reason = control(&receipt).expect_err("receipts are end-to-end now");
            assert!(!reason.contains("abc"));
        }
    }
}
