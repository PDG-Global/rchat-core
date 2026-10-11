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
/// Every knock is exactly this long (spec §5.3, L3).
pub const KNOCK_BYTES: usize = 2048;
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

/// Shape of a v2 bundle. The signature is verified in `signaling::key_auth`
/// before anything is stored; here only its form is checked.
pub fn key_bundle(b: &KeyBundle) -> Result<(), Invalid> {
    if !is_key_hex(&b.identity_key) {
        return Err("identity_key must be 64 lowercase hex characters");
    }
    if !is_key_hex(&b.identity_agreement_key) {
        return Err("identity_agreement_key must be 64 lowercase hex characters");
    }
    if !is_key_hex(&b.signed_pre_key) {
        return Err("signed_pre_key must be 64 lowercase hex characters");
    }
    if !is_lower_hex(&b.signed_pre_key_signature, SIGNATURE_BYTES) {
        return Err("signed_pre_key_signature must be 128 lowercase hex characters");
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
            knock,
            ..
        } => {
            key_bytes(target_identity, "target_identity must be 32 bytes")?;
            key_bytes(ephemeral_key, "ephemeral_key must be 32 bytes")?;
            if knock.len() != KNOCK_BYTES || knock[0] != SEALED_V2 {
                return Err("knock must be a 2048-byte sealed v2 payload");
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

    fn good_bundle() -> KeyBundle {
        KeyBundle {
            identity_key: "11".repeat(32),
            identity_agreement_key: "22".repeat(32),
            signed_pre_key: "33".repeat(32),
            signed_pre_key_signature: "44".repeat(64),
            one_time_pre_keys: Vec::new(),
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
                    signed_pre_key_signature: String::new(),
                    ..good_bundle()
                },
                String::new(),
            ),
            (
                "127-character bundle signature",
                KeyBundle {
                    signed_pre_key_signature: "4".repeat(127),
                    ..good_bundle()
                },
                "4".repeat(127),
            ),
            (
                "uppercase bundle signature",
                KeyBundle {
                    signed_pre_key_signature: "AB".repeat(64),
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

        let ask = |target: Vec<u8>, ek: Vec<u8>, knock: Vec<u8>| ControlMessage::CircuitAsk {
            target_identity: target,
            ephemeral_key: ek,
            knock,
            resume_circuit: None,
        };
        let mut v2_knock = vec![0u8; KNOCK_BYTES];
        v2_knock[0] = SEALED_V2;
        assert!(control(&ask(vec![1; 32], vec![2; 32], v2_knock.clone())).is_ok());
        let mut v1_knock = v2_knock.clone();
        v1_knock[0] = 0x00;
        for (name, msg) in [
            (
                "short target",
                ask(vec![1; 31], vec![2; 32], v2_knock.clone()),
            ),
            (
                "short ephemeral",
                ask(vec![1; 32], vec![2; 31], v2_knock.clone()),
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
            ("empty knock", ask(vec![1; 32], vec![2; 32], Vec::new())),
        ] {
            assert!(control(&msg).is_err(), "{name} accepted");
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
