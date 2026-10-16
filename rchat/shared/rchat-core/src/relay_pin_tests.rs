//! RP3–RP6, RP8: the client's relay identity gate (spec §4.9).

use crate::relay_pin::{encode_pin, sign_relay_link};
use crate::test_support::*;
use crate::{ClientConfig, RChatError};
use ed25519_dalek::SigningKey;

fn client(
    pin: Option<String>,
    version: Option<u32>,
    strict: bool,
) -> (
    crate::ClientInner,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Recorder,
) {
    let (mut inner, rx) = inner_with_identity(0xA1);
    inner.config = ClientConfig {
        server_url: "ws://127.0.0.1:18443".into(),
        relay_pin: pin,
        relay_pin_version: version,
        relay_pin_strict: strict,
        ..ClientConfig::default()
    };
    let rec = Recorder::default();
    inner.callbacks = Some(Box::new(rec.clone()));
    inner.publish_requested = true;
    inner.is_connected = false;
    (inner, rx, rec)
}

fn publishes(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> usize {
    sent_signaling(rx)
        .iter()
        .filter(|m| m.msg_type == "publish_key_bundle")
        .count()
}

/// RP3: TOFU on first connect.
#[test]
fn rp3_tofu_pins_and_reports_the_relay() {
    let (mut inner, mut rx, _rec) = client(None, None, false);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected);
    assert_eq!(publishes(&mut rx), 1, "publish goes out after the gate");
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(info["source"], "tofu");
    assert_eq!(
        info["pin"],
        encode_pin(&test_relay().verifying_key().to_bytes())
    );
    assert_eq!(info["version"], 0);
    assert_eq!(info["origin"], "ws://127.0.0.1:18443");
    assert_eq!(
        inner.config.relay_pin.as_deref(),
        info["pin"].as_str(),
        "remembered for reconnects"
    );
}

/// RP4: strict mode without a pin refuses.
#[test]
fn rp4_strict_without_pin_refuses_without_publishing() {
    let (mut inner, mut rx, rec) = client(None, None, true);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(!inner.is_connected);
    assert_eq!(publishes(&mut rx), 0);
    assert!(
        inner.websocket.is_none(),
        "transport shut down, no auto-reconnect"
    );
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayPinRequired)));
}

/// RP5: a different relay key without a chain is a hard failure.
#[test]
fn rp5_pin_mismatch_refuses() {
    let other = SigningKey::from_bytes(&[0x12; 32]);
    let (mut inner, mut rx, rec) = client(
        Some(encode_pin(&other.verifying_key().to_bytes())),
        Some(0),
        false,
    );
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(!inner.is_connected);
    assert_eq!(publishes(&mut rx), 0);
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayIdentityChanged)));
}

/// RP6: a valid relay rotation chain re-pins silently; a bad one refuses.
#[test]
fn rp6_relay_rotation_follows_valid_chain_only() {
    let old = SigningKey::from_bytes(&[0x21; 32]);
    let new = test_relay();
    let link = sign_relay_link(&old, &new.verifying_key().to_bytes(), 1);
    let (mut inner, mut rx, _rec) = client(
        Some(encode_pin(&old.verifying_key().to_bytes())),
        Some(0),
        true,
    );
    feed_signaling(
        &mut inner,
        hello_response_from([0x4e; 32], &new, 1, &[link]),
    );
    assert!(inner.is_connected);
    assert_eq!(publishes(&mut rx), 1);
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(info["source"], "rotated");
    assert_eq!(info["version"], 1);
    assert_eq!(
        info["from"],
        encode_pin(&old.verifying_key().to_bytes()),
        "the pin the chain was walked from (Task 20e triage)"
    );

    let stranger = SigningKey::from_bytes(&[0x22; 32]);
    let forged = sign_relay_link(&stranger, &new.verifying_key().to_bytes(), 1);
    let (mut inner, mut rx, rec) = client(
        Some(encode_pin(&old.verifying_key().to_bytes())),
        Some(0),
        false,
    );
    feed_signaling(
        &mut inner,
        hello_response_from([0x4e; 32], &new, 1, &[forged]),
    );
    assert!(!inner.is_connected);
    assert_eq!(publishes(&mut rx), 0);
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayIdentityChanged)));
}

/// RP3 (round-2 L6): same key, higher offered version → pinned version kept.
#[test]
fn rp3_same_key_higher_version_keeps_pinned_version() {
    let relay = test_relay();
    let (mut inner, _rx, _rec) = client(
        Some(encode_pin(&relay.verifying_key().to_bytes())),
        Some(0),
        false,
    );
    feed_signaling(&mut inner, hello_response_from([0x4e; 32], &relay, 5, &[]));
    assert!(inner.is_connected);
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(
        info["version"], 0,
        "versions advance only through chain steps"
    );
}

/// RP10 (round-2 L2): equivalent URLs share one canonical origin.
#[test]
fn rp10_origin_equivalence() {
    use crate::relay_pin::canonical_origin;
    let a = canonical_origin("wss://Example.COM./ws?x=1").unwrap();
    assert_eq!(a, "wss://example.com:443");
    assert_eq!(canonical_origin("wss://example.com:443").unwrap(), a);
    assert_eq!(canonical_origin("wss://example.com").unwrap(), a);
    assert_eq!(
        canonical_origin("https://example.com/").unwrap(),
        "https://example.com:443"
    );
    assert_eq!(
        canonical_origin("ws://[::1]:8443/").unwrap(),
        "ws://[::1]:8443"
    );
    assert!(
        canonical_origin("wss://bücher.example").is_err(),
        "non-ASCII host refused"
    );
    assert!(canonical_origin("ftp://example.com").is_err());
}

/// RP11 (round-2 L5): non-signaling frames before the publish is accepted are dropped.
#[test]
fn rp11_frames_before_the_gate_are_dropped() {
    let (mut inner, _rx, _rec) = client(None, None, false);
    inner.bypass_frame_gate = false;
    let before = inner.frames_dropped_before_gate;
    crate::RChatClient::handle_frame(
        &mut inner,
        crate::protocol::Frame::Control(crate::protocol::ControlMessage::CloseCircuit {
            circuit_id: crate::protocol::CircuitId([7; 16]),
        }),
    );
    assert_eq!(inner.frames_dropped_before_gate, before + 1);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected, "signaling still passes");
    assert!(
        !inner.is_key_bundle_published,
        "still gated until the publish is accepted"
    );
}

/// RP8: missing, malformed, or wrongly bound relay identity.
#[test]
fn rp8_missing_or_bad_relay_identity_is_invalid() {
    let mut no_identity = hello_response([0x4e; 32]);
    no_identity.payload.inner["data"]
        .as_object_mut()
        .unwrap()
        .remove("relay_identity");
    let mut malformed = hello_response([0x4e; 32]);
    malformed.payload.inner["data"]["relay_identity"]["signature"] = serde_json::json!("zz");
    // Signed over another challenge (as if relayed from another session).
    let mut rebound = hello_response_from([0x01; 32], &test_relay(), 0, &[]);
    rebound.payload.inner["data"]["auth_challenge"] = serde_json::json!(hex::encode([0x4e; 32]));
    for msg in [no_identity, malformed, rebound] {
        let (mut inner, mut rx, rec) = client(None, None, false);
        feed_signaling(&mut inner, msg);
        assert!(!inner.is_connected);
        assert_eq!(publishes(&mut rx), 0);
        assert!(rec
            .take()
            .contains(&format!("error:{}", RChatError::RelayIdentityInvalid)));
    }
}

/// RP11 (round-2 L5): raw relay binaries before the publish are dropped too.
#[test]
fn rp11_binary_before_the_gate_is_dropped() {
    let (mut inner, _rx, _rec) = client(None, None, false);
    inner.bypass_frame_gate = false;
    let before = inner.frames_dropped_before_gate;
    crate::RChatClient::handle_binary(&mut inner, vec![0u8; 64]);
    assert_eq!(inner.frames_dropped_before_gate, before + 1);
}

/// RP5: the pin learned by TOFU is enforced on an auto-reconnect in the same
/// process; a different relay key then hard-fails instead of re-TOFU.
#[test]
fn rp5_learned_pin_is_enforced_on_reconnect() {
    let (mut inner, mut rx, rec) = client(None, None, false);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected);
    inner.handle_transport_disconnected();
    inner.handle_transport_reconnected();
    drain(&mut rx);
    rec.take();
    let other = SigningKey::from_bytes(&[0x12; 32]);
    feed_signaling(&mut inner, hello_response_from([0x4f; 32], &other, 0, &[]));
    assert!(!inner.is_connected);
    assert_eq!(publishes(&mut rx), 0);
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayIdentityChanged)));
    assert!(
        inner.relay_pin_info_json().is_none(),
        "no accepted relay after a failed gate"
    );
}

/// RP10 (round-2 L2): scheme case, userinfo and empty hosts.
#[test]
fn rp10_origin_edge_cases() {
    use crate::relay_pin::canonical_origin;
    assert_eq!(
        canonical_origin("WSS://EXAMPLE.com:8443/x#f").unwrap(),
        "wss://example.com:8443"
    );
    assert_eq!(
        canonical_origin("ws://example.com").unwrap(),
        "ws://example.com:80"
    );
    assert_eq!(
        canonical_origin("wss://xn--bcher-kva.example").unwrap(),
        "wss://xn--bcher-kva.example:443"
    );
    assert!(
        canonical_origin("wss://user@example.com").is_err(),
        "userinfo refused"
    );
    assert!(canonical_origin("wss://.").is_err());
    assert!(canonical_origin("example.com").is_err(), "scheme required");
    assert!(canonical_origin("").is_err());
}

/// RP11 (round-2 L5), gate NOT bypassed: a queued message that arrives
/// before the publish is accepted is dropped; one that follows the publish
/// response (the relay's order) is delivered.
#[test]
fn rp11_queued_message_after_publish_ok_is_delivered() {
    use crate::protocol::{ControlMessage, Frame};
    let mut p = establish(0xA1, 0xB2);
    // B reconnects: a fresh hello and publish, with the gate in force.
    p.b.bypass_frame_gate = false;
    p.b.is_connected = false;
    p.b.is_key_bundle_published = false;
    p.b.retire_connection();
    p.b.hello_outstanding = true;
    p.b.request_publish().unwrap();
    let delivered = |log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>| -> Vec<(String, Vec<u8>)> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::Message(s, c, _) => Some((s.clone(), c.clone())),
                _ => None,
            })
            .collect()
    };

    let early =
        p.a.seal_ratchet(&p.pb.hex, [1; 16], b"\x01\0\0\0\0early")
            .unwrap();
    crate::RChatClient::handle_frame(
        &mut p.b,
        Frame::Control(ControlMessage::QueuedMessage {
            payload: early.payload,
        }),
    );
    assert_eq!(p.b.frames_dropped_before_gate, 1);
    assert!(delivered(&p.b_log).is_empty(), "dropped before the gate");

    feed_signaling(&mut p.b, hello_response([0x4e; 32]));
    feed_signaling(&mut p.b, publish_ok([0x55; 32]));
    assert!(p.b.is_key_bundle_published);

    let queued =
        p.a.seal_ratchet(&p.pb.hex, [2; 16], b"\x01\0\0\0\0queued")
            .unwrap();
    crate::RChatClient::handle_frame(
        &mut p.b,
        Frame::Control(ControlMessage::QueuedMessage {
            payload: queued.payload,
        }),
    );
    assert_eq!(p.b.frames_dropped_before_gate, 1, "nothing more dropped");
    assert_eq!(
        delivered(&p.b_log),
        vec![(p.pa.hex.clone(), b"queued".to_vec())]
    );
}

/// RP10 (round-2 L2): IP literals have one canonical spelling.
#[test]
fn rp10_ip_literals_normalise() {
    use crate::relay_pin::canonical_origin;
    let one = canonical_origin("ws://[::1]:8443").unwrap();
    assert_eq!(canonical_origin("ws://[0:0::1]:8443").unwrap(), one);
    assert_eq!(
        canonical_origin("ws://[0000:0:0:0:0:0:0:1]:8443/x").unwrap(),
        one
    );
    assert_eq!(
        canonical_origin("wss://[2001:DB8::A]").unwrap(),
        "wss://[2001:db8::a]:443"
    );
    assert_eq!(
        canonical_origin("ws://127.0.0.1.:18443").unwrap(),
        "ws://127.0.0.1:18443"
    );
}

/// An unparsable server URL still runs the gate, but no relay info (and so
/// no empty-origin pin) is reported; a disconnect clears the info.
#[test]
fn relay_pin_info_needs_an_origin_and_clears_on_disconnect() {
    let (mut inner, _rx, _rec) = client(None, None, false);
    inner.config.server_url = "not a url".into();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected, "gate passed");
    assert!(
        inner.config.relay_pin.is_some(),
        "pin still remembered for reconnects"
    );
    assert!(inner.relay_pin_info_json().is_none());

    let (mut inner, _rx, _rec) = client(None, None, false);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.relay_pin_info_json().is_some());
    inner.handle_transport_disconnected();
    assert!(inner.relay_pin_info_json().is_none());
}

/// An entered pin without its version: a matching key adopts the relay's
/// signed version, and it is reported for the app to persist.
#[test]
fn rp3_unknown_version_adopts_the_signed_version_on_a_match() {
    let relay = test_relay();
    let (mut inner, mut rx, _rec) = client(
        Some(encode_pin(&relay.verifying_key().to_bytes())),
        None,
        true,
    );
    feed_signaling(&mut inner, hello_response_from([0x4e; 32], &relay, 3, &[]));
    assert!(inner.is_connected);
    assert_eq!(publishes(&mut rx), 1);
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(info["source"], "pinned");
    assert_eq!(info["version"], 3);
    assert_eq!(inner.config.relay_pin_version, Some(3));
}

/// The adopted version lets the relay's next legitimate rotation through,
/// where version 0 would have been refused as "changed".
#[test]
fn rp6_adopted_version_follows_the_next_rotation() {
    let old = SigningKey::from_bytes(&[0x21; 32]);
    let new = test_relay();
    let link = sign_relay_link(&old, &new.verifying_key().to_bytes(), 4);
    let (mut inner, _rx, _rec) = client(
        Some(encode_pin(&old.verifying_key().to_bytes())),
        None,
        false,
    );
    feed_signaling(&mut inner, hello_response_from([0x4e; 32], &old, 3, &[]));
    assert!(inner.is_connected);
    inner.handle_transport_disconnected();
    inner.handle_transport_reconnected();
    feed_signaling(
        &mut inner,
        hello_response_from([0x4f; 32], &new, 4, std::slice::from_ref(&link)),
    );
    assert!(inner.is_connected, "rotation from the adopted version 3");
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(info["source"], "rotated");
    assert_eq!(info["version"], 4);

    // Unknown version and an already rotated relay: walked from the link
    // the pinned key signed.
    let (mut inner, _rx, _rec) = client(
        Some(encode_pin(&old.verifying_key().to_bytes())),
        None,
        false,
    );
    feed_signaling(
        &mut inner,
        hello_response_from([0x4e; 32], &new, 4, &[link]),
    );
    assert!(inner.is_connected);

    // Unknown version, different key, no chain from the pinned key: refused.
    let stranger = SigningKey::from_bytes(&[0x22; 32]);
    let forged = sign_relay_link(&stranger, &new.verifying_key().to_bytes(), 4);
    let (mut inner, mut rx, rec) = client(
        Some(encode_pin(&old.verifying_key().to_bytes())),
        None,
        false,
    );
    feed_signaling(
        &mut inner,
        hello_response_from([0x4e; 32], &new, 4, &[forged]),
    );
    assert!(!inner.is_connected);
    assert_eq!(publishes(&mut rx), 0);
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayIdentityChanged)));
}

/// Task 10b minor: a correctly signed link that skips a version is no
/// continuation, at the start or in the middle, and a pin at u32::MAX
/// (no next version) walks to a refusal, not an overflow.
#[test]
fn rp6_signed_version_skips_and_u32_max_are_refused() {
    use crate::relay_pin::{walk_relay_chain, RelayPinError};
    let k0 = SigningKey::from_bytes(&[0x31; 32]);
    let k1 = SigningKey::from_bytes(&[0x32; 32]);
    let k2 = SigningKey::from_bytes(&[0x33; 32]);
    let (p0, p1, p2) = (
        k0.verifying_key().to_bytes(),
        k1.verifying_key().to_bytes(),
        k2.verifying_key().to_bytes(),
    );
    let pin = encode_pin(&p0);
    let good = [sign_relay_link(&k0, &p1, 1), sign_relay_link(&k1, &p2, 2)];
    assert_eq!(walk_relay_chain(&good, &pin, 0, &p2, 2), Ok(()));
    // Start skips 0 -> 2.
    let skip_start = [sign_relay_link(&k0, &p1, 2)];
    assert_eq!(
        walk_relay_chain(&skip_start, &pin, 0, &p1, 2),
        Err(RelayPinError::BadChain)
    );
    // Middle skips 1 -> 3.
    let skip_mid = [sign_relay_link(&k0, &p1, 1), sign_relay_link(&k1, &p2, 3)];
    assert_eq!(
        walk_relay_chain(&skip_mid, &pin, 0, &p2, 3),
        Err(RelayPinError::BadChain)
    );
    // Pinned at u32::MAX: no link can follow it.
    let wrap = [sign_relay_link(&k0, &p1, 0)];
    assert_eq!(
        walk_relay_chain(&wrap, &pin, u32::MAX, &p1, 0),
        Err(RelayPinError::BadChain)
    );
    let at_max = [sign_relay_link(&k0, &p1, u32::MAX)];
    assert_eq!(
        walk_relay_chain(&at_max, &pin, u32::MAX - 1, &p1, u32::MAX),
        Ok(())
    );
}

/// Part J: an invite pre-sets the pin before the first connect (version
/// unknown, as the app saves it). A first relay with a different key is
/// refused through the relay-identity-changed path, never trusted on first
/// use; the invite's own relay is accepted as pinned.
#[test]
fn invite_pin_is_enforced_on_the_first_connect() {
    let invite_for = |key: &SigningKey| {
        let link = format!(
            "rchat://relay?u=ws%3A%2F%2F127.0.0.1%3A18443&pin={}",
            encode_pin(&key.verifying_key().to_bytes())
        );
        crate::invite::parse_invite_allowing_loopback_ws(&link).unwrap()
    };
    let first_connect = |invite: crate::invite::Invite| {
        let (mut inner, rx) = inner_with_identity(0xA1);
        inner.config = ClientConfig {
            server_url: invite.url,
            relay_pin: Some(invite.pin),
            relay_pin_version: None,
            relay_pin_strict: false,
            ..ClientConfig::default()
        };
        let rec = Recorder::default();
        inner.callbacks = Some(Box::new(rec.clone()));
        inner.publish_requested = true;
        inner.is_connected = false;
        (inner, rx, rec)
    };

    let other = SigningKey::from_bytes(&[0x12; 32]);
    let (mut inner, mut rx, rec) = first_connect(invite_for(&other));
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(!inner.is_connected, "a mismatching first relay is refused");
    assert_eq!(publishes(&mut rx), 0);
    assert!(rec
        .take()
        .contains(&format!("error:{}", RChatError::RelayIdentityChanged)));
    assert!(inner.relay_pin_info_json().is_none());

    let (mut inner, mut rx, _rec) = first_connect(invite_for(&test_relay()));
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected);
    assert_eq!(publishes(&mut rx), 1);
    let info: serde_json::Value =
        serde_json::from_str(&inner.relay_pin_info_json().unwrap()).unwrap();
    assert_eq!(
        info["source"], "pinned",
        "checked against the invite, not TOFU"
    );
}
