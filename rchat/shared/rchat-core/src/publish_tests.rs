//! K10 and RF2: deferred, channel-bound publish (spec §4.4 "Connect and publish").

use crate::keyauth::{self, SignedBundle};
use crate::protocol::SignalingMessage;
use crate::test_support::*;
use crate::RChatError;

/// Every publish_key_bundle message sent, as (bundle, conn_signature).
fn publishes(msgs: &[SignalingMessage]) -> Vec<(SignedBundle, [u8; 64])> {
    msgs.iter()
        .filter(|m| m.msg_type == "publish_key_bundle")
        .map(|m| {
            let data = &m.payload.inner["data"];
            let kb = &data["key_bundle"];
            let h = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
            assert!(kb["one_time_pre_keys"].as_array().unwrap().is_empty());
            assert!(kb.get("signed_pre_key").is_none(), "v3 has no SPK");
            use base64::Engine as _;
            let kem = base64::engine::general_purpose::STANDARD
                .decode(kb["kem_pk"].as_str().unwrap())
                .unwrap();
            let bundle = SignedBundle::from_wire(
                &h(&kb["identity_key"]),
                &h(&kb["identity_agreement_key"]),
                &kem,
                &h(&kb["bundle_signature"]),
            )
            .unwrap();
            let sig: [u8; 64] = h(&data["conn_signature"]).try_into().unwrap();
            (bundle, sig)
        })
        .collect()
}

/// K10: nothing is published before the challenge; the proof covers the
/// challenge and this connection's binding; published only on the response.
#[test]
fn k10_publish_waits_for_the_challenge_and_the_response() {
    let (mut inner, mut rx) = inner_with_identity(1);
    inner.is_connected = false;
    inner.request_publish().unwrap();
    assert!(
        publishes(&sent_signaling(&mut rx)).is_empty(),
        "no publish before hello_response"
    );

    let challenge = [0x4e; 32];
    feed_signaling(&mut inner, hello_response(challenge));
    assert!(inner.is_connected);
    let sent = publishes(&sent_signaling(&mut rx));
    assert_eq!(sent.len(), 1);
    let (bundle, sig) = &sent[0];
    keyauth::verify_bundle(bundle).unwrap();
    keyauth::verify_conn(&challenge, &TEST_BINDING, bundle, sig).unwrap();
    assert!(
        !inner.is_key_bundle_published,
        "published only on the response"
    );

    feed_signaling(&mut inner, publish_ok([0x55; 32]));
    assert!(inner.is_key_bundle_published);
    assert_eq!(
        inner.auth_challenge,
        Some([0x55; 32]),
        "next_challenge stored"
    );
}

/// K10: hello is sent again on reconnect and the bundle is re-published
/// over the new challenge and the new connection's binding.
#[test]
fn k10_reconnect_sends_hello_again_and_republishes() {
    let (mut inner, mut rx) = published(1);
    let epoch = inner.transport_epoch;
    inner
        .websocket
        .as_ref()
        .unwrap()
        .set_channel_binding_for_test(Some([0x43; 32]));
    inner.handle_transport_reconnected();
    let sent = sent_signaling(&mut rx);
    let hello = sent
        .iter()
        .find(|m| m.msg_type == "hello")
        .expect("hello re-sent");
    assert_eq!(
        hello.payload.inner["data"]["supported_versions"],
        serde_json::json!([3])
    );
    assert!(!inner.is_key_bundle_published);
    assert!(!inner.is_connected);
    assert_eq!(inner.transport_epoch, epoch + 1);

    let fresh = [0x61; 32];
    feed_signaling(&mut inner, hello_response_bound(fresh, [0x43; 32]));
    let p = publishes(&sent_signaling(&mut rx));
    assert_eq!(p.len(), 1);
    keyauth::verify_conn(&fresh, &[0x43; 32], &p[0].0, &p[0].1).unwrap();
}

/// K10: without a channel binding the publish is refused with NoChannelBinding.
/// The relay gate needs the binding too, so it fails first and the transport
/// is shut down (Task 11b).
#[test]
fn k10_without_channel_binding_publish_is_refused() {
    let (mut inner, mut rx) = inner_with_identity(1);
    let rec = Recorder::default();
    inner.callbacks = Some(Box::new(rec.clone()));
    inner
        .websocket
        .as_ref()
        .unwrap()
        .set_channel_binding_for_test(None);
    inner.request_publish().unwrap();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(publishes(&sent_signaling(&mut rx)).is_empty());
    let expected = format!("error:{}", RChatError::NoChannelBinding);
    assert!(rec.take().contains(&expected));
    assert!(inner.websocket.is_none(), "transport shut down");
    assert!(matches!(
        inner.request_publish(),
        Err(RChatError::NotConnected)
    ));
    assert!(!inner.is_key_bundle_published);
}

/// K10: a second request while a publish is in flight (or done) sends nothing.
#[test]
fn k10_duplicate_publish_requests_send_one_publish() {
    let (mut inner, mut rx) = inner_with_identity(1);
    inner.request_publish().unwrap();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert_eq!(publishes(&sent_signaling(&mut rx)).len(), 1);
    inner.request_publish().unwrap();
    assert!(publishes(&sent_signaling(&mut rx)).is_empty(), "in flight");
    feed_signaling(&mut inner, publish_ok([0x55; 32]));
    inner.request_publish().unwrap();
    assert!(
        publishes(&sent_signaling(&mut rx)).is_empty(),
        "already published"
    );
}

/// RF2: the connection drops mid-publish. A late response from the old
/// connection is ignored; the re-publish is signed over the NEW challenge
/// and the NEW binding, never the stale ones.
#[test]
fn rf2_reconnect_mid_publish_never_signs_stale_challenge() {
    let (mut inner, mut rx) = inner_with_identity(1);
    inner.request_publish().unwrap();
    let old = [0x4e; 32];
    feed_signaling(&mut inner, hello_response(old));
    assert_eq!(publishes(&sent_signaling(&mut rx)).len(), 1);

    inner.handle_transport_disconnected();
    inner
        .websocket
        .as_ref()
        .unwrap()
        .set_channel_binding_for_test(Some([0x43; 32]));
    inner.handle_transport_reconnected();
    feed_signaling(&mut inner, publish_ok([0x55; 32]));
    assert!(
        !inner.is_key_bundle_published,
        "a stale response does not count"
    );
    assert_eq!(
        inner.auth_challenge, None,
        "a stale next_challenge is not adopted"
    );

    let fresh = [0x61; 32];
    feed_signaling(&mut inner, hello_response_bound(fresh, [0x43; 32]));
    let second = publishes(&sent_signaling(&mut rx));
    assert_eq!(second.len(), 1);
    let (bundle, sig) = &second[0];
    keyauth::verify_conn(&fresh, &[0x43; 32], bundle, sig).unwrap();
    assert!(keyauth::verify_conn(&old, &TEST_BINDING, bundle, sig).is_err());
    assert!(keyauth::verify_conn(&fresh, &TEST_BINDING, bundle, sig).is_err());
    feed_signaling(&mut inner, publish_ok([0x56; 32]));
    assert!(inner.is_key_bundle_published);
}

/// AuthenticationFailed: reported once as KeyAuthRejected, transport shut, no retry.
#[test]
fn authentication_failure_reports_key_auth_rejected_and_stops() {
    let (mut inner, mut rx) = inner_with_identity(1);
    let rec = Recorder::default();
    inner.callbacks = Some(Box::new(rec.clone()));
    inner.request_publish().unwrap();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    drain(&mut rx);
    feed_signaling(&mut inner, error_message("AuthenticationFailed"));
    let events = rec.take();
    assert!(events.contains(&format!("error:{}", RChatError::KeyAuthRejected)));
    assert!(events.contains(&"status:Error".to_string()));
    assert!(!inner.is_key_bundle_published);
    assert!(!inner.is_connected);
    assert!(inner.websocket.is_none(), "transport shut down");
    assert!(
        matches!(inner.request_publish(), Err(RChatError::NotConnected)),
        "no retry loop"
    );
    assert!(
        sent_controls(&mut rx).is_empty(),
        "nothing else sent after the failure"
    );
}

/// Version gate: a v1 or v2 hello_response (v3 hard cutover), a malformed
/// challenge, or VersionMismatch → ServerTooNew.
#[test]
fn version_or_challenge_problems_report_server_too_new() {
    let cases = [
        hello_response_raw(1, Some(&"4e".repeat(32))),
        hello_response_raw(2, Some(&"4e".repeat(32))),
        hello_response_raw(3, None),
        hello_response_raw(3, Some("not-hex")),
        error_message("VersionMismatch"),
    ];
    for msg in cases {
        let (mut inner, mut rx) = inner_with_identity(1);
        let rec = Recorder::default();
        inner.callbacks = Some(Box::new(rec.clone()));
        inner.is_connected = false;
        inner.request_publish().unwrap();
        feed_signaling(&mut inner, msg);
        assert!(rec
            .take()
            .contains(&format!("error:{}", RChatError::ServerTooNew)));
        assert!(!inner.is_connected);
        assert!(inner.websocket.is_none());
        assert!(sent_signaling(&mut rx)
            .iter()
            .all(|m| m.msg_type != "publish_key_bundle"));
    }
}

/// Connected fires on hello_response; after a reconnect, on_reconnect follows it.
#[test]
fn connected_and_reconnect_callbacks_fire_after_hello_response() {
    let (mut inner, _rx) = inner_with_identity(1);
    let rec = Recorder::default();
    inner.callbacks = Some(Box::new(rec.clone()));
    inner.is_connected = false;
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert_eq!(rec.take(), vec!["status:Connected".to_string()]);
    inner.handle_transport_reconnected();
    assert!(
        rec.take().is_empty(),
        "nothing until the new hello_response"
    );
    feed_signaling(&mut inner, hello_response([0x61; 32]));
    assert_eq!(
        rec.take(),
        vec!["status:Connected".to_string(), "reconnect".to_string()]
    );
}

/// Review fix: after disconnect + connect, a hello_response still queued from
/// the retired client is dropped (generation gate): no publish is signed over
/// the old challenge and is_connected is unchanged. Once the client is retired
/// after a protocol failure, its events are dropped too.
#[test]
fn stale_hello_response_from_a_retired_connection_is_dropped() {
    use crate::protocol::Frame;
    use crate::CoreEvent;
    let (mut inner, mut rx) = inner_with_identity(1);
    inner.is_connected = false;
    inner.request_publish().unwrap();
    let old_generation = inner.connection_generation;
    let old = [0x4e; 32];

    // disconnect_transport_only() + connect(): the old client is retired and
    // the new connection has sent its own hello.
    inner.retire_connection();
    inner.hello_outstanding = true;
    inner
        .websocket
        .as_ref()
        .unwrap()
        .set_channel_binding_for_test(Some([0x43; 32]));
    inner.handle_event(
        old_generation,
        CoreEvent::Frame(Box::new(Frame::Signaling(hello_response(old)))),
    );
    assert!(
        publishes(&sent_signaling(&mut rx)).is_empty(),
        "no publish over the old challenge"
    );
    assert!(!inner.is_connected, "is_connected unchanged");
    assert_eq!(inner.auth_challenge, None);

    let fresh = [0x61; 32];
    let current = inner.connection_generation;
    inner.handle_event(
        current,
        CoreEvent::Frame(Box::new(Frame::Signaling(hello_response_bound(
            fresh, [0x43; 32],
        )))),
    );
    let p = publishes(&sent_signaling(&mut rx));
    assert_eq!(p.len(), 1);
    keyauth::verify_conn(&fresh, &[0x43; 32], &p[0].0, &p[0].1).unwrap();
    assert!(keyauth::verify_conn(&old, &[0x43; 32], &p[0].0, &p[0].1).is_err());

    // After a protocol failure the generation moves on: late events are dropped.
    inner.handle_event(
        current,
        CoreEvent::Frame(Box::new(Frame::Signaling(error_message(
            "AuthenticationFailed",
        )))),
    );
    assert!(inner.websocket.is_none());
    inner.handle_event(current, CoreEvent::Reconnected);
    inner.handle_event(
        current,
        CoreEvent::Frame(Box::new(Frame::Signaling(hello_response_bound(
            fresh, [0x43; 32],
        )))),
    );
    assert!(
        !inner.is_connected,
        "a retired client cannot revive the state"
    );
}

/// Review fix: a hello_response with no hello outstanding is ignored, so an
/// unsolicited one neither connects nor clears an in-flight publish.
#[test]
fn hello_response_without_an_outstanding_hello_is_ignored() {
    let (mut inner, mut rx) = inner_with_identity(1);
    inner.is_connected = false;
    inner.hello_outstanding = false;
    inner.request_publish().unwrap();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(!inner.is_connected);
    assert_eq!(inner.auth_challenge, None);
    assert!(publishes(&sent_signaling(&mut rx)).is_empty());

    // The answered hello is consumed: a second hello_response is unsolicited.
    inner.hello_outstanding = true;
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert_eq!(publishes(&sent_signaling(&mut rx)).len(), 1);
    feed_signaling(&mut inner, hello_response([0x61; 32]));
    assert!(inner.publish_in_flight, "in-flight publish not cleared");
    assert_eq!(
        inner.auth_challenge, None,
        "unsolicited challenge not adopted"
    );
    assert!(publishes(&sent_signaling(&mut rx)).is_empty());
}

/// Review fix: connect() refuses while a WebSocketClient is still installed
/// (live, or waiting for the handshake / auto-reconnect).
#[test]
fn connect_is_rejected_while_a_client_is_installed() {
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    client.inner.try_write().unwrap().websocket = Some(crate::transport::WebSocketClient::new(
        crate::transport::TransportConfig::default(),
    ));
    match client.connect() {
        Err(RChatError::ConnectionFailed { message }) => assert_eq!(message, "Already connected"),
        other => panic!("expected Already connected, got {other:?}"),
    }
}
