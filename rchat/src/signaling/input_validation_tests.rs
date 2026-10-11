//! Hostile-input tests against the real server (release blockers from the
//! S3 security review): malformed identity material must be rejected at the
//! boundary with an error frame, never panic (release builds abort on panic,
//! which would take the relay down), never be stored, and never be echoed.

use crate::config::ServerConfig;
use crate::protocol::signaling::{
    KeyBundle, LookupKeyBundlePayload, Payload, PublishKeyBundlePayload, SignalingMessage,
    MSG_TYPE_ERROR, MSG_TYPE_HELLO, MSG_TYPE_LOOKUP_KEY_BUNDLE, MSG_TYPE_PUBLISH_KEY_BUNDLE,
    MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE,
};
use crate::protocol::unified::{ControlErrorCode, ControlMessage, FrameBuilder, UnifiedFrame};
use crate::protocol::CircuitId;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use super::test_support::{self, TestIdentity};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn test_config() -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        // Plaintext test server on loopback (the --no-tls dev mode).
        insecure_no_tls: true,
        max_connections_per_ip: 0,
        dev_origin: Some(test_support::DEV_ORIGIN.to_string()),
        ..ServerConfig::default()
    }
}

struct Running {
    addr: SocketAddr,
    state: super::RelayState,
}

async fn start(config: ServerConfig) -> Running {
    let (addr, state) = test_support::start(config).await;
    Running { addr, state }
}

async fn connect(addr: SocketAddr) -> Ws {
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        connect_async(format!("ws://{addr}/")),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    ws
}

fn hex32() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn bundle(identity: &str) -> KeyBundle {
    KeyBundle {
        identity_key: identity.to_string(),
        identity_agreement_key: hex32(),
        signed_pre_key: hex32(),
        signed_pre_key_signature: "ab".repeat(64),
        one_time_pre_keys: Vec::new(),
    }
}

fn publish(b: KeyBundle) -> Message {
    UnifiedFrame::signaling(SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        Payload::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            PublishKeyBundlePayload {
                key_bundle: b,
                conn_signature: "cd".repeat(64),
            },
        ),
    ))
    .encode()
}

enum Reply {
    SignalingError(String),
    PublishOk,
    ControlError(ControlErrorCode),
    Other,
    Closed,
    Silent,
}

/// Next reply that is not a keepalive.
async fn next_reply(ws: &mut Ws, wait: Duration) -> Reply {
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Err(_) => return Reply::Silent,
            Ok(None) | Ok(Some(Err(_))) => return Reply::Closed,
            Ok(Some(Ok(Message::Close(_)))) => return Reply::Closed,
            Ok(Some(Ok(m))) => match UnifiedFrame::decode(&m) {
                Ok(UnifiedFrame::Keepalive(_)) => continue,
                Ok(UnifiedFrame::Signaling(s)) if s.msg_type == MSG_TYPE_ERROR => {
                    return Reply::SignalingError(serde_json::to_string(&s.payload).unwrap())
                }
                Ok(UnifiedFrame::Signaling(s))
                    if s.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE =>
                {
                    let ok = s
                        .payload
                        .deserialize_data::<serde_json::Value>()
                        .ok()
                        .and_then(|d| d.get("status").cloned())
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .map(|v| v.eq_ignore_ascii_case("ok"))
                        .unwrap_or(false);
                    return if ok { Reply::PublishOk } else { Reply::Other };
                }
                Ok(UnifiedFrame::Control(ControlMessage::Error { code, .. })) => {
                    return Reply::ControlError(code)
                }
                _ => return Reply::Other,
            },
        }
    }
}

async fn published_peer(addr: SocketAddr) -> (Ws, String) {
    let id = TestIdentity::random();
    let ws = test_support::authed(addr, &id).await;
    (ws, id.hex)
}

/// The server is still accepting and serving connections.
async fn assert_alive(addr: SocketAddr) {
    let (_ws, _id) = published_peer(addr).await;
}

#[tokio::test]
async fn malformed_key_bundles_are_rejected_without_panic() {
    let srv = start(test_config()).await;
    let good = hex32();
    // 15 ASCII bytes + a 2-byte char: slicing [..16] would panic.
    let multibyte_at_16 = format!("{}\u{e9}{}", "a".repeat(15), "b".repeat(47));
    let cases: Vec<(&str, KeyBundle)> = vec![
        ("multibyte identity", bundle(&multibyte_at_16)),
        ("short identity", bundle("abcd")),
        ("empty identity", bundle("")),
        ("overlong identity", bundle(&"a".repeat(65))),
        ("uppercase identity", bundle(&good.to_uppercase())),
        ("non-hex identity", bundle(&"g".repeat(64))),
        // Long, but under `MAX_SIGNALING_BYTES` so it reaches validation
        // (larger frames are closed unparsed: see the R-1 test).
        ("huge identity", bundle(&"a".repeat(10_000))),
        (
            "bad agreement key",
            KeyBundle {
                identity_agreement_key: "\u{1F600}".repeat(16),
                ..bundle(&hex32())
            },
        ),
        (
            "bad signed pre-key",
            KeyBundle {
                signed_pre_key: "zz".into(),
                ..bundle(&hex32())
            },
        ),
        (
            "bad signature length",
            KeyBundle {
                signed_pre_key_signature: "ab".repeat(10),
                ..bundle(&hex32())
            },
        ),
        (
            "bad one-time pre-key",
            KeyBundle {
                one_time_pre_keys: vec!["x".into()],
                ..bundle(&hex32())
            },
        ),
        (
            "one-time pre-keys present",
            KeyBundle {
                one_time_pre_keys: vec![hex32()],
                ..bundle(&hex32())
            },
        ),
        (
            "empty signature",
            KeyBundle {
                signed_pre_key_signature: String::new(),
                ..bundle(&hex32())
            },
        ),
    ];
    for (name, b) in cases {
        // A malformed publish is a failed publish (spec §4.3): it is counted,
        // answered with an error that does not echo the input, and the
        // connection is closed - so every case needs its own connection.
        let before = crate::metrics::rejections(crate::metrics::REJECT_KEY_AUTH);
        let mut ws = connect(srv.addr).await;
        let identity = b.identity_key.clone();
        ws.send(publish(b)).await.unwrap();
        match next_reply(&mut ws, Duration::from_secs(5)).await {
            Reply::SignalingError(text) => {
                if identity.len() > 8 {
                    assert!(!text.contains(&identity), "{name}: error echoes input");
                }
            }
            _ => panic!("{name}: expected a signaling error reply"),
        }
        assert!(
            matches!(
                next_reply(&mut ws, Duration::from_secs(5)).await,
                Reply::Closed
            ),
            "{name}: connection left open after a malformed publish"
        );
        assert!(
            crate::metrics::rejections(crate::metrics::REJECT_KEY_AUTH) > before,
            "{name}: not counted as a key-auth rejection"
        );
        assert!(
            srv.state.identity_to_client.is_empty(),
            "{name}: malformed identity was stored"
        );
    }
    assert_alive(srv.addr).await;
}

#[tokio::test]
async fn malformed_circuit_asks_are_rejected_and_not_stored() {
    let srv = start(test_config()).await;
    let (mut ws, _id) = published_peer(srv.addr).await;
    let mut good_knock = vec![0u8; 2048];
    good_knock[0] = 0x02;
    let mut v1_knock = good_knock.clone();
    v1_knock[0] = 0x00;
    let cases: Vec<(&str, Message)> = vec![
        (
            "empty target",
            FrameBuilder::circuit_ask(vec![], vec![2; 32], good_knock.clone(), None).encode(),
        ),
        (
            "short target",
            FrameBuilder::circuit_ask(vec![1; 31], vec![2; 32], good_knock.clone(), None).encode(),
        ),
        (
            "huge target",
            FrameBuilder::circuit_ask(vec![7; 1 << 20], vec![2; 32], good_knock.clone(), None)
                .encode(),
        ),
        (
            "short ephemeral",
            FrameBuilder::circuit_ask(vec![1; 32], vec![2; 31], good_knock.clone(), None).encode(),
        ),
        (
            "knock 2047 bytes",
            FrameBuilder::circuit_ask(vec![1; 32], vec![2; 32], vec![0x02; 2047], None).encode(),
        ),
        (
            "knock with v1 prefix",
            FrameBuilder::circuit_ask(vec![1; 32], vec![2; 32], v1_knock, None).encode(),
        ),
        (
            "v1 CreateCircuit",
            FrameBuilder::create_circuit(vec![1; 32], Some(vec![2; 32])).encode(),
        ),
    ];
    for (name, msg) in cases {
        ws.send(msg).await.unwrap();
        match next_reply(&mut ws, Duration::from_secs(5)).await {
            Reply::ControlError(ControlErrorCode::InvalidMessage) => {}
            _ => panic!("{name}: expected an InvalidMessage control error"),
        }
        assert!(srv.state.pending_asks.is_empty(), "{name}: ask was stored");
    }
    assert_alive(srv.addr).await;
}

#[tokio::test]
async fn malformed_lookup_and_receipts_are_rejected() {
    let srv = start(test_config()).await;
    let (mut ws, _id) = published_peer(srv.addr).await;

    for key in [vec![], vec![1u8; 3], vec![1u8; 33]] {
        let msg = SignalingMessage::new(
            MSG_TYPE_LOOKUP_KEY_BUNDLE,
            Payload::new(
                MSG_TYPE_LOOKUP_KEY_BUNDLE,
                LookupKeyBundlePayload { identity_key: key },
            ),
        );
        ws.send(UnifiedFrame::signaling(msg).encode())
            .await
            .unwrap();
        assert!(matches!(
            next_reply(&mut ws, Duration::from_secs(5)).await,
            Reply::SignalingError(_)
        ));
    }

    for id in [
        String::new(),
        "\u{e9}".repeat(8),
        "a".repeat(7) + "\u{e9}",
        "x".repeat(5000),
        "has space".to_string(),
    ] {
        for receipt in [
            ControlMessage::DeliveryReceipt {
                message_id: id.clone(),
                delivered_at: 1,
                circuit_id: CircuitId::generate(),
            },
            ControlMessage::ReadReceipt {
                message_id: id.clone(),
                read_at: 1,
                circuit_id: CircuitId::generate(),
            },
        ] {
            ws.send(UnifiedFrame::control(receipt).encode())
                .await
                .unwrap();
            assert!(matches!(
                next_reply(&mut ws, Duration::from_secs(5)).await,
                Reply::ControlError(ControlErrorCode::InvalidMessage)
            ));
        }
    }
    assert_alive(srv.addr).await;
}

/// Fuzz-style: a stream of random and mutated messages on several real
/// connections. Whatever happens to those connections, the server must stay
/// up and keep serving new clients.
#[tokio::test]
async fn random_hostile_input_never_takes_the_server_down() {
    // Test builds unwind, so a panicking connection task would not take the
    // test server down the way `panic = "abort"` takes a release relay down.
    // Record any panic raised from non-test server code instead.
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SERVER_PANICS: AtomicUsize = AtomicUsize::new(0);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let in_server = info
            .location()
            .map(|l| l.file().starts_with("src/") && !l.file().ends_with("_tests.rs"))
            .unwrap_or(false);
        if in_server {
            SERVER_PANICS.fetch_add(1, Ordering::SeqCst);
        }
        previous(info);
    }));

    let srv = start(test_config()).await;
    let samples = [
        "a",
        "\u{e9}",
        "\u{1F600}",
        "0",
        "f",
        "G",
        " ",
        "\u{0}",
        "\"",
        "\\",
    ];
    for round in 0..8 {
        let mut ws = connect(srv.addr).await;
        for i in 0..40 {
            let len = (rand::random::<u16>() % 140) as usize;
            let s: String = (0..len)
                .map(|_| samples[rand::random::<usize>() % samples.len()])
                .collect();
            let bytes: Vec<u8> = (0..(rand::random::<u16>() % 70))
                .map(|_| rand::random())
                .collect();
            let msg = match (round + i) % 7 {
                0 => publish(bundle(&s)),
                1 => publish(KeyBundle {
                    identity_agreement_key: s.clone(),
                    signed_pre_key: s.clone(),
                    ..bundle(&hex32())
                }),
                2 => FrameBuilder::create_circuit(bytes.clone(), Some(bytes.clone())).encode(),
                3 => UnifiedFrame::control(ControlMessage::DeliveryReceipt {
                    message_id: s.clone(),
                    delivered_at: 0,
                    circuit_id: CircuitId::generate(),
                })
                .encode(),
                4 => {
                    let mut raw = vec![rand::random::<u8>() % 5];
                    raw.extend_from_slice(&bytes);
                    Message::Binary(raw)
                }
                5 => Message::Text(format!(
                    "{{\"id\":\"{}\",\"type\":\"{}\",\"payload\":{{\"type\":\"x\",\"data\":{{\"key_bundle\":{{\"identity_key\":\"{}\"}}}}}},\"timestamp\":{}}}",
                    s.escape_default(),
                    [MSG_TYPE_PUBLISH_KEY_BUNDLE, MSG_TYPE_HELLO, MSG_TYPE_LOOKUP_KEY_BUNDLE][i % 3],
                    s.escape_default(),
                    crate::protocol::timestamp()
                )),
                _ => FrameBuilder::create_circuit(vec![9; 32], None).encode(),
            };
            if ws.send(msg).await.is_err() {
                break;
            }
        }
        // Drain whatever came back (errors, acks, or a close).
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        {}
    }
    assert_alive(srv.addr).await;
    assert_eq!(
        SERVER_PANICS.load(Ordering::SeqCst),
        0,
        "server code panicked on hostile input"
    );
}

/// R-1: a signaling frame over `MAX_SIGNALING_BYTES` closes the connection
/// before any JSON is parsed - here a correctly signed publish padded with
/// an unknown junk array, sent as a text frame and as a binary 0x01 frame.
/// It is never accepted and maps nothing.
#[tokio::test]
async fn oversized_signaling_frames_close_the_connection_unparsed() {
    let srv = start(test_config()).await;
    for binary in [false, true] {
        let id = TestIdentity::random();
        let mut ws = connect(srv.addr).await;
        let nonce = test_support::hello(&mut ws).await;
        let Message::Text(json) =
            test_support::publish_message(&id, &nonce, &test_support::dev_binding())
        else {
            panic!("publish is a text frame");
        };
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["payload"]["data"]["junk"] = serde_json::Value::from(vec![0u8; 10_000]);
        let padded = serde_json::to_string(&v).unwrap();
        assert!(padded.len() > crate::limits::MAX_SIGNALING_BYTES);
        let frame = if binary {
            let mut b = vec![crate::protocol::unified::FRAME_TYPE_SIGNALING];
            b.extend_from_slice(padded.as_bytes());
            Message::Binary(b)
        } else {
            Message::Text(padded)
        };
        let oversized = crate::metrics::rejections(crate::metrics::REJECT_OVERSIZED_FRAME);
        ws.send(frame).await.unwrap();
        assert!(
            matches!(
                next_reply(&mut ws, Duration::from_secs(5)).await,
                Reply::Closed
            ),
            "binary={binary}: oversized signaling frame left the connection open"
        );
        assert!(crate::metrics::rejections(crate::metrics::REJECT_OVERSIZED_FRAME) > oversized);
        assert!(srv.state.identity_to_client.is_empty());
    }
    // A normal, unpadded publish is still accepted.
    assert_alive(srv.addr).await;
}
