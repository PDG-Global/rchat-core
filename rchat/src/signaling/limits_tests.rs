//! Tests of resource limits against the real accept loop and connection
//! handler (plain TCP, `--no-tls` development mode).

use super::Server;
use crate::config::ServerConfig;
use crate::metrics;
use crate::protocol::unified::{KeepaliveMessage, UnifiedFrame};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
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
        dev_origin: Some(test_support::DEV_ORIGIN.to_string()),
        ..ServerConfig::default()
    }
}

/// A binary message of exactly `len` bytes with the keepalive frame type and
/// a body that does not decode (so the server ignores it without replying).
fn junk(len: usize) -> Message {
    let mut m = vec![0xFFu8; len];
    m[0] = 0x04;
    Message::Binary(m)
}

async fn start(config: ServerConfig) -> SocketAddr {
    let server = Server::new(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    addr
}

async fn ws_connect(addr: SocketAddr) -> anyhow::Result<Ws> {
    let url = format!("ws://{addr}/");
    let (ws, _) = tokio::time::timeout(Duration::from_secs(5), connect_async(url)).await??;
    Ok(ws)
}

/// Send a keepalive ping and wait for any binary reply within `within`.
async fn ping_pong(ws: &mut Ws, within: Duration) -> bool {
    if ws
        .send(UnifiedFrame::keepalive_ping().encode())
        .await
        .is_err()
    {
        return false;
    }
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(m @ Message::Binary(_)))) => {
                // Ignore the server's own keepalive pings; wait for our pong.
                if let Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Pong { .. })) =
                    UnifiedFrame::decode(&m)
                {
                    return true;
                }
            }
            Ok(Some(Ok(_))) => continue,
            _ => return false,
        }
    }
}

/// True if the server closes the connection within `within`.
async fn closed_within(ws: &mut Ws, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return false, // still open
            Ok(None) | Ok(Some(Err(_))) => return true,
            Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => continue, // e.g. server keepalive
        }
    }
}

#[tokio::test]
async fn n_plus_one_connection_is_refused_and_slot_is_released() {
    let before = metrics::rejections(metrics::REJECT_MAX_CONNECTIONS);
    let addr = start(ServerConfig {
        max_connections: 2,
        max_connections_per_ip: 0,
        ..test_config()
    })
    .await;

    let mut a = ws_connect(addr).await.expect("1st connection");
    let mut b = ws_connect(addr).await.expect("2nd connection");
    assert!(ping_pong(&mut a, Duration::from_secs(5)).await);
    assert!(ping_pong(&mut b, Duration::from_secs(5)).await);

    // The 3rd TCP connection is closed before any HTTP/WebSocket work.
    let mut raw = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .expect("server should close the refused socket promptly")
        .unwrap_or(0);
    assert_eq!(n, 0, "refused connection must get no bytes");
    assert!(
        ws_connect(addr).await.is_err(),
        "WebSocket over the cap must fail"
    );
    assert!(metrics::rejections(metrics::REJECT_MAX_CONNECTIONS) >= before + 2);

    // Existing connections are unaffected.
    assert!(ping_pong(&mut a, Duration::from_secs(5)).await);

    // Closing one frees its slot.
    b.close(None).await.ok();
    drop(b);
    let mut ok = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(mut c) = ws_connect(addr).await {
            ok = ping_pong(&mut c, Duration::from_secs(5)).await;
            if ok {
                break;
            }
        }
    }
    assert!(ok, "slot should be released after a client disconnects");
}

#[tokio::test]
async fn per_ip_cap_refuses_extra_connection_from_same_address() {
    let before = metrics::rejections(metrics::REJECT_PER_IP_CAP);
    let addr = start(ServerConfig {
        max_connections: 100,
        max_connections_per_ip: 1,
        ..test_config()
    })
    .await;

    let mut a = ws_connect(addr).await.expect("1st connection");
    assert!(ping_pong(&mut a, Duration::from_secs(5)).await);
    assert!(
        ws_connect(addr).await.is_err(),
        "2nd connection from 127.0.0.1 must be refused"
    );
    assert!(metrics::rejections(metrics::REJECT_PER_IP_CAP) > before);
    assert!(ping_pong(&mut a, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn oversized_message_closes_connection() {
    let before = metrics::rejections(metrics::REJECT_OVERSIZED_FRAME);
    let max = 64 * 1024;
    let addr = start(ServerConfig {
        max_message_bytes: max,
        ..test_config()
    })
    .await;

    // A message at the limit is accepted (connection stays usable).
    let mut ok = ws_connect(addr).await.unwrap();
    ok.send(junk(max)).await.unwrap();
    assert!(ping_pong(&mut ok, Duration::from_secs(5)).await);

    // One byte over the limit closes the connection.
    let mut bad = ws_connect(addr).await.unwrap();
    let _ = bad.send(junk(max + 1)).await;
    assert!(closed_within(&mut bad, Duration::from_secs(5)).await);
    assert!(metrics::rejections(metrics::REJECT_OVERSIZED_FRAME) > before);
}

#[tokio::test]
async fn rate_limit_throttles_reads() {
    let before = metrics::rejections(metrics::REJECT_RATE_LIMIT);
    let addr = start(ServerConfig {
        rate_limit_bps: 1024,
        max_message_bytes: 64 * 1024, // burst = 64 KiB
        ..test_config()
    })
    .await;

    let mut ws = ws_connect(addr).await.unwrap();
    // Three 32 KiB junk keepalive frames: the burst covers ~two of them, the
    // third puts the bucket ~32 KiB in debt => ~32 s pause at 1 KiB/s.
    for _ in 0..3 {
        ws.send(junk(32 * 1024)).await.unwrap();
    }
    assert!(
        !ping_pong(&mut ws, Duration::from_secs(2)).await,
        "ping should not be served while the connection is throttled"
    );
    assert!(metrics::rejections(metrics::REJECT_RATE_LIMIT) > before);
}

#[tokio::test]
async fn idle_connection_times_out() {
    let before = metrics::rejections(metrics::REJECT_IDLE_TIMEOUT);
    // Below the validated minimum on purpose: Server::new does not validate,
    // which lets the test observe the timeout quickly.
    let addr = start(ServerConfig {
        connection_timeout_secs: 1,
        ..test_config()
    })
    .await;
    let mut ws = ws_connect(addr).await.unwrap();
    assert!(closed_within(&mut ws, Duration::from_secs(5)).await);
    assert!(metrics::rejections(metrics::REJECT_IDLE_TIMEOUT) > before);
}

#[tokio::test]
async fn anonymous_connection_is_closed_after_identification_timeout() {
    let before = metrics::rejections(metrics::REJECT_IDENTIFICATION_TIMEOUT);
    let addr = start(ServerConfig {
        identification_timeout_secs: 1,
        ..test_config()
    })
    .await;

    // Upgraded but never publishes: closed.
    let mut anon = ws_connect(addr).await.unwrap();
    // Sending non-identifying traffic does not count as identification.
    anon.send(Message::Binary(vec![0x04, 0xff])).await.unwrap();

    // A hello alone no longer identifies a connection.
    let mut hello_only = ws_connect(addr).await.unwrap();
    hello_only
        .send(test_support::hello_message(vec![3]))
        .await
        .unwrap();

    // A proven publish does: kept open past the identification timeout.
    let mut proven = ws_connect(addr).await.unwrap();
    test_support::publish(&mut proven, &TestIdentity::random()).await;

    assert!(closed_within(&mut anon, Duration::from_secs(5)).await);
    assert!(closed_within(&mut hello_only, Duration::from_secs(5)).await);
    assert!(metrics::rejections(metrics::REJECT_IDENTIFICATION_TIMEOUT) > before);
    assert!(
        !closed_within(&mut proven, Duration::from_secs(3)).await,
        "identified connection was closed"
    );
}

#[tokio::test]
async fn stalled_websocket_upgrade_is_dropped() {
    let addr = start(test_config()).await;
    // Send nothing at all: the header peek gives up after 5 s.
    let mut raw = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(8), raw.read(&mut buf))
        .await
        .expect("silent connection should be closed")
        .unwrap_or(0);
    assert_eq!(n, 0);
}

#[test]
fn message_id_extraction_reads_only_the_v2_header() {
    use super::extract_message_id;
    let mut p = vec![0x02];
    p.extend_from_slice(&[0xab; 16]);
    p.resize(162, 0);
    assert_eq!(
        extract_message_id(&p).as_deref(),
        Some("ab".repeat(16).as_str())
    );
    let mut short = p.clone();
    short.truncate(161);
    assert_eq!(
        extract_message_id(&short),
        None,
        "shorter than a sealed payload"
    );
    let mut v1 = p.clone();
    v1[0] = 0x00;
    assert_eq!(extract_message_id(&v1), None, "v1 payloads have no id");
    assert_eq!(extract_message_id(&[]), None);
}

/// TM6b: ping waits are 25-35 s.
#[test]
fn tm6b_ping_wait_is_jittered_between_25_and_35_seconds() {
    assert_eq!(super::ping_wait(0.0), Duration::from_secs(25));
    assert_eq!(super::ping_wait(1.0), Duration::from_secs(35));
    assert_eq!(super::ping_wait(0.5), Duration::from_secs(30));
    assert_eq!(super::ping_wait(7.0), Duration::from_secs(35), "clamped");
    assert_eq!(super::ping_wait(-1.0), Duration::from_secs(25), "clamped");
}

/// TM6b: an all-zero resume circuit is no resume.
#[test]
fn tm6b_all_zero_resume_means_none() {
    use crate::protocol::CircuitId;
    assert_eq!(super::normalize_resume(Some(CircuitId([0; 16]))), None);
    assert_eq!(super::normalize_resume(None), None);
    assert_eq!(
        super::normalize_resume(Some(CircuitId([5; 16]))),
        Some(CircuitId([5; 16]))
    );
}

mod auth_budget_tests {
    use crate::signaling::test_support::{self, *};
    use crate::signaling::*;

    /// R-5: hello (a relay signature each) is budgeted per connection: ten in a
    /// row get at most `AUTH_OPS_BURST` answers, then a RateLimited error and
    /// the connection is closed.
    #[tokio::test]
    async fn hello_flood_on_one_connection_is_cut_off() {
        let (addr, _state) = start(test_config()).await;
        let mut ws = connect(addr).await;
        for _ in 0..10 {
            ws.send(hello_message(vec![3])).await.unwrap();
        }
        // The relay closes the connection (panics if it stays open). The
        // last frames can be lost to the TCP reset of closing with unread
        // hellos, so only an upper bound on the answers is asserted.
        let frames = frames_until_closed(&mut ws, Duration::from_secs(5)).await;
        let answered = frames
            .iter()
            .filter(|f| {
                matches!(f, UnifiedFrame::Signaling(s)
                    if s.msg_type == crate::protocol::signaling::MSG_TYPE_HELLO_RESPONSE)
            })
            .count();
        assert!(
            answered <= crate::limits::AUTH_OPS_BURST as usize,
            "{answered}"
        );
        if let Some(code) = signaling_error_code(&frames) {
            assert_eq!(code, "RateLimited");
        }
    }

    #[test]
    fn auth_budget_refills_one_operation_per_interval() {
        let t0 = Instant::now();
        let mut b = crate::limits::AuthBudget::new(t0);
        for _ in 0..crate::limits::AUTH_OPS_BURST as usize {
            assert!(b.try_take(t0));
        }
        assert!(!b.try_take(t0));
        let later = t0 + crate::limits::AUTH_OPS_REFILL;
        assert!(b.try_take(later));
        assert!(!b.try_take(later));
    }

    /// R-5: re-publishes share the same budget as hellos.
    #[tokio::test]
    async fn republish_flood_on_one_connection_is_cut_off() {
        let (addr, _state) = start(test_config()).await;
        let mut ws = connect(addr).await;
        let id = TestIdentity::random();
        let mut next = test_support::publish(&mut ws, &id).await; // 2 ops
        let mut accepted = 1;
        loop {
            match send_publish(&mut ws, &id, &next, &dev_binding()).await {
                PublishReply::Ok(n) => {
                    accepted += 1;
                    next = n;
                }
                PublishReply::Error(e) => {
                    assert!(
                        e.contains("RateLimited") || e.contains("rate_limited"),
                        "{e}"
                    );
                    break;
                }
                PublishReply::Closed => break,
            }
            assert!(accepted <= 10, "publishes were never limited");
        }
        assert_eq!(accepted, crate::limits::AUTH_OPS_BURST as usize - 1);
        assert!(closed_within(&mut ws, Duration::from_secs(5)).await);
    }
}
