//! Behind a layer-4 front end on the same host, the per-source fair shares
//! use the client address from the front end's PROXY protocol v2 header
//! (`proxy_protocol = true`), read from the raw TCP stream before TLS. The
//! header is accepted only from a loopback peer; anyone else is refused.

use super::test_support::*;
use super::*;
use crate::proxy_protocol::encode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A PROXY v2 header for a client at `client` reaching the front end.
fn header_for(client: &str) -> Vec<u8> {
    encode(Some((sock(client), sock("127.0.0.1:443"))))
}

/// A LOCAL header (the front end's own health check).
fn local_header() -> Vec<u8> {
    let mut h = crate::proxy_protocol::SIGNATURE.to_vec();
    h.extend_from_slice(&[0x20, 0x00, 0, 0]);
    h
}

#[test]
fn only_a_loopback_peer_may_send_a_proxy_header() {
    for ok in [
        "127.0.0.1:1",
        "127.9.9.9:1",
        "[::1]:1",
        "[::ffff:127.0.0.1]:1",
    ] {
        assert!(proxy_peer_allowed(sock(ok)), "{ok}");
    }
    for refused in [
        "198.51.100.1:1",
        "[2001:db8::1]:1",
        "[::ffff:198.51.100.1]:1",
        "10.0.0.1:1",
        "0.0.0.0:1",
    ] {
        assert!(!proxy_peer_allowed(sock(refused)), "{refused}");
    }
}

#[test]
fn connection_source_uses_the_proxied_address_only_with_proxy_protocol() {
    let limiter = ConnectionLimiter::new(10, 0, 0);
    let local = sock("127.0.0.1:50000");
    let remote = sock("198.51.100.1:50000");
    let client: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    let mut config = test_config(); // max_connections_per_ip = 0
    assert_eq!(connection_source(local, None, &config, &limiter), None);
    assert_eq!(
        connection_source(local, Some(client), &config, &limiter),
        None,
        "ignored unless proxy_protocol is on"
    );
    config.proxy_protocol = true;
    assert_eq!(
        connection_source(local, Some(client), &config, &limiter),
        Some(limiter.source_key(client))
    );
    // Off: per-IP limits decide, as before.
    config.proxy_protocol = false;
    config.max_connections_per_ip = 4;
    assert_eq!(
        connection_source(remote, None, &config, &limiter),
        Some(limiter.source_key(remote.ip()))
    );
}

/// A plaintext (`--no-tls`) WebSocket to `addr` whose TCP stream starts
/// with `prefix`.
async fn ws_after(addr: SocketAddr, prefix: &[u8]) -> WebSocketStreamTcp {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(prefix).await.unwrap();
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async(format!("ws://{addr}/"), tcp),
    )
    .await
    .expect("upgrade timed out")
    .expect("upgrade failed");
    ws
}

type WebSocketStreamTcp = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

fn source_of(state: &RelayState, id: &TestIdentity) -> Option<SourceKey> {
    state
        .connections
        .iter()
        .find(|c| c.proven_identity == Some(id.bytes))
        .and_then(|c| c.source)
}

/// Whether the relay closes a TCP connection that sent `bytes` without
/// answering anything.
async fn closed_silently(addr: SocketAddr, bytes: &[u8]) -> bool {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = tcp.write_all(bytes).await;
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

/// Serialises the tests that make a `proxy_protocol` relay refuse
/// connections, so each can assert the exact change in the process-global
/// `proxy_header` / `proxy_not_loopback` counters (no other test in the
/// crate runs a `proxy_protocol` relay).
static PROXY_METRICS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `bytes` sent to `addr` are refused without a reply, and exactly one
/// `reason` rejection is counted for it. Call with `PROXY_METRICS` held.
async fn refused_once(addr: SocketAddr, bytes: &[u8], reason: &str) {
    let before = metrics::rejections(reason);
    assert!(closed_silently(addr, bytes).await, "not closed: {bytes:?}");
    assert_eq!(
        metrics::rejections(reason),
        before + 1,
        "exactly one {reason} rejection for {bytes:?}"
    );
}

/// End to end (plaintext): the PROXY v2 address becomes the connection's
/// source even with `max_connections_per_ip = 0`; LOCAL falls back to the
/// peer; a connection without a valid header is closed.
#[tokio::test]
async fn a_proxy_v2_header_sets_the_source() {
    let _serial = PROXY_METRICS.lock().await;
    let config = ServerConfig {
        proxy_protocol: true,
        ..test_config()
    };
    let (addr, state) = start(config).await;
    let ids: Vec<TestIdentity> = (0..6).map(|_| TestIdentity::random()).collect();
    let mut a = ws_after(addr, &header_for("203.0.113.7:50001")).await;
    publish(&mut a, &ids[0]).await;
    let mut b = ws_after(addr, &header_for("203.0.113.7:50002")).await;
    publish(&mut b, &ids[1]).await;
    let mut c = ws_after(addr, &header_for("[2001:db8:1::9]:50003")).await;
    publish(&mut c, &ids[2]).await;
    let mut d = ws_after(addr, &local_header()).await;
    publish(&mut d, &ids[3]).await;
    // The peer's own address, named explicitly, for comparison with LOCAL.
    let peer = format!("{}:50004", addr.ip());
    let mut e = ws_after(addr, &header_for(&peer)).await;
    publish(&mut e, &ids[5]).await;

    let src: Vec<_> = ids.iter().map(|id| source_of(&state, id)).collect();
    assert!(src[0].is_some(), "the PROXY v2 address gives a source");
    assert_eq!(src[0], src[1], "same client address, same source");
    assert!(src[2].is_some());
    assert_ne!(src[0], src[2], "different client address, different source");
    assert!(src[3].is_some());
    assert_eq!(src[3], src[5], "LOCAL: the peer's address");
    assert_ne!(src[3], src[0]);

    // No header (a plain upgrade), a v1 header, a bad signature: each is
    // closed and counted once.
    let header = metrics::REJECT_PROXY_HEADER;
    refused_once(addr, b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n", header).await;
    refused_once(addr, b"PROXY TCP4 203.0.113.7 127.0.0.1 1 2\r\n", header).await;
    let mut bad = header_for("203.0.113.7:1");
    bad[0] = b'X';
    refused_once(addr, &bad, header).await;
    // Header and the whole upgrade request in ONE write: the parser takes
    // exactly the header and the request that follows still upgrades.
    let mut joined = header_for("203.0.113.8:1");
    joined.extend_from_slice(
        b"GET / HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&joined).await.unwrap();
    let mut reply = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut reply))
        .await
        .expect("no reply")
        .unwrap();
    assert!(
        reply[..n].starts_with(b"HTTP/1.1 101"),
        "{:?}",
        String::from_utf8_lossy(&reply[..n])
    );

    // Without proxy_protocol no header is expected: a plain upgrade works.
    let (addr, _) = start(test_config()).await;
    let mut f = connect(addr).await;
    publish(&mut f, &ids[4]).await;
}

/// End to end over TLS, the deployed layout: PROXY v2 header in the clear,
/// then the TLS 1.3 handshake on the same stream, then the WebSocket, and a
/// key-authenticated publish bound to the relay's own TLS session.
#[tokio::test]
async fn proxy_v2_then_tls_works_end_to_end() {
    let _serial = PROXY_METRICS.lock().await;
    let (addr, state) = tls_relay_with(|c| c.proxy_protocol = true).await;
    let id = TestIdentity::random();
    let (mut ws, binding) = tls_ws_after(addr, &header_for("198.51.100.23:40000"))
        .await
        .expect("PROXY v2 + TLS connection works");
    let nonce = hello(&mut ws).await;
    assert!(matches!(
        send_publish(&mut ws, &id, &nonce, &binding).await,
        PublishReply::Ok(_)
    ));
    // A second client behind the same front end, at the same and at a
    // different address.
    let (id2, id3) = (TestIdentity::random(), TestIdentity::random());
    let (mut ws2, b2) = tls_ws_after(addr, &header_for("198.51.100.23:40001"))
        .await
        .unwrap();
    let n2 = hello(&mut ws2).await;
    assert!(matches!(
        send_publish(&mut ws2, &id2, &n2, &b2).await,
        PublishReply::Ok(_)
    ));
    let (mut ws3, b3) = tls_ws_after(addr, &header_for("[2001:db8::23]:40002"))
        .await
        .unwrap();
    let n3 = hello(&mut ws3).await;
    assert!(matches!(
        send_publish(&mut ws3, &id3, &n3, &b3).await,
        PublishReply::Ok(_)
    ));
    let (s1, s2, s3) = (
        source_of(&state, &id),
        source_of(&state, &id2),
        source_of(&state, &id3),
    );
    assert!(s1.is_some(), "per-source fairness is on behind PROXY v2");
    assert_eq!(s1, s2);
    assert_ne!(s1, s3);

    // A front end that forgot `send-proxy-v2`: the ClientHello is not a
    // PROXY header, so the connection is closed before any TLS reply.
    let before = metrics::rejections(metrics::REJECT_PROXY_HEADER);
    assert!(tls_ws_after(addr, &[]).await.is_err());
    assert_eq!(
        metrics::rejections(metrics::REJECT_PROXY_HEADER),
        before + 1
    );
}

/// A peer that is not loopback is refused before anything is read, even
/// with a well-formed header. Needs a non-loopback local address to connect
/// from. On a host without one it prints an explicit SKIPPED line (only
/// `proxy_peer_allowed`'s unit test then covers the refusal), and fails
/// instead when `CI` is set, so CI never passes it silently.
#[tokio::test]
async fn a_non_loopback_peer_is_refused() {
    let skip = |why: &str| {
        let msg = format!("SKIPPED a_non_loopback_peer_is_refused: {why}");
        if std::env::var_os("CI").is_some() {
            panic!("{msg} (CI is set: a routable local address is required)");
        }
        eprintln!("{msg}");
    };
    let Some(local_ip) = non_loopback_local_ip() else {
        return skip("no non-loopback local address");
    };
    let _serial = PROXY_METRICS.lock().await;
    // Built directly: validate() would refuse this wildcard bind (L1); here
    // it is what lets a non-loopback peer reach the listener at all.
    let (addr, _) = tls_relay_with(|c| {
        c.proxy_protocol = true;
        c.bind_addr = "0.0.0.0:0".parse().unwrap();
    })
    .await;
    let target = SocketAddr::new(local_ip, addr.port());
    let reason = metrics::REJECT_PROXY_NOT_LOOPBACK;
    let before = metrics::rejections(reason);
    let Ok(mut probe) = tokio::net::TcpStream::connect(target).await else {
        return skip("the host's own non-loopback address is not reachable");
    };
    // The probe itself is refused (closed unread) and counted once.
    let mut buf = [0u8; 8];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), probe.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    assert_eq!(metrics::rejections(reason), before + 1);
    refused_once(target, &header_for("203.0.113.7:1"), reason).await;
    let before = metrics::rejections(reason);
    assert!(tls_ws_after(target, &header_for("203.0.113.7:1"))
        .await
        .is_err());
    assert_eq!(metrics::rejections(reason), before + 1);
}

/// This host's address on its default route, if it has one (no packet is
/// sent: connecting a UDP socket only picks the source address).
fn non_loopback_local_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}
