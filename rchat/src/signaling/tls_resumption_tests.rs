//! Spec §D.1 on the relay: TLS 1.3 resumption saves a round trip and the
//! certificate, never the connection proof. Every connection, resumed or
//! not, gets its own TLS exporter, so a proof made on one connection is
//! refused on another, and a resumed connection is routed nothing (no
//! queue, no circuits) until it proves its identity over its own exporter.

use super::test_support::*;
use super::*;
use rchat_core::keyauth;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(5);

/// A TLS 1.3 client that keeps the relay's tickets (rustls's in-memory
/// resumption store). Shared by every connection of one test.
fn resuming_client() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    Arc::new(config)
}

/// A WebSocket over TLS 1.3 with `config`; its exporter and whether the TLS
/// session was resumed.
async fn ws_with(addr: SocketAddr, config: &Arc<rustls::ClientConfig>) -> (TlsWs, [u8; 32], bool) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(config.clone())
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("TLS handshake");
    let conn = tls.get_ref().1;
    let resumed = conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
    let binding = conn
        .export_keying_material([0u8; 32], keyauth::EXPORTER_LABEL, Some(b"".as_slice()))
        .unwrap();
    let (ws, _) = tokio_tungstenite::client_async(format!("ws://localhost:{}/", addr.port()), tls)
        .await
        .expect("WebSocket");
    (ws, binding, resumed)
}

fn has_delivery(frames: &[UnifiedFrame]) -> bool {
    frames.iter().any(|f| {
        matches!(
            f,
            UnifiedFrame::Relay(_) | UnifiedFrame::Control(ControlMessage::QueuedMessage { .. })
        )
    })
}

/// The security invariant of §D.1: a resumed connection still has to prove
/// its identity, over its own exporter. A proof captured on conn 1 (as is,
/// or re-signed for the new challenge but over conn 1's exporter) is refused
/// on resumed connections, nothing queued is handed over before a proof, and
/// a proof over the resumed connection's own exporter is accepted.
#[tokio::test]
async fn resumed_connection_still_requires_conn_proof() {
    let (addr, state) = tls_relay().await;
    let id = TestIdentity::random();
    let client = resuming_client();

    // Conn 1: a full handshake; the proof over its exporter is accepted.
    let (mut c1, b1, resumed) = ws_with(addr, &client).await;
    assert!(!resumed, "conn 1 is a full handshake");
    let n1 = hello(&mut c1).await;
    let captured = publish_message(&id, &n1, &b1);
    c1.send(captured.clone()).await.unwrap();
    assert!(matches!(publish_reply(&mut c1).await, PublishReply::Ok(_)));
    drop(c1);
    queue_test_message(&state, &id, b"QUEUED-FOR-ID".to_vec());

    // Conn 2: resumed, with a different exporter. Conn 1's proof, replayed
    // as captured, is refused.
    let (mut c2, b2, resumed) = ws_with(addr, &client).await;
    assert!(resumed, "conn 2 resumes the TLS session");
    assert_ne!(b1, b2, "a resumed connection has its own exporter");
    hello(&mut c2).await;
    c2.send(captured).await.unwrap();
    let frames = frames_until_closed(&mut c2, WAIT).await;
    assert!(!has_delivery(&frames), "nothing handed to a replayed proof");
    let code = signaling_error_code(&frames).unwrap_or_default();
    assert!(code.contains("AuthenticationFailed"), "{code}");

    // Conn 3: resumed. A proof for this challenge but over conn 1's
    // exporter is refused too: only the exporter is wrong.
    let (mut c3, b3, resumed) = ws_with(addr, &client).await;
    assert!(resumed);
    assert_ne!(b3, b1);
    let n3 = hello(&mut c3).await;
    match send_publish(&mut c3, &id, &n3, &b1).await {
        PublishReply::Error(e) => assert!(e.contains("AuthenticationFailed"), "{e}"),
        other => panic!("proof over another connection's exporter accepted: {other:?}"),
    }
    assert!(closed_within(&mut c3, WAIT).await);

    // Conn 4: resumed. Before any proof it is routed nothing; its own proof
    // is accepted and only then is the queue handed over.
    let (mut c4, b4, resumed) = ws_with(addr, &client).await;
    assert!(resumed);
    let n4 = hello(&mut c4).await;
    assert!(
        !has_delivery(&frames_until_quiet(&mut c4, Duration::from_millis(300)).await),
        "a resumed connection gets no queue before its proof"
    );
    assert_eq!(queued_len(&state, &id), 1);
    match send_publish(&mut c4, &id, &n4, &b4).await {
        PublishReply::Ok(_) => {}
        other => panic!("own proof on a resumed connection refused: {other:?}"),
    }
    assert!(has_delivery(
        &frames_until_quiet(&mut c4, Duration::from_millis(500)).await
    ));
}

/// With `session_tickets = false` the relay issues no ticket and keeps no
/// session cache: every connection is a full handshake.
#[tokio::test]
async fn tickets_off_means_every_handshake_is_full() {
    let (addr, _state) = tls_relay_with(|c| {
        c.tls.as_mut().unwrap().session_tickets = false;
    })
    .await;
    let client = resuming_client();
    for _ in 0..3 {
        let (mut ws, binding, resumed) = ws_with(addr, &client).await;
        assert!(!resumed, "no resumption with tickets off");
        let id = TestIdentity::random();
        let nonce = hello(&mut ws).await;
        assert!(matches!(
            send_publish(&mut ws, &id, &nonce, &binding).await,
            PublishReply::Ok(_)
        ));
    }
}
