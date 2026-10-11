//! Guards the relay's log privacy policy (see `crate::privacy` and
//! `docs/security/01-threat-model.md`, "What the relay logs").
//!
//! A real in-process server is driven over real WebSockets through a full v2
//! scenario (signed publishes, CircuitAsk, match, relay, member close, a
//! knock for an offline identity, an offline enqueue, a decoy HTTP request)
//! with a capturing `tracing` subscriber. Every captured line, at every
//! level, must be free of raw circuit ids, identity keys, client addresses,
//! request headers, auth tags, token keys, message ids and payload bytes,
//! and no line may carry two identity-derived values (R6). A TLS 1.3 leg
//! repeats publish, match, relay and close over the real TLS path (spec L1).
//! The offline-queue path is driven directly with hostile payload prefixes.
//! A source-level companion test scans the server sources for macros that
//! would reintroduce such leaks.

use super::test_support::{
    self, ask, ask_each_other, connect, eventually, hello, publish, send_publish, start,
    test_config, tls_relay, tls_ws, PublishReply, TestIdentity, Ws,
};
use super::*;
use crate::protocol::relay::CircuitToken;
use std::io::Write;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::WebSocketStream;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(self.0.clone())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
    }
}

fn local_addr_of(ws: &Ws) -> SocketAddr {
    match ws.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(s) => s.local_addr().unwrap(),
        _ => unreachable!(),
    }
}

async fn until_control<S>(
    ws: &mut WebSocketStream<S>,
    want: impl Fn(&ControlMessage) -> bool,
) -> Option<ControlMessage>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match test_support::next_control(ws, Duration::from_secs(3)).await {
            Some(m) if want(&m) => return Some(m),
            Some(_) => continue,
            None => return None,
        }
    }
}

async fn until_created<S>(ws: &mut WebSocketStream<S>) -> (CircuitId, Vec<u8>, CircuitId)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match until_control(ws, |m| matches!(m, ControlMessage::CircuitCreatedV2 { .. })).await {
        Some(ControlMessage::CircuitCreatedV2 {
            circuit_id,
            token,
            target_circuit_id,
            ..
        }) => (circuit_id, token, target_circuit_id),
        other => panic!("expected CircuitCreatedV2, got {other:?}"),
    }
}

async fn until_relay<S>(ws: &mut WebSocketStream<S>) -> Option<RelayPacket>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for _ in 0..20 {
        let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .ok()??;
        if let Ok(UnifiedFrame::Relay(p)) = UnifiedFrame::decode(&next.ok()?) {
            return Some(p);
        }
    }
    None
}

/// Relay frame on `target_circuit` tagged with the sender's token; returns
/// the frame and its auth tag.
fn relay_on(target_circuit: CircuitId, my_token: &[u8], payload: &[u8]) -> (Message, [u8; 16]) {
    let mut key = [0u8; 32];
    key.copy_from_slice(my_token);
    let token = CircuitToken {
        circuit_id: target_circuit,
        key,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    let mut p = RelayPacket::new(target_circuit, payload.to_vec());
    p.auth_tag = token.authenticate(&target_circuit, payload);
    let tag = p.auth_tag;
    (UnifiedFrame::relay(p).encode(), tag)
}

const MESSAGE_ID: [u8; 16] = [0x5e; 16];

/// A v2-shaped payload: version 0x02, message id, filler, then `marker`.
fn sealed_like(marker: &[u8]) -> Vec<u8> {
    let mut p = vec![0x02];
    p.extend_from_slice(&MESSAGE_ID);
    p.extend_from_slice(&[0x11; 160]);
    p.extend_from_slice(marker);
    p
}

/// Everything sensitive the scenario uses, to grep the captured logs for.
struct Secrets {
    needles: Vec<(&'static str, String)>,
    ids: Vec<TestIdentity>,
}

/// `privacy::set_log_client_ips` is process-global; serialize scenarios.
static SCENARIO_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn run_scenario(capture_level: tracing::Level, log_ips: bool) -> (String, Secrets) {
    let _serial = SCENARIO_LOCK.lock().await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(capture_level)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    crate::privacy::set_log_client_ips(log_ips);

    let (server_addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0xA1),
        TestIdentity::from_seed(0xB2),
        TestIdentity::from_seed(0xC3),
    );
    let mut wa = connect(server_addr).await;
    let a_addr = local_addr_of(&wa);
    publish(&mut wa, &a).await;
    let mut wb = connect(server_addr).await;
    let b_addr = local_addr_of(&wb);
    publish(&mut wb, &b).await;

    // Ask, knock delivered live, ask back, match.
    wa.send(ask(&b, [0x44; 32], None)).await.unwrap();
    assert!(
        until_control(&mut wb, |m| matches!(
            m,
            ControlMessage::QueuedMessage { .. }
        ))
        .await
        .is_some(),
        "B received A's knock"
    );
    wb.send(ask(&a, [0x45; 32], None)).await.unwrap();
    let ca = until_created(&mut wa).await;
    let cb = until_created(&mut wb).await;

    // Relay A -> B.
    let payload = sealed_like(b"TOP-SECRET-PAYLOAD-MARKER-0123456789");
    let (frame, auth_tag) = relay_on(ca.2, &ca.1, &payload);
    wa.send(frame).await.unwrap();
    let got = until_relay(&mut wb)
        .await
        .expect("B received the relayed packet");
    assert_eq!(got.payload, payload, "relayed payload arrived intact");

    // Bad tag on a known circuit, and an unknown circuit.
    let mut bad = RelayPacket::new(ca.2, payload.clone());
    bad.auth_tag = [0xEE; 16];
    wa.send(UnifiedFrame::relay(bad).encode()).await.unwrap();
    let unknown = CircuitId([0x5Au8; 16]);
    wa.send(UnifiedFrame::relay(RelayPacket::new(unknown, payload.clone())).encode())
        .await
        .unwrap();

    // Knock for an identity that has never connected.
    wa.send(ask(&c, [0x46; 32], None)).await.unwrap();

    // B goes offline; the pair outlives its socket and A's packet queues.
    let _ = wb.close(None).await;
    drop(wb);
    let st = state.clone();
    let b_bytes = b.bytes;
    eventually("B gone", move || {
        !st.connections
            .iter()
            .any(|c| c.proven_identity == Some(b_bytes))
    })
    .await;
    let offline = sealed_like(b"OFFLINE-SECRET-BODY");
    let (frame, _) = relay_on(ca.2, &ca.1, &offline);
    wa.send(frame).await.unwrap();
    let st = state.clone();
    let b_tag = tags::id_tag(&b.bytes);
    eventually("offline enqueue", move || {
        st.message_queues
            .get(&b_tag)
            .is_some_and(|q| q.pending.iter().any(|m| !m.is_knock))
    })
    .await;

    // Member close.
    wa.send(FrameBuilder::close_circuit(ca.0).encode())
        .await
        .unwrap();

    // Plain HTTP request with a distinctive header (decoy path).
    let mut raw = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let raw_addr = raw.local_addr().unwrap();
    raw.write_all(
        b"GET /?q=query-secret HTTP/1.1\r\nHost: x\r\nX-Header-Secret: header-secret-value\r\n\r\n",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = wa.close(None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    crate::privacy::set_log_client_ips(false);

    let enc = |b: &[u8]| hex::encode(b);
    let dec_list = |b: &[u8]| {
        b.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let secrets = Secrets {
        needles: vec![
            ("circuit id A (hex)", enc(ca.0.as_ref())),
            ("circuit id B (hex)", enc(cb.0.as_ref())),
            ("circuit id B (debug bytes)", dec_list(cb.0.as_ref())),
            ("unknown circuit id (hex)", enc(unknown.as_ref())),
            ("identity A (hex)", a.hex.clone()),
            ("identity B (hex)", b.hex.clone()),
            ("identity C (hex)", c.hex.clone()),
            ("identity A prefix", a.hex[..16].to_string()),
            ("identity B prefix", b.hex[..16].to_string()),
            ("payload marker", "TOP-SECRET-PAYLOAD-MARKER".to_string()),
            ("offline body", "OFFLINE-SECRET-BODY".to_string()),
            ("payload prefix (hex)", enc(&payload[..8])),
            ("payload (debug bytes)", dec_list(&payload[..8])),
            ("message id (hex)", enc(&MESSAGE_ID)),
            ("auth tag (hex)", enc(&auth_tag)),
            ("auth tag prefix (hex)", enc(&auth_tag[..4])),
            ("token key A (hex)", enc(&ca.1)),
            ("token key B (hex)", enc(&cb.1)),
            ("client A socket addr", a_addr.to_string()),
            ("client B socket addr", b_addr.to_string()),
            ("raw http client socket addr", raw_addr.to_string()),
            ("request header value", "header-secret-value".to_string()),
            ("request header name", "X-Header-Secret".to_string()),
            ("request path", "query-secret".to_string()),
        ],
        ids: vec![a, b, c],
    };
    (capture.text(), secrets)
}

fn assert_clean(logs: &str, secrets: &Secrets, skip: &[&str]) {
    for (name, needle) in &secrets.needles {
        if skip.contains(name) {
            continue;
        }
        assert!(
            !logs.to_lowercase().contains(&needle.to_lowercase()),
            "log output leaks {name} ({needle}):\n{}",
            logs.lines()
                .filter(|l| l.to_lowercase().contains(&needle.to_lowercase()))
                .take(5)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// Every identity-derived value the relay could print for these identities
/// (R6): log tags of the hex and the bytes, the keyed id tags (raw and
/// log-tagged), and the pair tags of every pair among them.
fn identity_needles(ids: &[TestIdentity]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        let t = tags::id_tag(&id.bytes);
        out.push(crate::privacy::tag_str(&id.hex));
        out.push(crate::privacy::tag(id.bytes));
        out.push(hex::encode(t.0));
        out.push(crate::privacy::tag(t.0));
    }
    for (i, x) in ids.iter().enumerate() {
        for y in &ids[i + 1..] {
            let p = tags::pair_tag(&x.bytes, &y.bytes);
            out.push(hex::encode(p.0));
            out.push(crate::privacy::tag(p.0));
        }
    }
    out
}

/// L1 / R6: no captured line contains two identity-derived values.
fn assert_no_line_links_two_identity_values(logs: &str, ids: &[TestIdentity]) {
    super::circuits::assert_r6(logs, &identity_needles(ids));
}

/// Is `line` (fmt output, no ANSI) exactly the startup pin line
/// `^Relay identity: rk:1:[a-z2-7]{52} \(version \d+\)$` from the signaling
/// module, once the timestamp/level/target prefix is stripped?
fn is_relay_pin_startup_line(line: &str) -> bool {
    let Some((_, rest)) = line.split_once(" INFO ") else {
        return false;
    };
    let Some(msg) = rest.strip_prefix("rchat_server::signaling: ") else {
        return false;
    };
    let Some(rest) = msg.strip_prefix("Relay identity: rk:1:") else {
        return false;
    };
    let Some((body, rest)) = rest.split_at_checked(52) else {
        return false;
    };
    let Some(digits) = rest
        .strip_prefix(" (version ")
        .and_then(|r| r.strip_suffix(')'))
    else {
        return false;
    };
    body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

#[test]
fn relay_pin_startup_line_matcher_is_exact() {
    let pin = "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia";
    let ok = format!("2026-10-03T17:35:22.514111Z  INFO rchat_server::signaling: Relay identity: {pin} (version 0)");
    assert!(is_relay_pin_startup_line(&ok));
    for bad in [
        format!("2026-10-03T17:35:22Z  INFO rchat_server::signaling: Relay identity: {pin} (version 0) circuit 7"),
        format!("2026-10-03T17:35:22Z  INFO rchat_server::signaling: relay identity: {pin} (version 0)"),
        format!("2026-10-03T17:35:22Z  INFO rchat_server::signaling: Relay identity: {pin}x (version 0)"),
        format!("2026-10-03T17:35:22Z  INFO rchat_server::signaling: Relay identity: {pin} (version )"),
        format!("2026-10-03T17:35:22Z  INFO rchat_server::other: Relay identity: {pin} (version 1)"),
        format!("2026-10-03T17:35:22Z  INFO rchat_server::signaling: client abc Relay identity: {pin} (version 1)"),
        "2026-10-03T17:35:22Z  INFO rchat_server::signaling: Relay identity: rk:1:MC7QPREIVLIY7WRTTXYH4T54I62PAC7HC4IZG3YY2BGTKKWQDCIA (version 1)".to_string(),
    ] {
        assert!(!is_relay_pin_startup_line(&bad), "{bad}");
    }
}

/// Default config: nothing sensitive at any level, down to TRACE; and at INFO
/// the only lines are startup/operational ones.
#[tokio::test]
async fn relay_logs_no_metadata_or_content_at_any_level() {
    let (trace_logs, secrets) = run_scenario(tracing::Level::TRACE, false).await;
    assert!(
        trace_logs.contains("listening"),
        "capture is not wired up; got: {trace_logs}"
    );
    assert!(
        trace_logs.lines().count() > 10,
        "scenario produced suspiciously few log lines (did it run?):\n{trace_logs}"
    );
    assert_clean(&trace_logs, &secrets, &[]);

    let (info_logs, secrets) = run_scenario(tracing::Level::INFO, false).await;
    assert!(info_logs.contains("listening"));
    assert_clean(&info_logs, &secrets, &[]);
    for line in info_logs.lines() {
        let l = line.to_lowercase();
        // The startup line naming the relay's own public pin (spec §4.9) is
        // operational, not activity. Exempt only that exact message.
        if is_relay_pin_startup_line(line) {
            continue;
        }
        for banned in [
            "circuit",
            "client ",
            "relay",
            "identity",
            "connection from",
            "peeked",
            "payload",
            "knock",
        ] {
            assert!(
                !l.contains(banned),
                "INFO line reveals activity ({banned}): {line}"
            );
        }
    }
}

/// L1: a TRACE capture over the full scenario links no two identities.
#[tokio::test]
async fn l1_no_log_line_carries_two_identity_derived_values() {
    let (trace_logs, secrets) = run_scenario(tracing::Level::TRACE, false).await;
    assert!(trace_logs.lines().count() > 10, "scenario ran");
    assert_no_line_links_two_identity_values(&trace_logs, &secrets.ids);
}

/// With `logging.log_client_ips = true` the peer address may appear, but only
/// at debug, never at info/warn/error, and nothing else becomes loggable.
#[tokio::test]
async fn client_ips_only_when_opted_in_and_never_at_info() {
    let (debug_logs, secrets) = run_scenario(tracing::Level::DEBUG, true).await;
    let ip_needles = [
        "client A socket addr",
        "client B socket addr",
        "raw http client socket addr",
    ];
    let ip_visible = secrets
        .needles
        .iter()
        .filter(|(n, _)| ip_needles.contains(n))
        .any(|(_, v)| debug_logs.contains(v.as_str()));
    assert!(
        ip_visible,
        "log_client_ips=true should surface the peer at debug:\n{debug_logs}"
    );
    assert_clean(&debug_logs, &secrets, &ip_needles);

    let (info_logs, secrets) = run_scenario(tracing::Level::INFO, true).await;
    assert_clean(&info_logs, &secrets, &[]);
}

/// L1 over TLS (spec L1 names the TLS path): publish with this session's real
/// exporter binding, ask, match, relay and member close over TLS 1.3 under a
/// TRACE capture. Nothing sensitive leaks and no line links two identities.
#[tokio::test]
async fn l1_tls_path_logs_no_metadata_and_links_no_two_identities() {
    let _serial = SCENARIO_LOCK.lock().await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (addr, state) = tls_relay().await;
    let (a, b) = (TestIdentity::from_seed(0xA4), TestIdentity::from_seed(0xB5));
    let (mut wa, binding_a) = tls_ws(addr).await;
    let nonce_a = hello(&mut wa).await;
    assert!(matches!(
        send_publish(&mut wa, &a, &nonce_a, &binding_a).await,
        PublishReply::Ok(_)
    ));
    let (mut wb, binding_b) = tls_ws(addr).await;
    let nonce_b = hello(&mut wb).await;
    assert!(matches!(
        send_publish(&mut wb, &b, &nonce_b, &binding_b).await,
        PublishReply::Ok(_)
    ));

    ask_each_other(&state, &mut wa, &a, &mut wb, &b).await;
    let ca = until_created(&mut wa).await;
    let cb = until_created(&mut wb).await;
    let payload = sealed_like(b"TLS-SECRET-PAYLOAD-MARKER");
    let (frame, auth_tag) = relay_on(ca.2, &ca.1, &payload);
    wa.send(frame).await.unwrap();
    let got = until_relay(&mut wb)
        .await
        .expect("B received the packet over TLS");
    assert_eq!(got.payload, payload);
    wa.send(FrameBuilder::close_circuit(ca.0).encode())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = wa.close(None).await;
    let _ = wb.close(None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let logs = capture.text();
    assert!(
        logs.contains("(TLS 1.3)"),
        "the TLS relay did not log under this capture:\n{logs}"
    );
    let enc = |b: &[u8]| hex::encode(b);
    let secrets = Secrets {
        needles: vec![
            ("circuit id A (hex)", enc(ca.0.as_ref())),
            ("circuit id B (hex)", enc(cb.0.as_ref())),
            ("identity A (hex)", a.hex.clone()),
            ("identity B (hex)", b.hex.clone()),
            ("identity A prefix", a.hex[..16].to_string()),
            ("identity B prefix", b.hex[..16].to_string()),
            ("payload marker", "TLS-SECRET-PAYLOAD-MARKER".to_string()),
            ("message id (hex)", enc(&MESSAGE_ID)),
            ("auth tag (hex)", enc(&auth_tag)),
            ("token key A (hex)", enc(&ca.1)),
            ("token key B (hex)", enc(&cb.1)),
            ("channel binding A (hex)", enc(&binding_a)),
            ("auth nonce A (hex)", enc(&nonce_a)),
        ],
        ids: vec![a, b],
    };
    assert_clean(&logs, &secrets, &[]);
    assert_no_line_links_two_identity_values(&logs, &secrets.ids);
}

/// RQ5 (R6, spec §18.6 D34): the three forwarding outcomes - handed to an
/// online member that has not resumed (RQ1), queued for an offline member
/// (RQ2), and re-queued after a failed hand-over (RQ1b) - under a TRACE
/// capture. No line carries two of A's and B's identity hex, `IdTag`s or
/// `PairTag`.
#[tokio::test]
async fn rq5_forwarding_logs_one_identity_value_per_line() {
    let _serial = SCENARIO_LOCK.lock().await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Callsites first hit by a parallel test without a subscriber are cached
    // as "never" process-wide; recompute their interest with this capture
    // registered so its lines are not dropped.
    tracing::callsite::rebuild_interest_cache();

    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0xA6), TestIdentity::from_seed(0xB7));
    let gone = |state: &RelayState| {
        let st = state.clone();
        let bb = b.bytes;
        eventually("B gone", move || {
            !st.connections.iter().any(|c| c.proven_identity == Some(bb))
        })
    };
    let (mut wa, wb, ca, _cb) = test_support::pair_up(&state, addr, &a, &b).await;
    let send_a = |marker: &[u8]| {
        test_support::relay_on(ca.target_circuit_id, &ca.token, sealed_like(marker))
    };

    // RQ1: B is back online without resuming; the packet is handed over.
    drop(wb);
    gone(&state).await;
    let mut wb2 = test_support::authed(addr, &b).await;
    wa.send(send_a(b"RQ5-LIVE")).await.unwrap();
    assert!(
        until_control(&mut wb2, |m| matches!(
            m,
            ControlMessage::QueuedMessage { .. }
        ))
        .await
        .is_some(),
        "B's unresumed connection received the packet"
    );

    // RQ2: B offline; the packet is queued.
    drop(wb2);
    gone(&state).await;
    wa.send(send_a(b"RQ5-OFFLINE")).await.unwrap();
    let b_tag = tags::id_tag(&b.bytes);
    let queued = |n: usize| {
        let st = state.clone();
        move || st.message_queues.get(&b_tag).map_or(0, |q| q.pending.len()) == n
    };
    eventually("queued", queued(1)).await;

    // RQ1b: B mapped to a connection that cannot receive; re-queued.
    let (_client, rx) = test_support::proven_bare(&state, &b, None);
    drop(rx);
    wa.send(send_a(b"RQ5-REQUEUE")).await.unwrap();
    eventually("re-queued", queued(2)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let logs = capture.text();
    assert!(
        logs.contains("handed a packet to a member that has not resumed"),
        "the live hand-over ran under this capture:\n{logs}"
    );
    assert!(
        logs.contains("has not resumed failed; re-queueing"),
        "the failed hand-over ran under this capture:\n{logs}"
    );
    let ids = [a, b];
    let mut needles = identity_needles(&ids);
    needles.extend(ids.iter().map(|i| i.hex.clone()));
    super::circuits::assert_r6(&logs, &needles);
}

/// Offline queue path, driven directly: recipient offline -> messages queued
/// under its tag -> recipient publishes (signed) -> `QueuedMessage` delivery.
/// Payload prefixes are client-chosen; short and multi-byte-straddling
/// message ids used to panic trace formatting (`&message_id[..8]`), which
/// aborts a release build. Runs at TRACE and applies the same no-identifier
/// and R6 assertions.
#[tokio::test]
async fn offline_queue_with_hostile_message_ids_does_not_panic_or_leak() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let state = RelayState::new(Arc::new(ServerConfig::default()));
    let connections = state.connections.clone();
    let circuits = state.circuits.clone();
    let queues = state.message_queues.clone();

    // `proof_ready`: the connection said hello v2 and holds a nonce, so a
    // signed publish over nonce [0x4e; 32] and binding [0x42; 32] verifies.
    let mk_conn = |id: ClientId, proof_ready: bool| {
        let (tx, rx, _kill) = ConnTx::channel();
        connections.insert(
            id,
            UnifiedConnection {
                client_id: id,
                _addr: "127.0.0.1:1".parse().unwrap(),
                ws_tx: tx,
                key_bundle: None,
                identity_key: None,
                last_activity: Instant::now(),
                circuits: Arc::new(DashMap::new()),
                last_pong: Instant::now(),
                pending_ping: None,
                identified: true,
                created_circuits: Default::default(),
                pending_charges: Default::default(),
                closing: false,
                auth_budget: crate::limits::AuthBudget::new(Instant::now()),
                source: None,
                protocol_version: if proof_ready { 2 } else { 0 },
                auth_nonce: proof_ready.then_some([0x4e; 32]),
                channel_binding: [0x42; 32],
                proven_identity: None,
            },
        );
        rx
    };
    let sender = ClientId::generate();
    let recipient_gone = ClientId::generate();
    let _sender_rx = mk_conn(sender, false);

    let sender_identity = TestIdentity::with_first_nibble(0xb);
    let recip = TestIdentity::with_first_nibble(0xa);
    let id_sender = sender_identity.hex.clone();
    let id_recip = recip.hex.clone();
    let circuit = CircuitId::generate();
    let tok_s = CircuitToken::generate(circuit, Duration::from_secs(60));
    let tok_r = CircuitToken::generate(circuit, Duration::from_secs(60));
    circuits.insert(
        circuit,
        CircuitRoutingInfo {
            client_a: sender,
            client_b: recipient_gone, // not in `connections`: offline
            tag_a: tags::id_tag(&sender_identity.bytes),
            tag_b: tags::id_tag(&recip.bytes),
            token_a: tok_s.clone(),
            token_b: tok_r,
            pair: tags::pair_tag(&sender_identity.bytes, &recip.bytes),
            peer_circuit: circuit,
        },
    );

    let ids = ["ab", "abcdefg\u{e9}", "\u{20ac}\u{20ac}\u{20ac}"];
    let mut bodies = Vec::new();
    for id in ids {
        let mut p = (id.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(id.as_bytes());
        p.extend_from_slice(b"OFFLINE-SECRET-BODY");
        let mut pkt = RelayPacket::new(circuit, p.clone());
        pkt.auth_tag = tok_s.authenticate(&circuit, &p);
        handle_relay_packet(sender, pkt, &state)
            .await
            .expect("relay of an offline-bound packet succeeds");
        bodies.push(p);
    }
    assert_eq!(
        queues
            .get(&tags::id_tag(&recip.bytes))
            .map(|q| q.pending.len()),
        Some(3),
        "all three messages were queued for the offline identity"
    );

    // Recipient comes back and publishes its signed bundle: the queue arrives.
    let back = ClientId::generate();
    let mut back_rx = mk_conn(back, true);
    let proof =
        rchat_core::keyauth::sign_conn(&recip.keys, &[0x4e; 32], &[0x42; 32], &recip.bundle)
            .unwrap();
    let msg = SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        SignalingPayload::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            PublishKeyBundlePayload {
                key_bundle: test_support::key_bundle_of(&recip),
                conn_signature: hex::encode(proof),
            },
        ),
    );
    handle_signaling_message(back, msg, &state).await.unwrap();
    let mut delivered = Vec::new();
    while let Ok((m, _permit)) = back_rx.try_recv() {
        if let Ok(UnifiedFrame::Control(ControlMessage::QueuedMessage { payload })) =
            UnifiedFrame::decode(&m)
        {
            delivered.push(payload);
        }
    }
    for b in &bodies {
        assert!(
            delivered.contains(b),
            "queued message delivered on reconnect"
        );
    }

    let logs = capture.text();
    assert!(logs.lines().count() > 5, "trace output captured:\n{logs}");
    let secrets = Secrets {
        needles: vec![
            ("circuit id", hex::encode(circuit.as_ref())),
            ("sender identity", id_sender),
            ("recipient identity", id_recip.clone()),
            ("recipient identity prefix", id_recip[..16].to_string()),
            ("offline body", "OFFLINE-SECRET-BODY".to_string()),
            ("message id", "abcdefg\u{e9}".to_string()),
            ("short message id", "ab".to_string()),
            (
                "auth tag",
                hex::encode(tok_s.authenticate(&circuit, &bodies[0])),
            ),
        ],
        ids: vec![sender_identity, recip],
    };
    // A two-letter id can legitimately occur inside unrelated words; the other
    // needles carry the real assertion.
    assert_clean(&logs, &secrets, &["short message id"]);
    assert_no_line_links_two_identity_values(&logs, &secrets.ids);
}

/// Server sources scanned by the source-level guards.
const SCANNED: &[&str] = &[
    "src/main.rs",
    "src/metrics.rs",
    "src/signaling/mod.rs",
    "src/signaling/circuits.rs",
    "src/signaling/key_auth.rs",
    "src/signaling/tags.rs",
    "src/protocol/relay.rs",
    "src/protocol/unified.rs",
    "src/tls.rs",
    "src/limits.rs",
    "src/decoy.rs",
    "src/config.rs",
    "src/signaling/pair_lock.rs",
    "src/signaling/knock_store.rs",
    "src/signaling/persist.rs",
    "src/signaling/relay_identity.rs",
    "src/signaling/fair_share.rs",
    "src/proxy_protocol.rs",
];

/// Source-level guard: no logging macro in the server sources may format a
/// known-sensitive expression.
#[test]
fn logging_macros_never_reference_sensitive_expressions() {
    let root = env!("CARGO_MANIFEST_DIR");
    let banned: &[&str] = &[
        "auth_tag",
        ".payload",
        "payload_str",
        "message_id",
        "msg_type",
        "peek_buf",
        "bin_hex",
        "hex::encode(&bin",
        "encoded_bytes",
        "ephemeral",
        "token.key",
        "identity_key_hex",
        "identity_hex",
        "target_identity",
        "key_bundle",
        "conn_signature",
        "auth_nonce",
        "channel_binding",
        "{:?}\", frame",
    ];
    let raw_hex = ["hex::encode(", "[..16"];
    let mut offenders = Vec::new();
    for rel in SCANNED {
        let src = std::fs::read_to_string(format!("{root}/{rel}")).unwrap();
        let src = strip_cfg_test_items(&src);
        for (line_no, call) in log_calls(&src) {
            let sans_tag = strip_tag_calls(&call);
            for b in banned.iter().chain(raw_hex.iter()) {
                if sans_tag.contains(b) {
                    offenders.push(format!("{rel}:{line_no}: contains `{b}`: {call}"));
                }
            }
            if call.contains("addr")
                && !call.contains("privacy::peer")
                && !call.contains("bind_addr")
                && !call.contains("persist_path")
            {
                offenders.push(format!("{rel}:{line_no}: raw address: {call}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "sensitive logging:\n{}",
        offenders.join("\n")
    );
}

/// Expressions that produce an identity-derived value (R6). Counted over the
/// whole call, format string included, so inline captures (`{caller_tag:?}`)
/// count too.
const IDENTITY_MARKERS: &[&str] = &[
    "tag_str(",
    "id_tag(",
    "pair_tag(",
    "IdTag",
    "PairTag",
    "asker_tag",
    "target_tag",
    "caller_tag",
    "peer_tag",
    "tag_a",
    "tag_b",
    "slot_a",
];

/// `privacy::tag(..)` calls in `call` whose argument is not a circuit id.
/// A `privacy::tag` of a connection id stands for whoever is proven on that
/// connection, so it counts as identity-derived; circuit ids name no one.
fn connection_tag_count(call: &str) -> usize {
    const NEEDLE: &str = "privacy::tag(";
    call.match_indices(NEEDLE)
        .filter(|(at, _)| {
            let rest = &call[at + NEEDLE.len()..];
            let mut depth = 1usize;
            let end = rest
                .char_indices()
                .find(|&(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(rest.len(), |(i, _)| i);
            let arg = &rest[..end];
            // Whole identifiers, not substrings (Task 9 minor): `cid`, `cid_*`,
            // `*_cid` or anything naming a circuit; "decide" is not one.
            let names_circuit = arg
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|w| {
                    w == "cid"
                        || w.starts_with("cid_")
                        || w.ends_with("_cid")
                        || w.contains("circuit")
                });
            !names_circuit
        })
        .count()
}

/// R6, source level: no logging call formats two identity-derived values.
#[test]
fn r6_no_logging_call_formats_two_identity_derived_values() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut offenders = Vec::new();
    for rel in SCANNED {
        let src = std::fs::read_to_string(format!("{root}/{rel}")).unwrap();
        let src = strip_cfg_test_items(&src);
        for (line_no, call) in log_calls(&src) {
            let count: usize = IDENTITY_MARKERS
                .iter()
                .map(|m| call.matches(m).count())
                .sum::<usize>()
                + connection_tag_count(&call);
            if count >= 2 {
                offenders.push(format!("{rel}:{line_no}: {count} identity values: {call}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "R6 violations:\n{}",
        offenders.join("\n")
    );
}

/// Blank out every `#[cfg(test)]`-gated item (the attribute plus the one item
/// that follows: `mod x;`, `use ..;`, or a brace-delimited block), keeping line
/// numbers intact. Everything else is left for the scan.
fn strip_cfg_test_items(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = chars.clone();
    let needle: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + needle.len() <= chars.len() {
        if chars[i..i + needle.len()] == needle[..] {
            let mut j = i + needle.len();
            let mut depth = 0i32;
            let mut in_str = false;
            while j < chars.len() {
                let c = chars[j];
                if in_str {
                    if c == '\\' {
                        j += 1;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                } else if c == ';' && depth == 0 {
                    break;
                }
                j += 1;
            }
            let end = j.min(chars.len() - 1);
            for ch in out.iter_mut().take(end + 1).skip(i) {
                if *ch != '\n' {
                    *ch = ' ';
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out.into_iter().collect()
}

/// Extract `(line, text)` of every tracing macro / println-family call,
/// spanning multiple lines.
fn log_calls(src: &str) -> Vec<(usize, String)> {
    let names = [
        "info!",
        "debug!",
        "warn!",
        "error!",
        "trace!",
        "println!",
        "eprintln!",
        "print!",
        "dbg!",
    ];
    let bytes: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest: String = bytes[i..bytes.len().min(i + 10)].iter().collect();
        let prev_ok = i == 0 || !(bytes[i - 1].is_alphanumeric() || bytes[i - 1] == '_');
        if prev_ok {
            if let Some(n) = names.iter().find(|n| rest.starts_with(**n)) {
                let mut j = i + n.len();
                while j < bytes.len() && bytes[j].is_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == '(' {
                    let (mut depth, mut k, mut in_str) = (0i32, j, false);
                    while k < bytes.len() {
                        let c = bytes[k];
                        if in_str {
                            if c == '\\' {
                                k += 1;
                            } else if c == '"' {
                                in_str = false;
                            }
                        } else if c == '"' {
                            in_str = true;
                        } else if c == '(' {
                            depth += 1;
                        } else if c == ')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        k += 1;
                    }
                    let line = bytes[..i].iter().filter(|c| **c == '\n').count() + 1;
                    let text: String = bytes[i..=k.min(bytes.len() - 1)].iter().collect();
                    out.push((line, text.split_whitespace().collect::<Vec<_>>().join(" ")));
                    i = k;
                }
            }
        }
        i += 1;
    }
    out
}

/// Remove `privacy::tag(...)` / `privacy::tag_str(...)` / `privacy::peer(...)`
/// calls (balanced) so that their sanctioned arguments are not flagged.
fn strip_tag_calls(call: &str) -> String {
    let mut s = call.to_string();
    for name in ["privacy::tag_str(", "privacy::tag(", "privacy::peer("] {
        while let Some(start) = s.find(name) {
            let mut depth = 0;
            let mut end = start;
            for (off, c) in s[start..].char_indices() {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        end = start + off + 1;
                        break;
                    }
                }
            }
            s.replace_range(start..end, "T");
        }
    }
    s
}
