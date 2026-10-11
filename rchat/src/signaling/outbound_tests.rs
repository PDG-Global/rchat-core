//! H-1: a peer that stops reading cannot pin the relay's outbound budget.
//! Its writer gives up after `writer_stall` without progress, a spent
//! relay-wide budget closes the heaviest holder, and a keepalive ping that
//! cannot be queued closes the connection. These run over real sockets
//! where it matters (R-17's own test was a `ConnTx` unit test only).

use super::test_support::*;
use super::*;

/// Start a relay after adjusting its state (budgets, timeouts).
async fn start_tuned(
    config: ServerConfig,
    tune: impl FnOnce(&mut RelayState),
) -> (SocketAddr, RelayState) {
    let mut server = Server::new(config).await.expect("server starts");
    tune(&mut server.state);
    let addr = server.local_addr().expect("bound");
    let state = server.state();
    tokio::spawn(server.run());
    (addr, state)
}

/// No inbound throttling: the tests push megabytes through one sender.
fn fast_config() -> ServerConfig {
    ServerConfig {
        rate_limit_bps: 1 << 30,
        ..test_config()
    }
}

/// Connect and pair `a` with `b`; returns both sockets and `a`'s circuit.
async fn pair(
    state: &RelayState,
    addr: SocketAddr,
    a: &TestIdentity,
    b: &TestIdentity,
) -> (Ws, (CircuitId, Vec<u8>, CircuitId), Ws) {
    let mut wa = authed(addr, a).await;
    let mut wb = authed(addr, b).await;
    ask_each_other(state, &mut wa, a, &mut wb, b).await;
    let ca = created(&mut wa).await;
    let _ = created(&mut wb).await;
    (wa, ca, wb)
}

fn payload(len: usize, fill: u8) -> Vec<u8> {
    let mut p = vec![fill; len];
    p[0] = 0x02;
    p
}

/// Push 1 MiB packets on `cs` until at least 2 MiB stay in the (non-
/// reading) peer's relay queue - beyond what the kernel socket buffers
/// absorb, which on loopback can be several MiB and grow while sending -
/// and well under the 16 MiB per-connection cap. A momentary 2 MiB, while
/// the writer is still draining into the kernel, does not count.
async fn fill_stuck_queue(ws_s: &mut Ws, cs: &(CircuitId, Vec<u8>, CircuitId), state: &RelayState) {
    for sent in 0..40u8 {
        ws_s.send(relay_on(cs.2, &cs.1, payload(1 << 20, sent)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        if held(state) >= 2 << 20 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if held(state) >= 2 << 20 {
                assert!(held(state) < limits::OUTBOUND_QUEUE_MAX_BYTES);
                return;
            }
        }
    }
    panic!("the peer's queue never stayed filled");
}

/// Bytes currently held in `state`'s outbound queues.
fn held(state: &RelayState) -> usize {
    limits::GLOBAL_OUTBOUND_MAX_BYTES - state.outbound.available()
}

/// H-1 (b): a receiver that stops reading is closed once its writer has
/// made no progress for `writer_stall`, although its queue is far from
/// the 16 MiB slow-consumer cap and the relay-wide budget is far from
/// spent. Its queue goes back to the budget, and what it held goes to the
/// offline store under the normal caps (R-10 on the real connection-death
/// path, with the budget accounting checked).
#[tokio::test]
async fn a_receiver_that_stops_reading_is_closed_and_its_queue_released() {
    let (addr, state) = start_tuned(fast_config(), |s| {
        s.writer_stall = Duration::from_secs(1);
    })
    .await;
    let (s_id, r_id) = (TestIdentity::random(), TestIdentity::random());
    let (mut ws_s, cs, ws_r) = pair(&state, addr, &s_id, &r_id).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");

    // R never reads again. Push 1 MiB packets until at least 2 MiB sit in
    // R's relay queue (beyond what the kernel buffers absorb), well under
    // the 16 MiB per-connection cap.
    fill_stuck_queue(&mut ws_s, &cs, &state).await;

    let st = state.clone();
    eventually_within("R is closed", Duration::from_secs(5), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
    let st = state.clone();
    eventually_within("R's queue is released", Duration::from_secs(5), move || {
        held(&st) < 64 << 10
    })
    .await;
    // What R's queue held was acknowledged to S; it is back in R's offline
    // queue, charged to the offline budget exactly once.
    let st = state.clone();
    let tag = tags::id_tag(&r_id.bytes);
    eventually_within("salvaged", Duration::from_secs(5), move || {
        st.message_queues.contains_key(&tag)
    })
    .await;
    let q = state.message_queues.get(&tag).unwrap();
    assert!(!q.pending.is_empty());
    assert_eq!(q.bytes, state.offline_budget.used());
    drop(ws_r);
}

/// H-1 (a): when the relay-wide budget is spent, the connection holding
/// the most of it (a receiver that stopped reading) is closed and its
/// bytes released, and relaying between other connections goes on live.
/// The writer stall timeout is left long so only shedding can act.
#[tokio::test]
async fn a_spent_global_budget_sheds_the_stuck_reader_and_others_keep_flowing() {
    let (addr, state) = start_tuned(fast_config(), |s| {
        s.outbound = limits::OutboundBudget::new(6 << 20);
        s.writer_stall = Duration::from_secs(600);
    })
    .await;
    let (s_id, r_id) = (TestIdentity::random(), TestIdentity::random());
    let (c_id, d_id) = (TestIdentity::random(), TestIdentity::random());
    let (mut ws_s, cs, ws_r) = pair(&state, addr, &s_id, &r_id).await;
    let (mut ws_c, cc, mut ws_d) = pair(&state, addr, &c_id, &d_id).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");

    // S floods R, which never reads, until R is gone.
    let st = state.clone();
    let flood = tokio::spawn(async move {
        for i in 0..64u8 {
            if !st.connections.contains_key(&r_client) {
                break;
            }
            if ws_s
                .send(relay_on(cs.2, &cs.1, payload(1 << 20, i)))
                .await
                .is_err()
            {
                break;
            }
        }
        ws_s
    });
    let st = state.clone();
    eventually_within(
        "the stuck reader is shed",
        Duration::from_secs(30),
        move || !st.connections.contains_key(&r_client),
    )
    .await;
    let _ws_s = flood.await.unwrap();
    let full = 6usize << 20;
    let st = state.clone();
    eventually_within(
        "R's bytes are released",
        Duration::from_secs(5),
        move || st.outbound.available() > full - (64 << 10),
    )
    .await;

    // C -> D is relayed live (not parked offline after a 5 s wait).
    let started = Instant::now();
    ws_c.send(relay_on(cc.2, &cc.1, payload(64, 0x77)))
        .await
        .unwrap();
    let got = loop {
        match tokio::time::timeout(Duration::from_secs(3), ws_d.next()).await {
            Ok(Some(Ok(m))) => match UnifiedFrame::decode(&m) {
                Ok(UnifiedFrame::Relay(p)) => break Some(p.payload),
                _ => continue,
            },
            _ => break None,
        }
    };
    assert_eq!(got, Some(payload(64, 0x77)), "D gets C's packet live");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        state
            .connections
            .iter()
            .any(|c| c.proven_identity == Some(d_id.bytes)),
        "D was not shed"
    );
    drop(ws_r);
}

/// N-1: a ping refused only because the relay-wide budget is held by
/// someone else does not close the pinging connection; the next tick
/// pings again once there is room.
#[tokio::test]
async fn a_ping_refused_by_a_spent_global_budget_is_retried_not_fatal() {
    let state = RelayState::new(Arc::new(test_config()));
    let budget = limits::OutboundBudget::new(16);
    let (hog, hog_rx, _) = ConnTx::channel_with_global(budget.clone());
    hog.send(Message::Binary(vec![0; 16])).unwrap();
    let (mut conn, _rx) = bare_connection([0u8; 32]);
    let (tx, mut conn_rx, _) = ConnTx::channel_with_global(budget);
    conn.ws_tx = tx.clone();
    let client = conn.client_id;
    state.connections.insert(client, conn);

    assert!(keepalive_tick(
        client,
        &state.connections,
        Instant::now(),
        PONG_TIMEOUT,
        None
    ));
    assert!(!tx.is_closed(), "an innocent pinger stays");
    assert!(state
        .connections
        .get(&client)
        .unwrap()
        .pending_ping
        .is_none());
    drop(hog_rx); // the heaviest holder let go
    assert!(keepalive_tick(
        client,
        &state.connections,
        Instant::now(),
        PONG_TIMEOUT,
        None
    ));
    assert!(conn_rx.try_recv().is_ok(), "the next tick pings");
    assert!(state
        .connections
        .get(&client)
        .unwrap()
        .pending_ping
        .is_some());
}

/// H-1 (c): a ping that cannot be queued because the peer's own queue is
/// full (it is not draining) closes the connection.
#[tokio::test]
async fn a_ping_into_a_full_queue_closes_the_connection() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, _rx) = bare_connection([0u8; 32]);
    let tx = conn.ws_tx.clone();
    tx.send(Message::Binary(vec![0; limits::OUTBOUND_QUEUE_MAX_BYTES]))
        .unwrap();
    let client = conn.client_id;
    state.connections.insert(client, conn);

    assert!(!keepalive_tick(
        client,
        &state.connections,
        Instant::now(),
        PONG_TIMEOUT,
        None
    ));
    assert!(tx.is_closed(), "the connection was told to close");
}

/// A healthy connection gets a ping and stays; an unanswered one is closed
/// `PONG_TIMEOUT` after its ping was written.
#[tokio::test]
async fn keepalive_pings_then_times_out_an_unanswered_ping() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, mut rx) = bare_connection([0u8; 32]);
    let tx = conn.ws_tx.clone();
    let client = conn.client_id;
    state.connections.insert(client, conn);
    let t0 = Instant::now();

    assert!(keepalive_tick(
        client,
        &state.connections,
        t0,
        PONG_TIMEOUT,
        None
    ));
    assert!(rx.try_recv().is_ok(), "a ping was queued");
    let written = Some(t0 + Duration::from_secs(1));
    assert!(keepalive_tick(
        client,
        &state.connections,
        t0 + Duration::from_secs(1) + PONG_TIMEOUT,
        PONG_TIMEOUT,
        written
    ));
    assert!(!tx.is_closed());
    assert!(!keepalive_tick(
        client,
        &state.connections,
        t0 + Duration::from_secs(2) + PONG_TIMEOUT,
        PONG_TIMEOUT,
        written
    ));
    assert!(tx.is_closed());
}

/// Debug-voice-loss: a ping not yet written (queued behind a frame the
/// peer is still reading) does not time out, however long it waits; an
/// older ping's write time does not count for it either.
#[tokio::test]
async fn an_unwritten_ping_does_not_time_out() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, _rx) = bare_connection([0u8; 32]);
    let tx = conn.ws_tx.clone();
    let client = conn.client_id;
    let before = Instant::now();
    state.connections.insert(client, conn);
    let t0 = before + Duration::from_millis(10);
    assert!(keepalive_tick(
        client,
        &state.connections,
        t0,
        PONG_TIMEOUT,
        Some(before)
    ));
    let late = t0 + PONG_TIMEOUT * 5;
    assert!(keepalive_tick(
        client,
        &state.connections,
        late,
        PONG_TIMEOUT,
        None
    ));
    assert!(keepalive_tick(
        client,
        &state.connections,
        late,
        PONG_TIMEOUT,
        Some(before)
    ));
    assert!(!tx.is_closed());
}

/// Open a raw WebSocket (upgrade done by hand) so a test can send a
/// partial frame, which no WebSocket client library will do.
async fn raw_upgrade(addr: SocketAddr) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "upgrade refused");
    tcp
}

/// Send the header of one masked binary frame of `total` bytes and the
/// first `sent` bytes of its payload, then stop.
async fn partial_frame(tcp: &mut tokio::net::TcpStream, total: usize, sent: usize) {
    use tokio::io::AsyncWriteExt;
    let mut header = vec![0x82, 0x80 | 127];
    header.extend_from_slice(&(total as u64).to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    tcp.write_all(&header).await.unwrap();
    let chunk = vec![0x5a; 64 << 10];
    let mut left = sent;
    while left > 0 {
        let n = left.min(chunk.len());
        tcp.write_all(&chunk[..n]).await.unwrap();
        left -= n;
    }
}

/// True once the relay has closed `tcp` (EOF or reset).
async fn tcp_closed_within(tcp: &mut tokio::net::TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, tcp.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
        }
    }
}

/// M-5: bytes of messages still being received count against one
/// relay-wide buffer budget. Past it, the connection holding the most -
/// here one that sent most of a large message and stopped - is closed and
/// its bytes released; a lighter one is not, and the relay keeps serving.
#[tokio::test]
async fn partial_messages_count_against_the_buffer_budget_and_the_heaviest_goes() {
    let cap = 3usize << 20;
    let (addr, state) = start_tuned(test_config(), |s| {
        s.buffers = limits::BufferBudget::new(cap);
    })
    .await;
    let mut heavy = raw_upgrade(addr).await;
    partial_frame(&mut heavy, 4 << 20, 2_500 << 10).await;
    let st = state.clone();
    eventually_within(
        "the partial message is charged",
        Duration::from_secs(5),
        move || st.buffers.used() >= 2_400 << 10,
    )
    .await;
    let mut light = raw_upgrade(addr).await;
    partial_frame(&mut light, 4 << 20, 1 << 20).await;

    assert!(
        tcp_closed_within(&mut heavy, Duration::from_secs(5)).await,
        "the heaviest holder is closed"
    );
    let st = state.clone();
    eventually_within(
        "its bytes are released",
        Duration::from_secs(5),
        move || st.buffers.used() <= cap,
    )
    .await;
    assert!(
        !tcp_closed_within(&mut light, Duration::from_millis(300)).await,
        "the lighter connection stays"
    );
    // The relay still serves new clients.
    let _ws = authed(addr, &TestIdentity::random()).await;
}

/// L-6: when a connection task panics, the relayed messages still in its
/// queue (already acknowledged to their senders) are re-queued for the
/// identity, as on a normal close - not dropped.
#[tokio::test]
async fn a_panicking_connection_still_salvages_its_queue() {
    let (addr, state) = start_tuned(fast_config(), |_| {}).await;
    let (s_id, r_id) = (TestIdentity::random(), TestIdentity::random());
    let (mut ws_s, cs, mut ws_r) = pair(&state, addr, &s_id, &r_id).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");
    fill_stuck_queue(&mut ws_s, &cs, &state).await;

    let boom = SignalingMessage::new("test_panic", SignalingPayload::simple("test_panic"));
    ws_r.send(UnifiedFrame::signaling(boom).encode())
        .await
        .unwrap();
    let st = state.clone();
    eventually_within("R's task is gone", Duration::from_secs(5), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
    let st = state.clone();
    let tag = tags::id_tag(&r_id.bytes);
    eventually_within("R's queue is salvaged", Duration::from_secs(5), move || {
        st.message_queues
            .get(&tag)
            .is_some_and(|q| !q.pending.is_empty())
    })
    .await;
    let q = state.message_queues.get(&tag).unwrap();
    assert_eq!(q.bytes, state.offline_budget.used());
}

/// N-2: control frames interleaved between the fragments of a data message
/// do not reset the buffer meter; the codec still holds the fragments.
#[tokio::test]
async fn an_interleaved_ping_does_not_reset_the_buffer_meter() {
    use tokio::io::AsyncWriteExt;
    let (addr, state) = start_tuned(test_config(), |_| {}).await;
    let mut tcp = raw_upgrade(addr).await;
    // A first fragment (binary, FIN clear) of 2.5 MiB, complete.
    let len = 2_500usize << 10;
    let mut header = vec![0x02, 0x80 | 127];
    header.extend_from_slice(&(len as u64).to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    tcp.write_all(&header).await.unwrap();
    tcp.write_all(&vec![0x5a; len]).await.unwrap();
    let st = state.clone();
    eventually_within(
        "the fragment is charged",
        Duration::from_secs(5),
        move || st.buffers.used() >= len,
    )
    .await;
    // Then a masked, empty Ping. The relay answers it with a Pong.
    tcp.write_all(&[0x89, 0x80, 1, 2, 3, 4]).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .expect("a pong")
        .unwrap();
    assert!(
        n >= 2 && buf[0] == 0x8a,
        "pong expected, got {:?}",
        &buf[..n]
    );
    assert!(
        state.buffers.used() >= len,
        "the fragment is still charged: {}",
        state.buffers.used()
    );
}

/// The relay-wide budgets come from the config, so a small host can size
/// them to its RAM.
#[test]
fn relay_budgets_come_from_the_config() {
    let config = ServerConfig {
        outbound_budget_bytes: 32 << 20,
        buffer_budget_bytes: 64 << 20,
        ..test_config()
    };
    config.validate().expect("valid budgets");
    let state = RelayState::new(Arc::new(config));
    assert_eq!(state.outbound.available(), 32 << 20);
    assert_eq!(state.buffers.used(), 0);
    assert_eq!(state.buffers.cap(), 64 << 20);
}
