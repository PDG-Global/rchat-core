//! Owner ruling 2026-10-26 (Task 8 B; review M1, L1): a relayed record
//! written in full to a connection is held until the client's TCP stack
//! has acknowledged its bytes. A connection that ends first (keepalive
//! failure, a stale connection closed by a newer publish, a client Close)
//! puts the copies still held back into the recipient's offline queue, in
//! order. A client frame alone never releases an unacknowledged copy. The
//! acknowledgement source is faked here (`FakeAck`); the kernel source has
//! its own test in `tcp_ack`. The budget is covered by `held`'s unit tests.

use super::tcp_ack::FakeAck;
use super::test_support::*;
use super::*;
use futures_util::{SinkExt, StreamExt};

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

/// Everything acknowledged, as far as a `FakeAck` can tell.
const ALL: u64 = FakeAck::ALL;

/// Relay pings every 200 ms; an unanswered one closes after 1 s.
fn short_keepalive(s: &mut RelayState) {
    s.writer_stall = Duration::from_secs(600);
    s.keepalive_ping_every = Some(Duration::from_millis(200));
    s.pong_timeout = Duration::from_secs(1);
}

/// Relayed payloads in `frames`, knocks left out (a re-queued copy of the
/// pairing's knock is a duplicate the core drops).
fn queued_payloads(frames: &[UnifiedFrame]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::QueuedMessage { payload }) => {
                Some(payload.clone())
            }
            UnifiedFrame::Relay(p) => Some(p.payload.clone()),
            _ => None,
        })
        .filter(|p| {
            !(p.len() == crate::validate::KNOCK_BYTES
                && p.first() == Some(&crate::validate::KNOCK_VERSION))
        })
        .collect()
}

/// Read `ws` until a relay packet carrying `payload` arrives.
async fn read_until_relay(ws: &mut Ws, payload: &[u8]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(m))) => {
                if let Ok(UnifiedFrame::Relay(p)) = UnifiedFrame::decode(&m) {
                    if p.payload == payload {
                        return;
                    }
                }
            }
            other => panic!("relay packet not received: {other:?}"),
        }
    }
}

fn payload(n: u8) -> Vec<u8> {
    vec![n; 150]
}

/// B's socket goes silent (never read, never answered: a phone gone
/// without a FIN) after A's packets were written to it. The relay
/// acknowledged them to A. B's keepalive times out, the held copies go
/// back into B's queue in order, and B gets them on its next connection.
#[tokio::test]
async fn copies_written_to_a_silently_dead_connection_are_requeued_in_order() {
    let (addr, state) = start_tuned(test_config(), |s| {
        short_keepalive(s);
        s.ack_override = Some(FakeAck::new(0)); // nothing ever acknowledged
    })
    .await;
    let (a, b) = (TestIdentity::from_seed(0xB0), TestIdentity::from_seed(0xB1));
    let (mut wa, wb_dead, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let dead = mapped_client(&state, &b).expect("B mapped");
    for n in 1..=3u8 {
        wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(n)))
            .await
            .unwrap();
    }
    let acks = frames_until_quiet(&mut wa, Duration::from_millis(300))
        .await
        .iter()
        .filter(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. })))
        .count();
    assert_eq!(acks, 3, "A was told the relay accepted all three");
    let st = state.clone();
    eventually_within(
        "B's dead connection closed",
        Duration::from_secs(10),
        move || !st.connections.contains_key(&dead),
    )
    .await;
    // (Knocks are left out of the count: with the production guard, the
    // pairing's knock would be re-queued too, a duplicate the core drops.)
    let st = state.clone();
    let bb = b.clone();
    eventually("the copies re-queued", move || {
        queued_len(&st, &bb) - queued_knocks(&st, &bb) == 3
    })
    .await;
    let mut wb2 = authed(addr, &b).await;
    let got = queued_payloads(&frames_until_quiet(&mut wb2, Duration::from_millis(500)).await);
    assert_eq!(got, vec![payload(1), payload(2), payload(3)], "in order");
    assert_eq!(queued_len(&state, &b), 0);
    drop(wb_dead);
}

/// The same with B reconnecting before the relay noticed: B's publish
/// closes the stale connection (Task 8 A), its held copy goes back to B's
/// queue, and B's new connection gets it at its first ask.
#[tokio::test]
async fn copies_of_a_stale_connection_reach_the_new_one() {
    let (addr, state) =
        start_tuned(test_config(), |s| s.ack_override = Some(FakeAck::new(0))).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0xB2),
        TestIdentity::from_seed(0xB3),
        TestIdentity::from_seed(0xB4),
    );
    let (mut wa, _wb_dead, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let dead = mapped_client(&state, &b).expect("B mapped");
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(7)))
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    let mut wb2 = authed(addr, &b).await;
    let st = state.clone();
    eventually("stale connection gone", move || {
        !st.connections.contains_key(&dead)
    })
    .await;
    // The first ask makes it B's foreground connection, which takes what
    // was re-queued (`note_first_ask`, or at once if the salvage came
    // after the ask).
    wb2.send(ask(&c, [0x21; 32], None)).await.unwrap();
    let got = queued_payloads(&frames_until_quiet(&mut wb2, Duration::from_millis(800)).await);
    assert_eq!(got, vec![payload(7)]);
    assert_eq!(queued_len(&state, &b), 0);
}

/// Review L2: B reconnects while its stale connection still holds p1
/// (unacknowledged). A's next packet p2 arrives while that connection is
/// being torn down. B's new connection gets p1 before p2: newer packets wait
/// in the queue behind the re-queued copies instead of overtaking them.
#[tokio::test]
async fn copies_of_a_stale_connection_stay_ahead_of_newer_packets() {
    let (addr, state) =
        start_tuned(test_config(), |s| s.ack_override = Some(FakeAck::new(0))).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0xBD),
        TestIdentity::from_seed(0xBE),
        TestIdentity::from_seed(0xBF),
    );
    let (mut wa, _wb_dead, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(1)))
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    let mut wb2 = authed(addr, &b).await;
    // At once, while the stale connection is still closing.
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(2)))
        .await
        .unwrap();
    wb2.send(ask(&c, [0x22; 32], None)).await.unwrap();
    let got = queued_payloads(&frames_until_quiet(&mut wb2, Duration::from_millis(1500)).await);
    let order: Vec<u8> = got.iter().map(|p| p[0]).collect();
    assert_eq!(order, vec![1, 2], "the older copy first");
    assert!(state.salvaging.is_empty(), "the listing ended");
}

/// Review M1: a client frame is a sign of life, not proof of arrival. A
/// copy whose bytes are not acknowledged survives B's keepalive ping and,
/// when B then goes silent and times out, is re-queued.
#[tokio::test]
async fn an_unacknowledged_copy_survives_a_client_frame_and_is_requeued() {
    let (addr, state) = start_tuned(test_config(), |s| {
        short_keepalive(s);
        s.ack_override = Some(FakeAck::new(0));
    })
    .await;
    let (a, b) = (TestIdentity::from_seed(0xB5), TestIdentity::from_seed(0xB6));
    let (mut wa, mut wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let conn = mapped_client(&state, &b).expect("B mapped");
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(9)))
        .await
        .unwrap();
    read_until_relay(&mut wb, &payload(9)).await;
    wb.send(Frame::keepalive_ping().encode()).await.unwrap();
    let st = state.clone();
    eventually_within(
        "B's connection closed",
        Duration::from_secs(10),
        move || !st.connections.contains_key(&conn),
    )
    .await;
    let st = state.clone();
    let bb = b.clone();
    eventually("re-queued", move || {
        queued_len(&st, &bb) - queued_knocks(&st, &bb) == 1
    })
    .await;
}

/// Once the client's TCP stack has acknowledged a copy's bytes it is
/// released: nothing is re-queued when the connection later dies.
#[tokio::test]
async fn an_acknowledged_copy_is_released_and_not_requeued() {
    let ack = FakeAck::new(0);
    let fake = ack.clone();
    let (addr, state) = start_tuned(test_config(), move |s| {
        short_keepalive(s);
        s.ack_override = Some(fake);
    })
    .await;
    let (a, b) = (TestIdentity::from_seed(0xBB), TestIdentity::from_seed(0xBC));
    let (mut wa, mut wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let conn = mapped_client(&state, &b).expect("B mapped");
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(8)))
        .await
        .unwrap();
    read_until_relay(&mut wb, &payload(8)).await;
    ack.set_acked(ALL);
    // Any check releases it: B's frame here (or the idle tick).
    wb.send(Frame::keepalive_ping().encode()).await.unwrap();
    let st = state.clone();
    eventually("released", move || st.held_budget.used() == 0).await;
    let st = state.clone();
    eventually_within(
        "B's connection closed",
        Duration::from_secs(10),
        move || !st.connections.contains_key(&conn),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(queued_len(&state, &b), 0, "nothing re-queued");
}

/// Review L1: a client Close releases what is acknowledged and re-queues
/// the rest (a record written while the Close was in flight).
#[tokio::test]
async fn a_client_close_requeues_only_unacknowledged_copies() {
    for (acked, expect) in [(0, 1usize), (ALL, 0)] {
        let (addr, state) = start_tuned(test_config(), |s| {
            s.ack_override = Some(FakeAck::new(acked))
        })
        .await;
        let (a, b) = (TestIdentity::random(), TestIdentity::random());
        let (mut wa, mut wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
        let conn = mapped_client(&state, &b).expect("B mapped");
        wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(5)))
            .await
            .unwrap();
        read_until_relay(&mut wb, &payload(5)).await;
        wb.close(None).await.unwrap();
        let st = state.clone();
        eventually("B's connection closed", move || {
            !st.connections.contains_key(&conn)
        })
        .await;
        let st = state.clone();
        let bb = b.clone();
        eventually("the expected re-queue", move || {
            queued_len(&st, &bb) - queued_knocks(&st, &bb) == expect
        })
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            queued_len(&state, &b) - queued_knocks(&state, &b),
            expect,
            "acked={acked}"
        );
    }
}

/// The held copies are charged to their own budget (never the offline
/// store's) while held, and released once acknowledged.
#[tokio::test]
async fn held_copies_are_charged_to_their_own_budget() {
    let ack = FakeAck::new(ALL);
    let fake = ack.clone();
    let (addr, state) = start_tuned(test_config(), move |s| s.ack_override = Some(fake)).await;
    let (a, b) = (TestIdentity::from_seed(0xB9), TestIdentity::from_seed(0xBA));
    let (mut wa, mut wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    // Both sides show life with everything acknowledged: nothing is held.
    let _ = frames_until_quiet(&mut wa, Duration::from_millis(200)).await;
    let _ = frames_until_quiet(&mut wb, Duration::from_millis(200)).await;
    wa.send(Frame::keepalive_ping().encode()).await.unwrap();
    wb.send(Frame::keepalive_ping().encode()).await.unwrap();
    let st = state.clone();
    eventually("nothing held", move || st.held_budget.used() == 0).await;
    ack.set_acked(0);
    ack.written
        .store(10_000, std::sync::atomic::Ordering::SeqCst);
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(3)))
        .await
        .unwrap();
    read_until_relay(&mut wb, &payload(3)).await;
    let st = state.clone();
    eventually("charged while held", move || st.held_budget.used() > 0).await;
    assert_eq!(
        state.offline_budget.used(),
        0,
        "the offline store is not charged"
    );
    ack.set_acked(ALL);
    wb.send(Frame::keepalive_ping().encode()).await.unwrap();
    let st = state.clone();
    eventually("released once acknowledged", move || {
        st.held_budget.used() == 0
    })
    .await;
}

/// Only relay packets and `QueuedMessage` records are held: never an ack
/// or another control frame.
#[test]
fn only_relayed_records_are_held() {
    let queued = FrameBuilder::queued_message(vec![0x02; 10]).encode();
    assert!(is_relayed_record(&queued));
    let ack = UnifiedFrame::Control(ControlMessage::MessageAck {
        message_id: "00".repeat(16),
        sender_identity: String::new(),
        recipient_identity: String::new(),
        received_at: 0,
    })
    .encode();
    assert!(!is_relayed_record(&ack));
    assert!(!is_relayed_record(&Frame::keepalive_ping().encode()));
    assert!(!is_relayed_record(&Message::Text("{}".into())));
}

/// Review L3: at shutdown with RCQ2 on, live connections' held copies go
/// into their recipients' queues before the save, so the snapshot keeps
/// them.
#[tokio::test]
async fn a_shutdown_puts_held_copies_into_the_saved_queue() {
    let (addr, state) =
        start_tuned(test_config(), |s| s.ack_override = Some(FakeAck::new(0))).await;
    let (a, b) = (TestIdentity::from_seed(0xC2), TestIdentity::from_seed(0xC3));
    let (mut wa, _wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload(6)))
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(requeue_held_for_shutdown(&state).await >= 1);
    let b_tag = tags::id_tag(&b.bytes);
    let snapshot = super::persist::snapshot_queues(&state, crate::protocol::timestamp());
    let saved = snapshot
        .queues
        .iter()
        .find(|q| q.tag == b_tag.0)
        .expect("B's queue is in the snapshot");
    assert!(
        saved.messages.iter().any(|m| m.payload == payload(6)),
        "the held copy is saved"
    );
    assert_eq!(state.held_budget.used(), 0, "nothing left held");
}

/// Re-review L-new-2: a teardown that panics after `cleanup.run()` (which
/// disarms the cleanup) still ends the connection's `salvaging` listing
/// when the cleanup is dropped while unwinding.
#[test]
fn a_disarmed_cleanup_ends_a_leftover_salvaging_listing() {
    let state = RelayState::new(Arc::new(test_config()));
    let client = ClientId::generate();
    state.salvaging.insert(client, tags::id_tag(&[7u8; 32]));
    let cleanup = ConnectionCleanup {
        client_id: client,
        state: state.clone(),
        kill: tokio_util::sync::CancellationToken::new(),
        armed: false,
        writer: None,
        held: Arc::new(super::held::HeldCopies::new(
            state.held_budget.clone(),
            super::held::HOLD_GUARD,
            FakeAck::new(0),
        )),
    };
    drop(cleanup);
    assert!(state.salvaging.is_empty());
}
