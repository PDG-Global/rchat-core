//! Debug-voice-loss: a relay packet acknowledged to its sender must not be
//! lost when the recipient's connection ends while the relay's writer is
//! in the middle of writing it. Over real sockets: the recipient stops
//! reading, so a message larger than the loopback socket buffers stays
//! part-written, and then the recipient's socket goes away.

use super::test_support::*;
use super::*;

/// A frame bigger than the loopback send and receive buffers together
/// (4 MiB + 4 MiB autotuned on macOS; less on Linux), under the 16 MiB
/// per-connection outbound cap and the per-recipient offline cap.
const BIG: usize = 12 << 20;

fn big_config() -> ServerConfig {
    ServerConfig {
        rate_limit_bps: 1 << 30,
        max_message_bytes: 16 << 20,
        // Room for more than one copy of a big frame: a double salvage
        // would be admitted, and caught, rather than refused by the cap.
        offline_queue_max_bytes_per_recipient: 64 << 20,
        ..test_config()
    }
}

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

fn payload(len: usize, fill: u8) -> Vec<u8> {
    let mut p = vec![fill; len];
    p[0] = 0x02;
    p
}

/// Bytes currently held in `state`'s outbound queues.
fn held(state: &RelayState) -> usize {
    limits::GLOBAL_OUTBOUND_MAX_BYTES - state.outbound.available()
}

/// The payloads waiting in `id`'s offline queue, oldest first.
fn queued(state: &RelayState, id: &TestIdentity) -> Vec<Vec<u8>> {
    state
        .message_queues
        .get(&tags::id_tag(&id.bytes))
        .map(|q| q.pending.iter().map(|m| m.payload.clone()).collect())
        .unwrap_or_default()
}

/// Wait until S's packet has been acknowledged.
async fn acked(ws: &mut Ws) {
    loop {
        match next_control(ws, Duration::from_secs(10)).await {
            Some(ControlMessage::MessageAck { .. }) => return,
            Some(_) => continue,
            None => panic!("no MessageAck"),
        }
    }
}

/// The relay acknowledged S's large packet and its writer is part-way
/// through writing it to R (R stopped reading). R's socket then goes:
/// the packet is back in R's offline queue, whole.
#[tokio::test]
async fn a_part_written_relay_packet_goes_back_to_the_offline_queue() {
    let (addr, state) = start_tuned(big_config(), |s| {
        s.writer_stall = Duration::from_secs(600);
    })
    .await;
    let (s_id, r_id) = (TestIdentity::random(), TestIdentity::random());
    let mut ws_s = authed(addr, &s_id).await;
    let mut ws_r = authed(addr, &r_id).await;
    ask_each_other(&state, &mut ws_s, &s_id, &mut ws_r, &r_id).await;
    let cs = created(&mut ws_s).await;
    let _ = created(&mut ws_r).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");

    // R reads nothing from here on.
    let big = payload(BIG, 0x5c);
    ws_s.send(relay_on(cs.2, &cs.1, big.clone())).await.unwrap();
    acked(&mut ws_s).await;
    // The writer has it: the queue's byte budget stays held until the
    // write completes, and the kernel buffers cannot take 12 MiB.
    let st = state.clone();
    eventually_within(
        "the writer holds the packet",
        Duration::from_secs(5),
        move || held(&st) >= BIG,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(held(&state) >= BIG, "the write must still be in progress");
    assert!(queued(&state, &r_id).is_empty());

    drop(ws_r);
    let st = state.clone();
    eventually_within("R is gone", Duration::from_secs(5), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
    let st = state.clone();
    let r = r_id.clone();
    eventually_within(
        "the packet is re-queued",
        Duration::from_secs(5),
        move || !queued(&st, &r).is_empty(),
    )
    .await;
    let q = queued(&state, &r_id);
    assert_eq!(q.len(), 1);
    assert!(q[0] == big, "the whole payload, unchanged");
    let tag = tags::id_tag(&r_id.bytes);
    assert_eq!(
        state.message_queues.get(&tag).unwrap().bytes,
        state.offline_budget.used(),
        "charged to the offline budget exactly once"
    );
}

/// The same for a stored message being handed over (`QueuedMessage`, as
/// the drain on publish and the D34 hand-over send it): a part-written
/// record goes back too, and is delivered on the recipient's next
/// connection.
#[tokio::test]
async fn a_part_written_queued_record_goes_back_and_is_delivered_later() {
    let (addr, state) = start_tuned(big_config(), |s| {
        s.writer_stall = Duration::from_secs(600);
    })
    .await;
    let r_id = TestIdentity::random();
    let big = payload(BIG, 0x6d);
    queue_test_message(&state, &r_id, big.clone());

    // R connects and publishes; the drain hands the record over, and R
    // reads nothing more.
    let ws_r = authed(addr, &r_id).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");
    let st = state.clone();
    eventually_within(
        "the writer holds the record",
        Duration::from_secs(5),
        move || held(&st) >= BIG,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(held(&state) >= BIG);
    assert!(queued(&state, &r_id).is_empty());

    drop(ws_r);
    let st = state.clone();
    eventually_within("R is gone", Duration::from_secs(5), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
    let st = state.clone();
    let r = r_id.clone();
    eventually_within(
        "the record is re-queued",
        Duration::from_secs(5),
        move || queued(&st, &r).len() == 1,
    )
    .await;

    // Delivered whole on the next connection.
    let mut ws_r2 = authed(addr, &r_id).await;
    loop {
        match next_control(&mut ws_r2, Duration::from_secs(10)).await {
            Some(ControlMessage::QueuedMessage { payload }) => {
                assert!(payload == big);
                break;
            }
            Some(_) => continue,
            None => panic!("the re-queued record was not delivered"),
        }
    }
}

/// The stored records waiting for `id`, oldest first.
fn stored(state: &RelayState, id: &TestIdentity) -> Vec<(Vec<u8>, u64)> {
    state
        .message_queues
        .get(&tags::id_tag(&id.bytes))
        .map(|q| {
            q.pending
                .iter()
                .map(|m| (m.payload.clone(), m.enqueued_at_unix_secs))
                .collect()
        })
        .unwrap_or_default()
}

/// R connects and publishes, so the drain hands it its queue; R reads
/// nothing, so the first (big) record stays part-written. Waits until
/// `held_bytes` sit in R's outbound queue, then R's socket goes. Returns
/// once R is gone.
async fn hand_over_then_drop(
    addr: SocketAddr,
    state: &RelayState,
    r_id: &TestIdentity,
    held_bytes: usize,
) {
    let ws_r = authed(addr, r_id).await;
    let r_client = mapped_client(state, r_id).expect("R is mapped");
    let st = state.clone();
    eventually_within(
        "the queue is handed over",
        Duration::from_secs(5),
        move || held(&st) >= held_bytes,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        held(state) >= held_bytes,
        "the big record must still be part-written"
    );
    assert!(queued(state, r_id).is_empty());
    drop(ws_r);
    let st = state.clone();
    eventually_within("R is gone", Duration::from_secs(5), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
}

/// TG-1: the part-written record goes back first, ahead of the records
/// still waiting in the connection's queue, which keep their order.
#[tokio::test]
async fn the_part_written_record_is_requeued_before_the_waiting_ones() {
    let (addr, state) = start_tuned(big_config(), |s| {
        s.writer_stall = Duration::from_secs(600);
    })
    .await;
    let r_id = TestIdentity::random();
    let now = crate::protocol::timestamp();
    let records = [
        payload(BIG, 0x0a),
        payload(1024, 0x0b),
        payload(1024, 0x0c),
        payload(1024, 0x0d),
    ];
    for r in &records {
        queue_test_message_at(&state, &r_id, r.clone(), now);
    }
    hand_over_then_drop(addr, &state, &r_id, BIG + 3 * 1024).await;
    let st = state.clone();
    let r = r_id.clone();
    eventually_within(
        "all four are re-queued",
        Duration::from_secs(5),
        move || queued(&st, &r).len() == 4,
    )
    .await;
    let q = queued(&state, &r_id);
    let fills: Vec<u8> = q.iter().map(|p| p[1]).collect();
    assert_eq!(
        fills,
        vec![0x0a, 0x0b, 0x0c, 0x0d],
        "in-flight first, then in order"
    );
    assert!(q[0] == records[0], "the big record whole");
}

/// L-2: a re-queued record keeps the time it was first stored, so a record
/// handed over and re-queued again and again still expires at its TTL.
#[tokio::test]
async fn a_requeued_record_keeps_its_first_store_time_and_still_expires() {
    let (addr, state) = start_tuned(big_config(), |s| {
        s.writer_stall = Duration::from_secs(600);
    })
    .await;
    let r_id = TestIdentity::random();
    let ttl = state.config.offline_queue.ttl_secs;
    let first = crate::protocol::timestamp() - (ttl - 60); // a minute left
    let small_at = first + 5;
    queue_test_message_at(&state, &r_id, payload(BIG, 0x1a), first);
    queue_test_message_at(&state, &r_id, payload(1024, 0x1b), small_at);
    hand_over_then_drop(addr, &state, &r_id, BIG + 1024).await;
    let st = state.clone();
    let r = r_id.clone();
    eventually_within("both are re-queued", Duration::from_secs(5), move || {
        queued(&st, &r).len() == 2
    })
    .await;
    let stamps: Vec<u64> = stored(&state, &r_id).iter().map(|(_, t)| *t).collect();
    assert_eq!(
        stamps,
        vec![first, small_at],
        "first store times kept (in flight and queued)"
    );
    // Past the TTL counted from the first store, both are gone.
    expire_queues(first + ttl + 6, &state);
    assert!(
        queued(&state, &r_id).is_empty(),
        "expired at the original TTL"
    );
    assert_eq!(state.offline_budget.used(), 0);
}
