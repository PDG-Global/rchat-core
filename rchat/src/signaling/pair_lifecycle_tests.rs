//! Pair lifecycle against the v2 relay (spec §6.2): resume, teardown, member
//! close, orphaning on disconnect, the sweep, and knock delivery timing (L7).

use super::test_support::*;
use super::*;
use crate::limits::Outbound;
use crate::protocol::signaling::KeyBundle;
use crate::protocol::unified::CircuitCloseReason;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;

/// Map an identity to a connection the way a successful publish does
/// (`identity_to_client` is keyed by the per-boot `IdTag` since Task 6).
fn map_identity(state: &RelayState, id: &TestIdentity, client: ClientId) {
    state
        .identity_to_client
        .insert(tags::id_tag(&id.bytes), client);
}

/// The connection an identity is routed to, if any.
fn mapped(state: &RelayState, id: &TestIdentity) -> Option<ClientId> {
    state
        .identity_to_client
        .get(&tags::id_tag(&id.bytes))
        .map(|c| *c)
}

/// A connection inserted straight into the state (no socket): proven as
/// `id` when given. Returns the outbound receiver (never drained unless the
/// test reads it) and the kill token.
fn fake_conn(
    state: &RelayState,
    id: Option<&TestIdentity>,
) -> (ClientId, Receiver<Outbound>, CancellationToken) {
    let client_id = ClientId::generate();
    let (tx, rx, kill) = ConnTx::channel();
    let now = Instant::now();
    state.connections.insert(
        client_id,
        UnifiedConnection {
            client_id,
            _addr: "127.0.0.1:1".parse().unwrap(),
            ws_tx: tx,
            key_bundle: id.map(|i| KeyBundle {
                identity_key: i.hex.clone(),
                identity_agreement_key: hex::encode(i.bundle.identity_agreement_key),
                kem_pk: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &i.bundle.kem_pk[..],
                ),
                bundle_signature: hex::encode(i.bundle.bundle_signature),
                one_time_pre_keys: Vec::new(),
            }),
            identity_key: id.map(|i| i.hex.clone()),
            last_activity: now,
            circuits: Arc::new(DashMap::new()),
            last_pong: now,
            pending_ping: None,
            identified: id.is_some(),
            created_circuits: Default::default(),
            pending_charges: Default::default(),
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            auth_nonce: None,
            channel_binding: [0u8; 32],
            proven_identity: id.map(|i| i.bytes),
            closing: false,
            auth_budget: crate::limits::AuthBudget::new(Instant::now()),
            source: None,
            has_asked: false,
            blind_ask_bucket: None,
            peer_bundle: None,
        },
    );
    if let Some(i) = id {
        map_identity(state, i, client_id);
    }
    (client_id, rx, kill)
}

async fn until_relay(ws: &mut Ws, wait: Duration) -> Option<RelayPacket> {
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Ok(Some(Ok(m))) => {
                if let Ok(UnifiedFrame::Relay(p)) = UnifiedFrame::decode(&m) {
                    return Some(p);
                }
            }
            _ => return None,
        }
    }
}

fn is_closed_normal(m: &ControlMessage) -> bool {
    matches!(
        m,
        ControlMessage::CircuitClosed {
            reason: CircuitCloseReason::Normal,
            ..
        }
    )
}

// ---------------------------------------------------------------- A5 (resume)

#[tokio::test]
async fn a5_valid_resume_rebinds_only_the_callers_slot() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x51), TestIdentity::from_seed(0x52));
    let (mut a1, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;

    // A comes back on a second socket (transport reconnect) and resumes.
    let mut a2 = authed(addr, &a).await;
    a2.send(ask(&b, rand::random(), Some(ca.circuit_id)))
        .await
        .unwrap();
    match until_control(&mut a2, |m| {
        matches!(m, ControlMessage::CircuitExists { .. })
    })
    .await
    {
        Some(ControlMessage::CircuitExists {
            circuit_id,
            target_circuit_id,
            is_initiator,
            ..
        }) => {
            assert_eq!(circuit_id, ca.circuit_id);
            assert_eq!(target_circuit_id, ca.target_circuit_id);
            assert_eq!(is_initiator, ca.role == 0);
        }
        other => panic!("expected CircuitExists, got {other:?}"),
    }
    assert!(
        until_control(&mut wb, |m| matches!(
            m,
            ControlMessage::CircuitExists { .. }
        ))
        .await
        .is_some(),
        "the online peer is told too"
    );
    assert_eq!(
        state.identity_pair_circuits.len(),
        1,
        "same pair, not a new one"
    );

    // B's traffic now reaches the resumed socket, not the old one.
    wb.send(relay_on(cb.target_circuit_id, &cb.token, vec![0x02; 200]))
        .await
        .unwrap();
    assert!(until_relay(&mut a2, Duration::from_secs(3)).await.is_some());
    assert!(until_relay(&mut a1, Duration::from_millis(500))
        .await
        .is_none());
}

#[tokio::test]
async fn a5_resume_naming_another_circuit_tears_down_only_the_callers_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x53), TestIdentity::from_seed(0x54));
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;

    // A names B's circuit: not the caller's side of the pair -> teardown.
    wa.send(ask(&b, rand::random(), Some(cb.circuit_id)))
        .await
        .unwrap();
    assert!(until_control(&mut wb, is_closed_normal).await.is_some());
    let st = state.clone();
    let (x, y) = (ca.circuit_id, cb.circuit_id);
    eventually("old routing removed", move || {
        !st.circuits.contains_key(&x) && !st.circuits.contains_key(&y)
    })
    .await;
    // The ask itself continues as a fresh pending ask (step 3/5).
    assert_eq!(state.pending_asks.len(), 1);
}

#[tokio::test]
async fn a5_resume_from_an_identity_that_is_not_the_slots_does_not_rebind() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0x55),
        TestIdentity::from_seed(0x56),
        TestIdentity::from_seed(0x57),
    );
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;

    // C asks A naming A's circuit: (C, A) has no active pair, so the resume
    // is meaningless; A <-> B must be untouched.
    let mut wc = authed(addr, &c).await;
    wc.send(ask(&a, rand::random(), Some(ca.circuit_id)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(state.circuits.contains_key(&ca.circuit_id));
    assert!(state.circuits.contains_key(&cb.circuit_id));
    assert!(until_control(&mut wc, |m| matches!(
        m,
        ControlMessage::CircuitExists { .. }
    ))
    .await
    .is_none());
    wb.send(relay_on(cb.target_circuit_id, &cb.token, vec![0x02; 200]))
        .await
        .unwrap();
    assert!(
        until_relay(&mut wa, Duration::from_secs(3)).await.is_some(),
        "A's slot still routes to A"
    );
}

// ------------------------------------------------------------------- A8 (H2)

#[tokio::test]
async fn a8_member_close_tears_down_the_whole_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x58), TestIdentity::from_seed(0x59));
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;

    wa.send(FrameBuilder::close_circuit(ca.circuit_id).encode())
        .await
        .unwrap();
    match until_control(&mut wb, is_closed_normal).await {
        Some(ControlMessage::CircuitClosed { circuit_id, .. }) => {
            assert!(circuit_id == cb.circuit_id || circuit_id == ca.circuit_id)
        }
        other => panic!("B must get CircuitClosed{{Normal}}, got {other:?}"),
    }
    assert!(!state.circuits.contains_key(&ca.circuit_id));
    assert!(!state.circuits.contains_key(&cb.circuit_id));
    assert_eq!(state.identity_pair_circuits.len(), 0);

    // B's packet on the old circuit is refused, not queued.
    wb.send(relay_on(cb.target_circuit_id, &cb.token, vec![0x02; 200]))
        .await
        .unwrap();
    match until_control(&mut wb, |m| matches!(m, ControlMessage::Error { .. })).await {
        Some(ControlMessage::Error { code, .. }) => {
            assert!(matches!(code, ControlErrorCode::CircuitNotFound))
        }
        other => panic!("expected CircuitNotFound, got {other:?}"),
    }
    assert!(state.message_queues.get(&tags::id_tag(&a.bytes)).is_none());
}

#[tokio::test]
async fn a8_close_from_a_non_member_is_ignored() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0x5a),
        TestIdentity::from_seed(0x5b),
        TestIdentity::from_seed(0x5c),
    );
    let (_wa, _wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    let mut wc = authed(addr, &c).await;
    wc.send(FrameBuilder::close_circuit(ca.circuit_id).encode())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(state.circuits.contains_key(&ca.circuit_id));
    assert!(state.circuits.contains_key(&cb.circuit_id));
    assert_eq!(state.identity_pair_circuits.len(), 1);
}

// ------------------------------------------------------------------ Q1 (L7)

#[tokio::test]
async fn q1_knock_to_an_online_target_with_a_full_queue_takes_no_longer_than_offline() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (x, b, d) = (
        TestIdentity::from_seed(0x61),
        TestIdentity::from_seed(0x62),
        TestIdentity::from_seed(0x63),
    );
    let (caller, _rx_x, _kx) = fake_conn(&state, Some(&x));
    let (target, _rx_b, kill_b) = fake_conn(&state, Some(&b));

    // Fill B's outbound queue to capacity without draining it.
    let tx_b = state.connections.get(&target).unwrap().ws_tx.clone();
    for _ in 0..crate::limits::OUTBOUND_QUEUE_CAPACITY {
        tx_b.send(Message::Binary(vec![0u8; 16])).unwrap();
    }

    let t0 = Instant::now();
    circuits::handle_circuit_ask(
        caller,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(1),
        None,
        &state,
    )
    .await;
    let online_full = t0.elapsed();

    let t1 = Instant::now();
    circuits::handle_circuit_ask(
        caller,
        d.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(2),
        None,
        &state,
    )
    .await;
    let offline = t1.elapsed();

    // A blocked send would wait for queue space (seconds); 1 s leaves room
    // for a loaded machine without hiding that (Task 7 minor: 50 ms could flake).
    let bound = Duration::from_secs(1);
    assert!(online_full < bound, "full-queue ask took {online_full:?}");
    assert!(offline < bound, "offline ask took {offline:?}");
    assert!(
        !kill_b.is_cancelled(),
        "a knock must never disconnect its target"
    );
    for id in [&b, &d] {
        let knocks = state
            .message_queues
            .get(&tags::id_tag(&id.bytes))
            .map(|q| q.pending.iter().filter(|m| m.is_knock).count());
        assert_eq!(knocks, Some(1), "knock fell back to the store");
    }
}

// ------------------------------------------------------------------------ Q3

#[tokio::test]
async fn q3_pending_asks_expire_after_ask_ttl_via_the_sweep() {
    let (addr, state) = start(test_config()).await;
    let (a, offline) = (TestIdentity::from_seed(0x64), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    wa.send(ask(&offline, rand::random(), None)).await.unwrap();
    let st = state.clone();
    eventually("ask registered", move || st.pending_asks.len() == 1).await;

    // ASK_TTL is 540 s, so with the 60 s sweep the ask is gone within 600 s.
    sweep_stale_state(Instant::now() + Duration::from_secs(539), &state);
    assert_eq!(state.pending_asks.len(), 1, "still inside the window");
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert_eq!(state.pending_asks.len(), 0, "expired after ASK_TTL (540 s)");
}

// ------------------------------------------------------------------------ Q6

#[tokio::test]
async fn q6_ask_with_an_invalid_resume_tears_down_the_active_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x6a), TestIdentity::from_seed(0x6b));
    let (mut wa, mut wb, _ca, _cb) = pair_up(&state, addr, &a, &b).await;
    wa.send(ask(&b, rand::random(), Some(CircuitId::generate())))
        .await
        .unwrap();
    assert!(until_control(&mut wb, is_closed_normal).await.is_some());
    assert_eq!(state.identity_pair_circuits.len(), 0);
}

// ------------------------------------------------------------------------ Q8

/// Re-ask rounds a simulated client tries before giving up. Far above what
/// a correct relay needs, so the ask-count bound in `q8_scenario` can fail.
const Q8_MAX_ROUNDS: u32 = 10;

/// Protocol-level client: closes its circuit, then re-asks with 2 s, 4 s,
/// 8 s, ... (x (1 + jitter)) backoff until a pair forms. Returns the round in
/// which its `CircuitCreatedV3` arrived.
async fn sim_client(
    state: RelayState,
    me: ClientId,
    peer: [u8; 32],
    mut rx: Receiver<Outbound>,
    jitter: f64,
    asks: Arc<AtomicUsize>,
) -> u32 {
    // The initial pair's CircuitCreatedV3 (a knock may precede it).
    let own = loop {
        let (msg, _) = rx.recv().await.expect("connection open");
        if let Ok(UnifiedFrame::Control(ControlMessage::CircuitCreatedV3 { circuit_id, .. })) =
            UnifiedFrame::decode(&msg)
        {
            break circuit_id;
        }
    };
    // Both members close at the same instant.
    circuits::handle_close_circuit(me, own, &state).await;
    for round in 1..=Q8_MAX_ROUNDS {
        let delay = Duration::from_secs_f64(2f64.powi(round as i32) * (1.0 + jitter));
        tokio::time::sleep(delay).await;
        asks.fetch_add(1, Ordering::SeqCst);
        circuits::handle_circuit_ask(
            me,
            peer,
            rand::random(),
            kem_for(rand::random()),
            knock(round as u8),
            None,
            &state,
        )
        .await;
        let deadline = tokio::time::sleep(Duration::from_secs_f64(2f64.powi(round as i32 + 1)));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                m = rx.recv() => {
                    let (msg, _) = m.expect("connection open");
                    if let Ok(UnifiedFrame::Control(ControlMessage::CircuitCreatedV3 { .. })) =
                        UnifiedFrame::decode(&msg)
                    {
                        return round;
                    }
                }
            }
        }
    }
    panic!("no pair within {Q8_MAX_ROUNDS} rounds");
}

/// `seed`: distinct identities per scenario (each passes its own), since
/// pair locks are process-global per pair tag and scenarios running in
/// parallel must not share a pair (Task 8 minor: was derived from jitter).
async fn q8_scenario(seed: u8, jitter_a: f64, jitter_b: f64) {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (a, b) = (
        TestIdentity::from_seed(seed),
        TestIdentity::from_seed(seed + 1),
    );
    let (ca, rx_a, _ka) = fake_conn(&state, Some(&a));
    let (cb, rx_b, _kb) = fake_conn(&state, Some(&b));
    circuits::handle_circuit_ask(
        ca,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(1),
        None,
        &state,
    )
    .await;
    circuits::handle_circuit_ask(
        cb,
        a.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(2),
        None,
        &state,
    )
    .await;
    assert_eq!(state.identity_pair_circuits.len(), 1, "initial pair");

    let asks = Arc::new(AtomicUsize::new(0));
    let ta = tokio::spawn(sim_client(
        state.clone(),
        ca,
        b.bytes,
        rx_a,
        jitter_a,
        asks.clone(),
    ));
    let tb = tokio::spawn(sim_client(
        state.clone(),
        cb,
        a.bytes,
        rx_b,
        jitter_b,
        asks.clone(),
    ));
    let (ra, rb) = (ta.await.unwrap(), tb.await.unwrap());
    assert_eq!(state.identity_pair_circuits.len(), 1, "exactly one pair");
    assert_eq!(
        state.circuits.len(),
        2,
        "exactly one pair of routing entries"
    );
    // Both re-asks of the first round match (the earlier one waits as a
    // pending ask, the later one completes it), so a correct relay forms the
    // pair in round 1 with 2 asks. Allow one extra round each; a relay whose
    // re-asks tear each other down keeps asking (up to 2 x Q8_MAX_ROUNDS).
    assert!(ra <= 2 && rb <= 2, "pair formed in rounds {ra}/{rb}");
    let total = asks.load(Ordering::SeqCst);
    assert!(total <= 4, "ask count is bounded: {total} re-asks");
}

#[tokio::test(start_paused = true)]
async fn q8_concurrent_teardown_and_reask_forms_exactly_one_pair() {
    q8_scenario(0x6c, 0.10, -0.15).await;
}

#[tokio::test(start_paused = true)]
async fn q8_simultaneous_reasks_still_form_exactly_one_pair() {
    q8_scenario(0x8c, 0.0, 0.0).await;
}

// --------------------------------------------------------------- orphaning

#[tokio::test]
async fn pair_survives_one_member_leaving_and_queues_for_it() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x6e), TestIdentity::from_seed(0x6f));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    let st = state.clone();
    let bb = b.bytes;
    eventually("B gone", move || {
        !st.connections.iter().any(|c| c.proven_identity == Some(bb))
    })
    .await;
    assert_eq!(
        state.identity_pair_circuits.len(),
        1,
        "pair kept while A is here"
    );
    assert!(state
        .identity_pair_circuits
        .iter()
        .all(|p| p.orphaned_since.is_none()));
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("queued for B", move || {
        st.message_queues
            .get(&btag)
            .is_some_and(|q| q.pending.iter().any(|m| !m.is_knock))
    })
    .await;
}

#[tokio::test]
async fn pair_is_removed_540_s_after_both_members_left() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x70), TestIdentity::from_seed(0x71));
    let (wa, wb, _ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wa);
    drop(wb);
    let st = state.clone();
    eventually("both gone and orphaned", move || {
        st.connections.is_empty()
            && st
                .identity_pair_circuits
                .iter()
                .all(|p| p.orphaned_since.is_some())
    })
    .await;
    sweep_stale_state(Instant::now() + Duration::from_secs(539), &state);
    assert_eq!(state.identity_pair_circuits.len(), 1);
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert_eq!(state.identity_pair_circuits.len(), 0);
    assert_eq!(state.circuits.len(), 0);
}

#[tokio::test]
async fn sweep_clears_a_stale_orphan_stamp_on_a_pair_with_a_live_member() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x74), TestIdentity::from_seed(0x75));
    let (_wa, _wb, _ca, _cb) = pair_up(&state, addr, &a, &b).await;
    // A stale stamp, as if a member had left and the pair was then resumed.
    for mut p in state.identity_pair_circuits.iter_mut() {
        p.orphaned_since = Some(Instant::now());
    }
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert_eq!(state.identity_pair_circuits.len(), 1, "live pair kept");
    assert!(state
        .identity_pair_circuits
        .iter()
        .all(|p| p.orphaned_since.is_none()));
    // And its routing entries with it.
    assert_eq!(state.circuits.len(), 2);
}

// ------------------------------------------------------------- RF1 (resume)

#[tokio::test]
async fn rf1_old_socket_close_does_not_steal_resumed_slot() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x72), TestIdentity::from_seed(0x73));
    let (a1, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;

    let mut a2 = authed(addr, &a).await;
    a2.send(ask(&b, rand::random(), Some(ca.circuit_id)))
        .await
        .unwrap();
    assert!(until_control(&mut a2, |m| matches!(
        m,
        ControlMessage::CircuitExists { .. }
    ))
    .await
    .is_some());
    let a2_id = mapped(&state, &a).expect("A mapped to the new socket");

    drop(a1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(mapped(&state, &a), Some(a2_id), "old close must not unmap");
    assert_eq!(state.identity_pair_circuits.len(), 1);
    assert!(state
        .identity_pair_circuits
        .iter()
        .all(|p| p.orphaned_since.is_none()));
    assert_eq!(
        state.circuits.get(&ca.circuit_id).map(|r| r.client_a),
        Some(a2_id),
        "A's slot stays on the resumed socket"
    );
    wb.send(relay_on(cb.target_circuit_id, &cb.token, vec![0x02; 200]))
        .await
        .unwrap();
    assert!(until_relay(&mut a2, Duration::from_secs(3)).await.is_some());
}

// ------------------------------------------------- knock vs publish race

/// A publish that maps the target and drains its queue between
/// `deliver_knock`'s failed lookup and its queue push must not strand the
/// knock in the store until the next publish: it is delivered live, once.
#[tokio::test]
async fn knock_racing_a_publish_is_delivered_not_stranded() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (x, b) = (TestIdentity::from_seed(0x74), TestIdentity::from_seed(0x75));
    let (caller, _rx_x, _kx) = fake_conn(&state, Some(&x));
    let (target, mut rx_b, _kb) = fake_conn(&state, Some(&b));
    let btag = tags::id_tag(&b.bytes);
    // B is connected but has not published yet: not routable.
    state.identity_to_client.remove(&btag);

    // The publish lands exactly between the lookup and the push.
    let st = state.clone();
    circuits::tests_hook::set_before_knock_queued(move || {
        st.identity_to_client.insert(btag, target);
        st.message_queues.remove(&btag);
    });
    circuits::handle_circuit_ask(
        caller,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(7),
        None,
        &state,
    )
    .await;

    let mut delivered = 0;
    while let Ok((msg, _)) = rx_b.try_recv() {
        if let Ok(UnifiedFrame::Control(ControlMessage::QueuedMessage { payload })) =
            UnifiedFrame::decode(&msg)
        {
            assert_eq!(payload, knock(7));
            delivered += 1;
        }
    }
    assert_eq!(delivered, 1, "knock delivered live exactly once");
    assert!(
        state
            .message_queues
            .get(&btag)
            .map_or(true, |q| !q.pending.iter().any(|m| m.is_knock)),
        "no knock left stranded in the store"
    );
}

// ------------------------------------------------------- re-ask lifetime

/// A re-ask replaces the EK but does not extend the ask: it is gone
/// `ASK_TTL` after the *first* ask (spec §5.2, "held for at most 600 s"),
/// and a re-ask after that starts a new ask.
#[tokio::test]
async fn reask_does_not_keep_an_ask_alive_past_ask_ttl() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (a, offline) = (TestIdentity::from_seed(0x76), TestIdentity::from_seed(0x77));
    let (caller, _rx, _k) = fake_conn(&state, Some(&a));
    circuits::handle_circuit_ask(
        caller,
        offline.bytes,
        [1; 32],
        kem_for([1; 32]),
        knock(1),
        None,
        &state,
    )
    .await;
    let pair = tags::pair_tag(&a.bytes, &offline.bytes);
    let first_at = state.pending_asks.get(&pair).map(|p| p.at).unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    circuits::handle_circuit_ask(
        caller,
        offline.bytes,
        [2; 32],
        kem_for([2; 32]),
        knock(2),
        None,
        &state,
    )
    .await;
    {
        let p = state.pending_asks.get(&pair).unwrap();
        assert_eq!(p.ephemeral, [2; 32], "re-ask replaces the EK");
        assert_eq!(p.at, first_at, "re-ask does not refresh the ask's age");
    }
    sweep_stale_state(
        first_at + circuits::ASK_TTL + Duration::from_secs(1),
        &state,
    );
    assert_eq!(
        state.pending_asks.len(),
        0,
        "expired ASK_TTL after the first ask"
    );

    // An expired-but-unswept ask is not refreshed by a re-ask either.
    circuits::handle_circuit_ask(
        caller,
        offline.bytes,
        [3; 32],
        kem_for([3; 32]),
        knock(3),
        None,
        &state,
    )
    .await;
    let at3 = state.pending_asks.get(&pair).map(|p| p.at).unwrap();
    state.pending_asks.get_mut(&pair).unwrap().at =
        at3 - (circuits::ASK_TTL + Duration::from_secs(1));
    circuits::handle_circuit_ask(
        caller,
        offline.bytes,
        [4; 32],
        kem_for([4; 32]),
        knock(4),
        None,
        &state,
    )
    .await;
    let p = state.pending_asks.get(&pair).unwrap();
    assert!(p.at >= at3, "an expired ask is replaced by a new one");
    assert_eq!(
        p.knocks_delivered, 1,
        "the new ask has its own knock budget"
    );
}

// --------------------------------------------- close vs replaced pair

/// A CloseCircuit naming a circuit of a pair that was torn down is ignored
/// and leaves the new pair for the same identities alone.
#[tokio::test]
async fn close_of_an_old_circuit_leaves_the_new_pair_alone() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (a, b) = (TestIdentity::from_seed(0x78), TestIdentity::from_seed(0x79));
    let (ca, _rx_a, _ka) = fake_conn(&state, Some(&a));
    let (cb, _rx_b, _kb) = fake_conn(&state, Some(&b));
    circuits::handle_circuit_ask(
        ca,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(1),
        None,
        &state,
    )
    .await;
    circuits::handle_circuit_ask(
        cb,
        a.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(2),
        None,
        &state,
    )
    .await;
    let old: Vec<CircuitId> = state.circuits.iter().map(|e| *e.key()).collect();
    // A re-asks without resume: teardown, then B re-asks: a new pair.
    circuits::handle_circuit_ask(
        ca,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(3),
        None,
        &state,
    )
    .await;
    circuits::handle_circuit_ask(
        cb,
        a.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(4),
        None,
        &state,
    )
    .await;
    assert_eq!(state.identity_pair_circuits.len(), 1);
    for id in old {
        circuits::handle_close_circuit(ca, id, &state).await;
    }
    assert_eq!(state.identity_pair_circuits.len(), 1, "new pair untouched");
    assert_eq!(state.circuits.len(), 2);
}

// ------------------------------------------- M-1 (close after reconnect)

/// Wait until no connection is proven as `id` (its socket was dropped).
async fn gone(state: &RelayState, id: &TestIdentity) {
    let st = state.clone();
    let bytes = id.bytes;
    eventually("old connection gone", move || {
        !st.connections
            .iter()
            .any(|c| c.proven_identity == Some(bytes))
    })
    .await;
}

/// The member's packet on a torn-down circuit gets `CircuitNotFound`.
async fn assert_circuit_not_found(ws: &mut Ws, c: &Created) {
    ws.send(relay_on(c.target_circuit_id, &c.token, vec![0x02; 200]))
        .await
        .unwrap();
    match until_control(ws, |m| matches!(m, ControlMessage::Error { .. })).await {
        Some(ControlMessage::Error { code, message }) => {
            assert!(matches!(code, ControlErrorCode::CircuitNotFound));
            // Re-review R-1: the error names the circuit the packet used.
            assert_eq!(
                rchat_core::protocol::circuit_not_found_id(&message).map(|id| id.0.to_vec()),
                Some(c.target_circuit_id.as_ref().to_vec()),
                "{message}"
            );
        }
        other => panic!("expected CircuitNotFound, got {other:?}"),
    }
}

/// Security review M-1: B reconnects (its slot still names the dead
/// connection) and closes before resuming, as a block in that window does.
/// The close counts: membership is B's proven identity, not the connection
/// id in the routing entry. A is told, and A's packets are refused instead
/// of filling B's offline queue.
#[tokio::test]
async fn m1_close_after_reconnect_before_resume_tears_down_the_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x7a), TestIdentity::from_seed(0x7b));
    let (mut wa, wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    gone(&state, &b).await;

    let mut wb2 = authed(addr, &b).await;
    wb2.send(FrameBuilder::close_circuit(cb.circuit_id).encode())
        .await
        .unwrap();
    assert!(
        until_control(&mut wa, is_closed_normal).await.is_some(),
        "A gets CircuitClosed{{Normal}}"
    );
    assert_eq!(state.identity_pair_circuits.len(), 0);
    assert!(!state.circuits.contains_key(&ca.circuit_id));
    assert!(!state.circuits.contains_key(&cb.circuit_id));
    assert_circuit_not_found(&mut wa, &ca).await;
    assert!(state.message_queues.get(&tags::id_tag(&b.bytes)).is_none());
    // Nothing goes back to the closer.
    assert!(until_control(&mut wb2, |_| true).await.is_none());
}

/// M-1, the close-by-tag rule still needs membership: a proven third party
/// naming the pair's circuit changes nothing, and gets nothing back.
#[tokio::test]
async fn m1_close_by_a_proven_non_member_after_a_reconnect_is_ignored() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0x7c),
        TestIdentity::from_seed(0x7d),
        TestIdentity::from_seed(0x7e),
    );
    let (_wa, wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    gone(&state, &b).await;
    let mut wc = authed(addr, &c).await;
    for cid in [ca.circuit_id, cb.circuit_id] {
        wc.send(FrameBuilder::close_circuit(cid).encode())
            .await
            .unwrap();
    }
    assert!(until_control(&mut wc, |_| true).await.is_none());
    assert_eq!(state.identity_pair_circuits.len(), 1);
    assert_eq!(state.circuits.len(), 2);
}

/// M-1, the restart path: B comes back (an app restart has no session, so
/// it never resumes) while A stays connected. Once B has been online without
/// resuming for longer than `PAIR_RESUME_GRACE`, the sweep tears the pair
/// down: no structure links A and B any more, A is told, and A's packets
/// are refused instead of filling B's queue.
#[tokio::test]
async fn m1_member_online_without_resume_loses_the_pair_after_the_grace() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x80), TestIdentity::from_seed(0x81));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    gone(&state, &b).await;
    let _wb2 = authed(addr, &b).await;

    let t0 = Instant::now();
    sweep_stale_state(t0, &state);
    sweep_stale_state(t0 + circuits::PAIR_RESUME_GRACE, &state);
    assert_eq!(
        state.identity_pair_circuits.len(),
        1,
        "kept inside the grace"
    );
    sweep_stale_state(
        t0 + circuits::PAIR_RESUME_GRACE + Duration::from_secs(1),
        &state,
    );
    assert_eq!(state.identity_pair_circuits.len(), 0, "torn down");
    assert_eq!(state.circuits.len(), 0);
    assert!(until_control(&mut wa, is_closed_normal).await.is_some());
    assert_circuit_not_found(&mut wa, &ca).await;
    assert!(state.message_queues.get(&tags::id_tag(&b.bytes)).is_none());
}

/// M-1: a member that resumes after coming back keeps the pair, and so does
/// a pair whose other member is simply offline (not mapped).
#[tokio::test]
async fn m1_resumed_or_offline_members_keep_the_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x82), TestIdentity::from_seed(0x83));
    let (_wa, wb, _ca, cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    gone(&state, &b).await;
    let t0 = Instant::now();
    // Offline: not mapped, so not "online without resuming".
    sweep_stale_state(t0, &state);
    sweep_stale_state(t0 + Duration::from_secs(300), &state);
    assert_eq!(state.identity_pair_circuits.len(), 1, "offline: kept");

    let mut wb2 = authed(addr, &b).await;
    sweep_stale_state(t0 + Duration::from_secs(301), &state);
    wb2.send(ask(&a, rand::random(), Some(cb.circuit_id)))
        .await
        .unwrap();
    assert!(until_control(&mut wb2, |m| matches!(
        m,
        ControlMessage::CircuitExists { .. }
    ))
    .await
    .is_some());
    sweep_stale_state(t0 + Duration::from_secs(302), &state);
    sweep_stale_state(t0 + Duration::from_secs(1000), &state);
    assert_eq!(state.identity_pair_circuits.len(), 1, "resumed: kept");
    assert!(state
        .identity_pair_circuits
        .iter()
        .all(|p| p.unresumed_since.is_none()));
}

// ------------------------------------------- re-review R-1 (sweep vs resume)

/// Re-review R-1: the sweep never removes a pair whose lock is held (an
/// ask, resume or close in flight); it takes it on a later sweep.
#[tokio::test]
async fn r1_sweep_skips_a_pair_whose_lock_is_held() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x84), TestIdentity::from_seed(0x85));
    let (_wa, wb, _ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    gone(&state, &b).await;
    let _wb2 = authed(addr, &b).await;
    let pair = tags::pair_tag(&a.bytes, &b.bytes);

    let t0 = Instant::now();
    sweep_stale_state(t0, &state);
    let held = pair_lock::PAIR_LOCKS.lock(pair).await;
    let past = t0 + circuits::PAIR_RESUME_GRACE + Duration::from_secs(1);
    sweep_stale_state(past, &state);
    assert_eq!(state.identity_pair_circuits.len(), 1, "busy pair skipped");
    drop(held);
    sweep_stale_state(past + Duration::from_secs(1), &state);
    assert_eq!(state.identity_pair_circuits.len(), 0, "taken next sweep");
}

/// Re-review R-1: a pair that vanishes between the resume's slot check and
/// the end of its rebind is not reported as resumed. The caller gets no
/// `CircuitExists`, holds no circuit for it, and the ask goes on as a fresh
/// one.
#[tokio::test]
async fn r1_resume_of_a_pair_removed_during_the_rebind_is_not_reported() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let (a, b) = (TestIdentity::from_seed(0x86), TestIdentity::from_seed(0x87));
    let (ca, _rx_a, _ka) = fake_conn(&state, Some(&a));
    let (cb, _rx_b, _kb) = fake_conn(&state, Some(&b));
    circuits::handle_circuit_ask(
        ca,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(1),
        None,
        &state,
    )
    .await;
    circuits::handle_circuit_ask(
        cb,
        a.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(2),
        None,
        &state,
    )
    .await;
    let a_tag = tags::id_tag(&a.bytes);
    let own = state
        .circuits
        .iter()
        .find(|r| r.tag_a == a_tag)
        .map(|r| *r.key())
        .unwrap();
    let pair = tags::pair_tag(&a.bytes, &b.bytes);

    // A reconnects (new connection) and resumes; the pair goes mid-rebind.
    state.connections.remove(&ca);
    let (ca2, mut rx_a2, _ka2) = fake_conn(&state, Some(&a));
    let st = state.clone();
    circuits::tests_hook::set_after_rebind(move || {
        circuits::teardown_pair(pair, &st, None);
    });
    circuits::handle_circuit_ask(
        ca2,
        b.bytes,
        rand::random(),
        kem_for(rand::random()),
        knock(3),
        Some(own),
        &state,
    )
    .await;

    while let Ok((msg, _)) = rx_a2.try_recv() {
        assert!(
            !matches!(
                UnifiedFrame::decode(&msg),
                Ok(UnifiedFrame::Control(ControlMessage::CircuitExists { .. }))
            ),
            "a pair that is gone is never reported as resumed"
        );
    }
    assert!(!state
        .connections
        .get(&ca2)
        .unwrap()
        .circuits
        .contains_key(&own));
    assert_eq!(state.identity_pair_circuits.len(), 0);
    assert_eq!(state.pending_asks.len(), 1, "continues as a fresh ask");
}
