//! Bounds on relay state a client can create: pending asks are capped per
//! relay and per connection and expire, circuits are capped, CloseCircuit
//! needs membership, and identity mappings do not outlive their connection.

use super::test_support::{self, *};
use super::*;
use crate::protocol::relay::CircuitToken;
use crate::protocol::unified::PeerBundle;

const QUIET: Duration = Duration::from_millis(400);

/// Next control error, skipping everything else; None if none arrives.
async fn next_error(ws: &mut Ws, wait: Duration) -> Option<ControlErrorCode> {
    loop {
        match next_control(ws, wait).await {
            Some(ControlMessage::Error { code, .. }) => return Some(code),
            Some(_) => continue,
            None => return None,
        }
    }
}

/// `a` asks `b`, then `b` asks `a`: one pair.
async fn pair_up(state: &RelayState, wa: &mut Ws, a: &TestIdentity, wb: &mut Ws, b: &TestIdentity) {
    ask_each_other(state, wa, a, wb, b).await;
    let _ = frames_until_quiet(wa, QUIET).await;
    let _ = frames_until_quiet(wb, QUIET).await;
}

#[tokio::test]
async fn pending_ask_targets_are_capped() {
    let (addr, state) = start(ServerConfig {
        max_pending_circuit_targets: 2,
        max_pending_per_connection: 2,
        ..test_config()
    })
    .await;
    let mut ws = authed(addr, &TestIdentity::random()).await;
    for i in 0..2 {
        ws.send(ask(&TestIdentity::random(), [1; 32], None))
            .await
            .unwrap();
        let s = state.clone();
        eventually("ask stored", move || s.pending_asks.len() == i + 1).await;
    }
    // A third distinct target is refused, not stored.
    ws.send(ask(&TestIdentity::random(), [1; 32], None))
        .await
        .unwrap();
    assert!(matches!(
        next_error(&mut ws, Duration::from_secs(5)).await,
        Some(ControlErrorCode::RateLimited)
    ));
    assert_eq!(state.pending_asks.len(), 2);
}

#[tokio::test]
async fn one_connection_cannot_exhaust_the_pending_target_cap() {
    let (addr, state) = start(ServerConfig {
        max_pending_per_connection: 2,
        ..test_config()
    })
    .await;
    let mut greedy = authed(addr, &TestIdentity::random()).await;
    let targets: Vec<TestIdentity> = (0..3).map(|_| TestIdentity::random()).collect();
    greedy.send(ask(&targets[0], [1; 32], None)).await.unwrap();
    greedy.send(ask(&targets[1], [1; 32], None)).await.unwrap();
    let s = state.clone();
    eventually("two pending asks", move || s.pending_asks.len() == 2).await;
    // A re-ask to a pending target is not charged again.
    greedy.send(ask(&targets[0], [2; 32], None)).await.unwrap();
    assert!(next_error(&mut greedy, Duration::from_millis(500))
        .await
        .is_none());
    // A third distinct target is refused for this connection...
    greedy.send(ask(&targets[2], [1; 32], None)).await.unwrap();
    assert!(matches!(
        next_error(&mut greedy, Duration::from_secs(5)).await,
        Some(ControlErrorCode::RateLimited)
    ));
    assert_eq!(state.pending_asks.len(), 2);
    // ...but another connection can still ask.
    let mut other = authed(addr, &TestIdentity::random()).await;
    other.send(ask(&targets[2], [1; 32], None)).await.unwrap();
    let s = state.clone();
    eventually("other connection asks", move || s.pending_asks.len() == 3).await;
}

#[tokio::test]
async fn circuits_per_connection_are_capped() {
    let (addr, state) = start(ServerConfig {
        max_circuits_per_connection: 2,
        ..test_config()
    })
    .await;
    let caller = TestIdentity::random();
    let mut wc = authed(addr, &caller).await;
    let targets: Vec<TestIdentity> = (0..3).map(|_| TestIdentity::random()).collect();
    let mut sockets = Vec::new();
    for t in &targets {
        let mut ws = authed(addr, t).await;
        ws.send(ask(&caller, [3; 32], None)).await.unwrap();
        sockets.push(ws);
    }
    let s = state.clone();
    eventually("three pending asks", move || s.pending_asks.len() == 3).await;
    // The caller completes two pairs (it is the later asker each time)...
    wc.send(ask(&targets[0], [4; 32], None)).await.unwrap();
    wc.send(ask(&targets[1], [4; 32], None)).await.unwrap();
    let s = state.clone();
    eventually("two circuit pairs", move || s.circuits.len() == 4).await;
    // ...and the third is refused.
    wc.send(ask(&targets[2], [4; 32], None)).await.unwrap();
    assert!(matches!(
        next_error(&mut wc, Duration::from_secs(5)).await,
        Some(ControlErrorCode::RateLimited)
    ));
    assert_eq!(state.circuits.len(), 4, "refused match created circuits");

    // Other connections are unaffected by this connection's cap.
    let other = TestIdentity::random();
    let mut wo = authed(addr, &other).await;
    let t2 = &targets[2];
    pair_up(&state, &mut sockets[2], t2, &mut wo, &other).await;
    assert_eq!(state.circuits.len(), 6);
}

#[tokio::test]
async fn global_circuit_cap_refuses_new_circuits() {
    let (addr, state) = start(ServerConfig {
        max_circuits: 4,
        ..test_config()
    })
    .await;
    let ids: Vec<TestIdentity> = (0..6).map(|_| TestIdentity::random()).collect();
    let mut ws = Vec::new();
    for id in &ids {
        ws.push(authed(addr, id).await);
    }
    let (left, right) = ws.split_at_mut(1);
    pair_up(&state, &mut left[0], &ids[0], &mut right[0], &ids[1]).await;
    let (left, right) = ws.split_at_mut(3);
    pair_up(&state, &mut left[2], &ids[2], &mut right[0], &ids[3]).await;
    assert_eq!(state.circuits.len(), 4);

    let (left, right) = ws.split_at_mut(5);
    ask_each_other(&state, &mut left[4], &ids[4], &mut right[0], &ids[5]).await;
    assert!(matches!(
        next_error(&mut right[0], Duration::from_secs(5)).await,
        Some(ControlErrorCode::RateLimited)
    ));
    assert_eq!(state.circuits.len(), 4);
}

#[tokio::test]
async fn close_circuit_requires_membership() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    pair_up(&state, &mut wa, &a, &mut wb, &b).await;
    let a_client = mapped_client(&state, &a).unwrap();
    let a_circuit = state
        .circuits
        .iter()
        .find(|e| e.value().client_a == a_client)
        .map(|e| *e.key())
        .unwrap();

    let mut outsider = authed(addr, &TestIdentity::random()).await;
    let ids: Vec<CircuitId> = state.circuits.iter().map(|e| *e.key()).collect();
    for id in ids {
        outsider
            .send(FrameBuilder::close_circuit(id).encode())
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        state.circuits.len(),
        2,
        "outsider closed someone else's circuit"
    );
    // A member can close it.
    wa.send(FrameBuilder::close_circuit(a_circuit).encode())
        .await
        .unwrap();
    let s = state.clone();
    eventually("member closes", move || s.circuits.is_empty()).await;
}

#[tokio::test]
async fn republishing_the_same_identity_keeps_one_mapping_and_disconnect_drops_it() {
    let (addr, state) = start(test_config()).await;
    let mut ws = connect(addr).await;
    let id = TestIdentity::random();
    let next = test_support::publish(&mut ws, &id).await;
    assert!(mapped_client(&state, &id).is_some());
    let again = send_publish(&mut ws, &id, &next, &dev_binding()).await;
    assert!(matches!(again, PublishReply::Ok(_)));
    assert_eq!(
        state.identity_to_client.len(),
        1,
        "one connection owns one mapping"
    );

    drop(ws);
    let s = state.clone();
    let tag = tags::id_tag(&id.bytes);
    eventually("mapping removed on disconnect", move || {
        !s.identity_to_client.contains_key(&tag)
    })
    .await;
}

#[test]
fn sweep_removes_expired_and_orphaned_asks_and_pairs_without_circuits() {
    let state = RelayState::new(Arc::new(ServerConfig::default()));
    let (conn, _rx) = bare_connection([0u8; 32]);
    let live = conn.client_id;
    state.connections.insert(live, conn);
    let gone = ClientId::generate();
    let now = Instant::now() + Duration::from_secs(1000);
    let peer = PeerBundle {
        identity_key: vec![0; 32],
        identity_agreement_key: vec![0; 32],
        kem_pk: vec![0; 1184],
        bundle_signature: vec![0; 64],
    };
    let pending = |asker, at, n: u8| PendingAsk {
        asker,
        asker_tag: IdTag([n; 32]),
        target_tag: Some(IdTag([n.wrapping_add(1); 32])),
        asker_bundle: std::sync::Arc::new(peer.clone()),
        ephemeral: [0; 32],
        kem_ephemeral: Box::new(crate::signaling::circuits::AskEphemerals {
            kem: [0; crate::validate::KEM_PK_BYTES],
            sig: [0; crate::validate::ASK_EPH_SIG_BYTES],
        }),
        knocks_delivered: 1,
        at,
        source: None,
    };
    state.pending_asks.insert(
        PairTag([1; 32]),
        pending(live, now - Duration::from_secs(10), 1),
    );
    state.pending_asks.insert(
        PairTag([2; 32]),
        pending(live, now - Duration::from_secs(541), 2),
    );
    state.pending_asks.insert(
        PairTag([3; 32]),
        pending(gone, now - Duration::from_secs(10), 3),
    );

    let (ca, cb) = (CircuitId::generate(), CircuitId::generate());
    let token = |id| CircuitToken::generate(id, Duration::from_secs(60));
    state.circuits.insert(
        ca,
        CircuitRoutingInfo {
            client_a: live,
            client_b: gone,
            tag_a: IdTag([7; 32]),
            tag_b: IdTag([8; 32]),
            token_a: token(ca),
            token_b: token(cb),
            pair: PairKey::Identity(PairTag([4; 32])),
            peer_circuit: cb,
        },
    );
    let pair_info = |a, b| CircuitPairInfo {
        circuit_id_a: a,
        circuit_id_b: b,
        token_a: token(a),
        token_b: token(b),
        slot_a: IdTag([7; 32]),
        slot_b: IdTag([8; 32]),
        source_a: None,
        source_b: None,
        orphaned_since: None,
        unresumed_since: None,
        created_at: Instant::now(),
    };
    state
        .identity_pair_circuits
        .insert(PairTag([4; 32]), pair_info(ca, cb));
    state.identity_pair_circuits.insert(
        PairTag([5; 32]),
        pair_info(CircuitId::generate(), CircuitId::generate()),
    );

    sweep_stale_state(now, &state);

    assert_eq!(state.pending_asks.len(), 1);
    assert!(state.pending_asks.contains_key(&PairTag([1; 32])));
    assert_eq!(state.identity_pair_circuits.len(), 1);
    assert!(state.identity_pair_circuits.contains_key(&PairTag([4; 32])));
}

/// R-8: asks inserted while `sweep_asks` retains shard by shard can make the
/// map larger than it was; the removed count must not underflow (a panic
/// in debug builds and with overflow checks on).
#[test]
fn sweep_asks_count_survives_concurrent_inserts() {
    let state = RelayState::new(Arc::new(ServerConfig::default()));
    let peer = PeerBundle {
        identity_key: vec![0; 32],
        identity_agreement_key: vec![0; 32],
        kem_pk: vec![0; 1184],
        bundle_signature: vec![0; 64],
    };
    let live: std::collections::HashSet<ClientId> = [ClientId::generate()].into();
    let asker = *live.iter().next().unwrap();
    let writer_state = state.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..200_000u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            writer_state.pending_asks.insert(
                PairTag(k),
                PendingAsk {
                    asker,
                    asker_tag: IdTag(k),
                    target_tag: Some(IdTag(k)),
                    asker_bundle: std::sync::Arc::new(peer.clone()),
                    ephemeral: [0; 32],
                    kem_ephemeral: Box::new(crate::signaling::circuits::AskEphemerals {
                        kem: [0; crate::validate::KEM_PK_BYTES],
                        sig: [0; crate::validate::ASK_EPH_SIG_BYTES],
                    }),
                    knocks_delivered: 1,
                    at: Instant::now(),
                    source: None,
                },
            );
        }
    });
    while !writer.is_finished() {
        let _ = circuits::sweep_asks(Instant::now(), &live, &state);
    }
    writer.join().unwrap();
}

/// S-5: a panic inside one connection's task closes that connection only;
/// its relay state is removed while unwinding and the relay keeps serving.
#[tokio::test]
async fn a_panicking_connection_task_is_cleaned_up_and_the_relay_survives() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    // A pending ask, so there is per-connection state beyond the slot.
    wa.send(ask(&b, [1; 32], None)).await.unwrap();
    let s = state.clone();
    eventually("ask stored", move || s.pending_asks.len() == 1).await;
    let before = metrics::rejections(metrics::REJECT_TASK_PANIC);

    let boom = SignalingMessage::new("test_panic", SignalingPayload::simple("test_panic"));
    wa.send(UnifiedFrame::signaling(boom).encode())
        .await
        .unwrap();
    assert!(closed_within(&mut wa, Duration::from_secs(5)).await);
    let s = state.clone();
    eventually("state removed", move || {
        s.connections.is_empty() && s.identity_to_client.is_empty() && s.pending_asks.is_empty()
    })
    .await;
    assert!(metrics::rejections(metrics::REJECT_TASK_PANIC) > before);

    // The relay still accepts and serves new connections.
    let _wb = authed(addr, &b).await;
    assert!(mapped_client(&state, &b).is_some());
}

/// R-1: a connection that proves X and then stops reading while its backlog
/// is handed over must not hold X's identity lock: another connection
/// proving X is answered at once, not after the drain's send timeout.
#[tokio::test]
async fn a_stalled_backlog_drain_does_not_hold_the_identity_lock() {
    let (addr, state) = start(test_config()).await;
    let x = TestIdentity::random();
    // ~25 MiB: more than the outbound queue (16 MiB) plus socket buffers.
    for _ in 0..400 {
        queue_test_message(&state, &x, vec![0x02; 64 << 10]);
    }
    // H1 proves X and then never reads again.
    let _h1 = authed(addr, &x).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut h2 = connect(addr).await;
    let nonce = hello(&mut h2).await;
    let started = Instant::now();
    let reply = send_publish(&mut h2, &x, &nonce, &dev_binding()).await;
    assert!(matches!(reply, PublishReply::Ok(_)), "{reply:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "second publish waited {:?} on the identity lock",
        started.elapsed()
    );
}

fn fairness_config() -> ServerConfig {
    ServerConfig {
        max_pending_circuit_targets: 200,
        max_pending_per_source: 50,
        max_pending_per_connection: 8,
        ..test_config()
    }
}

/// R-3: many connections from one source cannot take more than the
/// source's share of pending asks, and once the relay-wide table is full a
/// request from a source with fewer asks evicts from the heaviest source
/// instead of being refused.
#[tokio::test]
async fn pending_asks_are_shared_fairly_between_sources() {
    let state = RelayState::new(Arc::new(fairness_config()));
    let mut keep = Vec::new();
    // Source 1: 32 connections x 8 asks = 256 attempts.
    for _ in 0..32 {
        let (c, rx) = proven_bare(&state, &TestIdentity::random(), Some(source_key(1)));
        keep.push(rx);
        for _ in 0..8 {
            ask_direct(&state, c, &TestIdentity::random()).await;
        }
    }
    assert_eq!(
        state.pending_asks.len(),
        50,
        "source 1 holds only its share"
    );
    assert_eq!(state.pending_asks.source_count(&source_key(1)), 50);

    // Three more sources fill the relay-wide table (200).
    for s in 2..=4u8 {
        for _ in 0..7 {
            let (c, rx) = proven_bare(&state, &TestIdentity::random(), Some(source_key(s)));
            keep.push(rx);
            for _ in 0..8 {
                ask_direct(&state, c, &TestIdentity::random()).await;
            }
        }
    }
    assert_eq!(state.pending_asks.len(), 200, "table full");

    // A fresh source can still park an ask: a heavier source's oldest goes.
    let victim_target = TestIdentity::random();
    let (fresh, rx) = proven_bare(&state, &TestIdentity::random(), Some(source_key(9)));
    keep.push(rx);
    ask_direct(&state, fresh, &victim_target).await;
    assert_eq!(state.pending_asks.source_count(&source_key(9)), 1);
    assert_eq!(state.pending_asks.len(), 200);
    assert!(state.pending_asks.iter().any(|a| a.asker == fresh));
}

/// R-3: circuits count against both identities - the earlier asker too -
/// and the count lives with the pairs, so reconnecting does not reset it.
#[tokio::test]
async fn circuits_count_both_sides_and_survive_reconnect() {
    let state = RelayState::new(Arc::new(ServerConfig {
        max_circuits_per_connection: 2,
        ..test_config()
    }));
    let hub = TestIdentity::random();
    let (h, _hrx) = proven_bare(&state, &hub, None);
    let targets: Vec<TestIdentity> = (0..3).map(|_| TestIdentity::random()).collect();
    let mut keep = Vec::new();
    let mut clients = Vec::new();
    // The hub is the earlier asker every time.
    for t in &targets {
        ask_direct(&state, h, t).await;
    }
    for t in &targets {
        let (c, rx) = proven_bare(&state, t, None);
        keep.push(rx);
        clients.push(c);
        ask_direct(&state, c, &hub).await;
    }
    assert_eq!(
        state.identity_pair_circuits.len(),
        2,
        "the hub's identity is capped even as the earlier asker"
    );
    assert_eq!(state.circuit_counts.identity(&tags::id_tag(&hub.bytes)), 2);

    // The hub reconnects: its pairs (and their count) persist.
    let conn = state.connections.remove(&h).unwrap().1;
    circuits::on_disconnect(h, &conn, &state, Instant::now());
    let (h2, _h2rx) = proven_bare(&state, &hub, None);
    let fresh = TestIdentity::random();
    let (f, _frx) = proven_bare(&state, &fresh, None);
    ask_direct(&state, h2, &fresh).await;
    ask_direct(&state, f, &hub).await;
    assert_eq!(
        state.identity_pair_circuits.len(),
        2,
        "count kept across reconnect"
    );

    // Tearing pairs down releases the counts.
    let pairs: Vec<PairTag> = state
        .identity_pair_circuits
        .iter()
        .map(|e| *e.key())
        .collect();
    for p in pairs {
        circuits::teardown_pair(p, &state, None);
    }
    assert!(state.circuit_counts.is_empty());
}

/// R-3: identities asking from one source share `max_circuits_per_source`;
/// other sources are unaffected.
#[tokio::test]
async fn circuits_per_source_are_capped() {
    let state = RelayState::new(Arc::new(ServerConfig {
        max_circuits_per_source: Some(4),
        ..test_config()
    }));
    let mut keep = Vec::new();
    let pair_from = |s1: u8, s2: u8, keep: &mut Vec<_>| {
        let (a, b) = (TestIdentity::random(), TestIdentity::random());
        let (ca, ra) = proven_bare(&state, &a, Some(source_key(s1)));
        let (cb, rb) = proven_bare(&state, &b, Some(source_key(s2)));
        keep.push(ra);
        keep.push(rb);
        (ca, a, cb, b)
    };
    for _ in 0..5 {
        let (ca, a, cb, b) = pair_from(1, 2, &mut keep);
        ask_direct(&state, ca, &b).await;
        ask_direct(&state, cb, &a).await;
    }
    assert_eq!(
        state.identity_pair_circuits.len(),
        4,
        "source 1 (and 2) hold four circuits each"
    );
    assert_eq!(state.circuit_counts.source(&source_key(1)), 4);
    let (ca, a, cb, b) = pair_from(3, 4, &mut keep);
    ask_direct(&state, ca, &b).await;
    ask_direct(&state, cb, &a).await;
    assert_eq!(state.identity_pair_circuits.len(), 5, "other sources pair");
}

/// R-3 plumbing: with per-address limits on, every socket gets its source
/// bucket, so connections from one address share `max_pending_per_source`
/// (all test sockets come from 127.0.0.1).
#[tokio::test]
async fn sockets_from_one_address_share_the_per_source_pending_cap() {
    let (addr, state) = start(ServerConfig {
        max_connections_per_ip: 64,
        max_pending_per_source: 2,
        ..test_config()
    })
    .await;
    let mut first = authed(addr, &TestIdentity::random()).await;
    let mut second = authed(addr, &TestIdentity::random()).await;
    first
        .send(ask(&TestIdentity::random(), [1; 32], None))
        .await
        .unwrap();
    second
        .send(ask(&TestIdentity::random(), [1; 32], None))
        .await
        .unwrap();
    let s = state.clone();
    eventually("two asks", move || s.pending_asks.len() == 2).await;
    second
        .send(ask(&TestIdentity::random(), [1; 32], None))
        .await
        .unwrap();
    assert!(matches!(
        next_error(&mut second, Duration::from_secs(5)).await,
        Some(ControlErrorCode::RateLimited)
    ));
    assert_eq!(state.pending_asks.len(), 2);
}

/// M-3: unset, the per-source circuit cap is `max_circuits / 64`, so a
/// few sources cannot fill the table (it was a fixed 8192 sides against
/// 200,000 entries: about 25 sources).
#[tokio::test]
async fn the_per_source_circuit_cap_follows_max_circuits() {
    assert_eq!(ServerConfig::default().circuits_per_source(), 3_125);
    let state = RelayState::new(Arc::new(ServerConfig {
        max_circuits: 256, // 4 sides per source
        ..test_config()
    }));
    assert_eq!(state.config.circuits_per_source(), 4);
    let mut keep = Vec::new();
    for _ in 0..3 {
        let (a, b) = (TestIdentity::random(), TestIdentity::random());
        let (ca, ra) = proven_bare(&state, &a, Some(source_key(1)));
        let (cb, rb) = proven_bare(&state, &b, Some(source_key(1)));
        keep.extend([ra, rb]);
        ask_direct(&state, ca, &b).await;
        ask_direct(&state, cb, &a).await;
    }
    assert_eq!(state.identity_pair_circuits.len(), 2, "4 sides = 2 pairs");
    assert_eq!(state.circuit_counts.source(&source_key(1)), 4);
}

/// M-3: with the circuit table full, a pair from a lighter source evicts
/// the heaviest source's newest pair instead of being refused; the heavy
/// source itself still cannot grow.
#[tokio::test]
async fn a_full_circuit_table_evicts_the_heaviest_sources_newest_pair() {
    let state = RelayState::new(Arc::new(ServerConfig {
        max_circuits: 8, // four pairs
        max_circuits_per_source: Some(8),
        ..test_config()
    }));
    let mut keep = Vec::new();
    let mut pair_from = |s1: u8, s2: u8| {
        let (a, b) = (TestIdentity::random(), TestIdentity::random());
        let (ca, ra) = proven_bare(&state, &a, Some(source_key(s1)));
        let (cb, rb) = proven_bare(&state, &b, Some(source_key(s2)));
        keep.extend([ra, rb]);
        (ca, a, cb, b)
    };
    let mut heavy = Vec::new();
    for _ in 0..4 {
        let (ca, a, cb, b) = pair_from(1, 1);
        ask_direct(&state, ca, &b).await;
        ask_direct(&state, cb, &a).await;
        heavy.push(tags::pair_tag(&a.bytes, &b.bytes));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(state.circuits.len(), 8, "the table is full");

    // The heavy source cannot make room for itself.
    let (ca, a, cb, b) = pair_from(1, 1);
    ask_direct(&state, ca, &b).await;
    ask_direct(&state, cb, &a).await;
    assert_eq!(state.circuit_counts.source(&source_key(1)), 8);
    assert!(!state
        .identity_pair_circuits
        .contains_key(&tags::pair_tag(&a.bytes, &b.bytes)));

    // A lighter source's pair goes in; the heavy source's newest goes.
    let (ca, a, cb, b) = pair_from(2, 3);
    ask_direct(&state, ca, &b).await;
    ask_direct(&state, cb, &a).await;
    assert!(state
        .identity_pair_circuits
        .contains_key(&tags::pair_tag(&a.bytes, &b.bytes)));
    assert!(state.circuits.len() <= 8);
    assert_eq!(state.circuit_counts.source(&source_key(1)), 6);
    assert!(!state.identity_pair_circuits.contains_key(&heavy[3]));
    for older in &heavy[..3] {
        assert!(state.identity_pair_circuits.contains_key(older));
    }
}

/// L-3: a panicking round of a background task is contained and logged;
/// the next round runs.
#[test]
fn a_panicking_background_round_does_not_end_the_task() {
    let before = metrics::rejections(metrics::REJECT_TASK_PANIC);
    assert!(!supervised_round("test", || panic!("boom")));
    assert!(metrics::rejections(metrics::REJECT_TASK_PANIC) > before);
    let mut ran = false;
    assert!(supervised_round("test", || ran = true));
    assert!(ran);
}
