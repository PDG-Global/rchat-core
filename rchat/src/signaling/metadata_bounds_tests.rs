//! Metadata bounds (spec §5.2, M8): identity material lives only in the
//! connection's own bundle and in pending asks, and nothing links two
//! identities ten minutes after the conversation ended.

use super::test_support::{
    ask, ask_each_other, authed, eventually, start, test_config, TestIdentity, Ws,
};
use super::*;
use crate::protocol::relay::CircuitToken;

async fn created(ws: &mut Ws) -> (CircuitId, Vec<u8>, CircuitId) {
    loop {
        match super::test_support::next_control(ws, Duration::from_secs(3)).await {
            Some(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                token,
                target_circuit_id,
                ..
            }) => return (circuit_id, token, target_circuit_id),
            Some(_) => continue,
            None => panic!("no CircuitCreatedV3"),
        }
    }
}

fn relay_on(target_circuit: CircuitId, my_token: &[u8], payload: Vec<u8>) -> Message {
    let mut key = [0u8; 32];
    key.copy_from_slice(my_token);
    let token = CircuitToken {
        circuit_id: target_circuit,
        key,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    let mut p = RelayPacket::new(target_circuit, payload.clone());
    p.auth_tag = token.authenticate(&target_circuit, &payload);
    UnifiedFrame::relay(p).encode()
}

/// A <-> B paired, A has relayed once, A has a pending ask (and charge) for
/// offline C. Returns sockets and A's (own, token, target) circuit triple.
async fn full_session(
    state: &RelayState,
    addr: SocketAddr,
    a: &TestIdentity,
    b: &TestIdentity,
    c: &TestIdentity,
) -> (Ws, Ws, (CircuitId, Vec<u8>, CircuitId)) {
    let mut wa = authed(addr, a).await;
    let mut wb = authed(addr, b).await;
    ask_each_other(state, &mut wa, a, &mut wb, b).await;
    let ca = created(&mut wa).await;
    let _cb = created(&mut wb).await;
    wa.send(relay_on(ca.2, &ca.1, vec![0x02; 200]))
        .await
        .unwrap();
    wa.send(ask(c, rand::random(), None)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    (wa, wb, ca)
}

#[tokio::test]
async fn m1_message_ack_carries_no_identities() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x81), TestIdentity::from_seed(0x82));
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    ask_each_other(&state, &mut wa, &a, &mut wb, &b).await;
    let ca = created(&mut wa).await;
    wa.send(relay_on(ca.2, &ca.1, vec![0x02; 200]))
        .await
        .unwrap();
    loop {
        match super::test_support::next_control(&mut wa, Duration::from_secs(3)).await {
            Some(ControlMessage::MessageAck {
                sender_identity,
                recipient_identity,
                ..
            }) => {
                assert_eq!(sender_identity, "");
                assert_eq!(recipient_identity, "");
                return;
            }
            Some(_) => continue,
            None => panic!("no MessageAck"),
        }
    }
}

#[tokio::test]
async fn m2_raw_identities_only_in_connection_bundles_and_pending_asks() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0x83),
        TestIdentity::from_seed(0x84),
        TestIdentity::from_seed(0x85),
    );
    let (mut wa, wb, ca) = full_session(&state, addr, &a, &b, &c).await;
    // B leaves; A's next packet is queued under B's tag.
    drop(wb);
    tokio::time::sleep(Duration::from_millis(300)).await;
    wa.send(relay_on(ca.2, &ca.1, vec![0x02; 200]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let raw = [a.bytes, b.bytes, c.bytes];
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for e in state.identity_to_client.iter() {
        seen.push(e.key().0);
    }
    for e in state.identity_pair_circuits.iter() {
        seen.extend([e.key().0, e.slot_a.0, e.token_a.key, e.token_b.key]);
    }
    for e in state.circuits.iter() {
        seen.extend([
            e.tag_a.0,
            e.tag_b.0,
            e.pair.raw(),
            e.token_a.key,
            e.token_b.key,
        ]);
    }
    for e in state.message_queues.iter() {
        seen.push(e.key().0);
        for m in &e.pending {
            assert!(
                !m.payload.windows(32).any(|w| raw.iter().any(|r| r == w)),
                "a queued record contains a raw identity"
            );
        }
    }
    for e in state.pending_asks.iter() {
        seen.push(e.key().raw());
    }
    for conn in state.connections.iter() {
        for (t, _) in &conn.pending_charges {
            seen.push(t.raw());
        }
    }
    for r in raw {
        assert!(
            !seen.contains(&r),
            "raw identity outside the allowed places"
        );
    }
    // The allowed places do hold them (so the scan above is not vacuous).
    assert!(state
        .connections
        .iter()
        .any(|c| c.proven_identity == Some(a.bytes)));
}

fn links_either(state: &RelayState, ids: &[&TestIdentity]) -> Vec<&'static str> {
    let tags: Vec<IdTag> = ids.iter().map(|i| tags::id_tag(&i.bytes)).collect();
    let mut found = Vec::new();
    if !state.circuits.is_empty() {
        found.push("circuits");
    }
    if !state.identity_pair_circuits.is_empty() {
        found.push("pairs");
    }
    if !state.pending_asks.is_empty() {
        found.push("pending asks");
    }
    if state.connections.iter().any(|c| {
        c.pending_charges
            .iter()
            .any(|(t, _)| matches!(t, ChargeKey::Target(t) if tags.contains(t)))
    }) {
        found.push("pending charges");
    }
    if state
        .identity_to_client
        .iter()
        .any(|e| tags.contains(e.key()) && !state.connections.contains_key(e.value()))
    {
        found.push("stale identity mapping");
    }
    found
}

#[tokio::test]
async fn m3_ten_minute_bound_with_the_asker_disconnected() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0x86),
        TestIdentity::from_seed(0x87),
        TestIdentity::from_seed(0x88),
    );
    let (wa, wb, _) = full_session(&state, addr, &a, &b, &c).await;
    drop(wa);
    drop(wb);
    let st = state.clone();
    eventually("everyone gone", move || st.connections.is_empty()).await;
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert_eq!(links_either(&state, &[&a, &b, &c]), Vec::<&str>::new());
}

#[tokio::test]
async fn m3_ten_minute_bound_with_the_asker_still_connected() {
    let (addr, state) = start(test_config()).await;
    let (a, c) = (TestIdentity::from_seed(0x89), TestIdentity::from_seed(0x8b));
    let mut wa = authed(addr, &a).await;
    // A asks offline C and stays connected (M8).
    wa.send(ask(&c, rand::random(), None)).await.unwrap();
    let st = state.clone();
    eventually("ask + charge recorded", move || {
        st.pending_asks.len() == 1
            && st
                .connections
                .iter()
                .any(|conn| !conn.pending_charges.is_empty())
    })
    .await;
    // Both windows are 540 s, so one sweep at 541 s clears them: with the
    // 60 s sweep interval nothing outlives 600 s (M3/M8).
    sweep_stale_state(Instant::now() + Duration::from_secs(539), &state);
    assert_eq!(state.pending_asks.len(), 1, "ask still inside ASK_TTL");
    assert!(
        state
            .connections
            .iter()
            .any(|conn| !conn.pending_charges.is_empty()),
        "charge still inside PENDING_CHARGE_WINDOW"
    );
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert!(state.pending_asks.is_empty(), "ask expired");
    assert!(
        state
            .connections
            .iter()
            .all(|conn| conn.pending_charges.is_empty()),
        "pending_charges pruned eagerly by the sweep"
    );
    assert_eq!(links_either(&state, &[&a, &c]), Vec::<&str>::new());
}

/// R-11: the forwarding circuit id comes from the routing entry itself, not
/// from a scan of the target connection's circuits: with B's per-connection
/// circuit map emptied, a packet A sends on its own circuit still reaches B
/// on the circuit id B owns.
#[tokio::test]
async fn relay_forwarding_uses_the_routing_entry_not_a_circuit_scan() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    ask_each_other(&state, &mut wa, &a, &mut wb, &b).await;
    let (a_own, a_token, a_target) = created(&mut wa).await;
    let (b_own, _, _) = created(&mut wb).await;
    assert_eq!(a_target, b_own);
    let b_client = super::test_support::mapped_client(&state, &b).unwrap();
    state.connections.get(&b_client).unwrap().circuits.clear();

    wa.send(relay_on(a_own, &a_token, vec![0x02; 200]))
        .await
        .unwrap();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(3), wb.next())
            .await
            .expect("B got the packet")
            .unwrap()
            .unwrap();
        if let Ok(UnifiedFrame::Relay(p)) = UnifiedFrame::decode(&m) {
            assert_eq!(p.circuit_id, b_own, "delivered on B's own circuit id");
            return;
        }
    }
}

/// R-2: a message request to an offline user survives a relay-wide knock
/// flood from one source - 300 throwaway identities on connections sharing
/// one source address, 9000 asks to random targets (18 MiB of knocks
/// against a 16 MiB store). The pending-ask share is lifted so only the
/// knock store's fairness is under test.
#[tokio::test]
async fn a_one_source_knock_flood_does_not_evict_other_sources_knocks() {
    use super::test_support::{ask_direct, proven_bare, queued_knocks, source_key};
    let state = RelayState::new(Arc::new(ServerConfig {
        max_pending_per_source: 10_000,
        ..test_config()
    }));
    let (alice, victim) = (TestIdentity::random(), TestIdentity::random());
    let (a, _arx) = proven_bare(&state, &alice, Some(source_key(1)));
    ask_direct(&state, a, &victim).await;
    assert_eq!(queued_knocks(&state, &victim), 1);

    let mut keep = Vec::new();
    for _ in 0..300 {
        let (c, rx) = proven_bare(&state, &TestIdentity::random(), Some(source_key(2)));
        keep.push(rx);
        for _ in 0..30 {
            ask_direct(&state, c, &TestIdentity::random()).await;
        }
    }
    assert_eq!(
        queued_knocks(&state, &victim),
        1,
        "the victim's knock survived the flood"
    );
}
