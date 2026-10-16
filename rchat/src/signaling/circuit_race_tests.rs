//! Mutual-intent circuits against a real relay (spec §6.2): a circuit exists
//! only when both identities asked; a one-sided ask leaves a knock for the
//! target and sends the asker nothing. Tests A3 (CreateCircuit refused), A5,
//! A6, Q1 (presence), Q2, Q3 (asks expire / leave with the asker, two knocks
//! per ask), Q4, R1, R3, R5.

use super::circuits::{assert_r1, assert_r2_slot, assert_r3, assert_r5};
use super::tags::{id_tag, pair_tag};
use super::test_support::*;
use super::*;
use crate::protocol::unified::PeerBundle;

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(400);

#[derive(Debug, Clone)]
struct Created {
    circuit_id: CircuitId,
    target_circuit_id: CircuitId,
    role: u8,
    peer: PeerBundle,
    initiator_ek: Vec<u8>,
    responder_ek: Vec<u8>,
    initiator_kem: Vec<u8>,
    responder_kem: Vec<u8>,
    initiator_sig: Vec<u8>,
    responder_sig: Vec<u8>,
}

fn created(frames: &[UnifiedFrame]) -> Vec<Created> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                target_circuit_id,
                role,
                peer,
                initiator_ephemeral_key,
                responder_ephemeral_key,
                initiator_kem_ephemeral_pk,
                responder_kem_ephemeral_pk,
                initiator_ephemeral_sig,
                responder_ephemeral_sig,
                ..
            }) => Some(Created {
                circuit_id: *circuit_id,
                target_circuit_id: *target_circuit_id,
                role: *role,
                peer: peer.clone(),
                initiator_ek: initiator_ephemeral_key.clone(),
                responder_ek: responder_ephemeral_key.clone(),
                initiator_kem: initiator_kem_ephemeral_pk.clone(),
                responder_kem: responder_kem_ephemeral_pk.clone(),
                initiator_sig: initiator_ephemeral_sig.clone(),
                responder_sig: responder_ephemeral_sig.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn queued(frames: &[UnifiedFrame]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::QueuedMessage { payload }) => {
                Some(payload.clone())
            }
            _ => None,
        })
        .collect()
}

/// Two proven peers that have both asked: returns (earlier, later) with
/// their frames.
async fn matched(
    state: &RelayState,
    addr: SocketAddr,
    first: &TestIdentity,
    second: &TestIdentity,
) -> (Ws, Vec<UnifiedFrame>, Ws, Vec<UnifiedFrame>) {
    let mut a = authed(addr, first).await;
    let mut b = authed(addr, second).await;
    // The first ask is held before the second, so "earlier" is well defined.
    ask_held(&mut a, state, first, second, [0xA1; 32]).await;
    b.send(ask(first, [0xB2; 32], None)).await.unwrap();
    let fa = frames_until_quiet(&mut a, QUIET).await;
    let fb = frames_until_quiet(&mut b, QUIET).await;
    (a, fa, b, fb)
}

/// A3: the v1 `CreateCircuit` is refused and creates nothing.
#[tokio::test]
async fn a3_create_circuit_is_refused() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let _wb = authed(addr, &b).await;
    wa.send(FrameBuilder::create_circuit(b.bytes.to_vec(), Some(vec![1; 32])).encode())
        .await
        .unwrap();
    assert!(matches!(
        next_control(&mut wa, WAIT).await,
        Some(ControlMessage::Error {
            code: ControlErrorCode::InvalidMessage,
            ..
        })
    ));
    assert!(state.circuits.is_empty());
    assert!(state.pending_asks.is_empty());
}

/// Q2: a one-sided ask creates no circuit and sends the asker nothing; the
/// target gets the knock. A match needs both asks within `ASK_TTL` (540 s).
#[tokio::test]
async fn q2_one_sided_ask_creates_no_circuit_and_sends_nothing_back() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;

    wa.send(ask_with_knock(&b, [0xA1; 32], knock(0x61)))
        .await
        .unwrap();
    assert!(
        frames_until_quiet(&mut wa, QUIET).await.is_empty(),
        "asker got a frame"
    );
    assert_eq!(
        queued(&frames_until_quiet(&mut wb, QUIET).await),
        vec![knock(0x61)]
    );
    assert!(state.circuits.is_empty());
    assert_eq!(state.pending_asks.len(), 1);

    // 541 s later the ask is gone; B's ask is then one-sided too.
    sweep_stale_state(Instant::now() + Duration::from_secs(541), &state);
    assert!(
        state.pending_asks.is_empty(),
        "ask outlived ASK_TTL (540 s)"
    );
    wb.send(ask(&a, [0xB2; 32], None)).await.unwrap();
    assert!(frames_until_quiet(&mut wb, QUIET).await.is_empty());
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(created(&fa).is_empty(), "matched an expired ask");
    assert_eq!(queued(&fa).len(), 1, "A got B's knock instead");
    assert!(state.circuits.is_empty());
}

/// A6: a match carries both verified bundles byte for byte, the earlier
/// asker is the initiator, both ask EKs are echoed to both sides, and the
/// later asker's knock is discarded.
#[tokio::test]
async fn a6_match_carries_verified_bundles_and_both_eks() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (_wa, fa, _wb, fb) = matched(&state, addr, &a, &b).await;

    let ca = created(&fa);
    let cb = created(&fb);
    assert_eq!(
        (ca.len(), cb.len()),
        (1, 1),
        "exactly one CircuitCreatedV3 each"
    );
    let (ca, cb) = (&ca[0], &cb[0]);
    assert_eq!(ca.role, 0, "earlier asker is the initiator");
    assert_eq!(cb.role, 1);
    assert_r5(&ca.peer, &b.bundle);
    assert_r5(&cb.peer, &a.bundle);
    for c in [ca, cb] {
        assert_eq!(c.initiator_ek, vec![0xA1; 32]);
        assert_eq!(c.responder_ek, vec![0xB2; 32]);
        assert_eq!(c.initiator_kem, kem_for([0xA1; 32]).kem.to_vec());
        assert_eq!(c.responder_kem, kem_for([0xB2; 32]).kem.to_vec());
        assert_eq!(c.initiator_sig, sig_for([0xA1; 32]).to_vec());
        assert_eq!(c.responder_sig, sig_for([0xB2; 32]).to_vec());
    }
    assert_eq!(ca.target_circuit_id, cb.circuit_id);
    assert_eq!(cb.target_circuit_id, ca.circuit_id);
    assert!(
        queued(&fa).is_empty(),
        "the later asker's knock must be discarded"
    );
    assert_eq!(queued(&fb).len(), 1, "B saw A's knock once");
    assert!(state.pending_asks.is_empty());
    assert_eq!(state.circuits.len(), 2);
    assert_r2_slot(&state, ca.circuit_id);
    assert_r2_slot(&state, cb.circuit_id);
    let pair = state
        .identity_pair_circuits
        .get(&pair_tag(&a.bytes, &b.bytes))
        .map(|p| p.slot_a);
    assert_eq!(pair, Some(id_tag(&a.bytes)), "side a is the earlier asker");
}

/// Protocol v3 §A.3: two identity asks pair and both sides receive
/// `CircuitCreatedV3` carrying both asks' ML-KEM ephemerals byte for byte,
/// in initiator/responder order, and both asks' ephemeral signatures (R7)
/// likewise. A re-ask replaces the held KEM ephemeral and signature with
/// its new ones, like the X25519 one.
#[tokio::test]
async fn v3_match_forwards_both_kem_ephemerals_unmodified() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    let random_kem = || -> Vec<u8> {
        (0..crate::validate::KEM_PK_BYTES)
            .map(|_| rand::random::<u8>())
            .collect()
    };
    let (stale_kem, kem_a, kem_b) = (random_kem(), random_kem(), random_kem());
    let random_sig = || -> Vec<u8> { (0..64).map(|_| rand::random::<u8>()).collect() };
    let (stale_sig, sig_a, sig_b) = (random_sig(), random_sig(), random_sig());
    let ask_frame = |target: &TestIdentity, ek: [u8; 32], kem: &[u8], sig: &[u8]| {
        FrameBuilder::circuit_ask(
            target.bytes.to_vec(),
            ek.to_vec(),
            kem.to_vec(),
            sig.to_vec(),
            knock(0x5a),
            Some(NO_RESUME),
        )
        .encode()
    };
    wa.send(ask_frame(&b, [0xA0; 32], &stale_kem, &stale_sig))
        .await
        .unwrap();
    let pair = pair_tag(&a.bytes, &b.bytes);
    eventually("A's ask to be held", || {
        state.pending_asks.get(&pair).is_some()
    })
    .await;
    // Re-ask: new EK and KEM ephemeral.
    wa.send(ask_frame(&b, [0xA1; 32], &kem_a, &sig_a))
        .await
        .unwrap();
    eventually("A's re-ask to replace the KEM ephemeral", || {
        state.pending_asks.get(&pair).is_some_and(|p| {
            p.kem_ephemeral.kem[..] == kem_a[..] && p.kem_ephemeral.sig[..] == sig_a[..]
        })
    })
    .await;
    wb.send(ask_frame(&a, [0xB2; 32], &kem_b, &sig_b))
        .await
        .unwrap();
    let ca = created(&frames_until_quiet(&mut wa, QUIET).await);
    let cb = created(&frames_until_quiet(&mut wb, QUIET).await);
    assert_eq!((ca.len(), cb.len()), (1, 1));
    for c in [&ca[0], &cb[0]] {
        assert_eq!(c.initiator_kem, kem_a, "initiator KEM ephemeral altered");
        assert_eq!(c.responder_kem, kem_b, "responder KEM ephemeral altered");
        assert_eq!(
            c.initiator_sig, sig_a,
            "initiator ephemeral signature altered"
        );
        assert_eq!(
            c.responder_sig, sig_b,
            "responder ephemeral signature altered"
        );
        assert_eq!(c.initiator_ek, vec![0xA1; 32]);
        assert_eq!(c.responder_ek, vec![0xB2; 32]);
    }
    assert!(state.pending_asks.is_empty(), "the held ask is dropped");
}

/// Q4 (F17): the lower identity asking first, then the higher, matches.
#[tokio::test]
async fn q4_lower_identity_first_then_higher_matches() {
    let (addr, state) = start(test_config()).await;
    let lo = TestIdentity::with_first_nibble(0x0);
    let hi = TestIdentity::with_first_nibble(0xf);
    let (_wl, fl, _wh, fh) = matched(&state, addr, &lo, &hi).await;
    assert_eq!(
        created(&fl).iter().map(|c| c.role).collect::<Vec<_>>(),
        vec![0]
    );
    assert_eq!(
        created(&fh).iter().map(|c| c.role).collect::<Vec<_>>(),
        vec![1]
    );
}

/// Q1 (presence): whether the target is online-but-not-asking or offline,
/// the asker sees the same frame sequence: nothing.
#[tokio::test]
async fn q1_presence_online_and_offline_targets_look_the_same_to_the_asker() {
    let (addr, state) = start(test_config()).await;
    let asker = TestIdentity::random();
    let online = TestIdentity::random();
    let offline = TestIdentity::random();
    let mut wa = authed(addr, &asker).await;
    let mut wo = authed(addr, &online).await;

    wa.send(ask(&online, [1; 32], None)).await.unwrap();
    let to_online = frames_until_quiet(&mut wa, QUIET).await;
    wa.send(ask(&offline, [2; 32], None)).await.unwrap();
    let to_offline = frames_until_quiet(&mut wa, QUIET).await;

    assert_eq!(format!("{to_online:?}"), format!("{to_offline:?}"));
    assert!(to_online.is_empty());
    assert_eq!(queued(&frames_until_quiet(&mut wo, QUIET).await).len(), 1);
    assert_eq!(queued_knocks(&state, &offline), 1);
}

/// A knock left for an offline target is delivered when it publishes.
#[tokio::test]
async fn knock_for_an_offline_target_is_delivered_on_publish() {
    let (addr, state) = start(test_config()).await;
    let (a, c) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    wa.send(ask_with_knock(&c, [1; 32], knock(0x63)))
        .await
        .unwrap();
    let s = state.clone();
    let cc = c.clone();
    eventually("knock queued", move || queued_knocks(&s, &cc) == 1).await;

    // C publishes by hand so every frame after the publish is seen. The
    // client handles non-signaling frames only after its publish is accepted
    // (round-2 L5), so the publish response must come first and the queued
    // knock after it.
    let mut wc = connect(addr).await;
    let nonce = hello(&mut wc).await;
    wc.send(publish_message(&c, &nonce, &dev_binding()))
        .await
        .unwrap();
    let frames = frames_until_quiet(&mut wc, QUIET).await;
    assert!(
        matches!(
            frames.first(),
            Some(UnifiedFrame::Signaling(sig)) if sig.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE
        ),
        "the first frame after a publish is its (ok) response"
    );
    assert_eq!(
        queued(&frames[1..]),
        vec![knock(0x63)],
        "queued frames follow it"
    );
    assert_eq!(queued_len(&state, &c), 0);
}

/// Q3: at most two knocks per pending ask; a re-ask replaces the EK.
#[tokio::test]
async fn q3_at_most_two_knocks_per_pending_ask() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    for i in 0..4u8 {
        wa.send(ask(&b, [0x10 + i; 32], None)).await.unwrap();
    }
    assert_eq!(queued(&frames_until_quiet(&mut wb, QUIET).await).len(), 2);
    let ask = state
        .pending_asks
        .get(&pair_tag(&a.bytes, &b.bytes))
        .map(|p| (p.ephemeral, p.knocks_delivered));
    assert_eq!(
        ask,
        Some(([0x13; 32], 2)),
        "latest EK kept; two knocks counted"
    );
}

/// Q3: an asker's pending asks leave with its connection.
#[tokio::test]
async fn q3_pending_ask_leaves_with_the_asker() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    wa.send(ask(&b, [1; 32], None)).await.unwrap();
    let s = state.clone();
    eventually("ask stored", move || s.pending_asks.len() == 1).await;
    wa.close(None).await.unwrap();
    let s = state.clone();
    eventually("ask removed on disconnect", move || {
        s.pending_asks.is_empty()
    })
    .await;
}

/// A5: a third party asking one member leaves the existing pair untouched.
#[tokio::test]
async fn a5_third_party_ask_leaves_an_existing_pair_untouched() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let (_wa, fa, mut wb, _fb) = matched(&state, addr, &a, &b).await;
    let ca = created(&fa)[0].clone();
    let before: Vec<(CircuitId, ClientId, ClientId)> = [ca.circuit_id, ca.target_circuit_id]
        .iter()
        .map(|id| {
            let r = state.circuits.get(id).unwrap();
            (*id, r.client_a, r.client_b)
        })
        .collect();

    let mut wc = authed(addr, &c).await;
    wc.send(ask(&b, [3; 32], None)).await.unwrap();
    assert!(frames_until_quiet(&mut wc, QUIET).await.is_empty());
    assert_eq!(
        queued(&frames_until_quiet(&mut wb, QUIET).await).len(),
        1,
        "B got C's knock"
    );

    for (id, client_a, client_b) in before {
        let r = state.circuits.get(&id).expect("A↔B circuit still there");
        assert_eq!(
            (r.client_a, r.client_b),
            (client_a, client_b),
            "routing unchanged"
        );
    }
    assert!(state
        .identity_pair_circuits
        .contains_key(&pair_tag(&a.bytes, &b.bytes)));
}

/// A5 / R2: naming someone else's circuit as `resume_circuit` rebinds nothing.
#[tokio::test]
async fn a5_r2_resume_naming_another_pairs_circuit_rebinds_nothing() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let (_wa, fa, _wb, fb) = matched(&state, addr, &a, &b).await;
    let b_circuit = created(&fb)[0].circuit_id;
    let a_circuit = created(&fa)[0].circuit_id;
    let b_slot = state.circuits.get(&b_circuit).unwrap().client_a;

    let mut wc = authed(addr, &c).await;
    wc.send(ask(&a, [4; 32], Some(b_circuit))).await.unwrap();
    assert!(frames_until_quiet(&mut wc, QUIET).await.is_empty());
    assert_eq!(state.circuits.get(&b_circuit).unwrap().client_a, b_slot);
    assert_r2_slot(&state, b_circuit);
    assert_r2_slot(&state, a_circuit);
}

/// R3: an unproven connection's ask is refused and leaves no trace.
#[tokio::test]
async fn r3_unproven_ask_is_refused() {
    let (addr, state) = start(test_config()).await;
    let target = TestIdentity::random();
    let mut wt = authed(addr, &target).await;
    let mut anon = connect(addr).await;
    let _challenge = hello(&mut anon).await;
    anon.send(ask(&target, [5; 32], None)).await.unwrap();
    assert!(matches!(
        next_control(&mut anon, WAIT).await,
        Some(ControlMessage::Error {
            code: ControlErrorCode::AuthenticationFailed,
            ..
        })
    ));
    assert!(state.pending_asks.is_empty());
    assert!(queued(&frames_until_quiet(&mut wt, QUIET).await).is_empty());
    // A proven connection's ask stands; the invariant holds throughout.
    let mut wa = authed(addr, &TestIdentity::random()).await;
    wa.send(ask(&target, [6; 32], None)).await.unwrap();
    let st = state.clone();
    eventually("the proven ask stands", move || st.pending_asks.len() == 1).await;
    assert_r3(&state);
}

#[tokio::test]
async fn asking_yourself_is_refused() {
    let (addr, state) = start(test_config()).await;
    let a = TestIdentity::random();
    let mut wa = authed(addr, &a).await;
    wa.send(ask(&a, [6; 32], None)).await.unwrap();
    assert!(matches!(
        next_control(&mut wa, WAIT).await,
        Some(ControlMessage::Error {
            code: ControlErrorCode::InvalidMessage,
            ..
        })
    ));
    assert!(state.pending_asks.is_empty());
}

/// Spec §6.2 step 2: an ask on an active pair without a valid resume tears
/// the pair down and tells the peer.
#[tokio::test]
async fn ask_on_active_pair_without_resume_tears_it_down() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, _fa, mut wb, fb) = matched(&state, addr, &a, &b).await;
    let b_circuit = created(&fb)[0].circuit_id;

    wa.send(ask(&b, [7; 32], None)).await.unwrap();
    let fb2 = frames_until_quiet(&mut wb, QUIET).await;
    assert!(fb2.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed { circuit_id, .. }) if *circuit_id == b_circuit
    )));
    assert!(
        frames_until_quiet(&mut wa, QUIET).await.is_empty(),
        "nothing back to the asker"
    );
    assert!(state.circuits.is_empty());
    assert!(!state
        .identity_pair_circuits
        .contains_key(&pair_tag(&a.bytes, &b.bytes)));
    assert_eq!(
        state.pending_asks.len(),
        1,
        "the ask continues as a fresh one"
    );
}

/// R1: mappings only point at connections proven as their identity.
#[tokio::test]
async fn r1_mappings_point_only_at_proven_connections() {
    let (addr, state) = start(test_config()).await;
    let ids: Vec<TestIdentity> = (0..3).map(|_| TestIdentity::random()).collect();
    let mut sockets = Vec::new();
    for id in &ids {
        sockets.push(authed(addr, id).await);
    }
    let _anon = connect(addr).await;
    assert_eq!(state.identity_to_client.len(), 3);
    assert_r1(&state);
}

/// Task 7 minor: the rebind also checks that the named circuit's slot is the
/// caller's own identity (defence in depth): with the slot naming another
/// identity, the pair member's resume rebinds nothing.
#[tokio::test]
async fn resume_rebinds_only_a_slot_that_names_the_caller() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (_wa, fa, _wb, _fb) = matched(&state, addr, &a, &b).await;
    let a_circuit = created(&fa)[0].circuit_id;
    let a_slot = state.circuits.get(&a_circuit).unwrap().client_a;
    state.circuits.get_mut(&a_circuit).unwrap().tag_a =
        super::tags::id_tag(&TestIdentity::random().bytes);

    let mut wa2 = authed(addr, &a).await;
    wa2.send(ask(&b, [7; 32], Some(a_circuit))).await.unwrap();
    let _ = frames_until_quiet(&mut wa2, QUIET).await;
    // Either left as it was or torn down by the fresh ask; never moved to
    // the caller's new connection.
    let slot = state.circuits.get(&a_circuit).map(|r| r.client_a);
    assert!(
        slot.is_none() || slot == Some(a_slot),
        "a slot that isn't the caller's is never rebound"
    );
}
