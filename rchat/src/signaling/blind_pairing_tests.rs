//! Blinded pairing (protocol v3 §C.2): two proven connections of different
//! identities that ask with the same rotating pair token are paired, and
//! the relay's pair row is keyed by the keyed token hash (`BlindTag`) with
//! the two connection slots only, never by `PairTag(identity_a,
//! identity_b)`. Replays, a busy token, unproven callers, the ask TTL, the
//! orphan sweep, the pending caps and log privacy are covered too.

use super::circuits::{assert_r2_slot, assert_r5};
use super::tags::{blind_tag, id_tag, pair_tag, BlindTag};
use super::test_support::*;
use super::*;
use crate::protocol::unified::{CircuitCloseReason, PeerBundle};

const QUIET: Duration = Duration::from_millis(400);

/// `CircuitAskBlind` for `token` with X25519 ephemeral `ek` (KEM ephemeral
/// `kem_for(ek)`, signature `sig_for(ek)`), padded to `ASK_WIRE_LEN`.
fn blind_ask(token: [u8; 32], ek: [u8; 32]) -> Message {
    blind_ask_with_pad(token, ek, crate::validate::BLIND_PAD_LEN)
}

fn blind_ask_with_pad(token: [u8; 32], ek: [u8; 32], pad: usize) -> Message {
    UnifiedFrame::Control(ControlMessage::CircuitAskBlind {
        pair_token: token.to_vec(),
        ephemeral_key: ek.to_vec(),
        kem_ephemeral_pk: kem_for(ek).kem.to_vec(),
        ephemeral_sig: sig_for(ek).to_vec(),
        pad: vec![0; pad],
    })
    .encode()
}

/// The pending blind ask's (asker connection, X25519 ephemeral), if held.
fn held(state: &RelayState, token: [u8; 32]) -> Option<(ClientId, [u8; 32])> {
    state
        .pending_asks
        .get_blind(&blind_tag(&token))
        .map(|a| (a.asker, a.ephemeral))
}

/// `ws` (proven as `asker`) sends a blind ask and returns once the relay
/// holds it.
async fn blind_held(
    ws: &mut Ws,
    state: &RelayState,
    asker: &TestIdentity,
    token: [u8; 32],
    ek: [u8; 32],
) {
    ws.send(blind_ask(token, ek)).await.unwrap();
    let tag = id_tag(&asker.bytes);
    eventually("the blind ask to be held", || {
        state
            .pending_asks
            .get_blind(&blind_tag(&token))
            .is_some_and(|a| a.asker_tag == tag && a.ephemeral == ek)
    })
    .await;
}

#[derive(Debug, Clone)]
struct CreatedV3 {
    circuit_id: CircuitId,
    token: Vec<u8>,
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

fn created_v3(frames: &[UnifiedFrame]) -> Vec<CreatedV3> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                token,
                target_circuit_id,
                role,
                peer,
                initiator_ephemeral_key,
                responder_ephemeral_key,
                initiator_kem_ephemeral_pk,
                responder_kem_ephemeral_pk,
                initiator_ephemeral_sig,
                responder_ephemeral_sig,
            }) => Some(CreatedV3 {
                circuit_id: *circuit_id,
                token: token.clone(),
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

fn control_errors(frames: &[UnifiedFrame]) -> Vec<ControlErrorCode> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::Error { code, .. }) => Some(*code),
            _ => None,
        })
        .collect()
}

/// The ephemerals named by the typed `PairTokenBusy` answers (R22).
fn busy_eks(frames: &[UnifiedFrame]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|f| match f {
            UnifiedFrame::Control(ControlMessage::PairTokenBusy { ephemeral_key }) => {
                Some(ephemeral_key.clone())
            }
            _ => None,
        })
        .collect()
}

fn queued(frames: &[UnifiedFrame]) -> usize {
    frames
        .iter()
        .filter(|f| {
            matches!(
                f,
                UnifiedFrame::Control(ControlMessage::QueuedMessage { .. })
            )
        })
        .count()
}

/// A (earlier) and B blind-ask with `token`; returns both sockets and both
/// `CircuitCreatedV3`.
async fn blind_pair(
    state: &RelayState,
    addr: SocketAddr,
    a: &TestIdentity,
    b: &TestIdentity,
    token: [u8; 32],
) -> (Ws, Ws, CreatedV3, CreatedV3) {
    let mut wa = authed(addr, a).await;
    let mut wb = authed(addr, b).await;
    blind_held(&mut wa, state, a, token, [0xA1; 32]).await;
    wb.send(blind_ask(token, [0xB2; 32])).await.unwrap();
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    let fb = frames_until_quiet(&mut wb, QUIET).await;
    let (ca, cb) = (created_v3(&fa), created_v3(&fb));
    assert_eq!((ca.len(), cb.len()), (1, 1), "one CircuitCreatedV3 each");
    (wa, wb, ca[0].clone(), cb[0].clone())
}

async fn gone(state: &RelayState, id: &TestIdentity) {
    let (st, bytes) = (state.clone(), id.bytes);
    eventually("the connection to be gone", move || {
        !st.connections
            .iter()
            .any(|c| c.proven_identity == Some(bytes))
    })
    .await;
}

// ------------------------------------------------------------- tag

/// `blind_tag` is keyed with the per-boot pair key and its own domain: it
/// differs per token, from a pair tag over the same bytes, and prints no
/// bytes.
#[test]
fn blind_tag_is_keyed_domain_separated_and_opaque() {
    let t = [0x42; 32];
    assert_eq!(blind_tag(&t), blind_tag(&t));
    assert_ne!(blind_tag(&t), blind_tag(&[0x43; 32]));
    assert_ne!(blind_tag(&t).0, t, "a blind tag is not the token");
    assert_ne!(
        blind_tag(&t).0,
        pair_tag(&t, &t).0,
        "domain-separated from pair tags"
    );
    let k1 = super::tags::blind_tag_with(&[1; 32], &t);
    assert_ne!(k1, super::tags::blind_tag_with(&[2; 32], &t), "keyed");
    let mut h = blake3::Hasher::new_keyed(&[1; 32]);
    h.update(b"rchat/blind/v3\0");
    h.update(&t);
    assert_eq!(
        k1.0,
        *h.finalize().as_bytes(),
        "BLAKE3-keyed(key, domain || token)"
    );
    assert_eq!(format!("{:?}", blind_tag(&t)), "BlindTag(..)");
}

// ------------------------------------------------------------- matching

/// §C.2: two proven identities with the same token are paired; each gets
/// `CircuitCreatedV3` with the role set by ask order, the other's verified
/// bundle (R5), and both asks' ephemerals, KEM ephemerals and signatures
/// byte for byte. No knock is delivered; packets route both ways.
#[tokio::test]
async fn two_identities_with_one_token_are_paired_by_ask_order() {
    let before = metrics::BLIND_ASKS_MATCHED.get();
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    blind_held(&mut wa, &state, &a, token, [0xA1; 32]).await;
    wb.send(blind_ask(token, [0xB2; 32])).await.unwrap();
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    let fb = frames_until_quiet(&mut wb, QUIET).await;
    let (ca, cb) = (created_v3(&fa), created_v3(&fb));
    assert_eq!((ca.len(), cb.len()), (1, 1));
    let (ca, cb) = (&ca[0], &cb[0]);
    assert_eq!((ca.role, cb.role), (0, 1), "the earlier asker initiates");
    assert_eq!(ca.target_circuit_id, cb.circuit_id);
    assert_eq!(cb.target_circuit_id, ca.circuit_id);
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
    assert_eq!(queued(&fa) + queued(&fb), 0, "blind asks carry no knock");
    assert!(state.pending_asks.is_empty(), "the held ask is consumed");
    assert!(
        !state.connections.iter().any(|c| c
            .pending_charges
            .iter()
            .any(|(k, _)| *k == ChargeKey::Blind(blind_tag(&token)))),
        "the consumed ask's charge goes with it (no connection keeps the tag)"
    );
    assert_eq!(state.circuits.len(), 2);
    assert_r2_slot(&state, ca.circuit_id);
    assert_r2_slot(&state, cb.circuit_id);
    assert!(metrics::BLIND_ASKS_MATCHED.get() > before);

    // Routing works as for identity circuits.
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 64]))
        .await
        .unwrap();
    let got = frames_until_quiet(&mut wb, QUIET).await;
    assert!(
        got.iter()
            .any(|f| matches!(f, UnifiedFrame::Relay(p) if p.circuit_id == cb.circuit_id)),
        "B received A's packet on its own circuit"
    );
    wb.send(relay_on(cb.target_circuit_id, &cb.token, vec![0x02; 64]))
        .await
        .unwrap();
    let got = frames_until_quiet(&mut wa, QUIET).await;
    assert!(got
        .iter()
        .any(|f| matches!(f, UnifiedFrame::Relay(p) if p.circuit_id == ca.circuit_id)));
}

/// §C.2 "No identity pair is stored": a blinded circuit leaves no row under
/// `PairTag(a, b)`; its row is keyed by the token's `BlindTag` and holds the
/// two connection slots and circuit ids only. No map is keyed by the
/// identity pair. Honest limit (§C.5): while the circuit is live its two
/// routing entries name both members' `IdTag`s (offline filing); rulings
/// R15's bounds on the row's lifetime are tested below.
#[tokio::test]
async fn a_blinded_circuit_has_no_pair_row_but_live_routing_names_both_members() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (_wa, _wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    let pair = pair_tag(&a.bytes, &b.bytes);
    assert!(
        state.identity_pair_circuits.get(&pair).is_none(),
        "no PairTag(a, b) row"
    );
    assert!(state.identity_pair_circuits.is_empty());
    let row = state
        .blind_pair_circuits
        .get(&blind_tag(&token))
        .map(|r| r.clone())
        .expect("a row under the BlindTag");
    assert_eq!(state.blind_pair_circuits.len(), 1);
    let (conn_a, conn_b) = (
        mapped_client(&state, &a).unwrap(),
        mapped_client(&state, &b).unwrap(),
    );
    assert_eq!(
        (row.conn_a, row.conn_b),
        (conn_a, conn_b),
        "slot connections"
    );
    assert_eq!(
        (row.circuit_id_a, row.circuit_id_b),
        (ca.circuit_id, cb.circuit_id)
    );
    let (ta, tb) = (id_tag(&a.bytes), id_tag(&b.bytes));
    for e in state.circuits.iter() {
        assert_eq!(e.pair, PairKey::Blind(blind_tag(&token)));
        assert_ne!(e.pair, PairKey::Identity(pair));
        assert!(
            [e.tag_a, e.tag_b] == [ta, tb] || [e.tag_a, e.tag_b] == [tb, ta],
            "live routing names both members (the §C.5 honest limit)"
        );
    }
    assert!(!super::pair_lock::PAIR_LOCKS.is_tracked(&pair));
}

/// §C.2 replay: the same identity asking twice with one token (the same
/// connection, or another connection of it) is never a pair. The newer ask
/// replaces the older one silently; a later peer matches the newer.
#[tokio::test]
async fn the_same_identity_twice_is_a_replay_and_the_older_ask_is_dropped() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let mut wa1 = authed(addr, &a).await;
    let mut wa2 = authed(addr, &a).await;
    let a1 = state
        .connections
        .iter()
        .filter(|c| c.proven_identity == Some(a.bytes))
        .map(|c| *c.key())
        .collect::<Vec<_>>();
    assert_eq!(a1.len(), 2, "two live connections of A");

    blind_held(&mut wa1, &state, &a, token, [0x11; 32]).await;
    // Same connection again: replaced.
    blind_held(&mut wa1, &state, &a, token, [0x12; 32]).await;
    // Another connection of the same identity: replaced, not paired.
    blind_held(&mut wa2, &state, &a, token, [0x13; 32]).await;
    let a2 = mapped_client(&state, &a).unwrap();
    assert_eq!(held(&state, token), Some((a2, [0x13; 32])));
    assert_eq!(state.pending_asks.len(), 1, "one ask per token");
    assert!(state.circuits.is_empty(), "never a self pair");
    let f1 = frames_until_quiet(&mut wa1, QUIET).await;
    let f2 = frames_until_quiet(&mut wa2, QUIET).await;
    assert!(
        f1.is_empty() && f2.is_empty(),
        "a replay is dropped silently"
    );

    let mut wb = authed(addr, &b).await;
    wb.send(blind_ask(token, [0xB2; 32])).await.unwrap();
    let fb = created_v3(&frames_until_quiet(&mut wb, QUIET).await);
    let f2 = created_v3(&frames_until_quiet(&mut wa2, QUIET).await);
    let f1 = created_v3(&frames_until_quiet(&mut wa1, QUIET).await);
    assert_eq!((fb.len(), f2.len(), f1.len()), (1, 1, 0));
    assert_eq!(fb[0].initiator_ek, vec![0x13; 32], "the newer ask matched");
    // The replay replaced the KEM ephemeral and the ephemeral signature
    // (R7) with the X25519 key: all three come from the newest ask.
    for c in [&fb[0], &f2[0]] {
        assert_eq!(c.initiator_kem, kem_for([0x13; 32]).kem.to_vec());
        assert_eq!(c.initiator_sig, sig_for([0x13; 32]).to_vec());
    }
    assert_eq!(f2[0].role, 0);
}

/// §C.2: a token that already paired two asks refuses a third with
/// `PairTokenBusy`; nothing is stored and the pair is untouched.
#[tokio::test]
async fn a_third_ask_on_a_paired_token_gets_pair_token_busy() {
    let before = metrics::BLIND_ASKS_BUSY.get();
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let token = rand::random();
    let (_wa, mut wb, _ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    let mut wc = authed(addr, &c).await;
    wc.send(blind_ask(token, [0xC3; 32])).await.unwrap();
    let fc = frames_until_quiet(&mut wc, QUIET).await;
    // R22: the typed answer names the refused ask's own ephemeral, so the
    // client advances the right pair; no error code is sent.
    assert!(control_errors(&fc).is_empty());
    assert_eq!(busy_eks(&fc), vec![vec![0xC3u8; 32]]);
    assert!(created_v3(&fc).is_empty());
    assert!(state.pending_asks.is_empty(), "the third ask is not stored");
    assert_eq!(state.circuits.len(), 2, "the pair is untouched");
    assert_eq!(state.blind_pair_circuits.len(), 1);
    // A member on another connection (not a slot of the row) asking the
    // consumed token is refused the same way; the pair is untouched.
    let mut wb2 = authed(addr, &b).await;
    wb2.send(blind_ask(token, [0xB9; 32])).await.unwrap();
    let fb = frames_until_quiet(&mut wb2, QUIET).await;
    assert_eq!(busy_eks(&fb), vec![vec![0xB9u8; 32]]);
    assert_eq!(state.circuits.len(), 2);
    assert_eq!(state.blind_pair_circuits.len(), 1);
    assert!(frames_until_quiet(&mut wb, QUIET).await.is_empty());
    assert!(metrics::BLIND_ASKS_BUSY.get() >= before + 2);
}

/// Ruling R16, the wedge: B's `CircuitCreatedV3` was lost (a full queue
/// drops it), so B, still on its slot connection, re-asks the spent token.
/// The row is torn down (A is told `CircuitClosed`) and B is still told
/// busy; a fresh token then pairs them again.
#[tokio::test]
async fn a_slot_re_asking_its_spent_token_unwedges_the_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, mut wb, _ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    wb.send(blind_ask(token, [0xB9; 32])).await.unwrap();
    let fb = frames_until_quiet(&mut wb, QUIET).await;
    assert!(
        busy_eks(&fb) == vec![vec![0xB9u8; 32]],
        "still told busy: {fb:?}"
    );
    assert!(state.blind_pair_circuits.is_empty(), "the row is gone");
    assert!(state.circuits.is_empty());
    assert!(state.circuit_counts.is_empty());
    assert!(state.pending_asks.is_empty(), "the busy ask is not held");
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(fa.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed { .. })
    )));
    // Both advance to the next token and pair again.
    let next = rand::random();
    blind_held(&mut wa, &state, &a, next, [0xA5; 32]).await;
    wb.send(blind_ask(next, [0xB5; 32])).await.unwrap();
    assert_eq!(
        created_v3(&frames_until_quiet(&mut wb, QUIET).await).len(),
        1
    );
    assert_eq!(state.blind_pair_circuits.len(), 1);
}

// ------------------------------------------------------------- who may ask

/// §C.2 / Task 3 M5: a connection whose publish was not accepted is refused
/// before anything is parsed or stored, malformed or not.
#[tokio::test]
async fn an_unproven_connection_is_refused() {
    let before = metrics::BLIND_ASKS_REFUSED_UNPROVEN.get();
    let (addr, state) = start(test_config()).await;
    let mut ws = connect(addr).await;
    let _nonce = hello(&mut ws).await;
    for msg in [
        blind_ask(rand::random(), [1; 32]),
        blind_ask_with_pad(rand::random(), [1; 32], 3),
    ] {
        ws.send(msg).await.unwrap();
        let frames = frames_until_quiet(&mut ws, QUIET).await;
        assert!(
            matches!(
                control_errors(&frames)[..],
                [ControlErrorCode::AuthenticationFailed]
            ),
            "got {frames:?}"
        );
        assert!(state.pending_asks.is_empty(), "nothing stored");
    }
    assert!(metrics::BLIND_ASKS_REFUSED_UNPROVEN.get() >= before + 2);
}

/// F.2 frame checks: a blind ask of the wrong length is refused from a
/// proven connection and stores nothing; a well-formed one is exactly as
/// long on the wire as an identity ask.
#[tokio::test]
async fn a_blind_ask_of_the_wrong_length_is_refused() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let token = rand::random();
    let pad = crate::validate::BLIND_PAD_LEN;
    for p in [0, pad - 1, pad + 1] {
        wa.send(blind_ask_with_pad(token, [1; 32], p))
            .await
            .unwrap();
        let frames = frames_until_quiet(&mut wa, QUIET).await;
        assert!(
            matches!(
                control_errors(&frames)[..],
                [ControlErrorCode::InvalidMessage]
            ),
            "pad {p}: got {frames:?}"
        );
        assert!(state.pending_asks.is_empty(), "pad {p}: stored");
    }
    // R17 M1: the right length with a non-zero pad byte is refused too.
    let nonzero = UnifiedFrame::Control(ControlMessage::CircuitAskBlind {
        pair_token: token.to_vec(),
        ephemeral_key: vec![1; 32],
        kem_ephemeral_pk: kem_for([1; 32]).kem.to_vec(),
        ephemeral_sig: sig_for([1; 32]).to_vec(),
        pad: {
            let mut p = vec![0; pad];
            p[pad - 1] = 0x80;
            p
        },
    })
    .encode();
    wa.send(nonzero).await.unwrap();
    let frames = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        matches!(
            control_errors(&frames)[..],
            [ControlErrorCode::InvalidMessage]
        ),
        "non-zero pad: got {frames:?}"
    );
    assert!(state.pending_asks.is_empty(), "non-zero pad: stored");
    let blind_len = match blind_ask(token, [1; 32]) {
        Message::Binary(b) => b.len(),
        _ => unreachable!(),
    };
    let ident_len = match ask(&b, [1; 32], None) {
        Message::Binary(b) => b.len(),
        _ => unreachable!(),
    };
    assert_eq!(blind_len, ident_len, "blind and identity asks look alike");
}

// ------------------------------------------------------------- lifetimes

/// A blind ask expires `ASK_TTL` after it was made, like an identity ask:
/// the sweep removes it, and an ask past the TTL never matches.
#[tokio::test]
async fn a_blind_ask_expires_after_ask_ttl() {
    let before = metrics::BLIND_ASKS_EXPIRED.get();
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let mut wa = authed(addr, &a).await;
    blind_held(&mut wa, &state, &a, token, [0xA1; 32]).await;
    sweep_stale_state(
        Instant::now() + circuits::ASK_TTL - Duration::from_secs(1),
        &state,
    );
    assert!(held(&state, token).is_some(), "kept inside the TTL");
    sweep_stale_state(
        Instant::now() + circuits::ASK_TTL + Duration::from_secs(1),
        &state,
    );
    assert!(held(&state, token).is_none(), "expired after ASK_TTL");
    assert!(metrics::BLIND_ASKS_EXPIRED.get() > before);

    // Past the TTL but not yet swept: it never matches.
    blind_held(&mut wa, &state, &a, token, [0xA2; 32]).await;
    state
        .pending_asks
        .get_blind_mut(&blind_tag(&token))
        .unwrap()
        .at = Instant::now() - circuits::ASK_TTL - Duration::from_secs(1);
    let mut wb = authed(addr, &b).await;
    blind_held(&mut wb, &state, &b, token, [0xB2; 32]).await;
    assert!(state.circuits.is_empty(), "an expired ask does not match");
    assert!(created_v3(&frames_until_quiet(&mut wa, QUIET).await).is_empty());
}

/// A re-ask (replay) never keeps a blind ask alive past `ASK_TTL` from the
/// first ask.
#[tokio::test]
async fn a_replay_does_not_extend_the_ttl() {
    let (addr, state) = start(test_config()).await;
    let a = TestIdentity::random();
    let token = rand::random();
    let mut wa = authed(addr, &a).await;
    blind_held(&mut wa, &state, &a, token, [0xA1; 32]).await;
    let first = state.pending_asks.get_blind(&blind_tag(&token)).unwrap().at;
    blind_held(&mut wa, &state, &a, token, [0xA2; 32]).await;
    let again = state.pending_asks.get_blind(&blind_tag(&token)).unwrap().at;
    assert_eq!(first, again, "the first ask's time is kept");
}

/// A blind ask goes when its connection disconnects.
#[tokio::test]
async fn a_blind_ask_leaves_with_its_connection() {
    let (addr, state) = start(test_config()).await;
    let a = TestIdentity::random();
    let token = rand::random();
    let mut wa = authed(addr, &a).await;
    blind_held(&mut wa, &state, &a, token, [0xA1; 32]).await;
    drop(wa);
    let st = state.clone();
    eventually("the blind ask to go", move || st.pending_asks.is_empty()).await;
}

/// Ruling R15 state scan: no structure in relay state holds both members'
/// `IdTag`s, and no pair-level structure holds either member's source
/// digest. A connection's own record (its proven identity and its source)
/// and the identity's own routing slot and offline queue are per identity,
/// not per pair, and are scanned as separate structures. Every live
/// connection is scanned too (review L-4): no pending charge for the pair's
/// token, and none of the pair's circuit ids in its circuit table or its
/// created-circuit set.
fn assert_no_trace_of_the_pair(
    state: &RelayState,
    a: &TestIdentity,
    b: &TestIdentity,
    sources: &[crate::limits::SourceKey],
    pair: (BlindTag, [CircuitId; 2]),
) {
    let (tag, cids) = pair;
    for conn in state.connections.iter() {
        assert!(
            !conn
                .pending_charges
                .iter()
                .any(|(k, _)| *k == ChargeKey::Blind(tag)),
            "a connection holds a charge for the pair's token"
        );
        for cid in &cids {
            assert!(
                !conn.circuits.contains_key(cid),
                "a connection's circuit table names the pair"
            );
            assert!(
                !conn.created_circuits.contains(cid),
                "a connection's created circuits name the pair"
            );
        }
        assert!(
            !conn
                .circuits
                .iter()
                .any(|c| cids.contains(&c.target_circuit_id)),
            "a connection's circuit info points at the pair"
        );
    }
    let (ta, tb) = (id_tag(&a.bytes), id_tag(&b.bytes));
    let both = |tags: &[IdTag]| tags.contains(&ta) && tags.contains(&tb);
    let (count_tags, count_sources) = state.circuit_counts.keys();
    type Scan<'a> = (&'a str, Vec<IdTag>, Vec<crate::limits::SourceKey>);
    let structures: Vec<Scan> = vec![
        (
            "circuits",
            state
                .circuits
                .iter()
                .flat_map(|e| [e.tag_a, e.tag_b])
                .collect(),
            Vec::new(),
        ),
        (
            "blind rows",
            Vec::new(),
            state
                .blind_pair_circuits
                .iter()
                .flat_map(|e| [e.source_a, e.source_b])
                .flatten()
                .collect(),
        ),
        (
            "identity rows",
            state
                .identity_pair_circuits
                .iter()
                .flat_map(|e| [e.slot_a, e.slot_b])
                .collect(),
            state
                .identity_pair_circuits
                .iter()
                .flat_map(|e| [e.source_a, e.source_b])
                .flatten()
                .collect(),
        ),
        (
            "pending asks",
            state.pending_asks.iter().map(|e| e.asker_tag).collect(),
            state.pending_asks.sources(),
        ),
        (
            "routing slots",
            state.identity_to_client.iter().map(|e| *e.key()).collect(),
            Vec::new(),
        ),
        (
            "offline queues",
            state.message_queues.iter().map(|e| *e.key()).collect(),
            Vec::new(),
        ),
        ("circuit counts", count_tags, count_sources),
        (
            "departed blind index",
            state.departed_blind.iter().map(|e| *e.key()).collect(),
            Vec::new(),
        ),
    ];
    // A connected identity is mapped whatever pairs exist (§C.5: the relay
    // sees connected accounts); with both members online the routing slots
    // name both by being online, not by any pair.
    let online = |id: &TestIdentity| {
        state
            .connections
            .iter()
            .any(|c| c.proven_identity == Some(id.bytes))
    };
    let both_online = online(a) && online(b);
    for (name, tags, srcs) in &structures {
        if !(both_online && *name == "routing slots") {
            assert!(!both(tags), "{name} holds both members' IdTags");
        }
        assert!(
            !srcs.iter().any(|s| sources.contains(s)),
            "{name} holds a member's source digest"
        );
    }
    assert!(state.blind_pair_circuits.is_empty() && state.circuits.is_empty());
    assert!(
        !state
            .departed_blind
            .iter()
            .any(|e| e.value().iter().any(|c| cids.contains(c))),
        "the R21 index names a circuit of the pair"
    );
}

/// Ruling R21, as amended by final review L1: a member back on a new
/// connection ends its blinded rows whose slot is still its closed
/// connection at that connection's first ask, not at its publish (a
/// background drain publishes too, and never re-pairs): the peer that
/// stayed is told `CircuitClosed` then (and re-asks blind), and the index
/// entry goes with the row. A row whose last member leaves takes its entry
/// too.
#[tokio::test]
async fn a_member_asking_again_ends_its_departed_blind_rows() {
    let before = metrics::BLIND_ROWS_ENDED_AT_PUBLISH.get();
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    drop(wb);
    gone(&state, &b).await;
    let tb = id_tag(&b.bytes);
    let st = state.clone();
    eventually("B's departed circuit to be indexed", move || {
        st.departed_blind
            .get(&tb)
            .is_some_and(|c| c.contains(&cb.circuit_id))
    })
    .await;
    assert_eq!(state.blind_pair_circuits.len(), 1, "A is still online");
    assert!(frames_until_quiet(&mut wa, QUIET).await.is_empty());
    let mut wb2 = authed(addr, &b).await;
    assert!(
        frames_until_quiet(&mut wa, QUIET).await.is_empty(),
        "a publish alone ends nothing"
    );
    assert_eq!(state.blind_pair_circuits.len(), 1);
    wb2.send(blind_ask(rand::random(), [0xB3; 32]))
        .await
        .unwrap();
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        fa.iter().any(|f| matches!(
            f,
            UnifiedFrame::Control(ControlMessage::CircuitClosed { circuit_id, .. })
                if *circuit_id == ca.circuit_id
        )),
        "A told at B's first ask: {fa:?}"
    );
    assert!(state.blind_pair_circuits.is_empty());
    assert!(state.circuits.is_empty());
    assert!(state.departed_blind.is_empty(), "the index entry is gone");
    assert!(metrics::BLIND_ROWS_ENDED_AT_PUBLISH.get() > before);

    // The last member leaving ends the row and prunes its entry too.
    let token2 = rand::random();
    let (c, d) = (TestIdentity::random(), TestIdentity::random());
    let (wc, wd, _cc, _cd) = blind_pair(&state, addr, &c, &d, token2).await;
    drop(wd);
    gone(&state, &d).await;
    let td = id_tag(&d.bytes);
    let st = state.clone();
    eventually("D's circuit indexed", move || {
        st.departed_blind.contains_key(&td)
    })
    .await;
    drop(wc);
    gone(&state, &c).await;
    let st = state.clone();
    eventually("the entry to go with the row", move || {
        st.departed_blind.is_empty() && st.blind_pair_circuits.is_empty()
    })
    .await;
}

/// Fix round 2 N-1: the member publishes and asks on a new connection
/// before the relay has closed its old one (the common mobile case). Its
/// first ask has nothing to end yet; when the old socket closes, the row
/// ends at once (the peer told `CircuitClosed`) and nothing is left in the
/// index.
#[tokio::test]
async fn an_old_socket_closing_after_the_members_new_ask_ends_the_row() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    let mut wb2 = authed(addr, &b).await;
    blind_held(&mut wb2, &state, &b, rand::random(), [0xB3; 32]).await;
    assert_eq!(
        state.blind_pair_circuits.len(),
        1,
        "the old slot is still live"
    );
    assert!(frames_until_quiet(&mut wa, QUIET).await.is_empty());
    drop(wb);
    let st = state.clone();
    eventually("the old connection to go", move || {
        st.connections.len() == 2
    })
    .await;
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        fa.iter().any(|f| matches!(
            f,
            UnifiedFrame::Control(ControlMessage::CircuitClosed { circuit_id, .. })
                if *circuit_id == ca.circuit_id
        )),
        "A told when B's old socket closed: {fa:?}"
    );
    assert!(state.blind_pair_circuits.is_empty());
    assert!(state.circuits.is_empty());
    assert!(state.departed_blind.is_empty(), "nothing left in the index");
}

/// Final review L1: a background drain (publish, read the queue, leave,
/// never ask) does not end the peer's blinded row, whether the member's
/// old socket closed before or after it, and the sweep's 0 s grace does
/// not fire for it either. Until a connection of the member asks, the
/// member counts as offline: the peer's packets are filed and
/// acknowledged. The foreground connection's first ask hands them over and
/// ends the row (the peer told `CircuitClosed`).
#[tokio::test]
async fn a_drain_publish_keeps_the_peers_row_until_the_first_ask() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    // A drain connection publishes while the old socket is still open...
    let drain1 = authed(addr, &b).await;
    drop(wb);
    let st = state.clone();
    eventually("the old connection to go", move || {
        st.connections.len() == 2
    })
    .await;
    // ...and another after it closed.
    drop(drain1);
    gone(&state, &b).await;
    let mut drain2 = authed(addr, &b).await;
    sweep_stale_state(Instant::now(), &state);
    assert!(
        frames_until_quiet(&mut wa, QUIET).await.is_empty(),
        "A is not told: a drain never re-pairs"
    );
    assert_eq!(state.blind_pair_circuits.len(), 1, "the row stays");

    // B counts as offline: A's packet is filed and acknowledged.
    let payload = vec![0x02; 64];
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload.clone()))
        .await
        .unwrap();
    let (st, bb) = (state.clone(), b.clone());
    eventually("filed in B's queue", move || queued_len(&st, &bb) == 1).await;
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        fa.iter()
            .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))),
        "acknowledged: {fa:?}"
    );
    assert!(!fa.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::Error { .. })
            | UnifiedFrame::Control(ControlMessage::CircuitClosed { .. })
    )));
    assert_eq!(
        queued(&frames_until_quiet(&mut drain2, QUIET).await),
        0,
        "nothing handed to the drain after its marker"
    );

    // The foreground connection's first ask: the queue, then the teardown.
    let mut foreground = drain2;
    foreground
        .send(blind_ask(rand::random(), [0xB3; 32]))
        .await
        .unwrap();
    let fb = frames_until_quiet(&mut foreground, QUIET).await;
    assert_eq!(queued(&fb), 1, "the filed packet is handed over: {fb:?}");
    assert_eq!(queued_len(&state, &b), 0);
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        fa.iter().any(|f| matches!(
            f,
            UnifiedFrame::Control(ControlMessage::CircuitClosed { circuit_id, .. })
                if *circuit_id == ca.circuit_id
        )),
        "A told at B's first ask: {fa:?}"
    );
    assert!(state.blind_pair_circuits.is_empty());
    assert!(state.departed_blind.is_empty());
}

/// Final review L1: an identity ask is an ask too: a foreground connection
/// whose first ask is an identity ask (first contact with someone else)
/// ends its departed blinded rows the same way.
#[tokio::test]
async fn a_first_identity_ask_also_ends_departed_blind_rows() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, _ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    drop(wb);
    gone(&state, &b).await;
    let mut wb2 = authed(addr, &b).await;
    assert!(frames_until_quiet(&mut wa, QUIET).await.is_empty());
    wb2.send(ask(&TestIdentity::random(), [0xB4; 32], None))
        .await
        .unwrap();
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(fa.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed { .. })
    )));
    assert!(state.blind_pair_circuits.is_empty());
}

/// Per-source accounting on, so connections have source digests.
fn sourced_config() -> ServerConfig {
    let mut config = test_config();
    config.max_connections_per_ip = 100;
    config
}

fn sources_of(state: &RelayState, ids: &[&TestIdentity]) -> Vec<crate::limits::SourceKey> {
    let s: Vec<_> = state
        .connections
        .iter()
        .filter(|c| ids.iter().any(|i| c.proven_identity == Some(i.bytes)))
        .filter_map(|c| c.source)
        .collect();
    assert!(!s.is_empty(), "per-source accounting is on");
    s
}

/// Ruling R15 (a): when the last member of a blinded row leaves, the row,
/// its routing entries and counts go at once, not after the orphan TTL.
#[tokio::test]
async fn the_last_member_leaving_tears_the_blinded_row_down_at_once() {
    let (addr, state) = start(sourced_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (wa, wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    let sources = sources_of(&state, &[&a, &b]);
    let pair = (blind_tag(&token), [ca.circuit_id, cb.circuit_id]);
    drop(wa);
    gone(&state, &a).await;
    assert_eq!(state.blind_pair_circuits.len(), 1, "B is still here");
    drop(wb);
    gone(&state, &b).await;
    let st = state.clone();
    eventually("the row to go with the last member", move || {
        st.blind_pair_circuits.is_empty() && st.circuits.is_empty()
    })
    .await;
    assert!(state.circuit_counts.is_empty(), "counts released");
    assert_no_trace_of_the_pair(&state, &a, &b, &sources, pair);
}

/// Review L-1: if the last-member teardown missed the token's lock, the
/// next sweep removes the row at once (every slot dead), not 600 s later.
#[tokio::test]
async fn a_row_whose_last_teardown_missed_its_lock_goes_at_the_next_sweep() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (wa, wb, _ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    let held = super::pair_lock::BLIND_LOCKS.lock(blind_tag(&token)).await;
    drop(wa);
    drop(wb);
    gone(&state, &a).await;
    gone(&state, &b).await;
    assert_eq!(state.blind_pair_circuits.len(), 1, "the lock was busy");
    drop(held);
    sweep_stale_state(Instant::now(), &state);
    assert!(
        state.blind_pair_circuits.is_empty(),
        "taken by the next sweep"
    );
    assert!(state.circuits.is_empty());
}

/// Ruling R15 (b): `PAIR_ORPHAN_TTL` after one member left, the row goes
/// even though the other is still online, which is told `CircuitClosed`.
/// Until then, its packets are filed in the departed member's offline
/// queue.
#[tokio::test]
async fn a_blinded_row_goes_at_the_orphan_ttl_after_one_member_left() {
    let (addr, state) = start(sourced_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    let sources = sources_of(&state, &[&a, &b]);
    let pair = (blind_tag(&token), [ca.circuit_id, cb.circuit_id]);
    // Before the disconnect, so the row's clock starts at or after t0.
    let t0 = Instant::now();
    drop(wb);
    gone(&state, &b).await;
    // Offline filing to the departed member works inside the window.
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 64]))
        .await
        .unwrap();
    let (st, bb) = (state.clone(), b.clone());
    eventually("filed in B's queue", move || queued_len(&st, &bb) == 1).await;
    let acked = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        acked
            .iter()
            .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))),
        "B fully offline: filed and acknowledged"
    );
    sweep_stale_state(t0, &state);
    sweep_stale_state(t0 + circuits::PAIR_ORPHAN_TTL, &state);
    assert_eq!(state.blind_pair_circuits.len(), 1, "kept inside the TTL");
    let _ = frames_until_quiet(&mut wa, QUIET).await;
    sweep_stale_state(
        t0 + circuits::PAIR_ORPHAN_TTL + Duration::from_secs(2),
        &state,
    );
    assert!(state.blind_pair_circuits.is_empty(), "torn down at the TTL");
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        fa.iter().any(|f| matches!(
            f,
            UnifiedFrame::Control(ControlMessage::CircuitClosed {
                reason: CircuitCloseReason::Normal,
                ..
            })
        )),
        "the live peer is told"
    );
    assert!(state.circuit_counts.is_empty(), "counts released");
    assert_no_trace_of_the_pair(&state, &a, &b, &sources, pair);
}

/// R15 (b) with the other member left online: the later asker (which
/// created the circuit pair and so holds it in its created-circuit set)
/// stays; after the TTL no trace of the pair remains on its connection.
#[tokio::test]
async fn after_the_ttl_the_remaining_creator_holds_no_trace_of_the_pair() {
    let (addr, state) = start(sourced_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (wa, mut wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    let sources = sources_of(&state, &[&a, &b]);
    let pair = (blind_tag(&token), [ca.circuit_id, cb.circuit_id]);
    let t0 = Instant::now();
    drop(wa);
    gone(&state, &a).await;
    sweep_stale_state(
        t0 + circuits::PAIR_ORPHAN_TTL + Duration::from_secs(2),
        &state,
    );
    assert!(state.blind_pair_circuits.is_empty());
    let _ = frames_until_quiet(&mut wb, QUIET).await;
    assert_no_trace_of_the_pair(&state, &a, &b, &sources, pair);
}

/// Rulings R15 (c) and R18: no D34 hand-over for blinded circuits. A packet
/// for a member that is back on a new connection is neither handed over
/// nor filed (it would wait for that member's next publish while showing
/// delivered): the row is torn down at once, both sides are told
/// `CircuitClosed`, and the sender gets `CircuitNotFound` naming the
/// circuit it sent on, never a `MessageAck`, so its core keeps the message
/// unacked and re-pairs (core test `ak4_circuit_not_found_marks_and_resends`).
#[tokio::test]
async fn a_packet_for_a_member_back_on_a_new_connection_ends_the_blinded_row() {
    let (addr, state) = start(sourced_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, ca, cb) = blind_pair(&state, addr, &a, &b, token).await;
    let sources = sources_of(&state, &[&a, &b]);
    let pair = (blind_tag(&token), [ca.circuit_id, cb.circuit_id]);
    // B's foreground connection (it has asked) is up before the old one
    // closes, and the old one's close-time teardown misses the token's
    // lock, so the row is still there when A's packet comes (final review
    // L1: only a connection that has asked counts as B being back).
    let mut wb2 = authed(addr, &b).await;
    blind_held(&mut wb2, &state, &b, rand::random(), [0xB3; 32]).await;
    let held = super::pair_lock::BLIND_LOCKS.lock(blind_tag(&token)).await;
    drop(wb);
    let st = state.clone();
    eventually("the old connection to go", move || {
        st.connections.len() == 2
    })
    .await;
    drop(held);
    assert_eq!(state.blind_pair_circuits.len(), 1, "the teardown missed");
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 64]))
        .await
        .unwrap();
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    assert!(
        !fa.iter()
            .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))),
        "never acknowledged: {fa:?}"
    );
    let expected = format!(
        "{}{}",
        rchat_core::protocol::CIRCUIT_NOT_FOUND_PREFIX,
        hex::encode(ca.target_circuit_id.as_ref())
    );
    assert!(
        fa.iter().any(|f| matches!(
            f,
            UnifiedFrame::Control(ControlMessage::Error {
                code: ControlErrorCode::CircuitNotFound,
                message,
            }) if *message == expected
        )),
        "CircuitNotFound naming the circuit A sent on: {fa:?}"
    );
    assert!(fa.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed { .. })
    )));
    assert!(state.blind_pair_circuits.is_empty(), "the row is gone");
    assert_eq!(queued_len(&state, &b), 0, "nothing filed for B");
    assert_eq!(
        queued(&frames_until_quiet(&mut wb2, QUIET).await),
        0,
        "nothing handed to B's new connection"
    );
    assert!(state.circuit_counts.is_empty());
    // B stays online on its new connection, so its routing slot remains;
    // nothing else of the pair does. (B's own held ask, for an unrelated
    // token, is no trace of this pair; it goes first so the scan below
    // looks at the pair's state only.)
    let tb = id_tag(&b.bytes);
    state.pending_asks.retain(|_, ask| ask.asker_tag != tb);
    assert_no_trace_of_the_pair(&state, &a, &b, &sources, pair);
}

/// A blinded circuit is never resumed (§C.3): a member that comes back
/// re-pairs under a new token, and the old row goes at the first sweep
/// that sees it back (0 s grace, ruling R18), not after
/// `PAIR_RESUME_GRACE` as for identity pairs.
#[tokio::test]
async fn a_member_back_online_loses_the_old_blinded_row_at_the_next_sweep() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let token = rand::random();
    let (mut wa, wb, _ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    drop(wb);
    gone(&state, &b).await;
    sweep_stale_state(Instant::now(), &state);
    assert_eq!(state.blind_pair_circuits.len(), 1, "B offline: kept");
    let mut wb2 = authed(addr, &b).await;
    sweep_stale_state(Instant::now(), &state);
    assert_eq!(
        state.blind_pair_circuits.len(),
        1,
        "published but not asked (a drain, final review L1): kept"
    );
    // Take the R21 entry out so the first ask's teardown misses and the
    // sweep is what ends the row.
    state.departed_blind.clear();
    blind_held(&mut wb2, &state, &b, rand::random(), [0xB3; 32]).await;
    assert_eq!(state.blind_pair_circuits.len(), 1);
    sweep_stale_state(Instant::now(), &state);
    assert!(state.blind_pair_circuits.is_empty(), "torn down at once");
    assert!(state.circuits.is_empty());
    let closed = frames_until_quiet(&mut wa, QUIET).await;
    assert!(closed.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed {
            reason: CircuitCloseReason::Normal,
            ..
        })
    )));
}

/// A member's `CloseCircuit` tears down the whole blinded pair; the other
/// member is told, a non-member is ignored.
#[tokio::test]
async fn a_member_close_tears_down_the_blinded_pair() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let token = rand::random();
    let (mut wa, mut wb, ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    let mut wc = authed(addr, &c).await;
    wc.send(FrameBuilder::close_circuit(ca.circuit_id).encode())
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wc, QUIET).await;
    assert_eq!(state.blind_pair_circuits.len(), 1, "non-member ignored");
    wa.send(FrameBuilder::close_circuit(ca.circuit_id).encode())
        .await
        .unwrap();
    let st = state.clone();
    eventually("the blinded pair to go", move || {
        st.blind_pair_circuits.is_empty() && st.circuits.is_empty()
    })
    .await;
    let fb = frames_until_quiet(&mut wb, QUIET).await;
    assert!(fb.iter().any(|f| matches!(
        f,
        UnifiedFrame::Control(ControlMessage::CircuitClosed { .. })
    )));
    assert!(state.circuit_counts.is_empty());
    let _ = frames_until_quiet(&mut wa, QUIET).await;
}

/// Blind asks count against their own per-connection cap (final review
/// M1), here one, and an identity ask against its own, also one.
#[tokio::test]
async fn blind_asks_count_against_the_pending_caps() {
    let mut config = test_config();
    config.max_pending_per_connection = 1;
    config.max_pending_blind_per_connection = Some(1);
    let (addr, state) = start(config).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let mut wa = authed(addr, &a).await;
    let token = rand::random();
    blind_held(&mut wa, &state, &a, token, [1; 32]).await;
    // A replay of the held token is free.
    blind_held(&mut wa, &state, &a, token, [2; 32]).await;
    // A second token is over the blind cap.
    wa.send(blind_ask(rand::random(), [3; 32])).await.unwrap();
    let frames = frames_until_quiet(&mut wa, QUIET).await;
    assert!(matches!(
        control_errors(&frames)[..],
        [ControlErrorCode::RateLimited]
    ));
    // An identity ask has its own share; a second one is over it.
    wa.send(ask(&b, [4; 32], None)).await.unwrap();
    let frames = frames_until_quiet(&mut wa, QUIET).await;
    assert!(control_errors(&frames).is_empty());
    wa.send(ask(&TestIdentity::random(), [5; 32], None))
        .await
        .unwrap();
    let frames = frames_until_quiet(&mut wa, QUIET).await;
    assert!(matches!(
        control_errors(&frames)[..],
        [ControlErrorCode::RateLimited]
    ));
    assert_eq!(state.pending_asks.len(), 2);
}

/// The global pending cap is shared by both kinds of ask.
#[tokio::test]
async fn blind_asks_share_the_global_pending_cap() {
    let mut config = test_config();
    config.max_pending_circuit_targets = 1;
    let (addr, state) = start(config).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    blind_held(&mut wa, &state, &a, rand::random(), [1; 32]).await;
    wb.send(ask(&c, [2; 32], None)).await.unwrap();
    let frames = frames_until_quiet(&mut wb, QUIET).await;
    assert!(matches!(
        control_errors(&frames)[..],
        [ControlErrorCode::RateLimited]
    ));
    assert_eq!(state.pending_asks.len(), 1);
}

/// Accepted asks are counted, with no identifier in any label.
#[tokio::test]
async fn accepted_blind_asks_are_counted() {
    let before = metrics::BLIND_ASKS_ACCEPTED.get();
    let (addr, state) = start(test_config()).await;
    let a = TestIdentity::random();
    let mut wa = authed(addr, &a).await;
    blind_held(&mut wa, &state, &a, rand::random(), [1; 32]).await;
    assert!(metrics::BLIND_ASKS_ACCEPTED.get() > before);
}

// ------------------------------------------------------------- logs

/// R6 over a blinded scenario under a TRACE capture: no log line carries
/// two identity-derived values, with the `BlindTag` counted as
/// pair-derived.
#[tokio::test]
async fn no_log_line_links_two_identity_values_in_a_blinded_scenario() {
    use super::log_privacy_tests::{capture_trace, identity_needles, SCENARIO_LOCK};
    let _serial = SCENARIO_LOCK.lock().await;
    let capture = capture_trace(tracing::Level::TRACE);

    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::from_seed(0xD1),
        TestIdentity::from_seed(0xD2),
        TestIdentity::from_seed(0xD3),
    );
    let token = [0x7B; 32];
    let (mut wa, wb, ca, _cb) = blind_pair(&state, addr, &a, &b, token).await;
    // Busy, replay, unproven, relay, offline queue, close and sweep.
    let mut wc = authed(addr, &c).await;
    wc.send(blind_ask(token, [0xC3; 32])).await.unwrap();
    let _ = frames_until_quiet(&mut wc, QUIET).await;
    let other = [0x7C; 32];
    blind_held(&mut wc, &state, &c, other, [0xC4; 32]).await;
    blind_held(&mut wc, &state, &c, other, [0xC5; 32]).await;
    let mut anon = connect(addr).await;
    let _ = hello(&mut anon).await;
    anon.send(blind_ask(other, [9; 32])).await.unwrap();
    let _ = frames_until_quiet(&mut anon, QUIET).await;
    drop(wb);
    gone(&state, &b).await;
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 64]))
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wa, QUIET).await;
    wa.send(FrameBuilder::close_circuit(ca.circuit_id).encode())
        .await
        .unwrap();
    let _ = frames_until_quiet(&mut wa, QUIET).await;
    sweep_stale_state(Instant::now() + Duration::from_secs(600), &state);
    // R21: a member back on a new connection ends its departed row at its
    // first ask (final review L1).
    let (e, f) = (TestIdentity::from_seed(0xD4), TestIdentity::from_seed(0xD5));
    let token3 = [0x7D; 32];
    let (_we, wf, _ce, _cf) = blind_pair(&state, addr, &e, &f, token3).await;
    drop(wf);
    gone(&state, &f).await;
    let tf = id_tag(&f.bytes);
    let st = state.clone();
    eventually("F's circuit indexed", move || {
        st.departed_blind.contains_key(&tf)
    })
    .await;
    let mut wf2 = authed(addr, &f).await;
    wf2.send(blind_ask([0x7E; 32], [0xF2; 32])).await.unwrap();
    let st = state.clone();
    eventually("F's row ended at its first ask", move || {
        st.departed_blind.is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let logs = capture.text();
    for expected in [
        "Created circuit pair",
        "Blind ask refused: token busy",
        "Blind ask replaced by a newer one",
        "Circuit pair closed by a member",
        "Blinded pair torn down: its member published again",
    ] {
        assert!(
            logs.contains(expected),
            "{expected:?} not captured:\n{logs}"
        );
    }
    let ids = [a, b, c, e, f];
    let mut needles = identity_needles(&ids);
    needles.extend(ids.iter().map(|i| i.hex.clone()));
    for t in [token, other, token3] {
        let bt: BlindTag = blind_tag(&t);
        needles.push(hex::encode(bt.0));
        needles.push(crate::privacy::tag(bt.0));
        needles.push(hex::encode(t));
        needles.push(crate::privacy::tag(t));
    }
    super::circuits::assert_r6(&logs, &needles);
}

// ------------------------------------------------------------- replay accounting (R17 M2)

/// A replay from another connection of the same identity moves the
/// per-connection charge to the new connection.
#[tokio::test]
async fn a_replay_from_another_connection_moves_the_charge() {
    let (addr, state) = start(test_config()).await;
    let a = TestIdentity::random();
    let token = rand::random();
    let tag = blind_tag(&token);
    let mut wa1 = authed(addr, &a).await;
    blind_held(&mut wa1, &state, &a, token, [1; 32]).await;
    let c1 = mapped_client(&state, &a).unwrap();
    let mut wa2 = authed(addr, &a).await;
    let c2 = mapped_client(&state, &a).unwrap();
    assert_ne!(c1, c2);
    let charged = |c: ClientId| {
        state.connections.get(&c).is_some_and(|conn| {
            conn.pending_charges
                .iter()
                .any(|(k, _)| *k == ChargeKey::Blind(tag))
        })
    };
    assert!(charged(c1) && !charged(c2));
    blind_held(&mut wa2, &state, &a, token, [2; 32]).await;
    assert!(!charged(c1), "the old connection's charge is gone");
    assert!(charged(c2), "the new connection is charged");
}

/// A replay from another source re-books the source share; over the new
/// source's share it is refused and the held ask stays as it was.
#[tokio::test]
async fn a_replay_from_another_source_re_books_the_share() {
    let mut config = test_config();
    config.max_pending_blind_per_source = Some(1);
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    let (a, c) = (TestIdentity::random(), TestIdentity::random());
    let (s1, s2) = (source_key(1), source_key(2));
    let (a1, _rx1) = proven_bare(&state, &a, Some(s1));
    let (a2, _rx2) = proven_bare(&state, &a, Some(s2));
    let token: [u8; 32] = rand::random();
    let ask = |who, ek: [u8; 32], token: [u8; 32]| {
        circuits::handle_circuit_ask_blind(who, token, ek, kem_for(ek), &state)
    };
    ask(a1, [1; 32], token).await;
    assert_eq!(
        (
            state.pending_asks.source_count(&s1),
            state.pending_asks.source_count(&s2)
        ),
        (1, 0)
    );
    ask(a2, [2; 32], token).await;
    assert_eq!(
        (
            state.pending_asks.source_count(&s1),
            state.pending_asks.source_count(&s2)
        ),
        (0, 1),
        "the share moved to the replay's source"
    );
    assert_eq!(held(&state, token), Some((a2, [2; 32])));

    // s1 is now full with another identity's ask: a replay from s1 is
    // refused and the held ask (from s2) stays.
    let (c1, _rxc) = proven_bare(&state, &c, Some(s1));
    ask(c1, [9; 32], rand::random()).await;
    assert_eq!(state.pending_asks.source_count(&s1), 1);
    ask(a1, [3; 32], token).await;
    assert_eq!(
        held(&state, token),
        Some((a2, [2; 32])),
        "held ask unchanged"
    );
    assert_eq!(
        (
            state.pending_asks.source_count(&s1),
            state.pending_asks.source_count(&s2)
        ),
        (1, 1)
    );
    assert_eq!(state.pending_asks.len(), 2);
}

// ------------------------------------------------------------- concurrency (R17 M5)

/// Two identities asking one token at the same instant form exactly one
/// pair, and each side gets exactly one `CircuitCreatedV3`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_asks_on_one_token_form_exactly_one_pair() {
    for _ in 0..25 {
        let server = Server::new(test_config()).await.unwrap();
        let state = server.state();
        let (a, b) = (TestIdentity::random(), TestIdentity::random());
        let (ca, mut rxa) = proven_bare(&state, &a, None);
        let (cb, mut rxb) = proven_bare(&state, &b, None);
        let token: [u8; 32] = rand::random();
        let (sa, sb) = (state.clone(), state.clone());
        let ta = tokio::spawn(async move {
            circuits::handle_circuit_ask_blind(ca, token, [1; 32], kem_for([1; 32]), &sa).await
        });
        let tb = tokio::spawn(async move {
            circuits::handle_circuit_ask_blind(cb, token, [2; 32], kem_for([2; 32]), &sb).await
        });
        let (ra, rb) = tokio::join!(ta, tb);
        ra.unwrap();
        rb.unwrap();
        assert_eq!(state.blind_pair_circuits.len(), 1);
        assert_eq!(state.circuits.len(), 2);
        assert!(state.pending_asks.is_empty());
        let count = |rx: &mut tokio::sync::mpsc::Receiver<crate::limits::Outbound>| {
            let mut n = 0;
            while let Ok((m, _)) = rx.try_recv() {
                if let Ok(UnifiedFrame::Control(ControlMessage::CircuitCreatedV3 { .. })) =
                    UnifiedFrame::decode(&m)
                {
                    n += 1;
                }
            }
            n
        };
        assert_eq!((count(&mut rxa), count(&mut rxb)), (1, 1));
    }
}

/// Deadlock and panic stress test (not a detector for `forget_if_gone`, whose
/// window it cannot reliably hit; see
/// `a_blind_ask_inserted_as_its_connection_closes_is_dropped`): a blind ask
/// racing its connection's disconnect on a multi-thread runtime finishes,
/// and leaves no held ask behind for the gone connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blind_ask_racing_a_disconnect_leaves_no_ask_behind() {
    for i in 0..50u32 {
        let server = Server::new(test_config()).await.unwrap();
        let state = server.state();
        let a = TestIdentity::random();
        let (ca, _rx) = proven_bare(&state, &a, None);
        let token: [u8; 32] = rand::random();
        let sa = state.clone();
        let ask = tokio::spawn(async move {
            circuits::handle_circuit_ask_blind(ca, token, [1; 32], kem_for([1; 32]), &sa).await
        });
        let sd = state.clone();
        let leave = tokio::spawn(async move {
            if i % 2 == 0 {
                tokio::task::yield_now().await;
            }
            if let Some((_, conn)) = sd.connections.remove(&ca) {
                circuits::on_disconnect(ca, &conn, &sd, Instant::now());
            }
        });
        let (r1, r2) = tokio::join!(ask, leave);
        r1.unwrap();
        r2.unwrap();
        assert!(
            !state.pending_asks.iter().any(|e| e.asker == ca),
            "iteration {i}: an ask outlived its connection"
        );
    }
}

/// The race made deterministic with a hook: the connection closes (and its
/// asks are dropped) right before the ask is inserted, for a new ask and
/// for a replay. No held ask may outlive the connection.
#[tokio::test]
async fn a_blind_ask_inserted_as_its_connection_closes_is_dropped() {
    for replay in [false, true] {
        let server = Server::new(test_config()).await.unwrap();
        let state = server.state();
        let a = TestIdentity::random();
        let (ca, _rx) = proven_bare(&state, &a, None);
        let token: [u8; 32] = rand::random();
        if replay {
            circuits::handle_circuit_ask_blind(ca, token, [1; 32], kem_for([1; 32]), &state).await;
            assert_eq!(state.pending_asks.len(), 1);
        }
        let st = state.clone();
        circuits::tests_hook::set_before_blind_insert(move || {
            if let Some((_, conn)) = st.connections.remove(&ca) {
                circuits::on_disconnect(ca, &conn, &st, Instant::now());
            }
        });
        circuits::handle_circuit_ask_blind(ca, token, [2; 32], kem_for([2; 32]), &state).await;
        assert!(!state.connections.contains_key(&ca), "the hook ran");
        assert!(
            state.pending_asks.is_empty(),
            "replay={replay}: an ask outlived its connection"
        );
    }
}

// ------------------------------------------------- M1: many contacts

/// A distinct X25519 ephemeral per (side, contact, ask).
fn ek_of(side: u8, i: usize, k: usize) -> [u8; 32] {
    let mut e = [side; 32];
    e[0] = i as u8;
    e[1] = k as u8;
    e
}

/// Final review M1: blind asks are charged against their own per-connection
/// cap (`max_pending_blind_per_connection`, default 1024), not the 32 of
/// identity asks. A core holds about four blind asks per offline contact
/// (the current and previous 10-minute slot, each with its ±1 window
/// sibling). Two users with 64 offline contacts each hold all 256 of
/// theirs; when the 64 come online and ask back, all 128 pairs form.
#[tokio::test]
async fn sixty_four_contacts_on_both_sides_all_hold_blind_asks_and_pair() {
    // All 256 at once, faster than the core paces them: the new-token
    // bucket (N-1 (a), tested on its own below) is opened up here.
    let mut config = sourced_config();
    config.blind_ask_burst = 1024;
    let (addr, state) = start(config).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let contacts: Vec<TestIdentity> = (0..64).map(|_| TestIdentity::random()).collect();
    let ta: Vec<[[u8; 32]; 4]> = (0..64).map(|_| rand::random()).collect();
    let tb: Vec<[[u8; 32]; 4]> = (0..64).map(|_| rand::random()).collect();
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    for i in 0..64 {
        for k in 0..4 {
            wa.send(blind_ask(ta[i][k], ek_of(0xA0, i, k)))
                .await
                .unwrap();
            wb.send(blind_ask(tb[i][k], ek_of(0xB0, i, k)))
                .await
                .unwrap();
        }
    }
    let st = state.clone();
    eventually_within(
        "all 512 blind asks held",
        Duration::from_secs(20),
        move || st.pending_asks.len() == 512,
    )
    .await;
    assert!(control_errors(&frames_until_quiet(&mut wa, QUIET).await).is_empty());
    assert!(control_errors(&frames_until_quiet(&mut wb, QUIET).await).is_empty());

    let mut wc = Vec::new();
    for (i, c) in contacts.iter().enumerate() {
        let mut w = authed(addr, c).await;
        w.send(blind_ask(ta[i][0], ek_of(0xC0, i, 0)))
            .await
            .unwrap();
        w.send(blind_ask(tb[i][2], ek_of(0xC0, i, 2)))
            .await
            .unwrap();
        wc.push(w);
    }
    let fa = frames_until_quiet(&mut wa, QUIET).await;
    let fb = frames_until_quiet(&mut wb, QUIET).await;
    assert_eq!(created_v3(&fa).len(), 64, "A paired with every contact");
    assert_eq!(created_v3(&fb).len(), 64, "B paired with every contact");
    for w in wc.iter_mut() {
        let f = frames_until_quiet(w, QUIET).await;
        assert_eq!(created_v3(&f).len(), 2, "each contact paired with A and B");
    }
    assert_eq!(state.blind_pair_circuits.len(), 128);
}

/// M1: the identity-ask cap is unchanged and separate: blind asks never use
/// up a connection's identity share (the identity fallback stays on it),
/// and identity asks never use up its blind share.
#[tokio::test]
async fn blind_and_identity_asks_have_separate_connection_caps() {
    let mut config = test_config();
    config.max_pending_per_connection = 1;
    config.max_pending_blind_per_connection = Some(2);
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let (a1, _rx) = proven_bare(&state, &a, None);
    let blind = |ek: [u8; 32]| {
        circuits::handle_circuit_ask_blind(a1, rand::random(), ek, kem_for(ek), &state)
    };
    blind([1; 32]).await;
    blind([2; 32]).await;
    assert_eq!(state.pending_asks.len(), 2);
    blind([3; 32]).await;
    assert_eq!(state.pending_asks.len(), 2, "third blind ask over its cap");
    ask_direct(&state, a1, &b).await;
    assert_eq!(
        state.pending_asks.len(),
        3,
        "identity ask has its own share"
    );
    ask_direct(&state, a1, &c).await;
    assert_eq!(
        state.pending_asks.len(),
        3,
        "second identity ask over its cap"
    );
}

/// M1, carrier-grade NAT: blind asks have their own per-source share
/// (`max_pending_blind_per_source`), so many users behind one address can
/// hold blind asks beyond the identity-ask share, and blind asks never
/// crowd that address's identity (first contact, fallback) asks out.
#[tokio::test]
async fn blind_asks_have_their_own_per_source_share() {
    let mut config = test_config();
    config.max_pending_per_source = 2;
    config.max_pending_blind_per_source = Some(4);
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    let s = source_key(1);
    let ids: Vec<TestIdentity> = (0..6).map(|_| TestIdentity::random()).collect();
    let (a1, _rxa) = proven_bare(&state, &ids[0], Some(s));
    let (c1, _rxc) = proven_bare(&state, &ids[1], Some(s));
    for i in 0..4u8 {
        circuits::handle_circuit_ask_blind(a1, rand::random(), [i; 32], kem_for([i; 32]), &state)
            .await;
    }
    assert_eq!(
        state.pending_asks.len(),
        4,
        "blind asks beyond the identity share"
    );
    circuits::handle_circuit_ask_blind(c1, rand::random(), [9; 32], kem_for([9; 32]), &state).await;
    assert_eq!(state.pending_asks.len(), 4, "the blind share is full");
    ask_direct(&state, c1, &ids[2]).await;
    ask_direct(&state, c1, &ids[3]).await;
    assert_eq!(
        state.pending_asks.len(),
        6,
        "identity asks keep their share"
    );
    let (d1, _rxd) = proven_bare(&state, &ids[4], Some(s));
    ask_direct(&state, d1, &ids[5]).await;
    assert_eq!(state.pending_asks.len(), 6, "the identity share is full");
}

// ------------------------------------- final re-review N-1, N-2

/// `RateLimited` errors waiting in a bare connection's queue. Each is an
/// ask refusal as the core classifies it (final re-review N-3): never
/// mistaken for the offline queue's refusal of a packet.
fn rate_limited(rx: &mut tokio::sync::mpsc::Receiver<crate::limits::Outbound>) -> usize {
    let mut n = 0;
    while let Ok((m, _)) = rx.try_recv() {
        if let Ok(UnifiedFrame::Control(ControlMessage::Error {
            code: ControlErrorCode::RateLimited,
            message,
        })) = UnifiedFrame::decode(&m)
        {
            assert!(
                !rchat_core::protocol::is_offline_queue_refusal(&message),
                "an ask refusal read as a queue refusal: {message}"
            );
            n += 1;
        }
    }
    n
}

/// N-1 (a): new pair tokens are charged against a per-connection bucket
/// (burst `blind_ask_burst`, refill `blind_ask_refill_per_sec`); over it a
/// new token is refused with `RateLimited`, while a replay of a token the
/// connection already holds is free and never charged a second time.
#[tokio::test]
async fn the_new_token_bucket_refuses_over_rate_tags_but_not_replays() {
    let mut config = test_config();
    config.blind_ask_burst = 64;
    config.blind_ask_refill_per_sec = 2;
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    let a = TestIdentity::random();
    let (a1, mut rx) = proven_bare(&state, &a, None);
    let tokens: Vec<[u8; 32]> = (0..64).map(|_| rand::random()).collect();
    let rejected = metrics::rejections(metrics::REJECT_BLIND_ASK_RATE);
    for (i, t) in tokens.iter().enumerate() {
        circuits::handle_circuit_ask_blind(a1, *t, ek_of(1, i, 0), kem_for(ek_of(1, i, 0)), &state)
            .await;
    }
    assert_eq!(state.pending_asks.len(), 64, "the burst is held");
    assert_eq!(rate_limited(&mut rx), 0);
    // A 65th new token at once: refused.
    let extra: [u8; 32] = rand::random();
    circuits::handle_circuit_ask_blind(a1, extra, [0xE1; 32], kem_for([0xE1; 32]), &state).await;
    assert_eq!(state.pending_asks.len(), 64);
    assert_eq!(rate_limited(&mut rx), 1);
    assert!(metrics::rejections(metrics::REJECT_BLIND_ASK_RATE) > rejected);
    // Replays of every held token, with fresh ephemerals: all accepted and
    // none charged (the bucket is empty, so a charge would refuse it).
    for (i, t) in tokens.iter().enumerate() {
        circuits::handle_circuit_ask_blind(a1, *t, ek_of(2, i, 0), kem_for(ek_of(2, i, 0)), &state)
            .await;
    }
    assert_eq!(rate_limited(&mut rx), 0, "a replay is never charged");
    assert_eq!(state.pending_asks.len(), 64);
    for (i, t) in tokens.iter().enumerate() {
        let held = state.pending_asks.get_blind(&blind_tag(t)).unwrap();
        assert_eq!(
            held.ephemeral,
            ek_of(2, i, 0),
            "the replay replaced the ask"
        );
    }
    // A held ask evicted from a full table (its connection keeps the
    // token's charge): asking under that token again is not a new token,
    // so it is not charged either.
    state.pending_asks.remove_blind(&blind_tag(&tokens[0]));
    circuits::handle_circuit_ask_blind(a1, tokens[0], [0xE0; 32], kem_for([0xE0; 32]), &state)
        .await;
    assert_eq!(
        rate_limited(&mut rx),
        0,
        "a re-ask of a charged token is free"
    );
    assert!(state
        .pending_asks
        .get_blind(&blind_tag(&tokens[0]))
        .is_some());
    // The bucket refills at its rate: one new token after ~0.5 s, not two.
    tokio::time::sleep(Duration::from_millis(600)).await;
    circuits::handle_circuit_ask_blind(a1, extra, [0xE2; 32], kem_for([0xE2; 32]), &state).await;
    circuits::handle_circuit_ask_blind(a1, rand::random(), [0xE3; 32], kem_for([0xE3; 32]), &state)
        .await;
    assert_eq!(state.pending_asks.len(), 65);
    assert_eq!(rate_limited(&mut rx), 1);
    state.pending_asks.assert_index_consistent();
}

/// N-1 (c), end to end through the handlers and without per-source
/// accounting (a layer-4 front end, no `proxy_protocol`): connections
/// filling the blind share are refused past it, and identity asks
/// (first contact, the identity fallback) still get the reserved quarter.
#[tokio::test]
async fn identity_asks_still_admit_when_blind_asks_fill_their_share() {
    let mut config = test_config();
    config.max_pending_circuit_targets = 40;
    config.max_pending_per_connection = 40;
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    assert_eq!(state.config.pending_blind_table_cap(), 30);
    let ids: Vec<TestIdentity> = (0..4).map(|_| TestIdentity::random()).collect();
    let mut blind_rx = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let (c, rx) = proven_bare(&state, id, None);
        for i in 0..10 {
            circuits::handle_circuit_ask_blind(
                c,
                rand::random(),
                ek_of(n as u8, i, 0),
                kem_for(ek_of(n as u8, i, 0)),
                &state,
            )
            .await;
        }
        blind_rx.push(rx);
    }
    assert_eq!(
        state.pending_asks.len(),
        30,
        "blind asks stop at their share"
    );
    assert_eq!(blind_rx.iter_mut().map(rate_limited).sum::<usize>(), 10);
    let asker = TestIdentity::random();
    let (c, mut rx) = proven_bare(&state, &asker, None);
    for _ in 0..10 {
        ask_direct(&state, c, &TestIdentity::random()).await;
    }
    assert_eq!(rate_limited(&mut rx), 0, "the identity reserve is free");
    assert_eq!(state.pending_asks.len(), 40);
    state.pending_asks.assert_index_consistent();
}

/// N-2: every pending ask of a connection shares one copy of its bundle,
/// and the next publish starts a new one. Prints the per-ask memory before
/// (a bundle copy in each ask) and after.
#[tokio::test]
async fn pending_asks_share_their_connections_bundle() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let a = TestIdentity::random();
    let (a1, _rx) = proven_bare(&state, &a, None);
    for i in 0..3 {
        circuits::handle_circuit_ask_blind(
            a1,
            rand::random(),
            ek_of(7, i, 0),
            kem_for(ek_of(7, i, 0)),
            &state,
        )
        .await;
    }
    ask_direct(&state, a1, &TestIdentity::random()).await;
    let bundles: Vec<std::sync::Arc<PeerBundle>> = state
        .pending_asks
        .iter()
        .map(|e| e.asker_bundle.clone())
        .collect();
    assert_eq!(bundles.len(), 4);
    assert!(bundles
        .iter()
        .all(|b| std::sync::Arc::ptr_eq(b, &bundles[0])));
    // The connection's copy plus one per ask, plus the clones just taken.
    assert_eq!(std::sync::Arc::strong_count(&bundles[0]), 1 + 4 + 4);
    // A publish drops the connection's copy: the next ask makes a new one.
    state.connections.get_mut(&a1).unwrap().peer_bundle = None;
    circuits::handle_circuit_ask_blind(a1, rand::random(), [0x77; 32], kem_for([0x77; 32]), &state)
        .await;
    let newest = state
        .pending_asks
        .iter()
        .find(|e| e.ephemeral == [0x77; 32])
        .map(|e| e.asker_bundle.clone())
        .unwrap();
    assert!(!std::sync::Arc::ptr_eq(&newest, &bundles[0]));
    assert_eq!(*newest, *bundles[0], "the same verified bundle");

    let heap_bundle = bundles[0].identity_key.len()
        + bundles[0].identity_agreement_key.len()
        + bundles[0].kem_pk.len()
        + bundles[0].bundle_signature.len();
    let inline =
        std::mem::size_of::<circuits::PendingAsk>() + std::mem::size_of::<fair_share::AskKey>();
    let boxed = std::mem::size_of::<circuits::AskEphemerals>();
    let before = inline + boxed + heap_bundle + std::mem::size_of::<PeerBundle>()
        - std::mem::size_of::<std::sync::Arc<PeerBundle>>();
    // After: no bundle per ask; one index entry (age set) per ask.
    let index = std::mem::size_of::<(Instant, fair_share::AskKey)>();
    let after = inline + boxed + index;
    eprintln!(
        "per-ask memory (payload, excluding map overhead): before {before} B, after {after} B"
    );
    assert!(after * 10 < before * 6, "{after} vs {before}");
}

/// N-3, across the crates: the core tells the offline queue's refusal of a
/// packet from an ask refusal by the prefix it shares with the relay. Every
/// ask refusal text the relay sends is an ask refusal to the core, and the
/// queue's refusal (driven end to end in `unresumed_forward_tests`) is not.
#[test]
fn the_core_tells_ask_refusals_from_the_queue_refusal() {
    use rchat_core::protocol::{is_offline_queue_refusal, OFFLINE_QUEUE_FULL_PREFIX};
    assert!(!is_offline_queue_refusal(super::PENDING_REFUSAL_TEXT));
    assert!(!is_offline_queue_refusal(super::CIRCUIT_REFUSAL_TEXT));
    assert!(is_offline_queue_refusal(&format!(
        "{OFFLINE_QUEUE_FULL_PREFIX}message 01234567 not stored"
    )));
}
