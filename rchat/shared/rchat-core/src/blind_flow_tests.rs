//! Task 9: the client's blinded pairing flow (protocol v3 §C.1–C.4):
//! known contacts re-pair on every reconnect with a blind ask under the
//! next counter, the midnight neighbour-day retry, `PairTokenBusy` heals,
//! the identity fallback after `BLIND_TIMEOUT_FALLBACK` timeouts, and the
//! re-sealing of unacked messages under the newest session (R19).

use crate::blind::{BLIND_BUSY_CAP, IDENTITY_FALLBACK_AFTER_SECS};
use crate::pairing::{pair_slot, pair_token, utc_day, PairEpoch};
use crate::peers::ASK_TTL;
use crate::protocol::{CircuitId, ControlMessage, Frame};
use crate::status::StatusEvent;
use crate::test_support::*;
use crate::ClientInner;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;

/// A UTC day used by every test clock (an arbitrary day in 2024).
const DAY: u32 = 19_800;
/// Noon of `DAY`, far from either day boundary.
const NOON: u64 = DAY as u64 * 86_400 + 43_200;
/// The pair-token slot of `NOON` (R40-M3).
const NOON_SLOT: u32 = (NOON / 600) as u32;

/// An established pair with both clocks at `unix` (both epochs `(day, 0)`)
/// and a fake relay that knows both sides and routes the pair's circuits.
fn blind_pair_at(unix: u64) -> (Pair, FakeRelay) {
    let mut p = establish(0xA1, 0xB2);
    set_clock(&mut p.a, &p.pb.hex, unix);
    set_clock(&mut p.b, &p.pa.hex, unix);
    let mut relay = FakeRelay::default();
    relay.join(0, &p.pa.bundle);
    relay.join(1, &p.pb.bundle);
    // A owns C1 (B sends on it), B owns C2.
    relay.identity_pair(C1, 0, C2, 1);
    (p, relay)
}

fn blind_pair() -> (Pair, FakeRelay) {
    blind_pair_at(NOON)
}

fn set_clock(inner: &mut ClientInner, peer_hex: &str, unix: u64) {
    inner.pair_clock_override = Some(unix);
    if let Some(mut s) = inner.session_manager.get_mut(peer_hex) {
        s.pair_epoch = PairEpoch {
            day: utc_day(unix),
            counter: 0,
        };
    }
}

fn ps_of(inner: &ClientInner, peer_hex: &str) -> [u8; 32] {
    **inner
        .session_manager
        .get(peer_hex)
        .unwrap()
        .pair_secret
        .as_ref()
        .unwrap()
}

fn epoch_of(inner: &ClientInner, peer_hex: &str) -> PairEpoch {
    inner.session_manager.get(peer_hex).unwrap().pair_epoch
}

fn binding_of(inner: &ClientInner, peer_hex: &str) -> [u8; 32] {
    inner.session_manager.get(peer_hex).unwrap().session_binding
}

fn since_of(inner: &ClientInner, peer_hex: &str) -> Option<u64> {
    inner
        .session_manager
        .get(peer_hex)
        .unwrap()
        .blind_since_unix
}

/// The token of `(day, counter)` under the slot of `NOON`.
fn c(ps: &[u8; 32], day: u32, counter: u32) -> [u8; 32] {
    cs(ps, day, counter, NOON_SLOT)
}

/// The token of `(day, counter)` under `slot` (R40-M3).
fn cs(ps: &[u8; 32], day: u32, counter: u32, slot: u32) -> [u8; 32] {
    pair_token(ps, PairEpoch { day, counter }, slot)
}

fn tokens_of(relay: &FakeRelay, side: usize) -> Vec<[u8; 32]> {
    relay
        .blind_asks
        .iter()
        .filter(|(s, _)| *s == side)
        .map(|(_, t)| *t)
        .collect()
}

fn blind_tokens(sent: &[ControlMessage]) -> Vec<[u8; 32]> {
    sent.iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAskBlind { pair_token, .. } => {
                Some(pair_token.as_slice().try_into().unwrap())
            }
            _ => None,
        })
        .collect()
}

fn identity_asks(sent: &[ControlMessage]) -> usize {
    sent.iter()
        .filter(|m| matches!(m, ControlMessage::CircuitAsk { .. }))
        .count()
}

/// Both sides lose their connection (the relay sees both leave, so a
/// blinded row goes with no one left to tell, R15), then reconnect and
/// publish; the relay runs until quiet.
fn reconnect_both(p: &mut Pair, relay: &mut FakeRelay) {
    for side in [0, 1] {
        drop(relay.leave(side)); // both connections are gone
    }
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(p, relay);
}

fn run(p: &mut Pair, relay: &mut FakeRelay) {
    pump(
        relay,
        &mut [(&mut p.a, &mut p.a_rx), (&mut p.b, &mut p.b_rx)],
    );
}

/// The user-visible warnings a routine re-pair must never raise.
fn warnings(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<StatusEvent> {
    statuses(log)
        .into_iter()
        .filter(|s| {
            matches!(
                s,
                StatusEvent::PeerSessionReset { .. }
                    | StatusEvent::PeerUndelivered { .. }
                    | StatusEvent::ResendEligible { .. }
                    | StatusEvent::SessionReplaced { .. }
                    | StatusEvent::DecryptFailed { .. }
                    | StatusEvent::QueuedSendLost { .. }
            )
        })
        .collect()
}

fn messages_with(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>, body: &[u8]) -> usize {
    texts(log).iter().filter(|t| t.as_slice() == body).count()
}

fn rx_controls(rx: &mut Receiver<Vec<u8>>) -> Vec<ControlMessage> {
    sent_controls(rx)
}

/// After a session exists, a transport reconnect sends `CircuitAskBlind`
/// under `pair_token(PS, epoch, NOON_SLOT)`: never an identity `CircuitAsk`, never a
/// resume of the old circuit.
#[test]
fn known_contact_reconnect_uses_blind_ask() {
    let (mut p, _relay) = blind_pair();
    let ps = ps_of(&p.a, &p.pb.hex);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    let expected = pair_token(
        &ps,
        PairEpoch {
            day: DAY,
            counter: 0,
        },
        NOON_SLOT,
    );
    assert_eq!(blind_tokens(&sent), vec![expected]);
    assert_eq!(identity_asks(&sent), 0, "no identity ask, so no resume");
}

/// A blind ask has no target and no knock: an all-zero pad makes it the
/// size of an identity ask on the wire (§C.2).
#[test]
fn blind_ask_carries_no_knock() {
    let (mut p, _relay) = blind_pair();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let frames = drain(&mut p.a_rx);
    let blind: Vec<&Vec<u8>> = frames
        .iter()
        .filter(|f| {
            matches!(
                ControlMessage::decode(f),
                Some(ControlMessage::CircuitAskBlind { .. })
            )
        })
        .collect();
    assert_eq!(blind.len(), 1);
    assert_eq!(blind[0].len(), 1 + crate::protocol::ASK_WIRE_LEN);
    match ControlMessage::decode(blind[0]) {
        Some(ControlMessage::CircuitAskBlind { pad, .. }) => {
            assert_eq!(pad, vec![0; crate::protocol::BLIND_PAD_LEN]);
        }
        _ => unreachable!(),
    }
}

/// Both sides re-pair blind and both advance the counter after the match;
/// the pair secret is kept (R14), the session is new.
#[test]
fn epoch_advances_after_blind_match_on_both_sides() {
    let (mut p, mut relay) = blind_pair();
    let (ps_a, ps_b) = (ps_of(&p.a, &p.pb.hex), ps_of(&p.b, &p.pa.hex));
    assert_eq!(ps_a, ps_b);
    let (bind_a, bind_b) = (binding_of(&p.a, &p.pb.hex), binding_of(&p.b, &p.pa.hex));
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true)], "one blinded pair");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert_ne!(binding_of(&p.a, &p.pb.hex), bind_a, "a new session");
    assert_ne!(binding_of(&p.b, &p.pa.hex), bind_b, "a new session");
    assert_eq!(ps_of(&p.a, &p.pb.hex), ps_a, "PS kept on a blind install");
    assert_eq!(ps_of(&p.b, &p.pa.hex), ps_b, "PS kept on a blind install");
    let one = PairEpoch {
        day: DAY,
        counter: 1,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), one);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), one);
    // The next reconnect uses counter 1, and both move on to 2.
    relay.blind_asks.clear();
    reconnect_both(&mut p, &mut relay);
    let t1 = pair_token(&ps_a, one, NOON_SLOT);
    assert!(relay.blind_asks.iter().all(|(_, t)| *t == t1));
    assert_eq!(relay.blind_asks.len(), 2);
    let two = PairEpoch {
        day: DAY,
        counter: 2,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), two);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), two);
    assert!(relay.identity_asks.is_empty());
}

/// A blinded circuit is never resumed by id: reconnecting after a blind
/// match sends no identity ask (so no `resume_circuit`) at all.
#[test]
fn blinded_circuit_is_never_resumed() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    assert!(p.a.session_manager.get(&p.pb.hex).unwrap().blinded);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 0);
    assert_eq!(blind_tokens(&sent).len(), 1);
    assert_eq!(p.a.resume_circuit_for(&p.pb.hex), None);
}

/// Near midnight the own-day token goes first; when it does not match
/// within the ask TTL, one re-ask under the neighbouring day's counter-0
/// token, which is not counted as a timeout.
#[test]
fn near_midnight_retries_neighbour_day_once() {
    // A: 23:58 on DAY (its epoch (DAY, 0)). B: 00:02 on DAY + 1, so its
    // own-day token is (DAY + 1, 0).
    let end = (DAY as u64 + 1) * 86_400;
    let (mut p, mut relay) = blind_pair_at(end - 120);
    p.b.pair_clock_override = Some(end + 120);
    let ps = ps_of(&p.a, &p.pb.hex);
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    run(&mut p, &mut relay);
    // B asks later than A, so B's ask is still held when A's times out.
    for (_to, f) in relay.leave(1) {
        feed(&mut p.a, f);
    }
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert!(relay.pairs.is_empty(), "different days: no match yet");
    // R40-M3: each side's token is under its own clock's slot (A in the
    // day's last slot, B in the next day's first).
    let own_a = pair_token(
        &ps,
        PairEpoch {
            day: DAY,
            counter: 0,
        },
        pair_slot(end - 120),
    );
    let own_b = pair_token(
        &ps,
        PairEpoch {
            day: DAY + 1,
            counter: 0,
        },
        pair_slot(end + 120),
    );
    assert_eq!(relay.blind_asks, vec![(0, own_a), (1, own_b)]);
    // A's own-day ask runs out (the relay drops only A's); A's clock moved
    // on with it, into B's slot.
    relay.held_retain_side(1);
    p.a.pair_clock_override = Some(end - 120 + 601);
    p.a.fire_blind_timeouts(t0 + ASK_TTL + Duration::from_secs(1));
    run(&mut p, &mut relay);
    assert_eq!(relay.blind_asks[2], (0, own_b), "neighbour day, counter 0");
    assert_eq!(relay.pairs, vec![(1, 0, true)], "matched B's held ask");
    assert!(relay.identity_asks.is_empty(), "never the identity path");
    // Both advance from the matched epoch (DAY + 1, 0).
    let next = PairEpoch {
        day: DAY + 1,
        counter: 1,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), next);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), next);
}

/// The neighbour re-ask is made once: when it times out too, the ±1 window
/// follows (own and own + 1 together), then a plain own ask, with no second
/// neighbour retry for the same boundary and never an identity ask.
#[test]
fn neighbour_retry_is_bounded_to_one() {
    let end = (DAY as u64 + 1) * 86_400;
    let (mut p, mut relay) = blind_pair_at(end - 120);
    let ps = ps_of(&p.a, &p.pb.hex);
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    run(&mut p, &mut relay);
    for k in 1..=3u32 {
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + ASK_TTL * k + Duration::from_secs(k as u64));
        run(&mut p, &mut relay);
    }
    // A's clock stays in the day's last slot here (R40-M3).
    let s = pair_slot(end - 120);
    assert_eq!(
        tokens_of(&relay, 0),
        vec![
            cs(&ps, DAY, 0, s),
            cs(&ps, DAY + 1, 0, s),
            cs(&ps, DAY, 0, s),
            cs(&ps, DAY, 1, s),
            cs(&ps, DAY, 0, s)
        ]
    );
    assert!(relay.identity_asks.is_empty());
}

/// R20: one side's counter is behind by one. After one timeout both hold
/// the ±1 window, the two windows meet on the shared token, and the pair
/// heals blind within one TTL: no identity ask, no warning.
#[test]
fn desynced_by_one_heals_blind_within_one_ttl() {
    let (mut p, mut relay) = blind_pair();
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pair_epoch
        .counter = 1;
    let ps = ps_of(&p.a, &p.pb.hex);
    let t0 = Instant::now();
    reconnect_both(&mut p, &mut relay);
    assert!(relay.pairs.is_empty(), "one apart: no match yet");
    relay.expire_asks();
    let at = t0 + ASK_TTL + Duration::from_secs(1);
    p.a.fire_blind_timeouts(at);
    p.b.fire_blind_timeouts(at);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true)], "the windows met");
    assert!(tokens_of(&relay, 0).contains(&c(&ps, DAY, 1)));
    assert!(relay.identity_asks.is_empty());
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    let two = PairEpoch {
        day: DAY,
        counter: 2,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), two);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), two);
    assert_eq!(ps_of(&p.a, &p.pb.hex), ps, "PS kept");
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
    // The next reconnect pairs blind at once under counter 2.
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 2);
    assert!(relay.identity_asks.is_empty());
}

/// Advance both clocks and fire both sides' timeouts, `k` TTLs (plus `k`
/// seconds) after `t0` and `base`.
fn tick_both(p: &mut Pair, relay: &mut FakeRelay, t0: Instant, base: u64, k: u32) {
    let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
    p.a.pair_clock_override = Some(base + secs);
    p.b.pair_clock_override = Some(base + secs);
    relay.expire_asks();
    let at = t0 + Duration::from_secs(secs);
    p.a.fire_blind_timeouts(at);
    p.b.fire_blind_timeouts(at);
    run(p, relay);
}

/// R20: counters two or more apart are not met by the ±1 window, but the
/// day change resets both to `(day, 0)`: the pair heals blind at the next
/// UTC midnight, well within the 24 h fallback clock.
#[test]
fn desynced_by_two_heals_blind_at_the_day_change() {
    let (mut p, mut relay) = blind_pair();
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pair_epoch
        .counter = 2;
    let t0 = Instant::now();
    reconnect_both(&mut p, &mut relay);
    let mut k = 0;
    while relay.pairs.is_empty() {
        k += 1;
        assert!(k <= 80, "healed by the day change");
        tick_both(&mut p, &mut relay, t0, NOON, k);
    }
    assert!(u64::from(k) * 601 >= 43_200, "not before midnight");
    assert!(relay.pairs[0].2, "blind");
    assert!(relay.identity_asks.is_empty());
}

/// R20: a desync no window or day change heals (here the peer holds
/// another pair secret, as after a lost session-init over an older
/// session) goes to the identity path only after 24 h of unmatched blind
/// asking, once; the pair then resets to a new PS and `(day, 0)`. Every
/// identity fallback raises `SessionReplaced` on both sides (I-2): on the
/// receiving side it is the genuine seed-thief signal, so it is not
/// suppressed; R20 makes the fallback rare. Nothing else is raised.
#[test]
fn unhealable_desync_heals_via_identity_after_24h_then_resets() {
    let (mut p, mut relay) = blind_pair();
    p.b.session_manager.get_mut(&p.pa.hex).unwrap().pair_secret =
        Some(zeroize::Zeroizing::new([9; 32]));
    let ps_before = ps_of(&p.a, &p.pb.hex);
    let t0 = Instant::now();
    reconnect_both(&mut p, &mut relay);
    let mut k = 0;
    while relay.identity_asks.is_empty() {
        k += 1;
        assert!(k <= 150);
        assert!(relay.pairs.is_empty());
        tick_both(&mut p, &mut relay, t0, NOON, k);
    }
    let elapsed = u64::from(k) * 601;
    assert!(
        (IDENTITY_FALLBACK_AFTER_SECS..IDENTITY_FALLBACK_AFTER_SECS + 601).contains(&elapsed),
        "first identity ask once 24 h passed: {elapsed}"
    );
    assert_eq!(relay.identity_asks.len(), 2, "one per side");
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 1);
    assert!(!relay.pairs[0].2, "an identity pair");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    let (ps_a, ps_b) = (ps_of(&p.a, &p.pb.hex), ps_of(&p.b, &p.pa.hex));
    assert_eq!(ps_a, ps_b);
    assert_ne!(ps_a, ps_before, "a new PS from the new SK");
    let today = utc_day(NOON + elapsed);
    let zero = PairEpoch {
        day: today,
        counter: 0,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), zero);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), zero);
    assert_eq!(since_of(&p.a, &p.pb.hex), None, "clock reset at install");
    for (log, peer) in [(&p.a_log, &p.pb.hex), (&p.b_log, &p.pa.hex)] {
        assert_eq!(
            warnings(log),
            vec![StatusEvent::SessionReplaced { peer: peer.clone() }],
            "the identity fallback raises SessionReplaced, nothing else"
        );
        assert!(
            !log.lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, Ev::Request(_))),
            "a contact's knock is no message request"
        );
    }
    // The next reconnect is blind again, under the new PS.
    relay.blind_asks.clear();
    reconnect_both(&mut p, &mut relay);
    assert!(relay
        .blind_asks
        .iter()
        .all(|(_, t)| *t == pair_token(&ps_a, zero, pair_slot(NOON + elapsed))));
    assert!(relay.pairs.last().unwrap().2, "a blinded pair");
}

/// R20: a contact that is simply away (offline for days of our online
/// time) never causes an identity ask within 24 h of blind asking; then at
/// most one per 24 h, and when it runs out unmatched the pair goes back to
/// blind with its clock restarted.
#[test]
fn absent_contact_never_causes_an_identity_ask_within_24h() {
    let (mut p, mut relay) = blind_pair();
    drop(relay.leave(1)); // B is gone and stays gone
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    let mut identity_at = Vec::new();
    for k in 1..=300u32 {
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        let before = relay.identity_asks.len();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
        if relay.identity_asks.len() > before {
            identity_at.push(secs);
            if identity_at.len() == 1 {
                // The connection drops while that ask is out: the next
                // one still waits a full interval.
                reconnect_in_place(&mut p.a, &mut p.a_rx);
                pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
            }
        }
    }
    assert_eq!(
        identity_at.len(),
        2,
        "one per day over two days: {identity_at:?}"
    );
    assert!(
        identity_at[0] >= IDENTITY_FALLBACK_AFTER_SECS,
        "never within 24 h"
    );
    assert!(
        identity_at[1] - identity_at[0] >= IDENTITY_FALLBACK_AFTER_SECS,
        "at most one per 24 h"
    );
    // Between and after them it kept asking blind.
    assert!(relay.blind_asks.len() > 250);
    assert!(relay.pairs.is_empty());
}

/// No session: the identity path.
#[test]
fn first_contact_uses_identity_path() {
    let (mut a, mut rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    a.ask(&b.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let sent = sent_controls(&mut rx);
    assert_eq!(identity_asks(&sent), 1);
    assert!(blind_tokens(&sent).is_empty());
}

/// After our own key rotation a contact not yet reached under the new
/// identity is asked on the identity path (its knock carries the chain).
#[test]
fn after_rotation_uses_identity_path() {
    let (mut p, _relay) = blind_pair();
    let new_me = peer(0xA9);
    p.a.rotation_block = Some(crate::rotation::RotationBlock {
        current_version: 1,
        links: vec![crate::rotation::sign_link(
            &p.pa.id,
            &new_me.bundle.identity_key,
            &new_me.bundle.identity_agreement_key,
            1,
        )],
    });
    p.a.rotation_unreached.insert(p.pb.hex.clone());
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert!(
        blind_tokens(&sent).is_empty(),
        "never blind while unreached"
    );
    assert!(identity_asks(&sent) >= 1);
}

/// A routine re-pair replaces the ratchet but raises none of the §18
/// recovery warnings; the unacked message is re-sealed under the new
/// session and shown exactly once.
#[test]
fn reconnect_repair_never_raises_peer_session_reset() {
    let (mut p, mut relay) = blind_pair();
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0across the reconnect")
        .unwrap();
    drain(&mut p.a_rx); // lost with the old connection
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true)]);
    assert_eq!(messages_with(&p.b_log, b"across the reconnect"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
    // The relay acked the re-sealed copy: nothing left to re-send.
    assert_eq!(p.a.acks.lock().unwrap().len(), 0);
    // Again, with B's receipt and A's notice in flight: still nothing.
    reconnect_both(&mut p, &mut relay);
    assert_eq!(messages_with(&p.b_log, b"across the reconnect"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// R19: two re-pairs before delivery (B keeps one retired session only):
/// the message is re-sealed under the newest session, decrypted and shown
/// exactly once.
#[test]
fn double_reconnect_before_delivery_delivers_once() {
    let (mut p, mut relay) = blind_pair();
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0twice reconnected")
        .unwrap();
    let original = sent_relays(&mut p.a_rx).remove(0);
    // First re-pair: A's re-sealed copy is lost too.
    relay.drop_ids.insert(id);
    reconnect_both(&mut p, &mut relay);
    relay.drop_ids.clear();
    assert_eq!(relay.pairs.len(), 1);
    assert_eq!(messages_with(&p.b_log, b"twice reconnected"), 0);
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 2);
    assert_eq!(messages_with(&p.b_log, b"twice reconnected"), 1);
    // The original ciphertext arrives late: a duplicate, dropped unseen.
    feed(&mut p.b, queued(original.payload));
    assert_eq!(messages_with(&p.b_log, b"twice reconnected"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// R19: after one re-pair the original ciphertext (under the now retired
/// session) arrives late, after the re-sealed copy: shown once.
#[test]
fn late_original_after_resealed_copy_is_not_shown_twice() {
    let (mut p, mut relay) = blind_pair();
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0late original")
        .unwrap();
    let original = sent_relays(&mut p.a_rx).remove(0);
    reconnect_both(&mut p, &mut relay);
    assert_eq!(messages_with(&p.b_log, b"late original"), 1);
    feed(&mut p.b, queued(original.payload));
    assert_eq!(messages_with(&p.b_log, b"late original"), 1);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// R16: `PairTokenBusy` means the token is spent: advance the counter and
/// re-ask at once under the next token. Not a timeout.
#[test]
fn pair_token_busy_advances_and_reasks_without_counting() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    // B lost its CircuitCreatedV3: simulated by putting B back on the old
    // epoch, so its re-ask names the token the pair already spent.
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pair_epoch
        .counter = 0;
    let ps = ps_of(&p.b, &p.pa.hex);
    // B's circuit is gone on its side only.
    let b_circuit =
        p.b.session_manager
            .get(&p.pa.hex)
            .unwrap()
            .circuit_id
            .clone()
            .unwrap();
    p.b.handle_circuit_closed(b_circuit);
    let later = Instant::now() + Duration::from_secs(5);
    p.b.fire_due_reasks(later);
    run(&mut p, &mut relay);
    assert_eq!(relay.busy, vec![1], "the spent token is busy");
    // The torn-down row told A too: A re-asks under its counter 1.
    p.a.fire_due_reasks(later);
    run(&mut p, &mut relay);
    let b_tokens: Vec<[u8; 32]> = relay
        .blind_asks
        .iter()
        .filter(|(s, _)| *s == 1)
        .map(|(_, t)| *t)
        .collect();
    let c = |n| {
        pair_token(
            &ps,
            PairEpoch {
                day: DAY,
                counter: n,
            },
            NOON_SLOT,
        )
    };
    // The re-ask under counter 0 tore the row down (B was its slot), A
    // re-asked under counter 1, and B's busy-driven re-ask matched it.
    assert_eq!(b_tokens[b_tokens.len() - 2..], [c(0), c(1)]);
    assert_eq!(relay.pairs.len(), 2);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(
        relay.identity_asks.is_empty(),
        "busy never leads to identity"
    );
    assert_eq!(epoch_of(&p.a, &p.pb.hex), epoch_of(&p.b, &p.pa.hex));
}

/// R16 cap, R20: a relay that answers busy forever gets at most
/// `BLIND_BUSY_CAP` advances per connection; then blind asks to the peer
/// pause until the next reconnect. Never the identity path.
#[test]
fn pair_token_busy_beyond_the_cap_pauses_and_never_goes_identity() {
    let (mut p, _relay) = blind_pair();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    for n in 0..=BLIND_BUSY_CAP {
        let sent = rx_controls(&mut p.a_rx);
        assert_eq!(blind_tokens(&sent).len(), 1, "blind ask {n}");
        assert_eq!(identity_asks(&sent), 0);
        let ek = sent
            .iter()
            .find_map(|m| match m {
                ControlMessage::CircuitAskBlind { ephemeral_key, .. } => {
                    Some(ephemeral_key.clone())
                }
                _ => None,
            })
            .unwrap();
        feed(
            &mut p.a,
            Frame::Control(ControlMessage::PairTokenBusy { ephemeral_key: ek }),
        );
    }
    assert!(rx_controls(&mut p.a_rx).is_empty(), "paused: nothing sent");
    assert_eq!(
        epoch_of(&p.a, &p.pb.hex).counter,
        BLIND_BUSY_CAP,
        "advanced once per busy within the cap"
    );
    // Neither timeouts nor re-asks send anything while paused, for days.
    p.a.schedule_reask(&p.pb.hex);
    for k in 1..=200u32 {
        let secs = u64::from(k) * 601;
        p.a.pair_clock_override = Some(NOON + secs);
        p.a.fire_due_reasks(Instant::now() + Duration::from_secs(secs));
    }
    assert!(
        rx_controls(&mut p.a_rx).is_empty(),
        "never identity, never blind"
    );
    // A busy naming no ask of ours changes nothing.
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::PairTokenBusy {
            ephemeral_key: [9u8; 32].to_vec(),
        }),
    );
    assert!(rx_controls(&mut p.a_rx).is_empty());
    // The next reconnect asks blind again.
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(blind_tokens(&sent).len(), 1);
    assert_eq!(identity_asks(&sent), 0);
}

/// R18 (adapted to blind): `CircuitClosed` then `CircuitNotFound` on a
/// blinded circuit keep the message unacked; the re-ask is blind under the
/// next counter, and the message is re-sent on the re-paired session and
/// shown once.
#[test]
fn r18_closed_then_not_found_on_a_blinded_circuit_reasks_blind() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    let ps = ps_of(&p.a, &p.pb.hex);
    let (cid, target) = {
        let s = p.a.session_manager.get(&p.pb.hex).unwrap();
        (
            s.circuit_id.clone().unwrap(),
            s.target_circuit_id.clone().unwrap(),
        )
    };
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0r18")
        .unwrap();
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: cid,
            reason: crate::protocol::CircuitCloseReason::Normal,
        }),
    );
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::Error {
            code: crate::protocol::ControlErrorCode::CircuitNotFound,
            message: format!(
                "{}{}",
                crate::protocol::CIRCUIT_NOT_FOUND_PREFIX,
                hex::encode(target.0)
            ),
        }),
    );
    assert!(statuses(&p.a_log)
        .iter()
        .any(|e| matches!(e, StatusEvent::SendNotAccepted { .. })));
    assert!(p
        .a
        .acks
        .lock()
        .unwrap()
        .attempts(&hex::encode(id))
        .is_some());
    assert!(
        p.a.pending_reasks.contains_key(&p.pb.hex),
        "re-ask scheduled"
    );
    // The relay tore the row down for both (R18): B is told too.
    for (to, f) in relay.leave(0) {
        if to == 1 {
            feed(&mut p.b, f);
        }
    }
    relay.blind_asks.clear();
    let later = Instant::now() + Duration::from_secs(5);
    p.a.fire_due_reasks(later);
    p.b.fire_due_reasks(later);
    run(&mut p, &mut relay);
    let next = pair_token(
        &ps,
        PairEpoch {
            day: DAY,
            counter: 1,
        },
        NOON_SLOT,
    );
    assert!(relay.identity_asks.is_empty(), "never the identity path");
    assert_eq!(
        relay
            .blind_asks
            .iter()
            .filter(|(s, _)| *s == 0)
            .map(|(_, t)| *t)
            .collect::<Vec<_>>(),
        vec![next]
    );
    assert_eq!(messages_with(&p.b_log, b"r18"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// A pinned contact's knock means the peer is on the identity path (it
/// lost its sessions, or fell back): the answer is an identity ask.
#[test]
fn contact_knock_is_answered_on_the_identity_path() {
    let (mut p, _relay) = blind_pair();
    // A's circuit is gone (no live circuit), and B knocks.
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    let knock = knock_from(&p.pb, &p.pa, crate::circuits::now_hour());
    feed(&mut p.a, queued(knock));
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 1);
    assert!(blind_tokens(&sent).is_empty());
}

/// A contact's knock that arrives while our blind ask is still out: when
/// that ask times out, the re-ask is the identity ask the knock calls for,
/// never another blind ask (which also dropped the identity re-ask the
/// knock had scheduled, so the pair stayed blind; found by E23).
#[test]
fn contact_knock_during_a_blind_ask_is_answered_on_the_identity_path_at_its_timeout() {
    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    let t0 = Instant::now();
    p.a.send_blind_plan(&p.pb.hex, t0, crate::blind::BlindPlan::Own)
        .unwrap();
    assert_eq!(
        blind_tokens(&rx_controls(&mut p.a_rx)).len(),
        1,
        "a blind ask is out"
    );
    let knock = knock_from(&p.pb, &p.pa, crate::circuits::now_hour());
    feed(&mut p.a, queued(knock));
    assert!(p.a.identity_wanted.contains_key(&p.pb.hex));
    // The blind ask times out before the knock's scheduled re-ask runs.
    // (Within that identity ask's own TTL: once it runs out unmatched, the
    // pair goes back to blind, final review H-1.)
    p.a.fire_blind_timeouts(t0 + crate::peers::ASK_TTL + Duration::from_secs(1));
    p.a.fire_due_reasks(t0 + crate::peers::ASK_TTL + Duration::from_secs(60));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 1, "the knock's identity ask");
    assert!(blind_tokens(&sent).is_empty(), "no further blind ask");
}

/// Both sides answer each other's fresh knock: the identity ask of each
/// meets the other's, and the verified identity install on both sides is a
/// completed identity re-pair. `a_knock` is the knock A acts on.
fn complete_identity_repair(p: &mut Pair, relay: &mut FakeRelay, a_knock: Vec<u8>) {
    let hour = crate::circuits::now_hour();
    feed(&mut p.a, queued(a_knock));
    feed(&mut p.b, queued(knock_from(&p.pa, &p.pb, hour)));
    let at = Instant::now() + Duration::from_secs(700);
    p.a.fire_due_reasks(at);
    p.b.fire_due_reasks(at);
    run(p, relay);
    assert!(!relay.pairs.last().unwrap().2, "an identity pair");
}

/// R35 (final review I-1, re-expressed by the 2026-10-19 ruling): a relay
/// withholds a contact's genuine knocks (from identity asks that declare no
/// lost session), forces blind re-pairs in the same hour, then delivers
/// them: first seen, new digest, issued this hour. Each used to close the
/// blinded circuit and ask on the identity path, so a relay could loop it
/// past R20's bound (and raise SessionReplaced each time). The bound is now
/// on completed identity re-pairs: the first knock is answered and its
/// re-pair completes; each later one, delivered after a blind re-pair
/// within 24 h, changes nothing (no identity ask, the blinded circuit
/// stays).
#[test]
fn withheld_contact_knocks_force_at_most_one_completed_identity_repair_per_day() {
    let (mut p, mut relay) = blind_pair();
    let hour = crate::circuits::now_hour();
    let withheld = [
        knock_from(&p.pb, &p.pa, hour),
        knock_from(&p.pb, &p.pa, hour),
        knock_from(&p.pb, &p.pa, hour),
    ];
    let [first, second, third] = withheld;
    reconnect_both(&mut p, &mut relay); // the forced blind re-pair, this hour
    assert!(p.a.has_live_circuit(&p.pb.hex));
    complete_identity_repair(&mut p, &mut relay, first);
    assert!(p
        .a
        .session_manager
        .get(&p.pb.hex)
        .is_some_and(|s| { s.last_identity_fallback_unix == Some(p.a.pair_now_unix()) }));
    let pairs = relay.pairs.len();
    for knock in [second, third] {
        reconnect_both(&mut p, &mut relay); // a forced blind re-pair
        assert!(p.a.has_live_circuit(&p.pb.hex));
        drain(&mut p.a_rx);
        feed(&mut p.a, queued(knock));
        p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
        assert_eq!(identity_asks(&rx_controls(&mut p.a_rx)), 0);
        assert!(p.a.has_live_circuit(&p.pb.hex), "the blinded circuit stays");
        assert!(!p.a.identity_wanted.contains_key(&p.pb.hex));
    }
    assert!(relay.pairs.len() > pairs, "the blind re-pairs went on");
}

/// R35: once an identity re-pair has completed within 24 h (stamped an hour
/// ago here), a contact's knock
/// that declares no lost session is ignored for re-pairing: the blinded
/// circuit stays and nothing names the peer.
#[test]
fn contact_knock_without_lost_session_is_ignored_once_the_budget_is_spent() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    let now = p.a.pair_now_unix();
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .last_identity_fallback_unix = Some(now - 3600);
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        queued(knock_from(&p.pb, &p.pa, crate::circuits::now_hour())),
    );
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 0);
    assert!(p.a.has_live_circuit(&p.pb.hex), "the blinded circuit stays");
    assert!(!p.a.identity_wanted.contains_key(&p.pb.hex));
}

/// R35 with M-1 (2026-10-19 ruling): a genuine reinstall (the knock declares
/// no prior session) re-pairs at once: the ask goes out but stamps nothing.
/// The completed identity re-pair stamps the budget on both sides; a second
/// flagged knock within 24 h (one a relay withheld, delivered after a blind
/// re-pair) triggers no identity ask.
#[test]
fn reinstall_knock_re_pairs_at_once_and_the_completed_re_pair_stamps_the_budget() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    let created_hour = p.a.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        queued(knock_from_no_prior(&p.pb, &p.pa, created_hour + 1)),
    );
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 1, "an identity ask at once");
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .last_identity_fallback_unix,
        None,
        "an ask nobody answered yet spends nothing"
    );
    // B answers by identity too: the re-pair completes and stamps.
    for m in sent {
        for (_, f) in relay.control(0, m) {
            feed(&mut p.b, f);
        }
    }
    feed(
        &mut p.b,
        queued(knock_from(&p.pa, &p.pb, crate::circuits::now_hour())),
    );
    p.b.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    run(&mut p, &mut relay);
    assert!(!relay.pairs.last().unwrap().2, "an identity pair");
    let now = p.a.pair_now_unix();
    for (inner, peer) in [(&p.a, &p.pb.hex), (&p.b, &p.pa.hex)] {
        assert_eq!(
            inner
                .session_manager
                .get(peer)
                .unwrap()
                .last_identity_fallback_unix,
            Some(now),
            "the completed identity re-pair stamps the budget"
        );
    }
    let withheld = knock_from_no_prior(&p.pb, &p.pa, created_hour + 1);
    reconnect_both(&mut p, &mut relay); // the forced blind re-pair
    assert!(p.a.has_live_circuit(&p.pb.hex));
    drain(&mut p.a_rx);
    feed(&mut p.a, queued(withheld));
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    assert_eq!(
        identity_asks(&rx_controls(&mut p.a_rx)),
        0,
        "one completed re-pair per pair per 24 h"
    );
    assert!(p.a.has_live_circuit(&p.pb.hex), "the blinded circuit stays");
}

/// A completed identity re-pair stamps the pair's budget with the time of
/// the install; a second fresh knock within 24 h is ignored (the pair stays
/// blind), and once 24 h have passed it is answered.
#[test]
fn completed_identity_repair_blocks_a_second_one_for_24h() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .last_identity_fallback_unix,
        None
    );
    let hour = crate::circuits::now_hour();
    let first = knock_from(&p.pb, &p.pa, hour);
    complete_identity_repair(&mut p, &mut relay, first);
    let stamped = p.a.pair_now_unix();
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .last_identity_fallback_unix,
        Some(stamped)
    );
    reconnect_both(&mut p, &mut relay); // blind again
    assert!(p.a.has_live_circuit(&p.pb.hex));
    drain(&mut p.a_rx);
    feed(&mut p.a, queued(knock_from(&p.pb, &p.pa, hour)));
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    assert_eq!(identity_asks(&rx_controls(&mut p.a_rx)), 0, "ignored");
    assert!(p.a.has_live_circuit(&p.pb.hex), "the pair stays blind");
    // 24 h on, a fresh knock is answered.
    p.a.pair_clock_override = Some(stamped + crate::blind::IDENTITY_FALLBACK_INTERVAL_SECS);
    feed(&mut p.a, queued(knock_from(&p.pb, &p.pa, hour)));
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(1400));
    assert_eq!(identity_asks(&rx_controls(&mut p.a_rx)), 1, "answered");
}

/// First contact (no pair secret before the install) is not a re-pair: the
/// identity install stamps nothing.
#[test]
fn first_contact_install_does_not_stamp_the_budget() {
    let p = establish(0xA1, 0xB2);
    for (inner, peer) in [(&p.a, &p.pb.hex), (&p.b, &p.pa.hex)] {
        let s = inner.session_manager.get(peer).unwrap();
        assert!(s.pair_secret.is_some(), "an identity install derives PS");
        assert_eq!(s.last_identity_fallback_unix, None);
    }
}

/// After a timed identity fallback ask runs out unanswered, the next one
/// waits a full 24 h from it (nothing is stamped, the blind clock restarts),
/// also when the connection drops while it is out.
#[test]
fn no_second_timed_fallback_within_24h_of_one_that_ran_out() {
    let (mut p, mut relay) = blind_pair();
    let t0 = Instant::now();
    let mut k = unanswered_fallback(&mut p, &mut relay, t0);
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .last_identity_fallback_unix,
        None,
        "an unanswered ask spends no budget"
    );
    let ran_out_at = NOON + u64::from(k) * (ASK_TTL.as_secs() + 1);
    let asks = relay.identity_asks.len();
    while NOON + u64::from(k) * (ASK_TTL.as_secs() + 1) < ran_out_at + 23 * 3600 {
        k += 1;
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    }
    assert_eq!(relay.identity_asks.len(), asks, "none within the day");
    while relay.identity_asks.len() == asks {
        k += 1;
        assert!(k <= 600, "the next one comes");
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    }
    let at = NOON + u64::from(k) * (ASK_TTL.as_secs() + 1);
    assert!(at >= ran_out_at + IDENTITY_FALLBACK_AFTER_SECS, "a day on");
    // It goes out with the connection: the next waits another day.
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    let asks = relay.identity_asks.len();
    for _ in 0..20 {
        k += 1;
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    }
    assert_eq!(relay.identity_asks.len(), asks, "not again right away");
}

/// The fallback clock, the last fallback and the blinded mark are
/// persisted with the session,
/// and a blind wait for session-init keeps its origin across a restart.
#[test]
fn blind_state_survives_a_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    set_clock(&mut p.a, &p.pb.hex, NOON);
    set_clock(&mut p.b, &p.pa.hex, NOON);
    let mut relay = FakeRelay::default();
    relay.join(0, &p.pa.bundle);
    relay.join(1, &p.pb.bundle);
    relay.route(&C2, 1);
    relay.route(&C1, 0);
    // B's session-init never arrives: A's packets are lost.
    relay.drop_from.insert(0);
    reconnect_both(&mut p, &mut relay);
    assert!(p.b.awaiting_init(&p.pa.hex));
    if let Some(mut s) = p.a.session_manager.get_mut(&p.pb.hex) {
        s.blind_since_unix = Some(123);
        s.last_identity_fallback_unix = Some(456);
    }
    p.a.persist_peer(&p.pb.hex).unwrap();
    let rec = open_record(&sa, 0xA1, &p.pb);
    let s = rec.session.as_ref().unwrap();
    assert_eq!(
        (s.blind_since_unix, s.last_identity_fallback_unix),
        (Some(123), Some(456))
    );
    assert!(s.blinded);
    let rec_b = open_record(&sb, 0xB2, &p.pa);
    assert!(
        rec_b.pending_init.as_ref().unwrap().blind,
        "blind origin kept"
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    let s2 = a2.session_manager.get(&p.pb.hex).unwrap();
    assert_eq!(
        (s2.blind_since_unix, s2.last_identity_fallback_unix),
        (Some(123), Some(456))
    );
    assert!(s2.blinded);
    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(
        b2.pending_inits.get(&p.pa.hex).map(|w| w.origin),
        Some(crate::blind::InstallOrigin::Blind)
    );
}

/// No log line carries two identity-derived values, the pair secret or a
/// pair token, through a whole blind re-pair.
#[test]
fn blind_flow_logs_no_secret_and_no_identity_pair() {
    let (mut p, mut relay) = blind_pair();
    let ps = ps_of(&p.a, &p.pb.hex);
    let tokens: Vec<String> = (0..4)
        .map(|n| {
            hex::encode(pair_token(
                &ps,
                PairEpoch {
                    day: DAY,
                    counter: n,
                },
                NOON_SLOT,
            ))
        })
        .collect();
    let cap = LogCapture::start();
    reconnect_both(&mut p, &mut relay);
    reconnect_both(&mut p, &mut relay);
    let lines = cap.take();
    assert_eq!(relay.pairs.len(), 2);
    let ids = vec![p.pa.hex.clone(), p.pb.hex.clone()];
    for line in lines.lines() {
        assert!(identity_values_in(line, &ids) <= 1, "{line}");
        assert!(!line.contains(&hex::encode(ps)), "{line}");
        for t in &tokens {
            assert!(!line.contains(t.as_str()), "{line}");
        }
    }
}

/// A responder still waiting for a blind pair's session-init when its
/// transport is replaced cannot resume that circuit (blinded): it asks
/// blind again under the next counter, and the pair re-forms.
#[test]
fn responder_awaiting_blind_init_reasks_after_reconnect() {
    let (mut p, mut relay) = blind_pair();
    relay.drop_from.insert(0); // A's session-init is lost
    reconnect_both(&mut p, &mut relay);
    relay.drop_from.clear();
    assert!(p.b.awaiting_init(&p.pa.hex));
    let ps = ps_of(&p.a, &p.pb.hex);
    relay.blind_asks.clear();
    reconnect_both(&mut p, &mut relay);
    let next = pair_token(
        &ps,
        PairEpoch {
            day: DAY,
            counter: 1,
        },
        NOON_SLOT,
    );
    assert_eq!(relay.blind_asks, vec![(0, next), (1, next)]);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(!p.b.awaiting_init(&p.pa.hex));
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// Only one side reconnects while the other keeps its identity circuit
/// from first contact: the reconnecting side closes that stale identity
/// circuit (the relay already keys it by the identity pair) and asks blind;
/// the peer, told `CircuitClosed`, re-asks blind at once and the pair
/// re-forms in one round trip, not after the relay's unresumed grace.
#[test]
fn one_sided_reconnect_closes_the_identity_circuit_and_re_pairs_blind() {
    let (mut p, mut relay) = blind_pair();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.closes, vec![(0, C1)]);
    assert!(p.b.pending_reasks.contains_key(&p.pa.hex), "B was told");
    p.b.fire_due_reasks(Instant::now() + Duration::from_secs(5));
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true)]);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
    // A blinded circuit's id is never presented again: the next one-sided
    // reconnect sends no close at all (the relay's sweep or R18 ends it).
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    assert!(sent
        .iter()
        .all(|m| !matches!(m, ControlMessage::CloseCircuit { .. })));
    assert_eq!(blind_tokens(&sent).len(), 1);
}

/// Puts a live call with `peer` on `inner` (Connected, no media): what a
/// call carried on the pair's identity circuit looks like to the circuits.
fn live_call(inner: &mut ClientInner, peer: &str, id: crate::call::CallId) {
    use crate::call::machine::{ActiveCall, Direction, Phase};
    let now = Instant::now();
    inner.call.active = Some(ActiveCall {
        id,
        peer: peer.to_string(),
        direction: Direction::Outgoing,
        placed_at: now,
        started_at_ms: 0,
        phase: Phase::Connected {
            at: now,
            last_status: now,
        },
        media: None,
        video: Default::default(),
    });
}

/// Final review N1: a chat reconnect during a call on the identity circuit
/// (the call right after first contact) closes that circuit at once, as
/// without a call: the relay keeps a token with live call connections
/// across `CloseCircuit` (relay `a_close_keeps_a_token_with_live_call_connections`,
/// `a_call_survives_a_chat_reconnect_that_closes_its_identity_circuit`).
/// The pair re-forms blind in one round trip, and a chat message and the
/// hang-up End then go out at once on the new circuit, not the old one.
#[test]
fn a_reconnect_during_a_call_closes_the_identity_circuit_and_sends_on_the_new_one() {
    let (mut p, mut relay) = blind_pair();
    let id = crate::call::CallId([9; 16]);
    live_call(&mut p.a, &p.pb.hex, id);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.closes, vec![(0, C1)], "closed at once");
    p.b.fire_due_reasks(Instant::now() + Duration::from_secs(5));
    run(&mut p, &mut relay);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    // A sends on the peer's side of the pair (its target circuit).
    let new_circuit =
        p.a.session_manager
            .get(&p.pb.hex)
            .and_then(|s| s.target_circuit_id.clone())
            .expect("re-paired");
    assert_ne!(new_circuit, C2, "not the old identity pair");
    assert!(p.a.call.active.is_some(), "the call carries on");
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0during the call")
        .unwrap();
    p.a.call_end(id, Instant::now(), 0).unwrap();
    let circuits: Vec<CircuitId> = drain(&mut p.a_rx)
        .iter()
        .filter_map(|f| crate::protocol::RelayPacket::decode(f))
        .map(|pkt| pkt.circuit_id)
        .collect();
    assert!(
        circuits.len() >= 2,
        "message and End sent at once: {circuits:?}"
    );
    assert!(
        circuits.iter().all(|c| *c == new_circuit),
        "all on the new circuit: {circuits:?}"
    );
}

/// R19 on the responder's side: B (role 1 in every re-pair here) has an
/// unacked message across two re-pairs; it is re-sealed once B's new
/// ratchet can send (after the session-init's first message) and shown
/// exactly once.
#[test]
fn responder_unacked_message_is_resealed_and_shown_once() {
    let (mut p, mut relay) = blind_pair();
    let id: [u8; 16] = rand::random();
    p.b.send_tracked_for_test(&p.pa.hex, id, b"\x01\0\0\0\0from the responder")
        .unwrap();
    drain(&mut p.b_rx); // lost
    relay.drop_ids.insert(id);
    reconnect_both(&mut p, &mut relay);
    relay.drop_ids.clear();
    assert_eq!(relay.pairs.len(), 1);
    assert_eq!(messages_with(&p.a_log, b"from the responder"), 0);
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true), (0, 1, true)]);
    assert_eq!(messages_with(&p.a_log, b"from the responder"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// A contact's fresh knock while our blinded circuit with it is live: the
/// contact is on the identity path (it restarted without its sessions), so
/// the blinded circuit is closed on this connection and the answer is an
/// identity ask. A knock issued before the current session began changes
/// nothing.
#[test]
fn contact_knock_on_a_live_blinded_circuit_closes_it_and_asks_identity() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    assert!(p.a.has_live_circuit(&p.pb.hex));
    let cid =
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .circuit_id
            .clone()
            .unwrap();
    let created_hour = p.a.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    // Stale: issued an hour before this session.
    let stale = knock_from(&p.pb, &p.pa, created_hour - 1);
    feed(&mut p.a, queued(stale));
    assert!(
        p.a.has_live_circuit(&p.pb.hex),
        "a stale knock changes nothing"
    );
    assert!(rx_controls(&mut p.a_rx).is_empty());
    let fresh = knock_from(&p.pb, &p.pa, crate::circuits::now_hour());
    feed(&mut p.a, queued(fresh));
    assert!(!p.a.has_live_circuit(&p.pb.hex));
    let sent = rx_controls(&mut p.a_rx);
    assert!(sent
        .iter()
        .any(|m| matches!(m, ControlMessage::CloseCircuit { circuit_id } if *circuit_id == cid)));
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 1);
    assert!(blind_tokens(&sent).is_empty());
}

/// A quick reconnect right after first contact, before the responder's
/// answer to our session-init reached us: the initiator is blind-capable
/// at once (the relay took its init for the peer, so the peer installs it
/// and holds PS) and asks blind; it does not close the identity circuit
/// the peer may still await the init on. When both reconnect, they re-pair
/// blind with no identity re-pair and no recovery warning (an identity
/// resume here would race the peer's close into a needless identity pair).
#[test]
fn quick_reconnect_before_the_init_is_answered_re_pairs_blind() {
    let (mut p, mut relay) = blind_pair();
    if let Some(mut s) = p.a.session_manager.get_mut(&p.pb.hex) {
        s.init_out = Some(Box::new(crate::session::InitOut {
            ct: Box::new([0; crate::kem::KEM_CT_LEN]),
            confirm: [0; 32],
            sent: None,
        }));
    }
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    assert!(
        sent.iter()
            .all(|m| !matches!(m, ControlMessage::CloseCircuit { .. })),
        "the peer may still await the init on it"
    );
    assert_eq!(blind_tokens(&sent).len(), 1);
    assert_eq!(identity_asks(&sent), 0);
    for f in sent {
        for (to, frame) in relay.control(0, f) {
            let c = if to == 0 { &mut p.a } else { &mut p.b };
            feed(c, frame);
        }
    }
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs, vec![(0, 1, true)]);
    assert!(relay.identity_asks.is_empty());
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// R20 stray match: a window sibling the relay still holds after its pair
/// matched on the other token is met later by the peer (here after a
/// one-sided reconnect). Our echo check fails as before (its keys are
/// gone), but our epoch follows the peer's, so the re-asks that follow the
/// close meet at once instead of drifting one apart.
#[test]
fn stale_window_ask_met_later_syncs_the_epoch() {
    let (mut p, mut relay) = blind_pair();
    let ps = ps_of(&p.a, &p.pb.hex);
    drop(relay.leave(1));
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    relay.expire_asks();
    p.a.fire_blind_timeouts(t0 + ASK_TTL + Duration::from_secs(1));
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(
        tokens_of(&relay, 0)[1..],
        [c(&ps, DAY, 0), c(&ps, DAY, 1)],
        "A holds the ±1 window"
    );
    // B comes back on counter 0: the pair matches there; A's counter-1
    // ask stays held at the relay.
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 1);
    let one = PairEpoch {
        day: DAY,
        counter: 1,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), one);
    // B alone reconnects: the relay ends the row at its publish (R21, A is
    // told), and B's counter-1 ask meets A's stale one.
    for (to, f) in relay.leave(1) {
        if to == 0 {
            feed(&mut p.a, f);
        }
    }
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 2, "the stray match");
    assert_eq!(
        epoch_of(&p.a, &p.pb.hex),
        PairEpoch {
            day: DAY,
            counter: 2
        },
        "A followed B past the stray token"
    );
    let later = Instant::now() + Duration::from_secs(5);
    p.a.fire_due_reasks(later);
    p.b.fire_due_reasks(later);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 3, "the re-asks met at once");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert_eq!(epoch_of(&p.a, &p.pb.hex), epoch_of(&p.b, &p.pa.hex));
    assert!(relay.identity_asks.is_empty());
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// M-1 (the reviewer's scenario): the side already on the next day (B)
/// asks first while the pair's stored counter on the old day is 1. B's
/// neighbour retry is the stored `(DAY, 1)`, which is exactly what A, still
/// on DAY, asks, so they meet.
#[test]
fn midnight_ahead_side_retries_with_the_stored_counter() {
    let end = (DAY as u64 + 1) * 86_400;
    let (mut p, mut relay) = blind_pair_at(end - 300);
    reconnect_both(&mut p, &mut relay);
    let one = PairEpoch {
        day: DAY,
        counter: 1,
    };
    assert_eq!(epoch_of(&p.a, &p.pb.hex), one);
    assert_eq!(epoch_of(&p.b, &p.pa.hex), one);
    let pairs_before = relay.pairs.len();
    p.a.pair_clock_override = Some(end - 120);
    p.b.pair_clock_override = Some(end + 120);
    let t0 = Instant::now();
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    run(&mut p, &mut relay);
    assert_eq!(
        relay.pairs.len(),
        pairs_before,
        "different tokens: no match"
    );
    // R40-M3: both clocks run on (B's 240 s ahead of A's) in 30 s steps,
    // and the relay drops asks held for a TTL. Every ask is under its own
    // clock's 10-minute slot; B's neighbour retry is under its stored
    // (DAY, 1), which A, still on that epoch, asks again under each new
    // slot (rollover asks): they meet blind within a bounded time.
    let ps = ps_of(&p.a, &p.pb.hex);
    let mut secs = 0;
    while !(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex)) {
        secs += 30;
        assert!(secs <= 1800, "healed within 30 minutes");
        relay.now_secs = secs;
        relay.expire_held_after(ASK_TTL.as_secs());
        p.a.pair_clock_override = Some(end - 120 + secs);
        p.b.pair_clock_override = Some(end + 120 + secs);
        let at = t0 + Duration::from_secs(secs);
        p.a.fire_due_reasks(at);
        p.b.fire_due_reasks(at);
        run(&mut p, &mut relay);
    }
    let slots = pair_slot(end - 600)..=pair_slot(end + 3600);
    assert!(
        tokens_of(&relay, 1)
            .iter()
            .any(|t| slots.clone().any(|s| *t == cs(&ps, DAY, 1, s))),
        "B retried under the stored (DAY, 1)"
    );
    assert!(relay.pairs.last().unwrap().2, "a blinded pair");
    assert!(relay.identity_asks.is_empty());
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert_eq!(epoch_of(&p.a, &p.pb.hex), epoch_of(&p.b, &p.pa.hex));
}

/// M-2: a pinned contact's knock is acted on once. A relay replaying the
/// same knock (same hour) cannot turn the pair to the identity path again.
#[test]
fn replayed_contact_knock_is_ignored() {
    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    let knock = knock_from(&p.pb, &p.pa, crate::circuits::now_hour());
    feed(&mut p.a, queued(knock.clone()));
    assert!(p.a.identity_wanted.contains_key(&p.pb.hex), "first knock");
    p.a.identity_wanted.clear(); // as after the identity install
    feed(&mut p.a, queued(knock));
    assert!(
        !p.a.identity_wanted.contains_key(&p.pb.hex),
        "the replay changes nothing"
    );
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 0);
    assert_eq!(blind_tokens(&sent).len(), 1);
}

/// M-3, fix round 2 N-3: a match on our blind ask that fails verification
/// (here the peer's ephemeral signature, as a relay forging it would) moves
/// nothing: not our counter, not the fallback clock, which runs on until a
/// verified install.
#[test]
fn unverified_match_does_not_reset_the_fallback_clock() {
    let (mut p, _relay) = blind_pair();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let since = since_of(&p.a, &p.pb.hex);
    assert!(since.is_some(), "the clock started at the blind ask");
    let (ek, kem) = rx_controls(&mut p.a_rx)
        .into_iter()
        .find_map(|m| match m {
            ControlMessage::CircuitAskBlind {
                ephemeral_key,
                kem_ephemeral_pk,
                ..
            } => Some((ephemeral_key, kem_ephemeral_pk)),
            _ => None,
        })
        .unwrap();
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    let r_kem = crate::kem::KemKeyPair::generate().public().to_vec();
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitCreatedV3 {
            circuit_id: crate::protocol::CircuitId([0x51; 16]),
            token: TOKEN.to_vec(),
            target_circuit_id: crate::protocol::CircuitId([0x52; 16]),
            role: 0,
            peer: crate::protocol::PeerBundle::from_signed(&p.pb.bundle),
            initiator_ephemeral_key: ek,
            responder_ephemeral_key: r_ek.to_vec(),
            initiator_kem_ephemeral_pk: kem,
            responder_kem_ephemeral_pk: r_kem,
            initiator_ephemeral_sig: vec![0; 64],
            responder_ephemeral_sig: vec![0; 64], // not B's signature
        }),
    );
    assert_eq!(
        epoch_of(&p.a, &p.pb.hex).counter,
        0,
        "a tampered frame never moves our counter (N-3)"
    );
    assert_eq!(
        since_of(&p.a, &p.pb.hex),
        since,
        "no reset before a verified install"
    );
}

/// M-4: a tracked message keeps its plaintext only while a later blind
/// session of the same pair secret could re-seal it; an identity install
/// (a new PS) wipes it.
#[test]
fn identity_install_drops_kept_plaintexts() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0kept")
        .unwrap();
    drain(&mut p.a_rx);
    let has = |a: &ClientInner| a.acks.lock().unwrap().has_plaintext(&hex::encode(id));
    assert_eq!(has(&p.a), Some(true));
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb); // identity asks
    assert_eq!(has(&p.a), Some(false), "re-sent as old bytes only (AK4)");
}

/// M-5: B misses the `CircuitCreatedV3` of a blind match, so A's re-sealed
/// copy goes under a session B never installs. It is not lost silently: B
/// raises `DecryptFailed`, and once the pair heals (busy → advance, R16) B's
/// session notice reports it, so A raises `PeerUndelivered` (reason 1) for
/// that id: the §18 lost-id path.
#[test]
fn resealed_copy_lost_to_a_missed_match_falls_to_lost_id_recovery() {
    let (mut p, mut relay) = blind_pair();
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0missed match")
        .unwrap();
    drain(&mut p.a_rx);
    relay.drop_created_once = Some(1);
    let t0 = Instant::now();
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 1);
    assert!(statuses(&p.b_log)
        .iter()
        .any(|e| matches!(e, StatusEvent::DecryptFailed { message_id, .. } if *message_id == hex::encode(id))));
    // B's ask runs out; its window's own token is busy (the row exists):
    // the row goes, B advances, both re-ask and meet.
    p.b.fire_blind_timeouts(t0 + ASK_TTL + Duration::from_secs(1));
    run(&mut p, &mut relay);
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(5));
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.len(), 2);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(statuses(&p.a_log).contains(&StatusEvent::PeerUndelivered {
        peer: p.pb.hex.clone(),
        message_id: hex::encode(id),
        reason: 1,
    }));
}

/// R21 (client): one side reconnects and sends at once. The send is
/// parked on the session while the blind re-pair is in flight (no
/// `SessionNotEstablished` after the send wait), moves to the new session
/// at its install, and is delivered once.
#[test]
fn one_sided_reconnect_parks_sends_until_the_re_pair() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay); // a blinded pair
                                        // B alone: the relay ends the row at B's publish (R21), A is told.
    let told: Vec<(usize, Frame)> = relay.leave(1);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    assert!(p.b.blind_repair_in_flight(&p.pa.hex));
    p.b.send_wait_ms = 50;
    let client = wrap(std::mem::replace(
        &mut p.b,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    let sent = client.send_text_message(p.pa.hex.clone(), "right away".into());
    assert!(sent.is_ok(), "parked, not refused: {sent:?}");
    p.b = std::mem::replace(
        &mut *client.inner.try_write().unwrap(),
        ClientInner::new(crate::ClientConfig::default()),
    );
    drop(client);
    assert_eq!(
        p.b.session_manager
            .get(&p.pa.hex)
            .unwrap()
            .pending_messages
            .len(),
        1
    );
    for (to, f) in told {
        if to == 0 {
            feed(&mut p.a, f);
        }
    }
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(5));
    run(&mut p, &mut relay);
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    let mut b = std::mem::replace(&mut p.b, ClientInner::new(crate::ClientConfig::default()));
    b = process_pending_on(b);
    p.b = b;
    run(&mut p, &mut relay);
    assert_eq!(messages_with(&p.a_log, b"right away"), 1);
    assert_eq!(warnings(&p.a_log), vec![]);
    assert_eq!(warnings(&p.b_log), vec![]);
}

/// R21: a send parked for a re-pair that never forms leaves the queue as
/// `QueuedSendLost` once it is older than the offline queue's 72 h (it
/// could no longer reach the peer even then).
#[test]
fn parked_send_past_72h_is_reported_lost() {
    let (mut p, _relay) = blind_pair();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let mut m = pending_msg(7, "never paired");
    m.timestamp_ms = (crate::unix_now_secs() - 73 * 3600) * 1000;
    let fresh = {
        let mut f = pending_msg(8, "recent");
        f.timestamp_ms = crate::unix_now_secs() * 1000;
        f
    };
    if let Some(mut s) = p.a.session_manager.get_mut(&p.pb.hex) {
        s.pending_messages.push_back(m);
        s.pending_messages.push_back(fresh);
    }
    p.a.purge_stale(Instant::now());
    assert_eq!(
        statuses(&p.a_log),
        vec![StatusEvent::QueuedSendLost {
            peer: p.pb.hex.clone(),
            message_id: hex::encode([7u8; 16]),
        }]
    );
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .pending_messages
            .len(),
        1,
        "the recent one stays parked"
    );
}

/// N-3: a forged `CircuitCreatedV3` naming a window ask we retired (a stray
/// match) moves our counter only when the peer's signature verifies.
#[test]
fn forged_stray_match_does_not_move_the_counter() {
    let (mut p, _relay) = blind_pair();
    let spent_ek = [0x5A; 32];
    p.a.spent_blind_asks.insert(
        spent_ek,
        crate::blind::SpentAsk {
            peer: p.pb.hex.clone(),
            epoch: PairEpoch {
                day: DAY,
                counter: 4,
            },
            sent_at: Instant::now(),
            lineage: p.a.session_manager.get(&p.pb.hex).unwrap().pair_lineage(),
        },
    );
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitCreatedV3 {
            circuit_id: crate::protocol::CircuitId([0x61; 16]),
            token: TOKEN.to_vec(),
            target_circuit_id: crate::protocol::CircuitId([0x62; 16]),
            role: 0,
            peer: crate::protocol::PeerBundle::from_signed(&p.pb.bundle),
            initiator_ephemeral_key: spent_ek.to_vec(),
            responder_ephemeral_key: r_ek.to_vec(),
            initiator_kem_ephemeral_pk: crate::kem::KemKeyPair::generate().public().to_vec(),
            responder_kem_ephemeral_pk: crate::kem::KemKeyPair::generate().public().to_vec(),
            initiator_ephemeral_sig: vec![0; 64],
            responder_ephemeral_sig: vec![0; 64],
        }),
    );
    assert_eq!(epoch_of(&p.a, &p.pb.hex).counter, 0, "forged: not moved");
}

/// Fix round 2 N-2: the issue hour and digest of the last contact knock
/// acted on are persisted, so a relay replaying that knock (or an older
/// one) after an app restart changes nothing. The seen-knock set and the
/// one-answer-per-day budget are memory only, so after a restart one new
/// knock of the same hour (as from a peer that lost its sessions again) is
/// answered, and no more than that one within 24 h.
#[test]
fn contact_knock_replay_after_restart_costs_at_most_one_answer() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    p.a.handle_circuit_closed(C1);
    let hour = crate::circuits::now_hour();
    let knock = knock_from(&p.pb, &p.pa, hour);
    feed(&mut p.a, queued(knock.clone()));
    assert!(
        p.a.identity_wanted.contains_key(&p.pb.hex),
        "first knock acted on"
    );
    assert_eq!(
        open_record(&sa, 0xA1, &p.pb).last_knock.map(|(h, _)| h),
        Some(hour)
    );
    let (mut a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    feed(&mut a2, queued(knock));
    assert!(
        !a2.identity_wanted.contains_key(&p.pb.hex),
        "the replay changes nothing"
    );
    let older = knock_from(&p.pb, &p.pa, hour - 1);
    feed(&mut a2, queued(older));
    assert!(
        !a2.identity_wanted.contains_key(&p.pb.hex),
        "an older knock changes nothing"
    );
    // The answer budget did not survive the restart: one new knock of the
    // same hour is answered...
    let again = knock_from(&p.pb, &p.pa, hour);
    feed(&mut a2, queued(again));
    assert!(
        a2.identity_wanted.contains_key(&p.pb.hex),
        "one answer after a restart"
    );
    a2.identity_wanted.clear();
    // ...and no second one within 24 h, flagged or not.
    feed(&mut a2, queued(knock_from(&p.pb, &p.pa, hour)));
    assert!(
        !a2.identity_wanted.contains_key(&p.pb.hex),
        "a further knock waits for the answer budget"
    );
    let created_hour = a2.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    feed(
        &mut a2,
        queued(knock_from_no_prior(&p.pb, &p.pa, created_hour + 1)),
    );
    assert!(
        !a2.identity_wanted.contains_key(&p.pb.hex),
        "a flagged knock waits for it too"
    );
}

/// Step the pair's clocks and timers `k` ask TTLs (plus a second each)
/// past `t0`: the relay drops held asks, timeouts and re-asks fire.
fn step_ttls(p: &mut Pair, relay: &mut FakeRelay, t0: Instant, k: u32) {
    let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
    p.a.pair_clock_override = Some(NOON + secs);
    p.b.pair_clock_override = Some(NOON + secs);
    relay.expire_asks();
    let at = t0 + Duration::from_secs(secs);
    p.a.fire_due_reasks(at);
    p.b.fire_due_reasks(at);
    run(p, relay);
}

/// Final review H-1 (from the reviewer's scratch test): a contact merely
/// away. A completed an identity re-pair an hour ago (its budget is spent, and its
/// knock waited at the relay for B). B returns and re-pairs blind, then
/// acts on A's knock (B's budget is free): B closes the blinded circuit and
/// asks by identity. A's budget is spent, so A ignores B's knock and stays
/// blind. B's knock-driven identity ask must run out like a timed fallback
/// and send B back to blind, so the pair forms again (blind) within a few
/// ask TTLs, not after up to 24 h.
#[test]
fn away_contact_returns_after_peer_fallback_re_pairs_blind() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    let now = p.a.pair_now_unix();
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .last_identity_fallback_unix = Some(now - 3600);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert_eq!(relay.pairs.last(), Some(&(0, 1, true)), "blind re-pair");
    drain(&mut p.b_rx);
    // B finds A's fallback knock in its offline queue.
    let b_budget_before =
        p.b.session_manager
            .get(&p.pa.hex)
            .unwrap()
            .last_identity_fallback_unix;
    assert_eq!(b_budget_before, None);
    feed(
        &mut p.b,
        queued(knock_from(&p.pa, &p.pb, crate::circuits::now_hour())),
    );
    assert!(p.b.identity_wanted.contains_key(&p.pa.hex));
    let t0 = Instant::now();
    // B's identity re-ask is scheduled (backoff): let it go out.
    p.b.fire_due_reasks(t0 + Duration::from_secs(120));
    run(&mut p, &mut relay);
    let pairs_mid = relay.pairs.len();
    assert!(
        !p.a.has_live_circuit(&p.pb.hex) && !p.b.has_live_circuit(&p.pa.hex),
        "B closed the blinded circuit"
    );
    assert!(
        relay.identity_asks.iter().any(|(s, _, _)| *s == 1),
        "B asked by identity"
    );
    // A ignored B's knock: its budget is spent.
    assert!(!p.a.identity_wanted.contains_key(&p.pb.hex));
    for k in 1..=3u32 {
        step_ttls(&mut p, &mut relay, t0, k);
        if relay.pairs.len() > pairs_mid {
            break;
        }
    }
    assert!(
        relay.pairs.len() > pairs_mid,
        "a new pair forms within three ask TTLs"
    );
    assert_eq!(relay.pairs.last().map(|x| x.2), Some(true), "blind");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(
        !p.b.identity_wanted.contains_key(&p.pa.hex),
        "B back on blind"
    );
}

/// H-1: a knock-driven identity ask goes with the connection like a timed
/// fallback: the next connection re-pairs blind. A knock that declares no
/// session on the contact's side (a reinstall) keeps the identity path
/// across the reconnect, since such a peer cannot ask blind.
#[test]
fn knock_driven_identity_path_ends_at_reconnect_unless_flagged() {
    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        queued(knock_from(&p.pb, &p.pa, crate::circuits::now_hour())),
    );
    assert!(p.a.identity_wanted.contains_key(&p.pb.hex));
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let sent = rx_controls(&mut p.a_rx);
    assert!(!p.a.identity_wanted.contains_key(&p.pb.hex));
    assert_eq!(identity_asks(&sent), 0);
    assert_eq!(blind_tokens(&sent).len(), 1, "back on blind");

    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    let created_hour = p.a.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    feed(
        &mut p.a,
        queued(knock_from_no_prior(&p.pb, &p.pa, created_hour + 1)),
    );
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    p.a.fire_due_reasks(Instant::now() + Duration::from_secs(120));
    let sent = rx_controls(&mut p.a_rx);
    assert!(p.a.identity_wanted.contains_key(&p.pb.hex));
    assert_eq!(identity_asks(&sent), 1, "still the identity path");
    // Final re-review N-1: A still holds the pair secret, so it also asks
    // blind beside the identity ask.
    assert_eq!(blind_tokens(&sent).len(), 1, "a blind ask beside it");
}

/// H-1: a flagged knock's identity ask that runs out unmatched does not
/// end the identity path (the contact may have no pair secret). Final
/// re-review N-1: while A still holds one, blind asks run beside it and
/// keep going after their own timeouts.
#[test]
fn flagged_knock_identity_ask_does_not_expire_to_blind() {
    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    let created_hour = p.a.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    feed(
        &mut p.a,
        queued(knock_from_no_prior(&p.pb, &p.pa, created_hour + 1)),
    );
    let t0 = Instant::now();
    p.a.fire_due_reasks(t0 + Duration::from_secs(120));
    let sent = rx_controls(&mut p.a_rx);
    assert_eq!(identity_asks(&sent), 1);
    assert_eq!(blind_tokens(&sent).len(), 1, "a blind ask beside it");
    p.a.fire_due_reasks(t0 + ASK_TTL * 2);
    assert!(p.a.identity_wanted.contains_key(&p.pb.hex));
    assert!(
        !blind_tokens(&rx_controls(&mut p.a_rx)).is_empty(),
        "the blind plan goes on after its timeout"
    );
}

/// R40-M3: A asks in the slot before B's (each under its own clock's
/// slot, A's ask still held). They do not match until A's clock reaches
/// B's slot; then A asks its epoch again under the new slot (a rollover
/// ask) while its previous-slot ask stays held, and they meet.
#[test]
fn clients_in_adjacent_slots_meet_after_the_rollover() {
    let (mut p, mut relay) = blind_pair_at(NOON - 60);
    let ps = ps_of(&p.a, &p.pb.hex);
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    p.b.pair_clock_override = Some(NOON + 60);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    assert!(relay.pairs.is_empty(), "different slots: no match yet");
    assert_eq!(tokens_of(&relay, 0), vec![cs(&ps, DAY, 0, NOON_SLOT - 1)]);
    assert_eq!(tokens_of(&relay, 1), vec![c(&ps, DAY, 0)]);
    // A's clock crosses the boundary; its ask is still held.
    p.a.pair_clock_override = Some(NOON + 1);
    p.a.fire_blind_timeouts(t0 + Duration::from_secs(61));
    assert_eq!(
        p.a.blind_asks.get(&p.pb.hex).map(Vec::len),
        Some(2),
        "the previous slot's ask and the rollover ask"
    );
    run(&mut p, &mut relay);
    assert_eq!(
        tokens_of(&relay, 0)[1],
        c(&ps, DAY, 0),
        "under the new slot"
    );
    assert_eq!(relay.pairs, vec![(1, 0, true)], "they meet");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(relay.identity_asks.is_empty());
}

/// R40-M3: two clients of the same pair asking hours apart (never online
/// together) send different tokens, so a relay recording asks cannot link
/// them; in the same slot they send the same one.
#[test]
fn clients_online_hours_apart_send_different_tokens() {
    let (mut p, mut relay) = blind_pair();
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    drop(relay.leave(0));
    p.b.pair_clock_override = Some(NOON + 3 * 3600);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    run(&mut p, &mut relay);
    let (ta, tb) = (tokens_of(&relay, 0), tokens_of(&relay, 1));
    assert_eq!((ta.len(), tb.len()), (1, 1));
    assert_ne!(ta[0], tb[0], "same epoch, hours apart: unlinkable tokens");
    assert_eq!(epoch_of(&p.a, &p.pb.hex), epoch_of(&p.b, &p.pa.hex));
    assert!(relay.pairs.is_empty());
}

/// R40-M3 bound: at most four blind asks per peer are held at once (the
/// ±1 window under the current slot plus its asks under the previous one
/// after a rollover). The plan times out with its own asks: a rollover ask
/// still held then does not hold up the next plan.
#[test]
fn rollover_keeps_at_most_four_asks_and_never_delays_the_plan() {
    let (mut p, mut relay) = blind_pair_at(NOON - 300);
    let ps = ps_of(&p.a, &p.pb.hex);
    drop(relay.leave(1));
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    // The own ask times out: the ±1 window (two asks) under the slot.
    relay.expire_asks();
    p.a.pair_clock_override = Some(NOON - 300 + 280);
    p.a.fire_blind_timeouts(t0 + ASK_TTL + Duration::from_secs(1));
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(p.a.blind_asks.get(&p.pb.hex).map(Vec::len), Some(2));
    // The slot rolls over while the window waits: two rollover asks.
    p.a.pair_clock_override = Some(NOON + 5);
    let at = t0 + ASK_TTL + Duration::from_secs(30);
    p.a.fire_blind_timeouts(at);
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(p.a.blind_asks.get(&p.pb.hex).map(Vec::len), Some(4));
    assert_eq!(
        tokens_of(&relay, 0)[3..],
        [c(&ps, DAY, 0), c(&ps, DAY, 1)],
        "the window's epochs under the new slot"
    );
    // Further ticks in the same slot send nothing more.
    p.a.fire_blind_timeouts(at + Duration::from_secs(60));
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(tokens_of(&relay, 0).len(), 5);
    // The window's own asks run out (the rollover asks are still held):
    // the next plan (a plain own ask) goes at once, and the rollover asks
    // are retired with the window.
    p.a.fire_blind_timeouts(t0 + ASK_TTL * 2 + Duration::from_secs(2));
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(tokens_of(&relay, 0).len(), 6, "the next plan went");
    assert_eq!(p.a.blind_asks.get(&p.pb.hex).map(Vec::len), Some(1));
    assert!(relay.identity_asks.is_empty());
}

fn rate_limited(message: &str) -> Frame {
    Frame::Control(ControlMessage::Error {
        code: crate::protocol::ControlErrorCode::RateLimited,
        message: message.to_string(),
    })
}

/// Final review (RateLimited): a relay refusing our ask over its cap used
/// to be ignored, so the refused ask counted as held until its 600 s TTL.
/// Now the latest ask is taken as refused and asked again after a short
/// backoff (10 s, doubling, capped below the TTL); a refusal about the
/// offline queue is not about an ask and changes nothing.
#[test]
fn rate_limited_ask_is_retried_sooner_with_backoff() {
    let (mut p, mut relay) = blind_pair();
    p.a.ask_jitter_override = Some(0.0);
    drop(relay.leave(1));
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    assert_eq!(blind_tokens(&rx_controls(&mut p.a_rx)).len(), 1);
    // Not about an ask: ignored.
    feed(
        &mut p.a,
        rate_limited(&format!(
            "{}message 01234567 not stored",
            crate::protocol::OFFLINE_QUEUE_FULL_PREFIX
        )),
    );
    assert!(p.a.blind_asks.contains_key(&p.pb.hex));
    assert!(!p.a.pending_reasks.contains_key(&p.pb.hex));
    feed(
        &mut p.a,
        rate_limited("Too many pending circuit requests; try again later"),
    );
    assert!(!p.a.blind_asks.contains_key(&p.pb.hex), "taken as refused");
    let due = p.a.pending_reasks[&p.pb.hex];
    assert!(
        due <= Instant::now() + Duration::from_secs(10),
        "after 10 s"
    );
    // Not before it is due.
    p.a.fire_due_reasks(t0 + Duration::from_secs(5));
    assert!(blind_tokens(&rx_controls(&mut p.a_rx)).is_empty());
    let at = Instant::now() + Duration::from_secs(11);
    p.a.fire_due_reasks(at);
    assert_eq!(
        blind_tokens(&rx_controls(&mut p.a_rx)).len(),
        1,
        "asked again"
    );
    // Refused again: the backoff doubles.
    feed(
        &mut p.a,
        rate_limited("Too many pending circuit requests; try again later"),
    );
    let due = p.a.pending_reasks[&p.pb.hex];
    let after = due.saturating_duration_since(Instant::now());
    assert!(after > Duration::from_secs(19), "20 s now: {after:?}");
    assert!(after <= Duration::from_secs(20));
    // A refusal with no recent ask of ours to blame changes nothing.
    p.a.pending_reasks.clear();
    feed(&mut p.a, rate_limited("Too many circuits; try again later"));
    assert!(p.a.pending_reasks.is_empty());
}

/// Final review (RateLimited): the reconnect burst is spread. Past the
/// pacer's burst, blind re-pair asks wait for its rate instead of all going
/// at once into the relay's per-connection cap.
#[test]
fn reconnect_ask_burst_is_paced() {
    let (mut p, _relay) = blind_pair();
    // Two more contacts with sessions: C and D.
    let mut others = Vec::new();
    for (seed, circuits) in [
        (0xC3u8, (CircuitId([0x51; 16]), CircuitId([0x52; 16]))),
        (0xD4, (CircuitId([0x53; 16]), CircuitId([0x54; 16]))),
    ] {
        let (mut c, c_rx) = published(seed);
        let pc = peer(seed);
        p.a.peers.pin_card(&pc).unwrap();
        c.peers.pin_card(&p.pa).unwrap();
        reestablish_on(&mut p.a, &mut c, &p.pa, &pc, circuits);
        assert!(p
            .a
            .session_manager
            .get(&pc.hex)
            .unwrap()
            .pair_secret
            .is_some());
        others.push((c, c_rx));
    }
    p.a.ask_pacer.set_for_test(1, 4.0);
    let t0 = Instant::now();
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    assert_eq!(
        blind_tokens(&rx_controls(&mut p.a_rx)).len(),
        1,
        "the burst"
    );
    p.a.fire_due_reasks(t0 + Duration::from_millis(100));
    assert!(blind_tokens(&rx_controls(&mut p.a_rx)).is_empty(), "paced");
    p.a.fire_due_reasks(Instant::now() + Duration::from_millis(300));
    assert_eq!(
        blind_tokens(&rx_controls(&mut p.a_rx)).len(),
        1,
        "one per 250 ms"
    );
    p.a.fire_due_reasks(Instant::now() + Duration::from_millis(600));
    assert_eq!(
        blind_tokens(&rx_controls(&mut p.a_rx)).len(),
        1,
        "the third"
    );
    assert_eq!(p.a.blind_asks.len(), 3);
    drop(others);
}

/// Final review L1: a spent ask records the pair-secret lineage it was made
/// under. A stray match on it moves our epoch only for the same lineage
/// and the same peer: one from before an identity re-pair (a new PS) or
/// filed under another peer is ignored.
#[test]
fn stray_match_from_another_lineage_moves_nothing() {
    let (mut p, _relay) = blind_pair();
    let lineage = p.a.session_manager.get(&p.pb.hex).unwrap().pair_lineage();
    let spent = |lineage: Option<[u8; 32]>, peer: &str| crate::blind::SpentAsk {
        peer: peer.to_string(),
        epoch: PairEpoch {
            day: DAY,
            counter: 4,
        },
        sent_at: Instant::now(),
        lineage,
    };
    p.a.spent_blind_asks
        .insert([1; 32], spent(Some([9; 32]), &p.pb.hex));
    p.a.adopt_stray_blind_match(&p.pb.hex, &[1; 32]);
    assert_eq!(epoch_of(&p.a, &p.pb.hex).counter, 0, "other lineage");
    p.a.spent_blind_asks.insert([2; 32], spent(None, &p.pb.hex));
    p.a.adopt_stray_blind_match(&p.pb.hex, &[2; 32]);
    assert_eq!(epoch_of(&p.a, &p.pb.hex).counter, 0, "no lineage");
    p.a.spent_blind_asks
        .insert([3; 32], spent(lineage, &p.pa.hex));
    p.a.adopt_stray_blind_match(&p.pb.hex, &[3; 32]);
    assert_eq!(epoch_of(&p.a, &p.pb.hex).counter, 0, "another peer's");
    p.a.spent_blind_asks
        .insert([4; 32], spent(lineage, &p.pb.hex));
    p.a.adopt_stray_blind_match(&p.pb.hex, &[4; 32]);
    assert_eq!(epoch_of(&p.a, &p.pb.hex).counter, 5, "same lineage: synced");
}

/// Final review L2: a match never moves the stored epoch back. A match on
/// an older token (here the stored epoch already moved past it, as after a
/// busy advance) keeps the later stored epoch.
#[test]
fn a_match_on_an_older_token_never_moves_the_epoch_back() {
    let (mut p, _relay) = blind_pair();
    let later_epoch = PairEpoch {
        day: DAY,
        counter: 5,
    };
    p.a.session_manager.get_mut(&p.pb.hex).unwrap().pair_epoch = later_epoch;
    p.a.note_pair_match(
        &p.pb.hex,
        &[7; 32],
        Some(PairEpoch {
            day: DAY,
            counter: 1,
        }),
    );
    assert_eq!(epoch_of(&p.a, &p.pb.hex), later_epoch, "kept the later one");
    p.a.note_pair_match(&p.pb.hex, &[7; 32], Some(later_epoch));
    assert_eq!(
        epoch_of(&p.a, &p.pb.hex).counter,
        6,
        "advanced past a match"
    );
}

/// Final review L3: a `CircuitCreatedV3` echoing one of our asks whose peer
/// ephemeral signature fails (R7, as a relay forging it would) wipes none
/// of our other outstanding asks: they are dropped only after the frame
/// verifies.
#[test]
fn unverified_match_keeps_our_other_asks() {
    let (mut p, _relay) = blind_pair();
    p.a.handle_circuit_closed(C1);
    drain(&mut p.a_rx);
    p.a.send_blind_plan(&p.pb.hex, Instant::now(), crate::blind::BlindPlan::Window)
        .unwrap();
    let eks: Vec<Vec<u8>> = rx_controls(&mut p.a_rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAskBlind { ephemeral_key, .. } => Some(ephemeral_key),
            _ => None,
        })
        .collect();
    assert_eq!(eks.len(), 2);
    assert_eq!(p.a.peers.outstanding_asks(&p.pb.hex), 2);
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitCreatedV3 {
            circuit_id: CircuitId([0x61; 16]),
            token: TOKEN.to_vec(),
            target_circuit_id: CircuitId([0x62; 16]),
            role: 0,
            peer: crate::protocol::PeerBundle::from_signed(&p.pb.bundle),
            initiator_ephemeral_key: eks[0].clone(),
            responder_ephemeral_key: r_ek.to_vec(),
            initiator_kem_ephemeral_pk: crate::kem::KemKeyPair::generate().public().to_vec(),
            responder_kem_ephemeral_pk: crate::kem::KemKeyPair::generate().public().to_vec(),
            initiator_ephemeral_sig: vec![0; 64],
            responder_ephemeral_sig: vec![0; 64],
        }),
    );
    assert!(!p.a.has_live_circuit(&p.pb.hex));
    assert_eq!(
        p.a.peers.outstanding_asks(&p.pb.hex),
        1,
        "the other ask is still answerable"
    );
}

/// Final re-review N-1: the relay withholds B's flagged knock ("no prior
/// session", sent while B had lost its sessions) and delivers it to A after
/// the pair has re-paired blind. A's identity budget is free, so A acts on
/// it: it closes the blinded circuit and goes to the identity path, held
/// there by the flag. B's budget is spent, so B ignores A's identity knock
/// and stays blind. Asking only by identity, A would keep the pair apart
/// until B's daily fallback; with blind asks beside the identity ask (A
/// still holds the pair secret) the pair forms again, blind, within a few
/// ask TTLs.
#[test]
fn withheld_flagged_knock_after_a_blind_re_pair_causes_no_long_outage() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    assert_eq!(relay.pairs.last(), Some(&(0, 1, true)), "blind re-pair");
    let now = p.b.pair_now_unix();
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .last_identity_fallback_unix = Some(now - 3600);
    drain(&mut p.a_rx);
    let created_hour = p.a.session_manager.get(&p.pb.hex).unwrap().created_at_unix / 3600;
    feed(
        &mut p.a,
        queued(knock_from_no_prior(&p.pb, &p.pa, created_hour + 1)),
    );
    assert!(p.a.identity_wanted[&p.pb.hex].no_prior_session);
    let t0 = Instant::now();
    p.a.fire_due_reasks(t0 + Duration::from_secs(120));
    p.b.fire_due_reasks(t0 + Duration::from_secs(120));
    let pairs_mid = relay.pairs.len();
    run(&mut p, &mut relay);
    assert!(
        relay.identity_asks.iter().any(|(s, _, _)| *s == 0),
        "A asked by identity"
    );
    for k in 1..=3u32 {
        if relay.pairs.len() > pairs_mid {
            break;
        }
        step_ttls(&mut p, &mut relay, t0, k);
    }
    assert!(
        relay.pairs.len() > pairs_mid,
        "a new pair forms within three ask TTLs"
    );
    assert_eq!(relay.pairs.last().map(|x| x.2), Some(true), "blind");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
    assert!(
        !p.a.identity_wanted.contains_key(&p.pb.hex),
        "the install ends the identity path"
    );
}

/// Final re-review N-2: at most `MAX_HELD_BLIND_ASKS` (4) blind asks per
/// peer are held. Each ask past it retires the oldest: its ephemeral
/// secrets are wiped (gone from the ask ring) and it is remembered as
/// spent, so a match on it, if the relay still held it, syncs the epoch.
#[test]
fn a_blind_ask_past_four_held_retires_the_oldest() {
    use crate::blind::{BlindPlan, MAX_HELD_BLIND_ASKS};
    let (mut p, mut relay) = blind_pair();
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    let peer = p.pb.hex.clone();
    let mut sent: Vec<([u8; 32], Instant)> = p.a.blind_asks[&peer]
        .iter()
        .map(|a| (a.ek_pub, a.sent_at))
        .collect();
    assert_eq!(sent.len(), 1, "the reconnect's own ask");
    let t0 = Instant::now();
    for k in 1..=3u64 {
        let at = t0 + Duration::from_secs(k);
        p.a.send_blind_plan(&peer, at, BlindPlan::Window).unwrap();
        for a in &p.a.blind_asks[&peer] {
            if !sent.iter().any(|(ek, _)| *ek == a.ek_pub) {
                sent.push((a.ek_pub, a.sent_at));
            }
        }
        assert!(p.a.blind_asks[&peer].len() <= MAX_HELD_BLIND_ASKS);
    }
    assert_eq!(sent.len(), 7, "seven asks sent");
    let held: Vec<[u8; 32]> = p.a.blind_asks[&peer].iter().map(|a| a.ek_pub).collect();
    let newest: Vec<[u8; 32]> = sent[3..].iter().map(|(ek, _)| *ek).collect();
    assert_eq!(held, newest, "the four newest are held");
    for (ek, at) in &sent[..3] {
        assert!(p.a.spent_blind_asks.contains_key(ek), "remembered as spent");
        assert!(
            p.a.peers.take_ask(&peer, ek, *at).is_none(),
            "its ephemeral secrets are wiped"
        );
    }
    for (ek, at) in &sent[3..] {
        assert!(
            p.a.peers.take_ask(&peer, ek, *at).is_some(),
            "a held ask keeps its keys"
        );
    }
    let _ = rx_controls(&mut p.a_rx);
}

/// Final review P-1: with an identity ask and four blind asks held (a full
/// ring), a fifth blind ask retires the oldest blind ask first, so the ring
/// never overflows onto the identity ask's keys.
#[test]
fn a_fifth_blind_ask_keeps_the_identity_asks_keys() {
    use crate::blind::{BlindPlan, MAX_HELD_BLIND_ASKS};
    let (mut p, mut relay) = blind_pair();
    for side in [0, 1] {
        drop(relay.leave(side));
    }
    let peer = p.pb.hex.clone();
    let id_keys = crate::peers::AskKeys::generate();
    let id_ek = id_keys.ek.public_key().to_bytes();
    let t0 = Instant::now();
    p.a.peers.push_ask(&peer, id_keys, t0);
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    for k in 1..=3u64 {
        let at = t0 + Duration::from_secs(k);
        p.a.send_blind_plan(&peer, at, BlindPlan::Window).unwrap();
    }
    assert_eq!(p.a.blind_asks[&peer].len(), MAX_HELD_BLIND_ASKS);
    p.a.send_blind_plan(&peer, t0 + Duration::from_secs(4), BlindPlan::Window)
        .unwrap();
    assert_eq!(p.a.blind_asks[&peer].len(), MAX_HELD_BLIND_ASKS);
    assert!(
        p.a.peers
            .take_ask(&peer, &id_ek, t0 + Duration::from_secs(5))
            .is_some(),
        "the identity ask keeps its keys"
    );
    let _ = rx_controls(&mut p.a_rx);
}

/// One tick of the harness `k` ask TTLs after `t0` (clocks from `NOON`):
/// held asks expire at the relay, timeouts and re-asks fire on both sides.
fn tick_all(p: &mut Pair, relay: &mut FakeRelay, t0: Instant, k: u32) {
    let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
    p.a.pair_clock_override = Some(NOON + secs);
    p.b.pair_clock_override = Some(NOON + secs);
    relay.expire_asks();
    let at = t0 + Duration::from_secs(secs);
    p.a.fire_blind_timeouts(at);
    p.b.fire_blind_timeouts(at);
    p.a.fire_due_reasks(at);
    p.b.fire_due_reasks(at);
    run(p, relay);
}

/// A's timed identity fallback goes out while B is away and runs out
/// unanswered. Returns the tick count reached.
fn unanswered_fallback(p: &mut Pair, relay: &mut FakeRelay, t0: Instant) -> u32 {
    drop(relay.leave(1)); // B is gone
    reconnect_in_place(&mut p.a, &mut p.a_rx);
    pump_alone(relay, &mut p.a, &mut p.a_rx);
    let mut k = 0;
    while relay.identity_asks.is_empty() {
        k += 1;
        assert!(k <= 200, "the fallback fires");
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(relay, &mut p.a, &mut p.a_rx);
    }
    while p.a.identity_fallback.contains_key(&p.pb.hex) {
        k += 1;
        assert!(k <= 400, "the fallback ask runs out");
        let secs = u64::from(k) * (ASK_TTL.as_secs() + 1);
        p.a.pair_clock_override = Some(NOON + secs);
        relay.expire_asks();
        p.a.fire_blind_timeouts(t0 + Duration::from_secs(secs));
        pump_alone(relay, &mut p.a, &mut p.a_rx);
    }
    k
}

/// Seen on the owner's phones: A's timed identity fallback nobody answered
/// used to spend A's 24 h identity budget, so A then refused B's genuine
/// fallback knock ("identity budget spent; staying blind") and the pair
/// stayed apart. Only a completed identity re-pair counts now: A answers,
/// and the pair re-forms on the identity path.
#[test]
fn unanswered_fallback_does_not_block_answering_the_contacts_knock() {
    let (mut p, mut relay) = blind_pair();
    // B holds another pair secret: blind asks never meet, so B falls back too.
    p.b.session_manager.get_mut(&p.pa.hex).unwrap().pair_secret =
        Some(zeroize::Zeroizing::new([9; 32]));
    let t0 = Instant::now();
    let mut k = unanswered_fallback(&mut p, &mut relay, t0);
    assert_eq!(
        relay
            .identity_asks
            .iter()
            .filter(|(s, _, _)| *s == 0)
            .count(),
        1,
        "A's one fallback ask, unanswered"
    );
    assert!(relay.pairs.is_empty());
    // B comes back with its own fallback due.
    relay.join(1, &p.pb.bundle);
    let now = NOON + u64::from(k) * (ASK_TTL.as_secs() + 1);
    p.b.pair_clock_override = Some(now);
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .blind_since_unix = Some(now - IDENTITY_FALLBACK_AFTER_SECS - 60);
    reconnect_in_place(&mut p.b, &mut p.b_rx);
    let b_asks = relay
        .identity_asks
        .iter()
        .filter(|(s, _, _)| *s == 1)
        .count();
    assert_eq!(b_asks, 0);
    while relay.identity_asks.iter().all(|(s, _, _)| *s != 1) {
        k += 1;
        assert!(k <= 480, "B's fallback fires");
        tick_all(&mut p, &mut relay, t0, k);
    }
    // B's knock reached A. A answers within B's ask TTL.
    let at = t0 + Duration::from_secs(u64::from(k) * (ASK_TTL.as_secs() + 1) + 120);
    p.a.fire_due_reasks(at);
    run(&mut p, &mut relay);
    assert!(
        relay.identity_asks.iter().any(|(s, _, _)| *s == 1),
        "B fell back by identity"
    );
    assert!(!relay.pairs.is_empty(), "the pair re-forms");
    assert!(!relay.pairs[0].2, "an identity pair");
    assert!(p.a.has_live_circuit(&p.pb.hex) && p.b.has_live_circuit(&p.pa.hex));
}

/// Every identity ask carries a fresh knock, so with no limit on answers a
/// relay that never matches the asks and delivers each one-sided ask's knock
/// has A answer B, B answer A, and so on. One knock answer per pair per 24 h
/// (memory only) ends it; neither side's own attempt spends it. After 24 h
/// the contact is answered again.
#[test]
fn knock_answers_cannot_ping_pong() {
    let (mut p, mut relay) = blind_pair();
    reconnect_both(&mut p, &mut relay);
    let pairs = relay.pairs.len();
    // Blind asks never meet either, so nothing but knock answers asks.
    p.b.session_manager.get_mut(&p.pa.hex).unwrap().pair_secret =
        Some(zeroize::Zeroizing::new([9; 32]));
    let t0 = Instant::now();
    let hour = crate::circuits::now_hour();
    feed(&mut p.a, queued(knock_from(&p.pb, &p.pa, hour)));
    let per_side = |relay: &FakeRelay, side: usize| {
        relay
            .identity_asks
            .iter()
            .filter(|(s, _, _)| *s == side)
            .count()
    };
    for k in 1..=100u32 {
        tick_all(&mut p, &mut relay, t0, k); // about 16 h
    }
    assert_eq!(per_side(&relay, 0), 1, "A answered once");
    assert_eq!(per_side(&relay, 1), 1, "B answered once");
    assert_eq!(relay.pairs.len(), pairs, "no pair formed");
    // 24 h after A's answer, a fresh knock is answered again.
    let later = NOON + 25 * 3600;
    p.a.pair_clock_override = Some(later);
    feed(&mut p.a, queued(knock_from(&p.pb, &p.pa, hour)));
    p.a.fire_due_reasks(t0 + Duration::from_secs(25 * 3600));
    pump_alone(&mut relay, &mut p.a, &mut p.a_rx);
    assert_eq!(per_side(&relay, 0), 2, "answered again after 24 h");
}
