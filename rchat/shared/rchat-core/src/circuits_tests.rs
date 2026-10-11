//! Tests of `circuits.rs` (Task 14 minor: moved out of the 4800-line file).

use crate::circuits::AskTrigger;
use crate::crypto::EphemeralKeyPair;
use crate::keyauth;
use crate::peers::PeerKeyState;
use crate::protocol::CircuitCloseReason;
use crate::protocol::{ControlMessage, Frame, PeerBundle};
use crate::sealed;
use crate::test_support::*;
use crate::ClientInner;
use std::time::Duration;
use std::time::Instant;

fn closes(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> usize {
    sent_controls(rx)
        .into_iter()
        .filter(|m| matches!(m, ControlMessage::CloseCircuit { .. }))
        .count()
}

/// Published B that pinned A and has one outstanding ask; returns its EK pub.
fn responder_with_ask() -> (
    crate::ClientInner,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Peer,
    [u8; 32],
) {
    let (mut b, rx) = published(0xB2);
    let pa = peer(0xA1);
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek, Instant::now());
    (b, rx, pa, ek_pub)
}

/// P3 / M7d: a one-character message and a receipt both occupy the
/// 256-byte bucket on the wire; knocks stay exactly 2048 bytes (L3).
#[test]
fn ratchet_plaintexts_are_padded_and_knocks_are_not() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "x");
    let relays = sent_relays(&mut p.a_rx);
    // sealed: header 73 + AEAD tag 16 + sender 32 + kind 1 + ratchet header 40
    //         + ratchet nonce 24 + padded plaintext 256 + ratchet tag 16
    let expected = sealed::SEALED_HEADER_LEN + 16 + 33 + 40 + 24 + 256 + 16;
    assert_eq!(relays[0].payload.len(), expected);
    for r in relays {
        feed(&mut p.b, Frame::Relay(r));
    }
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"x")));
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // the app stored it (D36)
    let receipt = sent_relays(&mut p.b_rx);
    assert_eq!(
        receipt[0].payload.len(),
        expected,
        "receipts share the bucket"
    );

    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    assert_eq!(asks(&mut rx)[0].2.len(), sealed::KNOCK_PAYLOAD_LEN);
}

#[test]
fn established_pair_exchanges_text_both_ways() {
    let mut p = establish(0xA1, 0xB2);
    assert!(p.a.has_live_circuit(&p.pb.hex));
    assert!(p.b.has_live_circuit(&p.pa.hex));
    push_text(&p.a, &p.pb.hex, "hi B");
    relay_all(&mut p.a_rx, &mut p.b);
    push_text(&p.b, &p.pa.hex, "hi A");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(s, c, _) if *s == p.pa.hex && c == b"hi B")));
    assert!(p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(s, c, _) if *s == p.pb.hex && c == b"hi A")));
}

/// K3: swapped SPK → no session; transient bad_signature; CloseCircuit; can_send false; re-ask scheduled.
#[test]
fn k3_swapped_spk_is_transient_bad_signature() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let log = install_event_log(&mut b);
    let mut forged = pa.bundle.clone();
    forged.signed_pre_key = peer(0x33).bundle.signed_pre_key;
    feed(&mut b, created_v2(1, &forged, [0x11; 32], ek));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::BadSignature);
    assert_eq!(closes(&mut rx), 1);
    assert!(!b.has_live_circuit(&pa.hex));
    // can_send false: the send path refuses this peer before any wait.
    assert!(matches!(
        b.check_sendable(&pa.hex),
        Err(crate::RChatError::PeerKeyUnverified { .. })
    ));
    assert!(b.pending_reasks.contains_key(&pa.hex), "re-ask scheduled");
    assert!(log
        .lock()
        .unwrap()
        .contains(&Ev::PeerKey(pa.hex.clone(), 3, String::new())));
}

/// v2 bundles carry SPK == identity agreement key. A bundle validly signed
/// by the peer but naming a different SPK is refused like an unverifiable one.
#[test]
fn v2_signed_bundle_with_spk_not_equal_to_agreement_key_is_refused() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let ak = pa.bundle.identity_agreement_key;
    let other_spk = peer(0x34).bundle.signed_pre_key;
    let t = crate::keyauth::bundle_transcript(&pa.bundle.identity_key, &ak, &other_spk).unwrap();
    let odd = crate::keyauth::SignedBundle {
        identity_key: pa.bundle.identity_key,
        identity_agreement_key: ak,
        signed_pre_key: other_spk,
        bundle_signature: pa.id.sign(&t).to_bytes(),
    };
    assert!(
        crate::keyauth::verify_bundle(&odd).is_ok(),
        "the signature itself is valid"
    );
    feed(&mut b, created_v2(1, &odd, [0x11; 32], ek));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::BadSignature);
    assert_eq!(closes(&mut rx), 1);
}

/// C-13: the timer's purge drops retired sessions past 72 h, expired
/// asks, and a rotated contact's old-identity session after the grace.
#[test]
fn stale_sessions_and_asks_are_purged() {
    let mut p = establish(0xA1, 0xB2);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
    feed(&mut p.a, created_v2(0, &p.pb.bundle, i_ek, r_ek));
    assert_eq!(p.a.session_manager.retired_count(&p.pb.hex), 1);
    p.a.peers
        .push_ask(&p.pb.hex, EphemeralKeyPair::generate(), Instant::now());
    let now = Instant::now();
    p.a.purge_stale(now);
    assert_eq!(p.a.session_manager.retired_count(&p.pb.hex), 1, "young");
    assert_eq!(p.a.peers.outstanding_asks(&p.pb.hex), 1, "young");
    p.a.purge_stale(now + crate::peers::ASK_TTL + Duration::from_secs(1));
    assert_eq!(p.a.peers.outstanding_asks(&p.pb.hex), 0);
    // The retired session's age is wall-clock time (D31), not the tick's.
    p.a.session_manager
        .age_retired_for_test(&p.pb.hex, crate::session::RETIRED_MAX_AGE.as_secs() + 1);
    p.a.purge_stale(now);
    assert_eq!(p.a.session_manager.retired_count(&p.pb.hex), 0);
    assert!(p.a.session_manager.has_established_session(&p.pb.hex));

    // B's contact A rotated away to some new identity: A's session stays
    // for the grace period, then goes.
    let new_hex = peer(0x77).hex;
    p.b.peers.unpin(&p.pa.hex);
    p.b.rotated_from.insert(p.pa.hex.clone(), (new_hex, now));
    p.b.purge_stale(now + Duration::from_secs(3600));
    assert!(p.b.session_manager.has_established_session(&p.pa.hex));
    p.b.purge_stale(now + Duration::from_secs(crate::ROTATION_GRACE_SECS));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(p.b.rotated_from.is_empty());
}

/// C-8: a peer in sticky mismatch gets no circuit from a valid
/// CircuitCreatedV2, even one echoing a still-valid ask: no session, no
/// callback, nothing sent but the CloseCircuit.
#[test]
fn circuit_created_v2_honours_sticky_mismatch() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let log = install_event_log(&mut b);
    b.peers.mark_mismatch(&pa.hex);
    assert_eq!(b.peers.outstanding_asks(&pa.hex), 0, "asks dropped");
    // Even an ask that somehow survived is refused at step 1.
    let late = EphemeralKeyPair::generate();
    let late_pub = late.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, late, Instant::now());
    for echo in [ek, late_pub] {
        feed(&mut b, created_v2(1, &pa.bundle, [0x11; 32], echo));
    }
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert!(log.lock().unwrap().is_empty(), "no callback");
    let sent = sent_controls(&mut rx);
    assert_eq!(sent.len(), 2);
    assert!(sent
        .iter()
        .all(|m| matches!(m, ControlMessage::CloseCircuit { .. })));
    assert!(sent_relays(&mut rx).is_empty(), "no hello sync");
}

/// K4: mismatched pin → refused; sticky mismatch; event 2; send refused; no re-ask.
#[test]
fn k4_mismatched_pin_is_sticky_and_not_reasked() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let log = install_event_log(&mut b);
    let other_ak = peer(0x44).bundle.identity_agreement_key;
    let lying = bundle_with_ak(&pa, other_ak);
    feed(&mut b, created_v2(1, &lying, [0x11; 32], ek));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert_eq!(closes(&mut rx), 1);
    assert!(!b.pending_reasks.contains_key(&pa.hex));
    assert!(log
        .lock()
        .unwrap()
        .contains(&Ev::PeerKey(pa.hex.clone(), 2, hex::encode(other_ak))));
    assert!(matches!(
        b.check_sendable(&pa.hex),
        Err(crate::RChatError::PeerKeyRejected { .. })
    ));
}

/// K5 (F5 regression): the set_recipient ak wins; a relay-offered ak₂ is never used.
#[test]
fn k5_set_recipient_ak_wins_over_offered_ak() {
    let (mut b, _rx) = published(0xB2);
    let pa = peer(0xA1);
    let ak1 = hex::encode(pa.bundle.identity_agreement_key);
    b.apply_set_recipient(&pa.hex, Some(&ak1)).unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek, Instant::now());
    let ak2 = peer(0x55).bundle.identity_agreement_key;
    feed(
        &mut b,
        created_v2(1, &bundle_with_ak(&pa, ak2), [0x11; 32], ek_pub),
    );
    assert_eq!(
        b.peers.pin_for(&pa.hex),
        Some(pa.bundle.identity_agreement_key)
    );
    assert!(b.session_manager.get(&pa.hex).is_none());
}

/// K6: CircuitCreatedV2 from an unpinned or a blocked peer → CloseCircuit, no session.
#[test]
fn k6_unpinned_or_blocked_peer_is_closed() {
    let (mut b, mut rx) = published(0xB2);
    let pa = peer(0xA1);
    feed(&mut b, created_v2(1, &pa.bundle, [0x11; 32], [0x22; 32]));
    assert_eq!(closes(&mut rx), 1);
    assert!(b.session_manager.get(&pa.hex).is_none());
    b.peers.set_blocked(&pa.hex, true);
    feed(&mut b, created_v2(1, &pa.bundle, [0x11; 32], [0x22; 32]));
    assert_eq!(closes(&mut rx), 1);
    assert!(b.session_manager.get(&pa.hex).is_none());
}

/// K7: role 0 with an initiator EK that isn't mine → refused + re-ask;
/// role 1 with no matching outstanding ask → refused.
#[test]
fn k7_echo_checks_both_roles() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.peers
        .push_ask(&pb.hex, EphemeralKeyPair::generate(), Instant::now());
    feed(&mut a, created_v2(0, &pb.bundle, [0x99; 32], [0x22; 32]));
    assert!(a.session_manager.get(&pb.hex).is_none());
    assert_eq!(closes(&mut rx), 1);
    assert!(a.pending_reasks.contains_key(&pb.hex));
    assert_eq!(
        a.peers.outstanding_asks(&pb.hex),
        1,
        "a failed echo consumes nothing"
    );

    let (mut b, mut brx) = published(0xB2);
    let pa = peer(0xA1);
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    feed(&mut b, created_v2(1, &pa.bundle, [0x11; 32], [0x22; 32]));
    assert!(
        b.session_manager.get(&pa.hex).is_none(),
        "role 1 requires my own outstanding ask"
    );
    assert_eq!(closes(&mut brx), 1);
}

/// K8: a relay-substituted EK on either side fails the echo check; a
/// relay-chosen peer EK yields keys the real peer cannot reproduce.
#[test]
fn k8_relay_substituted_ek_cannot_reproduce_the_root() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    // The relay keeps A's own EK (echo passes) but swaps B's for one it chose.
    let relay_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, relay_ek));
    feed(&mut b, created_v2(1, &pa.bundle, i_ek, r_ek));
    assert!(a.session_manager.get(&pb.hex).is_some());
    assert!(b.session_manager.get(&pa.hex).is_some());
    push_text(&a, &pb.hex, "secret");
    relay_all(&mut a_rx, &mut b);
    assert!(
        !b_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(..))),
        "roots differ: nothing decrypts"
    );
}

/// K9: current_recipient never changes on CircuitCreatedV2 (F4).
#[test]
fn k9_current_recipient_untouched() {
    let (mut b, _rx, pa, ek) = responder_with_ask();
    let someone_else = "ee".repeat(32);
    b.current_recipient = Some(someone_else.clone());
    feed(
        &mut b,
        created_v2(
            1,
            &pa.bundle,
            EphemeralKeyPair::generate().public_key().to_bytes(),
            ek,
        ),
    );
    assert!(b.session_manager.get(&pa.hex).is_some());
    assert_eq!(b.current_recipient, Some(someone_else));
}

/// K12 (H1): record a CircuitCreatedV2 that B actually accepted and the
/// sealed traffic that followed, restart B's core, replay both → the frame
/// is refused (its EK is no longer in the ring) and the envelopes are not
/// delivered.
#[test]
fn k12_replay_after_restart_is_refused() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    let recorded_frame = created_v2(1, &pa.bundle, i_ek, r_ek);
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, recorded_frame.clone());
    assert!(
        b.session_manager.get(&pa.hex).is_some(),
        "the recorded frame was accepted once"
    );
    relay_all(&mut a_rx, &mut b); // hello sync
    push_text(&a, &pb.hex, "before restart");
    let recorded_packets = sent_relays(&mut a_rx);
    assert_eq!(recorded_packets.len(), 1);
    for pkt in recorded_packets.clone() {
        feed(&mut b, Frame::Relay(pkt));
    }
    assert!(
        b_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"before restart")),
        "the recorded envelope was delivered once"
    );

    // Restart B: same identity, pins restored, sessions and EK ring gone.
    let (mut b2, mut b2_rx) = published(0xB2);
    let log = install_event_log(&mut b2);
    b2.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    feed(&mut b2, recorded_frame);
    assert!(
        b2.session_manager.get(&pa.hex).is_none(),
        "replayed frame refused"
    );
    assert_eq!(closes(&mut b2_rx), 1);
    for pkt in recorded_packets {
        b2.handle_sealed_payload(&pkt.payload);
        feed(&mut b2, Frame::Relay(pkt));
    }
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(..))),
        "replayed envelopes not delivered"
    );
    assert!(b2.session_manager.get(&pa.hex).is_none());
}

/// K14: pinning an ak already pinned for another identity → AgreementKeyInUse;
/// a frame whose peer ak belongs to another identity is refused.
#[test]
fn k14_agreement_key_steering_is_refused() {
    let (mut b, mut rx) = published(0xB2);
    let (pa, pc) = (peer(0xA1), peer(0xC3));
    b.pin_peer(&pa.hex, &hex::encode(pa.bundle.identity_agreement_key))
        .unwrap();
    assert!(matches!(
        b.pin_peer(&pc.hex, &hex::encode(pa.bundle.identity_agreement_key)),
        Err(crate::RChatError::AgreementKeyInUse)
    ));
    b.pin_peer(&pc.hex, &hex::encode(pc.bundle.identity_agreement_key))
        .unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pc.hex, ek, Instant::now());
    // C presents A's agreement key (validly signed by C): refused.
    feed(
        &mut b,
        created_v2(
            1,
            &bundle_with_ak(&pc, pa.bundle.identity_agreement_key),
            [0x11; 32],
            ek_pub,
        ),
    );
    assert!(b.session_manager.get(&pc.hex).is_none());
    assert_eq!(closes(&mut rx), 1);
}

/// K15 (transient part): after a forged bad bundle, a later valid frame
/// establishes and clears the state. Nothing is persisted.
#[test]
fn k15_bad_signature_is_cleared_by_a_later_valid_frame() {
    let (mut b, _rx, pa, ek) = responder_with_ask();
    let mut forged = pa.bundle.clone();
    forged.bundle_signature[0] ^= 1;
    feed(&mut b, created_v2(1, &forged, [0x11; 32], ek));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::BadSignature);
    let ek2 = EphemeralKeyPair::generate();
    let ek2_pub = ek2.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek2, Instant::now());
    feed(
        &mut b,
        created_v2(
            1,
            &pa.bundle,
            EphemeralKeyPair::generate().public_key().to_bytes(),
            ek2_pub,
        ),
    );
    assert!(b.session_manager.get(&pa.hex).is_some());
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Pinned);
}

/// K17: a low-order relay-supplied EK (either role) → refused, no session.
#[test]
fn k17_low_order_relay_ek_is_refused() {
    let mut low = [0u8; 32];
    low[0] = 1;
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    feed(&mut b, created_v2(1, &pa.bundle, low, ek));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(closes(&mut rx), 1);

    let (mut a, mut arx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let eka = EphemeralKeyPair::generate();
    let eka_pub = eka.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, eka, Instant::now());
    feed(&mut a, created_v2(0, &pb.bundle, eka_pub, [0u8; 32]));
    assert!(a.session_manager.get(&pb.hex).is_none());
    assert_eq!(closes(&mut arx), 1);
}

/// K18 (L11): in mismatch, set_recipient(Some(same ak)) keeps mismatch
/// and sends no ask; set_recipient(Some(new ak)) re-pins and clears it.
#[test]
fn k18_repin_semantics() {
    let (mut b, mut rx) = published(0xB2);
    let pa = peer(0xA1);
    let ak = hex::encode(pa.bundle.identity_agreement_key);
    b.apply_set_recipient(&pa.hex, Some(&ak)).unwrap();
    b.peers.mark_mismatch(&pa.hex);
    drain(&mut rx);
    b.apply_set_recipient(&pa.hex, Some(&ak)).unwrap();
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert!(
        !sent_controls(&mut rx)
            .iter()
            .any(|m| matches!(m, ControlMessage::CircuitAsk { .. })),
        "no ask while in mismatch"
    );
    let new_ak = hex::encode(peer(0x66).bundle.identity_agreement_key);
    b.apply_set_recipient(&pa.hex, Some(&new_ak)).unwrap();
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Pinned);
    assert_eq!(b.peers.pin_for(&pa.hex).map(hex::encode), Some(new_ak));
}

#[test]
fn set_recipient_without_pin_or_blocked_is_refused() {
    let (mut b, _rx) = published(0xB2);
    let pa = peer(0xA1);
    assert!(matches!(
        b.apply_set_recipient(&pa.hex, None),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
    b.peers.set_blocked(&pa.hex, true);
    assert!(matches!(
        b.apply_set_recipient(&pa.hex, None),
        Err(crate::RChatError::PeerBlocked { .. })
    ));
    assert!(b.current_recipient.is_none());
}

/// N14 (core): unpin and block each send exactly one CloseCircuit for a live circuit.
#[test]
fn n14_unpin_and_block_close_the_live_circuit_once() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    p.a.unpin_peer(&p.pb.hex).unwrap();
    let sent = sent_controls(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C1));
    assert!(p.a.session_manager.get(&p.pb.hex).is_none());

    let mut q = establish(0xA1, 0xB2);
    drain(&mut q.b_rx);
    q.b.block_peer(&q.pa.hex, true).unwrap();
    let sent = sent_controls(&mut q.b_rx);
    assert_eq!(sent.len(), 1);
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C2));
    assert_eq!(q.b.peers.state(&q.pa.hex), PeerKeyState::Blocked);
}

/// Reconnect `inner` on a fresh outgoing channel: transport back, hello
/// answered, publish accepted. Returns the new channel's receiver.
fn reconnect_and_publish(inner: &mut crate::ClientInner) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    inner
        .websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(tx);
    inner.handle_transport_reconnected();
    feed_signaling(inner, hello_response([0x4f; 32]));
    feed_signaling(inner, publish_ok([0x56; 32]));
    assert!(inner.is_key_bundle_published, "publish accepted");
    rx
}

fn close_ids(sent: &[ControlMessage]) -> Vec<crate::protocol::CircuitId> {
    sent.iter()
        .filter_map(|m| match m {
            ControlMessage::CloseCircuit { circuit_id } => Some(circuit_id.clone()),
            _ => None,
        })
        .collect()
}

fn not_found(text: &str) -> Frame {
    Frame::Control(ControlMessage::Error {
        code: crate::protocol::ControlErrorCode::CircuitNotFound,
        message: text.to_string(),
    })
}

/// Re-review R-1: `CircuitNotFound` naming the circuit A believes is
/// live is handled like `CircuitClosed`: the circuit is forgotten and a
/// re-ask is scheduled under the backoff. An error naming another
/// circuit, or no circuit (an older relay), changes nothing.
#[test]
fn r1_circuit_not_found_for_a_live_circuit_detaches_and_reasks() {
    let mut p = establish(0xA1, 0xB2);
    let target =
        p.a.session_manager
            .get(&p.pb.hex)
            .and_then(|s| s.target_circuit_id.clone())
            .unwrap();
    assert!(p.a.has_live_circuit(&p.pb.hex));
    let prefix = crate::protocol::CIRCUIT_NOT_FOUND_PREFIX;
    for text in [
        "Circuit not found".to_string(),
        format!("{prefix}{}", hex::encode([0x99u8; 16])),
        format!("{prefix}zz"),
    ] {
        feed(&mut p.a, not_found(&text));
        assert!(p.a.has_live_circuit(&p.pb.hex), "unchanged by {text:?}");
        assert!(!p.a.pending_reasks.contains_key(&p.pb.hex));
    }
    feed(
        &mut p.a,
        not_found(&format!("{prefix}{}", hex::encode(target.0))),
    );
    assert!(!p.a.has_live_circuit(&p.pb.hex), "forgotten");
    assert!(
        p.a.pending_reasks.contains_key(&p.pb.hex),
        "re-ask scheduled under the backoff"
    );
    assert!(
        p.a.session_manager.get(&p.pb.hex).is_some(),
        "the ratchet is kept, as for CircuitClosed"
    );
}

/// Security review M-1: a block made while a reconnect is in progress
/// (no publish accepted on the new connection yet, so the relay would
/// ignore the close) is not sent then, and is sent first thing after the
/// publish is accepted, exactly once.
#[test]
fn m1_close_made_during_a_reconnect_is_sent_after_the_publish_is_accepted() {
    let mut q = establish(0xA1, 0xB2);
    q.b.bypass_frame_gate = false;
    q.b.handle_transport_disconnected();
    drain(&mut q.b_rx);
    q.b.block_peer(&q.pa.hex, true).unwrap();
    assert!(
        close_ids(&sent_controls(&mut q.b_rx)).is_empty(),
        "no close before the publish is accepted"
    );
    assert!(q.b.session_manager.get(&q.pa.hex).is_none());

    let mut rx = reconnect_and_publish(&mut q.b);
    let sent = sent_controls(&mut rx);
    assert_eq!(close_ids(&sent), vec![C2], "sent after the publish-ok");
    assert!(
        matches!(&sent[0], ControlMessage::CloseCircuit { .. }),
        "before any ask: {sent:?}"
    );
    assert!(q.b.pending_closes.is_empty());
    let mut rx = reconnect_and_publish(&mut q.b);
    assert!(close_ids(&sent_controls(&mut rx)).is_empty(), "sent once");
}

/// M-1: a close that could not be queued at all (offline: the transport
/// is gone before the core noticed) is kept and sent after the next
/// accepted publish; unpin and delete take the same path as block.
#[test]
fn m1_close_that_failed_while_offline_is_sent_after_the_next_publish_ok() {
    let mut q = establish(0xA1, 0xB2);
    q.b.bypass_frame_gate = false;
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    drop(dead_rx);
    q.b.websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(dead_tx);
    q.b.unpin_peer(&q.pa.hex).unwrap();
    assert_eq!(q.b.pending_closes, vec![C2], "kept, not dropped");
    q.b.handle_transport_disconnected();

    let mut rx = reconnect_and_publish(&mut q.b);
    assert_eq!(close_ids(&sent_controls(&mut rx)), vec![C2]);
    assert!(q.b.pending_closes.is_empty());
}

/// M-1, the restart path (client half): after a restart there is no
/// session, so the core has no circuit id to close. A peer blocked in
/// the pin book the app restores at launch is never resumed or asked,
/// even when its knock arrives; the relay's sweep then ends a pair whose
/// member is online but never resumed it (relay test
/// `m1_member_online_without_resume_loses_the_pair_after_the_grace`).
#[test]
fn m1_blocked_peer_from_the_restored_pin_book_is_never_resumed_or_asked() {
    let (a, me) = (peer(0xA1), peer(0xB2));
    let (mut b, mut rx) = inner_with_identity(0xB2);
    b.bypass_frame_gate = false;
    let mut book = crate::peers::PeerBook::default();
    book.pin(&a.hex, a.bundle.identity_agreement_key).unwrap();
    book.set_blocked(&a.hex, true);
    b.peers = book;
    b.is_connected = false;
    b.request_publish().unwrap();
    feed_signaling(&mut b, hello_response([0x4e; 32]));
    feed_signaling(&mut b, publish_ok([0x55; 32]));
    assert!(b.is_key_bundle_published);
    feed(
        &mut b,
        queued(knock_from(&a, &me, crate::circuits::now_hour())),
    );
    b.fire_due_reasks(Instant::now() + Duration::from_secs(700));
    let sent = sent_controls(&mut rx);
    assert!(
        !sent
            .iter()
            .any(|m| matches!(m, ControlMessage::CircuitAsk { .. })),
        "a blocked peer is never asked or resumed: {sent:?}"
    );
}

/// Fix round 2: pin changes staged while connecting go through the
/// same teardown as live ones — an unpin or block closes the circuit
/// and drops the session; re-staging the same pin changes nothing.
#[test]
fn staged_unpin_and_block_close_the_live_circuit() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    let mut staged = crate::peers::PeerBook::default();
    staged.unpin(&p.pb.hex);
    p.a.apply_staged_peers(staged);
    let sent = sent_controls(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C1));
    assert!(p.a.session_manager.get(&p.pb.hex).is_none());
    assert_eq!(p.a.peers.state(&p.pb.hex), PeerKeyState::None);

    let mut q = establish(0xA1, 0xB2);
    drain(&mut q.b_rx);
    let mut staged = crate::peers::PeerBook::default();
    staged.set_blocked(&q.pa.hex, true);
    q.b.apply_staged_peers(staged);
    let sent = sent_controls(&mut q.b_rx);
    assert_eq!(sent.len(), 1);
    assert!(q.b.session_manager.get(&q.pa.hex).is_none());
    assert_eq!(q.b.peers.state(&q.pa.hex), PeerKeyState::Blocked);

    let mut r = establish(0xA1, 0xB2);
    drain(&mut r.a_rx);
    let ak = r.a.peers.pin_for(&r.pb.hex).unwrap();
    let mut staged = crate::peers::PeerBook::default();
    staged.pin(&r.pb.hex, ak).unwrap();
    r.a.apply_staged_peers(staged);
    assert!(
        sent_controls(&mut r.a_rx).is_empty(),
        "same pin: circuit kept"
    );
    assert!(r.a.has_live_circuit(&r.pb.hex));
}

/// RF4: malformed CircuitCreatedV2 from a hostile relay → no panic,
/// CloseCircuit, no session, EK ring untouched.
#[test]
fn rf4_malformed_circuit_created_v2_is_refused_without_panic() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let good = PeerBundle::from_signed(&pa.bundle);
    let mut short_sig = good.clone();
    short_sig.bundle_signature.pop();
    let mut long_ak = good.clone();
    long_ak.identity_agreement_key.push(0);
    let cases: Vec<(u8, Vec<u8>, PeerBundle, Vec<u8>, Vec<u8>)> = vec![
        (7, TOKEN.to_vec(), good.clone(), vec![0x11; 32], ek.to_vec()),
        (1, TOKEN.to_vec(), good.clone(), vec![0x11; 31], ek.to_vec()),
        (
            1,
            TOKEN.to_vec(),
            good.clone(),
            vec![0x11; 32],
            ek[..31].to_vec(),
        ),
        (1, TOKEN.to_vec(), short_sig, vec![0x11; 32], ek.to_vec()),
        (1, TOKEN.to_vec(), long_ak, vec![0x11; 32], ek.to_vec()),
        (1, Vec::new(), good.clone(), vec![0x11; 32], ek.to_vec()),
        (1, vec![1; 31], good, vec![0x11; 32], ek.to_vec()),
    ];
    let n = cases.len();
    for (role, token, peer_bundle, i_ek, r_ek) in cases {
        feed(
            &mut b,
            Frame::Control(ControlMessage::CircuitCreatedV2 {
                circuit_id: C2,
                token,
                target_circuit_id: C1,
                role,
                peer: peer_bundle,
                initiator_ephemeral_key: i_ek,
                responder_ephemeral_key: r_ek,
            }),
        );
    }
    assert_eq!(closes(&mut rx), n);
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(b.peers.outstanding_asks(&pa.hex), 1, "ring untouched");
}

#[test]
fn role_zero_sends_hello_sync_and_reports_initiator() {
    let (mut a, mut rx) = published(0xA1);
    let log = install_event_log(&mut a);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, ek, Instant::now());
    feed(
        &mut a,
        created_v2(
            0,
            &pb.bundle,
            ek_pub,
            EphemeralKeyPair::generate().public_key().to_bytes(),
        ),
    );
    assert!(log
        .lock()
        .unwrap()
        .contains(&Ev::Established(pb.hex.clone(), true)));
    let relays = sent_relays(&mut rx);
    assert_eq!(relays.len(), 1, "invisible hello sync");
    assert_eq!(relays[0].circuit_id, C2, "sent on target_circuit_id");
    assert_eq!(a.peers.outstanding_asks(&pb.hex), 0, "matched EK consumed");
}

/// Step 8 / carry-forward: re-pairing goes through `install`, so the old
/// session stays as the single retired session and still decrypts
/// messages sealed before the switch; a third pairing keeps only one.
#[test]
fn re_pairing_keeps_exactly_one_retired_session() {
    let mut p = establish(0xA1, 0xB2);
    let late = p.a.seal_ratchet(&p.pb.hex, [9; 16], b"\x01late").unwrap();
    for round in 0..2 {
        let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
        let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
        p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
        p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
        feed(&mut p.a, created_v2(0, &p.pb.bundle, i_ek, r_ek));
        feed(&mut p.b, created_v2(1, &p.pa.bundle, i_ek, r_ek));
        relay_all(&mut p.a_rx, &mut p.b);
        assert_eq!(
            p.a.session_manager.retired_count(&p.pb.hex),
            1,
            "round {round}"
        );
        assert_eq!(
            p.b.session_manager.retired_count(&p.pa.hex),
            1,
            "round {round}"
        );
        if round == 0 {
            p.b.handle_sealed_payload(&late.payload);
            assert!(p
                .b_log
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"late")));
        }
    }
    push_text(&p.a, &p.pb.hex, "new");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"new")));
}

/// Task 12 minor: while a re-paired responder's new session can't send
/// yet (no message from the initiator on it), nothing is sealed on the
/// retired session instead; once the initiator's hello sync arrives,
/// the new session sends.
#[test]
fn a_waiting_new_session_never_falls_back_to_the_retired_one() {
    let mut p = establish(0xA1, 0xB2);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
    feed(&mut p.b, created_v2(1, &p.pa.bundle, i_ek, r_ek));
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 1);
    assert!(
        p.b.seal_ratchet(&p.pa.hex, [3; 16], b"\x01x").is_err(),
        "the responder waits for the new session, never uses the retired one"
    );
    feed(&mut p.a, created_v2(0, &p.pb.bundle, i_ek, r_ek));
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p.b.seal_ratchet(&p.pa.hex, [4; 16], b"\x01y").is_ok());
}

/// The seal path takes the recipient's agreement key from the pin store
/// only: with the pin gone, sealing fails even though a session exists.
#[test]
fn seal_uses_the_pinned_agreement_key_only() {
    let mut p = establish(0xA1, 0xB2);
    assert!(p.b.seal_ratchet(&p.pa.hex, [1; 16], b"\x01x").is_ok());
    p.b.peers.unpin(&p.pa.hex);
    assert!(p.b.session_manager.get(&p.pa.hex).is_some());
    assert!(matches!(
        p.b.seal_ratchet(&p.pa.hex, [2; 16], b"\x01x"),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
}

/// Unpin and block drop the retired session too, and a blocked sender's
/// envelopes are neither delivered nor held.
#[test]
fn block_drops_everything_from_the_peer() {
    let mut p = establish(0xA1, 0xB2);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
    feed(&mut p.b, created_v2(1, &p.pa.bundle, i_ek, r_ek));
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 1);
    let msg = p.a.seal_ratchet(&p.pb.hex, [3; 16], b"\x01x").unwrap();
    p.b.block_peer(&p.pa.hex, true).unwrap();
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    p.b.handle_sealed_payload(&msg.payload);
    assert!(
        p.b.pending_encrypted_messages.is_empty(),
        "nothing held from a blocked peer"
    );
    assert!(!p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(..))));
    let mut q = establish(0xA1, 0xB2);
    q.a.unpin_peer(&q.pb.hex).unwrap();
    assert_eq!(q.a.session_manager.retired_count(&q.pb.hex), 0);
    assert!(!q.a.has_live_circuit(&q.pb.hex));
}

/// §4.4 Sending: in mismatch, has_session and can_send are false.
#[test]
fn has_session_and_can_send_are_false_in_mismatch() {
    let p = establish(0xA1, 0xB2);
    let a_hex = p.pa.hex.clone();
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    *client.inner.try_write().unwrap() = p.b;
    assert!(client.has_session(a_hex.clone()));
    assert!(client.can_send(a_hex.clone()));
    assert_eq!(client.peer_key_state(a_hex.clone()), 1);
    client
        .inner
        .try_write()
        .unwrap()
        .peers
        .mark_mismatch(&a_hex);
    assert!(!client.has_session(a_hex.clone()));
    assert!(!client.can_send(a_hex.clone()));
    assert_eq!(client.peer_key_state(a_hex), 2);
}

/// Records each delivered message's content and whether it was text.
struct KindLog(std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, bool)>>>);
impl crate::RChatCallbacks for KindLog {
    fn on_connection_status_changed(&self, _: crate::ConnectionStatus) {}
    fn on_message_received(&self, m: crate::ReceivedMessage) {
        self.0.lock().unwrap().push((m.content, m.is_text));
    }
    fn on_message_delivered(&self, _: String) {}
    fn on_error(&self, _: String) {}
    fn on_circuit_established(&self, _: String, _: bool) {}
}

/// Media travel as binary plaintexts with a known magic (backlog: media
/// type); text stays text, prefix and all. No panic on peer input: an
/// unknown magic, a short or empty binary body and an empty plaintext
/// are dropped (this replaces the vacuous image-length test, Task 15).
#[test]
fn binary_plaintexts_need_a_known_magic() {
    let mut p = establish(0xA1, 0xB2);
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    p.b.callbacks = Some(Box::new(KindLog(log.clone())));
    let plaintexts: [&[u8]; 9] = [
        b"\x02IMG1jpeg",
        b"\x02VOCEm4a",
        b"\x02TXT1$$IMG$$:aGk=",
        b"\x01$$IMG$$:aGk=",
        b"\x02BSTPold",
        b"\x02IMG",
        b"\x02",
        b"",
        b"\x02TXT1\xff\xfe", // completion review L5: not UTF-8
    ];
    p.b.receipt_delay_override = Some(Duration::from_secs(60));
    for (n, pt) in plaintexts.iter().enumerate() {
        let msg = p.a.seal_ratchet(&p.pb.hex, [n as u8 + 10; 16], pt).unwrap();
        p.b.handle_sealed_payload(&msg.payload);
    }
    // The app confirms every id stored (D36): only those it was handed count.
    for n in 0..plaintexts.len() {
        p.b.mark_seen_and_receipt(&p.pa.hex, [n as u8 + 10; 16])
            .unwrap();
    }
    // Completion review L7: only the four accepted bodies got a DELIVERED
    // receipt queued; every dropped one got none.
    let queued =
        p.b.pending_receipts
            .get(&(p.pa.hex.clone(), crate::receipts::DELIVERED))
            .cloned()
            .unwrap_or_default();
    assert_eq!(
        queued,
        (10u8..14).map(|n| [n; 16]).collect::<Vec<_>>(),
        "a dropped body is never receipted"
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            (b"IMG1jpeg".to_vec(), false),
            (b"VOCEm4a".to_vec(), false),
            (b"TXT1$$IMG$$:aGk=".to_vec(), false),
            (b"$$IMG$$:aGk=".to_vec(), true),
        ]
    );
}

/// The sender refuses a binary body the receiver would drop.
#[test]
fn send_binary_refuses_an_unknown_magic() {
    assert!(!crate::protocol::is_known_binary(b"BSTPx"));
    assert!(!crate::protocol::is_known_binary(b"IMG"));
    assert!(crate::protocol::is_known_binary(b"IMG1"));
    assert!(crate::protocol::is_known_binary(b"VOCE\x00"));
    assert!(crate::protocol::is_known_binary(b"TXT1hi"));
    assert!(
        !crate::protocol::is_known_binary(b"TXT1\xff\xfe"),
        "TXT1 must be UTF-8"
    );
}

/// Fix round 1: messages queued on the responder are not sent while the
/// peer is in mismatch or bad signature (they stay queued), nor through
/// `send_queued_message`; once the peer is sendable they go out.
#[test]
fn queued_messages_respect_the_peer_key_state() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    feed(&mut b, created_v2(1, &pa.bundle, i_ek, r_ek));
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, r_ek));
    b.session_manager
        .get_mut(&pa.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(1, "held"));
    relay_all(&mut a_rx, &mut b); // hello: B can send now
    b.peers.mark_mismatch(&pa.hex);
    drain(&mut b_rx);
    let b = process_pending_on(b);
    assert!(
        sent_relays(&mut b_rx).is_empty(),
        "nothing sent in mismatch"
    );
    assert_eq!(
        b.session_manager
            .get(&pa.hex)
            .unwrap()
            .pending_messages
            .len(),
        1
    );

    // send_queued_message re-checks the state itself.
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    *client.inner.try_write().unwrap() = b;
    let r = client
        .runtime
        .block_on(crate::RChatClient::send_queued_message(
            client.inner.clone(),
            pa.hex.clone(),
            b"x",
            crate::protocol::MessageType::Text,
            [2; 16],
            true,
            false,
        ));
    assert!(matches!(r, Err(crate::RChatError::PeerKeyRejected { .. })));
    assert!(sent_relays(&mut b_rx).is_empty());
    let mut b = std::mem::replace(
        &mut *client.inner.try_write().unwrap(),
        crate::ClientInner::new(crate::ClientConfig::default()),
    );

    // Transient bad signature: still queued, then sent once cleared.
    let ak = pa.bundle.identity_agreement_key;
    b.peers.repin(&pa.hex, ak).unwrap(); // clears mismatch
    b.peers.mark_bad_signature(&pa.hex, Instant::now());
    let mut b = process_pending_on(b);
    assert!(
        sent_relays(&mut b_rx).is_empty(),
        "nothing sent with a bad signature"
    );
    b.peers.clear_bad_signature(&pa.hex);
    let b = process_pending_on(b);
    assert_eq!(sent_relays(&mut b_rx).len(), 1, "sent once sendable");
    assert!(b
        .session_manager
        .get(&pa.hex)
        .unwrap()
        .pending_messages
        .is_empty());
}

/// Fix round 1: messages queued on a session that is replaced are moved
/// to the new session (send_* already returned Ok for them).
#[test]
fn re_establishment_carries_queued_messages_over() {
    let mut p = establish(0xA1, 0xB2);
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(5, "carried"));
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
    feed(&mut p.a, created_v2(0, &p.pb.bundle, i_ek, r_ek));
    feed(&mut p.b, created_v2(1, &p.pa.bundle, i_ek, r_ek));
    relay_all(&mut p.a_rx, &mut p.b); // hello on the new session
    let a = process_pending_on(p.a);
    assert!(a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .pending_messages
        .is_empty());
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"carried")));
}

/// Fix round 1, C-1: a re-pin from the contact's code closes the circuit
/// and drops the session derived under the old pin (no retired copy);
/// queued messages wait for the session made under the new pin.
#[test]
fn repin_closes_and_forgets_the_old_session() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.b_rx);
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(6, "waits"));
    let new_ak = peer(0x66).bundle.identity_agreement_key;
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode(new_ak)))
        .unwrap();
    let sent = sent_controls(&mut p.b_rx);
    assert_eq!(
        sent.len(),
        2,
        "close the old circuit, ask under the new pin"
    );
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C2));
    assert!(matches!(&sent[1], ControlMessage::CircuitAsk { .. }));
    assert!(
        !p.b.session_manager.has_established_session(&p.pa.hex),
        "only a bare placeholder holding the queued message"
    );
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    assert!(!p.b.has_live_circuit(&p.pa.hex));
    // Same value again: no close (only a fresh user ask, since there is
    // still no live circuit).
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode(new_ak)))
        .unwrap();
    assert!(!sent_controls(&mut p.b_rx)
        .iter()
        .any(|m| matches!(m, ControlMessage::CloseCircuit { .. })));
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    // A session under the new pin picks up the queued message.
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    p.b.peers.push_ask(&p.pa.hex, ek, Instant::now());
    let i_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(
        &mut p.b,
        created_v2(1, &bundle_with_ak(&p.pa, new_ak), i_ek, ek_pub),
    );
    let s = p.b.session_manager.get(&p.pa.hex).unwrap();
    assert!(s.is_established);
    assert_eq!(s.pending_messages.len(), 1);
    assert_eq!(s.pending_messages[0].id.0, hex::encode([6u8; 16]));
    drop(s);
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
}

/// C-1: after a re-pin to a different key, an envelope only the old
/// session could decrypt (the impostor's ratchet) is never delivered:
/// not by a retired copy of the old session, and not replayed from the
/// hold buffer (a later re-pin drops what is held for the peer).
#[test]
fn old_session_envelope_is_not_delivered_after_a_repin() {
    let mut p = establish(0xA1, 0xB2);
    let held = p.a.seal_ratchet(&p.pb.hex, [7; 16], b"\x01held").unwrap();
    let after = p.a.seal_ratchet(&p.pb.hex, [8; 16], b"\x01after").unwrap();
    let ak_1 = peer(0x66).bundle.identity_agreement_key;
    let ak_2 = peer(0x67).bundle.identity_agreement_key;
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode(ak_1)))
        .unwrap();
    p.b.handle_sealed_payload(&held.payload);
    assert_eq!(p.b.pending_encrypted_messages.len(), 1, "held: no session");
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode(ak_2)))
        .unwrap();
    assert!(
        p.b.pending_encrypted_messages.is_empty(),
        "a re-pin drops what is held for the peer"
    );
    p.b.handle_sealed_payload(&held.payload);
    // A session under the new pin replays what is held, then live traffic.
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    p.b.peers.push_ask(&p.pa.hex, ek, Instant::now());
    let i_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(
        &mut p.b,
        created_v2(1, &bundle_with_ak(&p.pa, ak_2), i_ek, ek_pub),
    );
    assert!(p.b.session_manager.has_established_session(&p.pa.hex));
    p.b.handle_sealed_payload(&after.payload);
    assert!(
        !p.b_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(..))),
        "nothing from the old session is delivered"
    );
}

/// N-6: a re-pin also drops receipts owed for what the old session
/// decrypted and the ids sent over it.
#[test]
fn repin_drops_the_old_sessions_receipts_and_sent_ids() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(60));
    let old = push_text(&p.a, &p.pb.hex, "from the old session");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, old).unwrap();
    assert!(
        !p.b.pending_receipts.is_empty(),
        "a delivered receipt is owed"
    );
    let sent = push_text(&p.b, &p.pa.hex, "to the old session");
    assert!(p.b.was_sent_to(&p.pa.hex, &sent));
    let new_ak = peer(0x66).bundle.identity_agreement_key;
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode(new_ak)))
        .unwrap();
    assert!(p.b.pending_receipts.is_empty());
    assert!(!p.b.receipt_due.contains_key(&p.pa.hex));
    assert!(!p.b.was_sent_to(&p.pa.hex, &sent));
}

fn asks(
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Vec<(
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<crate::protocol::CircuitId>,
)> {
    sent_controls(rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk {
                target_identity,
                ephemeral_key,
                knock,
                resume_circuit,
            } => Some((target_identity, ephemeral_key, knock, resume_circuit)),
            _ => None,
        })
        .collect()
}

fn requests(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<crate::MessageRequest> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Request(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn user_ask_sends_circuit_ask_with_fresh_ek_and_2048_byte_knock() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let sent = asks(&mut rx);
    assert_eq!(sent.len(), 1);
    let (target, ek, knock, resume) = &sent[0];
    assert_eq!(target.as_slice(), &pb.bundle.identity_key);
    assert_eq!(ek.len(), 32);
    assert_eq!(knock.len(), crate::sealed::KNOCK_PAYLOAD_LEN);
    assert_eq!(
        *resume,
        Some(crate::circuits::ZERO_CIRCUIT),
        "no resume is the all-zero id"
    );
    assert_eq!(a.peers.outstanding_asks(&pb.hex), 1);
}

#[test]
fn asks_before_publish_are_deferred_then_sent() {
    let (mut a, mut rx) = published(0xA1);
    a.is_key_bundle_published = false; // as right after a reconnect, before the new publish is acknowledged
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    assert!(asks(&mut rx).is_empty());
    assert_eq!(a.deferred_asks, vec![pb.hex.clone()]);
    a.is_key_bundle_published = true;
    a.after_publish_ok(Instant::now());
    assert_eq!(asks(&mut rx).len(), 1, "flushed after publish ok");
    assert!(a.deferred_asks.is_empty());
}

/// Task 14 minor: a deferred ask whose send fails (the socket went again)
/// is kept for the next accepted publish, not dropped.
#[test]
fn a_deferred_ask_that_fails_to_send_is_kept() {
    let (mut a, rx) = published(0xA1);
    a.is_key_bundle_published = false;
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    drop(rx); // the connection is gone again: every send fails
    a.is_key_bundle_published = true;
    a.after_publish_ok(Instant::now());
    assert_eq!(
        a.deferred_asks,
        vec![pb.hex.clone()],
        "kept for the next publish"
    );
    // A peer no longer askable is not kept.
    a.peers.unpin(&pb.hex);
    a.after_publish_ok(Instant::now());
    assert!(a.deferred_asks.is_empty());
}

/// A scheduled re-ask that falls due between a reconnect and the new
/// publish acknowledgement is deferred, not sent.
#[test]
fn due_reasks_wait_for_the_publish_ack() {
    let (mut a, mut rx) = published(0xA1);
    a.ask_jitter_override = Some(0.0);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let t0 = Instant::now();
    a.ask(&pb.hex, crate::circuits::AskTrigger::Auto, t0)
        .unwrap();
    a.is_key_bundle_published = false; // the transport reconnected; new publish not yet acknowledged
    a.fire_due_reasks(t0 + Duration::from_secs(2));
    assert!(
        asks(&mut rx).is_empty(),
        "nothing sent before the publish ack"
    );
    assert_eq!(a.deferred_asks, vec![pb.hex.clone()]);
    a.is_key_bundle_published = true;
    a.after_publish_ok(t0 + Duration::from_secs(2));
    assert_eq!(asks(&mut rx).len(), 1, "sent after the publish ack");
}

/// A user ask while the circuit is live sends nothing (a resume-less ask
/// would make the relay tear the pair down, §6.2 step 2); after a
/// transport reconnect the same ask carries the resume (M9).
#[test]
fn user_ask_with_a_live_circuit_sends_nothing() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    assert!(p.a.has_live_circuit(&p.pb.hex));
    p.a.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    assert!(
        asks(&mut p.a_rx).is_empty(),
        "no CircuitAsk while the pair is live"
    );
    assert!(p.a.has_live_circuit(&p.pb.hex));
    p.a.transport_epoch += 1;
    p.a.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let sent = asks(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].3, Some(C1), "resume after reconnect");
}

#[test]
fn set_recipient_asks_for_a_pinned_peer_without_a_circuit() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.apply_set_recipient(
        &pb.hex,
        Some(&hex::encode(pb.bundle.identity_agreement_key)),
    )
    .unwrap();
    assert_eq!(asks(&mut rx).len(), 1);
    // K18: in mismatch, re-setting the same key sends nothing.
    a.peers.mark_mismatch(&pb.hex);
    a.apply_set_recipient(
        &pb.hex,
        Some(&hex::encode(pb.bundle.identity_agreement_key)),
    )
    .unwrap();
    assert!(asks(&mut rx).is_empty());
}

/// K15 (client): auto re-asks wait 2 s, then 4 s; success resets the schedule.
#[test]
fn k15_auto_reask_is_scheduled_with_backoff_and_reset_on_success() {
    let (mut a, mut rx) = published(0xA1);
    a.ask_jitter_override = Some(0.0);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let t0 = Instant::now();
    a.ask(&pb.hex, crate::circuits::AskTrigger::Auto, t0)
        .unwrap();
    assert!(asks(&mut rx).is_empty(), "never inline");
    assert_eq!(
        a.pending_reasks.get(&pb.hex),
        Some(&(t0 + Duration::from_secs(2)))
    );
    a.fire_due_reasks(t0 + Duration::from_secs(1));
    assert!(asks(&mut rx).is_empty());
    a.fire_due_reasks(t0 + Duration::from_secs(2));
    assert_eq!(asks(&mut rx).len(), 1);
    let t1 = t0 + Duration::from_secs(2);
    a.ask(&pb.hex, crate::circuits::AskTrigger::Auto, t1)
        .unwrap();
    assert_eq!(
        a.pending_reasks.get(&pb.hex),
        Some(&(t1 + Duration::from_secs(4)))
    );
    // A session established with an outstanding EK resets the schedule.
    let fresh = EphemeralKeyPair::generate();
    let fresh_pub = fresh.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, fresh, t1);
    feed(
        &mut a,
        created_v2(
            0,
            &pb.bundle,
            fresh_pub,
            EphemeralKeyPair::generate().public_key().to_bytes(),
        ),
    );
    assert_eq!(a.peers.backoff_mut(&pb.hex).attempts(), 0);
    assert!(!a.pending_reasks.contains_key(&pb.hex));
}

/// K16 (resume definition): Some(c) only for this run's established
/// session after a transport reconnect; None otherwise, and None after a restart.
#[test]
fn k16_resume_circuit_only_after_reconnect_for_this_runs_session() {
    let mut p = establish(0xA1, 0xB2);
    assert_eq!(
        p.a.resume_circuit_for(&p.pb.hex),
        None,
        "no reconnect since"
    );
    p.a.transport_epoch += 1;
    assert_eq!(p.a.resume_circuit_for(&p.pb.hex), Some(C1));
    assert!(
        !p.a.has_live_circuit(&p.pb.hex),
        "not live until the relay confirms"
    );
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
    assert!(p.a.has_live_circuit(&p.pb.hex));
    assert_eq!(p.a.resume_circuit_for(&p.pb.hex), None);
    let (restarted, _rx) = published(0xA1);
    assert_eq!(
        restarted.resume_circuit_for(&p.pb.hex),
        None,
        "no session after restart"
    );
}

#[test]
fn publish_ok_after_reconnect_sends_resume_asks() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    p.a.transport_epoch += 1;
    p.a.after_publish_ok(Instant::now());
    let sent = asks(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].3, Some(C1));
}

/// N1: a knock from an unpinned identity → one request; nothing sent; no session.
#[test]
fn n1_stranger_knock_becomes_a_quiet_request() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    let reqs = requests(&log);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].identity_hex, pa.hex);
    assert_eq!(
        reqs[0].agreement_hex,
        hex::encode(pa.bundle.identity_agreement_key)
    );
    assert!(drain(&mut rx).is_empty(), "outbound queue stays empty");
    assert!(b.session_manager.get(&pa.hex).is_none());
    // A replay of the same knock is de-duplicated.
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    assert_eq!(requests(&log).len(), 1);
}

/// N2: knock from a pinned peer without a circuit → one CircuitAsk (after
/// backoff); with a live circuit → nothing.
#[test]
fn n2_pinned_peer_knock_triggers_a_reask_only_without_circuit() {
    let (mut b, mut rx) = published(0xB2);
    b.ask_jitter_override = Some(0.0);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    assert!(b.pending_reasks.contains_key(&pa.hex));
    b.fire_due_reasks(Instant::now() + Duration::from_secs(3));
    assert_eq!(asks(&mut rx).len(), 1);

    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.b_rx);
    feed(
        &mut p.b,
        queued(knock_from(&p.pa, &p.pb, crate::circuits::now_hour())),
    );
    assert!(!p.b.pending_reasks.contains_key(&p.pa.hex));
    assert!(drain(&mut p.b_rx).is_empty());
}

/// N3: a knock from a blocked identity → nothing.
#[test]
fn n3_blocked_knock_is_dropped() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    b.peers.set_blocked(&pa.hex, true);
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    assert!(log.lock().unwrap().is_empty());
    assert!(drain(&mut rx).is_empty());
}

/// Body of a knock with a MAC computed for `mac_recipient`, sealed to `sealed_to`.
fn knock_with_mac_for(sender: &Peer, mac_recipient: &Peer, sealed_to: &Peer, hour: u64) -> Vec<u8> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let env = StaticSecret::from([0x45; 32]);
    let env_pub = PublicKey::from(&env).to_bytes();
    let keys = keyauth::knock_keys(
        sender.id.agreement_secret(),
        &mac_recipient.bundle.identity_agreement_key,
        &env_pub,
        &sender.bundle.identity_key,
        &mac_recipient.bundle.identity_key,
    )
    .unwrap();
    let mac = keyauth::knock_mac(
        &keys.k_mac,
        &mac_recipient.bundle.identity_key,
        &sender.bundle,
        hour,
    )
    .unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(&sender.bundle.identity_agreement_key);
    body.extend_from_slice(&sender.bundle.signed_pre_key);
    body.extend_from_slice(&sender.bundle.bundle_signature);
    body.extend_from_slice(&hour.to_be_bytes());
    body.extend_from_slice(&mac);
    body.push(0);
    body.resize(crate::knock::KNOCK_BODY_LEN, 0);
    sealed::seal_with(
        &env,
        [1; 24],
        [2; 16],
        &sealed_to.bundle.identity_key,
        &sealed_to.bundle.identity_agreement_key,
        &sender.bundle.identity_key,
        sealed::KIND_KNOCK,
        &body,
    )
    .unwrap()
}

/// N4: forged knocks are all dropped silently.
#[test]
fn n4_forged_knocks_are_dropped() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb, pc, pm) = (peer(0xA1), peer(0xB2), peer(0xC3), peer(0x4D));
    let now = crate::circuits::now_hour();
    let mut bad_mac = knock_with_mac_for(&pa, &pb, &pb, now);
    // Bad MAC: flip a byte of the MAC inside the body, re-sealed with the same envelope key.
    {
        let o = sealed::open(&pb.bundle.identity_key, pb.id.agreement_secret(), &bad_mac).unwrap();
        let mut body = o.body.clone();
        body[140] ^= 1;
        let env = x25519_dalek::StaticSecret::from([0x45; 32]);
        bad_mac = sealed::seal_with(
            &env,
            [1; 24],
            [2; 16],
            &pb.bundle.identity_key,
            &pb.bundle.identity_agreement_key,
            &pa.bundle.identity_key,
            sealed::KIND_KNOCK,
            &body,
        )
        .unwrap();
    }
    let forged: Vec<Vec<u8>> = vec![
        bad_mac,
        // MAC computed for a different recipient (C), sealed to B.
        knock_with_mac_for(&pa, &pc, &pb, now),
        // Older than knock_ttl_hours + 1 (72 + 1).
        knock_from(&pa, &pb, now - 74),
        // More than one hour in the future (L2).
        knock_from(&pa, &pb, now + 2),
        // A's bundle replayed with a MAC keyed from M's agreement key.
        crate::knock::build_knock_with(
            &pm.id,
            &pa.bundle,
            &pb.bundle.identity_key,
            &pb.bundle.identity_agreement_key,
            now,
            None,
            &x25519_dalek::StaticSecret::from([0x46; 32]),
            [3; 24],
            [4; 16],
            [5; 24],
            None,
        )
        .unwrap(),
        // Low-order sender agreement key (K17).
        crate::knock::build_knock(
            &pa.id,
            &bundle_with_ak(&pa, [0u8; 32]),
            &pb.bundle.identity_key,
            &pb.bundle.identity_agreement_key,
            now,
            None,
            None,
        )
        .unwrap(),
    ];
    for k in forged {
        feed(&mut b, queued(k));
    }
    // Sender ak pinned to another identity (M10): Y pins A's ak, then A knocks.
    let y = "99".repeat(32);
    b.peers.pin(&y, pa.bundle.identity_agreement_key).unwrap();
    feed(&mut b, queued(knock_from(&pa, &pb, now)));
    assert!(requests(&log).is_empty());
    assert!(drain(&mut rx).is_empty());
}

/// N5: a ratchet message from an unpinned or blocked identity is dropped, no receipt.
#[test]
fn n5_ratchet_from_unpinned_or_blocked_is_dropped() {
    let mut p = establish(0xA1, 0xB2);
    p.b.peers.unpin(&p.pa.hex); // keep the session; only the pin goes
    push_text(&p.a, &p.pb.hex, "unaccepted");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(!p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(..))));
    assert!(drain(&mut p.b_rx).is_empty(), "no receipt");
    assert!(
        p.b.pending_encrypted_messages.is_empty(),
        "not buffered either"
    );

    let mut q = establish(0xA1, 0xB2);
    q.b.peers.set_blocked(&q.pa.hex, true);
    push_text(&q.a, &q.pb.hex, "blocked");
    relay_all(&mut q.a_rx, &mut q.b);
    assert!(!q
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(..))));
    assert!(drain(&mut q.b_rx).is_empty());
}

/// N12 (client level, M2): the recipient alone can produce the knock's MAC.
#[test]
fn n12_recipient_reproduces_the_knock_mac() {
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let hour = crate::circuits::now_hour();
    let k = knock_from(&pa, &pb, hour);
    let o = sealed::open(&pb.bundle.identity_key, pb.id.agreement_secret(), &k).unwrap();
    let mac_in_knock = &o.body[136..168];
    let keys = keyauth::knock_keys(
        pb.id.agreement_secret(),
        &pa.bundle.identity_agreement_key,
        &o.env_eph_pub,
        &pa.bundle.identity_key,
        &pb.bundle.identity_key,
    )
    .unwrap();
    let recipient_made =
        keyauth::knock_mac(&keys.k_mac, &pb.bundle.identity_key, &pa.bundle, hour).unwrap();
    assert_eq!(mac_in_knock, &recipient_made[..]);
}

#[test]
fn circuit_closed_clears_the_circuit_and_schedules_a_reask() {
    let mut p = establish(0xA1, 0xB2);
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: C1,
            reason: CircuitCloseReason::Normal,
        }),
    );
    assert!(!p.a.has_live_circuit(&p.pb.hex));
    assert!(
        p.a.session_manager.get(&p.pb.hex).is_some(),
        "ratchet kept for queued messages"
    );
    assert!(p.a.pending_reasks.contains_key(&p.pb.hex));
}

/// RF3: after CircuitClosed, nothing goes out on the dead circuit, the
/// send is not reported as sent, and only the re-ask is queued.
#[test]
fn rf3_send_after_circuit_closed_puts_nothing_on_the_wire() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    p.a.send_wait_ms = 50;
    p.a.ask_jitter_override = Some(0.0);
    let peer_hex = p.pb.hex.clone();
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: C2,
            reason: CircuitCloseReason::Normal,
        }),
    );
    let client = wrap(p.a);
    assert!(!client.has_session(peer_hex.clone()));
    let sent = client.send_text_message(peer_hex.clone(), "after close".into());
    assert!(matches!(
        sent,
        Err(crate::RChatError::SessionNotEstablished { .. })
    ));
    client
        .inner
        .try_write()
        .unwrap()
        .fire_due_reasks(Instant::now() + Duration::from_secs(3));
    let frames = drain(&mut p.a_rx);
    assert!(
        frames
            .iter()
            .all(|f| f.first() != Some(&crate::protocol::FRAME_TYPE_RELAY)),
        "no relay frame on a dead circuit"
    );
    let reasks: Vec<(Vec<u8>, Option<crate::protocol::CircuitId>)> = frames
        .iter()
        .filter(|f| f.first() == Some(&crate::protocol::FRAME_TYPE_CONTROL))
        .filter_map(|f| ControlMessage::decode(f))
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk {
                target_identity,
                resume_circuit,
                ..
            } => Some((target_identity, resume_circuit)),
            _ => None,
        })
        .collect();
    assert_eq!(reasks.len(), 1, "exactly the scheduled re-ask goes out");
    assert_eq!(reasks[0].0.as_slice(), &p.pb.bundle.identity_key);
    assert_eq!(
        reasks[0].1,
        Some(crate::circuits::ZERO_CIRCUIT),
        "a closed circuit is never offered for resume"
    );
    assert_eq!(frames.len(), 1, "nothing else went out for this peer");
}

/// TM6: an ask encodes to the same length with and without a resume; the
/// client never sends `resume_circuit: None`.
#[test]
fn tm6_circuit_ask_has_one_size_with_and_without_resume() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    let (mut c, mut c_rx) = published(0xC3);
    c.peers
        .pin(&p.pb.hex, p.pb.bundle.identity_agreement_key)
        .unwrap();
    c.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let fresh = drain(&mut c_rx);
    p.a.transport_epoch += 1;
    p.a.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let resumed = drain(&mut p.a_rx);
    assert_eq!((fresh.len(), resumed.len()), (1, 1));
    assert_eq!(fresh[0].len(), resumed[0].len(), "same encoded size");
    let resume_of = |f: &Vec<u8>| match ControlMessage::decode(f) {
        Some(ControlMessage::CircuitAsk { resume_circuit, .. }) => resume_circuit,
        other => panic!("expected an ask, got {other:?}"),
    };
    assert_eq!(
        resume_of(&fresh[0]),
        Some(crate::circuits::ZERO_CIRCUIT),
        "no resume is the zero id, not None"
    );
    let resumed_id = resume_of(&resumed[0]);
    assert!(resumed_id.is_some() && resumed_id != Some(crate::circuits::ZERO_CIRCUIT));
}

/// End to end at the core level: set_recipient on both sides sends one
/// ask each, and a relay pairing those two EKs establishes both sessions.
#[test]
fn set_recipient_on_both_sides_establishes_from_the_asked_eks() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.apply_set_recipient(
        &pb.hex,
        Some(&hex::encode(pb.bundle.identity_agreement_key)),
    )
    .unwrap();
    b.apply_set_recipient(
        &pa.hex,
        Some(&hex::encode(pa.bundle.identity_agreement_key)),
    )
    .unwrap();
    let (a_ask, b_ask) = (asks(&mut a_rx), asks(&mut b_rx));
    assert_eq!((a_ask.len(), b_ask.len()), (1, 1));
    let i_ek: [u8; 32] = a_ask[0].1.clone().try_into().unwrap();
    let r_ek: [u8; 32] = b_ask[0].1.clone().try_into().unwrap();
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v2(1, &pa.bundle, i_ek, r_ek));
    assert!(a.has_live_circuit(&pb.hex));
    assert!(b.has_live_circuit(&pa.hex));
    relay_all(&mut a_rx, &mut b); // hello sync
    push_text(&b, &pa.hex, "hi");
    let a_log = install_event_log(&mut a);
    relay_all(&mut b_rx, &mut a);
    assert!(a_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(s, c, _) if *s == pb.hex && c == b"hi")));
    assert!(b_log
        .lock()
        .unwrap()
        .contains(&Ev::Established(pa.hex.clone(), false)));
}

/// Public send path: a mismatched or unverified peer is refused at once,
/// without waiting out `send_wait_ms`.
#[test]
fn send_refuses_mismatch_and_bad_signature_without_waiting() {
    let mut p = establish(0xA1, 0xB2);
    p.a.send_wait_ms = 30_000;
    let peer_hex = p.pb.hex.clone();
    p.a.peers.mark_mismatch(&peer_hex);
    let client = wrap(p.a);
    let started = Instant::now();
    assert!(matches!(
        client.send_text_message(peer_hex.clone(), "x".into()),
        Err(crate::RChatError::PeerKeyRejected { .. })
    ));
    {
        let mut g = client.inner.try_write().unwrap();
        let ak = g.peers.pin_for(&peer_hex).unwrap();
        g.peers.repin(&peer_hex, ak).unwrap();
        g.peers.mark_bad_signature(&peer_hex, Instant::now());
    }
    assert!(matches!(
        client.send_text_message(peer_hex.clone(), "x".into()),
        Err(crate::RChatError::PeerKeyUnverified { .. })
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no wait before refusing"
    );
    assert!(sent_relays(&mut p.a_rx).is_empty());
}

/// `request_circuit` asks an accepted peer and refuses everyone else.
#[test]
fn request_circuit_asks_only_accepted_peers() {
    let (mut a, mut rx) = published(0xA1);
    let (pb, pc) = (peer(0xB2), peer(0xC3));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.peers.set_blocked(&pc.hex, true);
    let client = wrap(a);
    client.request_circuit(pb.hex.to_uppercase()).unwrap();
    assert_eq!(asks(&mut rx).len(), 1);
    assert!(matches!(
        client.request_circuit(pc.hex.clone()),
        Err(crate::RChatError::PeerBlocked { .. })
    ));
    assert!(matches!(
        client.request_circuit(peer(0xD4).hex),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
    assert!(asks(&mut rx).is_empty());
}

/// Fix 1: resumes never grow the backoff, and an accepted resume resets
/// it, so after many reconnects a CircuitClosed re-asks at the base delay.
#[test]
fn resume_rounds_keep_the_backoff_at_its_base() {
    let mut p = establish(0xA1, 0xB2);
    p.a.ask_jitter_override = Some(0.0);
    drain(&mut p.a_rx);
    for round in 0..12 {
        p.a.transport_epoch += 1;
        p.a.after_publish_ok(Instant::now());
        let sent = asks(&mut p.a_rx);
        assert_eq!(sent.len(), 1, "round {round}");
        assert_eq!(sent[0].3, Some(C1));
        feed(
            &mut p.a,
            Frame::Control(ControlMessage::CircuitExists {
                circuit_id: C1,
                token: TOKEN.to_vec(),
                target_circuit_id: C2,
                is_initiator: true,
            }),
        );
        assert!(p.a.has_live_circuit(&p.pb.hex));
    }
    assert_eq!(p.a.peers.backoff_mut(&p.pb.hex).attempts(), 0);
    let before = Instant::now();
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: C1,
            reason: CircuitCloseReason::Normal,
        }),
    );
    let due = *p.a.pending_reasks.get(&p.pb.hex).unwrap();
    assert!(due >= before + Duration::from_secs(2));
    assert!(
        due <= Instant::now() + Duration::from_secs(2),
        "base delay, not capped"
    );
}

/// Fix 2: after a re-pin, a replayed knock carrying the old agreement key
/// (issued no later than the pin) is ignored; a newer one marks mismatch,
/// and the key event fires once, not on every repeat.
#[test]
fn old_key_knock_replayed_after_repin_is_ignored() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let new_ak = peer(0x66).bundle.identity_agreement_key;
    b.apply_set_recipient(&pa.hex, Some(&hex::encode(new_ak)))
        .unwrap();
    drain(&mut rx);
    let hour = crate::circuits::now_hour();
    feed(&mut b, queued(knock_from(&pa, &pb, hour)));
    assert_eq!(
        b.peers.state(&pa.hex),
        PeerKeyState::Pinned,
        "replay ignored"
    );
    assert!(log.lock().unwrap().is_empty());
    feed(&mut b, queued(knock_from(&pa, &pb, hour + 1)));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    feed(&mut b, queued(knock_from(&pa, &pb, hour + 1)));
    let events: Vec<Ev> = log.lock().unwrap().clone();
    assert_eq!(
        events,
        vec![Ev::PeerKey(
            pa.hex.clone(),
            2,
            hex::encode(pa.bundle.identity_agreement_key)
        )],
        "one event per state change"
    );
    assert!(asks(&mut rx).is_empty());
}

/// Fix 3: a knock that marks mismatch closes the live circuit.
#[test]
fn mismatch_knock_closes_the_live_circuit() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.b_rx);
    let other_ak = peer(0x66).bundle.identity_agreement_key;
    p.b.peers.repin(&p.pa.hex, other_ak).unwrap();
    feed(
        &mut p.b,
        queued(knock_from(&p.pa, &p.pb, crate::circuits::now_hour())),
    );
    assert_eq!(p.b.peers.state(&p.pa.hex), PeerKeyState::Mismatch);
    let sent = sent_controls(&mut p.b_rx);
    assert_eq!(sent.len(), 1);
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C2));
    assert!(!p.b.has_live_circuit(&p.pa.hex));
}

/// Fix 4: a due re-ask that can't be sent is kept for the next publish ack.
#[test]
fn unsendable_due_reask_is_deferred_not_lost() {
    let (mut a, _rx) = published(0xA1);
    a.ask_jitter_override = Some(0.0);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let t0 = Instant::now();
    a.ask(&pb.hex, crate::circuits::AskTrigger::Auto, t0)
        .unwrap();
    a.websocket = None; // the send fails
    a.fire_due_reasks(t0 + Duration::from_secs(3));
    assert_eq!(a.deferred_asks, vec![pb.hex.clone()]);
}

/// Fix 5 (client): a knock with a newer issued hour is a new request.
#[test]
fn newer_knock_from_a_stranger_is_a_new_request() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let hour = crate::circuits::now_hour();
    feed(&mut b, queued(knock_from(&pa, &pb, hour - 1)));
    feed(&mut b, queued(knock_from(&pa, &pb, hour - 1)));
    feed(&mut b, queued(knock_from(&pa, &pb, hour)));
    let hours: Vec<u64> = requests(&log).iter().map(|r| r.issued_hour).collect();
    assert_eq!(hours, vec![hour - 1, hour]);
    assert!(drain(&mut rx).is_empty());
}

/// Fix 6 (N5): a mismatched sender's ratchet body is dropped; a sender
/// with a transient bad signature is still accepted.
#[test]
fn n5_mismatch_sender_dropped_bad_signature_sender_accepted() {
    let mut p = establish(0xA1, 0xB2);
    p.b.peers.mark_mismatch(&p.pa.hex);
    push_text(&p.a, &p.pb.hex, "mismatch");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(!p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(..))));
    assert!(drain(&mut p.b_rx).is_empty(), "no receipt");
    assert!(p.b.pending_encrypted_messages.is_empty());

    let mut q = establish(0xA1, 0xB2);
    q.b.peers.mark_bad_signature(&q.pa.hex, Instant::now());
    push_text(&q.a, &q.pb.hex, "transient");
    relay_all(&mut q.a_rx, &mut q.b);
    assert!(q
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(_, c, _) if c == b"transient")));
}

// ---- Task 15: intros, message ids, de-duplication ----

use crate::knock::{Intro, KNOCK_BODY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use x25519_dalek::{PublicKey as XPub, StaticSecret};

const ENV: [u8; 32] = [0x45; 32];

fn intro_knock(sender: &Peer, recipient: &Peer, hour: u64, intro: Option<&Intro>) -> Vec<u8> {
    crate::knock::build_knock_with(
        &sender.id,
        &sender.bundle,
        &recipient.bundle.identity_key,
        &recipient.bundle.identity_agreement_key,
        hour,
        intro,
        &StaticSecret::from(ENV),
        [1; 24],
        [2; 16],
        [3; 24],
        None,
    )
    .unwrap()
}

fn body_of(recipient: &Peer, knock: &[u8]) -> Vec<u8> {
    sealed::open(
        &recipient.bundle.identity_key,
        recipient.id.agreement_secret(),
        knock,
    )
    .unwrap()
    .body
}

/// Re-seal a (possibly edited) knock body with the same envelope key, so
/// the knock MAC and k_intro (salted with env_eph_pub) stay as they were.
fn reseal(sender: &Peer, recipient: &Peer, body: &[u8]) -> Vec<u8> {
    sealed::seal_with(
        &StaticSecret::from(ENV),
        [1; 24],
        [2; 16],
        &recipient.bundle.identity_key,
        &recipient.bundle.identity_agreement_key,
        &sender.bundle.identity_key,
        sealed::KIND_KNOCK,
        body,
    )
    .unwrap()
}

/// Replace the intro block with one encrypting `pt` under the real k_intro.
fn craft_intro(sender: &Peer, recipient: &Peer, body: &mut Vec<u8>, pt: &[u8]) {
    let env_pub = XPub::from(&StaticSecret::from(ENV)).to_bytes();
    let keys = keyauth::knock_keys(
        sender.id.agreement_secret(),
        &recipient.bundle.identity_agreement_key,
        &env_pub,
        &sender.bundle.identity_key,
        &recipient.bundle.identity_key,
    )
    .unwrap();
    let mut aad = Vec::new();
    aad.extend_from_slice(&sender.bundle.identity_key);
    aad.extend_from_slice(&recipient.bundle.identity_key);
    aad.extend_from_slice(&body[136..168]);
    let ct = XChaCha20Poly1305::new_from_slice(&keys.k_intro)
        .unwrap()
        .encrypt(XNonce::from_slice(&[3; 24]), Payload { msg: pt, aad: &aad })
        .unwrap();
    body.truncate(168);
    body.push(0x01);
    body.extend_from_slice(&[3; 24]);
    body.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    body.extend_from_slice(&ct);
    body.resize(KNOCK_BODY_LEN, 0);
}

fn intro_pt(text: &[u8], declared_len: u16) -> Vec<u8> {
    let mut pt = vec![7u8; 16];
    pt.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
    pt.extend_from_slice(&declared_len.to_be_bytes());
    pt.extend_from_slice(text);
    pt
}

/// N7: intro round trip; the recipient creates no session and sends nothing.
#[test]
fn n7_intro_round_trip_without_session_or_frames() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let intro_id = a
        .set_intro(&pb.hex, "hello from A", Instant::now())
        .unwrap();
    assert!(
        drain(&mut a_rx).is_empty(),
        "no outstanding ask, so nothing sent yet"
    );
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let knock = asks(&mut a_rx).remove(0).2;
    feed(&mut b, queued(knock));
    let reqs = requests(&log);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].identity_hex, pa.hex);
    assert_eq!(reqs[0].intro_text, "hello from A");
    assert_eq!(reqs[0].intro_message_id_hex, intro_id);
    assert!(reqs[0].intro_sent_at_ms > 0);
    assert!(drain(&mut b_rx).is_empty());
    assert!(b.session_manager.get(&pa.hex).is_none());
}

/// N8: intro tampering drops only the intro; the request survives.
#[test]
fn n8_tampered_intros_drop_only_the_intro() {
    let (pa, pb, pc) = (peer(0xA1), peer(0xB2), peer(0xC3));
    let hour = crate::circuits::now_hour();
    let intro = Intro {
        message_id: [9; 16],
        sent_at_ms: 5,
        text: "hi".into(),
    };
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // (a) a flipped ciphertext bit
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, Some(&intro)));
    body[169 + 26] ^= 1;
    cases.push(reseal(&pa, &pb, &body));
    // (b) aad_intro bound to a different knock_mac (intro block from an earlier-hour knock)
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, Some(&intro)));
    let other = body_of(&pb, &intro_knock(&pa, &pb, hour - 1, Some(&intro)));
    body[169..].copy_from_slice(&other[169..]);
    cases.push(reseal(&pa, &pb, &body));
    // (c) an intro keyed with a different sender's agreement key (C's block in A's knock)
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, None));
    let c_body = body_of(&pb, &intro_knock(&pc, &pb, hour, Some(&intro)));
    body[168] = 0x01;
    body[169..].copy_from_slice(&c_body[169..]);
    cases.push(reseal(&pa, &pb, &body));
    // (d) text_len > 1024
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, None));
    craft_intro(&pa, &pb, &mut body, &intro_pt(&[b'x'; 1025], 1025));
    cases.push(reseal(&pa, &pb, &body));
    // (e) invalid UTF-8
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, None));
    craft_intro(&pa, &pb, &mut body, &intro_pt(&[0xff, 0xfe], 2));
    cases.push(reseal(&pa, &pb, &body));

    for knock in cases {
        let (mut b, _rx) = published(0xB2);
        let log = install_event_log(&mut b);
        feed(&mut b, queued(knock));
        let reqs = requests(&log);
        assert_eq!(reqs.len(), 1, "the request survives");
        assert_eq!(reqs[0].intro_text, "");
        assert_eq!(reqs[0].intro_message_id_hex, "");
    }
}

/// A re-armed intro keeps the id the app passes: it is the queued intro's
/// id and recorded as sent; the other set_intro rules still apply.
#[test]
fn set_intro_with_id_uses_the_preset_id() {
    let (mut a, _rx) = published(0xA1);
    let pb = peer(0xB2);
    let now = Instant::now();
    let preset = [0x5au8; 16];
    assert!(matches!(
        a.set_intro_with_id(&pb.hex, "x", Some(preset), now),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    assert!(matches!(
        a.set_intro_with_id(&pb.hex, "", Some(preset), now),
        Err(crate::RChatError::Internal { .. })
    ));
    let id = a
        .set_intro_with_id(&pb.hex, "again", Some(preset), now)
        .unwrap();
    assert_eq!(id, hex::encode(preset));
    assert_eq!(a.intros.get(&pb.hex).map(|i| i.message_id), Some(preset));
    assert_eq!(
        a.intros.get(&pb.hex).map(|i| i.text.as_str()),
        Some("again")
    );
    assert!(a.was_sent_to(&pb.hex, &preset));
    assert!(
        matches!(
            a.set_intro_with_id(&pb.hex, "again", Some(preset), now),
            Err(crate::RChatError::Internal { .. })
        ),
        "refused while an intro is queued"
    );
}

/// N9: set_intro refusals; a pinned peer's intro is ignored; one report per intro id.
#[test]
fn n9_intro_limits() {
    let (mut a, _rx) = published(0xA1);
    let pb = peer(0xB2);
    let now = Instant::now();
    assert!(matches!(
        a.set_intro(&pb.hex, "x", now),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    assert!(matches!(
        a.set_intro(&pb.hex, "", now),
        Err(crate::RChatError::Internal { .. })
    ));
    assert!(matches!(
        a.set_intro(&pb.hex, &"x".repeat(1025), now),
        Err(crate::RChatError::Internal { .. })
    ));
    assert!(matches!(
        a.set_intro(&pb.hex, "a\0b", now),
        Err(crate::RChatError::Internal { .. })
    ));
    a.set_intro(&pb.hex, "first", now).unwrap();
    assert!(matches!(
        a.set_intro(&pb.hex, "second", now),
        Err(crate::RChatError::Internal { .. })
    ));
    let mut p = establish(0xA1, 0xB2);
    assert!(
        matches!(
            p.a.set_intro(&p.pb.hex, "late", now),
            Err(crate::RChatError::Internal { .. })
        ),
        "session exists"
    );

    // Pinned sender: intro ignored, no request, a re-ask is scheduled instead.
    let (mut b, _brx) = published(0xB2);
    let log = install_event_log(&mut b);
    let pa = peer(0xA1);
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let intro = Intro {
        message_id: [1; 16],
        sent_at_ms: 1,
        text: "hey".into(),
    };
    feed(
        &mut b,
        queued(intro_knock(
            &pa,
            &peer(0xB2),
            crate::circuits::now_hour(),
            Some(&intro),
        )),
    );
    assert!(requests(&log).is_empty());
    assert!(b.pending_reasks.contains_key(&pa.hex));

    // Unpinned: the same (identity, intro id) is reported once; a new intro id is new.
    let (mut c, _crx) = published(0xB2);
    let log = install_event_log(&mut c);
    let hour = crate::circuits::now_hour();
    feed(
        &mut c,
        queued(intro_knock(&pa, &peer(0xB2), hour, Some(&intro))),
    );
    feed(
        &mut c,
        queued(intro_knock(&pa, &peer(0xB2), hour, Some(&intro))),
    );
    let other = Intro {
        message_id: [2; 16],
        ..intro.clone()
    };
    feed(
        &mut c,
        queued(intro_knock(&pa, &peer(0xB2), hour, Some(&other))),
    );
    assert_eq!(requests(&log).len(), 2);
    drain(&mut p.a_rx);
}

/// N10: a message id the app already has is decrypted (chain advances)
/// but not delivered again.
#[test]
fn n10_seen_message_is_decrypted_but_not_delivered() {
    let mut p = establish(0xA1, 0xB2);
    let dup = push_text(&p.a, &p.pb.hex, "intro text again");
    p.b.peers.mark_seen(&p.pa.hex, dup);
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(!p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(..))));
    let next = push_text(&p.a, &p.pb.hex, "next");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(
        p.b_log.lock().unwrap().iter().any(
            |e| matches!(e, Ev::Message(_, c, id) if c == b"next" && *id == hex::encode(next))
        ),
        "the chain stayed in step"
    );
}

/// N11: setting an intro while an ask is outstanding sends exactly one new ask, carrying it.
#[test]
fn n11_reask_with_intro_sends_exactly_one_ask() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    drain(&mut rx);
    a.set_intro(&pb.hex, "with intro", Instant::now()).unwrap();
    let sent = asks(&mut rx);
    assert_eq!(sent.len(), 1);
    let (mut b, _brx) = published(0xB2);
    let log = install_event_log(&mut b);
    feed(&mut b, queued(sent[0].2.clone()));
    assert_eq!(requests(&log)[0].intro_text, "with intro");
}

#[test]
fn received_message_id_is_the_envelope_id() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "id check");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Message(_, _, got) if *got == hex::encode(id))));
}

#[test]
fn send_text_message_using_id_uses_the_given_envelope_id() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    // `published` leaves the connection flags off; let the async send through.
    p.a.is_connected = true;
    p.a.websocket.as_ref().unwrap().set_connected_for_test();
    let peer_hex = p.pb.hex.clone();
    let client = wrap(p.a);
    let id_hex = "0123456789abcdef0123456789abcdef".to_string();
    assert_eq!(
        client
            .send_text_message_using_id(peer_hex.clone(), "hi".into(), id_hex.clone())
            .unwrap(),
        id_hex
    );
    let relays = sent_relays(&mut p.a_rx);
    assert_eq!(relays.len(), 1);
    assert_eq!(
        sealed::peek_message_id(&relays[0].payload).map(hex::encode),
        Some(id_hex)
    );
    assert!(client
        .send_text_message_using_id(peer_hex, "hi".into(), "nothex".into())
        .is_err());
}

#[test]
fn message_id_from_hex_accepts_only_32_hex_chars() {
    assert_eq!(
        crate::message_id_from_hex("0123456789abcdef0123456789ABCDEF").unwrap()[15],
        0xef
    );
    for bad in [
        "",
        "0123",
        "0123456789abcdef0123456789abcdeg",
        "0123456789abcdef0123456789abcdef00",
    ] {
        assert!(
            matches!(
                crate::message_id_from_hex(bad),
                Err(crate::RChatError::Internal { .. })
            ),
            "{bad}"
        );
    }
}

fn receipts_seen(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<(String, u8)> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Receipt(_, id, k) => Some((id.clone(), *k)),
            _ => None,
        })
        .collect()
}

/// N6: delivered and read receipts round-trip in-band; no receipt for a
/// receipt; none to an unaccepted peer.
#[test]
fn n6_in_band_receipts_round_trip() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "receipt me");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // the app stored it (D36)
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "B sent one delivered receipt"
    );
    assert_eq!(
        receipts_seen(&p.a_log),
        vec![(hex::encode(id), crate::receipts::DELIVERED)]
    );
    assert!(
        drain(&mut p.a_rx).is_empty(),
        "a receipt never triggers a receipt"
    );

    p.b.queue_receipt(&p.pa.hex, crate::receipts::READ, &[id]);
    p.b.flush_receipts(&p.pa.hex);
    relay_all(&mut p.b_rx, &mut p.a);
    assert_eq!(
        receipts_seen(&p.a_log).last(),
        Some(&(hex::encode(id), crate::receipts::READ))
    );

    let mut q = establish(0xA1, 0xB2);
    q.b.peers.unpin(&q.pa.hex);
    let unaccepted = push_text(&q.a, &q.pb.hex, "to an unaccepted peer");
    relay_all(&mut q.a_rx, &mut q.b);
    q.b.mark_seen_and_receipt(&q.pa.hex, unaccepted).unwrap();
    assert!(
        drain(&mut q.b_rx).is_empty(),
        "no receipt to an unaccepted peer"
    );
}

#[test]
fn send_read_receipt_public_api() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "read me");
    relay_all(&mut p.a_rx, &mut p.b);
    drain(&mut p.b_rx);
    let a_hex = p.pa.hex.clone();
    let b = wrap(p.b);
    b.send_read_receipt(a_hex.clone(), vec![hex::encode(id)])
        .unwrap();
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1);
    assert_eq!(
        receipts_seen(&p.a_log),
        vec![(hex::encode(id), crate::receipts::READ)]
    );
    assert!(b.send_read_receipt(a_hex, vec!["zz".into()]).is_err());
}

/// N10 (receipt half): a de-duplicated message still gets a delivered receipt.
#[test]
fn n10_seen_message_still_gets_a_delivered_receipt() {
    let mut p = establish(0xA1, 0xB2);
    let dup = push_text(&p.a, &p.pb.hex, "already shown");
    p.b.peers.mark_seen(&p.pa.hex, dup);
    relay_all(&mut p.a_rx, &mut p.b);
    relay_all(&mut p.b_rx, &mut p.a);
    assert_eq!(
        receipts_seen(&p.a_log),
        vec![(hex::encode(dup), crate::receipts::DELIVERED)]
    );
}

#[test]
fn receipts_wait_for_a_live_circuit() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "queued receipt");
    p.b.transport_epoch += 1; // B reconnected: circuit not live until resumed
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // the app stored it (D36)
    assert!(sent_relays(&mut p.b_rx).is_empty());
    feed(
        &mut p.b,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    relay_all(&mut p.b_rx, &mut p.a);
    assert_eq!(
        receipts_seen(&p.a_log),
        vec![(hex::encode(id), crate::receipts::DELIVERED)]
    );
}

fn count_relays(p: &mut Pair) -> usize {
    sent_relays(&mut p.b_rx).len()
}

/// Receipts are subject to check_sendable: terminal states drop them,
/// transient BadSignature keeps them; send_read_receipt errors.
#[test]
fn receipts_respect_key_state() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "x");
    relay_all(&mut p.a_rx, &mut p.b);
    drain(&mut p.b_rx);
    p.b.peers.mark_bad_signature(&p.pa.hex, Instant::now());
    p.b.queue_receipt(&p.pa.hex, crate::receipts::READ, &[id]);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(count_relays(&mut p), 0, "bad signature: nothing sent");
    assert!(p
        .b
        .pending_receipts
        .contains_key(&(p.pa.hex.clone(), crate::receipts::READ)));
    p.b.peers.clear_bad_signature(&p.pa.hex);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(count_relays(&mut p), 1, "sent once the key is good again");

    p.b.peers.mark_mismatch(&p.pa.hex);
    p.b.queue_receipt(&p.pa.hex, crate::receipts::READ, &[id]);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(count_relays(&mut p), 0, "mismatch: nothing sent");
    assert!(p.b.pending_receipts.is_empty(), "terminal: dropped");

    let a_hex = p.pa.hex.clone();
    let b = wrap(p.b);
    assert!(b
        .send_read_receipt(a_hex.clone(), vec![hex::encode(id)])
        .is_err());
    assert_eq!(sent_relays(&mut p.b_rx).len(), 0);
    b.set_peer_blocked(a_hex.clone(), true).unwrap();
    assert!(b.send_read_receipt(a_hex, vec![hex::encode(id)]).is_err());
    assert_eq!(sent_relays(&mut p.b_rx).len(), 0);
}

/// Queued receipts do not survive unpin/block.
#[test]
fn queued_receipts_are_cleared_on_unpin_and_block() {
    for block in [false, true] {
        let mut p = establish(0xA1, 0xB2);
        p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[7; 16]]);
        p.b.queue_receipt(&p.pa.hex, crate::receipts::READ, &[[8; 16]]);
        if block {
            p.b.block_peer(&p.pa.hex, true).unwrap();
        } else {
            p.b.unpin_peer(&p.pa.hex).unwrap();
        }
        assert!(p.b.pending_receipts.is_empty());
    }
}

/// Forged, malformed and never-sent receipts are ignored.
#[test]
fn forged_and_malformed_receipts_are_ignored() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "mine");
    let (a_hex, b_hex) = (p.pa.hex.clone(), p.pb.hex.clone());
    // B tells A about a message A never sent, and sends garbage bodies.
    p.a.handle_decrypted_message(
        &b_hex,
        [0; 16],
        &crate::receipts::encode(1, &[[0xEE; 16]]).unwrap(),
        crate::session::DecryptedBy::Current,
        None,
    );
    p.a.handle_decrypted_message(
        &b_hex,
        [0; 16],
        &[0x03, 1, 5, 1, 2],
        crate::session::DecryptedBy::Current,
        None,
    );
    p.a.handle_decrypted_message(
        &b_hex,
        [0; 16],
        &[0x03],
        crate::session::DecryptedBy::Current,
        None,
    );
    p.a.handle_decrypted_message(
        &b_hex,
        [0; 16],
        &[0x03, 9, 1],
        crate::session::DecryptedBy::Current,
        None,
    );
    assert!(receipts_seen(&p.a_log).is_empty());
    // A real id from a different peer is not accepted either.
    p.a.handle_decrypted_message(
        &a_hex,
        [0; 16],
        &crate::receipts::encode(1, &[id]).unwrap(),
        crate::session::DecryptedBy::Current,
        None,
    );
    assert!(
        receipts_seen(&p.a_log).is_empty(),
        "id was sent to B, not to A"
    );
    p.a.handle_decrypted_message(
        &b_hex,
        [0; 16],
        &crate::receipts::encode(1, &[id]).unwrap(),
        crate::session::DecryptedBy::Current,
        None,
    );
    assert_eq!(receipts_seen(&p.a_log).len(), 1);
}

/// TM1: delay bounds.
#[test]
fn tm1_receipt_delay_is_between_half_a_second_and_three_seconds() {
    assert_eq!(
        crate::circuits::receipt_delay_for(0.0),
        Duration::from_millis(500)
    );
    assert_eq!(
        crate::circuits::receipt_delay_for(1.0),
        Duration::from_millis(3000)
    );
    assert_eq!(
        crate::circuits::receipt_delay_for(9.0),
        Duration::from_millis(3000)
    );
}

/// TM1: delivered receipts wait for their deadline and leave as one batch.
#[test]
fn tm1_delivered_receipts_are_delayed_and_batched() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(2));
    let t0 = Instant::now();
    let ids: Vec<[u8; 16]> = (0..3)
        .map(|i| push_text(&p.a, &p.pb.hex, &format!("m{i}")))
        .collect();
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(drain(&mut p.b_rx).is_empty(), "no receipt at decrypt time");
    for id in &ids {
        p.b.mark_seen_and_receipt(&p.pa.hex, *id).unwrap(); // stored (D36)
    }
    assert!(drain(&mut p.b_rx).is_empty(), "nor when stored: delayed");
    p.b.fire_due_receipts(t0 + Duration::from_millis(1500));
    assert!(drain(&mut p.b_rx).is_empty(), "not before the deadline");
    p.b.fire_due_receipts(t0 + Duration::from_secs(3));
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "one receipt packet for three messages"
    );
    let got: Vec<String> = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Receipt(_, id, k) if *k == crate::receipts::DELIVERED => Some(id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(got, ids.iter().map(hex::encode).collect::<Vec<_>>());
}

/// TM2: read receipts follow the same rule.
#[test]
fn tm2_read_receipts_are_delayed() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "read me");
    relay_all(&mut p.a_rx, &mut p.b);
    drain(&mut p.b_rx);
    p.b.receipt_delay_override = Some(Duration::from_secs(1));
    let t0 = Instant::now();
    p.b.queue_receipt(&p.pa.hex, crate::receipts::READ, &[id]);
    p.b.flush_receipts(&p.pa.hex);
    assert!(drain(&mut p.b_rx).is_empty());
    p.b.fire_due_receipts(t0 + Duration::from_secs(2));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1);
}

/// Clearing a peer's receipts also cancels the pending delayed flush.
#[test]
fn clearing_receipts_cancels_the_delayed_flush() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(2));
    let id = push_text(&p.a, &p.pb.hex, "x");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // stored (D36)
    assert!(p.b.receipt_due.contains_key(&p.pa.hex));
    p.b.clear_receipts(&p.pa.hex);
    assert!(p.b.receipt_due.is_empty());
    p.b.fire_due_receipts(Instant::now() + Duration::from_secs(5));
    assert!(drain(&mut p.b_rx).is_empty());
}

/// TM4: cover packets look like short texts and vanish at the recipient.
#[test]
fn tm4_cover_is_bucket_sized_and_dropped_silently() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "x");
    let text = sent_relays(&mut p.a_rx);
    p.a.send_cover(&p.pb.hex, false, Instant::now()).unwrap();
    let cover = sent_relays(&mut p.a_rx);
    assert_eq!(cover.len(), 1);
    assert_eq!(
        cover[0].payload.len(),
        text[0].payload.len(),
        "same bucket as a 1-character text"
    );
    for r in text.into_iter().chain(cover) {
        feed(&mut p.b, Frame::Relay(r));
    }
    let messages = p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Message(..)))
        .count();
    assert_eq!(messages, 1, "only the text is delivered");
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // stored (D36)
    let delivered_receipts = drain(&mut p.b_rx).len();
    assert_eq!(
        delivered_receipts, 1,
        "one receipt (for the text), none for cover"
    );
}

/// TM4b (round-2 M4): a cover request is answered like a real message,
/// even with the recipient's cover off; a reply is never answered.
#[test]
fn tm4b_cover_requests_are_answered_and_replies_are_not() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(true);
    let t0 = Instant::now();
    p.a.send_cover(&p.pb.hex, false, t0).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(!p.b.cover_enabled, "recipient's own cover is off");
    assert_eq!(
        p.b.cover_replies_due.len(),
        2,
        "receipt-like and read-like replies scheduled"
    );
    // Zero receipt delay (establish): the first reply is due at once; the
    // second is at least 2 s away.
    p.b.fire_cover(t0 + Duration::from_secs(1));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1, "first reply");
    p.b.fire_cover(t0 + Duration::from_secs(31));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1, "second reply");
    assert!(p.b.cover_replies_due.is_empty());
    assert!(
        p.a.cover_replies_due.is_empty(),
        "replies are never answered"
    );
    p.a.fire_cover(t0 + Duration::from_secs(60));
    assert!(
        drain(&mut p.a_rx).is_empty(),
        "A (cover off) sends nothing back"
    );
    assert!(p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .all(|e| !matches!(e, Ev::Message(..) | Ev::Receipt(..))));
}

/// Without the coin, the second reply is skipped; replies to a peer that
/// became unsendable (blocked) are never sent.
#[test]
fn cover_replies_honor_the_coin_and_key_state() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(false);
    let t0 = Instant::now();
    p.a.send_cover(&p.pb.hex, false, t0).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(p.b.cover_replies_due.len(), 1, "no second reply");
    p.b.peers.set_blocked(&p.pa.hex, true);
    p.b.fire_cover(t0 + Duration::from_secs(31));
    assert!(drain(&mut p.b_rx).is_empty(), "never to a blocked peer");
    assert!(p.b.send_cover(&p.pa.hex, false, t0).is_err());
}

/// A flood of cover requests schedules a bounded number of replies.
#[test]
fn cover_replies_are_bounded_per_peer() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(true);
    let now = Instant::now();
    for _ in 0..100 {
        p.b.schedule_cover_replies(&p.pa.hex, now);
    }
    assert!(p.b.cover_replies_due.len() <= crate::circuits::MAX_COVER_PER_HOUR);
    p.b.fire_cover(now + Duration::from_secs(31));
    assert!(sent_relays(&mut p.b_rx).len() <= crate::circuits::MAX_COVER_PER_HOUR);
}

/// Security review L-2: a peer sending cover requests far faster than
/// its own cap (here one every 18 s, 200 an hour) gets at most
/// `MAX_COVER_REPLIES_PER_HOUR` replies an hour; extra requests are
/// dropped silently. Once the hour has passed, replies resume.
#[test]
fn l2_cover_replies_are_capped_per_peer_per_hour() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(true); // two replies per request
    let t0 = Instant::now();
    let mut replies = 0usize;
    for i in 0..200u64 {
        let t = t0 + Duration::from_secs(i * 18);
        p.a.send_cover(&p.pb.hex, false, t).unwrap();
        relay_all(&mut p.a_rx, &mut p.b);
        p.b.fire_cover(t + Duration::from_secs(31));
        replies += relay_all(&mut p.b_rx, &mut p.a);
    }
    assert_eq!(
        replies,
        crate::circuits::MAX_COVER_REPLIES_PER_HOUR,
        "replies in the first hour are capped"
    );
    assert!(p.b.cover_replies_due.is_empty(), "nothing left waiting");
    // Requests are charged when they are decrypted (now); an hour on,
    // the budget is back.
    let later = Instant::now() + Duration::from_secs(3600);
    p.b.schedule_cover_replies(&p.pa.hex, later);
    assert_eq!(p.b.cover_replies_due.len(), 2, "an hour later, answered");
}

/// TM8 (round-2 M5): no cover to a peer not heard from in 60 s; 20 per peer per hour.
#[test]
fn tm8_cover_only_to_connected_peers_and_capped() {
    let mut p = establish(0xA1, 0xB2);
    p.a.cover_enabled = true;
    p.a.cover_foreground = true;
    let t0 = Instant::now();
    p.a.last_heard.clear();
    p.a.cover_next = Some(t0);
    p.a.fire_cover(t0 + Duration::from_secs(1));
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "not heard from: nothing queued for it"
    );
    p.a.last_heard.insert(p.pb.hex.clone(), t0);
    p.a.cover_next = Some(t0);
    p.a.fire_cover(t0 + Duration::from_secs(61));
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "heard from more than 60 s ago"
    );
    p.a.cover_sent
        .insert(p.pb.hex.clone(), (0..20).map(|_| t0).collect());
    p.a.cover_next = Some(t0);
    p.a.fire_cover(t0 + Duration::from_secs(1));
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "cap of 20 per hour reached"
    );
    p.a.cover_sent.clear();
    p.a.cover_next = Some(t0);
    p.a.fire_cover(t0 + Duration::from_secs(1));
    assert_eq!(sent_relays(&mut p.a_rx).len(), 1);
    p.a.transport_epoch += 1; // circuit no longer live
    p.a.cover_next = Some(t0);
    p.a.fire_cover(t0 + Duration::from_secs(2));
    assert!(sent_relays(&mut p.a_rx).is_empty(), "no live circuit");
}

/// A successful ratchet decrypt records when the peer was last heard from.
#[test]
fn ratchet_decrypt_records_last_heard() {
    let mut p = establish(0xA1, 0xB2);
    assert!(p.b.last_heard.contains_key(&p.pa.hex), "hello sync counts");
    assert!(!p.a.last_heard.contains_key(&p.pb.hex));
    push_text(&p.b, &p.pa.hex, "hi");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(p.a.last_heard.contains_key(&p.pb.hex));
}

/// TM5: delay bounds and mean; cover requests only when enabled and in the foreground.
#[test]
fn tm5_cover_schedule() {
    assert_eq!(
        crate::circuits::cover_delay_for(0.0),
        Duration::from_secs(10)
    );
    assert_eq!(
        crate::circuits::cover_delay_for(0.999_999),
        Duration::from_secs(180)
    );
    let n = 10_000;
    let mean: f64 = (0..n)
        .map(|_| crate::circuits::cover_delay_for(rand::random::<f64>()).as_secs_f64())
        .sum::<f64>()
        / n as f64;
    assert!((mean - 45.0).abs() < 3.0, "mean {mean}");

    let mut p = establish(0xA1, 0xB2);
    let t0 = Instant::now();
    p.a.fire_cover(t0 + Duration::from_secs(1000));
    assert!(sent_relays(&mut p.a_rx).is_empty(), "disabled by default");
    p.a.cover_enabled = true;
    p.a.fire_cover(t0);
    p.a.fire_cover(t0 + Duration::from_secs(1000));
    assert!(sent_relays(&mut p.a_rx).is_empty(), "background: nothing");
    p.a.cover_foreground = true;
    p.a.last_heard
        .insert(p.pb.hex.clone(), t0 + Duration::from_secs(175));
    p.a.fire_cover(t0); // schedules
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "first call only schedules"
    );
    p.a.fire_cover(t0 + Duration::from_secs(181));
    assert_eq!(
        sent_relays(&mut p.a_rx).len(),
        1,
        "one cover packet once due"
    );
}

/// Task 16b: a second flush inside the window does not move the deadline.
#[test]
fn second_flush_in_window_keeps_the_deadline() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(2));
    let one = push_text(&p.a, &p.pb.hex, "one");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, one).unwrap(); // stored (D36)
    let first = *p.b.receipt_due.get(&p.pa.hex).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let two = push_text(&p.a, &p.pb.hex, "two");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, two).unwrap();
    assert_eq!(p.b.receipt_due.get(&p.pa.hex), Some(&first));
}

/// Task 16b: a deadline that fires while the circuit is down keeps the
/// ids queued; the next flush schedules them again.
#[test]
fn deadline_with_circuit_down_keeps_ids_and_reschedules() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(2));
    let id = push_text(&p.a, &p.pb.hex, "x");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // stored (D36)
    p.b.transport_epoch += 1; // circuit not live on this connection
    p.b.fire_due_receipts(Instant::now() + Duration::from_secs(3));
    assert!(drain(&mut p.b_rx).is_empty());
    assert!(p.b.receipt_due.is_empty());
    assert_eq!(
        p.b.pending_receipts
            .get(&(p.pa.hex.clone(), crate::receipts::DELIVERED))
            .map(Vec::as_slice),
        Some(&[id][..])
    );
    p.b.transport_epoch -= 1; // circuit back
    p.b.flush_receipts(&p.pa.hex);
    assert!(p.b.receipt_due.contains_key(&p.pa.hex), "rescheduled");
    p.b.fire_due_receipts(Instant::now() + Duration::from_secs(3));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1);
    assert!(p.a_log.lock().unwrap().contains(&Ev::Receipt(
        p.pb.hex.clone(),
        hex::encode(id),
        crate::receipts::DELIVERED
    )));
}

/// Task 16b: a full batch (32 ids) is sent at once, without waiting.
#[test]
fn thirty_two_queued_ids_send_immediately() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(2));
    let ids: Vec<[u8; 16]> = (0..crate::receipts::MAX_IDS)
        .map(|i| push_text(&p.a, &p.pb.hex, &format!("m{i}")))
        .collect();
    relay_all(&mut p.a_rx, &mut p.b);
    for id in ids {
        p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap(); // stored (D36)
    }
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "one batch, no deadline"
    );
    assert!(p.b.receipt_due.is_empty());
    let got = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Receipt(..)))
        .count();
    assert_eq!(got, crate::receipts::MAX_IDS);
}

/// Task 17 review: a ratchet plaintext without a valid padding (no marker,
/// or a marker at a non-bucket length) yields no message and no receipt.
#[test]
fn unpadded_ratchet_plaintext_is_dropped_without_receipt() {
    let mut p = establish(0xA1, 0xB2);
    for raw in [&b"\x01hi"[..], &b"\x01hi\x80"[..]] {
        let (ciphertext, header) =
            p.a.session_manager
                .get_mut(&p.pb.hex)
                .unwrap()
                .encrypt_message(raw)
                .unwrap();
        let mut body = header.encode();
        body.extend_from_slice(&ciphertext);
        p.b.handle_ratchet(&p.pa.hex, [9; 16], &body);
    }
    assert!(p.b_log.lock().unwrap().is_empty(), "no message event");
    assert!(drain(&mut p.b_rx).is_empty(), "no receipt");
    assert!(p.b.receipt_due.is_empty() && p.b.pending_receipts.is_empty());
}

/// The shared ticker fires due work every 250 ms, so a 0.5-3 s receipt
/// deadline is met to within a quarter second.
#[test]
fn ticker_fires_due_receipts_within_a_quarter_second() {
    assert_eq!(crate::TICK_INTERVAL, Duration::from_millis(250));
    let (inner, _rx) = published(0xA1);
    let client = crate::test_support::wrap(inner);
    client.runtime.block_on(async {
        client
            .inner
            .write()
            .await
            .receipt_due
            .insert("ab".repeat(32), Instant::now());
    });
    let started = Instant::now();
    crate::spawn_ticker(&client.runtime, std::sync::Arc::downgrade(&client.inner));
    // Wait for the receipt to fire (bounded), then check how long it took.
    let fired = || {
        client
            .runtime
            .block_on(async { client.inner.read().await.receipt_due.is_empty() })
    };
    while !fired() && started.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(fired(), "the ticker never fired the due receipt");
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "fired after {:?}: a 1 s ticker would not have fired yet",
        started.elapsed()
    );
}

/// Fix round 1: replies are exempt from the cap. Over a simulated hour of
/// A's requests at the configured rate, every request is answered.
#[test]
fn every_cover_request_in_an_hour_is_answered() {
    let mut p = establish(0xA1, 0xB2);
    p.a.cover_enabled = true;
    p.a.cover_foreground = true;
    p.b.cover_reply_coin_override = Some(true); // two replies per request
    let t0 = Instant::now();
    let (mut requests, mut replies) = (0usize, 0usize);
    for s in 0..=3600u64 {
        let t = t0 + Duration::from_secs(s);
        p.a.last_heard.insert(p.pb.hex.clone(), t); // B stays online
        p.a.fire_cover(t);
        requests += relay_all(&mut p.a_rx, &mut p.b);
        p.b.fire_cover(t + Duration::from_secs(31));
        replies += relay_all(&mut p.b_rx, &mut p.a);
    }
    // Delays are at most 180 s, so the requester reaches its own cap
    // (20 per peer per hour) within the hour.
    assert_eq!(requests, crate::circuits::MAX_COVER_PER_HOUR);
    assert_eq!(replies, 2 * requests, "no unanswered requests");
    assert!(p.b.cover_replies_due.is_empty());
    assert!(
        !p.b.cover_sent.contains_key(&p.pa.hex),
        "replies are not counted"
    );
}

/// Fix round 1: a reply due while the circuit is down waits for it.
#[test]
fn cover_replies_wait_for_the_circuit() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(true);
    let t0 = Instant::now();
    p.a.send_cover(&p.pb.hex, false, t0).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.transport_epoch += 1; // circuit down
    p.b.fire_cover(t0 + Duration::from_secs(31));
    assert!(drain(&mut p.b_rx).is_empty());
    assert_eq!(p.b.cover_replies_due.len(), 2, "kept, not dropped");
    p.b.transport_epoch -= 1; // circuit back
    p.b.fire_cover(t0 + Duration::from_secs(32));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 2);
    assert!(p.b.cover_replies_due.is_empty());
}

/// Fix round 1: blocking (or unpinning) a peer clears its cover state.
#[test]
fn block_clears_cover_state_for_the_peer() {
    let mut p = establish(0xA1, 0xB2);
    p.b.cover_reply_coin_override = Some(true);
    let t0 = Instant::now();
    p.a.send_cover(&p.pb.hex, false, t0).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.cover_sent
        .insert(p.pa.hex.clone(), [t0].into_iter().collect());
    p.b.cover_replies_due.push(("cd".repeat(32), t0));
    assert!(p.b.last_heard.contains_key(&p.pa.hex));
    p.b.block_peer(&p.pa.hex, true).unwrap();
    assert!(!p.b.last_heard.contains_key(&p.pa.hex));
    assert!(!p.b.cover_sent.contains_key(&p.pa.hex));
    assert_eq!(
        p.b.cover_replies_due,
        vec![("cd".repeat(32), t0)],
        "only that peer's replies are removed"
    );
    let mut q = establish(0xA1, 0xB2);
    q.a.send_cover(&q.pb.hex, false, t0).unwrap();
    relay_all(&mut q.a_rx, &mut q.b);
    q.b.unpin_peer(&q.pa.hex).unwrap();
    assert!(q.b.last_heard.is_empty() && q.b.cover_replies_due.is_empty());
}

/// Task 15 minor: seen-ids are filed only under a 64-hex sender.
#[test]
fn mark_message_seen_refuses_a_malformed_sender() {
    let (a, _rx) = published(0xA1);
    let client = wrap(a);
    let id = hex::encode([7u8; 16]);
    assert!(matches!(
        client.mark_message_seen("12".into(), id.clone()),
        Err(crate::RChatError::InvalidRecipient { .. })
    ));
    assert!(client
        .mark_message_seen(hex::encode([0xB2u8; 32]).to_uppercase(), id)
        .is_ok());
}

/// Task 16 minor: no receipt is queued for a peer that isn't pinned.
#[test]
fn receipts_are_queued_only_for_pinned_peers() {
    let mut p = establish(0xA1, 0xB2);
    p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[1; 16]]);
    assert!(p
        .b
        .pending_receipts
        .contains_key(&(p.pa.hex.clone(), crate::receipts::DELIVERED)));
    let stranger = hex::encode([0x77u8; 32]);
    p.b.queue_receipt(&stranger, crate::receipts::DELIVERED, &[[2; 16]]);
    assert!(!p
        .b
        .pending_receipts
        .contains_key(&(stranger, crate::receipts::DELIVERED)));
}

/// Task 19 minor: a read receipt for a peer whose bundle signature failed
/// (transient) is kept, not refused; a mismatched peer gets none.
#[test]
fn read_receipt_waits_out_a_transient_bad_signature() {
    let mut p = establish(0xA1, 0xB2);
    let peer_hex = p.pa.hex.clone();
    p.b.peers.mark_bad_signature(&peer_hex, Instant::now());
    let client = wrap(p.b);
    let id = hex::encode([5u8; 16]);
    assert!(client
        .send_read_receipt(peer_hex.clone(), vec![id.clone()])
        .is_ok());
    let queued = client.runtime.block_on(async {
        client
            .inner
            .read()
            .await
            .pending_receipts
            .contains_key(&(peer_hex.clone(), crate::receipts::READ))
    });
    assert!(queued, "kept for when the keys check out");
    client.runtime.block_on(async {
        client.inner.write().await.peers.mark_mismatch(&peer_hex);
    });
    assert!(matches!(
        client.send_read_receipt(peer_hex, vec![id]),
        Err(crate::RChatError::PeerKeyRejected { .. })
    ));
}

/// Live-loss debug (2026-10-09): the responder's app sends as soon as
/// `has_session` is true, which over a real relay is before the
/// initiator's hello sync arrives. Those messages wait on the session for
/// a sending chain. Once the hello sync gives it one, the core's own timer
/// must send them: an app that never calls `process_pending` (the test
/// client, any new port) used to lose them for good.
#[test]
fn responder_messages_sent_before_the_hello_sync_go_out_without_process_pending() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let a_log = install_event_log(&mut a);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v2(1, &pa.bundle, i_ek, r_ek));
    drain(&mut b_rx);

    // B's app sends while A's hello sync is still in flight.
    if let Some(ws) = &b.websocket {
        ws.set_connected_for_test();
    }
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    *client.inner.try_write().unwrap() = b;
    client
        .send_text_message(pa.hex.clone(), "early".into())
        .unwrap();
    assert!(
        sent_relays(&mut b_rx).is_empty(),
        "no sending chain yet: the message waits on the session"
    );

    // The hello sync arrives; the app never calls process_pending. The
    // timer runs as it does after every connect.
    relay_all(&mut a_rx, &mut client.inner.try_write().unwrap());
    crate::spawn_ticker(&client.runtime, std::sync::Arc::downgrade(&client.inner));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut packets = Vec::new();
    while packets.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        packets = sent_relays(&mut b_rx);
    }
    for p in packets {
        feed(&mut a, Frame::Relay(p));
    }
    assert!(
        a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(s, c, _) if *s == pb.hex && c == b"early")),
        "the queued message reached A"
    );
}

fn asks_to(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> usize {
    sent_controls(rx)
        .iter()
        .filter(|c| matches!(c, ControlMessage::CircuitAsk { .. }))
        .count()
}

/// RA1: an ask in flight when the transport is replaced is sent again
/// after the next accepted publish, without counting towards backoff.
#[test]
fn ra1_transport_replaced_mid_ask_reasks_after_publish() {
    let (mut a, mut rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers
        .pin(&b.hex, b.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&b.hex, AskTrigger::User, Instant::now()).unwrap();
    assert_eq!(asks_to(&mut rx), 1);
    let attempts = a.peers.backoff_mut(&b.hex).attempts();
    a.handle_transport_reconnected();
    a.is_key_bundle_published = true;
    a.after_publish_ok(Instant::now());
    assert_eq!(asks_to(&mut rx), 1, "re-sent once");
    assert_eq!(
        a.peers.backoff_mut(&b.hex).attempts(),
        attempts,
        "uncounted"
    );
}

/// RA2: one user ask in flight per peer within 5 s on one epoch.
#[test]
fn ra2_one_user_ask_in_flight() {
    let (mut a, mut rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers
        .pin(&b.hex, b.bundle.identity_agreement_key)
        .unwrap();
    let t0 = Instant::now();
    a.ask(&b.hex, AskTrigger::User, t0).unwrap();
    a.ask(&b.hex, AskTrigger::User, t0 + Duration::from_secs(1))
        .unwrap();
    assert_eq!(asks_to(&mut rx), 1);
    a.ask(&b.hex, AskTrigger::User, t0 + Duration::from_secs(6))
        .unwrap();
    assert_eq!(asks_to(&mut rx), 1, "after 5 s, a second ask");
    // Replacement half: inside the 5 s window, a transport replacement still re-sends.
    a.ask(&b.hex, AskTrigger::User, t0 + Duration::from_secs(7))
        .unwrap();
    assert_eq!(asks_to(&mut rx), 0, "suppressed: in flight");
    a.handle_transport_reconnected();
    a.is_key_bundle_published = true;
    a.after_publish_ok(t0 + Duration::from_secs(8));
    assert_eq!(asks_to(&mut rx), 1, "re-sent after the replacement");
}

/// RA3: a held body from a pinned peer without a session schedules a re-ask.
#[test]
fn ra3_held_body_triggers_an_ask() {
    let mut p = establish(0xA1, 0xB2);
    push_text(&p.a, &p.pb.hex, "for a lost session");
    let pk = sent_relays(&mut p.a_rx).remove(0);
    let (mut b2, _rx) = published(0xB2);
    b2.peers
        .pin(&p.pa.hex, p.pa.bundle.identity_agreement_key)
        .unwrap();
    feed(&mut b2, queued(pk.payload.clone()));
    assert!(b2.pending_reasks.contains_key(&p.pa.hex));

    // Review fix 3: a sender accepted only through the rotation grace (its
    // old identity, unpinned; the new one pinned) has its body held, but is
    // never asked: only a pinned contact can be.
    let (mut b3, _rx) = published(0xB2);
    let new_id = peer(0xC3);
    b3.peers
        .pin(&new_id.hex, new_id.bundle.identity_agreement_key)
        .unwrap();
    b3.rotated_from
        .insert(p.pa.hex.clone(), (new_id.hex.clone(), Instant::now()));
    feed(&mut b3, queued(pk.payload));
    assert_eq!(b3.pending_encrypted_messages.len(), 1, "held");
    assert!(b3.pending_reasks.is_empty() && b3.deferred_asks.is_empty());
    assert!(b3.unanswered_asks.is_empty());
}

/// A published client that has really asked B (so `unanswered_asks` is set
/// by `build_and_send_ask`, not by the test).
fn asked_b() -> (
    ClientInner,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Peer,
    [u8; 32],
) {
    let (mut a, mut rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers
        .pin(&b.hex, b.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&b.hex, AskTrigger::User, Instant::now()).unwrap();
    let ek = sent_controls(&mut rx)
        .into_iter()
        .find_map(|c| match c {
            ControlMessage::CircuitAsk { ephemeral_key, .. } => {
                Some(<[u8; 32]>::try_from(ephemeral_key).unwrap())
            }
            _ => None,
        })
        .unwrap();
    assert!(
        a.unanswered_asks.contains_key(&b.hex),
        "set by the real ask"
    );
    (a, rx, b, ek)
}

/// RA4: every answer clears the unanswered ask; another peer's does not.
#[test]
fn ra4_answers_clear_unanswered() {
    let r_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    // Success.
    let (mut a, _rx, b, ek) = asked_b();
    feed(&mut a, created_v2(0, &b.bundle, ek, r_ek));
    assert!(!a.unanswered_asks.contains_key(&b.hex), "success");
    // Echo refusal (an EK that isn't ours).
    let (mut a, _rx, b, _ek) = asked_b();
    feed(&mut a, created_v2(0, &b.bundle, [0x42; 32], r_ek));
    assert!(!a.unanswered_asks.contains_key(&b.hex), "echo refusal");
    // Mismatch (a validly signed bundle with another agreement key).
    let (mut a, _rx, b, ek) = asked_b();
    feed(
        &mut a,
        created_v2(
            0,
            &bundle_with_ak(&b, peer(0xC3).bundle.identity_agreement_key),
            ek,
            r_ek,
        ),
    );
    assert!(!a.unanswered_asks.contains_key(&b.hex), "mismatch");
    // Bad signature.
    let (mut a, _rx, b, ek) = asked_b();
    let mut forged = b.bundle.clone();
    forged.bundle_signature[0] ^= 1;
    feed(&mut a, created_v2(0, &forged, ek, r_ek));
    assert!(!a.unanswered_asks.contains_key(&b.hex), "bad signature");
    // CircuitExists for B's circuit (a resumed pair).
    let mut p = establish(0xA1, 0xB2);
    p.a.unanswered_asks
        .insert(p.pb.hex.clone(), (Instant::now(), p.a.transport_epoch));
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
    assert!(
        !p.a.unanswered_asks.contains_key(&p.pb.hex),
        "CircuitExists"
    );
    // Block.
    let (mut a, _rx, b, _ek) = asked_b();
    a.block_peer(&b.hex, true).unwrap();
    assert!(!a.unanswered_asks.contains_key(&b.hex), "block");
    // Another peer's frame leaves B's ask alone.
    let (mut a, _rx, b, _ek) = asked_b();
    let c = peer(0xC3);
    a.peers
        .pin(&c.hex, c.bundle.identity_agreement_key)
        .unwrap();
    feed(&mut a, created_v2(0, &c.bundle, [0x43; 32], r_ek));
    assert!(a.unanswered_asks.contains_key(&b.hex), "other peer");
}

/// RA5: replacing an established session raises SessionReplaced once.
#[test]
fn ra5_session_replaced_is_raised_once() {
    let mut p = establish(0xA1, 0xB2);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i, r) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    feed(&mut p.a, created_v2(0, &p.pb.bundle, i, r));
    let n = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| {
            matches!(
                e,
                Ev::Status(crate::status::StatusEvent::SessionReplaced { .. })
            )
        })
        .count();
    assert_eq!(n, 1);
    assert!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .replaced_established
    );
}

/// The EK of every `CircuitAsk` in `sent`.
fn ask_eks(sent: &[ControlMessage]) -> Vec<[u8; 32]> {
    sent.iter()
        .filter_map(|c| match c {
            ControlMessage::CircuitAsk { ephemeral_key, .. } => {
                <[u8; 32]>::try_from(ephemeral_key.as_slice()).ok()
            }
            _ => None,
        })
        .collect()
}

/// RC2, the `i1race.sh` interleaving (restart-loss root cause §3):
/// Alice asks, and her transport is replaced (I-1) before the relay's
/// `CircuitCreatedV2` comes back, so that frame goes to the retired
/// connection and is never processed. Her app calls `setRecipient` again
/// both before and after the new publish is accepted. Exactly one ask
/// goes out on the new connection, the relay's answer to it forms the
/// pair on both sides, and Bob's messages reach Alice.
#[test]
fn rc2_ask_lost_on_the_retired_connection_is_resent_once_and_pairs() {
    let (mut a, mut old_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    a.receipt_delay_override = Some(Duration::ZERO);
    b.receipt_delay_override = Some(Duration::ZERO);
    let a_log = install_event_log(&mut a);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();

    // Alice's setRecipient: one ask, on the connection about to be retired.
    a.ask(&pb.hex, AskTrigger::User, Instant::now()).unwrap();
    let lost = ask_eks(&sent_controls(&mut old_rx));
    assert_eq!(lost.len(), 1);
    let attempts = a.peers.backoff_mut(&pb.hex).attempts();

    // I-1: the transport is replaced. Its hello goes out; the publish is
    // not accepted yet, and the user taps the chat again meanwhile.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    a.websocket.as_ref().unwrap().install_outgoing_for_test(tx);
    a.handle_transport_reconnected();
    a.ask(&pb.hex, AskTrigger::User, Instant::now()).unwrap();
    assert_eq!(
        asks_to(&mut rx),
        0,
        "nothing before the publish is accepted"
    );
    // The relay pairs on the lost ask, but its CircuitCreatedV2 goes to the
    // retired connection: Alice never sees it.
    feed_signaling(&mut a, hello_response([0x4f; 32]));
    feed_signaling(&mut a, publish_ok([0x56; 32]));
    assert!(a.is_key_bundle_published);
    let sent = sent_controls(&mut rx);
    let eks = ask_eks(&sent);
    assert_eq!(eks.len(), 1, "the unanswered ask is sent again, once");
    assert_ne!(eks[0], lost[0], "a fresh EK");
    assert_eq!(
        a.peers.backoff_mut(&pb.hex).attempts(),
        attempts,
        "a re-send after a replacement is not a retry"
    );
    // setRecipient again right after the publish: the new ask is in flight.
    a.ask(&pb.hex, AskTrigger::User, Instant::now()).unwrap();
    assert_eq!(asks_to(&mut rx), 0, "one ask in flight");

    // The relay answers the new ask on the live connection.
    let ek_b = EphemeralKeyPair::generate();
    let r_ek = ek_b.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    feed(&mut a, created_v2(0, &pb.bundle, eks[0], r_ek));
    feed(&mut b, created_v2(1, &pa.bundle, eks[0], r_ek));
    assert!(a.has_live_circuit(&pb.hex) && b.has_live_circuit(&pa.hex));
    assert!(a.unanswered_asks.is_empty(), "answered");
    relay_all(&mut rx, &mut b); // Alice's hello sync
    drain(&mut b_rx);

    // "Bob to Alice" works.
    push_text(&b, &pa.hex, "Bob Test");
    assert_eq!(relay_all(&mut b_rx, &mut a), 1);
    assert!(
        a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(s, c, _) if *s == pb.hex && c == b"Bob Test")),
        "Bob's message reached Alice"
    );
}

/// The uncounted re-send after a replacement replaces a scheduled re-ask
/// for the same peer, so that one does not follow it as a second ask.
#[test]
fn resent_unanswered_ask_cancels_the_scheduled_reask() {
    let (mut a, _rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers
        .pin(&b.hex, b.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&b.hex, AskTrigger::User, Instant::now()).unwrap();
    a.schedule_reask(&b.hex);
    assert!(a.pending_reasks.contains_key(&b.hex));
    let mut rx2 = reconnect_and_publish(&mut a);
    assert_eq!(asks_to(&mut rx2), 1);
    assert!(
        !a.pending_reasks.contains_key(&b.hex),
        "no second ask queued"
    );
}

/// Review fix 1, the RC2 recovery sequence: the unanswered ask is re-sent
/// after the replacement, then a held body from the peer schedules a re-ask.
/// That re-ask must not fire while the re-sent ask is in flight (it would
/// tear down the pair being formed); it is due again when the window ends.
#[test]
fn held_body_reask_waits_for_the_ask_in_flight() {
    let mut p = establish(0xA1, 0xB2);
    push_text(&p.b, &p.pa.hex, "Bob Photo");
    let pk = sent_relays(&mut p.b_rx).remove(0);

    let (mut a, _old_rx) = published(0xA1);
    a.peers
        .pin(&p.pb.hex, p.pb.bundle.identity_agreement_key)
        .unwrap();
    a.ask(&p.pb.hex, AskTrigger::User, Instant::now()).unwrap();
    let mut rx = reconnect_and_publish(&mut a);
    assert_eq!(asks_to(&mut rx), 1, "re-sent after the replacement");
    let (at, _) = a.unanswered_asks[&p.pb.hex];

    feed(&mut a, queued(pk.payload));
    assert!(a.pending_reasks.contains_key(&p.pb.hex), "held body asks");
    a.pending_reasks.insert(p.pb.hex.clone(), at); // due now
    a.fire_due_reasks(at + Duration::from_secs(1));
    assert_eq!(asks_to(&mut rx), 0, "not inside the window");
    assert_eq!(
        a.pending_reasks.get(&p.pb.hex),
        Some(&(at + crate::circuits::ASK_IN_FLIGHT))
    );
    a.fire_due_reasks(at + crate::circuits::ASK_IN_FLIGHT);
    assert_eq!(asks_to(&mut rx), 1, "fires once the window ends");
}

/// Review fix 6: `SessionReplaced` is raised only once the new session is
/// durable (like `on_circuit_established`).
#[test]
fn session_replaced_waits_for_the_write() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i, r) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    sa.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    feed(&mut p.a, created_v2(0, &p.pb.bundle, i, r));
    assert!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .replaced_established
    );
    let replaced = |log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>| {
        log.lock()
            .unwrap()
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Ev::Status(crate::status::StatusEvent::SessionReplaced { .. })
                )
            })
            .count()
    };
    assert_eq!(replaced(&p.a_log), 0);
    // Task 4 re-review: the next good write of the session raises it, once.
    sa.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "after");
    assert_eq!(replaced(&p.a_log), 1, "raised once durable");
    push_text(&p.a, &p.pb.hex, "again");
    assert_eq!(replaced(&p.a_log), 1, "only once");
}

/// AK1: a replacement before the ack → the identical sealed payload goes
/// out again after resume; the late ack fires once.
#[test]
fn ak1_ack_survives_transport_replacement() {
    ak1_flow_for_ob2();
}

/// AK1's flow, shared with OB2 (Task 6a) instead of copied.
pub(crate) fn ak1_flow_for_ob2() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01hello")
        .unwrap();
    let first = sent_relays(&mut p.a_rx).remove(0).payload;
    p.a.handle_transport_reconnected();
    p.a.is_key_bundle_published = true;
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
    let again = sent_relays(&mut p.a_rx).remove(0).payload;
    assert_eq!(first, again, "byte-equal payload, no new encryption");
    let ack = || {
        Frame::Control(ControlMessage::MessageAck {
            message_id: hex::encode(id),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            timestamp: 0,
        })
    };
    feed(&mut p.a, ack());
    feed(&mut p.a, ack());
    let delivered = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Delivered(x) if *x == hex::encode(id)))
        .count();
    assert_eq!(delivered, 1, "on_message_delivered fires once");
    assert_eq!(p.a.acks.lock().unwrap().len(), 0);
}

/// AK2: a duplicate of an envelope the app already stored gets its delivered
/// receipt queued again (the first receipt may have been lost), and is
/// still never decrypted twice.
#[test]
fn ak2_duplicate_of_a_seen_message_is_receipted_again() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "dup");
    let pk = sent_relays(&mut p.a_rx).remove(0);
    feed(&mut p.b, Frame::Relay(pk.clone()));
    p.b.peers.mark_seen(&p.pa.hex, id); // the app stored it
    drain(&mut p.b_rx); // the first receipt went out (or was lost)
    let attempts =
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed);
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        attempts,
        "not decrypted again"
    );
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "receipt queued again for the duplicate"
    );
}

/// AK2, the negative: a duplicate the app has not stored gets no receipt.
#[test]
fn ak2_duplicate_of_an_unseen_message_gets_no_receipt() {
    let mut p = establish(0xA1, 0xB2);
    push_text(&p.a, &p.pb.hex, "dup");
    let pk = sent_relays(&mut p.a_rx).remove(0);
    feed(&mut p.b, Frame::Relay(pk.clone()));
    drain(&mut p.b_rx);
    p.b.pending_receipts.clear();
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 0);
    assert!(p.b.owed_receipts(&p.pa.hex).is_empty());
}

/// Task 3b carry-over: during a contact's rotation grace the duplicate
/// arrives from the old identity, but the seen ids (and the receipt) live
/// under the new one (`report_as`).
#[test]
fn ak2_rotation_grace_duplicate_is_receipted_under_the_new_identity() {
    let mut p = establish(0xA1, 0xB2);
    let pn = peer(0x77);
    p.b.peers.unpin(&p.pa.hex);
    p.b.peers
        .pin(&pn.hex, pn.bundle.identity_agreement_key)
        .unwrap();
    p.b.rotated_from
        .insert(p.pa.hex.clone(), (pn.hex.clone(), Instant::now()));
    let id = push_text(&p.a, &p.pb.hex, "grace");
    let pk = sent_relays(&mut p.a_rx).remove(0);
    feed(&mut p.b, Frame::Relay(pk.clone()));
    assert_eq!(texts(&p.b_log), vec![b"grace".to_vec()]);
    p.b.peers.mark_seen(&pn.hex, id); // the app stored it under the new identity
    p.b.pending_receipts.clear(); // the first receipt went out (or was lost)
    let attempts =
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed);
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        attempts,
        "not decrypted again"
    );
    assert_eq!(
        p.b.owed_receipts(&pn.hex),
        vec![(crate::receipts::DELIVERED, id)],
        "re-owed to the new identity"
    );
    assert!(p.b.owed_receipts(&p.pa.hex).is_empty());
}

/// AK4: CircuitNotFound for the circuit of a tracked send → SendNotAccepted,
/// and the payload goes out again once a new pair forms.
#[test]
fn ak4_circuit_not_found_marks_and_resends() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01x").unwrap();
    drain(&mut p.a_rx);
    let msg = format!(
        "{}{}",
        crate::protocol::CIRCUIT_NOT_FOUND_PREFIX,
        hex::encode(C2.0)
    );
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::Error {
            code: crate::protocol::ControlErrorCode::CircuitNotFound,
            message: msg,
        }),
    );
    assert!(p.a_log.lock().unwrap().iter().any(|e| matches!(
        e,
        Ev::Status(crate::status::StatusEvent::SendNotAccepted { .. })
    )));
    // Re-pair: the identical payload goes out on the new pair and the
    // receiver decrypts it under its retired session.
    let first = p.a.acks.lock().unwrap().payloads_for(&p.pb.hex)[0]
        .1
        .clone();
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    let packets = sent_relays(&mut p.a_rx);
    assert!(
        packets.iter().any(|r| r.payload == first),
        "resent after the re-pair"
    );
    // Review fix I2: the refused send never counted, so its re-send is
    // still the first attempt (spec §18.7: "not a resend").
    assert_eq!(p.a.acks.lock().unwrap().attempts(&hex::encode(id)), Some(1));
    // Review minor 6: B decrypts the re-sent payload under its retired
    // session (the old pair's ratchet).
    let retired = |b: &ClientInner| {
        b.session_manager
            .retired_parts_for_test(&p.pa.hex)
            .unwrap()
            .1
    };
    let before = retired(&p.b);
    for packet in packets {
        feed(&mut p.b, Frame::Relay(packet));
    }
    assert!(texts(&p.b_log).contains(&b"x".to_vec()), "decrypted");
    assert_eq!(retired(&p.b), before + 1, "under the retired session");
}

/// AK5 (client): evictions raise AckUnknown.
#[test]
fn ak5_evictions_raise_ack_unknown() {
    let mut p = establish(0xA1, 0xB2);
    for _ in 0..(crate::acks::MAX_TRACKED_ACKS + 3) {
        p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01e")
            .unwrap();
        drain(&mut p.a_rx); // the fake socket holds 256 frames
    }
    let unknown = statuses(&p.a_log)
        .iter()
        .filter(|s| matches!(s, crate::status::StatusEvent::AckUnknown { .. }))
        .count();
    assert_eq!(unknown, 3);
}

/// Resume the A→B circuit on a replaced transport (as in AK1).
fn replace_and_resume(a: &mut ClientInner) {
    a.handle_transport_reconnected();
    a.is_key_bundle_published = true;
    feed(
        a,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
}

/// AK3 (client): the first send and two re-sends go out; at the next
/// re-send opportunity the id is ack unknown (3 attempts) and not sent again.
#[test]
fn ak3_exhausted_at_the_next_resend_opportunity() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01x").unwrap();
    assert_eq!(sent_relays(&mut p.a_rx).len(), 1);
    for _ in 0..2 {
        replace_and_resume(&mut p.a);
        assert_eq!(sent_relays(&mut p.a_rx).len(), 1, "re-sent");
    }
    assert!(statuses(&p.a_log).is_empty());
    replace_and_resume(&mut p.a);
    assert!(sent_relays(&mut p.a_rx).is_empty(), "not a fourth time");
    assert_eq!(
        statuses(&p.a_log),
        vec![crate::status::StatusEvent::AckUnknown {
            peer: p.pb.hex.clone(),
            message_id: hex::encode(id),
            attempts: 3,
        }]
    );
    assert_eq!(p.a.acks.lock().unwrap().len(), 0);
}

/// F31: the 120 s clock counts only time while published.
#[test]
fn ack_clock_counts_published_time_only() {
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01x")
        .unwrap();
    let t0 = Instant::now();
    p.a.fire_ack_expiry(t0);
    p.a.is_key_bundle_published = false;
    p.a.fire_ack_expiry(t0 + Duration::from_secs(300));
    p.a.is_key_bundle_published = true;
    p.a.fire_ack_expiry(t0 + Duration::from_secs(400));
    assert!(statuses(&p.a_log).is_empty(), "100 s published");
    p.a.fire_ack_expiry(t0 + Duration::from_secs(421));
    assert!(matches!(
        statuses(&p.a_log).as_slice(),
        [crate::status::StatusEvent::AckUnknown { attempts: 1, .. }]
    ));
}

/// D35: the async send path (`send_queued_message`) tracks the sealed
/// payload it hands to the transport, under the message id.
#[test]
fn queued_send_tracks_the_sealed_payload() {
    let mut p = establish(0xA1, 0xB2);
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(9, "tracked"));
    let a = process_pending_on(p.a);
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    let tracked = a.acks.lock().unwrap().payloads_for(&p.pb.hex);
    assert_eq!(
        tracked,
        vec![(hex::encode([9u8; 16]), sent[0].payload.clone())]
    );
}

/// Review fix I1: unpin, block and re-pin drop the peer's tracked sends
/// (sealed to keys no longer trusted); a later pair re-sends none of them.
#[test]
fn revoked_peer_tracked_sends_are_dropped() {
    // Unpin, pin again, re-pair: nothing tracked goes out.
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01old")
        .unwrap();
    let old = sent_relays(&mut p.a_rx).remove(0).payload;
    p.a.unpin_peer(&p.pb.hex).unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "unpin");
    p.a.peers
        .pin(&p.pb.hex, p.pb.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    assert!(
        !sent_relays(&mut p.a_rx).iter().any(|r| r.payload == old),
        "not re-sent on the new pair"
    );
    // Only the new session's own notice is tracked now.
    assert!(!p
        .a
        .acks
        .lock()
        .unwrap()
        .payloads_for(&p.pb.hex)
        .iter()
        .any(|(_, payload)| *payload == old));

    // Re-pin to another agreement key (C-1).
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01old")
        .unwrap();
    p.a.apply_set_recipient(&p.pb.hex, Some(&hex::encode([0x5a; 32])))
        .unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "re-pin");

    // Block.
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01old")
        .unwrap();
    p.a.block_peer(&p.pb.hex, true).unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "block");
}

/// Review minor 2: a CircuitExists for a circuit already live on this
/// connection (the peer resumed) re-sends nothing.
#[test]
fn circuit_exists_for_a_live_circuit_resends_nothing() {
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01x")
        .unwrap();
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: false,
        }),
    );
    assert!(sent_relays(&mut p.a_rx).is_empty());
}

/// Review minor 3: an id already queued for a receipt is not queued twice.
#[test]
fn queued_receipt_ids_are_not_repeated() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(60));
    p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[1; 16], [1; 16]]);
    p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[1; 16], [2; 16]]);
    assert_eq!(
        p.b.owed_receipts(&p.pa.hex),
        vec![
            (crate::receipts::DELIVERED, [1; 16]),
            (crate::receipts::DELIVERED, [2; 16])
        ]
    );
}

/// Review minor 7: on the direct path a send the transport refused is not
/// tracked: the app sees the `Err` and shows it failed, and that stays final
/// (no later `on_message_delivered`).
#[test]
fn failed_direct_send_is_not_tracked() {
    let p = establish(0xA1, 0xB2);
    let peer_hex = p.pb.hex.clone();
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    drop(rx); // the socket is gone
    let ws = p.a.websocket.as_ref().unwrap();
    ws.install_outgoing_for_test(tx);
    ws.set_connected_for_test();
    let client = wrap(p.a);
    assert!(client.send_text_message(peer_hex, "lost".into()).is_err());
    assert_eq!(
        client.inner.try_read().unwrap().acks.lock().unwrap().len(),
        0
    );
}

/// Re-review: on the queued path nobody sees the `Err`, so a sealed message
/// the transport refused is tracked; the next resume sends the identical
/// payload, and its ack reports it delivered once.
#[test]
fn failed_queued_send_is_tracked_and_resent_on_resume() {
    let p = establish(0xA1, 0xB2);
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    drop(rx); // the socket is gone
    p.a.websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(tx);
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(9, "queued"));
    let mut a = process_pending_on(p.a);
    let id_hex = hex::encode([9u8; 16]);
    let tracked = a.acks.lock().unwrap().payloads_for(&p.pb.hex);
    assert_eq!(tracked.len(), 1);
    assert_eq!(tracked[0].0, id_hex);
    // A new connection, and the circuit resumes on it.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    a.websocket.as_ref().unwrap().install_outgoing_for_test(tx);
    let log = install_event_log(&mut a);
    a.bypass_frame_gate = true;
    replace_and_resume(&mut a);
    let sent = sent_relays(&mut rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].payload, tracked[0].1, "identical payload");
    feed(
        &mut a,
        Frame::Control(ControlMessage::MessageAck {
            message_id: id_hex.clone(),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            timestamp: 0,
        }),
    );
    let delivered = log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Delivered(x) if *x == id_hex))
        .count();
    assert_eq!(delivered, 1);
    assert_eq!(a.acks.lock().unwrap().len(), 0);
}

/// RV1 (client): a notice never triggers a receipt or a notice.
#[test]
fn rv1_notice_is_never_answered() {
    let mut p = establish(0xA1, 0xB2);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [5; 16], &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    p.a.fire_due_receipts(Instant::now() + Duration::from_secs(5));
    assert!(sent_relays(&mut p.a_rx).is_empty());
}

/// RV2: on each side exactly one notice per new session, the flag set iff
/// no prior session; none on resume.
#[test]
fn rv2_one_notice_per_new_session_both_sides() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    for c in [&mut a, &mut b] {
        c.receipt_delay_override = Some(Duration::ZERO);
    }
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut a, &mut b, &pa, &pb);
    // A (role 0): hello sync + notice. B (role 1): notice after the hello sync gives it a sending chain.
    let from_a = sent_relays(&mut a_rx);
    assert_eq!(from_a.len(), 2, "hello sync and A's notice");
    for pk in from_a {
        feed(&mut b, Frame::Relay(pk));
    }
    let from_b = sent_relays(&mut b_rx);
    assert_eq!(from_b.len(), 1, "B's notice");
    let opened = crate::sealed::open(
        &pa.bundle.identity_key,
        pa.id.agreement_secret(),
        &from_b[0].payload,
    )
    .unwrap();
    assert_eq!(opened.kind, crate::sealed::KIND_RATCHET);
    assert!(!b.notice_due.contains(&pa.hex), "sent and cleared");
    feed(
        &mut b,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    b.fire_due_receipts(Instant::now() + Duration::from_secs(5));
    assert!(sent_relays(&mut b_rx).is_empty(), "no notice on resume");
    // Both had a session now: the next pair's notices carry no flag, so
    // neither side, though its session replaced an established one,
    // raises a reset.
    let (a_log, b_log) = (install_event_log(&mut a), install_event_log(&mut b));
    // The relay acked the first pair's notices.
    relay_acked_all(&a);
    relay_acked_all(&b);
    reestablish(&mut a, &mut b, &pa, &pb);
    for pk in sent_relays(&mut a_rx) {
        feed(&mut b, Frame::Relay(pk));
    }
    let from_b = sent_relays(&mut b_rx);
    assert_eq!(from_b.len(), 1, "B's notice on the new session");
    for pk in from_b {
        feed(&mut a, Frame::Relay(pk));
    }
    for log in [&a_log, &b_log] {
        assert!(!statuses(log)
            .iter()
            .any(|s| matches!(s, crate::status::StatusEvent::PeerSessionReset { .. })));
    }
}

/// Ruling N4: reason 3 names only sends strictly before the new session;
/// one in the session's own second was sent on it.
#[test]
fn reason_3_is_strictly_before_the_new_session() {
    let mut p = establish(0xA1, 0xB2);
    let older = push_text(&p.a, &p.pb.hex, "older");
    drain(&mut p.a_rx);
    p.a.age_sent_for_test(&p.pb.hex, 1);
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    relay_all(&mut p.a_rx, &mut p.b); // B's sending chain
    drain(&mut p.b_rx);
    let fresh = push_text(&p.a, &p.pb.hex, "on the new session");
    drain(&mut p.a_rx);
    let fresh_at =
        p.a.sent_ids_for(&p.pb.hex)
            .iter()
            .find(|e| e.id == fresh)
            .unwrap()
            .sent_at_unix;
    {
        // As if the session were made in `fresh`'s second; B's first notice
        // never reached A in `establish`, so the reset is set by hand.
        let mut s = p.a.session_manager.get_mut(&p.pb.hex).unwrap();
        s.created_at_unix = fresh_at;
        s.reset_since_unix = Some(fresh_at);
    }
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: crate::notice::FLAG_NO_PRIOR_SESSION,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [8; 16], &pt).unwrap();
    p.a_log.lock().unwrap().clear();
    feed(&mut p.a, Frame::Relay(pk));
    let reported: Vec<String> = statuses(&p.a_log)
        .into_iter()
        .filter_map(|s| match s {
            crate::status::StatusEvent::PeerUndelivered {
                message_id,
                reason: 3,
                ..
            } => Some(message_id),
            _ => None,
        })
        .collect();
    assert_eq!(reported, vec![hex::encode(older)]);
}

/// RV4: a notice that decrypts only under the retired session is dropped.
#[test]
fn rv4_retired_session_cannot_carry_a_notice() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "will be reported");
    drain(&mut p.a_rx);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 1,
        reason: 1,
        ids: vec![id],
        sig: None,
    })
    .unwrap();
    let old = p.b.seal_ratchet(&p.pa.hex, [9; 16], &pt).unwrap();
    let ek_a = EphemeralKeyPair::generate();
    let i = ek_a.public_key().to_bytes();
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    feed(
        &mut p.a,
        created_v2(
            0,
            &p.pb.bundle,
            i,
            EphemeralKeyPair::generate().public_key().to_bytes(),
        ),
    ); // A's old session retired
    p.a_log.lock().unwrap().clear();
    feed(&mut p.a, Frame::Relay(old));
    assert!(statuses(&p.a_log).is_empty());
}

/// RV5: ids A never sent → no events; forged envelopes raise DecryptFailed
/// on B, capped at 256 ids.
#[test]
fn rv5_forged_ids_are_ignored_and_capped() {
    let mut p = establish(0xA1, 0xB2);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 1,
        ids: vec![[0xEE; 16]],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [5; 16], &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    assert!(statuses(&p.a_log).is_empty());
    // B's notice waits for the receipt timer, so the ids pile up unreported.
    p.b.receipt_delay_override = Some(Duration::from_secs(60));
    // 300 envelopes "from A" that decrypt under nothing.
    for i in 0..300u16 {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&i.to_be_bytes());
        let body = [vec![0u8; crate::crypto::RatchetHeader::LEN], vec![1u8; 64]].concat();
        let sealed = crate::sealed::seal(
            id,
            &p.pb.bundle.identity_key,
            &p.pb.bundle.identity_agreement_key,
            &p.pa.bundle.identity_key,
            crate::sealed::KIND_RATCHET,
            &body,
        )
        .unwrap();
        feed(&mut p.b, queued(sealed));
    }
    assert_eq!(
        p.b.undecryptable.get(&p.pa.hex).map(|q| q.len()),
        Some(crate::persistence::MAX_UNDECRYPTABLE)
    );
    let failed = statuses(&p.b_log)
        .iter()
        .filter(|s| {
            matches!(
                s,
                crate::status::StatusEvent::DecryptFailed { detail: 1, .. }
            )
        })
        .count();
    // Final review M-1: at most 32 DecryptFailed per peer per tick; the
    // rest are listed (capped above) and reported in the notices.
    assert_eq!(
        failed,
        crate::circuits::MAX_DECRYPT_FAILED_PER_TICK as usize,
        "DecryptFailed is rate-limited per tick"
    );
}

/// An undecryptable id listed on B: A's same-id resend decrypts and is
/// delivered once; a replay of that resend is dropped before decrypt.
#[test]
fn undecryptable_id_resend_passes_the_duplicate_drop_once() {
    let mut p = establish(0xA1, 0xB2);
    let id = [0x5a; 16];
    let body = [vec![0u8; crate::crypto::RatchetHeader::LEN], vec![1u8; 64]].concat();
    let forged = crate::sealed::seal(
        id,
        &p.pb.bundle.identity_key,
        &p.pb.bundle.identity_agreement_key,
        &p.pa.bundle.identity_key,
        crate::sealed::KIND_RATCHET,
        &body,
    )
    .unwrap();
    feed(&mut p.b, queued(forged));
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1, "B's notice");
    assert!(statuses(&p.a_log).is_empty(), "A never sent that id");
    // A really did send under that id, and resends it.
    let pk = p.a.seal_ratchet(&p.pb.hex, id, b"\x01resent").unwrap();
    let replay = pk.clone();
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(texts(&p.b_log), vec![b"resent".to_vec()]);
    let before =
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed);
    feed(&mut p.b, Frame::Relay(replay));
    assert_eq!(texts(&p.b_log).len(), 1, "replay dropped");
    assert_eq!(
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        before,
        "dropped before any decrypt"
    );
}

/// A notice's flag and ids reach the peer even when the session's first
/// write failed: the hello sync and the notice are re-driven by the tick
/// once writes succeed, so the responder gets its sending chain.
#[test]
fn hello_sync_and_notice_are_redriven_after_a_failed_install_write() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    for c in [&mut a, &mut b] {
        c.receipt_delay_override = Some(Duration::ZERO);
    }
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let sa = MemorySink::default();
    with_store(&mut a, &sa);
    sa.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    reestablish(&mut a, &mut b, &pa, &pb);
    assert!(
        sent_relays(&mut a_rx).is_empty(),
        "nothing leaves unpersisted"
    );
    let t0 = Instant::now();
    let tried = || sa.tried.load(std::sync::atomic::Ordering::SeqCst);
    let before = tried();
    a.redrive_owed_sends(t0);
    assert!(sent_relays(&mut a_rx).is_empty(), "still failing");
    assert_eq!(tried(), before + 1, "one probe");
    for ms in (250..2000).step_by(250) {
        a.redrive_owed_sends(t0 + Duration::from_millis(ms));
    }
    assert_eq!(tried(), before + 1, "throttled while the disk is full");
    sa.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    a.redrive_owed_sends(t0 + crate::circuits::REDRIVE_PROBE_INTERVAL);
    let from_a = sent_relays(&mut a_rx);
    assert_eq!(from_a.len(), 2, "hello sync and A's notice");
    for pk in from_a {
        feed(&mut b, Frame::Relay(pk));
    }
    assert_eq!(sent_relays(&mut b_rx).len(), 1, "B can send: its notice");
    a.redrive_owed_sends(t0 + 2 * crate::circuits::REDRIVE_PROBE_INTERVAL);
    assert!(sent_relays(&mut a_rx).is_empty(), "nothing owed twice");
}

/// The queued-send loss hook (3a note): messages whose session went while
/// they were being re-queued are reported, one `QueuedSendLost` each.
#[test]
fn queued_sends_whose_session_went_are_reported_lost() {
    let (mut a, _rx) = published(0xA1);
    let log = install_event_log(&mut a);
    let lost: std::collections::VecDeque<_> = [pending_msg(1, "x"), pending_msg(2, "y")]
        .into_iter()
        .collect();
    a.report_queued_sends_lost("ab", &lost);
    let ev = statuses(&log);
    assert_eq!(
        ev,
        vec![
            crate::status::StatusEvent::QueuedSendLost {
                peer: "ab".into(),
                message_id: hex::encode([1u8; 16]),
            },
            crate::status::StatusEvent::QueuedSendLost {
                peer: "ab".into(),
                message_id: hex::encode([2u8; 16]),
            },
        ]
    );
}

/// Named ids are reported in the notice's order, each once.
#[test]
fn named_ids_are_reported_in_notice_order_once() {
    let mut p = establish(0xA1, 0xB2);
    let x1 = push_text(&p.a, &p.pb.hex, "one");
    let x2 = push_text(&p.a, &p.pb.hex, "two");
    drain(&mut p.a_rx);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: crate::notice::REASON_UNDECRYPTABLE,
        ids: vec![x2, x1, x2],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [6; 16], &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    let order: Vec<String> = statuses(&p.a_log)
        .into_iter()
        .filter_map(|s| match s {
            crate::status::StatusEvent::PeerUndelivered { message_id, .. } => Some(message_id),
            _ => None,
        })
        .collect();
    assert_eq!(order, vec![hex::encode(x2), hex::encode(x1)]);
}

/// A second install before the first notice left keeps its flag (OR).
#[test]
fn an_owed_flag_survives_a_second_install() {
    let (mut a, _a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut a, &mut b, &pa, &pb); // B (responder) cannot send yet
    assert_eq!(b.notice_flag_pending.get(&pa.hex), Some(&1));
    reestablish(&mut a, &mut b, &pa, &pb); // B had a session now
    assert_eq!(
        b.notice_flag_pending.get(&pa.hex),
        Some(&1),
        "the unsent no-prior-session flag is kept"
    );
}

fn resets(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| matches!(s, crate::status::StatusEvent::PeerSessionReset { .. }))
        .count()
}

/// Task 11 follow-up: a relay restart re-makes a first-contact pair while
/// A's first notice (no prior session, truthfully) is still owed; neither
/// side lost state, so neither may report a reset.
#[test]
fn relay_restart_with_an_owed_first_notice_raises_no_reset() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    for c in [&mut a, &mut b] {
        c.receipt_delay_override = Some(Duration::from_secs(60));
    }
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let (a_log, b_log) = (install_event_log(&mut a), install_event_log(&mut b));
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    // First contact: both flags are true for this session.
    reestablish(&mut a, &mut b, &pa, &pb);
    assert_eq!(a.notice_flag_pending.get(&pb.hex), Some(&1));
    relay_all(&mut a_rx, &mut b); // A's hello sync
                                  // Messages both ways on the first session.
    let s1 = push_text(&a, &pb.hex, "s1");
    relay_all(&mut a_rx, &mut b);
    b.mark_seen_and_receipt(&pa.hex, s1).unwrap();
    let later = Instant::now() + Duration::from_secs(120);
    b.fire_due_receipts(later); // B's receipt and B's (flagged) notice
    relay_all(&mut b_rx, &mut a);
    assert!(!b.notice_due.contains(&pa.hex), "B's first notice left");
    assert!(
        a.notice_due.contains(&pb.hex),
        "A's first notice still owed"
    );
    // The relay restarts: the pair is re-made; both kept their state.
    reestablish(&mut a, &mut b, &pa, &pb);
    relay_all(&mut a_rx, &mut b); // hello sync
    a.fire_due_receipts(later);
    b.fire_due_receipts(later);
    relay_all(&mut a_rx, &mut b);
    relay_all(&mut b_rx, &mut a);
    assert!(!a.notice_due.contains(&pb.hex) && !b.notice_due.contains(&pa.hex));
    assert_eq!(resets(&a_log), 0, "A raised a reset");
    assert_eq!(resets(&b_log), 0, "B raised a reset");
}

/// Task 11 follow-up: B truly lost its state, and its first new session is
/// replaced (relay restart) before B's flagged notice could leave. The
/// reset is still reported, once, on the session that does carry it.
#[test]
fn a_genuine_loss_is_reported_across_a_second_install() {
    let mut p = establish(0xA1, 0xB2);
    // B's first notice (which `establish` drops) reaches A.
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: crate::notice::FLAG_NO_PRIOR_SESSION,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [8; 16], &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    assert_eq!(resets(&p.a_log), 0, "first contact: no reset");
    let lost = push_text(&p.a, &p.pb.hex, "never delivered");
    drain(&mut p.a_rx);
    p.a.age_sent_for_test(&p.pb.hex, 5);
    // B comes back with no state at all.
    let (mut b2, mut b2_rx) = published(0xB2);
    b2.peers
        .pin(&p.pa.hex, p.pa.bundle.identity_agreement_key)
        .unwrap();
    for c in [&mut p.a, &mut b2] {
        c.receipt_delay_override = Some(Duration::from_secs(60));
    }
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    assert_eq!(b2.notice_flag_pending.get(&p.pa.hex), Some(&1));
    drain(&mut p.a_rx); // the relay restarts before anything crosses
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    relay_all(&mut p.a_rx, &mut b2); // hello sync
    let later = Instant::now() + Duration::from_secs(120);
    p.a.fire_due_receipts(later);
    b2.fire_due_receipts(later);
    relay_all(&mut p.a_rx, &mut b2);
    relay_all(&mut b2_rx, &mut p.a);
    assert_eq!(resets(&p.a_log), 1, "A learns that B's session was reset");
    assert!(statuses(&p.a_log).iter().any(|s| matches!(
        s,
        crate::status::StatusEvent::PeerUndelivered { message_id, reason: 3, .. }
            if *message_id == hex::encode(lost)
    )));
}

/// The peer's verdict counts as heard on a notice or a receipt under the
/// current session (the peer flushes its owed notice with its receipts),
/// never on a plain message: the peer's notice may still be owed then.
#[test]
fn a_receipt_or_notice_marks_the_peers_notice_heard_and_a_message_does_not() {
    let mut p = establish(0xA1, 0xB2); // B's notice never reached A
    let heard =
        |c: &ClientInner, peer: &str| c.session_manager.get(peer).unwrap().peer_notice_heard;
    assert!(!heard(&p.a, &p.pb.hex));
    push_text(&p.b, &p.pa.hex, "from B");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(
        !heard(&p.a, &p.pb.hex),
        "a message says nothing of B's notice"
    );
    let to_b = push_text(&p.a, &p.pb.hex, "from A");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, to_b).unwrap();
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(heard(&p.a, &p.pb.hex), "a receipt from B");
    assert!(
        heard(&p.b, &p.pa.hex),
        "A's notice (relayed in `establish`)"
    );
}

/// Fix round 1 (review I-1): a receipt must never leave ahead of an owed
/// flagged notice. Here the outgoing queue has room for one frame when A's
/// receipt and its first-contact notice are both due: the notice takes it,
/// the receipt waits. Then the relay restarts; neither side lost state, so
/// B raises no reset and no reason-3 report.
#[test]
fn a_receipt_never_overtakes_an_owed_flagged_notice() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    for c in [&mut a, &mut b] {
        c.receipt_delay_override = Some(Duration::from_secs(60));
    }
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut a, &mut b, &pa, &pb); // first contact
    relay_all(&mut a_rx, &mut b); // A's hello sync
    let later = Instant::now() + Duration::from_secs(120);
    b.fire_due_receipts(later); // B's notice
    relay_all(&mut b_rx, &mut a);
    let m = push_text(&b, &pa.hex, "to be receipted");
    let unreceipted = push_text(&b, &pa.hex, "never receipted");
    b.age_sent_for_test(&pa.hex, 5);
    relay_all(&mut b_rx, &mut a);
    a.mark_seen_and_receipt(&pb.hex, m).unwrap();
    assert!(a.notice_due.contains(&pb.hex) && a.receipt_due.contains_key(&pb.hex));
    // One free slot in A's outgoing queue.
    let (tx1, mut rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    a.websocket.as_ref().unwrap().install_outgoing_for_test(tx1);
    a.fire_due_receipts(later);
    relay_all(&mut rx1, &mut b);
    // The relay restarts: the pair is re-made; both kept their state.
    let (tx2, mut a_rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    a.websocket.as_ref().unwrap().install_outgoing_for_test(tx2);
    reestablish(&mut a, &mut b, &pa, &pb);
    relay_all(&mut a_rx2, &mut b); // hello sync
    let later = later + Duration::from_secs(120);
    a.fire_due_receipts(later);
    b.fire_due_receipts(later);
    relay_all(&mut a_rx2, &mut b);
    relay_all(&mut b_rx, &mut a);
    assert_eq!(resets(&b_log), 0, "B raised a reset");
    assert!(
        !statuses(&b_log).iter().any(|s| matches!(
            s,
            crate::status::StatusEvent::PeerUndelivered { reason: 3, .. }
        )),
        "reason 3 for {}",
        hex::encode(unreceipted)
    );
}

/// Fix round 1 (review M-3): a receipt window that closes while the
/// transport is unusable is re-armed, so the receipt still leaves once
/// the queue has room again, with no other event to flush it.
#[test]
fn a_receipt_window_closing_on_a_full_queue_is_rearmed() {
    let mut p = establish(0xA1, 0xB2);
    p.b.receipt_delay_override = Some(Duration::from_secs(1));
    let id = push_text(&p.a, &p.pb.hex, "x");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    tx.try_send(vec![0]).unwrap(); // full
    p.b.websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(tx);
    let t = Instant::now() + Duration::from_secs(2);
    p.b.fire_due_receipts(t);
    let at = *p.b.receipt_due.get(&p.pa.hex).expect("re-armed");
    assert!(at > t);
    drop(rx);
    let (tx, mut b_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    p.b.websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(tx);
    p.b.fire_due_receipts(at);
    assert_eq!(relay_all(&mut b_rx, &mut p.a), 1);
    assert!(p.a_log.lock().unwrap().contains(&Ev::Receipt(
        p.pb.hex.clone(),
        hex::encode(id),
        crate::receipts::DELIVERED
    )));
}

/// B's sending-chain index for `peer` (a re-seal would advance it).
fn rr_ns(b: &ClientInner, peer: &str) -> u32 {
    b.session_manager
        .get(peer)
        .unwrap()
        .ratchet_snapshot()
        .unwrap()
        .ns
}

/// B's transport is replaced and its circuit resumed on the new one.
fn rr_replace_and_resume(b: &mut ClientInner) {
    b.handle_transport_reconnected();
    b.is_key_bundle_published = true;
    feed(
        b,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
}

/// RR1 (debug-receipts-hang concern 2): a delivered receipt handed to a
/// connection that is replaced before its frame left is not lost. The
/// resume re-sends the identical bytes (no new seal, no chain key spent),
/// the sender gets the receipt, and the relay's ack for it is never
/// reported to the app as a message ack.
#[test]
fn rr1_a_receipt_survives_a_transport_replacement() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let lost = sent_relays(&mut p.b_rx); // queued on the old connection, never written
    assert_eq!(lost.len(), 1, "the receipt was handed to the transport");
    let ns = rr_ns(&p.b, &p.pa.hex);
    rr_replace_and_resume(&mut p.b);
    let again = sent_relays(&mut p.b_rx);
    assert_eq!(again.len(), 1, "re-sent on the resume");
    assert_eq!(again[0].payload, lost[0].payload, "identical bytes");
    assert_eq!(rr_ns(&p.b, &p.pa.hex), ns, "no chain key spent");
    feed(&mut p.a, Frame::Relay(again[0].clone()));
    let receipts = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Receipt(_, x, 1) if *x == hex::encode(id)))
        .count();
    assert_eq!(receipts, 1, "the sender got its delivered receipt");
    let rid = hex::encode(&again[0].payload[1..17]);
    feed(
        &mut p.b,
        Frame::Control(ControlMessage::MessageAck {
            message_id: rid.clone(),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            timestamp: 0,
        }),
    );
    assert!(
        !p.b_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Delivered(x) if *x == rid)),
        "a receipt's ack is not a message ack"
    );
    assert_eq!(
        p.b.acks.lock().unwrap().len(),
        0,
        "acked: no longer tracked"
    );
}

/// RR2: a flagged notice and the receipts behind it, both lost with the
/// connection, go out again in the same order (I-1): the notice first, and
/// both before a receipt that became owed while the transport was down
/// (the resume re-sends what was tracked before it flushes what is owed).
#[test]
fn rr2_a_lost_flagged_notice_still_leaves_before_its_receipts() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    let later = push_text(&p.a, &p.pb.hex, "later");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.notice_flag_pending
        .insert(p.pa.hex.clone(), crate::notice::FLAG_NO_PRIOR_SESSION);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let lost: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert_eq!(lost.len(), 2, "notice + receipt handed to the transport");
    // The connection goes; the second message is stored while it is down.
    p.b.handle_transport_reconnected();
    p.b.mark_seen_and_receipt(&p.pa.hex, later).unwrap();
    assert!(
        sent_relays(&mut p.b_rx).is_empty(),
        "nothing leaves while down"
    );
    // Back: hello answered and publish accepted on the new connection.
    p.b.set_connected(true);
    p.b.is_key_bundle_published = true;
    feed(
        &mut p.b,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    let again: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert_eq!(
        again.len(),
        3,
        "the two lost frames and the new receipt; owed {:?} usable {} live {}",
        p.b.owed_receipts(&p.pa.hex),
        p.b.transport_usable(),
        p.b.has_live_circuit(&p.pa.hex)
    );
    assert_eq!(
        again[..2],
        lost[..],
        "same bytes, same order: the notice first"
    );
    // The new receipt is a fresh seal, after both.
    assert!(!lost.contains(&again[2]));
}

/// RR3 (review I-1): a receipt refused by a full but open queue is not
/// stranded in the tracker: it waits in `pending_receipts` (never sealed
/// while the queue has no room) and leaves with a later flush.
#[test]
fn rr3_a_receipt_refused_by_a_full_queue_is_not_stranded() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    // An owed notice (no flag) takes the queue's last slot.
    p.b.notice_due.insert(p.pa.hex.clone());
    let tx = p.b.websocket.as_ref().unwrap().outgoing_sender().unwrap();
    while tx.capacity() > 1 {
        p.b.send_now(vec![0]).unwrap();
    }
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    for f in sent_relays(&mut p.b_rx) {
        feed(&mut p.a, Frame::Relay(f)); // the notice, once the queue drains
    }
    let t0 = Instant::now();
    for i in 0..200u64 {
        let t = t0 + Duration::from_millis(250 * i);
        p.b.fire_due_receipts(t);
        p.b.redrive_owed_sends(t);
    }
    // A later flush to the peer (the next message stored) carries it.
    let id2 = push_text(&p.a, &p.pb.hex, "two");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id2).unwrap();
    relay_all(&mut p.b_rx, &mut p.a);
    let got = |x: [u8; 16]| {
        p.a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Receipt(_, m, 1) if *m == hex::encode(x)))
    };
    assert!(got(id), "the first receipt reached the sender");
    assert!(got(id2));
}

/// RR4 (review I-2): after a re-pair, a receipt tracked under the old
/// session is not re-sent as old-session bytes (a peer that lost its state
/// would report an undecryptable message): its ids are sealed again under
/// the new session. A tracked notice of the old session is dropped (D37).
#[test]
fn rr4_old_session_receipts_are_resealed_under_the_new_session() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    drain(&mut p.b_rx); // lost
                        // A restarts with no state and the pair is re-made.
    let (mut a2, mut a2_rx) = published(0xA1);
    a2.receipt_delay_override = Some(Duration::ZERO);
    let a2_log = install_event_log(&mut a2);
    a2.peers
        .pin(&p.pb.hex, p.pb.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut a2, &mut p.b, &p.pa, &p.pb);
    relay_all(&mut a2_rx, &mut p.b); // A2's hello sync gives B a sending chain
    let from_b = sent_relays(&mut p.b_rx);
    assert!(!from_b.is_empty());
    for f in from_b {
        feed(&mut a2, Frame::Relay(f));
    }
    assert!(
        !statuses(&a2_log)
            .iter()
            .any(|s| matches!(s, crate::status::StatusEvent::DecryptFailed { .. })),
        "nothing B sent is undecryptable for the new session: {:?}",
        statuses(&a2_log)
    );

    // Both sides kept their state (review N-4): B's receipt, tracked under
    // the old session and lost, is sealed again under the new one and
    // reaches A.
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "kept");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let lost = sent_relays(&mut p.b_rx);
    assert_eq!(lost.len(), 1);
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    relay_all(&mut p.a_rx, &mut p.b);
    let from_b = sent_relays(&mut p.b_rx);
    assert!(
        !from_b.iter().any(|f| f.payload == lost[0].payload),
        "never the old-session bytes"
    );
    for f in from_b {
        feed(&mut p.a, Frame::Relay(f));
    }
    assert!(
        p.a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Receipt(_, m, 1) if *m == hex::encode(id))),
        "the re-sealed receipt reached A"
    );
}

/// RR5 (review M-1): the relay refusing a circuit marks tracked notices and
/// receipts not accepted, but never reports their ids to the app.
#[test]
fn rr5_internal_entries_never_reach_the_app_as_send_not_accepted() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let sent = sent_relays(&mut p.b_rx);
    assert_eq!(sent.len(), 1);
    p.b.handle_circuit_not_found(&format!(
        "{}{}",
        crate::protocol::CIRCUIT_NOT_FOUND_PREFIX,
        hex::encode(sent[0].circuit_id.0)
    ));
    assert!(
        !statuses(&p.b_log)
            .iter()
            .any(|s| matches!(s, crate::status::StatusEvent::SendNotAccepted { .. })),
        "{:?}",
        statuses(&p.b_log)
    );
}

/// RR6 (review M-2): the resume's re-send stops at the first frame the
/// transport refuses, so a receipt can never overtake the notice ahead of it.
#[test]
fn rr6_the_resend_stops_at_the_first_refused_frame() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.notice_flag_pending
        .insert(p.pa.hex.clone(), crate::notice::FLAG_NO_PRIOR_SESSION);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let lost: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert_eq!(lost.len(), 2);
    p.b.handle_transport_reconnected();
    p.b.is_key_bundle_published = true;
    p.b.refuse_sends_for_test
        .store(1, std::sync::atomic::Ordering::SeqCst); // the notice is refused
    feed(
        &mut p.b,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    let sent: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert!(
        !sent.contains(&lost[1]),
        "the receipt did not overtake the refused notice"
    );
}

/// RR7 (review M-3, M-5): a tracked flagged notice and its receipt that
/// leave the tracker without an ack raise no AckUnknown; the notice and its
/// flag are owed again and the receipt ids go back to the owed receipts.
#[test]
fn rr7_unacked_internal_entries_that_expire_are_owed_again_silently() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.notice_flag_pending
        .insert(p.pa.hex.clone(), crate::notice::FLAG_NO_PRIOR_SESSION);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    assert_eq!(sent_relays(&mut p.b_rx).len(), 2);
    assert!(!p.b.notice_flag_pending.contains_key(&p.pa.hex));
    p.b.set_connected(false); // hold what is owed again, to look at it
    let t0 = Instant::now();
    p.b.fire_ack_expiry(t0);
    p.b.fire_ack_expiry(t0 + crate::acks::ACK_UNKNOWN_AFTER + Duration::from_secs(1));
    assert!(
        !statuses(&p.b_log)
            .iter()
            .any(|s| matches!(s, crate::status::StatusEvent::AckUnknown { .. })),
        "{:?}",
        statuses(&p.b_log)
    );
    assert_eq!(p.b.acks.lock().unwrap().len(), 0);
    assert!(
        p.b.notice_due.contains(&p.pa.hex),
        "the notice is owed again"
    );
    assert_eq!(
        p.b.notice_flag_pending.get(&p.pa.hex),
        Some(&crate::notice::FLAG_NO_PRIOR_SESSION)
    );
    assert!(p.b.owed_receipts(&p.pa.hex).contains(&(1, id)));
    // Back: the notice (flagged, sealed afresh) leaves, then the receipt.
    p.b.set_connected(true);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(sent_relays(&mut p.b_rx).len(), 2);
    assert!(!p.b.notice_flag_pending.contains_key(&p.pa.hex));
    assert!(p.b.owed_receipts(&p.pa.hex).is_empty());
}

/// RR8 (review N-1): against a relay that never acks (or refuses, which an
/// honest relay does without an ack), an owed notice and a receipt are
/// re-owed a bounded number of times with growing gaps, then given up
/// silently: an hour of connected time spends exactly 8 chain keys
/// (each of the two sealed once, then re-owed `ACK_MAX_ATTEMPTS` = 3 times,
/// at 120 s, 240 s and 480 s gaps of connected time; the fourth expiry,
/// 960 s later, gives up).
#[test]
fn rr8_a_never_acking_relay_costs_a_bounded_number_of_chain_keys() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    let ns0 = rr_ns(&p.b, &p.pa.hex);
    p.b.notice_due.insert(p.pa.hex.clone()); // an empty notice, no flag
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    let t0 = Instant::now();
    let mut sent = sent_relays(&mut p.b_rx).len();
    for s in 0..=3600u64 {
        let t = t0 + Duration::from_secs(s);
        p.b.fire_ack_expiry(t);
        p.b.fire_due_receipts(t);
        p.b.redrive_owed_sends(t);
        sent += sent_relays(&mut p.b_rx).len();
    }
    assert_eq!(
        rr_ns(&p.b, &p.pa.hex) - ns0,
        8,
        "chain keys spent in an hour"
    );
    assert_eq!(sent, 8, "packets sent in an hour");
    assert_eq!(p.b.acks.lock().unwrap().len(), 0, "given up");
    assert!(
        !statuses(&p.b_log)
            .iter()
            .any(|s| matches!(s, crate::status::StatusEvent::AckUnknown { .. })),
        "silently"
    );
}

/// RR9 (review N-2): a re-owed flagged notice is never re-tracked behind a
/// receipt of the same session: the receipt is owed again behind the flag,
/// so a resume re-sends the notice first.
#[test]
fn rr9_a_reowed_flagged_notice_still_precedes_its_receipts() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    let t0 = Instant::now();
    p.b.fire_ack_expiry(t0);
    // T: the flagged notice leaves alone (and is lost).
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.notice_flag_pending
        .insert(p.pa.hex.clone(), crate::notice::FLAG_NO_PRIOR_SESSION);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(sent_relays(&mut p.b_rx).len(), 1);
    // T+5 s: a receipt, not held (the flag left with the notice).
    p.b.fire_ack_expiry(t0 + Duration::from_secs(5));
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    assert_eq!(sent_relays(&mut p.b_rx).len(), 1);
    // T+122 s: the notice expires and is owed again, flag and all.
    p.b.fire_ack_expiry(t0 + Duration::from_secs(122));
    let reowed: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert!(!reowed.is_empty());
    // Everything since is lost with the connection; the resume re-sends.
    rr_replace_and_resume(&mut p.b);
    let again: Vec<Vec<u8>> = sent_relays(&mut p.b_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    assert_eq!(
        again.first(),
        reowed.first(),
        "the re-owed notice goes first"
    );
    assert_eq!(again, reowed, "and nothing tracked earlier overtakes it");
}

/// RR10 (review N-3): a notice re-owed after it left unacked reports its
/// ids again: undecryptable ids are listed again, and lost ids move back
/// from `lost_reported` to `lost_unstored`.
#[test]
fn rr10_a_reowed_notice_lists_its_ids_again() {
    let mut p = establish(0xA1, 0xB2);
    let (bad, lost) = ([0xBA; 16], [0x10; 16]);
    p.b.undecryptable.insert(
        p.pa.hex.clone(),
        std::collections::VecDeque::from(vec![bad]),
    );
    p.b.lost_unstored.insert(
        p.pa.hex.clone(),
        std::collections::VecDeque::from(vec![lost]),
    );
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.flush_receipts(&p.pa.hex);
    p.b.flush_receipts(&p.pa.hex); // one batch per flush (M-1)
    assert_eq!(sent_relays(&mut p.b_rx).len(), 2, "one batch per reason");
    assert!(p.b.lost_reported[&p.pa.hex].iter().any(|(x, _)| *x == lost));
    p.b.set_connected(false); // hold what is owed again, to look at it
    let t0 = Instant::now();
    p.b.fire_ack_expiry(t0);
    p.b.fire_ack_expiry(t0 + crate::acks::ACK_UNKNOWN_AFTER + Duration::from_secs(1));
    assert!(p.b.notice_due.contains(&p.pa.hex));
    assert!(p.b.undecryptable[&p.pa.hex].contains(&bad));
    assert!(p.b.lost_unstored[&p.pa.hex].contains(&lost));
    assert!(!p
        .b
        .lost_reported
        .get(&p.pa.hex)
        .is_some_and(|q| q.iter().any(|(x, _)| *x == lost)));
}

/// The implementer's concern 1, pinned (review): a second copy of a notice
/// for the same session (its ack was lost, so it was owed again) raises no
/// second reset, no second ResendEligible and no second PeerUndelivered.
#[test]
fn second_notice_same_session_is_harmless() {
    let mut r = rv3_run(2, |_, _| {});
    let count = |log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>| {
        let st = statuses(log);
        let n = |f: fn(&crate::status::StatusEvent) -> bool| st.iter().filter(|s| f(s)).count();
        (
            n(|s| matches!(s, crate::status::StatusEvent::PeerSessionReset { .. })),
            n(|s| matches!(s, crate::status::StatusEvent::ResendEligible { .. })),
            n(|s| matches!(s, crate::status::StatusEvent::PeerUndelivered { .. })),
        )
    };
    let before = count(&r.p.a_log);
    assert!(before.0 >= 1 && before.1 >= 1, "{before:?}");
    // B2's notice was never acked: it expires through the real path and is
    // sealed again, then reaches A.
    drain(&mut r.b2_rx);
    let t0 = Instant::now();
    r.b2.fire_ack_expiry(t0);
    r.b2.fire_ack_expiry(t0 + crate::acks::ACK_UNKNOWN_AFTER + Duration::from_secs(1));
    let again = sent_relays(&mut r.b2_rx);
    assert!(!again.is_empty(), "the notice was sealed again");
    for f in again {
        feed(&mut r.p.a, Frame::Relay(f));
    }
    assert_eq!(count(&r.p.a_log), before);
}

/// A departed internal entry of `peer` under `binding`, for settle tests.
fn r4_departed(peer: &str, binding: [u8; 32], what: crate::acks::Internal) -> crate::acks::Tracked {
    crate::acks::Tracked {
        peer: peer.to_string(),
        payload: vec![1],
        circuit: C1,
        first_sent: Instant::now(),
        attempts: 1,
        not_accepted: false,
        connected_for: Duration::ZERO,
        internal: Some(what),
        binding,
        expire_after: crate::acks::ACK_UNKNOWN_AFTER,
    }
}

fn r4_binding(c: &ClientInner, peer: &str) -> [u8; 32] {
    c.session_manager.get(peer).unwrap().session_binding
}

/// R3-1: a full re-owe map is never cleared. Counters of ids no longer
/// tracked or owed are dropped first; if it is still full, the new id is
/// given up. 5 peers x 1000 ids against a never-acking relay stay within
/// the cap, and a live id keeps its count.
#[test]
fn r4_a_full_reowe_map_is_pruned_never_cleared() {
    let (mut c, _rx) = published(0xB2);
    let peers: Vec<String> = (1..=5u8)
        .map(|i| {
            let p = peer(0x10 + i);
            c.peers
                .pin(&p.hex, p.bundle.identity_agreement_key)
                .unwrap();
            p.hex
        })
        .collect();
    let rid = |p: usize, i: usize| {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(p as u64).to_be_bytes());
        id[8..].copy_from_slice(&(i as u64).to_be_bytes());
        id
    };
    let receipt = |id| crate::acks::Internal::Receipt {
        kind: crate::receipts::DELIVERED,
        ids: vec![id],
    };
    // Peer 0's first id departs twice early on: its count is 2, and it
    // stays owed (pending) throughout.
    for _ in 0..2 {
        let t = r4_departed(&peers[0], [0; 32], receipt(rid(0, 0)));
        c.settle_internal(&peers[0].clone(), t, true);
    }
    for round in 0..2 {
        for (p, hex) in peers.iter().enumerate() {
            for i in 0..1000 {
                let t = r4_departed(hex, [0; 32], receipt(rid(p, i)));
                c.settle_internal(&hex.clone(), t, true);
                assert!(
                    c.reowes.len() <= crate::acks::MAX_REOWE_COUNTERS,
                    "round {round}: {} counters",
                    c.reowes.len()
                );
            }
        }
    }
    assert_eq!(
        c.reowes
            .iter()
            .find(|(k, _)| k.0 == peers[0]
                && format!("{:?}", k.1).contains(&format!("{:?}", rid(0, 0))))
            .map(|(_, v)| v.1),
        Some(crate::acks::REOWE_CAP),
        "a live id is never reset: 2 early, 1 in the first round, then given up at the cap"
    );
}

/// R3-2: a receipt id's re-owes are counted per receipt kind: a read
/// receipt for an id whose delivered receipt was given up still gets its
/// own re-owes.
#[test]
fn r4_receipt_reowes_are_counted_per_kind() {
    let mut p = establish(0xA1, 0xB2);
    let b = r4_binding(&p.b, &p.pa.hex);
    let id = [0x44; 16];
    for _ in 0..crate::acks::REOWE_CAP + 1 {
        let t = r4_departed(
            &p.pa.hex,
            b,
            crate::acks::Internal::Receipt {
                kind: crate::receipts::DELIVERED,
                ids: vec![id],
            },
        );
        p.b.settle_internal(&p.pa.hex.clone(), t, true);
    }
    p.b.pending_receipts.clear();
    let t = r4_departed(
        &p.pa.hex,
        b,
        crate::acks::Internal::Receipt {
            kind: crate::receipts::READ,
            ids: vec![id],
        },
    );
    p.b.settle_internal(&p.pa.hex.clone(), t, true);
    assert!(p
        .b
        .owed_receipts(&p.pa.hex)
        .contains(&(crate::receipts::READ, id)));
}

/// R3-2: a notice with new content gets its own re-owes: an earlier
/// notice of the session that was given up does not use them up.
#[test]
fn r4_a_notice_with_new_ids_gets_its_own_reowes() {
    let mut p = establish(0xA1, 0xB2);
    let b = r4_binding(&p.b, &p.pa.hex);
    let notice = |ids: Vec<[u8; 16]>| crate::acks::Internal::Notice {
        flags: 0,
        reason: crate::notice::REASON_UNDECRYPTABLE,
        ids,
    };
    for _ in 0..crate::acks::REOWE_CAP + 1 {
        let t = r4_departed(&p.pa.hex, b, notice(vec![[1; 16]]));
        p.b.settle_internal(&p.pa.hex.clone(), t, true);
    }
    p.b.notice_due.clear();
    let t = r4_departed(&p.pa.hex, b, notice(vec![[2; 16]]));
    p.b.settle_internal(&p.pa.hex.clone(), t, true);
    assert!(
        p.b.notice_due.contains(&p.pa.hex),
        "the new notice is owed again"
    );
}

/// Drive `c` for `secs` of connected time against a relay that never acks
/// (1 s ticks); the seconds at which it sent anything to the peer.
fn r4_send_times(
    c: &mut ClientInner,
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    secs: u64,
) -> Vec<u64> {
    let t0 = Instant::now();
    let mut at = Vec::new();
    for s in 0..=secs {
        let t = t0 + Duration::from_secs(s);
        c.fire_ack_expiry(t);
        c.fire_due_receipts(t);
        c.redrive_owed_sends(t);
        if !sent_relays(rx).is_empty() {
            at.push(s);
        }
    }
    at
}

/// R3-3: a flagged notice gives up after exactly `REOWE_CAP_FLAGGED` (6)
/// re-owes: 7 seals in all, then nothing, and the flag is given up.
#[test]
fn r4_a_flagged_notice_gives_up_after_exactly_six_reowes() {
    let mut p = establish(0xA1, 0xB2);
    let ns0 = rr_ns(&p.b, &p.pa.hex);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.notice_flag_pending
        .insert(p.pa.hex.clone(), crate::notice::FLAG_NO_PRIOR_SESSION);
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(sent_relays(&mut p.b_rx).len(), 1);
    let at = r4_send_times(&mut p.b, &mut p.b_rx, 24 * 3600);
    assert_eq!(at.len(), 6, "six re-owes: {at:?}");
    assert_eq!(rr_ns(&p.b, &p.pa.hex) - ns0, 7, "seven seals in all");
    assert!(!p.b.notice_due.contains(&p.pa.hex));
    assert!(!p.b.notice_flag_pending.contains_key(&p.pa.hex));
}

/// R3-3: the gaps between re-seals double (connected time, 1 s ticks: an
/// entry leaves on the first tick past its 120 s x 2^n).
#[test]
fn r4_the_gaps_between_reseals_double() {
    let mut p = establish(0xA1, 0xB2);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.flush_receipts(&p.pa.hex);
    assert_eq!(sent_relays(&mut p.b_rx).len(), 1, "sealed at 0 s");
    let at = r4_send_times(&mut p.b, &mut p.b_rx, 3 * 3600);
    assert_eq!(at, vec![121, 362, 843], "re-sealed after 121, 241, 481 s");
}

/// R3-3: the relay's ack of a re-sealed copy resets its counter: a later
/// loss of the same content starts again at 120 s.
#[test]
fn r4_the_relay_ack_resets_the_counter() {
    let mut p = establish(0xA1, 0xB2);
    p.b.notice_due.insert(p.pa.hex.clone());
    p.b.flush_receipts(&p.pa.hex);
    drain(&mut p.b_rx);
    let t0 = Instant::now();
    p.b.fire_ack_expiry(t0);
    p.b.fire_ack_expiry(t0 + Duration::from_secs(121)); // re-owed once
    let copy = sent_relays(&mut p.b_rx);
    assert_eq!(copy.len(), 1);
    assert_eq!(p.b.reowes.len(), 1);
    feed(
        &mut p.b,
        Frame::Control(ControlMessage::MessageAck {
            message_id: hex::encode(&copy[0].payload[1..17]),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            timestamp: 0,
        }),
    );
    assert!(p.b.reowes.is_empty(), "the ack resets it");
    assert_eq!(p.b.acks.lock().unwrap().len(), 0);
}

/// Final review H-1 (`audit_resend_after_session_replaced_reaches_seed_thief`,
/// kept as a regression test): a resend made eligible by the real phone's
/// signed notice under session S1 must never go into a session S2 that a
/// seed thief (with the relay) set up meanwhile. The checked resend is
/// refused and the thief receives nothing.
#[test]
fn audit_resend_after_session_replaced_reaches_seed_thief() {
    let mut r = rv3_run_with_keys(1, Some(3), Some(3), |_, _| {});
    let id = r.ids[0];
    let id_hex = hex::encode(id);
    assert!(
        statuses(&r.p.a_log).iter().any(
            |s| matches!(s, crate::status::StatusEvent::ResendEligible { message_id, .. } if *message_id == id_hex)
        ),
        "the real phone's signed notice made it eligible"
    );
    // The thief holds Bob's seed (same identity, same agreement key).
    let (mut thief, _thief_rx) = published(0xB2);
    thief.receipt_delay_override = Some(Duration::ZERO);
    let thief_log = install_event_log(&mut thief);
    thief
        .peers
        .pin(&r.p.pa.hex, r.p.pa.bundle.identity_agreement_key)
        .unwrap();
    reestablish(&mut r.p.a, &mut thief, &r.p.pa, &r.p.pb);
    for f in sent_relays(&mut r.p.a_rx) {
        feed(&mut thief, Frame::Relay(f)); // A's hello sync and notice
    }
    let a = std::mem::replace(
        &mut r.p.a,
        crate::ClientInner::new(crate::ClientConfig::default()),
    );
    let client = wrap(a);
    // The app's deferred automatic resend fires now.
    let sent = client.resend_text_message_using_id(r.p.pb.hex.clone(), "q0".into(), id_hex.clone());
    assert!(
        matches!(sent, Err(crate::RChatError::ResendRefused { .. })),
        "refused: {sent:?}"
    );
    for f in sent_relays(&mut r.p.a_rx) {
        feed(&mut thief, Frame::Relay(f));
    }
    assert!(texts(&thief_log).is_empty(), "the thief receives nothing");
}

/// H-1: under the session that made it eligible, the checked resend goes.
#[test]
fn the_checked_resend_goes_under_the_eligible_session() {
    let mut r = rv3_run_with_keys(1, Some(3), Some(3), |_, _| {});
    let id_hex = hex::encode(r.ids[0]);
    let a = std::mem::replace(
        &mut r.p.a,
        crate::ClientInner::new(crate::ClientConfig::default()),
    );
    let client = wrap(a);
    let sent = client.resend_text_message_using_id(r.p.pb.hex.clone(), "q0".into(), id_hex.clone());
    assert_eq!(sent.unwrap(), id_hex);
    let frames = sent_relays(&mut r.p.a_rx);
    assert_eq!(frames.len(), 1);
    feed(&mut r.b2, Frame::Relay(frames[0].clone()));
    assert!(texts(&r.b2_log).contains(&b"q0".to_vec()));
}

/// A sealed ratchet envelope "from" `sender` to `to` with `id` and a body
/// that never decrypts (a forgery needs only the recipient's public keys).
fn forged(sender: &Peer, to: &Peer, id: [u8; 16]) -> Vec<u8> {
    let header = crate::crypto::RatchetHeader {
        message_number: 0,
        previous_chain_length: 0,
        dh_public_key: rand::random(),
    };
    let mut body = header.encode().to_vec();
    body.extend_from_slice(&[0x5a; 64]);
    crate::sealed::seal(
        id,
        &to.bundle.identity_key,
        &to.bundle.identity_agreement_key,
        &sender.bundle.identity_key,
        crate::sealed::KIND_RATCHET,
        &body,
    )
    .unwrap()
}

/// Final review L-1: a forged copy of id X listed X as undecryptable; the
/// genuine X then decrypts, so X is unlisted and never reported.
#[test]
fn l1_an_undecryptable_id_is_unlisted_when_its_genuine_copy_decrypts() {
    let mut p = establish(0xA1, 0xB2);
    let x: [u8; 16] = rand::random();
    p.b.set_connected(false); // the notice waits, so the listing is visible
    feed(&mut p.b, queued(forged(&p.pa, &p.pb, x)));
    assert!(
        p.b.undecryptable[&p.pa.hex].contains(&x),
        "the forgery listed it"
    );
    let pk = p.a.seal_ratchet(&p.pb.hex, x, b"\x01genuine").unwrap();
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(texts(&p.b_log), vec![b"genuine".to_vec()]);
    assert!(
        !p.b.undecryptable
            .get(&p.pa.hex)
            .is_some_and(|q| q.contains(&x)),
        "unlisted once the genuine copy decrypted"
    );
}

/// Final review L-5: a repeated reason-2 notice for one of our ids raises
/// PeerUndelivered once per id per session.
#[test]
fn l5_reason_2_reports_are_raised_once_per_id() {
    let mut p = establish(0xA1, 0xB2);
    let x = push_text(&p.a, &p.pb.hex, "lost");
    drain(&mut p.a_rx);
    for i in 0..3u8 {
        let pt = crate::notice::encode(&crate::notice::Notice {
            flags: 0,
            reason: crate::notice::REASON_LOST_BEFORE_STORED,
            ids: vec![x],
            sig: None,
        })
        .unwrap();
        let pk = p.b.seal_ratchet(&p.pa.hex, [0x60 + i; 16], &pt).unwrap();
        feed(&mut p.a, Frame::Relay(pk));
    }
    let n = statuses(&p.a_log)
        .iter()
        .filter(|s| {
            matches!(
                s,
                crate::status::StatusEvent::PeerUndelivered { reason: 2, .. }
            )
        })
        .count();
    assert_eq!(n, 1);
}

/// H-1, the re-check under the sealing guard: the checked resend starts
/// with the circuit down (so the first check passes under the eligible
/// session and the send waits); a seed thief's session is installed during
/// the wait. The re-check under the guard that seals refuses, and the thief
/// receives nothing.
#[test]
fn a_session_installed_during_the_resend_wait_is_refused_under_the_seal() {
    let mut r = rv3_run_with_keys(1, Some(3), Some(3), |_, _| {});
    let id_hex = hex::encode(r.ids[0]);
    let (mut thief, _thief_rx) = published(0xB2);
    thief.receipt_delay_override = Some(Duration::ZERO);
    let thief_log = install_event_log(&mut thief);
    thief
        .peers
        .pin(&r.p.pa.hex, r.p.pa.bundle.identity_agreement_key)
        .unwrap();
    let mut a = std::mem::replace(
        &mut r.p.a,
        crate::ClientInner::new(crate::ClientConfig::default()),
    );
    a.send_wait_ms = 5_000;
    a.transport_epoch += 1; // the circuit is down: the send waits for one
    assert!(
        a.check_auto_resend(&r.p.pb.hex, &r.ids[0]).is_ok(),
        "eligible here"
    );
    let client = wrap(a);
    let c = client.clone();
    let pb = r.p.pb.hex.clone();
    let sending =
        std::thread::spawn(move || c.resend_text_message_using_id(pb, "q0".into(), id_hex));
    std::thread::sleep(Duration::from_millis(300)); // in the wait
    {
        let mut g = client.inner.blocking_write();
        reestablish(&mut g, &mut thief, &r.p.pa, &r.p.pb);
    }
    let sent = sending.join().unwrap();
    assert!(
        matches!(sent, Err(crate::RChatError::ResendRefused { .. })),
        "refused under the seal: {sent:?}"
    );
    for f in sent_relays(&mut r.p.a_rx) {
        feed(&mut thief, Frame::Relay(f));
    }
    assert!(texts(&thief_log).is_empty(), "the thief receives nothing");
}

/// H-1, the `!can_send` branch: a checked resend for a session that has no
/// sending chain yet (a responder before the initiator's first message) is
/// refused, never parked on the session for whatever session is current
/// when it would be flushed.
#[test]
fn a_checked_resend_without_a_sending_chain_is_refused_not_queued() {
    let mut p = establish(0xA1, 0xB2);
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb); // A's hello sync is not relayed
    drain(&mut p.b_rx);
    assert!(!p.b.session_manager.get(&p.pa.hex).unwrap().can_send());
    let id: [u8; 16] = rand::random();
    p.b.record_sent(&p.pa.hex, id);
    p.b.mark_sent_resent(&p.pa.hex, &id);
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .reported_lost
        .insert(id, (crate::notice::REASON_UNDECRYPTABLE, true));
    assert!(
        p.b.check_auto_resend(&p.pa.hex, &id).is_ok(),
        "every other check holds"
    );
    let b = std::mem::replace(
        &mut p.b,
        crate::ClientInner::new(crate::ClientConfig::default()),
    );
    let client = wrap(b);
    let sent = client.resend_text_message_using_id(p.pa.hex.clone(), "x".into(), hex::encode(id));
    assert!(
        matches!(sent, Err(crate::RChatError::ResendRefused { .. })),
        "{sent:?}"
    );
    let g = client.inner.try_read().unwrap();
    assert!(
        g.session_manager
            .get(&p.pa.hex)
            .unwrap()
            .pending_messages
            .is_empty(),
        "nothing parked on the session"
    );
    drop(g);
    assert!(sent_relays(&mut p.b_rx).is_empty());
}
