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
    b.peers.pin_card(&pa).unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek, Instant::now());
    (b, rx, pa, ek_pub)
}

/// P3 / M7d: a one-character message and a receipt both occupy the
/// 256-byte bucket on the wire; knocks stay exactly 5120 bytes (L3, §A.5).
#[test]
fn ratchet_plaintexts_are_padded_and_knocks_are_not() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "x");
    let relays = sent_relays(&mut p.a_rx);
    // sealed: header 73 + AEAD tag 16 + sender 32 + kind 1 + ratchet header 40
    //         + ratchet nonce 24 + padded plaintext 256 + ratchet tag 16
    let expected = sealed::SEALED_HEADER_LEN + 16 + 33 + 40 + 24 + 256 + 16;
    assert_eq!(expected, sealed::RATCHET_ENVELOPE_OVERHEAD + 256);
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
    a.peers.pin_card(&pb).unwrap();
    a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    assert_eq!(asks(&mut rx)[0].2.len(), sealed::KNOCK_PAYLOAD_LEN);
}

/// R1, §A.5: the sender needs the recipient's pinned ML-KEM key (from
/// the contact's card). Without one, the ask (which always carries a
/// knock) fails locally with the typed `NoKemKey`, nothing is sent, and
/// there is never an X25519-only knock; the automatic path defers it.
#[test]
fn knock_without_pinned_kem_pk_is_refused_locally() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    assert!(a.peers.kem_pk_for(&pb.hex).is_none());
    let r = a.ask(&pb.hex, AskTrigger::User, Instant::now());
    assert!(
        matches!(r, Err(crate::RChatError::NoKemKey { ref identity }) if *identity == pb.hex),
        "{r:?}"
    );
    assert!(sent_controls(&mut rx).is_empty(), "nothing left the device");
    assert_eq!(a.peers.outstanding_asks(&pb.hex), 0);
    // With the card's key pinned, the same ask goes out as a v3 knock.
    assert!(a.peers.set_kem_pk(&pb.hex, pb.bundle.kem_pk.clone()));
    a.ask(
        &pb.hex,
        AskTrigger::User,
        Instant::now() + Duration::from_secs(700),
    )
    .unwrap();
    let sent = asks(&mut rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].2.len(), sealed::KNOCK_PAYLOAD_LEN);
    assert_eq!(sent[0].2[0], sealed::KNOCK_VERSION);
}

/// Fix round 1 M-2: an ask that can't be sent for want of a KEM key
/// charges no backoff, by the user, the automatic path or each publish's
/// retry of the deferred ask.
#[test]
fn missing_kem_key_charges_no_backoff() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    let now = Instant::now();
    for _ in 0..3 {
        assert!(a.ask(&pb.hex, AskTrigger::User, now).is_err());
        assert!(a.ask(&pb.hex, AskTrigger::Auto, now).is_err());
        a.deferred_asks.push(pb.hex.clone());
        a.after_publish_ok(now);
    }
    assert_eq!(a.peers.backoff_mut(&pb.hex).attempts(), 0);
    assert!(!a.pending_reasks.contains_key(&pb.hex));
    assert!(sent_controls(&mut rx).is_empty());
}

/// Accepting a request (spec §6.3, §A.5): the requester's ML-KEM key came
/// in its knock, inside the bundle its identity signed, so pinning it
/// under the agreement key the request named lets the acceptor knock back.
/// A pinned contact's verified knock fills a missing KEM key the same way.
#[test]
fn accepted_request_and_contact_knocks_supply_the_kem_key() {
    let (mut a, mut rx) = published(0xA1);
    let log = install_event_log(&mut a);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    feed(
        &mut a,
        queued(knock_from(&pb, &pa, crate::circuits::now_hour())),
    );
    let req = requests(&log);
    assert_eq!(req.len(), 1);
    assert!(a.peers.kem_pk_for(&pb.hex).is_none());
    a.pin_peer(&req[0].identity_hex, &req[0].agreement_hex, None)
        .unwrap();
    assert_eq!(
        a.peers.kem_pk_for(&pb.hex).map(|k| k.to_vec()),
        Some(pb.bundle.kem_pk.to_vec())
    );
    a.ask(&pb.hex, AskTrigger::User, Instant::now()).unwrap();
    assert_eq!(asks(&mut rx).len(), 1);

    let (mut c, _crx) = published(0xC3);
    let pc = peer(0xC3);
    c.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut c,
        queued(knock_from(&pa, &pc, crate::circuits::now_hour())),
    );
    assert_eq!(
        c.peers.kem_pk_for(&pa.hex).map(|k| k.to_vec()),
        Some(pa.bundle.kem_pk.to_vec())
    );
}

/// Protocol v3 (§A.3, §C.2): every ask carries a fresh, valid 1184-byte
/// ML-KEM-768 ephemeral, and is exactly `ASK_WIRE_LEN` bytes on the wire.
#[test]
fn v3_ask_carries_a_fresh_kem_ephemeral_and_is_ask_wire_len() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let mut kems = Vec::new();
    for _ in 0..2 {
        a.ask(&pb.hex, crate::circuits::AskTrigger::User, Instant::now())
            .unwrap();
        for m in sent_controls(&mut rx) {
            if let ControlMessage::CircuitAsk {
                ref kem_ephemeral_pk,
                ..
            } = m
            {
                assert_eq!(kem_ephemeral_pk.len(), crate::kem::KEM_PK_LEN);
                crate::kem::validate_public_key(kem_ephemeral_pk).expect("valid ML-KEM key");
                assert_eq!(m.encode().len(), crate::protocol::ASK_WIRE_LEN);
                kems.push(kem_ephemeral_pk.clone());
            }
        }
        a.unanswered_asks.clear();
    }
    assert_eq!(kems.len(), 2, "two asks went out");
    assert_ne!(kems[0], kems[1], "a new KEM ephemeral for every ask");
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

/// K3: swapped KEM key (v3; was the SPK in v2) → no session; transient
/// bad_signature; CloseCircuit; can_send false; re-ask scheduled.
#[test]
fn k3_swapped_kem_pk_is_transient_bad_signature() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let log = install_event_log(&mut b);
    let mut forged = pa.bundle.clone();
    forged.kem_pk = peer(0x33).bundle.kem_pk.clone();
    feed(&mut b, created_v3(1, &forged, [0x11; 32], ek));
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

/// v3: a bundle validly signed by the peer but carrying a malformed ML-KEM
/// key (coefficients >= q, FIPS 203 modulus check) is refused like an
/// unverifiable one.
#[test]
fn v3_signed_bundle_with_malformed_kem_pk_is_refused() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let ak = pa.bundle.identity_agreement_key;
    let bad_kem = Box::new([0xFFu8; crate::kem::KEM_PK_LEN]);
    let t = crate::keyauth::bundle_transcript(&pa.bundle.identity_key, &ak, &bad_kem);
    let odd = crate::keyauth::SignedBundle {
        identity_key: pa.bundle.identity_key,
        identity_agreement_key: ak,
        kem_pk: bad_kem,
        bundle_signature: pa.id.sign(&t).to_bytes(),
    };
    assert_eq!(
        crate::keyauth::verify_bundle(&odd),
        Err(crate::keyauth::KeyAuthError::WeakKey),
        "validly signed, refused for the KEM key"
    );
    feed(&mut b, created_v3(1, &odd, [0x11; 32], ek));
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
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
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
/// CircuitCreatedV3, even one echoing a still-valid ask: no session, no
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
        feed(&mut b, created_v3(1, &pa.bundle, [0x11; 32], echo));
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
    feed(&mut b, created_v3(1, &lying, [0x11; 32], ek));
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
        created_v3(1, &bundle_with_ak(&pa, ak2), [0x11; 32], ek_pub),
    );
    assert_eq!(
        b.peers.pin_for(&pa.hex),
        Some(pa.bundle.identity_agreement_key)
    );
    assert!(b.session_manager.get(&pa.hex).is_none());
}

/// K6: CircuitCreatedV3 from an unpinned or a blocked peer → CloseCircuit, no session.
#[test]
fn k6_unpinned_or_blocked_peer_is_closed() {
    let (mut b, mut rx) = published(0xB2);
    let pa = peer(0xA1);
    feed(&mut b, created_v3(1, &pa.bundle, [0x11; 32], [0x22; 32]));
    assert_eq!(closes(&mut rx), 1);
    assert!(b.session_manager.get(&pa.hex).is_none());
    b.peers.set_blocked(&pa.hex, true);
    feed(&mut b, created_v3(1, &pa.bundle, [0x11; 32], [0x22; 32]));
    assert_eq!(closes(&mut rx), 1);
    assert!(b.session_manager.get(&pa.hex).is_none());
}

/// K7: role 0 with an initiator EK that isn't mine → refused + re-ask;
/// role 1 with no matching outstanding ask → refused.
#[test]
fn k7_echo_checks_both_roles() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    a.peers
        .push_ask(&pb.hex, EphemeralKeyPair::generate(), Instant::now());
    feed(&mut a, created_v3(0, &pb.bundle, [0x99; 32], [0x22; 32]));
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
    b.peers.pin_card(&pa).unwrap();
    feed(&mut b, created_v3(1, &pa.bundle, [0x11; 32], [0x22; 32]));
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    // The relay keeps A's own EK (echo passes) but swaps B's for one it chose.
    let relay_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, relay_ek));
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
    assert!(a.session_manager.get(&pb.hex).is_some());
    assert!(b.awaiting_init(&pa.hex), "v3: B waits for session-init");
    push_text(&a, &pb.hex, "secret");
    relay_all(&mut a_rx, &mut b);
    // A's session-init does not confirm under B's keys: no session (§A.3).
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert!(
        !b_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Message(..))),
        "roots differ: nothing decrypts"
    );
}

/// K9: current_recipient never changes on CircuitCreatedV3 (F4).
#[test]
fn k9_current_recipient_untouched() {
    let (mut b, _rx, pa, ek) = responder_with_ask();
    let someone_else = "ee".repeat(32);
    b.current_recipient = Some(someone_else.clone());
    feed(
        &mut b,
        created_v3(
            1,
            &pa.bundle,
            EphemeralKeyPair::generate().public_key().to_bytes(),
            ek,
        ),
    );
    assert!(b.awaiting_init(&pa.hex));
    assert_eq!(b.current_recipient, Some(someone_else));
}

/// K12 (H1): record a CircuitCreatedV3 that B actually accepted and the
/// sealed traffic that followed, restart B's core, replay both → the frame
/// is refused (its EK is no longer in the ring) and the envelopes are not
/// delivered.
#[test]
fn k12_replay_after_restart_is_refused() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    let recorded_frame = created_v3(1, &pa.bundle, i_ek, r_ek);
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, recorded_frame.clone());
    assert!(
        b.awaiting_init(&pa.hex),
        "the recorded frame was accepted once"
    );
    relay_all(&mut a_rx, &mut b); // session-init (hello sync)
    assert!(b.session_manager.get(&pa.hex).is_some());
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
    b2.peers.pin_card(&pa).unwrap();
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
    assert!(!b2.awaiting_init(&pa.hex));
}

/// K14: pinning an ak already pinned for another identity → AgreementKeyInUse;
/// a frame whose peer ak belongs to another identity is refused.
#[test]
fn k14_agreement_key_steering_is_refused() {
    let (mut b, mut rx) = published(0xB2);
    let (pa, pc) = (peer(0xA1), peer(0xC3));
    b.pin_peer(
        &pa.hex,
        &hex::encode(pa.bundle.identity_agreement_key),
        None,
    )
    .unwrap();
    assert!(matches!(
        b.pin_peer(
            &pc.hex,
            &hex::encode(pa.bundle.identity_agreement_key),
            None
        ),
        Err(crate::RChatError::AgreementKeyInUse)
    ));
    b.pin_peer(
        &pc.hex,
        &hex::encode(pc.bundle.identity_agreement_key),
        None,
    )
    .unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pc.hex, ek, Instant::now());
    // C presents A's agreement key (validly signed by C): refused.
    feed(
        &mut b,
        created_v3(
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
    feed(&mut b, created_v3(1, &forged, [0x11; 32], ek));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::BadSignature);
    let ek2 = EphemeralKeyPair::generate();
    let ek2_pub = ek2.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek2, Instant::now());
    feed(
        &mut b,
        created_v3(
            1,
            &pa.bundle,
            EphemeralKeyPair::generate().public_key().to_bytes(),
            ek2_pub,
        ),
    );
    assert!(b.awaiting_init(&pa.hex));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Pinned);
}

/// K17: a low-order relay-supplied EK (either role) → refused, no session.
#[test]
fn k17_low_order_relay_ek_is_refused() {
    let mut low = [0u8; 32];
    low[0] = 1;
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    feed(&mut b, created_v3(1, &pa.bundle, low, ek));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(closes(&mut rx), 1);

    let (mut a, mut arx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let eka = EphemeralKeyPair::generate();
    let eka_pub = eka.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, eka, Instant::now());
    feed(&mut a, created_v3(0, &pb.bundle, eka_pub, [0u8; 32]));
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
    book.pin_card(&a).unwrap();
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

/// RF4: malformed CircuitCreatedV3 from a hostile relay → no panic,
/// CloseCircuit, no session, EK ring untouched.
#[test]
fn rf4_malformed_circuit_created_v2_is_refused_without_panic() {
    let (mut b, mut rx, pa, ek) = responder_with_ask();
    let good = PeerBundle::from_signed(&pa.bundle);
    let mut short_sig = good.clone();
    short_sig.bundle_signature.pop();
    let mut long_ak = good.clone();
    long_ak.identity_agreement_key.push(0);
    let kem_ok = vec![0x5a; crate::kem::KEM_PK_LEN];
    type Case = (u8, Vec<u8>, PeerBundle, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let mut cases: Vec<Case> = vec![
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
        (1, vec![1; 31], good.clone(), vec![0x11; 32], ek.to_vec()),
    ]
    .into_iter()
    .map(|(r, t, p, i, e)| (r, t, p, i, e, kem_ok.clone(), kem_ok.clone()))
    .collect();
    // v3: either KEM ephemeral of the wrong length (§A.3).
    for bad in [
        0,
        32,
        crate::kem::KEM_PK_LEN - 1,
        crate::kem::KEM_PK_LEN + 1,
    ] {
        let v = vec![0x5a; bad];
        let base = (1, TOKEN.to_vec(), good.clone(), vec![0x11; 32], ek.to_vec());
        cases.push((
            base.0,
            base.1.clone(),
            base.2.clone(),
            base.3.clone(),
            base.4.clone(),
            v.clone(),
            kem_ok.clone(),
        ));
        cases.push((base.0, base.1, base.2, base.3, base.4, kem_ok.clone(), v));
    }
    let n = cases.len();
    for (role, token, peer_bundle, i_ek, r_ek, i_kem, r_kem) in cases {
        feed(
            &mut b,
            Frame::Control(ControlMessage::CircuitCreatedV3 {
                circuit_id: C2,
                token,
                target_circuit_id: C1,
                role,
                peer: peer_bundle,
                initiator_ephemeral_key: i_ek,
                responder_ephemeral_key: r_ek,
                initiator_kem_ephemeral_pk: i_kem,
                responder_kem_ephemeral_pk: r_kem,
                initiator_ephemeral_sig: vec![0; 64],
                responder_ephemeral_sig: vec![0; 64],
            }),
        );
    }
    // R7: an ephemeral signature of the wrong length, on either side.
    let sig_cases = [0usize, 63, 65];
    for bad in sig_cases {
        for side in 0..2 {
            let (i_sig, r_sig) = if side == 0 {
                (vec![0; bad], vec![0; 64])
            } else {
                (vec![0; 64], vec![0; bad])
            };
            feed(
                &mut b,
                Frame::Control(ControlMessage::CircuitCreatedV3 {
                    circuit_id: C2,
                    token: TOKEN.to_vec(),
                    target_circuit_id: C1,
                    role: 1,
                    peer: good.clone(),
                    initiator_ephemeral_key: vec![0x11; 32],
                    responder_ephemeral_key: ek.to_vec(),
                    initiator_kem_ephemeral_pk: kem_ok.clone(),
                    responder_kem_ephemeral_pk: kem_ok.clone(),
                    initiator_ephemeral_sig: i_sig,
                    responder_ephemeral_sig: r_sig,
                }),
            );
        }
    }
    let n = n + 2 * sig_cases.len();
    assert_eq!(closes(&mut rx), n);
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(b.peers.outstanding_asks(&pa.hex), 1, "ring untouched");
}

#[test]
fn role_zero_sends_hello_sync_and_reports_initiator() {
    let (mut a, mut rx) = published(0xA1);
    let log = install_event_log(&mut a);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, ek, Instant::now());
    feed(
        &mut a,
        created_v3(
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
    let late =
        p.a.seal_ratchet(&p.pb.hex, [9; 16], b"\x01\0\0\0\0late")
            .unwrap();
    for round in 0..2 {
        let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
        let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
        p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
        p.b.peers.push_ask(&p.pa.hex, ek_b, Instant::now());
        feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
        feed(&mut p.b, created_v3(1, &p.pa.bundle, i_ek, r_ek));
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
    feed(&mut p.b, created_v3(1, &p.pa.bundle, i_ek, r_ek));
    // v3: the old session stays current until session-init (§A.3).
    assert!(p.b.awaiting_init(&p.pa.hex));
    assert!(
        p.b.seal_ratchet(&p.pa.hex, [3; 16], b"\x01\0\0\0\0x")
            .is_err(),
        "the responder waits for the new session, never uses the retired one"
    );
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p
        .b
        .seal_ratchet(&p.pa.hex, [4; 16], b"\x01\0\0\0\0y")
        .is_ok());
}

/// The seal path takes the recipient's agreement key from the pin store
/// only: with the pin gone, sealing fails even though a session exists.
#[test]
fn seal_uses_the_pinned_agreement_key_only() {
    let mut p = establish(0xA1, 0xB2);
    assert!(p
        .b
        .seal_ratchet(&p.pa.hex, [1; 16], b"\x01\0\0\0\0x")
        .is_ok());
    p.b.peers.unpin(&p.pa.hex);
    assert!(p.b.session_manager.get(&p.pa.hex).is_some());
    assert!(matches!(
        p.b.seal_ratchet(&p.pa.hex, [2; 16], b"\x01\0\0\0\0x"),
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
    feed(&mut p.b, created_v3(1, &p.pa.bundle, i_ek, r_ek));
    assert!(p.b.awaiting_init(&p.pa.hex));
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
    relay_all(&mut p.a_rx, &mut p.b); // session-init: the old session retires
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 1);
    let msg =
        p.a.seal_ratchet(&p.pb.hex, [3; 16], b"\x01\0\0\0\0x")
            .unwrap();
    p.b.block_peer(&p.pa.hex, true).unwrap();
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    assert!(!p.b.awaiting_init(&p.pa.hex));
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
    // Each body follows its type byte and `expire_secs` (§I.2).
    let plaintexts: [&[u8]; 10] = [
        b"\x02\0\0\0\0IMG1jpeg",
        b"\x02\0\0\0\0VOCEm4a",
        b"\x02\0\0\0\0TXT1$$IMG$$:aGk=",
        b"\x01\0\0\0\0$$IMG$$:aGk=",
        b"\x02\0\0\0\0BSTPold",
        b"\x02\0\0\0\0IMG",
        b"\x02\0\0\0\0",
        b"",
        b"\x02\0\0\0\0TXT1\xff\xfe", // completion review L5: not UTF-8
        b"\x01\0\0\0",               // too short to carry expire_secs
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    // Queued while B waits for session-init (a placeholder, as the send
    // path does); it moves to the session at install.
    b.session_manager
        .get_or_create(pa.hex.clone())
        .pending_messages
        .push_back(pending_msg(1, "held"));
    relay_all(&mut a_rx, &mut b); // session-init: B can send now
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
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
    feed(&mut p.b, created_v3(1, &p.pa.bundle, i_ek, r_ek));
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
    // R1: new keys drop the old card's ML-KEM key, so the ask under the
    // new pin waits for the new card's (Task 6 pins both together).
    assert_eq!(
        sent.len(),
        1,
        "close the old circuit; no knock without a KEM key"
    );
    assert!(matches!(&sent[0], ControlMessage::CloseCircuit { circuit_id } if *circuit_id == C2));
    assert!(p.b.peers.kem_pk_for(&p.pa.hex).is_none());
    assert!(p.b.peers.set_kem_pk(&p.pa.hex, p.pa.bundle.kem_pk.clone()));
    p.b.ask(&p.pa.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let sent = sent_controls(&mut p.b_rx);
    assert!(
        matches!(&sent[0], ControlMessage::CircuitAsk { .. }),
        "ask under the new pin"
    );
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
    // B is the initiator here, so the session is installed at once (a
    // responder would wait for session-init, §A.3).
    let r_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(
        &mut p.b,
        created_v3(0, &bundle_with_ak(&p.pa, new_ak), ek_pub, r_ek),
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
    let held =
        p.a.seal_ratchet(&p.pb.hex, [7; 16], b"\x01\0\0\0\0held")
            .unwrap();
    let after =
        p.a.seal_ratchet(&p.pb.hex, [8; 16], b"\x01\0\0\0\0after")
            .unwrap();
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
    // B initiates, so the session is installed at once (§A.3).
    let r_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    feed(
        &mut p.b,
        created_v3(0, &bundle_with_ak(&p.pa, ak_2), ek_pub, r_ek),
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
                ..
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
fn user_ask_sends_circuit_ask_with_fresh_ek_and_5120_byte_knock() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
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
    // A known contact re-pairs blind after a reconnect (Task 9, §C.3).
    let sent = sent_controls(&mut p.a_rx);
    assert_eq!(blind_asks_in(&sent), 1, "blind after reconnect");
    assert!(sent
        .iter()
        .all(|m| !matches!(m, ControlMessage::CircuitAsk { .. })));
    // On the identity path, the same ask carries the resume (M9).
    keep_identity_path(&mut p.a, &p.pb.hex);
    p.a.transport_epoch += 1;
    p.a.ask(
        &p.pb.hex,
        crate::circuits::AskTrigger::User,
        Instant::now() + crate::circuits::ASK_IN_FLIGHT,
    )
    .unwrap();
    let sent = asks(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].3, Some(C1), "resume after reconnect");
}

#[test]
fn set_recipient_asks_for_a_pinned_peer_without_a_circuit() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap(); // the scanned card (R1)
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
    a.peers.pin_card(&pb).unwrap();
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
        created_v3(
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
    p.a.transport_epoch += 1;
    assert_eq!(
        p.a.resume_circuit_for(&p.pb.hex),
        None,
        "a known contact on the blind path is never resumed (Task 9)"
    );
    p.a.transport_epoch -= 1;
    keep_identity_path(&mut p.a, &p.pb.hex);
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
    keep_identity_path(&mut p.a, &p.pb.hex);
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
    b.peers.pin_card(&pa).unwrap();
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
    // The envelope opens for `sealed_to` (its KEM key); the MAC keys are
    // derived for `mac_recipient`.
    let (_, kem_ss) = kem_for(sealed_to);
    let keys = keyauth::knock_keys_v3(
        sender.id.agreement_secret(),
        &mac_recipient.bundle.identity_agreement_key,
        &env_pub,
        &kem_ss,
        &sender.bundle.identity_key,
        &mac_recipient.bundle.identity_key,
        keyauth::KnockRole::Sender,
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
    body.extend_from_slice(&sender.bundle.kem_pk[..]);
    body.extend_from_slice(&sender.bundle.bundle_signature);
    body.extend_from_slice(&hour.to_be_bytes());
    body.extend_from_slice(&mac);
    body.push(0);
    body.resize(crate::knock::KNOCK_BODY_LEN, 0);
    reseal_to(sender, sealed_to, &body)
}

/// One fixed ML-KEM encapsulation per recipient for the hand-built knocks
/// here, so a re-sealed body keeps the knock keys of the knock it came from.
fn kem_for(r: &Peer) -> ([u8; crate::kem::KEM_CT_LEN], [u8; 32]) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    type Cache = Mutex<HashMap<[u8; 32], ([u8; crate::kem::KEM_CT_LEN], [u8; 32])>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    *CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(r.bundle.identity_key)
        .or_insert_with(|| {
            let (ct, ss) = crate::kem::encapsulate(&r.bundle.kem_pk[..]).unwrap();
            (ct, *ss)
        })
}

/// Seal a knock body to `recipient` with the fixed envelope inputs (env
/// 0x45.., nonce 1.., id 2..) and `kem_for(recipient)`.
fn reseal_to(sender: &Peer, recipient: &Peer, body: &[u8]) -> Vec<u8> {
    let (ct, ss) = kem_for(recipient);
    sealed::seal_knock_with(
        &x25519_dalek::StaticSecret::from([0x45; 32]),
        [1; 24],
        [2; 16],
        &recipient.bundle.identity_agreement_key,
        &ct,
        &ss,
        &sender.bundle.identity_key,
        body,
    )
    .unwrap()
}

fn open_body(recipient: &Peer, knock: &[u8]) -> Vec<u8> {
    sealed::open_knock(recipient.id.agreement_secret(), recipient.id.kem(), knock)
        .unwrap()
        .body
}

/// R10: a knock whose `ct_k`, `env_eph_pub` or message id was changed on
/// the wire fails the hybrid envelope and is dropped silently: no request,
/// nothing sent. The untouched knock is a request.
#[test]
fn knock_tampered_on_the_wire_is_dropped_silently() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let k = knock_from(&pa, &pb, crate::circuits::now_hour());
    for at in [
        sealed::KNOCK_CT_OFFSET,
        sealed::KNOCK_CT_OFFSET + 1000,
        20,
        3,
    ] {
        let mut t = k.clone();
        t[at] ^= 0x01;
        feed(&mut b, queued(t));
    }
    assert!(
        requests(&log).is_empty(),
        "no request from a tampered knock"
    );
    assert!(drain(&mut rx).is_empty());
    feed(&mut b, queued(k));
    assert_eq!(requests(&log).len(), 1);
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
        let mut body = open_body(&pb, &bad_mac);
        body[KMAC_AT] ^= 1;
        bad_mac = reseal_to(&pa, &pb, &body);
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
        {
            let (ct, ss) = crate::kem::encapsulate(&pb.bundle.kem_pk[..]).unwrap();
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
                &ct,
                &ss,
                None,
                false,
            )
            .unwrap()
        },
        // Low-order sender agreement key (K17).
        crate::knock::build_knock(
            &pa.id,
            &bundle_with_ak(&pa, [0u8; 32]),
            &pb.bundle.identity_key,
            &pb.bundle.identity_agreement_key,
            &pb.bundle.kem_pk,
            now,
            None,
            None,
            false,
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

/// Knock body offsets (v3 layout: ak, kem_pk, sig, hour, mac, flag, intro;
/// `ct_k` is in the envelope's clear header, R10).
const KFLAG_AT: usize = crate::knock::KNOCK_FIXED_LEN - 1;
const KMAC_AT: usize = KFLAG_AT - 32;
const KINTRO_AT: usize = crate::knock::KNOCK_FIXED_LEN;

/// N12 (client level, M2): the recipient alone can produce the knock's MAC.
#[test]
fn n12_recipient_reproduces_the_knock_mac() {
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let hour = crate::circuits::now_hour();
    let k = knock_from(&pa, &pb, hour);
    let o = sealed::open_knock(pb.id.agreement_secret(), pb.id.kem(), &k).unwrap();
    let mac_in_knock = &o.body[KMAC_AT..KFLAG_AT];
    let keys = keyauth::knock_keys_v3(
        pb.id.agreement_secret(),
        &pa.bundle.identity_agreement_key,
        &o.env_eph_pub,
        &o.kem_ss,
        &pa.bundle.identity_key,
        &pb.bundle.identity_key,
        keyauth::KnockRole::Recipient,
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
    let controls: Vec<ControlMessage> = frames
        .iter()
        .filter(|f| f.first() == Some(&crate::protocol::FRAME_TYPE_CONTROL))
        .filter_map(|f| ControlMessage::decode(f))
        .collect();
    // A known contact's re-ask is blind (Task 9, R18): no target, so no
    // resume of the closed circuit either.
    assert_eq!(
        blind_asks_in(&controls),
        1,
        "exactly the scheduled re-ask goes out"
    );
    assert!(controls
        .iter()
        .all(|m| !matches!(m, ControlMessage::CircuitAsk { .. })));
    assert_eq!(frames.len(), 1, "nothing else went out for this peer");
}

/// TM6: an ask encodes to the same length with and without a resume; the
/// client never sends `resume_circuit: None`.
#[test]
fn tm6_circuit_ask_has_one_size_with_and_without_resume() {
    let mut p = establish(0xA1, 0xB2);
    drain(&mut p.a_rx);
    let (mut c, mut c_rx) = published(0xC3);
    c.peers.pin_card(&p.pb).unwrap();
    c.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    let fresh = drain(&mut c_rx);
    keep_identity_path(&mut p.a, &p.pb.hex);
    p.a.transport_epoch += 1;
    p.a.ask(&p.pb.hex, crate::circuits::AskTrigger::User, Instant::now())
        .unwrap();
    // The helper's flagged entry also asks blind beside the identity ask
    // while A holds a PS (final re-review N-1): only the identity ask counts.
    let resumed: Vec<Vec<u8>> = drain(&mut p.a_rx)
        .into_iter()
        .filter(|f| {
            matches!(
                ControlMessage::decode(f),
                Some(ControlMessage::CircuitAsk { .. })
            )
        })
        .collect();
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
    // The scanned cards (R1): agreement and ML-KEM keys.
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
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
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
    assert!(a.has_live_circuit(&pb.hex));
    assert!(b.awaiting_init(&pa.hex), "v3: B waits for session-init");
    relay_all(&mut a_rx, &mut b); // session-init (hello sync)
    assert!(b.has_live_circuit(&pa.hex));
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
    a.peers.pin_card(&pb).unwrap();
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
    keep_identity_path(&mut p.a, &p.pb.hex);
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
    a.peers.pin_card(&pb).unwrap();
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
    let (ct, ss) = kem_for(recipient);
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
        &ct,
        &ss,
        None,
        false,
    )
    .unwrap()
}

fn body_of(recipient: &Peer, knock: &[u8]) -> Vec<u8> {
    open_body(recipient, knock)
}

/// Re-seal a (possibly edited) knock body with the same envelope inputs
/// and `ss_k`, so the knock MAC and k_intro stay as they were.
fn reseal(sender: &Peer, recipient: &Peer, body: &[u8]) -> Vec<u8> {
    reseal_to(sender, recipient, body)
}

/// Replace the intro block with one encrypting `pt` under the real k_intro.
fn craft_intro(sender: &Peer, recipient: &Peer, body: &mut Vec<u8>, pt: &[u8]) {
    let env_pub = XPub::from(&StaticSecret::from(ENV)).to_bytes();
    let (_, kem_ss) = kem_for(recipient);
    let keys = keyauth::knock_keys_v3(
        sender.id.agreement_secret(),
        &recipient.bundle.identity_agreement_key,
        &env_pub,
        &kem_ss,
        &sender.bundle.identity_key,
        &recipient.bundle.identity_key,
        keyauth::KnockRole::Sender,
    )
    .unwrap();
    let mut aad = Vec::new();
    aad.extend_from_slice(&sender.bundle.identity_key);
    aad.extend_from_slice(&recipient.bundle.identity_key);
    aad.extend_from_slice(&body[KMAC_AT..KFLAG_AT]);
    let ct = XChaCha20Poly1305::new_from_slice(&keys.k_intro)
        .unwrap()
        .encrypt(XNonce::from_slice(&[3; 24]), Payload { msg: pt, aad: &aad })
        .unwrap();
    body.truncate(KFLAG_AT);
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
    a.peers.pin_card(&pb).unwrap();
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
    body[KINTRO_AT + 26] ^= 1;
    cases.push(reseal(&pa, &pb, &body));
    // (b) aad_intro bound to a different knock_mac (intro block from an earlier-hour knock)
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, Some(&intro)));
    let other = body_of(&pb, &intro_knock(&pa, &pb, hour - 1, Some(&intro)));
    body[KINTRO_AT..].copy_from_slice(&other[KINTRO_AT..]);
    cases.push(reseal(&pa, &pb, &body));
    // (c) an intro keyed with a different sender's agreement key (C's block in A's knock)
    let mut body = body_of(&pb, &intro_knock(&pa, &pb, hour, None));
    let c_body = body_of(&pb, &intro_knock(&pc, &pb, hour, Some(&intro)));
    body[KFLAG_AT] = 0x01;
    body[KINTRO_AT..].copy_from_slice(&c_body[KINTRO_AT..]);
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
    a.peers.pin_card(&pb).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
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
    b.peers.pin_card(&pa).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    a.peers.push_ask(&pb.hex, ek_a, Instant::now());
    b.peers.push_ask(&pa.hex, ek_b, Instant::now());
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
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
    a.peers.pin_card(&b).unwrap();
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
    a.peers.pin_card(&b).unwrap();
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
    b2.peers.pin_card(&p.pa).unwrap();
    feed(&mut b2, queued(pk.payload.clone()));
    assert!(b2.pending_reasks.contains_key(&p.pa.hex));

    // Review fix 3: a sender accepted only through the rotation grace (its
    // old identity, unpinned; the new one pinned) has its body held, but is
    // never asked: only a pinned contact can be.
    let (mut b3, _rx) = published(0xB2);
    let new_id = peer(0xC3);
    b3.peers.pin_card(&new_id).unwrap();
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
    a.peers.pin_card(&b).unwrap();
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
    feed(&mut a, created_v3(0, &b.bundle, ek, r_ek));
    assert!(!a.unanswered_asks.contains_key(&b.hex), "success");
    // Echo refusal (an EK that isn't ours).
    let (mut a, _rx, b, _ek) = asked_b();
    feed(&mut a, created_v3(0, &b.bundle, [0x42; 32], r_ek));
    assert!(!a.unanswered_asks.contains_key(&b.hex), "echo refusal");
    // Mismatch (a validly signed bundle with another agreement key).
    let (mut a, _rx, b, ek) = asked_b();
    feed(
        &mut a,
        created_v3(
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
    feed(&mut a, created_v3(0, &forged, ek, r_ek));
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
    a.peers.pin_card(&c).unwrap();
    feed(&mut a, created_v3(0, &c.bundle, [0x43; 32], r_ek));
    assert!(a.unanswered_asks.contains_key(&b.hex), "other peer");
}

/// RA5: replacing an established session raises SessionReplaced once.
#[test]
fn ra5_session_replaced_is_raised_once() {
    let mut p = establish(0xA1, 0xB2);
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i, r) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers.push_ask(&p.pb.hex, ek_a, Instant::now());
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i, r));
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
/// `CircuitCreatedV3` comes back, so that frame goes to the retired
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();

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
    // The relay pairs on the lost ask, but its CircuitCreatedV3 goes to the
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
    feed(&mut a, created_v3(0, &pb.bundle, eks[0], r_ek));
    feed(&mut b, created_v3(1, &pa.bundle, eks[0], r_ek));
    assert!(a.has_live_circuit(&pb.hex) && b.awaiting_init(&pa.hex));
    assert!(a.unanswered_asks.is_empty(), "answered");
    relay_all(&mut rx, &mut b); // Alice's session-init (hello sync)
    assert!(b.has_live_circuit(&pa.hex));
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
    a.peers.pin_card(&b).unwrap();
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
    a.peers.pin_card(&p.pb).unwrap();
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
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i, r));
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
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0hello")
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
    p.b.peers.pin_card(&pn).unwrap();
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
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0x")
        .unwrap();
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
    // v3: B retires its old session only when the session-init arrives,
    // which goes first on the new pair (§A.4).
    let retired = |b: &ClientInner| {
        b.session_manager
            .retired_parts_for_test(&p.pa.hex)
            .map_or(0, |r| r.1)
    };
    let before = retired(&p.b);
    for packet in packets {
        feed(&mut p.b, Frame::Relay(packet));
    }
    assert!(texts(&p.b_log).contains(&b"x".to_vec()), "decrypted");
    assert_eq!(retired(&p.b), before + 1, "under the retired session");
}

/// Relay ruling R18 (Task 8 fix round 2): when a blinded pair's peer is
/// back on a new connection, the relay ends the pair with `CircuitClosed`
/// for A's own circuit and answers A's packet with `CircuitNotFound` naming
/// the circuit A sent on, never a `MessageAck`. A keeps the message tracked
/// (SendNotAccepted, never Delivered), schedules a re-ask, and sends the
/// identical payload again once a new pair forms.
#[test]
fn r18_closed_then_not_found_keeps_the_message_and_resends_it() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0r18")
        .unwrap();
    drain(&mut p.a_rx);
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: C1,
            reason: CircuitCloseReason::Normal,
        }),
    );
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::Error {
            code: crate::protocol::ControlErrorCode::CircuitNotFound,
            message: format!(
                "{}{}",
                crate::protocol::CIRCUIT_NOT_FOUND_PREFIX,
                hex::encode(C2.0)
            ),
        }),
    );
    assert!(p.a_log.lock().unwrap().iter().any(|e| matches!(
        e,
        Ev::Status(crate::status::StatusEvent::SendNotAccepted { .. })
    )));
    assert!(
        p.a.acks
            .lock()
            .unwrap()
            .attempts(&hex::encode(id))
            .is_some(),
        "still tracked: no MessageAck, never reported delivered"
    );
    assert!(
        p.a.pending_reasks.contains_key(&p.pb.hex),
        "re-ask scheduled"
    );
    let first = p.a.acks.lock().unwrap().payloads_for(&p.pb.hex)[0]
        .1
        .clone();
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    let packets = sent_relays(&mut p.a_rx);
    assert!(
        packets.iter().any(|r| r.payload == first),
        "re-sent on the re-paired session"
    );
}

/// AK5 (client): evictions raise AckUnknown.
#[test]
fn ak5_evictions_raise_ack_unknown() {
    let mut p = establish(0xA1, 0xB2);
    for _ in 0..(crate::acks::MAX_TRACKED_ACKS + 3) {
        p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0e")
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
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0x")
        .unwrap();
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
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0x")
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
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0old")
        .unwrap();
    let old = sent_relays(&mut p.a_rx).remove(0).payload;
    p.a.unpin_peer(&p.pb.hex).unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "unpin");
    p.a.peers.pin_card(&p.pb).unwrap();
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
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0old")
        .unwrap();
    p.a.apply_set_recipient(&p.pb.hex, Some(&hex::encode([0x5a; 32])))
        .unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "re-pin");

    // Block.
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0old")
        .unwrap();
    p.a.block_peer(&p.pb.hex, true).unwrap();
    assert_eq!(p.a.acks.lock().unwrap().len(), 0, "block");
}

/// Review minor 2: a CircuitExists for a circuit already live on this
/// connection (the peer resumed) re-sends nothing.
#[test]
fn circuit_exists_for_a_live_circuit_resends_nothing() {
    let mut p = establish(0xA1, 0xB2);
    p.a.send_tracked_for_test(&p.pb.hex, rand::random(), b"\x01\0\0\0\0x")
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
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
        created_v3(
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
    let pk =
        p.a.seal_ratchet(&p.pb.hex, id, b"\x01\0\0\0\0resent")
            .unwrap();
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
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
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    b.receipt_delay_override = Some(Duration::from_secs(60)); // B's notice waits
    reestablish(&mut a, &mut b, &pa, &pb);
    relay_all(&mut a_rx, &mut b); // session-init: B installs (v3, §A.3)
    assert_eq!(b.notice_flag_pending.get(&pa.hex), Some(&1));
    reestablish(&mut a, &mut b, &pa, &pb); // B had a session now
    relay_all(&mut a_rx, &mut b);
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
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
    b2.peers.pin_card(&p.pa).unwrap();
    for c in [&mut p.a, &mut b2] {
        c.receipt_delay_override = Some(Duration::from_secs(60));
    }
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    // v3: B2 installs at A's session-init; the init crosses, nothing else.
    let mut from_a = sent_relays(&mut p.a_rx);
    feed(&mut b2, Frame::Relay(from_a.remove(0)));
    assert_eq!(b2.notice_flag_pending.get(&p.pa.hex), Some(&1));
    drain(&mut b2_rx); // the relay restarts before anything else crosses
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
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
    a2.peers.pin_card(&p.pb).unwrap();
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
        plaintext: None,
        lineage: None,
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
            c.peers.pin_card(&p).unwrap();
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
    thief.peers.pin_card(&r.p.pa).unwrap();
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
    let sent =
        client.resend_text_message_using_id(r.p.pb.hex.clone(), "q0".into(), 0, id_hex.clone());
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
    let sent =
        client.resend_text_message_using_id(r.p.pb.hex.clone(), "q0".into(), 0, id_hex.clone());
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
    let pk =
        p.a.seal_ratchet(&p.pb.hex, x, b"\x01\0\0\0\0genuine")
            .unwrap();
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
    thief.peers.pin_card(&r.p.pa).unwrap();
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
        std::thread::spawn(move || c.resend_text_message_using_id(pb, "q0".into(), 0, id_hex));
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
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb); // A's session-init is not relayed
    drain(&mut p.b_rx);
    // v3: B waits for the session-init; its old session is not used (§A.3).
    assert!(p.b.awaiting_init(&p.pa.hex));
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
    let sent =
        client.resend_text_message_using_id(p.pa.hex.clone(), "x".into(), 0, hex::encode(id));
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

// ---- Protocol v3: X3DH v3 and session-init (Task 4, §A.3–A.4) ----

/// A pair the relay just matched (A initiates): A's session is installed,
/// B waits for the session-init, which is captured and not delivered.
struct InitPair {
    a: ClientInner,
    a_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    b: ClientInner,
    b_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pa: Peer,
    pb: Peer,
    a_log: std::sync::Arc<std::sync::Mutex<Vec<Ev>>>,
    b_log: std::sync::Arc<std::sync::Mutex<Vec<Ev>>>,
    /// A's first relay packet (the session-init).
    init: crate::protocol::RelayPacket,
    /// What A sent after it (its notice).
    rest: Vec<crate::protocol::RelayPacket>,
}

fn init_pair() -> InitPair {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, b_rx) = published(0xB2);
    a.receipt_delay_override = Some(Duration::ZERO);
    b.receipt_delay_override = Some(Duration::ZERO);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let a_log = install_event_log(&mut a);
    let b_log = install_event_log(&mut b);
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    reestablish(&mut a, &mut b, &pa, &pb);
    let mut relays = sent_relays(&mut a_rx);
    let init = relays.remove(0);
    InitPair {
        a,
        a_rx,
        b,
        b_rx,
        pa,
        pb,
        a_log,
        b_log,
        init,
        rest: relays,
    }
}

/// Open A's session-init as B, apply `edit` to its unpadded body
/// (`ct || confirm || ratchet_message`) and seal it again under `id`, as a
/// relay or anyone else could (the sealed sender is not authenticated).
fn reseal_init(
    b: &ClientInner,
    pa: &Peer,
    init: &crate::protocol::RelayPacket,
    id: [u8; 16],
    edit: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let b_id = b.identity.clone().unwrap();
    let (b_ik, b_ak) = (
        b_id.public_signing_key().to_bytes(),
        b_id.public_agreement_key().to_bytes(),
    );
    let opened = sealed::open(&b_ik, b_id.agreement_secret(), &init.payload).unwrap();
    assert_eq!(opened.kind, crate::session_init::SESSION_INIT_TYPE);
    let mut body = crate::padding::unpad(&opened.body).unwrap().to_vec();
    edit(&mut body);
    sealed::seal(
        id,
        &b_ik,
        &b_ak,
        &pa.bundle.identity_key,
        crate::session_init::SESSION_INIT_TYPE,
        &crate::padding::pad(&body),
    )
    .unwrap()
}

/// Everything sent so far, as (control messages, relay packets).
fn split_sent(
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> (Vec<ControlMessage>, Vec<crate::protocol::RelayPacket>) {
    let frames = drain(rx);
    let controls = frames
        .iter()
        .filter(|f| f.first() == Some(&crate::protocol::FRAME_TYPE_CONTROL))
        .filter_map(|f| ControlMessage::decode(f))
        .collect();
    let relays = frames
        .iter()
        .filter_map(|f| crate::protocol::RelayPacket::decode(f))
        .collect();
    (controls, relays)
}

fn count_closes(controls: &[ControlMessage]) -> usize {
    controls
        .iter()
        .filter(|m| matches!(m, ControlMessage::CloseCircuit { .. }))
        .count()
}

fn init_id(init: &crate::protocol::RelayPacket) -> [u8; 16] {
    sealed::peek_message_id(&init.payload).unwrap()
}

fn status_kinds(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<String> {
    statuses(log).iter().map(|s| format!("{s:?}")).collect()
}

/// §A.4: the initiator's first packet on the circuit is the session-init
/// (sealed kind 0x08, 4 KiB bucket) carrying an invisible cover message;
/// the responder installs only once it verifies, and both ask KEM
/// ephemerals are gone after setup (the initiator's at once, the
/// responder's right after decapsulation).
#[test]
fn initiator_sends_session_init_first_and_ephemerals_are_wiped() {
    let mut p = init_pair();
    // The initiator dropped its own KEM ephemeral with the consumed ask.
    assert_eq!(p.a.peers.outstanding_asks(&p.pb.hex), 0);
    assert!(!p.a.awaiting_init(&p.pb.hex));
    // The responder holds its KEM ephemeral, and no session yet.
    assert!(p.b.awaiting_init(&p.pa.hex));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(!p.b.has_live_circuit(&p.pa.hex));
    let b_id = p.b.identity.clone().unwrap();
    let opened = sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &p.init.payload,
    )
    .unwrap();
    assert_eq!(opened.kind, crate::session_init::SESSION_INIT_TYPE);
    assert_eq!(opened.body.len(), 4096, "padded to the 4 KiB bucket");
    // The rest of A's traffic is ordinary ratchet traffic.
    for r in &p.rest {
        let o = sealed::open(
            &b_id.public_signing_key().to_bytes(),
            b_id.agreement_secret(),
            &r.payload,
        )
        .unwrap();
        assert_eq!(o.kind, sealed::KIND_RATCHET);
    }
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    assert!(p.b.has_live_circuit(&p.pa.hex));
    assert!(p.b.session_manager.get(&p.pa.hex).unwrap().can_send());
    // The KEM ephemeral is gone (wiped on drop) once the init was used.
    assert!(!p.b.pending_inits.contains_key(&p.pa.hex));
    assert!(texts(&p.b_log).is_empty(), "the cover message is invisible");
    assert!(p
        .b_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Established(peer, false) if *peer == p.pa.hex)));
    // Both ends derived the same SK: text flows both ways.
    for r in std::mem::take(&mut p.rest) {
        feed(&mut p.b, Frame::Relay(r));
    }
    push_text(&p.b, &p.pa.hex, "from b");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(texts(&p.a_log).contains(&b"from b".to_vec()));
    push_text(&p.a, &p.pb.hex, "from a");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"from a".to_vec()]);
}

/// §A.4: a real message can travel inside the session-init. Here A's
/// invisible hello could not be sealed (its write failed, D28), so the
/// app's first text becomes the init, and B shows it.
#[test]
fn a_real_message_travels_inside_the_session_init() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let b_log = install_event_log(&mut b);
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sa = MemorySink::default();
    with_store(&mut a, &sa);
    sa.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    reestablish(&mut a, &mut b, &pa, &pb);
    assert!(sent_relays(&mut a_rx).is_empty(), "nothing sealed");
    assert!(a.hello_sync_due.contains(&pb.hex));
    sa.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    push_text(&a, &pb.hex, "first words");
    let pkts = sent_relays(&mut a_rx);
    assert_eq!(pkts.len(), 1);
    let b_id = b.identity.clone().unwrap();
    let opened = sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &pkts[0].payload,
    )
    .unwrap();
    assert_eq!(opened.kind, crate::session_init::SESSION_INIT_TYPE);
    feed(&mut b, Frame::Relay(pkts[0].clone()));
    assert_eq!(texts(&b_log), vec![b"first words".to_vec()]);
    assert!(b.session_manager.get(&pa.hex).unwrap().can_send());
}

/// §A.3 failure handling, ruling R9: a session-init whose confirmation tag
/// is wrong installs nothing and raises nothing.
/// - From the offline queue it changes nothing: the wait and its TTL stand,
///   and the genuine init, still in flight, installs afterwards.
/// - On the pending circuit itself (token verified, sender the owner) it
///   ends the wait at once: the circuit is closed and the pair re-asked.
#[test]
fn session_init_wrong_confirm_no_session() {
    let mut p = init_pair();
    let expires = p.b.pending_inits.get(&p.pa.hex).unwrap().expires_at_unix;
    let forged = reseal_init(&p.b, &p.pa, &p.init, [0x0f; 16], |body| {
        body[crate::kem::KEM_CT_LEN] ^= 1; // first confirm byte
    });
    feed(&mut p.b, queued(forged));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(
        p.b.awaiting_init(&p.pa.hex),
        "a genuine init may still come"
    );
    assert_eq!(
        p.b.pending_inits.get(&p.pa.hex).unwrap().expires_at_unix,
        expires,
        "the TTL runs unchanged"
    );
    assert!(statuses(&p.b_log).is_empty(), "the user sees nothing");
    assert!(texts(&p.b_log).is_empty());
    assert_eq!(closes(&mut p.b_rx), 0);
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    assert!(p.b.session_manager.get(&p.pa.hex).unwrap().can_send());

    // A tampered ct decapsulates to another secret (implicit rejection);
    // here it arrives on the pending circuit: the wait ends at once.
    let mut p = init_pair();
    let forged = reseal_init(&p.b, &p.pa, &p.init, [0x1f; 16], |body| body[5] ^= 1);
    let on_circuit = crate::protocol::RelayPacket::with_auth(
        p.init.circuit_id.clone(),
        forged,
        crate::protocol::PacketFlags {
            encrypted: true,
            ..Default::default()
        },
        &TOKEN,
    );
    feed(&mut p.b, Frame::Relay(on_circuit));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(!p.b.awaiting_init(&p.pa.hex), "the wait ended");
    assert!(
        p.b.pending_reasks.contains_key(&p.pa.hex),
        "re-ask scheduled"
    );
    assert_eq!(closes(&mut p.b_rx), 1, "the half-made circuit is closed");
    assert!(statuses(&p.b_log).is_empty());
    // The genuine init now finds nothing awaiting it: no session, and its
    // first message is listed as lost (review M-2).
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(p
        .b
        .undecryptable
        .get(&p.pa.hex)
        .is_some_and(|q| q.contains(&init_id(&p.init))));
}

/// Ruling R8: the wait's TTL counts published time only. The tick never
/// ends it while unpublished (short of the 72 h cap); once published it
/// ends at its expiry, closing the circuit and re-asking.
#[test]
fn pending_init_ttl_counts_online_time_only() {
    let mut p = init_pair();
    let now = crate::unix_now_secs();
    p.b.is_key_bundle_published = false;
    p.b.purge_expired_pending_inits(now + 3600);
    assert!(p.b.awaiting_init(&p.pa.hex), "offline: the wait stands");
    p.b.is_key_bundle_published = true;
    p.b.purge_expired_pending_inits(now + crate::peers::ASK_TTL.as_secs() + 1);
    assert!(!p.b.awaiting_init(&p.pa.hex));
    assert!(
        p.b.pending_reasks.contains_key(&p.pa.hex),
        "re-ask scheduled"
    );
    assert_eq!(closes(&mut p.b_rx), 1);
    // The 72 h cap holds even offline.
    let mut p = init_pair();
    p.b.is_key_bundle_published = false;
    p.b.purge_expired_pending_inits(now + crate::circuits::PENDING_INIT_MAX_AGE_SECS + 1);
    assert!(!p.b.awaiting_init(&p.pa.hex));
}

/// Ruling R8: a reconnect pushes the wait back to now + ASK_TTL, capped at
/// 72 h after the circuit was set up.
#[test]
fn a_reconnect_extends_the_wait_up_to_the_offline_queue_age() {
    let mut p = init_pair();
    let now = crate::unix_now_secs();
    {
        let w = p.b.pending_inits.get_mut(&p.pa.hex).unwrap();
        w.created_at_unix = now - 1800;
        w.expires_at_unix = now - 1200; // ran out while offline
    }
    p.b.after_publish_ok(Instant::now());
    let w = p.b.pending_inits.get(&p.pa.hex).unwrap();
    assert!(w.expires_at_unix >= now + crate::peers::ASK_TTL.as_secs());
    let mut p = init_pair();
    {
        let w = p.b.pending_inits.get_mut(&p.pa.hex).unwrap();
        w.created_at_unix = now - crate::circuits::PENDING_INIT_MAX_AGE_SECS + 60;
    }
    p.b.after_publish_ok(Instant::now());
    let w = p.b.pending_inits.get(&p.pa.hex).unwrap();
    assert_eq!(
        w.expires_at_unix,
        w.created_at_unix + crate::circuits::PENDING_INIT_MAX_AGE_SECS,
        "never past the offline-queue age"
    );
}

/// §A.3 / §F.1: a truncated session-init (short ct, or no room for the
/// ratchet message) installs nothing.
#[test]
fn session_init_truncated_no_session() {
    let mut p = init_pair();
    let cuts: [fn(&mut Vec<u8>); 3] = [
        |b| b.truncate(1000),                                  // inside ct
        |b| b.truncate(crate::kem::KEM_CT_LEN + 32),           // no ratchet message
        |b| b.truncate(crate::kem::KEM_CT_LEN + 32 + 40 + 39), // a byte short
    ];
    for (i, cut) in cuts.into_iter().enumerate() {
        let forged = reseal_init(&p.b, &p.pa, &p.init, [0x20 + i as u8; 16], cut);
        feed(&mut p.b, queued(forged));
        assert!(p.b.session_manager.get(&p.pa.hex).is_none(), "cut {i}");
    }
    assert!(statuses(&p.b_log).is_empty());
    assert!(p.b.awaiting_init(&p.pa.hex));
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    assert!(p.b.session_manager.get(&p.pa.hex).is_some());
}

/// Review Focus 2: a byte-identical second session-init after the session
/// is installed (a relay replay or the initiator's re-send) is dropped:
/// no second install, no ratchet change, no decrypt attempt, and no
/// `PeerSessionReset`, `SessionReplaced` or `DecryptFailed`. The same for
/// the init re-sealed under a new id (a different init for the installed
/// session: nothing awaits it), and for a replay arriving while a newer
/// pair waits for its own init (it must not cut that wait short).
#[test]
fn session_init_replay_is_dropped() {
    let mut p = init_pair();
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    for r in std::mem::take(&mut p.rest) {
        feed(&mut p.b, Frame::Relay(r));
    }
    let snap = |b: &ClientInner, peer: &str| {
        let s = b.session_manager.get(peer).unwrap();
        (
            bincode::serialize(&s.ratchet_snapshot().unwrap()).unwrap(),
            s.session_binding,
            s.created_at_unix,
        )
    };
    let before = snap(&p.b, &p.pa.hex);
    let retired = p.b.session_manager.retired_count(&p.pa.hex);
    let attempts =
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed);
    let events = p.b_log.lock().unwrap().len();
    // Byte-identical, on the circuit and from the offline queue.
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    feed(&mut p.b, queued(p.init.payload.clone()));
    assert!(
        before == snap(&p.b, &p.pa.hex),
        "no ratchet reset, no reinstall"
    );
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), retired);
    assert_eq!(
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        attempts,
        "never decrypted"
    );
    assert_eq!(p.b_log.lock().unwrap().len(), events, "no event at all");
    assert!(!status_kinds(&p.b_log)
        .iter()
        .any(|s| s.contains("PeerSessionReset") || s.contains("SessionReplaced")));
    // A different init (same ct and confirm) under a new id: nothing awaits
    // it, so no install; its first message is listed as lost (review M-2),
    // which is reported, but never as a reset or a replaced session.
    let other = reseal_init(&p.b, &p.pa, &p.init, [0x33; 16], |_| {});
    feed(&mut p.b, queued(other));
    let after = snap(&p.b, &p.pa.hex);
    assert_eq!((after.1, after.2), (before.1, before.2), "not reinstalled");
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), retired);
    assert_eq!(
        p.b.decrypt_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        attempts,
        "never decrypted"
    );
    let lost = hex::encode([0x33u8; 16]);
    assert!(
        statuses(&p.b_log).iter().any(|e| matches!(
            e,
            crate::status::StatusEvent::DecryptFailed { message_id, .. } if *message_id == lost
        )),
        "listed as lost and reported"
    );
    assert!(!status_kinds(&p.b_log)
        .iter()
        .any(|s| s.contains("PeerSessionReset") || s.contains("SessionReplaced")));
    // The pair is re-made: B waits for a new init; the old one replayed
    // now does not touch that wait.
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    let expires = p.b.pending_inits.get(&p.pa.hex).unwrap().expires_at_unix;
    feed(&mut p.b, queued(p.init.payload.clone()));
    assert_eq!(
        p.b.pending_inits.get(&p.pa.hex).unwrap().expires_at_unix,
        expires
    );
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(!p.b.awaiting_init(&p.pa.hex), "the new init installs");
    assert!(!status_kinds(&p.b_log)
        .iter()
        .any(|s| s.contains("PeerSessionReset")));
}

/// §A.3: until the session-init arrives the responder has no session, and
/// what the app sends waits; the init's arrival installs the session and
/// the waiting messages go out.
#[test]
fn responder_holds_sends_until_the_init_then_flushes_them() {
    let p = init_pair();
    let InitPair {
        mut a,
        b,
        mut b_rx,
        pa,
        a_log,
        init,
        rest,
        ..
    } = p;
    let client = wrap(b);
    {
        let g = client.inner.try_read().unwrap();
        g.websocket.as_ref().unwrap().set_connected_for_test();
    }
    let id = client
        .send_text_message(pa.hex.clone(), "early".into())
        .unwrap();
    assert!(sent_relays(&mut b_rx).is_empty(), "held, not sealed");
    {
        let g = client.inner.try_read().unwrap();
        let s = g.session_manager.get(&pa.hex).unwrap();
        assert!(s.ratchet.is_none(), "a placeholder");
        assert_eq!(s.pending_messages[0].id.0, id);
    }
    {
        let mut g = client.inner.try_write().unwrap();
        feed(&mut g, Frame::Relay(init));
        for r in rest {
            feed(&mut g, Frame::Relay(r));
        }
    }
    client.process_pending().unwrap();
    relay_all(&mut b_rx, &mut a);
    assert!(texts(&a_log).contains(&b"early".to_vec()));
}

/// §A.4 with spec §18.7 D35: the session-init is ack-tracked and re-sent
/// byte for byte, first, on each new transport until the responder's first
/// reply; after that reply it is never sent again.
#[test]
fn session_init_is_resent_byte_for_byte_until_the_first_reply() {
    let mut p = init_pair();
    let id = hex::encode(init_id(&p.init));
    assert!(
        p.a.acks
            .lock()
            .unwrap()
            .payloads_for(&p.pb.hex)
            .iter()
            .any(|(i, payload)| *i == id && *payload == p.init.payload),
        "tracked under its id"
    );
    let resume = |a: &mut ClientInner| {
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
    };
    resume(&mut p.a);
    let again = sent_relays(&mut p.a_rx);
    assert_eq!(again[0].payload, p.init.payload, "first, identical bytes");
    assert_eq!(
        again.iter().filter(|r| r.payload == p.init.payload).count(),
        1,
        "once"
    );
    // The relay acks it; it is still re-sent until the peer replies.
    feed(
        &mut p.a,
        Frame::Control(ControlMessage::MessageAck {
            message_id: id.clone(),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            timestamp: 0,
        }),
    );
    assert!(p
        .a
        .acks
        .lock()
        .unwrap()
        .payloads_for(&p.pb.hex)
        .iter()
        .all(|(i, _)| *i != id));
    assert!(
        !p.a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Delivered(_))),
        "an internal entry, never the app's"
    );
    resume(&mut p.a);
    assert_eq!(sent_relays(&mut p.a_rx)[0].payload, p.init.payload);
    // B gets the init (twice: the duplicate is dropped) and replies.
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    push_text(&p.b, &p.pa.hex, "reply");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(texts(&p.a_log).contains(&b"reply".to_vec()));
    assert!(p
        .a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .init_out
        .is_none());
    resume(&mut p.a);
    assert!(
        !sent_relays(&mut p.a_rx)
            .iter()
            .any(|r| r.payload == p.init.payload),
        "not after the first reply"
    );
}

/// Ruling 2: the responder refuses a CircuitCreatedV3 whose echoed
/// responder KEM ephemeral is not its own (constant-time compare): the
/// relay swapped keys. The initiator refuses a responder KEM key that
/// fails the FIPS 203 modulus check. Both close the circuit.
#[test]
fn swapped_or_malformed_kem_ephemerals_are_refused() {
    let (mut b, mut b_rx, pa, r_ek) = responder_with_ask();
    let i_ek = EphemeralKeyPair::generate().public_key().to_bytes();
    let mut frame = created_v3(1, &pa.bundle, i_ek, r_ek);
    if let Frame::Control(ControlMessage::CircuitCreatedV3 {
        responder_kem_ephemeral_pk,
        ..
    }) = &mut frame
    {
        *responder_kem_ephemeral_pk = crate::kem::KemKeyPair::generate().public().to_vec();
    }
    feed(&mut b, frame);
    assert!(!b.awaiting_init(&pa.hex));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(closes(&mut b_rx), 1);

    let (mut a, mut a_rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let ek = EphemeralKeyPair::generate();
    let i_ek = ek.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, ek, Instant::now());
    let mut frame = created_v3(0, &pb.bundle, i_ek, [0x09; 32]);
    if let Frame::Control(ControlMessage::CircuitCreatedV3 {
        responder_kem_ephemeral_pk,
        ..
    }) = &mut frame
    {
        responder_kem_ephemeral_pk[0] = 0xff; // coefficient 0 >= q
        responder_kem_ephemeral_pk[1] |= 0x0f;
    }
    feed(&mut a, frame);
    assert!(a.session_manager.get(&pb.hex).is_none());
    let (controls, relays) = split_sent(&mut a_rx);
    assert_eq!(count_closes(&controls), 1);
    assert!(relays.is_empty(), "no session-init");
}

/// D45 with §A.3: both ends bind notices to the v3 session binding,
/// `SHA-256("rchat/session-binding/v3\0" || SK)`, with SK rebuilt here
/// from B's side of the handshake.
#[test]
fn device_key_notices_bind_to_the_v3_session_binding() {
    use sha2::{Digest, Sha256};
    let mut p = init_pair();
    let b_id = p.b.identity.clone().unwrap();
    let opened = sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &p.init.payload,
    )
    .unwrap();
    let body = crate::padding::unpad(&opened.body).unwrap().to_vec();
    let mut pt = vec![crate::session_init::SESSION_INIT_TYPE];
    pt.extend_from_slice(&body);
    let (ct, _, _) = crate::session_init::parse_session_init(&pt).unwrap();
    let sk = {
        let pending = p.b.pending_inits.get(&p.pa.hex).unwrap();
        let ss = pending.kem.decapsulate(ct).unwrap();
        crate::crypto::x3dh_v3_responder(
            b_id.agreement_secret(),
            &pending.ek_r,
            &p.pa.bundle.identity_agreement_key,
            &pending.i_ek,
            &ss,
            pending.kem.public(),
            ct,
            &p.pa.bundle.identity_key,
            &p.pb.bundle.identity_key,
        )
        .unwrap()
    };
    feed(&mut p.b, Frame::Relay(p.init.clone()));
    let mut h = Sha256::new();
    h.update(b"rchat/session-binding/v3\0");
    h.update(&sk[..]);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(
        crate::device_key::SESSION_BINDING_DOMAIN,
        b"rchat/session-binding/v3\0"
    );
    for (c, peer) in [(&p.a, &p.pb.hex), (&p.b, &p.pa.hex)] {
        assert_eq!(
            c.session_manager.get(peer).unwrap().session_binding,
            expected
        );
    }
}

/// Spec §9a: plaintext types 0x0A–0x0F (future call signalling) are
/// dropped silently: no message, no receipt, no error.
#[test]
fn call_signalling_types_are_dropped_without_a_receipt() {
    let mut p = establish(0xA1, 0xB2);
    for ty in 0x0Au8..=0x0F {
        let id: [u8; 16] = [ty; 16];
        let pk = p.a.seal_ratchet(&p.pb.hex, id, &[ty, 1, 2, 3]).unwrap();
        feed(&mut p.b, Frame::Relay(pk));
    }
    p.b.flush_receipts(&p.pa.hex);
    assert!(texts(&p.b_log).is_empty());
    assert!(p.b.owed_receipts(&p.pa.hex).is_empty(), "no receipt owed");
    assert!(sent_relays(&mut p.b_rx).is_empty(), "nothing sent back");
    assert!(statuses(&p.b_log).is_empty(), "no error");
}

// ---- Fix round 1: signed ask ephemerals (ruling R7) and M-3/M-4 ----

/// A `CircuitCreatedV3` for `a` (role 0) that pairs with B's genuine ask
/// (its EK `r_ek`, its KEM key and its real signature), before any tampering.
fn genuine_initiator_frame(a: &mut ClientInner, pb: &Peer) -> (Frame, [u8; 32]) {
    let ek = EphemeralKeyPair::generate();
    let i_ek = ek.public_key().to_bytes();
    a.peers.push_ask(&pb.hex, ek, Instant::now());
    let b_ek = EphemeralKeyPair::generate();
    let r_ek = b_ek.public_key().to_bytes();
    // B's ask: registers its KEM ephemeral for `created_v3`.
    let _b_ask = crate::peers::AskKeys::with_ek(b_ek);
    (created_v3(0, &pb.bundle, i_ek, r_ek), r_ek)
}

fn responder_fields(frame: &mut Frame) -> (&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>) {
    match frame {
        Frame::Control(ControlMessage::CircuitCreatedV3 {
            responder_ephemeral_key,
            responder_kem_ephemeral_pk,
            responder_ephemeral_sig,
            ..
        }) => (
            responder_ephemeral_key,
            responder_kem_ephemeral_pk,
            responder_ephemeral_sig,
        ),
        _ => unreachable!(),
    }
}

/// Review I-1 (the reviewer's scenario, now a regression test): the relay
/// hands the initiator its own ML-KEM key as the responder's ephemeral,
/// while B would see (and echo-check) its real one. The responder's
/// signature does not cover the relay's key: A refuses before any
/// encapsulation, installs nothing, sends no session-init, closes the
/// circuit and re-asks with backoff.
#[test]
fn relay_swapped_kem_ephemeral_in_the_initiators_view_is_refused() {
    let (mut a, mut a_rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let (mut frame, _) = genuine_initiator_frame(&mut a, &pb);
    let relay_kem = crate::kem::KemKeyPair::generate();
    *responder_fields(&mut frame).1 = relay_kem.public().to_vec();
    feed(&mut a, frame);
    assert!(
        a.session_manager.get(&pb.hex).is_none(),
        "nothing installed"
    );
    let (controls, relays) = split_sent(&mut a_rx);
    assert!(relays.is_empty(), "no session-init left");
    assert_eq!(count_closes(&controls), 1);
    assert!(
        a.pending_reasks.contains_key(&pb.hex),
        "re-ask with backoff"
    );
}

/// R7: a relay-swapped X25519 ephemeral is refused on either side: the
/// initiator checks the responder's signature, the responder the
/// initiator's.
#[test]
fn relay_swapped_x25519_ephemeral_is_refused() {
    let (mut a, mut a_rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    let (mut frame, _) = genuine_initiator_frame(&mut a, &pb);
    *responder_fields(&mut frame).0 = EphemeralKeyPair::generate()
        .public_key()
        .to_bytes()
        .to_vec();
    feed(&mut a, frame);
    assert!(a.session_manager.get(&pb.hex).is_none());
    assert_eq!(closes(&mut a_rx), 1);

    // Responder view: the relay swaps the initiator's EK (the frame is
    // built over the genuine EK, so A's signature covers that one).
    let (mut b, mut b_rx, pa, r_ek) = responder_with_ask();
    let a_ek = EphemeralKeyPair::generate();
    let i_ek = a_ek.public_key().to_bytes();
    let _a_ask = crate::peers::AskKeys::with_ek(a_ek);
    let mut frame = created_v3(1, &pa.bundle, i_ek, r_ek);
    if let Frame::Control(ControlMessage::CircuitCreatedV3 {
        initiator_ephemeral_key,
        ..
    }) = &mut frame
    {
        *initiator_ephemeral_key = EphemeralKeyPair::generate()
            .public_key()
            .to_bytes()
            .to_vec();
    }
    feed(&mut b, frame);
    assert!(!b.awaiting_init(&pa.hex), "no wait from an unsigned EK");
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert_eq!(closes(&mut b_rx), 1);
    assert!(b.pending_reasks.contains_key(&pa.hex));
}

/// R7: a valid signature by another identity (not the peer's pinned key)
/// over the very same ephemerals is refused, as is a zeroed one.
#[test]
fn ask_ephemerals_signed_by_another_identity_are_refused() {
    for forged in ["other identity", "zeros"] {
        let (mut a, mut a_rx) = published(0xA1);
        let pb = peer(0xB2);
        a.peers.pin_card(&pb).unwrap();
        let (mut frame, r_ek) = genuine_initiator_frame(&mut a, &pb);
        let (_, kem, sig) = responder_fields(&mut frame);
        *sig = match forged {
            "zeros" => vec![0; 64],
            _ => {
                let mallory = peer(0x6d);
                let kem: [u8; 1184] = kem.as_slice().try_into().unwrap();
                keyauth::sign_ask_ephemerals(&mallory.id, &r_ek, &kem).to_vec()
            }
        };
        feed(&mut a, frame);
        assert!(a.session_manager.get(&pb.hex).is_none(), "{forged}");
        assert_eq!(closes(&mut a_rx), 1, "{forged}");
    }
}

/// R7 unit: the transcript is the domain, the asker's identity key and both
/// ephemerals; any change to them, or to the signer, fails `verify_strict`.
#[test]
fn ask_ephemeral_signature_binds_identity_and_both_ephemerals() {
    let pa = peer(0xA1);
    let ek = [0x61u8; 32];
    let kem = *crate::kem::KemKeyPair::from_seed(&[0x73; 64]).public();
    let sig = keyauth::sign_ask_ephemerals(&pa.id, &ek, &kem);
    let ik = pa.bundle.identity_key;
    let t = keyauth::ask_eph_transcript(&ik, &ek, &kem);
    assert_eq!(&t[..17], b"rchat/ask-eph/v3\0");
    assert_eq!(t.len(), keyauth::ASK_EPH_TRANSCRIPT_LEN);
    assert!(keyauth::verify_ask_ephemerals(&ik, &ek, &kem, &sig).is_ok());
    let mut ek2 = ek;
    ek2[0] ^= 1;
    assert!(keyauth::verify_ask_ephemerals(&ik, &ek2, &kem, &sig).is_err());
    let mut kem2 = kem;
    kem2[1183] ^= 1;
    assert!(keyauth::verify_ask_ephemerals(&ik, &ek, &kem2, &sig).is_err());
    let other = peer(0xB2).bundle.identity_key;
    assert!(keyauth::verify_ask_ephemerals(&other, &ek, &kem, &sig).is_err());
    assert_eq!(
        keyauth::verify_ask_ephemerals(&ik, &ek, &kem, &sig[..63]),
        Err(keyauth::KeyAuthError::BadLength)
    );
}

/// R7: a real ask carries a 64-byte signature that verifies under the
/// asker's identity over the ask's own EK and KEM ephemeral.
#[test]
fn a_real_ask_signs_its_ephemerals() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap(); // the scanned card (R1)
    a.apply_set_recipient(
        &pb.hex,
        Some(&hex::encode(pb.bundle.identity_agreement_key)),
    )
    .unwrap();
    let ik = peer(0xA1).bundle.identity_key;
    let asks: Vec<_> = sent_controls(&mut rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk {
                ephemeral_key,
                kem_ephemeral_pk,
                ephemeral_sig,
                ..
            } => Some((ephemeral_key, kem_ephemeral_pk, ephemeral_sig)),
            _ => None,
        })
        .collect();
    assert_eq!(asks.len(), 1);
    let (ek, kem, sig) = &asks[0];
    assert_eq!(sig.len(), 64);
    let ek: [u8; 32] = ek.as_slice().try_into().unwrap();
    assert!(keyauth::verify_ask_ephemerals(&ik, &ek, kem, sig).is_ok());
}

/// Review M-4: once a pair forms, the peer's other outstanding asks (and
/// their ephemeral secrets) are gone at once.
#[test]
fn a_formed_pair_wipes_the_other_outstanding_asks() {
    let (mut a, _rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers.pin_card(&pb).unwrap();
    a.peers
        .push_ask(&pb.hex, EphemeralKeyPair::generate(), Instant::now());
    a.peers
        .push_ask(&pb.hex, EphemeralKeyPair::generate(), Instant::now());
    let (frame, _) = genuine_initiator_frame(&mut a, &pb);
    assert_eq!(a.peers.outstanding_asks(&pb.hex), 3);
    feed(&mut a, frame);
    assert!(a.session_manager.get(&pb.hex).is_some());
    assert_eq!(a.peers.outstanding_asks(&pb.hex), 0);
}

/// Review M-3: when the hello's seal fails at install, nothing tracked from
/// before is re-sent ahead of the session-init; once the init leaves (the
/// tick), the held re-sends follow it, in that order.
#[test]
fn tracked_resends_wait_for_the_session_init() {
    let mut p = establish(0xA1, 0xB2);
    let id: [u8; 16] = rand::random();
    p.a.send_tracked_for_test(&p.pb.hex, id, b"\x01\0\0\0\0old")
        .unwrap();
    let old = sent_relays(&mut p.a_rx).remove(0).payload;
    let sa = MemorySink::default();
    with_store(&mut p.a, &sa);
    sa.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "nothing before the init"
    );
    sa.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    p.a.redrive_owed_sends(Instant::now() + Duration::from_secs(10));
    let sent = sent_relays(&mut p.a_rx);
    assert!(sent.len() >= 2, "init and the held re-send: {}", sent.len());
    let b_id = p.b.identity.clone().unwrap();
    let first = sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &sent[0].payload,
    )
    .unwrap();
    assert_eq!(
        first.kind,
        crate::session_init::SESSION_INIT_TYPE,
        "init first"
    );
    assert!(
        sent.iter().any(|r| r.payload == old),
        "then the held re-send"
    );
    for r in sent {
        feed(&mut p.b, Frame::Relay(r));
    }
    assert!(texts(&p.b_log).contains(&b"old".to_vec()));
}

/// Task 6 (§A.6, R11): a signed bundle as `p`'s identity would sign it,
/// but naming `kem_pk` (a valid ML-KEM key of someone else's).
fn bundle_with_kem(
    p: &Peer,
    kem_pk: &[u8; crate::kem::KEM_PK_LEN],
) -> crate::keyauth::SignedBundle {
    let t = keyauth::bundle_transcript(
        &p.bundle.identity_key,
        &p.bundle.identity_agreement_key,
        kem_pk,
    );
    crate::keyauth::SignedBundle {
        identity_key: p.bundle.identity_key,
        identity_agreement_key: p.bundle.identity_agreement_key,
        kem_pk: Box::new(*kem_pk),
        bundle_signature: p.id.sign(&t).to_bytes(),
    }
}

/// Review Focus 3 (§A.6): B pinned A from a card whose ML-KEM key is not
/// the one A's identity signs. At pairing the bundle's signed `kem_pk`
/// differs from the pinned one: the existing key-mismatch outcome
/// (sticky, event 2, circuit closed, no session, no re-ask), never a
/// silent re-pin of the KEM key.
#[test]
fn card_kem_differs_from_bundle_is_mismatch() {
    let (mut b, mut rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let pa = peer(0xA1);
    let card_kem = peer(0x44).bundle.kem_pk;
    b.peers
        .pin_with_kem(&pa.hex, pa.bundle.identity_agreement_key, Some(&card_kem))
        .unwrap();
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek, Instant::now());
    // A's real bundle: valid signature, same agreement key, its own KEM key.
    feed(&mut b, created_v3(1, &pa.bundle, [0x11; 32], ek_pub));
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert!(!b.pending_inits.contains_key(&pa.hex), "no init awaited");
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert_eq!(
        b.peers.kem_pk_for(&pa.hex).map(|k| k.to_vec()),
        Some(card_kem.to_vec()),
        "the pinned KEM key is never replaced"
    );
    assert_eq!(closes(&mut rx), 1);
    assert!(!b.pending_reasks.contains_key(&pa.hex));
    assert!(log.lock().unwrap().contains(&Ev::PeerKey(
        pa.hex.clone(),
        2,
        hex::encode(pa.bundle.identity_agreement_key)
    )));
}

/// The same check for the bundle inside a knock (§A.6, R11): a pinned
/// contact's verified knock whose signed KEM key differs from the pinned
/// one flags a mismatch; it neither fills nor replaces the key.
#[test]
fn knock_bundle_kem_differing_from_the_pin_is_mismatch() {
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let card_kem = peer(0x44).bundle.kem_pk;
    b.peers
        .pin_with_kem(&pa.hex, pa.bundle.identity_agreement_key, Some(&card_kem))
        .unwrap();
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert_eq!(
        b.peers.kem_pk_for(&pa.hex).map(|k| k.to_vec()),
        Some(card_kem.to_vec())
    );
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::PeerKey(id, 2, _) if *id == pa.hex)));
    // The matching key (a correct card) is no mismatch.
    let (mut c, _crx) = published(0xC3);
    let pc = peer(0xC3);
    c.peers.pin_card(&pa).unwrap();
    feed(
        &mut c,
        queued(knock_from(&pa, &pc, crate::circuits::now_hour())),
    );
    assert_eq!(c.peers.state(&pa.hex), PeerKeyState::Pinned);
}

/// The same check through the app's pin call, which records the pin hour:
/// a knock from the pin's own hour (or older) may be a relay replay and is
/// ignored, as for a differing agreement key; a newer one flags the
/// mismatch. Neither fills nor replaces the pinned key.
#[test]
fn knock_kem_mismatch_respects_the_pin_hour() {
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let card_kem = hex::encode(&peer(0x44).bundle.kem_pk[..]);
    b.pin_peer(
        &pa.hex,
        &hex::encode(pa.bundle.identity_agreement_key),
        Some(&card_kem),
    )
    .unwrap();
    let now = crate::circuits::now_hour();
    assert_eq!(b.peers.pin_hour(&pa.hex), Some(now), "a real pin hour");
    // Same hour: the replay guard.
    feed(&mut b, queued(knock_from(&pa, &pb, now)));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Pinned);
    assert!(log.lock().unwrap().is_empty(), "no event");
    // Pinned an hour earlier: the knock is newer, so it is a mismatch.
    b.peers.set_pin_hour(&pa.hex, now - 1);
    feed(&mut b, queued(knock_from(&pa, &pb, now)));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert_eq!(
        b.peers.kem_pk_for(&pa.hex).map(hex::encode),
        Some(card_kem.clone())
    );
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::PeerKey(id, 2, _) if *id == pa.hex)));
}

/// Fix round 1 minor 2: a KEM key adopted from a pinned contact's knock
/// (no key pinned yet) reaches the app as key event 5 with the key, so the
/// app stores it with the pin; a pinned key that matches raises nothing.
#[test]
fn a_kem_key_learned_from_a_contacts_knock_is_reported() {
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    let kem_hex = hex::encode(&pa.bundle.kem_pk[..]);
    assert!(log
        .lock()
        .unwrap()
        .contains(&Ev::PeerKey(pa.hex.clone(), 5, kem_hex.clone())));
    // Again, with the key pinned now: nothing new.
    let before = log.lock().unwrap().len();
    feed(
        &mut b,
        queued(knock_from(&pa, &pb, crate::circuits::now_hour())),
    );
    assert!(!log.lock().unwrap()[before..]
        .iter()
        .any(|e| matches!(e, Ev::PeerKey(_, 5, _))));
}

/// Fix round 1 minor 6: a KEM key that arrives with the staged book (the
/// app pinned while a connect ran) asks a peer deferred for want of one.
#[test]
fn a_staged_kem_key_asks_a_deferred_peer() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    a.schedule_reask(&pb.hex);
    assert!(a.deferred_asks.contains(&pb.hex));
    let mut staged = crate::peers::PeerBook::default();
    staged
        .pin_with_kem(
            &pb.hex,
            pb.bundle.identity_agreement_key,
            Some(&pb.bundle.kem_pk),
        )
        .unwrap();
    a.apply_staged_peers(staged);
    assert!(!a.deferred_asks.contains(&pb.hex));
    assert_eq!(asks(&mut rx).len(), 1);
}

/// The test helper signs like a real identity: a bundle naming another
/// KEM key verifies, so only the pin comparison can catch it.
#[test]
fn a_differing_signed_kem_key_verifies_and_is_caught_by_the_pin() {
    let (mut b, mut rx) = published(0xB2);
    let pa = peer(0xA1);
    b.peers.pin_card(&pa).unwrap();
    let lying = bundle_with_kem(&pa, &peer(0x45).bundle.kem_pk);
    assert!(keyauth::verify_bundle(&lying).is_ok());
    let ek = EphemeralKeyPair::generate();
    let ek_pub = ek.public_key().to_bytes();
    b.peers.push_ask(&pa.hex, ek, Instant::now());
    feed(&mut b, created_v3(1, &lying, [0x11; 32], ek_pub));
    assert_eq!(b.peers.state(&pa.hex), PeerKeyState::Mismatch);
    assert_eq!(
        b.peers.kem_pk_for(&pa.hex).map(|k| k.to_vec()),
        Some(pa.bundle.kem_pk.to_vec())
    );
    assert_eq!(closes(&mut rx), 1);
}

/// T5 N-1: an automatic re-ask that fails for want of a KEM key is kept
/// in `deferred_asks` (no backoff charged), not dropped; pinning the KEM
/// key then asks at once.
#[test]
fn reask_without_kem_key_is_deferred_and_the_kem_pin_asks() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    a.pin_peer(
        &pb.hex,
        &hex::encode(pb.bundle.identity_agreement_key),
        None,
    )
    .unwrap();
    a.schedule_reask(&pb.hex);
    assert!(a.deferred_asks.contains(&pb.hex), "deferred, not dropped");
    assert_eq!(a.peers.backoff_mut(&pb.hex).attempts(), 0);
    assert!(!a.pending_reasks.contains_key(&pb.hex));
    assert!(sent_controls(&mut rx).is_empty());
    // The user's ask too.
    assert!(a.ask(&pb.hex, AskTrigger::User, Instant::now()).is_err());
    assert_eq!(
        a.deferred_asks.iter().filter(|p| **p == pb.hex).count(),
        1,
        "once"
    );
    a.pin_peer_kem(&pb.hex, &pb.bundle.kem_pk).unwrap();
    assert!(!a.deferred_asks.contains(&pb.hex));
    assert_eq!(asks(&mut rx).len(), 1, "asked once the key arrived");
}

/// The pin call with the KEM key (a stored card's, re-pinned at launch)
/// asks a peer deferred for lack of one, as the KEM-only pin does.
#[test]
fn pin_with_kem_key_asks_a_peer_deferred_for_lack_of_one() {
    let (mut a, mut rx) = published(0xA1);
    let pb = peer(0xB2);
    let ak = hex::encode(pb.bundle.identity_agreement_key);
    a.pin_peer(&pb.hex, &ak, None).unwrap();
    a.schedule_reask(&pb.hex);
    assert!(a.deferred_asks.contains(&pb.hex));
    a.pin_peer(&pb.hex, &ak, Some(&hex::encode(&pb.bundle.kem_pk[..])))
        .unwrap();
    assert!(!a.deferred_asks.contains(&pb.hex));
    assert_eq!(asks(&mut rx).len(), 1);
    // Not published yet: the deferred ask waits for the publish instead.
    let (mut c, mut crx) = inner_with_identity(0xC3);
    c.pin_peer(&pb.hex, &ak, None).unwrap();
    c.deferred_asks.push(pb.hex.clone());
    c.pin_peer_kem(&pb.hex, &pb.bundle.kem_pk).unwrap();
    assert!(c.deferred_asks.contains(&pb.hex));
    assert!(sent_controls(&mut crx).is_empty());
}

/// The pin call refuses a KEM key that differs from the pinned one
/// (`PinConflict`, nothing changed) and a malformed one.
#[test]
fn pin_peer_refuses_a_different_or_malformed_kem_key() {
    let (mut a, _rx) = published(0xA1);
    let pb = peer(0xB2);
    let ak = hex::encode(pb.bundle.identity_agreement_key);
    let kem = hex::encode(&pb.bundle.kem_pk[..]);
    a.pin_peer(&pb.hex, &ak, Some(&kem)).unwrap();
    let other = hex::encode(&peer(0x46).bundle.kem_pk[..]);
    assert!(matches!(
        a.pin_peer(&pb.hex, &ak, Some(&other)),
        Err(crate::RChatError::PinConflict)
    ));
    assert!(matches!(
        a.pin_peer_kem(&pb.hex, &peer(0x46).bundle.kem_pk),
        Err(crate::RChatError::PinConflict)
    ));
    assert_eq!(
        a.peers.kem_pk_for(&pb.hex).map(|k| k.to_vec()),
        Some(pb.bundle.kem_pk.to_vec())
    );
    assert!(matches!(
        a.pin_peer(&pb.hex, &ak, Some("abcd")),
        Err(crate::RChatError::InvalidRecipient { .. })
    ));
    let c = peer(0xC4);
    assert!(matches!(
        a.pin_peer(
            &c.hex,
            &hex::encode(c.bundle.identity_agreement_key),
            Some(&"ff".repeat(1184))
        ),
        Err(crate::RChatError::InvalidRecipient { .. })
    ));
    assert_eq!(a.peers.pin_for(&c.hex), None, "nothing pinned");
}

/// R11 / I-2: an accepted request's KEM key reaches the app with the
/// request (`MessageRequest::kem_hex`), so the app can store it with the
/// pin. After a restart (a fresh core that keeps no pins), re-pinning
/// from the app's stored values keeps the contact askable.
#[test]
fn restart_with_app_stored_kem_key_keeps_an_accepted_requester_askable() {
    let (mut a, _rx) = published(0xA1);
    let log = install_event_log(&mut a);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    feed(
        &mut a,
        queued(knock_from(&pb, &pa, crate::circuits::now_hour())),
    );
    let req = requests(&log);
    assert_eq!(req.len(), 1);
    assert_eq!(req[0].kem_hex, hex::encode(&pb.bundle.kem_pk[..]));
    // Accept: the app pins the request's keys (and stores them).
    a.pin_peer(
        &req[0].identity_hex,
        &req[0].agreement_hex,
        Some(&req[0].kem_hex),
    )
    .unwrap();
    let stored = (
        req[0].identity_hex.clone(),
        req[0].agreement_hex.clone(),
        req[0].kem_hex.clone(),
    );
    drop(a);

    // Restart: a new core with no pins; the app re-pins what it stored.
    let (mut a2, mut rx2) = published(0xA1);
    a2.pin_peer(&stored.0, &stored.1, Some(&stored.2)).unwrap();
    a2.ask(&pb.hex, AskTrigger::User, Instant::now()).unwrap();
    assert_eq!(asks(&mut rx2).len(), 1, "askable after the restart");

    // Without the stored key it would not be (the gap R11 closes).
    let (mut a3, mut rx3) = published(0xA1);
    a3.pin_peer(&stored.0, &stored.1, None).unwrap();
    assert!(matches!(
        a3.ask(&pb.hex, AskTrigger::User, Instant::now()),
        Err(crate::RChatError::NoKemKey { .. })
    ));
    assert!(asks(&mut rx3).is_empty());
}

/// Fix round 1 minor 8: `set_recipient` with no agreement key keeps the
/// pin the core holds, ML-KEM key included (a reconnect's re-set).
#[test]
fn set_recipient_without_an_agreement_key_keeps_the_pin_and_kem_key() {
    let (mut a, _rx) = published(0xA1);
    let pb = peer(0xB2);
    a.pin_peer(
        &pb.hex,
        &hex::encode(pb.bundle.identity_agreement_key),
        Some(&hex::encode(&pb.bundle.kem_pk[..])),
    )
    .unwrap();
    a.apply_set_recipient(&pb.hex, None).unwrap();
    assert_eq!(
        a.peers.pin_for(&pb.hex),
        Some(pb.bundle.identity_agreement_key)
    );
    assert_eq!(
        a.peers.kem_pk_for(&pb.hex).map(|k| k.to_vec()),
        Some(pb.bundle.kem_pk.to_vec())
    );
    let other = peer(0xC3);
    assert!(matches!(
        a.apply_set_recipient(&other.hex, None),
        Err(crate::RChatError::PeerNotAccepted { .. })
    ));
}
