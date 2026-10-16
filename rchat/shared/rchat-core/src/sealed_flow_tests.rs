//! S2, S3, pending-buffer cap and hello sync over sealed v2 payloads,
//! on top of the Task 13 circuit API.

use crate::crypto::{EphemeralKeyPair, IdentityKeyPair};
use crate::protocol::{CircuitId, ControlMessage, Frame, PacketFlags, RelayPacket};
use crate::sealed::{self, KIND_RATCHET};
use crate::test_support::*;
use crate::{RChatClient, MAX_PENDING_BYTES, MAX_PENDING_ENCRYPTED, MAX_PENDING_ENTRY_BYTES};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// (sender hex, content) of every message the core delivered.
fn messages(log: &Arc<Mutex<Vec<Ev>>>) -> Vec<(String, Vec<u8>)> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Message(s, c, _) => Some((s.clone(), c.clone())),
            _ => None,
        })
        .collect()
}

fn errors(log: &Arc<Mutex<Vec<Ev>>>) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Error(_)))
        .count()
}

/// S3 / F13: a live packet on a circuit the receiver doesn't know (stale
/// after a relay restart), and a QueuedMessage with no circuit at all, both
/// decrypt by the sender identity inside the envelope.
#[test]
fn s3_stale_circuit_and_queued_messages_decrypt_by_sender_identity() {
    let mut p = establish(0xA1, 0xB2);
    let packet =
        p.a.seal_ratchet(&p.pb.hex, [1; 16], b"\x01\0\0\0\0hi")
            .unwrap();
    let stale = RelayPacket::with_auth(
        CircuitId([0x99; 16]),
        packet.payload.clone(),
        PacketFlags {
            encrypted: true,
            ..Default::default()
        },
        &TOKEN,
    );
    RChatClient::handle_relay_packet(&mut p.b, stale);
    assert_eq!(messages(&p.b_log), vec![(p.pa.hex.clone(), b"hi".to_vec())]);

    let packet =
        p.a.seal_ratchet(&p.pb.hex, [2; 16], b"\x01\0\0\0\0again")
            .unwrap();
    RChatClient::handle_frame(
        &mut p.b,
        Frame::Control(ControlMessage::QueuedMessage {
            payload: packet.payload,
        }),
    );
    assert_eq!(messages(&p.b_log).last().unwrap().1, b"again".to_vec());
}

#[test]
fn relay_packet_with_a_bad_tag_on_a_known_circuit_is_dropped() {
    let mut p = establish(0xA1, 0xB2);
    let packet =
        p.a.seal_ratchet(&p.pb.hex, [3; 16], b"\x01\0\0\0\0x")
            .unwrap();
    assert_eq!(packet.circuit_id, C2, "B's own circuit: B knows its token");
    let mut forged = packet.clone();
    forged.auth_tag = [0u8; 16];
    RChatClient::handle_relay_packet(&mut p.b, forged);
    assert!(messages(&p.b_log).is_empty());
    RChatClient::handle_relay_packet(&mut p.b, packet);
    assert_eq!(messages(&p.b_log).len(), 1);
}

/// S2: an envelope naming A as sender but not made with A's session fails
/// the ratchet, is not delivered or attributed, and A's session survives.
#[test]
fn s2_spoofed_sender_is_neither_delivered_nor_attributed() {
    let mut p = establish(0xA1, 0xB2);
    let spoof = sealed::seal(
        [3; 16],
        &p.pb.bundle.identity_key,
        &p.pb.bundle.identity_agreement_key,
        &p.pa.bundle.identity_key,
        KIND_RATCHET,
        &[0x5a; 104],
    )
    .unwrap();
    p.b.handle_sealed_payload(&spoof);
    assert!(messages(&p.b_log).is_empty());
    assert!(p.b.pending_encrypted_messages.is_empty());
    assert_eq!(errors(&p.b_log), 0, "nothing attributed to A");
    // Only the id goes out, in a session notice (spec §18.6, forgery
    // limit); A never sent it, so A raises nothing.
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "only the session notice in reply to a spoof"
    );
    assert!(
        statuses(&p.a_log).is_empty(),
        "A ignores an id it never sent"
    );
    let real =
        p.a.seal_ratchet(&p.pb.hex, [4; 16], b"\x01\0\0\0\0real")
            .unwrap();
    p.b.handle_sealed_payload(&real.payload);
    assert_eq!(
        messages(&p.b_log),
        vec![(p.pa.hex.clone(), b"real".to_vec())],
        "A's session unharmed"
    );
}

/// A pinned identity (seed byte `n`) with no session, and a sealed ratchet
/// envelope from it to `b`.
fn pinned_sender(b: &mut crate::ClientInner, n: u8) -> IdentityKeyPair {
    let id = IdentityKeyPair::from_seed(&[n; 64]).unwrap();
    b.peers
        .pin(&id.public_key_hex(), id.public_agreement_key().to_bytes())
        .unwrap();
    id
}

fn ratchet_from(b: &crate::ClientInner, sender: &IdentityKeyPair, id: [u8; 16]) -> Vec<u8> {
    let b_id = b.identity.clone().unwrap();
    sealed::seal(
        id,
        &b_id.public_signing_key().to_bytes(),
        &b_id.public_agreement_key().to_bytes(),
        &sender.public_signing_key().to_bytes(),
        KIND_RATCHET,
        &[0x11; 60],
    )
    .unwrap()
}

fn numbered(i: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..4].copy_from_slice(&i.to_be_bytes());
    id
}

/// C-3: without callbacks nothing is queued for polling any more: a
/// received message, error or ack goes nowhere and nothing accumulates.
#[test]
fn nothing_is_kept_without_callbacks() {
    let mut p = establish(0xA1, 0xB2);
    p.b.callbacks = None;
    for n in 0..300u32 {
        push_text(&p.a, &p.pb.hex, &format!("m{n}"));
        relay_all(&mut p.a_rx, &mut p.b);
        drain(&mut p.b_rx);
    }
    for _ in 0..300 {
        p.b.report_error(&crate::RChatError::NotConnected);
        p.b.report_delivered("id".into());
    }
    // The session still advanced: a later message with callbacks arrives.
    let rec = crate::test_support::Recorder::default();
    p.b.callbacks = Some(Box::new(rec.clone()));
    push_text(&p.a, &p.pb.hex, "after");
    relay_all(&mut p.a_rx, &mut p.b);
    let got: Vec<String> = rec
        .take()
        .into_iter()
        .filter(|e| e.starts_with("message:"))
        .collect();
    assert_eq!(got.len(), 1);
    assert!(got[0].ends_with(&hex::encode(b"after")), "{got:?}");
}

/// Memory bound: with no session for the senders, at most 256 bodies are
/// held and the oldest are dropped first.
#[test]
fn pending_buffer_keeps_the_newest_256_messages() {
    let (mut b, _rx) = inner_with_identity(2);
    let senders: Vec<IdentityKeyPair> = (10..15).map(|n| pinned_sender(&mut b, n)).collect();
    let ids: Vec<[u8; 16]> = (0..300u32).map(numbered).collect();
    for (i, id) in ids.iter().enumerate() {
        let payload = ratchet_from(&b, &senders[i % senders.len()], *id);
        b.handle_sealed_payload(&payload);
    }
    assert_eq!(b.pending_encrypted_messages.len(), MAX_PENDING_ENCRYPTED);
    assert_eq!(
        b.pending_encrypted_messages.front().unwrap().message_id,
        ids[300 - MAX_PENDING_ENCRYPTED]
    );
    assert_eq!(
        b.pending_encrypted_messages.back().unwrap().message_id,
        ids[299]
    );
}

/// C-7: one claimed sender keeps only its newest `MAX_PENDING_PER_SENDER`
/// bodies and cannot evict another contact's held messages.
#[test]
fn a_flooding_claimed_sender_cannot_evict_other_contacts() {
    let (mut b, _rx) = inner_with_identity(2);
    let q = pinned_sender(&mut b, 20);
    let p = pinned_sender(&mut b, 21);
    for i in 0..10u32 {
        let payload = ratchet_from(&b, &q, numbered(i));
        b.handle_sealed_payload(&payload);
    }
    for i in 1000..1256u32 {
        let payload = ratchet_from(&b, &p, numbered(i));
        b.handle_sealed_payload(&payload);
    }
    let held_from = |who: &IdentityKeyPair| {
        b.pending_encrypted_messages
            .iter()
            .filter(|h| h.sender_hex == who.public_key_hex())
            .count()
    };
    assert_eq!(held_from(&q), 10, "Q's held messages survive");
    assert_eq!(held_from(&p), crate::MAX_PENDING_PER_SENDER);
    assert_eq!(
        b.pending_encrypted_messages.back().unwrap().message_id,
        numbered(1255),
        "the flooder keeps its newest"
    );
}

/// N-1: four claimed contacts flooding the buffer cannot flush a fifth
/// contact's few held bodies: a full buffer evicts from the largest holder.
#[test]
fn claimed_senders_cannot_flush_a_quiet_contacts_held_bodies() {
    let (mut b, _rx) = inner_with_identity(2);
    let quiet = pinned_sender(&mut b, 30);
    let flooders: Vec<IdentityKeyPair> = (31..35).map(|n| pinned_sender(&mut b, n)).collect();
    for i in 0..5u32 {
        let payload = ratchet_from(&b, &quiet, numbered(i));
        b.handle_sealed_payload(&payload);
    }
    for i in 0..1000u32 {
        let payload = ratchet_from(&b, &flooders[i as usize % 4], numbered(100 + i));
        b.handle_sealed_payload(&payload);
    }
    assert_eq!(b.pending_encrypted_messages.len(), MAX_PENDING_ENCRYPTED);
    let quiet_held = b
        .pending_encrypted_messages
        .iter()
        .filter(|h| h.sender_hex == quiet.public_key_hex())
        .count();
    assert_eq!(quiet_held, 5, "the quiet contact's held bodies survive");
}

/// N-1: a ratchet envelope in a knock-sized (5120-byte) payload never came
/// from a ratchet send: dropped, not held.
#[test]
fn knock_sized_ratchet_envelopes_are_not_held() {
    let (mut b, _rx) = inner_with_identity(2);
    let p = pinned_sender(&mut b, 40);
    let b_id = b.identity.clone().unwrap();
    let body_len = sealed::KNOCK_PAYLOAD_LEN - sealed::SEALED_HEADER_LEN - 16 - 33;
    let payload = sealed::seal(
        [1; 16],
        &b_id.public_signing_key().to_bytes(),
        &b_id.public_agreement_key().to_bytes(),
        &p.public_signing_key().to_bytes(),
        KIND_RATCHET,
        &vec![0x11; body_len],
    )
    .unwrap();
    assert_eq!(payload.len(), sealed::KNOCK_PAYLOAD_LEN);
    b.handle_sealed_payload(&payload);
    assert!(b.pending_encrypted_messages.is_empty());
    let normal = ratchet_from(&b, &p, [2; 16]);
    b.handle_sealed_payload(&normal);
    assert_eq!(
        b.pending_encrypted_messages.len(),
        1,
        "other sizes still held"
    );
}

/// Accept (pin) the identity `from_stranger` seals as: ratchet bodies are
/// only held for accepted senders (N5).
fn accept_stranger(b: &mut crate::ClientInner) {
    let stranger = IdentityKeyPair::from_seed(&[1u8; 64]).unwrap();
    b.peers
        .pin(
            &stranger.public_key_hex(),
            stranger.public_agreement_key().to_bytes(),
        )
        .unwrap();
}

/// A ratchet envelope to `b` from an identity `b` has no session with.
fn from_stranger(b: &crate::ClientInner, id: [u8; 16], body_len: usize) -> Vec<u8> {
    let b_id = b.identity.clone().unwrap();
    let stranger = IdentityKeyPair::from_seed(&[1u8; 64]).unwrap();
    sealed::seal(
        id,
        &b_id.public_signing_key().to_bytes(),
        &b_id.public_agreement_key().to_bytes(),
        &stranger.public_signing_key().to_bytes(),
        KIND_RATCHET,
        &vec![0x11; body_len],
    )
    .unwrap()
}

fn held_bytes(b: &crate::ClientInner) -> usize {
    b.pending_encrypted_messages
        .iter()
        .map(|p| p.body.len())
        .sum()
}

/// Memory bound: total held bytes never exceed the byte cap; the oldest
/// bodies are evicted first.
#[test]
fn pending_buffer_is_byte_capped_and_evicts_oldest() {
    let (mut b, _rx) = inner_with_identity(2);
    accept_stranger(&mut b);
    let body_len = 900 << 10;
    let ids: Vec<[u8; 16]> = (0..20u8).map(|i| [i; 16]).collect();
    for id in &ids {
        let payload = from_stranger(&b, *id, body_len);
        b.handle_sealed_payload(&payload);
        assert!(held_bytes(&b) <= MAX_PENDING_BYTES);
    }
    let kept = MAX_PENDING_BYTES / body_len;
    assert_eq!(b.pending_encrypted_messages.len(), kept);
    assert_eq!(
        b.pending_encrypted_messages.front().unwrap().message_id,
        ids[20 - kept]
    );
    assert_eq!(
        b.pending_encrypted_messages.back().unwrap().message_id,
        ids[19]
    );
}

/// A body over the per-entry cap is never held (and evicts nothing).
#[test]
fn oversize_pending_entry_is_refused() {
    let (mut b, _rx) = inner_with_identity(2);
    accept_stranger(&mut b);
    b.handle_sealed_payload(&from_stranger(&b, [1; 16], 60));
    b.handle_sealed_payload(&from_stranger(&b, [2; 16], MAX_PENDING_ENTRY_BYTES + 1));
    assert_eq!(b.pending_encrypted_messages.len(), 1);
    assert_eq!(b.pending_encrypted_messages[0].message_id, [1; 16]);
    b.handle_sealed_payload(&from_stranger(&b, [3; 16], MAX_PENDING_ENTRY_BYTES));
    assert_eq!(
        b.pending_encrypted_messages.len(),
        2,
        "a body at the cap is held"
    );
}

#[test]
fn held_messages_are_delivered_once_the_session_exists() {
    let mut p = establish(0xA1, 0xB2);
    let saved = p.b.session_manager.remove(&p.pa.hex).unwrap();
    let packet =
        p.a.seal_ratchet(&p.pb.hex, [5; 16], b"\x01\0\0\0\0early")
            .unwrap();
    p.b.handle_sealed_payload(&packet.payload);
    assert_eq!(p.b.pending_encrypted_messages.len(), 1);
    assert!(messages(&p.b_log).is_empty());
    p.b.session_manager.install(p.pa.hex.clone(), saved);
    p.b.process_pending_encrypted(&p.pa.hex);
    assert!(p.b.pending_encrypted_messages.is_empty());
    assert_eq!(
        messages(&p.b_log),
        vec![(p.pa.hex.clone(), b"early".to_vec())]
    );
}

/// Task 17 review: a body padded to the 1 MiB bucket (plus ratchet header
/// and AEAD tag) that arrives before its session is held, then delivered.
#[test]
fn padded_one_mebibyte_body_is_held_until_the_session_exists() {
    let mut p = establish(0xA1, 0xB2);
    let saved = p.b.session_manager.remove(&p.pa.hex).unwrap();
    // `expire_secs` follows the type byte; binary bodies start with a known magic.
    let mut pt = b"\x02\0\0\0\0IMG1".to_vec();
    pt.resize((1 << 20) - 1, 0x5A); // pads to exactly 1 MiB
    assert_eq!(crate::padding::bucket(pt.len()), 1 << 20);
    let packet = p.a.seal_ratchet(&p.pb.hex, [6; 16], &pt).unwrap();
    p.b.handle_sealed_payload(&packet.payload);
    assert_eq!(p.b.pending_encrypted_messages.len(), 1, "held, not dropped");
    assert!(p.b.pending_encrypted_messages[0].body.len() > 1 << 20);
    p.b.session_manager.install(p.pa.hex.clone(), saved);
    p.b.process_pending_encrypted(&p.pa.hex);
    assert_eq!(
        messages(&p.b_log),
        vec![(p.pa.hex.clone(), pt[5..].to_vec())]
    );
}

/// The invisible hello is sealed, sent on the peer's circuit, hidden from
/// the user, and gives the responder its sending chain.
#[test]
fn hello_sync_is_sealed_hidden_and_starts_the_responders_sending_chain() {
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
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
    // v3 (§A.3): the responder has no session until session-init.
    assert!(b.session_manager.get(&pa.hex).is_none());
    assert!(b.awaiting_init(&pa.hex));
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    let relays = sent_relays(&mut a_rx);
    assert_eq!(relays.len(), 1, "one hello");
    let packet = relays.into_iter().next().unwrap();
    assert_eq!(packet.circuit_id, C2);
    assert!(packet.verify_auth_tag(&TOKEN));
    assert_eq!(packet.payload[0], sealed::SEALED_VERSION);
    // The hello travels as the session-init (§A.4), in the 4 KiB bucket.
    let b_id = b.identity.clone().unwrap();
    let opened = sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &packet.payload,
    )
    .unwrap();
    assert_eq!(opened.kind, crate::session_init::SESSION_INIT_TYPE);
    assert_eq!(opened.body.len(), 4096);
    feed(&mut b, Frame::Relay(packet));
    assert!(!b.awaiting_init(&pa.hex));
    assert!(messages(&b_log).is_empty(), "hello is invisible");
    assert!(b.session_manager.get(&pa.hex).unwrap().can_send());
}

#[test]
fn malformed_knock_is_dropped_without_a_request() {
    let (mut b, mut rx) = inner_with_identity(2);
    let log = install_event_log(&mut b);
    let b_id = b.identity.clone().unwrap();
    let (ct, ss) = crate::kem::encapsulate(&b_id.kem_public()[..]).unwrap();
    let payload = sealed::seal_knock_with(
        &x25519_dalek::StaticSecret::from([0x45; 32]),
        [4; 24],
        [4; 16],
        &b_id.public_agreement_key().to_bytes(),
        &ct,
        &ss,
        &[9u8; 32],
        &[0u8; sealed::KNOCK_INNER_LEN - 33],
    )
    .unwrap();
    b.handle_sealed_payload(&payload);
    assert!(b.pending_encrypted_messages.is_empty());
    assert!(
        log.lock().unwrap().is_empty(),
        "no request for a malformed knock"
    );
    assert!(drain(&mut rx).is_empty());
}

/// The id the relay sees on the wire (what it acks) is the sealed message id,
/// and the frame that left A opens at B by sender identity.
#[test]
fn relay_visible_message_id_matches_sealed_id_and_wire_frame_opens_at_recipient() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "x");
    let mut relays = sent_relays(&mut p.a_rx);
    assert_eq!(relays.len(), 1, "exactly one relay frame left A");
    let wire = relays.pop().unwrap();
    assert_eq!(sealed::peek_message_id(&wire.payload), Some(id));
    RChatClient::handle_relay_packet(&mut p.b, wire);
    assert_eq!(messages(&p.b_log), vec![(p.pa.hex.clone(), b"x".to_vec())]);
}
