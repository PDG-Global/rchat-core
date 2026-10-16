//! Task 10: steady-rate sending (protocol v3 §B): uniform destinations,
//! the starvation override, exactly 1 KiB plaintexts, what goes outside
//! the shape, and the gates (open circuits, foreground, connected).

use super::*;
use crate::protocol::Frame;
use crate::sealed::RATCHET_ENVELOPE_OVERHEAD;
use crate::test_support::*;
use crate::ClientInner;
use rand::rngs::mock::StepRng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::{Duration, Instant};

/// The sealed payload length of every packet inside the shape.
const STEADY_SEALED_LEN: usize = RATCHET_ENVELOPE_OVERHEAD + STEADY_PLAINTEXT_LEN;

fn peers(names: &[&str]) -> Vec<PeerHex> {
    names.iter().map(|s| s.to_string()).collect()
}

/// An RNG whose every draw is zero: the uniform pick is always `open[0]`.
fn always_first() -> StepRng {
    StepRng::new(0, 0)
}

fn steady_on(inner: &mut ClientInner) {
    inner.apply_steady(true, STEADY_DEFAULT_SLOT_MS, true);
}

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

#[test]
fn destination_is_uniform_over_open_circuits() {
    let open = peers(&["a", "b", "c", "d"]);
    let mut s = SteadyScheduler::new(Duration::from_millis(500));
    let mut rng = StdRng::seed_from_u64(0x5EED_0010);
    let mut now = Instant::now();
    let mut counts = std::collections::HashMap::<PeerHex, u32>::new();
    for _ in 0..10_000 {
        now += s.slot();
        let d = s.next_destination(&open, &mut rng, now).unwrap();
        *counts.entry(d).or_default() += 1;
    }
    for p in &open {
        let c = counts.get(p).copied().unwrap_or(0);
        assert!(
            (2375..=2625).contains(&c),
            "{p} drawn {c} times of 10,000 (want 2,500 ± 5%)"
        );
    }
}

#[test]
fn starved_item_overrides_after_3n_slots() {
    let open = peers(&["a", "b", "c", "d"]);
    let slot = Duration::from_millis(500);
    let mut s = SteadyScheduler::new(slot);
    let mut rng = always_first();
    let t0 = Instant::now();
    s.note_waiting("d", true, t0);
    // Up to and including 3n = 12 slots of waiting: the uniform pick.
    for k in 1..=12u32 {
        let d = s.next_destination(&open, &mut rng, t0 + slot * k).unwrap();
        assert_eq!(d, "a", "slot {k}: no override yet");
    }
    // Past 3n slots: the waiting peer gets the slot.
    let d = s.next_destination(&open, &mut rng, t0 + slot * 13).unwrap();
    assert_eq!(d, "d", "slot 13: the starved item overrides");
    // Served: its clock restarts, so it does not take every later slot.
    s.served("d", t0 + slot * 13);
    for k in 14..=25u32 {
        let d = s.next_destination(&open, &mut rng, t0 + slot * k).unwrap();
        assert_eq!(d, "a", "slot {k}: the clock restarted at its service");
    }
    let d = s.next_destination(&open, &mut rng, t0 + slot * 26).unwrap();
    assert_eq!(d, "d", "still waiting: overrides again after 3n more");
    // Nothing waiting any more: back to the uniform pick.
    s.note_waiting("d", false, t0 + slot * 26);
    let d = s
        .next_destination(&open, &mut rng, t0 + slot * 100)
        .unwrap();
    assert_eq!(d, "a");
}

/// The bound stated in the report: an item at the head of a queue is sent
/// within 4n slots (3n before it starves, then at most n-1 older starved
/// peers ahead of it, one slot each).
#[test]
fn every_waiting_peer_is_served_within_4n_slots() {
    let open = peers(&["a", "b", "c", "d"]);
    let n = open.len() as u32;
    let slot = Duration::from_millis(500);
    let mut s = SteadyScheduler::new(slot);
    let mut rng = always_first(); // the uniform pick never helps b, c or d
    let t0 = Instant::now();
    for p in ["b", "c", "d"] {
        s.note_waiting(p, true, t0);
    }
    let mut served_at = std::collections::HashMap::new();
    for k in 1..=4 * n {
        let now = t0 + slot * k;
        let d = s.next_destination(&open, &mut rng, now).unwrap();
        if d != "a" && !served_at.contains_key(&d) {
            served_at.insert(d.clone(), k);
            s.served(&d, now);
            s.note_waiting(&d, false, now);
        }
    }
    for p in ["b", "c", "d"] {
        let k = served_at.get(p).copied();
        assert!(k.is_some_and(|k| k <= 4 * n), "{p} served at {k:?}");
    }
}

#[test]
fn no_destination_without_open_circuits() {
    let mut s = SteadyScheduler::new(Duration::from_millis(500));
    s.note_waiting("gone", true, Instant::now());
    let mut rng = StdRng::seed_from_u64(1);
    let later = Instant::now() + Duration::from_secs(3600);
    assert_eq!(s.next_destination(&[], &mut rng, later), None);
    // A closed circuit's waiting clock is forgotten, not carried over.
    assert!(s.waiting_since.is_empty());
}

#[test]
fn slot_choices_and_fit() {
    assert_eq!(STEADY_SLOT_CHOICES_MS, [500, 1000, 2000]);
    assert_eq!(STEADY_DEFAULT_SLOT_MS, 500);
    for ms in STEADY_SLOT_CHOICES_MS {
        assert!(valid_slot_ms(ms));
    }
    for ms in [0, 1, 250, 499, 501, 750, 1500, 3000, u32::MAX] {
        assert!(!valid_slot_ms(ms), "{ms}");
    }
    assert!(fits(1023), "type byte and content, plus one pad byte");
    assert!(!fits(1024));
    // A text: type byte, expire_secs (4) and the text, plus one pad byte.
    assert_eq!(STEADY_MAX_TEXT_BYTES, 1018);
    assert!(fits(1 + 4 + STEADY_MAX_TEXT_BYTES));
    assert!(!fits(1 + 4 + STEADY_MAX_TEXT_BYTES + 1));
    assert!(
        fits(crate::disappearing::TIMER_PLAINTEXT_LEN),
        "a timer change rides a slot"
    );
}

#[test]
fn pad_exact_is_exactly_the_length_and_unpads() {
    for len in [0usize, 1, 2, 255, 256, 700, 1023] {
        let msg = vec![0x80u8; len];
        let p = crate::padding::pad_exact(&msg, STEADY_PLAINTEXT_LEN).unwrap();
        assert_eq!(p.len(), STEADY_PLAINTEXT_LEN, "len {len}");
        assert_eq!(crate::padding::unpad(&p), Some(&msg[..]), "len {len}");
    }
    assert_eq!(crate::padding::pad_exact(&[0u8; 1024], 1024), None);
    assert_eq!(crate::padding::pad_exact(&[0u8; 5000], 1024), None);
}

// ---------------------------------------------------------------------------
// Slots on a client
// ---------------------------------------------------------------------------

/// Park a text on `inner`'s session for `peer_hex`, as `send_payload` does
/// in steady mode.
fn park_text(inner: &ClientInner, peer_hex: &str, id: u8, len: usize) {
    let text = "x".repeat(len);
    inner
        .session_manager
        .get_mut(peer_hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(id, &text));
}

fn slot(inner: &mut ClientInner, rng: &mut impl rand::RngCore) -> Option<SlotFill> {
    inner.fire_steady_slot_with(Instant::now(), rng)
}

#[test]
fn every_steady_packet_is_1024_plaintext() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(7);
    // A real message of every fitting size, then cover.
    for (i, len) in [0usize, 1, 200, 600, STEADY_MAX_TEXT_BYTES]
        .into_iter()
        .enumerate()
    {
        park_text(&p.a, &p.pb.hex, i as u8 + 1, len);
        assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Message));
        let sent = sent_relays(&mut p.a_rx);
        assert_eq!(sent.len(), 1, "one packet per slot");
        assert_eq!(sent[0].payload.len(), STEADY_SEALED_LEN, "text of {len}");
        feed(&mut p.b, Frame::Relay(sent[0].clone()));
    }
    let got = texts(&p.b_log);
    assert_eq!(got.len(), 5, "every steady message decrypts and unpads");
    assert_eq!(got[4], "x".repeat(STEADY_MAX_TEXT_BYTES).into_bytes());
    for _ in 0..3 {
        assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Cover));
        let sent = sent_relays(&mut p.a_rx);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload.len(), STEADY_SEALED_LEN, "cover");
    }
}

#[test]
fn a_slot_message_is_ack_tracked_like_a_queued_send() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    park_text(&p.a, &p.pb.hex, 9, 10);
    let mut rng = StdRng::seed_from_u64(7);
    assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Message));
    let id_hex = hex::encode([9u8; 16]);
    assert!(
        p.a.acks.lock().unwrap().attempts(&id_hex).is_some(),
        "tracked for the relay's ack and the resume re-send"
    );
    assert!(p.a.was_sent_to(&p.pb.hex, &[9u8; 16]), "recorded as sent");
}

#[test]
fn items_over_1kib_go_outside_the_shape() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    // 1 + 4 + 1019 bytes needs the 4 KiB bucket: never in a slot.
    park_text(&p.a, &p.pb.hex, 1, STEADY_MAX_TEXT_BYTES + 1);
    park_text(&p.a, &p.pb.hex, 2, 5);
    let mut rng = StdRng::seed_from_u64(7);
    assert_eq!(
        slot(&mut p.a, &mut rng),
        Some(SlotFill::Cover),
        "an oversized head never fills a slot"
    );
    drain(&mut p.a_rx);
    // The normal path sends it at once, at its own bucket, and leaves the
    // small one behind it for a slot.
    let a = process_pending_on(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    p.a = a;
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1, "only the oversized item left");
    assert_eq!(
        sent[0].payload.len(),
        RATCHET_ENVELOPE_OVERHEAD + crate::padding::bucket(1024)
    );
    let left =
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .pending_messages
            .len();
    assert_eq!(left, 1, "the fitting item waits for a slot");
    assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Message));
    assert_eq!(sent_relays(&mut p.a_rx)[0].payload.len(), STEADY_SEALED_LEN);
}

#[test]
fn send_parks_fitting_messages_and_sends_large_ones_at_once() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let client = wrap(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    if let Some(ws) = &client.inner.try_read().unwrap().websocket {
        ws.set_connected_for_test();
    }
    client
        .send_text_message(p.pb.hex.clone(), "small".into())
        .unwrap();
    client
        .send_text_message(p.pb.hex.clone(), "y".repeat(3000))
        .unwrap();
    p.a = std::mem::replace(
        &mut *client.inner.try_write().unwrap(),
        ClientInner::new(crate::ClientConfig::default()),
    );
    drop(client);
    // Both wait (order kept: the large one is behind a parked one).
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "nothing sent outside a slot"
    );
    assert_eq!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .pending_messages
            .len(),
        2
    );
    // With nothing parked, a large send goes at once.
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let client = wrap(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    if let Some(ws) = &client.inner.try_read().unwrap().websocket {
        ws.set_connected_for_test();
    }
    client
        .send_text_message(p.pb.hex.clone(), "y".repeat(3000))
        .unwrap();
    p.a = std::mem::replace(
        &mut *client.inner.try_write().unwrap(),
        ClientInner::new(crate::ClientConfig::default()),
    );
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].payload.len(),
        RATCHET_ENVELOPE_OVERHEAD + crate::padding::bucket(1 + 4 + 3000)
    );
}

#[test]
fn no_packets_without_open_circuits() {
    // No sessions at all.
    let (mut a, mut a_rx) = published(0xA1);
    steady_on(&mut a);
    let mut rng = StdRng::seed_from_u64(7);
    assert!(!a.steady_should_run());
    assert_eq!(slot(&mut a, &mut rng), None);
    assert!(drain(&mut a_rx).is_empty());
    // A session whose circuit is not live on this connection.
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    assert!(p.a.steady_should_run());
    p.a.transport_epoch += 1;
    assert!(p.a.steady_open_peers().is_empty());
    assert!(!p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), None);
    assert!(sent_relays(&mut p.a_rx).is_empty());
}

#[test]
fn peers_awaiting_a_session_init_are_not_open() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    p.a.hello_sync_due.insert(p.pb.hex.clone());
    assert!(
        p.a.steady_open_peers().is_empty(),
        "the session-init goes first, outside the shape"
    );
}

#[test]
fn steady_only_in_foreground_and_connected() {
    let mut p = establish(0xA1, 0xB2);
    let mut rng = StdRng::seed_from_u64(7);
    // Off.
    assert!(!p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), None);
    // On, in the background.
    p.a.apply_steady(true, STEADY_DEFAULT_SLOT_MS, false);
    assert!(!p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), None);
    assert!(sent_relays(&mut p.a_rx).is_empty());
    // On, in the foreground: runs.
    p.a.apply_steady(true, STEADY_DEFAULT_SLOT_MS, true);
    assert!(p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Cover));
    drain(&mut p.a_rx);
    // Disconnected.
    p.a.is_connected = false;
    assert!(!p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), None);
    assert!(drain(&mut p.a_rx).is_empty());
}

#[test]
fn steady_replaces_random_cover_requests() {
    let mut p = establish(0xA1, 0xB2);
    p.a.cover_enabled = true;
    p.a.cover_foreground = true;
    steady_on(&mut p.a);
    p.a.last_heard.insert(p.pb.hex.clone(), Instant::now());
    let now = Instant::now();
    p.a.fire_cover(now);
    p.a.fire_cover(now + Duration::from_secs(200));
    p.a.fire_cover(now + Duration::from_secs(400));
    assert!(p.a.cover_next.is_none(), "no cover request scheduled");
    assert!(sent_relays(&mut p.a_rx).is_empty(), "no cover request sent");
}

#[test]
fn receivers_drop_steady_cover_and_never_reply() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..5 {
        assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Cover));
        for pkt in sent_relays(&mut p.a_rx) {
            feed(&mut p.b, Frame::Relay(pkt));
        }
    }
    assert!(texts(&p.b_log).is_empty(), "never delivered");
    assert!(p.b.cover_replies_due.is_empty(), "no reply scheduled");
    assert!(p.b.pending_receipts.is_empty(), "no receipt owed");
    let later = Instant::now() + Duration::from_secs(120);
    p.b.fire_cover(later);
    p.b.fire_due_receipts(later);
    p.b.redrive_owed_sends(later);
    assert!(sent_relays(&mut p.b_rx).is_empty(), "nothing sent back");
}

#[test]
fn receipts_drain_through_slots() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.b);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log).len(), 1);
    // The app stored it: B owes a delivered receipt; steady holds it for a slot.
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    p.b.fire_due_receipts(Instant::now() + Duration::from_secs(5));
    assert!(
        sent_relays(&mut p.b_rx).is_empty(),
        "not sent outside a slot"
    );
    let mut rng = StdRng::seed_from_u64(7);
    assert_eq!(slot(&mut p.b, &mut rng), Some(SlotFill::Receipt));
    let sent = sent_relays(&mut p.b_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].payload.len(), STEADY_SEALED_LEN);
    feed(&mut p.a, Frame::Relay(sent[0].clone()));
    assert!(p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::Receipt(_, m, _) if *m == hex::encode(id))));
    // Drained: the next slot is cover.
    assert_eq!(slot(&mut p.b, &mut rng), Some(SlotFill::Cover));
}

#[test]
fn turning_steady_off_sends_what_waited_normally() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.b);
    let id = push_text(&p.a, &p.pb.hex, "hi");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    assert!(sent_relays(&mut p.b_rx).is_empty());
    p.b.apply_steady(false, STEADY_DEFAULT_SLOT_MS, true);
    let sent = sent_relays(&mut p.b_rx);
    assert_eq!(sent.len(), 1, "the held receipt leaves when steady stops");
    assert_eq!(
        sent[0].payload.len(),
        RATCHET_ENVELOPE_OVERHEAD + 256,
        "at its normal bucket"
    );
}

#[test]
fn set_steady_traffic_rejects_other_slot_lengths() {
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    for ms in [0, 250, 750, 1500, 5000] {
        assert!(client.set_steady_traffic(true, ms, true).is_err(), "{ms}");
    }
    for ms in STEADY_SLOT_CHOICES_MS {
        assert!(client.set_steady_traffic(true, ms, true).is_ok(), "{ms}");
    }
}

/// The app calls this from the UI thread on every scene-phase change; a
/// connect holds the client lock across network I/O, so it never waits.
#[test]
fn set_steady_traffic_never_waits_for_a_busy_client() {
    let client =
        std::sync::Arc::new(crate::RChatClient::new(crate::ClientConfig::default()).unwrap());
    let lock = client.inner.clone();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _g = lock.blocking_write();
        held_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(10));
    });
    held_rx.recv().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let caller = client.clone();
    std::thread::spawn(move || {
        let _ = caller.set_steady_traffic(true, 1000, true);
        let _ = caller.set_steady_traffic(true, 2000, false);
        let _ = done_tx.send(());
    });
    let returned = done_rx.recv_timeout(Duration::from_millis(500)).is_ok();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert!(returned, "set_steady_traffic waited for the client lock");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let applied = client
            .inner
            .try_read()
            .map(|i| (i.steady_enabled, i.steady_slot_ms, i.steady_foreground))
            .unwrap_or_default();
        if applied == (true, 2000, false) {
            break;
        }
        assert!(Instant::now() < deadline, "never applied: {applied:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The dedicated slot timer: started by the shared tick once steady should
/// run, one packet per slot at the slot rhythm, and it stops when the app
/// leaves the foreground.
#[test]
fn the_slot_timer_keeps_the_rhythm_and_stops_in_the_background() {
    let mut p = establish(0xA1, 0xB2);
    let client = wrap(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    client.set_steady_traffic(true, 500, true).unwrap();
    crate::spawn_ticker(&client.runtime, std::sync::Arc::downgrade(&client.inner));
    std::thread::sleep(Duration::from_millis(1900));
    let sent = sent_relays(&mut p.a_rx);
    // Started within a 250 ms tick, then one slot every 500 ms.
    assert!((2..=4).contains(&sent.len()), "{} packets", sent.len());
    assert!(sent.iter().all(|s| s.payload.len() == STEADY_SEALED_LEN));
    client.set_steady_traffic(true, 500, false).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drain(&mut p.a_rx);
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        sent_relays(&mut p.a_rx).is_empty(),
        "stopped in the background"
    );
    let running = client
        .runtime
        .block_on(async { client.inner.read().await.steady_task_running });
    assert!(!running);
}

// ---------------------------------------------------------------------------
// Fix round 1
// ---------------------------------------------------------------------------

/// R23: after `STEADY_UNHEARD_LIMIT` slots with nothing decrypted from the
/// peer, it leaves the draw; its next decrypted packet brings it back.
#[test]
fn an_unheard_peer_leaves_the_draw_after_k_slots_and_rejoins_on_decrypt() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(7);
    for k in 1..=STEADY_UNHEARD_LIMIT {
        assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Cover), "slot {k}");
    }
    assert_eq!(
        sent_relays(&mut p.a_rx).len(),
        STEADY_UNHEARD_LIMIT as usize
    );
    assert!(p.a.steady_paused(&p.pb.hex));
    assert!(p.a.steady_open_peers().is_empty(), "out of the draw");
    assert!(!p.a.steady_should_run());
    assert_eq!(slot(&mut p.a, &mut rng), None);
    assert!(sent_relays(&mut p.a_rx).is_empty());
    // Its real items take the normal path meanwhile, outside the shape.
    p.a.queue_receipt(&p.pb.hex, crate::receipts::READ, &[[4u8; 16]]);
    p.a.flush_receipts(&p.pb.hex);
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1, "a receipt to a paused peer is not held");
    assert_eq!(sent[0].payload.len(), RATCHET_ENVELOPE_OVERHEAD + 256);
    park_text(&p.a, &p.pb.hex, 1, 5);
    let a = process_pending_on(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    p.a = a;
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1, "a parked message to a paused peer goes now");
    assert_eq!(sent[0].payload.len(), RATCHET_ENVELOPE_OVERHEAD + 256);
    // B is heard from: it rejoins.
    push_text(&p.b, &p.pa.hex, "back");
    relay_all(&mut p.b_rx, &mut p.a);
    assert!(!p.a.steady_paused(&p.pb.hex));
    assert_eq!(p.a.steady_open_peers(), vec![p.pb.hex.clone()]);
    assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Cover));
    assert_eq!(sent_relays(&mut p.a_rx)[0].payload.len(), STEADY_SEALED_LEN);
}

/// C1 (integration): a steady sender and a recipient whose connection
/// dropped while the relay kept the pair's row. Over many slots at most
/// `STEADY_UNHEARD_LIMIT` packets are sent to it, far inside the relay's
/// per-recipient offline queue (1,000, `OFFLINE_QUEUE_MAX_MESSAGES_PER_RECIPIENT`),
/// and even if every one is lost the sender's ratchet gap stays inside
/// `MAX_SKIP`, so its next real message decrypts at the recipient.
#[test]
fn a_steady_sender_never_floods_an_offline_recipient() {
    const RELAY_OFFLINE_QUEUE_PER_RECIPIENT: usize = 1000;
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(11);
    let mut to_b = 0usize;
    for _ in 0..1000 {
        let _ = slot(&mut p.a, &mut rng);
        to_b += sent_relays(&mut p.a_rx).len(); // B is offline: all lost
    }
    assert!(
        to_b <= STEADY_UNHEARD_LIMIT as usize,
        "{to_b} slots to an offline peer"
    );
    assert!(to_b < RELAY_OFFLINE_QUEUE_PER_RECIPIENT / 10);
    assert!((to_b as u32) < crate::crypto::MAX_SKIP);
    // A real message, outside the shape now: B decrypts it after the gap.
    push_text(&p.a, &p.pb.hex, "still there?");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"still there?".to_vec()]);
}

/// M1: a steady stream of receipts never starves our messages to the same
/// peer: when both wait, they take turns.
#[test]
fn receipts_and_messages_take_turns() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    for i in 1..=3u8 {
        park_text(&p.a, &p.pb.hex, i, 5);
    }
    let mut rng = always_first();
    let mut fills = Vec::new();
    for i in 0..6u8 {
        // A new receipt is owed before every slot.
        p.a.queue_receipt(&p.pb.hex, crate::receipts::DELIVERED, &[[0x40 + i; 16]]);
        fills.push(slot(&mut p.a, &mut rng).unwrap());
    }
    use SlotFill::{Message, Receipt};
    assert_eq!(
        fills,
        vec![Receipt, Message, Receipt, Message, Receipt, Message]
    );
    assert!(p
        .a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .pending_messages
        .is_empty());
}

/// M2: the largest slot item, a signed notice with 32 ids, seals at
/// exactly 202 + 1024 bytes.
#[test]
fn the_largest_notice_seals_at_exactly_the_slot_size() {
    use crate::device_key::test_keys::{soft_dk, SoftSigner};
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    p.a.device_signer = Some(std::sync::Arc::new(SoftSigner(soft_dk(0x11).0)));
    let ids: std::collections::VecDeque<[u8; 16]> =
        (0..crate::notice::MAX_IDS as u8).map(|i| [i; 16]).collect();
    p.a.undecryptable.insert(p.pb.hex.clone(), ids);
    p.a.notice_due.insert(p.pb.hex.clone());
    let mut rng = always_first();
    assert_eq!(slot(&mut p.a, &mut rng), Some(SlotFill::Notice));
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].payload.len(), STEADY_SEALED_LEN);
    assert!(
        !p.a.notice_due.contains(&p.pb.hex),
        "all 32 ids in one batch"
    );
}

/// M2: an item over 1 KiB is never padded to a bucket inside a slot: the
/// seal refuses it (and a debug build asserts).
#[test]
#[should_panic(expected = "a steady slot item over 1 KiB")]
fn a_slot_never_falls_back_to_bucket_padding() {
    let mut p = establish(0xA1, 0xB2);
    p.a.steady_padding = true;
    let _ = p.a.seal_ratchet(&p.pb.hex, [1; 16], &[0x01; 2000]);
}

/// M6: a parked message whose seal fails for any reason but a failed
/// write is reported lost, never dropped silently.
#[test]
fn a_slot_message_that_cannot_be_sealed_is_reported_lost() {
    let mut p = establish(0xA1, 0xB2);
    steady_on(&mut p.a);
    park_text(&p.a, &p.pb.hex, 7, 5);
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .target_circuit_id = None;
    assert!(!p.a.steady_send_message(&p.pb.hex));
    assert!(
        statuses(&p.a_log).contains(&crate::status::StatusEvent::QueuedSendLost {
            peer: p.pb.hex.clone(),
            message_id: hex::encode([7u8; 16]),
        })
    );
}

/// M9: a bad slot length is an invalid parameter (FFI code 9).
#[test]
fn a_bad_slot_length_is_an_invalid_parameter() {
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    assert!(matches!(
        client.set_steady_traffic(true, 750, true),
        Err(crate::RChatError::InvalidParameter { .. })
    ));
}

// ---------------------------------------------------------------------------
// Fix round 2
// ---------------------------------------------------------------------------

/// The restarted client's circuit to `peer_hex` is live again, as when it
/// resumes a relay row the peer's departure did not close.
fn resume_live(inner: &mut ClientInner, peer_hex: &str) {
    let epoch = inner.transport_epoch;
    inner
        .session_manager
        .get_mut(peer_hex)
        .unwrap()
        .circuit_epoch = epoch;
}

/// R26: the unheard count survives relaunches. With B offline through two
/// restarts of A, A sends at most `STEADY_UNHEARD_LIMIT` slots to B in all,
/// and A's next real message still decrypts at B.
#[test]
fn the_unheard_count_survives_restarts() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(21);
    let mut to_b = 0usize;
    for _ in 0..200 {
        let _ = slot(&mut p.a, &mut rng);
    }
    to_b += sent_relays(&mut p.a_rx).len();
    for _restart in 0..2 {
        let (mut a2, mut a2_rx, _log) = restart_from(0xA1, 0xB2, &sa);
        resume_live(&mut a2, &p.pb.hex);
        steady_on(&mut a2);
        for _ in 0..200 {
            let _ = slot(&mut a2, &mut rng);
        }
        to_b += sent_relays(&mut a2_rx).len();
        p.a = a2;
        p.a_rx = a2_rx;
    }
    assert!(
        to_b <= STEADY_UNHEARD_LIMIT as usize,
        "{to_b} in-shape packets to an offline peer across restarts"
    );
    push_text(&p.a, &p.pb.hex, "after two restarts");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"after two restarts".to_vec()]);
}

/// R26: a restart pauses no peer by itself: a peer below the limit is in
/// the draw at once (two steady users never wait on each other).
#[test]
fn a_restart_pauses_no_peer_below_the_limit() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    steady_on(&mut p.a);
    let mut rng = StdRng::seed_from_u64(22);
    for _ in 0..10 {
        let _ = slot(&mut p.a, &mut rng);
    }
    let (mut a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    resume_live(&mut a2, &p.pb.hex);
    steady_on(&mut a2);
    assert_eq!(
        a2.steady_unheard.get(&p.pb.hex),
        Some(&10),
        "restored exactly"
    );
    assert_eq!(a2.steady_open_peers(), vec![p.pb.hex.clone()]);
}
