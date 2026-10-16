use super::*;
use crate::test_support::*;
use crate::{ClientInner, ConnectionStatus, RChatCallbacks, ReceivedMessage};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// The 0x09 control plaintext and the conflict rule
// ---------------------------------------------------------------------------

#[test]
fn timer_round_trip() {
    for secs in TIMER_CHOICES_SECS {
        for at in [0u64, 1, 1_760_000_000_123, u64::MAX] {
            let pt = encode_timer(secs, at);
            assert_eq!(pt.len(), TIMER_PLAINTEXT_LEN);
            assert_eq!(pt[0], TIMER_TYPE);
            assert_eq!(decode_timer(&pt), Ok((secs, at)), "{secs} {at}");
        }
    }
    // The exact layout: 0x09 ‖ secs u32 BE ‖ changed_at_ms u64 BE.
    assert_eq!(
        encode_timer(86400, 0x0102_0304_0506_0708),
        [0x09, 0, 1, 0x51, 0x80, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn timer_refuses_unknown_value() {
    for secs in [1u32, 60, 299, 301, 3599, 7200, 86401, 1_209_600, u32::MAX] {
        assert_eq!(
            decode_timer(&encode_timer(secs, 5)),
            Err(TimerError::UnknownValue),
            "{secs}"
        );
        assert!(!valid_timer(secs));
    }
    let good = encode_timer(300, 5);
    assert_eq!(decode_timer(&good[..12]), Err(TimerError::Malformed));
    assert_eq!(
        decode_timer(&[good.clone(), vec![0]].concat()),
        Err(TimerError::Malformed)
    );
    let mut wrong_type = good.clone();
    wrong_type[0] = 0x01;
    assert_eq!(decode_timer(&wrong_type), Err(TimerError::Malformed));
    assert_eq!(decode_timer(&[]), Err(TimerError::Malformed));
}

#[test]
fn later_change_wins_and_tie_breaks_on_lower_ik() {
    let (low, high) = ("0a".repeat(32), "f0".repeat(32));
    // Later wins, whoever made it.
    assert!(timer_wins((2, &high), (1, &low)));
    assert!(!timer_wins((1, &low), (2, &high)));
    assert!(timer_wins((1_000_001, &low), (1_000_000, &high)));
    // A tie goes to the lower identity-key hex, from either side.
    assert!(timer_wins((7, &low), (7, &high)));
    assert!(!timer_wins((7, &high), (7, &low)));
    // Case does not matter (both sides compare lowercase hex).
    assert!(timer_wins((7, &"0A".repeat(32)), (7, &high)));
    // The same change never beats itself.
    assert!(!timer_wins((7, &low), (7, &low)));
}

// ---------------------------------------------------------------------------
// Per-message expire_secs
// ---------------------------------------------------------------------------

#[test]
fn expire_secs_round_trips_in_text_image_file() {
    use crate::protocol::MessageType;
    use crate::steady::message_plaintext;
    for expire in TIMER_CHOICES_SECS {
        let text = message_plaintext(MessageType::Text, &with_expire(expire, b"hello"));
        assert_eq!(&text[..5], [&[0x01][..], &expire.to_be_bytes()].concat());
        assert_eq!(split_expire(&text), Some((expire, &b"hello"[..])));
        assert!(crate::is_deliverable(&text));

        let img = [&b"IMG1"[..], &[0xFF, 0xD8, 0xFF]].concat();
        let image = message_plaintext(MessageType::Binary, &with_expire(expire, &img));
        assert_eq!(image[0], 0x02);
        assert_eq!(split_expire(&image), Some((expire, &img[..])));
        assert!(crate::is_deliverable(&image));

        let file =
            crate::file_msg::encode_file("a.pdf", "application/pdf", b"%PDF", expire).unwrap();
        assert_eq!(split_expire(&file).map(|(e, _)| e), Some(expire));
        assert_eq!(
            crate::file_msg::decode_file(&file).unwrap().expire_secs,
            expire
        );
    }
    // Too short to carry expire_secs: never delivered.
    assert!(!crate::is_deliverable(&[0x01, 0, 0, 0]));
    assert!(!crate::is_deliverable(&[0x02, 0, 0, 0]));
    // A binary body must still start with a known magic after the timer.
    assert!(!crate::is_deliverable(
        &[&[0x02, 0, 0, 0, 0][..], b"NOPE"].concat()
    ));
}

/// Records what a receiving app is handed.
#[derive(Clone, Default)]
struct Rec {
    /// (id, content, expire_secs)
    messages: Arc<Mutex<Vec<(String, Vec<u8>, u32)>>>,
    /// (id, name, expire_secs)
    files: Arc<Mutex<Vec<(String, String, u32)>>>,
    /// (peer, secs, changed_at_ms, by_me)
    timers: Arc<Mutex<Vec<(String, u32, u64, bool)>>>,
    /// Receipts and status events handed to the app (message ids).
    receipts: Arc<Mutex<Vec<String>>>,
    statuses: Arc<Mutex<Vec<crate::status::StatusEvent>>>,
    /// Relay acks handed to the app.
    delivered: Arc<Mutex<Vec<String>>>,
}

impl RChatCallbacks for Rec {
    fn on_connection_status_changed(&self, _: ConnectionStatus) {}
    fn on_message_received(&self, m: ReceivedMessage) {
        self.messages
            .lock()
            .unwrap()
            .push((m.id, m.content, m.expire_secs));
    }
    fn on_file_received(&self, f: crate::ReceivedFile) {
        self.files
            .lock()
            .unwrap()
            .push((f.id, f.name, f.expire_secs));
    }
    fn on_message_delivered(&self, id: String) {
        self.delivered.lock().unwrap().push(id);
    }
    fn on_error(&self, _: String) {}
    fn on_circuit_established(&self, _: String, _: bool) {}
    fn on_message_receipt(&self, _: String, id: String, _: u8) {
        self.receipts.lock().unwrap().push(id);
    }
    fn on_status_event(&self, e: crate::status::StatusEvent) {
        self.statuses.lock().unwrap().push(e);
    }
    fn on_timer_changed(&self, peer: String, secs: u32, changed_at_ms: u64, by_me: bool) {
        self.timers
            .lock()
            .unwrap()
            .push((peer, secs, changed_at_ms, by_me));
    }
}

fn record(inner: &mut ClientInner) -> Rec {
    let rec = Rec::default();
    inner.callbacks = Some(Box::new(rec.clone()));
    rec
}

/// Run `f` on A's inner behind a real client (the public send API), then
/// hand A back.
fn with_client(p: &mut Pair, f: impl FnOnce(&crate::RChatClient)) {
    let client = wrap(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    if let Some(ws) = &client.inner.try_read().unwrap().websocket {
        ws.set_connected_for_test();
    }
    f(&client);
    p.a = std::mem::replace(
        &mut *client.inner.try_write().unwrap(),
        ClientInner::new(crate::ClientConfig::default()),
    );
}

fn set_timer(inner: &mut ClientInner, peer: &str, secs: u32, by_me: bool) {
    lock_timers(inner).insert(
        peer.to_string(),
        PeerTimer {
            secs,
            changed_at_ms: 1,
            by_me,
            acked: true,
            out_id: None,
            resends: 0,
        },
    );
}

/// Hand everything each side queued to the other, flushing queued sends,
/// until nothing moves (at most `rounds`). Returns the packets relayed.
fn pump_pair(p: &mut Pair, rounds: usize) -> usize {
    let mut total = 0;
    for _ in 0..rounds {
        p.a = process_pending_on(std::mem::replace(
            &mut p.a,
            ClientInner::new(crate::ClientConfig::default()),
        ));
        p.b = process_pending_on(std::mem::replace(
            &mut p.b,
            ClientInner::new(crate::ClientConfig::default()),
        ));
        let moved = relay_all(&mut p.a_rx, &mut p.b) + relay_all(&mut p.b_rx, &mut p.a);
        total += moved;
        if moved == 0 {
            break;
        }
    }
    total
}

#[test]
fn receiver_honours_per_message_value_not_own_setting() {
    let mut p = establish(0xA1, 0xB2);
    let rec = record(&mut p.b);
    // B's own setting for A is a day; A's for B is five minutes.
    set_timer(&mut p.b, &p.pa.hex.clone(), 86400, true);
    set_timer(&mut p.a, &p.pb.hex.clone(), 300, true);
    let (pb, img) = (p.pb.hex.clone(), [&b"IMG1"[..], &[1, 2, 3]].concat());
    with_client(&mut p, |c| {
        c.send_text_message(pb.clone(), "five".into()).unwrap();
        c.send_binary_message(pb.clone(), img.clone()).unwrap();
        c.send_file_message(
            pb.clone(),
            "n.txt".into(),
            "text/plain".into(),
            b"f".to_vec(),
        )
        .unwrap();
    });
    // A turns its timer off: the next message says never, whatever B has.
    set_timer(&mut p.a, &pb, 0, true);
    with_client(&mut p, |c| {
        c.send_text_message(pb.clone(), "never".into()).unwrap();
    });
    relay_all(&mut p.a_rx, &mut p.b);
    let messages = rec.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 3);
    assert_eq!(
        (messages[0].1.clone(), messages[0].2),
        (b"five".to_vec(), 300)
    );
    assert_eq!((messages[1].1.clone(), messages[1].2), (img, 300));
    assert_eq!(
        (messages[2].1.clone(), messages[2].2),
        (b"never".to_vec(), 0)
    );
    let files = rec.files.lock().unwrap().clone();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].2, 300);
    // B's own setting is untouched by what A's messages carry.
    assert_eq!(p.b.timer_secs(&p.pa.hex), 86400);
}

#[test]
fn resends_carry_the_original_timer_not_the_current_one() {
    // Three messages B lost and A may resend automatically (RV3).
    let mut r = rv3_run(3, |_, _| {});
    let rec = record(&mut r.b2);
    let pb = r.p.pb.hex.clone();
    // The conversation's timer is now a week, but the messages were first
    // sent under five minutes: the resends must say five minutes.
    set_timer(&mut r.p.a, &pb, 604800, true);
    let ids: Vec<String> = r.ids.iter().map(hex::encode).collect();
    with_client(&mut r.p, |c| {
        c.resend_text_message_using_id(pb.clone(), "again".into(), 300, ids[0].clone())
            .unwrap();
        c.resend_binary_message_using_id(pb.clone(), b"IMG1x".to_vec(), 300, ids[1].clone())
            .unwrap();
        c.resend_file_message_using_id(
            pb.clone(),
            "r.txt".into(),
            "".into(),
            b"r".to_vec(),
            300,
            ids[2].clone(),
        )
        .unwrap();
    });
    relay_all(&mut r.p.a_rx, &mut r.b2);
    let messages = rec.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(messages.iter().all(|m| m.2 == 300), "{messages:?}");
    let files = rec.files.lock().unwrap().clone();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].2, 300);
}

#[test]
fn resend_with_an_unknown_timer_is_refused() {
    let mut p = establish(0xA1, 0xB2);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        assert!(matches!(
            c.resend_text_message_using_id(pb.clone(), "x".into(), 301, hex::encode([0x61; 16])),
            Err(crate::RChatError::InvalidParameter { .. })
        ));
    });
}

// ---------------------------------------------------------------------------
// The timer change: sent, applied, synced
// ---------------------------------------------------------------------------

#[test]
fn timer_change_is_padded_and_ack_tracked() {
    let mut p = establish(0xA1, 0xB2);
    let rec_a = record(&mut p.a);
    let rec_b = record(&mut p.b);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 86400).unwrap();
    });
    // Applied on this side, reported as mine.
    assert_eq!(p.a.timer_secs(&pb), 86400);
    let mine = rec_a.timers.lock().unwrap().clone();
    assert_eq!(mine.len(), 1);
    assert_eq!(
        (mine[0].0.as_str(), mine[0].1, mine[0].3),
        (&pb[..], 86400, true)
    );
    // One packet, padded to the 256-byte bucket like any short message.
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].payload.len(),
        crate::sealed::RATCHET_ENVELOPE_OVERHEAD + crate::padding::bucket(TIMER_PLAINTEXT_LEN)
    );
    // Tracked for the relay's ack (and re-sent at a resume like a message).
    assert_eq!(
        p.a.tracked_ids_for(&pb).len(),
        1,
        "the change is ack-tracked"
    );
    assert!(!p.a.timer_state(&pb).unwrap().acked, "not yet acknowledged");
    // B applies it, reports it as the peer's, and shows no message.
    feed(&mut p.b, crate::protocol::Frame::Relay(sent[0].clone()));
    assert_eq!(p.b.timer_secs(&p.pa.hex), 86400);
    let theirs = rec_b.timers.lock().unwrap().clone();
    assert_eq!(theirs.len(), 1);
    assert_eq!(
        (theirs[0].0.as_str(), theirs[0].1, theirs[0].2, theirs[0].3),
        (&p.pa.hex[..], 86400, mine[0].2, false)
    );
    assert!(rec_b.messages.lock().unwrap().is_empty());
    // R32: B's core answers it with a delivered receipt; A's core takes it
    // as the acknowledgement, and A's app never hears of the id.
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1, "one receipt back");
    assert!(p.a.timer_state(&pb).unwrap().acked);
    assert!(rec_a.receipts.lock().unwrap().is_empty());
    assert!(rec_a.statuses.lock().unwrap().is_empty());
    // New sends now carry the day.
    with_client(&mut p, |c| {
        c.send_text_message(pb.clone(), "x".into()).unwrap();
    });
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(rec_b.messages.lock().unwrap()[0].2, 86400);
}

#[test]
fn set_timer_refuses_values_outside_the_choices() {
    let mut p = establish(0xA1, 0xB2);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        for secs in [1u32, 600, 7200, u32::MAX] {
            assert!(matches!(
                c.set_disappearing_timer(pb.clone(), secs),
                Err(crate::RChatError::InvalidParameter { .. })
            ));
        }
    });
    assert!(sent_relays(&mut p.a_rx).is_empty());
    assert_eq!(p.a.timer_secs(&pb), 0);
}

#[test]
fn an_older_or_losing_change_is_ignored() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    let a_hex = p.pa.hex.clone();
    // B's own change at t=100.
    lock_timers(&p.b).insert(
        a_hex.clone(),
        PeerTimer {
            secs: 3600,
            changed_at_ms: 100,
            by_me: true,
            acked: true,
            out_id: None,
            resends: 0,
        },
    );
    // An older change from A loses.
    assert!(!p.b.apply_peer_timer(&a_hex, 300, 99));
    assert_eq!(p.b.timer_secs(&a_hex), 3600);
    // A tie goes to the lower identity hex.
    let a_lower = a_hex < p.pb.hex;
    assert_eq!(p.b.apply_peer_timer(&a_hex, 300, 100), a_lower);
    assert_eq!(p.b.timer_secs(&a_hex), if a_lower { 300 } else { 3600 });
    // A later one wins.
    assert!(p.b.apply_peer_timer(&a_hex, 0, 101));
    assert_eq!(p.b.timer_secs(&a_hex), 0);
    let reported = rec_b.timers.lock().unwrap().len();
    assert_eq!(
        reported,
        if a_lower { 2 } else { 1 },
        "only applied changes are reported"
    );
}

#[test]
fn malformed_or_unknown_timer_changes_are_dropped() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    for pt in [
        encode_timer(301, 5),
        encode_timer(300, 5)[..12].to_vec(),
        [encode_timer(300, 5), vec![0]].concat(),
    ] {
        p.a.send_tracked_for_test(&p.pb.hex, rand::random(), &pt)
            .unwrap();
    }
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(rec_b.timers.lock().unwrap().is_empty());
    assert!(rec_b.messages.lock().unwrap().is_empty());
    assert_eq!(p.b.timer_secs(&p.pa.hex), 0);
}

#[test]
fn the_timer_survives_a_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 3600).unwrap();
    });
    let before = p.a.timer_state(&pb).unwrap();
    assert!(before.out_id.is_some());
    let (a, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    assert_eq!(
        a.timer_state(&pb),
        Some(PeerTimer {
            resends: 0,
            ..before
        }),
        "value, time, setter, ack state and carrier id"
    );
}

#[test]
fn forgetting_an_expired_message_drops_its_kept_plaintext() {
    let mut p = establish(0xA1, 0xB2);
    let id = [0x71u8; 16];
    p.a.send_tracked_for_test(&p.pb.hex, id, &[&[0x01][..], &[0; 4], b"secret"].concat())
        .unwrap();
    // And one still queued on the session, unsent.
    let mut queued = pending_msg(0x72, "queued");
    queued.content = with_expire(300, b"queued");
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .pending_messages
        .push_back(queued);
    assert!(p
        .a
        .acks
        .lock()
        .unwrap()
        .attempts(&hex::encode(id))
        .is_some());
    p.a.forget_message(&hex::encode(id));
    p.a.forget_message(&hex::encode([0x72u8; 16]));
    assert!(p
        .a
        .acks
        .lock()
        .unwrap()
        .attempts(&hex::encode(id))
        .is_none());
    assert!(p
        .a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .pending_messages
        .is_empty());
}

/// §B.1 with §I.2: a timer change is 13 bytes, so in steady mode it waits
/// for a slot and rides it at exactly 1 KiB, like a short message.
#[test]
fn a_timer_change_rides_a_steady_slot() {
    use rand::SeedableRng;
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    p.a.apply_steady(true, crate::steady::STEADY_DEFAULT_SLOT_MS, true);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 300).unwrap();
    });
    assert!(sent_relays(&mut p.a_rx).is_empty(), "parked for a slot");
    assert_eq!(p.a.timer_secs(&pb), 300, "applied once queued");
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    assert_eq!(
        p.a.fire_steady_slot_with(std::time::Instant::now(), &mut rng),
        Some(crate::steady::SlotFill::Message)
    );
    let sent = sent_relays(&mut p.a_rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].payload.len(),
        crate::sealed::RATCHET_ENVELOPE_OVERHEAD + crate::steady::STEADY_PLAINTEXT_LEN
    );
    feed(&mut p.b, crate::protocol::Frame::Relay(sent[0].clone()));
    assert_eq!(p.b.timer_secs(&p.pa.hex), 300);
    assert_eq!(rec_b.timers.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Ruling R32: original timers on retries, the timer a send carried, and the
// core owning 0x09 delivery
// ---------------------------------------------------------------------------

/// Manual Retry and the fallback Resend (same id, not the checked entry)
/// carry the message's original timer after the timer changed; a first
/// send carries the new one.
#[test]
fn retries_carry_the_original_timer_after_a_change() {
    let mut p = establish(0xA1, 0xB2);
    let rec = record(&mut p.b);
    let pb = p.pb.hex.clone();
    // First sent under five minutes, then the conversation went to a week.
    set_timer(&mut p.a, &pb, 604800, true);
    let id = |b: u8| hex::encode([b; 16]);
    with_client(&mut p, |c| {
        c.retry_text_message_using_id(pb.clone(), "again".into(), 300, id(0x41))
            .unwrap();
        c.retry_binary_message_using_id(pb.clone(), b"IMG1x".to_vec(), 300, id(0x42))
            .unwrap();
        c.retry_file_message_using_id(
            pb.clone(),
            "r.txt".into(),
            "".into(),
            b"r".to_vec(),
            300,
            id(0x43),
        )
        .unwrap();
        // A brand-new message takes the week.
        c.send_text_message(pb.clone(), "new".into()).unwrap();
    });
    relay_all(&mut p.a_rx, &mut p.b);
    let messages = rec.messages.lock().unwrap().clone();
    assert_eq!(
        messages.iter().map(|m| m.2).collect::<Vec<_>>(),
        vec![300, 300, 604800]
    );
    assert_eq!(rec.files.lock().unwrap()[0].2, 300);
    // A value outside the choices is refused.
    with_client(&mut p, |c| {
        assert!(matches!(
            c.retry_text_message_using_id(pb.clone(), "x".into(), 7, id(0x44)),
            Err(crate::RChatError::InvalidParameter { .. })
        ));
    });
}

/// Ruling R32 point 3: a first send reports the timer it actually carried.
#[test]
fn first_sends_report_the_timer_they_carried() {
    let mut p = establish(0xA1, 0xB2);
    let rec = record(&mut p.b);
    let pb = p.pb.hex.clone();
    set_timer(&mut p.a, &pb, 3600, true);
    let mut reported = Vec::new();
    with_client(&mut p, |c| {
        reported.push(
            c.send_text(pb.clone(), "t".into(), None)
                .unwrap()
                .expire_secs,
        );
        reported.push(
            c.send_binary(pb.clone(), b"IMG1y".to_vec(), None)
                .unwrap()
                .expire_secs,
        );
        let f = c
            .send_file(pb.clone(), "f".into(), "".into(), b"f".to_vec(), None)
            .unwrap();
        reported.push(f.expire_secs);
        reported.push(
            c.send_text(pb.clone(), "intro".into(), Some(hex::encode([0x55u8; 16])))
                .unwrap()
                .expire_secs,
        );
    });
    set_timer(&mut p.a, &pb, 0, true);
    with_client(&mut p, |c| {
        reported.push(
            c.send_text(pb.clone(), "off".into(), None)
                .unwrap()
                .expire_secs,
        );
    });
    assert_eq!(reported, vec![3600, 3600, 3600, 3600, 0]);
    relay_all(&mut p.a_rx, &mut p.b);
    let got: Vec<u32> = rec.messages.lock().unwrap().iter().map(|m| m.2).collect();
    assert_eq!(
        got,
        vec![3600, 3600, 3600, 0],
        "what was reported is what was sent"
    );
    assert_eq!(rec.files.lock().unwrap()[0].2, 3600);
}

/// A 0x09 reported lost is re-sent by the core with the latest state; the
/// app never sees the report, and resends stop once acknowledged.
#[test]
fn a_lost_timer_change_is_resent() {
    let mut p = establish(0xA1, 0xB2);
    let rec_a = record(&mut p.a);
    let rec_b = record(&mut p.b);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 300).unwrap();
    });
    let first = p.a.timer_state(&pb).unwrap().out_id.unwrap();
    assert_eq!(sent_relays(&mut p.a_rx).len(), 1, "sent, then lost");
    // Then the conversation went to an hour, also lost.
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 3600).unwrap();
    });
    drain(&mut p.a_rx);
    // B's phone reports the first one undelivered.
    p.a.emit_status(crate::status::StatusEvent::PeerUndelivered {
        peer: pb.clone(),
        message_id: hex::encode(first),
        reason: 1,
    });
    assert!(
        rec_a.statuses.lock().unwrap().is_empty(),
        "the core's, not the app's"
    );
    // The next flush re-sends the latest state (an hour), not the lost bytes.
    pump_pair(&mut p, 6);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 3600);
    assert_eq!(
        rec_b.timers.lock().unwrap().len(),
        1,
        "only the latest arrived"
    );
    assert!(p.a.timer_state(&pb).unwrap().acked);
    assert!(rec_a.receipts.lock().unwrap().is_empty());
    assert!(rec_a.delivered.lock().unwrap().is_empty());
    // Acknowledged: a late loss report changes nothing.
    p.a.emit_status(crate::status::StatusEvent::AckUnknown {
        peer: pb.clone(),
        message_id: hex::encode(first),
        attempts: 3,
    });
    assert_eq!(pump_pair(&mut p, 3), 0, "nothing re-sent once acknowledged");
    // An ordinary message's report still reaches the app.
    p.a.emit_status(crate::status::StatusEvent::AckUnknown {
        peer: pb.clone(),
        message_id: hex::encode([0x99u8; 16]),
        attempts: 3,
    });
    assert_eq!(rec_a.statuses.lock().unwrap().len(), 1);
}

/// Loss-triggered resends are capped per state, so a relay that never
/// delivers can't make the core send forever.
#[test]
fn loss_resends_are_capped() {
    let mut p = establish(0xA1, 0xB2);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 300).unwrap();
    });
    let mut sends = 0;
    for _ in 0..(MAX_TIMER_RESENDS as usize + 3) {
        drain(&mut p.a_rx);
        let id = p.a.timer_state(&pb).unwrap().out_id.unwrap();
        p.a.emit_status(crate::status::StatusEvent::SendNotAccepted {
            peer: pb.clone(),
            message_id: hex::encode(id),
        });
        p.a = process_pending_on(std::mem::replace(
            &mut p.a,
            ClientInner::new(crate::ClientConfig::default()),
        ));
        sends += sent_relays(&mut p.a_rx).len();
    }
    assert_eq!(sends, MAX_TIMER_RESENDS as usize);
}

/// After a re-pair, our unacknowledged change goes again on the new
/// session; an acknowledged one does not.
#[test]
fn an_unacked_timer_is_resent_after_a_re_pair() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    let pb = p.pb.hex.clone();
    with_client(&mut p, |c| {
        c.set_disappearing_timer(pb.clone(), 86400).unwrap();
    });
    // The relay took it, but it never reached B's app (B's old session
    // could not read it): the tracker holds nothing to re-send.
    drain(&mut p.a_rx);
    relay_acked_all(&p.a);
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    pump_pair(&mut p, 8);
    assert_eq!(
        p.b.timer_secs(&p.pa.hex),
        86400,
        "re-sent on the new session"
    );
    assert_eq!(rec_b.timers.lock().unwrap().len(), 1);
    assert!(p.a.timer_state(&pb).unwrap().acked);
    // Acknowledged: a second re-pair sends no timer change.
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    assert!(
        !p.a.session_manager
            .get(&pb)
            .unwrap()
            .pending_messages
            .iter()
            .any(|m| m.msg_type == crate::protocol::MessageType::Timer),
        "nothing queued for an acknowledged state"
    );
}

/// Both phones change the timer at the same moment: the tie-break picks
/// one value on both, and the exchange ends (no loop).
#[test]
fn simultaneous_changes_settle_without_a_loop() {
    let mut p = establish(0xA1, 0xB2);
    let (pa, pb) = (p.pa.hex.clone(), p.pb.hex.clone());
    p.a.change_timer(&pb, 300, 1_000).unwrap();
    p.b.change_timer(&pa, 3600, 1_000).unwrap();
    let moved = pump_pair(&mut p, 20);
    assert!(moved > 0);
    assert_eq!(pump_pair(&mut p, 5), 0, "quiet once settled");
    let winner = if pa < pb { 300 } else { 3600 };
    assert_eq!(p.a.timer_secs(&pb), winner);
    assert_eq!(p.b.timer_secs(&pa), winner);
    // The winner's change is acknowledged; the loser holds the peer's.
    let (a, b) = (p.a.timer_state(&pb).unwrap(), p.b.timer_state(&pa).unwrap());
    assert_eq!(a.by_me, pa < pb);
    assert_eq!(b.by_me, pb < pa);
    assert!(a.acked && b.acked);
}

// ---------------------------------------------------------------------------
// Ruling R33
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// I-1: a change timed at u64::MAX (or more than a day ahead) is neither
/// applied nor receipted, so it can't lock the timer; our own change still
/// applies afterwards.
#[test]
fn a_far_future_timer_change_is_refused() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    for at in [u64::MAX, now_ms() + MAX_TIMER_FUTURE_MS + 60_000] {
        p.a.send_tracked_for_test(&p.pb.hex, rand::random(), &encode_timer(300, at))
            .unwrap();
    }
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 0, "not applied");
    assert!(rec_b.timers.lock().unwrap().is_empty());
    assert!(
        !p.b.pending_receipts.keys().any(|(h, _)| *h == p.pa.hex),
        "not receipted: the sender's capped re-sends run out"
    );
    assert!(sent_relays(&mut p.b_rx).is_empty());
    // B (whatever its identity) can still set the timer.
    let out = p.b.change_timer(&p.pa.hex, 3600, now_ms()).unwrap();
    assert_eq!(
        out,
        TimerOutcome {
            applied: true,
            secs: 3600,
            intro_dropped: None
        }
    );
    // Within the day ahead is accepted (a peer clock somewhat fast).
    p.a.send_tracked_for_test(
        &p.pb.hex,
        rand::random(),
        &encode_timer(86400, now_ms() + 3_600_000),
    )
    .unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 86400);
}

/// I-1 / M-9: the peer's clock is an hour ahead; our change is timed just
/// after theirs (`last + 1`), so it wins on both phones.
#[test]
fn our_change_wins_when_the_peer_clock_is_ahead() {
    let mut p = establish(0xA1, 0xB2);
    let ahead = now_ms() + 3_600_000;
    // B's change, timed by B's fast clock, reaches A.
    p.b.change_timer(&p.pa.hex, 300, ahead).unwrap();
    pump_pair(&mut p, 6);
    assert_eq!(p.a.timer_secs(&p.pb.hex), 300);
    // A changes it now by A's clock: still later than B's.
    let out = p.a.change_timer(&p.pb.hex, 86400, now_ms()).unwrap();
    assert!(out.applied);
    assert_eq!(out.secs, 86400);
    assert_eq!(p.a.timer_state(&p.pb.hex).unwrap().changed_at_ms, ahead + 1);
    pump_pair(&mut p, 6);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 86400, "B takes it too");
    assert!(p.a.timer_state(&p.pb.hex).unwrap().acked);
}

/// I-1: a change that loses reports the timer in force, not the request.
#[test]
fn a_losing_change_reports_the_state_in_force() {
    let mut p = establish(0xA1, 0xB2);
    // Our clock says 1000, but a change at 5000 is in force and its last+1
    // rule makes ours later, so force a loss: equal time, higher ik setter.
    lock_timers(&p.a).insert(
        p.pb.hex.clone(),
        PeerTimer {
            secs: 300,
            changed_at_ms: u64::MAX,
            by_me: false,
            acked: true,
            out_id: None,
            resends: 0,
        },
    );
    let out = p.a.change_timer(&p.pb.hex, 3600, 1_000).unwrap();
    let a_lower = p.pa.hex < p.pb.hex;
    if a_lower {
        assert_eq!(
            out,
            TimerOutcome {
                applied: true,
                secs: 3600,
                intro_dropped: None
            }
        );
    } else {
        assert_eq!(
            out,
            TimerOutcome {
                applied: false,
                secs: 300,
                intro_dropped: None
            },
            "the state in force"
        );
        assert!(p
            .a
            .session_manager
            .get(&p.pb.hex)
            .unwrap()
            .pending_messages
            .is_empty());
    }
}

/// M-8: a change decrypted under the retired session is dropped.
#[test]
fn a_timer_change_from_a_retired_session_is_refused() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    let old =
        p.a.seal_ratchet(&p.pb.hex, [0x66; 16], &encode_timer(300, now_ms()))
            .unwrap();
    reestablish(&mut p.a, &mut p.b, &p.pa, &p.pb);
    pump_pair(&mut p, 6);
    assert!(p.b.session_manager.retired_count(&p.pa.hex) > 0);
    p.b.handle_sealed_payload(&old.payload);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 0);
    assert!(rec_b.timers.lock().unwrap().is_empty());
}

/// M-1: a message whose expire_secs is not a timer choice is dropped.
#[test]
fn messages_with_an_unknown_timer_are_dropped() {
    use crate::protocol::MessageType;
    use crate::steady::message_plaintext;
    for expire in [1u32, 299, 301, 7200, u32::MAX] {
        let text = message_plaintext(MessageType::Text, &with_expire(expire, b"x"));
        assert!(!crate::is_deliverable(&text), "{expire}");
        let img = message_plaintext(MessageType::Binary, &with_expire(expire, b"IMG1x"));
        assert!(!crate::is_deliverable(&img), "{expire}");
        let file = crate::file_msg::encode_file("a", "", b"f", expire).unwrap();
        assert!(!crate::is_deliverable(&file), "{expire}");
    }
    // End to end: B shows nothing.
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    p.a.send_tracked_for_test(
        &p.pb.hex,
        rand::random(),
        &[&[0x01][..], &301u32.to_be_bytes(), b"x"].concat(),
    )
    .unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(rec_b.messages.lock().unwrap().is_empty());
}

/// I-2: no intro while the conversation has a timer.
#[test]
fn no_intro_while_a_timer_is_on() {
    let (mut a, _rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    set_timer(&mut a, &b.hex, 300, true);
    assert!(matches!(
        a.set_intro(&b.hex, "hello", std::time::Instant::now()),
        Err(crate::RChatError::InvalidParameter { .. })
    ));
    assert!(matches!(
        a.set_intro_with_id(&b.hex, "hello", Some([7; 16]), std::time::Instant::now()),
        Err(crate::RChatError::InvalidParameter { .. })
    ));
    set_timer(&mut a, &b.hex, 0, true);
    assert!(a
        .set_intro(&b.hex, "hello", std::time::Instant::now())
        .is_ok());
}

/// Final review M-1: an intro queued before the timer was turned on would
/// go out in the next knock with no timer. Our change to a non-zero timer
/// drops it (and says so); re-arming it is refused while the timer is on,
/// and the next ask's knock carries no intro.
#[test]
fn turning_a_timer_on_drops_the_queued_intro() {
    let (mut a, _rx) = published(0xA1);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    let id = a
        .set_intro(&b.hex, "hello", std::time::Instant::now())
        .unwrap();
    assert!(a.intros.contains_key(&b.hex));
    // Off again (not applied: already off) keeps it.
    let off = a.change_timer(&b.hex, 0, now_ms()).unwrap();
    assert_eq!(off.intro_dropped, None);
    assert!(a.intros.contains_key(&b.hex));
    let out = a.change_timer(&b.hex, 300, now_ms()).unwrap();
    assert!(out.applied);
    assert_eq!(out.intro_dropped.as_deref(), Some(id.as_str()));
    assert!(!a.intros.contains_key(&b.hex), "the intro is gone");
    assert!(matches!(
        a.set_intro_with_id(&b.hex, "hello", Some([7; 16]), std::time::Instant::now()),
        Err(crate::RChatError::InvalidParameter { .. })
    ));
    // A later change (still on) has nothing more to drop.
    let again = a.change_timer(&b.hex, 3600, now_ms() + 10).unwrap();
    assert_eq!(again.intro_dropped, None);
}

/// M-2: the peer reports no prior session; the current state (here the
/// peer's own change) goes again with its time unchanged, B shows no
/// second system line, and A sees it acknowledged.
#[test]
fn a_peer_reset_resends_the_current_timer_state() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    // B set a day; A has it (acked: the peer's own change).
    p.b.change_timer(&p.pa.hex, 86400, now_ms()).unwrap();
    pump_pair(&mut p, 6);
    let before = p.a.timer_state(&p.pb.hex).unwrap();
    assert!(before.acked && !before.by_me);
    assert_eq!(rec_b.timers.lock().unwrap().len(), 1);
    // B's notice says it had no prior session.
    p.a.handle_notice(
        &p.pb.hex.clone(),
        crate::notice::Notice {
            flags: crate::notice::FLAG_NO_PRIOR_SESSION,
            reason: 0,
            ids: vec![],
            sig: None,
        },
        crate::session::DecryptedBy::Current,
        None,
    );
    let now = p.a.timer_state(&p.pb.hex).unwrap();
    assert!(!now.acked && now.resends == 0);
    assert_eq!(now.changed_at_ms, before.changed_at_ms, "time unchanged");
    pump_pair(&mut p, 6);
    assert_eq!(p.b.timer_secs(&p.pa.hex), 86400);
    assert_eq!(
        rec_b.timers.lock().unwrap().len(),
        1,
        "the same state again shows nothing new"
    );
    assert!(p.a.timer_state(&p.pb.hex).unwrap().acked);
}

/// M-3: a new connection resets the loss re-send budget.
#[test]
fn a_new_connection_resets_timer_resends() {
    let mut p = establish(0xA1, 0xB2);
    p.a.change_timer(&p.pb.hex, 300, now_ms()).unwrap();
    if let Some(t) = lock_timers(&p.a).get_mut(&p.pb.hex) {
        t.resends = MAX_TIMER_RESENDS;
    }
    p.a.after_publish_ok(std::time::Instant::now());
    assert_eq!(p.a.timer_state(&p.pb.hex).unwrap().resends, 0);
}

/// M-9: the relay's ack for a timer change never reaches the app; an
/// ordinary message's still does.
#[test]
fn relay_acks_for_timer_changes_stay_in_the_core() {
    let mut p = establish(0xA1, 0xB2);
    let rec_a = record(&mut p.a);
    p.a.change_timer(&p.pb.hex, 300, now_ms()).unwrap();
    p.a = process_pending_on(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    let timer_id = hex::encode(p.a.timer_state(&p.pb.hex).unwrap().out_id.unwrap());
    let text_id = [0x77u8; 16];
    p.a.send_tracked_for_test(&p.pb.hex, text_id, &[&[0x01][..], &[0; 4], b"x"].concat())
        .unwrap();
    for id in [timer_id.clone(), hex::encode(text_id)] {
        feed(
            &mut p.a,
            crate::protocol::Frame::Control(crate::protocol::ControlMessage::MessageAck {
                message_id: id,
                sender_identity: String::new(),
                recipient_identity: String::new(),
                timestamp: 0,
            }),
        );
    }
    assert_eq!(*rec_a.delivered.lock().unwrap(), vec![hex::encode(text_id)]);
}

/// M-2: a re-pin to new keys starts a session with no shared timer state,
/// so the current state is marked for re-sending (the install queues it).
#[test]
fn a_repin_marks_the_timer_for_resending() {
    let mut p = establish(0xA1, 0xB2);
    p.a.change_timer(&p.pb.hex, 3600, now_ms()).unwrap();
    pump_pair(&mut p, 6);
    assert!(p.a.timer_state(&p.pb.hex).unwrap().acked);
    let new_ak = hex::encode([0x42u8; 32]);
    p.a.apply_set_recipient(&p.pb.hex.clone(), Some(&new_ak))
        .unwrap();
    let t = p.a.timer_state(&p.pb.hex).unwrap();
    assert_eq!(t.secs, 3600, "kept with the contact");
    assert!(!t.acked && t.resends == 0, "goes again on the new session");
}

// ---------------------------------------------------------------------------
// Fix round 2
// ---------------------------------------------------------------------------

/// N-1: a change that used up its loss re-sends goes again at the next
/// connection.
#[test]
fn an_exhausted_change_is_sent_again_after_a_reconnect() {
    let mut p = establish(0xA1, 0xB2);
    let rec_b = record(&mut p.b);
    p.a.change_timer(&p.pb.hex, 300, now_ms()).unwrap();
    p.a = process_pending_on(std::mem::replace(
        &mut p.a,
        ClientInner::new(crate::ClientConfig::default()),
    ));
    drain(&mut p.a_rx); // lost
    relay_acked_all(&p.a);
    if let Some(t) = lock_timers(&p.a).get_mut(&p.pb.hex) {
        t.resends = MAX_TIMER_RESENDS;
    }
    assert!(!p
        .a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .pending_messages
        .iter()
        .any(|m| m.msg_type == crate::protocol::MessageType::Timer));
    p.a.after_publish_ok(std::time::Instant::now());
    drain(&mut p.a_rx);
    pump_pair(&mut p, 6);
    assert_eq!(
        p.b.timer_secs(&p.pa.hex),
        300,
        "sent again after the reconnect"
    );
    assert_eq!(rec_b.timers.lock().unwrap().len(), 1);
    assert!(p.a.timer_state(&p.pb.hex).unwrap().acked);
}

/// N-3: a re-pin deletes the peer record; the timer is written again at
/// once, so a restart before the new install keeps it (still owed).
#[test]
fn the_timer_survives_a_restart_after_a_repin() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    p.a.change_timer(&p.pb.hex, 3600, now_ms()).unwrap();
    pump_pair(&mut p, 6);
    let before = p.a.timer_state(&p.pb.hex).unwrap();
    assert!(before.acked);
    p.a.apply_set_recipient(&p.pb.hex.clone(), Some(&hex::encode([0x42u8; 32])))
        .unwrap();
    let (a, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    let after = a.timer_state(&p.pb.hex).expect("kept across the restart");
    assert_eq!(
        (after.secs, after.changed_at_ms),
        (3600, before.changed_at_ms)
    );
    assert!(!after.acked, "still owed to the session under the new pin");
}

/// Rotation re-send: the moved state is owed to the new identity and is
/// queued as soon as it has a session.
#[test]
fn a_rotation_moves_the_timer_and_owes_it_to_the_new_identity() {
    let mut p = establish(0xA1, 0xB2);
    p.a.change_timer(&p.pb.hex, 86400, now_ms()).unwrap();
    pump_pair(&mut p, 6);
    assert!(p.a.timer_state(&p.pb.hex).unwrap().acked);
    let new = peer(0xC3);
    assert!(p.a.apply_peer_rotation(&p.pb.hex.clone(), &new.bundle, 1));
    assert!(
        p.a.timer_state(&p.pb.hex).is_none(),
        "moved off the old identity"
    );
    let moved =
        p.a.timer_state(&new.hex)
            .expect("moved to the new identity");
    assert_eq!(moved.secs, 86400);
    assert!(
        !moved.acked && moved.resends == 0,
        "owed to the new identity"
    );
    // Queued once the new identity has a session (the install hook).
    p.a.session_manager.get_or_create(new.hex.clone());
    assert!(p.a.queue_timer_state(&new.hex));
    assert!(p
        .a
        .session_manager
        .get(&new.hex)
        .unwrap()
        .pending_messages
        .iter()
        .any(|m| m.msg_type == crate::protocol::MessageType::Timer));
}
