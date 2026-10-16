//! Background drain (protocol v3 §H.1, F.4a): the core side, run headless.

use super::*;
use crate::circuits::{now_hour, AskTrigger};
use crate::protocol::{ControlMessage, Frame, FRAME_TYPE_SIGNALING};
use crate::test_support::*;
use crate::{ConnectionStatus, RChatCallbacks, ReceivedMessage};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// The relay's `QueueHandedOver` marker (R34a).
fn handed_over() -> Frame {
    Frame::Control(ControlMessage::QueueHandedOver {
        pad: vec![0; crate::protocol::QUEUE_HANDED_OVER_PAD_LEN],
    })
}

/// A text from A to B that the relay queued while B was offline: the
/// sealed payloads a `QueuedMessage` carries, and the message id.
fn queued_text(p: &mut Pair, text: &str) -> (Vec<Vec<u8>>, [u8; 16]) {
    let id = push_text(&p.a, &p.pb.hex, text);
    let payloads = sent_relays(&mut p.a_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    (payloads, id)
}

/// B's next connection, as `reconnect_in_place` makes it: hello answered,
/// publish accepted (`after_publish_ok` runs). Drain mode first when `drain`.
fn reconnect_b(p: &mut Pair, drain_mode: bool) {
    if drain_mode {
        p.b.begin_drain(Instant::now());
    }
    reconnect_in_place(&mut p.b, &mut p.b_rx);
}

fn frame_types(frames: &[Vec<u8>]) -> Vec<u8> {
    frames.iter().filter_map(|f| f.first().copied()).collect()
}

fn asks_in(frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter_map(|f| ControlMessage::decode(f))
        .filter(|m| {
            matches!(
                m,
                ControlMessage::CircuitAsk { .. } | ControlMessage::CircuitAskBlind { .. }
            )
        })
        .count()
}

/// Everything the foreground does on a reconnect that would send: the
/// queued message and A's knock arrive, the app asks for the circuit, and
/// two minutes of ticks pass (re-asks, receipts, cover, notices).
fn run_reconnect(p: &mut Pair, payloads: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    for q in payloads {
        feed(&mut p.b, queued(q));
    }
    feed(&mut p.b, queued(knock_from(&p.pa, &p.pb, now_hour())));
    let _ = p.b.ask(&p.pa.hex.clone(), AskTrigger::User, Instant::now());
    for s in [1, 10, 60, 120] {
        p.b.tick(Instant::now() + Duration::from_secs(s));
    }
    drain(&mut p.b_rx)
}

#[test]
fn background_drain_makes_no_circuit_asks() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, _) = queued_text(&mut p, "queued while rChat was closed");
    reconnect_b(&mut p, true);
    let frames = run_reconnect(&mut p, payloads);
    // The message reached the app...
    assert_eq!(
        texts(&p.b_log),
        vec![b"queued while rChat was closed".to_vec()]
    );
    // ...and nothing but signaling left: no identity or blind ask, no
    // resume, no close, no receipt, no relay packet of any kind.
    assert_eq!(asks_in(&frames), 0, "no circuit ask in a drain");
    assert!(
        frame_types(&frames)
            .iter()
            .all(|t| *t == FRAME_TYPE_SIGNALING),
        "only signaling leaves a drain: {:?}",
        frame_types(&frames)
    );
    // Not even recorded as asked: the asks wait for the next foreground
    // publish instead of counting as sent and unanswered.
    assert!(p.b.unanswered_asks.is_empty(), "no ask recorded as sent");
    assert!(
        p.b.deferred_asks.contains(&p.pa.hex),
        "the app's ask waits for the next foreground publish"
    );
}

/// The control for the test above: the same reconnect in the foreground
/// does ask (and sends), so the drain's silence is the mode's doing.
#[test]
fn a_foreground_reconnect_asks_where_a_drain_does_not() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, _) = queued_text(&mut p, "queued while rChat was closed");
    reconnect_b(&mut p, false);
    let mut frames = drain(&mut p.b_rx);
    frames.extend(run_reconnect(&mut p, payloads));
    assert!(asks_in(&frames) > 0, "a foreground reconnect re-pairs");
}

#[test]
fn drain_mode_lets_only_signaling_leave() {
    let (mut inner, mut rx) = published(0xB2);
    inner.begin_drain(Instant::now());
    let close = ControlMessage::CloseCircuit {
        circuit_id: crate::protocol::CircuitId([7; 16]),
    };
    assert!(inner.send_control_now(close).is_err(), "control refused");
    assert!(
        inner.send_now(vec![0x02, 1, 2, 3]).is_err(),
        "relay refused"
    );
    let hello = crate::protocol::SignalingMessage::hello(vec![crate::protocol::PROTOCOL_VERSION]);
    assert!(inner.send_signaling_now(&hello).is_ok(), "signaling passes");
    assert_eq!(frame_types(&drain(&mut rx)), vec![FRAME_TYPE_SIGNALING]);
    // Cover and steady traffic never run in a drain, whatever the app set.
    inner.cover_enabled = true;
    inner.cover_foreground = true;
    inner.steady_enabled = true;
    inner.steady_foreground = true;
    assert!(!inner.steady_active(), "no steady slots in a drain");
}

#[test]
fn background_drain_queues_receipts_for_next_foreground() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, id) = queued_text(&mut p, "receipt later");
    reconnect_b(&mut p, true);
    for q in payloads {
        feed(&mut p.b, queued(q));
    }
    // The app stored it (D36): the receipt is owed, not sent.
    p.b.mark_seen_and_receipt(&p.pa.hex.clone(), id).unwrap();
    for s in [1, 5, 30] {
        p.b.tick(Instant::now() + Duration::from_secs(s));
    }
    assert!(
        sent_relays(&mut p.b_rx).is_empty(),
        "no receipt leaves a drain"
    );
    let (_, count) = p.b.end_drain();
    assert_eq!(count, 1);
    // Owed in B's stored record, so it survives the app being suspended
    // or killed after the drain.
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(
        rec.owed_receipts
            .contains(&(crate::receipts::DELIVERED, id)),
        "owed receipt persisted: {:?}",
        rec.owed_receipts
    );
    // The next foreground connection, from the store, re-pairs and sends it.
    let (mut b2, mut b2_rx, _) = restart_from(0xB2, 0xA1, &sb);
    drain(&mut p.a_rx);
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    // A's session-init (B is the responder), then whatever B owes.
    for _ in 0..3 {
        relay_all(&mut p.a_rx, &mut b2);
        b2.tick(Instant::now() + Duration::from_secs(5));
        relay_all(&mut b2_rx, &mut p.a);
    }
    let receipts: Vec<Ev> = p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Receipt(..)))
        .cloned()
        .collect();
    assert!(
        receipts.contains(&Ev::Receipt(
            p.pb.hex.clone(),
            hex::encode(id),
            crate::receipts::DELIVERED
        )),
        "the receipt reaches A at the next foreground connection: {receipts:?}"
    );
}

/// An app that stores each message on its own thread after `delay`, then
/// confirms it to the core, as the iOS app does (off the callback thread).
struct SlowApp {
    client: Arc<OnceLock<Weak<RChatClient>>>,
    stored: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<u32>>,
    delay: Duration,
}

impl RChatCallbacks for SlowApp {
    fn on_connection_status_changed(&self, _: ConnectionStatus) {}
    fn on_message_received(&self, m: ReceivedMessage) {
        let (client, stored, delay) = (self.client.clone(), self.stored.clone(), self.delay);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            stored.lock().unwrap().push(m.id.clone());
            if let Some(c) = client.get().and_then(Weak::upgrade) {
                c.mark_message_seen(m.sender_identity, m.id).unwrap();
            }
        });
    }
    fn on_message_request(&self, _: crate::MessageRequest) {
        *self.requests.lock().unwrap() += 1;
    }
    fn on_message_delivered(&self, _: String) {}
    fn on_error(&self, _: String) {}
    fn on_circuit_established(&self, _: String, _: bool) {}
}

/// B in drain mode, published, behind a real client with `SlowApp`.
fn drained_client(
    p: &mut Pair,
    quiet: Duration,
    delay: Duration,
) -> (Arc<RChatClient>, Arc<Mutex<Vec<String>>>, Arc<Mutex<u32>>) {
    reconnect_b(p, true);
    let mut b = std::mem::replace(&mut p.b, published(0xEE).0);
    let d = b.drain.as_mut().unwrap();
    d.quiet = quiet;
    d.grace = quiet;
    d.marker_wait = Duration::from_secs(30);
    b.callbacks = None;
    let client = wrap(b);
    let (stored, requests) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(0)));
    let slot = Arc::new(OnceLock::new());
    slot.set(Arc::downgrade(&client)).unwrap();
    client.set_callbacks(Box::new(SlowApp {
        client: slot,
        stored: stored.clone(),
        requests: requests.clone(),
        delay,
    }));
    (client, stored, requests)
}

/// The relay hands `frames` over after `after`, as a socket would.
fn deliver_later(client: &Arc<RChatClient>, frames: Vec<Frame>, after: Duration) {
    let client = client.clone();
    std::thread::spawn(move || {
        std::thread::sleep(after);
        for f in frames {
            let inner = client.inner.clone();
            let _ = crate::block_on_async(client.runtime.clone(), move || async move {
                RChatClient::handle_frame(&mut *inner.write().await, f);
                Ok(())
            });
        }
    });
}

#[test]
fn background_drain_stores_before_returning() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, id) = queued_text(&mut p, "stored before the drain returns");
    let stranger = peer(0x5C);
    let knock = knock_from(&stranger, &p.pb, now_hour());
    // The app takes longer to store than the quiet window lasts.
    let (client, stored, requests) = drained_client(
        &mut p,
        Duration::from_millis(100),
        Duration::from_millis(600),
    );
    let mut frames: Vec<Frame> = payloads.into_iter().map(queued).collect();
    frames.push(queued(knock));
    frames.push(handed_over());
    deliver_later(&client, frames, Duration::from_millis(50));
    let started = Instant::now();
    let n = client
        .finish_drain(started + Duration::from_secs(10), &|| false)
        .unwrap();
    assert_eq!(n, 2, "one message and one request handed over");
    assert_eq!(
        *stored.lock().unwrap(),
        vec![hex::encode(id)],
        "the app stored it before the drain returned"
    );
    assert_eq!(*requests.lock().unwrap(), 1, "the request reached the app");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "ended on its own"
    );
    // The transport is gone and drain mode with it; the client stays.
    let (drain_on, ws) = client.query((true, true), |i| (i.drain.is_some(), i.websocket.is_some()));
    assert!(!drain_on && !ws);
    assert!(sent_relays(&mut p.b_rx).is_empty());
}

#[test]
fn a_cancelled_drain_ends_at_once_keeping_what_was_stored() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, _) = queued_text(&mut p, "never confirmed");
    // The app never gets to store it within the test.
    let (client, _, _) =
        drained_client(&mut p, Duration::from_millis(100), Duration::from_secs(60));
    deliver_later(
        &client,
        payloads.into_iter().map(queued).collect(),
        Duration::from_millis(20),
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let c2 = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        c2.store(true, Ordering::SeqCst);
    });
    let started = Instant::now();
    let n = client
        .finish_drain(started + Duration::from_secs(20), &|| {
            cancel.load(Ordering::SeqCst)
        })
        .unwrap();
    assert_eq!(n, 1);
    assert!(started.elapsed() < Duration::from_secs(3), "cancel ends it");
    assert!(!client.query(true, |i| i.drain.is_some()));
}

#[test]
fn a_drain_that_never_publishes_times_out_with_an_error() {
    let (mut inner, _rx) = inner_with_identity(0xB2);
    inner.is_connected = false;
    inner.bypass_frame_gate = false;
    inner.begin_drain(Instant::now());
    let client = wrap(inner);
    let started = Instant::now();
    let r = client.finish_drain(started + Duration::from_millis(200), &|| false);
    assert!(
        matches!(r, Err(RChatError::ConnectionFailed { .. })),
        "{r:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!client.query(true, |i| i.drain.is_some()));
}

#[test]
fn background_drain_is_refused_while_connected() {
    let (inner, mut rx) = published(0xB2);
    assert!(inner.is_connected);
    let client = wrap(inner);
    let r = client.background_drain(Duration::from_secs(5), &AtomicBool::new(false));
    assert!(matches!(r, Err(RChatError::ForegroundConnected)), "{r:?}");
    // Untouched: still connected, no drain mode, nothing sent.
    let (connected, drain_on) =
        client.query((false, true), |i| (i.is_connected, i.drain.is_some()));
    assert!(connected && !drain_on);
    assert!(drain(&mut rx).is_empty());
}

#[test]
fn a_relay_refusal_ends_the_drain_with_its_error() {
    let (mut inner, _rx) = inner_with_identity(0xB2);
    inner.is_connected = false;
    inner.begin_drain(Instant::now());
    inner.fail_protocol(RChatError::RelayIdentityChanged);
    assert!(matches!(
        inner.drain_progress(Instant::now()),
        DrainProgress::Failed(_)
    ));
}

#[test]
fn the_drain_ends_at_the_marker_and_the_app() {
    let (mut inner, _rx) = published(0xB2);
    let t0 = Instant::now();
    inner.begin_drain(t0);
    let at = |inner: &ClientInner, ms: u64| {
        inner.drain_progress_at(t0 + Duration::from_millis(ms), None)
    };
    assert_eq!(at(&inner, 60_000), DrainProgress::Waiting, "not published");
    // A marker before the publish means nothing.
    inner.drain_note_handed_over(t0);
    inner.drain_note_published(t0);
    assert_eq!(at(&inner, 1_000), DrainProgress::Waiting, "no marker yet");
    inner.drain_note_handed_over(t0 + Duration::from_millis(100));
    assert_eq!(at(&inner, 200), DrainProgress::Waiting, "inside the grace");
    inner.drain_note_delivered("AB", [1; 16]);
    assert_eq!(at(&inner, 2_000), DrainProgress::Waiting, "not stored yet");
    inner.drain_note_stored("ab", [1; 16]);
    assert_eq!(at(&inner, 2_000), DrainProgress::Complete(1));
}

/// R34a: without a marker the fallback counts bytes, not frames. A large
/// frame still arriving (bytes, no complete frame) keeps the drain open.
#[test]
fn a_stalled_frame_still_receiving_bytes_keeps_the_drain_open() {
    let (mut inner, _rx) = published(0xB2);
    let t0 = Instant::now();
    inner.begin_drain(t0);
    inner.drain_note_published(t0);
    let late = t0 + DRAIN_MARKER_WAIT + DRAIN_QUIET * 3;
    // No frame since the publish, but bytes kept arriving until just now.
    assert_eq!(
        inner.drain_progress_at(late, Some(late - Duration::from_millis(100))),
        DrainProgress::Waiting,
        "bytes are still arriving"
    );
    // The bytes stopped for the quiet window: the fallback ends it.
    assert_eq!(
        inner.drain_progress_at(late, Some(late - DRAIN_QUIET)),
        DrainProgress::Complete(0)
    );
    // Before the marker wait, never, however quiet.
    assert_eq!(
        inner.drain_progress_at(t0 + DRAIN_MARKER_WAIT / 2, None),
        DrainProgress::Waiting
    );
    // After the marker, bytes still arriving hold it within the grace.
    inner.drain_note_handed_over(t0);
    let soon = t0 + Duration::from_secs(1);
    assert_eq!(
        inner.drain_progress_at(soon, Some(soon - Duration::from_millis(50))),
        DrainProgress::Waiting
    );
}

/// R34a by construction: the marker is one more frame on the same ordered
/// event queue, so every queued frame the relay wrote before it has been
/// handled (and handed to the app) by the time it counts. Here the queued
/// message and the marker arrive together; the drain counts the message.
#[test]
fn every_frame_before_the_marker_is_handled_first() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (payloads, _) = queued_text(&mut p, "before the marker");
    reconnect_b(&mut p, true);
    for q in payloads {
        feed(&mut p.b, queued(q));
    }
    feed(&mut p.b, handed_over());
    let d = p.b.drain.as_ref().unwrap();
    assert_eq!(d.delivered, 1, "handled before the marker counted");
    assert!(d.handed_over_at.is_some());
}

/// The marker outside a drain (the foreground) changes nothing.
#[test]
fn the_foreground_ignores_the_marker() {
    let (mut inner, mut rx) = published(0xB2);
    feed(&mut inner, handed_over());
    assert!(inner.drain.is_none());
    assert!(drain(&mut rx).is_empty(), "nothing sent in answer");
}

/// The marker has one fixed size and carries nothing.
#[test]
fn the_marker_is_fixed_and_empty() {
    let frame = crate::protocol::ControlMessage::QueueHandedOver {
        pad: vec![0; crate::protocol::QUEUE_HANDED_OVER_PAD_LEN],
    };
    let bytes = frame.encode();
    assert_eq!(bytes[..4], 18u32.to_le_bytes());
    assert_eq!(
        bytes.len(),
        4 + 8 + crate::protocol::QUEUE_HANDED_OVER_PAD_LEN
    );
    assert!(bytes[12..].iter().all(|b| *b == 0));
}

/// Each layer on its own (mutation-checked): the publish in a drain
/// re-pairs nothing. A known contact's stale identity circuit is neither
/// closed nor detached, and nothing is queued to close later.
#[test]
fn a_drain_publish_leaves_every_pair_as_it_was() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let before =
        p.b.session_manager
            .get(&p.pa.hex)
            .and_then(|s| s.circuit_id.clone());
    assert!(before.is_some(), "precondition: a circuit from before");
    reconnect_b(&mut p, true);
    let after =
        p.b.session_manager
            .get(&p.pa.hex)
            .and_then(|s| s.circuit_id.clone());
    assert_eq!(after, before, "not detached by a re-pair");
    assert!(p.b.pending_closes.is_empty(), "no close queued");
    assert!(p.b.unanswered_asks.is_empty());
}

#[test]
fn no_ask_of_any_kind_is_built_in_a_drain() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    reconnect_b(&mut p, true);
    drain(&mut p.b_rx); // its hello and publish
    let peer = p.pa.hex.clone();
    let now = Instant::now();
    assert!(
        p.b.send_ask(&peer, now).is_err(),
        "identity or blind: refused"
    );
    assert!(
        p.b.send_blind_plan(&peer, now, crate::blind::BlindPlan::Own)
            .is_err(),
        "a blind plan: refused"
    );
    assert!(p.b.unanswered_asks.is_empty(), "nothing recorded as asked");
    assert!(
        p.b.blind_asks.get(&peer).is_none_or(|v| v.is_empty()),
        "no blind ask held"
    );
    assert!(drain(&mut p.b_rx).is_empty());
}

/// The timer does nothing that would send: a re-ask a contact's knock
/// scheduled stays scheduled for the next foreground connection.
#[test]
fn the_timer_consumes_nothing_in_a_drain() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    reconnect_b(&mut p, true);
    drain(&mut p.b_rx); // its hello and publish
    let peer = p.pa.hex.clone();
    p.b.pending_reasks.insert(peer.clone(), Instant::now());
    p.b.tick(Instant::now() + Duration::from_secs(60));
    assert!(
        p.b.pending_reasks.contains_key(&peer),
        "the re-ask waits for the foreground"
    );
    assert!(drain(&mut p.b_rx).is_empty());
}

/// A timer change (0x09) received in a drain is acknowledged end to end
/// only later: its receipt is owed and written by the end of the drain.
#[test]
fn a_timer_change_receipt_is_owed_and_persisted_by_the_end_of_the_drain() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id: [u8; 16] = rand::random();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let pt = crate::disappearing::encode_timer(300, now_ms);
    let packet = p.a.seal_ratchet(&p.pb.hex, id, &pt).unwrap();
    reconnect_b(&mut p, true);
    feed(&mut p.b, queued(packet.payload));
    assert!(sent_relays(&mut p.b_rx).is_empty(), "no receipt leaves");
    p.b.end_drain();
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(
        rec.owed_receipts
            .contains(&(crate::receipts::DELIVERED, id)),
        "owed and written: {:?}",
        rec.owed_receipts
    );
}

/// No cover traffic either way: a contact's cover request (queued) is not
/// answered later from the drain's budget.
#[test]
fn a_cover_request_is_not_answered_from_a_drain() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id: [u8; 16] = rand::random();
    let pt = [crate::circuits::COVER_TYPE, crate::circuits::COVER_REQUEST];
    let packet = p.a.seal_ratchet(&p.pb.hex, id, &pt).unwrap();
    reconnect_b(&mut p, true);
    feed(&mut p.b, queued(packet.payload));
    assert!(p.b.cover_replies_due.is_empty(), "no cover reply scheduled");
}

/// The app's periodic `process_pending` sends nothing in a drain either.
#[test]
fn process_pending_consumes_nothing_in_a_drain() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    reconnect_b(&mut p, true);
    let peer = p.pa.hex.clone();
    let mut b = std::mem::replace(&mut p.b, published(0xEE).0);
    b.pending_reasks.insert(peer.clone(), Instant::now());
    let client = wrap(b);
    std::thread::sleep(Duration::from_millis(10));
    client.process_pending().unwrap();
    assert!(client.query(false, move |i| i.pending_reasks.contains_key(&peer)));
}

/// R34 M-4: the ask guards on their own. An unpinned peer is refused as
/// "not connected" (the drain's refusal) before any other check, and a
/// neighbour blind plan for a paused peer is refused, not a silent Ok.
#[test]
fn the_ask_guards_refuse_first_and_touch_nothing() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    reconnect_b(&mut p, true);
    drain(&mut p.b_rx);
    let stranger = peer(0x5D).hex;
    let now = Instant::now();
    assert!(matches!(
        p.b.send_ask(&stranger, now),
        Err(RChatError::NotConnected)
    ));
    let contact = p.pa.hex.clone();
    p.b.blind_paused.insert(contact.clone());
    assert!(matches!(
        p.b.send_blind_plan(
            &contact,
            now,
            crate::blind::BlindPlan::Neighbour(crate::pairing::PairEpoch { day: 1, counter: 0 })
        ),
        Err(RChatError::NotConnected)
    ));
    assert!(p.b.blind_asks.get(&contact).is_none_or(|v| v.is_empty()));
    assert!(
        p.b.blind_neighbour_tried.is_empty(),
        "no neighbour retry recorded"
    );
    assert!(p.b.rotation_knocks.is_empty(), "no rotation quota charged");
    assert!(drain(&mut p.b_rx).is_empty());
}

/// Round 2 N-1: a connect that takes the client lock only after its drain
/// attempt was given up refuses. It never becomes a normal connection
/// (30 s x 5 attempts, auto-reconnect, a publish on a client nobody holds).
#[test]
fn a_connect_given_up_before_it_takes_the_lock_never_becomes_a_normal_one() {
    // A relay address that accepts TCP and never answers the WebSocket
    // handshake: a normal connect would sit "connecting" for its timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = crate::ClientConfig {
        server_url: format!("ws://127.0.0.1:{port}"),
        dev_origin: Some(format!("ws://127.0.0.1:{port}")),
        connection_timeout_secs: 30,
        reconnect_max_attempts: 5,
        ..crate::ClientConfig::default()
    };
    let client = RChatClient::new(config).unwrap();
    client.generate_identity_from_seed(&[9; 32]).unwrap();
    *client.pre_lock_delay_for_test.lock().unwrap() = Duration::from_millis(400);
    let started = Instant::now();
    let end = client.drain_connecting(started + Duration::from_secs(20), &|| {
        started.elapsed() > Duration::from_millis(50)
    });
    assert!(matches!(end, DrainEnd::GaveUp(_)), "{end:?}");
    // The late connect has taken the lock by now.
    std::thread::sleep(Duration::from_millis(800));
    let (connecting, drain_on, ws) = client.query((true, true, true), |i| {
        (i.connecting, i.drain.is_some(), i.websocket.is_some())
    });
    assert!(
        !connecting,
        "the late connect refused instead of connecting"
    );
    assert!(!drain_on, "and cleared the given-up drain");
    assert!(!ws, "no transport");
    drop(listener);
}

/// Round 2 N-1: a retired client never connects again.
#[test]
fn a_retired_client_refuses_to_connect() {
    let client = RChatClient::new(crate::ClientConfig::default()).unwrap();
    client.retire();
    let started = Instant::now();
    assert!(
        matches!(
            client.connect(),
            Err(RChatError::ConnectionFailed { ref message }) if message == "client retired"
        ),
        "refused before any network"
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}

/// Final review L5 (defence in depth): in a drain the transport is never
/// usable for sends, and a direct send of a message is refused before it
/// is sealed (no ratchet step, nothing tracked, nothing on the wire),
/// although its frame would bypass `send_now`'s gate.
#[test]
fn a_drain_seals_and_sends_no_message() {
    let mut p = establish(0xA1, 0xB2);
    p.b.begin_drain(Instant::now());
    assert!(!p.b.transport_usable());
    drain(&mut p.b_rx);
    let peer = p.pa.hex.clone();
    let b = std::mem::replace(&mut p.b, published(0xEE).0);
    let inner = Arc::new(tokio::sync::RwLock::new(b));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let id = [0x4D; 16];
    let r = rt.block_on(crate::RChatClient::send_queued_message(
        inner.clone(),
        peer,
        b"hello",
        crate::protocol::MessageType::Text,
        id,
        true,
        false,
    ));
    assert!(matches!(r, Err(RChatError::NotConnected)), "{r:?}");
    let guard = inner.try_read().unwrap();
    assert!(guard
        .acks
        .lock()
        .unwrap()
        .attempts(&hex::encode(id))
        .is_none());
    drop(guard);
    assert!(drain(&mut p.b_rx).is_empty());
}
