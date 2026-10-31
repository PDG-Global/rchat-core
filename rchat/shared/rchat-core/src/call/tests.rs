//! Spec §3, §4, §9 (core): ringing, answer, connect, end; the offer-age
//! rule; glare; 15 s unreachable; 45 s no answer; 20 s connect and
//! reconnect limits; busy; unknown call ids; no receipts; calls off; the
//! queue handover (D11); the ring settle and late Offers (D13); the
//! held-offer cap (D11); failed after Answer (D16); the audio handle (D37).
//! On the `Pair` fixture: real ratchet sessions, fake media.

use super::engine::{AudioLink, ControlSink, MediaStart, MediaStatus};
use super::machine::{
    Availability, CallEvent, CallResult, Direction, LateOffer, MediaControl, MediaStarter, Phase,
    VideoState, RING_SETTLE,
};
use super::signal::{CallSignal, EndReason};
use super::video::engine::{EncoderHint, TakenFrame, VideoControl, VideoStart, VideoStatus};
use super::video::frag::TooSmall;
use super::video::health::Banner;
use super::video::signal::VideoSignal;
use super::video::VideoCodec;
use super::*;
use crate::protocol::{ControlMessage, Frame, RelayPacket, FRAME_TYPE_CONTROL, FRAME_TYPE_RELAY};
use crate::test_support::{drain, establish, feed, Pair};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Default)]
struct FakeMedia {
    status: Mutex<MediaStatus>,
    stopped: AtomicBool,
    muted: AtomicBool,
}

impl MediaControl for FakeMedia {
    fn push_pcm(&self, _: &[i16]) -> usize {
        FRAME_SAMPLES
    }
    fn pull_pcm(&self, out: &mut [i16]) -> usize {
        out.fill(0);
        FRAME_SAMPLES
    }
    fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::SeqCst)
    }
    fn status(&self, _: Instant) -> MediaStatus {
        *self.status.lock()
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst)
    }
    fn audio_link(self: Arc<Self>) -> Option<Arc<dyn AudioLink>> {
        Some(Arc::new(FakeAudio))
    }
}

/// The audio engine's link for video, doing nothing.
struct FakeAudio;

impl AudioLink for FakeAudio {
    fn send_control(&self, _: &[u8]) {}
    fn set_control_sink(&self, _: Option<Weak<dyn ControlSink>>) {}
    fn audio_depth_ms(&self) -> u64 {
        0
    }
    fn audio_lanes_dropped(&self) -> u64 {
        0
    }
    fn audio_poor(&self) -> bool {
        false
    }
    fn audio_concealed_pct(&self) -> u8 {
        0
    }
}

fn quiet_status() -> VideoStatus {
    VideoStatus {
        banner: Banner::None,
        paused_in: false,
        paused_out: false,
        rung: None,
        first_frame: false,
        refused: false,
    }
}

/// Fake video media: records what it was started with and the flags the
/// machine sets.
struct FakeVideo {
    role: u8,
    token: [u8; 32],
    codec: VideoCodec,
    sending: AtomicBool,
    receiving: AtomicBool,
    stopped: AtomicBool,
    status: Mutex<VideoStatus>,
}

impl VideoControl for FakeVideo {
    fn send_frame(&self, _: &[u8], _: bool, _: u16, _: Instant) -> i32 {
        i32::from(self.sending.load(Ordering::SeqCst))
    }
    fn take(&self, _: &mut [u8], _: Instant) -> Result<Option<TakenFrame>, TooSmall> {
        Ok(None)
    }
    fn need_keyframe(&self, _: Instant) {}
    fn encoder_hint(&self) -> EncoderHint {
        EncoderHint {
            generation: 0,
            width: 0,
            height: 0,
            fps: 0,
            bitrate: 0,
            keyframe: false,
            active: self.sending.load(Ordering::SeqCst),
        }
    }
    fn set_sending(&self, on: bool) {
        self.sending.store(on, Ordering::SeqCst)
    }
    fn set_receiving(&self, on: bool) {
        self.receiving.store(on, Ordering::SeqCst)
    }
    fn set_thermal(&self, _: u8) {}
    fn status(&self, _: Instant) -> VideoStatus {
        *self.status.lock()
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst)
    }
}

#[derive(Default)]
struct FakeStarter {
    started: Mutex<Vec<(u8, [u8; 32])>>,
    media: Mutex<Vec<Arc<FakeMedia>>>,
    /// As `CallMedia::start` failing (no runtime, no codec).
    cannot_start: AtomicBool,
    video: Mutex<Vec<Arc<FakeVideo>>>,
    /// As `VideoMedia::start` failing.
    cannot_start_video: AtomicBool,
}

impl MediaStarter for FakeStarter {
    fn start(&self, s: MediaStart) -> Option<Arc<dyn MediaControl>> {
        if self.cannot_start.load(Ordering::SeqCst) {
            return None;
        }
        self.started.lock().push((s.role, *s.keys.relay_token));
        let m = Arc::new(FakeMedia::default());
        self.media.lock().push(m.clone());
        Some(m)
    }
    fn start_video(&self, s: VideoStart) -> Option<Arc<dyn VideoControl>> {
        if self.cannot_start_video.load(Ordering::SeqCst) {
            return None;
        }
        let v = Arc::new(FakeVideo {
            role: s.role,
            token: *s.relay_token,
            codec: s.codec,
            sending: AtomicBool::new(false),
            receiving: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            status: Mutex::new(quiet_status()),
        });
        self.video.lock().push(v.clone());
        Some(v)
    }
}

struct Calls {
    p: Pair,
    a_media: Arc<FakeStarter>,
    b_media: Arc<FakeStarter>,
    t0: Instant,
    ms0: u64,
}

fn calls() -> Calls {
    let mut p = establish(1, 2);
    let (a_media, b_media) = (
        Arc::new(FakeStarter::default()),
        Arc::new(FakeStarter::default()),
    );
    for (inner, starter) in [(&mut p.a, a_media.clone()), (&mut p.b, b_media.clone())] {
        inner.config.calls_enabled = true;
        inner.relay_calls = true;
        inner.call.starter = starter;
        feed(
            inner,
            Frame::Control(ControlMessage::QueueHandedOver { pad: vec![0; 32] }),
        );
    }
    Calls {
        p,
        a_media,
        b_media,
        t0: Instant::now(),
        ms0: unix_ms(),
    }
}

/// Hand `from`'s relay packets to `to`; return `from`'s control frames.
fn pump(
    from_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    to: &mut crate::ClientInner,
) -> Vec<ControlMessage> {
    let mut controls = Vec::new();
    for f in drain(from_rx) {
        match f.first() {
            Some(&FRAME_TYPE_RELAY) => {
                if let Some(p) = RelayPacket::decode(&f) {
                    feed(to, Frame::Relay(p));
                }
            }
            Some(&FRAME_TYPE_CONTROL) => controls.extend(ControlMessage::decode(&f)),
            _ => {}
        }
    }
    controls
}

fn events(inner: &crate::ClientInner) -> Vec<CallEvent> {
    inner.call.events.lock().drain(..).collect()
}

fn ended(evs: &[CallEvent]) -> Option<(CallResult, Direction, u64)> {
    evs.iter().find_map(|e| match e {
        CallEvent::Ended {
            result,
            direction,
            duration_secs,
            ..
        } => Some((*result, *direction, *duration_secs)),
        _ => None,
    })
}

fn grants(controls: &[ControlMessage]) -> Vec<[u8; 32]> {
    controls
        .iter()
        .filter_map(|c| match c {
            ControlMessage::MediaGrant { token, .. } => Some(*token),
            _ => None,
        })
        .collect()
}

/// Seal any call signal from `from` to `to_hex` (for hand-made Offers).
fn send(from: &crate::ClientInner, to_hex: &str, sig: &CallSignal) {
    let packet = from
        .seal_ratchet(to_hex, rand::random(), &sig.encode())
        .unwrap();
    from.send_now(packet.encode_with_frame_type()).unwrap();
}

/// Let an incoming Offer settle (D13): it rings at the first tick
/// `RING_SETTLE` after it arrived. Returns the tick's time.
fn ring(inner: &mut crate::ClientInner) -> Instant {
    let at = Instant::now() + RING_SETTLE;
    inner.call_tick(at, unix_ms() + RING_SETTLE.as_millis() as u64);
    at
}

/// No delivery receipt is queued or due on `inner` (spec §4).
fn no_receipt(inner: &crate::ClientInner) -> bool {
    inner.pending_receipts.is_empty() && inner.receipt_due.is_empty()
}

#[test]
fn a_call_rings_is_answered_connects_and_ends() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    assert!(matches!(events(&c.p.a)[..], [CallEvent::Outgoing { .. }]));
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(
        events(&c.p.b).is_empty(),
        "nothing rings before RING_SETTLE (D13)"
    );
    assert!(
        drain(&mut c.p.b_rx).is_empty(),
        "no Ringing before RING_SETTLE"
    );
    ring(&mut c.p.b);
    assert!(
        matches!(&events(&c.p.b)[..], [CallEvent::Incoming { call_id, peer, .. }] if *call_id == id && *peer == a_hex)
    );
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(matches!(events(&c.p.a)[..], [CallEvent::Ringing { .. }]));
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    let b_controls = pump(&mut c.p.b_rx, &mut c.p.a);
    let a_controls = drain(&mut c.p.a_rx)
        .iter()
        .filter_map(|f| ControlMessage::decode(f))
        .collect::<Vec<_>>();
    // Both members granted the same token, the HKDF relay token; media started as caller (0) and callee (1).
    let token = grants(&b_controls)[0];
    assert_eq!(grants(&a_controls), vec![token]);
    assert_eq!(c.a_media.started.lock()[0], (0, token));
    assert_eq!(c.b_media.started.lock()[0], (1, token));
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Connecting { .. })));
    // First media frame: connected.
    for s in [&c.a_media, &c.b_media] {
        s.media.lock()[0].status.lock().first_frame = true;
    }
    c.p.a.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    c.p.b.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Connected { .. })));
    events(&c.p.b);
    // 4:12 later A hangs up.
    let later = c.t0 + Duration::from_secs(1 + 252);
    c.p.a.call_end(id, later, c.ms0 + 253_000).unwrap();
    assert_eq!(
        ended(&events(&c.p.a)),
        Some((CallResult::Completed, Direction::Outgoing, 252))
    );
    assert!(c.a_media.media.lock()[0].stopped.load(Ordering::SeqCst));
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(matches!(
        ended(&events(&c.p.b)),
        Some((CallResult::Completed, Direction::Incoming, _))
    ));
    assert!(c.p.b.call.active.is_none() && c.p.a.call.active.is_none());
}

#[test]
fn call_signals_get_no_delivery_receipt() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    assert!(
        no_receipt(&c.p.b),
        "no receipt queued or due for an Offer (spec §4)"
    );
    pump(&mut c.p.b_rx, &mut c.p.a); // the Ringing
    assert!(
        no_receipt(&c.p.a),
        "no receipt queued or due for a Ringing (spec §4)"
    );
}

#[test]
fn an_offer_more_than_60_s_old_never_rings_and_is_missed() {
    let mut c = calls();
    let a_hex = c.p.pa.hex.clone();
    let b_hex = c.p.pb.hex.clone();
    let old = CallSignal::Offer {
        call_id: CallId([7; 16]),
        caller_rand: Zeroizing::new([1; 32]),
        sent_at_ms: c.ms0 - 61_000,
    };
    send(&c.p.a, &b_hex, &old);
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert!(!evs.iter().any(|e| matches!(e, CallEvent::Incoming { .. })));
    assert!(
        matches!(&evs[..], [CallEvent::Ended { result: CallResult::Missed, direction: Direction::Incoming, peer, .. }] if *peer == a_hex)
    );
    assert!(
        drain(&mut c.p.b_rx).is_empty(),
        "no Ringing for a stale Offer"
    );
}

/// Review Focus 3, D12.
#[test]
fn an_offer_dated_far_ahead_is_missed() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let future = CallSignal::Offer {
        call_id: CallId([8; 16]),
        caller_rand: Zeroizing::new([1; 32]),
        sent_at_ms: c.ms0 + 3_600_000,
    };
    send(&c.p.a, &b_hex, &future);
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Missed)
    );
    assert!(c.p.b.call.active.is_none());
}

#[test]
fn glare_connects_the_lower_call_id_at_once_on_both_phones() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.a.call.next_call_id = Some(CallId([1; 16]));
    c.p.b.call.next_call_id = Some(CallId([2; 16]));
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    c.p.b.call_place(&a_hex, c.t0, c.ms0).unwrap();
    events(&c.p.a);
    events(&c.p.b);
    // Both Offers cross on the wire.
    let a_out = drain(&mut c.p.a_rx);
    let b_out = drain(&mut c.p.b_rx);
    for f in b_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.a, Frame::Relay(p));
        }
    }
    for f in a_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.b, Frame::Relay(p));
        }
    }
    // B's own (higher) call is dropped silently; B answers A's at once, no ringing anywhere.
    let b_evs = events(&c.p.b);
    assert!(
        matches!(&b_evs[..], [CallEvent::Connecting { call_id, replaced: Some(r), .. }] if *call_id == CallId([1; 16]) && *r == CallId([2; 16]))
    );
    assert!(events(&c.p.a).is_empty(), "A ignores B's higher Offer");
    pump(&mut c.p.b_rx, &mut c.p.a);
    let a_evs = events(&c.p.a);
    assert!(a_evs.iter().any(
        |e| matches!(e, CallEvent::Connecting { call_id, .. } if *call_id == CallId([1; 16]))
    ));
    assert!(!a_evs
        .iter()
        .chain(b_evs.iter())
        .any(|e| matches!(e, CallEvent::Ringing { .. } | CallEvent::Incoming { .. })));
}

/// Final review I2 (Task 9 minor): glare where the switch to the peer's
/// lower call fails (no media). The app still holds its own call, so the
/// Ended carries that id; the peer is told End for the call it waits on.
#[test]
fn a_failed_glare_switch_ends_the_apps_own_call_and_tells_the_peer() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.a.call.next_call_id = Some(CallId([1; 16]));
    c.p.b.call.next_call_id = Some(CallId([2; 16]));
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    c.p.b.call_place(&a_hex, c.t0, c.ms0).unwrap();
    events(&c.p.a);
    events(&c.p.b);
    c.b_media.cannot_start.store(true, Ordering::SeqCst);
    let a_out = drain(&mut c.p.a_rx);
    let b_out = drain(&mut c.p.b_rx);
    for f in b_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.a, Frame::Relay(p));
        }
    }
    for f in a_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.b, Frame::Relay(p));
        }
    }
    let b_evs = events(&c.p.b);
    assert!(
        matches!(
            &b_evs[..],
            [CallEvent::Ended { call_id, direction: Direction::Outgoing, result: CallResult::Failed, .. }]
                if *call_id == CallId([2; 16])
        ),
        "the app's own call ends"
    );
    assert!(c.p.b.call.active.is_none());
    pump(&mut c.p.b_rx, &mut c.p.a);
    let a_evs = events(&c.p.a);
    assert!(
        a_evs
            .iter()
            .any(|e| matches!(e, CallEvent::Ended { call_id, .. } if *call_id == CallId([1; 16]))),
        "the peer's call ends too: {a_evs:?}"
    );
    assert!(c.p.a.call.active.is_none());
}

#[test]
fn no_ringing_within_15_s_is_unreachable() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    events(&c.p.a);
    assert_eq!(
        drain(&mut c.p.a_rx).len(),
        2,
        "the Offer and its Caps went (B never answers it)"
    );
    c.p.a
        .call_tick(c.t0 + Duration::from_millis(14_900), c.ms0 + 14_900);
    assert!(events(&c.p.a).is_empty());
    c.p.a.call_tick(c.t0 + UNREACHABLE_AFTER, c.ms0 + 15_000);
    assert_eq!(
        ended(&events(&c.p.a)),
        Some((CallResult::Unreachable, Direction::Outgoing, 0))
    );
    assert_eq!(
        drain(&mut c.p.a_rx).len(),
        1,
        "End(unreachable) follows the Offer"
    );
}

/// Review Focus 2, D11: an Offer and its End both waiting in the offline
/// queue give a missed call and never ring.
#[test]
fn a_queued_offer_followed_by_its_end_is_missed_without_ringing() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.b.call.handed_over = false; // B's fresh connection: the queue is being handed over
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    c.p.a.call_tick(c.t0 + UNREACHABLE_AFTER, c.ms0 + 15_000);
    pump(&mut c.p.a_rx, &mut c.p.b); // Offer, then End(unreachable)
    assert!(events(&c.p.b).is_empty(), "held until the handover");
    assert!(drain(&mut c.p.b_rx).is_empty(), "no Ringing while held");
    c.p.b
        .call_on_queue_handed_over(c.t0 + Duration::from_secs(16), c.ms0 + 16_000);
    let evs = events(&c.p.b);
    assert!(!evs.iter().any(|e| matches!(e, CallEvent::Incoming { .. })));
    assert_eq!(ended(&evs).map(|e| e.0), Some(CallResult::Missed));
    assert!(
        drain(&mut c.p.b_rx).is_empty(),
        "no Ringing for an ended call"
    );
}

#[test]
fn a_held_offer_still_fresh_rings_at_the_handover() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.b.call.handed_over = false;
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(events(&c.p.b).is_empty());
    c.p.b.call_on_queue_handed_over(Instant::now(), unix_ms());
    assert!(events(&c.p.b).is_empty(), "still settling (D13)");
    ring(&mut c.p.b);
    assert!(matches!(events(&c.p.b)[..], [CallEvent::Incoming { .. }]));
}

/// D13: a late Offer and its End(unreachable) go out together once a
/// circuit opens; the callee records a missed call and never rings.
#[test]
fn a_late_offer_and_its_end_go_together_and_never_ring() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    let id = CallId([0x44; 16]);
    c.p.a.call.late.insert(
        b_hex.clone(),
        LateOffer {
            offer: CallSignal::Offer {
                call_id: id,
                caller_rand: Zeroizing::new([6; 32]),
                sent_at_ms: c.ms0 - 20_000,
            },
            end: CallSignal::End {
                call_id: id,
                reason: EndReason::Unreachable,
            },
            at: c.t0,
        },
    );
    c.p.a.call_tick(c.t0, c.ms0);
    assert!(c.p.a.call.late.is_empty());
    let out = drain(&mut c.p.a_rx);
    assert_eq!(out.len(), 2, "the Offer and its End in one batch");
    for f in out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.b, Frame::Relay(p));
        }
    }
    let evs = events(&c.p.b);
    assert!(!evs.iter().any(|e| matches!(e, CallEvent::Incoming { .. })));
    assert!(
        matches!(&evs[..], [CallEvent::Ended { result: CallResult::Missed, peer, .. }] if *peer == a_hex)
    );
    ring(&mut c.p.b);
    assert!(
        events(&c.p.b).is_empty(),
        "nothing rings after the settle either"
    );
    assert!(
        drain(&mut c.p.b_rx).is_empty(),
        "no Ringing for an ended Offer"
    );
    assert!(c.p.b.call.active.is_none());
}

/// D13: an End that arrives within RING_SETTLE of its Offer means missed.
#[test]
fn an_end_within_the_settle_makes_the_offer_missed_without_ringing() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = CallId([0x45; 16]);
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::Offer {
            call_id: id,
            caller_rand: Zeroizing::new([7; 32]),
            sent_at_ms: c.ms0,
        },
    );
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::End {
            call_id: id,
            reason: EndReason::HangUp,
        },
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert!(!evs.iter().any(|e| matches!(e, CallEvent::Incoming { .. })));
    assert_eq!(ended(&evs).map(|e| e.0), Some(CallResult::Missed));
    assert!(drain(&mut c.p.b_rx).is_empty(), "no Ringing");
}

/// D11: an Offer beyond the held-offer cap is recorded as missed, never lost.
#[test]
fn an_offer_beyond_the_held_cap_is_missed() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.b.call.handed_over = false;
    for n in 1..=5u8 {
        send(
            &c.p.a,
            &b_hex,
            &CallSignal::Offer {
                call_id: CallId([n; 16]),
                caller_rand: Zeroizing::new([n; 32]),
                sent_at_ms: c.ms0,
            },
        );
    }
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert_eq!(evs.len(), 1, "{evs:?}");
    assert!(
        matches!(&evs[0], CallEvent::Ended { call_id, result: CallResult::Missed, .. } if *call_id == CallId([5; 16]))
    );
    assert_eq!(c.p.b.call.held.len(), 4);
}

#[test]
fn no_answer_at_45_s_and_the_callee_sees_a_missed_call() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    events(&c.p.a);
    events(&c.p.b);
    c.p.a.call_tick(c.t0 + NO_ANSWER_AFTER, c.ms0 + 45_000);
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::NoAnswer)
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Missed)
    );
}

/// D14.
#[test]
fn the_callee_gives_up_ringing_at_50_s() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    // The 50 s run from the Offer's arrival, which is no earlier than now.
    let received = Instant::now();
    ring(&mut c.p.b);
    events(&c.p.b);
    c.p.b
        .call_tick(received + Duration::from_secs(49), c.ms0 + 49_000);
    assert!(events(&c.p.b).is_empty());
    c.p.b
        .call_tick(Instant::now() + INCOMING_GIVE_UP, c.ms0 + 50_000);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Missed)
    );
}

#[test]
fn decline_tells_the_caller_declined_and_busy_tells_busy() {
    for (busy, caller, callee) in [
        (false, CallResult::Declined, CallResult::Declined),
        (true, CallResult::Busy, CallResult::Busy),
    ] {
        let mut c = calls();
        let b_hex = c.p.pb.hex.clone();
        let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
        pump(&mut c.p.a_rx, &mut c.p.b);
        ring(&mut c.p.b);
        events(&c.p.b);
        c.p.b.call_decline(id, busy, c.ms0 + 3000).unwrap();
        assert_eq!(ended(&events(&c.p.b)).map(|e| e.0), Some(callee));
        pump(&mut c.p.b_rx, &mut c.p.a);
        assert_eq!(ended(&events(&c.p.a)).map(|e| e.0), Some(caller));
    }
}

#[test]
fn a_new_offer_during_a_call_gets_busy() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    events(&c.p.b);
    drain(&mut c.p.b_rx);
    let second = CallSignal::Offer {
        call_id: CallId([9; 16]),
        caller_rand: Zeroizing::new([3; 32]),
        sent_at_ms: c.ms0,
    };
    send(&c.p.a, &b_hex, &second);
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Busy),
        "the callee sees a missed (busy) call"
    );
    assert_eq!(
        c.p.b.call.active.as_ref().map(|a| a.id),
        Some(id),
        "the first call goes on"
    );
    assert!(!drain(&mut c.p.b_rx).is_empty(), "End(busy) went back");
}

#[test]
fn signals_for_an_unknown_call_id_are_ignored() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let x = CallId([0x55; 16]);
    for sig in [
        CallSignal::Ringing { call_id: x },
        CallSignal::Answer {
            call_id: x,
            callee_rand: Zeroizing::new([4; 32]),
        },
        CallSignal::End {
            call_id: x,
            reason: EndReason::HangUp,
        },
    ] {
        send(&c.p.a, &b_hex, &sig);
    }
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(events(&c.p.b).is_empty());
    assert!(c.p.b.call.active.is_none());
}

#[test]
fn answered_but_no_media_for_20_s_fails() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    events(&c.p.b);
    c.p.b.call_tick(c.t0 + CONNECT_GIVE_UP, c.ms0 + 20_000);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Failed)
    );
}

/// D16: a call that ends after Answer but before the first media frame is
/// failed on both phones ("Call failed"), never cancelled or missed.
#[test]
fn ending_after_answer_before_media_is_failed_on_both_phones() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    events(&c.p.a);
    events(&c.p.b);
    c.p.a
        .call_end(id, c.t0 + Duration::from_secs(2), c.ms0 + 2000)
        .unwrap();
    assert_eq!(
        ended(&events(&c.p.a)),
        Some((CallResult::Failed, Direction::Outgoing, 0))
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(
        ended(&events(&c.p.b)),
        Some((CallResult::Failed, Direction::Incoming, 0))
    );
}

/// D16: the caller hanging up before any Answer is cancelled.
#[test]
fn hanging_up_before_an_answer_is_cancelled() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    events(&c.p.a);
    c.p.a
        .call_end(id, c.t0 + Duration::from_secs(3), c.ms0 + 3000)
        .unwrap();
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Cancelled)
    );
}

/// D37: the audio handle reaches the call's media without the client and
/// gives silence and 0 once the call is over.
#[test]
fn the_audio_handle_follows_the_call() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let h = CallAudioHandle::new(c.p.a.call.audio.clone(), c.p.a.call.muted.clone());
    let mut out = [7i16; FRAME_SAMPLES];
    assert_eq!(h.pull_pcm(&mut out), 0);
    assert!(out.iter().all(|s| *s == 0), "silence without a call");
    assert_eq!(h.push_pcm(&[0; FRAME_SAMPLES]), 0);
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert_eq!(h.push_pcm(&[0; FRAME_SAMPLES]), FRAME_SAMPLES);
    assert_eq!(h.pull_pcm(&mut out), FRAME_SAMPLES);
    h.set_muted(true);
    assert!(c.p.a.call.muted.load(Ordering::SeqCst));
    c.p.a
        .call_end(id, c.t0 + Duration::from_secs(1), c.ms0 + 1000)
        .unwrap();
    out.fill(7);
    assert_eq!(h.pull_pcm(&mut out), 0);
    assert!(out.iter().all(|s| *s == 0));
}

#[test]
fn reconnecting_that_does_not_recover_in_20_s_ends_the_call() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let media = c.a_media.media.lock()[0].clone();
    media.status.lock().first_frame = true;
    c.p.a.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    events(&c.p.a);
    {
        let mut st = media.status.lock();
        st.reconnecting = true;
        st.silent_for = Duration::from_secs(10);
    }
    c.p.a
        .call_tick(c.t0 + Duration::from_secs(11), c.ms0 + 11_000);
    assert!(ended(&events(&c.p.a)).is_none(), "still reconnecting");
    media.status.lock().silent_for = SILENT_AFTER + RECONNECT_GIVE_UP;
    c.p.a
        .call_tick(c.t0 + Duration::from_secs(24), c.ms0 + 24_000);
    let (result, _, duration) = ended(&events(&c.p.a)).unwrap();
    assert_eq!(result, CallResult::Failed);
    assert!(
        duration > 0,
        "a call that connected keeps its duration (D15)"
    );
}

#[test]
fn status_goes_to_the_app_every_second_while_connected() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let media = c.a_media.media.lock()[0].clone();
    *media.status.lock() = MediaStatus {
        first_frame: true,
        connections: 2,
        concealed_pct: 7,
        poor: true,
        ..MediaStatus::default()
    };
    for ms in (250..=3000).step_by(250) {
        c.p.a
            .call_tick(c.t0 + Duration::from_millis(ms), c.ms0 + ms);
    }
    let statuses: Vec<_> = events(&c.p.a)
        .into_iter()
        .filter(|e| matches!(e, CallEvent::Status { .. }))
        .collect();
    assert!((2..=3).contains(&statuses.len()), "{}", statuses.len());
    let json = statuses[0].to_json();
    assert!(
        json.contains("\"type\":\"status\"")
            && json.contains("\"concealed_pct\":7")
            && json.contains("\"poor\":true")
            && json.contains("\"connections\":2"),
        "{json}"
    );
}

#[test]
fn a_relay_without_calls_refuses_to_place_and_one_call_at_a_time() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.relay_calls = false;
    assert!(matches!(
        c.p.a.call_place(&b_hex, c.t0, c.ms0),
        Err(crate::RChatError::RelayNoCalls)
    ));
    c.p.a.relay_calls = true;
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    assert!(matches!(
        c.p.a.call_place(&b_hex, c.t0, c.ms0),
        Err(crate::RChatError::CallInProgress)
    ));
    assert!(matches!(
        c.p.a.call_answer(CallId([1; 16]), c.t0, c.ms0),
        Err(crate::RChatError::NoSuchCall)
    ));
}

/// D9: an app without calls drops call signalling exactly as protocol v3 does.
#[test]
fn with_calls_off_signalling_is_dropped_like_v3() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.b.config.calls_enabled = false;
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    assert!(events(&c.p.b).is_empty());
    assert!(c.p.b.call.active.is_none());
    assert!(no_receipt(&c.p.b), "no receipt queued or due (v3 drops it)");
    assert!(drain(&mut c.p.b_rx).is_empty(), "no Ringing");
}

/// D19: one status callback when the queue goes from empty to non-empty.
#[test]
fn queued_events_raise_one_status_callback_until_drained() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    c.p.a.call_tick(c.t0 + UNREACHABLE_AFTER, c.ms0 + 15_000); // a second event, queue not drained
    let raised = crate::test_support::statuses(&c.p.a_log)
        .into_iter()
        .filter(|s| matches!(s, crate::status::StatusEvent::CallEvents))
        .count();
    assert_eq!(raised, 1);
    assert_eq!(
        crate::status::StatusEvent::CallEvents.parts(),
        (11, String::new(), String::new(), 0)
    );
}

#[test]
fn event_json_carries_the_fields_the_app_reads() {
    let e = CallEvent::Ended {
        call_id: CallId([0xAB; 16]),
        peer: "ab".repeat(32),
        direction: Direction::Outgoing,
        result: CallResult::NoAnswer,
        duration_secs: 0,
        started_at_ms: 1_700_000_000_000,
        video: false,
    };
    let v: serde_json::Value = serde_json::from_str(&e.to_json()).unwrap();
    assert_eq!(v["type"], "ended");
    assert_eq!(v["call_id"], "ab".repeat(16));
    assert_eq!(v["direction"], "out");
    assert_eq!(v["result"], "no_answer");
    assert_eq!(v["duration_secs"], 0);
    assert_eq!(v["started_at_ms"], 1_700_000_000_000u64);
    let c = CallEvent::Connecting {
        call_id: CallId([1; 16]),
        peer: "cd".repeat(32),
        replaced: Some(CallId([2; 16])),
    };
    let v: serde_json::Value = serde_json::from_str(&c.to_json()).unwrap();
    assert_eq!(v["replaced_call_id"], "02".repeat(16));
}

/// Answer A's call on B and let A see the Answer: both connecting, both
/// media started. Returns the call id and each side's media.
fn connecting(c: &mut Calls) -> (CallId, Arc<FakeMedia>, Arc<FakeMedia>) {
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    drain(&mut c.p.a_rx);
    events(&c.p.a);
    events(&c.p.b);
    let a = c.a_media.media.lock()[0].clone();
    let b = c.b_media.media.lock()[0].clone();
    (id, a, b)
}

fn caller_rand_of(inner: &crate::ClientInner) -> [u8; 32] {
    match &inner.call.active.as_ref().unwrap().phase {
        Phase::Outgoing { caller_rand, .. } => **caller_rand,
        _ => panic!("not outgoing"),
    }
}

/// Carried from Task 4: caller_rand and callee_rand are fresh for every
/// call, even for the same call id and the same caller_rand.
#[test]
fn both_randoms_are_fresh_for_every_call() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let id = CallId([0x31; 16]);
    c.p.a.call.next_call_id = Some(id);
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    let first = caller_rand_of(&c.p.a);
    c.p.a.call_end(id, c.t0, c.ms0).unwrap();
    c.p.a.call.next_call_id = Some(id);
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    let second = caller_rand_of(&c.p.a);
    assert_ne!(first, second, "caller_rand fresh per call");
    assert_ne!(first, [0; 32]);
    c.p.a.call_end(id, c.t0, c.ms0).unwrap();
    drain(&mut c.p.a_rx);
    // The callee: the same Offer twice gives two different relay tokens,
    // so callee_rand differed.
    for _ in 0..2 {
        let offer = CallSignal::Offer {
            call_id: id,
            caller_rand: Zeroizing::new([9; 32]),
            sent_at_ms: unix_ms(),
        };
        send(&c.p.a, &b_hex, &offer);
        pump(&mut c.p.a_rx, &mut c.p.b);
        ring(&mut c.p.b);
        c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
        c.p.b.call_end(id, c.t0, c.ms0).unwrap();
        drain(&mut c.p.b_rx);
    }
    let started = c.b_media.started.lock();
    assert_eq!(started.len(), 2);
    assert_ne!(started[0].1, started[1].1, "callee_rand fresh per call");
}

/// Carried from Task 8: media that cannot start (no runtime, no codec)
/// fails the call on both phones, and the caller's media is stopped.
#[test]
fn media_that_cannot_start_fails_the_call() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.b_media.cannot_start.store(true, Ordering::SeqCst);
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    events(&c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(c.p.b.call.active.is_none());
    let b_controls = pump(&mut c.p.b_rx, &mut c.p.a); // Answer, then End(failed)
    assert!(grants(&b_controls).is_empty(), "no grant without media");
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(c.a_media.media.lock()[0].stopped.load(Ordering::SeqCst));
}

/// Carried from Task 8: refused, a failed relay pin and the engine's
/// give-up fail the call while connecting; exhausted and gave_up end a
/// connected call (keeping its duration).
#[test]
fn media_status_outcomes_end_the_call_as_failed() {
    let connecting_cases: [fn(&mut MediaStatus); 3] = [
        |s| s.refused = true,
        |s| {
            s.refused = true;
            s.pin_failed = true;
        },
        |s| s.gave_up = true,
    ];
    for set in connecting_cases {
        let mut c = calls();
        let (_, a, b) = connecting(&mut c);
        set(&mut a.status.lock());
        c.p.a.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
        assert_eq!(
            ended(&events(&c.p.a)),
            Some((CallResult::Failed, Direction::Outgoing, 0))
        );
        assert!(a.stopped.load(Ordering::SeqCst));
        pump(&mut c.p.a_rx, &mut c.p.b);
        assert_eq!(
            ended(&events(&c.p.b)).map(|e| e.0),
            Some(CallResult::Failed)
        );
        assert!(b.stopped.load(Ordering::SeqCst));
    }
    let connected_cases: [fn(&mut MediaStatus); 3] = [
        |s| s.exhausted = true,
        |s| s.gave_up = true,
        |s| s.refused = true,
    ];
    for set in connected_cases {
        let mut c = calls();
        let (_, a, _) = connecting(&mut c);
        a.status.lock().first_frame = true;
        c.p.a.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
        assert!(events(&c.p.a)
            .iter()
            .any(|e| matches!(e, CallEvent::Connected { .. })));
        set(&mut a.status.lock());
        c.p.a.call_tick(c.t0 + Duration::from_secs(9), c.ms0 + 9000);
        assert_eq!(
            ended(&events(&c.p.a)),
            Some((CallResult::Failed, Direction::Outgoing, 8))
        );
        assert!(a.stopped.load(Ordering::SeqCst));
        assert!(c.p.a.call.audio.lock().is_none());
    }
}

/// Carried from Task 8: every way a call ends stops its media (wiping the
/// keys) and empties the audio slot.
#[test]
fn every_end_path_stops_the_media() {
    let refused = || {
        Frame::Control(ControlMessage::Error {
            code: crate::protocol::ControlErrorCode::InvalidMessage,
            message: crate::protocol::MEDIA_GRANT_REFUSED.to_string(),
        })
    };
    // The relay refusing our grant.
    let mut c = calls();
    let (_, a, b) = connecting(&mut c);
    feed(&mut c.p.a, refused());
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(a.stopped.load(Ordering::SeqCst));
    // ... and the peer's End(failed) that follows.
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(b.stopped.load(Ordering::SeqCst));
    assert!(c.p.a.call.audio.lock().is_none() && c.p.b.call.audio.lock().is_none());
    // Disconnect.
    let mut c = calls();
    let (_, a, _) = connecting(&mut c);
    c.p.a.call_abort(c.ms0);
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(a.stopped.load(Ordering::SeqCst) && c.p.a.call.audio.lock().is_none());
    // No media within 20 s.
    let mut c = calls();
    let (_, _, b) = connecting(&mut c);
    c.p.b.call_tick(c.t0 + CONNECT_GIVE_UP, c.ms0 + 20_000);
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(b.stopped.load(Ordering::SeqCst) && c.p.b.call.audio.lock().is_none());
    // Our own hang-up, connected.
    let mut c = calls();
    let (id, _, b) = connecting(&mut c);
    b.status.lock().first_frame = true;
    c.p.b.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    c.p.b
        .call_end(id, c.t0 + Duration::from_secs(5), c.ms0 + 5000)
        .unwrap();
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Completed)
    );
    assert!(b.stopped.load(Ordering::SeqCst) && c.p.b.call.audio.lock().is_none());
}

/// Carried from Task 2: after a network switch the chat circuit ids change
/// and the relay refuses a second grant of a live token, so the core never
/// grants it again; the token and the call connections carry on.
#[test]
fn a_live_call_is_never_granted_again_after_re_pairing() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    let (_, a, _) = connecting(&mut c);
    // Re-paired: both members hold new circuit ids.
    for (inner, peer, n) in [(&c.p.a, &b_hex, 0x71u8), (&c.p.b, &a_hex, 0x72)] {
        let mut s = inner.session_manager.get_mut(peer).unwrap();
        s.circuit_id = Some(crate::protocol::CircuitId([n; 16]));
        s.target_circuit_id = Some(crate::protocol::CircuitId([n ^ 3; 16]));
    }
    for ms in (250..=2000).step_by(250) {
        c.p.a
            .call_tick(c.t0 + Duration::from_millis(ms), c.ms0 + ms);
        c.p.b
            .call_tick(c.t0 + Duration::from_millis(ms), c.ms0 + ms);
    }
    a.status.lock().first_frame = true;
    for ms in (2250..=5000).step_by(250) {
        c.p.a
            .call_tick(c.t0 + Duration::from_millis(ms), c.ms0 + ms);
    }
    let controls: Vec<_> = drain(&mut c.p.a_rx)
        .iter()
        .chain(drain(&mut c.p.b_rx).iter())
        .filter_map(|f| ControlMessage::decode(f))
        .collect();
    assert!(grants(&controls).is_empty(), "no second grant");
    assert_eq!(
        c.a_media.started.lock().len(),
        1,
        "the same media carries on"
    );
    assert!(!a.stopped.load(Ordering::SeqCst));
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Connected { .. })));
}

/// Carried from Task 8: the real starter runs the engine on the client's
/// long-lived runtime from any thread; without one there is no media.
#[cfg(feature = "calls-codec")]
#[test]
fn the_real_starter_starts_media_on_the_clients_runtime() {
    use super::machine::RealStarter;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let start = || MediaStart {
        call_id: CallId([3; 16]),
        role: 0,
        keys: keys::derive(&CallId([3; 16]), &[1; 32], &[2; 32], true).0,
        lane: super::test_relay::lane_config("ws://127.0.0.1:9/"),
    };
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "a thread without a runtime"
    );
    let media = RealStarter::new(Some(rt.handle().clone()))
        .start(start())
        .expect("started on the client's runtime");
    media.stop();
    assert!(RealStarter::new(None).start(start()).is_none());
}

fn ended_at(evs: &[CallEvent]) -> Option<u64> {
    evs.iter().find_map(|e| match e {
        CallEvent::Ended { started_at_ms, .. } => Some(*started_at_ms),
        _ => None,
    })
}

/// Review of Task 9: blocking (or unpinning) a contact ends its call in
/// every phase, stops the media, and drops its held and late Offers.
#[test]
fn blocking_a_contact_ends_its_call_in_every_phase() {
    // Ringing (rang): declined; the caller hears the hang-up.
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    events(&c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    events(&c.p.a);
    c.p.b.block_peer(&a_hex, true).unwrap();
    assert!(c.p.b.call.active.is_none());
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Declined)
    );
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(
        ended(&events(&c.p.a)).is_some(),
        "the End went out before the session"
    );
    assert!(c.p.a.call.active.is_none());
    // Not yet rung: missed.
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    c.p.b.block_peer(&a_hex, true).unwrap();
    assert!(c.p.b.call.active.is_none());
    assert_eq!(
        ended(&events(&c.p.b)).map(|e| e.0),
        Some(CallResult::Missed)
    );
    // Outgoing: cancelled.
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    events(&c.p.a);
    c.p.a.block_peer(&b_hex, true).unwrap();
    assert!(c.p.a.call.active.is_none());
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Cancelled)
    );
    // Connected: failed, media stopped, audio slot empty.
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let (_, a, _) = connecting(&mut c);
    a.status.lock().first_frame = true;
    c.p.a.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    events(&c.p.a);
    c.p.a.block_peer(&b_hex, true).unwrap();
    assert!(c.p.a.call.active.is_none());
    assert_eq!(
        ended(&events(&c.p.a)).map(|e| e.0),
        Some(CallResult::Failed)
    );
    assert!(a.stopped.load(Ordering::SeqCst) && c.p.a.call.audio.lock().is_none());
}

/// Review of Task 9: a held Offer from a contact blocked before the queue
/// handover is never taken, and a late Offer to one never goes.
#[test]
fn a_blocked_contacts_held_and_late_offers_are_dropped() {
    let mut c = calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.b.call.handed_over = false;
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(c.p.b.call.held.len(), 1);
    c.p.b.block_peer(&a_hex, true).unwrap();
    assert!(c.p.b.call.held.is_empty());
    c.p.b.call_on_queue_handed_over(Instant::now(), unix_ms());
    ring(&mut c.p.b);
    assert!(events(&c.p.b).is_empty());
    assert!(c.p.b.call.active.is_none());
    // A late Offer for a contact then blocked.
    let id = CallId([0x46; 16]);
    c.p.a.call_abort(c.ms0);
    c.p.a.call.late.insert(
        b_hex.clone(),
        LateOffer {
            offer: CallSignal::Offer {
                call_id: id,
                caller_rand: Zeroizing::new([6; 32]),
                sent_at_ms: c.ms0,
            },
            end: CallSignal::End {
                call_id: id,
                reason: EndReason::Unreachable,
            },
            at: c.t0,
        },
    );
    c.p.a.block_peer(&b_hex, true).unwrap();
    assert!(c.p.a.call.late.is_empty());
}

/// Review of Task 9: event times are our clock's, never the caller's
/// `sent_at_ms` (a contact could date an Offer 2100).
#[test]
fn incoming_events_carry_our_clock_not_the_callers() {
    let local = |t: u64| t.abs_diff(unix_ms()) < 10_000;
    // Too far ahead: missed at our time.
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    let far = CallSignal::Offer {
        call_id: CallId([0x61; 16]),
        caller_rand: Zeroizing::new([1; 32]),
        sent_at_ms: 4_102_444_800_000,
    };
    send(&c.p.a, &b_hex, &far);
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(ended_at(&events(&c.p.b)).is_some_and(local));
    // Dated 50 s ahead (inside the age rule), then its End: missed at our time.
    let id = CallId([0x62; 16]);
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::Offer {
            call_id: id,
            caller_rand: Zeroizing::new([2; 32]),
            sent_at_ms: unix_ms() + 50_000,
        },
    );
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::End {
            call_id: id,
            reason: EndReason::HangUp,
        },
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(ended_at(&events(&c.p.b)).is_some_and(local));
    // Busy during a call.
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    connecting(&mut c);
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::Offer {
            call_id: CallId([0x63; 16]),
            caller_rand: Zeroizing::new([3; 32]),
            sent_at_ms: unix_ms() + 55_000,
        },
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert_eq!(ended(&evs).map(|e| e.0), Some(CallResult::Busy));
    assert!(ended_at(&evs).is_some_and(local));
    // Past the held cap, and held then ended.
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.b.call.handed_over = false;
    for n in 1..=5u8 {
        send(
            &c.p.a,
            &b_hex,
            &CallSignal::Offer {
                call_id: CallId([n; 16]),
                caller_rand: Zeroizing::new([n; 32]),
                sent_at_ms: unix_ms() + 50_000,
            },
        );
    }
    send(
        &c.p.a,
        &b_hex,
        &CallSignal::End {
            call_id: CallId([1; 16]),
            reason: EndReason::HangUp,
        },
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(
        ended_at(&events(&c.p.b)).is_some_and(local),
        "the capped one"
    );
    c.p.b.call_on_queue_handed_over(Instant::now(), unix_ms());
    let evs = events(&c.p.b);
    assert!(ended_at(&evs).is_some_and(local), "the held, ended one");
    assert!(
        c.p.b
            .call
            .active
            .as_ref()
            .is_some_and(|a| local(a.started_at_ms)),
        "the taken one"
    );
}

/// Review of Task 9: a mute set before the media starts reaches it.
#[test]
fn a_mute_set_before_connecting_reaches_the_media() {
    let mut c = calls();
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call.muted.store(true, Ordering::SeqCst);
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(c.a_media.media.lock()[0].muted.load(Ordering::SeqCst));
}

/// Review of Task 9: the app's mute landing between the flag read and the
/// apply (`call_begin_connecting`) still ends with the media muted.
#[test]
fn a_mute_racing_the_media_start_still_mutes_it() {
    struct Racing {
        flag: Arc<AtomicBool>,
        muted: AtomicBool,
        raced: AtomicBool,
    }
    impl MediaControl for Racing {
        fn push_pcm(&self, _: &[i16]) -> usize {
            0
        }
        fn pull_pcm(&self, _: &mut [i16]) -> usize {
            0
        }
        fn set_muted(&self, muted: bool) {
            // The app stores `true` (and applies it) just before our stale
            // `false` lands.
            if !self.raced.swap(true, Ordering::SeqCst) {
                self.flag.store(true, Ordering::SeqCst);
            }
            self.muted.store(muted, Ordering::SeqCst);
        }
        fn status(&self, _: Instant) -> MediaStatus {
            MediaStatus::default()
        }
        fn stop(&self) {}
        fn audio_link(self: Arc<Self>) -> Option<Arc<dyn AudioLink>> {
            Some(Arc::new(FakeAudio))
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    let media = Racing {
        flag: flag.clone(),
        muted: AtomicBool::new(false),
        raced: AtomicBool::new(false),
    };
    super::machine::apply_mute(&flag, &media);
    assert!(flag.load(Ordering::SeqCst));
    assert!(
        media.muted.load(Ordering::SeqCst),
        "the flag's last value reached the media"
    );
}

// ---- Video in the call machine (video spec §4, R1, R7, R17-R19) ----

/// `calls()` with video on both sides: codecs 3 and a relay with `video-v1`.
fn video_calls() -> Calls {
    let mut c = calls();
    for inner in [&mut c.p.a, &mut c.p.b] {
        inner.relay_video = true;
        inner.call.video_prefs.set(3, false, false);
    }
    c
}

/// The call and video plaintexts `inner` decrypted since last asked.
fn heard(inner: &mut crate::ClientInner) -> Vec<Vec<u8>> {
    std::mem::take(&mut inner.call.heard)
}

fn video_signals(pts: &[Vec<u8>]) -> Vec<VideoSignal> {
    pts.iter().filter_map(|p| VideoSignal::decode(p)).collect()
}

fn video_states(evs: &[CallEvent]) -> Vec<VideoState> {
    evs.iter()
        .filter_map(|e| match e {
            CallEvent::Video { state, .. } => Some(*state),
            _ => None,
        })
        .collect()
}

fn last_video(evs: &[CallEvent]) -> Option<VideoState> {
    video_states(evs).last().copied()
}

fn requests(evs: &[CallEvent]) -> usize {
    evs.iter()
        .filter(|e| matches!(e, CallEvent::VideoRequest { .. }))
        .count()
}

/// Seal a video signal from `from` to `to_hex`.
fn send_video(from: &crate::ClientInner, to_hex: &str, sig: &VideoSignal) {
    let packet = from
        .seal_ratchet(to_hex, rand::random(), &sig.encode())
        .unwrap();
    from.send_now(packet.encode_with_frame_type()).unwrap();
}

/// B answers A's call `id` and both connect (first media frame). Events,
/// heard plaintexts and sent frames are cleared.
fn answer_and_connect(c: &mut Calls, id: CallId) {
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    drain(&mut c.p.a_rx);
    for s in [&c.a_media, &c.b_media] {
        s.media.lock()[0].status.lock().first_frame = true;
    }
    let t = c.t0 + Duration::from_secs(1);
    c.p.a.call_tick(t, c.ms0 + 1000);
    c.p.b.call_tick(t, c.ms0 + 1000);
    drain(&mut c.p.a_rx);
    drain(&mut c.p.b_rx);
    events(&c.p.a);
    events(&c.p.b);
    heard(&mut c.p.a);
    heard(&mut c.p.b);
}

/// A voice call from A to B, connected on both.
fn connected(c: &mut Calls) -> CallId {
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    answer_and_connect(c, id);
    id
}

/// A asks for video and B accepts: video agreed on both.
fn agree(c: &mut Calls) {
    let now = c.t0;
    c.p.a.call_video_set_camera(true, now).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    c.p.b.call_video_respond(true, now).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    events(&c.p.a);
    events(&c.p.b);
    heard(&mut c.p.a);
    heard(&mut c.p.b);
}

fn state_of(inner: &crate::ClientInner) -> VideoState {
    inner.call_video_state().expect("a call")
}

#[test]
fn caps_follow_the_offer_and_the_ringing_and_the_offer_stays_59_bytes() {
    let mut c = video_calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    let pts = heard(&mut c.p.b);
    assert_eq!(pts.len(), 2, "Offer, then Caps");
    assert_eq!(pts[0].len(), 59, "the exact 2.2.0 Offer");
    assert_eq!(pts[0][58], super::signal::MEDIA_AUDIO);
    assert!(matches!(
        CallSignal::decode(&pts[0]),
        Some(CallSignal::Offer { call_id, .. }) if call_id == id
    ));
    assert!(matches!(
        VideoSignal::decode(&pts[1]),
        Some(VideoSignal::Caps { call_id, caps })
            if call_id == id && caps.video && caps.video_call && caps.codecs == 3
    ));
    ring(&mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    let pts = heard(&mut c.p.a);
    assert_eq!(pts.len(), 2, "Ringing, then Caps");
    assert!(matches!(
        CallSignal::decode(&pts[0]),
        Some(CallSignal::Ringing { call_id }) if call_id == id
    ));
    assert!(matches!(
        VideoSignal::decode(&pts[1]),
        Some(VideoSignal::Caps { call_id, caps })
            if call_id == id && caps.video && !caps.video_call && caps.codecs == 3
    ));
}

#[test]
fn the_glare_winner_sends_caps_before_its_answer_and_a_late_caps_upgrades_the_peer() {
    let mut c = video_calls();
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    let win = CallId([1; 16]);
    c.p.a.call.next_call_id = Some(win);
    c.p.b.call.next_call_id = Some(CallId([2; 16]));
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    c.p.b.call_place(&a_hex, c.t0, c.ms0).unwrap();
    let a_out = drain(&mut c.p.a_rx);
    let b_out = drain(&mut c.p.b_rx);
    for f in b_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.a, Frame::Relay(p));
        }
    }
    for f in a_out {
        if let Some(p) = RelayPacket::decode(&f) {
            feed(&mut c.p.b, Frame::Relay(p));
        }
    }
    heard(&mut c.p.a);
    events(&c.p.a);
    // B switched to A's lower call: its Caps for that call, then its Answer.
    pump(&mut c.p.b_rx, &mut c.p.a);
    let pts = heard(&mut c.p.a);
    assert_eq!(pts.len(), 2);
    assert!(matches!(
        VideoSignal::decode(&pts[0]),
        Some(VideoSignal::Caps { call_id, caps }) if call_id == win && caps.video
    ));
    assert!(matches!(
        CallSignal::decode(&pts[1]),
        Some(CallSignal::Answer { call_id, .. }) if call_id == win
    ));
    assert_eq!(state_of(&c.p.a).available, Availability::Yes);
    // B had A's Caps only after its Answer: the late Caps made video possible.
    assert_eq!(state_of(&c.p.b).available, Availability::Yes);
    assert!(!state_of(&c.p.a).agreed && !state_of(&c.p.b).agreed);

    // A late Caps after an Answer moves Peer to Yes.
    let mut c = video_calls();
    c.p.b.call.ignore_video = true;
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    answer_and_connect(&mut c, id);
    assert_eq!(state_of(&c.p.a).available, Availability::Peer);
    let a_hex = c.p.pa.hex.clone();
    send_video(
        &c.p.b,
        &a_hex,
        &VideoSignal::Caps {
            call_id: id,
            caps: c.p.a.call.video_prefs.caps(true, false),
        },
    );
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert_eq!(
        last_video(&events(&c.p.a)).map(|s| s.available),
        Some(Availability::Yes)
    );
}

#[test]
fn a_2_2_0_peer_gets_a_plain_offer_and_video_is_unavailable_after_its_answer() {
    let mut c = video_calls();
    c.p.b.call.ignore_video = true;
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    assert!(events(&c.p.b)
        .iter()
        .any(|e| matches!(e, CallEvent::Incoming { video: false, .. })));
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert_eq!(heard(&mut c.p.a).len(), 1, "a Ringing and no Caps");
    events(&c.p.a);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let st = last_video(&events(&c.p.a)).expect("a video event at the Answer");
    assert_eq!(st.available, Availability::Peer);
    assert!(!st.camera && !st.agreed, "the caller's camera stops");
    assert!(c.a_media.video.lock().is_empty() && c.b_media.video.lock().is_empty());
    assert!(matches!(
        c.p.a.call_video_set_camera(true, c.t0),
        Err(crate::RChatError::VideoUnavailable)
    ));
    assert!(c.p.a.call.active.is_some(), "the call goes on as voice");
}

#[test]
fn header_video_call_rings_as_video_and_answer_agrees() {
    let mut c = video_calls();
    let b_hex = c.p.pb.hex.clone();
    let id = c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    let evs = events(&c.p.a);
    assert!(evs
        .iter()
        .any(|e| matches!(e, CallEvent::Outgoing { video: true, .. })));
    assert!(
        last_video(&evs).unwrap().camera,
        "the caller's preview runs"
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    assert!(events(&c.p.b)
        .iter()
        .any(|e| matches!(e, CallEvent::Incoming { video: true, .. })));
    pump(&mut c.p.b_rx, &mut c.p.a);
    c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let (sa, sb) = (
        last_video(&events(&c.p.a)).unwrap(),
        last_video(&events(&c.p.b)).unwrap(),
    );
    assert!(sa.agreed && sb.agreed);
    assert!(sa.camera && !sa.peer_camera);
    assert!(
        sb.peer_shown && !sb.camera,
        "answering shows the caller's video"
    );
    assert_eq!(sa.codec, Some(VideoCodec::H265));
    let token = c.a_media.started.lock()[0].1;
    let (va, vb) = (
        c.a_media.video.lock()[0].clone(),
        c.b_media.video.lock()[0].clone(),
    );
    assert_eq!((va.role, vb.role), (0, 1));
    assert_eq!(
        (va.token, vb.token),
        (token, token),
        "the audio's relay token"
    );
    assert_eq!((va.codec, vb.codec), (VideoCodec::H265, VideoCodec::H265));
    assert!(va.sending.load(Ordering::SeqCst) && !va.receiving.load(Ordering::SeqCst));
    assert!(vb.receiving.load(Ordering::SeqCst) && !vb.sending.load(Ordering::SeqCst));
    // A plain Answer: the app turns the callee's camera on, with no prompt.
    c.p.b.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let evs = events(&c.p.a);
    assert_eq!(requests(&evs), 0);
    assert!(last_video(&evs).unwrap().peer_shown);
    assert!(vb.sending.load(Ordering::SeqCst) && va.receiving.load(Ordering::SeqCst));
    c.p.a.call_end(id, c.t0, c.ms0).unwrap();
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Ended { video: true, .. })));
    assert!(va.stopped.load(Ordering::SeqCst));
    assert!(c.p.a.call.video.lock().is_none());
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(events(&c.p.b)
        .iter()
        .any(|e| matches!(e, CallEvent::Ended { video: true, .. })));
    assert!(vb.stopped.load(Ordering::SeqCst));
}

#[test]
fn video_call_rings_as_voice_when_the_callee_has_no_video_or_no_video_relay() {
    for no_relay in [false, true] {
        let mut c = video_calls();
        if no_relay {
            c.p.b.relay_video = false;
        } else {
            c.p.b.call.video_prefs.set(0, false, false);
        }
        let b_hex = c.p.pb.hex.clone();
        let id = c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
        pump(&mut c.p.a_rx, &mut c.p.b);
        ring(&mut c.p.b);
        assert!(events(&c.p.b)
            .iter()
            .any(|e| matches!(e, CallEvent::Incoming { video: false, .. })));
        pump(&mut c.p.b_rx, &mut c.p.a);
        c.p.b.call_answer(id, c.t0, c.ms0).unwrap();
        pump(&mut c.p.b_rx, &mut c.p.a);
        let sa = state_of(&c.p.a);
        assert_eq!(sa.available, Availability::Peer, "B's Caps say no video");
        assert!(!sa.agreed && !sa.camera);
        if no_relay {
            assert_eq!(state_of(&c.p.b).available, Availability::Relay);
        }
        assert!(c.a_media.video.lock().is_empty());
    }
}

#[test]
fn place_video_on_a_relay_without_video_places_a_voice_call() {
    let mut c = video_calls();
    c.p.a.relay_video = false;
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    let evs = events(&c.p.a);
    assert!(evs
        .iter()
        .any(|e| matches!(e, CallEvent::Outgoing { video: false, .. })));
    assert_eq!(last_video(&evs).unwrap().available, Availability::Relay);
    pump(&mut c.p.a_rx, &mut c.p.b);
    let caps = video_signals(&heard(&mut c.p.b));
    assert!(matches!(
        caps[..],
        [VideoSignal::Caps { caps, .. }] if !caps.video_call && !caps.video
    ));
}

#[test]
fn video_never_appears_without_accept() {
    let mut c = video_calls();
    let id = connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    assert!(state_of(&c.p.a).camera, "the requester's preview runs");
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert!(evs
        .iter()
        .any(|e| matches!(e, CallEvent::VideoRequest { call_id } if *call_id == id)));
    let sb = last_video(&evs).unwrap();
    assert!(sb.request_in && !sb.peer_shown && !sb.agreed);
    assert!(
        c.a_media.video.lock().is_empty(),
        "nothing is sent before the Accept"
    );
    c.p.b.call_video_respond(true, c.t0).unwrap();
    let sb = last_video(&events(&c.p.b)).unwrap();
    assert!(sb.peer_shown && sb.agreed && !sb.camera && !sb.request_in);
    let vb = c.b_media.video.lock()[0].clone();
    assert!(vb.receiving.load(Ordering::SeqCst) && !vb.sending.load(Ordering::SeqCst));
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(last_video(&events(&c.p.a)).unwrap().agreed);
    assert!(c.a_media.video.lock()[0].sending.load(Ordering::SeqCst));
}

#[test]
fn not_now_and_the_30_second_limit_after_a_decline() {
    let mut c = video_calls();
    let id = connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    c.p.b.call_video_respond(false, c.t0).unwrap();
    assert!(!state_of(&c.p.b).peer_camera);
    heard(&mut c.p.b);
    let before = Instant::now();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let after = Instant::now();
    let evs = events(&c.p.a);
    assert!(evs
        .iter()
        .any(|e| matches!(e, CallEvent::VideoDeclined { call_id } if *call_id == id)));
    assert!(!last_video(&evs).unwrap().camera);
    assert!(matches!(
        c.p.a
            .call_video_set_camera(true, before + Duration::from_millis(29_900)),
        Err(crate::RChatError::VideoTooSoon)
    ));
    assert!(drain(&mut c.p.a_rx).is_empty(), "no Request sent");
    c.p.a
        .call_video_set_camera(true, after + Duration::from_secs(30))
        .unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(matches!(
        video_signals(&heard(&mut c.p.b))[..],
        [VideoSignal::Request { .. }]
    ));
}

#[test]
fn a_withdrawn_or_unanswered_request_may_be_sent_again_at_once() {
    let mut c = video_calls();
    connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    c.p.a.call_video_set_camera(false, c.t0).unwrap();
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(matches!(
        video_signals(&heard(&mut c.p.b))[..],
        [
            VideoSignal::Request { .. },
            VideoSignal::Camera { on: false, .. },
            VideoSignal::Request { .. }
        ]
    ));
}

#[test]
fn set_camera_in_outgoing_or_incoming_returns_33_and_unknown_caps_returns_34() {
    let mut c = video_calls();
    assert!(matches!(
        c.p.a.call_video_set_camera(true, c.t0),
        Err(crate::RChatError::NoSuchCall)
    ));
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    assert!(matches!(
        c.p.a.call_video_set_camera(true, c.t0),
        Err(crate::RChatError::NoSuchCall)
    ));
    pump(&mut c.p.a_rx, &mut c.p.b);
    ring(&mut c.p.b);
    assert!(matches!(
        c.p.b.call_video_set_camera(true, c.t0),
        Err(crate::RChatError::NoSuchCall)
    ));
    assert!(matches!(
        c.p.b.call_video_respond(true, c.t0),
        Err(crate::RChatError::NoSuchCall)
    ));
    // Connected, but the peer never sent Caps.
    let mut c = video_calls();
    c.p.b.call.ignore_video = true;
    connected(&mut c);
    assert!(matches!(
        c.p.a.call_video_set_camera(true, c.t0),
        Err(crate::RChatError::VideoUnavailable)
    ));
    // Connected on a relay without video.
    let mut c2 = video_calls();
    c2.p.a.relay_video = false;
    connected(&mut c2);
    assert!(matches!(
        c2.p.a.call_video_set_camera(true, c2.t0),
        Err(crate::RChatError::RelayNoVideo)
    ));
}

#[test]
fn once_agreed_the_other_camera_needs_no_prompt() {
    let mut c = video_calls();
    connected(&mut c);
    agree(&mut c);
    c.p.b.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let pts = heard(&mut c.p.a);
    assert!(matches!(
        video_signals(&pts)[..],
        [VideoSignal::Camera { on: true, .. }]
    ));
    let evs = events(&c.p.a);
    assert_eq!(requests(&evs), 0);
    assert!(last_video(&evs).unwrap().peer_shown);
}

#[test]
fn both_requesting_at_once_agree_without_prompts() {
    let mut c = video_calls();
    connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    c.p.b.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    let (ea, eb) = (events(&c.p.a), events(&c.p.b));
    assert_eq!(requests(&ea) + requests(&eb), 0);
    for st in [state_of(&c.p.a), state_of(&c.p.b)] {
        assert!(st.agreed && st.camera && st.peer_shown && !st.request_in);
    }
}

#[test]
fn withdrawing_a_request_clears_the_prompt() {
    let mut c = video_calls();
    connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(state_of(&c.p.b).request_in);
    events(&c.p.b);
    c.p.a.call_video_set_camera(false, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    let st = last_video(&events(&c.p.b)).unwrap();
    assert!(!st.request_in && !st.peer_camera);
    assert!(matches!(
        c.p.b.call_video_respond(true, c.t0),
        Err(crate::RChatError::NoSuchCall)
    ));
}

#[test]
fn camera_request_to_a_peer_without_video_fails_at_once() {
    let mut c = video_calls();
    c.p.b.call.video_prefs.set(0, false, false);
    connected(&mut c);
    let now = c.t0;
    let a = &mut c.p.a;
    assert!(matches!(
        a.call_video_set_camera(true, now),
        Err(RChatError::VideoUnavailable)
    ));
    assert!(drain(&mut c.p.a_rx).is_empty(), "nothing waits for a reply");
}

use crate::RChatError;

#[test]
fn video_media_starts_once_and_survives_camera_toggles() {
    let mut c = video_calls();
    connected(&mut c);
    agree(&mut c);
    for on in [false, true, false, true] {
        c.p.a.call_video_set_camera(on, c.t0).unwrap();
        c.p.b.call_video_set_camera(on, c.t0).unwrap();
        pump(&mut c.p.a_rx, &mut c.p.b);
        pump(&mut c.p.b_rx, &mut c.p.a);
    }
    assert_eq!(c.a_media.video.lock().len(), 1);
    assert_eq!(c.b_media.video.lock().len(), 1);
    let vb = c.b_media.video.lock()[0].clone();
    assert!(vb.sending.load(Ordering::SeqCst) && vb.receiving.load(Ordering::SeqCst));
}

#[test]
fn video_signals_for_unknown_calls_or_retired_sessions_are_ignored() {
    let mut c = video_calls();
    let id = connected(&mut c);
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    let before = state_of(&c.p.b);
    // A wrong call id.
    send_video(
        &c.p.a,
        &b_hex,
        &VideoSignal::Request {
            call_id: CallId([9; 16]),
        },
    );
    pump(&mut c.p.a_rx, &mut c.p.b);
    // Another peer.
    let other = "cd".repeat(32);
    c.p.b
        .handle_video_plaintext(&other, &VideoSignal::Request { call_id: id }.encode(), c.t0);
    // A retired session.
    c.p.b.handle_decrypted_message(
        &a_hex,
        [7; 16],
        &VideoSignal::Request { call_id: id }.encode(),
        crate::session::DecryptedBy::Retired,
        None,
    );
    assert!(events(&c.p.b).is_empty());
    assert_eq!(state_of(&c.p.b), before);
    // Calls off: dropped as v3 drops it, never delivered, never receipted.
    c.p.b.config.calls_enabled = false;
    send_video(&c.p.a, &b_hex, &VideoSignal::Request { call_id: id });
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(events(&c.p.b).is_empty());
    assert_eq!(state_of(&c.p.b), before);
    assert!(no_receipt(&c.p.b));
    assert!(crate::test_support::texts(&c.p.b_log).is_empty());
}

#[test]
fn caps_for_a_held_offer_are_kept_until_the_handover() {
    let mut c = video_calls();
    c.p.b.call.handed_over = false;
    let b_hex = c.p.pb.hex.clone();
    c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(c.p.b.call.active.is_none(), "held");
    feed(
        &mut c.p.b,
        Frame::Control(ControlMessage::QueueHandedOver { pad: vec![0; 32] }),
    );
    ring(&mut c.p.b);
    assert!(events(&c.p.b)
        .iter()
        .any(|e| matches!(e, CallEvent::Incoming { video: true, .. })));
}

#[test]
fn ended_event_says_whether_the_call_had_video() {
    let mut c = video_calls();
    let id = connected(&mut c);
    c.p.a.call_end(id, c.t0, c.ms0).unwrap();
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Ended { video: false, .. })));
    let mut c = video_calls();
    let id = connected(&mut c);
    agree(&mut c);
    c.p.a.call_video_set_camera(false, c.t0).unwrap();
    c.p.a.call_end(id, c.t0, c.ms0).unwrap();
    assert!(events(&c.p.a)
        .iter()
        .any(|e| matches!(e, CallEvent::Ended { video: true, .. })));
}

#[test]
fn video_status_events_are_rate_limited_to_one_per_second() {
    let mut c = video_calls();
    connected(&mut c);
    agree(&mut c);
    let vb = c.b_media.video.lock()[0].clone();
    let t = c.t0 + Duration::from_secs(10);
    let mut at = Vec::new();
    for i in 0..12u64 {
        vb.status.lock().banner = if i % 2 == 1 {
            Banner::Mine
        } else {
            Banner::None
        };
        let now = t + Duration::from_millis(250 * i);
        c.p.b.call_tick(now, c.ms0 + 10_000 + 250 * i);
        if !video_states(&events(&c.p.b)).is_empty() {
            at.push(now);
        }
    }
    assert!(at.len() >= 2, "banner changes are polled");
    assert!(
        at.windows(2).all(|w| w[1] - w[0] >= Duration::from_secs(1)),
        "at most one tick-driven event a second"
    );
    // A signalling change goes out at once, right after a tick's event.
    vb.status.lock().banner = Banner::Theirs;
    let now = t + Duration::from_secs(5);
    c.p.b.call_tick(now, c.ms0 + 15_000);
    events(&c.p.b);
    c.p.a.call_video_set_camera(false, now).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    let st = last_video(&events(&c.p.b)).expect("at once");
    assert!(!st.peer_camera);
}

#[test]
fn video_events_carry_the_r19_fields() {
    let st = VideoState {
        available: Availability::Peer,
        agreed: true,
        camera: false,
        peer_camera: true,
        peer_shown: true,
        paused_in: false,
        paused_out: true,
        banner: Banner::Theirs,
        codec: None,
        request_in: true,
    };
    let v: serde_json::Value = serde_json::from_str(
        &CallEvent::Video {
            call_id: CallId([3; 16]),
            state: st,
        }
        .to_json(),
    )
    .unwrap();
    assert_eq!(v["type"], "video");
    assert_eq!(v["call_id"], "03".repeat(16));
    assert_eq!(v["available"], "peer");
    assert_eq!(v["agreed"], true);
    assert_eq!(v["camera"], false);
    assert_eq!(v["peer_camera"], true);
    assert_eq!(v["peer_shown"], true);
    assert_eq!(v["paused_in"], false);
    assert_eq!(v["paused_out"], true);
    assert_eq!(v["banner"], "theirs");
    assert!(v["codec"].is_null());
    assert_eq!(v["request_in"], true);
    let h: serde_json::Value = serde_json::from_str(
        &CallEvent::Video {
            call_id: CallId([3; 16]),
            state: VideoState {
                codec: Some(VideoCodec::H264),
                ..st
            },
        }
        .to_json(),
    )
    .unwrap();
    assert_eq!(h["codec"], "h264");
    for (e, t) in [
        (
            CallEvent::VideoRequest {
                call_id: CallId([3; 16]),
            },
            "video_request",
        ),
        (
            CallEvent::VideoDeclined {
                call_id: CallId([3; 16]),
            },
            "video_declined",
        ),
    ] {
        let v: serde_json::Value = serde_json::from_str(&e.to_json()).unwrap();
        assert_eq!(v["type"], t);
        assert_eq!(v["call_id"], "03".repeat(16));
    }
    for e in [
        CallEvent::Outgoing {
            call_id: CallId([3; 16]),
            peer: "ab".repeat(32),
            video: true,
        },
        CallEvent::Incoming {
            call_id: CallId([3; 16]),
            peer: "ab".repeat(32),
            video: true,
        },
    ] {
        let v: serde_json::Value = serde_json::from_str(&e.to_json()).unwrap();
        assert_eq!(v["video"], true);
    }
}

#[test]
fn a_video_start_failure_or_refusal_keeps_the_call_as_voice() {
    let mut c = video_calls();
    c.b_media.cannot_start_video.store(true, Ordering::SeqCst);
    connected(&mut c);
    agree(&mut c);
    assert_eq!(state_of(&c.p.b).available, Availability::Relay);
    assert!(c.p.b.call.active.is_some());
    // A refusal seen at a tick.
    let va = c.a_media.video.lock()[0].clone();
    va.status.lock().refused = true;
    c.p.a
        .call_tick(c.t0 + Duration::from_secs(20), c.ms0 + 20_000);
    assert_eq!(state_of(&c.p.a).available, Availability::Relay);
    assert!(c.p.a.call.active.is_some());
    assert!(va.stopped.load(Ordering::SeqCst));
    // A's camera was on: B is told it is off (no "Video paused" forever).
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(!state_of(&c.p.b).peer_camera);
    assert!(matches!(
        c.p.a.call_video_set_camera(true, c.t0),
        Err(RChatError::RelayNoVideo)
    ));
}

#[test]
fn an_accept_crossing_a_withdrawal_still_agrees_both_sides() {
    let mut c = video_calls();
    connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    c.p.a.call_video_set_camera(false, c.t0).unwrap(); // not yet delivered
    c.p.b.call_video_respond(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    let (sa, sb) = (state_of(&c.p.a), state_of(&c.p.b));
    assert!(sa.agreed && !sa.camera);
    assert!(sb.agreed && !sb.peer_shown);
    events(&c.p.b);
    heard(&mut c.p.b);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert!(matches!(
        video_signals(&heard(&mut c.p.b))[..],
        [VideoSignal::Camera { on: true, .. }]
    ));
    let evs = events(&c.p.b);
    assert_eq!(requests(&evs), 0);
    assert!(last_video(&evs).unwrap().peer_shown);
}

#[test]
fn only_the_first_caps_of_a_call_counts() {
    let mut c = video_calls();
    let id = connected(&mut c);
    assert_eq!(state_of(&c.p.a).available, Availability::Yes);
    let a_hex = c.p.pa.hex.clone();
    send_video(
        &c.p.b,
        &a_hex,
        &VideoSignal::Caps {
            call_id: id,
            caps: c.p.b.call.video_prefs.caps(false, false),
        },
    );
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(events(&c.p.a).is_empty());
    assert_eq!(state_of(&c.p.a).available, Availability::Yes);
}

#[test]
fn an_unsolicited_accept_never_turns_video_on() {
    let mut c = video_calls();
    let id = connected(&mut c);
    let a_hex = c.p.pa.hex.clone();
    for sig in [
        VideoSignal::Accept { call_id: id },
        VideoSignal::Camera {
            call_id: id,
            on: true,
        },
    ] {
        send_video(&c.p.b, &a_hex, &sig);
    }
    pump(&mut c.p.b_rx, &mut c.p.a);
    let st = state_of(&c.p.a);
    assert!(!st.agreed && !st.peer_shown);
    assert!(c.a_media.video.lock().is_empty(), "no video engine");
}

/// Both phones place calls to each other at once; A's (lower id) wins and
/// B switches to it. Returns once B's Caps and Answer reached A.
fn glare(c: &mut Calls, a_video: bool, b_video: bool) {
    glare_with(c, a_video, b_video, false)
}

/// As `glare`; with `held`, B holds A's Offer and Caps until its queue
/// handover, and switches then.
fn glare_with(c: &mut Calls, a_video: bool, b_video: bool, held: bool) {
    if held {
        c.p.b.call.handed_over = false;
    }
    let (a_hex, b_hex) = (c.p.pa.hex.clone(), c.p.pb.hex.clone());
    c.p.a.call.next_call_id = Some(CallId([1; 16]));
    c.p.b.call.next_call_id = Some(CallId([2; 16]));
    if a_video {
        c.p.a.call_place_video(&b_hex, c.t0, c.ms0).unwrap();
    } else {
        c.p.a.call_place(&b_hex, c.t0, c.ms0).unwrap();
    }
    if b_video {
        c.p.b.call_place_video(&a_hex, c.t0, c.ms0).unwrap();
    } else {
        c.p.b.call_place(&a_hex, c.t0, c.ms0).unwrap();
    }
    let a_out = drain(&mut c.p.a_rx);
    let b_out = drain(&mut c.p.b_rx);
    for (to, out) in [(&mut c.p.a, b_out), (&mut c.p.b, a_out)] {
        for f in out {
            if let Some(p) = RelayPacket::decode(&f) {
                feed(to, Frame::Relay(p));
            }
        }
    }
    if held {
        assert!(c.p.b.call.held.len() == 1, "A's Offer is held");
        feed(
            &mut c.p.b,
            Frame::Control(ControlMessage::QueueHandedOver { pad: vec![0; 32] }),
        );
    }
    pump(&mut c.p.b_rx, &mut c.p.a);
    drain(&mut c.p.a_rx);
}

#[test]
fn header_video_glare_with_both_video_shows_both_ways() {
    let mut c = video_calls();
    glare(&mut c, true, true);
    for st in [state_of(&c.p.a), state_of(&c.p.b)] {
        assert!(st.agreed && st.camera && st.peer_camera && st.peer_shown);
    }
    for s in [&c.a_media, &c.b_media] {
        let v = s.video.lock()[0].clone();
        assert!(v.sending.load(Ordering::SeqCst) && v.receiving.load(Ordering::SeqCst));
    }
}

#[test]
fn header_video_glare_with_one_voice_call_stays_voice_with_both_cameras_off() {
    for (a_video, b_video) in [(false, true), (true, false)] {
        let mut c = video_calls();
        glare(&mut c, a_video, b_video);
        for st in [state_of(&c.p.a), state_of(&c.p.b)] {
            assert!(!st.agreed && !st.camera && !st.peer_camera);
            assert_eq!(st.available, Availability::Yes);
        }
        assert!(c.a_media.video.lock().is_empty() && c.b_media.video.lock().is_empty());
        // A later Request and Accept show only the requester.
        events(&c.p.a);
        events(&c.p.b);
        agree(&mut c);
        let (va, vb) = (
            c.a_media.video.lock()[0].clone(),
            c.b_media.video.lock()[0].clone(),
        );
        assert!(va.sending.load(Ordering::SeqCst) && !va.receiving.load(Ordering::SeqCst));
        assert!(!vb.sending.load(Ordering::SeqCst) && vb.receiving.load(Ordering::SeqCst));
    }
}

#[test]
fn glare_with_no_caps_from_the_winner_stops_the_switchers_camera_at_connected() {
    let mut c = video_calls();
    c.p.a.call.ignore_video = true; // the winner sends no Caps
    glare(&mut c, false, true);
    assert!(state_of(&c.p.b).camera, "still waiting for Caps");
    c.b_media.media.lock()[0].status.lock().first_frame = true;
    c.p.b.call_tick(c.t0 + Duration::from_secs(1), c.ms0 + 1000);
    assert!(!state_of(&c.p.b).camera);
}

#[test]
fn a_request_that_cannot_be_met_gets_not_now() {
    let mut c = video_calls();
    c.p.b.call.video_prefs.set(0, false, false);
    let id = connected(&mut c);
    let b_hex = c.p.pb.hex.clone();
    send_video(&c.p.a, &b_hex, &VideoSignal::Request { call_id: id });
    pump(&mut c.p.a_rx, &mut c.p.b);
    assert_eq!(requests(&events(&c.p.b)), 0);
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(matches!(
        video_signals(&heard(&mut c.p.a))[..],
        [VideoSignal::Decline { .. }]
    ));
}

#[test]
fn a_peer_cannot_flood_the_event_queue() {
    let mut c = video_calls();
    let id = connected(&mut c);
    let b_hex = c.p.pb.hex.clone();
    for _ in 0..20 {
        send_video(&c.p.a, &b_hex, &VideoSignal::Request { call_id: id });
        send_video(
            &c.p.a,
            &b_hex,
            &VideoSignal::Camera {
                call_id: id,
                on: false,
            },
        );
    }
    send_video(&c.p.a, &b_hex, &VideoSignal::Request { call_id: id });
    pump(&mut c.p.a_rx, &mut c.p.b);
    let evs = events(&c.p.b);
    assert_eq!(requests(&evs), 1, "one video_request event per 30 s");
    assert!(evs.len() <= 3, "video events coalesce: {evs:?}");
    assert!(
        last_video(&evs).unwrap().request_in,
        "the state stays exact"
    );
}

#[test]
fn header_video_glare_through_a_held_offer_settles_like_a_live_one() {
    let mut c = video_calls();
    glare_with(&mut c, true, true, true);
    for st in [state_of(&c.p.a), state_of(&c.p.b)] {
        assert!(st.agreed && st.camera && st.peer_shown);
    }
    for (a_video, b_video) in [(false, true), (true, false)] {
        let mut c = video_calls();
        glare_with(&mut c, a_video, b_video, true);
        for st in [state_of(&c.p.a), state_of(&c.p.b)] {
            assert!(!st.agreed && !st.camera && !st.peer_camera);
        }
        assert!(c.b_media.video.lock().is_empty());
    }
}

#[test]
fn the_automatic_not_now_goes_once_per_call() {
    let mut c = video_calls();
    c.p.b.call.video_prefs.set(0, false, false);
    let id = connected(&mut c);
    let b_hex = c.p.pb.hex.clone();
    for _ in 0..5 {
        send_video(&c.p.a, &b_hex, &VideoSignal::Request { call_id: id });
    }
    pump(&mut c.p.a_rx, &mut c.p.b);
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert_eq!(video_signals(&heard(&mut c.p.a)).len(), 1);
}

#[test]
fn an_accept_after_not_now_needs_a_fresh_request() {
    let mut c = video_calls();
    let id = connected(&mut c);
    c.p.a.call_video_set_camera(true, c.t0).unwrap();
    pump(&mut c.p.a_rx, &mut c.p.b);
    c.p.b.call_video_respond(false, c.t0).unwrap();
    pump(&mut c.p.b_rx, &mut c.p.a);
    let a_hex = c.p.pa.hex.clone();
    send_video(&c.p.b, &a_hex, &VideoSignal::Accept { call_id: id });
    pump(&mut c.p.b_rx, &mut c.p.a);
    assert!(!state_of(&c.p.a).agreed);
    assert!(c.a_media.video.lock().is_empty());
}
