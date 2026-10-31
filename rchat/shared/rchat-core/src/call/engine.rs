//! One call's audio engine (spec §6): PCM in → Opus → sealed frame → both
//! call connections; frames in → first copy wins → playback buffer → PCM
//! out. One 20 ms buffer each way; the exchange path allocates nothing.
//! The send and receive sides have their own locks, and the call
//! connections run on their own tasks, so push and pull never wait on the
//! network or on the client lock. Push takes the receive lock briefly (to
//! read "Poor connection") before, not while, it holds the send lock;
//! `status` takes only the receive lock.
//!
//! Nonce safety: the engine owns the call's one `FrameSealer` for its whole
//! life. The connections carry already sealed bytes and are restarted
//! without touching it, so a reconnect can't reset or repeat `seq`. The
//! sealer and opener (and with them the keys) are dropped at `stop`.

use super::codec::{Codec, CodecError};
use super::frame::{FrameError, FrameOpener, FrameSealer, MAX_WIRE_FRAME};
use super::keys::CallKeys;
use super::lanes::{LaneConfig, LaneSink, Lanes};
use super::playout::{BitrateStepper, Playout};
use super::video::{is_stream_frame, STREAM_CONTROL};
use super::{
    CallId, CONNECT_GIVE_UP, FRAME_SAMPLES, MAX_OPUS_BYTES, RECONNECT_GIVE_UP, SILENT_AFTER,
    STALL_AFTER,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// "Poor connection" needs this many played frames behind the share (1 s).
const POOR_MIN_FRAMES: usize = 50;
/// The engine's own give-up comes this long after the connections' (their
/// last retry sleep is 2 s), so a refusal is reported by the connection first.
const GIVE_UP_GRACE: Duration = Duration::from_secs(3);
const WATCH_TICK: Duration = Duration::from_millis(250);

pub struct MediaStart {
    pub call_id: CallId,
    /// 0 caller, 1 callee (the relay's side, D1).
    pub role: u8,
    pub keys: CallKeys,
    pub lane: LaneConfig,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaStatus {
    pub concealed_pct: u32,
    pub connections: u8,
    pub poor: bool,
    pub reconnecting: bool,
    pub first_frame: bool,
    pub silent_for: Duration,
    /// The relay kept refusing the token, or failed its identity pin.
    pub refused: bool,
    /// Part of `refused`: the relay failed its identity pin.
    pub pin_failed: bool,
    /// No media came in time (or it stopped for good): the engine stopped
    /// the connections.
    pub gave_up: bool,
    pub exhausted: bool,
}

struct TxSide {
    codec: Box<dyn Codec>,
    /// `None` once the call has stopped (the key is wiped).
    sealer: Option<FrameSealer>,
    muted: bool,
    stepper: BitrateStepper,
    packet: [u8; MAX_OPUS_BYTES],
    wire: [u8; MAX_WIRE_FRAME],
    /// For `start_seq` (the 2^63 test) to rebuild the sealer with the same key.
    #[cfg(test)]
    send_key: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    call_id: CallId,
}

struct RxSide {
    codec: Box<dyn Codec>,
    /// `None` once the call has stopped (the key is wiped).
    opener: Option<FrameOpener>,
    playout: Playout,
    /// Last authenticated frame per lane, fresh or a repeat of the other
    /// lane's: it proves that lane's path works. Used only to pick a
    /// single lane to restart.
    heard: [Option<Instant>; 2],
    /// Last fresh frame on either lane: the media itself. Only fresh frames
    /// drive `first`, silence, "Reconnecting" and the give-up, so a relay
    /// replaying old authentic frames can't keep a dead call alive.
    last_fresh: Option<Instant>,
    /// When each lane last came up, and was last restarted by the watchdog.
    up_at: [Option<Instant>; 2],
    restart_at: [Option<Instant>; 2],
    first: Option<Instant>,
    lane_up: [bool; 2],
    opened: [u8; MAX_OPUS_BYTES],
}

/// Receives the video call's control frames (stream `STREAM_CONTROL`) that
/// arrive on the audio connections; the video side opens them.
pub trait ControlSink: Send + Sync {
    fn on_control(&self, frame: &[u8], at: Instant);
}

/// What video needs of the audio engine: the control channel on the audio
/// connections and the audio's own health.
pub trait AudioLink: Send + Sync {
    fn send_control(&self, frame: &[u8]);
    fn set_control_sink(&self, sink: Option<Weak<dyn ControlSink>>);
    /// Playout depth in ms (R21).
    fn audio_depth_ms(&self) -> u64;
    fn audio_lanes_dropped(&self) -> u64;
    fn audio_poor(&self) -> bool;
    /// Share of the peer's audio this phone concealed (0-100), for the
    /// health note (R15) the peer's resume check reads (R11).
    fn audio_concealed_pct(&self) -> u8;
}

struct RxShared {
    rx: Mutex<RxSide>,
    control: Mutex<Option<Weak<dyn ControlSink>>>,
    /// Once per call, however many lanes report.
    refused: AtomicBool,
    pin_failed: AtomicBool,
}

impl LaneSink for RxShared {
    fn on_frame(&self, lane: u8, frame: &[u8], at: Instant) {
        // Length first, then the AEAD: nothing else sees an unauthenticated frame.
        if frame.len() > MAX_WIRE_FRAME {
            return;
        }
        if is_stream_frame(frame) == Some(STREAM_CONTROL) {
            // Not audio: never reaches the audio opener. The sink is called
            // with no engine lock held.
            let sink = self.control.lock().as_ref().and_then(Weak::upgrade);
            if let Some(sink) = sink {
                sink.on_control(frame, at);
            }
            return;
        }
        let mut guard = self.rx.lock();
        let r = &mut *guard;
        let Some(opener) = r.opener.as_mut() else {
            return;
        };
        if let Ok((seq, n, fresh)) = opener.open_counting_repeats(frame, &mut r.opened) {
            // A repeat still times its lane (the restart mark and the lane's
            // jitter, D18; the buffer itself ignores it), but only a fresh
            // frame is media.
            r.heard[usize::from(lane & 1)] = Some(at);
            if fresh {
                r.last_fresh = Some(at);
                r.first.get_or_insert(at);
            }
            r.playout.on_frame(lane, seq, &r.opened[..n], at);
        }
    }

    fn on_peer(&self, _lane: u8, _present: bool) {}

    fn on_lane(&self, lane: u8, up: bool) {
        let mut r = self.rx.lock();
        let l = usize::from(lane & 1);
        r.lane_up[l] = up;
        if up {
            r.up_at[l] = Some(Instant::now());
        }
    }

    fn on_refused(&self) {
        self.refused.store(true, Ordering::SeqCst);
    }

    fn on_relay_identity_failed(&self) {
        self.pin_failed.store(true, Ordering::SeqCst);
        self.refused.store(true, Ordering::SeqCst);
    }
}

/// What the watchdog decided at one tick.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub restart: [bool; 2],
    pub give_up: bool,
}

pub struct CallMedia {
    tx: Mutex<TxSide>,
    rx: Arc<RxShared>,
    /// Set by push when `seq` would reach 2^63; read by `status` without
    /// the send lock.
    exhausted: AtomicBool,
    stopped: AtomicBool,
    gave_up: AtomicBool,
    started: Instant,
    give_up: Duration,
    lanes: Lanes,
}

/// The encoder and decoder of one call: libopus with `calls-codec` (D32).
#[cfg(feature = "calls-codec")]
fn codecs() -> Result<(Box<dyn Codec>, Box<dyn Codec>), CodecError> {
    use super::codec::OpusCodec;
    Ok((Box::new(OpusCodec::new()?), Box::new(OpusCodec::new()?)))
}

/// Built without `calls-codec` (the relay's production build): no calls.
#[cfg(not(feature = "calls-codec"))]
fn codecs() -> Result<(Box<dyn Codec>, Box<dyn Codec>), CodecError> {
    Err(CodecError::Unavailable)
}

fn poor_reported(p: &Playout) -> bool {
    p.window_frames() >= POOR_MIN_FRAMES && p.poor()
}

#[cfg(any(test, feature = "test-hooks"))]
impl CallMedia {
    /// Test hook (network simulator): frames played by kind.
    pub fn play_totals(&self) -> super::playout::PlayTotals {
        self.rx.rx.lock().playout.totals()
    }

    /// Test hook: the seq of the frame the last pull played, if any.
    pub fn last_played_seq(&self) -> Option<u64> {
        self.rx.rx.lock().playout.played_seq()
    }
}

impl CallMedia {
    /// Must run inside the tokio runtime (the call connections are spawned
    /// onto it); from any other thread it is an error, not a panic.
    pub fn start(s: MediaStart) -> Result<Arc<CallMedia>, CodecError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(CodecError::NoRuntime);
        }
        let (enc, dec) = codecs()?;
        Ok(Self::start_with(s, enc, dec, CONNECT_GIVE_UP))
    }

    /// `give_up`: how long a call connection retries refused joins (D34).
    /// Inside the tokio runtime only (`start` checks).
    pub(crate) fn start_with(
        s: MediaStart,
        enc: Box<dyn Codec>,
        dec: Box<dyn Codec>,
        give_up: Duration,
    ) -> Arc<CallMedia> {
        let rx = Arc::new(RxShared {
            rx: Mutex::new(RxSide {
                codec: dec,
                opener: Some(FrameOpener::new(&s.keys.recv, s.call_id)),
                playout: Playout::new(),
                heard: [None, None],
                last_fresh: None,
                up_at: [None, None],
                restart_at: [None, None],
                first: None,
                lane_up: [false, false],
                opened: [0; MAX_OPUS_BYTES],
            }),
            control: Mutex::new(None),
            refused: AtomicBool::new(false),
            pin_failed: AtomicBool::new(false),
        });
        let lanes = Lanes::start_with_give_up(
            s.lane.clone(),
            Zeroizing::new(*s.keys.relay_token),
            s.role,
            rx.clone(),
            give_up,
        );
        let media = Arc::new(CallMedia {
            tx: Mutex::new(TxSide {
                codec: enc,
                sealer: Some(FrameSealer::new(&s.keys.send, s.call_id)),
                muted: false,
                stepper: BitrateStepper::new(),
                packet: [0; MAX_OPUS_BYTES],
                wire: [0; MAX_WIRE_FRAME],
                #[cfg(test)]
                send_key: Zeroizing::new(*s.keys.send),
                #[cfg(test)]
                call_id: s.call_id,
            }),
            rx,
            exhausted: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            gave_up: AtomicBool::new(false),
            started: Instant::now(),
            give_up,
            lanes,
        });
        // `s` (and its keys) drops here, wiping them.
        tokio::spawn(watch(Arc::downgrade(&media)));
        media
    }

    pub fn push_pcm(&self, pcm: &[i16]) -> usize {
        self.push_pcm_at(pcm, Instant::now())
    }

    pub(crate) fn push_pcm_at(&self, pcm: &[i16], now: Instant) -> usize {
        let Ok(input) = <&[i16; FRAME_SAMPLES]>::try_from(pcm) else {
            return 0;
        };
        if self.exhausted.load(Ordering::Acquire) {
            return 0;
        }
        // The receive lock is released at the end of this statement, before
        // the send lock is taken: the two are never held together.
        let poor = poor_reported(&self.rx.rx.lock().playout);
        let mut guard = self.tx.lock();
        let t = &mut *guard;
        let Some(sealer) = t.sealer.as_mut() else {
            return 0; // stopped
        };
        if let Some(bps) = t.stepper.update(poor, now) {
            let _ = t.codec.set_bitrate(bps);
        }
        // Muted: encoded silence at the same rate (D17).
        let mut frame = [0i16; FRAME_SAMPLES];
        if !t.muted {
            frame.copy_from_slice(input);
        }
        let Ok(n) = t.codec.encode(&frame, &mut t.packet) else {
            return FRAME_SAMPLES;
        };
        match sealer.seal(&t.packet[..n], &mut t.wire) {
            Ok(len) => self.lanes.send(&t.wire[..len]),
            Err(FrameError::SeqExhausted) => {
                self.exhausted.store(true, Ordering::Release);
                return 0;
            }
            Err(FrameError::TooLarge) => {}
        }
        FRAME_SAMPLES
    }

    pub fn pull_pcm(&self, out: &mut [i16]) -> usize {
        let Ok(out) = <&mut [i16; FRAME_SAMPLES]>::try_from(out) else {
            return 0;
        };
        if self.stopped.load(Ordering::Acquire) {
            return 0;
        }
        let mut guard = self.rx.rx.lock();
        let r = &mut *guard;
        r.playout.next_pcm(r.codec.as_mut(), out, Instant::now());
        FRAME_SAMPLES
    }

    pub fn set_muted(&self, muted: bool) {
        self.tx.lock().muted = muted;
    }

    /// A sealed control frame on both audio connections.
    pub(crate) fn send_control(&self, frame: &[u8]) {
        if frame.len() <= MAX_WIRE_FRAME && !self.stopped.load(Ordering::Acquire) {
            self.lanes.send_control(frame);
        }
    }

    /// Held weakly, so a video side that holds this engine forms no cycle.
    pub(crate) fn set_control_sink(&self, sink: Option<Weak<dyn ControlSink>>) {
        *self.rx.control.lock() = sink;
    }

    /// Playout depth in ms.
    pub(crate) fn audio_depth_ms(&self) -> u64 {
        self.rx.rx.lock().playout.depth_ms()
    }

    pub(crate) fn audio_lanes_dropped(&self) -> u64 {
        self.lanes.dropped_total()
    }

    pub fn status(&self, now: Instant) -> MediaStatus {
        let r = self.rx.rx.lock();
        let silent_for = r
            .last_fresh
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        MediaStatus {
            concealed_pct: r.playout.concealed_pct(),
            connections: r.lane_up.iter().filter(|u| **u).count() as u8,
            poor: poor_reported(&r.playout),
            reconnecting: r.first.is_some() && silent_for >= SILENT_AFTER,
            first_frame: r.first.is_some(),
            silent_for,
            refused: self.rx.refused.load(Ordering::SeqCst),
            pin_failed: self.rx.pin_failed.load(Ordering::SeqCst),
            gave_up: self.gave_up.load(Ordering::Acquire),
            exhausted: self.exhausted.load(Ordering::Acquire),
        }
    }

    /// Stops the connections and wipes the keys. Safe to call twice, and
    /// late events from the connections are harmless.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.lanes.stop();
        self.tx.lock().sealer = None;
        self.rx.rx.lock().opener = None;
    }

    /// One watchdog tick (spec §6): a lane that is up but has received
    /// nothing for 2 s while the other still receives is restarted; with
    /// both silent for 3 s both are restarted (the status already reads
    /// Reconnecting), at most once per 3 s. Gives up when no media came by
    /// the connections' give-up plus a grace, or when it has stopped for
    /// `RECONNECT_GIVE_UP` plus the grace; never while a connection is
    /// still connecting or retrying refused joins (a slow connect delays
    /// its refusal past the timer: the refusal is reported, not a give-up).
    pub(crate) fn watchdog(&self, now: Instant) -> Verdict {
        let joining = self.lanes.joining();
        let mut r = self.rx.rx.lock();
        let none = Verdict {
            restart: [false; 2],
            give_up: false,
        };
        let since = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t));
        let Some(last_any) = r.last_fresh else {
            let waited = now.saturating_duration_since(self.started);
            return Verdict {
                give_up: !joining && waited >= self.give_up + GIVE_UP_GRACE,
                ..none
            };
        };
        if !joining && now.saturating_duration_since(last_any) >= RECONNECT_GIVE_UP + GIVE_UP_GRACE
        {
            return Verdict {
                give_up: true,
                ..none
            };
        }
        let newest_restart = r.restart_at.iter().flatten().max().copied();
        let both_quiet = since(Some(last_any.max(newest_restart.unwrap_or(last_any))));
        if both_quiet.is_some_and(|q| q >= SILENT_AFTER) {
            r.restart_at = [Some(now); 2];
            return Verdict {
                restart: [true; 2],
                ..none
            };
        }
        let quiet = |r: &RxSide, i: usize| {
            let mark = [r.heard[i], r.up_at[i], r.restart_at[i]]
                .into_iter()
                .flatten()
                .max();
            since(mark)
        };
        let restart = [0usize, 1].map(|l| {
            r.lane_up[l]
                && quiet(&r, l).is_some_and(|q| q >= STALL_AFTER)
                && quiet(&r, 1 - l).is_some_and(|q| q < STALL_AFTER)
        });
        for (l, go) in restart.into_iter().enumerate() {
            if go {
                r.restart_at[l] = Some(now);
            }
        }
        Verdict { restart, ..none }
    }

    #[cfg(test)]
    pub(crate) fn lanes_stopped(&self) -> bool {
        self.lanes.is_stopped()
    }

    #[cfg(test)]
    pub(crate) fn sink(&self) -> Arc<dyn LaneSink> {
        self.rx.clone()
    }

    #[cfg(test)]
    pub(crate) fn start_seq(&self, seq: u64) {
        let mut guard = self.tx.lock();
        let t = &mut *guard;
        t.sealer = Some(FrameSealer::starting_at(&t.send_key, t.call_id, seq));
    }
}

impl super::machine::MediaControl for CallMedia {
    fn push_pcm(&self, pcm: &[i16]) -> usize {
        CallMedia::push_pcm(self, pcm)
    }
    fn pull_pcm(&self, out: &mut [i16]) -> usize {
        CallMedia::pull_pcm(self, out)
    }
    fn set_muted(&self, muted: bool) {
        CallMedia::set_muted(self, muted)
    }
    fn status(&self, now: Instant) -> MediaStatus {
        CallMedia::status(self, now)
    }
    fn stop(&self) {
        CallMedia::stop(self)
    }
    fn audio_link(self: Arc<Self>) -> Option<Arc<dyn AudioLink>> {
        Some(self)
    }
}

impl AudioLink for CallMedia {
    fn send_control(&self, frame: &[u8]) {
        CallMedia::send_control(self, frame)
    }
    fn set_control_sink(&self, sink: Option<Weak<dyn ControlSink>>) {
        CallMedia::set_control_sink(self, sink)
    }
    fn audio_depth_ms(&self) -> u64 {
        CallMedia::audio_depth_ms(self)
    }
    fn audio_lanes_dropped(&self) -> u64 {
        CallMedia::audio_lanes_dropped(self)
    }
    fn audio_poor(&self) -> bool {
        poor_reported(&self.rx.rx.lock().playout)
    }
    fn audio_concealed_pct(&self) -> u8 {
        self.rx.rx.lock().playout.concealed_pct().min(100) as u8
    }
}

impl Drop for CallMedia {
    fn drop(&mut self) {
        self.lanes.stop();
    }
}

/// Runs the watchdog until the call stops, is refused or gives up. Holds the
/// call only weakly, so dropping it ends the task.
async fn watch(media: std::sync::Weak<CallMedia>) {
    let mut tick = tokio::time::interval(WATCH_TICK);
    loop {
        tick.tick().await;
        let Some(m) = media.upgrade() else {
            return;
        };
        if m.stopped.load(Ordering::Acquire) {
            return;
        }
        if m.rx.refused.load(Ordering::SeqCst) {
            m.lanes.stop(); // the call fails once; no more retries
            return;
        }
        let v = m.watchdog(Instant::now());
        for (lane, restart) in v.restart.into_iter().enumerate() {
            if restart {
                m.lanes.restart(lane as u8);
            }
        }
        if v.give_up {
            m.gave_up.store(true, Ordering::Release);
            m.lanes.stop();
            return;
        }
    }
}

/// A stand-in codec for the tests that don't need real Opus (they run
/// without the `calls-codec` feature too): a 3-byte packet per frame,
/// silence out.
#[cfg(test)]
pub(crate) struct NullCodec;

#[cfg(test)]
impl Codec for NullCodec {
    fn encode(&mut self, _pcm: &[i16; FRAME_SAMPLES], out: &mut [u8]) -> Result<usize, CodecError> {
        out[..3].copy_from_slice(&[0xF8, 0xFF, 0xFE]);
        Ok(3)
    }
    fn decode(&mut self, _packet: &[u8], out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
        out.fill(0);
        Ok(())
    }
    fn decode_fec(
        &mut self,
        _next: &[u8],
        out: &mut [i16; FRAME_SAMPLES],
    ) -> Result<(), CodecError> {
        out.fill(0);
        Ok(())
    }
    fn conceal(&mut self, out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
        out.fill(0);
        Ok(())
    }
    fn set_bitrate(&mut self, _bps: i32) -> Result<(), CodecError> {
        Ok(())
    }
    fn bitrate(&self) -> i32 {
        super::BITRATE_NORMAL
    }
}

#[cfg(test)]
impl CallMedia {
    /// Test constructor: a call's audio engine with the null codec, for the
    /// tests here and the video engine's (inside the tokio runtime).
    pub(crate) fn start_null(s: MediaStart, give_up: Duration) -> Arc<CallMedia> {
        Self::start_with(s, Box::new(NullCodec), Box::new(NullCodec), give_up)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::test_relay::{fake_relay, lane_config, Mode};
    use crate::call::{CallId, MAX_SEQ};

    fn start_null(s: MediaStart, give_up: Duration) -> Arc<CallMedia> {
        CallMedia::start_null(s, give_up)
    }

    /// Loopback keys: with an echoing relay a phone hears itself, so send == recv.
    fn loop_keys() -> CallKeys {
        CallKeys {
            send: Zeroizing::new([0x42; 32]),
            recv: Zeroizing::new([0x42; 32]),
            relay_token: Zeroizing::new([0x24; 32]),
        }
    }

    fn start(id: u8, role: u8, url: &str) -> MediaStart {
        MediaStart {
            call_id: CallId([id; 16]),
            role,
            keys: loop_keys(),
            lane: lane_config(url),
        }
    }

    #[derive(Default)]
    struct CtlRec {
        got: Mutex<Vec<Vec<u8>>>,
    }

    impl ControlSink for CtlRec {
        fn on_control(&self, frame: &[u8], _at: Instant) {
            self.got.lock().push(frame.to_vec());
        }
    }

    #[tokio::test]
    async fn control_frames_go_on_both_audio_lanes_and_reach_the_control_sink() {
        let (url, _seen) = fake_relay(Mode::Pair).await;
        let keys = |send: u8, recv: u8| CallKeys {
            send: Zeroizing::new([send; 32]),
            recv: Zeroizing::new([recv; 32]),
            relay_token: Zeroizing::new([0x24; 32]),
        };
        let mk = |role: u8, send: u8, recv: u8| MediaStart {
            call_id: CallId([9; 16]),
            role,
            keys: keys(send, recv),
            lane: lane_config(&url),
        };
        let a = start_null(mk(0, 0x11, 0x22), CONNECT_GIVE_UP);
        let b = start_null(mk(1, 0x22, 0x11), CONNECT_GIVE_UP);
        let rec = Arc::new(CtlRec::default());
        let dynrec: Arc<dyn ControlSink> = rec.clone();
        b.set_control_sink(Some(Arc::downgrade(&dynrec)));
        let up = |m: &CallMedia| m.status(Instant::now()).connections == 2;
        let end = Instant::now() + Duration::from_secs(5);
        while !(up(&a) && up(&b)) {
            assert!(Instant::now() < end, "lanes up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await; // MediaJoined both ways
        let mut frame = vec![
            crate::protocol::FRAME_TYPE_MEDIA,
            super::super::video::STREAM_CONTROL,
        ];
        frame.extend_from_slice(&[7u8; 40]);
        a.send_control(&frame);
        let end = Instant::now() + Duration::from_secs(5);
        while rec.got.lock().len() < 2 {
            assert!(Instant::now() < end, "both copies reach the sink");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rec.got.lock().iter().all(|f| *f == frame));
        assert_eq!(b.play_totals().audio, 0, "control is not audio");
        assert_eq!(a.audio_lanes_dropped(), 0);
        a.stop();
        b.stop();
    }

    #[cfg(feature = "calls-codec")]
    fn tone(hz: f64, frame: usize) -> [i16; FRAME_SAMPLES] {
        core::array::from_fn(|i| {
            let t = (frame * FRAME_SAMPLES + i) as f64 / 48_000.0;
            ((2.0 * std::f64::consts::PI * hz * t).sin() * 8000.0) as i16
        })
    }

    /// Goertzel power of `hz` in `pcm`, normalised by its total power
    /// (about 1.0 for a pure tone, about 0 for silence or another pitch).
    #[cfg(feature = "calls-codec")]
    fn tone_share(pcm: &[i16], hz: f64) -> f64 {
        let k = 2.0 * (2.0 * std::f64::consts::PI * hz / 48_000.0).cos();
        let (mut s1, mut s2, mut total) = (0.0f64, 0.0f64, 0.0f64);
        for x in pcm {
            let x = f64::from(*x);
            let s = x + k * s1 - s2;
            s2 = s1;
            s1 = s;
            total += x * x;
        }
        let power = s1 * s1 + s2 * s2 - k * s1 * s2;
        power / (total * pcm.len() as f64 / 2.0).max(1.0)
    }

    /// Judged frame by frame, so one concealed or skipped frame (a phase
    /// jump) can't sink the whole check: at least 60 of the last 75 frames
    /// must be mostly the 440 Hz tone.
    #[cfg(feature = "calls-codec")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tone_goes_out_and_comes_back_through_an_echoing_relay() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let media = CallMedia::start(start(1, 0, &url)).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await; // both lanes joined
        let mut toned = 0;
        let mut out = [0i16; FRAME_SAMPLES];
        for f in 0..150 {
            assert_eq!(media.push_pcm(&tone(440.0, f)), FRAME_SAMPLES);
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(media.pull_pcm(&mut out), FRAME_SAMPLES);
            if f >= 75 && tone_share(&out, 440.0) > 0.5 {
                toned += 1;
            }
        }
        assert!(toned >= 60, "440 Hz came back in {toned} of 75 frames");
        let st = media.status(Instant::now());
        assert!(
            st.first_frame && st.connections == 2 && !st.reconnecting,
            "{st:?}"
        );
        media.stop();
    }

    #[cfg(feature = "calls-codec")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn muted_sends_silence_at_the_same_rate() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let media = CallMedia::start(start(2, 0, &url)).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        media.set_muted(true);
        let mut heard = Vec::new();
        let mut out = [0i16; FRAME_SAMPLES];
        for f in 0..100 {
            media.push_pcm(&tone(440.0, f));
            tokio::time::sleep(Duration::from_millis(20)).await;
            media.pull_pcm(&mut out);
            if f >= 50 {
                heard.extend_from_slice(&out);
            }
        }
        let sent = seen.lock().media_in;
        assert!(
            sent >= 180,
            "frames still flow on both lanes while muted: {sent}"
        );
        assert!(tone_share(&heard, 440.0) < 0.05, "nothing of the tone");
    }

    #[cfg(feature = "calls-codec")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn push_and_pull_allocate_nothing() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let media = CallMedia::start(start(3, 0, &url)).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let input = tone(300.0, 0);
        let mut out = [0i16; FRAME_SAMPLES];
        for _ in 0..10 {
            media.push_pcm(&input);
            media.pull_pcm(&mut out);
        }
        let bytes = crate::alloc_probe::bytes_allocated(|| {
            for _ in 0..50 {
                media.push_pcm(&input);
                media.pull_pcm(&mut out);
            }
        });
        assert_eq!(
            bytes, 0,
            "the PCM exchange path allocates nothing (spec §6)"
        );
    }

    #[cfg(not(feature = "calls-codec"))]
    #[test]
    fn without_the_codec_feature_a_call_cannot_start() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        assert!(matches!(
            CallMedia::start(start(8, 0, "ws://127.0.0.1:9/")),
            Err(CodecError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn silence_on_both_lanes_for_3_s_is_reconnecting() {
        let (url, _seen) = fake_relay(Mode::Refuse).await; // no media ever arrives from the network
        let media = start_null(start(4, 1, &url), CONNECT_GIVE_UP);
        // Feed one real frame through the sink as if it came on lane 0.
        let mut sealer = crate::call::frame::FrameSealer::new(&[0x42; 32], CallId([4; 16]));
        let mut wire = [0u8; crate::call::frame::MAX_WIRE_FRAME];
        let n = sealer.seal(&[0xF8, 0xFF, 0xFE], &mut wire).unwrap();
        let t0 = Instant::now();
        media.sink().on_frame(0, &wire[..n], t0);
        assert!(media.status(t0).first_frame);
        assert!(!media.status(t0 + Duration::from_millis(2900)).reconnecting);
        let st = media.status(t0 + SILENT_AFTER);
        assert!(st.reconnecting && st.silent_for >= SILENT_AFTER, "{st:?}");
        media.stop();
    }

    #[tokio::test]
    async fn a_call_at_2_pow_63_frames_is_exhausted() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let media = start_null(start(5, 0, &url), CONNECT_GIVE_UP);
        media.start_seq(MAX_SEQ - 1);
        let pcm = [0i16; FRAME_SAMPLES];
        assert_eq!(media.push_pcm(&pcm), FRAME_SAMPLES);
        assert_eq!(media.push_pcm(&pcm), 0);
        assert!(media.status(Instant::now()).exhausted);
        media.stop();
    }

    /// D34: refusals are retried until the give-up, then reported. A 1.5 s
    /// give-up keeps the test short; production uses `CONNECT_GIVE_UP`.
    #[tokio::test]
    async fn the_relay_refusing_the_token_is_reported() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(6, 0, &url), Duration::from_millis(1500));
        let begun = Instant::now();
        let end = begun + Duration::from_secs(8);
        while !media.status(Instant::now()).refused {
            assert!(Instant::now() < end, "refusal not reported");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            begun.elapsed() >= Duration::from_millis(1500),
            "not before the give-up"
        );
    }

    #[test]
    fn wrong_sized_buffers_are_refused_not_a_panic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let media = start_null(start(7, 0, "ws://127.0.0.1:9/"), CONNECT_GIVE_UP);
        assert_eq!(media.push_pcm(&[0; 100]), 0);
        assert_eq!(media.pull_pcm(&mut [0; 2000]), 0);
        media.stop();
    }

    /// A sealed frame with this seq from the peer's sealer (loop keys).
    fn sealed(id: u8, seq_pos: u64) -> Vec<u8> {
        let mut sealer = crate::call::frame::FrameSealer::new(&[0x42; 32], CallId([id; 16]));
        let mut wire = [0u8; MAX_WIRE_FRAME];
        let mut n = 0;
        for _ in 0..=seq_pos {
            n = sealer.seal(&[0xF8, 0xFF, 0xFE], &mut wire).unwrap();
        }
        wire[..n].to_vec()
    }

    #[tokio::test]
    async fn the_sink_drops_oversize_and_forged_frames_before_anything_else() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(10, 0, &url), CONNECT_GIVE_UP);
        let t0 = Instant::now();
        let good = sealed(10, 0);
        let mut oversize = good.clone();
        oversize.resize(MAX_WIRE_FRAME + 1, 0);
        media.sink().on_frame(0, &oversize, t0);
        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        media.sink().on_frame(0, &forged, t0);
        media.sink().on_frame(1, &[0x05; 4], t0);
        assert!(
            !media.status(t0).first_frame,
            "nothing unauthenticated counts as media"
        );
        media.sink().on_frame(0, &good, t0);
        assert!(media.status(t0).first_frame);
        media.stop();
    }

    #[tokio::test]
    async fn a_relay_pin_failure_is_reported_apart_from_a_token_refusal() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let mut s = start(11, 0, &url);
        s.lane.relay_pin = crate::relay_pin::encode_pin(&[9; 32]);
        let media = start_null(s, CONNECT_GIVE_UP);
        let end = Instant::now() + Duration::from_secs(5);
        while !media.status(Instant::now()).refused {
            assert!(Instant::now() < end, "pin failure not reported");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let st = media.status(Instant::now());
        assert!(st.pin_failed, "{st:?}");
        // Both lanes report; the call still fails once, and the lanes are stopped.
        media.sink().on_refused();
        assert!(media.status(Instant::now()).refused);
        media.stop();
    }

    #[tokio::test]
    async fn a_token_refusal_is_not_a_pin_failure() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(12, 0, &url), Duration::from_millis(300));
        let end = Instant::now() + Duration::from_secs(6);
        while !media.status(Instant::now()).refused {
            assert!(Instant::now() < end);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!media.status(Instant::now()).pin_failed);
    }

    /// Nonce safety: one sealer for the whole call; lane drops and restarts
    /// never reset or repeat seq.
    #[tokio::test]
    async fn seq_runs_on_across_lane_reconnects() {
        let (url, seen) = fake_relay(Mode::DropAfter(Duration::from_millis(300))).await;
        let media = start_null(start(13, 0, &url), CONNECT_GIVE_UP);
        let pcm = [0i16; FRAME_SAMPLES];
        for _ in 0..100 {
            media.push_pcm(&pcm);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        media.lanes.restart(0);
        for _ in 0..20 {
            media.push_pcm(&pcm);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let joins = seen.lock().joins.len();
        assert!(joins >= 4, "lanes reconnected: {joins}");
        assert_eq!(
            media.tx.lock().sealer.as_ref().unwrap().next_seq(),
            120,
            "one sealer, never reset"
        );
        media.stop();
    }

    #[tokio::test]
    async fn after_stop_the_keys_are_gone_and_late_sink_events_are_harmless() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let media = start_null(start(14, 0, &url), CONNECT_GIVE_UP);
        let sink = media.sink();
        media.stop();
        assert!(media.tx.lock().sealer.is_none() && media.rx.rx.lock().opener.is_none());
        assert_eq!(media.push_pcm(&[0; FRAME_SAMPLES]), 0);
        assert_eq!(media.pull_pcm(&mut [0; FRAME_SAMPLES]), 0);
        let t = Instant::now();
        sink.on_lane(0, false);
        sink.on_lane(1, true);
        sink.on_peer(0, false);
        sink.on_peer(1, true);
        sink.on_frame(0, &sealed(14, 0), t);
        assert!(!media.status(t).first_frame);
        media.stop(); // idempotent
    }

    #[test]
    fn starting_from_a_thread_without_a_runtime_is_an_error_not_a_panic() {
        assert!(CallMedia::start(start(15, 0, "ws://127.0.0.1:9/")).is_err());
    }

    /// Blackholed path: a lane up but silent for 2 s while the other still
    /// receives is restarted (and only that one); a duplicate copy proves a
    /// lane alive. Both silent for 3 s: both restart, then not again at once.
    #[tokio::test]
    async fn a_silent_lane_is_restarted_while_the_other_receives_and_both_after_3_s() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(16, 0, &url), Duration::from_secs(600));
        let sink = media.sink();
        let t0 = Instant::now();
        sink.on_lane(0, true);
        sink.on_lane(1, true);
        let ms = Duration::from_millis;
        for (i, at) in [0u64, 500, 1000, 1500, 2000, 2500].into_iter().enumerate() {
            sink.on_frame(0, &sealed(16, i as u64), t0 + ms(at));
        }
        // Lane 1 has only ever repeated frames lane 0 already won: still alive.
        sink.on_frame(1, &sealed(16, 5), t0 + ms(2400));
        assert_eq!(media.watchdog(t0 + ms(2500)).restart, [false, false]);
        assert_eq!(
            media.watchdog(t0 + ms(4500)).restart,
            [false, false],
            "lane 1 heard at 2.4 s"
        );
        sink.on_frame(0, &sealed(16, 6), t0 + ms(4600));
        assert_eq!(
            media.watchdog(t0 + ms(4700)).restart,
            [false, true],
            "lane 1 silent 2.3 s, lane 0 receiving"
        );
        assert_eq!(
            media.watchdog(t0 + ms(4800)).restart,
            [false, false],
            "not again at once"
        );
        let v = media.watchdog(t0 + ms(7700));
        assert_eq!(v.restart, [true, true], "both silent 3.1 s");
        assert_eq!(
            media.watchdog(t0 + ms(7800)).restart,
            [false, false],
            "rate limited"
        );
        assert!(media.status(t0 + ms(7700)).reconnecting);
        assert!(!v.give_up);
        media.stop();
    }

    #[tokio::test]
    async fn a_lane_that_never_came_up_is_left_to_its_own_retries() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(17, 0, &url), Duration::from_secs(600));
        let sink = media.sink();
        let t0 = Instant::now();
        sink.on_lane(0, true);
        sink.on_frame(0, &sealed(17, 0), t0);
        sink.on_frame(0, &sealed(17, 1), t0 + Duration::from_millis(2900));
        assert_eq!(
            media.watchdog(t0 + Duration::from_millis(3000)).restart,
            [false, false]
        );
        media.stop();
    }

    #[tokio::test]
    async fn the_engine_stops_the_lanes_at_its_give_up() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(18, 0, &url), Duration::from_millis(100));
        let t0 = Instant::now();
        // Once the lanes are done with their refusal retries (reported).
        let end = t0 + Duration::from_secs(8);
        while !media.status(Instant::now()).refused {
            assert!(Instant::now() < end, "refusal not reported");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!media.watchdog(t0 + Duration::from_millis(100)).give_up);
        assert!(media.watchdog(t0 + Duration::from_secs(4)).give_up);
        // And for real, on an address nothing listens on (plain network failure).
        let media = start_null(
            start(19, 0, "ws://127.0.0.1:9/"),
            Duration::from_millis(100),
        );
        let end = Instant::now() + Duration::from_secs(8);
        while !media.status(Instant::now()).gave_up {
            assert!(Instant::now() < end, "never gave up");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(media.lanes_stopped());
        // Media that stops for 20 s plus the grace is given up too.
        let t = Instant::now();
        media.sink().on_frame(0, &sealed(19, 0), t);
        assert!(media.watchdog(t + Duration::from_secs(24)).give_up);
    }

    /// "Poor connection" only once the window holds 50 frames.
    #[tokio::test]
    async fn poor_connection_waits_for_50_frames_of_evidence() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(20, 0, &url), Duration::from_secs(600));
        let t = Instant::now();
        for i in 0..5 {
            media.sink().on_frame(0, &sealed(20, i), t);
        }
        let mut out = [0i16; FRAME_SAMPLES];
        for _ in 0..45 {
            media.pull_pcm(&mut out); // 5 played, then 40 concealed
        }
        let st = media.status(Instant::now());
        assert!(st.concealed_pct > 5 && !st.poor, "45 frames: {st:?}");
        for _ in 0..6 {
            media.pull_pcm(&mut out);
        }
        assert!(media.status(Instant::now()).poor, "51 frames");
        media.stop();
    }

    /// Review of Task 8: a relay replaying old authentic frames can't keep
    /// a dead call alive. Only fresh frames are media; a repeat only shows
    /// that its lane's path works.
    #[tokio::test]
    async fn replayed_frames_do_not_keep_a_dead_call_alive() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(21, 0, &url), Duration::from_secs(600));
        let sink = media.sink();
        let t0 = Instant::now();
        let frame = sealed(21, 0);
        sink.on_frame(0, &frame, t0);
        for s in 1..=30u64 {
            let at = t0 + Duration::from_secs(s);
            sink.on_frame(0, &frame, at);
            sink.on_frame(1, &frame, at);
        }
        let st = media.status(t0 + SILENT_AFTER);
        assert!(
            st.reconnecting && st.silent_for == SILENT_AFTER,
            "replays are not media: {st:?}"
        );
        assert!(
            media
                .watchdog(t0 + RECONNECT_GIVE_UP + GIVE_UP_GRACE)
                .give_up,
            "replays don't hold off the give-up"
        );
        media.stop();
    }

    /// Review of Task 8: a slow connect delays a lane's first refusal, so
    /// the lane reports it later than the engine's own give-up would come.
    /// The engine does not give up while a lane is still connecting or
    /// retrying refused joins: the refusal is what is reported.
    #[tokio::test]
    async fn a_slow_connect_reports_the_refusal_not_a_give_up() {
        let (url, _seen) = fake_relay(Mode::SlowRefuse(Duration::from_millis(3600))).await;
        let media = start_null(start(22, 0, &url), Duration::from_millis(300));
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            let st = media.status(Instant::now());
            assert!(!st.gave_up, "gave up inside the lanes' retries: {st:?}");
            if st.refused {
                break;
            }
            assert!(Instant::now() < end, "refusal not reported");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        media.stop();
    }

    /// Review of Task 9 (D18): a repeat still times its lane's jitter. Lane
    /// 0 wins every frame but is jittery; lane 1 always comes second, late
    /// but steady. The target follows lane 1's steadiness, which it sees
    /// only through repeats.
    #[tokio::test]
    async fn repeats_still_time_their_lanes_jitter() {
        let (url, _seen) = fake_relay(Mode::Refuse).await;
        let media = start_null(start(23, 0, &url), Duration::from_secs(600));
        let sink = media.sink();
        let now = Instant::now();
        let base = now - Duration::from_millis(1500);
        let mut sealer = crate::call::frame::FrameSealer::new(&[0x42; 32], CallId([23; 16]));
        let mut wire = [0u8; MAX_WIRE_FRAME];
        for i in 0..60u64 {
            let n = sealer.seal(&[0xF8, 0xFF, 0xFE], &mut wire).unwrap();
            let sent = base + Duration::from_millis(20 * i);
            sink.on_frame(0, &wire[..n], sent + Duration::from_millis(i * 37 % 200));
            sink.on_frame(1, &wire[..n], sent + Duration::from_millis(250));
        }
        let mut out = [0i16; FRAME_SAMPLES];
        media.pull_pcm(&mut out);
        let target = media.rx.rx.lock().playout.target_ms();
        assert_eq!(
            target,
            crate::call::BUFFER_MIN_MS,
            "lane 1's repeats are timed"
        );
        media.stop();
    }
}
