//! The video engine of one call (R4, R6, R11-R16, R21): encoded frames in
//! → fragments → sealed once on the video stream → one of the two video
//! connections; fragments in → opened → reassembled → taken by the app's
//! decoder. Keyframe requests and ~1 s health notes ride as sealed control
//! frames on the audio connections (`AudioLink`), never in the ratchet.
//!
//! Nonce safety: the engine holds the call's one `StreamSealer` per stream
//! (video, control) and direction for its whole life. Camera off/on, pause,
//! lane restarts and network changes never touch them, so a `seq` (the
//! nonce) is never repeated. The keys go into the sealers and openers at
//! `start` and are wiped when those are dropped at `stop`.
//!
//! Locks: the send side (sealer, adapter, need-keyframe), the receive side
//! (opener, reassembler) and the control side (control sealer and opener,
//! peer notes, banner) each have their own, and no two are ever held
//! together. None is held while calling into the audio engine, so the app's
//! encoder and decoder threads never wait on the network, the audio or the
//! client lock. The control sink the audio engine holds is weak and cleared
//! at `stop`; the tick task and the connections hold the engine weakly.

use super::adapt::{AdaptInput, Adapter, DownCause, Rung};
use super::frag::{fragment_count, Assembled, FragHeader, Reassembler, TooSmall};
use super::health::{
    decode_keyframe_request, keyframe_request, raw_banner, recv_health, send_health, Banner,
    BannerState, DelayTracker, Health, HealthNote,
};
use super::queue::Pushed;
use super::stream::{StreamOpener, StreamSealer};
use super::{
    is_stream_frame, Quality, VideoCodec, FRAG_HEADER, MAX_VIDEO_WIRE, STREAM_CONTROL,
    STREAM_HEADER, STREAM_VIDEO, VIDEO_FRAGMENT_MAX,
};
use crate::call::codec::CodecError;
use crate::call::engine::{AudioLink, ControlSink};
use crate::call::frame::TAG_LEN;
use crate::call::keys::VideoKeys;
use crate::call::lanes::{LaneConfig, LaneSink, LaneStats, VideoLanes};
use crate::call::{CallId, CONNECT_GIVE_UP, MAX_SEQ};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const TICK: Duration = Duration::from_millis(250);
/// A health note every this many ticks (1 s).
const NOTE_TICKS: u32 = 4;
/// Keyframe requests repeat this often while waiting (R14).
const KEY_REPEAT: Duration = Duration::from_millis(500);
/// The sender honours at most one keyframe request per this (R14).
const KEY_HONOUR_GAP: Duration = Duration::from_millis(500);
/// A peer note older than this is unknown (R15).
const NOTE_STALE: Duration = Duration::from_secs(3);
/// "Video paused" after this long without a delivered frame (R16).
const PAUSED_IN_AFTER: Duration = Duration::from_secs(3);
const AUDIO_DROP_RECENT: Duration = Duration::from_secs(2);
const STEPPED_DOWN_RECENT: Duration = Duration::from_secs(5);
/// R11 / R12: no write progress for this long is a stalled lane.
const STALLED_AFTER: Duration = Duration::from_millis(500);
/// Loss share window: 3 s of ticks.
const LOSS_TICKS: usize = 12;
const VIDEO_WINDOW: usize = 1024;
const CONTROL_WINDOW: usize = 128;
/// The longest control body (a health note).
const CONTROL_BODY_MAX: usize = 6;
const CONTROL_WIRE: usize = STREAM_HEADER + CONTROL_BODY_MAX + TAG_LEN;
/// Health note `rung` while paused.
const RUNG_PAUSED: u8 = 255;
const MAX_RUNG: u8 = Rung::P240 as u8;
/// R21: hold = clamp(audio depth - 60, 0, 150) ms.
const LIP_SYNC_OFFSET_MS: u64 = 60;
const HOLD_MAX_MS: u64 = 150;

pub struct VideoStart {
    pub call_id: CallId,
    /// 0 caller, 1 callee (the relay's side), as for the audio lanes.
    pub role: u8,
    pub keys: VideoKeys,
    /// The call's relay token: the video lanes join with the audio's (R7).
    pub relay_token: Zeroizing<[u8; 32]>,
    pub lane: LaneConfig,
    pub codec: VideoCodec,
    /// The receiver's Caps `max_recv`.
    pub peer_max: Quality,
    pub software_encoder: bool,
    pub audio: Arc<dyn AudioLink>,
}

/// What the app's encoder should produce now. `generation` bumps on any
/// change, so the app can skip an unchanged hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderHint {
    pub generation: u32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
    pub keyframe: bool,
    pub active: bool,
}

impl EncoderHint {
    /// The fields in declaration order, booleans as 0/1 (for the FFI).
    pub fn to_ints(&self) -> [i32; 7] {
        let i = |v: u32| i32::try_from(v).unwrap_or(i32::MAX);
        [
            self.generation as i32,
            i(self.width),
            i(self.height),
            i(self.fps),
            i(self.bitrate),
            i32::from(self.keyframe),
            i32::from(self.active),
        ]
    }
}

/// A frame the app's decoder took: its bytes are in the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakenFrame {
    pub len: usize,
    pub keyframe: bool,
    pub codec: VideoCodec,
    pub rotation_deg: u16,
    /// Render this much later than now, for lip sync (R21).
    pub hold_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoStatus {
    pub banner: Banner,
    /// The peer's video is paused (R16).
    pub paused_in: bool,
    /// My video is paused below the ladder (R11).
    pub paused_out: bool,
    /// `None` while paused.
    pub rung: Option<Rung>,
    pub first_frame: bool,
    /// The relay refused the video lanes, or failed its pin.
    pub refused: bool,
}

/// Test hook (`counters`): the send side's lane switches and reconnects,
/// and the receive side's reassembly totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VideoCounters {
    pub lane_switches: u64,
    pub lane_reconnects: u64,
    /// Fragments that arrived after a later frame had completed.
    pub stale_fragments: u64,
    pub frames_delivered: u64,
    pub frames_lost: u64,
    /// Sender: frames queued, keyframes among them, frames dropped for a
    /// full queue, and frames not sent for a lane move (R12).
    pub frames_queued: u64,
    pub keyframes_queued: u64,
    pub sender_dropped: u64,
    pub switched: u64,
    /// Why the adapter last stepped down or paused.
    pub last_down_cause: Option<DownCause>,
}

/// The video engine as the call machine and the app see it.
pub(crate) trait VideoControl: Send + Sync {
    /// Fragments queued; 0 when not sending, paused or dropped; -9 bad input.
    fn send_frame(&self, data: &[u8], keyframe: bool, rotation_deg: u16, now: Instant) -> i32;
    /// The next complete frame into `out`. `TooSmall` drops the frame and
    /// asks the sender for a keyframe.
    fn take(&self, out: &mut [u8], now: Instant) -> Result<Option<TakenFrame>, TooSmall>;
    /// The app's decoder failed: wait for and ask for a keyframe.
    fn need_keyframe(&self, now: Instant);
    fn encoder_hint(&self) -> EncoderHint;
    /// My camera is on and video is agreed.
    fn set_sending(&self, on: bool);
    /// The peer's camera is on and video is agreed (video is expected).
    fn set_receiving(&self, on: bool);
    /// `PowerManager` thermal status, 0-6.
    fn set_thermal(&self, level: u8);
    fn status(&self, now: Instant) -> VideoStatus;
    fn stop(&self);
}

pub(crate) fn hold_ms(audio_depth_ms: u64) -> u32 {
    audio_depth_ms
        .saturating_sub(LIP_SYNC_OFFSET_MS)
        .min(HOLD_MAX_MS) as u32
}

fn quarter_turns(rotation_deg: u16) -> Option<u8> {
    match rotation_deg {
        0 => Some(0),
        90 => Some(1),
        180 => Some(2),
        270 => Some(3),
        _ => None,
    }
}

/// The peer's health notes: untrusted input, clamped when recorded.
#[derive(Default)]
struct PeerNotes {
    latest: Option<(HealthNote, Instant)>,
    previous: Option<(HealthNote, Instant)>,
    /// The control seq of `latest`: an older note arriving late is ignored.
    latest_seq: Option<u64>,
    /// The last share of my audio the peer concealed. Kept, never expired:
    /// the resume check (R11) reads the latest one there is.
    concealed_pct: Option<u8>,
    /// When a note first said the peer's video is no longer paused (the
    /// peer resumed), after one that said it was.
    resumed_at: Option<Instant>,
    /// When a note first said the peer's video is paused.
    paused_at: Option<Instant>,
}

impl PeerNotes {
    fn record(&mut self, seq: u64, mut note: HealthNote, at: Instant) {
        if self.latest_seq.is_some_and(|s| seq < s) {
            return;
        }
        if note.rung != RUNG_PAUSED {
            note.rung = note.rung.min(MAX_RUNG);
        }
        note.audio_concealed_pct = note.audio_concealed_pct.min(100);
        let was_paused = self.latest.is_some_and(|(n, _)| n.paused_out);
        if !note.paused_out && was_paused {
            self.resumed_at = Some(at);
        }
        if note.paused_out && !was_paused {
            self.paused_at = Some(at);
        }
        self.previous = self.latest.replace((note, at));
        self.latest_seq = Some(seq);
        self.concealed_pct = Some(note.audio_concealed_pct);
    }

    fn fresh(n: &Option<(HealthNote, Instant)>, now: Instant) -> Option<HealthNote> {
        n.filter(|(_, at)| now.saturating_duration_since(*at) <= NOTE_STALE)
            .map(|(n, _)| n)
    }

    /// For the step-up: an unknown or stale note is "not bad", or video
    /// could never climb back after the notes stop.
    fn recv_good(&self, now: Instant) -> bool {
        Self::fresh(&self.latest, now).is_none_or(|n| n.recv != Health::Bad)
    }

    /// When the latest note, if fresh and saying `recv` bad, arrived.
    fn recv_bad_at(&self, now: Instant) -> Option<Instant> {
        self.latest
            .filter(|(n, at)| {
                n.recv == Health::Bad && now.saturating_duration_since(*at) <= NOTE_STALE
            })
            .map(|(_, at)| at)
    }

    fn recv_bad_twice(&self, now: Instant) -> bool {
        let bad = |n: Option<HealthNote>| n.is_some_and(|n| n.recv == Health::Bad);
        bad(Self::fresh(&self.latest, now)) && bad(Self::fresh(&self.previous, now))
    }

    /// The peer's send health, `None` when unknown (R15).
    fn send(&self, now: Instant) -> Option<Health> {
        Self::fresh(&self.latest, now).map(|n| n.send)
    }

    /// The peer's recv health (its downlink), `None` when unknown.
    fn recv(&self, now: Instant) -> Option<Health> {
        Self::fresh(&self.latest, now).map(|n| n.recv)
    }

    /// The peer's latest (fresh) note says its video is paused: I am not
    /// waiting for frames it is not sending.
    fn peer_paused(&self, now: Instant) -> bool {
        Self::fresh(&self.latest, now).is_some_and(|n| n.paused_out)
    }

    /// The peer said its video is paused, after the last frame I got.
    fn paused_out_since(&self, now: Instant, last_frame: Option<Instant>) -> bool {
        self.latest.is_some_and(|(n, at)| {
            n.paused_out
                && now.saturating_duration_since(at) <= NOTE_STALE
                && last_frame.is_none_or(|f| at > f)
        })
    }
}

struct TxSide {
    /// `None` once stopped (the key is wiped).
    sealer: Option<StreamSealer>,
    adapter: Adapter,
    frame_no: u32,
    /// A frame was dropped at the sender queue (or no lane was up): drop
    /// non-key frames until a keyframe is queued (R13).
    drop_until_key: bool,
    /// The peer asked for a keyframe (or the camera came back on).
    key_requested: bool,
    last_honour: Option<Instant>,
    /// For the adapter's next tick.
    sender_dropped: bool,
    /// The lane (2 or 3) the last frame went on.
    last_lane: Option<u8>,
    /// The rung before a pause: the hint keeps its size while paused.
    last_rung: Rung,
    /// Since when an up video lane has had nothing queued.
    idle_since: Option<Instant>,
    hint: EncoderHint,
    /// One fragment's plaintext: header and payload.
    body: Vec<u8>,
    /// (queued, keyframes queued, dropped, switched), for `counters`.
    sent: [u64; 4],
    #[cfg(test)]
    honoured: Vec<Instant>,
}

struct RxSide {
    /// `None` once stopped (the key is wiped).
    opener: Option<StreamOpener>,
    reasm: Reassembler,
    /// One opened fragment.
    body: Vec<u8>,
    /// When the last complete frame arrived.
    last_frame: Option<Instant>,
    /// When receiving was last turned on.
    recv_on: Option<Instant>,
    /// Each complete frame's delay over the fastest (R15 recv).
    delay: DelayTracker,
    /// The peer resume (`PeerNotes::resumed_at`) the loss window last
    /// restarted for.
    loss_reset_for: Option<Instant>,
    /// The peer resume (`PeerNotes::resumed_at`) the delay baseline last
    /// restarted for.
    delay_reset_for: Option<Instant>,
    last_frame_no: u32,
    last_request: Option<Instant>,
    /// (delivered, lost) at each of the last ticks, for the 3 s loss share.
    loss: [(u64, u64); LOSS_TICKS],
    loss_at: usize,
}

impl RxSide {
    /// Records this tick's counters; returns the share lost over 3 s.
    fn lost_share(&mut self) -> f32 {
        let now = self.reasm.stats();
        let then = self.loss[self.loss_at];
        self.loss[self.loss_at] = now;
        self.loss_at = (self.loss_at + 1) % LOSS_TICKS;
        let delivered = now.0.saturating_sub(then.0);
        let lost = now.1.saturating_sub(then.1);
        let total = delivered.saturating_add(lost);
        if total == 0 {
            0.0
        } else {
            lost as f32 / total as f32
        }
    }
}

struct CtlSide {
    /// `None` once stopped (the keys are wiped).
    sealer: Option<StreamSealer>,
    opener: Option<StreamOpener>,
    notes: PeerNotes,
    banner: BannerState,
    shown: Banner,
    audio_dropped: u64,
    audio_dropped_at: Option<Instant>,
}

/// What the adapter reads from the peer's notes.
#[derive(Clone, Copy, Default)]
struct PeerView {
    recv_good: bool,
    bad_twice: bool,
    bad_at: Option<Instant>,
    concealed: Option<u8>,
}

/// After the peer resumes, for this long a frame this late (ms over the
/// fastest) makes my recv bad at once (R11 fast failure of a probe).
const PROBE_WINDOW: Duration = Duration::from_secs(3);
const PROBE_LATE_MS: i64 = 250;

/// The video connections' sink. Holds the engine weakly.
struct LaneEvents {
    media: Weak<VideoMedia>,
    refused: AtomicBool,
    /// When a video lane last went down or came up (R11 probe window).
    lane_event_at: Mutex<Option<Instant>>,
    /// Video lanes up now.
    lanes_up: AtomicU8,
}

impl LaneSink for LaneEvents {
    fn on_frame(&self, _lane: u8, frame: &[u8], at: Instant) {
        if let Some(m) = self.media.upgrade() {
            m.on_video_frame(frame, at);
        }
    }
    fn on_peer(&self, _lane: u8, _present: bool) {}
    fn on_lane(&self, _lane: u8, up: bool) {
        *self.lane_event_at.lock() = Some(Instant::now());
        let was = if up {
            self.lanes_up.fetch_add(1, Ordering::AcqRel)
        } else {
            self.lanes_up
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    Some(n.saturating_sub(1))
                })
                .unwrap_or(0)
        };
        // Both video lanes down (a network change): the path may be new, so
        // the delay baseline starts again.
        if !up && was <= 1 {
            if let Some(m) = self.media.upgrade() {
                m.rx.lock().delay.reset();
            }
        }
    }
    fn on_refused(&self) {
        self.refused.store(true, Ordering::SeqCst);
    }
}

pub struct VideoMedia {
    tx: Mutex<TxSide>,
    rx: Mutex<RxSide>,
    ctl: Mutex<CtlSide>,
    codec: VideoCodec,
    peer_max: Quality,
    software_encoder: bool,
    sending: AtomicBool,
    receiving: AtomicBool,
    stopped: AtomicBool,
    /// The video seq would pass 2^63: video stops, the call goes on.
    exhausted: AtomicBool,
    thermal: AtomicU8,
    ticks: AtomicU32,
    requests_sent: AtomicU64,
    events: Arc<LaneEvents>,
    lanes: VideoLanes,
    audio: Arc<dyn AudioLink>,
    /// This phone's origin for the fragment header's `sent_ms` and for the
    /// arrival times the delay measure compares them with.
    origin: Instant,
}

impl VideoMedia {
    /// Must run inside the tokio runtime (the video connections and the
    /// tick are spawned onto it); from any other thread it is an error.
    pub fn start(s: VideoStart) -> Result<Arc<VideoMedia>, CodecError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(CodecError::NoRuntime);
        }
        let now = Instant::now();
        // Each phone its own random resume jitter (R11 probes).
        let adapter = Adapter::new(s.software_encoder, now).with_resume_jitter(rand::random());
        let first_rung = adapter.rung().unwrap_or(Rung::P720);
        let media = Arc::new_cyclic(|weak: &Weak<VideoMedia>| {
            let events = Arc::new(LaneEvents {
                lane_event_at: Mutex::new(None),
                lanes_up: AtomicU8::new(0),
                media: weak.clone(),
                refused: AtomicBool::new(false),
            });
            let lanes = VideoLanes::start(
                s.lane.clone(),
                Zeroizing::new(*s.relay_token),
                s.role,
                events.clone(),
                CONNECT_GIVE_UP,
            );
            let (w, h) = first_rung.size();
            VideoMedia {
                tx: Mutex::new(TxSide {
                    sealer: Some(StreamSealer::new(&s.keys.send, s.call_id, STREAM_VIDEO)),
                    adapter,
                    frame_no: 0,
                    drop_until_key: false,
                    key_requested: false,
                    last_honour: None,
                    sender_dropped: false,
                    last_lane: None,
                    last_rung: first_rung,
                    idle_since: None,
                    hint: EncoderHint {
                        generation: 0,
                        width: w,
                        height: h,
                        fps: first_rung.fps(),
                        bitrate: first_rung.bitrate(),
                        keyframe: false,
                        active: false,
                    },
                    body: vec![0; FRAG_HEADER + VIDEO_FRAGMENT_MAX],
                    sent: [0; 4],
                    #[cfg(test)]
                    honoured: Vec::new(),
                }),
                rx: Mutex::new(RxSide {
                    opener: Some(StreamOpener::new(
                        &s.keys.recv,
                        s.call_id,
                        STREAM_VIDEO,
                        VIDEO_WINDOW,
                    )),
                    reasm: Reassembler::new(),
                    body: vec![0; MAX_VIDEO_WIRE],
                    last_frame: None,
                    recv_on: None,
                    delay: DelayTracker::default(),
                    loss_reset_for: None,
                    delay_reset_for: None,
                    last_frame_no: 0,
                    last_request: None,
                    loss: [(0, 0); LOSS_TICKS],
                    loss_at: 0,
                }),
                ctl: Mutex::new(CtlSide {
                    sealer: Some(StreamSealer::new(
                        &s.keys.ctl_send,
                        s.call_id,
                        STREAM_CONTROL,
                    )),
                    opener: Some(StreamOpener::new(
                        &s.keys.ctl_recv,
                        s.call_id,
                        STREAM_CONTROL,
                        CONTROL_WINDOW,
                    )),
                    notes: PeerNotes::default(),
                    banner: BannerState::new(),
                    shown: Banner::None,
                    audio_dropped: 0,
                    audio_dropped_at: None,
                }),
                codec: s.codec,
                peer_max: s.peer_max,
                software_encoder: s.software_encoder,
                sending: AtomicBool::new(false),
                receiving: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                exhausted: AtomicBool::new(false),
                thermal: AtomicU8::new(0),
                ticks: AtomicU32::new(0),
                requests_sent: AtomicU64::new(0),
                events,
                lanes,
                audio: s.audio.clone(),
                origin: Instant::now(),
            }
        });
        // `s.keys` and `s.relay_token` drop here, wiping them.
        let weak: Weak<VideoMedia> = Arc::downgrade(&media);
        let sink: Weak<dyn ControlSink> = weak;
        media.audio.set_control_sink(Some(sink));
        tokio::spawn(run_ticks(Arc::downgrade(&media)));
        Ok(media)
    }

    pub fn send_frame(&self, data: &[u8], keyframe: bool, rotation_deg: u16, now: Instant) -> i32 {
        let (Some(rotation), Some(n)) = (quarter_turns(rotation_deg), fragment_count(data.len()))
        else {
            return -9;
        };
        if self.stopped.load(Ordering::Acquire)
            || self.exhausted.load(Ordering::Acquire)
            || !self.sending.load(Ordering::Acquire)
        {
            return 0;
        }
        let codec = self.codec;
        let mut guard = self.tx.lock();
        let TxSide {
            sealer,
            adapter,
            frame_no,
            drop_until_key,
            key_requested,
            sender_dropped,
            last_lane,
            body,
            sent,
            ..
        } = &mut *guard;
        let Some(sealer) = sealer.as_mut() else {
            return 0; // stopped
        };
        if adapter.rung().is_none() || (*drop_until_key && !keyframe) {
            return 0;
        }
        if sealer
            .next_seq()
            .checked_add(n as u64)
            .is_none_or(|end| end > MAX_SEQ)
        {
            self.exhausted.store(true, Ordering::Release);
            return 0;
        }
        let sent_ms = self.ms(now);
        let header = |index: usize| FragHeader {
            frame_no: *frame_no,
            index: index as u8,
            count: n as u8,
            keyframe,
            codec,
            rotation,
            sent_ms,
        };
        let mut fill = |i: usize, slot: &mut [u8]| -> usize {
            let start = i * VIDEO_FRAGMENT_MAX;
            let part = &data[start..data.len().min(start + VIDEO_FRAGMENT_MAX)];
            let len = FRAG_HEADER + part.len();
            body[..FRAG_HEADER].copy_from_slice(&header(i).encode());
            body[FRAG_HEADER..len].copy_from_slice(part);
            sealer.seal(&body[..len], slot).unwrap_or(0)
        };
        let pushed = self.lanes.push_frame(n, keyframe, now, &mut fill);
        // Every frame offered to the lanes takes a number, so the receiver
        // sees a gap where one was lost here.
        *frame_no = frame_no.wrapping_add(1);
        match pushed {
            Pushed::Queued { lane } | Pushed::ClearedForKeyframe { lane } => {
                sent[0] += 1;
                sent[1] += u64::from(keyframe);
                *last_lane = Some(lane);
                if keyframe {
                    *drop_until_key = false;
                    *key_requested = false;
                }
                n as i32
            }
            Pushed::Dropped => {
                sent[2] += 1;
                *sender_dropped = true;
                *drop_until_key = true;
                0
            }
            Pushed::NoLane => {
                *drop_until_key = true;
                0
            }
            // Moved to the other lane (R12): it starts with a keyframe.
            Pushed::Switched { lane } => {
                sent[3] += 1;
                *last_lane = Some(lane);
                *drop_until_key = true;
                0
            }
        }
    }

    pub fn take(&self, out: &mut [u8], now: Instant) -> Result<Option<TakenFrame>, TooSmall> {
        if self.stopped.load(Ordering::Acquire) {
            return Ok(None);
        }
        let popped = {
            let mut r = self.rx.lock();
            if r.opener.is_none() {
                return Ok(None);
            }
            let waiting = r.reasm.waiting_for_keyframe();
            match r.reasm.pop_ready(out) {
                // The wait began here: ask at once; else the tick repeats.
                Err(TooSmall) if !waiting => {
                    r.last_request = Some(now);
                    Err(Some(r.last_frame_no))
                }
                Err(TooSmall) => Err(None),
                Ok(f) => Ok(f),
            }
        };
        match popped {
            Ok(None) => Ok(None),
            Ok(Some(f)) => Ok(Some(TakenFrame {
                len: f.len,
                keyframe: f.keyframe,
                codec: f.codec,
                rotation_deg: u16::from(f.rotation) * 90,
                hold_ms: hold_ms(self.audio.audio_depth_ms()),
            })),
            Err(ask) => {
                if let Some(frame_no) = ask {
                    self.request_keyframe(frame_no);
                }
                Err(TooSmall)
            }
        }
    }

    /// Asks at once when this begins the wait; while already waiting the
    /// tick repeats the request (so a decoder failing on every frame can't
    /// flood the audio connections).
    pub fn need_keyframe(&self, now: Instant) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let frame_no = {
            let mut r = self.rx.lock();
            if r.opener.is_none() {
                return;
            }
            let began = !r.reasm.waiting_for_keyframe();
            r.reasm.force_keyframe_wait();
            if !began {
                return;
            }
            r.last_request = Some(now);
            r.last_frame_no
        };
        self.request_keyframe(frame_no);
    }

    pub fn encoder_hint(&self) -> EncoderHint {
        let on = self.sending.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
            && !self.exhausted.load(Ordering::Acquire);
        let mut t = self.tx.lock();
        let rung = t.adapter.rung();
        if let Some(r) = rung {
            t.last_rung = r;
        }
        let r = t.last_rung;
        let (width, height) = r.size();
        let now = EncoderHint {
            generation: t.hint.generation,
            width,
            height,
            fps: r.fps(),
            bitrate: r.bitrate(),
            keyframe: t.drop_until_key || t.key_requested,
            active: on && rung.is_some() && t.sealer.is_some(),
        };
        if now != t.hint {
            t.hint = EncoderHint {
                generation: t.hint.generation.wrapping_add(1),
                ..now
            };
        }
        t.hint
    }

    pub fn set_sending(&self, on: bool) {
        if on && !self.sending.swap(true, Ordering::AcqRel) {
            // A camera coming back on starts with a keyframe.
            self.tx.lock().key_requested = true;
        } else if !on {
            self.sending.store(false, Ordering::Release);
        }
    }

    pub fn set_receiving(&self, on: bool) {
        if on && !self.receiving.swap(true, Ordering::AcqRel) {
            let mut r = self.rx.lock();
            r.recv_on = Some(Instant::now());
            r.delay.reset();
        } else if !on {
            self.receiving.store(false, Ordering::Release);
        }
    }

    pub fn set_thermal(&self, level: u8) {
        self.thermal.store(level.min(6), Ordering::Release);
    }

    pub fn status(&self, now: Instant) -> VideoStatus {
        let sending = self.sending.load(Ordering::Acquire);
        let receiving = self.receiving.load(Ordering::Acquire);
        let (last_frame, recv_on, first_frame) = {
            let r = self.rx.lock();
            (r.last_frame, r.recv_on, r.last_frame.is_some())
        };
        let (shown, peer_paused) = {
            let c = self.ctl.lock();
            (c.shown, c.notes.paused_out_since(now, last_frame))
        };
        let rung = self.tx.lock().adapter.rung();
        let since_frame = last_frame
            .max(recv_on)
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        VideoStatus {
            banner: if sending || receiving {
                shown
            } else {
                Banner::None
            },
            paused_in: receiving && (peer_paused || since_frame >= PAUSED_IN_AFTER),
            paused_out: sending && rung.is_none(),
            rung,
            first_frame,
            refused: self.events.refused.load(Ordering::SeqCst),
        }
    }

    /// Stops the connections and wipes the keys. Safe to call twice; later
    /// calls of any kind are harmless.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.lanes.stop();
        self.tx.lock().sealer = None;
        self.rx.lock().opener = None;
        {
            let mut c = self.ctl.lock();
            c.sealer = None;
            c.opener = None;
        }
        self.audio.set_control_sink(None);
    }

    /// Test hook: the video stream's next seq (0 once stopped).
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn next_seq(&self) -> u64 {
        self.tx.lock().sealer.as_ref().map_or(0, |s| s.next_seq())
    }

    /// Test hook: what the lanes and the reassembler counted.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn counters(&self) -> VideoCounters {
        let lanes = self.lanes.counters();
        let (sent, last_down_cause) = {
            let t = self.tx.lock();
            (t.sent, t.adapter.last_cause())
        };
        let r = self.rx.lock();
        let (delivered, lost) = r.reasm.stats();
        VideoCounters {
            frames_queued: sent[0],
            keyframes_queued: sent[1],
            sender_dropped: sent[2],
            switched: sent[3],
            last_down_cause,
            lane_switches: lanes.switches,
            lane_reconnects: lanes.reconnects,
            stale_fragments: r.reasm.stale_fragments(),
            frames_delivered: delivered,
            frames_lost: lost,
        }
    }

    /// Ms since this phone's origin (wrapping), for `sent_ms`.
    fn ms(&self, at: Instant) -> u32 {
        at.saturating_duration_since(self.origin).as_millis() as u32
    }

    /// Test hook: the peer's latest health note.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn peer_note(&self) -> Option<HealthNote> {
        self.ctl.lock().notes.latest.map(|(n, _)| n)
    }

    /// Test hook: the video lanes' state.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn lane_stats(&self, now: Instant) -> [LaneStats; 2] {
        self.lanes.stats(now)
    }

    #[cfg(test)]
    pub(crate) fn keyframe_requests_sent(&self) -> u64 {
        self.requests_sent.load(Ordering::SeqCst)
    }

    /// A fragment from a video lane: opened, then reassembled.
    fn on_video_frame(&self, frame: &[u8], at: Instant) {
        if is_stream_frame(frame) != Some(STREAM_VIDEO) {
            return;
        }
        let request = {
            let mut guard = self.rx.lock();
            let r = &mut *guard;
            let Some(opener) = r.opener.as_mut() else {
                return;
            };
            let Ok((_, n)) = opener.open(frame, &mut r.body) else {
                return;
            };
            if n <= FRAG_HEADER {
                return;
            }
            let Some(h) = FragHeader::decode(&r.body[..FRAG_HEADER]) else {
                return;
            };
            if h.codec != self.codec {
                return;
            }
            r.last_frame_no = h.frame_no;
            match r.reasm.push(h, &r.body[FRAG_HEADER..n]) {
                Assembled::Complete => {
                    r.last_frame = Some(at);
                    let arrived = self.ms(at);
                    r.delay.on_frame(h.sent_ms, arrived, at);
                    None
                }
                Assembled::NeedKeyframe => {
                    r.last_request = Some(at);
                    Some(h.frame_no)
                }
                Assembled::Partial | Assembled::Dropped => None,
            }
        };
        if let Some(frame_no) = request {
            self.request_keyframe(frame_no);
        }
    }

    fn on_keyframe_request(&self, at: Instant) {
        let mut t = self.tx.lock();
        if t.sealer.is_none() {
            return;
        }
        if t.last_honour
            .is_none_or(|h| at.saturating_duration_since(h) >= KEY_HONOUR_GAP)
        {
            t.key_requested = true;
            t.last_honour = Some(at);
            #[cfg(test)]
            t.honoured.push(at);
        }
    }

    fn request_keyframe(&self, frame_no: u32) {
        if self.send_control_body(&keyframe_request(frame_no)) {
            self.requests_sent.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Seals a control body and hands it to the audio connections (both).
    fn send_control_body(&self, body: &[u8]) -> bool {
        let mut wire = [0u8; CONTROL_WIRE];
        let n = {
            let mut c = self.ctl.lock();
            c.sealer.as_mut().and_then(|s| s.seal(body, &mut wire).ok())
        };
        match n {
            Some(n) => {
                self.audio.send_control(&wire[..n]);
                true
            }
            None => false,
        }
    }

    /// One 250 ms tick: the adapter (while sending), the keyframe-request
    /// repeats, and each 1 s the health, the banner and a note.
    fn tick(&self, now: Instant) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let sending = self.sending.load(Ordering::Acquire);
        let receiving = self.receiving.load(Ordering::Acquire);
        let note_tick = self
            .ticks
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(NOTE_TICKS);
        let stats = self.lanes.stats(now);
        let (peer, peer_resumed_at, peer_paused_at) = {
            let c = self.ctl.lock();
            (
                PeerView {
                    recv_good: c.notes.recv_good(now),
                    bad_twice: c.notes.recv_bad_twice(now),
                    bad_at: c.notes.recv_bad_at(now),
                    concealed: c.notes.concealed_pct,
                },
                c.notes.resumed_at,
                c.notes.paused_at,
            )
        };
        let (rung, backlog, stepped, paused_own) = self.adapt(now, sending, &stats, peer);
        let (since_frame, lost_share, late, request) = {
            let mut r = self.rx.lock();
            // The peer resumed: the frame numbers it skipped across the
            // pause (what was in flight when its lanes reset) are not
            // losses on my downlink, so the 3 s loss window starts again.
            // The peer resumed: once its probe has held (3 s), its frames
            // set a fresh delay baseline (during the probe the old one
            // judges lateness, R11 fast failure).
            if let Some(t) = peer_resumed_at.filter(|t| {
                now.saturating_duration_since(*t) >= PROBE_WINDOW
                    && peer_paused_at.is_none_or(|p| p < *t)
            }) {
                if r.delay_reset_for != Some(t) {
                    r.delay_reset_for = Some(t);
                    r.delay.reset();
                }
            }
            if peer_resumed_at.is_some() && peer_resumed_at != r.loss_reset_for {
                r.loss_reset_for = peer_resumed_at;
                let now_stats = r.reasm.stats();
                r.loss = [now_stats; LOSS_TICKS];
            }
            let lost = r.lost_share();
            // Just after the peer resumed (its probe), frames 250 ms late
            // are enough (R11 fast failure).
            let probing =
                peer_resumed_at.filter(|t| now.saturating_duration_since(*t) < PROBE_WINDOW);
            let late = r.delay.late(now)
                || probing
                    .is_some_and(|t| r.delay.excess_since(t).is_some_and(|e| e > PROBE_LATE_MS));
            // A peer that just resumed has sent nothing yet: count from then.
            let mark = r.last_frame.max(r.recv_on).max(peer_resumed_at);
            let since = mark.map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
            let due = receiving
                && r.opener.is_some()
                && r.reasm.waiting_for_keyframe()
                && r.last_request
                    // Half a tick of slack: a tick a little early still
                    // repeats at 500 ms, not 750.
                    .is_none_or(|t| now.saturating_duration_since(t) + TICK / 2 >= KEY_REPEAT);
            if due {
                r.last_request = Some(now);
            }
            (since, lost, late, due.then_some(r.last_frame_no))
        };
        if let Some(frame_no) = request {
            self.request_keyframe(frame_no);
        }
        if !note_tick {
            return;
        }
        // The audio engine's own short locks; none of ours is held.
        let audio_dropped = self.audio.audio_lanes_dropped();
        let audio_poor = self.audio.audio_poor();
        let audio_pct = self.audio.audio_concealed_pct().min(100);
        let note = {
            let mut c = self.ctl.lock();
            if audio_dropped > c.audio_dropped {
                c.audio_dropped = audio_dropped;
                c.audio_dropped_at = Some(now);
            }
            let audio_recent = c
                .audio_dropped_at
                .is_some_and(|t| now.saturating_duration_since(t) < AUDIO_DROP_RECENT);
            let paused = sending && rung.is_none();
            // A pause or step-down for the peer's recv-bad notes is not my
            // send path's fault: only my own counts against my send.
            let my_send = send_health(
                sending && paused_own,
                if sending { backlog } else { Duration::ZERO },
                audio_recent,
                sending && stepped,
            );
            // A peer that says its video is paused is not a fault of my
            // downlink: with that counted, its notes of mine would read
            // `recv` bad for as long as it is paused, and the moment it
            // resumed at 240p it would step straight down and pause again.
            let expected = receiving && !c.notes.peer_paused(now);
            let my_recv = recv_health(expected, since_frame, lost_share, late, audio_poor);
            let on = sending || receiving;
            let raw = if on {
                raw_banner(my_send, my_recv, c.notes.send(now), c.notes.recv(now))
            } else {
                Banner::None
            };
            c.shown = c.banner.update(raw, now);
            on.then(|| {
                HealthNote {
                    send: my_send,
                    recv: my_recv,
                    rung: rung.map_or(RUNG_PAUSED, |r| r as u8),
                    audio_concealed_pct: audio_pct,
                    paused_out: paused,
                }
                .encode()
            })
        };
        if let Some(body) = note {
            self.send_control_body(&body);
        }
    }

    /// The adapter's tick (while sending). Returns the rung, the chosen
    /// lane's backlog, whether it stepped down for my own send path in the
    /// last 5 s, and whether it is paused for my own send path.
    fn adapt(
        &self,
        now: Instant,
        sending: bool,
        stats: &[LaneStats; 2],
        peer: PeerView,
    ) -> (Option<Rung>, Duration, bool, bool) {
        let PeerView {
            recv_good,
            bad_twice,
            bad_at,
            concealed,
        } = peer;
        let lane_event_at = *self.events.lane_event_at.lock();
        let mut guard = self.tx.lock();
        let t = &mut *guard;
        let chosen = t
            .last_lane
            .map(|l| stats[usize::from(l & 1)])
            .filter(|s| s.up);
        // The chosen lane's: a lane the frames moved off had what waited
        // there dropped (R12), so a stuck lane left behind cannot drive a
        // step-down.
        let backlog = chosen.and_then(|s| s.oldest).unwrap_or(Duration::ZERO);
        let lane_up = stats.iter().any(|s| s.up);
        if stats.iter().any(|s| s.up && s.queued_bytes == 0) {
            t.idle_since.get_or_insert(now);
        } else {
            t.idle_since = None;
        }
        let was = t.adapter.rung();
        if sending && (lane_up || was.is_none()) && t.sealer.is_some() {
            let input = AdaptInput {
                backlog,
                sender_dropped: std::mem::take(&mut t.sender_dropped),
                stalled: chosen.is_some_and(|s| s.since_progress >= STALLED_AFTER),
                any_lane_stalled: stats
                    .iter()
                    .any(|s| s.up && s.since_progress >= STALLED_AFTER),
                lane_up,
                idle_for: t
                    .idle_since
                    .map_or(Duration::ZERO, |s| now.saturating_duration_since(s)),
                peer_recv_bad_twice: bad_twice,
                peer_recv_good: recv_good,
                peer_recv_bad_at: bad_at,
                lane_event_at,
                peer_audio_concealed_pct: concealed,
                thermal: self.thermal.load(Ordering::Acquire),
                peer_wants_1080: self.peer_max == Quality::P1080,
                software_encoder: self.software_encoder,
            };
            match t.adapter.on_tick(&input, now) {
                Some(Some(r)) => {
                    t.last_rung = r;
                    if was.is_none() {
                        t.key_requested = true; // resuming starts with a keyframe
                    }
                }
                // Paused: nothing more goes out on the video lanes, so what
                // waits there, in the app and in the kernel, is dropped, not
                // left to compete with audio (the lanes reopen at once).
                Some(None) => self.lanes.abort_and_restart(),
                None => {}
            }
        }
        (
            t.adapter.rung(),
            backlog,
            t.adapter.own_strain_within(STEPPED_DOWN_RECENT, now),
            t.adapter.paused_for_own_path(),
        )
    }
}

impl ControlSink for VideoMedia {
    /// A control frame from an audio lane (either copy): a health note or
    /// a keyframe request. Untrusted until opened; strict after.
    fn on_control(&self, frame: &[u8], at: Instant) {
        if is_stream_frame(frame) != Some(STREAM_CONTROL) {
            return;
        }
        let mut body = [0u8; CONTROL_BODY_MAX];
        let request = {
            let mut c = self.ctl.lock();
            let Some(opener) = c.opener.as_mut() else {
                return;
            };
            let Ok((seq, n)) = opener.open(frame, &mut body) else {
                return;
            };
            let body = &body[..n];
            if let Some(note) = HealthNote::decode(body) {
                c.notes.record(seq, note, at);
                false
            } else {
                decode_keyframe_request(body).is_some()
            }
        };
        if request {
            self.on_keyframe_request(at);
        }
    }
}

impl VideoControl for VideoMedia {
    fn send_frame(&self, data: &[u8], keyframe: bool, rotation_deg: u16, now: Instant) -> i32 {
        VideoMedia::send_frame(self, data, keyframe, rotation_deg, now)
    }
    fn take(&self, out: &mut [u8], now: Instant) -> Result<Option<TakenFrame>, TooSmall> {
        VideoMedia::take(self, out, now)
    }
    fn need_keyframe(&self, now: Instant) {
        VideoMedia::need_keyframe(self, now)
    }
    fn encoder_hint(&self) -> EncoderHint {
        VideoMedia::encoder_hint(self)
    }
    fn set_sending(&self, on: bool) {
        VideoMedia::set_sending(self, on)
    }
    fn set_receiving(&self, on: bool) {
        VideoMedia::set_receiving(self, on)
    }
    fn set_thermal(&self, level: u8) {
        VideoMedia::set_thermal(self, level)
    }
    fn status(&self, now: Instant) -> VideoStatus {
        VideoMedia::status(self, now)
    }
    fn stop(&self) {
        VideoMedia::stop(self)
    }
}

impl Drop for VideoMedia {
    fn drop(&mut self) {
        self.lanes.stop();
    }
}

/// Ticks until the engine stops or is dropped; holds it only weakly.
async fn run_ticks(media: Weak<VideoMedia>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(m) = media.upgrade() else {
            return;
        };
        if m.stopped.load(Ordering::Acquire) {
            return;
        }
        m.tick(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::engine::{CallMedia, MediaStart};
    use crate::call::keys;
    use crate::call::test_relay::{fake_relay, lane_config, Mode, Seen};
    use crate::call::video::testing::SyntheticEncoder;
    use crate::call::video::VIDEO_MAX_FRAME;
    use parking_lot::Mutex as PMutex;

    const ID: CallId = CallId([0x5A; 16]);

    struct Two {
        a: Arc<VideoMedia>,
        b: Arc<VideoMedia>,
        aa: Arc<CallMedia>,
        ba: Arc<CallMedia>,
        seen: Arc<PMutex<Seen>>,
    }

    fn video_start(url: &str, caller: bool, audio: Arc<CallMedia>, token: [u8; 32]) -> VideoStart {
        let vk = keys::derive(&ID, &[0x11; 32], &[0x22; 32], caller).1;
        VideoStart {
            call_id: ID,
            role: u8::from(!caller),
            keys: vk,
            relay_token: Zeroizing::new(token),
            lane: lane_config(url),
            codec: VideoCodec::H265,
            peer_max: Quality::P720,
            software_encoder: false,
            audio,
        }
    }

    fn audio_start(url: &str, caller: bool) -> (MediaStart, [u8; 32]) {
        let ck = keys::derive(&ID, &[0x11; 32], &[0x22; 32], caller).0;
        let token = *ck.relay_token;
        (
            MediaStart {
                call_id: ID,
                role: u8::from(!caller),
                keys: ck,
                lane: lane_config(url),
            },
            token,
        )
    }

    async fn wait_until(what: &str, secs: f64, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs_f64(secs);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn video_up(v: &VideoMedia) -> bool {
        v.lanes.stats(Instant::now()).iter().all(|s| s.up)
    }

    /// Two phones through one fake relay, every connection joined.
    async fn two(mode: Mode) -> Two {
        let (url, seen) = fake_relay(mode).await;
        let (sa, token) = audio_start(&url, true);
        let (sb, _) = audio_start(&url, false);
        let aa = CallMedia::start_null(sa, crate::call::CONNECT_GIVE_UP);
        let ba = CallMedia::start_null(sb, crate::call::CONNECT_GIVE_UP);
        let a = VideoMedia::start(video_start(&url, true, aa.clone(), token)).unwrap();
        let b = VideoMedia::start(video_start(&url, false, ba.clone(), token)).unwrap();
        let audio_up = |m: &CallMedia| m.status(Instant::now()).connections == 2;
        wait_until("all lanes up", 5.0, || {
            audio_up(&aa) && audio_up(&ba) && video_up(&a) && video_up(&b)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await; // every join registered
        Two { a, b, aa, ba, seen }
    }

    fn picture(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ seed)
            .collect()
    }

    async fn take_one(v: &VideoMedia, out: &mut [u8], secs: f64) -> TakenFrame {
        let end = Instant::now() + Duration::from_secs_f64(secs);
        loop {
            if let Ok(Some(t)) = v.take(out, Instant::now()) {
                return t;
            }
            assert!(Instant::now() < end, "timed out waiting for a frame");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn start_outside_the_runtime_is_an_error_not_a_panic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let aa = rt.block_on(async {
            let (sa, _) = audio_start("ws://127.0.0.1:9/", true);
            CallMedia::start_null(sa, crate::call::CONNECT_GIVE_UP)
        });
        let s = video_start("ws://127.0.0.1:9/", true, aa.clone(), [0; 32]);
        assert!(matches!(VideoMedia::start(s), Err(CodecError::NoRuntime)));
        aa.stop();
    }

    #[test]
    fn hint_ints_are_in_declaration_order() {
        let h = EncoderHint {
            generation: 7,
            width: 1280,
            height: 720,
            fps: 30,
            bitrate: 1_300_000,
            keyframe: true,
            active: false,
        };
        assert_eq!(h.to_ints(), [7, 1280, 720, 30, 1_300_000, 1, 0]);
        assert_eq!(hold_ms(0), 0);
        assert_eq!(hold_ms(60), 0);
        assert_eq!(hold_ms(100), 40);
        assert_eq!(hold_ms(400), 150);
    }

    #[test]
    fn peer_notes_are_untrusted_and_stale_ones_count_as_not_bad() {
        let t0 = Instant::now();
        let mut p = PeerNotes::default();
        // unknown: not bad, no concealed share
        assert!(p.recv_good(t0) && !p.recv_bad_twice(t0));
        assert_eq!(p.concealed_pct, None);
        assert_eq!(p.send(t0), None);
        let bad = HealthNote {
            send: Health::Strained,
            recv: Health::Bad,
            rung: 200,
            audio_concealed_pct: 250,
            paused_out: false,
        };
        p.record(1, bad, t0);
        assert!(!p.recv_good(t0));
        assert!(!p.recv_bad_twice(t0), "one bad note is not two");
        p.record(2, bad, t0 + Duration::from_secs(1));
        assert!(p.recv_bad_twice(t0 + Duration::from_secs(1)));
        let (latest, _) = p.latest.unwrap();
        assert_eq!(latest.rung, 4, "rung clamped");
        assert_eq!(latest.audio_concealed_pct, 100, "pct clamped");
        assert_eq!(p.send(t0 + Duration::from_secs(1)), Some(Health::Strained));
        // stale after 3 s: not bad, unknown send, but the last share is kept
        let late = t0 + Duration::from_secs(5);
        assert!(p.recv_good(late) && !p.recv_bad_twice(late));
        assert_eq!(p.send(late), None);
        assert_eq!(p.concealed_pct, Some(100));
        // an older note arriving late changes nothing
        let good = HealthNote {
            recv: Health::Good,
            audio_concealed_pct: 0,
            ..bad
        };
        p.record(1, good, late);
        assert_eq!(p.concealed_pct, Some(100));
        // a paused rung stays 255
        p.record(3, HealthNote { rung: 255, ..good }, late);
        assert_eq!(p.latest.unwrap().0.rung, 255);
        assert_eq!(p.concealed_pct, Some(0));
    }

    #[tokio::test]
    async fn frames_round_trip_with_codec_rotation_and_hold() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let f = picture(20 * 1024, 1);
        assert_eq!(t.a.send_frame(&f, true, 90, now()), 3);
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        let got = take_one(&t.b, &mut out, 3.0).await;
        assert_eq!(got.len, f.len());
        assert_eq!(&out[..got.len], &f[..]);
        assert!(got.keyframe);
        assert_eq!(got.codec, VideoCodec::H265);
        assert_eq!(got.rotation_deg, 90);
        assert!(got.hold_ms <= 150);
        assert!(t.b.status(now()).first_frame);
        // every rotation, and bad input refused
        for (i, rot) in [0u16, 180, 270].into_iter().enumerate() {
            let f = picture(9000, i as u8);
            assert_eq!(t.a.send_frame(&f, false, rot, now()), 2);
            let got = take_one(&t.b, &mut out, 3.0).await;
            assert_eq!((got.rotation_deg, got.keyframe), (rot, false));
            assert_eq!(&out[..got.len], &f[..]);
        }
        assert_eq!(t.a.send_frame(&f, true, 45, now()), -9);
        assert_eq!(t.a.send_frame(&[], true, 0, now()), -9);
        assert_eq!(
            t.a.send_frame(&vec![0; VIDEO_MAX_FRAME + 1], true, 0, now()),
            -9
        );
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn nothing_is_sent_until_sending_is_allowed() {
        let t = two(Mode::Pair).await;
        let f = picture(4000, 2);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 0);
        assert!(!t.a.encoder_hint().active);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let s = t.seen.lock();
        assert_eq!(s.lane_in[2] + s.lane_in[3], 0);
        drop(s);
        t.a.set_sending(true);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 1);
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn a_lost_fragment_triggers_keyframe_requests_until_a_keyframe_arrives() {
        // Fragments on the video lanes: K 1-3, K2 4-6, P1 7-9 (8 is lost), P2 10-12.
        let t = two(Mode::DropNth(8)).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        let f = picture(20 * 1024, 3);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 3);
        take_one(&t.b, &mut out, 3.0).await;
        // requests from before the first keyframe have all landed; a
        // second keyframe clears what they asked for
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 3);
        take_one(&t.b, &mut out, 3.0).await;
        let h0 = t.a.encoder_hint();
        assert!(!h0.keyframe);
        let sent0 = t.b.keyframe_requests_sent();
        assert_eq!(t.a.send_frame(&f, false, 0, now()), 3);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(t.a.send_frame(&f, false, 0, now()), 3);
        wait_until("a keyframe asked of A", 1.0, || t.a.encoder_hint().keyframe).await;
        assert!(t.a.encoder_hint().generation > h0.generation);
        assert!(t.b.keyframe_requests_sent() > sent0, "B asked at once");
        assert!(matches!(t.b.take(&mut out, now()), Ok(None)), "P2 dropped");
        let sent1 = t.b.keyframe_requests_sent();
        tokio::time::sleep(Duration::from_millis(1300)).await;
        let sent2 = t.b.keyframe_requests_sent();
        assert!(
            sent2 >= sent1 + 2,
            "repeats every 500 ms: {sent1} -> {sent2}"
        );
        assert!(
            sent2 <= sent1 + 3,
            "no faster than every 500 ms: {sent1} -> {sent2}"
        );
        {
            let honoured = t.a.tx.lock().honoured.clone();
            assert!(!honoured.is_empty());
            for w in honoured.windows(2) {
                assert!(w[1] - w[0] >= KEY_HONOUR_GAP, "at most 1 per 500 ms");
            }
        }
        // the keyframe ends the requests
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 3);
        assert!(!t.a.encoder_hint().keyframe);
        let k = take_one(&t.b, &mut out, 3.0).await;
        assert!(k.keyframe);
        let sent3 = t.b.keyframe_requests_sent();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            t.b.keyframe_requests_sent(),
            sent3,
            "no requests after the keyframe"
        );
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn the_sender_honours_at_most_one_keyframe_request_per_500_ms() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        let f = picture(3000, 4);
        let t0 = now();
        assert_eq!(t.a.send_frame(&f, true, 0, t0), 1);
        assert!(!t.a.encoder_hint().keyframe);
        t.a.on_keyframe_request(t0);
        assert!(t.a.encoder_hint().keyframe);
        assert_eq!(t.a.send_frame(&f, true, 0, t0), 1);
        assert!(!t.a.encoder_hint().keyframe);
        t.a.on_keyframe_request(t0 + Duration::from_millis(100));
        t.a.on_keyframe_request(t0 + Duration::from_millis(499));
        assert!(!t.a.encoder_hint().keyframe, "inside 500 ms");
        t.a.on_keyframe_request(t0 + Duration::from_millis(500));
        assert!(t.a.encoder_hint().keyframe);
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn decoder_error_need_keyframe_asks_the_sender() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        let f = picture(3000, 5);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!t.a.encoder_hint().keyframe);
        let sent = t.b.keyframe_requests_sent();
        for _ in 0..30 {
            t.b.need_keyframe(now()); // a decoder failing on every frame
        }
        assert_eq!(
            t.b.keyframe_requests_sent(),
            sent + 1,
            "asked once, at once"
        );
        wait_until("A asked for a keyframe", 1.0, || {
            t.a.encoder_hint().keyframe
        })
        .await;
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn health_notes_flow_each_second_and_feed_the_banner() {
        let t = two(Mode::PairStallVideo).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let started = now();
        let a = t.a.clone();
        let feeder = tokio::spawn(async move {
            let mut enc = SyntheticEncoder::new(7);
            let end = Instant::now() + Duration::from_secs(14);
            while Instant::now() < end {
                if let Some((f, key)) = enc.next(&a.encoder_hint()) {
                    a.send_frame(&f, key, 0, Instant::now());
                }
                tokio::time::sleep(Duration::from_millis(33)).await;
            }
        });
        wait_until("A shows Mine", 12.0, || {
            t.a.status(now()).banner == Banner::Mine
        })
        .await;
        assert!(now() - started >= Duration::from_secs(3), "held 3 s first");
        wait_until("B shows Theirs", 12.0, || {
            t.b.status(now()).banner == Banner::Theirs
        })
        .await;
        assert!(t.b.ctl.lock().notes.latest.is_some(), "notes reached B");
        feeder.abort();
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn the_sealer_is_never_rebuilt() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        let f = picture(10_000, 6);
        assert_eq!(t.a.next_seq(), 0);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 2);
        let s1 = t.a.next_seq();
        assert_eq!(s1, 2);
        t.a.set_sending(false);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 0);
        assert_eq!(t.a.next_seq(), s1);
        t.a.set_sending(true);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 2);
        let s2 = t.a.next_seq();
        assert!(s2 > s1);
        t.a.lanes.restart(2);
        t.a.lanes.restart(3);
        tokio::time::sleep(Duration::from_millis(100)).await;
        wait_until("video lanes back", 5.0, || video_up(&t.a)).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let f2 = picture(10_000, 7);
        assert_eq!(t.a.send_frame(&f2, true, 0, now()), 2);
        assert!(t.a.next_seq() > s2);
        // the peer still opens it: the stream carried on, no reset
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            let got = take_one(&t.b, &mut out, 3.0).await;
            if out[..got.len] == f2[..] {
                break;
            }
            assert!(Instant::now() < end);
        }
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn stop_wipes_keys_and_later_calls_are_harmless() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let f = picture(3000, 8);
        t.a.stop();
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 0);
        assert!(!t.a.encoder_hint().active);
        assert!(t.a.tx.lock().sealer.is_none());
        assert!(t.a.rx.lock().opener.is_none());
        {
            let c = t.a.ctl.lock();
            assert!(c.sealer.is_none() && c.opener.is_none());
        }
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(matches!(t.b.take(&mut out, now()), Ok(None)));
        assert!(matches!(t.a.take(&mut out, now()), Ok(None)));
        t.a.need_keyframe(now());
        t.a.set_thermal(6);
        t.a.on_keyframe_request(now());
        t.a.on_control(&[5, 0x82, 0, 0], now());
        let _ = t.a.status(now());
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn take_into_a_too_small_buffer_drops_the_frame_and_asks_for_a_keyframe() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        let f = picture(20 * 1024, 9);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 3);
        assert!(!t.a.encoder_hint().keyframe);
        let mut small = vec![0u8; 1024];
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            match t.b.take(&mut small, now()) {
                Err(TooSmall) => break,
                Ok(None) => {}
                Ok(Some(_)) => panic!("a 20 KiB frame in 1 KiB"),
            }
            assert!(Instant::now() < end, "frame arrives");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        assert!(matches!(t.b.take(&mut out, now()), Ok(None)));
        wait_until("A asked for a keyframe", 1.0, || {
            t.a.encoder_hint().keyframe
        })
        .await;
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn the_engine_is_freed_after_stop() {
        let t = two(Mode::Pair).await;
        t.a.set_sending(true);
        t.b.set_receiving(true);
        let f = picture(3000, 10);
        assert_eq!(t.a.send_frame(&f, true, 0, now()), 1);
        tokio::time::sleep(Duration::from_millis(600)).await; // ticks and notes ran
        let (wa, waa) = (Arc::downgrade(&t.a), Arc::downgrade(&t.aa));
        let control: Arc<dyn VideoControl> = t.a.clone();
        control.stop();
        drop(control);
        t.aa.stop();
        let Two { a, b, aa, ba, .. } = t;
        drop(a);
        drop(aa);
        wait_until("both engines freed", 3.0, || {
            wa.upgrade().is_none() && waa.upgrade().is_none()
        })
        .await;
        b.stop();
        ba.stop();
    }

    #[tokio::test]
    async fn sender_queue_drop_sets_need_keyframe_and_drops_p_frames_until_one() {
        let t = two(Mode::PairStallVideo).await;
        t.a.set_sending(true);
        let key = picture(20_000, 11);
        assert_eq!(t.a.send_frame(&key, true, 0, now()), 3);
        assert!(!t.a.encoder_hint().keyframe);
        let p = picture(5 * 8192, 12);
        // No await while filling: the writers can't drain on this runtime.
        let mut queued = 0;
        loop {
            match t.a.send_frame(&p, false, 0, now()) {
                5 => queued += 1,
                0 => break,
                r => panic!("unexpected {r}"),
            }
            assert!(queued < 100, "the queues never filled");
        }
        assert!(queued >= 9);
        let h = t.a.encoder_hint();
        assert!(h.keyframe && h.active);
        // the writers drain some into the socket; P frames still drop
        tokio::time::sleep(Duration::from_millis(200)).await;
        let st = t.a.lanes.stats(now());
        assert!(
            st.iter()
                .any(|s| s.queued_bytes <= (48 - 5) * crate::call::video::MAX_VIDEO_WIRE),
            "room for a P frame: {st:?}"
        );
        assert_eq!(t.a.send_frame(&p, false, 0, now()), 0);
        assert_eq!(t.a.send_frame(&p, false, 0, now()), 0);
        assert!(t.a.encoder_hint().keyframe);
        assert_eq!(t.a.send_frame(&key, true, 0, now()), 3);
        assert!(!t.a.encoder_hint().keyframe);
        assert_eq!(t.a.send_frame(&p, false, 0, now()), 5);
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn encoder_hint_follows_the_rung_and_is_inactive_when_paused_or_not_sending() {
        let t = two(Mode::Pair).await;
        let h0 = t.a.encoder_hint();
        assert!(!h0.active);
        t.a.set_sending(true);
        let h = t.a.encoder_hint();
        assert_eq!(
            (h.width, h.height, h.fps, h.bitrate, h.active),
            (1280, 720, 30, 1_300_000, true)
        );
        assert!(h.generation > h0.generation, "generation bumps on change");
        assert_eq!(t.a.encoder_hint().generation, h.generation, "and only then");
        assert_eq!(t.a.status(now()).rung, Some(Rung::P720));
        t.a.set_sending(false);
        assert!(!t.a.encoder_hint().active);
        t.a.set_sending(true);
        t.a.set_thermal(5); // emergency: video pauses at the next tick
        wait_until("paused", 2.0, || !t.a.encoder_hint().active).await;
        let s = t.a.status(now());
        assert_eq!(s.rung, None);
        assert!(s.paused_out);
        assert_eq!(t.a.send_frame(&picture(100, 1), true, 0, now()), 0);
        t.a.stop();
        t.b.stop();
    }

    /// A peer that says its video is paused is not my downlink's fault: my
    /// notes to it must not say `recv` bad (it would step down and pause
    /// again the moment it resumed).
    #[tokio::test]
    async fn a_paused_peer_does_not_make_my_recv_bad() {
        let t = two(Mode::Pair).await;
        t.b.set_receiving(true);
        let paused = HealthNote {
            send: Health::Bad,
            recv: Health::Good,
            rung: RUNG_PAUSED,
            audio_concealed_pct: 0,
            paused_out: true,
        };
        // The peer keeps saying it is paused; 3.5 s with no frame, so
        // without the exemption B's later notes say bad.
        for i in 0..7u64 {
            t.b.ctl
                .lock()
                .notes
                .record(1_000 + i, paused, Instant::now());
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let latest = t.a.ctl.lock().notes.latest.map(|(n, _)| n);
        assert_eq!(latest.map(|n| n.recv), Some(Health::Good), "{latest:?}");
        t.a.stop();
        t.b.stop();
    }

    /// R15 delay term: complete frames, none lost, arriving 700 ms later
    /// than the fastest for over 1 s make my recv bad.
    #[tokio::test]
    async fn frames_arriving_late_make_my_recv_bad() {
        let t = two(Mode::Pair).await;
        t.b.set_receiving(true);
        let mut s = StreamSealer::new(
            &keys::derive(&ID, &[0x11; 32], &[0x22; 32], true).1.send,
            ID,
            STREAM_VIDEO,
        );
        let mut wire = vec![0u8; MAX_VIDEO_WIRE];
        let start = now();
        let mut k = 0u32;
        let mut late_from = None;
        while now() - start < Duration::from_secs(5) {
            let at = now();
            // On time for 1.5 s, then each frame 700 ms later than that.
            let lag = if at - start < Duration::from_millis(1500) {
                0
            } else {
                700
            };
            let h = FragHeader {
                frame_no: k,
                index: 0,
                count: 1,
                keyframe: k == 0,
                codec: VideoCodec::H265,
                rotation: 0,
                sent_ms: t.b.ms(at).wrapping_sub(lag),
            };
            let mut body = h.encode().to_vec();
            body.extend_from_slice(&[7; 100]);
            let n = s.seal(&body, &mut wire).unwrap();
            t.b.on_video_frame(&wire[..n], at);
            let mut out = vec![0u8; 4096];
            while let Ok(Some(_)) = t.b.take(&mut out, now()) {}
            if lag > 0 && late_from.is_none() {
                late_from = Some(at);
            }
            let latest = t.a.ctl.lock().notes.latest.map(|(n, _)| n.recv);
            if late_from.is_some_and(|l| now() - l > Duration::from_millis(1000))
                && latest == Some(Health::Bad)
            {
                assert_eq!(t.b.counters().frames_lost, 0, "nothing lost");
                t.a.stop();
                t.b.stop();
                return;
            }
            k += 1;
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
        panic!("B never said recv bad for late frames");
    }

    /// Just after the peer resumes (its probe), frames 300 ms later than
    /// the fastest make my recv bad at once (R11 fast failure), without the
    /// 400 ms / 1 s rule.
    #[tokio::test]
    async fn late_frames_just_after_the_peer_resumes_make_my_recv_bad_at_once() {
        let t = two(Mode::Pair).await;
        t.b.set_receiving(true);
        let mut s = StreamSealer::new(
            &keys::derive(&ID, &[0x11; 32], &[0x22; 32], true).1.send,
            ID,
            STREAM_VIDEO,
        );
        let mut wire = vec![0u8; MAX_VIDEO_WIRE];
        let note = |paused: bool| HealthNote {
            send: Health::Good,
            recv: Health::Good,
            rung: if paused { RUNG_PAUSED } else { 4 },
            audio_concealed_pct: 0,
            paused_out: paused,
        };
        let mut frame = |t: &Two, frame_no: u32, lag: u32| {
            let at = now();
            let h = FragHeader {
                frame_no,
                index: 0,
                count: 1,
                keyframe: frame_no == 0,
                codec: VideoCodec::H265,
                rotation: 0,
                sent_ms: t.b.ms(at).wrapping_sub(lag),
            };
            let mut body = h.encode().to_vec();
            body.extend_from_slice(&[7; 100]);
            let n = s.seal(&body, &mut wire).unwrap();
            t.b.on_video_frame(&wire[..n], at);
            let mut out = vec![0u8; 4096];
            while let Ok(Some(_)) = t.b.take(&mut out, now()) {}
        };
        for k in 0..20 {
            frame(&t, k, 0);
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
        t.b.ctl.lock().notes.record(10, note(true), now());
        tokio::time::sleep(Duration::from_millis(300)).await;
        t.b.ctl.lock().notes.record(11, note(false), now());
        let resumed = now();
        let mut k = 20;
        while now() - resumed < Duration::from_millis(2600) {
            let lag = 300;
            frame(&t, k, lag);
            k += 1;
            tokio::time::sleep(Duration::from_millis(33)).await;
            let latest = t.a.ctl.lock().notes.latest;
            if latest.is_some_and(|(n, at)| at > resumed && n.recv == Health::Bad) {
                t.a.stop();
                t.b.stop();
                return;
            }
        }
        panic!("B's recv never went bad for frames 300 ms late during the probe");
    }

    /// A peer that resumes after a pause skips the frame numbers it lost
    /// when its lanes reset; that gap is not a loss on my downlink, so my
    /// recv stays good (the clean-link re-pause of the recovery scenario).
    #[tokio::test]
    async fn a_gap_across_the_peers_pause_is_not_a_loss() {
        let t = two(Mode::Pair).await;
        t.b.set_receiving(true);
        let mut s = StreamSealer::new(
            &keys::derive(&ID, &[0x11; 32], &[0x22; 32], true).1.send,
            ID,
            STREAM_VIDEO,
        );
        let mut wire = vec![0u8; MAX_VIDEO_WIRE];
        let note = |paused: bool| HealthNote {
            send: if paused { Health::Bad } else { Health::Good },
            recv: Health::Good,
            rung: if paused { RUNG_PAUSED } else { 4 },
            audio_concealed_pct: 0,
            paused_out: paused,
        };
        let mut seq = 1_000u64;
        let mut frame = |t: &Two, frame_no: u32, key: bool| {
            let at = now();
            let h = FragHeader {
                frame_no,
                index: 0,
                count: 1,
                keyframe: key,
                codec: VideoCodec::H265,
                rotation: 0,
                sent_ms: t.b.ms(at),
            };
            let mut body = h.encode().to_vec();
            body.extend_from_slice(&[7; 100]);
            let n = s.seal(&body, &mut wire).unwrap();
            t.b.on_video_frame(&wire[..n], at);
            let mut out = vec![0u8; 4096];
            while let Ok(Some(_)) = t.b.take(&mut out, now()) {}
        };
        let mut note_at = |t: &Two, paused: bool| {
            seq += 1;
            t.b.ctl.lock().notes.record(seq, note(paused), now());
        };
        for k in 0..30 {
            frame(&t, k, k == 0);
            if k % 15 == 0 {
                note_at(&t, false);
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
        // Paused for 2 s; 20 frame numbers went with the lane reset.
        for _ in 0..4 {
            note_at(&t, true);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let mut bad = false;
        for k in 50..140u32 {
            frame(&t, k, k == 50);
            if k % 15 == 5 {
                note_at(&t, false);
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
            let latest = t.a.ctl.lock().notes.latest.map(|(n, _)| n.recv);
            bad |= latest == Some(Health::Bad);
        }
        assert!(!bad, "B's recv stayed good across the peer's pause");
        assert!(t.b.counters().frames_lost >= 20, "the gap was there");
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn pausing_flushes_what_waits_on_the_video_lanes() {
        let t = two(Mode::PairStallVideo).await;
        t.a.set_sending(true);
        let mut enc = SyntheticEncoder::new(3);
        let queued = |v: &VideoMedia| {
            v.lanes
                .stats(Instant::now())
                .iter()
                .map(|s| s.queued_bytes)
                .sum::<usize>()
        };
        // The stalled socket takes a few hundred KiB, then frames wait.
        for _ in 0..2000 {
            if queued(&t.a) > 0 {
                break;
            }
            if let Some((f, key)) = enc.next(&t.a.encoder_hint()) {
                t.a.send_frame(&f, key, 0, now());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(queued(&t.a) > 0, "video waits behind the stalled lanes");
        t.a.set_thermal(5); // emergency: paused at the next tick
        wait_until("paused", 2.0, || !t.a.encoder_hint().active).await;
        assert_eq!(queued(&t.a), 0, "nothing stale left to compete with audio");
        // The kernel's share goes too: both lanes reset and reopen.
        wait_until("both lanes reopened", 5.0, || {
            t.a.counters().lane_reconnects >= 2 && video_up(&t.a)
        })
        .await;
        t.a.stop();
        t.b.stop();
    }

    /// The backlog the adapter sees is the chosen lane's: a lane the frames
    /// moved off had what waited there dropped, so one left stuck (no write
    /// progress for seconds) cannot drive a step-down or a pause.
    #[tokio::test]
    async fn a_stuck_lane_left_behind_does_not_drive_the_adapter() {
        let t = two(Mode::Pair).await;
        t.a.tx.lock().last_lane = Some(3);
        let lane = |up: bool, oldest: Option<u64>, stuck_ms: u64| LaneStats {
            up,
            queued_bytes: usize::from(oldest.is_some()) * 5000,
            oldest: oldest.map(Duration::from_millis),
            since_progress: Duration::from_millis(stuck_ms),
        };
        let stats = [lane(true, Some(2500), 3000), lane(true, None, 0)];
        let t0 = now();
        let calm = PeerView {
            recv_good: true,
            concealed: Some(0),
            ..PeerView::default()
        };
        for k in 0..20u32 {
            let (rung, backlog, _, _) = t.a.adapt(t0 + TICK * k, true, &stats, calm);
            assert_eq!(backlog, Duration::ZERO);
            assert_eq!(rung, Some(Rung::P720), "tick {k}: no step-down");
        }
        let (_, backlog, _, _) = t.a.adapt(
            t0 + TICK * 20,
            true,
            &[lane(true, None, 0), lane(true, Some(400), 0)],
            calm,
        );
        assert_eq!(backlog, Duration::from_millis(400), "the chosen lane's");
        t.a.stop();
        t.b.stop();
    }

    #[tokio::test]
    async fn hostile_frames_never_panic() {
        let t = two(Mode::Pair).await;
        t.b.set_receiving(true);
        let mut f = vec![0u8; MAX_VIDEO_WIRE + 10];
        for len in [
            0usize,
            1,
            2,
            10,
            26,
            27,
            40,
            MAX_VIDEO_WIRE,
            MAX_VIDEO_WIRE + 10,
        ] {
            f.truncate(len);
            f.resize(len, 0);
            if len > 1 {
                f[0] = 5;
                f[1] = STREAM_VIDEO;
            }
            t.b.on_video_frame(&f, now());
            if len > 1 {
                f[1] = STREAM_CONTROL;
            }
            t.b.on_control(&f, now());
        }
        // an authentic fragment with a bad header is dropped
        let mut s = StreamSealer::new(
            &keys::derive(&ID, &[0x11; 32], &[0x22; 32], true).1.send,
            ID,
            STREAM_VIDEO,
        );
        let mut wire = vec![0u8; MAX_VIDEO_WIRE];
        for body in [
            &[0u8; 3][..],
            &[0, 0, 0, 1, 5, 2, 0, 1][..],
            &[0, 0, 0, 1, 0, 1, 0xF0, 1][..],
        ] {
            let n = s.seal(body, &mut wire).unwrap();
            t.b.on_video_frame(&wire[..n], now());
        }
        let mut out = vec![0u8; 64];
        assert!(matches!(t.b.take(&mut out, now()), Ok(None)));
        t.a.stop();
        t.b.stop();
    }
}
