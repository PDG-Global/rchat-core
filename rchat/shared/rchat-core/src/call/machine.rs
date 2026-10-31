//! The call state machine (spec §3, §4). It lives in `ClientInner`, so
//! signalling goes through the ratchet session like any plaintext and the
//! timers run on the client's 250 ms ticker. One call at a time. Events go
//! to a queue the app polls (D19); media runs in `CallMedia`, reached by
//! the app's audio thread without the client lock (D37). A fresh Offer
//! settles for `RING_SETTLE` before it rings, so an Offer followed by its
//! End (D13) is recorded as missed and never rings.
//!
//! Video (video spec §4, R1, R7, R17-R19) rides on the same call: Caps
//! (`0x0E`) go right behind the Offer, the Ringing and, in glare, before
//! the Answer; the Offer itself stays the 59-byte 2.2.0 one. Requests,
//! Accepts, Declines and Camera changes ride in the ratchet. The video
//! engine starts at most once per call, when video is first agreed while
//! connecting or connected, with the video keys kept from the Answer.

use super::engine::{CallMedia, MediaStart, MediaStatus};
use super::keys::{self, CallKeys, VideoKeys};
use super::lanes::LaneConfig;
use super::signal::{CallSignal, EndReason};
use super::video::engine::{VideoControl, VideoMedia, VideoStart};
use super::video::health::Banner;
use super::video::signal::{Caps, VideoSignal};
use super::video::{agree_codec, Quality, VideoCodec};
use super::*;
use crate::protocol::ControlMessage;
use crate::{ClientInner, RChatError};
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// D13: an Offer that never left is kept this long for its peer.
const LATE_OFFER_TTL: Duration = Duration::from_secs(24 * 3600);
/// D11: Offers held until the queue handover, at most; one more is missed.
const MAX_HELD_OFFERS: usize = 4;
/// D13: a fresh Offer rings only once it has waited this long, so its End,
/// sent right behind it (a late Offer, or a caller who gave up), lands first.
pub const RING_SETTLE: Duration = Duration::from_millis(500);
const STATUS_EVERY: Duration = Duration::from_secs(1);
/// R17: after a Decline, a new Request waits this long.
pub const REQUEST_AFTER_DECLINE: Duration = Duration::from_secs(30);
/// R19: tick-polled video fields go out at most this often.
const VIDEO_STATUS_EVERY: Duration = Duration::from_secs(1);
/// A peer's requests raise a `video_request` event at most this often
/// (`request_in` in the `video` event stays exact).
const REQUEST_EVENT_EVERY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Outgoing => "out",
            Self::Incoming => "in",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallResult {
    Completed,
    Missed,
    Declined,
    NoAnswer,
    Busy,
    Unreachable,
    Failed,
    Cancelled,
}

impl CallResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Missed => "missed",
            Self::Declined => "declined",
            Self::NoAnswer => "no_answer",
            Self::Busy => "busy",
            Self::Unreachable => "unreachable",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum CallEvent {
    /// `video`: placed as a video call (Caps said so).
    Outgoing {
        call_id: CallId,
        peer: String,
        video: bool,
    },
    Ringing {
        call_id: CallId,
    },
    /// `video`: rings as a video call (R18).
    Incoming {
        call_id: CallId,
        peer: String,
        video: bool,
    },
    Connecting {
        call_id: CallId,
        peer: String,
        replaced: Option<CallId>,
    },
    Connected {
        call_id: CallId,
        at_ms: u64,
    },
    Status {
        call_id: CallId,
        status: MediaStatus,
    },
    Ended {
        call_id: CallId,
        peer: String,
        direction: Direction,
        result: CallResult,
        duration_secs: u64,
        started_at_ms: u64,
        /// Video was agreed at some point in the call (R19).
        video: bool,
    },
    /// The peer asks to switch to video (one-shot).
    VideoRequest {
        call_id: CallId,
    },
    /// The peer said Not now to our request (one-shot).
    VideoDeclined {
        call_id: CallId,
    },
    Video {
        call_id: CallId,
        state: VideoState,
    },
}

/// Never logged: it names a contact.
impl std::fmt::Debug for CallEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ended {
                result,
                direction,
                duration_secs,
                ..
            } => write!(f, "Ended({result:?}, {direction:?}, {duration_secs}s)"),
            other => f.write_str(match other {
                Self::Outgoing { .. } => "Outgoing",
                Self::Ringing { .. } => "Ringing",
                Self::Incoming { .. } => "Incoming",
                Self::Connecting { .. } => "Connecting",
                Self::Connected { .. } => "Connected",
                Self::VideoRequest { .. } => "VideoRequest",
                Self::VideoDeclined { .. } => "VideoDeclined",
                Self::Video { .. } => "Video",
                _ => "Status",
            }),
        }
    }
}

impl CallEvent {
    pub fn to_json(&self) -> String {
        use serde_json::json;
        match self {
            Self::Outgoing { call_id, peer, video } => json!({"type": "outgoing", "call_id": call_id.hex(), "peer": peer, "video": video}),
            Self::Ringing { call_id } => json!({"type": "ringing", "call_id": call_id.hex()}),
            Self::Incoming { call_id, peer, video } => json!({"type": "incoming", "call_id": call_id.hex(), "peer": peer, "video": video}),
            Self::Connecting { call_id, peer, replaced } => json!({
                "type": "connecting", "call_id": call_id.hex(), "peer": peer,
                "replaced_call_id": replaced.map(|r| r.hex()),
            }),
            Self::Connected { call_id, at_ms } => json!({"type": "connected", "call_id": call_id.hex(), "at_ms": at_ms}),
            Self::Status { call_id, status } => json!({
                "type": "status", "call_id": call_id.hex(), "concealed_pct": status.concealed_pct,
                "connections": status.connections, "poor": status.poor, "reconnecting": status.reconnecting,
            }),
            Self::Ended { call_id, peer, direction, result, duration_secs, started_at_ms, video } => json!({
                "type": "ended", "call_id": call_id.hex(), "peer": peer, "direction": direction.as_str(),
                "result": result.as_str(), "duration_secs": duration_secs, "started_at_ms": started_at_ms,
                "video": video,
            }),
            Self::VideoRequest { call_id } => json!({"type": "video_request", "call_id": call_id.hex()}),
            Self::VideoDeclined { call_id } => json!({"type": "video_declined", "call_id": call_id.hex()}),
            Self::Video { call_id, state } => json!({
                "type": "video", "call_id": call_id.hex(), "available": state.available.as_str(),
                "agreed": state.agreed, "camera": state.camera, "peer_camera": state.peer_camera,
                "peer_shown": state.peer_shown, "paused_in": state.paused_in, "paused_out": state.paused_out,
                "banner": match state.banner {
                    Banner::None => "none",
                    Banner::Mine => "mine",
                    Banner::Theirs => "theirs",
                },
                "codec": state.codec.map(|c| match c {
                    VideoCodec::H265 => "h265",
                    VideoCodec::H264 => "h264",
                }),
                "request_in": state.request_in,
            }),
        }
        .to_string()
    }
}

pub(crate) trait MediaControl: Send + Sync {
    fn push_pcm(&self, pcm: &[i16]) -> usize;
    fn pull_pcm(&self, out: &mut [i16]) -> usize;
    fn set_muted(&self, muted: bool);
    fn status(&self, now: Instant) -> MediaStatus;
    fn stop(&self);
    /// The audio engine's link for video (control frames, audio health).
    /// Only the real engine has one.
    fn audio_link(self: Arc<Self>) -> Option<Arc<dyn super::engine::AudioLink>> {
        None
    }
}

pub(crate) trait MediaStarter: Send + Sync {
    fn start(&self, s: MediaStart) -> Option<Arc<dyn MediaControl>>;
    /// The call's video engine; called at most once per call.
    fn start_video(&self, s: VideoStart) -> Option<Arc<dyn VideoControl>>;
}

/// Starts the real engine (`CallMedia::start`, never `start_with`) on the
/// client's own long-lived runtime, whatever thread asks: the call
/// connections and the watchdog are spawned onto it and must outlive the
/// call, so never onto a short `block_on` runtime. Without that runtime
/// (or without the codec) there is no media and the call fails.
pub(crate) struct RealStarter {
    runtime: Option<tokio::runtime::Handle>,
}

impl RealStarter {
    pub(crate) fn new(runtime: Option<tokio::runtime::Handle>) -> Self {
        Self { runtime }
    }
}

impl MediaStarter for RealStarter {
    fn start(&self, s: MediaStart) -> Option<Arc<dyn MediaControl>> {
        let _on_client_runtime = self.runtime.as_ref()?.enter();
        CallMedia::start(s).ok().map(|m| m as Arc<dyn MediaControl>)
    }

    /// As `start`: on the client's runtime, which the video connections
    /// and the tick must outlive the call on.
    fn start_video(&self, s: VideoStart) -> Option<Arc<dyn VideoControl>> {
        let _on_client_runtime = self.runtime.as_ref()?.enter();
        VideoMedia::start(s)
            .ok()
            .map(|m| m as Arc<dyn VideoControl>)
    }
}

/// Whether video can run on this call (R19 `available`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// The peer's Caps have not arrived yet (or this phone has no video).
    Unknown,
    Yes,
    /// The peer announced no video (or answered without Caps: 2.2.0).
    Peer,
    /// This relay has no `video-v1`, refused the video connections, or
    /// the video engine could not start.
    Relay,
}

impl Availability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Yes => "yes",
            Self::Peer => "peer",
            Self::Relay => "relay",
        }
    }
}

/// The `video` event's fields (R19). Signalling-driven fields change at
/// once; `paused_in`, `paused_out` and `banner` are tick-polled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoState {
    pub available: Availability,
    pub agreed: bool,
    /// My camera is wanted on (agreed, or a pending request, or a header
    /// video call's preview).
    pub camera: bool,
    pub peer_camera: bool,
    /// `agreed && peer_camera`.
    pub peer_shown: bool,
    pub paused_in: bool,
    pub paused_out: bool,
    pub banner: Banner,
    pub codec: Option<VideoCodec>,
    /// An incoming request is still waiting for Accept / Not now.
    pub request_in: bool,
}

/// What this phone announces in Caps, set by the app (`call_video_configure`)
/// and read when a call starts: a running call keeps what it announced.
#[derive(Default)]
pub struct VideoPrefs {
    codecs: AtomicU8,
    want_1080: AtomicBool,
    thermal: AtomicU8,
    software: AtomicBool,
}

impl VideoPrefs {
    /// `codecs`: bit0 H.265, bit1 H.264 (other bits ignored).
    pub fn set(&self, codecs: u8, want_1080: bool, software: bool) {
        self.codecs.store(codecs & 0b11, Ordering::SeqCst);
        self.want_1080.store(want_1080, Ordering::SeqCst);
        self.software.store(software, Ordering::SeqCst);
    }

    /// `PowerManager` thermal status, 0-6.
    pub fn set_thermal(&self, level: u8) {
        self.thermal.store(level.min(6), Ordering::SeqCst);
    }

    pub fn thermal(&self) -> u8 {
        self.thermal.load(Ordering::SeqCst)
    }

    /// (codec mask, 1080p wanted, software encoder, thermal level).
    pub fn snapshot(&self) -> (u8, bool, bool, u8) {
        (
            self.codecs.load(Ordering::SeqCst),
            self.want_1080.load(Ordering::SeqCst),
            self.software.load(Ordering::SeqCst),
            self.thermal(),
        )
    }

    /// Take over another set of prefs (the process-wide ones, at install).
    pub fn copy_from(&self, other: &VideoPrefs) {
        let (codecs, want_1080, software, thermal) = other.snapshot();
        self.set(codecs, want_1080, software);
        self.set_thermal(thermal);
    }

    /// The Caps this phone sends: no video without codecs or without a
    /// relay with `video-v1`; a header video call only with video (R9, R18).
    pub(crate) fn caps(&self, relay_video: bool, video_call: bool) -> Caps {
        let codecs = self.codecs.load(Ordering::SeqCst);
        let video = relay_video && codecs != 0;
        Caps {
            video,
            video_call: video && video_call,
            codecs,
            max_recv: if self.want_1080.load(Ordering::SeqCst) {
                Quality::P1080
            } else {
                Quality::P720
            },
        }
    }
}

/// The video side of one call (R17-R19). The video keys are kept from the
/// Answer until the engine starts (they move into it) or the call ends
/// (dropped, wiped); the engine is created at most once per call, so its
/// sealers, and so its nonces, are never rebuilt.
pub(crate) struct VideoCall {
    mine: Caps,
    peer: Option<Caps>,
    /// A header video call: placed as one, or rings as one (R18).
    video_call: bool,
    agreed: bool,
    camera: bool,
    peer_camera: bool,
    /// R17: the 30 s limit runs only from a received Decline.
    declined_at: Option<Instant>,
    request_pending_out: bool,
    /// We sent a Request in this call (kept after a withdrawal): only then
    /// does the peer's Accept count, so agreement always follows a local
    /// action.
    requested_this_call: bool,
    request_in: bool,
    /// When the last `video_request` event went out.
    last_request_event: Option<Instant>,
    /// An automatic Not now went out (at most once per call).
    auto_declined: bool,
    keys: Option<VideoKeys>,
    relay_token: Option<Zeroizing<[u8; 32]>>,
    role: u8,
    media: Option<Arc<dyn VideoControl>>,
    had_video: bool,
    available: Availability,
    /// When the last tick-polled `video` event went out.
    last_event: Option<Instant>,
    /// This phone's relay announced `video-v1` when the call began.
    relay_ok: bool,
    /// The video engine could not start, or the relay refused its lanes.
    failed: bool,
    /// The caller got the Answer before any Caps (a 2.2.0 peer).
    answered_without_caps: bool,
    /// Both phones placed a call to each other at once (§3).
    glare: bool,
    /// The last `video` event, `None` until the first one is due.
    last_state: Option<VideoState>,
}

impl Default for VideoCall {
    fn default() -> Self {
        Self::new(
            Caps {
                video: false,
                video_call: false,
                codecs: 0,
                max_recv: Quality::P720,
            },
            false,
        )
    }
}

impl VideoCall {
    fn new(mine: Caps, relay_ok: bool) -> Self {
        let mut v = Self {
            mine,
            peer: None,
            video_call: mine.video_call,
            agreed: false,
            camera: mine.video_call,
            peer_camera: false,
            declined_at: None,
            request_pending_out: false,
            requested_this_call: false,
            request_in: false,
            last_request_event: None,
            auto_declined: false,
            keys: None,
            relay_token: None,
            role: 0,
            media: None,
            had_video: false,
            available: Availability::Unknown,
            last_event: None,
            relay_ok,
            failed: false,
            answered_without_caps: false,
            glare: false,
            last_state: None,
        };
        v.refresh();
        // A voice call says nothing until something changes; a video
        // intent is reported at once.
        if !mine.video_call {
            v.last_state = Some(v.state());
        }
        v
    }

    fn refresh(&mut self) {
        self.available = if !self.relay_ok || self.failed {
            Availability::Relay
        } else if !self.mine.video {
            Availability::Unknown
        } else {
            match self.peer {
                Some(p) if p.video && agree_codec(self.mine.codecs, p.codecs).is_some() => {
                    Availability::Yes
                }
                Some(_) => Availability::Peer,
                None if self.answered_without_caps => Availability::Peer,
                None => Availability::Unknown,
            }
        };
        if self.agreed {
            self.had_video = true;
        }
    }

    /// Only when both set the video bit (R9): `Caps.video == false` is no
    /// video whatever its codec bits say.
    fn codec(&self) -> Option<VideoCodec> {
        match self.peer {
            Some(p) if p.video && self.mine.video => agree_codec(self.mine.codecs, p.codecs),
            _ => None,
        }
    }

    fn state(&self) -> VideoState {
        let running = self.media.is_some() && !self.failed;
        let (banner, paused_in, paused_out) = match (running, self.last_state) {
            (true, Some(s)) => (s.banner, s.paused_in, s.paused_out),
            _ => (Banner::None, false, false),
        };
        VideoState {
            available: self.available,
            agreed: self.agreed,
            camera: self.camera,
            peer_camera: self.peer_camera,
            peer_shown: self.agreed && self.peer_camera,
            paused_in,
            paused_out,
            banner,
            codec: if self.available == Availability::Yes {
                self.codec()
            } else {
                None
            },
            request_in: self.request_in,
        }
    }

    /// Glare, on the phone that switched to the peer's call, once the
    /// peer's Caps are known (R17, R18): both placed video calls → agreed,
    /// both shown; otherwise voice, and our camera stops as the other
    /// phone's does at its Answer.
    fn settle_glare(&mut self) {
        let Some(p) = self.peer else {
            return;
        };
        if !self.glare || self.agreed {
            return;
        }
        if self.mine.video_call && p.video_call && self.available == Availability::Yes {
            self.agreed = true;
            self.peer_camera = true;
        } else {
            self.camera = false;
            self.peer_camera = false;
        }
    }

    /// Video can't run on this call (the engine failed to start, or the
    /// relay refused its lanes): my camera stops, the call goes on.
    fn fail(&mut self) {
        self.failed = true;
        self.camera = false;
        self.request_pending_out = false;
        self.refresh();
    }

    fn apply(&self) {
        if let Some(m) = &self.media {
            m.set_sending(self.agreed && self.camera);
            m.set_receiving(self.agreed && self.peer_camera);
        }
    }
}

pub(crate) enum Phase {
    Outgoing {
        offer_sent: bool,
        ringing: bool,
        caller_rand: Zeroizing<[u8; 32]>,
        sent_at_ms: u64,
    },
    /// `rang`: the settle is over, Ringing went and the app was told (D13).
    Incoming {
        caller_rand: Zeroizing<[u8; 32]>,
        received_at: Instant,
        rang: bool,
    },
    Connecting {
        since: Instant,
        granted: bool,
        token: Zeroizing<[u8; 32]>,
    },
    Connected {
        at: Instant,
        last_status: Instant,
    },
}

pub(crate) struct ActiveCall {
    pub(crate) id: CallId,
    pub(crate) peer: String,
    pub(crate) direction: Direction,
    pub(crate) placed_at: Instant,
    pub(crate) started_at_ms: u64,
    pub(crate) phase: Phase,
    pub(crate) media: Option<Arc<dyn MediaControl>>,
    pub(crate) video: VideoCall,
}

impl ActiveCall {
    /// The app has been told of this call (an incoming call once it rang).
    fn known_to_app(&self) -> bool {
        !matches!(self.phase, Phase::Incoming { rang: false, .. })
    }
}

pub(crate) struct HeldOffer {
    from: String,
    call_id: CallId,
    caller_rand: Zeroizing<[u8; 32]>,
    /// The peer's clock: for the 60 s age check only.
    sent_at_ms: u64,
    /// Our clock when it arrived: the time a missed call is recorded at.
    received_ms: u64,
    ended: bool,
    /// The caller's Caps, if they came before the handover (R1).
    caps: Option<Caps>,
}

pub(crate) struct LateOffer {
    pub(crate) offer: CallSignal,
    pub(crate) end: CallSignal,
    pub(crate) at: Instant,
}

pub(crate) struct CallSlot {
    pub(crate) active: Option<ActiveCall>,
    pub(crate) held: Vec<HeldOffer>,
    pub(crate) late: HashMap<String, LateOffer>,
    /// `QueueHandedOver` seen on this connection (D11).
    pub(crate) handed_over: bool,
    pub(crate) events: Arc<Mutex<VecDeque<CallEvent>>>,
    pub(crate) audio: Arc<Mutex<Option<Arc<dyn MediaControl>>>>,
    pub(crate) muted: Arc<AtomicBool>,
    /// The current call's video engine, for the app's encoder and decoder
    /// threads without the client lock.
    pub(crate) video: Arc<Mutex<Option<Arc<dyn VideoControl>>>>,
    pub(crate) video_prefs: Arc<VideoPrefs>,
    pub(crate) starter: Arc<dyn MediaStarter>,
    #[cfg(test)]
    pub(crate) next_call_id: Option<CallId>,
    /// Tests: behave as a 2.2.0 core (drop `0x0E`, send no Caps).
    #[cfg(test)]
    pub(crate) ignore_video: bool,
    /// Tests: every call and video plaintext decrypted, in order.
    #[cfg(test)]
    pub(crate) heard: Vec<Vec<u8>>,
}

impl Default for CallSlot {
    fn default() -> Self {
        Self {
            active: None,
            held: Vec::new(),
            late: HashMap::new(),
            handed_over: false,
            events: Arc::default(),
            audio: Arc::default(),
            muted: Arc::default(),
            video: Arc::default(),
            video_prefs: Arc::default(),
            // `RChatClient::new` gives it the client's runtime.
            starter: Arc::new(RealStarter::new(None)),
            #[cfg(test)]
            next_call_id: None,
            #[cfg(test)]
            ignore_video: false,
            #[cfg(test)]
            heard: Vec::new(),
        }
    }
}

/// Applies the mute flag to `media` until the flag reads the same after
/// the apply as before it. Both writers (the app's `set_muted`: store the
/// flag, then find the media in the slot; `call_begin_connecting`: publish
/// the media in the slot, then this) end with it, so under any interleaving
/// the media's last mute write equals the flag's last value: take the last
/// write to the media and the re-check that follows it. If that re-check
/// comes after the flag's last store it saw the final value, and the loop
/// only stops when it applied that value. If it came before, the flag was
/// stored after this writer's last apply; the writer that stored it then
/// either found the media in the slot and applied after it (so this was not
/// the last write), or found the slot empty, which puts its store before
/// the media was published and so before this re-check. Either way the
/// contradiction leaves only the first case.
pub(crate) fn apply_mute(flag: &AtomicBool, media: &dyn MediaControl) {
    loop {
        let muted = flag.load(Ordering::SeqCst);
        media.set_muted(muted);
        if flag.load(Ordering::SeqCst) == muted {
            break;
        }
    }
}

fn random32() -> Zeroizing<[u8; 32]> {
    let mut r = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut r[..]);
    r
}

impl ClientInner {
    fn call_event(&self, ev: CallEvent) {
        let was_empty = {
            let mut q = self.call.events.lock();
            let was = q.is_empty();
            // A `video` event replaces one for the same call still waiting
            // at the back of the queue: the app needs only the latest, and a
            // busy peer can't grow the queue.
            let same = matches!(
                (&ev, q.back()),
                (CallEvent::Video { call_id: a, .. }, Some(CallEvent::Video { call_id: b, .. }))
                    if a == b
            );
            match q.back_mut() {
                Some(back) if same => *back = ev,
                _ => q.push_back(ev),
            }
            was
        };
        if was_empty {
            self.emit_status(crate::status::StatusEvent::CallEvents);
        }
    }

    fn call_send(&self, peer: &str, sig: &CallSignal) -> Result<(), RChatError> {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let packet = self.seal_ratchet(peer, id, &sig.encode())?;
        self.send_now(packet.encode_with_frame_type())
    }

    /// Grants the call's relay token on the chat circuit with `peer`, once
    /// per call (only from `Connecting`, and never again once sent): after a
    /// network switch the circuit ids change and the relay refuses a second
    /// grant of a live token, while the token already granted and the call
    /// connections carry on.
    fn call_grant(&self, peer: &str, token: &[u8; 32]) -> bool {
        if !self.has_live_circuit(peer) {
            return false;
        }
        let Some(circuit_id) = self
            .session_manager
            .get(peer)
            .and_then(|s| s.circuit_id.clone())
        else {
            return false;
        };
        self.send_now(
            ControlMessage::MediaGrant {
                circuit_id,
                token: *token,
            }
            .encode_with_frame_type(),
        )
        .is_ok()
    }

    fn call_lane_config(&self) -> Option<LaneConfig> {
        Some(LaneConfig {
            server_url: self.config.server_url.clone(),
            dev_origin: self.config.dev_origin.clone(),
            relay_pin: self.config.relay_pin.clone()?,
            relay_pin_version: self.config.relay_pin_version,
            tls_fingerprint: self.config.tls_fingerprint,
            resumption: Some(self.tls_tickets.clone()),
        })
    }

    /// Answered (either side): grant, start media, Connecting.
    fn call_begin_connecting(
        &mut self,
        (keys, video_keys): (CallKeys, VideoKeys),
        role: u8,
        now: Instant,
        replaced: Option<CallId>,
    ) -> bool {
        let Some(a) = self.call.active.as_ref() else {
            return false;
        };
        let (id, peer) = (a.id, a.peer.clone());
        let token = keys.relay_token.clone();
        let Some(lane) = self.call_lane_config() else {
            return false;
        };
        let Some(media) = self.call.starter.start(MediaStart {
            call_id: id,
            role,
            keys,
            lane,
        }) else {
            return false;
        };
        // Granted only once the media runs: a call that fails here never
        // leaves a granted token behind.
        let granted = self.call_grant(&peer, &token);
        // Published first, then the mute applied until stable (see
        // `apply_mute`): correct whatever an app `set_muted` does meanwhile.
        *self.call.audio.lock() = Some(media.clone());
        apply_mute(&self.call.muted, media.as_ref());
        if let Some(a) = self.call.active.as_mut() {
            a.phase = Phase::Connecting {
                since: now,
                granted,
                token: token.clone(),
            };
            a.media = Some(media);
            // Kept for the call's life until video starts (R5).
            a.video.keys = Some(video_keys);
            a.video.relay_token = Some(token);
            a.video.role = role;
        }
        self.call_event(CallEvent::Connecting {
            call_id: id,
            peer,
            replaced,
        });
        true
    }

    /// The call is over: media stopped, keys dropped (zeroized), event out.
    /// Every end goes through here.
    fn call_finish(&mut self, result: CallResult, now: Instant) {
        let Some(a) = self.call.active.take() else {
            return;
        };
        // Video stops before audio (its control frames ride the audio).
        if let Some(m) = &a.video.media {
            m.stop();
        }
        // The slot holds the same engine (stopped above); dropped with the
        // lock released.
        let slot = self.call.video.lock().take();
        drop(slot);
        if let Some(m) = &a.media {
            m.stop();
        }
        // Taken with the slot's lock released before the stop.
        let slot = self.call.audio.lock().take();
        if let Some(m) = slot {
            m.stop(); // the same media; stop is idempotent
        }
        self.call.muted.store(false, Ordering::SeqCst);
        let duration_secs = match a.phase {
            Phase::Connected { at, .. } => now.saturating_duration_since(at).as_secs(),
            _ => 0,
        };
        self.call_event(CallEvent::Ended {
            call_id: a.id,
            peer: a.peer,
            direction: a.direction,
            result,
            duration_secs,
            started_at_ms: a.started_at_ms,
            video: a.video.had_video,
        });
        // `a` drops here: any video keys never handed to an engine are wiped.
    }

    fn call_send_end(&mut self, reason: EndReason) {
        if let Some(a) = &self.call.active {
            let (peer, id) = (a.peer.clone(), a.id);
            let _ = self.call_send(
                &peer,
                &CallSignal::End {
                    call_id: id,
                    reason,
                },
            );
        }
    }

    pub(crate) fn call_place(
        &mut self,
        peer: &str,
        now: Instant,
        now_ms: u64,
    ) -> Result<CallId, RChatError> {
        self.call_place_as(peer, now, now_ms, false)
    }

    /// A header video call (R18): Caps say "video call". On a relay without
    /// `video-v1` it places a voice call and says `available: relay`.
    pub(crate) fn call_place_video(
        &mut self,
        peer: &str,
        now: Instant,
        now_ms: u64,
    ) -> Result<CallId, RChatError> {
        self.call_place_as(peer, now, now_ms, true)
    }

    fn call_place_as(
        &mut self,
        peer: &str,
        now: Instant,
        now_ms: u64,
        video: bool,
    ) -> Result<CallId, RChatError> {
        if !self.config.calls_enabled {
            return Err(RChatError::InvalidParameter {
                message: "calls are off".into(),
            });
        }
        if !self.relay_calls {
            return Err(RChatError::RelayNoCalls);
        }
        if self.call.active.is_some() {
            return Err(RChatError::CallInProgress);
        }
        self.check_sendable(peer)?;
        #[cfg(test)]
        let id = self.call.next_call_id.take().unwrap_or_else(CallId::random);
        #[cfg(not(test))]
        let id = CallId::random();
        // As a message does: ask for the circuit if none is open (spec §4).
        self.ask(peer, crate::circuits::AskTrigger::User, now)?;
        self.call.active = Some(ActiveCall {
            id,
            peer: peer.to_string(),
            direction: Direction::Outgoing,
            placed_at: now,
            started_at_ms: now_ms,
            phase: Phase::Outgoing {
                offer_sent: false,
                ringing: false,
                caller_rand: random32(),
                sent_at_ms: now_ms,
            },
            media: None,
            video: VideoCall::new(
                self.call.video_prefs.caps(self.relay_video, video),
                self.relay_video,
            ),
        });
        if video {
            if let Some(a) = self.call.active.as_mut() {
                a.video.last_state = None; // the intent is reported at once
            }
        }
        self.call_event(CallEvent::Outgoing {
            call_id: id,
            peer: peer.to_string(),
            video: self
                .call
                .active
                .as_ref()
                .is_some_and(|a| a.video.video_call),
        });
        self.call_video_changed();
        self.call_try_send_offer();
        Ok(id)
    }

    fn call_try_send_offer(&mut self) {
        let Some(a) = self.call.active.as_ref() else {
            return;
        };
        let Phase::Outgoing {
            offer_sent: false,
            caller_rand,
            sent_at_ms,
            ..
        } = &a.phase
        else {
            return;
        };
        if !self.has_live_circuit(&a.peer) {
            return;
        }
        let offer = CallSignal::Offer {
            call_id: a.id,
            caller_rand: caller_rand.clone(),
            sent_at_ms: *sent_at_ms,
        };
        let peer = a.peer.clone();
        if self.call_send(&peer, &offer).is_ok() {
            if let Some(ActiveCall {
                phase: Phase::Outgoing { offer_sent, .. },
                ..
            }) = self.call.active.as_mut()
            {
                *offer_sent = true;
            }
            // R1: Caps right behind the Offer, which stays the 2.2.0 one.
            self.call_send_caps();
        }
    }

    pub(crate) fn call_answer(
        &mut self,
        id: CallId,
        now: Instant,
        _now_ms: u64,
    ) -> Result<(), RChatError> {
        let Some(a) = self.call.active.as_ref().filter(|a| a.id == id) else {
            return Err(RChatError::NoSuchCall);
        };
        // Not yet rung (D13): the app has not been told of it.
        let Phase::Incoming {
            caller_rand,
            rang: true,
            ..
        } = &a.phase
        else {
            return Err(RChatError::NoSuchCall);
        };
        let callee_rand = random32();
        let keys = keys::derive(&id, caller_rand, &callee_rand, false);
        let peer = a.peer.clone();
        self.call_send(
            &peer,
            &CallSignal::Answer {
                call_id: id,
                callee_rand,
            },
        )?;
        if !self.call_begin_connecting(keys, 1, now, None) {
            self.call_send_end(EndReason::Failed);
            self.call_finish(CallResult::Failed, now);
            return Ok(());
        }
        // R17: answering a call that rang as video is the acceptance of
        // the caller's video; the app turns our camera on after a plain
        // Answer (never from the lock screen).
        if let Some(a) = self.call.active.as_mut() {
            if a.video.video_call {
                a.video.agreed = true;
            }
        }
        self.call_video_changed();
        Ok(())
    }

    pub(crate) fn call_decline(
        &mut self,
        id: CallId,
        busy: bool,
        _now_ms: u64,
    ) -> Result<(), RChatError> {
        if !self
            .call
            .active
            .as_ref()
            .is_some_and(|a| a.id == id && matches!(a.phase, Phase::Incoming { rang: true, .. }))
        {
            return Err(RChatError::NoSuchCall);
        }
        let (reason, result) = if busy {
            (EndReason::Busy, CallResult::Busy)
        } else {
            (EndReason::Declined, CallResult::Declined)
        };
        self.call_send_end(reason);
        self.call_finish(result, Instant::now());
        Ok(())
    }

    pub(crate) fn call_end(
        &mut self,
        id: CallId,
        now: Instant,
        _now_ms: u64,
    ) -> Result<(), RChatError> {
        let Some(a) = self.call.active.as_ref().filter(|a| a.id == id) else {
            return Err(RChatError::NoSuchCall);
        };
        // D16: cancelled only before any Answer; after it, without media, failed.
        let result = match a.phase {
            Phase::Connected { .. } => CallResult::Completed,
            Phase::Incoming { .. } => CallResult::Declined,
            Phase::Connecting { .. } => CallResult::Failed,
            Phase::Outgoing { .. } => CallResult::Cancelled,
        };
        let reason = if result == CallResult::Declined {
            EndReason::Declined
        } else {
            EndReason::HangUp
        };
        self.call_send_end(reason);
        self.call_finish(result, now);
        Ok(())
    }

    fn call_send_video(&self, peer: &str, sig: &VideoSignal) -> Result<(), RChatError> {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let packet = self.seal_ratchet(peer, id, &sig.encode())?;
        self.send_now(packet.encode_with_frame_type())
    }

    /// This call's Caps to the peer (R1). Best effort: a peer that never
    /// gets them sees this phone as one without video.
    fn call_send_caps(&self) {
        #[cfg(test)]
        if self.call.ignore_video {
            return;
        }
        if let Some(a) = &self.call.active {
            let _ = self.call_send_video(
                &a.peer,
                &VideoSignal::Caps {
                    call_id: a.id,
                    caps: a.video.mine,
                },
            );
        }
    }

    /// The caller got the Answer (R1, R17, R18): no Caps by now means a
    /// peer without video; a header video call is agreed if the callee can
    /// do video (in glare, only if both placed video calls), and otherwise
    /// the caller's camera stops and the call goes on as voice.
    fn call_video_on_answer(&mut self) {
        if let Some(a) = self.call.active.as_mut() {
            let v = &mut a.video;
            if v.peer.is_none() {
                v.answered_without_caps = true;
            }
            v.refresh();
            if v.video_call {
                let peer_video_call = v.peer.is_some_and(|p| p.video_call);
                if v.available == Availability::Yes && (!v.glare || peer_video_call) {
                    v.agreed = true;
                    // In glare both placed video calls: both cameras are on.
                    if v.glare {
                        v.peer_camera = true;
                    }
                } else {
                    v.camera = false;
                }
            }
        }
        self.call_video_changed();
    }

    /// After any change to the call's video: start the engine if due, set
    /// its flags, and tell the app what changed (signalling-driven fields
    /// at once, R19).
    fn call_video_changed(&mut self) {
        if let Some(a) = self.call.active.as_mut() {
            a.video.refresh();
        }
        self.call_video_start();
        let Some(a) = self.call.active.as_mut() else {
            return;
        };
        a.video.refresh();
        a.video.apply();
        if !a.known_to_app() {
            return;
        }
        let st = a.video.state();
        if a.video.last_state != Some(st) {
            a.video.last_state = Some(st);
            let id = a.id;
            self.call_event(CallEvent::Video {
                call_id: id,
                state: st,
            });
        }
    }

    /// Starts the call's video engine, once (R5, R7): when video is agreed
    /// and possible while connecting or connected. The keys kept from the
    /// Answer move into it; a failure leaves the call as voice with
    /// `available: relay`, and is never retried (the keys are gone).
    fn call_video_start(&mut self) {
        if self.call_video_start_inner() {
            self.call_video_tell_camera_off();
        }
    }

    /// After a local failure (start, or the relay refused): our camera was
    /// on, so the peer is told it is off rather than seeing "Video paused".
    fn call_video_tell_camera_off(&self) {
        if let Some(a) = &self.call.active {
            let _ = self.call_send_video(
                &a.peer,
                &VideoSignal::Camera {
                    call_id: a.id,
                    on: false,
                },
            );
        }
    }

    /// Returns true when it failed with our camera on.
    fn call_video_start_inner(&mut self) -> bool {
        let due = self.call.active.as_ref().is_some_and(|a| {
            a.video.agreed
                && a.video.available == Availability::Yes
                && a.video.keys.is_some()
                && matches!(a.phase, Phase::Connecting { .. } | Phase::Connected { .. })
        });
        if !due {
            return false;
        }
        let lane = self.call_lane_config();
        let prefs = self.call.video_prefs.clone();
        let starter = self.call.starter.clone();
        let Some(a) = self.call.active.as_mut() else {
            return false;
        };
        let was_on = a.video.camera;
        let (Some(keys), Some(relay_token)) = (a.video.keys.take(), a.video.relay_token.take())
        else {
            return false;
        };
        let audio = a.media.clone().and_then(|m| m.audio_link());
        let (Some(lane), Some(audio), Some(codec), Some(peer)) =
            (lane, audio, a.video.codec(), a.video.peer)
        else {
            // `keys` and `relay_token` drop here, wiped.
            a.video.fail();
            return was_on;
        };
        let started = starter.start_video(VideoStart {
            call_id: a.id,
            role: a.video.role,
            keys,
            relay_token,
            lane,
            codec,
            peer_max: peer.max_recv,
            software_encoder: prefs.software.load(Ordering::SeqCst),
            audio,
        });
        match started {
            Some(m) => {
                m.set_thermal(prefs.thermal());
                a.video.media = Some(m.clone());
                *self.call.video.lock() = Some(m);
                false
            }
            None => {
                a.video.fail();
                was_on
            }
        }
    }

    /// Polls the video engine (R19): a refusal turns video off for the call
    /// at once; the banner and paused fields go out at most once a second.
    fn call_video_tick(&mut self, now: Instant) {
        let Some(a) = self.call.active.as_mut() else {
            return;
        };
        let Some(m) = a.video.media.clone().filter(|_| !a.video.failed) else {
            return;
        };
        let st = m.status(now);
        if st.refused {
            let was_on = a.video.camera;
            a.video.fail();
            m.stop();
            *self.call.video.lock() = None;
            if was_on {
                self.call_video_tell_camera_off();
            }
            self.call_video_changed();
            return;
        }
        if a.video
            .last_event
            .is_some_and(|t| now.saturating_duration_since(t) < VIDEO_STATUS_EVERY)
        {
            return;
        }
        let state = VideoState {
            banner: st.banner,
            paused_in: st.paused_in,
            paused_out: st.paused_out,
            ..a.video.state()
        };
        if a.video.last_state != Some(state) {
            a.video.last_state = Some(state);
            a.video.last_event = Some(now);
            let id = a.id;
            self.call_event(CallEvent::Video { call_id: id, state });
        }
    }

    /// The current call's video state (tests).
    #[cfg(test)]
    pub(crate) fn call_video_state(&self) -> Option<VideoState> {
        self.call.active.as_ref().map(|a| a.video.state())
    }

    /// The call's video, while connecting or connected; 33 otherwise.
    fn call_video_live(&mut self) -> Result<&mut ActiveCall, RChatError> {
        self.call
            .active
            .as_mut()
            .filter(|a| matches!(a.phase, Phase::Connecting { .. } | Phase::Connected { .. }))
            .ok_or(RChatError::NoSuchCall)
    }

    /// My camera on or off (R17). Before agreement, on sends a Request
    /// (the preview runs locally, nothing is sent until agreed), and off
    /// withdraws it; once agreed, a Camera change needs no prompt. A new
    /// Request within 30 s of the peer's Decline is `VideoTooSoon`.
    pub(crate) fn call_video_set_camera(
        &mut self,
        on: bool,
        now: Instant,
    ) -> Result<(), RChatError> {
        let relay_video = self.relay_video;
        let a = self.call_video_live()?;
        let (id, peer) = (a.id, a.peer.clone());
        let v = &a.video;
        if v.camera == on {
            return Ok(());
        }
        let sig = if on {
            if !relay_video || v.available == Availability::Relay {
                return Err(RChatError::RelayNoVideo);
            }
            if v.available != Availability::Yes {
                return Err(RChatError::VideoUnavailable);
            }
            if v.agreed {
                VideoSignal::Camera { call_id: id, on }
            } else {
                // R17 glare: our Request while theirs is pending agrees.
                if !v.request_in
                    && v.declined_at
                        .is_some_and(|t| now.saturating_duration_since(t) < REQUEST_AFTER_DECLINE)
                {
                    return Err(RChatError::VideoTooSoon);
                }
                VideoSignal::Request { call_id: id }
            }
        } else {
            VideoSignal::Camera { call_id: id, on }
        };
        self.call_send_video(&peer, &sig)?;
        if let Some(a) = self.call.active.as_mut() {
            let v = &mut a.video;
            v.camera = on;
            match sig {
                VideoSignal::Request { .. } if v.request_in => {
                    v.request_in = false;
                    v.agreed = true;
                }
                VideoSignal::Request { .. } => {
                    v.request_pending_out = true;
                    v.requested_this_call = true;
                }
                _ => v.request_pending_out = false,
            }
        }
        self.call_video_changed();
        Ok(())
    }

    /// Accept or Not now for the peer's pending request (R17); 33 without one.
    pub(crate) fn call_video_respond(
        &mut self,
        accept: bool,
        _now: Instant,
    ) -> Result<(), RChatError> {
        let a = self.call_video_live()?;
        if !a.video.request_in {
            return Err(RChatError::NoSuchCall);
        }
        let (call_id, peer) = (a.id, a.peer.clone());
        let sig = if accept {
            VideoSignal::Accept { call_id }
        } else {
            VideoSignal::Decline { call_id }
        };
        self.call_send_video(&peer, &sig)?;
        if let Some(a) = self.call.active.as_mut() {
            let v = &mut a.video;
            v.request_in = false;
            if accept {
                // Accepting shows the requester; our own camera stays off.
                v.agreed = true;
            } else {
                v.peer_camera = false;
            }
        }
        self.call_video_changed();
        Ok(())
    }

    /// `0x0E` video signalling from the current session (the caller checked
    /// `calls_enabled` and the session). Anything for another call or from
    /// another peer is ignored.
    pub(crate) fn handle_video_plaintext(&mut self, sender: &str, pt: &[u8], now: Instant) {
        #[cfg(test)]
        if self.call.ignore_video {
            return;
        }
        let Some(signal) = VideoSignal::decode(pt) else {
            return;
        };
        let call_id = signal.call_id();
        if let VideoSignal::Caps { caps, .. } = signal {
            // R1: a held Offer keeps its Caps until the handover.
            if let Some(h) = self
                .call
                .held
                .iter_mut()
                .find(|h| h.call_id == call_id && h.from == sender)
            {
                h.caps.get_or_insert(caps);
                return;
            }
        }
        let Some(a) = self
            .call
            .active
            .as_mut()
            .filter(|a| a.id == call_id && a.peer == sender)
        else {
            return;
        };
        let live = matches!(a.phase, Phase::Connecting { .. } | Phase::Connected { .. });
        // In glare, the phone that switched to the peer's call.
        let switched = a.direction == Direction::Incoming;
        let v = &mut a.video;
        let (mut one_shot, mut reply) = (None, None);
        match signal {
            // Caps count once per call: a later one changes nothing.
            VideoSignal::Caps { .. } if v.peer.is_some() => return,
            VideoSignal::Caps { caps, .. } => {
                // A late Caps (after the Answer) upgrades Peer to Yes.
                v.peer = Some(caps);
                v.refresh();
                if switched && live {
                    v.settle_glare();
                }
            }
            _ if !live => return,
            VideoSignal::Request { .. } => {
                if v.agreed {
                    // Agreed already: no prompt.
                    v.peer_camera = true;
                } else if v.request_pending_out {
                    // R17 glare: both asked; agreed with no prompt.
                    v.request_pending_out = false;
                    v.agreed = true;
                    v.peer_camera = true;
                } else if v.available != Availability::Yes {
                    // Video can't run here: Not now, rather than silence,
                    // once per call (never a reflector).
                    if !v.auto_declined {
                        v.auto_declined = true;
                        reply = Some(VideoSignal::Decline { call_id });
                    }
                } else if !v.request_in {
                    v.request_in = true;
                    v.peer_camera = true;
                    if v.last_request_event
                        .is_none_or(|t| now.saturating_duration_since(t) >= REQUEST_EVENT_EVERY)
                    {
                        v.last_request_event = Some(now);
                        one_shot = Some(CallEvent::VideoRequest { call_id });
                    }
                }
            }
            VideoSignal::Accept { .. } => {
                // Only an answer to a Request we sent counts (even one we
                // withdrew since, so a crossing Accept still agrees): an
                // unsolicited Accept never turns video on.
                if v.requested_this_call {
                    v.request_pending_out = false;
                    v.agreed = true;
                }
            }
            VideoSignal::Decline { .. } => {
                // A later Accept needs a fresh Request from us.
                v.requested_this_call = false;
                if v.request_pending_out {
                    v.request_pending_out = false;
                    v.camera = false;
                    v.declined_at = Some(now);
                    one_shot = Some(CallEvent::VideoDeclined { call_id });
                }
            }
            VideoSignal::Camera { on: true, .. } => {
                // Without agreement a camera never shows (R17).
                if v.agreed {
                    v.peer_camera = true;
                }
            }
            VideoSignal::Camera { on: false, .. } => {
                // Also withdraws a pending request.
                v.peer_camera = false;
                v.request_in = false;
            }
        }
        if let Some(r) = reply {
            let _ = self.call_send_video(sender, &r);
        }
        if let Some(e) = one_shot {
            self.call_event(e);
        }
        self.call_video_changed();
    }

    pub(crate) fn handle_call_plaintext(
        &mut self,
        sender: &str,
        pt: &[u8],
        now: Instant,
        now_ms: u64,
    ) {
        let Some(sig) = CallSignal::decode(pt) else {
            return;
        };
        match sig {
            CallSignal::Offer {
                call_id,
                caller_rand,
                sent_at_ms,
            } => {
                if now_ms.abs_diff(sent_at_ms) > OFFER_MAX_AGE_MS {
                    // Event times are our clock's: the peer's `sent_at_ms`
                    // is only used for the age check.
                    self.call_event(CallEvent::Ended {
                        call_id,
                        peer: sender.to_string(),
                        direction: Direction::Incoming,
                        result: CallResult::Missed,
                        duration_secs: 0,
                        started_at_ms: now_ms,
                        video: false,
                    });
                    return;
                }
                if !self.call.handed_over {
                    if self.call.held.iter().any(|h| h.call_id == call_id) {
                        return;
                    }
                    if self.call.held.len() < MAX_HELD_OFFERS {
                        self.call.held.push(HeldOffer {
                            from: sender.to_string(),
                            call_id,
                            caller_rand,
                            sent_at_ms,
                            received_ms: now_ms,
                            ended: false,
                            caps: None,
                        });
                    } else {
                        // D11: past the cap, recorded as missed, never lost.
                        self.call_event(CallEvent::Ended {
                            call_id,
                            peer: sender.to_string(),
                            direction: Direction::Incoming,
                            result: CallResult::Missed,
                            duration_secs: 0,
                            started_at_ms: now_ms,
                            video: false,
                        });
                    }
                    return;
                }
                self.call_take_offer(sender, call_id, caller_rand, None, now, now_ms);
            }
            CallSignal::Ringing { call_id } => {
                let mut rang = false;
                if let Some(ActiveCall {
                    id,
                    peer,
                    phase: Phase::Outgoing { ringing, .. },
                    ..
                }) = self.call.active.as_mut()
                {
                    if *id == call_id && peer == sender && !*ringing {
                        *ringing = true;
                        rang = true;
                    }
                }
                if rang {
                    self.call_event(CallEvent::Ringing { call_id });
                }
            }
            CallSignal::Answer {
                call_id,
                callee_rand,
            } => {
                let keys = match self.call.active.as_ref() {
                    Some(ActiveCall {
                        id,
                        peer,
                        phase: Phase::Outgoing { caller_rand, .. },
                        ..
                    }) if *id == call_id && peer == sender => {
                        keys::derive(&call_id, caller_rand, &callee_rand, true)
                    }
                    _ => return,
                };
                if !self.call_begin_connecting(keys, 0, now, None) {
                    self.call_send_end(EndReason::Failed);
                    self.call_finish(CallResult::Failed, now);
                    return;
                }
                self.call_video_on_answer();
            }
            CallSignal::End { call_id, reason } => {
                if let Some(h) = self
                    .call
                    .held
                    .iter_mut()
                    .find(|h| h.call_id == call_id && h.from == sender)
                {
                    h.ended = true;
                    return;
                }
                let Some(a) = self
                    .call
                    .active
                    .as_ref()
                    .filter(|a| a.id == call_id && a.peer == sender)
                else {
                    return;
                };
                let result = match (&a.phase, reason) {
                    (Phase::Connected { .. }, EndReason::Failed) => CallResult::Failed,
                    (Phase::Connected { .. }, _) => CallResult::Completed,
                    (Phase::Incoming { .. }, _) => CallResult::Missed,
                    (Phase::Outgoing { .. }, EndReason::Busy) => CallResult::Busy,
                    (Phase::Outgoing { .. }, EndReason::Failed) => CallResult::Failed,
                    (Phase::Outgoing { .. }, EndReason::NoAnswer | EndReason::Unreachable) => {
                        CallResult::NoAnswer
                    }
                    (Phase::Outgoing { .. }, _) => CallResult::Declined,
                    // D16: answered, no media yet: failed whatever the reason.
                    (Phase::Connecting { .. }, _) => CallResult::Failed,
                };
                self.call_finish(result, now);
            }
        }
    }

    fn call_take_offer(
        &mut self,
        sender: &str,
        call_id: CallId,
        caller_rand: Zeroizing<[u8; 32]>,
        caps: Option<Caps>,
        now: Instant,
        now_ms: u64,
    ) {
        match self.call.active.as_ref() {
            None => {
                let mut video = VideoCall::new(
                    self.call.video_prefs.caps(self.relay_video, false),
                    self.relay_video,
                );
                video.peer = caps;
                video.refresh();
                self.call.active = Some(ActiveCall {
                    id: call_id,
                    peer: sender.to_string(),
                    direction: Direction::Incoming,
                    placed_at: now,
                    started_at_ms: now_ms,
                    phase: Phase::Incoming {
                        caller_rand,
                        received_at: now,
                        rang: false,
                    },
                    media: None,
                    video,
                });
                // Ringing and the Incoming event wait for RING_SETTLE (D13, `call_tick`).
            }
            Some(a) if a.id == call_id => {}
            Some(a) if a.peer == sender && matches!(a.phase, Phase::Outgoing { .. }) => {
                // Glare (§3): the lower call id connects at once on both phones.
                if call_id < a.id {
                    let (ours, ours_started_ms) = (a.id, a.started_at_ms);
                    // Ours was a video call or not: the call we switch to
                    // keeps that intent, and video is agreed only if both
                    // placed video calls (R17).
                    let mut video = VideoCall::new(a.video.mine, a.video.relay_ok);
                    video.camera = a.video.camera;
                    video.last_state = a.video.last_state;
                    video.glare = true;
                    video.peer = caps;
                    video.refresh();
                    self.call.active = Some(ActiveCall {
                        id: call_id,
                        peer: sender.to_string(),
                        direction: Direction::Incoming,
                        placed_at: now,
                        started_at_ms: now_ms,
                        phase: Phase::Incoming {
                            caller_rand: caller_rand.clone(),
                            received_at: now,
                            rang: true,
                        },
                        media: None,
                        video,
                    });
                    let callee_rand = random32();
                    let keys = keys::derive(&call_id, &caller_rand, &callee_rand, false);
                    // R1 / H4: Caps for the winning call go before the
                    // Answer, so the peer has them when it connects.
                    self.call_send_caps();
                    if self
                        .call_send(
                            sender,
                            &CallSignal::Answer {
                                call_id,
                                callee_rand,
                            },
                        )
                        .is_err()
                        || !self.call_begin_connecting(keys, 1, now, Some(ours))
                    {
                        // Final review I2: the peer waits on its call and may
                        // still hold ours, so both are ended; the app knows
                        // only its own call, so the Ended carries that id.
                        for id in [call_id, ours] {
                            let _ = self.call_send(
                                sender,
                                &CallSignal::End {
                                    call_id: id,
                                    reason: EndReason::Failed,
                                },
                            );
                        }
                        if let Some(a) = self.call.active.as_mut() {
                            a.id = ours;
                            a.direction = Direction::Outgoing;
                            a.started_at_ms = ours_started_ms;
                        }
                        self.call_finish(CallResult::Failed, now);
                    } else {
                        // Caps that came with a held Offer are known now.
                        if let Some(a) = self.call.active.as_mut() {
                            a.video.settle_glare();
                        }
                        self.call_video_changed();
                    }
                } else if let Some(a) = self.call.active.as_mut() {
                    // Ours is lower: theirs is dropped; they answer ours.
                    a.video.glare = true;
                }
            }
            Some(_) => {
                let _ = self.call_send(
                    sender,
                    &CallSignal::End {
                        call_id,
                        reason: EndReason::Busy,
                    },
                );
                self.call_event(CallEvent::Ended {
                    call_id,
                    peer: sender.to_string(),
                    direction: Direction::Incoming,
                    result: CallResult::Busy,
                    duration_secs: 0,
                    started_at_ms: now_ms,
                    video: false,
                });
            }
        }
    }

    pub(crate) fn call_on_queue_handed_over(&mut self, now: Instant, now_ms: u64) {
        self.call.handed_over = true;
        for h in std::mem::take(&mut self.call.held) {
            if h.ended || now_ms.abs_diff(h.sent_at_ms) > OFFER_MAX_AGE_MS {
                self.call_event(CallEvent::Ended {
                    call_id: h.call_id,
                    peer: h.from,
                    direction: Direction::Incoming,
                    result: CallResult::Missed,
                    duration_secs: 0,
                    started_at_ms: h.received_ms,
                    video: false,
                });
            } else {
                self.call_take_offer(&h.from, h.call_id, h.caller_rand, h.caps, now, now_ms);
            }
        }
    }

    /// The contact is blocked, unpinned or replaced by a rotation
    /// (`forget_peer_session`, before its session goes): its call ends now,
    /// with a best-effort End(hang-up), and its held and late Offers are
    /// dropped without an event. Results: an answered call (connecting or
    /// connected) is failed, keeping a connected call's duration; an
    /// outgoing call not yet answered is cancelled (we ended it); an
    /// incoming call is declined once it rang (the user turned it away) and
    /// missed if it had not rung yet (the user never saw it).
    pub(crate) fn call_forget_peer(&mut self, peer: &str, now: Instant) {
        self.call.held.retain(|h| h.from != peer);
        self.call.late.remove(peer);
        let Some(a) = self.call.active.as_ref().filter(|a| a.peer == peer) else {
            return;
        };
        let result = match a.phase {
            Phase::Connecting { .. } | Phase::Connected { .. } => CallResult::Failed,
            Phase::Outgoing { .. } => CallResult::Cancelled,
            Phase::Incoming { rang: true, .. } => CallResult::Declined,
            Phase::Incoming { rang: false, .. } => CallResult::Missed,
        };
        self.call_send_end(EndReason::HangUp);
        self.call_finish(result, now);
    }

    pub(crate) fn call_grant_refused(&mut self, _now_ms: u64) {
        if self
            .call
            .active
            .as_ref()
            .is_some_and(|a| matches!(a.phase, Phase::Connecting { .. }))
        {
            self.call_send_end(EndReason::Failed);
            self.call_finish(CallResult::Failed, Instant::now());
        }
    }

    pub(crate) fn call_abort(&mut self, _now_ms: u64) {
        if self.call.active.is_some() {
            self.call_send_end(EndReason::Failed);
            self.call_finish(CallResult::Failed, Instant::now());
        }
        self.call.late.clear();
        self.call.held.clear();
    }

    pub(crate) fn call_tick(&mut self, now: Instant, now_ms: u64) {
        // D13: Offers that never left go with their End, back to back in one
        // batch (both sealed first), once a circuit opens.
        let due: Vec<String> = self
            .call
            .late
            .iter()
            .filter(|(p, l)| {
                self.has_live_circuit(p) || now.saturating_duration_since(l.at) > LATE_OFFER_TTL
            })
            .map(|(p, _)| p.clone())
            .collect();
        for p in due {
            if let Some(l) = self.call.late.remove(&p) {
                if self.has_live_circuit(&p)
                    && now.saturating_duration_since(l.at) <= LATE_OFFER_TTL
                {
                    let sealed = [&l.offer, &l.end].map(|sig| {
                        let mut id = [0u8; 16];
                        rand::rngs::OsRng.fill_bytes(&mut id);
                        self.seal_ratchet(&p, id, &sig.encode())
                    });
                    if let [Ok(offer), Ok(end)] = sealed {
                        let _ = self.send_now(offer.encode_with_frame_type());
                        let _ = self.send_now(end.encode_with_frame_type());
                    }
                }
            }
        }
        self.call_try_send_offer();
        let Some(a) = self.call.active.as_ref() else {
            return;
        };
        let (id, elapsed) = (a.id, now.saturating_duration_since(a.placed_at));
        let status = a.media.as_ref().map(|m| m.status(now));
        match &a.phase {
            Phase::Outgoing {
                ringing,
                offer_sent,
                caller_rand,
                sent_at_ms,
            } => {
                if !*ringing && elapsed >= UNREACHABLE_AFTER {
                    if !*offer_sent {
                        let offer = CallSignal::Offer {
                            call_id: id,
                            caller_rand: caller_rand.clone(),
                            sent_at_ms: *sent_at_ms,
                        };
                        let end = CallSignal::End {
                            call_id: id,
                            reason: EndReason::Unreachable,
                        };
                        let peer = a.peer.clone();
                        self.call.late.insert(
                            peer,
                            LateOffer {
                                offer,
                                end,
                                at: now,
                            },
                        );
                    } else {
                        self.call_send_end(EndReason::Unreachable);
                    }
                    self.call_finish(CallResult::Unreachable, now);
                } else if elapsed >= NO_ANSWER_AFTER {
                    self.call_send_end(EndReason::NoAnswer);
                    self.call_finish(CallResult::NoAnswer, now);
                }
            }
            Phase::Incoming {
                received_at, rang, ..
            } => {
                let (waited, rang, peer) = (
                    now.saturating_duration_since(*received_at),
                    *rang,
                    a.peer.clone(),
                );
                if waited >= INCOMING_GIVE_UP {
                    self.call_finish(CallResult::Missed, now);
                } else if !rang && waited >= RING_SETTLE {
                    let mut video = false;
                    if let Some(ActiveCall {
                        phase: Phase::Incoming { rang, .. },
                        video: v,
                        ..
                    }) = self.call.active.as_mut()
                    {
                        *rang = true;
                        // R18: rings as video only if this phone and its
                        // relay can do video and the caller's Caps asked.
                        v.video_call = v.available == Availability::Yes
                            && v.peer.is_some_and(|p| p.video_call);
                        v.peer_camera = v.video_call;
                        v.last_state = Some(v.state());
                        video = v.video_call;
                    }
                    let _ = self.call_send(&peer, &CallSignal::Ringing { call_id: id });
                    // R1: Caps right behind the Ringing.
                    self.call_send_caps();
                    self.call_event(CallEvent::Incoming {
                        call_id: id,
                        peer,
                        video,
                    });
                }
            }
            Phase::Connecting {
                since,
                granted,
                token,
            } => {
                let (since, granted, token, peer) =
                    (*since, *granted, token.clone(), a.peer.clone());
                let st = status.unwrap_or_default();
                if !granted && self.call_grant(&peer, &token) {
                    if let Some(ActiveCall {
                        phase: Phase::Connecting { granted, .. },
                        ..
                    }) = self.call.active.as_mut()
                    {
                        *granted = true;
                    }
                }
                // Refused (a failed relay pin included) or the engine gave
                // up: failed. `NoRuntime` never got this far (no media).
                if st.refused || st.gave_up {
                    self.call_send_end(EndReason::Failed);
                    self.call_finish(CallResult::Failed, now);
                } else if st.first_frame {
                    if let Some(a) = self.call.active.as_mut() {
                        a.phase = Phase::Connected {
                            at: now,
                            last_status: now,
                        };
                    }
                    self.call_event(CallEvent::Connected {
                        call_id: id,
                        at_ms: now_ms,
                    });
                    if let Some(a) = self.call.active.as_mut() {
                        let v = &mut a.video;
                        // Glare and still no Caps from the other phone:
                        // voice, and our camera stops (R18).
                        if v.glare && v.peer.is_none() && !v.agreed {
                            v.camera = false;
                        }
                    }
                    self.call_video_changed();
                } else if now.saturating_duration_since(since) >= CONNECT_GIVE_UP {
                    self.call_send_end(EndReason::Failed);
                    self.call_finish(CallResult::Failed, now);
                }
            }
            Phase::Connected { last_status, .. } => {
                let last_status = *last_status;
                let st = status.unwrap_or_default();
                if st.exhausted
                    || st.refused
                    || st.gave_up
                    || (st.reconnecting && st.silent_for >= SILENT_AFTER + RECONNECT_GIVE_UP)
                {
                    self.call_send_end(EndReason::Failed);
                    self.call_finish(CallResult::Failed, now);
                } else if now.saturating_duration_since(last_status) >= STATUS_EVERY {
                    if let Some(ActiveCall {
                        phase: Phase::Connected { last_status, .. },
                        ..
                    }) = self.call.active.as_mut()
                    {
                        *last_status = now;
                    }
                    self.call_event(CallEvent::Status {
                        call_id: id,
                        status: st,
                    });
                }
            }
        }
        self.call_video_tick(now);
    }
}
