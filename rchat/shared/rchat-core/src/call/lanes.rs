//! The two call connections (spec §5 "Joining", §6 "Sending"): each a fresh
//! WebSocket over TLS to the same relay, port and path; `hello`, the relay
//! identity checked against the chat connection's pin (strict), then
//! `MediaJoin(token, lane, role)`. Every frame goes to both; each holds at
//! most 3 frames waiting (the oldest dropped); a connection with no write
//! progress for 2 s is closed and reopened with the same token and lane in
//! the background while the other carries the call. A join the relay
//! refuses (the other side may not have granted yet) is retried with
//! backoff until `CONNECT_GIVE_UP` after the lane's first refusal (D34).
//!
//! The video connections (`VideoLanes`, lanes 2 and 3) join, retry and
//! restart the same way, except that a video connection's stall is no write
//! progress in bytes for 2 s (the socket took none and sent none), so a slow
//! but moving one is kept, and that it closes with a reset. They differ in
//! the send side: each video frame goes once, on one of the two (R12), into
//! a byte-bounded queue. Lanes never seal; video fragments arrive already
//! sealed.

use super::frame::MAX_WIRE_FRAME;
use super::video::queue::{Pushed, VideoQueue};
use super::{CONNECT_GIVE_UP, SEND_QUEUE_FRAMES, STALL_AFTER};
use crate::protocol::{
    classify_signaling, signaling_frame, ControlMessage, KeepaliveMessage, SignalingEvent,
    SignalingMessage, FRAME_TYPE_CONTROL, FRAME_TYPE_KEEPALIVE, FRAME_TYPE_MEDIA,
    FRAME_TYPE_SIGNALING, PROTOCOL_VERSION,
};
use crate::tls_boring::TlsFingerprint;
use crate::tls_resumption::ResumptionStore;
use crate::transport::{open_websocket, TransportConfig, TransportStream};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use zeroize::Zeroizing;

/// Where and how to reach the relay: the chat connection's URL, origin,
/// pin and ticket store.
#[derive(Clone)]
pub struct LaneConfig {
    pub server_url: String,
    pub dev_origin: Option<String>,
    pub relay_pin: String,
    pub relay_pin_version: Option<u32>,
    pub tls_fingerprint: TlsFingerprint,
    pub resumption: Option<ResumptionStore>,
}

pub trait LaneSink: Send + Sync + 'static {
    fn on_frame(&self, lane: u8, frame: &[u8], at: Instant);
    fn on_peer(&self, lane: u8, present: bool);
    fn on_lane(&self, lane: u8, up: bool);
    /// The relay kept refusing the token on a lane for the give-up time
    /// after its first refusal (D34), or failed its pin. Once per lane.
    fn on_refused(&self);
    /// The relay failed its identity pin (never joined). Defaults to a
    /// plain refusal; the engine overrides it to tell the two apart.
    fn on_relay_identity_failed(&self) {
        self.on_refused();
    }
}

/// What a connection's writer drains. `pop_into` fills `out` with the next
/// frame; `clear` runs when a connection comes up; `on_written` after each
/// frame was handed to the socket.
pub(crate) trait SendQueue: Send + 'static {
    fn pop_into(&mut self, out: &mut Vec<u8>) -> bool;
    fn clear(&mut self);
    fn on_written(&mut self, _bytes: usize, _at: Instant) {}
}

pub(crate) struct LaneQueue {
    slots: [[u8; MAX_WIRE_FRAME]; SEND_QUEUE_FRAMES],
    lens: [usize; SEND_QUEUE_FRAMES],
    head: usize,
    len: usize,
    dropped: u64,
}

impl LaneQueue {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [[0; MAX_WIRE_FRAME]; SEND_QUEUE_FRAMES],
            lens: [0; SEND_QUEUE_FRAMES],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, frame: &[u8]) {
        let n = frame.len().min(MAX_WIRE_FRAME);
        if self.len == SEND_QUEUE_FRAMES {
            self.head = (self.head + 1) % SEND_QUEUE_FRAMES;
            self.len -= 1;
            self.dropped += 1;
        }
        let i = (self.head + self.len) % SEND_QUEUE_FRAMES;
        self.slots[i][..n].copy_from_slice(&frame[..n]);
        self.lens[i] = n;
        self.len += 1;
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl SendQueue for LaneQueue {
    fn pop_into(&mut self, out: &mut Vec<u8>) -> bool {
        if self.len == 0 {
            return false;
        }
        out.clear();
        out.extend_from_slice(&self.slots[self.head][..self.lens[self.head]]);
        self.head = (self.head + 1) % SEND_QUEUE_FRAMES;
        self.len -= 1;
        true
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

struct LaneShared<Q> {
    queue: Mutex<Q>,
    ready: Notify,
    up: AtomicBool,
    /// A connect and join is under way.
    connecting: AtomicBool,
    /// Inside the refusal retries (D34): refused at least once since the
    /// lane last carried media, and not yet reported.
    refusing: AtomicBool,
    /// Bumped to close and reopen this lane (same token and lane).
    restart: watch::Sender<u64>,
    /// Times this lane came up (joined).
    ups: AtomicU64,
}

pub struct Lanes {
    shared: [Arc<LaneShared<LaneQueue>>; 2],
    stop: watch::Sender<bool>,
}

enum LaneError {
    Network,
    RelayIdentity,
}

enum Served {
    Stopped,
    Dropped,
    RefusedAtJoin,
}

impl Lanes {
    pub fn start(
        cfg: LaneConfig,
        token: Zeroizing<[u8; 32]>,
        role: u8,
        sink: Arc<dyn LaneSink>,
    ) -> Lanes {
        Self::start_with_give_up(cfg, token, role, sink, CONNECT_GIVE_UP)
    }

    /// As `start`, with the time a lane keeps retrying refused joins.
    pub(crate) fn start_with_give_up(
        cfg: LaneConfig,
        token: Zeroizing<[u8; 32]>,
        role: u8,
        sink: Arc<dyn LaneSink>,
        give_up: Duration,
    ) -> Lanes {
        let (shared, stop) = spawn_lanes(cfg, token, role, sink, give_up, 0, |_| LaneQueue::new());
        Lanes { shared, stop }
    }

    /// Every frame on both connections; a connection that is down keeps nothing.
    pub fn send(&self, frame: &[u8]) {
        for s in &self.shared {
            if s.up.load(Ordering::Acquire) {
                s.queue.lock().push(frame);
                s.ready.notify_one();
            }
        }
    }

    /// A control frame (already sealed on the control stream) on both audio
    /// connections, like `send`.
    pub fn send_control(&self, frame: &[u8]) {
        self.send(frame);
    }

    /// Frames the audio queues dropped (full, oldest out), both lanes.
    pub fn dropped_total(&self) -> u64 {
        self.shared.iter().map(|s| s.queue.lock().dropped()).sum()
    }

    /// Close one lane's connection and reopen it in the background, with
    /// the same token and lane (a blackholed path). The other keeps going.
    pub fn restart(&self, lane: u8) {
        restart_lane(&self.shared, lane);
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Whether `stop` was called.
    #[cfg(test)]
    pub fn is_stopped(&self) -> bool {
        *self.stop.borrow()
    }

    /// A connection is still connecting or retrying refused joins: it has
    /// not yet decided how the join ends. False once stopped.
    pub(crate) fn joining(&self) -> bool {
        !*self.stop.borrow()
            && self
                .shared
                .iter()
                .any(|s| s.connecting.load(Ordering::Acquire) || s.refusing.load(Ordering::Acquire))
    }
}

impl Drop for Lanes {
    fn drop(&mut self) {
        self.stop();
    }
}

fn restart_lane<Q>(shared: &[Arc<LaneShared<Q>>; 2], lane: u8) {
    shared[usize::from(lane & 1)]
        .restart
        .send_modify(|g| *g = g.wrapping_add(1));
}

/// Starts the two connections `first_lane` and `first_lane + 1`.
fn spawn_lanes<Q: SendQueue>(
    cfg: LaneConfig,
    token: Zeroizing<[u8; 32]>,
    role: u8,
    sink: Arc<dyn LaneSink>,
    give_up: Duration,
    first_lane: u8,
    make_queue: impl Fn(u8) -> Q,
) -> ([Arc<LaneShared<Q>>; 2], watch::Sender<bool>) {
    let (stop, rx) = watch::channel(false);
    let cfg = Arc::new(cfg);
    let token = Arc::new(token);
    let shared = [first_lane, first_lane + 1].map(|lane| {
        Arc::new(LaneShared {
            queue: Mutex::new(make_queue(lane)),
            ready: Notify::new(),
            up: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            refusing: AtomicBool::new(false),
            restart: watch::channel(0).0,
            ups: AtomicU64::new(0),
        })
    });
    for (i, s) in shared.iter().enumerate() {
        tokio::spawn(run_lane(
            first_lane + i as u8,
            cfg.clone(),
            token.clone(),
            role,
            s.clone(),
            sink.clone(),
            rx.clone(),
            give_up,
        ));
    }
    (shared, stop)
}

/// A video connection with no write progress for this long is not chosen
/// for the next frame (R12).
const VIDEO_STALLED_AFTER: Duration = Duration::from_millis(500);

/// A connection whose oldest waiting fragment is older than this is behind
/// (R12), when the other connection has nothing waiting.
const VIDEO_BEHIND_AGE: Duration = Duration::from_millis(250);
/// Frames stay on a connection at least this long before moving off it for
/// being behind (a stall or a lane going down moves them at once). Both
/// connections usually share one link: when it is full, moving does not
/// help, and each move costs a keyframe.
const VIDEO_SWITCH_HOLD: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneStats {
    pub up: bool,
    pub queued_bytes: usize,
    pub oldest: Option<Duration>,
    /// How long it has had work and finished no write.
    pub since_progress: Duration,
}

/// The two video connections (lanes 2 and 3). Each frame goes once, on the
/// better-moving one.
pub struct VideoLanes {
    shared: [Arc<LaneShared<VideoQueue>>; 2],
    stop: watch::Sender<bool>,
    /// Index (0 or 1) of the connection the last frame used.
    last: AtomicU8,
    /// When frames moved to the `last` connection.
    chosen_at: Mutex<Option<Instant>>,
    /// Moves off a connection that was up but behind or stalled (R12).
    switches: AtomicU64,
}

/// What the video connections did, for tests and traces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VideoLaneCounters {
    /// Moves off a connection that was up but behind or stalled (R12).
    pub switches: u64,
    /// Joins beyond each connection's first (reconnects and restarts).
    pub reconnects: u64,
}

impl VideoLanes {
    pub fn start(
        cfg: LaneConfig,
        token: Zeroizing<[u8; 32]>,
        role: u8,
        sink: Arc<dyn LaneSink>,
        give_up: Duration,
    ) -> VideoLanes {
        let (shared, stop) = spawn_lanes(cfg, token, role, sink, give_up, 2, VideoQueue::new);
        VideoLanes {
            shared,
            stop,
            last: AtomicU8::new(0),
            chosen_at: Mutex::new(None),
            switches: AtomicU64::new(0),
        }
    }

    pub fn counters(&self) -> VideoLaneCounters {
        VideoLaneCounters {
            switches: self.switches.load(Ordering::Relaxed),
            reconnects: self
                .shared
                .iter()
                .map(|s| s.ups.load(Ordering::Relaxed).saturating_sub(1))
                .sum(),
        }
    }

    pub fn stats(&self, now: Instant) -> [LaneStats; 2] {
        [0, 1].map(|i| {
            let s = &self.shared[i];
            let q = s.queue.lock();
            LaneStats {
                up: s.up.load(Ordering::Acquire),
                queued_bytes: q.queued_bytes(),
                oldest: q.oldest(now),
                since_progress: q.since_progress(now),
            }
        })
    }

    /// The connection for the next frame (R12): the current one is kept
    /// unless it is down, made no write progress for 500 ms, or (after
    /// `VIDEO_SWITCH_HOLD` on it) its oldest fragment waited 250 ms while
    /// the other has nothing waiting; then the other, if it is up and not
    /// itself stalled.
    fn choose(&self, now: Instant) -> Option<usize> {
        let st = self.stats(now);
        let cur = usize::from(self.last.load(Ordering::Relaxed));
        let other = 1 - cur;
        let stalled = |i: usize| st[i].since_progress >= VIDEO_STALLED_AFTER;
        let usable = |i: usize| st[i].up && !stalled(i);
        if !st[cur].up {
            return st[other].up.then_some(other);
        }
        let held = self
            .chosen_at
            .lock()
            .is_none_or(|t| now.saturating_duration_since(t) >= VIDEO_SWITCH_HOLD);
        let behind = held
            && st[cur].oldest.is_some_and(|o| o >= VIDEO_BEHIND_AGE)
            && st[other].queued_bytes == 0;
        if (stalled(cur) || behind) && usable(other) {
            Some(other)
        } else {
            Some(cur)
        }
    }

    /// Sends one frame of `n` fragments (`fill(i, slot)` seals fragment `i`
    /// into `slot` and returns its length) once, on one connection. A frame
    /// that does not fit is dropped, unless `keyframe`, which clears that
    /// connection's queue. Moving off a connection that is up drops what
    /// waits there and, unless this frame is a keyframe, sends nothing
    /// (`Switched`: the next frame must be a keyframe).
    pub fn push_frame(
        &self,
        n: usize,
        keyframe: bool,
        now: Instant,
        fill: &mut dyn FnMut(usize, &mut [u8]) -> usize,
    ) -> Pushed {
        let Some(i) = self.choose(now) else {
            return Pushed::NoLane;
        };
        let cur = usize::from(self.last.load(Ordering::Relaxed));
        if i != cur || self.chosen_at.lock().is_none() {
            *self.chosen_at.lock() = Some(now);
        }
        if i != cur {
            self.last.store(i as u8, Ordering::Relaxed);
            if self.shared[cur].up.load(Ordering::Acquire) {
                // Fragments left there would arrive after this lane's frames,
                // and the receiver drops a frame older than one it completed.
                self.shared[cur].queue.lock().drop_waiting();
                self.switches.fetch_add(1, Ordering::Relaxed);
                if !keyframe {
                    return Pushed::Switched { lane: 2 + i as u8 };
                }
            }
        }
        let s = &self.shared[i];
        let mut q = s.queue.lock();
        if !q.has_room(n) && !keyframe {
            return Pushed::Dropped;
        }
        let r = q.push_frame(n, keyframe, now, fill);
        drop(q);
        if !matches!(r, Pushed::Dropped | Pushed::NoLane) {
            s.ready.notify_one();
        }
        r
    }

    /// Video paused: drops every fragment still waiting to be sent, and
    /// closes the connections with a reset and reopens them, so what their
    /// kernels still hold unsent is discarded too instead of draining over
    /// the audio. Lane 3 goes only once lane 2 is back up (or after 5 s),
    /// so the peer's video keeps arriving through the relay's fallback to
    /// the other lane. The sealer is the caller's and carries on.
    pub fn abort_and_restart(&self) {
        for s in &self.shared {
            s.queue.lock().clear();
        }
        restart_lane(&self.shared, 2);
        let shared = self.shared.clone();
        let mut stop = self.stop.subscribe();
        tokio::spawn(async move {
            // Lane 2 goes down first, then comes back.
            let end = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut seen_down = false;
            loop {
                let up = shared[0].up.load(Ordering::Acquire);
                seen_down |= !up;
                if (seen_down && up) || tokio::time::Instant::now() >= end || *stop.borrow() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                    _ = stop.changed() => {}
                }
            }
            if !*stop.borrow() {
                restart_lane(&shared, 3);
            }
        });
    }

    /// Drops every fragment still waiting to be sent.
    #[cfg(test)]
    pub(crate) fn clear_queues(&self) {
        for s in &self.shared {
            s.queue.lock().clear();
        }
    }

    /// `lane` is 2 or 3.
    pub fn restart(&self, lane: u8) {
        restart_lane(&self.shared, lane);
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// A connection is still connecting or retrying refused joins.
    #[allow(dead_code)] // used by the video media (a later task)
    pub(crate) fn joining(&self) -> bool {
        !*self.stop.borrow()
            && self
                .shared
                .iter()
                .any(|s| s.connecting.load(Ordering::Acquire) || s.refusing.load(Ordering::Acquire))
    }
}

impl Drop for VideoLanes {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_lane<Q: SendQueue>(
    lane: u8,
    cfg: Arc<LaneConfig>,
    token: Arc<Zeroizing<[u8; 32]>>,
    role: u8,
    shared: Arc<LaneShared<Q>>,
    sink: Arc<dyn LaneSink>,
    mut stop: watch::Receiver<bool>,
    give_up: Duration,
) {
    let mut backoff = Duration::from_millis(250);
    // Set at the first refusal since the lane last carried media (D34).
    let mut first_refusal: Option<Instant> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        shared.connecting.store(true, Ordering::Release);
        let outcome = tokio::select! {
            r = connect_and_join(&cfg, &token, lane, role) => r,
            _ = stop.changed() => break,
        };
        shared.connecting.store(false, Ordering::Release);
        match outcome {
            Ok(ws) => {
                shared.queue.lock().clear();
                shared.ups.fetch_add(1, Ordering::Relaxed);
                shared.up.store(true, Ordering::Release);
                sink.on_lane(lane, true);
                let mut restart = shared.restart.subscribe();
                let ended = serve(lane, ws, &shared, sink.as_ref(), &mut stop, &mut restart).await;
                shared.up.store(false, Ordering::Release);
                sink.on_lane(lane, false);
                sink.on_peer(lane, false);
                match ended {
                    Served::Stopped => break,
                    Served::RefusedAtJoin => {
                        shared.refusing.store(true, Ordering::Release);
                        let since = *first_refusal.get_or_insert_with(Instant::now);
                        if since.elapsed() >= give_up {
                            sink.on_refused();
                            break;
                        }
                    }
                    Served::Dropped => {
                        shared.refusing.store(false, Ordering::Release);
                        first_refusal = None;
                        backoff = Duration::from_millis(250);
                    }
                }
            }
            Err(LaneError::RelayIdentity) => {
                sink.on_relay_identity_failed();
                break;
            }
            Err(LaneError::Network) => {}
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = stop.changed() => break,
        }
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
    // Done: stopped, refused or a failed pin (each reported).
    shared.connecting.store(false, Ordering::Release);
    shared.refusing.store(false, Ordering::Release);
}

async fn connect_and_join(
    cfg: &LaneConfig,
    token: &[u8; 32],
    lane: u8,
    role: u8,
) -> Result<WebSocketStream<TransportStream>, LaneError> {
    let tcfg = TransportConfig {
        server_url: cfg.server_url.clone(),
        dev_origin: cfg.dev_origin.clone(),
        tls_fingerprint: cfg.tls_fingerprint,
        resumption: cfg.resumption.clone(),
        connection_timeout_secs: 10,
        ..TransportConfig::default()
    };
    let net = |_| LaneError::Network;
    let (mut ws, binding) = open_websocket(&tcfg, true).await.map_err(net)?;
    let hello = signaling_frame(&SignalingMessage::hello(vec![PROTOCOL_VERSION]))
        .map_err(|_| LaneError::Network)?;
    ws.send(Message::Binary(hello))
        .await
        .map_err(|_| LaneError::Network)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (challenge, offer) = loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .map_err(|_| LaneError::Network)?
            .ok_or(LaneError::Network)?
            .map_err(|_| LaneError::Network)?;
        let sig = match &msg {
            Message::Text(t) => serde_json::from_str::<SignalingMessage>(t).ok(),
            Message::Binary(b) if b.first() == Some(&FRAME_TYPE_SIGNALING) => {
                serde_json::from_slice(&b[1..]).ok()
            }
            _ => None,
        };
        if let Some(SignalingEvent::HelloResponse {
            selected_version,
            auth_challenge,
            relay_identity,
            ..
        }) = sig.as_ref().map(classify_signaling)
        {
            let challenge = auth_challenge
                .filter(|_| selected_version == PROTOCOL_VERSION)
                .ok_or(LaneError::Network)?;
            break (challenge, relay_identity);
        }
    };
    let offer = offer.ok_or(LaneError::RelayIdentity)?;
    crate::relay_pin::decide(
        &offer,
        &binding,
        &challenge,
        Some((&cfg.relay_pin, cfg.relay_pin_version)),
        true,
    )
    .map_err(|_| LaneError::RelayIdentity)?;
    let join = ControlMessage::MediaJoin {
        token: *token,
        lane,
        role,
    }
    .encode_with_frame_type();
    ws.send(Message::Binary(join))
        .await
        .map_err(|_| LaneError::Network)?;
    Ok(ws)
}

/// One joined connection: the writer drains the queue while the reader
/// takes frames, until it stops, drops (no write progress for
/// `STALL_AFTER`, a restart, or the connection ending) or was refused. A
/// video connection that drops closes with a reset, so its kernel's unsent
/// video goes with it.
async fn serve<Q: SendQueue>(
    lane: u8,
    ws: WebSocketStream<TransportStream>,
    shared: &LaneShared<Q>,
    sink: &dyn LaneSink,
    stop: &mut watch::Receiver<bool>,
    restart: &mut watch::Receiver<u64>,
) -> Served {
    let reset = ws.get_ref().reset_on_close();
    let mut progress = ws.get_ref().send_progress();
    let video = lane >= 2;
    let (mut tx, mut rx) = ws.split();
    let joined_at = Instant::now();
    let mut heard = false;
    // One pong waits at most; the relay's pings are seconds apart.
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    // The writer and the reader run at the same time: a send blocked on a
    // saturated uplink must not stop the downlink being read.
    let writer = async {
        let mut out = Vec::new();
        loop {
            while shared.queue.lock().pop_into(&mut out) {
                // The socket takes the buffer; the next pop fills a fresh one.
                let sent = std::mem::take(&mut out);
                let n = sent.len();
                let send = tx.send(Message::Binary(sent));
                // No write progress for 2 s. On a video connection that is
                // no bytes taken for 2 s, so a slow but moving one (an 8 KiB
                // fragment can take seconds on a thin uplink) stays up.
                let written = if video {
                    moving(send, &mut progress).await
                } else {
                    matches!(tokio::time::timeout(STALL_AFTER, send).await, Ok(Ok(())))
                };
                if !written {
                    return Served::Dropped;
                }
                shared.queue.lock().on_written(n, Instant::now());
            }
            tokio::select! {
                _ = shared.ready.notified() => {}
                Some(p) = pong_rx.recv() => {
                    if !matches!(
                        tokio::time::timeout(STALL_AFTER, tx.send(Message::Binary(p))).await,
                        Ok(Ok(()))
                    ) {
                        return Served::Dropped;
                    }
                }
            }
        }
    };
    let mut writer = Box::pin(writer);
    let served = loop {
        tokio::select! {
            served = &mut writer => break served,
            // A hang-up ends a write in progress too.
            _ = stop.changed() => {
                drop(writer);
                let _ = tokio::time::timeout(Duration::from_millis(200), tx.close()).await;
                return Served::Stopped;
            }
            _ = restart.changed() => break Served::Dropped,
            msg = rx.next() => match msg {
                Some(Ok(Message::Binary(b))) => match b.first() {
                    Some(&FRAME_TYPE_MEDIA) => {
                        heard = true;
                        sink.on_frame(lane, &b, Instant::now());
                    }
                    Some(&FRAME_TYPE_CONTROL) => match ControlMessage::decode(&b) {
                        Some(ControlMessage::MediaJoined) => {
                            heard = true;
                            sink.on_peer(lane, true);
                        }
                        Some(ControlMessage::MediaPeerGone) => sink.on_peer(lane, false),
                        _ => {}
                    },
                    Some(&FRAME_TYPE_KEEPALIVE) => {
                        if let Some(KeepaliveMessage::Ping { timestamp }) = KeepaliveMessage::decode(&b) {
                            let now = crate::unix_now_secs();
                            // A pong already waiting answers this ping too.
                            let _ = pong_tx.try_send(KeepaliveMessage::Pong { ping_timestamp: timestamp, timestamp: now }.encode_with_frame_type());
                        }
                    }
                    _ => {}
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                    break if !heard && joined_at.elapsed() < Duration::from_secs(2) {
                        Served::RefusedAtJoin
                    } else {
                        Served::Dropped
                    };
                }
                Some(Ok(_)) => {}
            },
        }
    };
    if video && matches!(served, Served::Dropped) {
        reset.arm();
    }
    served
}
/// How long a connection has made no write progress in bytes.
trait WriteProgress {
    fn idle_for(&mut self) -> Duration;
}

impl WriteProgress for crate::transport::SendProgress {
    fn idle_for(&mut self) -> Duration {
        crate::transport::SendProgress::idle_for(self)
    }
}

/// Runs one send; false once the socket has made no write progress in
/// bytes (took none, sent none) for `STALL_AFTER`, counting from the start
/// of this send.
async fn moving<E>(
    send: impl std::future::Future<Output = Result<(), E>>,
    progress: &mut impl WriteProgress,
) -> bool {
    let start = Instant::now();
    tokio::pin!(send);
    loop {
        tokio::select! {
            r = &mut send => return r.is_ok(),
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if start.elapsed().min(progress.idle_for()) >= STALL_AFTER {
                    return false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::test_relay::{fake_relay, lane_config, Mode};
    use crate::call::video::queue::Pushed;
    use crate::call::video::MAX_VIDEO_WIRE;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Rec {
        frames: Mutex<Vec<(u8, Vec<u8>)>>,
        peers: Mutex<Vec<(u8, bool)>>,
        lanes: Mutex<Vec<(u8, bool)>>,
        refused: AtomicUsize,
    }

    impl LaneSink for Rec {
        fn on_frame(&self, lane: u8, frame: &[u8], _at: Instant) {
            self.frames.lock().push((lane, frame.to_vec()));
        }
        fn on_peer(&self, lane: u8, present: bool) {
            self.peers.lock().push((lane, present));
        }
        fn on_lane(&self, lane: u8, up: bool) {
            self.lanes.lock().push((lane, up));
        }
        fn on_refused(&self) {
            self.refused.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_until(what: &str, secs: u64, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(secs);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn frame(seq: u8, len: usize) -> Vec<u8> {
        let mut f = vec![FRAME_TYPE_MEDIA, 0, 0, 0, 0, 0, 0, 0, seq];
        f.resize(len, 0xEE);
        f
    }

    #[test]
    fn each_queue_holds_at_most_3_frames_and_drops_the_oldest() {
        let mut q = LaneQueue::new();
        for seq in 1..=5u8 {
            q.push(&frame(seq, 40));
        }
        assert_eq!(q.dropped(), 2);
        let mut out = Vec::with_capacity(MAX_WIRE_FRAME);
        let mut got = Vec::new();
        while q.pop_into(&mut out) {
            got.push(out[8]);
        }
        assert_eq!(got, vec![3, 4, 5]);
    }

    fn video_fill(len: usize) -> impl FnMut(usize, &mut [u8]) -> usize {
        move |_i, slot| {
            slot[0] = FRAME_TYPE_MEDIA;
            len
        }
    }

    /// Lanes that never connect, marked up by hand: only the queues matter.
    fn offline_video_lanes() -> VideoLanes {
        let lanes = VideoLanes::start(
            lane_config("ws://127.0.0.1:1/"),
            Zeroizing::new([0x6E; 32]),
            0,
            Arc::new(Rec::default()),
            CONNECT_GIVE_UP,
        );
        for s in &lanes.shared {
            s.up.store(true, Ordering::Release);
        }
        lanes
    }

    #[tokio::test]
    async fn with_no_video_lane_up_a_frame_is_no_lane() {
        let lanes = offline_video_lanes();
        for s in &lanes.shared {
            s.up.store(false, Ordering::Release);
        }
        let r = lanes.push_frame(1, true, Instant::now(), &mut video_fill(100));
        assert_eq!(r, Pushed::NoLane);
    }

    /// Only the stall tier: nothing waits, but a fragment has been in flight
    /// on lane 2 for over 500 ms with no write finished.
    #[tokio::test]
    async fn a_lane_blocked_on_its_last_write_is_stalled_not_chosen() {
        let lanes = offline_video_lanes();
        let t0 = Instant::now();
        assert_eq!(
            lanes.push_frame(1, false, t0, &mut video_fill(100)),
            Pushed::Queued { lane: 2 }
        );
        let mut out = Vec::new();
        assert!(lanes.shared[0].queue.lock().pop_into(&mut out)); // in flight
        let now = t0 + Duration::from_millis(600);
        let st = lanes.stats(now);
        assert_eq!((st[0].queued_bytes, st[0].oldest), (0, None));
        assert!(st[0].since_progress >= Duration::from_millis(500));
        // The move sends nothing (the next frame must be a keyframe); the
        // keyframe goes on lane 3.
        assert_eq!(
            lanes.push_frame(1, false, now, &mut video_fill(100)),
            Pushed::Switched { lane: 3 }
        );
        assert_eq!(
            lanes.push_frame(1, true, now, &mut video_fill(100)),
            Pushed::Queued { lane: 3 }
        );
        assert_eq!(lanes.counters().switches, 1);
    }

    /// A lane that completes writes, but slowly, is left once it is behind
    /// (oldest over 250 ms, the other empty), after the 1 s hold: what waited
    /// there is dropped (it would arrive after the new lane's frames), the
    /// move itself sends nothing, and the frames stay on the moving lane.
    #[tokio::test]
    async fn frames_move_off_a_slow_but_moving_lane_and_what_waited_there_is_dropped() {
        let lanes = offline_video_lanes();
        let t0 = Instant::now();
        let mut out = Vec::new();
        let mut on = [0usize; 2];
        let mut switched_at = None;
        for k in 0..100u32 {
            let now = t0 + Duration::from_millis(20) * k;
            // Lane 3 drains at once; lane 2 takes a fragment every 100 ms.
            while lanes.shared[1].queue.lock().pop_into(&mut out) {
                lanes.shared[1].queue.lock().on_written(out.len(), now);
            }
            if k % 5 == 0 && lanes.shared[0].queue.lock().pop_into(&mut out) {
                lanes.shared[0].queue.lock().on_written(out.len(), now);
            }
            match lanes.push_frame(1, false, now, &mut video_fill(MAX_VIDEO_WIRE)) {
                Pushed::Queued { lane } => on[usize::from(lane - 2)] += 1,
                Pushed::Switched { lane: 3 } if switched_at.is_none() => {
                    switched_at = Some(k);
                    assert_eq!(lanes.stats(now)[0].queued_bytes, 0, "lane 2 emptied");
                }
                other => panic!("frame {k}: {other:?}"),
            }
        }
        let k = switched_at.expect("moved to lane 3");
        assert!(
            (50..=52).contains(&k),
            "moved once the 1 s hold was up: {k}"
        );
        assert_eq!(on, [50, 49], "every frame after the move on lane 3");
        assert_eq!(lanes.counters().switches, 1, "never moved back");
    }

    /// The writer and the reader run together: while writes are blocked on a
    /// full socket (an uplink at its limit), frames from the peer still come in.
    #[tokio::test]
    async fn a_blocked_write_does_not_stop_reading() {
        let (url, _seen) = fake_relay(Mode::DeafTalker).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x6F; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        let mut stalled_at = None;
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            lanes.push_frame(1, false, Instant::now(), &mut video_fill(MAX_VIDEO_WIRE));
            if stalled_at.is_none()
                && lanes
                    .stats(Instant::now())
                    .iter()
                    .any(|s| s.since_progress >= VIDEO_STALLED_AFTER)
            {
                stalled_at = Some(rec.frames.lock().len());
            }
            if stalled_at.is_some_and(|n| rec.frames.lock().len() >= n + 60) {
                assert_eq!(
                    lanes.counters().reconnects,
                    0,
                    "the frames came in on the same connections"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "frames kept coming in after writes stalled: stalled at {stalled_at:?}, got {}",
            rec.frames.lock().len()
        );
    }

    /// A hang-up ends a write that is blocked on a full socket at once, not
    /// after the 2 s stall limit.
    #[tokio::test]
    async fn stop_ends_a_blocked_write_at_once() {
        let (url, _seen) = fake_relay(Mode::DeafTalker).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x71; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        let end = Instant::now() + Duration::from_secs(5);
        while !lanes
            .stats(Instant::now())
            .iter()
            .any(|s| s.since_progress >= Duration::from_millis(200))
        {
            assert!(Instant::now() < end, "a write blocked");
            lanes.push_frame(1, true, Instant::now(), &mut video_fill(MAX_VIDEO_WIRE));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let stopped = Instant::now();
        lanes.stop();
        wait_until("both down", 2, || {
            rec.lanes.lock().iter().filter(|l| !l.1).count() == 2
        })
        .await;
        assert!(
            stopped.elapsed() < Duration::from_millis(600),
            "down {:?} after the stop",
            stopped.elapsed()
        );
    }

    /// Bytes moving on a fixed clock: progress every `every`, for `for_`.
    struct Ticking {
        start: Instant,
        every: Duration,
        for_: Duration,
    }

    impl WriteProgress for Ticking {
        fn idle_for(&mut self) -> Duration {
            let e = self.start.elapsed();
            if e <= self.for_ {
                Duration::from_nanos((e.as_nanos() % self.every.as_nanos()) as u64)
            } else {
                e - self.for_
            }
        }
    }

    /// A video connection that is slow but moving is not a stall: a send
    /// that takes 3 s while bytes move every 500 ms completes; one with no
    /// bytes moving for 2 s is a stall (the old rule, a 2 s limit on the
    /// whole send, dropped both).
    #[tokio::test]
    async fn a_slow_but_moving_send_is_not_a_stall() {
        let slow = tokio::time::sleep(Duration::from_secs(3));
        let mut p = Ticking {
            start: Instant::now(),
            every: Duration::from_millis(500),
            for_: Duration::from_secs(10),
        };
        assert!(
            moving(
                async {
                    slow.await;
                    Ok::<(), ()>(())
                },
                &mut p
            )
            .await
        );
        let started = Instant::now();
        let stuck = tokio::time::sleep(Duration::from_secs(10));
        let mut p = Ticking {
            start: Instant::now(),
            every: Duration::from_millis(500),
            for_: Duration::ZERO,
        };
        assert!(
            !moving(
                async {
                    stuck.await;
                    Ok::<(), ()>(())
                },
                &mut p
            )
            .await
        );
        let took = started.elapsed();
        assert!(
            took >= STALL_AFTER && took < STALL_AFTER + Duration::from_millis(600),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn clearing_the_queues_drops_what_waits_to_be_sent() {
        let (url, _seen) = fake_relay(Mode::Stall).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x70; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        // Stall never joins, so no lane is up: nothing to queue on. Queue on
        // the lanes' own queues instead.
        for s in &lanes.shared {
            s.queue
                .lock()
                .push_frame(2, false, Instant::now(), &mut video_fill(300));
        }
        assert!(lanes
            .stats(Instant::now())
            .iter()
            .all(|s| s.queued_bytes > 0));
        lanes.clear_queues();
        assert!(lanes
            .stats(Instant::now())
            .iter()
            .all(|s| s.queued_bytes == 0));
    }

    #[tokio::test]
    async fn video_lanes_join_lanes_2_and_3_with_the_same_token_and_role() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x6B; 32]),
            1,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("two joins", 5, || seen.lock().joins.len() == 2).await;
        let mut joins = seen.lock().joins.clone();
        joins.sort_by_key(|j| j.1);
        assert_eq!(joins, vec![([0x6B; 32], 2, 1), ([0x6B; 32], 3, 1)]);
        drop(lanes);
    }

    #[tokio::test]
    async fn a_video_frame_goes_once_on_one_lane() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x6C; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        let pushed = lanes.push_frame(3, true, Instant::now(), &mut video_fill(300));
        assert!(matches!(pushed, Pushed::Queued { .. }), "{pushed:?}");
        wait_until("3 fragments", 5, || seen.lock().media_in == 3).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let s = seen.lock();
        assert_eq!(s.media_in, 3, "sent once, not on both lanes");
        assert!(
            (s.lane_in[2], s.lane_in[3]) == (3, 0) || (s.lane_in[2], s.lane_in[3]) == (0, 3),
            "all on one lane: {:?}",
            s.lane_in
        );
    }

    /// R12: a lane whose writes stopped making progress for over 500 ms is
    /// not chosen for the next frame.
    #[tokio::test]
    async fn lane_choice_moves_off_a_stalled_lane() {
        let (url, _seen) = fake_relay(Mode::StallLane(2)).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x6D; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        let mut first = None;
        let mut dropped = 0;
        let end = Instant::now() + Duration::from_secs(15);
        while Instant::now() < end {
            match lanes.push_frame(1, false, Instant::now(), &mut video_fill(MAX_VIDEO_WIRE)) {
                Pushed::Queued { lane: 3 } | Pushed::Switched { lane: 3 } => {
                    first = Some(lanes.stats(Instant::now()));
                    break;
                }
                Pushed::Dropped | Pushed::NoLane => dropped += 1,
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stats = first.expect("a frame went on lane 3");
        assert_eq!(dropped, 0, "moved because of the stall, not a full queue");
        assert!(
            stats[0].since_progress > Duration::ZERO,
            "lane 2 was not progressing: {:?}",
            stats[0]
        );
    }

    #[tokio::test]
    async fn both_lanes_say_hello_check_the_pin_and_join_with_token_lane_and_role() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = Lanes::start(
            lane_config(&url),
            Zeroizing::new([0x5A; 32]),
            1,
            rec.clone(),
        );
        wait_until("two joins", 5, || seen.lock().joins.len() == 2).await;
        let mut joins = seen.lock().joins.clone();
        joins.sort_by_key(|j| j.1);
        assert_eq!(joins, vec![([0x5A; 32], 0, 1), ([0x5A; 32], 1, 1)]);
        wait_until("peer on both", 5, || {
            rec.peers.lock().iter().filter(|p| p.1).count() == 2
        })
        .await;
        drop(lanes);
    }

    #[tokio::test]
    async fn a_relay_that_fails_the_pin_is_refused_before_any_join() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let mut cfg = lane_config(&url);
        cfg.relay_pin = crate::relay_pin::encode_pin(&[9; 32]);
        let _lanes = Lanes::start(cfg, Zeroizing::new([1; 32]), 0, rec.clone());
        wait_until("refused", 5, || rec.refused.load(Ordering::SeqCst) >= 1).await;
        assert!(
            seen.lock().joins.is_empty(),
            "never joined a relay that failed its pin"
        );
    }

    #[tokio::test]
    async fn every_frame_goes_out_on_both_lanes() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = Lanes::start(lane_config(&url), Zeroizing::new([2; 32]), 0, rec.clone());
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        for seq in 0..20u8 {
            lanes.send(&frame(seq, 85));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        wait_until("echoes", 5, || rec.frames.lock().len() >= 38).await;
        let frames = rec.frames.lock();
        for seq in 0..20u8 {
            let lanes_with: Vec<u8> = frames
                .iter()
                .filter(|f| f.1[8] == seq)
                .map(|f| f.0)
                .collect();
            assert!(
                lanes_with.contains(&0) && lanes_with.contains(&1) || seq < 2,
                "seq {seq} on {lanes_with:?}"
            );
        }
        assert!(seen.lock().media_in >= 38);
    }

    #[tokio::test]
    async fn a_lane_with_no_write_progress_for_2_s_reconnects_on_the_same_lane() {
        // The fake relay never reads after the join, and its sockets have an
        // 8 KiB receive buffer, so the client's writes stop making progress.
        let (url, seen) = fake_relay(Mode::Stall).await;
        let rec = Arc::new(Rec::default());
        let lanes = Arc::new(Lanes::start(
            lane_config(&url),
            Zeroizing::new([3; 32]),
            0,
            rec.clone(),
        ));
        wait_until("two joins", 5, || seen.lock().joins.len() == 2).await;
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        let flood = tokio::spawn({
            let l = lanes.clone();
            async move {
                loop {
                    l.send(&[FRAME_TYPE_MEDIA; MAX_WIRE_FRAME]);
                    tokio::task::yield_now().await;
                }
            }
        });
        let per_lane = |l: u8| seen.lock().joins.iter().filter(|j| j.1 == l).count();
        wait_until("both lanes rejoined", 12, || {
            per_lane(0) >= 2 && per_lane(1) >= 2
        })
        .await;
        flood.abort();
        let joins = seen.lock().joins.clone();
        assert!(
            joins.iter().all(|j| j.0 == [3; 32] && j.2 == 0),
            "same token and role: {joins:?}"
        );
        assert!(
            rec.lanes.lock().iter().any(|l| !l.1),
            "a stalled lane was reported down"
        );
        assert_eq!(
            rec.refused.load(Ordering::SeqCst),
            0,
            "a stall is not a refusal"
        );
    }

    /// Review Focus 1: a lane that drops comes back with the same token and lane.
    #[tokio::test]
    async fn a_dropped_lane_reconnects_with_the_same_token_and_lane() {
        let (url, seen) = fake_relay(Mode::DropAfter(Duration::from_millis(500))).await;
        let rec = Arc::new(Rec::default());
        let lanes = Arc::new(Lanes::start(
            lane_config(&url),
            Zeroizing::new([4; 32]),
            1,
            rec.clone(),
        ));
        let sender = tokio::spawn({
            let l = lanes.clone();
            async move {
                for seq in 0..=u8::MAX {
                    l.send(&frame(seq, 85));
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        });
        let per_lane = |l: u8| seen.lock().joins.iter().filter(|j| j.1 == l).count();
        wait_until("each lane joined again", 8, || {
            per_lane(0) >= 2 && per_lane(1) >= 2
        })
        .await;
        sender.abort();
        let joins = seen.lock().joins.clone();
        assert!(
            joins.iter().all(|j| j.0 == [4; 32] && j.2 == 1),
            "same token and role: {joins:?}"
        );
        assert_eq!(
            rec.refused.load(Ordering::SeqCst),
            0,
            "a drop after media is not a refusal"
        );
    }

    /// D34: a refused join is retried (250 ms, 500 ms, 1 s, then every 2 s)
    /// until the give-up time after the lane's first refusal, then reported.
    /// With a 1.5 s give-up the refusals land at about 0, 0.25, 0.75 and
    /// 1.75 s, so each lane tries exactly 4 times.
    #[tokio::test]
    async fn refused_joins_are_retried_with_backoff_until_the_give_up() {
        let (url, seen) = fake_relay(Mode::Refuse).await;
        let rec = Arc::new(Rec::default());
        let give_up = Duration::from_millis(1500);
        let _lanes = Lanes::start_with_give_up(
            lane_config(&url),
            Zeroizing::new([5; 32]),
            0,
            rec.clone(),
            give_up,
        );
        wait_until("both lanes gave up", 8, || {
            rec.refused.load(Ordering::SeqCst) == 2
        })
        .await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let per_lane = |l: u8| seen.lock().joins.iter().filter(|j| j.1 == l).count();
        assert_eq!(
            (per_lane(0), per_lane(1)),
            (4, 4),
            "retried with backoff, then stopped"
        );
        assert_eq!(rec.refused.load(Ordering::SeqCst), 2, "one report per lane");
    }

    /// The callee may join before the caller's grant has reached the relay:
    /// the first refusals are retried and the call connections come up.
    #[tokio::test]
    async fn joins_refused_before_the_peer_granted_are_retried_until_they_succeed() {
        let (url, seen) = fake_relay(Mode::RefuseFirst(4)).await;
        let rec = Arc::new(Rec::default());
        let _lanes = Lanes::start(lane_config(&url), Zeroizing::new([7; 32]), 1, rec.clone());
        // MediaJoined (on_peer true) comes only on a join the relay kept.
        wait_until("joined on both lanes", 8, || {
            rec.peers.lock().iter().filter(|p| p.1).count() == 2
        })
        .await;
        assert!(
            seen.lock().joins.len() >= 6,
            "4 refused joins, then one per lane"
        );
        assert_eq!(
            rec.refused.load(Ordering::SeqCst),
            0,
            "not given up within CONNECT_GIVE_UP"
        );
    }

    /// A pause resets the video lanes one after the other: lane 3 only once
    /// lane 2 is back up, so incoming video always has a lane.
    #[tokio::test]
    async fn a_pause_restarts_lane_3_only_after_lane_2_is_back() {
        let (url, _seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = VideoLanes::start(
            lane_config(&url),
            Zeroizing::new([0x74; 32]),
            0,
            rec.clone(),
            CONNECT_GIVE_UP,
        );
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        lanes.abort_and_restart();
        wait_until("both back", 8, || rec.lanes.lock().len() == 6).await;
        let events = rec.lanes.lock()[2..].to_vec();
        assert_eq!(
            events,
            vec![(2, false), (2, true), (3, false), (3, true)],
            "lane 3 waited for lane 2"
        );
        assert_eq!(lanes.counters().reconnects, 2);
    }

    #[tokio::test]
    async fn restarting_one_lane_reopens_only_that_lane_with_the_same_token() {
        let (url, seen) = fake_relay(Mode::Echo).await;
        let rec = Arc::new(Rec::default());
        let lanes = Lanes::start(lane_config(&url), Zeroizing::new([9; 32]), 1, rec.clone());
        wait_until("two joins", 5, || seen.lock().joins.len() == 2).await;
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        lanes.restart(1);
        wait_until("lane 1 rejoined", 5, || seen.lock().joins.len() == 3).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let joins = seen.lock().joins.clone();
        assert_eq!(joins.iter().filter(|j| j.1 == 0).count(), 1, "{joins:?}");
        assert_eq!(joins.iter().filter(|j| j.1 == 1).count(), 2, "{joins:?}");
        assert!(joins.iter().all(|j| j.0 == [9; 32] && j.2 == 1));
        assert_eq!(rec.refused.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn peer_presence_is_reported_and_pings_are_answered() {
        let (url, seen) = fake_relay(Mode::PeerComesAndGoes).await;
        let rec = Arc::new(Rec::default());
        let lanes = Lanes::start(lane_config(&url), Zeroizing::new([6; 32]), 0, rec.clone());
        wait_until("peer gone on a lane", 5, || {
            rec.peers.lock().iter().any(|p| !p.1)
        })
        .await;
        lanes.send(&frame(1, 40)); // gives the writer a turn to send the pong
        wait_until("pongs", 5, || seen.lock().pongs >= 1).await;
        let peers = rec.peers.lock().clone();
        let first_gone = peers.iter().position(|p| !p.1).unwrap();
        assert!(
            peers[..first_gone].iter().any(|p| p.1),
            "joined before gone: {peers:?}"
        );
    }

    /// Nonce safety: the lanes carry sealed bytes and never make or re-make
    /// one, so a lane reconnect neither restarts nor repeats a sequence number
    /// (the sequence is inside the frame the caller sealed once).
    #[tokio::test]
    async fn a_lane_reconnect_neither_resets_nor_duplicates_seq() {
        let (url, seen) = fake_relay(Mode::DropAfter(Duration::from_millis(400))).await;
        let rec = Arc::new(Rec::default());
        let lanes = Arc::new(Lanes::start(
            lane_config(&url),
            Zeroizing::new([8; 32]),
            0,
            rec.clone(),
        ));
        wait_until("both up", 5, || {
            rec.lanes.lock().iter().filter(|l| l.1).count() == 2
        })
        .await;
        for seq in 0..=u8::MAX {
            lanes.send(&frame(seq, 85));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let per_lane = |l: u8| seen.lock().joins.iter().filter(|j| j.1 == l).count();
        assert!(
            per_lane(0) >= 2 && per_lane(1) >= 2,
            "each lane reconnected at least once"
        );
        let frames = rec.frames.lock();
        for lane in 0..2u8 {
            let seqs: Vec<u8> = frames
                .iter()
                .filter(|f| f.0 == lane)
                .map(|f| f.1[8])
                .collect();
            assert!(
                seqs.len() > 20,
                "lane {lane} carried frames: {}",
                seqs.len()
            );
            assert!(
                seqs.windows(2).all(|w| w[0] < w[1]),
                "lane {lane}: seq strictly increasing, no repeat or restart: {seqs:?}"
            );
            assert!(
                seqs.iter().any(|&s| s > 200),
                "lane {lane} still carrying late seq after reconnects"
            );
        }
    }
}
