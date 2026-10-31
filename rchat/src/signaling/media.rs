//! Call connections (Android voice calls spec §5): a token both members of
//! a circuit granted, call connections joined to it on lane 0 or 1 (audio)
//! or 2 or 3 (video) of the caller's or the callee's side, and `0x05`
//! forwarding. Audio and video lanes never cross: lane 0 falls back to 1,
//! 2 to 3, and back. Video lanes have their own 4 Mbps ceiling, queue cap
//! and metrics. Nothing
//! here is stored or queued, and nothing names anyone: a token is held only
//! as its keyed `MediaTag` (D3), and a call connection never publishes.
//! Logs carry no identifier at all.
//!
//! Lock order: the `MediaState` lock may be taken while no `connections`
//! guard is held, and a `connections` guard may be taken under it; never
//! the media lock under a `connections` guard.

use super::tags::{media_tag, MediaTag};
use super::{circuits, PairKey, RelayState, UnifiedConnection};
use crate::limits::{MediaBucket, MEDIA_QUEUED_MAX_BYTES, VIDEO_QUEUED_MAX_BYTES};
use crate::metrics;
use crate::protocol::unified::{ControlMessage, UnifiedFrame};
use crate::protocol::{CircuitId, ClientId};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use tracing::trace;

/// A usable token nobody joined, or a one-sided grant, lasts this long.
pub(crate) const UNJOINED_TTL: Duration = Duration::from_secs(60);
/// A joined token outlives its last call connection by this long.
pub(crate) const EMPTY_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_LIVE_TOKENS_PER_CONNECTION: usize = 2;
/// How often `sweep` runs.
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Where a call connection sits: its token, side (0 caller, 1 callee) and lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MediaLane {
    pub(crate) tag: MediaTag,
    pub(crate) role: u8,
    pub(crate) lane: u8,
}

/// Lanes 2 and 3 carry video; 0 and 1 carry audio.
pub(crate) fn is_video_lane(lane: u8) -> bool {
    lane >= 2
}

/// The lane a frame falls back to when the other side lacks its own: the
/// other lane of the same kind.
fn partner(lane: usize) -> usize {
    lane ^ 1
}

/// On a call connection's `UnifiedConnection`: its place and rate bucket
/// (64 kbps on audio lanes, about 4 Mbps on video lanes).
#[derive(Debug)]
pub(crate) struct LaneState {
    pub(crate) place: MediaLane,
    pub(crate) bucket: MediaBucket,
}

struct MediaToken {
    pair: PairKey,
    /// The pair's two circuit ids in bytewise order; grant `i` is for `circuits[i]`.
    circuits: [CircuitId; 2],
    granted_by: [Option<ClientId>; 2],
    first_grant_at: Instant,
    usable_since: Option<Instant>,
    /// Call connections, `[role][lane]`.
    lanes: [[Option<ClientId>; 4]; 2],
    ever_joined: bool,
    empty_since: Option<Instant>,
}

impl MediaToken {
    fn has_lanes(&self) -> bool {
        self.lanes.iter().flatten().any(Option::is_some)
    }

    fn side(&self, role: usize) -> Vec<ClientId> {
        self.lanes[role].iter().flatten().copied().collect()
    }

    fn expired(&self, now: Instant) -> bool {
        let since = |t: Instant| now.saturating_duration_since(t);
        match (self.usable_since, self.ever_joined) {
            (None, _) => since(self.first_grant_at) >= UNJOINED_TTL,
            (Some(at), false) => since(at) >= UNJOINED_TTL,
            (Some(_), true) => self.empty_since.is_some_and(|e| since(e) >= EMPTY_TTL),
        }
    }
}

#[derive(Default)]
struct Inner {
    tokens: HashMap<MediaTag, MediaToken>,
    by_pair: HashMap<PairKey, MediaTag>,
}

impl Inner {
    fn remove(&mut self, tag: MediaTag) -> Option<MediaToken> {
        let t = self.tokens.remove(&tag)?;
        if self.by_pair.get(&t.pair) == Some(&tag) {
            self.by_pair.remove(&t.pair);
        }
        metrics::MEDIA_TOKENS_ACTIVE.dec();
        Some(t)
    }
}

/// Every media token of this relay (at most one per circuit).
#[derive(Default)]
pub(crate) struct MediaState(Mutex<Inner>);

pub(crate) enum Grant {
    Held,
    Usable,
    Refused,
}

pub(crate) enum Join {
    Joined,
    Refused,
}

fn send_to(id: ClientId, msg: Message, state: &RelayState) {
    if let Some(c) = state.connections.get(&id) {
        let _ = c.ws_tx.send(msg);
    }
}

fn close_lanes(t: &MediaToken, state: &RelayState) {
    for id in t.lanes.iter().flatten().flatten() {
        if let Some(c) = state.connections.get(id) {
            c.ws_tx.kill();
        }
    }
}

/// `MediaGrant` from `caller` (spec §5 "Granting a token", D5).
pub(crate) fn grant(
    caller: ClientId,
    circuit_id: CircuitId,
    token: &[u8; 32],
    state: &RelayState,
    now: Instant,
) -> Grant {
    if !circuits::is_proven(caller, state) {
        return Grant::Refused;
    }
    // `client_a` of a routing entry owns that circuit id: the caller's own side.
    let Some((pair, peer)) = state
        .circuits
        .get(&circuit_id)
        .filter(|r| r.client_a == caller)
        .map(|r| (r.pair, r.peer_circuit))
    else {
        return Grant::Refused;
    };
    let tag = media_tag(token);
    let ordered = if circuit_id.0 <= peer.0 {
        [circuit_id, peer]
    } else {
        [peer, circuit_id]
    };
    let side = usize::from(ordered[0] != circuit_id);
    let mut guard = state.media.0.lock();
    let inner = &mut *guard;
    // A token another pair holds is refused before anything of the caller's
    // own is replaced.
    if inner
        .tokens
        .get(&tag)
        .is_some_and(|tok| tok.pair != pair || tok.circuits != ordered)
    {
        return Grant::Refused;
    }
    let held = inner
        .tokens
        .iter()
        // The token this grant would replace on the same pair does not count.
        .filter(|(t, tok)| **t != tag && tok.pair != pair && tok.granted_by.contains(&Some(caller)))
        .count();
    if held >= MAX_LIVE_TOKENS_PER_CONNECTION {
        return Grant::Refused;
    }
    if let Some(&old) = inner.by_pair.get(&pair) {
        if old != tag {
            if inner.tokens.get(&old).is_some_and(MediaToken::has_lanes) {
                return Grant::Refused;
            }
            inner.remove(old);
        }
    }
    let Inner { tokens, by_pair } = inner;
    let tok = tokens.entry(tag).or_insert_with(|| {
        metrics::MEDIA_TOKENS_ACTIVE.inc();
        MediaToken {
            pair,
            circuits: ordered,
            granted_by: [None, None],
            first_grant_at: now,
            usable_since: None,
            lanes: [[None; 4]; 2],
            ever_joined: false,
            empty_since: None,
        }
    });
    tok.granted_by[side] = Some(caller);
    by_pair.insert(pair, tag);
    if tok.granted_by.iter().all(Option::is_some) {
        tok.usable_since.get_or_insert(now);
        trace!("Media token usable");
        Grant::Usable
    } else {
        Grant::Held
    }
}

/// `MediaJoin` from `caller` (spec §5 "Joining", D1, D6).
pub(crate) fn join(
    caller: ClientId,
    token: &[u8; 32],
    lane: u8,
    role: u8,
    state: &RelayState,
    now: Instant,
) -> Join {
    if lane > 3 || role > 1 {
        return Join::Refused;
    }
    {
        let Some(mut c) = state.connections.get_mut(&caller) else {
            return Join::Refused;
        };
        let fresh = c.protocol_version == crate::protocol::PROTOCOL_VERSION
            && c.proven_identity.is_none()
            && c.media.is_none();
        if !fresh || !c.auth_budget.try_take(now) {
            return Join::Refused;
        }
    }
    let tag = media_tag(token);
    let (r, l) = (usize::from(role), usize::from(lane));
    let (replaced, tell_me, tell_peers) = {
        let mut m = state.media.0.lock();
        let Some(t) = m.tokens.get_mut(&tag) else {
            return Join::Refused;
        };
        if t.usable_since.is_none() || t.expired(now) {
            return Join::Refused;
        }
        let first_on_side = t.lanes[r].iter().all(Option::is_none);
        let replaced = t.lanes[r][l].replace(caller);
        t.ever_joined = true;
        t.empty_since = None;
        let peers = t.side(1 - r);
        let tell_me = !peers.is_empty();
        (
            replaced,
            tell_me,
            if first_on_side { peers } else { Vec::new() },
        )
    };
    let attached = if let Some(mut c) = state.connections.get_mut(&caller) {
        c.media = Some(LaneState {
            place: MediaLane { tag, role, lane },
            bucket: if is_video_lane(lane) {
                MediaBucket::video_at(now)
            } else {
                MediaBucket::audio_at(now)
            },
        });
        // A call connection never identifies; it must not be closed as anonymous.
        c.identified = true;
        true
    } else {
        false
    };
    if !attached {
        // The connection went while it joined: give the lane back, so the
        // token can still empty and expire, and count nothing.
        let mut m = state.media.0.lock();
        if let Some(t) = m.tokens.get_mut(&tag) {
            if t.lanes[r][l] == Some(caller) {
                t.lanes[r][l] = replaced;
                if !t.has_lanes() {
                    t.empty_since = Some(now);
                }
            }
        }
        return Join::Refused;
    }
    metrics::MEDIA_CONNECTIONS_ACTIVE.inc();
    if is_video_lane(lane) {
        metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.inc();
    }
    if let Some(old) = replaced.filter(|o| *o != caller) {
        if let Some(c) = state.connections.get(&old) {
            c.ws_tx.kill();
        }
    }
    let joined = UnifiedFrame::control(ControlMessage::MediaJoined).encode();
    if tell_me {
        send_to(caller, joined.clone(), state);
    }
    for p in tell_peers {
        send_to(p, joined.clone(), state);
    }
    trace!("Call connection joined");
    Join::Joined
}

/// From `ConnectionCleanup::run`, after `conn` left `state.connections`.
pub(crate) fn on_connection_closed(
    client_id: ClientId,
    conn: &UnifiedConnection,
    state: &RelayState,
    now: Instant,
) {
    let Some(ls) = conn.media.as_ref() else {
        return;
    };
    metrics::MEDIA_CONNECTIONS_ACTIVE.dec();
    let p = ls.place;
    if is_video_lane(p.lane) {
        metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.dec();
    }
    let tell = {
        let mut m = state.media.0.lock();
        let Some(t) = m.tokens.get_mut(&p.tag) else {
            return;
        };
        let (r, l) = (usize::from(p.role), usize::from(p.lane));
        if t.lanes[r][l] != Some(client_id) {
            return; // replaced by a newer join
        }
        t.lanes[r][l] = None;
        if !t.has_lanes() {
            t.empty_since = Some(now);
        }
        if t.lanes[r].iter().all(Option::is_none) {
            t.side(1 - r)
        } else {
            Vec::new()
        }
    };
    let gone = UnifiedFrame::control(ControlMessage::MediaPeerGone).encode();
    for id in tell {
        send_to(id, gone.clone(), state);
    }
}

/// A member closed the circuit (`CloseCircuit`, D4): a token nobody has
/// joined goes now. A token with call connections keeps them and lives on
/// its own expiry rules (`EMPTY_TTL` after its last call connection leaves):
/// a client closes a blind-path peer's old identity circuit after every chat
/// reconnect, which must not end a call carried on it (final review I1). A
/// hang-up, block or unpin ends the call itself, so its call connections
/// leave anyway.
pub(crate) fn on_circuit_closed(pair: PairKey, state: &RelayState) {
    let mut m = state.media.0.lock();
    let Some(tag) = m.by_pair.get(&pair).copied() else {
        return;
    };
    if m.tokens.get(&tag).is_some_and(MediaToken::has_lanes) {
        return;
    }
    // No call connection to close: nothing of `connections` is touched.
    m.remove(tag);
}

/// Expire tokens (spec §5 "Expiry", D4); returns how many went.
pub(crate) fn sweep(now: Instant, state: &RelayState) -> usize {
    let removed: Vec<MediaToken> = {
        let mut m = state.media.0.lock();
        let dead: Vec<MediaTag> = m
            .tokens
            .iter()
            .filter(|(_, t)| t.expired(now))
            .map(|(k, _)| *k)
            .collect();
        dead.into_iter().filter_map(|k| m.remove(k)).collect()
    };
    for t in &removed {
        close_lanes(t, state);
    }
    removed.len()
}

pub(crate) enum FrameVerdict {
    Forwarded,
    Dropped,
    NotACallConnection,
}

/// A `0x05` frame from `caller` (spec §5 "Forwarding"): side A lane L to
/// side B lane L, else B's other lane of the same kind (audio 0/1, video
/// 2/3); over the lane's ceiling (64 kbps audio, about 4 Mbps video), or
/// with the target full or absent, dropped and counted. Never stored, never queued
/// beyond the target's outbound queue; a video frame still waiting there
/// after `VIDEO_MAX_QUEUED_AGE` is dropped unwritten (`reason="stale"`).
pub(crate) fn on_media_frame(
    caller: ClientId,
    frame: Vec<u8>,
    state: &RelayState,
    now: Instant,
) -> FrameVerdict {
    let place = {
        let Some(mut c) = state.connections.get_mut(&caller) else {
            return FrameVerdict::Dropped;
        };
        let Some(ls) = c.media.as_mut() else {
            return FrameVerdict::NotACallConnection;
        };
        if !ls.bucket.try_take_at(frame.len(), now) {
            if is_video_lane(ls.place.lane) {
                metrics::media_video_dropped(metrics::MEDIA_DROP_RATE);
            } else {
                metrics::media_dropped(metrics::MEDIA_DROP_RATE);
            }
            return FrameVerdict::Dropped;
        }
        ls.place
    };
    let target = {
        let m = state.media.0.lock();
        m.tokens.get(&place.tag).and_then(|t| {
            let other = 1 - usize::from(place.role);
            let l = usize::from(place.lane);
            t.lanes[other][l].or(t.lanes[other][partner(l)])
        })
    };
    let video = is_video_lane(place.lane);
    let (cap, max_age) = if video {
        (
            VIDEO_QUEUED_MAX_BYTES,
            Some(crate::limits::VIDEO_MAX_QUEUED_AGE),
        )
    } else {
        (MEDIA_QUEUED_MAX_BYTES, None)
    };
    let sent = target
        .and_then(|id| {
            state.connections.get(&id).map(|c| {
                c.ws_tx
                    .try_send_media(Message::Binary(frame), cap, max_age)
                    .is_ok()
            })
        })
        .unwrap_or(false);
    match (sent, video) {
        (true, true) => metrics::MEDIA_VIDEO_FRAMES_FORWARDED.inc(),
        (true, false) => metrics::MEDIA_FRAMES_FORWARDED.inc(),
        (false, true) => metrics::media_video_dropped(metrics::MEDIA_DROP_FULL),
        (false, false) => metrics::media_dropped(metrics::MEDIA_DROP_FULL),
    }
    if sent {
        FrameVerdict::Forwarded
    } else {
        FrameVerdict::Dropped
    }
}

#[cfg(test)]
impl MediaState {
    pub(crate) fn token_count(&self) -> usize {
        self.0.lock().tokens.len()
    }

    pub(crate) fn is_usable(&self, token: &[u8; 32]) -> bool {
        self.0
            .lock()
            .tokens
            .get(&media_tag(token))
            .is_some_and(|t| t.usable_since.is_some())
    }

    pub(crate) fn lanes_of(&self, token: &[u8; 32]) -> [[bool; 4]; 2] {
        let m = self.0.lock();
        let Some(t) = m.tokens.get(&media_tag(token)) else {
            return [[false; 4]; 2];
        };
        t.lanes.map(|side| side.map(|c| c.is_some()))
    }
}
