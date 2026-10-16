//! The client's blinded pairing flow (protocol v3 §C.1–C.4, Task 9, with
//! the fix-round rulings R20–R22).
//!
//! Which ask, when:
//! - **Identity path** (`CircuitAsk` with a target and a knock): no session
//!   with a pair secret (first contact, or the peer lost its sessions); a
//!   contact not yet reached after our own key rotation; a responder still
//!   waiting for the session-init of an identity pair (v2 resume stays for
//!   that circuit: identity circuits before their first blind epoch); after
//!   a pinned contact's fresh, first-seen knock (the peer is on the identity
//!   path); and the timed identity fallback (R20): one identity ask, at most
//!   once per pair per `IDENTITY_FALLBACK_INTERVAL_SECS`, once the pair has
//!   asked blind unmatched for `IDENTITY_FALLBACK_AFTER_SECS`. If that ask
//!   runs out unmatched, or the connection goes, the pair goes back to
//!   blind. So does a knock-driven identity ask (final review H-1), unless
//!   the knock declared that the contact holds no session with us; then,
//!   while we still hold a pair secret with it, blind asks run beside the
//!   identity ask (final re-review N-1), so a withheld flagged knock
//!   delivered after a blind re-pair cannot keep the pair apart.
//! - **Blind path** (`CircuitAskBlind`) otherwise: for every known contact
//!   on every reconnect, and for every re-ask after the pair's circuit
//!   went (`CircuitClosed`, `CircuitNotFound`). A blinded circuit is never
//!   resumed by id.
//!
//! Token epoch: the session's `pair_epoch`, or `(today, 0)` once the UTC
//! day moved past it. Timeouts (an ask held `ASK_TTL` on one connection
//! without a match) never count toward anything but the 24 h clock:
//! - an own-day ask sent within 600 s of a day boundary is retried once
//!   under the neighbouring day's token: `(d', 0)` for the next day, the
//!   stored `(d, c)` for the previous one (M-1, symmetric for both sides);
//! - otherwise an own ask that times out is followed by a **±1 window**:
//!   blind asks on `c` and `c + 1` held together for one TTL (R20), which
//!   heals a pair one counter apart without the identity path; a window
//!   that times out is followed by a plain own ask, and so on.
//!
//! Slots (R40-M3): every token also carries the 10-minute slot
//! `floor(unix / 600)` of the asker's clock (`pairing::pair_slot`). A plan's
//! asks go under the current slot. When the slot rolls over while they
//! wait, each of the plan's token epochs is asked again under the new slot
//! (a rollover ask) while the asks under the previous slot stay held until
//! their TTL, which equals the slot length. So a peer asking now and one
//! that asked before the boundary both meet us, and at most four blind asks
//! per peer are held at once (the window's two epochs under the current
//! and the previous slot; two for an own or neighbour plan). A rollover ask
//! never times the plan out: the plan's own asks do, and rollover asks
//! still held then are retired with them. Clock skew never stops a match:
//! the relay refuses a client more than 300 s off its clock, so connected
//! clients are less than a slot apart and share one while both ask. A new
//! ask past four held for a peer retires the oldest (final re-review N-2).
//!
//! A match (`CircuitCreatedV3` echoing a blind ask) sets the epoch to the
//! matched one advanced (`PairEpoch::advance(today)`), on both sides, when
//! it arrives: the token is spent whether or not the session-init comes.
//! The window sibling still held at the relay is remembered by its public
//! EK and epoch for one TTL: a later match on it (the peer met our stale
//! ask) fails the echo check as before, and also moves our epoch where the
//! peer's went, so the re-ask that follows meets. `PairTokenBusy` (the
//! token is spent) advances the counter past the ask's and re-asks at once;
//! past `BLIND_BUSY_CAP` on one connection blind asks to that peer pause
//! until the next reconnect (never the identity path).

use crate::pairing::{self, PairEpoch};
use crate::peers::{AskKeys, ASK_TTL};
use crate::protocol::{ControlMessage, BLIND_PAD_LEN};
use crate::{ClientInner, RChatError};
use std::time::Instant;

/// `PairTokenBusy`-driven counter advances per peer per connection
/// (ruling R16): a relay answering busy forever cannot spin the client.
/// Past it blind asks to the peer pause until the next reconnect (R20).
pub const BLIND_BUSY_CAP: u32 = 3;

/// Most blind asks held for one peer at once (§C.1: the window's two
/// epochs under the current and the previous slot). A new ask past it
/// retires the oldest (final re-review N-2).
pub const MAX_HELD_BLIND_ASKS: usize = 4;

/// Unmatched blind asking for this long (wall clock since the first
/// unmatched blind ask after the last install) makes the identity fallback
/// due (R20, §C.4).
pub const IDENTITY_FALLBACK_AFTER_SECS: u64 = 24 * 3600;

/// At most one identity fallback ask per pair in this long (R20): a relay
/// can force at most one target-naming ask per pair per day.
pub const IDENTITY_FALLBACK_INTERVAL_SECS: u64 = 24 * 3600;

/// Where a session's secret came from. Carried explicitly from the ask the
/// relay matched to the install (R14): never inferred from side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOrigin {
    /// An identity ask (first contact, fallback): a new pair secret is
    /// derived from SK and the epoch starts at `(today, 0)`.
    Identity,
    /// A blind ask matched on the pair token: the pair secret is kept, the
    /// epoch was advanced at the match, and none of the §18 recovery
    /// warnings is raised for the replaced ratchet.
    Blind,
}

/// Which token a blind ask carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlindKind {
    /// The session's own token epoch.
    Own,
    /// The neighbouring day's token (one retry near midnight).
    Neighbour,
    /// `own + 1`, held with an own ask as the ±1 window (R20).
    Ahead,
}

/// One outstanding blind ask to a peer. No secret: the token itself is
/// not kept (it is re-derived), and nothing here is logged.
pub(crate) struct BlindAsk {
    pub ek_pub: [u8; 32],
    pub epoch: PairEpoch,
    pub kind: BlindKind,
    /// The neighbouring day's token epoch to retry under if this own-day
    /// ask times out (sent within 600 s of a day boundary), else None.
    pub neighbour: Option<PairEpoch>,
    pub sent_at: Instant,
    /// Transport epoch it was sent on: only an ask held for its whole TTL
    /// on one connection can time out.
    pub transport_epoch: u64,
    /// The token's 10-minute slot (`pairing::pair_slot`, R40-M3).
    pub slot: u32,
    /// Sent because the slot rolled over while the plan's asks waited: it
    /// keeps the plan meetable under the new slot, but never times the
    /// plan out (the plan's own asks do).
    pub rollover: bool,
}

/// A blind ask of ours wiped locally while the relay may still hold it (a
/// window sibling when its pair matched): its public EK and token epoch,
/// for one TTL. No secret.
pub(crate) struct SpentAsk {
    pub peer: String,
    pub epoch: PairEpoch,
    pub sent_at: Instant,
    /// `ChatSession::pair_lineage` of the session it was asked under
    /// (final review L1): a stray match syncs only that lineage's epoch.
    pub lineage: Option<[u8; 32]>,
}

/// A pinned contact's knock put the peer on the identity path (§C.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentityWanted {
    /// The knock declared that the contact holds no session with us (R35):
    /// it cannot ask blind, so the pair stays on the identity path until
    /// an install, however long its asks go unmatched.
    pub no_prior_session: bool,
    /// The first identity ask this caused on a connection: sent at, on
    /// transport epoch (final review H-1). None until one is sent.
    pub asked: Option<(Instant, u64)>,
}

/// Asks a connection may send at once (the reconnect burst), then at most
/// `ASK_PACE_PER_SEC` (final review, RateLimited): a user with many
/// contacts spreads the re-pair asks of a reconnect, and the asks of a
/// slot rollover, instead of running into the relay's per-connection cap.
pub const ASK_BURST: u32 = 32;
/// Refill rate of the ask pacer, asks per second.
pub const ASK_PACE_PER_SEC: f64 = 8.0;
/// First wait before an ask the relay refused (`RateLimited`) is asked
/// again; it doubles with each further refusal (counted until a quiet
/// `ASK_TTL`) up to `ASK_REFUSED_MAX`, so a refused ask goes again long
/// before the 600 s it would otherwise wait as "held".
pub const ASK_REFUSED_BASE: std::time::Duration = std::time::Duration::from_secs(10);
/// Longest wait before a refused ask is asked again.
pub const ASK_REFUSED_MAX: std::time::Duration = std::time::Duration::from_secs(320);
/// A `RateLimited` answer is blamed on our latest ask sent at most this
/// long before it (the relay answers an ask at once).
const ASK_REFUSAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
/// Asks remembered per connection for blaming a refusal on.
const RECENT_ASKS_KEPT: usize = 64;

/// A token bucket for the asks a connection sends (no secret).
pub(crate) struct AskPacer {
    tokens: f64,
    last: Option<Instant>,
    burst: u32,
    per_sec: f64,
}

impl Default for AskPacer {
    fn default() -> Self {
        AskPacer {
            tokens: f64::from(ASK_BURST),
            last: None,
            burst: ASK_BURST,
            per_sec: ASK_PACE_PER_SEC,
        }
    }
}

impl AskPacer {
    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let dt = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + dt * self.per_sec).min(f64::from(self.burst));
        }
        if self.last.map_or(true, |l| now > l) {
            self.last = Some(now);
        }
    }

    /// Take one ask's worth now, if there is one.
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// When the next ask's worth is there.
    pub(crate) fn next_at(&self, now: Instant) -> Instant {
        let missing = (1.0 - self.tokens).max(0.0);
        now + std::time::Duration::from_secs_f64(missing / self.per_sec.max(0.001))
    }

    /// A new connection starts with a full burst.
    pub(crate) fn reset(&mut self) {
        self.tokens = f64::from(self.burst);
        self.last = None;
    }

    #[cfg(test)]
    pub(crate) fn set_for_test(&mut self, burst: u32, per_sec: f64) {
        self.burst = burst;
        self.per_sec = per_sec;
        self.tokens = f64::from(burst);
        self.last = None;
    }
}

/// One ask we sent on a connection, kept to blame a `RateLimited` answer
/// on (public EK only, no secret).
pub(crate) struct RecentAsk {
    pub peer: String,
    pub ek_pub: [u8; 32],
    pub sent_at: Instant,
    pub transport_epoch: u64,
    pub blind: bool,
}

/// How one blind ask is sent: its kind, the neighbour day to retry under
/// (own asks near midnight), its slot, and whether it is a rollover ask.
#[derive(Debug, Clone, Copy)]
struct BlindAskSpec {
    kind: BlindKind,
    neighbour: Option<PairEpoch>,
    slot: u32,
    rollover: bool,
}

/// What the next blind ask to a peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlindPlan {
    Own,
    Neighbour(PairEpoch),
    Window,
}

/// The token epoch to ask under on `today`: the stored one, or `(today, 0)`
/// once the day moved past it (§C.1 "resets to 0 when the day changes").
pub(crate) fn ask_epoch(stored: PairEpoch, today: u32) -> PairEpoch {
    if today > stored.day {
        PairEpoch {
            day: today,
            counter: 0,
        }
    } else {
        stored
    }
}

/// `a` is later than `b` in (day, counter) order.
fn later(a: PairEpoch, b: PairEpoch) -> bool {
    (a.day, a.counter) > (b.day, b.counter)
}

impl ClientInner {
    /// Unix time for the pair epoch and the fallback clock (tests pin it).
    pub(crate) fn pair_now_unix(&self) -> u64 {
        self.pair_clock_override.unwrap_or_else(|| {
            crate::unix_now_secs().saturating_add_signed(self.pair_clock_offset_secs)
        })
    }

    /// How long a blind (or identity fallback) ask is held before it times
    /// out: `ASK_TTL`, or the end-to-end test override (`test-hooks`).
    fn blind_ttl(&self) -> std::time::Duration {
        self.blind_ask_ttl_override.unwrap_or(ASK_TTL)
    }

    /// The peer is asked on the blind path (see the module docs).
    pub(crate) fn blind_path(&self, peer_hex: &str) -> bool {
        if self.rotation_unreached.contains(peer_hex)
            || self.identity_wanted.contains_key(peer_hex)
            || self.identity_fallback.contains_key(peer_hex)
        {
            return false;
        }
        // A pair from an identity ask waiting for its session-init resumes
        // that identity circuit (v2): the peer may hold no PS for it yet.
        if self
            .pending_inits
            .get(peer_hex)
            .is_some_and(|p| p.origin == InstallOrigin::Identity)
        {
            return false;
        }
        self.blind_capable_session(peer_hex)
    }

    /// We hold an established session with a pair secret with the peer.
    /// An identity session we initiated is blind-capable at once, even
    /// before the peer answers its session-init: the init went to the peer
    /// on the pair's circuit (or its offline queue), so the peer normally
    /// installs it and holds the same PS. Waiting for the answer instead
    /// let a quick reconnect after first contact split the pair (one side
    /// blind, the other on the identity path) into a needless identity
    /// re-pair and a false `SessionReplaced`.
    fn blind_capable_session(&self, peer_hex: &str) -> bool {
        self.session_manager
            .get(peer_hex)
            .is_some_and(|s| s.ratchet.is_some() && s.is_established && s.pair_secret.is_some())
    }

    /// Final re-review N-1: a flagged knock (`no_prior_session`) holds the
    /// pair on the identity path until an install, but while we still hold
    /// a pair secret with the peer, blind asks run beside the identity ask.
    /// The knock may be one the relay withheld and delivered after a blind
    /// re-pair (the peer holds the PS again and asks blind); asking only by
    /// identity would then keep the pair apart until the peer's own daily
    /// fallback. A peer that really has no PS never meets the blind asks,
    /// and its identity ask still meets ours.
    pub(crate) fn blind_alongside(&self, peer_hex: &str) -> bool {
        self.identity_wanted
            .get(peer_hex)
            .is_some_and(|w| w.no_prior_session)
            && !self.rotation_unreached.contains(peer_hex)
            && !self.identity_fallback.contains_key(peer_hex)
            && !self
                .pending_inits
                .get(peer_hex)
                .is_some_and(|p| p.origin == InstallOrigin::Identity)
            && self.blind_capable_session(peer_hex)
    }

    /// The peer is asked blind beside its identity ask (`blind_alongside`)
    /// and no blind ask to it is held on this connection yet.
    pub(crate) fn blind_alongside_due(&self, peer_hex: &str) -> bool {
        let epoch = self.transport_epoch;
        self.blind_alongside(peer_hex)
            && !self
                .blind_asks
                .get(peer_hex)
                .is_some_and(|v| v.iter().any(|a| a.transport_epoch == epoch))
    }

    /// A responder wait for a session-init that can still be answered on
    /// its circuit: not a blind pair's wait from an earlier connection
    /// (that circuit is never resumed; the pair re-asks blind instead).
    pub(crate) fn awaiting_live_init(&self, peer_hex: &str) -> bool {
        self.pending_inits.get(peer_hex).is_some_and(|p| {
            p.origin != InstallOrigin::Blind || p.circuit_epoch >= self.transport_epoch
        })
    }

    /// R21: an established pair is re-pairing blind on this connection
    /// (an ask of ours is out, no live circuit yet). Sends to the peer wait
    /// on the session's queue meanwhile and move to the new session at its
    /// install, instead of failing after the send wait.
    pub(crate) fn blind_repair_in_flight(&self, peer_hex: &str) -> bool {
        let epoch = self.transport_epoch;
        !self.has_live_circuit(peer_hex)
            && self
                .session_manager
                .get(peer_hex)
                .is_some_and(|s| s.is_established && s.ratchet.is_some())
            && self
                .blind_asks
                .get(peer_hex)
                .is_some_and(|v| v.iter().any(|a| a.transport_epoch == epoch))
    }

    /// Send the blind ask(s) of `plan` to the peer: nothing while blind
    /// asks to it are paused (busy past the cap, R20).
    pub(crate) fn send_blind_plan(
        &mut self,
        peer_hex: &str,
        now: Instant,
        plan: BlindPlan,
    ) -> Result<(), RChatError> {
        if self.in_drain() {
            // Never from a background drain (§H.1).
            return Err(RChatError::NotConnected);
        }
        if self.blind_paused.contains(peer_hex) {
            return Ok(());
        }
        let now_unix = self.pair_now_unix();
        let today = pairing::utc_day(now_unix);
        let stored = self
            .session_manager
            .get(peer_hex)
            .map(|s| s.pair_epoch)
            .ok_or_else(|| RChatError::SessionNotEstablished {
                identity: peer_hex.to_string(),
            })?;
        let own = ask_epoch(stored, today);
        // R40-M3: every ask of a plan is under the current slot; the
        // previous slot's stays held from before a rollover
        // (`fire_blind_timeouts`), so no ask under it is sent here.
        let slot = pairing::pair_slot(now_unix);
        let one = |kind, neighbour| BlindAskSpec {
            kind,
            neighbour,
            slot,
            rollover: false,
        };
        match plan {
            BlindPlan::Neighbour(e) => {
                self.blind_neighbour_tried.insert(peer_hex.to_string(), e);
                self.send_one_blind(peer_hex, now, e, one(BlindKind::Neighbour, None))
            }
            BlindPlan::Own => {
                // M-1: the neighbour day's token as the side on that day
                // holds it: the stored epoch when it is that day (the side
                // still on it asks exactly that), else that day's counter 0
                // (the side that moved on to it reset there).
                let tried = self.blind_neighbour_tried.get(peer_hex).copied();
                let nb = pairing::near_day_boundary(now_unix)
                    .then(|| {
                        let d = pairing::neighbour_day(now_unix);
                        if d == stored.day {
                            stored
                        } else {
                            PairEpoch { day: d, counter: 0 }
                        }
                    })
                    .filter(|e| *e != own && Some(*e) != tried);
                self.send_one_blind(peer_hex, now, own, one(BlindKind::Own, nb))
            }
            BlindPlan::Window => {
                let ahead = PairEpoch {
                    day: own.day,
                    counter: own.counter.saturating_add(1),
                };
                self.send_one_blind(peer_hex, now, own, one(BlindKind::Own, None))?;
                self.send_one_blind(peer_hex, now, ahead, one(BlindKind::Ahead, None))
            }
        }
    }

    /// Build and send one `CircuitAskBlind` (§C.2): fresh ephemerals into
    /// the ask ring (tagged with the token epoch, so the match knows its
    /// origin), the identity signature over them (R7), the token, and an
    /// all-zero pad. No target, no knock.
    fn send_one_blind(
        &mut self,
        peer_hex: &str,
        now: Instant,
        epoch: PairEpoch,
        spec: BlindAskSpec,
    ) -> Result<(), RChatError> {
        let BlindAskSpec {
            kind,
            neighbour,
            slot,
            rollover,
        } = spec;
        let ps = self
            .session_manager
            .get(peer_hex)
            .and_then(|s| s.pair_secret.clone())
            .ok_or_else(|| RChatError::SessionNotEstablished {
                identity: peer_hex.to_string(),
            })?;
        let token = zeroize::Zeroizing::new(pairing::pair_token(&ps, epoch, slot));
        drop(ps);
        let identity = self.identity.as_ref().ok_or(RChatError::NotConnected)?;
        let mut keys = AskKeys::generate();
        keys.blind = Some(epoch);
        let ek_pub = keys.ek.public_key().to_bytes();
        let ephemeral_sig =
            crate::keyauth::sign_ask_ephemerals(identity, &ek_pub, keys.kem.public());
        self.send_control_now(ControlMessage::CircuitAskBlind {
            pair_token: token.to_vec(),
            ephemeral_key: ek_pub.to_vec(),
            kem_ephemeral_pk: keys.kem.public().to_vec(),
            ephemeral_sig: ephemeral_sig.to_vec(),
            pad: vec![0; BLIND_PAD_LEN],
        })?;
        // Retire down to one below the cap first, so the ask ring (cap
        // `MAX_HELD_BLIND_ASKS + 1`) never overflows onto an identity ask's
        // keys (final review P-1).
        self.retire_blind_asks_past_cap(peer_hex, MAX_HELD_BLIND_ASKS - 1);
        self.peers.push_ask(peer_hex, keys, now);
        self.note_recent_ask(peer_hex, ek_pub, now, true);
        self.unanswered_asks
            .insert(peer_hex.to_string(), (now, self.transport_epoch));
        self.blind_asks
            .entry(peer_hex.to_string())
            .or_default()
            .push(BlindAsk {
                ek_pub,
                epoch,
                kind,
                neighbour,
                sent_at: now,
                transport_epoch: self.transport_epoch,
                slot,
                rollover,
            });
        // The 24 h fallback clock starts at the first unmatched blind ask
        // since the last install (R20); persisted, best effort.
        let now_unix = self.pair_now_unix();
        let started = self.session_manager.get_mut(peer_hex).is_some_and(|mut s| {
            let fresh = s.blind_since_unix.is_none();
            if fresh {
                s.blind_since_unix = Some(now_unix);
            }
            fresh
        });
        if started {
            let _ = self.persist_peer(peer_hex);
        }
        self.persist_meta();
        Ok(())
    }

    /// The identity fallback is due for the peer (R20): unmatched blind
    /// asking for `IDENTITY_FALLBACK_AFTER_SECS`, and no fallback ask in the
    /// last `IDENTITY_FALLBACK_INTERVAL_SECS`.
    fn identity_fallback_due(&self, peer_hex: &str, now_unix: u64) -> bool {
        self.session_manager.get(peer_hex).is_some_and(|s| {
            s.blind_since_unix
                .is_some_and(|t| now_unix.saturating_sub(t) >= IDENTITY_FALLBACK_AFTER_SECS)
                && s.last_identity_fallback_unix.map_or(true, |t| {
                    now_unix.saturating_sub(t) >= IDENTITY_FALLBACK_INTERVAL_SECS
                })
        })
    }

    /// Asks held for `ASK_TTL` on this connection without a match (tick).
    /// See the module docs for what follows each; an identity fallback ask
    /// that runs out sends the pair back to blind with its clock restarted.
    pub(crate) fn fire_blind_timeouts(&mut self, now: Instant) {
        let ttl = self.blind_ttl();
        self.spent_blind_asks
            .retain(|_, s| now.saturating_duration_since(s.sent_at) < ttl);
        if !self.is_key_bundle_published {
            return;
        }
        let epoch = self.transport_epoch;
        let now_unix = self.pair_now_unix();
        let ran_out: Vec<String> = self
            .identity_fallback
            .iter()
            .filter(|(_, (at, ep))| *ep == epoch && now.saturating_duration_since(*at) >= ttl)
            .map(|(p, _)| p.clone())
            .collect();
        for peer in ran_out {
            self.identity_fallback.remove(&peer);
            if let Some(mut s) = self.session_manager.get_mut(&peer) {
                s.blind_since_unix = Some(now_unix);
            }
            let _ = self.persist_peer(&peer);
            log::debug!("[RUST] identity fallback ask ran out; back to blind");
            self.reask_now(&peer, now);
        }
        // Final review H-1: an identity ask a pinned contact's knock caused
        // runs out the same way. The contact may have gone back to blind
        // meanwhile (its own identity ask ran out, or a reconnect), or never
        // answer ours (its budget spent): staying on the identity path would
        // leave the pair without a circuit for up to a day.
        let knock_ran_out: Vec<String> = self
            .identity_wanted
            .iter()
            .filter(|(_, w)| {
                !w.no_prior_session
                    && w.asked.is_some_and(|(at, ep)| {
                        ep == epoch && now.saturating_duration_since(at) >= ttl
                    })
            })
            .map(|(p, _)| p.clone())
            .collect();
        for peer in knock_ran_out {
            if self.has_live_circuit(&peer) || self.pending_inits.contains_key(&peer) {
                continue; // it matched; the install clears it
            }
            self.identity_wanted.remove(&peer);
            if let Some(mut s) = self.session_manager.get_mut(&peer) {
                s.blind_since_unix = Some(now_unix);
            }
            let _ = self.persist_peer(&peer);
            log::debug!("[RUST] knock-driven identity ask ran out; back to blind");
            self.reask_now(&peer, now);
        }
        let expired: Vec<String> = self
            .blind_asks
            .iter()
            .filter(|(_, v)| {
                v.iter().any(|a| {
                    a.transport_epoch == epoch && now.saturating_duration_since(a.sent_at) >= ttl
                })
            })
            .map(|(p, _)| p.clone())
            .collect();
        for peer in expired {
            let Some(asks) = self.blind_asks.remove(&peer) else {
                continue;
            };
            let (gone, alive): (Vec<BlindAsk>, Vec<BlindAsk>) = asks.into_iter().partition(|a| {
                a.transport_epoch == epoch && now.saturating_duration_since(a.sent_at) >= ttl
            });
            for a in &gone {
                // Its ephemerals can no longer be echoed: wiped now.
                drop(self.peers.take_ask(&peer, &a.ek_pub, a.sent_at));
            }
            // The plan times out with its own asks (R40-M3): a rollover ask
            // alone never does, and one still held when the plan's asks run
            // out is retired (the next plan's ask under the same token
            // replaces it at the relay; a match on it still syncs).
            if alive.iter().any(|a| !a.rollover) || gone.iter().all(|a| a.rollover) {
                if !alive.is_empty() {
                    self.blind_asks.insert(peer, alive);
                }
                continue;
            }
            self.blind_asks.insert(peer.clone(), alive);
            self.retire_blind_asks(&peer, None);
            let gone: Vec<BlindAsk> = gone.into_iter().filter(|a| !a.rollover).collect();
            self.clear_unanswered(&peer);
            if self.require_askable(&peer).is_err()
                || self.has_live_circuit(&peer)
                || self.awaiting_live_init(&peer)
                || self.blind_paused.contains(&peer)
            {
                continue;
            }
            let neighbour = gone
                .iter()
                .find(|a| a.kind == BlindKind::Own)
                .and_then(|a| a.neighbour);
            let was_window = gone.iter().any(|a| a.kind == BlindKind::Ahead);
            // The peer left the blind path while these asks were out (a
            // pinned contact's fresh knock, §C.4): its re-ask is an identity
            // ask now. Asking blind here would also drop the identity
            // re-ask the knock scheduled, and keep the pair blind.
            // A flagged knock's pair that we still hold a PS with keeps its
            // blind plan beside the identity ask (N-1).
            if !self.blind_path(&peer) && !self.blind_alongside(&peer) {
                self.reask_now(&peer, now);
                continue;
            }
            self.pending_reasks.remove(&peer);
            if let (Some(e), false) = (neighbour, was_window) {
                if self
                    .send_blind_plan(&peer, now, BlindPlan::Neighbour(e))
                    .is_err()
                {
                    log::debug!("[RUST] neighbour-day blind ask not sent");
                }
                continue;
            }
            if self.identity_fallback_due(&peer, now_unix) {
                if let Some(mut s) = self.session_manager.get_mut(&peer) {
                    s.last_identity_fallback_unix = Some(now_unix);
                }
                let _ = self.persist_peer(&peer);
                self.identity_fallback.insert(peer.clone(), (now, epoch));
                log::debug!("[RUST] blind asks unmatched for a day; one identity ask");
                self.reask_now(&peer, now);
                continue;
            }
            let plan = if was_window {
                BlindPlan::Own
            } else {
                BlindPlan::Window
            };
            if self.send_blind_plan(&peer, now, plan).is_err() {
                log::debug!("[RUST] re-ask after a blind timeout not sent; deferred");
                if !self.deferred_asks.contains(&peer) {
                    self.deferred_asks.push(peer);
                }
            }
        }
        self.fire_slot_rollovers(now, now_unix);
    }

    /// R40-M3: the 10-minute slot rolled over while a plan's asks wait
    /// unmatched. The plan's token epochs are asked again under the new
    /// slot (rollover asks), while the asks under the previous slot stay
    /// held until their TTL: a contact asking now (under the new slot) and
    /// one that asked before the boundary both meet us. An older rollover
    /// ask (two slots back, after a suspended clock) is retired first.
    /// Never from a background drain, never for a paused or paired peer.
    fn fire_slot_rollovers(&mut self, now: Instant, now_unix: u64) {
        if self.in_drain() {
            return;
        }
        let epoch = self.transport_epoch;
        let slot = pairing::pair_slot(now_unix);
        let rolled: Vec<String> = self
            .blind_asks
            .iter()
            .filter(|(_, v)| {
                v.iter().any(|a| !a.rollover && a.transport_epoch == epoch)
                    && v.iter().all(|a| a.slot < slot)
            })
            .map(|(p, _)| p.clone())
            .collect();
        for peer in rolled {
            if self.blind_paused.contains(&peer) || self.has_live_circuit(&peer) {
                continue;
            }
            // Paced: the rest roll over on a later tick (their asks under
            // the previous slot are still held meanwhile).
            if !self.ask_pacer.take(now) {
                break;
            }
            let Some(asks) = self.blind_asks.get_mut(&peer) else {
                continue;
            };
            let (old_rollovers, plan): (Vec<BlindAsk>, Vec<BlindAsk>) =
                std::mem::take(asks).into_iter().partition(|a| a.rollover);
            let mut again: Vec<(PairEpoch, BlindKind)> = Vec::new();
            for a in &plan {
                if !again.contains(&(a.epoch, a.kind)) {
                    again.push((a.epoch, a.kind));
                }
            }
            *asks = plan;
            let lineage = self.peer_lineage(&peer);
            for a in old_rollovers {
                drop(self.peers.take_ask(&peer, &a.ek_pub, a.sent_at));
                self.spent_blind_asks.insert(
                    a.ek_pub,
                    SpentAsk {
                        peer: peer.clone(),
                        epoch: a.epoch,
                        sent_at: a.sent_at,
                        lineage,
                    },
                );
            }
            for (e, kind) in again {
                let spec = BlindAskSpec {
                    kind,
                    neighbour: None,
                    slot,
                    rollover: true,
                };
                if self.send_one_blind(&peer, now, e, spec).is_err() {
                    log::debug!("[RUST] rollover blind ask not sent");
                    break;
                }
            }
        }
    }

    /// Ask the peer now (blind or identity, as `send_ask` decides); kept
    /// for the next accepted publish if it cannot be sent.
    fn reask_now(&mut self, peer: &str, now: Instant) {
        if self.require_askable(peer).is_err()
            || self.has_live_circuit(peer)
            || self.awaiting_live_init(peer)
        {
            return;
        }
        self.pending_reasks.remove(peer);
        if self.send_ask(peer, now).is_err() && !self.deferred_asks.iter().any(|p| p == peer) {
            self.deferred_asks.push(peer.to_string());
        }
    }

    /// Final re-review N-2: at most `MAX_HELD_BLIND_ASKS` held blind asks
    /// per peer. Past it the oldest are retired: their ephemeral secrets
    /// wiped (taken out of the ask ring and dropped), and each remembered as
    /// spent for one TTL, since the relay may still hold it.
    fn retire_blind_asks_past_cap(&mut self, peer_hex: &str, keep: usize) {
        let Some(asks) = self.blind_asks.get_mut(peer_hex) else {
            return;
        };
        if asks.len() <= keep {
            return;
        }
        asks.sort_by_key(|a| a.sent_at);
        let excess = asks.len() - keep;
        let old: Vec<BlindAsk> = asks.drain(..excess).collect();
        let lineage = self.peer_lineage(peer_hex);
        for a in old {
            drop(self.peers.take_ask(peer_hex, &a.ek_pub, a.sent_at));
            self.spent_blind_asks.insert(
                a.ek_pub,
                SpentAsk {
                    peer: peer_hex.to_string(),
                    epoch: a.epoch,
                    sent_at: a.sent_at,
                    lineage,
                },
            );
        }
        log::debug!("[RUST] blind asks past the per-peer cap retired");
    }

    /// Forget the peer's outstanding blind asks; those the relay may still
    /// hold are remembered as spent (public EK and epoch) for one TTL.
    fn retire_blind_asks(&mut self, peer_hex: &str, keep_none_but: Option<&[u8; 32]>) {
        let Some(asks) = self.blind_asks.remove(peer_hex) else {
            return;
        };
        let lineage = self.peer_lineage(peer_hex);
        for a in asks {
            if keep_none_but.is_some_and(|ek| *ek == a.ek_pub) {
                continue;
            }
            drop(self.peers.take_ask(peer_hex, &a.ek_pub, a.sent_at));
            self.spent_blind_asks.insert(
                a.ek_pub,
                SpentAsk {
                    peer: peer_hex.to_string(),
                    epoch: a.epoch,
                    sent_at: a.sent_at,
                    lineage,
                },
            );
        }
    }

    /// `PairTokenBusy` (rulings R16, R22): the token of our blind ask whose
    /// X25519 ephemeral is `ek` is spent. The counter moves past the ask's
    /// and the peer is re-asked at once. Past `BLIND_BUSY_CAP` advances on
    /// this connection, blind asks to the peer pause until the next
    /// reconnect (R20: never the identity path). A busy naming no ask of
    /// ours is ignored.
    pub(crate) fn handle_pair_token_busy(&mut self, ek: &[u8], now: Instant) {
        let Ok(ek) = <[u8; 32]>::try_from(ek) else {
            return;
        };
        let epoch = self.transport_epoch;
        let found = self.blind_asks.iter().find_map(|(p, v)| {
            v.iter()
                .find(|a| {
                    a.transport_epoch == epoch && constant_time_eq::constant_time_eq(&a.ek_pub, &ek)
                })
                .map(|a| (p.clone(), a.epoch, a.sent_at))
        });
        let Some((peer, ask_epoch_used, sent_at)) = found else {
            return;
        };
        if let Some(v) = self.blind_asks.get_mut(&peer) {
            v.retain(|a| a.ek_pub != ek);
        }
        drop(self.peers.take_ask(&peer, &ek, sent_at));
        // Any sibling still held is retired too: one fresh ask follows.
        self.retire_blind_asks(&peer, None);
        self.clear_unanswered(&peer);
        let busy = self.blind_busy.entry(peer.clone()).or_insert(0);
        *busy = busy.saturating_add(1);
        if *busy > BLIND_BUSY_CAP {
            self.blind_paused.insert(peer);
            log::debug!("[RUST] pair token busy past the cap; blind asks paused");
            return;
        }
        let next = PairEpoch {
            day: ask_epoch_used.day,
            counter: ask_epoch_used.counter.saturating_add(1),
        };
        if let Some(mut s) = self.session_manager.get_mut(&peer) {
            if later(next, s.pair_epoch) {
                s.pair_epoch = next;
            }
        }
        let _ = self.persist_peer(&peer);
        self.reask_now(&peer, now);
    }

    /// The current session's pair-secret lineage with the peer, if any.
    fn peer_lineage(&self, peer_hex: &str) -> Option<[u8; 32]> {
        self.session_manager
            .get(peer_hex)
            .and_then(|s| s.pair_lineage())
    }

    /// Remember an ask we just sent on this connection (for `RateLimited`).
    pub(crate) fn note_recent_ask(
        &mut self,
        peer_hex: &str,
        ek_pub: [u8; 32],
        now: Instant,
        blind: bool,
    ) {
        if self.recent_asks.len() >= RECENT_ASKS_KEPT {
            self.recent_asks.pop_front();
        }
        self.recent_asks.push_back(RecentAsk {
            peer: peer_hex.to_string(),
            ek_pub,
            sent_at: now,
            transport_epoch: self.transport_epoch,
            blind,
        });
    }

    /// The relay refused an ask over one of its caps (`RateLimited`; it
    /// names no ask). Over a cap every later ask is refused too, so the
    /// refusal is blamed on our latest ask on this connection not yet
    /// blamed (sent within `ASK_REFUSAL_WINDOW`): it is forgotten as held
    /// (a blind ask is retired, so a match on it if it was held after all
    /// still syncs the epoch) and the peer is asked again after a backoff
    /// (`ASK_REFUSED_BASE`, doubling to `ASK_REFUSED_MAX`), not after the
    /// 600 s TTL. A refusal with no recent ask to blame changes nothing.
    pub(crate) fn handle_ask_rate_limited(&mut self, now: Instant) {
        let epoch = self.transport_epoch;
        loop {
            let Some(pos) = self.recent_asks.iter().rposition(|r| {
                r.transport_epoch == epoch
                    && now.saturating_duration_since(r.sent_at) < ASK_REFUSAL_WINDOW
            }) else {
                return;
            };
            let Some(r) = self.recent_asks.remove(pos) else {
                return;
            };
            let outstanding = if r.blind {
                self.blind_asks
                    .get(&r.peer)
                    .is_some_and(|v| v.iter().any(|a| a.ek_pub == r.ek_pub))
            } else {
                self.peers.take_ask(&r.peer, &r.ek_pub, r.sent_at).is_some()
            };
            if !outstanding {
                // Matched or gone already: not the refused one.
                continue;
            }
            if r.blind {
                self.retire_blind_asks(&r.peer, None);
            }
            self.clear_unanswered(&r.peer);
            let (count, last) = &mut self.ask_refusals;
            if last.map_or(true, |l| now.saturating_duration_since(l) >= ASK_TTL) {
                *count = 0;
            }
            *count = count.saturating_add(1);
            *last = Some(now);
            let doublings = (*count - 1).min(16);
            let wait = ASK_REFUSED_BASE
                .saturating_mul(1u32 << doublings)
                .min(ASK_REFUSED_MAX)
                .mul_f64(1.0 + self.jitter());
            if self.require_askable(&r.peer).is_ok() && !self.has_live_circuit(&r.peer) {
                self.pending_reasks.insert(r.peer, now + wait);
            }
            log::debug!("[RUST] ask refused over a relay cap; asked again after a backoff");
            return;
        }
    }

    /// The peer's session went (unpin, block, re-pin): its blind-ask state
    /// goes too. Its ask keys go with the peer book's ring.
    pub(crate) fn forget_blind_state(&mut self, peer_hex: &str) {
        self.blind_asks.remove(peer_hex);
        self.blind_busy.remove(peer_hex);
        self.blind_paused.remove(peer_hex);
        self.blind_neighbour_tried.remove(peer_hex);
        self.identity_wanted.remove(peer_hex);
        self.identity_fallback.remove(peer_hex);
        self.spent_blind_asks.retain(|_, s| s.peer != peer_hex);
        self.seen_knocks.remove(peer_hex);
        self.knock_acted.remove(peer_hex);
    }

    /// A `CircuitCreatedV3` consumed our ask `my_ek` to `peer_hex`. For a
    /// blind ask (`blind`: its token epoch) the token is spent: the current
    /// session's epoch becomes the matched one advanced (§C.1, R14; both
    /// sides do this at their match). Any match ends this connection's busy
    /// count and pause, and retires the peer's other outstanding asks. The
    /// 24 h fallback state resets only at a verified install (M-3).
    pub(crate) fn note_pair_match(
        &mut self,
        peer_hex: &str,
        my_ek: &[u8; 32],
        blind: Option<PairEpoch>,
    ) {
        self.retire_blind_asks(peer_hex, Some(my_ek));
        self.blind_busy.remove(peer_hex);
        self.blind_paused.remove(peer_hex);
        self.blind_neighbour_tried.remove(peer_hex);
        let Some(matched) = blind else {
            return;
        };
        let today = pairing::utc_day(self.pair_now_unix());
        if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
            let mut e = matched;
            e.advance(today);
            // L2: never back (a match on an older token than the stored
            // epoch, e.g. after a busy advance, keeps the later one).
            if later(e, s.pair_epoch) {
                s.pair_epoch = e;
            }
        }
        // Best effort: a restart before the install still asks under the
        // next token.
        let _ = self.persist_peer(peer_hex);
    }

    /// A `CircuitCreatedV3` whose echoed EK (`mine`) is none of our live
    /// asks: if it is a blind ask we retired while the relay still held it,
    /// the peer met it and advanced past its epoch, so ours goes there too
    /// and the re-ask that follows the close meets the peer's.
    pub(crate) fn adopt_stray_blind_match(&mut self, peer_hex: &str, mine: &[u8; 32]) {
        let Some(spent) = self.spent_blind_asks.remove(mine) else {
            return;
        };
        // L1: only an ask of this peer under the current pair secret: one
        // from an earlier lineage (before an identity re-pair) names an
        // epoch of tokens nobody asks any more.
        let current = self.peer_lineage(peer_hex);
        if spent.peer != peer_hex || spent.lineage.is_none() || spent.lineage != current {
            return;
        }
        let today = pairing::utc_day(self.pair_now_unix());
        let mut e = spent.epoch;
        e.advance(today);
        let moved = self.session_manager.get_mut(peer_hex).is_some_and(|mut s| {
            let later_epoch = later(e, s.pair_epoch);
            if later_epoch {
                s.pair_epoch = e;
            }
            later_epoch
        });
        if moved {
            let _ = self.persist_peer(peer_hex);
        }
    }
}
