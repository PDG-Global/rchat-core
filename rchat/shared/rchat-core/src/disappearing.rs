//! Disappearing messages (protocol v3 §I.2): the per-conversation timer,
//! its in-session control plaintext and the per-message `expire_secs`.
//!
//! Layouts (every integer big-endian):
//!
//! ```text
//! 0x01 ‖ expire_secs(u32) ‖ UTF-8 text                       text
//! 0x02 ‖ expire_secs(u32) ‖ magic ‖ body                     binary (image, voice)
//! 0x07 ‖ expire_secs(u32) ‖ name_len ‖ …                     file (file_msg.rs)
//! 0x09 ‖ timer_secs(u32) ‖ changed_at_ms(u64)                timer change
//! ```
//!
//! - `expire_secs` is the sender's timer when the message was first sent
//!   (0 = never). The receiver honours it, never its own setting.
//! - A timer change travels inside the ratchet like a message: padded and
//!   ack-tracked, 13 bytes, so it fits a steady slot. The receiver answers
//!   it with a delivered receipt (never shown to its app); it never reaches
//!   the app as a message. The core owns its delivery (ruling R32): the
//!   latest unacknowledged state of our own change is re-sent when a
//!   carrier is reported lost and after each new session install, and
//!   `timer_wins` makes duplicates harmless.
//! - Conflicts: the later `changed_at_ms` wins; on a tie, the change made
//!   by the lower identity-key hex wins (`timer_wins`).
//! - The core keeps each contact's timer in its peer record, so new sends
//!   carry it after a relaunch; resends carry the message's original value.

/// The ratchet plaintext type of a timer change.
pub const TIMER_TYPE: u8 = 0x09;
/// The timers a conversation can have: off, 5 minutes, 1 hour, 1 day,
/// 1 week, 4 weeks.
pub const TIMER_CHOICES_SECS: [u32; 6] = [0, 300, 3600, 86400, 604800, 2419200];
/// An unread message's countdown starts at the latest this long after it
/// was received (the app applies it; §I.2).
pub const UNREAD_BACKSTOP_SECS: u64 = 7 * 86400;
/// A timer change's plaintext length, type byte included.
pub const TIMER_PLAINTEXT_LEN: usize = 1 + 4 + 8;
/// Bytes of `expire_secs` after a message plaintext's type byte.
pub const EXPIRE_LEN: usize = 4;

/// Why a `0x09` plaintext was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// Not a `0x09` plaintext of exactly 13 bytes.
    Malformed,
    /// A timer value not in `TIMER_CHOICES_SECS`.
    UnknownValue,
}

/// One of `TIMER_CHOICES_SECS`.
pub fn valid_timer(secs: u32) -> bool {
    TIMER_CHOICES_SECS.contains(&secs)
}

/// The `0x09` plaintext of a timer change.
pub fn encode_timer(secs: u32, changed_at_ms: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(TIMER_PLAINTEXT_LEN);
    v.push(TIMER_TYPE);
    v.extend_from_slice(&secs.to_be_bytes());
    v.extend_from_slice(&changed_at_ms.to_be_bytes());
    v
}

/// Parse a `0x09` plaintext; refuses any other length and any value not
/// in `TIMER_CHOICES_SECS`.
pub fn decode_timer(pt: &[u8]) -> Result<(u32, u64), TimerError> {
    if pt.len() != TIMER_PLAINTEXT_LEN || pt[0] != TIMER_TYPE {
        return Err(TimerError::Malformed);
    }
    let secs = u32::from_be_bytes([pt[1], pt[2], pt[3], pt[4]]);
    let mut at = [0u8; 8];
    at.copy_from_slice(&pt[5..13]);
    if !valid_timer(secs) {
        return Err(TimerError::UnknownValue);
    }
    Ok((secs, u64::from_be_bytes(at)))
}

/// Whether change `a` (its `changed_at_ms` and the identity-key hex of
/// whoever made it) wins over change `b`: the later one wins; on a tie,
/// the lower identity-key hex wins. The same change never wins over itself.
pub fn timer_wins(a: (u64, &str), b: (u64, &str)) -> bool {
    if a.0 != b.0 {
        return a.0 > b.0;
    }
    a.1.to_ascii_lowercase() < b.1.to_ascii_lowercase()
}

/// `expire_secs ‖ body`: what follows a `0x01`/`0x02` type byte.
pub(crate) fn with_expire(expire_secs: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(EXPIRE_LEN + body.len());
    v.extend_from_slice(&expire_secs.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// A `0x01`/`0x02`/`0x07` plaintext's `expire_secs` and what follows it,
/// or `None` when it is too short to carry one.
pub fn split_expire(pt: &[u8]) -> Option<(u32, &[u8])> {
    let rest = pt.get(1..)?;
    if rest.len() < EXPIRE_LEN {
        return None;
    }
    let (e, body) = rest.split_at(EXPIRE_LEN);
    Some((u32::from_be_bytes([e[0], e[1], e[2], e[3]]), body))
}

/// A contact's timer as the core holds it: the value, when it was changed
/// and whether this device made that change (for the tie-break, §I.2), and
/// for our own change whether the peer has acknowledged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerTimer {
    pub secs: u32,
    pub changed_at_ms: u64,
    pub by_me: bool,
    /// Our change reached the peer's app: its delivered receipt for the
    /// latest `0x09` (`out_id`) came back. Always true for the peer's own
    /// change (it has it).
    pub acked: bool,
    /// The id of the latest `0x09` carrying this state.
    pub out_id: Option<[u8; 16]>,
    /// Re-sends made because a carrier was reported lost, since the last
    /// change or ack (capped by `MAX_TIMER_RESENDS`).
    pub resends: u8,
}

/// The furthest past this phone's clock a received change may be timed
/// (R33 I-1): 24 hours.
pub const MAX_TIMER_FUTURE_MS: u64 = 24 * 3600 * 1000;

/// What a change of our own left in force (R33 I-1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TimerOutcome {
    /// Our change won and is in force.
    pub applied: bool,
    /// The timer in force now (ours when applied, else the current one).
    pub secs: u32,
    /// Final review M-1: the 32-hex id of the intro queued for this contact
    /// that this change dropped (an intro carries no timer, so none goes
    /// once one is on); None when nothing was dropped. The message itself
    /// still waits in the app's queue for the circuit, where it goes with
    /// the timer.
    pub intro_dropped: Option<String>,
}

/// Re-sends of one timer state triggered by loss reports (status events)
/// before the core waits for the next session install. A new session
/// install always re-sends an unacknowledged state.
pub const MAX_TIMER_RESENDS: u8 = 5;
/// `0x09` ids remembered per peer, so their receipts and status events are
/// the core's, never the app's.
const TIMER_IDS_KEPT: usize = 16;

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The client's timer map, locked (never held across a persist or callback).
pub(crate) fn lock_timers(
    inner: &crate::ClientInner,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PeerTimer>> {
    lock(&inner.timers)
}

impl crate::ClientInner {
    /// The contact's timer state, if one was ever set.
    pub(crate) fn timer_state(&self, peer_hex: &str) -> Option<PeerTimer> {
        lock(&self.timers).get(&peer_hex.to_lowercase()).copied()
    }

    /// The contact's current timer, 0 when off or never set.
    pub(crate) fn timer_secs(&self, peer_hex: &str) -> u32 {
        self.timer_state(peer_hex).map_or(0, |t| t.secs)
    }

    /// The identity-key hex of whoever made a change.
    fn timer_setter(&self, peer_hex: &str, by_me: bool) -> String {
        if by_me {
            self.identity
                .as_ref()
                .map(|i| i.public_key_hex())
                .unwrap_or_default()
        } else {
            peer_hex.to_string()
        }
    }

    /// Apply a change (ours or the peer's) when it wins over the current
    /// one (`timer_wins`): stored, persisted with the peer record and
    /// reported (`on_timer_changed`). Returns whether it was applied.
    fn apply_timer(&self, peer_hex: &str, change: PeerTimer) -> bool {
        let peer = peer_hex.to_lowercase();
        if !valid_timer(change.secs) {
            return false;
        }
        if let Some(cur) = self.timer_state(&peer) {
            // The same change again (a re-send, or our own state echoed
            // back after a peer reset, R33 M-2): nothing to apply or show.
            if cur.secs == change.secs && cur.changed_at_ms == change.changed_at_ms {
                return false;
            }
            let new_by = self.timer_setter(&peer, change.by_me);
            let cur_by = self.timer_setter(&peer, cur.by_me);
            if !timer_wins(
                (change.changed_at_ms, &new_by),
                (cur.changed_at_ms, &cur_by),
            ) {
                return false;
            }
        }
        lock(&self.timers).insert(peer.clone(), change);
        // A failed write is reported by `persist_peer` itself; the timer
        // still applies in memory.
        let _ = self.persist_peer(&peer);
        if let Some(cb) = &self.callbacks {
            cb.on_timer_changed(peer, change.secs, change.changed_at_ms, change.by_me);
        }
        true
    }

    /// A timer change that arrived from `peer_hex` (`0x09`).
    pub(crate) fn apply_peer_timer(&self, peer_hex: &str, secs: u32, changed_at_ms: u64) -> bool {
        self.apply_timer(
            peer_hex,
            PeerTimer {
                secs,
                changed_at_ms,
                by_me: false,
                acked: true,
                out_id: None,
                resends: 0,
            },
        )
    }

    /// Our own change (`set_disappearing_timer`): applied here at once,
    /// timed now or just after the current change (a peer clock ahead of
    /// ours), and queued for the peer on its session. The core owns its
    /// delivery from here: re-sent when reported lost and after a new
    /// session install until the peer acknowledges it. Refused for a peer
    /// we may not send to.
    pub(crate) fn change_timer(
        &mut self,
        peer_hex: &str,
        secs: u32,
        now_ms: u64,
    ) -> Result<TimerOutcome, crate::RChatError> {
        let peer = peer_hex.to_lowercase();
        if !valid_timer(secs) {
            return Err(crate::RChatError::InvalidParameter {
                message: "unknown timer value".into(),
            });
        }
        self.check_sendable(&peer)?;
        let last = self.timer_state(&peer).map_or(0, |t| t.changed_at_ms);
        let changed_at_ms = now_ms.max(last.saturating_add(1));
        let applied = self.apply_timer(
            &peer,
            PeerTimer {
                secs,
                changed_at_ms,
                by_me: true,
                acked: false,
                out_id: None,
                resends: 0,
            },
        );
        if applied {
            self.queue_timer_state(&peer);
        }
        // Final review M-1: an intro queued while the timer was off would
        // go in the next knock without one. A change that turns it on drops
        // it (`set_intro` refuses a new one while it is on, R33 I-2).
        let secs_now = self.timer_secs(&peer);
        let intro_dropped = (applied && secs_now != 0)
            .then(|| self.intros.remove(&peer))
            .flatten()
            .map(|i| hex::encode(i.message_id));
        // R33 I-1: the caller learns what is in force now, never the
        // requested value.
        Ok(TimerOutcome {
            applied,
            secs: secs_now,
            intro_dropped,
        })
    }

    /// A timer change that arrived from `peer_hex` under the session
    /// `by`, checked before it is applied (R33 I-1, M-8): never from a
    /// retired session, never timed more than `MAX_TIMER_FUTURE_MS` past
    /// this phone's clock (a far-future time would win every later change
    /// and lock the timer). Returns whether it is acceptable: only an
    /// acceptable change is applied and receipted, so the sender's capped
    /// re-sends of a refused one run out.
    pub(crate) fn timer_change_acceptable(
        &self,
        changed_at_ms: u64,
        by: crate::session::DecryptedBy,
        now_ms: u64,
    ) -> bool {
        by == crate::session::DecryptedBy::Current
            && changed_at_ms <= now_ms.saturating_add(MAX_TIMER_FUTURE_MS)
    }

    /// The peer may have lost our shared timer state (it reported no prior
    /// session, the contact rotated, or was re-pinned to new keys, R33
    /// M-2): the current state, whoever set it, goes again with its time
    /// unchanged until the peer acknowledges it. Duplicates are no-ops.
    pub(crate) fn timer_resync(&self, peer_hex: &str) {
        let peer = peer_hex.to_lowercase();
        let had = {
            let mut timers = lock(&self.timers);
            match timers.get_mut(&peer) {
                Some(t) => {
                    t.acked = false;
                    t.resends = 0;
                    true
                }
                None => false,
            }
        };
        if had {
            self.queue_timer_state(&peer);
        }
    }

    /// Round 2 N-1: at a new connection every state the peer hasn't
    /// acknowledged is queued again (with a fresh budget, `reset_timer_resends`).
    pub(crate) fn requeue_unacked_timers(&self) {
        let peers: Vec<String> = lock(&self.timers)
            .iter()
            .filter(|(_, t)| !t.acked)
            .map(|(p, _)| p.clone())
            .collect();
        for peer in peers {
            self.queue_timer_state(&peer);
        }
    }

    /// A new connection (R33 M-3): loss-triggered re-sends get a fresh
    /// budget, so a change is never stuck after `MAX_TIMER_RESENDS` losses.
    pub(crate) fn reset_timer_resends(&self) {
        for t in lock(&self.timers).values_mut() {
            t.resends = 0;
        }
    }

    /// Queue our latest unacknowledged timer state for the peer on its
    /// session, as a `0x09` message (padded, ack-tracked, steady-aware like
    /// any message). One at most waits: a queued one is brought up to date
    /// in place. Nothing when the state is the peer's, already
    /// acknowledged, or there is no session yet (the install sends it).
    pub(crate) fn queue_timer_state(&self, peer_hex: &str) -> bool {
        self.queue_timer_state_with(peer_hex, true)
    }

    /// `queue_timer_state`; `persist` false when the caller writes the
    /// record next (a session install, whose own write must come first).
    pub(crate) fn queue_timer_state_with(&self, peer_hex: &str, persist: bool) -> bool {
        let peer = peer_hex.to_lowercase();
        let Some(t) = self.timer_state(&peer) else {
            return false;
        };
        // Our own change until the peer acknowledges it; after a peer
        // reset also the peer's (R33 M-2: `acked` cleared by `timer_resync`).
        if t.acked {
            return false;
        }
        let body = encode_timer(t.secs, t.changed_at_ms)[1..].to_vec();
        let id = {
            let Some(mut s) = self.session_manager.get_mut(&peer) else {
                return false;
            };
            let waiting = s
                .pending_messages
                .iter_mut()
                .find(|m| m.msg_type == crate::protocol::MessageType::Timer);
            match waiting {
                Some(m) => {
                    m.content = body;
                    crate::circuits::message_id_from_hex(&m.id.0)
                }
                None => {
                    let mut id = [0u8; 16];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
                    s.pending_messages
                        .push_back(crate::session::PendingMessage {
                            id: crate::protocol::MessageId(hex::encode(id)),
                            content: body,
                            msg_type: crate::protocol::MessageType::Timer,
                            timestamp_ms: crate::unix_now_secs().saturating_mul(1000),
                        });
                    Some(id)
                }
            }
        };
        let Some(id) = id else {
            return false;
        };
        self.note_timer_id(&peer, id);
        if let Some(cur) = lock(&self.timers).get_mut(&peer) {
            cur.out_id = Some(id);
        }
        if persist {
            let _ = self.persist_peer(&peer);
        }
        true
    }

    fn note_timer_id(&self, peer: &str, id: [u8; 16]) {
        let mut ids = lock(&self.timer_ids);
        let q = ids.entry(peer.to_string()).or_default();
        if !q.contains(&id) {
            q.push_back(id);
            while q.len() > TIMER_IDS_KEPT {
                q.pop_front();
            }
        }
    }

    /// `id` carried a timer change to `peer_hex` (this run, or the latest
    /// one restored with the record).
    pub(crate) fn is_timer_id(&self, peer_hex: &str, id: &[u8; 16]) -> bool {
        let peer = peer_hex.to_lowercase();
        lock(&self.timer_ids)
            .get(&peer)
            .is_some_and(|q| q.contains(id))
            || self.timer_state(&peer).and_then(|t| t.out_id) == Some(*id)
    }

    /// `is_timer_id` for any peer (the relay's ack names no peer).
    pub(crate) fn is_any_timer_id(&self, id_hex: &str) -> bool {
        let Some(id) = crate::circuits::message_id_from_hex(id_hex) else {
            return false;
        };
        lock(&self.timer_ids).values().any(|q| q.contains(&id))
            || lock(&self.timers).values().any(|t| t.out_id == Some(id))
    }

    /// A delivered receipt from `peer_hex` for `id`: true when `id` was a
    /// timer change (the receipt is the core's, never the app's). The
    /// latest state's receipt marks it acknowledged.
    pub(crate) fn timer_receipt(&self, peer_hex: &str, id: &[u8; 16]) -> bool {
        if !self.is_timer_id(peer_hex, id) {
            return false;
        }
        let peer = peer_hex.to_lowercase();
        let acked = {
            let mut timers = lock(&self.timers);
            match timers.get_mut(&peer) {
                Some(t) if !t.acked && t.out_id == Some(*id) => {
                    t.acked = true;
                    t.resends = 0;
                    true
                }
                _ => false,
            }
        };
        if acked {
            let _ = self.persist_peer(&peer);
        }
        true
    }

    /// A status event for one of our message ids: when it names a timer
    /// change, the core takes it (a loss re-sends the latest state at the
    /// next flush) and the app never sees it. True when taken.
    pub(crate) fn take_timer_status(&self, ev: &crate::status::StatusEvent) -> bool {
        let (kind, peer, id_hex, _) = ev.parts();
        // Our own ids: undelivered, not accepted, ack unknown, queued send
        // lost, resend eligible.
        if !matches!(kind, 2 | 5 | 6 | 7 | 10) {
            return false;
        }
        let Some(id) = crate::circuits::message_id_from_hex(&id_hex) else {
            return false;
        };
        if !self.is_timer_id(&peer, &id) {
            return false;
        }
        lock(&self.timer_requeue).push(peer.to_lowercase());
        true
    }

    /// Re-send the latest timer state to every peer a loss was reported
    /// for, up to `MAX_TIMER_RESENDS` per state. Run before each flush of
    /// queued sends.
    pub(crate) fn process_timer_requeues(&self) {
        let peers: Vec<String> = std::mem::take(&mut *lock(&self.timer_requeue));
        for peer in peers {
            let allowed = {
                let mut timers = lock(&self.timers);
                match timers.get_mut(&peer) {
                    Some(t) if !t.acked && t.resends < MAX_TIMER_RESENDS => {
                        t.resends += 1;
                        true
                    }
                    _ => false,
                }
            };
            if allowed {
                self.queue_timer_state(&peer);
            }
        }
    }

    /// A message expired on this device (§I.2): drop any plaintext the core
    /// still holds for it, the ack tracker's kept copy (R19) and any copy
    /// still queued on a session. The relay's copy, if any, is the
    /// relay's.
    ///
    /// Final review L7: a message that is the payload of our unanswered
    /// session-init would be re-sent with it on every new transport (and
    /// after a restart, from the stored record). That init is unclaimed and
    /// rebuilt around a cover message (a new hello, §A.4): sealed now when
    /// the session can, otherwise owed to the tick. The record is written
    /// either way, so the stored copy goes too.
    pub(crate) fn forget_message(&mut self, id_hex: &str) {
        let id = id_hex.to_lowercase();
        self.untrack_sent(&id);
        let mut reinit = Vec::new();
        for peer in self.session_manager.get_all_recipients() {
            if let Some(mut s) = self.session_manager.get_mut(&peer) {
                s.pending_messages.retain(|m| m.id.0 != id);
                if let Some(i) = s.init_out.as_mut() {
                    if i.sent.as_ref().is_some_and(|x| hex::encode(x.id) == id) {
                        if let Some(mut old) = i.sent.take() {
                            zeroize::Zeroize::zeroize(&mut old.payload);
                        }
                        reinit.push(peer.clone());
                    }
                }
            }
        }
        for peer in reinit {
            if !self.send_hello_sync(&peer) {
                self.hello_sync_due.insert(peer.clone());
            }
            let _ = self.persist_peer(&peer);
        }
    }
}

#[cfg(test)]
mod tests;
