//! Client-level ack tracking (spec §18.7 D35). The tracker lives in
//! `ClientInner`, so it survives a transport replacement, and it holds each
//! message's sealed payload, so the identical bytes can be sent again on the
//! peer's live circuit. Not persisted (§18.2).

use crate::protocol::{CircuitId, PacketFlags, RelayPacket};
use crate::status::StatusEvent;
use crate::ClientInner;
#[cfg(test)]
use crate::RChatError;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Sends of one payload (the first plus re-sends) before it is ack unknown.
pub(crate) const ACK_MAX_ATTEMPTS: u8 = 3;
/// Connected time after the first send before an unacked id is ack unknown.
pub(crate) const ACK_UNKNOWN_AFTER: Duration = Duration::from_secs(120);
/// Most ids tracked; beyond it the oldest leave as ack unknown.
pub(crate) const MAX_TRACKED_ACKS: usize = 1024;
/// Most payload bytes tracked; beyond it the oldest leave as ack unknown.
pub(crate) const MAX_TRACKED_ACK_BYTES: usize = 8 * 1024 * 1024;
/// Times a notice or a receipt id that left the tracker without an ack is
/// owed (sealed) again in one session before it is given up silently, as
/// app messages give up after `ACK_MAX_ATTEMPTS` (review N-1). A relay
/// that never acks, or refuses without an ack, costs a bounded number of
/// chain keys.
pub(crate) const REOWE_CAP: u8 = ACK_MAX_ATTEMPTS;
/// The same for a flagged notice: the peer learns of a reset only through
/// it, so it gets twice the tries, still bounded (a relay can withhold it
/// whatever the cap).
pub(crate) const REOWE_CAP_FLAGGED: u8 = 2 * ACK_MAX_ATTEMPTS;
/// Most re-owe counters kept. When full, counters of what is no longer
/// tracked or owed go first; if it is still full, a new id is given up
/// (never a reset of live counts, which would lift the cap).
pub(crate) const MAX_REOWE_COUNTERS: usize = 4096;

/// What a re-owe counter counts, per peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReoweKey {
    /// A notice, by its content (reason and ids): a later notice with new
    /// ids gets its own re-owes.
    Notice([u8; 32]),
    /// A receipt id, per receipt kind.
    Receipt(u8, [u8; 16]),
}

/// The counter key of a notice's content.
pub(crate) fn notice_key(reason: u8, ids: &[[u8; 16]]) -> ReoweKey {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([reason]);
    for id in ids {
        h.update(id);
    }
    ReoweKey::Notice(h.finalize().into())
}

/// One sent message waiting for the relay's `MessageAck`.
pub(crate) struct Tracked {
    pub peer: String,
    /// The sealed payload, exactly as first sent.
    pub payload: Vec<u8>,
    /// The circuit it was last sent on.
    pub circuit: CircuitId,
    pub first_sent: Instant,
    pub attempts: u8,
    /// The relay refused it (`CircuitNotFound` for `circuit`).
    pub not_accepted: bool,
    /// Time spent published since the first send (F31).
    pub connected_for: Duration,
    /// A session notice or receipt, not an app message: re-sent like one
    /// (under its own session only), and never reported to the app.
    pub internal: Option<Internal>,
    /// The session it was sealed under (`ChatSession::session_binding`);
    /// unused for app messages.
    pub binding: [u8; 32],
    /// Connected time after which it leaves unacked: `ACK_UNKNOWN_AFTER`,
    /// doubled for each time an internal entry was already owed again
    /// (backoff between re-seals, review N-1).
    pub expire_after: Duration,
}

/// What an internal entry carries, so it can be owed again rather than
/// re-sent once it can no longer go as these bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Internal {
    /// A session notice: `flags` as sent (the no-prior-session flag), its
    /// reason and the ids it reported (listed again if it is owed again).
    Notice {
        flags: u8,
        reason: u8,
        ids: Vec<[u8; 16]>,
    },
    /// A receipt batch of `kind` for `ids`.
    Receipt { kind: u8, ids: Vec<[u8; 16]> },
}

/// Unacked sends by message id (lowercase hex), oldest first.
#[derive(Default)]
pub(crate) struct AckTracker {
    entries: HashMap<String, Tracked>,
    /// Ids in tracking order; may hold ids already gone (skipped lazily).
    order: VecDeque<String>,
    bytes: usize,
    /// Internal entries that left without an ack (evicted, expired,
    /// exhausted), for the client to owe again (`settle_departed`).
    departed: Vec<(String, Tracked)>,
}

/// `(peer, id, attempts)` of each app entry, for `AckUnknown`. Internal
/// entries never reach the app: they go to `departed`.
fn unknown(
    departed: &mut Vec<(String, Tracked)>,
    gone: Vec<(String, Tracked)>,
) -> Vec<(String, String, u8)> {
    let (internal, app): (Vec<_>, Vec<_>) =
        gone.into_iter().partition(|(_, t)| t.internal.is_some());
    departed.extend(internal);
    app.into_iter()
        .map(|(id, t)| {
            log::debug!(
                "[RUST] ack unknown after {} attempt(s), {:?} since the first send",
                t.attempts,
                t.first_sent.elapsed()
            );
            (t.peer, id, t.attempts)
        })
        .collect()
}

impl AckTracker {
    /// Track `id_hex`; returns the entries evicted to stay within the bounds.
    pub fn track(&mut self, id_hex: String, t: Tracked) -> Vec<(String, String, u8)> {
        self.bytes += t.payload.len();
        if let Some(old) = self.entries.insert(id_hex.clone(), t) {
            self.bytes -= old.payload.len();
        }
        // Never twice in `order`, even if a lazily left copy remains.
        self.order.retain(|id| *id != id_hex);
        self.order.push_back(id_hex);
        let mut evicted = Vec::new();
        while self.len() > MAX_TRACKED_ACKS || self.bytes() > MAX_TRACKED_ACK_BYTES {
            let Some(id) = self.order.pop_front() else {
                break;
            };
            if let Some(t) = self.remove(&id) {
                evicted.push((id, t));
            }
        }
        // Acked ids leave `order` lazily; keep it within a small multiple.
        if self.order.len() > 2 * MAX_TRACKED_ACKS {
            let entries = &self.entries;
            self.order.retain(|id| entries.contains_key(id));
        }
        unknown(&mut self.departed, evicted)
    }

    fn remove(&mut self, id_hex: &str) -> Option<Tracked> {
        let t = self.entries.remove(id_hex)?;
        self.bytes -= t.payload.len();
        Some(t)
    }

    /// Stop tracking `id_hex` (its send failed and the caller reports it).
    pub fn untrack(&mut self, id_hex: &str) {
        self.remove(id_hex);
    }

    /// The relay acked `id_hex`: true the first time only (C-5).
    /// An internal entry (notice, receipt) leaves silently: false. (Tests;
    /// the client uses `ack_take`.)
    #[cfg(test)]
    pub fn ack(&mut self, id_hex: &str) -> bool {
        self.remove(id_hex).is_some_and(|t| t.internal.is_none())
    }

    /// Remove and return the peer's internal entries sealed under another
    /// session than `binding`: they can no longer go as these bytes (a peer
    /// without the old session could not decrypt them, D39).
    pub fn take_internal_not_under(&mut self, peer: &str, binding: &[u8; 32]) -> Vec<Tracked> {
        let ids: Vec<String> = self
            .order
            .iter()
            .filter(|id| {
                self.entries.get(*id).is_some_and(|t| {
                    t.peer == peer && t.internal.is_some() && t.binding != *binding
                })
            })
            .cloned()
            .collect();
        ids.iter().filter_map(|id| self.remove(id)).collect()
    }

    /// The relay acked `id_hex`: the entry, the first time only.
    pub fn ack_take(&mut self, id_hex: &str) -> Option<Tracked> {
        self.remove(id_hex)
    }

    /// Remove and return the peer's tracked receipt entries sealed under
    /// `binding` (a flagged notice owed again goes before them, N-2).
    pub fn take_receipts_under(&mut self, peer: &str, binding: &[u8; 32]) -> Vec<Tracked> {
        let ids: Vec<String> = self
            .order
            .iter()
            .filter(|id| {
                self.entries.get(*id).is_some_and(|t| {
                    t.peer == peer
                        && t.binding == *binding
                        && matches!(t.internal, Some(Internal::Receipt { .. }))
                })
            })
            .cloned()
            .collect();
        ids.iter().filter_map(|id| self.remove(id)).collect()
    }

    /// Internal entries that left without an ack since the last call.
    pub fn take_departed(&mut self) -> Vec<(String, Tracked)> {
        std::mem::take(&mut self.departed)
    }

    /// `(id, payload)` of every id tracked for `peer`, in send order.
    pub fn payloads_for(&self, peer: &str) -> Vec<(String, Vec<u8>)> {
        self.order
            .iter()
            .filter_map(|id| {
                let t = self.entries.get(id).filter(|t| t.peer == peer)?;
                Some((id.clone(), t.payload.clone()))
            })
            .collect()
    }

    /// `id_hex` was sent again, on `circuit`. A send the relay refused
    /// (`not_accepted`) never counted, so its re-send is not an attempt
    /// (spec §18.7: "not a resend").
    pub fn note_attempt(&mut self, id_hex: &str, circuit: CircuitId) {
        if let Some(t) = self.entries.get_mut(id_hex) {
            if !t.not_accepted {
                t.attempts = t.attempts.saturating_add(1);
            }
            t.circuit = circuit;
            t.not_accepted = false;
        }
    }

    /// The relay refused packets on `circuit`: mark the ids last sent there.
    /// Returns `(peer, id)` of those newly marked (one event per refusal).
    pub fn mark_not_accepted(&mut self, circuit: &CircuitId) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for id in &self.order {
            if let Some(t) = self.entries.get_mut(id) {
                if t.circuit == *circuit && !t.not_accepted {
                    t.not_accepted = true;
                    // Internal ids were never the app's (review M-1).
                    if t.internal.is_none() {
                        out.push((t.peer.clone(), id.clone()));
                    }
                }
            }
        }
        out
    }

    /// Add `connected` to every entry; remove those past `ACK_UNKNOWN_AFTER`.
    pub fn advance(&mut self, connected: Duration) -> Vec<(String, String, u8)> {
        for t in self.entries.values_mut() {
            t.connected_for = t.connected_for.saturating_add(connected);
        }
        self.remove_where(|t| t.connected_for > t.expire_after)
    }

    /// Remove the peer's entries already sent `ACK_MAX_ATTEMPTS` times.
    /// Called at a re-send opportunity, so the third send gets its full wait.
    pub fn take_exhausted(&mut self, peer: &str) -> Vec<(String, String, u8)> {
        self.remove_where(|t| t.peer == peer && t.attempts >= ACK_MAX_ATTEMPTS)
    }

    fn remove_where(&mut self, pred: impl Fn(&Tracked) -> bool) -> Vec<(String, String, u8)> {
        let due: Vec<String> = self
            .order
            .iter()
            .filter(|id| self.entries.get(*id).is_some_and(&pred))
            .cloned()
            .collect();
        let gone = due
            .into_iter()
            .filter_map(|id| {
                let t = self.remove(&id)?;
                Some((id, t))
            })
            .collect();
        unknown(&mut self.departed, gone)
    }

    /// Forget every id tracked for `peer`, silently: its payloads are
    /// sealed to keys that are no longer trusted (unpin, block, re-pin).
    pub fn drop_peer(&mut self, peer: &str) {
        let mut freed = 0;
        self.entries.retain(|_, t| {
            let keep = t.peer != peer;
            if !keep {
                freed += t.payload.len();
            }
            keep
        });
        self.bytes -= freed;
        let entries = &self.entries;
        self.order.retain(|id| entries.contains_key(id));
        self.departed.retain(|(_, t)| t.peer != peer);
    }

    /// Attempts recorded for `id_hex` (tests).
    #[cfg(test)]
    pub fn attempts(&self, id_hex: &str) -> Option<u8> {
        self.entries.get(id_hex).map(|t| t.attempts)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl ClientInner {
    fn ack_tracker(&self) -> std::sync::MutexGuard<'_, AckTracker> {
        self.acks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Track a sealed message the transport accepted (delivery confirmation
    /// on); evicted ids are reported as ack unknown.
    pub(crate) fn track_sent(
        &self,
        peer_hex: &str,
        id_hex: &str,
        circuit: CircuitId,
        payload: Vec<u8>,
    ) {
        self.track(peer_hex, id_hex, circuit, payload, None);
    }

    /// Track a session notice or receipt the transport accepted, so a
    /// connection replaced before its frame left re-sends the identical
    /// bytes on the resume under the same session (never re-sealed), in
    /// send order: a flagged notice still goes before the receipts behind
    /// it (I-1). Under another session, or if it leaves without an ack, it
    /// is owed again instead (`settle_internal`). False with delivery
    /// confirmation off.
    pub(crate) fn track_internal(
        &self,
        peer_hex: &str,
        id_hex: &str,
        circuit: CircuitId,
        payload: Vec<u8>,
        what: Internal,
    ) -> bool {
        self.track(peer_hex, id_hex, circuit, payload, Some(what))
    }

    fn track(
        &self,
        peer_hex: &str,
        id_hex: &str,
        circuit: CircuitId,
        payload: Vec<u8>,
        internal: Option<Internal>,
    ) -> bool {
        let binding = match internal {
            Some(_) => self
                .session_manager
                .get(peer_hex)
                .map(|s| s.session_binding)
                .unwrap_or_default(),
            None => [0; 32],
        };
        let level = match &internal {
            None => 0,
            Some(Internal::Notice { reason, ids, .. }) => {
                self.reowe_count(peer_hex, notice_key(*reason, ids), &binding)
            }
            Some(Internal::Receipt { kind, ids }) => ids
                .iter()
                .map(|id| self.reowe_count(peer_hex, ReoweKey::Receipt(*kind, *id), &binding))
                .max()
                .unwrap_or(0),
        };
        let expire_after = ACK_UNKNOWN_AFTER * (1u32 << level.min(8));
        if !self.config.enable_delivery_confirmation {
            return false;
        }
        let evicted = self.ack_tracker().track(
            id_hex.to_string(),
            Tracked {
                peer: peer_hex.to_string(),
                payload,
                circuit,
                first_sent: Instant::now(),
                attempts: 1,
                not_accepted: false,
                connected_for: Duration::ZERO,
                internal,
                binding,
                expire_after,
            },
        );
        for (peer, message_id, attempts) in evicted {
            self.emit_status(StatusEvent::AckUnknown {
                peer,
                message_id,
                attempts,
            });
        }
        true
    }

    /// `AckTracker::untrack` under the tracker's own lock.
    pub(crate) fn untrack_sent(&self, id_hex: &str) {
        self.ack_tracker().untrack(id_hex);
    }

    /// Re-send every tracked payload for `peer_hex` on its live circuit
    /// (spec §18.7 D35): identical bytes, re-wrapped for the current circuit.
    pub(crate) fn resend_tracked(&mut self, peer_hex: &str) {
        if !self.has_live_circuit(peer_hex) {
            return;
        }
        let exhausted = self.ack_tracker().take_exhausted(peer_hex);
        for (peer, message_id, attempts) in exhausted {
            self.emit_status(StatusEvent::AckUnknown {
                peer,
                message_id,
                attempts,
            });
        }
        self.settle_departed();
        let Some((target, token, binding)) = self.session_manager.get(peer_hex).and_then(|s| {
            Some((
                s.target_circuit_id.clone()?,
                s.get_token_key()?,
                s.session_binding,
            ))
        }) else {
            return;
        };
        // Sealed under an earlier session: owed again under this one
        // (review I-2), never re-sent as old-session bytes.
        let stale = self
            .ack_tracker()
            .take_internal_not_under(peer_hex, &binding);
        for t in stale {
            self.settle_internal(peer_hex, t, false);
        }
        let todo = self.ack_tracker().payloads_for(peer_hex);
        for (id, payload) in todo {
            let packet = RelayPacket::with_auth(
                target.clone(),
                payload,
                PacketFlags {
                    encrypted: true,
                    ..Default::default()
                },
                &token,
            );
            if self.send_now(packet.encode_with_frame_type()).is_err() {
                // The rest waits for the next opportunity, in order: nothing
                // overtakes what was refused (review M-2, I-1).
                break;
            }
            self.ack_tracker().note_attempt(&id, target.clone());
        }
    }

    /// Owe again every internal entry that left the tracker without an ack;
    /// returns the peers concerned. Not flushed here: a caller that is about
    /// to re-send tracked payloads flushes after them (I-1).
    pub(crate) fn settle_departed(&mut self) -> Vec<String> {
        let departed = self.ack_tracker().take_departed();
        let mut peers: Vec<String> = Vec::new();
        for (_, t) in departed {
            let peer = t.peer.clone();
            self.settle_internal(&peer, t, true);
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
        peers
    }

    /// Times `id` (a receipt id, or None for the notice) was owed again
    /// under the session `binding`.
    fn reowe_count(&self, peer: &str, key: ReoweKey, binding: &[u8; 32]) -> u8 {
        match self.reowes.get(&(peer.to_string(), key)) {
            Some((b, n)) if b == binding => *n,
            _ => 0,
        }
    }

    /// Count one more re-owe of `key` under `binding`; false (and nothing
    /// counted) once `cap` re-owes were made, or if a new counter has no
    /// room (R3-1): it is given up.
    fn bump_reowe(&mut self, peer: &str, key: ReoweKey, binding: [u8; 32], cap: u8) -> bool {
        let n = self.reowe_count(peer, key, &binding);
        if n >= cap {
            return false;
        }
        let k = (peer.to_string(), key);
        if !self.reowes.contains_key(&k) && self.reowes.len() >= MAX_REOWE_COUNTERS {
            // At most one prune a second: a full map of live counters makes
            // every later new id a give-up, without a scan each time.
            let now = Instant::now();
            let due = match self.last_reowe_prune {
                Some(at) => now.saturating_duration_since(at) >= Duration::from_secs(1),
                None => true,
            };
            if due {
                self.last_reowe_prune = Some(now);
                self.prune_reowes();
            }
            if self.reowes.len() >= MAX_REOWE_COUNTERS {
                return false;
            }
        }
        self.reowes.insert(k, (binding, n + 1));
        true
    }

    /// Drop the counters of what is neither tracked nor owed any more.
    fn prune_reowes(&mut self) {
        let mut live: std::collections::HashSet<(String, ReoweKey)> = Default::default();
        for ((peer, kind), ids) in &self.pending_receipts {
            for id in ids {
                live.insert((peer.clone(), ReoweKey::Receipt(*kind, *id)));
            }
        }
        for t in self.ack_tracker().entries.values() {
            match &t.internal {
                Some(Internal::Receipt { kind, ids }) => {
                    for id in ids {
                        live.insert((t.peer.clone(), ReoweKey::Receipt(*kind, *id)));
                    }
                }
                Some(Internal::Notice { reason, ids, .. }) => {
                    live.insert((t.peer.clone(), notice_key(*reason, ids)));
                }
                None => {}
            }
        }
        let due = &self.notice_due;
        self.reowes.retain(|k, _| {
            live.contains(k) || (matches!(k.1, ReoweKey::Notice(_)) && due.contains(&k.0))
        });
    }

    /// The relay acked an internal entry: its counters go.
    pub(crate) fn forget_reowes(&mut self, t: &Tracked) {
        match &t.internal {
            Some(Internal::Receipt { kind, ids }) => {
                for id in ids {
                    self.reowes
                        .remove(&(t.peer.clone(), ReoweKey::Receipt(*kind, *id)));
                }
            }
            Some(Internal::Notice { reason, ids, .. }) => {
                self.reowes
                    .remove(&(t.peer.clone(), notice_key(*reason, ids)));
            }
            None => {}
        }
    }

    /// An internal entry that will not go as its bytes.
    /// - Receipt ids are owed again (sealed afresh under the current
    ///   session; receipts are idempotent at the receiver), each at most
    ///   `REOWE_CAP` times per session (N-1).
    /// - A notice is owed again only if it was for the current session and
    ///   `same_session_retry` (one of an earlier session is dead, D37), at
    ///   most `REOWE_CAP` (`REOWE_CAP_FLAGGED` flagged) times, with its flag
    ///   and its ids listed again (N-3). A flagged one takes the session's
    ///   still-tracked receipts back too, so they wait behind it (N-2).
    pub(crate) fn settle_internal(&mut self, peer_hex: &str, t: Tracked, same_session_retry: bool) {
        let current = self
            .session_manager
            .get(peer_hex)
            .map(|s| s.session_binding);
        match t.internal {
            Some(Internal::Receipt { kind, ids }) => {
                let binding = current.unwrap_or_default();
                let owed: Vec<[u8; 16]> = ids
                    .into_iter()
                    .filter(|id| {
                        self.bump_reowe(peer_hex, ReoweKey::Receipt(kind, *id), binding, REOWE_CAP)
                    })
                    .collect();
                if owed.is_empty() {
                    return;
                }
                self.queue_receipt(peer_hex, kind, &owed);
            }
            Some(Internal::Notice { flags, reason, ids }) => {
                if !(same_session_retry && current == Some(t.binding)) {
                    return;
                }
                let cap = if flags != 0 {
                    REOWE_CAP_FLAGGED
                } else {
                    REOWE_CAP
                };
                if !self.bump_reowe(peer_hex, notice_key(reason, &ids), t.binding, cap) {
                    log::debug!("[RUST] session notice given up after its re-owes");
                    return;
                }
                self.notice_due.insert(peer_hex.to_string());
                if flags != 0 {
                    *self
                        .notice_flag_pending
                        .entry(peer_hex.to_string())
                        .or_insert(0) |= flags;
                    let behind = self.ack_tracker().take_receipts_under(peer_hex, &t.binding);
                    for r in behind {
                        if let Some(Internal::Receipt { kind, ids }) = r.internal {
                            self.queue_receipt(peer_hex, kind, &ids);
                        }
                    }
                }
                self.relist_notice_ids(peer_hex, reason, &ids);
            }
            None => return,
        }
        let _ = self.persist_peer(peer_hex);
    }

    /// A notice owed again reports its ids again: undecryptable ids are
    /// listed again; lost ids leave `lost_reported` for `lost_unstored`.
    fn relist_notice_ids(&mut self, peer_hex: &str, reason: u8, ids: &[[u8; 16]]) {
        use crate::persistence::{push_capped, MAX_DELIVERED_UNSTORED, MAX_UNDECRYPTABLE};
        for id in ids {
            match reason {
                crate::notice::REASON_UNDECRYPTABLE => {
                    if !self
                        .undecryptable
                        .get(peer_hex)
                        .is_some_and(|q| q.contains(id))
                    {
                        push_capped(&mut self.undecryptable, peer_hex, *id, MAX_UNDECRYPTABLE);
                    }
                }
                crate::notice::REASON_LOST_BEFORE_STORED => {
                    if let Some(q) = self.lost_reported.get_mut(peer_hex) {
                        q.retain(|(x, _)| x != id);
                    }
                    if !self
                        .lost_unstored
                        .get(peer_hex)
                        .is_some_and(|q| q.contains(id))
                    {
                        push_capped(
                            &mut self.lost_unstored,
                            peer_hex,
                            *id,
                            MAX_DELIVERED_UNSTORED,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    /// Ticker: count connected time towards `ACK_UNKNOWN_AFTER` (F31).
    pub(crate) fn fire_ack_expiry(&mut self, now: Instant) {
        let elapsed = self
            .ack_last_tick
            .map(|t| now.saturating_duration_since(t))
            .unwrap_or_default();
        self.ack_last_tick = Some(now);
        if !self.is_key_bundle_published {
            return; // the 120 s clock counts connected time only
        }
        let gone = self.ack_tracker().advance(elapsed);
        for (peer, message_id, attempts) in gone {
            self.emit_status(StatusEvent::AckUnknown {
                peer,
                message_id,
                attempts,
            });
        }
        // Expired here, or evicted by any track since the last tick. An
        // entry leaves no later than the ones tracked after it (same clock,
        // FIFO eviction), so what is owed again here is not overtaking a
        // flagged notice still tracked.
        for peer in self.settle_departed() {
            self.flush_receipts(&peer);
        }
    }

    /// `send_queued_message`'s seal → track → send, synchronously.
    #[cfg(test)]
    pub(crate) fn send_tracked_for_test(
        &mut self,
        peer: &str,
        id: [u8; 16],
        pt: &[u8],
    ) -> Result<(), RChatError> {
        let packet = self.seal_ratchet(peer, id, pt)?;
        self.send_now(packet.encode_with_frame_type())?;
        self.track_sent(peer, &hex::encode(id), packet.circuit_id, packet.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CircuitId;

    fn t(peer: &str, n: usize) -> Tracked {
        Tracked {
            peer: peer.into(),
            payload: vec![0; n],
            circuit: CircuitId([1; 16]),
            first_sent: Instant::now(),
            attempts: 1,
            not_accepted: false,
            connected_for: Duration::ZERO,
            internal: None,
            binding: [0; 32],
            expire_after: ACK_UNKNOWN_AFTER,
        }
    }

    #[test]
    fn c5_replayed_ack_fires_once() {
        let mut a = AckTracker::default();
        a.track("id1".into(), t("p", 10));
        assert!(a.ack("id1"));
        assert!(!a.ack("id1"));
    }

    /// AK3: three sends and no ack → exhausted at the next replacement (not
    /// right after the third send); 120 s of connected time → unknown; a late
    /// ack is ignored.
    #[test]
    fn ak3_ack_unknown_after_attempts_or_time() {
        let mut a = AckTracker::default();
        a.track("x".into(), t("p", 10));
        a.note_attempt("x", CircuitId([1; 16]));
        assert!(a.take_exhausted("p").is_empty(), "2 sends: not yet");
        a.note_attempt("x", CircuitId([1; 16]));
        assert!(
            a.advance(Duration::from_secs(1)).is_empty(),
            "3 sends: still waiting for its ack"
        );
        assert_eq!(a.take_exhausted("p"), vec![("p".into(), "x".into(), 3)]);
        // A refused send's re-send is not an attempt.
        a.track("z".into(), t("p", 10));
        a.mark_not_accepted(&CircuitId([1; 16]));
        a.note_attempt("z", CircuitId([1; 16]));
        a.note_attempt("z", CircuitId([1; 16]));
        assert!(a.take_exhausted("p").is_empty(), "z: 2 attempts, not 3");
        a.ack("z");
        assert!(!a.ack("x"));
        a.track("y".into(), t("p", 10));
        assert!(a.advance(Duration::from_secs(119)).is_empty());
        assert_eq!(
            a.advance(Duration::from_secs(2)).len(),
            1,
            "past 120 s connected"
        );
    }

    /// AK5: bounded by count and bytes; evictions are reported.
    #[test]
    fn ak5_tracker_bounds() {
        let mut a = AckTracker::default();
        let mut evicted = 0;
        for i in 0..1100 {
            evicted += a.track(format!("{i:032x}"), t("p", 10_000)).len();
        }
        assert!(a.len() <= MAX_TRACKED_ACKS && a.bytes() <= MAX_TRACKED_ACK_BYTES);
        assert_eq!(evicted + a.len(), 1100);
    }

    /// Review M-5: an evicted internal entry is never reported as ack
    /// unknown; it is handed back as departed, to be owed again.
    #[test]
    fn evicted_internal_entries_are_departed_not_unknown() {
        let mut a = AckTracker::default();
        let internal = |n| Tracked {
            internal: Some(Internal::Receipt {
                kind: 1,
                ids: vec![[n; 16]],
            }),
            ..t("p", 10_000)
        };
        let mut reported = 0;
        for i in 0..1100u32 {
            reported += a.track(format!("{i:032x}"), internal(i as u8)).len();
        }
        assert_eq!(reported, 0, "no AckUnknown for internal entries");
        assert_eq!(a.take_departed().len() + a.len(), 1100);
        assert!(a.take_departed().is_empty(), "handed back once");
    }

    /// AK4 (unit): CircuitNotFound marks the ids sent on that circuit.
    #[test]
    fn ak4_not_accepted_by_circuit() {
        let mut a = AckTracker::default();
        a.track("x".into(), t("p", 10));
        let mut other = t("p", 10);
        other.circuit = CircuitId([2; 16]);
        a.track("y".into(), other);
        assert_eq!(
            a.mark_not_accepted(&CircuitId([1; 16])),
            vec![("p".into(), "x".into())]
        );
        assert!(
            a.mark_not_accepted(&CircuitId([1; 16])).is_empty(),
            "reported once per refusal"
        );
        a.note_attempt("x", CircuitId([1; 16]));
        assert_eq!(
            a.mark_not_accepted(&CircuitId([1; 16])),
            vec![("p".into(), "x".into())],
            "a re-send can be refused again"
        );
    }

    /// Fix round 1: a re-tracked id appears once in `order`; `drop_peer`
    /// removes a peer's entries and their bytes.
    #[test]
    fn retrack_and_drop_peer_keep_the_books() {
        let mut a = AckTracker::default();
        a.track("x".into(), t("p", 10));
        a.ack("x");
        a.track("x".into(), t("p", 10));
        a.track("x".into(), t("p", 20));
        assert_eq!(a.order.len(), 1);
        assert_eq!(a.bytes(), 20);
        a.track("y".into(), t("q", 5));
        a.drop_peer("p");
        assert_eq!((a.len(), a.bytes()), (1, 5));
        assert_eq!(a.payloads_for("p"), vec![]);
        assert_eq!(a.order.len(), 1);
    }
}
