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
/// Most bytes (payload plus kept plaintext) of small entries tracked;
/// beyond it the oldest small entries leave as ack unknown.
pub(crate) const MAX_TRACKED_ACK_BYTES: usize = 8 * 1024 * 1024;
/// An entry whose sealed payload is at least this large (files, images,
/// voice notes) counts toward the separate large budget (ruling R29), so a
/// file never pushes texts out of the tracker, nor texts a file.
pub(crate) const LARGE_ACK_PAYLOAD: usize = 64 * 1024;
/// What a sealed payload can add over its plaintext: the relay message
/// bounds the payload, so this is the relay's 4 MiB less the largest file
/// plaintext (padding steps, ratchet header and tag, envelope).
pub(crate) const LARGE_ACK_ENTRY_OVERHEAD: usize =
    crate::file_msg::RELAY_MAX_MESSAGE_BYTES - crate::file_msg::MAX_FILE_PLAINTEXT;
/// Bytes of large entries tracked: three maximum-size files, each its
/// payload plus the plaintext kept for a re-seal (R19). Beyond it the
/// oldest large entries leave as ack unknown; small entries are never
/// touched (R29).
pub(crate) const MAX_TRACKED_LARGE_ACK_BYTES: usize =
    3 * (2 * crate::file_msg::MAX_FILE_PLAINTEXT + LARGE_ACK_ENTRY_OVERHEAD);
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
    /// An app message's plaintext (type byte first), kept so it can be
    /// re-sealed under a later session of the same pair-secret lineage
    /// (R19). Memory only, like the tracker; wiped when the entry goes.
    pub plaintext: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// `ChatSession::pair_lineage` of the session it was sealed under.
    pub lineage: Option<[u8; 32]>,
}

impl Tracked {
    /// Bytes it counts toward `MAX_TRACKED_ACK_BYTES`.
    fn size(&self) -> usize {
        self.payload.len() + self.plaintext.as_ref().map_or(0, |p| p.len())
    }
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
    /// A session-init (§A.4) carrying the invisible first message. Never
    /// owed again: the session keeps the init and re-sends it until the
    /// peer's first reply (`ChatSession::init_out`).
    SessionInit,
}

/// Unacked sends by message id (lowercase hex), oldest first.
#[derive(Default)]
pub(crate) struct AckTracker {
    entries: HashMap<String, Tracked>,
    /// Ids in tracking order; may hold ids already gone (skipped lazily).
    order: VecDeque<String>,
    /// Bytes of small entries (`MAX_TRACKED_ACK_BYTES`).
    bytes: usize,
    /// Ids of large entries (payload at least `LARGE_ACK_PAYLOAD` when
    /// tracked), and their bytes (`MAX_TRACKED_LARGE_ACK_BYTES`).
    large: std::collections::HashSet<String>,
    large_bytes: usize,
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
    /// Only entries of the new one's class (small or large, R29) are
    /// evicted: that is the only budget it grew.
    pub fn track(&mut self, id_hex: String, t: Tracked) -> Vec<(String, String, u8)> {
        self.remove(&id_hex);
        let large = t.payload.len() >= LARGE_ACK_PAYLOAD;
        if large {
            self.large_bytes += t.size();
            self.large.insert(id_hex.clone());
        } else {
            self.bytes += t.size();
        }
        self.entries.insert(id_hex.clone(), t);
        // Never twice in `order`, even if a lazily left copy remains.
        self.order.retain(|id| *id != id_hex);
        self.order.push_back(id_hex);
        let mut evicted = Vec::new();
        let over = |a: &Self| {
            a.len() > MAX_TRACKED_ACKS
                || if large {
                    a.large_bytes > MAX_TRACKED_LARGE_ACK_BYTES
                } else {
                    a.bytes > MAX_TRACKED_ACK_BYTES
                }
        };
        // Accepted outage behaviour (fix round 2 N-2): the count limit is
        // shared, but eviction stays within the new entry's class. With
        // `MAX_TRACKED_ACKS` small entries tracked (a long outage of acks),
        // a new large entry is its class's only candidate, so it is
        // evicted at once and reported as AckUnknown; the small entries,
        // and the large budget, are untouched.
        while over(self) {
            // The oldest live entry of the same class.
            let Some(pos) = self
                .order
                .iter()
                .position(|id| self.entries.contains_key(id) && self.large.contains(id) == large)
            else {
                break;
            };
            let Some(id) = self.order.remove(pos) else {
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
        *self.budget_of(id_hex) -= t.size();
        self.large.remove(id_hex);
        Some(t)
    }

    /// The byte count `id_hex` is charged to.
    fn budget_of(&mut self, id_hex: &str) -> &mut usize {
        if self.large.contains(id_hex) {
            &mut self.large_bytes
        } else {
            &mut self.bytes
        }
    }

    /// Ids tracked for `peer`, in send order.
    pub fn ids_for(&self, peer: &str) -> Vec<String> {
        self.order
            .iter()
            .filter(|id| self.entries.get(*id).is_some_and(|t| t.peer == peer))
            .cloned()
            .collect()
    }

    /// The peer's app entries sealed under another session than `binding`
    /// of the same pair-secret `lineage`, with their plaintext, in send
    /// order (R19).
    pub fn to_reseal(
        &self,
        peer: &str,
        binding: &[u8; 32],
        lineage: &[u8; 32],
    ) -> Vec<(String, zeroize::Zeroizing<Vec<u8>>)> {
        self.order
            .iter()
            .filter_map(|id| {
                let t = self.entries.get(id)?;
                let same_lineage = t
                    .lineage
                    .as_ref()
                    .is_some_and(|l| constant_time_eq::constant_time_eq(l, lineage));
                (t.peer == peer && t.internal.is_none() && t.binding != *binding && same_lineage)
                    .then(|| Some((id.clone(), t.plaintext.clone()?)))
                    .flatten()
            })
            .collect()
    }

    /// `id_hex` was re-sealed under the session `binding`: these bytes go
    /// out from now on.
    pub fn resealed(&mut self, id_hex: &str, payload: Vec<u8>, binding: [u8; 32]) {
        let large = self.large.contains(id_hex);
        if let Some(t) = self.entries.get_mut(id_hex) {
            let counter = if large {
                &mut self.large_bytes
            } else {
                &mut self.bytes
            };
            *counter -= t.payload.len();
            *counter += payload.len();
            t.payload = payload;
            t.binding = binding;
        }
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
    /// M-4: the peer's plaintexts kept for a re-seal under `lineage` only;
    /// every other one (an identity install changed the pair secret) is
    /// wiped now: it can never be re-sealed (R19).
    pub fn drop_plaintexts(&mut self, peer: &str, lineage: Option<[u8; 32]>) {
        for (id, t) in self.entries.iter_mut().filter(|(_, t)| t.peer == peer) {
            if t.plaintext.is_some() && (lineage.is_none() || t.lineage != lineage) {
                let freed = t.plaintext.take().map_or(0, |p| p.len());
                if self.large.contains(id) {
                    self.large_bytes -= freed;
                } else {
                    self.bytes -= freed;
                }
            }
        }
    }

    pub fn drop_peer(&mut self, peer: &str) {
        let ids: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, t)| t.peer == peer)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.remove(&id);
        }
        let entries = &self.entries;
        self.order.retain(|id| entries.contains_key(id));
        self.departed.retain(|(_, t)| t.peer != peer);
    }

    /// Whether `id_hex` still keeps its plaintext for a re-seal (tests).
    #[cfg(test)]
    pub fn has_plaintext(&self, id_hex: &str) -> Option<bool> {
        self.entries.get(id_hex).map(|t| t.plaintext.is_some())
    }

    /// Attempts recorded for `id_hex` (tests).
    #[cfg(test)]
    pub fn attempts(&self, id_hex: &str) -> Option<u8> {
        self.entries.get(id_hex).map(|t| t.attempts)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Bytes of small entries (tests).
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Bytes of large entries (tests).
    #[cfg(test)]
    pub fn large_bytes(&self) -> usize {
        self.large_bytes
    }
}

impl ClientInner {
    fn ack_tracker(&self) -> std::sync::MutexGuard<'_, AckTracker> {
        self.acks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Track a sealed message the transport accepted (delivery confirmation
    /// on); evicted ids are reported as ack unknown.
    /// `plaintext` (type byte first) is kept with it for a re-seal under a
    /// later session of the same pair-secret lineage (R19).
    pub(crate) fn track_sent(
        &self,
        peer_hex: &str,
        id_hex: &str,
        circuit: CircuitId,
        payload: Vec<u8>,
        plaintext: &[u8],
    ) {
        self.track(
            peer_hex,
            id_hex,
            circuit,
            payload,
            None,
            Some(zeroize::Zeroizing::new(plaintext.to_vec())),
        );
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
        self.track(peer_hex, id_hex, circuit, payload, Some(what), None)
    }

    fn track(
        &self,
        peer_hex: &str,
        id_hex: &str,
        circuit: CircuitId,
        payload: Vec<u8>,
        internal: Option<Internal>,
        plaintext: Option<zeroize::Zeroizing<Vec<u8>>>,
    ) -> bool {
        // The session it was sealed under (app messages too: R19 re-seals
        // those sealed under an earlier session of the same lineage).
        let (binding, lineage) = self
            .session_manager
            .get(peer_hex)
            .map(|s| (s.session_binding, s.pair_lineage()))
            .unwrap_or_default();
        // M-4: a plaintext is kept only while a later blind session of the
        // same pair secret could re-seal it.
        let plaintext = plaintext.filter(|_| lineage.is_some());
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
            Some(Internal::SessionInit) => 0,
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
                plaintext,
                lineage,
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

    /// `AckTracker::drop_plaintexts` under the tracker's own lock (M-4).
    pub(crate) fn ack_tracker_drop_plaintexts(&self, peer_hex: &str, lineage: Option<[u8; 32]>) {
        self.ack_tracker().drop_plaintexts(peer_hex, lineage);
    }

    /// `AckTracker::untrack` under the tracker's own lock.
    pub(crate) fn untrack_sent(&self, id_hex: &str) {
        self.ack_tracker().untrack(id_hex);
    }

    /// Re-send every tracked payload for `peer_hex` on its live circuit
    /// (spec §18.7 D35): identical bytes, re-wrapped for the current circuit.
    pub(crate) fn resend_tracked(&mut self, peer_hex: &str) {
        self.resend_tracked_among(peer_hex, None);
    }

    /// Ids tracked for `peer_hex`, in send order.
    pub(crate) fn tracked_ids_for(&self, peer_hex: &str) -> std::collections::HashSet<String> {
        self.ack_tracker().ids_for(peer_hex).into_iter().collect()
    }

    /// `resend_tracked`, limited to the ids in `among` when given. App
    /// messages sealed under an earlier session of the current session's
    /// pair-secret lineage (a blind re-pair since, §C.3) are first re-sealed
    /// under the current session with the same message id (R19): the peer
    /// keeps one retired session only, so after two re-pairs the old bytes
    /// would no longer decrypt; the peer drops a second copy of an id it
    /// already decrypted (`received_ids`). After an identity install the
    /// lineage differs and the old bytes are re-sent as before (AK4): only
    /// a holder of the old session can read them.
    pub(crate) fn resend_tracked_among(
        &mut self,
        peer_hex: &str,
        among: Option<&std::collections::HashSet<String>>,
    ) {
        if !self.has_live_circuit(peer_hex) {
            return;
        }
        // §A.4 (review M-3): the session-init is the first packet on a new
        // circuit. While ours is not out yet (its seal failed), nothing
        // tracked is re-sent; the tick re-sends once it is
        // (`redrive_owed_sends`).
        let init_pending = self.session_manager.get(peer_hex).is_some_and(|s| {
            s.init_out
                .as_ref()
                .is_some_and(|i| !matches!(&i.sent, Some(x) if !x.payload.is_empty()))
        });
        if init_pending {
            self.resend_after_init.insert(peer_hex.to_string());
            return;
        }
        self.resend_after_init.remove(peer_hex);
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
        // §A.4: a session-init the peer has not answered goes first, as its
        // first bytes, once per new transport, until the peer's first reply
        // or `ASK_TTL` (after which the peer can no longer open it).
        let epoch = self.transport_epoch;
        let init = self.session_manager.get(peer_hex).and_then(|s| {
            let sent = s.init_out.as_ref()?.sent.as_ref()?;
            // The peer may wait for it as long as the offline queue keeps
            // it (ruling R8: its wait counts online time, capped at 72 h).
            let fresh = crate::unix_now_secs().saturating_sub(s.created_at_unix)
                <= crate::circuits::PENDING_INIT_MAX_AGE_SECS;
            Some((
                hex::encode(sent.id),
                sent.payload.clone(),
                sent.epoch < epoch && fresh,
            ))
        });
        if let Some((init_id, payload, due)) = &init {
            if *due {
                let packet = RelayPacket::with_auth(
                    target.clone(),
                    payload.clone(),
                    PacketFlags {
                        encrypted: true,
                        ..Default::default()
                    },
                    &token,
                );
                if self.send_now(packet.encode_with_frame_type()).is_err() {
                    return; // nothing may overtake it
                }
                self.ack_tracker().note_attempt(init_id, target.clone());
                if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
                    if let Some(sent) = s.init_out.as_mut().and_then(|i| i.sent.as_mut()) {
                        sent.epoch = epoch;
                    }
                }
            }
        }
        let init_id = init.map(|(id, _, _)| id);
        self.reseal_tracked(peer_hex, &binding);
        let todo = self.ack_tracker().payloads_for(peer_hex);
        for (id, payload) in todo {
            if init_id.as_ref() == Some(&id) {
                continue; // handled above, once per transport
            }
            if among.is_some_and(|a| !a.contains(&id)) {
                continue; // tracked under the new session: not sent twice
            }
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

    /// R19: re-seal, under the current session (`binding`) and in send
    /// order, the peer's tracked app messages sealed under an earlier
    /// session of the same pair-secret lineage. Same message ids. A message
    /// that cannot be sealed now keeps its old bytes (and so does the rest,
    /// in order).
    fn reseal_tracked(&mut self, peer_hex: &str, binding: &[u8; 32]) {
        let Some(lineage) = self
            .session_manager
            .get(peer_hex)
            .filter(|s| s.can_send())
            .and_then(|s| s.pair_lineage())
        else {
            return;
        };
        let todo = self.ack_tracker().to_reseal(peer_hex, binding, &lineage);
        for (id_hex, plaintext) in todo {
            let Some(id) = crate::circuits::message_id_from_hex(&id_hex) else {
                continue;
            };
            match self.seal_ratchet(peer_hex, id, &plaintext) {
                Ok(packet) => self
                    .ack_tracker()
                    .resealed(&id_hex, packet.payload, *binding),
                Err(_) => {
                    log::debug!("[RUST] tracked message not re-sealed; old bytes kept");
                    break;
                }
            }
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
                Some(Internal::SessionInit) | None => {}
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
            Some(Internal::SessionInit) | None => {}
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
            Some(Internal::SessionInit) | None => return,
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
        self.track_sent(
            peer,
            &hex::encode(id),
            packet.circuit_id,
            packet.payload,
            pt,
        );
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
            plaintext: None,
            lineage: None,
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

    /// A maximum-size file's entry at its worst: the payload as large as
    /// the relay message, plus the kept plaintext (R19).
    fn max_file(peer: &str) -> Tracked {
        Tracked {
            payload: vec![0; crate::file_msg::RELAY_MAX_MESSAGE_BYTES],
            plaintext: Some(zeroize::Zeroizing::new(vec![
                0;
                crate::file_msg::MAX_FILE_PLAINTEXT
            ])),
            lineage: Some([1; 32]),
            ..t(peer, 0)
        }
    }

    /// R29: two maximum files and a text all stay tracked.
    #[test]
    fn r29_two_max_files_and_a_text_are_kept() {
        let mut a = AckTracker::default();
        assert!(a.track("f1".into(), max_file("p")).is_empty());
        assert!(a.track("t1".into(), t("p", 300)).is_empty());
        assert!(a.track("f2".into(), max_file("p")).is_empty());
        assert_eq!(a.len(), 3);
        assert_eq!(
            a.bytes(),
            300,
            "the text alone counts toward the small budget"
        );
    }

    /// R29: a 4th maximum file evicts only the oldest large entry; the
    /// text, older than all of them, survives.
    #[test]
    fn r29_fourth_max_file_evicts_only_the_oldest_large_entry() {
        let mut a = AckTracker::default();
        a.track("t1".into(), t("p", 300));
        for f in ["f1", "f2", "f3"] {
            assert!(a.track(f.into(), max_file("p")).is_empty(), "{f}");
        }
        let evicted = a.track("f4".into(), max_file("p"));
        assert_eq!(evicted, vec![("p".to_string(), "f1".to_string(), 1)]);
        assert_eq!(a.ids_for("p"), vec!["t1", "f2", "f3", "f4"]);
        assert!(a.large_bytes() <= MAX_TRACKED_LARGE_ACK_BYTES);
    }

    /// R29: filling the small budget never evicts a large entry.
    #[test]
    fn r29_small_eviction_never_touches_large_entries() {
        let mut a = AckTracker::default();
        a.track("f1".into(), max_file("p"));
        let mut evicted = Vec::new();
        for i in 0..1000 {
            evicted.extend(a.track(format!("s{i}"), t("p", 10_000)));
        }
        assert!(!evicted.is_empty(), "the small budget overflowed");
        assert!(evicted.iter().all(|(_, id, _)| id != "f1"));
        assert!(a.ids_for("p").contains(&"f1".to_string()));
        assert!(a.bytes() <= MAX_TRACKED_ACK_BYTES);
    }

    /// R29: the large budget is derived from the file limit.
    #[test]
    fn r29_large_budget_is_three_max_files() {
        use crate::file_msg::{MAX_FILE_PLAINTEXT, RELAY_MAX_MESSAGE_BYTES};
        assert_eq!(
            MAX_TRACKED_LARGE_ACK_BYTES,
            3 * (MAX_FILE_PLAINTEXT + RELAY_MAX_MESSAGE_BYTES)
        );
        assert_eq!(LARGE_ACK_PAYLOAD, 64 * 1024);
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
