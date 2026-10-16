//! Write-ahead persistence of core session state (spec §18.2, §18.4).

use crate::session::{ChatSession, RETIRED_MAX_AGE, RETIRED_MAX_DECRYPTS};
use crate::state_store::*;
use crate::status::StatusEvent;
use crate::{ClientInner, RChatError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

pub(crate) const MAX_RECEIVED_IDS: usize = 4096;
pub(crate) const MAX_DELIVERED_UNSTORED: usize = 1024;
/// Undecryptable ids kept per peer until reported.
pub(crate) const MAX_UNDECRYPTABLE: usize = 256;
/// Senders whose held bodies `retry_held` retries per tick.
pub(crate) const MAX_RETRY_SENDERS: usize = 32;

pub(crate) struct StateStore {
    pub(crate) keys: StateKeys,
    pub(crate) sink: Arc<dyn StateSink>,
    /// Last counter written per record; also the persist lock (D28).
    pub(crate) counters: std::sync::Mutex<HashMap<String, u64>>,
    /// Records whose last write failed. `StatePersistFailed` is raised when
    /// a record enters this set, not on every retry (ruling N3), and the
    /// record leaves it on its next successful write.
    pub(crate) failing: std::sync::Mutex<HashSet<String>>,
    /// Sealed records read from the store, opened at `connect()`
    /// (`restore_staged_state`). One entry per record key.
    pub(crate) staged: Vec<(String, Vec<u8>)>,
}

/// The counter in a sealed record's header (0 when too short to have one).
fn sealed_counter(sealed: &[u8]) -> u64 {
    sealed
        .get(6..14)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

impl StateStore {
    /// Stage one sealed record. For a key already staged the higher
    /// counter wins (D26): an older copy never replaces a newer one.
    pub(crate) fn stage_keep_higher(&mut self, key: String, sealed: Vec<u8>) {
        match self.staged.iter_mut().find(|(k, _)| *k == key) {
            Some(existing) => {
                if sealed_counter(&sealed) > sealed_counter(&existing.1) {
                    existing.1 = sealed;
                }
            }
            None => self.staged.push((key, sealed)),
        }
    }
}

/// A staged record, opened and checked against its key.
enum OpenedRecord {
    Meta(MetaRecordV1),
    Peer(Box<PeerRecordV2>),
}

/// Push with a FIFO cap; returns the entry evicted to make room.
pub(crate) fn push_capped(
    map: &mut HashMap<String, VecDeque<[u8; 16]>>,
    peer: &str,
    id: [u8; 16],
    cap: usize,
) -> Option<[u8; 16]> {
    let q = map.entry(peer.to_string()).or_default();
    let evicted = if q.len() >= cap { q.pop_front() } else { None };
    q.push_back(id);
    evicted
}

/// Undo the last `push_capped` exactly: the pushed id goes, the evicted
/// entry comes back at the front.
pub(crate) fn unpush_capped(
    map: &mut HashMap<String, VecDeque<[u8; 16]>>,
    peer: &str,
    evicted: Option<[u8; 16]>,
) {
    if let Some(q) = map.get_mut(peer) {
        q.pop_back();
        if let Some(e) = evicted {
            q.push_front(e);
        }
    }
}

/// Keep at most `MAX_RETRY_SENDERS` of `senders`, starting at `cursor`
/// (wrapping), and return the cursor for the next tick.
pub(crate) fn pick_retry_senders(senders: &mut Vec<String>, cursor: usize) -> usize {
    if senders.len() <= MAX_RETRY_SENDERS {
        return 0;
    }
    let start = cursor % senders.len();
    senders.rotate_left(start);
    senders.truncate(MAX_RETRY_SENDERS);
    start + MAX_RETRY_SENDERS
}

/// Add the ids not already in the peer's queue (capped). What is in memory
/// is kept: a second restore after `disconnect`/`connect` duplicates nothing.
fn merge_ids(
    map: &mut HashMap<String, VecDeque<[u8; 16]>>,
    peer: &str,
    ids: Vec<[u8; 16]>,
    cap: usize,
) {
    for id in ids {
        if !map.get(peer).is_some_and(|q| q.contains(&id)) {
            push_capped(map, peer, id, cap);
        }
    }
}

/// A current session rebuilt from its snapshot (None: the ratchet
/// snapshot was refused). Its circuit predates this run (epoch 0), so it is
/// resumed after the first accepted publish.
fn restored_session(
    hex: &str,
    our_ik: [u8; 32],
    peer_ik: [u8; 32],
    s: &SessionSnapshotV2,
    id: Option<&x25519_dalek::StaticSecret>,
) -> Option<ChatSession> {
    let mut session = ChatSession::new(hex.to_string());
    session.set_identities(our_ik, peer_ik);
    session.ratchet = Some(crate::crypto::DoubleRatchet::from_snapshot(&s.ratchet, id).ok()?);
    session.is_established = s.is_established;
    session.is_initiator = s.is_initiator;
    session.needs_hello_sync = s.needs_hello_sync;
    session.replaced_established = s.replaced_established;
    session.peer_notice_heard = s.peer_notice_heard;
    session.reset_since_unix = s.reset_since_unix;
    session.peer_ak = s.peer_ak;
    session.created_at_unix = s.created_at_unix;
    session.reported_lost = s
        .reported_lost
        .iter()
        .take(crate::circuits::MAX_SENT_IDS)
        .map(|(id, reason, eligible)| (*id, (*reason, *eligible)))
        .collect();
    session.session_binding = s.session_binding;
    session.pair_secret = s.pair_secret.as_ref().map(|p| zeroize::Zeroizing::new(p.0));
    session.pair_epoch = s.pair_epoch;
    session.blinded = s.blinded;
    session.blind_since_unix = s.blind_since_unix;
    session.last_identity_fallback_unix = s.last_identity_fallback_unix;
    session.init_out = match &s.init_out {
        Some(i) => Some(Box::new(crate::session::InitOut {
            ct: Box::new(i.ct.as_slice().try_into().ok()?),
            confirm: i.confirm,
            sent: i.sent_id.map(|id| crate::session::SentInit {
                id,
                payload: i.sent_payload.clone(),
                // Before this run: re-sent at the first opportunity.
                epoch: 0,
            }),
        })),
        None => None,
    };
    if let Some(c) = &s.circuit {
        session.set_circuit(
            crate::protocol::CircuitId(c.circuit_id),
            crate::protocol::CircuitId(c.target_circuit_id),
            c.token.to_vec(),
        );
    }
    session.circuit_epoch = 0;
    Some(session)
}

fn list(map: &HashMap<String, VecDeque<[u8; 16]>>, peer: &str) -> Vec<[u8; 16]> {
    map.get(peer)
        .map(|q| q.iter().copied().collect())
        .unwrap_or_default()
}

impl ClientInner {
    pub(crate) fn our_ik(&self) -> Option<[u8; 32]> {
        self.identity
            .as_ref()
            .map(|i| i.public_signing_key().to_bytes())
    }

    /// The peer's record as it would be written now (None: nothing to keep).
    pub(crate) fn peer_record(&self, peer_hex: &str) -> Option<PeerRecordV2> {
        let peer_ik = crate::peers::key_from_hex(peer_hex)?;
        let session = self.session_manager.get(peer_hex).and_then(|s| {
            Some(SessionSnapshotV2 {
                ratchet: s.ratchet_snapshot()?,
                is_established: s.is_established,
                is_initiator: s.is_initiator,
                needs_hello_sync: s.needs_hello_sync,
                circuit: match (&s.circuit_id, &s.target_circuit_id, s.get_token_key()) {
                    (Some(c), Some(t), Some(token)) => Some(CircuitV1 {
                        circuit_id: c.0,
                        target_circuit_id: t.0,
                        token,
                    }),
                    _ => None,
                },
                replaced_established: s.replaced_established,
                peer_notice_heard: s.peer_notice_heard,
                reset_since_unix: s.reset_since_unix,
                peer_ak: s.peer_ak,
                created_at_unix: s.created_at_unix,
                reported_lost: s
                    .reported_lost
                    .iter()
                    .map(|(id, (reason, eligible))| (*id, *reason, *eligible))
                    .collect(),
                session_binding: s.session_binding,
                init_out: s.init_out.as_ref().map(|i| {
                    // A claimed init whose bytes are not built yet is not sent.
                    let sent = i.sent.as_ref().filter(|x| !x.payload.is_empty());
                    InitOutV1 {
                        ct: i.ct.to_vec(),
                        confirm: i.confirm,
                        sent_id: sent.map(|x| x.id),
                        sent_payload: sent.map(|x| x.payload.clone()).unwrap_or_default(),
                    }
                }),
                pair_secret: s
                    .pair_secret
                    .as_ref()
                    .map(|p| crate::state_store::Secret32(**p)),
                pair_epoch: s.pair_epoch,
                blinded: s.blinded,
                blind_since_unix: s.blind_since_unix,
                last_identity_fallback_unix: s.last_identity_fallback_unix,
            })
        });
        let retired = self.session_manager.retired_parts(peer_hex).map(
            |(ratchet, retired_at_unix, decrypts, peer_ak)| RetiredSnapshotV1 {
                ratchet,
                retired_at_unix,
                decrypts,
                peer_ak,
            },
        );
        let rec = PeerRecordV2 {
            peer_ik,
            session,
            retired,
            sent_ids: self.sent_ids_for(peer_hex),
            received_ids: list(&self.received_ids, peer_hex),
            seen_ids: self.peers.seen_ids(peer_hex),
            owed_receipts: self.owed_receipts(peer_hex),
            delivered_unstored: list(&self.delivered_unstored, peer_hex),
            lost_unstored_ids: list(&self.lost_unstored, peer_hex),
            lost_reported: self
                .lost_reported
                .get(peer_hex)
                .map(|q| q.iter().copied().collect())
                .unwrap_or_default(),
            pending_send_ids: self.session_manager.pending_ids(peer_hex),
            undecryptable_ids: list(&self.undecryptable, peer_hex),
            notice_due: self.notice_due.contains(peer_hex),
            notice_flags: self.notice_flag_pending.get(peer_hex).copied().unwrap_or(0),
            auto_resends_unix: self
                .auto_resends
                .get(peer_hex)
                .map(|q| q.iter().copied().collect())
                .unwrap_or_default(),
            last_knock: self.knock_acted.get(peer_hex).copied(),
            steady_unheard: self.steady_unheard.get(peer_hex).copied().unwrap_or(0),
            timer: crate::disappearing::lock_timers(self)
                .get(peer_hex)
                .map(|t| crate::state_store::TimerV1 {
                    secs: t.secs,
                    changed_at_ms: t.changed_at_ms,
                    by_me: t.by_me,
                    acked: t.acked,
                    out_id: t.out_id,
                }),
            pending_init: self.pending_inits.get(peer_hex).map(|p| PendingInitV1 {
                kem_seed: p.kem_seed.to_vec(),
                ek_r: *p.ek_r.as_bytes(),
                i_ek: p.i_ek,
                peer_ak: p.peer_ak,
                circuit: CircuitV1 {
                    circuit_id: p.circuit_id.0,
                    target_circuit_id: p.target_circuit_id.0,
                    token: *p.token,
                },
                expires_at_unix: p.expires_at_unix,
                created_at_unix: p.created_at_unix,
                blind: p.origin == crate::blind::InstallOrigin::Blind,
            }),
        };
        let empty = rec.session.is_none()
            && rec.retired.is_none()
            && rec.sent_ids.is_empty()
            && rec.received_ids.is_empty()
            && rec.seen_ids.is_empty()
            && rec.owed_receipts.is_empty()
            && rec.delivered_unstored.is_empty()
            && rec.lost_unstored_ids.is_empty()
            && rec.lost_reported.is_empty()
            && rec.notice_flags == 0
            && rec.pending_send_ids.is_empty()
            && rec.undecryptable_ids.is_empty()
            && !rec.notice_due
            && rec.auto_resends_unix.is_empty()
            && rec.pending_init.is_none()
            && rec.last_knock.is_none()
            && rec.steady_unheard == 0
            && rec.timer.is_none();
        (!empty).then_some(rec)
    }

    /// The peer's last record write failed and no write has succeeded since.
    pub(crate) fn persist_failing(&self, peer_hex: &str) -> bool {
        let (Some(store), Some(peer_ik)) =
            (self.state.as_ref(), crate::peers::key_from_hex(peer_hex))
        else {
            return false;
        };
        let key = store.keys.record_key_for(&peer_ik);
        store
            .failing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key)
    }

    /// Raise `StatePersistFailed` for the first failure of an episode (N3).
    /// Called after the persist lock is released (no event under it).
    fn report_persist_failure(&self, first: bool, peer: Option<&str>) -> RChatError {
        if first {
            self.emit_status(StatusEvent::StatePersistFailed {
                peer: peer.map(str::to_string),
            });
        }
        RChatError::StatePersistFailed
    }

    /// Hand one sealed record (empty: delete) to the sink, under the
    /// persist lock. A record over `MAX_RECORD_BYTES` could never be
    /// restored, so it is a failure and is not written. `Err(first)`:
    /// whether this failure starts an episode.
    fn write_locked(
        store: &StateStore,
        _lock: &PersistLock<'_>,
        key: &str,
        sealed: Option<&[u8]>,
    ) -> Result<(), bool> {
        let mut failing = store.failing.lock().unwrap_or_else(|e| e.into_inner());
        match sealed {
            Some(sealed)
                if sealed.len() <= MAX_RECORD_BYTES && store.sink.write(key, sealed).is_ok() =>
            {
                failing.remove(key);
                Ok(())
            }
            _ => Err(failing.insert(key.to_string())),
        }
    }

    /// Tests: write `sealed` as the record `key` through the length check.
    #[cfg(test)]
    pub(crate) fn write_record(
        &self,
        key: &str,
        sealed: &[u8],
        peer: Option<&str>,
    ) -> Result<(), RChatError> {
        let Some(store) = self.state.as_ref() else {
            return Ok(());
        };
        let lock = PersistLock::take(store);
        let result = Self::write_locked(store, &lock, key, Some(sealed));
        drop(lock);
        result.map_err(|first| self.report_persist_failure(first, peer))
    }

    /// Write the peer's record before anything that depends on it (D28).
    /// Persistence off: Ok. An empty record is written as a delete.
    pub(crate) fn persist_peer(&self, peer_hex: &str) -> Result<(), RChatError> {
        let result = self.write_peer(peer_hex);
        if result.is_ok() {
            self.after_durable(peer_hex);
        }
        result
    }

    /// The peer's session is durable (after the persist lock is released):
    /// raise a `SessionReplaced` it owes, and write the meta record that
    /// drops the ask it answered.
    fn after_durable(&self, peer_hex: &str) {
        let (owed, answered) = self
            .session_manager
            .get_mut(peer_hex)
            .map(|mut s| {
                s.heard_unrecorded = false; // carried by this write
                (
                    std::mem::take(&mut s.replaced_unannounced),
                    std::mem::take(&mut s.ask_answered_unrecorded),
                )
            })
            .unwrap_or_default();
        if answered {
            self.persist_meta();
        }
        if owed {
            self.emit_status(crate::status::StatusEvent::SessionReplaced {
                peer: peer_hex.to_string(),
            });
        }
    }

    fn write_peer(&self, peer_hex: &str) -> Result<(), RChatError> {
        let (Some(store), Some(our_ik)) = (self.state.as_ref(), self.our_ik()) else {
            return Ok(());
        };
        let Some(peer_ik) = crate::peers::key_from_hex(peer_hex) else {
            return Ok(());
        };
        let key = store.keys.record_key_for(&peer_ik);
        // Held while the record is built and written (D28 lock order:
        // persist lock first, then the session maps).
        let mut lock = PersistLock::take(store);
        // D31: no skipped key past its 72 h reaches the record.
        self.session_manager
            .purge_expired_skipped_for(peer_hex, crate::unix_now_secs());
        let (sealed, counter) = match self.peer_record(peer_hex) {
            Some(rec) => match encode_body(&rec) {
                Ok(body) => {
                    let counter = lock.counters.get(&key).copied().unwrap_or(0) + 1;
                    (
                        Some(store.keys.seal(&our_ik, &key, KIND_PEER, counter, &body)),
                        Some(counter),
                    )
                }
                Err(_) => (None, None),
            },
            None => (Some(Vec::new()), None),
        };
        let result = Self::write_locked(store, &lock, &key, sealed.as_deref());
        if let (Ok(()), Some(counter)) = (&result, counter) {
            lock.counters.insert(key, counter);
        }
        drop(lock);
        result.map_err(|first| self.report_persist_failure(first, Some(peer_hex)))
    }

    /// Best effort (D28): closes, unanswered asks, held bodies.
    pub(crate) fn persist_meta(&self) {
        let (Some(store), Some(our_ik)) = (self.state.as_ref(), self.our_ik()) else {
            return;
        };
        let mut rec = MetaRecordV1 {
            pending_closes: self.pending_closes.iter().map(|c| c.0).collect(),
            // An ask answered by a session not yet on disk stays named: a
            // kill before that session's write must still find it (D33).
            unanswered_asks: self
                .unanswered_asks
                .keys()
                .cloned()
                .chain(
                    self.session_manager
                        .get_all_recipients()
                        .into_iter()
                        .filter(|p| {
                            !self.unanswered_asks.contains_key(p)
                                && self
                                    .session_manager
                                    .get(p)
                                    .is_some_and(|s| s.ask_answered_unrecorded)
                        }),
                )
                .filter_map(|p| crate::peers::key_from_hex(&p))
                .collect(),
            held: Vec::new(),
        };
        // Held bodies go in oldest first, up to what still fits in one
        // record; the rest stay in memory only (the held queue may hold
        // more than `MAX_RECORD_BYTES`, and the closes and asks must not be
        // lost with it).
        let base = bincode::serialized_size(&rec).map_or(u64::MAX, |n| n);
        let mut budget = (MAX_RECORD_BYTES - SEAL_OVERHEAD) as u64;
        budget = budget.saturating_sub(base);
        for h in &self.pending_encrypted_messages {
            let Some(sender_ik) = crate::peers::key_from_hex(&h.sender_hex) else {
                continue;
            };
            // sender_ik, message_id, the body's length prefix and the body.
            let cost = (32 + 16 + 8 + h.body.len()) as u64;
            if cost > budget {
                break;
            }
            budget -= cost;
            rec.held.push(HeldV1 {
                sender_ik,
                message_id: h.message_id,
                body: h.body.clone(),
            });
        }
        let mut lock = PersistLock::take(store);
        let counter = lock.counters.get(META_KEY).copied().unwrap_or(0) + 1;
        let sealed = encode_body(&rec).ok().map(|body| {
            store
                .keys
                .seal(&our_ik, META_KEY, KIND_META, counter, &body)
        });
        let result = Self::write_locked(store, &lock, META_KEY, sealed.as_deref());
        if result.is_ok() {
            lock.counters.insert(META_KEY.to_string(), counter);
        }
        drop(lock);
        if let Err(first) = result {
            self.report_persist_failure(first, None);
        }
    }

    /// Delete the peer's record (forget, unpin, re-pin, block). A failed
    /// delete raises `StatePersistFailed`; the restore then drops the record
    /// of a peer that is no longer pinned under the session's key.
    pub(crate) fn delete_peer_record(&self, peer_hex: &str) {
        let (Some(store), Some(peer_ik)) =
            (self.state.as_ref(), crate::peers::key_from_hex(peer_hex))
        else {
            return;
        };
        let key = store.keys.record_key_for(&peer_ik);
        self.delete_record(&key, Some(peer_hex));
    }

    fn delete_record(&self, key: &str, peer: Option<&str>) {
        let Some(store) = self.state.as_ref() else {
            return;
        };
        let lock = PersistLock::take(store);
        let result = Self::write_locked(store, &lock, key, Some(&[]));
        drop(lock);
        if let Err(first) = result {
            self.report_persist_failure(first, peer);
        }
    }

    /// Clear the per-peer tracking fields (every forget path), and
    /// the peer's tracked sends: sealed to keys no longer trusted (D35).
    /// The tick's flush of writes coalesced by M-1 (final review): the meta
    /// record once if a body was held since, and each peer record whose
    /// only change was a newly listed undecryptable id. Both are best
    /// effort under D28 (§18.4: "retried on the next tick"); no write-ahead
    /// write is ever deferred. Also starts the per-tick limits again.
    pub(crate) fn flush_deferred_writes(&mut self) {
        if std::mem::take(&mut self.meta_dirty) {
            self.persist_meta();
        }
        let dirty: Vec<String> = self.peers_dirty.drain().collect();
        for peer in dirty {
            let _ = self.persist_peer(&peer);
        }
        self.decrypt_failed_this_tick.clear();
    }

    pub(crate) fn clear_peer_tracking(&mut self, peer_hex: &str) {
        self.acks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drop_peer(peer_hex);
        self.received_ids.remove(peer_hex);
        self.delivered_unstored.remove(peer_hex);
        self.lost_unstored.remove(peer_hex);
        self.lost_reported.remove(peer_hex);
        self.undecryptable.remove(peer_hex);
        self.notice_due.remove(peer_hex);
        self.notice_flag_pending.remove(peer_hex);
        self.notice_send_stalled.remove(peer_hex);
        self.hello_sync_due.remove(peer_hex);
        self.auto_resends.remove(peer_hex);
        self.unanswered_asks.remove(peer_hex);
        self.reowes.retain(|(p, _), _| p != peer_hex);
        self.peers_dirty.remove(peer_hex);
        self.decrypt_failed_this_tick.remove(peer_hex);
    }

    /// Forget every session and staged record in memory (Reset Identity,
    /// our own rotation). The app deletes the stored records itself.
    pub(crate) fn clear_state_now(&mut self) {
        // Reset Identity / our own rotation: no ticket outlives the identity.
        self.tls_tickets.clear();
        if let Some(store) = self.state.as_mut() {
            store.staged.clear();
            store
                .failing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
        self.session_manager.forget_all();
        self.pending_inits.clear();
        self.resend_after_init.clear();
        // Everything kept for the identity's contacts goes with it.
        self.sent_ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.pending_receipts.clear();
        self.receipt_due.clear();
        self.pending_encrypted_messages.clear();
        self.pending_closes.clear();
        self.deferred_asks.clear();
        self.pending_reasks.clear();
        self.intros.clear();
        self.rotated_from.clear();
        self.last_heard.clear();
        self.cover_sent.clear();
        self.cover_replies_due.clear();
        self.cover_replies_charged.clear();
        self.retry_cursor = 0;
        self.received_ids.clear();
        self.delivered_unstored.clear();
        self.lost_unstored.clear();
        self.lost_reported.clear();
        self.undecryptable.clear();
        self.notice_due.clear();
        self.notice_flag_pending.clear();
        self.notice_send_stalled.clear();
        self.last_redrive_probe = None;
        self.hello_sync_due.clear();
        self.retrying_held = false;
        self.auto_resends.clear();
        self.unanswered_asks.clear();
        self.reowes.clear();
        self.meta_dirty = false;
        self.peers_dirty.clear();
        self.decrypt_failed_this_tick.clear();
        // Sealed payloads to the old identity's contacts (spec §18.7 D35).
        *self.acks.lock().unwrap_or_else(|e| e.into_inner()) = Default::default();
    }

    /// Open and apply the staged records (spec §18.5). Called by `connect()`
    /// once the identity is loaded and the staged peer book adopted, before
    /// the transport opens. A record that does not open, or does not match
    /// its key, is reported (`StateRestoreFailed`) and deleted.
    pub(crate) fn restore_staged_state(&mut self) {
        let Some(our_ik) = self.our_ik() else {
            return;
        };
        let Some(store) = self.state.as_mut() else {
            return;
        };
        let staged = std::mem::take(&mut store.staged);
        let identity_secret = self.identity.as_ref().map(|i| i.agreement_secret().clone());
        for (key, sealed) in staged {
            let applied = match self.open_staged(&our_ik, &key, &sealed) {
                Ok(OpenedRecord::Meta(m)) => {
                    self.apply_meta(m);
                    Ok(())
                }
                Ok(OpenedRecord::Peer(rec)) => {
                    let peer = hex::encode(rec.peer_ik);
                    if self.apply_peer(*rec, identity_secret.as_ref()) {
                        Ok(())
                    } else {
                        Err((RestoreError::Parse, Some(peer)))
                    }
                }
                Err(e) => Err((e, None)),
            };
            if let Err((reason, peer)) = applied {
                self.emit_status(StatusEvent::StateRestoreFailed {
                    reason: reason as u8,
                });
                self.delete_record(&key, peer.as_deref());
            }
        }
        // Waits too old to answer (R8), dropped while the records were
        // applied: closed and re-asked now that meta and every peer record
        // are in memory, so the writes below carry all of it (review N-1).
        for (peer, circuit) in std::mem::take(&mut self.abandoned_at_restore) {
            self.close_circuit_id(&circuit);
            let _ = self.persist_peer(&peer);
            if self.require_askable(&peer).is_ok() {
                self.schedule_reask(&peer);
            }
        }
    }

    /// Open one staged record and check it against its key: the meta key
    /// holds only the meta kind, a peer key only the record of the peer it
    /// is derived from. Seeds the record's counter, so the next write of it
    /// follows every copy staged (D26).
    fn open_staged(
        &self,
        our_ik: &[u8; 32],
        key: &str,
        sealed: &[u8],
    ) -> Result<OpenedRecord, RestoreError> {
        let store = self.state.as_ref().ok_or(RestoreError::Parse)?;
        let (kind, counter, body) = store.keys.open(our_ik, key, sealed)?;
        let opened = match kind {
            KIND_META if key == META_KEY => {
                OpenedRecord::Meta(bincode::deserialize(&body).map_err(|_| RestoreError::Parse)?)
            }
            KIND_PEER if key != META_KEY => {
                let rec: PeerRecordV2 =
                    bincode::deserialize(&body).map_err(|_| RestoreError::Parse)?;
                if store.keys.record_key_for(&rec.peer_ik) != key {
                    return Err(RestoreError::Parse);
                }
                OpenedRecord::Peer(Box::new(rec))
            }
            _ => return Err(RestoreError::Parse),
        };
        let mut counters = store.counters.lock().unwrap_or_else(|e| e.into_inner());
        let seeded = counters.entry(key.to_string()).or_insert(0);
        *seeded = (*seeded).max(counter);
        Ok(opened)
    }

    /// Apply one peer record. True once handled, including the delete of a
    /// record nobody should keep (peer no longer pinned, blocked, or its
    /// session made under another pin, C-1); false: the record is unusable.
    fn apply_peer(&mut self, rec: PeerRecordV2, id: Option<&x25519_dalek::StaticSecret>) -> bool {
        let hex = hex::encode(rec.peer_ik);
        let Some(pinned_ak) = self.peers.pin_for(&hex) else {
            self.delete_peer_record(&hex);
            return true;
        };
        let other_pin = |ak: &[u8; 32]| !constant_time_eq::constant_time_eq(ak, &pinned_ak);
        let other_pin = rec.session.as_ref().is_some_and(|s| other_pin(&s.peer_ak))
            || rec.retired.as_ref().is_some_and(|r| other_pin(&r.peer_ak))
            || rec
                .pending_init
                .as_ref()
                .is_some_and(|p| other_pin(&p.peer_ak));
        if self.peers.is_blocked(&hex) || other_pin {
            self.delete_peer_record(&hex);
            return true;
        }
        let Some(our_ik) = self.our_ik() else {
            return false;
        };
        let current = match &rec.session {
            Some(s) => match restored_session(&hex, our_ik, rec.peer_ik, s, id) {
                Some(c) => Some(c),
                None => return false,
            },
            None => None,
        };
        // A retired session past its limits (wall clock, SP12) is dropped.
        let now = crate::unix_now_secs();
        let retired = match &rec.retired {
            Some(r)
                if r.decrypts < RETIRED_MAX_DECRYPTS
                    && now.saturating_sub(r.retired_at_unix) <= RETIRED_MAX_AGE.as_secs() =>
            {
                let Ok(ratchet) = crate::crypto::DoubleRatchet::from_snapshot(&r.ratchet, id)
                else {
                    return false;
                };
                let mut session = ChatSession::new(hex.clone());
                session.set_identities(our_ik, rec.peer_ik);
                session.ratchet = Some(ratchet);
                session.is_established = true;
                session.peer_ak = r.peer_ak;
                // A future stamp (the clock stepped back) counts from now.
                Some((session, r.retired_at_unix.min(now), r.decrypts))
            }
            _ => None,
        };
        self.session_manager
            .install_restored(hex.clone(), current, retired);
        // Review N-2: a session whose session-init was never sealed owes the
        // hello that carries it (`hello_sync_due` is not persisted), or the
        // M-3 hold would keep tracked re-sends back until the app sends.
        let init_unsent = self.session_manager.get(&hex).is_some_and(|s| {
            s.init_out
                .as_ref()
                .is_some_and(|i| !matches!(&i.sent, Some(x) if !x.payload.is_empty()))
        });
        if init_unsent {
            self.hello_sync_due.insert(hex.clone());
        }
        // A session-init still awaited (§A.3); one in memory is newer than
        // the record. The wait counts online time only (R8): it is pushed
        // back to now + ASK_TTL, unless it is older than the offline queue,
        // when it is dropped like any expired wait (closed, re-asked).
        if let Some(p) = &rec.pending_init {
            if p.kem_seed.len() != crate::kem::KEM_SEED_LEN {
                return false;
            }
            let mut seed = zeroize::Zeroizing::new([0u8; crate::kem::KEM_SEED_LEN]);
            seed.copy_from_slice(&p.kem_seed);
            if !self.pending_inits.contains_key(&hex) {
                let mut ek_bytes = p.ek_r;
                let ek_r = crate::crypto::X25519SecretKey::from(ek_bytes);
                zeroize::Zeroize::zeroize(&mut ek_bytes);
                self.pending_inits.insert(
                    hex.clone(),
                    crate::circuits::PendingInit {
                        kem: crate::kem::KemKeyPair::from_seed(&seed),
                        kem_seed: seed,
                        ek_r,
                        i_ek: p.i_ek,
                        peer_ak: p.peer_ak,
                        circuit_id: crate::protocol::CircuitId(p.circuit.circuit_id),
                        target_circuit_id: crate::protocol::CircuitId(p.circuit.target_circuit_id),
                        token: zeroize::Zeroizing::new(p.circuit.token),
                        // Before this run: resumed after the first publish.
                        circuit_epoch: 0,
                        expires_at_unix: p.expires_at_unix,
                        created_at_unix: p.created_at_unix.min(crate::unix_now_secs()),
                        origin: if p.blind {
                            crate::blind::InstallOrigin::Blind
                        } else {
                            crate::blind::InstallOrigin::Identity
                        },
                    },
                );
                let now = crate::unix_now_secs();
                let too_old = self.pending_inits.get(&hex).is_some_and(|w| w.too_old(now));
                if too_old {
                    // Dropped in memory only (review N-1): the close and the
                    // re-ask wait until every staged record is applied, so no
                    // write here carries a half-merged peer record or a meta
                    // record from before the staged one.
                    if let Some(w) = self.pending_inits.remove(&hex) {
                        self.abandoned_at_restore
                            .push((hex.clone(), w.circuit_id.clone()));
                    }
                } else if let Some(w) = self.pending_inits.get_mut(&hex) {
                    w.refresh(now);
                }
            }
        }

        // Merged with what is in memory, which is never older than the
        // record: a second restore (after `disconnect`/`connect`) adds nothing twice.
        if !rec.sent_ids.is_empty() {
            // The list is oldest first (the cap evicts from the front), so a
            // record id goes in by its send time, not at the back, and the
            // cap then drops the oldest entry of the merged list.
            let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
            let q = all.entry(hex.clone()).or_default();
            for s in rec.sent_ids {
                if q.iter().any(|m| m.id == s.id) {
                    continue;
                }
                let at = q
                    .iter()
                    .rposition(|m| m.sent_at_unix <= s.sent_at_unix)
                    .map_or(0, |i| i + 1);
                q.insert(at, s);
                if q.len() > crate::circuits::MAX_SENT_IDS {
                    q.pop_front();
                }
            }
        }
        for id in rec.seen_ids {
            self.peers.mark_seen(&hex, id);
        }
        merge_ids(
            &mut self.received_ids,
            &hex,
            rec.received_ids,
            MAX_RECEIVED_IDS,
        );
        for (kind, id) in rec.owed_receipts {
            if kind == crate::receipts::DELIVERED || kind == crate::receipts::READ {
                let q = self
                    .pending_receipts
                    .entry((hex.clone(), kind))
                    .or_default();
                if !q.contains(&id) {
                    q.push(id);
                }
            }
        }
        // R26: restored exactly. Only a peer that was already out of the
        // draw starts out of it; no peer is paused because of the restart.
        if rec.steady_unheard > 0 {
            let e = self.steady_unheard.entry(hex.clone()).or_insert(0);
            *e = (*e).max(rec.steady_unheard);
        }
        // §I.2: a timer never set again since the record was written is
        // restored as it was (a value outside the choices is ignored).
        if let Some(t) = rec.timer {
            let mut timers = crate::disappearing::lock_timers(self);
            if crate::disappearing::valid_timer(t.secs) && !timers.contains_key(&hex) {
                timers.insert(
                    hex.clone(),
                    crate::disappearing::PeerTimer {
                        secs: t.secs,
                        changed_at_ms: t.changed_at_ms,
                        by_me: t.by_me,
                        acked: t.acked,
                        out_id: t.out_id,
                        resends: 0,
                    },
                );
            }
        }
        if let Some(k) = rec.last_knock {
            let e = self.knock_acted.entry(hex.clone()).or_insert(k);
            if k.0 > e.0 {
                *e = k;
            }
        }
        if !rec.auto_resends_unix.is_empty() && !self.auto_resends.contains_key(&hex) {
            self.auto_resends
                .insert(hex.clone(), rec.auto_resends_unix.into_iter().collect());
        }
        merge_ids(
            &mut self.undecryptable,
            &hex,
            rec.undecryptable_ids,
            MAX_UNDECRYPTABLE,
        );
        if rec.notice_due {
            self.notice_due.insert(hex.clone());
        }
        // Handed to the app before the restart and never confirmed stored
        // (§18.5 step 4): lost, and the peer is owed a notice. One the app
        // marked seen was stored; one handed over in this run (still in
        // memory) may yet be stored, so it stays delivered-unstored.
        merge_ids(
            &mut self.lost_unstored,
            &hex,
            rec.lost_unstored_ids,
            MAX_DELIVERED_UNSTORED,
        );
        let now_unix = crate::unix_now_secs();
        for (id, at) in rec.lost_reported {
            // Expired entries go at restore too (72 h, future stamps → now).
            let at = at.min(now_unix);
            if now_unix.saturating_sub(at) <= crate::circuits::RESET_REPORT_MAX_AGE_SECS {
                self.list_lost_reported(&hex, id, at);
            }
        }
        if rec.notice_flags != 0 {
            *self.notice_flag_pending.entry(hex.clone()).or_insert(0) |= rec.notice_flags;
        }
        let mut lost_now = false;
        for id in rec.delivered_unstored {
            let in_this_run = self
                .delivered_unstored
                .get(&hex)
                .is_some_and(|q| q.contains(&id));
            let known_lost = self
                .lost_unstored
                .get(&hex)
                .is_some_and(|q| q.contains(&id));
            if !self.peers.is_seen(&hex, &id) && !in_this_run && !known_lost {
                push_capped(&mut self.lost_unstored, &hex, id, MAX_DELIVERED_UNSTORED);
                lost_now = true;
            }
        }
        if lost_now {
            self.notice_due.insert(hex.clone());
        }
        // Messages queued for the peer lived in memory only.
        for id in rec.pending_send_ids {
            self.emit_status(StatusEvent::QueuedSendLost {
                peer: hex.clone(),
                message_id: hex::encode(id),
            });
        }
        // Durable at once, so delivered → lost survives a second crash (F4).
        let _ = self.persist_peer(&hex);
        true
    }

    /// Apply the meta record: closes still owed, asks that had no answer
    /// (sent after the first accepted publish), and held bodies (re-held
    /// without a re-ask; the tick retries those whose sender has a session).
    fn apply_meta(&mut self, m: MetaRecordV1) {
        for id in m.pending_closes {
            let cid = crate::protocol::CircuitId(id);
            if !self.pending_closes.contains(&cid)
                && self.pending_closes.len() < crate::circuits::MAX_PENDING_CLOSES
            {
                self.pending_closes.push(cid);
            }
        }
        for ik in m.unanswered_asks {
            let peer = hex::encode(ik);
            if self.require_askable(&peer).is_err() {
                continue;
            }
            // Still unanswered: kept in the next meta write, and re-sent
            // uncounted after the publish (spec §18.6 D33). Epoch 0 is
            // before any connection, so it never suppresses a user ask.
            self.unanswered_asks
                .entry(peer.clone())
                .or_insert((std::time::Instant::now(), 0));
            if !self.deferred_asks.contains(&peer) {
                self.deferred_asks.push(peer);
            }
        }
        for h in m.held {
            let sender_hex = hex::encode(h.sender_ik);
            let held_already = self
                .pending_encrypted_messages
                .iter()
                .any(|p| p.sender_hex == sender_hex && p.message_id == h.message_id);
            if !held_already {
                self.push_held_capped(crate::PendingEncrypted {
                    sender_hex,
                    message_id: h.message_id,
                    body: h.body,
                });
            }
        }
    }

    /// Retry held bodies of peers that have an established session (spec
    /// §18.4: a body whose write failed). Considers every distinct such
    /// sender in the held queue (itself capped at `MAX_PENDING_ENCRYPTED`),
    /// at most `MAX_RETRY_SENDERS` per tick, rotating between ticks so no
    /// sender is starved by others' bodies (bodies of senders without a
    /// session, or whose writes keep failing). Each sender's oldest body
    /// goes first, alone; only once it is through (delivered or dropped) do
    /// the sender's other bodies follow. So while a sender's writes keep
    /// failing, one body per tick is tried, not all of them.
    pub(crate) fn retry_held(&mut self) {
        let mut senders: Vec<String> = Vec::new();
        for h in &self.pending_encrypted_messages {
            if !senders.contains(&h.sender_hex)
                && self.session_manager.has_established_session(&h.sender_hex)
            {
                senders.push(h.sender_hex.clone());
            }
        }
        self.retry_cursor = pick_retry_senders(&mut senders, self.retry_cursor);
        let mut released = false;
        for peer in senders {
            let Some(pos) = self
                .pending_encrypted_messages
                .iter()
                .position(|h| h.sender_hex == peer)
            else {
                continue;
            };
            let Some(oldest) = self.pending_encrypted_messages.remove(pos) else {
                continue;
            };
            match self.try_ratchet(&oldest.sender_hex, oldest.message_id, &oldest.body, true) {
                // Still failing: back in its place, retried next tick.
                Err(held) => self.pending_encrypted_messages.insert(pos, held),
                Ok(()) => {
                    let (mine, rest): (VecDeque<_>, VecDeque<_>) =
                        std::mem::take(&mut self.pending_encrypted_messages)
                            .into_iter()
                            .partition(|h| h.sender_hex == peer);
                    self.pending_encrypted_messages = rest;
                    self.release_held(mine.into());
                    released = true;
                }
            }
        }
        // Bodies left the held queue: the meta record follows (once).
        if released {
            self.persist_meta();
        }
    }
}

/// The persist lock (D28): the counters mutex. Tests also check that no
/// status event is raised while it is held.
pub(crate) struct PersistLock<'a> {
    pub(crate) counters: std::sync::MutexGuard<'a, HashMap<String, u64>>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static PERSIST_LOCK_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl<'a> PersistLock<'a> {
    fn take(store: &'a StateStore) -> Self {
        let counters = store.counters.lock().unwrap_or_else(|e| e.into_inner());
        #[cfg(test)]
        PERSIST_LOCK_HELD.with(|h| h.set(true));
        Self { counters }
    }
}

impl Drop for PersistLock<'_> {
    fn drop(&mut self) {
        #[cfg(test)]
        PERSIST_LOCK_HELD.with(|h| h.set(false));
    }
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;
