//! Knock store (spec §5.3, H3). Knocks sit in the recipient's offline queue
//! (`StoredMessage { is_knock: true, .. }`) but are accounted here, never
//! against the offline budget (`RelayState::offline_budget`):
//! * a global byte budget — when full, the oldest knock of the *heaviest
//!   source* (by stored bytes) goes, so one source cannot flush everyone
//!   else's knocks (R-2);
//! * each source (keyed IPv4 address / IPv6 /48 of the asking connection)
//!   may hold at most `budget / KNOCK_SOURCE_SHARES` bytes — beyond that its
//!   own oldest knock goes;
//! * at most `MAX_KNOCKS_PER_RECIPIENT` per recipient — the oldest knock of
//!   the source holding most of that recipient's knocks goes;
//! * at most one queued knock per (recipient, pair) — a newer one replaces it
//!   in place with a fresh `enqueued_at`;
//! * each asker may start `ASKER_QUOTA` new asks with a knock per
//!   `QUOTA_WINDOW` (`charge_asker`; a counter only, no targets recorded).
//!   The charge is taken before delivery, identically whether the target is
//!   online (live) or not (store), so the quota reveals no presence. The
//!   quota table holds at most `QUOTA_TABLE_CAP` askers (R-4); one source
//!   may hold at most `cap / QUOTA_SOURCE_SHARES` of them, and a full table
//!   drops the oldest asker of the source holding the most (M-2), so no
//!   one source can deny first contact relay-wide.
//!
//! Knocks restored from disk, re-queued after a failed drain or salvaged
//! from a closed connection have no live source; they share their own
//! bucket (`RESTORED_SOURCE`), apart from unattributed connections (`None`).
//! A full store or recipient cap evicts a knock only from the caller's own
//! bucket or from one holding more than the caller would (L-1).
//!
//! The pair index is memory-only and never persisted.
//!
//! Lock order: `inner` before any `queues` shard, never the reverse.

use super::tags::{IdTag, PairTag};
use super::{expired, MessageQueue, StoredMessage};
use crate::limits::SourceKey;
use crate::metrics;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

pub(crate) const MAX_KNOCKS_PER_RECIPIENT: usize = 200;
pub(crate) const ASKER_QUOTA: u32 = 100;
pub(crate) const QUOTA_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// One source may hold at most `budget / KNOCK_SOURCE_SHARES` knock bytes
/// (default budget 16 MiB: 1 MiB, 512 knocks).
pub(crate) const KNOCK_SOURCE_SHARES: usize = 16;
/// Most askers the 24 h quota table tracks (~100 B each, R-4). When full
/// (after pruning ended windows), the oldest asker of the heaviest source
/// is forgotten to make room (M-2).
pub(crate) const QUOTA_TABLE_CAP: usize = 1 << 20;
/// One known source may hold at most `cap / QUOTA_SOURCE_SHARES` askers in
/// the quota table (default 65,536 new identities per 24 h); its further
/// new askers get no knock until its entries' windows end (M-2).
pub(crate) const QUOTA_SOURCE_SHARES: usize = 16;

/// One asker's quota window.
struct QuotaEntry {
    asks: u32,
    start: Instant,
    /// Source of the connection that first charged it (fixed).
    source: Option<SourceKey>,
}

/// The asker-quota table, with each source's askers oldest first.
#[derive(Default)]
struct Quota {
    map: HashMap<IdTag, QuotaEntry>,
    by_source: HashMap<Option<SourceKey>, VecDeque<IdTag>>,
}

impl Quota {
    fn source_len(&self, source: &Option<SourceKey>) -> usize {
        self.by_source.get(source).map_or(0, VecDeque::len)
    }

    /// Forget askers whose window has ended.
    fn prune(&mut self, now: Instant) {
        let before = self.map.len();
        self.map
            .retain(|_, e| now.saturating_duration_since(e.start) <= QUOTA_WINDOW);
        if self.map.len() == before {
            return;
        }
        let map = &self.map;
        self.by_source.retain(|source, askers| {
            askers.retain(|t| map.get(t).is_some_and(|e| e.source == *source));
            !askers.is_empty()
        });
    }

    /// Forget the oldest asker of the source holding the most. False if
    /// the table is empty.
    fn evict_heaviest(&mut self) -> bool {
        let Some(source) = self
            .by_source
            .iter()
            .max_by_key(|(_, askers)| askers.len())
            .map(|(s, _)| *s)
        else {
            return false;
        };
        let Some(askers) = self.by_source.get_mut(&source) else {
            return false;
        };
        let victim = askers.pop_front();
        if askers.is_empty() {
            self.by_source.remove(&source);
        }
        match victim {
            Some(t) => {
                self.map.remove(&t);
                true
            }
            None => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnockOutcome {
    Queued,
    Replaced,
    /// Not stored: making room would have evicted a knock of a source
    /// holding no more than the caller would (L-1).
    Dropped,
}

/// The bucket of knocks with no live source: restored from disk, re-queued
/// after a failed drain, or salvaged from a closed connection (L-1). Kept
/// apart from unattributed live connections (`None`), so a flood from
/// those does not evict restored knocks first; salvaged knocks are held to
/// a source share like any other. A real `SourceKey` is a keyed hash, so
/// it never equals this value in practice.
pub(crate) const RESTORED_SOURCE: Option<SourceKey> = Some(SourceKey([0xff; 32]));

struct Entry {
    recipient: IdTag,
    pair: Option<PairTag>,
    bytes: usize,
    source: Option<SourceKey>,
}

/// Knocks stored on behalf of one source bucket.
#[derive(Default)]
struct Bucket {
    bytes: usize,
    seqs: BTreeSet<u64>,
}

struct Inner {
    used: usize,
    next_seq: u64,
    /// Every accounted knock, oldest first.
    order: BTreeMap<u64, Entry>,
    by_pair: HashMap<(IdTag, PairTag), u64>,
    per_recipient: HashMap<IdTag, usize>,
    by_source: HashMap<Option<SourceKey>, Bucket>,
}

pub(crate) struct KnockStore {
    budget_bytes: usize,
    /// Most bytes one (known) source may hold.
    source_share: usize,
    quota_cap: usize,
    inner: Mutex<Inner>,
    /// Asker tag -> new asks charged in its window. Independent of the
    /// queues; entries go once their window has ended (`prune_quota`).
    quota: Mutex<Quota>,
}

impl KnockStore {
    pub fn new(budget_bytes: usize) -> Self {
        Self::with_quota_cap(budget_bytes, QUOTA_TABLE_CAP)
    }

    pub fn with_quota_cap(budget_bytes: usize, quota_cap: usize) -> Self {
        Self {
            budget_bytes,
            source_share: (budget_bytes / KNOCK_SOURCE_SHARES).max(crate::validate::KNOCK_BYTES),
            quota_cap,
            inner: Mutex::new(Inner {
                used: 0,
                next_seq: 1,
                order: BTreeMap::new(),
                by_pair: HashMap::new(),
                per_recipient: HashMap::new(),
                by_source: HashMap::new(),
            }),
            quota: Mutex::new(Quota::default()),
        }
    }

    /// Charge `asker`, asking from `source`, for a new ask that carries a
    /// knock. False when its quota for the window is spent, or when it is a
    /// new asker and its source already holds its share of the table: the
    /// caller then drops the knock on every path (no live send, no store).
    /// Never depends on the target.
    pub fn charge_asker(&self, asker: IdTag, source: Option<SourceKey>, now: Instant) -> bool {
        let mut guard = self.quota.lock();
        let q = &mut *guard;
        if !q.map.contains_key(&asker) {
            let share = (self.quota_cap / QUOTA_SOURCE_SHARES).max(1);
            if source.is_some() && q.source_len(&source) >= share {
                q.prune(now);
                if q.source_len(&source) >= share {
                    metrics::reject(metrics::REJECT_KNOCK_QUOTA);
                    return false;
                }
            }
            if q.map.len() >= self.quota_cap {
                q.prune(now);
            }
            while q.map.len() >= self.quota_cap {
                if !q.evict_heaviest() {
                    metrics::reject(metrics::REJECT_KNOCK_QUOTA);
                    return false;
                }
            }
            q.map.insert(
                asker,
                QuotaEntry {
                    asks: 0,
                    start: now,
                    source,
                },
            );
            q.by_source.entry(source).or_default().push_back(asker);
        }
        let Some(e) = q.map.get_mut(&asker) else {
            return false;
        };
        if now.saturating_duration_since(e.start) > QUOTA_WINDOW {
            e.asks = 0;
            e.start = now;
        }
        if e.asks >= ASKER_QUOTA {
            metrics::reject(metrics::REJECT_KNOCK_QUOTA);
            return false;
        }
        e.asks += 1;
        true
    }

    /// Forget askers whose quota window has ended (same strict comparison
    /// as the reset in `charge_asker`).
    pub fn prune_quota(&self, now: Instant) {
        self.quota.lock().prune(now);
    }

    /// Queue a knock for `recipient` (the asker's quota was charged by the
    /// caller) on behalf of the asking connection's `source`. Replaces the
    /// queued knock of the same pair, if any.
    pub fn enqueue(
        &self,
        recipient: IdTag,
        pair: Option<PairTag>,
        payload: Vec<u8>,
        now_unix: u64,
        queues: &DashMap<IdTag, MessageQueue>,
        source: Option<SourceKey>,
    ) -> KnockOutcome {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;

        if let Some(p) = pair {
            if let Some(old) = inner.by_pair.get(&(recipient, p)).copied() {
                let seq = inner.next_seq;
                inner.next_seq += 1;
                let replaced = queues
                    .get_mut(&recipient)
                    .map(|mut q| {
                        match q
                            .pending
                            .iter_mut()
                            .find(|m| m.is_knock && m.knock_seq == old)
                        {
                            Some(m) => {
                                m.payload = payload.clone();
                                m.enqueued_at_unix_secs = now_unix;
                                m.knock_seq = seq;
                                true
                            }
                            None => false,
                        }
                    })
                    .unwrap_or(false);
                if replaced {
                    if let Some(mut e) = inner.order.remove(&old) {
                        bucket_remove(inner, e.source, old, e.bytes);
                        inner.used = inner.used - e.bytes + payload.len();
                        e.bytes = payload.len();
                        e.source = source;
                        bucket_add(inner, source, seq, e.bytes);
                        inner.order.insert(seq, e);
                    }
                    inner.by_pair.insert((recipient, p), seq);
                    return KnockOutcome::Replaced;
                }
                // The indexed record is gone (delivered or evicted): drop the
                // stale entry and treat this as a new knock.
                forget(inner, old);
            }
        }

        if inner.per_recipient.get(&recipient).copied().unwrap_or(0) >= MAX_KNOCKS_PER_RECIPIENT {
            // The recipient's oldest knock from the source that holds most
            // of its knocks: a flood aimed at one recipient evicts itself.
            // A source holding no more of them than the caller would after
            // this knock is not evicted for it; the new knock is dropped
            // (L-1: many one-knock sources cannot flush older requests).
            let mut tally: HashMap<Option<SourceKey>, (usize, u64)> = HashMap::new();
            for (seq, e) in inner.order.iter().filter(|(_, e)| e.recipient == recipient) {
                tally.entry(e.source).or_insert((0, *seq)).0 += 1;
            }
            let own = tally.remove(&source);
            let other = tally
                .into_iter()
                .max_by_key(|(_, (n, seq))| (*n, std::cmp::Reverse(*seq)))
                .map(|(_, v)| v);
            let own_n = own.map_or(0, |(n, _)| n);
            match (other, own) {
                (Some((n, seq)), _) if n > own_n + 1 => evict(inner, seq, queues),
                (_, Some((_, seq))) => evict(inner, seq, queues),
                _ => {
                    metrics::reject(metrics::REJECT_KNOCK_EVICTED);
                    return KnockOutcome::Dropped;
                }
            }
        }
        if source.is_some() {
            // A source over its share makes room from its own knocks.
            while inner
                .by_source
                .get(&source)
                .is_some_and(|b| b.bytes + payload.len() > self.source_share)
            {
                let Some(seq) = inner
                    .by_source
                    .get(&source)
                    .and_then(|b| b.seqs.first().copied())
                else {
                    break;
                };
                evict(inner, seq, queues);
            }
        }
        while inner.used + payload.len() > self.budget_bytes {
            // Who pays for a full store, in order (R-2, L-1, N-5):
            // 1. a source holding more than the caller would after this
            //    knock (the heaviest, its oldest knock);
            // 2. else the caller's own bucket, if it holds any;
            // 3. else the heaviest source anyway - among equally heavy ones
            //    the one with the oldest knock - so a store filled by many
            //    one-knock sources still takes new knocks, oldest out first,
            //    instead of refusing first contact relay-wide until they
            //    expire. Never decided by map order.
            let (own_bytes, own_oldest) = inner
                .by_source
                .get(&source)
                .map_or((0, None), |b| (b.bytes, b.seqs.first().copied()));
            let other = inner
                .by_source
                .iter()
                .filter(|(s, _)| **s != source)
                .filter_map(|(_, b)| Some((b.bytes, b.seqs.first().copied()?)))
                .max_by_key(|(held, seq)| (*held, std::cmp::Reverse(*seq)));
            match (other, own_oldest) {
                (Some((held, seq)), _) if held > own_bytes + payload.len() => {
                    evict(inner, seq, queues)
                }
                (_, Some(seq)) => evict(inner, seq, queues),
                (Some((_, seq)), None) => evict(inner, seq, queues),
                (None, None) => {
                    metrics::reject(metrics::REJECT_KNOCK_EVICTED);
                    return KnockOutcome::Dropped;
                }
            }
        }

        let seq = inner.next_seq;
        inner.next_seq += 1;
        let bytes = payload.len();
        queues
            .entry(recipient)
            .or_insert_with(|| MessageQueue {
                pending: Vec::new(),
                bytes: 0,
            })
            .pending
            .push(StoredMessage {
                payload,
                enqueued_at_unix_secs: now_unix,
                is_knock: true,
                knock_seq: seq,
            });
        inner.order.insert(
            seq,
            Entry {
                recipient,
                pair,
                bytes,
                source,
            },
        );
        bucket_add(inner, source, seq, bytes);
        if let Some(p) = pair {
            inner.by_pair.insert((recipient, p), seq);
        }
        *inner.per_recipient.entry(recipient).or_insert(0) += 1;
        inner.used += bytes;
        KnockOutcome::Queued
    }

    /// Remove `recipient`'s whole queue for delivery and forget its knocks,
    /// atomically with respect to `enqueue` (so a knock enqueued during the
    /// handover is either in the taken queue or still accounted).
    pub fn take_queue(
        &self,
        recipient: IdTag,
        queues: &DashMap<IdTag, MessageQueue>,
    ) -> Option<MessageQueue> {
        let mut guard = self.inner.lock();
        let (_, queue) = queues.remove(&recipient)?;
        forget_recipient(&mut guard, recipient);
        Some(queue)
    }

    /// Drop knocks whose age exceeds `knock_ttl_secs` (strict, from the
    /// stored `enqueued_at_unix_secs`).
    pub fn expire(
        &self,
        now_unix: u64,
        knock_ttl_secs: u64,
        queues: &DashMap<IdTag, MessageQueue>,
    ) {
        let mut guard = self.inner.lock();
        let mut gone = Vec::new();
        for mut q in queues.iter_mut() {
            q.pending.retain(|m| {
                if m.is_knock && expired(now_unix, m.enqueued_at_unix_secs, knock_ttl_secs) {
                    gone.push(m.knock_seq);
                    false
                } else {
                    true
                }
            });
        }
        for seq in gone {
            forget(&mut guard, seq);
        }
    }

    /// Account knocks without pair entries (test helper; RCQ2 restores go
    /// through `requeue`, which does the same atomically with the insert).
    #[cfg(test)]
    pub(super) fn restore_counts(&self, recipient: IdTag, msgs: &mut [StoredMessage]) {
        account_unindexed(&mut self.inner.lock(), recipient, msgs);
    }

    /// Put undelivered items back at the front of `recipient`'s queue,
    /// re-accounting its knocks (without pair entries), atomically with
    /// respect to `enqueue`/`expire`. `charged` message bytes were already
    /// re-added to the offline budget (`RelayState::offline_budget`) by the caller.
    pub(super) fn requeue(
        &self,
        recipient: IdTag,
        mut msgs: Vec<StoredMessage>,
        charged: usize,
        queues: &DashMap<IdTag, MessageQueue>,
    ) {
        let mut guard = self.inner.lock();
        account_unindexed(&mut guard, recipient, &mut msgs);
        let mut queue = queues.entry(recipient).or_insert_with(|| MessageQueue {
            pending: Vec::new(),
            bytes: 0,
        });
        let newer = std::mem::replace(&mut queue.pending, msgs);
        queue.pending.extend(newer);
        queue.bytes += charged;
    }

    /// Take back the knock queued for `(recipient, pair)` (a concurrent
    /// publish made the recipient routable): removes the record from the
    /// queue and the accounting. `None` if it is no longer queued (the
    /// publish delivered it).
    pub fn reclaim(
        &self,
        recipient: IdTag,
        pair: PairTag,
        queues: &DashMap<IdTag, MessageQueue>,
    ) -> Option<Vec<u8>> {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let seq = inner.by_pair.get(&(recipient, pair)).copied()?;
        let payload = queues.get_mut(&recipient).and_then(|mut q| {
            let pos = q
                .pending
                .iter()
                .position(|m| m.is_knock && m.knock_seq == seq)?;
            Some(q.pending.remove(pos).payload)
        });
        // Either way the entry is done: reclaimed, or stale.
        forget(inner, seq);
        queues.remove_if(&recipient, |_, q| q.pending.is_empty());
        payload
    }

    #[cfg(test)]
    pub fn quota_len(&self) -> usize {
        self.quota.lock().map.len()
    }

    #[cfg(test)]
    pub fn has_asker(&self, asker: &IdTag) -> bool {
        self.quota.lock().map.contains_key(asker)
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.inner.lock().used
    }

    #[cfg(test)]
    pub fn index_len(&self) -> usize {
        self.inner.lock().by_pair.len()
    }

    #[cfg(test)]
    pub fn count_for(&self, recipient: IdTag) -> usize {
        self.inner
            .lock()
            .per_recipient
            .get(&recipient)
            .copied()
            .unwrap_or(0)
    }
}

/// Account `msgs`' knocks with fresh seqs and no pair entry.
fn account_unindexed(inner: &mut Inner, recipient: IdTag, msgs: &mut [StoredMessage]) {
    for m in msgs.iter_mut().filter(|m| m.is_knock) {
        let seq = inner.next_seq;
        inner.next_seq += 1;
        m.knock_seq = seq;
        inner.order.insert(
            seq,
            Entry {
                recipient,
                pair: None,
                bytes: m.payload.len(),
                source: RESTORED_SOURCE,
            },
        );
        bucket_add(inner, RESTORED_SOURCE, seq, m.payload.len());
        *inner.per_recipient.entry(recipient).or_insert(0) += 1;
        inner.used += m.payload.len();
    }
}

/// Forget every accounted knock of `recipient` (not from any queue).
fn forget_recipient(inner: &mut Inner, recipient: IdTag) {
    let seqs: Vec<u64> = inner
        .order
        .iter()
        .filter(|(_, e)| e.recipient == recipient)
        .map(|(s, _)| *s)
        .collect();
    for seq in seqs {
        forget(inner, seq);
    }
}

/// Remove `seq` from the accounting (not from any queue).
fn forget(inner: &mut Inner, seq: u64) -> Option<Entry> {
    let e = inner.order.remove(&seq)?;
    bucket_remove(inner, e.source, seq, e.bytes);
    inner.used = inner.used.saturating_sub(e.bytes);
    if let Some(n) = inner.per_recipient.get_mut(&e.recipient) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            inner.per_recipient.remove(&e.recipient);
        }
    }
    if let Some(p) = e.pair {
        if inner.by_pair.get(&(e.recipient, p)) == Some(&seq) {
            inner.by_pair.remove(&(e.recipient, p));
        }
    }
    Some(e)
}

fn bucket_add(inner: &mut Inner, source: Option<SourceKey>, seq: u64, bytes: usize) {
    let b = inner.by_source.entry(source).or_default();
    b.bytes += bytes;
    b.seqs.insert(seq);
}

fn bucket_remove(inner: &mut Inner, source: Option<SourceKey>, seq: u64, bytes: usize) {
    if let Some(b) = inner.by_source.get_mut(&source) {
        b.bytes = b.bytes.saturating_sub(bytes);
        b.seqs.remove(&seq);
        if b.seqs.is_empty() {
            inner.by_source.remove(&source);
        }
    }
}

/// Forget `seq` and delete its record from the recipient's queue.
fn evict(inner: &mut Inner, seq: u64, queues: &DashMap<IdTag, MessageQueue>) {
    let Some(e) = forget(inner, seq) else {
        return;
    };
    let empty = queues
        .get_mut(&e.recipient)
        .map(|mut q| {
            q.pending.retain(|m| !(m.is_knock && m.knock_seq == seq));
            q.pending.is_empty()
        })
        .unwrap_or(false);
    if empty {
        queues.remove_if(&e.recipient, |_, q| q.pending.is_empty());
    }
    metrics::reject(metrics::REJECT_KNOCK_EVICTED);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::{MessageQueue, StoredMessage};
    use crate::validate::KNOCK_BYTES;

    fn tag(i: u32) -> IdTag {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_be_bytes());
        IdTag(b)
    }
    fn pair(i: u32) -> PairTag {
        let mut b = [0xffu8; 32];
        b[..4].copy_from_slice(&i.to_be_bytes());
        PairTag(b)
    }
    /// A knock-v3-shaped payload (the store never opens it).
    fn knock(fill: u8) -> Vec<u8> {
        let mut k = vec![fill; KNOCK_BYTES];
        k[0] = crate::validate::KNOCK_VERSION;
        k
    }
    fn knocks_for(q: &DashMap<IdTag, MessageQueue>, r: IdTag) -> Vec<StoredMessage> {
        q.get(&r)
            .map(|q| q.pending.iter().filter(|m| m.is_knock).cloned().collect())
            .unwrap_or_default()
    }

    fn src(n: u8) -> Option<SourceKey> {
        Some(SourceKey([n; 32]))
    }

    /// Knock v3 budget arithmetic (§A.5, 5120-byte knocks): the default
    /// 16 MiB store holds 3276 knocks, a source's share (1/16) is 204, and
    /// the share never drops below one knock on a tiny budget.
    #[test]
    fn knock_v3_budget_arithmetic() {
        assert_eq!(KNOCK_BYTES, 5120);
        let store = KnockStore::new(16 << 20);
        let queues = DashMap::new();
        let mut i = 0u32;
        // 17 sources x 204 = 3468 offered: each source is capped at its
        // share, and the store at its budget.
        for s in 1..=17u8 {
            for _ in 0..204 {
                i += 1;
                store.enqueue(tag(i), Some(pair(i)), knock(s), 1, &queues, src(s));
            }
        }
        assert_eq!((16usize << 20) / KNOCK_BYTES, 3276);
        assert_eq!((16usize << 20) / KNOCK_SOURCE_SHARES / KNOCK_BYTES, 204);
        assert!(store.used() <= 16 << 20);
        assert_eq!(store.used() % KNOCK_BYTES, 0, "whole knocks only");
        assert_eq!(store.used() / KNOCK_BYTES, 3276, "full to the budget");
        let tiny = KnockStore::new(KNOCK_BYTES);
        tiny.enqueue(tag(1), Some(pair(1)), knock(1), 1, &queues, src(1));
        assert_eq!(
            tiny.used(),
            KNOCK_BYTES,
            "one knock fits the minimum budget"
        );
    }

    /// R-2: one source cannot flush the store - beyond its share it evicts
    /// its own knocks, so another source's knock survives 9000 of them.
    #[test]
    fn one_source_cannot_flush_another_sources_knock() {
        let store = KnockStore::new(16 << 20);
        let queues = DashMap::new();
        let victim = tag(1);
        store.enqueue(victim, Some(pair(1)), knock(0xaa), 1, &queues, src(1));
        for i in 0..9000u32 {
            store.enqueue(
                tag(1000 + i),
                Some(pair(1000 + i)),
                knock(2),
                2,
                &queues,
                src(2),
            );
        }
        assert_eq!(knocks_for(&queues, victim).len(), 1, "victim's knock kept");
        assert!(store.used() <= (16 << 20) / KNOCK_SOURCE_SHARES + KNOCK_BYTES);
    }

    /// R-2: with the store full from many sources, the heaviest source pays,
    /// not the oldest knock relay-wide.
    #[test]
    fn a_full_store_evicts_from_the_heaviest_source() {
        // 32 knocks fit; each source's share is 32 * KNOCK_BYTES / 16 = 2 knocks.
        // 20 sources x 2 + the victim's 1 = 41: nine evictions, each from a
        // source still holding two, never the victim's lone knock (which a
        // relay-wide oldest-first eviction would take first).
        let store = KnockStore::new(32 * KNOCK_BYTES);
        let queues = DashMap::new();
        let victim = tag(1);
        store.enqueue(victim, Some(pair(1)), knock(0xaa), 1, &queues, src(1));
        let mut i = 0u32;
        for s in 2..=21u8 {
            for _ in 0..2 {
                i += 1;
                store.enqueue(
                    tag(100 + i),
                    Some(pair(100 + i)),
                    knock(2),
                    2,
                    &queues,
                    src(s),
                );
            }
        }
        assert_eq!(knocks_for(&queues, victim).len(), 1, "lightest source kept");
        assert_eq!(store.used(), 32 * KNOCK_BYTES);
    }

    /// R-2: a flood aimed at one recipient evicts the flooder's own knocks
    /// at the per-recipient cap, not the recipient's earlier requests from
    /// other sources.
    #[test]
    fn a_per_recipient_flood_evicts_the_flooding_source() {
        let store = KnockStore::new(1 << 30);
        let queues = DashMap::new();
        let victim = tag(1);
        store.enqueue(victim, Some(pair(1)), knock(0xaa), 1, &queues, src(1));
        for i in 0..400u32 {
            store.enqueue(victim, Some(pair(10 + i)), knock(2), 2, &queues, src(2));
        }
        let left = knocks_for(&queues, victim);
        assert_eq!(left.len(), MAX_KNOCKS_PER_RECIPIENT);
        assert!(
            left.iter().any(|m| m.payload == knock(0xaa)),
            "real request kept"
        );
    }

    /// R-4 / M-2: the asker quota table is bounded. When it is full, the
    /// oldest asker of the heaviest source is forgotten - new askers are
    /// not denied relay-wide.
    #[test]
    fn the_asker_quota_table_is_bounded() {
        let store = KnockStore::with_quota_cap(1 << 20, 1000);
        let t0 = Instant::now();
        for i in 0..2000u32 {
            assert!(store.charge_asker(tag(i), None, t0), "new asker {i}");
            assert!(store.quota_len() <= 1000);
        }
        assert!(!store.has_asker(&tag(0)), "the oldest went first");
        assert!(store.has_asker(&tag(1999)));
        // Known askers keep their count; ended windows free room.
        assert!(store.charge_asker(tag(1999), None, t0));
        let later = t0 + QUOTA_WINDOW + Duration::from_secs(1);
        assert!(store.charge_asker(tag(5000), None, later));
        assert_eq!(store.quota_len(), 1);
    }

    /// M-2: one source churning identities cannot deny first contact to
    /// everyone else. It is held to its share of the table (its own new
    /// askers are refused beyond it), and other sources' new askers still
    /// get their knocks. Before, a full table refused every new asker.
    #[test]
    fn one_source_cannot_fill_the_asker_quota_table_for_everyone() {
        let cap = 64; // share: 4 askers per source
        let store = KnockStore::with_quota_cap(1 << 20, cap);
        let t0 = Instant::now();
        let flood = Some(SourceKey([1; 32]));
        let admitted = (0..1000u32)
            .filter(|i| store.charge_asker(tag(i + 10_000), flood, t0))
            .count();
        assert_eq!(admitted, cap / QUOTA_SOURCE_SHARES);
        let other = Some(SourceKey([2; 32]));
        assert!(
            store.charge_asker(tag(1), other, t0),
            "another source's asker"
        );
        // Even a table filled by many sources takes new askers, at the
        // cost of the heaviest source's oldest entry.
        let unknown = None; // no share for unattributed connections
        for i in 0..1000u32 {
            assert!(store.charge_asker(tag(i + 20_000), unknown, t0));
        }
        assert_eq!(store.quota_len(), cap);
        assert!(store.charge_asker(tag(2), Some(SourceKey([3; 32])), t0));
        assert!(store.has_asker(&tag(1)) && store.has_asker(&tag(2)));
        assert!(
            !store.has_asker(&tag(20_000)),
            "the heaviest (unattributed) bucket's oldest asker made room"
        );
    }
    #[test]
    fn q7_full_global_budget_evicts_the_oldest_knock_relay_wide() {
        let store = KnockStore::new(3 * KNOCK_BYTES);
        let queues: DashMap<IdTag, MessageQueue> = DashMap::new();
        // A recipient with an ordinary queued message: never touched.
        queues.insert(
            tag(99),
            MessageQueue {
                pending: vec![StoredMessage {
                    payload: vec![0x02; 300],
                    enqueued_at_unix_secs: 1,
                    is_knock: false,
                    knock_seq: 0,
                }],
                bytes: 300,
            },
        );
        for i in 1..=4 {
            let out = store.enqueue(
                tag(i),
                Some(pair(i)),
                knock(i as u8),
                i as u64,
                &queues,
                None,
            );
            assert_eq!(out, KnockOutcome::Queued);
        }
        assert!(
            knocks_for(&queues, tag(1)).is_empty(),
            "oldest knock evicted"
        );
        for i in 2..=4 {
            assert_eq!(knocks_for(&queues, tag(i)).len(), 1);
        }
        assert_eq!(store.used(), 3 * KNOCK_BYTES);
        let msgs = queues.get(&tag(99)).unwrap();
        assert_eq!(msgs.pending.len(), 1, "message queue unaffected");
        assert_eq!(msgs.bytes, 300);
    }

    #[test]
    fn q7_201st_knock_for_one_recipient_evicts_its_oldest() {
        let store = KnockStore::new(1 << 30);
        let queues = DashMap::new();
        let r = tag(1);
        for i in 0..201u32 {
            store.enqueue(r, Some(pair(i)), knock(1), u64::from(i), &queues, None);
        }
        assert_eq!(store.count_for(r), MAX_KNOCKS_PER_RECIPIENT);
        let left = knocks_for(&queues, r);
        assert_eq!(left.len(), 200);
        assert!(
            left.iter().all(|m| m.enqueued_at_unix_secs != 0),
            "oldest went"
        );
        assert_eq!(store.index_len(), 200);
    }

    #[test]
    fn q7_newer_knock_for_the_same_pair_replaces_the_queued_one() {
        let store = KnockStore::new(1 << 20);
        let queues = DashMap::new();
        let (r, p) = (tag(1), pair(1));
        assert_eq!(
            store.enqueue(r, Some(p), knock(0xaa), 10, &queues, None),
            KnockOutcome::Queued
        );
        assert_eq!(
            store.enqueue(r, Some(p), knock(0xbb), 20, &queues, None),
            KnockOutcome::Replaced
        );
        let left = knocks_for(&queues, r);
        assert_eq!(left.len(), 1, "count stays 1");
        assert_eq!(left[0].payload, knock(0xbb));
        assert_eq!(left[0].enqueued_at_unix_secs, 20, "takes a new enqueued_at");
        assert_eq!(store.index_len(), 1);
        assert_eq!(store.used(), KNOCK_BYTES);
    }

    #[test]
    fn q7_asker_quota_101st_new_ask_is_refused() {
        let store = KnockStore::new(1 << 30);
        let asker = tag(7);
        let now = Instant::now();
        for _ in 0..ASKER_QUOTA {
            assert!(store.charge_asker(asker, None, now));
        }
        assert!(!store.charge_asker(asker, None, now), "101st new ask");
        assert!(
            store.charge_asker(tag(8), None, now),
            "quotas are per asker"
        );
    }

    #[test]
    fn q7_asker_quota_resets_after_24_hours() {
        let store = KnockStore::new(1 << 30);
        let asker = tag(7);
        let t0 = Instant::now();
        for _ in 0..ASKER_QUOTA {
            store.charge_asker(asker, None, t0);
        }
        assert!(
            !store.charge_asker(asker, None, t0 + QUOTA_WINDOW),
            "still inside the window"
        );
        assert!(store.charge_asker(asker, None, t0 + QUOTA_WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn q7_asker_quota_entries_are_pruned_after_the_window() {
        let store = KnockStore::new(1 << 30);
        let t0 = Instant::now();
        store.charge_asker(tag(7), None, t0);
        store.charge_asker(tag(8), None, t0 + Duration::from_secs(10));
        store.prune_quota(t0 + QUOTA_WINDOW);
        assert_eq!(store.quota_len(), 2, "inside the window: kept");
        store.prune_quota(t0 + QUOTA_WINDOW + Duration::from_secs(1));
        assert_eq!(store.quota_len(), 1, "tag(7)'s window ended: gone");
        store.prune_quota(t0 + QUOTA_WINDOW + Duration::from_secs(11));
        assert_eq!(store.quota_len(), 0);
    }

    #[test]
    fn q7_knocks_older_than_knock_ttl_are_dropped() {
        let store = KnockStore::new(1 << 20);
        let queues = DashMap::new();
        store.enqueue(tag(1), Some(pair(1)), knock(1), 1_000, &queues, None);
        store.enqueue(tag(2), Some(pair(2)), knock(1), 1_001, &queues, None);
        let ttl = 259_200;
        store.expire(1_001 + ttl, ttl, &queues);
        assert!(knocks_for(&queues, tag(1)).is_empty(), "age ttl+1 dropped");
        assert_eq!(
            knocks_for(&queues, tag(2)).len(),
            1,
            "age == ttl kept (strict)"
        );
        assert_eq!(store.index_len(), 1);
        assert_eq!(store.used(), KNOCK_BYTES);
    }

    #[test]
    fn q7_knock_index_is_cleared_on_delivery() {
        let store = KnockStore::new(1 << 20);
        let queues = DashMap::new();
        for i in 0..3 {
            store.enqueue(tag(1), Some(pair(i)), knock(1), 5, &queues, None);
        }
        let taken = store.take_queue(tag(1), &queues).unwrap();
        assert_eq!(taken.pending.len(), 3);
        assert!(queues.get(&tag(1)).is_none());
        assert_eq!(store.index_len(), 0);
        assert_eq!(store.used(), 0);
        assert_eq!(store.count_for(tag(1)), 0);
    }

    #[test]
    fn q5_knock_records_have_no_sender_and_never_charge_the_offline_budget() {
        let store = KnockStore::new(1 << 20);
        let queues = DashMap::new();
        store.enqueue(tag(1), Some(pair(1)), knock(0x33), 5, &queues, None);
        let q = queues.get(&tag(1)).unwrap();
        assert_eq!(q.bytes, 0, "knocks are not charged to the message budget");
        let StoredMessage {
            payload,
            enqueued_at_unix_secs,
            is_knock,
            knock_seq,
        } = &q.pending[0];
        assert_eq!(
            payload,
            &knock(0x33),
            "the sealed knock only; no sender field"
        );
        assert_eq!(*enqueued_at_unix_secs, 5);
        assert!(*is_knock);
        assert!(*knock_seq > 0);
        assert_eq!(q.pending[0].budget_cost(), 0);
    }

    #[test]
    fn restored_knocks_count_toward_budget_and_cap_without_an_index() {
        let store = KnockStore::new(2 * KNOCK_BYTES);
        let queues = DashMap::new();
        let mut restored = vec![StoredMessage {
            payload: knock(1),
            enqueued_at_unix_secs: 1,
            is_knock: true,
            knock_seq: 0,
        }];
        store.restore_counts(tag(1), &mut restored);
        queues.insert(
            tag(1),
            MessageQueue {
                pending: restored,
                bytes: 0,
            },
        );
        assert_eq!(store.used(), KNOCK_BYTES);
        assert_eq!(store.index_len(), 0, "pair tags are never persisted");
        // L-1: restored knocks have their own bucket. Two new knocks from
        // one (unattributed) bucket: the second makes room from its own
        // bucket, not from the restored one, which is no heavier.
        store.enqueue(tag(2), Some(pair(2)), knock(2), 2, &queues, None);
        assert_eq!(
            store.enqueue(tag(3), Some(pair(3)), knock(3), 3, &queues, None),
            KnockOutcome::Queued
        );
        assert_eq!(knocks_for(&queues, tag(1)).len(), 1, "restored knock kept");
        assert!(knocks_for(&queues, tag(2)).is_empty(), "own oldest went");
        assert_eq!(knocks_for(&queues, tag(3)).len(), 1);
    }

    /// N-5 (with L-1's determinism): a store full of one-knock sources
    /// still takes a new source's knock; the oldest knock goes, never one
    /// picked by map order.
    #[test]
    fn a_full_store_of_one_knock_sources_takes_new_knocks_oldest_first() {
        let store = KnockStore::new(4 * KNOCK_BYTES); // share: one knock per source
        let queues = DashMap::new();
        let src = |n: u8| Some(SourceKey([n; 32]));
        for i in [3u8, 1, 0, 2] {
            // Insertion order (seq) is the age; sources differ from it.
            let at = u64::from(i);
            store.enqueue(
                tag(1),
                Some(pair(u32::from(i))),
                knock(i),
                at,
                &queues,
                src(10 - i),
            );
        }
        assert_eq!(
            store.enqueue(tag(1), Some(pair(9)), knock(9), 9, &queues, src(99)),
            KnockOutcome::Queued
        );
        let mut left: Vec<u64> = knocks_for(&queues, tag(1))
            .iter()
            .map(|m| m.enqueued_at_unix_secs)
            .collect();
        left.sort();
        assert_eq!(left, vec![0, 1, 2, 9], "the first-stored knock went");
    }

    /// N-5: single-knock sources filling the 16 MiB store (3,276 knocks
    /// of 5120 bytes, e.g. a proxy pool) do not block a new source's first
    /// contact for the knock TTL.
    #[test]
    fn many_single_knock_sources_do_not_block_a_new_sources_knock() {
        let store = KnockStore::new(16 << 20);
        let queues = DashMap::new();
        let src = |n: u32| Some(SourceKey(blake3::hash(&n.to_le_bytes()).into()));
        let fit = ((16usize << 20) / KNOCK_BYTES) as u32;
        for i in 0..fit {
            store.enqueue(tag(i), None, knock(1), u64::from(i), &queues, src(i));
        }
        let full = fit as usize * KNOCK_BYTES;
        assert_eq!(store.used(), full, "the store is full");
        assert_eq!(
            store.enqueue(tag(90_000), None, knock(2), 90_000, &queues, src(90_000)),
            KnockOutcome::Queued
        );
        assert_eq!(knocks_for(&queues, tag(90_000)).len(), 1);
        assert!(knocks_for(&queues, tag(0)).is_empty(), "the oldest went");
        assert_eq!(store.used(), full);
    }

    /// L-1: at a recipient's cap, many one-knock sources cannot flush the
    /// recipient's older requests; a source already holding more than one
    /// still pays for its own new knock.
    #[test]
    fn a_recipient_cap_does_not_break_ties_against_older_knocks() {
        let store = KnockStore::new(1 << 30);
        let queues = DashMap::new();
        let src = |n: u32| Some(SourceKey(blake3::hash(&n.to_le_bytes()).into()));
        let r = tag(1);
        for i in 0..MAX_KNOCKS_PER_RECIPIENT as u32 {
            store.enqueue(r, Some(pair(i)), knock(1), u64::from(i), &queues, src(i));
        }
        assert_eq!(
            store.enqueue(r, Some(pair(5000)), knock(2), 5000, &queues, src(5000)),
            KnockOutcome::Dropped
        );
        assert!(knocks_for(&queues, r)
            .iter()
            .any(|m| m.enqueued_at_unix_secs == 0));
        // Source 7 already has one knock here: its next one replaces its own.
        assert_eq!(
            store.enqueue(r, Some(pair(6000)), knock(3), 6000, &queues, src(7)),
            KnockOutcome::Queued
        );
        let left = knocks_for(&queues, r);
        assert_eq!(left.len(), MAX_KNOCKS_PER_RECIPIENT);
        assert!(!left.iter().any(|m| m.enqueued_at_unix_secs == 7));
        assert!(left.iter().any(|m| m.enqueued_at_unix_secs == 0));
    }
}
