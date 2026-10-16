//! Per-source and per-identity fair shares of client-creatable relay state
//! (findings R-3, R-11):
//!
//! * [`PendingAsks`] - the one-sided `CircuitAsk` and `CircuitAskBlind`
//!   table (one table, so both kinds share the caps) with an ordered index
//!   (asks per source by age, sources by count) kept in step with every
//!   insert and removal, so the per-source caps are O(1) and a full table
//!   evicts the heaviest source's oldest ask in O(log n) instead of
//!   refusing everyone (final re-review N-1). A share of the table is
//!   reserved for identity asks.
//! * [`CircuitCounts`] - circuits (pair sides) per identity tag and per
//!   source, charged when a pair is created and released when it is torn
//!   down. Pairs outlive connections, so the counts survive reconnects.
//!
//! A source is a keyed digest of an IPv4 address or IPv6 /48
//! (`limits::SourceKey`); `None` (per-source accounting off, or state with
//! no known source) is never counted against any source.
//!
//! PRIVACY: identity tags and source keys only; nothing here links two
//! identities, and an entry goes as soon as its count is zero.

use super::circuits::PendingAsk;
use super::tags::{BlindTag, IdTag, PairTag};
use crate::limits::SourceKey;
use crate::protocol::ClientId;
use dashmap::mapref::multiple::RefMulti;
use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

fn add(map: &mut HashMap<SourceKey, usize>, key: SourceKey) {
    *map.entry(key).or_insert(0) += 1;
}

fn sub(map: &mut HashMap<SourceKey, usize>, key: SourceKey) {
    if let Some(n) = map.get_mut(&key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(&key);
        }
    }
}

/// Outcome of asking for room for a new pending ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskAdmission {
    /// There is room (possibly after evicting a heavier source's ask).
    Admitted,
    /// The caller's source holds its full share.
    SourceFull,
    /// The table is full and no source is heavier than the caller's.
    Full,
}

/// Which share a new pending ask is charged to (final review M1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskKind {
    /// `CircuitAsk`: `max_pending_per_source`.
    Identity,
    /// `CircuitAskBlind`: `max_pending_blind_per_source`.
    Blind,
}

/// A pending ask's key: an identity ask by its pair tag, a blinded ask
/// (protocol v3 §C.2) by its token's keyed tag. Never logged.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AskKey {
    Pair(PairTag),
    Blind(BlindTag),
}

#[cfg(test)]
impl AskKey {
    /// The tag's bytes, for tests that scan relay state.
    pub(crate) fn raw(&self) -> [u8; 32] {
        match self {
            AskKey::Pair(p) => p.0,
            AskKey::Blind(b) => b.0,
        }
    }
}

impl std::fmt::Debug for AskKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AskKey(..)")
    }
}

impl PartialOrd for AskKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An arbitrary total order (kind, then tag bytes), only to break ties
/// between asks made at the same instant in the age index. Not a secret
/// comparison: the tags are keyed per boot and never leave the process.
impl Ord for AskKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let parts = |k: &AskKey| match k {
            AskKey::Pair(p) => (0u8, p.0),
            AskKey::Blind(b) => (1u8, b.0),
        };
        parts(self).cmp(&parts(other))
    }
}

/// The limits one admission is checked against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AskLimits {
    /// `max_pending_circuit_targets`: both kinds together.
    pub global: usize,
    /// The caller's source share for the ask's kind
    /// (`max_pending_per_source` or `pending_blind_per_source()`).
    pub per_source: usize,
    /// Most blind asks in the whole table (`pending_blind_table_cap()`,
    /// final re-review N-1 (c)): the rest of `global` is reserved for
    /// identity asks (first contact and the identity fallback).
    pub blind_cap: usize,
}

/// Asks of one kind by age.
type AgeSet = BTreeSet<(Instant, AskKey)>;

/// One source's asks, oldest first, per kind (final re-review N-1 (b)).
/// The counts are the set sizes.
#[derive(Default)]
struct SourceAsks {
    identity: AgeSet,
    blind: AgeSet,
}

impl SourceAsks {
    fn set(&mut self, key: &AskKey) -> &mut AgeSet {
        match key {
            AskKey::Pair(_) => &mut self.identity,
            AskKey::Blind(_) => &mut self.blind,
        }
    }

    fn count(&self, kind: AskKind) -> usize {
        match kind {
            AskKind::Identity => self.identity.len(),
            AskKind::Blind => self.blind.len(),
        }
    }

    fn total(&self) -> usize {
        self.identity.len() + self.blind.len()
    }

    /// The oldest ask of either kind.
    fn oldest(&self) -> Option<(Instant, AskKey)> {
        match (self.identity.first(), self.blind.first()) {
            (Some(a), Some(b)) => Some(*a.min(b)),
            (a, b) => a.or(b).copied(),
        }
    }
}

/// The ordered index beside the map: every ask by source and age, and the
/// sources ordered by how many asks they hold, so the per-source caps, the
/// heaviest source and its oldest ask are O(log n) (final re-review N-1
/// (b)). Asks with no source (accounting off) are indexed apart and never
/// counted against any source.
#[derive(Default)]
struct AskIndex {
    sources: HashMap<SourceKey, SourceAsks>,
    unsourced: SourceAsks,
    /// (asks of both kinds, source), for the heaviest source.
    by_total: BTreeSet<(usize, SourceKey)>,
    /// (blind asks, source), for the heaviest blind source.
    by_blind: BTreeSet<(usize, SourceKey)>,
    /// Blind asks in the table, sourced or not (the blind share).
    blind_total: usize,
    /// Identity asks in the table, sourced or not (the identity reserve).
    identity_total: usize,
}

impl AskIndex {
    fn count(&self, source: &SourceKey, kind: AskKind) -> usize {
        self.sources.get(source).map_or(0, |s| s.count(kind))
    }

    fn total(&self, source: &SourceKey) -> usize {
        self.sources.get(source).map_or(0, SourceAsks::total)
    }

    /// Apply `f` to the asks of `source` (`None`: the unsourced ones),
    /// keeping the by-count orders and the totals in step.
    fn update(
        &mut self,
        key: &AskKey,
        source: Option<SourceKey>,
        f: impl FnOnce(&mut AgeSet) -> bool,
    ) {
        let blind = matches!(key, AskKey::Blind(_));
        let Some(s) = source else {
            let set = self.unsourced.set(key);
            let before = set.len();
            f(set);
            let after = set.len();
            self.adjust_totals(blind, before, after);
            return;
        };
        let entry = self.sources.entry(s).or_default();
        let (old_total, old_blind) = (entry.total(), entry.blind.len());
        let set = entry.set(key);
        let before = set.len();
        f(set);
        let after = set.len();
        let (new_total, new_blind) = (entry.total(), entry.blind.len());
        if new_total == 0 {
            self.sources.remove(&s);
        }
        for (order, old, new) in [
            (&mut self.by_total, old_total, new_total),
            (&mut self.by_blind, old_blind, new_blind),
        ] {
            if old != new {
                if old > 0 {
                    order.remove(&(old, s));
                }
                if new > 0 {
                    order.insert((new, s));
                }
            }
        }
        self.adjust_totals(blind, before, after);
    }

    fn adjust_totals(&mut self, blind: bool, before: usize, after: usize) {
        let total = if blind {
            &mut self.blind_total
        } else {
            &mut self.identity_total
        };
        *total = total.saturating_add(after).saturating_sub(before);
    }

    fn add(&mut self, key: AskKey, at: Instant, source: Option<SourceKey>) {
        self.update(&key, source, |set| set.insert((at, key)));
    }

    fn remove(&mut self, key: AskKey, at: Instant, source: Option<SourceKey>) {
        self.update(&key, source, |set| set.remove(&(at, key)));
    }

    /// The oldest ask of `source`, of `kind` or (`None`) of either kind.
    fn oldest_of(
        &self,
        source: Option<SourceKey>,
        kind: Option<AskKind>,
    ) -> Option<(Instant, AskKey)> {
        let asks = match source {
            Some(s) => self.sources.get(&s)?,
            None => &self.unsourced,
        };
        match kind {
            None => asks.oldest(),
            Some(AskKind::Identity) => asks.identity.first().copied(),
            Some(AskKind::Blind) => asks.blind.first().copied(),
        }
    }
}

/// The pending-ask table. Every insert and removal goes through these
/// methods, under the index lock, so the ordered index matches the map.
/// `get_mut` callers must not change an ask's `source` or `at`.
///
/// Lock order: `index` before any `map` shard. No caller holds a map
/// reference (`get`, `get_mut`, `iter`) while calling another method here.
#[derive(Default)]
pub(crate) struct PendingAsks {
    map: DashMap<AskKey, PendingAsk>,
    index: Mutex<AskIndex>,
}

impl PendingAsks {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, pair: &PairTag) -> Option<Ref<'_, AskKey, PendingAsk>> {
        self.map.get(&AskKey::Pair(*pair))
    }

    pub fn get_mut(&self, pair: &PairTag) -> Option<RefMut<'_, AskKey, PendingAsk>> {
        self.map.get_mut(&AskKey::Pair(*pair))
    }

    #[allow(dead_code)]
    pub fn contains_key(&self, pair: &PairTag) -> bool {
        self.map.contains_key(&AskKey::Pair(*pair))
    }

    /// The held blinded ask for a token's tag.
    pub fn get_blind(&self, tag: &BlindTag) -> Option<Ref<'_, AskKey, PendingAsk>> {
        self.map.get(&AskKey::Blind(*tag))
    }

    #[cfg(test)]
    pub fn get_blind_mut(&self, tag: &BlindTag) -> Option<RefMut<'_, AskKey, PendingAsk>> {
        self.map.get_mut(&AskKey::Blind(*tag))
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = RefMulti<'_, AskKey, PendingAsk>> {
        self.map.iter()
    }

    pub fn insert(&self, pair: PairTag, ask: PendingAsk) -> Option<PendingAsk> {
        self.insert_key(AskKey::Pair(pair), ask)
    }

    pub fn insert_blind(&self, tag: BlindTag, ask: PendingAsk) -> Option<PendingAsk> {
        self.insert_key(AskKey::Blind(tag), ask)
    }

    fn insert_key(&self, key: AskKey, ask: PendingAsk) -> Option<PendingAsk> {
        let mut ix = self.index.lock();
        let (at, source) = (ask.at, ask.source);
        let old = self.map.insert(key, ask);
        if let Some(o) = old.as_ref() {
            ix.remove(key, o.at, o.source);
        }
        ix.add(key, at, source);
        old
    }

    pub fn remove(&self, pair: &PairTag) -> Option<(AskKey, PendingAsk)> {
        self.remove_key_if(&AskKey::Pair(*pair), |_, _| true)
    }

    pub fn remove_blind(&self, tag: &BlindTag) -> Option<(AskKey, PendingAsk)> {
        self.remove_key_if(&AskKey::Blind(*tag), |_, _| true)
    }

    pub fn remove_if(
        &self,
        pair: &PairTag,
        f: impl FnOnce(&AskKey, &PendingAsk) -> bool,
    ) -> Option<(AskKey, PendingAsk)> {
        self.remove_key_if(&AskKey::Pair(*pair), f)
    }

    pub fn remove_blind_if(
        &self,
        tag: &BlindTag,
        f: impl FnOnce(&AskKey, &PendingAsk) -> bool,
    ) -> Option<(AskKey, PendingAsk)> {
        self.remove_key_if(&AskKey::Blind(*tag), f)
    }

    fn remove_key_if(
        &self,
        key: &AskKey,
        f: impl FnOnce(&AskKey, &PendingAsk) -> bool,
    ) -> Option<(AskKey, PendingAsk)> {
        let mut ix = self.index.lock();
        let removed = self.map.remove_if(key, f);
        if let Some((k, a)) = removed.as_ref() {
            ix.remove(*k, a.at, a.source);
        }
        removed
    }

    /// Keep the asks for which `keep` is true; returns the asks removed.
    /// O(n): used by the periodic sweep and on disconnect
    /// (≤ `max_pending_circuit_targets` entries). The scan takes no lock
    /// beyond each map shard's, so inserts are never held up behind it;
    /// the removals then go under the index lock, each only if the ask is
    /// still the one scanned (same `at` and `asker`). So `keep` must decide
    /// on the key, `at` and `asker` only, and must not call into the table.
    pub fn retain(
        &self,
        mut keep: impl FnMut(&AskKey, &PendingAsk) -> bool,
    ) -> Vec<(AskKey, PendingAsk)> {
        let doomed: Vec<(AskKey, Instant, ClientId)> = self
            .map
            .iter()
            .filter(|e| !keep(e.key(), e.value()))
            .map(|e| (*e.key(), e.at, e.asker))
            .collect();
        if doomed.is_empty() {
            return Vec::new();
        }
        let mut ix = self.index.lock();
        let mut removed = Vec::with_capacity(doomed.len());
        for (key, at, asker) in doomed {
            if let Some((k, a)) = self
                .map
                .remove_if(&key, |_, a| a.at == at && a.asker == asker)
            {
                ix.remove(k, a.at, a.source);
                removed.push((k, a));
            }
        }
        removed
    }

    /// Every source with a pending-ask share of either kind (tests
    /// scanning state).
    #[cfg(test)]
    pub fn sources(&self) -> Vec<SourceKey> {
        self.index.lock().sources.keys().copied().collect()
    }

    /// Pending asks of both kinds currently held by `source` (tests).
    #[cfg(test)]
    pub fn source_count(&self, source: &SourceKey) -> usize {
        self.index.lock().total(source)
    }

    /// Room for one more ask of `kind` (an identity or a blinded ask) from
    /// `source`? O(log n) (final re-review N-1 (b)).
    ///
    /// * Over the source's share for that kind: refused (the two kinds have
    ///   separate shares, final review M1).
    /// * A blind ask with blind asks at `limits.blind_cap`: the oldest blind
    ///   ask of the heaviest blind source is evicted when that source holds
    ///   more blind asks than the caller's would after this one; otherwise
    ///   refused. The rest of the table is the identity reserve (N-1 (c)).
    /// * An identity ask with the table full while identity asks hold less
    ///   than their reserve: a blind ask is evicted (the heaviest blind
    ///   source's oldest, or the oldest unsourced one), so blind churn
    ///   never locks first contact or the identity fallback out, even
    ///   without per-source accounting.
    /// * Otherwise, with the table full, the oldest ask of the heaviest
    ///   source (both kinds counted) is evicted when that source holds more
    ///   than the caller's would after this ask; otherwise refused.
    ///
    /// Without a source (accounting off) only the global cap, the blind
    /// share and the reserve apply.
    pub fn admit(
        &self,
        kind: AskKind,
        source: Option<SourceKey>,
        limits: AskLimits,
    ) -> AskAdmission {
        let mut ix = self.index.lock();
        if let Some(s) = source {
            if ix.count(&s, kind) >= limits.per_source {
                return AskAdmission::SourceFull;
            }
        }
        if kind == AskKind::Blind && ix.blind_total >= limits.blind_cap {
            let own = source.map_or(0, |s| ix.count(&s, AskKind::Blind));
            return match ix.by_blind.last().copied() {
                Some((n, victim)) if source.is_some() && n > own + 1 => {
                    self.evict(&mut ix, Some(victim), Some(AskKind::Blind))
                }
                _ => AskAdmission::Full,
            };
        }
        if self.map.len() < limits.global {
            return AskAdmission::Admitted;
        }
        let reserve = limits.global.saturating_sub(limits.blind_cap);
        if kind == AskKind::Identity && ix.identity_total < reserve {
            let victim = ix.by_blind.last().map(|(_, s)| *s);
            return self.evict(&mut ix, victim, Some(AskKind::Blind));
        }
        let own = source.map_or(0, |s| ix.total(&s));
        match ix.by_total.last().copied() {
            Some((n, victim)) if source.is_some() && n > own + 1 => {
                self.evict(&mut ix, Some(victim), None)
            }
            _ => AskAdmission::Full,
        }
    }

    /// Evict the oldest ask of `source` (`None`: the unsourced asks), of
    /// `kind` or of either kind. O(log n), under the index lock.
    fn evict(
        &self,
        ix: &mut AskIndex,
        source: Option<SourceKey>,
        kind: Option<AskKind>,
    ) -> AskAdmission {
        let Some((at, key)) = ix.oldest_of(source, kind) else {
            return AskAdmission::Full;
        };
        match self.map.remove(&key) {
            Some((k, a)) => {
                ix.remove(k, a.at, a.source);
                crate::metrics::reject(crate::metrics::REJECT_PENDING_EVICTED);
                AskAdmission::Admitted
            }
            None => {
                // Never expected (every map change goes through the index
                // lock); drop the stale index entry rather than loop on it.
                debug_assert!(false, "pending-ask index out of step with the map");
                ix.remove(key, at, source);
                AskAdmission::Full
            }
        }
    }

    /// Check the index against the map (tests): every ask indexed once
    /// under its source, kind and age, and the counts and orders exact.
    #[cfg(test)]
    pub fn assert_index_consistent(&self) {
        let ix = self.index.lock();
        let mut expect: HashMap<Option<SourceKey>, (AgeSet, AgeSet)> = HashMap::new();
        let (mut identity_total, mut blind_total) = (0, 0);
        for e in self.map.iter() {
            let slot = expect.entry(e.source).or_default();
            match e.key() {
                AskKey::Pair(_) => {
                    identity_total += 1;
                    slot.0.insert((e.at, *e.key()));
                }
                AskKey::Blind(_) => {
                    blind_total += 1;
                    slot.1.insert((e.at, *e.key()));
                }
            }
        }
        assert_eq!(ix.identity_total, identity_total, "identity total");
        assert_eq!(ix.blind_total, blind_total, "blind total");
        let none = expect.remove(&None).unwrap_or_default();
        assert_eq!(ix.unsourced.identity, none.0, "unsourced identity asks");
        assert_eq!(ix.unsourced.blind, none.1, "unsourced blind asks");
        assert_eq!(ix.sources.len(), expect.len(), "sources indexed");
        let mut by_total = BTreeSet::new();
        let mut by_blind = BTreeSet::new();
        for (s, (identity, blind)) in expect {
            let s = s.expect("sourced");
            let got = ix.sources.get(&s).expect("source indexed");
            assert_eq!(got.identity, identity, "identity asks of a source");
            assert_eq!(got.blind, blind, "blind asks of a source");
            by_total.insert((identity.len() + blind.len(), s));
            if !blind.is_empty() {
                by_blind.insert((blind.len(), s));
            }
        }
        assert_eq!(ix.by_total, by_total, "sources by total");
        assert_eq!(ix.by_blind, by_blind, "sources by blind asks");
    }
}

#[derive(Default)]
struct Counts {
    per_identity: HashMap<IdTag, usize>,
    per_source: HashMap<SourceKey, usize>,
}

/// Circuits (pair sides) per identity tag and per source.
#[derive(Default)]
pub(crate) struct CircuitCounts {
    inner: Mutex<Counts>,
}

/// One side of a pair, for charging and releasing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Side {
    pub tag: IdTag,
    pub source: Option<SourceKey>,
}

impl CircuitCounts {
    /// May a pair between `a` and `b` be created? Each identity stays at or
    /// below `per_identity` circuits and each source at or below
    /// `per_source` (both sides from one source cost it two).
    pub fn admits(&self, a: Side, b: Side, per_identity: usize, per_source: usize) -> bool {
        let c = self.inner.lock();
        let id = |t: &IdTag| c.per_identity.get(t).copied().unwrap_or(0);
        if id(&a.tag) >= per_identity || id(&b.tag) >= per_identity {
            return false;
        }
        for s in [a.source, b.source].into_iter().flatten() {
            let wanted = [a.source, b.source]
                .iter()
                .filter(|x| **x == Some(s))
                .count();
            if c.per_source.get(&s).copied().unwrap_or(0) + wanted > per_source {
                return false;
            }
        }
        true
    }

    pub fn charge(&self, sides: [Side; 2]) {
        let mut c = self.inner.lock();
        for side in sides {
            *c.per_identity.entry(side.tag).or_insert(0) += 1;
            if let Some(s) = side.source {
                add(&mut c.per_source, s);
            }
        }
    }

    pub fn release(&self, sides: [Side; 2]) {
        let mut c = self.inner.lock();
        for side in sides {
            if let Some(n) = c.per_identity.get_mut(&side.tag) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    c.per_identity.remove(&side.tag);
                }
            }
            if let Some(s) = side.source {
                sub(&mut c.per_source, s);
            }
        }
    }

    #[cfg(test)]
    pub fn identity(&self, tag: &IdTag) -> usize {
        self.inner
            .lock()
            .per_identity
            .get(tag)
            .copied()
            .unwrap_or(0)
    }

    /// Every identity tag and source with a circuit count (tests scanning
    /// state).
    #[cfg(test)]
    pub fn keys(&self) -> (Vec<IdTag>, Vec<SourceKey>) {
        let c = self.inner.lock();
        (
            c.per_identity.keys().copied().collect(),
            c.per_source.keys().copied().collect(),
        )
    }

    /// Circuit sides held by `s`.
    pub fn source(&self, s: &SourceKey) -> usize {
        self.inner.lock().per_source.get(s).copied().unwrap_or(0)
    }

    /// The source holding the most circuit sides, and how many.
    pub fn heaviest_source(&self) -> Option<(SourceKey, usize)> {
        self.inner
            .lock()
            .per_source
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(s, n)| (*s, *n))
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        let c = self.inner.lock();
        c.per_identity.is_empty() && c.per_source.is_empty()
    }
}

#[cfg(test)]
mod tests {
    //! Final re-review N-1 (b), (c): the ordered index, O(log n) eviction
    //! and the identity reserve, on the table alone.
    use super::*;
    use crate::protocol::unified::PeerBundle;
    use crate::signaling::circuits::AskEphemerals;
    use std::sync::Arc;
    use std::time::Duration;

    fn ask(at: Instant, source: Option<SourceKey>, bundle: &Arc<PeerBundle>) -> PendingAsk {
        PendingAsk {
            asker: ClientId::generate(),
            asker_tag: IdTag([1; 32]),
            target_tag: None,
            asker_bundle: bundle.clone(),
            ephemeral: [0; 32],
            kem_ephemeral: Box::new(AskEphemerals {
                kem: [0; crate::validate::KEM_PK_BYTES],
                sig: [0; crate::validate::ASK_EPH_SIG_BYTES],
            }),
            knocks_delivered: 2,
            at,
            source,
        }
    }

    fn bundle() -> Arc<PeerBundle> {
        Arc::new(PeerBundle {
            identity_key: vec![0; 32],
            identity_agreement_key: vec![0; 32],
            kem_pk: vec![0; crate::validate::KEM_PK_BYTES],
            bundle_signature: vec![0; 64],
        })
    }

    fn tag(n: u32) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..4].copy_from_slice(&n.to_be_bytes());
        t
    }

    fn src(n: u8) -> SourceKey {
        SourceKey([n; 32])
    }

    /// A tiny deterministic generator (xorshift), so a failure replays.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// What `admit` should evict at a full table, by brute force over the
    /// map: the oldest ask of the heaviest source (ties as the index
    /// breaks them: larger source key).
    fn expected_victim(t: &PendingAsks, own: Option<SourceKey>) -> Option<AskKey> {
        let mut totals: HashMap<SourceKey, usize> = HashMap::new();
        for e in t.map.iter() {
            if let Some(s) = e.source {
                *totals.entry(s).or_default() += 1;
            }
        }
        let own_n = own.and_then(|s| totals.get(&s).copied()).unwrap_or(0);
        let (victim, n) = totals.into_iter().max_by_key(|(s, n)| (*n, *s))?;
        if own.is_none() || n <= own_n + 1 {
            return None;
        }
        t.map
            .iter()
            .filter(|e| e.source == Some(victim))
            .map(|e| (e.at, *e.key()))
            .min()
            .map(|(_, k)| k)
    }

    /// Property-style: random inserts (both kinds, five sources and none),
    /// replacements, removals, retains and full-table admits. After every
    /// step the index matches the map, and every eviction takes exactly the
    /// entry a brute-force scan picks.
    #[test]
    fn the_index_stays_consistent_and_eviction_picks_the_oldest_of_the_heaviest() {
        let b = bundle();
        let t0 = Instant::now();
        for seed in 1..=8u64 {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
            let t = PendingAsks::default();
            let limits = AskLimits {
                global: 64,
                per_source: 48,
                blind_cap: 64,
            };
            for step in 0..3_000u32 {
                let source = match rng.below(6) {
                    0 => None,
                    n => Some(src(n as u8)),
                };
                let at = t0 + Duration::from_millis(rng.below(500));
                let key = tag(rng.below(96) as u32);
                match rng.below(10) {
                    0..=3 => {
                        let kind = if rng.below(2) == 0 {
                            AskKind::Identity
                        } else {
                            AskKind::Blind
                        };
                        let full = t.len() >= limits.global;
                        let before: Vec<AskKey> = t.map.iter().map(|e| *e.key()).collect();
                        let victim = if full {
                            expected_victim(&t, source)
                        } else {
                            None
                        };
                        let own_kind = source.map_or(0, |s| {
                            t.map
                                .iter()
                                .filter(|e| {
                                    e.source == Some(s)
                                        && matches!(
                                            (e.key(), kind),
                                            (AskKey::Pair(_), AskKind::Identity)
                                                | (AskKey::Blind(_), AskKind::Blind)
                                        )
                                })
                                .count()
                        });
                        let got = t.admit(kind, source, limits);
                        if own_kind >= limits.per_source {
                            assert_eq!(got, AskAdmission::SourceFull, "seed {seed} step {step}");
                        } else if !full {
                            assert_eq!(got, AskAdmission::Admitted, "seed {seed} step {step}");
                        } else {
                            let gone: Vec<AskKey> = before
                                .iter()
                                .filter(|k| !t.map.contains_key(k))
                                .copied()
                                .collect();
                            match victim {
                                Some(v) => {
                                    assert_eq!(got, AskAdmission::Admitted);
                                    assert_eq!(gone, vec![v], "seed {seed} step {step}: victim");
                                }
                                None => {
                                    assert_eq!(got, AskAdmission::Full);
                                    assert!(gone.is_empty());
                                }
                            }
                        }
                        if got == AskAdmission::Admitted {
                            match kind {
                                AskKind::Identity => t.insert(PairTag(key), ask(at, source, &b)),
                                AskKind::Blind => {
                                    t.insert_blind(BlindTag(key), ask(at, source, &b))
                                }
                            };
                        }
                    }
                    4 => {
                        // An unchecked insert or replacement (a replay).
                        t.insert_blind(BlindTag(key), ask(at, source, &b));
                    }
                    5 | 6 => {
                        t.remove(&PairTag(key));
                        t.remove_blind_if(&BlindTag(key), |_, a| a.source == source);
                    }
                    7 => {
                        let cut = t0 + Duration::from_millis(rng.below(500));
                        t.retain(|_, a| a.at >= cut);
                    }
                    _ => {
                        let s = Some(src(rng.below(6) as u8));
                        t.retain(|_, a| a.source != s);
                    }
                }
                t.assert_index_consistent();
            }
        }
    }

    /// N-1 (c): with blind asks at their share, a new blind ask from a
    /// source no heavier than the rest is refused, but identity asks still
    /// fill the reserve; with the whole table full, an identity ask under
    /// its reserve evicts a blind ask, even with no source accounting.
    #[test]
    fn identity_asks_keep_their_reserve_when_blind_asks_fill_their_share() {
        let b = bundle();
        let now = Instant::now();
        let t = PendingAsks::default();
        let limits = AskLimits {
            global: 100,
            per_source: 1_000,
            blind_cap: 75,
        };
        // No accounting: blind asks up to their share, then refused.
        for i in 0..75 {
            assert_eq!(
                t.admit(AskKind::Blind, None, limits),
                AskAdmission::Admitted
            );
            t.insert_blind(BlindTag(tag(i)), ask(now, None, &b));
        }
        assert_eq!(t.admit(AskKind::Blind, None, limits), AskAdmission::Full);
        // Identity asks fill the remaining 25.
        for i in 0..25 {
            assert_eq!(
                t.admit(AskKind::Identity, None, limits),
                AskAdmission::Admitted,
                "{i}"
            );
            t.insert(PairTag(tag(i)), ask(now, None, &b));
        }
        assert_eq!(t.len(), 100);
        // Full, identity at its reserve: refused, nothing evicted.
        assert_eq!(t.admit(AskKind::Identity, None, limits), AskAdmission::Full);
        assert_eq!(t.len(), 100);
        // Blind asks over their share (inserted around the caps, as a
        // concurrent admission can): an identity ask under its reserve
        // evicts the oldest blind ask.
        t.remove(&PairTag(tag(0)));
        t.insert_blind(
            BlindTag(tag(500)),
            ask(now + Duration::from_secs(1), None, &b),
        );
        assert_eq!(
            t.admit(AskKind::Identity, None, limits),
            AskAdmission::Admitted
        );
        assert_eq!(t.len(), 99);
        assert!(
            t.get_blind(&BlindTag(tag(500))).is_some(),
            "the newest blind ask stays"
        );
        t.assert_index_consistent();
    }

    /// N-1 (c) with accounting: a heavy blind source at the blind share
    /// loses its oldest blind ask to a lighter source's blind ask; identity
    /// asks are untouched.
    #[test]
    fn a_full_blind_share_evicts_from_the_heaviest_blind_source() {
        let b = bundle();
        let now = Instant::now();
        let t = PendingAsks::default();
        let limits = AskLimits {
            global: 100,
            per_source: 1_000,
            blind_cap: 10,
        };
        for i in 0..10 {
            t.insert_blind(
                BlindTag(tag(i)),
                ask(now + Duration::from_millis(i.into()), Some(src(1)), &b),
            );
        }
        for i in 0..5 {
            t.insert(PairTag(tag(i)), ask(now, Some(src(3)), &b));
        }
        assert_eq!(
            t.admit(AskKind::Blind, Some(src(2)), limits),
            AskAdmission::Admitted
        );
        assert!(
            t.get_blind(&BlindTag(tag(0))).is_none(),
            "the oldest blind ask went"
        );
        assert_eq!(t.len(), 14);
        // The heavy source itself is refused, not served by evicting itself.
        t.insert_blind(BlindTag(tag(99)), ask(now, Some(src(2)), &b));
        assert_eq!(
            t.admit(AskKind::Blind, Some(src(1)), limits),
            AskAdmission::Full
        );
        t.assert_index_consistent();
    }

    /// Fill a table of `n` asks over 200 sources, then time 2,000
    /// full-table admits (each evicting) plus inserts.
    fn full_table_admit_cost(n: usize) -> Duration {
        let b = bundle();
        let t = PendingAsks::default();
        let now = Instant::now();
        for i in 0..n {
            let s = Some(src((i % 200) as u8));
            t.insert_blind(
                BlindTag(tag(i as u32)),
                ask(now + Duration::from_micros(i as u64), s, &b),
            );
        }
        let limits = AskLimits {
            global: n,
            per_source: usize::MAX,
            blind_cap: n,
        };
        let light = Some(src(250));
        let start = Instant::now();
        for i in 0..2_000u32 {
            // A fresh light source each time, so every admit evicts.
            let caller = Some(SourceKey({
                let mut k = [0xEE; 32];
                k[..4].copy_from_slice(&i.to_be_bytes());
                k
            }));
            assert_eq!(
                t.admit(AskKind::Blind, caller, limits),
                AskAdmission::Admitted
            );
            t.insert_blind(BlindTag(tag(1_000_000 + i)), ask(now, light, &b));
        }
        start.elapsed()
    }

    /// N-1 (b): admit cost at a full table does not grow with the table.
    /// A 16x larger table may cost at most 4x per admit (the O(n) scan it
    /// replaced cost 16x, plus the per-admit clone of every source count);
    /// best of three runs against scheduler noise.
    #[test]
    fn full_table_admit_cost_does_not_grow_linearly() {
        let best = |n| (0..3).map(|_| full_table_admit_cost(n)).min().unwrap();
        let small = best(2_000);
        let large = best(32_000);
        assert!(
            large < small * 4 + Duration::from_millis(20),
            "admit cost grew with the table: {small:?} at 2,000, {large:?} at 32,000"
        );
    }
}
