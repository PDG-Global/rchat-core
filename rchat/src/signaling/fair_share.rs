//! Per-source and per-identity fair shares of client-creatable relay state
//! (findings R-3, R-11):
//!
//! * [`PendingAsks`] - the one-sided `CircuitAsk` table with a per-source
//!   count kept in step with every insert and removal, so the per-source
//!   cap is O(1) and a full table evicts from the heaviest source instead
//!   of refusing everyone.
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
use super::tags::{IdTag, PairTag};
use crate::limits::SourceKey;
use dashmap::mapref::multiple::RefMulti;
use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashMap;

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

/// The pending-ask table. Every removal path goes through these methods so
/// the per-source counts stay exact. `get_mut` callers must not change an
/// ask's `source`.
#[derive(Default)]
pub(crate) struct PendingAsks {
    map: DashMap<PairTag, PendingAsk>,
    per_source: Mutex<HashMap<SourceKey, usize>>,
}

impl PendingAsks {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, pair: &PairTag) -> Option<Ref<'_, PairTag, PendingAsk>> {
        self.map.get(pair)
    }

    pub fn get_mut(&self, pair: &PairTag) -> Option<RefMut<'_, PairTag, PendingAsk>> {
        self.map.get_mut(pair)
    }

    #[allow(dead_code)]
    pub fn contains_key(&self, pair: &PairTag) -> bool {
        self.map.contains_key(pair)
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = RefMulti<'_, PairTag, PendingAsk>> {
        self.map.iter()
    }

    pub fn insert(&self, pair: PairTag, ask: PendingAsk) -> Option<PendingAsk> {
        let source = ask.source;
        let old = self.map.insert(pair, ask);
        let mut counts = self.per_source.lock();
        if let Some(s) = old.as_ref().and_then(|o| o.source) {
            sub(&mut counts, s);
        }
        if let Some(s) = source {
            add(&mut counts, s);
        }
        old
    }

    pub fn remove(&self, pair: &PairTag) -> Option<(PairTag, PendingAsk)> {
        let removed = self.map.remove(pair);
        self.forget(removed.as_ref().map(|(_, a)| a));
        removed
    }

    pub fn remove_if(
        &self,
        pair: &PairTag,
        f: impl FnOnce(&PairTag, &PendingAsk) -> bool,
    ) -> Option<(PairTag, PendingAsk)> {
        let removed = self.map.remove_if(pair, f);
        self.forget(removed.as_ref().map(|(_, a)| a));
        removed
    }

    /// Keep the asks for which `keep` is true. O(n): used by the periodic
    /// sweep and on disconnect (≤ `max_pending_circuit_targets` entries).
    pub fn retain(&self, mut keep: impl FnMut(&PairTag, &PendingAsk) -> bool) {
        let mut gone: Vec<SourceKey> = Vec::new();
        self.map.retain(|k, a| {
            let kept = keep(k, a);
            if !kept {
                if let Some(s) = a.source {
                    gone.push(s);
                }
            }
            kept
        });
        if !gone.is_empty() {
            let mut counts = self.per_source.lock();
            for s in gone {
                sub(&mut counts, s);
            }
        }
    }

    fn forget(&self, ask: Option<&PendingAsk>) {
        if let Some(s) = ask.and_then(|a| a.source) {
            sub(&mut self.per_source.lock(), s);
        }
    }

    /// Pending asks currently held by `source`.
    pub fn source_count(&self, source: &SourceKey) -> usize {
        self.per_source.lock().get(source).copied().unwrap_or(0)
    }

    /// Room for one more ask from `source`? Over the per-source share it is
    /// refused. With the table full, the oldest ask of the heaviest source
    /// is evicted when that source holds more than the caller's would after
    /// this ask; otherwise refused. Without a source (accounting off) only
    /// the global cap applies.
    pub fn admit(
        &self,
        source: Option<SourceKey>,
        global: usize,
        per_source: usize,
    ) -> AskAdmission {
        let own = source.map(|s| self.source_count(&s)).unwrap_or(0);
        if source.is_some() && own >= per_source {
            return AskAdmission::SourceFull;
        }
        if self.map.len() < global {
            return AskAdmission::Admitted;
        }
        let heaviest = self
            .per_source
            .lock()
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(s, n)| (*s, *n));
        match heaviest {
            Some((victim, n)) if source.is_some() && n > own + 1 => {
                if self.evict_oldest_of(victim) {
                    AskAdmission::Admitted
                } else {
                    AskAdmission::Full
                }
            }
            _ => AskAdmission::Full,
        }
    }

    /// Remove the oldest ask held by `source`. O(n), only when the table is
    /// full.
    fn evict_oldest_of(&self, source: SourceKey) -> bool {
        let oldest = self
            .map
            .iter()
            .filter(|e| e.source == Some(source))
            .min_by_key(|e| e.at)
            .map(|e| *e.key());
        let Some(pair) = oldest else {
            return false;
        };
        let evicted = self
            .remove_if(&pair, |_, a| a.source == Some(source))
            .is_some();
        if evicted {
            crate::metrics::reject(crate::metrics::REJECT_PENDING_EVICTED);
        }
        evicted
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
