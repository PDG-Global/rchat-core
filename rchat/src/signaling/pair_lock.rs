//! Keyed async locks: per identity pair for circuit creation (`PAIR_LOCKS`,
//! keyed by `PairTag`), per blinded pairing token (`BLIND_LOCKS`, keyed by
//! `BlindTag`), per identity tag for publishes (`ID_LOCKS`, keyed by
//! `IdTag`).
//!
//! Circuit creation reads and writes several maps (`identity_pair_circuits`,
//! `pending_asks`, `circuits`, per-connection circuit tables) and then sends
//! `CircuitCreatedV3`. Without serialisation, both peers' asks arriving at
//! the same instant could both decide "no match yet", or both match, and
//! each build a different circuit. Holding the pair's lock across the whole
//! decision *and* the notifications makes that sequence atomic per pair;
//! unrelated pairs are not serialised against each other.
//!
//! Entries are removed as soon as no task holds or waits for the lock, so the
//! map does not grow with the number of pairs ever seen.
//!
//! # Lock order (final review L4)
//!
//! `ID_LOCKS` before `BLIND_LOCKS`; **never** an `ID_LOCKS` lock while the
//! same task holds a `PAIR_LOCKS` or `BLIND_LOCKS` lock.
//!
//! * R21 (`end_departed_blind_rows`) takes the member's identity lock, then
//!   each row's token lock. A path holding a token or pair lock and then
//!   waiting for an identity lock could deadlock against it, so none does:
//!   publishes, the D34 forward, salvage and the first-ask hand-over take
//!   the identity lock with no pair or token lock held, and release it
//!   before any wait on a connection (R-1).
//! * Pair and token locks are never waited for while another pair or token
//!   lock is held: the circuit-table eviction under a creating pair's lock
//!   (`evict_for`) and the disconnect teardown only `try_lock`.
//!
//! Debug builds check the first rule at run time: taking an `ID_LOCKS` lock
//! in a task that holds a `PAIR_LOCKS` or `BLIND_LOCKS` guard panics (see
//! `order`). Code running outside a Tokio task is not tracked.

use super::tags::{BlindTag, IdTag, PairTag};
use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Which lock table a guard belongs to, for the lock-order check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// `ID_LOCKS`: must never be taken under `Pair` or `Blind`.
    Identity,
    /// `PAIR_LOCKS`.
    Pair,
    /// `BLIND_LOCKS`.
    Blind,
    /// Any other table (tests): not checked.
    Other,
}

/// Async locks keyed by `K`; an entry exists only while held or awaited.
pub struct KeyedLocks<K> {
    map: DashMap<K, Arc<Mutex<()>>>,
    kind: LockKind,
}

impl<K: Eq + Hash> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self::new(LockKind::Other)
    }
}

impl<K: Eq + Hash> KeyedLocks<K> {
    /// An empty table whose guards are checked as `kind`.
    pub fn new(kind: LockKind) -> Self {
        Self {
            map: DashMap::new(),
            kind,
        }
    }
}

lazy_static::lazy_static! {
    /// Process-wide lock table for circuit creation per identity pair.
    pub static ref PAIR_LOCKS: KeyedLocks<PairTag> = KeyedLocks::new(LockKind::Pair);
    /// Process-wide lock table for publishes per identity (spec §4.3: the
    /// success branch of a publish runs in one critical section per tag).
    /// Never taken while a `PAIR_LOCKS` or `BLIND_LOCKS` guard is held.
    pub static ref ID_LOCKS: KeyedLocks<IdTag> = KeyedLocks::new(LockKind::Identity);
    /// Process-wide lock table for blinded pairing per token (protocol v3
    /// §C.2), keyed by the token's `BlindTag`: matching, replay and busy
    /// decisions for one token, and its row's teardown, are serialised.
    pub static ref BLIND_LOCKS: KeyedLocks<BlindTag> = KeyedLocks::new(LockKind::Blind);
}

/// Debug-build check of the lock order: the `PAIR_LOCKS` and `BLIND_LOCKS`
/// guards each Tokio task holds, by task id. Release builds keep nothing.
mod order {
    use super::LockKind;

    #[cfg(debug_assertions)]
    lazy_static::lazy_static! {
        static ref HELD: dashmap::DashMap<tokio::task::Id, usize> = dashmap::DashMap::new();
    }

    /// Before waiting for a lock of `kind`: an identity lock under a pair
    /// or token lock is a lock-order violation.
    pub(super) fn before_acquire(kind: LockKind) {
        #[cfg(debug_assertions)]
        if kind == LockKind::Identity {
            if let Some(id) = tokio::task::try_id() {
                let held = HELD.get(&id).map(|n| *n).unwrap_or(0);
                assert!(
                    held == 0,
                    "lock order: ID_LOCKS taken while this task holds a PAIR_LOCKS or BLIND_LOCKS lock"
                );
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = kind;
    }

    /// A guard of `kind` was acquired.
    pub(super) fn acquired(kind: LockKind) {
        #[cfg(debug_assertions)]
        if matches!(kind, LockKind::Pair | LockKind::Blind) {
            if let Some(id) = tokio::task::try_id() {
                *HELD.entry(id).or_insert(0) += 1;
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = kind;
    }

    /// A guard of `kind` was released.
    pub(super) fn released(kind: LockKind) {
        #[cfg(debug_assertions)]
        if matches!(kind, LockKind::Pair | LockKind::Blind) {
            if let Some(id) = tokio::task::try_id() {
                HELD.remove_if_mut(&id, |_, n| {
                    *n = n.saturating_sub(1);
                    *n == 0
                });
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = kind;
    }

    /// Pair and token guards held by the current task (tests).
    #[cfg(all(test, debug_assertions))]
    pub(super) fn held_here() -> usize {
        tokio::task::try_id()
            .and_then(|id| HELD.get(&id).map(|n| *n))
            .unwrap_or(0)
    }
}

/// Holds a key's lock; releases it and prunes the table entry on drop.
pub struct KeyedGuard<K: Eq + Hash + Clone + 'static> {
    guard: Option<OwnedMutexGuard<()>>,
    key: K,
    locks: &'static KeyedLocks<K>,
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> KeyedLocks<K> {
    /// Acquire the lock for `key`. No map guard is held across the await.
    /// Debug builds panic on a lock-order violation (module docs).
    pub async fn lock(&'static self, key: K) -> KeyedGuard<K> {
        order::before_acquire(self.kind);
        // The entry guard is dropped at the end of this statement.
        let mutex = self.map.entry(key.clone()).or_default().clone();
        let guard = mutex.lock_owned().await;
        order::acquired(self.kind);
        KeyedGuard {
            guard: Some(guard),
            key,
            locks: self,
        }
    }

    /// The lock for `key` if nobody holds it now; never waits.
    pub fn try_lock(&'static self, key: K) -> Option<KeyedGuard<K>> {
        order::before_acquire(self.kind);
        let mutex = self.map.entry(key.clone()).or_default().clone();
        let guard = mutex.try_lock_owned().ok()?;
        order::acquired(self.kind);
        Some(KeyedGuard {
            guard: Some(guard),
            key,
            locks: self,
        })
    }

    /// Whether an entry for `key` is currently in the table.
    #[cfg(test)]
    pub fn is_tracked(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
}

impl<K: Eq + Hash + Clone + 'static> Drop for KeyedGuard<K> {
    fn drop(&mut self) {
        // Release the mutex first so our clone of the Arc is gone, then remove
        // the entry if nobody else holds or waits for it. `remove_if` runs
        // under the shard lock, and waiters clone the Arc under that same
        // lock (in `lock`), so a waiter is either counted here or creates a
        // fresh entry afterwards - never left holding an orphaned mutex while
        // another task locks a new one.
        drop(self.guard.take());
        order::released(self.locks.kind);
        self.locks
            .map
            .remove_if(&self.key, |_, m| Arc::strong_count(m) == 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lock_serialises_same_key_and_prunes_entry() {
        lazy_static::lazy_static! { static ref LOCKS: KeyedLocks<&'static str> = KeyedLocks::default(); }
        static INSIDE: AtomicUsize = AtomicUsize::new(0);
        static MAX: AtomicUsize = AtomicUsize::new(0);
        let mut tasks = Vec::new();
        for _ in 0..16 {
            tasks.push(tokio::spawn(async move {
                let _g = LOCKS.lock("x-y").await;
                let n = INSIDE.fetch_add(1, Ordering::SeqCst) + 1;
                MAX.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
                INSIDE.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(
            MAX.load(Ordering::SeqCst),
            1,
            "critical section must be exclusive"
        );
        assert!(
            !LOCKS.is_tracked(&"x-y"),
            "entry must be pruned when unused"
        );
    }

    #[tokio::test]
    async fn different_keys_do_not_block_each_other() {
        lazy_static::lazy_static! { static ref LOCKS: KeyedLocks<&'static str> = KeyedLocks::default(); }
        let _a = LOCKS.lock("a-b").await;
        tokio::time::timeout(Duration::from_secs(1), LOCKS.lock("c-d"))
            .await
            .expect("unrelated key must not wait");
    }

    /// Final review L4: an identity lock then a token lock is the allowed
    /// order; an identity lock taken while the task holds a token or pair
    /// lock panics in debug builds; released guards leave nothing tracked.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn lock_order_identity_under_a_pair_or_token_lock_panics() {
        use super::super::tags::{blind_tag, id_tag, pair_tag};
        let held = tokio::spawn(async {
            let _i = ID_LOCKS.lock(id_tag(&[0x51; 32])).await;
            let _b = BLIND_LOCKS.lock(blind_tag(&[0x52; 32])).await;
            order::held_here()
        })
        .await
        .expect("ID before BLIND is allowed");
        assert_eq!(held, 1);

        let under_blind = tokio::spawn(async {
            let _b = BLIND_LOCKS.lock(blind_tag(&[0x53; 32])).await;
            let _i = ID_LOCKS.lock(id_tag(&[0x54; 32])).await;
        })
        .await;
        assert!(under_blind.expect_err("ID under BLIND").is_panic());

        let under_pair = tokio::spawn(async {
            let _p = PAIR_LOCKS.lock(pair_tag(&[0x55; 32], &[0x56; 32])).await;
            let _i = ID_LOCKS.lock(id_tag(&[0x57; 32])).await;
        })
        .await;
        assert!(under_pair.expect_err("ID under PAIR").is_panic());

        let after = tokio::spawn(async {
            {
                let _b = BLIND_LOCKS.try_lock(blind_tag(&[0x58; 32]));
                let _p = PAIR_LOCKS.lock(pair_tag(&[0x59; 32], &[0x5A; 32])).await;
                assert_eq!(order::held_here(), 2);
            }
            let _i = ID_LOCKS.lock(id_tag(&[0x5B; 32])).await;
            order::held_here()
        })
        .await
        .expect("all released before the identity lock");
        assert_eq!(after, 0);
    }
}
