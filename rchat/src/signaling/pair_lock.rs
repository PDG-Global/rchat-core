//! Keyed async locks: per identity pair for circuit creation (`PAIR_LOCKS`,
//! keyed by `PairTag`), per identity tag for publishes (`ID_LOCKS`, keyed by
//! `IdTag`).
//!
//! Circuit creation reads and writes several maps (`identity_pair_circuits`,
//! `pending_asks`, `circuits`, per-connection circuit tables) and then sends
//! `CircuitCreatedV2`. Without serialisation, both peers' asks arriving at
//! the same instant could both decide "no match yet", or both match, and
//! each build a different circuit. Holding the pair's lock across the whole
//! decision *and* the notifications makes that sequence atomic per pair;
//! unrelated pairs are not serialised against each other.
//!
//! Entries are removed as soon as no task holds or waits for the lock, so the
//! map does not grow with the number of pairs ever seen.

use super::tags::{IdTag, PairTag};
use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Async locks keyed by `K`; an entry exists only while held or awaited.
pub struct KeyedLocks<K> {
    map: DashMap<K, Arc<Mutex<()>>>,
}

impl<K: Eq + Hash> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self {
            map: DashMap::new(),
        }
    }
}

lazy_static::lazy_static! {
    /// Process-wide lock table for circuit creation per identity pair.
    pub static ref PAIR_LOCKS: KeyedLocks<PairTag> = KeyedLocks::default();
    /// Process-wide lock table for publishes per identity (spec §4.3: the
    /// success branch of a publish runs in one critical section per tag).
    pub static ref ID_LOCKS: KeyedLocks<IdTag> = KeyedLocks::default();
}

/// Holds a key's lock; releases it and prunes the table entry on drop.
pub struct KeyedGuard<K: Eq + Hash + Clone + 'static> {
    guard: Option<OwnedMutexGuard<()>>,
    key: K,
    locks: &'static KeyedLocks<K>,
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> KeyedLocks<K> {
    /// Acquire the lock for `key`. No map guard is held across the await.
    pub async fn lock(&'static self, key: K) -> KeyedGuard<K> {
        // The entry guard is dropped at the end of this statement.
        let mutex = self.map.entry(key.clone()).or_default().clone();
        let guard = mutex.lock_owned().await;
        KeyedGuard {
            guard: Some(guard),
            key,
            locks: self,
        }
    }

    /// Whether an entry for `key` is currently in the table.
    /// The lock for `key` if nobody holds it now; never waits.
    pub fn try_lock(&'static self, key: K) -> Option<KeyedGuard<K>> {
        let mutex = self.map.entry(key.clone()).or_default().clone();
        let guard = mutex.try_lock_owned().ok()?;
        Some(KeyedGuard {
            guard: Some(guard),
            key,
            locks: self,
        })
    }

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
}
