//! Held copies (owner ruling 2026-10-26, Task 8 B; review M1, L1).
//!
//! A relayed record (a relay packet, or a `QueuedMessage` from the offline
//! queue, a D34 hand-over or a live knock) is acknowledged to its sender
//! once it is queued to the recipient's connection, and the writer used to
//! forget it as soon as the socket accepted its bytes. A recipient that
//! vanished without a FIN never reads those bytes, and nothing re-sent
//! them: the sender saw "Sent" and no receipt. So each connection keeps a
//! copy of every relayed record written to it, with the offset in the TCP
//! stream its frame ends at, until the client's TCP stack has acknowledged
//! those bytes:
//!
//! - **Released on acknowledgement.** The connection checks what the
//!   kernel reports acknowledged (`tcp_ack`) on every frame it reads from
//!   the client and on its read loop's idle tick (at most every 5 s), and
//!   once more when it ends. A copy goes once its end offset is
//!   acknowledged: its bytes reached the client's kernel. That is proof of
//!   arrival, not of the app having read it; it is good enough (owner
//!   ruling). A client frame is a sign of life only: it never releases a
//!   copy whose bytes are not acknowledged.
//! - **Fallback without a source.** Where the platform cannot report
//!   acknowledgement (`AckSource::acked` returns None), a client frame
//!   discards the copies written at least `guard` before it was read, the
//!   earlier timing rule. Linux, Android, FreeBSD, macOS and iOS have a
//!   source.
//! - **A client Close** (a deliberate disconnect) releases what is
//!   acknowledged, and the rest is re-queued like any other end (review
//!   L1): a record written while the Close was in flight never reaches the
//!   client.
//! - **Any end** (keepalive failure, idle timeout, writer stall, shedding,
//!   a stale connection closed by a newer publish, a read error, an EOF or
//!   a Close) puts the copies still held back into the recipient's offline
//!   queue, oldest first, ahead of the writer's in-flight record and unsent
//!   queue (`salvage_unsent`), exactly as salvaged records go back today.
//!
//! The copies are bounded by a budget of their own (`HeldBudget`, review
//! M2), separate from the offline store's, so they never crowd out
//! messages waiting for offline recipients: per connection
//! `held_copy_max_bytes_per_connection` (4 MiB) and at most
//! `HELD_COPY_MAX_PER_CONNECTION` copies, relay-wide
//! `held_copy_max_total_bytes` (64 MiB). A copy that does not fit evicts
//! that connection's own oldest copies, one at a time, and only while doing
//! so can make room; if it cannot fit even with all of them gone, only the
//! new copy is dropped. Each dropped copy is counted as
//! `held_copy_dropped`.

use super::tcp_ack::{Ack, AckSource};
use crate::limits::{HeldBudget, HELD_COPY_MAX_PER_CONNECTION};
use crate::metrics;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

/// Fallback only (no acknowledgement source): how long before a client
/// frame is read a copy must have been written for that frame to discard
/// it (one round trip, plus time the frame waited in the relay's receive
/// buffer). It is a heuristic, which is why the kernel's acknowledgement is
/// used wherever the platform reports it.
pub(crate) const HOLD_GUARD: Duration = Duration::from_secs(10);

struct Copy {
    msg: Message,
    /// When the record was first stored, for one from the offline queue
    /// (its TTL keeps running from then); None for a live frame.
    enqueued_at: Option<u64>,
    written_at: Instant,
    /// Offset in the connection's TCP stream at which this copy's frame
    /// ends (bytes the kernel had accepted once it was flushed).
    end: u64,
    cost: usize,
}

#[derive(Default)]
struct Inner {
    copies: VecDeque<Copy>,
    bytes: usize,
}

/// One connection's held copies, oldest first.
pub(crate) struct HeldCopies {
    inner: Mutex<Inner>,
    budget: Arc<HeldBudget>,
    guard: Duration,
    ack: Arc<dyn AckSource>,
}

impl HeldCopies {
    pub(crate) fn new(budget: Arc<HeldBudget>, guard: Duration, ack: Arc<dyn AckSource>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            budget,
            guard,
            ack,
        }
    }

    /// The connection joined a video lane (`AckSource::bound_send_queue`).
    pub(crate) fn bound_send_queue(&self) {
        self.ack.bound_send_queue();
    }

    /// Keep a copy of `msg`, a relayed record the writer has just written
    /// in full. When it does not fit, this connection's own oldest copies
    /// go first, one at a time, but only if that can make room: a copy
    /// that could not fit even with every other copy of this connection
    /// gone is dropped alone, and the others stay (review M2). Each drop is
    /// counted.
    pub(crate) fn hold(&self, msg: Message, enqueued_at: Option<u64>, now: Instant) {
        let cost = msg.len().max(1);
        // Read after the write was flushed: the frame ends at or before it.
        let end = self.ack.written();
        let per_connection = self.budget.max_per_connection();
        let mut inner = self.inner.lock();
        loop {
            let fits_here = inner.bytes + cost <= per_connection
                && inner.copies.len() < HELD_COPY_MAX_PER_CONNECTION;
            if fits_here && self.budget.try_add(cost) {
                inner.bytes += cost;
                inner.copies.push_back(Copy {
                    msg,
                    enqueued_at,
                    written_at: now,
                    end,
                    cost,
                });
                return;
            }
            // Could it fit with all of this connection's copies gone?
            let could_fit = cost <= per_connection && cost <= self.budget.free() + inner.bytes;
            if !could_fit {
                metrics::reject(metrics::REJECT_HELD_COPY_DROPPED);
                return;
            }
            match inner.copies.pop_front() {
                Some(old) => {
                    metrics::reject(metrics::REJECT_HELD_COPY_DROPPED);
                    inner.bytes -= old.cost;
                    self.budget.release(old.cost);
                }
                None => {
                    // Another connection took the room meanwhile.
                    metrics::reject(metrics::REJECT_HELD_COPY_DROPPED);
                    return;
                }
            }
        }
    }

    /// Release the copies whose bytes the client's TCP stack has
    /// acknowledged. Returns the kernel's answer.
    fn release_acknowledged(&self) -> Ack {
        let answer = self.ack.acked();
        let Ack::Acked(acked) = answer else {
            // No source on this platform, or a dropped connection (re-review
            // H1): nothing is released by acknowledgement. Counted so a
            // silent fallback shows after deploy.
            metrics::HELD_ACK_UNAVAILABLE.inc();
            return answer;
        };
        let mut inner = self.inner.lock();
        while inner.copies.front().is_some_and(|c| c.end <= acked) {
            if let Some(c) = inner.copies.pop_front() {
                inner.bytes -= c.cost;
                self.budget.release(c.cost);
            }
        }
        answer
    }

    /// A frame from the client was read at `now`: a sign of life. Copies go
    /// only once acknowledged. Only on a platform with no source at all does
    /// the timing guard apply; a connection whose state gives no answer (it
    /// was dropped, and frames it sent before can still be read) releases
    /// nothing, and its copies are re-queued at teardown (R2-M1).
    pub(crate) fn on_client_frame(&self, now: Instant) {
        if self.release_acknowledged() == Ack::NoSource {
            self.release_by_guard(now);
        }
    }

    /// The read loop's idle tick: release what has been acknowledged.
    pub(crate) fn tick(&self) {
        let _ = self.release_acknowledged();
    }

    /// Fallback: discard the copies written at least `guard` before `now`.
    fn release_by_guard(&self, now: Instant) {
        let mut inner = self.inner.lock();
        while inner
            .copies
            .front()
            .is_some_and(|c| c.written_at + self.guard <= now)
        {
            if let Some(c) = inner.copies.pop_front() {
                inner.bytes -= c.cost;
                self.budget.release(c.cost);
            }
        }
    }

    /// The connection ended without proof: every copy, oldest first, with
    /// its first store time. Their reservation is released here; the
    /// caller re-queues them through the normal admission.
    pub(crate) fn take(&self) -> Vec<(Message, Option<u64>)> {
        let mut inner = self.inner.lock();
        let copies = std::mem::take(&mut inner.copies);
        inner.bytes = 0;
        copies
            .into_iter()
            .map(|c| {
                self.budget.release(c.cost);
                (c.msg, c.enqueued_at)
            })
            .collect()
    }

    /// Copies held now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().copies.len()
    }
}

impl Drop for HeldCopies {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        for c in inner.copies.drain(..) {
            self.budget.release(c.cost);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::tcp_ack::FakeAck;
    use std::sync::atomic::Ordering;

    /// Copies whose acknowledgement the test does not care about (never
    /// acknowledged).
    fn new_held(budget: &Arc<HeldBudget>) -> HeldCopies {
        HeldCopies::new(budget.clone(), HOLD_GUARD, FakeAck::new(0))
    }

    fn msg(n: usize) -> Message {
        Message::Binary(vec![0x02; n])
    }

    fn tagged(tag: u8, n: usize) -> Message {
        Message::Binary(vec![tag; n])
    }

    fn tags(held: &HeldCopies) -> Vec<u8> {
        held.take()
            .into_iter()
            .map(|(m, _)| m.into_data()[0])
            .collect()
    }

    /// Review M1: a client frame is a sign of life, never a release: a copy
    /// whose bytes are not acknowledged survives it, however late.
    #[test]
    fn an_unacknowledged_copy_survives_a_client_frame() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 1 << 20));
        let ack = FakeAck::new(0);
        let held = HeldCopies::new(budget.clone(), HOLD_GUARD, ack.clone());
        let t0 = Instant::now();
        ack.written.store(500, Ordering::SeqCst);
        held.hold(msg(100), None, t0);
        held.on_client_frame(t0 + Duration::from_secs(3600));
        held.tick();
        assert_eq!(held.len(), 1, "not acknowledged: kept");
        ack.set_acked(499);
        held.on_client_frame(t0 + Duration::from_secs(3601));
        assert_eq!(held.len(), 1, "one byte short: kept");
    }

    /// Review M1: a copy goes once the bytes its frame ends at are
    /// acknowledged, in order, with or without a client frame.
    #[test]
    fn a_copy_is_released_once_its_bytes_are_acknowledged() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 1 << 20));
        let ack = FakeAck::new(0);
        let held = HeldCopies::new(budget.clone(), HOLD_GUARD, ack.clone());
        let now = Instant::now();
        for (i, end) in [(1u8, 1000u64), (2, 2000), (3, 3000)] {
            ack.written.store(end, Ordering::SeqCst);
            held.hold(tagged(i, 100), None, now);
        }
        ack.set_acked(2000);
        held.tick();
        assert_eq!(held.len(), 1, "the first two are acknowledged");
        ack.set_acked(3000);
        held.on_client_frame(now);
        assert_eq!(held.len(), 0);
        assert_eq!(budget.used(), 0, "reservations released");
    }

    /// R2-M1: a dropped connection (no answer from a platform that has a
    /// source) releases nothing on a client frame, however late; only a
    /// platform without any source uses the timing guard.
    #[test]
    fn a_dead_connection_releases_nothing_on_a_client_frame() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 1 << 20));
        let held = HeldCopies::new(budget.clone(), HOLD_GUARD, FakeAck::new(FakeAck::DEAD));
        let t0 = Instant::now();
        held.hold(msg(100), None, t0);
        held.on_client_frame(t0 + Duration::from_secs(3600));
        held.tick();
        assert_eq!(held.len(), 1, "kept for re-queueing");
        assert_eq!(held.take().len(), 1);
    }

    /// Without an acknowledgement source, the timing guard applies.
    #[test]
    fn without_a_source_a_frame_discards_copies_written_a_guard_before_it() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 1 << 20));
        let held = HeldCopies::new(
            budget.clone(),
            Duration::from_secs(10),
            FakeAck::new(FakeAck::NO_SOURCE),
        );
        let t0 = Instant::now();
        held.hold(msg(100), None, t0);
        held.hold(msg(100), None, t0 + Duration::from_secs(8));
        let unavailable = metrics::HELD_ACK_UNAVAILABLE.get();
        held.tick();
        assert_eq!(held.len(), 2, "the tick releases nothing without a source");
        assert!(
            metrics::HELD_ACK_UNAVAILABLE.get() > unavailable,
            "the fallback is counted"
        );
        held.on_client_frame(t0 + Duration::from_secs(12));
        assert_eq!(held.len(), 1, "the copy written 4 s before stays");
        held.on_client_frame(t0 + Duration::from_secs(18));
        assert_eq!(held.len(), 0);
        assert_eq!(budget.used(), 0, "reservations released");
    }

    #[test]
    fn over_the_per_connection_budget_the_oldest_copy_goes_first() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 250));
        let held = new_held(&budget);
        let now = Instant::now();
        let before = metrics::rejections(metrics::REJECT_HELD_COPY_DROPPED);
        for i in 0..3u8 {
            held.hold(tagged(i, 100), None, now);
        }
        assert_eq!(tags(&held), vec![1, 2], "oldest dropped, order kept");
        assert!(metrics::rejections(metrics::REJECT_HELD_COPY_DROPPED) > before);
        assert_eq!(budget.used(), 0);
    }

    /// Review M2: another connection filling the relay-wide budget costs
    /// this connection only the copies that make room, never its whole set
    /// plus the new copy.
    #[test]
    fn a_full_relay_wide_budget_never_empties_a_connection_for_nothing() {
        let budget = Arc::new(HeldBudget::new(300, 300));
        let mine = new_held(&budget);
        let other = new_held(&budget);
        let now = Instant::now();
        mine.hold(tagged(1, 100), None, now);
        mine.hold(tagged(2, 50), None, now);
        other.hold(tagged(9, 150), None, now);
        assert_eq!(budget.used(), 300);
        // 200 bytes cannot fit even with all 150 of mine gone: only the new
        // copy is dropped, mine stay.
        mine.hold(tagged(3, 200), None, now);
        assert_eq!(
            mine.len(),
            2,
            "nothing of mine evicted for a copy that cannot fit"
        );
        // 100 bytes fit once my oldest (100) goes: exactly that one goes.
        mine.hold(tagged(4, 100), None, now);
        assert_eq!(tags(&mine), vec![2, 4]);
        assert_eq!(budget.used(), 150, "only the other connection's copy left");
        assert_eq!(tags(&other), vec![9]);
        assert_eq!(budget.used(), 0);
    }

    /// Review M2: held copies have their own budget; filling it leaves the
    /// offline store's budget untouched.
    #[test]
    fn held_copies_never_touch_the_offline_budget() {
        let offline = crate::limits::OfflineBudget::new(1 << 20, 1 << 20);
        let budget = Arc::new(HeldBudget::new(1000, 1000));
        let held = new_held(&budget);
        for _ in 0..20 {
            held.hold(msg(100), None, Instant::now());
        }
        assert_eq!(budget.used(), 1000, "the held budget is full");
        assert_eq!(offline.used(), 0, "the offline store's is not touched");
        assert!(offline.try_reserve(0, 0, 1 << 19).is_ok());
    }

    #[test]
    fn a_copy_larger_than_the_connection_budget_is_dropped_alone() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 500));
        let held = new_held(&budget);
        let now = Instant::now();
        held.hold(tagged(1, 100), None, now);
        held.hold(tagged(2, 600), None, now);
        assert_eq!(tags(&held), vec![1]);
    }

    #[test]
    fn take_and_drop_release_the_budget() {
        let budget = Arc::new(HeldBudget::new(1 << 20, 1 << 20));
        let held = new_held(&budget);
        held.hold(msg(10), Some(7), Instant::now());
        assert_eq!(held.take().len(), 1);
        assert_eq!((held.len(), budget.used()), (0, 0));
        held.hold(msg(10), Some(7), Instant::now());
        drop(held);
        assert_eq!(budget.used(), 0);
    }
}
