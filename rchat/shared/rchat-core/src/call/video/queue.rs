//! The video connections' send queue: `VIDEO_QUEUE_SLOTS` preallocated
//! slots of `MAX_VIDEO_WIRE` bytes (about 395 KB), each fragment stamped
//! with its enqueue time. Whole frames only: a frame that does not fit is
//! dropped, unless it is a keyframe, which discards what is waiting (older
//! frames are of no use once a keyframe is coming). Fragments are sealed
//! straight into their slots by the caller's `fill`, so a push copies once
//! and allocates nothing. The queue never seals or reseals: a lane restart
//! clears it and the sealer, which the caller owns, carries on.

use super::MAX_VIDEO_WIRE;
use crate::call::lanes::SendQueue;
use std::time::{Duration, Instant};

pub(crate) const VIDEO_QUEUE_SLOTS: usize = 48;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pushed {
    Queued {
        lane: u8,
    },
    Dropped,
    ClearedForKeyframe {
        lane: u8,
    },
    /// Neither video connection is up.
    NoLane,
    /// Not sent: the connection the frames were on fell behind or stalled
    /// (R12), so what waited there was dropped and the frames move to
    /// `lane`, starting with a keyframe (a frame after the dropped ones
    /// would only be thrown away by the receiver).
    Switched {
        lane: u8,
    },
}

pub(crate) struct VideoQueue {
    lane: u8,
    buf: Vec<u8>,
    lens: [usize; VIDEO_QUEUE_SLOTS],
    at: [Option<Instant>; VIDEO_QUEUE_SLOTS],
    head: usize,
    len: usize,
    bytes: usize,
    /// A fragment was popped and its write has not finished.
    in_flight: bool,
    /// Since when this connection has had work without finishing a write.
    busy_since: Option<Instant>,
}

impl VideoQueue {
    pub(crate) fn new(lane: u8) -> Self {
        Self {
            lane,
            buf: vec![0; VIDEO_QUEUE_SLOTS * MAX_VIDEO_WIRE],
            lens: [0; VIDEO_QUEUE_SLOTS],
            at: [None; VIDEO_QUEUE_SLOTS],
            head: 0,
            len: 0,
            bytes: 0,
            in_flight: false,
            busy_since: None,
        }
    }

    /// Queues one frame of `n` fragments, `fill(i, slot)` sealing fragment
    /// `i` into `slot` and returning its length (0 on failure, which drops
    /// the frame). `keyframe`: may discard the queue to make room; if its
    /// `fill` then fails, the queue stays cleared (the frame is dropped).
    pub(crate) fn push_frame(
        &mut self,
        n: usize,
        keyframe: bool,
        now: Instant,
        fill: &mut dyn FnMut(usize, &mut [u8]) -> usize,
    ) -> Pushed {
        if n == 0 || n > VIDEO_QUEUE_SLOTS {
            return Pushed::Dropped;
        }
        let mut cleared = false;
        if VIDEO_QUEUE_SLOTS - self.len < n {
            if !keyframe {
                return Pushed::Dropped;
            }
            self.discard();
            cleared = true;
        }
        // Only a frame that is queued starts the clock: a failed fill leaves
        // the queue as it was, not stalled.
        let was_idle = self.len == 0 && !self.in_flight;
        let (start_len, start_bytes) = (self.len, self.bytes);
        for i in 0..n {
            let slot = (self.head + self.len) % VIDEO_QUEUE_SLOTS;
            let w = fill(
                i,
                &mut self.buf[slot * MAX_VIDEO_WIRE..(slot + 1) * MAX_VIDEO_WIRE],
            );
            if w == 0 || w > MAX_VIDEO_WIRE {
                self.len = start_len;
                self.bytes = start_bytes;
                return Pushed::Dropped;
            }
            self.lens[slot] = w;
            self.at[slot] = Some(now);
            self.len += 1;
            self.bytes += w;
        }
        if was_idle {
            self.busy_since = Some(now);
        }
        if cleared {
            Pushed::ClearedForKeyframe { lane: self.lane }
        } else {
            Pushed::Queued { lane: self.lane }
        }
    }

    fn discard(&mut self) {
        self.len = 0;
        self.bytes = 0;
        self.head = 0;
        self.at = [None; VIDEO_QUEUE_SLOTS];
    }

    /// Drops what waits, as on a lane switch. A write already handed to the
    /// socket is still in flight, so its stall clock keeps running.
    pub(crate) fn drop_waiting(&mut self) {
        self.discard();
        if !self.in_flight {
            self.busy_since = None;
        }
    }

    pub(crate) fn queued_bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn has_room(&self, n: usize) -> bool {
        VIDEO_QUEUE_SLOTS - self.len >= n
    }

    /// Age of the oldest waiting fragment.
    pub(crate) fn oldest(&self, now: Instant) -> Option<Duration> {
        if self.len == 0 {
            return None;
        }
        self.at[self.head].map(|t| now.saturating_duration_since(t))
    }

    /// How long this connection has had work and finished no write.
    pub(crate) fn since_progress(&self, now: Instant) -> Duration {
        self.busy_since
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t))
    }
}

impl SendQueue for VideoQueue {
    fn pop_into(&mut self, out: &mut Vec<u8>) -> bool {
        if self.len == 0 {
            return false;
        }
        let h = self.head;
        out.clear();
        out.extend_from_slice(&self.buf[h * MAX_VIDEO_WIRE..h * MAX_VIDEO_WIRE + self.lens[h]]);
        self.bytes -= self.lens[h];
        self.at[h] = None;
        self.head = (h + 1) % VIDEO_QUEUE_SLOTS;
        self.len -= 1;
        self.in_flight = true;
        true
    }

    fn clear(&mut self) {
        self.discard();
        self.in_flight = false;
        self.busy_since = None;
    }

    fn on_written(&mut self, _bytes: usize, at: Instant) {
        self.in_flight = false;
        self.busy_since = (self.len > 0).then_some(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn fill_len(len: usize) -> impl FnMut(usize, &mut [u8]) -> usize {
        move |i, slot| {
            slot[0] = 0x05;
            slot[1] = i as u8;
            len
        }
    }

    #[test]
    fn video_queue_drops_non_key_frames_that_do_not_fit_and_clears_for_a_keyframe() {
        let mut q = VideoQueue::new(2);
        let t0 = Instant::now();
        for _ in 0..VIDEO_QUEUE_SLOTS {
            assert_eq!(
                q.push_frame(1, false, t0, &mut fill_len(100)),
                Pushed::Queued { lane: 2 }
            );
        }
        assert_eq!(q.queued_bytes(), VIDEO_QUEUE_SLOTS * 100);
        assert_eq!(
            q.push_frame(2, false, t0, &mut fill_len(100)),
            Pushed::Dropped
        );
        assert_eq!(q.queued_bytes(), VIDEO_QUEUE_SLOTS * 100);
        assert_eq!(
            q.push_frame(3, true, t0, &mut fill_len(200)),
            Pushed::ClearedForKeyframe { lane: 2 }
        );
        assert_eq!(q.queued_bytes(), 3 * 200);
    }

    #[test]
    fn a_failed_fill_leaves_the_queue_unstalled_and_unchanged() {
        let mut q = VideoQueue::new(2);
        let t0 = Instant::now();
        let mut fail = |_: usize, _: &mut [u8]| 0;
        assert_eq!(q.push_frame(2, false, t0, &mut fail), Pushed::Dropped);
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(
            q.since_progress(t0 + Duration::from_secs(5)),
            Duration::ZERO
        );
        assert_eq!(q.oldest(t0 + Duration::from_secs(5)), None);
    }

    #[test]
    fn video_queue_reports_its_oldest_fragment_age() {
        let mut q = VideoQueue::new(3);
        let t0 = Instant::now();
        assert_eq!(q.oldest(t0), None);
        q.push_frame(2, false, t0, &mut fill_len(50));
        assert_eq!(
            q.oldest(t0 + Duration::from_millis(300)),
            Some(Duration::from_millis(300))
        );
        let mut out = Vec::new();
        assert!(q.pop_into(&mut out));
        assert_eq!(out.len(), 50);
        assert!(q.pop_into(&mut out));
        assert!(!q.pop_into(&mut out));
        assert_eq!(q.oldest(t0 + Duration::from_secs(1)), None);
        assert_eq!(q.queued_bytes(), 0);
    }
}
