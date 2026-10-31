//! The adaptive playback buffer (spec §6 "Receiving", D18). Pull-driven by
//! the audio loop every 20 ms; arrivals from both call connections. The
//! target is 60-400 ms from the better connection's jitter; a frame missing
//! at its playout time comes from the next frame's FEC if that has arrived,
//! else Opus PLC; more than 100 ms over target drops frames, quiet ones
//! at once and loud ones at most once per 5 pulls, any frame at once more
//! than 200 ms over (D33). Fixed storage: nothing allocates per frame.

use super::codec::Codec;
use super::{
    BITRATE_NORMAL, BITRATE_POOR, BUFFER_MAX_MS, BUFFER_MIN_MS, CATCH_UP_OVER_MS, FRAME_MS,
    FRAME_SAMPLES, MAX_OPUS_BYTES, POOR_CONCEALED_PCT, STEP_DOWN_AFTER, STEP_UP_AFTER,
};
use std::time::{Duration, Instant};

/// 64 frames (1.28 s): more than the 400 ms target plus catch-up and margin.
const SLOTS: usize = 64;
/// 2 s of arrivals per connection for the jitter estimate.
const JITTER_WINDOW: usize = 100;
/// 3 s of played frames for the concealed share.
const CONCEAL_WINDOW: usize = 150;
/// A connection with no arrival for this long is left out of the target.
const LANE_STALE: Duration = Duration::from_secs(1);
/// D33: a frame quieter than this (RMS of 32768) is skipped first.
pub const QUIET_RMS: f64 = 500.0;
/// D33: over the target by more than this, the next frame is skipped
/// whatever its energy.
const CATCH_UP_HARD_MS: u64 = 200;
/// D33: between 100 and 200 ms over, a loud frame is skipped at most once
/// per this many pulls (quiet frames go at once).
const LOUD_SKIP_EVERY: u32 = 5;
/// An underrun (the frame at the playout point has not arrived and nothing
/// newer is buffered) keeps the playout point in place for one pull, so a
/// frame that arrives a little late plays on the next pull and the buffer
/// re-grows by a frame instead of the point staying on the arrival edge and
/// losing every late frame. At most one hold per underrun episode, never in a
/// row: an outage moves on in step with the clock, which keeps the delay
/// bounded (spec §6, §9). After start the buffer only grows reactively, one
/// frame per underrun; the target governs the start and the catch-up only.
const UNDERRUN_HOLD_MAX: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Played {
    Audio,
    Fec,
    Concealed,
    Silence,
}

/// Frames played since the call started, by kind (the simulator's concealed
/// share). A test hook: never in an app library.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlayTotals {
    pub audio: u64,
    pub fec: u64,
    pub concealed: u64,
}

struct Slot {
    seq: u64,
    len: usize,
    filled: bool,
    data: [u8; MAX_OPUS_BYTES],
}

#[derive(Clone, Copy)]
struct LaneJitter {
    rel: [i32; JITTER_WINDOW],
    n: usize,
    at: usize,
    base: Option<Instant>,
    last: Option<Instant>,
}

impl LaneJitter {
    const fn new() -> Self {
        Self {
            rel: [0; JITTER_WINDOW],
            n: 0,
            at: 0,
            base: None,
            last: None,
        }
    }

    fn on_arrival(&mut self, seq: u64, at: Instant) {
        let send_offset = Duration::from_millis(seq.saturating_mul(FRAME_MS));
        let base = *self
            .base
            .get_or_insert(at.checked_sub(send_offset).unwrap_or(at));
        let elapsed = at.saturating_duration_since(base).as_millis() as i64;
        let rel = (elapsed - (seq.saturating_mul(FRAME_MS)) as i64).clamp(-60_000, 60_000) as i32;
        self.rel[self.at] = rel;
        self.at = (self.at + 1) % JITTER_WINDOW;
        self.n = (self.n + 1).min(JITTER_WINDOW);
        self.last = Some(at);
    }

    /// 95th percentile of the delay above the window's fastest frame, in ms.
    fn p95_ms(&self, now: Instant) -> Option<u64> {
        if self.n < 10
            || self
                .last
                .map_or(true, |l| now.saturating_duration_since(l) > LANE_STALE)
        {
            return None;
        }
        let mut v = self.rel;
        let w = &mut v[..self.n];
        w.sort_unstable();
        let min = w[0];
        let p95 = w[(self.n * 95 / 100).min(self.n - 1)];
        Some((p95 - min).max(0) as u64)
    }
}

/// The concealed share over the last 3 s of played frames (PLC only; a
/// frame rebuilt from FEC counts as received).
pub(crate) struct ConcealWindow {
    bits: [bool; CONCEAL_WINDOW],
    at: usize,
    n: usize,
    concealed: usize,
}

impl ConcealWindow {
    pub(crate) const fn new() -> Self {
        Self {
            bits: [false; CONCEAL_WINDOW],
            at: 0,
            n: 0,
            concealed: 0,
        }
    }

    pub(crate) fn push(&mut self, concealed: bool) {
        if self.n == CONCEAL_WINDOW && self.bits[self.at] {
            self.concealed -= 1;
        }
        self.bits[self.at] = concealed;
        if concealed {
            self.concealed += 1;
        }
        self.at = (self.at + 1) % CONCEAL_WINDOW;
        self.n = (self.n + 1).min(CONCEAL_WINDOW);
    }

    /// Frames the window holds (up to its size).
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn pct(&self) -> u32 {
        if self.n == 0 {
            return 0;
        }
        (self.concealed * 100 / self.n) as u32
    }
}

fn rms(pcm: &[i16; FRAME_SAMPLES]) -> f64 {
    let sum: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum();
    (sum / FRAME_SAMPLES as f64).sqrt()
}

pub struct Playout {
    slots: Box<[Slot]>,
    next: u64,
    lowest: Option<u64>,
    newest: Option<u64>,
    started: bool,
    jitter: [LaneJitter; 2],
    target_ms: u64,
    conceal: ConcealWindow,
    scratch: [i16; FRAME_SAMPLES],
    played_seq: Option<u64>,
    /// Pulls since the last loud frame was skipped (D33).
    since_loud_skip: u32,
    /// Consecutive pulls that waited at the playout point for a frame
    /// that had not arrived and had nothing behind it (underrun).
    holds: u32,
    #[cfg(any(test, feature = "test-hooks"))]
    totals: PlayTotals,
}

impl Default for Playout {
    fn default() -> Self {
        Self::new()
    }
}

impl Playout {
    pub fn new() -> Self {
        let slots = (0..SLOTS)
            .map(|_| Slot {
                seq: 0,
                len: 0,
                filled: false,
                data: [0; MAX_OPUS_BYTES],
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            next: 0,
            lowest: None,
            newest: None,
            started: false,
            jitter: [LaneJitter::new(); 2],
            target_ms: BUFFER_MIN_MS,
            conceal: ConcealWindow::new(),
            scratch: [0; FRAME_SAMPLES],
            played_seq: None,
            since_loud_skip: LOUD_SKIP_EVERY,
            holds: 0,
            #[cfg(any(test, feature = "test-hooks"))]
            totals: PlayTotals::default(),
        }
    }

    /// Test hook: frames played since the call started, by kind.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn totals(&self) -> PlayTotals {
        self.totals
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn count(&mut self, played: Played) {
        match played {
            Played::Audio => self.totals.audio += 1,
            Played::Fec => self.totals.fec += 1,
            Played::Concealed => self.totals.concealed += 1,
            Played::Silence => {}
        }
    }

    #[cfg(not(any(test, feature = "test-hooks")))]
    fn count(&mut self, _played: Played) {}

    pub fn target_ms(&self) -> u64 {
        self.target_ms
    }

    pub fn concealed_pct(&self) -> u32 {
        self.conceal.pct()
    }

    /// How many played frames the concealed share is judged over.
    pub fn window_frames(&self) -> usize {
        self.conceal.len()
    }

    pub fn poor(&self) -> bool {
        self.conceal.pct() > POOR_CONCEALED_PCT
    }

    pub fn played_seq(&self) -> Option<u64> {
        self.played_seq
    }

    pub fn depth_ms(&self) -> u64 {
        match (self.started, self.lowest, self.newest) {
            (true, _, Some(n)) if n + 1 >= self.next => (n + 1 - self.next) * FRAME_MS,
            (false, Some(lo), Some(n)) => (n + 1 - lo) * FRAME_MS,
            _ => 0,
        }
    }

    fn index(seq: u64) -> usize {
        (seq % SLOTS as u64) as usize
    }

    fn filled(&self, seq: u64) -> Option<usize> {
        let i = Self::index(seq);
        (self.slots[i].filled && self.slots[i].seq == seq).then_some(i)
    }

    fn clear(&mut self) {
        for s in self.slots.iter_mut() {
            s.filled = false;
        }
    }

    pub fn on_frame(&mut self, lane: u8, seq: u64, opus: &[u8], at: Instant) -> bool {
        if opus.is_empty() || opus.len() > MAX_OPUS_BYTES {
            return false;
        }
        self.jitter[usize::from(lane & 1)].on_arrival(seq, at);
        if self.started && seq < self.next {
            return false; // older than the playout point
        }
        if self.started && seq >= self.next + SLOTS as u64 {
            // Far ahead after a long gap: play from near the newest frame.
            self.clear();
            self.next = seq.saturating_sub(self.target_ms / FRAME_MS);
        }
        if self.filled(seq).is_some() {
            return false;
        }
        let slot = &mut self.slots[Self::index(seq)];
        slot.seq = seq;
        slot.len = opus.len();
        slot.filled = true;
        slot.data[..opus.len()].copy_from_slice(opus);
        self.newest = Some(self.newest.map_or(seq, |n| n.max(seq)));
        if !self.started {
            self.lowest = Some(self.lowest.map_or(seq, |l| l.min(seq)));
        }
        true
    }

    fn update_target(&mut self, now: Instant) {
        let best = self.jitter.iter().filter_map(|j| j.p95_ms(now)).min();
        self.target_ms = match best {
            Some(j) => (j + 40).div_ceil(FRAME_MS) * FRAME_MS,
            None => BUFFER_MIN_MS,
        }
        .clamp(BUFFER_MIN_MS, BUFFER_MAX_MS);
    }

    fn take(&mut self, seq: u64) {
        if let Some(i) = self.filled(seq) {
            self.slots[i].filled = false;
        }
    }

    /// A stack copy of `seq`'s packet, so the codec can decode it while
    /// `self` is borrowed mutably (a copy, not an allocation).
    fn packet(&self, seq: u64) -> Option<([u8; MAX_OPUS_BYTES], usize)> {
        self.filled(seq)
            .map(|i| (self.slots[i].data, self.slots[i].len))
    }

    pub fn next_pcm(
        &mut self,
        codec: &mut dyn Codec,
        out: &mut [i16; FRAME_SAMPLES],
        now: Instant,
    ) -> Played {
        let played = self.next_pcm_inner(codec, out, now);
        self.count(played);
        played
    }

    fn next_pcm_inner(
        &mut self,
        codec: &mut dyn Codec,
        out: &mut [i16; FRAME_SAMPLES],
        now: Instant,
    ) -> Played {
        self.update_target(now);
        self.played_seq = None;
        if !self.started {
            if self.depth_ms() < self.target_ms {
                out.fill(0);
                return Played::Silence;
            }
            self.started = true;
            self.next = self.lowest.unwrap_or(0);
        }
        self.since_loud_skip = self.since_loud_skip.saturating_add(1);
        // Staying current (§6, D33): more than 100 ms over target, decode the
        // next frame and skip it if it is quiet, if a loud skip is due (one
        // per 5 pulls), or at once when more than 200 ms over; otherwise play
        // it. At most one skip per pull.
        let over = self.depth_ms().saturating_sub(self.target_ms);
        if over > CATCH_UP_OVER_MS {
            let seq = self.next;
            self.next += 1;
            // A hole while far behind is simply skipped.
            if let Some((data, len)) = self.packet(seq) {
                self.take(seq);
                let quiet = codec.decode(&data[..len], &mut self.scratch).is_err()
                    || rms(&self.scratch) < QUIET_RMS;
                let hard = over > CATCH_UP_HARD_MS;
                let loud_due = self.since_loud_skip >= LOUD_SKIP_EVERY;
                if !(quiet || hard || loud_due) {
                    out.copy_from_slice(&self.scratch);
                    self.played_seq = Some(seq);
                    self.conceal.push(false);
                    return Played::Audio;
                }
                if !quiet && !hard {
                    self.since_loud_skip = 0;
                }
            }
        }
        let seq = self.next;
        let underrun = self.packet(seq).is_none() && self.newest.map_or(true, |n| n < seq);
        if underrun && self.holds < UNDERRUN_HOLD_MAX {
            self.holds += 1;
            if codec.conceal(out).is_err() {
                out.fill(0);
            }
            self.conceal.push(true);
            return Played::Concealed;
        }
        if !underrun {
            self.holds = 0;
        }
        self.next += 1;
        let played = if let Some((data, len)) = self.packet(seq) {
            if codec.decode(&data[..len], out).is_ok() {
                Played::Audio
            } else {
                Played::Concealed
            }
        } else if let Some((data, len)) = self.packet(seq + 1) {
            // FEC only from a packet that carries it; else Opus would conceal anyway.
            if codec.packet_has_lbrr(&data[..len]) && codec.decode_fec(&data[..len], out).is_ok() {
                Played::Fec
            } else {
                Played::Concealed
            }
        } else {
            Played::Concealed
        };
        if played == Played::Concealed && codec.conceal(out).is_err() {
            out.fill(0);
        }
        self.take(seq);
        if played != Played::Concealed {
            self.played_seq = Some(seq);
        }
        self.conceal.push(played == Played::Concealed);
        played
    }
}

/// CBR 24 kbps, 16 kbps once "Poor connection" held 5 s, back after 10 s good (§6, D17).
pub struct BitrateStepper {
    current: i32,
    poor_since: Option<Instant>,
    good_since: Option<Instant>,
}

impl Default for BitrateStepper {
    fn default() -> Self {
        Self::new()
    }
}

impl BitrateStepper {
    pub fn new() -> Self {
        Self {
            current: BITRATE_NORMAL,
            poor_since: None,
            good_since: None,
        }
    }

    pub fn current(&self) -> i32 {
        self.current
    }

    pub fn update(&mut self, poor: bool, now: Instant) -> Option<i32> {
        if poor {
            self.good_since = None;
            let since = *self.poor_since.get_or_insert(now);
            if self.current == BITRATE_NORMAL
                && now.saturating_duration_since(since) >= STEP_DOWN_AFTER
            {
                self.current = BITRATE_POOR;
                return Some(self.current);
            }
        } else {
            self.poor_since = None;
            let since = *self.good_since.get_or_insert(now);
            if self.current == BITRATE_POOR && now.saturating_duration_since(since) >= STEP_UP_AFTER
            {
                self.current = BITRATE_NORMAL;
                return Some(self.current);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::codec::{Codec, CodecError};
    use std::time::{Duration, Instant};

    /// Deterministic codec: a packet `[e, seq_lo]` decodes to a constant
    /// sample `e * 100` (so `e = 0` is quiet, `e = 100` loud), FEC to -1,
    /// PLC to 0. Counts each kind and keeps the low byte of every decoded seq.
    #[derive(Default)]
    struct FakeCodec {
        decoded: usize,
        fec: usize,
        plc: usize,
        decoded_seqs: Vec<u8>,
    }

    impl Codec for FakeCodec {
        fn encode(&mut self, _: &[i16; FRAME_SAMPLES], _: &mut [u8]) -> Result<usize, CodecError> {
            unreachable!("playout never encodes")
        }
        fn decode(&mut self, p: &[u8], out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
            self.decoded += 1;
            self.decoded_seqs.push(p[1]);
            out.fill(i16::from(p[0]) * 100);
            Ok(())
        }
        fn decode_fec(
            &mut self,
            _: &[u8],
            out: &mut [i16; FRAME_SAMPLES],
        ) -> Result<(), CodecError> {
            self.fec += 1;
            out.fill(-1);
            Ok(())
        }
        fn conceal(&mut self, out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
            self.plc += 1;
            out.fill(0);
            Ok(())
        }
        fn set_bitrate(&mut self, _: i32) -> Result<(), CodecError> {
            Ok(())
        }
        fn bitrate(&self) -> i32 {
            0
        }
    }

    /// One connection: base delay, jitter (deterministic LCG), freezes
    /// `[start_ms, end_ms)` during which TCP holds everything back and the
    /// sender keeps only its 3 newest frames (60 ms), delivered at the end.
    #[derive(Clone, Default)]
    struct Link {
        delay_ms: u64,
        jitter_ms: u64,
        freezes: Vec<(u64, u64)>,
        lost: Vec<u64>,
    }

    fn arrivals(link: &Link, frames: u64, seed: u64) -> Vec<(u64, u64)> {
        let mut x = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut out = Vec::new();
        for seq in 0..frames {
            if link.lost.contains(&seq) {
                continue;
            }
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let send = seq * FRAME_MS;
            let mut arrive = send
                + link.delay_ms
                + if link.jitter_ms > 0 {
                    (x >> 33) % link.jitter_ms
                } else {
                    0
                };
            if let Some(&(s, e)) = link
                .freezes
                .iter()
                .find(|(s, e)| arrive >= *s && arrive < *e)
            {
                let _ = s;
                if send + 3 * FRAME_MS < e.saturating_sub(link.delay_ms) {
                    continue; // dropped from the 3-frame send queue
                }
                arrive = e;
            }
            out.push((arrive, seq));
        }
        out
    }

    struct Report {
        played: Vec<(u64, Played)>,
        /// (pull time ms, mouth-to-ear ms) for frames played from their own packet or FEC.
        delays: Vec<(u64, u64)>,
        codec: FakeCodec,
    }

    /// Feeds both links' arrivals and pulls at `pulls` (ms, ascending).
    fn run(links: [&Link; 2], frames: u64, pulls: &[u64], loud: impl Fn(u64) -> bool) -> Report {
        let t0 = Instant::now();
        let mut events: Vec<(u64, u8, u64)> = Vec::new();
        for (lane, link) in links.iter().enumerate() {
            for (at, seq) in arrivals(link, frames, lane as u64 + 7) {
                events.push((at, lane as u8, seq));
            }
        }
        events.sort();
        let mut p = Playout::new();
        let mut codec = FakeCodec::default();
        let mut out = [0i16; FRAME_SAMPLES];
        let (mut played, mut delays, mut i) = (Vec::new(), Vec::new(), 0);
        for &pull in pulls {
            while i < events.len() && events[i].0 <= pull {
                let (at, lane, seq) = events[i];
                let e = if loud(seq) { 100u8 } else { 0 };
                p.on_frame(lane, seq, &[e, seq as u8], t0 + Duration::from_millis(at));
                i += 1;
            }
            let kind = p.next_pcm(&mut codec, &mut out, t0 + Duration::from_millis(pull));
            if matches!(kind, Played::Audio | Played::Fec) {
                let seq = p.played_seq().expect("a played frame has a seq");
                delays.push((pull, pull.saturating_sub(seq * FRAME_MS)));
            }
            played.push((pull, kind));
        }
        Report {
            played,
            delays,
            codec,
        }
    }

    fn every_20ms(frames: u64) -> Vec<u64> {
        (0..frames).map(|i| i * FRAME_MS).collect()
    }

    #[test]
    fn steady_arrivals_play_every_frame_at_the_minimum_target() {
        let link = Link {
            delay_ms: 50,
            ..Link::default()
        };
        let r = run([&link, &link], 300, &every_20ms(300), |_| true);
        let after_start: Vec<_> = r
            .played
            .iter()
            .skip_while(|(_, k)| *k == Played::Silence)
            .collect();
        assert!(after_start.iter().all(|(_, k)| *k == Played::Audio));
        let max = r.delays.iter().map(|d| d.1).max().unwrap();
        assert!(max <= 50 + BUFFER_MIN_MS + FRAME_MS, "delay {max} ms");
    }

    /// Spec §9: no audible gap after a 600 ms freeze on one connection.
    #[test]
    fn a_600ms_freeze_on_one_connection_is_not_heard() {
        let frozen = Link {
            delay_ms: 50,
            jitter_ms: 10,
            freezes: vec![(2000, 2600)],
            ..Link::default()
        };
        let fine = Link {
            delay_ms: 50,
            jitter_ms: 10,
            ..Link::default()
        };
        let r = run([&frozen, &fine], 250, &every_20ms(250), |_| true);
        let concealed = r
            .played
            .iter()
            .filter(|(_, k)| *k == Played::Concealed)
            .count();
        assert_eq!(concealed, 0);
    }

    /// Spec §9: 200-600 ms freezes on both connections, delay stays bounded
    /// and comes back down.
    #[test]
    fn freezes_on_both_connections_keep_the_delay_bounded() {
        for freeze in [200u64, 400, 600] {
            let link = Link {
                delay_ms: 50,
                jitter_ms: 20,
                freezes: vec![(2000, 2000 + freeze)],
                ..Link::default()
            };
            let r = run([&link, &link.clone()], 400, &every_20ms(400), |_| true);
            let max = r.delays.iter().map(|d| d.1).max().unwrap();
            assert!(
                max <= 50 + 20 + BUFFER_MIN_MS + 2 * FRAME_MS,
                "{freeze} ms freeze: max delay {max}"
            );
            let settled: Vec<u64> = r
                .delays
                .iter()
                .filter(|(t, _)| *t >= 2000 + freeze + 2000)
                .map(|d| d.1)
                .collect();
            assert!(!settled.is_empty());
            assert!(
                settled
                    .iter()
                    .all(|d| *d <= 50 + 20 + BUFFER_MIN_MS + FRAME_MS),
                "{freeze} ms freeze: delay did not come back down: {settled:?}"
            );
        }
    }

    #[test]
    fn a_missing_frame_uses_the_next_frames_fec_else_plc() {
        // 10 lost on both links: 11 is there in time -> FEC. 20 and 21 lost: 20 -> PLC, 21 -> FEC from 22.
        let link = Link {
            delay_ms: 30,
            lost: vec![10, 20, 21],
            ..Link::default()
        };
        let r = run([&link, &link.clone()], 60, &every_20ms(60), |_| true);
        assert_eq!(r.codec.fec, 2, "frames 10 and 21");
        assert_eq!(r.codec.plc, 1, "frame 20");
    }

    #[test]
    fn frames_older_than_the_playout_point_are_dropped() {
        let t0 = Instant::now();
        let mut p = Playout::new();
        let mut codec = FakeCodec::default();
        let mut out = [0i16; FRAME_SAMPLES];
        for seq in 0..5 {
            assert!(p.on_frame(0, seq, &[100, 0], t0));
        }
        for i in 0..5 {
            p.next_pcm(&mut codec, &mut out, t0 + Duration::from_millis(i * 20));
        }
        assert!(
            !p.on_frame(1, 1, &[100, 0], t0 + Duration::from_millis(100)),
            "already past seq 1"
        );
    }

    /// 140 ms over the target (the 100-200 ms band of D33), a loud skip not
    /// yet due: a quiet frame at the playout point is skipped at once, a loud
    /// one is played. Deterministic, so no pointer phase decides it.
    fn pull_140_ms_over(first_energy: u8) -> Option<u64> {
        let mut codec = FakeCodec::default();
        let mut p = Playout::new();
        let mut out = [0i16; FRAME_SAMPLES];
        let t0 = Instant::now();
        for seq in 0..10u64 {
            let e = if seq == 0 { first_energy } else { 100 };
            assert!(p.on_frame(
                0,
                seq,
                &[e, seq as u8],
                t0 + Duration::from_millis(seq * FRAME_MS)
            ));
        }
        p.since_loud_skip = 0;
        let now = t0 + Duration::from_millis(10 * FRAME_MS);
        assert_eq!(p.next_pcm(&mut codec, &mut out, now), Played::Audio);
        p.played_seq()
    }

    #[test]
    fn catch_up_skips_a_quiet_frame_at_once_in_the_100_to_200_ms_band() {
        assert_eq!(
            pull_140_ms_over(0),
            Some(1),
            "frame 0 was quiet: skipped, 1 played"
        );
    }

    #[test]
    fn catch_up_plays_a_loud_frame_in_the_100_to_200_ms_band_until_a_skip_is_due() {
        assert_eq!(pull_140_ms_over(100), Some(0), "frame 0 was loud: played");
    }

    #[test]
    fn a_long_stall_comes_back_to_within_100_ms_over_the_target() {
        let max = catch_up_run(1520, 300);
        assert!(max <= 40 + BUFFER_MIN_MS + CATCH_UP_OVER_MS, "delay {max}");
    }

    /// Both links freeze 300 ms at 1 s; the audio thread then stalls `len` ms
    /// at `start`. Returns the largest delay after 2.2 s.
    fn catch_up_run(start: u64, len: u64) -> u64 {
        let link = Link {
            delay_ms: 40,
            freezes: vec![(1000, 1300)],
            ..Link::default()
        };
        let mut pulls = every_20ms(200);
        pulls.retain(|t| !(start..start + len).contains(t));
        let r = run([&link, &link.clone()], 200, &pulls, |seq| seq % 2 == 0);
        r.delays
            .iter()
            .filter(|(t, _)| *t > 2200)
            .map(|d| d.1)
            .max()
            .unwrap()
    }

    /// Review Focus 4: an irregular audio loop (two pulls back to back, then
    /// a 40 ms gap; a 200 ms stall) does not build up delay.
    #[test]
    fn late_and_bunched_pulls_do_not_grow_the_delay() {
        let link = Link {
            delay_ms: 50,
            jitter_ms: 15,
            ..Link::default()
        };
        let mut pulls = Vec::new();
        let mut t = 0;
        while t < 10_000 {
            pulls.push(t);
            pulls.push(t + 1); // bunched
            t += 40;
            if t == 4000 {
                t += 200; // stall
            }
        }
        let r = run([&link, &link.clone()], 500, &pulls, |_| true);
        let late: Vec<u64> = r
            .delays
            .iter()
            .filter(|(t, _)| *t > 6000)
            .map(|d| d.1)
            .collect();
        assert!(
            late.iter()
                .all(|d| *d <= 50 + 15 + BUFFER_MIN_MS + CATCH_UP_OVER_MS),
            "{late:?}"
        );
    }

    #[test]
    fn the_target_follows_the_better_connections_jitter() {
        let jittery = Link {
            delay_ms: 50,
            jitter_ms: 250,
            ..Link::default()
        };
        let steady = Link {
            delay_ms: 60,
            jitter_ms: 10,
            ..Link::default()
        };
        let t0 = Instant::now();
        let mut p = Playout::new();
        for (lane, link) in [(0u8, &jittery), (1u8, &steady)] {
            for (at, seq) in arrivals(link, 150, u64::from(lane)) {
                p.on_frame(lane, seq, &[100, 0], t0 + Duration::from_millis(at));
            }
        }
        let mut codec = FakeCodec::default();
        p.next_pcm(
            &mut codec,
            &mut [0; FRAME_SAMPLES],
            t0 + Duration::from_millis(3000),
        );
        assert!(
            (BUFFER_MIN_MS..=80).contains(&p.target_ms()),
            "target {}",
            p.target_ms()
        );
        // Both jittery: the target grows, never past 400 ms.
        let mut q = Playout::new();
        let wild = Link {
            delay_ms: 50,
            jitter_ms: 600,
            ..Link::default()
        };
        for lane in 0..2u8 {
            for (at, seq) in arrivals(&wild, 150, u64::from(lane) + 3) {
                q.on_frame(lane, seq, &[100, 0], t0 + Duration::from_millis(at));
            }
        }
        q.next_pcm(
            &mut codec,
            &mut [0; FRAME_SAMPLES],
            t0 + Duration::from_millis(3000),
        );
        assert!(
            q.target_ms() > 200 && q.target_ms() <= BUFFER_MAX_MS,
            "target {}",
            q.target_ms()
        );
    }

    #[test]
    fn poor_means_more_than_5_percent_concealed_in_the_last_3_s() {
        let mut w = ConcealWindow::new();
        for i in 0..150 {
            w.push(i < 7); // 7/150 = 4.7%
        }
        assert_eq!(w.pct(), 4);
        assert!(w.pct() <= POOR_CONCEALED_PCT);
        let mut w = ConcealWindow::new();
        for i in 0..150 {
            w.push(i < 9); // 6%
        }
        assert!(w.pct() > POOR_CONCEALED_PCT);
        // Only the last 3 s count.
        for _ in 0..150 {
            w.push(false);
        }
        assert_eq!(w.pct(), 0);
    }

    #[test]
    fn the_bitrate_steps_down_after_5_s_poor_and_up_after_10_s_good() {
        let t0 = Instant::now();
        let mut s = BitrateStepper::new();
        assert_eq!(s.current(), BITRATE_NORMAL);
        assert_eq!(s.update(true, t0), None);
        assert_eq!(s.update(true, t0 + Duration::from_millis(4900)), None);
        assert_eq!(s.update(true, t0 + STEP_DOWN_AFTER), Some(BITRATE_POOR));
        assert_eq!(s.update(false, t0 + Duration::from_secs(6)), None);
        // A poor moment restarts the good clock.
        assert_eq!(s.update(true, t0 + Duration::from_secs(10)), None);
        assert_eq!(s.update(false, t0 + Duration::from_secs(11)), None);
        assert_eq!(s.update(false, t0 + Duration::from_secs(20)), None);
        assert_eq!(
            s.update(false, t0 + Duration::from_secs(21)),
            Some(BITRATE_NORMAL)
        );
    }

    #[cfg(feature = "calls-codec")]
    #[test]
    fn with_opus_a_lost_frame_plays_as_fec_and_nothing_allocates() {
        use crate::call::codec::OpusCodec;
        let mut enc = OpusCodec::new().unwrap();
        let mut dec = OpusCodec::new().unwrap();
        let t0 = Instant::now();
        let mut p = Playout::new();
        let mut packets = Vec::new();
        for f in 0..40u64 {
            let pcm: [i16; FRAME_SAMPLES] = core::array::from_fn(|i| {
                (((f as usize * FRAME_SAMPLES + i) as f64 * 0.05).sin() * 8000.0) as i16
            });
            let mut out = [0u8; MAX_OPUS_BYTES];
            let n = enc.encode(&pcm, &mut out).unwrap();
            packets.push(out[..n].to_vec());
        }
        let mut kinds = Vec::with_capacity(packets.len());
        let mut out = [0i16; FRAME_SAMPLES];
        let bytes = crate::alloc_probe::bytes_allocated(|| {
            for (seq, pkt) in packets.iter().enumerate() {
                if seq != 20 {
                    p.on_frame(
                        0,
                        seq as u64,
                        pkt,
                        t0 + Duration::from_millis(seq as u64 * 20),
                    );
                }
                if seq >= 4 {
                    kinds.push(p.next_pcm(
                        &mut dec,
                        &mut out,
                        t0 + Duration::from_millis(seq as u64 * 20),
                    ));
                }
            }
        });
        assert!(kinds.contains(&Played::Fec));
        assert!(!kinds.contains(&Played::Concealed));
        assert_eq!(bytes, 0, "arrivals and pulls allocate nothing");
    }

    /// D33: between 100 and 200 ms over target a loud frame is skipped at
    /// most once per 5 pulls; more than 200 ms over, every pull skips one.
    #[test]
    fn loud_frames_are_skipped_at_most_once_per_5_pulls() {
        let t0 = Instant::now();
        let mut p = Playout::new();
        let mut codec = FakeCodec::default();
        let mut out = [0i16; FRAME_SAMPLES];
        // Frames keep arriving on time; the audio loop starts 320 ms late,
        // so it begins 260 ms over the 60 ms target.
        let mut arrived = 0u64;
        let mut last_loud_skip: Option<usize> = None;
        let mut overs = Vec::new();
        for pull in 0..40usize {
            let now_ms = 320 + pull as u64 * FRAME_MS;
            while arrived * FRAME_MS <= now_ms {
                p.on_frame(
                    0,
                    arrived,
                    &[100, arrived as u8],
                    t0 + Duration::from_millis(arrived * FRAME_MS),
                );
                arrived += 1;
            }
            let over = p.depth_ms().saturating_sub(p.target_ms());
            let before = codec.decoded;
            let kind = p.next_pcm(&mut codec, &mut out, t0 + Duration::from_millis(now_ms));
            assert_eq!(kind, Played::Audio, "pull {pull}");
            let skipped = codec.decoded - before == 2;
            overs.push((over, skipped));
            if over > CATCH_UP_HARD_MS {
                assert!(skipped, "pull {pull}: {over} ms over must skip");
            } else if over > CATCH_UP_OVER_MS && skipped {
                if let Some(prev) = last_loud_skip {
                    assert!(
                        pull - prev >= LOUD_SKIP_EVERY as usize,
                        "pull {pull}: loud skips too close: {overs:?}"
                    );
                }
                last_loud_skip = Some(pull);
            } else if over <= CATCH_UP_OVER_MS {
                assert!(!skipped, "pull {pull}: {over} ms over must not skip");
            }
        }
        assert!(
            last_loud_skip.is_some(),
            "a loud frame was skipped: {overs:?}"
        );
        assert!(
            overs.last().unwrap().0 <= CATCH_UP_OVER_MS,
            "the excess drained: {overs:?}"
        );
    }

    /// A codec whose decode fails (as OpusCodec does for a short decode) is a
    /// missing frame: it is concealed, not played, and not counted as audio.
    #[test]
    fn a_failed_decode_is_concealed_not_played() {
        struct Bad(FakeCodec);
        impl Codec for Bad {
            fn encode(
                &mut self,
                p: &[i16; FRAME_SAMPLES],
                o: &mut [u8],
            ) -> Result<usize, CodecError> {
                self.0.encode(p, o)
            }
            fn decode(&mut self, _: &[u8], _: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
                Err(CodecError::Short)
            }
            fn decode_fec(
                &mut self,
                p: &[u8],
                o: &mut [i16; FRAME_SAMPLES],
            ) -> Result<(), CodecError> {
                self.0.decode_fec(p, o)
            }
            fn conceal(&mut self, o: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
                self.0.conceal(o)
            }
            fn set_bitrate(&mut self, b: i32) -> Result<(), CodecError> {
                self.0.set_bitrate(b)
            }
            fn bitrate(&self) -> i32 {
                0
            }
        }
        let t0 = Instant::now();
        let mut p = Playout::new();
        let mut codec = Bad(FakeCodec::default());
        let mut out = [7i16; FRAME_SAMPLES];
        for seq in 0..6 {
            p.on_frame(0, seq, &[100, 0], t0);
        }
        let kind = p.next_pcm(&mut codec, &mut out, t0 + Duration::from_millis(200));
        assert_eq!(kind, Played::Concealed);
        assert_eq!(codec.0.plc, 1);
        assert_eq!(p.played_seq(), None);
        assert!(out.iter().all(|s| *s == 0));
    }

    /// A next packet without FEC data is not decoded as FEC: PLC instead.
    #[test]
    fn fec_is_used_only_when_the_next_packet_carries_it() {
        struct NoLbrr(FakeCodec);
        impl Codec for NoLbrr {
            fn encode(
                &mut self,
                p: &[i16; FRAME_SAMPLES],
                o: &mut [u8],
            ) -> Result<usize, CodecError> {
                self.0.encode(p, o)
            }
            fn decode(&mut self, p: &[u8], o: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
                self.0.decode(p, o)
            }
            fn decode_fec(
                &mut self,
                p: &[u8],
                o: &mut [i16; FRAME_SAMPLES],
            ) -> Result<(), CodecError> {
                self.0.decode_fec(p, o)
            }
            fn conceal(&mut self, o: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
                self.0.conceal(o)
            }
            fn set_bitrate(&mut self, b: i32) -> Result<(), CodecError> {
                self.0.set_bitrate(b)
            }
            fn bitrate(&self) -> i32 {
                0
            }
            fn packet_has_lbrr(&self, _: &[u8]) -> bool {
                false
            }
        }
        let t0 = Instant::now();
        let mut p = Playout::new();
        let mut codec = NoLbrr(FakeCodec::default());
        let mut out = [0i16; FRAME_SAMPLES];
        for seq in (0..8).filter(|s| *s != 3) {
            p.on_frame(0, seq, &[100, 0], t0);
        }
        let kinds: Vec<_> = (0..5)
            .map(|i| {
                p.next_pcm(
                    &mut codec,
                    &mut out,
                    t0 + Duration::from_millis(100 + i * 20),
                )
            })
            .collect();
        assert_eq!(kinds[3], Played::Concealed);
        assert_eq!((codec.0.fec, codec.0.plc), (0, 1));
    }

    #[test]
    fn totals_count_each_kind_of_played_frame() {
        let mut codec = FakeCodec::default();
        let mut p = Playout::new();
        let mut out = [0i16; FRAME_SAMPLES];
        let t0 = Instant::now();
        assert_eq!(p.totals(), PlayTotals::default());
        // Frames 0..10 arrive on time, 10 is lost, 11..20 arrive.
        for seq in (0..20u64).filter(|s| *s != 10) {
            assert!(p.on_frame(
                0,
                seq,
                &[seq as u8; 60],
                t0 + Duration::from_millis(seq * FRAME_MS)
            ));
        }
        let mut played = PlayTotals::default();
        for pull in 0..40u64 {
            match p.next_pcm(
                &mut codec,
                &mut out,
                t0 + Duration::from_millis(pull * FRAME_MS),
            ) {
                Played::Audio => played.audio += 1,
                Played::Fec => played.fec += 1,
                Played::Concealed => played.concealed += 1,
                Played::Silence => {}
            }
        }
        assert_eq!(
            p.totals(),
            played,
            "the counters match what next_pcm returned"
        );
        assert!(
            played.audio > 0 && played.fec + played.concealed > 0,
            "{played:?}"
        );
    }

    #[test]
    fn a_frame_a_little_late_is_played_on_the_next_pull_not_lost() {
        let mut codec = FakeCodec::default();
        let mut p = Playout::new();
        let mut out = [0i16; FRAME_SAMPLES];
        let t0 = Instant::now();
        for seq in 0..4u64 {
            assert!(p.on_frame(0, seq, &[100, seq as u8], t0));
        }
        let mut kinds = Vec::new();
        for pull in 0..4u64 {
            kinds.push(p.next_pcm(
                &mut codec,
                &mut out,
                t0 + Duration::from_millis(pull * FRAME_MS),
            ));
        }
        assert_eq!(kinds, vec![Played::Audio; 4]);
        // Frame 4 arrives just after its pull: that pull is concealed, the point
        // stays, and frame 4 plays on the next one (the buffer grew by one frame).
        let late = t0 + Duration::from_millis(4 * FRAME_MS + 5);
        assert_eq!(
            p.next_pcm(
                &mut codec,
                &mut out,
                t0 + Duration::from_millis(4 * FRAME_MS)
            ),
            Played::Concealed
        );
        assert!(
            p.on_frame(0, 4, &[100, 4], late),
            "not older than the playout point"
        );
        assert_eq!(
            p.next_pcm(
                &mut codec,
                &mut out,
                t0 + Duration::from_millis(5 * FRAME_MS)
            ),
            Played::Audio
        );
        assert_eq!(p.played_seq(), Some(4));
    }
}
