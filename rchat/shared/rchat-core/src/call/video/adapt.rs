//! Video quality ladder and sender adaptation (R10, R11). Pure logic: time is
//! injected as `Instant`s, nothing here sleeps or does I/O.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Rung {
    P1080 = 0,
    P720 = 1,
    P480 = 2,
    P360 = 3,
    P240 = 4,
}

impl Rung {
    /// Landscape sensor size.
    pub fn size(self) -> (u32, u32) {
        match self {
            Rung::P1080 => (1920, 1080),
            Rung::P720 => (1280, 720),
            Rung::P480 => (848, 480),
            Rung::P360 => (640, 360),
            Rung::P240 => (432, 240),
        }
    }

    pub fn fps(self) -> u32 {
        match self {
            Rung::P1080 | Rung::P720 | Rung::P480 => 30,
            Rung::P360 => 24,
            Rung::P240 => 15,
        }
    }

    /// Encoder target, bits per second.
    pub fn bitrate(self) -> u32 {
        match self {
            Rung::P1080 => 3_000_000,
            Rung::P720 => 1_300_000,
            Rung::P480 => 700_000,
            Rung::P360 => 400_000,
            Rung::P240 => 180_000,
        }
    }

    /// One rung of better quality, if any.
    fn better(self) -> Option<Rung> {
        match self {
            Rung::P1080 => None,
            Rung::P720 => Some(Rung::P1080),
            Rung::P480 => Some(Rung::P720),
            Rung::P360 => Some(Rung::P480),
            Rung::P240 => Some(Rung::P360),
        }
    }

    /// One rung of worse quality; `None` below 240p (video pauses).
    fn worse(self) -> Option<Rung> {
        match self {
            Rung::P1080 => Some(Rung::P720),
            Rung::P720 => Some(Rung::P480),
            Rung::P480 => Some(Rung::P360),
            Rung::P360 => Some(Rung::P240),
            Rung::P240 => None,
        }
    }
}

/// One 250 ms tick's view of the send path and the peer.
pub struct AdaptInput {
    /// Age of the oldest queued fragment on the chosen lane.
    pub backlog: Duration,
    /// A frame was dropped at the sender queue.
    pub sender_dropped: bool,
    /// The chosen lane made no write progress for 500 ms.
    pub stalled: bool,
    /// Some up video lane (chosen or not) made no write progress for
    /// 500 ms: my send path is in trouble (R15 attribution only; a lane
    /// the frames moved off never drives a step-down).
    pub any_lane_stalled: bool,
    pub lane_up: bool,
    /// How long the video lane has had zero backlog.
    pub idle_for: Duration,
    /// The peer's last two health notes both say `recv` bad.
    pub peer_recv_bad_twice: bool,
    /// The peer's latest note says `recv` good.
    pub peer_recv_good: bool,
    /// When the peer's latest (fresh) note, saying `recv` bad, arrived.
    pub peer_recv_bad_at: Option<Instant>,
    /// When one of my video lanes last went down or came back (a
    /// reconnect): frames lost on it are not congestion.
    pub lane_event_at: Option<Instant>,
    /// From the peer's latest note; `None` when unknown.
    pub peer_audio_concealed_pct: Option<u8>,
    /// `PowerManager` thermal status, 0-6.
    pub thermal: u8,
    /// The receiver's Caps `max_recv` is 1080.
    pub peer_wants_1080: bool,
    pub software_encoder: bool,
}

const STEP_DOWN_GAP: Duration = Duration::from_secs(1);
const SLOW_LANE: Duration = Duration::from_millis(300);
const HEALTHY_BACKLOG: Duration = Duration::from_millis(100);
const COOL_BACKLOG: Duration = Duration::from_millis(50);
const PAUSE_BACKLOG: Duration = Duration::from_secs(2);
const WAIT_MIN: Duration = Duration::from_secs(10);
const WAIT_MAX: Duration = Duration::from_secs(60);
const COOL_WINDOW: Duration = Duration::from_secs(10);
const MIN_PAUSED: Duration = Duration::from_secs(5);
/// A resume that pauses again within this long failed: the next minimum
/// pause doubles (up to `WAIT_MAX`).
const RESUME_FAILED_WITHIN: Duration = Duration::from_secs(10);
/// A resume that holds this long resets the minimum pause.
const RESUME_HELD: Duration = Duration::from_secs(30);
const RESUME_IDLE: Duration = Duration::from_secs(3);
/// For this long after a resume, one sign of trouble re-pauses at once.
const PROBE_WINDOW: Duration = Duration::from_secs(3);
/// ... a backlog over this on the chosen lane is one.
const PROBE_BACKLOG: Duration = Duration::from_millis(150);
/// A resume waits a random 0-2 s more than the minimum pause, so two
/// phones paused together do not probe together.
const RESUME_JITTER_MS: u64 = 2000;

/// Why the adapter stepped down or paused (for attribution, the resume
/// backoff and traces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownCause {
    Thermal,
    /// Backlog over 2 s.
    DeepBacklog,
    /// The receiver's Caps or the thermal cap.
    Cap,
    /// Chosen lane backlog over 300 ms (150 ms just after a resume).
    Backlog,
    /// A frame dropped at the sender queue.
    Dropped,
    /// The chosen lane made no write progress for 500 ms.
    Stalled,
    /// The peer's notes say `recv` bad (twice; once just after a resume).
    PeerRecvBad,
}

impl DownCause {
    /// My own send path's trouble (R15 attribution), not the peer's notes.
    fn own(self) -> bool {
        self != DownCause::PeerRecvBad
    }

    /// Evidence of congestion: only these make a re-pause soon after a
    /// resume a failed resume (a lane reconnect or a keyframe burst alone
    /// is not).
    fn congestion(self) -> bool {
        matches!(
            self,
            DownCause::DeepBacklog | DownCause::Backlog | DownCause::PeerRecvBad
        )
    }
}

pub struct Adapter {
    /// `None` while paused.
    rung: Option<Rung>,
    paused_at: Option<Instant>,
    last_down: Option<Instant>,
    /// Set by a step-up, cleared by the first step-down after it.
    last_up: Option<Instant>,
    /// Time of the last tick that was not healthy (or of the last change).
    healthy_since: Instant,
    /// Time of the last tick with backlog >= 50 ms (or not healthy).
    cool_since: Instant,
    /// Like `healthy_since`, but a step-up does not restart it.
    calm_since: Instant,
    wait: Duration,
    /// The last tick my own send path was in trouble (backlog, a drop, a
    /// stall) or stepped down for itself (also thermal or a cap); not a
    /// step-down for the peer's recv-bad notes alone.
    own_down: Option<Instant>,
    /// Paused for the peer's recv-bad notes, not for my own send path.
    paused_for_peer: bool,
    /// How long a pause lasts at least before a resume (5 s, doubled after
    /// each failed resume).
    min_paused: Duration,
    /// When video last resumed, until the resume holds or fails.
    resumed_at: Option<Instant>,
    /// The extra wait before the next resume (`RESUME_JITTER_MS`).
    jitter: Duration,
    /// xorshift state for the jitter; 0: no jitter (tests).
    rng: u64,
    last_cause: Option<DownCause>,
}

impl Adapter {
    pub fn new(software_encoder: bool, now: Instant) -> Self {
        Adapter {
            rung: Some(if software_encoder {
                Rung::P480
            } else {
                Rung::P720
            }),
            paused_at: None,
            last_down: None,
            last_up: None,
            healthy_since: now,
            cool_since: now,
            calm_since: now,
            wait: WAIT_MIN,
            own_down: None,
            paused_for_peer: false,
            min_paused: MIN_PAUSED,
            resumed_at: None,
            jitter: Duration::ZERO,
            rng: 0,
            last_cause: None,
        }
    }

    /// Resumes wait a random 0-2 s beyond the minimum pause; `seed` must
    /// differ between the two phones (any non-zero value).
    pub fn with_resume_jitter(mut self, seed: u64) -> Self {
        self.rng = seed | 1;
        self
    }

    /// Why it last stepped down or paused.
    pub fn last_cause(&self) -> Option<DownCause> {
        self.last_cause
    }

    pub fn rung(&self) -> Option<Rung> {
        self.rung
    }

    pub fn stepped_down_within(&self, d: Duration, now: Instant) -> bool {
        self.last_down
            .is_some_and(|t| now.saturating_duration_since(t) < d)
    }

    /// My own send path was in trouble (backlog over 300 ms, a sender drop
    /// or a stall) or stepped down for it within `d` (R15 `strained`); a
    /// step-down for the peer's recv-bad notes alone is not my send's fault.
    pub fn own_strain_within(&self, d: Duration, now: Instant) -> bool {
        self.own_down
            .is_some_and(|t| now.saturating_duration_since(t) < d)
    }

    /// Paused for my own send path (R15 `bad`), not for the peer's notes.
    pub fn paused_for_own_path(&self) -> bool {
        self.rung.is_none() && !self.paused_for_peer
    }

    /// The minimum pause before the next resume.
    pub fn min_paused(&self) -> Duration {
        self.min_paused
    }

    /// Runs every 250 ms. `Some(new)` means the rung changed (`new == None`:
    /// video paused); `None` means no change.
    pub fn on_tick(&mut self, i: &AdaptInput, now: Instant) -> Option<Option<Rung>> {
        let since = |t: Instant| now.saturating_duration_since(t);

        // Emergency thermal pauses and blocks any resume.
        if i.thermal >= 5 {
            return if self.rung.is_some() {
                Some(self.go_down(None, now, DownCause::Thermal))
            } else {
                None
            };
        }

        let Some(rung) = self.rung else {
            let concealed_ok = i.peer_audio_concealed_pct.is_some_and(|p| p < 5);
            let paused_long = self
                .paused_at
                .is_some_and(|t| since(t) >= self.min_paused + self.jitter);
            if paused_long && i.lane_up && i.idle_for >= RESUME_IDLE && concealed_ok {
                self.rung = Some(Rung::P240);
                self.paused_at = None;
                self.resumed_at = Some(now);
                self.healthy_since = now;
                self.cool_since = now;
                self.calm_since = now;
                return Some(self.rung);
            }
            return None;
        };

        if self.resumed_at.is_some_and(|t| since(t) >= RESUME_HELD) {
            self.resumed_at = None;
            self.min_paused = MIN_PAUSED;
        }

        // A backlog this deep pauses at once, whatever the rung.
        if i.backlog > PAUSE_BACKLOG {
            return Some(self.go_down(None, now, DownCause::DeepBacklog));
        }

        // Just after a resume (a probe), one sign of trouble re-pauses at
        // once: one recv-bad note sent after the resume, or a backlog over
        // 150 ms. The peer's notes don't count once one of my lanes has
        // reconnected since the resume (the frames lost there are not
        // congestion).
        let probing = self.resumed_at.filter(|t| since(*t) < PROBE_WINDOW);
        let reconnected = probing.is_some_and(|r| i.lane_event_at.is_some_and(|e| e >= r));
        if let Some(r) = probing {
            if i.backlog > PROBE_BACKLOG {
                return Some(self.go_down(None, now, DownCause::Backlog));
            }
            if !reconnected && i.peer_recv_bad_at.is_some_and(|t| t > r) {
                return Some(self.go_down(None, now, DownCause::PeerRecvBad));
            }
        }
        let peer_bad_twice = i.peer_recv_bad_twice && !reconnected;

        // The best rung the thermal state, encoder and receiver allow.
        let cap = if i.software_encoder || i.thermal >= 3 {
            Rung::P480
        } else if i.thermal >= 2 || !i.peer_wants_1080 {
            Rung::P720
        } else {
            Rung::P1080
        };
        if rung < cap {
            return Some(self.go_down(Some(cap), now, DownCause::Cap));
        }

        let own_trouble = i.backlog > SLOW_LANE || i.sender_dropped || i.stalled;
        let trouble = own_trouble || peer_bad_twice;
        if own_trouble || i.any_lane_stalled {
            self.own_down = Some(now);
        }
        let healthy = i.backlog < HEALTHY_BACKLOG
            && !i.sender_dropped
            && !i.stalled
            && i.peer_recv_good
            && !peer_bad_twice;

        if !healthy {
            self.healthy_since = now;
            self.cool_since = now;
            self.calm_since = now;
        }
        if trouble {
            let gap_ok = self.last_down.is_none_or(|t| since(t) >= STEP_DOWN_GAP);
            return if gap_ok {
                let cause = if i.backlog > SLOW_LANE {
                    DownCause::Backlog
                } else if i.sender_dropped {
                    DownCause::Dropped
                } else if i.stalled {
                    DownCause::Stalled
                } else {
                    DownCause::PeerRecvBad
                };
                Some(self.go_down(rung.worse(), now, cause))
            } else {
                None
            };
        }
        if !healthy {
            return None;
        }
        if i.backlog >= COOL_BACKLOG {
            self.cool_since = now;
        }
        if since(self.calm_since) >= WAIT_MAX {
            self.wait = WAIT_MIN;
        }
        if since(self.healthy_since) >= self.wait {
            if let Some(up) = rung.better().filter(|u| *u >= cap) {
                let cool = up != Rung::P1080 || since(self.cool_since) >= COOL_WINDOW;
                if cool {
                    self.rung = Some(up);
                    self.last_up = Some(now);
                    self.healthy_since = now;
                    self.cool_since = now;
                    return Some(self.rung);
                }
            }
        }
        None
    }

    /// Moves down (`None` pauses) and applies the step-up backoff: a
    /// step-down within 10 s of a step-up doubles the next wait, and a pause
    /// for congestion within 10 s of a resume (a failed resume) doubles the
    /// next minimum pause.
    fn go_down(&mut self, to: Option<Rung>, now: Instant, cause: DownCause) -> Option<Rung> {
        self.last_cause = Some(cause);
        if cause.own() {
            self.own_down = Some(now);
        }
        if to.is_none() {
            self.paused_for_peer = !cause.own();
            if let Some(r) = self.resumed_at.take() {
                if cause.congestion() && now.saturating_duration_since(r) < RESUME_FAILED_WITHIN {
                    self.min_paused = (self.min_paused * 2).min(WAIT_MAX);
                }
            }
            self.jitter = self.next_jitter();
        }
        if let Some(up) = self.last_up.take() {
            if now.saturating_duration_since(up) < WAIT_MIN {
                self.wait = (self.wait * 2).min(WAIT_MAX);
            }
        }
        self.rung = to;
        self.last_down = Some(now);
        self.healthy_since = now;
        self.cool_since = now;
        self.calm_since = now;
        if to.is_none() {
            self.paused_at = Some(now);
        }
        to
    }

    fn next_jitter(&mut self) -> Duration {
        if self.rng == 0 {
            return Duration::ZERO;
        }
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        Duration::from_millis(x % (RESUME_JITTER_MS + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    fn calm() -> AdaptInput {
        AdaptInput {
            backlog: Duration::ZERO,
            sender_dropped: false,
            stalled: false,
            any_lane_stalled: false,
            lane_up: true,
            idle_for: Duration::ZERO,
            peer_recv_bad_twice: false,
            peer_recv_good: true,
            peer_recv_bad_at: None,
            lane_event_at: None,
            peer_audio_concealed_pct: Some(0),
            thermal: 0,
            peer_wants_1080: false,
            software_encoder: false,
        }
    }

    /// Ticks every 250 ms from `from` (exclusive of `from`) to `to`
    /// inclusive; returns each change with its offset in ms.
    fn run(
        a: &mut Adapter,
        t0: Instant,
        from_ms: u64,
        to_ms: u64,
        i: &AdaptInput,
    ) -> Vec<(u64, Option<Rung>)> {
        let mut out = Vec::new();
        let mut t = from_ms;
        while t <= to_ms {
            if let Some(c) = a.on_tick(i, t0 + MS(t)) {
                out.push((t, c));
            }
            t += 250;
        }
        out
    }

    #[test]
    fn ladder_matches_the_ruling() {
        assert_eq!(Rung::P720.size(), (1280, 720));
        assert_eq!(Rung::P360.fps(), 24);
        assert_eq!(Rung::P240.bitrate(), 180_000);
        assert_eq!(Rung::P1080.bitrate(), 3_000_000);
        assert_eq!(Rung::P1080.size(), (1920, 1080));
        assert_eq!(Rung::P480.size(), (848, 480));
        assert_eq!(Rung::P360.size(), (640, 360));
        assert_eq!(Rung::P240.size(), (432, 240));
        assert_eq!(
            [Rung::P1080, Rung::P720, Rung::P480, Rung::P360, Rung::P240].map(|r| r.fps()),
            [30, 30, 30, 24, 15]
        );
        assert_eq!(Rung::P720.bitrate(), 1_300_000);
        assert_eq!(Rung::P480.bitrate(), 700_000);
        assert_eq!(Rung::P360.bitrate(), 400_000);
    }

    #[test]
    fn steps_down_fast_at_most_once_per_second() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        assert_eq!(a.rung(), Some(Rung::P720));
        let mut i = calm();
        i.backlog = MS(400);
        let ch = run(&mut a, t0, 0, 2100, &i);
        assert_eq!(
            ch,
            vec![
                (0, Some(Rung::P480)),
                (1000, Some(Rung::P360)),
                (2000, Some(Rung::P240))
            ]
        );
        assert!(a.stepped_down_within(MS(500), t0 + MS(2100)));
        assert!(!a.stepped_down_within(MS(50), t0 + MS(2100)));
    }

    #[test]
    fn each_step_down_trigger_works_and_300ms_is_not_enough() {
        let t0 = Instant::now();
        for f in [
            |i: &mut AdaptInput| i.sender_dropped = true,
            |i: &mut AdaptInput| i.stalled = true,
            |i: &mut AdaptInput| i.peer_recv_bad_twice = true,
            |i: &mut AdaptInput| i.backlog = MS(301),
        ] {
            let mut a = Adapter::new(false, t0);
            let mut i = calm();
            f(&mut i);
            assert_eq!(a.on_tick(&i, t0 + MS(250)), Some(Some(Rung::P480)));
        }
        let mut a = Adapter::new(false, t0);
        let mut i = calm();
        i.backlog = MS(300);
        assert_eq!(a.on_tick(&i, t0 + MS(250)), None);
    }

    #[test]
    fn steps_up_after_ten_healthy_seconds_and_backs_off_after_a_failed_step_up() {
        let t0 = Instant::now();
        let mut a = Adapter::new(true, t0);
        assert_eq!(a.rung(), Some(Rung::P480));
        let i = calm();
        assert!(run(&mut a, t0, 0, 9750, &i).is_empty());
        assert_eq!(
            run(&mut a, t0, 10000, 10000, &i),
            vec![(10000, Some(Rung::P720))]
        );
        // Down within 10 s of the step-up: next wait 20 s.
        let mut bad = calm();
        bad.backlog = MS(400);
        assert_eq!(a.on_tick(&bad, t0 + MS(15000)), Some(Some(Rung::P480)));
        assert!(run(&mut a, t0, 15250, 34750, &i).is_empty());
        assert_eq!(
            run(&mut a, t0, 35000, 35000, &i),
            vec![(35000, Some(Rung::P720))]
        );
    }

    #[test]
    fn backoff_doubles_to_sixty_and_resets_after_sixty_healthy_seconds() {
        let t0 = Instant::now();
        let mut a = Adapter::new(true, t0);
        let i = calm();
        let mut bad = calm();
        bad.backlog = MS(400);
        // Each step-up fails 250 ms later. Waits: 10, 20, 40, 60.
        let mut t = 0u64;
        for wait in [10_000u64, 20_000, 40_000, 60_000] {
            let start = t;
            if wait > 10_000 {
                assert!(run(&mut a, t0, start + 250, start + wait - 250, &i).is_empty());
            } else {
                assert!(run(&mut a, t0, 0, wait - 250, &i).is_empty());
            }
            t = start + wait;
            assert_eq!(
                a.on_tick(&i, t0 + MS(t)),
                Some(Some(Rung::P720)),
                "wait {wait}"
            );
            t += 250;
            assert_eq!(a.on_tick(&bad, t0 + MS(t)), Some(Some(Rung::P480)));
        }
        // The 60 s healthy window reset the wait to 10 s, so the next failure
        // doubles it to 20 s, not 60 s.
        assert!(run(&mut a, t0, t + 250, t + 19_750, &i).is_empty());
        assert_eq!(a.on_tick(&i, t0 + MS(t + 20_000)), Some(Some(Rung::P720)));
        // A step-down long after a step-up does not double the wait again.
        let up = t + 20_000;
        assert_eq!(
            a.on_tick(&bad, t0 + MS(up + 12_000)),
            Some(Some(Rung::P480))
        );
        assert!(run(&mut a, t0, up + 12_250, up + 31_750, &i).is_empty());
        assert_eq!(a.on_tick(&i, t0 + MS(up + 32_000)), Some(Some(Rung::P720)));
    }

    #[test]
    fn p1080_only_when_requested_sustained_cool_and_hardware() {
        let t0 = Instant::now();
        // Not requested: never over 60 s.
        let mut a = Adapter::new(false, t0);
        assert!(run(&mut a, t0, 0, 60_000, &calm()).is_empty());
        // Requested: at 10 s and not before.
        let mut want = calm();
        want.peer_wants_1080 = true;
        let mut a = Adapter::new(false, t0);
        assert!(run(&mut a, t0, 0, 9750, &want).is_empty());
        assert_eq!(a.on_tick(&want, t0 + MS(10_000)), Some(Some(Rung::P1080)));
        // Thermal 2: never.
        let hot = want.clone_with(|i| i.thermal = 2);
        let mut a = Adapter::new(false, t0);
        assert!(run(&mut a, t0, 0, 60_000, &hot).is_empty());
        // Software encoder: never.
        let sw = want.clone_with(|i| i.software_encoder = true);
        let mut a = Adapter::new(true, t0);
        assert!(run(&mut a, t0, 0, 60_000, &sw).is_empty());
        // 60 ms backlog once restarts the 10 s window.
        let mut a = Adapter::new(false, t0);
        assert!(run(&mut a, t0, 0, 4750, &want).is_empty());
        let warm = want.clone_with(|i| i.backlog = MS(60));
        assert!(run(&mut a, t0, 5000, 5000, &warm).is_empty());
        assert!(run(&mut a, t0, 5250, 14_750, &want).is_empty());
        assert_eq!(a.on_tick(&want, t0 + MS(15_000)), Some(Some(Rung::P1080)));
        // Once at 1080, withdrawing the request drops to 720 at once.
        assert_eq!(a.on_tick(&calm(), t0 + MS(15_250)), Some(Some(Rung::P720)));
    }

    #[test]
    fn thermal_caps_and_pauses() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut i = calm();
        i.thermal = 3;
        assert_eq!(a.on_tick(&i, t0 + MS(250)), Some(Some(Rung::P480)));
        // The cap holds: no step up while severe.
        assert!(run(&mut a, t0, 500, 30_000, &i).is_empty());
        i.thermal = 5;
        assert_eq!(a.on_tick(&i, t0 + MS(30_250)), Some(None));
        assert_eq!(a.rung(), None);
        // Still emergency: no resume however calm.
        let mut idle = i.clone_with(|i| i.idle_for = Duration::from_secs(10));
        assert!(run(&mut a, t0, 31_000, 60_000, &idle).is_empty());
        idle.thermal = 0;
        assert_eq!(a.on_tick(&idle, t0 + MS(60_250)), Some(Some(Rung::P240)));
    }

    #[test]
    fn thermal_two_caps_at_720() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut want = calm();
        want.peer_wants_1080 = true;
        assert_eq!(a.on_tick(&want, t0 + MS(10_000)), Some(Some(Rung::P1080)));
        want.thermal = 2;
        assert_eq!(a.on_tick(&want, t0 + MS(10_250)), Some(Some(Rung::P720)));
    }

    #[test]
    fn pauses_below_240_and_resumes_on_recovery() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut bad = calm();
        bad.backlog = MS(400);
        let ch = run(&mut a, t0, 0, 3000, &bad);
        assert_eq!(ch.last(), Some(&(3000, None)));
        assert_eq!(a.rung(), None);
        let paused_at = 3000;
        let mut ok = calm();
        ok.idle_for = Duration::from_secs(3);
        // Before 5 s paused: nothing.
        assert!(run(&mut a, t0, 3250, paused_at + 4750, &ok).is_empty());
        // Each condition missing blocks the resume.
        let at = t0 + MS(paused_at + 5000);
        assert_eq!(a.on_tick(&ok.clone_with(|i| i.lane_up = false), at), None);
        assert_eq!(
            a.on_tick(&ok.clone_with(|i| i.idle_for = MS(2900)), at),
            None
        );
        assert_eq!(
            a.on_tick(&ok.clone_with(|i| i.peer_audio_concealed_pct = Some(5)), at),
            None
        );
        assert_eq!(
            a.on_tick(&ok.clone_with(|i| i.peer_audio_concealed_pct = None), at),
            None
        );
        assert_eq!(a.on_tick(&ok, at), Some(Some(Rung::P240)));
        assert_eq!(a.rung(), Some(Rung::P240));
    }

    /// Pauses at once (backlog over 2 s) and resumes at the first tick
    /// allowed; returns the resume time in ms.
    fn pause_then_resume(a: &mut Adapter, t0: Instant, at_ms: u64) -> u64 {
        let mut deep = calm();
        deep.backlog = MS(2001);
        assert_eq!(a.on_tick(&deep, t0 + MS(at_ms)), Some(None));
        let mut ok = calm();
        ok.idle_for = Duration::from_secs(3);
        let mut t = at_ms + 250;
        while a.on_tick(&ok, t0 + MS(t)).is_none() {
            t += 250;
            assert!(t < at_ms + 120_000, "never resumed");
        }
        t - at_ms
    }

    /// A resume that pauses again within 10 s doubles the next minimum pause
    /// (5, 10, 20, 40, then 60 s at most); one that holds 30 s resets it.
    #[test]
    fn a_failed_resume_doubles_the_next_minimum_pause() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut t = 0;
        let mut waited = Vec::new();
        for _ in 0..6 {
            let w = pause_then_resume(&mut a, t0, t);
            waited.push(w);
            t += w + 2_000; // fails 2 s after the resume
        }
        assert_eq!(waited, vec![5_000, 10_000, 20_000, 40_000, 60_000, 60_000]);
        // A resume that holds 30 s: the next pause is 5 s again.
        let _ = a.on_tick(&calm(), t0 + MS(t - 2_000 + 30_000));
        let w = pause_then_resume(&mut a, t0, t - 2_000 + 30_250);
        assert_eq!(w, 5_000);
    }

    /// A step-down or pause for the peer's recv-bad notes is not my send
    /// path's fault (R15 attribution); one for my own backlog is.
    #[test]
    fn a_step_down_for_the_peers_notes_is_not_my_own() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut peer = calm();
        peer.peer_recv_bad_twice = true;
        peer.peer_recv_good = false;
        let ch = run(&mut a, t0, 0, 3000, &peer);
        assert_eq!(ch.last(), Some(&(3000, None)), "down to a pause");
        assert!(!a.own_strain_within(Duration::from_secs(5), t0 + MS(3000)));
        assert!(a.stepped_down_within(Duration::from_secs(5), t0 + MS(3000)));
        assert!(!a.paused_for_own_path());
        let mut b = Adapter::new(false, t0);
        let mut own = calm();
        own.backlog = MS(400);
        own.peer_recv_bad_twice = true;
        assert_eq!(b.on_tick(&own, t0), Some(Some(Rung::P480)));
        assert!(b.own_strain_within(Duration::from_secs(5), t0));
        let mut c = Adapter::new(false, t0);
        let mut deep = calm();
        deep.backlog = MS(2001);
        assert_eq!(c.on_tick(&deep, t0), Some(None));
        assert!(c.paused_for_own_path());
    }

    /// Resumes (at the first allowed tick) after a deep-backlog pause at
    /// `at_ms`; returns the resume time in ms.
    fn resume_after_pause(a: &mut Adapter, t0: Instant, at_ms: u64) -> u64 {
        at_ms + pause_then_resume(a, t0, at_ms)
    }

    /// R11 fast failure: within 3 s of a resume, one recv-bad note sent
    /// after the resume, or a backlog over 150 ms, re-pauses at once.
    #[test]
    fn a_probe_fails_fast_on_one_bad_note_or_a_150_ms_backlog() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let r = resume_after_pause(&mut a, t0, 0);
        // A bad note from before the resume does not count.
        let mut old = calm();
        old.peer_recv_bad_at = Some(t0 + MS(r - 100));
        assert_eq!(a.on_tick(&old, t0 + MS(r + 250)), None);
        let mut bad = calm();
        bad.peer_recv_bad_at = Some(t0 + MS(r + 400));
        assert_eq!(a.on_tick(&bad, t0 + MS(r + 500)), Some(None));
        assert_eq!(a.last_cause(), Some(DownCause::PeerRecvBad));
        let mut b = Adapter::new(false, t0);
        let r = resume_after_pause(&mut b, t0, 0);
        let mut slow = calm();
        slow.backlog = MS(151);
        assert_eq!(b.on_tick(&slow, t0 + MS(r + 250)), Some(None));
        // After the 3 s window a 151 ms backlog is not trouble.
        let mut c = Adapter::new(false, t0);
        let r = resume_after_pause(&mut c, t0, 0);
        assert_eq!(c.on_tick(&slow, t0 + MS(r + 3000)), None);
        assert_eq!(c.rung(), Some(Rung::P240));
    }

    /// A lane reconnect since the resume: the peer's recv-bad notes (the
    /// frames lost on that lane) neither fail the probe nor step down.
    #[test]
    fn peer_notes_after_my_lane_reconnects_do_not_fail_a_probe() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let r = resume_after_pause(&mut a, t0, 0);
        let mut i = calm();
        i.lane_event_at = Some(t0 + MS(r + 100));
        i.peer_recv_bad_at = Some(t0 + MS(r + 400));
        i.peer_recv_bad_twice = true;
        i.peer_recv_good = false;
        assert_eq!(a.on_tick(&i, t0 + MS(r + 500)), None);
        assert_eq!(a.on_tick(&i, t0 + MS(r + 1750)), None);
        assert_eq!(a.rung(), Some(Rung::P240));
    }

    /// A re-pause soon after a resume doubles the next minimum pause only
    /// on congestion evidence; a stall (a lane reconnect) or a sender drop
    /// (a keyframe burst) alone does not.
    #[test]
    fn only_congestion_makes_a_failed_resume() {
        let t0 = Instant::now();
        for (what, mut i, doubles) in [
            ("stall", calm(), false),
            ("drop", calm(), false),
            ("backlog", calm(), true),
        ] {
            match what {
                "stall" => i.stalled = true,
                "drop" => i.sender_dropped = true,
                _ => i.backlog = MS(400),
            }
            let mut a = Adapter::new(false, t0);
            let r = resume_after_pause(&mut a, t0, 0);
            // After the probe window, so only the ordinary rules apply.
            assert_eq!(a.on_tick(&i, t0 + MS(r + 4000)), Some(None), "{what}");
            let want = if doubles { MS(10_000) } else { MS(5_000) };
            assert_eq!(a.min_paused(), want, "{what}");
        }
    }

    /// The resume waits a random 0-2 s beyond the minimum pause, so two
    /// phones paused together resume apart.
    #[test]
    fn resumes_are_jittered_by_up_to_2_s() {
        let t0 = Instant::now();
        let mut waits = Vec::new();
        for seed in 1..=8u64 {
            let mut a = Adapter::new(false, t0).with_resume_jitter(seed * 0x9E37_79B9);
            let w = pause_then_resume(&mut a, t0, 0);
            assert!((5_000..=7_250).contains(&w), "seed {seed}: {w}");
            waits.push(w);
        }
        waits.sort_unstable();
        waits.dedup();
        assert!(waits.len() >= 3, "spread: {waits:?}");
    }

    #[test]
    fn backlog_over_two_seconds_pauses_from_any_rung() {
        let t0 = Instant::now();
        let mut a = Adapter::new(false, t0);
        let mut i = calm();
        i.backlog = MS(2001);
        assert_eq!(a.on_tick(&i, t0 + MS(250)), Some(None));
    }

    #[test]
    fn software_encoder_starts_and_tops_at_480() {
        let t0 = Instant::now();
        assert_eq!(Adapter::new(true, t0).rung(), Some(Rung::P480));
        assert_eq!(Adapter::new(false, t0).rung(), Some(Rung::P720));
    }

    impl AdaptInput {
        fn clone_with(&self, f: impl FnOnce(&mut AdaptInput)) -> AdaptInput {
            let mut c = AdaptInput {
                backlog: self.backlog,
                sender_dropped: self.sender_dropped,
                stalled: self.stalled,
                any_lane_stalled: self.any_lane_stalled,
                lane_up: self.lane_up,
                idle_for: self.idle_for,
                peer_recv_bad_twice: self.peer_recv_bad_twice,
                peer_recv_good: self.peer_recv_good,
                peer_recv_bad_at: self.peer_recv_bad_at,
                lane_event_at: self.lane_event_at,
                peer_audio_concealed_pct: self.peer_audio_concealed_pct,
                thermal: self.thermal,
                peer_wants_1080: self.peer_wants_1080,
                software_encoder: self.software_encoder,
            };
            f(&mut c);
            c
        }
    }
}
