//! Video health, the unstable banner and the health / keyframe-request
//! notes (R15). Pure logic; notes are untrusted peer input.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    Good = 0,
    Strained = 1,
    Bad = 2,
}

impl Health {
    fn from_u8(b: u8) -> Option<Health> {
        match b {
            0 => Some(Health::Good),
            1 => Some(Health::Strained),
            2 => Some(Health::Bad),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Banner {
    None,
    Mine,
    Theirs,
}

/// `bad` when paused, backlog over 1 s or audio frames dropped in the last
/// 2 s; `strained` when stepped down in the last 5 s or backlog over 300 ms.
pub fn send_health(
    paused: bool,
    backlog: Duration,
    audio_dropped_recently: bool,
    stepped_down_5s: bool,
) -> Health {
    if paused || backlog > Duration::from_secs(1) || audio_dropped_recently {
        Health::Bad
    } else if stepped_down_5s || backlog > Duration::from_millis(300) {
        Health::Strained
    } else {
        Health::Good
    }
}

/// `bad` when video is expected and no frame arrived for 1.5 s, over 10%
/// of frames were lost in the last 3 s, or frames have been arriving late
/// (`DelayTracker::late`); also `bad` when audio playout is poor.
pub fn recv_health(
    video_expected: bool,
    since_frame: Duration,
    lost_share_3s: f32,
    late: bool,
    audio_poor: bool,
) -> Health {
    let video_bad = video_expected
        && (since_frame > Duration::from_millis(1500) || lost_share_3s > 0.10 || late);
    if video_bad || audio_poor {
        Health::Bad
    } else {
        Health::Good
    }
}

/// Mine if my send isn't good; else Theirs if the peer's (known) send isn't
/// good; else Mine if my recv is bad (my downlink); else Theirs if the
/// peer's (known) recv is bad (its downlink); else None.
pub fn raw_banner(
    my_send: Health,
    my_recv: Health,
    peer_send: Option<Health>,
    peer_recv: Option<Health>,
) -> Banner {
    if my_send != Health::Good {
        Banner::Mine
    } else if peer_send.is_some_and(|h| h != Health::Good) {
        Banner::Theirs
    } else if my_recv == Health::Bad {
        Banner::Mine
    } else if peer_recv == Some(Health::Bad) {
        Banner::Theirs
    } else {
        Banner::None
    }
}

/// A frame this much later than the fastest one so far is late.
const LATE_EXCESS_MS: i64 = 400;
/// ... and frames have to stay late this long.
const LATE_FOR: Duration = Duration::from_secs(1);

/// The minimum delay is kept per bucket of this long ...
const MIN_BUCKET: Duration = Duration::from_secs(10);
/// ... over the buckets of the last this long, so a lasting change of the
/// path's base delay (a new route) stops counting as lateness.
const MIN_WINDOW: Duration = Duration::from_secs(90);

/// The receiver's delay measure (R15): each complete frame's one-way delay
/// (arrival minus the sender's `sent_ms`, two unrelated clock origins) less
/// the smallest seen over the last 90 s (10 s buckets), so the origins
/// cancel. Late once every frame for 1 s has been over 400 ms above that
/// minimum.
#[derive(Default)]
pub struct DelayTracker {
    /// (bucket start, smallest delay in it), oldest first.
    buckets: std::collections::VecDeque<(Instant, i64)>,
    late_since: Option<Instant>,
    /// The last frame's excess over the minimum, ms, and when it came.
    last: Option<(i64, Instant)>,
}

impl DelayTracker {
    /// A complete frame: `sent_ms` from its header, `arrived_ms` on my own
    /// origin, both wrapping.
    pub fn on_frame(&mut self, sent_ms: u32, arrived_ms: u32, at: Instant) {
        let d = i64::from(arrived_ms.wrapping_sub(sent_ms) as i32);
        match self.buckets.back_mut() {
            Some((start, m)) if at.saturating_duration_since(*start) < MIN_BUCKET => {
                *m = (*m).min(d);
            }
            _ => self.buckets.push_back((at, d)),
        }
        while self
            .buckets
            .front()
            .is_some_and(|(start, _)| at.saturating_duration_since(*start) >= MIN_WINDOW)
        {
            self.buckets.pop_front();
        }
        let min = self.buckets.iter().map(|b| b.1).min().unwrap_or(d);
        self.last = Some((d - min, at));
        if d - min > LATE_EXCESS_MS {
            self.late_since.get_or_insert(at);
        } else {
            self.late_since = None;
        }
    }

    /// The last frame's excess over the minimum (ms), if it came at or
    /// after `since`.
    pub fn excess_since(&self, since: Instant) -> Option<i64> {
        self.last.filter(|(_, at)| *at >= since).map(|(e, _)| e)
    }

    pub fn late(&self, now: Instant) -> bool {
        self.late_since
            .is_some_and(|t| now.saturating_duration_since(t) >= LATE_FOR)
    }

    /// Receiving starts again, the network changed or the peer paused:
    /// forget the past.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

const SHOW_AFTER: Duration = Duration::from_secs(3);
const CLEAR_AFTER: Duration = Duration::from_secs(2);

/// Hysteresis: the shown banner follows the raw one only after the raw one
/// has held 3 s (towards Mine or Theirs) or 2 s (towards None).
pub struct BannerState {
    shown: Banner,
    pending: Option<(Banner, Instant)>,
}

impl Default for BannerState {
    fn default() -> Self {
        Self::new()
    }
}

impl BannerState {
    pub fn new() -> Self {
        BannerState {
            shown: Banner::None,
            pending: None,
        }
    }

    pub fn update(&mut self, raw: Banner, now: Instant) -> Banner {
        if raw == self.shown {
            self.pending = None;
            return self.shown;
        }
        let since = match self.pending {
            Some((p, t)) if p == raw => t,
            _ => {
                self.pending = Some((raw, now));
                now
            }
        };
        let hold = if raw == Banner::None {
            CLEAR_AFTER
        } else {
            SHOW_AFTER
        };
        if now.saturating_duration_since(since) >= hold {
            self.shown = raw;
            self.pending = None;
        }
        self.shown
    }
}

const NOTE_HEALTH: u8 = 1;
const NOTE_KEYFRAME_REQUEST: u8 = 2;

/// `[1, send, recv, rung, audio_concealed_pct, paused_out]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HealthNote {
    pub send: Health,
    pub recv: Health,
    pub rung: u8,
    pub audio_concealed_pct: u8,
    pub paused_out: bool,
}

impl HealthNote {
    pub fn encode(&self) -> [u8; 6] {
        [
            NOTE_HEALTH,
            self.send as u8,
            self.recv as u8,
            self.rung,
            self.audio_concealed_pct,
            self.paused_out as u8,
        ]
    }

    /// Strict: exactly 6 bytes, type 1, health values 0-2, paused 0 or 1.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let [t, send, recv, rung, pct, paused] = *<&[u8; 6]>::try_from(b).ok()?;
        if t != NOTE_HEALTH || paused > 1 {
            return None;
        }
        Some(HealthNote {
            send: Health::from_u8(send)?,
            recv: Health::from_u8(recv)?,
            rung,
            audio_concealed_pct: pct,
            paused_out: paused == 1,
        })
    }
}

/// `[2, frame_no (4, BE)]`.
pub fn keyframe_request(frame_no: u32) -> [u8; 5] {
    let n = frame_no.to_be_bytes();
    [NOTE_KEYFRAME_REQUEST, n[0], n[1], n[2], n[3]]
}

pub fn decode_keyframe_request(b: &[u8]) -> Option<u32> {
    let [t, a, b, c, d] = *<&[u8; 5]>::try_from(b).ok()?;
    (t == NOTE_KEYFRAME_REQUEST).then(|| u32::from_be_bytes([a, b, c, d]))
}

#[cfg(test)]
mod tests {
    use super::*;
    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn send_and_recv_health_thresholds() {
        let z = Duration::ZERO;
        assert_eq!(send_health(false, z, false, false), Health::Good);
        assert_eq!(send_health(true, z, false, false), Health::Bad);
        assert_eq!(send_health(false, MS(1001), false, false), Health::Bad);
        assert_eq!(send_health(false, MS(1000), false, false), Health::Strained);
        assert_eq!(send_health(false, z, true, false), Health::Bad);
        assert_eq!(send_health(false, z, false, true), Health::Strained);
        assert_eq!(send_health(false, MS(301), false, false), Health::Strained);
        assert_eq!(send_health(false, MS(300), false, false), Health::Good);
        assert_eq!(send_health(true, z, false, true), Health::Bad);

        assert_eq!(recv_health(true, MS(1500), 0.0, false, false), Health::Good);
        assert_eq!(recv_health(true, MS(1501), 0.0, false, false), Health::Bad);
        assert_eq!(recv_health(true, z, 0.11, false, false), Health::Bad);
        assert_eq!(recv_health(true, z, 0.10, false, false), Health::Good);
        assert_eq!(recv_health(false, MS(9000), 0.9, true, false), Health::Good);
        assert_eq!(recv_health(false, z, 0.0, false, true), Health::Bad);
        assert_eq!(recv_health(true, z, f32::NAN, false, false), Health::Good);
        assert_eq!(recv_health(true, z, 0.0, true, false), Health::Bad, "late");
    }

    /// Frames arriving over 400 ms later than the fastest one, for 1 s,
    /// are late; one on time clears it. The clocks' origins don't matter.
    #[test]
    fn frames_late_by_over_400_ms_for_1_s_make_the_receiver_late() {
        let t0 = Instant::now();
        let mut d = DelayTracker::default();
        // Sender origin far from mine, across the wrap.
        let off = 0xFFFF_FF00u32;
        let frame = |d: &mut DelayTracker, k: u32, delay: u32| {
            let sent = off.wrapping_add(k * 33);
            d.on_frame(
                sent,
                (k * 33).wrapping_add(delay),
                t0 + MS(u64::from(k * 33) + u64::from(delay)),
            );
        };
        for k in 0..30 {
            frame(&mut d, k, 80);
        }
        let at = |k: u32, delay: u32| t0 + MS(u64::from(k * 33) + u64::from(delay));
        assert!(!d.late(at(30, 80)));
        // 400 ms over the minimum is not late; 401 is, once it lasts 1 s.
        for k in 30..70 {
            frame(&mut d, k, 480);
        }
        assert!(!d.late(at(70, 480) + MS(2000)), "exactly 400 ms over");
        frame(&mut d, 70, 481);
        assert!(!d.late(at(70, 481) + MS(999)));
        assert!(d.late(at(70, 481) + MS(1000)));
        frame(&mut d, 71, 100);
        assert!(!d.late(at(71, 100) + MS(5000)), "a frame on time clears it");
        d.reset();
        assert!(!d.late(at(72, 0) + MS(5000)));
    }

    /// The base delay steps up 500 ms and stays (a new route): late at
    /// first, good again once the old minimum has left the 90 s window.
    #[test]
    fn a_lasting_step_in_base_delay_stops_counting_as_late() {
        let t0 = Instant::now();
        let mut d = DelayTracker::default();
        let at = |ms: u64| t0 + MS(ms);
        let mut t = 0u64;
        while t < 30_000 {
            d.on_frame(t as u32, (t + 80) as u32, at(t + 80));
            t += 100;
        }
        let mut late_at = None;
        let mut good_again = None;
        while t < 200_000 {
            d.on_frame(t as u32, (t + 580) as u32, at(t + 580));
            let now = at(t + 580);
            if d.late(now) && late_at.is_none() {
                late_at = Some(t);
            }
            if late_at.is_some() && good_again.is_none() && !d.late(now) {
                good_again = Some(t);
            }
            t += 100;
        }
        assert!(
            late_at.is_some_and(|t| t <= 31_100),
            "late at first: {late_at:?}"
        );
        let g = good_again.expect("good again");
        assert!((100_000..=130_000).contains(&g), "good again at {g} ms");
    }

    #[test]
    fn banner_attribution_and_hysteresis() {
        // The peer's downlink: only when nothing of mine is wrong.
        assert_eq!(
            raw_banner(
                Health::Good,
                Health::Good,
                Some(Health::Good),
                Some(Health::Bad)
            ),
            Banner::Theirs
        );
        assert_eq!(
            raw_banner(
                Health::Good,
                Health::Bad,
                Some(Health::Good),
                Some(Health::Bad)
            ),
            Banner::Mine
        );
        assert_eq!(
            raw_banner(Health::Strained, Health::Good, Some(Health::Good), None),
            Banner::Mine
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Bad, Some(Health::Bad), None),
            Banner::Theirs
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Bad, Some(Health::Good), None),
            Banner::Mine
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Bad, None, None),
            Banner::Mine
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Good, None, None),
            Banner::None
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Strained, Some(Health::Good), None),
            Banner::None
        );
        assert_eq!(
            raw_banner(Health::Good, Health::Good, Some(Health::Strained), None),
            Banner::Theirs
        );

        let t0 = Instant::now();
        let mut b = BannerState::new();
        assert_eq!(b.update(Banner::None, t0), Banner::None);
        assert_eq!(b.update(Banner::Mine, t0), Banner::None);
        assert_eq!(b.update(Banner::Mine, t0 + MS(2900)), Banner::None);
        assert_eq!(b.update(Banner::Mine, t0 + MS(3000)), Banner::Mine);
        assert_eq!(b.update(Banner::None, t0 + MS(3100)), Banner::Mine);
        assert_eq!(b.update(Banner::None, t0 + MS(5000)), Banner::Mine);
        assert_eq!(b.update(Banner::None, t0 + MS(5100)), Banner::None);
        // Flapping every second is never shown.
        let mut b = BannerState::new();
        for s in 0..20u64 {
            let raw = if s % 2 == 0 {
                Banner::Mine
            } else {
                Banner::None
            };
            assert_eq!(b.update(raw, t0 + MS(s * 1000)), Banner::None);
        }
        // Mine to Theirs needs its own 3 s.
        let mut b = BannerState::new();
        b.update(Banner::Mine, t0);
        assert_eq!(b.update(Banner::Mine, t0 + MS(3000)), Banner::Mine);
        assert_eq!(b.update(Banner::Theirs, t0 + MS(3100)), Banner::Mine);
        assert_eq!(b.update(Banner::Theirs, t0 + MS(6100)), Banner::Theirs);
    }

    #[test]
    fn health_note_and_keyframe_request_layouts() {
        let n = HealthNote {
            send: Health::Strained,
            recv: Health::Bad,
            rung: 3,
            audio_concealed_pct: 17,
            paused_out: true,
        };
        assert_eq!(n.encode(), [1, 1, 2, 3, 17, 1]);
        assert_eq!(HealthNote::decode(&n.encode()), Some(n));
        assert_eq!(HealthNote::decode(&[1, 0, 0, 0, 0]), None);
        assert_eq!(HealthNote::decode(&[1, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(HealthNote::decode(&[]), None);
        assert_eq!(HealthNote::decode(&[1, 3, 0, 0, 0, 0]), None);
        assert_eq!(HealthNote::decode(&[1, 0, 3, 0, 0, 0]), None);
        assert_eq!(HealthNote::decode(&[1, 0, 0, 0, 0, 2]), None);
        assert_eq!(HealthNote::decode(&[9, 0, 0, 0, 0, 0]), None);
        assert!(HealthNote::decode(&[1, 0, 0, 0, 0, 0]).is_some());

        assert_eq!(keyframe_request(0x0102_0304), [2, 1, 2, 3, 4]);
        assert_eq!(decode_keyframe_request(&[2, 1, 2, 3, 4]), Some(0x0102_0304));
        assert_eq!(decode_keyframe_request(&[2, 1, 2, 3]), None);
        assert_eq!(decode_keyframe_request(&[2, 1, 2, 3, 4, 5]), None);
        assert_eq!(decode_keyframe_request(&[1, 1, 2, 3, 4]), None);
        assert_eq!(decode_keyframe_request(&[]), None);
    }

    #[test]
    fn decode_never_panics_on_any_short_input() {
        for len in 0..9usize {
            for fill in [0u8, 1, 2, 255] {
                let b = vec![fill; len];
                let _ = HealthNote::decode(&b);
                let _ = decode_keyframe_request(&b);
            }
        }
    }
}
