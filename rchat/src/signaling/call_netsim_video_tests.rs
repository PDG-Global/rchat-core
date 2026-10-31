//! Android video calls spec §4, §9: the video scenarios of the network
//! simulator (`call_netsim_tests` has the proxy and the rig). Real time, so
//! `#[ignore]`d: run `scripts/test-calls-netsim.sh`.

use super::call_netsim_tests::*;
use rchat_core::call::video::adapt::Rung;
use rchat_core::call::video::engine::VideoCounters;
use rchat_core::call::video::health::Banner;
use rchat_core::call::video::Quality;

/// Index of the first sample at or after `secs`.
fn after<T>(v: &[(f64, T)], secs: f64) -> usize {
    v.iter().position(|(t, _)| *t >= secs).unwrap_or(v.len())
}

fn values_after(v: &[(f64, u64)], secs: f64) -> Vec<u64> {
    v[after(v, secs)..].iter().map(|s| s.1).collect()
}

fn audio_delays_after(r: &CallRun, secs: f64) -> Vec<u64> {
    r.delays
        .iter()
        .filter(|(t, _)| *t as f64 / 1000.0 >= secs)
        .map(|d| d.1)
        .collect()
}

/// The first time the rung is `rung` or worse (paused counts as worse);
/// infinity if it never is.
fn first_time_at_or_below(r: &[(f64, Option<Rung>)], rung: Rung) -> f64 {
    r.iter()
        .find(|(_, x)| x.is_none_or(|x| x >= rung))
        .map_or(f64::INFINITY, |s| s.0)
}

fn first_time_at_or_above(r: &[(f64, Option<Rung>)], rung: Rung, from: f64) -> f64 {
    r.iter()
        .find(|(t, x)| *t >= from && x.is_some_and(|x| x <= rung))
        .map_or(f64::INFINITY, |s| s.0)
}

fn first_banner(b: &[(f64, Banner)], want: Banner) -> f64 {
    b.iter()
        .find(|(_, x)| *x == want)
        .map_or(f64::INFINITY, |s| s.0)
}

fn rung_name(r: Option<Rung>) -> String {
    r.map_or("paused".into(), |r| format!("{r:?}"))
}

/// Rung changes and the audio / video summary of a run, for the report.
fn video_trace(name: &str, r: &VideoRun) {
    let mut last = None;
    for (t, x) in &r.rungs_a {
        if last != Some(*x) {
            println!("  {name} rung A @ {t:.1}s -> {}", rung_name(*x));
            last = Some(*x);
        }
    }
    let mut lastr = None;
    for (t, x) in &r.rungs_b {
        if lastr != Some(*x) {
            println!("  {name} rung B @ {t:.1}s -> {}", rung_name(*x));
            lastr = Some(*x);
        }
    }
    let mut lastb = (Banner::None, Banner::None);
    for ((t, a), (_, b)) in r.banner_a.iter().zip(&r.banner_b) {
        if (*a, *b) != lastb {
            println!("  {name} banner @ {t:.1}s A {a:?} B {b:?}");
            lastb = (*a, *b);
        }
    }
    let mut prev = VideoCounters::default();
    let mut prev_b = VideoCounters::default();
    for (sec, ((ur, up), (dr, dp))) in r.link_a.iter().enumerate() {
        let (ta, tb) = r.taken.get(sec).copied().unwrap_or_default();
        let c = r.counters_a_by_second.get(sec).copied().unwrap_or_default();
        let (old, stuck) = r.lanes_a_by_second.get(sec).copied().unwrap_or_default();
        println!(
            "  {name} s{sec:02} A up {ur} kbit/s (queue {up} ms) down {dr} kbit/s (queue {dp} ms); frames taken A {ta} B {tb}; A sent {} (key {}) dropped {} switched {}, lane wait {old} ms, no progress {stuck} ms, reconnects {}, last down {:?}",
            c.frames_queued - prev.frames_queued,
            c.keyframes_queued - prev.keyframes_queued,
            c.sender_dropped - prev.sender_dropped,
            c.switched - prev.switched,
            c.lane_reconnects - prev.lane_reconnects,
            c.last_down_cause,
        );
        let cb = r.counters_b_by_second.get(sec).copied().unwrap_or_default();
        let (oldb, stuckb) = r.lanes_b_by_second.get(sec).copied().unwrap_or_default();
        println!(
            "  {name} s{sec:02} B sent {} (key {}) dropped {} switched {}, lane wait {oldb} ms, no progress {stuckb} ms, reconnects {}, last down {:?}",
            cb.frames_queued - prev_b.frames_queued,
            cb.keyframes_queued - prev_b.keyframes_queued,
            cb.sender_dropped - prev_b.sender_dropped,
            cb.switched - prev_b.switched,
            cb.lane_reconnects - prev_b.lane_reconnects,
            cb.last_down_cause,
        );
        prev_b = cb;
        prev = c;
        if let Some(conns) = r.conns_by_second.get(sec) {
            println!("  {name} s{sec:02} by connection: {conns}");
        }
    }
    println!(
        "  {name} counters A {:?}\n  {name} counters B {:?}",
        r.counters_a, r.counters_b
    );
    let mut d = values_after(&r.frame_delay_ms_b, 10.0);
    if !d.is_empty() {
        let n = d.len();
        println!(
            "  {name} video frames B after 10 s: {n}, p95 delay {} ms",
            p95(&mut d)
        );
    }
    let secs = r.audio.totals_by_second.len();
    if secs > 10 {
        let mut ad = audio_delays_after(&r.audio, 10.0);
        println!(
            "  {name} audio 10-{secs} s: concealed {:.2}%, p95 mouth-to-ear {} ms, audio lane drops {}",
            concealed_share(&r.audio, 10, secs - 1) * 100.0,
            p95(&mut ad),
            r.audio_dropped
        );
    }
}

/// R11 / spec §4: a 1 Mbps bottleneck both ways (shared by audio and
/// video), 50 ms one way, 2% loss: video steps down to 480p or lower within
/// 5 s, stays within 600 ms (p95) of the camera, and audio keeps its voice
/// targets. Control frames (one note a second, keyframe requests) share the
/// audio queue; `audio lane drops` in the trace shows whether any audio
/// frame was pushed out of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_steps_down_under_a_1_mbps_bottleneck_and_audio_still_meets_its_targets()
{
    let imp = Impair {
        one_way_ms: 50,
        loss: 0.02,
        rate_bps: Some(1_000_000),
        ..Impair::default()
    };
    let r = run_video_call(imp.clone(), imp, 40, VideoSetup::default()).await;
    video_trace("1mbps", &r);
    assert!(!r.audio.refused);
    let down = first_time_at_or_below(&r.rungs_a, Rung::P480);
    // Ruling (fix round 3): over three script runs the median is at most
    // 5.0 s (checked across runs, from this line) and no run over 6.5 s.
    println!("netsim 1 Mbps: 480p or lower at {down:.2} s");
    assert!(down <= 6.5, "480p or lower after {down:.1} s");
    let mut vd = values_after(&r.frame_delay_ms_b, 10.0);
    assert!(vd.len() > 50, "video kept arriving: {} frames", vd.len());
    let p = p95(&mut vd);
    assert!(p <= 600, "video p95 delay {p} ms");
    let share = concealed_share(&r.audio, 10, 39);
    assert!(share < 0.03, "audio concealed {:.2}%", share * 100.0);
    let mut ad = audio_delays_after(&r.audio, 10.0);
    let a = p95(&mut ad);
    assert!(a <= 400, "audio p95 mouth-to-ear {a} ms");
}

/// R11: the bottleneck lifts at 20 s; the sender climbs back to 720p by 60 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_steps_back_up_when_the_link_recovers() {
    let imp = Impair {
        one_way_ms: 50,
        loss: 0.02,
        rate_bps: Some(1_000_000),
        ..Impair::default()
    };
    let setup = VideoSetup {
        acts: vec![(20_000, Act::Recover)],
        ..VideoSetup::default()
    };
    let r = run_video_call(imp.clone(), imp, 60, setup).await;
    video_trace("recover", &r);
    let up = first_time_at_or_above(&r.rungs_a, Rung::P720, 20.0);
    assert!(up <= 60.0, "back to 720p at {up:.1} s");
}

/// R10: 1080p only when the receiver asked and the link has been clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_1080p_only_when_requested_and_sustained() {
    let clean = Impair {
        one_way_ms: 20,
        ..Impair::default()
    };
    let r = run_video_call(clean.clone(), clean.clone(), 40, VideoSetup::default()).await;
    video_trace("1080-not-asked", &r);
    assert!(
        r.rungs_a.iter().all(|(_, x)| *x != Some(Rung::P1080)),
        "never 1080p when the receiver asked for 720p"
    );
    let setup = VideoSetup {
        peer_max_a: Quality::P1080,
        ..VideoSetup::default()
    };
    let r = run_video_call(clean.clone(), clean, 40, setup).await;
    video_trace("1080-asked", &r);
    let at = first_time_at_or_above(&r.rungs_a, Rung::P1080, 0.0);
    assert!(at.is_finite(), "1080p reached in 40 s");
    assert!(at >= 10.0, "not before 10 s of a clean link: {at:.1} s");
}

/// R11: below 240p video pauses (within 10 s at 160 kbps both ways: two-lane
/// voice alone needs about 85-90 kbps, so 100 kbps could never meet the voice
/// targets) and, from 3 s after the pause until video first resumes, audio
/// is as on a voice-only call: what video had queued, in the app and in the
/// kernels, is gone with the pause. Each resume probe before the lift
/// pauses again within 2 s and costs at most 2 s of concealed audio. When
/// the link lifts at 20 s, video resumes at 240p or better within 15 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_pauses_below_240p_and_resumes() {
    let imp = Impair {
        one_way_ms: 50,
        rate_bps: Some(160_000),
        ..Impair::default()
    };
    let setup = VideoSetup {
        acts: vec![(20_000, Act::RateA(None)), (20_000, Act::RateB(None))],
        ..VideoSetup::default()
    };
    let r = run_video_call(imp.clone(), imp, 55, setup).await;
    video_trace("160kbps", &r);
    trace("160kbps", &r.audio);
    let paused = r
        .rungs_a
        .iter()
        .find(|(_, x)| x.is_none())
        .map_or(f64::INFINITY, |s| s.0);
    assert!(paused <= 10.0, "paused at {paused:.1} s");
    // Paused and flushed: voice as on a voice-only call from 3 s after the
    // pause until video first resumes (R11 probes at 240p, which a 160 kbps
    // link cannot carry; a failed probe doubles the next minimum pause).
    let resumed = r
        .rungs_a
        .iter()
        .find(|(t, x)| *t > paused && x.is_some())
        .map_or(19.0, |s| s.0);
    // Whole seconds [from, to): `totals_by_second[i]` is the total at the
    // end of second i, so a share over seconds a..b is totals[b-1] - totals[a-1].
    let from = (paused + 3.0).ceil() as usize;
    let to = (resumed.floor() as usize).max(from + 1);
    let share = concealed_share(&r.audio, from - 1, to - 1);
    let mut ad: Vec<u64> = r
        .audio
        .delays
        .iter()
        .filter(|(t, _)| (from as u64 * 1000..to as u64 * 1000).contains(t))
        .map(|d| d.1)
        .collect();
    let p = p95(&mut ad);
    let total = concealed_share(&r.audio, 9, 18); // seconds 10.0-19.0
    println!(
        "netsim 160 kbps: paused at {paused:.1} s, resumed at {resumed:.1} s; audio {from}.0-{to}.0 s concealed {:.2}%, p95 mouth-to-ear {p} ms; 10.0-19.0 s concealed {:.2}%",
        share * 100.0,
        total * 100.0
    );
    // Each resume probe before the link lifts (240p cannot fit 160 kbps)
    // fails fast: paused again within 2.0 s, costing at most 2 s of
    // concealed audio over the seconds it touched and the one after.
    let mut probes = Vec::new();
    for w in r.rungs_a.windows(2) {
        if w[0].1.is_none() && w[1].1.is_some() && w[1].0 < 20.0 {
            let start = w[1].0;
            let end = r
                .rungs_a
                .iter()
                .find(|(t, x)| *t > start && x.is_none())
                .map_or(f64::INFINITY, |s| s.0);
            probes.push((start, end));
        }
    }
    for &(start, end) in &probes {
        let (a, b) = (start.floor() as usize, (end.ceil() as usize + 1).min(54));
        let (x, y) = (r.audio.totals_by_second[a - 1], r.audio.totals_by_second[b]);
        let cost = y.concealed - x.concealed;
        println!("netsim 160 kbps: probe {start:.1}-{end:.1} s, {cost} concealed frames");
        assert!(
            end - start <= 2.0,
            "probe at {start:.1} s paused again at {end:.1} s"
        );
        assert!(
            cost <= 100,
            "probe at {start:.1} s cost {cost} concealed frames"
        );
    }
    assert!(
        resumed - paused >= 4.0,
        "paused long enough to measure: {paused:.1}-{resumed:.1} s"
    );
    assert!(
        share < 0.03,
        "audio concealed {:.2}% while paused",
        share * 100.0
    );
    assert!(p <= 400, "audio p95 mouth-to-ear {p} ms while paused");
    let back = first_time_at_or_above(&r.rungs_a, Rung::P240, 20.0);
    assert!(back <= 35.0, "video back at {back:.1} s");
}

/// R15: A's uplink alone is impaired. A's banner says Mine, B's says
/// Theirs (within 10 s); a banner needs 3 s of the same state, so none in
/// the first 3 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_banner_names_the_impaired_sender() {
    let weak_up = Impair {
        one_way_ms: 50,
        loss: 0.02,
        rate_bps: Some(300_000),
        up_only: true,
        ..Impair::default()
    };
    let clean = Impair {
        one_way_ms: 50,
        ..Impair::default()
    };
    // Two-way video: both cameras on, as in a video call.
    let r = run_video_call(weak_up, clean, 25, VideoSetup::default()).await;
    video_trace("banner", &r);
    let (a, b) = (
        first_banner(&r.banner_a, Banner::Mine),
        first_banner(&r.banner_b, Banner::Theirs),
    );
    assert!(a <= 10.0, "A shows Mine at {a:.1} s");
    assert!(b <= 10.0, "B shows Theirs at {b:.1} s");
    let early = |bs: &[(f64, Banner)]| bs.iter().any(|(t, x)| *t < 3.0 && *x != Banner::None);
    assert!(
        !early(&r.banner_a) && !early(&r.banner_b),
        "nothing in the first 3 s"
    );
    // Each blames the right side first: A's first banner is Mine, B's first
    // is Theirs (B never starts by blaming its own link).
    let first = |bs: &[(f64, Banner)]| bs.iter().map(|s| s.1).find(|b| *b != Banner::None);
    assert_eq!(first(&r.banner_a), Some(Banner::Mine));
    assert_eq!(first(&r.banner_b), Some(Banner::Theirs));
}

/// R6 / Review: both phones' connections drop at 10 s and come back at
/// 11 s. The same engines carry on: B takes a keyframe within 8 s after,
/// and A's video seq only ever grows (a repeat would reuse a nonce).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_survives_a_network_drop_without_reusing_a_seq() {
    let imp = Impair {
        one_way_ms: 25,
        ..Impair::default()
    };
    let setup = VideoSetup {
        acts: vec![(10_000, Act::DropA), (11_000, Act::AllowA)],
        ..VideoSetup::default()
    };
    let r = run_video_call(imp.clone(), imp, 25, setup).await;
    video_trace("drop", &r);
    assert!(!r.audio.refused);
    let key = r
        .keyframes_b
        .iter()
        .find(|t| **t >= 11.0)
        .copied()
        .unwrap_or(f64::INFINITY);
    assert!(
        key <= 19.0,
        "keyframe at {key:.1} s after the allow at 11 s"
    );
    assert!(
        r.seqs_a.windows(2).all(|w| w[1].1 >= w[0].1),
        "A's seq never goes back"
    );
    let steady: Vec<u64> = r.seqs_a[after(&r.seqs_a, 13.0)..]
        .iter()
        .map(|s| s.1)
        .collect();
    assert!(
        steady.windows(2).all(|w| w[1] >= w[0]) && steady.last() > steady.first(),
        "never repeats or goes back once the connections are back"
    );
    assert!(
        values_after(&r.frame_delay_ms_b, 14.0).len() > 100,
        "video flows after the drop"
    );
}

/// B's downlink alone is impaired (A films over a clean link, B receives
/// through 300 kbps with 2% loss). A steps down for B's notes within 10 s,
/// A's video reaches B within about 1 s (p95, the relay keeps little unsent
/// towards B and drops what waits over 500 ms), A's voice reaches B within
/// the voice targets, and the banners blame B's link: B shows Mine ("Your
/// connection"), A shows Theirs ("[Name]'s connection"), within 10 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_a_weak_receiver_downlink_steps_the_sender_down() {
    let clean = Impair {
        one_way_ms: 50,
        ..Impair::default()
    };
    let weak_down = Impair {
        one_way_ms: 50,
        loss: 0.02,
        rate_bps: Some(300_000),
        down_only: true,
        ..Impair::default()
    };
    let r = run_video_call(clean, weak_down, 25, VideoSetup::default()).await;
    video_trace("b-downlink", &r);
    let down = first_time_at_or_below(&r.rungs_a, Rung::P480);
    assert!(
        down <= 10.0,
        "A stepped down for B's downlink at {down:.1} s"
    );
    let mut vd = values_after(&r.frame_delay_ms_b, 10.0);
    let p = p95(&mut vd);
    let dropped = |r: &str| {
        crate::metrics::MEDIA_VIDEO_FRAMES_DROPPED
            .with_label_values(&[r])
            .get()
    };
    println!(
        "netsim B downlink: A at 480p or lower at {down:.1} s; B video p95 after 10 s {p} ms; relay video drops stale {} full {} rate {}",
        dropped(crate::metrics::MEDIA_DROP_STALE),
        dropped(crate::metrics::MEDIA_DROP_FULL),
        dropped(crate::metrics::MEDIA_DROP_RATE)
    );
    // The relay keeps little unsent towards a video receiver, so late video
    // waits in its queue, where the age cap drops it. Only Linux shows that
    // here: macOS grows a socket's receive buffer past `SO_RCVBUF` under
    // load (measured: 8 KB set, 321-523 KB grown; 436 KB of A's video
    // waiting in the proxy's relay-side socket), so on this proxy the
    // downlink holds seconds of video whatever the relay does.
    #[cfg(target_os = "linux")]
    assert!(p <= 1000, "B's video p95 delay {p} ms");
    let (a, b) = (
        first_banner(&r.banner_a, Banner::Theirs),
        first_banner(&r.banner_b, Banner::Mine),
    );
    assert!(b <= 10.0, "B shows Mine at {b:.1} s");
    assert!(a <= 10.0, "A shows Theirs at {a:.1} s");
    let first = |bs: &[(f64, Banner)]| bs.iter().map(|s| s.1).find(|b| *b != Banner::None);
    assert_eq!(first(&r.banner_b), Some(Banner::Mine));
    assert_eq!(first(&r.banner_a), Some(Banner::Theirs));
    let share = concealed_share(&r.audio, 10, 24);
    assert!(share < 0.03, "audio concealed {:.2}%", share * 100.0);
    let mut ad = audio_delays_after(&r.audio, 10.0);
    let a = p95(&mut ad);
    assert!(a <= 400, "audio p95 mouth-to-ear {a} ms");
}

/// R10 at a long round trip: a clean link with 100 ms one way per proxy
/// (a frame crosses two), the receiver asks for 1080p: the sender reaches
/// 1080p (not before 10 s) and holds it to the end. The proxy ends TCP at
/// each side, so it does not model the kernel's in-flight limit at this
/// RTT (send buffer and window over the whole path): the phone's 32 KB
/// Apple send buffer would cap one connection at about 1.3 Mbps on a real
/// 200 ms path. This checks the adapter's rule, not 1080p throughput.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_video_1080p_is_reached_and_held_over_a_long_round_trip() {
    let far = Impair {
        one_way_ms: 100,
        ..Impair::default()
    };
    let setup = VideoSetup {
        peer_max_a: Quality::P1080,
        ..VideoSetup::default()
    };
    let r = run_video_call(far.clone(), far, 40, setup).await;
    video_trace("1080-far", &r);
    let at = first_time_at_or_above(&r.rungs_a, Rung::P1080, 0.0);
    assert!(at.is_finite(), "1080p reached in 40 s");
    assert!(at >= 10.0, "not before 10 s of a clean link: {at:.1} s");
    let held = r.rungs_a[after(&r.rungs_a, at)..]
        .iter()
        .all(|(_, x)| *x == Some(Rung::P1080));
    assert!(held, "1080p held from {at:.1} s to the end");
}
