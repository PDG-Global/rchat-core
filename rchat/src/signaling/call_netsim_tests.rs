//! Android calls spec §9 "Network simulator": two real call connections
//! per phone through an in-process TCP proxy that adds delay, loss and
//! freezes, to the real relay, with two real `CallMedia` engines. TCP never
//! loses data, so a lost segment is modelled as what it causes: everything
//! behind it held back until the re-send (a fast retransmit after about
//! one RTT plus three frames, or an RTO of 300 ms for one loss in five).
//! Real time, so `#[ignore]`d: run `scripts/test-calls-netsim.sh` (D28).

use super::test_support::{
    eventually, grant_message, pair_up, start, test_config, TestIdentity, DEV_ORIGIN,
};
use super::*;
use rchat_core::call::engine::{AudioLink, CallMedia, MediaStart};
use rchat_core::call::lanes::LaneConfig;
use rchat_core::call::video::adapt::Rung;
use rchat_core::call::video::engine::{VideoCounters, VideoMedia, VideoStart};
use rchat_core::call::video::health::Banner;
use rchat_core::call::video::testing::SyntheticEncoder;
use rchat_core::call::video::{Quality, VideoCodec};
use rchat_core::call::{keys, CallId, FRAME_SAMPLES};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub(super) struct Impair {
    pub(super) one_way_ms: u64,
    pub(super) loss: f64,
    /// (connection index at this proxy, start ms, end ms) from the proxy's start.
    pub(super) freezes: Vec<(usize, u64, u64)>,
    /// R33: only the phone-to-relay direction is impaired (a weak uplink).
    pub(super) up_only: bool,
    /// Only the relay-to-phone direction is impaired (a weak downlink).
    pub(super) down_only: bool,
    /// R33: a shared bandwidth limit, bits per second, one bucket per
    /// direction per proxy, shared by every connection through it (so audio
    /// and video compete as on one real link). Changeable with `set_rate`.
    pub(super) rate_bps: Option<u64>,
}

/// One direction's link: the time it is next free. Connections reserve it
/// 1500 bytes at a time, so they interleave (a fair queue) instead of one
/// connection's whole chunk delaying another's audio.
type Link = Arc<tokio::sync::Mutex<Instant>>;
/// What passed one direction of a proxy: bytes, and the longest the shared
/// link's queue was since the last `take` (for the report's traces).
#[derive(Default)]
struct Meter {
    bytes: AtomicU64,
    peak_ms: AtomicU64,
    /// Bytes past the link by connection index at the proxy.
    by_conn: parking_lot::Mutex<std::collections::BTreeMap<usize, u64>>,
}

impl Meter {
    /// "index:kbit/s" for each connection that passed bytes since the last
    /// call (one second).
    fn take_conns(&self) -> String {
        let m = std::mem::take(&mut *self.by_conn.lock());
        m.iter()
            .map(|(i, b)| format!("{i}:{}", b * 8 / 1000))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// (kbit/s over `secs`, peak queue ms) since the last call.
    fn take(&self, secs: f64) -> (u64, u64) {
        let bytes = self.bytes.swap(0, Ordering::SeqCst);
        (
            (bytes as f64 * 8.0 / 1000.0 / secs) as u64,
            self.peak_ms.swap(0, Ordering::SeqCst),
        )
    }
}

const MTU: usize = 1500;
const PROXY_SOCKET_BUF: libc::c_int = 8 * 1024;

/// Small socket buffers on the proxy's sockets: a real bottleneck's queue is
/// bounded, so a sender that outruns it must see its writes back up instead
/// of the loopback absorbing (and auto-tuning to) seconds of it.
fn shrink_buffers(sock: &impl std::os::fd::AsRawFd) {
    for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        // SAFETY: a valid socket fd and a pointer to a c_int of the stated size.
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &PROXY_SOCKET_BUF as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

struct Proxy {
    url: String,
    kill_all: Arc<AtomicBool>,
    /// 0 = no limit.
    rate: Arc<AtomicU64>,
    /// Loss share in millionths.
    loss_ppm: Arc<AtomicU64>,
    up: Arc<Meter>,
    down: Arc<Meter>,
}

impl Proxy {
    async fn start(relay: SocketAddr, imp: Impair) -> Proxy {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let kill_all = Arc::new(AtomicBool::new(false));
        let (k, t0, count) = (
            kill_all.clone(),
            Instant::now(),
            Arc::new(AtomicUsize::new(0)),
        );
        let rate = Arc::new(AtomicU64::new(imp.rate_bps.unwrap_or(0)));
        let (up_link, down_link): (Link, Link) = (
            Arc::new(tokio::sync::Mutex::new(Instant::now())),
            Arc::new(tokio::sync::Mutex::new(Instant::now())),
        );
        let rate_task = rate.clone();
        let loss_ppm = Arc::new(AtomicU64::new((imp.loss * 1_000_000.0) as u64));
        let loss_task = loss_ppm.clone();
        let (up_meter, down_meter) = (Arc::new(Meter::default()), Arc::new(Meter::default()));
        let (up_m, down_m) = (up_meter.clone(), down_meter.clone());
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let index = count.fetch_add(1, Ordering::SeqCst);
                let Ok(upstream) = tokio::net::TcpStream::connect(relay).await else {
                    continue;
                };
                let _ = client.set_nodelay(true);
                let _ = upstream.set_nodelay(true);
                shrink_buffers(&client);
                shrink_buffers(&upstream);
                let (cr, cw) = client.into_split();
                let (ur, uw) = upstream.into_split();
                let seed = index as u64 * 2 + 1;
                let reset = Arc::new(AtomicBool::new(false));
                // The impaired directions: both, or only up, or only down.
                let impaired = |up: bool| if up { !imp.down_only } else { !imp.up_only };
                let dir = |up: bool, link: &Link| Dir {
                    reset: reset.clone(),
                    from_phone: up,
                    meter: if up { up_m.clone() } else { down_m.clone() },
                    imp: if impaired(up) {
                        imp.clone()
                    } else {
                        Impair::default()
                    },
                    limited: impaired(up),
                    rate: rate_task.clone(),
                    loss_ppm: loss_task.clone(),
                    link: link.clone(),
                };
                tokio::spawn(pump(
                    cr,
                    uw,
                    dir(true, &up_link),
                    index,
                    t0,
                    seed,
                    k.clone(),
                ));
                tokio::spawn(pump(
                    ur,
                    cw,
                    dir(false, &down_link),
                    index,
                    t0,
                    seed + 1,
                    k.clone(),
                ));
            }
        });
        Proxy {
            url,
            kill_all,
            rate,
            loss_ppm,
            up: up_meter,
            down: down_meter,
        }
    }

    /// Changes the loss share while running.
    fn set_loss(&self, loss: f64) {
        self.loss_ppm
            .store((loss * 1_000_000.0) as u64, Ordering::SeqCst);
    }

    /// Changes the bandwidth limit while running (`None` lifts it).
    fn set_rate(&self, rate_bps: Option<u64>) {
        self.rate.store(rate_bps.unwrap_or(0), Ordering::SeqCst);
    }

    /// Every connection through this proxy drops at once (a network change).
    fn drop_all(&self) {
        self.kill_all.store(true, Ordering::SeqCst);
    }

    fn allow(&self) {
        self.kill_all.store(false, Ordering::SeqCst);
    }
}

/// What one direction of one connection is subject to.
struct Dir {
    /// The phone reset this connection (an abortive close). Bytes the proxy
    /// holds for it and has not yet put on the link are dropped: on the
    /// loopback the phone's backlog moves at once into the proxy's receive
    /// buffer (macOS keeps about 50 KB there whatever `SO_RCVBUF` says), where
    /// on a real path it would still be in the phone's send buffer, which
    /// the reset discards. Bytes already past the link still arrive.
    reset: Arc<AtomicBool>,
    /// This direction reads from the phone (phone to relay).
    from_phone: bool,
    imp: Impair,
    /// The shared bandwidth limit applies in this direction.
    limited: bool,
    rate: Arc<AtomicU64>,
    loss_ppm: Arc<AtomicU64>,
    link: Link,
    meter: Arc<Meter>,
}

/// Reads, serialises over the shared link, and hands each chunk to a writer
/// task with its release time. The writer keeps order (TCP: nothing
/// overtakes a held segment) while the reader goes on, so the one-way delay
/// never limits throughput; a loss stalls the reader too (the sender waits
/// for the re-send).
async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    dir: Dir,
    index: usize,
    t0: Instant,
    seed: u64,
    kill: Arc<AtomicBool>,
) {
    let Dir {
        reset,
        from_phone,
        imp,
        limited,
        rate,
        loss_ppm,
        link,
        meter,
    } = dir;
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 11) as f64 / (1u64 << 53) as f64
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Instant, Vec<u8>)>(8);
    let writer_kill = kill.clone();
    let writer_reset = reset.clone();
    tokio::spawn(async move {
        while let Some((at, bytes)) = rx.recv().await {
            tokio::time::sleep_until(at.into()).await;
            if writer_kill.load(Ordering::SeqCst) {
                return;
            }
            if let Err(e) = to.write_all(&bytes).await {
                if e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::BrokenPipe
                {
                    writer_reset.store(true, Ordering::SeqCst);
                }
                return;
            }
        }
    });
    // Reads the phone's socket error (this pump reads from the phone).
    let phone_reset = |from: &tokio::net::tcp::OwnedReadHalf| -> bool {
        use std::os::fd::AsRawFd;
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: a live socket fd owned by `from`, and an int-sized buffer.
        let r = unsafe {
            libc::getsockopt(
                from.as_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        r == 0 && err == libc::ECONNRESET
    };

    let mut buf = vec![0u8; 16 * 1024];
    let mut release = Instant::now();
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if kill.load(Ordering::SeqCst) {
            return;
        }
        let gone = |from: &tokio::net::tcp::OwnedReadHalf| {
            if from_phone && phone_reset(from) {
                reset.store(true, Ordering::SeqCst);
            }
            reset.load(Ordering::SeqCst)
        };
        if gone(&from) {
            return;
        }
        meter.bytes.fetch_add(n as u64, Ordering::Relaxed);
        let bps = rate.load(Ordering::SeqCst);
        if limited && bps > 0 {
            let mut left = n;
            while left > 0 {
                if gone(&from) {
                    return;
                }
                let slice = left.min(MTU);
                left -= slice;
                let done = {
                    let mut free = link.lock().await;
                    let start = (*free).max(Instant::now());
                    *free = start + Duration::from_micros(slice as u64 * 8_000_000 / bps);
                    *free
                };
                meter.peak_ms.fetch_max(
                    done.saturating_duration_since(Instant::now()).as_millis() as u64,
                    Ordering::Relaxed,
                );
                tokio::time::sleep_until(done.into()).await;
            }
        }
        *meter.by_conn.lock().entry(index).or_default() += n as u64;
        let now = Instant::now();
        let mut at = now + Duration::from_millis(imp.one_way_ms);
        let mut stall = Duration::ZERO;
        if rnd() < loss_ppm.load(Ordering::Relaxed) as f64 / 1_000_000.0 {
            let rto = rnd() < 0.2;
            let ms = if rto { 300 } else { 2 * imp.one_way_ms + 60 };
            stall = Duration::from_millis(ms);
            at += stall;
        }
        let since = now.saturating_duration_since(t0).as_millis() as u64;
        for &(i, s, e) in &imp.freezes {
            if i == index && since >= s && since < e {
                at = at.max(t0 + Duration::from_millis(e));
            }
        }
        release = release.max(at);
        if tx.send((release, buf[..n].to_vec())).await.is_err() {
            return;
        }
        if !stall.is_zero() {
            tokio::time::sleep(stall).await;
        }
    }
}

pub(super) struct CallRun {
    /// (time since start in ms, mouth-to-ear ms) of each frame B played.
    pub(super) delays: Vec<(u64, u64)>,
    /// B's play totals per second of the run.
    pub(super) totals_by_second: Vec<rchat_core::call::playout::PlayTotals>,
    pub(super) refused: bool,
}

/// A scripted change to the proxies during a run, at a time in ms.
#[derive(Clone, Copy)]
pub(super) enum Act {
    RateA(Option<u64>),
    RateB(Option<u64>),
    /// Both proxies: no bandwidth limit and no loss (the link recovers).
    Recover,
    DropA,
    AllowA,
}

/// What a video run is set up with: the receivers' Caps `max_recv`
/// (`peer_max_a` is what B asks A to send at most) and scripted changes.
#[derive(Clone)]
pub(super) struct VideoSetup {
    pub(super) peer_max_a: Quality,
    pub(super) peer_max_b: Quality,
    /// B's camera is on too (a two-way video call); off, B only watches.
    pub(super) b_sends: bool,
    pub(super) acts: Vec<(u64, Act)>,
}

impl Default for VideoSetup {
    fn default() -> Self {
        VideoSetup {
            peer_max_a: Quality::P720,
            peer_max_b: Quality::P720,
            b_sends: true,
            acts: Vec::new(),
        }
    }
}

pub(super) struct VideoRun {
    /// A's rung every 100 ms (`None` = paused), by seconds since the start.
    pub(super) rungs_a: Vec<(f64, Option<Rung>)>,
    pub(super) rungs_b: Vec<(f64, Option<Rung>)>,
    pub(super) banner_a: Vec<(f64, Banner)>,
    pub(super) banner_b: Vec<(f64, Banner)>,
    /// (seconds since the start, ms from A's `send_frame` to B's `take`).
    pub(super) frame_delay_ms_b: Vec<(f64, u64)>,
    /// Seconds at which B took a keyframe.
    pub(super) keyframes_b: Vec<f64>,
    /// A's video seq sampled every 100 ms (`next_seq`).
    pub(super) seqs_a: Vec<(f64, u64)>,
    /// Audio lane queue drops (both phones, both lanes) over the run.
    pub(super) audio_dropped: u64,
    /// Per second: A's uplink and downlink at the proxy, (kbit/s, peak queue ms).
    pub(super) link_a: Vec<((u64, u64), (u64, u64))>,
    /// Per second: frames A and B took from their engines.
    pub(super) taken: Vec<(u64, u64)>,
    /// Each phone's lane switches and reconnects, and reassembly totals.
    pub(super) counters_a: VideoCounters,
    pub(super) counters_b: VideoCounters,
    /// A's counters each second, and A's worst lane wait in that second
    /// (oldest fragment ms, no-progress ms) for the traces.
    pub(super) counters_a_by_second: Vec<VideoCounters>,
    pub(super) lanes_a_by_second: Vec<(u64, u64)>,
    pub(super) counters_b_by_second: Vec<VideoCounters>,
    pub(super) lanes_b_by_second: Vec<(u64, u64)>,
    /// Per second: kbit/s past A's uplink and B's downlink by connection.
    pub(super) conns_by_second: Vec<String>,
    pub(super) audio: CallRun,
}

async fn run_call(imp_a: Impair, imp_b: Impair, seconds: u64, drop_a_at: Option<u64>) -> CallRun {
    let acts = drop_a_at.map_or(Vec::new(), |s| {
        vec![(s * 1000, Act::DropA), (s * 1000 + 300, Act::AllowA)]
    });
    run_rig(imp_a, imp_b, seconds, acts, None).await.0
}

pub(super) async fn run_video_call(
    imp_a: Impair,
    imp_b: Impair,
    seconds: u64,
    setup: VideoSetup,
) -> VideoRun {
    let acts = setup.acts.clone();
    let (audio, video) = run_rig(imp_a, imp_b, seconds, acts, Some(setup)).await;
    let mut v = video.expect("video run");
    v.audio = audio;
    v
}

/// A video phone: the encoder loop at the engine's hint and the decoder
/// loop. Frame `n` carries `n` in its first 4 bytes; `sent[n]` is when it
/// was handed to the engine.
#[allow(clippy::too_many_arguments)]
fn spawn_video_phone(
    media: Arc<VideoMedia>,
    sent_mine: Arc<parking_lot::Mutex<Vec<Option<Instant>>>>,
    sent_theirs: Arc<parking_lot::Mutex<Vec<Option<Instant>>>>,
    seed: u64,
    t0: Instant,
    delays: Arc<parking_lot::Mutex<Vec<(f64, u64)>>>,
    keyframes: Arc<parking_lot::Mutex<Vec<f64>>>,
    taken: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let m = media.clone();
    let stop_enc = stop.clone();
    tokio::spawn(async move {
        let mut enc = SyntheticEncoder::new(seed);
        let mut n: u32 = 0;
        let mut next = Instant::now();
        // The app re-asks its encoder for a keyframe while the engine's hint
        // still wants one (the engine bumps the hint's generation only when
        // the hint changes, and the synthetic encoder answers once per
        // generation): a keyframe sent with no lane up, or dropped, is
        // asked for again.
        let mut reask = 0u32;
        while !stop_enc.load(Ordering::SeqCst) {
            let mut hint = m.encoder_hint();
            hint.generation = hint.generation.wrapping_add(reask);
            next += Duration::from_micros(1_000_000 / u64::from(hint.fps.max(1)));
            tokio::time::sleep_until(next.into()).await;
            let now = Instant::now();
            if next + Duration::from_millis(200) < now {
                next = now; // never burst after a stall
            }
            if let Some((mut data, key)) = enc.next(&hint) {
                data[..4].copy_from_slice(&n.to_le_bytes());
                if let Some(slot) = sent_mine.lock().get_mut(n as usize) {
                    *slot = Some(now);
                }
                let queued = m.send_frame(&data, key, 0, now);
                if key && queued <= 0 {
                    reask += 1;
                }
                n += 1;
            }
        }
    });
    tokio::spawn(async move {
        let mut out = vec![0u8; rchat_core::call::video::VIDEO_MAX_FRAME];
        while !stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            match media.take(&mut out, now) {
                Ok(Some(f)) => {
                    taken.fetch_add(1, Ordering::Relaxed);
                    let n = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
                    let at = t0.elapsed().as_secs_f64();
                    if let Some(Some(sent)) = sent_theirs.lock().get(n) {
                        delays
                            .lock()
                            .push((at, now.duration_since(*sent).as_millis() as u64));
                    }
                    if f.keyframe {
                        keyframes.lock().push(at);
                    }
                }
                _ => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    });
}

async fn run_rig(
    imp_a: Impair,
    imp_b: Impair,
    seconds: u64,
    acts: Vec<(u64, Act)>,
    video: Option<VideoSetup>,
) -> (CallRun, Option<VideoRun>) {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    let call_id = CallId([0x31; 16]);
    let ((ka, kva), (kb, kvb)) = (
        keys::derive(&call_id, &[1; 32], &[2; 32], true),
        keys::derive(&call_id, &[1; 32], &[2; 32], false),
    );
    let token = *ka.relay_token;
    wa.send(grant_message(ca.circuit_id, token)).await.unwrap();
    wb.send(grant_message(cb.circuit_id, token)).await.unwrap();
    eventually("token usable", || state.media.is_usable(&token)).await;
    let (pa, pb) = (
        Proxy::start(addr, imp_a).await,
        Proxy::start(addr, imp_b).await,
    );
    let lane = |url: &str| LaneConfig {
        server_url: url.to_string(),
        dev_origin: Some(DEV_ORIGIN.to_string()),
        relay_pin: state.relay_identity.pin(),
        relay_pin_version: Some(state.relay_identity.version()),
        tls_fingerprint: Default::default(),
        resumption: None,
    };
    let ma = CallMedia::start(MediaStart {
        call_id,
        role: 0,
        keys: ka,
        lane: lane(&pa.url),
    })
    .unwrap();
    let mb = CallMedia::start(MediaStart {
        call_id,
        role: 1,
        keys: kb,
        lane: lane(&pb.url),
    })
    .unwrap();
    let t0 = Instant::now();
    // Video: both phones send and decode, as in a video call.
    type Sent = Arc<parking_lot::Mutex<Vec<Option<Instant>>>>;
    let stop = Arc::new(AtomicBool::new(false));
    let (delays_b, keyframes_b) = (
        Arc::new(parking_lot::Mutex::new(Vec::new())),
        Arc::new(parking_lot::Mutex::new(Vec::new())),
    );
    let (taken_a, taken_b) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut vm = None;
    if let Some(setup) = &video {
        let mk = |role: u8, vk, peer_max, m: &Arc<CallMedia>, url: &str| {
            let link: Arc<dyn AudioLink> = m.clone();
            VideoMedia::start(VideoStart {
                call_id,
                role,
                keys: vk,
                relay_token: Zeroizing::new(token),
                lane: lane(url),
                codec: VideoCodec::H265,
                peer_max,
                software_encoder: false,
                audio: link,
            })
            .unwrap()
        };
        let va = mk(0, kva, setup.peer_max_a, &ma, &pa.url);
        let vb = mk(1, kvb, setup.peer_max_b, &mb, &pb.url);
        va.set_sending(true);
        va.set_receiving(setup.b_sends);
        vb.set_sending(setup.b_sends);
        vb.set_receiving(true);
        let slots =
            |n: u64| -> Sent { Arc::new(parking_lot::Mutex::new(vec![None; (n * 31) as usize])) };
        let (sent_a, sent_b) = (slots(seconds + 5), slots(seconds + 5));
        spawn_video_phone(
            va.clone(),
            sent_a.clone(),
            sent_b.clone(),
            1,
            t0,
            Arc::new(parking_lot::Mutex::new(Vec::new())),
            Arc::new(parking_lot::Mutex::new(Vec::new())),
            taken_a.clone(),
            stop.clone(),
        );
        // B's encoder runs too; B's decoder measures A's frames.
        spawn_video_phone(
            vb.clone(),
            sent_b,
            sent_a,
            2,
            t0,
            delays_b.clone(),
            keyframes_b.clone(),
            taken_b.clone(),
            stop.clone(),
        );
        vm = Some((va, vb));
    }
    let frames = (seconds * 50) as usize;
    let mut pushed_at = vec![None; frames + 1];
    let (mut delays, mut totals_by_second) = (Vec::new(), Vec::new());
    let (mut rungs_a, mut banner_a, mut banner_b, mut seqs_a) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut link_a = Vec::new();
    let mut rungs_b = Vec::new();
    let mut taken_by_second = Vec::new();
    let (mut counters_a_by_second, mut lanes_a_by_second) = (Vec::new(), Vec::new());
    let mut lane_worst = (0u64, 0u64);
    let (mut counters_b_by_second, mut lanes_b_by_second) = (Vec::new(), Vec::new());
    let mut lane_worst_b = (0u64, 0u64);
    let mut conns_by_second = Vec::new();
    let mut out = [0i16; FRAME_SAMPLES];
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut last_seq = None;
    let mut pending = acts;
    for k in 0..frames {
        tick.tick().await;
        let ms = k as u64 * 20;
        pending.retain(|&(at, act)| {
            if ms < at {
                return true;
            }
            match act {
                Act::RateA(r) => pa.set_rate(r),
                Act::RateB(r) => pb.set_rate(r),
                Act::Recover => {
                    for p in [&pa, &pb] {
                        p.set_rate(None);
                        p.set_loss(0.0);
                    }
                }
                Act::DropA => pa.drop_all(),
                Act::AllowA => pa.allow(),
            }
            false
        });
        let pcm: [i16; FRAME_SAMPLES] = core::array::from_fn(|i| {
            (((k * FRAME_SAMPLES + i) as f64 * 0.0576).sin() * 8000.0) as i16
        });
        pushed_at[k] = Some(Instant::now());
        ma.push_pcm(&pcm);
        mb.push_pcm(&[0; FRAME_SAMPLES]);
        mb.pull_pcm(&mut out);
        ma.pull_pcm(&mut out);
        if let Some(seq) = mb.last_played_seq().filter(|s| Some(*s) != last_seq) {
            if let Some(Some(at)) = pushed_at.get(seq as usize) {
                delays.push((
                    t0.elapsed().as_millis() as u64,
                    at.elapsed().as_millis() as u64,
                ));
            }
            last_seq = Some(seq);
        }
        if let Some((va, vb)) = &vm {
            for (v, w) in [(va, &mut lane_worst), (vb, &mut lane_worst_b)] {
                for st in v.lane_stats(Instant::now()).iter().filter(|s| s.up) {
                    let old = st.oldest.map_or(0, |d| d.as_millis() as u64);
                    w.0 = w.0.max(old);
                    w.1 = w.1.max(st.since_progress.as_millis() as u64);
                }
            }
        }
        if k % 50 == 49 {
            if let Some((va, vb)) = &vm {
                counters_a_by_second.push(va.counters());
                lanes_a_by_second.push(std::mem::take(&mut lane_worst));
                counters_b_by_second.push(vb.counters());
                lanes_b_by_second.push(std::mem::take(&mut lane_worst_b));
            }
            totals_by_second.push(mb.play_totals());
            link_a.push((pa.up.take(1.0), pa.down.take(1.0)));
            let notes = vm.as_ref().map_or(String::new(), |(va, vb)| {
                let f = |n: Option<rchat_core::call::video::health::HealthNote>| {
                    n.map_or("-".into(), |n| {
                        format!("send {:?} recv {:?} rung {}", n.send, n.recv, n.rung)
                    })
                };
                format!(
                    "; A's note {}; B's note {}",
                    f(vb.peer_note()),
                    f(va.peer_note())
                )
            });
            conns_by_second.push(format!(
                "A up [{}] B down [{}]{notes}",
                pa.up.take_conns(),
                pb.down.take_conns()
            ));
            let _ = (pa.down.take_conns(), pb.up.take_conns());
            taken_by_second.push((
                taken_a.swap(0, Ordering::Relaxed),
                taken_b.swap(0, Ordering::Relaxed),
            ));
        }
        if k % 5 == 0 {
            if let Some((va, vb)) = &vm {
                let (now, t) = (Instant::now(), t0.elapsed().as_secs_f64());
                rungs_a.push((t, va.status(now).rung));
                rungs_b.push((t, vb.status(now).rung));
                banner_a.push((t, va.status(now).banner));
                banner_b.push((t, vb.status(now).banner));
                seqs_a.push((t, va.next_seq()));
            }
        }
    }
    let refused = ma.status(Instant::now()).refused || mb.status(Instant::now()).refused;
    let audio_dropped = ma.audio_lanes_dropped() + mb.audio_lanes_dropped();
    let counters = vm.as_ref().map(|(va, vb)| (va.counters(), vb.counters()));
    stop.store(true, Ordering::SeqCst);
    if let Some((va, vb)) = &vm {
        va.stop();
        vb.stop();
    }
    ma.stop();
    mb.stop();
    let audio = CallRun {
        delays,
        totals_by_second,
        refused,
    };
    let v = vm.map(|_| VideoRun {
        rungs_a,
        rungs_b,
        banner_a,
        banner_b,
        frame_delay_ms_b: delays_b.lock().clone(),
        keyframes_b: keyframes_b.lock().clone(),
        seqs_a,
        audio_dropped,
        link_a,
        taken: taken_by_second,
        counters_a: counters.unwrap_or_default().0,
        counters_b: counters.unwrap_or_default().1,
        counters_a_by_second,
        lanes_a_by_second,
        counters_b_by_second,
        lanes_b_by_second,
        conns_by_second,
        audio: CallRun {
            delays: Vec::new(),
            totals_by_second: Vec::new(),
            refused: false,
        },
    });
    (audio, v)
}

/// Per-second played frames (audio+fec / concealed) and the worst
/// mouth-to-ear in that second, for the measurements in a report.
pub(super) fn trace(name: &str, r: &CallRun) {
    let mut prev = rchat_core::call::playout::PlayTotals::default();
    for (sec, t) in r.totals_by_second.iter().enumerate() {
        let worst = r
            .delays
            .iter()
            .filter(|(at, _)| (*at / 1000) as usize == sec)
            .map(|d| d.1)
            .max()
            .unwrap_or(0);
        println!(
            "  {name} s{sec:02}: played {:2} concealed {:2} worst mouth-to-ear {worst} ms",
            (t.audio + t.fec) - (prev.audio + prev.fec),
            t.concealed - prev.concealed
        );
        prev = *t;
    }
}

/// The 95th percentile; `u64::MAX` for no samples (fails any target).
pub(super) fn p95(v: &mut [u64]) -> u64 {
    if v.is_empty() {
        return u64::MAX;
    }
    v.sort_unstable();
    v[(v.len() * 95 / 100).min(v.len() - 1)]
}

pub(super) fn concealed_share(r: &CallRun, from_s: usize, to_s: usize) -> f64 {
    let (a, b) = (r.totals_by_second[from_s], r.totals_by_second[to_s]);
    let concealed = (b.concealed - a.concealed) as f64;
    let all = ((b.audio + b.fec + b.concealed) - (a.audio + a.fec + a.concealed)) as f64;
    concealed / all.max(1.0)
}

/// Spec §9 targets: 100 ms RTT and 2% loss per connection: at most about
/// 400 ms one-way mouth-to-ear (engine-measured) and under 3% concealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_100ms_rtt_2pct_loss_meets_the_targets() {
    // 50 ms each way per proxy: 100 ms RTT on every call connection; a frame crosses two of them.
    let imp = Impair {
        one_way_ms: 50,
        loss: 0.02,
        ..Impair::default()
    };
    let r = run_call(imp.clone(), imp, 30, None).await;
    trace("100ms/2%", &r);
    assert!(!r.refused);
    let mut settled: Vec<u64> = r
        .delays
        .iter()
        .filter(|(t, _)| *t > 3000)
        .map(|d| d.1)
        .collect();
    let p = p95(&mut settled);
    let share = concealed_share(&r, 3, r.totals_by_second.len() - 1);
    println!(
        "netsim 100 ms RTT, 2% loss: p95 mouth-to-ear {p} ms, concealed {:.2}%",
        share * 100.0
    );
    assert!(p <= 400, "p95 one-way {p} ms");
    assert!(share < 0.03, "concealed {:.2}%", share * 100.0);
}

/// Spec §9: no audible gap after a 600 ms freeze on one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_a_600ms_freeze_on_one_connection_is_not_heard() {
    let frozen = Impair {
        one_way_ms: 25,
        freezes: vec![(0, 8000, 8600)],
        ..Impair::default()
    };
    let clean = Impair {
        one_way_ms: 25,
        ..Impair::default()
    };
    let r = run_call(frozen, clean, 15, None).await;
    trace("freeze", &r);
    let share = concealed_share(&r, 7, 10);
    println!(
        "netsim 600 ms freeze on one connection: concealed {:.2}% around it",
        share * 100.0
    );
    // The other connection carries every frame; at most one concealed 20 ms
    // frame in the 150 around the freeze (well under audible).
    assert!(
        share <= 1.0 / 150.0,
        "concealed {:.2}% around the freeze",
        share * 100.0
    );
}

/// Review Focus 1: both call connections of one phone drop (a network
/// change); they reconnect on the same token and the call carries on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_both_lanes_drop_and_come_back() {
    let imp = Impair {
        one_way_ms: 25,
        ..Impair::default()
    };
    let r = run_call(imp.clone(), imp, 20, Some(6)).await;
    trace("both-drop", &r);
    assert!(!r.refused, "the token survived the drop");
    let late: Vec<u64> = r
        .delays
        .iter()
        .filter(|(t, _)| *t > 11_000)
        .map(|d| d.1)
        .collect();
    assert!(
        late.len() > 300,
        "audio back after the drop: {} frames",
        late.len()
    );
    let share = concealed_share(&r, 11, r.totals_by_second.len() - 1);
    assert!(
        share < 0.01,
        "concealed {:.2}% after recovery",
        share * 100.0
    );
}

/// Carried check: a "both connections silent" restart opens two new
/// connections every 3 s for up to about 23 s from the chat connection's
/// address. At the default per-address cap (64) and the per-connection
/// hello budget, none of those reconnects is refused, even when the
/// abandoned connections are never closed from the client's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real-time network simulator: scripts/test-calls-netsim.sh"]
async fn call_netsim_restart_storm_is_not_refused_at_default_limits() {
    let config = ServerConfig {
        max_connections_per_ip: ServerConfig::default().max_connections_per_ip,
        ..test_config()
    };
    let (addr, state) = start(config).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    let token = [0x44; 32];
    wa.send(grant_message(ca.circuit_id, token)).await.unwrap();
    wb.send(grant_message(cb.circuit_id, token)).await.unwrap();
    eventually("token usable", || state.media.is_usable(&token)).await;
    let rejected = |reason: &str| {
        crate::metrics::REJECTIONS
            .with_label_values(&[reason])
            .get()
    };
    let before = (
        rejected(crate::metrics::REJECT_PER_IP_CAP),
        rejected(crate::metrics::REJECT_MAX_CONNECTIONS),
        rejected(crate::metrics::REJECT_RATE_LIMIT),
    );
    // B's two lanes stay up; A's two lanes restart every 3 s for 24 s and the
    // old sockets are kept open (the worst case: nothing is closed client-side).
    let mut kept = vec![
        super::test_support::joined(&state, addr, token, 0, 1).await,
        super::test_support::joined(&state, addr, token, 1, 1).await,
    ];
    let mut joins = 0;
    for round in 0..8 {
        for lane in 0..2u8 {
            let mut ws = super::test_support::call_connection(addr).await;
            ws.send(super::test_support::join_message(token, lane, 0))
                .await
                .unwrap();
            let got =
                super::test_support::next_media_control(&mut ws, Duration::from_secs(2)).await;
            assert!(
                matches!(got, Some(ControlMessage::MediaJoined)),
                "round {round} lane {lane}: {got:?}"
            );
            joins += 1;
            kept.push(ws);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let after = (
        rejected(crate::metrics::REJECT_PER_IP_CAP),
        rejected(crate::metrics::REJECT_MAX_CONNECTIONS),
        rejected(crate::metrics::REJECT_RATE_LIMIT),
    );
    println!(
        "netsim restart storm: {joins} reconnects in 24 s from one address, {} sockets open at the end (cap {}), refusals per_ip/max/rate: {:?}",
        kept.len() + 2,
        ServerConfig::default().max_connections_per_ip,
        (after.0 - before.0, after.1 - before.1, after.2 - before.2)
    );
    assert_eq!(after, before, "no reconnect was refused");
    drop((wa, wb));
}

/// 20 ms frames from A (a tone) and B (silence), both played out.
async fn talk(ma: &CallMedia, mb: &CallMedia, tick: &mut tokio::time::Interval, frames: usize) {
    let mut out = [0i16; FRAME_SAMPLES];
    for k in 0..frames {
        tick.tick().await;
        let pcm: [i16; FRAME_SAMPLES] = core::array::from_fn(|i| {
            (((k * FRAME_SAMPLES + i) as f64 * 0.0576).sin() * 8000.0) as i16
        });
        ma.push_pcm(&pcm);
        mb.push_pcm(&[0; FRAME_SAMPLES]);
        mb.pull_pcm(&mut out);
        ma.pull_pcm(&mut out);
    }
}

/// Final review I1 (the e2e first-contact case): a call carried on an
/// identity circuit survives a chat reconnect. The reconnecting client's
/// new chat connection closes the old identity circuit (`CloseCircuit`, as
/// the core does for a blind-path contact after every reconnect); the
/// call's token keeps its live call connections and audio carries on with
/// two real engines. Real time but short, so it runs with `cargo test`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_survives_a_chat_reconnect_that_closes_its_identity_circuit() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, mut wb, ca, cb) = pair_up(&state, addr, &a, &b).await;
    let call_id = CallId([0x51; 16]);
    let (ka, kb) = (
        keys::derive(&call_id, &[5; 32], &[6; 32], true).0,
        keys::derive(&call_id, &[5; 32], &[6; 32], false).0,
    );
    let token = *ka.relay_token;
    wa.send(grant_message(ca.circuit_id, token)).await.unwrap();
    wb.send(grant_message(cb.circuit_id, token)).await.unwrap();
    eventually("token usable", || state.media.is_usable(&token)).await;
    let lane = || LaneConfig {
        server_url: format!("ws://{addr}/"),
        dev_origin: Some(DEV_ORIGIN.to_string()),
        relay_pin: state.relay_identity.pin(),
        relay_pin_version: Some(state.relay_identity.version()),
        tls_fingerprint: Default::default(),
        resumption: None,
    };
    let start_media = |role: u8, keys| {
        CallMedia::start(MediaStart {
            call_id,
            role,
            keys,
            lane: lane(),
        })
        .unwrap()
    };
    let (ma, mb) = (start_media(0, ka), start_media(1, kb));
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    talk(&ma, &mb, &mut tick, 100).await;
    let before = mb.last_played_seq().expect("audio before the reconnect");
    // A's chat connection drops; its next one publishes and closes the old
    // identity circuit.
    drop(wa);
    let mut wa2 = super::test_support::authed(addr, &a).await;
    wa2.send(
        UnifiedFrame::control(ControlMessage::CloseCircuit {
            circuit_id: ca.circuit_id,
        })
        .encode(),
    )
    .await
    .unwrap();
    eventually("identity pair closed", || {
        state.circuits.get(&ca.circuit_id).is_none()
    })
    .await;
    talk(&ma, &mb, &mut tick, 100).await;
    let now = Instant::now();
    let (sa, sb) = (ma.status(now), mb.status(now));
    assert!(!sa.refused && !sb.refused, "the token outlived the close");
    assert_eq!((sa.connections, sb.connections), (2, 2), "lanes stay up");
    let after = mb.last_played_seq().expect("audio after the reconnect");
    assert!(after > before + 50, "audio carried on: {before} -> {after}");
    assert!(state.media.is_usable(&token));
    ma.stop();
    mb.stop();
    drop((wa2, wb));
}
