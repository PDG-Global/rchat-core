//! iOS test companion (protocol v2): a predictable peer for manual testing.
//!
//! 1. `--print-card` prints this peer's card; add it in the app by pasting
//!    or scanning the JSON (the app pins it as "Keys from their code").
//! 2. Run with `--peer-card '<the app's card JSON>'`: the companion pins the
//!    app, asks for a circuit, and replies "pong: <text>" to every message,
//!    marking each one read.

#[path = "support/harness.rs"]
pub mod harness;

use clap::Parser;
use harness::{Card, Peer};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "test-ios-companion",
    about = "Protocol v2 peer for manual iOS testing"
)]
struct Args {
    #[arg(long, default_value = "ws://127.0.0.1:18443")]
    server: String,
    #[arg(long)]
    origin: Option<String>,
    #[arg(long, default_value = "ios-companion")]
    seed: String,
    /// The iOS app's contact card JSON.
    #[arg(long = "peer-card")]
    peer_card: Option<String>,
    #[arg(long)]
    print_card: bool,
    #[arg(long, default_value_t = 600)]
    duration_secs: u64,
    /// Wait this long after a message arrives before answering it (the
    /// Android background-delivery test sends, leaves the foreground, and
    /// expects the answer while backgrounded).
    #[arg(long, default_value_t = 0)]
    reply_delay_secs: u64,
    /// The companion's state directory (sessions survive a restart).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// How to handle an incoming call: answer (then send --tone-hz and
    /// listen for --expect-hz), decline, busy, or ignore (let it ring out).
    #[arg(long, default_value = "ignore")]
    calls: String,
    /// Read every 20 ms: when present, its trimmed content overrides
    /// --calls; each change to `call` places one call to the app. Lets one
    /// companion serve every step of a run without a restart.
    #[arg(long)]
    calls_mode_file: Option<PathBuf>,
    /// Video behaviour: echo, decline, ignore or none (no video capability).
    #[arg(long)]
    video_mode_file: Option<PathBuf>,
    #[arg(long, default_value_t = 440.0)]
    tone_hz: f64,
    #[arg(long, default_value_t = 880.0)]
    expect_hz: f64,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("companion error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let me = Peer::new(
        "Companion",
        &args.server,
        args.origin.as_deref(),
        &args.seed,
        args.state_dir.clone(),
        None,
    )?;
    if args.print_card {
        println!("{}", me.card.to_json());
        return Ok(());
    }
    let app = Card::parse(args.peer_card.as_deref().ok_or("--peer-card is required")?)?;
    // E15: pin before start, as the app does.
    me.pin(&app)?;
    me.start(Duration::from_secs(15))?;
    me.ask(&app)?;
    let client = me.client.clone();
    let mode = CallMode {
        default: args.calls.clone(),
        file: args.calls_mode_file.clone(),
        tone_hz: args.tone_hz,
        expect_hz: args.expect_hz,
        video_file: args.video_mode_file.clone(),
    };
    let app_ik = app.ik.clone();
    let video_client = client.clone();
    std::thread::spawn(move || call_loop(&client, &mode, &app_ik));
    std::thread::spawn(move || video_loop(&video_client));
    println!("Companion card: {}", me.card.to_json());
    println!("Waiting for the app (up to {} s)...", args.duration_secs);
    let end = Instant::now() + Duration::from_secs(args.duration_secs);
    let mut answered: HashSet<String> = HashSet::new();
    let mut reported: HashSet<String> = HashSet::new();
    let mut retrying: HashSet<String> = HashSet::new();
    let mut seen_at: HashMap<String, Instant> = HashMap::new();
    while Instant::now() < end {
        let new: Vec<(String, String)> = me.snapshot(|r| {
            r.messages
                .iter()
                .filter(|m| m.sender_identity == app.ik && m.is_text && !answered.contains(&m.id))
                .map(|m| {
                    (
                        m.id.clone(),
                        String::from_utf8_lossy(&m.content).into_owned(),
                    )
                })
                .collect()
        });
        // A message counts as answered only once its reply was taken; until
        // then it is retried on every pass (every 250 ms).
        for (id, text) in new {
            if reported.insert(id.clone()) {
                println!("received: {text}");
            }
            let first = *seen_at.entry(id.clone()).or_insert_with(Instant::now);
            if first.elapsed() < Duration::from_secs(args.reply_delay_secs) {
                continue;
            }
            match me.send(&app, &format!("pong: {text}")) {
                Ok(_) => {
                    answered.insert(id.clone());
                    let _ = me.client.send_read_receipt(app.ik.clone(), vec![id]);
                }
                Err(e) if retrying.insert(id.clone()) => {
                    println!("reply not sent yet ({e}); retrying until it is");
                }
                Err(_) => {}
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = me.client.disconnect();
    Ok(())
}

/// What the call loop does: `default` unless `file` exists, then its
/// trimmed content (`answer`, `decline`, `busy`, `ignore` or `call`).
struct CallMode {
    default: String,
    file: Option<PathBuf>,
    tone_hz: f64,
    expect_hz: f64,
    video_file: Option<PathBuf>,
}

impl CallMode {
    fn current(&self) -> String {
        self.file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| self.default.clone())
    }

    fn video(&self) -> String {
        self.video_file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "ignore".into())
    }
}

/// Answers, declines or refuses calls as told, places one call to the app
/// each time the mode changes to `call`; while a call runs, sends a tone
/// every 20 ms and reports once it hears the app's tone.
fn call_loop(client: &rchat_core::RChatClient, mode: &CallMode, app_ik: &str) {
    let mut last_mode = String::new();
    let mut last_video = String::new();
    let mut in_call: Option<String> = None;
    let mut heard = Vec::new();
    let mut reported = false;
    let mut frame = 0usize;
    let mut out = [0i16; 960];
    // Paced on a deadline, not a plain sleep, so a busy host (an emulator
    // running beside) never makes it send fewer than 50 frames a second.
    let mut next = Instant::now();
    loop {
        let now_mode = mode.current();
        let video_mode = mode.video();
        if video_mode != last_video {
            client.call_video_configure(if video_mode == "none" { 0 } else { 3 }, false, false);
            last_video = video_mode.clone();
        }
        if now_mode != last_mode {
            if now_mode == "call" {
                match client.call_place(app_ik.to_string()) {
                    Ok(id) => in_call = Some(id),
                    Err(e) => println!("call: place failed {e}"),
                }
            }
            last_mode = now_mode.clone();
        }
        while let Some(json) = client.call_poll_event() {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            let id = v["call_id"].as_str().unwrap_or_default().to_string();
            match v["type"].as_str().unwrap_or_default() {
                "incoming" => {
                    println!("call: incoming");
                    match now_mode.as_str() {
                        "answer" => match client.call_answer(id.clone()) {
                            Ok(()) => {
                                if v["video"].as_bool().unwrap_or(false) && video_mode == "echo" {
                                    let _ = client.call_video_set_camera(true);
                                }
                                in_call = Some(id);
                            }
                            Err(e) => println!("call: answer failed {e}"),
                        },
                        "decline" => {
                            let _ = client.call_decline(id, false);
                        }
                        "busy" => {
                            let _ = client.call_decline(id, true);
                        }
                        _ => {}
                    }
                }
                "ringing" => println!("call: ringing"),
                "connected" => println!("call: connected"),
                "status" => println!("call: status {json}"),
                "video_request" => {
                    println!("video: request");
                    match video_mode.as_str() {
                        "echo" => {
                            let _ = client.call_video_respond(true);
                            let _ = client.call_video_set_camera(true);
                        }
                        "decline" => {
                            let _ = client.call_video_respond(false);
                        }
                        _ => {}
                    }
                }
                "video" if v["agreed"].as_bool().unwrap_or(false) => println!("video: agreed"),
                "ended" => {
                    println!(
                        "call: ended {} {}",
                        v["result"].as_str().unwrap_or_default(),
                        v["duration_secs"]
                    );
                    in_call = None;
                    heard.clear();
                    reported = false;
                }
                _ => {}
            }
        }
        if in_call.is_some() {
            if client.call_push_pcm(&harness::tone(mode.tone_hz, frame)) == 960 {
                frame += 1;
            }
            if client.call_pull_pcm(&mut out) == 960 {
                heard.extend_from_slice(&out);
                if heard.len() >= 48_000 {
                    if !reported && harness::tone_share(&heard, mode.expect_hz) > 0.3 {
                        println!("call: heard {}", mode.expect_hz);
                        reported = true;
                    }
                    heard.drain(..24_000);
                }
            }
        }
        next += Duration::from_millis(20);
        let now = Instant::now();
        if next + Duration::from_millis(200) < now {
            next = now;
        }
        std::thread::sleep(next.saturating_duration_since(now));
    }
}

/// Echoes each complete encoded frame back to the app. The handle never waits on the client lock.
fn video_loop(client: &rchat_core::RChatClient) {
    let video = client.call_video_handle();
    let mut buf = vec![0u8; 393_216];
    let mut echoed = 0usize;
    let mut took = false;
    let mut echo_not_ready = false;
    loop {
        if let Ok(Some(frame)) = video.take(&mut buf) {
            if !took {
                println!("video: took");
                took = true;
            }
            let sent = video.send_frame(&buf[..frame.len], frame.keyframe, frame.rotation_deg);
            if sent > 0 {
                echoed += 1;
                if echoed.is_multiple_of(30) {
                    println!("video: echoed {echoed}");
                }
            } else if sent == 0 && !echo_not_ready {
                println!("video: echo not ready");
                echo_not_ready = true;
            } else if sent < 0 {
                println!("video: echo rejected");
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::harness::{tone, tone_share};

    #[test]
    fn tone_share_finds_its_own_frequency_and_not_another() {
        let pcm: Vec<i16> = (0..50).flat_map(|n| tone(440.0, n)).collect();
        assert!(tone_share(&pcm, 440.0) > 0.9);
        assert!(tone_share(&pcm, 880.0) < 0.05);
    }
}
