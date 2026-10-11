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
use std::collections::HashSet;
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
        None,
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
    println!("Companion card: {}", me.card.to_json());
    println!("Waiting for the app (up to {} s)...", args.duration_secs);
    let end = Instant::now() + Duration::from_secs(args.duration_secs);
    let mut answered: HashSet<String> = HashSet::new();
    let mut reported: HashSet<String> = HashSet::new();
    let mut retrying: HashSet<String> = HashSet::new();
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
