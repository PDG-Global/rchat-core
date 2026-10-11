//! In-process protocol-v2 end-to-end scenarios (spec §12.3: E1, E2, E3, E4,
//! E6). The binary owns the relay process so E2 can restart it.
//!
//! cargo run --bin test-e2ee-integration -- \
//!   --server-bin target/debug/rchat-server --config /tmp/x/server.toml \
//!   --server ws://127.0.0.1:18443/ --origin ws://127.0.0.1:18443 --scenario all

#[path = "support/harness.rs"]
pub mod harness;

use clap::Parser;
use harness::{wait_until, Card, Peer};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "test-e2ee-integration",
    about = "Protocol v2 end-to-end scenarios"
)]
struct Args {
    #[arg(long, default_value = "ws://127.0.0.1:18443/")]
    server: String,
    #[arg(long, default_value = "ws://127.0.0.1:18443")]
    origin: String,
    /// rchat-server binary to spawn (with --config <path> --no-tls).
    #[arg(long)]
    server_bin: String,
    #[arg(long)]
    config: String,
    #[arg(long, default_value = "all")]
    scenario: String,
}

const T: Duration = Duration::from_secs(20);

/// The relay child process.
struct Relay {
    bin: String,
    config: String,
    addr: String,
    child: Option<Child>,
}

impl Relay {
    fn start(bin: &str, config: &str, addr: &str) -> Result<Relay, String> {
        let mut r = Relay {
            bin: bin.to_string(),
            config: config.to_string(),
            addr: addr.to_string(),
            child: None,
        };
        r.spawn()?;
        Ok(r)
    }

    /// The relay's working home: the config's directory. `HOME` points there
    /// too, so the relay's legacy-queue wipe can never touch the real
    /// `~/.rchat`.
    fn home(&self) -> PathBuf {
        Path::new(&self.config)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// A relay started from a config file refuses to run without its
    /// identity key: create it next to the config the first time.
    fn ensure_identity(&self) -> Result<(), String> {
        if self.home().join("relay_identity.key").exists() {
            return Ok(());
        }
        let status = Command::new(&self.bin)
            .args([
                "--config",
                &self.config,
                "--no-tls",
                "--init-relay-identity",
            ])
            .env("HOME", self.home())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("init relay identity: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("init relay identity failed: {status}"))
        }
    }

    fn spawn(&mut self) -> Result<(), String> {
        self.ensure_identity()?;
        let child = Command::new(&self.bin)
            .args(["--config", &self.config, "--no-tls", "--log-level", "warn"])
            .env("HOME", self.home())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn relay: {e}"))?;
        self.child = Some(child);
        if wait_until(Duration::from_secs(10), || {
            TcpStream::connect(&self.addr).is_ok()
        }) {
            Ok(())
        } else {
            Err("relay did not start listening".to_string())
        }
    }

    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        wait_until(Duration::from_secs(5), || {
            TcpStream::connect(&self.addr).is_err()
        });
    }

    fn restart(&mut self) -> Result<(), String> {
        self.kill();
        self.spawn()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.kill();
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();
    let args = Args::parse();
    let addr = args
        .origin
        .trim_start_matches("ws://")
        .trim_end_matches('/')
        .to_string();
    let mut relay = match Relay::start(&args.server_bin, &args.config, &addr) {
        Ok(r) => r,
        Err(e) => {
            println!("FAIL setup: {e}");
            return ExitCode::from(2);
        }
    };
    let all = args.scenario == "all";
    let mut failed = 0;
    let mut run = |id: &str, f: &dyn Fn(&Args, &mut Relay) -> Result<(), String>| {
        if all || args.scenario == id.to_lowercase() {
            match f(&args, &mut relay) {
                Ok(()) => println!("PASS {id}"),
                Err(e) => {
                    println!("FAIL {id}: {e}");
                    failed += 1;
                }
            }
        }
    };
    run("E1", &e1_both_pinned);
    run("E2", &e2_reconnect_matrix);
    run("E3", &e3_offline_delivery);
    run("E4", &e4_requests);
    run("E6", &e6_block_stops_flooding);
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Fresh identities per run: queued state from an earlier run can't leak in.
fn seed(name: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{name}-{}-{now}", std::process::id())
}

/// A peer that is not connected yet. E15: every scenario pins what it
/// pins before `start`, as the app does (pins are staged in the peer book;
/// a record or packet queued for us then finds its peer pinned).
fn peer_with_seed(args: &Args, name: &str, seed_text: &str) -> Result<Peer, String> {
    Peer::new(
        name,
        &args.server,
        Some(&args.origin),
        seed_text,
        None,
        None,
    )
}

fn peer(args: &Args, name: &str) -> Result<Peer, String> {
    peer_with_seed(args, name, &seed(name))
}

fn check(cond: bool, what: &str) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

/// Both pin each other, then start (E15), then ask; wait until both hold a
/// live session.
fn pair_up(a: &Peer, b: &Peer) -> Result<(), String> {
    a.pin(&b.card)?;
    b.pin(&a.card)?;
    a.start(T)?;
    b.start(T)?;
    a.ask(&b.card)?;
    b.ask(&a.card)?;
    check(
        wait_until(T, || {
            a.client.has_session(b.card.ik.clone()) && b.client.has_session(a.card.ik.clone())
        }),
        "circuit never formed with both pinned",
    )
}

/// `from` sends `text` and `to` receives it exactly once.
fn deliver(from: &Peer, to: &Peer, text: &str) -> Result<String, String> {
    let id = from.send(&to.card, text)?;
    check(
        to.wait(T, |r| r.texts_from(&from.card.ik).iter().any(|t| t == text)),
        &format!("{} never received {text:?}", to.name),
    )?;
    let copies = to.snapshot(|r| {
        r.texts_from(&from.card.ik)
            .iter()
            .filter(|t| *t == text)
            .count()
    });
    check(copies == 1, &format!("{text:?} arrived {copies} times"))?;
    Ok(id)
}

fn reconnect_transport(p: &Peer, peer: &Card) -> Result<(), String> {
    p.client
        .disconnect_transport_only()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(500));
    p.start(T)?;
    // Same process, established session, transport reconnected: the core's
    // own `after_publish_ok` sends the resume ask and the relay answers
    // CircuitExists. The harness must not ask again: a resume-less ask that
    // races CircuitExists makes the relay tear the pair down (spec §6.2
    // step 2). Wait until the session is live again.
    check(
        wait_until(T, || p.client.has_session(peer.ik.clone())),
        &format!("{} did not resume its circuit after reconnecting", p.name),
    )
}

/// E1: both pinned — messages both ways with delivered and read receipts.
fn e1_both_pinned(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    let mut a_ids = Vec::new();
    let mut b_ids = Vec::new();
    for i in 0..3 {
        a_ids.push(deliver(&a, &b, &format!("a->b {i}"))?);
        b_ids.push(deliver(&b, &a, &format!("b->a {i}"))?);
    }
    check(
        a.wait(T, |r| a_ids.iter().all(|id| r.has_receipt(id, 1))),
        "alice missing delivered receipts",
    )?;
    let b_got: Vec<String> = b.snapshot(|r| r.messages.iter().map(|m| m.id.clone()).collect());
    b.client
        .send_read_receipt(a.card.ik.clone(), b_got)
        .map_err(|e| e.to_string())?;
    check(
        a.wait(T, |r| a_ids.iter().all(|id| r.has_receipt(id, 2))),
        "alice missing read receipts",
    )?;
    // A receipt never triggers a receipt: every receipt bob holds is for a
    // message bob sent, and none is a read receipt (alice sent none).
    std::thread::sleep(Duration::from_secs(2));
    let stray = b.snapshot(|r| {
        r.receipts
            .iter()
            .filter(|(id, k)| *k == 2 || !b_ids.contains(id))
            .count()
    });
    check(stray == 0, "a receipt triggered a receipt")
}

/// E2: reconnect matrix — initiator, responder, both, relay restart, app restart.
fn e2_reconnect_matrix(args: &Args, relay: &mut Relay) -> Result<(), String> {
    let a_seed = seed("alice");
    let a = peer_with_seed(args, "alice", &a_seed)?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    let circuits = |p: &Peer, q: &Peer| p.snapshot(|r| r.circuits_with(&q.card.ik));

    // Transport-only reconnects resume the circuit: no new CircuitCreatedV2.
    reconnect_transport(&a, &b.card)?;
    std::thread::sleep(Duration::from_secs(2));
    deliver(&a, &b, "after initiator reconnect a->b")?;
    deliver(&b, &a, "after initiator reconnect b->a")?;
    reconnect_transport(&b, &a.card)?;
    std::thread::sleep(Duration::from_secs(2));
    deliver(&a, &b, "after responder reconnect a->b")?;
    deliver(&b, &a, "after responder reconnect b->a")?;
    reconnect_transport(&a, &b.card)?;
    reconnect_transport(&b, &a.card)?;
    std::thread::sleep(Duration::from_secs(2));
    deliver(&a, &b, "after both reconnect")?;
    check(
        circuits(&a, &b) == 1 && circuits(&b, &a) == 1,
        "a transport reconnect created a new circuit instead of resuming",
    )?;

    // Relay restart: all relay state is gone. After republishing, each core
    // asks on its own (`after_publish_ok`, resume naming a circuit the new
    // relay does not know, so it counts as an ordinary ask) and a new pair
    // forms. No explicit harness asks: they would race the cores' asks.
    relay.restart()?;
    check(
        wait_until(T, || {
            a.client.is_key_bundle_published() && b.client.is_key_bundle_published()
        }),
        "clients did not republish after the relay restart",
    )?;
    check(
        wait_until(T, || circuits(&a, &b) == 2 && circuits(&b, &a) == 2),
        "no new circuit after relay restart",
    )?;
    deliver(&a, &b, "after relay restart")?;

    // App restart of alice: a new process has no session, so its ask carries
    // no resume; the relay tears the pair down (bob gets CircuitClosed) and
    // bob's core re-asks, so a new pair forms. Counted per identity:
    // 1 original + 1 after relay restart + 1 now = 3.
    let _ = a.client.disconnect();
    drop(a);
    let a2 = peer_with_seed(args, "alice", &a_seed)?;
    a2.pin(&b.card)?;
    a2.start(T)?;
    a2.ask(&b.card)?;
    check(
        wait_until(T, || {
            circuits(&b, &a2) == 3 && a2.client.has_session(b.card.ik.clone())
        }),
        "no teardown and re-ask after alice's app restart",
    )?;
    deliver(&a2, &b, "after app restart a->b")?;
    deliver(&b, &a2, "after app restart b->a")?;
    Ok(())
}

/// E3: offline delivery — bob's transport is down, alice sends, bob returns.
fn e3_offline_delivery(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    b.client
        .disconnect_transport_only()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_secs(1));
    let ids = [
        a.send(&b.card, "while offline 1")?,
        a.send(&b.card, "while offline 2")?,
    ];
    check(
        a.wait(T, |r| ids.iter().all(|id| r.acks.contains(id))),
        "relay did not acknowledge the queued messages",
    )?;
    b.start(T)?;
    check(
        b.wait(T, |r| {
            let t = r.texts_from(&a.card.ik);
            t.iter().any(|x| x == "while offline 1") && t.iter().any(|x| x == "while offline 2")
        }),
        "queued messages were not delivered by sender identity",
    )
}

/// E4: request with an intro, accept without a duplicate; blocked C never surfaces.
fn e4_requests(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    let c = peer(args, "carol")?;

    // Alice has Bob's code; Bob doesn't know Alice (nothing to pin).
    a.pin(&b.card)?;
    a.start(T)?;
    b.start(T)?;
    a.ask(&b.card)?;
    let intro = "hi bob, it's alice";
    let intro_id = a
        .client
        .set_intro(b.card.ik.clone(), intro.to_string())
        .map_err(|e| e.to_string())?;
    check(
        b.wait(T, |r| {
            r.requests_from(&a.card.ik)
                .iter()
                .any(|q| q.intro_text == intro)
        }),
        "bob never got alice's request with its intro",
    )?;
    // Both sides (Task 24 minor: only Alice's was checked).
    check(
        !a.client.has_session(b.card.ik.clone()) && !b.client.has_session(a.card.ik.clone()),
        "a circuit formed before acceptance",
    )?;
    check(
        a.snapshot(|r| r.receipts.is_empty()),
        "alice got a receipt before bob accepted",
    )?;
    check(
        b.snapshot(|r| r.messages.is_empty()),
        "bob got a message before accepting",
    )?;

    // Bob accepts: pin the request's keys, mark the intro seen, ask.
    let req = b.snapshot(|r| {
        r.requests_from(&a.card.ik)
            .into_iter()
            .find(|q| q.intro_text == intro)
            .expect("checked above")
    });
    check(
        req.intro_message_id_hex == intro_id,
        "intro id changed in transit",
    )?;
    b.client
        .pin_peer_key(req.identity_hex.clone(), req.agreement_hex.clone())
        .map_err(|e| e.to_string())?;
    b.client
        .mark_message_seen(req.identity_hex.clone(), req.intro_message_id_hex.clone())
        .map_err(|e| e.to_string())?;
    b.ask(&a.card)?;
    check(
        wait_until(T, || {
            a.client.has_session(b.card.ik.clone()) && b.client.has_session(a.card.ik.clone())
        }),
        "accepting did not open the conversation",
    )?;
    // Alice sends the intro for real under its id: Bob already has it.
    a.client
        .send_text_message_using_id(b.card.ik.clone(), intro.to_string(), intro_id.clone())
        .map_err(|e| e.to_string())?;
    check(
        a.wait(T, |r| r.has_receipt(&intro_id, 1)),
        "de-duplicated intro got no delivered receipt",
    )?;
    deliver(&a, &b, "first message after accept")?;
    check(
        b.snapshot(|r| r.texts_from(&a.card.ik).iter().all(|t| t != intro)),
        "the intro was delivered twice",
    )?;

    // Bob blocks Carol before she knocks: nothing from her ever surfaces.
    b.client
        .set_peer_blocked(c.card.ik.clone(), true)
        .map_err(|e| e.to_string())?;
    c.pin(&b.card)?;
    c.start(T)?;
    c.ask(&b.card)?;
    let _ = c
        .client
        .set_intro(b.card.ik.clone(), "let me in".to_string());
    std::thread::sleep(Duration::from_secs(5));
    check(
        b.snapshot(|r| r.requests_from(&c.card.ik).is_empty()),
        "blocked carol's request surfaced",
    )?;
    check(
        !c.client.has_session(b.card.ik.clone()),
        "blocked carol got a circuit",
    )
}

/// E6: block stops flooding — the circuit goes, sends fail, knocks are dropped.
fn e6_block_stops_flooding(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    deliver(&a, &b, "before block")?;
    b.client
        .set_peer_blocked(a.card.ik.clone(), true)
        .map_err(|e| e.to_string())?;
    check(
        wait_until(T, || !a.client.has_session(b.card.ik.clone())),
        "alice still has a live circuit after bob blocked her",
    )?;
    let before = b.snapshot(|r| r.texts_from(&a.card.ik).len());
    let acks_before = a.snapshot(|r| r.acks.len());
    // Spec E6: "A's further sends fail at the relay (`CircuitNotFound`) and
    // never reach B's queue." The v2 core refuses to put a frame on a torn-
    // down circuit (RF3), so the client-visible failure is local; the relay
    // half — a relay packet on the torn-down circuit gets `CircuitNotFound`
    // and B's queue stays empty — is asserted in the relay test
    // `a8_member_close_tears_down_the_whole_pair` (Task 7). Here we assert
    // the end-to-end consequence: the send fails, and the relay never
    // acknowledges (so never queued) anything from alice after the block.
    let sent = a.send(&b.card, "after block");
    check(sent.is_err(), "a send succeeded after the block")?;
    // Alice's core re-asks (she still pins bob): only knocks, which bob drops.
    std::thread::sleep(Duration::from_secs(5));
    check(
        a.snapshot(|r| r.acks.len()) == acks_before,
        "the relay acknowledged (queued) a message from blocked alice",
    )?;
    check(
        b.snapshot(|r| r.requests_from(&a.card.ik).is_empty()),
        "blocked alice's knock surfaced",
    )?;
    // Nothing was queued for bob either: reconnecting delivers nothing.
    reconnect_transport(&b, &a.card).ok();
    std::thread::sleep(Duration::from_secs(3));
    check(
        b.snapshot(|r| r.texts_from(&a.card.ik).len()) == before,
        "a message from blocked alice reached bob",
    )
}
