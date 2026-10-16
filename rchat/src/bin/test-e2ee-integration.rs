//! In-process protocol-v2 end-to-end scenarios (spec §12.3: E1, E2, E3, E4,
//! E6), and E7 (protocol v3 blind re-pair across reconnects). The binary owns the relay process so E2 can restart it.
//!
//! cargo run --bin test-e2ee-integration -- \
//!   --server-bin target/debug/rchat-server --config /tmp/x/server.toml \
//!   --server ws://127.0.0.1:18443/ --origin ws://127.0.0.1:18443 --scenario all

#[path = "support/harness.rs"]
pub mod harness;

use clap::Parser;
use harness::{wait_until, Peer};
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
    run("E7", &e7_blind_repair_delivers_once);
    run("E8", &e8_background_drain);
    run("E9", &e9_ffi_background_drain);
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

/// Transport down and up again in the same process (sessions kept): the
/// core's own `after_publish_ok` re-pairs a known contact with a blind ask
/// under the next token (protocol v3 §C.3). The harness never asks itself:
/// its ask would race the core's.
fn bounce_transport(p: &Peer) -> Result<(), String> {
    p.client
        .disconnect_transport_only()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(500));
    p.start(T)
}

/// Both hold a live session again.
fn wait_paired(a: &Peer, b: &Peer, what: &str) -> Result<(), String> {
    check(
        wait_until(T, || {
            a.client.has_session(b.card.ik.clone()) && b.client.has_session(a.card.ik.clone())
        }),
        what,
    )
}

/// None of the spec §18 recovery warnings (PeerSessionReset 3,
/// SessionReplaced 4, DecryptFailed 1, PeerUndelivered 2, ResendEligible
/// 10): a routine blind re-pair raises none of them.
fn no_recovery_warnings(p: &Peer) -> Result<(), String> {
    let raised: Vec<i32> = p.snapshot(|r| {
        [1, 2, 3, 4, 10]
            .into_iter()
            .filter(|k| r.events_of(*k) > 0)
            .collect()
    });
    check(
        raised.is_empty(),
        &format!("{} raised recovery warnings {raised:?}", p.name),
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

    // Messages both ways first: Bob's answer to Alice's session-init has
    // reached her, so she may close the first-contact circuit (she leaves
    // it to the relay's grace while Bob may still await her init there).
    deliver(&a, &b, "before reconnects a->b")?;
    deliver(&b, &a, "before reconnects b->a")?;
    // Protocol v3 §C.3: every transport reconnect re-pairs blind, so each
    // one makes a new circuit (a new CircuitCreatedV3), never a resume.
    // Alice alone first: she closes the first-contact identity circuit, Bob
    // is told and re-asks blind, and the pair re-forms at once.
    bounce_transport(&a)?;
    wait_paired(&a, &b, "no blind re-pair after alice's reconnect")?;
    deliver(&a, &b, "after initiator reconnect a->b")?;
    deliver(&b, &a, "after initiator reconnect b->a")?;
    // Bob alone, with a blinded circuit: Alice, who stayed, sends first. The
    // relay ends the stale blinded row at her packet (ruling R18), she
    // re-asks blind, and her message is re-sent on the new pair.
    bounce_transport(&b)?;
    deliver(&a, &b, "after responder reconnect a->b")?;
    deliver(&b, &a, "after responder reconnect b->a")?;
    bounce_transport(&a)?;
    bounce_transport(&b)?;
    wait_paired(&a, &b, "no blind re-pair after both reconnected")?;
    deliver(&a, &b, "after both reconnect")?;
    let (ca, cb) = (circuits(&a, &b), circuits(&b, &a));
    check(
        ca == 4 && cb == 4,
        &format!("each transport reconnect re-pairs once (1 + 3 circuits): {ca}, {cb}"),
    )?;
    no_recovery_warnings(&a)?;
    no_recovery_warnings(&b)?;

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
        wait_until(T, || circuits(&a, &b) == 5 && circuits(&b, &a) == 5),
        "no new circuit after relay restart",
    )?;
    deliver(&a, &b, "after relay restart")?;

    // App restart of alice: a new process has no session, so she asks on
    // the identity path and her knock reaches bob; bob's live blinded
    // circuit is one she no longer uses, so bob closes it and answers on
    // the identity path (Task 9), and a new pair forms. Counted per
    // identity: 5 so far + 1 now = 6.
    let _ = a.client.disconnect();
    drop(a);
    let a2 = peer_with_seed(args, "alice", &a_seed)?;
    a2.pin(&b.card)?;
    a2.start(T)?;
    a2.ask(&b.card)?;
    check(
        wait_until(T, || {
            circuits(&b, &a2) == 6 && a2.client.has_session(b.card.ik.clone())
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
        .pin_peer_key(
            req.identity_hex.clone(),
            req.agreement_hex.clone(),
            Some(req.kem_hex.clone()),
        )
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
    // Protocol v3 (R21): alice's core re-pairs blind after the close, and
    // a send meanwhile is parked on her session (Ok), not refused; it never
    // leaves her device while bob blocks her (no pair forms), as checked
    // below.
    let sent = a.send(&b.card, "after block");
    check(
        sent.is_ok(),
        &format!("the send after the block was not parked: {sent:?}"),
    )?;
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
    bounce_transport(&b).ok();
    std::thread::sleep(Duration::from_secs(3));
    check(
        b.snapshot(|r| r.texts_from(&a.card.ik).len()) == before,
        "a message from blocked alice reached bob",
    )
}

/// E7 (protocol v3 §C.3, Task 9): a message sent across a reconnect is
/// delivered exactly once while the pair re-pairs blind, with none of the
/// §18 recovery warnings: Bob's transport is down while Alice sends (the
/// relay queues it under Bob's blinded pair, R15); Bob comes back, gets it
/// once, and the pair re-pairs blind; then both reconnect once more.
fn e7_blind_repair_delivers_once(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    // Both reconnect: the first blind pair.
    bounce_transport(&a)?;
    bounce_transport(&b)?;
    wait_paired(&a, &b, "no blind pair after both reconnected")?;
    let before = a.snapshot(|r| r.circuits_with(&b.card.ik));

    b.client
        .disconnect_transport_only()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(500));
    a.send(&b.card, "across bob's reconnect")?;
    std::thread::sleep(Duration::from_millis(500));
    b.start(T)?;
    check(
        b.wait(T, |r| {
            r.texts_from(&a.card.ik)
                .iter()
                .any(|t| t == "across bob's reconnect")
        }),
        "bob never received the message sent across his reconnect",
    )?;
    deliver(&a, &b, "after bob's reconnect a->b")?;
    deliver(&b, &a, "after bob's reconnect b->a")?;

    // Both away and back: the pair re-pairs blind again.
    bounce_transport(&a)?;
    bounce_transport(&b)?;
    wait_paired(&a, &b, "no blind re-pair after both reconnected")?;
    deliver(&a, &b, "after both reconnects a->b")?;
    deliver(&b, &a, "after both reconnects b->a")?;
    std::thread::sleep(Duration::from_secs(2));
    for text in ["across bob's reconnect", "after bob's reconnect a->b"] {
        let copies = b.snapshot(|r| {
            r.texts_from(&a.card.ik)
                .iter()
                .filter(|t| *t == text)
                .count()
        });
        check(copies == 1, &format!("{text:?} arrived {copies} times"))?;
    }
    let after = a.snapshot(|r| r.circuits_with(&b.card.ik));
    check(after >= before + 2, "the reconnects re-paired")?;
    no_recovery_warnings(&a)?;
    no_recovery_warnings(&b)
}

/// E8 (protocol v3 §H.1): a background drain over a real relay. Bob goes
/// offline and Alice's message waits in the relay's queue; Bob's drain
/// connects, publishes, takes it and has it stored (the recorder marks it
/// seen) before returning. It forms no circuit (Alice sees none) and sends
/// no receipt; the receipt reaches Alice at Bob's next foreground connect.
fn e8_background_drain(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let b = peer(args, "bob")?;
    pair_up(&a, &b)?;
    b.client
        .disconnect_transport_only()
        .map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_secs(1));
    let text = "drained in the background";
    let id = a.send(&b.card, text)?;
    check(
        a.wait(T, |r| r.acks.contains(&id)),
        "relay did not acknowledge the queued message",
    )?;
    let circuits_before = a.snapshot(|r| r.circuits_with(&b.card.ik));
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let n = b
        .client
        .background_drain(Duration::from_secs(20), &cancel)
        .map_err(|e| format!("drain: {e}"))?;
    check(n == 1, &format!("drain handed over {n} items, not 1"))?;
    check(
        b.snapshot(|r| r.texts_from(&a.card.ik).iter().any(|t| t == text)),
        "the message was not stored before the drain returned",
    )?;
    check(
        !b.client.is_key_bundle_published(),
        "the drain left its connection up",
    )?;
    std::thread::sleep(Duration::from_secs(4));
    check(
        a.snapshot(|r| r.circuits_with(&b.card.ik)) == circuits_before,
        "a background drain formed a circuit",
    )?;
    check(
        !a.snapshot(|r| r.has_receipt(&id, 1)),
        "a background drain sent a receipt",
    )?;
    // The next foreground connection re-pairs and delivers the receipt.
    b.start(T)?;
    check(
        a.wait(T, |r| r.has_receipt(&id, 1)),
        "the receipt never reached Alice after the foreground connect",
    )
}

// --- E9: the C FFI drain (R34 M-8) -----------------------------------------

use rchat_core::ffi as cffi;
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::Mutex;

/// What the FFI callbacks saw: message ids stored, requests.
static E9_SEEN: Mutex<(Vec<String>, usize)> = Mutex::new((Vec::new(), 0));

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

extern "C" fn e9_message(
    sender: *const c_char,
    _t: *const c_char,
    _ts: u64,
    id: *const c_char,
    _k: c_int,
    _e: u32,
) {
    let (sender_c, id_c) = (
        CString::new(cstr(sender)).unwrap(),
        CString::new(cstr(id)).unwrap(),
    );
    // "Stored": confirmed to the core, as the app does (D36).
    unsafe { cffi::rchat_mark_message_seen(sender_c.as_ptr(), id_c.as_ptr()) };
    E9_SEEN.lock().unwrap().0.push(cstr(id));
}
extern "C" fn e9_state(_: c_int) {}
extern "C" fn e9_error(_: *const c_char) {}
extern "C" fn e9_circuit(_: *const c_char, _: c_int) {}
extern "C" fn e9_delivered(_: *const c_char) {}
extern "C" fn e9_reconnect() {}
extern "C" fn e9_key(_: *const c_char, _: c_int, _: *const c_char) {}
#[allow(clippy::too_many_arguments)]
extern "C" fn e9_request(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: u64,
    _: *const c_char,
    _: *const c_char,
    _: u64,
    _: u32,
) {
    E9_SEEN.lock().unwrap().1 += 1;
}
extern "C" fn e9_receipt(_: *const c_char, _: *const c_char, _: c_int) {}
extern "C" fn e9_rotated(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: u32,
) {
}
extern "C" fn e9_status(_: c_int, _: *const c_char, _: *const c_char, _: c_int) {}
#[allow(clippy::too_many_arguments)]
extern "C" fn e9_file(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: u32,
    _: *const u8,
    _: usize,
    _: u64,
) {
}
extern "C" fn e9_timer(_: *const c_char, _: u32, _: u64, _: c_int) {}

/// E9 (protocol v3 §H.1, R34 M-8): `rchat_background_drain` itself, against
/// the real relay. Bob has never connected; Alice asks him (a one-sided
/// ask, so the relay queues her knock). Bob's first drain builds, installs
/// and connects a new client, hands the request over and returns 1, ended
/// by the relay's marker. A second drain reuses the kept client and ends at
/// the marker at once (0 items), well before the no-marker fallback.
fn e9_ffi_background_drain(args: &Args, _relay: &mut Relay) -> Result<(), String> {
    let a = peer(args, "alice")?;
    let bob_seed_text = seed("bob-ffi");
    let bob_card = peer_with_seed(args, "bob", &bob_seed_text)?.card;
    a.pin(&bob_card)?;
    a.start(T)?;
    a.ask(&bob_card)?;
    std::thread::sleep(Duration::from_millis(500));
    check(cffi::rchat_initialize() == 0, "rchat_initialize")?;
    let registered = cffi::rchat_register_callbacks(
        Some(e9_message),
        Some(e9_state),
        Some(e9_error),
        Some(e9_circuit),
        Some(e9_delivered),
        Some(e9_reconnect),
        Some(e9_key),
        Some(e9_request),
        Some(e9_receipt),
        Some(e9_rotated),
        Some(e9_status),
        Some(e9_file),
        Some(e9_timer),
    );
    check(registered == 0, "rchat_register_callbacks")?;
    let config = CString::new(format!(
        r#"{{"server_url":"{}","dev_origin":"{}","connection_timeout_secs":10,
        "reconnect_max_attempts":1,"message_retry_count":0,
        "enable_delivery_confirmation":true,"keepalive_interval_secs":30,"tls_fingerprint":"None"}}"#,
        harness::ws_url(&args.server),
        args.origin
    ))
    .unwrap();
    let seed_bytes = harness::derive_seed(&bob_seed_text);
    let started = std::time::Instant::now();
    let n = unsafe {
        cffi::rchat_background_drain(
            config.as_ptr(),
            seed_bytes.as_ptr(),
            seed_bytes.len(),
            20_000,
        )
    };
    check(
        n == 1,
        &format!("the first drain returned {n}, not 1 (the request)"),
    )?;
    check(
        E9_SEEN.lock().unwrap().1 == 1,
        "the request reached the callbacks",
    )?;
    check(
        started.elapsed() < Duration::from_secs(6),
        &format!(
            "ended by the marker, not the fallback: {:?}",
            started.elapsed()
        ),
    )?;
    let again = std::time::Instant::now();
    let n2 = unsafe {
        cffi::rchat_background_drain(
            config.as_ptr(),
            seed_bytes.as_ptr(),
            seed_bytes.len(),
            20_000,
        )
    };
    check(n2 == 0, &format!("the second drain returned {n2}"))?;
    check(
        again.elapsed() < Duration::from_secs(4),
        &format!(
            "the kept client's drain ended at the marker: {:?}",
            again.elapsed()
        ),
    )?;
    // The lock is free: a foreground connect goes ahead at once.
    let connected = unsafe {
        cffi::rchat_connect_with_seed(config.as_ptr(), seed_bytes.as_ptr(), seed_bytes.len())
    };
    check(
        connected == 0,
        &format!("foreground connect after the drains: {connected}"),
    )?;
    cffi::rchat_disconnect();
    Ok(())
}
