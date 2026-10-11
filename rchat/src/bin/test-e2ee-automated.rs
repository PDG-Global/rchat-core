//! Protocol-v2 scenario client for the end-to-end scripts (spec §12.3).
//!
//! One process = one account. Pins peers from contact cards, asks for
//! circuits, and checks one scenario. Exit status 0 only when the
//! scenario's assertions hold; results are printed as `RESULT key=value`.
//!
//! `--mode script --steps "a;b;…"` replays an app's call order step by step
//! (spec §18.10 E10–E16): with `--state-dir` a process can be killed and
//! restarted with its sessions, and `--device-key-seed` gives it a software
//! device key (and a v2 card).

#[path = "support/harness.rs"]
pub mod harness;

use clap::{Parser, ValueEnum};
use harness::{result, Card, Peer, Recorded};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Pin the cards, ask, exchange messages, expect delivered receipts.
    Chat,
    /// Requester: pin the first card, ask with an intro, then talk once accepted.
    Request,
    /// Recipient of a request: wait for it, accept it, then talk.
    Accept,
    /// Block every card; expect nothing at all from them.
    Block,
    /// After the circuit forms, wait for the peer to go offline, then send.
    OfflineSend,
    /// Connect and publish; expect no messages and no requests.
    ExpectNone,
    /// Run the `--steps` list (see `script`).
    Script,
}

#[derive(Parser, Debug)]
#[command(name = "test-e2ee-automated", about = "Protocol v2 scenario client")]
struct Args {
    #[arg(long)]
    name: String,
    #[arg(long)]
    identity_seed: String,
    #[arg(long, default_value = "ws://127.0.0.1:18443")]
    server: String,
    /// `dev_origin` of a --no-tls relay (default: derived from --server).
    #[arg(long)]
    origin: Option<String>,
    /// Contact card JSON {"n":..,"ik":..,"ak":..} (v1) or
    /// {"v":2,"n":..,"ik":..,"ak":..,"dk":..,"dkh":..,"dks":..} (v2); repeatable.
    #[arg(long = "peer-card")]
    peer_cards: Vec<String>,
    /// Print this account's card (v2 with --device-key-seed) and exit.
    #[arg(long)]
    print_card: bool,
    /// Keep sealed session records here (created if missing); the records
    /// in it are imported before the first connect.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Sign session notices with a software P-256 device key from this seed.
    #[arg(long)]
    device_key_seed: Option<String>,
    /// Script mode: steps separated by ';' (see `script`).
    #[arg(long, default_value = "")]
    steps: String,
    #[arg(long, value_enum, default_value = "chat")]
    mode: Mode,
    #[arg(long, default_value_t = 3)]
    send: usize,
    #[arg(long, default_value_t = 3)]
    expect: usize,
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
    /// Chat: go offline this many seconds after the circuit forms.
    #[arg(long, default_value_t = 0)]
    offline_secs: u64,
    /// Chat: success means the circuit never forms and nothing arrives.
    #[arg(long)]
    expect_refusal: bool,
}

/// Wait before disconnecting so our last delivered receipts leave: the
/// core holds one 0.5-3 s (spec §5.6, ticker 250 ms) before sending it, so
/// wait past the longest delay. A shorter wait (request/accept used 2 s)
/// dropped them whenever our delay beat the peer's by more than that.
const RECEIPT_DRAIN: Duration = Duration::from_millis(3_750);

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();
    let args = Args::parse();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("[{}] error: {e}", args.name);
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<bool, String> {
    let me = Peer::new(
        &args.name,
        &args.server,
        args.origin.as_deref(),
        &args.identity_seed,
        args.state_dir.clone(),
        args.device_key_seed.clone(),
    )?;
    if args.print_card {
        println!("{}", me.card.to_json());
        return Ok(true);
    }
    let cards = args
        .peer_cards
        .iter()
        .map(String::as_str)
        .map(Card::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let timeout = Duration::from_secs(args.timeout_secs);
    if args.mode == Mode::Script {
        return script(&me, &cards, &args.steps);
    }
    // E15: pin before start, as the app does: a session record restored at
    // connect, or a packet queued for us, then finds its peer pinned.
    match args.mode {
        Mode::Chat => cards.iter().try_for_each(|c| me.pin(c))?,
        Mode::Request | Mode::OfflineSend => me.pin(first(&cards)?)?,
        _ => {}
    }
    if args.mode == Mode::Block {
        // Block before connecting: a knock already queued for us is
        // delivered as `QueuedMessage` right after publish, so blocking
        // after `start` would race it into a request. While disconnected,
        // `set_peer_blocked` only updates the core's peer book.
        for c in &cards {
            me.client
                .set_peer_blocked(c.ik.clone(), true)
                .map_err(|e| e.to_string())?;
        }
    }
    me.start(Duration::from_secs(15))?;
    match args.mode {
        Mode::Chat => chat(&me, &cards, args, timeout),
        Mode::Request => request(&me, &cards, args, timeout),
        Mode::Accept => accept(&me, &cards, args, timeout),
        Mode::Block => block(&me, &cards, timeout),
        Mode::OfflineSend => offline_send(&me, &cards, args, timeout),
        Mode::ExpectNone => expect_none(&me, timeout),
        Mode::Script => unreachable!("handled above"),
    }
}

fn first(cards: &[Card]) -> Result<&Card, String> {
    cards
        .first()
        .ok_or_else(|| "this mode needs --peer-card".to_string())
}

fn send_n(me: &Peer, peer: &Card, n: usize) -> Result<Vec<String>, String> {
    (1..=n)
        .map(|i| me.send(peer, &format!("msg-{i} from {}", me.name)))
        .collect()
}

fn chat(me: &Peer, cards: &[Card], args: &Args, timeout: Duration) -> Result<bool, String> {
    let peer = first(cards)?;
    // Pinned before start (`run`).
    for c in cards {
        me.ask(c)?;
    }
    let established = harness::wait_until(timeout, || me.client.has_session(peer.ik.clone()));
    result("established", established);
    result(
        "key_event_3",
        me.snapshot(|r| r.key_events_for(&peer.ik, 3)),
    );
    if args.expect_refusal {
        let received = me.snapshot(|r| r.texts_from(&peer.ik).len());
        result("received", received);
        return Ok(!established && received == 0);
    }
    if !established {
        return Ok(false);
    }
    if args.offline_secs > 0 {
        me.client
            .disconnect_transport_only()
            .map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_secs(args.offline_secs));
        me.start(Duration::from_secs(15))?;
        // No explicit ask here: after publish-ok the core sends its own
        // resume ask (Task 14 `after_publish_ok`). A second, resume-less ask
        // racing the relay's `CircuitExists` would make the relay tear the
        // pair down (spec §6.2 step 2). Wait for the resumed session instead.
        if !harness::wait_until(timeout, || me.client.has_session(peer.ik.clone())) {
            result("resumed", false);
            return Ok(false);
        }
    }
    let ids = send_n(me, peer, args.send)?;
    result("sent", ids.len());
    let got = me.wait(timeout, |r| r.texts_from(&peer.ik).len() >= args.expect);
    let received = me.snapshot(|r| r.texts_from(&peer.ik).len());
    result("received", received);
    let receipts_ok = me.wait(timeout, |r| ids.iter().all(|id| r.has_receipt(id, 1)));
    let delivered = me.snapshot(|r| ids.iter().filter(|id| r.has_receipt(id, 1)).count());
    result("receipts_delivered", delivered);
    // Tell the peer we read what it sent (kind 2).
    let incoming: Vec<String> = me.snapshot(|r| {
        r.messages
            .iter()
            .filter(|m| m.sender_identity == peer.ik)
            .map(|m| m.id.clone())
            .collect()
    });
    if !incoming.is_empty() {
        me.client
            .send_read_receipt(peer.ik.clone(), incoming)
            .map_err(|e| e.to_string())?;
    }
    std::thread::sleep(RECEIPT_DRAIN);
    let _ = me.client.disconnect();
    Ok(got && receipts_ok)
}

fn request(me: &Peer, cards: &[Card], args: &Args, timeout: Duration) -> Result<bool, String> {
    let peer = first(cards)?;
    // Pinned before start (`run`).
    me.ask(peer)?;
    let intro_text = format!("intro from {}", me.name);
    let intro_id = me
        .client
        .set_intro(peer.ik.clone(), intro_text.clone())
        .map_err(|e| e.to_string())?;
    let established = harness::wait_until(timeout, || me.client.has_session(peer.ik.clone()));
    result("established", established);
    if !established {
        return Ok(false);
    }
    // The intro becomes the first real message, under the intro's id, so the
    // recipient (who already has it) de-duplicates it.
    me.client
        .send_text_message_using_id(peer.ik.clone(), intro_text, intro_id.clone())
        .map_err(|e| e.to_string())?;
    let mut ids = vec![intro_id];
    ids.extend(send_n(me, peer, args.send)?);
    result("sent", ids.len());
    let got = me.wait(timeout, |r| r.texts_from(&peer.ik).len() >= args.expect);
    result("received", me.snapshot(|r| r.texts_from(&peer.ik).len()));
    let receipts_ok = me.wait(timeout, |r| ids.iter().all(|id| r.has_receipt(id, 1)));
    result(
        "receipts_delivered",
        me.snapshot(|r| ids.iter().filter(|id| r.has_receipt(id, 1)).count()),
    );
    std::thread::sleep(RECEIPT_DRAIN);
    let _ = me.client.disconnect();
    Ok(got && receipts_ok)
}

fn accept(me: &Peer, cards: &[Card], args: &Args, timeout: Duration) -> Result<bool, String> {
    // The card names who we expect to hear from; it is NOT pinned up front.
    let peer = first(cards)?;
    let has_intro = |r: &harness::Recorded| {
        r.requests_from(&peer.ik)
            .iter()
            .any(|q| !q.intro_text.is_empty())
    };
    if !me.wait(timeout, has_intro) {
        result("requests", me.snapshot(|r| r.requests_from(&peer.ik).len()));
        return Ok(false);
    }
    let req = me.snapshot(|r| {
        r.requests_from(&peer.ik)
            .into_iter()
            .find(|q| !q.intro_text.is_empty())
            .expect("checked above")
    });
    result("intro_received", 1);
    me.client
        .pin_peer_key(req.identity_hex.clone(), req.agreement_hex.clone())
        .map_err(|e| e.to_string())?;
    me.client
        .mark_message_seen(req.identity_hex.clone(), req.intro_message_id_hex.clone())
        .map_err(|e| e.to_string())?;
    me.ask(peer)?;
    let established = harness::wait_until(timeout, || me.client.has_session(peer.ik.clone()));
    result("established", established);
    if !established {
        return Ok(false);
    }
    let got = me.wait(timeout, |r| r.texts_from(&peer.ik).len() >= args.expect);
    let texts = me.snapshot(|r| r.texts_from(&peer.ik));
    let duplicate = texts.iter().filter(|t| **t == req.intro_text).count();
    result("received", texts.len());
    result("duplicate", duplicate);
    let ids = send_n(me, peer, args.send)?;
    let receipts_ok = me.wait(timeout, |r| ids.iter().all(|id| r.has_receipt(id, 1)));
    std::thread::sleep(RECEIPT_DRAIN);
    let _ = me.client.disconnect();
    Ok(got && duplicate == 0 && receipts_ok)
}

fn block(me: &Peer, cards: &[Card], timeout: Duration) -> Result<bool, String> {
    // The blocks were applied in `run()` before `start`.
    std::thread::sleep(timeout);
    let (requests, messages) = me.snapshot(|r| {
        let req = cards
            .iter()
            .map(|c| r.requests_from(&c.ik).len())
            .sum::<usize>();
        let msg = cards
            .iter()
            .map(|c| r.texts_from(&c.ik).len())
            .sum::<usize>();
        (req, msg)
    });
    result("requests", requests);
    result("received", messages);
    let _ = me.client.disconnect();
    Ok(requests == 0 && messages == 0)
}

fn offline_send(me: &Peer, cards: &[Card], args: &Args, timeout: Duration) -> Result<bool, String> {
    let peer = first(cards)?;
    // Pinned before start (`run`).
    me.ask(peer)?;
    let established = harness::wait_until(timeout, || me.client.has_session(peer.ik.clone()));
    result("established", established);
    if !established {
        return Ok(false);
    }
    // The peer runs `chat --offline-secs N` with N > this pause, so it is
    // offline when these leave: the relay queues them under the recipient.
    std::thread::sleep(Duration::from_secs(args.offline_secs.max(2)));
    let ids = send_n(me, peer, args.send)?;
    let acked = me.wait(timeout, |r| ids.iter().all(|id| r.acks.contains(id)));
    result(
        "acked",
        me.snapshot(|r| ids.iter().filter(|id| r.acks.contains(id)).count()),
    );
    let receipts_ok = me.wait(timeout, |r| ids.iter().all(|id| r.has_receipt(id, 1)));
    result(
        "receipts_delivered",
        me.snapshot(|r| ids.iter().filter(|id| r.has_receipt(id, 1)).count()),
    );
    let _ = me.client.disconnect();
    Ok(acked && receipts_ok)
}

fn expect_none(me: &Peer, timeout: Duration) -> Result<bool, String> {
    std::thread::sleep(timeout);
    let (messages, requests) = me.snapshot(|r| (r.messages.len(), r.requests.len()));
    result("received", messages);
    result("requests", requests);
    let _ = me.client.disconnect();
    Ok(messages == 0 && requests == 0)
}

/// `--steps`: an app's call order, one step at a time, for the first card.
/// Each step prints `STEP <step>`. A step that errors, or an `expect*` or
/// `wait*` that times out, prints the report and exits 1. A run that
/// completes waits `RECEIPT_DRAIN`, then re-checks every count it asserted
/// (the latest assertion of each quantity), that no key event arrived if
/// `nokeyevents` was asserted, and that no error was recorded: a late
/// duplicate or a late event fails the run too. Then it disconnects.
///
/// - `pin` (every card, with its device key), `start` (connect + publish),
///   `ask` (`request_circuit`), `setrcpt` (`set_recipient(ik, Some(ak))`)
/// - `send <text>`
/// - `discon` (`disconnect_transport_only`), `reconnect` (connect + publish
///   on the kept client: the I-1 path, so nothing is re-imported),
///   `kill` (exit 0 with no disconnect: the app killed), `fulldiscon`
///   (the app's full disconnect: store detached, circuits closed, exit 0)
/// - `sleep <secs>`, `waitsession <secs>`, `waitfile <path> <secs>` (until
///   the script signals by creating the file)
/// - `expect <n> <secs>`: until n texts received (more fails: a duplicate)
/// - `expectorder <t1,t2,..>`: the texts received so far start with these,
///   in this order
/// - `expectevent <kind> <n> <secs>`: until n events of that kind (spec
///   §18.9 codes; more fails); n = 0: none may arrive within the window
/// - `expectundelivered <reason> <n> <resent> <secs>`: in one window, until
///   n `PeerUndelivered`, every one with that reason and for an id we sent,
///   and `resent` `ResendEligible`, every one for one of those ids
/// - `expectreceipts <n> <secs>`: until n of our messages have a delivered
///   receipt
/// - `expectacks <n> <secs>`: until n of our messages have the relay's ack;
///   an ack for an id we never sent (another spelling) fails
/// - `nokeyevents`: no key event (held to the end)
/// - `report`: `RESULT received=[..] receipts_delivered=N ... events=k:n,..`
fn script(me: &Peer, cards: &[Card], steps: &str) -> Result<bool, String> {
    let peer = first(cards)?;
    let mut held = Held::default();
    for step in steps.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        println!("STEP {step}");
        let ok = run_step(me, cards, peer, step, &mut held).unwrap_or_else(|e| {
            println!("STEP {step} error: {e}");
            false
        });
        if !ok {
            println!("STEP {step} FAILED");
            report(me, peer);
            return Ok(false);
        }
    }
    // Our last delivered receipts (and a notice) leave before we go: one
    // re-scheduled by a reconnect is still in its 0.5-3 s window. Anything
    // late (a duplicate, a second event) has arrived by now too.
    std::thread::sleep(RECEIPT_DRAIN);
    let broken = me.snapshot(|r| held.broken(r));
    let _ = me.client.disconnect();
    if !broken.is_empty() {
        println!("STEP final re-check FAILED: {}", broken.join("; "));
        report(me, peer);
        return Ok(false);
    }
    Ok(true)
}

/// A count that must still hold at the end of the run.
type Count = Box<dyn Fn(&Recorded) -> usize>;

/// The counts a run asserted, by quantity: a later assertion of the same
/// quantity (`expect 2`, then `expect 4`) replaces the earlier one.
#[derive(Default)]
struct Held(Vec<(String, usize, Count)>);

impl Held {
    fn hold(&mut self, what: String, want: usize, count: Count) {
        self.0.retain(|(w, _, _)| *w != what);
        self.0.push((what, want, count));
    }

    /// Every held count that changed, and any recorded error.
    fn broken(&self, r: &Recorded) -> Vec<String> {
        let mut out: Vec<String> = self
            .0
            .iter()
            .filter_map(|(what, want, count)| {
                let got = count(r);
                (got != *want).then(|| format!("{what}: {got}, asserted {want}"))
            })
            .collect();
        out.extend(r.errors.iter().map(|e| format!("error: {e}")));
        out
    }
}

/// `n` was reached within the window, and is held to the end.
fn hold_count(me: &Peer, held: &mut Held, what: String, n: usize, secs: f64, count: Count) -> bool {
    let ok = wait_count(me, n, secs, &count);
    held.hold(what, n, count);
    ok
}

fn run_step(
    me: &Peer,
    cards: &[Card],
    peer: &Card,
    step: &str,
    held: &mut Held,
) -> Result<bool, String> {
    let (op, arg) = step.split_once(' ').unwrap_or((step, ""));
    let mut args = arg.split_whitespace();
    let mut num = |what: &str| -> Result<f64, String> {
        args.next()
            .and_then(|a| a.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or_else(|| format!("{op}: missing or bad {what}"))
    };
    let start_wait = Duration::from_secs(15);
    let ik = peer.ik.clone();
    match op {
        "pin" => cards.iter().try_for_each(|c| me.pin(c)).map(|_| true),
        "start" | "reconnect" => me.start(start_wait).map(|_| true),
        "ask" => me.ask(peer).map(|_| true),
        "setrcpt" => me
            .client
            .set_recipient(peer.ik.clone(), Some(peer.ak.clone()))
            .map(|_| true)
            .map_err(|e| e.to_string()),
        "send" => me.send(peer, arg).map(|_| true),
        "discon" => me
            .client
            .disconnect_transport_only()
            .map(|_| true)
            .map_err(|e| e.to_string()),
        "kill" => std::process::exit(0),
        // The app's full disconnect (`rchat_disconnect`, e.g. Settings →
        // Save & Reconnect): the store is detached first (the FFI's
        // disconnect generation refuses its later writes), then the client
        // disconnects (closing its circuits); the process then exits, and
        // the script starts it again from its state dir (the app's
        // initialize + import + connect).
        "fulldiscon" => {
            me.client.detach_state_store();
            let _ = me.client.disconnect();
            std::process::exit(0)
        }
        "sleep" => {
            std::thread::sleep(Duration::from_secs_f64(num("seconds")?));
            Ok(true)
        }
        "waitsession" => {
            let t = Duration::from_secs_f64(num("seconds")?);
            Ok(harness::wait_until(t, || {
                me.client.has_session(peer.ik.clone())
            }))
        }
        "waitfile" => {
            let (path, secs) = arg
                .rsplit_once(' ')
                .and_then(|(p, t)| Some((p, t.parse::<f64>().ok()?)))
                .filter(|(_, t)| t.is_finite() && *t >= 0.0)
                .ok_or_else(|| "waitfile: <path> <seconds>".to_string())?;
            let t = Duration::from_secs_f64(secs);
            Ok(harness::wait_until(t, || {
                std::path::Path::new(path).exists()
            }))
        }
        "expect" => {
            let (n, t) = (num("count")? as usize, num("seconds")?);
            let count: Count = Box::new(move |r| r.texts_from(&ik).len());
            Ok(hold_count(me, held, "texts".into(), n, t, count))
        }
        "expectorder" => {
            let want: Vec<String> = arg
                .split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
            let out_of_order: Count =
                Box::new(move |r| usize::from(!r.texts_from(&ik).starts_with(&want)));
            let ok = me.snapshot(|r| out_of_order(r)) == 0;
            held.hold("texts out of order".into(), 0, out_of_order);
            Ok(ok)
        }
        "expectevent" => {
            let kind = num("kind")? as i32;
            let (n, t) = (num("count")? as usize, num("seconds")?);
            let count: Count = Box::new(move |r| r.events_of(kind));
            Ok(hold_count(me, held, format!("events {kind}"), n, t, count))
        }
        "expectundelivered" => {
            let reason = num("reason")? as u8;
            let (n, resent) = (num("count")? as usize, num("resent count")? as usize);
            let t = Duration::from_secs_f64(num("seconds")?);
            me.wait(t, |r| {
                r.undelivered().len() >= n && r.resend_eligible().len() >= resent
            });
            // Exactly n, all with this reason and for ids we sent; every
            // ResendEligible names one of those ids.
            let stray: Count = Box::new(move |r| {
                let und = r.undelivered();
                let bad = und
                    .iter()
                    .filter(|(why, id)| *why != reason || !r.sent.contains_key(id))
                    .count();
                let foreign = r
                    .resend_eligible()
                    .iter()
                    .filter(|id| !und.iter().any(|(_, u)| u == *id))
                    .count();
                bad + foreign
            });
            let ok = me.snapshot(|r| {
                r.undelivered().len() == n && r.resend_eligible().len() == resent && stray(r) == 0
            });
            held.hold("events 2".into(), n, Box::new(|r| r.events_of(2)));
            held.hold("events 10".into(), resent, Box::new(|r| r.events_of(10)));
            held.hold("stray undelivered or resend".into(), 0, stray);
            Ok(ok)
        }
        "expectreceipts" => {
            let (n, t) = (num("count")? as usize, num("seconds")?);
            let count: Count = Box::new(Recorded::delivered_sent);
            Ok(hold_count(me, held, "receipts".into(), n, t, count))
        }
        "expectacks" => {
            let (n, t) = (num("count")? as usize, num("seconds")?);
            let count: Count = Box::new(Recorded::acked_sent);
            let foreign: Count =
                Box::new(|r| r.acks.iter().filter(|a| !r.sent.contains_key(*a)).count());
            let ok = hold_count(me, held, "acks".into(), n, t, count);
            let clean = me.snapshot(|r| foreign(r)) == 0;
            held.hold("acks for ids we never sent".into(), 0, foreign);
            Ok(ok && clean)
        }
        "nokeyevents" => {
            let count: Count = Box::new(|r| r.key_events.len());
            let ok = me.snapshot(|r| count(r)) == 0;
            held.hold("key events".into(), 0, count);
            Ok(ok)
        }
        "report" => {
            report(me, peer);
            Ok(true)
        }
        other => Err(format!("unknown step {other:?}")),
    }
}

/// Wait until `count` reaches `n`, then hold it to exactly `n` (more is a
/// duplicate). `n = 0`: the count must stay 0 for the whole window.
fn wait_count(me: &Peer, n: usize, secs: f64, count: &Count) -> bool {
    let t = Duration::from_secs_f64(secs);
    if n == 0 {
        return !me.wait(t, |r| count(r) > 0);
    }
    me.wait(t, |r| count(r) >= n) && me.snapshot(|r| count(r)) == n
}

fn report(me: &Peer, peer: &Card) {
    let line = me.snapshot(|r| {
        let mut kinds: Vec<i32> = r.status.iter().map(|e| e.code()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        let events = kinds
            .iter()
            .map(|k| format!("{k}:{}", r.events_of(*k)))
            .collect::<Vec<_>>()
            .join(",");
        let reasons: Vec<u8> = r.undelivered().iter().map(|(why, _)| *why).collect();
        format!(
            "received={:?} sent={} receipts_delivered={} acked={} resent={} events={} undelivered_reasons={:?} key_events={} errors={:?}",
            r.texts_from(&peer.ik),
            r.sent_order.len(),
            r.delivered_sent(),
            r.acked_sent(),
            r.resent.len(),
            events,
            reasons,
            r.key_events.len(),
            r.errors,
        )
    });
    println!("RESULT {line}");
}

#[cfg(test)]
mod tests {
    use super::harness::{read_records, Card, CardDk, FileSink};
    use rchat_core::state_store::StateSink;

    fn key64(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn cards_v1_and_v2_round_trip_and_bad_ones_are_refused() {
        let v1 = format!(r#"{{"n":"A","ik":"{}","ak":"{}"}}"#, key64('A'), key64('b'));
        let c = Card::parse(&v1).unwrap();
        assert_eq!((c.ik.as_str(), c.dk.is_none()), (key64('a').as_str(), true));
        assert_eq!(Card::parse(&c.to_json()).unwrap(), c);
        assert!(!c.to_json().contains("\"v\""), "a v1 card stays v1");

        let dk = CardDk {
            dk: "04".to_string() + &"c".repeat(128),
            dkh: false,
            dks: "d".repeat(128),
        };
        let v2 = Card {
            dk: Some(dk.clone()),
            ..c.clone()
        };
        let json = v2.to_json();
        assert!(json.starts_with(r#"{"v":2,"n":"A""#), "{json}");
        assert_eq!(Card::parse(&json).unwrap(), v2);

        let partial = json.replace(r#","dkh":false"#, "");
        assert!(Card::parse(&partial).is_err(), "v2 without dkh");
        assert!(
            Card::parse(&json.replace(r#""v":2"#, r#""v":1"#)).is_err(),
            "v1 with a dk"
        );
        assert!(Card::parse(&json.replace(r#""v":2"#, r#""v":3"#)).is_err());
        assert!(Card::parse(&json.replace(&"d".repeat(128), &"d".repeat(126))).is_err());
    }

    #[test]
    fn file_sink_writes_replaces_deletes_and_reads_back() {
        // A fresh directory of our own (create_dir fails if it exists).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rchat-filesink-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let sink = FileSink(dir.clone());
        let key = "0123456789abcdef0123456789abcdef";
        sink.write(key, b"one").unwrap();
        sink.write(key, b"two").unwrap();
        sink.write("meta", b"m").unwrap();
        std::fs::write(dir.join("sent.jsonl"), b"[]\n").unwrap(); // not a record
        let mut got = read_records(&dir).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                (key.to_string(), b"two".to_vec()),
                ("meta".to_string(), b"m".to_vec())
            ]
        );
        sink.write(key, b"").unwrap();
        sink.write(key, b"").unwrap(); // deleting a missing record is fine
        assert_eq!(read_records(&dir).unwrap().len(), 1);
        assert!(sink.write("../escape", b"x").is_err(), "only record keys");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
