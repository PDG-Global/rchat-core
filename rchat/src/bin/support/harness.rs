//! Shared protocol-v2 test peer for the end-to-end binaries.
//!
//! Included by each test binary with
//! `#[path = "support/harness.rs"] pub mod harness;` — it is not a binary
//! itself. Each binary uses a different subset; declaring the module `pub`
//! at the binary's crate root makes its `pub` items reachable, so the
//! `dead_code` lint does not fire for the helpers a given binary leaves
//! unused (no `allow` needed — Global Constraints).
//! Nothing here prints key material: cards carry public keys only, and
//! message text is test text.
//!
//! Persistence goes through the same `StateSink` contract the app uses
//! (spec §18.3, §18.4): `FileSink` writes each sealed record before the
//! core sends or delivers anything, and the records on disk are imported
//! before the first connect (`Peer::new`).

use rchat_core::device_key::DeviceSigner;
use rchat_core::state_store::{is_valid_record_key, StateSink};
use rchat_core::status::StatusEvent;
use rchat_core::{
    ClientConfig, ConnectionStatus, MessageRequest, RChatCallbacks, RChatClient, ReceivedMessage,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// A card's device key (v2 cards, spec §18.14 D43): the 65-byte SEC1 key
/// (130 hex), whether it is hardware-bound, and the identity's binding of
/// it (128 hex). Public values only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardDk {
    pub dk: String,
    pub dkh: bool,
    pub dks: String,
}

/// A contact card, the same JSON the iOS app shows as a QR code: v1
/// `{"n","ik","ak"}`, or v2 `{"v":2,"n","ik","ak","dk","dkh","dks"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub name: String,
    pub ik: String,
    pub ak: String,
    pub dk: Option<CardDk>,
}

/// The card's JSON, field for field.
#[derive(Serialize, Deserialize)]
struct CardJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v: Option<u32>,
    n: String,
    ik: String,
    ak: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dkh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dks: Option<String>,
}

fn is_hex(k: &str, len: usize) -> bool {
    k.len() == len && k.bytes().all(|b| b.is_ascii_hexdigit())
}

impl CardDk {
    fn checked(dk: String, dkh: bool, dks: String) -> Result<CardDk, String> {
        if !is_hex(&dk, 130) || !is_hex(&dks, 128) {
            return Err("dk must be 130 and dks 128 hex characters".to_string());
        }
        Ok(CardDk {
            dk: dk.to_lowercase(),
            dkh,
            dks: dks.to_lowercase(),
        })
    }
}

impl Card {
    pub fn parse(s: &str) -> Result<Card, String> {
        let c: CardJson = serde_json::from_str(s).map_err(|e| format!("bad card: {e}"))?;
        if !is_hex(&c.ik, 64) || !is_hex(&c.ak, 64) {
            return Err("card keys must be 64 hex characters".to_string());
        }
        let dk = match (c.v.unwrap_or(1), c.dk, c.dkh, c.dks) {
            (1, None, None, None) => None,
            (2, Some(dk), Some(dkh), Some(dks)) => Some(CardDk::checked(dk, dkh, dks)?),
            (1 | 2, ..) => return Err("a v2 card needs dk, dkh and dks; v1 has none".to_string()),
            (v, ..) => return Err(format!("unknown card version {v}")),
        };
        Ok(Card {
            name: c.n,
            ik: c.ik.to_lowercase(),
            ak: c.ak.to_lowercase(),
            dk,
        })
    }

    pub fn to_json(&self) -> String {
        let d = self.dk.clone();
        let json = CardJson {
            v: d.as_ref().map(|_| 2),
            n: self.name.clone(),
            ik: self.ik.clone(),
            ak: self.ak.clone(),
            dkh: d.as_ref().map(|d| d.dkh),
            dk: d.as_ref().map(|d| d.dk.clone()),
            dks: d.map(|d| d.dks),
        };
        serde_json::to_string(&json).expect("a card always serialises")
    }
}

/// A `StateSink` writing `<dir>/<key>.rcs`: synchronous and durable before
/// it returns (temp file, fsync, rename, fsync of the directory), as the
/// contract requires. An empty record deletes the file.
pub struct FileSink(pub PathBuf);

impl StateSink for FileSink {
    fn write(&self, key: &str, sealed: &[u8]) -> Result<(), String> {
        if !is_valid_record_key(key) {
            return Err(format!("invalid record key {key:?}"));
        }
        let path = self.0.join(format!("{key}.rcs"));
        if sealed.is_empty() {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
                _ => {}
            }
        } else {
            let tmp = self.0.join(format!(".{key}.tmp"));
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut f, sealed).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        }
        // The rename (or unlink) itself is durable only once the directory is.
        std::fs::File::open(&self.0)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("state dir sync: {e}"))
    }
}

/// Every `<key>.rcs` record in `dir`, for `import_state_records`.
pub fn read_records(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("state dir: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let key = match (path.file_stem(), path.extension()) {
            (Some(stem), Some(ext)) if ext == "rcs" => stem.to_string_lossy().into_owned(),
            _ => continue,
        };
        out.push((key, std::fs::read(&path).map_err(|e| e.to_string())?));
    }
    Ok(out)
}

/// A software P-256 device key (test only; the app's lives in the Secure
/// Enclave), derived from a seed text.
pub fn soft_device_key(seed: &str) -> Result<p256::ecdsa::SigningKey, String> {
    p256::ecdsa::SigningKey::from_slice(&blake3::derive_key("rchat-test-dk", seed.as_bytes()))
        .map_err(|e| format!("device key seed: {e}"))
}

/// Signs our session notices with the software device key (D45).
pub struct SoftSigner(pub p256::ecdsa::SigningKey);

impl DeviceSigner for SoftSigner {
    fn sign(&self, msg: &[u8]) -> Option<[u8; 64]> {
        use p256::ecdsa::signature::Signer;
        let s: p256::ecdsa::Signature = self.0.sign(msg);
        Some(s.to_bytes().into())
    }
}

/// Everything the core reported through its callbacks.
#[derive(Debug, Default)]
pub struct Recorded {
    pub connection: Option<ConnectionStatus>,
    /// Delivery and recovery events (spec §18.9), in arrival order.
    pub status: Vec<StatusEvent>,
    /// What we sent: message id -> text, the log a `ResendEligible` is
    /// answered from (same id, same text).
    pub sent: HashMap<String, String>,
    /// Ids we sent, in order.
    pub sent_order: Vec<String>,
    /// Ids resent automatically on `ResendEligible`.
    pub resent: Vec<String>,
    pub messages: Vec<ReceivedMessage>,
    /// Relay `MessageAck`s (message ids).
    pub acks: Vec<String>,
    /// In-band receipts: (message id, 1 delivered | 2 read).
    pub receipts: Vec<(String, u8)>,
    pub requests: Vec<MessageRequest>,
    /// (peer identity, we are the initiator).
    pub circuits: Vec<(String, bool)>,
    /// (peer identity, 2 mismatch | 3 bad signature, offered agreement key).
    pub key_events: Vec<(String, u8, String)>,
    pub errors: Vec<String>,
}

impl Recorded {
    pub fn texts_from(&self, ik: &str) -> Vec<String> {
        self.messages
            .iter()
            .filter(|m| m.sender_identity == ik && m.is_text)
            .map(|m| String::from_utf8_lossy(&m.content).into_owned())
            .collect()
    }

    pub fn circuits_with(&self, ik: &str) -> usize {
        self.circuits.iter().filter(|(p, _)| p == ik).count()
    }

    pub fn has_receipt(&self, id: &str, kind: u8) -> bool {
        self.receipts.iter().any(|(i, k)| i == id && *k == kind)
    }

    pub fn requests_from(&self, ik: &str) -> Vec<MessageRequest> {
        self.requests
            .iter()
            .filter(|r| r.identity_hex == ik)
            .cloned()
            .collect()
    }

    /// Events of one kind (`StatusEvent::code`, spec §18.9).
    pub fn events_of(&self, kind: i32) -> usize {
        self.status.iter().filter(|e| e.code() == kind).count()
    }

    /// `PeerUndelivered` events as (reason, message id), in arrival order.
    pub fn undelivered(&self) -> Vec<(u8, String)> {
        self.status
            .iter()
            .filter_map(|e| match e {
                StatusEvent::PeerUndelivered {
                    message_id, reason, ..
                } => Some((*reason, message_id.clone())),
                _ => None,
            })
            .collect()
    }

    /// Message ids of the `ResendEligible` events, in arrival order.
    pub fn resend_eligible(&self) -> Vec<String> {
        self.status
            .iter()
            .filter_map(|e| match e {
                StatusEvent::ResendEligible { message_id, .. } => Some(message_id.clone()),
                _ => None,
            })
            .collect()
    }

    /// Our sent messages with a delivered receipt.
    pub fn delivered_sent(&self) -> usize {
        self.sent_order
            .iter()
            .filter(|id| self.has_receipt(id, 1))
            .count()
    }

    /// Our sent messages the relay acknowledged (ids as we hold them:
    /// the lowercase hex the core returned from the send).
    pub fn acked_sent(&self) -> usize {
        self.sent_order
            .iter()
            .filter(|id| self.acks.contains(id))
            .count()
    }

    pub fn key_events_for(&self, ik: &str, code: u8) -> usize {
        self.key_events
            .iter()
            .filter(|(p, c, _)| p == ik && *c == code)
            .count()
    }
}

/// The recorded callbacks, and the client they came from: Weak, so the
/// callbacks never keep the client alive.
struct Recorder(Arc<Mutex<Recorded>>, Weak<RChatClient>);

impl RChatCallbacks for Recorder {
    fn on_connection_status_changed(&self, status: ConnectionStatus) {
        self.0.lock().unwrap().connection = Some(status);
    }
    fn on_message_received(&self, message: ReceivedMessage) {
        let (sender, id) = (message.sender_identity.clone(), message.id.clone());
        self.0.lock().unwrap().messages.push(message);
        // Recorded is "stored": tell the core, which queues the delivered
        // receipt only now (spec §18.7 D36). Callbacks may call back in.
        if let Some(client) = self.1.upgrade() {
            if let Err(e) = client.mark_message_seen(sender, id) {
                self.0
                    .lock()
                    .unwrap()
                    .errors
                    .push(format!("mark seen: {e}"));
            }
        }
    }
    fn on_message_delivered(&self, message_id: String) {
        self.0.lock().unwrap().acks.push(message_id);
    }
    fn on_error(&self, error: String) {
        self.0.lock().unwrap().errors.push(error);
    }
    fn on_circuit_established(&self, recipient_identity: String, is_initiator: bool) {
        self.0
            .lock()
            .unwrap()
            .circuits
            .push((recipient_identity, is_initiator));
    }
    fn on_peer_key_event(&self, identity_hex: String, code: u8, agreement_hex: String) {
        self.0
            .lock()
            .unwrap()
            .key_events
            .push((identity_hex, code, agreement_hex));
    }
    fn on_message_request(&self, request: MessageRequest) {
        self.0.lock().unwrap().requests.push(request);
    }
    fn on_message_receipt(&self, _sender_hex: String, message_id_hex: String, kind: u8) {
        self.0.lock().unwrap().receipts.push((message_id_hex, kind));
    }
    fn on_status_event(&self, event: StatusEvent) {
        let resend = match &event {
            StatusEvent::ResendEligible { peer, message_id } => {
                Some((peer.clone(), message_id.clone()))
            }
            _ => None,
        };
        let text = {
            let mut r = self.0.lock().unwrap();
            r.status.push(event);
            match resend {
                Some((peer, id)) => match r.sent.get(&id).cloned() {
                    Some(t) => Some((peer, id, t)),
                    None => {
                        // Eligible for an id we never sent: a core bug.
                        r.errors
                            .push(format!("resend eligible for unknown id {id}"));
                        None
                    }
                },
                None => None,
            }
        };
        // The app's automatic resend (D38): the same id and text, through
        // the client the recorder holds weakly. Not under the record lock.
        if let (Some((peer, id, text)), Some(client)) = (text, self.1.upgrade()) {
            let outcome = client.send_text_message_using_id(peer, text, id.clone());
            let mut r = self.0.lock().unwrap();
            match outcome {
                Ok(_) => r.resent.push(id),
                Err(e) => r.errors.push(format!("resend: {e}")),
            }
        }
    }
}

/// One test client with a deterministic identity.
pub struct Peer {
    pub name: String,
    pub client: Arc<RChatClient>,
    pub rec: Arc<Mutex<Recorded>>,
    pub card: Card,
    /// `<state dir>/sent.jsonl`: our sent messages, kept across a restart
    /// as the app's message store keeps them (receipts and resends after a
    /// restart are matched against it).
    sent_log: Option<PathBuf>,
}

/// File name of the sent-message log in a state dir (not a `.rcs` record).
const SENT_LOG: &str = "sent.jsonl";

impl Peer {
    /// `state_dir`: persist sealed session records there (state key derived
    /// from `seed_text`, test only) and import what it holds now, before the
    /// first connect. `device_key_seed`: sign session notices with a
    /// software device key, and put it on our card (v2).
    pub fn new(
        name: &str,
        server_url: &str,
        origin: Option<&str>,
        seed_text: &str,
        state_dir: Option<PathBuf>,
        device_key_seed: Option<String>,
    ) -> Result<Peer, String> {
        let config = ClientConfig {
            server_url: ws_url(server_url),
            dev_origin: origin.map(str::to_string),
            reconnect_max_attempts: 5,
            enable_delivery_confirmation: true,
            ..ClientConfig::default()
        };
        let client = RChatClient::new(config).map_err(|e| e.to_string())?;
        client
            .generate_identity_from_seed(&derive_seed(seed_text))
            .map_err(|e| e.to_string())?;
        let dk = match device_key_seed {
            Some(seed) => {
                let key = soft_device_key(&seed)?;
                let dk_pub: [u8; 65] = key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .try_into()
                    .map_err(|_| "device key is not a 65-byte point".to_string())?;
                let dks = client
                    .device_key_binding(dk_pub, false)
                    .map_err(|e| e.to_string())?;
                client.set_device_signer(Arc::new(SoftSigner(key)));
                Some(CardDk {
                    dk: hex::encode(dk_pub),
                    dkh: false,
                    dks: hex::encode(dks),
                })
            }
            None => None,
        };
        let card = Card {
            name: name.to_string(),
            ik: client.get_identity().map_err(|e| e.to_string())?,
            ak: client.get_agreement_key().map_err(|e| e.to_string())?,
            dk,
        };
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let mut sent_log = None;
        if let Some(dir) = state_dir {
            std::fs::create_dir_all(&dir).map_err(|e| format!("state dir: {e}"))?;
            let log = dir.join(SENT_LOG);
            if let Ok(text) = std::fs::read_to_string(&log) {
                let mut r = rec.lock().unwrap();
                for line in text.lines() {
                    let (id, body): (String, String) =
                        serde_json::from_str(line).map_err(|e| format!("sent log: {e}"))?;
                    r.sent_order.push(id.clone());
                    r.sent.insert(id, body);
                }
            }
            sent_log = Some(log);
            let key = blake3::derive_key("rchat-test-state", seed_text.as_bytes());
            client.set_state_store(&key, Arc::new(FileSink(dir.clone())));
            client.import_state_records(read_records(&dir)?);
        }
        client.set_callbacks(Box::new(Recorder(rec.clone(), Arc::downgrade(&client))));
        Ok(Peer {
            name: name.to_string(),
            client,
            rec,
            card,
            sent_log,
        })
    }

    /// Connect and publish; succeeds only once the relay accepted the
    /// signed bundle (`publish_key_bundle_response` ok).
    pub fn start(&self, timeout: Duration) -> Result<(), String> {
        self.client
            .connect()
            .map_err(|e| format!("{}: connect: {e}", self.name))?;
        self.client
            .publish_key_bundle()
            .map_err(|e| format!("{}: publish: {e}", self.name))?;
        if wait_until(timeout, || self.client.is_key_bundle_published()) {
            Ok(())
        } else {
            Err(format!(
                "{}: relay never accepted the key bundle",
                self.name
            ))
        }
    }

    /// Pin the card's keys, then its device key if it has one: the test
    /// analog of a scan (D44: DK values only ever come from a card).
    pub fn pin(&self, c: &Card) -> Result<(), String> {
        self.client
            .pin_peer_key(c.ik.clone(), c.ak.clone())
            .map_err(|e| format!("{}: pin {}: {e}", self.name, c.name))?;
        let Some(d) = &c.dk else {
            return Ok(());
        };
        let bad = |what: &str| format!("{}: pin {}: bad {what}", self.name, c.name);
        let dk: [u8; 65] = hex::decode(&d.dk)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| bad("dk"))?;
        let dks: [u8; 64] = hex::decode(&d.dks)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| bad("dks"))?;
        self.client
            .pin_device_key(c.ik.clone(), dk, d.dkh, dks)
            .map_err(|e| format!("{}: pin {} device key: {e}", self.name, c.name))
    }

    pub fn ask(&self, c: &Card) -> Result<(), String> {
        self.client
            .request_circuit(c.ik.clone())
            .map_err(|e| format!("{}: ask {}: {e}", self.name, c.name))
    }

    /// Send, and log the text under its id (answers `ResendEligible`).
    pub fn send(&self, to: &Card, text: &str) -> Result<String, String> {
        let id = self
            .client
            .send_text_message(to.ik.clone(), text.to_string())
            .map_err(|e| e.to_string())?;
        if let Some(log) = &self.sent_log {
            let mut line = serde_json::to_string(&(&id, text)).map_err(|e| e.to_string())?;
            line.push('\n');
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)
                .map_err(|e| format!("sent log: {e}"))?;
            std::io::Write::write_all(&mut f, line.as_bytes()).map_err(|e| e.to_string())?;
        }
        let mut r = self.rec.lock().unwrap();
        r.sent.insert(id.clone(), text.to_string());
        r.sent_order.push(id.clone());
        Ok(id)
    }

    pub fn wait(&self, timeout: Duration, f: impl Fn(&Recorded) -> bool) -> bool {
        wait_until(timeout, || f(&self.rec.lock().unwrap()))
    }

    pub fn snapshot<T>(&self, f: impl FnOnce(&Recorded) -> T) -> T {
        f(&self.rec.lock().unwrap())
    }
}

/// Poll `f` every 100 ms until it holds or `timeout` passes.
pub fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Deterministic 32-byte identity seed from a test name.
pub fn derive_seed(input: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input.as_bytes());
    hasher.update(b"rchat-test-seed-v1");
    *hasher.finalize().as_bytes()
}

/// Machine-readable result line for the scripts.
pub fn result(key: &str, value: impl Display) {
    println!("RESULT {key}={value}");
}

pub fn ws_url(server: &str) -> String {
    if server.starts_with("ws://") || server.starts_with("wss://") {
        server.to_string()
    } else {
        format!("ws://{server}")
    }
}
