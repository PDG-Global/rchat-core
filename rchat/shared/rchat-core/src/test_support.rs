//! Test helpers: a `ClientInner` whose outgoing frames land in a channel.

use crate::crypto::{EphemeralKeyPair, IdentityKeyPair};
use crate::keyauth::{self, SignedBundle};
use crate::protocol::PeerBundle;
use crate::protocol::{
    CircuitId, ControlMessage, Frame, RelayPacket, SignalingMessage, SignalingPayload, CAPABILITIES,
};
use crate::relay_pin::{sign_relay_auth, RelayLink};
use crate::transport::{TransportConfig, WebSocketClient};
use crate::{
    ClientConfig, ClientInner, ConnectionStatus, RChatCallbacks, RChatClient, ReceivedMessage,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc::Receiver;

/// The channel binding every test connection reports.
pub(crate) const TEST_BINDING: [u8; 32] = [0x42; 32];

/// Seed of the relay identity every test hello carries.
pub(crate) const TEST_RELAY_SEED: [u8; 32] = [0x77; 32];

pub(crate) fn test_relay() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&TEST_RELAY_SEED)
}

fn relay_identity_json(
    binding: &[u8; 32],
    challenge: &[u8; 32],
    relay: &ed25519_dalek::SigningKey,
    version: u32,
    chain: &[RelayLink],
) -> serde_json::Value {
    serde_json::json!({
        "key": hex::encode(relay.verifying_key().to_bytes()),
        "version": version,
        "signature": hex::encode(sign_relay_auth(relay, binding, challenge, version)),
        "chain": chain.iter().map(|l| serde_json::json!({
            "prev_key": hex::encode(l.prev_key),
            "new_key": hex::encode(l.new_key),
            "version": l.version,
            "signature": hex::encode(l.signature),
        })).collect::<Vec<_>>(),
    })
}

/// A v2 hello_response from `relay` (signed over `TEST_BINDING`).
pub(crate) fn hello_response_from(
    challenge: [u8; 32],
    relay: &ed25519_dalek::SigningKey,
    version: u32,
    chain: &[RelayLink],
) -> SignalingMessage {
    let mut msg = hello_response_raw(2, Some(&hex::encode(challenge)));
    msg.payload.inner["data"]["relay_identity"] =
        relay_identity_json(&TEST_BINDING, &challenge, relay, version, chain);
    msg
}

/// A v2 hello_response from the test relay, signed over `binding` (for
/// tests that give the connection another channel binding).
pub(crate) fn hello_response_bound(challenge: [u8; 32], binding: [u8; 32]) -> SignalingMessage {
    let mut msg = hello_response_raw(2, Some(&hex::encode(challenge)));
    msg.payload.inner["data"]["relay_identity"] =
        relay_identity_json(&binding, &challenge, &test_relay(), 0, &[]);
    msg
}

/// A client with identity `[seed_byte; 64]`, a fake socket (frames go to the
/// returned receiver, capacity 256) and binding `TEST_BINDING`.
pub(crate) fn inner_with_identity(seed_byte: u8) -> (ClientInner, Receiver<Vec<u8>>) {
    let mut inner = ClientInner::new(ClientConfig::default());
    inner.identity = Some(IdentityKeyPair::from_seed(&[seed_byte; 64]).expect("64-byte seed"));
    let our_ik = inner
        .identity
        .as_ref()
        .unwrap()
        .public_signing_key()
        .to_bytes();
    inner.session_manager.set_our_identity(our_ik);
    let ws = WebSocketClient::new(TransportConfig::default());
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    ws.install_outgoing_for_test(tx);
    ws.set_channel_binding_for_test(Some(TEST_BINDING));
    inner.websocket = Some(ws);
    inner.is_connected = true;
    // As if `connect()` had just sent the hello.
    inner.hello_outstanding = true;
    // Frame-level tests act as if the relay gate and publish had passed;
    // RP11 turns this off.
    inner.bypass_frame_gate = true;
    (inner, rx)
}

pub(crate) fn drain(rx: &mut Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        out.push(frame);
    }
    out
}

pub(crate) fn sent_controls(rx: &mut Receiver<Vec<u8>>) -> Vec<ControlMessage> {
    drain(rx)
        .iter()
        .filter(|f| f.first() == Some(&crate::protocol::FRAME_TYPE_CONTROL))
        .filter_map(|f| ControlMessage::decode(f))
        .collect()
}

pub(crate) fn sent_signaling(rx: &mut Receiver<Vec<u8>>) -> Vec<SignalingMessage> {
    drain(rx)
        .iter()
        .filter(|f| f.first() == Some(&crate::protocol::FRAME_TYPE_SIGNALING))
        .filter_map(|f| serde_json::from_slice(&f[1..]).ok())
        .collect()
}

fn signaling(msg_type: &str, data: serde_json::Value) -> SignalingMessage {
    SignalingMessage::new(
        msg_type,
        SignalingPayload {
            inner: serde_json::json!({ "type": msg_type, "data": data }),
        },
    )
}

pub(crate) fn hello_response_raw(
    selected_version: u32,
    challenge: Option<&str>,
) -> SignalingMessage {
    let mut data = serde_json::json!({
        "selected_version": selected_version,
        "server_info": { "version": "test", "capabilities": CAPABILITIES },
        "knock_ttl_hours": 72
    });
    if let Some(c) = challenge {
        data["auth_challenge"] = serde_json::Value::String(c.to_string());
    }
    if let Some(bytes) = challenge
        .and_then(|c| hex::decode(c).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        data["relay_identity"] = relay_identity_json(&TEST_BINDING, &bytes, &test_relay(), 0, &[]);
    }
    signaling("hello_response", data)
}

pub(crate) fn hello_response(challenge: [u8; 32]) -> SignalingMessage {
    hello_response_raw(2, Some(&hex::encode(challenge)))
}

pub(crate) fn publish_ok(next: [u8; 32]) -> SignalingMessage {
    signaling(
        "publish_key_bundle_response",
        serde_json::json!({ "status": "ok", "bundle_id": "b", "next_challenge": hex::encode(next) }),
    )
}

pub(crate) fn error_message(code: &str) -> SignalingMessage {
    signaling("error", serde_json::json!({ "code": code, "message": "x" }))
}

pub(crate) fn feed_signaling(inner: &mut ClientInner, msg: SignalingMessage) {
    RChatClient::handle_frame(inner, Frame::Signaling(msg));
}

/// A client that has completed hello + an authenticated publish (outgoing drained).
pub(crate) fn published(seed_byte: u8) -> (ClientInner, Receiver<Vec<u8>>) {
    let (mut inner, mut rx) = inner_with_identity(seed_byte);
    inner.is_connected = false;
    inner.request_publish().expect("publish recorded");
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    feed_signaling(&mut inner, publish_ok([0x55; 32]));
    assert!(inner.is_key_bundle_published, "published() precondition");
    drain(&mut rx);
    (inner, rx)
}

/// Like `published`, with a custom config (identity still `[seed_byte; 64]`).
pub(crate) fn published_with_config(
    seed_byte: u8,
    config: ClientConfig,
) -> (ClientInner, Receiver<Vec<u8>>) {
    let (mut inner, rx) = published(seed_byte);
    inner.apply_rotation_config(config);
    (inner, rx)
}

/// Records every callback as a short string.
#[derive(Clone, Default)]
pub(crate) struct Recorder {
    pub events: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    pub(crate) fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
    fn push(&self, s: String) {
        self.events.lock().unwrap().push(s);
    }
}

impl RChatCallbacks for Recorder {
    fn on_connection_status_changed(&self, status: ConnectionStatus) {
        let s = match status {
            ConnectionStatus::Error { .. } => "status:Error".to_string(),
            other => format!("status:{other:?}"),
        };
        self.push(s);
    }
    fn on_message_received(&self, message: ReceivedMessage) {
        self.push(format!(
            "message:{}:{}",
            message.sender_identity,
            hex::encode(&message.content)
        ));
    }
    fn on_message_delivered(&self, message_id: String) {
        self.push(format!("delivered:{message_id}"));
    }
    fn on_error(&self, error: String) {
        self.push(format!("error:{error}"));
    }
    fn on_circuit_established(&self, recipient_identity: String, is_initiator: bool) {
        self.push(format!("circuit:{recipient_identity}:{is_initiator}"));
    }
    fn on_reconnect(&self) {
        self.push("reconnect".to_string());
    }
}

pub(crate) fn sent_relays(rx: &mut Receiver<Vec<u8>>) -> Vec<RelayPacket> {
    drain(rx)
        .iter()
        .filter_map(|f| RelayPacket::decode(f))
        .collect()
}

/// A remote identity with its signed bundle (identity from seed `[b; 64]`,
/// the same derivation as `inner_with_identity(b)`).
pub(crate) struct Peer {
    pub id: IdentityKeyPair,
    pub bundle: SignedBundle,
    pub hex: String,
}

pub(crate) fn peer(seed_byte: u8) -> Peer {
    let id = IdentityKeyPair::from_seed(&[seed_byte; 64]).unwrap();
    let bundle = keyauth::sign_bundle(&id).unwrap();
    let hex = hex::encode(bundle.identity_key);
    Peer { id, bundle, hex }
}

/// A bundle for `p` validly signed by `p` but naming agreement key `ak`
/// (a relay cannot make one; a peer that rotated or lied can).
pub(crate) fn bundle_with_ak(p: &Peer, ak: [u8; 32]) -> SignedBundle {
    let t = keyauth::bundle_transcript(&p.bundle.identity_key, &ak, &ak).unwrap();
    SignedBundle {
        identity_key: p.bundle.identity_key,
        identity_agreement_key: ak,
        signed_pre_key: ak,
        bundle_signature: p.id.sign(&t).to_bytes(),
    }
}

pub(crate) const C1: CircuitId = CircuitId([0xC1; 16]);
pub(crate) const C2: CircuitId = CircuitId([0xC2; 16]);
pub(crate) const TOKEN: [u8; 32] = [7; 32];

/// `CircuitCreatedV2` as the relay would send it. Role 0 gets circuit C1
/// (sends on C2), role 1 gets C2 (sends on C1); both share `TOKEN` so
/// packets can be handed straight from one test client to the other.
pub(crate) fn created_v2(
    role: u8,
    peer_bundle: &SignedBundle,
    i_ek: [u8; 32],
    r_ek: [u8; 32],
) -> Frame {
    let (circuit_id, target_circuit_id) = if role == 0 { (C1, C2) } else { (C2, C1) };
    Frame::Control(ControlMessage::CircuitCreatedV2 {
        circuit_id,
        token: TOKEN.to_vec(),
        target_circuit_id,
        role,
        peer: PeerBundle::from_signed(peer_bundle),
        initiator_ephemeral_key: i_ek.to_vec(),
        responder_ephemeral_key: r_ek.to_vec(),
    })
}

pub(crate) fn feed(inner: &mut ClientInner, frame: Frame) {
    RChatClient::handle_frame(inner, frame);
}

/// Everything the core reported through `RChatCallbacks`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ev {
    Receipt(String, String, u8),
    Established(String, bool),
    PeerKey(String, u8, String),
    /// (sender hex, content bytes, message id)
    Message(String, Vec<u8>, String),
    Error(String),
    Request(crate::MessageRequest),
    /// (old identity hex, new identity hex, new agreement hex, new version)
    Rotated(String, String, String, u32),
    Status(crate::status::StatusEvent),
    /// `on_message_delivered` (the relay acked our message).
    Delivered(String),
}

pub(crate) struct EventLog(pub Arc<Mutex<Vec<Ev>>>);

impl RChatCallbacks for EventLog {
    fn on_connection_status_changed(&self, _status: ConnectionStatus) {}
    fn on_message_received(&self, m: ReceivedMessage) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Message(m.sender_identity, m.content, m.id));
    }
    fn on_message_delivered(&self, message_id: String) {
        self.0.lock().unwrap().push(Ev::Delivered(message_id));
    }
    fn on_error(&self, e: String) {
        self.0.lock().unwrap().push(Ev::Error(e));
    }
    fn on_circuit_established(&self, peer: String, is_initiator: bool) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Established(peer, is_initiator));
    }
    fn on_peer_key_event(&self, identity_hex: String, code: u8, agreement_hex: String) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::PeerKey(identity_hex, code, agreement_hex));
    }
    fn on_message_request(&self, request: crate::MessageRequest) {
        self.0.lock().unwrap().push(Ev::Request(request));
    }
    fn on_peer_rotated(&self, old: String, new: String, ak: String, version: u32) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Rotated(old, new, ak, version));
    }
    fn on_message_receipt(&self, sender_hex: String, message_id_hex: String, kind: u8) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Receipt(sender_hex, message_id_hex, kind));
    }
    fn on_status_event(&self, e: crate::status::StatusEvent) {
        self.0.lock().unwrap().push(Ev::Status(e));
    }
}

pub(crate) fn install_event_log(inner: &mut ClientInner) -> Arc<Mutex<Vec<Ev>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    inner.callbacks = Some(Box::new(EventLog(log.clone())));
    log
}

/// Two published clients, A (role 0) and B (role 1), each pinning the
/// other, with an established v2 session and A's hello sync delivered.
pub(crate) struct Pair {
    pub a: ClientInner,
    pub a_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub b: ClientInner,
    pub b_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub pa: Peer,
    pub pb: Peer,
    pub a_log: Arc<Mutex<Vec<Ev>>>,
    pub b_log: Arc<Mutex<Vec<Ev>>>,
}

pub(crate) fn establish(a_seed: u8, b_seed: u8) -> Pair {
    let (mut a, mut a_rx) = published(a_seed);
    let (mut b, mut b_rx) = published(b_seed);
    a.receipt_delay_override = Some(std::time::Duration::ZERO);
    b.receipt_delay_override = Some(std::time::Duration::ZERO);
    let (pa, pb) = (peer(a_seed), peer(b_seed));
    let a_log = install_event_log(&mut a);
    let b_log = install_event_log(&mut b);
    a.peers
        .pin(&pb.hex, pb.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&pa.hex, pa.bundle.identity_agreement_key)
        .unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    let now = Instant::now();
    a.peers.push_ask(&pb.hex, ek_a, now);
    b.peers.push_ask(&pa.hex, ek_b, now);
    feed(&mut a, created_v2(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v2(1, &pa.bundle, i_ek, r_ek));
    relay_all(&mut a_rx, &mut b); // A's hello sync gives B a sending chain
    drain(&mut b_rx);
    // The relay acked what the set-up sent (both notices are tracked).
    relay_acked_all(&a);
    relay_acked_all(&b);
    a_log.lock().unwrap().clear();
    b_log.lock().unwrap().clear();
    Pair {
        a,
        a_rx,
        b,
        b_rx,
        pa,
        pb,
        a_log,
        b_log,
    }
}

/// As if the relay had acked every payload `inner` tracks.
pub(crate) fn relay_acked_all(inner: &ClientInner) {
    *inner.acks.lock().unwrap() = Default::default();
}

/// Seal a text message from `from` to `peer_hex` and queue it on `from`'s
/// outgoing channel, as the async send path does. Returns the message id.
pub(crate) fn push_text(from: &ClientInner, peer_hex: &str, text: &str) -> [u8; 16] {
    let id: [u8; 16] = rand::random();
    let mut pt = vec![0x01];
    pt.extend_from_slice(text.as_bytes());
    let packet = from.seal_ratchet(peer_hex, id, &pt).unwrap();
    from.send_now(packet.encode_with_frame_type()).unwrap();
    id
}

/// Hand every relay frame `from` queued to `to`. Returns how many.
pub(crate) fn relay_all(
    from_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    to: &mut ClientInner,
) -> usize {
    let packets = sent_relays(from_rx);
    let n = packets.len();
    for p in packets {
        feed(to, Frame::Relay(p));
    }
    n
}

/// A knock from `sender` to `recipient` for `issued_hour`, no intro.
pub(crate) fn knock_from(sender: &Peer, recipient: &Peer, issued_hour: u64) -> Vec<u8> {
    crate::knock::build_knock(
        &sender.id,
        &sender.bundle,
        &recipient.bundle.identity_key,
        &recipient.bundle.identity_agreement_key,
        issued_hour,
        None,
        None,
    )
    .unwrap()
}

/// A knock from `sender` to `recipient` carrying a rotation block.
pub(crate) fn knock_from_rotating(
    sender: &Peer,
    recipient: &Peer,
    issued_hour: u64,
    block: &crate::rotation::RotationBlock,
) -> Vec<u8> {
    crate::knock::build_knock(
        &sender.id,
        &sender.bundle,
        &recipient.bundle.identity_key,
        &recipient.bundle.identity_agreement_key,
        issued_hour,
        None,
        Some(block),
    )
    .expect("knock")
}

pub(crate) fn queued(payload: Vec<u8>) -> Frame {
    Frame::Control(ControlMessage::QueuedMessage { payload })
}

/// Put a test `ClientInner` behind a real `RChatClient` (own runtime) to
/// drive the public async API.
pub(crate) fn wrap(inner: ClientInner) -> Arc<RChatClient> {
    let connected_mirror = inner.connected_mirror.clone();
    Arc::new(RChatClient {
        runtime: Arc::new(crate::ClientRuntime::new().unwrap()),
        inner: Arc::new(tokio::sync::RwLock::new(inner)),
        callback_hub: crate::CallbackHub::new(),
        cover_wanted: Default::default(),
        connected_mirror,
    })
}

/// Key every test store seals with.
pub(crate) const TEST_STATE_KEY: [u8; 32] = [0x5e; 32];

/// An in-memory `StateSink` that can be made to fail ("disk full").
#[derive(Clone, Default)]
pub(crate) struct MemorySink {
    pub files: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    pub fail: Arc<std::sync::atomic::AtomicBool>,
    /// (record key, counter) of every successful write; counter 0 = delete.
    pub log: Arc<Mutex<Vec<(String, u64)>>>,
    /// (record key, sealed bytes) of every successful write, in order.
    pub history: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    /// Some(n): n more writes succeed, then every write fails.
    pub budget: Arc<Mutex<Option<usize>>>,
    /// Writes to these record keys fail; the others go through.
    pub fail_keys: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Every write attempted, failed or not.
    pub tried: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::state_store::StateSink for MemorySink {
    fn write(&self, key: &str, sealed: &[u8]) -> Result<(), String> {
        self.tried.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("disk full".into());
        }
        if self.fail_keys.lock().unwrap().contains(key) {
            return Err("write refused".into());
        }
        match &mut *self.budget.lock().unwrap() {
            Some(0) => return Err("disk full".into()),
            Some(n) => *n -= 1,
            None => {}
        }
        let counter = sealed
            .get(6..14)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        self.log.lock().unwrap().push((key.to_string(), counter));
        self.history
            .lock()
            .unwrap()
            .push((key.to_string(), sealed.to_vec()));
        let mut f = self.files.lock().unwrap();
        if sealed.is_empty() {
            f.remove(key);
        } else {
            f.insert(key.to_string(), sealed.to_vec());
        }
        Ok(())
    }
}

pub(crate) fn with_store(inner: &mut ClientInner, sink: &MemorySink) {
    inner.state = Some(crate::persistence::StateStore {
        keys: crate::state_store::StateKeys::new(TEST_STATE_KEY),
        sink: Arc::new(sink.clone()),
        counters: std::sync::Mutex::new(Default::default()),
        failing: std::sync::Mutex::new(Default::default()),
        staged: Vec::new(),
    });
}

/// A client restarted from `sink` (spec §18.5): `published(seed)` with a
/// zero receipt delay, an event log and `peer(peer_seed)` pinned, the store
/// installed, the sink's records staged (higher counter wins) and restored,
/// then a new transport connection (`transport_epoch` + 1).
pub(crate) fn restart_from(
    seed: u8,
    peer_seed: u8,
    sink: &MemorySink,
) -> (ClientInner, Receiver<Vec<u8>>, Arc<Mutex<Vec<Ev>>>) {
    let (mut inner, rx) = published(seed);
    inner.receipt_delay_override = Some(std::time::Duration::ZERO);
    let log = install_event_log(&mut inner);
    let p = peer(peer_seed);
    inner
        .peers
        .pin(&p.hex, p.bundle.identity_agreement_key)
        .unwrap();
    with_store(&mut inner, sink);
    let files = sink.files.lock().unwrap().clone();
    let store = inner.state.as_mut().unwrap();
    for (key, sealed) in files {
        store.stage_keep_higher(key, sealed);
    }
    inner.restore_staged_state();
    inner.transport_epoch += 1;
    (inner, rx, log)
}

/// `establish` with both stores installed and both peer records written.
pub(crate) fn stored_pair(sa: &MemorySink, sb: &MemorySink) -> Pair {
    let mut p = establish(0xA1, 0xB2);
    with_store(&mut p.a, sa);
    with_store(&mut p.b, sb);
    p.a.persist_peer(&p.pb.hex).unwrap();
    p.b.persist_peer(&p.pa.hex).unwrap();
    p
}

/// The peer record `our_seed`'s client stored for `peer`, opened.
pub(crate) fn open_record(
    sink: &MemorySink,
    our_seed: u8,
    peer: &Peer,
) -> crate::state_store::PeerRecordV1 {
    let key = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .record_key_for(&peer.bundle.identity_key);
    let sealed = sink
        .files
        .lock()
        .unwrap()
        .get(&key)
        .cloned()
        .expect("record written");
    open_sealed(our_seed, &key, &sealed)
}

/// Open one sealed peer record written by `our_seed`'s client.
pub(crate) fn open_sealed(
    our_seed: u8,
    key: &str,
    sealed: &[u8],
) -> crate::state_store::PeerRecordV1 {
    let keys = crate::state_store::StateKeys::new(TEST_STATE_KEY);
    let our_ik = self::peer(our_seed).bundle.identity_key;
    let (_, _, body) = keys.open(&our_ik, key, sealed).unwrap();
    bincode::deserialize(&body).unwrap()
}

/// The contents of every message delivered to the app, in order.
pub(crate) fn texts(log: &Arc<Mutex<Vec<Ev>>>) -> Vec<Vec<u8>> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Message(_, c, _) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

/// Every status event raised, in order.
pub(crate) fn statuses(log: &Arc<Mutex<Vec<Ev>>>) -> Vec<crate::status::StatusEvent> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Status(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

pub(crate) fn pending_msg(id: u8, text: &str) -> crate::session::PendingMessage {
    crate::session::PendingMessage {
        id: crate::protocol::MessageId(hex::encode([id; 16])),
        content: text.as_bytes().to_vec(),
        msg_type: crate::protocol::MessageType::Text,
        timestamp_ms: 0,
    }
}

/// Run `RChatClient::process_pending` over `inner` and hand it back.
pub(crate) fn process_pending_on(inner: crate::ClientInner) -> crate::ClientInner {
    if let Some(ws) = &inner.websocket {
        ws.set_connected_for_test();
    }
    let client = crate::RChatClient::new(crate::ClientConfig::default()).unwrap();
    *client.inner.try_write().unwrap() = inner;
    client.process_pending().unwrap();
    let mut guard = client.inner.try_write().unwrap();
    std::mem::replace(
        &mut *guard,
        crate::ClientInner::new(crate::ClientConfig::default()),
    )
}

/// A fresh `CircuitCreatedV2` on both sides (role 0 for `a`), with new EKs
/// pushed onto both ask rings: the pair is re-made.
pub(crate) fn reestablish(a: &mut ClientInner, b: &mut ClientInner, pa: &Peer, pb: &Peer) {
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    let now = Instant::now();
    a.peers.push_ask(&pb.hex, ek_a, now);
    b.peers.push_ask(&pa.hex, ek_b, now);
    feed(a, created_v2(0, &pb.bundle, i_ek, r_ek));
    feed(b, created_v2(1, &pa.bundle, i_ek, r_ek));
}

/// What `rv3_run` leaves behind: the pair (A still holds its store `sa`),
/// the queued ids that B lost, the unreceipted-and-unqueued id (`earlier`,
/// reason 3), the receipted one, and B's restarted client.
pub(crate) struct Rv3 {
    pub p: Pair,
    pub ids: Vec<[u8; 16]>,
    pub earlier: [u8; 16],
    pub receipted: [u8; 16],
    pub b2: ClientInner,
    pub b2_rx: Receiver<Vec<u8>>,
    pub b2_log: Arc<Mutex<Vec<Ev>>>,
    pub sa: MemorySink,
}

/// RV3's flow (spec §18.10): B loses all state while A has `queued`
/// messages for it. A sends one receipted message, one lost elsewhere
/// (`earlier`), then `queued` that B's new install holds and fails to
/// decrypt; the pair is re-made and B's notice reaches A. `hook(&mut A,
/// &B)` runs just before B's notice is relayed to A.
pub(crate) fn rv3_run(queued: usize, hook: impl FnOnce(&mut ClientInner, &Peer)) -> Rv3 {
    rv3_run_with(queued, DkSetup::Matching, hook)
}

/// The device-key setup of an `rv3_run` (D46, DK2–DK7).
pub(crate) enum DkSetup {
    /// A pins B's software DK (seed 1) and B signs with it: guard 7 holds.
    Matching,
    /// B signs, but A pinned no DK (an old card).
    NoPin,
    /// A pins the DK, but B has no signer (unsigned notices).
    NoSigner,
    /// A pins seed 1; B signs with seed 2 (the seed without the phone).
    Thief,
    /// A pins seed 1 and B signs with it, then the hook re-pins seed 3.
    Rescanned,
}

/// `rv3_run` with a device-key setup.
pub(crate) fn rv3_run_with(
    queued: usize,
    dk: DkSetup,
    hook: impl FnOnce(&mut ClientInner, &Peer),
) -> Rv3 {
    let (a_pins, b_signs) = match dk {
        DkSetup::Matching | DkSetup::Rescanned => (Some(1), Some(1)),
        DkSetup::NoPin => (None, Some(1)),
        DkSetup::NoSigner => (Some(1), None),
        DkSetup::Thief => (Some(1), Some(2)),
    };
    let rescanned = matches!(dk, DkSetup::Rescanned);
    rv3_run_with_keys(queued, a_pins, b_signs, move |a, b| {
        if rescanned {
            a.peers
                .pin_device_key(&b.hex, crate::device_key::test_keys::soft_dk(3).1);
        }
        hook(a, b);
    })
}

/// The general form: A pins B's software DK from seed `a_pins`, and B's
/// restarted client signs with the DK from seed `b_signs` (None: no pin,
/// no signer).
pub(crate) fn rv3_run_with_keys(
    queued: usize,
    a_pins: Option<u8>,
    b_signs: Option<u8>,
    hook: impl FnOnce(&mut ClientInner, &Peer),
) -> Rv3 {
    use crate::device_key::test_keys::{soft_dk, SoftSigner};
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    if let Some(seed) = a_pins {
        p.a.peers.pin_device_key(&p.pb.hex, soft_dk(seed).1);
    }
    let receipted = push_text(&p.a, &p.pb.hex, "receipted");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, receipted).unwrap();
    relay_all(&mut p.b_rx, &mut p.a); // A marks it delivered
    let earlier = push_text(&p.a, &p.pb.hex, "unreceipted, not queued");
    drain(&mut p.a_rx); // lost elsewhere
    p.a.age_sent_for_test(&p.pb.hex, 10); // sent before the new session (F14)
    let ids: Vec<[u8; 16]> = (0..queued)
        .map(|i| push_text(&p.a, &p.pb.hex, &format!("q{i}")))
        .collect();
    let queued_payloads: Vec<_> = sent_relays(&mut p.a_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    let (mut b2, mut b2_rx) = published(0xB2);
    b2.receipt_delay_override = Some(std::time::Duration::ZERO);
    let b2_log = install_event_log(&mut b2);
    b2.peers
        .pin(&p.pa.hex, p.pa.bundle.identity_agreement_key)
        .unwrap();
    if let Some(seed) = b_signs {
        b2.device_signer = Some(Arc::new(SoftSigner(soft_dk(seed).0)));
    }
    for q in queued_payloads {
        feed(&mut b2, self::queued(q));
    }
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    relay_all(&mut p.a_rx, &mut b2); // A's hello sync and notice
    hook(&mut p.a, &p.pb);
    relay_all(&mut b2_rx, &mut p.a); // B's notice
    Rv3 {
        p,
        ids,
        earlier,
        receipted,
        b2,
        b2_rx,
        b2_log,
        sa,
    }
}

thread_local! {
    /// This thread's captured log lines, while a `LogCapture` is alive.
    static LOG_BUF: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The one global test logger: each line goes to the logging thread's
/// buffer, and only while that thread holds a `LogCapture`, so parallel
/// tests never see each other's lines.
struct CaptureLogger;

impl log::Log for CaptureLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format!("{} {}\n", record.level(), record.args());
        LOG_BUF.with(|b| {
            if let Some(buf) = b.borrow_mut().as_mut() {
                buf.push_str(&line);
            }
        });
    }
    fn flush(&self) {}
}

static CAPTURE_LOGGER: CaptureLogger = CaptureLogger;
static CAPTURE_INSTALL: std::sync::Once = std::sync::Once::new();

/// Captures every log line this thread writes from `start` to `take`.
pub(crate) struct LogCapture {
    /// Bound to the thread whose buffer it owns.
    _thread: std::marker::PhantomData<*const ()>,
}

impl LogCapture {
    pub fn start() -> LogCapture {
        CAPTURE_INSTALL.call_once(|| {
            if log::set_logger(&CAPTURE_LOGGER).is_ok() {
                log::set_max_level(log::LevelFilter::Trace);
            }
        });
        LOG_BUF.with(|b| *b.borrow_mut() = Some(String::new()));
        LogCapture {
            _thread: std::marker::PhantomData,
        }
    }

    /// Everything captured, one line per record (`LEVEL message`).
    pub fn take(self) -> String {
        LOG_BUF.with(|b| b.borrow_mut().take()).unwrap_or_default()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        LOG_BUF.with(|b| *b.borrow_mut() = None);
    }
}

/// Record a status event in this thread's capture (`EVENT …` lines), if
/// a `LogCapture` is alive, so tests can check events like log lines.
pub(crate) fn capture_event(line: &str) {
    LOG_BUF.with(|b| {
        if let Some(buf) = b.borrow_mut().as_mut() {
            buf.push_str("EVENT ");
            buf.push_str(line);
            buf.push('\n');
        }
    });
}

/// How many of `ids` (hex identities) appear in `line`, in full or as
/// their first 8 characters (relay invariant R6: at most one per line).
pub(crate) fn identity_values_in(line: &str, ids: &[String]) -> usize {
    ids.iter()
        .filter(|id| line.contains(id.as_str()) || id.get(..8).is_some_and(|p| line.contains(p)))
        .count()
}
