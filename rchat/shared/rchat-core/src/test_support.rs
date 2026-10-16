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
    let mut msg = hello_response_raw(
        crate::protocol::PROTOCOL_VERSION,
        Some(&hex::encode(challenge)),
    );
    msg.payload.inner["data"]["relay_identity"] =
        relay_identity_json(&TEST_BINDING, &challenge, relay, version, chain);
    msg
}

/// A v2 hello_response from the test relay, signed over `binding` (for
/// tests that give the connection another channel binding).
pub(crate) fn hello_response_bound(challenge: [u8; 32], binding: [u8; 32]) -> SignalingMessage {
    let mut msg = hello_response_raw(
        crate::protocol::PROTOCOL_VERSION,
        Some(&hex::encode(challenge)),
    );
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
    hello_response_raw(
        crate::protocol::PROTOCOL_VERSION,
        Some(&hex::encode(challenge)),
    )
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

impl crate::peers::PeerBook {
    /// Test analog of pinning from a scanned v3 card: the agreement key and
    /// the ML-KEM key (R1; Task 6 wires real cards).
    pub(crate) fn pin_card(&mut self, p: &Peer) -> Result<(), crate::peers::PinError> {
        self.pin(&p.hex, p.bundle.identity_agreement_key)?;
        self.set_kem_pk(&p.hex, p.bundle.kem_pk.clone());
        Ok(())
    }
}

pub(crate) fn peer(seed_byte: u8) -> Peer {
    let id = IdentityKeyPair::from_seed(&[seed_byte; 64]).unwrap();
    let bundle = keyauth::sign_bundle(&id).unwrap();
    register_identity(&id);
    let hex = hex::encode(bundle.identity_key);
    Peer { id, bundle, hex }
}

/// A bundle for `p` validly signed by `p` but naming agreement key `ak`
/// (a relay cannot make one; a peer that rotated or lied can).
pub(crate) fn bundle_with_ak(p: &Peer, ak: [u8; 32]) -> SignedBundle {
    let t = keyauth::bundle_transcript(&p.bundle.identity_key, &ak, &p.bundle.kem_pk);
    SignedBundle {
        identity_key: p.bundle.identity_key,
        identity_agreement_key: ak,
        kem_pk: p.bundle.kem_pk.clone(),
        bundle_signature: p.id.sign(&t).to_bytes(),
    }
}

pub(crate) const C1: CircuitId = CircuitId([0xC1; 16]);
pub(crate) const C2: CircuitId = CircuitId([0xC2; 16]);
pub(crate) const TOKEN: [u8; 32] = [7; 32];

/// The KEM ephemeral public key of every ask made in tests, by the ask's
/// X25519 public key (EKs are random, so entries never collide), so that
/// `created_v3` can echo the keys the asks really carried (§A.3).
static ASK_KEMS: std::sync::OnceLock<Mutex<std::collections::HashMap<[u8; 32], Box<[u8; 1184]>>>> =
    std::sync::OnceLock::new();

pub(crate) fn register_ask_kem(ek_pub: [u8; 32], kem_pub: [u8; 1184]) {
    ASK_KEMS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(ek_pub, Box::new(kem_pub));
}

/// Every test identity made by `peer()`, by identity key, so `created_v3`
/// can sign the peer's ask ephemerals as the peer would (ruling R7).
static IDENTITIES: std::sync::OnceLock<
    Mutex<std::collections::HashMap<[u8; 32], IdentityKeyPair>>,
> = std::sync::OnceLock::new();

fn register_identity(id: &IdentityKeyPair) {
    IDENTITIES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.public_signing_key().to_bytes(), id.clone());
}

/// The ask-ephemeral signature `ik`'s owner makes over `(ek, kem)`, or 64
/// zero bytes for an identity no test made.
pub(crate) fn ask_sig_by(ik: &[u8; 32], ek: &[u8; 32], kem: &[u8]) -> Vec<u8> {
    let ids = IDENTITIES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match (ids.get(ik), <&[u8; 1184]>::try_from(kem)) {
        (Some(id), Ok(kem)) => keyauth::sign_ask_ephemerals(id, ek, kem).to_vec(),
        _ => vec![0; 64],
    }
}

/// The KEM ephemeral of the ask whose EK is `ek_pub`, or a fresh unrelated
/// key if no ask was made with it.
pub(crate) fn ask_kem_for(ek_pub: &[u8; 32]) -> Vec<u8> {
    ASK_KEMS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(ek_pub)
        .map(|k| k.to_vec())
        .unwrap_or_else(|| crate::kem::KemKeyPair::generate().public().to_vec())
}

/// `CircuitCreatedV3` as the relay would send it. Role 0 gets circuit C1
/// (sends on C2), role 1 gets C2 (sends on C1); both share `TOKEN` so
/// packets can be handed straight from one test client to the other. The
/// KEM ephemerals are those the two asks carried (`ask_kem_for`). The
/// peer's side is signed by the peer (`peer_bundle`'s identity, R7); the
/// recipient's own side carries 64 zero bytes (nobody checks its own).
pub(crate) fn created_v3(
    role: u8,
    peer_bundle: &SignedBundle,
    i_ek: [u8; 32],
    r_ek: [u8; 32],
) -> Frame {
    created_v3_on(role, peer_bundle, i_ek, r_ek, (C1, C2))
}

/// `created_v3` on the pair's own circuits `(initiator's, responder's)`,
/// for tests where a stale circuit of an earlier pair must not match.
pub(crate) fn created_v3_on(
    role: u8,
    peer_bundle: &SignedBundle,
    i_ek: [u8; 32],
    r_ek: [u8; 32],
    (c_i, c_r): (CircuitId, CircuitId),
) -> Frame {
    let (circuit_id, target_circuit_id) = if role == 0 { (c_i, c_r) } else { (c_r, c_i) };
    let (i_kem, r_kem) = (ask_kem_for(&i_ek), ask_kem_for(&r_ek));
    let peer_ik = &peer_bundle.identity_key;
    let (i_sig, r_sig) = if role == 0 {
        (vec![0; 64], ask_sig_by(peer_ik, &r_ek, &r_kem))
    } else {
        (ask_sig_by(peer_ik, &i_ek, &i_kem), vec![0; 64])
    };
    Frame::Control(ControlMessage::CircuitCreatedV3 {
        circuit_id,
        token: TOKEN.to_vec(),
        target_circuit_id,
        role,
        peer: PeerBundle::from_signed(peer_bundle),
        initiator_ephemeral_key: i_ek.to_vec(),
        responder_ephemeral_key: r_ek.to_vec(),
        initiator_kem_ephemeral_pk: i_kem,
        responder_kem_ephemeral_pk: r_kem,
        initiator_ephemeral_sig: i_sig,
        responder_ephemeral_sig: r_sig,
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
    /// `on_file_received`.
    File(FileEv),
    Error(String),
    Request(crate::MessageRequest),
    /// (old identity hex, new identity hex, new agreement hex, new KEM
    /// key hex, new version)
    Rotated(String, String, String, String, u32),
    Status(crate::status::StatusEvent),
    /// `on_message_delivered` (the relay acked our message).
    Delivered(String),
}

/// What `on_file_received` was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileEv {
    pub sender: String,
    pub id: String,
    pub name: String,
    pub mime: String,
    pub expire_secs: u32,
    pub bytes: Vec<u8>,
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
    fn on_file_received(&self, f: crate::ReceivedFile) {
        self.0.lock().unwrap().push(Ev::File(FileEv {
            sender: f.sender_identity,
            id: f.id,
            name: f.name,
            mime: f.mime,
            expire_secs: f.expire_secs,
            bytes: f.bytes,
        }));
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
    fn on_peer_rotated(&self, old: String, new: String, ak: String, kem: String, version: u32) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Rotated(old, new, ak, kem, version));
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
/// other, with an established v3 session and A's session-init delivered.
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
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    let now = Instant::now();
    a.peers.push_ask(&pb.hex, ek_a, now);
    b.peers.push_ask(&pa.hex, ek_b, now);
    feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
    feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
    relay_all(&mut a_rx, &mut b); // A's session-init (hello) gives B its session and a sending chain
    drain(&mut b_rx);
    // As if B's first reply had reached A: A stops re-sending its
    // session-init (§A.4). Tests of the re-send set up their own pair.
    answered_init(&a, &pb.hex);
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

/// As if the peer's first reply had arrived: `inner`'s session-init to
/// `peer_hex` is no longer re-sent (§A.4).
pub(crate) fn answered_init(inner: &ClientInner, peer_hex: &str) {
    if let Some(mut s) = inner.session_manager.get_mut(peer_hex) {
        s.init_out = None;
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
    // `0x01 ‖ expire_secs (0) ‖ text` (§I.2).
    let mut pt = vec![0x01, 0, 0, 0, 0];
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
        &recipient.bundle.kem_pk,
        issued_hour,
        None,
        None,
        false,
    )
    .unwrap()
}

/// A knock declaring that `sender` holds no session with `recipient` (a
/// reinstall, R35), for `issued_hour`, no intro.
pub(crate) fn knock_from_no_prior(sender: &Peer, recipient: &Peer, issued_hour: u64) -> Vec<u8> {
    crate::knock::build_knock(
        &sender.id,
        &sender.bundle,
        &recipient.bundle.identity_key,
        &recipient.bundle.identity_agreement_key,
        &recipient.bundle.kem_pk,
        issued_hour,
        None,
        None,
        true,
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
        &recipient.bundle.kem_pk,
        issued_hour,
        None,
        Some(block),
        false,
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
        steady_wanted: Default::default(),
        connected_mirror,
        retired: Default::default(),
        pre_lock_delay_for_test: Default::default(),
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
    inner.peers.pin_card(&p).unwrap();
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
) -> crate::state_store::PeerRecordV2 {
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
) -> crate::state_store::PeerRecordV2 {
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
        // `expire_secs` (0) then the text, as `send_payload` queues it.
        content: crate::disappearing::with_expire(0, text.as_bytes()),
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

/// A fresh `CircuitCreatedV3` on both sides (role 0 for `a`), with new EKs
/// pushed onto both ask rings: the pair is re-made.
pub(crate) fn reestablish(a: &mut ClientInner, b: &mut ClientInner, pa: &Peer, pb: &Peer) {
    reestablish_on(a, b, pa, pb, (C1, C2));
}

/// `reestablish` on the pair's own circuits `(A's, B's)`.
pub(crate) fn reestablish_on(
    a: &mut ClientInner,
    b: &mut ClientInner,
    pa: &Peer,
    pb: &Peer,
    circuits: (CircuitId, CircuitId),
) {
    let (ek_a, ek_b) = (EphemeralKeyPair::generate(), EphemeralKeyPair::generate());
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    let now = Instant::now();
    a.peers.push_ask(&pb.hex, ek_a, now);
    b.peers.push_ask(&pa.hex, ek_b, now);
    feed(
        a,
        created_v3_on(0, &pb.bundle, i_ek, r_ek, circuits.clone()),
    );
    feed(b, created_v3_on(1, &pa.bundle, i_ek, r_ek, circuits));
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
                                          // The queued sends' second, read before they are sent (each is sent at
                                          // or after it): see the pin below.
    let queued_at = crate::unix_now_secs();
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
    b2.peers.pin_card(&p.pa).unwrap();
    if let Some(seed) = b_signs {
        b2.device_signer = Some(Arc::new(SoftSigner(soft_dk(seed).0)));
    }
    for q in queued_payloads {
        feed(&mut b2, self::queued(q));
    }
    reestablish(&mut p.a, &mut b2, &p.pa, &p.pb);
    // Pin the start of the session B's flag reports a reset against to the
    // queued sends' second. A's reset report takes the sends *strictly*
    // before it (reason 3, ruling N4), in whole seconds of wall clock: the
    // queued sends and the new session normally share a second, but when a
    // second boundary fell between them (about 1 run in 12 under load) the
    // queued ids were reported with reason 3 and made eligible first, so
    // B's reason-1 notice for them was (rightly) not reported again, and
    // the assertions below failed. `earlier` is 10 s older and stays before.
    if let Some(mut s) = p.a.session_manager.get_mut(&p.pb.hex) {
        if s.reset_since_unix.is_some() {
            s.reset_since_unix = Some(queued_at);
        }
    }
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

/// A two-or-more-party fake relay for the blinded pairing flow (protocol v3
/// §C.2, Task 8): blind asks are matched on the same token from two
/// different identities (the earlier asker initiates), the same identity
/// again replaces its held ask, and a token whose pair row exists answers
/// `PairTokenBusy` (a caller that is a slot of that row also tears the row
/// down, `CircuitClosed` to both, ruling R16). Identity asks match on
/// mutual targets and deliver their knock to a registered target. Relay
/// packets are routed by circuit; one for a circuit that is gone is
/// answered with the `CircuitNotFound` error, otherwise it is delivered
/// and acked (`MessageAck` by the envelope's clear id).
#[derive(Default)]
pub(crate) struct FakeRelay {
    sides: Vec<[u8; 32]>,
    bundles: Vec<Option<SignedBundle>>,
    held: Vec<FakeHeld>,
    rows: Vec<FakeRow>,
    /// Circuit id → the side it delivers to.
    routes: std::collections::HashMap<[u8; 16], usize>,
    /// Identity pairs made outside the fake: ((circuit, side), (circuit, side)).
    identity_rows: Vec<((CircuitId, usize), (CircuitId, usize))>,
    /// `CloseCircuit`s seen: (side, circuit).
    pub closes: Vec<(usize, CircuitId)>,
    next: u8,
    /// Every blind ask seen: (side, token).
    pub blind_asks: Vec<(usize, [u8; 32])>,
    /// Every identity ask seen: (side, target identity, resume id).
    pub identity_asks: Vec<(usize, Vec<u8>, Option<CircuitId>)>,
    /// `PairTokenBusy` answers sent, by side.
    pub busy: Vec<usize>,
    /// Pairs made: (initiator side, responder side, blinded).
    pub pairs: Vec<(usize, usize, bool)>,
    /// Every relay packet from these sides is lost (no delivery, no ack).
    pub drop_from: std::collections::HashSet<usize>,
    /// Relay packets whose envelope carries one of these clear ids are lost.
    pub drop_ids: std::collections::HashSet<[u8; 16]>,
    /// The next `CircuitCreatedV3` to this side is lost (once).
    pub drop_created_once: Option<usize>,
    /// The relay's clock in seconds (tests set it): held asks record it,
    /// and `expire_held_after` drops those held for a TTL.
    pub now_secs: u64,
}

struct FakeHeld {
    at: u64,
    side: usize,
    ik: [u8; 32],
    ek: Vec<u8>,
    kem: Vec<u8>,
    sig: Vec<u8>,
    key: FakeAskKey,
}

#[derive(Clone, PartialEq, Eq)]
enum FakeAskKey {
    Blind([u8; 32]),
    Identity([u8; 32]),
}

struct FakeRow {
    token: [u8; 32],
    slots: (usize, usize),
    circuits: (CircuitId, CircuitId),
}

impl FakeRelay {
    /// Register `side` as the client whose identity bundle is `bundle`.
    pub(crate) fn join(&mut self, side: usize, bundle: &SignedBundle) {
        while self.sides.len() <= side {
            self.sides.push([0; 32]);
            self.bundles.push(None);
        }
        self.sides[side] = bundle.identity_key;
        self.bundles[side] = Some(bundle.clone());
    }

    /// Route the circuits of a pair made outside the fake (`establish`).
    pub(crate) fn route(&mut self, circuit: &CircuitId, side: usize) {
        self.routes.insert(circuit.0, side);
    }

    /// An identity pair made outside the fake: `side_a` owns `c_a`.
    pub(crate) fn identity_pair(
        &mut self,
        c_a: CircuitId,
        side_a: usize,
        c_b: CircuitId,
        side_b: usize,
    ) {
        self.route(&c_a, side_a);
        self.route(&c_b, side_b);
        self.identity_rows.push(((c_a, side_a), (c_b, side_b)));
    }

    fn side_of(&self, ik: &[u8]) -> Option<usize> {
        self.sides.iter().position(|s| s.as_slice() == ik)
    }

    fn fresh_circuits(&mut self) -> (CircuitId, CircuitId) {
        self.next = self.next.wrapping_add(2);
        (
            CircuitId([0x10u8.wrapping_add(self.next); 16]),
            CircuitId([0x11u8.wrapping_add(self.next); 16]),
        )
    }

    /// Held asks past their TTL are gone at the relay.
    pub(crate) fn expire_asks(&mut self) {
        self.held.clear();
    }

    /// Held asks at least `ttl_secs` old on the relay's clock are gone.
    pub(crate) fn expire_held_after(&mut self, ttl_secs: u64) {
        let now = self.now_secs;
        self.held.retain(|h| now.saturating_sub(h.at) < ttl_secs);
    }

    /// Only `side`'s held asks are still within their TTL.
    pub(crate) fn held_retain_side(&mut self, side: usize) {
        self.held.retain(|h| h.side == side);
    }

    /// `side`'s connection closed: its held asks go, and each blinded row it
    /// is a slot of is torn down with `CircuitClosed` to the other slot
    /// (R15, collapsed to now). Identity circuits stay (v2 resume).
    pub(crate) fn leave(&mut self, side: usize) -> Vec<(usize, Frame)> {
        self.held.retain(|h| h.side != side);
        let mut out = Vec::new();
        let (gone, keep): (Vec<FakeRow>, Vec<FakeRow>) = std::mem::take(&mut self.rows)
            .into_iter()
            .partition(|r| r.slots.0 == side || r.slots.1 == side);
        self.rows = keep;
        for r in gone {
            self.routes.remove(&r.circuits.0 .0);
            self.routes.remove(&r.circuits.1 .0);
            let (other, cid) = if r.slots.0 == side {
                (r.slots.1, r.circuits.1.clone())
            } else {
                (r.slots.0, r.circuits.0.clone())
            };
            out.push((other, Self::closed(cid)));
        }
        out
    }

    fn closed(circuit_id: CircuitId) -> Frame {
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id,
            reason: crate::protocol::CircuitCloseReason::Normal,
        })
    }

    fn pair(
        &mut self,
        earlier: FakeHeld,
        caller: FakeHeld,
        blind: Option<[u8; 32]>,
    ) -> Vec<(usize, Frame)> {
        let (c_i, c_r) = self.fresh_circuits();
        // Each side sends on the other's circuit.
        self.routes.insert(c_i.0, earlier.side);
        self.routes.insert(c_r.0, caller.side);
        let bundle = |s: usize| PeerBundle::from_signed(self.bundles[s].as_ref().expect("joined"));
        let frame = |role: u8, cid: &CircuitId, tid: &CircuitId, peer: PeerBundle| {
            Frame::Control(ControlMessage::CircuitCreatedV3 {
                circuit_id: cid.clone(),
                token: TOKEN.to_vec(),
                target_circuit_id: tid.clone(),
                role,
                peer,
                initiator_ephemeral_key: earlier.ek.clone(),
                responder_ephemeral_key: caller.ek.clone(),
                initiator_kem_ephemeral_pk: earlier.kem.clone(),
                responder_kem_ephemeral_pk: caller.kem.clone(),
                initiator_ephemeral_sig: earlier.sig.clone(),
                responder_ephemeral_sig: caller.sig.clone(),
            })
        };
        let mut out = vec![
            (earlier.side, frame(0, &c_i, &c_r, bundle(caller.side))),
            (caller.side, frame(1, &c_r, &c_i, bundle(earlier.side))),
        ];
        if let Some(side) = self.drop_created_once.take() {
            out.retain(|(to, _)| *to != side);
        }
        if let Some(token) = blind {
            self.rows.push(FakeRow {
                token,
                slots: (earlier.side, caller.side),
                circuits: (c_i, c_r),
            });
        }
        self.pairs
            .push((earlier.side, caller.side, blind.is_some()));
        out
    }

    /// One control frame from `side`; returns the frames the relay sends.
    pub(crate) fn control(&mut self, side: usize, msg: ControlMessage) -> Vec<(usize, Frame)> {
        let ik = self.sides[side];
        match msg {
            ControlMessage::CircuitAskBlind {
                pair_token,
                ephemeral_key,
                kem_ephemeral_pk,
                ephemeral_sig,
                pad,
            } => {
                assert_eq!(pad, vec![0; crate::protocol::BLIND_PAD_LEN], "pad all zero");
                let token: [u8; 32] = pair_token.as_slice().try_into().expect("32-byte token");
                self.blind_asks.push((side, token));
                if let Some(pos) = self.rows.iter().position(|r| r.token == token) {
                    let mut out = Vec::new();
                    let r = &self.rows[pos];
                    if r.slots.0 == side || r.slots.1 == side {
                        let r = self.rows.remove(pos);
                        self.routes.remove(&r.circuits.0 .0);
                        self.routes.remove(&r.circuits.1 .0);
                        out.push((r.slots.0, Self::closed(r.circuits.0.clone())));
                        out.push((r.slots.1, Self::closed(r.circuits.1.clone())));
                    }
                    self.busy.push(side);
                    out.push((
                        side,
                        Frame::Control(ControlMessage::PairTokenBusy { ephemeral_key }),
                    ));
                    return out;
                }
                let me = FakeHeld {
                    at: self.now_secs,
                    side,
                    ik,
                    ek: ephemeral_key,
                    kem: kem_ephemeral_pk,
                    sig: ephemeral_sig,
                    key: FakeAskKey::Blind(token),
                };
                let found = self
                    .held
                    .iter()
                    .position(|h| h.key == FakeAskKey::Blind(token));
                match found {
                    Some(pos) if self.held[pos].ik == ik => {
                        self.held[pos] = me; // replay: the newer replaces
                        Vec::new()
                    }
                    Some(pos) => {
                        let earlier = self.held.remove(pos);
                        self.pair(earlier, me, Some(token))
                    }
                    None => {
                        self.held.push(me);
                        Vec::new()
                    }
                }
            }
            ControlMessage::CircuitAsk {
                target_identity,
                ephemeral_key,
                kem_ephemeral_pk,
                ephemeral_sig,
                knock,
                resume_circuit,
            } => {
                self.identity_asks
                    .push((side, target_identity.clone(), resume_circuit));
                let target: [u8; 32] = target_identity.as_slice().try_into().expect("target");
                let me = FakeHeld {
                    at: self.now_secs,
                    side,
                    ik,
                    ek: ephemeral_key,
                    kem: kem_ephemeral_pk,
                    sig: ephemeral_sig,
                    key: FakeAskKey::Identity(target),
                };
                let found = self
                    .held
                    .iter()
                    .position(|h| h.key == FakeAskKey::Identity(ik) && h.ik == target);
                if let Some(pos) = found {
                    let earlier = self.held.remove(pos);
                    return self.pair(earlier, me, None);
                }
                self.held
                    .retain(|h| !(h.ik == ik && h.key == FakeAskKey::Identity(target)));
                self.held.push(me);
                match self.side_of(&target) {
                    Some(t) => vec![(t, queued(knock))],
                    None => Vec::new(),
                }
            }
            ControlMessage::CloseCircuit { circuit_id } => {
                self.closes.push((side, circuit_id.clone()));
                // A member's close tears the pair down; the other member is
                // told `CircuitClosed` (H2).
                let mut out = Vec::new();
                if let Some(pos) = self.identity_rows.iter().position(|((ca, sa), (cb, sb))| {
                    (*ca == circuit_id && *sa == side) || (*cb == circuit_id && *sb == side)
                }) {
                    let ((ca, sa), (cb, sb)) = self.identity_rows.remove(pos);
                    self.routes.remove(&ca.0);
                    self.routes.remove(&cb.0);
                    let (other, cid) = if sa == side { (sb, cb) } else { (sa, ca) };
                    out.push((other, Self::closed(cid)));
                }
                if let Some(pos) = self.rows.iter().position(|r| {
                    (r.circuits.0 == circuit_id && r.slots.0 == side)
                        || (r.circuits.1 == circuit_id && r.slots.1 == side)
                }) {
                    let r = self.rows.remove(pos);
                    self.routes.remove(&r.circuits.0 .0);
                    self.routes.remove(&r.circuits.1 .0);
                    let (other, cid) = if r.slots.0 == side {
                        (r.slots.1, r.circuits.1)
                    } else {
                        (r.slots.0, r.circuits.0)
                    };
                    out.push((other, Self::closed(cid)));
                }
                out
            }
            _ => Vec::new(),
        }
    }

    /// One relay packet from `side`, routed by its circuit.
    pub(crate) fn packet(&mut self, side: usize, p: RelayPacket) -> Vec<(usize, Frame)> {
        let clear_id: Option<[u8; 16]> = p.payload.get(1..17).and_then(|b| b.try_into().ok());
        if self.drop_from.contains(&side) || clear_id.is_some_and(|id| self.drop_ids.contains(&id))
        {
            return Vec::new();
        }
        match self.routes.get(&p.circuit_id.0).copied() {
            Some(to) => {
                let ack = p.payload.get(1..17).map(hex::encode).map(|message_id| {
                    Frame::Control(ControlMessage::MessageAck {
                        message_id,
                        sender_identity: String::new(),
                        recipient_identity: String::new(),
                        timestamp: 0,
                    })
                });
                let mut out = vec![(to, Frame::Relay(p))];
                if let Some(a) = ack {
                    out.push((side, a));
                }
                out
            }
            None => vec![(
                side,
                Frame::Control(ControlMessage::Error {
                    code: crate::protocol::ControlErrorCode::CircuitNotFound,
                    message: format!(
                        "{}{}",
                        crate::protocol::CIRCUIT_NOT_FOUND_PREFIX,
                        hex::encode(p.circuit_id.0)
                    ),
                }),
            )],
        }
    }
}

/// Control and relay frames `rx` holds, in order (signaling dropped).
pub(crate) fn split_sent(rx: &mut Receiver<Vec<u8>>) -> Vec<Result<ControlMessage, RelayPacket>> {
    drain(rx)
        .iter()
        .filter_map(|f| match f.first() {
            Some(&crate::protocol::FRAME_TYPE_CONTROL) => ControlMessage::decode(f).map(Ok),
            Some(_) => RelayPacket::decode(f).map(Err),
            None => None,
        })
        .collect()
}

/// Run `clients` (side = index) against `relay` until nothing more is sent.
pub(crate) fn pump(
    relay: &mut FakeRelay,
    clients: &mut [(&mut ClientInner, &mut Receiver<Vec<u8>>)],
) {
    for _ in 0..64 {
        let mut out: Vec<(usize, Frame)> = Vec::new();
        for (side, (_, rx)) in clients.iter_mut().enumerate() {
            for f in split_sent(rx) {
                match f {
                    Ok(c) => out.extend(relay.control(side, c)),
                    Err(p) => out.extend(relay.packet(side, p)),
                }
            }
        }
        if out.is_empty() {
            return;
        }
        for (to, frame) in out {
            feed(clients[to].0, frame);
        }
    }
    panic!("the fake relay never went quiet");
}

/// `pump` with only side 0 connected: frames for any other side are lost.
pub(crate) fn pump_alone(relay: &mut FakeRelay, a: &mut ClientInner, rx: &mut Receiver<Vec<u8>>) {
    for _ in 0..64 {
        let mut out: Vec<(usize, Frame)> = Vec::new();
        for f in split_sent(rx) {
            match f {
                Ok(c) => out.extend(relay.control(0, c)),
                Err(p) => out.extend(relay.packet(0, p)),
            }
        }
        out.retain(|(to, _)| *to == 0);
        if out.is_empty() {
            return;
        }
        for (_, frame) in out {
            feed(a, frame);
        }
    }
    panic!("the fake relay never went quiet");
}

/// Reconnect `inner` on its existing channel: the transport is replaced,
/// the hello answered and the publish accepted (`after_publish_ok` runs).
pub(crate) fn reconnect_in_place(inner: &mut ClientInner, rx: &mut Receiver<Vec<u8>>) {
    drain(rx);
    inner.handle_transport_reconnected();
    feed_signaling(inner, hello_response([0x4f; 32]));
    feed_signaling(inner, publish_ok([0x56; 32]));
    assert!(inner.is_key_bundle_published, "publish accepted");
}

/// Keep `peer_hex` on the identity path (as after its knock, Task 9), so
/// the pre-v3 resume of its identity circuit applies: v2 resume stays for
/// identity circuits before their first blind epoch only.
pub(crate) fn keep_identity_path(inner: &mut ClientInner, peer_hex: &str) {
    inner.identity_wanted.insert(
        peer_hex.to_string(),
        crate::blind::IdentityWanted {
            no_prior_session: true,
            asked: None,
        },
    );
}

/// The blind asks in `sent`.
pub(crate) fn blind_asks_in(sent: &[ControlMessage]) -> usize {
    sent.iter()
        .filter(|m| matches!(m, ControlMessage::CircuitAskBlind { .. }))
        .count()
}
