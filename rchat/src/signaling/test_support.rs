//! Shared helpers for the relay's socket-level tests: real keypairs, signed
//! publishes over the `--no-tls` dev binding, and frame readers. The
//! helpers are generic over the stream so TLS tests can use them too.

use super::*;
use crate::protocol::signaling::{
    ClientInfo, ErrorPayload, HelloPayload, HelloResponsePayload, KeyBundle,
    PublishKeyBundlePayload, PublishKeyBundleResponsePayload, MSG_TYPE_ERROR, MSG_TYPE_HELLO,
    MSG_TYPE_HELLO_RESPONSE, MSG_TYPE_PUBLISH_KEY_BUNDLE, MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE,
};
use rchat_core::crypto::IdentityKeyPair;
use rchat_core::keyauth::{self, SignedBundle};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// `dev_origin` of every plaintext test relay. Clients compute the same
/// binding from it (`dev_binding`).
pub(super) const DEV_ORIGIN: &str = "ws://127.0.0.1:18443";

pub(super) type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Loopback, `--no-tls`, no per-IP cap, `dev_origin` set. The offline
/// queue is memory-only by default, so nothing is written under `~/.rchat`.
pub(super) fn test_config() -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        insecure_no_tls: true,
        max_connections_per_ip: 0,
        dev_origin: Some(DEV_ORIGIN.to_string()),
        ..ServerConfig::default()
    }
}

/// The binding a client of a `test_config()` relay signs over.
pub(super) fn dev_binding() -> [u8; 32] {
    keyauth::dev_origin_binding(&keyauth::relay_origin(DEV_ORIGIN).unwrap()).unwrap()
}

/// A real identity with its signed bundle.
#[derive(Clone)]
pub(super) struct TestIdentity {
    pub keys: IdentityKeyPair,
    pub bundle: SignedBundle,
    pub hex: String,
    pub bytes: [u8; 32],
}

impl TestIdentity {
    fn from_seed64(seed: [u8; 64]) -> Self {
        let keys = IdentityKeyPair::from_seed(&seed).expect("64-byte seed");
        let bundle = keyauth::sign_bundle(&keys).expect("sign bundle");
        let bytes = bundle.identity_key;
        Self {
            keys,
            bundle,
            hex: hex::encode(bytes),
            bytes,
        }
    }

    /// Deterministic identity from `[b; 64]`.
    pub fn from_seed(b: u8) -> Self {
        Self::from_seed64([b; 64])
    }

    pub fn random() -> Self {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&rand::random::<[u8; 32]>());
        seed[32..].copy_from_slice(&rand::random::<[u8; 32]>());
        Self::from_seed64(seed)
    }

    /// A random identity whose hex starts with the nibble `n` (0..=15), for
    /// tests that need a known ordering.
    pub fn with_first_nibble(n: u8) -> Self {
        let want = char::from_digit(u32::from(n), 16).expect("nibble 0..=15");
        loop {
            let id = Self::random();
            if id.hex.starts_with(want) {
                return id;
            }
        }
    }
}

/// Start a relay; returns its address and shared state.
pub(super) async fn start(config: ServerConfig) -> (SocketAddr, RelayState) {
    let server = Server::new(config).await.expect("server starts");
    let addr = server.local_addr().expect("bound");
    let state = server.state();
    tokio::spawn(server.run());
    (addr, state)
}

pub(super) async fn connect(addr: SocketAddr) -> Ws {
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        connect_async(format!("ws://{addr}/")),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    ws
}

/// A signaling `hello` offering `versions`.
pub(super) fn hello_message(versions: Vec<u32>) -> Message {
    UnifiedFrame::signaling(SignalingMessage::new(
        MSG_TYPE_HELLO,
        SignalingPayload::new(
            MSG_TYPE_HELLO,
            HelloPayload {
                supported_versions: versions,
                capabilities: vec![
                    "key-auth-v1".into(),
                    "sealed-relay-v1".into(),
                    "mutual-circuits-v1".into(),
                ],
                client_info: ClientInfo {
                    name: "test".into(),
                    version: "2".into(),
                    platform: "test".into(),
                },
            },
        ),
    ))
    .encode()
}

/// Say hello (v3) and return the relay's auth challenge.
pub(super) async fn hello<S>(ws: &mut WebSocketStream<S>) -> [u8; 32]
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(hello_message(vec![3])).await.expect("send hello");
    let reply = next_signaling(ws, MSG_TYPE_HELLO_RESPONSE, Duration::from_secs(5))
        .await
        .expect("hello_response");
    let p: HelloResponsePayload = reply.payload.deserialize_data().expect("hello payload");
    assert_eq!(p.selected_version, 3);
    let challenge = hex::decode(p.auth_challenge.expect("auth_challenge")).expect("hex");
    challenge.try_into().expect("32-byte challenge")
}

/// The hex key bundle of `id`.
pub(super) fn key_bundle_of(id: &TestIdentity) -> KeyBundle {
    KeyBundle {
        identity_key: id.hex.clone(),
        identity_agreement_key: hex::encode(id.bundle.identity_agreement_key),
        kem_pk: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &id.bundle.kem_pk[..],
        ),
        bundle_signature: hex::encode(id.bundle.bundle_signature),
        one_time_pre_keys: Vec::new(),
    }
}

/// A publish frame with an arbitrary bundle and proof (for forgeries).
pub(super) fn raw_publish(key_bundle: KeyBundle, conn_signature: &[u8]) -> Message {
    UnifiedFrame::signaling(SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        SignalingPayload::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            PublishKeyBundlePayload {
                key_bundle,
                conn_signature: hex::encode(conn_signature),
            },
        ),
    ))
    .encode()
}

/// A correctly signed publish of `id` over `nonce` and `binding`.
pub(super) fn publish_message(id: &TestIdentity, nonce: &[u8; 32], binding: &[u8; 32]) -> Message {
    let sig = keyauth::sign_conn(&id.keys, nonce, binding, &id.bundle).expect("sign conn");
    raw_publish(key_bundle_of(id), &sig)
}

/// What came back for a publish.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PublishReply {
    /// Accepted; carries `next_challenge`.
    Ok([u8; 32]),
    /// A signaling error; carries the payload JSON.
    Error(String),
    Closed,
}

/// Read until the publish is answered.
pub(super) async fn publish_reply<S>(ws: &mut WebSocketStream<S>) -> PublishReply
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Err(_) => panic!("no reply to publish"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {
                return PublishReply::Closed
            }
            Ok(Some(Ok(m))) => match UnifiedFrame::decode(&m) {
                Ok(UnifiedFrame::Signaling(s))
                    if s.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE =>
                {
                    let p: PublishKeyBundleResponsePayload =
                        s.payload.deserialize_data().expect("publish response");
                    let next = hex::decode(p.next_challenge.expect("next_challenge")).unwrap();
                    return PublishReply::Ok(next.try_into().expect("32 bytes"));
                }
                Ok(UnifiedFrame::Signaling(s)) if s.msg_type == MSG_TYPE_ERROR => {
                    return PublishReply::Error(serde_json::to_string(&s.payload).unwrap())
                }
                _ => continue,
            },
        }
    }
}

/// Send a signed publish and read the reply.
pub(super) async fn send_publish<S>(
    ws: &mut WebSocketStream<S>,
    id: &TestIdentity,
    nonce: &[u8; 32],
    binding: &[u8; 32],
) -> PublishReply
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if ws.send(publish_message(id, nonce, binding)).await.is_err() {
        return PublishReply::Closed;
    }
    publish_reply(ws).await
}

/// hello + signed publish over the dev binding; returns `next_challenge`.
pub(super) async fn publish<S>(ws: &mut WebSocketStream<S>, id: &TestIdentity) -> [u8; 32]
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nonce = hello(ws).await;
    match send_publish(ws, id, &nonce, &dev_binding()).await {
        PublishReply::Ok(next) => next,
        other => panic!("publish failed: {other:?}"),
    }
}

/// Connect and prove `id`.
pub(super) async fn authed(addr: SocketAddr, id: &TestIdentity) -> Ws {
    let mut ws = connect(addr).await;
    publish(&mut ws, id).await;
    ws
}

/// Next signaling message of `msg_type`, skipping everything else.
pub(super) async fn next_signaling<S>(
    ws: &mut WebSocketStream<S>,
    msg_type: &str,
    wait: Duration,
) -> Option<SignalingMessage>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Ok(Some(Ok(m))) => {
                if let Ok(UnifiedFrame::Signaling(s)) = UnifiedFrame::decode(&m) {
                    if s.msg_type == msg_type {
                        return Some(s);
                    }
                }
            }
            _ => return None,
        }
    }
}

/// Next control message, skipping everything else.
pub(super) async fn next_control<S>(
    ws: &mut WebSocketStream<S>,
    wait: Duration,
) -> Option<ControlMessage>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Ok(Some(Ok(m))) => {
                if let Ok(UnifiedFrame::Control(c)) = UnifiedFrame::decode(&m) {
                    // The queue-handed-over marker follows every publish
                    // (R34a); tests that look for it read raw frames.
                    if !matches!(c, ControlMessage::QueueHandedOver { .. }) {
                        return Some(c);
                    }
                }
            }
            _ => return None,
        }
    }
}

/// Every non-keepalive frame until the connection is quiet for `quiet`.
pub(super) async fn frames_until_quiet<S>(
    ws: &mut WebSocketStream<S>,
    quiet: Duration,
) -> Vec<UnifiedFrame>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut frames = Vec::new();
    while let Ok(Some(Ok(m))) = tokio::time::timeout(quiet, ws.next()).await {
        match UnifiedFrame::decode(&m) {
            Ok(UnifiedFrame::Keepalive(_)) | Err(_) => {}
            Ok(frame) if is_marker(&frame) => {}
            Ok(frame) => frames.push(frame),
        }
    }
    frames
}

/// The queue-handed-over marker every publish ends with (R34a).
pub(super) fn is_marker(frame: &UnifiedFrame) -> bool {
    matches!(
        frame,
        UnifiedFrame::Control(ControlMessage::QueueHandedOver { .. })
    )
}

/// Every non-keepalive frame until the relay closes the connection; panics
/// if it is still open after `wait`.
pub(super) async fn frames_until_closed<S>(
    ws: &mut WebSocketStream<S>,
    wait: Duration,
) -> Vec<UnifiedFrame>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + wait;
    let mut frames = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => panic!("connection still open after {wait:?}"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return frames,
            Ok(Some(Ok(m))) => match UnifiedFrame::decode(&m) {
                Ok(UnifiedFrame::Keepalive(_)) | Err(_) => {}
                Ok(frame) if is_marker(&frame) => {}
                Ok(frame) => frames.push(frame),
            },
        }
    }
}

/// True if the relay closes the connection within `wait`.
pub(super) async fn closed_within<S>(ws: &mut WebSocketStream<S>, wait: Duration) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return false,
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// The `code` of the first signaling error among `frames`, as its Debug name.
pub(super) fn signaling_error_code(frames: &[UnifiedFrame]) -> Option<String> {
    frames.iter().find_map(|f| match f {
        UnifiedFrame::Signaling(s) if s.msg_type == MSG_TYPE_ERROR => s
            .payload
            .deserialize_data::<ErrorPayload>()
            .ok()
            .map(|p| format!("{:?}", p.code)),
        _ => None,
    })
}

/// A `KNOCK_BYTES` (5120) knock-v3-shaped knock (the relay never opens it).
pub(super) fn knock(fill: u8) -> Vec<u8> {
    let mut k = vec![fill; crate::validate::KNOCK_BYTES];
    k[0] = crate::validate::KNOCK_VERSION;
    k
}

/// Poll `cond` every 50 ms for up to 5 s.
pub(super) async fn eventually(what: &str, cond: impl FnMut() -> bool) {
    eventually_within(what, Duration::from_secs(5), cond).await;
}

/// Poll `cond` every 50 ms until it holds; panic after `within`.
pub(super) async fn eventually_within(
    what: &str,
    within: Duration,
    mut cond: impl FnMut() -> bool,
) {
    let deadline = Instant::now() + within;
    while !cond() {
        if Instant::now() >= deadline {
            panic!("timed out after {within:?} waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A connection record with no socket behind it; the receiver gets
/// whatever the relay queues for it.
pub(super) fn bare_connection(
    channel_binding: [u8; 32],
) -> (
    UnifiedConnection,
    tokio::sync::mpsc::Receiver<crate::limits::Outbound>,
) {
    let (tx, rx, _kill) = ConnTx::channel();
    let id = ClientId::generate();
    let now = Instant::now();
    (
        UnifiedConnection {
            client_id: id,
            _addr: "127.0.0.1:1".parse().unwrap(),
            ws_tx: tx,
            key_bundle: None,
            identity_key: None,
            last_activity: now,
            circuits: Arc::new(DashMap::new()),
            last_pong: now,
            pending_ping: None,
            identified: false,
            created_circuits: Default::default(),
            pending_charges: Default::default(),
            protocol_version: 0,
            auth_nonce: None,
            channel_binding,
            proven_identity: None,
            closing: false,
            auth_budget: crate::limits::AuthBudget::new(Instant::now()),
            source: None,
            has_asked: false,
            blind_ask_bucket: None,
            peer_bundle: None,
        },
        rx,
    )
}

/// Put one stored message in `recipient`'s offline queue.
pub(super) fn queue_test_message(state: &RelayState, recipient: &TestIdentity, payload: Vec<u8>) {
    queue_test_message_at(state, recipient, payload, crate::protocol::timestamp());
}

/// Put one stored message in `recipient`'s offline queue, stored at
/// `enqueued_at` (unix seconds).
pub(super) fn queue_test_message_at(
    state: &RelayState,
    recipient: &TestIdentity,
    payload: Vec<u8>,
    enqueued_at: u64,
) {
    let msg = StoredMessage {
        payload,
        enqueued_at_unix_secs: enqueued_at,
        is_knock: false,
        knock_seq: 0,
    };
    let cost = msg.budget_cost();
    state.offline_budget.force_add(cost);
    let mut queue = state
        .message_queues
        .entry(id_tag(&recipient.bytes))
        .or_default();
    queue.bytes += cost;
    queue.pending.push(msg);
}

/// How many records wait in `recipient`'s offline queue.
pub(super) fn queued_len(state: &RelayState, recipient: &TestIdentity) -> usize {
    state
        .message_queues
        .get(&id_tag(&recipient.bytes))
        .map(|q| q.pending.len())
        .unwrap_or(0)
}

/// How many knocks wait in `recipient`'s offline queue.
pub(super) fn queued_knocks(state: &RelayState, recipient: &TestIdentity) -> usize {
    state
        .message_queues
        .get(&id_tag(&recipient.bytes))
        .map(|q| q.pending.iter().filter(|m| m.is_knock).count())
        .unwrap_or(0)
}

/// The connection `id` is routed to, if any.
pub(super) fn mapped_client(state: &RelayState, id: &TestIdentity) -> Option<ClientId> {
    state.identity_to_client.get(&id_tag(&id.bytes)).map(|c| *c)
}

/// The test ML-KEM-768 ephemeral of an ask whose X25519 ephemeral is `ek`:
/// `ek` repeated 37 times (exactly 1184 bytes), so a test can tell which
/// ask a forwarded KEM ephemeral came from. The relay checks only its size.
pub(super) fn kem_for(ek: [u8; 32]) -> Box<circuits::AskEphemerals> {
    let v = ek.repeat(crate::validate::KEM_PK_BYTES / 32);
    Box::new(circuits::AskEphemerals {
        kem: v.try_into().expect("1184 bytes"),
        sig: sig_for(ek),
    })
}

/// A stand-in ephemeral signature derived from `ek` (the relay never
/// verifies it, R7): 64 bytes, distinct per ask.
pub(super) fn sig_for(ek: [u8; 32]) -> [u8; crate::validate::ASK_EPH_SIG_BYTES] {
    let mut s = [0u8; 64];
    s[..32].copy_from_slice(&ek);
    s[32..].copy_from_slice(&ek);
    s[0] ^= 0x5a;
    s
}

/// The all-zero resume id a client sends when it resumes nothing (the
/// relay refuses an ask whose `resume_circuit` is `None`, §C.2).
pub(super) const NO_RESUME: CircuitId = CircuitId([0; 16]);

/// `CircuitAsk` for `target` with a filler knock (KEM ephemeral
/// `kem_for(ek)`). `None` is sent as `Some(NO_RESUME)`, as the core does.
pub(super) fn ask(target: &TestIdentity, ek: [u8; 32], resume: Option<CircuitId>) -> Message {
    FrameBuilder::circuit_ask(
        target.bytes.to_vec(),
        ek.to_vec(),
        kem_for(ek).kem.to_vec(),
        sig_for(ek).to_vec(),
        knock(0x5a),
        Some(resume.unwrap_or(NO_RESUME)),
    )
    .encode()
}

/// `CircuitAsk` for `target` carrying `knock`.
pub(super) fn ask_with_knock(target: &TestIdentity, ek: [u8; 32], knock: Vec<u8>) -> Message {
    FrameBuilder::circuit_ask(
        target.bytes.to_vec(),
        ek.to_vec(),
        kem_for(ek).kem.to_vec(),
        sig_for(ek).to_vec(),
        knock,
        Some(NO_RESUME),
    )
    .encode()
}

/// `asker` asks `target` on `ws` (ephemeral key `ek`) and returns once the
/// relay holds that pending ask, so an ask back from `target` finds it.
/// Waits on the relay's state, never a fixed sleep.
pub(super) async fn ask_held<S>(
    ws: &mut WebSocketStream<S>,
    state: &RelayState,
    asker: &TestIdentity,
    target: &TestIdentity,
    ek: [u8; 32],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(ask(target, ek, None)).await.unwrap();
    let pair = super::tags::pair_tag(&asker.bytes, &target.bytes);
    let asker_tag = id_tag(&asker.bytes);
    eventually("the first ask to be held", || {
        state
            .pending_asks
            .get(&pair)
            .is_some_and(|p| p.asker_tag == asker_tag)
    })
    .await;
}

/// Pair two clients: `a` (on `wa`) asks `b`, and `b` (on `wb`) asks back
/// once the relay holds `a`'s ask, so `a` is the initiator (role 0). The
/// two `CircuitCreatedV3` frames are left for the caller to read.
pub(super) async fn ask_each_other<S>(
    state: &RelayState,
    wa: &mut WebSocketStream<S>,
    a: &TestIdentity,
    wb: &mut WebSocketStream<S>,
    b: &TestIdentity,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ask_held(wa, state, a, b, rand::random()).await;
    wb.send(ask(a, rand::random(), None)).await.unwrap();
}

/// Test-only verifier: the TLS relays here use throwaway self-signed certs.
#[derive(Debug)]
pub(super) struct AcceptAnyCert(pub(super) Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub(super) type TlsWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// A TLS 1.3 relay with a fresh self-signed certificate; returns its
/// address and shared state.
pub(super) async fn tls_relay() -> (SocketAddr, RelayState) {
    tls_relay_with(|_| {}).await
}

/// `tls_relay`, with `adjust` applied to its config before it starts.
pub(super) async fn tls_relay_with(
    adjust: impl FnOnce(&mut ServerConfig),
) -> (SocketAddr, RelayState) {
    let dir = std::env::temp_dir().join(format!(
        "rchat-keyauth-tls-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
    let mut config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        max_connections_per_ip: 0,
        tls: Some(crate::config::TlsConfig::static_cert(cert_path, key_path)),
        ..ServerConfig::default()
    };
    adjust(&mut config);
    let started = start(config).await;
    // The certificate is loaded at start; the files are not needed again.
    let _ = std::fs::remove_dir_all(&dir);
    started
}

/// A WebSocket over TLS 1.3, plus this TLS session's exporter as the client
/// sees it (the channel binding a publish on it must sign).
pub(super) async fn tls_ws(addr: SocketAddr) -> (TlsWs, [u8; 32]) {
    tls_ws_after(addr, &[]).await.expect("TLS WebSocket")
}

/// `tls_ws` over a TCP stream that first sends `prefix` in the clear (a
/// PROXY v2 header, as a layer-4 front end would). An error if the relay
/// closes the connection before the WebSocket is up.
pub(super) async fn tls_ws_after(
    addr: SocketAddr,
    prefix: &[u8],
) -> std::io::Result<(TlsWs, [u8; 32])> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    let mut tcp = TcpStream::connect(addr).await?;
    tokio::io::AsyncWriteExt::write_all(&mut tcp, prefix).await?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .map_err(|_| std::io::Error::other("TLS handshake timed out"))??;
    let binding = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 32], keyauth::EXPORTER_LABEL, Some(b"".as_slice()))
        .unwrap();
    let (ws, _) = tokio_tungstenite::client_async(format!("ws://localhost:{}/", addr.port()), tls)
        .await
        .map_err(std::io::Error::other)?;
    Ok((ws, binding))
}

/// A proven connection record for `id` with no socket behind it, from the
/// given source bucket, registered in `state` (for state-level fairness
/// tests that drive the handlers directly).
pub(super) fn proven_bare(
    state: &RelayState,
    id: &TestIdentity,
    source: Option<crate::limits::SourceKey>,
) -> (
    ClientId,
    tokio::sync::mpsc::Receiver<crate::limits::Outbound>,
) {
    let (mut conn, rx) = bare_connection([0u8; 32]);
    conn.protocol_version = crate::protocol::PROTOCOL_VERSION;
    conn.proven_identity = Some(id.bytes);
    conn.key_bundle = Some(key_bundle_of(id));
    conn.identity_key = Some(id.hex.clone());
    conn.identified = true;
    conn.source = source;
    let client = conn.client_id;
    state.connections.insert(client, conn);
    state.identity_to_client.insert(id_tag(&id.bytes), client);
    (client, rx)
}

/// A distinct test source bucket.
pub(super) fn source_key(n: u8) -> crate::limits::SourceKey {
    crate::limits::SourceKey([n; 32])
}

/// `caller` asks for a circuit with `target` through the real handler.
pub(super) async fn ask_direct(state: &RelayState, caller: ClientId, target: &TestIdentity) {
    circuits::handle_circuit_ask(
        caller,
        target.bytes,
        [7; 32],
        kem_for([7; 32]),
        knock(0x5a),
        None,
        state,
    )
    .await;
}

/// The next `CircuitCreatedV3`: (own circuit id, token, peer circuit id).
pub(super) async fn created(ws: &mut Ws) -> (CircuitId, Vec<u8>, CircuitId) {
    loop {
        match next_control(ws, Duration::from_secs(3)).await {
            Some(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                token,
                target_circuit_id,
                ..
            }) => return (circuit_id, token, target_circuit_id),
            Some(_) => continue,
            None => panic!("no CircuitCreatedV3"),
        }
    }
}

/// A relay packet to `target_circuit`, authenticated with `my_token`.
pub(super) fn relay_on(target_circuit: CircuitId, my_token: &[u8], payload: Vec<u8>) -> Message {
    let mut key = [0u8; 32];
    key.copy_from_slice(my_token);
    let token = crate::protocol::relay::CircuitToken {
        circuit_id: target_circuit,
        key,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    let mut p = crate::protocol::relay::RelayPacket::new(target_circuit, payload.clone());
    p.auth_tag = token.authenticate(&target_circuit, &payload);
    UnifiedFrame::relay(p).encode()
}

/// A `CircuitCreatedV3` as one member received it.
#[derive(Debug, Clone)]
pub(super) struct Created {
    pub circuit_id: CircuitId,
    pub token: Vec<u8>,
    pub target_circuit_id: CircuitId,
    pub role: u8,
}

/// The next control message matching `want`, skipping others (3 s each).
pub(super) async fn until_control(
    ws: &mut Ws,
    want: impl Fn(&ControlMessage) -> bool,
) -> Option<ControlMessage> {
    loop {
        match next_control(ws, Duration::from_secs(3)).await {
            Some(m) if want(&m) => return Some(m),
            Some(_) => continue,
            None => return None,
        }
    }
}

/// The next `CircuitCreatedV3`; panics if none arrives.
pub(super) async fn until_created(ws: &mut Ws) -> Created {
    match until_control(ws, |m| matches!(m, ControlMessage::CircuitCreatedV3 { .. })).await {
        Some(ControlMessage::CircuitCreatedV3 {
            circuit_id,
            token,
            target_circuit_id,
            role,
            ..
        }) => Created {
            circuit_id,
            token,
            target_circuit_id,
            role,
        },
        other => panic!("expected CircuitCreatedV3, got {other:?}"),
    }
}

/// A and B ask each other; returns both sockets and both CircuitCreatedV3.
pub(super) async fn pair_up(
    state: &RelayState,
    addr: SocketAddr,
    a: &TestIdentity,
    b: &TestIdentity,
) -> (Ws, Ws, Created, Created) {
    let mut wa = authed(addr, a).await;
    let mut wb = authed(addr, b).await;
    ask_each_other(state, &mut wa, a, &mut wb, b).await;
    let ca = until_created(&mut wa).await;
    let cb = until_created(&mut wb).await;
    assert_eq!(ca.target_circuit_id, cb.circuit_id);
    assert_eq!(cb.target_circuit_id, ca.circuit_id);
    (wa, wb, ca, cb)
}
