//! RChat Core Library
//!
//! A unified Rust library for RChat clients, providing:
//! - End-to-end encryption (X3DH + Double Ratchet)
//! - WebSocket transport with delivery confirmation
//! - Protocol serialization
//!
//! This library is used by the native clients via UniFFI bindings (Swift) or the C FFI.

// Pre-existing lint debt (baseline ad29473). New code must be clean
// without these; drop entries as the code they cover is rewritten.
#![allow(
    clippy::collapsible_match,
    clippy::doc_overindented_list_items,
    clippy::empty_line_after_doc_comments,
    clippy::get_first,
    clippy::io_other_error,
    clippy::len_zero,
    clippy::match_single_binding,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::single_component_path_imports,
    clippy::single_match,
    clippy::type_complexity,
    clippy::unnecessary_lazy_evaluations,
    clippy::unnecessary_map_or,
    clippy::unnecessary_unwrap,
    clippy::useless_conversion
)]

use log;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod acks;
#[cfg(test)]
mod alloc_probe;
pub mod blind;
#[cfg(test)]
mod blind_flow_tests;
mod circuits;
pub mod crypto;
pub mod device_key;
pub mod disappearing;
pub mod drain;
pub mod ffi;
pub mod file_msg;
pub mod invite;
pub mod kem;
pub mod keyauth;
pub mod knock;
pub mod notice;
pub mod padding;
pub mod pairing;
pub mod peers;
mod persistence;
pub mod protocol;
#[cfg(test)]
mod publish_tests;
pub mod receipts;
pub mod relay_pin;
#[cfg(test)]
mod relay_pin_tests;
pub mod rotation;
#[cfg(test)]
mod rotation_flow_tests;
pub mod safety_number;
pub mod sealed;
#[cfg(test)]
mod sealed_flow_tests;
pub mod session;
pub mod session_init;
pub mod state_store;
pub mod status;
pub mod steady;
#[cfg(test)]
mod test_support;
pub mod tls_boring;
pub mod tls_resumption;
#[cfg(test)]
mod tls_resumption_tests;
pub mod transport;

use crypto::IdentityKeyPair;
use keyauth::SignedBundle;
use peers::{PeerBook, PeerKeyState};
use protocol::{classify_signaling, signaling_frame, SignalingEvent, SignalingMessage};
use protocol::{CircuitId, ControlMessage, Frame, MessageId, MessageType, RelayPacket};
use session::SessionManager;
use transport::{TransportConfig, WebSocketClient};

/// Most sealed bodies held for senders whose session does not exist yet.
pub(crate) const MAX_PENDING_ENCRYPTED: usize = 256;

/// Most bodies held for any one claimed sender (C-7). The sender identity
/// inside an envelope is not authenticated until the ratchet opens it, so
/// anyone can claim to be a contact; this keeps one claimed sender from
/// evicting every other contact's held messages.
pub(crate) const MAX_PENDING_PER_SENDER: usize = 64;

/// Total body bytes held for senders whose session does not exist yet.
/// Anyone who knows our public keys (or the relay) can seal envelopes that
/// claim unknown senders, so the buffer is bounded in bytes as well as in
/// entries: when a new body would exceed this, the oldest held bodies are
/// evicted first (newest wins, like the entry cap).
pub(crate) const MAX_PENDING_BYTES: usize = 8 << 20;

/// Largest single body held while its sender has no session. Larger bodies
/// are dropped on arrival rather than evicting up to 8 MiB of other
/// senders' messages; the sender sees no delivery receipt for them.
/// 1 MiB plus room for the ratchet header and AEAD tag, so a body padded to
/// a 1 MiB bucket is still held.
pub(crate) const MAX_PENDING_ENTRY_BYTES: usize = (1 << 20) + 256;

/// Upper bound on the initial-connect attempts an app config may ask for
/// (C-15): each attempt can wait up to 30 s, so more only stalls `connect`.
pub(crate) const MAX_RECONNECT_ATTEMPTS: u32 = 20;

/// Period of the shared timer that fires re-asks, receipts and cover
/// traffic; short enough that a 0.5-3 s receipt deadline is met closely.
pub(crate) const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The shared timer: holds only a `Weak` to the client, so it stops when the
/// client is dropped. Sends go through the current connection's sender, so a
/// retired connection never receives them.
pub(crate) fn spawn_ticker(runtime: &ClientRuntime, weak: std::sync::Weak<RwLock<ClientInner>>) {
    runtime.spawn(async move {
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            let Some(inner) = weak.upgrade() else { break };
            let mut guard = inner.write().await;
            let now = std::time::Instant::now();
            // A background drain (§H.1) sends nothing: `tick` says so.
            let sends = guard.tick(now);
            // Steady slots (§B): their own timer, started only while it
            // should run; it stops itself otherwise.
            if !guard.steady_task_running && guard.steady_should_run() {
                guard.steady_task_running = true;
                steady::spawn_steady(weak.clone(), guard.steady_task_gen, guard.steady.slot());
            }
            drop(guard);
            // Without this a responder's early messages waited for an app
            // that calls `process_pending`; one that doesn't lost them.
            if sends {
                RChatClient::flush_queued_sends(&inner).await;
            }
        }
    });
}

/// How long after a rotation the client accepts a rotated contact's old
/// identity for in-flight messages (spec §4.8).
pub const ROTATION_GRACE_SECS: u64 = 72 * 3600;
/// Minimum time between two rotations of our own identity.
pub const ROTATION_INTERVAL_SECS: u64 = 24 * 3600;
/// Round-2 M3: rotation knocks per 24 h (inside the relay's 100 per asker).
pub const MAX_ROTATION_KNOCKS_PER_DAY: usize = 90;

pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A plaintext the app is handed: text (`0x01`), binary (`0x02`) with a
/// known magic, or a well-formed file (`0x07`, `file_msg::decode_file`
/// would accept it). Shared by delivery and `delivered_unstored` (D36).
pub(crate) fn is_deliverable(plaintext: &[u8]) -> bool {
    // `expire_secs` (4 bytes) follows the type byte (§I.2) and must be one
    // of the timer choices (R33 M-1): anything else is dropped.
    let timer_ok = disappearing::split_expire(plaintext)
        .is_some_and(|(expire, _)| disappearing::valid_timer(expire));
    match plaintext.first() {
        Some(0x01) => timer_ok,
        Some(0x02) => {
            timer_ok
                && disappearing::split_expire(plaintext)
                    .is_some_and(|(_, body)| protocol::is_known_binary(body))
        }
        Some(&file_msg::FILE_TYPE) => timer_ok && file_msg::is_valid(plaintext),
        _ => false,
    }
}

/// Concatenated 196-byte links in hex; anything malformed yields no links.
fn parse_links_hex(s: &str) -> Vec<rotation::RotationLink> {
    let Ok(raw) = hex::decode(s) else {
        return Vec::new();
    };
    if raw.len() % rotation::LINK_LEN != 0 {
        return Vec::new();
    }
    raw.chunks(rotation::LINK_LEN)
        .map(rotation::RotationLink::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

/// A ratchet body that arrived before its sender's session existed.
pub(crate) struct PendingEncrypted {
    pub(crate) sender_hex: String,
    pub(crate) message_id: [u8; 16],
    pub(crate) body: Vec<u8>,
}

/// The client's Tokio runtime. Dropped without blocking (C-23): the last
/// reference may go on a runtime thread (a task, a callback), where dropping
/// a plain `Runtime` panics ("Cannot drop a runtime in a context where
/// blocking is not allowed") and, with panic = abort, kills the app.
pub(crate) struct ClientRuntime(Option<Runtime>);

impl ClientRuntime {
    fn new() -> std::io::Result<Self> {
        Runtime::new().map(|rt| Self(Some(rt)))
    }
}

impl std::ops::Deref for ClientRuntime {
    type Target = Runtime;
    fn deref(&self) -> &Runtime {
        self.0.as_ref().expect("runtime present until drop")
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

/// Capacity of the transport event queue (C-9): beyond it the socket is not
/// read until the event task catches up.
pub(crate) const EVENT_QUEUE_CAPACITY: usize = 1024;

/// How long `set_callbacks` waits for the client lock when it is busy
/// (C-14) before logging and giving up.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a synchronous state query (often from the UI thread) waits for
/// a busy client lock before answering "busy" (N-8).
const QUERY_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Helper function to execute async code from any context
/// This function spawns the future on the runtime and waits for it using a channel
fn block_on_async<M, F, T>(runtime: Arc<ClientRuntime>, make: M) -> Result<T, RChatError>
where
    M: FnOnce() -> F + Send + 'static,
    F: std::future::Future<Output = Result<T, RChatError>>,
    T: Send + 'static,
{
    // Run the block_on from a dedicated thread: this avoids the "Cannot
    // start a runtime from within a runtime" error.
    //
    // The future is built there, by `make`, never here (R31): a future
    // built on the caller's thread was moved, uninitialised slots and all,
    // into the heap box `thread::spawn` makes, and those slots held
    // whatever the caller's stack last held (plaintext a send had just
    // encoded), freed unwiped. The box now holds only `make`'s captures.
    let handle = runtime.handle().clone();

    std::thread::spawn(move || handle.block_on(make()))
        .join()
        .map_err(|e| RChatError::Internal {
            message: format!("Thread panicked: {:?}", e),
        })?
}

/// Main error type for RChat operations
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum RChatError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Not connected")]
    NotConnected,

    #[error("Encryption failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Invalid recipient: {identity}")]
    InvalidRecipient { identity: String },

    #[error("Session not established with {identity}")]
    SessionNotEstablished { identity: String },

    #[error("Message timeout: {message_id}")]
    MessageTimeout { message_id: String },

    #[error("Internal error: {message}")]
    Internal { message: String },

    /// A caller-supplied argument outside its documented range (FFI code 9).
    #[error("Invalid parameter: {message}")]
    InvalidParameter { message: String },

    #[error("No keys are pinned for {identity}")]
    NoPinnedKeys { identity: String },
    #[error("The safety number changed since it was shown")]
    SafetyNumberChanged,

    #[error("key authentication rejected by the relay")]
    KeyAuthRejected,

    #[error("relay and client protocol versions differ; update rChat")]
    ServerTooNew,

    #[error("no channel binding for this connection")]
    NoChannelBinding,

    #[error("The relay could not prove its identity")]
    RelayIdentityInvalid,

    #[error("A saved relay identity is required")]
    RelayPinRequired,

    #[error("The relay's identity changed")]
    RelayIdentityChanged,

    #[error("A different key is already saved for this contact")]
    PinConflict,

    #[error("These keys already belong to another contact")]
    AgreementKeyInUse,

    #[error("Their keys don't match the saved ones")]
    PeerKeyRejected { identity: String },

    #[error("Couldn't check their keys")]
    PeerKeyUnverified { identity: String },

    #[error("Not an accepted contact")]
    PeerNotAccepted { identity: String },

    #[error("Contact is blocked")]
    PeerBlocked { identity: String },

    #[error("Keys can be rotated once a day")]
    RotationTooSoon,

    #[error("A safety number is 60 digits")]
    InvalidSafetyNumber,

    #[error("session state could not be saved")]
    StatePersistFailed,

    /// An automatic resend no longer holds (final review H-1): the session
    /// that made the id eligible is gone, or the peer is no longer plainly
    /// pinned. The app falls back to its manual Resend row.
    #[error("Automatic resend refused")]
    ResendRefused { identity: String },

    /// No ML-KEM key is pinned for the contact (R1, §A.5): no request or
    /// circuit ask can be sent until their v3 card's key is pinned. There
    /// is never an X25519-only knock.
    #[error("Their contact card's ML-KEM key is missing; scan their code again")]
    NoKemKey { identity: String },

    /// A file over `file_msg::MAX_FILE_PLAINTEXT` (protocol v3 §E.2):
    /// refused before anything is sent.
    #[error("File too large: at most {max} bytes in all")]
    FileTooLarge { max: u64 },

    /// A background drain (protocol v3 §H.1) was asked for while the
    /// client is connected: a connected client receives the queue itself,
    /// and the drain never takes its connection over (FFI code 29).
    #[error("A connected client is running; no background drain")]
    ForegroundConnected,
}

/// Configuration for the RChat client. `Debug` never prints the identity
/// seed (C-10); the client takes the seed out of its copy at creation.
#[derive(Clone, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ClientConfig {
    pub server_url: String,
    /// Never deserialized with the rest (R1-3): a later field failing would
    /// free a plain copy of it. `rchat_connect` reads it apart, wiped.
    #[serde(skip_deserializing)]
    pub identity_key_seed: Option<String>,
    pub connection_timeout_secs: u32,
    pub reconnect_max_attempts: u32,
    pub message_retry_count: u32,
    pub enable_delivery_confirmation: bool,
    pub keepalive_interval_secs: u32,
    /// BoringSSL ClientHello profile (default `Chrome`: the TLS 1.3-only
    /// profile). No profile reproduces a real browser's fingerprint.
    pub tls_fingerprint: crate::tls_boring::TlsFingerprint,
    /// `ws://` (dev) only: the relay's configured `dev_origin`, if it differs
    /// from the server URL's `scheme://host:port`.
    #[serde(default)]
    pub dev_origin: Option<String>,
    /// Saved relay identity pin for this server (`rk:1:…`), if any (spec §4.9).
    #[serde(default)]
    pub relay_pin: Option<String>,
    /// Version of the saved relay identity.
    #[serde(default)]
    pub relay_pin_version: Option<u32>,
    /// Refuse to trust a relay on first use (require `relay_pin`).
    #[serde(default)]
    pub relay_pin_strict: bool,
    /// This identity's key version (0 for a new account; +1 per rotation).
    #[serde(default)]
    pub identity_version: u32,
    /// The last ≤ 3 rotation links leading to this identity (196-byte links, hex, concatenated).
    #[serde(default)]
    pub rotation_links_hex: Option<String>,
    /// When this identity was rotated in (Unix seconds).
    #[serde(default)]
    pub rotated_at_unix: Option<u64>,
    /// Identities pinned at rotation time that have not yet been reached
    /// under the new identity (round-2 M3; persisted by the app, which
    /// removes a peer on `on_circuit_established`).
    #[serde(default)]
    pub rotation_unreached_hex: Option<Vec<String>>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server_url", &self.server_url)
            .field(
                "identity_key_seed",
                &self.identity_key_seed.as_ref().map(|_| "<redacted>"),
            )
            .field("connection_timeout_secs", &self.connection_timeout_secs)
            .field("reconnect_max_attempts", &self.reconnect_max_attempts)
            .field("identity_version", &self.identity_version)
            .finish_non_exhaustive()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            identity_key_seed: None,
            connection_timeout_secs: 30,
            reconnect_max_attempts: 5,
            message_retry_count: 3,
            enable_delivery_confirmation: true,
            keepalive_interval_secs: 30,
            tls_fingerprint: crate::tls_boring::TlsFingerprint::default(),
            dev_origin: None,
            relay_pin: None,
            relay_pin_version: None,
            relay_pin_strict: false,
            identity_version: 0,
            rotation_links_hex: None,
            rotated_at_unix: None,
            rotation_unreached_hex: None,
        }
    }
}

/// Connection status for UI updates
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32, max_attempts: u32 },
    Error { message: String },
}

/// A received message with metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReceivedMessage {
    pub id: String,
    pub sender_identity: String,
    pub content: Vec<u8>,
    pub timestamp_ms: u64,
    pub is_text: bool,
    /// The sender's disappearing timer for this message (0 = never,
    /// protocol v3 §I.2). The app honours it, never its own setting.
    pub expire_secs: u32,
}

/// A received file message (`0x07`, protocol v3 §E.2). `name` is already
/// cleaned (`file_msg::sanitise_name`); `mime` is advisory only, never a
/// reason to open anything; `expire_secs` is the sender's disappearing
/// timer for this message (0 = never, §I.2). The core wipes `bytes` once
/// the callback returns (or at once when no app is attached).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReceivedFile {
    pub id: String,
    pub sender_identity: String,
    pub name: String,
    pub mime: String,
    pub expire_secs: u32,
    pub bytes: Vec<u8>,
    pub timestamp_ms: u64,
}

/// A knock from someone not yet accepted (spec §6.3). Intro fields are
/// empty / 0 when the knock carried no intro.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MessageRequest {
    pub identity_hex: String,
    pub agreement_hex: String,
    /// The requester's ML-KEM-768 key (2368 hex), from the bundle its
    /// identity signed in the knock (§A.5). The app stores it with the
    /// request and passes it to the pin on accept, so it survives a
    /// restart (R11).
    pub kem_hex: String,
    pub issued_hour: u64,
    pub intro_message_id_hex: String,
    pub intro_text: String,
    pub intro_sent_at_ms: u64,
    /// The sender's key version from its knock's rotation block (0 if none).
    pub key_version: u32,
}

/// Callback interface for UI updates from Swift
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait RChatCallbacks: Send + Sync {
    /// Called when connection status changes
    fn on_connection_status_changed(&self, status: ConnectionStatus);

    /// Called when a message is received
    fn on_message_received(&self, message: ReceivedMessage);

    /// Called when a file message (`0x07`) is received. A file never
    /// reaches `on_message_received`. Its delivered receipt is queued when
    /// the app calls `mark_message_seen`, as for any message (D36).
    fn on_file_received(&self, _file: ReceivedFile) {}

    /// A contact's disappearing timer changed (protocol v3 §I.2): `secs` is
    /// one of `disappearing::TIMER_CHOICES_SECS` (0 = off), `changed_at_ms`
    /// when it was changed, `by_me` whether this device changed it (the app
    /// shows "You set…" or the contact's name). Only a change that won
    /// (`disappearing::timer_wins`) is reported.
    fn on_timer_changed(&self, _peer_hex: String, _secs: u32, _changed_at_ms: u64, _by_me: bool) {}

    /// Called when a message is confirmed delivered
    fn on_message_delivered(&self, message_id: String);

    /// Called when an error occurs
    fn on_error(&self, error: String);

    /// Called when a circuit is established with a peer.
    /// is_initiator: true if we are the X3DH initiator (role 0: we asked first)
    fn on_circuit_established(&self, recipient_identity: String, is_initiator: bool);

    /// Key events for a peer: code 2 = keys don't match the pin (sticky),
    /// 3 = bundle signature failed (transient), 5 = the pinned contact's
    /// ML-KEM key was learned from a bundle their identity signed (store it
    /// with the pin, R11). `agreement_hex` is the offered agreement key for
    /// code 2, the ML-KEM key (2368 hex) for code 5, empty otherwise.
    fn on_peer_key_event(&self, _identity_hex: String, _code: u8, _agreement_hex: String) {}

    /// Someone not yet accepted knocked. Nothing has been sent back.
    fn on_message_request(&self, _request: MessageRequest) {}
    /// An end-to-end receipt for a message we sent: kind 1 delivered, 2 read.
    /// `sender_hex` is the peer that sent the receipt; bind it to the contact
    /// the message went to.
    fn on_message_receipt(&self, _sender_hex: String, _message_id_hex: String, _kind: u8) {}

    /// A pinned contact proved a rotation to new keys and was re-pinned
    /// silently (spec §4.8). The app moves the contact to the new identity,
    /// clears its safety-number "compared" mark (D20) and offers a one-tap
    /// Resend for unconfirmed messages (never automatic: D23, H1).
    /// `new_kem_hex` is the new identity's ML-KEM key (from the bundle it
    /// signed), which the app stores and re-pins with the agreement key (R11).
    fn on_peer_rotated(
        &self,
        _old_identity_hex: String,
        _new_identity_hex: String,
        _new_agreement_hex: String,
        _new_kem_hex: String,
        _new_version: u32,
    ) {
    }

    /// A delivery or recovery event (spec §18.9). Never carries secrets.
    fn on_status_event(&self, _event: status::StatusEvent) {}

    /// Called when the transport auto-reconnects after an unexpected disconnect.
    /// The UI should re-publish the key bundle and re-set recipients.
    fn on_reconnect(&self) {
        // Default no-op implementation
    }

    /// Called for debug logging (optional)
    fn on_log(&self, _message: String) {
        // Default no-op implementation
    }
}

/// Main RChat client - primary interface for Swift
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct RChatClient {
    runtime: Arc<ClientRuntime>,
    inner: Arc<RwLock<ClientInner>>,
    /// Delivers callbacks; reachable without the client lock.
    callback_hub: Arc<CallbackHub>,
    /// The latest `set_cover_traffic` value, applied under the client lock
    /// by whichever apply runs next (so the last call wins).
    cover_wanted: Arc<std::sync::Mutex<(bool, bool)>>,
    /// The latest `set_steady_traffic` value (enabled, slot ms, foreground),
    /// applied the same way.
    steady_wanted: Arc<std::sync::Mutex<(bool, u32, bool)>>,
    /// The inner `connected_mirror`, read without the client lock.
    connected_mirror: Arc<std::sync::atomic::AtomicBool>,
    /// Set by `retire` (and so by every uninstall): `connect` refuses from
    /// then on, so a client the app no longer holds never connects or
    /// publishes again (R34 round 2 N-1).
    retired: Arc<std::sync::atomic::AtomicBool>,
    /// Tests: a pause in `connect` before it takes the client lock.
    #[cfg(test)]
    pre_lock_delay_for_test: Arc<std::sync::Mutex<std::time::Duration>>,
}

struct ClientInner {
    config: ClientConfig,
    websocket: Option<WebSocketClient>,
    identity: Option<IdentityKeyPair>,
    callbacks: Option<Box<dyn RChatCallbacks>>,
    session_manager: SessionManager,
    is_connected: bool,
    is_key_bundle_published: bool,
    current_recipient: Option<String>,
    /// Role of the most recently established session (role 0 = initiator).
    is_e2ee_initiator: bool,
    /// Pins, blocks and key flags per peer (spec §4.4). Pinned == accepted.
    peers: PeerBook,
    /// Asks made before the publish on this connection was acknowledged;
    /// sent by `after_publish_ok`.
    deferred_asks: Vec<String>,
    /// Scheduled automatic re-asks: peer → earliest send time.
    pending_reasks: std::collections::HashMap<String, std::time::Instant>,
    /// Queued intros (§6.5) per peer, carried by every knock until a
    /// session is established. In memory only.
    intros: std::collections::HashMap<String, knock::Intro>,
    /// Fixed jitter for tests; random in [-0.2, 0.2] when None.
    ask_jitter_override: Option<f64>,
    /// The once-per-second re-ask ticker has been spawned.
    reask_ticker_started: bool,
    /// How long `send_*` waits for a live circuit before failing.
    send_wait_ms: u64,
    /// Sealed ratchet bodies received before their sender's session existed (bounded).
    pending_encrypted_messages: VecDeque<PendingEncrypted>,
    /// Receipts waiting for the peer to have a live circuit, keyed by
    /// (peer identity hex, kind); bounded by `MAX_PENDING_RECEIPTS`.
    pending_receipts: std::collections::HashMap<(String, u8), Vec<[u8; 16]>>,
    /// Per-peer receipt deadline (spec §5.7: 0.5-3 s after the first queued receipt).
    receipt_due: std::collections::HashMap<String, std::time::Instant>,
    /// Tests: a fixed receipt delay (zero = send immediately).
    receipt_delay_override: Option<std::time::Duration>,
    /// Cover traffic (spec §5.7) is on; off by default.
    cover_enabled: bool,
    /// The app is in the foreground (cover requests only then).
    cover_foreground: bool,
    /// When the next cover request is due (None = not scheduled).
    cover_next: Option<std::time::Instant>,
    /// Last successful ratchet decrypt per peer (round-2 M5 eligibility).
    last_heard: std::collections::HashMap<String, std::time::Instant>,
    /// Cover packets sent per peer within the last hour (cap).
    cover_sent: std::collections::HashMap<String, VecDeque<std::time::Instant>>,
    /// Scheduled replies to received cover requests (round-2 M4).
    cover_replies_due: Vec<(String, std::time::Instant)>,
    /// Cover replies scheduled per peer within the last hour (L-2 cap).
    cover_replies_charged: std::collections::HashMap<String, VecDeque<std::time::Instant>>,
    /// Tests: force the 0.8 coin for the second cover reply.
    cover_reply_coin_override: Option<bool>,
    /// Each contact's disappearing timer (protocol v3 §I.2), persisted in
    /// its peer record. Absent means off, never changed.
    pub(crate) timers: std::sync::Mutex<std::collections::HashMap<String, disappearing::PeerTimer>>,
    /// Recent `0x09` ids per peer (memory only): their receipts and status
    /// events are the core's (ruling R32).
    pub(crate) timer_ids: std::sync::Mutex<std::collections::HashMap<String, VecDeque<[u8; 16]>>>,
    /// Peers whose timer change was reported lost, re-sent at the next flush.
    pub(crate) timer_requeue: std::sync::Mutex<Vec<String>>,
    /// Steady traffic (protocol v3 §B) is on; off by default.
    steady_enabled: bool,
    /// The app is in the foreground (steady slots only then).
    steady_foreground: bool,
    /// The slot length, one of `steady::STEADY_SLOT_CHOICES_MS`.
    steady_slot_ms: u32,
    /// Chooses each slot's destination (§B.1).
    steady: steady::SteadyScheduler,
    /// Bumped by every setting change that ends the running slot task.
    steady_task_gen: u64,
    /// A slot task for `steady_task_gen` is running.
    steady_task_running: bool,
    /// Set only while a slot seals: pad to exactly `STEADY_PLAINTEXT_LEN`.
    steady_padding: bool,
    /// Set by `seal_ratchet` when a slot item did not fit 1 KiB (never
    /// expected: every slot item is bounded); the slot then sends it
    /// outside the shape explicitly.
    steady_oversize: std::sync::atomic::AtomicBool,
    /// Per peer: slots sent since anything from that peer last decrypted
    /// (R23). At `steady::STEADY_UNHEARD_LIMIT` the peer leaves the draw.
    steady_unheard: std::collections::HashMap<String, u32>,
    /// Peers whose next slot goes to a waiting message before receipts
    /// (M1: receipts and messages alternate).
    steady_message_turn: std::collections::HashSet<String>,
    /// Ids of messages we sent to each peer (bounded), so a receipt naming
    /// an id never sent to that peer is ignored.
    sent_ids: std::sync::Mutex<std::collections::HashMap<String, VecDeque<state_store::SentIdV1>>>,
    // Message queues for polling (non-UniFFI usage)
    /// Challenge from the relay for the next publish (one use).
    auth_challenge: Option<[u8; 32]>,
    /// The app asked to publish; sent once a challenge is held.
    publish_requested: bool,
    /// A publish was sent on this connection and awaits its response.
    publish_in_flight: bool,
    /// Fire `on_reconnect` after the next hello_response (auto-reconnect).
    notify_reconnect: bool,
    /// Knock validity window announced by the relay (1..=72, default 72).
    knock_ttl_hours: u32,
    /// Our signed bundle, built once per identity.
    signed_bundle: Option<SignedBundle>,
    /// Incremented on every new transport connection.
    transport_epoch: u64,
    /// Identifies the `WebSocketClient` whose events may touch this state.
    /// Bumped on every `connect()`, manual disconnect and protocol failure;
    /// events tagged with an older value come from a retired client and are
    /// dropped (`handle_event`).
    connection_generation: u64,
    /// A hello was sent on the live connection and its response is awaited.
    /// A hello_response without one is ignored.
    hello_outstanding: bool,
    /// Canonical origin and outcome of the relay gate on this connection.
    relay_pin_info: Option<(String, relay_pin::PinOutcome)>,
    /// TLS 1.3 tickets for the pinned relay (spec §D.1): memory only, kept
    /// across auto-reconnects and `disconnect_transport_only`, bound to the
    /// relay's host, port and pin, and dropped on `disconnect()`, a pin
    /// change, a refused relay and an identity wipe or change.
    tls_tickets: tls_resumption::ResumptionStore,
    /// Tests only: let non-signaling frames through before the gate.
    bypass_frame_gate: bool,
    /// Non-signaling frames dropped before the relay gate and publish passed.
    frames_dropped_before_gate: u64,
    /// Our own rotation chain (spec §4.8), carried in knocks to unreached pins.
    rotation_block: Option<rotation::RotationBlock>,
    /// Peers that rotated away from an old identity: old → (new, when).
    /// In-flight messages from the old identity are accepted for
    /// `ROTATION_GRACE_SECS` and reported as from the new one.
    rotated_from: std::collections::HashMap<String, (String, std::time::Instant)>,
    /// Round-2 M3: identities pinned when we rotated, not yet reached under
    /// the new identity.
    rotation_unreached: std::collections::HashSet<String>,
    /// The identity seed from the config (hex), held only until the identity
    /// is loaded, wiped on drop (C-10).
    identity_seed: Option<zeroize::Zeroizing<String>>,
    /// The prepared new seed, handed out once by `take_rotation_seed` (L4).
    /// Boxed so moving it (through the async hand-off) copies no seed bytes.
    pending_rotation_seed: Option<Box<zeroize::Zeroizing<[u8; 64]>>>,
    /// Times of the rotation knocks sent in the last 24 h (round-2 M3 quota).
    rotation_knocks: VecDeque<std::time::Instant>,
    /// `CloseCircuit`s that could not reach the relay (not published on
    /// this connection, or not sendable), sent right after the next
    /// accepted publish (security review M-1). In memory only: after a
    /// restart the relay's sweep ends a pair the member never resumes.
    pending_closes: Vec<CircuitId>,
    /// The sealed on-device store (spec §18.3); None = persistence off.
    state: Option<persistence::StateStore>,
    // Per-peer tracking persisted in the peer record (spec §18.2). Every
    // wipe and forget path must clear all of them for the peer (Task 3b),
    // and the notice and hello-sync state below (Task 6a).
    /// Envelope ids already decrypted from each peer (`MAX_RECEIVED_IDS`).
    received_ids: std::collections::HashMap<String, VecDeque<[u8; 16]>>,
    /// Ids handed to the app and not yet confirmed stored (`MAX_DELIVERED_UNSTORED`).
    delivered_unstored: std::collections::HashMap<String, VecDeque<[u8; 16]>>,
    /// Reason-2 ids: delivered but lost before stored (cap 1,024).
    lost_unstored: std::collections::HashMap<String, VecDeque<[u8; 16]>>,
    /// Ids that decrypted under neither session, not yet reported (cap 256).
    undecryptable: std::collections::HashMap<String, VecDeque<[u8; 16]>>,
    /// Peers owed a session notice on the current session.
    notice_due: std::collections::HashSet<String>,
    /// Ids reported lost before stored (reason 2), with the unix time of
    /// the report, whose sender may resend them under the same id: such a
    /// resend passes the duplicate drop once, for at most
    /// `RESET_REPORT_MAX_AGE_SECS` (cap `MAX_DELIVERED_UNSTORED`; persisted).
    lost_reported: std::collections::HashMap<String, VecDeque<([u8; 16], u64)>>,
    /// The flags of the notice still owed on the current session
    /// (`FLAG_NO_PRIOR_SESSION` or 0); persisted, so a restart keeps it.
    notice_flag_pending: std::collections::HashMap<String, u8>,
    /// Peers whose notice the transport refused, with that transport's
    /// epoch: the tick does not try them again on it (in memory only).
    notice_send_stalled: std::collections::HashMap<String, u64>,
    /// When the tick's re-drive last probed a peer whose writes fail.
    last_redrive_probe: Option<std::time::Instant>,
    /// Initiators whose hello sync could not leave (the session's write
    /// failed): re-sent by the tick, so the responder gets its sending chain.
    hello_sync_due: std::collections::HashSet<String>,
    /// Responders (role 1) waiting for the initiator's session-init (§A.3):
    /// no session is installed until it arrives. Persisted with the peer
    /// record, so a restart can still open the init.
    pending_inits: std::collections::HashMap<String, circuits::PendingInit>,
    /// Peers whose tracked re-sends wait for our session-init to leave
    /// first (§A.4, review M-3); the tick re-sends them.
    resend_after_init: std::collections::HashSet<String>,
    /// Waits for a session-init dropped at restore as too old (peer, its
    /// circuit): closed and re-asked once every staged record is applied.
    abandoned_at_restore: Vec<(String, protocol::CircuitId)>,
    /// Held bodies are being retried right after a new install: a failure
    /// there is reported as `DecryptFailed` detail 2.
    retrying_held: bool,
    /// Per-peer automatic resend times (unix seconds, D38 bound).
    auto_resends: std::collections::HashMap<String, VecDeque<u64>>,
    /// Peers with an ask that has had no answer: (sent at, attempts).
    unanswered_asks: std::collections::HashMap<String, (std::time::Instant, u64)>,
    /// Calls into `SessionManager::decrypt_from` (read by tests only).
    decrypt_attempts: std::sync::atomic::AtomicU64,
    /// Where `retry_held` resumes when more senders wait than it takes per
    /// tick (fair rotation; in memory only).
    retry_cursor: usize,
    /// Sent messages awaiting the relay's `MessageAck`, across transport
    /// replacements (spec §18.7 D35; in memory only).
    acks: std::sync::Mutex<acks::AckTracker>,
    /// `is_connected`, readable without the client lock (`get_connection_status`
    /// while the lock is busy). Written only by `set_connected`.
    connected_mirror: Arc<std::sync::atomic::AtomicBool>,
    /// A `connect()` is in its network part (run without the client lock).
    connecting: bool,
    /// Re-owes of internal entries per (peer, notice content or receipt
    /// kind and id), with the session binding they count under (N-1, R3-2).
    reowes: std::collections::HashMap<(String, acks::ReoweKey), ([u8; 32], u8)>,
    /// When the full re-owe map was last pruned (at most once a second).
    last_reowe_prune: Option<std::time::Instant>,
    /// Final review M-1: writes coalesced to the tick. The meta record
    /// (held bodies, best effort under D28) and peer records whose only
    /// change was a newly listed undecryptable id (losing one costs one
    /// missed report, never a key).
    meta_dirty: bool,
    peers_dirty: std::collections::HashSet<String>,
    /// M-1: DecryptFailed raised per peer in this tick (at most
    /// `MAX_DECRYPT_FAILED_PER_TICK`).
    decrypt_failed_this_tick: std::collections::HashMap<String, u32>,
    /// Tests: a pause before a connect installs its connection.
    #[cfg(test)]
    install_delay_for_test: std::time::Duration,
    /// Tests: transport events handled while a connect was still running.
    #[cfg(test)]
    events_while_connecting_for_test: u32,
    /// Tests: `send_now` refuses this many frames, as a full queue would.
    #[cfg(test)]
    refuse_sends_for_test: std::sync::atomic::AtomicU32,
    /// When the ticker last advanced the ack clock (`fire_ack_expiry`).
    ack_last_tick: Option<std::time::Instant>,
    /// Signs our session notices with this install's device key (D45);
    /// set by the app (`set_device_signer`). None: notices go unsigned.
    device_signer: Option<Arc<dyn device_key::DeviceSigner>>,
    /// The outstanding blind ask per peer (§C.2, Task 9). Memory only: the
    /// relay drops held asks with their connection.
    blind_asks: std::collections::HashMap<String, Vec<blind::BlindAsk>>,
    /// `PairTokenBusy` advances per peer on this connection (R16 cap).
    blind_busy: std::collections::HashMap<String, u32>,
    /// Peers whose blind asks pause until the next reconnect: busy past
    /// the cap (R20). Never the identity path.
    blind_paused: std::collections::HashSet<String>,
    /// The neighbouring day's token already retried per peer (one retry,
    /// §C.1).
    blind_neighbour_tried: std::collections::HashMap<String, pairing::PairEpoch>,
    /// Blind asks we retired while the relay may still hold them, by public
    /// EK, for one TTL (no secret): a stray match on one syncs our epoch.
    spent_blind_asks: std::collections::HashMap<[u8; 32], blind::SpentAsk>,
    /// The timed identity fallback ask in flight per peer (R20): sent at,
    /// on transport epoch. Memory only (the relay drops it with the
    /// connection).
    identity_fallback: std::collections::HashMap<String, (std::time::Instant, u64)>,
    /// Knock digests seen per pinned contact, with their unix time (M-2):
    /// a replayed knock never turns the path again. Memory only, like
    /// knocks; bounded per contact and by `KNOCK_SEEN_SECS`.
    seen_knocks: std::collections::HashMap<String, VecDeque<([u8; 32], u64)>>,
    /// Issue hour and digest of the last knock acted on per pinned contact
    /// (N-2): an older knock, or that very knock, is ignored. Persisted in
    /// the peer record.
    knock_acted: std::collections::HashMap<String, (u64, [u8; 32])>,
    /// Peers whose knock (a pinned contact's) shows they are on the
    /// identity path: our next ask to them is an identity ask, until the
    /// next session install, until that identity ask runs out unmatched
    /// (held `ASK_TTL` on one connection, like the timed fallback), or the
    /// next transport reconnect (final review H-1): then back to blind.
    /// A knock declaring that the contact holds no session with us
    /// (`no_prior_session`, R35) keeps it there: a blind ask can never meet
    /// a peer with no pair secret. While we still hold one, blind asks run
    /// beside the identity ask (final re-review N-1). Memory only.
    identity_wanted: std::collections::HashMap<String, blind::IdentityWanted>,
    /// Paces the asks a connection sends (final review, RateLimited).
    pub(crate) ask_pacer: blind::AskPacer,
    /// Asks sent on this connection, newest last, to blame a `RateLimited`
    /// answer on. Public EKs only; memory only.
    recent_asks: VecDeque<blind::RecentAsk>,
    /// `RateLimited` ask refusals in a row (reset after a quiet `ASK_TTL`)
    /// and the last one's time: the backoff before the refused ask goes
    /// again.
    ask_refusals: (u32, Option<std::time::Instant>),
    /// Tests: the unix time the pair epoch is computed from.
    pair_clock_override: Option<u64>,
    /// End-to-end tests only (`test-hooks`, `test_set_pair_clock_offset`):
    /// seconds added to the wall clock for the pair epoch and the 24 h
    /// fallback clock. Always 0 in an app build.
    pub(crate) pair_clock_offset_secs: i64,
    /// End-to-end tests only (`test-hooks`, `test_set_blind_ask_ttl`): how
    /// long a blind or identity-fallback ask is held before it times out,
    /// instead of `peers::ASK_TTL`. Always None in an app build.
    pub(crate) blind_ask_ttl_override: Option<std::time::Duration>,
    /// A background drain (protocol v3 §H.1) is running on this client:
    /// only signaling leaves (`send_now`), and nothing asks, resumes,
    /// closes, sends receipts or cover/steady traffic. Memory only.
    pub(crate) drain: Option<drain::DrainState>,
}

/// Transport events, handled one at a time in arrival order.
pub(crate) use transport::TransportEvent as CoreEvent;

impl ClientInner {
    /// Report a delivery or recovery event to the app (spec §18.9). Never
    /// carries secrets; logged without two identity-derived values (R6).
    pub(crate) fn emit_status(&self, ev: status::StatusEvent) {
        #[cfg(test)]
        assert!(
            !persistence::PERSIST_LOCK_HELD.with(|h| h.get()),
            "status event raised under the persist lock"
        );
        // A timer change's loss is the core's to repair (ruling R32).
        if self.take_timer_status(&ev) {
            return;
        }
        log::debug!("[RUST] status event kind {}", ev.code());
        #[cfg(test)]
        test_support::capture_event(&format!("{ev:?}"));
        if let Some(cb) = &self.callbacks {
            cb.on_status_event(ev);
        }
    }

    pub(crate) fn new(mut config: ClientConfig) -> Self {
        // The seed lives in a wiped buffer only, never in `config` (C-10).
        let identity_seed = config.identity_key_seed.take().map(zeroize::Zeroizing::new);
        let mut inner = Self {
            config: config.clone(),
            websocket: None,
            identity: None,
            callbacks: None,
            session_manager: SessionManager::new(),
            is_connected: false,
            is_key_bundle_published: false,
            current_recipient: None,
            is_e2ee_initiator: false,
            peers: PeerBook::default(),
            deferred_asks: Vec::new(),
            pending_reasks: std::collections::HashMap::new(),
            intros: std::collections::HashMap::new(),
            ask_jitter_override: None,
            reask_ticker_started: false,
            send_wait_ms: 10_000,
            pending_encrypted_messages: VecDeque::new(),
            pending_receipts: std::collections::HashMap::new(),
            receipt_due: std::collections::HashMap::new(),
            receipt_delay_override: None,
            cover_enabled: false,
            cover_foreground: false,
            cover_next: None,
            last_heard: std::collections::HashMap::new(),
            cover_sent: std::collections::HashMap::new(),
            cover_replies_due: Vec::new(),
            cover_replies_charged: std::collections::HashMap::new(),
            cover_reply_coin_override: None,
            timers: Default::default(),
            timer_ids: Default::default(),
            timer_requeue: Default::default(),
            steady_enabled: false,
            steady_foreground: false,
            steady_slot_ms: steady::STEADY_DEFAULT_SLOT_MS,
            steady: steady::SteadyScheduler::new(std::time::Duration::from_millis(u64::from(
                steady::STEADY_DEFAULT_SLOT_MS,
            ))),
            steady_task_gen: 0,
            steady_task_running: false,
            steady_padding: false,
            steady_oversize: std::sync::atomic::AtomicBool::new(false),
            steady_unheard: std::collections::HashMap::new(),
            steady_message_turn: std::collections::HashSet::new(),
            sent_ids: std::sync::Mutex::new(std::collections::HashMap::new()),
            auth_challenge: None,
            publish_requested: false,
            publish_in_flight: false,
            notify_reconnect: false,
            knock_ttl_hours: 72,
            signed_bundle: None,
            transport_epoch: 0,
            connection_generation: 0,
            hello_outstanding: false,
            relay_pin_info: None,
            tls_tickets: tls_resumption::ResumptionStore::new(),
            bypass_frame_gate: false,
            frames_dropped_before_gate: 0,
            rotation_block: None,
            rotated_from: std::collections::HashMap::new(),
            rotation_unreached: std::collections::HashSet::new(),
            identity_seed,
            pending_rotation_seed: None,
            rotation_knocks: VecDeque::new(),
            pending_closes: Vec::new(),
            state: None,
            received_ids: std::collections::HashMap::new(),
            delivered_unstored: std::collections::HashMap::new(),
            lost_unstored: std::collections::HashMap::new(),
            undecryptable: std::collections::HashMap::new(),
            notice_due: std::collections::HashSet::new(),
            lost_reported: std::collections::HashMap::new(),
            notice_flag_pending: std::collections::HashMap::new(),
            notice_send_stalled: std::collections::HashMap::new(),
            last_redrive_probe: None,
            hello_sync_due: std::collections::HashSet::new(),
            pending_inits: std::collections::HashMap::new(),
            resend_after_init: std::collections::HashSet::new(),
            abandoned_at_restore: Vec::new(),
            retrying_held: false,
            auto_resends: std::collections::HashMap::new(),
            unanswered_asks: std::collections::HashMap::new(),
            decrypt_attempts: std::sync::atomic::AtomicU64::new(0),
            retry_cursor: 0,
            acks: std::sync::Mutex::new(acks::AckTracker::default()),
            connected_mirror: Arc::default(),
            connecting: false,
            reowes: std::collections::HashMap::new(),
            last_reowe_prune: None,
            meta_dirty: false,
            peers_dirty: std::collections::HashSet::new(),
            decrypt_failed_this_tick: std::collections::HashMap::new(),
            #[cfg(test)]
            install_delay_for_test: std::time::Duration::ZERO,
            #[cfg(test)]
            events_while_connecting_for_test: 0,
            #[cfg(test)]
            refuse_sends_for_test: std::sync::atomic::AtomicU32::new(0),
            ack_last_tick: None,
            device_signer: None,
            blind_asks: std::collections::HashMap::new(),
            blind_busy: std::collections::HashMap::new(),
            blind_paused: std::collections::HashSet::new(),
            blind_neighbour_tried: std::collections::HashMap::new(),
            spent_blind_asks: std::collections::HashMap::new(),
            identity_fallback: std::collections::HashMap::new(),
            seen_knocks: std::collections::HashMap::new(),
            knock_acted: std::collections::HashMap::new(),
            identity_wanted: std::collections::HashMap::new(),
            ask_pacer: blind::AskPacer::default(),
            recent_asks: VecDeque::new(),
            ask_refusals: (0, None),
            pair_clock_override: None,
            pair_clock_offset_secs: 0,
            blind_ask_ttl_override: None,
            drain: None,
        };
        inner.apply_rotation_config(config);
        inner
    }

    /// Adopt the rotation part of `config` (called by `new` and tests). A
    /// chain that does not verify, or does not end at `identity_version`, is
    /// not carried (it would only be ignored by every peer).
    pub(crate) fn apply_rotation_config(&mut self, config: ClientConfig) {
        let links = config
            .rotation_links_hex
            .as_deref()
            .map(parse_links_hex)
            .unwrap_or_default();
        let block = rotation::RotationBlock {
            current_version: config.identity_version,
            links,
        };
        self.rotation_block =
            (config.identity_version > 0 && block.encode().is_ok()).then_some(block);
        self.rotation_unreached = config
            .rotation_unreached_hex
            .iter()
            .flatten()
            .map(|h| h.to_lowercase())
            .collect();
        self.config.identity_version = config.identity_version;
        self.config.rotation_links_hex = config.rotation_links_hex;
        self.config.rotated_at_unix = config.rotated_at_unix;
        self.config.rotation_unreached_hex = config.rotation_unreached_hex;
    }

    /// Round-2 M3: a rotation chain to deliver, and someone still to reach.
    pub(crate) fn rotation_pending_reach(&self) -> bool {
        self.rotation_block
            .as_ref()
            .is_some_and(|b| !b.links.is_empty())
            && !self.rotation_unreached.is_empty()
    }

    /// Round-2 M3: the peer has a circuit under our new identity.
    pub(crate) fn rotation_reached(&mut self, peer_hex: &str) {
        self.rotation_unreached.remove(peer_hex);
    }

    /// Round-2 M3: take one of the daily rotation knocks, if any is left.
    pub(crate) fn take_rotation_knock(&mut self, now: std::time::Instant) -> bool {
        let day = std::time::Duration::from_secs(24 * 3600);
        while self
            .rotation_knocks
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= day)
        {
            self.rotation_knocks.pop_front();
        }
        if self.rotation_knocks.len() >= MAX_ROTATION_KNOCKS_PER_DAY {
            return false;
        }
        self.rotation_knocks.push_back(now);
        true
    }

    /// Queue one frame without waiting (bounded queue: Full is an error).
    pub(crate) fn send_now(&self, frame: Vec<u8>) -> Result<(), RChatError> {
        // A background drain (§H.1) sends its hello and publish, nothing
        // else: no ask, close, relay packet, receipt or cover. Refused like
        // an absent transport, so callers keep what they meant to send.
        if self.in_drain() && frame.first() != Some(&protocol::FRAME_TYPE_SIGNALING) {
            return Err(RChatError::NotConnected);
        }
        #[cfg(test)]
        if self
            .refuse_sends_for_test
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            return Err(RChatError::Internal {
                message: "outgoing queue full".to_string(),
            });
        }
        let sender = self
            .websocket
            .as_ref()
            .and_then(|ws| ws.outgoing_sender())
            .ok_or(RChatError::NotConnected)?;
        sender.try_send(frame).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => RChatError::Internal {
                message: "outgoing queue full".to_string(),
            },
            tokio::sync::mpsc::error::TrySendError::Closed(_) => RChatError::NotConnected,
        })
    }

    pub(crate) fn send_control_now(&self, msg: ControlMessage) -> Result<(), RChatError> {
        self.send_now(msg.encode_with_frame_type())
    }

    /// Signaling goes as a binary `0x01 || JSON` frame (accepted by the relay).
    pub(crate) fn send_signaling_now(&self, msg: &SignalingMessage) -> Result<(), RChatError> {
        let frame = signaling_frame(msg).map_err(|e| RChatError::Internal {
            message: format!("signaling message did not serialize: {e}"),
        })?;
        self.send_now(frame)
    }

    /// Report to the callback; without one there is nobody to tell.
    pub(crate) fn report_error(&mut self, err: &RChatError) {
        if let Some(cb) = &self.callbacks {
            cb.on_error(err.to_string());
        }
    }

    /// The relay acknowledged one of our messages: to the callback.
    pub(crate) fn report_delivered(&mut self, message_id: String) {
        // A timer change's relay ack is the core's, never the app's.
        if self.is_any_timer_id(&message_id) {
            return;
        }
        if let Some(cb) = &self.callbacks {
            cb.on_message_delivered(message_id);
        }
    }

    /// Our signed bundle (signed once per identity, then cached).
    pub(crate) fn my_bundle(&mut self) -> Result<SignedBundle, RChatError> {
        if let Some(b) = &self.signed_bundle {
            return Ok(b.clone());
        }
        let identity = self.identity.as_ref().ok_or(RChatError::NotConnected)?;
        let bundle = keyauth::sign_bundle(identity).map_err(|e| RChatError::Internal {
            message: format!("bundle signing failed: {e}"),
        })?;
        self.signed_bundle = Some(bundle.clone());
        Ok(bundle)
    }

    /// The app asks to publish. Recorded until a challenge is held; a no-op
    /// while a publish is in flight or already acknowledged.
    pub(crate) fn request_publish(&mut self) -> Result<(), RChatError> {
        if self.websocket.is_none() {
            return Err(RChatError::NotConnected);
        }
        if self.is_key_bundle_published || self.publish_in_flight {
            return Ok(());
        }
        self.publish_requested = true;
        self.try_publish()
    }

    /// Send the publish if one is requested and a challenge is held. The
    /// challenge is used once; the proof is bound to this connection.
    fn try_publish(&mut self) -> Result<(), RChatError> {
        if !self.publish_requested || self.publish_in_flight {
            return Ok(());
        }
        let Some(challenge) = self.auth_challenge else {
            return Ok(());
        };
        let binding = self
            .websocket
            .as_ref()
            .and_then(|ws| ws.channel_binding())
            .ok_or(RChatError::NoChannelBinding)?;
        let bundle = self.my_bundle()?;
        let identity = self.identity.as_ref().ok_or(RChatError::NotConnected)?;
        let conn_signature =
            keyauth::sign_conn(identity, &challenge, &binding, &bundle).map_err(|e| {
                RChatError::Internal {
                    message: format!("connection proof failed: {e}"),
                }
            })?;
        self.send_signaling_now(&SignalingMessage::publish_key_bundle(
            &bundle,
            &conn_signature,
        ))?;
        self.auth_challenge = None;
        self.publish_requested = false;
        self.publish_in_flight = true;
        log::info!(
            "[RUST] Key bundle publish sent (transport epoch {})",
            self.transport_epoch
        );
        Ok(())
    }

    /// The relay pin outcome of the current connection, as JSON for the app.
    pub(crate) fn relay_pin_info_json(&self) -> Option<String> {
        let (origin, o) = self.relay_pin_info.as_ref()?;
        Some(
            serde_json::json!({
                "origin": origin,
                "pin": o.pin,
                "version": o.version,
                "source": o.source.as_str(),
                "from": o.from,
            })
            .to_string(),
        )
    }

    /// Spec §4.9: check the relay before trusting the connection. On success
    /// the outcome is remembered in `config` too, so an auto-reconnect in
    /// this process is checked against it.
    fn check_relay_identity(
        &mut self,
        offer: Option<&relay_pin::RelayIdentityOffer>,
        challenge: &[u8; 32],
    ) -> Result<(), RChatError> {
        self.relay_pin_info = None;
        let offer = offer.ok_or(RChatError::RelayIdentityInvalid)?;
        let binding = self
            .websocket
            .as_ref()
            .and_then(|ws| ws.channel_binding())
            .ok_or(RChatError::NoChannelBinding)?;
        let pinned = self
            .config
            .relay_pin
            .as_deref()
            .map(|p| (p, self.config.relay_pin_version));
        let outcome = relay_pin::decide(
            offer,
            &binding,
            challenge,
            pinned,
            self.config.relay_pin_strict,
        )
        .map_err(|f| match f {
            relay_pin::RelayPinFailure::Invalid => RChatError::RelayIdentityInvalid,
            relay_pin::RelayPinFailure::Required => RChatError::RelayPinRequired,
            relay_pin::RelayPinFailure::Changed => RChatError::RelayIdentityChanged,
        })?;
        log::info!(
            "[RUST] Relay identity accepted ({})",
            outcome.source.as_str()
        );
        self.config.relay_pin = Some(outcome.pin.clone());
        self.config.relay_pin_version = Some(outcome.version);
        // Tickets are kept for this relay under the pin it just proved: a
        // different pin (first use, rotation) drops the ones held.
        self.bind_tls_tickets();
        // Without a canonical origin there is nothing an app could key the
        // pin on, so none is reported (the gate itself has passed).
        self.relay_pin_info = relay_pin::canonical_origin(&self.config.server_url)
            .ok()
            .map(|origin| (origin, outcome));
        Ok(())
    }

    /// React to a signaling message from the relay.
    pub(crate) fn handle_signaling(&mut self, msg: &SignalingMessage) {
        match classify_signaling(msg) {
            SignalingEvent::HelloResponse {
                selected_version,
                auth_challenge,
                knock_ttl_hours,
                relay_identity,
            } => {
                if !self.hello_outstanding {
                    log::debug!("[RUST] Ignoring a hello_response with no hello outstanding");
                    return;
                }
                self.hello_outstanding = false;
                let Some(challenge) = auth_challenge
                    .filter(|_| selected_version == crate::protocol::PROTOCOL_VERSION)
                else {
                    self.fail_protocol(RChatError::ServerTooNew);
                    return;
                };
                // The relay gate runs before anything is trusted or published.
                if let Err(e) = self.check_relay_identity(relay_identity.as_ref(), &challenge) {
                    self.fail_protocol(e);
                    return;
                }
                self.auth_challenge = Some(challenge);
                self.publish_in_flight = false;
                if let Some(hours) = knock_ttl_hours {
                    self.knock_ttl_hours = hours.clamp(1, 72);
                }
                self.set_connected(true);
                if let Some(cb) = &self.callbacks {
                    cb.on_connection_status_changed(ConnectionStatus::Connected);
                    if self.notify_reconnect {
                        cb.on_reconnect();
                    }
                }
                self.notify_reconnect = false;
                if let Err(e) = self.try_publish() {
                    self.report_error(&e);
                }
            }
            SignalingEvent::PublishOk { next_challenge } => {
                if !self.publish_in_flight {
                    log::debug!("[RUST] Ignoring a publish response with no publish in flight");
                    return;
                }
                self.publish_in_flight = false;
                self.is_key_bundle_published = true;
                self.auth_challenge = next_challenge;
                log::info!("[RUST] Key bundle published");
                self.after_publish_ok(std::time::Instant::now());
            }
            SignalingEvent::PublishFailed => {
                if self.publish_in_flight {
                    self.fail_protocol(RChatError::KeyAuthRejected);
                }
            }
            SignalingEvent::AuthenticationFailed => self.fail_protocol(RChatError::KeyAuthRejected),
            SignalingEvent::VersionMismatch => self.fail_protocol(RChatError::ServerTooNew),
            SignalingEvent::Other => {}
        }
    }

    /// Bind the ticket store to the configured relay and its current pin
    /// (a change drops every ticket); no relay host: drop them.
    pub(crate) fn bind_tls_tickets(&self) {
        match tls_resumption::RelayKey::for_url(
            &self.config.server_url,
            self.config.relay_pin.as_deref(),
        ) {
            Some(key) => self.tls_tickets.bind(key),
            None => self.tls_tickets.clear(),
        }
    }

    /// Unrecoverable protocol failure: report once, stop, no retry loop.
    fn fail_protocol(&mut self, err: RChatError) {
        // A background drain on this connection ends with the error.
        self.drain_note_failure(&err);
        // Nothing from a refused relay (or session) is offered again.
        self.tls_tickets.clear();
        self.report_error(&err);
        self.retire_connection();
        self.publish_requested = false;
        self.set_connected(false);
        self.is_key_bundle_published = false;
        if let Some(ws) = self.websocket.take() {
            ws.shutdown_now();
        }
        if let Some(cb) = &self.callbacks {
            cb.on_connection_status_changed(ConnectionStatus::Error {
                message: err.to_string(),
            });
        }
    }

    /// The connection task ended. Sessions, pins and the recipient are kept;
    /// circuits live on their sessions and are re-established by resume.
    pub(crate) fn handle_transport_disconnected(&mut self) {
        self.auth_challenge = None;
        self.relay_pin_info = None;
        self.publish_in_flight = false;
        self.hello_outstanding = false;
        if self.is_connected {
            log::debug!(
                "[RUST] Transport disconnected, clearing transport state (preserving sessions)"
            );
            self.set_connected(false);
            self.is_key_bundle_published = false;
            if let Some(cb) = &self.callbacks {
                cb.on_connection_status_changed(ConnectionStatus::Disconnected);
            }
        }
    }

    /// The transport reconnected on its own: start v2 again with hello.
    pub(crate) fn handle_transport_reconnected(&mut self) {
        log::info!("[RUST] Transport auto-reconnected; sending hello");
        self.transport_epoch += 1;
        // Asks in flight may have been answered to the old connection.
        self.requeue_unanswered_asks();
        // The relay dropped our held blind asks with that connection: they
        // are asked again after the publish, never counted as timeouts,
        // and the busy cap counts per connection (R16).
        self.blind_asks.clear();
        self.blind_busy.clear();
        self.blind_paused.clear();
        self.spent_blind_asks.clear();
        // A fallback identity ask went with the connection: back to blind
        // (the next one waits out `IDENTITY_FALLBACK_INTERVAL_SECS`).
        self.identity_fallback.clear();
        // So did a knock-driven identity ask (final review H-1): back to
        // blind, unless the knock said the contact holds no session with us
        // (it cannot ask blind; its identity ask is answered again, with
        // blind asks beside it while we hold a PS, N-1).
        self.identity_wanted.retain(|_, w| {
            w.asked = None;
            w.no_prior_session
        });
        // A new connection: a full ask burst, and nothing to blame a
        // refusal on yet.
        self.ask_pacer.reset();
        self.recent_asks.clear();
        self.ask_refusals = (0, None);
        self.set_connected(false);
        self.is_key_bundle_published = false;
        self.auth_challenge = None;
        self.publish_in_flight = false;
        self.publish_requested = true;
        self.notify_reconnect = true;
        match self.send_signaling_now(&SignalingMessage::hello(vec![
            crate::protocol::PROTOCOL_VERSION,
        ])) {
            Ok(()) => self.hello_outstanding = true,
            Err(e) => {
                self.hello_outstanding = false;
                self.report_error(&e);
            }
        }
    }

    /// Entry point for every sealed payload (live relay and QueuedMessage).
    /// A sealed payload that arrived on `owner`'s circuit (final review
    /// M-1): a ratchet envelope claiming another sender is dropped before
    /// any decrypt, hold or write (a contact on a circuit cannot speak for
    /// others). Its rotation pair (old or new identity in the grace) still
    /// passes. Queued delivery has no circuit and goes through
    /// `handle_sealed_payload`.
    pub(crate) fn handle_sealed_payload_on_circuit(
        &mut self,
        payload: &[u8],
        owner: &str,
        on_pending_circuit: bool,
    ) {
        if payload.first() == Some(&crate::sealed::KNOCK_VERSION) {
            // A knock is never a circuit peer's ratchet traffic: its own
            // envelope and checks (§A.5, R10).
            self.handle_knock(payload);
            return;
        }
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let my_ik = identity.public_signing_key().to_bytes();
        let Ok(opened) = crate::sealed::open(&my_ik, identity.agreement_secret(), payload) else {
            log::debug!("[RUST] sealed payload did not open");
            return;
        };
        if opened.kind == crate::sealed::KIND_RATCHET
            || opened.kind == crate::session_init::SESSION_INIT_TYPE
        {
            let sender = hex::encode(opened.sender_identity_key);
            let rotation_pair = self
                .rotated_from
                .get(&sender)
                .is_some_and(|(n, _)| n == owner)
                || self
                    .rotated_from
                    .get(owner)
                    .is_some_and(|(n, _)| *n == sender);
            if sender != owner && !rotation_pair {
                log::debug!("[RUST] envelope from another sender than the circuit's peer dropped");
                return;
            }
        }
        self.dispatch_opened(opened, payload.len(), on_pending_circuit);
    }

    pub(crate) fn handle_sealed_payload(&mut self, payload: &[u8]) {
        if payload.first() == Some(&crate::sealed::KNOCK_VERSION) {
            self.handle_knock(payload);
            return;
        }
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let my_ik = identity.public_signing_key().to_bytes();
        match crate::sealed::open(&my_ik, identity.agreement_secret(), payload) {
            Ok(opened) => self.dispatch_opened(opened, payload.len(), false),
            Err(_) => log::debug!("[RUST] sealed payload did not open"),
        }
    }

    /// Set `is_connected` and its lock-free mirror together.
    pub(crate) fn set_connected(&mut self, connected: bool) {
        self.is_connected = connected;
        self.connected_mirror
            .store(connected, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stop accepting events from the current `WebSocketClient` and forget
    /// per-connection handshake state (manual disconnect, protocol failure,
    /// or a new `connect()`).
    pub(crate) fn retire_connection(&mut self) {
        self.connection_generation += 1;
        self.hello_outstanding = false;
        self.auth_challenge = None;
        self.publish_in_flight = false;
        self.notify_reconnect = false;
    }

    /// Handle one transport event, unless it comes from a retired client.
    pub(crate) fn handle_event(&mut self, generation: u64, event: CoreEvent) {
        if generation != self.connection_generation {
            log::debug!("[RUST] Dropping an event from a retired connection");
            return;
        }
        #[cfg(test)]
        if self.connecting {
            self.events_while_connecting_for_test += 1;
        }
        match event {
            CoreEvent::Frame(frame) => RChatClient::handle_frame(self, *frame),
            CoreEvent::Binary(data) => RChatClient::handle_binary(self, data),
            CoreEvent::Disconnected => self.handle_transport_disconnected(),
            CoreEvent::Reconnected => self.handle_transport_reconnected(),
        }
    }
}

impl ClientInner {
    /// Non-signaling frames are handled only after the relay gate passed and
    /// a publish was accepted on this connection (round-2 L5).
    fn frame_gate_open(&self) -> bool {
        self.is_key_bundle_published || self.bypass_frame_gate
    }

    /// A decrypted ratchet plaintext from an accepted peer. Format:
    /// `00 00 00 00` legacy invisible hello (v3 sends a cover reply,
    /// `05 01`, instead); `01 || text`; `02 || binary`; `0A`-`0F` reserved
    /// for call signalling and dropped like any unknown type (§9a);
    /// `06 ||` session notice (accepted only under the current session, `by`;
    /// its signature checked against that session's `binding`).
    /// `message_id` is the sealed envelope's id (§4.5): delivered as
    /// `ReceivedMessage.id`, and checked against the ids the app already has
    /// (an accepted intro) so the ratchet copy isn't shown twice. Content is
    /// untrusted and passed through; the app sanitises it for display.
    fn handle_decrypted_message(
        &mut self,
        sender: &str,
        message_id: [u8; 16],
        plaintext: &[u8],
        by: session::DecryptedBy,
        binding: Option<[u8; 32]>,
    ) {
        if plaintext == [0u8; 4] {
            return;
        }
        if plaintext.first() == Some(&notice::NOTICE_TYPE) {
            if let Some(n) = notice::decode(plaintext) {
                self.handle_notice(sender, n, by, binding);
            }
            return; // never a message, never receipted, never answered
        }
        if plaintext.first() == Some(&circuits::ROTATION_NOTICE_TYPE) {
            // A rotation notice is not a message and gets no receipt (§4.8).
            // It changes nothing either (security review L-1): only the chain
            // inside a knock from the new identity re-pins (`handle_knock`).
            return;
        }
        if plaintext.first() == Some(&circuits::COVER_TYPE) {
            // Cover traffic (spec §5.7): answer a request (round-2 M4); never
            // a message, a receipt or a seen id.
            if plaintext.get(1) == Some(&circuits::COVER_REQUEST) {
                self.schedule_cover_replies(sender, std::time::Instant::now());
            }
            return;
        }
        if plaintext.first() == Some(&receipts::RECEIPT_TYPE) {
            // Receipts are reported, never answered with a receipt.
            if let Some((kind, ids)) = receipts::decode(plaintext) {
                // A receipt under the current session also says that the
                // peer's notice for it left (same flush).
                let mut marked =
                    by == session::DecryptedBy::Current && self.note_peer_notice_heard(sender);
                for id in ids {
                    if !self.was_sent_to(sender, &id) {
                        continue; // forged or stale: never sent to this peer
                    }
                    // End-to-end proof: never reported undelivered (D37).
                    marked |= self.mark_sent_delivered(sender, &id);
                    // A timer change's receipt acknowledges it (R32); the
                    // app never hears of it.
                    if kind == receipts::DELIVERED && self.timer_receipt(sender, &id) {
                        continue;
                    }
                    if self.is_timer_id(sender, &id) {
                        continue;
                    }
                    if let Some(cb) = &self.callbacks {
                        cb.on_message_receipt(sender.to_string(), hex::encode(id), kind);
                    }
                }
                if marked {
                    let _ = self.persist_peer(sender);
                }
            }
            return;
        }
        if plaintext.first() == Some(&disappearing::TIMER_TYPE) {
            // A timer change (§I.2): applied when it wins, never a message.
            // A malformed one, an unknown value, one from a retired session
            // or one timed more than a day ahead of our clock is dropped
            // unreceipted (R33 I-1, M-8).
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok((secs, changed_at_ms)) = disappearing::decode_timer(plaintext) {
                if !self.timer_change_acceptable(changed_at_ms, by, now_ms) {
                    log::debug!("[RUST] timer change refused (retired session or far future)");
                    return;
                }
                self.apply_peer_timer(sender, secs, changed_at_ms);
                // Acknowledged end to end (R32), applied or not: a
                // duplicate or a losing change is still received.
                self.queue_receipt(sender, receipts::DELIVERED, &[message_id]);
                self.flush_receipts(sender);
            }
            return;
        }
        if !is_deliverable(plaintext) {
            log::debug!("[RUST] unknown plaintext type dropped");
            return;
        }
        let is_text = plaintext[0] == 0x01;
        if self.peers.is_seen(sender, &message_id) {
            // Already stored by the app (an intro or a resend): delivered
            // now (D36). The chain advanced anyway.
            self.queue_receipt(sender, receipts::DELIVERED, &[message_id]);
            return;
        }
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if plaintext[0] == file_msg::FILE_TYPE {
            // A file goes to its own callback only, never as a message
            // (§E.2); its receipt follows `mark_message_seen` like any
            // message's. `is_deliverable` already checked it decodes.
            let Ok(f) = file_msg::decode_file(plaintext) else {
                return;
            };
            let file = ReceivedFile {
                id: hex::encode(message_id),
                sender_identity: sender.to_string(),
                name: f.name,
                mime: f.mime,
                expire_secs: f.expire_secs,
                bytes: f.bytes,
                timestamp_ms,
            };
            self.drain_note_delivered(sender, message_id);
            match &self.callbacks {
                Some(cb) => cb.on_file_received(file),
                None => {
                    let mut file = file;
                    zeroize::Zeroize::zeroize(&mut file.bytes);
                }
            }
            return;
        }
        // "Delivered" means the app stored it (D36): the receipt is queued
        // when the app calls `mark_message_seen` (`mark_seen_and_receipt`),
        // also for media it then refuses as outside its limits (L5).
        // `is_deliverable` checked the timer is there.
        let Some((expire_secs, content)) = disappearing::split_expire(plaintext) else {
            return;
        };
        let msg = ReceivedMessage {
            id: hex::encode(message_id),
            sender_identity: sender.to_string(),
            content: content.to_vec(),
            timestamp_ms,
            is_text,
            expire_secs,
        };
        // To the callback. Without one (no app attached) the plaintext is
        // wiped, never kept: there is no polling queue (C-3).
        self.drain_note_delivered(sender, message_id);
        match &self.callbacks {
            Some(cb) => cb.on_message_received(msg),
            None => {
                let mut msg = msg;
                zeroize::Zeroize::zeroize(&mut msg.content);
            }
        }
    }
}

#[cfg(feature = "test-hooks")]
impl RChatClient {
    /// Integration tests only (`test-hooks` feature): trust this PEM
    /// certificate instead of the platform roots for later TLS connections.
    pub fn set_test_trust_pem(&self, pem: &[u8]) {
        let pem = pem.to_vec();
        self.query((), move |i| i.tls_tickets.set_test_trust_pem(&pem));
    }

    /// Run `f` on the client under its write lock (test hooks only).
    fn with_inner_for_test<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut ClientInner) -> T + Send + 'static,
    ) -> Result<T, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            Ok(f(&mut guard))
        })
    }

    /// End-to-end tests only (`test-hooks`): shift the clock the pair epoch
    /// (day, counter) and the 24 h identity-fallback clock read by
    /// `secs` (protocol v3 §C.1, §C.4). Nothing else reads it: knocks,
    /// receipts and timers keep the real clock.
    pub fn test_set_pair_clock_offset(&self, secs: i64) -> Result<(), RChatError> {
        self.with_inner_for_test(move |i| i.pair_clock_offset_secs = secs)
    }

    /// End-to-end tests only (`test-hooks`): blind asks (and the identity
    /// fallback ask) time out after `ttl` instead of `peers::ASK_TTL`.
    pub fn test_set_blind_ask_ttl(&self, ttl: std::time::Duration) -> Result<(), RChatError> {
        self.with_inner_for_test(move |i| i.blind_ask_ttl_override = Some(ttl))
    }

    /// End-to-end tests only (`test-hooks`): the stored pair epoch with
    /// `peer_hex` as (day, counter), if a session holds one.
    pub fn test_pair_epoch(&self, peer_hex: String) -> Option<(u32, u32)> {
        let peer = peer_hex.to_lowercase();
        self.with_inner_for_test(move |i| {
            i.session_manager
                .get(&peer)
                .map(|s| (s.pair_epoch.day, s.pair_epoch.counter))
        })
        .ok()
        .flatten()
    }

    /// End-to-end tests only (`test-hooks`): move the stored pair counter
    /// with `peer_hex` on by `by` (a counter desync, §C.1), persisted.
    pub fn test_bump_pair_counter(&self, peer_hex: String, by: u32) -> Result<(), RChatError> {
        let peer = peer_hex.to_lowercase();
        self.with_inner_for_test(move |i| {
            let moved = i.session_manager.get_mut(&peer).is_some_and(|mut s| {
                s.pair_epoch.counter = s.pair_epoch.counter.saturating_add(by);
                true
            });
            if !moved {
                return Err(RChatError::SessionNotEstablished { identity: peer });
            }
            i.persist_peer(&peer)
        })?
    }

    /// End-to-end tests only (`test-hooks`): replace the pair secret with
    /// `peer_hex` by a random one (a pair-secret mismatch: no blind ask can
    /// ever match), persisted.
    pub fn test_replace_pair_secret(&self, peer_hex: String) -> Result<(), RChatError> {
        let peer = peer_hex.to_lowercase();
        self.with_inner_for_test(move |i| {
            let replaced = i.session_manager.get_mut(&peer).is_some_and(|mut s| {
                if s.pair_secret.is_none() {
                    return false;
                }
                let mut ps = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ps);
                s.pair_secret = Some(zeroize::Zeroizing::new(ps));
                true
            });
            if !replaced {
                return Err(RChatError::SessionNotEstablished { identity: peer });
            }
            i.persist_peer(&peer)
        })?
    }
}

// Kept out of the exported block below: uniffi's export macro generates
// scaffolding for every method in it regardless of `cfg`, so a cfg-gated
// method there breaks `--features uniffi` builds.
#[cfg(any(test, feature = "test-hooks"))]
impl RChatClient {
    /// Tests only: the IANA id of the TLS key exchange group the latest
    /// relay connection negotiated (0x11EC: X25519MLKEM768; 0x001D: X25519).
    pub fn tls_key_exchange_group(&self) -> Option<u16> {
        self.query(None, |i| i.tls_tickets.last_group())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl RChatClient {
    /// Create a new RChat client
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(mut config: ClientConfig) -> Result<Arc<Self>, RChatError> {
        // Held wiped while the runtime is built: a failure there must not
        // free the seed as a plain `String` (R1-N2).
        let mut seed = config.identity_key_seed.take().map(zeroize::Zeroizing::new);
        let runtime = ClientRuntime::new().map_err(|e| RChatError::Internal {
            message: e.to_string(),
        })?;

        // Moved back for `ClientInner::new`, which takes it at once.
        config.identity_key_seed = seed.as_mut().map(|hex| std::mem::take(&mut **hex));
        drop(seed);
        let inner = ClientInner::new(config);
        let connected_mirror = inner.connected_mirror.clone();

        Ok(Arc::new(Self {
            runtime: Arc::new(runtime),
            inner: Arc::new(RwLock::new(inner)),
            callback_hub: CallbackHub::new(),
            cover_wanted: Arc::default(),
            steady_wanted: Arc::default(),
            connected_mirror,
            retired: Arc::default(),
            #[cfg(test)]
            pre_lock_delay_for_test: Arc::default(),
        }))
    }

    /// Tell `sender_hex` that these messages were read (end-to-end encrypted).
    pub fn send_read_receipt(
        &self,
        sender_hex: String,
        message_ids_hex: Vec<String>,
    ) -> Result<(), RChatError> {
        let ids = message_ids_hex
            .iter()
            .map(|h| message_id_from_hex(h))
            .collect::<Result<Vec<[u8; 16]>, RChatError>>()?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let peer = sender_hex.to_lowercase();
            let mut guard = inner.write().await;
            // A transient bad signature keeps the receipt queued, as
            // `send_receipts_now` does (Task 19 minor: it was refused).
            match guard.check_sendable(&peer) {
                Ok(()) | Err(RChatError::PeerKeyUnverified { .. }) => {}
                Err(e) => return Err(e),
            }
            guard.queue_receipt(&peer, receipts::READ, &ids);
            guard.flush_receipts(&peer);
            Ok(())
        })
    }

    /// Set the callback interface for UI updates. Callbacks run on their
    /// own thread, in order, never with client state locked (C-11), so one
    /// may call back into the client. Replacing callbacks keeps calls
    /// already queued (they go to the new ones, N-7). Waits for the lock
    /// rather than dropping the callbacks when it is busy (C-14).
    pub fn set_callbacks(&self, callbacks: Box<dyn RChatCallbacks>) {
        self.callback_hub.set_target(Arc::from(callbacks));
        let dispatcher: Box<dyn RChatCallbacks> = Box::new(HubCallbacks(self.callback_hub.clone()));
        if let Ok(mut inner) = self.inner.try_write() {
            inner.callbacks = Some(dispatcher);
            return;
        }
        let inner = self.inner.clone();
        let installed = block_on_async(self.runtime.clone(), move || async move {
            let mut guard = tokio::time::timeout(LOCK_WAIT, inner.write())
                .await
                .map_err(|_| RChatError::Internal {
                    message: "client busy".into(),
                })?;
            guard.callbacks = Some(dispatcher);
            Ok(())
        });
        if let Err(e) = installed {
            log::warn!("[RUST] callbacks not installed: {e}");
        }
    }

    /// Connect to the server
    pub fn connect(&self) -> Result<(), RChatError> {
        // A retired client never connects again (N-1).
        if self.retired.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RChatError::ConnectionFailed {
                message: "client retired".to_string(),
            });
        }
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        let callback_hub = self.callback_hub.clone();
        #[cfg(test)]
        let pre_lock_delay = *self
            .pre_lock_delay_for_test
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        block_on_async(runtime.clone(), move || async move {
            #[cfg(test)]
            tokio::time::sleep(pre_lock_delay).await;
            let mut guard = inner.write().await;

            log::info!("[RUST] connect() called");

            // A background drain's attempt that was given up (cancel or
            // deadline) before this connect took the lock: refused, never a
            // normal connection in its place (round 2 N-1).
            if guard.drain.as_ref().is_some_and(|d| d.aborted) {
                guard.drain = None;
                return Err(RChatError::ConnectionFailed {
                    message: "background drain attempt given up".to_string(),
                });
            }

            // A live (or still auto-reconnecting) client must be disconnected
            // first; otherwise two clients would feed the same state.
            if guard.is_connected || guard.websocket.is_some() || guard.connecting {
                log::info!("[RUST] connect() FAILED: Already connected");
                return Err(RChatError::ConnectionFailed {
                    message: "Already connected".to_string(),
                });
            }

            // Generate or load identity (only if not already set)
            if guard.identity.is_none() {
                let identity = match &guard.identity_seed {
                    Some(seed_hex) => identity_from_seed_hex(seed_hex)?,
                    None => IdentityKeyPair::generate(),
                };
                // Loaded: the seed is not needed again (wiped on drop).
                guard.identity_seed = None;

                let pub_key = identity.public_key_hex();
                log::debug!(
                    "[RUST] Identity generated/loaded: {}...",
                    &pub_key[..8.min(pub_key.len())]
                );

                guard.identity = Some(identity);
                guard.signed_bundle = None;
            } else {
                let pub_key = guard.identity.as_ref().unwrap().public_key_hex();
                log::debug!(
                    "[RUST] Using existing identity: {}...",
                    &pub_key[..8.min(pub_key.len())]
                );
            }
            if let Some(our_ik) = guard
                .identity
                .as_ref()
                .map(|i| i.public_signing_key().to_bytes())
            {
                guard.session_manager.set_our_identity(our_ik);
            }
            // Staged session records, opened before the transport opens
            // (spec §18.5).
            guard.restore_staged_state();

            // Create transport config
            // A background drain's connect (§H.1, R34 I-2): one attempt,
            // bounded by the drain's budget, and no auto-reconnect.
            let drain_connect = guard.drain.as_ref().map(|d| d.connect_secs);
            let transport_config = TransportConfig {
                server_url: guard.config.server_url.clone(),
                connection_timeout_secs: drain_connect
                    .unwrap_or(guard.config.connection_timeout_secs)
                    .min(guard.config.connection_timeout_secs.max(1))
                    as u64,
                reconnect_max_attempts: if drain_connect.is_some() {
                    1
                } else {
                    guard
                        .config
                        .reconnect_max_attempts
                        .min(MAX_RECONNECT_ATTEMPTS)
                },
                reconnect_base_delay_secs: 1,
                keepalive_interval_secs: guard.config.keepalive_interval_secs as u64,
                keepalive_timeout_secs: 10,
                delivery_confirmation_timeout_secs: 30,
                tls_fingerprint: guard.config.tls_fingerprint,
                auto_reconnect: drain_connect.is_none(),
                reconnect_max_attempts_after_connect: 0,
                dev_origin: guard.config.dev_origin.clone(),
                resumption: Some(guard.tls_tickets.clone()),
            };
            guard.bind_tls_tickets();

            // Create WebSocket client
            let ws_client = WebSocketClient::new(transport_config);

            // The transport's closures hold only a `Weak` to the client
            // state and a runtime `Handle`, never the runtime itself: the
            // transport lives inside that state, so a strong reference would
            // be a cycle that keeps the identity alive and drops the runtime
            // on one of its own threads (C-23).
            // All transport events go through one bounded queue and one task,
            // so they are handled in arrival order (a frame from a dropped
            // connection can never be handled after the reconnect that
            // replaced it) and a slow consumer pushes back on the socket (C-9).
            let (event_tx, mut event_rx) =
                tokio::sync::mpsc::channel::<CoreEvent>(EVENT_QUEUE_CAPACITY);
            // Events from any earlier client are dropped from here on.
            guard.retire_connection();
            let generation = guard.connection_generation;
            let weak = Arc::downgrade(&inner);
            let hub = callback_hub.clone();
            // Events wait until this connect has installed (or dropped) the
            // connection, as when connect held the lock throughout: none is
            // handled before the websocket and the hello are in place.
            let (installed_tx, installed_rx) = tokio::sync::oneshot::channel::<()>();
            runtime.spawn(async move {
                let _ = installed_rx.await;
                while let Some(event) = event_rx.recv().await {
                    // A slow app holds back the socket, not memory (N-2).
                    wait_for_callback_room(&hub).await;
                    let Some(inner) = weak.upgrade() else { break };
                    inner.write().await.handle_event(generation, event);
                }
            });
            ws_client.set_event_sink(event_tx);
            // The network part runs without the client lock (it can take up
            // to attempts x timeout): the app's calls, some on the UI thread,
            // must never wait for it. `connecting` refuses a second connect
            // meanwhile; a disconnect or retire meanwhile retires this
            // generation, and the connection is then dropped below.
            guard.connecting = true;
            #[cfg(test)]
            let install_delay = guard.install_delay_for_test;
            drop(guard);

            // Connect
            log::info!("[RUST] Connecting to WebSocket...");
            let connected = ws_client.connect().await;
            #[cfg(test)]
            tokio::time::sleep(install_delay).await;
            let mut guard = inner.write().await;
            guard.connecting = false;
            if guard.connection_generation != generation {
                // A given-up drain attempt ends here (round 2 N-1).
                if guard.drain.as_ref().is_some_and(|d| d.aborted) {
                    guard.drain = None;
                }
                drop(guard);
                drop(installed_tx);
                ws_client.disconnect().await;
                return Err(RChatError::ConnectionFailed {
                    message: "Disconnected while connecting".to_string(),
                });
            }
            let _ = installed_tx.send(());
            match connected {
                Ok(()) => {
                    log::info!("[RUST] WebSocket connected; sending hello v2");
                    guard.websocket = Some(ws_client);
                    if !guard.reask_ticker_started {
                        guard.reask_ticker_started = true;
                        spawn_ticker(&runtime, Arc::downgrade(&inner));
                    }
                    guard.transport_epoch += 1;
                    guard.requeue_unanswered_asks();
                    guard.auth_challenge = None;
                    guard.publish_in_flight = false;
                    guard.is_key_bundle_published = false;
                    // Connected is reported when the hello_response arrives.
                    let hello = crate::protocol::SignalingMessage::hello(vec![
                        crate::protocol::PROTOCOL_VERSION,
                    ]);
                    if let Err(e) = guard.send_signaling_now(&hello) {
                        // Without a hello the connection is useless: drop it
                        // (after releasing the lock).
                        let ws = guard.websocket.take();
                        guard.retire_connection();
                        drop(guard);
                        if let Some(ws) = ws {
                            ws.disconnect().await;
                        }
                        return Err(e);
                    }
                    guard.hello_outstanding = true;
                    // Every connection publishes once the challenge arrives,
                    // as an auto-reconnect does: without an accepted publish
                    // the frame gate stays shut, so the app never has to ask.
                    guard.publish_requested = true;
                    Ok(())
                }
                Err(e) => {
                    log::info!("[RUST] WebSocket connection FAILED: {}", e);
                    if let Some(cb) = &guard.callbacks {
                        cb.on_connection_status_changed(ConnectionStatus::Error {
                            message: e.to_string(),
                        });
                    }
                    Err(e)
                }
            }
        })
    }

    /// Disconnect from the server
    pub fn disconnect(&self) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();

        block_on_async(runtime, move || async move {
            let mut guard = inner.write().await;

            // Coalesced best-effort writes go before the sessions are wiped.
            guard.flush_deferred_writes();
            // Sessions are wiped below, so every peer must re-ask: close our circuits.
            for peer in guard.session_manager.get_all_recipients() {
                guard.close_circuit_with(&peer);
            }

            // Shut down after releasing the lock (below); retired first, so
            // nothing it still reports is handled.
            let ws = guard.websocket.take();
            // Tickets never outlive a disconnect (spec §D.1).
            guard.tls_tickets.clear();
            guard.set_connected(false);
            guard.is_key_bundle_published = false;
            guard.retire_connection();
            guard.publish_requested = false;
            guard.current_recipient = None;
            guard.session_manager = SessionManager::new();
            if let Some(our_ik) = guard
                .identity
                .as_ref()
                .map(|i| i.public_signing_key().to_bytes())
            {
                guard.session_manager.set_our_identity(our_ik);
            }

            if let Some(cb) = &guard.callbacks {
                cb.on_connection_status_changed(ConnectionStatus::Disconnected);
            }
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }

            Ok(())
        })
    }

    /// Disconnect transport only, preserving E2EE session state for fast reconnect.
    /// Used during network transitions (e.g. 4G→WiFi) where the connection drops
    /// but we want to resume messaging without re-establishing Double Ratchet sessions.
    pub fn disconnect_transport_only(&self) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();

        block_on_async(runtime, move || async move {
            let mut guard = inner.write().await;

            // Clear only transport-level state; preserve identity, sessions, and recipient
            let ws = guard.websocket.take();
            guard.set_connected(false);
            guard.is_key_bundle_published = false;
            guard.retire_connection();
            // NOTE: session_manager, pins and current_recipient are
            // intentionally preserved for a fast resume.

            if let Some(cb) = &guard.callbacks {
                cb.on_connection_status_changed(ConnectionStatus::Disconnected);
            }
            // Shut down without the client lock (retired above).
            drop(guard);
            if let Some(ws) = ws {
                ws.disconnect().await;
            }

            Ok(())
        })
    }

    /// Make `recipient_identity` the current recipient (spec §4.4 Pins).
    /// `Some(ak)` equal to the pin is a no-op that keeps a mismatch; a
    /// different `ak` re-pins from the contact's code; `None` needs an
    /// existing pin (`PeerNotAccepted`). Blocked peers: `PeerBlocked`.
    pub fn set_recipient(
        &self,
        recipient_identity: String,
        agreement_key: Option<String>,
    ) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        block_on_async(runtime, move || async move {
            let mut guard = inner.write().await;
            guard.apply_set_recipient(&recipient_identity, agreement_key.as_deref())
        })
    }

    /// Pin (accept) a peer's agreement key and, when known, its ML-KEM
    /// key (`kem_hex`, 2368 hex: card, request, rotation or the app's
    /// stored copy). Fails with `PinConflict` if a different agreement key
    /// or KEM key is pinned (never replaced: unpin first), `AgreementKeyInUse`
    /// if the key is pinned for another identity, `PeerBlocked` if the
    /// identity is blocked, `InvalidRecipient` for a malformed KEM key.
    pub fn pin_peer_key(
        &self,
        identity_hex: String,
        agreement_hex: String,
        kem_hex: Option<String>,
    ) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner
                .write()
                .await
                .pin_peer(&identity_hex, &agreement_hex, kem_hex.as_deref())
        })
    }

    /// Ask for a circuit with an accepted peer without changing the current
    /// recipient. Sends nothing while the circuit is live. Fails with
    /// `PeerNotAccepted`, `PeerBlocked` or `PeerKeyRejected`.
    pub fn request_circuit(&self, identity_hex: String) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let id = identity_hex.to_lowercase();
            inner
                .write()
                .await
                .ask(&id, circuits::AskTrigger::User, std::time::Instant::now())
        })
    }

    /// Forget a peer's pin; closes any live circuit with it.
    pub fn unpin_peer_key(&self, identity_hex: String) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.unpin_peer(&identity_hex)
        })
    }

    /// Block or unblock. Blocking unpins and closes any live circuit.
    pub fn set_peer_blocked(&self, identity_hex: String, blocked: bool) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.block_peer(&identity_hex, blocked)
        })
    }

    /// 0 none, 1 pinned, 2 mismatch, 3 bad signature, 4 blocked. While the
    /// client stays busy past a short wait this answers 0; use
    /// `peer_key_state_checked` to tell "busy" from "none".
    pub fn peer_key_state(&self, identity_hex: String) -> u8 {
        self.peer_key_state_checked(identity_hex).unwrap_or(0)
    }

    /// The 60-digit safety number with `peer_hex`, from the pinned keys.
    pub fn safety_number(&self, peer_hex: String) -> Result<String, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let guard = inner.read().await;
            let id = guard.identity.as_ref().ok_or(RChatError::NotConnected)?;
            let (ik, ak) = (
                id.public_signing_key().to_bytes(),
                *id.public_agreement_key().as_bytes(),
            );
            guard
                .peers
                .safety_number(&peer_hex, &ik, &ak)
                .map_err(|e| sn_error(e, &peer_hex))
        })
    }

    /// D22: compare the other phone's scanned safety-number QR.
    pub fn compare_scanned_safety_number(
        &self,
        peer_hex: String,
        scanned: String,
    ) -> Result<safety_number::ScanComparison, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let guard = inner.read().await;
            let id = guard.identity.as_ref().ok_or(RChatError::NotConnected)?;
            let (ik, ak) = (
                id.public_signing_key().to_bytes(),
                *id.public_agreement_key().as_bytes(),
            );
            guard
                .peers
                .compare_scanned_safety_number(&peer_hex, &ik, &ak, &scanned)
                .map_err(|e| sn_error(e, &peer_hex))
        })
    }

    /// The user compared `digits` with `peer_hex` (spec §4.7).
    pub fn mark_safety_number_compared(
        &self,
        peer_hex: String,
        digits: String,
    ) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            let id = guard.identity.as_ref().ok_or(RChatError::NotConnected)?;
            let (ik, ak) = (
                id.public_signing_key().to_bytes(),
                *id.public_agreement_key().as_bytes(),
            );
            guard
                .peers
                .mark_safety_number_compared(&peer_hex, &ik, &ak, &digits)
                .map_err(|e| sn_error(e, &peer_hex))
        })
    }

    /// Send a text message. Returns the 32-hex message id (also the id the
    /// relay acknowledges). Refused at once for a peer whose keys don't match
    /// (`PeerKeyRejected`), couldn't be checked (`PeerKeyUnverified`), who is
    /// blocked or not accepted; otherwise waits up to `send_wait_ms` for a
    /// live circuit.
    /// The message carries the contact's current disappearing timer
    /// (§I.2), read under the lock that seals it.
    pub fn send_text_message(&self, recipient: String, text: String) -> Result<String, RChatError> {
        self.send_text(recipient, text, None).map(|s| s.id)
    }

    /// Send a text message under a caller-chosen 32-hex message id (the
    /// intro id, so the recipient can de-duplicate the ratchet copy). A
    /// first send: the contact's current timer. A retry of a message
    /// already sent goes through `retry_text_message_using_id`.
    pub fn send_text_message_using_id(
        &self,
        recipient: String,
        text: String,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        self.send_text(recipient, text, Some(message_id_hex))
            .map(|s| s.id)
    }

    /// A first text send, under a fresh id or the caller's (the intro id).
    /// It carries the contact's current timer; `Sent` says which value
    /// (ruling R32: the app labels its own copy from it, never a later read).
    pub fn send_text(
        &self,
        recipient: String,
        text: String,
        message_id_hex: Option<String>,
    ) -> Result<Sent, RChatError> {
        // Wiped on every path, a refused id included (R30 M-3).
        let text = zeroize::Zeroizing::new(text);
        let id = new_or_given_id(message_id_hex.as_deref())?;
        let body = disappearing::with_expire(0, text.as_bytes());
        self.send_payload(recipient, body, MessageType::Text, id)
    }

    /// The app's same-id retry or manual resend of a text it already sent
    /// (spec §18.8, D23/D38 fallback): `expire_secs` is the message's
    /// original timer (§I.2, ruling R32), one of the choices
    /// (`InvalidParameter` otherwise). Not the checked automatic resend
    /// (`resend_text_message_using_id`).
    pub fn retry_text_message_using_id(
        &self,
        recipient: String,
        text: String,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        let text = zeroize::Zeroizing::new(text);
        let id = message_id_from_hex(&message_id_hex)?;
        check_timer(expire_secs)?;
        let body = disappearing::with_expire(expire_secs, text.as_bytes());
        self.send_payload_checked(recipient, body, MessageType::Text, id, false, false)
            .map(|s| s.id)
    }

    /// The automatic resend of `ResendEligible` (spec §18.6 D38): the stored
    /// text under its own id, refused (`ResendRefused`) unless the current
    /// session is the one that made the id eligible, the peer is still
    /// plainly pinned and the D38 guards on the sent entry still hold.
    /// `expire_secs` is the message's timer when it was first sent (§I.2),
    /// one of `disappearing::TIMER_CHOICES_SECS` (`InvalidParameter`
    /// otherwise): a resend never takes the current timer.
    pub fn resend_text_message_using_id(
        &self,
        recipient: String,
        text: String,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        // Wiped on every path, a refused id or timer included.
        let text = zeroize::Zeroizing::new(text);
        let id = message_id_from_hex(&message_id_hex)?;
        check_timer(expire_secs)?;
        let body = disappearing::with_expire(expire_secs, text.as_bytes());
        self.send_payload_checked(recipient, body, MessageType::Text, id, true, false)
            .map(|s| s.id)
    }

    /// `resend_text_message_using_id` for a binary (media) message, with
    /// its original `expire_secs`.
    pub fn resend_binary_message_using_id(
        &self,
        recipient: String,
        data: Vec<u8>,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        // Wiped on every path, a refused body, id or timer included.
        let data = zeroize::Zeroizing::new(data);
        check_known_binary(&data)?;
        let id = message_id_from_hex(&message_id_hex)?;
        check_timer(expire_secs)?;
        let body = disappearing::with_expire(expire_secs, &data);
        self.send_payload_checked(recipient, body, MessageType::Binary, id, true, false)
            .map(|s| s.id)
    }

    /// `retry_text_message_using_id` for a binary (media) message.
    pub fn retry_binary_message_using_id(
        &self,
        recipient: String,
        data: Vec<u8>,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        let data = zeroize::Zeroizing::new(data);
        check_known_binary(&data)?;
        let id = message_id_from_hex(&message_id_hex)?;
        check_timer(expire_secs)?;
        let body = disappearing::with_expire(expire_secs, &data);
        self.send_payload_checked(recipient, body, MessageType::Binary, id, false, false)
            .map(|s| s.id)
    }

    /// Queue a first message for an accepted peer with no session yet; it
    /// travels sealed inside knocks (§6.5). Returns the 32-hex intro id; send
    /// the same text later with `send_text_message_using_id(intro id)`.
    /// The intro is deniable but not forward-secret (static-static DH).
    pub fn set_intro(&self, identity_hex: String, text: String) -> Result<String, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let id = identity_hex.to_lowercase();
            inner
                .write()
                .await
                .set_intro(&id, &text, std::time::Instant::now())
        })
    }

    /// `set_intro` under the id the app already gave this intro (re-armed
    /// after a relaunch: core intros live in memory only), so the recipient
    /// can still de-duplicate it against the real message.
    pub fn set_intro_with_id(
        &self,
        identity_hex: String,
        text: String,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        let preset = message_id_from_hex(&message_id_hex)?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let id = identity_hex.to_lowercase();
            inner.write().await.set_intro_with_id(
                &id,
                &text,
                Some(preset),
                std::time::Instant::now(),
            )
        })
    }

    /// The app has stored this message (or deliberately dropped it), or
    /// already has it (e.g. an accepted intro): its delivered receipt is
    /// queued now (D36), and a later ratchet copy is decrypted to stay in
    /// step but not delivered again. At most `peers::SEEN_IDS_CAP` per peer.
    pub fn mark_message_seen(
        &self,
        sender_hex: String,
        message_id_hex: String,
    ) -> Result<(), RChatError> {
        let id = message_id_from_hex(&message_id_hex)?;
        // A 64-hex identity only (Task 15 minor): anything else would file
        // seen-ids under a key no sender can have.
        if peers::key_from_hex(&sender_hex).is_none() {
            return Err(RChatError::InvalidRecipient {
                identity: sender_hex,
            });
        }
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner
                .write()
                .await
                .mark_seen_and_receipt(&sender_hex.to_lowercase(), id)
        })
    }

    /// Send a binary message: media, or text that starts with an old
    /// in-band media prefix. `data` must start with a known magic
    /// (`protocol::is_known_binary`); receivers drop anything else.
    pub fn send_binary_message(
        &self,
        recipient: String,
        data: Vec<u8>,
    ) -> Result<String, RChatError> {
        self.send_binary(recipient, data, None).map(|s| s.id)
    }

    /// A first binary send, under a fresh id or the caller's, as `send_text`.
    pub fn send_binary(
        &self,
        recipient: String,
        data: Vec<u8>,
        message_id_hex: Option<String>,
    ) -> Result<Sent, RChatError> {
        // Wiped on every path, a refused body or id included.
        let data = zeroize::Zeroizing::new(data);
        check_known_binary(&data)?;
        let id = new_or_given_id(message_id_hex.as_deref())?;
        let body = disappearing::with_expire(0, &data);
        self.send_payload(recipient, body, MessageType::Binary, id)
    }

    /// Send a file message (`0x07`, protocol v3 §E.2) and return its 32-hex
    /// message id, as `send_binary_message` does. The name is cleaned
    /// (`file_msg::sanitise_name`) before it leaves; `mime` is advisory and
    /// must be printable ASCII of at most 255 bytes (`InvalidParameter`);
    /// the whole plaintext must fit `file_msg::MAX_FILE_PLAINTEXT`
    /// (`FileTooLarge`). Both are checked before anything else.
    /// The message carries the contact's current disappearing timer (§I.2),
    /// read under the lock that seals it. Files travel outside the steady
    /// shape unless the whole plaintext fits a slot, and are ack-tracked
    /// like any message.
    pub fn send_file_message(
        &self,
        recipient: String,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Result<String, RChatError> {
        self.send_file(recipient, name, mime, data, None)
            .map(|s| s.id)
    }

    /// `send_file_message` under a caller-chosen 32-hex id: a first send
    /// with an id the app picked (the contact's current timer). A Retry of
    /// a file already sent goes through `retry_file_message_using_id`.
    /// Checked in this order: the id (`Internal`), then the MIME
    /// (`InvalidParameter`) and the size (`FileTooLarge`). `data` is wiped
    /// on every path, a refused id included.
    pub fn send_file_message_using_id(
        &self,
        recipient: String,
        name: String,
        mime: String,
        data: Vec<u8>,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        self.send_file(recipient, name, mime, data, Some(message_id_hex))
            .map(|s| s.id)
    }

    /// A first file send, under a fresh id or the caller's, as `send_text`.
    pub fn send_file(
        &self,
        recipient: String,
        name: String,
        mime: String,
        data: Vec<u8>,
        message_id_hex: Option<String>,
    ) -> Result<Sent, RChatError> {
        let data = zeroize::Zeroizing::new(data);
        let id = new_or_given_id(message_id_hex.as_deref())?;
        let body = file_body(&name, &mime, &data, 0)?;
        self.send_payload(recipient, body, MessageType::File, id)
    }

    /// The app's same-id Retry or manual resend of a file it already sent
    /// (spec §18.8): the original name, MIME and bytes (the core keeps no
    /// file bytes after an ack or eviction) and its original `expire_secs`
    /// (§I.2, R32). Checked in the order `send_file_message_using_id`
    /// checks, then the timer (`InvalidParameter`).
    pub fn retry_file_message_using_id(
        &self,
        recipient: String,
        name: String,
        mime: String,
        data: Vec<u8>,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        let data = zeroize::Zeroizing::new(data);
        let id = message_id_from_hex(&message_id_hex)?;
        let body = file_body(&name, &mime, &data, expire_secs)?;
        check_timer(expire_secs)?;
        self.send_payload_checked(recipient, body, MessageType::File, id, false, false)
            .map(|s| s.id)
    }

    /// The automatic resend of a `ResendEligible` file (spec §18.6 D38,
    /// final review H-1): as `retry_file_message_using_id`, but refused
    /// (`ResendRefused`) unless the current session is the one that made
    /// the id eligible, as `resend_binary_message_using_id`.
    pub fn resend_file_message_using_id(
        &self,
        recipient: String,
        name: String,
        mime: String,
        data: Vec<u8>,
        expire_secs: u32,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        let data = zeroize::Zeroizing::new(data);
        let id = message_id_from_hex(&message_id_hex)?;
        let body = file_body(&name, &mime, &data, expire_secs)?;
        check_timer(expire_secs)?;
        self.send_payload_checked(recipient, body, MessageType::File, id, true, false)
            .map(|s| s.id)
    }

    /// Change the disappearing timer for `peer_hex` (protocol v3 §I.2):
    /// `secs` must be one of `disappearing::TIMER_CHOICES_SECS`
    /// (`InvalidParameter` otherwise, nothing sent), and the peer one we may
    /// send to (pinned, not blocked). The change applies here at once
    /// (persisted with the peer record, reported through `on_timer_changed`
    /// with `by_me`) and goes to the contact as a `0x09` plaintext inside
    /// the session, padded and ack-tracked like a message: now when the
    /// session can send, otherwise when it can. The core owns its delivery
    /// (ruling R32): until the contact's delivered receipt comes back it is
    /// re-sent when reported lost and after each new session install. Its
    /// time is now, or just after the current change if that one is later
    /// (a peer's clock ahead of ours), so the change wins on both phones.
    /// Returns what is in force afterwards (R33 I-1): the app shows that,
    /// never the requested value. A change that turns the timer on drops
    /// the intro queued for the contact (final review M-1: an intro carries
    /// no timer) and names it in `intro_dropped`.
    pub fn set_disappearing_timer(
        &self,
        peer_hex: String,
        secs: u32,
    ) -> Result<disappearing::TimerOutcome, RChatError> {
        check_timer(secs)?;
        let peer = peer_hex.to_lowercase();
        if peers::key_from_hex(&peer).is_none() {
            return Err(RChatError::InvalidRecipient { identity: peer });
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let outcome = inner.write().await.change_timer(&peer, secs, now_ms)?;
            // Sent now when the session can send; otherwise it waits on
            // the session and goes with the next flush or install.
            Self::flush_queued_sends(&inner).await;
            Ok(outcome)
        })
    }

    /// The disappearing timer for `peer_hex` (0 = off), as new sends carry it.
    pub fn disappearing_timer(&self, peer_hex: String) -> Result<u32, RChatError> {
        let peer = peer_hex.to_lowercase();
        if peers::key_from_hex(&peer).is_none() {
            return Err(RChatError::InvalidRecipient { identity: peer });
        }
        self.query(
            Err(RChatError::Internal {
                message: "client busy".into(),
            }),
            move |i| Ok(i.timer_secs(&peer)),
        )
    }

    /// A message expired on this device (§I.2): the core drops any copy of
    /// its plaintext it still holds (the ack tracker's kept copy, a copy
    /// queued for a session). Nothing is sent and nothing reaches the relay.
    pub fn forget_message(&self, message_id_hex: String) -> Result<(), RChatError> {
        message_id_from_hex(&message_id_hex)?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.forget_message(&message_id_hex);
            Ok(())
        })
    }

    /// Get the client's identity public key (for sharing with contacts)
    pub fn get_identity(&self) -> Result<String, RChatError> {
        let busy = Err(RChatError::Internal {
            message: "Failed to acquire read lock".to_string(),
        });
        self.query(busy, |i| {
            i.identity
                .as_ref()
                .map(|id| id.public_key_hex())
                .ok_or(RChatError::NotConnected)
        })
    }

    /// Get the client's agreement key (X25519, for E2EE)
    pub fn get_agreement_key(&self) -> Result<String, RChatError> {
        let busy = Err(RChatError::Internal {
            message: "Failed to acquire read lock".to_string(),
        });
        self.query(busy, |i| {
            i.identity
                .as_ref()
                .map(|id| id.agreement_key_hex())
                .ok_or(RChatError::NotConnected)
        })
    }

    /// Generate identity from a deterministic seed
    pub fn generate_identity_from_seed(&self, seed: &[u8]) -> Result<(), RChatError> {
        if seed.len() != 32 {
            return Err(RChatError::Internal {
                message: format!("Seed must be 32 bytes, got {}", seed.len()),
            });
        }
        let seed_array: [u8; 32] = seed.try_into().map_err(|_| RChatError::Internal {
            message: "Failed to convert seed to fixed array".to_string(),
        })?;
        let mut inner = self.inner.try_write().map_err(|_| RChatError::Internal {
            message: "Failed to acquire write lock".to_string(),
        })?;
        // Never under a connect or a live connection (review M-4): the
        // publish would sign with a key the restored sessions were not
        // made for.
        if inner.connecting || inner.websocket.is_some() || inner.is_connected {
            return Err(RChatError::Internal {
                message: "Identity can't change while connecting or connected".to_string(),
            });
        }

        let full_seed = expand_seed_to_64(&seed_array);
        let identity = IdentityKeyPair::from_seed(&full_seed[..])?;
        inner
            .session_manager
            .set_our_identity(identity.public_signing_key().to_bytes());
        inner.identity = Some(identity);
        inner.signed_bundle = None;
        // A ticket would link the old identity's connections to the new one's.
        inner.tls_tickets.clear();
        Ok(())
    }

    /// Connect to server (blocking version)
    pub fn connect_blocking(&self) -> Result<(), RChatError> {
        self.connect()
    }

    /// Disconnect from server (blocking version)
    pub fn disconnect_blocking(&self) -> Result<(), RChatError> {
        self.disconnect()
    }

    /// Check if key bundle has been published
    pub fn is_key_bundle_published(&self) -> bool {
        if let Ok(inner) = self.inner.try_read() {
            inner.is_key_bundle_published
        } else {
            false
        }
    }

    /// Spec §4.8: a new identity plus a link signed by the current one at
    /// `identity_version + 1`. The new seed stays in the core for
    /// `take_rotation_seed` (round-2 L4); nothing else changes until the app
    /// stores the seed, announces and reconnects with the new config.
    /// JSON: {"new_version","links","new_identity","new_agreement"} — no seed.
    pub fn prepare_rotation(&self) -> Result<String, RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            if guard
                .config
                .rotated_at_unix
                .is_some_and(|at| unix_now_secs().saturating_sub(at) < ROTATION_INTERVAL_SECS)
            {
                return Err(RChatError::RotationTooSoon);
            }
            let old = guard.identity.as_ref().ok_or(RChatError::NotConnected)?;
            let version = guard
                .config
                .identity_version
                .checked_add(1)
                .ok_or_else(|| RChatError::Internal {
                    message: "key version overflow".into(),
                })?;
            let new = IdentityKeyPair::generate();
            let (nik, nak) = (
                new.public_signing_key().to_bytes(),
                *new.public_agreement_key().as_bytes(),
            );
            let link = rotation::sign_link(old, &nik, &nak, version);
            let mut links = guard
                .config
                .rotation_links_hex
                .as_deref()
                .map(parse_links_hex)
                .unwrap_or_default();
            links.push(link.clone());
            let keep = links.len().saturating_sub(rotation::MAX_CHAIN);
            let mut links = links.split_off(keep);
            if rotation::verify_chain_to(&links, &nik, &nak).is_err() {
                // The saved links do not lead here: carry the new link alone.
                log::debug!("[RUST] saved rotation links do not connect; using the new link only");
                links = vec![link];
            }
            rotation::verify_chain_to(&links, &nik, &nak).map_err(|e| RChatError::Internal {
                message: format!("rotation link invalid: {e}"),
            })?;
            let links_hex: String = links.iter().map(|l| hex::encode(l.to_bytes())).collect();
            let mut seed = Box::new(zeroize::Zeroizing::new([0u8; 64]));
            new.write_seed(&mut seed);
            guard.pending_rotation_seed = Some(seed);
            Ok(serde_json::json!({
                "new_version": version,
                "links": links_hex,
                "new_identity": hex::encode(nik),
                "new_agreement": hex::encode(nak),
            })
            .to_string())
        })
    }

    /// Send the rotation notice over every live circuit, still as the old
    /// identity (spec §4.8). `links_hex` is the `links` from
    /// `prepare_rotation`; its last link must start at our current identity.
    /// Returns how many notices were queued.
    pub fn announce_rotation(&self, links_hex: String) -> Result<u32, RChatError> {
        let links = parse_links_hex(&links_hex);
        let last = links.last().cloned().ok_or_else(|| RChatError::Internal {
            message: "no rotation link".into(),
        })?;
        let block = rotation::RotationBlock {
            current_version: last.new_version,
            links,
        };
        rotation::verify_chain_to(
            &block.links,
            &last.new_identity_key,
            &last.new_agreement_key,
        )
        .and_then(|()| block.encode().map(|_| ()))
        .map_err(|e| RChatError::Internal {
            message: format!("rotation links invalid: {e}"),
        })?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let mut guard = inner.write().await;
            let me = guard
                .identity
                .as_ref()
                .ok_or(RChatError::NotConnected)?
                .public_signing_key()
                .to_bytes();
            if last.prev_identity_key != me {
                return Err(RChatError::Internal {
                    message: "rotation links are not from this identity".into(),
                });
            }
            Ok(guard.announce_rotation(&block))
        })
    }

    /// The pinned key version of a contact (QR card `"kv"`, accepted request).
    pub fn set_peer_key_version(
        &self,
        identity_hex: String,
        version: u32,
    ) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let id = identity_hex.to_lowercase();
            let mut guard = inner.write().await;
            if guard.peers.pin_for(&id).is_none() {
                return Err(RChatError::NoPinnedKeys { identity: id });
            }
            guard.peers.set_pin_version(&id, version);
            Ok(())
        })
    }

    /// Diagnostics: whether the latest TLS connection to the relay resumed
    /// a session from a ticket (spec §D.1).
    pub fn tls_session_resumed(&self) -> bool {
        self.query(false, |i| i.tls_tickets.last_resumed())
    }

    /// Diagnostics: TLS tickets held for the relay (at most 2, memory only).
    pub fn tls_ticket_count(&self) -> u32 {
        self.query(0, |i| i.tls_tickets.len() as u32)
    }

    /// The relay identity accepted on the current connection, as JSON
    /// `{"origin","pin","version","source"}` (source: tofu, pinned, rotated).
    pub fn relay_pin_info(&self) -> Option<String> {
        self.query(None, |i| i.relay_pin_info_json())
    }

    pub fn has_session(&self, recipient: String) -> bool {
        let r = recipient.to_lowercase();
        self.query(false, move |i| {
            i.is_connected && i.peers.state(&r) != PeerKeyState::Mismatch && i.has_live_circuit(&r)
        })
    }

    pub fn can_send(&self, recipient: String) -> bool {
        let r = recipient.to_lowercase();
        self.query(false, move |i| {
            i.is_connected
                && i.peers.state(&r) == PeerKeyState::Pinned
                && i.has_live_circuit(&r)
                && i.session_manager
                    .get(&r)
                    .map(|s| s.can_send())
                    .unwrap_or(false)
        })
    }

    /// Check if any session is established
    pub fn has_any_session(&self) -> bool {
        if let Ok(inner) = self.inner.try_read() {
            !inner.session_manager.is_empty()
        } else {
            false
        }
    }

    /// Get the first established recipient (for testing)
    pub fn get_established_recipient(&self) -> Option<String> {
        if let Ok(inner) = self.inner.try_read() {
            inner.session_manager.get_first_established_recipient()
        } else {
            None
        }
    }

    /// Get current connection status
    pub fn get_connection_status(&self) -> ConnectionStatus {
        let connected = match self.inner.try_read() {
            Ok(inner) => inner.is_connected,
            // Busy is not disconnected (the app would force a reconnect):
            // the last state the client recorded.
            Err(_) => self
                .connected_mirror
                .load(std::sync::atomic::Ordering::SeqCst),
        };
        if connected {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        }
    }

    /// Check if this client is the E2EE initiator for the current session
    /// Returns true if we initiated the E2EE handshake (our identity > their identity)
    pub fn is_e2ee_initiator(&self) -> bool {
        if let Ok(inner) = self.inner.try_read() {
            inner.is_e2ee_initiator
        } else {
            false
        }
    }

    /// Steady traffic (protocol v3 §B): one same-size packet every slot
    /// while enabled, in the foreground and connected with an open
    /// circuit. Off by default; while it is on and in the foreground it
    /// replaces the random cover requests of `set_cover_traffic`.
    /// `slot_ms` must be one of `steady::STEADY_SLOT_CHOICES_MS`
    /// (otherwise `InvalidParameter`). Never waits for the client lock (as
    /// `set_cover_traffic`); the last call wins.
    pub fn set_steady_traffic(
        &self,
        enabled: bool,
        slot_ms: u32,
        foreground: bool,
    ) -> Result<(), RChatError> {
        if !steady::valid_slot_ms(slot_ms) {
            return Err(RChatError::InvalidParameter {
                message: "steady slot must be 500, 1000 or 2000 ms".into(),
            });
        }
        *self.steady_wanted.lock().unwrap_or_else(|e| e.into_inner()) =
            (enabled, slot_ms, foreground);
        let wanted = self.steady_wanted.clone();
        if let Ok(mut guard) = self.inner.try_write() {
            Self::apply_steady_wanted(&mut guard, &wanted);
            return Ok(());
        }
        let inner = self.inner.clone();
        self.runtime.spawn(async move {
            let mut guard = inner.write().await;
            Self::apply_steady_wanted(&mut guard, &wanted);
        });
        Ok(())
    }

    /// "Extra traffic protection" (spec §5.7): send cover packets while
    /// enabled and in the foreground. Off by default. Replies to a peer's
    /// cover requests are sent either way.
    /// Never waits for the client lock: the app calls this from the UI
    /// thread on every scene-phase change, and a connect or reconnect holds
    /// the lock across network I/O. Applied now when the lock is free,
    /// otherwise as soon as it is; the last call wins.
    pub fn set_cover_traffic(&self, enabled: bool, foreground: bool) {
        *self.cover_wanted.lock().unwrap_or_else(|e| e.into_inner()) = (enabled, foreground);
        let wanted = self.cover_wanted.clone();
        if let Ok(mut guard) = self.inner.try_write() {
            Self::apply_cover(&mut guard, &wanted);
            return;
        }
        let inner = self.inner.clone();
        self.runtime.spawn(async move {
            let mut guard = inner.write().await;
            Self::apply_cover(&mut guard, &wanted);
        });
    }

    /// Process pending operations (call this periodically from UI)
    pub fn process_pending(&self) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        block_on_async(runtime, move || async move {
            {
                let mut guard = inner.write().await;
                let now = std::time::Instant::now();
                guard.flush_deferred_writes();
                if guard.in_drain() {
                    // A background drain sends nothing (§H.1).
                    return Ok(());
                }
                guard.fire_due_reasks(now);
                guard.fire_due_receipts(now);
                guard.fire_cover(now);
            }
            Self::flush_queued_sends(&inner).await;
            Ok(())
        })
    }

    /// Publish the signed key bundle. Recorded until the relay's challenge
    /// arrives; complete only when the relay acknowledges it. `connect`
    /// already requests it, so calling this after a connect is a no-op.
    pub fn publish_key_bundle(&self) -> Result<(), RChatError> {
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        block_on_async(runtime, move || async move {
            let mut guard = inner.write().await;
            guard.request_publish()
        })
    }
}

/// A safety-number error as the client's error type.
pub(crate) fn sn_error(e: peers::SafetyNumberError, peer: &str) -> RChatError {
    match e {
        peers::SafetyNumberError::NoPinnedKeys => RChatError::NoPinnedKeys {
            identity: peer.to_lowercase(),
        },
        peers::SafetyNumberError::Changed => RChatError::SafetyNumberChanged,
        peers::SafetyNumberError::BadPeer => RChatError::InvalidRecipient {
            identity: peer.to_string(),
        },
        peers::SafetyNumberError::BadDigits => RChatError::InvalidSafetyNumber,
    }
}

/// A file send's body (`file_msg::encode_file_body`, errors mapped for the
/// app). The caller holds `data` in `Zeroizing`; the body is wiped by
/// `send_payload_checked`.
fn file_body(name: &str, mime: &str, data: &[u8], expire_secs: u32) -> Result<Vec<u8>, RChatError> {
    file_msg::encode_file_body(name, mime, data, expire_secs).map_err(|e| match e {
        file_msg::FileError::TooLarge => RChatError::FileTooLarge {
            max: file_msg::MAX_FILE_PLAINTEXT as u64,
        },
        _ => RChatError::InvalidParameter {
            message: "MIME type must be printable ASCII, at most 255 bytes".into(),
        },
    })
}

/// What a send handed to the core: its 32-hex id and the disappearing
/// timer it carries (§I.2). For a first send that is the contact's timer
/// as the core held it when it checked the send (ruling R32).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Sent {
    pub id: String,
    pub expire_secs: u32,
}

/// The caller's 32-hex id, or a fresh random one.
fn new_or_given_id(hex_id: Option<&str>) -> Result<[u8; 16], RChatError> {
    match hex_id {
        Some(h) => message_id_from_hex(h),
        None => {
            let mut id = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
            Ok(id)
        }
    }
}

/// A binary body must start with a known magic (`protocol::is_known_binary`).
fn check_known_binary(data: &[u8]) -> Result<(), RChatError> {
    if crate::protocol::is_known_binary(data) {
        Ok(())
    } else {
        Err(RChatError::Internal {
            message: "unknown binary payload".into(),
        })
    }
}

/// One of `disappearing::TIMER_CHOICES_SECS`, or `InvalidParameter`.
fn check_timer(secs: u32) -> Result<(), RChatError> {
    if disappearing::valid_timer(secs) {
        Ok(())
    } else {
        Err(RChatError::InvalidParameter {
            message: "timer must be off, 5 minutes, 1 hour, 1 day, 1 week or 4 weeks".into(),
        })
    }
}

/// Parse a caller-supplied 32-hex message id (app/FFI boundary). The one
/// place the format check and its error live.
pub(crate) fn message_id_from_hex(s: &str) -> Result<[u8; 16], RChatError> {
    circuits::message_id_from_hex(s).ok_or_else(|| RChatError::Internal {
        message: "message id must be 32 hex characters".into(),
    })
}

/// Expand a 32-byte seed to 64 bytes using blake3
fn expand_seed_to_64(seed_32: &[u8; 32]) -> zeroize::Zeroizing<[u8; 64]> {
    let expanded = blake3::hash(seed_32);
    let expanded_bytes = expanded.as_bytes();
    let mut full_seed = zeroize::Zeroizing::new([0u8; 64]);
    full_seed[0..32].copy_from_slice(seed_32);
    full_seed[32..64].copy_from_slice(&expanded_bytes[0..32]);
    full_seed
}

/// The identity from a 64- or 32-byte (expanded) hex seed. Every decoded
/// copy is wiped, and no error echoes seed characters (C-10).
fn identity_from_seed_hex(seed_hex: &str) -> Result<IdentityKeyPair, RChatError> {
    // Decoded straight into fixed wiped buffers: no growing Vec is freed
    // holding seed bytes (N-3).
    let invalid = || RChatError::Internal {
        message: "Invalid seed hex".to_string(),
    };
    match seed_hex.len() {
        128 => {
            let mut seed = zeroize::Zeroizing::new([0u8; 64]);
            hex::decode_to_slice(seed_hex, &mut seed[..]).map_err(|_| invalid())?;
            IdentityKeyPair::from_seed(&seed[..])
        }
        64 => {
            // Expand 32-byte seed to 64 bytes (iOS compatibility)
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(seed_hex, &mut seed[..]).map_err(|_| invalid())?;
            IdentityKeyPair::from_seed(&expand_seed_to_64(&seed)[..])
        }
        n if n % 2 == 0 && seed_hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Err(RChatError::Internal {
                message: format!("Seed must be 32 or 64 bytes, got {}", n / 2),
            })
        }
        _ => Err(invalid()),
    }
}

impl RChatClient {
    /// Apply the latest wanted steady setting (under the client lock).
    fn apply_steady_wanted(guard: &mut ClientInner, wanted: &std::sync::Mutex<(bool, u32, bool)>) {
        let (enabled, slot_ms, foreground) = *wanted.lock().unwrap_or_else(|e| e.into_inner());
        guard.apply_steady(enabled, slot_ms, foreground);
    }

    /// Apply the latest wanted cover setting (under the client lock).
    fn apply_cover(guard: &mut ClientInner, wanted: &std::sync::Mutex<(bool, bool)>) {
        let (enabled, foreground) = *wanted.lock().unwrap_or_else(|e| e.into_inner());
        guard.cover_enabled = enabled;
        guard.cover_foreground = foreground;
        if !(enabled && foreground) {
            guard.cover_next = None;
        }
    }

    /// `send_binary_message` under a caller-chosen 32-hex id: a first send
    /// with an id the app picked (the contact's current timer). A resend of
    /// media already sent goes through `retry_binary_message_using_id`.
    pub fn send_binary_message_using_id(
        &self,
        recipient: String,
        data: Vec<u8>,
        message_id_hex: String,
    ) -> Result<String, RChatError> {
        self.send_binary(recipient, data, Some(message_id_hex))
            .map(|s| s.id)
    }

    /// Sign our session notices with this install's device key (D45). The
    /// signer is called synchronously while a notice is built, with the
    /// client lock held: it must not call back into rchat.
    pub fn set_device_signer(&self, s: Arc<dyn device_key::DeviceSigner>) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.device_signer = Some(s);
            Ok(())
        });
    }

    /// The identity's signature binding this install's device key (D43, the
    /// card's `dks`). Needs the identity, loaded by `connect`: before the
    /// first connect it fails with `NotConnected`.
    pub fn device_key_binding(
        &self,
        dk_pub: [u8; 65],
        hardware: bool,
    ) -> Result<[u8; 64], RChatError> {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let g = inner.read().await;
            let identity = g.identity.as_ref().ok_or(RChatError::NotConnected)?;
            keyauth::sign_device_key(identity, &dk_pub, hardware).map_err(|e| {
                RChatError::Internal {
                    message: format!("device key not bound: {e}"),
                }
            })
        })
    }

    /// Pin a contact's device key from their scanned or pasted card, or
    /// restore one the app stored from such a scan (D44). Only the app's
    /// scan, paste and restore paths may call this; nothing received ever
    /// does. `dks` must verify under the identity (`Internal` if not), and
    /// the identity must be pinned (`PinConflict` if not). A different DK
    /// replaces the old one (a re-scan).
    pub fn pin_device_key(
        &self,
        identity_hex: String,
        dk_pub: [u8; 65],
        hardware: bool,
        dks: [u8; 64],
    ) -> Result<(), RChatError> {
        let id = identity_hex.to_lowercase();
        let ik = peers::key_from_hex(&id).ok_or_else(|| RChatError::InvalidRecipient {
            identity: identity_hex.clone(),
        })?;
        keyauth::verify_device_key(&ik, &dk_pub, hardware, &dks).map_err(|e| {
            RChatError::Internal {
                message: format!("device key binding refused: {e}"),
            }
        })?;
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            let mut g = inner.write().await;
            if g.peers.pin_for(&id).is_none() {
                return Err(RChatError::PinConflict);
            }
            g.peers
                .pin_device_key(&id, device_key::DevicePin { dk_pub, hardware });
            Ok(())
        })
    }

    /// Pin `identity_hex`'s ML-KEM-768 public key (1184 bytes) onto its
    /// existing pin (R1). The identity must be pinned first, and a
    /// different KEM key must not be (`PinConflict` either way: never
    /// replaced, R11); a key that is not a valid ML-KEM-768 key is refused
    /// (`InvalidRecipient`). A peer whose ask waited for it is asked.
    pub fn pin_peer_kem_key(
        &self,
        identity_hex: String,
        kem_pk: Vec<u8>,
    ) -> Result<(), RChatError> {
        let id = identity_hex.to_lowercase();
        let bad = || RChatError::InvalidRecipient {
            identity: identity_hex.clone(),
        };
        peers::key_from_hex(&id).ok_or_else(bad)?;
        kem::validate_public_key(&kem_pk).map_err(|_| bad())?;
        let mut boxed = Box::new([0u8; kem::KEM_PK_LEN]);
        boxed.copy_from_slice(&kem_pk);
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.pin_peer_kem(&id, &boxed)
        })
    }

    /// Our card's bundle signature (64 bytes, R13): our identity's
    /// signature over the v3 bundle transcript `ik ‖ ak ‖ kem_pk`.
    pub fn get_bundle_signature(&self) -> Result<[u8; 64], RChatError> {
        let busy = Err(RChatError::Internal {
            message: "Failed to acquire read lock".to_string(),
        });
        self.query(busy, |i| {
            let id = i.identity.as_ref().ok_or(RChatError::NotConnected)?;
            keyauth::sign_bundle(id)
                .map(|b| b.bundle_signature)
                .map_err(|e| RChatError::Internal {
                    message: e.to_string(),
                })
        })
    }

    /// Our identity's ML-KEM-768 public key (1184 bytes), for our card.
    pub fn get_kem_public_key(&self) -> Result<Vec<u8>, RChatError> {
        let busy = Err(RChatError::Internal {
            message: "Failed to acquire read lock".to_string(),
        });
        self.query(busy, |i| {
            i.identity
                .as_ref()
                .map(|id| id.kem_public().to_vec())
                .ok_or(RChatError::NotConnected)
        })
    }

    /// `peer_key_state`, or None when the client stayed busy (N-8): never
    /// "none" for a peer that may be mismatched or blocked.
    pub fn peer_key_state_checked(&self, identity_hex: String) -> Option<u8> {
        let id = identity_hex.to_lowercase();
        self.query(None, move |i| Some(i.peers.state(&id) as u8))
    }

    /// Read client state for a synchronous query. Uncontended: at once.
    /// Busy: waits up to `QUERY_WAIT` (C-14, N-8: short, as callers are
    /// often the UI thread), then logs and returns `fallback`.
    fn query<T, F>(&self, fallback: T, f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&ClientInner) -> T + Send + 'static,
    {
        if let Ok(guard) = self.inner.try_read() {
            return f(&guard);
        }
        let inner = self.inner.clone();
        let answer = block_on_async(self.runtime.clone(), move || async move {
            match tokio::time::timeout(QUERY_WAIT, inner.read()).await {
                Ok(guard) => Ok(f(&guard)),
                Err(_) => Err(RChatError::Internal {
                    message: "client busy".into(),
                }),
            }
        });
        answer.unwrap_or_else(|e| {
            log::warn!("[RUST] query gave up: {e}");
            fallback
        })
    }

    /// Replace the peer book (pins and blocks staged by the C FFI before
    /// connect). Waits for the lock, so the staged book is never lost.
    pub fn import_peer_book(&self, book: PeerBook) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.peers = book;
            Ok(())
        });
    }

    /// Persist session state through `sink`, sealed under `state_key`
    /// (spec §18.3). Call before `connect`; staged records are opened there.
    /// Records already staged, and the counters written, are kept.
    /// The key is borrowed, so no unwiped copy of it is left on the
    /// caller's side; the client keeps it only in wiped buffers.
    pub fn set_state_store(&self, state_key: &[u8; 32], sink: Arc<dyn state_store::StateSink>) {
        let key = zeroize::Zeroizing::new(*state_key);
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            let mut g = inner.write().await;
            // Staged records and written counters are kept across a re-set,
            // so a later write never goes below a counter already written.
            let (staged, counters) = g
                .state
                .take()
                .map(|s| {
                    let counters = s.counters.into_inner().unwrap_or_else(|e| e.into_inner());
                    (s.staged, counters)
                })
                .unwrap_or_default();
            g.state = Some(persistence::StateStore {
                keys: state_store::StateKeys::new(*key),
                sink,
                counters: std::sync::Mutex::new(counters),
                failing: std::sync::Mutex::new(std::collections::HashSet::new()),
                staged,
            });
            Ok(())
        });
    }

    /// Stop persisting: drop the store (its key wiped) and anything staged.
    /// A client being retired or abandoned calls this so it can never write
    /// through a writer that now serves another account, or a wiped store.
    pub fn detach_state_store(&self) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.state = None;
            Ok(())
        });
    }

    /// Stage records read from the store (after `set_state_store`; ignored
    /// without one). Invalid keys, empty and oversize records are skipped;
    /// for a duplicate key the higher counter wins (D26).
    pub fn import_state_records(&self, records: Vec<(String, Vec<u8>)>) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            let mut g = inner.write().await;
            if let Some(s) = g.state.as_mut() {
                for (k, v) in records {
                    if !state_store::is_valid_record_key(&k)
                        || v.is_empty()
                        || v.len() > state_store::MAX_RECORD_BYTES
                    {
                        continue;
                    }
                    s.stage_keep_higher(k, v);
                }
            }
            Ok(())
        });
    }

    /// Forget every session and staged record in memory (Reset Identity,
    /// our own rotation).
    pub fn clear_state(&self) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.clear_state_now();
            Ok(())
        });
    }

    /// Apply pin and block changes staged while this client was connecting
    /// (`PeerBook::overlay`). A peer the changes unpin or block loses its
    /// circuit and session, as a live unpin or block would. Waits for the
    /// lock, so none are lost.
    pub fn overlay_peer_book(&self, newer: PeerBook) {
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.apply_staged_peers(newer);
            Ok(())
        });
    }

    /// Silence and disconnect a client that is being replaced: its
    /// callbacks are dropped first, so nothing it still receives (or its
    /// timers fire) reaches the app, then the transport and its
    /// auto-reconnect are stopped and pending transport events are retired.
    pub fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Silenced first, without the client lock: queued calls are skipped
        // and a call in flight finishes before this returns (N-7).
        self.callback_hub.silence();
        let inner = self.inner.clone();
        let _ = block_on_async(self.runtime.clone(), move || async move {
            inner.write().await.callbacks = None;
            Ok(())
        });
        if let Err(e) = self.disconnect() {
            log::warn!("[RUST] Retired client disconnect failed: {e}");
        }
    }

    /// `retire` for the same account reconnecting: calls already queued
    /// (messages whose delivery receipt was sent) reach the app first (R1-1).
    pub fn retire_delivering_queued(&self) {
        self.flush_callbacks();
        self.retire();
    }

    /// Wait (bounded) until every callback already queued was delivered,
    /// e.g. the Disconnected status before a logout retires the client.
    pub fn flush_callbacks(&self) {
        self.callback_hub.flush(CALLBACK_WAIT);
    }

    /// Take the peer book back out (a failed C FFI connect returns it to
    /// the staged book). Leaves an empty book behind.
    pub fn export_peer_book(&self) -> PeerBook {
        let inner = self.inner.clone();
        block_on_async(self.runtime.clone(), move || async move {
            Ok(std::mem::take(&mut inner.write().await.peers))
        })
        .unwrap_or_default()
    }

    /// Copy the seed prepared by `prepare_rotation` into `out`, once; the
    /// core's copy is zeroized. False (and `out` untouched) if there is none.
    /// Not exported through UniFFI: the C FFI hands it over in a zeroizable
    /// buffer (round-2 L4).
    pub fn take_rotation_seed(&self, out: &mut [u8; 64]) -> bool {
        let inner = self.inner.clone();
        let seed = block_on_async(self.runtime.clone(), move || async move {
            Ok(inner.write().await.pending_rotation_seed.take())
        });
        match seed {
            Ok(Some(seed)) => {
                out.copy_from_slice(&seed[..]);
                true // `seed` (Zeroizing) is wiped when it drops here
            }
            _ => false,
        }
    }

    /// A first send: the body's 4-byte `expire_secs` placeholder is filled
    /// with the contact's current timer under the lock that checks the
    /// peer (§I.2); `Sent` says which value it carried.
    fn send_payload(
        &self,
        recipient: String,
        content: Vec<u8>,
        msg_type: MessageType,
        message_id: [u8; 16],
    ) -> Result<Sent, RChatError> {
        self.send_payload_checked(recipient, content, msg_type, message_id, false, true)
    }

    /// `send_payload`; with `auto_resend`, the H-1 check
    /// (`check_auto_resend`) runs first and again under the lock that seals,
    /// and nothing is queued for a later session. With `stamp` false the
    /// body keeps the `expire_secs` it was built with: a retry or resend of
    /// an existing message id carries its original timer (ruling R32).
    fn send_payload_checked(
        &self,
        recipient: String,
        content: Vec<u8>,
        msg_type: MessageType,
        message_id: [u8; 16],
        auto_resend: bool,
        stamp: bool,
    ) -> Result<Sent, RChatError> {
        // The plaintext body is wiped wherever this copy ends (R30 M-3);
        // a queued copy is wiped by `PendingMessage`'s drop.
        let mut content = zeroize::Zeroizing::new(content);
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        let recipient = recipient.to_lowercase();
        // A first send of a message carries the contact's current timer
        // (§I.2): its body starts with a 4-byte placeholder, filled in here
        // under the lock. A retry or resend keeps the original value it was
        // given (R32); a timer change is not a message.
        let is_message = msg_type != MessageType::Timer;
        let stamp_timer = stamp && is_message;
        block_on_async(runtime, move || async move {
            let wait_ms = {
                let g = inner.read().await;
                g.check_sendable(&recipient)?;
                if auto_resend {
                    g.check_auto_resend(&recipient, &message_id)?;
                }
                if stamp_timer {
                    let Some(slot) = content.get_mut(..disappearing::EXPIRE_LEN) else {
                        return Err(RChatError::Internal {
                            message: "message body without a timer".into(),
                        });
                    };
                    slot.copy_from_slice(&g.timer_secs(&recipient).to_be_bytes());
                }
                g.send_wait_ms
            };
            // The timer this message carries, as the caller learns it.
            let expire_secs = match content.get(..disappearing::EXPIRE_LEN) {
                Some(e) if is_message => u32::from_be_bytes([e[0], e[1], e[2], e[3]]),
                _ => 0,
            };
            let sent = |id: String| Sent { id, expire_secs };
            let mut waited = 0u64;
            loop {
                {
                    let g = inner.read().await;
                    if !g.is_connected {
                        return Err(RChatError::NotConnected);
                    }
                    g.check_sendable(&recipient)?;
                    if g.has_live_circuit(&recipient)
                        || g.awaiting_init(&recipient)
                        || g.blind_repair_in_flight(&recipient)
                    {
                        break;
                    }
                }
                if waited >= wait_ms {
                    return Err(RChatError::SessionNotEstablished {
                        identity: recipient.clone(),
                    });
                }
                let step = (wait_ms - waited).clamp(1, 100);
                tokio::time::sleep(tokio::time::Duration::from_millis(step)).await;
                waited += step;
            }
            {
                // Responder before the first incoming message: no sending
                // chain yet, so queue on the session (sent by `flush_queued_sends`
                // from the timer once the first incoming message gives it one).
                let g = inner.read().await;
                // A responder waiting for session-init has no session yet
                // (§A.3): the message waits on a placeholder (or the old
                // session) and moves to the new session at install.
                let awaiting = g.awaiting_init(&recipient);
                // R21: re-pairing blind on this connection: parked on the
                // session's queue, moved to the new session at its install.
                let repairing = g.blind_repair_in_flight(&recipient);
                let session = if awaiting {
                    Some(g.session_manager.get_or_create(recipient.clone()))
                } else {
                    g.session_manager.get_mut(&recipient)
                };
                if let Some(mut s) = session {
                    if awaiting || repairing || !s.can_send() {
                        if auto_resend {
                            // Never parked for whatever session is current
                            // when it would be flushed.
                            return Err(RChatError::ResendRefused {
                                identity: recipient.clone(),
                            });
                        }
                        s.pending_messages
                            .push_back(crate::session::PendingMessage {
                                id: MessageId(hex::encode(message_id)),
                                content: std::mem::take(&mut *content),
                                msg_type,
                                timestamp_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as u64,
                            });
                        return Ok(sent(hex::encode(message_id)));
                    }
                    // Steady traffic (§B.1): a message that fits a slot
                    // waits for one; so does anything behind a waiting
                    // one, keeping the order. A larger one with nothing
                    // ahead goes now, outside the shape. Automatic resends
                    // are never parked (H-1).
                    if !auto_resend
                        && g.steady_holds(&recipient)
                        && (steady::fits(1 + content.len()) || !s.pending_messages.is_empty())
                    {
                        s.pending_messages
                            .push_back(crate::session::PendingMessage {
                                id: MessageId(hex::encode(message_id)),
                                content: std::mem::take(&mut *content),
                                msg_type,
                                timestamp_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as u64,
                            });
                        return Ok(sent(hex::encode(message_id)));
                    }
                }
            }
            // The app sees an `Err` from here and shows the send failed.
            Self::send_queued_message(
                inner,
                recipient,
                &content,
                msg_type,
                message_id,
                false,
                auto_resend,
            )
            .await
            .map(sent)
        })
    }

    fn handle_frame(guard: &mut ClientInner, frame: Frame) {
        // A background drain's quiet window starts again (§H.1).
        guard.drain_note_activity(std::time::Instant::now());
        // Round-2 L5: only signaling until the relay gate and publish passed.
        if !matches!(frame, Frame::Signaling(_)) && !guard.frame_gate_open() {
            guard.frames_dropped_before_gate += 1;
            log::debug!("[RUST] frame before the relay gate and publish dropped");
            return;
        }
        log::trace!("[RUST] handle_frame called");

        match frame {
            Frame::Control(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                token,
                target_circuit_id,
                role,
                peer,
                initiator_ephemeral_key,
                responder_ephemeral_key,
                initiator_kem_ephemeral_pk,
                responder_kem_ephemeral_pk,
                initiator_ephemeral_sig,
                responder_ephemeral_sig,
            }) => guard.handle_circuit_created_v3(circuits::CircuitCreatedV3Frame {
                circuit_id,
                token,
                target_circuit_id,
                role,
                peer,
                initiator_ephemeral_key,
                responder_ephemeral_key,
                initiator_kem_ephemeral_pk,
                responder_kem_ephemeral_pk,
                initiator_ephemeral_sig,
                responder_ephemeral_sig,
            }),
            Frame::Control(ControlMessage::MessageAck { message_id, .. }) => {
                // The first ack for a tracked id is reported once (C-5); the
                // tracker outlives transport replacements (spec §18.7 D35).
                let acked = guard
                    .acks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .ack_take(&message_id);
                match acked {
                    Some(t) if t.internal.is_none() => guard.report_delivered(message_id),
                    // A notice or receipt: never the app's; its re-owe
                    // counters go with it.
                    Some(t) => guard.forget_reowes(&t),
                    None => {}
                }
            }
            Frame::Signaling(msg) => guard.handle_signaling(&msg),
            Frame::Control(ControlMessage::QueuedMessage { payload }) => {
                guard.handle_sealed_payload(&payload);
            }
            // R34a: the queue taken at our publish is handed over. Only a
            // background drain acts on it (it may end); otherwise nothing.
            Frame::Control(ControlMessage::QueueHandedOver { .. }) => {
                guard.drain_note_handed_over(std::time::Instant::now());
            }
            Frame::Control(ControlMessage::CircuitClosed { circuit_id, .. }) => {
                guard.handle_circuit_closed(circuit_id)
            }
            Frame::Control(ControlMessage::Error {
                code: protocol::ControlErrorCode::CircuitNotFound,
                message,
            }) => guard.handle_circuit_not_found(&message),
            // Final review: an ask refused over a relay cap. The offline
            // queue's refusal of a relay packet (its text starts with the
            // shared `OFFLINE_QUEUE_FULL_PREFIX`, N-3) is not about an ask.
            Frame::Control(ControlMessage::Error {
                code: protocol::ControlErrorCode::RateLimited,
                message,
            }) if !protocol::is_offline_queue_refusal(&message) => {
                guard.handle_ask_rate_limited(std::time::Instant::now())
            }
            Frame::Control(ControlMessage::PairTokenBusy { ephemeral_key }) => {
                guard.handle_pair_token_busy(&ephemeral_key, std::time::Instant::now())
            }
            Frame::Control(ControlMessage::CircuitExists {
                circuit_id,
                token,
                target_circuit_id,
                ..
            }) => guard.handle_circuit_exists(circuit_id, token, target_circuit_id),
            Frame::Relay(packet) => {
                Self::handle_relay_packet(guard, packet);
            }
            _ => {
                log::trace!("[RUST] handle_frame: unhandled frame type");
            }
        }
    }

    fn handle_binary(guard: &mut ClientInner, data: Vec<u8>) {
        guard.drain_note_activity(std::time::Instant::now());
        // Round-2 L5: relay packets wait for the relay gate and publish too.
        if !guard.frame_gate_open() {
            guard.frames_dropped_before_gate += 1;
            log::debug!("[RUST] relay packet before the relay gate and publish dropped");
            return;
        }
        // Try to decode as relay packet
        if let Some(packet) = RelayPacket::decode(&data) {
            Self::handle_relay_packet(guard, packet);
        }
    }

    fn handle_relay_packet(guard: &mut ClientInner, packet: RelayPacket) {
        if !packet.packet_flags().encrypted {
            return;
        }
        // Authenticate with the token of the session owning this circuit, if
        // any. Routing is by the sender identity inside the envelope (F13).
        // Defence in depth only (Task 12 minor): a relay that rewrites the
        // circuit id to one we don't know skips this check; authenticity
        // rests on the sealed envelope and the ratchet's AEAD.
        let circuit_id = CircuitId(packet.circuit_id.0);
        // A pair waiting for its session-init owns its circuit (§A.3).
        let pending = guard.pending_init_by_circuit(&circuit_id);
        let owner = pending.as_ref().map(|(p, _)| p.clone()).or_else(|| {
            guard
                .session_manager
                .find_by_circuit_id(&circuit_id)
                .or_else(|| guard.session_manager.find_by_target_circuit_id(&circuit_id))
        });
        if let Some(owner) = &owner {
            let token = match &pending {
                Some((_, token)) => Some(*token),
                None => guard
                    .session_manager
                    .get(&owner)
                    .and_then(|s| s.get_token_key()),
            };
            if let Some(token) = token {
                if !packet.verify_auth_tag(&token) {
                    log::debug!("[RUST] Relay auth tag mismatch; packet dropped");
                    return;
                }
            }
        }
        match owner {
            Some(owner) => {
                // Reached only with the pending circuit's token verified.
                let on_pending = pending.is_some();
                guard.handle_sealed_payload_on_circuit(&packet.payload, &owner, on_pending)
            }
            None => guard.handle_sealed_payload(&packet.payload),
        }
    }

    /// Send the messages the responder queued on a session before it had
    /// a sending chain (before the first incoming message, normally the
    /// initiator's hello sync). Run by the core's timer on every tick and
    /// by `process_pending`; each message is taken off the session once, so
    /// the two never send it twice.
    pub(crate) async fn flush_queued_sends(inner: &Arc<RwLock<ClientInner>>) {
        let ready: Vec<(String, VecDeque<crate::session::PendingMessage>)> = {
            let guard = inner.read().await;
            if !guard.is_connected {
                return;
            }
            // Timer changes reported lost go back on their sessions (R32).
            guard.process_timer_requeues();
            guard
                .session_manager
                .get_all_recipients()
                .into_iter()
                .filter_map(|r| {
                    // Not sendable (mismatch, bad signature, blocked, not
                    // accepted): the messages stay queued.
                    if guard.check_sendable(&r).is_err() || !guard.has_live_circuit(&r) {
                        return None;
                    }
                    let mut s = guard.session_manager.get_mut(&r)?;
                    if !s.can_send() || s.pending_messages.is_empty() {
                        return None;
                    }
                    if guard.steady_holds(&r) {
                        // Steady (§B.1): what fits waits for a slot; only
                        // the larger messages at the head go now, outside
                        // the shape, so the order is kept.
                        let mut large = VecDeque::new();
                        while s
                            .pending_messages
                            .front()
                            .is_some_and(|m| !steady::fits(1 + m.content.len()))
                        {
                            large.extend(s.pending_messages.pop_front());
                        }
                        return (!large.is_empty()).then(|| (r.clone(), large));
                    }
                    let pending = s.take_pending_messages();
                    Some((r.clone(), pending))
                })
                .collect()
        };
        for (recipient, mut pending) in ready {
            while let Some(msg) = pending.pop_front() {
                let Some(id) = circuits::message_id_from_hex(&msg.id.0) else {
                    continue;
                };
                match Self::send_queued_message(
                    inner.clone(),
                    recipient.clone(),
                    &msg.content,
                    msg.msg_type,
                    id,
                    // Nobody sees this `Err`: a sealed message the transport
                    // refused is tracked, so the next resume re-sends it.
                    true,
                    false,
                )
                .await
                {
                    Ok(_) => {}
                    Err(RChatError::StatePersistFailed) => {
                        // Not sent (D28): this and the rest go back to the
                        // front of the queue, in order, for the next tick.
                        pending.push_front(msg);
                        let guard = inner.read().await;
                        match guard.session_manager.get_mut(&recipient) {
                            Some(mut s) => {
                                while let Some(m) = pending.pop_back() {
                                    s.pending_messages.push_front(m);
                                }
                            }
                            // The session went meanwhile (forgotten): the
                            // batch cannot be re-queued; reported as lost.
                            None => guard.report_queued_sends_lost(&recipient, &pending),
                        }
                        break;
                    }
                    Err(_) => log::warn!("[RUST] a queued message could not be sent"),
                }
            }
        }
    }

    /// Encrypt, seal and send one message on the peer's circuit.
    /// `track_on_err`: a sealed message the transport refused is tracked
    /// anyway, so the identical bytes go out on the next resume (the queued
    /// path, where no caller sees the error). Without it only a good send
    /// is tracked (the direct path: the app shows the error, and that must
    /// stay final, with no later `on_message_delivered`).
    async fn send_queued_message(
        inner: Arc<tokio::sync::RwLock<ClientInner>>,
        recipient: String,
        content: &[u8],
        msg_type: MessageType,
        message_id: [u8; 16],
        track_on_err: bool,
        auto_resend: bool,
    ) -> Result<String, RChatError> {
        let guard = inner.read().await;
        // Re-checked under the lock that seals: the peer's state may have
        // changed since the caller looked.
        guard.check_sendable(&recipient)?;
        if auto_resend {
            // H-1, under the same guard as the seal: no session can be
            // installed in between.
            guard.check_auto_resend(&recipient, &message_id)?;
        }
        // Final review L5: a background drain sends no message (§H.1). Its
        // frame goes straight to the outgoing channel, past `send_now`'s
        // gate, so it is refused here, before a message number is burnt.
        if guard.in_drain() {
            return Err(RChatError::NotConnected);
        }
        // Wiped when it goes (R30 M-3); the tracker keeps its own copy.
        let plaintext = zeroize::Zeroizing::new(steady::message_plaintext(msg_type, content));
        // Checked before sealing so a missing socket does not burn a message number.
        let tx = guard
            .websocket
            .as_ref()
            .ok_or(RChatError::NotConnected)?
            .outgoing_sender();
        let packet = guard.seal_ratchet(&recipient, message_id, &plaintext)?;
        let id_hex = hex::encode(message_id);
        // Tracked before the send, under this read guard: an ack is handled
        // under the write lock, so it can only come after. The wait for
        // queue space (up to OUTGOING_SEND_TIMEOUT on a slow network) runs
        // without the client lock, so no other call waits behind it.
        let (circuit, payload) = (packet.circuit_id.clone(), packet.payload.clone());
        guard.track_sent(&recipient, &id_hex, circuit, payload, &plaintext);
        drop(guard);
        let frame = packet.encode_with_frame_type();
        let sent = match tx {
            None => Err(RChatError::ConnectionFailed {
                message: "Outgoing channel not initialized".to_string(),
            }),
            Some(tx) => {
                match tokio::time::timeout(transport::OUTGOING_SEND_TIMEOUT, tx.send(frame)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(RChatError::ConnectionFailed {
                        message: "Failed to queue message".to_string(),
                    }),
                    Err(_) => Err(RChatError::ConnectionFailed {
                        message: "Outgoing queue full".to_string(),
                    }),
                }
            }
        };
        if sent.is_err() && !track_on_err {
            // The caller reports the failure: not tracked for a re-send
            // (a resume in the meantime may already have re-sent it; the
            // recipient drops a second copy of an id it decrypted).
            inner.read().await.untrack_sent(&id_hex);
        }
        sent.map(|()| id_hex)
    }
}

/// A queued call to the app's callbacks.
type CallbackJob = Box<dyn FnOnce(&dyn RChatCallbacks) + Send>;

/// Most callback calls queued before the transport event task stops taking
/// events (N-2): calls are never dropped, the backlog pushes back on the
/// socket instead (C-9), and posting never blocks under the client lock.
pub(crate) const CALLBACK_BACKLOG_CAP: usize = 1024;

/// How long `retire` and `rchat_disconnect` wait for a callback in flight
/// or for queued calls to be delivered.
const CALLBACK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The app's current callbacks and whether one of them is running.
#[derive(Default)]
struct HubTarget {
    callbacks: Option<Arc<dyn RChatCallbacks>>,
    running: bool,
}

/// Runs the app's callbacks on one dedicated thread, in order (C-11): the
/// core only queues the call, so no callback ever runs with client state
/// locked and a callback may call back into the client. Replacing the
/// callbacks keeps the queue: calls already queued go to the new callbacks
/// (N-7). `silence` (retire) drops queued calls and waits for one in flight.
pub(crate) struct CallbackHub {
    target: std::sync::Mutex<HubTarget>,
    jobs: std::sync::Mutex<Option<std::sync::mpsc::Sender<CallbackJob>>>,
    /// Calls posted and not yet delivered or skipped.
    pending: std::sync::atomic::AtomicUsize,
    worker: std::sync::Mutex<Option<std::thread::ThreadId>>,
}

impl CallbackHub {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            target: std::sync::Mutex::new(HubTarget::default()),
            jobs: std::sync::Mutex::new(None),
            pending: std::sync::atomic::AtomicUsize::new(0),
            worker: std::sync::Mutex::new(None),
        })
    }

    fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Point the hub at new callbacks, starting the thread on first use.
    fn set_target(self: &Arc<Self>, callbacks: Arc<dyn RChatCallbacks>) {
        Self::lock(&self.target).callbacks = Some(callbacks);
        let mut jobs = Self::lock(&self.jobs);
        if jobs.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel::<CallbackJob>();
        let weak = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("rchat-callbacks".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    let Some(hub) = weak.upgrade() else { break };
                    let target = {
                        let mut t = Self::lock(&hub.target);
                        t.running = t.callbacks.is_some();
                        t.callbacks.clone()
                    };
                    if let Some(cb) = target {
                        job(cb.as_ref());
                        Self::lock(&hub.target).running = false;
                    }
                    hub.pending
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
        match spawned {
            Ok(handle) => {
                *Self::lock(&self.worker) = Some(handle.thread().id());
                *jobs = Some(tx);
            }
            Err(e) => log::warn!("[RUST] callback thread not started: {e}"),
        }
    }

    fn post(&self, job: impl FnOnce(&dyn RChatCallbacks) + Send + 'static) {
        let jobs = Self::lock(&self.jobs);
        let Some(tx) = jobs.as_ref() else { return };
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if tx.send(Box::new(job)).is_err() {
            self.pending
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            log::warn!("[RUST] callback dropped: callback thread gone");
        }
    }

    pub(crate) fn backlog(&self) -> usize {
        self.pending.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn on_worker_thread(&self) -> bool {
        *Self::lock(&self.worker) == Some(std::thread::current().id())
    }

    /// Wait (bounded) until every queued call has been delivered.
    fn flush(&self, timeout: std::time::Duration) {
        if self.on_worker_thread() {
            return;
        }
        let deadline = std::time::Instant::now() + timeout;
        while self.backlog() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// No further calls reach the app: queued calls are skipped and a call
    /// in flight is waited for (bounded; not when called from a callback).
    fn silence(&self) {
        Self::lock(&self.target).callbacks = None;
        if self.on_worker_thread() {
            return;
        }
        let deadline = std::time::Instant::now() + CALLBACK_WAIT;
        while Self::lock(&self.target).running && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

/// Wait, without holding any lock, until the callback backlog is below
/// `CALLBACK_BACKLOG_CAP` (N-2).
pub(crate) async fn wait_for_callback_room(hub: &CallbackHub) {
    while hub.backlog() >= CALLBACK_BACKLOG_CAP {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// A received file queued on the hub: if its job is dropped undelivered
/// (no callback thread, or the callbacks were silenced), the bytes are
/// wiped, never just freed. Kept off `ReceivedFile` itself, a
/// `uniffi::Record` whose fields must stay movable.
struct QueuedFile(Option<ReceivedFile>);

impl Drop for QueuedFile {
    fn drop(&mut self) {
        if let Some(f) = self.0.as_mut() {
            zeroize::Zeroize::zeroize(&mut f.bytes);
        }
    }
}

/// What `ClientInner::callbacks` holds once the app registered callbacks:
/// every call is queued on the hub.
struct HubCallbacks(Arc<CallbackHub>);

impl RChatCallbacks for HubCallbacks {
    fn on_connection_status_changed(&self, status: ConnectionStatus) {
        self.0
            .post(move |cb| cb.on_connection_status_changed(status));
    }
    fn on_message_received(&self, message: ReceivedMessage) {
        self.0.post(move |cb| cb.on_message_received(message));
    }
    fn on_file_received(&self, file: ReceivedFile) {
        let mut queued = QueuedFile(Some(file));
        self.0.post(move |cb| {
            if let Some(f) = queued.0.take() {
                cb.on_file_received(f);
            }
        });
    }
    fn on_message_delivered(&self, message_id: String) {
        self.0.post(move |cb| cb.on_message_delivered(message_id));
    }
    fn on_timer_changed(&self, peer_hex: String, secs: u32, changed_at_ms: u64, by_me: bool) {
        self.0
            .post(move |cb| cb.on_timer_changed(peer_hex, secs, changed_at_ms, by_me));
    }
    fn on_error(&self, error: String) {
        self.0.post(move |cb| cb.on_error(error));
    }
    fn on_circuit_established(&self, recipient_identity: String, is_initiator: bool) {
        self.0
            .post(move |cb| cb.on_circuit_established(recipient_identity, is_initiator));
    }
    fn on_peer_key_event(&self, identity_hex: String, code: u8, agreement_hex: String) {
        self.0
            .post(move |cb| cb.on_peer_key_event(identity_hex, code, agreement_hex));
    }
    fn on_message_request(&self, request: MessageRequest) {
        self.0.post(move |cb| cb.on_message_request(request));
    }
    fn on_message_receipt(&self, sender_hex: String, message_id_hex: String, kind: u8) {
        self.0
            .post(move |cb| cb.on_message_receipt(sender_hex, message_id_hex, kind));
    }
    fn on_peer_rotated(&self, old: String, new: String, ak: String, kem: String, version: u32) {
        self.0
            .post(move |cb| cb.on_peer_rotated(old, new, ak, kem, version));
    }
    fn on_status_event(&self, event: status::StatusEvent) {
        self.0.post(move |cb| cb.on_status_event(event));
    }
    fn on_reconnect(&self) {
        self.0.post(|cb| cb.on_reconnect());
    }
    fn on_log(&self, message: String) {
        self.0.post(move |cb| cb.on_log(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";

    /// R31 round 2: `block_on_async` must build the future on its worker
    /// thread. The caller's stack is painted with a needle; a future built
    /// here (big, and live across awaits, so most of it is uninitialised
    /// slots) would copy that paint into `thread::spawn`'s heap box, freed
    /// unwiped. Independent of any send's stack layout, debug and release.
    #[test]
    fn block_on_async_moves_no_caller_stack_into_the_heap() {
        #[inline(never)]
        fn paint(n: [u8; 32]) {
            let a = [n; 1024];
            std::hint::black_box(&a);
        }
        let rt = Arc::new(ClientRuntime::new().unwrap());
        for _ in 0..8 {
            let n: [u8; 32] = rand::random();
            let hits = crate::alloc_probe::freed_containing_any_thread(n, || {
                paint(n);
                let r = block_on_async(rt.clone(), move || async move {
                    tokio::task::yield_now().await;
                    let big = [7u8; 4096];
                    tokio::task::yield_now().await;
                    Ok(std::hint::black_box(big)[0])
                });
                assert_eq!(r.unwrap(), 7);
            });
            assert_eq!(hits, 0, "caller stack reached the heap box");
        }
    }

    /// R31 round 2, a compile-time guard: the future holds an `Rc` (not
    /// `Send`) across an await. That compiles only because the future is
    /// built and polled on the worker thread and never crosses threads;
    /// a `block_on_async` that built it here and moved it into
    /// `thread::spawn` would need `F: Send`, and this test would stop
    /// compiling.
    #[test]
    fn block_on_async_futures_need_not_be_send() {
        let rt = Arc::new(ClientRuntime::new().unwrap());
        let r = block_on_async(rt, || async {
            let rc = std::rc::Rc::new(5u8);
            tokio::task::yield_now().await;
            Ok(*rc)
        });
        assert_eq!(r.unwrap(), 5);
    }

    /// A callback whose `on_error` waits on a gate, recording what it saw.
    struct Gated {
        name: &'static str,
        gate: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RChatCallbacks for Gated {
        fn on_connection_status_changed(&self, _: ConnectionStatus) {}
        fn on_message_received(&self, _: ReceivedMessage) {}
        fn on_message_delivered(&self, _: String) {}
        fn on_circuit_established(&self, _: String, _: bool) {}
        fn on_error(&self, e: String) {
            let _ = self.gate.lock().unwrap().recv();
            self.seen.lock().unwrap().push(format!("{} {e}", self.name));
        }
    }

    fn gated(
        name: &'static str,
        seen: &Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (Box<Gated>, std::sync::mpsc::Sender<()>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let cb = Gated {
            name,
            gate: std::sync::Mutex::new(rx),
            seen: seen.clone(),
        };
        (Box::new(cb), tx)
    }

    fn post_errors(client: &RChatClient, n: usize) {
        let mut guard = client.inner.try_write().unwrap();
        for i in 0..n {
            guard.report_error(&RChatError::Internal {
                message: format!("e{i}"),
            });
        }
    }

    fn wait_for<F: Fn() -> bool>(f: F) {
        for _ in 0..500 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// N-7: replacing the callbacks keeps calls already queued; they go to
    /// the new callbacks instead of being dropped.
    #[test]
    fn replacing_callbacks_keeps_queued_calls() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, open_a) = gated("a", &seen);
        client.set_callbacks(a);
        post_errors(&client, 3);
        wait_for(|| client.callback_hub.target.lock().unwrap().running);
        let (b, open_b) = gated("b", &seen);
        client.set_callbacks(b);
        for _ in 0..3 {
            let _ = open_a.send(());
            let _ = open_b.send(());
        }
        wait_for(|| client.callback_hub.backlog() == 0);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen[0].starts_with("a "), "in flight on the old callbacks");
        assert!(seen[1..].iter().all(|s| s.starts_with("b ")), "{seen:?}");
    }

    /// N-7: `retire` returns only after a callback in flight finished, and
    /// queued calls are skipped.
    #[test]
    fn retire_waits_for_the_callback_in_flight() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, open) = gated("a", &seen);
        client.set_callbacks(a);
        post_errors(&client, 3);
        wait_for(|| client.callback_hub.target.lock().unwrap().running);
        let opener = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            for _ in 0..3 {
                let _ = open.send(());
            }
        });
        client.retire();
        assert_eq!(seen.lock().unwrap().len(), 1, "the call in flight finished");
        opener.join().unwrap();
        wait_for(|| client.callback_hub.backlog() == 0);
        assert_eq!(seen.lock().unwrap().len(), 1, "queued calls skipped");
    }

    /// R1-1: a reconnect retires the old client without losing calls it
    /// already queued.
    #[test]
    fn retire_delivering_queued_keeps_queued_calls() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, open) = gated("a", &seen);
        client.set_callbacks(a);
        post_errors(&client, 3);
        wait_for(|| client.callback_hub.target.lock().unwrap().running);
        let opener = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            for _ in 0..3 {
                let _ = open.send(());
            }
        });
        client.retire_delivering_queued();
        opener.join().unwrap();
        assert_eq!(seen.lock().unwrap().len(), 3, "queued calls delivered");
    }

    /// N-2: posting never blocks, but the event task waits while the app
    /// lags `CALLBACK_BACKLOG_CAP` calls behind, then resumes.
    #[test]
    fn a_slow_app_holds_back_the_event_task() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, open) = gated("a", &seen);
        client.set_callbacks(a);
        post_errors(&client, CALLBACK_BACKLOG_CAP + 10);
        assert!(client.callback_hub.backlog() >= CALLBACK_BACKLOG_CAP);
        let hub = client.callback_hub.clone();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let held = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), wait_for_callback_room(&hub)).await
        });
        assert!(held.is_err(), "the event task must wait");
        for _ in 0..CALLBACK_BACKLOG_CAP + 10 {
            let _ = open.send(());
        }
        let resumed = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), wait_for_callback_room(&hub)).await
        });
        assert!(resumed.is_ok());
        wait_for(|| client.callback_hub.backlog() == 0);
        assert_eq!(
            seen.lock().unwrap().len(),
            CALLBACK_BACKLOG_CAP + 10,
            "none lost"
        );
    }

    /// N-8: a busy client answers "busy" after a short wait, never "none"
    /// for a peer that is in fact mismatched.
    #[test]
    fn peer_state_is_busy_not_none_and_does_not_block_long() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client
            .inner
            .try_write()
            .unwrap()
            .peers
            .pin(PEER, [1; 32])
            .unwrap();
        client.inner.try_write().unwrap().peers.mark_mismatch(PEER);
        assert_eq!(client.peer_key_state_checked(PEER.into()), Some(2));
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let holder = client.clone();
        let busy = std::thread::spawn(move || {
            let inner = holder.inner.clone();
            holder.runtime.block_on(async move {
                let guard = inner.write().await;
                locked_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_millis(1500)).await;
                drop(guard);
            });
        });
        locked_rx.recv().unwrap();
        let started = std::time::Instant::now();
        assert_eq!(client.peer_key_state_checked(PEER.into()), None);
        assert!(started.elapsed() < Duration::from_millis(1000));
        busy.join().unwrap();
        assert_eq!(client.peer_key_state_checked(PEER.into()), Some(2));
    }

    /// N-3: loading a hex seed frees no buffer holding the seed in hex.
    #[test]
    fn seed_loading_frees_no_hex_copy() {
        let seed = "ab".repeat(64);
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            assert!(identity_from_seed_hex(&seed).is_ok());
        });
        assert_eq!(hits, 0);
    }

    /// C-10: the seed never shows in Debug output, is gone from the
    /// client's config copy, and errors never echo its characters.
    #[test]
    fn the_seed_is_redacted_and_not_kept_in_config() {
        let seed = "ab".repeat(64);
        let cfg = ClientConfig {
            identity_key_seed: Some(seed.clone()),
            ..ClientConfig::default()
        };
        assert!(!format!("{cfg:?}").contains(&seed));
        assert!(format!("{cfg:?}").contains("redacted"));
        let inner = ClientInner::new(cfg);
        assert!(inner.config.identity_key_seed.is_none());
        assert!(inner.identity_seed.is_some());
        let bad = format!("{}q", "ab".repeat(63));
        let err = identity_from_seed_hex(&bad).err().unwrap().to_string();
        assert!(!err.contains("'q'"), "{err}");
        assert!(!err.contains("position"), "{err}");
        assert!(identity_from_seed_hex(&seed).is_ok());
        assert!(identity_from_seed_hex(&"cd".repeat(32)).is_ok());
    }

    /// Task 24 / C-23: the last reference to a client may go on a runtime
    /// thread without panicking (which aborts the app).
    #[tokio::test]
    async fn dropping_a_client_on_a_runtime_thread_does_not_panic() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        drop(client);
    }

    /// C-23: a connected client dropped without `disconnect` frees its state
    /// (identity included): no reference cycle through the transport.
    #[test]
    fn a_connected_client_dropped_without_disconnect_is_freed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut ws = tokio_tungstenite::tungstenite::accept(tcp).unwrap();
            while ws.read().is_ok() {}
        });
        let client = RChatClient::new(ClientConfig {
            server_url: format!("ws://{addr}/"),
            reconnect_max_attempts: 1,
            ..ClientConfig::default()
        })
        .unwrap();
        client.connect().unwrap();
        let weak = Arc::downgrade(&client.inner);
        // Dropped on a runtime thread, like a callback-held last reference.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { drop(client) });
        for _ in 0..200 {
            if weak.upgrade().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(weak.upgrade().is_none(), "client state leaked");
        drop(rt);
        let _ = relay.join();
    }

    /// Calls the client back from `on_error` and reports the result.
    struct Reentrant {
        client: std::sync::OnceLock<Arc<RChatClient>>,
        done: std::sync::Mutex<std::sync::mpsc::Sender<Result<(), RChatError>>>,
    }

    impl RChatCallbacks for Reentrant {
        fn on_connection_status_changed(&self, _: ConnectionStatus) {}
        fn on_message_received(&self, _: ReceivedMessage) {}
        fn on_message_delivered(&self, _: String) {}
        fn on_circuit_established(&self, _: String, _: bool) {}
        fn on_error(&self, _: String) {
            let client = self.client.get().unwrap();
            let r = client.pin_peer_key(PEER.into(), PEER_AK.into(), None);
            let _ = self.done.lock().unwrap().send(r);
        }
    }

    /// C-11: a callback may call a blocking client method: callbacks never
    /// run with client state locked.
    #[test]
    fn a_callback_can_call_back_into_the_client() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let cb = Arc::new(Reentrant {
            client: std::sync::OnceLock::new(),
            done: std::sync::Mutex::new(tx),
        });
        let _ = cb.client.set(client.clone());
        struct Shared(Arc<Reentrant>);
        impl RChatCallbacks for Shared {
            fn on_connection_status_changed(&self, _: ConnectionStatus) {}
            fn on_message_received(&self, _: ReceivedMessage) {}
            fn on_message_delivered(&self, _: String) {}
            fn on_circuit_established(&self, _: String, _: bool) {}
            fn on_error(&self, e: String) {
                self.0.on_error(e)
            }
        }
        client.set_callbacks(Box::new(Shared(cb.clone())));
        let raiser = client.clone();
        std::thread::spawn(move || {
            let inner = raiser.inner.clone();
            raiser.runtime.block_on(async move {
                inner.write().await.report_error(&RChatError::NotConnected);
            });
        });
        let r = rx.recv_timeout(Duration::from_secs(5));
        assert!(matches!(r, Ok(Ok(()))), "re-entrant call: {r:?}");
        assert_eq!(client.peer_key_state(PEER.into()), 1);
        client.inner.try_write().unwrap().callbacks = None;
    }

    /// C-14: callbacks set while the client is busy are installed once the
    /// lock frees, not silently dropped.
    #[test]
    fn set_callbacks_waits_for_a_busy_client() {
        struct Quiet;
        impl RChatCallbacks for Quiet {
            fn on_connection_status_changed(&self, _: ConnectionStatus) {}
            fn on_message_received(&self, _: ReceivedMessage) {}
            fn on_message_delivered(&self, _: String) {}
            fn on_error(&self, _: String) {}
            fn on_circuit_established(&self, _: String, _: bool) {}
        }
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let holder = client.clone();
        let busy = std::thread::spawn(move || {
            let inner = holder.inner.clone();
            holder.runtime.block_on(async move {
                let guard = inner.write().await;
                locked_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(guard);
            });
        });
        locked_rx.recv().unwrap();
        client.set_callbacks(Box::new(Quiet));
        busy.join().unwrap();
        assert!(client.inner.try_read().unwrap().callbacks.is_some());
        assert_eq!(client.peer_key_state(PEER.into()), 0);
    }

    /// Task 8 carry-over: `QueuedSendLost` / `StateRestoreFailed` are raised
    /// inside `connect()` with the write lock held. Raising only queues the
    /// event; the callback runs on the callback thread once the lock is
    /// released, so a callback that reads the client (as one must never do
    /// synchronously, but might) waits for the lock instead of deadlocking.
    #[test]
    fn status_events_raised_under_the_write_lock_never_block_on_the_callback() {
        struct ReEnter {
            client: std::sync::Mutex<Option<std::sync::Weak<RChatClient>>>,
            done: std::sync::Mutex<std::sync::mpsc::Sender<u8>>,
        }
        impl RChatCallbacks for ReEnter {
            fn on_connection_status_changed(&self, _: ConnectionStatus) {}
            fn on_message_received(&self, _: ReceivedMessage) {}
            fn on_message_delivered(&self, _: String) {}
            fn on_error(&self, _: String) {}
            fn on_circuit_established(&self, _: String, _: bool) {}
            fn on_status_event(&self, _: status::StatusEvent) {
                let client = self
                    .client
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|w| w.upgrade());
                let state = client.map_or(255, |c| c.peer_key_state(PEER.into()));
                let _ = self.done.lock().unwrap().send(state);
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let cb = ReEnter {
            client: std::sync::Mutex::new(None),
            done: std::sync::Mutex::new(tx),
        };
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        *cb.client.lock().unwrap() = Some(Arc::downgrade(&client));
        client.set_callbacks(Box::new(cb));
        let inner = client.inner.clone();
        let raised = client.runtime.block_on(async move {
            let guard = inner.write().await;
            let start = std::time::Instant::now();
            guard.emit_status(status::StatusEvent::StateRestoreFailed { reason: 2 });
            let raised = start.elapsed();
            // Held a while: the callback must be waiting on the lock, not
            // holding up the raise.
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(guard);
            raised
        });
        assert!(raised < Duration::from_millis(100), "raise only queues");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            0,
            "the callback ran after the lock was released"
        );
    }

    /// Task 13: the hub (what the app's registered callbacks sit behind)
    /// forwards a received file to `on_file_received`, never as a message.
    #[test]
    fn the_hub_forwards_files() {
        #[derive(Default)]
        struct Files(std::sync::Mutex<Vec<String>>);
        impl RChatCallbacks for Files {
            fn on_connection_status_changed(&self, _: ConnectionStatus) {}
            fn on_message_received(&self, _: ReceivedMessage) {
                self.0.lock().unwrap().push("message".into());
            }
            fn on_file_received(&self, f: ReceivedFile) {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("file {} {}", f.name, f.bytes.len()));
            }
            fn on_message_delivered(&self, _: String) {}
            fn on_error(&self, _: String) {}
            fn on_circuit_established(&self, _: String, _: bool) {}
        }
        let hub = CallbackHub::new();
        let files = Arc::new(Files::default());
        hub.set_target(files.clone());
        HubCallbacks(hub.clone()).on_file_received(ReceivedFile {
            id: "ab".repeat(16),
            sender_identity: PEER.into(),
            name: "x.bin".into(),
            mime: String::new(),
            expire_secs: 0,
            bytes: vec![1, 2, 3],
            timestamp_ms: 1,
        });
        hub.flush(Duration::from_secs(2));
        assert_eq!(*files.0.lock().unwrap(), vec!["file x.bin 3".to_string()]);
    }

    /// Fix round 2 N-1: a file whose hub job is dropped undelivered is
    /// wiped: with no callback thread (dropped in `post`), and after the
    /// callbacks were silenced (dropped on the callback thread).
    #[test]
    fn dropped_hub_jobs_wipe_files() {
        struct Quiet;
        impl RChatCallbacks for Quiet {
            fn on_connection_status_changed(&self, _: ConnectionStatus) {}
            fn on_message_received(&self, _: ReceivedMessage) {}
            fn on_message_delivered(&self, _: String) {}
            fn on_error(&self, _: String) {}
            fn on_circuit_established(&self, _: String, _: bool) {}
        }
        fn file(needle: [u8; 32]) -> ReceivedFile {
            ReceivedFile {
                id: "ab".repeat(16),
                sender_identity: PEER.into(),
                name: "x".into(),
                mime: String::new(),
                expire_secs: 0,
                bytes: needle.to_vec(),
                timestamp_ms: 1,
            }
        }
        // No target ever set: no callback thread, the job is dropped.
        let needle: [u8; 32] = rand::random();
        let idle = CallbackHub::new();
        let hits = crate::alloc_probe::freed_containing(needle, || {
            HubCallbacks(idle.clone()).on_file_received(file(needle));
        });
        assert_eq!(hits, 0, "dropped in post");
        // Silenced: the job reaches the thread and is dropped there.
        let needle: [u8; 32] = rand::random();
        let hub = CallbackHub::new();
        hub.set_target(Arc::new(Quiet));
        hub.silence();
        let hits = crate::alloc_probe::freed_containing_any_thread(needle, || {
            HubCallbacks(hub.clone()).on_file_received(file(needle));
            hub.flush(Duration::from_secs(2));
        });
        assert_eq!(hits, 0, "dropped on the callback thread");
    }

    #[test]
    fn send_binary_using_id_checks_the_body_and_the_id() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let id = "ab".repeat(16);
        assert!(matches!(
            client.send_binary_message_using_id(PEER.into(), b"nope".to_vec(), id.clone()),
            Err(RChatError::Internal { .. })
        ));
        assert!(matches!(
            client.send_binary_message_using_id(PEER.into(), b"IMG1x".to_vec(), "zz".into()),
            Err(RChatError::Internal { .. })
        ));
        // Pinned, so `check_sendable` passes: the refusal comes from
        // `send_payload`'s connection check, proving the call got there.
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        assert!(matches!(
            client.send_binary_message_using_id(PEER.into(), b"IMG1x".to_vec(), id),
            Err(RChatError::NotConnected)
        ));
    }

    /// D43/D44: the binding needs the identity; a DK is pinned only with a
    /// binding that verifies under the identity, and only for a pinned one;
    /// a re-scan replaces it.
    #[test]
    fn device_key_binding_and_pinning_check_the_binding() {
        use crate::device_key::test_keys::soft_dk;
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let (_, dk) = soft_dk(4);
        assert!(matches!(
            client.device_key_binding(dk.dk_pub, false),
            Err(RChatError::NotConnected)
        ));
        let me = IdentityKeyPair::from_seed(&[0x21; 64]).unwrap();
        let my_ik = me.public_signing_key().to_bytes();
        client.inner.try_write().unwrap().identity = Some(me);
        let dks = client.device_key_binding(dk.dk_pub, false).unwrap();
        assert!(keyauth::verify_device_key(&my_ik, &dk.dk_pub, false, &dks).is_ok());
        assert!(client.device_key_binding([0; 65], false).is_err());

        let them = IdentityKeyPair::from_seed(&[0x22; 64]).unwrap();
        let their_hex = hex::encode(them.public_signing_key().to_bytes());
        let their_dks = keyauth::sign_device_key(&them, &dk.dk_pub, false).unwrap();
        assert!(matches!(
            client.pin_device_key(their_hex.clone(), dk.dk_pub, false, their_dks),
            Err(RChatError::PinConflict)
        ));
        client
            .pin_peer_key(
                their_hex.clone(),
                hex::encode(them.public_agreement_key().to_bytes()),
                None,
            )
            .unwrap();
        let mut bad = their_dks;
        bad[0] ^= 1;
        for (hw, sig) in [(false, bad), (true, their_dks), (false, dks)] {
            assert!(matches!(
                client.pin_device_key(their_hex.clone(), dk.dk_pub, hw, sig),
                Err(RChatError::Internal { .. })
            ));
        }
        let dk_of = |c: &RChatClient| {
            c.inner
                .try_read()
                .unwrap()
                .peers
                .device_key(&their_hex)
                .cloned()
        };
        assert_eq!(dk_of(&client), None, "nothing pinned by a refused card");
        client
            .pin_device_key(their_hex.to_uppercase(), dk.dk_pub, false, their_dks)
            .unwrap();
        assert_eq!(dk_of(&client), Some(dk));
        let (_, rescanned) = soft_dk(6);
        let dks6 = keyauth::sign_device_key(&them, &rescanned.dk_pub, true).unwrap();
        client
            .pin_device_key(their_hex.clone(), rescanned.dk_pub, true, dks6)
            .unwrap();
        let hw = device_key::DevicePin {
            hardware: true,
            ..rescanned
        };
        assert_eq!(dk_of(&client), Some(hw), "a re-scan replaces it");
    }

    #[test]
    fn test_client_creation() {
        let config = ClientConfig::default();
        let client = RChatClient::new(config).unwrap();
        assert!(matches!(
            client.get_connection_status(),
            ConnectionStatus::Disconnected
        ));
    }

    /// The app calls `set_cover_traffic` from the UI thread (scene phase
    /// changes). A connect holds the client lock across network I/O, so the
    /// call must never wait for that lock; the setting lands once it is free.
    #[test]
    fn set_cover_traffic_never_waits_for_a_busy_client() {
        let client = Arc::new(RChatClient::new(ClientConfig::default()).unwrap());
        let lock = client.inner.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = lock.blocking_write(); // e.g. a connect in progress
            held_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        held_rx.recv().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let caller = client.clone();
        std::thread::spawn(move || {
            caller.set_cover_traffic(true, true);
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_millis(500)).is_ok();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(returned, "set_cover_traffic waited for the client lock");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let applied = client
                .inner
                .try_read()
                .map(|i| i.cover_enabled && i.cover_foreground)
                .unwrap_or(false);
            if applied {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "never applied");
            std::thread::sleep(Duration::from_millis(10));
        }
        // The last call wins, whatever order the deferred ones run in.
        let lock = client.inner.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = lock.blocking_write();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        held_rx.recv().unwrap();
        for (on, fg) in [(false, true), (true, false), (true, true), (false, false)] {
            client.set_cover_traffic(on, fg);
        }
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let i = client.inner.try_read().unwrap();
        assert_eq!((i.cover_enabled, i.cover_foreground), (false, false));
    }

    /// The UI calls into the client from the main thread (pins, mark seen,
    /// cover). A connect waiting on the network must not hold the client
    /// lock, or those calls wait for the whole handshake.
    #[test]
    fn client_calls_return_promptly_while_a_connect_waits_on_the_network() {
        // A server that accepts and never answers the WebSocket upgrade.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8080);
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in listener.incoming().take(4).flatten() {
                held.push(s);
            }
            std::thread::sleep(Duration::from_secs(10));
        });
        let config = ClientConfig {
            server_url: format!("ws://127.0.0.1:{port}/"),
            connection_timeout_secs: 4,
            reconnect_max_attempts: 1,
            ..ClientConfig::default()
        };
        let client = RChatClient::new(config).unwrap();
        let c = client.clone();
        let connecting = std::thread::spawn(move || c.connect());
        std::thread::sleep(Duration::from_millis(400)); // now in the handshake
        let t = std::time::Instant::now();
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        client.set_cover_traffic(true, true);
        let _ = client.peer_key_state_checked(PEER.into());
        assert!(
            t.elapsed() < Duration::from_millis(1000),
            "UI calls waited {:?} for a connect",
            t.elapsed()
        );
        assert!(
            connecting.join().unwrap().is_err(),
            "the stalled connect fails"
        );
        // A connect that failed leaves nothing installed; a second may run.
        assert!(client.inner.try_read().unwrap().websocket.is_none());
    }

    /// Concern 4: a busy client lock is not "disconnected" (that answer made
    /// the app force a reconnect).
    #[test]
    fn connection_status_while_the_lock_is_busy_is_the_last_known_one() {
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client.inner.try_write().unwrap().set_connected(true);
        let lock = client.inner.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _g = lock.blocking_write();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        held_rx.recv().unwrap();
        let busy = client.get_connection_status();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(matches!(busy, ConnectionStatus::Connected), "got {busy:?}");
        client.inner.try_write().unwrap().set_connected(false);
        assert!(matches!(
            client.get_connection_status(),
            ConnectionStatus::Disconnected
        ));
    }

    /// A loopback WebSocket server for connect tests (never port 8080): it
    /// accepts one connection, waits `before`, completes the upgrade, then
    /// holds the socket `hold` (or closes it at once).
    fn ws_server(before: Duration, hold: Duration) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 8080);
        std::thread::spawn(move || {
            if let Some(Ok(stream)) = listener.incoming().next() {
                std::thread::sleep(before);
                if let Ok(ws) = tokio_tungstenite::tungstenite::accept(stream) {
                    std::thread::sleep(hold);
                    drop(ws);
                }
            }
        });
        port
    }

    fn client_for(port: u16) -> Arc<RChatClient> {
        RChatClient::new(ClientConfig {
            server_url: format!("ws://127.0.0.1:{port}/"),
            connection_timeout_secs: 4,
            reconnect_max_attempts: 1,
            ..ClientConfig::default()
        })
        .unwrap()
    }

    fn wait_connecting(client: &RChatClient) {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !client
            .inner
            .try_read()
            .map(|i| i.connecting)
            .unwrap_or(false)
        {
            assert!(std::time::Instant::now() < deadline, "never connecting");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Review M-5: a disconnect during the handshake wins: the connection
    /// that completes afterwards is dropped, never installed.
    #[test]
    fn a_disconnect_during_the_handshake_wins() {
        let port = ws_server(Duration::from_millis(800), Duration::from_secs(3));
        let client = client_for(port);
        let c = client.clone();
        let connecting = std::thread::spawn(move || c.connect());
        wait_connecting(&client);
        client.disconnect().unwrap();
        let result = connecting.join().unwrap();
        assert!(result.is_err(), "the overtaken connect reports failure");
        let inner = client.inner.try_read().unwrap();
        assert!(inner.websocket.is_none() && !inner.connecting);
    }

    /// Review M-5: a second connect while one is in its handshake is refused
    /// at once (it would otherwise race the first for the client).
    #[test]
    fn a_second_connect_while_connecting_is_refused() {
        let port = ws_server(Duration::from_millis(1500), Duration::from_secs(3));
        let client = client_for(port);
        let c = client.clone();
        let first = std::thread::spawn(move || c.connect());
        wait_connecting(&client);
        let t = std::time::Instant::now();
        let second = client.connect();
        assert!(t.elapsed() < Duration::from_millis(500), "refused at once");
        assert!(
            matches!(&second, Err(RChatError::ConnectionFailed { message }) if message.contains("Already")),
            "{second:?}"
        );
        assert!(
            first.join().unwrap().is_ok(),
            "the first connect is unaffected"
        );
        let _ = client.disconnect();
    }

    /// Review M-5: no transport event is handled before the connect has
    /// installed its connection (the server closes right after the upgrade,
    /// while the connect is delayed before installing).
    #[test]
    fn no_event_is_handled_before_the_install() {
        let port = ws_server(Duration::ZERO, Duration::ZERO);
        let client = client_for(port);
        client.inner.try_write().unwrap().install_delay_for_test = Duration::from_millis(400);
        let _ = client.connect();
        std::thread::sleep(Duration::from_millis(300));
        let inner = client.inner.try_read().unwrap();
        assert_eq!(inner.events_while_connecting_for_test, 0);
        drop(inner);
        let _ = client.disconnect();
    }

    /// Review M-4: the identity cannot be swapped while a connect runs (or
    /// once connected): the publish would sign with a key the restored
    /// sessions were not made for.
    #[test]
    fn the_identity_cannot_change_while_connecting() {
        let port = ws_server(Duration::from_millis(1000), Duration::from_secs(3));
        let client = client_for(port);
        let c = client.clone();
        let connecting = std::thread::spawn(move || c.connect());
        wait_connecting(&client);
        assert!(client.generate_identity_from_seed(&[7u8; 32]).is_err());
        assert!(connecting.join().unwrap().is_ok());
        assert!(
            client.generate_identity_from_seed(&[7u8; 32]).is_err(),
            "nor with a connection installed"
        );
        let _ = client.disconnect();
        assert!(client.generate_identity_from_seed(&[7u8; 32]).is_ok());
    }
}
