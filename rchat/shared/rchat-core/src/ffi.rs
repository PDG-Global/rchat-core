//! C FFI layer for iOS and other C-ABI consumers.
//!
//! All functions are thread-safe; they synchronize through a global `Mutex`.
//! String memory allocated by Rust and returned to C must be freed via
//! `rchat_free_string`. Passing `NULL` where a string is required returns
//! error code 9 (`Invalid parameter`), except where a function documents its
//! own results: the pin calls (`rchat_pin_peer_key`, `rchat_unpin_peer_key`,
//! `rchat_set_peer_blocked`, `rchat_peer_key_state`) return -1 and
//! `rchat_set_intro` returns NULL. Those still record code 9, readable with
//! `rchat_last_error_code`. The last error (code and message) is kept per
//! calling thread: read it on the thread that made the failing call, right
//! after it.
//!
//! Callbacks run one at a time, in order, on a single dedicated
//! `rchat-callbacks` thread, never with the client's lock held. They must
//! still return quickly and must never call an `rchat_*` function
//! synchronously: every later callback waits behind the one running, and an
//! `rchat_*` call can block on the global state lock or the network. Hand
//! the work to another thread or queue first.
//!
//! Two callbacks are different: the state writer (`rchat_set_state_store`)
//! and the device signer (`rchat_set_device_signer`) are called
//! synchronously, on whichever core thread needs them, while the core's
//! state is locked. They must finish their work before returning and must
//! never call an `rchat_*` function at all: such a call is refused (it
//! returns that function's failure value and records code 8) rather than
//! deadlocking.

// C ABI entry points that read caller-supplied pointers are `unsafe extern
// "C" fn`s, each with its `# Safety` contract (S-15).

use once_cell::sync::Lazy;
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::crypto::IdentityKeyPair;
use crate::peers::{key_from_hex, PeerBook, PinError};
use crate::{
    ClientConfig, ConnectionStatus, MessageRequest, RChatCallbacks, RChatClient, RChatError,
    ReceivedMessage,
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

struct GlobalState {
    runtime: Option<tokio::runtime::Runtime>,
    client: Option<Arc<RChatClient>>,
    identity: Option<IdentityKeyPair>,
    callbacks: Option<CCallbackBridge>,
    /// Pins and blocks set before `rchat_connect`; moved into the new client.
    staged: PeerBook,
    /// Cover traffic (enabled, foreground), applied to each new client at
    /// `rchat_connect` so a scene phase reported before connecting is kept.
    cover: (bool, bool),
    /// The state key and writer from `rchat_set_state_store`, applied to
    /// each new client at `rchat_connect` (spec §18.4 D27). Dropped (the
    /// key wiped) by `rchat_disconnect`: they belong to one account.
    state_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    state_write: Option<StateWriteFn>,
    /// Sealed records from `rchat_import_state_record`, handed to the next
    /// client `rchat_connect` builds (and taken by it, whether or not the
    /// connect succeeds).
    staged_records: Vec<(String, Vec<u8>)>,
    /// The signer from `rchat_set_device_signer`, applied to each new
    /// client. Kept across `rchat_disconnect`, as the callbacks are: it
    /// belongs to the install, not the account.
    device_signer: Option<CDeviceSigner>,
}

static GLOBAL_STATE: Lazy<Mutex<GlobalState>> = Lazy::new(|| {
    Mutex::new(GlobalState {
        runtime: None,
        client: None,
        identity: None,
        callbacks: None,
        staged: PeerBook::default(),
        cover: (false, false),
        state_key: None,
        state_write: None,
        staged_records: Vec::new(),
        device_signer: None,
    })
});

/// Serialises `rchat_connect`: two overlapping connects (a foreground and a
/// network-restored reconnect) would otherwise each move the peer book and
/// one client would replace the other's.
static CONNECT_LOCK: Mutex<()> = Mutex::new(());

/// Bumped by every `rchat_disconnect` (C-6). A connect that started under an
/// older value finished after a logout/reset: its client is never installed
/// and its peer book is discarded, not staged for the next account.
static DISCONNECT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Error codes:
/// 0 = Success
/// 1 = Invalid config
/// 2 = Network unreachable
/// 3 = Authentication failed
/// 4 = Invalid recipient
/// 5 = Session not established
/// 6 = Already connected / already initialized
/// 7 = Not connected
/// 8 = Internal error
/// 9 = Invalid parameter
/// 10 = Peer's keys don't match the pin (PeerKeyRejected; stays queued)
/// 11 = Peer's keys couldn't be checked (PeerKeyUnverified; resend after the circuit)
/// 12 = Not an accepted contact (PeerNotAccepted)
/// 13 = Contact is blocked (PeerBlocked)
/// 14 = Key authentication rejected by the relay
/// 15 = Protocol version mismatch with the relay
/// 16 = No channel binding for this connection
/// 17 = A different key is already pinned (PinConflict)
/// 18 = Agreement key pinned for another contact (AgreementKeyInUse)
/// 19 = No keys pinned for this contact (NoPinnedKeys)
/// 20 = Safety number changed since it was shown
/// 21 = Relay could not prove its identity
/// 22 = A saved relay identity is required
/// 23 = The relay's identity changed
/// 24 = Keys can be rotated once a day (RotationTooSoon)
/// 25 = Session state could not be written (StatePersistFailed; nothing was
///      sent or delivered, try again later)
/// 26 = Automatic resend refused (ResendRefused: the session that made the
///      id eligible is gone, or the contact is no longer plainly pinned)
///
/// `rchat_last_error_code` returns the code of the most recent failing call
/// on the calling thread; every error return records the code it returns.

fn lock_state() -> std::sync::MutexGuard<'static, GlobalState> {
    GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

thread_local! {
    /// The last failure on this thread: its code and message, read by
    /// `rchat_last_error_code` / `rchat_last_error`. Per thread, so two
    /// calls on different threads never read each other's error; the
    /// caller reads it on the thread that made the failing call, before
    /// making another `rchat_*` call there. Every failure is recorded on
    /// the calling thread (never inside a spawned worker).
    static LAST_ERROR: std::cell::RefCell<(c_int, String)> =
        const { std::cell::RefCell::new((0, String::new())) };
}

/// Record a failure on the calling thread and return its code, so every
/// error return reports the code `rchat_last_error_code` then gives.
fn record_error(code: c_int, message: String) -> c_int {
    LAST_ERROR.with(|e| *e.borrow_mut() = (code, message));
    code
}

fn last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0)
}

fn record_rchat_error(e: &RChatError, context: &str) -> c_int {
    record_error(error_code_from_err(e), format!("{context}: {e}"))
}

thread_local! {
    /// Set while this thread runs the state writer or the device signer.
    /// Both run with the client (and maybe the global state) locked, so an
    /// `rchat_*` call from inside them would deadlock: every entry that
    /// takes a lock refuses instead (code 8).
    static IN_SYNC_CALLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Marks this thread as inside a synchronous callback until dropped.
struct SyncCallbackScope(bool);

impl SyncCallbackScope {
    fn enter() -> Self {
        Self(IN_SYNC_CALLBACK.with(|f| f.replace(true)))
    }
}

impl Drop for SyncCallbackScope {
    fn drop(&mut self) {
        IN_SYNC_CALLBACK.with(|f| f.set(self.0));
    }
}

/// True (code 8 recorded) when called from the state writer or the signer.
fn refused_in_sync_callback() -> bool {
    if IN_SYNC_CALLBACK.with(std::cell::Cell::get) {
        record_error(
            8,
            "rchat_* called from the state writer or device signer".to_string(),
        );
        return true;
    }
    false
}

/// First line of every entry that takes a lock: return `$ret` (with code 8
/// recorded) instead of deadlocking when re-entered from a synchronous
/// callback.
macro_rules! refuse_reentry {
    ($ret:expr) => {
        if refused_in_sync_callback() {
            return $ret;
        }
    };
}

/// A NUL-terminated UTF-8 argument, or None for NULL / invalid UTF-8.
///
/// # Safety
///
/// `p` must be NULL or point to a NUL-terminated string valid for reads
/// for the duration of the call.
unsafe fn arg(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// The client, or record "not connected" (7).
fn client_or_7() -> Result<Arc<RChatClient>, c_int> {
    lock_state()
        .client
        .clone()
        .ok_or_else(|| record_error(7, "Not connected".to_string()))
}

/// Where a pin/block/state call acts: the live client, or the book staged
/// before `rchat_connect` (held under the state lock).
enum PeerTarget {
    Client(Arc<RChatClient>),
    Staged(std::sync::MutexGuard<'static, GlobalState>),
}

/// Validate a 64-hex identity argument (lowercased) and pick the target.
/// `Err(-1)`: NULL, bad UTF-8 or not 64 hex; `Err(-3)`: `need_runtime` and
/// `rchat_initialize` has not run. Both failures record a code (9 / 8).
///
/// # Safety
///
/// As `arg` for `identity_hex`.
unsafe fn peer_target(
    identity_hex: *const c_char,
    need_runtime: bool,
) -> Result<(String, PeerTarget), c_int> {
    let Some(id) = arg(identity_hex)
        .map(|s| s.to_lowercase())
        .filter(|s| key_from_hex(s).is_some())
    else {
        record_error(9, "Invalid identity".to_string());
        return Err(-1);
    };
    let guard = lock_state();
    if need_runtime && guard.runtime.is_none() {
        drop(guard);
        record_error(8, "Runtime not initialized".to_string());
        return Err(-3);
    }
    let target = match guard.client.clone() {
        Some(client) => {
            drop(guard);
            PeerTarget::Client(client)
        }
        None => PeerTarget::Staged(guard),
    };
    Ok((id, target))
}

fn error_code_from_err(e: &RChatError) -> c_int {
    match e {
        RChatError::ConnectionFailed { .. } => 2,
        RChatError::NotConnected => 7,
        RChatError::EncryptionFailed { .. } => 8,
        RChatError::DecryptionFailed { .. } => 8,
        RChatError::InvalidRecipient { .. } => 4,
        RChatError::SessionNotEstablished { .. } => 5,
        RChatError::MessageTimeout { .. } => 8,
        RChatError::Internal { .. } => 8,
        RChatError::KeyAuthRejected => 14,
        RChatError::ServerTooNew => 15,
        RChatError::NoChannelBinding => 16,
        RChatError::RelayIdentityInvalid => 21,
        RChatError::RelayPinRequired => 22,
        RChatError::RelayIdentityChanged => 23,
        RChatError::PeerKeyRejected { .. } => 10,
        RChatError::PeerKeyUnverified { .. } => 11,
        RChatError::PeerNotAccepted { .. } => 12,
        RChatError::PeerBlocked { .. } => 13,
        RChatError::PinConflict => 17,
        RChatError::AgreementKeyInUse => 18,
        RChatError::NoPinnedKeys { .. } => 19,
        RChatError::SafetyNumberChanged => 20,
        RChatError::RotationTooSoon => 24,
        RChatError::InvalidSafetyNumber => 9,
        RChatError::StatePersistFailed => 25,
        RChatError::ResendRefused { .. } => 26,
    }
}

// ---------------------------------------------------------------------------
// C callback bridge
// ---------------------------------------------------------------------------

/// `on_message`'s last argument: the plaintext's type. Text (UTF-8, type
/// 0x01) may carry an older peer's in-band media prefix; binary (type 0x02)
/// starts with a known magic (`protocol::is_known_binary`): media, or text
/// that begins with an old media prefix.
pub const MESSAGE_KIND_TEXT: c_int = 1;
pub const MESSAGE_KIND_BINARY: c_int = 2;

/// Function pointers received from Swift / C.
#[derive(Clone, Copy)]
struct CCallbackPointers {
    on_message: extern "C" fn(*const c_char, *const c_char, u64, *const c_char, c_int),
    on_state_change: extern "C" fn(c_int),
    on_error: extern "C" fn(*const c_char),
    on_circuit_established: extern "C" fn(*const c_char, c_int),
    on_message_delivered: extern "C" fn(*const c_char),
    on_reconnect: extern "C" fn(),
    on_peer_key_event: extern "C" fn(*const c_char, c_int, *const c_char),
    on_message_request:
        extern "C" fn(*const c_char, *const c_char, u64, *const c_char, *const c_char, u64, u32),
    on_message_receipt: extern "C" fn(*const c_char, *const c_char, c_int),
    on_peer_rotated: extern "C" fn(*const c_char, *const c_char, *const c_char, u32),
    on_status_event: extern "C" fn(c_int, *const c_char, *const c_char, c_int),
}

#[derive(Clone)]
struct CCallbackBridge {
    ptrs: CCallbackPointers,
}

// Plain `extern "C" fn` pointers are Send + Sync, so the bridge is too,
// checked by the compiler (no `unsafe impl`, S-15). The C side promises the
// functions are safe to call from any thread: the core calls them on its
// dedicated, ordered `rchat-callbacks` thread (`RChatClient::set_callbacks`),
// never with the client's lock held.

impl RChatCallbacks for CCallbackBridge {
    fn on_connection_status_changed(&self, status: ConnectionStatus) {
        let code = match status {
            ConnectionStatus::Disconnected => 0,
            ConnectionStatus::Connecting => 1,
            ConnectionStatus::Connected => 2,
            ConnectionStatus::Reconnecting { .. } => 3,
            ConnectionStatus::Error { .. } => 4,
        };
        (self.ptrs.on_state_change)(code);
    }

    fn on_message_received(&self, message: ReceivedMessage) {
        let (Ok(sender), Ok(id)) = (
            CString::new(message.sender_identity),
            CString::new(message.id),
        ) else {
            return;
        };
        // Content may contain NUL bytes, so it crosses as hex.
        let Ok(content) = CString::new(hex::encode(&message.content)) else {
            return;
        };
        (self.ptrs.on_message)(
            sender.as_ptr(),
            content.as_ptr(),
            message.timestamp_ms,
            id.as_ptr(),
            if message.is_text {
                MESSAGE_KIND_TEXT
            } else {
                MESSAGE_KIND_BINARY
            },
        );
    }

    fn on_peer_key_event(&self, identity_hex: String, code: u8, agreement_hex: String) {
        if let (Ok(id), Ok(ak)) = (CString::new(identity_hex), CString::new(agreement_hex)) {
            (self.ptrs.on_peer_key_event)(id.as_ptr(), c_int::from(code), ak.as_ptr());
        }
    }

    /// "No intro" crosses as `""` and `0`.
    fn on_message_request(&self, r: MessageRequest) {
        let parts = (
            CString::new(r.identity_hex),
            CString::new(r.agreement_hex),
            CString::new(r.intro_message_id_hex),
            CString::new(r.intro_text),
        );
        if let (Ok(id), Ok(ak), Ok(intro_id), Ok(text)) = parts {
            (self.ptrs.on_message_request)(
                id.as_ptr(),
                ak.as_ptr(),
                r.issued_hour,
                intro_id.as_ptr(),
                text.as_ptr(),
                r.intro_sent_at_ms,
                r.key_version,
            );
        }
    }

    fn on_peer_rotated(&self, old: String, new: String, ak: String, version: u32) {
        if let (Ok(o), Ok(n), Ok(a)) = (CString::new(old), CString::new(new), CString::new(ak)) {
            (self.ptrs.on_peer_rotated)(o.as_ptr(), n.as_ptr(), a.as_ptr(), version);
        }
    }

    fn on_message_receipt(&self, sender_hex: String, message_id_hex: String, kind: u8) {
        if let (Ok(sender), Ok(id)) = (CString::new(sender_hex), CString::new(message_id_hex)) {
            (self.ptrs.on_message_receipt)(sender.as_ptr(), id.as_ptr(), c_int::from(kind));
        }
    }

    fn on_message_delivered(&self, message_id: String) {
        if let Ok(cstr) = CString::new(message_id) {
            (self.ptrs.on_message_delivered)(cstr.as_ptr());
        }
    }

    fn on_error(&self, error: String) {
        if let Ok(cstr) = CString::new(error) {
            (self.ptrs.on_error)(cstr.as_ptr());
        }
    }

    fn on_circuit_established(&self, recipient_identity: String, is_initiator: bool) {
        let recipient = match CString::new(recipient_identity) {
            Ok(s) => s,
            Err(_) => return,
        };
        (self.ptrs.on_circuit_established)(recipient.as_ptr(), if is_initiator { 1 } else { 0 });
    }

    fn on_reconnect(&self) {
        (self.ptrs.on_reconnect)();
    }

    fn on_log(&self, message: String) {
        let msg = format!("[LOG] {}", message);
        if let Ok(cstr) = CString::new(msg) {
            (self.ptrs.on_error)(cstr.as_ptr());
        }
    }

    /// (kind, peer or "", message id or "", detail), spec §18.9 D40.
    fn on_status_event(&self, event: crate::status::StatusEvent) {
        let (kind, peer, id, detail) = event.parts();
        if let (Ok(p), Ok(i)) = (CString::new(peer), CString::new(id)) {
            (self.ptrs.on_status_event)(kind, p.as_ptr(), i.as_ptr(), detail);
        }
    }
}

// ---------------------------------------------------------------------------
// Synchronous callbacks: the state writer and the device signer
// ---------------------------------------------------------------------------

/// Writes one sealed record for the core (spec §18.4 D27): `record_key` is
/// a NUL-terminated file-name-safe key, `sealed` the record's `len` bytes
/// (ciphertext only). `len == 0` (and `sealed` NULL) deletes the record.
/// Return 0 once it is durably written, non-zero on failure.
///
/// Called synchronously, on whichever core thread needs the write, while
/// the core's state is locked: it must not call any `rchat_*` function, and
/// it must not keep `sealed` or `record_key` past the call.
pub type StateWriteFn = extern "C" fn(*const c_char, *const u8, usize) -> c_int;

/// A client's view of the app's writer, valid for one account: once
/// `rchat_disconnect` has run (the generation moved), a client still
/// holding it (retired, abandoned) can no longer write through whichever
/// writer is current then.
struct CStateSink {
    write: StateWriteFn,
    generation: u64,
}

impl crate::state_store::StateSink for CStateSink {
    fn write(&self, record_key: &str, sealed: &[u8]) -> Result<(), String> {
        if DISCONNECT_GENERATION.load(Ordering::SeqCst) != self.generation {
            return Err("store detached: account disconnected".to_string());
        }
        let key = CString::new(record_key).map_err(|_| "key".to_string())?;
        let ptr = if sealed.is_empty() {
            std::ptr::null()
        } else {
            sealed.as_ptr()
        };
        let _scope = SyncCallbackScope::enter();
        match (self.write)(key.as_ptr(), ptr, sealed.len()) {
            0 => Ok(()),
            code => Err(format!("write failed ({code})")),
        }
    }
}

/// Signs `msg` (`len` bytes) with this install's device key (spec §18.14
/// D45), writing a raw `r || s` P-256 signature into the 64 bytes at
/// `sig_out`. Return 0 when signed; anything else and the notice goes out
/// unsigned (receivers then treat it as unsigned, D46).
///
/// Called synchronously, on the core thread building a session notice,
/// with the core's state locked: it must not call any `rchat_*` function,
/// must write at most 64 bytes, and must keep neither pointer past the call.
pub type DeviceSignFn = extern "C" fn(*const u8, usize, *mut u8) -> c_int;

#[derive(Clone, Copy)]
struct CDeviceSigner(DeviceSignFn);

impl crate::device_key::DeviceSigner for CDeviceSigner {
    fn sign(&self, msg: &[u8]) -> Option<[u8; 64]> {
        // The buffer is ours and lives for the call only; nothing is
        // retained after it, whatever the signer returns.
        let mut out = [0u8; 64];
        let _scope = SyncCallbackScope::enter();
        match (self.0)(msg.as_ptr(), msg.len(), out.as_mut_ptr()) {
            0 => Some(out),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Exported FFI functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn rchat_initialize() -> c_int {
    refuse_reentry!(8);
    let mut guard = lock_state();
    if guard.runtime.is_some() {
        // Runtime already exists — expected during fast reconnect where we
        // preserve the runtime across disconnect/connect cycles.
        return 0;
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return record_error(8, format!("Failed to create runtime: {}", e));
        }
    };
    guard.runtime = Some(rt);
    0
}

/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_connect(config_json: *const c_char) -> c_int {
    refuse_reentry!(8);
    // Kept for compatibility: the config may carry the seed in hex.
    // `rchat_connect_with_seed` keeps it out of the JSON (I-8).
    unsafe { connect_with(config_json, None) }
}

/// `rchat_connect` with the identity seed passed as raw bytes (I-8), so no
/// caller has to build a string holding it. `config_json` must not carry
/// `identity_key_seed` (error 9 if it does). `seed_len` is 64 (or a legacy
/// 32). The core copies the seed into a wiped buffer; the caller wipes its
/// own after the call. Same results as `rchat_connect`.
///
/// # Safety
///
/// `config_json` must point to a NUL-terminated string that stays valid
/// for the call; `seed` must be valid for reads of `seed_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rchat_connect_with_seed(
    config_json: *const c_char,
    seed: *const u8,
    seed_len: usize,
) -> c_int {
    refuse_reentry!(8);
    if seed.is_null() || !(seed_len == 64 || seed_len == 32) {
        return record_error(9, "Invalid parameter".to_string());
    }
    // SAFETY: non-null and valid for `seed_len` bytes per the contract.
    let bytes = unsafe { std::slice::from_raw_parts(seed, seed_len) };
    // Sized up front so no growing buffer is freed holding seed hex (N-3).
    let mut hex = zeroize::Zeroizing::new(String::with_capacity(seed_len * 2));
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        hex.push(DIGITS[usize::from(b >> 4)] as char);
        hex.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    unsafe { connect_with(config_json, Some(hex)) }
}

/// A seed from JSON, wrapped the moment it is read (R1-3).
fn wiped_seed<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<zeroize::Zeroizing<String>>, D::Error> {
    use serde::Deserialize;
    Option::<String>::deserialize(d).map(|s| s.map(zeroize::Zeroizing::new))
}

/// The config's seed alone; every other field is skipped unread.
#[derive(serde::Deserialize)]
struct SeedField {
    #[serde(default, deserialize_with = "wiped_seed")]
    identity_key_seed: Option<zeroize::Zeroizing<String>>,
}

/// An identity file's fields, the seed wiped however parsing ends (R1-3).
#[derive(serde::Deserialize)]
struct IdentityFields {
    #[serde(default, deserialize_with = "wiped_seed")]
    seed: Option<zeroize::Zeroizing<String>>,
    #[serde(default)]
    signing_pubkey: Option<String>,
    #[serde(default)]
    agreement_pubkey: Option<String>,
}

/// The shared body of both connects. `seed_hex`, when given, becomes the
/// config's seed; the JSON must then have none.
unsafe fn connect_with(
    config_json: *const c_char,
    seed_hex: Option<zeroize::Zeroizing<String>>,
) -> c_int {
    // Read before waiting for CONNECT_LOCK (N-5): a connect issued before a
    // logout but queued behind another connect must still lose to it.
    let generation = DISCONNECT_GENERATION.load(Ordering::SeqCst);
    // The config may carry the identity seed: wiped when dropped (N-3).
    let Some(json_str) = arg(config_json).map(zeroize::Zeroizing::new) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let _connecting = CONNECT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The seed is read on its own, straight into a wiped buffer, so no
    // failure later in the JSON frees a plain copy of it (R1-3); the
    // config proper never deserializes it.
    let json_seed = match serde_json::from_str::<SeedField>(json_str.as_str()) {
        Ok(f) => f.identity_key_seed,
        Err(e) => return record_error(1, format!("Invalid config JSON: {}", e)),
    };
    let mut config: ClientConfig = match serde_json::from_str(json_str.as_str()) {
        Ok(c) => c,
        Err(e) => return record_error(1, format!("Invalid config JSON: {}", e)),
    };
    // The seed, from the JSON or as bytes, is held in a wiped buffer until
    // the last fallible step before the client takes it (R1-N2): every early
    // return below drops it wiped, never as a plain `String` in `config`.
    let mut seed = match (seed_hex, json_seed) {
        (Some(_), Some(_)) => {
            return record_error(9, "Seed given both in the config and as bytes".to_string());
        }
        (bytes, json) => bytes.or(json),
    };

    // Extract what we need from global state, then drop the lock before spawning
    // a thread: the connect thread may need GLOBAL_STATE, so holding the
    // lock across join() would deadlock.
    let (runtime, callbacks_snapshot) = {
        let guard = lock_state();
        let runtime = match guard.runtime {
            Some(ref rt) => Arc::new(rt.handle().clone()),
            None => {
                return record_error(
                    8,
                    "Runtime not initialized. Call rchat_initialize() first.".to_string(),
                );
            }
        };
        let cb = guard.callbacks.clone();
        (runtime, cb)
    };

    // Moved, not copied: the client takes it into its own wiped buffer
    // before anything else can fail (C-10, R1-N2).
    config.identity_key_seed = seed.as_mut().map(|hex| std::mem::take(&mut **hex));
    drop(seed);
    // Create client
    let client = match RChatClient::new(config) {
        Ok(c) => c,
        Err(e) => return record_rchat_error(&e, "Failed to create client"),
    };

    // Register callbacks if they were previously set
    if let Some(ref bridge) = callbacks_snapshot {
        client.set_callbacks(Box::new(bridge.clone()));
    }
    // A client kept by `rchat_disconnect_transport_only` holds the live pins
    // and blocks: move them to the staged book before it is replaced.
    retire_previous_client();
    // Pins staged before connect must be in place before any knock arrives.
    adopt_staged(&client);
    // The store and its records before `connect()`, which opens them.
    apply_store_and_signer(&client, generation);
    let (cover_on, cover_fg) = lock_state().cover;
    client.set_cover_traffic(cover_on, cover_fg);

    // Connect (block_on via the runtime handle) — no lock held during this call
    let client_for_connect = client.clone();
    let result =
        std::thread::spawn(move || runtime.block_on(async move { client_for_connect.connect() }))
            .join();

    // A disconnect (logout, Reset Identity) ran while this connect did: the
    // client belongs to the old account. Silence it and drop its book.
    if DISCONNECT_GENERATION.load(Ordering::SeqCst) != generation {
        abandon_client(&client);
        return record_error(7, "Disconnected while connecting".to_string());
    }
    match result {
        Ok(Ok(())) => {
            if install_client_if_current(client.clone(), generation) {
                0
            } else {
                abandon_client(&client);
                record_error(7, "Disconnected while connecting".to_string())
            }
        }
        Ok(Err(e)) => {
            restore_staged(&client);
            record_rchat_error(&e, "Connect failed")
        }
        Err(e) => {
            restore_staged(&client);
            record_error(8, format!("Connect thread panicked: {:?}", e))
        }
    }
}

/// A client whose connect was overtaken by `rchat_disconnect`: its peer
/// book is discarded and it is silenced and disconnected.
fn abandon_client(client: &RChatClient) {
    drop(client.export_peer_book());
    // Before retiring: it belongs to an account that has logged out.
    client.detach_state_store();
    client.retire();
}

#[no_mangle]
pub extern "C" fn rchat_disconnect() -> c_int {
    refuse_reentry!(8);
    // A connect still running must not install its client afterwards (C-6).
    DISCONNECT_GENERATION.fetch_add(1, Ordering::SeqCst);
    // Extract client + runtime, then drop the lock before spawning a thread
    // to avoid deadlock (the disconnect thread may need GLOBAL_STATE).
    let (client_opt, runtime_handle_opt) = {
        let guard = lock_state();
        let c = guard.client.clone();
        let r = guard
            .runtime
            .as_ref()
            .map(|rt| Arc::new(rt.handle().clone()));
        (c, r)
    };

    if let (Some(client), Some(runtime_handle)) = (client_opt, runtime_handle_opt) {
        let disconnecting = client.clone();
        let result = std::thread::spawn(move || {
            runtime_handle.block_on(async move { disconnecting.disconnect() })
        })
        .join();
        match result {
            Ok(Ok(())) => {}
            // It still returns 0 (the client is dropped either way), so
            // nothing is recorded as this call's error.
            Ok(Err(e)) => log::warn!("[RUST] Disconnect error: {e}"),
            Err(e) => log::warn!("[RUST] Disconnect thread panicked: {e:?}"),
        }
        // No write through the app's writer from now on: the next account
        // may set its own (the sink already refuses: the generation moved).
        client.detach_state_store();
        // The app still hears the Disconnected status, then nothing more
        // from this client, even if a reconnect races with this (N-5).
        client.flush_callbacks();
        client.retire();
    }

    let mut guard = lock_state();
    guard.client = None;
    guard.runtime = None;
    guard.staged = PeerBook::default();
    guard.cover = (false, false);
    // The account's state key (wiped on drop), writer and staged records.
    guard.state_key = None;
    guard.state_write = None;
    guard.staged_records.clear();
    // An identity loaded before a connect (onboarding): wiped on drop.
    guard.identity = None;
    0
}

/// Move pins/blocks set before `rchat_connect` into the new client.
fn adopt_staged(client: &RChatClient) {
    let staged = std::mem::take(&mut lock_state().staged);
    client.import_peer_book(staged);
}

/// Hand the state store and the staged records (taken: each connect
/// consumes them, so the app imports them before every `rchat_connect`) to
/// a new client, and the device signer. Without a store the records are
/// dropped and persistence stays off.
///
/// The sink is bound to `generation` (the connect's): if a disconnect has
/// already run, the client can never write.
fn apply_store_and_signer(client: &RChatClient, generation: u64) {
    let (key, write, records, signer) = {
        let mut g = lock_state();
        (
            g.state_key.clone(),
            g.state_write,
            std::mem::take(&mut g.staged_records),
            g.device_signer,
        )
    };
    if let (Some(key), Some(write)) = (key, write) {
        client.set_state_store(&key, Arc::new(CStateSink { write, generation }));
        client.import_state_records(records);
    }
    if let Some(signer) = signer {
        client.set_device_signer(Arc::new(signer));
    }
}

/// Take the current client (if any) out of the state, move its peer book
/// into the staged book (anything already staged applied on top), and
/// silence and disconnect it.
fn retire_previous_client() {
    let Some(previous) = lock_state().client.take() else {
        return;
    };
    let mut book = previous.export_peer_book();
    {
        let mut guard = lock_state();
        let newer = std::mem::take(&mut guard.staged);
        book.overlay(newer);
        guard.staged = book;
    }
    // It may still be connected or auto-reconnecting: with an empty book it
    // would report contacts as strangers through the shared callbacks. Only
    // `rchat_disconnect_transport_only` leaves a client here (same account;
    // a logout clears it), so its queued calls are delivered first (R1-1).
    // It stops writing first: the new client restores and owns the records.
    previous.detach_state_store();
    previous.retire_delivering_queued();
}

/// `install_client`, unless `rchat_disconnect` ran since `generation` was
/// read (checked under the state lock, so a disconnect is either seen here
/// or finds the installed client). False: not installed.
fn install_client_if_current(client: Arc<RChatClient>, generation: u64) -> bool {
    let guard = lock_state();
    if DISCONNECT_GENERATION.load(Ordering::SeqCst) != generation {
        return false;
    }
    install_client_locked(guard, client);
    true
}

/// Make a connected client current, then apply the pin and block changes
/// and the cover setting that were staged while it connected (the state
/// lock is held throughout, so later calls reach the client only after them).
#[cfg(test)]
fn install_client(client: Arc<RChatClient>) {
    install_client_locked(lock_state(), client);
}

fn install_client_locked(
    mut guard: std::sync::MutexGuard<'static, GlobalState>,
    client: Arc<RChatClient>,
) {
    guard.client = Some(client.clone());
    // The client holds the identity now: the one loaded before the first
    // connect goes, wiped on drop (its keys zeroize), so a retired identity
    // can never sign again (Task 9b re-review).
    guard.identity = None;
    let newer = std::mem::take(&mut guard.staged);
    client.overlay_peer_book(newer);
    let (cover_on, cover_fg) = guard.cover;
    client.set_cover_traffic(cover_on, cover_fg);
}

/// A connect failed: hand the book `adopt_staged` gave the client back to
/// the staged book, so the next connect still has every pin and block.
/// Anything staged while the connect ran is applied on top.
fn restore_staged(client: &RChatClient) {
    let mut book = client.export_peer_book();
    let mut guard = lock_state();
    let newer = std::mem::take(&mut guard.staged);
    book.overlay(newer);
    guard.staged = book;
}

/// Drop only the transport, keeping the client with its E2EE sessions, pins
/// and recipient; `rchat_reconnect` brings it back. Returns 0.
#[no_mangle]
pub extern "C" fn rchat_disconnect_transport_only() -> c_int {
    refuse_reentry!(8);
    // Serialised with connects (C-6): it acts on the client a connect installs.
    let _connecting = CONNECT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (client_opt, runtime_handle_opt) = {
        let guard = lock_state();
        let c = guard.client.clone();
        let r = guard
            .runtime
            .as_ref()
            .map(|rt| Arc::new(rt.handle().clone()));
        (c, r)
    };

    if let (Some(client), Some(runtime_handle)) = (client_opt, runtime_handle_opt) {
        let result = std::thread::spawn(move || {
            runtime_handle.block_on(async move { client.disconnect_transport_only() })
        })
        .join();
        match result {
            Ok(Ok(())) => {}
            // Returns 0 either way: nothing recorded as this call's error.
            Ok(Err(e)) => log::warn!("[RUST] Disconnect transport error: {e}"),
            Err(e) => log::warn!("[RUST] Disconnect transport thread panicked: {e:?}"),
        }
    }
    // NOTE: Intentionally keep client and runtime alive so that E2EE
    // sessions survive for fast reconnect.
    0
}

/// Reconnect the client kept by `rchat_disconnect_transport_only`, keeping
/// its identity, Double Ratchet sessions, pins and current recipient: only
/// the transport is new. Everything `rchat_connect` applies still applies:
/// the registered callbacks and pins/blocks set meanwhile already act on
/// the live client, anything staged is applied on top, the cover setting is
/// re-applied, the bundle is published, and a `rchat_disconnect` racing
/// this wins (N-5). Returns 0 on success, 7 when there is no client to
/// reconnect (call `rchat_connect`) or a disconnect overtook it.
#[no_mangle]
pub extern "C" fn rchat_reconnect() -> c_int {
    refuse_reentry!(8);
    // A disconnect after this point wins over the reconnect (N-5).
    let generation = DISCONNECT_GENERATION.load(Ordering::SeqCst);
    // Serialised with connects (C-6).
    let _connecting = CONNECT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (client_opt, runtime_handle_opt) = {
        let guard = lock_state();
        let c = guard.client.clone();
        let r = guard
            .runtime
            .as_ref()
            .map(|rt| Arc::new(rt.handle().clone()));
        (c, r)
    };

    let (client, runtime_handle) = match (client_opt, runtime_handle_opt) {
        (Some(c), Some(r)) => (c, r),
        _ => {
            return record_error(
                7,
                "No client to reconnect; call rchat_connect first".to_string(),
            );
        }
    };

    let connecting = client.clone();
    let result =
        std::thread::spawn(move || runtime_handle.block_on(async move { connecting.connect() }))
            .join();

    if DISCONNECT_GENERATION.load(Ordering::SeqCst) != generation {
        client.retire();
        return record_error(7, "Disconnected while reconnecting".to_string());
    }
    match result {
        // The same install step as a connect: staged changes and the cover
        // setting, under the state lock, unless a disconnect got in first.
        Ok(Ok(())) => {
            if install_client_if_current(client.clone(), generation) {
                0
            } else {
                client.retire();
                record_error(7, "Disconnected while reconnecting".to_string())
            }
        }
        Ok(Err(e)) => record_rchat_error(&e, "Reconnect failed"),
        Err(e) => record_error(8, format!("Reconnect thread panicked: {:?}", e)),
    }
}

/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_recipient(
    recipient: *const c_char,
    agreement_key: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let Some(recipient_str) = arg(recipient) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let agreement_key_str = if agreement_key.is_null() {
        None
    } else {
        match arg(agreement_key) {
            Some(s) => Some(s),
            None => return record_error(9, "Invalid parameter".to_string()),
        }
    };

    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => return record_error(7, "Not connected".to_string()),
    };
    let runtime_handle = match guard.runtime {
        Some(ref rt) => Arc::new(rt.handle().clone()),
        None => return record_error(7, "Not connected".to_string()),
    };
    drop(guard);

    let result = std::thread::spawn(move || {
        runtime_handle
            .block_on(async move { client.set_recipient(recipient_str, agreement_key_str) })
    })
    .join();

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => record_rchat_error(&e, "Set recipient failed"),
        Err(e) => record_error(8, format!("Set recipient thread panicked: {:?}", e)),
    }
}

#[no_mangle]
pub extern "C" fn rchat_publish_key_bundle() -> c_int {
    refuse_reentry!(8);
    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => return record_error(7, "Not connected".to_string()),
    };
    let runtime_handle = match guard.runtime {
        Some(ref rt) => Arc::new(rt.handle().clone()),
        None => return record_error(7, "Not connected".to_string()),
    };
    drop(guard);

    let result = std::thread::spawn(move || {
        runtime_handle.block_on(async move { client.publish_key_bundle() })
    })
    .join();

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => record_rchat_error(&e, "Publish key bundle failed"),
        Err(e) => record_error(8, format!("Publish key bundle thread panicked: {:?}", e)),
    }
}

/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_message(
    recipient: *const c_char,
    text: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(recipient_str), Some(text_str)) = (arg(recipient), arg(text)) else {
        return record_error(9, "Invalid parameter".to_string());
    };

    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => return record_error(7, "Not connected".to_string()),
    };
    let runtime_handle = match guard.runtime {
        Some(ref rt) => Arc::new(rt.handle().clone()),
        None => return record_error(7, "Not connected".to_string()),
    };
    drop(guard);

    let result = std::thread::spawn(move || {
        runtime_handle.block_on(async move { client.send_text_message(recipient_str, text_str) })
    })
    .join();

    match result {
        Ok(Ok(_msg_id)) => 0,
        Ok(Err(e)) => record_rchat_error(&e, "Send failed"),
        Err(e) => record_error(8, format!("Send thread panicked: {:?}", e)),
    }
}

/// Send a text message and return the message ID (heap C string; free with `rchat_free_string`).
/// Returns NULL on failure. Use with `on_message_delivered` to track delivery.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_message_with_id(
    recipient: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let (Some(recipient_str), Some(text_str)) = (arg(recipient), arg(text)) else {
        record_error(9, "Invalid parameter".to_string());
        return std::ptr::null_mut();
    };
    send_returning_id(move |client| client.send_text_message(recipient_str, text_str))
}

/// Send media (or text that starts with an old in-band media prefix) as a
/// binary plaintext, type 0x02, and return the message ID as
/// `rchat_send_message_with_id` does. `data` must start with a known magic
/// (`IMG1` image, `VOCE` voice note, `TXT1` text); anything else is refused
/// with code 9.
///
/// # Safety
///
/// `recipient` must be NULL or a NUL-terminated string, and `data` NULL or
/// valid for reads of `len` bytes; both stay valid and unmodified for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_binary_with_id(
    recipient: *const c_char,
    data: *const u8,
    len: usize,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let Some(recipient_str) = arg(recipient) else {
        record_error(9, "Invalid parameter".to_string());
        return std::ptr::null_mut();
    };
    let Ok(body) = (unsafe { binary_body(data, len) }) else {
        return std::ptr::null_mut();
    };
    send_returning_id(move |client| client.send_binary_message(recipient_str, body))
}

/// A binary send's body: `data` non-NULL, `len > 0` and a known magic
/// (`protocol::is_known_binary`). `Err(9)`, recorded, otherwise.
///
/// # Safety
///
/// `data` must be NULL or valid for reads of `len` bytes for the call.
unsafe fn binary_body(data: *const u8, len: usize) -> Result<Vec<u8>, c_int> {
    if data.is_null() || len == 0 {
        return Err(record_error(9, "Invalid parameter".to_string()));
    }
    // SAFETY: non-null and valid for `len` bytes per the contract.
    let body = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    if !crate::protocol::is_known_binary(&body) {
        return Err(record_error(9, "Unknown binary payload".to_string()));
    }
    Ok(body)
}

/// The shared tail of the id-returning sends: run `send` on the client off
/// the caller's thread and hand back the id as a heap C string, or NULL with
/// the error recorded.
fn send_returning_id(
    send: impl FnOnce(Arc<RChatClient>) -> Result<String, RChatError> + Send + 'static,
) -> *mut c_char {
    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => {
            record_error(7, "Not connected".to_string());
            return std::ptr::null_mut();
        }
    };
    let runtime_handle = match guard.runtime {
        Some(ref rt) => Arc::new(rt.handle().clone()),
        None => {
            record_error(7, "Not connected".to_string());
            return std::ptr::null_mut();
        }
    };
    drop(guard);

    let result =
        std::thread::spawn(move || runtime_handle.block_on(async move { send(client) })).join();

    match result {
        Ok(Ok(msg_id)) => match CString::new(msg_id) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                record_error(8, "Message ID contained NUL".to_string());
                std::ptr::null_mut()
            }
        },
        Ok(Err(e)) => {
            record_rchat_error(&e, "Send failed");
            std::ptr::null_mut()
        }
        Err(e) => {
            record_error(8, format!("Send thread panicked: {:?}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn rchat_generate_identity() -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let identity = IdentityKeyPair::generate();
    // Every copy of the seed lives in a wiped buffer (C-10); the returned
    // string is wiped by `rchat_free_string`.
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    identity.write_seed(&mut seed);
    // Sized up front so no growing buffer is freed with seed bytes (N-3).
    let mut seed_hex = zeroize::Zeroizing::new([0u8; 128]);
    if hex::encode_to_slice(&seed[..], &mut seed_hex[..]).is_err() {
        return std::ptr::null_mut();
    }
    let (signing, agreement) = (identity.public_key_hex(), identity.agreement_key_hex());
    let parts: [&[u8]; 7] = [
        b"{\"seed\":\"",
        &seed_hex[..],
        b"\",\"signing_pubkey\":\"",
        signing.as_bytes(),
        b"\",\"agreement_pubkey\":\"",
        agreement.as_bytes(),
        b"\"}",
    ];
    let mut json = zeroize::Zeroizing::new(Vec::with_capacity(
        parts.iter().map(|p| p.len()).sum::<usize>() + 1,
    ));
    for part in parts {
        json.extend_from_slice(part);
    }

    let mut guard = lock_state();
    guard.identity = Some(identity);

    // The buffer already has room for the NUL, so CString takes it over
    // without reallocating; it is the returned string, wiped by
    // `rchat_free_string`.
    match CString::new(std::mem::take(&mut *json)) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Generates a new identity, like `rchat_generate_identity`, but hands the
/// 64-byte seed out through `out` instead of a JSON string (I-8); the
/// core's copy is wiped. The public keys are then available from
/// `rchat_get_identity_pubkey` / `rchat_get_agreement_pubkey` (no client
/// yet). 1 written, -1 `out` is NULL or `len < 64`. The caller wipes `out`.
///
/// # Safety
///
/// `out` must be NULL or valid for writes of `len` bytes for the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_generate_identity_seed(out: *mut u8, len: usize) -> c_int {
    refuse_reentry!(-1);
    if out.is_null() || len < 64 {
        record_error(9, "Invalid parameter".into());
        return -1;
    }
    let identity = IdentityKeyPair::generate();
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    identity.write_seed(&mut seed);
    // SAFETY: `out` is non-null and the caller promises `len >= 64` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), out, 64) };
    lock_state().identity = Some(identity);
    1
}

#[no_mangle]
pub extern "C" fn rchat_get_identity_pubkey() -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    // The state lock is released before asking the client, which may wait
    // for its own lock (C-14).
    let (client, staged) = {
        let guard = lock_state();
        (
            guard.client.clone(),
            guard.identity.as_ref().map(|i| i.public_key_hex()),
        )
    };
    // Prefer the client's identity (it's what actually connects to the server)
    let hex_str = if let Some(client) = client {
        match client.get_identity() {
            Ok(s) => s,
            Err(e) => {
                record_rchat_error(&e, "No identity");
                return std::ptr::null_mut();
            }
        }
    } else if let Some(hex) = staged {
        hex
    } else {
        record_error(8, "No identity available".to_string());
        return std::ptr::null_mut();
    };
    match CString::new(hex_str) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rchat_get_agreement_pubkey() -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    // The state lock is released before asking the client, which may wait
    // for its own lock (C-14).
    let (client, staged) = {
        let guard = lock_state();
        (
            guard.client.clone(),
            guard.identity.as_ref().map(|i| i.agreement_key_hex()),
        )
    };
    // Prefer the client's agreement key (it's what actually connects to the server)
    let hex_str = if let Some(client) = client {
        match client.get_agreement_key() {
            Ok(s) => s,
            Err(e) => {
                record_rchat_error(&e, "No identity");
                return std::ptr::null_mut();
            }
        }
    } else if let Some(hex) = staged {
        hex
    } else {
        record_error(8, "No identity available".to_string());
        return std::ptr::null_mut();
    };
    match CString::new(hex_str) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_validate_identity(identity_content: *const c_char) -> c_int {
    let Some(content) = arg(identity_content).map(zeroize::Zeroizing::new) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    // Typed, with the seed wiped the moment it is read: a parse error after
    // it (a later field, bad syntax) frees no plain copy of it (R1-3).
    let fields = match serde_json::from_str::<IdentityFields>(content.as_str()) {
        Ok(f) => f,
        Err(_) => {
            // Which message: syntax, or a field of the wrong type.
            let syntax = serde_json::from_str::<serde::de::IgnoredAny>(content.as_str()).is_err();
            let why = if syntax {
                "Identity is not valid JSON"
            } else {
                "Identity is missing a key"
            };
            return record_error(1, why.to_string());
        }
    };
    let present = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());
    let seed_present = fields.seed.as_deref().is_some_and(|s| !s.is_empty());
    if !(seed_present && present(&fields.signing_pubkey) && present(&fields.agreement_pubkey)) {
        return record_error(1, "Identity is missing a key".to_string());
    }
    0
}

/// Register the C callbacks (all eleven are required). Receipts carry the
/// peer that sent them (`sender_hex`), so the app binds a receipt to the
/// contact the message went to. Key event codes use the
/// `rchat_peer_key_state` numbering (2 mismatch, 3 bad signature).
///
/// Every pointer must be non-NULL. Each parameter is an
/// `Option<extern "C" fn>` (the same ABI as a C function pointer, with NULL
/// as `None`), so a NULL is detected instead of being undefined behaviour:
/// if any is NULL, nothing is registered (any earlier registration stays)
/// and the call returns -1 with error code 9 (security review L-3).
///
/// Threading: every callback is invoked on the core's one dedicated
/// `rchat-callbacks` thread, in the order the events happened, and never
/// with the client's lock held. A callback must still never call any
/// `rchat_*` function synchronously (it would hold up every later callback
/// while it waits on the global state lock or the network); copy the
/// arguments (they are valid only for the call) and hop to another thread
/// or queue before touching the core or the UI.
///
/// `on_status_event(kind, peer_hex, message_id_hex, detail)` (11th, spec
/// §18.9 D40): `kind` 1-10 as `StatusEvent::parts`, with `""` for an
/// absent peer or id and 0 for no detail. Some events (`QueuedSendLost`,
/// `StateRestoreFailed`) are raised inside a connect while the client is
/// locked; they are only queued there, and reach this callback on the
/// callback thread after the lock is released, so a callback that obeys
/// the rule above cannot deadlock the connect.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn rchat_register_callbacks(
    on_message: Option<extern "C" fn(*const c_char, *const c_char, u64, *const c_char, c_int)>,
    on_state_change: Option<extern "C" fn(c_int)>,
    on_error: Option<extern "C" fn(*const c_char)>,
    on_circuit_established: Option<extern "C" fn(*const c_char, c_int)>,
    on_message_delivered: Option<extern "C" fn(*const c_char)>,
    on_reconnect: Option<extern "C" fn()>,
    on_peer_key_event: Option<extern "C" fn(*const c_char, c_int, *const c_char)>,
    on_message_request: Option<
        extern "C" fn(*const c_char, *const c_char, u64, *const c_char, *const c_char, u64, u32),
    >,
    on_message_receipt: Option<extern "C" fn(*const c_char, *const c_char, c_int)>,
    on_peer_rotated: Option<extern "C" fn(*const c_char, *const c_char, *const c_char, u32)>,
    on_status_event: Option<extern "C" fn(c_int, *const c_char, *const c_char, c_int)>,
) -> c_int {
    refuse_reentry!(-1);
    let (
        Some(on_message),
        Some(on_state_change),
        Some(on_error),
        Some(on_circuit_established),
        Some(on_message_delivered),
        Some(on_reconnect),
        Some(on_peer_key_event),
        Some(on_message_request),
        Some(on_message_receipt),
        Some(on_peer_rotated),
        Some(on_status_event),
    ) = (
        on_message,
        on_state_change,
        on_error,
        on_circuit_established,
        on_message_delivered,
        on_reconnect,
        on_peer_key_event,
        on_message_request,
        on_message_receipt,
        on_peer_rotated,
        on_status_event,
    )
    else {
        record_error(9, "A callback pointer is NULL".to_string());
        return -1;
    };
    let bridge = CCallbackBridge {
        ptrs: CCallbackPointers {
            on_message,
            on_state_change,
            on_error,
            on_circuit_established,
            on_message_delivered,
            on_reconnect,
            on_peer_key_event,
            on_message_request,
            on_message_receipt,
            on_peer_rotated,
            on_status_event,
        },
    };
    let client = {
        let mut guard = lock_state();
        guard.callbacks = Some(bridge.clone());
        guard.client.clone()
    };
    // If a client already exists, register the callbacks on it (outside the
    // state lock: `set_callbacks` may wait for the client's lock, C-14).
    if let Some(client) = client {
        client.set_callbacks(Box::new(bridge));
    }
    0
}

#[no_mangle]
pub extern "C" fn rchat_get_connection_state() -> c_int {
    refuse_reentry!(0);
    let guard = lock_state();
    if let Some(ref client) = guard.client {
        match client.get_connection_status() {
            ConnectionStatus::Disconnected => 0,
            ConnectionStatus::Connecting => 1,
            ConnectionStatus::Connected => 2,
            ConnectionStatus::Reconnecting { .. } => 3,
            ConnectionStatus::Error { .. } => 4,
        }
    } else {
        0
    }
}

/// Message of the most recent failing call on this thread (free with
/// `rchat_free_string`).
#[no_mangle]
pub extern "C" fn rchat_last_error() -> *mut c_char {
    let err = LAST_ERROR.with(|e| e.borrow().1.clone());
    match CString::new(err) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `ptr` must be NULL or a string returned by this library that has not
/// been freed yet; it must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn rchat_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Strings may carry secrets (the generated seed): wiped before the
        // allocation is freed (C-10).
        let mut bytes = unsafe { CString::from_raw(ptr) }.into_bytes_with_nul();
        zeroize::Zeroize::zeroize(&mut bytes);
    }
}

#[no_mangle]
pub extern "C" fn rchat_process_pending() -> c_int {
    refuse_reentry!(8);
    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => return record_error(7, "Not connected".to_string()),
    };
    drop(guard);

    match client.process_pending() {
        Ok(()) => 0,
        Err(e) => record_rchat_error(&e, "Process pending failed"),
    }
}

/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_has_session(recipient: *const c_char) -> c_int {
    refuse_reentry!(8);
    let Some(recipient_str) = arg(recipient) else {
        return record_error(9, "Invalid parameter".to_string());
    };

    let guard = lock_state();
    let client = match guard.client {
        Some(ref c) => c.clone(),
        None => return 0,
    };
    drop(guard);

    if client.has_session(recipient_str) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// ABI v2: pins, requests, intros, receipts (spec §4.5)
// ---------------------------------------------------------------------------

/// Return code for a pin refusal; also records the matching error code.
fn pin_code(e: PinError) -> c_int {
    match e {
        PinError::Conflict => {
            record_rchat_error(&RChatError::PinConflict, "Pin failed");
            -2
        }
        PinError::AgreementKeyInUse => {
            record_rchat_error(&RChatError::AgreementKeyInUse, "Pin failed");
            -4
        }
        PinError::RotationTooSoon => {
            record_rchat_error(&RChatError::RotationTooSoon, "Pin failed");
            -1
        }
    }
}

/// Pin (accept) a contact's agreement key. Works before `rchat_connect`
/// once `rchat_initialize` has run (the pin is staged and moved into the
/// client on connect). 0 ok, -1 invalid or blocked, -2 a different key is
/// pinned, -3 not initialised, -4 the key is pinned for another contact.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_pin_peer_key(
    identity_hex: *const c_char,
    agreement_hex: *const c_char,
) -> c_int {
    refuse_reentry!(-1);
    let Some((ak_hex, ak)) = arg(agreement_hex).and_then(|h| key_from_hex(&h).map(|k| (h, k)))
    else {
        record_error(9, "Invalid agreement key".to_string());
        return -1;
    };
    let (id, target) = match peer_target(identity_hex, true) {
        Ok(t) => t,
        Err(code) => return code,
    };
    match target {
        PeerTarget::Client(client) => match client.pin_peer_key(id, ak_hex) {
            Ok(()) => 0,
            Err(e @ RChatError::PinConflict) => {
                record_rchat_error(&e, "Pin failed");
                -2
            }
            Err(e @ RChatError::AgreementKeyInUse) => {
                record_rchat_error(&e, "Pin failed");
                -4
            }
            Err(e) => {
                record_rchat_error(&e, "Pin failed");
                -1
            }
        },
        PeerTarget::Staged(mut guard) => {
            if guard.staged.is_blocked(&id) {
                record_rchat_error(&RChatError::PeerBlocked { identity: id }, "Pin failed");
                return -1;
            }
            let new_pin = guard.staged.pin_for(&id).is_none();
            match guard.staged.pin(&id, ak) {
                Ok(()) => {
                    // As a live pin does: knocks no newer than this hour
                    // can't flag a mismatch (relay replay of an old key).
                    if new_pin {
                        guard.staged.set_pin_hour(&id, crate::circuits::now_hour());
                    }
                    0
                }
                Err(e) => pin_code(e),
            }
        }
    }
}

/// Forget a contact's pin. 0 ok, -1 invalid, -3 not initialised.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_unpin_peer_key(identity_hex: *const c_char) -> c_int {
    refuse_reentry!(-1);
    match peer_target(identity_hex, true) {
        Err(code) => code,
        Ok((id, PeerTarget::Client(client))) => match client.unpin_peer_key(id) {
            Ok(()) => 0,
            Err(e) => {
                record_rchat_error(&e, "Unpin failed");
                -1
            }
        },
        Ok((id, PeerTarget::Staged(mut guard))) => {
            guard.staged.unpin(&id);
            0
        }
    }
}

/// Block (non-zero) or unblock (0). Blocking also unpins.
/// 0 ok, -1 invalid, -3 not initialised.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_peer_blocked(
    identity_hex: *const c_char,
    blocked: c_int,
) -> c_int {
    refuse_reentry!(-1);
    match peer_target(identity_hex, true) {
        Err(code) => code,
        Ok((id, PeerTarget::Client(client))) => match client.set_peer_blocked(id, blocked != 0) {
            Ok(()) => 0,
            Err(e) => {
                record_rchat_error(&e, "Block failed");
                -1
            }
        },
        Ok((id, PeerTarget::Staged(mut guard))) => {
            guard.staged.set_blocked(&id, blocked != 0);
            0
        }
    }
}

/// 0 none, 1 pinned, 2 mismatch, 3 bad signature, 4 blocked; -1 invalid;
/// -5 the client stayed busy for a short wait (last error 8): the state is
/// unknown, so treat the peer as not sendable and ask again (N-8). Waits at
/// most ~250 ms.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_peer_key_state(identity_hex: *const c_char) -> c_int {
    refuse_reentry!(-5);
    match peer_target(identity_hex, false) {
        Err(code) => code,
        Ok((id, PeerTarget::Client(client))) => match client.peer_key_state_checked(id) {
            Some(state) => c_int::from(state),
            None => {
                record_error(8, "Client busy".to_string());
                -5
            }
        },
        Ok((id, PeerTarget::Staged(guard))) => guard.staged.state(&id) as c_int,
    }
}

/// Ask for a circuit with an accepted contact. 0 ok, else an error code.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_request_circuit(identity_hex: *const c_char) -> c_int {
    refuse_reentry!(8);
    let Some(id) = arg(identity_hex) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.request_circuit(id) {
        Ok(()) => 0,
        Err(e) => record_rchat_error(&e, "Request failed"),
    }
}

/// Queue a first message that travels sealed inside knocks. Returns the
/// 32-hex intro id (free with `rchat_free_string`), or NULL; the code is
/// in `rchat_last_error_code`.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_intro(
    identity_hex: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let (Some(id), Some(text)) = (arg(identity_hex), arg(text)) else {
        record_error(9, "Invalid parameter".to_string());
        return std::ptr::null_mut();
    };
    let Ok(client) = client_or_7() else {
        return std::ptr::null_mut();
    };
    match client.set_intro(id, text).map(CString::new) {
        Ok(Ok(intro_id)) => intro_id.into_raw(),
        Ok(Err(_)) => {
            record_error(8, "Intro id contained NUL".to_string());
            std::ptr::null_mut()
        }
        Err(e) => {
            record_rchat_error(&e, "Intro refused");
            std::ptr::null_mut()
        }
    }
}

/// `rchat_set_intro` under a caller-chosen 32-hex id (an intro re-armed
/// after a relaunch keeps the id it was first given). Returns the id (free
/// with `rchat_free_string`), or NULL; the code is in `rchat_last_error_code`.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_intro_with_id(
    identity_hex: *const c_char,
    text: *const c_char,
    message_id_hex: *const c_char,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let (Some(id), Some(text), Some(message_id)) =
        (arg(identity_hex), arg(text), arg(message_id_hex))
    else {
        record_error(9, "Invalid parameter".to_string());
        return std::ptr::null_mut();
    };
    let Ok(client) = client_or_7() else {
        return std::ptr::null_mut();
    };
    match client
        .set_intro_with_id(id, text, message_id)
        .map(CString::new)
    {
        Ok(Ok(intro_id)) => intro_id.into_raw(),
        Ok(Err(_)) => {
            record_error(8, "Intro id contained NUL".to_string());
            std::ptr::null_mut()
        }
        Err(e) => {
            record_rchat_error(&e, "Intro refused");
            std::ptr::null_mut()
        }
    }
}

/// Send a text message under a caller-chosen 32-hex id (an accepted
/// intro's id). 0 ok, else an error code.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_message_using_id(
    recipient_hex: *const c_char,
    text: *const c_char,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(recipient), Some(text), Some(id)) =
        (arg(recipient_hex), arg(text), arg(message_id_hex))
    else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.send_text_message_using_id(recipient, text, id) {
        Ok(_) => 0,
        Err(e) => record_rchat_error(&e, "Send failed"),
    }
}

/// Send media (a body `rchat_send_binary_with_id` accepts) under a
/// caller-chosen 32-hex id: the app's same-id resend (spec §18.6 D38).
/// It takes the same path as every send (`send_payload`, where the sealed
/// id is recorded as sent). Returns as `rchat_send_message_using_id`: 0 ok,
/// else an error code (9 for a NULL argument, an empty or unknown body).
///
/// # Safety
///
/// `recipient_hex` and `message_id_hex` must be NULL or NUL-terminated
/// strings, and `data` NULL or valid for reads of `len` bytes; all stay
/// valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_binary_using_id(
    recipient_hex: *const c_char,
    data: *const u8,
    len: usize,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(recipient), Some(id)) = (arg(recipient_hex), arg(message_id_hex)) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let body = match unsafe { binary_body(data, len) } {
        Ok(b) => b,
        Err(code) => return code,
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.send_binary_message_using_id(recipient, body, id) {
        Ok(_) => 0,
        Err(e) => record_rchat_error(&e, "Send failed"),
    }
}

/// The automatic resend of a `ResendEligible` text (spec §18.6 D38, final
/// review H-1): like `rchat_send_message_using_id`, but refused with code
/// 26 unless the current session is the one that made the id eligible, the
/// contact is still plainly pinned and the D38 guards on the sent entry
/// still hold. On 26 the app offers its manual Resend row instead.
///
/// # Safety
///
/// As `rchat_send_message_using_id`.
#[no_mangle]
pub unsafe extern "C" fn rchat_resend_message_using_id(
    recipient_hex: *const c_char,
    text: *const c_char,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(recipient), Some(text), Some(id)) =
        (arg(recipient_hex), arg(text), arg(message_id_hex))
    else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.resend_text_message_using_id(recipient, text, id) {
        Ok(_) => 0,
        Err(e) => record_rchat_error(&e, "Resend failed"),
    }
}

/// `rchat_resend_message_using_id` for a binary (media) message.
///
/// # Safety
///
/// As `rchat_send_binary_using_id`.
#[no_mangle]
pub unsafe extern "C" fn rchat_resend_binary_using_id(
    recipient_hex: *const c_char,
    data: *const u8,
    len: usize,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(recipient), Some(id)) = (arg(recipient_hex), arg(message_id_hex)) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let body = match unsafe { binary_body(data, len) } {
        Ok(b) => b,
        Err(code) => return code,
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.resend_binary_message_using_id(recipient, body, id) {
        Ok(_) => 0,
        Err(e) => record_rchat_error(&e, "Resend failed"),
    }
}

/// The app has durably stored this message (or deliberately dropped it as
/// outside its limits), or already has it (a duplicate, an accepted
/// intro). "Delivered" means stored (spec §18.7 D36): the delivered receipt
/// is queued now, never at decrypt, and a later ratchet copy is decrypted to
/// stay in step but not delivered again. Call it after the store succeeds
/// and on the duplicate path, never when the store failed. 0 ok, else an
/// error code (25 when the state could not be written: call it again).
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_mark_message_seen(
    sender_hex: *const c_char,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(sender), Some(id)) = (arg(sender_hex), arg(message_id_hex)) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.mark_message_seen(sender, id) {
        Ok(()) => 0,
        Err(e) => record_rchat_error(&e, "Mark seen failed"),
    }
}

/// Send an end-to-end encrypted read receipt (replaces
/// `rchat_send_delivery_receipt`). Delivered receipts are not sent from
/// here: the core queues one when the app calls `rchat_mark_message_seen`
/// after storing the message (spec §18.7 D36).
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_send_read_receipt(
    sender_hex: *const c_char,
    message_id_hex: *const c_char,
) -> c_int {
    refuse_reentry!(8);
    let (Some(sender), Some(id)) = (arg(sender_hex), arg(message_id_hex)) else {
        return record_error(9, "Invalid parameter".to_string());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return code,
    };
    match client.send_read_receipt(sender, vec![id]) {
        Ok(()) => 0,
        Err(e) => record_rchat_error(&e, "Read receipt failed"),
    }
}

/// Code of the most recent failing call on this thread (0 if none yet).
/// Read it on the thread that made the call, right after it.
#[no_mangle]
pub extern "C" fn rchat_last_error_code() -> c_int {
    last_error_code()
}

// ---------------------------------------------------------------------------
// Safety numbers, key versions, rotation, relay pin, cover traffic (T34)
// ---------------------------------------------------------------------------

/// A 64-hex key argument, or None for NULL / bad UTF-8 / anything else.
///
/// # Safety
///
/// As `arg`.
unsafe fn hex32_arg(p: *const c_char) -> Option<[u8; 32]> {
    arg(p).as_deref().and_then(key_from_hex)
}

/// The contact's 60-digit safety number (spec §4.7). Works before
/// `rchat_connect` (from the staged pins); the app passes its own public
/// keys for that case. NULL with last error 19 (nothing pinned), 9 (bad
/// argument or not initialised) or 7.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_safety_number(
    peer_ik_hex: *const c_char,
    my_ik_hex: *const c_char,
    my_ak_hex: *const c_char,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let (Some(my_ik), Some(my_ak)) = (hex32_arg(my_ik_hex), hex32_arg(my_ak_hex)) else {
        record_error(9, "Invalid parameter".into());
        return std::ptr::null_mut();
    };
    // `peer_target` records its own code (9 invalid, 8 not initialised);
    // it is never overwritten (Task 20b minor).
    let Ok((id, target)) = peer_target(peer_ik_hex, true) else {
        return std::ptr::null_mut();
    };
    let result = match target {
        PeerTarget::Client(client) => client.safety_number(id.clone()),
        PeerTarget::Staged(guard) => guard
            .staged
            .safety_number(&id, &my_ik, &my_ak)
            .map_err(|e| crate::sn_error(e, &id)),
    };
    match result.map(CString::new) {
        Ok(Ok(s)) => s.into_raw(),
        Ok(Err(_)) => {
            record_error(8, "Safety number contained NUL".into());
            std::ptr::null_mut()
        }
        Err(e) => {
            record_rchat_error(&e, "Safety number");
            std::ptr::null_mut()
        }
    }
}

/// Record that the user compared `digits` with the contact. 0 ok, -1
/// invalid, -2 nothing pinned, -3 not initialised, -5 the number changed.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_mark_safety_number_compared(
    peer_ik_hex: *const c_char,
    my_ik_hex: *const c_char,
    my_ak_hex: *const c_char,
    digits: *const c_char,
) -> c_int {
    refuse_reentry!(-1);
    let (Some(my_ik), Some(my_ak), Some(digits)) =
        (hex32_arg(my_ik_hex), hex32_arg(my_ak_hex), arg(digits))
    else {
        record_error(9, "Invalid parameter".into());
        return -1;
    };
    let (id, target) = match peer_target(peer_ik_hex, true) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let result = match target {
        PeerTarget::Client(client) => client.mark_safety_number_compared(id, digits),
        PeerTarget::Staged(mut guard) => guard
            .staged
            .mark_safety_number_compared(&id, &my_ik, &my_ak, &digits)
            .map_err(|e| crate::sn_error(e, &id)),
    };
    match result {
        Ok(()) => 0,
        Err(e @ RChatError::SafetyNumberChanged) => {
            record_rchat_error(&e, "Mark compared");
            -5
        }
        Err(e @ RChatError::NoPinnedKeys { .. }) => {
            record_rchat_error(&e, "Mark compared");
            -2
        }
        Err(e) => {
            record_rchat_error(&e, "Mark compared");
            -1
        }
    }
}

/// Compare a scanned `sn:1:` code with the contact's safety number (D22).
/// 1 match, 0 mismatch, -1 not a safety-number code or bad argument, -2
/// nothing pinned, -3 not initialised. Only 1 may enable "Mark as compared".
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_compare_safety_number_qr(
    peer_ik_hex: *const c_char,
    my_ik_hex: *const c_char,
    my_ak_hex: *const c_char,
    scanned: *const c_char,
) -> c_int {
    refuse_reentry!(-1);
    use crate::safety_number::ScanComparison;
    let (Some(my_ik), Some(my_ak), Some(scanned)) =
        (hex32_arg(my_ik_hex), hex32_arg(my_ak_hex), arg(scanned))
    else {
        record_error(9, "Invalid parameter".into());
        return -1;
    };
    let (id, target) = match peer_target(peer_ik_hex, true) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let result = match target {
        PeerTarget::Client(client) => client.compare_scanned_safety_number(id, scanned),
        PeerTarget::Staged(guard) => guard
            .staged
            .compare_scanned_safety_number(&id, &my_ik, &my_ak, &scanned)
            .map_err(|e| crate::sn_error(e, &id)),
    };
    // Every failure records its code (Task 20b minor); -2 is only "nothing
    // pinned", other errors are -1.
    match result {
        Ok(ScanComparison::Match) => 1,
        Ok(ScanComparison::Mismatch) => 0,
        Ok(ScanComparison::Invalid) => {
            record_error(9, "Not a safety-number code".into());
            -1
        }
        Err(e @ RChatError::NoPinnedKeys { .. }) => {
            record_rchat_error(&e, "Compare safety number");
            -2
        }
        Err(e) => {
            record_rchat_error(&e, "Compare safety number");
            -1
        }
    }
}

/// The pinned key version of a contact (QR card `"kv"`, accepted request).
/// 0 ok, -1 invalid, -2 nothing pinned, -3 not initialised.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_peer_key_version(
    identity_hex: *const c_char,
    version: u32,
) -> c_int {
    refuse_reentry!(-1);
    match peer_target(identity_hex, true) {
        Err(code) => code,
        Ok((id, PeerTarget::Client(client))) => match client.set_peer_key_version(id, version) {
            Ok(()) => 0,
            Err(e @ RChatError::NoPinnedKeys { .. }) => {
                record_rchat_error(&e, "Key version");
                -2
            }
            Err(e) => {
                record_rchat_error(&e, "Key version");
                -1
            }
        },
        Ok((id, PeerTarget::Staged(mut guard))) => {
            if guard.staged.pin_for(&id).is_none() {
                drop(guard);
                record_rchat_error(&RChatError::NoPinnedKeys { identity: id }, "Key version");
                return -2;
            }
            guard.staged.set_pin_version(&id, version);
            0
        }
    }
}

/// Prepare a key rotation (spec §4.8): JSON `{"new_version","links",
/// "new_identity","new_agreement"}` without the seed (take it with
/// `rchat_take_rotation_seed`), or NULL with last error 24 / 7.
#[no_mangle]
pub extern "C" fn rchat_prepare_rotation() -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let Ok(client) = client_or_7() else {
        return std::ptr::null_mut();
    };
    match client.prepare_rotation().map(CString::new) {
        Ok(Ok(json)) => json.into_raw(),
        Ok(Err(_)) => std::ptr::null_mut(),
        Err(e) => {
            record_rchat_error(&e, "Rotation refused");
            std::ptr::null_mut()
        }
    }
}

/// Copy the prepared rotation seed into `out` (64 bytes) once (spec §4.8,
/// L4); the core's copy is zeroized. 1 written, 0 nothing prepared (or no
/// client), -1 `out` is NULL or `len < 64`. The caller zeroes `out` after use.
///
/// # Safety
///
/// `out` must be NULL or valid for writes of `len` bytes for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_take_rotation_seed(out: *mut u8, len: usize) -> c_int {
    refuse_reentry!(-1);
    if out.is_null() || len < 64 {
        record_error(9, "Invalid parameter".into());
        return -1;
    }
    let Some(client) = lock_state().client.clone() else {
        return 0;
    };
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    if !client.take_rotation_seed(&mut seed) {
        return 0;
    }
    // SAFETY: `out` is non-null and the caller promises `len >= 64` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), out, 64) };
    1
}

/// The canonical relay origin (spec §4.9, L2): the key for saved relay pins.
/// Pure: needs neither `rchat_initialize` nor a client. NULL (last error 9)
/// for an invalid address.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_canonical_origin(server_url: *const c_char) -> *mut c_char {
    let Some(url) = arg(server_url) else {
        record_error(9, "Invalid parameter".into());
        return std::ptr::null_mut();
    };
    match crate::relay_pin::canonical_origin(&url).map(CString::new) {
        Ok(Ok(s)) if !s.as_bytes().is_empty() => s.into_raw(),
        _ => {
            record_error(9, "Invalid relay address".into());
            std::ptr::null_mut()
        }
    }
}

/// Send the rotation notice over every live circuit (spec §4.8). `links_hex`
/// is the `links` from `rchat_prepare_rotation`. Notices sent (>= 0), or the
/// negated error code.
///
/// # Safety
///
/// Every non-NULL pointer argument must point to a NUL-terminated string
/// that stays valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_announce_rotation(links_hex: *const c_char) -> c_int {
    refuse_reentry!(-8);
    let Some(links) = arg(links_hex) else {
        return -record_error(9, "Invalid parameter".into());
    };
    let client = match client_or_7() {
        Ok(c) => c,
        Err(code) => return -code,
    };
    match client.announce_rotation(links) {
        Ok(n) => c_int::try_from(n).unwrap_or(c_int::MAX),
        Err(e) => -record_rchat_error(&e, "Announce failed"),
    }
}

/// The relay identity accepted on this connection, as JSON
/// `{"origin","pin","version","source"}`, or NULL (no client, or no checked
/// relay identity yet).
#[no_mangle]
pub extern "C" fn rchat_relay_pin_info() -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    let Some(client) = lock_state().client.clone() else {
        return std::ptr::null_mut();
    };
    match client.relay_pin_info().map(CString::new) {
        Some(Ok(json)) => json.into_raw(),
        _ => std::ptr::null_mut(),
    }
}

/// Cover traffic on/off and whether the app is in the foreground (spec
/// §5.7, D19). Kept until `rchat_connect` when there is no client. Always 0.
#[no_mangle]
pub extern "C" fn rchat_set_cover_traffic(enabled: c_int, foreground: c_int) -> c_int {
    refuse_reentry!(8);
    let (on, fg) = (enabled != 0, foreground != 0);
    let client = {
        let mut guard = lock_state();
        guard.cover = (on, fg);
        guard.client.clone()
    };
    if let Some(client) = client {
        client.set_cover_traffic(on, fg);
    }
    0
}

// ---------------------------------------------------------------------------
// Session state store (spec §18.4 D27)
// ---------------------------------------------------------------------------

/// At most this many records are staged between connects: one per contact
/// plus the meta record, the same order as `MAX_SENT_IDS`.
pub const MAX_STAGED_RECORDS: usize = 4096;

/// Hand the core its 32-byte state key and the writer it persists sealed
/// session records through. Call after `rchat_initialize` and before
/// `rchat_connect`; a live client takes the store at once. The key is
/// copied into a wiped buffer; the caller wipes its own copy. The store
/// lasts until `rchat_disconnect` (which drops it: it belongs to one
/// account) and is kept by `rchat_reconnect`. 0 ok, -1 invalid (NULL key or
/// writer, `key_len != 32`; code 9), -3 not initialised (code 8).
///
/// `write` is called synchronously with the core's state locked
/// (`StateWriteFn`): it must never call an `rchat_*` function.
///
/// # Safety
///
/// `key` must be NULL or valid for reads of `key_len` bytes for the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_set_state_store(
    key: *const u8,
    key_len: usize,
    write: Option<StateWriteFn>,
) -> c_int {
    refuse_reentry!(-1);
    let (Some(write), false, 32) = (write, key.is_null(), key_len) else {
        record_error(9, "Invalid parameter".to_string());
        return -1;
    };
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    // SAFETY: non-null and 32 readable bytes per the contract.
    k.copy_from_slice(unsafe { std::slice::from_raw_parts(key, 32) });
    let mut g = lock_state();
    if g.runtime.is_none() {
        record_error(
            8,
            "Runtime not initialized. Call rchat_initialize() first.".to_string(),
        );
        return -3;
    }
    g.state_key = Some(k.clone());
    g.state_write = Some(write);
    let client = g.client.clone();
    // Read under the state lock: a disconnect after this is seen by the sink.
    let generation = DISCONNECT_GENERATION.load(Ordering::SeqCst);
    drop(g);
    // Outside the state lock: the client waits for its own lock.
    if let Some(client) = client {
        client.set_state_store(&k, Arc::new(CStateSink { write, generation }));
        keep_store_only_if_current(&client, generation);
    }
    0
}

/// After `set_state_store` on `client` outside the state lock: if a
/// disconnect ran meanwhile, or a new connect replaced `client`, the store
/// just set would outlive the detach that retired it. Detach it again.
fn keep_store_only_if_current(client: &Arc<RChatClient>, generation: u64) {
    let current = {
        let g = lock_state();
        DISCONNECT_GENERATION.load(Ordering::SeqCst) == generation
            && g.client.as_ref().is_some_and(|c| Arc::ptr_eq(c, client))
    };
    if !current {
        client.detach_state_store();
    }
}

/// Stage one stored record (`<record_key>.rcs` as the app read it) for the
/// next `rchat_connect`, which opens it. Call once per record after
/// `rchat_set_state_store`, before every `rchat_connect`: a connect takes
/// every staged record, whether or not it succeeds. The bytes are copied.
/// 0 ok, -1 invalid (NULL or malformed key, NULL `sealed`, `len == 0`;
/// code 9), -2 larger than `MAX_RECORD_BYTES` (2 MiB; code 9, checked
/// before the buffer is read) or `MAX_STAGED_RECORDS` already staged
/// (code 9), -3 not initialised (code 8).
///
/// # Safety
///
/// `record_key` must be NULL or a NUL-terminated string, and `sealed` NULL
/// or valid for reads of `len` bytes, for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_import_state_record(
    record_key: *const c_char,
    sealed: *const u8,
    len: usize,
) -> c_int {
    refuse_reentry!(-1);
    let Some(key) = arg(record_key).filter(|k| crate::state_store::is_valid_record_key(k)) else {
        record_error(9, "Invalid record key".to_string());
        return -1;
    };
    if sealed.is_null() || len == 0 {
        record_error(9, "Invalid parameter".to_string());
        return -1;
    }
    // Before anything reads the buffer (Task 2 carry-over).
    if len > crate::state_store::MAX_RECORD_BYTES {
        record_error(9, "Record too large".to_string());
        return -2;
    }
    let mut g = lock_state();
    if g.runtime.is_none() {
        record_error(
            8,
            "Runtime not initialized. Call rchat_initialize() first.".to_string(),
        );
        return -3;
    }
    if g.staged_records.len() >= MAX_STAGED_RECORDS {
        record_error(9, "Too many staged records".to_string());
        return -2;
    }
    // SAFETY: non-null and `len` (≤ 2 MiB) readable bytes per the contract.
    let bytes = unsafe { std::slice::from_raw_parts(sealed, len) }.to_vec();
    g.staged_records.push((key, bytes));
    0
}

/// Forget every staged record and every session of the live client, in
/// memory (Reset Identity, our own rotation). Touches no file: the app
/// deletes its record directory. Always 0.
#[no_mangle]
pub extern "C" fn rchat_clear_state() -> c_int {
    refuse_reentry!(8);
    let client = {
        let mut g = lock_state();
        g.staged_records.clear();
        // Reset Identity: the loaded identity's secret goes too, wiped on drop.
        g.identity = None;
        g.client.clone()
    };
    if let Some(client) = client {
        client.clear_state();
    }
    0
}

// ---------------------------------------------------------------------------
// Device key (spec §18.14 D43-D45)
// ---------------------------------------------------------------------------

/// Register the device-key signer that signs our session notices (D45).
/// Applied to the live client and to every client a later `rchat_connect`
/// builds; kept across `rchat_disconnect`. `sign` is synchronous, called
/// with the core locked (`DeviceSignFn`): it must not call into rchat. A
/// signer that fails leaves the notice unsigned. 0 ok, -1 NULL (code 9),
/// -3 not initialised (code 8).
#[no_mangle]
pub extern "C" fn rchat_set_device_signer(sign: Option<DeviceSignFn>) -> c_int {
    refuse_reentry!(-1);
    let Some(sign) = sign else {
        record_error(9, "Invalid parameter".to_string());
        return -1;
    };
    let mut g = lock_state();
    if g.runtime.is_none() {
        record_error(
            8,
            "Runtime not initialized. Call rchat_initialize() first.".to_string(),
        );
        return -3;
    }
    g.device_signer = Some(CDeviceSigner(sign));
    let client = g.client.clone();
    drop(g);
    if let Some(c) = client {
        c.set_device_signer(Arc::new(CDeviceSigner(sign)));
    }
    0
}

/// Our identity's signature binding this install's device key `dk_pub`
/// (65-byte uncompressed P-256 point; `hardware` non-zero for a Secure
/// Enclave or StrongBox key): the card's 128-hex `dks` (D43), freed with
/// `rchat_free_string`. Signed by the client's identity, or before the
/// first connect by the identity `rchat_generate_identity(_seed)` loaded;
/// no connection is needed. NULL on failure: 9 bad arguments or an invalid
/// key, 7 no identity loaded.
///
/// # Safety
///
/// `dk_pub` must be NULL or valid for reads of `len` bytes for the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_device_key_binding(
    dk_pub: *const u8,
    len: usize,
    hardware: c_int,
) -> *mut c_char {
    refuse_reentry!(std::ptr::null_mut());
    if dk_pub.is_null() || len != 65 {
        record_error(9, "Invalid parameter".to_string());
        return std::ptr::null_mut();
    }
    let mut dk = [0u8; 65];
    // SAFETY: non-null and 65 readable bytes per the contract.
    dk.copy_from_slice(unsafe { std::slice::from_raw_parts(dk_pub, 65) });
    let hardware = hardware != 0;
    // The binding is a local signature by the identity: the client's once
    // it has one, else the identity generated before the first connect
    // (onboarding shows its card before connecting). Signed under the
    // state lock, which `sign_device_key` never re-takes.
    let (client, staged) = {
        let g = lock_state();
        let staged = g
            .identity
            .as_ref()
            .map(|i| crate::keyauth::sign_device_key(i, &dk, hardware));
        (g.client.clone(), staged)
    };
    let from_client = client.map(|c| c.device_key_binding(dk, hardware));
    let signed = match (from_client, staged) {
        (Some(Ok(sig)), _) => sig,
        (Some(Err(RChatError::NotConnected)) | None, Some(Ok(sig))) => sig,
        (Some(Err(RChatError::NotConnected)) | None, Some(Err(_))) => {
            record_error(9, "Invalid parameter".to_string());
            return std::ptr::null_mut();
        }
        (Some(Err(RChatError::NotConnected)) | None, None) => {
            record_error(7, "No identity loaded".to_string());
            return std::ptr::null_mut();
        }
        (Some(Err(e)), _) => {
            record_rchat_error(&e, "Device key binding failed");
            return std::ptr::null_mut();
        }
    };
    CString::new(hex::encode(signed))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Pin a contact's device key from their scanned or pasted card, or restore
/// one the app stored from such a scan (D44): `dk_hex` the 130-hex key,
/// `dks_hex` the 128-hex binding signed by the identity, `hardware` the
/// card's flag (covered by the signature). Only the app's scan, paste and
/// restore paths may call this; nothing received over the network does.
///
/// The contact's agreement key must be pinned first (`rchat_pin_peer_key`).
/// Like pins, DK pins live in memory only: before every `rchat_connect`
/// the app re-stages each stored DK pin (after its agreement-key pin), and
/// they are moved into the client with the pins.
///
/// 0 ok, -1 invalid argument or a binding that does not verify (code 9;
/// any other refusal from a live client records its own code), -2
/// identity not pinned (code 12, as the brief fixes it), -3 not
/// initialised (code 8).
///
/// # Safety
///
/// Every non-NULL pointer must be a NUL-terminated string valid for the call.
#[no_mangle]
pub unsafe extern "C" fn rchat_pin_device_key(
    identity_hex: *const c_char,
    dk_hex: *const c_char,
    hardware: c_int,
    dks_hex: *const c_char,
) -> c_int {
    refuse_reentry!(-1);
    let parsed = (|| {
        let id = arg(identity_hex)?.to_lowercase();
        let ik = key_from_hex(&id)?;
        let dk: [u8; 65] = hex::decode(arg(dk_hex)?).ok()?.try_into().ok()?;
        let dks: [u8; 64] = hex::decode(arg(dks_hex)?).ok()?.try_into().ok()?;
        Some((id, ik, dk, dks))
    })();
    let Some((id, ik, dk, dks)) = parsed else {
        record_error(9, "Invalid parameter".to_string());
        return -1;
    };
    let hardware = hardware != 0;
    // The binding first, for both paths (`RChatClient::pin_device_key`
    // checks in this order too), so its refusal has its own message.
    if crate::keyauth::verify_device_key(&ik, &dk, hardware, &dks).is_err() {
        record_error(9, "Device key signature invalid".to_string());
        return -1;
    }
    let mut g = lock_state();
    if g.runtime.is_none() {
        record_error(
            8,
            "Runtime not initialized. Call rchat_initialize() first.".to_string(),
        );
        return -3;
    }
    let Some(client) = g.client.clone() else {
        // No client yet: staged like `rchat_pin_peer_key`, with the pin
        // check `RChatClient::pin_device_key` makes.
        if g.staged.pin_for(&id).is_none() {
            record_error(12, "Identity not pinned".to_string());
            return -2;
        }
        g.staged.pin_device_key(
            &id,
            crate::device_key::DevicePin {
                dk_pub: dk,
                hardware,
            },
        );
        return 0;
    };
    drop(g);
    match client.pin_device_key(id, dk, hardware, dks) {
        Ok(()) => 0,
        Err(RChatError::PinConflict) => {
            record_error(12, "Identity not pinned".to_string());
            -2
        }
        Err(e) => {
            record_rchat_error(&e, "Device key refused");
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// GLOBAL_STATE is process-wide; FFI tests run one at a time.
    static FFI_TEST_LOCK: StdMutex<()> = StdMutex::new(());
    static CALLS: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }
    fn s(p: *const c_char) -> String {
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string()
    }
    fn record(line: String) {
        CALLS.lock().unwrap().push(line);
    }

    extern "C" fn t_on_message(
        sender: *const c_char,
        text: *const c_char,
        ts: u64,
        id: *const c_char,
        kind: c_int,
    ) {
        record(format!(
            "msg {} {} {} {} k{kind}",
            s(sender),
            s(text),
            ts,
            s(id)
        ));
    }
    static STATE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    extern "C" fn t_on_state(_: c_int) {
        STATE_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    extern "C" fn t_on_error(_: *const c_char) {}
    extern "C" fn t_on_circuit(_: *const c_char, _: c_int) {}
    extern "C" fn t_on_delivered(_: *const c_char) {}
    extern "C" fn t_on_reconnect() {}
    extern "C" fn t_on_key(id: *const c_char, code: c_int, ak: *const c_char) {
        record(format!("key {} {} {}", s(id), code, s(ak)));
    }
    extern "C" fn t_on_request(
        id: *const c_char,
        ak: *const c_char,
        hour: u64,
        iid: *const c_char,
        text: *const c_char,
        at: u64,
        kv: u32,
    ) {
        record(format!(
            "req {} {} {} [{}] [{}] {} kv{}",
            s(id),
            s(ak),
            hour,
            s(iid),
            s(text),
            at,
            kv
        ));
    }
    extern "C" fn t_on_rotated(old: *const c_char, new: *const c_char, ak: *const c_char, v: u32) {
        record(format!("rot {} {} {} {}", s(old), s(new), s(ak), v));
    }
    extern "C" fn t_on_receipt(sender: *const c_char, id: *const c_char, kind: c_int) {
        record(format!("rcpt {} {} {}", s(sender), s(id), kind));
    }
    extern "C" fn t_on_status(_: c_int, _: *const c_char, _: *const c_char, _: c_int) {}

    fn bridge() -> CCallbackBridge {
        CCallbackBridge {
            ptrs: CCallbackPointers {
                on_message: t_on_message,
                on_state_change: t_on_state,
                on_error: t_on_error,
                on_circuit_established: t_on_circuit,
                on_message_delivered: t_on_delivered,
                on_reconnect: t_on_reconnect,
                on_peer_key_event: t_on_key,
                on_message_request: t_on_request,
                on_message_receipt: t_on_receipt,
                on_peer_rotated: t_on_rotated,
                on_status_event: t_on_status,
            },
        }
    }

    /// Pointers that do nothing with what they get (bar `CALLS` records).
    fn noop_pointers() -> CCallbackPointers {
        bridge().ptrs
    }

    const ID_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const ID_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";
    const AK_1: &str = "0100000000000000000000000000000000000000000000000000000000000001";
    const AK_2: &str = "0200000000000000000000000000000000000000000000000000000000000002";

    /// Security review L-3: a NULL callback pointer is refused (-1, code
    /// 9) and registers nothing, leaving any earlier registration in place;
    /// a full set registers (0).
    #[test]
    fn register_callbacks_refuses_null_pointers() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved = lock_state().callbacks.take();
        let all = || {
            (
                Some(t_on_message as extern "C" fn(_, _, _, _, _)),
                Some(t_on_state as extern "C" fn(_)),
                Some(t_on_error as extern "C" fn(_)),
                Some(t_on_circuit as extern "C" fn(_, _)),
                Some(t_on_delivered as extern "C" fn(_)),
                Some(t_on_reconnect as extern "C" fn()),
                Some(t_on_key as extern "C" fn(_, _, _)),
                Some(t_on_request as extern "C" fn(_, _, _, _, _, _, _)),
                Some(t_on_receipt as extern "C" fn(_, _, _)),
                Some(t_on_rotated as extern "C" fn(_, _, _, _)),
                Some(t_on_status as extern "C" fn(_, _, _, _)),
            )
        };
        let (m, st, e, ci, d, r, k, rq, rc, ro, se) = all();
        // Each position NULL in turn.
        for null_at in 0..11 {
            let code = rchat_register_callbacks(
                m.filter(|_| null_at != 0),
                st.filter(|_| null_at != 1),
                e.filter(|_| null_at != 2),
                ci.filter(|_| null_at != 3),
                d.filter(|_| null_at != 4),
                r.filter(|_| null_at != 5),
                k.filter(|_| null_at != 6),
                rq.filter(|_| null_at != 7),
                rc.filter(|_| null_at != 8),
                ro.filter(|_| null_at != 9),
                se.filter(|_| null_at != 10),
            );
            assert_eq!(code, -1, "NULL at {null_at} refused");
            assert_eq!(rchat_last_error_code(), 9);
            assert!(lock_state().callbacks.is_none(), "nothing registered");
        }
        assert_eq!(
            rchat_register_callbacks(m, st, e, ci, d, r, k, rq, rc, ro, se),
            0
        );
        assert!(lock_state().callbacks.is_some());
        assert_eq!(
            rchat_register_callbacks(None, st, e, ci, d, r, k, rq, rc, ro, se),
            -1
        );
        assert!(
            lock_state().callbacks.is_some(),
            "a refused call keeps the earlier registration"
        );
        lock_state().callbacks = saved;
    }

    /// R1-3: the identity check and the connect config read the seed into
    /// a wiped buffer on its own; every outcome is still reported as before.
    #[test]
    fn seed_json_error_paths_keep_their_codes() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let seed = "ab".repeat(64);
        let check = |json: String| unsafe { rchat_validate_identity(c(&json).as_ptr()) };
        let ok = format!(r#"{{"seed":"{seed}","signing_pubkey":"aa","agreement_pubkey":"bb"}}"#);
        assert_eq!(check(ok), 0);
        // Seed read, then bad syntax.
        assert_eq!(check(format!(r#"{{"seed":"{seed}","signing_pubkey":"#)), 1);
        assert!(LAST_ERROR
            .with(|e| e.borrow().1.clone())
            .contains("not valid JSON"));
        // Seed read, then a field of the wrong type.
        assert_eq!(
            check(format!(
                r#"{{"seed":"{seed}","signing_pubkey":5,"agreement_pubkey":"bb"}}"#
            )),
            1
        );
        assert!(LAST_ERROR
            .with(|e| e.borrow().1.clone())
            .contains("missing a key"));
        assert_eq!(
            check(format!(r#"{{"seed":"{seed}","agreement_pubkey":"bb"}}"#)),
            1
        );
        assert_eq!(
            check(r#"{"seed":"","signing_pubkey":"a","agreement_pubkey":"b"}"#.into()),
            1
        );

        // A config whose seed parses but a later field doesn't.
        assert_eq!(rchat_initialize(), 0);
        let bad = c(&format!(
            r#"{{"server_url":"ws://127.0.0.1:9","identity_key_seed":"{seed}","connection_timeout_secs":"x"}}"#
        ));
        assert_eq!(unsafe { rchat_connect(bad.as_ptr()) }, 1);
        assert!(LAST_ERROR
            .with(|e| e.borrow().1.clone())
            .contains("Invalid config JSON"));
        rchat_disconnect();
    }

    /// Backlog (media type): media go as binary only with a known magic;
    /// a NULL, empty or unknown body is refused before any client lookup.
    #[test]
    fn send_binary_checks_its_body() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        let to = c(ID_A);
        let send = |data: &[u8]| unsafe {
            let p = rchat_send_binary_with_id(to.as_ptr(), data.as_ptr(), data.len());
            assert!(p.is_null());
            rchat_last_error_code()
        };
        assert_eq!(send(b"BSTPx"), 9, "unknown magic");
        assert_eq!(send(b"IMG"), 9, "too short for a magic");
        assert_eq!(
            unsafe { rchat_send_binary_with_id(to.as_ptr(), std::ptr::null(), 4) },
            std::ptr::null_mut()
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(
            unsafe { rchat_send_binary_with_id(std::ptr::null(), b"IMG1".as_ptr(), 4) },
            std::ptr::null_mut()
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(
            send(b"IMG1jpeg"),
            7,
            "a known body gets as far as the client"
        );
    }

    #[test]
    fn pin_codes_and_state_before_connect() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect(); // no runtime, no client
        let (a, b, ak1, ak2) = (c(ID_A), c(ID_B), c(AK_1), c(AK_2));
        assert_eq!(
            unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) },
            -3,
            "uninitialised"
        );
        assert_eq!(unsafe { rchat_unpin_peer_key(a.as_ptr()) }, -3);
        assert_eq!(unsafe { rchat_set_peer_blocked(a.as_ptr(), 1) }, -3);
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(
            unsafe { rchat_pin_peer_key(c("nothex").as_ptr(), ak1.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { rchat_pin_peer_key(std::ptr::null(), ak1.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { rchat_pin_peer_key(a.as_ptr(), c("nothex").as_ptr()) },
            -1
        );
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert!(
            lock_state().staged.pin_hour(ID_A).is_some(),
            "a staged pin records its hour, as a live pin does"
        );
        assert_eq!(
            unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) },
            0,
            "same value: no-op"
        );
        assert_eq!(
            unsafe { rchat_pin_peer_key(a.as_ptr(), ak2.as_ptr()) },
            -2,
            "conflict"
        );
        assert_eq!(rchat_last_error_code(), 17);
        assert_eq!(
            unsafe { rchat_pin_peer_key(b.as_ptr(), ak1.as_ptr()) },
            -4,
            "agreement key in use"
        );
        assert_eq!(rchat_last_error_code(), 18);
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, 1);
        assert_eq!(unsafe { rchat_peer_key_state(b.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_peer_key_state(c("x").as_ptr()) }, -1);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        assert_eq!(unsafe { rchat_peer_key_state(b.as_ptr()) }, 4);
        assert_eq!(
            unsafe { rchat_pin_peer_key(b.as_ptr(), ak2.as_ptr()) },
            -1,
            "blocked"
        );
        assert_eq!(rchat_last_error_code(), 13);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 0) }, 0);
        assert_eq!(unsafe { rchat_unpin_peer_key(a.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, 0);
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(
            unsafe { rchat_peer_key_state(b.as_ptr()) },
            0,
            "disconnect clears the staged book"
        );
        rchat_disconnect();
    }

    /// A local relay accepting one WebSocket after `stall_ms`, kept open.
    fn stalled_relay(stall_ms: u64) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(stall_ms));
            if let Ok(mut ws) = tokio_tungstenite::tungstenite::accept(tcp) {
                while ws.read().is_ok() {}
            }
        });
        addr
    }

    fn ws_config(addr: std::net::SocketAddr) -> CString {
        c(&format!(
            r#"{{"server_url":"ws://{addr}/","identity_key_seed":null,
            "connection_timeout_secs":5,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}}"#
        ))
    }

    /// N-5 (a): a connect issued before a logout but queued behind another
    /// connect loses to the logout, even after `rchat_initialize` ran again.
    #[test]
    fn a_connect_queued_behind_another_loses_to_a_disconnect() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let config = ws_config(stalled_relay(0));
        let other_connect = CONNECT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let queued = std::thread::spawn(move || unsafe { rchat_connect(config.as_ptr()) });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(rchat_disconnect(), 0);
        assert_eq!(rchat_initialize(), 0);
        drop(other_connect);
        assert_eq!(queued.join().unwrap(), 7, "overtaken by the disconnect");
        assert!(lock_state().client.is_none());
        rchat_disconnect();
    }

    /// N-5 (b): a disconnect during `rchat_reconnect` wins: the reconnect
    /// reports 7 and the client is retired (no callbacks, no transport).
    #[test]
    fn a_disconnect_during_a_reconnect_retires_the_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let addr = stalled_relay(500);
        let client = RChatClient::new(ClientConfig {
            server_url: format!("ws://{addr}/"),
            reconnect_max_attempts: 1,
            ..ClientConfig::default()
        })
        .unwrap();
        client.set_callbacks(Box::new(bridge()));
        lock_state().client = Some(client.clone());
        let reconnecting = std::thread::spawn(|| rchat_reconnect());
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(rchat_disconnect(), 0);
        assert_eq!(reconnecting.join().unwrap(), 7);
        let inner = client.inner.try_read().unwrap();
        assert!(inner.callbacks.is_none(), "retired");
        assert!(inner.websocket.is_none(), "no live transport");
        drop(inner);
        rchat_disconnect();
    }

    /// N-5 / N-7: `rchat_disconnect` still delivers the Disconnected status,
    /// then retires the client's callbacks.
    #[test]
    fn rchat_disconnect_delivers_the_status_then_retires_callbacks() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client.set_callbacks(Box::new(bridge()));
        lock_state().client = Some(client.clone());
        STATE_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(rchat_disconnect(), 0);
        assert_eq!(
            STATE_CALLS.load(Ordering::SeqCst),
            1,
            "Disconnected delivered"
        );
        assert!(client.inner.try_read().unwrap().callbacks.is_none());
    }

    /// N-8: a busy client makes `rchat_peer_key_state` answer -5 (code 8)
    /// quickly, never 0 for a mismatched peer.
    #[test]
    fn peer_key_state_reports_busy() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        {
            let mut inner = client.inner.try_write().unwrap();
            inner.peers.pin(ID_A, [1; 32]).unwrap();
            inner.peers.mark_mismatch(ID_A);
        }
        lock_state().client = Some(client.clone());
        let a = c(ID_A);
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, 2);
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let holder = client.clone();
        let busy = std::thread::spawn(move || {
            let inner = holder.inner.clone();
            holder.runtime.block_on(async move {
                let guard = inner.write().await;
                locked_tx.send(()).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                drop(guard);
            });
        });
        locked_rx.recv().unwrap();
        let started = std::time::Instant::now();
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, -5);
        assert_eq!(rchat_last_error_code(), 8);
        assert!(started.elapsed() < std::time::Duration::from_millis(1000));
        busy.join().unwrap();
        rchat_disconnect();
    }

    /// N-3: generating, validating and connecting with a seed free no
    /// buffer still holding the seed in hex.
    #[test]
    fn seed_handling_frees_no_hex_copy() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            let p = rchat_generate_identity();
            assert!(!p.is_null());
            unsafe { rchat_free_string(p) };
        });
        assert_eq!(hits, 0, "rchat_generate_identity");

        let seed = "cd".repeat(64);
        let identity = c(&format!(
            r#"{{"seed":"{seed}","signing_pubkey":"x","agreement_pubkey":"y"}}"#
        ));
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            assert_eq!(unsafe { rchat_validate_identity(identity.as_ptr()) }, 0);
        });
        assert_eq!(hits, 0, "rchat_validate_identity");

        let config = c(&format!(
            r#"{{"server_url":"ws://127.0.0.1:9","identity_key_seed":"{seed}",
            "connection_timeout_secs":1,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}}"#
        ));
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            assert_ne!(unsafe { rchat_connect(config.as_ptr()) }, 0);
        });
        assert_eq!(hits, 0, "rchat_connect");
        rchat_disconnect();
    }

    /// I-8: the seed by bytes. Bad parameters are refused, a seed in both
    /// places is refused, and connecting frees no hex copy of the seed.
    #[test]
    fn connect_with_seed_takes_bytes_and_leaves_no_hex_copy() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let plain = c(
            r#"{"server_url":"ws://127.0.0.1:9","identity_key_seed":null,
            "connection_timeout_secs":1,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}"#,
        );
        let seed = [0xcdu8; 64];
        assert_eq!(
            unsafe { rchat_connect_with_seed(plain.as_ptr(), std::ptr::null(), 64) },
            9
        );
        assert_eq!(
            unsafe { rchat_connect_with_seed(plain.as_ptr(), seed.as_ptr(), 48) },
            9
        );
        // An empty seed is refused, never taken as "no seed" (R1-N8).
        assert_eq!(
            unsafe { rchat_connect_with_seed(plain.as_ptr(), seed.as_ptr(), 0) },
            9
        );

        let both = c(&format!(
            r#"{{"server_url":"ws://127.0.0.1:9","identity_key_seed":"{}",
            "connection_timeout_secs":1,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}}"#,
            "cd".repeat(64)
        ));
        assert_eq!(
            unsafe { rchat_connect_with_seed(both.as_ptr(), seed.as_ptr(), 64) },
            9
        );
        assert_eq!(rchat_last_error_code(), 9);

        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            // Nothing listens on :9, so the connect itself fails — after
            // the seed was taken in.
            let code = unsafe { rchat_connect_with_seed(plain.as_ptr(), seed.as_ptr(), 64) };
            assert_ne!(code, 0);
            assert_ne!(code, 9);
        });
        assert_eq!(hits, 0, "rchat_connect_with_seed");
        rchat_disconnect();
    }

    /// R1-N2: a connect refused before the client exists (no runtime) frees
    /// no buffer holding the seed in hex, by bytes or from the JSON.
    #[test]
    fn a_connect_refused_early_frees_no_hex_seed() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect(); // no runtime: the connect stops with code 8
        let plain = c(
            r#"{"server_url":"ws://127.0.0.1:9","identity_key_seed":null,
            "connection_timeout_secs":1,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}"#,
        );
        let with_seed = c(&format!(
            r#"{{"server_url":"ws://127.0.0.1:9","identity_key_seed":"{}",
            "connection_timeout_secs":1,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}}"#,
            "cd".repeat(64)
        ));
        let seed = [0xcdu8; 64];
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            assert_eq!(
                unsafe { rchat_connect_with_seed(plain.as_ptr(), seed.as_ptr(), 64) },
                8
            );
            assert_eq!(unsafe { rchat_connect(with_seed.as_ptr()) }, 8);
        });
        assert_eq!(hits, 0);
    }

    /// I-8: generation hands the seed out by buffer; the staged identity is
    /// the one the seed rebuilds.
    #[test]
    fn generate_identity_seed_writes_the_seed_it_stages() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let mut small = [0u8; 63];
        assert_eq!(
            unsafe { rchat_generate_identity_seed(small.as_mut_ptr(), small.len()) },
            -1
        );
        assert_eq!(
            unsafe { rchat_generate_identity_seed(std::ptr::null_mut(), 64) },
            -1
        );
        let mut out = [0u8; 64];
        let hits = crate::alloc_probe::freed_hex_seeds(|| {
            assert_eq!(
                unsafe { rchat_generate_identity_seed(out.as_mut_ptr(), out.len()) },
                1
            );
        });
        assert_eq!(hits, 0, "rchat_generate_identity_seed");
        assert_ne!(out, [0u8; 64]);
        let rebuilt = IdentityKeyPair::from_seed(&out).unwrap();
        let p = rchat_get_identity_pubkey();
        assert!(!p.is_null());
        let staged = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        unsafe { rchat_free_string(p) };
        assert_eq!(staged, rebuilt.public_key_hex());
        let p = rchat_get_agreement_pubkey();
        let staged_ak = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        unsafe { rchat_free_string(p) };
        assert_eq!(staged_ak, rebuilt.agreement_key_hex());
        rchat_disconnect();
    }

    /// C-6: a disconnect (logout, Reset Identity) while a connect is still
    /// running wins: the connect's client is never installed and its book
    /// is not staged for the next account.
    #[test]
    fn a_disconnect_during_a_connect_leaves_no_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, ak1) = (c(ID_A), c(AK_1));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            // Stall the WebSocket handshake past the disconnect.
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut ws = tokio_tungstenite::tungstenite::accept(tcp).unwrap();
            while ws.read().is_ok() {}
        });
        let config = c(&format!(
            r#"{{"server_url":"ws://{addr}/","identity_key_seed":null,
            "connection_timeout_secs":5,"reconnect_max_attempts":1,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}}"#
        ));
        // The code is read on the thread that made the call (thread-local).
        let connecting = std::thread::spawn(move || {
            let code = unsafe { rchat_connect(config.as_ptr()) };
            (code, rchat_last_error_code())
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        record_error(0, String::new());
        assert_eq!(rchat_disconnect(), 0);
        let (code, recorded) = connecting.join().unwrap();
        assert_eq!(code, 7, "overtaken by the disconnect");
        assert_eq!(recorded, 7);
        assert_eq!(
            rchat_last_error_code(),
            0,
            "another thread's error is not ours"
        );
        let guard = lock_state();
        assert!(guard.client.is_none(), "no client installed");
        assert!(guard.staged.pin_for(ID_A).is_none(), "old book not staged");
        drop(guard);
        rchat_disconnect();
    }

    #[test]
    fn staged_pins_move_into_the_new_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, b, ak1) = (c(ID_A), c(ID_B), c(AK_1));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        assert_eq!(
            client.peer_key_state(ID_A.to_string()),
            1,
            "pin survives into the client"
        );
        assert_eq!(
            client.peer_key_state(ID_B.to_string()),
            4,
            "block survives too"
        );
        assert_eq!(
            unsafe { rchat_peer_key_state(a.as_ptr()) },
            0,
            "staged book was moved, not copied"
        );
        rchat_disconnect();
    }

    #[test]
    fn a_failed_connect_keeps_the_staged_pins() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, b, ak1) = (c(ID_A), c(ID_B), c(AK_1));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        // A bad seed fails inside `connect()`, after the book was adopted,
        // without touching the network.
        let config = bad_seed_config();
        assert_ne!(
            unsafe { rchat_connect(config.as_ptr()) },
            0,
            "connect fails"
        );
        assert!(lock_state().client.is_none());
        assert_eq!(
            unsafe { rchat_peer_key_state(a.as_ptr()) },
            1,
            "pin restored to the staged book"
        );
        assert_eq!(
            unsafe { rchat_peer_key_state(b.as_ptr()) },
            4,
            "block restored too"
        );
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        assert_eq!(
            client.peer_key_state(ID_A.to_string()),
            1,
            "the next connect still adopts the pin"
        );
        rchat_disconnect();
    }

    #[test]
    fn restore_applies_pins_staged_during_the_connect_on_top() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, b, ak1, ak2) = (c(ID_A), c(ID_B), c(AK_1), c(AK_2));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        // Staged while the (failing) connect ran.
        assert_eq!(unsafe { rchat_pin_peer_key(b.as_ptr(), ak2.as_ptr()) }, 0);
        restore_staged(&client);
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, 1);
        assert_eq!(unsafe { rchat_peer_key_state(b.as_ptr()) }, 1);
        assert_eq!(
            client.peer_key_state(ID_A.to_string()),
            0,
            "moved out of the client"
        );
        rchat_disconnect();
    }

    const ID_C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";
    const AK_3: &str = "0300000000000000000000000000000000000000000000000000000000000003";

    fn bad_seed_config() -> CString {
        c(
            r#"{"server_url":"ws://127.0.0.1:9","identity_key_seed":"zz",
            "connection_timeout_secs":1,"reconnect_max_attempts":0,"message_retry_count":0,
            "enable_delivery_confirmation":false,"keepalive_interval_secs":30,
            "tls_fingerprint":"None"}"#,
        )
    }

    #[test]
    fn unpins_staged_during_a_failed_connect_are_not_lost() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, b, ak1, ak2) = (c(ID_A), c(ID_B), c(AK_1), c(AK_2));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        // While the (failing) connect runs, the contact is deleted and the
        // block lifted: both land in the staged book as tombstones.
        assert_eq!(unsafe { rchat_unpin_peer_key(a.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 0) }, 0);
        restore_staged(&client);
        assert_eq!(
            unsafe { rchat_peer_key_state(a.as_ptr()) },
            0,
            "unpin survives the restore"
        );
        assert_eq!(
            unsafe { rchat_peer_key_state(b.as_ptr()) },
            0,
            "unblock survives too"
        );
        assert_eq!(unsafe { rchat_pin_peer_key(b.as_ptr(), ak2.as_ptr()) }, 0);
        rchat_disconnect();
    }

    #[test]
    fn a_reconnect_carries_the_live_clients_pins_to_the_new_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let old = RChatClient::new(ClientConfig::default()).unwrap();
        lock_state().client = Some(old.clone());
        let (a, b, ak1) = (c(ID_A), c(ID_B), c(AK_1));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        assert_eq!(
            lock_state().staged.pin_for(ID_A),
            None,
            "pin is in the client"
        );
        // The steps `rchat_connect` takes around its network call.
        retire_previous_client();
        let new = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&new);
        install_client(new.clone());
        assert_eq!(
            new.peer_key_state(ID_A.to_string()),
            1,
            "pin reached the new client"
        );
        assert_eq!(new.peer_key_state(ID_B.to_string()), 4, "block too");
        rchat_disconnect();
    }

    #[test]
    fn a_retired_client_is_silenced_and_disconnected() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let old = RChatClient::new(ClientConfig::default()).unwrap();
        old.set_callbacks(Box::new(bridge()));
        old.inner.try_write().unwrap().is_connected = true;
        let generation = old.inner.try_read().unwrap().connection_generation;
        lock_state().client = Some(old.clone());
        STATE_CALLS.store(0, Ordering::SeqCst);

        retire_previous_client();
        assert!(
            old.inner.try_read().unwrap().callbacks.is_none(),
            "callbacks dropped"
        );
        assert!(matches!(
            old.get_connection_status(),
            ConnectionStatus::Disconnected
        ));
        assert!(
            old.inner.try_read().unwrap().connection_generation > generation,
            "its pending transport events are retired"
        );
        assert_eq!(STATE_CALLS.load(Ordering::SeqCst), 0, "retired silently");
        // Anything it still does reaches no one.
        let _ = old.disconnect();
        assert_eq!(STATE_CALLS.load(Ordering::SeqCst), 0);
        rchat_disconnect();
    }

    #[test]
    fn a_failed_reconnect_leaves_the_live_clients_pins_staged() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let old = RChatClient::new(ClientConfig::default()).unwrap();
        lock_state().client = Some(old.clone());
        let (a, ak1) = (c(ID_A), c(AK_1));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        let config = bad_seed_config();
        assert_ne!(
            unsafe { rchat_connect(config.as_ptr()) },
            0,
            "connect fails"
        );
        assert!(lock_state().client.is_none(), "the old client was retired");
        assert_eq!(
            unsafe { rchat_peer_key_state(a.as_ptr()) },
            1,
            "its pin is in the staged book"
        );
        let next = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&next);
        assert_eq!(next.peer_key_state(ID_A.to_string()), 1);
        rchat_disconnect();
    }

    #[test]
    fn changes_staged_during_a_successful_connect_reach_the_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let (a, b, cc, ak1, ak2, ak3) = (c(ID_A), c(ID_B), c(ID_C), c(AK_1), c(AK_2), c(AK_3));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_pin_peer_key(cc.as_ptr(), ak3.as_ptr()) }, 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        // While connecting (no client in the state yet): a delete, an add, a block.
        assert_eq!(unsafe { rchat_unpin_peer_key(a.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_pin_peer_key(b.as_ptr(), ak2.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_set_peer_blocked(cc.as_ptr(), 1) }, 0);
        install_client(client.clone());
        assert_eq!(
            client.peer_key_state(ID_A.to_string()),
            0,
            "deleted contact unpinned"
        );
        assert_eq!(
            client.peer_key_state(ID_B.to_string()),
            1,
            "new contact pinned"
        );
        assert_eq!(client.peer_key_state(ID_C.to_string()), 4, "block applied");
        assert_eq!(
            unsafe { rchat_peer_key_state(b.as_ptr()) },
            1,
            "calls now reach the client"
        );
        rchat_disconnect();
    }

    #[test]
    fn pin_codes_with_a_live_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        lock_state().client = Some(client.clone());
        let (a, b, ak1, ak2) = (c(ID_A), c(ID_B), c(AK_1), c(AK_2));
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        assert_eq!(
            client.peer_key_state(ID_A.to_string()),
            1,
            "acts on the client"
        );
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak2.as_ptr()) }, -2);
        assert_eq!(rchat_last_error_code(), 17);
        assert_eq!(unsafe { rchat_pin_peer_key(b.as_ptr(), ak1.as_ptr()) }, -4);
        assert_eq!(rchat_last_error_code(), 18);
        assert_eq!(unsafe { rchat_set_peer_blocked(b.as_ptr(), 1) }, 0);
        assert_eq!(unsafe { rchat_peer_key_state(b.as_ptr()) }, 4);
        assert_eq!(
            unsafe { rchat_pin_peer_key(b.as_ptr(), ak2.as_ptr()) },
            -1,
            "blocked"
        );
        assert_eq!(rchat_last_error_code(), 13);
        assert_eq!(unsafe { rchat_unpin_peer_key(a.as_ptr()) }, 0);
        assert_eq!(unsafe { rchat_peer_key_state(a.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rchat_request_circuit(a.as_ptr()) },
            12,
            "not accepted after unpin"
        );
        assert_eq!(rchat_last_error_code(), 12);
        rchat_disconnect();
    }

    #[test]
    fn calls_needing_a_client_report_not_connected() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let a = c(ID_A);
        assert_eq!(unsafe { rchat_request_circuit(a.as_ptr()) }, 7);
        assert_eq!(rchat_last_error_code(), 7);
        assert!(unsafe { rchat_set_intro(a.as_ptr(), c("hi").as_ptr()) }.is_null());
        assert_eq!(rchat_last_error_code(), 7);
        let id = c("0123456789abcdef0123456789abcdef");
        assert!(
            unsafe { rchat_set_intro_with_id(a.as_ptr(), c("hi").as_ptr(), id.as_ptr()) }.is_null()
        );
        assert_eq!(rchat_last_error_code(), 7);
        assert!(
            unsafe { rchat_set_intro_with_id(a.as_ptr(), c("hi").as_ptr(), std::ptr::null()) }
                .is_null()
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(
            unsafe { rchat_send_message_using_id(a.as_ptr(), c("hi").as_ptr(), id.as_ptr()) },
            7
        );
        assert_eq!(
            unsafe { rchat_mark_message_seen(a.as_ptr(), id.as_ptr()) },
            7
        );
        assert_eq!(
            unsafe { rchat_send_read_receipt(a.as_ptr(), id.as_ptr()) },
            7
        );
        assert_eq!(
            unsafe { rchat_send_message_using_id(std::ptr::null(), c("hi").as_ptr(), id.as_ptr()) },
            9
        );
        assert_eq!(rchat_last_error_code(), 9);

        // The code is never stale: after a key-rejected failure (10), a later
        // NULL from rchat_send_message_with_id reports its own cause.
        record_error(10, String::new());
        assert!(unsafe { rchat_send_message_with_id(a.as_ptr(), c("hi").as_ptr()) }.is_null());
        assert_eq!(
            rchat_last_error_code(),
            7,
            "not connected, not the stale 10"
        );
        record_error(10, String::new());
        assert!(
            unsafe { rchat_send_message_with_id(std::ptr::null(), c("hi").as_ptr()) }.is_null()
        );
        assert_eq!(
            rchat_last_error_code(),
            9,
            "an invalid parameter overwrites the stale 10 (C-22)"
        );
        // C-22: every NULL-argument 9 is also the recorded code.
        let null = std::ptr::null();
        let calls: [(&str, Box<dyn Fn() -> c_int>); 6] = [
            ("connect", Box::new(|| unsafe { rchat_connect(null) })),
            (
                "set_recipient",
                Box::new(|| unsafe { rchat_set_recipient(null, null) }),
            ),
            (
                "send_message",
                Box::new(|| unsafe { rchat_send_message(null, null) }),
            ),
            (
                "has_session",
                Box::new(|| unsafe { rchat_has_session(null) }),
            ),
            (
                "validate_identity",
                Box::new(|| unsafe { rchat_validate_identity(null) }),
            ),
            (
                "request_circuit",
                Box::new(|| unsafe { rchat_request_circuit(null) }),
            ),
        ];
        for (name, call) in calls {
            record_error(0, String::new());
            assert_eq!(call(), 9, "{name}");
            assert_eq!(rchat_last_error_code(), 9, "{name} records 9");
        }
        rchat_disconnect();
    }

    #[test]
    fn unified_error_codes() {
        let id = || "x".to_string();
        let cases: Vec<(crate::RChatError, c_int)> = vec![
            (crate::RChatError::PeerKeyRejected { identity: id() }, 10),
            (crate::RChatError::PeerKeyUnverified { identity: id() }, 11),
            (crate::RChatError::PeerNotAccepted { identity: id() }, 12),
            (crate::RChatError::PeerBlocked { identity: id() }, 13),
            (crate::RChatError::KeyAuthRejected, 14),
            (crate::RChatError::ServerTooNew, 15),
            (crate::RChatError::NoChannelBinding, 16),
            (crate::RChatError::PinConflict, 17),
            (crate::RChatError::AgreementKeyInUse, 18),
            (crate::RChatError::NoPinnedKeys { identity: id() }, 19),
            (crate::RChatError::SafetyNumberChanged, 20),
            (crate::RChatError::RelayIdentityInvalid, 21),
            (crate::RChatError::RelayPinRequired, 22),
            (crate::RChatError::RelayIdentityChanged, 23),
            (crate::RChatError::RotationTooSoon, 24),
            (crate::RChatError::NotConnected, 7),
        ];
        for (e, code) in cases {
            assert_eq!(error_code_from_err(&e), code, "{e}");
        }
    }

    #[test]
    fn callbacks_carry_the_new_fields() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        CALLS.lock().unwrap().clear();
        let b = bridge();
        b.on_message_received(ReceivedMessage {
            id: "0123456789abcdef0123456789abcdef".into(),
            sender_identity: ID_A.into(),
            content: b"hi".to_vec(),
            timestamp_ms: 5,
            is_text: true,
        });
        b.on_message_received(ReceivedMessage {
            id: "00000000000000000000000000000001".into(),
            sender_identity: ID_A.into(),
            content: b"IMG1\x00".to_vec(),
            timestamp_ms: 6,
            is_text: false,
        });
        b.on_peer_key_event(ID_A.into(), 2, AK_2.into());
        b.on_message_request(crate::MessageRequest {
            identity_hex: ID_B.into(),
            agreement_hex: AK_1.into(),
            issued_hour: 486_000,
            intro_message_id_hex: String::new(),
            intro_text: String::new(),
            intro_sent_at_ms: 0,
            key_version: 0,
        });
        b.on_message_request(crate::MessageRequest {
            identity_hex: ID_B.into(),
            agreement_hex: AK_1.into(),
            issued_hour: 486_001,
            intro_message_id_hex: "00112233445566778899aabbccddeeff".into(),
            intro_text: "hello there".into(),
            intro_sent_at_ms: 1_700_000_000_000,
            key_version: 0,
        });
        b.on_message_receipt(ID_B.into(), "ffeeddccbbaa99887766554433221100".into(), 2);
        let calls = CALLS.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                format!("msg {ID_A} 6869 5 0123456789abcdef0123456789abcdef k1"),
                format!("msg {ID_A} 494d473100 6 00000000000000000000000000000001 k2"),
                format!("key {ID_A} 2 {AK_2}"),
                format!("req {ID_B} {AK_1} 486000 [] [] 0 kv0"),
                format!(
                    "req {ID_B} {AK_1} 486001 [00112233445566778899aabbccddeeff] [hello there] 1700000000000 kv0"
                ),
                format!("rcpt {ID_B} ffeeddccbbaa99887766554433221100 2"),
            ]
        );
    }

    /// SN4 through the C API, before connect (staged book), and codes 19/20.
    #[test]
    fn safety_number_ffi_staged() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        rchat_initialize();
        let my_ik = c(&hex::encode([0x11u8; 32]));
        let my_ak = c(&hex::encode([0x22u8; 32]));
        let peer = c(&hex::encode([0x33u8; 32]));
        assert!(
            unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr()) }.is_null()
        );
        assert_eq!(rchat_last_error_code(), 19, "no pinned keys");
        let ak = c(&hex::encode([0x44u8; 32]));
        assert_eq!(unsafe { rchat_pin_peer_key(peer.as_ptr(), ak.as_ptr()) }, 0);
        let p = unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr()) };
        let n = s(p);
        unsafe { rchat_free_string(p) };
        assert_eq!(
            n,
            "207876968560055734126985141340311686637181083400395252065708"
        );
        let wrong = c(&format!("{}9", &n[..59]));
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    wrong.as_ptr(),
                )
            },
            -5
        );
        let right = c(&n);
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    right.as_ptr(),
                )
            },
            0
        );
        let other = c(&hex::encode([0x55u8; 32]));
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    other.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    right.as_ptr(),
                )
            },
            -2
        );
        let qr = c(&crate::safety_number::to_text_form(&n));
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    qr.as_ptr(),
                )
            },
            1
        );
        let qr_off = c(&crate::safety_number::to_text_form(&format!(
            "{}9",
            &n[..59]
        )));
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    qr_off.as_ptr(),
                )
            },
            0
        );
        let junk = c("hello");
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    junk.as_ptr(),
                )
            },
            -1
        );
        assert_eq!(rchat_last_error_code(), 9, "Task 20b: -1 records its code");
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    other.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    qr.as_ptr(),
                )
            },
            -2
        );
        assert_eq!(
            rchat_last_error_code(),
            19,
            "Task 20b: -2 is nothing pinned, recorded"
        );
        assert_eq!(unsafe { rchat_set_peer_key_version(peer.as_ptr(), 3) }, 0);
        assert_eq!(unsafe { rchat_set_peer_key_version(other.as_ptr(), 3) }, -2);
        assert_eq!(rchat_set_cover_traffic(1, 1), 0);
        rchat_disconnect();
    }

    /// Null, non-UTF-8 and malformed arguments are refused without a panic,
    /// and every new call reports "not initialised" before `rchat_initialize`.
    #[test]
    fn safety_number_ffi_rejects_bad_arguments() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        let null = std::ptr::null();
        let my_ik = c(&hex::encode([0x11u8; 32]));
        let my_ak = c(&hex::encode([0x22u8; 32]));
        let peer = c(&hex::encode([0x33u8; 32]));
        let digits = c(&"1".repeat(60));
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    digits.as_ptr(),
                )
            },
            -3
        );
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    digits.as_ptr(),
                )
            },
            -3
        );
        assert_eq!(unsafe { rchat_set_peer_key_version(peer.as_ptr(), 1) }, -3);
        // Task 20b: "not initialised" (8) is not shadowed by 9.
        assert!(
            unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr()) }.is_null()
        );
        assert_eq!(rchat_last_error_code(), 8);
        rchat_initialize();
        let bad_utf8 = CString::new(vec![0xffu8, 0xfe]).unwrap();
        let short = c("abcd");
        for bad in [null, bad_utf8.as_ptr(), short.as_ptr()] {
            assert!(unsafe { rchat_safety_number(bad, my_ik.as_ptr(), my_ak.as_ptr()) }.is_null());
            assert_eq!(rchat_last_error_code(), 9);
            assert!(unsafe { rchat_safety_number(peer.as_ptr(), bad, my_ak.as_ptr()) }.is_null());
            assert!(unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), bad) }.is_null());
            assert_eq!(
                unsafe {
                    rchat_mark_safety_number_compared(
                        bad,
                        my_ik.as_ptr(),
                        my_ak.as_ptr(),
                        digits.as_ptr(),
                    )
                },
                -1
            );
            assert_eq!(
                unsafe {
                    rchat_mark_safety_number_compared(
                        peer.as_ptr(),
                        bad,
                        my_ak.as_ptr(),
                        digits.as_ptr(),
                    )
                },
                -1
            );
            assert_eq!(
                unsafe {
                    rchat_compare_safety_number_qr(
                        peer.as_ptr(),
                        my_ik.as_ptr(),
                        bad,
                        digits.as_ptr(),
                    )
                },
                -1
            );
            assert_eq!(unsafe { rchat_set_peer_key_version(bad, 1) }, -1);
            assert!(unsafe { rchat_canonical_origin(bad) }.is_null());
            assert_eq!(rchat_last_error_code(), 9);
        }
        assert!(rchat_prepare_rotation().is_null());
        assert_eq!(rchat_last_error_code(), 7, "no client");
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    null,
                )
            },
            -1
        );
        assert_eq!(rchat_last_error_code(), 9);
        let links = c("00");
        assert_eq!(
            unsafe { rchat_announce_rotation(links.as_ptr()) },
            -7,
            "no client"
        );
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr(), null)
            },
            -1
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(unsafe { rchat_announce_rotation(null) }, -9);
        assert!(rchat_relay_pin_info().is_null(), "no client, no relay pin");
        rchat_disconnect();
    }

    /// L4: no client, no seed; a null or short buffer is invalid.
    #[test]
    fn take_rotation_seed_ffi() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        rchat_initialize();
        let mut buf = [0u8; 64];
        assert_eq!(
            unsafe { rchat_take_rotation_seed(buf.as_mut_ptr(), 64) },
            0,
            "no client, nothing to take"
        );
        assert_eq!(
            unsafe { rchat_take_rotation_seed(std::ptr::null_mut(), 64) },
            -1
        );
        assert_eq!(
            unsafe { rchat_take_rotation_seed(buf.as_mut_ptr(), 32) },
            -1
        );
        assert_eq!(buf, [0u8; 64]);
        rchat_disconnect();
    }

    /// L4 with a live client: the plan JSON carries no seed, and the seed
    /// is handed over through the buffer exactly once.
    #[test]
    fn rotation_seed_handoff_through_the_c_api() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        rchat_initialize();
        let (inner, _rx) = crate::test_support::published(0xA1);
        lock_state().client = Some(crate::test_support::wrap(inner));
        let p = rchat_prepare_rotation();
        assert!(!p.is_null());
        let json: serde_json::Value = serde_json::from_str(&s(p)).unwrap();
        unsafe { rchat_free_string(p) };
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), 4, "{keys:?}");
        for k in ["new_version", "links", "new_identity", "new_agreement"] {
            assert!(json.get(k).is_some(), "{k}");
        }
        let mut buf = [0u8; 64];
        assert_eq!(
            unsafe { rchat_take_rotation_seed(buf.as_mut_ptr(), 32) },
            -1,
            "short buffer"
        );
        assert_eq!(buf, [0u8; 64]);
        assert_eq!(unsafe { rchat_take_rotation_seed(buf.as_mut_ptr(), 64) }, 1);
        let new = crate::crypto::IdentityKeyPair::from_seed(&buf).unwrap();
        assert_eq!(
            hex::encode(new.public_signing_key().to_bytes()),
            json["new_identity"].as_str().unwrap()
        );
        let mut again = [0u8; 64];
        assert_eq!(
            unsafe { rchat_take_rotation_seed(again.as_mut_ptr(), 64) },
            0,
            "single use"
        );
        assert_eq!(again, [0u8; 64]);
        lock_state().client = None;
        rchat_disconnect();
    }

    /// With a live client the number uses the client's own keys.
    #[test]
    fn safety_number_ffi_live_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        rchat_initialize();
        let (inner, _rx) = crate::test_support::published(0xA1);
        let client = crate::test_support::wrap(inner);
        lock_state().client = Some(client.clone());
        let me = crate::crypto::IdentityKeyPair::from_seed(&[0xA1u8; 64]).unwrap();
        let my_ik = c(&hex::encode(me.public_signing_key().to_bytes()));
        let my_ak = c(&hex::encode(me.public_agreement_key().as_bytes()));
        let peer = c(&hex::encode([0x33u8; 32]));
        assert!(
            unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr()) }.is_null()
        );
        assert_eq!(rchat_last_error_code(), 19);
        let ak = c(&hex::encode([0x44u8; 32]));
        assert_eq!(unsafe { rchat_pin_peer_key(peer.as_ptr(), ak.as_ptr()) }, 0);
        let p = unsafe { rchat_safety_number(peer.as_ptr(), my_ik.as_ptr(), my_ak.as_ptr()) };
        let n = s(p);
        unsafe { rchat_free_string(p) };
        assert_eq!(n, client.safety_number(hex::encode([0x33u8; 32])).unwrap());
        let qr = c(&crate::safety_number::to_text_form(&n));
        assert_eq!(
            unsafe {
                rchat_compare_safety_number_qr(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    qr.as_ptr(),
                )
            },
            1
        );
        let wrong = c(&format!(
            "{}{}",
            &n[..59],
            if n.ends_with('9') { '8' } else { '9' }
        ));
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    wrong.as_ptr(),
                )
            },
            -5
        );
        assert_eq!(rchat_last_error_code(), 20);
        let right = c(&n);
        assert_eq!(
            unsafe {
                rchat_mark_safety_number_compared(
                    peer.as_ptr(),
                    my_ik.as_ptr(),
                    my_ak.as_ptr(),
                    right.as_ptr(),
                )
            },
            0
        );
        assert_eq!(unsafe { rchat_set_peer_key_version(peer.as_ptr(), 2) }, 0);
        lock_state().client = None;
        rchat_disconnect();
    }

    /// A cover setting reported while a connect is in flight reaches the
    /// client when it is installed.
    #[test]
    fn cover_changed_during_a_connect_reaches_the_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(rchat_set_cover_traffic(1, 0), 0, "staged before connect");
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        adopt_staged(&client);
        let (on, fg) = lock_state().cover;
        client.set_cover_traffic(on, fg);
        let cover = |c: &RChatClient| {
            let i = c.inner.try_read().unwrap();
            (i.cover_enabled, i.cover_foreground)
        };
        assert_eq!(cover(&client), (true, false), "applied at connect");
        // The app comes to the foreground while the connect runs (no client yet).
        assert_eq!(rchat_set_cover_traffic(1, 1), 0);
        assert_eq!(cover(&client), (true, false), "not reachable yet");
        install_client(client.clone());
        assert_eq!(cover(&client), (true, true), "applied on install");
        assert_eq!(rchat_set_cover_traffic(0, 1), 0);
        assert_eq!(
            cover(&client),
            (false, true),
            "later calls reach the client"
        );
        rchat_disconnect();
    }

    /// Final review I-1: `rchat_reconnect` keeps the live client (its
    /// callbacks, sessions and pins) and, like a connect, applies whatever
    /// is staged and the cover setting once the transport is back.
    #[test]
    fn a_reconnect_keeps_the_client_and_applies_staged_state() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(rchat_reconnect(), 7, "no client yet");
        assert_eq!(rchat_last_error_code(), 7);
        let addr = stalled_relay(0);
        let client = RChatClient::new(ClientConfig {
            server_url: format!("ws://{addr}/"),
            reconnect_max_attempts: 1,
            ..ClientConfig::default()
        })
        .unwrap();
        client.set_callbacks(Box::new(bridge()));
        install_client(client.clone());
        let a = c(ID_A);
        let ak1 = c(AK_1);
        assert_eq!(unsafe { rchat_pin_peer_key(a.as_ptr(), ak1.as_ptr()) }, 0);
        // Staged directly: a change that reached no client.
        lock_state()
            .staged
            .pin(ID_B, key_from_hex(AK_2).unwrap())
            .unwrap();
        lock_state().cover = (true, true);
        assert_eq!(rchat_disconnect_transport_only(), 0);
        assert_eq!(rchat_reconnect(), 0);
        let current = lock_state().client.clone().unwrap();
        assert!(Arc::ptr_eq(&current, &client), "the same client");
        assert_eq!(client.peer_key_state(ID_A.to_string()), 1, "pin kept");
        assert_eq!(client.peer_key_state(ID_B.to_string()), 1, "staged applied");
        let inner = client.inner.try_read().unwrap();
        assert!(inner.callbacks.is_some(), "callbacks kept");
        assert!(inner.publish_requested, "publishes on its own");
        assert_eq!((inner.cover_enabled, inner.cover_foreground), (true, true));
        drop(inner);
        rchat_disconnect();
    }

    /// L2 through the C API (the full table is Task 11b's RP10).
    #[test]
    fn canonical_origin_ffi() {
        let out = |u: &str| {
            let cu = c(u);
            let p = unsafe { rchat_canonical_origin(cu.as_ptr()) };
            if p.is_null() {
                None
            } else {
                let v = s(p);
                unsafe { rchat_free_string(p) };
                Some(v)
            }
        };
        assert_eq!(
            out("wss://Relay.Example.org./path"),
            Some("wss://relay.example.org:443".into())
        );
        assert_eq!(out("wss://[::1]:8443"), Some("wss://[::1]:8443".into()));
        assert_eq!(out("wss://bücher.example"), None, "punycode only");
    }

    /// Codes 19–24 map from the new errors.
    #[test]
    fn new_error_codes() {
        use crate::RChatError as E;
        assert_eq!(
            error_code_from_err(&E::NoPinnedKeys {
                identity: String::new()
            }),
            19
        );
        assert_eq!(error_code_from_err(&E::SafetyNumberChanged), 20);
        assert_eq!(error_code_from_err(&E::RelayIdentityInvalid), 21);
        assert_eq!(error_code_from_err(&E::RelayPinRequired), 22);
        assert_eq!(error_code_from_err(&E::RelayIdentityChanged), 23);
        assert_eq!(error_code_from_err(&E::RotationTooSoon), 24);
    }

    /// The new callback fields reach C.
    #[test]
    fn rotated_and_request_version_callbacks() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        CALLS.lock().unwrap().clear();
        let b = bridge();
        b.on_peer_rotated("aa".into(), "bb".into(), "cc".into(), 2);
        b.on_message_request(crate::MessageRequest {
            identity_hex: "dd".into(),
            agreement_hex: "ee".into(),
            issued_hour: 5,
            intro_message_id_hex: String::new(),
            intro_text: String::new(),
            intro_sent_at_ms: 0,
            key_version: 4,
        });
        let calls = CALLS.lock().unwrap().clone();
        assert!(calls.contains(&"rot aa bb cc 2".to_string()), "{calls:?}");
        assert!(
            calls
                .iter()
                .any(|l| l.starts_with("req dd ee 5") && l.ends_with("kv4")),
            "{calls:?}"
        );
    }

    static EVENTS: StdMutex<Vec<(c_int, String, String, c_int)>> = StdMutex::new(Vec::new());
    extern "C" fn rec_status(kind: c_int, peer: *const c_char, id: *const c_char, detail: c_int) {
        EVENTS.lock().unwrap().push((kind, s(peer), s(id), detail));
    }

    /// OB1: every StatusEvent crosses the bridge with its documented code and strings.
    #[test]
    fn ob1_status_events_cross_the_bridge() {
        let bridge = CCallbackBridge {
            ptrs: CCallbackPointers {
                on_status_event: rec_status,
                ..noop_pointers()
            },
        };
        let p = "ab".repeat(32);
        let id = "cd".repeat(16);
        use crate::status::StatusEvent::*;
        for ev in [
            DecryptFailed {
                peer: p.clone(),
                message_id: id.clone(),
                detail: 1,
            },
            PeerUndelivered {
                peer: p.clone(),
                message_id: id.clone(),
                reason: 2,
            },
            PeerSessionReset { peer: p.clone() },
            SessionReplaced { peer: p.clone() },
            SendNotAccepted {
                peer: p.clone(),
                message_id: id.clone(),
            },
            AckUnknown {
                peer: p.clone(),
                message_id: id.clone(),
                attempts: 3,
            },
            QueuedSendLost {
                peer: p.clone(),
                message_id: id.clone(),
            },
            StatePersistFailed { peer: None },
            StateRestoreFailed { reason: 2 },
            ResendEligible {
                peer: p.clone(),
                message_id: id.clone(),
            },
        ] {
            bridge.on_status_event(ev);
        }
        let got = EVENTS.lock().unwrap().clone();
        assert_eq!(
            got.iter().map(|e| e.0).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
        assert_eq!(got[7], (8, String::new(), String::new(), 0));
        assert_eq!(got[8], (9, String::new(), String::new(), 2));
        assert_eq!(got[5], (6, p.clone(), id.clone(), 3));
        assert_eq!(got[1], (2, p, id, 2));
    }

    #[test]
    fn state_store_ffi_validates_arguments() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        extern "C" fn w(_: *const c_char, _: *const u8, _: usize) -> c_int {
            0
        }
        let key = [7u8; 32];
        let k = CString::new("meta").unwrap();
        assert_eq!(
            unsafe { rchat_set_state_store(key.as_ptr(), 32, Some(w)) },
            -3,
            "uninitialised"
        );
        assert_eq!(rchat_last_error_code(), 8);
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
            -3
        );
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(
            unsafe { rchat_set_state_store(std::ptr::null(), 32, Some(w)) },
            -1
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(
            unsafe { rchat_set_state_store(key.as_ptr(), 31, Some(w)) },
            -1
        );
        assert_eq!(unsafe { rchat_set_state_store(key.as_ptr(), 32, None) }, -1);
        assert!(lock_state().state_key.is_none(), "nothing set on a refusal");
        assert_eq!(
            unsafe { rchat_set_state_store(key.as_ptr(), 32, Some(w)) },
            0
        );
        assert_eq!(lock_state().state_key.as_deref(), Some(&key));
        let bad = CString::new("../meta").unwrap();
        let big = vec![1u8; crate::state_store::MAX_RECORD_BYTES + 1];
        assert_eq!(
            unsafe { rchat_import_state_record(bad.as_ptr(), [1u8].as_ptr(), 1) },
            -1
        );
        assert_eq!(
            unsafe { rchat_import_state_record(std::ptr::null(), [1u8].as_ptr(), 1) },
            -1
        );
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), std::ptr::null(), 1) },
            -1
        );
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 0) },
            -1
        );
        assert_eq!(rchat_last_error_code(), 9);
        // The length is checked before the buffer is read: a huge `len`
        // over a 1-byte buffer is refused without touching it.
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), usize::MAX) },
            -2
        );
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), big.as_ptr(), big.len()) },
            -2
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert!(
            lock_state().staged_records.is_empty(),
            "refusals stage nothing"
        );
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
            0
        );
        assert_eq!(
            lock_state().staged_records,
            vec![("meta".to_string(), vec![1u8])]
        );
        assert_eq!(rchat_clear_state(), 0);
        assert!(lock_state().staged_records.is_empty());
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
            0
        );
        rchat_disconnect();
        let g = lock_state();
        assert!(
            g.staged_records.is_empty() && g.state_key.is_none() && g.state_write.is_none(),
            "a full disconnect drops the account's store and staged records"
        );
    }

    #[test]
    fn device_signer_and_pin_ffi_validate_arguments() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        extern "C" fn fails(_: *const u8, _: usize, _: *mut u8) -> c_int {
            1
        }
        assert_eq!(rchat_set_device_signer(Some(fails)), -3, "uninitialised");
        assert_eq!(rchat_initialize(), 0);
        assert_eq!(rchat_set_device_signer(None), -1);
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(rchat_set_device_signer(Some(fails)), 0);
        assert!(lock_state().device_signer.is_some());
        assert!(
            crate::device_key::DeviceSigner::sign(&CDeviceSigner(fails), b"x").is_none(),
            "non-zero → unsigned"
        );
        extern "C" fn signs(_: *const u8, len: usize, out: *mut u8) -> c_int {
            // SAFETY: the core passes a 64-byte buffer.
            unsafe { std::ptr::write_bytes(out, len as u8, 64) };
            0
        }
        assert_eq!(
            crate::device_key::DeviceSigner::sign(&CDeviceSigner(signs), b"abc"),
            Some([3u8; 64])
        );
        let peer = crate::test_support::peer(0x71);
        let (_, pin) = crate::device_key::test_keys::soft_dk(1);
        let dks = crate::keyauth::sign_device_key(&peer.id, &pin.dk_pub, false).unwrap();
        let (i, d, good, bad) = (
            c(&peer.hex),
            c(&hex::encode(pin.dk_pub)),
            c(&hex::encode(dks)),
            c(&"00".repeat(64)),
        );
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), d.as_ptr(), 0, good.as_ptr()) },
            -2,
            "not pinned"
        );
        assert_eq!(rchat_last_error_code(), 12);
        let ak = c(&hex::encode(peer.bundle.identity_agreement_key));
        assert_eq!(unsafe { rchat_pin_peer_key(i.as_ptr(), ak.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), d.as_ptr(), 0, bad.as_ptr()) },
            -1,
            "bad dks"
        );
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), d.as_ptr(), 1, good.as_ptr()) },
            -1,
            "the hardware flag is signed"
        );
        assert_eq!(
            unsafe { rchat_pin_device_key(std::ptr::null(), d.as_ptr(), 0, good.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), c("04").as_ptr(), 0, good.as_ptr()) },
            -1,
            "short dk"
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert!(lock_state().staged.device_key(&peer.hex).is_none());
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), d.as_ptr(), 0, good.as_ptr()) },
            0
        );
        assert_eq!(lock_state().staged.device_key(&peer.hex), Some(&pin));
        assert!(unsafe { rchat_device_key_binding(std::ptr::null(), 65, 0) }.is_null());
        assert_eq!(rchat_last_error_code(), 9);
        assert!(unsafe { rchat_device_key_binding(pin.dk_pub.as_ptr(), 64, 0) }.is_null());
        let loaded = lock_state().identity.take();
        assert!(
            unsafe { rchat_device_key_binding(pin.dk_pub.as_ptr(), 65, 0) }.is_null(),
            "no client and no identity loaded: nothing to sign with"
        );
        assert_eq!(rchat_last_error_code(), 7);
        lock_state().identity = loaded;
        rchat_disconnect();
        assert!(
            lock_state().device_signer.is_some(),
            "the signer is kept, as the callbacks are"
        );
        lock_state().device_signer = None;
    }

    /// Task 9b review: the binding is a local signature, so it works with
    /// no connection and no client — by the identity loaded before the
    /// first connect (onboarding's card) — and verifies under that identity.
    #[test]
    fn device_key_binding_needs_no_connection() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert!(lock_state().client.is_none());
        let mut seed = [0u8; 64];
        assert_eq!(
            unsafe { rchat_generate_identity_seed(seed.as_mut_ptr(), 64) },
            1
        );
        let ik = lock_state()
            .identity
            .as_ref()
            .unwrap()
            .public_signing_key()
            .to_bytes();
        let (_, pin) = crate::device_key::test_keys::soft_dk(2);
        for hardware in [0, 1] {
            let p = unsafe { rchat_device_key_binding(pin.dk_pub.as_ptr(), 65, hardware) };
            assert!(!p.is_null(), "signed without a connection");
            let sig: [u8; 64] = hex::decode(s(p)).unwrap().try_into().unwrap();
            unsafe { rchat_free_string(p) };
            assert!(
                crate::keyauth::verify_device_key(&ik, &pin.dk_pub, hardware != 0, &sig).is_ok()
            );
        }
        // Not a P-256 point: refused, nothing signed.
        assert!(unsafe { rchat_device_key_binding([4u8; 65].as_ptr(), 65, 0) }.is_null());
        assert_eq!(rchat_last_error_code(), 9);
        lock_state().identity = None;
    }

    /// Task 9b re-review: the identity loaded before the first connect is
    /// wiped once a client is installed, by `rchat_disconnect` and by
    /// `rchat_clear_state`, so a deleted or retired identity never signs a
    /// device key again; before any of them, onboarding's binding works.
    #[test]
    fn the_loaded_identity_is_wiped_at_connect_disconnect_and_clear() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        let (_, pin) = crate::device_key::test_keys::soft_dk(3);
        let load = || {
            let mut seed = [0u8; 64];
            assert_eq!(
                unsafe { rchat_generate_identity_seed(seed.as_mut_ptr(), 64) },
                1
            );
            assert!(lock_state().identity.is_some());
        };
        let binds = || {
            let p = unsafe { rchat_device_key_binding(pin.dk_pub.as_ptr(), 65, 0) };
            let ok = !p.is_null();
            if ok {
                unsafe { rchat_free_string(p) };
            }
            ok
        };

        load();
        assert!(binds(), "onboarding: bound before the first connect");
        rchat_disconnect();
        assert!(lock_state().identity.is_none(), "rchat_disconnect wipes it");
        assert!(!binds());
        assert_eq!(rchat_last_error_code(), 7);

        load();
        assert_eq!(rchat_clear_state(), 0);
        assert!(
            lock_state().identity.is_none(),
            "rchat_clear_state wipes it"
        );
        assert!(!binds());

        load();
        assert_eq!(rchat_initialize(), 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        install_client(client.clone());
        assert!(
            lock_state().identity.is_none(),
            "a connected client replaces it"
        );
        assert!(
            !binds(),
            "a client without an identity: the retired one can't sign"
        );
        assert_eq!(rchat_last_error_code(), 7);
        rchat_disconnect();
    }

    /// The staged DK pin, and the signer, reach the client a connect builds.
    #[test]
    fn staged_device_keys_and_signer_move_into_the_new_client() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let peer = crate::test_support::peer(0x72);
        let (_, pin) = crate::device_key::test_keys::soft_dk(2);
        let dks = crate::keyauth::sign_device_key(&peer.id, &pin.dk_pub, true).unwrap();
        let (i, d, s_, ak) = (
            c(&peer.hex),
            c(&hex::encode(pin.dk_pub)),
            c(&hex::encode(dks)),
            c(&hex::encode(peer.bundle.identity_agreement_key)),
        );
        assert_eq!(unsafe { rchat_pin_peer_key(i.as_ptr(), ak.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rchat_pin_device_key(i.as_ptr(), d.as_ptr(), 1, s_.as_ptr()) },
            0
        );
        extern "C" fn fails(_: *const u8, _: usize, _: *mut u8) -> c_int {
            1
        }
        assert_eq!(rchat_set_device_signer(Some(fails)), 0);
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        assert!(client.inner.try_read().unwrap().device_signer.is_none());
        adopt_staged(&client);
        apply_store_and_signer(&client, DISCONNECT_GENERATION.load(Ordering::SeqCst));
        assert!(client.inner.try_read().unwrap().device_signer.is_some());
        let expected = crate::device_key::DevicePin {
            dk_pub: pin.dk_pub,
            hardware: true,
        };
        assert_eq!(
            client.export_peer_book().device_key(&peer.hex),
            Some(&expected)
        );
        rchat_disconnect();
        lock_state().device_signer = None;
    }

    /// A store set before connect is applied to the new client and the
    /// staged records are handed to it (taken from the global state).
    #[test]
    fn connect_applies_the_store_and_the_staged_records() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        extern "C" fn w(_: *const c_char, _: *const u8, _: usize) -> c_int {
            0
        }
        let key = [9u8; 32];
        assert_eq!(
            unsafe { rchat_set_state_store(key.as_ptr(), 32, Some(w)) },
            0
        );
        let k = c("meta");
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8; 20].as_ptr(), 20) },
            0
        );
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        apply_store_and_signer(&client, DISCONNECT_GENERATION.load(Ordering::SeqCst));
        assert!(
            lock_state().staged_records.is_empty(),
            "taken by the client"
        );
        let staged = client
            .inner
            .try_read()
            .unwrap()
            .state
            .as_ref()
            .map(|st| st.staged.clone());
        assert_eq!(staged, Some(vec![("meta".to_string(), vec![1u8; 20])]));
        assert_eq!(rchat_clear_state(), 0);
        rchat_disconnect();
    }

    /// `rchat_send_binary_using_id` validates like `rchat_send_binary_with_id`
    /// and reports "not connected" without a client.
    #[test]
    fn send_binary_using_id_checks_its_arguments() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        let (r, id) = (c(ID_A), c(&"ab".repeat(16)));
        let img = b"IMG1abc";
        let call = |r: *const c_char, d: *const u8, n: usize, m: *const c_char| unsafe {
            rchat_send_binary_using_id(r, d, n, m)
        };
        assert_eq!(call(std::ptr::null(), img.as_ptr(), 7, id.as_ptr()), 9);
        assert_eq!(call(r.as_ptr(), img.as_ptr(), 7, std::ptr::null()), 9);
        assert_eq!(call(r.as_ptr(), std::ptr::null(), 7, id.as_ptr()), 9);
        assert_eq!(call(r.as_ptr(), img.as_ptr(), 0, id.as_ptr()), 9);
        assert_eq!(call(r.as_ptr(), b"nope".as_ptr(), 4, id.as_ptr()), 9);
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(call(r.as_ptr(), img.as_ptr(), 7, id.as_ptr()), 7);
        assert_eq!(rchat_last_error_code(), 7);
    }

    /// The checked resend entries (H-1) validate their arguments like the
    /// same-id sends and report "not connected" without a client.
    #[test]
    fn resend_using_id_checks_its_arguments() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        let (r, t, id) = (c(ID_A), c("hi"), c(&"ab".repeat(16)));
        let text = |r: *const c_char, t: *const c_char, m: *const c_char| unsafe {
            rchat_resend_message_using_id(r, t, m)
        };
        assert_eq!(text(std::ptr::null(), t.as_ptr(), id.as_ptr()), 9);
        assert_eq!(text(r.as_ptr(), std::ptr::null(), id.as_ptr()), 9);
        assert_eq!(text(r.as_ptr(), t.as_ptr(), std::ptr::null()), 9);
        assert_eq!(text(r.as_ptr(), t.as_ptr(), id.as_ptr()), 7);
        let img = b"IMG1abc";
        let bin = |r: *const c_char, d: *const u8, n: usize, m: *const c_char| unsafe {
            rchat_resend_binary_using_id(r, d, n, m)
        };
        assert_eq!(bin(std::ptr::null(), img.as_ptr(), 7, id.as_ptr()), 9);
        assert_eq!(bin(r.as_ptr(), std::ptr::null(), 7, id.as_ptr()), 9);
        assert_eq!(bin(r.as_ptr(), b"nope".as_ptr(), 4, id.as_ptr()), 9);
        assert_eq!(bin(r.as_ptr(), img.as_ptr(), 7, id.as_ptr()), 7);
        assert_eq!(
            error_code_from_err(&RChatError::ResendRefused {
                identity: String::new()
            }),
            26
        );
    }

    /// What the recording writer saw: (key, bytes or None for NULL, len).
    type Write = (String, Option<Vec<u8>>, usize);
    static WRITES: StdMutex<Vec<Write>> = StdMutex::new(Vec::new());
    static WRITE_RESULT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    extern "C" fn rec_write(key: *const c_char, bytes: *const u8, len: usize) -> c_int {
        let body =
            (!bytes.is_null()).then(|| unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec());
        WRITES.lock().unwrap().push((s(key), body, len));
        WRITE_RESULT.load(Ordering::SeqCst)
    }
    fn writes() -> Vec<Write> {
        WRITES.lock().unwrap().clone()
    }
    fn current_sink() -> CStateSink {
        CStateSink {
            write: rec_write,
            generation: DISCONNECT_GENERATION.load(Ordering::SeqCst),
        }
    }

    /// The sink hands the writer the key and bytes, deletes with NULL and
    /// length 0, and turns a non-zero return into an error.
    #[test]
    fn state_sink_writes_deletes_and_reports_failure() {
        use crate::state_store::StateSink;
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        WRITES.lock().unwrap().clear();
        WRITE_RESULT.store(0, Ordering::SeqCst);
        let sink = current_sink();
        assert_eq!(sink.write("meta", &[1, 2, 3]), Ok(()));
        assert_eq!(sink.write("meta", &[]), Ok(()), "a delete");
        WRITE_RESULT.store(5, Ordering::SeqCst);
        assert_eq!(
            sink.write("meta", &[4]),
            Err("write failed (5)".to_string())
        );
        WRITE_RESULT.store(0, Ordering::SeqCst);
        assert_eq!(
            writes(),
            vec![
                ("meta".to_string(), Some(vec![1, 2, 3]), 3),
                ("meta".to_string(), None, 0),
                ("meta".to_string(), Some(vec![4]), 1),
            ]
        );
    }

    /// Review I2: once `rchat_disconnect` has run, no client of that account
    /// writes again: the sink refuses (generation), the live client is
    /// detached, and so is a client abandoned by an overtaken connect.
    #[test]
    fn a_disconnected_or_abandoned_client_never_writes_again() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        WRITE_RESULT.store(0, Ordering::SeqCst);
        let key = [5u8; 32];
        let with_store = || {
            assert_eq!(rchat_initialize(), 0);
            assert_eq!(
                unsafe { rchat_set_state_store(key.as_ptr(), 32, Some(rec_write)) },
                0
            );
            let client = RChatClient::new(ClientConfig::default()).unwrap();
            client.inner.try_write().unwrap().identity =
                Some(IdentityKeyPair::from_seed(&[0x31; 64]).unwrap());
            let generation = DISCONNECT_GENERATION.load(Ordering::SeqCst);
            apply_store_and_signer(&client, generation);
            WRITES.lock().unwrap().clear();
            client.inner.try_read().unwrap().persist_meta();
            assert_eq!(writes().len(), 1, "the current account's client writes");
            WRITES.lock().unwrap().clear();
            (client, generation)
        };

        // The live client, through rchat_disconnect.
        let (client, generation) = with_store();
        install_client(client.clone());
        rchat_disconnect();
        assert!(client.inner.try_read().unwrap().state.is_none(), "detached");
        client.inner.try_read().unwrap().persist_meta();
        client.retire();
        assert!(writes().is_empty(), "{:?}", writes());
        // (a) alone: a sink made before the disconnect refuses, unwritten.
        let stale = CStateSink {
            write: rec_write,
            generation,
        };
        assert!(crate::state_store::StateSink::write(&stale, "meta", &[1]).is_err());
        assert!(writes().is_empty());

        // A client abandoned by a connect a disconnect overtook.
        let (client, _) = with_store();
        abandon_client(&client);
        assert!(client.inner.try_read().unwrap().state.is_none(), "detached");
        client.inner.try_read().unwrap().persist_meta();
        assert!(writes().is_empty(), "{:?}", writes());
        rchat_disconnect();
    }

    /// At most `MAX_STAGED_RECORDS` records wait for a connect.
    #[test]
    fn staged_records_are_capped() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let k = c("meta");
        for _ in 0..MAX_STAGED_RECORDS {
            assert_eq!(
                unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
                0
            );
        }
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
            -2
        );
        assert_eq!(rchat_last_error_code(), 9);
        assert_eq!(lock_state().staged_records.len(), MAX_STAGED_RECORDS);
        assert_eq!(rchat_clear_state(), 0);
        assert_eq!(
            unsafe { rchat_import_state_record(k.as_ptr(), [1u8].as_ptr(), 1) },
            0,
            "room again after a clear"
        );
        rchat_disconnect();
    }

    static REENTRY: StdMutex<Vec<c_int>> = StdMutex::new(Vec::new());
    extern "C" fn reentering_write(_: *const c_char, _: *const u8, _: usize) -> c_int {
        let id = c(ID_A);
        let results = [
            rchat_initialize(),
            unsafe { rchat_has_session(id.as_ptr()) },
            unsafe { rchat_pin_peer_key(id.as_ptr(), c(AK_1).as_ptr()) },
            rchat_clear_state(),
            c_int::from(rchat_generate_identity().is_null()),
            rchat_last_error_code(),
        ];
        REENTRY.lock().unwrap().extend(results);
        0
    }
    extern "C" fn reentering_sign(_: *const u8, _: usize, _: *mut u8) -> c_int {
        let r = unsafe { rchat_device_key_binding([4u8; 65].as_ptr(), 65, 0) };
        REENTRY.lock().unwrap().push(c_int::from(r.is_null()));
        REENTRY.lock().unwrap().push(rchat_last_error_code());
        0
    }

    /// Review minor 8: an `rchat_*` call from inside the state writer or the
    /// device signer is refused (code 8) instead of deadlocking on a lock
    /// the core holds around them; the flag is cleared afterwards.
    #[test]
    fn rchat_calls_from_a_synchronous_callback_are_refused() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        REENTRY.lock().unwrap().clear();
        // The global state lock is held, as during `install_client_locked`:
        // without the guard, the first re-entry would deadlock here.
        let held = lock_state();
        let sink = CStateSink {
            write: reentering_write,
            generation: DISCONNECT_GENERATION.load(Ordering::SeqCst),
        };
        assert_eq!(
            crate::state_store::StateSink::write(&sink, "meta", &[1]),
            Ok(())
        );
        assert!(
            crate::device_key::DeviceSigner::sign(&CDeviceSigner(reentering_sign), b"m").is_some()
        );
        drop(held);
        assert_eq!(*REENTRY.lock().unwrap(), vec![8, 8, -1, 8, 1, 8, 1, 8]);
        assert!(!IN_SYNC_CALLBACK.with(std::cell::Cell::get), "cleared");
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0, "entries work again outside");
        rchat_disconnect();
    }

    /// Re-review 3: a store set on a client that a disconnect or a newer
    /// connect retired meanwhile is detached again; the current one keeps it.
    #[test]
    fn a_store_set_on_a_retired_client_is_detached_again() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        rchat_disconnect();
        assert_eq!(rchat_initialize(), 0);
        let stored = |c: &RChatClient| c.inner.try_read().unwrap().state.is_some();
        let set = |c: &Arc<RChatClient>, generation| {
            c.set_state_store(&[3u8; 32], Arc::new(current_sink()));
            keep_store_only_if_current(c, generation);
        };
        let live = RChatClient::new(ClientConfig::default()).unwrap();
        install_client(live.clone());
        let generation = DISCONNECT_GENERATION.load(Ordering::SeqCst);
        set(&live, generation);
        assert!(stored(&live), "the current client keeps it");
        // Replaced by a newer connect before the re-check.
        let replaced = RChatClient::new(ClientConfig::default()).unwrap();
        set(&replaced, generation);
        assert!(!stored(&replaced));
        // A disconnect ran before the re-check.
        rchat_disconnect();
        set(&live, generation);
        assert!(!stored(&live));
        live.retire();
    }
}
