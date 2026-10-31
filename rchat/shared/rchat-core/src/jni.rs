//! JNI layer for the Android app (Android sub-project 1, spec §6).
//!
//! One `Java_net_rchat_client_core_RChatCore_*` export per C FFI function
//! the app uses, each a thin conversion around the `rchat_*` function in
//! `ffi.rs`: same semantics, same JSON and string formats, same error codes.
//! A Java `null`, or a string the C side can't carry (an embedded NUL), is
//! passed on as a NULL pointer, so the C function itself records and returns
//! code 9. The one refusal made here, a null or empty out-array
//! (`IntArray(1)`, `Array<String?>(1)`), records code 9 the same way
//! before the C call is skipped, so `lastErrorCode()` is never stale.
//! Strings return as `jstring`; secrets cross as `ByteArray` and are wiped
//! here after use.
//! Plaintext crosses through buffers this layer wipes: outgoing strings are
//! read as UTF-16 into wiped buffers (`to_c`), and event JSON carrying
//! content is built and handed to Java the same way (`content_json`,
//! `utf16_of`). Copies the JVM makes are Kotlin's to manage.
//!
//! Events: Kotlin registers one handler object (`registerHandler`). The
//! core's 14 callbacks are C trampolines here that turn each one into
//! `onEvent(kind, json)` on that handler; the state writer and the device
//! signer call `writeStateRecord` / `signWithDeviceKey` on it synchronously.
//! Every export takes `(env, _class)` first, as rVPN's do (its AGENTS.md
//! "JNI Rules"). Nothing here logs.

use std::ffi::{c_char, c_int, CStr};
use std::sync::Arc;

use serde_json::json;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Conversions (no JVM needed; host-tested)
// ---------------------------------------------------------------------------

/// A NUL-terminated string for the C side, wiped when dropped.
pub(crate) struct SecretCString(zeroize::Zeroizing<Vec<u8>>);

impl SecretCString {
    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }
}

/// A Java string's UTF-16 units as a C string, for the C side. Written into
/// one buffer sized for the worst case (3 UTF-8 bytes a unit, plus the NUL),
/// so it never reallocates and leaves no unwiped copy. None (passed as NULL)
/// for a Java null or a string with an embedded NUL, so the C function
/// records its own code; an unpaired surrogate becomes U+FFFD.
pub(crate) fn to_c(units: Option<&[u16]>) -> Option<SecretCString> {
    let units = units?;
    let capacity = units.len().checked_mul(3)?.checked_add(1)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    let mut utf8 = zeroize::Zeroizing::new([0u8; 4]);
    for ch in char::decode_utf16(units.iter().copied()) {
        let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        if ch == '\0' {
            return None;
        }
        out.extend_from_slice(ch.encode_utf8(&mut utf8[..]).as_bytes());
    }
    out.push(0);
    Some(SecretCString(out))
}

/// The pointer the C side gets: NULL for None.
pub(crate) fn ptr(c: &Option<SecretCString>) -> *const c_char {
    c.as_ref().map_or(std::ptr::null(), SecretCString::as_ptr)
}

/// `s` as UTF-16 for Java's `NewString`, in a wiped buffer sized up front
/// (a string never has more UTF-16 units than UTF-8 bytes), so it never
/// reallocates.
pub(crate) fn utf16_of(s: &str) -> zeroize::Zeroizing<Vec<u16>> {
    let mut units = zeroize::Zeroizing::new(Vec::with_capacity(s.len()));
    units.extend(s.encode_utf16());
    units
}

/// Whether a Kotlin out-array (`IntArray(1)`, `Array<String?>(1)`) of this
/// length has room for its result.
/// A PCM array is exactly one 20 ms frame (`FRAME_SAMPLES`).
pub(crate) fn pcm_array_fits(len: i32) -> bool {
    usize::try_from(len) == Ok(crate::call::FRAME_SAMPLES)
}

pub(crate) fn out_array_fits(len: i32) -> bool {
    len >= 1
}

/// A string the C side returned: copied out, then wiped and freed by
/// `rchat_free_string`. NULL is None.
pub(crate) fn take_c(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-NULL string returned by this library, not yet freed.
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned);
    // SAFETY: freed once, here; never used afterwards.
    unsafe { crate::ffi::rchat_free_string(p) };
    s
}

/// Bytes that may be secret (the identity seed, the state key): zeroed in
/// place by `wipe` and again when dropped.
pub(crate) struct SecretBytes(zeroize::Zeroizing<Box<[u8]>>);

impl SecretBytes {
    pub(crate) fn zeroed(len: usize) -> Self {
        Self(zeroize::Zeroizing::new(vec![0u8; len].into_boxed_slice()))
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_slice(b: &[u8]) -> Self {
        Self(zeroize::Zeroizing::new(b.to_vec().into_boxed_slice()))
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn wipe(&mut self) {
        self.0.zeroize();
    }
}

/// Generates an identity seed into `out` (64 bytes) through a buffer that
/// is wiped before returning. The C function's result (1 written). The
/// export does the same with a Java array; this form is host-tested.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn generate_seed_into(out: &mut [u8]) -> c_int {
    let mut buf = SecretBytes::zeroed(out.len());
    // SAFETY: `buf` is valid for `len` writes.
    let rc = unsafe { crate::ffi::rchat_generate_identity_seed(buf.as_mut_ptr(), buf.len()) };
    if rc == 1 {
        out.copy_from_slice(buf.as_slice());
    }
    buf.wipe();
    rc
}

/// Takes the prepared rotation seed into `out` through a buffer that is
/// wiped before returning, as `takeRotationSeed` does with a Java array.
/// The C function's result (1 written, 0 nothing prepared, -1 refused);
/// `out` is untouched unless 1. Host-tested form of the export.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn take_rotation_seed_into(out: &mut [u8]) -> c_int {
    let mut buf = SecretBytes::zeroed(out.len());
    let p = if out.is_empty() {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr()
    };
    // SAFETY: `buf` is valid for `len` writes (NULL when empty).
    let rc = unsafe { crate::ffi::rchat_take_rotation_seed(p, buf.len()) };
    if rc == 1 {
        out.copy_from_slice(buf.as_slice());
    }
    buf.wipe();
    rc
}

/// A C string argument the core passed, borrowed for content fields
/// (`content_json`): no copy is made, so nothing is left to wipe. "" for
/// NULL or, never from the core, invalid UTF-8 (a lossy decode would copy).
fn borrowed_text<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    // SAFETY: the core passes NUL-terminated strings valid for the call.
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

/// A C string argument copied into an owned `String` for serde (`json!`),
/// lossily ("" for NULL): only for fields that are not content (ids, keys,
/// codes, errors), since the copy is not wiped.
fn owned_lossy(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the core passes NUL-terminated strings valid for the call.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// The handler slot
// ---------------------------------------------------------------------------

/// `onEvent` kinds: one per C callback, in `rchat_register_callbacks`
/// argument order. Kotlin mirrors them in `CoreEventKind` (parity-tested).
pub(crate) mod kind {
    pub const MESSAGE: i32 = 1;
    pub const STATE: i32 = 2;
    pub const ERROR: i32 = 3;
    pub const CIRCUIT_ESTABLISHED: i32 = 4;
    pub const MESSAGE_DELIVERED: i32 = 5;
    pub const RECONNECT: i32 = 6;
    pub const PEER_KEY: i32 = 7;
    pub const MESSAGE_REQUEST: i32 = 8;
    pub const MESSAGE_RECEIPT: i32 = 9;
    pub const PEER_ROTATED: i32 = 10;
    pub const STATUS: i32 = 11;
    pub const FILE: i32 = 12;
    pub const TIMER_CHANGED: i32 = 13;
    pub const FILE_BLOCKED: i32 = 14;
}

/// What the core's callbacks reach: the Kotlin handler on Android, a
/// recorder in tests.
pub(crate) trait EventSink: Send + Sync {
    fn on_event(&self, kind: i32, json: &str);
    /// The raw 64-byte signature, or None to leave the notice unsigned.
    fn sign(&self, msg: &[u8]) -> Option<[u8; 64]>;
    /// 0 when durably written (None: deleted); anything else a failure.
    fn write_state(&self, key: &str, sealed: Option<&[u8]>) -> i32;
}

static SINK: parking_lot::RwLock<Option<Arc<dyn EventSink>>> = parking_lot::const_rwlock(None);

/// Installs (or, with None, removes) the handler. The previous one is
/// dropped after the lock is released (a `GlobalRef` drop attaches).
///
/// A callback that already took the previous handler (`current_sink`) can
/// still deliver one event to it after a clear or a replace: Kotlin's
/// dispatcher generation (Task 5) must drop such late events.
pub(crate) fn set_sink(sink: Option<Arc<dyn EventSink>>) {
    let old = std::mem::replace(&mut *SINK.write(), sink);
    drop(old);
}

fn current_sink() -> Option<Arc<dyn EventSink>> {
    SINK.read().clone()
}

/// An event for the current handler; dropped when there is none.
fn emit(kind: i32, value: serde_json::Value) {
    if let Some(sink) = current_sink() {
        sink.on_event(kind, &value.to_string());
    }
}

/// A content field of an event, written into the wiped buffer.
enum Content<'a> {
    /// Raw bytes, hex-encoded here (a received file).
    Raw(&'a [u8]),
    /// Already hex, as the core's `on_message` passes it: copied as is
    /// (anything that is not hex, never from the core, crosses as "").
    Hex(&'a [u8]),
    /// Text (an intro, a file name), JSON-escaped here.
    Text(&'a str),
}

impl Content<'_> {
    /// The most bytes its JSON value can take, quotes included (an escape
    /// such as `\u0001` is at most 6 bytes for 1).
    fn max_len(&self) -> usize {
        let n = match self {
            Content::Raw(b) => b.len().saturating_mul(2),
            Content::Hex(h) => h.len(),
            Content::Text(t) => t.len().saturating_mul(6),
        };
        n.saturating_add(2)
    }
}

/// The bytes the buffer for `head` (a JSON object) plus `fields` needs:
/// each field adds a comma, its quoted key, a colon and its value.
fn content_json_capacity(head: &str, fields: &[(&str, Content)]) -> usize {
    fields.iter().fold(head.len(), |n, (key, c)| {
        n.saturating_add(key.len() + 4).saturating_add(c.max_len())
    })
}

/// `head`'s fields (a JSON object serialised by serde, holding no content)
/// followed by the content `fields`, written into one buffer sized up front
/// so it never reallocates, and wiped when dropped. None if `head` is not
/// an object.
fn content_json(head: &str, fields: &[(&str, Content)]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let open = head.strip_suffix('}')?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(content_json_capacity(head, fields)));
    out.extend_from_slice(open.as_bytes());
    let mut first = open.len() <= 1;
    for (key, content) in fields {
        if !first {
            out.push(b',');
        }
        first = false;
        out.push(b'"');
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b"\":");
        match content {
            Content::Raw(b) => {
                out.push(b'"');
                for &byte in *b {
                    out.push(DIGITS[usize::from(byte >> 4)]);
                    out.push(DIGITS[usize::from(byte & 0x0f)]);
                }
                out.push(b'"');
            }
            Content::Hex(h) => {
                out.push(b'"');
                if h.iter().all(u8::is_ascii_hexdigit) {
                    out.extend_from_slice(h);
                }
                out.push(b'"');
            }
            // serde writes the escaped string straight into the buffer.
            Content::Text(t) => serde_json::to_writer(&mut *out, t).ok()?,
        }
    }
    out.push(b'}');
    Some(out)
}

/// An event carrying content: built by `content_json`, so this layer
/// leaves no unwiped copy of it (the Java side builds its string from a
/// wiped UTF-16 buffer too, `utf16_of`).
fn emit_with_content(kind: i32, head: serde_json::Value, fields: &[(&str, Content)]) {
    let Some(sink) = current_sink() else { return };
    let Some(json) = content_json(&head.to_string(), fields) else {
        return;
    };
    if let Ok(json) = std::str::from_utf8(&json) {
        sink.on_event(kind, json);
    }
}

// ---------------------------------------------------------------------------
// Trampolines: the C callbacks the core calls
// ---------------------------------------------------------------------------

extern "C" fn t_message(
    s: *const c_char,
    c: *const c_char,
    ts: u64,
    id: *const c_char,
    k: c_int,
    e: u32,
) {
    let head = json!({"sender": owned_lossy(s), "timestamp_ms": ts, "message_id": owned_lossy(id), "kind": k, "expire_secs": e});
    let content = Content::Hex(borrowed_text(c).as_bytes());
    emit_with_content(kind::MESSAGE, head, &[("content_hex", content)]);
}
extern "C" fn t_state(state: c_int) {
    emit(kind::STATE, json!({ "state": state }));
}
extern "C" fn t_error(m: *const c_char) {
    emit(kind::ERROR, json!({ "message": owned_lossy(m) }));
}
extern "C" fn t_circuit(p: *const c_char, initiator: c_int) {
    emit(
        kind::CIRCUIT_ESTABLISHED,
        json!({"peer": owned_lossy(p), "initiator": initiator != 0}),
    );
}
extern "C" fn t_delivered(id: *const c_char) {
    emit(
        kind::MESSAGE_DELIVERED,
        json!({ "message_id": owned_lossy(id) }),
    );
}
extern "C" fn t_reconnect() {
    emit(kind::RECONNECT, json!({}));
}
extern "C" fn t_peer_key(p: *const c_char, code: c_int, ak: *const c_char) {
    emit(
        kind::PEER_KEY,
        json!({"peer": owned_lossy(p), "code": code, "agreement": owned_lossy(ak)}),
    );
}
#[allow(clippy::too_many_arguments)]
extern "C" fn t_request(
    id: *const c_char,
    ak: *const c_char,
    kem: *const c_char,
    hour: u64,
    iid: *const c_char,
    intro: *const c_char,
    at: u64,
    kv: u32,
) {
    let head = json!({"identity": owned_lossy(id), "agreement": owned_lossy(ak), "kem": owned_lossy(kem), "issued_hour": hour, "intro_id": owned_lossy(iid), "intro_sent_at_ms": at, "key_version": kv});
    let intro = Content::Text(borrowed_text(intro));
    emit_with_content(kind::MESSAGE_REQUEST, head, &[("intro_text", intro)]);
}
extern "C" fn t_receipt(s: *const c_char, id: *const c_char, k: c_int) {
    emit(
        kind::MESSAGE_RECEIPT,
        json!({"sender": owned_lossy(s), "message_id": owned_lossy(id), "kind": k}),
    );
}
extern "C" fn t_rotated(
    o: *const c_char,
    n: *const c_char,
    ak: *const c_char,
    kem: *const c_char,
    v: u32,
) {
    emit(
        kind::PEER_ROTATED,
        json!({"old": owned_lossy(o), "new": owned_lossy(n), "agreement": owned_lossy(ak), "kem": owned_lossy(kem), "version": v}),
    );
}
extern "C" fn t_status(k: c_int, p: *const c_char, id: *const c_char, detail: c_int) {
    emit(
        kind::STATUS,
        json!({"kind": k, "peer": owned_lossy(p), "message_id": owned_lossy(id), "detail": detail}),
    );
}
/// A received file: the bytes cross as hex, as a binary message body does
/// (`content_hex`); they are valid only for this call, and the core wipes
/// its own copy when it returns.
#[allow(clippy::too_many_arguments)]
extern "C" fn t_file(
    s: *const c_char,
    id: *const c_char,
    name: *const c_char,
    mime: *const c_char,
    e: u32,
    b: *const u8,
    len: usize,
    ts: u64,
) {
    let content = if b.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: the core passes `len` readable bytes, valid for the call.
        unsafe { std::slice::from_raw_parts(b, len) }
    };
    let head = json!({"sender": owned_lossy(s), "message_id": owned_lossy(id), "mime": owned_lossy(mime), "expire_secs": e, "len": len, "timestamp_ms": ts});
    let fields = [
        ("name", Content::Text(borrowed_text(name))),
        ("content_hex", Content::Raw(content)),
    ];
    emit_with_content(kind::FILE, head, &fields);
}
extern "C" fn t_timer(p: *const c_char, secs: u32, at: u64, by_me: c_int) {
    emit(
        kind::TIMER_CHANGED,
        json!({"peer": owned_lossy(p), "secs": secs, "changed_at_ms": at, "by_me": by_me != 0}),
    );
}

/// A received file the core blocked: no bytes; the name is content.
extern "C" fn t_file_blocked(
    s: *const c_char,
    id: *const c_char,
    name: *const c_char,
    e: u32,
    ts: u64,
) {
    let head = json!({"sender": owned_lossy(s), "message_id": owned_lossy(id), "expire_secs": e, "timestamp_ms": ts});
    emit_with_content(
        kind::FILE_BLOCKED,
        head,
        &[("name", Content::Text(borrowed_text(name)))],
    );
}

/// The state writer (`StateWriteFn`). Synchronous, core locked: never calls
/// `rchat_*`. -1 without a handler.
extern "C" fn t_state_write(key: *const c_char, sealed: *const u8, len: usize) -> c_int {
    let Some(sink) = current_sink() else {
        return -1;
    };
    let bytes = if sealed.is_null() || len == 0 {
        None
    } else {
        // SAFETY: the core passes `len` readable bytes, valid for the call.
        Some(unsafe { std::slice::from_raw_parts(sealed, len) })
    };
    sink.write_state(&owned_lossy(key), bytes)
}

/// The device signer (`DeviceSignFn`). Synchronous, core locked: never
/// calls `rchat_*`. -1 (notice unsigned) without a handler or signature.
extern "C" fn t_device_sign(msg: *const u8, len: usize, out: *mut u8) -> c_int {
    if msg.is_null() || out.is_null() {
        return -1;
    }
    let Some(sink) = current_sink() else {
        return -1;
    };
    // SAFETY: the core passes `len` readable bytes, valid for the call.
    let m = unsafe { std::slice::from_raw_parts(msg, len) };
    match sink.sign(m) {
        Some(sig) => {
            // SAFETY: the core's buffer holds 64 bytes (`DeviceSignFn`).
            unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), out, 64) };
            0
        }
        None => -1,
    }
}

/// Every trampoline, typed as the core expects them.
pub(crate) struct Trampolines {
    pub message: crate::ffi::MessageFn,
    pub state: extern "C" fn(c_int),
    pub error: extern "C" fn(*const c_char),
    pub circuit: extern "C" fn(*const c_char, c_int),
    pub delivered: extern "C" fn(*const c_char),
    pub reconnect: extern "C" fn(),
    pub peer_key: extern "C" fn(*const c_char, c_int, *const c_char),
    pub request: crate::ffi::MessageRequestFn,
    pub receipt: extern "C" fn(*const c_char, *const c_char, c_int),
    pub rotated: crate::ffi::PeerRotatedFn,
    pub status: extern "C" fn(c_int, *const c_char, *const c_char, c_int),
    pub file: crate::ffi::FileReceivedFn,
    pub timer: crate::ffi::TimerChangedFn,
    pub file_blocked: crate::ffi::FileBlockedFn,
    pub state_write: crate::ffi::StateWriteFn,
    pub device_sign: crate::ffi::DeviceSignFn,
}

pub(crate) fn trampolines() -> Trampolines {
    Trampolines {
        message: t_message,
        state: t_state,
        error: t_error,
        circuit: t_circuit,
        delivered: t_delivered,
        reconnect: t_reconnect,
        peer_key: t_peer_key,
        request: t_request,
        receipt: t_receipt,
        rotated: t_rotated,
        status: t_status,
        file: t_file,
        timer: t_timer,
        file_blocked: t_file_blocked,
        state_write: t_state_write,
        device_sign: t_device_sign,
    }
}

/// Registers the 14 event trampolines with the core (`registerHandler`).
pub(crate) fn register_trampolines() -> c_int {
    let t = trampolines();
    crate::ffi::rchat_register_callbacks(
        Some(t.message),
        Some(t.state),
        Some(t.error),
        Some(t.circuit),
        Some(t.delivered),
        Some(t.reconnect),
        Some(t.peer_key),
        Some(t.request),
        Some(t.receipt),
        Some(t.rotated),
        Some(t.status),
        Some(t.file),
        Some(t.timer),
        Some(t.file_blocked),
    )
}

// ---------------------------------------------------------------------------
// The Kotlin handler (JNI)
// ---------------------------------------------------------------------------

/// The Kotlin `CoreEventHandler` methods the trampolines call, as (name, JVM
/// descriptor). The trampolines read these; the parity test checks them
/// against `interface CoreEventHandler` in `RChatCore.kt`, so a drifted
/// Kotlin signature fails a test instead of failing at run time.
pub(crate) const HANDLER_ON_EVENT: (&str, &str) = ("onEvent", "(ILjava/lang/String;)V");
pub(crate) const HANDLER_SIGN: (&str, &str) = ("signWithDeviceKey", "([B)[B");
pub(crate) const HANDLER_WRITE_STATE: (&str, &str) =
    ("writeStateRecord", "(Ljava/lang/String;[B)I");
/// All three, for the parity test.
#[cfg(test)]
pub(crate) const HANDLER_METHODS: [(&str, &str); 3] =
    [HANDLER_ON_EVENT, HANDLER_SIGN, HANDLER_WRITE_STATE];

/// The JNI name → C function table: one row per Kotlin `external fun`.
/// The parity test (`jni_parity_tests`) checks it against the exports,
/// `ffi.rs` and `RChatCore.kt`; nothing else reads it, so it exists only in
/// test builds.
#[cfg(test)]
pub(crate) const JNI_TO_FFI: &[(&str, &str)] = &[
    ("initialize", "rchat_initialize"),
    ("connectWithSeed", "rchat_connect_with_seed"),
    ("disconnect", "rchat_disconnect"),
    ("disconnectTransportOnly", "rchat_disconnect_transport_only"),
    ("reconnect", "rchat_reconnect"),
    ("getConnectionState", "rchat_get_connection_state"),
    ("lastErrorCode", "rchat_last_error_code"),
    ("processPending", "rchat_process_pending"),
    ("registerHandler", "rchat_register_callbacks"),
    ("setStateStore", "rchat_set_state_store"),
    ("importStateRecord", "rchat_import_state_record"),
    ("clearState", "rchat_clear_state"),
    ("refreshTrustStore", "rchat_refresh_trust_store"),
    ("setCoverTraffic", "rchat_set_cover_traffic"),
    ("setBackgroundKeepalive", "rchat_set_background_keepalive"),
    ("callPlace", "rchat_call_place"),
    ("callAnswer", "rchat_call_answer"),
    ("callDecline", "rchat_call_decline"),
    ("callEnd", "rchat_call_end"),
    ("callSetMuted", "rchat_call_set_muted"),
    ("callPushPcm", "rchat_call_push_pcm"),
    ("callPullPcm", "rchat_call_pull_pcm"),
    ("callPollEvent", "rchat_call_poll_event"),
    ("callPlaceVideo", "rchat_call_place_video"),
    ("callVideoSetCamera", "rchat_call_video_set_camera"),
    ("callVideoRespond", "rchat_call_video_respond"),
    ("callVideoConfigure", "rchat_call_video_configure"),
    ("callVideoSetThermal", "rchat_call_video_set_thermal"),
    ("callVideoEncoderHint", "rchat_call_video_encoder_hint"),
    ("callVideoSend", "rchat_call_video_send"),
    ("callVideoTake", "rchat_call_video_take"),
    ("callVideoNeedKeyframe", "rchat_call_video_need_keyframe"),
    ("setDeviceSigner", "rchat_set_device_signer"),
    ("generateIdentitySeed", "rchat_generate_identity_seed"),
    ("getIdentityPubkey", "rchat_get_identity_pubkey"),
    ("getAgreementPubkey", "rchat_get_agreement_pubkey"),
    ("getKemPubkey", "rchat_get_kem_pubkey"),
    ("kemPubkeyFromSeed", "rchat_kem_pubkey_from_seed"),
    ("getBundleSignature", "rchat_get_bundle_signature"),
    (
        "bundleSignatureFromSeed",
        "rchat_bundle_signature_from_seed",
    ),
    ("verifyCardBundle", "rchat_verify_card_bundle"),
    ("deviceKeyBinding", "rchat_device_key_binding"),
    ("verifyDeviceKeyBinding", "rchat_verify_device_key_binding"),
    ("pinDeviceKey", "rchat_pin_device_key"),
    ("setRecipient", "rchat_set_recipient"),
    ("pinPeerKey", "rchat_pin_peer_key"),
    ("unpinPeerKey", "rchat_unpin_peer_key"),
    ("setPeerBlocked", "rchat_set_peer_blocked"),
    ("peerKeyState", "rchat_peer_key_state"),
    ("setPeerKeyVersion", "rchat_set_peer_key_version"),
    ("requestCircuit", "rchat_request_circuit"),
    ("hasSession", "rchat_has_session"),
    ("setIntro", "rchat_set_intro"),
    ("setIntroWithId", "rchat_set_intro_with_id"),
    ("sendMessageWithId", "rchat_send_message_with_id"),
    ("sendMessageUsingId", "rchat_send_message_using_id"),
    ("retryMessageUsingId", "rchat_retry_message_using_id"),
    ("resendMessageUsingId", "rchat_resend_message_using_id"),
    ("markMessageSeen", "rchat_mark_message_seen"),
    ("sendReadReceipt", "rchat_send_read_receipt"),
    ("safetyNumber", "rchat_safety_number"),
    (
        "markSafetyNumberCompared",
        "rchat_mark_safety_number_compared",
    ),
    ("compareSafetyNumberQr", "rchat_compare_safety_number_qr"),
    ("canonicalOrigin", "rchat_canonical_origin"),
    ("parseRelayInvite", "rchat_parse_relay_invite"),
    ("parseRelayInviteDev", "rchat_parse_relay_invite_dev"),
    ("formatRelayInvite", "rchat_format_relay_invite"),
    ("relayPinInfo", "rchat_relay_pin_info"),
    ("prepareRotation", "rchat_prepare_rotation"),
    ("takeRotationSeed", "rchat_take_rotation_seed"),
    ("announceRotation", "rchat_announce_rotation"),
    ("sendBinaryWithId", "rchat_send_binary_with_id"),
    ("retryBinaryUsingId", "rchat_retry_binary_using_id"),
    ("resendBinaryUsingId", "rchat_resend_binary_using_id"),
    ("sendFile", "rchat_send_file"),
    ("retryFileUsingId", "rchat_retry_file_using_id"),
    ("resendFileUsingId", "rchat_resend_file_using_id"),
    ("sanitiseFileName", "rchat_sanitise_file_name"),
    ("fileCheck", "rchat_file_check"),
    ("mediaCheck", "rchat_media_check"),
    ("verifyEd25519", "rchat_verify_ed25519"),
    ("setDisappearingTimerEx", "rchat_set_disappearing_timer_ex"),
    ("disappearingTimer", "rchat_disappearing_timer"),
    ("forgetMessage", "rchat_forget_message"),
];

/// The frame length of a `callVideoSend` range, or None when `offset` or
/// `size` is negative, `size` is 0, or `offset + size` passes `cap`.
pub(crate) fn send_range_ok(offset: i32, size: i32, cap: usize) -> Option<usize> {
    let off = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok().filter(|l| *l > 0)?;
    (off.checked_add(len)? <= cap).then_some(len)
}

#[cfg(any(target_os = "android", test))]
#[allow(non_snake_case, clippy::too_many_arguments)]
mod exports {
    use super::*;
    use ::jni::errors::{Error, JniError};
    use ::jni::objects::{
        AsJArrayRaw, GlobalRef, JByteArray, JByteBuffer, JIntArray, JObject, JObjectArray,
        JShortArray, JString, JValue,
    };
    use ::jni::sys::{
        jboolean, jbyteArray, jclass, jint, jintArray, jlong, jobject, jobjectArray, jshortArray,
        jsize, jstring,
    };
    use ::jni::{JNIEnv, JavaVM};

    type Env = *mut ::jni::sys::JNIEnv;

    /// The `jstring` an export returns on failure.
    const NO_STRING: jstring = std::ptr::null_mut();

    /// The Kotlin `CoreEventHandler`, held as a global reference.
    struct JavaSink {
        vm: JavaVM,
        handler: GlobalRef,
    }

    fn clear_exception(env: &mut JNIEnv) {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }

    /// A Java string made from `s` through one wiped UTF-16 buffer
    /// (`utf16_of`) and raw `NewString`, not through `JNIString`, whose
    /// modified-UTF-8 copies are never wiped.
    fn new_string_wiped<'l>(env: &mut JNIEnv<'l>, s: &str) -> ::jni::errors::Result<JString<'l>> {
        let units = utf16_of(s);
        let len =
            jsize::try_from(units.len()).map_err(|_| Error::JniCall(JniError::InvalidArguments))?;
        let raw = env.get_native_interface();
        // SAFETY: `raw` is this thread's valid env; the table is the JVM's.
        let new_string =
            unsafe { (**raw).NewString }.ok_or(Error::JNIEnvMethodNotFound("NewString"))?;
        // SAFETY: `units` holds `len` UTF-16 units; NewString copies them.
        let j = unsafe { new_string(raw, units.as_ptr(), len) };
        if env.exception_check()? {
            return Err(Error::JavaException);
        }
        if j.is_null() {
            return Err(Error::NullPtr("NewString returned null"));
        }
        // SAFETY: a new local reference, owned by the current local frame.
        Ok(unsafe { JString::from_raw(j) })
    }

    /// A Java `byte[]` holding `b`; refused when its length is not a `jsize`
    /// (`byte_array_from_slice` would truncate it).
    fn byte_array<'l>(env: &mut JNIEnv<'l>, b: &[u8]) -> ::jni::errors::Result<JByteArray<'l>> {
        if jsize::try_from(b.len()).is_err() {
            return Err(Error::JniCall(JniError::InvalidArguments));
        }
        env.byte_array_from_slice(b)
    }

    impl EventSink for JavaSink {
        fn on_event(&self, kind: i32, json: &str) {
            // The core's callback thread lives as long as the client:
            // attached once, permanently; every call in its own local frame.
            let Ok(mut env) = self.vm.attach_current_thread_permanently() else {
                return;
            };
            let _ = env.with_local_frame(8, |env| -> ::jni::errors::Result<()> {
                let s = new_string_wiped(env, json)?;
                env.call_method(
                    self.handler.as_obj(),
                    HANDLER_ON_EVENT.0,
                    HANDLER_ON_EVENT.1,
                    &[JValue::Int(kind), JValue::Object(&JObject::from(s))],
                )?;
                Ok(())
            });
            clear_exception(&mut env);
        }

        fn sign(&self, msg: &[u8]) -> Option<[u8; 64]> {
            let mut env = self.vm.attach_current_thread_permanently().ok()?;
            let out = env.with_local_frame(8, |env| -> ::jni::errors::Result<Option<[u8; 64]>> {
                let arr = JObject::from(byte_array(env, msg)?);
                let ret = env
                    .call_method(
                        self.handler.as_obj(),
                        HANDLER_SIGN.0,
                        HANDLER_SIGN.1,
                        &[JValue::Object(&arr)],
                    )?
                    .l()?;
                if ret.is_null() {
                    return Ok(None);
                }
                let ret = JByteArray::from(ret);
                if env.get_array_length(&ret)? != 64 {
                    return Ok(None);
                }
                let mut sig = [0i8; 64];
                env.get_byte_array_region(&ret, 0, &mut sig)?;
                Ok(Some(sig.map(|b| b as u8)))
            });
            clear_exception(&mut env);
            out.ok().flatten()
        }

        fn write_state(&self, key: &str, sealed: Option<&[u8]>) -> i32 {
            if sealed.is_some_and(|b| jsize::try_from(b.len()).is_err()) {
                return -1;
            }
            let Ok(mut env) = self.vm.attach_current_thread_permanently() else {
                return -1;
            };
            let r = env.with_local_frame(8, |env| -> ::jni::errors::Result<i32> {
                let k = JObject::from(env.new_string(key)?);
                let arr = match sealed {
                    Some(b) => JObject::from(byte_array(env, b)?),
                    None => JObject::null(),
                };
                env.call_method(
                    self.handler.as_obj(),
                    HANDLER_WRITE_STATE.0,
                    HANDLER_WRITE_STATE.1,
                    &[JValue::Object(&k), JValue::Object(&arr)],
                )?
                .i()
            });
            clear_exception(&mut env);
            r.unwrap_or(-1)
        }
    }

    /// One export call's JNI side. A JNI step that fails (no env, a JNI
    /// error, a pending Java exception, a missing or short out-array) fails
    /// the call: before the C call the export returns -1 or null without
    /// calling C; after it, no further JNI call is made. A pending exception
    /// is thrown in Kotlin when the export returns.
    struct Jni<'a> {
        env: Option<JNIEnv<'a>>,
        failed: bool,
    }

    impl<'a> Jni<'a> {
        /// # Safety
        ///
        /// `raw` is the env the JVM passed for this call.
        unsafe fn new(raw: Env) -> Self {
            // SAFETY: the JVM passes a valid env pointer for this call.
            let env = unsafe { JNIEnv::from_raw(raw) }.ok();
            Self {
                failed: env.is_none(),
                env,
            }
        }

        /// Whether every JNI step so far succeeded.
        fn ok(&self) -> bool {
            !self.failed
        }

        /// The env, while nothing has failed.
        fn env(&mut self) -> Option<&mut JNIEnv<'a>> {
            if self.failed {
                return None;
            }
            self.env.as_mut()
        }

        /// A JNI step's outcome: None, failing the call, on an error or a
        /// pending exception.
        fn check<T>(&mut self, r: ::jni::errors::Result<T>) -> Option<T> {
            let pending = self
                .env
                .as_mut()
                .map_or(true, |e| e.exception_check().unwrap_or(true));
            match r {
                Ok(v) if !pending => Some(v),
                _ => {
                    self.failed = true;
                    None
                }
            }
        }

        /// A Java String argument for the C side, read as UTF-16 into wiped
        /// buffers (`to_c`): None (NULL) for null or an embedded NUL.
        ///
        /// # Safety
        ///
        /// `raw` is null or a String reference the JVM passed for this call.
        unsafe fn s(&mut self, raw: jstring) -> Option<SecretCString> {
            if raw.is_null() {
                return None;
            }
            let sys = self.env()?.get_native_interface();
            // SAFETY: `sys` is this thread's valid env; the table is the JVM's.
            let (Some(length), Some(region)) =
                (unsafe { ((**sys).GetStringLength, (**sys).GetStringRegion) })
            else {
                self.failed = true;
                return None;
            };
            // SAFETY: `raw` is a live String reference.
            let len = unsafe { length(sys, raw) };
            let Ok(n) = usize::try_from(len) else {
                self.failed = true;
                return None;
            };
            let mut units = zeroize::Zeroizing::new(vec![0u16; n]);
            // SAFETY: `units` holds `len` UTF-16 units.
            unsafe { region(sys, raw, 0, len, units.as_mut_ptr()) };
            self.check(Ok(()))?;
            to_c(Some(&units))
        }

        /// A Java byte[] argument, read straight into a wiped buffer.
        ///
        /// # Safety
        ///
        /// `raw` is null or a byte[] reference the JVM passed for this call.
        unsafe fn bytes(&mut self, raw: jbyteArray) -> Option<SecretBytes> {
            if raw.is_null() {
                return None;
            }
            // SAFETY: a local reference the JVM passed for this call.
            let a = unsafe { JByteArray::from_raw(raw) };
            let len = self.env()?.get_array_length(&a);
            let Ok(len) = usize::try_from(self.check(len)?) else {
                self.failed = true;
                return None;
            };
            let mut buf = SecretBytes::zeroed(len);
            // SAFETY: `buf` holds `len` bytes; i8 and u8 have the same layout.
            let view =
                unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<i8>(), len) };
            let r = self.env()?.get_byte_array_region(&a, 0, view);
            self.check(r)?;
            Some(buf)
        }

        /// Checks an out-array before the C call: it must be non-null with
        /// room for its result (`out_array_fits`), or the call fails with
        /// code 9 recorded, as the C side records for a bad argument.
        fn out_array<'o>(&mut self, a: &impl AsJArrayRaw<'o>) {
            if self.failed {
                return;
            }
            let fits = if a.as_ref().is_null() {
                false
            } else {
                let Some(env) = self.env() else { return };
                let len = env.get_array_length(a);
                match self.check(len) {
                    Some(n) => out_array_fits(n),
                    // A JNI failure: the pending exception reports it.
                    None => return,
                }
            };
            if !fits {
                // Refused as the C side refuses a bad argument.
                crate::ffi::record_error(9, "Invalid parameter".to_string());
                self.failed = true;
            }
        }

        /// Checks a PCM array before the C call: non-null and exactly one
        /// 20 ms frame (`FRAME_SAMPLES`), or the call fails with code 9
        /// recorded. A JNI failure fails the call (its exception reports it).
        fn pcm_array(&mut self, a: &JShortArray) -> bool {
            if self.failed {
                return false;
            }
            if a.is_null() {
                crate::ffi::record_error(9, "pcm must be 960 samples".to_string());
                self.failed = true;
                return false;
            }
            let Some(env) = self.env() else {
                return false;
            };
            let len = env.get_array_length(a);
            match self.check(len) {
                Some(n) if pcm_array_fits(n) => true,
                Some(_) => {
                    crate::ffi::record_error(9, "pcm must be 960 samples".to_string());
                    self.failed = true;
                    false
                }
                None => false,
            }
        }

        /// A direct ByteBuffer argument: its address and capacity, with no
        /// copy. Null, a non-direct buffer, or a JNI failure fails the call
        /// with code 9 recorded, before C runs.
        ///
        /// # Safety
        ///
        /// `raw` is null or a ByteBuffer reference the JVM passed for this call.
        unsafe fn direct_buffer(&mut self, raw: jobject) -> Option<(*mut u8, usize)> {
            if self.failed {
                return None;
            }
            let found = if raw.is_null() {
                None
            } else {
                // SAFETY: a local reference the JVM passed for this call.
                let buf = unsafe { JByteBuffer::from(JObject::from_raw(raw)) };
                let env = self.env.as_mut()?;
                let addr = env.get_direct_buffer_address(&buf).ok();
                let cap = env.get_direct_buffer_capacity(&buf).ok();
                addr.zip(cap).filter(|(a, _)| !a.is_null())
            };
            // A pending Java exception is reported by the caller's return.
            let pending = self
                .env
                .as_mut()
                .is_some_and(|e| e.exception_check().unwrap_or(true));
            match found {
                Some(v) if !pending => Some(v),
                _ => {
                    crate::ffi::record_error(9, "Not a direct buffer".to_string());
                    self.failed = true;
                    None
                }
            }
        }

        /// Checks an `IntArray` has exactly `n` elements before the C call
        /// (null or another length fails with code 9 recorded).
        fn int_array_len(&mut self, a: &JIntArray, n: usize) -> bool {
            if self.failed {
                return false;
            }
            let len = if a.is_null() {
                None
            } else {
                let env = self.env.as_mut();
                match env.map(|e| e.get_array_length(a)) {
                    Some(r) => match self.check(r) {
                        Some(len) => Some(len),
                        None => return false,
                    },
                    None => return false,
                }
            };
            if len.and_then(|l| usize::try_from(l).ok()) == Some(n) {
                return true;
            }
            crate::ffi::record_error(9, "Invalid parameter".to_string());
            self.failed = true;
            false
        }

        /// Writes a `uint32_t` result into `IntArray(1)` (bits reinterpreted).
        fn put_u32(&mut self, a: &JIntArray, v: u32) {
            let Some(env) = self.env() else { return };
            let r = env.set_int_array_region(a, 0, &[v as i32]);
            self.check(r);
        }

        /// Writes an optional string into `Array<String?>(1)` (null for None).
        fn put_string(&mut self, a: &JObjectArray, v: Option<String>) {
            let Some(env) = self.env() else { return };
            let obj = match v {
                Some(s) => match env.new_string(s) {
                    Ok(j) => JObject::from(j),
                    Err(e) => {
                        self.check::<()>(Err(e));
                        return;
                    }
                },
                None => JObject::null(),
            };
            let Some(env) = self.env() else { return };
            let r = env.set_object_array_element(a, 0, obj);
            self.check(r);
        }

        /// A string result for Kotlin: null for None or a failed call.
        fn out(&mut self, s: Option<String>) -> jstring {
            let (Some(s), Some(env)) = (s, self.env()) else {
                return NO_STRING;
            };
            let r = env.new_string(s);
            self.check(r).map_or(NO_STRING, JString::into_raw)
        }
    }

    fn bytes_ptr(b: &Option<SecretBytes>) -> (*const u8, usize) {
        b.as_ref()
            .map_or((std::ptr::null(), 0), |b| (b.as_ptr(), b.len()))
    }

    fn wipe(b: &mut Option<SecretBytes>) {
        if let Some(b) = b.as_mut() {
            b.wipe();
        }
    }

    fn flag(b: jboolean) -> c_int {
        c_int::from(b != 0)
    }

    // --- lifecycle -----------------------------------------------------------

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_initialize(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_initialize()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_connectWithSeed(
        env: Env,
        _class: jclass,
        config_json: jstring,
        seed: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let cfg = unsafe { j.s(config_json) };
        let mut seed = unsafe { j.bytes(seed) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&seed);
        let rc = unsafe { crate::ffi::rchat_connect_with_seed(ptr(&cfg), p, n) };
        wipe(&mut seed);
        rc
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_disconnect(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_disconnect()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_disconnectTransportOnly(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_disconnect_transport_only()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_reconnect(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_reconnect()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_getConnectionState(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_get_connection_state()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_lastErrorCode(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_last_error_code()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_processPending(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_process_pending()
    }

    /// Installs the Kotlin handler (null clears it) and registers the
    /// trampolines with the core (`register_trampolines` →
    /// rchat_register_callbacks). -1 if the handler can't be held.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_registerHandler(
        env: Env,
        _class: jclass,
        handler: jobject,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: a local reference the JVM passed for this call.
        let obj = unsafe { JObject::from_raw(handler) };
        if obj.is_null() {
            set_sink(None);
            return 0;
        }
        let Some(env) = j.env() else {
            return -1;
        };
        let vm = env.get_java_vm();
        let Some(vm) = j.check(vm) else {
            return -1;
        };
        let Some(env) = j.env() else {
            return -1;
        };
        let global = env.new_global_ref(&obj);
        let Some(global) = j.check(global) else {
            return -1;
        };
        set_sink(Some(Arc::new(JavaSink {
            vm,
            handler: global,
        })));
        // rchat_register_callbacks, through register_trampolines().
        register_trampolines()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setStateStore(
        env: Env,
        _class: jclass,
        key: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let mut key = unsafe { j.bytes(key) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&key);
        let rc =
            unsafe { crate::ffi::rchat_set_state_store(p, n, Some(trampolines().state_write)) };
        wipe(&mut key);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_importStateRecord(
        env: Env,
        _class: jclass,
        record_key: jstring,
        sealed: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let k = unsafe { j.s(record_key) };
        let b = unsafe { j.bytes(sealed) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&b);
        unsafe { crate::ffi::rchat_import_state_record(ptr(&k), p, n) }
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_clearState(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_clear_state()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_refreshTrustStore(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_refresh_trust_store()
    }

    /// Cover traffic on/off and whether the app is in the foreground;
    /// rchat_set_cover_traffic's result (always 0).
    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_setCoverTraffic(
        _env: Env,
        _class: jclass,
        enabled: jboolean,
        foreground: jboolean,
    ) -> jint {
        crate::ffi::rchat_set_cover_traffic(flag(enabled), flag(foreground))
    }

    /// Android background receiving: the keepalive stretches to 240 s while
    /// `background` is set; rchat_set_background_keepalive's result (always 0).
    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_setBackgroundKeepalive(
        _env: Env,
        _class: jclass,
        background: jboolean,
    ) -> jint {
        crate::ffi::rchat_set_background_keepalive(flag(background))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callPlace(
        env: Env,
        _class: jclass,
        peer: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let p = unsafe { j.s(peer) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_call_place(ptr(&p)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callAnswer(
        env: Env,
        _class: jclass,
        call_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(call_id) };
        if !j.ok() {
            return 9;
        }
        unsafe { crate::ffi::rchat_call_answer(ptr(&id)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callDecline(
        env: Env,
        _class: jclass,
        call_id: jstring,
        busy: jboolean,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(call_id) };
        if !j.ok() {
            return 9;
        }
        unsafe { crate::ffi::rchat_call_decline(ptr(&id), flag(busy)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callEnd(
        env: Env,
        _class: jclass,
        call_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(call_id) };
        if !j.ok() {
            return 9;
        }
        unsafe { crate::ffi::rchat_call_end(ptr(&id)) }
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callSetMuted(
        _env: Env,
        _class: jclass,
        muted: jboolean,
    ) -> jint {
        crate::ffi::rchat_call_set_muted(flag(muted))
    }

    /// One 960-sample frame read with GetShortArrayRegion into a stack
    /// buffer: nothing allocates per frame (spec §6). The array is checked
    /// (`pcm_array`) and every JNI step goes through `check` before C runs.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callPushPcm(
        env: Env,
        _class: jclass,
        pcm: jshortArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: null or a local reference the JVM passed for this call.
        let a = unsafe { JShortArray::from_raw(pcm) };
        if !j.pcm_array(&a) {
            return -9;
        }
        let mut buf = [0i16; crate::call::FRAME_SAMPLES];
        let Some(env) = j.env() else {
            return -9;
        };
        let r = env.get_short_array_region(&a, 0, &mut buf);
        if j.check(r).is_none() {
            return -9;
        }
        // SAFETY: `buf` holds FRAME_SAMPLES samples.
        unsafe { crate::ffi::rchat_call_push_pcm(buf.as_ptr(), buf.len()) }
    }

    /// The out-array is checked before C runs (`pcm_array`), so a wrong
    /// size never takes, and loses, a playback frame.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callPullPcm(
        env: Env,
        _class: jclass,
        out: jshortArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: null or a local reference the JVM passed for this call.
        let a = unsafe { JShortArray::from_raw(out) };
        if !j.pcm_array(&a) {
            return -9;
        }
        let mut buf = [0i16; crate::call::FRAME_SAMPLES];
        // SAFETY: `buf` holds FRAME_SAMPLES samples.
        let n = unsafe { crate::ffi::rchat_call_pull_pcm(buf.as_mut_ptr(), buf.len()) };
        let Some(env) = j.env() else {
            return -9;
        };
        let r = env.set_short_array_region(&a, 0, &buf);
        if j.check(r).is_none() {
            return -9;
        }
        n
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callPollEvent(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_call_poll_event()))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callPlaceVideo(
        env: Env,
        _class: jclass,
        peer: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(peer) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(unsafe {
            crate::ffi::rchat_call_place_video(ptr(&id))
        }))
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoSetCamera(
        _env: Env,
        _class: jclass,
        on: jboolean,
    ) -> jint {
        crate::ffi::rchat_call_video_set_camera(flag(on))
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoRespond(
        _env: Env,
        _class: jclass,
        accept: jboolean,
    ) -> jint {
        crate::ffi::rchat_call_video_respond(flag(accept))
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoConfigure(
        _env: Env,
        _class: jclass,
        codec_mask: jint,
        receive1080: jboolean,
        software_encoder: jboolean,
    ) -> jint {
        crate::ffi::rchat_call_video_configure(
            codec_mask,
            flag(receive1080),
            flag(software_encoder),
        )
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoSetThermal(
        _env: Env,
        _class: jclass,
        level: jint,
    ) -> jint {
        crate::ffi::rchat_call_video_set_thermal(level)
    }

    /// The out-array must be exactly 7 ints (checked before C runs); the
    /// hint is copied into it only when C reports 1 (written).
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoEncoderHint(
        env: Env,
        _class: jclass,
        out: jintArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: null or a local reference the JVM passed for this call.
        let a = unsafe { JIntArray::from_raw(out) };
        if !j.int_array_len(&a, 7) {
            return -9;
        }
        let mut hint = [0i32; 7];
        // SAFETY: `hint` holds 7 values.
        let n = unsafe { crate::ffi::rchat_call_video_encoder_hint(hint.as_mut_ptr(), 7) };
        if n == 1 {
            let Some(env) = j.env() else {
                return -9;
            };
            let r = env.set_int_array_region(&a, 0, &hint);
            if j.check(r).is_none() {
                return -9;
            }
        }
        n
    }

    /// One encoded frame from a direct buffer, with no copy: C reads at
    /// `addr + offset`. Null, non-direct, a negative offset or size, or
    /// `offset + size` past the capacity returns -9 before C runs.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoSend(
        env: Env,
        _class: jclass,
        buf: jobject,
        offset: jint,
        size: jint,
        keyframe: jboolean,
        rotation: jint,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let Some((addr, capacity)) = (unsafe { j.direct_buffer(buf) }) else {
            return -9;
        };
        let Some(len) = send_range_ok(offset, size, capacity) else {
            crate::ffi::record_error(9, "Invalid video frame".to_string());
            return -9;
        };
        let off = offset as usize;
        // SAFETY: `off + len` is within the buffer's capacity.
        unsafe { crate::ffi::rchat_call_video_send(addr.add(off), len, flag(keyframe), rotation) }
    }

    /// The next frame straight into a direct buffer (capacity = its room),
    /// no copy; `meta` must be exactly 4 ints (checked before C runs) and
    /// is written only when a frame was taken.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoTake(
        env: Env,
        _class: jclass,
        buf: jobject,
        meta: jintArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let Some((addr, capacity)) = (unsafe { j.direct_buffer(buf) }) else {
            return -9;
        };
        // SAFETY: null or a local reference the JVM passed for this call.
        let a = unsafe { JIntArray::from_raw(meta) };
        if !j.int_array_len(&a, 4) {
            return -9;
        }
        let mut m = [0i32; 4];
        // SAFETY: `addr` has `capacity` writable bytes; `m` holds 4 values.
        let n = unsafe { crate::ffi::rchat_call_video_take(addr, capacity, m.as_mut_ptr(), 4) };
        if n > 0 {
            let Some(env) = j.env() else {
                return -9;
            };
            let r = env.set_int_array_region(&a, 0, &m);
            if j.check(r).is_none() {
                return -9;
            }
        }
        n
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_callVideoNeedKeyframe(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_call_video_need_keyframe()
    }

    #[no_mangle]
    pub extern "C" fn Java_net_rchat_client_core_RChatCore_setDeviceSigner(
        _env: Env,
        _class: jclass,
    ) -> jint {
        crate::ffi::rchat_set_device_signer(Some(trampolines().device_sign))
    }

    // --- identity --------------------------------------------------------------

    /// Fills `out` (64 bytes) with a new seed through a wiped buffer;
    /// rchat_generate_identity_seed's result (1 written, -1 refused), or -1
    /// when the seed could not be copied into `out` (never 1 with `out`
    /// unfilled).
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_generateIdentitySeed(
        env: Env,
        _class: jclass,
        out_arr: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: a local reference the JVM passed for this call.
        let a = unsafe { JByteArray::from_raw(out_arr) };
        let len = match j.env() {
            Some(_) if a.is_null() => Some(0),
            Some(env) => {
                let n = env.get_array_length(&a);
                j.check(n).and_then(|n| usize::try_from(n).ok())
            }
            None => None,
        };
        let Some(len) = len else {
            return -1;
        };
        let mut buf = SecretBytes::zeroed(len);
        let p = if len == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        // SAFETY: `buf` is valid for `len` writes (NULL when empty, refused
        // by the C function with code 9).
        let rc = unsafe { crate::ffi::rchat_generate_identity_seed(p, len) };
        if rc == 1 {
            // SAFETY: i8 and u8 have the same layout; `buf` holds `len` bytes.
            let view = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<i8>(), len) };
            let copied = j.env().map(|env| env.set_byte_array_region(&a, 0, view));
            if copied.and_then(|r| j.check(r)).is_none() {
                buf.wipe();
                return -1;
            }
        }
        buf.wipe();
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_getIdentityPubkey(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_get_identity_pubkey()))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_getAgreementPubkey(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_get_agreement_pubkey()))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_getKemPubkey(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_get_kem_pubkey()))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_kemPubkeyFromSeed(
        env: Env,
        _class: jclass,
        seed: jbyteArray,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let mut b = unsafe { j.bytes(seed) };
        if !j.ok() {
            return NO_STRING;
        }
        let (p, n) = bytes_ptr(&b);
        let r = take_c(unsafe { crate::ffi::rchat_kem_pubkey_from_seed(p, n) });
        wipe(&mut b);
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_getBundleSignature(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_get_bundle_signature()))
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_bundleSignatureFromSeed(
        env: Env,
        _class: jclass,
        seed: jbyteArray,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let mut b = unsafe { j.bytes(seed) };
        if !j.ok() {
            return NO_STRING;
        }
        let (p, n) = bytes_ptr(&b);
        let r = take_c(unsafe { crate::ffi::rchat_bundle_signature_from_seed(p, n) });
        wipe(&mut b);
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_verifyCardBundle(
        env: Env,
        _class: jclass,
        ik: jstring,
        ak: jstring,
        kem: jstring,
        sig: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (ik, ak, kem, sig) = unsafe { (j.s(ik), j.s(ak), j.s(kem), j.s(sig)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_verify_card_bundle(ptr(&ik), ptr(&ak), ptr(&kem), ptr(&sig)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_deviceKeyBinding(
        env: Env,
        _class: jclass,
        dk_pub: jbyteArray,
        hardware: jboolean,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let b = unsafe { j.bytes(dk_pub) };
        if !j.ok() {
            return NO_STRING;
        }
        let (p, n) = bytes_ptr(&b);
        let r = take_c(unsafe { crate::ffi::rchat_device_key_binding(p, n, flag(hardware)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_verifyDeviceKeyBinding(
        env: Env,
        _class: jclass,
        ik: jstring,
        dk: jstring,
        hardware: jboolean,
        dks: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (ik, dk, dks) = unsafe { (j.s(ik), j.s(dk), j.s(dks)) };
        if !j.ok() {
            return -1;
        }
        unsafe {
            crate::ffi::rchat_verify_device_key_binding(
                ptr(&ik),
                ptr(&dk),
                flag(hardware),
                ptr(&dks),
            )
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_pinDeviceKey(
        env: Env,
        _class: jclass,
        identity: jstring,
        dk: jstring,
        hardware: jboolean,
        dks: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (id, dk, dks) = unsafe { (j.s(identity), j.s(dk), j.s(dks)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_pin_device_key(ptr(&id), ptr(&dk), flag(hardware), ptr(&dks)) }
    }

    // --- peers -------------------------------------------------------------------

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setRecipient(
        env: Env,
        _class: jclass,
        identity: jstring,
        agreement: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (id, ak) = unsafe { (j.s(identity), j.s(agreement)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_set_recipient(ptr(&id), ptr(&ak)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_pinPeerKey(
        env: Env,
        _class: jclass,
        identity: jstring,
        agreement: jstring,
        kem: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (id, ak, kem) = unsafe { (j.s(identity), j.s(agreement), j.s(kem)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_pin_peer_key(ptr(&id), ptr(&ak), ptr(&kem)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_unpinPeerKey(
        env: Env,
        _class: jclass,
        identity: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_unpin_peer_key(ptr(&id)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setPeerBlocked(
        env: Env,
        _class: jclass,
        identity: jstring,
        blocked: jboolean,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_set_peer_blocked(ptr(&id), flag(blocked)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_peerKeyState(
        env: Env,
        _class: jclass,
        identity: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_peer_key_state(ptr(&id)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setPeerKeyVersion(
        env: Env,
        _class: jclass,
        identity: jstring,
        version: jint,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_set_peer_key_version(ptr(&id), version as u32) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_requestCircuit(
        env: Env,
        _class: jclass,
        identity: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_request_circuit(ptr(&id)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_hasSession(
        env: Env,
        _class: jclass,
        identity: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let id = unsafe { j.s(identity) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_has_session(ptr(&id)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setIntro(
        env: Env,
        _class: jclass,
        identity: jstring,
        text: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (id, t) = unsafe { (j.s(identity), j.s(text)) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_set_intro(ptr(&id), ptr(&t)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setIntroWithId(
        env: Env,
        _class: jclass,
        identity: jstring,
        text: jstring,
        message_id: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (id, t, m) = unsafe { (j.s(identity), j.s(text), j.s(message_id)) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_set_intro_with_id(ptr(&id), ptr(&t), ptr(&m)) });
        j.out(r)
    }

    // --- messages --------------------------------------------------------------------

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sendMessageWithId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        text: jstring,
        expire_out: jintArray,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (r, t) = unsafe { (j.s(recipient), j.s(text)) };
        // SAFETY: a local reference the JVM passed for this call.
        let expire_out = unsafe { JIntArray::from_raw(expire_out) };
        j.out_array(&expire_out);
        if !j.ok() {
            return NO_STRING;
        }
        let mut expire: u32 = 0;
        let id = take_c(unsafe {
            crate::ffi::rchat_send_message_with_id(ptr(&r), ptr(&t), &mut expire)
        });
        j.put_u32(&expire_out, expire);
        j.out(id)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sendMessageUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        text: jstring,
        message_id: jstring,
        expire_out: jintArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, t, m) = unsafe { (j.s(recipient), j.s(text), j.s(message_id)) };
        // SAFETY: a local reference the JVM passed for this call.
        let expire_out = unsafe { JIntArray::from_raw(expire_out) };
        j.out_array(&expire_out);
        if !j.ok() {
            return -1;
        }
        let mut expire: u32 = 0;
        let rc = unsafe {
            crate::ffi::rchat_send_message_using_id(ptr(&r), ptr(&t), ptr(&m), &mut expire)
        };
        j.put_u32(&expire_out, expire);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_retryMessageUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        text: jstring,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, t, m) = unsafe { (j.s(recipient), j.s(text), j.s(message_id)) };
        if !j.ok() {
            return -1;
        }
        unsafe {
            crate::ffi::rchat_retry_message_using_id(ptr(&r), ptr(&t), expire_secs as u32, ptr(&m))
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_resendMessageUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        text: jstring,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, t, m) = unsafe { (j.s(recipient), j.s(text), j.s(message_id)) };
        if !j.ok() {
            return -1;
        }
        unsafe {
            crate::ffi::rchat_resend_message_using_id(ptr(&r), ptr(&t), expire_secs as u32, ptr(&m))
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_markMessageSeen(
        env: Env,
        _class: jclass,
        sender: jstring,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (sn, m) = unsafe { (j.s(sender), j.s(message_id)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_mark_message_seen(ptr(&sn), ptr(&m)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sendReadReceipt(
        env: Env,
        _class: jclass,
        sender: jstring,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (sn, m) = unsafe { (j.s(sender), j.s(message_id)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_send_read_receipt(ptr(&sn), ptr(&m)) }
    }

    // --- safety numbers ------------------------------------------------------------

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_safetyNumber(
        env: Env,
        _class: jclass,
        peer: jstring,
        my_ik: jstring,
        my_ak: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (p, i, a) = unsafe { (j.s(peer), j.s(my_ik), j.s(my_ak)) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_safety_number(ptr(&p), ptr(&i), ptr(&a)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_markSafetyNumberCompared(
        env: Env,
        _class: jclass,
        peer: jstring,
        my_ik: jstring,
        my_ak: jstring,
        digits: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (p, i, a, d) = unsafe { (j.s(peer), j.s(my_ik), j.s(my_ak), j.s(digits)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_mark_safety_number_compared(ptr(&p), ptr(&i), ptr(&a), ptr(&d)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_compareSafetyNumberQr(
        env: Env,
        _class: jclass,
        peer: jstring,
        my_ik: jstring,
        my_ak: jstring,
        scanned: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (p, i, a, q) = unsafe { (j.s(peer), j.s(my_ik), j.s(my_ak), j.s(scanned)) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_compare_safety_number_qr(ptr(&p), ptr(&i), ptr(&a), ptr(&q)) }
    }

    // --- relay -------------------------------------------------------------------------

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_canonicalOrigin(
        env: Env,
        _class: jclass,
        url: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let u = unsafe { j.s(url) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_canonical_origin(ptr(&u)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_parseRelayInvite(
        env: Env,
        _class: jclass,
        link: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let l = unsafe { j.s(link) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_parse_relay_invite(ptr(&l)) });
        j.out(r)
    }

    /// The debug variant's parser (also `ws://` to this device), built only
    /// with `dev-invite`; the app calls it only when `BuildConfig.DEBUG`.
    #[cfg(any(feature = "dev-invite", test))]
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_parseRelayInviteDev(
        env: Env,
        _class: jclass,
        link: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let l = unsafe { j.s(link) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_parse_relay_invite_dev(ptr(&l)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_formatRelayInvite(
        env: Env,
        _class: jclass,
        url: jstring,
        pin: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (u, p) = unsafe { (j.s(url), j.s(pin)) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_format_relay_invite(ptr(&u), ptr(&p)) });
        j.out(r)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_relayPinInfo(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_relay_pin_info()))
    }

    // --- our own key rotation (spec §4.8) ----------------------------------------------
    // The plan JSON holds public values only; the new seed crosses once, as
    // a ByteArray filled from a wiped buffer (`takeRotationSeed`).

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_prepareRotation(
        env: Env,
        _class: jclass,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        if !j.ok() {
            return NO_STRING;
        }
        j.out(take_c(crate::ffi::rchat_prepare_rotation()))
    }

    /// Fills `out` (64 bytes) with the prepared rotation seed, once, through
    /// a wiped buffer; rchat_take_rotation_seed's result (1 written, 0
    /// nothing prepared, -1 refused), or -1 when the seed could not be
    /// copied into `out` (never 1 with `out` unfilled). The core's own copy
    /// is gone either way.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_takeRotationSeed(
        env: Env,
        _class: jclass,
        out_arr: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        // SAFETY: a local reference the JVM passed for this call.
        let a = unsafe { JByteArray::from_raw(out_arr) };
        let len = match j.env() {
            Some(_) if a.is_null() => Some(0),
            Some(env) => {
                let n = env.get_array_length(&a);
                j.check(n).and_then(|n| usize::try_from(n).ok())
            }
            None => None,
        };
        let Some(len) = len else {
            return -1;
        };
        let mut buf = SecretBytes::zeroed(len);
        let p = if len == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        // SAFETY: `buf` is valid for `len` writes (NULL when empty, refused
        // by the C function with code 9, as a short buffer is).
        let rc = unsafe { crate::ffi::rchat_take_rotation_seed(p, len) };
        if rc == 1 {
            // SAFETY: i8 and u8 have the same layout; `buf` holds `len` bytes.
            let view = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<i8>(), len) };
            let copied = j.env().map(|env| env.set_byte_array_region(&a, 0, view));
            if copied.and_then(|r| j.check(r)).is_none() {
                buf.wipe();
                return -1;
            }
        }
        buf.wipe();
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_announceRotation(
        env: Env,
        _class: jclass,
        links_hex: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let links = unsafe { j.s(links_hex) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_announce_rotation(ptr(&links)) }
    }

    // --- media and files (protocol v3 §E) --------------------------------------------
    // Media bytes are read straight into a wiped buffer (`bytes`) and wiped
    // again after the C call, like the seed: they are message plaintext.

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sendBinaryWithId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        data: jbyteArray,
        expire_out: jintArray,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let r = unsafe { j.s(recipient) };
        let mut d = unsafe { j.bytes(data) };
        // SAFETY: a local reference the JVM passed for this call.
        let expire_out = unsafe { JIntArray::from_raw(expire_out) };
        j.out_array(&expire_out);
        if !j.ok() {
            return NO_STRING;
        }
        let (p, n) = bytes_ptr(&d);
        let mut expire: u32 = 0;
        let id =
            take_c(unsafe { crate::ffi::rchat_send_binary_with_id(ptr(&r), p, n, &mut expire) });
        wipe(&mut d);
        j.put_u32(&expire_out, expire);
        j.out(id)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_retryBinaryUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        data: jbyteArray,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, m) = unsafe { (j.s(recipient), j.s(message_id)) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe {
            crate::ffi::rchat_retry_binary_using_id(ptr(&r), p, n, expire_secs as u32, ptr(&m))
        };
        wipe(&mut d);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_resendBinaryUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        data: jbyteArray,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, m) = unsafe { (j.s(recipient), j.s(message_id)) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe {
            crate::ffi::rchat_resend_binary_using_id(ptr(&r), p, n, expire_secs as u32, ptr(&m))
        };
        wipe(&mut d);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sendFile(
        env: Env,
        _class: jclass,
        recipient: jstring,
        name: jstring,
        mime: jstring,
        data: jbyteArray,
        expire_out: jintArray,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let (r, nm, mt) = unsafe { (j.s(recipient), j.s(name), j.s(mime)) };
        let mut d = unsafe { j.bytes(data) };
        // SAFETY: a local reference the JVM passed for this call.
        let expire_out = unsafe { JIntArray::from_raw(expire_out) };
        j.out_array(&expire_out);
        if !j.ok() {
            return NO_STRING;
        }
        let (p, n) = bytes_ptr(&d);
        let mut expire: u32 = 0;
        let id = take_c(unsafe {
            crate::ffi::rchat_send_file(ptr(&r), ptr(&nm), ptr(&mt), p, n, &mut expire)
        });
        wipe(&mut d);
        j.put_u32(&expire_out, expire);
        j.out(id)
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_retryFileUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        name: jstring,
        mime: jstring,
        data: jbyteArray,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, nm, mt, m) = unsafe { (j.s(recipient), j.s(name), j.s(mime), j.s(message_id)) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe {
            crate::ffi::rchat_retry_file_using_id(
                ptr(&r),
                ptr(&nm),
                ptr(&mt),
                p,
                n,
                expire_secs as u32,
                ptr(&m),
            )
        };
        wipe(&mut d);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_resendFileUsingId(
        env: Env,
        _class: jclass,
        recipient: jstring,
        name: jstring,
        mime: jstring,
        data: jbyteArray,
        expire_secs: jint,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let (r, nm, mt, m) = unsafe { (j.s(recipient), j.s(name), j.s(mime), j.s(message_id)) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe {
            crate::ffi::rchat_resend_file_using_id(
                ptr(&r),
                ptr(&nm),
                ptr(&mt),
                p,
                n,
                expire_secs as u32,
                ptr(&m),
            )
        };
        wipe(&mut d);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_sanitiseFileName(
        env: Env,
        _class: jclass,
        name: jstring,
    ) -> jstring {
        let mut j = unsafe { Jni::new(env) };
        let nm = unsafe { j.s(name) };
        if !j.ok() {
            return NO_STRING;
        }
        let r = take_c(unsafe { crate::ffi::rchat_sanitise_file_name(ptr(&nm)) });
        j.out(r)
    }

    // --- file safety (file-safety spec §3, §4) -------------------------------------------

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_fileCheck(
        env: Env,
        _class: jclass,
        name: jstring,
        data: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let nm = unsafe { j.s(name) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            wipe(&mut d);
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe { crate::ffi::rchat_file_check(ptr(&nm), p, n) };
        wipe(&mut d);
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_mediaCheck(
        env: Env,
        _class: jclass,
        kind: jint,
        data: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let mut d = unsafe { j.bytes(data) };
        if !j.ok() {
            wipe(&mut d);
            return -1;
        }
        let (p, n) = bytes_ptr(&d);
        let rc = unsafe { crate::ffi::rchat_media_check(kind, p, n) };
        wipe(&mut d);
        rc
    }

    /// Ed25519 check over raw bytes: 0 valid, 1 not, -1 bad argument. All
    /// three arrays are public; nothing secret crosses here.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_verifyEd25519(
        env: Env,
        _class: jclass,
        public_key: jbyteArray,
        message: jbyteArray,
        signature: jbyteArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let mut k = unsafe { j.bytes(public_key) };
        let mut m = unsafe { j.bytes(message) };
        let mut s = unsafe { j.bytes(signature) };
        if !j.ok() {
            wipe(&mut k);
            wipe(&mut m);
            wipe(&mut s);
            return -1;
        }
        let (kp, kn) = bytes_ptr(&k);
        let (mp, mn) = bytes_ptr(&m);
        let (sp, sn) = bytes_ptr(&s);
        let rc = unsafe { crate::ffi::rchat_verify_ed25519(kp, kn, mp, mn, sp, sn) };
        wipe(&mut k);
        wipe(&mut m);
        wipe(&mut s);
        rc
    }

    // --- disappearing messages (protocol v3 §I.2) --------------------------------------

    /// `currentOut[0]` gets the timer in force, `appliedOut[0]` 1 when ours
    /// is it, and `introDroppedOut[0]` the dropped intro's id (or null), as
    /// the C function's three out-parameters; the id is freed here on every
    /// path and handed to Kotlin only on code 0.
    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_setDisappearingTimerEx(
        env: Env,
        _class: jclass,
        peer: jstring,
        secs: jint,
        current_out: jintArray,
        applied_out: jintArray,
        intro_dropped_out: jobjectArray,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let p = unsafe { j.s(peer) };
        // SAFETY: local references the JVM passed for this call.
        let (current_out, applied_out, intro_dropped_out) = unsafe {
            (
                JIntArray::from_raw(current_out),
                JIntArray::from_raw(applied_out),
                JObjectArray::from_raw(intro_dropped_out),
            )
        };
        j.out_array(&current_out);
        j.out_array(&applied_out);
        j.out_array(&intro_dropped_out);
        if !j.ok() {
            return -1;
        }
        let mut current: u32 = 0;
        let mut applied: i32 = 0;
        let mut dropped: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            crate::ffi::rchat_set_disappearing_timer_ex(
                ptr(&p),
                secs as u32,
                &mut current,
                &mut applied,
                &mut dropped,
            )
        };
        let dropped = take_c(dropped);
        j.put_u32(&current_out, current);
        j.put_u32(&applied_out, applied as u32);
        j.put_string(&intro_dropped_out, if rc == 0 { dropped } else { None });
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_disappearingTimer(
        env: Env,
        _class: jclass,
        peer: jstring,
    ) -> jlong {
        let mut j = unsafe { Jni::new(env) };
        let p = unsafe { j.s(peer) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_disappearing_timer(ptr(&p)) }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_rchat_client_core_RChatCore_forgetMessage(
        env: Env,
        _class: jclass,
        message_id: jstring,
    ) -> jint {
        let mut j = unsafe { Jni::new(env) };
        let m = unsafe { j.s(message_id) };
        if !j.ok() {
            return -1;
        }
        unsafe { crate::ffi::rchat_forget_message(ptr(&m)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::tests::FFI_TEST_LOCK;
    use std::ffi::CString;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<(i32, String)>>,
        writes: Mutex<Vec<(String, Option<Vec<u8>>)>>,
        sign_with: Option<[u8; 64]>,
        write_result: i32,
    }
    impl EventSink for Recorder {
        fn on_event(&self, kind: i32, json: &str) {
            self.events.lock().unwrap().push((kind, json.to_string()));
        }
        fn sign(&self, _msg: &[u8]) -> Option<[u8; 64]> {
            self.sign_with
        }
        fn write_state(&self, key: &str, sealed: Option<&[u8]>) -> i32 {
            self.writes
                .lock()
                .unwrap()
                .push((key.to_string(), sealed.map(<[u8]>::to_vec)));
            self.write_result
        }
    }

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }
    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }
    /// A string as Kotlin hands it over (UTF-16), then as the C side gets it.
    fn c_of(s: &str) -> Option<SecretCString> {
        to_c(Some(&s.encode_utf16().collect::<Vec<_>>()))
    }

    #[test]
    fn to_c_refuses_none_and_embedded_nul() {
        assert!(to_c(None).is_none());
        assert!(c_of("a\0b").is_none());
        assert_eq!(c_of("abc").unwrap().0.as_slice(), b"abc\0");
        assert!(ptr(&None).is_null());
    }

    /// Outgoing text crosses through one wiped buffer: sized for the worst
    /// case, so it never reallocates (no stale copy), and exact UTF-8.
    #[test]
    fn to_c_converts_utf16_in_place_without_reallocating() {
        let text = "héllo \u{1F600} \u{FFFF}";
        let units: Vec<u16> = text.encode_utf16().collect();
        let c = to_c(Some(&units)).unwrap();
        assert_eq!(&c.0[..c.0.len() - 1], text.as_bytes());
        assert_eq!(c.0.last(), Some(&0));
        let worst = Vec::<u8>::with_capacity(units.len() * 3 + 1).capacity();
        assert_eq!(c.0.capacity(), worst, "never reallocated");
        // An unpaired surrogate becomes U+FFFD, as the JVM's own decoding does.
        let lone = to_c(Some(&[0x61, 0xD800, 0x62])).unwrap();
        assert_eq!(&lone.0[..], "a\u{FFFD}b\0".as_bytes());
    }

    #[test]
    fn utf16_for_java_round_trips_without_reallocating() {
        for s in ["", "plain", "h\u{e9}llo \u{1F600}", "\u{1}\"\\\u{2028}"] {
            let units = utf16_of(s);
            assert_eq!(String::from_utf16(&units).unwrap(), s);
            assert_eq!(
                units.capacity(),
                Vec::<u16>::with_capacity(s.len()).capacity()
            );
        }
    }

    /// callPushPcm / callPullPcm check the array before the C call (a
    /// null or wrong-sized array records code 9 and never reaches C), and
    /// the C functions refuse the same buffers with -9 themselves.
    #[test]
    fn pcm_arrays_must_be_one_frame_and_refusals_take_no_frame() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert!(pcm_array_fits(960));
        for bad in [-1, 0, 100, 959, 961, 1920] {
            assert!(!pcm_array_fits(bad), "{bad}");
        }
        // What the C side does with the buffers a refused array stands for.
        let mut out = [7i16; 100];
        assert_eq!(
            unsafe { crate::ffi::rchat_call_pull_pcm(out.as_mut_ptr(), 100) },
            -9
        );
        assert_eq!(crate::ffi::rchat_last_error_code(), 9);
        assert!(out.iter().all(|s| *s == 7), "a refused pull writes nothing");
        assert_eq!(
            unsafe { crate::ffi::rchat_call_push_pcm(std::ptr::null(), 960) },
            -9
        );
        assert_eq!(crate::ffi::rchat_last_error_code(), 9);
    }

    #[test]
    fn out_arrays_need_room_for_one_result() {
        assert!(out_array_fits(1));
        assert!(out_array_fits(4));
        assert!(!out_array_fits(0));
        assert!(!out_array_fits(-1));
    }

    #[test]
    fn content_json_writes_hex_text_and_heads_in_one_buffer() {
        // Not hex (never from the core): crosses as "", and the JSON is valid.
        let head = r#"{"sender":"aa"}"#;
        let out = content_json(head, &[("content_hex", Content::Hex(b"zz\"}"))]).unwrap();
        let v = json(std::str::from_utf8(&out).unwrap());
        assert_eq!(v["content_hex"], "");
        assert_eq!(v["sender"], "aa");
        // An empty head: the content fields alone, no stray comma.
        let out = content_json("{}", &[("content_hex", Content::Raw(&[1, 0xab]))]).unwrap();
        assert_eq!(&out[..], br#"{"content_hex":"01ab"}"#);
        // Text is escaped by serde, worst case included, without reallocating.
        let intro = "\u{1}\"\\\n\u{1F600}".repeat(50);
        let fields = [
            ("intro_text", Content::Text(&intro)),
            ("content_hex", Content::Raw(&[7; 9])),
        ];
        let out = content_json(head, &fields).unwrap();
        let v = json(std::str::from_utf8(&out).unwrap());
        assert_eq!(v["intro_text"], intro.as_str());
        assert_eq!(v["content_hex"], "07".repeat(9));
        let sized = Vec::<u8>::with_capacity(content_json_capacity(head, &fields)).capacity();
        assert_eq!(out.capacity(), sized, "never reallocated");
        // A head that is not an object is refused.
        assert!(content_json("[]", &fields).is_none());
    }

    #[test]
    fn take_c_copies_then_frees_and_reads_null_as_none() {
        assert!(take_c(std::ptr::null_mut()).is_none());
        let url = cs("wss://relay.example.net/p");
        let p = unsafe { crate::ffi::rchat_canonical_origin(url.as_ptr()) };
        let s = take_c(p).expect("a canonical origin");
        assert!(s.starts_with("wss://relay.example.net"));
    }

    #[test]
    fn null_arguments_get_the_c_functions_own_code() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // A Java null and a NUL-embedded string both arrive as NULL.
        for c in [None, c_of("bad\0id")] {
            assert_eq!(unsafe { crate::ffi::rchat_unpin_peer_key(ptr(&c)) }, -1);
            assert_eq!(crate::ffi::rchat_last_error_code(), 9);
            assert_eq!(unsafe { crate::ffi::rchat_request_circuit(ptr(&c)) }, 9);
            assert!(take_c(unsafe { crate::ffi::rchat_parse_relay_invite(ptr(&c)) }).is_none());
            assert_eq!(crate::ffi::rchat_last_error_code(), 9);
            assert!(take_c(unsafe { crate::ffi::rchat_parse_relay_invite_dev(ptr(&c)) }).is_none());
            assert_eq!(crate::ffi::rchat_last_error_code(), 9);
        }
    }

    /// Exports 48–57: a Java null (or an empty array) reaches C as NULL / (NULL, 0),
    /// and the code is the C function's own.
    #[test]
    fn media_and_timer_entries_refuse_null_with_their_own_codes() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let none: Option<SecretCString> = None;
        let mut expire = 7u32;
        assert!(take_c(unsafe {
            crate::ffi::rchat_send_binary_with_id(ptr(&none), std::ptr::null(), 0, &mut expire)
        })
        .is_none());
        assert_eq!(crate::ffi::rchat_last_error_code(), 9);
        assert!(take_c(unsafe { crate::ffi::rchat_sanitise_file_name(ptr(&none)) }).is_none());
        assert_eq!(crate::ffi::rchat_last_error_code(), 9);
        assert_eq!(unsafe { crate::ffi::rchat_forget_message(ptr(&none)) }, 9);
        assert_eq!(
            unsafe { crate::ffi::rchat_disappearing_timer(ptr(&none)) },
            -1
        );
        // The core's cleaning, as the app shows and sends it (protocol v3 §E.2).
        let hostile = c_of("../a\u{202E}b.txt");
        assert_eq!(
            take_c(unsafe { crate::ffi::rchat_sanitise_file_name(ptr(&hostile)) }).as_deref(),
            Some("_a_b.txt")
        );
    }

    #[test]
    fn hostile_lengths_and_json_are_refused_by_the_core() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(crate::ffi::rchat_initialize(), 0);
        // A seed of the wrong length (Kotlin passes whatever ByteArray it has).
        let cfg = cs(r#"{"server_url":"ws://127.0.0.1:1/","display_name":""}"#);
        let short = SecretBytes::from_slice(&[7u8; 31]);
        let rc = unsafe {
            crate::ffi::rchat_connect_with_seed(cfg.as_ptr(), short.as_ptr(), short.len())
        };
        assert_eq!(rc, 9);
        // Bad JSON.
        let bad = cs("{not json");
        let seed = SecretBytes::from_slice(&[7u8; 64]);
        let rc =
            unsafe { crate::ffi::rchat_connect_with_seed(bad.as_ptr(), seed.as_ptr(), seed.len()) };
        assert_eq!(rc, 1);
        // A state key of the wrong length.
        let key = SecretBytes::zeroed(31);
        let t = trampolines();
        assert_eq!(
            unsafe {
                crate::ffi::rchat_set_state_store(key.as_ptr(), key.len(), Some(t.state_write))
            },
            -1
        );
        assert_eq!(crate::ffi::rchat_last_error_code(), 9);
        // A seed buffer that is too small.
        let mut out = SecretBytes::zeroed(63);
        assert_eq!(
            unsafe { crate::ffi::rchat_generate_identity_seed(out.as_mut_ptr(), out.len()) },
            -1
        );
    }

    #[test]
    fn secret_bytes_are_zeroed_in_place_on_wipe() {
        let mut s = SecretBytes::from_slice(&[0xAB; 64]);
        assert_eq!(s.len(), 64);
        s.wipe();
        assert_eq!(s.len(), 64);
        assert!(s.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn generate_seed_into_copies_a_seed_out() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut copy = [0u8; 64];
        let rc = generate_seed_into(&mut copy);
        assert_eq!(rc, 1);
        assert!(copy.iter().any(|&b| b != 0), "the seed reached the caller");
        copy.fill(0);
    }

    /// Exports 58–60 without a client: each refuses with the C function's
    /// own result and code, and a short, empty or missing seed buffer is
    /// refused with code 9 and left untouched.
    #[test]
    fn rotation_entries_refuse_without_a_client_and_bad_buffers() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::ffi::rchat_disconnect();
        assert_eq!(crate::ffi::rchat_initialize(), 0);
        crate::ffi::tests::set_test_client(None);
        assert!(take_c(crate::ffi::rchat_prepare_rotation()).is_none());
        assert_eq!(crate::ffi::rchat_last_error_code(), 7, "no client");
        let links = c_of("00");
        assert_eq!(
            unsafe { crate::ffi::rchat_announce_rotation(ptr(&links)) },
            -7
        );
        let none: Option<SecretCString> = None;
        assert_eq!(
            unsafe { crate::ffi::rchat_announce_rotation(ptr(&none)) },
            -9,
            "a Java null or an embedded NUL reaches C as NULL"
        );
        assert!(c_of("0\0").is_none());
        let mut out = [0u8; 64];
        assert_eq!(take_rotation_seed_into(&mut out), 0, "nothing prepared");
        for len in [0usize, 32, 63] {
            let mut short = vec![0u8; len];
            assert_eq!(take_rotation_seed_into(&mut short), -1);
            assert_eq!(crate::ffi::rchat_last_error_code(), 9);
            assert!(short.iter().all(|&b| b == 0));
        }
        crate::ffi::rchat_disconnect();
    }

    /// With a live client: the plan holds public values only, and the seed
    /// crosses once, matching the plan's new identity.
    #[test]
    fn rotation_seed_crosses_once_through_a_wiped_buffer() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::ffi::rchat_disconnect();
        assert_eq!(crate::ffi::rchat_initialize(), 0);
        let (inner, _rx) = crate::test_support::published(0xB2);
        crate::ffi::tests::set_test_client(Some(crate::test_support::wrap(inner)));
        let plan = json(&take_c(crate::ffi::rchat_prepare_rotation()).expect("a plan"));
        let keys: Vec<&String> = plan.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 4, "no seed in the plan: {keys:?}");
        let mut short = [0u8; 63];
        assert_eq!(take_rotation_seed_into(&mut short), -1);
        assert_eq!(short, [0u8; 63], "refused before anything is copied");
        let mut seed = [0u8; 64];
        assert_eq!(take_rotation_seed_into(&mut seed), 1);
        let new = crate::crypto::IdentityKeyPair::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(new.public_signing_key().to_bytes()),
            plan["new_identity"].as_str().unwrap()
        );
        seed.fill(0);
        let mut again = [0u8; 64];
        assert_eq!(take_rotation_seed_into(&mut again), 0, "single use");
        assert_eq!(again, [0u8; 64]);
        // The links announce over the live client (no circuit: 0 notices).
        let links = c_of(plan["links"].as_str().unwrap());
        assert_eq!(
            unsafe { crate::ffi::rchat_announce_rotation(ptr(&links)) },
            0
        );
        crate::ffi::tests::set_test_client(None);
        crate::ffi::rchat_disconnect();
    }

    #[test]
    fn every_trampoline_emits_its_kind_and_json() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let rec = Arc::new(Recorder::default());
        set_sink(Some(rec.clone()));
        let t = trampolines();
        let (a, b, id, text) = (cs("aa"), cs("bb"), cs("0123"), cs("hi"));
        (t.message)(a.as_ptr(), b.as_ptr(), 5, id.as_ptr(), 1, 30);
        (t.state)(2);
        (t.error)(text.as_ptr());
        (t.circuit)(a.as_ptr(), 1);
        (t.delivered)(id.as_ptr());
        (t.reconnect)();
        (t.peer_key)(a.as_ptr(), 2, b.as_ptr());
        (t.request)(
            a.as_ptr(),
            b.as_ptr(),
            b.as_ptr(),
            7,
            id.as_ptr(),
            text.as_ptr(),
            9,
            3,
        );
        (t.receipt)(a.as_ptr(), id.as_ptr(), 2);
        (t.rotated)(a.as_ptr(), b.as_ptr(), b.as_ptr(), b.as_ptr(), 4);
        (t.status)(10, a.as_ptr(), id.as_ptr(), 0);
        let bytes = [1u8, 2, 3];
        (t.file)(
            a.as_ptr(),
            id.as_ptr(),
            text.as_ptr(),
            text.as_ptr(),
            0,
            bytes.as_ptr(),
            3,
            11,
        );
        (t.timer)(a.as_ptr(), 60, 12, 1);
        (t.file_blocked)(a.as_ptr(), id.as_ptr(), text.as_ptr(), 300, 13);
        set_sink(None);
        let ev = rec.events.lock().unwrap().clone();
        let kinds: Vec<i32> = ev.iter().map(|e| e.0).collect();
        assert_eq!(kinds, (1..=14).collect::<Vec<_>>());
        let m = json(&ev[0].1);
        assert_eq!(m["sender"], "aa");
        assert_eq!(m["content_hex"], "bb");
        assert_eq!(m["timestamp_ms"], 5);
        assert_eq!(m["message_id"], "0123");
        assert_eq!(m["kind"], 1);
        assert_eq!(m["expire_secs"], 30);
        assert_eq!(json(&ev[1].1)["state"], 2);
        assert_eq!(json(&ev[2].1)["message"], "hi");
        assert_eq!(json(&ev[3].1)["initiator"], true);
        assert_eq!(json(&ev[4].1)["message_id"], "0123");
        assert_eq!(ev[5].1, "{}");
        let k = json(&ev[6].1);
        assert_eq!(
            (
                k["peer"].as_str(),
                k["code"].as_i64(),
                k["agreement"].as_str()
            ),
            (Some("aa"), Some(2), Some("bb"))
        );
        let r = json(&ev[7].1);
        assert_eq!(r["issued_hour"], 7);
        assert_eq!(r["intro_id"], "0123");
        assert_eq!(r["intro_text"], "hi");
        assert_eq!(r["intro_sent_at_ms"], 9);
        assert_eq!(r["key_version"], 3);
        assert_eq!(json(&ev[8].1)["kind"], 2);
        assert_eq!(json(&ev[9].1)["version"], 4);
        let st = json(&ev[10].1);
        assert_eq!(
            (st["kind"].as_i64(), st["detail"].as_i64()),
            (Some(10), Some(0))
        );
        let f = json(&ev[11].1);
        assert_eq!(f["len"], 3);
        assert_eq!(
            (f["name"].as_str(), f["mime"].as_str()),
            (Some("hi"), Some("hi"))
        );
        assert_eq!(
            f["content_hex"], "010203",
            "a file's bytes cross as hex, like a binary message body"
        );
        assert_eq!(json(&ev[12].1)["by_me"], true);
        let fb = json(&ev[13].1);
        assert_eq!(
            (
                fb["name"].as_str(),
                fb["expire_secs"].as_i64(),
                fb["timestamp_ms"].as_i64()
            ),
            (Some("hi"), Some(300), Some(13))
        );
        assert_eq!(fb["sender"], "aa");
        assert_eq!(fb["message_id"], "0123");
        assert!(
            fb.get("content_hex").is_none(),
            "a blocked file carries no bytes"
        );
    }

    #[test]
    fn events_go_to_the_current_sink_only_and_are_dropped_without_one() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let first = Arc::new(Recorder::default());
        let second = Arc::new(Recorder::default());
        let t = trampolines();
        // Before any registration (a fresh process): dropped, no crash.
        set_sink(None);
        (t.state)(1);
        set_sink(Some(first.clone()));
        (t.state)(1);
        set_sink(Some(second.clone()));
        (t.state)(2);
        set_sink(None);
        (t.state)(3);
        assert_eq!(first.events.lock().unwrap().len(), 1);
        assert_eq!(second.events.lock().unwrap().len(), 1);
        assert_eq!(json(&second.events.lock().unwrap()[0].1)["state"], 2);
    }

    #[test]
    fn sync_requests_without_a_sink_fail_and_with_one_pass_through() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let t = trampolines();
        let key = cs("meta");
        let data = [9u8; 4];
        let mut out = [0u8; 64];
        set_sink(None);
        assert_eq!((t.state_write)(key.as_ptr(), data.as_ptr(), 4), -1);
        assert_eq!((t.device_sign)(data.as_ptr(), 4, out.as_mut_ptr()), -1);
        let rec = Arc::new(Recorder {
            sign_with: Some([5u8; 64]),
            write_result: 0,
            ..Default::default()
        });
        set_sink(Some(rec.clone()));
        assert_eq!((t.state_write)(key.as_ptr(), data.as_ptr(), 4), 0);
        assert_eq!((t.state_write)(key.as_ptr(), std::ptr::null(), 0), 0);
        assert_eq!((t.device_sign)(data.as_ptr(), 4, out.as_mut_ptr()), 0);
        assert_eq!(out, [5u8; 64]);
        // NULL buffers are refused before the sink is asked.
        assert_eq!((t.device_sign)(std::ptr::null(), 4, out.as_mut_ptr()), -1);
        set_sink(None);
        let writes = rec.writes.lock().unwrap().clone();
        assert_eq!(
            writes,
            vec![
                ("meta".to_string(), Some(vec![9u8; 4])),
                ("meta".to_string(), None)
            ]
        );
    }

    #[test]
    fn a_signer_that_declines_leaves_the_notice_unsigned() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_sink(Some(Arc::new(Recorder::default())));
        let mut out = [0u8; 64];
        let msg = [1u8; 8];
        assert_eq!(
            (trampolines().device_sign)(msg.as_ptr(), 8, out.as_mut_ptr()),
            -1
        );
        set_sink(None);
    }

    #[test]
    fn registering_the_trampolines_succeeds() {
        let _g = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(register_trampolines(), 0);
    }

    #[test]
    fn send_range_checks() {
        assert_eq!(send_range_ok(0, 10, 10), Some(10));
        assert_eq!(send_range_ok(4, 6, 10), Some(6));
        assert_eq!(send_range_ok(4, 7, 10), None);
        assert_eq!(send_range_ok(-1, 5, 10), None);
        assert_eq!(send_range_ok(0, -1, 10), None);
        assert_eq!(send_range_ok(0, 0, 10), None);
        assert_eq!(send_range_ok(10, 1, 10), None);
        assert_eq!(
            send_range_ok(i32::MAX, i32::MAX, usize::MAX),
            Some(i32::MAX as usize)
        );
        assert_eq!(send_range_ok(i32::MAX, 1, i32::MAX as usize), None);
    }
}

/// Debug libraries only: installs the core's logcat diagnostics
/// (`android_log`). A release library exports no `JNI_OnLoad`.
#[cfg(all(target_os = "android", feature = "dev-log"))]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut jni_sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni_sys::jint {
    crate::android_log::install();
    jni_sys::JNI_VERSION_1_6
}
