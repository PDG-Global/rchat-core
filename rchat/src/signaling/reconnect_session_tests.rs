//! Final review I-1: the app's preserve-state reconnect
//! (`rchat_disconnect_transport_only` + `rchat_reconnect`) keeps the Double
//! Ratchet sessions. A message the peer encrypted under the old session
//! while we were away is queued by the relay and decrypts after the
//! reconnect, and our own sending chain still works. Real core clients
//! against a real `--no-tls` test relay; one side goes through the C ABI the
//! iOS app uses. This is the only test in this binary that touches the
//! core's process-wide FFI state.

use super::test_support::*;
use rchat_core::ffi::{
    rchat_connect_with_seed, rchat_disconnect, rchat_disconnect_transport_only, rchat_has_session,
    rchat_initialize, rchat_pin_peer_key, rchat_reconnect, rchat_register_callbacks,
    rchat_request_circuit, rchat_send_message,
};
use rchat_core::{ClientConfig, ConnectionStatus, RChatCallbacks, RChatClient, ReceivedMessage};
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// (sender identity hex, content hex) of every message the FFI side got.
static RECEIVED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn text(p: *const c_char) -> String {
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

extern "C" fn on_message(
    sender: *const c_char,
    content_hex: *const c_char,
    _: u64,
    _: *const c_char,
    _: c_int,
    _expire_secs: u32,
) {
    RECEIVED
        .lock()
        .unwrap()
        .push((text(sender), text(content_hex)));
}
/// The plain core client's received message contents.
#[derive(Clone, Default)]
struct Inbox(Arc<Mutex<Vec<Vec<u8>>>>);

impl RChatCallbacks for Inbox {
    fn on_connection_status_changed(&self, _: ConnectionStatus) {}
    fn on_message_received(&self, message: ReceivedMessage) {
        self.0.lock().unwrap().push(message.content);
    }
    fn on_message_delivered(&self, _: String) {}
    fn on_error(&self, _: String) {}
    fn on_circuit_established(&self, _: String, _: bool) {}
}

extern "C" fn on_state(_: c_int) {}
extern "C" fn on_error(_: *const c_char) {}
extern "C" fn on_circuit(_: *const c_char, _: c_int) {}
extern "C" fn on_delivered(_: *const c_char) {}
extern "C" fn on_reconnect() {}
extern "C" fn on_key(_: *const c_char, _: c_int, _: *const c_char) {}
#[allow(clippy::too_many_arguments)]
extern "C" fn on_request(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: u64,
    _: *const c_char,
    _: *const c_char,
    _: u64,
    _: u32,
) {
}
extern "C" fn on_receipt(_: *const c_char, _: *const c_char, _: c_int) {}
extern "C" fn on_rotated(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: u32,
) {
}
extern "C" fn on_status(_: c_int, _: *const c_char, _: *const c_char, _: c_int) {}
extern "C" fn on_timer(_: *const c_char, _: u32, _: u64, _: c_int) {}
#[allow(clippy::too_many_arguments)]
extern "C" fn on_file(
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

fn ffi_got(sender: &str, body: &str) -> bool {
    let want = hex::encode(body);
    RECEIVED
        .lock()
        .unwrap()
        .iter()
        .any(|(s, c)| s == sender && c.contains(&want))
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn sessions_survive_a_transport_only_disconnect_and_reconnect() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (addr, state) = rt.block_on(start(test_config()));
    let url = format!("ws://{addr}/");
    let a_seed = [0xA1u8; 64];
    let a = TestIdentity::from_seed(0xA1);
    let b = TestIdentity::from_seed(0xB2);
    let a_ak = a.keys.agreement_key_hex();
    let b_ak = b.keys.agreement_key_hex();

    // A: the app's path through the C ABI. No explicit publish: every
    // connect (and reconnect) publishes on its own.
    rchat_disconnect();
    assert_eq!(rchat_initialize(), 0);
    assert_eq!(
        rchat_register_callbacks(
            Some(on_message),
            Some(on_state),
            Some(on_error),
            Some(on_circuit),
            Some(on_delivered),
            Some(on_reconnect),
            Some(on_key),
            Some(on_request),
            Some(on_receipt),
            Some(on_rotated),
            Some(on_status),
            Some(on_file),
            Some(on_timer),
        ),
        0
    );
    // Both sides pin from each other's v3 card: agreement and ML-KEM key.
    let b_kem = hex::encode(b.keys.kem_public());
    assert_eq!(
        unsafe { rchat_pin_peer_key(c(&b.hex).as_ptr(), c(&b_ak).as_ptr(), c(&b_kem).as_ptr(),) },
        0
    );
    let config = c(&format!(
        r#"{{"server_url":"{url}","identity_key_seed":null,
        "connection_timeout_secs":5,"reconnect_max_attempts":1,"message_retry_count":0,
        "enable_delivery_confirmation":true,"keepalive_interval_secs":30,
        "tls_fingerprint":"None","dev_origin":"{DEV_ORIGIN}"}}"#
    ));
    assert_eq!(
        unsafe { rchat_connect_with_seed(config.as_ptr(), a_seed.as_ptr(), 64) },
        0
    );

    // B: a plain core client.
    let bob = RChatClient::new(ClientConfig {
        server_url: url.clone(),
        dev_origin: Some(DEV_ORIGIN.to_string()),
        identity_key_seed: Some(hex::encode([0xB2u8; 64])),
        reconnect_max_attempts: 1,
        enable_delivery_confirmation: true,
        ..ClientConfig::default()
    })
    .unwrap();
    let inbox = Inbox::default();
    bob.set_callbacks(Box::new(inbox.clone()));
    bob.pin_peer_key(a.hex.clone(), a_ak, Some(hex::encode(a.keys.kem_public())))
        .unwrap();
    bob.connect().unwrap();
    wait_for("B's publish", || bob.is_key_bundle_published());
    wait_for("A's publish", || mapped_client(&state, &a).is_some());

    bob.request_circuit(a.hex.clone()).unwrap();
    wait_for("A's ask", || {
        (unsafe { rchat_request_circuit(c(&b.hex).as_ptr()) }) == 0
    });
    let has_b = || unsafe { rchat_has_session(c(&b.hex).as_ptr()) } == 1;
    wait_for("the session", || has_b() && bob.has_session(a.hex.clone()));
    bob.send_text_message(a.hex.clone(), "before".into())
        .unwrap();
    wait_for("the first message", || ffi_got(&b.hex, "before"));

    // Away: the transport goes, the client and its sessions stay.
    assert_eq!(rchat_disconnect_transport_only(), 0);
    wait_for("the relay to see A leave", || {
        mapped_client(&state, &a).is_none()
    });
    // Encrypted under the session A already holds; the relay queues it.
    bob.send_text_message(a.hex.clone(), "while away".into())
        .unwrap();

    assert_eq!(rchat_reconnect(), 0);
    wait_for("the message sent while away", || {
        ffi_got(&b.hex, "while away")
    });

    // A's sending chain is intact too.
    wait_for("A to resume the circuit", || {
        let code = unsafe {
            rchat_send_message(
                c(&b.hex).as_ptr(),
                c("after").as_ptr(),
                std::ptr::null_mut(),
            )
        };
        code == 0
    });
    wait_for("B to get A's reply", || {
        inbox.0.lock().unwrap().iter().any(|m| m == b"after")
    });

    rchat_disconnect();
    let _ = bob.disconnect();
}
