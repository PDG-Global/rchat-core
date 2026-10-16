//! Spec §D.1 end to end: the real core client (BoringSSL and its ticket
//! store) against the real relay (rustls and its in-memory ticketer). A
//! resumed connection saves a round trip and the certificate, never the
//! relay's identity check or the client's connection proof; a relay that
//! refuses the ticket gets a full handshake and no error reaches the app.

use super::*;
use rchat_core::{ClientConfig, ConnectionStatus, RChatCallbacks, RChatClient, ReceivedMessage};
use rustls::server::ProducesTickets;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// One self-signed certificate (`127.0.0.1`) for every relay here: (cert
/// path, key path, cert PEM). Each client trusts it through the core's
/// `test-hooks` trust hook, never through a process-wide environment
/// variable (BoringSSL's C `getenv` would race `set_var`).
fn shared_cert() -> &'static (PathBuf, PathBuf, Vec<u8>) {
    static CERT: OnceLock<(PathBuf, PathBuf, Vec<u8>)> = OnceLock::new();
    CERT.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "rchat-client-resumption-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let pem = ck.cert.pem();
        std::fs::write(&cert, &pem).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (cert, key, pem.into_bytes())
    })
}

/// A relay on `port` (0: any) with the shared certificate. `identity`: its
/// relay identity key file (kept across a restart), or None for a random
/// one; `ticketer`: share ticket keys with another relay; `tickets`:
/// `session_tickets`.
async fn relay(
    port: u16,
    identity: Option<&PathBuf>,
    ticketer: Option<Arc<dyn ProducesTickets>>,
    tickets: bool,
) -> (u16, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let (cert, key, _) = shared_cert().clone();
    let mut tls = crate::config::TlsConfig::static_cert(cert, key);
    tls.session_tickets = tickets;
    let config = ServerConfig {
        bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        max_connections_per_ip: 0,
        tls: Some(tls),
        test_ticketer: ticketer,
        relay_identity_path: identity.map(|p| p.display().to_string()),
        ..ServerConfig::default()
    };
    let server = Server::new(config).await.expect("relay starts");
    let port = server.local_addr().unwrap().port();
    (port, tokio::spawn(server.run()))
}

/// Stop a relay and wait until its listener is gone.
fn stop(rt: &tokio::runtime::Runtime, handle: tokio::task::JoinHandle<anyhow::Result<()>>) {
    handle.abort();
    let _ = rt.block_on(handle);
}

/// A relay identity key path in a fresh directory (created on first start).
fn identity_path() -> PathBuf {
    std::env::temp_dir()
        .join(format!(
            "rchat-client-resumption-id-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
        .join("relay_identity.key")
}

/// Every error the app would see.
#[derive(Clone, Default)]
struct Errors(Arc<Mutex<Vec<String>>>);

impl Errors {
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl RChatCallbacks for Errors {
    fn on_connection_status_changed(&self, status: ConnectionStatus) {
        if let ConnectionStatus::Error { message } = status {
            self.0.lock().unwrap().push(message);
        }
    }
    fn on_message_received(&self, _: ReceivedMessage) {}
    fn on_message_delivered(&self, _: String) {}
    fn on_error(&self, error: String) {
        self.0.lock().unwrap().push(error);
    }
    fn on_circuit_established(&self, _: String, _: bool) {}
}

fn client(port: u16) -> (Arc<RChatClient>, Errors) {
    let client = RChatClient::new(ClientConfig {
        server_url: format!("wss://127.0.0.1:{port}/"),
        identity_key_seed: Some(hex::encode(rand::random::<[u8; 32]>().repeat(2))),
        reconnect_max_attempts: 1,
        connection_timeout_secs: 5,
        ..ClientConfig::default()
    })
    .unwrap();
    client.set_test_trust_pem(&shared_cert().2);
    let errors = Errors::default();
    client.set_callbacks(Box::new(errors.clone()));
    (client, errors)
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A transport-only reconnect (the app's network-change path), until the
/// relay has accepted the publish on the new connection.
fn reconnect_and_publish(client: &RChatClient) {
    client.disconnect_transport_only().unwrap();
    client.connect().unwrap();
    wait_for("the publish", || client.is_key_bundle_published());
}

/// The first connection pins the relay (first use drops what it got); the
/// second leaves tickets held under that pin.
fn pinned_with_tickets(client: &RChatClient) {
    client.connect().unwrap();
    wait_for("the first publish", || client.is_key_bundle_published());
    reconnect_and_publish(client);
    wait_for("tickets", || client.tls_ticket_count() > 0);
}

/// Conn 1 full, conn 2 resumed, and the relay accepted the publish on the
/// resumed connection: the proof was made over its own exporter.
#[test]
fn core_client_resumes_and_still_proves_every_connection() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (port, _relay) = rt.block_on(relay(0, None, None, true));
    let (client, errors) = client(port);
    client.connect().unwrap();
    wait_for("the first publish", || client.is_key_bundle_published());
    assert!(!client.tls_session_resumed(), "conn 1 is a full handshake");
    reconnect_and_publish(&client);
    assert!(
        !client.tls_session_resumed(),
        "first-use tickets were dropped"
    );
    wait_for("tickets", || client.tls_ticket_count() > 0);
    assert!(client.tls_ticket_count() as usize <= rchat_core::tls_resumption::MAX_TICKETS);
    reconnect_and_publish(&client);
    assert!(client.tls_session_resumed(), "conn 3 resumes");
    assert!(errors.all().is_empty(), "{:?}", errors.all());
    client.disconnect().unwrap();
    assert_eq!(client.tls_ticket_count(), 0);
}

/// A server holding the relay's ticket keys but not its identity key (a
/// different relay identity at the same address) resumes the TLS session
/// and is still refused: the pin is checked on every connection.
#[test]
fn resumed_connection_with_wrong_relay_identity_is_refused() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let shared = rustls::crypto::ring::Ticketer::new().unwrap();
    let (port, honest) = rt.block_on(relay(0, None, Some(shared.clone()), true));
    let (client, errors) = client(port);
    pinned_with_tickets(&client);
    assert!(errors.all().is_empty(), "{:?}", errors.all());

    client.disconnect_transport_only().unwrap();
    stop(&rt, honest);
    let (_, _impostor) = rt.block_on(relay(port, None, Some(shared), true));
    let _ = client.connect();
    wait_for("the refusal", || !errors.all().is_empty());
    assert!(
        client.tls_session_resumed(),
        "the impostor resumed the TLS session"
    );
    assert!(
        errors.all().iter().any(|e| e.contains("identity changed")),
        "{:?}",
        errors.all()
    );
    assert!(!client.is_key_bundle_published(), "nothing published to it");
    assert_eq!(client.tls_ticket_count(), 0, "its tickets are dropped");
}

/// The relay restarted (fresh ticket keys) or turned tickets off: the
/// client's ticket is refused, it does a full handshake, publishes, and the
/// app sees no error.
#[test]
fn relay_refusing_resumption_falls_back_cleanly() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let id = identity_path();
    let (port, first) = rt.block_on(relay(0, Some(&id), None, true));
    let (client, errors) = client(port);
    pinned_with_tickets(&client);

    client.disconnect_transport_only().unwrap();
    stop(&rt, first);
    let (_, restarted) = rt.block_on(relay(port, Some(&id), None, true));
    client.connect().unwrap();
    wait_for("the publish", || client.is_key_bundle_published());
    assert!(
        !client.tls_session_resumed(),
        "old ticket key: full handshake"
    );
    wait_for("fresh tickets", || client.tls_ticket_count() > 0);

    client.disconnect_transport_only().unwrap();
    stop(&rt, restarted);
    let (_, _off) = rt.block_on(relay(port, Some(&id), None, false));
    client.connect().unwrap();
    wait_for("the publish", || client.is_key_bundle_published());
    assert!(!client.tls_session_resumed(), "tickets off: full handshake");
    assert!(errors.all().is_empty(), "{:?}", errors.all());
    client.disconnect().unwrap();
    let _ = std::fs::remove_dir_all(id.parent().unwrap());
}

/// Ruling R37 end to end: the real core client (BoringSSL) and the real
/// relay (rustls with `tls_pq`) negotiate X25519MLKEM768, on the first full
/// handshake and on a resumed one, and the relay accepts the connection
/// proof made over that connection's exporter.
#[test]
fn core_client_and_relay_negotiate_x25519mlkem768() {
    use rchat_core::tls_boring::GROUP_X25519_MLKEM768;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (port, _relay) = rt.block_on(relay(0, None, None, true));
    let (client, errors) = client(port);
    client.connect().unwrap();
    wait_for("the first publish", || client.is_key_bundle_published());
    assert_eq!(client.tls_key_exchange_group(), Some(GROUP_X25519_MLKEM768));
    reconnect_and_publish(&client);
    wait_for("tickets", || client.tls_ticket_count() > 0);
    reconnect_and_publish(&client);
    assert!(client.tls_session_resumed(), "conn 3 resumes");
    assert_eq!(client.tls_key_exchange_group(), Some(GROUP_X25519_MLKEM768));
    assert!(errors.all().is_empty(), "{:?}", errors.all());
    client.disconnect().unwrap();
}
