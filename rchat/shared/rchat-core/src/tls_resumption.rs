//! TLS 1.3 resumption tickets for the pinned relay (spec §D.1).
//!
//! Ported from rVPN `rvpn-tls/src/resumption.rs` (its BoringSSL side) and
//! adapted for rChat:
//!
//! - **At most [`MAX_TICKETS`] (2) tickets, each used once.** [`take`]
//!   removes the ticket it returns; a resumed connection gets fresh tickets
//!   from the relay, which the new-session callback [`put`]s back.
//! - **Keyed to one relay**: host, port and relay pin ([`RelayKey`]).
//!   [`bind`] sets the key and drops every ticket when it changes (relay
//!   switch, pin change); a ticket is only ever offered to the bound host
//!   and port.
//! - **Generations.** Every drop starts a new generation, and a connection
//!   records the generation it started in. Tickets from a connection that
//!   started before the last drop (one still finishing after `disconnect()`,
//!   or made under a former pin) are discarded, never stored.
//! - **Memory only.** The store has no serialized form and nothing in it
//!   reaches the state store; tickets die with the process. Persisted
//!   tickets would link connections across app launches.
//! - **No 0-RTT**: early data is switched off on every client connector
//!   (`tls_boring`), so a ticket only ever saves a round trip and the
//!   certificate, never the connection proof.
//!
//! What a ticket does not change: the relay still signs its identity over
//! this connection's TLS exporter (checked against the pin on every
//! connection), and the client still proves its identity over that
//! exporter. TLS 1.3 exporters differ per connection, resumed or not.
//!
//! Linkability (accepted in the spec, as in rVPN): a presented ticket is
//! visible in the ClientHello and links two connections of one client for a
//! network observer. Single use and the relay's 6-hour key rotation bound
//! it; the relay itself learns the identity at publish anyway.
//!
//! [`take`]: ResumptionStore::take
//! [`put`]: ResumptionStore::put
//! [`bind`]: ResumptionStore::bind

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Weak};

use boring::ssl::{SslConnector, SslSession};
use parking_lot::Mutex;

/// Tickets kept for the relay (spec §D.1). The relay issues 2 per handshake.
pub const MAX_TICKETS: usize = 2;

/// The one relay tickets are kept for: where it is and the pin it proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayKey {
    pub host: String,
    pub port: u16,
    pub pin: Option<String>,
}

impl RelayKey {
    /// The key for a `wss://` relay URL and its pin, if the URL has a host.
    pub fn for_url(server_url: &str, pin: Option<&str>) -> Option<Self> {
        let uri: tokio_tungstenite::tungstenite::http::Uri = server_url.parse().ok()?;
        let host = uri.host()?.to_string();
        let default_port = if server_url.starts_with("wss://") {
            443
        } else {
            80
        };
        Some(Self {
            host,
            port: uri.port_u16().unwrap_or(default_port),
            pin: pin.map(str::to_owned),
        })
    }
}

/// A bounded, single-use, memory-only store of TLS 1.3 tickets for one
/// relay. Clones share the store.
#[derive(Clone, Default)]
pub struct ResumptionStore {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    /// Whether the latest connection through the store resumed (kept
    /// across drops; diagnostics and tests).
    last_resumed: std::sync::atomic::AtomicBool,
    /// IANA id of the key exchange group the latest connection negotiated
    /// (0: none yet, or that connection failed; diagnostics and tests).
    last_group: std::sync::atomic::AtomicU16,
    /// Tests only: a PEM trust root replacing the platform roots.
    #[cfg(any(test, feature = "test-hooks"))]
    test_trust_pem: Mutex<Option<Vec<u8>>>,
}

#[derive(Default)]
struct State {
    key: Option<RelayKey>,
    /// Bumped on every drop; tickets from an older generation are refused.
    generation: u64,
    /// Oldest first; never more than `MAX_TICKETS`.
    tickets: VecDeque<SslSession>,
    /// The connector (SSL context) every stored ticket came from, for the
    /// bound host. `SSL_set_session` requires the session and the
    /// connection to share a context; a new connector means a new
    /// generation, so no ticket ever crosses contexts.
    connector: Option<(String, SslConnector)>,
}

impl State {
    fn drop_all(&mut self) {
        self.tickets.clear();
        self.connector = None;
        self.generation = self.generation.wrapping_add(1);
    }
}

/// What a connection carries (as SSL ex-data) so the new-session callback
/// can file its tickets: the store, and the generation it started in.
pub(crate) struct TicketSink {
    store: Weak<Inner>,
    generation: u64,
}

impl TicketSink {
    /// File `ticket` if the store still exists and is in the same generation.
    pub(crate) fn file(&self, ticket: SslSession) {
        if let Some(inner) = self.store.upgrade() {
            ResumptionStore { inner }.put(self.generation, ticket);
        }
    }
}

impl ResumptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep tickets for `key` from now on. A different key (another host,
    /// port or pin) drops every ticket first.
    pub fn bind(&self, key: RelayKey) {
        let mut s = self.inner.state.lock();
        if s.key.as_ref() != Some(&key) {
            s.drop_all();
            s.key = Some(key);
        }
    }

    /// Drop every ticket and the binding (`disconnect()`, identity wipe or
    /// change, a refused relay). Tickets still arriving from a connection
    /// made before this are discarded.
    pub fn clear(&self) {
        let mut s = self.inner.state.lock();
        s.drop_all();
        s.key = None;
    }

    /// Number of tickets held.
    pub fn len(&self) -> usize {
        self.inner.state.lock().tickets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the latest TLS connection made through this store resumed a
    /// session from one of its tickets.
    pub fn last_resumed(&self) -> bool {
        self.inner
            .last_resumed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The key exchange group of the latest connection through the store.
    pub fn last_group(&self) -> Option<u16> {
        match self
            .inner
            .last_group
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            id => Some(id),
        }
    }

    pub(crate) fn note_group(&self, group: Option<u16>) {
        self.inner
            .last_group
            .store(group.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn note_handshake(&self, resumed: bool) {
        self.inner
            .last_resumed
            .store(resumed, std::sync::atomic::Ordering::Relaxed);
    }

    /// Take (remove) the newest ticket, only for the bound host and port.
    pub fn take(&self, host: &str, port: u16) -> Option<SslSession> {
        let mut s = self.inner.state.lock();
        let bound = s.key.as_ref()?;
        if bound.host != host || bound.port != port {
            return None;
        }
        s.tickets.pop_back()
    }

    /// Store a ticket from a connection started in `generation`. Refused
    /// when unbound or when the store was dropped since; the oldest ticket
    /// goes beyond `MAX_TICKETS`.
    pub fn put(&self, generation: u64, ticket: SslSession) {
        let mut s = self.inner.state.lock();
        if s.key.is_none() || s.generation != generation {
            return;
        }
        s.tickets.push_back(ticket);
        while s.tickets.len() > MAX_TICKETS {
            s.tickets.pop_front();
        }
    }

    /// Everything a resumable connection needs, under ONE lock acquisition:
    /// the connector for `host` (built with `build` if there is none for
    /// that host yet), the sink for its tickets (current generation), and
    /// the newest stored ticket, taken (removed). Because the three come
    /// from the same critical section, the ticket always belongs to the
    /// returned connector's SSL context: a concurrent `clear`, `bind` or
    /// connector rebuild either happens before (no ticket) or after (the
    /// ticket was already ours). Unbound or bound to another host or port:
    /// `None` (connect without resumption).
    pub(crate) fn connector_for(
        &self,
        host: &str,
        port: u16,
        build: impl FnOnce() -> std::io::Result<SslConnector>,
    ) -> std::io::Result<Option<(SslConnector, TicketSink, Option<SslSession>)>> {
        let mut s = self.inner.state.lock();
        match s.key.as_ref() {
            Some(k) if k.host == host && k.port == port => {}
            _ => return Ok(None),
        }
        let current = match &s.connector {
            Some((h, c)) if h == host => c.clone(),
            _ => {
                // A new context: nothing stored so far may be offered on it.
                let generation = s.generation;
                s.drop_all();
                debug_assert_ne!(generation, s.generation);
                let c = build()?;
                s.connector = Some((host.to_owned(), c.clone()));
                c
            }
        };
        let sink = TicketSink {
            store: Arc::downgrade(&self.inner),
            generation: s.generation,
        };
        // Same lock: every stored ticket was filed under this generation,
        // so by this connector (a rebuild above dropped all of them).
        let ticket = s.tickets.pop_back();
        Ok(Some((current, sink, ticket)))
    }

    /// Tests (and, with the `test-hooks` feature, the relay's integration
    /// tests): trust this PEM certificate instead of the platform roots for
    /// the connectors this store builds from now on. Never in production.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_test_trust_pem(&self, pem: &[u8]) {
        *self.inner.test_trust_pem.lock() = Some(pem.to_vec());
        let mut s = self.inner.state.lock();
        s.drop_all();
    }

    /// The trust store `set_test_trust_pem` asked for, if any.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn test_trust(&self) -> Option<boring::x509::store::X509Store> {
        let pem = self.inner.test_trust_pem.lock().clone()?;
        let mut b = boring::x509::store::X509StoreBuilder::new().ok()?;
        for cert in boring::x509::X509::stack_from_pem(&pem).ok()? {
            b.add_cert(cert).ok()?;
        }
        Some(b.build())
    }

    /// Tests only: the raw TLS ticket of every stored session.
    #[cfg(test)]
    pub(crate) fn ticket_bytes(&self) -> Vec<Vec<u8>> {
        self.inner
            .state
            .lock()
            .tickets
            .iter()
            .map(crate::tls_boring::session_ticket_bytes)
            .collect()
    }

    /// Tests only: the resumption master secret of every stored session
    /// (`SSL_SESSION_get_master_key`).
    #[cfg(test)]
    pub(crate) fn master_keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .state
            .lock()
            .tickets
            .iter()
            .map(|t| {
                let mut buf = vec![0u8; t.master_key_len()];
                let n = t.master_key(&mut buf);
                buf.truncate(n);
                buf
            })
            .collect()
    }

    /// Tests only: the generation in force.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.inner.state.lock().generation
    }
}

// Structure only, never key material.
impl fmt::Debug for ResumptionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.inner.state.lock();
        f.debug_struct("ResumptionStore")
            .field("bound", &s.key.is_some())
            .field("tickets", &s.tickets.len())
            .finish()
    }
}

/// A BoringSSL TLS 1.3 server for the resumption tests (no relay behind
/// it): it writes one byte and holds the connection until the client goes.
/// BoringSSL issues 2 tickets per handshake by default, as the relay does.
#[cfg(test)]
pub(crate) mod test_server {
    use boring::asn1::Asn1Time;
    use boring::bn::BigNum;
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::{PKey, Private};
    use boring::ssl::{SslAcceptor, SslMethod, SslOptions, SslVersion};
    use boring::x509::extension::SubjectAlternativeName;
    use boring::x509::store::{X509Store, X509StoreBuilder};
    use boring::x509::{X509NameBuilder, X509};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::ResumptionStore;
    use crate::tls_boring::{connect_resumable_with, BoringTlsStream, TlsFingerprint};

    pub(crate) struct TestTlsServer {
        pub addr: SocketAddr,
        cert: X509,
        key: PKey<Private>,
        acceptor: Arc<parking_lot::RwLock<Arc<SslAcceptor>>>,
    }

    fn self_signed() -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(rand::random::<u32>() | 1)
            .unwrap()
            .to_asn1_integer()
            .unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&b.x509v3_context(None, None))
            .unwrap();
        b.append_extension(&san).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    /// A fresh acceptor: new ticket keys. `tickets` false: no tickets at
    /// all; `early_data`: the server would accept 0-RTT.
    fn acceptor(
        cert: &X509,
        key: &PKey<Private>,
        tickets: bool,
        early_data: bool,
    ) -> Arc<SslAcceptor> {
        acceptor_with_groups(cert, key, tickets, early_data, None)
    }

    /// `acceptor`, offering only `groups` (when None, the defaults of
    /// boring-sys's patched BoringSSL, which already include X25519MLKEM768).
    fn acceptor_with_groups(
        cert: &X509,
        key: &PKey<Private>,
        tickets: bool,
        early_data: bool,
        groups: Option<&str>,
    ) -> Arc<SslAcceptor> {
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        if let Some(groups) = groups {
            b.set_curves_list(groups).unwrap();
        }
        b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
        b.set_certificate(cert).unwrap();
        b.set_private_key(key).unwrap();
        if !tickets {
            b.set_options(SslOptions::NO_TICKET);
        }
        if early_data {
            // SAFETY: the live SSL_CTX of this builder; sets a flag.
            unsafe { boring_sys::SSL_CTX_set_early_data_enabled(b.as_ptr(), 1) };
        }
        Arc::new(b.build())
    }

    impl TestTlsServer {
        pub(crate) async fn start(tickets: bool, early_data: bool) -> Self {
            Self::start_with_groups(tickets, early_data, None).await
        }

        /// A server offering only `groups` (None: boring-sys's defaults).
        pub(crate) async fn start_with_groups(
            tickets: bool,
            early_data: bool,
            groups: Option<&str>,
        ) -> Self {
            let (cert, key) = self_signed();
            let acceptor = Arc::new(parking_lot::RwLock::new(acceptor_with_groups(
                &cert, &key, tickets, early_data, groups,
            )));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let current = acceptor.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = current.read().clone();
                    tokio::spawn(async move {
                        let Ok(stream) = tokio_boring::accept(&acceptor, tcp).await else {
                            return;
                        };
                        let (mut rd, mut wr) = tokio::io::split(stream);
                        if wr.write_all(b"x").await.is_err() || wr.flush().await.is_err() {
                            return;
                        }
                        let mut buf = [0u8; 64];
                        while let Ok(n) = rd.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                        }
                    });
                }
            });
            Self {
                addr,
                cert,
                key,
                acceptor,
            }
        }

        /// The server restarts: new ticket keys (old tickets are refused),
        /// optionally with tickets switched off.
        pub(crate) fn restart(&self, tickets: bool) {
            *self.acceptor.write() = acceptor(&self.cert, &self.key, tickets, false);
        }

        pub(crate) fn trust(&self) -> X509Store {
            let mut b = X509StoreBuilder::new().unwrap();
            b.add_cert(self.cert.clone()).unwrap();
            b.build()
        }

        pub(crate) fn port(&self) -> u16 {
            self.addr.port()
        }

        /// Connect as the core does, through `store`, and read the server's
        /// byte (which also takes in the tickets sent after the handshake).
        pub(crate) async fn dial(&self, store: &ResumptionStore) -> BoringTlsStream {
            let tcp = TcpStream::connect(self.addr).await.unwrap();
            let mut s = connect_resumable_with(
                tcp,
                "localhost",
                self.port(),
                TlsFingerprint::Chrome,
                store,
                Some(self.trust()),
            )
            .await
            .expect("TLS handshake");
            let mut byte = [0u8; 1];
            s.read_exact(&mut byte).await.unwrap();
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::TestTlsServer;
    use super::*;

    fn key_for(server: &TestTlsServer, pin: &str) -> RelayKey {
        RelayKey {
            host: "localhost".into(),
            port: server.port(),
            pin: Some(pin.into()),
        }
    }

    /// Ruling R37: the client offers X25519MLKEM768 then X25519. A server
    /// with the hybrid group negotiates it (full and resumed handshakes);
    /// a classical-only server falls back to X25519 with no error.
    #[tokio::test]
    async fn hybrid_group_preferred_and_x25519_fallback() {
        use crate::tls_boring::{GROUP_X25519, GROUP_X25519_MLKEM768};
        let pq = TestTlsServer::start_with_groups(true, false, Some("X25519MLKEM768")).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&pq, "rk:1:a"));
        let c1 = pq.dial(&store).await;
        assert_eq!(c1.negotiated_group(), Some(GROUP_X25519_MLKEM768));
        assert_eq!(store.last_group(), Some(GROUP_X25519_MLKEM768));
        let c2 = pq.dial(&store).await;
        assert!(c2.session_reused());
        assert_eq!(c2.negotiated_group(), Some(GROUP_X25519_MLKEM768));

        let classical =
            TestTlsServer::start_with_groups(true, false, Some("X25519:P-256:P-384")).await;
        store.bind(key_for(&classical, "rk:1:a"));
        let c3 = classical.dial(&store).await;
        assert_eq!(c3.negotiated_group(), Some(GROUP_X25519));
        assert_eq!(store.last_group(), Some(GROUP_X25519));
    }

    /// rVPN's three-connection shape: conn 1 full, conn 2 resumed through
    /// the store, then a relay with tickets off: a full handshake.
    #[tokio::test]
    async fn three_connections_full_resumed_then_tickets_off_full() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let c1 = server.dial(&store).await;
        assert!(!c1.session_reused(), "conn 1 is a full handshake");
        assert!(!store.is_empty(), "conn 1's tickets are kept");
        let c2 = server.dial(&store).await;
        assert!(c2.session_reused(), "conn 2 resumes");

        let off = TestTlsServer::start(false, false).await;
        store.bind(key_for(&off, "rk:1:a"));
        let c3 = off.dial(&store).await;
        assert!(!c3.session_reused(), "tickets off: full handshake");
        assert!(store.is_empty(), "no ticket from a relay with tickets off");
    }

    /// At most two tickets, each offered once.
    #[tokio::test]
    async fn at_most_two_tickets_each_used_once() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        for _ in 0..4 {
            let _c = server.dial(&store).await;
            assert!(store.len() <= MAX_TICKETS, "never more than 2");
        }
        assert_eq!(store.len(), MAX_TICKETS);
        let before = store.ticket_bytes();
        let first = store.take("localhost", server.port()).unwrap();
        let second = store.take("localhost", server.port()).unwrap();
        assert!(store.take("localhost", server.port()).is_none());
        let taken = [
            crate::tls_boring::session_ticket_bytes(&first),
            crate::tls_boring::session_ticket_bytes(&second),
        ];
        assert_ne!(taken[0], taken[1], "each ticket is handed out once");
        assert!(before.iter().all(|t| taken.contains(t)));
    }

    /// A ticket is only offered to the bound host and port.
    #[tokio::test]
    async fn tickets_only_for_the_bound_host_and_port() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let _c = server.dial(&store).await;
        let held = store.len();
        assert!(held > 0);
        assert!(store.take("localhost", server.port() ^ 1).is_none());
        assert!(store.take("127.0.0.1", server.port()).is_none());
        assert_eq!(store.len(), held, "a refused take removes nothing");
        // Another relay: nothing offered, nothing kept from the old one.
        let other = TestTlsServer::start(true, false).await;
        store.bind(key_for(&other, "rk:1:a"));
        assert!(store.is_empty());
        let c = other.dial(&store).await;
        assert!(!c.session_reused());
    }

    /// Dropping (a new pin, `clear`) starts a new generation: tickets from
    /// a connection that started before are discarded.
    #[tokio::test]
    async fn drops_discard_tickets_from_older_connections() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let _c = server.dial(&store).await;
        let stale = store.take("localhost", server.port()).unwrap();
        let generation = store.generation();

        store.bind(key_for(&server, "rk:1:a"));
        assert_eq!(store.generation(), generation, "same key: kept");
        store.bind(key_for(&server, "rk:1:b"));
        assert!(store.is_empty(), "pin change drops every ticket");
        store.put(generation, stale.clone());
        assert!(store.is_empty(), "a ticket from before the drop is refused");

        let _c = server.dial(&store).await;
        assert!(!store.is_empty());
        let generation = store.generation();
        store.clear();
        store.put(generation, stale);
        assert!(store.is_empty(), "nothing is kept after clear()");
        assert!(store.take("localhost", server.port()).is_none());
    }

    /// The relay restarted (new ticket keys) or has tickets off: the stored
    /// ticket is refused and the connection is a full handshake, no error.
    #[tokio::test]
    async fn relay_refusing_resumption_falls_back_cleanly() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let _c = server.dial(&store).await;
        server.restart(true);
        let c = server.dial(&store).await;
        assert!(!c.session_reused(), "unknown ticket key: full handshake");
        assert!(!store.is_empty(), "the new keys' tickets are kept");
        let c = server.dial(&store).await;
        assert!(c.session_reused(), "and resume the next connection");

        server.restart(false);
        let c = server.dial(&store).await;
        assert!(!c.session_reused(), "tickets off: full handshake");
    }

    /// No 0-RTT, even against a server that would take it: the ticket is
    /// used, but no early data is offered, sent or accepted.
    #[tokio::test]
    async fn early_data_is_never_offered() {
        let server = TestTlsServer::start(true, true).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let _c = server.dial(&store).await;
        let c = server.dial(&store).await;
        assert!(c.session_reused());
        assert!(!c.in_early_data());
        assert!(!c.early_data_accepted(), "early data must never be used");
    }

    /// The ticket comes out of `connector_for` together with its
    /// connector, in one critical section; a rebuilt connector (another
    /// context) never gets a ticket stored under the old one. (The former
    /// race needed a `clear`/`bind`/rebuild between two lock acquisitions;
    /// with one acquisition there is no interleaving left to schedule.)
    #[tokio::test]
    async fn connector_and_ticket_come_from_one_critical_section() {
        let server = TestTlsServer::start(true, false).await;
        let store = ResumptionStore::new();
        store.bind(key_for(&server, "rk:1:a"));
        let _c = server.dial(&store).await;
        let held = store.len();
        let built = std::cell::Cell::new(false);
        let (_, sink, ticket) = store
            .connector_for("localhost", server.port(), || {
                built.set(true);
                unreachable!("the cached connector is reused")
            })
            .unwrap()
            .unwrap();
        assert!(!built.get());
        assert!(ticket.is_some(), "a ticket for the cached connector");
        assert_eq!(store.len(), held - 1, "taken, not copied");
        assert_eq!(sink.generation, store.generation());

        // A new connector (here: the cached one is gone after a rebind to
        // another pin and back) is handed out with no ticket.
        let _c = server.dial(&store).await;
        assert!(!store.is_empty());
        store.inner.state.lock().connector = None;
        let (_, sink, ticket) = store
            .connector_for("localhost", server.port(), || {
                crate::tls_boring::test_connector(server.trust())
            })
            .unwrap()
            .unwrap();
        assert!(ticket.is_none(), "no ticket from another SSL context");
        assert!(store.is_empty());
        assert_eq!(sink.generation, store.generation());
    }

    #[test]
    fn relay_key_from_urls() {
        let k = RelayKey::for_url("wss://chat.example.com/p", Some("rk:1:x")).unwrap();
        assert_eq!((k.host.as_str(), k.port), ("chat.example.com", 443));
        let k = RelayKey::for_url("wss://127.0.0.1:18443/", None).unwrap();
        assert_eq!((k.host.as_str(), k.port, k.pin), ("127.0.0.1", 18443, None));
        assert!(RelayKey::for_url("not a url", None).is_none());
    }
}
