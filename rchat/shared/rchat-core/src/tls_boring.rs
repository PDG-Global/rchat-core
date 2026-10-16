//! Client TLS over BoringSSL.
//!
//! This is not browser fingerprint mimicry. The ClientHello is BoringSSL's
//! own with a few settings: TLS 1.3 only, ALPN `http/1.1` only, BoringSSL's
//! default TLS 1.3 cipher suites, GREASE not enabled. Its JA3/JA4 hash is therefore that of a BoringSSL
//! client configured this way, not that of Chrome, Firefox or Safari, and a
//! DPI system that compares against real browser fingerprints can tell it
//! apart. The `TlsFingerprint` variants other than `None` currently all
//! produce this same ClientHello; `None` uses BoringSSL's defaults
//! (`connect_standard`) apart from the key exchange groups below.
//!
//! Early data (0-RTT) is switched off on every connector. With a
//! [`ResumptionStore`] (`connect_resumable`), the ClientHello offers a
//! stored TLS 1.3 ticket for the pinned relay (`SSL_set_session`) and the
//! new-session callback keeps the relay's fresh tickets (spec §D.1). A
//! relay that refuses the ticket gets a full handshake, with no error.
//!
//! Key exchange (ruling R37): every connector offers the hybrid
//! post-quantum group X25519MLKEM768 first and X25519 second
//! ([`KEY_EXCHANGE_GROUPS`]), sending a key share for each, so a relay with
//! the hybrid group uses it and one without falls back to X25519 with no
//! extra round trip. (boring-sys patches BoringSSL so that its default list
//! already starts with X25519MLKEM768, then the obsolete draft group
//! P256Kyber768Draft00, X25519, P-256 and P-384; the explicit list drops the
//! draft group and the NIST curves and keeps the order fixed whatever the
//! defaults become.)

use std::pin::Pin;
use std::task::{Context, Poll};

use boring::ssl::{
    Ssl, SslConnector, SslConnectorBuilder, SslMethod, SslSessionCacheMode, SslVersion,
};
use boring::x509::store::X509Store;
use foreign_types::ForeignTypeRef;
use once_cell::sync::Lazy;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::tls_resumption::{ResumptionStore, TicketSink};

/// Where a resumable connection keeps the store and generation its tickets
/// are filed under (SSL ex-data).
static TICKET_SINK: Lazy<boring::ex_data::Index<Ssl, TicketSink>> =
    Lazy::new(|| Ssl::new_ex_index().expect("SSL ex-data index"));

/// No 0-RTT, ever (spec §D.1): BoringSSL never offers or sends early data
/// from a connector built with this, whatever a ticket allows.
fn disable_early_data(builder: &mut SslConnectorBuilder) {
    // SAFETY: `as_ptr` is the live SSL_CTX this builder owns; the call only
    // sets a flag on it.
    unsafe { boring_sys::SSL_CTX_set_early_data_enabled(builder.as_ptr(), 0) };
}

/// Supported groups, most preferred first: hybrid X25519 + ML-KEM-768
/// (IANA 0x11EC), then plain X25519.
pub const KEY_EXCHANGE_GROUPS: &str = "X25519MLKEM768:X25519";

/// IANA group id of X25519MLKEM768.
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;
/// IANA group id of X25519.
pub const GROUP_X25519: u16 = 0x001d;

/// Offer [`KEY_EXCHANGE_GROUPS`]. Fails closed: a BoringSSL without the
/// hybrid group is an error, never a silent classical-only ClientHello.
fn set_key_exchange_groups(builder: &mut SslConnectorBuilder) -> std::io::Result<()> {
    builder
        .set_curves_list(KEY_EXCHANGE_GROUPS)
        .map_err(|e| std::io::Error::other(format!("Failed to set TLS groups: {e}")))
}

/// ClientHello profile names (accepted in config). `Chrome`, `Firefox` and
/// `Safari` all select the same TLS 1.3-only BoringSSL ClientHello today;
/// none of them reproduces that browser's real fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum TlsFingerprint {
    /// Default: the TLS 1.3-only, ALPN http/1.1 BoringSSL ClientHello
    #[default]
    Chrome,
    /// Same ClientHello as `Chrome` (name kept for config compatibility)
    Firefox,
    /// Same ClientHello as `Chrome` (name kept for config compatibility)
    Safari,
    /// BoringSSL's default ClientHello (`connect_standard`)
    None,
}

/// A BoringSSL client TLS stream
pub struct BoringTlsStream {
    inner: SslStream<TcpStream>,
}

impl BoringTlsStream {
    fn new(stream: SslStream<TcpStream>) -> Self {
        Self { inner: stream }
    }

    /// Whether this connection resumed a TLS session from a ticket.
    pub fn session_reused(&self) -> bool {
        self.inner.ssl().session_reused()
    }

    /// Whether the server accepted early data on this connection (never,
    /// since early data is off: kept for the tests that prove it).
    pub fn early_data_accepted(&self) -> bool {
        // SAFETY: a live SSL owned by this stream; a read-only query.
        unsafe { boring_sys::SSL_early_data_accepted(self.inner.ssl().as_ptr()) == 1 }
    }

    /// Whether the connection is still in its early-data phase.
    pub fn in_early_data(&self) -> bool {
        // SAFETY: as above.
        unsafe { boring_sys::SSL_in_early_data(self.inner.ssl().as_ptr()) == 1 }
    }

    /// The IANA id of the key exchange group this connection negotiated
    /// ([`GROUP_X25519_MLKEM768`] with a relay that has it).
    pub fn negotiated_group(&self) -> Option<u16> {
        self.inner.ssl().curve()
    }

    /// TLS 1.3 exporter (RFC 8446 §7.5) for key authentication: label
    /// `EXPORTER-rchat-conn-auth-v1`, empty context, 32 bytes.
    pub fn export_channel_binding(&self) -> std::io::Result<[u8; 32]> {
        let label = std::str::from_utf8(crate::keyauth::EXPORTER_LABEL)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut out = [0u8; 32];
        self.inner
            .ssl()
            .export_keying_material(&mut out, label, Some(&[]))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(out)
    }
}

impl AsyncRead for BoringTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoringTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Build the TLS connector for the non-`None` profiles:
/// - TLS 1.3 only (no TLS 1.2)
/// - BoringSSL's default TLS 1.3 cipher suites
/// - ALPN with http/1.1 only (for WebSocket compatibility)
///
/// This does not reproduce Chrome's ClientHello (Chrome also offers TLS 1.2,
/// h2, GREASE and its own extension set); the function name is historical.
///
/// `resumable` enables the client session cache and the new-session callback
/// that files each TLS 1.3 ticket into the connection's `ResumptionStore`.
/// `trust` replaces the platform trust roots (tests only; never on iOS).
#[allow(unused_variables)]
fn build_chrome_connector(
    host: &str,
    sni_hostname: Option<&str>,
    resumable: bool,
    trust: Option<X509Store>,
) -> std::io::Result<SslConnector> {
    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create SSL connector: {}", e),
        )
    })?;

    // TLS 1.3 only
    let _ = builder.set_min_proto_version(Some(SslVersion::TLS1_3));
    let _ = builder.set_max_proto_version(Some(SslVersion::TLS1_3));

    // Set ALPN to http/1.1 only (critical for WebSocket compatibility)
    builder.set_alpn_protos(b"\x08http/1.1").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to set ALPN: {}", e),
        )
    })?;

    // TLS 1.3 cipher suites are not configurable in BoringSSL: its built-in
    // list is used. `set_cipher_list` only affects TLS 1.2, which is
    // disabled above, so this call (whose error is ignored) changes nothing
    // on the wire.
    let _ = builder.set_cipher_list(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    );

    // Hybrid post-quantum key exchange first, X25519 as the fallback.
    set_key_exchange_groups(&mut builder)?;

    // Certificate verification
    // On iOS: the Network Extension sandbox blocks /etc/ssl/, so we use a
    // custom callback that delegates to Apple's Security framework.
    // On other platforms: use boring's built-in CA store.
    #[cfg(target_os = "ios")]
    {
        let sni = sni_hostname.unwrap_or(host);
        set_ios_cert_verify(&mut builder, sni);
    }

    #[cfg(not(target_os = "ios"))]
    {
        builder.set_verify(boring::ssl::SslVerifyMode::PEER);
        match trust {
            Some(store) => builder.set_verify_cert_store(store),
            None => builder.set_default_verify_paths(),
        }
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to set verify paths: {}", e),
            )
        })?;
    }

    disable_early_data(&mut builder);

    // Resumption: the client session cache must be on for the new-session
    // callback to fire. For TLS 1.3 it fires once per NewSessionTicket the
    // relay sends after the handshake, the only point a ticket exists.
    if resumable {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(|ssl, session| {
            if let Some(sink) = ssl.ex_data(*TICKET_SINK) {
                sink.file(session);
            }
        });
    }

    Ok(builder.build())
}

/// Connect to a server over BoringSSL TLS
///
/// 1. Connects via TCP
/// 2. Performs the TLS handshake with the selected profile's settings
///    (see the module notes: no browser fingerprint is reproduced)
/// 3. Forces ALPN to http/1.1
/// 4. Returns the TLS stream for WebSocket upgrade
pub async fn connect_with_fingerprint(
    tcp: TcpStream,
    host: &str,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
) -> std::io::Result<BoringTlsStream> {
    if fingerprint == TlsFingerprint::None {
        return connect_standard(tcp, host, sni_hostname).await;
    }

    // Build the TLS 1.3-only SSL context
    let connector = build_chrome_connector(host, sni_hostname, false, None)?;

    // Determine actual SNI hostname for the TLS handshake
    let sni = sni_hostname.unwrap_or(host);

    // Configure SSL with SNI
    let config = connector.configure().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to configure SSL: {}", e),
        )
    })?;

    // Perform TLS handshake
    let stream = tokio_boring::connect(config, sni, tcp).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("TLS handshake failed: {}", e),
        )
    })?;

    Ok(BoringTlsStream::new(stream))
}

/// `connect_with_fingerprint`, offering a ticket from `store` for this relay
/// and keeping the tickets it sends (spec §D.1). The store must be bound to
/// `host` and `port` (`ResumptionStore::bind`); otherwise, and with profile
/// `None`, no ticket is offered or kept. A refused ticket, or one that
/// cannot be attached, means a full handshake, never an error.
pub async fn connect_resumable(
    tcp: TcpStream,
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
    store: &ResumptionStore,
) -> std::io::Result<BoringTlsStream> {
    #[cfg(any(test, feature = "test-hooks"))]
    let trust = store.test_trust();
    #[cfg(not(any(test, feature = "test-hooks")))]
    let trust = None;
    connect_resumable_with(tcp, host, port, fingerprint, store, trust).await
}

/// Tests only: a resumable connector trusting `trust`.
#[cfg(test)]
pub(crate) fn test_connector(trust: X509Store) -> std::io::Result<SslConnector> {
    build_chrome_connector("localhost", None, true, Some(trust))
}

pub(crate) async fn connect_resumable_with(
    tcp: TcpStream,
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
    store: &ResumptionStore,
    trust: Option<X509Store>,
) -> std::io::Result<BoringTlsStream> {
    store.note_handshake(false);
    store.note_group(None);
    if fingerprint == TlsFingerprint::None {
        let stream = connect_standard(tcp, host, None).await?;
        store.note_group(stream.negotiated_group());
        return Ok(stream);
    }
    let Some((connector, sink, ticket)) = store.connector_for(host, port, || {
        build_chrome_connector(host, None, true, trust)
    })?
    else {
        let stream = connect_with_fingerprint(tcp, host, fingerprint, None).await?;
        store.note_group(stream.negotiated_group());
        return Ok(stream);
    };
    let mut config = connector.configure().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to configure SSL: {}", e),
        )
    })?;
    config.set_ex_data(*TICKET_SINK, sink);
    if let Some(ticket) = ticket {
        // SAFETY: `connector_for` handed out `connector` and `ticket` in one
        // critical section of the store's lock. Tickets are filed only
        // through the new-session callback of the connector cached in the
        // store, only under the generation that connector was handed out
        // in, and replacing the connector bumps the generation and drops
        // every ticket, so `ticket` belongs to `config`'s SSL context.
        if let Err(e) = unsafe { config.set_session(&ticket) } {
            log::debug!("[RUST] TLS ticket not attached ({e}); full handshake");
        }
    }
    let stream = tokio_boring::connect(config, host, tcp)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("TLS handshake failed: {}", e),
            )
        })?;
    let resumed = stream.ssl().session_reused();
    store.note_handshake(resumed);
    let stream = BoringTlsStream::new(stream);
    let group = stream.negotiated_group();
    store.note_group(group);
    log::debug!(
        "[RUST] TLS handshake done (resumed={resumed}, group={:#06x})",
        group.unwrap_or(0)
    );
    Ok(stream)
}

/// Tests only: the raw ticket a stored session would present.
#[cfg(test)]
pub(crate) fn session_ticket_bytes(session: &boring::ssl::SslSession) -> Vec<u8> {
    use foreign_types::ForeignType;
    let mut ptr: *const u8 = std::ptr::null();
    let mut len: usize = 0;
    // SAFETY: a live session; BoringSSL points `ptr` into it for `len`
    // bytes, copied before the session can go away.
    unsafe {
        boring_sys::SSL_SESSION_get0_ticket(session.as_ptr(), &mut ptr, &mut len);
        if ptr.is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(ptr, len).to_vec()
    }
}

/// TLS connection with BoringSSL's default settings (profile `None`)
async fn connect_standard(
    tcp: TcpStream,
    host: &str,
    sni_hostname: Option<&str>,
) -> std::io::Result<BoringTlsStream> {
    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create SSL connector: {}", e),
        )
    })?;

    // TLS 1.3
    let _ = builder.set_min_proto_version(Some(SslVersion::TLS1_3));
    let _ = builder.set_max_proto_version(Some(SslVersion::TLS1_3));

    // ALPN: http/1.1 for WebSocket
    builder.set_alpn_protos(b"\x08http/1.1").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to set ALPN: {}", e),
        )
    })?;

    // The same groups as every other connector: post-quantum hybrid first.
    set_key_exchange_groups(&mut builder)?;

    // SNI hostname
    let sni = sni_hostname.unwrap_or(host);

    // Certificate verification
    #[cfg(target_os = "ios")]
    set_ios_cert_verify(&mut builder, sni);

    #[cfg(not(target_os = "ios"))]
    {
        builder.set_verify(boring::ssl::SslVerifyMode::PEER);
        builder.set_default_verify_paths().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to set default verify paths: {}", e),
            )
        })?;
    }

    disable_early_data(&mut builder);
    let connector = builder.build();
    let config = connector.configure().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to configure SSL: {}", e),
        )
    })?;

    let stream = tokio_boring::connect(config, sni, tcp).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("TLS handshake failed: {}", e),
        )
    })?;

    Ok(BoringTlsStream::new(stream))
}

/// On iOS the Network Extension sandbox blocks filesystem access to /etc/ssl/,
/// so BoringSSL's set_default_verify_paths() finds no CA roots.
/// We install a custom verify callback that delegates to Apple's
/// SecTrustEvaluateWithError via the security-framework crate.
#[cfg(target_os = "ios")]
fn set_ios_cert_verify(builder: &mut boring::ssl::SslConnectorBuilder, hostname: &str) {
    use security_framework::certificate::SecCertificate;
    use security_framework::policy::SecPolicy;
    use security_framework::secure_transport::SslProtocolSide;
    use security_framework::trust::SecTrust;

    let hostname = hostname.to_string();
    builder.set_verify_callback(
        boring::ssl::SslVerifyMode::PEER,
        move |_preverify_ok, ctx| {
            // Get the full chain presented by the server
            let chain = match ctx.chain() {
                Some(c) => c,
                None => return false,
            };

            // Convert each OpenSSL X509 cert to DER bytes then into a SecCertificate
            let sec_certs: Vec<SecCertificate> = chain
                .iter()
                .filter_map(|cert| {
                    let der = cert.to_der().ok()?;
                    SecCertificate::from_der(&der).ok()
                })
                .collect();

            if sec_certs.is_empty() {
                return false;
            }

            // SSL policy for server auth against the target hostname
            let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, Some(&hostname));

            let trust = match SecTrust::create_with_certificates(&sec_certs, &[policy]) {
                Ok(t) => t,
                Err(_) => return false,
            };

            // Evaluate using the iOS system trust store
            match trust.evaluate_with_error() {
                Ok(_) => true,
                Err(_) => false,
            }
        },
    );
}

/// Parse fingerprint from string
pub fn fingerprint_from_str(s: &str) -> Option<TlsFingerprint> {
    match s.to_lowercase().as_str() {
        "chrome" | "chrome120" => Some(TlsFingerprint::Chrome),
        "firefox" | "firefox120" => Some(TlsFingerprint::Firefox),
        "safari" | "safari17" => Some(TlsFingerprint::Safari),
        "none" | "standard" => Some(TlsFingerprint::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_parsing() {
        assert_eq!(fingerprint_from_str("chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(fingerprint_from_str("Chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(
            fingerprint_from_str("firefox"),
            Some(TlsFingerprint::Firefox)
        );
        assert_eq!(fingerprint_from_str("safari"), Some(TlsFingerprint::Safari));
        assert_eq!(fingerprint_from_str("none"), Some(TlsFingerprint::None));
        assert_eq!(fingerprint_from_str("invalid"), None);
    }

    #[test]
    fn test_fingerprint_default_is_chrome() {
        let fp: TlsFingerprint = Default::default();
        assert_eq!(fp, TlsFingerprint::Chrome);
    }
}
