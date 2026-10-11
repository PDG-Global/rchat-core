//! Client TLS over BoringSSL.
//!
//! This is not browser fingerprint mimicry. The ClientHello is BoringSSL's
//! own with a few settings: TLS 1.3 only, ALPN `http/1.1` only, BoringSSL's
//! default TLS 1.3 cipher suites, GREASE not enabled. Its JA3/JA4 hash is therefore that of a BoringSSL
//! client configured this way, not that of Chrome, Firefox or Safari, and a
//! DPI system that compares against real browser fingerprints can tell it
//! apart. The `TlsFingerprint` variants other than `None` currently all
//! produce this same ClientHello; `None` uses BoringSSL's defaults
//! (`connect_standard`).

use std::pin::Pin;
use std::task::{Context, Poll};

use boring::ssl::{SslConnector, SslMethod, SslVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

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
#[allow(unused_variables)]
fn build_chrome_connector(host: &str, sni_hostname: Option<&str>) -> std::io::Result<SslConnector> {
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
        builder.set_default_verify_paths().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to set default verify paths: {}", e),
            )
        })?;
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
    let connector = build_chrome_connector(host, sni_hostname)?;

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
