//! TLS front end for the unified listener.
//!
//! Two certificate sources, never both:
//! - **Static**: a cert/key pair from disk, hot-reloadable with SIGHUP.
//! - **ACME**: certificates issued and renewed in-process from Let's Encrypt
//!   using TLS-ALPN-01 on this same listener (no port 80).
//!
//! Every traffic handshake is TLS 1.3 only, ring provider, no 0-RTT and no
//! ALPN (unchanged from before: clients offer `http/1.1`, the WebSocket and
//! decoy paths run after the handshake). The ACME challenge configuration is
//! also TLS 1.3 only and answers nothing but `acme-tls/1`.
//!
//! Before the first ACME certificate exists, the resolver has nothing to
//! serve, so traffic handshakes fail until issuance completes.

#[cfg(feature = "native-tls")]
compile_error!("key authentication needs a TLS exporter; build without the native-tls feature");

use crate::config::{AcmeConfig, ServerConfig, TlsMode};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig as RustlsServerConfig, SupportedProtocolVersion};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// The only protocol version the server speaks.
static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// ALPN protocol id for TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server config for normal traffic: TLS 1.3 only, no ALPN, no early data.
pub fn traffic_config(resolver: Arc<dyn ResolvesServerCert>) -> Result<Arc<RustlsServerConfig>> {
    let mut config = RustlsServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(TLS13_ONLY)
        .context("failed to configure TLS 1.3")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Server config used only for TLS-ALPN-01 validation handshakes.
fn challenge_config(resolver: Arc<dyn ResolvesServerCert>) -> Result<Arc<RustlsServerConfig>> {
    let mut config = RustlsServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(TLS13_ONLY)
        .context("failed to configure TLS 1.3")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Which server config a ClientHello is handed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRoute {
    /// A TLS-ALPN-01 validation connection from the ACME server.
    AcmeChallenge,
    /// Everything else: WebSocket clients, browsers (decoy), probes.
    Traffic,
}

/// RFC 8737 section 3: a validation ClientHello offers `acme-tls/1` and
/// nothing else. Anything that also offers another protocol (or no ALPN at
/// all) is ordinary traffic and gets the normal certificate.
pub fn route_for_alpn<'a, I>(offered: Option<I>) -> HandshakeRoute
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut protocols = match offered {
        Some(p) => p.into_iter(),
        None => return HandshakeRoute::Traffic,
    };
    match (protocols.next(), protocols.next()) {
        (Some(only), None) if only == ACME_TLS_ALPN => HandshakeRoute::AcmeChallenge,
        _ => HandshakeRoute::Traffic,
    }
}

fn route_for_hello(hello: &ClientHello<'_>) -> HandshakeRoute {
    route_for_alpn(hello.alpn())
}

/// Result of a completed server handshake.
pub enum Accepted<S> {
    /// A normal TLS 1.3 session, ready for the decoy/WebSocket path.
    Traffic(Box<TlsStream<S>>),
    /// An ACME validation handshake was answered; drop the connection.
    ChallengeAnswered,
}

/// This connection's channel binding: the TLS 1.3 exporter (RFC 8446 §7.5)
/// with label `EXPORTER-rchat-conn-auth-v1`, empty context, 32 bytes. A
/// connection proof signed over another session's exporter fails.
pub fn channel_binding<S>(tls: &TlsStream<S>) -> Result<[u8; 32]> {
    let (_, conn) = tls.get_ref();
    conn.export_keying_material(
        [0u8; 32],
        rchat_core::keyauth::EXPORTER_LABEL,
        Some(b"".as_slice()),
    )
    .map_err(|e| anyhow!("TLS exporter failed: {e}"))
}

#[derive(Clone)]
enum FrontKind {
    Static(TlsAcceptor),
    Acme {
        challenge: Arc<RustlsServerConfig>,
        traffic: Arc<RustlsServerConfig>,
    },
}

/// The listener's TLS acceptor.
#[derive(Clone)]
pub struct TlsFront {
    kind: FrontKind,
    handshake_timeout: Duration,
}

impl TlsFront {
    fn new(kind: FrontKind, handshake_timeout: Duration) -> Self {
        Self {
            kind,
            handshake_timeout,
        }
    }

    /// Build the front end for `config`. `Ok(None)` means plaintext, which is
    /// only possible after an explicit `--no-tls`. Any problem loading the
    /// certificate, or preparing ACME, is an error: there is no fallback to
    /// plaintext.
    pub async fn from_config(config: &ServerConfig) -> Result<Option<Self>> {
        let timeout = config.tls_handshake_timeout();
        match config.tls_mode()? {
            TlsMode::Plaintext => {
                spawn_sighup_reload(None);
                Ok(None)
            }
            TlsMode::Static {
                cert_path,
                key_path,
            } => {
                let expiry = Arc::new(CertExpiry::default());
                let resolver = Arc::new(StaticCertResolver::load_with_expiry(
                    cert_path,
                    key_path,
                    expiry.clone(),
                )?);
                spawn_expiry_monitor(expiry);
                spawn_sighup_reload(Some(resolver.clone()));
                let acceptor = TlsAcceptor::from(traffic_config(resolver)?);
                info!("TLS 1.3 enabled with static certificate (SIGHUP reloads it)");
                Ok(Some(Self::new(FrontKind::Static(acceptor), timeout)))
            }
            TlsMode::Acme(acme) => {
                if config.bind_addr.port() != 443 {
                    warn!(
                        "ACME: listening on port {}, but Let's Encrypt validates TLS-ALPN-01 on \
                         port 443 only. Make sure public :443 is forwarded to this listener \
                         without TLS termination in between.",
                        config.bind_addr.port()
                    );
                }
                let (challenge, traffic) = start_acme(&acme).await?;
                spawn_sighup_reload(None);
                Ok(Some(Self::new(
                    FrontKind::Acme { challenge, traffic },
                    timeout,
                )))
            }
        }
    }

    /// Complete a server handshake within the configured timeout.
    pub async fn accept<S>(&self, stream: S) -> Result<Accepted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(self.handshake_timeout, self.accept_inner(stream)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "TLS handshake not completed within {:?}",
                self.handshake_timeout
            )),
        }
    }

    async fn accept_inner<S>(&self, stream: S) -> Result<Accepted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match &self.kind {
            FrontKind::Static(acceptor) => {
                Ok(Accepted::Traffic(Box::new(acceptor.accept(stream).await?)))
            }
            FrontKind::Acme { challenge, traffic } => {
                let start = LazyConfigAcceptor::new(Acceptor::default(), stream).await?;
                match route_for_hello(&start.client_hello()) {
                    HandshakeRoute::AcmeChallenge => {
                        let mut tls = start.into_stream(challenge.clone()).await?;
                        let _ = tls.shutdown().await;
                        Ok(Accepted::ChallengeAnswered)
                    }
                    HandshakeRoute::Traffic => Ok(Accepted::Traffic(Box::new(
                        start.into_stream(traffic.clone()).await?,
                    ))),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Static certificate
// ---------------------------------------------------------------------------

/// Serves a cert/key pair from disk and can swap it in place on reload.
#[derive(Debug)]
pub struct StaticCertResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
    expiry: Arc<CertExpiry>,
}

impl StaticCertResolver {
    #[cfg(test)]
    pub fn load(cert_path: PathBuf, key_path: PathBuf) -> Result<Self> {
        Self::load_with_expiry(cert_path, key_path, Arc::new(CertExpiry::default()))
    }

    pub fn load_with_expiry(
        cert_path: PathBuf,
        key_path: PathBuf,
        expiry: Arc<CertExpiry>,
    ) -> Result<Self> {
        let key = load_certified_key(&cert_path, &key_path)?;
        expiry.record_der(&key.cert[0]);
        Ok(Self {
            cert_path,
            key_path,
            current: RwLock::new(Arc::new(key)),
            expiry,
        })
    }

    /// Re-read the files. On failure the previous certificate stays live.
    pub fn reload(&self) -> Result<()> {
        let key = load_certified_key(&self.cert_path, &self.key_path)?;
        self.expiry.record_der(&key.cert[0]);
        *self.current.write() = Arc::new(key);
        self.expiry.check_and_log();
        Ok(())
    }
}

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().clone())
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let certs = load_certs(cert_path)
        .with_context(|| format!("failed to load TLS certificate chain from {cert_path:?}"))?;
    let key = load_private_key(key_path)
        .with_context(|| format!("failed to load TLS private key from {key_path:?}"))?;
    CertifiedKey::from_der(certs, key, &ring_provider())
        .with_context(|| format!("TLS key {key_path:?} does not match certificate {cert_path:?}"))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let content = std::fs::read(path)?;
    let certs = CertificateDer::pem_slice_iter(&content).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        bail!("no PEM certificates found");
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let content = std::fs::read(path)?;
    match PrivateKeyDer::from_pem_slice(&content) {
        Ok(key) => Ok(key),
        Err(PemError::NoItemsFound) => Err(anyhow!("no PEM private key found")),
        Err(e) => Err(e.into()),
    }
}

/// Handle SIGHUP (`systemctl reload`) in every mode so it never falls through
/// to the default action, which would terminate the process. With a static
/// certificate it reloads the files; otherwise there is nothing to reload.
#[cfg(unix)]
fn spawn_sighup_reload(resolver: Option<Arc<StaticCertResolver>>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hangups = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            warn!("cannot install SIGHUP handler; certificate reload needs a restart: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            match &resolver {
                Some(resolver) => match resolver.reload() {
                    Ok(()) => info!("SIGHUP: TLS certificate reloaded"),
                    Err(e) => {
                        error!("SIGHUP: TLS certificate reload failed, keeping the old one: {e:#}")
                    }
                },
                None => info!("SIGHUP: nothing to reload (no static certificate in use)"),
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload(_resolver: Option<Arc<StaticCertResolver>>) {}

// ---------------------------------------------------------------------------
// Certificate expiry
// ---------------------------------------------------------------------------

const EXPIRY_WARN_SECS: i64 = 7 * 86_400;
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Tracks the notAfter of the certificate being served, exports it as the
/// `rchat_tls_cert_not_after_seconds` gauge, and warns when it is close.
#[derive(Debug, Default)]
pub struct CertExpiry {
    not_after: parking_lot::Mutex<Option<i64>>,
}

impl CertExpiry {
    /// Record from a PEM bundle (the first CERTIFICATE block is the leaf;
    /// key blocks are skipped).
    pub fn record_pem(&self, pem: &[u8]) {
        if let Some(t) = leaf_not_after(pem) {
            self.set(t);
        }
    }

    pub fn record_der(&self, der: &[u8]) {
        if let Some(t) = der_not_after(der) {
            self.set(t);
        }
    }

    fn set(&self, not_after: i64) {
        *self.not_after.lock() = Some(not_after);
        crate::metrics::TLS_CERT_NOT_AFTER.set(not_after as f64);
    }

    pub fn get(&self) -> Option<i64> {
        *self.not_after.lock()
    }

    /// Warn (or error, if expired) about the certificate being served.
    pub fn check_and_log(&self) {
        let Some(not_after) = self.get() else { return };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        match expiry_status(not_after, now) {
            ExpiryStatus::Valid => {}
            ExpiryStatus::ExpiringSoon { days_left } => warn!(
                "TLS certificate expires in {days_left} day(s). With ACME this means renewal \
                 has been failing (check the ACME warnings); with a static certificate, renew \
                 it and reload (SIGHUP)."
            ),
            ExpiryStatus::Expired => error!(
                "TLS certificate being served has EXPIRED; clients will reject it. With ACME a \
                 new order is in progress (check the ACME warnings); with a static \
                 certificate, renew it and reload (SIGHUP)."
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    Valid,
    ExpiringSoon { days_left: i64 },
    Expired,
}

pub fn expiry_status(not_after: i64, now: i64) -> ExpiryStatus {
    let left = not_after - now;
    if left <= 0 {
        ExpiryStatus::Expired
    } else if left < EXPIRY_WARN_SECS {
        ExpiryStatus::ExpiringSoon {
            days_left: left / 86_400,
        }
    } else {
        ExpiryStatus::Valid
    }
}

fn der_not_after(der: &[u8]) -> Option<i64> {
    x509_parser::parse_x509_certificate(der)
        .ok()
        .map(|(_, cert)| cert.validity().not_after.timestamp())
}

fn leaf_not_after(pem: &[u8]) -> Option<i64> {
    let leaf = CertificateDer::pem_slice_iter(pem).next()?.ok()?;
    der_not_after(&leaf)
}

fn spawn_expiry_monitor(expiry: Arc<CertExpiry>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EXPIRY_CHECK_INTERVAL);
        loop {
            tick.tick().await;
            expiry.check_and_log();
        }
    });
}

// ---------------------------------------------------------------------------
// ACME
// ---------------------------------------------------------------------------

async fn start_acme(
    acme: &AcmeConfig,
) -> Result<(Arc<RustlsServerConfig>, Arc<RustlsServerConfig>)> {
    acme.validate()?;
    let contacts = acme.normalized_contacts()?;
    let cache_dir = acme.cache_dir.clone();
    let prepared = cache_dir.clone();
    tokio::task::spawn_blocking(move || prepare_cache_dir(&prepared))
        .await
        .context("ACME cache directory task failed")??;

    let directory_url = if acme.staging {
        rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY
    } else {
        rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
    };
    let expiry = Arc::new(CertExpiry::default());
    let cache = SecureDirCache::new(cache_dir.clone(), expiry.clone());
    let have_cert = cache.cert_path(&acme.domains, directory_url).exists();
    let retry_floor = acme_retry_floor(acme.staging);

    info!(
        "ACME: Let's Encrypt {} directory, domains {:?}, cache {:?}",
        if acme.staging {
            "STAGING"
        } else {
            "production"
        },
        acme.domains,
        cache_dir
    );
    if acme.staging {
        warn!("ACME: staging certificates are NOT trusted by clients; switch staging off once issuance works");
    }
    if !have_cert {
        warn!(
            "ACME: no certificate cached yet. TLS handshakes will FAIL until Let's Encrypt \
             issues one (usually under a minute). Issuance needs public DNS for {:?} pointing \
             here and port 443 reaching this listener directly.",
            acme.domains
        );
        if !acme.staging {
            warn!(
                "ACME: first production issuance. Let's Encrypt allows only 5 failed \
                 validations per host name per hour; set `staging = true` first if this host \
                 has not been tested."
            );
        }
    }

    let state = rustls_acme::AcmeConfig::new_with_provider(acme.domains.clone(), ring_provider())
        .contact(contacts)
        .cache(cache)
        .directory(directory_url)
        .state();

    let resolver = state.resolver();
    let challenge = challenge_config(resolver.clone())?;
    let traffic = traffic_config(resolver)?;

    spawn_expiry_monitor(expiry.clone());
    tokio::spawn(drive_acme(state, have_cert, retry_floor, expiry));
    Ok((challenge, traffic))
}

/// Minimum time between failed ACME attempts. rustls-acme's own backoff
/// starts at 1 s and doubles (1, 2, 4, 8, 16 s ...), which on a misconfigured
/// first production run would spend Let's Encrypt's 5 failed validations per
/// host per hour in about half a minute. Production attempts are therefore
/// spaced at least 5 minutes apart (at most 12 per hour, and in practice the
/// library's doubling takes over after a few). Staging keeps the fast
/// library backoff for quick iteration.
fn acme_retry_floor(staging: bool) -> Duration {
    if staging {
        Duration::ZERO
    } else {
        Duration::from_secs(300)
    }
}

/// Map an ACME error to a recovery instruction when it points at a corrupt
/// cache file.
fn cache_recovery_hint(text: &str) -> Option<&'static str> {
    if text.contains("invalid key pair") {
        Some(
            "the cached ACME account key looks corrupt. Stop the server, delete \
             account-*.der in cache_dir and start again; a new account is registered \
             automatically.",
        )
    } else if text.contains("cached cert parse") {
        Some(
            "the cached certificate looks corrupt. Stop the server, delete cert-*.pem in \
             cache_dir and start again; a new certificate is ordered (mind production rate \
             limits).",
        )
    } else {
        None
    }
}

/// Poll the ACME state machine forever: initial issuance, challenge data and
/// renewals (rustls-acme renews when two thirds of the lifetime has passed).
/// Errors are retried by rustls-acme with exponential backoff, never closer
/// together than `retry_floor`, and never stop the server.
async fn drive_acme<S, E>(
    mut state: S,
    mut ready: bool,
    retry_floor: Duration,
    expiry: Arc<CertExpiry>,
) where
    S: futures_util::Stream<Item = Result<rustls_acme::EventOk, E>> + Unpin,
    E: std::fmt::Display,
{
    use rustls_acme::EventOk;
    let mut rate_limit_warned = false;
    while let Some(event) = state.next().await {
        match event {
            Ok(EventOk::DeployedCachedCert) => {
                ready = true;
                info!("ACME: cached certificate loaded; TLS is ready");
                expiry.check_and_log();
            }
            Ok(EventOk::DeployedNewCert) => {
                rate_limit_warned = false;
                if ready {
                    info!("ACME: certificate renewed and deployed (no restart needed)");
                } else {
                    ready = true;
                    info!("ACME: certificate issued and deployed; TLS is ready");
                }
                expiry.check_and_log();
            }
            Ok(EventOk::CertCacheStore) => debug!("ACME: certificate written to cache"),
            Ok(EventOk::AccountCacheStore) => debug!("ACME: account key written to cache"),
            Err(err) => {
                let text = err.to_string();
                match acme_rate_limit(&text) {
                    Some(retry) if !rate_limit_warned => {
                        rate_limit_warned = true;
                        warn!(
                            "ACME: rate-limited by Let's Encrypt{}. Retrying automatically with \
                             backoff; further rate-limit errors are logged at debug. \
                             See https://letsencrypt.org/docs/rate-limits/",
                            retry
                                .map(|r| format!(" (retry after {r})"))
                                .unwrap_or_default()
                        );
                    }
                    Some(_) => debug!("ACME: still rate-limited"),
                    None => {
                        warn!(
                            "ACME: certificate {} failed, will retry with backoff{}: {}",
                            if ready { "renewal" } else { "issuance" },
                            if retry_floor.is_zero() {
                                String::new()
                            } else {
                                format!(" (not before {} s)", retry_floor.as_secs())
                            },
                            truncate(&text, 400)
                        );
                        if let Some(hint) = cache_recovery_hint(&text) {
                            warn!("ACME: {hint}");
                        }
                    }
                }
                if !retry_floor.is_zero() {
                    tokio::time::sleep(retry_floor).await;
                }
            }
        }
    }
    error!("ACME: certificate manager stopped; renewals will not run until the server restarts");
}

/// If an ACME error is a Let's Encrypt rate-limit response, return
/// `Some(retry_after_hint)`; otherwise `None`.
fn acme_rate_limit(text: &str) -> Option<Option<String>> {
    let is_rate_limit = text.contains("urn:ietf:params:acme:error:rateLimited")
        || text.contains("rateLimited")
        || text.contains("status: 429");
    if !is_rate_limit {
        return None;
    }
    let hint = text.find("retry after ").map(|i| {
        let rest = &text[i + "retry after ".len()..];
        let end = [": see", "\\\"", "\"", "\\n", ","]
            .iter()
            .filter_map(|stop| rest.find(stop))
            .min()
            .unwrap_or(rest.len())
            .min(64);
        // `end` is a byte offset capped at 64: never split a character.
        crate::validate::prefix(rest, end).trim().to_string()
    });
    Some(hint.filter(|h| !h.is_empty()))
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Create (or tighten) the cache directory: owner-only, 0700. Existing files
/// are tightened to 0600. Fails if the directory cannot be created or its
/// permissions cannot be set (e.g. it belongs to another user).
fn prepare_cache_dir(dir: &Path) -> Result<()> {
    if !dir.is_absolute() {
        bail!("ACME cache_dir {dir:?} must be absolute");
    }
    let refuse_symlink = || -> Result<()> {
        if let Ok(meta) = std::fs::symlink_metadata(dir) {
            if meta.file_type().is_symlink() {
                bail!(
                    "ACME cache_dir {dir:?} is a symlink; refusing to follow it. Point \
                     cache_dir at the real directory."
                );
            }
        }
        Ok(())
    };
    refuse_symlink()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create ACME cache directory {dir:?}"))?;
        refuse_symlink()?;
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() {
            bail!("ACME cache_dir {dir:?} is not a directory");
        }
        if meta.permissions().mode() & 0o077 != 0 {
            warn!("ACME: tightening permissions on {dir:?} to 0700");
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot set 0700 on ACME cache directory {dir:?}"))?;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() && meta.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("cannot set 0600 on {:?}", entry.path()))?;
            }
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create ACME cache directory {dir:?}"))?;
    Ok(())
}

/// ACME cache on disk. Unlike rustls-acme's `DirCache`, every file is written
/// owner-only (0600) via a temp file and atomic rename, so the account key and
/// certificate private keys are never world-readable, even briefly.
///
/// File names hash the domains (or contacts) together with the directory URL,
/// so staging and production entries never collide.
struct SecureDirCache {
    dir: PathBuf,
    expiry: Arc<CertExpiry>,
}

impl SecureDirCache {
    fn new(dir: PathBuf, expiry: Arc<CertExpiry>) -> Self {
        Self { dir, expiry }
    }

    fn file_name(kind: &str, ext: &str, items: &[String], directory_url: &str) -> String {
        let mut hasher = Sha256::new();
        for item in items {
            hasher.update(item.as_bytes());
            hasher.update([0u8]);
        }
        hasher.update(directory_url.as_bytes());
        format!("{kind}-{}.{ext}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Private key + certificate chain, PEM.
    fn cert_path(&self, domains: &[String], directory_url: &str) -> PathBuf {
        self.dir
            .join(Self::file_name("cert", "pem", domains, directory_url))
    }

    /// ACME account key, PKCS#8 DER.
    fn account_path(&self, contacts: &[String], directory_url: &str) -> PathBuf {
        self.dir
            .join(Self::file_name("account", "der", contacts, directory_url))
    }

    async fn read(path: PathBuf) -> std::io::Result<Option<Vec<u8>>> {
        tokio::task::spawn_blocking(move || match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        })
        .await
        .map_err(std::io::Error::other)?
    }

    async fn write(path: PathBuf, contents: Vec<u8>) -> std::io::Result<()> {
        tokio::task::spawn_blocking(move || write_private_file(&path, &contents))
            .await
            .map_err(std::io::Error::other)?
    }
}

/// Write `contents` to `path` as a 0600 file: unique temp file (pid + random,
/// `create_new`), fsync, atomic rename, then fsync the directory so the
/// rename itself survives a crash.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("cache path has no parent"))?;
    let tmp = dir.join(format!(
        ".{}.{}.{:016x}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[async_trait::async_trait]
impl rustls_acme::CertCache for SecureDirCache {
    type EC = std::io::Error;
    async fn load_cert(&self, domains: &[String], url: &str) -> Result<Option<Vec<u8>>, Self::EC> {
        let cert = Self::read(self.cert_path(domains, url)).await?;
        if let Some(pem) = &cert {
            self.expiry.record_pem(pem);
        }
        Ok(cert)
    }
    async fn store_cert(&self, domains: &[String], url: &str, cert: &[u8]) -> Result<(), Self::EC> {
        self.expiry.record_pem(cert);
        Self::write(self.cert_path(domains, url), cert.to_vec()).await
    }
}

#[async_trait::async_trait]
impl rustls_acme::AccountCache for SecureDirCache {
    type EA = std::io::Error;
    async fn load_account(
        &self,
        contacts: &[String],
        url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        Self::read(self.account_path(contacts, url)).await
    }
    async fn store_account(
        &self,
        contacts: &[String],
        url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        Self::write(self.account_path(contacts, url), account.to_vec()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// Unique scratch directory under the system temp dir.
    fn scratch_dir(tag: &str) -> crate::ScratchDir {
        crate::ScratchDir::new(&format!("rchat-tls-test-{tag}"))
    }

    /// Write a fresh self-signed cert and key; returns (cert, key) paths.
    fn self_signed(dir: &Path) -> (PathBuf, PathBuf) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (cert, key)
    }

    #[derive(Debug)]
    struct AcceptAnyCert(Arc<CryptoProvider>);

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

    fn client(versions: &[&'static SupportedProtocolVersion], alpn: &[&[u8]]) -> TlsConnector {
        let provider = ring_provider();
        let mut config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
    }

    /// Accept one connection with `front`; report how the server saw it.
    async fn serve_once(
        front: TlsFront,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<&'static str>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            match front.accept(tcp).await? {
                Accepted::ChallengeAnswered => Ok("challenge"),
                Accepted::Traffic(mut tls) => {
                    let mut buf = [0u8; 4];
                    tls.read_exact(&mut buf).await?;
                    assert_eq!(&buf, b"ping");
                    tls.write_all(b"pong").await?;
                    tls.flush().await?;
                    Ok("traffic")
                }
            }
        });
        (addr, task)
    }

    async fn connect(
        addr: std::net::SocketAddr,
        connector: TlsConnector,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
    }

    fn static_front(timeout: Duration) -> TlsFront {
        let dir = scratch_dir("static");
        let (cert, key) = self_signed(&dir);
        let resolver = Arc::new(StaticCertResolver::load(cert, key).unwrap());
        TlsFront::new(
            FrontKind::Static(TlsAcceptor::from(traffic_config(resolver).unwrap())),
            timeout,
        )
    }

    /// An ACME-shaped front with self-signed certs standing in for the ACME
    /// resolver, so the ALPN dispatch can be exercised end to end.
    fn acme_shaped_front() -> TlsFront {
        let dir = scratch_dir("acme");
        let (cert, key) = self_signed(&dir);
        let resolver: Arc<dyn ResolvesServerCert> =
            Arc::new(StaticCertResolver::load(cert, key).unwrap());
        TlsFront::new(
            FrontKind::Acme {
                challenge: challenge_config(resolver.clone()).unwrap(),
                traffic: traffic_config(resolver).unwrap(),
            },
            Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn static_front_accepts_tls13() {
        let (addr, server) = serve_once(static_front(Duration::from_secs(5))).await;
        let mut tls = connect(addr, client(&[&rustls::version::TLS13], &[b"http/1.1"]))
            .await
            .expect("TLS 1.3 handshake must succeed");
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        // No ALPN is negotiated on the traffic path (unchanged behaviour).
        assert_eq!(tls.get_ref().1.alpn_protocol(), None);
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        assert_eq!(server.await.unwrap().unwrap(), "traffic");
    }

    #[tokio::test]
    async fn static_front_refuses_tls12() {
        let (addr, server) = serve_once(static_front(Duration::from_secs(5))).await;
        let result = connect(addr, client(&[&rustls::version::TLS12], &[])).await;
        assert!(result.is_err(), "TLS 1.2 handshake must be refused");
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn acme_front_refuses_tls12_on_both_paths() {
        for alpn in [&[][..], &[ACME_TLS_ALPN][..]] {
            let (addr, server) = serve_once(acme_shaped_front()).await;
            let result = connect(addr, client(&[&rustls::version::TLS12], alpn)).await;
            assert!(result.is_err(), "TLS 1.2 must be refused (alpn {alpn:?})");
            assert!(server.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn acme_front_routes_validation_handshake_to_challenge_config() {
        let (addr, server) = serve_once(acme_shaped_front()).await;
        let tls = connect(addr, client(&[&rustls::version::TLS13], &[ACME_TLS_ALPN]))
            .await
            .expect("challenge handshake must succeed");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ACME_TLS_ALPN));
        assert_eq!(server.await.unwrap().unwrap(), "challenge");
    }

    #[tokio::test]
    async fn acme_front_routes_websocket_clients_to_traffic_config() {
        for alpn in [
            &[b"http/1.1".as_slice()][..],
            &[][..],
            &[ACME_TLS_ALPN, b"http/1.1"][..],
        ] {
            let (addr, server) = serve_once(acme_shaped_front()).await;
            let mut tls = connect(addr, client(&[&rustls::version::TLS13], alpn))
                .await
                .expect("traffic handshake must succeed");
            assert_eq!(tls.get_ref().1.alpn_protocol(), None, "alpn {alpn:?}");
            tls.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(server.await.unwrap().unwrap(), "traffic");
        }
    }

    #[tokio::test]
    async fn handshake_timeout_drops_silent_connections() {
        let (addr, server) = serve_once(static_front(Duration::from_millis(200))).await;
        let _idle = TcpStream::connect(addr).await.unwrap(); // never sends a ClientHello
        let started = std::time::Instant::now();
        let err = server.await.unwrap().expect_err("must time out");
        assert!(err.to_string().contains("not completed within"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn alpn_routing_decision() {
        let route = |p: Option<Vec<&[u8]>>| route_for_alpn(p);
        assert_eq!(route(None), HandshakeRoute::Traffic);
        assert_eq!(route(Some(vec![])), HandshakeRoute::Traffic);
        assert_eq!(
            route(Some(vec![ACME_TLS_ALPN])),
            HandshakeRoute::AcmeChallenge
        );
        assert_eq!(route(Some(vec![b"http/1.1"])), HandshakeRoute::Traffic);
        assert_eq!(
            route(Some(vec![b"h2", b"http/1.1"])),
            HandshakeRoute::Traffic
        );
        assert_eq!(
            route(Some(vec![ACME_TLS_ALPN, b"http/1.1"])),
            HandshakeRoute::Traffic
        );
        assert_eq!(route(Some(vec![b"acme-tls/2"])), HandshakeRoute::Traffic);
    }

    #[test]
    fn unloadable_static_tls_is_an_error() {
        let dir = scratch_dir("bad");
        let (cert, key) = self_signed(&dir);
        // Missing files.
        assert!(StaticCertResolver::load(dir.join("nope.pem"), key.clone()).is_err());
        assert!(StaticCertResolver::load(cert.clone(), dir.join("nope.pem")).is_err());
        // Garbage contents.
        let junk = dir.join("junk.pem");
        std::fs::write(&junk, "not a pem file").unwrap();
        assert!(StaticCertResolver::load(junk.clone(), key.clone()).is_err());
        assert!(StaticCertResolver::load(cert.clone(), junk).is_err());
        // Key from a different certificate.
        let other = scratch_dir("other");
        let (_, other_key) = self_signed(&other);
        assert!(StaticCertResolver::load(cert, other_key).is_err());
    }

    #[tokio::test]
    async fn from_config_refuses_unloadable_static_cert() {
        let cfg = ServerConfig {
            tls: Some(crate::config::TlsConfig {
                cert_path: "/nonexistent/cert.pem".into(),
                key_path: "/nonexistent/key.pem".into(),
            }),
            ..ServerConfig::default()
        };
        assert!(TlsFront::from_config(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn from_config_plaintext_only_with_explicit_no_tls() {
        let cfg = ServerConfig::default();
        assert!(
            TlsFront::from_config(&cfg).await.is_err(),
            "no TLS and no --no-tls"
        );
        let mut cfg = ServerConfig {
            bind_addr: "127.0.0.1:8443".parse().unwrap(),
            ..ServerConfig::default()
        };
        cfg.disable_tls_for_dev(false);
        assert!(TlsFront::from_config(&cfg).await.unwrap().is_none());
    }

    #[test]
    fn static_reload_keeps_old_cert_on_failure_and_swaps_on_success() {
        let dir = scratch_dir("reload");
        let (cert, key) = self_signed(&dir);
        let resolver = StaticCertResolver::load(cert.clone(), key.clone()).unwrap();
        let before = resolver.current.read().cert[0].clone();
        std::fs::write(&cert, "broken").unwrap();
        assert!(resolver.reload().is_err());
        assert_eq!(resolver.current.read().cert[0], before);
        let fresh = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert, fresh.cert.pem()).unwrap();
        std::fs::write(&key, fresh.key_pair.serialize_pem()).unwrap();
        resolver.reload().unwrap();
        assert_ne!(resolver.current.read().cert[0], before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn acme_cache_is_owner_only() {
        use rustls_acme::{AccountCache, CertCache};
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("cache");
        let dir = base.join("nested").join("acme");
        prepare_cache_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);

        let cache = SecureDirCache::new(dir.clone(), Arc::new(CertExpiry::default()));
        let domains = vec!["chat.example.com".to_string()];
        let url = rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY;
        assert_eq!(cache.load_cert(&domains, url).await.unwrap(), None);
        cache.store_cert(&domains, url, b"cert+key").await.unwrap();
        cache.store_account(&[], url, b"account-key").await.unwrap();
        assert_eq!(
            cache.load_cert(&domains, url).await.unwrap().as_deref(),
            Some(&b"cert+key"[..])
        );
        assert_eq!(mode(&cache.cert_path(&domains, url)), 0o600);
        assert_eq!(mode(&cache.account_path(&[], url)), 0o600);
        // Staging and production never share a file.
        assert_ne!(
            cache.cert_path(&domains, url),
            cache.cert_path(
                &domains,
                rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
            )
        );

        // A loosened directory and file are tightened again on startup.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let loose = dir.join("loose.pem");
        std::fs::write(&loose, "x").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        prepare_cache_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&loose), 0o600);
    }

    #[test]
    fn rate_limit_errors_are_recognised() {
        let body = r#"order: acme error: http request error: non 2xx http status: 429 "{\"type\":\"urn:ietf:params:acme:error:rateLimited\",\"detail\":\"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-10-03 06:01:16 UTC: see https://letsencrypt.org/docs/rate-limits/\",\"status\":429}""#;
        assert_eq!(
            acme_rate_limit(body),
            Some(Some("2026-10-03 06:01:16 UTC".to_string()))
        );
        assert_eq!(acme_rate_limit("rateLimited without a hint"), Some(None));
        assert_eq!(
            acme_rate_limit("order: acme error: http request error: non 2xx http status: 400"),
            None
        );
        assert_eq!(
            acme_rate_limit("authorization for chat.example.com failed too many times"),
            None
        );
    }

    fn failing_events(
        n: usize,
    ) -> impl futures_util::Stream<Item = Result<rustls_acme::EventOk, &'static str>> + Unpin {
        futures_util::stream::iter((0..n).map(|_| Err("order: acme error: boom")))
    }

    #[tokio::test(start_paused = true)]
    async fn acme_retry_floor_spaces_failed_attempts() {
        let floor = Duration::from_secs(300);
        let start = tokio::time::Instant::now();
        drive_acme(
            failing_events(3),
            false,
            floor,
            Arc::new(CertExpiry::default()),
        )
        .await;
        assert!(start.elapsed() >= floor * 3, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn acme_retry_floor_zero_adds_no_delay() {
        let start = tokio::time::Instant::now();
        drive_acme(
            failing_events(3),
            false,
            Duration::ZERO,
            Arc::new(CertExpiry::default()),
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn retry_floor_applies_to_production_only() {
        assert_eq!(acme_retry_floor(true), Duration::ZERO);
        assert!(acme_retry_floor(false) >= Duration::from_secs(300));
    }

    #[test]
    fn expiry_classification() {
        let now = 1_900_000_000;
        let day = 86_400;
        assert_eq!(expiry_status(now + 30 * day, now), ExpiryStatus::Valid);
        assert_eq!(
            expiry_status(now + 3 * day, now),
            ExpiryStatus::ExpiringSoon { days_left: 3 }
        );
        assert_eq!(
            expiry_status(now + 7 * day - 1, now),
            ExpiryStatus::ExpiringSoon { days_left: 6 }
        );
        assert_eq!(expiry_status(now, now), ExpiryStatus::Expired);
        assert_eq!(expiry_status(now - day, now), ExpiryStatus::Expired);
    }

    fn pem_with_not_after(year: i32) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(year, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn leaf_not_after_is_read_from_acme_style_pem() {
        // rustls-acme stores the private key PEM first, then the chain.
        let (cert, key) = pem_with_not_after(2030);
        let combined = format!("{key}\n{cert}");
        assert_eq!(leaf_not_after(combined.as_bytes()), Some(1_893_456_000));
        assert_eq!(leaf_not_after(b"garbage"), None);
    }

    #[test]
    fn static_cert_expiry_is_recorded() {
        let dir = scratch_dir("expiry");
        let (cert, key) = pem_with_not_after(2031);
        std::fs::write(dir.join("c.pem"), cert).unwrap();
        std::fs::write(dir.join("k.pem"), key).unwrap();
        let expiry = Arc::new(CertExpiry::default());
        let resolver = StaticCertResolver::load_with_expiry(
            dir.join("c.pem"),
            dir.join("k.pem"),
            expiry.clone(),
        )
        .unwrap();
        assert_eq!(expiry.get(), Some(1_924_992_000));
        drop(resolver);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cache_dir_is_refused() {
        let base = scratch_dir("symlink");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("acme");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = prepare_cache_dir(&link).expect_err("symlink must be refused");
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
    }

    #[test]
    fn private_file_writes_leave_no_temp_files() {
        let dir = scratch_dir("tmpnames");
        let target = dir.join("cert-x.pem");
        // A stale temp file from a crashed run must not get in the way.
        std::fs::write(dir.join(".cert-x.pem.tmp"), "stale").unwrap();
        write_private_file(&target, b"one").unwrap();
        write_private_file(&target, b"two").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"two");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp") && n != ".cert-x.pem.tmp")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn corrupt_cache_files_get_a_recovery_hint() {
        assert!(
            cache_recovery_hint("order: acme error: invalid key pair: InvalidEncoding")
                .unwrap()
                .contains("account-")
        );
        assert!(
            cache_recovery_hint("cached cert parse: expected 2 or more pem, got: 0")
                .unwrap()
                .contains("cert-")
        );
        assert_eq!(cache_recovery_hint("order: acme error: boom"), None);
    }
}
