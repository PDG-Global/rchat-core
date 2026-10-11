use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::warn;

/// Config path used when `--config` is not given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/rchat/server.toml";

/// Default ACME cache directory (account key + certificates).
pub const DEFAULT_ACME_CACHE_DIR: &str = "/var/lib/rchat/acme";

/// Upper bound for `tls_handshake_timeout_secs`; anything longer defeats the
/// point of the timeout.
const MAX_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 120;

/// Unknown keys anywhere in the file are an error (fail closed on typos:
/// a misspelt limit must not silently fall back to its default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_rate_limit_bps")]
    pub rate_limit_bps: u64,

    /// Deprecated and ignored: circuits live while both endpoints are
    /// connected and are removed when either disconnects. Accepted so old
    /// config files still load; a warning is logged when it is set.
    #[serde(default)]
    pub circuit_ttl_secs: Option<u64>,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Maximum simultaneous connections from one source address (IPv4
    /// address or IPv6 /64). 0 disables the per-address cap - required when
    /// running behind a layer-4 front end, where every connection comes from
    /// the front end's address.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    /// Largest WebSocket message (and frame) accepted from a client, in
    /// bytes. Larger messages close the connection.
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,

    /// Aggregate cap on simultaneous connections from one IPv6 /48 (one
    /// /48 holds 65,536 /64s, each of which gets its own per-address cap).
    /// 0 disables it. IPv4 is unaffected.
    #[serde(default = "default_max_connections_per_ipv6_48")]
    pub max_connections_per_ipv6_48: usize,

    /// Seconds a new connection may stay anonymous: it must prove an
    /// identity (an authenticated key-bundle publish; a hello alone does
    /// not count) within this time or it is closed.
    #[serde(default = "default_identification_timeout")]
    pub identification_timeout_secs: u64,

    /// Most pending `CircuitAsk`s (one-sided asks waiting for the other
    /// identity to ask back, 540 s lifetime) in the whole server. When full,
    /// an ask from a lighter source evicts the oldest ask of the heaviest
    /// source (`max_pending_per_source`); otherwise it is refused.
    #[serde(default = "default_max_pending_circuit_targets")]
    pub max_pending_circuit_targets: usize,

    /// Most circuits one connection may hold that it created itself (that
    /// still exist), and most circuits one identity may be a member of,
    /// whichever side asked first and across reconnects. Refused with
    /// RateLimited beyond this.
    #[serde(default = "default_max_circuits_per_connection")]
    pub max_circuits_per_connection: usize,

    /// Most circuit routing entries in the whole server (each circuit pair
    /// uses two). When full, the heaviest source's newest pair is torn down
    /// for a lighter source's; otherwise refused with RateLimited.
    #[serde(default = "default_max_circuits")]
    pub max_circuits: usize,

    /// Most distinct targets one connection may have pending `CircuitAsk`s
    /// for within a 540 s window (the lifetime of an ask). Re-asking the
    /// same target is free.
    #[serde(default = "default_max_pending_per_connection")]
    pub max_pending_per_connection: usize,

    /// Most pending `CircuitAsk`s all connections from one source (an IPv4
    /// address or IPv6 /48) may hold at once. When the relay-wide cap is
    /// reached, an ask from a lighter source evicts the oldest ask of the
    /// heaviest source instead of being refused. Not
    /// enforced when `max_connections_per_ip = 0` (behind a front end every
    /// connection has the front end's address) unless `proxy_protocol`
    /// supplies the client's address.
    #[serde(default = "default_max_pending_per_source")]
    pub max_pending_per_source: usize,

    /// Most circuits (pair sides) the identities that asked from one source
    /// may hold at once, counted at creation and kept across reconnects.
    /// Unset: `max_circuits / CIRCUIT_SOURCE_SHARES` (M-3), so no handful
    /// of addresses can fill the table. Same proxy caveat as
    /// `max_pending_per_source`. See `circuits_per_source()`.
    #[serde(default)]
    pub max_circuits_per_source: Option<usize>,

    /// Behind a layer-4 (TCP passthrough) front end on the same host: when
    /// true, every connection must start with a PROXY protocol v2 header,
    /// read before TLS, and its source address is used for the per-source
    /// fair shares only (pending asks, circuits, knocks, the asker-quota
    /// table, shedding). Connection caps and logging are unaffected.
    /// Connections whose TCP peer is not a loopback address are refused,
    /// as are connections without a valid header. Requires a loopback
    /// `bind_addr` and both per-address caps at 0. The front end must send
    /// PROXY v2 (HAProxy `send-proxy-v2`, caddy-l4 `proxy_protocol v2`).
    /// Any local process can send a header naming any source: fairness
    /// only, never authentication, logging or caps.
    #[serde(default)]
    pub proxy_protocol: bool,

    /// Removed: the relay no longer trusts `X-Forwarded-For` (a TLS-
    /// terminating proxy cannot work with protocol v2, and a TCP
    /// passthrough cannot set the header). Present only so validate() can
    /// refuse it and point to `proxy_protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_proxy: Option<toml::Value>,

    /// Total bytes the offline message store may hold across all recipients.
    #[serde(default = "default_offline_queue_max_total_bytes")]
    pub offline_queue_max_total_bytes: usize,

    /// Bytes the offline message store may hold for a single recipient.
    #[serde(default = "default_offline_queue_max_bytes_per_recipient")]
    pub offline_queue_max_bytes_per_recipient: usize,

    /// Relay-wide cap on bytes queued for sending across all connections.
    /// When spent, the heaviest source's heaviest connection is shed. Size
    /// it, with `buffer_budget_bytes` and the offline queue, to the host's RAM.
    #[serde(default = "default_outbound_budget_bytes")]
    pub outbound_budget_bytes: usize,

    /// Relay-wide cap on WebSocket read/write buffer bytes (largest message
    /// per connection so far). When spent, the heaviest holder is shed.
    #[serde(default = "default_buffer_budget_bytes")]
    pub buffer_budget_bytes: usize,

    /// Request path on which WebSocket upgrades are accepted. Every other
    /// request (including upgrades to other paths) gets the decoy site.
    #[serde(default = "default_websocket_path")]
    pub websocket_path: String,

    /// Static certificate (`[server.tls]`). Mutually exclusive with `acme`.
    pub tls: Option<TlsConfig>,

    /// Built-in Let's Encrypt (`[server.acme]`). Mutually exclusive with `tls`.
    #[serde(default)]
    pub acme: AcmeConfig,

    /// Seconds a client gets to complete the TLS handshake before the
    /// connection is dropped. Stops slow-handshake connections pinning tasks.
    #[serde(default = "default_tls_handshake_timeout")]
    pub tls_handshake_timeout_secs: u64,

    /// Set only by the `--no-tls` CLI flag; never read from the config file.
    #[serde(skip)]
    pub insecure_no_tls: bool,

    /// Set only by `--insecure-public-plaintext`: permits `--no-tls` on a
    /// non-loopback bind address.
    #[serde(skip)]
    pub insecure_public_plaintext: bool,

    /// Removed: never used (the relay keeps no shared state outside the
    /// process). Present only so validate() can refuse it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis_url: Option<toml::Value>,

    /// Removed (pre-v2 plaintext queue file). Present only so validate() can refuse it.
    #[serde(default)]
    pub message_queue_persist_path: Option<String>,

    #[serde(default)]
    pub offline_queue: OfflineQueueConfig,

    /// `--no-tls` only: this relay's origin as clients dial it, e.g.
    /// "ws://127.0.0.1:18443". Without TLS there is no channel binding;
    /// connection proofs are bound to a hash of this origin instead, which
    /// only stops replay to a relay with a different origin.
    #[serde(default)]
    pub dev_origin: Option<String>,

    /// The relay identity key file (32-byte Ed25519 seed, mode 0600).
    /// Default: `relay_identity.key` next to the config file.
    #[serde(default)]
    pub relay_identity_path: Option<String>,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub decoy: DecoyConfig,
}

/// Static certificate. TLS 1.3 is mandatory and not configurable, so there
/// are deliberately no version keys here; unknown keys are rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Built-in ACME (Let's Encrypt) via TLS-ALPN-01 on the main listener.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Fully qualified host names to put on the certificate. No wildcards
    /// (TLS-ALPN-01 cannot validate them).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Contact addresses for the ACME account, `mailto:` optional.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Absolute path; holds the account key and certificate private keys.
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: PathBuf,
    /// Use the Let's Encrypt staging directory (untrusted certs, generous
    /// rate limits). Turn on for first-time setup.
    #[serde(default)]
    pub staging: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            contacts: Vec::new(),
            cache_dir: default_acme_cache_dir(),
            staging: false,
        }
    }
}

impl AcmeConfig {
    /// Validate the ACME settings. Called only when `enabled = true`.
    pub fn validate(&self) -> Result<()> {
        if self.domains.is_empty() {
            bail!("[server.acme] is enabled but `domains` is empty; list at least one host name");
        }
        for domain in &self.domains {
            validate_acme_domain(domain)?;
        }
        if !self.cache_dir.is_absolute() {
            bail!(
                "[server.acme] cache_dir {:?} must be an absolute path (a relative path depends \
                 on the working directory and can silently lose the account key)",
                self.cache_dir
            );
        }
        self.normalized_contacts()?;
        Ok(())
    }

    /// Contacts in ACME form (`mailto:user@host`). Bare addresses get the
    /// `mailto:` prefix; any other scheme is rejected.
    pub fn normalized_contacts(&self) -> Result<Vec<String>> {
        self.contacts
            .iter()
            .map(|c| {
                let c = c.trim();
                let addr = c.strip_prefix("mailto:").unwrap_or(c);
                if addr.contains(':') || !addr.contains('@') || addr.contains(char::is_whitespace) {
                    bail!("[server.acme] contact {c:?} is not an email address");
                }
                Ok(format!("mailto:{addr}"))
            })
            .collect()
    }
}

fn validate_acme_domain(domain: &str) -> Result<()> {
    let why = if domain.contains('*') {
        Some("wildcards cannot be issued with TLS-ALPN-01")
    } else if domain.parse::<std::net::IpAddr>().is_ok() {
        Some("IP addresses are not supported; use a DNS name")
    } else if domain.len() > 253 || !domain.contains('.') {
        Some("expected a fully qualified host name such as chat.example.com")
    } else if !domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        Some("use lowercase letters, digits and hyphens only (no scheme, port or path)")
    } else {
        None
    };
    match why {
        Some(why) => bail!("[server.acme] domain {domain:?} is invalid: {why}"),
        None => Ok(()),
    }
}

/// How the listener terminates (or does not terminate) TLS.
#[derive(Debug, Clone, PartialEq)]
pub enum TlsMode {
    /// Static certificate and key from disk.
    Static {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Certificates issued and renewed by the built-in ACME client.
    Acme(AcmeConfig),
    /// Plaintext WebSocket. Only reachable through `--no-tls`.
    Plaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Absolute path of a static site served to non-WebSocket requests.
    #[serde(default)]
    pub root: Option<PathBuf>,
    /// Value of the `Server` response header.
    #[serde(default = "default_decoy_server")]
    pub server_header: String,
    /// Timeout for writing a whole decoy response, in seconds.
    #[serde(default = "default_decoy_write_timeout")]
    pub write_timeout_secs: u64,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            root: None,
            server_header: default_decoy_server(),
            write_timeout_secs: default_decoy_write_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    /// Include client IP addresses in `debug` log lines (for abuse handling).
    /// Default false: the relay does not record who connected. Never affects
    /// `info`/`warn`/`error`, which carry no addresses either way.
    #[serde(default)]
    pub log_client_ips: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_addr")]
    pub bind_addr: SocketAddr,
    /// Permit a non-loopback `bind_addr`. The endpoint is unauthenticated
    /// and its aggregate counters can help correlate traffic on a quiet
    /// relay, so exposing it must be an explicit choice (R-15).
    #[serde(default)]
    pub allow_public: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: default_metrics_addr(),
            allow_public: false,
        }
    }
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_max_connections() -> usize {
    10_000
}

fn default_max_connections_per_ip() -> usize {
    64
}

fn default_max_connections_per_ipv6_48() -> usize {
    256
}

fn default_identification_timeout() -> u64 {
    15
}

fn default_max_pending_circuit_targets() -> usize {
    10_000
}

fn default_max_circuits_per_connection() -> usize {
    256
}

fn default_max_circuits() -> usize {
    200_000
}

fn default_max_pending_per_connection() -> usize {
    32
}

fn default_max_pending_per_source() -> usize {
    1_024
}

/// With `max_circuits_per_source` unset, one source may hold
/// `max_circuits / CIRCUIT_SOURCE_SHARES` circuit sides (M-3): at the
/// default 200,000 that is 3,125, so it takes at least 64 sources to fill
/// the table - and even then a lighter source's new pair evicts the
/// heaviest source's newest one instead of being refused.
pub const CIRCUIT_SOURCE_SHARES: usize = 64;

fn default_max_message_bytes() -> usize {
    4 << 20 // 4 MiB
}

fn default_offline_queue_max_total_bytes() -> usize {
    256 << 20 // 256 MiB
}

fn default_offline_queue_max_bytes_per_recipient() -> usize {
    16 << 20 // 16 MiB
}

fn default_outbound_budget_bytes() -> usize {
    crate::limits::GLOBAL_OUTBOUND_MAX_BYTES
}

fn default_buffer_budget_bytes() -> usize {
    crate::limits::GLOBAL_BUFFER_MAX_BYTES
}

/// Upper bound for the relay-wide memory budgets (a typo guard).
const MAX_RELAY_BUDGET_BYTES: usize = 64 << 30;

fn default_rate_limit_bps() -> u64 {
    1_048_576
}

fn default_connection_timeout() -> u64 {
    300
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_output() -> String {
    "stdout".to_string()
}

fn default_true() -> bool {
    true
}

fn default_websocket_path() -> String {
    "/".to_string()
}

fn default_decoy_write_timeout() -> u64 {
    30
}

fn default_decoy_server() -> String {
    "nginx/1.24.0".to_string()
}

fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9090".parse().unwrap()
}

/// 127.0.0.0/8, ::1, and IPv4-mapped loopback.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn default_acme_cache_dir() -> PathBuf {
    PathBuf::from(DEFAULT_ACME_CACHE_DIR)
}

fn default_tls_handshake_timeout() -> u64 {
    10
}

/// Longest knock lifetime: the clients' verification window (spec §5.3, L2).
pub const MAX_KNOCK_TTL_SECS: u64 = 259_200;

/// `[server.offline_queue]`: retention and (opt-in, encrypted) persistence
/// of queued items (spec §5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineQueueConfig {
    /// Message lifetime in seconds; accepted range 3600..=604800. Default 72 h.
    #[serde(default = "default_queue_ttl_secs")]
    pub ttl_secs: u64,
    /// Global knock budget in bytes (separate from the message budget).
    #[serde(default = "default_knock_budget_bytes")]
    pub knock_budget_bytes: usize,
    /// Keep queued items across restarts, encrypted (RCQ2). Default off.
    #[serde(default)]
    pub persist: bool,
    #[serde(default)]
    pub persist_path: Option<PathBuf>,
    /// 32 raw bytes on tmpfs/ramfs/mfs, owned by the service user, mode ≤ 0600.
    #[serde(default)]
    pub persist_key_path: Option<PathBuf>,
    /// Skip the memory-filesystem check (dev/exception; website sentence 8
    /// must then not be used for this relay).
    #[serde(default)]
    pub allow_persistent_key: bool,
}

fn default_queue_ttl_secs() -> u64 {
    259_200
}

fn default_knock_budget_bytes() -> usize {
    16 << 20
}

impl Default for OfflineQueueConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_queue_ttl_secs(),
            knock_budget_bytes: default_knock_budget_bytes(),
            persist: false,
            persist_path: None,
            persist_key_path: None,
            allow_persistent_key: false,
        }
    }
}

impl ServerConfig {
    /// Resolve which config file to read for the given CLI flags: the
    /// `--config` path, else the default path. A missing or unreadable file
    /// is always an error, `--no-tls` included: plaintext mode needs a file
    /// anyway, for its `dev_origin`.
    pub fn load_for_cli(explicit_path: Option<&str>, no_tls: bool) -> Result<Self> {
        Self::load_for_cli_with_default(explicit_path, no_tls, DEFAULT_CONFIG_PATH)
    }

    fn load_for_cli_with_default(
        explicit_path: Option<&str>,
        no_tls: bool,
        default_path: &str,
    ) -> Result<Self> {
        let path = explicit_path.unwrap_or(default_path);
        let loaded = Self::load(path);
        if no_tls && explicit_path.is_none() {
            return loaded.context(
                "--no-tls needs a config file with [server] dev_origin \
                 (e.g. \"ws://127.0.0.1:18443\"); pass it with --config",
            );
        }
        loaded
    }

    /// Load a config file. A missing, unreadable or invalid file is an error;
    /// the server never silently falls back to defaults.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {path:?}"))?;
        Self::from_toml_str(&content).with_context(|| format!("invalid config file {path:?}"))
    }

    /// Parse config from TOML text (accepts the `[server]` wrapper).
    pub fn from_toml_str(content: &str) -> Result<Self> {
        let mut value: toml::Value = toml::from_str(content)?;

        // Support legacy/docs format that wraps server fields in [server].
        // Flatten them to the root level so serde can deserialize into ServerConfig.
        if let Some(server_table) = value.get("server").cloned() {
            if let Some(table) = value.as_table_mut() {
                table.remove("server");
                if let Some(server_map) = server_table.as_table() {
                    for (k, v) in server_map {
                        table.insert(k.clone(), v.clone());
                    }
                }
            }
        }

        // These keys used to appear in the template but were never read.
        // Refuse them with an explanation rather than a bare serde error.
        if let Some(tls) = value.get("tls").and_then(|t| t.as_table()) {
            for key in ["min_version", "tls13_only"] {
                if tls.contains_key(key) {
                    bail!(
                        "[server.tls] `{key}` is not a setting: TLS 1.3 is mandatory and cannot \
                         be changed. Remove `{key}` from the config file."
                    );
                }
            }
        }

        let config: ServerConfig = value.try_into()?;
        Ok(config)
    }

    /// Knock lifetime: the queue TTL, capped at 72 h (announced to clients
    /// as `knock_ttl_hours`).
    pub fn knock_ttl_secs(&self) -> u64 {
        self.offline_queue.ttl_secs.min(MAX_KNOCK_TTL_SECS)
    }

    pub fn with_cli_overrides(mut self, cli: &crate::Cli) -> Self {
        if let Some(bind) = cli.bind {
            self.bind_addr = bind;
        }
        if cli.no_tls {
            self.disable_tls_for_dev(cli.insecure_public_plaintext);
        }
        self
    }

    /// Apply `--no-tls`: plaintext, explicitly requested. A non-loopback bind
    /// is additionally refused by `tls_mode` unless `allow_public_plaintext`
    /// (`--insecure-public-plaintext`) is set.
    pub fn disable_tls_for_dev(&mut self, allow_public_plaintext: bool) {
        self.insecure_public_plaintext = allow_public_plaintext;
        if self.tls.is_some() || self.acme.enabled {
            warn!("--no-tls given: ignoring [server.tls] / [server.acme] from the config file");
        }
        self.tls = None;
        self.acme.enabled = false;
        self.insecure_no_tls = true;
    }

    /// Decide the TLS mode, refusing ambiguous or unsafe configurations.
    pub fn tls_mode(&self) -> Result<TlsMode> {
        if self.tls_handshake_timeout_secs == 0
            || self.tls_handshake_timeout_secs > MAX_TLS_HANDSHAKE_TIMEOUT_SECS
        {
            bail!(
                "tls_handshake_timeout_secs must be between 1 and {MAX_TLS_HANDSHAKE_TIMEOUT_SECS}"
            );
        }
        if self.insecure_no_tls {
            if !is_loopback(&self.bind_addr) && !self.insecure_public_plaintext {
                bail!(
                    "--no-tls with non-loopback bind address {}: refusing to serve plaintext \
                     (including circuit tokens) on the network. --no-tls is for local \
                     development only: bind 127.0.0.1 / ::1, configure TLS, or, if you really \
                     mean it, add --insecure-public-plaintext.",
                    self.bind_addr
                );
            }
            return Ok(TlsMode::Plaintext);
        }
        match (&self.tls, self.acme.enabled) {
            (Some(_), true) => bail!(
                "both [server.tls] (static certificate) and [server.acme] (automatic \
                 certificates) are configured. Keep exactly one; the server will not guess \
                 which certificate to serve."
            ),
            (None, true) => {
                self.acme.validate()?;
                Ok(TlsMode::Acme(self.acme.clone()))
            }
            (Some(tls), false) => Ok(TlsMode::Static {
                cert_path: tls.cert_path.clone(),
                key_path: tls.key_path.clone(),
            }),
            (None, false) => bail!(
                "no TLS configured. Add [server.acme] (automatic Let's Encrypt certificates) or \
                 [server.tls] (static certificate) to the config file. To run without TLS for \
                 local development, pass --no-tls explicitly."
            ),
        }
    }

    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_handshake_timeout_secs)
    }

    /// Non-fatal configuration notices to log at startup.
    pub fn startup_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.circuit_ttl_secs.is_some() {
            out.push(
                "circuit_ttl_secs is ignored: circuits live while both endpoints are connected \
                 and are removed when either disconnects; remove it from the config file"
                    .to_string(),
            );
        }
        out
    }

    pub fn identification_timeout(&self) -> Duration {
        Duration::from_secs(self.identification_timeout_secs)
    }

    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    /// Circuit sides one source may hold: `max_circuits_per_source`, or
    /// `max_circuits / CIRCUIT_SOURCE_SHARES` (at least 2) when unset.
    pub fn circuits_per_source(&self) -> usize {
        self.max_circuits_per_source
            .unwrap_or((self.max_circuits / CIRCUIT_SOURCE_SHARES).max(2))
    }

    /// Token-bucket burst size for inbound traffic: one maximal message must
    /// always be admissible, and at least one second's worth of traffic.
    pub fn rate_limit_burst_bytes(&self) -> u64 {
        self.rate_limit_bps.max(self.max_message_bytes as u64)
    }

    /// The `--no-tls` stand-in for a channel binding:
    /// BLAKE3("rchat/conn-binding/no-tls/v1\0" || normalised dev_origin).
    /// `None` in TLS mode, where the TLS exporter is used.
    pub fn dev_binding(&self) -> Result<Option<[u8; 32]>> {
        if !self.insecure_no_tls {
            return Ok(None);
        }
        let origin = self
            .dev_origin
            .as_deref()
            .context("--no-tls requires [server] dev_origin")?;
        let normalised = rchat_core::keyauth::relay_origin(origin)
            .map_err(|_| anyhow::anyhow!("dev_origin must look like \"ws://127.0.0.1:18443\""))?;
        let binding = rchat_core::keyauth::dev_origin_binding(&normalised)
            .map_err(|_| anyhow::anyhow!("dev_origin is empty"))?;
        Ok(Some(binding))
    }

    /// Reject resource-limit settings that are missing, nonsensical or would
    /// silently disable a limit. Fail closed: the server refuses to start.
    pub fn validate(&self) -> Result<()> {
        use anyhow::bail;
        if let Some(origin) = &self.dev_origin {
            if rchat_core::keyauth::relay_origin(origin).is_err() {
                bail!("dev_origin must look like \"ws://127.0.0.1:18443\"");
            }
        }
        if self.insecure_no_tls && self.dev_origin.is_none() {
            bail!(
                "--no-tls requires [server] dev_origin (e.g. \"ws://127.0.0.1:18443\"): \
                 connection proofs are bound to it in plaintext mode"
            );
        }
        if self.max_connections == 0 {
            bail!("max_connections must be at least 1");
        }
        if self.max_connections_per_ip > self.max_connections {
            bail!(
                "max_connections_per_ip ({}) must not exceed max_connections ({}); use 0 to disable the per-address cap",
                self.max_connections_per_ip,
                self.max_connections
            );
        }
        if self.websocket_path.contains(WEBSOCKET_PATH_PLACEHOLDER) {
            bail!(
                "websocket_path still contains the template placeholder {:?}: set it to a long \
                 random path (e.g. \"/\" + `openssl rand -base64 24 | tr '+/' '-_'`) and put the \
                 same path in clients' server URL",
                WEBSOCKET_PATH_PLACEHOLDER
            );
        }
        if self.max_connections_per_ipv6_48 > self.max_connections {
            bail!(
                "max_connections_per_ipv6_48 ({}) must not exceed max_connections ({}); use 0 to disable the /48 cap",
                self.max_connections_per_ipv6_48,
                self.max_connections
            );
        }
        if !(1..=MAX_PENDING_CIRCUIT_TARGETS).contains(&self.max_pending_circuit_targets) {
            bail!(
                "max_pending_circuit_targets must be between 1 and {} (got {})",
                MAX_PENDING_CIRCUIT_TARGETS,
                self.max_pending_circuit_targets
            );
        }
        if !(1..=MAX_CIRCUITS_PER_CONNECTION).contains(&self.max_circuits_per_connection) {
            bail!(
                "max_circuits_per_connection must be between 1 and {} (got {})",
                MAX_CIRCUITS_PER_CONNECTION,
                self.max_circuits_per_connection
            );
        }
        if !(2..=MAX_CIRCUITS).contains(&self.max_circuits) {
            bail!(
                "max_circuits must be between 2 and {} (got {})",
                MAX_CIRCUITS,
                self.max_circuits
            );
        }
        if self.max_pending_per_connection == 0
            || self.max_pending_per_connection > self.max_pending_circuit_targets
        {
            bail!(
                "max_pending_per_connection must be between 1 and max_pending_circuit_targets (got {})",
                self.max_pending_per_connection
            );
        }
        if self.max_pending_per_source == 0
            || self.max_pending_per_source > self.max_pending_circuit_targets
        {
            bail!(
                "max_pending_per_source must be between 1 and max_pending_circuit_targets (got {})",
                self.max_pending_per_source
            );
        }
        if let Some(n) = self.max_circuits_per_source {
            if n < 2 || n > self.max_circuits {
                bail!(
                    "max_circuits_per_source must be between 2 and max_circuits (got {})",
                    n
                );
            }
        }
        if !(1..=MAX_IDENTIFICATION_TIMEOUT_SECS).contains(&self.identification_timeout_secs)
            || self.identification_timeout_secs > self.connection_timeout_secs
        {
            bail!(
                "identification_timeout_secs must be between 1 and {} and not exceed connection_timeout_secs (got {})",
                MAX_IDENTIFICATION_TIMEOUT_SECS,
                self.identification_timeout_secs
            );
        }
        if self.rate_limit_bps < MIN_RATE_LIMIT_BPS {
            bail!(
                "rate_limit_bps must be at least {} bytes/second (got {}); there is no 'unlimited' setting",
                MIN_RATE_LIMIT_BPS,
                self.rate_limit_bps
            );
        }
        if !(MIN_MESSAGE_BYTES..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes) {
            bail!(
                "max_message_bytes must be between {} and {} (got {})",
                MIN_MESSAGE_BYTES,
                MAX_MESSAGE_BYTES,
                self.max_message_bytes
            );
        }
        if !(MIN_CONNECTION_TIMEOUT_SECS..=MAX_CONNECTION_TIMEOUT_SECS)
            .contains(&self.connection_timeout_secs)
        {
            bail!(
                "connection_timeout_secs must be between {} and {} (clients send keepalives every 30 s; got {})",
                MIN_CONNECTION_TIMEOUT_SECS,
                MAX_CONNECTION_TIMEOUT_SECS,
                self.connection_timeout_secs
            );
        }
        if self.offline_queue_max_bytes_per_recipient < self.max_message_bytes {
            bail!(
                "offline_queue_max_bytes_per_recipient ({}) must be at least max_message_bytes ({})",
                self.offline_queue_max_bytes_per_recipient,
                self.max_message_bytes
            );
        }
        if self.offline_queue_max_total_bytes < self.offline_queue_max_bytes_per_recipient {
            bail!(
                "offline_queue_max_total_bytes ({}) must be at least offline_queue_max_bytes_per_recipient ({})",
                self.offline_queue_max_total_bytes,
                self.offline_queue_max_bytes_per_recipient
            );
        }
        if self.outbound_budget_bytes < crate::limits::OUTBOUND_QUEUE_MAX_BYTES
            || self.outbound_budget_bytes > MAX_RELAY_BUDGET_BYTES
        {
            bail!(
                "outbound_budget_bytes ({}) must be between {} (one connection's send queue) and {}",
                self.outbound_budget_bytes,
                crate::limits::OUTBOUND_QUEUE_MAX_BYTES,
                MAX_RELAY_BUDGET_BYTES
            );
        }
        if self.buffer_budget_bytes < self.max_message_bytes
            || self.buffer_budget_bytes > MAX_RELAY_BUDGET_BYTES
        {
            bail!(
                "buffer_budget_bytes ({}) must be between max_message_bytes ({}) and {}",
                self.buffer_budget_bytes,
                self.max_message_bytes,
                MAX_RELAY_BUDGET_BYTES
            );
        }
        if self.metrics.enabled
            && !is_loopback(&self.metrics.bind_addr)
            && !self.metrics.allow_public
        {
            bail!(
                "metrics.bind_addr {} is not a loopback address: the metrics endpoint is \
                 unauthenticated; bind it to 127.0.0.1, or set metrics.allow_public = true \
                 and restrict access with a firewall",
                self.metrics.bind_addr
            );
        }
        if self.message_queue_persist_path.is_some() {
            bail!(
                "message_queue_persist_path was removed; queued messages are memory-only by \
                 default — see [server.offline_queue]"
            );
        }
        if self.redis_url.is_some() {
            bail!(
                "redis_url was removed: the relay never used Redis and keeps all state in \
                 its own process. Delete the redis_url line from the config"
            );
        }
        if self.trusted_proxy.is_some() {
            bail!(
                "trusted_proxy was removed: the relay no longer reads X-Forwarded-For (a \
                 TLS-terminating proxy cannot carry protocol v2, and a TCP passthrough cannot \
                 set the header). Behind a layer-4 front end on this host, set \
                 proxy_protocol = true and have the front end send PROXY protocol v2 — see \
                 config/server-behind-proxy.toml"
            );
        }
        if self.proxy_protocol
            && (self.max_connections_per_ip > 0 || self.max_connections_per_ipv6_48 > 0)
        {
            bail!(
                "proxy_protocol = true needs max_connections_per_ip = 0 and \
                 max_connections_per_ipv6_48 = 0 (got {} and {}): every connection arrives \
                 from the front end's loopback address (127.0.0.1 or ::1), so either \
                 per-address cap would cap the whole relay. Enforce per-client connection \
                 caps in the front end (see config/server-behind-proxy.toml).",
                self.max_connections_per_ip,
                self.max_connections_per_ipv6_48
            );
        }
        if self.proxy_protocol && !is_loopback(&self.bind_addr) {
            bail!(
                "proxy_protocol = true with bind_addr {}: only a loopback bind is allowed \
                 (connections from any other peer are refused, so a wildcard or public bind \
                 would only expose the port). Bind 127.0.0.1 or ::1 and point the front end \
                 at it.",
                self.bind_addr
            );
        }
        if !(3_600..=604_800).contains(&self.offline_queue.ttl_secs) {
            bail!(
                "offline_queue.ttl_secs must be between 3600 and 604800 (got {})",
                self.offline_queue.ttl_secs
            );
        }
        if self.offline_queue.knock_budget_bytes < crate::validate::KNOCK_BYTES {
            bail!(
                "offline_queue.knock_budget_bytes must be at least {} (one knock)",
                crate::validate::KNOCK_BYTES
            );
        }
        if self.offline_queue.persist
            && (self.offline_queue.persist_path.is_none()
                || self.offline_queue.persist_key_path.is_none())
        {
            bail!("offline_queue.persist = true requires persist_path and persist_key_path");
        }
        Ok(())
    }
}

/// Lowest accepted `rate_limit_bps`.
const MIN_RATE_LIMIT_BPS: u64 = 1024;
/// Accepted range for `max_message_bytes`.
const MIN_MESSAGE_BYTES: usize = 64 << 10;
const MAX_MESSAGE_BYTES: usize = 64 << 20;
/// Lowest accepted `connection_timeout_secs`.
const MIN_CONNECTION_TIMEOUT_SECS: u64 = 60;
/// Highest accepted `connection_timeout_secs` (one day): larger values
/// overflow `Duration` arithmetic at startup (R-7).
const MAX_CONNECTION_TIMEOUT_SECS: u64 = 86_400;
/// Upper bounds for the anti-abuse settings.
const MAX_PENDING_CIRCUIT_TARGETS: usize = 1_000_000;
const MAX_IDENTIFICATION_TIMEOUT_SECS: u64 = 300;
const MAX_CIRCUITS_PER_CONNECTION: usize = 65_536;
const MAX_CIRCUITS: usize = 10_000_000;
/// Marker in the shipped template's `websocket_path`; the server refuses to
/// start until it is replaced.
pub const WEBSOCKET_PATH_PLACEHOLDER: &str = "CHANGE-ME";

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            max_connections: default_max_connections(),
            rate_limit_bps: default_rate_limit_bps(),
            circuit_ttl_secs: None,
            connection_timeout_secs: default_connection_timeout(),
            max_connections_per_ip: default_max_connections_per_ip(),
            max_connections_per_ipv6_48: default_max_connections_per_ipv6_48(),
            identification_timeout_secs: default_identification_timeout(),
            max_pending_circuit_targets: default_max_pending_circuit_targets(),
            max_circuits_per_connection: default_max_circuits_per_connection(),
            max_circuits: default_max_circuits(),
            max_pending_per_connection: default_max_pending_per_connection(),
            max_pending_per_source: default_max_pending_per_source(),
            max_circuits_per_source: None,
            proxy_protocol: false,
            trusted_proxy: None,
            max_message_bytes: default_max_message_bytes(),
            offline_queue_max_total_bytes: default_offline_queue_max_total_bytes(),
            offline_queue_max_bytes_per_recipient: default_offline_queue_max_bytes_per_recipient(),
            outbound_budget_bytes: default_outbound_budget_bytes(),
            buffer_budget_bytes: default_buffer_budget_bytes(),
            websocket_path: default_websocket_path(),
            tls: None,
            acme: AcmeConfig::default(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout(),
            insecure_no_tls: false,
            insecure_public_plaintext: false,
            redis_url: None,
            message_queue_persist_path: None,
            offline_queue: OfflineQueueConfig::default(),
            dev_origin: None,
            relay_identity_path: None,
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            decoy: DecoyConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_text(r: Result<impl std::fmt::Debug>) -> String {
        format!("{:#}", r.expect_err("expected an error"))
    }

    const ACME_OK: &str = r#"
        [server]
        bind_addr = "0.0.0.0:443"
        [server.acme]
        enabled = true
        domains = ["chat.example.com"]
        contacts = ["ops@example.com"]
        cache_dir = "/var/lib/rchat/acme"
    "#;

    #[test]
    fn offline_queue_section_parses_under_server() {
        let c = ServerConfig::from_toml_str(
            r#"
            [server]
            bind_addr = "127.0.0.1:1"
            [server.offline_queue]
            ttl_secs = 7200
            knock_budget_bytes = 4096
            "#,
        )
        .unwrap();
        assert_eq!(c.offline_queue.ttl_secs, 7200);
        assert_eq!(c.offline_queue.knock_budget_bytes, 4096);
        assert!(!c.offline_queue.persist);
        assert_eq!(c.knock_ttl_secs(), 7200);
        c.validate().unwrap();
    }

    #[test]
    fn offline_queue_defaults_are_memory_only_72_hours() {
        let c = ServerConfig::default();
        assert_eq!(c.offline_queue.ttl_secs, 259_200);
        assert_eq!(c.offline_queue.knock_budget_bytes, 16 << 20);
        assert!(!c.offline_queue.persist);
        assert!(!c.offline_queue.allow_persistent_key);
        let mut long = ServerConfig::default();
        long.offline_queue.ttl_secs = 604_800;
        assert_eq!(long.knock_ttl_secs(), MAX_KNOCK_TTL_SECS);
    }

    #[test]
    fn p2_legacy_message_queue_persist_path_is_a_startup_error() {
        let c =
            ServerConfig::from_toml_str("[server]\nmessage_queue_persist_path = \"/tmp/q.json\"\n")
                .unwrap();
        assert!(err_text(c.validate()).contains("message_queue_persist_path was removed"));
    }

    #[test]
    fn offline_queue_ttl_outside_range_is_rejected() {
        for ttl in [3_599u64, 604_801] {
            let mut c = ServerConfig::default();
            c.offline_queue.ttl_secs = ttl;
            assert!(err_text(c.validate()).contains("offline_queue.ttl_secs"));
        }
    }

    #[test]
    fn connection_timeout_is_bounded_above() {
        // R-7: u64::MAX passed validate() and then overflowed `Duration`
        // arithmetic when the cleanup task started.
        for secs in [u64::MAX, MAX_CONNECTION_TIMEOUT_SECS + 1] {
            let c = ServerConfig {
                connection_timeout_secs: secs,
                ..ServerConfig::default()
            };
            assert!(err_text(c.validate()).contains("connection_timeout_secs"));
        }
        let c = ServerConfig {
            connection_timeout_secs: MAX_CONNECTION_TIMEOUT_SECS,
            ..ServerConfig::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn persist_without_paths_is_rejected() {
        let mut c = ServerConfig::default();
        c.offline_queue.persist = true;
        assert!(err_text(c.validate()).contains("persist_path and persist_key_path"));
    }

    #[test]
    fn unknown_offline_queue_key_is_rejected() {
        let r = ServerConfig::from_toml_str("[server.offline_queue]\nttl = 5\n");
        assert!(r.is_err());
    }

    #[test]
    fn template_offline_queue_block_parses() {
        let c = ServerConfig::from_toml_str(include_str!("../config/server.toml")).unwrap();
        assert_eq!(c.offline_queue.ttl_secs, 259_200);
        assert!(!c.offline_queue.persist);
    }

    /// R-14 / S-13: both systemd units can write where the template puts the
    /// persisted queue and its key, forbid core dumps, cap memory and tasks,
    /// and share the sandbox (the Caddy layout parses the same frames).
    #[test]
    fn systemd_units_match_the_template_paths_and_are_sandboxed() {
        let root = env!("CARGO_MANIFEST_DIR");
        if !std::path::Path::new(&format!("{root}/scripts/rchat-server.service")).exists() {
            // Skip only in the public tree (no ios/ either); in the private
            // tree a renamed file must fail the test.
            assert!(
                !std::path::Path::new(&format!("{root}/ios")).exists(),
                "scripts/rchat-server.service is missing from the private tree"
            );
            eprintln!("skipped: scripts/*.service not present (public tree)");
            return;
        }
        let template = std::fs::read_to_string(format!("{root}/config/server.toml")).unwrap();
        let template_path = |key: &str| -> String {
            template
                .lines()
                .map(|l| l.trim_start_matches('#').trim())
                .find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
                })
                .unwrap_or_else(|| panic!("template documents {key}"))
        };
        let data = template_path("persist_path");
        let key = template_path("persist_key_path");
        for unit in ["rchat-server-direct.service", "rchat-server.service"] {
            let text = std::fs::read_to_string(format!("{root}/scripts/{unit}")).unwrap();
            let values = |name: &str| -> Vec<String> {
                text.lines()
                    .filter_map(|l| l.strip_prefix(&format!("{name}=")))
                    .flat_map(|v| v.split_whitespace().map(str::to_string))
                    .collect()
            };
            let mut writable = values("ReadWritePaths");
            writable.extend(
                values("RuntimeDirectory")
                    .iter()
                    .map(|d| format!("/run/{d}")),
            );
            writable.extend(
                values("StateDirectory")
                    .iter()
                    .map(|d| format!("/var/lib/{d}")),
            );
            for path in [&data, &key] {
                assert!(
                    writable.iter().any(|w| path.starts_with(&format!("{w}/"))),
                    "{unit}: {path} is not writable under ProtectSystem=strict ({writable:?})"
                );
            }
            assert!(key.starts_with("/run/"), "the queue key belongs on a tmpfs");
            // L-2: the runtime directory holding the key survives restarts,
            // and the unit creates the key the template points at.
            assert_eq!(values("RuntimeDirectoryPreserve"), vec!["yes"], "{unit}");
            let pre = text
                .lines()
                .find_map(|l| l.strip_prefix("ExecStartPre="))
                .unwrap_or_else(|| panic!("{unit}: no ExecStartPre creates the queue key"));
            assert!(
                pre.contains(&format!("k={key};"))
                    && pre.contains("bs=32 count=1")
                    && !pre.replace("$$", "").contains('$'),
                "{unit}: ExecStartPre must create {key} (shell `$` escaped as `$$`): {pre}"
            );
            for required in [
                "LimitCORE=0",
                "MemoryMax=",
                "TasksMax=",
                "ProtectProc=invisible",
                "ProcSubset=pid",
                "RemoveIPC=true",
                "ProtectSystem=strict",
                "NoNewPrivileges=true",
                "UMask=0077",
                "PrivateTmp=true",
                "PrivateDevices=true",
                "RestrictAddressFamilies=",
                "SystemCallFilter=@system-service",
                "MemoryDenyWriteExecute=true",
                // M-5: OOM kills under attack never leave the unit failed.
                "StartLimitIntervalSec=0",
                "Restart=on-failure",
                // ... with backoff, so a startup failure does not spin.
                "RestartSec=",
                "RestartSteps=",
                "RestartMaxDelaySec=",
            ] {
                assert!(
                    text.lines().any(|l| l.starts_with(required)),
                    "{unit} lacks {required}"
                );
            }
            assert!(
                !text.contains("StartLimitBurst"),
                "{unit}: a start-rate limit would leave the relay down"
            );
            // The backoff comment matches RestartMaxDelaySec.
            assert_eq!(values("RestartMaxDelaySec"), vec!["60"], "{unit}");
            assert!(!text.contains("5 min"), "{unit}: stale backoff comment");
            // Protocol v2: the relay always terminates TLS itself.
            let exec = text
                .split("ExecStart=")
                .nth(1)
                .and_then(|rest| rest.split("\n#").next())
                .unwrap_or_else(|| panic!("{unit}: no ExecStart"));
            assert!(!exec.contains("--no-tls"), "{unit}: {exec}");
            assert!(!text.contains("8080"), "{unit}");
        }
        // The layer-4 unit: loopback 8443 behind a PROXY v2 front end, no
        // capability needed; matches config/server-behind-proxy.toml.
        let l4 = std::fs::read_to_string(format!("{root}/scripts/rchat-server.service")).unwrap();
        assert!(l4.contains("--bind 127.0.0.1:8443"));
        assert!(l4.lines().any(|l| l == "CapabilityBoundingSet="));
        let behind =
            ServerConfig::load(&format!("{root}/config/server-behind-proxy.toml")).unwrap();
        assert_eq!(behind.bind_addr, "127.0.0.1:8443".parse().unwrap());
    }

    #[test]
    fn missing_config_file_is_an_error() {
        let e = err_text(ServerConfig::load("/nonexistent/rchat/server.toml"));
        assert!(e.contains("cannot read config file"), "{e}");
    }

    #[test]
    fn explicit_missing_config_is_an_error_even_with_no_tls() {
        let r = ServerConfig::load_for_cli_with_default(
            Some("/nonexistent/explicit.toml"),
            true,
            "/nonexistent/default.toml",
        );
        assert!(r.is_err());
    }

    #[test]
    fn default_missing_config_is_an_error_without_no_tls() {
        let r = ServerConfig::load_for_cli_with_default(None, false, "/nonexistent/default.toml");
        assert!(r.is_err());
    }

    /// Final review minor 4: no built-in plaintext defaults (they could
    /// never pass `validate`, which needs `dev_origin`).
    #[test]
    fn default_missing_config_with_no_tls_is_an_error_naming_dev_origin() {
        let e = err_text(ServerConfig::load_for_cli_with_default(
            None,
            true,
            "/nonexistent/default.toml",
        ));
        assert!(e.contains("dev_origin"), "{e}");
        assert!(e.contains("--config"), "{e}");
    }

    #[test]
    fn unparseable_config_is_an_error() {
        assert!(ServerConfig::from_toml_str("this is = = not toml").is_err());
    }

    #[test]
    fn no_tls_configured_refuses_to_start() {
        let cfg = ServerConfig::from_toml_str("[server]\nbind_addr = \"0.0.0.0:443\"\n").unwrap();
        let e = err_text(cfg.tls_mode());
        assert!(e.contains("no TLS configured"), "{e}");
        assert!(e.contains("--no-tls"), "{e}");
    }

    #[test]
    fn explicit_no_tls_gives_plaintext_and_clears_tls_and_acme() {
        let mut cfg = ServerConfig::from_toml_str(ACME_OK).unwrap();
        cfg.tls = Some(TlsConfig {
            cert_path: "/a".into(),
            key_path: "/b".into(),
        });
        cfg.bind_addr = "127.0.0.1:18443".parse().unwrap();
        cfg.disable_tls_for_dev(false);
        assert_eq!(cfg.tls_mode().unwrap(), TlsMode::Plaintext);
        assert!(cfg.tls.is_none());
        assert!(!cfg.acme.enabled);
    }

    #[test]
    fn no_tls_on_public_bind_is_refused() {
        for bind in [
            "0.0.0.0:443",
            "203.0.113.7:18443",
            "[::]:443",
            "[2001:db8::1]:443",
        ] {
            let mut cfg = ServerConfig {
                bind_addr: bind.parse().unwrap(),
                ..ServerConfig::default()
            };
            cfg.disable_tls_for_dev(false);
            let e = err_text(cfg.tls_mode());
            assert!(e.contains("--insecure-public-plaintext"), "{bind}: {e}");
        }
    }

    #[test]
    fn no_tls_on_public_bind_allowed_with_explicit_second_flag() {
        let mut cfg = ServerConfig {
            bind_addr: "0.0.0.0:443".parse().unwrap(),
            ..ServerConfig::default()
        };
        cfg.disable_tls_for_dev(true);
        assert_eq!(cfg.tls_mode().unwrap(), TlsMode::Plaintext);
    }

    #[test]
    fn no_tls_on_loopback_binds_is_allowed() {
        for bind in [
            "127.0.0.1:18443",
            "127.0.1.1:18443",
            "[::1]:18443",
            "[::ffff:127.0.0.1]:18443",
        ] {
            let mut cfg = ServerConfig {
                bind_addr: bind.parse().unwrap(),
                ..ServerConfig::default()
            };
            cfg.disable_tls_for_dev(false);
            assert_eq!(cfg.tls_mode().unwrap(), TlsMode::Plaintext, "{bind}");
        }
    }

    #[test]
    fn metrics_default_bind_is_loopback() {
        assert!(ServerConfig::default().metrics.bind_addr.ip().is_loopback());
        let cfg = ServerConfig::from_toml_str("[metrics]\nenabled = true\n").unwrap();
        assert!(cfg.metrics.bind_addr.ip().is_loopback());
    }

    #[test]
    fn public_metrics_bind_needs_an_explicit_opt_in() {
        // R-15: an unauthenticated endpoint is never exposed by accident.
        let mut c = ServerConfig::default();
        c.metrics.bind_addr = "0.0.0.0:9090".parse().unwrap();
        assert!(err_text(c.validate()).contains("metrics.bind_addr"));
        c.metrics.allow_public = true;
        assert!(c.validate().is_ok());
        c.metrics.allow_public = false;
        c.metrics.enabled = false;
        assert!(c.validate().is_ok(), "a disabled endpoint binds nothing");
    }

    #[test]
    fn static_and_acme_both_configured_refuses_to_start() {
        let toml = format!(
            "{ACME_OK}\n[server.tls]\ncert_path = \"/etc/rchat/tls/cert.pem\"\nkey_path = \"/etc/rchat/tls/key.pem\"\n"
        );
        let cfg = ServerConfig::from_toml_str(&toml).unwrap();
        let e = err_text(cfg.tls_mode());
        assert!(e.contains("both [server.tls]"), "{e}");
    }

    #[test]
    fn acme_disabled_block_with_static_cert_is_fine() {
        let toml = r#"
            [server.tls]
            cert_path = "/etc/rchat/tls/cert.pem"
            key_path = "/etc/rchat/tls/key.pem"
            [server.acme]
            enabled = false
            domains = ["chat.example.com"]
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert!(matches!(cfg.tls_mode().unwrap(), TlsMode::Static { .. }));
    }

    #[test]
    fn valid_acme_config_is_accepted() {
        let cfg = ServerConfig::from_toml_str(ACME_OK).unwrap();
        match cfg.tls_mode().unwrap() {
            TlsMode::Acme(a) => {
                assert_eq!(a.domains, vec!["chat.example.com".to_string()]);
                assert!(!a.staging);
                assert_eq!(
                    a.normalized_contacts().unwrap(),
                    vec!["mailto:ops@example.com".to_string()]
                );
            }
            other => panic!("expected ACME, got {other:?}"),
        }
    }

    #[test]
    fn acme_works_at_top_level_too() {
        let toml = "[acme]\nenabled = true\ndomains = [\"chat.example.com\"]\n";
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert!(matches!(cfg.tls_mode().unwrap(), TlsMode::Acme(_)));
        assert_eq!(cfg.acme.cache_dir, PathBuf::from(DEFAULT_ACME_CACHE_DIR));
    }

    #[test]
    fn relative_acme_cache_dir_is_rejected() {
        let toml = ACME_OK.replace("/var/lib/rchat/acme", "acme-cache");
        let cfg = ServerConfig::from_toml_str(&toml).unwrap();
        let e = err_text(cfg.tls_mode());
        assert!(e.contains("absolute path"), "{e}");
    }

    #[test]
    fn acme_without_domains_is_rejected() {
        let toml = ACME_OK.replace(r#"domains = ["chat.example.com"]"#, "domains = []");
        let cfg = ServerConfig::from_toml_str(&toml).unwrap();
        assert!(err_text(cfg.tls_mode()).contains("domains"));
    }

    #[test]
    fn bad_acme_domains_are_rejected() {
        for bad in [
            "*.example.com",
            "localhost",
            "https://chat.example.com",
            "chat.example.com:443",
            "Chat.Example.com",
            "203.0.113.7",
            "-bad.example.com",
            "a..example.com",
        ] {
            let mut acme = AcmeConfig {
                enabled: true,
                domains: vec![bad.to_string()],
                ..AcmeConfig::default()
            };
            assert!(acme.validate().is_err(), "{bad} should be rejected");
            acme.domains = vec!["ok-1.example.com".into()];
            assert!(acme.validate().is_ok());
        }
    }

    #[test]
    fn bad_acme_contacts_are_rejected() {
        for bad in ["not-an-email", "https://example.com", "tel:+15555550100"] {
            let acme = AcmeConfig {
                enabled: true,
                domains: vec!["chat.example.com".into()],
                contacts: vec![bad.into()],
                ..AcmeConfig::default()
            };
            assert!(acme.validate().is_err(), "{bad} should be rejected");
        }
        let acme = AcmeConfig {
            contacts: vec!["mailto:a@example.com".into()],
            ..AcmeConfig::default()
        };
        assert_eq!(
            acme.normalized_contacts().unwrap(),
            vec!["mailto:a@example.com".to_string()]
        );
    }

    #[test]
    fn unknown_acme_key_is_rejected() {
        let toml = format!("{ACME_OK}\nemail = \"ops@example.com\"\n");
        assert!(ServerConfig::from_toml_str(&toml).is_err());
    }

    #[test]
    fn dead_tls_version_keys_are_rejected_with_explanation() {
        for key in ["min_version = \"1.3\"", "tls13_only = true"] {
            let toml = format!("[server.tls]\ncert_path = \"/c\"\nkey_path = \"/k\"\n{key}\n");
            let e = err_text(ServerConfig::from_toml_str(&toml));
            assert!(e.contains("TLS 1.3 is mandatory"), "{e}");
        }
    }

    #[test]
    fn handshake_timeout_defaults_and_bounds() {
        let mut cfg = ServerConfig::from_toml_str(ACME_OK).unwrap();
        assert_eq!(cfg.tls_handshake_timeout(), Duration::from_secs(10));
        cfg.tls_handshake_timeout_secs = 0;
        assert!(cfg.tls_mode().is_err());
        cfg.tls_handshake_timeout_secs = 3600;
        assert!(cfg.tls_mode().is_err());
        cfg.tls_handshake_timeout_secs = 5;
        assert!(cfg.tls_mode().is_ok());
    }

    #[test]
    fn shipped_template_parses_and_selects_a_tls_mode() {
        let template = include_str!("../config/server.toml");
        let cfg = ServerConfig::from_toml_str(template).expect("template must parse");
        assert!(
            cfg.tls_mode().is_ok(),
            "template must be a valid TLS config"
        );
    }

    // ---- S3 resource-limit tests ----

    #[test]
    fn defaults_are_valid() {
        ServerConfig::default().validate().unwrap();
    }

    #[test]
    fn template_config_parses_and_is_valid_once_the_placeholder_path_is_set() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config/server.toml");
        let mut cfg = ServerConfig::load(path).unwrap();
        // The shipped placeholder websocket_path must be changed first.
        assert!(cfg.websocket_path.contains(WEBSOCKET_PATH_PLACEHOLDER));
        let e = format!("{:#}", cfg.validate().unwrap_err());
        assert!(e.contains("websocket_path"), "{e}");
        cfg.websocket_path = "/Zk3qA9-long-random-path".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn unknown_keys_are_rejected_in_every_table() {
        for toml in [
            "[server]\nbind_adr = \"127.0.0.1:1\"\n",
            "bind_adr = \"127.0.0.1:1\"\n",
            "[server]\ninsecure_no_tls = true\n",
            "[logging]\nlevle = \"debug\"\n",
            "[metrics]\nenabeld = true\n",
            "[server.decoy]\nrandomization_strength = 1\n",
            "[server.decoy]\nroot_dir = \"/x\"\n",
            "[redis]\nurl = \"redis://x\"\n",
        ] {
            assert!(
                ServerConfig::from_toml_str(toml).is_err(),
                "accepted unknown key: {toml}"
            );
        }
    }

    #[test]
    fn legacy_circuit_ttl_is_accepted_but_reported_as_ignored() {
        let cfg = ServerConfig::from_toml_str("[server]\ncircuit_ttl_secs = 3600\n").unwrap();
        assert!(cfg
            .startup_warnings()
            .iter()
            .any(|w| w.contains("circuit_ttl_secs")));
        assert!(ServerConfig::default().startup_warnings().is_empty());
    }

    /// Every `toml` example in the deployment docs that is a server config
    /// (contains `[server]`) must parse with the strict parser.
    #[test]
    fn deployment_doc_config_examples_parse() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/deployment");
        if !std::path::Path::new(dir).is_dir() {
            assert!(
                !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/ios")).exists(),
                "docs/deployment is missing from the private tree"
            );
            eprintln!("skipped: docs/deployment not present (public tree)");
            return;
        }
        let mut checked = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let mut rest = text.as_str();
            while let Some(start) = rest.find("```toml\n") {
                let body = &rest[start + 8..];
                let end = body.find("```").unwrap();
                let block = &body[..end];
                if block.contains("[server]") {
                    if let Err(e) = ServerConfig::from_toml_str(block) {
                        panic!("{}: example does not parse: {e:#}\n{block}", path.display());
                    }
                    checked += 1;
                }
                rest = &body[end + 3..];
            }
        }
        assert!(checked > 0, "no config examples found");
    }

    #[test]
    fn proxy_template_disables_per_ip_cap() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/server-behind-proxy.toml"
        );
        let mut cfg = ServerConfig::load(path).unwrap();
        // The template refuses to start until its placeholder path is set.
        assert!(err_text(cfg.validate()).contains(WEBSOCKET_PATH_PLACEHOLDER));
        cfg.websocket_path = "/a-long-random-path-for-this-test".to_string();
        cfg.validate().unwrap();
        assert_eq!(cfg.max_connections_per_ip, 0);
        assert_eq!(cfg.max_connections_per_ipv6_48, 0);
        // Layer 4: the relay terminates TLS itself on loopback, and the
        // front end supplies the client address in a PROXY v2 header.
        assert!(cfg.proxy_protocol);
        assert!(cfg.tls.is_some(), "the relay terminates TLS (protocol v2)");
        assert!(!cfg.insecure_no_tls);
        assert!(is_loopback(&cfg.bind_addr));
        assert_eq!(cfg.bind_addr.port(), 8443);
        assert!(matches!(cfg.tls_mode(), Ok(TlsMode::Static { .. })));
        let template = std::fs::read_to_string(path).unwrap();
        for front_end in ["send-proxy-v2", "proxy_protocol: v2", "sc0_conn_cur gt 64"] {
            assert!(
                template.contains(front_end),
                "the template shows the front-end line {front_end:?}"
            );
        }
        assert!(!template.contains("trusted_proxy ="));
        // Stock nginx stream sends PROXY v1 only: not a supported front end.
        assert!(!template.contains("proxy_protocol on;"));
        assert!(template.contains("Trust boundary"));
        let caddy = include_str!("../config/Caddyfile");
        assert!(
            caddy.contains("layer4"),
            "the Caddyfile is a caddy-l4 example"
        );
        assert!(caddy.contains("127.0.0.1:8443"));
        assert!(caddy.contains("proxy_protocol v2"));
        assert!(
            !caddy
                .lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("reverse_proxy")),
            "no TLS-terminating proxy"
        );
        let default = ServerConfig::from_toml_str(include_str!("../config/server.toml")).unwrap();
        assert!(!default.proxy_protocol, "off unless asked for");
    }

    /// Final review minor 6: the unused `redis_url` is refused like `trusted_proxy`.
    #[test]
    fn removed_redis_url_is_a_startup_error() {
        let c =
            ServerConfig::from_toml_str("[server]\nredis_url = \"redis://127.0.0.1/\"\n").unwrap();
        let e = err_text(c.validate());
        assert!(e.contains("redis_url was removed"), "{e}");
        let default = ServerConfig::from_toml_str(include_str!("../config/server.toml")).unwrap();
        assert!(default.redis_url.is_none());
    }

    #[test]
    fn removed_trusted_proxy_is_a_startup_error_pointing_to_proxy_protocol() {
        for value in ["true", "false"] {
            let c = ServerConfig::from_toml_str(&format!("[server]\ntrusted_proxy = {value}\n"))
                .unwrap();
            let e = err_text(c.validate());
            assert!(e.contains("trusted_proxy was removed"), "{e}");
            assert!(e.contains("proxy_protocol = true"), "{e}");
        }
    }

    #[test]
    fn proxy_protocol_needs_no_per_address_caps_and_a_loopback_bind() {
        let check = |bind: &str, per_ip: usize, per_48: usize| {
            ServerConfig::from_toml_str(&format!(
                "[server]\nproxy_protocol = true\nbind_addr = \"{bind}\"\n\
                 max_connections_per_ip = {per_ip}\nmax_connections_per_ipv6_48 = {per_48}\n"
            ))
            .unwrap()
            .validate()
        };
        for bind in ["127.0.0.1:8443", "[::1]:8443"] {
            assert!(check(bind, 0, 0).is_ok(), "{bind}");
            let e = err_text(check(bind, 4, 0));
            assert!(e.contains("max_connections_per_ip = 0"), "{e}");
            // M1: a front end on ::1 is one /48 key; the /48 cap would cap
            // the whole relay, so it is refused too.
            let e = err_text(check(bind, 0, 256));
            assert!(e.contains("max_connections_per_ipv6_48 = 0"), "{e}");
        }
        // The /48 cap's default (256) is refused when not set explicitly.
        let e = err_text(
            ServerConfig::from_toml_str(
                "[server]\nproxy_protocol = true\nbind_addr = \"[::1]:8443\"\n\
                 max_connections_per_ip = 0\n",
            )
            .unwrap()
            .validate(),
        );
        assert!(e.contains("max_connections_per_ipv6_48 = 0"), "{e}");
        // L1: only a loopback bind; wildcard and public binds are refused.
        for bind in [
            "0.0.0.0:8443",
            "[::]:8443",
            "192.0.2.1:8443",
            "[2001:db8::1]:8443",
        ] {
            let e = err_text(check(bind, 0, 0));
            assert!(e.contains("only a loopback bind"), "{bind}: {e}");
        }
        assert!(ServerConfig::from_toml_str("[server]\nproxy_protocol = 1\n").is_err());
    }

    #[test]
    fn invalid_limits_are_rejected() {
        let bad: Vec<fn(&mut ServerConfig)> = vec![
            |c| c.max_connections = 0,
            |c| c.max_connections_per_ip = c.max_connections + 1,
            |c| c.rate_limit_bps = 0,
            |c| c.max_message_bytes = 1024,
            |c| c.max_message_bytes = usize::MAX,
            |c| c.connection_timeout_secs = 5,
            |c| c.offline_queue_max_bytes_per_recipient = 1,
            |c| c.offline_queue_max_total_bytes = 1,
            |c| c.outbound_budget_bytes = 1 << 20,
            |c| c.outbound_budget_bytes = usize::MAX,
            |c| c.buffer_budget_bytes = c.max_message_bytes - 1,
            |c| c.buffer_budget_bytes = usize::MAX,
            |c| c.max_pending_circuit_targets = 0,
            |c| c.max_circuits_per_connection = 0,
            |c| c.max_circuits_per_connection = 100_000,
            |c| c.max_circuits = 1,
            |c| c.max_circuits = 20_000_000,
            |c| c.max_pending_per_connection = 0,
            |c| c.max_pending_per_connection = c.max_pending_circuit_targets + 1,
            |c| c.max_pending_circuit_targets = 2_000_000,
            |c| c.max_connections_per_ipv6_48 = c.max_connections + 1,
            |c| c.identification_timeout_secs = 0,
            |c| c.identification_timeout_secs = 301,
            |c| {
                c.connection_timeout_secs = 60;
                c.identification_timeout_secs = 61;
            },
        ];
        for (i, mutate) in bad.into_iter().enumerate() {
            let mut c = ServerConfig::default();
            mutate(&mut c);
            assert!(c.validate().is_err(), "case {i} should be rejected");
        }
    }

    #[test]
    fn per_ip_zero_is_allowed() {
        let c = ServerConfig {
            max_connections_per_ip: 0,
            ..ServerConfig::default()
        };
        c.validate().unwrap();
    }

    #[test]
    fn burst_admits_one_max_message() {
        let c = ServerConfig {
            rate_limit_bps: 1024,
            ..ServerConfig::default()
        };
        assert_eq!(c.rate_limit_burst_bytes(), c.max_message_bytes as u64);
    }

    #[test]
    fn no_tls_without_dev_origin_is_refused() {
        let cfg = ServerConfig {
            insecure_no_tls: true,
            ..ServerConfig::default()
        };
        let e = format!("{:#}", cfg.validate().unwrap_err());
        assert!(e.contains("dev_origin"), "{e}");
        assert!(cfg.dev_binding().is_err());
    }

    #[test]
    fn dev_binding_normalises_the_origin_and_matches_the_core() {
        let cfg = ServerConfig {
            insecure_no_tls: true,
            dev_origin: Some("WS://127.0.0.1:8443/some/path".to_string()),
            ..ServerConfig::default()
        };
        cfg.validate().unwrap();
        assert_eq!(
            hex::encode(cfg.dev_binding().unwrap().unwrap()),
            "dc0d2d9890cc672819a084e35d4f242202c9bb548e2f76d0fa3222b9a9475725",
            "same bytes as rchat-core's golden DEV_ORIGIN_BINDING(ws://127.0.0.1:8443)"
        );
        let tls = ServerConfig {
            dev_origin: Some("ws://127.0.0.1:8443".to_string()),
            ..ServerConfig::default()
        };
        assert_eq!(
            tls.dev_binding().unwrap(),
            None,
            "TLS mode never uses the dev binding"
        );
    }

    #[test]
    fn malformed_dev_origin_is_refused() {
        let cfg = ServerConfig {
            insecure_no_tls: true,
            dev_origin: Some("not an origin".to_string()),
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dev_origin_is_read_from_the_server_table() {
        let cfg = ServerConfig::from_toml_str(
            "[server]\nbind_addr = \"127.0.0.1:8443\"\ndev_origin = \"ws://127.0.0.1:8443\"\n",
        )
        .unwrap();
        assert_eq!(cfg.dev_origin.as_deref(), Some("ws://127.0.0.1:8443"));
    }
}
