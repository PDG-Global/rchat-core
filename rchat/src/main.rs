use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info, warn};

mod config;
mod decoy;
mod decoy_render;
#[cfg(test)]
mod decoy_render_tests;
mod hardening;
mod invite;
mod limits;
mod metrics;
mod privacy;
mod protocol;
mod proxy_protocol;
mod signaling;
mod tls;
mod tls_pq;
mod validate;

/// A test's scratch directory under the system temp dir, removed when the
/// test is done with it (test runs used to leave thousands behind).
#[cfg(test)]
pub(crate) struct ScratchDir(std::path::PathBuf);

#[cfg(test)]
impl ScratchDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

#[cfg(test)]
impl std::ops::Deref for ScratchDir {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
impl AsRef<std::path::Path> for ScratchDir {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

use config::ServerConfig;

#[derive(Parser, Debug)]
#[command(name = "rchat-server", version)]
#[command(about = "Secure end-to-end encrypted chat server (WebSocket over TLS 1.3)")]
struct Cli {
    /// Config file [default: /etc/rchat/server.toml]. A missing or unreadable
    /// file is a startup error.
    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long, env = "RCHAT_BIND_ADDR")]
    bind: Option<SocketAddr>,

    #[arg(short, long, env = "RCHAT_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// DEVELOPMENT ONLY: serve plaintext WebSocket with no TLS at all.
    /// Ignores [server.tls] and [server.acme].
    #[arg(long)]
    no_tls: bool,

    /// With --no-tls, also allow binding a non-loopback address. Anyone on
    /// the network can then read and tamper with all traffic. Without this
    /// flag, --no-tls on a non-loopback address refuses to start.
    #[arg(long, requires = "no_tls")]
    insecure_public_plaintext: bool,

    /// Create the relay identity key (once; refuses to overwrite), print its pin, then exit.
    #[arg(long, conflicts_with_all = ["print_relay_pin", "rotate_relay_identity"])]
    init_relay_identity: bool,

    /// Print this relay's identity pin (rk:1:…) and version, then exit.
    #[arg(long)]
    print_relay_pin: bool,

    /// Rotate the relay identity (new key, link signed by the old key,
    /// version + 1), print the new pin, then exit.
    #[arg(long, conflicts_with = "print_relay_pin")]
    rotate_relay_identity: bool,

    /// Print this relay's invite (an rchat://relay link with its URL and
    /// pin) and draw it as a QR code, then exit. Run it as the service user.
    /// The host comes from [server.decoy] host, else the first [server.acme]
    /// domain. The invite holds the secret WebSocket path: it is printed
    /// here only, never logged.
    #[arg(
        long,
        conflicts_with_all = ["init_relay_identity", "print_relay_pin", "rotate_relay_identity", "render_decoy", "no_tls"]
    )]
    print_invite: bool,

    /// With --print-invite: the port clients dial, overriding [server]
    /// public_port (NAT, rdr, a jail). 443 is left out of the invite.
    #[arg(long, value_name = "PORT", requires = "print_invite", value_parser = clap::value_parser!(u16).range(1..))]
    public_port: Option<u16>,

    /// Write this relay's static decoy website into DIR, then exit. DIR must
    /// be empty or a directory rendered this way before. The site is chosen
    /// from the relay identity key and the host name, so this relay always
    /// gives the same site and nobody without the key can work it out. Run
    /// it as the service user (it reads the identity key). Point
    /// `[server.decoy] root` at DIR to serve it.
    #[arg(
        long,
        value_name = "DIR",
        conflicts_with_all = ["init_relay_identity", "print_relay_pin", "rotate_relay_identity", "no_tls"]
    )]
    render_decoy: Option<PathBuf>,

    /// With --render-decoy: the relay's public host name (default: from
    /// [server.decoy] host or the first [server.acme] domain in the config).
    #[arg(long, value_name = "HOSTNAME", requires = "render_decoy")]
    host: Option<String>,
}

impl Cli {
    /// A one-shot mode whose result is printed to stdout: logs go to stderr.
    fn prints_result(&self) -> bool {
        self.print_invite
            || self.print_relay_pin
            || self.init_relay_identity
            || self.rotate_relay_identity
            || self.render_decoy.is_some()
    }
}

/// `--render-decoy`: render the site into `dir` and return the line to
/// print. The seed is the relay identity's decoy seed for `host` (final
/// review M2: `HKDF(identity secret, salt = host)`), the one the built-in
/// page uses, so the rendered site matches what the relay would serve
/// without a `root` and can't be computed from the host alone. The identity
/// key at `identity_path` must exist and be readable: run it as the service
/// user, as `--print-invite`.
fn run_render_decoy(
    dir: &std::path::Path,
    host: Option<&str>,
    identity_path: &std::path::Path,
) -> Result<String> {
    let fail = |e: std::io::Error| anyhow::anyhow!("--render-decoy failed: {e}");
    let host = host
        .map(decoy_render::normalize_host)
        .filter(|h| !h.is_empty());
    let seed = signaling::relay_identity_decoy_seed(identity_path, host.as_deref())?;
    decoy_render::render_decoy_seeded(seed, dir).map_err(fail)?;
    let source = match &host {
        Some(h) => h.clone(),
        None => "this relay (no host name)".to_string(),
    };
    let product = decoy_render::render_site_for_seed(seed).product;
    Ok(format!(
        "wrote a {product:?} decoy site for {source} into {}",
        dir.display()
    ))
}

/// `--print-invite`: the invite for this relay's configured host, path and
/// identity key. The caller prints it; nothing here logs.
fn run_print_invite(
    config: &ServerConfig,
    identity_path: &std::path::Path,
    ansi: bool,
) -> Result<String> {
    let (pin, _version) = signaling::relay_identity_load(identity_path)?;
    invite::print_invite_output(config, &pin, ansi)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // The one-shot print modes write only their result to stdout (the
    // invite, the pin), so logs go to stderr there (round 1 M-7).
    let writer = if cli.prints_result() {
        tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stderr)
    } else {
        tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stdout)
    };
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_writer(writer)
        .init();

    install_panic_hook();
    // R-13: no core file and no ptrace attach for a process holding keys.
    // Not fatal (a sandbox may forbid the calls; the units set LimitCORE=0).
    if let Err(e) = hardening::disable_core_dumps() {
        warn!("Could not fully disable core dumps: {}", e);
    }
    info!("Starting RChat server v{}", env!("CARGO_PKG_VERSION"));

    let config = ServerConfig::load_for_cli(cli.config.as_deref(), cli.no_tls)?;
    let mut config = config.with_cli_overrides(&cli);
    if config.relay_identity_path.is_none() {
        let dir = cli
            .config
            .as_deref()
            .map(std::path::Path::new)
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .or_else(|| {
                let default = std::path::Path::new(config::DEFAULT_CONFIG_PATH);
                default
                    .exists()
                    .then(|| default.parent().map(|d| d.to_path_buf()))
                    .flatten()
            })
            .unwrap_or_else(|| PathBuf::from("."));
        config.relay_identity_path = Some(
            dir.join("relay_identity.key")
                .to_string_lossy()
                .into_owned(),
        );
    }
    let identity_path = PathBuf::from(config.relay_identity_path.clone().unwrap_or_default());
    if let Some(dir) = &cli.render_decoy {
        // The host: --host, else the configured host (or first ACME
        // domain), else none. Seeded from the relay identity key with it,
        // as the built-in page (final review M2).
        let host = cli.host.clone().or_else(|| config.decoy_host());
        println!(
            "{}",
            run_render_decoy(dir, host.as_deref(), &identity_path)?
        );
        return Ok(());
    }
    if cli.print_invite {
        use std::io::IsTerminal;
        let ansi = std::io::stdout().is_terminal();
        print!("{}", run_print_invite(&config, &identity_path, ansi)?);
        return Ok(());
    }
    if cli.init_relay_identity || cli.print_relay_pin || cli.rotate_relay_identity {
        let (pin, version) = if cli.init_relay_identity {
            signaling::relay_identity_init(&identity_path)?
        } else if cli.rotate_relay_identity {
            signaling::relay_identity_rotate(&identity_path)?
        } else {
            signaling::relay_identity_load(&identity_path)?
        };
        println!("{pin} (version {version})");
        return Ok(());
    }
    // A config file is always in use (`load_for_cli`). Round-2 L1: fail
    // loudly rather than mint a new identity on redeploy.
    signaling::relay_identity_load(&identity_path)?;
    // Before validation: a config that still names the removed
    // `message_queue_persist_path` is refused below, but its plaintext file
    // is wiped first.
    wipe_legacy_queue_files(&config, dirs::home_dir());
    // Validate the TLS decision before anything binds or starts.
    let mode = config.tls_mode()?;
    config.validate()?;
    #[cfg(feature = "test-mitm")]
    {
        let acknowledged = std::env::var("RCHAT_MITM_I_UNDERSTAND").as_deref() == Ok("1");
        if !acknowledged || !config::is_loopback(&config.bind_addr) {
            anyhow::bail!(
                "this is a test-mitm build that tampers with key exchange; refusing to start \
                 (set RCHAT_MITM_I_UNDERSTAND=1 and bind a loopback address)"
            );
        }
        warn!(
            "TEST-MITM BUILD: this relay tampers with key exchange on purpose (mode {:?})",
            signaling::mitm::mode()
        );
    }
    for notice in config.startup_warnings() {
        warn!("{}", notice);
    }

    privacy::set_log_client_ips(config.logging.log_client_ips);
    info!("Configuration loaded successfully");
    if config.logging.log_client_ips {
        warn!("logging.log_client_ips is enabled: client IPs will appear in debug logs");
    }
    info!("WebSocket bind: {}", config.bind_addr);

    if mode == config::TlsMode::Plaintext {
        warn!("==================================================================");
        warn!("  TLS DISABLED (--no-tls). Traffic, including circuit tokens, is");
        warn!("  sent in PLAINTEXT. --no-tls is for local development only:");
        warn!("  protocol v2 needs the relay to terminate TLS itself.");
        warn!("==================================================================");
        if !config::is_loopback(&config.bind_addr) {
            // Only reachable with --insecure-public-plaintext; tls_mode()
            // refuses a public plaintext bind otherwise.
            error!(
                "--insecure-public-plaintext: plaintext listener on non-loopback address {}. \
                 Anyone on the network can read and tamper with this traffic, including \
                 circuit tokens.",
                config.bind_addr
            );
        }
    }

    metrics::init();
    if config.metrics.enabled {
        // The server's own listen address (not client data).
        let metrics_bind_addr = config.metrics.bind_addr;
        if !metrics_bind_addr.ip().is_loopback() {
            warn!(
                "metrics endpoint listens on non-loopback interface {}: it is \
                 unauthenticated; restrict access with a firewall",
                metrics_bind_addr
            );
        }
        // Metrics are not essential: a bind failure is logged, not fatal.
        tokio::spawn(async move {
            if let Err(e) = metrics::start_server(metrics_bind_addr).await {
                tracing::error!("Metrics endpoint failed on {}: {:#}", metrics_bind_addr, e);
            }
        });
    }

    let server = signaling::Server::new(config).await?;
    let saver = server.queue_saver();
    info!("Server initialized, starting main loop");
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let stop = tokio::select! {
        result = server.run() => {
            result?;
            None
        }
        _ = sigterm.recv() => Some("SIGTERM"),
        _ = sigint.recv() => Some("SIGINT"),
    };
    if let Some(sig) = stop {
        if let Some(saver) = saver {
            // save_now fsyncs and waits for any periodic save in flight.
            match tokio::task::spawn_blocking(move || saver.save_now()).await {
                Ok(Ok(())) => info!("{}: offline queue saved", sig),
                Ok(Err(e)) => error!("{}: saving the offline queue failed: {:#}", sig, e),
                Err(_) => error!("{}: saving the offline queue did not complete", sig),
            }
        }
        info!("{}: exiting", sig);
    }

    Ok(())
}

/// Log panics through tracing with their source location only. The payload
/// is withheld: assertion and `expect` messages can carry values (keys,
/// identities, payload bytes), and the default hook would print them to
/// stderr (S-5).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());
        error!("panic at {} (message withheld)", location);
    }));
}

/// Every place a pre-v2 relay may have left its plaintext offline-queue
/// file: the configured `message_queue_persist_path`, and the default
/// `~/.rchat/message_queues.json` (`./.rchat/…` when there was no home
/// directory).
fn legacy_queue_files(config: &ServerConfig, home: Option<PathBuf>) -> Vec<PathBuf> {
    let default_dir = home
        .map(|h| h.join(".rchat"))
        .unwrap_or_else(|| PathBuf::from(".rchat"));
    let mut paths = vec![default_dir.join("message_queues.json")];
    if let Some(configured) = config.message_queue_persist_path.as_deref() {
        let configured = PathBuf::from(configured);
        if !paths.contains(&configured) {
            paths.push(configured);
        }
    }
    paths
}

/// Zero-fill and unlink every legacy plaintext queue file (D6), naming
/// each removed path (paths only; the files' contents are never read).
fn wipe_legacy_queue_files(config: &ServerConfig, home: Option<PathBuf>) -> Vec<PathBuf> {
    let mut wiped = Vec::new();
    for path in legacy_queue_files(config, home) {
        match signaling::wipe_legacy_queue_file(&path) {
            Ok(true) => {
                warn!(
                    "Removed the legacy plaintext offline-queue file {}; messages queued before \
                     this version are discarded",
                    path.display()
                );
                wiped.push(path);
            }
            Ok(false) => {}
            Err(e) => warn!(
                "Could not remove the legacy plaintext offline-queue file {}: {}",
                path.display(),
                e
            ),
        }
    }
    wiped
}

#[cfg(test)]
mod legacy_wipe_tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rchat-legacy-main-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn configured_and_default_legacy_files_are_wiped() {
        let home = temp_dir();
        let custom_dir = temp_dir();
        std::fs::create_dir_all(home.join(".rchat")).unwrap();
        let default_file = home.join(".rchat").join("message_queues.json");
        let custom_file = custom_dir.join("message-queue.json");
        std::fs::write(&default_file, b"{\"queues\":[]}").unwrap();
        std::fs::write(&custom_file, b"{\"queues\":[]}").unwrap();
        let config = ServerConfig {
            message_queue_persist_path: Some(custom_file.to_string_lossy().into_owned()),
            ..ServerConfig::default()
        };

        let wiped = wipe_legacy_queue_files(&config, Some(home.clone()));
        assert_eq!(wiped, vec![default_file.clone(), custom_file.clone()]);
        assert!(!default_file.exists() && !custom_file.exists());
        // The relay still refuses to start with the removed key.
        let err = format!("{:#}", config.validate().unwrap_err());
        assert!(err.contains("message_queue_persist_path was removed"));
        assert!(wipe_legacy_queue_files(&config, Some(home.clone())).is_empty());
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&custom_dir);
    }

    #[test]
    fn without_a_home_directory_the_cwd_fallback_is_targeted() {
        let paths = legacy_queue_files(&ServerConfig::default(), None);
        assert_eq!(
            paths,
            vec![PathBuf::from(".rchat").join("message_queues.json")]
        );
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;
    use sha2::Digest;

    #[test]
    fn version_flag_prints_the_package_version() {
        let err = Cli::try_parse_from(["rchat-server", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            err.to_string().trim(),
            format!("rchat-server {}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            Cli::command().get_version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn render_decoy_flags_parse_and_conflict() {
        let c =
            Cli::try_parse_from(["rchat-server", "--render-decoy", "/d", "--host", "A.b"]).unwrap();
        assert_eq!(c.render_decoy.as_deref(), Some(std::path::Path::new("/d")));
        assert_eq!(c.host.as_deref(), Some("A.b"));
        assert!(Cli::try_parse_from(["rchat-server", "--host", "x"]).is_err());
        assert!(Cli::try_parse_from([
            "rchat-server",
            "--render-decoy",
            "/d",
            "--init-relay-identity"
        ])
        .is_err());
    }

    #[test]
    fn print_modes_log_to_stderr() {
        for args in [
            &["rchat-server", "--print-invite"][..],
            &["rchat-server", "--print-relay-pin"],
            &["rchat-server", "--init-relay-identity"],
            &["rchat-server", "--rotate-relay-identity"],
            &["rchat-server", "--render-decoy", "/d"],
        ] {
            assert!(
                Cli::try_parse_from(args).unwrap().prints_result(),
                "{args:?}"
            );
        }
        assert!(!Cli::try_parse_from(["rchat-server"])
            .unwrap()
            .prints_result());
    }

    #[test]
    fn print_invite_flag_parses_and_conflicts() {
        let c = Cli::try_parse_from(["rchat-server", "--config", "/c", "--print-invite"]).unwrap();
        assert!(c.print_invite);
        let c = Cli::try_parse_from(["rchat-server", "--print-invite", "--public-port", "443"])
            .unwrap();
        assert_eq!(c.public_port, Some(443));
        let cfg = ServerConfig::default().with_cli_overrides(&c);
        assert_eq!(cfg.public_port, Some(443));
        assert!(Cli::try_parse_from(["rchat-server", "--public-port", "443"]).is_err());
        assert!(
            Cli::try_parse_from(["rchat-server", "--print-invite", "--public-port", "0"]).is_err()
        );
        for other in [
            "--init-relay-identity",
            "--print-relay-pin",
            "--rotate-relay-identity",
            "--no-tls",
        ] {
            assert!(
                Cli::try_parse_from(["rchat-server", "--print-invite", other]).is_err(),
                "{other}"
            );
        }
    }

    /// Part J: the invite carries this relay's own pin, from its identity
    /// key; with no host configured it refuses and says to set one.
    #[test]
    fn print_invite_uses_the_relay_identity_and_configured_host() {
        let t = ScratchDir::new("print-invite-cmd");
        let key = t.join("relay_identity.key");
        let (pin, _) = signaling::relay_identity_init(&key).unwrap();
        let mut config = ServerConfig {
            websocket_path: "/dummy-secret-path".into(),
            ..ServerConfig::default()
        };
        config.bind_addr = "0.0.0.0:443".parse().unwrap();
        let e = run_print_invite(&config, &key, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("[server.decoy]"), "{e}");
        config.decoy.host = Some("chat.example.com".into());
        let out = run_print_invite(&config, &key, false).unwrap();
        let link = out
            .lines()
            .find(|l| l.starts_with("rchat://relay?"))
            .expect("link line");
        let parsed = rchat_core::invite::parse_invite(link).unwrap();
        assert_eq!(parsed.pin, pin);
        assert_eq!(parsed.url, "wss://chat.example.com/dummy-secret-path");
        assert!(out.contains(invite::SENSITIVITY));
        assert!(out.contains('▀') || out.contains('▄'), "a QR block");
        // No key: refused, as --print-relay-pin is.
        assert!(run_print_invite(&config, &t.join("missing.key"), false).is_err());
    }

    /// Final review M2: `--render-decoy` always loads the relay identity and
    /// seeds from its secret and the host, exactly as the built-in page
    /// does; a host alone (public) no longer determines the site.
    #[test]
    fn render_decoy_command_seeds_from_the_identity_and_host_and_refuses_foreign_dirs() {
        let t = ScratchDir::new("render-decoy-cmd");
        let key = t.join("relay_identity.key");
        signaling::relay_identity_init(&key).unwrap();
        let index = |dir: &str| std::fs::read(t.join(dir).join("index.html")).unwrap();
        let built_in = |host: Option<&str>| {
            let seed = signaling::relay_identity_decoy_seed(&key, host).unwrap();
            decoy_render::render_site_for_seed(seed)
                .get("index.html")
                .unwrap()
                .to_vec()
        };
        let msg = run_render_decoy(&t.join("a"), Some("Chat.Example.com."), &key).unwrap();
        assert!(msg.contains("chat.example.com"), "{msg}");
        assert_eq!(index("a"), built_in(Some("chat.example.com")));
        let public_only = decoy_render::render_site_for_seed(<[u8; 32]>::from(
            sha2::Sha256::digest(b"chat.example.com"),
        ));
        assert_ne!(index("a"), public_only.get("index.html").unwrap());
        // No host: the identity seed alone, and it matches the built-in site.
        run_render_decoy(&t.join("b"), None, &key).unwrap();
        assert_eq!(index("b"), built_in(None));
        // No identity key: refused, with or without a host; nothing written.
        let missing = t.join("missing.key");
        assert!(run_render_decoy(&t.join("n"), None, &missing).is_err());
        assert!(run_render_decoy(&t.join("n"), Some("h.example.com"), &missing).is_err());
        assert!(!t.join("n").exists());
        // A foreign directory is refused.
        std::fs::create_dir(t.join("f")).unwrap();
        std::fs::write(t.join("f/keep"), b"x").unwrap();
        assert!(run_render_decoy(&t.join("f"), Some("h.example.com"), &key).is_err());
        assert!(run_render_decoy(&t.join("f"), None, &key).is_err());
        assert!(!t.join("f/index.html").exists());
    }
}
