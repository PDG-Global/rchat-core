use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info, warn};

mod config;
mod decoy;
mod hardening;
mod limits;
mod metrics;
mod privacy;
mod protocol;
mod proxy_protocol;
mod signaling;
mod tls;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
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
}
