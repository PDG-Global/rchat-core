//! Signaling Server - WebSocket-based connection establishment
//!
//! This module provides a unified WebSocket server that handles both
//! signaling and relay traffic over a single TLS 1.3 connection.

use crate::config::ServerConfig;
use crate::decoy::{self, DecoyConfig};
use crate::limits::{
    self, ConnRejection, ConnTx, ConnectionLimiter, OfflineBudget, SourceKey, TokenBucket,
};
use crate::metrics;
use crate::privacy;
use crate::protocol::relay::{CircuitToken, RelayPacket};
use crate::protocol::signaling::{Payload as SignalingPayload, *};
use crate::protocol::unified::{
    ControlErrorCode, ControlMessage, FrameBuilder, FrameError, KeepaliveMessage, PeerBundle,
    UnifiedFrame, UnifiedFrame as Frame,
};
use crate::protocol::{validate_timestamp, CircuitId, ClientId, ErrorCode, PROTOCOL_VERSION};
use crate::validate;

#[cfg(test)]
use self::circuits::PendingAsk;
use self::tags::{id_tag, BlindTag, IdTag, PairTag};
use dashmap::DashMap;
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, tungstenite::Message};
use tokio_util::sync::CancellationToken;

use crate::tls::{Accepted, TlsFront};
use tracing::{debug, error, info, trace, warn};

mod circuits;
mod fair_share;
mod key_auth;
mod knock_store;
#[cfg(feature = "test-mitm")]
pub(crate) mod mitm;
mod pair_lock;
pub(crate) mod persist;
mod relay_identity;
mod tags;

#[cfg(test)]
mod blind_pairing_tests;
#[cfg(test)]
mod circuit_race_tests;
#[cfg(test)]
mod client_resumption_tests;
#[cfg(test)]
mod inflight_salvage_tests;
#[cfg(test)]
mod input_validation_tests;
#[cfg(test)]
mod key_auth_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod log_privacy_tests;
#[cfg(test)]
mod metadata_bounds_tests;
#[cfg(test)]
mod outbound_tests;
#[cfg(test)]
mod pair_lifecycle_tests;
#[cfg(test)]
mod pong_progress_tests;
#[cfg(test)]
mod proxy_source_tests;
#[cfg(test)]
mod queue_v2_tests;
#[cfg(test)]
mod reconnect_session_tests;
#[cfg(test)]
mod rotation_relay_tests;
#[cfg(test)]
mod state_bounds_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tls_resumption_tests;
#[cfg(test)]
mod unresumed_forward_tests;

/// A record in a recipient's offline queue (spec §5.3, M4). Nothing names a
/// sender; the single time field is the enqueue time, in memory and on disk.
#[derive(Clone, Debug)]
struct StoredMessage {
    /// The sealed v2 payload, byte for byte.
    payload: Vec<u8>,
    enqueued_at_unix_secs: u64,
    is_knock: bool,
    /// Knock accounting handle (`KnockStore`); 0 for messages. Memory-only:
    /// never persisted (RCQ2 stores only the three fields above) and
    /// reassigned by `KnockStore::requeue` when records come back (a
    /// re-queue after a failed drain, or a restore from RCQ2).
    knock_seq: u64,
}

/// One recipient's queued records (ratchet messages and knocks).
#[derive(Clone, Debug, Default)]
pub(crate) struct MessageQueue {
    pending: Vec<StoredMessage>,
    /// Bytes charged to the offline budget for the non-knock records.
    bytes: usize,
}

impl MessageQueue {
    /// Records that are messages (knocks have their own budget).
    fn message_count(&self) -> usize {
        self.pending.iter().filter(|m| !m.is_knock).count()
    }

    /// Messages of exactly the steady sealed size (R26 sub-cap).
    fn steady_sized_count(&self) -> usize {
        self.pending
            .iter()
            .filter(|m| !m.is_knock && m.payload.len() == limits::STEADY_SEALED_LEN)
            .count()
    }
}

impl StoredMessage {
    /// Bytes charged against the offline budget. Knocks are never charged.
    fn budget_cost(&self) -> usize {
        if self.is_knock {
            0
        } else {
            OfflineBudget::message_cost(self.payload.len(), 0, 0)
        }
    }
}

/// Strict TTL check from the stored time. A future-dated record counts as
/// enqueued now (age 0).
fn expired(now_unix: u64, enqueued_at: u64, ttl: u64) -> bool {
    now_unix.saturating_sub(enqueued_at) > ttl
}

/// Drop expired queued items: knocks after `knock_ttl_secs`, messages after
/// `offline_queue.ttl_secs`, returning message bytes to the budget.
fn expire_queues(now_unix: u64, state: &RelayState) {
    state.knocks.expire(
        now_unix,
        state.config.knock_ttl_secs(),
        &state.message_queues,
    );
    let ttl = state.config.offline_queue.ttl_secs;
    let mut released = 0usize;
    state.message_queues.retain(|_, q| {
        let mut freed = 0usize;
        q.pending.retain(|m| {
            if m.is_knock || !expired(now_unix, m.enqueued_at_unix_secs, ttl) {
                return true;
            }
            freed += m.budget_cost();
            false
        });
        q.bytes = q.bytes.saturating_sub(freed);
        released += freed;
        !q.pending.is_empty()
    });
    if released > 0 {
        state.offline_budget.release(released);
        debug!("Expired {} bytes of offline messages", released);
    }
}

/// Unified server that handles both signaling and relay over WebSocket
/// TLS 1.3 (static cert or ACME) unless started with the dev-only `--no-tls`.
pub struct Server {
    state: RelayState,
    listener: TcpListener,
    /// `None` only when plaintext was explicitly requested with `--no-tls`.
    tls_front: Option<TlsFront>,
    decoy_config: DecoyConfig,
    /// Global and per-address connection caps
    conn_limiter: Arc<ConnectionLimiter>,
    /// Encrypted queue persistence (RCQ2); `None` unless opted in.
    persist: Option<Arc<persist::PersistCtx>>,
}

/// Everything the connection handlers share. Cheap to clone: every field is
/// an `Arc`.
#[derive(Clone)]
pub(crate) struct RelayState {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) connections: Arc<DashMap<ClientId, UnifiedConnection>>,
    pub(crate) circuits: Arc<DashMap<CircuitId, CircuitRoutingInfo>>,
    /// Routing slot: identity tag -> the connection proven as it (R1).
    pub(crate) identity_to_client: Arc<DashMap<IdTag, ClientId>>,
    /// Live pairs from identity asks, keyed by pair tag.
    pub(crate) identity_pair_circuits: Arc<DashMap<PairTag, CircuitPairInfo>>,
    /// Live pairs from blinded asks (protocol v3 §C.2), keyed by the token's
    /// keyed tag: no identity pair is stored for them.
    pub(crate) blind_pair_circuits: Arc<DashMap<BlindTag, BlindPairInfo>>,
    /// Ruling R21: blinded circuits whose owning connection closed while the
    /// row stayed (the peer was still online), by the owner's identity tag,
    /// so the owner's next publish ends them at once. Memory only, per boot;
    /// an entry goes with its row (teardown, sweep), so none outlives
    /// `PAIR_ORPHAN_TTL`. It names one identity's circuits, never a pair.
    pub(crate) departed_blind: Arc<DashMap<IdTag, Vec<CircuitId>>>,
    /// One-sided asks, keyed by pair tag or, for blinded asks, by the token's
    /// keyed tag (≤ `ASK_TTL` = 540 s; gone within 600 s with the sweep).
    pub(crate) pending_asks: Arc<fair_share::PendingAsks>,
    /// Circuits per identity tag and per source (R-3).
    pub(crate) circuit_counts: Arc<fair_share::CircuitCounts>,
    /// Queued records, filed under the recipient's tag only.
    pub(crate) message_queues: Arc<DashMap<IdTag, MessageQueue>>,
    /// Knock accounting (separate budget, caps, asker quota).
    pub(crate) knocks: Arc<knock_store::KnockStore>,
    /// Byte budget of the offline message store (knocks excluded).
    pub(crate) offline_budget: Arc<OfflineBudget>,
    /// Bytes waiting in all outbound queues together, and who holds them
    /// (R-17, H-1).
    pub(crate) outbound: Arc<limits::OutboundBudget>,
    /// Bytes held in all connections' WebSocket buffers (M-5).
    pub(crate) buffers: Arc<limits::BufferBudget>,
    /// Longest a writer may make no progress with a message to send
    /// (`limits::WRITER_STALL_TIMEOUT`; shorter in tests).
    pub(crate) writer_stall: Duration,
    /// Fixed keepalive ping interval for tests; None: `ping_wait`'s jitter.
    pub(crate) keepalive_ping_every: Option<Duration>,
    /// How long a ping may go unanswered once written (`PONG_TIMEOUT`;
    /// shorter in tests).
    pub(crate) pong_timeout: Duration,
    /// The --no-tls stand-in binding; None with TLS.
    pub(crate) dev_binding: Option<[u8; 32]>,
    /// The relay's long-term identity (spec §4.9).
    pub(crate) relay_identity: Arc<relay_identity::RelayIdentity>,
}

impl RelayState {
    pub(crate) fn new(config: Arc<ServerConfig>) -> Self {
        let knocks = Arc::new(knock_store::KnockStore::new(
            config.offline_queue.knock_budget_bytes,
        ));
        let offline_budget = Arc::new(OfflineBudget::new(
            config.offline_queue_max_total_bytes,
            config.offline_queue_max_bytes_per_recipient,
        ));
        let outbound = limits::OutboundBudget::new(config.outbound_budget_bytes);
        let buffers = limits::BufferBudget::new(config.buffer_budget_bytes);
        Self {
            config,
            connections: Arc::new(DashMap::new()),
            circuits: Arc::new(DashMap::new()),
            identity_to_client: Arc::new(DashMap::new()),
            identity_pair_circuits: Arc::new(DashMap::new()),
            blind_pair_circuits: Arc::new(DashMap::new()),
            departed_blind: Arc::new(DashMap::new()),
            pending_asks: Arc::new(fair_share::PendingAsks::default()),
            circuit_counts: Arc::new(fair_share::CircuitCounts::default()),
            message_queues: Arc::new(DashMap::new()),
            knocks,
            offline_budget,
            outbound,
            writer_stall: limits::WRITER_STALL_TIMEOUT,
            keepalive_ping_every: None,
            pong_timeout: PONG_TIMEOUT,
            buffers,
            dev_binding: None,
            relay_identity: Arc::new(relay_identity::RelayIdentity::ephemeral()),
        }
    }
}

/// A live pair. Side a is the earlier asker (the initiator). No identities,
/// no ephemeral keys (spec §5.2).
#[derive(Clone)]
pub(crate) struct CircuitPairInfo {
    circuit_id_a: CircuitId,
    circuit_id_b: CircuitId,
    token_a: CircuitToken,
    token_b: CircuitToken,
    /// Tag of the identity on side a.
    slot_a: IdTag,
    /// Tag of the identity on side b, and each side's source at creation:
    /// what `circuit_counts` charged for this pair (R-3).
    slot_b: IdTag,
    source_a: Option<SourceKey>,
    source_b: Option<SourceKey>,
    /// When both members were last seen gone (pair lifecycle).
    orphaned_since: Option<Instant>,
    /// When the sweep first saw a member online (mapped to a live, proven
    /// connection) whose slot still names a dead connection (M-1).
    unresumed_since: Option<Instant>,
    /// When the pair was created (M-3: a full table evicts the heaviest
    /// source's newest pair).
    created_at: Instant,
}

/// A live pair from a blinded match (protocol v3 §C.2). Side a is the
/// earlier asker (the initiator). The row is keyed by the token's
/// `BlindTag` and holds the two connection slots and their circuit ids
/// only: no identity, no `IdTag`, no `PairTag`. A blinded pair is never
/// resumed, so its slots never change.
#[derive(Clone)]
pub(crate) struct BlindPairInfo {
    circuit_id_a: CircuitId,
    circuit_id_b: CircuitId,
    /// The connection of side a (owner of `circuit_id_a`) and of side b.
    conn_a: ClientId,
    conn_b: ClientId,
    /// Each side's source at creation (fair shares, R-3).
    source_a: Option<SourceKey>,
    source_b: Option<SourceKey>,
    /// As in `CircuitPairInfo`: the orphan and unresumed clocks.
    orphaned_since: Option<Instant>,
    unresumed_since: Option<Instant>,
    created_at: Instant,
}

/// Which pair row a circuit belongs to: an identity pair (`PairTag`) or a
/// blinded one (`BlindTag`). Never logged.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PairKey {
    Identity(PairTag),
    Blind(BlindTag),
}

#[cfg(test)]
impl PairKey {
    /// The tag's bytes, for tests that scan relay state.
    pub(crate) fn raw(&self) -> [u8; 32] {
        match self {
            PairKey::Identity(p) => p.0,
            PairKey::Blind(b) => b.0,
        }
    }
}

impl std::fmt::Debug for PairKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairKey(..)")
    }
}

/// Routing for one circuit id: `client_a` owns it (received it in
/// `CircuitCreatedV3`), `client_b` is the other member. The tags name each
/// member's identity for its offline queue and for a member that is back
/// on a new connection; blinded circuits carry them too (see
/// `circuits::handle_circuit_ask_blind`).
#[derive(Clone)]
pub(crate) struct CircuitRoutingInfo {
    client_a: ClientId,
    client_b: ClientId,
    tag_a: IdTag,
    tag_b: IdTag,
    token_a: CircuitToken,
    token_b: CircuitToken,
    pair: PairKey,
    /// The pair's other routing entry (the circuit id `client_b` owns), so
    /// forwarding never scans a connection's circuits (R-11).
    peer_circuit: CircuitId,
}

/// Circuit info sent to clients
#[derive(Clone)]
#[allow(dead_code)]
struct ClientCircuitInfo {
    /// The circuit ID for this client
    circuit_id: CircuitId,
    /// The token for authentication
    token: CircuitToken,
    /// The other client's circuit ID (may be same in simple implementation)
    target_circuit_id: CircuitId,
    /// The other client's ID
    target_client_id: ClientId,
}

/// A unified connection handling both signaling and relay
#[allow(dead_code)]
pub(crate) struct UnifiedConnection {
    client_id: ClientId,
    _addr: SocketAddr,
    /// Bounded outbound queue (see `limits::ConnTx` for the full-queue policy)
    ws_tx: ConnTx,
    key_bundle: Option<KeyBundle>,
    /// The client's identity key (set when key bundle is published)
    identity_key: Option<String>,
    last_activity: Instant,
    /// Circuits this client is part of (circuit_id -> ClientCircuitInfo)
    circuits: Arc<DashMap<CircuitId, ClientCircuitInfo>>,
    /// Last time a pong was received from the client
    last_pong: Instant,
    /// Pending ping timestamp (waiting for pong)
    pending_ping: Option<Instant>,
    /// Proved an identity with an authenticated publish; anonymous
    /// connections are closed after `identification_timeout_secs`.
    identified: bool,
    /// Circuits this connection created (its own side), established or
    /// parked. Pruned lazily against `circuits`; bounded by
    /// `max_circuits_per_connection`.
    created_circuits: std::collections::HashSet<CircuitId>,
    /// Offline targets (or, for blinded asks, token tags) this connection
    /// parked state for, with the time it did so; bounded by
    /// `max_pending_per_connection` (identity targets) plus
    /// `pending_blind_per_connection()` (tokens) within
    /// `PENDING_CHARGE_WINDOW`.
    pending_charges: std::collections::VecDeque<(ChargeKey, Instant)>,
    /// 2 after a v2 hello; 0 before. Publishes need 2.
    protocol_version: u32,
    /// Unused connection-auth nonce (from hello, or the last
    /// `next_challenge`). Consumed by a successful publish.
    auth_nonce: Option<[u8; 32]>,
    /// TLS exporter for this connection, or the `--no-tls` origin hash.
    channel_binding: [u8; 32],
    /// The identity this connection proved; set once, never changed (R7).
    proven_identity: Option<[u8; 32]>,
    /// Refused (failed publish or unsupported hello): the read loop handles
    /// no further frame from this connection and closes it.
    closing: bool,
    /// Hello/publish signature work left for this connection (R-5).
    auth_budget: limits::AuthBudget,
    /// Keyed source-address bucket (IPv4 address or IPv6 /48) for the
    /// per-source fair shares (R-2, R-3); `None` when per-source accounting
    /// is off (`max_connections_per_ip = 0` without `proxy_protocol`: behind
    /// a front end every connection has the front end's address).
    source: Option<SourceKey>,
    /// Sent a circuit ask (blind or identity) since its publish (final
    /// review L1). A background drain connection publishes, reads its
    /// queue and leaves without ever asking; only a connection that asks is
    /// the member's foreground connection. Until then the member counts as
    /// offline for its blinded rows (R21, R18 and the sweep's 0 s grace
    /// wait for the first ask; packets for it are queued and acknowledged),
    /// and records salvaged or re-queued for it wait in its queue (L5).
    /// Set once, never cleared.
    has_asked: bool,
    /// Bucket for blind asks under pair tokens this connection holds no
    /// charge for (final re-review N-1 (a)); made on the first such ask
    /// from `blind_ask_burst` and `blind_ask_refill_per_sec`.
    blind_ask_bucket: Option<limits::AskBucket>,
    /// The verified bundle as asks carry it, shared by every pending ask of
    /// this connection (final re-review N-2) instead of a copy in each.
    /// Made on the first ask after a publish; cleared by a publish.
    peer_bundle: Option<Arc<PeerBundle>>,
}

/// (pin, version) of the identity at `path`. A missing key is an error
/// (round-2 L1): `--init-relay-identity` creates it.
pub fn relay_identity_load(path: &Path) -> anyhow::Result<(String, u32)> {
    let id = relay_identity::RelayIdentity::load(path)?;
    Ok((id.pin(), id.version()))
}

/// The decoy seed derived from the identity at `path` (must exist) and
/// `host` (final review M2: the same seed the built-in page uses).
pub fn relay_identity_decoy_seed(path: &Path, host: Option<&str>) -> anyhow::Result<[u8; 32]> {
    Ok(relay_identity::RelayIdentity::load(path)?.decoy_seed(host))
}

/// `--init-relay-identity`: create the key once.
pub fn relay_identity_init(path: &Path) -> anyhow::Result<(String, u32)> {
    let id = relay_identity::RelayIdentity::create(path)?;
    Ok((id.pin(), id.version()))
}

/// `--rotate-relay-identity`: rotate and return the new (pin, version).
pub fn relay_identity_rotate(path: &Path) -> anyhow::Result<(String, u32)> {
    let id = relay_identity::RelayIdentity::rotate(path)?;
    Ok((id.pin(), id.version()))
}

impl Server {
    /// Create a new unified server. TLS is set up before the listener binds;
    /// a TLS or queue-persistence configuration that cannot be used is a
    /// startup error (there is no plaintext fallback).
    pub async fn new(config: ServerConfig) -> anyhow::Result<Self> {
        Self::new_with_persist_env(config, &persist::RealEnv).await
    }

    /// As `new`, with an injectable environment for the persistence checks.
    pub(crate) async fn new_with_persist_env(
        config: ServerConfig,
        env: &dyn persist::PathEnv,
    ) -> anyhow::Result<Self> {
        let dev_binding = config.dev_binding()?;
        // `main` always sets the path; a `Server` built directly (tests) with
        // no path gets an in-memory identity and never writes a key file.
        let relay_identity = match config.relay_identity_path.as_deref() {
            Some(path) => relay_identity::RelayIdentity::load_or_create(Path::new(path))?,
            None => relay_identity::RelayIdentity::ephemeral(),
        };
        info!(
            "Relay identity: {} (version {})",
            relay_identity.pin(),
            relay_identity.version()
        );
        let tls_front = TlsFront::from_config(&config).await?;

        let listener = TcpListener::bind(config.bind_addr).await?;

        let config = Arc::new(config);

        if tls_front.is_some() {
            info!(
                "WebSocket server listening on {} (TLS 1.3)",
                config.bind_addr
            );
        } else {
            warn!(
                "WebSocket server listening on {} in PLAINTEXT (--no-tls)",
                config.bind_addr
            );
        }

        let decoy_config = DecoyConfig::from_settings(
            &config.decoy,
            &config.websocket_path,
            relay_identity.decoy_seed(config.decoy_host().as_deref()),
        )?;
        // Only meaningful where the listener faces the network (TLS); the
        // --no-tls dev/proxy mode is loopback-only.
        if config.websocket_path == "/" && tls_front.is_some() {
            warn!(
                "websocket_path is the default \"/\": this offers no protection against active probing; \
                 set a long random path (and put it in clients' server URL)"
            );
        }

        let conn_limiter = ConnectionLimiter::new(
            config.max_connections,
            config.max_connections_per_ip,
            config.max_connections_per_ipv6_48,
        );
        info!(
            "Limits: max_connections={}, max_connections_per_ip={}, rate_limit_bps={}, max_message_bytes={}, connection_timeout_secs={}",
            config.max_connections,
            config.max_connections_per_ip,
            config.rate_limit_bps,
            config.max_message_bytes,
            config.connection_timeout_secs
        );

        let state = RelayState {
            dev_binding,
            relay_identity: Arc::new(relay_identity),
            ..RelayState::new(config)
        };
        // Before the listener accepts anything: restores the tag key so
        // restored queues stay reachable (spec §5.5).
        let persist = persist::open_at_startup(&state, env)?;

        Ok(Self {
            state,
            listener,
            tls_front,
            decoy_config,
            conn_limiter,
            persist,
        })
    }

    /// A handle that saves the offline queue (None when persistence is off).
    pub(crate) fn queue_saver(&self) -> Option<persist::QueueSaver> {
        self.persist.as_ref().map(|ctx| persist::QueueSaver {
            state: self.state.clone(),
            ctx: ctx.clone(),
        })
    }

    /// Shared state handle (tests inspect the maps through it).
    #[allow(dead_code)]
    pub(crate) fn state(&self) -> RelayState {
        self.state.clone()
    }

    /// Run the server
    pub async fn run(self) -> anyhow::Result<()> {
        let state = self.state.clone();
        let decoy_config = self.decoy_config.clone();

        // Start cleanup task
        self.start_cleanup_task();
        if let Some(saver) = self.queue_saver() {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let s = saver.clone();
                    match tokio::task::spawn_blocking(move || s.save_now()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => warn!("Saving the encrypted offline queue failed: {:#}", e),
                        Err(_) => warn!("Saving the encrypted offline queue did not complete"),
                    }
                }
            });
        }

        let tls_front = self.tls_front.clone();
        let proxy_protocol = state.config.proxy_protocol;

        loop {
            match self.listener.accept().await {
                Ok((mut stream, addr)) => {
                    // PROXY v2 is accepted only from a front end on this
                    // host; anyone else could name any source they like.
                    if proxy_protocol && !proxy_peer_allowed(addr) {
                        metrics::reject(metrics::REJECT_PROXY_NOT_LOOPBACK);
                        warn!(
                            "Refused a connection: proxy_protocol is on and the peer is not on \
                             loopback"
                        );
                        drop(stream);
                        continue;
                    }
                    // Admission control before any TLS/HTTP work. The permit
                    // is held by the connection task and released when it ends.
                    let permit = match self.conn_limiter.try_acquire(addr.ip()) {
                        Ok(permit) => permit,
                        Err(reason) => {
                            let label = match reason {
                                ConnRejection::MaxConnections => metrics::REJECT_MAX_CONNECTIONS,
                                ConnRejection::PerIpCap => metrics::REJECT_PER_IP_CAP,
                                ConnRejection::PerPrefixCap => metrics::REJECT_PER_PREFIX_CAP,
                            };
                            metrics::reject(label);
                            debug!("Refusing connection: {}", label);
                            drop(stream);
                            continue;
                        }
                    };
                    let state = state.clone();
                    let decoy_config = decoy_config.clone();
                    let tls_front = tls_front.clone();
                    let limiter = self.conn_limiter.clone();

                    let task = async move {
                        let _permit = permit;
                        // The client's address from the front end's PROXY
                        // v2 header (LOCAL/UNSPEC: the peer's), read from
                        // the raw TCP stream before TLS. Fair shares only.
                        let proxied = if proxy_protocol {
                            match crate::proxy_protocol::read_header(
                                &mut stream,
                                crate::proxy_protocol::HEADER_TIMEOUT,
                            )
                            .await
                            {
                                Ok(source) => Some(source.unwrap_or(addr.ip())),
                                Err(e) => {
                                    metrics::reject(metrics::REJECT_PROXY_HEADER);
                                    debug!("Refused a connection: {}", e);
                                    return;
                                }
                            }
                        } else {
                            None
                        };
                        if let Some(front) = tls_front {
                            // TLS 1.3 (handshake bounded by tls_handshake_timeout_secs)
                            match front.accept(stream).await {
                                Ok(Accepted::Traffic(tls_stream)) => {
                                    let binding = match crate::tls::channel_binding(&tls_stream) {
                                        Ok(binding) => binding,
                                        Err(e) => {
                                            debug!("No TLS exporter for connection: {:#}", e);
                                            return;
                                        }
                                    };
                                    if let Err(e) = handle_connection(
                                        tls_stream,
                                        addr,
                                        proxied,
                                        state,
                                        decoy_config.clone(),
                                        binding,
                                        limiter,
                                    )
                                    .await
                                    {
                                        debug!(
                                            "TLS connection error from {}: {}",
                                            privacy::peer(&addr),
                                            e
                                        );
                                    }
                                }
                                Ok(Accepted::ChallengeAnswered) => {
                                    // ACME TLS-ALPN-01 validation; nothing more to do.
                                    trace!("ACME validation handshake answered");
                                }
                                Err(e) => {
                                    // Scanners and probes fail handshakes constantly;
                                    // keep this out of the default log level.
                                    debug!("TLS handshake failed: {:#}", e);
                                }
                            }
                            return;
                        }

                        // Plaintext: only with the explicit, dev-only --no-tls
                        let Some(binding) = state.dev_binding else {
                            return;
                        };
                        if let Err(e) = handle_connection(
                            stream,
                            addr,
                            proxied,
                            state,
                            decoy_config,
                            binding,
                            limiter,
                        )
                        .await
                        {
                            debug!("Connection error from {}: {}", privacy::peer(&addr), e);
                        }
                    };
                    // S-5: a panic in one connection's task ends only that
                    // connection. `ConnectionCleanup` has already removed its
                    // relay state while unwinding; the payload is never
                    // logged (it can carry values).
                    tokio::spawn(async move {
                        if AssertUnwindSafe(task).catch_unwind().await.is_err() {
                            metrics::reject(metrics::REJECT_TASK_PANIC);
                            error!("A connection task panicked; that connection was closed");
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                    // Typically EMFILE/ENFILE: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Address the listener is bound to (useful when binding port 0).
    #[allow(dead_code)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Get connection count
    #[allow(dead_code)]
    pub fn connection_count(&self) -> usize {
        self.state.connections.len()
    }

    /// Start cleanup task for idle connections and expired offline messages.
    ///
    /// Each connection's read loop enforces `connection_timeout_secs` itself;
    /// this sweep is a backstop for a task that is wedged. It only *signals*
    /// the connection to close - the connection task owns removal from the
    /// maps, so the socket is really closed and gauges stay consistent.
    fn start_cleanup_task(&self) {
        let state = self.state.clone();
        let timeout = self
            .state
            .config
            .connection_timeout()
            .saturating_add(Duration::from_secs(30));

        tokio::spawn(async move {
            let connections = &state.connections;
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                // L-3: a panic here must not end the sweep for good (state
                // would then grow without bound); it is logged and the next
                // round runs as usual.
                supervised_round("state sweep", || {
                    let now = Instant::now();
                    for entry in connections.iter() {
                        if now.duration_since(entry.value().last_activity) > timeout {
                            entry.value().ws_tx.kill();
                            debug!("Closing idle client {}", privacy::tag(entry.key().as_ref()));
                        }
                    }
                    sweep_stale_state(now, &state);
                });
            }
        });
    }
}

/// A stream wrapper that prepends already-read bytes before delegating to the underlying stream.
/// Used for peeking at TCP data to detect plain HTTP requests before WebSocket upgrade.
/// It also counts the bytes the underlying stream accepted for writing, so
/// the connection's writer can tell a slow peer from one that stopped
/// reading (H-1), and charges the bytes read to the connection's buffer
/// meter (M-5).
struct PeekStream<S> {
    buffer: Vec<u8>,
    position: usize,
    stream: S,
    written: Arc<WriteProgress>,
    meter: Arc<limits::BufferMeter>,
}

/// Bytes the socket has accepted from a connection's writer (the writer's
/// stall check), and when the writer last finished writing a keepalive
/// ping (the pong timeout counts from there, not from when the ping was
/// queued: a ping waiting behind a large frame that the peer is still
/// reading slowly has not gone unanswered; debug-voice-loss).
pub(crate) struct WriteProgress {
    bytes: AtomicU64,
    base: Instant,
    /// Milliseconds after `base` (rounded up) at which the last ping was
    /// written; 0: none yet.
    ping_written_ms: AtomicU64,
}

impl WriteProgress {
    fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            base: Instant::now(),
            ping_written_ms: AtomicU64::new(0),
        }
    }

    fn wrote(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn ping_written(&self) {
        let ms = self.base.elapsed().as_millis() as u64 + 1;
        self.ping_written_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// When the writer last finished writing a ping, if ever.
    fn last_ping_written(&self) -> Option<Instant> {
        match self.ping_written_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(self.base + Duration::from_millis(ms)),
        }
    }
}

/// Whether `msg` is a keepalive ping (the relay's own; pongs answer the
/// client's pings and start no timer).
fn is_keepalive_ping(msg: &Message) -> bool {
    use crate::protocol::unified::FRAME_TYPE_KEEPALIVE;
    matches!(msg, Message::Binary(b) if b.first() == Some(&FRAME_TYPE_KEEPALIVE))
        && matches!(
            UnifiedFrame::decode(msg),
            Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Ping { .. }))
        )
}

impl<S> PeekStream<S> {
    fn new(
        buffer: Vec<u8>,
        stream: S,
        written: Arc<WriteProgress>,
        meter: Arc<limits::BufferMeter>,
    ) -> Self {
        Self {
            buffer,
            position: 0,
            stream,
            written,
            meter,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.position < self.buffer.len() {
            let remaining = self.buffer.len() - self.position;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.buffer[self.position..self.position + to_copy]);
            self.position += to_copy;
            // Return immediately after serving buffered bytes; do not try to
            // fill the rest of the buffer from the underlying stream here.
            // The caller will call poll_read again if it needs more data.
            self.meter.read(to_copy);
            Poll::Ready(Ok(()))
        } else {
            let before = buf.filled().len();
            let res = Pin::new(&mut self.stream).poll_read(cx, buf);
            if res.is_ready() {
                self.meter.read(buf.filled().len().saturating_sub(before));
            }
            res
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.written.wrote(n);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Whether `peer` may send a PROXY v2 header: only a front end on this
/// host. `to_canonical`: a front end reaching a dual-stack `[::]` bind over
/// IPv4 shows up as `::ffff:127.0.0.1`, which is loopback too.
fn proxy_peer_allowed(peer: SocketAddr) -> bool {
    peer.ip().to_canonical().is_loopback()
}

/// The source bucket of a connection from `peer`: with `proxy_protocol`,
/// the address its PROXY v2 header named (`proxied`, already resolved to
/// the peer for LOCAL/UNSPEC); else the peer's own address while
/// per-address limits are on; else none (behind a front end without PROXY
/// v2 every peer looks the same).
fn connection_source(
    peer: SocketAddr,
    proxied: Option<std::net::IpAddr>,
    config: &ServerConfig,
    limiter: &ConnectionLimiter,
) -> Option<SourceKey> {
    if config.proxy_protocol {
        if let Some(client) = proxied {
            return Some(limiter.source_key(client));
        }
    }
    (config.max_connections_per_ip > 0).then(|| limiter.source_key(peer.ip()))
}

/// Run one round of a relay-wide background task. A panic is caught,
/// counted and logged (without its payload, which can carry values), and
/// the task goes on with its next round instead of ending silently (L-3).
/// Returns whether the round completed.
fn supervised_round(task: &'static str, round: impl FnOnce()) -> bool {
    match std::panic::catch_unwind(AssertUnwindSafe(round)) {
        Ok(()) => true,
        Err(_) => {
            metrics::reject(metrics::REJECT_TASK_PANIC);
            error!(
                "Background task '{}' panicked; it runs again next round",
                task
            );
            false
        }
    }
}

/// Wait before the next keepalive ping: 25-35 s (spec 5.7, D19).
pub(crate) fn ping_wait(r: f64) -> Duration {
    Duration::from_millis(25_000 + (r.clamp(0.0, 1.0) * 10_000.0).round() as u64)
}

/// The client always sends a resume field; all-zero means none (spec 5.7).
pub(crate) fn normalize_resume(resume: Option<CircuitId>) -> Option<CircuitId> {
    resume.filter(|c| c.0 != [0u8; 16])
}

/// Periodic sweep of client-creatable state: pending asks older than
/// `ASK_TTL` (540 s) or whose asker is gone, and pairs orphaned for longer
/// than `PAIR_ORPHAN_TTL` (540 s) or whose routing entries are gone; and
/// queued records past their TTL (`expire_queues`).
fn sweep_stale_state(now: Instant, state: &RelayState) {
    // Snapshot liveness first so no map guard is held while another map is
    // locked (no lock-order inversions with the connection handlers).
    let live: std::collections::HashSet<ClientId> =
        state.connections.iter().map(|e| *e.key()).collect();
    prune_pending_charges(now, state);
    expire_queues(crate::protocol::timestamp(), state);
    state.knocks.prune_quota(now);
    let asks = circuits::sweep_asks(now, &live, state);
    let pairs = circuits::sweep_pairs(now, &live, state);
    if asks + pairs > 0 {
        debug!("Swept {} stale asks and {} orphaned pairs", asks, pairs);
    }
}

/// Text of the `RateLimited` refusal of an ask over a pending-ask cap.
/// Never starts with `rchat_core::protocol::OFFLINE_QUEUE_FULL_PREFIX`, so
/// the core takes it as an ask refusal (final re-review N-3).
pub(crate) const PENDING_REFUSAL_TEXT: &str = "Too many pending circuit requests; try again later";
/// Text of the `RateLimited` refusal of a matching ask over a circuit cap.
pub(crate) const CIRCUIT_REFUSAL_TEXT: &str = "Too many circuits; try again later";

/// Refuse a new pending `CircuitAsk`: over the connection's
/// `max_pending_per_connection`, over its source's `max_pending_per_source`,
/// or with the table (`max_pending_circuit_targets`) full and no heavier
/// source to evict from (the heaviest source's oldest ask is evicted
/// instead when there is one, see `PendingAsks::admit`).
async fn refuse_pending_target(
    client_id: ClientId,
    connections: &DashMap<ClientId, UnifiedConnection>,
) {
    metrics::reject(metrics::REJECT_PENDING_TARGETS);
    debug!("Pending circuit target cap reached; refusing request");
    let err = FrameBuilder::error(ControlErrorCode::RateLimited, PENDING_REFUSAL_TEXT);
    let _ = send_frame(client_id, err, connections).await;
}

/// Window over which `max_pending_per_connection` is counted; equals
/// `circuits::ASK_TTL` (540 s) so, with the 60 s sweep, no charge outlives
/// 600 s (M8).
const PENDING_CHARGE_WINDOW: Duration = Duration::from_secs(540);

/// What a pending charge is for: an identity ask's target, or a blinded
/// ask's token tag (protocol v3 §C.2). Never logged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargeKey {
    Target(IdTag),
    Blind(BlindTag),
}

impl ChargeKey {
    fn is_blind(&self) -> bool {
        matches!(self, ChargeKey::Blind(_))
    }
}

#[cfg(test)]
impl ChargeKey {
    /// The tag's bytes, for tests that scan relay state.
    pub(crate) fn raw(&self) -> [u8; 32] {
        match self {
            ChargeKey::Target(t) => t.0,
            ChargeKey::Blind(b) => b.0,
        }
    }
}

/// Charge `client_id` for parking state for offline `target`. A target
/// already charged within the window is free (client retries); otherwise at
/// most `cap` distinct targets of `target`'s kind (identity targets, or
/// blind tokens) per window, and a new blind token also takes a token from
/// the connection's bucket (`rate`: burst, refill per second; final
/// re-review N-1 (a)).
fn charge_pending(
    connections: &DashMap<ClientId, UnifiedConnection>,
    client_id: ClientId,
    target: ChargeKey,
    cap: usize,
    rate: Option<(u32, u32)>,
) -> PendingCharge {
    let Some(mut conn) = connections.get_mut(&client_id) else {
        return PendingCharge::Refused;
    };
    let now = Instant::now();
    while conn
        .pending_charges
        .front()
        .is_some_and(|(_, at)| now.saturating_duration_since(*at) > PENDING_CHARGE_WINDOW)
    {
        conn.pending_charges.pop_front();
    }
    if conn.pending_charges.iter().any(|(t, _)| *t == target) {
        return PendingCharge::Existing;
    }
    // Identity and blind charges have separate caps (final review M1).
    let same_kind = conn
        .pending_charges
        .iter()
        .filter(|(t, _)| t.is_blind() == target.is_blind())
        .count();
    if same_kind >= cap {
        return PendingCharge::Refused;
    }
    if let Some((burst, per_sec)) = rate {
        let bucket = conn
            .blind_ask_bucket
            .get_or_insert_with(|| limits::AskBucket::new_at(burst, per_sec, now));
        if !bucket.try_take_at(now) {
            metrics::reject(metrics::REJECT_BLIND_ASK_RATE);
            return PendingCharge::Refused;
        }
    }
    conn.pending_charges.push_back((target, now));
    PendingCharge::New
}

/// Result of `charge_pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCharge {
    /// Already charged for this target within the window: free.
    Existing,
    /// Newly charged (undo with `uncharge_pending` if the ask is refused).
    New,
    /// Over `max_pending_per_connection`.
    Refused,
}

/// Undo a `PendingCharge::New` for `target` (the ask was refused later).
fn uncharge_pending(
    connections: &DashMap<ClientId, UnifiedConnection>,
    client_id: ClientId,
    target: ChargeKey,
) {
    if let Some(mut conn) = connections.get_mut(&client_id) {
        if conn
            .pending_charges
            .back()
            .is_some_and(|(t, _)| *t == target)
        {
            conn.pending_charges.pop_back();
        }
    }
}

/// Remove `client_id`'s charge for `target`, wherever it is in its list
/// (a replayed blind ask moved to another connection).
fn discharge_pending(
    connections: &DashMap<ClientId, UnifiedConnection>,
    client_id: ClientId,
    target: ChargeKey,
) {
    if let Some(mut conn) = connections.get_mut(&client_id) {
        conn.pending_charges.retain(|(t, _)| *t != target);
    }
}

/// M8: drop charges older than the window on every connection, so a
/// connected asker holds no target tag longer than ten minutes.
fn prune_pending_charges(now: Instant, state: &RelayState) {
    for mut conn in state.connections.iter_mut() {
        while conn
            .pending_charges
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) > PENDING_CHARGE_WINDOW)
        {
            conn.pending_charges.pop_front();
        }
    }
}

/// May a new circuit pair between `sides` be created? Global:
/// `max_circuits` routing entries. Per identity (both sides, whoever asked
/// first, across reconnects): `max_circuits_per_connection`. Per source:
/// `max_circuits_per_source` (R-3). Per connection: circuits `client_id`
/// created that still exist, below `max_circuits_per_connection`.
fn admit_circuit(state: &RelayState, client_id: ClientId, sides: [fair_share::Side; 2]) -> bool {
    let (connections, circuits, config) = (&state.connections, &state.circuits, &state.config);
    if !state.circuit_counts.admits(
        sides[0],
        sides[1],
        config.max_circuits_per_connection,
        config.circuits_per_source(),
    ) {
        return false;
    }
    if circuits.len() + 2 > config.max_circuits && !evict_for(state, sides) {
        return false;
    }
    // Snapshot, prune against `circuits` without holding the connection
    // guard, then write the pruned set back.
    let Some(ids) = connections
        .get(&client_id)
        .map(|c| c.created_circuits.iter().copied().collect::<Vec<_>>())
    else {
        return false;
    };
    let live: std::collections::HashSet<CircuitId> = ids
        .into_iter()
        .filter(|id| circuits.contains_key(id))
        .collect();
    let count = live.len();
    if let Some(mut conn) = connections.get_mut(&client_id) {
        conn.created_circuits.retain(|id| live.contains(id));
    }
    count < config.max_circuits_per_connection
}

/// The circuit table is full (M-3). If some source holds more circuit sides
/// than the heavier of `sides`' sources would after this pair, tear down
/// that source's newest pair and report whether there is room now.
/// Without a known source on either side there is nothing to compare, so
/// the pair is refused as before. O(pairs), only when the table is full.
fn evict_for(state: &RelayState, sides: [fair_share::Side; 2]) -> bool {
    let own = sides
        .iter()
        .filter_map(|s| s.source)
        .map(|s| {
            let wanted = sides.iter().filter(|x| x.source == Some(s)).count();
            state.circuit_counts.source(&s) + wanted
        })
        .max();
    let Some(own) = own else {
        return false;
    };
    let Some((victim, held)) = state.circuit_counts.heaviest_source() else {
        return false;
    };
    if held <= own {
        return false;
    }
    let of_victim =
        |a: Option<SourceKey>, b: Option<SourceKey>| a == Some(victim) || b == Some(victim);
    let newest_identity = state
        .identity_pair_circuits
        .iter()
        .filter(|p| of_victim(p.source_a, p.source_b))
        .max_by_key(|p| p.created_at)
        .map(|p| (p.created_at, PairKey::Identity(*p.key())));
    let newest_blind = state
        .blind_pair_circuits
        .iter()
        .filter(|p| of_victim(p.source_a, p.source_b))
        .max_by_key(|p| p.created_at)
        .map(|p| (p.created_at, PairKey::Blind(*p.key())));
    let newest = newest_identity
        .into_iter()
        .chain(newest_blind)
        .max_by_key(|(at, _)| *at)
        .map(|(_, key)| key);
    let Some(key) = newest else {
        return false;
    };
    // Never wait for another pair's lock while holding the caller's.
    let Some(_guard) = circuits::try_lock_pair(key) else {
        return false;
    };
    circuits::teardown_key(key, state, None);
    metrics::reject(metrics::REJECT_CIRCUIT_EVICTED);
    debug!("Circuit table full; evicted the heaviest source's newest pair");
    state.circuits.len() + 2 <= state.config.max_circuits
}

/// Remember that `client_id` created `circuit_id` (counts toward its cap).
fn record_created_circuit(
    connections: &DashMap<ClientId, UnifiedConnection>,
    client_id: ClientId,
    circuit_id: CircuitId,
) {
    if let Some(mut conn) = connections.get_mut(&client_id) {
        conn.created_circuits.insert(circuit_id);
    }
}

/// Refuse a matching `CircuitAsk` over a circuit cap.
async fn refuse_circuit(client_id: ClientId, connections: &DashMap<ClientId, UnifiedConnection>) {
    metrics::reject(metrics::REJECT_CIRCUIT_CAP);
    debug!("Circuit cap reached; refusing CircuitAsk");
    let err = FrameBuilder::error(ControlErrorCode::RateLimited, CIRCUIT_REFUSAL_TEXT);
    let _ = send_frame(client_id, err, connections).await;
}

/// How a writer's attempt to put one message on the wire ended.
#[derive(Debug, PartialEq, Eq)]
enum WriteOutcome {
    Sent,
    /// The socket write failed.
    Failed,
    /// The connection was told to close.
    Killed,
    /// No byte was accepted by the socket for `stall` (H-1).
    Stalled,
}

/// Write `msg`, giving up when the connection is killed or when `written`
/// (bytes the socket accepted) does not move for `stall`. Slow progress is
/// fine; no progress at all means the peer stopped reading.
async fn send_or_stall<Si>(
    sink: &mut Si,
    msg: Message,
    written: &AtomicU64,
    stall: Duration,
    kill: &CancellationToken,
) -> WriteOutcome
where
    Si: futures_util::Sink<Message> + Unpin,
    Si::Error: std::fmt::Display,
{
    let send = sink.send(msg);
    tokio::pin!(send);
    let check = (stall / 4).max(Duration::from_millis(10));
    let mut seen = written.load(Ordering::Relaxed);
    let mut since = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = kill.cancelled() => return WriteOutcome::Killed,
            res = &mut send => {
                return match res {
                    Ok(()) => WriteOutcome::Sent,
                    Err(e) => {
                        debug!("WebSocket send error: {}", e);
                        WriteOutcome::Failed
                    }
                };
            }
            _ = tokio::time::sleep(check) => {
                let now = written.load(Ordering::Relaxed);
                if now != seen {
                    seen = now;
                    since = tokio::time::Instant::now();
                } else if since.elapsed() >= stall {
                    return WriteOutcome::Stalled;
                }
            }
        }
    }
}

/// Close a connection whose pong is this late, counted from when its ping
/// was written (not queued).
const PONG_TIMEOUT: Duration = Duration::from_secs(60);

/// One keepalive round for `client_id`: close it if its last ping went
/// unanswered for `pong_timeout` after the writer wrote it (`ping_written`),
/// else send a ping if none is pending.
/// Returns false when the keepalive task should stop (the connection is
/// gone or has been told to close).
fn keepalive_tick(
    client_id: ClientId,
    connections: &DashMap<ClientId, UnifiedConnection>,
    now: Instant,
    pong_timeout: Duration,
    ping_written: Option<Instant>,
) -> bool {
    let Some(conn) = connections.get(&client_id) else {
        return false;
    };
    if let Some(ping_sent) = conn.pending_ping {
        // Counted from when the writer finished writing this ping, not
        // from when it was queued: a ping still waiting behind a large
        // frame that the peer is reading slowly has not gone unanswered.
        // Until it is written the writer is either making progress (the
        // peer is reading) or stalls, and the writer stall closes it.
        let Some(written) = ping_written.filter(|w| *w >= ping_sent) else {
            return true;
        };
        if now.saturating_duration_since(written) > pong_timeout {
            debug!("Keepalive timeout, disconnecting peer");
            // Close the connection; its task removes it from the maps.
            conn.ws_tx.kill();
            return false;
        }
        return true;
    }
    match conn.ws_tx.send(Frame::keepalive_ping().encode()) {
        Ok(()) => {}
        // N-1: the relay-wide budget is spent, usually by others (its
        // heaviest holder is already being shed). Not this peer's fault:
        // no ping is pending, so the next tick tries again.
        Err(limits::ConnSendError::Overloaded) => return true,
        // H-1: a full queue (the peer is not draining what it is sent;
        // `send` has already told it to close) or a closed connection.
        Err(_) => {
            debug!("Keepalive ping could not be queued; closing the connection");
            conn.ws_tx.kill();
            return false;
        }
    }
    drop(conn);
    if let Some(mut conn) = connections.get_mut(&client_id) {
        conn.pending_ping = Some(now);
    }
    true
}

/// Longest a refused connection waits for its error reply to be written
/// before it is killed.
const REFUSAL_FLUSH: Duration = Duration::from_millis(500);

/// One client connection, over TLS (production) or plaintext (`--no-tls`).
/// Both transports share this single code path.
async fn handle_connection<S>(
    mut stream: S,
    addr: SocketAddr,
    proxied: Option<std::net::IpAddr>,
    state: RelayState,
    decoy_config: DecoyConfig,
    channel_binding: [u8; 32],
    limiter: Arc<ConnectionLimiter>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connections = state.connections.clone();
    let _config = state.config.clone();
    debug!("New connection from {}", privacy::peer(&addr));

    // Peek at first bytes to detect plain HTTP requests (non-WebSocket)
    // Read until we have the complete HTTP headers (\r\n\r\n) to avoid
    // misidentifying a partial WebSocket upgrade as plain HTTP.
    let mut peek_buf = Vec::new();
    let mut temp_buf = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            debug!(
                "Read timeout from {} waiting for HTTP headers",
                privacy::peer(&addr)
            );
            return Ok(());
        }
        match tokio::time::timeout(timeout, stream.read(&mut temp_buf)).await {
            Ok(Ok(0)) => {
                if peek_buf.is_empty() {
                    debug!(
                        "Connection from {} closed immediately",
                        privacy::peer(&addr)
                    );
                    return Ok(());
                }
                break; // Connection closed after sending some data
            }
            Ok(Ok(n)) => {
                peek_buf.extend_from_slice(&temp_buf[..n]);
                if peek_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break; // Got complete HTTP headers
                }
                if !decoy::may_be_http_head(&peek_buf) {
                    break; // Not HTTP at all: answer 400 right away
                }
                if peek_buf.len() >= 8192 {
                    debug!("HTTP header limit exceeded from {}", privacy::peer(&addr));
                    break; // Safety limit
                }
            }
            Ok(Err(e)) => {
                debug!("Read error from {}: {}", privacy::peer(&addr), e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Read timeout from {}", privacy::peer(&addr));
                return Ok(());
            }
        }
    }

    // Check if this is a plain HTTP request (not WebSocket upgrade)
    if !decoy_config.is_relay_upgrade(&peek_buf) {
        // Enforced even with the decoy disabled: never reach the relay.
        decoy::serve_non_relay(&mut stream, &peek_buf, &decoy_config).await?;
        return Ok(());
    }

    // The source bucket for the per-source fair shares (R-2, R-3, M-2).
    let source = connection_source(addr, proxied, &state.config, &limiter);

    // Wrap stream with peeked bytes for WebSocket upgrade
    // Bounded outbound queue plus the kill switch for this connection
    let (ws_tx, mut ws_rx, kill) = ConnTx::channel_from(state.outbound.clone(), source);
    let written = Arc::new(WriteProgress::new());
    let meter = limits::BufferMeter::new(state.buffers.clone(), kill.clone(), source);
    let stream = PeekStream::new(peek_buf, stream, written.clone(), meter.clone());
    let keepalive_progress = written.clone();

    // Accept WebSocket with explicit size limits, bounded in time
    let ws_config = websocket_config(&_config);
    let ws_stream = match tokio::time::timeout(
        limits::WS_HANDSHAKE_TIMEOUT,
        accept_async_with_config(stream, Some(ws_config)),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            metrics::reject(metrics::REJECT_HANDSHAKE_TIMEOUT);
            debug!("WebSocket upgrade timed out");
            return Ok(());
        }
    };
    let client_id = ClientId::generate();
    // The HTTP upgrade is done; only WebSocket bytes count from here.
    meter.received(0);

    // Store connection
    let client_circuits = Arc::new(DashMap::new());
    let now = Instant::now();
    connections.insert(
        client_id,
        UnifiedConnection {
            client_id,
            _addr: addr,
            ws_tx: ws_tx.clone(),
            key_bundle: None,
            identity_key: None,
            last_activity: now,
            circuits: client_circuits,
            last_pong: now,
            pending_ping: None,
            identified: false,
            created_circuits: std::collections::HashSet::new(),
            pending_charges: std::collections::VecDeque::new(),
            protocol_version: 0,
            auth_nonce: None,
            channel_binding,
            proven_identity: None,
            closing: false,
            auth_budget: crate::limits::AuthBudget::new(Instant::now()),
            source,
            has_asked: false,
            blind_ask_bucket: None,
            peer_bundle: None,
        },
    );

    metrics::CONNECTIONS_TOTAL.inc();
    metrics::CONNECTIONS_CREATED.inc();
    // From here on the connection's relay state is removed however this
    // task ends, including a panic unwinding through it (S-5).
    let mut cleanup = ConnectionCleanup {
        client_id,
        state: state.clone(),
        kill: kill.clone(),
        armed: true,
        writer: None,
    };

    trace!("Client {} connected", privacy::tag(client_id.as_ref()));

    // Note: Offline messages are delivered when the client publishes their key bundle
    // This ensures we have their identity key for routing

    // Split WebSocket
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Spawn sender task. It stops when the queue closes or the connection is
    // killed - including while blocked writing to a peer that stopped reading.
    let writer_kill = kill.clone();
    let writer_meter = meter.clone();
    let stall = state.writer_stall;
    let writer_task = tokio::spawn(async move {
        let mut in_flight: Option<limits::Outbound> = None;
        loop {
            let (msg, budget) = tokio::select! {
                biased;
                _ = writer_kill.cancelled() => break,
                msg = ws_rx.recv() => match msg {
                    Some(msg) => msg,
                    None => break,
                },
            };
            // A Close frame is the last thing this connection sends: queued
            // after an error reply (`key_auth::close_with_error`), it ends
            // the connection once the error is on the wire.
            let closing = matches!(msg, Message::Close(_));
            writer_meter.sending(msg.len());
            // A relayed record (relay packet or `QueuedMessage`) was
            // acknowledged to its sender: keep a copy until it is fully
            // written, so a write that does not complete re-queues it.
            let copy = carries_relayed_record(&msg).then(|| msg.clone());
            let ping = is_keepalive_ping(&msg);
            // `budget` (the message's share of the queue byte budget) is
            // released when this iteration ends, i.e. after the write - or,
            // for a copy kept because the write did not complete, once
            // salvage has re-queued it (security review L-1).
            match send_or_stall(&mut ws_sender, msg, &written.bytes, stall, &writer_kill).await {
                WriteOutcome::Sent => {
                    if ping {
                        written.ping_written();
                    }
                }
                WriteOutcome::Failed | WriteOutcome::Killed => {
                    in_flight = copy.map(|c| (c, budget));
                    break;
                }
                WriteOutcome::Stalled => {
                    metrics::reject(metrics::REJECT_WRITER_STALL);
                    debug!("Peer stopped reading; closing the connection");
                    in_flight = copy.map(|c| (c, budget));
                    break;
                }
            }
            if closing {
                break;
            }
        }
        // Whatever ended the writer, the connection is done: make sure the
        // read loop ends too. Close politely only if the peer is draining.
        writer_kill.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), ws_sender.close()).await;
        // NOTE: Do NOT remove from connections here.
        // The main loop below handles cleanup including identity_to_client.
        // Removing here creates a race where identity_to_client gets stale.
        // The message whose write did not complete and the queue's unsent
        // remainder go back to the connection task, which re-queues
        // relayed records (R-10).
        WriterRest {
            in_flight,
            rx: ws_rx,
        }
    });
    // Held by the cleanup guard, so an early exit or a panic still
    // salvages the writer's unsent queue (L-6).
    cleanup.writer = Some(writer_task);

    // Spawn keepalive task for this client
    let keepalive_client_id = client_id;
    let keepalive_connections = connections.clone();
    let keepalive_kill = kill.clone();
    let (ping_every, pong_timeout) = (state.keepalive_ping_every, state.pong_timeout);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(ping_every.unwrap_or_else(|| ping_wait(rand::random::<f64>()))) => {}
                _ = keepalive_kill.cancelled() => break,
            }
            if !keepalive_tick(
                keepalive_client_id,
                &keepalive_connections,
                Instant::now(),
                pong_timeout,
                keepalive_progress.last_ping_written(),
            ) {
                break;
            }
        }

        trace!(
            "Keepalive task ended for client {}",
            privacy::tag(keepalive_client_id.as_ref())
        );
    });

    // Handle incoming messages
    let timeout = _config.connection_timeout();
    let identification_timeout = _config.identification_timeout();
    let connected_at = Instant::now();
    let poll_interval = timeout
        .min(identification_timeout)
        .min(Duration::from_secs(5));
    let mut bucket = TokenBucket::new(_config.rate_limit_bps, _config.rate_limit_burst_bytes());
    // Set when a handler refused this connection (spec §4.3).
    let mut refused = false;

    loop {
        // Idle timeout: no client message for `connection_timeout_secs`
        if let Some(conn) = connections.get(&client_id) {
            if Instant::now().duration_since(conn.last_activity) > timeout {
                metrics::reject(metrics::REJECT_IDLE_TIMEOUT);
                trace!("Connection {} timed out", privacy::tag(client_id.as_ref()));
                break;
            }
            // Anonymous upgraded sockets must not hold a slot for the whole
            // idle timeout: Hello or a key bundle within the window, or out.
            if !conn.identified && connected_at.elapsed() > identification_timeout {
                metrics::reject(metrics::REJECT_IDENTIFICATION_TIMEOUT);
                trace!(
                    "Connection {} did not identify in time",
                    privacy::tag(client_id.as_ref())
                );
                break;
            }
        }

        // Receive with timeout, or stop if the server closed this connection
        let next = tokio::select! {
            _ = kill.cancelled() => {
                debug!("Connection {} closed by server", privacy::tag(client_id.as_ref()));
                break;
            }
            next = tokio::time::timeout(poll_interval, ws_receiver.next()) => next,
        };

        // Inbound rate limit: every message is charged its size plus a fixed
        // per-message cost; see `limits::TokenBucket`.
        let charge = match &next {
            Ok(Some(Ok(m))) => {
                // Only a data message ends what the codec was buffering: a
                // Ping or Pong may arrive between the fragments of one, so
                // it must not reset the meter (N-2).
                if matches!(m, Message::Text(_) | Message::Binary(_)) {
                    meter.received(m.len());
                }
                Some(m.len() + limits::PER_MESSAGE_COST_BYTES)
            }
            _ => None,
        };

        match next {
            Ok(Some(Ok(Message::Text(text)))) => {
                // R-1: signaling is small; refuse an oversized frame before
                // any parsing and close the connection.
                if text.len() > limits::MAX_SIGNALING_BYTES {
                    metrics::reject(metrics::REJECT_OVERSIZED_FRAME);
                    debug!(
                        "Closing {}: signaling message exceeds {} bytes",
                        privacy::tag(client_id.as_ref()),
                        limits::MAX_SIGNALING_BYTES
                    );
                    break;
                }
                // Update activity
                if let Some(mut conn) = connections.get_mut(&client_id) {
                    conn.last_activity = Instant::now();
                }

                // Handle signaling message. The input text is dropped before
                // the handler awaits anything.
                let parsed = serde_json::from_str::<SignalingMessage>(&text);
                drop(text);
                match parsed {
                    Ok(msg) => {
                        trace!(
                            "Received signaling message from client={}",
                            privacy::tag(client_id.as_ref())
                        );
                        if let Err(e) = handle_signaling_message(client_id, msg, &state).await {
                            debug!("Signaling error: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse signaling message ({:?})", e.classify());
                    }
                }
            }
            Ok(Some(Ok(Message::Binary(bin)))) => {
                if bin.first() == Some(&crate::protocol::unified::FRAME_TYPE_SIGNALING)
                    && bin.len() - 1 > limits::MAX_SIGNALING_BYTES
                {
                    metrics::reject(metrics::REJECT_OVERSIZED_FRAME);
                    debug!(
                        "Closing {}: signaling frame exceeds {} bytes",
                        privacy::tag(client_id.as_ref()),
                        limits::MAX_SIGNALING_BYTES
                    );
                    break;
                }
                // Update activity
                if let Some(mut conn) = connections.get_mut(&client_id) {
                    conn.last_activity = Instant::now();
                }

                // Handle binary frame using unified protocol
                if !bin.is_empty() {
                    let frame_type = bin[0];
                    trace!(
                        "Received binary frame from {}: type=0x{:02x}",
                        privacy::tag(client_id.as_ref()),
                        frame_type
                    );

                    let msg = Message::Binary(bin);
                    let decoded = UnifiedFrame::decode(&msg);
                    drop(msg);
                    match decoded {
                        Ok(frame) => {
                            if let Err(e) = handle_frame(client_id, frame, &state).await {
                                debug!("Frame handling error: {}", e);
                            }
                        }
                        Err(FrameError::UnknownFrameType(_)) => {
                            // An unknown prefix (0x05 is reserved for future
                            // media, protocol v3 §9a) is refused and the
                            // connection closed; nothing reaches a handler.
                            metrics::reject(metrics::REJECT_UNKNOWN_FRAME);
                            debug!("Unknown frame type; closing");
                            if let Some(mut conn) = connections.get_mut(&client_id) {
                                conn.closing = true;
                                let _ = conn.ws_tx.send(Message::Close(None));
                            }
                        }
                        Err(e) => {
                            // PRIVACY: never log the frame bytes themselves.
                            debug!("Failed to decode frame: {}", e.kind());
                        }
                    }
                } else {
                    debug!("Received empty binary frame");
                }
            }
            Ok(Some(Ok(Message::Ping(data)))) => {
                let _ = ws_tx.send(Message::Pong(data));
            }
            Ok(Some(Ok(Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Close(_)))) => {
                trace!(
                    "Client {} closed connection",
                    privacy::tag(client_id.as_ref())
                );
                break;
            }
            Ok(Some(Ok(Message::Frame(_)))) => {}
            Ok(Some(Err(e))) => {
                if matches!(e, tokio_tungstenite::tungstenite::Error::Capacity(_)) {
                    metrics::reject(metrics::REJECT_OVERSIZED_FRAME);
                    debug!(
                        "Closing {}: message exceeds max_message_bytes",
                        privacy::tag(client_id.as_ref())
                    );
                } else {
                    debug!("WebSocket error: {}", e);
                }
                break;
            }
            Ok(None) => {
                debug!("WebSocket stream ended");
                break;
            }
            Err(_) => {
                // Timeout - continue to check
            }
        }

        // A refused connection is done: no frame after the refusal reaches
        // a handler, even one the client already pipelined.
        if connections.get(&client_id).is_some_and(|c| c.closing) {
            refused = true;
            break;
        }

        if let Some(cost) = charge {
            let wait = bucket.consume(cost);
            if !wait.is_zero() {
                metrics::reject(metrics::REJECT_RATE_LIMIT);
                trace!(
                    "Throttling {} for {:?}",
                    privacy::tag(client_id.as_ref()),
                    wait
                );
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = kill.cancelled() => break,
                }
            }
        }
    }

    // Stop the writer and keepalive tasks; the socket closes once both halves
    // drop. A refused connection is torn down first and killed after the
    // writer has flushed its error and Close (bounded, below).
    let proven = connections
        .get(&client_id)
        .and_then(|conn| conn.proven_identity);
    if !refused {
        kill.cancel();
    }
    let Some(mut writer) = cleanup.writer.take() else {
        cleanup.run();
        return Ok(());
    };
    cleanup.run();

    let mut unsent: Option<Result<WriterRest, tokio::task::JoinError>> = None;
    if refused {
        // No frame is handled any more and the relay state is already
        // cleaned up; give the writer a bounded moment to put the queued
        // error and Close on the wire, then kill the connection regardless.
        if let Ok(rx) = tokio::time::timeout(REFUSAL_FLUSH, &mut writer).await {
            unsent = Some(rx);
        }
        kill.cancel();
    }
    // R-10: messages acknowledged to their senders but still queued here
    // when the connection died go back to this identity's offline queue.
    if let Some(identity) = proven {
        let rx = match unsent {
            Some(rx) => Some(rx),
            None => tokio::time::timeout(WRITER_EXIT_WAIT, &mut writer)
                .await
                .ok(),
        };
        if let Some(Ok(rest)) = rx {
            salvage_unsent(rest.in_flight, rest.rx, id_tag(&identity), &state).await;
        }
    }

    trace!("Client {} disconnected", privacy::tag(client_id.as_ref()));

    Ok(())
}

/// How long a closing connection waits for its writer to stop (the writer
/// gives the peer at most 1 s for a polite Close) before giving up on
/// salvaging its unsent messages.
const WRITER_EXIT_WAIT: Duration = Duration::from_secs(2);

/// What a connection's writer hands back when it stops: the message it
/// was writing when the write failed, stalled or was cut off (None when
/// every write it started completed), and its queue's unsent remainder.
struct WriterRest {
    /// With its budget permit: the copy stays charged until salvaged.
    in_flight: Option<limits::Outbound>,
    rx: tokio::sync::mpsc::Receiver<limits::Outbound>,
}

/// Whether `msg` carries a relayed record that was acknowledged to its
/// sender (a relay packet, or a `QueuedMessage` from the offline queue or
/// a D34 hand-over): by its frame type byte only, so the writer pays no
/// decode for it. `salvage_unsent` decodes what it keeps.
fn carries_relayed_record(msg: &Message) -> bool {
    use crate::protocol::unified::{FRAME_TYPE_CONTROL, FRAME_TYPE_RELAY};
    matches!(msg, Message::Binary(b)
        if matches!(b.first(), Some(&FRAME_TYPE_RELAY) | Some(&FRAME_TYPE_CONTROL)))
}

/// The record `msg` carries for re-queueing, if any, stamped `enqueued_at`
/// (its first store time for a record from the offline queue, so its TTL
/// still runs from then; now for a live frame).
fn salvageable(msg: &Message, enqueued_at: u64) -> Option<StoredMessage> {
    let (payload, is_knock) = match UnifiedFrame::decode(msg) {
        Ok(UnifiedFrame::Relay(packet)) => (packet.payload, false),
        Ok(UnifiedFrame::Control(ControlMessage::QueuedMessage { payload })) => {
            // Knocks reach a recipient as `QueuedMessage` records too;
            // they are exactly `KNOCK_BYTES` of knock v3 (version byte
            // 0x03, §A.5). Delivery is the same either way; only the
            // accounting differs.
            let knock = payload.len() == validate::KNOCK_BYTES
                && payload.first() == Some(&validate::KNOCK_VERSION);
            (payload, knock)
        }
        _ => return None,
    };
    Some(StoredMessage {
        payload,
        enqueued_at_unix_secs: enqueued_at,
        is_knock,
        knock_seq: 0,
    })
}

/// Re-queue the relayed records a dead connection did not deliver (R-10):
/// first the one whose write did not complete (`in_flight`: the peer may
/// hold part of it, never all of it), then those left in its outbound
/// queue, in order. Relay packets were already acknowledged to their
/// senders and `QueuedMessage` records already taken from the offline
/// queue (drain on publish, D34 hand-over). They go to the front of
/// `tag`'s offline queue, older first, through the normal admission
/// (`requeue_salvaged`): the offline budget and the per-recipient caps
/// apply, and what does not fit is dropped (M-1). If the identity is
/// already back on another connection, they are handed to it at once
/// rather than waiting for its next publish. A copy may arrive twice (the
/// peer read a frame whose write the relay saw fail); the receiver drops
/// a repeated envelope id (D35). What the socket accepted in full and the
/// peer never read is beyond the relay's sight; the client's end-to-end
/// receipts still show it undelivered.
///
/// Post-marker window (final review L5). A record handed to the member's
/// other connection after that connection's `QueueHandedOver` marker can
/// be lost the same way if that connection is about to close: a background
/// drain ends on the marker (plus a short grace) and may never read what
/// follows. So records go at once only to a connection that has asked
/// (`is_foreground`, which drains never are); otherwise they wait in the
/// queue for the next publish or the foreground connection's first ask
/// (`note_first_ask`). What remains: a foreground connection that is
/// closing without the relay knowing yet (its Close not yet read) may
/// still be handed records it never reads, as above.
async fn salvage_unsent(
    in_flight: Option<limits::Outbound>,
    mut rx: tokio::sync::mpsc::Receiver<limits::Outbound>,
    tag: IdTag,
    state: &RelayState,
) {
    rx.close();
    let now = crate::protocol::timestamp();
    // Permits are held until the records are re-queued below.
    let mut permits = Vec::new();
    let mut msgs: Vec<StoredMessage> = Vec::new();
    for (msg, permit) in in_flight
        .into_iter()
        .chain(std::iter::from_fn(|| rx.try_recv().ok()))
    {
        msgs.extend(salvageable(&msg, permit.enqueued_at().unwrap_or(now)));
        permits.push(permit);
    }
    if msgs.is_empty() {
        return;
    }
    debug!(
        "Re-queueing {} unsent messages of a closed connection",
        msgs.len()
    );
    let guard = pair_lock::ID_LOCKS.lock(tag).await;
    let dropped = requeue_salvaged(tag, msgs, state);
    if dropped > 0 {
        debug!(
            "Dropped {} salvaged messages over the offline caps",
            dropped
        );
    }
    // Final review L5: handed over at once only to a connection that has
    // asked (`is_foreground`). A background drain may already have read
    // its `QueueHandedOver` marker and be closing: a record written to it
    // now could be accepted by its socket and never read. Otherwise the
    // records wait in the queue for the member's next publish or its
    // foreground connection's first ask.
    let live = state
        .identity_to_client
        .get(&tag)
        .map(|c| *c)
        .filter(|c| is_foreground(*c, state));
    let backlog = live.and_then(|_| take_offline_queue(tag, state));
    drop(guard);
    // Re-queued (or dropped by admission): their outbound share goes back.
    drop(permits);
    if let (Some(client), Some(queue)) = (live, backlog) {
        drain_offline_queue(client, tag, queue, state).await;
    }
}

/// Admit salvaged records (M-1) as if they were newly stored: messages
/// through `offline_budget.try_reserve` against `tag`'s queue (relay-wide
/// budget, per-recipient bytes and count), knocks through the knock store
/// (its budget and caps). Admitted messages go to the front of the queue,
/// older first. Returns how many records were dropped. Called under
/// `tag`'s `ID_LOCKS` guard.
///
/// The R26 steady-size sub-cap is weighed per record (final review L3) but
/// never refuses one here: every salvaged record was already acknowledged
/// to its sender (a relay packet) or taken from the queue (a stored
/// record), so a refusal would lose a message that may be real with no one
/// told; steady-sized cover and real messages look the same to the relay.
/// A record over the sub-cap is kept and counted
/// (`rchat_salvaged_over_steady_subcap_total`). The overshoot is bounded by
/// what one salvage can carry (one connection's outbound queue), the
/// queue's byte and count caps still apply to it, and while the queue is
/// over the sub-cap new steady-sized records are refused at
/// `store_offline` as before, so R26's purpose (cover cannot crowd real
/// messages out of a recipient's queue) holds for every record not yet
/// acknowledged.
fn requeue_salvaged(tag: IdTag, msgs: Vec<StoredMessage>, state: &RelayState) -> usize {
    let (mut bytes, mut count, mut steady_sized) = state
        .message_queues
        .get(&tag)
        .map(|q| (q.bytes, q.message_count(), q.steady_sized_count()))
        .unwrap_or((0, 0, 0));
    let mut admitted = Vec::new();
    let mut charged = 0usize;
    let mut dropped = 0usize;
    let mut over_sub_cap = 0u64;
    for m in msgs {
        if m.is_knock {
            state.knocks.enqueue(
                tag,
                None,
                m.payload,
                m.enqueued_at_unix_secs,
                &state.message_queues,
                knock_store::RESTORED_SOURCE,
            );
            continue;
        }
        let cost = m.budget_cost();
        match state.offline_budget.try_reserve(bytes, count, cost) {
            Ok(()) => {
                if !limits::steady_sized_admits(steady_sized, m.payload.len()) {
                    over_sub_cap += 1;
                }
                if m.payload.len() == limits::STEADY_SEALED_LEN {
                    steady_sized += 1;
                }
                bytes += cost;
                count += 1;
                charged += cost;
                admitted.push(m);
            }
            Err(_) => {
                metrics::reject(metrics::REJECT_QUEUE_OVERFLOW);
                dropped += 1;
            }
        }
    }
    if over_sub_cap > 0 {
        metrics::SALVAGED_OVER_STEADY_SUBCAP.inc_by(over_sub_cap);
        debug!(
            "Kept {} salvaged steady-sized records over the steady-size sub-cap",
            over_sub_cap
        );
    }
    if !admitted.is_empty() {
        state
            .knocks
            .requeue(tag, admitted, charged, &state.message_queues);
    }
    dropped
}

/// Removes one connection's relay state: its routing slot, its pending asks
/// and its connection record (pairs are only marked orphaned). Runs once,
/// explicitly at the end of `handle_connection`, or from `Drop` when the
/// task ends early - an error return or a panic unwinding through it - so
/// no map entry outlives the connection (S-5).
struct ConnectionCleanup {
    client_id: ClientId,
    state: RelayState,
    kill: CancellationToken,
    armed: bool,
    /// The writer task, which hands back its unsent queue when it stops.
    writer: Option<tokio::task::JoinHandle<WriterRest>>,
}

impl ConnectionCleanup {
    fn run(&mut self) {
        if !std::mem::take(&mut self.armed) {
            return;
        }
        let (client_id, state) = (self.client_id, &self.state);
        // Drop the routing slot only if it still points at this connection:
        // if the identity has already reconnected, the mapping is the new
        // one's.
        let proven = state
            .connections
            .get(&client_id)
            .and_then(|conn| conn.proven_identity);
        if let Some(identity) = proven {
            state
                .identity_to_client
                .remove_if(&id_tag(&identity), |_, mapped| *mapped == client_id);
        }
        if let Some((_, conn)) = state.connections.remove(&client_id) {
            // This connection's asks go with it. Pairs outlive a member's
            // socket (the peer's packets queue for it, and a reconnect may
            // resume); only the orphan sweep removes them.
            circuits::on_disconnect(client_id, &conn, state, Instant::now());
        }
        metrics::CONNECTIONS_TOTAL.dec();
        metrics::CONNECTIONS_CLOSED.inc();
    }
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        if self.armed {
            // Early exit: stop the writer and keepalive tasks too.
            self.kill.cancel();
            let proven = self
                .state
                .connections
                .get(&self.client_id)
                .and_then(|conn| conn.proven_identity);
            self.run();
            // L-6: relayed messages still queued were acknowledged to their
            // senders; re-queue them as the normal path does (R-10).
            let writer = self.writer.take();
            let runtime = tokio::runtime::Handle::try_current();
            if let (Some(identity), Some(writer), Ok(runtime)) = (proven, writer, runtime) {
                let state = self.state.clone();
                runtime.spawn(async move {
                    if let Ok(Ok(rest)) = tokio::time::timeout(WRITER_EXIT_WAIT, writer).await {
                        salvage_unsent(rest.in_flight, rest.rx, id_tag(&identity), &state).await;
                    }
                });
            }
        }
    }
}

/// Handle a unified frame
async fn handle_frame(
    client_id: ClientId,
    frame: UnifiedFrame,
    state: &RelayState,
) -> anyhow::Result<()> {
    match frame {
        UnifiedFrame::Signaling(msg) => handle_signaling_message(client_id, msg, state).await,
        UnifiedFrame::Relay(packet) => handle_relay_packet(client_id, packet, state).await,
        UnifiedFrame::Control(ctrl) => {
            handle_control_message(client_id, ctrl, state).await;
            Ok(())
        }
        UnifiedFrame::Keepalive(k) => handle_keepalive(client_id, k, &state.connections).await,
    }
}

/// Handle a signaling message
async fn handle_signaling_message(
    client_id: ClientId,
    mut msg: SignalingMessage,
    state: &RelayState,
) -> anyhow::Result<()> {
    let connections = &state.connections;
    let identity_to_client = &state.identity_to_client;
    let _config: &ServerConfig = &state.config;
    trace!(
        "Signaling message from {}",
        privacy::tag(client_id.as_ref())
    );

    // Validate timestamp
    if !validate_timestamp(msg.timestamp) {
        return Err(anyhow::anyhow!("Invalid timestamp"));
    }

    // R-5: hello (one signature) and publish (two verifications) are
    // budgeted per connection; over budget, the connection is closed before
    // any signature work.
    if msg.msg_type == MSG_TYPE_HELLO || msg.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE {
        let Some(mut conn) = connections.get_mut(&client_id) else {
            return Ok(());
        };
        if !conn.auth_budget.try_take(Instant::now()) {
            metrics::reject(metrics::REJECT_AUTH_RATE);
            debug!("Too many hello/publish messages; closing the connection");
            conn.closing = true;
            conn.auth_nonce = None;
            let reply = key_auth::error_signal(
                ErrorCode::RateLimited,
                "too many hello or publish messages",
            );
            key_auth::close_with_error(&conn.ws_tx, UnifiedFrame::signaling(reply).encode());
            return Ok(());
        }
    }

    // Validate identity material at the boundary. Refused with an error
    // reply that does not echo the input; nothing is stored.
    if let Err(reason) = validate::signaling(&msg) {
        debug!("Rejected signaling message: {}", reason);
        if msg.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE {
            // A malformed publish is a failed publish (spec §4.3).
            if let Some(mut conn) = connections.get_mut(&client_id) {
                key_auth::refuse_publish(&mut conn);
            }
            return Ok(());
        }
        let response = SignalingMessage::new(
            MSG_TYPE_ERROR,
            SignalingPayload::new(
                MSG_TYPE_ERROR,
                ErrorPayload {
                    code: ErrorCode::InvalidMessage,
                    message: reason.to_string(),
                    request_id: validate::safe_request_id(&msg.id),
                },
            ),
        );
        send_signaling(client_id, response, connections).await?;
        return Ok(());
    }

    let msg_type = std::mem::take(&mut msg.msg_type);
    match msg_type.as_str() {
        MSG_TYPE_HELLO => {
            let offered = msg
                .payload
                .deserialize_data::<HelloPayload>()
                .map(|h| h.supported_versions)
                .unwrap_or_default();
            if !offered.contains(&PROTOCOL_VERSION) {
                debug!("Hello without protocol v3; closing");
                if let Some(mut conn) = connections.get_mut(&client_id) {
                    conn.closing = true;
                    let reply = key_auth::error_signal(
                        ErrorCode::VersionMismatch,
                        "client too old; update rChat",
                    );
                    key_auth::close_with_error(
                        &conn.ws_tx,
                        UnifiedFrame::signaling(reply).encode(),
                    );
                }
                return Ok(());
            }
            let nonce = key_auth::new_nonce();
            let mut binding = [0u8; 32];
            if let Some(mut conn) = connections.get_mut(&client_id) {
                conn.protocol_version = PROTOCOL_VERSION;
                conn.auth_nonce = Some(nonce);
                binding = conn.channel_binding;
            }
            let relay_identity = state.relay_identity.hello_info(&binding, &nonce);
            let response = SignalingMessage::new(
                MSG_TYPE_HELLO_RESPONSE,
                SignalingPayload::new(
                    MSG_TYPE_HELLO_RESPONSE,
                    HelloResponsePayload {
                        selected_version: PROTOCOL_VERSION,
                        server_info: ServerInfo {
                            version: env!("CARGO_PKG_VERSION").to_string(),
                            capabilities: vec![
                                "websocket-relay".to_string(),
                                "tls1.3".to_string(),
                                "unified-protocol".to_string(),
                                "circuit-relay".to_string(),
                                "key-auth-v1".to_string(),
                                "sealed-relay-v1".to_string(),
                                "mutual-circuits-v1".to_string(),
                            ],
                        },
                        auth_challenge: Some(hex::encode(nonce)),
                        knock_ttl_hours: Some(key_auth::knock_ttl_hours(_config)),
                        relay_identity: Some(relay_identity),
                    },
                ),
            );
            send_signaling(client_id, response, connections).await?;
        }
        MSG_TYPE_PUBLISH_KEY_BUNDLE => {
            trace!(
                "Received PublishKeyBundle from {}",
                privacy::tag(client_id.as_ref())
            );
            let Ok(payload) = msg.payload.deserialize_data::<PublishKeyBundlePayload>() else {
                // An undecodable publish is a failed publish (spec §4.3).
                debug!("Undecodable key bundle publish; closing the connection");
                if let Some(mut conn) = connections.get_mut(&client_id) {
                    key_auth::refuse_publish(&mut conn);
                }
                return Ok(());
            };
            // Nothing of the client's input is held across the awaits below.
            drop(msg);
            // Every check runs before anything changes (spec §4.3).
            let checked = match connections.get(&client_id) {
                Some(conn) => key_auth::verify_publish(&conn, &payload),
                None => return Ok(()),
            };
            let verified = match checked {
                Ok(verified) => verified,
                Err(why) => {
                    debug!(
                        "Key authentication failed ({:?}); closing the connection",
                        why
                    );
                    if let Some(mut conn) = connections.get_mut(&client_id) {
                        key_auth::refuse_publish_for(&mut conn, why);
                    }
                    return Ok(());
                }
            };
            let tag = id_tag(&verified.identity);
            // The success branch is one critical section per identity tag
            // (R1, R4).
            let identity_guard = pair_lock::ID_LOCKS.lock(tag).await;
            let next_challenge = key_auth::new_nonce();
            if let Some(mut conn) = connections.get_mut(&client_id) {
                // Replacing the nonce consumes the one just used.
                conn.auth_nonce = Some(next_challenge);
                conn.key_bundle = Some(key_auth::key_bundle_hex(&verified.bundle));
                conn.peer_bundle = None;
                conn.proven_identity = Some(verified.identity);
                conn.identified = true;
                conn.identity_key = Some(hex::encode(verified.identity));
            }
            // The response goes first, before the routing slot exists: the
            // client handles non-signaling frames only once its publish is
            // accepted (round-2 L5), and the socket is ordered, so anything
            // routed here (a live knock) must follow it (R-9).
            let response = SignalingMessage::new(
                MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE,
                SignalingPayload::new(
                    MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE,
                    PublishKeyBundleResponsePayload {
                        status: Status::Ok,
                        bundle_id: Some(uuid::Uuid::new_v4().to_string()),
                        next_challenge: Some(hex::encode(next_challenge)),
                    },
                ),
            );
            send_signaling(client_id, response, connections).await?;
            // R1: the slot points only at a connection proven as this
            // identity. A connection never changes identity (R7), so a
            // re-publish overwrites its own mapping.
            identity_to_client.insert(tag, client_id);
            #[cfg(test)]
            tests_hook::after_identity_mapped(tag);
            trace!(
                "Client {} published its key bundle",
                privacy::tag(client_id.as_ref())
            );
            #[cfg(feature = "test-mitm")]
            mitm::mitm_after_publish(client_id, verified.identity, state);
            // R4: queued messages and knocks are taken for delivery only
            // here, under the identity guard. The (possibly slow) hand-over
            // runs after the guard is released, so a connection that stops
            // reading cannot hold the identity's lock (R-1).
            let backlog = take_offline_queue(tag, state);
            drop(identity_guard);
            if let Some(queue) = backlog {
                drain_offline_queue(client_id, tag, queue, state).await;
            }
            // R34a: the queue (possibly empty) is handed over. Same channel,
            // after every queued record, so a client that sees the marker has
            // read everything the queue held (a background drain ends on it).
            send_queue_handed_over(client_id, state).await;
            // R21's teardown of the member's departed blinded rows waits
            // for this connection's first ask (final review L1,
            // `note_first_ask`): a background drain publishes and never
            // asks, so it must not end rows it will never re-pair.
        }
        MSG_TYPE_LOOKUP_KEY_BUNDLE => {
            // Return not found for now
            let response = SignalingMessage::new(
                MSG_TYPE_LOOKUP_KEY_BUNDLE_RESPONSE,
                SignalingPayload::new(
                    MSG_TYPE_LOOKUP_KEY_BUNDLE_RESPONSE,
                    LookupKeyBundleResponsePayload {
                        status: Status::Error,
                        bundle: None,
                    },
                ),
            );

            send_signaling(client_id, response, connections).await?;
        }
        MSG_TYPE_CONNECTION_REQUEST => {
            let response = SignalingMessage::new(
                MSG_TYPE_ERROR,
                SignalingPayload::new(
                    MSG_TYPE_ERROR,
                    ErrorPayload {
                        code: ErrorCode::TargetOffline,
                        message: "Target is offline".to_string(),
                        request_id: validate::safe_request_id(&msg.id),
                    },
                ),
            );

            send_signaling(client_id, response, connections).await?;
        }
        MSG_TYPE_RELAY_REQUEST => {
            // In unified mode, relay is handled over the same WebSocket
            let response = SignalingMessage::new(
                MSG_TYPE_RELAY_RESPONSE,
                SignalingPayload::new(
                    MSG_TYPE_RELAY_RESPONSE,
                    RelayResponsePayload {
                        status: Status::Ok,
                        circuit_id: Some("websocket".to_string()),
                        relay_endpoint: Some("wss://same-host/relay".to_string()),
                        relay_token: None,
                        target_endpoint: None,
                        target_circuit_id: None,
                    },
                ),
            );

            send_signaling(client_id, response, connections).await?;
        }
        MSG_TYPE_PING => {
            let response = SignalingMessage::new(
                MSG_TYPE_PONG,
                SignalingPayload::new(
                    MSG_TYPE_PONG,
                    PongPayload {
                        server_time: crate::protocol::timestamp(),
                    },
                ),
            );

            send_signaling(client_id, response, connections).await?;
        }
        #[cfg(test)]
        "test_panic" => panic!("test-only panic in a connection task"),
        "debug_log" => {
            // PRIVACY: client-supplied debug text is accepted and discarded.
            // It is attacker-controlled (log injection / log flooding) and can
            // contain anything the client chose to put in it, including
            // plaintext or key material. It is never logged and never broadcast.
        }
        MSG_TYPE_ENCRYPTED_MESSAGE => {
            // SECURITY: Never broadcast ciphertext. This legacy signaling
            // fallback has no recipient field, so delivering it to every
            // connected client is a confidentiality breach. Real E2EE
            // traffic is circuit-relayed (binary relay packets) and must
            // stay that way.
            debug!("Rejecting legacy encrypted_message: no recipient, refusing to broadcast. Use circuit relay instead.");
            let response = SignalingMessage::new(
                MSG_TYPE_ERROR,
                SignalingPayload::new(
                    MSG_TYPE_ERROR,
                    ErrorPayload {
                        code: ErrorCode::InvalidMessage,
                        message: "encrypted_message is not supported; send via circuit relay"
                            .to_string(),
                        request_id: validate::safe_request_id(&msg.id),
                    },
                ),
            );
            send_signaling(client_id, response, connections).await?;
        }
        _ => {
            // SECURITY: Unknown message types must not fan out to every
            // client. Log and drop; do not broadcast.
            debug!("Ignoring unknown signaling message type (no broadcast)");
        }
    }

    Ok(())
}

/// Handle a relay packet
async fn handle_relay_packet(
    from: ClientId,
    packet: RelayPacket,
    state: &RelayState,
) -> anyhow::Result<()> {
    let connections = &state.connections;
    let circuits = &state.circuits;
    trace!(
        "Relay packet from {} for circuit {}",
        privacy::tag(from.as_ref()),
        privacy::tag(packet.circuit_id.as_ref())
    );

    // Look up circuit. Clone the routing entry so no map guard is held across
    // the awaits below.
    let routing = match circuits.get(&packet.circuit_id) {
        Some(r) => r.clone(),
        None => {
            debug!("Relay packet for unknown circuit");
            // Send error to client so they can recreate the circuit. It
            // names the circuit the client sent on (its own value, fixed
            // length), so the core can forget that circuit (re-review R-1).
            let error_msg = FrameBuilder::error(
                ControlErrorCode::CircuitNotFound,
                format!(
                    "{}{}",
                    rchat_core::protocol::CIRCUIT_NOT_FOUND_PREFIX,
                    hex::encode(packet.circuit_id.as_ref())
                ),
            );
            let _ = send_frame(from, error_msg, connections).await;
            return Err(anyhow::anyhow!("Unknown circuit"));
        }
    };

    // Determine the target connection and the tag its queue is filed under
    let (target_id, target_token, target_tag) = if routing.client_a == from {
        (routing.client_b, &routing.token_b, routing.tag_b)
    } else if routing.client_b == from {
        (routing.client_a, &routing.token_a, routing.tag_a)
    } else {
        return Err(anyhow::anyhow!("Client not in circuit"));
    };

    // Verify authentication using the appropriate token
    let token_to_verify = if routing.client_a == from {
        &routing.token_a
    } else {
        &routing.token_b
    };

    if !token_to_verify.verify(&packet.circuit_id, &packet.payload, &packet.auth_tag) {
        debug!("Relay packet failed authentication");
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    trace!(
        "Relay auth verified for circuit {}",
        privacy::tag(packet.circuit_id.as_ref())
    );

    // The relay-visible message id of a sealed v2 payload (spec §5.3), echoed
    // in `MessageAck`; payloads without one get a random id.
    let message_id =
        extract_message_id(&packet.payload).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Forward to target
    trace!(
        "Relay: forwarding to target {} on circuit {}",
        privacy::tag(target_id.as_ref()),
        privacy::tag(packet.circuit_id.as_ref())
    );

    // The target receives on the circuit id it owns: this entry's id when
    // the target owns it (`client_a`), otherwise the pair's other entry. A
    // direct lookup, never a scan of the target's circuits (R-11).
    let target_cid = if routing.client_a == from {
        routing.peer_circuit
    } else {
        packet.circuit_id
    };
    // Clone the target's queue handle, then release the guard before
    // waiting on it.
    let target = connections
        .get(&target_id)
        .map(|target_conn| target_conn.ws_tx.clone());

    let mut forwarded = false;
    if let Some(target_tx) = target {
        // Rewrite with target's token and circuit ID
        let mut forward_packet = packet.clone();
        trace!(
            "Relay: rewriting circuit_id from {} to {} for target {}",
            privacy::tag(packet.circuit_id.as_ref()),
            privacy::tag(target_cid.as_ref()),
            privacy::tag(target_id.as_ref())
        );
        forward_packet.circuit_id = target_cid;

        forward_packet.auth_tag =
            target_token.authenticate(&forward_packet.circuit_id, &forward_packet.payload);

        let payload_len = forward_packet.payload.len();
        let frame = UnifiedFrame::relay(forward_packet);

        // Backpressure: if the recipient's queue is full, this sender's read
        // loop waits (bounded). A recipient that stays stuck is disconnected
        // and the message falls through to the offline store below.
        match target_tx
            .send_wait(frame.encode(), limits::OUTBOUND_SEND_TIMEOUT)
            .await
        {
            Ok(()) => {
                forwarded = true;
                trace!(
                    "Relay: forwarded {} bytes to target {}",
                    payload_len,
                    privacy::tag(target_id.as_ref())
                );
                metrics::RELAY_PACKETS.inc();
                metrics::RELAY_BYTES.inc_by(payload_len as f64);
            }
            Err(e) => debug!(
                "Relay: failed to forward to target {}: {}; storing offline",
                privacy::tag(target_id.as_ref()),
                e
            ),
        }
    }

    if forwarded {
        // Send MessageAck to sender
        send_message_ack(from, &message_id, connections);

        trace!(
            "Relayed packet via circuit {} (msg_id: {})",
            privacy::tag(packet.circuit_id.as_ref()),
            privacy::tag_str(&message_id)
        );
        return Ok(());
    }

    // The slot names a connection that is gone (or stuck). Decide under the
    // identity lock publish holds while it maps the identity and takes the
    // queue; send after releasing it (R-1); on failure re-check and re-queue
    // (spec §18.6 D34, ruling F19).
    trace!(
        "Target {} is not reachable on its slot; forwarding or storing",
        privacy::tag(target_id.as_ref())
    );
    // Ruling R15 (c) / R18: a blinded circuit is never handed over to its
    // member's new connection (no D34): a member that reconnected re-pairs
    // under a new token. Offline, the packet is filed in its queue; live
    // elsewhere, the row ends and the sender gets `CircuitNotFound`.
    let hand_over = matches!(routing.pair, PairKey::Identity(_));
    match forward_to_live_identity(target_tag, target_id, &packet.payload, hand_over, state).await {
        ForwardOutcome::Forwarded | ForwardOutcome::Queued => {
            send_message_ack(from, &message_id, connections)
        }
        ForwardOutcome::Moved => {
            // R18: no ack (the core keeps the message tracked and re-sends
            // it on the re-paired session); the blinded row goes now and the
            // sender is told its circuit is gone.
            circuits::teardown_moved_blind(packet.circuit_id, state).await;
            let error_msg = FrameBuilder::error(
                ControlErrorCode::CircuitNotFound,
                format!(
                    "{}{}",
                    rchat_core::protocol::CIRCUIT_NOT_FOUND_PREFIX,
                    hex::encode(packet.circuit_id.as_ref())
                ),
            );
            let _ = send_frame(from, error_msg, connections).await;
        }
        ForwardOutcome::Refused => {
            // Only members of a circuit (accepted contacts) can get here.
            // The refusal was counted where it happened (`store_offline` or
            // `requeue_salvaged`).
            let error_msg = FrameBuilder::error(
                ControlErrorCode::RateLimited,
                format!(
                    "{}message {} not stored",
                    rchat_core::protocol::OFFLINE_QUEUE_FULL_PREFIX,
                    validate::prefix(&message_id, 8)
                ),
            );
            let _ = send_frame(from, error_msg, connections).await;
        }
    }

    Ok(())
}

/// What became of a packet whose circuit slot names a gone connection.
#[derive(Debug, PartialEq, Eq)]
enum ForwardOutcome {
    /// Handed to the identity's live (not yet resumed) connection.
    Forwarded,
    /// Admitted to the identity's offline queue.
    Queued,
    /// Admission refused; the caller sends the queue-full error.
    Refused,
    /// Blinded circuit only (R18): the member is live on another
    /// connection. Nothing was stored; the caller ends the row.
    Moved,
}

/// D34: the decision is made under `ID_LOCKS(target_tag)`, the lock publish
/// holds while it maps the identity and takes its queue, so a packet is
/// either queued before the take (and drained by it) or sees the new
/// mapping. The send runs after the lock is released (R-1); a failed send
/// is re-queued under the lock by `requeue_after_failed_forward`.
async fn forward_to_live_identity(
    target_tag: IdTag,
    slot_client: ClientId,
    payload: &[u8],
    hand_over: bool,
    state: &RelayState,
) -> ForwardOutcome {
    let guard = pair_lock::ID_LOCKS.lock(target_tag).await;
    let live = state
        .identity_to_client
        .get(&target_tag)
        .map(|c| *c)
        .filter(|c| *c != slot_client)
        .and_then(|c| {
            state
                .connections
                .get(&c)
                .map(|conn| (conn.ws_tx.clone(), conn.has_asked))
        });
    // R15 (c) / R18: a blinded circuit is never handed over. With its
    // member live elsewhere (decided under the lock) the row must end;
    // with the member offline the packet is filed as for identity pairs.
    // Final review L1: a member live only on a connection that has not
    // asked (a background drain, or a foreground one before its first
    // ask) counts as offline: the packet is filed and acknowledged, and
    // the first ask hands it over (`note_first_ask`).
    let live = match live {
        Some((_, false)) if !hand_over => None,
        other => other.map(|(tx, _)| tx),
    };
    if !hand_over && live.is_some() {
        drop(guard);
        return ForwardOutcome::Moved;
    }
    // Final review L-2: a queue with no room gets the same answer whether
    // B is offline or online without having resumed (the queue-full
    // error), so a full queue reveals no presence. Decided under the lock.
    if live.is_some() {
        let cost = StoredMessage {
            payload: payload.to_vec(),
            enqueued_at_unix_secs: 0,
            is_knock: false,
            knock_seq: 0,
        }
        .budget_cost();
        let (bytes, count, steady_sized) = state
            .message_queues
            .get(&target_tag)
            .map(|q| (q.bytes, q.message_count(), q.steady_sized_count()))
            .unwrap_or((0, 0, 0));
        if !state.offline_budget.would_admit(bytes, count, cost)
            || !limits::steady_sized_admits(steady_sized, payload.len())
        {
            drop(guard);
            metrics::reject(metrics::REJECT_QUEUE_OVERFLOW);
            debug!("Offline queue full; refusing message");
            return ForwardOutcome::Refused;
        }
    }
    let Some(tx) = live else {
        // Offline: queue under the lock (drained by the next publish).
        #[cfg(test)]
        tests_hook::before_offline_store(target_tag);
        let admitted = store_offline(target_tag, payload.to_vec(), state);
        drop(guard);
        return if admitted {
            ForwardOutcome::Queued
        } else {
            ForwardOutcome::Refused
        };
    };
    drop(guard); // never wait while holding the identity's lock (R-1)
    let frame = FrameBuilder::queued_message(payload.to_vec()).encode();
    // Never waited on (final review L-2): the slot's send already had its
    // bounded wait, so a live connection with no room right now gets the
    // packet through its queue (re-queued below) instead of stalling A's
    // read loop a second time.
    if tx.try_send_or_return(frame).is_ok() {
        trace!("Relay: handed a packet to a member that has not resumed");
        metrics::RELAY_PACKETS.inc();
        metrics::RELAY_BYTES.inc_by(payload.len() as f64);
        return ForwardOutcome::Forwarded;
    }
    debug!("Relay: hand-over to a member that has not resumed failed; re-queueing");
    requeue_after_failed_forward(target_tag, payload.to_vec(), state).await
}

/// Re-take the lock, re-check, and re-queue through normal admission
/// (`requeue_salvaged`); hand the queue over if the identity is live again
/// elsewhere, as `salvage_unsent` does.
async fn requeue_after_failed_forward(
    target_tag: IdTag,
    payload: Vec<u8>,
    state: &RelayState,
) -> ForwardOutcome {
    let guard = pair_lock::ID_LOCKS.lock(target_tag).await;
    let msg = StoredMessage {
        payload,
        enqueued_at_unix_secs: crate::protocol::timestamp(),
        is_knock: false,
        knock_seq: 0,
    };
    let dropped = requeue_salvaged(target_tag, vec![msg], state);
    // As in `salvage_unsent` (final review L5): only to a foreground
    // connection; otherwise the next publish or first ask takes it.
    let live = state
        .identity_to_client
        .get(&target_tag)
        .map(|c| *c)
        .filter(|c| is_foreground(*c, state));
    let backlog = live.and_then(|_| take_offline_queue(target_tag, state));
    drop(guard);
    if let (Some(client), Some(queue)) = (live, backlog) {
        // The hand-over waits on the recipient (bounded, per message); run it
        // off the sender's read loop so A never waits on B.
        let state = state.clone();
        tokio::spawn(async move {
            drain_offline_queue(client, target_tag, queue, &state).await;
        });
    }
    if dropped == 0 {
        ForwardOutcome::Queued
    } else {
        ForwardOutcome::Refused
    }
}

/// File a sealed payload under `tag`'s offline queue. Admission is checked
/// *before* the caller acknowledges: a message the server cannot keep is
/// refused (returns false), never acknowledged and then dropped. Called
/// under `tag`'s `ID_LOCKS` guard.
fn store_offline(tag: IdTag, payload: Vec<u8>, state: &RelayState) -> bool {
    let message_queues = &state.message_queues;
    let stored_msg = StoredMessage {
        payload,
        enqueued_at_unix_secs: crate::protocol::timestamp(),
        is_knock: false,
        knock_seq: 0,
    };
    let cost = stored_msg.budget_cost();

    let admitted = {
        let mut queue = message_queues.entry(tag).or_default();
        let messages = queue.message_count();
        let steady_ok =
            limits::steady_sized_admits(queue.steady_sized_count(), stored_msg.payload.len());
        // R26: over the steady-size sub-cap reads as a full queue.
        let reserved = if steady_ok {
            state
                .offline_budget
                .try_reserve(queue.bytes, messages, cost)
        } else {
            Err(limits::OfflineRejection::RecipientFull)
        };
        match reserved {
            Ok(()) => {
                queue.bytes += cost;
                queue.pending.push(stored_msg);
                trace!(
                    "Stored an offline message (queue size: {})",
                    queue.pending.len()
                );
                Ok(())
            }
            Err(reason) => Err(reason),
        }
    };
    // Don't leave an empty queue entry behind for a refused message.
    message_queues.remove_if(&tag, |_, q| q.pending.is_empty());

    match admitted {
        Ok(()) => true,
        Err(reason) => {
            metrics::reject(metrics::REJECT_QUEUE_OVERFLOW);
            debug!("Offline queue full ({:?}); refusing message", reason);
            false
        }
    }
}

/// Send a `MessageAck` ("relay accepted this message") to the sender. It
/// names no identities (spec §5.2).
fn send_message_ack(
    to: ClientId,
    message_id: &str,
    connections: &DashMap<ClientId, UnifiedConnection>,
) {
    if let Some(sender_conn) = connections.get(&to) {
        let ack = ControlMessage::MessageAck {
            message_id: message_id.to_string(),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            received_at: crate::protocol::unified::current_timestamp(),
        };
        let _ = sender_conn.ws_tx.send(UnifiedFrame::control(ack).encode());
    }
}

/// Take an identity's offline queue for delivery on its successful publish
/// (spec §4.3 step 4), knocks included; the knock index entries go. Called
/// under the identity's `ID_LOCKS` guard; the delivery itself
/// (`drain_offline_queue`) runs after the guard is released.
fn take_offline_queue(tag: IdTag, state: &RelayState) -> Option<MessageQueue> {
    let queue = state.knocks.take_queue(tag, &state.message_queues)?;
    state.offline_budget.release(queue.bytes);
    Some(queue)
}

/// Hand a queue taken by `take_offline_queue` to `client_id`, waiting for
/// room (bounded); anything not handed over is re-queued, older first.
async fn drain_offline_queue(
    client_id: ClientId,
    tag: IdTag,
    queue: MessageQueue,
    state: &RelayState,
) {
    let tx = state.connections.get(&client_id).map(|c| c.ws_tx.clone());
    let mut rest = queue.pending.into_iter();
    let mut undelivered = Vec::new();
    if let Some(tx) = tx {
        for msg in rest.by_ref() {
            let frame = FrameBuilder::queued_message(msg.payload.clone()).encode();
            if tx
                .send_wait_stored(
                    frame,
                    limits::OUTBOUND_SEND_TIMEOUT,
                    msg.enqueued_at_unix_secs,
                )
                .await
                .is_err()
            {
                undelivered.push(msg);
                break;
            }
        }
    }
    undelivered.extend(rest);
    if !undelivered.is_empty() {
        debug!(
            "Re-queueing {} undelivered offline items",
            undelivered.len()
        );
        requeue_offline(tag, undelivered, state);
    }
}

/// Tell `client_id` its queue has been handed over (protocol v3 §H.1,
/// ruling R34a). Best effort: a connection that can't take it is going.
async fn send_queue_handed_over(client_id: ClientId, state: &RelayState) {
    let tx = state.connections.get(&client_id).map(|c| c.ws_tx.clone());
    if let Some(tx) = tx {
        let frame = FrameBuilder::queue_handed_over().encode();
        let _ = tx.send_wait(frame, limits::OUTBOUND_SEND_TIMEOUT).await;
    }
}

/// Put items back at the front of `tag`'s queue, re-charging messages and
/// re-accounting knocks (without pair entries).
fn requeue_offline(tag: IdTag, msgs: Vec<StoredMessage>, state: &RelayState) {
    let bytes: usize = msgs.iter().map(StoredMessage::budget_cost).sum();
    state.offline_budget.force_add(bytes);
    state
        .knocks
        .requeue(tag, msgs, bytes, &state.message_queues);
}

/// Zero-fill and unlink the pre-v2 plaintext queue file (D6). Returns
/// whether a file was removed. Acts only on a regular file that looks like
/// the old queue JSON (`{"queues": ...`): a symlink is never followed, and
/// anything else is left in place and reported as an error.
pub(crate) fn wipe_legacy_queue_file(path: &Path) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let refuse = |why: &str| {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{why}; left in place"),
        ))
    };
    let before = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !before.file_type().is_file() {
        return refuse("not a regular file (symlinks are never followed)");
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = f.metadata()?;
        if !meta.file_type().is_file() || meta.dev() != before.dev() || meta.ino() != before.ino() {
            return refuse("the file changed while being checked");
        }
        let mut head = Vec::with_capacity(LEGACY_SNIFF_BYTES);
        (&mut f)
            .take(LEGACY_SNIFF_BYTES as u64)
            .read_to_end(&mut head)?;
        if !looks_like_legacy_queue_json(&head) {
            return refuse("not a legacy offline-queue file");
        }
        f.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; 64 * 1024];
        let mut left = meta.len();
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    // Unlink only the file that was wiped.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.dev() == before.dev() && m.ino() == before.ino() => {}
        _ => return refuse("the file changed while being wiped"),
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

/// How much of a candidate legacy file is read to recognise it.
const LEGACY_SNIFF_BYTES: usize = 4096;

/// The pre-v2 file was `serde_json` of `PersistedQueues { queues, saved_at }`:
/// a JSON object whose first key is `"queues"`.
fn looks_like_legacy_queue_json(head: &[u8]) -> bool {
    let mut rest = head.iter().skip_while(|b| b.is_ascii_whitespace());
    if rest.next() != Some(&b'{') {
        return false;
    }
    let rest: Vec<u8> = rest
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(8)
        .collect();
    rest == b"\"queues\""
}

/// Smallest sealed v2 payload (header 73 + tag 16 + sender 32 + kind 1 +
/// ratchet header 40). Mirrors `rchat_core::sealed::MIN_SEALED_LEN`.
const MIN_SEALED_LEN: usize = 162;

/// The relay-visible message id of a sealed v2 payload (spec §5.3):
/// `hex(payload[1..17])` when `payload[0] == 0x02` and the payload is long
/// enough. v1 payloads have no id.
pub(crate) fn extract_message_id(payload: &[u8]) -> Option<String> {
    if payload.len() < MIN_SEALED_LEN || payload[0] != validate::SEALED_V2 {
        return None;
    }
    Some(hex::encode(&payload[1..17]))
}

/// Handle a control message
async fn handle_control_message(client_id: ClientId, msg: ControlMessage, state: &RelayState) {
    let connections = &state.connections;
    // Protocol v3 §C.2: only a proven connection may send a blinded ask.
    // Checked first, before the message is parsed further or anything is
    // stored (Task 3 review M5).
    if matches!(msg, ControlMessage::CircuitAskBlind { .. })
        && !circuits::is_proven(client_id, state)
    {
        circuits::refuse_unproven_blind(client_id, state).await;
        return;
    }
    // Validate client-supplied keys and ids at the boundary. Refused with an
    // error frame that does not echo the input; nothing is stored.
    if let Err(reason) = validate::control(&msg) {
        debug!("Rejected control message: {}", reason);
        let error_response = FrameBuilder::error(ControlErrorCode::InvalidMessage, reason);
        let _ = send_frame(client_id, error_response, connections).await;
        return;
    }

    if matches!(
        msg,
        ControlMessage::CircuitAsk { .. } | ControlMessage::CircuitAskBlind { .. }
    ) {
        note_first_ask(client_id, state).await;
    }

    match msg {
        ControlMessage::CircuitAsk {
            target_identity,
            ephemeral_key,
            kem_ephemeral_pk,
            ephemeral_sig,
            knock,
            resume_circuit,
        } => {
            // Lengths were checked by `validate::control`.
            let (Ok(target), Ok(ephemeral), Ok(kem), Ok(sig)) = (
                <[u8; 32]>::try_from(target_identity.as_slice()),
                <[u8; 32]>::try_from(ephemeral_key.as_slice()),
                <circuits::KemEphemeral>::try_from(kem_ephemeral_pk.as_slice()),
                <[u8; crate::validate::ASK_EPH_SIG_BYTES]>::try_from(ephemeral_sig.as_slice()),
            ) else {
                return;
            };
            circuits::handle_circuit_ask(
                client_id,
                target,
                ephemeral,
                Box::new(circuits::AskEphemerals { kem, sig }),
                knock,
                normalize_resume(resume_circuit),
                state,
            )
            .await;
        }
        ControlMessage::CloseCircuit { circuit_id } => {
            circuits::handle_close_circuit(client_id, circuit_id, state).await;
        }
        ControlMessage::CircuitAskBlind {
            pair_token,
            ephemeral_key,
            kem_ephemeral_pk,
            ephemeral_sig,
            pad: _,
        } => {
            // Lengths were checked by `validate::control`.
            let (Ok(token), Ok(ephemeral), Ok(kem), Ok(sig)) = (
                <[u8; 32]>::try_from(pair_token.as_slice()),
                <[u8; 32]>::try_from(ephemeral_key.as_slice()),
                <circuits::KemEphemeral>::try_from(kem_ephemeral_pk.as_slice()),
                <[u8; crate::validate::ASK_EPH_SIG_BYTES]>::try_from(ephemeral_sig.as_slice()),
            ) else {
                return;
            };
            circuits::handle_circuit_ask_blind(
                client_id,
                token,
                ephemeral,
                Box::new(circuits::AskEphemerals { kem, sig }),
                state,
            )
            .await;
        }
        _ => {}
    }
}

/// Final review L1: the first ask (blind or identity) on a proven
/// connection marks it as the member's foreground connection. Then, before
/// the ask itself is handled and before any pair or token lock is taken
/// (lock order: `ID_LOCKS` first), the member's offline queue filled since
/// its publish (packets for its blinded rows while it counted as offline,
/// records salvaged from its old connection) is handed over, and R21 ends
/// its blinded rows whose slot is still a closed connection, so the peers
/// that stayed are told `CircuitClosed` and re-ask blind. A background
/// drain connection never asks, so it never triggers either.
async fn note_first_ask(client_id: ClientId, state: &RelayState) {
    let tag = {
        let Some(mut conn) = state.connections.get_mut(&client_id) else {
            return;
        };
        let Some(identity) = conn.proven_identity else {
            return;
        };
        if conn.has_asked {
            return;
        }
        // Set before the queue is taken below: a packet decided after this
        // sees a foreground member; one decided before was queued under the
        // identity lock and is taken here.
        conn.has_asked = true;
        id_tag(&identity)
    };
    let guard = pair_lock::ID_LOCKS.lock(tag).await;
    let mapped = state
        .identity_to_client
        .get(&tag)
        .is_some_and(|c| *c == client_id);
    let backlog = mapped.then(|| take_offline_queue(tag, state)).flatten();
    drop(guard);
    if let Some(queue) = backlog {
        drain_offline_queue(client_id, tag, queue, state).await;
    }
    circuits::end_departed_blind_rows(tag, client_id, state).await;
}

/// Whether `client_id` is a live connection that has asked (its member's
/// foreground connection, `has_asked`) and is not being refused.
pub(super) fn is_foreground(client_id: ClientId, state: &RelayState) -> bool {
    state
        .connections
        .get(&client_id)
        .is_some_and(|c| c.has_asked && !c.closing)
}

/// Handle a keepalive message
async fn handle_keepalive(
    client_id: ClientId,
    msg: KeepaliveMessage,
    connections: &Arc<DashMap<ClientId, UnifiedConnection>>,
) -> anyhow::Result<()> {
    match msg {
        KeepaliveMessage::Ping { timestamp } => {
            // Send pong response
            let response = UnifiedFrame::keepalive_pong(timestamp);
            send_frame(client_id, response, connections).await?;
        }
        KeepaliveMessage::Pong { .. } => {
            // Pong received, update last_pong time and clear pending ping
            if let Some(mut conn) = connections.get_mut(&client_id) {
                conn.last_pong = Instant::now();
                conn.pending_ping = None;
                trace!(
                    "Received pong from {}, connection is alive",
                    privacy::tag(client_id.as_ref())
                );
            }
        }
    }

    Ok(())
}

/// Send a signaling message to a client
async fn send_signaling(
    client_id: ClientId,
    msg: SignalingMessage,
    connections: &DashMap<ClientId, UnifiedConnection>,
) -> anyhow::Result<()> {
    if let Some(conn) = connections.get(&client_id) {
        let frame = UnifiedFrame::signaling(msg);
        conn.ws_tx.send(frame.encode())?;
    }
    Ok(())
}

/// Send a unified frame to a client
async fn send_frame(
    client_id: ClientId,
    frame: UnifiedFrame,
    connections: &DashMap<ClientId, UnifiedConnection>,
) -> anyhow::Result<()> {
    if let Some(conn) = connections.get(&client_id) {
        conn.ws_tx.send(frame.encode())?;
    }
    Ok(())
}

/// WebSocket limits for client connections: incoming messages and frames are
/// capped at `max_message_bytes` (tungstenite's defaults are 64 MiB / 16 MiB),
/// and the write buffer is bounded so a stalled peer cannot grow it.
fn websocket_config(config: &ServerConfig) -> WebSocketConfig {
    let mut ws = WebSocketConfig::default();
    ws.max_message_size = Some(config.max_message_bytes);
    // Clients send each message as a single frame, so the frame cap equals
    // the message cap.
    ws.max_frame_size = Some(config.max_message_bytes);
    // Room for the normal write buffer plus one maximal outgoing message.
    ws.max_write_buffer_size = ws.write_buffer_size + config.max_message_bytes * 2;
    ws
}

/// Test hooks. `after_identity_mapped` runs right after a publish maps the
/// identity's routing slot, so a test can land a live delivery exactly
/// there (R-9). `before_offline_store` runs in `forward_to_live_identity`
/// between its decision (identity offline) and the offline store, so a test
/// can run a publish exactly there (D34). Thread-local hooks fire on the
/// thread that set them; the process-wide ones are keyed by identity tag,
/// for code that runs on a relay worker thread. Each test keys its own
/// identity, so parallel tests never consume each other's hook.
#[cfg(test)]
pub(super) mod tests_hook {
    use super::tags::IdTag;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    type KeyedHook = Box<dyn FnOnce() + Send>;
    type KeyedHooks = Mutex<Option<HashMap<IdTag, KeyedHook>>>;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    static AFTER_MAPPED: KeyedHooks = Mutex::new(None);
    static BEFORE_STORE: KeyedHooks = Mutex::new(None);

    fn set(hooks: &KeyedHooks, tag: IdTag, f: KeyedHook) {
        hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(HashMap::new)
            .insert(tag, f);
    }

    fn run(hooks: &KeyedHooks, tag: IdTag) {
        let f = hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .and_then(|m| m.remove(&tag));
        if let Some(f) = f {
            f();
        }
    }

    pub(in crate::signaling) fn set_after_identity_mapped(f: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Runs `f` once, in the publish of `tag`, on whichever thread runs it.
    pub(in crate::signaling) fn set_after_identity_mapped_for(
        tag: IdTag,
        f: impl FnOnce() + Send + 'static,
    ) {
        set(&AFTER_MAPPED, tag, Box::new(f));
    }

    /// Runs `f` once, in the next forward for `tag` that decided "offline",
    /// just before it stores the packet (still under the identity lock).
    pub(in crate::signaling) fn set_before_offline_store_for(
        tag: IdTag,
        f: impl FnOnce() + Send + 'static,
    ) {
        set(&BEFORE_STORE, tag, Box::new(f));
    }

    pub(super) fn after_identity_mapped(tag: IdTag) {
        if let Some(f) = HOOK.with(|h| h.borrow_mut().take()) {
            f();
        }
        run(&AFTER_MAPPED, tag);
    }

    pub(super) fn before_offline_store(tag: IdTag) {
        run(&BEFORE_STORE, tag);
    }
}
