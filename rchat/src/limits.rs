//! Resource limits and DoS resistance.
//!
//! Everything that bounds how much memory, bandwidth or connection slots a
//! single peer (or a single source address) can consume lives here, so the
//! policies are in one place and unit-testable without sockets:
//!
//! * [`ConnectionLimiter`] - global `max_connections` cap plus an optional
//!   per-source-address cap. Permits are RAII guards held by the connection
//!   task, so a slot is released however the task ends.
//! * [`TokenBucket`] - per-connection inbound byte budget (`rate_limit_bps`).
//! * [`ConnTx`] - bounded per-connection outbound queue with an explicit
//!   slow-consumer policy (see the type docs).
//! * [`OfflineBudget`] - global byte budget for the offline message store.
//!
//! None of this code logs addresses. The per-address table stores only a
//! keyed BLAKE3 digest of the (normalised) address, with a random key that
//! lives for the lifetime of the process, so the table itself cannot be read
//! back as a list of client IPs.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fixed limits (not configurable on purpose: they protect invariants rather
// than express deployment policy).
// ---------------------------------------------------------------------------

/// Capacity of each connection's outbound queue, in WebSocket messages.
///
/// 256 is the same order of magnitude rVPN settled on. It comfortably covers
/// the largest burst the server itself generates for one client in normal
/// operation (a handful of control frames per incoming message, up to 100
/// queued `CircuitCreated` notifications on reconnect). Bytes are bounded
/// separately by [`OUTBOUND_QUEUE_MAX_BYTES`]. Offline-queue drains do not
/// rely on this capacity: they wait for space.
pub const OUTBOUND_QUEUE_CAPACITY: usize = 256;

/// Byte budget of each connection's outbound queue. Together with the count
/// cap this bounds what a connection that stops reading can pin in memory to
/// about 16 MiB (plus one message if a single message is larger).
pub const OUTBOUND_QUEUE_MAX_BYTES: usize = 16 << 20;

/// How long a producer that is allowed to wait (relay forwarding, offline
/// drain) waits for space in a recipient's outbound queue before declaring
/// the recipient stuck and disconnecting it.
pub const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Bytes charged against the inbound token bucket for every message on top of
/// its length. Per-message work (JSON/bincode decode, map lookups) dominates
/// for tiny frames, so a floor keeps a flood of 1-byte frames from being
/// "free". At the default 1 MiB/s this caps a connection at ~4096 msgs/s.
pub const PER_MESSAGE_COST_BYTES: usize = 256;

/// Largest signaling message (a text frame, or a binary frame of type 0x01
/// without its type byte) the relay parses. Real signaling is under 2 KiB
/// (a publish is ~650 B); anything larger closes the connection before any
/// JSON is parsed (R-1).
pub const MAX_SIGNALING_BYTES: usize = 16 << 10;

/// Upper bound on the WebSocket upgrade (HTTP request -> 101) after the
/// header peek. The TLS handshake timeout is handled by the acceptor.
pub const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of queued offline messages per recipient identity.
pub const OFFLINE_QUEUE_MAX_MESSAGES_PER_RECIPIENT: usize = 1000;

/// Fixed per-message bookkeeping overhead counted against the offline budget
/// in addition to the payload and id strings.
pub const OFFLINE_MESSAGE_OVERHEAD_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// Byte-based token bucket.
///
/// Tokens are charged *after* a message has been read (its size is only
/// known then), so the balance may go negative; the returned duration is how
/// long the caller must pause before reading again so that the long-run rate
/// never exceeds `rate` bytes/second. Pausing the read loop stops draining
/// the socket, which pushes back on the sender through TCP flow control.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// `rate` is bytes/second, `capacity` the burst size in bytes. The bucket
    /// starts full.
    pub fn new(rate: u64, capacity: u64) -> Self {
        Self::new_at(rate, capacity, Instant::now())
    }

    pub fn new_at(rate: u64, capacity: u64, now: Instant) -> Self {
        let rate = rate.max(1) as f64;
        let capacity = capacity.max(1) as f64;
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Charge `bytes` and return how long to wait before the next read.
    pub fn consume(&mut self, bytes: usize) -> Duration {
        self.consume_at(bytes, Instant::now())
    }

    pub fn consume_at(&mut self, bytes: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.tokens -= bytes as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

// ---------------------------------------------------------------------------
// Signature-work budget
// ---------------------------------------------------------------------------

/// Hellos plus publishes one connection may send in a burst. A normal client
/// sends one of each per connection (a re-publish is rare).
pub const AUTH_OPS_BURST: f64 = 6.0;
/// One more hello or publish is allowed per this interval after the burst.
pub const AUTH_OPS_REFILL: Duration = Duration::from_secs(10);

/// Per-connection budget for signature work (R-5): every `hello` costs the
/// relay an Ed25519 signature and every publish two `verify_strict` calls,
/// while the byte-based [`TokenBucket`] lets a connection send thousands of
/// small signaling messages per second. A connection over budget is closed.
#[derive(Debug)]
pub struct AuthBudget {
    tokens: f64,
    last: Instant,
}

impl AuthBudget {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: AUTH_OPS_BURST,
            last: now,
        }
    }

    /// Take one operation; false when the budget is spent.
    pub fn try_take(&mut self, now: Instant) -> bool {
        let refill =
            now.saturating_duration_since(self.last).as_secs_f64() / AUTH_OPS_REFILL.as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + refill).min(AUTH_OPS_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Connection limiter
// ---------------------------------------------------------------------------

/// Why a new connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnRejection {
    MaxConnections,
    PerIpCap,
    /// IPv6 /48 aggregate cap (`max_connections_per_ipv6_48`).
    PerPrefixCap,
}

type AddrKey = [u8; 32];

/// Keyed digest of a connection's source bucket - an IPv4 address or an
/// IPv6 /48 - used for per-source fair shares of relay state (R-2, R-3).
/// The key is random per process, so it cannot be read back as an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceKey(pub [u8; 32]);

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_addr: HashMap<AddrKey, usize>,
    per_prefix: HashMap<AddrKey, usize>,
}

/// Global and per-source-address connection caps.
///
/// Counts every accepted TCP connection from `accept()` until its task ends,
/// including time spent in the TLS handshake, header peek and decoy serving,
/// so an attacker cannot hold unbounded half-open slots.
pub struct ConnectionLimiter {
    max_total: usize,
    /// 0 disables the per-address cap.
    max_per_addr: usize,
    /// 0 disables the IPv6 /48 aggregate cap.
    max_per_v6_48: usize,
    hash_key: [u8; 32],
    state: Mutex<LimiterState>,
}

/// RAII slot. Dropping it releases the global and per-address counts.
pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    addr_key: Option<AddrKey>,
    prefix_key: Option<AddrKey>,
}

impl ConnectionLimiter {
    pub fn new(max_total: usize, max_per_addr: usize, max_per_v6_48: usize) -> Arc<Self> {
        let mut hash_key = [0u8; 32];
        getrandom::getrandom(&mut hash_key).expect("OS RNG unavailable");
        Arc::new(Self {
            max_total,
            max_per_addr,
            max_per_v6_48,
            hash_key,
            state: Mutex::new(LimiterState::default()),
        })
    }

    /// Normalise an address to the unit we cap on: IPv4 (including
    /// IPv4-mapped IPv6) per address, IPv6 per /64 - a single host normally
    /// owns a whole /64, so capping per /128 would be trivial to bypass.
    fn addr_key(&self, ip: IpAddr) -> AddrKey {
        let mut buf = [0u8; 17];
        let bytes: &[u8] = match ip {
            IpAddr::V4(v4) => {
                buf[0] = 4;
                buf[1..5].copy_from_slice(&v4.octets());
                &buf[..5]
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => {
                    buf[0] = 4;
                    buf[1..5].copy_from_slice(&v4.octets());
                    &buf[..5]
                }
                None => {
                    buf[0] = 6;
                    buf[1..9].copy_from_slice(&v6.octets()[..8]);
                    &buf[..9]
                }
            },
        };
        *blake3::keyed_hash(&self.hash_key, bytes).as_bytes()
    }

    /// Key for the IPv6 /48 aggregate (native IPv6 only; IPv4 and
    /// IPv4-mapped addresses have no /48).
    fn prefix_key(&self, ip: IpAddr) -> Option<AddrKey> {
        match ip {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
                let mut buf = [0u8; 7];
                buf[0] = 48;
                buf[1..7].copy_from_slice(&v6.octets()[..6]);
                Some(*blake3::keyed_hash(&self.hash_key, &buf).as_bytes())
            }
            _ => None,
        }
    }

    /// The fair-share bucket of `ip`: the IPv4 address (IPv4-mapped
    /// included), or the IPv6 /48 (one site; a single attacker easily holds
    /// a whole /48, so a /64 bucket would be trivial to multiply).
    pub fn source_key(&self, ip: IpAddr) -> SourceKey {
        let mut buf = [0u8; 7];
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        let bytes: &[u8] = match (v4, ip) {
            (Some(v4), _) => {
                buf[0] = b's';
                buf[1..5].copy_from_slice(&v4.octets());
                &buf[..5]
            }
            (None, ip) => {
                let v6 = match ip {
                    IpAddr::V6(v6) => v6.octets(),
                    IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                };
                buf[0] = b'S';
                buf[1..7].copy_from_slice(&v6[..6]);
                &buf[..7]
            }
        };
        SourceKey(*blake3::keyed_hash(&self.hash_key, bytes).as_bytes())
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionPermit, ConnRejection> {
        let addr_key = (self.max_per_addr > 0).then(|| self.addr_key(ip));
        let prefix_key = if self.max_per_v6_48 > 0 {
            self.prefix_key(ip)
        } else {
            None
        };
        let mut state = self.state.lock();
        if state.total >= self.max_total {
            return Err(ConnRejection::MaxConnections);
        }
        if let Some(key) = prefix_key {
            if state.per_prefix.get(&key).copied().unwrap_or(0) >= self.max_per_v6_48 {
                return Err(ConnRejection::PerPrefixCap);
            }
        }
        if let Some(key) = addr_key {
            let count = state.per_addr.entry(key).or_insert(0);
            if *count >= self.max_per_addr {
                if *count == 0 {
                    state.per_addr.remove(&key);
                }
                return Err(ConnRejection::PerIpCap);
            }
            *count += 1;
        }
        if let Some(key) = prefix_key {
            *state.per_prefix.entry(key).or_insert(0) += 1;
        }
        state.total += 1;
        Ok(ConnectionPermit {
            limiter: Arc::clone(self),
            addr_key,
            prefix_key,
        })
    }

    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.state.lock().total
    }

    #[cfg(test)]
    fn tracked_addrs(&self) -> usize {
        self.state.lock().per_addr.len()
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(key) = self.addr_key {
            if let Some(count) = state.per_addr.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_addr.remove(&key);
                }
            }
        }
        if let Some(key) = self.prefix_key {
            if let Some(count) = state.per_prefix.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_prefix.remove(&key);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded outbound queue
// ---------------------------------------------------------------------------

/// Error returned when a message could not be queued for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnSendError {
    /// Queue full (or timed out waiting for space): the recipient is not
    /// reading. The connection has been told to close.
    SlowConsumer,
    /// The connection is closing or closed.
    Closed,
    /// The relay-wide outbound budget is spent (R-17). The heaviest
    /// holder of the budget has been told to close (H-1); this recipient
    /// stays connected unless it is that holder.
    Overloaded,
}

impl fmt::Display for ConnSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnSendError::SlowConsumer => {
                write!(f, "recipient outbound queue full; disconnecting")
            }
            ConnSendError::Closed => write!(f, "connection closed"),
            ConnSendError::Overloaded => write!(f, "relay-wide outbound budget exhausted"),
        }
    }
}

impl std::error::Error for ConnSendError {}

/// Default cap on bytes waiting in all of a relay's outbound queues together
/// (R-17). Each connection may hold [`OUTBOUND_QUEUE_MAX_BYTES`], but
/// 10,000 connections x 16 MiB is far more memory than a relay has; this
/// bounds the sum.
pub const GLOBAL_OUTBOUND_MAX_BYTES: usize = 1 << 30;

/// Longest a connection's writer may make no progress (not one byte
/// accepted by the socket) while it has a message to send before the
/// connection is closed (H-1). A peer that stops reading would otherwise
/// pin its queued bytes for as long as it keeps the connection alive.
pub const WRITER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Shedding: who lets go when a shared budget is spent (H-1, M-5)
// ---------------------------------------------------------------------------

/// Something holding part of a shared byte budget.
pub trait Held: Send + Sync {
    /// Bytes currently held.
    fn held(&self) -> usize;
}

/// A connection's outbound queue byte semaphore: what it holds is what is
/// not available.
impl Held for Semaphore {
    fn held(&self) -> usize {
        OUTBOUND_QUEUE_MAX_BYTES.saturating_sub(self.available_permits())
    }
}

/// How long a producer waiting on a spent relay-wide budget waits between
/// shedding attempts.
const SHED_RETRY: Duration = Duration::from_millis(250);

/// At most one shedding scan per this interval: a scan is O(holders), and
/// a victim needs a moment to release what it held.
const SHED_INTERVAL_MS: u64 = 10;

/// The holders of one shared budget, each with the token that closes it
/// and its source bucket. When the budget is spent, the source holding the
/// most (summed over its connections) loses its heaviest connection,
/// instead of everyone being refused (H-1). By source, not by connection
/// (N-3): many small holders from a few addresses cannot make a lone,
/// legitimately heavy receiver the victim. A holder with no known source
/// counts as a source of its own.
pub struct Shedder {
    holders: Mutex<ShedList>,
    epoch: Instant,
    /// Milliseconds since `epoch` before which no new scan starts.
    next_scan_ms: AtomicU64,
}

struct ShedList {
    list: Vec<(Weak<dyn Held>, CancellationToken, Option<SourceKey>)>,
    /// Prune dead entries when the list reaches this length (amortised:
    /// registration never scans the list on every call).
    prune_at: usize,
}

impl Default for Shedder {
    fn default() -> Self {
        Self::new()
    }
}

impl Shedder {
    pub fn new() -> Self {
        Self {
            holders: Mutex::new(ShedList {
                list: Vec::new(),
                prune_at: 64,
            }),
            epoch: Instant::now(),
            next_scan_ms: AtomicU64::new(0),
        }
    }

    /// Track `holder`; `kill` closes it. The entry goes once the holder is
    /// dropped.
    pub fn register(
        &self,
        holder: Weak<dyn Held>,
        kill: CancellationToken,
        source: Option<SourceKey>,
    ) {
        let mut l = self.holders.lock();
        if l.list.len() >= l.prune_at {
            l.list.retain(|(w, _, _)| w.strong_count() > 0);
            l.prune_at = (l.list.len() * 2).max(64);
        }
        l.list.push((holder, kill, source));
    }

    /// The budget is short by `excess` bytes. Holders already told to close
    /// are releasing what they hold; if that does not cover `excess`, close
    /// the heaviest open holder of the heaviest source. Returns whether one was
    /// closed. At most one scan per `SHED_INTERVAL_MS`.
    pub fn shed(&self, excess: usize, reason: &'static str) -> bool {
        let now = self.epoch.elapsed().as_millis() as u64;
        let next = self.next_scan_ms.load(Ordering::Acquire);
        if now < next
            || self
                .next_scan_ms
                .compare_exchange(
                    next,
                    now + SHED_INTERVAL_MS,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return false;
        }
        let mut l = self.holders.lock();
        l.list.retain(|(w, _, _)| w.strong_count() > 0);
        let mut releasing = 0usize;
        // Per group (a source, or a lone unattributed holder): total held
        // and its heaviest open holder.
        let mut groups: HashMap<(Option<SourceKey>, usize), (usize, usize, usize)> = HashMap::new();
        for (i, (w, kill, source)) in l.list.iter().enumerate() {
            let Some(h) = w.upgrade() else { continue };
            let n = h.held();
            if kill.is_cancelled() {
                releasing = releasing.saturating_add(n);
                continue;
            }
            if n == 0 {
                continue;
            }
            let key = (*source, if source.is_some() { 0 } else { i });
            let g = groups.entry(key).or_insert((0, 0, i));
            g.0 = g.0.saturating_add(n);
            if n > g.1 {
                g.1 = n;
                g.2 = i;
            }
        }
        if releasing >= excess.max(1) {
            return false;
        }
        let victim = groups
            .values()
            .max_by_key(|(total, _, i)| (*total, std::cmp::Reverse(*i)))
            .map(|(_, _, i)| &l.list[*i].1);
        match victim {
            Some(kill) => {
                kill.cancel();
                crate::metrics::reject(reason);
                true
            }
            None => false,
        }
    }
}

/// A relay's outbound byte budget, shared by every connection's queue, and
/// the connections holding it.
pub struct OutboundBudget {
    sem: Arc<Semaphore>,
    shedder: Shedder,
}

impl OutboundBudget {
    pub fn new(bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(bytes)),
            shedder: Shedder::new(),
        })
    }

    /// Bytes not currently held by any queue.
    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }

    /// The budget cannot give `cost` bytes: close the heaviest holder.
    fn shed(&self, cost: u32) {
        let excess = (cost as usize).saturating_sub(self.sem.available_permits());
        self.shedder
            .shed(excess, crate::metrics::REJECT_OUTBOUND_SHED);
    }
}

// ---------------------------------------------------------------------------
// WebSocket buffer budget (M-5)
// ---------------------------------------------------------------------------

/// Default cap on bytes held in all connections' WebSocket buffers
/// together (M-5): a message still being received (up to
/// `max_message_bytes` each, before any rate-limit charge) and the
/// capacity the WebSocket codec keeps after a large message in either
/// direction. Without it, 64 connections per address x 4 MiB lets a dozen
/// addresses exhaust the unit's `MemoryMax`.
pub const GLOBAL_BUFFER_MAX_BYTES: usize = 512 << 20;

/// The relay-wide WebSocket buffer budget and the connections holding it.
/// When it is exceeded, the connection holding the most is closed.
pub struct BufferBudget {
    used: AtomicUsize,
    cap: usize,
    shedder: Shedder,
}

impl BufferBudget {
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            cap,
            shedder: Shedder::new(),
        })
    }

    /// Bytes currently charged.
    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn cap(&self) -> usize {
        self.cap
    }
}

#[derive(Default)]
struct MeterState {
    /// Bytes read from the socket since the last complete message.
    partial: usize,
    /// Largest message received: the read buffer keeps that capacity.
    in_high: usize,
    /// Largest message sent: the write buffer keeps that capacity.
    out_high: usize,
}

impl MeterState {
    fn held(&self) -> usize {
        self.partial.max(self.in_high).saturating_add(self.out_high)
    }
}

/// One connection's charge against a [`BufferBudget`]. An approximation
/// of what its WebSocket codec holds: the larger of the message being
/// received and the largest received so far, plus the largest sent so far
/// (the codec's buffers never shrink). Released when dropped.
pub struct BufferMeter {
    budget: Arc<BufferBudget>,
    state: Mutex<MeterState>,
}

impl Held for BufferMeter {
    fn held(&self) -> usize {
        self.state.lock().held()
    }
}

impl BufferMeter {
    /// A meter for the connection that `kill` closes, registered with the
    /// budget so the connection can be shed.
    pub fn new(
        budget: Arc<BufferBudget>,
        kill: CancellationToken,
        source: Option<SourceKey>,
    ) -> Arc<Self> {
        let meter = Arc::new(Self {
            budget,
            state: Mutex::new(MeterState::default()),
        });
        let holder: Arc<dyn Held> = meter.clone();
        meter
            .budget
            .shedder
            .register(Arc::downgrade(&holder), kill, source);
        meter
    }

    fn update(&self, f: impl FnOnce(&mut MeterState)) {
        let mut st = self.state.lock();
        let before = st.held();
        f(&mut st);
        let after = st.held();
        drop(st);
        if after > before {
            let used = self
                .budget
                .used
                .fetch_add(after - before, Ordering::AcqRel)
                .saturating_add(after - before);
            if used > self.budget.cap {
                self.budget
                    .shedder
                    .shed(used - self.budget.cap, crate::metrics::REJECT_BUFFER_SHED);
            }
        } else if before > after {
            self.budget.used.fetch_sub(before - after, Ordering::AcqRel);
        }
    }

    /// `n` more bytes were read from the socket.
    pub fn read(&self, n: usize) {
        if n > 0 {
            self.update(|s| s.partial = s.partial.saturating_add(n));
        }
    }

    /// A complete message of `len` bytes came out of the codec.
    pub fn received(&self, len: usize) {
        self.update(|s| {
            s.partial = 0;
            s.in_high = s.in_high.max(len);
        });
    }

    /// A message of `len` bytes is going into the codec.
    pub fn sending(&self, len: usize) {
        self.update(|s| s.out_high = s.out_high.max(len));
    }
}

impl Drop for BufferMeter {
    fn drop(&mut self) {
        let held = self.state.get_mut().held();
        self.budget.used.fetch_sub(held, Ordering::AcqRel);
    }
}

/// A queued message's share of its connection's byte budget and of the
/// relay-wide one; both are returned when the writer drops it after the
/// write.
pub struct OutboundPermit {
    _conn: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    /// For a record handed over from the offline queue: when it was first
    /// stored, so a record re-queued after a failed hand-over keeps its
    /// TTL (security review L-2). None for live frames.
    enqueued_at: Option<u64>,
}

impl OutboundPermit {
    /// When the record this permit belongs to was first stored, if it
    /// came from the offline queue.
    pub fn enqueued_at(&self) -> Option<u64> {
        self.enqueued_at
    }
}

/// A queued outbound message together with its share of the byte budgets;
/// the writer task drops the permit once the message has been written.
pub type Outbound = (Message, OutboundPermit);

/// Sending half of a connection's bounded outbound queue, plus the handle used
/// to tear the connection down.
///
/// The queue is bounded twice: by count ([`OUTBOUND_QUEUE_CAPACITY`]) and by
/// bytes ([`OUTBOUND_QUEUE_MAX_BYTES`]); a message larger than the byte budget
/// takes the whole budget, so it can still be sent, alone. All queues
/// together are bounded by a relay-wide [`OutboundBudget`]
/// ([`GLOBAL_OUTBOUND_MAX_BYTES`] by default). When that is spent, the
/// connection holding the most of it is closed (its queue is released when
/// its writer stops) and the send fails ([`ConnSendError::Overloaded`]) -
/// or, for [`ConnTx::send_wait`], waits for the released bytes. Separately,
/// a writer that makes no progress for [`WRITER_STALL_TIMEOUT`] closes its
/// connection, so a peer that stops reading cannot pin its queue (H-1).
///
/// Slow-consumer policy: the server never grows a connection's buffer without
/// bound. Producers that run on another connection's read loop and cannot
/// sensibly wait (acks, receipts, keepalive pings, signaling replies) use
/// [`ConnTx::send`], which fails immediately on a full queue and disconnects
/// the recipient - a full queue of undelivered server messages means the peer
/// has stopped reading. Relay forwarding and offline drains use
/// [`ConnTx::send_wait`], which applies backpressure (the *sender's* read loop
/// pauses, so TCP pushes back on the sender) for up to
/// [`OUTBOUND_SEND_TIMEOUT`] and only then disconnects the recipient as stuck.
/// Backpressure for peer data means a fast sender is slowed to the reader's
/// pace instead of getting a slow but healthy reader kicked off.
#[derive(Clone)]
pub struct ConnTx {
    tx: mpsc::Sender<Outbound>,
    bytes: Arc<Semaphore>,
    global: Arc<OutboundBudget>,
    kill: CancellationToken,
}

impl ConnTx {
    /// Create the queue. The receiver goes to the writer task; the token is
    /// cancelled to close the connection.
    /// The queue draws on a budget of its own (tests, bare connections).
    #[cfg(test)]
    pub fn channel() -> (ConnTx, mpsc::Receiver<Outbound>, CancellationToken) {
        Self::channel_with_global(OutboundBudget::new(GLOBAL_OUTBOUND_MAX_BYTES))
    }

    /// As `channel`, drawing on `global` with no known source.
    #[cfg(test)]
    pub fn channel_with_global(
        global: Arc<OutboundBudget>,
    ) -> (ConnTx, mpsc::Receiver<Outbound>, CancellationToken) {
        Self::channel_from(global, None)
    }

    /// A queue drawing on `global` as the relay-wide budget, registered as
    /// one of its holders under `source`, so it can be shed (H-1, N-3).
    pub fn channel_from(
        global: Arc<OutboundBudget>,
        source: Option<SourceKey>,
    ) -> (ConnTx, mpsc::Receiver<Outbound>, CancellationToken) {
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let kill = CancellationToken::new();
        let bytes = Arc::new(Semaphore::new(OUTBOUND_QUEUE_MAX_BYTES));
        let holder: Arc<dyn Held> = bytes.clone();
        global
            .shedder
            .register(Arc::downgrade(&holder), kill.clone(), source);
        (
            ConnTx {
                tx,
                bytes,
                global,
                kill: kill.clone(),
            },
            rx,
            kill,
        )
    }

    /// Whether the connection has been told to close.
    #[cfg(test)]
    pub fn is_closed(&self) -> bool {
        self.kill.is_cancelled()
    }

    fn cost(msg: &Message) -> u32 {
        // At least 1 so empty messages still count; at most the budget.
        msg.len().clamp(1, OUTBOUND_QUEUE_MAX_BYTES) as u32
    }

    fn slow_consumer(&self) -> ConnSendError {
        crate::metrics::reject(crate::metrics::REJECT_SLOW_CONSUMER);
        self.kill.cancel();
        ConnSendError::SlowConsumer
    }

    fn overloaded() -> ConnSendError {
        crate::metrics::reject(crate::metrics::REJECT_GLOBAL_OUTBOUND);
        ConnSendError::Overloaded
    }

    /// Queue without waiting. On a full queue the recipient is disconnected;
    /// with the relay-wide budget spent the message is refused.
    pub fn send(&self, msg: Message) -> Result<(), ConnSendError> {
        if self.kill.is_cancelled() {
            return Err(ConnSendError::Closed);
        }
        let cost = Self::cost(&msg);
        let conn = match self.bytes.clone().try_acquire_many_owned(cost) {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(self.slow_consumer()),
            Err(TryAcquireError::Closed) => return Err(ConnSendError::Closed),
        };
        let global = match self.global.sem.clone().try_acquire_many_owned(cost) {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                self.global.shed(cost);
                return Err(Self::overloaded());
            }
            Err(TryAcquireError::Closed) => return Err(ConnSendError::Closed),
        };
        let permit = OutboundPermit {
            _conn: conn,
            _global: global,
            enqueued_at: None,
        };
        match self.tx.try_send((msg, permit)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(self.slow_consumer()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ConnSendError::Closed),
        }
    }

    /// Queue, waiting up to `timeout` for space (backpressure). On timeout
    /// waiting for this connection's queue the recipient is disconnected;
    /// on timeout waiting for the relay-wide budget the message is refused
    /// (`Overloaded`) and the recipient stays.
    pub async fn send_wait(&self, msg: Message, timeout: Duration) -> Result<(), ConnSendError> {
        self.send_wait_stamped(msg, timeout, None).await
    }

    /// `send_wait` for a record taken from the offline queue, carrying when
    /// it was first stored (`OutboundPermit::enqueued_at`).
    pub async fn send_wait_stored(
        &self,
        msg: Message,
        timeout: Duration,
        enqueued_at: u64,
    ) -> Result<(), ConnSendError> {
        self.send_wait_stamped(msg, timeout, Some(enqueued_at))
            .await
    }

    async fn send_wait_stamped(
        &self,
        msg: Message,
        timeout: Duration,
        enqueued_at: Option<u64>,
    ) -> Result<(), ConnSendError> {
        if self.kill.is_cancelled() {
            return Err(ConnSendError::Closed);
        }
        let cost = Self::cost(&msg);
        let deadline = tokio::time::Instant::now() + timeout;
        // `Err(None)` = this connection is stuck (slow consumer).
        let enqueue = async {
            let conn = match tokio::time::timeout_at(
                deadline,
                self.bytes.clone().acquire_many_owned(cost),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => return Err(Some(ConnSendError::Closed)),
                Err(_) => return Err(None),
            };
            let global = loop {
                match self.global.sem.clone().try_acquire_many_owned(cost) {
                    Ok(p) => break p,
                    Err(TryAcquireError::Closed) => return Err(Some(ConnSendError::Closed)),
                    Err(TryAcquireError::NoPermits) => {}
                }
                // Spent: close the heaviest holder (H-1), then wait a
                // little for it to let go, and look again.
                self.global.shed(cost);
                let step = (tokio::time::Instant::now() + SHED_RETRY).min(deadline);
                match tokio::time::timeout_at(
                    step,
                    self.global.sem.clone().acquire_many_owned(cost),
                )
                .await
                {
                    Ok(Ok(p)) => break p,
                    Ok(Err(_)) => return Err(Some(ConnSendError::Closed)),
                    Err(_) if step >= deadline => return Err(Some(Self::overloaded())),
                    Err(_) => {}
                }
            };
            let permit = OutboundPermit {
                _conn: conn,
                _global: global,
                enqueued_at,
            };
            match tokio::time::timeout_at(deadline, self.tx.send((msg, permit))).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(Some(ConnSendError::Closed)),
                Err(_) => Err(None),
            }
        };
        tokio::select! {
            res = enqueue => match res {
                Ok(()) => Ok(()),
                Err(Some(e)) => Err(e),
                Err(None) => Err(self.slow_consumer()),
            },
            _ = self.kill.cancelled() => Err(ConnSendError::Closed),
        }
    }

    /// Queue without waiting and without the slow-consumer policy: on a full
    /// (or closed) queue, or a spent relay-wide budget, the message comes
    /// back and the recipient stays connected. For knocks: the caller stores
    /// the knock instead, and the asker's read loop never waits on the
    /// target (spec §6.2, L7).
    pub fn try_send_or_return(&self, msg: Message) -> Result<(), Message> {
        if self.kill.is_cancelled() {
            return Err(msg);
        }
        let cost = Self::cost(&msg);
        let Ok(conn) = self.bytes.clone().try_acquire_many_owned(cost) else {
            return Err(msg);
        };
        let Ok(global) = self.global.sem.clone().try_acquire_many_owned(cost) else {
            self.global.shed(cost);
            return Err(msg);
        };
        let permit = OutboundPermit {
            _conn: conn,
            _global: global,
            enqueued_at: None,
        };
        self.tx.try_send((msg, permit)).map_err(|e| match e {
            mpsc::error::TrySendError::Full((msg, _))
            | mpsc::error::TrySendError::Closed((msg, _)) => msg,
        })
    }

    /// Ask the connection to close.
    pub fn kill(&self) {
        self.kill.cancel();
    }
}

// ---------------------------------------------------------------------------
// Offline store budget
// ---------------------------------------------------------------------------

/// Why a message could not be stored for an offline recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineRejection {
    RecipientFull,
    TotalFull,
}

/// Byte budget for the offline message store.
///
/// One per relay (`RelayState::offline_budget`), sized from the config.
pub struct OfflineBudget {
    used: AtomicUsize,
    max_total: AtomicUsize,
    max_per_recipient: AtomicUsize,
}

impl OfflineBudget {
    pub const fn new(max_total: usize, max_per_recipient: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max_total: AtomicUsize::new(max_total),
            max_per_recipient: AtomicUsize::new(max_per_recipient),
        }
    }

    /// Cost of one stored message.
    pub fn message_cost(payload_len: usize, id_len: usize, sender_len: usize) -> usize {
        payload_len + id_len + sender_len + OFFLINE_MESSAGE_OVERHEAD_BYTES
    }

    /// Reserve `cost` bytes for a recipient whose queue currently holds
    /// `recipient_bytes` bytes in `recipient_count` messages.
    pub fn try_reserve(
        &self,
        recipient_bytes: usize,
        recipient_count: usize,
        cost: usize,
    ) -> Result<(), OfflineRejection> {
        if recipient_count >= OFFLINE_QUEUE_MAX_MESSAGES_PER_RECIPIENT
            || recipient_bytes.saturating_add(cost) > self.max_per_recipient.load(Ordering::Relaxed)
        {
            return Err(OfflineRejection::RecipientFull);
        }
        let max_total = self.max_total.load(Ordering::Relaxed);
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let next = used.checked_add(cost)?;
                (next <= max_total).then_some(next)
            })
            .map(|_| ())
            .map_err(|_| OfflineRejection::TotalFull)
    }

    /// Whether `try_reserve` would admit `cost` now, without reserving (the
    /// D34 presence check, final review L-2).
    pub fn would_admit(&self, recipient_bytes: usize, recipient_count: usize, cost: usize) -> bool {
        recipient_count < OFFLINE_QUEUE_MAX_MESSAGES_PER_RECIPIENT
            && recipient_bytes.saturating_add(cost)
                <= self.max_per_recipient.load(Ordering::Relaxed)
            && self
                .used
                .load(Ordering::Acquire)
                .checked_add(cost)
                .is_some_and(|next| next <= self.max_total.load(Ordering::Relaxed))
    }

    /// Account for bytes that were not admitted through `try_reserve`
    /// (messages restored from disk, or re-queued after a failed drain).
    pub fn force_add(&self, cost: usize) {
        self.used.fetch_add(cost, Ordering::AcqRel);
    }

    pub fn release(&self, cost: usize) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(cost))
            });
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- relay-wide outbound budget (R-17) ----

    /// H-1: a spent relay-wide budget closes the connection holding the
    /// most of it - not the sender, not a lighter holder - and a waiting
    /// send gets the bytes once that queue is released.
    #[tokio::test]
    async fn a_spent_global_budget_closes_the_heaviest_holder() {
        let global = OutboundBudget::new(1000);
        let (a, a_rx, a_kill) = ConnTx::channel_with_global(global.clone());
        let (b, _b_rx, b_kill) = ConnTx::channel_with_global(global.clone());
        let (c, _c_rx, c_kill) = ConnTx::channel_with_global(global.clone());
        assert!(c.send(Message::Binary(vec![0; 100])).is_ok());
        assert!(a.send(Message::Binary(vec![0; 800])).is_ok());
        // b's own queue is empty, but the shared budget is not.
        assert_eq!(
            b.send(Message::Binary(vec![0; 800])),
            Err(ConnSendError::Overloaded)
        );
        assert!(a_kill.is_cancelled(), "the heaviest holder is closed");
        assert!(!b_kill.is_cancelled() && !c_kill.is_cancelled());
        // A second shortfall while a is still letting go closes no one else.
        tokio::time::sleep(Duration::from_millis(3 * SHED_INTERVAL_MS)).await;
        assert!(b.try_send_or_return(Message::Binary(vec![0; 800])).is_err());
        assert!(!b_kill.is_cancelled() && !c_kill.is_cancelled());
        // A waiting send succeeds as soon as a's queue is released (its
        // writer stopped and the receiver went).
        let waiter = tokio::spawn(async move {
            b.send_wait(Message::Binary(vec![0; 800]), Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(a_rx);
        assert_eq!(waiter.await.unwrap(), Ok(()));
        assert_eq!(global.available(), 1000 - 100 - 800);
        drop(a);
    }

    /// N-3: many small holders from a few attacker sources do not get a
    /// lone, legitimately heavy receiver shed: the source holding the most
    /// in total loses its heaviest connection.
    #[tokio::test]
    async fn shedding_picks_the_heaviest_source_not_the_heaviest_connection() {
        let global = OutboundBudget::new(1000);
        let attacker = |n: u8| Some(SourceKey([n; 32]));
        let mut sybils = Vec::new();
        for i in 0..10u8 {
            // Two attacker sources, five 60-byte holders each (300 apiece).
            let (tx, rx, kill) = ConnTx::channel_from(global.clone(), attacker(1 + i % 2));
            tx.send(Message::Binary(vec![0; 60])).unwrap();
            sybils.push((tx, rx, kill));
        }
        let (legit, _legit_rx, legit_kill) =
            ConnTx::channel_from(global.clone(), Some(SourceKey([9; 32])));
        legit.send(Message::Binary(vec![0; 250])).unwrap(); // largest single holder
        let (sender, _s_rx, sender_kill) = ConnTx::channel_from(global.clone(), None);
        assert_eq!(
            sender.send(Message::Binary(vec![0; 200])),
            Err(ConnSendError::Overloaded)
        );
        assert!(!legit_kill.is_cancelled(), "the legitimate receiver stays");
        assert!(!sender_kill.is_cancelled());
        let shed = sybils.iter().filter(|(_, _, k)| k.is_cancelled()).count();
        assert_eq!(shed, 1, "one attacker connection is shed");
    }

    // ---- token bucket ----

    #[test]
    fn bucket_allows_burst_up_to_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(1000, 4000, t0);
        assert_eq!(b.consume_at(4000, t0), Duration::ZERO);
    }

    #[test]
    fn bucket_throttles_when_exhausted() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(1000, 1000, t0);
        assert_eq!(b.consume_at(1000, t0), Duration::ZERO);
        // 500 bytes over budget at 1000 B/s => wait 0.5 s.
        let wait = b.consume_at(500, t0);
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "wait was {wait:?}");
    }

    #[test]
    fn bucket_refills_over_time_but_not_past_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(1000, 1000, t0);
        assert_eq!(b.consume_at(1000, t0), Duration::ZERO);
        // After 10 s idle the bucket holds only `capacity`, not 10_000.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(b.consume_at(1000, t1), Duration::ZERO);
        assert!(b.consume_at(1, t1) > Duration::ZERO);
    }

    #[test]
    fn bucket_long_run_rate_is_bounded() {
        // Sender ignores nothing: it sleeps exactly as told. Over N messages
        // the simulated clock must advance at least (total - burst) / rate.
        let t0 = Instant::now();
        let mut now = t0;
        let mut b = TokenBucket::new_at(10_000, 10_000, t0);
        let total: usize = 200 * 1_000;
        for _ in 0..200 {
            now += b.consume_at(1_000, now);
        }
        let elapsed = now.duration_since(t0).as_secs_f64();
        let min = (total as f64 - 10_000.0) / 10_000.0;
        assert!(elapsed + 1e-6 >= min, "elapsed {elapsed} < {min}");
    }

    #[test]
    fn bucket_handles_oversized_charge() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(1000, 1000, t0);
        let wait = b.consume_at(3000, t0);
        assert!((wait.as_secs_f64() - 2.0).abs() < 1e-6);
    }

    // ---- connection limiter ----

    #[test]
    fn limiter_caps_ipv6_48_aggregate() {
        // per-/64 cap 2, per-/48 cap 3
        let l = ConnectionLimiter::new(1000, 2, 3);
        let in_48 = |n: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, n, 0, 0, 0, 1));
        let p1 = l.try_acquire(in_48(1)).unwrap();
        let _p2 = l.try_acquire(in_48(2)).unwrap();
        let _p3 = l.try_acquire(in_48(3)).unwrap();
        // A fourth distinct /64 in the same /48 is refused.
        assert_eq!(
            l.try_acquire(in_48(4)).err(),
            Some(ConnRejection::PerPrefixCap)
        );
        // Another /48 is unaffected, and so is IPv4.
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x2, 1, 0, 0, 0, 1));
        assert!(l.try_acquire(other).is_ok());
        assert!(l.try_acquire(v4(1)).is_ok());
        // Rejections leak nothing; releasing one slot admits one more.
        drop(p1);
        assert!(l.try_acquire(in_48(4)).is_ok());
        // Held: p2, p3 (the probes above were dropped immediately).
        assert_eq!(l.active(), 2);
    }

    #[test]
    fn limiter_48_cap_zero_disables_it() {
        let l = ConnectionLimiter::new(1000, 0, 0);
        let held: Vec<_> = (0..50u16)
            .map(|n| {
                l.try_acquire(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, n, 0, 0, 0, 1)))
                    .unwrap()
            })
            .collect();
        assert_eq!(held.len(), 50);
    }

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, a))
    }

    #[test]
    fn limiter_enforces_global_cap_and_releases_on_drop() {
        let l = ConnectionLimiter::new(2, 0, 0);
        let p1 = l.try_acquire(v4(1)).unwrap();
        let _p2 = l.try_acquire(v4(2)).unwrap();
        assert_eq!(
            l.try_acquire(v4(3)).err(),
            Some(ConnRejection::MaxConnections)
        );
        drop(p1);
        assert!(l.try_acquire(v4(3)).is_ok());
    }

    #[test]
    fn limiter_enforces_per_addr_cap() {
        let l = ConnectionLimiter::new(100, 2, 0);
        let a = l.try_acquire(v4(1)).unwrap();
        let _b = l.try_acquire(v4(1)).unwrap();
        assert_eq!(l.try_acquire(v4(1)).err(), Some(ConnRejection::PerIpCap));
        // Other addresses unaffected.
        let _c = l.try_acquire(v4(2)).unwrap();
        drop(a);
        assert!(l.try_acquire(v4(1)).is_ok());
    }

    #[test]
    fn limiter_rejected_attempts_do_not_leak_slots() {
        let l = ConnectionLimiter::new(1, 1, 0);
        let p = l.try_acquire(v4(1)).unwrap();
        for _ in 0..10 {
            assert!(l.try_acquire(v4(1)).is_err());
            assert!(l.try_acquire(v4(9)).is_err());
        }
        assert_eq!(l.active(), 1);
        drop(p);
        assert_eq!(l.active(), 0);
        assert_eq!(
            l.tracked_addrs(),
            0,
            "empty per-address entries must be removed"
        );
    }

    #[test]
    fn limiter_groups_ipv6_by_slash64_and_mapped_v4_with_v4() {
        let l = ConnectionLimiter::new(100, 1, 0);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        let _pa = l.try_acquire(a).unwrap();
        assert_eq!(l.try_acquire(b).err(), Some(ConnRejection::PerIpCap));
        assert!(l.try_acquire(c).is_ok());

        let _p4 = l.try_acquire(v4(7)).unwrap();
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
        assert_eq!(l.try_acquire(mapped).err(), Some(ConnRejection::PerIpCap));
        let _ = Ipv6Addr::LOCALHOST;
    }

    #[test]
    fn limiter_per_addr_zero_disables_cap() {
        let l = ConnectionLimiter::new(3, 0, 0);
        let _a = l.try_acquire(v4(1)).unwrap();
        let _b = l.try_acquire(v4(1)).unwrap();
        let _c = l.try_acquire(v4(1)).unwrap();
        assert_eq!(
            l.try_acquire(v4(1)).err(),
            Some(ConnRejection::MaxConnections)
        );
        assert_eq!(l.tracked_addrs(), 0);
    }

    // ---- outbound queue ----

    #[tokio::test]
    async fn conn_tx_full_queue_disconnects_recipient() {
        let (tx, _rx, kill) = ConnTx::channel();
        for _ in 0..OUTBOUND_QUEUE_CAPACITY {
            tx.send(Message::Binary(vec![0])).unwrap();
        }
        assert_eq!(
            tx.send(Message::Binary(vec![0])),
            Err(ConnSendError::SlowConsumer)
        );
        assert!(kill.is_cancelled());
        assert_eq!(
            tx.send(Message::Binary(vec![0])),
            Err(ConnSendError::Closed)
        );
    }

    #[tokio::test]
    async fn conn_tx_send_wait_applies_backpressure_then_gives_up() {
        let timeout = Duration::from_millis(300);
        let (tx, mut rx, kill) = ConnTx::channel();
        for _ in 0..OUTBOUND_QUEUE_CAPACITY {
            tx.send(Message::Binary(vec![0])).unwrap();
        }
        // Space appears while we wait: succeeds.
        let reader = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = rx.recv().await;
            rx
        });
        tx.send_wait(Message::Binary(vec![1]), timeout)
            .await
            .unwrap();
        let _rx = reader.await.unwrap();
        assert!(!kill.is_cancelled());
        // No space ever appears: times out and disconnects.
        assert_eq!(
            tx.send_wait(Message::Binary(vec![2]), timeout).await,
            Err(ConnSendError::SlowConsumer)
        );
        assert!(kill.is_cancelled());
    }

    #[tokio::test]
    async fn conn_tx_byte_budget_bounds_queue_and_is_released_on_write() {
        let (tx, mut rx, kill) = ConnTx::channel();
        let big = OUTBOUND_QUEUE_MAX_BYTES / 4;
        for _ in 0..4 {
            tx.send(Message::Binary(vec![0; big])).unwrap();
        }
        // Count cap is far away, byte cap is reached.
        assert_eq!(
            tx.send(Message::Binary(vec![0; 1])),
            Err(ConnSendError::SlowConsumer)
        );
        assert!(kill.is_cancelled());

        // Writing (dropping the permit) frees budget on a fresh queue.
        let (tx, mut rx2, _kill) = ConnTx::channel();
        for _ in 0..4 {
            tx.send(Message::Binary(vec![0; big])).unwrap();
        }
        drop(rx2.recv().await.unwrap());
        tx.send(Message::Binary(vec![0; big])).unwrap();
        let _ = rx.recv().await;
    }

    #[tokio::test]
    async fn conn_tx_message_larger_than_budget_still_sends_alone() {
        let (tx, mut rx, _kill) = ConnTx::channel();
        tx.send(Message::Binary(vec![0; OUTBOUND_QUEUE_MAX_BYTES + 10]))
            .unwrap();
        let (msg, permit) = rx.recv().await.unwrap();
        assert_eq!(msg.len(), OUTBOUND_QUEUE_MAX_BYTES + 10);
        drop(permit);
        tx.send(Message::Binary(vec![0; 10])).unwrap();
    }

    // ---- offline budget ----

    #[test]
    fn offline_budget_enforces_total_and_per_recipient() {
        let b = OfflineBudget::new(1000, 600);
        b.try_reserve(0, 0, 500).unwrap();
        // Per-recipient: 500 + 200 > 600.
        assert_eq!(
            b.try_reserve(500, 1, 200),
            Err(OfflineRejection::RecipientFull)
        );
        // Another recipient fits per-recipient but total 500 + 600 > 1000.
        assert_eq!(b.try_reserve(0, 0, 600), Err(OfflineRejection::TotalFull));
        b.try_reserve(0, 0, 500).unwrap();
        assert_eq!(b.used(), 1000);
        b.release(500);
        assert_eq!(b.used(), 500);
        b.release(10_000);
        assert_eq!(b.used(), 0, "release saturates at zero");
    }

    #[test]
    fn offline_budget_enforces_message_count() {
        let b = OfflineBudget::new(usize::MAX, usize::MAX);
        assert_eq!(
            b.try_reserve(0, OFFLINE_QUEUE_MAX_MESSAGES_PER_RECIPIENT, 1),
            Err(OfflineRejection::RecipientFull)
        );
    }

    #[tokio::test]
    async fn conn_tx_try_send_or_return_hands_back_and_never_disconnects() {
        let (tx, mut rx, kill) = ConnTx::channel();
        for _ in 0..OUTBOUND_QUEUE_CAPACITY {
            tx.send(Message::Binary(vec![1])).unwrap();
        }
        let back = tx
            .try_send_or_return(Message::Binary(vec![2; 10]))
            .expect_err("a full queue hands the message back");
        assert_eq!(back, Message::Binary(vec![2; 10]));
        assert!(
            !kill.is_cancelled(),
            "a full queue must not disconnect the recipient"
        );

        let _ = rx.recv().await;
        assert!(tx.try_send_or_return(Message::Binary(vec![3])).is_ok());
    }
}
