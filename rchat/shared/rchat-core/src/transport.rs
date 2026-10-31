//! WebSocket transport layer with delivery confirmation
//!
//! This module handles:
//! - WebSocket connection management
//! - Automatic reconnection with exponential backoff
//! - Delivery confirmation tracking
//! - Half-open connection detection

use crate::tls_boring::{
    connect_resumable, connect_with_fingerprint, BoringTlsStream, TlsFingerprint,
};
use crate::tls_resumption::ResumptionStore;
use crate::{protocol::*, RChatError};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration, Instant};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

/// Largest WebSocket message (and frame) accepted from the relay: the
/// relay's default `max_message_bytes` (4 MiB) plus 64 KiB of slack for the
/// relay packet header and control-frame encoding around a payload. Without
/// it tungstenite would buffer up to 64 MiB per message for a hostile relay.
pub const MAX_INBOUND_MESSAGE_BYTES: usize = (4 << 20) + (64 << 10);

/// WebSocket limits for the relay connection (TLS and plain paths alike).
fn inbound_ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_INBOUND_MESSAGE_BYTES),
        max_frame_size: Some(MAX_INBOUND_MESSAGE_BYTES),
        ..WebSocketConfig::default()
    }
}

/// Longest one TCP connect to one address may take. A healthy connect takes
/// well under a second; a SYN that goes nowhere is better abandoned (and the
/// next address, or a fresh attempt a moment later, tried) than waited out for
/// the whole `connection_timeout_secs`.
pub(crate) const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest the DNS lookup may take, for the same reason: a healthy answer
/// takes well under a second.
pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve with a time limit. The messages never carry the host or an
/// address (they reach the log).
async fn resolve_within<I, Fut>(lookup: Fut, limit: Duration) -> Result<Vec<SocketAddr>, RChatError>
where
    I: Iterator<Item = SocketAddr>,
    Fut: std::future::Future<Output = std::io::Result<I>>,
{
    let addrs = timeout(limit, lookup)
        .await
        .map_err(|_| RChatError::ConnectionFailed {
            message: "DNS lookup timeout".to_string(),
        })?
        .map_err(|e| RChatError::ConnectionFailed {
            message: format!("DNS lookup failed: {}", e),
        })?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(RChatError::ConnectionFailed {
            message: "No addresses resolved".to_string(),
        });
    }
    Ok(addrs)
}

/// Addresses tried per connect attempt, in resolver order.
pub(crate) const MAX_CONNECT_ADDRS: usize = 4;

/// Try each address in order (at most [`MAX_CONNECT_ADDRS`]), each for at
/// most `per_try`; the first that connects wins. When all fail, the last
/// error is returned.
async fn connect_first<T, F, Fut>(
    addrs: &[SocketAddr],
    per_try: Duration,
    mut connect: F,
) -> Result<T, RChatError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut last = RChatError::ConnectionFailed {
        message: "No addresses resolved".to_string(),
    };
    // At most MAX_CONNECT_ADDRS: a DNS answer with many unreachable
    // addresses must not hold one attempt for minutes.
    for addr in addrs.iter().take(MAX_CONNECT_ADDRS) {
        last = match timeout(per_try, connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => RChatError::ConnectionFailed {
                message: format!("TCP connection failed: {}", e),
            },
            Err(_) => RChatError::ConnectionFailed {
                message: "TCP connection timeout".to_string(),
            },
        };
    }
    Err(last)
}

/// Unified stream type for WebSocket connections.
/// Wraps either a plain TCP stream or a BoringSSL TLS stream, and notes
/// when the socket last delivered any bytes (`last_read`).
pub struct TransportStream {
    kind: StreamKind,
    last_read: ReadClock,
    /// When the socket last took bytes from a write.
    last_write: ReadClock,
    /// Set by `ResetOnClose::arm`: closing resets the connection.
    reset_on_close: Arc<std::sync::atomic::AtomicBool>,
}

/// A socket's write progress in bytes: the socket took bytes from a write,
/// or its kernel send queue (unsent and unacknowledged) shrank. A slow but
/// moving connection keeps making progress even when one message takes
/// seconds, or when `TCP_NOTSENT_LOWAT` holds writes back while it drains.
pub(crate) struct SendProgress {
    wrote: ReadClock,
    fd: std::os::fd::RawFd,
    queued: Option<u64>,
    drained_at: Instant,
}

impl SendProgress {
    /// How long since the last progress (checks the kernel queue now).
    pub(crate) fn idle_for(&mut self) -> Duration {
        if let Some(q) = kernel_send_queued(self.fd) {
            if self.queued.is_some_and(|before| q < before) {
                self.drained_at = Instant::now();
            }
            self.queued = Some(q);
        }
        self.wrote.last().max(self.drained_at).elapsed()
    }
}

/// Bytes in a TCP socket's send queue (unsent and unacknowledged): Linux
/// and Android `TIOCOUTQ`, Apple `SO_NWRITE`; `None` elsewhere or on error.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn kernel_send_queued(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut n: libc::c_int = 0;
    // SAFETY: an fd the caller keeps open, and an int for the result.
    let r = unsafe { libc::ioctl(fd, libc::TIOCOUTQ as _, &mut n) };
    (r == 0).then(|| u64::try_from(n).unwrap_or(0))
}

#[cfg(target_vendor = "apple")]
fn kernel_send_queued(fd: std::os::fd::RawFd) -> Option<u64> {
    const SO_NWRITE: libc::c_int = 0x1024;
    let mut n: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: an fd the caller keeps open, and an int-sized buffer.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_NWRITE,
            &mut n as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0).then(|| u64::try_from(n).unwrap_or(0))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn kernel_send_queued(_fd: std::os::fd::RawFd) -> Option<u64> {
    None
}

/// Makes a stream's close a reset (`SO_LINGER` on with a zero timeout):
/// whatever the kernel still holds unsent is discarded at once instead of
/// draining after the close. For call connections being abandoned, so
/// stale video stops sharing the link with the audio.
#[derive(Clone)]
pub(crate) struct ResetOnClose(Arc<std::sync::atomic::AtomicBool>);

impl ResetOnClose {
    pub(crate) fn arm(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

enum StreamKind {
    Plain(TcpStream),
    Tls(BoringTlsStream),
}

/// When a connection's socket last delivered bytes (or, as a write clock,
/// last took bytes). Liveness is bytes
/// arriving, not messages completing: a large message coming in slowly
/// (a photo or voice note over a thin link, with the relay's pings queued
/// behind it) completes nothing for a long time on a healthy connection
/// (debug-voice-loss).
///
/// Known limit (security review L-3): over TLS, bytes reach this stream
/// only a whole TLS record at a time (up to 16 KiB of plaintext), so the
/// clock moves once per record. A healthy connection that delivers no
/// record for 30 s after a ping went out (with the app's 10 s keepalive
/// timeout; between 30 s and about 68 s between records, depending on when
/// the ping falls) can still be declared dead in the middle of a large
/// frame (spec §18.11 limit 12).
#[derive(Clone)]
pub(crate) struct ReadClock(Arc<parking_lot::Mutex<Instant>>);

impl ReadClock {
    fn new() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Instant::now())))
    }

    fn touch(&self) {
        *self.0.lock() = Instant::now();
    }

    pub(crate) fn last(&self) -> Instant {
        *self.0.lock()
    }
}

impl TransportStream {
    fn plain(stream: TcpStream) -> Self {
        Self {
            kind: StreamKind::Plain(stream),
            last_read: ReadClock::new(),
            last_write: ReadClock::new(),
            reset_on_close: Arc::default(),
        }
    }

    fn tls(stream: BoringTlsStream) -> Self {
        Self {
            kind: StreamKind::Tls(stream),
            last_read: ReadClock::new(),
            last_write: ReadClock::new(),
            reset_on_close: Arc::default(),
        }
    }

    /// Watches this socket's write progress (`SendProgress`). Use it only
    /// while the stream lives: it keeps the socket's fd, not the socket.
    pub(crate) fn send_progress(&self) -> SendProgress {
        use std::os::fd::AsRawFd;
        SendProgress {
            wrote: self.last_write.clone(),
            fd: self.tcp().as_raw_fd(),
            queued: None,
            drained_at: Instant::now(),
        }
    }

    /// A handle that, once armed, makes this stream's close a reset.
    pub(crate) fn reset_on_close(&self) -> ResetOnClose {
        ResetOnClose(self.reset_on_close.clone())
    }

    fn tcp(&self) -> &TcpStream {
        match &self.kind {
            StreamKind::Plain(s) => s,
            StreamKind::Tls(s) => s.tcp(),
        }
    }

    /// When this socket last delivered bytes.
    pub(crate) fn read_clock(&self) -> ReadClock {
        self.last_read.clone()
    }
}

impl Drop for TransportStream {
    fn drop(&mut self) {
        if self
            .reset_on_close
            .load(std::sync::atomic::Ordering::Acquire)
        {
            if let Err(e) = socket2::SockRef::from(self.tcp()).set_linger(Some(Duration::ZERO)) {
                log::debug!("SO_LINGER for a reset failed: {e}");
            }
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        let polled = match this.kind {
            StreamKind::Plain(ref mut s) => Pin::new(s).poll_read(cx, buf),
            StreamKind::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
        };
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.last_read.touch();
        }
        polled
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let polled = match this.kind {
            StreamKind::Plain(ref mut s) => Pin::new(s).poll_write(cx, buf),
            StreamKind::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
        };
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            this.last_write.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.kind {
            StreamKind::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            StreamKind::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.kind {
            StreamKind::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            StreamKind::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connection state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32, max: u32 },
}

/// Configuration for the WebSocket client
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub server_url: String,
    pub connection_timeout_secs: u64,
    pub reconnect_max_attempts: u32,
    pub reconnect_base_delay_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_timeout_secs: u64,
    pub delivery_confirmation_timeout_secs: u64,
    /// TLS fingerprint for DPI evasion (default: Chrome)
    pub tls_fingerprint: TlsFingerprint,
    /// Whether to automatically reconnect when the connection drops
    pub auto_reconnect: bool,
    /// Maximum reconnect attempts after initial connection (0 = infinite)
    pub reconnect_max_attempts_after_connect: u32,
    /// `ws://` only: origin whose hash stands in for the channel binding.
    pub dev_origin: Option<String>,
    /// `wss://` only: TLS 1.3 tickets for the pinned relay (spec §D.1),
    /// owned by the client. None: every handshake is a full one.
    pub resumption: Option<ResumptionStore>,
    /// The client's live keepalive interval: when set it overrides
    /// `keepalive_interval_secs` and may change while connected (Android
    /// background receiving, `KeepaliveInterval`).
    pub keepalive_live: Option<KeepaliveInterval>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            connection_timeout_secs: 30,
            reconnect_max_attempts: 5,
            reconnect_base_delay_secs: 1,
            keepalive_interval_secs: 30,
            keepalive_timeout_secs: 10,
            delivery_confirmation_timeout_secs: 30,
            tls_fingerprint: TlsFingerprint::default(),
            auto_reconnect: true,
            reconnect_max_attempts_after_connect: 0,
            dev_origin: None,
            resumption: None,
            keepalive_live: None,
        }
    }
}

/// A client's keepalive interval, shared with each of its connections and
/// changeable while they run (Android background receiving): a change
/// reschedules the next ping at once. Never below 1 s.
#[derive(Debug, Clone)]
pub struct KeepaliveInterval(Arc<tokio::sync::watch::Sender<u64>>);

impl KeepaliveInterval {
    pub fn new(secs: u64) -> Self {
        Self(Arc::new(tokio::sync::watch::channel(secs.max(1)).0))
    }

    /// Sets the interval; running connections pick it up before their next ping.
    pub fn set(&self, secs: u64) {
        let secs = secs.max(1);
        self.0.send_if_modified(|v| {
            if *v == secs {
                false
            } else {
                *v = secs;
                true
            }
        });
    }

    pub fn get(&self) -> u64 {
        *self.0.borrow()
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.subscribe()
    }
}

/// The next change of a connection's live interval: false when the client
/// dropped it; never resolves when there is none.
async fn interval_changed(rx: &mut Option<tokio::sync::watch::Receiver<u64>>) -> bool {
    match rx {
        Some(rx) => rx.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Events from the connection, delivered in arrival order through the event
/// sink (`set_event_sink`).
#[derive(Debug)]
pub enum TransportEvent {
    /// Boxed: v3 control frames (`CircuitCreatedV3`) make `Frame` large.
    Frame(Box<Frame>),
    Binary(Vec<u8>),
    Disconnected,
    Reconnected,
}

/// Internal message for the event loop
#[derive(Debug)]
pub enum InternalMessage {
    Frame(Box<Frame>),
    Binary(Vec<u8>),
    Disconnect,
}

/// Capacity of each outgoing queue (messages). If the socket cannot drain
/// (server or network stalled), senders wait up to `OUTGOING_SEND_TIMEOUT`
/// for space and then fail instead of buffering without bound.
const OUTGOING_QUEUE_CAPACITY: usize = 256;
pub(crate) const OUTGOING_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket client with delivery confirmation
pub struct WebSocketClient {
    config: TransportConfig,
    state: Arc<RwLock<ConnectionState>>,
    /// Channel for sending messages to the WebSocket
    tx: mpsc::UnboundedSender<InternalMessage>,
    /// Channel for receiving frames from the WebSocket
    rx: Arc<RwLock<mpsc::UnboundedReceiver<Frame>>>,
    /// Last time we received any data from the server
    last_received: Arc<RwLock<Instant>>,
    /// Callback for received messages
    message_callback: Arc<RwLock<Option<Box<dyn Fn(Frame) + Send + Sync>>>>,
    /// Callback for binary messages (relay packets)
    binary_callback: Arc<RwLock<Option<Box<dyn Fn(Vec<u8>) + Send + Sync>>>>,
    /// Callback when the connection task ends
    disconnect_callback: Arc<RwLock<Option<Box<dyn Fn() + Send + Sync>>>>,
    /// Handle to the background task
    task_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Sender for outgoing binary messages (to WebSocket). Bounded: see
    /// `OUTGOING_QUEUE_CAPACITY`.
    outgoing_tx: Arc<RwLock<Option<mpsc::Sender<Vec<u8>>>>>,
    /// Sender for outgoing text messages (to WebSocket). Bounded.
    outgoing_text_tx: Arc<RwLock<Option<mpsc::Sender<String>>>>,
    /// Whether the client should keep trying to reconnect
    should_reconnect: Arc<RwLock<bool>>,
    /// Number of reconnect attempts since last successful connection
    reconnect_attempt: Arc<RwLock<u32>>,
    /// Callback when auto-reconnect succeeds
    reconnect_callback: Arc<RwLock<Option<Box<dyn Fn() + Send + Sync>>>>,
    /// Handle to the reconnect watcher task
    reconnect_watcher_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Key-authentication channel binding of the current connection.
    channel_binding: Arc<parking_lot::Mutex<Option<[u8; 32]>>>,
    /// The live socket's byte clock (protocol v3 §H.1, R34a): a background
    /// drain's fallback end counts bytes, never only whole frames.
    read_clock: Arc<parking_lot::Mutex<Option<ReadClock>>>,
    /// Bounded queue for connection events (C-9). When set, the reader
    /// waits for room instead of calling the frame/binary/disconnect/
    /// reconnect callbacks, so a slow consumer stops the socket being read
    /// and TCP backpressure reaches the relay.
    event_sink: Arc<parking_lot::Mutex<Option<mpsc::Sender<TransportEvent>>>>,
}

/// `ws://` dev binding: BLAKE3 of the normalised relay origin (spec §4.1).
pub(crate) fn plain_channel_binding(
    server_url: &str,
    dev_origin: Option<&str>,
) -> Result<[u8; 32], RChatError> {
    let origin = crate::keyauth::relay_origin(dev_origin.unwrap_or(server_url)).map_err(|e| {
        RChatError::ConnectionFailed {
            message: format!("invalid relay origin: {e}"),
        }
    })?;
    crate::keyauth::dev_origin_binding(&origin).map_err(|e| RChatError::ConnectionFailed {
        message: format!("invalid relay origin: {e}"),
    })
}

/// Unsent bytes a call connection's kernel may hold before the socket
/// stops taking writes (`TCP_NOTSENT_LOWAT`, see `open_websocket`).
const CALL_NOTSENT_LOWAT: usize = 16 * 1024;
/// Send buffer of a call connection on Apple systems, bytes: their kernel
/// honours `TCP_NOTSENT_LOWAT` only when reporting the socket writable, and
/// a write still takes up to the whole send buffer, so a bound is kept.
#[cfg(target_vendor = "apple")]
const CALL_SEND_BUFFER: usize = 32 * 1024;

/// `TCP_NOTSENT_LOWAT` on a socket (Linux and Android 25, Apple 0x201).
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn set_notsent_lowat(tcp: &TcpStream, bytes: usize) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    #[cfg(target_vendor = "apple")]
    const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
    #[cfg(not(target_vendor = "apple"))]
    const TCP_NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;
    let v = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
    // SAFETY: a live socket fd owned by `tcp`, and a pointer to a c_int of
    // the size passed.
    let r = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn set_notsent_lowat(_tcp: &TcpStream, _bytes: usize) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// One WebSocket to `cfg.server_url`: DNS, TCP (keepalive 60 s / 10 s),
/// BoringSSL TLS 1.3 (with the ticket store) or the dev `ws://` path, and
/// the upgrade; returns it with its channel binding. `low_latency` turns on
/// `TCP_NODELAY` (call connections: 20 ms frames must not wait for Nagle).
pub(crate) async fn open_websocket(
    cfg: &TransportConfig,
    low_latency: bool,
) -> Result<(WebSocketStream<TransportStream>, [u8; 32]), RChatError> {
    let url = &cfg.server_url;

    // Parse URI to extract host and port for manual TCP connection
    let uri: tokio_tungstenite::tungstenite::http::Uri =
        url.parse().map_err(|e| RChatError::ConnectionFailed {
            message: format!("Invalid server URL: {}", e),
        })?;

    let host = uri.host().ok_or_else(|| RChatError::ConnectionFailed {
        message: "Server URL has no host".to_string(),
    })?;
    let is_wss = url.starts_with("wss://");
    if !is_wss && !plain_ws_allowed(host, !cfg!(debug_assertions)) {
        return Err(RChatError::ConnectionFailed {
            message: "ws:// is only allowed to a loopback relay; use wss://".to_string(),
        });
    }
    let port = uri.port_u16().unwrap_or(if is_wss { 443 } else { 80 });

    // DNS lookup, then TCP connect to each address in resolver order.
    let limit = Duration::from_secs(cfg.connection_timeout_secs);
    let addrs = resolve_within(
        tokio::net::lookup_host(format!("{}:{}", host, port)),
        DNS_TIMEOUT.min(limit),
    )
    .await?;
    let tcp_stream = connect_first(&addrs, TCP_CONNECT_TIMEOUT.min(limit), |addr| {
        TcpStream::connect(addr)
    })
    .await?;

    // Configure TCP keepalive for fast dead connection detection
    // Initial: 60s, Interval: 10s (matches RVPN settings)
    let tcp_stream = WebSocketClient::configure_tcp_keepalive(tcp_stream)
        .await
        .map_err(|e| RChatError::ConnectionFailed {
            message: format!("TCP keepalive configuration failed: {}", e),
        })?;
    if low_latency {
        tcp_stream
            .set_nodelay(true)
            .map_err(|e| RChatError::ConnectionFailed {
                message: format!("TCP_NODELAY failed: {e}"),
            })?;
        // Little unsent data in the kernel: with video on the same link, a
        // deep send buffer (auto-tuned to megabytes) holds seconds of stale
        // video that keep competing with the audio after the app has
        // dropped or paused it, and hides congestion from the adapter. The
        // low-water mark bounds only what is not yet sent, not what is in
        // flight, so a long fat path still fills. Best effort.
        if let Err(e) = set_notsent_lowat(&tcp_stream, CALL_NOTSENT_LOWAT) {
            log::debug!("TCP_NOTSENT_LOWAT on a call connection failed: {e}");
        }
        #[cfg(target_vendor = "apple")]
        if let Err(e) = socket2::SockRef::from(&tcp_stream).set_send_buffer_size(CALL_SEND_BUFFER) {
            log::debug!("send buffer on a call connection failed: {e}");
        }
    }

    // Establish TLS if needed, then perform WebSocket handshake
    let (stream, binding) = if is_wss {
        // BoringSSL; with a store, a ticket for the pinned relay is
        // offered and fresh ones kept (a refused ticket: full handshake).
        let fingerprint = cfg.tls_fingerprint;
        let handshake = async {
            match &cfg.resumption {
                Some(store) => connect_resumable(tcp_stream, host, port, fingerprint, store).await,
                None => connect_with_fingerprint(tcp_stream, host, fingerprint, None).await,
            }
        };
        let tls_stream = timeout(Duration::from_secs(cfg.connection_timeout_secs), handshake)
            .await
            .map_err(|_| RChatError::ConnectionFailed {
                message: "TLS handshake timeout".to_string(),
            })?
            .map_err(|e| RChatError::ConnectionFailed {
                message: format!("TLS handshake failed: {}", e),
            })?;
        let binding =
            tls_stream
                .export_channel_binding()
                .map_err(|e| RChatError::ConnectionFailed {
                    message: format!("TLS exporter unavailable: {}", e),
                })?;
        (TransportStream::tls(tls_stream), binding)
    } else {
        let binding = plain_channel_binding(url, cfg.dev_origin.as_deref())?;
        (TransportStream::plain(tcp_stream), binding)
    };

    // WebSocket handshake over the established stream.
    // Pass the URL string so tokio-tungstenite builds the request with
    // all required headers (Sec-WebSocket-Key, Upgrade, Connection, etc.).
    let result = timeout(
        Duration::from_secs(cfg.connection_timeout_secs),
        tokio_tungstenite::client_async_with_config(url, stream, Some(inbound_ws_config())),
    )
    .await;

    match result {
        Ok(Ok((ws_stream, _))) => Ok((ws_stream, binding)),
        Ok(Err(e)) => Err(RChatError::ConnectionFailed {
            message: format!("WebSocket error: {}", e),
        }),
        Err(_) => Err(RChatError::ConnectionFailed {
            message: "WebSocket handshake timeout".to_string(),
        }),
    }
}

impl WebSocketClient {
    /// Create a new WebSocket client
    pub fn new(config: TransportConfig) -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_frame_tx, frame_rx) = mpsc::unbounded_channel();

        Self {
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            tx,
            rx: Arc::new(RwLock::new(frame_rx)),
            last_received: Arc::new(RwLock::new(Instant::now())),
            message_callback: Arc::new(RwLock::new(None)),
            binary_callback: Arc::new(RwLock::new(None)),
            disconnect_callback: Arc::new(RwLock::new(None)),
            task_handle: Arc::new(RwLock::new(None)),
            outgoing_tx: Arc::new(RwLock::new(None)),
            outgoing_text_tx: Arc::new(RwLock::new(None)),
            should_reconnect: Arc::new(RwLock::new(true)),
            reconnect_attempt: Arc::new(RwLock::new(0)),
            reconnect_callback: Arc::new(RwLock::new(None)),
            reconnect_watcher_handle: Arc::new(RwLock::new(None)),
            channel_binding: Arc::new(parking_lot::Mutex::new(None)),
            read_clock: Arc::new(parking_lot::Mutex::new(None)),
            event_sink: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    /// Deliver frames, binary packets, disconnects and reconnects through
    /// `sink`, in arrival order, with backpressure (C-9). Replaces the
    /// corresponding callbacks.
    pub fn set_event_sink(&self, sink: mpsc::Sender<TransportEvent>) {
        *self.event_sink.lock() = Some(sink);
    }

    /// Set callback for received messages
    pub fn on_message_received<F>(&self, callback: F)
    where
        F: Fn(Frame) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.message_callback.try_write() {
            *guard = Some(Box::new(callback));
        }
    }

    /// Set callback for binary messages (relay packets)
    pub fn on_binary_received<F>(&self, callback: F)
    where
        F: Fn(Vec<u8>) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.binary_callback.try_write() {
            *guard = Some(Box::new(callback));
        }
    }

    /// Set callback for when the connection task ends
    pub fn on_disconnect<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.disconnect_callback.try_write() {
            *guard = Some(Box::new(callback));
        }
    }

    /// Set callback for when auto-reconnect succeeds
    pub fn on_reconnect<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.reconnect_callback.try_write() {
            *guard = Some(Box::new(callback));
        }
    }

    /// Connect to the server with automatic reconnection support
    pub async fn connect(&self) -> Result<(), RChatError> {
        let mut state = self.state.write().await;
        if *state != ConnectionState::Disconnected {
            return Err(RChatError::ConnectionFailed {
                message: "Already connected or connecting".to_string(),
            });
        }
        *state = ConnectionState::Connecting;
        drop(state);

        match self
            .try_connect_with_retries(self.config.reconnect_max_attempts)
            .await
        {
            Ok(()) => {
                if self.config.auto_reconnect {
                    // Only spawn watcher if one isn't already running
                    let has_watcher = {
                        let guard = self.reconnect_watcher_handle.read().await;
                        guard.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
                    };
                    if !has_watcher {
                        self.spawn_reconnect_watcher().await;
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Try to connect with a limited number of retries
    async fn try_connect_with_retries(&self, max_attempts: u32) -> Result<(), RChatError> {
        // Ensure at least one connection attempt
        let max = max_attempts.max(1);
        for attempt in 1..=max {
            match self.try_connect().await {
                Ok((ws_stream, binding)) => {
                    // Store before the reconnect callback can trigger a publish.
                    *self.channel_binding.lock() = Some(binding);
                    *self.state.write().await = ConnectionState::Connected;
                    *self.last_received.write().await = Instant::now();

                    let handle = self.spawn_connection_task(ws_stream);
                    *self.task_handle.write().await = Some(handle);

                    // Notify reconnect callback only on actual reconnects (not initial connect)
                    let was_reconnect = *self.reconnect_attempt.read().await > 0;
                    *self.reconnect_attempt.write().await = 0;
                    if was_reconnect {
                        let sink = self.event_sink.lock().clone();
                        if let Some(sink) = sink {
                            let _ = sink.send(TransportEvent::Reconnected).await;
                        } else {
                            let guard = self.reconnect_callback.read().await;
                            if let Some(cb) = guard.as_ref() {
                                cb();
                            }
                        }
                    }

                    return Ok(());
                }
                Err(e) => {
                    let delay =
                        reconnect_delay_secs(self.config.reconnect_base_delay_secs, attempt);

                    *self.state.write().await = ConnectionState::Reconnecting { attempt, max };

                    if attempt < max {
                        log::debug!(
                            "Connection attempt {} failed: {}, retrying in {}s",
                            attempt,
                            e,
                            delay
                        );
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    } else {
                        *self.state.write().await = ConnectionState::Disconnected;
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Spawn a background task that watches for connection drops and auto-reconnects
    async fn spawn_reconnect_watcher(&self) {
        let state = self.state.clone();
        let should_reconnect = self.should_reconnect.clone();
        let reconnect_attempt = self.reconnect_attempt.clone();
        let config = self.config.clone();
        let task_handle = self.task_handle.clone();

        // Clone self fields needed for reconnection
        let client_for_reconnect = WebSocketClient {
            config: config.clone(),
            state: state.clone(),
            tx: self.tx.clone(),
            rx: self.rx.clone(),
            last_received: self.last_received.clone(),
            message_callback: self.message_callback.clone(),
            binary_callback: self.binary_callback.clone(),
            disconnect_callback: self.disconnect_callback.clone(),
            task_handle: task_handle.clone(),
            outgoing_tx: self.outgoing_tx.clone(),
            outgoing_text_tx: self.outgoing_text_tx.clone(),
            should_reconnect: should_reconnect.clone(),
            reconnect_attempt: reconnect_attempt.clone(),
            reconnect_callback: self.reconnect_callback.clone(),
            reconnect_watcher_handle: Arc::new(RwLock::new(None)),
            channel_binding: self.channel_binding.clone(),
            read_clock: self.read_clock.clone(),
            event_sink: self.event_sink.clone(),
        };

        let handle = tokio::spawn(async move {
            loop {
                let should_stop = {
                    let guard = should_reconnect.read().await;
                    !*guard
                };
                if should_stop {
                    log::debug!("[RUST TRANSPORT] Auto-reconnect disabled, stopping watcher");
                    break;
                }

                // Poll the connection task handle without blocking
                let task_finished = {
                    let guard = task_handle.read().await;
                    if let Some(ref h) = *guard {
                        if h.is_finished() {
                            // Take and drop the handle to clean up
                            drop(guard);
                            let _ = task_handle.write().await.take();
                            true
                        } else {
                            false
                        }
                    } else {
                        true // No handle means no active connection
                    }
                };

                if !task_finished {
                    // Connection still healthy, check again in 1 second
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let current_state = *state.read().await;
                let should_reconnect_enabled = *should_reconnect.read().await;

                if !should_reconnect_enabled {
                    log::debug!("[RUST TRANSPORT] Not reconnecting: disabled");
                    break;
                }

                if current_state == ConnectionState::Disconnected {
                    log::debug!("[RUST TRANSPORT] Connection task ended, auto-reconnecting...");

                    let mut attempt_guard = reconnect_attempt.write().await;
                    *attempt_guard += 1;
                    let attempt = *attempt_guard;
                    drop(attempt_guard);

                    let max = config.reconnect_max_attempts_after_connect;
                    if max > 0 && attempt > max {
                        log::debug!("[RUST TRANSPORT] Max reconnect attempts ({}) reached", max);
                        break;
                    }

                    let delay = reconnect_delay_secs(config.reconnect_base_delay_secs, attempt);

                    log::debug!(
                        "[RUST TRANSPORT] Reconnect attempt {} in {}s",
                        attempt,
                        delay
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;

                    match client_for_reconnect.try_connect_with_retries(1).await {
                        Ok(()) => {
                            log::debug!("[RUST TRANSPORT] Auto-reconnect successful!");
                        }
                        Err(e) => {
                            log::debug!("[RUST TRANSPORT] Auto-reconnect failed: {}", e);
                        }
                    }
                }
            }
        });

        // Store the watcher handle
        let mut guard = self.reconnect_watcher_handle.write().await;
        *guard = Some(handle);
    }

    async fn try_connect(
        &self,
    ) -> Result<(WebSocketStream<TransportStream>, [u8; 32]), RChatError> {
        open_websocket(&self.config, false).await
    }

    /// Configure TCP keepalive on the underlying socket.
    /// Initial idle time: 60s, probe interval: 10s.
    /// On macOS/iOS, also sets retry count to 3.
    async fn configure_tcp_keepalive(tcp_stream: TcpStream) -> std::io::Result<TcpStream> {
        // Convert tokio TcpStream to std TcpStream to use socket2
        let std_stream = tcp_stream.into_std()?;
        let socket = socket2::Socket::from(std_stream);

        // Enable keepalive
        socket.set_keepalive(true)?;

        // Configure keepalive parameters
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10));

        socket.set_tcp_keepalive(&keepalive)?;

        // Ensure non-blocking mode for tokio
        socket.set_nonblocking(true)?;

        // Convert back to tokio TcpStream
        let std_stream = std::net::TcpStream::from(socket);
        TcpStream::from_std(std_stream)
    }

    fn spawn_connection_task(
        &self,
        ws_stream: WebSocketStream<TransportStream>,
    ) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        let last_received = self.last_received.clone();
        // Bytes arriving count as liveness, not only complete messages.
        let read_clock = ws_stream.get_ref().read_clock();
        *self.read_clock.lock() = Some(read_clock.clone());
        let message_callback = self.message_callback.clone();
        let binary_callback = self.binary_callback.clone();
        let disconnect_callback = self.disconnect_callback.clone();
        let channel_binding = self.channel_binding.clone();
        let event_sink = self.event_sink.lock().clone();
        let mut interval_rx = self
            .config
            .keepalive_live
            .as_ref()
            .map(KeepaliveInterval::subscribe);
        let mut keepalive_interval_secs = interval_rx
            .as_mut()
            .map(|rx| *rx.borrow_and_update())
            .unwrap_or(self.config.keepalive_interval_secs);
        let keepalive_timeout_secs = self.config.keepalive_timeout_secs;

        // Create channels for outgoing messages
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Vec<u8>>(OUTGOING_QUEUE_CAPACITY);
        let (outgoing_text_tx, mut outgoing_text_rx) =
            mpsc::channel::<String>(OUTGOING_QUEUE_CAPACITY);

        // Store the senders so send_binary/send_text can use them
        if let Ok(mut guard) = self.outgoing_tx.try_write() {
            *guard = Some(outgoing_tx.clone());
        }
        if let Ok(mut guard) = self.outgoing_text_tx.try_write() {
            *guard = Some(outgoing_text_tx.clone());
        }

        tokio::spawn(async move {
            let (mut ws_tx, mut ws_rx) = ws_stream.split();
            let mut next_keepalive =
                Instant::now() + keepalive_wait(keepalive_interval_secs, rand::random::<f64>());
            // The oldest ping with nothing read since it went out.
            let mut last_ping_sent: Option<Instant> = None;
            let dead_after = Duration::from_secs(keepalive_timeout_secs.saturating_mul(3));

            loop {
                tokio::select! {
                    // Handle outgoing binary messages
                    Some(data) = outgoing_rx.recv() => {
                        if ws_tx.send(Message::Binary(data)).await.is_err() {
                            log::debug!("Failed to send binary message");
                            break;
                        }
                    }

                    // Handle outgoing text messages
                    Some(text) = outgoing_text_rx.recv() => {
                        log::trace!("[RUST WEBSOCKET] Sending text frame: {} bytes", text.len());
                        if ws_tx.send(Message::Text(text)).await.is_err() {
                            log::debug!("[RUST WEBSOCKET] Failed to send text message");
                            break;
                        }
                        if ws_tx.flush().await.is_err() {
                            log::debug!("[RUST WEBSOCKET] Failed to flush text message");
                            break;
                        }
                        log::trace!("[RUST WEBSOCKET] Text frame sent and flushed successfully");
                    }

                    // Handle incoming WebSocket messages
                    msg = ws_rx.next() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                *last_received.write().await = Instant::now();
                                last_ping_sent = None;

                                log::trace!("[RUST] Received binary data: {} bytes", data.len());

                                // First, try to decode as a control message
                                if let Some(frame) = Frame::decode(&data) {
                                    // Handle keepalive pings from server - respond immediately with pong
                                    if let Frame::Keepalive(KeepaliveMessage::Ping { timestamp }) = &frame {
                                        let pong = KeepaliveMessage::Pong {
                                            ping_timestamp: *timestamp,
                                            timestamp: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs(),
                                        };
                                        let _ = ws_tx.send(Message::Binary(pong.encode_with_frame_type())).await;
                                        // Don't notify callback for keepalive pings
                                        continue;
                                    }

                                    // Handle keepalive pongs - just update last_received (already done above)
                                    if let Frame::Keepalive(KeepaliveMessage::Pong { .. }) = &frame {
                                        // Pong received, connection is alive
                                        continue;
                                    }

                                    // Notify the consumer (waits for room in the sink).
                                    if let Some(sink) = &event_sink {
                                        if sink.send(TransportEvent::Frame(Box::new(frame))).await.is_err() {
                                            break;
                                        }
                                    } else if let Some(cb) = message_callback.read().await.as_ref() {
                                        cb(frame);
                                    }
                                } else {
                                    // Not a recognized frame, pass as binary
                                    log::trace!("[RUST] Failed to decode frame, passing as binary: {} bytes", data.len());
                                    if let Some(sink) = &event_sink {
                                        if sink.send(TransportEvent::Binary(data)).await.is_err() {
                                            break;
                                        }
                                    } else if let Some(cb) = binary_callback.read().await.as_ref() {
                                        cb(data);
                                    }
                                }
                            }
                            Some(Ok(Message::Text(text))) => {
                                *last_received.write().await = Instant::now();
                                last_ping_sent = None;

                                // Handle text frames (signaling messages)
                                // Text frames are JSON-encoded signaling messages
                                if let Ok(signaling) = serde_json::from_str::<crate::protocol::SignalingMessage>(&text) {
                                    let frame = Frame::Signaling(signaling);
                                    if let Some(sink) = &event_sink {
                                        if sink.send(TransportEvent::Frame(Box::new(frame))).await.is_err() {
                                            break;
                                        }
                                    } else if let Some(cb) = message_callback.read().await.as_ref() {
                                        cb(frame);
                                    }
                                }
                            }
                            Some(Ok(Message::Ping(_))) => {
                                *last_received.write().await = Instant::now();
                            }
                            Some(Ok(Message::Pong(_))) => {
                                *last_received.write().await = Instant::now();
                                last_ping_sent = None;
                            }
                            Some(Ok(Message::Close(_))) => {
                                log::debug!("WebSocket closed by server");
                                break;
                            }
                            Some(Ok(Message::Frame(_))) => {
                                // Raw frame - ignore
                            }
                            Some(Err(e)) => {
                                log::debug!("WebSocket error: {}", e);
                                break;
                            }
                            None => {
                                log::debug!("WebSocket stream ended");
                                break;
                            }
                        }
                    }

                    // Dead: a ping has gone unanswered for `dead_after`. Armed
                    // only while one is outstanding, so it cannot spin; it
                    // does not move the ping schedule.
                    _ = tokio::time::sleep_until(last_ping_sent.unwrap_or_else(Instant::now) + dead_after),
                        if last_ping_sent.is_some() =>
                    {
                        if let Some(sent) = last_ping_sent {
                            let last = (*last_received.read().await).max(read_clock.last());
                            if last < sent {
                                log::debug!("Connection appears dead - ping unanswered for {:?}", sent.elapsed());
                                break;
                            }
                            // Bytes arrived since: the ping was answered.
                            last_ping_sent = None;
                        }
                    }

                    // The interval changed (the app went to, or came back
                    // from, the background): the next ping follows it.
                    alive = interval_changed(&mut interval_rx) => {
                        if !alive {
                            interval_rx = None;
                        } else if let Some(rx) = interval_rx.as_mut() {
                            let previous = keepalive_interval_secs;
                            keepalive_interval_secs = *rx.borrow_and_update();
                            next_keepalive = if keepalive_interval_secs < previous {
                                // Back from the background: probe now, so a
                                // connection that died while the interval was
                                // long is found within `dead_after`.
                                Instant::now()
                            } else {
                                Instant::now()
                                    + keepalive_wait(keepalive_interval_secs, rand::random::<f64>())
                            };
                        }
                    }

                    // Send keepalive pings
                    _ = tokio::time::sleep_until(next_keepalive) => {
                        next_keepalive = Instant::now()
                            + keepalive_wait(keepalive_interval_secs, rand::random::<f64>());
                        // The later of the last complete message and the
                        // last bytes read: a slow large message is alive.
                        let last = (*last_received.read().await).max(read_clock.last());

                        // Dead only when a ping went unanswered: nothing read
                        // for `keepalive_timeout_secs * 3` since it was sent.
                        // Measured from the last data instead, a quiet but
                        // healthy connection was dropped whenever the jittered
                        // wait (up to interval + 8 s) ran past that limit.
                        let unanswered = last_ping_sent.filter(|sent| last < *sent);
                        if let Some(sent) = unanswered {
                            if sent.elapsed() >= dead_after {
                                log::debug!("Connection appears dead - ping unanswered for {:?}", sent.elapsed());
                                break;
                            }
                        }

                        // Send ping
                        let ping = KeepaliveMessage::Ping {
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };

                        if ws_tx.send(Message::Binary(ping.encode_with_frame_type())).await.is_err() {
                            log::debug!("Failed to send ping");
                            break;
                        }

                        if unanswered.is_none() {
                            last_ping_sent = Some(Instant::now());
                        }
                    }
                }
            }

            // Connection lost
            *state.write().await = ConnectionState::Disconnected;
            *channel_binding.lock() = None;
            log::debug!("Connection task ended");

            // Notify the consumer
            if let Some(sink) = &event_sink {
                let _ = sink.send(TransportEvent::Disconnected).await;
            } else if let Some(cb) = disconnect_callback.read().await.as_ref() {
                cb();
            }
        })
    }

    /// Send a frame without waiting for confirmation
    pub async fn send_frame(&self, frame: Frame) -> Result<(), RChatError> {
        let state = *self.state.read().await;
        if state != ConnectionState::Connected {
            return Err(RChatError::NotConnected);
        }

        let data = match &frame {
            Frame::Relay(packet) => packet.encode_with_frame_type(),
            Frame::Control(msg) => msg.encode_with_frame_type(),
            Frame::Keepalive(msg) => msg.encode_with_frame_type(),
            _ => {
                return Err(RChatError::Internal {
                    message: "Unsupported frame type".to_string(),
                })
            }
        };

        self.send_binary(data).await
    }

    /// Send raw binary data
    pub async fn send_binary(&self, data: Vec<u8>) -> Result<(), RChatError> {
        let state = *self.state.read().await;
        if state != ConnectionState::Connected {
            return Err(RChatError::NotConnected);
        }

        // Get the outgoing sender from outgoing_tx. Clone it out so the lock
        // is not held while waiting for queue space.
        let sender = self.outgoing_tx.read().await.clone();
        if let Some(sender) = sender {
            match tokio::time::timeout(OUTGOING_SEND_TIMEOUT, sender.send(data)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(RChatError::ConnectionFailed {
                    message: "Failed to queue message".to_string(),
                }),
                Err(_) => Err(RChatError::ConnectionFailed {
                    message: "Outgoing queue full".to_string(),
                }),
            }
        } else {
            Err(RChatError::ConnectionFailed {
                message: "Outgoing channel not initialized".to_string(),
            })
        }
    }

    /// Send raw text data (for JSON signaling messages)
    pub async fn send_text(&self, text: String) -> Result<(), RChatError> {
        let state = *self.state.read().await;
        if state != ConnectionState::Connected {
            log::debug!(
                "[RUST TRANSPORT] send_text FAILED: not connected, state={:?}",
                state
            );
            return Err(RChatError::NotConnected);
        }

        // Get the outgoing text sender
        let sender = self.outgoing_text_tx.read().await.clone();
        if let Some(sender) = sender {
            log::trace!("[RUST TRANSPORT] send_text: queuing {} bytes", text.len());
            match tokio::time::timeout(OUTGOING_SEND_TIMEOUT, sender.send(text)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Err(RChatError::ConnectionFailed {
                        message: "Failed to queue text message".to_string(),
                    })
                }
                Err(_) => {
                    return Err(RChatError::ConnectionFailed {
                        message: "Outgoing text queue full".to_string(),
                    })
                }
            }
            log::trace!("[RUST TRANSPORT] send_text: queued successfully");
            Ok(())
        } else {
            log::debug!("[RUST TRANSPORT] send_text FAILED: outgoing_text_tx not initialized");
            Err(RChatError::ConnectionFailed {
                message: "Outgoing text channel not initialized".to_string(),
            })
        }
    }

    /// Send a control message
    pub async fn send_control(&self, msg: ControlMessage) -> Result<(), RChatError> {
        self.send_frame(Frame::Control(msg)).await
    }

    /// Clone the outgoing binary sender for fire-and-forget sends from
    /// synchronous callbacks (e.g. delivery receipts). The queue is bounded
    /// (`OUTGOING_QUEUE_CAPACITY`), so callers must use `try_send` and handle
    /// a full queue.
    pub fn outgoing_sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.outgoing_tx.try_read().ok().and_then(|g| g.clone())
    }

    /// Channel binding of the live connection (None while disconnected).
    pub fn channel_binding(&self) -> Option<[u8; 32]> {
        *self.channel_binding.lock()
    }
    #[cfg(test)]
    pub(crate) fn set_channel_binding_for_test(&self, b: Option<[u8; 32]>) {
        *self.channel_binding.lock() = b;
    }

    /// Stop the connection and auto-reconnect from synchronous code (protocol
    /// failures). Outside a Tokio runtime only the binding is cleared.
    pub fn shutdown_now(&self) {
        *self.channel_binding.lock() = None;
        if let Ok(mut tx) = self.outgoing_tx.try_write() {
            *tx = None;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let should_reconnect = self.should_reconnect.clone();
        let state = self.state.clone();
        let task = self.task_handle.clone();
        let watcher = self.reconnect_watcher_handle.clone();
        handle.spawn(async move {
            *should_reconnect.write().await = false;
            *state.write().await = ConnectionState::Disconnected;
            if let Some(h) = task.write().await.take() {
                h.abort();
            }
            if let Some(h) = watcher.write().await.take() {
                h.abort();
            }
        });
    }

    /// Test hook: install an outgoing binary queue without a socket.
    #[cfg(test)]
    pub(crate) fn install_outgoing_for_test(&self, tx: mpsc::Sender<Vec<u8>>) {
        *self.outgoing_tx.try_write().expect("uncontended in tests") = Some(tx);
    }

    /// Tests only: let the async send path (`send_frame`) through.
    #[cfg(test)]
    pub(crate) fn set_connected_for_test(&self) {
        *self.state.try_write().expect("uncontended in tests") = ConnectionState::Connected;
    }

    /// Send a relay packet
    pub async fn send_relay(&self, packet: RelayPacket) -> Result<(), RChatError> {
        self.send_frame(Frame::Relay(packet)).await
    }

    /// Receive a frame (non-blocking)
    pub async fn try_receive(&self) -> Option<Frame> {
        self.rx.write().await.try_recv().ok()
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Disconnect from the server
    pub async fn disconnect(&self) {
        *self.channel_binding.lock() = None;
        *self.should_reconnect.write().await = false;
        *self.state.write().await = ConnectionState::Disconnected;
        let _ = self.tx.send(InternalMessage::Disconnect);
        if let Some(handle) = self.task_handle.write().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.reconnect_watcher_handle.write().await.take() {
            handle.abort();
        }
    }

    /// When the current socket last delivered any bytes (None before one
    /// is open). Moves for every TLS record read, also mid-frame.
    pub(crate) fn last_bytes_at(&self) -> Option<std::time::Instant> {
        self.read_clock.lock().as_ref().map(|c| c.last().into_std())
    }

    /// Check if connection is healthy (received data recently)
    pub async fn is_healthy(&self) -> bool {
        let last = *self.last_received.read().await;
        // The live interval (it stretches in the background), not the configured one.
        let interval = self
            .config
            .keepalive_live
            .as_ref()
            .map_or(self.config.keepalive_interval_secs, KeepaliveInterval::get);
        let timeout = Duration::from_secs(interval.saturating_mul(2));
        last.elapsed() < timeout
    }
}

/// Plain `ws://` carries the key-authentication proof over cleartext with a
/// public origin hash as its binding, so release builds allow it only to a
/// loopback host (C-16, spec §4.9 L7); debug builds allow any host.
pub(crate) fn plain_ws_allowed(host: &str, release: bool) -> bool {
    if !release {
        return true;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Seconds to wait before reconnect attempt `attempt` (1-based): the base
/// delay doubled per attempt, capped at 30 s. Never overflows, whatever the
/// attempt count or base (C-15).
pub(crate) fn reconnect_delay_secs(base_secs: u64, attempt: u32) -> u64 {
    let doublings = attempt.saturating_sub(1).min(5);
    base_secs.saturating_mul(1u64 << doublings).min(30)
}

/// Next keepalive wait (spec §5.7): uniform in [max(5, i - 8), i + 8] seconds,
/// drawn afresh after every ping so pings carry no fixed rhythm.
pub(crate) fn keepalive_wait(interval_secs: u64, r: f64) -> Duration {
    let lo = interval_secs.saturating_sub(8).max(5) as f64;
    let hi = interval_secs.saturating_add(8) as f64;
    let r = if r.is_nan() { 0.0 } else { r.clamp(0.0, 1.0) };
    Duration::from_millis(((lo + r * (hi - lo)) * 1000.0).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-15: the backoff never overflows, for any attempt count or base.
    #[test]
    fn reconnect_delay_saturates() {
        assert_eq!(super::reconnect_delay_secs(1, 1), 1);
        assert_eq!(super::reconnect_delay_secs(1, 2), 2);
        assert_eq!(super::reconnect_delay_secs(1, 5), 16);
        assert_eq!(super::reconnect_delay_secs(1, 6), 30);
        assert_eq!(super::reconnect_delay_secs(1, 0), 1);
        assert_eq!(super::reconnect_delay_secs(1, 70), 30);
        assert_eq!(super::reconnect_delay_secs(1, u32::MAX), 30);
        assert_eq!(super::reconnect_delay_secs(u64::MAX, 70), 30);
    }

    /// TM3: keepalive waits are jittered around the interval.
    #[test]
    fn tm3_keepalive_wait_bounds() {
        assert_eq!(super::keepalive_wait(30, 0.0), Duration::from_secs(22));
        assert_eq!(super::keepalive_wait(30, 1.0), Duration::from_secs(38));
        assert_eq!(super::keepalive_wait(6, 0.0), Duration::from_secs(5));
        assert_eq!(super::keepalive_wait(6, 1.0), Duration::from_secs(14));
        assert_eq!(
            super::keepalive_wait(30, 2.0),
            Duration::from_secs(38),
            "clamped"
        );
        assert_eq!(super::keepalive_wait(30, f64::NAN), Duration::from_secs(22));
        for _ in 0..1000 {
            let w = super::keepalive_wait(30, rand::random::<f64>());
            assert!(w >= Duration::from_secs(22) && w <= Duration::from_secs(38));
        }
    }

    /// C-16: release builds refuse ws:// to anything but loopback.
    #[test]
    fn plain_ws_only_to_loopback_in_release() {
        for host in [
            "127.0.0.1",
            "127.9.9.9",
            "localhost",
            "LOCALHOST",
            "::1",
            "[::1]",
        ] {
            assert!(super::plain_ws_allowed(host, true), "{host}");
        }
        for host in [
            "example.com",
            "10.0.0.2",
            "192.168.1.5",
            "[2001:db8::1]",
            "localhost.evil",
        ] {
            assert!(!super::plain_ws_allowed(host, true), "{host}");
            assert!(super::plain_ws_allowed(host, false), "debug: {host}");
        }
    }

    /// A local relay that runs `script` on the accepted socket.
    async fn local_relay<F, Fut>(script: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            script(ws).await;
        });
        (format!("ws://{addr}/"), task)
    }

    fn connected_client(url: String) -> WebSocketClient {
        WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            ..TransportConfig::default()
        })
    }

    /// C-9: with an event sink, a consumer that falls behind stops the
    /// socket being read: the queue stays at its capacity and nothing is
    /// lost or reordered.
    #[tokio::test]
    async fn event_sink_applies_backpressure_without_loss() {
        const N: usize = 200;
        let (url, relay) = local_relay(|mut ws| async move {
            for n in 0..N {
                let frame = ControlMessage::QueuedMessage {
                    payload: (n as u32).to_be_bytes().to_vec(),
                };
                if ws
                    .send(Message::Binary(frame.encode_with_frame_type()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = ws.next().await;
        })
        .await;
        let client = connected_client(url);
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(4);
        client.set_event_sink(tx.clone());
        client.connect().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(tx.capacity(), 0, "the queue is full, and bounded at 4");
        drop(tx);
        for n in 0..N {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(TransportEvent::Frame(f))) => match *f {
                    Frame::Control(ControlMessage::QueuedMessage { payload }) => {
                        assert_eq!(payload, (n as u32).to_be_bytes().to_vec())
                    }
                    other => panic!("event {n}: {other:?}"),
                },
                other => panic!("event {n}: {other:?}"),
            }
        }
        client.disconnect().await;
        relay.abort();
    }

    #[tokio::test]
    async fn outgoing_sender_is_bounded_and_try_send_reports_full() {
        let client = WebSocketClient::new(TransportConfig::default());
        assert!(client.outgoing_sender().is_none());
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        *client.outgoing_tx.write().await = Some(tx);
        let sender = client.outgoing_sender().unwrap();
        assert!(sender.try_send(vec![1]).is_ok());
        assert!(
            sender.try_send(vec![2]).is_err(),
            "full queue must be reported"
        );
        assert_eq!(rx.recv().await, Some(vec![1]));
        assert!(sender.try_send(vec![3]).is_ok());
    }

    #[tokio::test]
    async fn test_websocket_client_creation() {
        let config = TransportConfig::default();
        let client = WebSocketClient::new(config);
        assert!(matches!(
            client.state().await,
            ConnectionState::Disconnected
        ));
    }

    #[tokio::test]
    async fn test_tcp_keepalive_configuration() {
        // Bind a local TCP listener to get a connected socket pair
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        // Connect a client stream
        let client_stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();

        // Apply keepalive configuration
        let configured = WebSocketClient::configure_tcp_keepalive(client_stream).await;
        assert!(
            configured.is_ok(),
            "TCP keepalive configuration failed: {:?}",
            configured.err()
        );

        // Verify the stream is still usable after configuration
        let stream = configured.unwrap();
        assert!(stream.writable().await.is_ok());
    }

    /// ws:// binding = BLAKE3 of the normalised relay origin (golden vector
    /// shared with keyauth); an explicit dev_origin overrides the URL.
    #[test]
    fn plain_binding_hashes_the_relay_origin() {
        let golden = "dc0d2d9890cc672819a084e35d4f242202c9bb548e2f76d0fa3222b9a9475725";
        assert_eq!(
            hex::encode(plain_channel_binding("ws://127.0.0.1:8443/relay", None).unwrap()),
            golden
        );
        assert_eq!(
            hex::encode(
                plain_channel_binding("ws://elsewhere:1/x", Some("WS://127.0.0.1:8443")).unwrap()
            ),
            golden
        );
        assert!(plain_channel_binding("not a url", None).is_err());
    }

    /// A malicious relay cannot make the client buffer an arbitrarily large
    /// message: one byte over `MAX_INBOUND_MESSAGE_BYTES` is refused, a
    /// message at the limit is accepted.
    #[tokio::test]
    async fn inbound_messages_over_the_cap_are_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::Binary(vec![1u8; MAX_INBOUND_MESSAGE_BYTES]))
                .await
                .unwrap();
            let _ = ws
                .send(Message::Binary(vec![2u8; MAX_INBOUND_MESSAGE_BYTES + 1]))
                .await;
            // Keep the socket open until the client has read both.
            let _ = ws.next().await;
        });
        let client = WebSocketClient::new(TransportConfig {
            server_url: format!("ws://{addr}/"),
            ..TransportConfig::default()
        });
        let (mut ws, _) = client.try_connect().await.unwrap();
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => assert_eq!(b.len(), MAX_INBOUND_MESSAGE_BYTES),
            other => panic!("message at the cap not delivered: {other:?}"),
        }
        assert!(
            matches!(ws.next().await, Some(Err(_)) | None),
            "oversized message must be refused"
        );
        drop(ws);
        server.abort();
    }

    /// Debug-voice-loss: a large message arriving slowly (a photo or voice
    /// note over a thin relay link) is liveness, not silence. Bytes keep
    /// arriving, but no message completes for longer than the dead
    /// threshold (`keepalive_timeout_secs * 3`, here 3 s); the client must
    /// not declare the connection dead and drop it mid-message (the relay
    /// has already acknowledged the message to its sender and cannot
    /// resend a frame its writer has taken).
    #[tokio::test]
    async fn slow_large_message_keeps_the_connection_alive() {
        use tokio::io::AsyncWriteExt;
        const CHUNK: usize = 1024;
        const CHUNKS: usize = 40; // 40 KiB over ~12 s: 4x the dead threshold
        let (url, relay) = local_relay(|mut ws| async move {
            // One unmasked binary frame (FIN | opcode 2), 64-bit length,
            // written by hand a chunk at a time.
            let len = (CHUNK * CHUNKS) as u64;
            let mut header = vec![0x82u8, 127];
            header.extend_from_slice(&len.to_be_bytes());
            let tcp = ws.get_mut();
            if tcp.write_all(&header).await.is_err() {
                return;
            }
            for i in 0..CHUNKS {
                tokio::time::sleep(Duration::from_millis(300)).await;
                if tcp.write_all(&[i as u8; CHUNK]).await.is_err() {
                    return;
                }
            }
            // Keep the socket open until the client goes.
            let _ = ws.next().await;
        })
        .await;
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_interval_secs: 1, // first check after 5-9 s
            keepalive_timeout_secs: 1,  // dead after 3 s without data
            ..TransportConfig::default()
        });
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(30), rx.recv()).await;
        match event {
            Ok(Some(TransportEvent::Binary(data))) => {
                assert_eq!(data.len(), CHUNK * CHUNKS);
                assert_eq!(data[CHUNK * CHUNKS - 1], (CHUNKS - 1) as u8);
            }
            other => panic!("the slow message never arrived: {other:?}"),
        }
        client.disconnect().await;
        relay.abort();
    }

    /// An armed `ResetOnClose` makes the close a reset (the peer reads an
    /// error, and unsent data is discarded); unarmed, a normal close (the
    /// peer reads the data, then the end).
    #[tokio::test]
    async fn an_armed_stream_closes_with_a_reset() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for armed in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
            let mut stream = TransportStream::plain(client.unwrap());
            let mut server = server.unwrap().0;
            stream.write_all(&[7; 1000]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            if armed {
                stream.reset_on_close().arm();
            }
            drop(stream);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut buf = vec![0u8; 4096];
            let mut got = 0;
            let ended = loop {
                match server.read(&mut buf).await {
                    Ok(0) => break Ok(()),
                    Ok(n) => got += n,
                    Err(e) => break Err(e.kind()),
                }
            };
            if armed {
                assert_eq!(ended, Err(std::io::ErrorKind::ConnectionReset));
            } else {
                assert_eq!((ended, got), (Ok(()), 1000));
            }
        }
    }

    /// TG-3: a read that delivers no bytes - nothing available yet
    /// (Pending) or end of stream (Ready with nothing filled) - leaves the
    /// clock where it was; a read that delivers bytes moves it.
    #[tokio::test]
    async fn read_clock_moves_only_when_bytes_arrive() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut stream = TransportStream::plain(client.unwrap());
        let (mut peer, _) = server.unwrap();
        let clock = stream.read_clock();
        let start = clock.last();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Nothing sent yet: Pending, clock unchanged.
        let mut byte = [0u8; 1];
        let pending = std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut byte);
            Poll::Ready(Pin::new(&mut stream).poll_read(cx, &mut buf).is_pending())
        })
        .await;
        assert!(pending, "nothing to read yet");
        assert_eq!(clock.last(), start, "Pending must not count as liveness");

        // Bytes: the clock moves.
        peer.write_all(b"x").await.unwrap();
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
        let moved = clock.last();
        assert!(moved > start, "bytes count as liveness");
        tokio::time::sleep(Duration::from_millis(20)).await;

        // End of stream: Ready with nothing filled, clock unchanged.
        drop(peer);
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        assert_eq!(clock.last(), moved, "EOF must not count as liveness");
    }

    /// A quiet relay that answers every ping (as the real one does) keeps
    /// the connection, however long the jittered wait runs past the dead
    /// limit: here every wait (5-9 s) is over it (3 s).
    #[tokio::test]
    async fn answered_pings_keep_a_quiet_connection() {
        let (url, relay) = local_relay(|mut ws| async move {
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Binary(data) = msg {
                    if let Some(Frame::Keepalive(KeepaliveMessage::Ping { timestamp })) =
                        Frame::decode(&data)
                    {
                        let pong = KeepaliveMessage::Pong {
                            ping_timestamp: timestamp,
                            timestamp,
                        };
                        if ws
                            .send(Message::Binary(pong.encode_with_frame_type()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        })
        .await;
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_interval_secs: 1,
            keepalive_timeout_secs: 1,
            ..TransportConfig::default()
        });
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(25), rx.recv()).await;
        assert!(
            event.is_err(),
            "a connection whose pings are answered was dropped: {event:?}"
        );
        client.disconnect().await;
        relay.abort();
    }

    /// The other half: a relay that stops sending bytes mid-message (socket
    /// open, nothing arriving) is still declared dead.
    #[tokio::test]
    async fn stalled_message_still_ends_the_connection() {
        use tokio::io::AsyncWriteExt;
        let (url, relay) = local_relay(|mut ws| async move {
            let mut frame = vec![0x82u8, 127];
            frame.extend_from_slice(&(64 * 1024u64).to_be_bytes());
            frame.extend_from_slice(&[7u8; 1024]);
            let _ = ws.get_mut().write_all(&frame).await;
            // Silent from here on, socket open.
            tokio::time::sleep(Duration::from_secs(60)).await;
        })
        .await;
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_interval_secs: 1,
            keepalive_timeout_secs: 1,
            ..TransportConfig::default()
        });
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(30), rx.recv()).await;
        assert!(
            matches!(event, Ok(Some(TransportEvent::Disconnected))),
            "a stalled connection must be declared dead: {event:?}"
        );
        client.disconnect().await;
        relay.abort();
    }

    /// DNS that never answers is abandoned at the limit, with a message
    /// that names no host.
    #[tokio::test(start_paused = true)]
    async fn dns_lookup_that_never_answers_times_out() {
        let started = Instant::now();
        let r = resolve_within(
            std::future::pending::<std::io::Result<std::vec::IntoIter<SocketAddr>>>(),
            DNS_TIMEOUT,
        )
        .await;
        assert_eq!(started.elapsed(), DNS_TIMEOUT);
        match r {
            Err(RChatError::ConnectionFailed { message }) => {
                assert_eq!(message, "DNS lookup timeout")
            }
            other => panic!("{other:?}"),
        }
        let ok = resolve_within(
            async { Ok(vec!["127.0.0.1:1".parse().unwrap()].into_iter()) },
            DNS_TIMEOUT,
        )
        .await;
        assert_eq!(ok.unwrap().len(), 1);
    }

    /// A hanging first address costs `per_try`, not the whole connection
    /// timeout, and the next address is tried.
    #[tokio::test(start_paused = true)]
    async fn connect_tries_the_next_address_when_one_hangs() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let started = Instant::now();
        let got = connect_first(&[first, second], TCP_CONNECT_TIMEOUT, |addr| async move {
            if addr == first {
                std::future::pending::<()>().await;
            }
            Ok(addr)
        })
        .await;
        assert_eq!(got.unwrap(), second);
        assert_eq!(started.elapsed(), TCP_CONNECT_TIMEOUT);
    }

    /// When every address fails, the last error is the one returned, in the
    /// same words as before.
    #[tokio::test(start_paused = true)]
    async fn connect_keeps_the_last_error_when_all_fail() {
        let addrs: Vec<SocketAddr> = vec![
            "192.0.2.1:1".parse().unwrap(),
            "192.0.2.2:1".parse().unwrap(),
        ];
        let msg = |r: Result<(), RChatError>| match r {
            Err(RChatError::ConnectionFailed { message }) => message,
            other => panic!("{other:?}"),
        };
        // Refused, then timed out: the timeout is last.
        let r = connect_first(&addrs, TCP_CONNECT_TIMEOUT, |addr| async move {
            if addr == addrs_first() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            std::future::pending().await
        })
        .await;
        assert_eq!(msg(r), "TCP connection timeout");
        // Timed out, then refused: the refusal is last.
        let r = connect_first(&addrs, TCP_CONNECT_TIMEOUT, |addr| async move {
            if addr != addrs_first() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            std::future::pending().await
        })
        .await;
        assert!(msg(r).starts_with("TCP connection failed: "));
        // Nothing to try.
        let r = connect_first::<(), _, _>(&[], TCP_CONNECT_TIMEOUT, |_| async { Ok(()) }).await;
        assert_eq!(msg(r), "No addresses resolved");
    }

    fn addrs_first() -> SocketAddr {
        "192.0.2.1:1".parse().unwrap()
    }

    /// A relay that reads everything and never answers. Reports when each
    /// ping reached it (std clock, so it is independent of the client's).
    async fn silent_relay(
        pings: mpsc::UnboundedSender<std::time::Instant>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        local_relay(|mut ws| async move {
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Binary(data) = msg {
                    if let Some(Frame::Keepalive(KeepaliveMessage::Ping { .. })) =
                        Frame::decode(&data)
                    {
                        let _ = pings.send(std::time::Instant::now());
                    }
                }
            }
        })
        .await
    }

    /// A silent relay is noticed `keepalive_timeout_secs * 3` after the
    /// ping, not at the next tick (5-9 s later, with an interval of 1).
    #[tokio::test]
    async fn silent_relay_is_declared_dead_soon_after_the_ping() {
        let (ping_tx, mut ping_rx) = mpsc::unbounded_channel();
        let (url, relay) = silent_relay(ping_tx).await;
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_interval_secs: 1,
            keepalive_timeout_secs: 1,
            ..TransportConfig::default()
        });
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(30), rx.recv()).await;
        let seen = std::time::Instant::now();
        assert!(
            matches!(event, Ok(Some(TransportEvent::Disconnected))),
            "{event:?}"
        );
        let first_ping = ping_rx.recv().await.expect("the relay saw a ping");
        let gap = seen.duration_since(first_ping);
        assert!(
            gap >= Duration::from_millis(2500) && gap < Duration::from_millis(4500),
            "dead {gap:?} after the ping; want about 3 s (the old rule needed 5-9 s)"
        );
        client.disconnect().await;
        relay.abort();
    }

    /// The deadline is measured from the oldest unanswered ping: further
    /// pings sent while the relay stays silent do not push it out.
    #[tokio::test]
    async fn oldest_unanswered_ping_is_the_one_timed() {
        let (ping_tx, mut ping_rx) = mpsc::unbounded_channel();
        let (url, relay) = silent_relay(ping_tx).await;
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_interval_secs: 1, // a tick every 5-9 s
            keepalive_timeout_secs: 4,  // dead 12 s after the first ping
            ..TransportConfig::default()
        });
        let (tx, mut rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(40), rx.recv()).await;
        let seen = std::time::Instant::now();
        assert!(
            matches!(event, Ok(Some(TransportEvent::Disconnected))),
            "{event:?}"
        );
        let first_ping = ping_rx.recv().await.expect("the relay saw a ping");
        let mut count = 1;
        while ping_rx.try_recv().is_ok() {
            count += 1;
        }
        assert!(count >= 2, "a later tick sent another ping ({count})");
        let gap = seen.duration_since(first_ping);
        assert!(
            gap >= Duration::from_millis(11900) && gap < Duration::from_millis(13500),
            "dead {gap:?} after the first ping; want about 12 s"
        );
        client.disconnect().await;
        relay.abort();
    }

    /// Android background receiving: the live interval floors at 1 s and
    /// notifies only on a real change.
    #[test]
    fn keepalive_interval_floors_and_notifies_only_on_change() {
        let k = KeepaliveInterval::new(0);
        assert_eq!(k.get(), 1);
        let mut rx = k.subscribe();
        k.set(1);
        assert!(!rx.has_changed().unwrap(), "same value: no change");
        k.set(240);
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), 240);
        k.set(0);
        assert_eq!(k.get(), 1);
    }

    /// A live change reschedules the next ping at once. Going to a shorter
    /// interval (the app came back to the foreground) pings immediately, so
    /// a connection that died while it slept is found by the dead-after-ping
    /// rule instead of being trusted for another interval (final review
    /// I-1); back at 240 s none follows.
    #[tokio::test]
    async fn a_live_interval_change_reschedules_the_next_ping() {
        let (ping_tx, mut ping_rx) = mpsc::unbounded_channel();
        let (url, relay) = silent_relay(ping_tx).await;
        let live = KeepaliveInterval::new(240);
        let client = WebSocketClient::new(TransportConfig {
            server_url: url,
            auto_reconnect: false,
            reconnect_max_attempts: 1,
            keepalive_timeout_secs: 60, // dead only 180 s after a ping: never in this test
            keepalive_live: Some(live.clone()),
            ..TransportConfig::default()
        });
        let (tx, _rx) = mpsc::channel::<TransportEvent>(8);
        client.set_event_sink(tx);
        client.connect().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(ping_rx.try_recv().is_err(), "no ping at a 240 s interval");
        let changed = std::time::Instant::now();
        live.set(1);
        let first = tokio::time::timeout(Duration::from_secs(12), ping_rx.recv())
            .await
            .expect("a ping after the change")
            .expect("the relay saw a ping");
        let gap = first.duration_since(changed);
        assert!(
            gap < Duration::from_secs(2),
            "first ping {gap:?} after the change; want at once"
        );
        live.set(240);
        tokio::time::sleep(Duration::from_millis(200)).await;
        while ping_rx.try_recv().is_ok() {}
        assert!(
            tokio::time::timeout(Duration::from_secs(12), ping_rx.recv())
                .await
                .is_err(),
            "no ping within 12 s once back at 240 s"
        );
        client.disconnect().await;
        relay.abort();
    }

    /// Final review M-6: health is judged against the live interval.
    #[tokio::test]
    async fn is_healthy_uses_the_live_interval() {
        let live = KeepaliveInterval::new(240);
        let client = WebSocketClient::new(TransportConfig {
            keepalive_interval_secs: 30,
            keepalive_live: Some(live.clone()),
            ..TransportConfig::default()
        });
        *client.last_received.write().await = Instant::now() - Duration::from_secs(100);
        assert!(
            client.is_healthy().await,
            "100 s of silence is fine at 240 s"
        );
        live.set(30);
        assert!(!client.is_healthy().await, "and not at 30 s");
    }

    #[test]
    fn channel_binding_hook_sets_and_clears() {
        let client = WebSocketClient::new(TransportConfig::default());
        assert_eq!(client.channel_binding(), None);
        client.set_channel_binding_for_test(Some([9; 32]));
        assert_eq!(client.channel_binding(), Some([9; 32]));
        client.set_channel_binding_for_test(None);
        assert_eq!(client.channel_binding(), None);
    }
}
