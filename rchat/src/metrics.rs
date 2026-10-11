//! Prometheus metrics for the server

use lazy_static::lazy_static;
use prometheus::{
    register_counter, register_gauge, register_int_counter_vec, Counter, Encoder, Gauge,
    IntCounterVec, TextEncoder,
};
use std::convert::Infallible;

lazy_static! {
    /// Total active connections
    pub static ref CONNECTIONS_TOTAL: Gauge = register_gauge!(
        "rchat_connections_total",
        "Total active WebSocket connections"
    ).unwrap();

    /// Total connections created
    pub static ref CONNECTIONS_CREATED: Counter = register_counter!(
        "rchat_connections_created_total",
        "Total connections created"
    ).unwrap();

    /// Total connections closed
    pub static ref CONNECTIONS_CLOSED: Counter = register_counter!(
        "rchat_connections_closed_total",
        "Total connections closed"
    ).unwrap();

    /// Total active circuits
    pub static ref CIRCUITS_TOTAL: Gauge = register_gauge!(
        "rchat_circuits_total",
        "Total active relay circuits"
    ).unwrap();

    /// Total circuits created
    pub static ref CIRCUITS_CREATED: Counter = register_counter!(
        "rchat_circuits_created_total",
        "Total circuits created"
    ).unwrap();

    /// Total bytes relayed
    pub static ref RELAY_BYTES: Counter = register_counter!(
        "rchat_relay_bytes_total",
        "Total bytes relayed"
    ).unwrap();

    /// Total packets relayed
    pub static ref RELAY_PACKETS: Counter = register_counter!(
        "rchat_relay_packets_total",
        "Total packets relayed"
    ).unwrap();

    /// Rate limit hits (times a connection's read loop was paused because it
    /// exceeded `rate_limit_bps`). Also counted as
    /// `rchat_rejections_total{reason="rate_limit"}`.
    pub static ref RATE_LIMIT_HITS: Counter = register_counter!(
        "rchat_rate_limit_hits_total",
        "Total rate limit hits"
    ).unwrap();

    /// notAfter of the certificate being served, as a Unix timestamp
    /// (0 until a certificate is loaded). Alert on `- time() < 7*86400`.
    pub static ref TLS_CERT_NOT_AFTER: Gauge = register_gauge!(
        "rchat_tls_cert_not_after_seconds",
        "Expiry (notAfter, Unix seconds) of the TLS certificate being served"
    ).unwrap();
    /// Resource-limit enforcement events, by reason. See the `REJECT_*`
    /// constants for the label values.
    pub static ref REJECTIONS: IntCounterVec = register_int_counter_vec!(
        "rchat_rejections_total",
        "Connections refused, throttled or dropped by resource limits",
        &["reason"]
    ).unwrap();
}

/// New connection refused: `max_connections` reached.
pub const REJECT_MAX_CONNECTIONS: &str = "max_connections";
/// New connection refused: per-address cap (`max_connections_per_ip`) reached.
pub const REJECT_PER_IP_CAP: &str = "per_ip_cap";
/// Connection throttled for exceeding `rate_limit_bps`.
pub const REJECT_RATE_LIMIT: &str = "rate_limit";
/// Connection closed for sending a frame/message over `max_message_bytes`.
pub const REJECT_OVERSIZED_FRAME: &str = "oversized_frame";
/// Message refused (not acknowledged) because the offline queue is full.
pub const REJECT_QUEUE_OVERFLOW: &str = "queue_overflow";
/// Connection closed because it stopped draining its outbound queue.
pub const REJECT_SLOW_CONSUMER: &str = "slow_consumer";
/// Connection closed for not completing the WebSocket upgrade in time.
pub const REJECT_HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
/// New connection refused: IPv6 /48 aggregate cap reached.
pub const REJECT_PER_PREFIX_CAP: &str = "per_prefix_cap";
/// CircuitAsk refused / notification not queued: pending-target cap.
pub const REJECT_PENDING_TARGETS: &str = "pending_targets";
/// A knock was not queued: its asker exceeded the 24 h new-entry quota.
pub const REJECT_KNOCK_QUOTA: &str = "knock_quota";
/// A queued knock was evicted (global knock budget or per-recipient cap).
pub const REJECT_KNOCK_EVICTED: &str = "knock_evicted";
/// Connection closed for not sending Hello / a key bundle in time.
pub const REJECT_IDENTIFICATION_TIMEOUT: &str = "identification_timeout";
/// CircuitAsk refused: `max_circuits` or `max_circuits_per_connection`.
pub const REJECT_CIRCUIT_CAP: &str = "circuit_cap";
/// Connection closed for exceeding `connection_timeout_secs` without traffic.
pub const REJECT_IDLE_TIMEOUT: &str = "idle_timeout";
/// Key bundle publish refused: bad bundle signature, bad or replayed
/// connection proof, missing challenge, or an identity switch.
pub const REJECT_KEY_AUTH: &str = "key_auth";

/// A pending circuit request of the heaviest source was evicted to make
/// room for one from a lighter source (relay-wide cap reached).
pub const REJECT_PENDING_EVICTED: &str = "pending_evicted";
/// Connection closed for exceeding its hello/publish signature budget.
pub const REJECT_AUTH_RATE: &str = "auth_rate";
/// A message was refused because the relay-wide outbound budget is spent.
pub const REJECT_GLOBAL_OUTBOUND: &str = "global_outbound";
/// The relay-wide outbound budget was spent; the connection holding the
/// most of it was closed (H-1).
pub const REJECT_OUTBOUND_SHED: &str = "outbound_shed";
/// A connection's writer made no progress for `WRITER_STALL_TIMEOUT` with
/// a message to send; the connection was closed (H-1).
pub const REJECT_WRITER_STALL: &str = "writer_stall";
/// The relay-wide WebSocket buffer budget was exceeded; the connection
/// holding the most of it was closed (M-5).
pub const REJECT_BUFFER_SHED: &str = "buffer_shed";
/// The circuit table was full; the heaviest source's newest pair was torn
/// down to make room for a lighter source's (M-3).
pub const REJECT_CIRCUIT_EVICTED: &str = "circuit_evicted";
/// A connection task panicked (only that connection was closed), or a
/// round of a background task did (the task runs again next round).
pub const REJECT_TASK_PANIC: &str = "task_panic";
/// `proxy_protocol` is on and a connection's PROXY v2 header was missing,
/// malformed, unsupported or late; the connection was closed.
pub const REJECT_PROXY_HEADER: &str = "proxy_header";
/// `proxy_protocol` is on and a connection came from a non-loopback peer;
/// it was refused before any read.
pub const REJECT_PROXY_NOT_LOOPBACK: &str = "proxy_not_loopback";

/// Count one enforcement event.
pub fn reject(reason: &str) {
    REJECTIONS.with_label_values(&[reason]).inc();
    if reason == REJECT_RATE_LIMIT {
        RATE_LIMIT_HITS.inc();
    }
}

/// Initialize metrics
pub fn init() {
    // The metrics are lazy statics: touch each one so it is registered (and
    // exported, with value 0) before anything has happened, instead of
    // appearing only after its first use.
    lazy_static::initialize(&CONNECTIONS_TOTAL);
    lazy_static::initialize(&CONNECTIONS_CREATED);
    lazy_static::initialize(&CONNECTIONS_CLOSED);
    lazy_static::initialize(&CIRCUITS_TOTAL);
    lazy_static::initialize(&CIRCUITS_CREATED);
    lazy_static::initialize(&RELAY_BYTES);
    lazy_static::initialize(&RELAY_PACKETS);
    lazy_static::initialize(&RATE_LIMIT_HITS);
    lazy_static::initialize(&TLS_CERT_NOT_AFTER);
    lazy_static::initialize(&REJECTIONS);
    tracing::info!("Metrics initialized");
}

/// Start the metrics endpoint (Prometheus text format, aggregate server
/// counters only). Binds `bind_addr`, then serves until the process exits.
pub async fn start_server(bind_addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("Metrics endpoint listening on {}", bind_addr);
    serve(listener).await
}

/// Bounds on the metrics endpoint (R-15): a scraper needs one connection
/// and a fraction of a second; nothing more is offered.
#[derive(Debug, Clone, Copy)]
pub struct EndpointLimits {
    /// Most connections served at once; further ones wait in the backlog.
    pub max_connections: usize,
    /// Time to send the request headers.
    pub header_timeout: std::time::Duration,
    /// Total lifetime of one connection.
    pub connection_timeout: std::time::Duration,
}

impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            max_connections: 8,
            header_timeout: std::time::Duration::from_secs(5),
            connection_timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// Serve metrics on an already-bound listener.
pub async fn serve(listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    serve_with(listener, EndpointLimits::default()).await
}

/// Serve metrics with explicit limits: a connection cap (taken before
/// `accept`, so excess clients wait in the kernel backlog instead of
/// holding tasks and descriptors), a header read timeout and a total
/// per-connection timeout, so slow clients cannot pin the endpoint.
pub async fn serve_with(
    listener: tokio::net::TcpListener,
    limits: EndpointLimits,
) -> anyhow::Result<()> {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!("Metrics accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(serve_metrics);
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(limits.header_timeout)
                .keep_alive(false)
                .serve_connection(io, service);
            match tokio::time::timeout(limits.connection_timeout, conn).await {
                Ok(Err(e)) => tracing::debug!("Metrics connection error: {}", e),
                Err(_) => tracing::debug!("Metrics connection timed out"),
                Ok(Ok(())) => {}
            }
        });
    }
}

async fn serve_metrics(
    _req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let response = hyper::Response::builder()
        .status(200)
        .header("Content-Type", encoder.format_type())
        .body(http_body_util::Full::new(hyper::body::Bytes::from(buffer)))
        .unwrap();

    Ok(response)
}

/// Current value of a rejection counter (tests).
#[cfg(test)]
pub fn rejections(reason: &str) -> u64 {
    REJECTIONS.with_label_values(&[reason]).get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The endpoint serves only aggregate server counters: every family is
    /// an `rchat_` (or standard `process_`) metric and the only label is a
    /// fixed `reason` value - nothing per user, address or circuit.
    #[test]
    fn init_registers_every_metric() {
        init();
        let names: Vec<String> = prometheus::gather()
            .iter()
            .map(|f| f.get_name().to_string())
            .collect();
        for expected in [
            "rchat_connections_total",
            "rchat_connections_created_total",
            "rchat_circuits_total",
            "rchat_relay_bytes_total",
            "rchat_relay_packets_total",
            "rchat_rate_limit_hits_total",
            "rchat_tls_cert_not_after_seconds",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} not registered"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_serves_aggregate_metrics_only() {
        reject(REJECT_RATE_LIMIT);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            s.read_to_string(&mut out),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("rchat_rejections_total{reason=\"rate_limit\"}"));

        for family in prometheus::gather() {
            let name = family.get_name();
            assert!(
                name.starts_with("rchat_") || name.starts_with("process_"),
                "unexpected metric family {name}"
            );
            for m in family.get_metric() {
                for l in m.get_label() {
                    assert_eq!(l.get_name(), "reason", "{name} has label {}", l.get_name());
                }
            }
        }
    }

    /// R-15: idle connections can hold at most `max_connections` slots, and
    /// only until the header timeout; then a real scrape is served.
    #[tokio::test]
    async fn endpoint_caps_connections_and_times_out_idle_ones() {
        use std::time::Duration;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_with(
            listener,
            EndpointLimits {
                max_connections: 2,
                header_timeout: Duration::from_millis(500),
                connection_timeout: Duration::from_secs(10),
            },
        ));
        // Two idle connections take both slots (slowloris).
        let mut idle1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _idle2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut scrape = tokio::net::TcpStream::connect(addr).await.unwrap();
        scrape
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(250), scrape.read(&mut buf))
                .await
                .is_err(),
            "a third connection was served while two slots were held"
        );
        // The idle ones are dropped at the header timeout...
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), idle1.read_to_end(&mut sink))
            .await
            .expect("idle connection closed by the header timeout");
        // ...and the waiting scrape is then answered.
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(3), scrape.read_to_string(&mut out))
            .await
            .expect("scrape served once a slot freed")
            .unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    }
}
