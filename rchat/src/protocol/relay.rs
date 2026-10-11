//! Relay Protocol - TURN-like opaque forwarding
//!
//! The relay protocol is designed to be completely opaque to the server.
//! It forwards encrypted payloads without any ability to inspect content.

#![allow(dead_code)]

use super::{CircuitId, ClientId};
use serde::{Deserialize, Serialize};

/// Relay packet format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPacket {
    /// Circuit identifier (16 bytes)
    pub circuit_id: CircuitId,

    /// Protocol version
    pub version: u8,

    /// Packet flags
    pub flags: PacketFlags,

    /// Authentication tag (HMAC-SHA256-128)
    pub auth_tag: [u8; 16],

    /// Encrypted payload (opaque to server)
    pub payload: Vec<u8>,
}

impl RelayPacket {
    /// Current protocol version
    pub const VERSION: u8 = 1;

    /// Create a new relay packet
    pub fn new(circuit_id: CircuitId, payload: Vec<u8>) -> Self {
        Self {
            circuit_id,
            version: Self::VERSION,
            flags: PacketFlags::empty(),
            auth_tag: [0; 16],
            payload,
        }
    }

    /// Encode packet to bytes using manual format (compatible with iOS)
    /// Format: [circuit_id: 16 bytes][version: 1 byte][flags: 1 byte][auth_tag: 16 bytes][payload_len: 8 bytes][payload: N bytes]
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.circuit_id.as_ref());
        data.push(self.version);
        data.push(self.flags.bits());
        data.extend_from_slice(&self.auth_tag);
        // Payload as Vec<u8> - bincode uses 8-byte length prefix
        data.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        data.extend_from_slice(&self.payload);
        data
    }

    /// Decode packet from bytes using manual format
    pub fn decode(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        tracing::trace!("RelayPacket::decode called");

        if data.len() < 42 {
            // 16 + 1 + 1 + 16 + 8 = 42 bytes minimum
            tracing::debug!("RelayPacket decode failed: data too short");
            return Err(format!("Data too short: {} bytes, need at least 42", data.len()).into());
        }

        let circuit_id = CircuitId::from_slice(&data[0..16]);
        let version = data[16];
        let flags = PacketFlags::from_bits_truncate(data[17]);
        let auth_tag: [u8; 16] = data[18..34]
            .try_into()
            .map_err(|e| format!("Auth tag extraction failed: {:?}", e))?;
        let payload_len = u64::from_le_bytes(
            data[34..42]
                .try_into()
                .map_err(|e| format!("Payload length extraction failed: {:?}", e))?,
        );

        // Checked: a hostile length near u64::MAX must not wrap the bound
        // check (the slice below would then panic and, with panic=abort,
        // take the whole server down).
        let payload_len_usize = usize::try_from(payload_len).unwrap_or(usize::MAX);
        let payload_end = match 42usize.checked_add(payload_len_usize) {
            Some(end) => end,
            None => return Err("Payload length overflows".into()),
        };
        if data.len() < payload_end {
            tracing::debug!("RelayPacket decode failed: payload truncated");
            return Err(format!(
                "Payload truncated: have {} bytes, need {} for payload",
                data.len() - 42,
                payload_len_usize
            )
            .into());
        }

        let payload = data[42..payload_end].to_vec();

        tracing::trace!("RelayPacket decoded");

        Ok(Self {
            circuit_id,
            version,
            flags,
            auth_tag,
            payload,
        })
    }

    /// Calculate packet size
    pub fn size(&self) -> usize {
        16 + 1 + 1 + 16 + self.payload.len()
    }
}

bitflags::bitflags! {
    /// Packet flags
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct PacketFlags: u8 {
        /// Payload is encrypted
        const ENCRYPTED = 0x01;
        /// Payload is compressed
        const COMPRESSED = 0x02;
        /// Part of fragmented message
        const FRAGMENTED = 0x04;
        /// Sender wants acknowledgment
        const ACK_REQUIRED = 0x08;
        /// Keepalive packet (no payload)
        const KEEPALIVE = 0x80;
    }
}

/// Circuit information
#[derive(Debug)]
pub struct Circuit {
    /// Circuit identifier
    pub id: CircuitId,

    /// Client A endpoint
    pub endpoint_a: Endpoint,

    /// Client B endpoint
    pub endpoint_b: Endpoint,

    /// Authentication token for client A
    pub token_a: CircuitToken,

    /// Authentication token for client B
    pub token_b: CircuitToken,

    /// Circuit creation time
    pub created_at: std::time::Instant,

    /// Bytes transferred through this circuit
    pub bytes_transferred: std::sync::atomic::AtomicU64,

    /// Circuit state
    pub state: CircuitState,
}

/// Endpoint information
#[derive(Debug)]
pub struct Endpoint {
    /// Client ID
    pub client_id: ClientId,

    /// Socket address (if known)
    pub socket_addr: Option<std::net::SocketAddr>,

    /// Last activity timestamp
    pub last_activity: std::sync::atomic::AtomicU64,
}

impl Endpoint {
    pub fn new(client_id: ClientId) -> Self {
        Self {
            client_id,
            socket_addr: None,
            last_activity: std::sync::atomic::AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        }
    }

    pub fn update_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Circuit authentication token
#[derive(Debug, Clone)]
pub struct CircuitToken {
    /// Circuit identifier
    pub circuit_id: CircuitId,

    /// HMAC key for authentication
    pub key: [u8; 32],

    /// Token expiration time
    pub expires_at: std::time::Instant,
}

impl CircuitToken {
    /// Generate a new circuit token
    pub fn generate(circuit_id: CircuitId, ttl: std::time::Duration) -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("Failed to generate token key");

        Self {
            circuit_id,
            key,
            expires_at: std::time::Instant::now() + ttl,
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        std::time::Instant::now() > self.expires_at
    }

    /// Calculate authentication tag for a packet
    pub fn authenticate(&self, circuit_id: &CircuitId, payload: &[u8]) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(circuit_id.as_ref());
        mac.update(payload);
        let result = mac.finalize().into_bytes();

        // Truncate to 16 bytes
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[..16]);
        tag
    }

    /// Verify authentication tag
    pub fn verify(&self, circuit_id: &CircuitId, payload: &[u8], tag: &[u8; 16]) -> bool {
        let expected = self.authenticate(circuit_id, payload);
        use constant_time_eq::constant_time_eq;
        constant_time_eq(&expected, tag)
    }
}

/// Circuit state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Waiting for both clients
    Pending,
    /// Both clients connected
    Active,
    /// Graceful shutdown
    Closing,
    /// Circuit terminated
    Closed,
}

/// Rate limiter for circuits
pub struct RateLimiter {
    /// Token bucket - current tokens
    tokens: std::sync::atomic::AtomicU64,

    /// Last refill time
    last_refill: std::sync::atomic::AtomicU64,

    /// Refill rate (bytes per second)
    rate: u64,

    /// Maximum burst size
    burst: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(rate: u64, burst: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            tokens: std::sync::atomic::AtomicU64::new(burst),
            last_refill: std::sync::atomic::AtomicU64::new(now),
            rate,
            burst,
        }
    }

    /// Check if request is allowed
    pub fn check(&self, bytes: usize) -> bool {
        self.refill();

        let current = self.tokens.load(std::sync::atomic::Ordering::Relaxed);
        if current >= bytes as u64 {
            self.tokens
                .fetch_sub(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Refill token bucket
    fn refill(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_refill.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);

        if elapsed > 0 {
            let tokens_to_add = elapsed * self.rate;
            let new_tokens = std::cmp::min(
                self.tokens.load(std::sync::atomic::Ordering::Relaxed) + tokens_to_add,
                self.burst,
            );

            self.tokens
                .store(new_tokens, std::sync::atomic::Ordering::Relaxed);
            self.last_refill
                .store(now, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_huge_length_without_panicking() {
        let mut data = vec![0u8; 50];
        data[34..42].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(RelayPacket::decode(&data).is_err());
        data[34..42].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(RelayPacket::decode(&data).is_err());
    }

    #[test]
    fn decode_roundtrip() {
        let p = RelayPacket::new(CircuitId::from_slice(&[7u8; 16]), vec![1, 2, 3]);
        let d = RelayPacket::decode(&p.encode()).unwrap();
        assert_eq!(d.payload, vec![1, 2, 3]);
    }
}
