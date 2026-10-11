//! Protocol definitions for RChat
//!
//! This module contains all protocol types and serialization logic
//! for the signaling and relay protocols.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod relay;
pub mod signaling;
pub mod unified;

#[cfg(test)]
mod codec_compat_tests;

// Re-export commonly used types (for external clients)
#[allow(unused_imports)]
pub use signaling::{
    ClientInfo, ConnectionRequestPayload, ConnectionResponsePayload, ErrorPayload, HelloPayload,
    HelloResponsePayload, IceCandidate, KeyBundle, Payload, PongPayload, PublishKeyBundlePayload,
    PublishKeyBundleResponsePayload, RelayRequestPayload, RelayResponsePayload, SessionDescription,
    SignalingMessage, Status, MSG_TYPE_CONNECTION_REQUEST, MSG_TYPE_CONNECTION_RESPONSE,
    MSG_TYPE_ENCRYPTED_MESSAGE, MSG_TYPE_ERROR, MSG_TYPE_HELLO, MSG_TYPE_HELLO_RESPONSE,
    MSG_TYPE_ICE_CANDIDATE, MSG_TYPE_LOOKUP_KEY_BUNDLE, MSG_TYPE_LOOKUP_KEY_BUNDLE_RESPONSE,
    MSG_TYPE_PING, MSG_TYPE_PONG, MSG_TYPE_PUBLISH_KEY_BUNDLE,
    MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE, MSG_TYPE_RELAY_REQUEST, MSG_TYPE_RELAY_RESPONSE,
};

/// Generate a timestamp in seconds since Unix epoch
pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validate timestamp is within acceptable window (±5 minutes)
pub fn validate_timestamp(ts: u64) -> bool {
    let now = timestamp();
    let diff = ts.abs_diff(now);
    diff <= 300 // 5 minutes
}

/// Circuit ID - 16 byte opaque identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CircuitId(pub [u8; 16]);

impl CircuitId {
    /// Generate a new random circuit ID
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).expect("Failed to generate random circuit ID");
        Self(id)
    }
}

impl AsRef<[u8]> for CircuitId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CircuitId {
    /// Create a CircuitId from a byte slice
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[..16.min(bytes.len())]);
        Self(id)
    }
}

/// Client ID - ephemeral identifier for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClientId(pub [u8; 16]);

impl ClientId {
    /// Generate a new random client ID
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).expect("Failed to generate random client ID");
        Self(id)
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Public key types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum KeyType {
    Ed25519,
    X25519,
}

/// Error codes for protocol errors
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidMessage,
    RateLimited,
    TargetOffline,
    TargetNotFound,
    KeyBundleExpired,
    RelayUnavailable,
    AuthenticationFailed,
    VersionMismatch,
    InternalError,
}

/// Result type for protocol operations
#[allow(dead_code)]
pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ProtocolError {
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Target offline")]
    TargetOffline,

    #[error("Target not found")]
    TargetNotFound,

    #[error("Key bundle expired")]
    KeyBundleExpired,

    #[error("Relay unavailable")]
    RelayUnavailable,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Version mismatch")]
    VersionMismatch,

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}
