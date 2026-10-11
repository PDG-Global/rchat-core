//! Signaling Protocol - WebSocket-based connection establishment
//!
//! This module defines the signaling messages used for:
//! - Publishing/looking up key bundles
//! - WebRTC connection negotiation
//! - Relay circuit establishment
//!
//! Protocol format (compatible with iOS and CLI clients):
//! ```json
//! {
//!   "id": "...",
//!   "type": "hello",
//!   "payload": {"type": "hello", "data": {...}},
//!   "timestamp": 123
//! }
//! ```

use super::{timestamp, validate_timestamp, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Signaling message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    /// Message ID (UUID v4)
    pub id: String,

    /// Message type (string like "hello", "publish_key_bundle", etc.)
    #[serde(rename = "type")]
    pub msg_type: String,

    /// Message payload with nested type/data format
    pub payload: Payload,

    /// Timestamp (Unix seconds)
    pub timestamp: u64,
}

impl SignalingMessage {
    /// Create a new signaling message
    pub fn new(msg_type: &str, payload: Payload) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: msg_type.to_string(),
            payload,
            timestamp: timestamp(),
        }
    }

    /// Validate the message
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), super::ProtocolError> {
        if !validate_timestamp(self.timestamp) {
            return Err(super::ProtocolError::InvalidMessage(
                "Timestamp outside acceptable window".to_string(),
            ));
        }
        Ok(())
    }
}

/// Message payload that supports both iOS format (nested type/data)
/// and legacy flat format (direct fields).
///
/// `data` is kept as the raw JSON text and parsed straight into the typed
/// payload struct by `deserialize_data`: no `serde_json::Value` tree is ever
/// built from client input (a `Value` costs ~16x the input in memory, R-1).
/// Frames are size-capped before parsing (`limits::MAX_SIGNALING_BYTES`).
#[derive(Debug, Clone, Serialize)]
pub struct Payload {
    /// Payload type (e.g., "hello", "publish_key_bundle")
    /// Note: This is for serialization; the actual message type comes from SignalingMessage::msg_type
    #[serde(rename = "type")]
    pub payload_type: String,

    /// Actual payload data (can be null for simple messages like ping)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<RawValue>>,
}

impl Payload {
    /// Create a new payload with data (iOS format)
    pub fn new<T: Serialize>(payload_type: &str, data: T) -> Self {
        Self {
            payload_type: payload_type.to_string(),
            data: serde_json::value::to_raw_value(&data).ok(),
        }
    }

    /// Create a payload without data (e.g., for ping)
    #[allow(dead_code)]
    pub fn simple(payload_type: &str) -> Self {
        Self {
            payload_type: payload_type.to_string(),
            data: None,
        }
    }

    /// Get the payload type
    #[allow(dead_code)]
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    /// Deserialize the data field to a specific type
    /// For iOS format: deserializes payload.data
    /// For flat format: deserializes the entire payload (stored in data field during deserialization)
    pub fn deserialize_data<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        match &self.data {
            Some(data) => serde_json::from_str(data.get()),
            None => serde_json::from_str("null"),
        }
    }
}

/// `deserialize_with` for a present `data` key: a present `null` is kept as
/// `Some("null")`, as the `Value`-based parser did (only a missing key is
/// `None`).
fn present_raw<'de, D>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <&RawValue>::deserialize(deserializer).map(Some)
}

/// The two keys that decide the payload format; every other key is skipped
/// without being materialised.
#[derive(Deserialize)]
struct PayloadProbe<'a> {
    #[serde(rename = "type", default, borrow)]
    payload_type: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    data: Option<&'a RawValue>,
}

impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let raw = Box::<RawValue>::deserialize(deserializer)?;

        // iOS format: {"type": "hello", "data": {...}} with a string type.
        if let Ok(PayloadProbe {
            payload_type: Some(t),
            data: Some(data),
        }) = serde_json::from_str::<PayloadProbe>(raw.get())
        {
            if t.get().starts_with('"') {
                let payload_type: String =
                    serde_json::from_str(t.get()).map_err(D::Error::custom)?;
                let data =
                    RawValue::from_string(data.get().to_owned()).map_err(D::Error::custom)?;
                return Ok(Payload {
                    payload_type,
                    data: Some(data),
                });
            }
        }

        // Legacy flat format: treat the entire value as data
        // The payload_type will be set to empty string since we don't know it
        // The actual type comes from SignalingMessage::msg_type
        Ok(Payload {
            payload_type: String::new(),
            data: Some(raw),
        })
    }
}

/// Hello message (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HelloPayload {
    pub supported_versions: Vec<u32>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub platform: String,
}

/// Hello response (server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponsePayload {
    pub selected_version: u32,
    pub server_info: ServerInfo,
    /// 32-byte connection-auth nonce as 64 lowercase hex (protocol v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_challenge: Option<String>,
    /// How long the relay keeps a knock (1..=72); clients bound knock
    /// freshness by it (spec §5.3, L2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knock_ttl_hours: Option<u32>,
    /// The relay's long-term identity and its proof for this connection
    /// (spec §4.9). Always present from protocol v2 on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_identity: Option<RelayIdentityInfo>,
}

/// `hello_response.relay_identity` (hex fields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayIdentityInfo {
    pub key: String,
    pub version: u32,
    pub signature: String,
    #[serde(default)]
    pub chain: Vec<RelayLinkInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayLinkInfo {
    pub prev_key: String,
    pub new_key: String,
    pub version: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub version: String,
    pub capabilities: Vec<String>,
}

/// Key bundle for X3DH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    /// Ed25519 identity key (hex string for JSON compatibility)
    /// Used for signatures and identity verification
    pub identity_key: String,

    /// X25519 identity key (hex string for JSON compatibility)
    /// This is the long-term X25519 key for X3DH key agreement
    pub identity_agreement_key: String,

    /// X25519 signed pre-key (hex string for JSON compatibility)
    pub signed_pre_key: String,

    /// Signature of signed_pre_key by identity_key (hex string for JSON compatibility)
    pub signed_pre_key_signature: String,

    /// One-time X25519 pre-keys (hex strings for JSON compatibility)
    pub one_time_pre_keys: Vec<String>,
}

/// Publish key bundle (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishKeyBundlePayload {
    pub key_bundle: KeyBundle,
    /// Ed25519 signature over the connection transcript (128 lowercase hex).
    pub conn_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishKeyBundleResponsePayload {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// Fresh nonce for a later re-publish on this connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_challenge: Option<String>,
}

/// Lookup key bundle (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct LookupKeyBundlePayload {
    pub identity_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupKeyBundleResponsePayload {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<KeyBundle>,
}

/// WebRTC session description
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SessionDescription {
    pub sdp_type: String,
    pub sdp: String,
}

/// ICE candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u32>,
}

/// Connection request (client -> server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConnectionRequestPayload {
    pub target_identity: Vec<u8>,
    pub webrtc_offer: SessionDescription,
    pub ice_candidates: Vec<IceCandidate>,
}

/// Connection response (client -> server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConnectionResponsePayload {
    pub request_id: String,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webrtc_answer: Option<SessionDescription>,
    pub ice_candidates: Vec<IceCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

/// ICE candidate exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct IceCandidatePayload {
    pub target_identity: Vec<u8>,
    pub candidate: IceCandidate,
}

/// Relay request (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RelayRequestPayload {
    pub target_identity: Vec<u8>,
    pub preferred_transport: TransportType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum TransportType {
    /// WebSocket over TLS 1.3 (only supported transport)
    WebSocket,
}

/// Relay response (server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayResponsePayload {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_circuit_id: Option<String>,
}

/// Pong response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongPayload {
    pub server_time: u64,
}

/// Error payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Encrypted message payload for demo
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct EncryptedMessagePayload {
    pub ciphertext: String,
    pub header: MessageHeader,
}

/// Message header for encrypted messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MessageHeader {
    #[serde(rename = "message_number")]
    pub message_number: u64,
}

/// Peer online notification payload
/// Sent by server when a peer comes online
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PeerOnlinePayload {
    pub identity_key: String,
    pub agreement_key: String,
}

/// Peer offline notification payload
/// Sent by server when a peer goes offline
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PeerOfflinePayload {
    pub identity_key: String,
}

/// Status indicator
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
}

/// Create an error response
#[allow(dead_code)]
pub fn error_response(request_id: &str, code: ErrorCode, message: &str) -> SignalingMessage {
    SignalingMessage::new(
        "error",
        Payload::new(
            "error",
            ErrorPayload {
                code,
                message: message.to_string(),
                request_id: Some(request_id.to_string()),
            },
        ),
    )
}

// Message type constants for convenience
pub const MSG_TYPE_HELLO: &str = "hello";
pub const MSG_TYPE_HELLO_RESPONSE: &str = "hello_response";
pub const MSG_TYPE_PUBLISH_KEY_BUNDLE: &str = "publish_key_bundle";
pub const MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE: &str = "publish_key_bundle_response";
pub const MSG_TYPE_LOOKUP_KEY_BUNDLE: &str = "lookup_key_bundle";
pub const MSG_TYPE_LOOKUP_KEY_BUNDLE_RESPONSE: &str = "lookup_key_bundle_response";
pub const MSG_TYPE_CONNECTION_REQUEST: &str = "connection_request";
#[allow(dead_code)]
pub const MSG_TYPE_CONNECTION_RESPONSE: &str = "connection_response";
#[allow(dead_code)]
pub const MSG_TYPE_ICE_CANDIDATE: &str = "ice_candidate";
pub const MSG_TYPE_RELAY_REQUEST: &str = "relay_request";
pub const MSG_TYPE_RELAY_RESPONSE: &str = "relay_response";
pub const MSG_TYPE_PING: &str = "ping";
pub const MSG_TYPE_PONG: &str = "pong";
pub const MSG_TYPE_ERROR: &str = "error";
pub const MSG_TYPE_ENCRYPTED_MESSAGE: &str = "encrypted_message";
#[allow(dead_code)]
pub const MSG_TYPE_PEER_ONLINE: &str = "peer_online";
#[allow(dead_code)]
pub const MSG_TYPE_PEER_OFFLINE: &str = "peer_offline";

#[cfg(test)]
mod payload_tests {
    use super::*;

    fn parse(json: &str) -> Payload {
        serde_json::from_str(json).expect("payload parses")
    }

    #[test]
    fn nested_format_keeps_type_and_raw_data() {
        let p = parse(r#"{"type":"ping","data":{"server_time":7},"extra":[1,2]}"#);
        assert_eq!(p.payload_type, "ping");
        assert_eq!(p.deserialize_data::<PongPayload>().unwrap().server_time, 7);
    }

    #[test]
    fn present_null_data_is_nested_and_missing_data_is_flat() {
        let p = parse(r#"{"type":"ping","data":null}"#);
        assert_eq!(p.payload_type, "ping");
        assert_eq!(p.data.as_ref().map(|d| d.get()), Some("null"));
        let flat = parse(r#"{"type":"ping","server_time":9}"#);
        assert_eq!(flat.payload_type, "");
        assert_eq!(
            flat.deserialize_data::<PongPayload>().unwrap().server_time,
            9
        );
    }

    #[test]
    fn non_string_type_or_non_object_is_flat() {
        let p = parse(r#"{"type":5,"data":{"server_time":1}}"#);
        assert_eq!(p.payload_type, "");
        assert!(p.data.unwrap().get().starts_with("{\"type\":5"));
        let p = parse("[1,2,3]");
        assert_eq!(p.payload_type, "");
        assert_eq!(p.data.unwrap().get(), "[1,2,3]");
    }

    #[test]
    fn serialization_round_trips() {
        let p = Payload::new("pong", PongPayload { server_time: 3 });
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, r#"{"type":"pong","data":{"server_time":3}}"#);
        let back = parse(&json);
        assert_eq!(
            back.deserialize_data::<PongPayload>().unwrap().server_time,
            3
        );
        assert_eq!(
            serde_json::to_string(&Payload::simple("ping")).unwrap(),
            r#"{"type":"ping"}"#
        );
    }
}
