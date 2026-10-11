//! Unified Protocol - Multiplexes all traffic over a single WebSocket connection
//!
//! This module provides a unified frame format that combines:
//! - Signaling (JSON messages for connection establishment)
//! - Relay (binary encrypted packets for data forwarding)
//! - Control (connection management messages)
//! - Keepalive (connection keepalive)
//!
//! All traffic goes over the same WebSocket connection with a type byte prefix.

use crate::protocol::relay::RelayPacket;
use crate::protocol::signaling::SignalingMessage;
use crate::protocol::{CircuitId, ClientId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;

/// Frame type byte values
pub const FRAME_TYPE_SIGNALING: u8 = 0x01;
pub const FRAME_TYPE_RELAY: u8 = 0x02;
pub const FRAME_TYPE_CONTROL: u8 = 0x03;
pub const FRAME_TYPE_KEEPALIVE: u8 = 0x04;

/// Unified frame that can be sent over a single WebSocket connection
#[derive(Debug, Clone)]
pub enum UnifiedFrame {
    /// Signaling message (JSON)
    Signaling(SignalingMessage),
    /// Relay packet (binary encrypted)
    Relay(RelayPacket),
    /// Control message (connection management)
    Control(ControlMessage),
    /// Keepalive ping/pong
    Keepalive(KeepaliveMessage),
}

impl UnifiedFrame {
    /// Encode the frame to a WebSocket message
    pub fn encode(&self) -> Message {
        match self {
            UnifiedFrame::Signaling(msg) => {
                // JSON text frame
                match serde_json::to_string(msg) {
                    Ok(json) => Message::Text(json),
                    Err(_) => Message::Binary(vec![]),
                }
            }
            UnifiedFrame::Relay(packet) => {
                // Binary frame with type prefix
                let mut data = vec![FRAME_TYPE_RELAY];
                data.extend_from_slice(&packet.encode());
                Message::Binary(data)
            }
            UnifiedFrame::Control(ctrl) => {
                // Binary frame with type prefix
                let mut data = vec![FRAME_TYPE_CONTROL];
                data.extend_from_slice(&ctrl.encode());
                Message::Binary(data)
            }
            UnifiedFrame::Keepalive(k) => {
                // Binary frame with type prefix
                let mut data = vec![FRAME_TYPE_KEEPALIVE];
                data.extend_from_slice(&k.encode());
                Message::Binary(data)
            }
        }
    }

    /// Decode a WebSocket message to a unified frame
    pub fn decode(msg: &Message) -> Result<Self, FrameError> {
        match msg {
            Message::Text(text) => {
                // Try to parse as signaling message
                match serde_json::from_str::<SignalingMessage>(text) {
                    Ok(msg) => Ok(UnifiedFrame::Signaling(msg)),
                    Err(e) => Err(FrameError::InvalidJson(e.to_string())),
                }
            }
            Message::Binary(bin) => {
                if bin.is_empty() {
                    tracing::debug!("UnifiedFrame::decode: Empty binary frame received");
                    return Err(FrameError::EmptyFrame);
                }

                let frame_type = bin[0];
                let payload = &bin[1..];

                tracing::trace!("UnifiedFrame::decode: frame_type=0x{:02x}", frame_type);

                match frame_type {
                    FRAME_TYPE_RELAY => {
                        tracing::trace!("UnifiedFrame::decode: Decoding RELAY frame (0x02)");
                        match RelayPacket::decode(payload) {
                            Ok(packet) => {
                                tracing::trace!(
                                    "UnifiedFrame::decode: RELAY packet decoded successfully"
                                );
                                Ok(UnifiedFrame::Relay(packet))
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "UnifiedFrame::decode: Failed to decode RELAY packet: {}",
                                    e
                                );
                                Err(FrameError::InvalidRelayPacket(e.to_string()))
                            }
                        }
                    }
                    FRAME_TYPE_CONTROL => {
                        tracing::trace!("UnifiedFrame::decode: Decoding CONTROL frame (0x03)");
                        match ControlMessage::decode(payload) {
                            Ok(ctrl) => {
                                tracing::trace!(
                                    "UnifiedFrame::decode: CONTROL message decoded successfully"
                                );
                                Ok(UnifiedFrame::Control(ctrl))
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "UnifiedFrame::decode: Failed to decode CONTROL message: {}",
                                    e
                                );
                                Err(FrameError::InvalidControlMessage(e.to_string()))
                            }
                        }
                    }
                    FRAME_TYPE_KEEPALIVE => {
                        tracing::trace!("UnifiedFrame::decode: Decoding KEEPALIVE frame (0x04)");
                        match KeepaliveMessage::decode(payload) {
                            Ok(k) => Ok(UnifiedFrame::Keepalive(k)),
                            Err(e) => Err(FrameError::InvalidKeepalive(e.to_string())),
                        }
                    }
                    FRAME_TYPE_SIGNALING => {
                        // Signaling over binary (JSON encoded)
                        tracing::trace!(
                            "UnifiedFrame::decode: Decoding SIGNALING frame over binary (0x01)"
                        );
                        match serde_json::from_slice::<SignalingMessage>(payload) {
                            Ok(msg) => Ok(UnifiedFrame::Signaling(msg)),
                            Err(e) => Err(FrameError::InvalidJson(e.to_string())),
                        }
                    }
                    _ => {
                        tracing::debug!(
                            "UnifiedFrame::decode: Unknown frame type: 0x{:02x}",
                            frame_type
                        );
                        Err(FrameError::UnknownFrameType(frame_type))
                    }
                }
            }
            _ => Err(FrameError::UnsupportedMessageType),
        }
    }

    /// Get the frame type byte
    #[allow(dead_code)]
    pub fn frame_type(&self) -> u8 {
        match self {
            UnifiedFrame::Signaling(_) => FRAME_TYPE_SIGNALING,
            UnifiedFrame::Relay(_) => FRAME_TYPE_RELAY,
            UnifiedFrame::Control(_) => FRAME_TYPE_CONTROL,
            UnifiedFrame::Keepalive(_) => FRAME_TYPE_KEEPALIVE,
        }
    }

    /// Create a signaling frame
    pub fn signaling(msg: SignalingMessage) -> Self {
        UnifiedFrame::Signaling(msg)
    }

    /// Create a relay frame
    pub fn relay(packet: RelayPacket) -> Self {
        UnifiedFrame::Relay(packet)
    }

    /// Create a control frame
    #[allow(dead_code)]
    pub fn control(ctrl: ControlMessage) -> Self {
        UnifiedFrame::Control(ctrl)
    }

    /// Create a keepalive ping frame
    #[allow(dead_code)]
    pub fn keepalive_ping() -> Self {
        UnifiedFrame::Keepalive(KeepaliveMessage::Ping {
            timestamp: current_timestamp(),
        })
    }

    /// Create a keepalive pong frame
    pub fn keepalive_pong(ping_timestamp: u64) -> Self {
        UnifiedFrame::Keepalive(KeepaliveMessage::Pong {
            ping_timestamp,
            timestamp: current_timestamp(),
        })
    }
}

/// Control messages for connection management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Client hello - initiate connection
    Hello {
        client_id: Option<ClientId>,
        supported_versions: Vec<u32>,
        capabilities: Vec<String>,
    },
    /// Server hello response
    HelloResponse {
        selected_version: u32,
        server_time: u64,
        capabilities: Vec<String>,
    },
    /// Request to create a relay circuit
    CreateCircuit {
        target_identity: Vec<u8>,
        /// Ephemeral public key for X3DH (32 bytes X25519 public key)
        initiator_ephemeral_key: Option<Vec<u8>>,
    },
    /// Circuit created notification
    CircuitCreated {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        /// Identity key of the initiator (Ed25519, only set for the responder)
        initiator_identity: Option<Vec<u8>>,
        /// Identity agreement key of the initiator (X25519, only set for the responder)
        /// This is the long-term X25519 identity key needed for X3DH
        initiator_identity_agreement_key: Option<Vec<u8>>,
        /// Agreement key of the initiator (X25519 signed pre-key, only set for the responder)
        /// This is the signed pre-key needed for X3DH
        initiator_agreement_key: Option<Vec<u8>>,
        /// Ephemeral public key of the initiator for X3DH (only set for the responder)
        initiator_ephemeral_key: Option<Vec<u8>>,
        /// Agreement key of the responder (X25519, only set for the initiator)
        /// This is the long-term X25519 key needed for X3DH
        responder_agreement_key: Option<Vec<u8>>,
    },
    /// Circuit already exists (deduplication)
    CircuitExists {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        /// Whether this client is the initiator (created the circuit first)
        is_initiator: bool,
    },
    /// Close a circuit
    CloseCircuit { circuit_id: CircuitId },
    /// Circuit closed notification
    CircuitClosed {
        circuit_id: CircuitId,
        reason: CircuitCloseReason,
    },
    /// Request connection stats
    StatsRequest,
    /// Connection stats response
    StatsResponse {
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
        circuits_active: u32,
    },
    /// Error response
    Error {
        code: ControlErrorCode,
        message: String,
    },
    /// Message acknowledgment - server confirms receipt of a message
    MessageAck {
        /// The message ID being acknowledged
        message_id: String,
        /// Sender identity (hex)
        sender_identity: String,
        /// Recipient identity (hex)
        recipient_identity: String,
        /// Timestamp when server received the message
        received_at: u64,
    },
    /// Delivery receipt - recipient confirms receipt of a message
    DeliveryReceipt {
        /// The message ID being delivered
        message_id: String,
        /// Timestamp when recipient received the message
        delivered_at: u64,
        /// Circuit ID of the recipient
        circuit_id: CircuitId,
    },
    /// Read receipt - recipient has read/opened the message. Never sent or
    /// accepted in protocol v2 (receipts travel end-to-end); index 12 stays
    /// reserved.
    ReadReceipt {
        /// The message ID being read
        message_id: String,
        /// Timestamp when recipient read the message
        read_at: u64,
        /// Circuit ID of the recipient
        circuit_id: CircuitId,
    },
    /// 13 (s→c): both sides asked; here is your side of the new pair.
    /// `role` 0 = initiator (earlier asker), 1 = responder (later asker).
    /// `peer` is the other side's bundle exactly as it was verified at
    /// publish. Both ask ephemeral keys are echoed so each side can check
    /// its own against the ones it has outstanding.
    CircuitCreatedV2 {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        role: u8,
        peer: PeerBundle,
        initiator_ephemeral_key: Vec<u8>,
        responder_ephemeral_key: Vec<u8>,
    },
    /// 14 (s→c): a sealed v2 payload delivered outside a live circuit: an
    /// offline ratchet message or a knock.
    QueuedMessage { payload: Vec<u8> },
    /// 15 (c→s): ask for a circuit with `target_identity`. `knock` is a
    /// sealed v2 knock of exactly 2048 bytes; `resume_circuit` names the
    /// caller's own circuit of an existing pair after a transport reconnect.
    CircuitAsk {
        target_identity: Vec<u8>,
        ephemeral_key: Vec<u8>,
        knock: Vec<u8>,
        resume_circuit: Option<CircuitId>,
    },
}

/// A peer's key bundle as carried in `CircuitCreatedV2`. bincode: four
/// length-prefixed byte vectors in this order (identical to rchat-core's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBundle {
    pub identity_key: Vec<u8>,
    pub identity_agreement_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub bundle_signature: Vec<u8>,
}

impl ControlMessage {
    /// Encode to bytes using bincode
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode from bytes using bincode
    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

/// Keepalive messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeepaliveMessage {
    /// Ping - request pong
    Ping { timestamp: u64 },
    /// Pong - response to ping
    Pong { ping_timestamp: u64, timestamp: u64 },
}

impl KeepaliveMessage {
    /// Encode to bytes using bincode
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode from bytes using bincode
    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

/// Circuit close reasons
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum CircuitCloseReason {
    /// Normal close
    Normal = 0,
    /// Timeout
    Timeout = 1,
    /// Error
    Error = 2,
    /// Rate limited
    RateLimited = 3,
    /// Authentication failed
    AuthFailed = 4,
}

/// Control error codes
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlErrorCode {
    InvalidMessage,
    UnsupportedVersion,
    RateLimited,
    CircuitNotFound,
    CircuitExists,
    AuthenticationFailed,
    TargetOffline,
    TargetNotFound,
    InternalError,
}

/// Frame encoding/decoding errors
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("Empty frame")]
    EmptyFrame,
    #[error("Unknown frame type: {0}")]
    UnknownFrameType(u8),
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),
    #[error("Invalid relay packet: {0}")]
    InvalidRelayPacket(String),
    #[error("Invalid control message: {0}")]
    InvalidControlMessage(String),
    #[error("Invalid keepalive message: {0}")]
    InvalidKeepalive(String),
    #[error("Unsupported message type")]
    UnsupportedMessageType,
}

impl FrameError {
    /// Static, content-free description for logs (the `Display` form can echo
    /// attacker-supplied bytes via the wrapped decoder message).
    pub fn kind(&self) -> &'static str {
        match self {
            FrameError::EmptyFrame => "empty frame",
            FrameError::UnknownFrameType(_) => "unknown frame type",
            FrameError::InvalidJson(_) => "invalid json",
            FrameError::InvalidRelayPacket(_) => "invalid relay packet",
            FrameError::InvalidControlMessage(_) => "invalid control message",
            FrameError::InvalidKeepalive(_) => "invalid keepalive message",
            FrameError::UnsupportedMessageType => "unsupported message type",
        }
    }
}

/// Get current timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Builder for creating unified frames
#[allow(dead_code)]
pub struct FrameBuilder;

#[allow(dead_code)]
impl FrameBuilder {
    /// Create a hello frame
    pub fn hello(supported_versions: Vec<u32>, capabilities: Vec<String>) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::Hello {
            client_id: None,
            supported_versions,
            capabilities,
        })
    }

    /// Create a hello response frame
    pub fn hello_response(selected_version: u32, capabilities: Vec<String>) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::HelloResponse {
            selected_version,
            server_time: current_timestamp(),
            capabilities,
        })
    }

    /// Create a create circuit frame
    pub fn create_circuit(
        target_identity: Vec<u8>,
        initiator_ephemeral_key: Option<Vec<u8>>,
    ) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CreateCircuit {
            target_identity,
            initiator_ephemeral_key,
        })
    }

    /// Create a circuit exists frame (for deduplication)
    pub fn circuit_exists(
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        is_initiator: bool,
    ) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CircuitExists {
            circuit_id,
            token,
            target_circuit_id,
            is_initiator,
        })
    }

    /// `CircuitCreatedV2` for one side of a new pair.
    #[allow(clippy::too_many_arguments)]
    pub fn circuit_created_v2(
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        role: u8,
        peer: PeerBundle,
        initiator_ephemeral_key: Vec<u8>,
        responder_ephemeral_key: Vec<u8>,
    ) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CircuitCreatedV2 {
            circuit_id,
            token,
            target_circuit_id,
            role,
            peer,
            initiator_ephemeral_key,
            responder_ephemeral_key,
        })
    }

    /// `QueuedMessage` carrying one sealed payload.
    pub fn queued_message(payload: Vec<u8>) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::QueuedMessage { payload })
    }

    /// `CircuitAsk` (client → relay; used by tests and tools).
    pub fn circuit_ask(
        target_identity: Vec<u8>,
        ephemeral_key: Vec<u8>,
        knock: Vec<u8>,
        resume_circuit: Option<CircuitId>,
    ) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CircuitAsk {
            target_identity,
            ephemeral_key,
            knock,
            resume_circuit,
        })
    }

    /// Create a close circuit frame
    pub fn close_circuit(circuit_id: CircuitId) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CloseCircuit { circuit_id })
    }

    /// Create a circuit closed frame
    pub fn circuit_closed(circuit_id: CircuitId, reason: CircuitCloseReason) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::CircuitClosed { circuit_id, reason })
    }

    /// Create a stats request frame
    pub fn stats_request() -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::StatsRequest)
    }

    /// Create a stats response frame
    pub fn stats_response(
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
        circuits_active: u32,
    ) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::StatsResponse {
            bytes_sent,
            bytes_received,
            packets_sent,
            packets_received,
            circuits_active,
        })
    }

    /// Create an error frame
    pub fn error(code: ControlErrorCode, message: impl Into<String>) -> UnifiedFrame {
        UnifiedFrame::Control(ControlMessage::Error {
            code,
            message: message.into(),
        })
    }

    /// Create a relay packet frame
    pub fn relay_packet(packet: RelayPacket) -> UnifiedFrame {
        UnifiedFrame::Relay(packet)
    }

    /// Create a signaling message frame
    pub fn signaling(msg: SignalingMessage) -> UnifiedFrame {
        UnifiedFrame::Signaling(msg)
    }

    /// Create a ping frame
    pub fn ping() -> UnifiedFrame {
        UnifiedFrame::keepalive_ping()
    }

    /// Create a pong frame
    pub fn pong(ping_timestamp: u64) -> UnifiedFrame {
        UnifiedFrame::keepalive_pong(ping_timestamp)
    }
}

/// Extension trait for easy conversion to unified frames
#[allow(dead_code)]
pub trait IntoUnifiedFrame {
    fn into_unified_frame(self) -> UnifiedFrame;
}

impl IntoUnifiedFrame for SignalingMessage {
    fn into_unified_frame(self) -> UnifiedFrame {
        UnifiedFrame::Signaling(self)
    }
}

impl IntoUnifiedFrame for RelayPacket {
    fn into_unified_frame(self) -> UnifiedFrame {
        UnifiedFrame::Relay(self)
    }
}

impl IntoUnifiedFrame for ControlMessage {
    fn into_unified_frame(self) -> UnifiedFrame {
        UnifiedFrame::Control(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::signaling::{ClientInfo, HelloPayload, Payload};

    #[test]
    fn test_signaling_frame_roundtrip() {
        let msg = SignalingMessage::new(
            "hello",
            Payload::new(
                "hello",
                HelloPayload {
                    supported_versions: vec![1],
                    capabilities: Vec::new(),
                    client_info: ClientInfo {
                        name: "test".to_string(),
                        version: "1.0".to_string(),
                        platform: "test".to_string(),
                    },
                },
            ),
        );

        let frame = UnifiedFrame::signaling(msg.clone());
        let encoded = frame.encode();

        // Signaling messages are sent as text frames
        assert!(matches!(encoded, Message::Text(_)));

        let decoded = UnifiedFrame::decode(&encoded).unwrap();
        match decoded {
            UnifiedFrame::Signaling(decoded_msg) => {
                assert_eq!(decoded_msg.msg_type, msg.msg_type);
            }
            _ => panic!("Expected signaling frame"),
        }
    }

    #[test]
    fn test_relay_frame_roundtrip() {
        let circuit_id = CircuitId::generate();
        let packet = RelayPacket::new(circuit_id, vec![1, 2, 3, 4, 5]);

        let frame = UnifiedFrame::relay(packet.clone());
        let encoded = frame.encode();

        // Relay packets are sent as binary frames
        assert!(matches!(encoded, Message::Binary(_)));

        if let Message::Binary(bin) = &encoded {
            assert_eq!(bin[0], FRAME_TYPE_RELAY);
        }

        let decoded = UnifiedFrame::decode(&encoded).unwrap();
        match decoded {
            UnifiedFrame::Relay(decoded_packet) => {
                assert_eq!(decoded_packet.circuit_id.0, packet.circuit_id.0);
                assert_eq!(decoded_packet.payload, packet.payload);
            }
            _ => panic!("Expected relay frame"),
        }
    }

    #[test]
    fn test_control_frame_roundtrip() {
        let ctrl = ControlMessage::Hello {
            client_id: None,
            supported_versions: vec![1, 2],
            capabilities: vec!["relay".to_string()],
        };

        let frame = UnifiedFrame::control(ctrl);
        let encoded = frame.encode();

        assert!(matches!(encoded, Message::Binary(_)));

        if let Message::Binary(bin) = &encoded {
            assert_eq!(bin[0], FRAME_TYPE_CONTROL);
        }

        let decoded = UnifiedFrame::decode(&encoded).unwrap();
        match decoded {
            UnifiedFrame::Control(ControlMessage::Hello {
                supported_versions, ..
            }) => {
                assert_eq!(supported_versions, vec![1, 2]);
            }
            _ => panic!("Expected hello control frame"),
        }
    }

    #[test]
    fn test_keepalive_frame_roundtrip() {
        let frame = UnifiedFrame::keepalive_ping();
        let encoded = frame.encode();

        assert!(matches!(encoded, Message::Binary(_)));

        let decoded = UnifiedFrame::decode(&encoded).unwrap();
        match decoded {
            UnifiedFrame::Keepalive(KeepaliveMessage::Ping { .. }) => {}
            _ => panic!("Expected ping frame"),
        }
    }

    #[test]
    fn test_frame_builder() {
        let frame = FrameBuilder::hello(vec![1], vec!["relay".to_string()]);
        assert_eq!(frame.frame_type(), FRAME_TYPE_CONTROL);

        let frame = FrameBuilder::ping();
        assert_eq!(frame.frame_type(), FRAME_TYPE_KEEPALIVE);

        let circuit_id = CircuitId::generate();
        let frame = FrameBuilder::close_circuit(circuit_id);
        assert_eq!(frame.frame_type(), FRAME_TYPE_CONTROL);
    }

    #[test]
    fn test_unknown_frame_type() {
        let bin = vec![0xFFu8]; // Unknown type
        let msg = Message::Binary(bin);
        let result = UnifiedFrame::decode(&msg);
        assert!(result.is_err());
    }

    fn sample_peer() -> PeerBundle {
        PeerBundle {
            identity_key: vec![0x11; 32],
            identity_agreement_key: vec![0x22; 32],
            signed_pre_key: vec![0x33; 32],
            bundle_signature: vec![0x44; 64],
        }
    }

    #[test]
    fn v2_variants_keep_their_bincode_indices() {
        // Indices 0..=12 must not move; the new variants are appended.
        let created = FrameBuilder::circuit_created_v2(
            CircuitId([1; 16]),
            vec![7; 32],
            CircuitId([2; 16]),
            1,
            sample_peer(),
            vec![0x55; 32],
            vec![0x66; 32],
        );
        let queued = FrameBuilder::queued_message(vec![0x02, 9, 9]);
        let ask = FrameBuilder::circuit_ask(vec![3; 32], vec![4; 32], vec![0x02; 2048], None);
        for (frame, index) in [(created, 13u32), (queued, 14), (ask, 15)] {
            let UnifiedFrame::Control(ctrl) = frame else {
                panic!("control frame expected")
            };
            assert_eq!(&ctrl.encode()[..4], &index.to_le_bytes());
        }
    }

    #[test]
    fn v2_variants_round_trip() {
        let frames = [
            FrameBuilder::circuit_created_v2(
                CircuitId([1; 16]),
                vec![7; 32],
                CircuitId([2; 16]),
                0,
                sample_peer(),
                vec![0x55; 32],
                vec![0x66; 32],
            ),
            FrameBuilder::queued_message(vec![0x02; 200]),
            FrameBuilder::circuit_ask(vec![3; 32], vec![4; 32], vec![0x02; 2048], None),
            FrameBuilder::circuit_ask(
                vec![3; 32],
                vec![4; 32],
                vec![0x02; 2048],
                Some(CircuitId([9; 16])),
            ),
        ];
        for frame in frames {
            let decoded = UnifiedFrame::decode(&frame.encode()).unwrap();
            let (UnifiedFrame::Control(a), UnifiedFrame::Control(b)) = (frame, decoded) else {
                panic!("control frames expected")
            };
            assert_eq!(a.encode(), b.encode());
        }
    }

    /// TM7: non-payload control frames have content-independent sizes.
    #[test]
    fn tm7_control_frame_sizes_are_constant() {
        fn r16() -> [u8; 16] {
            rand::random()
        }
        fn r32() -> Vec<u8> {
            (0..32).map(|_| rand::random::<u8>()).collect()
        }
        let sizes = |f: &dyn Fn() -> ControlMessage| -> std::collections::BTreeSet<usize> {
            (0..20).map(|_| f().encode().len()).collect()
        };
        let close = || ControlMessage::CloseCircuit {
            circuit_id: CircuitId(r16()),
        };
        let closed = || ControlMessage::CircuitClosed {
            circuit_id: CircuitId(r16()),
            reason: CircuitCloseReason::Normal,
        };
        let exists = || ControlMessage::CircuitExists {
            circuit_id: CircuitId(r16()),
            token: r32(),
            target_circuit_id: CircuitId(r16()),
            is_initiator: rand::random(),
        };
        // The id as the relay really takes it from a sealed v2 payload
        // (Task 10d minor: was a hex string built in the test).
        let real_id = || {
            let mut payload = vec![0x02];
            payload.extend_from_slice(&r16());
            payload.resize(162, 0);
            crate::signaling::extract_message_id(&payload).expect("a v2 payload has an id")
        };
        let ack = || ControlMessage::MessageAck {
            message_id: real_id(),
            sender_identity: String::new(),
            recipient_identity: String::new(),
            received_at: rand::random(),
        };
        let created = || ControlMessage::CircuitCreatedV2 {
            circuit_id: CircuitId(r16()),
            token: r32(),
            target_circuit_id: CircuitId(r16()),
            role: rand::random::<u8>() & 1,
            peer: PeerBundle {
                identity_key: r32(),
                identity_agreement_key: r32(),
                signed_pre_key: r32(),
                bundle_signature: (0..64).map(|_| rand::random::<u8>()).collect(),
            },
            initiator_ephemeral_key: r32(),
            responder_ephemeral_key: r32(),
        };
        use CircuitCloseReason::*;
        let closed_sizes: std::collections::BTreeSet<usize> =
            [Normal, Timeout, Error, RateLimited, AuthFailed]
                .into_iter()
                .map(|reason| {
                    ControlMessage::CircuitClosed {
                        circuit_id: CircuitId(r16()),
                        reason,
                    }
                    .encode()
                    .len()
                })
                .collect();
        assert_eq!(closed_sizes.len(), 1, "closed size varies by reason");
        assert_eq!(real_id().len(), 32);
        for (name, f) in [
            ("close", &close as &dyn Fn() -> ControlMessage),
            ("closed", &closed),
            ("exists", &exists),
            ("ack", &ack),
            ("created", &created),
        ] {
            assert_eq!(sizes(f).len(), 1, "{name} size varies");
        }
    }

    /// TM7: CircuitAsk and QueuedMessage sizes do not depend on content.
    #[test]
    fn tm7_circuit_ask_and_queued_message_sizes_are_constant() {
        fn r(n: usize) -> Vec<u8> {
            (0..n).map(|_| rand::random::<u8>()).collect()
        }
        let ask = |resume: Option<CircuitId>| {
            ControlMessage::CircuitAsk {
                target_identity: r(32),
                ephemeral_key: r(32),
                knock: r(2048),
                resume_circuit: resume,
            }
            .encode()
            .len()
        };
        let some: std::collections::BTreeSet<usize> = (0..50)
            .map(|_| ask(Some(CircuitId(rand::random()))))
            .collect();
        assert_eq!(some.len(), 1, "Some(random) sizes vary");
        let zero = ask(Some(CircuitId([0; 16])));
        assert_eq!(some.iter().next(), Some(&zero), "zero resume differs");
        // None encodes shorter: the client must always send Some.
        assert_ne!(ask(None), zero);

        let queued = |n: usize| {
            ControlMessage::QueuedMessage { payload: r(n) }
                .encode()
                .len()
                - n
        };
        let ks: std::collections::BTreeSet<usize> = [0usize, 1, 2, 100, 300, 1024, 4096]
            .iter()
            .map(|&n| queued(n))
            .collect();
        assert_eq!(ks.len(), 1, "QueuedMessage overhead varies");
    }
}
