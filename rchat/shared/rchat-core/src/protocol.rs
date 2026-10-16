//! Protocol definitions for RChat
//!
//! This module defines the message types and serialization for the RChat protocol.
//! It uses bincode format to match the Rust server implementation.

use crate::keyauth::{KeyAuthError, SignedBundle};
use base64::Engine as _;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Frame type constants
pub const FRAME_TYPE_SIGNALING: u8 = 0x01;
pub const FRAME_TYPE_RELAY: u8 = 0x02;
pub const FRAME_TYPE_CONTROL: u8 = 0x03;
pub const FRAME_TYPE_KEEPALIVE: u8 = 0x04;

/// Magics that start a binary (type 0x02) plaintext: what the app put in
/// it. Media travel as binary, never as an in-band text prefix, so a text
/// message is always text.
pub const IMAGE_MAGIC: u32 = 0x494D4731; // "IMG1": JPEG bytes follow
pub const VOICE_MAGIC: u32 = 0x564F4345; // "VOCE": M4A bytes follow
/// UTF-8 text sent as binary: a text that starts with an old in-band media
/// prefix (`$$IMG$$:`, `$$VOICE$$:`), so a receiver that still reads those
/// prefixes from older peers shows it as text.
pub const TEXT_MAGIC: u32 = 0x54585431; // "TXT1"

/// Whether a binary plaintext body starts with a magic the app knows.
/// Anything else is dropped on receipt and refused on send.
/// `TXT1` text must be UTF-8 (completion review L5): checked here, before
/// the delivered receipt, rather than refused by the app after it.
pub fn is_known_binary(body: &[u8]) -> bool {
    match body.get(..4) {
        Some(m) => {
            let m = u32::from_be_bytes([m[0], m[1], m[2], m[3]]);
            m == IMAGE_MAGIC
                || m == VOICE_MAGIC
                || (m == TEXT_MAGIC && std::str::from_utf8(&body[4..]).is_ok())
        }
        None => false,
    }
}

/// Unique identifier for a message
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 16] = rng.gen();
        Self(hex::encode(bytes))
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// A chat message with delivery tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: MessageId,
    /// Sender's identity (public key)
    pub sender: String,
    /// Recipient's identity (public key)
    pub recipient: String,
    /// Message content (encrypted)
    pub content: Vec<u8>,
    /// Timestamp when message was created
    pub timestamp_ms: u64,
    /// Message type
    pub msg_type: MessageType,
    /// Sequence number for ordering
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    Binary,
    Voice,
    E2EEHandshake,
    /// A file message (`0x07`, protocol v3 §E.2): the content is the
    /// plaintext after its type byte (`file_msg::encode_file_body`).
    File,
    /// A disappearing-timer change (`0x09`, protocol v3 §I.2): the content
    /// is the plaintext after its type byte. Sent, padded and ack-tracked
    /// like a message; never delivered to the app as one.
    Timer,
}

/// Delivery receipt - sent by recipient to confirm message received
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// The message ID being acknowledged
    pub message_id: MessageId,
    /// The recipient who received the message
    pub recipient: String,
    /// Timestamp when delivered
    pub delivered_at_ms: u64,
    /// Optional: hash of received content for verification
    pub content_hash: Option<String>,
}

/// Server acknowledgment - sent by server to confirm message stored for delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAck {
    /// The message ID being acknowledged
    pub message_id: MessageId,
    /// Timestamp when server received the message
    pub received_at_ms: u64,
    /// Status of the message
    pub status: MessageStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Message received by server, recipient is online
    Delivered,
    /// Message received by server, recipient is offline (queued)
    Queued,
    /// Message could not be delivered (recipient unknown, etc.)
    Failed,
}

/// Circuit ID - 16 byte opaque identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CircuitId(pub [u8; 16]);

impl Serialize for CircuitId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CircuitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 16] = Deserialize::deserialize(deserializer)?;
        Ok(CircuitId(bytes))
    }
}

impl CircuitId {
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for CircuitId {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet flags
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub fragmented: bool,
    pub ack_required: bool,
    pub keepalive: bool,
}

impl PacketFlags {
    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= 0x01;
        }
        if self.compressed {
            flags |= 0x02;
        }
        if self.fragmented {
            flags |= 0x04;
        }
        if self.ack_required {
            flags |= 0x08;
        }
        if self.keepalive {
            flags |= 0x80;
        }
        flags
    }

    pub fn from_u8(flags: u8) -> Self {
        Self {
            encrypted: flags & 0x01 != 0,
            compressed: flags & 0x02 != 0,
            fragmented: flags & 0x04 != 0,
            ack_required: flags & 0x08 != 0,
            keepalive: flags & 0x80 != 0,
        }
    }
}

/// Relay packet format for bincode serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPacket {
    /// Circuit identifier (16 bytes)
    pub circuit_id: CircuitId,
    /// Protocol version
    pub version: u8,
    /// Packet flags
    pub flags: u8,
    /// Authentication tag (HMAC-SHA256-128)
    pub auth_tag: [u8; 16],
    /// Encrypted payload (opaque to server)
    pub payload: Vec<u8>,
}

impl RelayPacket {
    /// Current protocol version
    pub const CURRENT_VERSION: u8 = 1;

    /// Create a new relay packet
    pub fn new(circuit_id: CircuitId, payload: Vec<u8>, flags: PacketFlags) -> Self {
        Self {
            circuit_id,
            version: Self::CURRENT_VERSION,
            flags: flags.to_u8(),
            auth_tag: [0u8; 16],
            payload,
        }
    }

    /// Create a relay packet with computed auth tag
    pub fn with_auth(
        circuit_id: CircuitId,
        payload: Vec<u8>,
        flags: PacketFlags,
        token_key: &[u8; 32],
    ) -> Self {
        let auth_tag = Self::compute_auth_tag(&circuit_id, &payload, token_key);
        Self {
            circuit_id,
            version: Self::CURRENT_VERSION,
            flags: flags.to_u8(),
            auth_tag,
            payload,
        }
    }

    /// Compute authentication tag using HMAC-SHA256-128
    pub fn compute_auth_tag(
        circuit_id: &CircuitId,
        payload: &[u8],
        token_key: &[u8; 32],
    ) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(token_key).expect("HMAC can take key of any size");
        mac.update(&circuit_id.0);
        mac.update(payload);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[..16]);
        tag
    }

    /// Verify authentication tag
    pub fn verify_auth_tag(&self, token_key: &[u8; 32]) -> bool {
        let expected = Self::compute_auth_tag(&self.circuit_id, &self.payload, token_key);
        constant_time_eq::constant_time_eq(&expected, &self.auth_tag)
    }

    /// Encode packet to bytes using bincode format
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.circuit_id.0);
        result.push(self.version);
        result.push(self.flags);
        result.extend_from_slice(&self.auth_tag);
        result.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        result.extend_from_slice(&self.payload);
        result
    }

    /// Encode packet with frame type prefix for WebSocket
    pub fn encode_with_frame_type(&self) -> Vec<u8> {
        let mut result = vec![FRAME_TYPE_RELAY];
        result.extend_from_slice(&self.encode());
        result
    }

    /// Decode packet from bytes using bincode format (expects frame type prefix)
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.first() != Some(&FRAME_TYPE_RELAY) {
            return None;
        }
        Self::decode_without_frame_type(&data[1..])
    }

    /// Decode packet from bytes using bincode format (without frame type prefix)
    pub fn decode_without_frame_type(data: &[u8]) -> Option<Self> {
        if data.len() < 42 {
            return None;
        }
        let mut circuit_id = [0u8; 16];
        circuit_id.copy_from_slice(&data[0..16]);
        let version = data[16];
        let flags = data[17];
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&data[18..34]);
        let payload_len = u64::from_le_bytes(data[34..42].try_into().ok()?) as usize;
        let end = 42usize.checked_add(payload_len)?;
        let payload = data.get(42..end)?.to_vec();
        Some(Self {
            circuit_id: CircuitId(circuit_id),
            version,
            flags,
            auth_tag,
            payload,
        })
    }

    /// Get packet flags
    pub fn packet_flags(&self) -> PacketFlags {
        PacketFlags::from_u8(self.flags)
    }
}

/// Control message variant indices (for bincode enum variant encoding)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlMessageVariant {
    Hello = 0,
    HelloResponse = 1,
    CreateCircuit = 2,
    CircuitCreated = 3,
    CircuitExists = 4,
    CloseCircuit = 5,
    CircuitClosed = 6,
    StatsRequest = 7,
    StatsResponse = 8,
    Error = 9,
    MessageAck = 10,
    DeliveryReceipt = 11,
    ReadReceipt = 12,
    CircuitCreatedV3 = 13,
    QueuedMessage = 14,
    CircuitAsk = 15,
    CircuitAskBlind = 16,
    PairTokenBusy = 17,
    QueueHandedOver = 18,
}

/// Circuit close reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CircuitCloseReason {
    Normal = 0,
    Timeout = 1,
    Error = 2,
    RateLimited = 3,
    AuthFailed = 4,
}

impl CircuitCloseReason {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::Timeout,
            2 => Self::Error,
            3 => Self::RateLimited,
            4 => Self::AuthFailed,
            _ => Self::Normal,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// Text of a `CircuitNotFound` error for a relay packet: this prefix then
/// the 32-hex circuit id the packet named (re-review R-1). Fixed length, and
/// only the sender's own value, so it tells the sender nothing new; it lets
/// the core forget a circuit it still believes is live.
pub const CIRCUIT_NOT_FOUND_PREFIX: &str = "Circuit not found: ";

/// Text of the `RateLimited` error a relay sends when its offline queue
/// refuses a relay packet: this prefix, then the message id prefix and
/// "not stored" (final re-review N-3). Shared with the relay, which builds
/// the text from it, so the core can tell this refusal (about a message)
/// from an ask refused over a relay cap (`RateLimited` with any other text).
pub const OFFLINE_QUEUE_FULL_PREFIX: &str = "Offline queue full; ";

/// Whether a `RateLimited` error's text is the offline queue's refusal of
/// a relay packet rather than an ask refusal.
pub fn is_offline_queue_refusal(message: &str) -> bool {
    message.starts_with(OFFLINE_QUEUE_FULL_PREFIX)
}

/// The circuit a `CircuitNotFound` error names, if its text carries one.
pub fn circuit_not_found_id(message: &str) -> Option<CircuitId> {
    let hex_id = message.strip_prefix(CIRCUIT_NOT_FOUND_PREFIX)?;
    if hex_id.len() != 32 {
        return None;
    }
    let bytes: [u8; 16] = hex::decode(hex_id).ok()?.try_into().ok()?;
    Some(CircuitId(bytes))
}

/// Control error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlErrorCode {
    InvalidMessage = 0,
    UnsupportedVersion = 1,
    RateLimited = 2,
    CircuitNotFound = 3,
    CircuitExists = 4,
    AuthenticationFailed = 5,
    TargetOffline = 6,
    TargetNotFound = 7,
    InternalError = 8,
    /// Protocol v3: a known message the relay does not serve yet.
    NotImplemented = 9,
    /// 10: reserved. A busy blinded token is answered with the typed
    /// `ControlMessage::PairTokenBusy` (17, ruling R22), never this code.
    PairTokenBusy = 10,
}

impl ControlErrorCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::InvalidMessage,
            1 => Self::UnsupportedVersion,
            2 => Self::RateLimited,
            3 => Self::CircuitNotFound,
            4 => Self::CircuitExists,
            5 => Self::AuthenticationFailed,
            6 => Self::TargetOffline,
            7 => Self::TargetNotFound,
            9 => Self::NotImplemented,
            10 => Self::PairTokenBusy,
            _ => Self::InternalError,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// A verified-by-the-client v3 key bundle on the wire: four length-prefixed
/// byte strings in this order (bincode). Lengths are checked by `to_signed`
/// (`kem_pk` exactly 1184 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBundle {
    pub identity_key: Vec<u8>,
    pub identity_agreement_key: Vec<u8>,
    pub kem_pk: Vec<u8>,
    pub bundle_signature: Vec<u8>,
}

impl PeerBundle {
    pub fn from_signed(b: &SignedBundle) -> Self {
        Self {
            identity_key: b.identity_key.to_vec(),
            identity_agreement_key: b.identity_agreement_key.to_vec(),
            kem_pk: b.kem_pk.to_vec(),
            bundle_signature: b.bundle_signature.to_vec(),
        }
    }

    pub fn to_signed(&self) -> Result<SignedBundle, KeyAuthError> {
        SignedBundle::from_wire(
            &self.identity_key,
            &self.identity_agreement_key,
            &self.kem_pk,
            &self.bundle_signature,
        )
    }
}

/// Control messages for connection management using bincode serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Client hello - initiate connection
    Hello {
        client_id: Option<[u8; 16]>,
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
        initiator_ephemeral_key: Option<Vec<u8>>,
    },
    /// Circuit created notification
    CircuitCreated {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        initiator_identity: Option<Vec<u8>>,
        initiator_identity_agreement_key: Option<Vec<u8>>,
        initiator_agreement_key: Option<Vec<u8>>,
        initiator_ephemeral_key: Option<Vec<u8>>,
        responder_agreement_key: Option<Vec<u8>>,
    },
    /// Circuit already exists (deduplication)
    CircuitExists {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
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
    /// Message acknowledgment from server to sender
    MessageAck {
        message_id: String,
        sender_identity: String,
        recipient_identity: String,
        timestamp: u64,
    },
    /// Delivery receipt from recipient to sender (via server)
    DeliveryReceipt {
        message_id: String,
        delivered_at: u64,
        circuit_id: CircuitId,
    },
    /// Read receipt from recipient to sender (via server)
    ReadReceipt {
        message_id: String,
        read_at: u64,
        circuit_id: CircuitId,
    },
    /// 13 (protocol v3, replaces v2's `CircuitCreatedV2` in the same slot):
    /// both peers asked; carries the other side's verified bundle, both
    /// asks' X25519 ephemerals and both asks' ML-KEM-768 ephemeral public
    /// keys (1184 bytes each), forwarded by the relay unmodified (§A.3).
    CircuitCreatedV3 {
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
        /// 0 = initiator (earlier asker), 1 = responder (later asker).
        role: u8,
        peer: PeerBundle,
        initiator_ephemeral_key: Vec<u8>,
        responder_ephemeral_key: Vec<u8>,
        initiator_kem_ephemeral_pk: Vec<u8>,
        responder_kem_ephemeral_pk: Vec<u8>,
        /// Each asker's Ed25519 signature over its own ephemerals (ruling
        /// R7, §A.3): `"rchat/ask-eph/v3\0" || asker_ik || ephemeral_key ||
        /// kem_ephemeral_pk`, 64 bytes, forwarded unmodified.
        initiator_ephemeral_sig: Vec<u8>,
        responder_ephemeral_sig: Vec<u8>,
    },
    /// 14: offline or knock delivery of one sealed v2 payload.
    QueuedMessage { payload: Vec<u8> },
    /// 15: ask for a circuit with `target_identity`; replaces CreateCircuit.
    /// v3 adds `kem_ephemeral_pk` (ML-KEM-768, 1184 bytes, fresh per ask).
    CircuitAsk {
        target_identity: Vec<u8>,
        ephemeral_key: Vec<u8>,
        kem_ephemeral_pk: Vec<u8>,
        /// The asker's identity signature over its ephemerals (R7), 64 bytes.
        ephemeral_sig: Vec<u8>,
        knock: Vec<u8>,
        resume_circuit: Option<CircuitId>,
    },
    /// 16 (protocol v3, §C.2): a blinded ask by rotating pair token, with no
    /// target identity and no knock. `pad` is `BLIND_PAD_LEN` bytes, so the
    /// encoding is exactly `ASK_WIRE_LEN` bytes, like an identity ask.
    CircuitAskBlind {
        pair_token: Vec<u8>,
        ephemeral_key: Vec<u8>,
        kem_ephemeral_pk: Vec<u8>,
        /// As in `CircuitAsk` (R7), 64 bytes.
        ephemeral_sig: Vec<u8>,
        pad: Vec<u8>,
    },
    /// 17 (protocol v3 §C.2, ruling R22): the token of our blinded ask whose
    /// X25519 ephemeral is `ephemeral_key` is already paired (spent).
    PairTokenBusy { ephemeral_key: Vec<u8> },
    /// 18 (protocol v3 §H.1, ruling R34a): the relay has handed over the
    /// queue it took at this connection's publish (possibly empty). Sent
    /// after every publish; `pad` is `QUEUE_HANDED_OVER_PAD_LEN` zero bytes.
    QueueHandedOver { pad: Vec<u8> },
}

/// `QueueHandedOver.pad` length (the frame's one fixed size).
pub const QUEUE_HANDED_OVER_PAD_LEN: usize = 32;

/// The only protocol version this core speaks (v3, hard cutover): the hello
/// offers `[PROTOCOL_VERSION]` and the relay must select it.
pub const PROTOCOL_VERSION: u32 = 3;

/// bincode length prefix of a `Vec<u8>` (fixint encoding: u64 LE).
const VEC_PREFIX: usize = 8;

/// Encoded length (bincode, without the 0x03 frame byte) of a v3
/// `CircuitAsk` as the core sends it: a knock and a resume id (the all-zero
/// id when there is none, so the `Some` arm is always on the wire). Variant
/// tag 4, target 8+32, EK 8+32, KEM ephemeral 8+1184, ephemeral signature
/// 8+64 (R7), knock 8+knock, resume 1+16.
pub const ASK_WIRE_LEN: usize = 4
    + (VEC_PREFIX + 32)
    + (VEC_PREFIX + 32)
    + (VEC_PREFIX + crate::kem::KEM_PK_LEN)
    + (VEC_PREFIX + ASK_EPH_SIG_LEN)
    + (VEC_PREFIX + crate::sealed::KNOCK_PAYLOAD_LEN)
    + (1 + 16);

/// `CircuitAskBlind.pad` length that makes a blinded ask exactly
/// `ASK_WIRE_LEN` bytes (§C.2): everything but the pad bytes is variant tag
/// 4, token 8+32, EK 8+32, KEM ephemeral 8+1184, ephemeral signature 8+64,
/// pad prefix 8. Derived from `KNOCK_PAYLOAD_LEN`, so it re-balances when
/// the knock size changes.
pub const BLIND_PAD_LEN: usize = ASK_WIRE_LEN
    - (4 + (VEC_PREFIX + 32)
        + (VEC_PREFIX + 32)
        + (VEC_PREFIX + crate::kem::KEM_PK_LEN)
        + (VEC_PREFIX + ASK_EPH_SIG_LEN)
        + VEC_PREFIX);

/// Length of an ask's ephemeral signature (Ed25519, ruling R7).
pub const ASK_EPH_SIG_LEN: usize = 64;

impl ControlMessage {
    /// Encode control message to bytes using bincode format (without frame type prefix)
    pub fn encode(&self) -> Vec<u8> {
        // Use bincode for serialization to match the server
        bincode::serialize(self).unwrap_or_default()
    }

    /// Encode with frame type prefix for WebSocket
    pub fn encode_with_frame_type(&self) -> Vec<u8> {
        let mut result = vec![FRAME_TYPE_CONTROL];
        result.extend_from_slice(&self.encode());
        result
    }

    /// Decode control message from bytes using bincode format (expects frame type prefix)
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.first() != Some(&FRAME_TYPE_CONTROL) {
            return None;
        }
        Self::decode_without_frame_type(&data[1..])
    }

    /// Decode control message from bytes using bincode format (without frame type prefix)
    pub fn decode_without_frame_type(data: &[u8]) -> Option<Self> {
        // Use bincode for deserialization to match the server
        bincode::deserialize(data).ok()
    }
}

/// Keepalive message types
#[derive(Debug, Clone)]
pub enum KeepaliveMessage {
    Ping { timestamp: u64 },
    Pong { ping_timestamp: u64, timestamp: u64 },
}

impl KeepaliveMessage {
    /// Encode to bytes using bincode format
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();

        match self {
            KeepaliveMessage::Ping { timestamp } => {
                result.extend_from_slice(&0u32.to_le_bytes()); // Ping variant index
                result.extend_from_slice(&timestamp.to_le_bytes());
            }
            KeepaliveMessage::Pong {
                ping_timestamp,
                timestamp,
            } => {
                result.extend_from_slice(&1u32.to_le_bytes()); // Pong variant index
                result.extend_from_slice(&ping_timestamp.to_le_bytes());
                result.extend_from_slice(&timestamp.to_le_bytes());
            }
        }

        result
    }

    /// Encode with frame type prefix
    pub fn encode_with_frame_type(&self) -> Vec<u8> {
        let mut result = vec![FRAME_TYPE_KEEPALIVE];
        result.extend_from_slice(&self.encode());
        result
    }

    /// Decode from bytes using bincode format (expects frame type prefix)
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 1 {
            return None;
        }

        let frame_type = data[0];
        if frame_type != FRAME_TYPE_KEEPALIVE {
            return None;
        }

        Self::decode_without_frame_type(&data[1..])
    }

    /// Decode from bytes using bincode format (without frame type prefix)
    pub fn decode_without_frame_type(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let variant_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match variant_index {
            0 => {
                // Ping
                if data.len() < 12 {
                    return None;
                }
                let timestamp = u64::from_le_bytes([
                    data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                ]);
                Some(KeepaliveMessage::Ping { timestamp })
            }
            1 => {
                // Pong
                if data.len() < 20 {
                    return None;
                }
                let ping_timestamp = u64::from_le_bytes([
                    data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                ]);
                let timestamp = u64::from_le_bytes([
                    data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
                ]);
                Some(KeepaliveMessage::Pong {
                    ping_timestamp,
                    timestamp,
                })
            }
            _ => None,
        }
    }
}

/// Unified frame types for WebSocket communication
// `Control` is the large variant since `CircuitCreatedV3` carries both
// asks' ephemeral signatures (R7). Frames are short-lived and travel boxed
// through the transport (`TransportEvent::Frame(Box<Frame>)`), so the size
// gap costs nothing worth an extra allocation per control frame.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Frame {
    /// Signaling message (JSON)
    Signaling(SignalingMessage),
    /// Relay packet (binary, encrypted)
    Relay(RelayPacket),
    /// Control message
    Control(ControlMessage),
    /// Keepalive
    Keepalive(KeepaliveMessage),
}

impl Frame {
    /// Decode frame from bytes received from WebSocket
    pub fn decode(data: &[u8]) -> Option<Self> {
        match *data.first()? {
            FRAME_TYPE_SIGNALING => serde_json::from_slice::<SignalingMessage>(&data[1..])
                .ok()
                .map(Frame::Signaling),
            FRAME_TYPE_RELAY => RelayPacket::decode(data).map(Frame::Relay),
            FRAME_TYPE_CONTROL => ControlMessage::decode(data).map(Frame::Control),
            FRAME_TYPE_KEEPALIVE => KeepaliveMessage::decode(data).map(Frame::Keepalive),
            _ => None,
        }
    }
}

/// Signaling message envelope (matches server protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    /// Message ID (UUID v4)
    pub id: String,
    /// Message type (string like "hello", "publish_key_bundle", etc.)
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Message payload with nested type/data format
    pub payload: SignalingPayload,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
}

impl SignalingMessage {
    /// Create a new signaling message
    pub fn new(msg_type: &str, payload: SignalingPayload) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: msg_type.to_string(),
            payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a hello message (protocol v3 offers only `[PROTOCOL_VERSION]`).
    pub fn hello(supported_versions: Vec<u32>) -> Self {
        let payload = serde_json::json!({
            "type": "hello",
            "data": {
                "supported_versions": supported_versions,
                "capabilities": CAPABILITIES,
                "client_info": {
                    "name": "RChatCore",
                    "version": "2.0",
                    "platform": "iOS"
                }
            }
        });
        Self::new("hello", SignalingPayload { inner: payload })
    }

    /// Create a publish_key_bundle message (v3: signed bundle + connection
    /// proof). `kem_pk` is standard base64 (§A.2).
    pub fn publish_key_bundle(bundle: &SignedBundle, conn_signature: &[u8; 64]) -> Self {
        let payload = serde_json::json!({
            "type": "publish_key_bundle",
            "data": {
                "key_bundle": {
                    "identity_key": hex::encode(bundle.identity_key),
                    "identity_agreement_key": hex::encode(bundle.identity_agreement_key),
                    "kem_pk": base64::engine::general_purpose::STANDARD.encode(&bundle.kem_pk[..]),
                    "bundle_signature": hex::encode(bundle.bundle_signature),
                    "one_time_pre_keys": []
                },
                "conn_signature": hex::encode(conn_signature)
            }
        });
        Self::new("publish_key_bundle", SignalingPayload { inner: payload })
    }
}

/// Signaling payload wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingPayload {
    #[serde(flatten)]
    pub inner: serde_json::Value,
}

/// Capabilities a v2 client and relay both announce.
pub const CAPABILITIES: [&str; 3] = ["key-auth-v1", "sealed-relay-v1", "mutual-circuits-v1"];

/// A signaling message as a binary frame (`0x01 || JSON`). The relay
/// accepts this form; it lets synchronous code use the binary send queue.
/// A serialization error is returned, never sent as an empty frame (Task 2
/// minor).
pub fn signaling_frame(msg: &SignalingMessage) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = vec![FRAME_TYPE_SIGNALING];
    out.extend_from_slice(&serde_json::to_vec(msg)?);
    Ok(out)
}

/// What a received signaling message means to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalingEvent {
    HelloResponse {
        selected_version: u32,
        auth_challenge: Option<[u8; 32]>,
        knock_ttl_hours: Option<u32>,
        relay_identity: Option<crate::relay_pin::RelayIdentityOffer>,
    },
    PublishOk {
        next_challenge: Option<[u8; 32]>,
    },
    PublishFailed,
    AuthenticationFailed,
    VersionMismatch,
    Other,
}

/// Exactly 64 lowercase hex characters -> 32 bytes.
fn parse_hex32(value: Option<&serde_json::Value>) -> Option<[u8; 32]> {
    let s = value?.as_str()?;
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Exactly `2 * N` lowercase hex characters -> N bytes.
fn parse_hex_n<const N: usize>(value: Option<&serde_json::Value>) -> Option<[u8; N]> {
    let s = value?.as_str()?;
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// `hello_response.relay_identity`; None if absent or malformed in any part.
fn parse_relay_identity(
    v: Option<&serde_json::Value>,
) -> Option<crate::relay_pin::RelayIdentityOffer> {
    let v = v?;
    let u32_of = |x: Option<&serde_json::Value>| x?.as_u64().and_then(|n| u32::try_from(n).ok());
    let chain = match v.get("chain") {
        None => Vec::new(),
        Some(c) => {
            // Length is judged by `walk_relay_chain` (too long -> Changed).
            c.as_array()?
                .iter()
                .map(|l| {
                    Some(crate::relay_pin::RelayLink {
                        prev_key: parse_hex_n::<32>(l.get("prev_key"))?,
                        new_key: parse_hex_n::<32>(l.get("new_key"))?,
                        version: u32_of(l.get("version"))?,
                        signature: parse_hex_n::<64>(l.get("signature"))?,
                    })
                })
                .collect::<Option<Vec<_>>>()?
        }
    };
    Some(crate::relay_pin::RelayIdentityOffer {
        key: parse_hex_n::<32>(v.get("key"))?,
        version: u32_of(v.get("version"))?,
        signature: parse_hex_n::<64>(v.get("signature"))?,
        chain,
    })
}

/// Classify a signaling message from the relay.
pub fn classify_signaling(msg: &SignalingMessage) -> SignalingEvent {
    let data = msg.payload.inner.get("data");
    let field = |name: &str| data.and_then(|d| d.get(name));
    match msg.msg_type.as_str() {
        "hello_response" => SignalingEvent::HelloResponse {
            selected_version: field("selected_version")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            auth_challenge: parse_hex32(field("auth_challenge")),
            knock_ttl_hours: field("knock_ttl_hours")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
            relay_identity: parse_relay_identity(field("relay_identity")),
        },
        "publish_key_bundle_response" => {
            if field("status").and_then(|v| v.as_str()) == Some("ok") {
                SignalingEvent::PublishOk {
                    next_challenge: parse_hex32(field("next_challenge")),
                }
            } else {
                SignalingEvent::PublishFailed
            }
        }
        "error" => match field("code").and_then(|v| v.as_str()) {
            Some("AuthenticationFailed") => SignalingEvent::AuthenticationFailed,
            Some("VersionMismatch") => SignalingEvent::VersionMismatch,
            _ => SignalingEvent::Other,
        },
        _ => SignalingEvent::Other,
    }
}

/// Frame padding for DPI evasion.
/// Adds 0-64 bytes of random padding after the real payload.
/// Format: `[real_len: u16 BE][real_data][random_padding]`
pub struct FramePadding;

impl FramePadding {
    /// Maximum padding bytes added
    pub const MAX_PADDING: usize = 64;

    /// Pad a payload by appending random bytes.
    /// The output can be later unpadded with `unpad`.
    pub fn pad(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len() + 2 + Self::MAX_PADDING);
        // Write real length as big-endian u16
        let real_len = data.len().min(u16::MAX as usize) as u16;
        result.extend_from_slice(&real_len.to_be_bytes());
        // Write real data
        result.extend_from_slice(data);
        // Generate random padding (0 to MAX_PADDING bytes)
        let pad_len = if cfg!(test) {
            8 // Deterministic for tests
        } else {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen_range(0..=Self::MAX_PADDING)
        };
        let mut padding = vec![0u8; pad_len];
        if !cfg!(test) {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.fill(&mut padding[..]);
        } else {
            // Deterministic test padding
            for (i, b) in padding.iter_mut().enumerate() {
                *b = (i % 256) as u8;
            }
        }
        result.extend_from_slice(&padding);
        result
    }

    /// Remove padding and return the original payload.
    /// Returns `None` if the data is malformed.
    pub fn unpad(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 2 {
            return None;
        }
        let real_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + real_len {
            return None;
        }
        Some(data[2..2 + real_len].to_vec())
    }
}

/// Packet padding for DPI evasion.
/// Packets are padded to 1KB (1024 byte) boundaries up to a max of 16KB.
pub struct PacketPadding;

impl PacketPadding {
    /// Boundary size in bytes (1KB)
    pub const BOUNDARY: usize = 1024;
    /// Maximum padded size (16KB)
    pub const MAX_SIZE: usize = 16 * 1024;

    /// Pad a packet to the next 1KB boundary.
    /// If the packet is already aligned, it is padded to the next boundary
    /// to avoid revealing exact-size messages.
    pub fn pad_packet(data: &[u8]) -> Vec<u8> {
        if data.len() >= Self::MAX_SIZE {
            return data.to_vec();
        }
        let padded_len = ((data.len() / Self::BOUNDARY) + 1) * Self::BOUNDARY;
        let padded_len = padded_len.min(Self::MAX_SIZE);
        let mut result = data.to_vec();
        result.resize(padded_len, 0);
        result
    }

    /// Strip packet padding (truncate to the actual length).
    /// This requires knowing the real length (e.g. from the frame padding prefix).
    pub fn strip_packet_padding(data: &[u8], real_len: usize) -> Vec<u8> {
        data[..real_len.min(data.len())].to_vec()
    }

    /// Generate a dummy packet of random size (64-1024 bytes), padded to 1KB.
    /// Used for constant-rate traffic shaping.
    pub fn generate_dummy_packet() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let real_len = rng.gen_range(64..=1024usize);
        let mut packet = vec![0u8; real_len];
        rng.fill(&mut packet[..]);
        Self::pad_packet(&packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_generation() {
        let id1 = MessageId::new();
        let id2 = MessageId::new();
        assert_ne!(id1.0, id2.0);
        assert_eq!(id1.0.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_relay_packet_encode_decode() {
        let circuit_id = CircuitId::new();
        let payload = b"Hello, World!".to_vec();
        let packet = RelayPacket::new(circuit_id.clone(), payload.clone(), PacketFlags::default());

        let encoded = packet.encode();
        let decoded = RelayPacket::decode_without_frame_type(&encoded).unwrap();

        assert_eq!(decoded.circuit_id.0, circuit_id.0);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay_packet_with_frame_type() {
        let circuit_id = CircuitId::new();
        let payload = b"Test payload".to_vec();
        let packet = RelayPacket::new(circuit_id, payload, PacketFlags::default());

        let encoded = packet.encode_with_frame_type();
        assert_eq!(encoded[0], FRAME_TYPE_RELAY);

        let decoded = RelayPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.version, RelayPacket::CURRENT_VERSION);
    }

    #[test]
    fn test_control_message_circuit_created() {
        let msg = ControlMessage::CircuitCreated {
            circuit_id: CircuitId::new(),
            token: vec![1, 2, 3, 4],
            target_circuit_id: CircuitId::new(),
            initiator_identity: Some(vec![5, 6, 7, 8]),
            initiator_identity_agreement_key: None,
            initiator_agreement_key: None,
            initiator_ephemeral_key: Some(vec![9, 10, 11, 12]),
            responder_agreement_key: None,
        };

        let encoded = msg.encode();
        println!("Client CircuitCreated encoded: {:?}", encoded);
        let decoded = ControlMessage::decode_without_frame_type(&encoded).unwrap();

        match decoded {
            ControlMessage::CircuitCreated {
                initiator_identity,
                initiator_ephemeral_key,
                ..
            } => {
                assert_eq!(initiator_identity, Some(vec![5, 6, 7, 8]));
                assert_eq!(initiator_ephemeral_key, Some(vec![9, 10, 11, 12]));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_server_to_client_compatibility() {
        // Build a CircuitCreated message and encode it with bincode (matching server serialization).
        // Prepend the frame type byte so decode() can strip it and deserialize.
        let msg = ControlMessage::CircuitCreated {
            circuit_id: CircuitId([
                91, 109, 143, 10, 44, 78, 107, 141, 15, 42, 76, 110, 139, 13, 47, 74,
            ]),
            token: vec![0u8; 32],
            target_circuit_id: CircuitId([
                160, 180, 198, 216, 224, 242, 132, 149, 166, 184, 192, 210, 228, 246, 136, 26,
            ]),
            initiator_identity: Some(vec![
                160, 180, 198, 216, 224, 242, 132, 149, 166, 184, 192, 210, 228, 246, 136, 26,
            ]),
            initiator_identity_agreement_key: None,
            initiator_agreement_key: Some(vec![0u8; 32]),
            initiator_ephemeral_key: None,
            responder_agreement_key: None,
        };

        // Encode with bincode and prepend frame type byte
        let body = msg.encode();
        let server_encoded = std::iter::once(FRAME_TYPE_CONTROL)
            .chain(body.into_iter())
            .collect::<Vec<u8>>();

        // Decode with frame type prefix (full message)
        let decoded = ControlMessage::decode(&server_encoded);

        println!("Decoded from server format: {:?}", decoded.is_some());

        match decoded {
            Some(ControlMessage::CircuitCreated {
                initiator_identity, ..
            }) => {
                println!("initiator_identity: {:?}", initiator_identity);
                assert!(
                    initiator_identity.is_some(),
                    "initiator_identity should be Some"
                );
            }
            _ => panic!("Failed to decode or wrong message type"),
        }
    }

    #[test]
    fn test_keepalive_encode_decode() {
        let ping = KeepaliveMessage::Ping { timestamp: 12345 };
        let encoded = ping.encode_with_frame_type();
        let decoded = KeepaliveMessage::decode(&encoded).unwrap();

        match decoded {
            KeepaliveMessage::Ping { timestamp } => {
                assert_eq!(timestamp, 12345);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags {
            encrypted: true,
            compressed: false,
            fragmented: true,
            ack_required: false,
            keepalive: false,
        };

        let encoded = flags.to_u8();
        assert_eq!(encoded, 0x05); // encrypted | fragmented

        let decoded = PacketFlags::from_u8(encoded);
        assert!(decoded.encrypted);
        assert!(!decoded.compressed);
        assert!(decoded.fragmented);
    }

    #[test]
    fn test_auth_tag() {
        let circuit_id = CircuitId([0u8; 16]);
        let payload = b"test payload";
        let token_key = [0x42u8; 32];

        let tag1 = RelayPacket::compute_auth_tag(&circuit_id, payload, &token_key);
        let tag2 = RelayPacket::compute_auth_tag(&circuit_id, payload, &token_key);

        assert_eq!(tag1, tag2);

        // Different payload should give different tag
        let tag3 = RelayPacket::compute_auth_tag(&circuit_id, b"different", &token_key);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_frame_padding_roundtrip() {
        let original = b"Hello, secure world!";
        let padded = FramePadding::pad(original);

        // Should have length prefix + data + padding
        assert!(padded.len() > original.len());

        let unpadded = FramePadding::unpad(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_frame_padding_empty() {
        let original: &[u8] = b"";
        let padded = FramePadding::pad(original);
        assert!(padded.len() >= 2); // At least the length prefix

        let unpadded = FramePadding::unpad(&padded).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_frame_padding_max_size() {
        let original = vec![0u8; FramePadding::MAX_PADDING + 10];
        let padded = FramePadding::pad(&original);

        let unpadded = FramePadding::unpad(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_frame_padding_invalid_data() {
        // Too short to contain length
        assert!(FramePadding::unpad(&[0x00]).is_none());

        // Length claims more data than available
        assert!(FramePadding::unpad(&[0x00, 0x10]).is_none());
    }

    #[test]
    fn test_packet_padding_boundary() {
        // 500 bytes should pad to 1024
        let data = vec![0xABu8; 500];
        let padded = PacketPadding::pad_packet(&data);
        assert_eq!(padded.len(), 1024);

        // 1024 bytes pad to next boundary (2048) to avoid revealing exact size
        let data = vec![0xCDu8; 1024];
        let padded = PacketPadding::pad_packet(&data);
        assert_eq!(padded.len(), 2048);

        // 1025 bytes should pad to 2048
        let data = vec![0xEFu8; 1025];
        let padded = PacketPadding::pad_packet(&data);
        assert_eq!(padded.len(), 2048);
    }

    #[test]
    fn test_packet_padding_max_size() {
        // Data larger than MAX_SIZE should not be padded
        let data = vec![0u8; PacketPadding::MAX_SIZE + 100];
        let padded = PacketPadding::pad_packet(&data);
        assert_eq!(padded.len(), data.len());
    }

    #[test]
    fn test_packet_padding_strip() {
        let data = b"secret message";
        let padded = PacketPadding::pad_packet(data);
        let stripped = PacketPadding::strip_packet_padding(&padded, data.len());
        assert_eq!(&stripped, data);
    }

    #[test]
    fn test_dummy_packet() {
        let dummy = PacketPadding::generate_dummy_packet();
        // Should be padded to 1KB boundary
        assert_eq!(dummy.len() % PacketPadding::BOUNDARY, 0);
        assert!(dummy.len() >= 64);
        assert!(dummy.len() <= PacketPadding::MAX_SIZE);
    }

    fn sample_peer() -> PeerBundle {
        PeerBundle {
            identity_key: vec![1; 32],
            identity_agreement_key: vec![2; 32],
            kem_pk: vec![3; 1184],
            bundle_signature: vec![4; 64],
        }
    }

    fn signaling(msg_type: &str, data: serde_json::Value) -> SignalingMessage {
        SignalingMessage::new(
            msg_type,
            SignalingPayload {
                inner: serde_json::json!({ "type": msg_type, "data": data }),
            },
        )
    }

    /// v3 (§A.3): CircuitCreatedV3 survives encode/decode with both EKs and
    /// both KEM ephemerals.
    #[test]
    fn c1_circuit_created_v3_round_trip() {
        let msg = ControlMessage::CircuitCreatedV3 {
            circuit_id: CircuitId([0xC1; 16]),
            token: vec![7; 32],
            target_circuit_id: CircuitId([0xC2; 16]),
            role: 1,
            peer: sample_peer(),
            initiator_ephemeral_key: vec![0x61; 32],
            responder_ephemeral_key: vec![0x62; 32],
            initiator_kem_ephemeral_pk: vec![0x71; 1184],
            responder_kem_ephemeral_pk: vec![0x72; 1184],
            initiator_ephemeral_sig: vec![0x81; 64],
            responder_ephemeral_sig: vec![0x82; 64],
        };
        match ControlMessage::decode(&msg.encode_with_frame_type()) {
            Some(ControlMessage::CircuitCreatedV3 {
                circuit_id,
                token,
                target_circuit_id,
                role,
                peer,
                initiator_ephemeral_key,
                responder_ephemeral_key,
                initiator_kem_ephemeral_pk,
                responder_kem_ephemeral_pk,
                initiator_ephemeral_sig,
                responder_ephemeral_sig,
            }) => {
                assert_eq!(circuit_id, CircuitId([0xC1; 16]));
                assert_eq!(token, vec![7; 32]);
                assert_eq!(target_circuit_id, CircuitId([0xC2; 16]));
                assert_eq!(role, 1);
                assert_eq!(peer, sample_peer());
                assert_eq!(initiator_ephemeral_key, vec![0x61; 32]);
                assert_eq!(responder_ephemeral_key, vec![0x62; 32]);
                assert_eq!(initiator_kem_ephemeral_pk, vec![0x71; 1184]);
                assert_eq!(responder_kem_ephemeral_pk, vec![0x72; 1184]);
                assert_eq!(initiator_ephemeral_sig, vec![0x81; 64]);
                assert_eq!(responder_ephemeral_sig, vec![0x82; 64]);
            }
            other => panic!("decoded {other:?}"),
        }
    }

    /// C1: QueuedMessage and CircuitAsk v3 (resume Some and None) round-trip.
    #[test]
    fn c1_queued_message_and_circuit_ask_round_trip() {
        let queued = ControlMessage::QueuedMessage {
            payload: vec![0x02; 200],
        };
        match ControlMessage::decode(&queued.encode_with_frame_type()) {
            Some(ControlMessage::QueuedMessage { payload }) => assert_eq!(payload, vec![0x02; 200]),
            other => panic!("decoded {other:?}"),
        }
        for resume in [None, Some(CircuitId([9; 16]))] {
            let ask = ControlMessage::CircuitAsk {
                target_identity: vec![0xAA; 32],
                ephemeral_key: vec![0xEE; 32],
                kem_ephemeral_pk: vec![0xEF; 1184],
                ephemeral_sig: vec![0xE5; 64],
                knock: vec![crate::sealed::KNOCK_VERSION; crate::sealed::KNOCK_PAYLOAD_LEN],
                resume_circuit: resume.clone(),
            };
            match ControlMessage::decode(&ask.encode_with_frame_type()) {
                Some(ControlMessage::CircuitAsk {
                    target_identity,
                    ephemeral_key,
                    kem_ephemeral_pk,
                    ephemeral_sig,
                    knock,
                    resume_circuit,
                }) => {
                    assert_eq!(target_identity, vec![0xAA; 32]);
                    assert_eq!(ephemeral_key, vec![0xEE; 32]);
                    assert_eq!(kem_ephemeral_pk, vec![0xEF; 1184]);
                    assert_eq!(ephemeral_sig, vec![0xE5; 64]);
                    assert_eq!(knock.len(), crate::sealed::KNOCK_PAYLOAD_LEN);
                    assert_eq!(resume_circuit, resume);
                }
                other => panic!("decoded {other:?}"),
            }
        }
    }

    /// v3 (§C.2): CircuitAskBlind round-trips.
    #[test]
    fn c1_circuit_ask_blind_round_trip() {
        let blind = ControlMessage::CircuitAskBlind {
            pair_token: vec![0xB1; 32],
            ephemeral_key: vec![0xB2; 32],
            kem_ephemeral_pk: vec![0xB3; 1184],
            ephemeral_sig: vec![0xB4; 64],
            pad: vec![0; BLIND_PAD_LEN],
        };
        match ControlMessage::decode(&blind.encode_with_frame_type()) {
            Some(ControlMessage::CircuitAskBlind {
                pair_token,
                ephemeral_key,
                kem_ephemeral_pk,
                ephemeral_sig,
                pad,
            }) => {
                assert_eq!(pair_token, vec![0xB1; 32]);
                assert_eq!(ephemeral_key, vec![0xB2; 32]);
                assert_eq!(kem_ephemeral_pk, vec![0xB3; 1184]);
                assert_eq!(ephemeral_sig, vec![0xB4; 64]);
                assert_eq!(pad, vec![0; BLIND_PAD_LEN]);
            }
            other => panic!("decoded {other:?}"),
        }
    }

    /// v3 (§C.2): a blinded ask and an identity ask carrying a knock have
    /// the same encoded length, measured from the real encodings.
    #[test]
    fn blind_and_identity_asks_have_equal_wire_length() {
        let ask = ControlMessage::CircuitAsk {
            target_identity: vec![0xAA; 32],
            ephemeral_key: vec![0xEE; 32],
            kem_ephemeral_pk: vec![0xEF; crate::kem::KEM_PK_LEN],
            ephemeral_sig: vec![0xE5; ASK_EPH_SIG_LEN],
            knock: vec![crate::sealed::KNOCK_VERSION; crate::sealed::KNOCK_PAYLOAD_LEN],
            resume_circuit: Some(CircuitId([0; 16])),
        };
        let blind = ControlMessage::CircuitAskBlind {
            pair_token: vec![0xB1; 32],
            ephemeral_key: vec![0xB2; 32],
            kem_ephemeral_pk: vec![0xB3; crate::kem::KEM_PK_LEN],
            ephemeral_sig: vec![0xB4; ASK_EPH_SIG_LEN],
            pad: vec![0; BLIND_PAD_LEN],
        };
        assert_eq!(ask.encode().len(), ASK_WIRE_LEN, "identity ask");
        assert_eq!(blind.encode().len(), ASK_WIRE_LEN, "blinded ask");
        assert_eq!(
            ask.encode_with_frame_type().len(),
            blind.encode_with_frame_type().len()
        );
        // Derived from the knock size (§C.2): ASK_WIRE_LEN = knock + 1373,
        // BLIND_PAD_LEN = knock + 17. The R7 signature adds 8+64 to both
        // forms, so the pad is unchanged by it. Pinned for knock v3 (5120).
        assert_eq!(crate::sealed::KNOCK_PAYLOAD_LEN + 1373, ASK_WIRE_LEN);
        assert_eq!(BLIND_PAD_LEN, crate::sealed::KNOCK_PAYLOAD_LEN + 17);
        assert_eq!((ASK_WIRE_LEN, BLIND_PAD_LEN), (6493, 5137));
    }

    /// v3: unchanged variants keep their bincode tags; CircuitCreatedV3
    /// takes v2's slot 13 and CircuitAskBlind is appended as 16.
    #[test]
    fn c1_v3_variant_indices() {
        let created = ControlMessage::CircuitCreatedV3 {
            circuit_id: CircuitId([0; 16]),
            token: vec![],
            target_circuit_id: CircuitId([0; 16]),
            role: 0,
            peer: sample_peer(),
            initiator_ephemeral_key: vec![],
            responder_ephemeral_key: vec![],
            initiator_kem_ephemeral_pk: vec![],
            responder_kem_ephemeral_pk: vec![],
            initiator_ephemeral_sig: vec![],
            responder_ephemeral_sig: vec![],
        };
        assert_eq!(created.encode()[..4], 13u32.to_le_bytes());
        assert_eq!(
            ControlMessage::QueuedMessage { payload: vec![] }.encode()[..4],
            14u32.to_le_bytes()
        );
        let ask = ControlMessage::CircuitAsk {
            target_identity: vec![],
            ephemeral_key: vec![],
            kem_ephemeral_pk: vec![],
            ephemeral_sig: vec![],
            knock: vec![],
            resume_circuit: None,
        };
        assert_eq!(ask.encode()[..4], 15u32.to_le_bytes());
        let blind = ControlMessage::CircuitAskBlind {
            pair_token: vec![],
            ephemeral_key: vec![],
            kem_ephemeral_pk: vec![],
            ephemeral_sig: vec![],
            pad: vec![],
        };
        assert_eq!(blind.encode()[..4], 16u32.to_le_bytes());
        let read = ControlMessage::ReadReceipt {
            message_id: String::new(),
            read_at: 0,
            circuit_id: CircuitId([0; 16]),
        };
        assert_eq!(read.encode()[..4], 12u32.to_le_bytes());
        assert_eq!(ControlMessageVariant::CircuitCreatedV3 as u32, 13);
        assert_eq!(ControlMessageVariant::QueuedMessage as u32, 14);
        assert_eq!(ControlMessageVariant::CircuitAsk as u32, 15);
        assert_eq!(ControlMessageVariant::CircuitAskBlind as u32, 16);
        assert_eq!(ControlMessageVariant::PairTokenBusy as u32, 17);
        let busy = ControlMessage::PairTokenBusy {
            ephemeral_key: vec![0xE1; 32],
        };
        assert_eq!(busy.encode()[..4], 17u32.to_le_bytes());
        assert!(matches!(
            ControlMessage::decode(&busy.encode_with_frame_type()),
            Some(ControlMessage::PairTokenBusy { ephemeral_key }) if ephemeral_key == vec![0xE1; 32]
        ));
        let err = ControlMessage::Error {
            code: ControlErrorCode::NotImplemented,
            message: String::new(),
        };
        assert_eq!(err.encode()[4..8], 9u32.to_le_bytes());
        assert_eq!(
            ControlErrorCode::from_u8(9),
            ControlErrorCode::NotImplemented
        );
        let busy = ControlMessage::Error {
            code: ControlErrorCode::PairTokenBusy,
            message: String::new(),
        };
        assert_eq!(busy.encode()[4..8], 10u32.to_le_bytes());
        assert_eq!(
            ControlErrorCode::from_u8(10),
            ControlErrorCode::PairTokenBusy
        );
        assert_eq!(ControlErrorCode::PairTokenBusy.to_u8(), 10);
    }

    /// v3 §9a: unified-frame prefix 0x05 is reserved for future media. The
    /// core's frame types are 0x01–0x04 only, every encoder starts with one
    /// of them, and an incoming 0x05 frame is not decoded.
    #[test]
    fn core_never_uses_reserved_media_prefix_0x05() {
        let types = [
            FRAME_TYPE_SIGNALING,
            FRAME_TYPE_RELAY,
            FRAME_TYPE_CONTROL,
            FRAME_TYPE_KEEPALIVE,
        ];
        assert_eq!(types, [1, 2, 3, 4]);
        let encoded = [
            signaling_frame(&SignalingMessage::hello(vec![PROTOCOL_VERSION])).unwrap(),
            RelayPacket::new(CircuitId([1; 16]), vec![0; 8], PacketFlags::default()).encode(),
            ControlMessage::QueuedMessage { payload: vec![] }.encode_with_frame_type(),
            KeepaliveMessage::Ping { timestamp: 1 }.encode_with_frame_type(),
        ];
        for bytes in encoded {
            assert!(types.contains(&bytes[0]));
            assert_ne!(bytes[0], 0x05);
        }
        assert!(Frame::decode(&[0x05]).is_none());
        assert!(Frame::decode(&[0x05, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn peer_bundle_converts_to_and_from_signed() {
        let signed = crate::keyauth::SignedBundle {
            identity_key: [1; 32],
            identity_agreement_key: [2; 32],
            kem_pk: Box::new([3; 1184]),
            bundle_signature: [4; 64],
        };
        let wire = PeerBundle::from_signed(&signed);
        assert_eq!(wire, sample_peer());
        assert_eq!(wire.to_signed().unwrap(), signed);
        let mut short = sample_peer();
        short.bundle_signature.pop();
        assert_eq!(
            short.to_signed(),
            Err(crate::keyauth::KeyAuthError::BadLength)
        );
        for len in [0, 32, 1183, 1185] {
            let mut odd = sample_peer();
            odd.kem_pk = vec![3; len];
            assert_eq!(
                odd.to_signed(),
                Err(crate::keyauth::KeyAuthError::BadLength),
                "kem_pk of {len} bytes"
            );
        }
    }

    #[test]
    fn hello_offers_v3_and_the_three_capabilities() {
        assert_eq!(PROTOCOL_VERSION, 3);
        let hello = SignalingMessage::hello(vec![PROTOCOL_VERSION]);
        assert_eq!(hello.msg_type, "hello");
        let data = &hello.payload.inner["data"];
        assert_eq!(data["supported_versions"], serde_json::json!([3]));
        assert_eq!(
            data["capabilities"],
            serde_json::json!(["key-auth-v1", "sealed-relay-v1", "mutual-circuits-v1"])
        );
        assert_eq!(data["client_info"]["name"], "RChatCore");
    }

    #[test]
    fn classify_hello_response_with_challenge_and_ttl() {
        let msg = signaling(
            "hello_response",
            serde_json::json!({
                "selected_version": 3,
                "server_info": { "version": "x", "capabilities": [] },
                "auth_challenge": "4e".repeat(32),
                "knock_ttl_hours": 72
            }),
        );
        assert_eq!(
            classify_signaling(&msg),
            SignalingEvent::HelloResponse {
                selected_version: 3,
                auth_challenge: Some([0x4e; 32]),
                knock_ttl_hours: Some(72),
                relay_identity: None,
            }
        );
    }

    #[test]
    fn classify_treats_a_malformed_challenge_as_absent() {
        for bad in [
            "4E".repeat(32),
            "4e".repeat(31),
            "zz".repeat(32),
            String::new(),
        ] {
            let msg = signaling(
                "hello_response",
                serde_json::json!({ "selected_version": 2, "auth_challenge": bad }),
            );
            assert!(matches!(
                classify_signaling(&msg),
                SignalingEvent::HelloResponse {
                    auth_challenge: None,
                    ..
                }
            ));
        }
        let v1 = signaling(
            "hello_response",
            serde_json::json!({ "selected_version": 1 }),
        );
        assert_eq!(
            classify_signaling(&v1),
            SignalingEvent::HelloResponse {
                selected_version: 1,
                auth_challenge: None,
                knock_ttl_hours: None,
                relay_identity: None,
            }
        );
    }

    #[test]
    fn classify_publish_responses_and_errors() {
        let ok = signaling(
            "publish_key_bundle_response",
            serde_json::json!({ "status": "ok", "bundle_id": "b", "next_challenge": "55".repeat(32) }),
        );
        assert_eq!(
            classify_signaling(&ok),
            SignalingEvent::PublishOk {
                next_challenge: Some([0x55; 32])
            }
        );
        let failed = signaling(
            "publish_key_bundle_response",
            serde_json::json!({ "status": "error" }),
        );
        assert_eq!(classify_signaling(&failed), SignalingEvent::PublishFailed);
        let auth = signaling(
            "error",
            serde_json::json!({ "code": "AuthenticationFailed", "message": "key authentication failed" }),
        );
        assert_eq!(
            classify_signaling(&auth),
            SignalingEvent::AuthenticationFailed
        );
        let version = signaling(
            "error",
            serde_json::json!({ "code": "VersionMismatch", "message": "client too old; update rChat" }),
        );
        assert_eq!(
            classify_signaling(&version),
            SignalingEvent::VersionMismatch
        );
        let other = signaling(
            "error",
            serde_json::json!({ "code": "RateLimited", "message": "x" }),
        );
        assert_eq!(classify_signaling(&other), SignalingEvent::Other);
        assert_eq!(
            classify_signaling(&signaling("pong", serde_json::json!({}))),
            SignalingEvent::Other
        );
    }

    #[test]
    fn binary_signaling_frame_round_trips_through_frame_decode() {
        let hello = SignalingMessage::hello(vec![PROTOCOL_VERSION]);
        let bytes = signaling_frame(&hello).unwrap();
        assert_eq!(bytes[0], FRAME_TYPE_SIGNALING);
        match Frame::decode(&bytes) {
            Some(Frame::Signaling(m)) => {
                assert_eq!(m.msg_type, "hello");
                assert_eq!(m.id, hello.id);
            }
            other => panic!("decoded {other:?}"),
        }
        assert!(Frame::decode(&[FRAME_TYPE_SIGNALING, b'{']).is_none());
        assert!(Frame::decode(&[]).is_none());
    }

    #[test]
    fn relay_packet_with_huge_length_field_does_not_panic() {
        let mut bytes = vec![FRAME_TYPE_RELAY];
        bytes.extend_from_slice(&[0u8; 34]);
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(RelayPacket::decode(&bytes).is_none());
    }
}
