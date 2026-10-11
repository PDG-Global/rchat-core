//! On-device session store (spec §18.3): sealed, versioned, identity-bound
//! records written through a synchronous `StateSink`.

use crate::crypto::RatchetSnapshotV1;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const RECORD_MAGIC: &[u8; 4] = b"RCS1";
pub const RECORD_VERSION: u8 = 1;
pub const KIND_META: u8 = 1;
pub const KIND_PEER: u8 = 2;
pub const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub const META_KEY: &str = "meta";

pub trait StateSink: Send + Sync {
    /// Durably replace (or, when `sealed` is empty, delete) one record.
    fn write(&self, record_key: &str, sealed: &[u8]) -> Result<(), String>;
}

/// Why a stored record was discarded (the `reason` of
/// `StatusEvent::StateRestoreFailed`, spec §18.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreError {
    Tag = 1,
    Version = 2,
    Parse = 3,
    TooLarge = 4,
}

#[derive(Serialize, Deserialize)]
pub struct CircuitV1 {
    pub circuit_id: [u8; 16],
    pub target_circuit_id: [u8; 16],
    pub token: [u8; 32],
}

/// The token authenticates the circuit: wiped when the record goes.
impl Drop for CircuitV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessionSnapshotV1 {
    pub ratchet: RatchetSnapshotV1,
    pub is_established: bool,
    pub is_initiator: bool,
    pub needs_hello_sync: bool,
    pub circuit: Option<CircuitV1>,
    pub replaced_established: bool,
    /// `ChatSession::peer_notice_heard`.
    pub peer_notice_heard: bool,
    /// `ChatSession::reset_since_unix`.
    pub reset_since_unix: Option<u64>,
    pub peer_ak: [u8; 32],
    pub created_at_unix: u64,
    /// `ChatSession::reported_lost`: (id, last reason, made eligible).
    pub reported_lost: Vec<([u8; 16], u8, bool)>,
    /// `ChatSession::session_binding` (D45): a hash of SK, not SK.
    pub session_binding: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct RetiredSnapshotV1 {
    pub ratchet: RatchetSnapshotV1,
    pub retired_at_unix: u64,
    pub decrypts: u32,
    /// Agreement key of the bundle the retired session was made from.
    pub peer_ak: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SentIdV1 {
    pub id: [u8; 16],
    pub sent_at_unix: u64,
    pub delivered: bool,
    pub pin_ak: [u8; 32],
    pub pin_version: u32,
    pub resent: bool,
}

/// One contact's record. No `Drop`: its nested snapshots wipe themselves,
/// and callers move fields out of it (F3). `lost_unstored_ids` holds the
/// reason-2 ids (F4).
#[derive(Serialize, Deserialize, Default)]
pub struct PeerRecordV1 {
    pub peer_ik: [u8; 32],
    pub session: Option<SessionSnapshotV1>,
    pub retired: Option<RetiredSnapshotV1>,
    pub sent_ids: Vec<SentIdV1>,
    pub received_ids: Vec<[u8; 16]>,
    pub seen_ids: Vec<[u8; 16]>,
    pub owed_receipts: Vec<(u8, [u8; 16])>,
    pub delivered_unstored: Vec<[u8; 16]>,
    pub pending_send_ids: Vec<[u8; 16]>,
    pub undecryptable_ids: Vec<[u8; 16]>,
    pub lost_unstored_ids: Vec<[u8; 16]>,
    /// Lost ids already reported (reason 2) with the report's unix time,
    /// awaiting a same-id resend (72 h at most).
    pub lost_reported: Vec<([u8; 16], u64)>,
    pub notice_due: bool,
    /// Flags of the notice still owed (`FLAG_NO_PRIOR_SESSION` or 0).
    pub notice_flags: u8,
    pub auto_resends_unix: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HeldV1 {
    pub sender_ik: [u8; 32],
    pub message_id: [u8; 16],
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct MetaRecordV1 {
    pub pending_closes: Vec<[u8; 16]>,
    pub unanswered_asks: Vec<[u8; 32]>,
    pub held: Vec<HeldV1>,
}

/// Serialise a record body straight into a wiped buffer. The buffer is
/// sized up front, so serialising never reallocates and leaves no unwiped
/// copy of the secrets behind.
pub fn encode_body<T: Serialize>(value: &T) -> bincode::Result<Zeroizing<Vec<u8>>> {
    let len = usize::try_from(bincode::serialized_size(value)?)
        .map_err(|e| Box::new(bincode::ErrorKind::Custom(e.to_string())))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(len));
    bincode::serialize_into(&mut *buf, value)?;
    Ok(buf)
}

const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 24;
/// Bytes a sealed record adds to its body: the header and the AEAD tag.
pub const SEAL_OVERHEAD: usize = HEADER_LEN + 16;

pub struct StateKeys {
    state_key: Zeroizing<[u8; 32]>,
}

impl StateKeys {
    pub fn new(state_key: [u8; 32]) -> Self {
        Self {
            state_key: Zeroizing::new(state_key),
        }
    }

    pub fn record_key_for(&self, peer_ik: &[u8; 32]) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&*self.state_key).expect("any key length");
        mac.update(b"rchat/state-record/v1\0");
        mac.update(peer_ik);
        hex::encode(&mac.finalize().into_bytes()[..16])
    }

    fn aead(&self, our_ik: &[u8; 32]) -> XChaCha20Poly1305 {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"rchat/state-seal/v1"), &*self.state_key);
        let mut k = Zeroizing::new([0u8; 32]);
        hk.expand(our_ik, &mut *k).expect("32 bytes");
        XChaCha20Poly1305::new((&*k).into())
    }

    fn aad(our_ik: &[u8; 32], record_key: &str, version: u8, kind: u8, counter: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(4 + 2 + 8 + 32 + record_key.len());
        aad.extend_from_slice(RECORD_MAGIC);
        aad.push(version);
        aad.push(kind);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(our_ik);
        aad.extend_from_slice(record_key.as_bytes());
        aad
    }

    /// Seal `body` (the caller owns and wipes it; see `encode_body`).
    pub fn seal(
        &self,
        our_ik: &[u8; 32],
        record_key: &str,
        kind: u8,
        counter: u64,
        body: &[u8],
    ) -> Vec<u8> {
        debug_assert!(kind == KIND_META || kind == KIND_PEER);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = Self::aad(our_ik, record_key, RECORD_VERSION, kind, counter);
        let ct = self
            .aead(our_ik)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .expect("XChaCha20-Poly1305 encrypt cannot fail");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_VERSION);
        out.push(kind);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Open a sealed record; the plaintext comes back in a wiped buffer.
    pub fn open(
        &self,
        our_ik: &[u8; 32],
        record_key: &str,
        sealed: &[u8],
    ) -> Result<(u8, u64, Zeroizing<Vec<u8>>), RestoreError> {
        if sealed.len() > MAX_RECORD_BYTES {
            return Err(RestoreError::TooLarge);
        }
        if sealed.len() < HEADER_LEN + 16 || &sealed[..4] != RECORD_MAGIC {
            return Err(RestoreError::Parse);
        }
        let (version, kind) = (sealed[4], sealed[5]);
        if version != RECORD_VERSION {
            return Err(RestoreError::Version);
        }
        if kind != KIND_META && kind != KIND_PEER {
            return Err(RestoreError::Parse);
        }
        let counter = u64::from_be_bytes(sealed[6..14].try_into().expect("8 bytes"));
        let aad = Self::aad(our_ik, record_key, version, kind, counter);
        let plain = self
            .aead(our_ik)
            .decrypt(
                XNonce::from_slice(&sealed[14..38]),
                Payload {
                    msg: &sealed[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| RestoreError::Tag)?;
        Ok((kind, counter, Zeroizing::new(plain)))
    }
}

pub fn is_valid_record_key(k: &str) -> bool {
    k == META_KEY || (k.len() == 32 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> Vec<u8> {
        bincode::serialize(&MetaRecordV1 {
            pending_closes: vec![[9; 16]],
            ..Default::default()
        })
        .unwrap()
    }

    /// SP3: round-trip; any flipped byte, another identity or key, an unknown
    /// version and an oversize record all fail.
    #[test]
    fn sp3_record_tamper_identity_version() {
        let keys = StateKeys::new([1; 32]);
        let me = [0xA1; 32];
        let sealed = keys.seal(&me, META_KEY, KIND_META, 7, &body());
        let (kind, counter, plain) = keys.open(&me, META_KEY, &sealed).unwrap();
        assert_eq!(
            (kind, counter, plain.as_slice()),
            (KIND_META, 7, body().as_slice())
        );
        for i in 0..sealed.len() {
            let mut t = sealed.clone();
            t[i] ^= 1;
            let e = keys.open(&me, META_KEY, &t).unwrap_err();
            assert!(
                matches!(
                    e,
                    RestoreError::Tag | RestoreError::Version | RestoreError::Parse
                ),
                "byte {i}"
            );
        }
        assert_eq!(
            keys.open(&[0xB2; 32], META_KEY, &sealed).unwrap_err(),
            RestoreError::Tag
        );
        assert_eq!(
            StateKeys::new([2; 32])
                .open(&me, META_KEY, &sealed)
                .unwrap_err(),
            RestoreError::Tag
        );
        assert_eq!(
            keys.open(&me, &"a".repeat(32), &sealed).unwrap_err(),
            RestoreError::Tag,
            "record key is bound"
        );
        let mut v2 = sealed.clone();
        v2[4] = 2;
        assert_eq!(
            keys.open(&me, META_KEY, &v2).unwrap_err(),
            RestoreError::Version
        );
        let huge = vec![0u8; MAX_RECORD_BYTES + 1];
        assert_eq!(
            keys.open(&me, META_KEY, &huge).unwrap_err(),
            RestoreError::TooLarge
        );
    }

    /// SP4: record keys are opaque, derived, distinct and valid.
    #[test]
    fn sp4_record_keys_are_opaque_hmac_names() {
        let k1 = StateKeys::new([1; 32]);
        let (a, b) = ([0xAA; 32], [0xBB; 32]);
        let ka = k1.record_key_for(&a);
        assert_eq!(ka.len(), 32);
        assert!(is_valid_record_key(&ka) && is_valid_record_key(META_KEY));
        assert!(!is_valid_record_key("../x") && !is_valid_record_key(&"A".repeat(32)));
        assert_ne!(ka, k1.record_key_for(&b));
        assert_ne!(ka, StateKeys::new([2; 32]).record_key_for(&a));
        assert!(!hex::encode(a).contains(&ka));
        // A peer record naming `a`: sealed, neither its raw bytes nor its hex appear (F28).
        let rec = PeerRecordV1 {
            peer_ik: a,
            received_ids: vec![[4; 16]],
            ..Default::default()
        };
        let sealed = k1.seal(
            &[3; 32],
            &ka,
            KIND_PEER,
            1,
            &bincode::serialize(&rec).unwrap(),
        );
        assert!(
            !sealed.windows(32).any(|w| w == a),
            "no raw identity in the record"
        );
        assert!(
            !String::from_utf8_lossy(&sealed).contains(&hex::encode(a)),
            "no hex identity"
        );
        let (kind, _, plain) = k1.open(&[3; 32], &ka, &sealed).unwrap();
        assert_eq!(kind, KIND_PEER);
        let back: PeerRecordV1 = bincode::deserialize(&plain).unwrap();
        assert_eq!(
            (back.peer_ik, back.received_ids),
            (a, vec![[4; 16]]),
            "SP3: a peer record round-trips"
        );
    }

    /// Carry-over from the Task 1 review: a body is serialised into a wiped
    /// buffer that never reallocates, and matches plain bincode.
    #[test]
    fn encode_body_fills_an_exactly_sized_wiped_buffer() {
        let rec = PeerRecordV1 {
            peer_ik: [7; 32],
            seen_ids: vec![[5; 16]; 3],
            ..Default::default()
        };
        let buf = encode_body(&rec).unwrap();
        assert_eq!(
            buf.len(),
            buf.capacity(),
            "no reallocation, no spare unwiped copy"
        );
        assert_eq!(buf.as_slice(), bincode::serialize(&rec).unwrap().as_slice());
    }
}
