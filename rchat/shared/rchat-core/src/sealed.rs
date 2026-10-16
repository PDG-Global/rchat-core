//! Sealed relay payload v2 (spec §5.3): the relay sees only the recipient.
//! The sender's identity travels inside the AEAD.
//!
//! Knocks have their own hybrid envelope (knock v3, protocol v3 §A.5,
//! ruling R10): version byte 0x03, `ct_k` (an ML-KEM-768 encapsulation to
//! the recipient's static KEM key) in the clear header, and an envelope key
//! from both the X25519 DH and `ss_k`, so a recording plus a future quantum
//! computer alone can't open one. `seal_knock_with` / `open_knock` handle
//! them; the generic `seal` / `open` refuse knocks.

use crate::kem::{KemKeyPair, KEM_CT_LEN};
use crate::keyauth::{dh_checked, KeyAuthError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Version byte of every sealed envelope except knocks.
pub const SEALED_VERSION: u8 = 0x02;
/// Version byte of a knock v3 envelope (§A.5); only `KIND_KNOCK` travels
/// under it, and it is always exactly `KNOCK_PAYLOAD_LEN` long.
pub const KNOCK_VERSION: u8 = 0x03;
pub const KIND_RATCHET: u8 = 0x01;
pub const KIND_KNOCK: u8 = 0x02;
/// version(1) + message_id(16) + env_eph_pub(32) + env_nonce(24).
pub const SEALED_HEADER_LEN: usize = 73;
/// Header + AEAD tag + sender(32) + kind(1) + ratchet header(40).
pub const MIN_SEALED_LEN: usize = 162;
/// Every knock payload is exactly this long (L3). 5120 since knock v3
/// (§A.5, ruling R5): the knock carries the sender's signed bundle with its
/// 1184-byte ML-KEM key and the 1088-byte `ct_k` to the recipient's static
/// ML-KEM key, beside the 1024-byte intro cap and the rotation tail.
pub const KNOCK_PAYLOAD_LEN: usize = 5120;
/// Knock clear header (R10): version(1) || message_id(16) ||
/// env_eph_pub(32) || ct_k(1088) || env_nonce(24) = 1161, all of it the
/// AEAD's associated data. `ct_k` starts at 49 and the nonce at 1137.
pub const KNOCK_CT_OFFSET: usize = 1 + 16 + 32;
pub const KNOCK_NONCE_OFFSET: usize = KNOCK_CT_OFFSET + KEM_CT_LEN;
pub const KNOCK_HEADER_LEN: usize = KNOCK_NONCE_OFFSET + 24;
/// Inner plaintext length of a knock: 5120 - 1161 - 16 = 3943 (sender 32,
/// kind 1, body 3910).
pub const KNOCK_INNER_LEN: usize = KNOCK_PAYLOAD_LEN - KNOCK_HEADER_LEN - 16;
const KNOCK_ENV_INFO: &[u8] = b"rchat/knock-env/v3";
/// Wire size of a ratchet envelope minus its padded plaintext: the sealed
/// minimum (header, AEAD tag, sender, kind, ratchet header) plus the ratchet
/// AEAD's nonce (24) and tag (16). 202 bytes.
pub const RATCHET_ENVELOPE_OVERHEAD: usize = MIN_SEALED_LEN + 24 + 16;
/// No ratchet envelope in a small padding bucket is knock-sized, so the
/// relay and `dispatch_opened` can tell knocks from messages by length (N-1).
const _: () = {
    let mut i = 0;
    while i < crate::padding::SMALL_BUCKETS.len() {
        assert!(RATCHET_ENVELOPE_OVERHEAD + crate::padding::SMALL_BUCKETS[i] != KNOCK_PAYLOAD_LEN);
        i += 1;
    }
};
const SEAL_INFO: &[u8] = b"rchat/seal/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("not a sealed payload")]
    BadFormat,
    #[error("key agreement failed")]
    KeyAgreement(#[from] KeyAuthError),
    #[error("envelope does not open")]
    Aead,
}

/// An opened envelope (never a knock: see `OpenedKnock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub message_id: [u8; 16],
    pub env_eph_pub: [u8; 32],
    pub sender_identity_key: [u8; 32],
    pub kind: u8,
    pub body: Vec<u8>,
}

/// An opened knock v3 envelope. It carries `ss_k` for the inner knock
/// keys (`knock::parse_knock`, which consumes it), so it is neither `Clone`
/// nor `PartialEq`, its `Debug` never prints the secret, and the secret is
/// wiped when it drops.
pub struct OpenedKnock {
    pub message_id: [u8; 16],
    pub env_eph_pub: [u8; 32],
    pub sender_identity_key: [u8; 32],
    /// The knock body (kind is always `KIND_KNOCK`), `KNOCK_INNER_LEN - 33` bytes.
    pub body: Vec<u8>,
    pub(crate) kem_ss: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for OpenedKnock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedKnock")
            .field("message_id", &hex::encode(self.message_id))
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

fn envelope_key(
    env_eph_pub: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    shared: &[u8; 32],
) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(env_eph_pub);
    salt[32..].copy_from_slice(recipient_agreement_key);
    let mut k = [0u8; 32];
    crate::keyauth::with_hkdf(Some(&salt), shared, |hk| {
        hk.expand(SEAL_INFO, &mut k).expect("32-byte HKDF output")
    });
    k
}

/// Knock envelope key (R10): HKDF-SHA256(salt = env_eph_pub ||
/// recipient_ak, ikm = DH(env_eph, recipient_ak) || ss_k,
/// info = "rchat/knock-env/v3"). The combined input is wiped here.
pub(crate) fn knock_envelope_key(
    env_eph_pub: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    dh: &[u8; 32],
    kem_ss: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(env_eph_pub);
    salt[32..].copy_from_slice(recipient_agreement_key);
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(kem_ss);
    let mut k = Zeroizing::new([0u8; 32]);
    crate::keyauth::with_hkdf(Some(&salt), &ikm[..], |hk| {
        hk.expand(KNOCK_ENV_INFO, &mut k[..])
            .expect("32-byte HKDF output")
    });
    k
}

fn aad(
    version: u8,
    message_id: &[u8; 16],
    env_eph_pub: &[u8; 32],
    recipient_identity_key: &[u8; 32],
) -> [u8; 81] {
    let mut a = [0u8; 81];
    a[0] = version;
    a[1..17].copy_from_slice(message_id);
    a[17..49].copy_from_slice(env_eph_pub);
    a[49..81].copy_from_slice(recipient_identity_key);
    a
}

/// Seal with a caller-chosen ephemeral secret and nonce, under
/// `SEALED_VERSION`. Knocks are refused (`BadFormat`): they have their own
/// hybrid envelope (`seal_knock_with`).
// Documented exception (Global Constraints, X30): validating constructor.
#[allow(clippy::too_many_arguments)]
pub fn seal_with(
    env_eph_secret: &StaticSecret,
    env_nonce: [u8; 24],
    message_id: [u8; 16],
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    sender_identity_key: &[u8; 32],
    kind: u8,
    body: &[u8],
) -> Result<Vec<u8>, SealError> {
    if kind == KIND_KNOCK {
        return Err(SealError::BadFormat);
    }
    seal_unchecked(
        env_eph_secret,
        env_nonce,
        message_id,
        recipient_identity_key,
        recipient_agreement_key,
        sender_identity_key,
        kind,
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_unchecked(
    env_eph_secret: &StaticSecret,
    env_nonce: [u8; 24],
    message_id: [u8; 16],
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    sender_identity_key: &[u8; 32],
    kind: u8,
    body: &[u8],
) -> Result<Vec<u8>, SealError> {
    let env_eph_pub = X25519PublicKey::from(env_eph_secret).to_bytes();
    // DH output, envelope key and inner plaintext are wiped on every return path.
    let shared = dh_checked(env_eph_secret, recipient_agreement_key)?;
    let key = Zeroizing::new(envelope_key(&env_eph_pub, recipient_agreement_key, &shared));
    let mut inner = Zeroizing::new(Vec::with_capacity(33 + body.len()));
    inner.extend_from_slice(sender_identity_key);
    inner.push(kind);
    inner.extend_from_slice(body);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| SealError::Aead)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&env_nonce),
            Payload {
                msg: &inner,
                aad: &aad(
                    SEALED_VERSION,
                    &message_id,
                    &env_eph_pub,
                    recipient_identity_key,
                ),
            },
        )
        .map_err(|_| SealError::Aead)?;
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN + ct.len());
    out.push(SEALED_VERSION);
    out.extend_from_slice(&message_id);
    out.extend_from_slice(&env_eph_pub);
    out.extend_from_slice(&env_nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Seal a knock v3 (R10) with a caller-chosen ephemeral secret, nonce and
/// ML-KEM encapsulation (`kem_ct`, `kem_ss`) to the recipient's static KEM
/// key. `body` must be exactly `KNOCK_INNER_LEN - 33` bytes, so the result
/// is always `KNOCK_PAYLOAD_LEN`. The AAD is the whole clear header.
// Documented exception (Global Constraints, X30): validating constructor.
#[allow(clippy::too_many_arguments)]
pub fn seal_knock_with(
    env_eph_secret: &StaticSecret,
    env_nonce: [u8; 24],
    message_id: [u8; 16],
    recipient_agreement_key: &[u8; 32],
    kem_ct: &[u8; KEM_CT_LEN],
    kem_ss: &[u8; 32],
    sender_identity_key: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, SealError> {
    if body.len() != KNOCK_INNER_LEN - 33 {
        return Err(SealError::BadFormat);
    }
    let env_eph_pub = X25519PublicKey::from(env_eph_secret).to_bytes();
    let dh = dh_checked(env_eph_secret, recipient_agreement_key)?;
    let key = knock_envelope_key(&env_eph_pub, recipient_agreement_key, &dh, kem_ss);
    let mut out = Vec::with_capacity(KNOCK_PAYLOAD_LEN);
    out.push(KNOCK_VERSION);
    out.extend_from_slice(&message_id);
    out.extend_from_slice(&env_eph_pub);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(&env_nonce);
    let mut inner = Zeroizing::new(Vec::with_capacity(KNOCK_INNER_LEN));
    inner.extend_from_slice(sender_identity_key);
    inner.push(KIND_KNOCK);
    inner.extend_from_slice(body);
    let ct = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| SealError::Aead)?
        .encrypt(
            XNonce::from_slice(&env_nonce),
            Payload {
                msg: &inner,
                aad: &out,
            },
        )
        .map_err(|_| SealError::Aead)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a knock v3 addressed to me (R10): exactly `KNOCK_PAYLOAD_LEN`
/// bytes under `KNOCK_VERSION`. `ct_k` is decapsulated with my static KEM
/// key before the AEAD, so a tampered `ct_k` (another `ss_k`, by implicit
/// rejection) fails the AEAD like any other forged knock.
pub fn open_knock(
    my_agreement_secret: &StaticSecret,
    my_kem: &KemKeyPair,
    payload: &[u8],
) -> Result<OpenedKnock, SealError> {
    if payload.len() != KNOCK_PAYLOAD_LEN || payload[0] != KNOCK_VERSION {
        return Err(SealError::BadFormat);
    }
    let kem_ss = my_kem
        .decapsulate(&payload[KNOCK_CT_OFFSET..KNOCK_NONCE_OFFSET])
        .map_err(|_| SealError::BadFormat)?;
    open_knock_with_ss(my_agreement_secret, &kem_ss, payload)
}

/// `open_knock` after the decapsulation (tests use it to try wrong `ss_k`).
pub(crate) fn open_knock_with_ss(
    my_agreement_secret: &StaticSecret,
    kem_ss: &[u8; 32],
    payload: &[u8],
) -> Result<OpenedKnock, SealError> {
    if payload.len() != KNOCK_PAYLOAD_LEN || payload[0] != KNOCK_VERSION {
        return Err(SealError::BadFormat);
    }
    let message_id: [u8; 16] = payload[1..17]
        .try_into()
        .map_err(|_| SealError::BadFormat)?;
    let env_eph_pub: [u8; 32] = payload[17..KNOCK_CT_OFFSET]
        .try_into()
        .map_err(|_| SealError::BadFormat)?;
    let my_agreement_key = X25519PublicKey::from(my_agreement_secret).to_bytes();
    let dh = dh_checked(my_agreement_secret, &env_eph_pub)?;
    let key = knock_envelope_key(&env_eph_pub, &my_agreement_key, &dh, kem_ss);
    let inner = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| SealError::Aead)?
            .decrypt(
                XNonce::from_slice(&payload[KNOCK_NONCE_OFFSET..KNOCK_HEADER_LEN]),
                Payload {
                    msg: &payload[KNOCK_HEADER_LEN..],
                    aad: &payload[..KNOCK_HEADER_LEN],
                },
            )
            .map_err(|_| SealError::Aead)?,
    );
    if inner.len() != KNOCK_INNER_LEN || inner[32] != KIND_KNOCK {
        return Err(SealError::BadFormat);
    }
    Ok(OpenedKnock {
        message_id,
        env_eph_pub,
        sender_identity_key: inner[..32].try_into().map_err(|_| SealError::BadFormat)?,
        body: inner[33..].to_vec(),
        kem_ss: Zeroizing::new(*kem_ss),
    })
}

/// Seal with a fresh ephemeral key and nonce.
pub fn seal(
    message_id: [u8; 16],
    recipient_identity_key: &[u8; 32],
    recipient_agreement_key: &[u8; 32],
    sender_identity_key: &[u8; 32],
    kind: u8,
    body: &[u8],
) -> Result<Vec<u8>, SealError> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    seal_with(
        &eph,
        nonce,
        message_id,
        recipient_identity_key,
        recipient_agreement_key,
        sender_identity_key,
        kind,
        body,
    )
}

/// Does `payload` have a known version byte and a length that version
/// allows (a knock v3 envelope is exactly `KNOCK_PAYLOAD_LEN`)? Both carry
/// the message id at bytes 1..17.
fn well_framed(payload: &[u8]) -> bool {
    match payload.first() {
        Some(&SEALED_VERSION) => payload.len() >= MIN_SEALED_LEN,
        Some(&KNOCK_VERSION) => payload.len() == KNOCK_PAYLOAD_LEN,
        _ => false,
    }
}

/// The cleartext message id of a sealed payload (what the relay acks).
pub fn peek_message_id(payload: &[u8]) -> Option<[u8; 16]> {
    if !well_framed(payload) {
        return None;
    }
    payload[1..17].try_into().ok()
}

/// Open an envelope addressed to me. Only `SEALED_VERSION`: a knock (0x03)
/// is refused here (`open_knock` opens it), and a 0x02 envelope claiming
/// the knock kind is refused after the AEAD (§A.5, R10).
pub fn open(
    my_identity_key: &[u8; 32],
    my_agreement_secret: &StaticSecret,
    payload: &[u8],
) -> Result<Opened, SealError> {
    if payload.first() != Some(&SEALED_VERSION) || payload.len() < MIN_SEALED_LEN {
        return Err(SealError::BadFormat);
    }
    let version = SEALED_VERSION;
    let message_id: [u8; 16] = payload[1..17]
        .try_into()
        .map_err(|_| SealError::BadFormat)?;
    let env_eph_pub: [u8; 32] = payload[17..49]
        .try_into()
        .map_err(|_| SealError::BadFormat)?;
    let nonce = &payload[49..73];
    let my_agreement_key = X25519PublicKey::from(my_agreement_secret).to_bytes();
    let shared = dh_checked(my_agreement_secret, &env_eph_pub)?;
    let key = Zeroizing::new(envelope_key(&env_eph_pub, &my_agreement_key, &shared));
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| SealError::Aead)?;
    let inner = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &payload[SEALED_HEADER_LEN..],
                    aad: &aad(version, &message_id, &env_eph_pub, my_identity_key),
                },
            )
            .map_err(|_| SealError::Aead)?,
    );
    if inner.len() < 33 || inner[32] == KIND_KNOCK {
        return Err(SealError::BadFormat);
    }
    Ok(Opened {
        message_id,
        env_eph_pub,
        sender_identity_key: inner[..32].try_into().map_err(|_| SealError::BadFormat)?,
        kind: inner[32],
        body: inner[33..].to_vec(),
    })
}

#[cfg(test)]
mod tests;
