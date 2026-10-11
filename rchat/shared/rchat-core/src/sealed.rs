//! Sealed relay payload v2 (spec §5.3): the relay sees only the recipient.
//! The sender's identity travels inside the AEAD.

use crate::keyauth::{dh_checked, KeyAuthError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const SEALED_VERSION: u8 = 0x02;
pub const KIND_RATCHET: u8 = 0x01;
pub const KIND_KNOCK: u8 = 0x02;
/// version(1) + message_id(16) + env_eph_pub(32) + env_nonce(24).
pub const SEALED_HEADER_LEN: usize = 73;
/// Header + AEAD tag + sender(32) + kind(1) + ratchet header(40).
pub const MIN_SEALED_LEN: usize = 162;
/// Every knock payload is exactly this long (L3).
pub const KNOCK_PAYLOAD_LEN: usize = 2048;
/// Inner plaintext length of a knock: 2048 - 73 - 16.
pub const KNOCK_INNER_LEN: usize = KNOCK_PAYLOAD_LEN - SEALED_HEADER_LEN - 16;
const SEAL_INFO: &[u8] = b"rchat/seal/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("not a v2 sealed payload")]
    BadFormat,
    #[error("key agreement failed")]
    KeyAgreement(#[from] KeyAuthError),
    #[error("envelope does not open")]
    Aead,
}

/// An opened envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub message_id: [u8; 16],
    pub env_eph_pub: [u8; 32],
    pub sender_identity_key: [u8; 32],
    pub kind: u8,
    pub body: Vec<u8>,
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

fn aad(
    message_id: &[u8; 16],
    env_eph_pub: &[u8; 32],
    recipient_identity_key: &[u8; 32],
) -> [u8; 81] {
    let mut a = [0u8; 81];
    a[0] = SEALED_VERSION;
    a[1..17].copy_from_slice(message_id);
    a[17..49].copy_from_slice(env_eph_pub);
    a[49..81].copy_from_slice(recipient_identity_key);
    a
}

/// Seal with a caller-chosen ephemeral secret and nonce. Knocks need this:
/// their MAC is salted with the envelope's ephemeral public key, so the key
/// must exist before the body is built.
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
                aad: &aad(&message_id, &env_eph_pub, recipient_identity_key),
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

/// The cleartext message id of a v2 payload (what the relay acks).
pub fn peek_message_id(payload: &[u8]) -> Option<[u8; 16]> {
    if payload.len() < MIN_SEALED_LEN || payload[0] != SEALED_VERSION {
        return None;
    }
    payload[1..17].try_into().ok()
}

/// Open an envelope addressed to me.
pub fn open(
    my_identity_key: &[u8; 32],
    my_agreement_secret: &StaticSecret,
    payload: &[u8],
) -> Result<Opened, SealError> {
    if payload.len() < MIN_SEALED_LEN || payload[0] != SEALED_VERSION {
        return Err(SealError::BadFormat);
    }
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
                    aad: &aad(&message_id, &env_eph_pub, my_identity_key),
                },
            )
            .map_err(|_| SealError::Aead)?,
    );
    if inner.len() < 33 {
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
