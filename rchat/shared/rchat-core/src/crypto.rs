//! Cryptographic operations for RChat
//!
//! This module provides:
//! - X25519 key exchange
//! - Ed25519 signatures
//! - AES-GCM encryption (for iOS/macOS compatibility)
//! - XChaCha20-Poly1305 encryption (for server compatibility)
//! - Double Ratchet algorithm
//! - X3DH key agreement

use crate::kem::{KemKeyPair, KEM_PK_LEN, KEM_SEED_LEN};
use crate::RChatError;
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use log;
// Re-export X25519 types for use in other modules
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
pub use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::{Zeroize, Zeroizing};

/// Identity key pair: Ed25519 for signatures, X25519 for key agreement and
/// ML-KEM-768 (protocol v3 §A.1). The KEM key is derived from the 64-byte
/// identity seed and never stored on its own.
#[derive(Clone)]
pub struct IdentityKeyPair {
    signing_key: SigningKey,
    agreement_key: X25519SecretKey,
    /// Shared on clone; the secret is wiped when the last holder drops it.
    kem: std::sync::Arc<KemKeyPair>,
}

/// HKDF info for the identity KEM seed (protocol v3 §A.1).
pub const KEM_SEED_INFO: &[u8] = b"rchat/kem-seed/v3";

/// `HKDF-SHA256(salt = None, ikm = identity_seed, info = "rchat/kem-seed/v3")`,
/// 64 bytes: the identity's ML-KEM-768 seed (`d || z`).
pub fn identity_kem_seed(identity_seed: &[u8; 64]) -> Zeroizing<[u8; KEM_SEED_LEN]> {
    let mut out = Zeroizing::new([0u8; KEM_SEED_LEN]);
    hkdf::Hkdf::<Sha256>::new(None, identity_seed)
        .expand(KEM_SEED_INFO, &mut out[..])
        .expect("64-byte HKDF output");
    out
}

impl IdentityKeyPair {
    /// Generate a new random identity. It goes through a random 64-byte seed,
    /// so the KEM key is derived exactly as on a reload (§A.1).
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(&mut seed[..]);
        Self::from_canonical_seed(&seed)
    }

    /// Derive identity from a seed (the first 64 bytes are used).
    pub fn from_seed(seed: &[u8]) -> Result<Self, RChatError> {
        let canonical: &[u8; 64] =
            seed.get(..64)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| RChatError::EncryptionFailed {
                    message: "Seed must be at least 64 bytes".to_string(),
                })?;
        Ok(Self::from_canonical_seed(canonical))
    }

    /// `seed = signing_secret(32) || agreement_secret(32)`; the KEM key comes
    /// from `identity_kem_seed(seed)`. The buffers this function owns are
    /// wiped (`Zeroizing`). Known limits of that wipe:
    /// - `X25519SecretKey::from([u8; 32])` takes its array by value, so the
    ///   argument copy made for that call (a stack temporary) is not wiped by
    ///   us. The resulting `StaticSecret` zeroizes itself on drop.
    /// - `identity_kem_seed`'s HKDF keeps the PRK inside `hkdf`'s HMAC state,
    ///   which the `hkdf` crate does not zeroize; it is dropped (not wiped)
    ///   when the function returns. The 64-byte KEM seed output is wiped.
    fn from_canonical_seed(seed: &[u8; 64]) -> Self {
        let mut signing_bytes = Zeroizing::new([0u8; 32]);
        signing_bytes.copy_from_slice(&seed[0..32]);
        let signing_key = SigningKey::from_bytes(&signing_bytes);

        // Use raw agreement key bytes directly (must match seed_bytes() output)
        let mut agreement_bytes = Zeroizing::new([0u8; 32]);
        agreement_bytes.copy_from_slice(&seed[32..64]);
        let agreement_key = X25519SecretKey::from(*agreement_bytes);

        let kem_seed = identity_kem_seed(seed);
        let kem = std::sync::Arc::new(KemKeyPair::from_seed(&kem_seed));

        Self {
            signing_key,
            agreement_key,
            kem,
        }
    }

    /// The identity's ML-KEM-768 public key (signed in the v3 bundle).
    pub fn kem_public(&self) -> &[u8; KEM_PK_LEN] {
        self.kem.public()
    }

    /// The identity's static ML-KEM-768 key pair: knocks are encapsulated
    /// to it (§A.5), and only knock parsing decapsulates with it.
    pub(crate) fn kem(&self) -> &KemKeyPair {
        &self.kem
    }

    /// Get the public signing key (identity)
    pub fn public_signing_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public agreement key
    pub fn public_agreement_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.agreement_key)
    }

    /// Get identity as hex string (Ed25519 public key)
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_signing_key().to_bytes())
    }

    /// Get agreement key as hex string (X25519 public key)
    pub fn agreement_key_hex(&self) -> String {
        hex::encode(self.public_agreement_key().as_bytes())
    }

    /// Write the 64-byte seed (same layout as `seed_bytes`) straight into
    /// `out`, without returning a copy by value (round-2 L4).
    pub(crate) fn write_seed(&self, out: &mut [u8; 64]) {
        out[0..32].copy_from_slice(self.signing_key.as_bytes());
        out[32..64].copy_from_slice(self.agreement_key.as_bytes());
    }

    /// Get the 64-byte seed for identity reconstruction
    /// Format: [signing_secret_key: 32 bytes][agreement_secret_key: 32 bytes]
    pub fn seed_bytes(&self) -> [u8; 64] {
        let mut full = [0u8; 64];
        full[0..32].copy_from_slice(&self.signing_key.to_bytes());
        full[32..64].copy_from_slice(&self.agreement_key.to_bytes());
        full
    }

    /// Sign a message. Crate-private (F21): only `keyauth::sign_bundle`,
    /// `keyauth::sign_conn`, `keyauth::sign_device_key` (D43) and
    /// `rotation::sign_link` (round-2 L6) call it,
    /// always over a domain-separated transcript.
    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// X25519 key agreement with our identity agreement key. A
    /// non-contributory (low-order) peer key is refused (L1); the output is
    /// wiped when dropped.
    pub fn agree(
        &self,
        other_public: &X25519PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, crate::keyauth::KeyAuthError> {
        crate::keyauth::dh_checked(&self.agreement_key, other_public.as_bytes())
    }

    /// Get the agreement secret key (for X3DH)
    pub fn agreement_secret(&self) -> &X25519SecretKey {
        &self.agreement_key
    }
}

/// Ephemeral key pair for X3DH
#[derive(Clone)]
pub struct EphemeralKeyPair {
    secret_key: X25519SecretKey,
    public_key: X25519PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let secret_key = X25519SecretKey::random_from_rng(&mut csprng);
        let public_key = X25519PublicKey::from(&secret_key);

        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &X25519SecretKey {
        &self.secret_key
    }
}

/// HKDF info prefix of X3DH v3 (protocol v3 §A.3).
pub const X3DH_V3_INFO: &[u8] = b"rchat/x3dh/v3";

/// X3DH v3 (protocol v3 §A.3), initiator side (role 0): v2's four DHs,
/// unchanged, plus the ML-KEM-768 shared secret.
///
/// v2 had no separate signed pre-key (it always equalled the identity
/// agreement key `ak`), so with `ak_r = ik_r_agree`:
/// DH1 = IK_i × ak_r, DH2 = EK_i × ak_r, DH3 = EK_i × ak_r (computed
/// twice, as v2 did, to keep the KDF input layout), DH4 = EK_i × EK_r.
/// Every DH must be contributory (L1). `kem_ss` is the secret the
/// initiator encapsulated to the responder's ask KEM key `kem_ek_pub_r`,
/// and `ct` the ciphertext sent in session-init (§A.4).
// Documented exception (Global Constraints, X30): the brief's signature.
#[allow(clippy::too_many_arguments)]
pub fn x3dh_v3_initiator(
    ik_i_agree: &X25519SecretKey,
    ek_i: &X25519SecretKey,
    ik_r_agree: &[u8; 32],
    ek_r: &[u8; 32],
    kem_ss: &[u8; 32],
    kem_ek_pub_r: &[u8; KEM_PK_LEN],
    ct: &[u8; crate::kem::KEM_CT_LEN],
    ik_initiator: &[u8; 32],
    ik_responder: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, crate::keyauth::KeyAuthError> {
    use crate::keyauth::dh_checked;
    // Each DH output is wiped on every return path, including an early `?`.
    let dh1 = dh_checked(ik_i_agree, ik_r_agree)?;
    let dh2 = dh_checked(ek_i, ik_r_agree)?;
    let dh3 = dh_checked(ek_i, ik_r_agree)?;
    let dh4 = dh_checked(ek_i, ek_r)?;
    Ok(x3dh_v3_kdf(
        [&dh1, &dh2, &dh3, &dh4],
        kem_ss,
        kem_ek_pub_r,
        ct,
        ik_initiator,
        ik_responder,
    ))
}

/// X3DH v3 (protocol v3 §A.3), responder side (role 1): the mirror of
/// [`x3dh_v3_initiator`]. `ik_r_agree` is our identity agreement secret
/// (v2's SPK too), `ek_r` our ask's X25519 ephemeral; `kem_ss` comes from
/// decapsulating `ct` with our ask's KEM ephemeral, whose public key is
/// `kem_ek_pub_r`.
// Documented exception (Global Constraints, X30): the brief's signature.
#[allow(clippy::too_many_arguments)]
pub fn x3dh_v3_responder(
    ik_r_agree: &X25519SecretKey,
    ek_r: &X25519SecretKey,
    ik_i_agree: &[u8; 32],
    ek_i: &[u8; 32],
    kem_ss: &[u8; 32],
    kem_ek_pub_r: &[u8; KEM_PK_LEN],
    ct: &[u8; crate::kem::KEM_CT_LEN],
    ik_initiator: &[u8; 32],
    ik_responder: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, crate::keyauth::KeyAuthError> {
    use crate::keyauth::dh_checked;
    let dh1 = dh_checked(ik_r_agree, ik_i_agree)?;
    let dh2 = dh_checked(ik_r_agree, ek_i)?;
    let dh3 = dh_checked(ik_r_agree, ek_i)?;
    let dh4 = dh_checked(ek_r, ek_i)?;
    Ok(x3dh_v3_kdf(
        [&dh1, &dh2, &dh3, &dh4],
        kem_ss,
        kem_ek_pub_r,
        ct,
        ik_initiator,
        ik_responder,
    ))
}

/// SK = HKDF-SHA256(salt = 0^32, ikm = DH1||DH2||DH3||DH4||kem_ss,
///                  info = "rchat/x3dh/v3" || IK_i || IK_r || SHA-256(kem_ek_pub_r || ct)).
fn x3dh_v3_kdf(
    dhs: [&[u8; 32]; 4],
    kem_ss: &[u8; 32],
    kem_ek_pub_r: &[u8; KEM_PK_LEN],
    ct: &[u8; crate::kem::KEM_CT_LEN],
    ik_initiator: &[u8; 32],
    ik_responder: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    use sha2::Digest;
    let mut ikm = Zeroizing::new([0u8; 160]);
    for (i, dh) in dhs.iter().enumerate() {
        ikm[32 * i..32 * (i + 1)].copy_from_slice(&dh[..]);
    }
    ikm[128..].copy_from_slice(kem_ss);
    let mut transcript = Sha256::new();
    transcript.update(kem_ek_pub_r);
    transcript.update(ct);
    let mut info = Vec::with_capacity(X3DH_V3_INFO.len() + 96);
    info.extend_from_slice(X3DH_V3_INFO);
    info.extend_from_slice(ik_initiator);
    info.extend_from_slice(ik_responder);
    info.extend_from_slice(&transcript.finalize());
    let mut out = Zeroizing::new([0u8; 32]);
    crate::keyauth::with_hkdf(Some(&[0u8; 32]), &ikm[..], |hk| {
        hk.expand(&info, &mut out[..]).expect("32-byte HKDF output")
    });
    out
}

/// Ratchet header for Double Ratchet messages
///
/// Wire format (40 bytes): `[DH Public Key: 32][Message Number: 4 BE][Previous Chain Length: 4 BE]`
/// Message numbers are `u32` per the Double Ratchet spec (ported from rVPN).
#[derive(Debug, Clone)]
pub struct RatchetHeader {
    pub message_number: u32,
    pub previous_chain_length: u32,
    pub dh_public_key: [u8; 32],
}

impl RatchetHeader {
    /// Size of an encoded ratchet header in bytes.
    pub const LEN: usize = 40;

    /// Encode header to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(Self::LEN);
        result.extend_from_slice(&self.dh_public_key);
        result.extend_from_slice(&self.message_number.to_be_bytes());
        result.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        result
    }

    /// Decode header from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::LEN {
            return None;
        }

        let mut dh_public_key = [0u8; 32];
        dh_public_key.copy_from_slice(&data[0..32]);

        let message_number = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let previous_chain_length = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);

        Some(Self {
            message_number,
            previous_chain_length,
            dh_public_key,
        })
    }
}

pub fn ratchet_aad(header: &RatchetHeader, ad: &[u8; 64]) -> [u8; 104] {
    let mut aad = [0u8; 104];
    aad[..40].copy_from_slice(&header.encode());
    aad[40..].copy_from_slice(ad);
    aad
}

/// A skipped message key in a ratchet snapshot. Wiped on drop.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SkippedKeyV1 {
    pub n: u32,
    pub key: [u8; 32],
    pub inserted_at_unix: u64,
}

/// A stashed receiving chain in a ratchet snapshot. Wiped on drop.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OldChainV1 {
    pub remote_dh: [u8; 32],
    pub chain_key: [u8; 32],
    pub next_n: u32,
    pub skipped: Vec<SkippedKeyV1>,
    pub seq: u64,
}

/// The complete, serialisable state of a `DoubleRatchet` (spec §18.2.1).
/// Secrets are wiped on drop; `Debug` prints no secret.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetSnapshotV1 {
    pub root_key: [u8; 32],
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub dh_secret: Option<[u8; 32]>,
    pub remote_dh: Option<[u8; 32]>,
    pub needs_identity_ratchet: bool,
    pub is_responder: bool,
    pub max_skip: u32,
    pub skipped: Vec<SkippedKeyV1>,
    pub old_chains: Vec<OldChainV1>,
    pub next_old_chain_seq: u64,
}

impl Drop for SkippedKeyV1 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl Drop for OldChainV1 {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}
impl Drop for RatchetSnapshotV1 {
    fn drop(&mut self) {
        self.root_key.zeroize();
        for k in [
            &mut self.sending_chain_key,
            &mut self.receiving_chain_key,
            &mut self.dh_secret,
        ]
        .into_iter()
        .flatten()
        {
            k.zeroize();
        }
    }
}
impl std::fmt::Debug for RatchetSnapshotV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSnapshotV1")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("secrets", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn skipped_v1(map: &BTreeMap<u32, SkippedKey>) -> Vec<SkippedKeyV1> {
    map.iter()
        .map(|(n, k)| SkippedKeyV1 {
            n: *n,
            key: k.key,
            inserted_at_unix: k.inserted_at_unix,
        })
        .collect()
}

fn skipped_from_v1(v: &[SkippedKeyV1], now: u64) -> BTreeMap<u32, SkippedKey> {
    // A stamp in the future (the clock stepped back) is re-stamped to `now`,
    // so a key cannot outlive the limit by a clock change.
    v.iter()
        .filter(|k| now.saturating_sub(k.inserted_at_unix) <= SKIPPED_KEY_MAX_AGE_SECS)
        .map(|k| {
            (
                k.n,
                SkippedKey {
                    key: k.key,
                    inserted_at_unix: k.inserted_at_unix.min(now),
                },
            )
        })
        .collect()
}

/// Most receiving chains kept for remote DH keys we have already left
/// (oldest dropped first). Late messages on an older chain no longer decrypt.
pub const MAX_OLD_RECEIVING_CHAINS: usize = 5;

/// Most skipped message keys kept across all receiving chains (C-2). When a
/// decrypt would exceed it, the oldest keys go first: the oldest stashed
/// chain's lowest message numbers, the current chain's last.
pub const MAX_SKIPPED_KEYS: usize = 1000;

/// Most message keys one receiving chain may skip in a single decrypt: a
/// message more than this far ahead of the last one received fails.
pub const MAX_SKIP: u32 = 100;

/// Skipped message keys expire after this (spec §18.2.1, D31): the relay's
/// default retention; a later message on that key cannot arrive.
pub const SKIPPED_KEY_MAX_AGE_SECS: u64 = 72 * 3600;

/// A skipped message key and when it was stored. Wiped on drop.
#[derive(Clone)]
struct SkippedKey {
    key: [u8; 32],
    inserted_at_unix: u64,
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Double Ratchet state for a session. Every secret is wiped on drop, so the
/// trial copy a failed decrypt discards leaves nothing behind.
#[derive(Clone)]
pub struct DoubleRatchet {
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_sending_chain_length: u32,

    // DH ratchet state
    dh_key_pair: Option<X25519SecretKey>,
    remote_dh_key: Option<X25519PublicKey>,

    // For responder: store the identity key to use for first ratchet
    identity_key_pair: Option<X25519SecretKey>,
    is_responder: bool,

    // Skipped message keys of the current receiving chain, by message number.
    skipped_message_keys: BTreeMap<u32, SkippedKey>,
    max_skip: u32,

    /// Receiving state for previous remote DH keys. Concurrent sends make both
    /// peers ratchet; late messages still arrive on the old chain and must
    /// remain decryptable. At most `MAX_OLD_RECEIVING_CHAINS`.
    old_receiving_chains: HashMap<[u8; 32], OldReceivingChain>,
    /// Stash order for `old_receiving_chains` (oldest = smallest).
    next_old_chain_seq: u64,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(k) = self.sending_chain_key.as_mut() {
            k.zeroize();
        }
        if let Some(k) = self.receiving_chain_key.as_mut() {
            k.zeroize();
        }
        wipe_keys(&mut self.skipped_message_keys);
        // Stashed chains wipe themselves; X25519 secrets are ZeroizeOnDrop.
    }
}

/// Zeroize and drop every key in a skipped-key map.
fn wipe_keys(keys: &mut BTreeMap<u32, SkippedKey>) {
    keys.clear(); // each SkippedKey zeroizes itself on drop
}

/// Stashed receiving state for a remote DH key we have already left.
#[derive(Clone)]
struct OldReceivingChain {
    chain_key: [u8; 32],
    next_message_number: u32,
    skipped: BTreeMap<u32, SkippedKey>,
    /// When it was stashed (from `next_old_chain_seq`).
    seq: u64,
}

impl Drop for OldReceivingChain {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        wipe_keys(&mut self.skipped);
    }
}

impl DoubleRatchet {
    /// X25519 that refuses a non-contributory result (L1); the output is
    /// wiped when dropped.
    fn checked_dh(
        secret: &X25519SecretKey,
        public: &X25519PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, RChatError> {
        crate::keyauth::dh_checked(secret, public.as_bytes()).map_err(|_| {
            RChatError::DecryptionFailed {
                message: "Ratchet key agreement refused (non-contributory key)".to_string(),
            }
        })
    }

    /// Debug: check if sending chain is initialized
    pub fn has_sending_chain(&self) -> bool {
        self.sending_chain_key.is_some()
    }

    /// Create a new Double Ratchet with the shared secret from X3DH
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            root_key: shared_secret,
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_sending_chain_length: 0,
            dh_key_pair: None,
            remote_dh_key: None,
            identity_key_pair: None,
            is_responder: false,
            skipped_message_keys: BTreeMap::new(),
            max_skip: MAX_SKIP,
            old_receiving_chains: HashMap::new(),
            next_old_chain_seq: 0,
        }
    }

    /// Initialize as initiator (Alice)
    /// Whitepaper: generate a NEW DH keypair for the Double Ratchet,
    /// do DH with remote_dh_public_key, derive root_key and sending_chain_key.
    pub fn initialize_alice(
        &mut self,
        _our_ephemeral_key: &X25519SecretKey, // X3DH ephemeral; kept for API compat but NOT reused
        remote_dh_public_key: &X25519PublicKey,
    ) -> Result<(), RChatError> {
        log::trace!("[DR] initialize_alice called");

        // Generate a NEW DH keypair for the Double Ratchet (whitepaper compliant)
        let mut csprng = OsRng;
        let dh_key_pair = X25519SecretKey::random_from_rng(&mut csprng);

        self.dh_key_pair = Some(dh_key_pair.clone());
        self.remote_dh_key = Some(*remote_dh_public_key);
        self.is_responder = false;

        // Perform DH and KDF to get initial sending chain key
        let dh_output = Self::checked_dh(&dh_key_pair, remote_dh_public_key)?;

        let (new_root_key, chain_key) = Self::kdf_root_key(&self.root_key, &dh_output);

        self.root_key = new_root_key;
        self.sending_chain_key = Some(chain_key);
        // receiving_chain_key remains None - will be set when we receive first message

        Ok(())
    }

    /// Initialize as responder (Bob)
    /// Whitepaper: store root_key = shared_secret, store dh_keypair,
    /// do NOT derive any chains yet. Chains are derived on first encrypt/decrypt.
    ///
    /// In our protocol the identity key serves as the signed pre-key, so Bob's
    /// initial dh_keypair IS his identity keypair.
    pub fn initialize_bob(
        &mut self,
        identity_key: &X25519SecretKey, // Bob's identity key = initial DH keypair
        _alice_ephemeral_key: &X25519PublicKey, // Kept for API compat
    ) -> Result<(), RChatError> {
        log::trace!("[DR] initialize_bob called");

        // Store identity key as the initial DH keypair AND as identity_key_pair
        // so dh_ratchet can use it for the first receiving chain (Alice derived
        // her sending chain from our identity/agreement key).
        self.dh_key_pair = Some(identity_key.clone());
        self.identity_key_pair = Some(identity_key.clone());
        self.is_responder = true;

        // Don't derive any chains yet — receiving chain is derived when first
        // message arrives (dh_ratchet with Alice's new DH key), and sending
        // chain is derived when Bob first sends (encrypt path).
        // This matches the whitepaper: initialize_bob stores root_key unchanged.

        Ok(())
    }

    /// Perform a DH ratchet step
    /// - For first message (responder): uses identity key to derive receiving chain
    /// - Generates new DH key pair
    /// - Derives new root key and receiving chain key
    /// - Derives new sending chain key
    fn dh_ratchet(&mut self, remote_dh_public_key: &X25519PublicKey) -> Result<(), RChatError> {
        log::trace!("[DR] dh_ratchet called, is_responder={}", self.is_responder);

        // Capture whether this is the responder's first incoming message
        // BEFORE resetting counters.
        let is_first_message = self.receiving_chain_key.is_none() && self.is_responder;

        // Store previous chain length for headers
        self.previous_sending_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
        self.receiving_message_number = 0;

        // Derive receiving chain key first
        // For responder's first message: use identity key (Alice used our identity key)
        // For subsequent messages: use existing DH key pair
        let dh_output = if is_first_message && self.identity_key_pair.is_some() {
            // First message as responder: use identity key
            // Alice did: her_ratchet_dh * our_identity
            // We do: our_identity * her_ratchet_dh (same DH output!)
            let identity_key = self.identity_key_pair.as_ref().unwrap();
            log::trace!("[DR] Using identity key for first ratchet");
            Self::checked_dh(identity_key, remote_dh_public_key)?
        } else if let Some(existing_key_pair) = &self.dh_key_pair {
            // Subsequent message: use existing DH key pair
            log::trace!("[DR] Using existing DH key pair for ratchet");
            Self::checked_dh(existing_key_pair, remote_dh_public_key)?
        } else {
            log::warn!("[DR] No key available for receiving chain derivation");
            return Err(RChatError::EncryptionFailed {
                message: "No key available for receiving chain derivation".to_string(),
            });
        };

        log::trace!("[DR] Deriving receiving chain");

        let (new_root_key, recv_chain_key) = Self::kdf_root_key(&self.root_key, &dh_output);

        self.root_key = new_root_key;
        self.receiving_chain_key = Some(recv_chain_key);

        // Generate new DH key pair for future sending
        let mut csprng = OsRng;
        let new_key_pair = X25519SecretKey::random_from_rng(&mut csprng);
        self.dh_key_pair = Some(new_key_pair.clone());
        self.remote_dh_key = Some(*remote_dh_public_key);

        // Derive new sending chain key
        let dh_output = Self::checked_dh(&new_key_pair, remote_dh_public_key)?;
        let (new_root_key, send_chain_key) = Self::kdf_root_key(&self.root_key, &dh_output);
        self.root_key = new_root_key;
        self.sending_chain_key = Some(send_chain_key);

        // Clear identity key after first use (we've now generated a proper DH key pair)
        if self.is_responder && self.identity_key_pair.is_some() {
            self.identity_key_pair = None;
            self.is_responder = false; // After first ratchet, we behave like normal
        }

        Ok(())
    }

    /// Encrypt with XChaCha20-Poly1305. `ad` = IK_sender || IK_recipient.
    /// The header is built first so the AEAD can authenticate it.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad: &[u8; 64],
    ) -> Result<(Vec<u8>, RatchetHeader), RChatError> {
        // Responder's first send: derive the sending chain via DH ratchet.
        if self.sending_chain_key.is_none() {
            if let Some(ref dh_key_pair) = self.dh_key_pair {
                if let Some(remote_dh) = self.remote_dh_key {
                    let dh_output = Self::checked_dh(dh_key_pair, &remote_dh).map_err(|_| {
                        RChatError::EncryptionFailed {
                            message: "Ratchet key agreement refused (non-contributory key)"
                                .to_string(),
                        }
                    })?;
                    let (new_root_key, send_chain_key) =
                        Self::kdf_root_key(&self.root_key, &dh_output);
                    self.root_key = new_root_key;
                    self.sending_chain_key = Some(send_chain_key);
                }
            }
        }
        let chain_key = self
            .sending_chain_key
            .ok_or_else(|| RChatError::EncryptionFailed {
                message: "Sending chain not initialized - cannot encrypt".to_string(),
            })?;
        let dh_public_key = self
            .dh_key_pair
            .as_ref()
            .map(|k| X25519PublicKey::from(k).to_bytes())
            .ok_or_else(|| RChatError::EncryptionFailed {
                message: "DH key pair not initialized - cannot encrypt".to_string(),
            })?;
        let (message_key, new_chain_key) = Self::kdf_message_key(&chain_key);
        let message_key = Zeroizing::new(message_key);
        let next_number = self.sending_message_number.checked_add(1).ok_or_else(|| {
            RChatError::EncryptionFailed {
                message: "Sending chain exhausted".to_string(),
            }
        })?;
        let header = RatchetHeader {
            message_number: self.sending_message_number,
            previous_chain_length: self.previous_sending_chain_length,
            dh_public_key,
        };
        let aad = ratchet_aad(&header, ad);
        let cipher = XChaCha20Poly1305::new_from_slice(&message_key[..]).map_err(|e| {
            RChatError::EncryptionFailed {
                message: format!("Failed to create cipher: {}", e),
            }
        })?;
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| RChatError::EncryptionFailed {
                message: format!("Encryption failed: {}", e),
            })?;
        self.sending_chain_key = Some(new_chain_key);
        self.sending_message_number = next_number;
        let mut full_ciphertext = Vec::with_capacity(24 + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce_bytes);
        full_ciphertext.extend_from_slice(&ciphertext);
        Ok((full_ciphertext, header))
    }

    /// Decrypt. `ad` = IK_sender || IK_recipient. Transactional: on any
    /// failure the ratchet is left exactly as it was, so a forged or
    /// replayed message cannot half-apply a DH step. Work per forged
    /// message is bounded (Task 12 minor): at most `max_skip` key
    /// derivations and one DH step before the AEAD check fails, and the
    /// inbound frame caps bound how many arrive.
    pub fn decrypt(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: &RatchetHeader,
        ad: &[u8; 64],
    ) -> Result<Vec<u8>, RChatError> {
        // The trial copy is bounded (caps below) and wiped when dropped, on
        // failure here or (as the replaced state) on success.
        let mut trial = self.clone();
        let plaintext = trial.decrypt_in_place(ciphertext_with_nonce, header, ad)?;
        trial.enforce_bounds();
        *self = trial;
        Ok(plaintext)
    }

    /// Skipped keys held across the current and stashed chains.
    fn skipped_total(&self) -> usize {
        self.skipped_message_keys.len()
            + self
                .old_receiving_chains
                .values()
                .map(|c| c.skipped.len())
                .sum::<usize>()
    }

    /// Apply `MAX_OLD_RECEIVING_CHAINS` and `MAX_SKIPPED_KEYS`, oldest first.
    fn enforce_bounds(&mut self) {
        while self.old_receiving_chains.len() > MAX_OLD_RECEIVING_CHAINS {
            let oldest = self
                .old_receiving_chains
                .iter()
                .min_by_key(|(_, c)| c.seq)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.old_receiving_chains.remove(&k);
                }
                None => break,
            }
        }
        let mut total = self.skipped_total();
        while total > MAX_SKIPPED_KEYS {
            let oldest_chain = self
                .old_receiving_chains
                .values_mut()
                .filter(|c| !c.skipped.is_empty())
                .min_by_key(|c| c.seq);
            let evicted = match oldest_chain {
                Some(chain) => chain.skipped.pop_first(),
                None => self.skipped_message_keys.pop_first(),
            };
            match evicted {
                Some((_, key)) => {
                    drop(key); // SkippedKey wipes itself on drop
                    total -= 1;
                }
                None => break,
            }
        }
    }

    fn decrypt_in_place(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: &RatchetHeader,
        ad: &[u8; 64],
    ) -> Result<Vec<u8>, RChatError> {
        let aad = ratchet_aad(header, ad);
        let header_dh = header.dh_public_key;
        let is_current = self
            .remote_dh_key
            .map(|k| k.as_bytes() == &header_dh)
            .unwrap_or(false);

        if !is_current {
            // Message on a remote DH key we already left — use the stashed chain.
            let max_skip = self.max_skip;
            if let Some(old) = self.old_receiving_chains.get_mut(&header_dh) {
                return Self::decrypt_on_chain(
                    ciphertext_with_nonce,
                    &aad,
                    header,
                    &mut old.chain_key,
                    &mut old.next_message_number,
                    &mut old.skipped,
                    max_skip,
                );
            }
            // Truly new remote DH key — stash current receiving state, then ratchet.
            if let (Some(remote), Some(chain)) = (self.remote_dh_key, self.receiving_chain_key) {
                let seq = self.next_old_chain_seq;
                self.next_old_chain_seq = seq.wrapping_add(1);
                self.old_receiving_chains.insert(
                    *remote.as_bytes(),
                    OldReceivingChain {
                        chain_key: chain,
                        next_message_number: self.receiving_message_number,
                        skipped: std::mem::take(&mut self.skipped_message_keys),
                        seq,
                    },
                );
            }
            self.dh_ratchet(&X25519PublicKey::from(header_dh))?;
        }

        let Some(mut chain) = self.receiving_chain_key else {
            return Err(RChatError::DecryptionFailed {
                message: "Receiving chain not initialized - cannot decrypt".to_string(),
            });
        };
        let mut next_num = self.receiving_message_number;
        let mut skipped = std::mem::take(&mut self.skipped_message_keys);
        let result = Self::decrypt_on_chain(
            ciphertext_with_nonce,
            &aad,
            header,
            &mut chain,
            &mut next_num,
            &mut skipped,
            self.max_skip,
        );
        self.receiving_chain_key = Some(chain);
        self.receiving_message_number = next_num;
        self.skipped_message_keys = skipped;
        result
    }

    /// Decrypt against a specific receiving chain, advancing that chain's counters.
    fn decrypt_on_chain(
        ciphertext_with_nonce: &[u8],
        aad: &[u8],
        header: &RatchetHeader,
        chain_key: &mut [u8; 32],
        receiving_message_number: &mut u32,
        skipped_message_keys: &mut BTreeMap<u32, SkippedKey>,
        max_skip: u32,
    ) -> Result<Vec<u8>, RChatError> {
        if header.message_number > *receiving_message_number {
            let skip_count = header.message_number - *receiving_message_number;
            if skip_count > max_skip {
                return Err(RChatError::DecryptionFailed {
                    message: format!("Too many skipped messages: {}", skip_count),
                });
            }
            let stored_at = crate::unix_now_secs();
            let mut current_chain_key = Zeroizing::new(*chain_key);
            for i in 0..skip_count {
                let (message_key, new_chain_key) = Self::kdf_message_key(&current_chain_key);
                skipped_message_keys.insert(
                    *receiving_message_number + i,
                    SkippedKey {
                        key: message_key,
                        inserted_at_unix: stored_at,
                    },
                );
                *current_chain_key = new_chain_key;
            }
            *chain_key = *current_chain_key;
            *receiving_message_number = header.message_number;
        }
        if header.message_number < *receiving_message_number {
            if let Some(sk) = skipped_message_keys.remove(&header.message_number) {
                let message_key = Zeroizing::new(sk.key);
                return Self::decrypt_with_key_static(ciphertext_with_nonce, &message_key, aad);
            }
            return Err(RChatError::DecryptionFailed {
                message: "Message number too old and not in skipped keys".to_string(),
            });
        }
        let (message_key, new_chain_key) = Self::kdf_message_key(chain_key);
        let message_key = Zeroizing::new(message_key);
        *chain_key = new_chain_key;
        *receiving_message_number = receiving_message_number.checked_add(1).ok_or_else(|| {
            RChatError::DecryptionFailed {
                message: "Receiving chain exhausted".to_string(),
            }
        })?;
        Self::decrypt_with_key_static(ciphertext_with_nonce, &message_key, aad)
    }

    fn decrypt_with_key_static(
        ciphertext_with_nonce: &[u8],
        message_key: &[u8; 32],
        aad: &[u8],
    ) -> Result<Vec<u8>, RChatError> {
        // ciphertext_with_nonce format: [nonce: 24 bytes][ciphertext: variable]
        if ciphertext_with_nonce.len() < 24 {
            return Err(RChatError::DecryptionFailed {
                message: "Ciphertext too short (missing nonce)".to_string(),
            });
        }
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(24);
        let cipher = XChaCha20Poly1305::new_from_slice(message_key).map_err(|e| {
            RChatError::DecryptionFailed {
                message: format!("Failed to create cipher: {}", e),
            }
        })?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| RChatError::DecryptionFailed {
                message: "Decryption failed".to_string(),
            })
    }

    /// KDF for root key: derives new root key and chain key from DH output
    /// Whitepaper: salt = root_key, IKM = dh_output, info = "RChat ratchet"
    fn kdf_root_key(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut okm = Zeroizing::new([0u8; 64]);
        crate::keyauth::with_hkdf(Some(root_key), dh_output, |hkdf| {
            hkdf.expand(b"RChat ratchet", &mut *okm)
                .expect("HKDF expand failed")
        });

        let new_root_key: [u8; 32] = okm[0..32].try_into().unwrap();
        let chain_key: [u8; 32] = okm[32..64].try_into().unwrap();

        (new_root_key, chain_key)
    }

    /// KDF for chain key: derives message key and new chain key
    /// Whitepaper: HMAC-SHA256 with constants 0x01 (message key) and 0x02 (chain key)
    fn kdf_message_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<Sha256>;

        // Message key: HMAC-SHA256(chain_key, 0x01)
        let mut mac: HmacSha256 =
            Mac::new_from_slice(chain_key).expect("HMAC can take key of any size");
        mac.update(&[0x01]);
        let message_key: [u8; 32] = mac.finalize().into_bytes()[..32].try_into().unwrap();

        // New chain key: HMAC-SHA256(chain_key, 0x02)
        let mut mac: HmacSha256 =
            Mac::new_from_slice(chain_key).expect("HMAC can take key of any size");
        mac.update(&[0x02]);
        let new_chain_key: [u8; 32] = mac.finalize().into_bytes()[..32].try_into().unwrap();

        (message_key, new_chain_key)
    }

    /// Every field (spec §18.2.1). Before a responder's first receive its DH
    /// key pair is the identity agreement secret: never copied out.
    pub fn snapshot(&self) -> RatchetSnapshotV1 {
        let pre_first = self.identity_key_pair.is_some();
        let mut old_chains: Vec<OldChainV1> = self
            .old_receiving_chains
            .iter()
            .map(|(dh, c)| OldChainV1 {
                remote_dh: *dh,
                chain_key: c.chain_key,
                next_n: c.next_message_number,
                skipped: skipped_v1(&c.skipped),
                seq: c.seq,
            })
            .collect();
        old_chains.sort_by_key(|c| c.seq);
        RatchetSnapshotV1 {
            root_key: self.root_key,
            sending_chain_key: self.sending_chain_key,
            receiving_chain_key: self.receiving_chain_key,
            ns: self.sending_message_number,
            nr: self.receiving_message_number,
            pn: self.previous_sending_chain_length,
            dh_secret: if pre_first {
                None
            } else {
                self.dh_key_pair.as_ref().map(|k| k.to_bytes())
            },
            remote_dh: self.remote_dh_key.map(|k| k.to_bytes()),
            needs_identity_ratchet: pre_first,
            is_responder: self.is_responder,
            max_skip: self.max_skip,
            skipped: skipped_v1(&self.skipped_message_keys),
            old_chains,
            next_old_chain_seq: self.next_old_chain_seq,
        }
    }

    /// Rebuild from `snapshot`. `identity_agreement_secret` is required when
    /// the snapshot `needs_identity_ratchet`. Expired skipped keys are dropped;
    /// a snapshot over the caps is refused (corrupt or hostile file).
    pub fn from_snapshot(
        s: &RatchetSnapshotV1,
        identity_agreement_secret: Option<&X25519SecretKey>,
    ) -> Result<Self, RChatError> {
        let refuse = |m: &str| RChatError::Internal {
            message: format!("ratchet snapshot refused: {m}"),
        };
        let total = s.skipped.len() + s.old_chains.iter().map(|c| c.skipped.len()).sum::<usize>();
        if total > MAX_SKIPPED_KEYS || s.old_chains.len() > MAX_OLD_RECEIVING_CHAINS {
            return Err(refuse("over the caps"));
        }
        if s.max_skip as usize > MAX_SKIPPED_KEYS {
            return Err(refuse("max_skip over the cap"));
        }
        if s.needs_identity_ratchet && s.dh_secret.is_some() {
            return Err(refuse("inconsistent identity state"));
        }
        let now = crate::unix_now_secs();
        let mut dr = Self::new(s.root_key);
        dr.sending_chain_key = s.sending_chain_key;
        dr.receiving_chain_key = s.receiving_chain_key;
        dr.sending_message_number = s.ns;
        dr.receiving_message_number = s.nr;
        dr.previous_sending_chain_length = s.pn;
        dr.remote_dh_key = s.remote_dh.map(X25519PublicKey::from);
        dr.is_responder = s.is_responder;
        dr.max_skip = s.max_skip;
        if s.needs_identity_ratchet {
            let id = identity_agreement_secret.ok_or_else(|| refuse("identity secret needed"))?;
            dr.dh_key_pair = Some(id.clone());
            dr.identity_key_pair = Some(id.clone());
        } else {
            dr.dh_key_pair = s.dh_secret.map(X25519SecretKey::from);
        }
        dr.skipped_message_keys = skipped_from_v1(&s.skipped, now);
        for c in &s.old_chains {
            dr.old_receiving_chains.insert(
                c.remote_dh,
                OldReceivingChain {
                    chain_key: c.chain_key,
                    next_message_number: c.next_n,
                    skipped: skipped_from_v1(&c.skipped, now),
                    seq: c.seq,
                },
            );
        }
        dr.next_old_chain_seq = s.next_old_chain_seq;
        Ok(dr)
    }

    /// Drop skipped keys older than `SKIPPED_KEY_MAX_AGE_SECS` (D31).
    pub fn purge_expired_skipped(&mut self, now_unix: u64) -> usize {
        // A stamp in the future (the clock stepped back) is re-stamped to now.
        let fresh = |k: &mut SkippedKey| {
            k.inserted_at_unix = k.inserted_at_unix.min(now_unix);
            now_unix - k.inserted_at_unix <= SKIPPED_KEY_MAX_AGE_SECS
        };
        let before = self.skipped_total();
        self.skipped_message_keys.retain(|_, k| fresh(k));
        for c in self.old_receiving_chains.values_mut() {
            c.skipped.retain(|_, k| fresh(k));
        }
        before - self.skipped_total()
    }

    #[cfg(test)]
    pub(crate) fn age_skipped_for_test(&mut self, by_secs: u64) {
        for k in self.skipped_message_keys.values_mut() {
            k.inserted_at_unix = k.inserted_at_unix.saturating_sub(by_secs);
        }
        for c in self.old_receiving_chains.values_mut() {
            for k in c.skipped.values_mut() {
                k.inserted_at_unix = k.inserted_at_unix.saturating_sub(by_secs);
            }
        }
    }

    /// Get current DH public key (for sending in headers)
    pub fn get_dh_public_key(&self) -> Option<[u8; 32]> {
        self.dh_key_pair
            .as_ref()
            .map(|k| X25519PublicKey::from(k).to_bytes())
    }
}

/// Compute HMAC-SHA256-128 authentication tag
pub fn compute_auth_tag(circuit_id: &[u8; 16], payload: &[u8], token_key: &[u8; 32]) -> [u8; 16] {
    use hmac::Mac;
    use sha2::Sha256;

    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut mac: HmacSha256 =
        Mac::new_from_slice(token_key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, circuit_id);
    Mac::update(&mut mac, payload);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bytes[..16]);
    tag
}

/// Verify HMAC-SHA256-128 authentication tag
pub fn verify_auth_tag(
    circuit_id: &[u8; 16],
    payload: &[u8],
    token_key: &[u8; 32],
    tag: &[u8; 16],
) -> bool {
    let expected = compute_auth_tag(circuit_id, payload, token_key);
    constant_time_eq::constant_time_eq(&expected, tag)
}

// Re-export for use in protocol module
pub use hmac::Mac as HmacMac;

/// Encrypt data with XChaCha20-Poly1305 (for server compatibility)
pub fn encrypt_xchacha20poly1305(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, RChatError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| RChatError::EncryptionFailed {
            message: e.to_string(),
        })?;

    let nonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| RChatError::EncryptionFailed {
            message: e.to_string(),
        })
}

/// Decrypt data with XChaCha20-Poly1305 (for server compatibility)
pub fn decrypt_xchacha20poly1305(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, RChatError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| RChatError::DecryptionFailed {
            message: e.to_string(),
        })?;

    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| RChatError::DecryptionFailed {
            message: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keyauth::{golden, KeyAuthError};

    #[test]
    fn write_seed_matches_seed_bytes() {
        let id = IdentityKeyPair::generate();
        let mut out = [0u8; 64];
        id.write_seed(&mut out);
        assert_eq!(out, id.seed_bytes());
    }

    fn golden_pair() -> (IdentityKeyPair, IdentityKeyPair) {
        (
            IdentityKeyPair::from_seed(&golden::seed_a()).unwrap(),
            IdentityKeyPair::from_seed(&golden::seed_b()).unwrap(),
        )
    }

    /// Fixed X3DH v3 inputs: golden identities A (initiator) and B
    /// (responder), EK_i = 0x61.., EK_r = 0x62.., kem_ss = 0x71..,
    /// kem_ek_pub_r = the KEM key of seed 0x73.., ct = 0x72...
    struct V3Inputs {
        a: IdentityKeyPair,
        b: IdentityKeyPair,
        ek_i: X25519SecretKey,
        ek_r: X25519SecretKey,
        kem_ss: [u8; 32],
        kem_pk: [u8; KEM_PK_LEN],
        ct: [u8; crate::kem::KEM_CT_LEN],
    }

    fn v3_inputs() -> V3Inputs {
        let (a, b) = golden_pair();
        V3Inputs {
            a,
            b,
            ek_i: X25519SecretKey::from([0x61u8; 32]),
            ek_r: X25519SecretKey::from([0x62u8; 32]),
            kem_ss: [0x71; 32],
            kem_pk: *KemKeyPair::from_seed(&[0x73; 64]).public(),
            ct: [0x72; crate::kem::KEM_CT_LEN],
        }
    }

    impl V3Inputs {
        fn ik_a(&self) -> [u8; 32] {
            self.a.public_signing_key().to_bytes()
        }
        fn ik_b(&self) -> [u8; 32] {
            self.b.public_signing_key().to_bytes()
        }
        fn initiator(&self) -> Zeroizing<[u8; 32]> {
            x3dh_v3_initiator(
                self.a.agreement_secret(),
                &self.ek_i,
                &self.b.public_agreement_key().to_bytes(),
                &X25519PublicKey::from(&self.ek_r).to_bytes(),
                &self.kem_ss,
                &self.kem_pk,
                &self.ct,
                &self.ik_a(),
                &self.ik_b(),
            )
            .unwrap()
        }
        fn responder(&self) -> Zeroizing<[u8; 32]> {
            x3dh_v3_responder(
                self.b.agreement_secret(),
                &self.ek_r,
                &self.a.public_agreement_key().to_bytes(),
                &X25519PublicKey::from(&self.ek_i).to_bytes(),
                &self.kem_ss,
                &self.kem_pk,
                &self.ct,
                &self.ik_a(),
                &self.ik_b(),
            )
            .unwrap()
        }
    }

    /// §F.1: fixed inputs give the exact SK, the same on both roles. The
    /// vector was reproduced independently in Python stdlib: a pure-Python
    /// RFC 7748 X25519 for the four DHs (from the golden seeds' agreement
    /// halves and the fixed EKs), then RFC 5869 HKDF-SHA256 with salt 0^32
    /// and info "rchat/x3dh/v3" || IK_A || IK_B || SHA-256(kem_pk || ct).
    #[test]
    fn x3dh_v3_vector_both_roles() {
        let v = v3_inputs();
        let (ski, skr) = (v.initiator(), v.responder());
        assert_eq!(
            hex::encode(*ski),
            "f46d359c092626543b55ac15acb1f632b56d3b8e7e714eadcc8e2e752e341f13"
        );
        assert_eq!(*ski, *skr);
    }

    /// §F.1: each input changes SK: every DH (through IK_i, EK_i, ak_r and
    /// EK_r), kem_ss, the IK order, kem_ek_pub_r and ct.
    #[test]
    fn x3dh_v3_each_input_changes_sk() {
        let base = *v3_inputs().initiator();
        let mut seen = vec![base];
        let mut check = |sk: [u8; 32], what: &str| {
            assert!(!seen.contains(&sk), "{what} must change SK");
            seen.push(sk);
        };
        // DH1 (and only DH1) through the initiator's identity agreement key.
        let mut v = v3_inputs();
        v.a = IdentityKeyPair::from_seed(&[0x44; 64]).unwrap();
        let ik_a = golden_pair().0.public_signing_key().to_bytes();
        let dh1_only = x3dh_v3_initiator(
            v.a.agreement_secret(),
            &v.ek_i,
            &v.b.public_agreement_key().to_bytes(),
            &X25519PublicKey::from(&v.ek_r).to_bytes(),
            &v.kem_ss,
            &v.kem_pk,
            &v.ct,
            &ik_a,
            &v.ik_b(),
        )
        .unwrap();
        check(*dh1_only, "DH1 (IK_i agreement key)");
        // DH2, DH3 and DH4 through EK_i.
        let mut v = v3_inputs();
        v.ek_i = X25519SecretKey::from([0x65u8; 32]);
        check(*v.initiator(), "EK_i (DH2-DH4)");
        // DH1-DH3 through the responder's agreement key, keeping IK_r.
        let v = v3_inputs();
        let other_ak = IdentityKeyPair::from_seed(&[0x45; 64])
            .unwrap()
            .public_agreement_key()
            .to_bytes();
        let ak_changed = x3dh_v3_initiator(
            v.a.agreement_secret(),
            &v.ek_i,
            &other_ak,
            &X25519PublicKey::from(&v.ek_r).to_bytes(),
            &v.kem_ss,
            &v.kem_pk,
            &v.ct,
            &v.ik_a(),
            &v.ik_b(),
        )
        .unwrap();
        check(*ak_changed, "ak_r (DH1-DH3)");
        // DH4 through EK_r.
        let mut v = v3_inputs();
        v.ek_r = X25519SecretKey::from([0x63u8; 32]);
        check(*v.initiator(), "EK_r (DH4)");
        let mut v = v3_inputs();
        v.kem_ss[31] ^= 1;
        check(*v.initiator(), "kem_ss");
        let mut v = v3_inputs();
        v.kem_pk = *KemKeyPair::from_seed(&[0x74; 64]).public();
        check(*v.initiator(), "kem_ek_pub_r");
        let mut v = v3_inputs();
        v.ct[0] ^= 1;
        check(*v.initiator(), "ct");
        // The IK order in info (the DHs are unchanged).
        let v = v3_inputs();
        let swapped = x3dh_v3_initiator(
            v.a.agreement_secret(),
            &v.ek_i,
            &v.b.public_agreement_key().to_bytes(),
            &X25519PublicKey::from(&v.ek_r).to_bytes(),
            &v.kem_ss,
            &v.kem_pk,
            &v.ct,
            &v.ik_b(),
            &v.ik_a(),
        )
        .unwrap();
        check(*swapped, "IK order");
        // IK_i and IK_r themselves.
        let v = v3_inputs();
        let other_ik = [0x99u8; 32];
        for (i, r, what) in [(other_ik, v.ik_b(), "IK_i"), (v.ik_a(), other_ik, "IK_r")] {
            let sk = x3dh_v3_initiator(
                v.a.agreement_secret(),
                &v.ek_i,
                &v.b.public_agreement_key().to_bytes(),
                &X25519PublicKey::from(&v.ek_r).to_bytes(),
                &v.kem_ss,
                &v.kem_pk,
                &v.ct,
                &i,
                &r,
            )
            .unwrap();
            check(*sk, what);
        }
    }

    /// A real ML-KEM round trip: the initiator encapsulates to the
    /// responder's ephemeral, the responder decapsulates; both get one SK.
    #[test]
    fn x3dh_v3_real_kem_round_trip() {
        let v = v3_inputs();
        let kem_eph = KemKeyPair::generate();
        let (ct, ss_i) = crate::kem::encapsulate(kem_eph.public()).unwrap();
        let ss_r = kem_eph.decapsulate(&ct).unwrap();
        let ek_r_pub = X25519PublicKey::from(&v.ek_r).to_bytes();
        let ek_i_pub = X25519PublicKey::from(&v.ek_i).to_bytes();
        let ski = x3dh_v3_initiator(
            v.a.agreement_secret(),
            &v.ek_i,
            &v.b.public_agreement_key().to_bytes(),
            &ek_r_pub,
            &ss_i,
            kem_eph.public(),
            &ct,
            &v.ik_a(),
            &v.ik_b(),
        )
        .unwrap();
        let skr = x3dh_v3_responder(
            v.b.agreement_secret(),
            &v.ek_r,
            &v.a.public_agreement_key().to_bytes(),
            &ek_i_pub,
            &ss_r,
            kem_eph.public(),
            &ct,
            &v.ik_a(),
            &v.ik_b(),
        )
        .unwrap();
        assert_eq!(*ski, *skr);
    }

    /// K17 / L1: an all-zero (or other low-order) relay-supplied EK is
    /// refused on either role (`dh_checked`).
    #[test]
    fn x3dh_v3_refuses_non_contributory() {
        let v = v3_inputs();
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1; // the point of order 1
        for bad in [zero, one] {
            assert_eq!(
                x3dh_v3_initiator(
                    v.a.agreement_secret(),
                    &v.ek_i,
                    &v.b.public_agreement_key().to_bytes(),
                    &bad,
                    &v.kem_ss,
                    &v.kem_pk,
                    &v.ct,
                    &v.ik_a(),
                    &v.ik_b(),
                )
                .map(|_| ()),
                Err(KeyAuthError::NonContributory)
            );
            assert_eq!(
                x3dh_v3_responder(
                    v.b.agreement_secret(),
                    &v.ek_r,
                    &v.a.public_agreement_key().to_bytes(),
                    &bad,
                    &v.kem_ss,
                    &v.kem_pk,
                    &v.ct,
                    &v.ik_a(),
                    &v.ik_b(),
                )
                .map(|_| ()),
                Err(KeyAuthError::NonContributory)
            );
        }
    }

    /// L1: identity agreement refuses a low-order peer key; a normal key
    /// gives the same secret on both sides.
    #[test]
    fn identity_agree_is_contributory_checked() {
        let (a, b) = golden_pair();
        let ab = a.agree(&b.public_agreement_key()).unwrap();
        let ba = b.agree(&a.public_agreement_key()).unwrap();
        assert_eq!(*ab, *ba);
        let mut one = [0u8; 32];
        one[0] = 1;
        for bad in [[0u8; 32], one] {
            assert_eq!(
                a.agree(&X25519PublicKey::from(bad)).map(|z| *z),
                Err(KeyAuthError::NonContributory)
            );
        }
    }

    /// AEAD associated data IK_sender || IK_recipient for tests.
    fn ad(sender: u8, recipient: u8) -> [u8; 64] {
        let mut a = [0u8; 64];
        a[..32].fill(sender);
        a[32..].fill(recipient);
        a
    }

    fn ratchet_pair() -> (DoubleRatchet, DoubleRatchet) {
        let shared_secret = [0x42u8; 32];
        let bob_identity = X25519SecretKey::random_from_rng(&mut OsRng);
        let bob_identity_pub = X25519PublicKey::from(&bob_identity);
        let alice_ephemeral = X25519SecretKey::random_from_rng(&mut OsRng);
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);
        let mut alice = DoubleRatchet::new(shared_secret);
        alice
            .initialize_alice(&alice_ephemeral, &bob_identity_pub)
            .unwrap();
        let mut bob = DoubleRatchet::new(shared_secret);
        bob.initialize_bob(&bob_identity, &alice_ephemeral_pub)
            .unwrap();
        (alice, bob)
    }

    /// K14 (AAD): a flipped header bit fails, and the failure leaves the
    /// receiving ratchet intact.
    #[test]
    fn k14_flipped_header_bit_fails_without_corrupting_state() {
        let (mut alice, mut bob) = ratchet_pair();
        let (ct, header) = alice.encrypt(b"hello", &ad(1, 2)).unwrap();
        let mut bad = header.clone();
        bad.previous_chain_length ^= 1;
        assert!(bob.decrypt(&ct, &bad, &ad(1, 2)).is_err());
        let mut bad_key = header.clone();
        bad_key.dh_public_key[0] ^= 1;
        assert!(bob.decrypt(&ct, &bad_key, &ad(1, 2)).is_err());
        assert_eq!(bob.decrypt(&ct, &header, &ad(1, 2)).unwrap(), b"hello");
    }

    /// L1: a header carrying a low-order DH key is refused before any key is
    /// derived, and the refusal leaves the receiving ratchet intact.
    #[test]
    fn low_order_header_dh_key_is_refused_without_corrupting_state() {
        let (mut alice, mut bob) = ratchet_pair();
        let (ct, header) = alice.encrypt(b"hello", &ad(1, 2)).unwrap();
        let mut bad = header.clone();
        bad.dh_public_key = [0u8; 32];
        assert!(bob.decrypt(&ct, &bad, &ad(1, 2)).is_err());
        assert_eq!(bob.decrypt(&ct, &header, &ad(1, 2)).unwrap(), b"hello");
    }

    /// K14 (AAD): a message presented as coming from another identity, or
    /// with the identities swapped, does not decrypt.
    #[test]
    fn k14_swapped_or_substituted_identity_fails() {
        let (mut alice, mut bob) = ratchet_pair();
        let (ct, header) = alice.encrypt(b"hello", &ad(1, 2)).unwrap();
        assert!(
            bob.decrypt(&ct, &header, &ad(3, 2)).is_err(),
            "IK_sender substituted"
        );
        assert!(
            bob.decrypt(&ct, &header, &ad(2, 1)).is_err(),
            "IK order swapped"
        );
        assert_eq!(bob.decrypt(&ct, &header, &ad(1, 2)).unwrap(), b"hello");
    }

    #[test]
    fn test_identity_key_generation() {
        let identity = IdentityKeyPair::generate();
        let hex = identity.public_key_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_identity_seed_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let seed = identity.seed_bytes();
        let pubkey1 = identity.public_key_hex();
        let agree1 = identity.agreement_key_hex();

        let identity2 = IdentityKeyPair::from_seed(&seed).unwrap();
        let pubkey2 = identity2.public_key_hex();
        let agree2 = identity2.agreement_key_hex();

        assert_eq!(pubkey1, pubkey2, "Public key mismatch after roundtrip");
        assert_eq!(agree1, agree2, "Agreement key mismatch after roundtrip");
    }

    #[test]
    fn test_double_ratchet_roundtrip() {
        // Simulate X3DH shared secret
        let shared_secret = [0x42u8; 32];

        // Bob (responder) identity key
        let bob_identity = X25519SecretKey::random_from_rng(&mut OsRng);
        let bob_identity_pub = X25519PublicKey::from(&bob_identity);

        // Alice (initiator) generates ephemeral key (same as X3DH)
        let alice_ephemeral = X25519SecretKey::random_from_rng(&mut OsRng);

        // Alice initializes with her ephemeral key and Bob's identity
        let mut alice_ratchet = DoubleRatchet::new(shared_secret);
        alice_ratchet
            .initialize_alice(&alice_ephemeral, &bob_identity_pub)
            .unwrap();

        // Get Alice's ephemeral public key
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);

        // Bob (responder) initializes with Alice's ephemeral key
        let mut bob_ratchet = DoubleRatchet::new(shared_secret);
        bob_ratchet
            .initialize_bob(&bob_identity, &alice_ephemeral_pub)
            .unwrap();

        // Alice sends first message
        let plaintext1 = b"Hello Bob!";
        let (ciphertext1, header1) = alice_ratchet.encrypt(plaintext1, &ad(1, 2)).unwrap();

        // Bob decrypts first message
        let decrypted1 = bob_ratchet
            .decrypt(&ciphertext1, &header1, &ad(1, 2))
            .unwrap();
        assert_eq!(decrypted1, plaintext1.as_slice());

        // Bob sends reply
        let plaintext2 = b"Hello Alice!";
        let (ciphertext2, header2) = bob_ratchet.encrypt(plaintext2, &ad(2, 1)).unwrap();

        // Alice decrypts reply
        let decrypted2 = alice_ratchet
            .decrypt(&ciphertext2, &header2, &ad(2, 1))
            .unwrap();
        assert_eq!(decrypted2, plaintext2.as_slice());
    }

    /// Both peers send before processing the other's messages (typical chat).
    /// Late messages on the previous sending chain must still decrypt.
    #[test]
    fn test_double_ratchet_concurrent_sends() {
        let shared_secret = [0x24u8; 32];
        let bob_identity = X25519SecretKey::random_from_rng(&mut OsRng);
        let bob_identity_pub = X25519PublicKey::from(&bob_identity);
        let alice_ephemeral = X25519SecretKey::random_from_rng(&mut OsRng);
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);

        let mut alice = DoubleRatchet::new(shared_secret);
        alice
            .initialize_alice(&alice_ephemeral, &bob_identity_pub)
            .unwrap();
        let mut bob = DoubleRatchet::new(shared_secret);
        bob.initialize_bob(&bob_identity, &alice_ephemeral_pub)
            .unwrap();

        // Alice sends three before receiving anything
        let (c0, h0) = alice.encrypt(b"a0", &ad(1, 2)).unwrap();
        let (c1, h1) = alice.encrypt(b"a1", &ad(1, 2)).unwrap();
        let (c2, h2) = alice.encrypt(b"a2", &ad(1, 2)).unwrap();

        // Bob also sends two before receiving Alice (queued responder send)
        // Bob has no sending chain yet — first encrypt derives it after he
        // would have received. Force by decrypting Alice's first, then send.
        assert_eq!(bob.decrypt(&c0, &h0, &ad(1, 2)).unwrap(), b"a0");

        let (b0, bh0) = bob.encrypt(b"b0", &ad(2, 1)).unwrap();
        let (b1, bh1) = bob.encrypt(b"b1", &ad(2, 1)).unwrap();

        // Alice processes Bob's reply (new remote DH → ratchet)
        assert_eq!(alice.decrypt(&b0, &bh0, &ad(2, 1)).unwrap(), b"b0");
        assert_eq!(alice.decrypt(&b1, &bh1, &ad(2, 1)).unwrap(), b"b1");

        // Late Alice messages on the OLD chain must still decrypt on Bob
        assert_eq!(bob.decrypt(&c1, &h1, &ad(1, 2)).unwrap(), b"a1");
        assert_eq!(bob.decrypt(&c2, &h2, &ad(1, 2)).unwrap(), b"a2");

        // Out-of-order delivery of Bob's messages on Alice after she ratcheted
        let (c3, h3) = alice.encrypt(b"a3", &ad(1, 2)).unwrap();
        assert_eq!(bob.decrypt(&c3, &h3, &ad(1, 2)).unwrap(), b"a3");
    }

    /// C-2: a peer that delivers only every 101st message cannot grow the
    /// skipped-key store past `MAX_SKIPPED_KEYS`; the latest still decrypt.
    #[test]
    fn c2_skipped_keys_are_capped() {
        let (mut alice, mut bob) = ratchet_pair();
        for round in 0..30 {
            let mut last = None;
            for _ in 0..101 {
                last = Some(alice.encrypt(b"x", &ad(1, 2)).unwrap());
            }
            let (c, h) = last.unwrap();
            assert_eq!(
                bob.decrypt(&c, &h, &ad(1, 2)).unwrap(),
                b"x",
                "round {round}"
            );
            assert!(bob.skipped_total() <= MAX_SKIPPED_KEYS, "round {round}");
        }
        assert_eq!(bob.skipped_total(), MAX_SKIPPED_KEYS);
    }

    /// C-2: a fresh remote DH key per round cannot grow the stashed chains
    /// past `MAX_OLD_RECEIVING_CHAINS`; a late message on a recent stashed
    /// chain still decrypts, one on an evicted chain does not.
    #[test]
    fn c2_old_receiving_chains_are_capped() {
        let (mut alice, mut bob) = ratchet_pair();
        let mut late = Vec::new();
        for round in 0..20 {
            let skipped = alice.encrypt(b"late", &ad(1, 2)).unwrap();
            let (c, h) = alice.encrypt(b"a", &ad(1, 2)).unwrap();
            assert_eq!(
                bob.decrypt(&c, &h, &ad(1, 2)).unwrap(),
                b"a",
                "round {round}"
            );
            let (r, rh) = bob.encrypt(b"b", &ad(2, 1)).unwrap();
            assert_eq!(alice.decrypt(&r, &rh, &ad(2, 1)).unwrap(), b"b");
            late.push(skipped);
            assert!(bob.old_receiving_chains.len() <= MAX_OLD_RECEIVING_CHAINS);
        }
        assert_eq!(bob.old_receiving_chains.len(), MAX_OLD_RECEIVING_CHAINS);
        let (c, h) = &late[18];
        assert_eq!(bob.decrypt(c, h, &ad(1, 2)).unwrap(), b"late");
        let (c, h) = &late[0];
        assert!(bob.decrypt(c, h, &ad(1, 2)).is_err(), "evicted chain");
    }

    #[test]
    fn test_ratchet_header_encode_decode() {
        let header = RatchetHeader {
            message_number: 42,
            previous_chain_length: 10,
            dh_public_key: [0xABu8; 32],
        };

        let encoded = header.encode();
        let decoded = RatchetHeader::decode(&encoded).unwrap();

        assert_eq!(header.message_number, decoded.message_number);
        assert_eq!(header.previous_chain_length, decoded.previous_chain_length);
        assert_eq!(header.dh_public_key, decoded.dh_public_key);
    }

    /// SP1: a snapshot carries skipped keys on the current chain and on two
    /// stashed old chains; every late message decrypts once after restore.
    #[test]
    fn sp1_snapshot_round_trip_keeps_skipped_and_old_chains() {
        let (mut alice, mut bob) = ratchet_pair();
        // Chain 1: Alice sends 3, Bob gets only the last (2 skipped).
        let a: Vec<_> = (0..3)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&a[2].0, &a[2].1, &ad(1, 2)).unwrap(), vec![2]);
        // Bob replies, Alice ratchets; chain 2: Alice sends 3, Bob gets the last.
        let (r, rh) = bob.encrypt(b"r", &ad(2, 1)).unwrap();
        alice.decrypt(&r, &rh, &ad(2, 1)).unwrap();
        let b: Vec<_> = (10..13)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&b[2].0, &b[2].1, &ad(1, 2)).unwrap(), vec![12]);
        // Again for a third chain, so two old chains are stashed.
        let (r, rh) = bob.encrypt(b"r2", &ad(2, 1)).unwrap();
        alice.decrypt(&r, &rh, &ad(2, 1)).unwrap();
        let c: Vec<_> = (20..22)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&c[1].0, &c[1].1, &ad(1, 2)).unwrap(), vec![21]);

        let snap = bob.snapshot();
        let bytes = bincode::serialize(&snap).unwrap();
        let back: RatchetSnapshotV1 = bincode::deserialize(&bytes).unwrap();
        let mut restored = DoubleRatchet::from_snapshot(&back, None).unwrap();
        for (ct, h) in [&a[0], &a[1], &b[0], &b[1], &c[0]] {
            assert!(restored.decrypt(ct, h, &ad(1, 2)).is_ok());
            assert!(
                restored.decrypt(ct, h, &ad(1, 2)).is_err(),
                "each key used once"
            );
        }
        // And it keeps talking.
        let (n, nh) = alice.encrypt(b"next", &ad(1, 2)).unwrap();
        assert_eq!(restored.decrypt(&n, &nh, &ad(1, 2)).unwrap(), b"next");
    }

    /// SP1: a responder before its first receive restores only with the
    /// identity secret supplied, and the snapshot never holds that secret.
    #[test]
    fn sp1_responder_snapshot_never_holds_the_identity_secret() {
        let shared = [0x42u8; 32];
        let bob_id = X25519SecretKey::random_from_rng(&mut OsRng);
        let alice_eph = X25519SecretKey::random_from_rng(&mut OsRng);
        let mut alice = DoubleRatchet::new(shared);
        alice
            .initialize_alice(&alice_eph, &X25519PublicKey::from(&bob_id))
            .unwrap();
        let mut bob = DoubleRatchet::new(shared);
        bob.initialize_bob(&bob_id, &X25519PublicKey::from(&alice_eph))
            .unwrap();
        let snap = bob.snapshot();
        assert!(snap.needs_identity_ratchet && snap.dh_secret.is_none());
        let bytes = bincode::serialize(&snap).unwrap();
        let secret = bob_id.to_bytes();
        assert!(
            !bytes.windows(32).any(|w| w == secret),
            "identity secret never serialised"
        );
        assert!(DoubleRatchet::from_snapshot(&snap, None).is_err());
        let mut restored = DoubleRatchet::from_snapshot(&snap, Some(&bob_id)).unwrap();
        let (m, h) = alice.encrypt(b"hi", &ad(1, 2)).unwrap();
        assert_eq!(restored.decrypt(&m, &h, &ad(1, 2)).unwrap(), b"hi");
    }

    /// SP2: skipped keys older than 72 h go, on purge and at restore.
    #[test]
    fn sp2_skipped_keys_expire_after_72_hours() {
        let (mut alice, mut bob) = ratchet_pair();
        let a: Vec<_> = (0..3)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        bob.decrypt(&a[2].0, &a[2].1, &ad(1, 2)).unwrap();
        bob.age_skipped_for_test(SKIPPED_KEY_MAX_AGE_SECS - 10);
        let mut kept = DoubleRatchet::from_snapshot(&bob.snapshot(), None).unwrap();
        assert_eq!(kept.purge_expired_skipped(crate::unix_now_secs()), 0);
        bob.age_skipped_for_test(20);
        assert_eq!(bob.purge_expired_skipped(crate::unix_now_secs()), 2);
        assert!(
            bob.decrypt(&a[0].0, &a[0].1, &ad(1, 2)).is_err(),
            "expired key gone"
        );
        assert!(kept.decrypt(&a[0].0, &a[0].1, &ad(1, 2)).is_ok());
        // Restore drops expired keys too.
        let mut old = DoubleRatchet::from_snapshot(&kept.snapshot(), None).unwrap();
        old.age_skipped_for_test(SKIPPED_KEY_MAX_AGE_SECS + 1);
        let restored = DoubleRatchet::from_snapshot(&old.snapshot(), None).unwrap();
        assert_eq!(restored.snapshot().skipped.len(), 0);
    }

    #[test]
    fn snapshot_debug_is_redacted() {
        let (alice, _) = ratchet_pair();
        let s = alice.snapshot();
        let shown = format!("{s:?}");
        assert!(!shown.contains(&hex::encode(s.root_key)) && shown.contains("redacted"));

        // Also the `{:?}` forms of root key, DH secret and a skipped key.
        let (mut a2, mut b2) = ratchet_pair();
        let m: Vec<_> = (0..2)
            .map(|i| a2.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        b2.decrypt(&m[1].0, &m[1].1, &ad(1, 2)).unwrap();
        let s = b2.snapshot();
        let shown = format!("{s:?}");
        assert!(!s.skipped.is_empty() && s.dh_secret.is_some());
        for key in [s.root_key, s.dh_secret.unwrap(), s.skipped[0].key] {
            assert!(!shown.contains(&format!("{key:?}")));
            assert!(!shown.contains(&hex::encode(key)));
        }
    }

    /// Review: a clock that steps back must not extend a key's life.
    #[test]
    fn sp2_clock_step_back_does_not_extend_skipped_keys() {
        let now = crate::unix_now_secs();
        let ten_days = 10 * 24 * 3600;
        // Purge path: keys stamped "now", purged by a clock 10 days behind.
        let (mut alice, mut bob) = ratchet_pair();
        let a: Vec<_> = (0..3)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        bob.decrypt(&a[2].0, &a[2].1, &ad(1, 2)).unwrap();
        let back = now - ten_days;
        assert_eq!(bob.purge_expired_skipped(back), 0);
        assert_eq!(
            bob.purge_expired_skipped(back + SKIPPED_KEY_MAX_AGE_SECS),
            0
        );
        assert_eq!(
            bob.purge_expired_skipped(back + SKIPPED_KEY_MAX_AGE_SECS + 1),
            2
        );
        // Restore path: a snapshot stamped 10 days ahead.
        let (mut alice, mut bob) = ratchet_pair();
        let a: Vec<_> = (0..3)
            .map(|i| alice.encrypt(&[i], &ad(1, 2)).unwrap())
            .collect();
        bob.decrypt(&a[2].0, &a[2].1, &ad(1, 2)).unwrap();
        let mut snap = bob.snapshot();
        for k in snap.skipped.iter_mut() {
            k.inserted_at_unix = now + ten_days;
        }
        let mut restored = DoubleRatchet::from_snapshot(&snap, None).unwrap();
        assert_eq!(restored.snapshot().skipped.len(), 2);
        let later = crate::unix_now_secs() + SKIPPED_KEY_MAX_AGE_SECS + 1;
        assert_eq!(restored.purge_expired_skipped(later), 2);
    }

    #[test]
    fn from_snapshot_refuses_inconsistent_or_oversized_snapshots() {
        let (_, bob) = ratchet_pair();
        let mut s = bob.snapshot();
        s.max_skip = MAX_SKIPPED_KEYS as u32 + 1;
        assert!(DoubleRatchet::from_snapshot(&s, None).is_err());
        let mut s = bob.snapshot();
        s.needs_identity_ratchet = true;
        s.dh_secret = Some([7u8; 32]);
        let id = X25519SecretKey::random_from_rng(&mut OsRng);
        assert!(DoubleRatchet::from_snapshot(&s, Some(&id)).is_err());
    }
}
