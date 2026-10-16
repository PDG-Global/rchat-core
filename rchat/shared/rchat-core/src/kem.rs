//! ML-KEM-768 (FIPS 203) key encapsulation for the protocol v3 hybrid
//! handshake (spec §A.1).
//!
//! A thin wrapper over RustCrypto `ml-kem` (pinned in `Cargo.toml`):
//! - secrets (the 2400-byte decapsulation key, the 64-byte seed, shared
//!   secrets) live only in `Zeroizing`, and the crate's temporaries this
//!   module owns are wiped before they go out of scope;
//! - no `Debug` prints key or secret bytes;
//! - every length is checked before any call into the crate, and a public key
//!   whose coefficients are not reduced mod q is refused (the FIPS 203 §7.2
//!   encapsulation-key check, also exposed as [`validate_public_key`]);
//! - this is the only module that names `ml_kem` (a source-scan test enforces
//!   it), and deterministic encapsulation is a disallowed method outside the
//!   test-only KAT helper (`clippy.toml`).
//!
//! There is deliberately no import of a raw 2400-byte secret key: persisted
//! keys are stored as their 64-byte seed and rebuilt with [`KemKeyPair::from_seed`].
//!
//! Decapsulation never fails on a well-formed ciphertext: ML-KEM rejects
//! implicitly, returning a pseudorandom secret for a tampered ciphertext, so
//! the handshake's confirmation tag is what detects tampering.

use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, B32};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// ML-KEM-768 encapsulation (public) key length.
pub const KEM_PK_LEN: usize = 1184;
/// ML-KEM-768 decapsulation (secret) key length, FIPS 203 encoding.
pub const KEM_SK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length.
pub const KEM_CT_LEN: usize = 1088;
/// Seed length for deterministic key generation: `d || z`.
pub const KEM_SEED_LEN: usize = 64;
/// Shared secret length.
pub const KEM_SS_LEN: usize = 32;

/// The ML-KEM modulus.
const Q: u16 = 3329;
/// Bytes of the encoded polynomial vector `t` at the start of an
/// ML-KEM-768 encapsulation key (k = 3, 384 bytes per polynomial).
const EK_T_LEN: usize = 384 * 3;

type Dk = DecapsulationKey<MlKem768Params>;
type Ek = EncapsulationKey<MlKem768Params>;

/// Errors from this module. None carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KemError {
    /// A key or ciphertext has the wrong length.
    #[error("ML-KEM input has the wrong length")]
    BadLength,
    /// The public key fails the FIPS 203 modulus check.
    #[error("ML-KEM public key is malformed")]
    BadKey,
    /// The underlying implementation reported a failure (encapsulation's
    /// error path; ML-KEM decapsulation itself cannot fail).
    #[error("ML-KEM operation failed")]
    Crypto,
}

/// An ML-KEM-768 key pair. The secret key lives on the heap (a move copies
/// only the pointer) and is wiped in place on drop, before it is freed.
pub struct KemKeyPair {
    public: [u8; KEM_PK_LEN],
    secret: Box<Zeroizing<[u8; KEM_SK_LEN]>>,
}

impl std::fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemKeyPair")
            .field("public", &format_args!("[{} bytes]", KEM_PK_LEN))
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl KemKeyPair {
    /// A fresh key pair from the OS RNG (FIPS 203 `ML-KEM.KeyGen`).
    pub fn generate() -> Self {
        Self::generate_with_seed().0
    }

    /// A fresh key pair and the 64-byte seed (`d || z`) it was built from, so
    /// the caller can persist the seed and rebuild the pair with
    /// [`KemKeyPair::from_seed`].
    pub fn generate_with_seed() -> (Self, Zeroizing<[u8; KEM_SEED_LEN]>) {
        let mut seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
        OsRng.fill_bytes(&mut seed[..]);
        (Self::from_seed(&seed), seed)
    }

    /// The encapsulation (public) key.
    pub fn public(&self) -> &[u8; KEM_PK_LEN] {
        &self.public
    }

    /// Deterministic key generation (FIPS 203 `ML-KEM.KeyGen_internal(d, z)`)
    /// with `seed64 = d || z`.
    pub fn from_seed(seed64: &[u8; KEM_SEED_LEN]) -> Self {
        let mut d = B32::default();
        let mut z = B32::default();
        d.copy_from_slice(&seed64[..32]);
        z.copy_from_slice(&seed64[32..]);
        let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
        d.as_mut_slice().zeroize();
        z.as_mut_slice().zeroize();

        let mut public = [0u8; KEM_PK_LEN];
        public.copy_from_slice(&ek.as_bytes());

        let mut secret = Box::new(Zeroizing::new([0u8; KEM_SK_LEN]));
        let mut dk_bytes = dk.as_bytes();
        secret.copy_from_slice(&dk_bytes[..]);
        dk_bytes.as_mut_slice().zeroize();
        // `dk` zeroes its own secret parts on drop (`zeroize` feature).
        drop(dk);

        Self { public, secret }
    }

    /// Decapsulates `ct`. A wrong length is `BadLength`; a tampered but
    /// well-sized ciphertext yields a different secret, not an error.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; KEM_SS_LEN]>, KemError> {
        if ct.len() != KEM_CT_LEN {
            return Err(KemError::BadLength);
        }
        let mut ct_arr = ml_kem::Ciphertext::<MlKem768>::default();
        ct_arr.copy_from_slice(ct);

        let mut enc = Encoded::<Dk>::default();
        enc.copy_from_slice(&self.secret[..]);
        let dk = Dk::from_bytes(&enc);
        enc.as_mut_slice().zeroize();

        // The crate's error type is `()` and is never produced (implicit
        // rejection); map it anyway rather than unwrap.
        let mut ss = dk.decapsulate(&ct_arr).map_err(|_| KemError::Crypto)?;
        drop(dk);
        let mut out = Zeroizing::new([0u8; KEM_SS_LEN]);
        out.copy_from_slice(&ss);
        ss.as_mut_slice().zeroize();
        Ok(out)
    }

    /// Test-only: a key pair from raw FIPS 203 encodings (KAT decaps).
    #[cfg(test)]
    pub(crate) fn from_raw(public: [u8; KEM_PK_LEN], secret: [u8; KEM_SK_LEN]) -> Self {
        Self {
            public,
            secret: Box::new(Zeroizing::new(secret)),
        }
    }

    /// Test-only: the encoded secret key (KAT keygen comparison).
    #[cfg(test)]
    pub(crate) fn secret_bytes(&self) -> &[u8; KEM_SK_LEN] {
        &self.secret
    }
}

/// FIPS 203 §7.2 modulus check: every 12-bit coefficient of `t` is < q.
/// Assumes `pk.len() == KEM_PK_LEN`.
fn ek_is_canonical(pk: &[u8]) -> bool {
    pk[..EK_T_LEN].chunks_exact(3).all(|b| {
        let c0 = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
        let c1 = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
        c0 < Q && c1 < Q
    })
}

/// Checks a received ML-KEM-768 public key: exactly [`KEM_PK_LEN`] bytes and
/// the FIPS 203 §7.2 modulus check. `encapsulate` runs the same check.
pub fn validate_public_key(pk: &[u8]) -> Result<(), KemError> {
    if pk.len() != KEM_PK_LEN {
        return Err(KemError::BadLength);
    }
    if !ek_is_canonical(pk) {
        return Err(KemError::BadKey);
    }
    Ok(())
}

fn parse_ek(pk: &[u8]) -> Result<Ek, KemError> {
    validate_public_key(pk)?;
    let mut enc = Encoded::<Ek>::default();
    enc.copy_from_slice(pk);
    Ok(Ek::from_bytes(&enc))
}

fn finish_encaps(
    result: Result<(ml_kem::Ciphertext<MlKem768>, ml_kem::SharedKey<MlKem768>), ()>,
) -> Result<([u8; KEM_CT_LEN], Zeroizing<[u8; KEM_SS_LEN]>), KemError> {
    let (ct, mut ss) = result.map_err(|_| KemError::Crypto)?;
    let mut ct_out = [0u8; KEM_CT_LEN];
    ct_out.copy_from_slice(&ct);
    let mut ss_out = Zeroizing::new([0u8; KEM_SS_LEN]);
    ss_out.copy_from_slice(&ss);
    ss.as_mut_slice().zeroize();
    Ok((ct_out, ss_out))
}

/// Encapsulates a fresh shared secret to `pk` (FIPS 203 `ML-KEM.Encaps`).
/// Returns the ciphertext and the shared secret.
pub fn encapsulate(pk: &[u8]) -> Result<([u8; KEM_CT_LEN], Zeroizing<[u8; KEM_SS_LEN]>), KemError> {
    let ek = parse_ek(pk)?;
    finish_encaps(ek.encapsulate(&mut OsRng))
}

/// Test-only: encapsulation with fixed randomness `m` (KAT encaps).
#[cfg(test)]
#[allow(clippy::disallowed_methods)] // the one sanctioned caller (KAT only)
pub(crate) fn encapsulate_deterministic(
    pk: &[u8],
    m: &[u8; 32],
) -> Result<([u8; KEM_CT_LEN], Zeroizing<[u8; KEM_SS_LEN]>), KemError> {
    use ml_kem::EncapsulateDeterministic;
    let ek = parse_ek(pk)?;
    let mut m_arr = B32::default();
    m_arr.copy_from_slice(m);
    finish_encaps(ek.encapsulate_deterministic(&m_arr))
}

#[cfg(test)]
mod tests;
