//! Key authentication (spec §4.1): bundle, connection and device-key (D43)
//! signatures, the
//! channel binding, and the deniable knock MAC and intro keys.
//!
//! Every transcript is fixed-length raw bytes. This module has no feature
//! flags; the relay links the same code through the `rchat-core` crate.

use crate::crypto::IdentityKeyPair;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const BUNDLE_DOMAIN: &[u8; 16] = b"rchat/bundle/v1\0";
pub const CONN_DOMAIN: &[u8; 19] = b"rchat/conn-auth/v1\0";
pub const KNOCK_DOMAIN: &[u8; 15] = b"rchat/knock/v1\0";
pub const NO_TLS_BINDING_DOMAIN: &[u8; 29] = b"rchat/conn-binding/no-tls/v1\0";
/// TLS 1.3 exporter label (RFC 8446 §7.5); empty context, 32 bytes.
pub const EXPORTER_LABEL: &[u8; 27] = b"EXPORTER-rchat-conn-auth-v1";
const KNOCK_MAC_INFO: &[u8] = b"rchat/knock-mac/v1";
const INTRO_INFO: &[u8] = b"rchat/intro/v1";

pub const BUNDLE_TRANSCRIPT_LEN: usize = 112;
pub const CONN_TRANSCRIPT_LEN: usize = 243;
pub const KNOCK_MAC_INPUT_LEN: usize = 215;
pub const DK_BIND_MSG_LEN: usize = 118;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyAuthError {
    #[error("wrong length")]
    BadLength,
    /// Weak, low-order, or not a valid key encoding at all (an Ed25519
    /// key that doesn't decode is reported here too: Task 1 minor).
    #[error("weak, low-order or invalid key")]
    WeakKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("bundle does not belong to this identity")]
    IdentityMismatch,
    #[error("non-contributory Diffie-Hellman")]
    NonContributory,
    #[error("MAC does not verify")]
    BadMac,
    #[error("malformed relay origin")]
    BadOrigin,
}

/// A key bundle as signed by its identity key (fixed-size fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle {
    pub identity_key: [u8; 32],
    pub identity_agreement_key: [u8; 32],
    pub signed_pre_key: [u8; 32],
    pub bundle_signature: [u8; 64],
}

impl SignedBundle {
    /// Build from wire slices, checking every length.
    pub fn from_slices(
        identity_key: &[u8],
        identity_agreement_key: &[u8],
        signed_pre_key: &[u8],
        bundle_signature: &[u8],
    ) -> Result<Self, KeyAuthError> {
        Ok(Self {
            identity_key: arr32(identity_key)?,
            identity_agreement_key: arr32(identity_agreement_key)?,
            signed_pre_key: arr32(signed_pre_key)?,
            bundle_signature: bundle_signature
                .try_into()
                .map_err(|_| KeyAuthError::BadLength)?,
        })
    }
}

/// The two keys derived for one knock. Zeroed on drop.
pub struct KnockKeys {
    pub k_mac: [u8; 32],
    pub k_intro: [u8; 32],
}

impl Drop for KnockKeys {
    fn drop(&mut self) {
        self.k_mac.zeroize();
        self.k_intro.zeroize();
    }
}

fn arr32(s: &[u8]) -> Result<[u8; 32], KeyAuthError> {
    s.try_into().map_err(|_| KeyAuthError::BadLength)
}

/// `BUNDLE_DOMAIN || identity_key || identity_agreement_key || signed_pre_key` (112 B).
pub fn bundle_transcript(
    identity_key: &[u8],
    identity_agreement_key: &[u8],
    signed_pre_key: &[u8],
) -> Result<[u8; BUNDLE_TRANSCRIPT_LEN], KeyAuthError> {
    let mut t = [0u8; BUNDLE_TRANSCRIPT_LEN];
    t[..16].copy_from_slice(BUNDLE_DOMAIN);
    t[16..48].copy_from_slice(&arr32(identity_key)?);
    t[48..80].copy_from_slice(&arr32(identity_agreement_key)?);
    t[80..112].copy_from_slice(&arr32(signed_pre_key)?);
    Ok(t)
}

/// `CONN_DOMAIN || nonce || binding || ik || ak || spk || bundle_signature` (243 B).
pub fn conn_transcript(
    nonce: &[u8],
    binding: &[u8],
    bundle: &SignedBundle,
) -> Result<[u8; CONN_TRANSCRIPT_LEN], KeyAuthError> {
    let mut t = [0u8; CONN_TRANSCRIPT_LEN];
    t[..19].copy_from_slice(CONN_DOMAIN);
    t[19..51].copy_from_slice(&arr32(nonce)?);
    t[51..83].copy_from_slice(&arr32(binding)?);
    t[83..115].copy_from_slice(&bundle.identity_key);
    t[115..147].copy_from_slice(&bundle.identity_agreement_key);
    t[147..179].copy_from_slice(&bundle.signed_pre_key);
    t[179..243].copy_from_slice(&bundle.bundle_signature);
    Ok(t)
}

/// Sign this identity's bundle. The signed pre-key is the identity
/// agreement key (one-time pre-keys are not used in v2).
pub fn sign_bundle(identity: &IdentityKeyPair) -> Result<SignedBundle, KeyAuthError> {
    let identity_key = identity.public_signing_key().to_bytes();
    let agreement = identity.public_agreement_key().to_bytes();
    let t = bundle_transcript(&identity_key, &agreement, &agreement)?;
    Ok(SignedBundle {
        identity_key,
        identity_agreement_key: agreement,
        signed_pre_key: agreement,
        bundle_signature: identity.sign(&t).to_bytes(),
    })
}

/// Prove possession of the identity key for this connection.
pub fn sign_conn(
    identity: &IdentityKeyPair,
    nonce: &[u8],
    binding: &[u8],
    bundle: &SignedBundle,
) -> Result<[u8; 64], KeyAuthError> {
    if identity.public_signing_key().to_bytes() != bundle.identity_key {
        return Err(KeyAuthError::IdentityMismatch);
    }
    let t = conn_transcript(nonce, binding, bundle)?;
    Ok(identity.sign(&t).to_bytes())
}

fn verifying_key(identity_key: &[u8; 32]) -> Result<VerifyingKey, KeyAuthError> {
    let vk = VerifyingKey::from_bytes(identity_key).map_err(|_| KeyAuthError::WeakKey)?;
    if vk.is_weak() {
        return Err(KeyAuthError::WeakKey);
    }
    Ok(vk)
}

/// True for the all-zero key and every other low-order X25519 point: a
/// clamped scalar times such a point is the identity, i.e. not contributory.
pub fn is_low_order_x25519(public: &[u8; 32]) -> bool {
    let probe = StaticSecret::from([1u8; 32]);
    !probe
        .diffie_hellman(&X25519PublicKey::from(*public))
        .was_contributory()
}

/// Check a bundle: strong Ed25519 identity, contributory X25519 keys, and a
/// strict signature over the bundle transcript.
pub fn verify_bundle(bundle: &SignedBundle) -> Result<(), KeyAuthError> {
    let vk = verifying_key(&bundle.identity_key)?;
    if is_low_order_x25519(&bundle.identity_agreement_key)
        || is_low_order_x25519(&bundle.signed_pre_key)
    {
        return Err(KeyAuthError::WeakKey);
    }
    let t = bundle_transcript(
        &bundle.identity_key,
        &bundle.identity_agreement_key,
        &bundle.signed_pre_key,
    )?;
    vk.verify_strict(&t, &Signature::from_bytes(&bundle.bundle_signature))
        .map_err(|_| KeyAuthError::BadSignature)
}

/// Check a connection proof (run `verify_bundle` first).
pub fn verify_conn(
    nonce: &[u8],
    binding: &[u8],
    bundle: &SignedBundle,
    sig: &[u8],
) -> Result<(), KeyAuthError> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| KeyAuthError::BadLength)?;
    let vk = verifying_key(&bundle.identity_key)?;
    let t = conn_transcript(nonce, binding, bundle)?;
    vk.verify_strict(&t, &Signature::from_bytes(&sig))
        .map_err(|_| KeyAuthError::BadSignature)
}

/// `DK_DOMAIN || identity_key || dk_pub || hardware` (118 B, spec D43).
pub fn dk_bind_msg(
    identity_key: &[u8; 32],
    dk_pub: &[u8; 65],
    hardware: bool,
) -> [u8; DK_BIND_MSG_LEN] {
    let mut m = [0u8; DK_BIND_MSG_LEN];
    m[..20].copy_from_slice(crate::device_key::DK_DOMAIN);
    m[20..52].copy_from_slice(identity_key);
    m[52..117].copy_from_slice(dk_pub);
    m[117] = u8::from(hardware);
    m
}

/// Bind this install's device key to the identity (D43): the card's `dks`.
/// A `dk_pub` that is not a SEC1 uncompressed P-256 point is refused.
pub fn sign_device_key(
    identity: &IdentityKeyPair,
    dk_pub: &[u8; 65],
    hardware: bool,
) -> Result<[u8; 64], KeyAuthError> {
    if !crate::device_key::is_valid_dk_pub(dk_pub) {
        return Err(KeyAuthError::WeakKey);
    }
    let ik = identity.public_signing_key().to_bytes();
    Ok(identity
        .sign(&dk_bind_msg(&ik, dk_pub, hardware))
        .to_bytes())
}

/// Check a contact's device key binding (`dks`) under their identity key:
/// a strong Ed25519 key, a valid P-256 point and a strict signature.
pub fn verify_device_key(
    identity_key: &[u8; 32],
    dk_pub: &[u8; 65],
    hardware: bool,
    sig: &[u8; 64],
) -> Result<(), KeyAuthError> {
    let vk = verifying_key(identity_key)?;
    if !crate::device_key::is_valid_dk_pub(dk_pub) {
        return Err(KeyAuthError::WeakKey);
    }
    vk.verify_strict(
        &dk_bind_msg(identity_key, dk_pub, hardware),
        &Signature::from_bytes(sig),
    )
    .map_err(|_| KeyAuthError::BadSignature)
}

/// X25519 that refuses a non-contributory result (L1). Used for every DH;
/// the output is wiped when dropped.
pub fn dh_checked(
    secret: &StaticSecret,
    public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KeyAuthError> {
    let shared = secret.diffie_hellman(&X25519PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(KeyAuthError::NonContributory);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// HKDF-SHA256 whose secret state is wiped once `f` is done with it
/// (Task 1 minor, completion review L1). The hkdf crate implements no
/// `Zeroize`, and its `expand` builds a fresh HMAC from the PRK-keyed core
/// for every output block, in its own stack frame. So: the long-lived
/// instance is zeroed in place (`wipe_hkdf`), and the stack those calls used
/// is overwritten afterwards (`scrub_stack`), which reaches the per-block
/// copies and the hash temporaries below them. Best effort: the compiler
/// may still have kept a value in a register or another stack slot.
pub(crate) fn with_hkdf<R>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    f: impl FnOnce(&Hkdf<Sha256>) -> R,
) -> R {
    let mut hk = Hkdf::<Sha256>::new(salt, ikm);
    let out = run_below(&hk, f);
    wipe_hkdf(&mut hk);
    scrub_stack();
    out
}

/// Runs `f` in its own frame below `with_hkdf`'s, so the HMAC copies it
/// leaves behind sit where `scrub_stack`'s buffer, at the same depth, lands.
#[inline(never)]
fn run_below<R>(hk: &Hkdf<Sha256>, f: impl FnOnce(&Hkdf<Sha256>) -> R) -> R {
    f(hk)
}

/// The byte size of `Hkdf<Sha256>` this wipe was reviewed for: three SHA-256
/// cores (`[u32; 8]` state + `u64` block count each), nothing else. hmac's
/// `reset` feature, which `p256` enables (ecdsa signing → rfc6979, Task 6b),
/// adds the third, `ipad_digest`, a PRK-keyed core like the other two. A
/// dependency bump that changes it fails to build.
pub(crate) const HKDF_SHA256_REVIEWED_SIZE: usize = 3 * (8 * 4 + 8);
// A layout change is a build error, not silent UB in `wipe_hkdf`.
const _: () = assert!(std::mem::size_of::<Hkdf<Sha256>>() == HKDF_SHA256_REVIEWED_SIZE);
const _: () = assert!(!std::mem::needs_drop::<Hkdf<Sha256>>());

/// Zero an HKDF-SHA256 instance in place. Not generic on purpose
/// (completion review L1): zeroing is only valid for a type made of plain
/// integers, which this one is (see `HKDF_SHA256_REVIEWED_SIZE`).
fn wipe_hkdf(hk: &mut Hkdf<Sha256>) {
    // SAFETY: `Hkdf<Sha256>` (hkdf 0.12 / hmac 0.12 / sha2 0.10) is
    // `HmacCore<Sha256>`: three `Sha256VarCore { state: [u32; 8],
    // block_len: u64 }` (`digest`, `opad_digest` and, with hmac's `reset`
    // feature, `ipad_digest`) and a `PhantomData`. No references, niches, enums or drop glue,
    // so all-zero bytes are a valid value, as `zeroize_flat_type` requires;
    // the layout is pinned by `hkdf_layout_is_the_reviewed_one`.
    unsafe { zeroize::zeroize_flat_type(hk as *mut Hkdf<Sha256>) }
}

/// Overwrite the stack below the caller's frame with zeros, where the
/// frames of the call just finished lived (completion review L1: the HMAC
/// copies `Hkdf::expand` makes). 16 KiB covers HKDF's frames many times.
#[inline(never)]
pub(crate) fn scrub_stack() {
    const SCRUB: usize = 16 * 1024;
    let mut buf = std::mem::MaybeUninit::<[u8; SCRUB]>::uninit();
    let p = buf.as_mut_ptr().cast::<u8>();
    for i in 0..SCRUB {
        // SAFETY: writing (never reading) bytes of a local buffer we own.
        unsafe { std::ptr::write_volatile(p.add(i), 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    std::hint::black_box(&mut buf);
}

/// `k_mac` and `k_intro` from the static-static DH, salted with the
/// envelope's ephemeral key. Both sides pass (sender, recipient) in that
/// order; the recipient's DH is the mirror of the sender's.
pub fn knock_keys(
    my_agreement_secret: &StaticSecret,
    their_agreement_key: &[u8; 32],
    env_eph_pub: &[u8; 32],
    sender_identity_key: &[u8; 32],
    recipient_identity_key: &[u8; 32],
) -> Result<KnockKeys, KeyAuthError> {
    let ss = dh_checked(my_agreement_secret, their_agreement_key)?;
    let mut keys = KnockKeys {
        k_mac: [0u8; 32],
        k_intro: [0u8; 32],
    };
    with_hkdf(Some(env_eph_pub), &*ss, |hk| {
        let mut info = Vec::with_capacity(KNOCK_MAC_INFO.len() + 64);
        info.extend_from_slice(KNOCK_MAC_INFO);
        info.extend_from_slice(sender_identity_key);
        info.extend_from_slice(recipient_identity_key);
        hk.expand(&info, &mut keys.k_mac)
            .expect("32-byte HKDF output");
        info.clear();
        info.extend_from_slice(INTRO_INFO);
        info.extend_from_slice(sender_identity_key);
        info.extend_from_slice(recipient_identity_key);
        hk.expand(&info, &mut keys.k_intro)
            .expect("32-byte HKDF output");
    });
    Ok(keys)
}

/// `KNOCK_DOMAIN || recipient_ik || sender_ik || ak || spk || sig || issued_hour BE` (215 B).
pub fn knock_mac_input(
    recipient_identity_key: &[u8; 32],
    sender: &SignedBundle,
    issued_hour: u64,
) -> [u8; KNOCK_MAC_INPUT_LEN] {
    let mut m = [0u8; KNOCK_MAC_INPUT_LEN];
    m[..15].copy_from_slice(KNOCK_DOMAIN);
    m[15..47].copy_from_slice(recipient_identity_key);
    m[47..79].copy_from_slice(&sender.identity_key);
    m[79..111].copy_from_slice(&sender.identity_agreement_key);
    m[111..143].copy_from_slice(&sender.signed_pre_key);
    m[143..207].copy_from_slice(&sender.bundle_signature);
    m[207..215].copy_from_slice(&issued_hour.to_be_bytes());
    m
}

type HmacSha256 = Hmac<Sha256>;

pub fn knock_mac(
    k_mac: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    sender: &SignedBundle,
    issued_hour: u64,
) -> Result<[u8; 32], KeyAuthError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(k_mac).map_err(|_| KeyAuthError::BadLength)?;
    mac.update(&knock_mac_input(
        recipient_identity_key,
        sender,
        issued_hour,
    ));
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time check of a knock MAC.
pub fn verify_knock_mac(
    k_mac: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    sender: &SignedBundle,
    issued_hour: u64,
    tag: &[u8],
) -> Result<(), KeyAuthError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(k_mac).map_err(|_| KeyAuthError::BadLength)?;
    mac.update(&knock_mac_input(
        recipient_identity_key,
        sender,
        issued_hour,
    ));
    mac.verify_slice(tag).map_err(|_| KeyAuthError::BadMac)
}

/// `--no-tls` dev binding: BLAKE3(NO_TLS_BINDING_DOMAIN || origin). Not a
/// channel binding; it only stops replay to a relay with another origin.
pub fn dev_origin_binding(origin: &str) -> Result<[u8; 32], KeyAuthError> {
    if origin.is_empty() {
        return Err(KeyAuthError::BadOrigin);
    }
    let mut h = blake3::Hasher::new();
    h.update(NO_TLS_BINDING_DOMAIN);
    h.update(origin.as_bytes());
    Ok(*h.finalize().as_bytes())
}

/// Lowercase `scheme://host:port` of a relay URL (path dropped, default
/// port filled in). Client and relay both normalise through this.
pub fn relay_origin(server_url: &str) -> Result<String, KeyAuthError> {
    let uri: tokio_tungstenite::tungstenite::http::Uri = server_url
        .trim()
        .parse()
        .map_err(|_| KeyAuthError::BadOrigin)?;
    let scheme = uri
        .scheme_str()
        .ok_or(KeyAuthError::BadOrigin)?
        .to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "ws" | "http" => 80,
        "wss" | "https" => 443,
        _ => return Err(KeyAuthError::BadOrigin),
    };
    let host = uri
        .host()
        .ok_or(KeyAuthError::BadOrigin)?
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(KeyAuthError::BadOrigin);
    }
    let port = uri.port_u16().unwrap_or(default_port);
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Fixed inputs for the golden vectors (K1). Shared with the relay's test.
#[doc(hidden)]
pub mod golden {
    /// Identity seed A: bytes 0x00..=0x3f.
    pub fn seed_a() -> [u8; 64] {
        core::array::from_fn(|i| i as u8)
    }
    /// Identity seed B: bytes 0x40..=0x7f.
    pub fn seed_b() -> [u8; 64] {
        core::array::from_fn(|i| 0x40 + i as u8)
    }
    pub const NONCE: [u8; 32] = [0x4e; 32];
    pub const BINDING: [u8; 32] = [0x42; 32];
    /// Envelope ephemeral secret for the knock vectors.
    pub const ENV_EPH_SECRET: [u8; 32] = [0x45; 32];
    pub const ISSUED_HOUR: u64 = 486_000;
}

#[cfg(test)]
mod tests;
