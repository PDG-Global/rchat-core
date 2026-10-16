//! Key authentication (spec §4.1): bundle, connection and device-key (D43)
//! signatures, the
//! channel binding, and the deniable knock MAC and intro keys.
//!
//! Every transcript is fixed-length raw bytes. This module has no feature
//! flags; the relay links the same code through the `rchat-core` crate.

use crate::crypto::IdentityKeyPair;
use crate::kem::{self, KEM_PK_LEN};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const BUNDLE_DOMAIN_V3: &[u8; 16] = b"rchat/bundle/v3\0";
pub const CONN_DOMAIN: &[u8; 19] = b"rchat/conn-auth/v3\0";
pub const KNOCK_DOMAIN: &[u8; 15] = b"rchat/knock/v3\0";
pub const NO_TLS_BINDING_DOMAIN: &[u8; 29] = b"rchat/conn-binding/no-tls/v1\0";
/// TLS 1.3 exporter label (RFC 8446 §7.5); empty context, 32 bytes.
pub const EXPORTER_LABEL: &[u8; 27] = b"EXPORTER-rchat-conn-auth-v1";
/// HKDF info prefix of the knock v3 keys (§A.5); both identities follow.
const KNOCK_KEYS_INFO_V3: &[u8] = b"rchat/knock/v3";

/// `BUNDLE_DOMAIN_V3 || ik(32) || ak(32) || kem_pk(1184)` (protocol v3 §A.2).
pub const BUNDLE_TRANSCRIPT_LEN_V3: usize = 16 + 32 + 32 + KEM_PK_LEN;
pub const CONN_TRANSCRIPT_LEN: usize = 211;
pub const KNOCK_MAC_INPUT_LEN: usize = 183;
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

/// A v3 key bundle as signed by its identity key (protocol v3 §A.2):
/// fixed-size fields, no signed pre-key (it always equalled `ak` in v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle {
    pub identity_key: [u8; 32],
    pub identity_agreement_key: [u8; 32],
    /// ML-KEM-768 public key; boxed so the bundle stays cheap to move.
    pub kem_pk: Box<[u8; KEM_PK_LEN]>,
    pub bundle_signature: [u8; 64],
}

impl SignedBundle {
    /// Build from wire bytes, checking every length (`kem_pk` exactly 1184).
    pub fn from_wire(
        identity_key: &[u8],
        identity_agreement_key: &[u8],
        kem_pk: &[u8],
        bundle_signature: &[u8],
    ) -> Result<Self, KeyAuthError> {
        if kem_pk.len() != KEM_PK_LEN {
            return Err(KeyAuthError::BadLength);
        }
        let mut boxed = Box::new([0u8; KEM_PK_LEN]);
        boxed.copy_from_slice(kem_pk);
        Ok(Self {
            identity_key: arr32(identity_key)?,
            identity_agreement_key: arr32(identity_agreement_key)?,
            kem_pk: boxed,
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

/// `BUNDLE_DOMAIN_V3 || ik || ak || kem_pk` (1264 B, protocol v3 §A.2).
pub fn bundle_transcript(
    ik: &[u8; 32],
    ak: &[u8; 32],
    kem_pk: &[u8; KEM_PK_LEN],
) -> [u8; BUNDLE_TRANSCRIPT_LEN_V3] {
    let mut t = [0u8; BUNDLE_TRANSCRIPT_LEN_V3];
    t[..16].copy_from_slice(BUNDLE_DOMAIN_V3);
    t[16..48].copy_from_slice(ik);
    t[48..80].copy_from_slice(ak);
    t[80..].copy_from_slice(kem_pk);
    t
}

/// `CONN_DOMAIN || nonce || binding || ik || ak || bundle_signature` (211 B).
/// `kem_pk` is bound through `bundle_signature`, which signs it.
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
    t[147..211].copy_from_slice(&bundle.bundle_signature);
    Ok(t)
}

/// Sign this identity's v3 bundle: `ik`, `ak` and the identity's ML-KEM key.
pub fn sign_bundle(identity: &IdentityKeyPair) -> Result<SignedBundle, KeyAuthError> {
    let identity_key = identity.public_signing_key().to_bytes();
    let agreement = identity.public_agreement_key().to_bytes();
    let kem_pk = Box::new(*identity.kem_public());
    let t = bundle_transcript(&identity_key, &agreement, &kem_pk);
    Ok(SignedBundle {
        identity_key,
        identity_agreement_key: agreement,
        kem_pk,
        bundle_signature: identity.sign(&t).to_bytes(),
    })
}

/// Domain of an ask's signature over its own ephemerals (ruling R7,
/// PQXDH-style): without it a relay could hand the initiator its own KEM
/// key as the responder's and decapsulate the post-quantum half.
pub const ASK_EPH_DOMAIN: &[u8; 17] = b"rchat/ask-eph/v3\0";
/// `ASK_EPH_DOMAIN || asker_ik(32) || ephemeral_key(32) || kem_ephemeral_pk(1184)`.
pub const ASK_EPH_TRANSCRIPT_LEN: usize = 17 + 32 + 32 + kem::KEM_PK_LEN;

/// The transcript an ask's ephemeral signature covers.
pub fn ask_eph_transcript(
    asker_ik: &[u8; 32],
    ephemeral_key: &[u8; 32],
    kem_ephemeral_pk: &[u8; kem::KEM_PK_LEN],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(ASK_EPH_TRANSCRIPT_LEN);
    t.extend_from_slice(ASK_EPH_DOMAIN);
    t.extend_from_slice(asker_ik);
    t.extend_from_slice(ephemeral_key);
    t.extend_from_slice(kem_ephemeral_pk);
    t
}

/// Sign an ask's X25519 and ML-KEM ephemerals with the identity key (R7).
pub fn sign_ask_ephemerals(
    identity: &IdentityKeyPair,
    ephemeral_key: &[u8; 32],
    kem_ephemeral_pk: &[u8; kem::KEM_PK_LEN],
) -> [u8; 64] {
    let ik = identity.public_signing_key().to_bytes();
    identity
        .sign(&ask_eph_transcript(&ik, ephemeral_key, kem_ephemeral_pk))
        .to_bytes()
}

/// Check a peer ask's ephemeral signature under the peer's pinned identity
/// key (`verify_strict`, as for bundles). A wrong-length signature is
/// `BadLength`.
pub fn verify_ask_ephemerals(
    asker_ik: &[u8; 32],
    ephemeral_key: &[u8; 32],
    kem_ephemeral_pk: &[u8],
    sig: &[u8],
) -> Result<(), KeyAuthError> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| KeyAuthError::BadLength)?;
    let kem_pk: &[u8; kem::KEM_PK_LEN] = kem_ephemeral_pk
        .try_into()
        .map_err(|_| KeyAuthError::BadLength)?;
    let vk = verifying_key(asker_ik)?;
    vk.verify_strict(
        &ask_eph_transcript(asker_ik, ephemeral_key, kem_pk),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| KeyAuthError::BadSignature)
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

/// Check a v3 bundle: strong Ed25519 identity, a contributory X25519
/// agreement key, a well-formed ML-KEM-768 key (length and FIPS 203 modulus)
/// and a strict signature over the v3 transcript.
pub fn verify_bundle(bundle: &SignedBundle) -> Result<(), KeyAuthError> {
    let vk = verifying_key(&bundle.identity_key)?;
    if is_low_order_x25519(&bundle.identity_agreement_key) {
        return Err(KeyAuthError::WeakKey);
    }
    kem::validate_public_key(&bundle.kem_pk[..]).map_err(|e| match e {
        kem::KemError::BadLength => KeyAuthError::BadLength,
        _ => KeyAuthError::WeakKey,
    })?;
    let t = bundle_transcript(
        &bundle.identity_key,
        &bundle.identity_agreement_key,
        &bundle.kem_pk,
    );
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

/// Which side of a knock is deriving its keys. The two sides compute the
/// same static DH from opposite ends; the salt names the recipient's
/// agreement key, which the sender has as `their_ak` and the recipient as
/// its own public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnockRole {
    Sender,
    Recipient,
}

/// Knock v3 keys (§A.5): `k_mac || k_intro` = HKDF-SHA256(
/// salt = env_eph_pub || recipient_ak, ikm = DH_static || kem_ss,
/// info = "rchat/knock/v3" || sender_ik || recipient_ik), 64 bytes.
/// `kem_ss` is the ML-KEM-768 secret encapsulated to the recipient's static
/// KEM key (`ct_k` in the knock). Both sides pass (sender, recipient)
/// identities in that order. The DH result and the combined input are
/// wiped when this returns; the keys are wiped when `KnockKeys` drops.
pub fn knock_keys_v3(
    my_ak_secret: &StaticSecret,
    their_ak: &[u8; 32],
    env_eph_pub: &[u8; 32],
    kem_ss: &[u8; 32],
    sender_identity_key: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    role: KnockRole,
) -> Result<KnockKeys, KeyAuthError> {
    let dh = dh_checked(my_ak_secret, their_ak)?;
    let recipient_ak = match role {
        KnockRole::Sender => *their_ak,
        KnockRole::Recipient => X25519PublicKey::from(my_ak_secret).to_bytes(),
    };
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(env_eph_pub);
    salt[32..].copy_from_slice(&recipient_ak);
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&*dh);
    ikm[32..].copy_from_slice(kem_ss);
    let mut info = [0u8; KNOCK_KEYS_INFO_V3.len() + 64];
    info[..KNOCK_KEYS_INFO_V3.len()].copy_from_slice(KNOCK_KEYS_INFO_V3);
    info[KNOCK_KEYS_INFO_V3.len()..KNOCK_KEYS_INFO_V3.len() + 32]
        .copy_from_slice(sender_identity_key);
    info[KNOCK_KEYS_INFO_V3.len() + 32..].copy_from_slice(recipient_identity_key);
    let mut okm = Zeroizing::new([0u8; 64]);
    with_hkdf(Some(&salt), &ikm[..], |hk| {
        hk.expand(&info, &mut okm[..]).expect("64-byte HKDF output")
    });
    let mut keys = KnockKeys {
        k_mac: [0u8; 32],
        k_intro: [0u8; 32],
    };
    keys.k_mac.copy_from_slice(&okm[..32]);
    keys.k_intro.copy_from_slice(&okm[32..]);
    Ok(keys)
}

/// `KNOCK_DOMAIN || recipient_ik || sender_ik || ak || sig || issued_hour BE` (183 B).
/// The sender's `kem_pk` is bound through `sig`, which signs it.
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
    m[111..175].copy_from_slice(&sender.bundle_signature);
    m[175..183].copy_from_slice(&issued_hour.to_be_bytes());
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

/// `knock_mac` over the knock's flags too (protocol v3 §A.5, ruling R35):
/// flags 0 is exactly `knock_mac`; any other flags byte is appended to the
/// MAC input, so a relay can neither set nor clear one.
pub fn knock_mac_flagged(
    k_mac: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    sender: &SignedBundle,
    issued_hour: u64,
    flags: u8,
) -> Result<[u8; 32], KeyAuthError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(k_mac).map_err(|_| KeyAuthError::BadLength)?;
    mac.update(&knock_mac_input(
        recipient_identity_key,
        sender,
        issued_hour,
    ));
    if flags != 0 {
        mac.update(&[flags]);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time check of a flagged knock MAC (`knock_mac_flagged`).
pub fn verify_knock_mac_flagged(
    k_mac: &[u8; 32],
    recipient_identity_key: &[u8; 32],
    sender: &SignedBundle,
    issued_hour: u64,
    flags: u8,
    tag: &[u8],
) -> Result<(), KeyAuthError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(k_mac).map_err(|_| KeyAuthError::BadLength)?;
    mac.update(&knock_mac_input(
        recipient_identity_key,
        sender,
        issued_hour,
    ));
    if flags != 0 {
        mac.update(&[flags]);
    }
    mac.verify_slice(tag).map_err(|_| KeyAuthError::BadMac)
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
