//! Relay identity pins and proofs (spec §4.9). Pure functions shared by the
//! relay (signing) and the client (verification).

use constant_time_eq::constant_time_eq;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const RELAY_AUTH_DOMAIN: &[u8; 20] = b"rchat/relay-auth/v1\0";
pub const RELAY_ROTATE_DOMAIN: &[u8; 22] = b"rchat/relay-rotate/v1\0";
pub const RELAY_AUTH_TRANSCRIPT_LEN: usize = 120;
pub const MAX_RELAY_CHAIN: usize = 3;
const PIN_PREFIX: &str = "rk:1:";
const PIN_BODY_LEN: usize = 52;
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayPinError {
    #[error("malformed relay pin")]
    BadPin,
    #[error("invalid relay key")]
    BadKey,
    #[error("relay signature does not verify")]
    BadSignature,
    #[error("relay rotation chain does not verify")]
    BadChain,
}

fn base32_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode_lower(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `rk:1:` + base32-lowercase-no-pad(SHA-256(relay_key)).
pub fn encode_pin(relay_key: &[u8; 32]) -> String {
    format!("{PIN_PREFIX}{}", base32_lower(&Sha256::digest(relay_key)))
}

/// The SHA-256 a pin carries. The body's letter case is ignored; the prefix
/// must be exactly `rk:1:`.
pub fn parse_pin(pin: &str) -> Result<[u8; 32], RelayPinError> {
    let body = pin
        .strip_prefix(PIN_PREFIX)
        .ok_or(RelayPinError::BadPin)?
        .to_ascii_lowercase();
    if body.len() != PIN_BODY_LEN {
        return Err(RelayPinError::BadPin);
    }
    let raw = base32_decode_lower(&body).ok_or(RelayPinError::BadPin)?;
    let hash: [u8; 32] = raw
        .get(..32)
        .and_then(|b| b.try_into().ok())
        .ok_or(RelayPinError::BadPin)?;
    // Canonical form only: the trailing pad bits must be zero.
    if base32_lower(&hash) != body {
        return Err(RelayPinError::BadPin);
    }
    Ok(hash)
}

/// Does `pin` name `relay_key`? Constant time over the hashes.
pub fn pin_matches(pin: &str, relay_key: &[u8; 32]) -> bool {
    match parse_pin(pin) {
        Ok(hash) => constant_time_eq(&hash, Sha256::digest(relay_key).as_slice()),
        Err(_) => false,
    }
}

pub fn relay_auth_transcript(
    binding: &[u8; 32],
    challenge: &[u8; 32],
    relay_key: &[u8; 32],
    version: u32,
) -> [u8; 120] {
    let mut t = [0u8; RELAY_AUTH_TRANSCRIPT_LEN];
    t[..20].copy_from_slice(RELAY_AUTH_DOMAIN);
    t[20..52].copy_from_slice(binding);
    t[52..84].copy_from_slice(challenge);
    t[84..116].copy_from_slice(relay_key);
    t[116..].copy_from_slice(&version.to_be_bytes());
    t
}

pub fn sign_relay_auth(
    sk: &SigningKey,
    binding: &[u8; 32],
    challenge: &[u8; 32],
    version: u32,
) -> [u8; 64] {
    let key = sk.verifying_key().to_bytes();
    sk.sign(&relay_auth_transcript(binding, challenge, &key, version))
        .to_bytes()
}

fn verifying_key(key: &[u8; 32]) -> Result<VerifyingKey, RelayPinError> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| RelayPinError::BadKey)?;
    if vk.is_weak() {
        return Err(RelayPinError::BadKey);
    }
    Ok(vk)
}

pub fn verify_relay_auth(
    relay_key: &[u8; 32],
    binding: &[u8; 32],
    challenge: &[u8; 32],
    version: u32,
    sig: &[u8; 64],
) -> Result<(), RelayPinError> {
    verifying_key(relay_key)?
        .verify_strict(
            &relay_auth_transcript(binding, challenge, relay_key, version),
            &Signature::from_bytes(sig),
        )
        .map_err(|_| RelayPinError::BadSignature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub prev_key: [u8; 32],
    pub new_key: [u8; 32],
    pub version: u32,
    pub signature: [u8; 64],
}

fn link_message(new_key: &[u8; 32], version: u32) -> [u8; 58] {
    let mut m = [0u8; 58];
    m[..22].copy_from_slice(RELAY_ROTATE_DOMAIN);
    m[22..54].copy_from_slice(new_key);
    m[54..].copy_from_slice(&version.to_be_bytes());
    m
}

pub fn sign_relay_link(prev: &SigningKey, new_key: &[u8; 32], version: u32) -> RelayLink {
    RelayLink {
        prev_key: prev.verifying_key().to_bytes(),
        new_key: *new_key,
        version,
        signature: prev.sign(&link_message(new_key, version)).to_bytes(),
    }
}

pub fn verify_relay_link(link: &RelayLink) -> Result<(), RelayPinError> {
    verifying_key(&link.new_key)?;
    verifying_key(&link.prev_key)?
        .verify_strict(
            &link_message(&link.new_key, link.version),
            &Signature::from_bytes(&link.signature),
        )
        .map_err(|_| RelayPinError::BadChain)
}

/// Spec §4.9: some link starts at the pinned key with version `pinned + 1`,
/// every later link continues it (+1 each), and the last one names the
/// presented key and version. At most `MAX_RELAY_CHAIN` links.
pub fn walk_relay_chain(
    links: &[RelayLink],
    pinned: &str,
    pinned_version: u32,
    presented_key: &[u8; 32],
    presented_version: u32,
) -> Result<(), RelayPinError> {
    if links.is_empty() || links.len() > MAX_RELAY_CHAIN {
        return Err(RelayPinError::BadChain);
    }
    let start = links
        .iter()
        .position(|l| {
            pin_matches(pinned, &l.prev_key) && Some(l.version) == pinned_version.checked_add(1)
        })
        .ok_or(RelayPinError::BadChain)?;
    let mut prev: Option<&RelayLink> = None;
    for link in &links[start..] {
        if let Some(p) = prev {
            if link.prev_key != p.new_key || Some(link.version) != p.version.checked_add(1) {
                return Err(RelayPinError::BadChain);
            }
        }
        verify_relay_link(link).map_err(|_| RelayPinError::BadChain)?;
        prev = Some(link);
    }
    let last = prev.ok_or(RelayPinError::BadChain)?;
    if last.new_key != *presented_key || last.version != presented_version {
        return Err(RelayPinError::BadChain);
    }
    Ok(())
}

/// What a relay presents in `hello_response.relay_identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIdentityOffer {
    pub key: [u8; 32],
    pub version: u32,
    pub signature: [u8; 64],
    pub chain: Vec<RelayLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    Tofu,
    Pinned,
    Rotated,
}

impl PinSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PinSource::Tofu => "tofu",
            PinSource::Pinned => "pinned",
            PinSource::Rotated => "rotated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinOutcome {
    pub pin: String,
    pub version: u32,
    pub source: PinSource,
    /// The saved pin this outcome was checked against (None for TOFU), so
    /// the app carries trust only from that pin, not from whatever is
    /// saved by the time it stores the result (Task 20e triage).
    pub from: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPinFailure {
    /// Missing/malformed identity or a signature that doesn't bind this connection.
    Invalid,
    /// Strict mode and no saved pin.
    Required,
    /// The key differs from the pin and no valid chain links them.
    Changed,
}

/// Spec §4.9 client table. Never falls back to TOFU once a pin is held.
///
/// `pinned` carries the saved pin and its version. The version is `None`
/// when unknown (a pin the user entered without the version printed next to
/// it): a matching key then adopts the relay's presented version, which the
/// pinned key itself signed over this connection, and a rotation chain is
/// walked from the link the pinned key signed.
pub fn decide(
    offer: &RelayIdentityOffer,
    binding: &[u8; 32],
    challenge: &[u8; 32],
    pinned: Option<(&str, Option<u32>)>,
    strict: bool,
) -> Result<PinOutcome, RelayPinFailure> {
    verify_relay_auth(
        &offer.key,
        binding,
        challenge,
        offer.version,
        &offer.signature,
    )
    .map_err(|_| RelayPinFailure::Invalid)?;
    let pin = encode_pin(&offer.key);
    match pinned {
        None if strict => Err(RelayPinFailure::Required),
        None => Ok(PinOutcome {
            pin,
            version: offer.version,
            source: PinSource::Tofu,
            from: None,
        }),
        // Round-2 L6: same key -> keep the pinned version; versions advance
        // only through chain steps. An unknown version is learned from the
        // pinned key's own signature.
        Some((saved, saved_version)) if pin_matches(saved, &offer.key) => Ok(PinOutcome {
            pin,
            version: saved_version.unwrap_or(offer.version),
            source: PinSource::Pinned,
            from: Some(saved.to_string()),
        }),
        Some((saved, saved_version)) => {
            let base = match saved_version {
                Some(v) => v,
                None => offer
                    .chain
                    .iter()
                    .find(|l| pin_matches(saved, &l.prev_key))
                    .and_then(|l| l.version.checked_sub(1))
                    .ok_or(RelayPinFailure::Changed)?,
            };
            walk_relay_chain(&offer.chain, saved, base, &offer.key, offer.version)
                .map_err(|_| RelayPinFailure::Changed)?;
            Ok(PinOutcome {
                pin,
                version: offer.version,
                source: PinSource::Rotated,
                from: Some(saved.to_string()),
            })
        }
    }
}

/// Round-2 L2: the one definition of a relay origin used to key pins.
/// `scheme://host:port`: scheme ws/wss/http/https (lowercased), host
/// lowercased without a trailing dot, IP literals in their canonical form
/// (IPv6 stays bracketed), port explicit
/// or the scheme default; path, query and fragment dropped. Non-ASCII hosts
/// are refused (punycode A-labels only), as is userinfo.
pub fn canonical_origin(server_url: &str) -> Result<String, RelayPinError> {
    let s = server_url.trim();
    if !s.is_ascii() {
        return Err(RelayPinError::BadPin);
    }
    let uri: tokio_tungstenite::tungstenite::http::Uri =
        s.parse().map_err(|_| RelayPinError::BadPin)?;
    let scheme = uri
        .scheme_str()
        .ok_or(RelayPinError::BadPin)?
        .to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "ws" | "http" => 80,
        "wss" | "https" => 443,
        _ => return Err(RelayPinError::BadPin),
    };
    let authority = uri.authority().ok_or(RelayPinError::BadPin)?;
    if authority.as_str().contains('@') {
        return Err(RelayPinError::BadPin);
    }
    let mut host = uri
        .host()
        .ok_or(RelayPinError::BadPin)?
        .to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.ends_with('.') {
        return Err(RelayPinError::BadPin);
    }
    // One spelling per IP literal: `[0:0::1]` and `[::1]` are one origin.
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let addr: std::net::Ipv6Addr = v6.parse().map_err(|_| RelayPinError::BadPin)?;
        host = format!("[{addr}]");
    } else if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        host = v4.to_string();
    }
    let port = uri.port_u16().unwrap_or(default_port);
    Ok(format!("{scheme}://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    /// RP1: golden pin and parse round-trip.
    #[test]
    fn rp1_pin_golden_and_round_trip() {
        let key = [0x5a; 32];
        let pin = encode_pin(&key);
        assert_eq!(
            pin,
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia"
        );
        assert!(pin_matches(&pin, &key));
        assert!(!pin_matches(&pin, &[0x5b; 32]));
        assert!(parse_pin(&pin).is_ok());
        assert_eq!(
            parse_pin("rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcib"),
            Err(RelayPinError::BadPin),
            "non-zero pad bits"
        );
        assert!(
            parse_pin(&pin.to_uppercase().replacen("RK:", "rk:", 1)).is_ok(),
            "body case is ignored"
        );
        for bad in [
            "",
            "ik:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia",
            "rk:2:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia",
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdci",
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdci1",
        ] {
            assert_eq!(parse_pin(bad), Err(RelayPinError::BadPin), "{bad}");
        }
    }

    /// RP2: the relay signature is bound to binding, challenge, key and version.
    #[test]
    fn rp2_relay_auth_binds_binding_challenge_and_version() {
        let s = sk(7);
        let key = s.verifying_key().to_bytes();
        let sig = sign_relay_auth(&s, &[1; 32], &[2; 32], 3);
        assert!(verify_relay_auth(&key, &[1; 32], &[2; 32], 3, &sig).is_ok());
        assert_eq!(
            verify_relay_auth(&key, &[9; 32], &[2; 32], 3, &sig),
            Err(RelayPinError::BadSignature)
        );
        assert_eq!(
            verify_relay_auth(&key, &[1; 32], &[9; 32], 3, &sig),
            Err(RelayPinError::BadSignature)
        );
        assert_eq!(
            verify_relay_auth(&key, &[1; 32], &[2; 32], 4, &sig),
            Err(RelayPinError::BadSignature)
        );
        let t = relay_auth_transcript(&[1; 32], &[2; 32], &key, 3);
        assert_eq!(t.len(), RELAY_AUTH_TRANSCRIPT_LEN);
        assert_eq!(&t[..20], RELAY_AUTH_DOMAIN);
        assert_eq!(&t[116..], &3u32.to_be_bytes());
    }

    /// RP6 (pure part): a chain from the pinned key to the presented key.
    #[test]
    fn rp6_chain_walk() {
        let (k0, k1, k2) = (sk(1), sk(2), sk(3));
        let (p0, p1, p2) = (
            k0.verifying_key().to_bytes(),
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
        );
        let l1 = sign_relay_link(&k0, &p1, 1);
        let l2 = sign_relay_link(&k1, &p2, 2);
        let pin0 = encode_pin(&p0);
        assert!(walk_relay_chain(&[l1.clone(), l2.clone()], &pin0, 0, &p2, 2).is_ok());
        assert!(walk_relay_chain(std::slice::from_ref(&l2), &encode_pin(&p1), 1, &p2, 2).is_ok());
        assert_eq!(
            walk_relay_chain(std::slice::from_ref(&l2), &pin0, 0, &p2, 2),
            Err(RelayPinError::BadChain),
            "gap"
        );
        assert_eq!(
            walk_relay_chain(&[l2.clone(), l1.clone()], &pin0, 0, &p2, 2),
            Err(RelayPinError::BadChain),
            "order"
        );
        assert_eq!(
            walk_relay_chain(std::slice::from_ref(&l1), &pin0, 0, &p2, 2),
            Err(RelayPinError::BadChain),
            "ends elsewhere"
        );
        let mut forged = l1.clone();
        forged.new_key = p2;
        assert_eq!(
            walk_relay_chain(&[forged], &pin0, 0, &p2, 1),
            Err(RelayPinError::BadChain)
        );
        let four = vec![l1.clone(), l2.clone(), l2.clone(), l2];
        assert_eq!(
            walk_relay_chain(&four, &pin0, 0, &p2, 2),
            Err(RelayPinError::BadChain),
            "> 3 links"
        );
        assert!(verify_relay_link(&l1).is_ok());
    }
}
