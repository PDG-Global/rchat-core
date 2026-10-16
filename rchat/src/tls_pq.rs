//! Hybrid post-quantum TLS key exchange: X25519MLKEM768 (IANA group 0x11EC,
//! draft-ietf-tls-ecdhe-mlkem), ruling R37.
//!
//! rustls's ring provider has no ML-KEM, so the relay adds this one group to
//! it. The two halves are code the relay already ships:
//! - X25519 is ring's own (`rustls::crypto::ring::kx_group::X25519`);
//! - ML-KEM-768 is the core's `kem` module (RustCrypto `ml-kem`, pinned and
//!   KAT-tested for the protocol v3 handshake), which also runs the FIPS 203
//!   §7.2 encapsulation-key check on every client share.
//!
//! Wire layout (the draft's, ML-KEM first): the client share is
//! `ek (1184) || x25519 (32)`, the server share `ct (1088) || x25519 (32)`,
//! and the shared secret `ss_mlkem (32) || ss_x25519 (32)`, which TLS 1.3
//! feeds to its key schedule like any (EC)DHE secret.
//!
//! [`traffic_provider`] puts this group first and keeps ring's X25519, P-256
//! and P-384 after it. rustls follows the client's group order: a client
//! that offers X25519MLKEM768 first (every rChat client does) gets it, and a
//! client without it falls back to a classical group, with no error. Only
//! key exchange changes: certificates, signatures, cipher suites, tickets
//! and the exporter are untouched.

use rchat_core::kem::{self, KemKeyPair, KEM_CT_LEN, KEM_PK_LEN};
use rustls::crypto::ring::kx_group::X25519;
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

/// X25519 public key length.
const X25519_LEN: usize = 32;
/// Client share: ML-KEM-768 encapsulation key, then X25519.
const CLIENT_SHARE_LEN: usize = KEM_PK_LEN + X25519_LEN;
/// Server share: ML-KEM-768 ciphertext, then X25519.
const SERVER_SHARE_LEN: usize = KEM_CT_LEN + X25519_LEN;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// The X25519MLKEM768 group.
#[derive(Debug)]
pub struct X25519MlKem768;

/// The X25519MLKEM768 group, as rustls lists groups.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768;

/// ring's provider with X25519MLKEM768 preferred: the server configs use it.
pub fn traffic_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.insert(0, X25519MLKEM768);
    provider
}

/// `a || b` in memory that is wiped on drop.
fn concat_secret(a: &[u8], b: &[u8]) -> SharedSecret {
    let mut out = Zeroizing::new(Vec::with_capacity(a.len() + b.len()));
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    // `SharedSecret` copies and wipes its own buffer on drop.
    SharedSecret::from(&out[..])
}

impl SupportedKxGroup for X25519MlKem768 {
    /// Client side, used only by tests (rustls clients offering the group;
    /// the relay never starts a key exchange): a fresh ML-KEM key pair and a
    /// fresh X25519 key.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = X25519.start()?;
        let kem = KemKeyPair::generate();
        let mut pub_key = Vec::with_capacity(CLIENT_SHARE_LEN);
        pub_key.extend_from_slice(kem.public());
        pub_key.extend_from_slice(classical.pub_key());
        Ok(Box::new(ActiveHybrid {
            classical,
            kem,
            pub_key,
        }))
    }

    /// Server side: encapsulate to the client's ML-KEM key, X25519 with its
    /// X25519 key. Any malformed share is `InvalidKeyShare`.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = client_share.split_at(KEM_PK_LEN);
        let classical = X25519.start_and_complete(classical_share)?;
        let (ct, ss) = kem::encapsulate(pq_share).map_err(|_| INVALID_KEY_SHARE)?;

        let mut pub_key = Vec::with_capacity(SERVER_SHARE_LEN);
        pub_key.extend_from_slice(&ct);
        pub_key.extend_from_slice(&classical.pub_key);
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: concat_secret(&ss[..], classical.secret.secret_bytes()),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// A client-side exchange in progress. The relay only ever runs the server
/// side (`start_and_complete`); this half, and `start`, serve the relay's
/// own tests (rustls clients offering the group). Its wire format is checked
/// against an independent implementation only indirectly: the server side is
/// interop-tested with BoringSSL clients, and this side agrees with it.
struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    kem: KemKeyPair,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != SERVER_SHARE_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ct, classical_share) = peer_pub_key.split_at(KEM_CT_LEN);
        let ss = self.kem.decapsulate(ct).map_err(|_| INVALID_KEY_SHARE)?;
        let classical = self.classical.complete(classical_share)?;
        Ok(concat_secret(&ss[..], classical.secret_bytes()))
    }

    /// Lets a rustls client send a plain X25519 share alongside, so a
    /// classical-only server needs no HelloRetryRequest.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_prefers_hybrid_then_ring_defaults() {
        let names: Vec<_> = traffic_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(
            names,
            [
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1
            ]
        );
        assert!(!X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_3));
    }

    #[test]
    fn both_sides_agree_and_shares_have_draft_lengths() {
        let client = X25519MLKEM768.start().unwrap();
        assert_eq!(client.pub_key().len(), 1184 + 32);
        assert_eq!(client.group(), NamedGroup::X25519MLKEM768);
        let server = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), 1088 + 32);
        assert_eq!(server.group, NamedGroup::X25519MLKEM768);
        let server_secret = server.secret.secret_bytes().to_vec();
        assert_eq!(server_secret.len(), 64);
        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(client_secret.secret_bytes(), &server_secret[..]);
    }

    #[test]
    fn malformed_shares_are_refused() {
        let client = X25519MLKEM768.start().unwrap();
        let share = client.pub_key().to_vec();
        // Wrong lengths.
        for bad in [&share[..share.len() - 1], &share[..32], &[][..]] {
            assert!(X25519MLKEM768.start_and_complete(bad).is_err());
        }
        // An ML-KEM key whose first coefficient is not reduced mod q
        // (FIPS 203 §7.2).
        let mut unreduced = share.clone();
        unreduced[0] = 0xff;
        unreduced[1] |= 0x0f;
        assert!(X25519MLKEM768.start_and_complete(&unreduced).is_err());
        // A server share of the wrong length.
        let server = X25519MLKEM768.start_and_complete(&share).unwrap();
        assert!(client
            .complete(&server.pub_key[..server.pub_key.len() - 1])
            .is_err());
    }

    /// A valid ML-KEM key with an all-zero (low-order) X25519 half: the
    /// X25519 result would be all zero, which ring refuses, so the whole
    /// share is refused.
    #[test]
    fn low_order_x25519_half_is_refused() {
        let client = X25519MLKEM768.start().unwrap();
        let mut share = client.pub_key().to_vec();
        share[KEM_PK_LEN..].fill(0);
        assert!(X25519MLKEM768.start_and_complete(&share).is_err());
        // Same on the client side: a valid ciphertext, zero X25519 half.
        let good = X25519MLKEM768.start_and_complete(client.pub_key()).unwrap();
        let mut reply = good.pub_key.clone();
        reply[KEM_CT_LEN..].fill(0);
        assert!(client.complete(&reply).is_err());
    }

    #[test]
    fn hybrid_component_is_plain_x25519() {
        let client = X25519MLKEM768.start().unwrap();
        let (group, share) = client.hybrid_component().unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(share, &client.pub_key()[KEM_PK_LEN..]);
        let server = X25519.start_and_complete(share).unwrap();
        let secret = client.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
}
