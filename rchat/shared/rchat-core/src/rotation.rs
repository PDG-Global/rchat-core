//! Contact key rotation proofs (spec §4.8): the old identity key signs the
//! new keys and version. Pure and client-only: the relay is told nothing
//! about rotations (D21) and touches no rotation data.

use crate::crypto::IdentityKeyPair;
use crate::keyauth::is_low_order_x25519;
use ed25519_dalek::{Signature, VerifyingKey};

pub const ROTATE_DOMAIN: &[u8; 16] = b"rchat/rotate/v1\0";
pub const LINK_LEN: usize = 196;
pub const MAX_CHAIN: usize = 3;
pub const BLOCK_LEN: usize = 1 + 4 + 1 + MAX_CHAIN * LINK_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    #[error("malformed rotation data")]
    Malformed,
    #[error("invalid key in rotation link")]
    BadKey,
    #[error("rotation signature does not verify")]
    BadSignature,
    #[error("rotation chain does not connect")]
    BadChain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationLink {
    pub prev_identity_key: [u8; 32],
    pub prev_agreement_key: [u8; 32],
    pub new_identity_key: [u8; 32],
    pub new_agreement_key: [u8; 32],
    pub new_version: u32,
    pub signature: [u8; 64],
}

impl RotationLink {
    /// `ROTATE_DOMAIN || prev_ak || new_ik || new_ak || new_version_be` (116 bytes).
    pub fn message(&self) -> [u8; 116] {
        link_message(
            &self.prev_agreement_key,
            &self.new_identity_key,
            &self.new_agreement_key,
            self.new_version,
        )
    }

    pub fn to_bytes(&self) -> [u8; LINK_LEN] {
        let mut b = [0u8; LINK_LEN];
        b[..32].copy_from_slice(&self.prev_identity_key);
        b[32..64].copy_from_slice(&self.prev_agreement_key);
        b[64..96].copy_from_slice(&self.new_identity_key);
        b[96..128].copy_from_slice(&self.new_agreement_key);
        b[128..132].copy_from_slice(&self.new_version.to_be_bytes());
        b[132..].copy_from_slice(&self.signature);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, RotationError> {
        if b.len() != LINK_LEN {
            return Err(RotationError::Malformed);
        }
        let k = |r: std::ops::Range<usize>| -> Result<[u8; 32], RotationError> {
            b[r].try_into().map_err(|_| RotationError::Malformed)
        };
        Ok(Self {
            prev_identity_key: k(0..32)?,
            prev_agreement_key: k(32..64)?,
            new_identity_key: k(64..96)?,
            new_agreement_key: k(96..128)?,
            new_version: u32::from_be_bytes(
                b[128..132]
                    .try_into()
                    .map_err(|_| RotationError::Malformed)?,
            ),
            signature: b[132..].try_into().map_err(|_| RotationError::Malformed)?,
        })
    }

    /// The old key's signature over the new keys; weak or low-order keys
    /// refused, and so is a "rotation" that keeps either old key.
    pub fn verify(&self) -> Result<(), RotationError> {
        if self.new_identity_key == self.prev_identity_key
            || self.new_agreement_key == self.prev_agreement_key
        {
            return Err(RotationError::BadKey);
        }
        let new_vk =
            VerifyingKey::from_bytes(&self.new_identity_key).map_err(|_| RotationError::BadKey)?;
        if new_vk.is_weak()
            || is_low_order_x25519(&self.new_agreement_key)
            || is_low_order_x25519(&self.prev_agreement_key)
        {
            return Err(RotationError::BadKey);
        }
        let prev_vk =
            VerifyingKey::from_bytes(&self.prev_identity_key).map_err(|_| RotationError::BadKey)?;
        if prev_vk.is_weak() {
            return Err(RotationError::BadKey);
        }
        prev_vk
            .verify_strict(&self.message(), &Signature::from_bytes(&self.signature))
            .map_err(|_| RotationError::BadSignature)
    }
}

fn link_message(
    prev_ak: &[u8; 32],
    new_ik: &[u8; 32],
    new_ak: &[u8; 32],
    new_version: u32,
) -> [u8; 116] {
    let mut m = [0u8; 116];
    m[..16].copy_from_slice(ROTATE_DOMAIN);
    m[16..48].copy_from_slice(prev_ak);
    m[48..80].copy_from_slice(new_ik);
    m[80..112].copy_from_slice(new_ak);
    m[112..].copy_from_slice(&new_version.to_be_bytes());
    m
}

/// Sign a rotation from `old` to the new keys (spec §4.8).
pub fn sign_link(
    old: &IdentityKeyPair,
    new_identity_key: &[u8; 32],
    new_agreement_key: &[u8; 32],
    new_version: u32,
) -> RotationLink {
    let prev_agreement_key = *old.public_agreement_key().as_bytes();
    let signature = old
        .sign(&link_message(
            &prev_agreement_key,
            new_identity_key,
            new_agreement_key,
            new_version,
        ))
        .to_bytes();
    RotationLink {
        prev_identity_key: old.public_signing_key().to_bytes(),
        prev_agreement_key,
        new_identity_key: *new_identity_key,
        new_agreement_key: *new_agreement_key,
        new_version,
        signature,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RotationBlock {
    pub current_version: u32,
    pub links: Vec<RotationLink>,
}

impl RotationBlock {
    /// The version must be the last link's (when there are links).
    fn check_shape(&self) -> Result<(), RotationError> {
        if self.links.len() > MAX_CHAIN {
            return Err(RotationError::Malformed);
        }
        if let Some(last) = self.links.last() {
            if last.new_version != self.current_version {
                return Err(RotationError::Malformed);
            }
        }
        Ok(())
    }

    /// `flag 0x01 || current_version || count || links`, zero-padded to
    /// `BLOCK_LEN`. More than `MAX_CHAIN` links, or a `current_version` other
    /// than the last link's, is refused (never silently trimmed).
    pub fn encode(&self) -> Result<[u8; BLOCK_LEN], RotationError> {
        self.check_shape()?;
        let mut b = [0u8; BLOCK_LEN];
        b[0] = 0x01;
        b[1..5].copy_from_slice(&self.current_version.to_be_bytes());
        b[5] = self.links.len() as u8;
        for (i, l) in self.links.iter().enumerate() {
            b[6 + i * LINK_LEN..6 + (i + 1) * LINK_LEN].copy_from_slice(&l.to_bytes());
        }
        Ok(b)
    }

    /// `Ok(None)` for an absent block, which must be all zero. A present
    /// block must be zero after its links and pass the `encode` rules.
    pub fn decode(b: &[u8]) -> Result<Option<Self>, RotationError> {
        if b.len() != BLOCK_LEN {
            return Err(RotationError::Malformed);
        }
        match b[0] {
            0x00 if b.iter().all(|&x| x == 0) => return Ok(None),
            0x01 => {}
            _ => return Err(RotationError::Malformed),
        }
        let count = b[5] as usize;
        if count > MAX_CHAIN {
            return Err(RotationError::Malformed);
        }
        let end = 6 + count * LINK_LEN;
        if b[end..].iter().any(|&x| x != 0) {
            return Err(RotationError::Malformed);
        }
        let links = (0..count)
            .map(|i| RotationLink::from_bytes(&b[6 + i * LINK_LEN..6 + (i + 1) * LINK_LEN]))
            .collect::<Result<Vec<_>, _>>()?;
        let block = Self {
            current_version: u32::from_be_bytes(
                b[1..5].try_into().map_err(|_| RotationError::Malformed)?,
            ),
            links,
        };
        block.check_shape()?;
        Ok(Some(block))
    }
}

fn check_links(
    links: &[RotationLink],
    final_ik: &[u8; 32],
    final_ak: &[u8; 32],
) -> Result<(), RotationError> {
    if links.is_empty() || links.len() > MAX_CHAIN {
        return Err(RotationError::BadChain);
    }
    for (i, l) in links.iter().enumerate() {
        l.verify()?;
        if i > 0 {
            let p = &links[i - 1];
            if l.prev_identity_key != p.new_identity_key
                || l.prev_agreement_key != p.new_agreement_key
                || Some(l.new_version) != p.new_version.checked_add(1)
            {
                return Err(RotationError::BadChain);
            }
        }
    }
    let last = links.last().ok_or(RotationError::BadChain)?;
    if last.new_identity_key != *final_ik || last.new_agreement_key != *final_ak {
        return Err(RotationError::BadChain);
    }
    Ok(())
}

/// The chain hangs together and ends at the given keys (no pin involved:
/// used for our own new chain and for a chain from a blocked identity).
pub fn verify_chain_to(
    links: &[RotationLink],
    final_ik: &[u8; 32],
    final_ak: &[u8; 32],
) -> Result<(), RotationError> {
    check_links(links, final_ik, final_ak)
}

/// Client check: some link starts at the pin (identity and agreement key,
/// constant time) with version `pinned + 1`, and from there the chain hangs
/// together and ends at the presented keys. Returns the new version.
pub fn walk_chain(
    links: &[RotationLink],
    pinned_ik: &[u8; 32],
    pinned_ak: &[u8; 32],
    pinned_version: u32,
    final_ik: &[u8; 32],
    final_ak: &[u8; 32],
) -> Result<u32, RotationError> {
    if links.len() > MAX_CHAIN {
        return Err(RotationError::BadChain);
    }
    let start = links
        .iter()
        .position(|l| {
            constant_time_eq::constant_time_eq(&l.prev_identity_key, pinned_ik)
                && constant_time_eq::constant_time_eq(&l.prev_agreement_key, pinned_ak)
                && Some(l.new_version) == pinned_version.checked_add(1)
        })
        .ok_or(RotationError::BadChain)?;
    check_links(&links[start..], final_ik, final_ak)?;
    Ok(links
        .last()
        .map(|l| l.new_version)
        .unwrap_or(pinned_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;

    fn id(b: u8) -> IdentityKeyPair {
        IdentityKeyPair::from_seed(&[b; 64]).unwrap()
    }
    fn keys(i: &IdentityKeyPair) -> ([u8; 32], [u8; 32]) {
        (
            i.public_signing_key().to_bytes(),
            *i.public_agreement_key().as_bytes(),
        )
    }

    /// KR1: round-trip, tamper, version and weak-key rules.
    #[test]
    fn kr1_link_sign_verify_and_tamper() {
        let (a, b) = (id(1), id(2));
        let (bik, bak) = keys(&b);
        let link = sign_link(&a, &bik, &bak, 1);
        assert!(link.verify().is_ok());
        assert_eq!(RotationLink::from_bytes(&link.to_bytes()).unwrap(), link);
        for i in 0..LINK_LEN {
            let mut raw = link.to_bytes();
            raw[i] ^= 1;
            let ok = RotationLink::from_bytes(&raw)
                .map(|l| l.verify().is_ok())
                .unwrap_or(false);
            assert!(!ok, "flipping byte {i} must break the link");
        }
        let mut weak = link.clone();
        weak.new_identity_key = [0; 32];
        assert!(weak.verify().is_err());
        assert_eq!(&link.message()[..16], ROTATE_DOMAIN);
        assert_eq!(
            &link.message()[16..48],
            a.public_agreement_key().as_bytes(),
            "prev agreement key bound"
        );
        assert_eq!(&link.message()[112..], &1u32.to_be_bytes());
    }

    /// KR2: chains of 1–3 links from the pin; every malformed variant fails.
    #[test]
    fn kr2_chain_walk() {
        let (a, b, c, d) = (id(1), id(2), id(3), id(4));
        let (aik, aak) = keys(&a);
        let (bik, bak) = keys(&b);
        let (cik, cak) = keys(&c);
        let (dik, dak) = keys(&d);
        let l1 = sign_link(&a, &bik, &bak, 1);
        let l2 = sign_link(&b, &cik, &cak, 2);
        let l3 = sign_link(&c, &dik, &dak, 3);
        assert_eq!(
            walk_chain(std::slice::from_ref(&l1), &aik, &aak, 0, &bik, &bak),
            Ok(1)
        );
        assert_eq!(
            walk_chain(
                &[l1.clone(), l2.clone(), l3.clone()],
                &aik,
                &aak,
                0,
                &dik,
                &dak
            ),
            Ok(3)
        );
        assert_eq!(
            walk_chain(&[l2.clone(), l3.clone()], &bik, &bak, 1, &dik, &dak),
            Ok(3)
        );
        assert!(
            walk_chain(std::slice::from_ref(&l2), &aik, &aak, 0, &cik, &cak).is_err(),
            "does not start at the pin"
        );
        assert!(
            walk_chain(std::slice::from_ref(&l1), &aik, &aak, 1, &bik, &bak).is_err(),
            "version must be pinned + 1"
        );
        assert!(
            walk_chain(&[l1.clone(), l3.clone()], &aik, &aak, 0, &dik, &dak).is_err(),
            "gap"
        );
        assert!(
            walk_chain(&[l2.clone(), l1.clone()], &aik, &aak, 0, &cik, &cak).is_err(),
            "order"
        );
        assert!(
            walk_chain(std::slice::from_ref(&l1), &aik, &aak, 0, &cik, &cak).is_err(),
            "ends at other keys"
        );
        let four = vec![l1.clone(), l2.clone(), l3.clone(), l3.clone()];
        assert!(
            walk_chain(&four, &aik, &aak, 0, &dik, &dak).is_err(),
            "more than 3 links"
        );
        // KR12 (pure): the first link must start at the pinned agreement key.
        assert!(
            walk_chain(std::slice::from_ref(&l1), &aik, &[0x77; 32], 0, &bik, &bak).is_err(),
            "pinned agreement key differs"
        );
        assert!(verify_chain_to(&[l1.clone(), l2.clone()], &cik, &cak).is_ok());
        assert!(verify_chain_to(&[l1, l3], &dik, &dak).is_err());
    }

    #[test]
    fn block_encode_decode() {
        let (a, b) = (id(1), id(2));
        let (bik, bak) = keys(&b);
        let block = RotationBlock {
            current_version: 1,
            links: vec![sign_link(&a, &bik, &bak, 1)],
        };
        let raw = block.encode().unwrap();
        assert_eq!(raw.len(), BLOCK_LEN);
        assert_eq!(RotationBlock::decode(&raw).unwrap(), Some(block));
        assert_eq!(
            RotationBlock::decode(&[0u8; BLOCK_LEN]).unwrap(),
            None,
            "flag 0 = no block"
        );
        let mut bad = raw;
        bad[5] = 4;
        assert!(RotationBlock::decode(&bad).is_err(), "count > 3");
    }

    /// Carry-forward (Task 10c review): strict block framing.
    #[test]
    fn block_decode_rejects_bad_framing() {
        let (a, b) = (id(1), id(2));
        let (bik, bak) = keys(&b);
        let block = RotationBlock {
            current_version: 1,
            links: vec![sign_link(&a, &bik, &bak, 1)],
        };
        let raw = block.encode().unwrap();
        // Flag 0x00 must be all zero.
        let mut absent = [0u8; BLOCK_LEN];
        absent[BLOCK_LEN - 1] = 1;
        assert_eq!(
            RotationBlock::decode(&absent),
            Err(RotationError::Malformed)
        );
        absent[BLOCK_LEN - 1] = 0;
        absent[1] = 1;
        assert_eq!(
            RotationBlock::decode(&absent),
            Err(RotationError::Malformed)
        );
        // Flag 0x01: zero padding after the links.
        let mut padded = raw;
        padded[6 + LINK_LEN] = 1;
        assert_eq!(
            RotationBlock::decode(&padded),
            Err(RotationError::Malformed)
        );
        let mut padded = raw;
        padded[BLOCK_LEN - 1] = 0xff;
        assert_eq!(
            RotationBlock::decode(&padded),
            Err(RotationError::Malformed)
        );
        // Unknown flags.
        for flag in [0x02u8, 0x80, 0xff] {
            let mut f = raw;
            f[0] = flag;
            assert_eq!(
                RotationBlock::decode(&f),
                Err(RotationError::Malformed),
                "flag {flag}"
            );
        }
        // Truncated and oversized.
        assert_eq!(
            RotationBlock::decode(&raw[..BLOCK_LEN - 1]),
            Err(RotationError::Malformed)
        );
        let mut long = raw.to_vec();
        long.push(0);
        assert_eq!(RotationBlock::decode(&long), Err(RotationError::Malformed));
        assert_eq!(RotationBlock::decode(&[]), Err(RotationError::Malformed));
        // The version must be the last link's.
        let mut v = raw;
        v[1..5].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(RotationBlock::decode(&v), Err(RotationError::Malformed));
        // An empty present block decodes (and carries nothing to walk).
        let empty = RotationBlock {
            current_version: 7,
            links: vec![],
        };
        assert_eq!(
            RotationBlock::decode(&empty.encode().unwrap()).unwrap(),
            Some(empty)
        );
    }

    /// Carry-forward: encode never trims links silently and checks the version.
    #[test]
    fn block_encode_refuses_bad_shape() {
        let (a, b, c, d, e) = (id(1), id(2), id(3), id(4), id(5));
        let link = |from: &IdentityKeyPair, to: &IdentityKeyPair, v: u32| {
            let (ik, ak) = keys(to);
            sign_link(from, &ik, &ak, v)
        };
        let four = RotationBlock {
            current_version: 4,
            links: vec![
                link(&a, &b, 1),
                link(&b, &c, 2),
                link(&c, &d, 3),
                link(&d, &e, 4),
            ],
        };
        assert_eq!(four.encode(), Err(RotationError::Malformed));
        let wrong_version = RotationBlock {
            current_version: 2,
            links: vec![link(&a, &b, 1)],
        };
        assert_eq!(wrong_version.encode(), Err(RotationError::Malformed));
        let three = RotationBlock {
            current_version: 3,
            links: vec![link(&a, &b, 1), link(&b, &c, 2), link(&c, &d, 3)],
        };
        let raw = three.encode().unwrap();
        assert_eq!(raw[5], 3);
        assert_eq!(RotationBlock::decode(&raw).unwrap(), Some(three));
    }

    /// Carry-forward: a link that keeps either old key is refused.
    #[test]
    fn self_rotation_is_refused() {
        let (a, b) = (id(1), id(2));
        let (aik, aak) = keys(&a);
        let (bik, bak) = keys(&b);
        assert_eq!(
            sign_link(&a, &aik, &aak, 1).verify(),
            Err(RotationError::BadKey)
        );
        assert_eq!(
            sign_link(&a, &bik, &aak, 1).verify(),
            Err(RotationError::BadKey)
        );
        assert_eq!(
            sign_link(&a, &aik, &bak, 1).verify(),
            Err(RotationError::BadKey)
        );
        assert!(walk_chain(&[sign_link(&a, &aik, &aak, 1)], &aik, &aak, 0, &aik, &aak).is_err());
    }

    /// Carry-forward edge cases: duplicate links, u32::MAX, low-order prev_ak.
    #[test]
    fn chain_edge_cases() {
        let (a, b, c) = (id(1), id(2), id(3));
        let (aik, aak) = keys(&a);
        let (bik, bak) = keys(&b);
        let (cik, cak) = keys(&c);
        let l1 = sign_link(&a, &bik, &bak, 1);
        assert!(
            walk_chain(&[l1.clone(), l1.clone()], &aik, &aak, 0, &bik, &bak).is_err(),
            "duplicate link"
        );
        assert!(verify_chain_to(&[l1.clone(), l1.clone()], &bik, &bak).is_err());
        // Version u32::MAX: reachable, but nothing follows it and nothing
        // follows a pin at u32::MAX (checked_add, no panic).
        let top = sign_link(&a, &bik, &bak, u32::MAX);
        assert_eq!(
            walk_chain(
                std::slice::from_ref(&top),
                &aik,
                &aak,
                u32::MAX - 1,
                &bik,
                &bak
            ),
            Ok(u32::MAX)
        );
        let wrapped = sign_link(&b, &cik, &cak, 0);
        assert!(
            walk_chain(
                &[top.clone(), wrapped],
                &aik,
                &aak,
                u32::MAX - 1,
                &cik,
                &cak
            )
            .is_err(),
            "no wrap past u32::MAX"
        );
        assert!(walk_chain(std::slice::from_ref(&top), &aik, &aak, u32::MAX, &bik, &bak).is_err());
        let zero = sign_link(&a, &bik, &bak, 0);
        assert!(walk_chain(
            std::slice::from_ref(&zero),
            &aik,
            &aak,
            u32::MAX,
            &bik,
            &bak
        )
        .is_err());
        // A link naming a low-order previous agreement key, validly signed.
        let mut low = RotationLink {
            prev_identity_key: aik,
            prev_agreement_key: [0u8; 32],
            new_identity_key: bik,
            new_agreement_key: bak,
            new_version: 1,
            signature: [0u8; 64],
        };
        low.signature = a.sign(&low.message()).to_bytes();
        assert_eq!(low.verify(), Err(RotationError::BadKey));
        assert!(walk_chain(&[low], &aik, &[0u8; 32], 0, &bik, &bak).is_err());
        // Empty chains never verify.
        assert!(walk_chain(&[], &aik, &aak, 0, &bik, &bak).is_err());
        assert!(verify_chain_to(&[], &bik, &bak).is_err());
    }
}
