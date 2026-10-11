//! Per-boot keyed tags for identities (spec §5.1).
//!
//! Relay maps that must find an identity again (its routing slot, its
//! offline queue) key it by `IdTag = BLAKE3-keyed(ID_KEY, "rchat/id/v1\0" ||
//! identity)`. The key is random per boot and never logged, so the tags are
//! useless outside this process. `Debug` deliberately prints no bytes.

use std::fmt;
use std::sync::OnceLock;

static ID_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn id_key_ref() -> &'static [u8; 32] {
    ID_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS randomness unavailable");
        key
    })
}

/// Install the tag key restored from the encrypted queue file. Succeeds only
/// before the key's first use; returns whether it was installed.
pub fn install_id_key(key: [u8; 32]) -> bool {
    ID_KEY.set(key).is_ok()
}

/// This boot's tag key, for saving with the encrypted queue. Never log it.
pub fn id_key() -> [u8; 32] {
    *id_key_ref()
}

/// Keyed tag of one identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdTag(pub [u8; 32]);

impl fmt::Debug for IdTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdTag(..)")
    }
}

/// `id_tag` under an explicit key (tests, and restoring a persisted key).
pub fn id_tag_with(key: &[u8; 32], id: &[u8; 32]) -> IdTag {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"rchat/id/v1\0");
    h.update(id);
    IdTag(*h.finalize().as_bytes())
}

/// This boot's tag for `id`.
pub fn id_tag(id: &[u8; 32]) -> IdTag {
    id_tag_with(id_key_ref(), id)
}

static PAIR_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn pair_key_ref() -> &'static [u8; 32] {
    PAIR_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS randomness unavailable");
        key
    })
}

/// Keyed, unordered tag of an identity pair. The key is per boot and never
/// persisted, so pair tags cannot be linked across restarts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairTag(pub [u8; 32]);

impl fmt::Debug for PairTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairTag(..)")
    }
}

/// `pair_tag` under an explicit key.
pub fn pair_tag_with(key: &[u8; 32], a: &[u8; 32], b: &[u8; 32]) -> PairTag {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"rchat/pair/v1\0");
    h.update(lo);
    h.update(hi);
    PairTag(*h.finalize().as_bytes())
}

/// This boot's tag for the pair {a, b}.
pub fn pair_tag(a: &[u8; 32], b: &[u8; 32]) -> PairTag {
    pair_tag_with(pair_key_ref(), a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_tag_is_stable_keyed_and_opaque() {
        let id = [7u8; 32];
        assert_eq!(id_tag(&id), id_tag(&id));
        assert_ne!(id_tag(&id), id_tag(&[8u8; 32]));
        assert_ne!(id_tag_with(&[1; 32], &id), id_tag_with(&[2; 32], &id));
        assert_ne!(id_tag(&id).0, id, "a tag is not the identity");
        assert_eq!(format!("{:?}", id_tag(&id)), "IdTag(..)");
    }

    #[test]
    fn install_id_key_only_before_first_use_and_id_key_is_stable() {
        let id = [1u8; 32];
        let _ = id_tag(&id); // first use fixes this process's key
        let key = id_key();
        assert!(
            !install_id_key([0x55; 32]),
            "a key in use is never replaced"
        );
        assert_eq!(id_key(), key, "id_key is stable");
        assert_eq!(id_tag(&id), id_tag_with(&key, &id), "id_tag uses id_key");
    }

    /// M4: pair tags are symmetric and change when the per-boot key changes.
    #[test]
    fn m4_pair_tag_is_symmetric_and_changes_across_boots() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(pair_tag(&a, &b), pair_tag(&b, &a));
        assert_ne!(pair_tag(&a, &b), pair_tag(&a, &[3u8; 32]));
        let boot1 = pair_tag_with(&[0x11; 32], &a, &b);
        let boot2 = pair_tag_with(&[0x22; 32], &a, &b);
        assert_ne!(boot1, boot2, "a new boot key gives unlinkable tags");
        assert_eq!(boot1, pair_tag_with(&[0x11; 32], &b, &a));
        assert_eq!(format!("{:?}", boot1), "PairTag(..)");
    }
}
