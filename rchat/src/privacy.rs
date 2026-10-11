//! Log privacy helpers.
//!
//! The relay is meant to be unable to tell who talks to whom, so its logs must not
//! be a side channel for that information. The rules, enforced by the
//! `log_privacy` tests in `signaling`:
//!
//! * Content and crypto material (payload bytes, auth tags, keys, raw frames,
//!   request headers) are never logged at any level.
//! * Identifiers (circuit ids, client ids, identity keys, message ids) are never
//!   logged raw. Where a log line needs to correlate events it uses [`tag`] /
//!   [`tag_str`]: a keyed BLAKE3 hash truncated to 32 bits, keyed with a random
//!   per-process salt. The tag is stable within one process run (so a developer
//!   at `trace` level can follow one circuit), cannot be reversed or matched
//!   against another run's logs, and 32 bits is far too short to brute-force
//!   back to a key. Tags only appear at `trace`/`debug`; `info`, `warn` and
//!   `error` carry no identifiers at all.
//! * Client IP addresses are never logged unless `logging.log_client_ips = true`
//!   (default false). Even then they only appear at `debug` via [`peer`].

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static SALT: OnceLock<[u8; 32]> = OnceLock::new();
static LOG_CLIENT_IPS: AtomicBool = AtomicBool::new(false);

fn salt() -> &'static [u8; 32] {
    SALT.get_or_init(|| {
        let mut s = [0u8; 32];
        getrandom::getrandom(&mut s).expect("OS randomness unavailable");
        s
    })
}

/// Non-reversible 8-hex-char correlation tag for an identifier.
pub fn tag(id: impl AsRef<[u8]>) -> String {
    let h = blake3::keyed_hash(salt(), id.as_ref());
    hex::encode(&h.as_bytes()[..4])
}

/// [`tag`] for identifiers held as strings (identity key hex, message ids).
pub fn tag_str(id: &str) -> String {
    tag(id.as_bytes())
}

/// Enable or disable client IP logging (from `logging.log_client_ips`).
pub fn set_log_client_ips(enabled: bool) {
    LOG_CLIENT_IPS.store(enabled, Ordering::Relaxed);
}

/// The text to log for a peer address: the address only when explicitly enabled.
pub fn peer(addr: &SocketAddr) -> String {
    if LOG_CLIENT_IPS.load(Ordering::Relaxed) {
        addr.to_string()
    } else {
        "<redacted>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_short_stable_and_not_the_input() {
        let a = tag([7u8; 16]);
        assert_eq!(a.len(), 8);
        assert_eq!(a, tag([7u8; 16]));
        assert_ne!(a, tag([8u8; 16]));
        assert!(!hex::encode([7u8; 16]).contains(&a));
    }
}
