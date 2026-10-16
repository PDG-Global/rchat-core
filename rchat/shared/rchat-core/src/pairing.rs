//! Pair secret, pair epoch and rotating pair tokens (protocol v3 §C.1).
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairEpoch {
    pub day: u32,
    pub counter: u32,
}

/// Seconds in a UTC day.
const DAY_SECS: u64 = 86_400;
/// Clock-skew window on either side of 00:00 UTC (§C.1: "within 10 minutes").
const BOUNDARY_WINDOW_SECS: u64 = 600;
/// Length of a pair-token slot (R40-M3): the relay's ask TTL, so an ask
/// is held across at most one slot boundary. A day is 144 slots.
pub const SLOT_SECS: u64 = 600;

const PAIR_SECRET_INFO: &[u8] = b"rchat/pair-secret/v3";
const PAIR_TOKEN_LABEL: &[u8] = b"rchat/pair-token/v3";

/// `PS = HKDF-SHA256(salt = none (all zero), ikm = SK, info = "rchat/pair-secret/v3")`,
/// 32 bytes (§C.1). Wiped on drop; never log it.
pub fn pair_secret(sk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, sk);
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the 255 * 32 HKDF limit: cannot fail.
    hk.expand(PAIR_SECRET_INFO, &mut *out)
        .expect("32-byte HKDF output");
    out
}

/// `HMAC-SHA256(PS, "rchat/pair-token/v3" || day (u32 BE) || counter (u32 BE)
/// || slot (u32 BE))`, `slot = floor(unix / 600)` (`pair_slot`). No
/// separator after the label (§C.1). R40-M3: the slot makes the token
/// change every 10 minutes, so a relay recording asks can link only asks
/// made in the same or adjacent slots. The label is unchanged: the input
/// has a fixed length per version (no pre-slot token was ever released),
/// so a slot-less and a slotted input can never collide.
pub fn pair_token(ps: &[u8; 32], e: PairEpoch, slot: u32) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ps).expect("HMAC takes any key length");
    mac.update(PAIR_TOKEN_LABEL);
    mac.update(&e.day.to_be_bytes());
    mac.update(&e.counter.to_be_bytes());
    mac.update(&slot.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// `floor(unix / 600)`, saturating at `u32::MAX` (R40-M3).
pub fn pair_slot(unix_secs: u64) -> u32 {
    u32::try_from(unix_secs / SLOT_SECS).unwrap_or(u32::MAX)
}

/// `floor(unix / 86400)`, saturating at `u32::MAX`.
pub fn utc_day(unix_secs: u64) -> u32 {
    u32::try_from(unix_secs / DAY_SECS).unwrap_or(u32::MAX)
}

/// Seconds since 00:00 UTC of the current day.
fn secs_into_day(unix_secs: u64) -> u64 {
    unix_secs % DAY_SECS
}

/// Within 600 s of a UTC day boundary: the last 600 s of a day
/// (`>= 86400 - 600` into it) or the first 600 s of one (`< 600`).
pub fn near_day_boundary(unix_secs: u64) -> bool {
    let s = secs_into_day(unix_secs);
    !(BOUNDARY_WINDOW_SECS..DAY_SECS - BOUNDARY_WINDOW_SECS).contains(&s)
}

/// The adjacent day nearer the boundary: `day + 1` in the last 600 s of a
/// day, `day - 1` in the first 600 s. Away from a boundary there is no
/// neighbour to try, and the current day is returned. Saturating: day 0
/// just after 00:00 stays day 0.
pub fn neighbour_day(unix_secs: u64) -> u32 {
    let day = utc_day(unix_secs);
    let s = secs_into_day(unix_secs);
    if s >= DAY_SECS - BOUNDARY_WINDOW_SECS {
        day.saturating_add(1)
    } else if s < BOUNDARY_WINDOW_SECS {
        day.saturating_sub(1)
    } else {
        day
    }
}

impl PairEpoch {
    /// After a successful pairing: on a later day than `self.day` the epoch
    /// resets to `(now_day, 0)`, otherwise the counter goes up by one
    /// (saturating). If the clock went backwards (`now_day < self.day`)
    /// the day is kept and the counter goes up, so a token is never reused
    /// and the day never moves back.
    pub fn advance(&mut self, now_day: u32) {
        if now_day > self.day {
            *self = PairEpoch {
                day: now_day,
                counter: 0,
            };
        } else {
            self.counter = self.counter.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests;
