//! Voice calls (Android voice calls spec §4, §6): signalling plaintexts,
//! call keys, media frames, the codec, the playback buffer, the call
//! connections, the audio engine and the call state machine. Here so iOS
//! reuses all of it.

use rand::RngCore;
use std::time::Duration;

mod api;
pub mod codec;
pub mod engine;
pub mod frame;
pub mod keys;
pub mod lanes;
pub mod machine;
pub mod playout;
pub mod signal;
#[cfg(test)]
pub(crate) mod test_relay;
#[cfg(test)]
mod tests;
pub mod video;

pub use api::{CallAudioHandle, CallVideoHandle};

/// Unix time in ms (offer timestamps, event times).
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A call's random 16-byte id. `Ord` is bytewise: in glare the lower id wins (§3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(pub [u8; 16]);

impl std::fmt::Debug for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallId(..)")
    }
}

impl CallId {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s).ok()?;
        Some(Self(v.try_into().ok()?))
    }
}

pub const SAMPLE_RATE: u32 = 48_000;
pub const FRAME_MS: u64 = 20;
/// One 20 ms mono frame at 48 kHz.
pub const FRAME_SAMPLES: usize = 960;
/// Largest Opus packet the engine makes or accepts (24 kbps CBR is 60 bytes).
pub const MAX_OPUS_BYTES: usize = 400;
/// A call that reaches 2^63 frames ends (§4).
pub const MAX_SEQ: u64 = 1 << 63;
pub const OFFER_MAX_AGE_MS: u64 = 60_000;
pub const UNREACHABLE_AFTER: Duration = Duration::from_secs(15);
pub const NO_ANSWER_AFTER: Duration = Duration::from_secs(45);
/// D14: the callee's own clock for an unanswered ringing call.
pub const INCOMING_GIVE_UP: Duration = Duration::from_secs(50);
/// D15: answered but no media yet.
pub const CONNECT_GIVE_UP: Duration = Duration::from_secs(20);
pub const RECONNECT_GIVE_UP: Duration = Duration::from_secs(20);
pub const SILENT_AFTER: Duration = Duration::from_secs(3);
pub const STALL_AFTER: Duration = Duration::from_secs(2);
pub const SEND_QUEUE_FRAMES: usize = 3;
pub const BITRATE_NORMAL: i32 = 24_000;
pub const BITRATE_POOR: i32 = 16_000;
pub const EXPECTED_LOSS_PCT: i32 = 10;
pub const POOR_CONCEALED_PCT: u32 = 5;
pub const POOR_WINDOW: Duration = Duration::from_secs(3);
pub const STEP_DOWN_AFTER: Duration = Duration::from_secs(5);
pub const STEP_UP_AFTER: Duration = Duration::from_secs(10);
pub const BUFFER_MIN_MS: u64 = 60;
pub const BUFFER_MAX_MS: u64 = 400;
pub const CATCH_UP_OVER_MS: u64 = 100;
