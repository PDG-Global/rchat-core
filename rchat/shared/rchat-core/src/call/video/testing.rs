//! Test hooks (`test-hooks`): a synthetic encoder that follows the encoder
//! hint like the app's MediaCodec encoder would, for the engine's tests and
//! the network simulator.

use super::engine::EncoderHint;
use super::VIDEO_MAX_FRAME;

/// Seconds between periodic keyframes (the encoder's I-frame interval).
const KEYFRAME_EVERY_SECS: u32 = 4;
/// A keyframe is this many times a delta frame's size.
const KEYFRAME_SCALE: usize = 6;

pub struct SyntheticEncoder {
    state: u64,
    frames_since_key: u32,
    first: bool,
    /// The hint generation whose keyframe request was answered.
    answered: Option<u32>,
}

impl SyntheticEncoder {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed | 1,
            frames_since_key: 0,
            first: true,
            answered: None,
        }
    }

    /// The next encoded frame for `hint`, `None` while it is inactive:
    /// `bitrate / 8 / fps` bytes, a keyframe (6x the size) first, every
    /// 4 s of frames and whenever the hint asks for one.
    pub fn next(&mut self, hint: &EncoderHint) -> Option<(Vec<u8>, bool)> {
        if !hint.active {
            return None;
        }
        let fps = hint.fps.max(1);
        let asked = hint.keyframe && self.answered != Some(hint.generation);
        let key = self.first || asked || self.frames_since_key >= KEYFRAME_EVERY_SECS * fps;
        if asked {
            self.answered = Some(hint.generation);
        }
        self.first = false;
        self.frames_since_key = if key { 1 } else { self.frames_since_key + 1 };
        let base = (hint.bitrate / 8 / fps).max(1) as usize;
        let len = if key { base * KEYFRAME_SCALE } else { base }.min(VIDEO_MAX_FRAME);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            // xorshift64
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            out.extend_from_slice(&self.state.to_le_bytes());
        }
        out.truncate(len);
        Some((out, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(active: bool, keyframe: bool, generation: u32) -> EncoderHint {
        EncoderHint {
            generation,
            width: 1280,
            height: 720,
            fps: 30,
            bitrate: 1_300_000,
            keyframe,
            active,
        }
    }

    #[test]
    fn sizes_follow_the_hint_with_keyframes_first_every_4_s_and_on_request() {
        let mut e = SyntheticEncoder::new(1);
        assert!(e.next(&hint(false, false, 1)).is_none());
        let (f, key) = e.next(&hint(true, false, 1)).unwrap();
        assert!(key);
        assert_eq!(f.len(), 1_300_000 / 8 / 30 * 6);
        let mut keys = 0;
        for _ in 1..120 {
            let (f, key) = e.next(&hint(true, false, 1)).unwrap();
            keys += usize::from(key);
            assert_eq!(f.len(), 1_300_000 / 8 / 30);
        }
        assert_eq!(keys, 0, "none before 4 s of frames");
        assert!(e.next(&hint(true, false, 1)).unwrap().1, "the 4 s keyframe");
        assert!(e.next(&hint(true, true, 2)).unwrap().1, "asked");
        assert!(
            !e.next(&hint(true, true, 2)).unwrap().1,
            "answered once per hint"
        );
    }
}
