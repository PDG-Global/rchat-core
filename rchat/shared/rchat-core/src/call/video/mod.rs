//! Video calls (Android video calls spec): the `0x0E` signalling plaintext
//! and the codec agreement; stream frames, fragments, the send queue, the
//! ladder, health, and the engine of one call (`engine::VideoMedia`).

pub mod adapt;
pub mod engine;
pub mod frag;
pub mod health;
pub(crate) mod queue;
pub mod signal;
pub mod stream;
#[cfg(any(test, feature = "test-hooks"))]
pub mod testing;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VideoCodec {
    H265,
    H264,
}

/// The largest picture a phone asks to receive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Quality {
    P720,
    P1080,
}

/// Caps `codecs` bit 0: hardware H.265 encoder and an H.265 decoder.
pub const CODEC_H265: u8 = 1;
/// Caps `codecs` bit 1: an H.264 encoder and an H.264 decoder.
pub const CODEC_H264: u8 = 2;

/// The call's codec: H.265 if both phones can, else H.264 if both can,
/// else none (video is unavailable).
pub fn agree_codec(mine: u8, theirs: u8) -> Option<VideoCodec> {
    let both = mine & theirs;
    if both & CODEC_H265 != 0 {
        Some(VideoCodec::H265)
    } else if both & CODEC_H264 != 0 {
        Some(VideoCodec::H264)
    } else {
        None
    }
}

/// Stream byte (second byte of a `0x05` frame) for video; audio frames
/// carry the high byte of a sequence below `MAX_SEQ`, so always `< 0x80`.
pub const STREAM_VIDEO: u8 = 0x81;
pub const STREAM_CONTROL: u8 = 0x82;
/// `0x05 ‖ stream ‖ seq (8, BE)`.
pub const STREAM_HEADER: usize = 1 + 1 + 8;
/// `frame_no (4) ‖ index ‖ count ‖ flags ‖ sent_ms (4)` (`frag`).
pub const FRAG_HEADER: usize = 11;
pub const VIDEO_FRAGMENT_MAX: usize = 8192;
pub const VIDEO_MAX_FRAGMENTS: usize = 48;
pub const VIDEO_MAX_FRAME: usize = 393_216;
pub const MAX_VIDEO_WIRE: usize = STREAM_HEADER + FRAG_HEADER + VIDEO_FRAGMENT_MAX + 16;

/// `Some(stream)` for a stream frame (`0x05` and a second byte `>= 0x80`);
/// audio frames are never stream frames.
pub fn is_stream_frame(frame: &[u8]) -> Option<u8> {
    match frame {
        [crate::protocol::FRAME_TYPE_MEDIA, s, ..] if *s >= 0x80 => Some(*s),
        _ => None,
    }
}
