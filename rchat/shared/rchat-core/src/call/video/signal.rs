//! Video signalling plaintexts (`0x0E`), inside the Double Ratchet like
//! the call signalling: no `expire_secs`, no delivery receipt.
//!
//! Layout: `0x0E ‖ kind ‖ call_id (16) ‖ body`. Kinds: 1 Caps
//! (`version=1 ‖ flags ‖ codecs ‖ max_recv`), 2 Request, 3 Accept,
//! 4 Decline, 5 Camera (`on`). Anything else is refused.

use super::super::CallId;
use super::Quality;

pub const VIDEO_TYPE: u8 = 0x0E;
const KIND_CAPS: u8 = 1;
const KIND_REQUEST: u8 = 2;
const KIND_ACCEPT: u8 = 3;
const KIND_DECLINE: u8 = 4;
const KIND_CAMERA: u8 = 5;
const CAPS_VERSION: u8 = 1;
const HEAD: usize = 2 + 16;
const FLAG_VIDEO: u8 = 0b01;
const FLAG_VIDEO_CALL: u8 = 0b10;
const CODECS_MASK: u8 = 0b11;

/// `0x0E`: video signalling (`0x0F` stays reserved and dropped).
pub fn is_video_type(b: u8) -> bool {
    b == VIDEO_TYPE
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caps {
    /// This phone can do video at all (camera and a codec).
    pub video: bool,
    /// This phone's app can place and take video calls.
    pub video_call: bool,
    /// `CODEC_H265 | CODEC_H264` bits.
    pub codecs: u8,
    pub max_recv: Quality,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VideoSignal {
    Caps { call_id: CallId, caps: Caps },
    Request { call_id: CallId },
    Accept { call_id: CallId },
    Decline { call_id: CallId },
    Camera { call_id: CallId, on: bool },
}

impl VideoSignal {
    pub fn call_id(&self) -> CallId {
        match self {
            Self::Caps { call_id, .. }
            | Self::Request { call_id }
            | Self::Accept { call_id }
            | Self::Decline { call_id }
            | Self::Camera { call_id, .. } => *call_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let kind = match self {
            Self::Caps { .. } => KIND_CAPS,
            Self::Request { .. } => KIND_REQUEST,
            Self::Accept { .. } => KIND_ACCEPT,
            Self::Decline { .. } => KIND_DECLINE,
            Self::Camera { .. } => KIND_CAMERA,
        };
        let mut out = Vec::with_capacity(HEAD + 4);
        out.push(VIDEO_TYPE);
        out.push(kind);
        out.extend_from_slice(&self.call_id().0);
        match self {
            Self::Caps { caps, .. } => {
                out.push(CAPS_VERSION);
                out.push(
                    u8::from(caps.video) * FLAG_VIDEO + u8::from(caps.video_call) * FLAG_VIDEO_CALL,
                );
                out.push(caps.codecs & CODECS_MASK);
                out.push(match caps.max_recv {
                    Quality::P720 => 0,
                    Quality::P1080 => 1,
                });
            }
            Self::Camera { on, .. } => out.push(u8::from(*on)),
            _ => {}
        }
        out
    }

    /// Strict: any other length, kind, version or reserved bit is `None`.
    pub fn decode(pt: &[u8]) -> Option<Self> {
        if pt.len() < HEAD || pt[0] != VIDEO_TYPE {
            return None;
        }
        let call_id = CallId(pt[2..HEAD].try_into().ok()?);
        let body = &pt[HEAD..];
        match (pt[1], body) {
            (KIND_CAPS, [CAPS_VERSION, flags, codecs, max_recv]) => {
                if flags & !(FLAG_VIDEO | FLAG_VIDEO_CALL) != 0 || codecs & !CODECS_MASK != 0 {
                    return None;
                }
                let max_recv = match max_recv {
                    0 => Quality::P720,
                    1 => Quality::P1080,
                    _ => return None,
                };
                Some(Self::Caps {
                    call_id,
                    caps: Caps {
                        video: flags & FLAG_VIDEO != 0,
                        video_call: flags & FLAG_VIDEO_CALL != 0,
                        codecs: *codecs,
                        max_recv,
                    },
                })
            }
            (KIND_REQUEST, []) => Some(Self::Request { call_id }),
            (KIND_ACCEPT, []) => Some(Self::Accept { call_id }),
            (KIND_DECLINE, []) => Some(Self::Decline { call_id }),
            (KIND_CAMERA, [on @ (0 | 1)]) => Some(Self::Camera {
                call_id,
                on: *on == 1,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{agree_codec, VideoCodec};
    use super::*;

    const ID: CallId = CallId([0xC1; 16]);

    #[test]
    fn encodings_are_the_ruling_layouts() {
        let caps = VideoSignal::Caps {
            call_id: ID,
            caps: Caps {
                video: true,
                video_call: true,
                codecs: 3,
                max_recv: Quality::P1080,
            },
        };
        assert_eq!(
            &caps.encode()[..],
            &[&[0x0E, 0x01][..], &[0xC1; 16][..], &[1, 0b11, 0b11, 1][..]].concat()[..]
        );
        assert_eq!(VideoSignal::Request { call_id: ID }.encode().len(), 18);
        assert_eq!(
            VideoSignal::Camera {
                call_id: ID,
                on: true
            }
            .encode(),
            [&[0x0E, 0x05][..], &[0xC1; 16][..], &[1][..]].concat()
        );
    }

    #[test]
    fn every_signal_round_trips() {
        for s in [
            VideoSignal::Caps {
                call_id: ID,
                caps: Caps {
                    video: true,
                    video_call: false,
                    codecs: 2,
                    max_recv: Quality::P720,
                },
            },
            VideoSignal::Request { call_id: ID },
            VideoSignal::Accept { call_id: ID },
            VideoSignal::Decline { call_id: ID },
            VideoSignal::Camera {
                call_id: ID,
                on: false,
            },
        ] {
            assert_eq!(VideoSignal::decode(&s.encode()), Some(s));
        }
    }

    #[test]
    fn decode_refuses_anything_else() {
        let head = |kind: u8| [&[0x0E, kind][..], &[0xC1; 16][..]].concat();
        let with = |kind: u8, body: &[u8]| [head(kind), body.to_vec()].concat();
        assert!(VideoSignal::decode(&[]).is_none());
        assert!(VideoSignal::decode(&head(0)).is_none());
        assert!(VideoSignal::decode(&head(6)).is_none());
        assert!(VideoSignal::decode(&head(2)[..17]).is_none(), "short");
        assert!(VideoSignal::decode(&with(2, &[0])).is_none(), "long");
        assert!(VideoSignal::decode(&with(3, &[0])).is_none());
        assert!(VideoSignal::decode(&with(4, &[0])).is_none());
        assert!(
            VideoSignal::decode(&with(1, &[1, 3, 3])).is_none(),
            "short caps"
        );
        assert!(
            VideoSignal::decode(&with(1, &[1, 3, 3, 1, 0])).is_none(),
            "long caps"
        );
        assert!(
            VideoSignal::decode(&with(1, &[2, 3, 3, 1])).is_none(),
            "version 2"
        );
        assert!(
            VideoSignal::decode(&with(1, &[1, 0b100, 3, 1])).is_none(),
            "flags bit2"
        );
        assert!(
            VideoSignal::decode(&with(1, &[1, 3, 4, 1])).is_none(),
            "codecs 4"
        );
        assert!(
            VideoSignal::decode(&with(1, &[1, 3, 3, 2])).is_none(),
            "max_recv 2"
        );
        assert!(VideoSignal::decode(&with(5, &[2])).is_none(), "camera on=2");
        assert!(VideoSignal::decode(&with(5, &[])).is_none());
        let mut other = with(2, &[]);
        other[0] = 0x0F;
        assert!(VideoSignal::decode(&other).is_none());
        other[0] = 0x0D;
        assert!(VideoSignal::decode(&other).is_none());
    }

    #[test]
    fn only_0x0e_is_a_video_type() {
        assert!(is_video_type(0x0E));
        assert!(!is_video_type(0x0D) && !is_video_type(0x0F));
    }

    #[test]
    fn codec_agreement_prefers_h265() {
        assert_eq!(agree_codec(3, 3), Some(VideoCodec::H265));
        assert_eq!(agree_codec(3, 2), Some(VideoCodec::H264));
        assert_eq!(agree_codec(1, 2), None);
        assert_eq!(agree_codec(0, 3), None);
    }
}
