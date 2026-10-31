//! Call-signalling plaintexts (spec §4), inside the Double Ratchet, padded
//! like any plaintext, with no `expire_secs` and no delivery receipt.

use super::CallId;
use zeroize::Zeroizing;

pub const OFFER_TYPE: u8 = 0x0A;
pub const RINGING_TYPE: u8 = 0x0B;
pub const ANSWER_TYPE: u8 = 0x0C;
pub const END_TYPE: u8 = 0x0D;
pub const OFFER_VERSION: u8 = 1;
pub const MEDIA_AUDIO: u8 = 0x01;
const OFFER_LEN: usize = 1 + 1 + 16 + 32 + 8 + 1;
const RINGING_LEN: usize = 1 + 16;
const ANSWER_LEN: usize = 1 + 16 + 32;
const END_LEN: usize = 1 + 16 + 1;

/// 0x0A-0x0D: call signalling (0x0E-0x0F stay reserved and dropped).
pub fn is_call_type(b: u8) -> bool {
    (OFFER_TYPE..=END_TYPE).contains(&b)
}

/// End reasons (D10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    HangUp = 1,
    Declined = 2,
    Busy = 3,
    NoAnswer = 4,
    Failed = 5,
    Unreachable = 6,
}

impl EndReason {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::HangUp,
            2 => Self::Declined,
            3 => Self::Busy,
            4 => Self::NoAnswer,
            5 => Self::Failed,
            6 => Self::Unreachable,
            _ => return None,
        })
    }
}

/// `PartialEq` only in tests: comparing the randoms outside a test would
/// not be constant-time.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum CallSignal {
    Offer {
        call_id: CallId,
        caller_rand: Zeroizing<[u8; 32]>,
        sent_at_ms: u64,
    },
    Ringing {
        call_id: CallId,
    },
    Answer {
        call_id: CallId,
        callee_rand: Zeroizing<[u8; 32]>,
    },
    End {
        call_id: CallId,
        reason: EndReason,
    },
}

impl std::fmt::Debug for CallSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Offer { .. } => "Offer(..)",
            Self::Ringing { .. } => "Ringing(..)",
            Self::Answer { .. } => "Answer(..)",
            Self::End { .. } => "End(..)",
        })
    }
}

/// The call id at `at` (1 after the type byte; 2 in an Offer, after the version).
fn id_at(pt: &[u8], at: usize) -> CallId {
    let mut b = [0u8; 16];
    b.copy_from_slice(&pt[at..at + 16]);
    CallId(b)
}

fn rand_at(pt: &[u8], at: usize) -> Zeroizing<[u8; 32]> {
    let mut r = Zeroizing::new([0u8; 32]);
    r.copy_from_slice(&pt[at..at + 32]);
    r
}

impl CallSignal {
    pub fn call_id(&self) -> CallId {
        match self {
            Self::Offer { call_id, .. }
            | Self::Ringing { call_id }
            | Self::Answer { call_id, .. }
            | Self::End { call_id, .. } => *call_id,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(OFFER_LEN));
        match self {
            Self::Offer {
                call_id,
                caller_rand,
                sent_at_ms,
            } => {
                v.extend_from_slice(&[OFFER_TYPE, OFFER_VERSION]);
                v.extend_from_slice(&call_id.0);
                v.extend_from_slice(&caller_rand[..]);
                v.extend_from_slice(&sent_at_ms.to_be_bytes());
                v.push(MEDIA_AUDIO);
            }
            Self::Ringing { call_id } => {
                v.push(RINGING_TYPE);
                v.extend_from_slice(&call_id.0);
            }
            Self::Answer {
                call_id,
                callee_rand,
            } => {
                v.push(ANSWER_TYPE);
                v.extend_from_slice(&call_id.0);
                v.extend_from_slice(&callee_rand[..]);
            }
            Self::End { call_id, reason } => {
                v.push(END_TYPE);
                v.extend_from_slice(&call_id.0);
                v.push(*reason as u8);
            }
        }
        v
    }

    /// Exact lengths only; an Offer must be version 1 and audio.
    pub fn decode(pt: &[u8]) -> Option<Self> {
        match (pt.first()?, pt.len()) {
            (&OFFER_TYPE, OFFER_LEN)
                if pt[1] == OFFER_VERSION && pt[OFFER_LEN - 1] == MEDIA_AUDIO =>
            {
                let mut at = [0u8; 8];
                at.copy_from_slice(&pt[50..58]);
                Some(Self::Offer {
                    call_id: id_at(pt, 2),
                    caller_rand: rand_at(pt, 18),
                    sent_at_ms: u64::from_be_bytes(at),
                })
            }
            (&RINGING_TYPE, RINGING_LEN) => Some(Self::Ringing {
                call_id: id_at(pt, 1),
            }),
            (&ANSWER_TYPE, ANSWER_LEN) => Some(Self::Answer {
                call_id: id_at(pt, 1),
                callee_rand: rand_at(pt, 17),
            }),
            (&END_TYPE, END_LEN) => Some(Self::End {
                call_id: id_at(pt, 1),
                reason: EndReason::from_u8(pt[17])?,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::CallId;
    use zeroize::Zeroizing;

    const ID: CallId = CallId([0xC1; 16]);

    #[test]
    fn encodings_are_the_spec_layouts() {
        let offer = CallSignal::Offer {
            call_id: ID,
            caller_rand: Zeroizing::new([0xAA; 32]),
            sent_at_ms: 0x0102_0304_0506_0708,
        };
        let mut want = vec![0x0A, 1];
        want.extend_from_slice(&[0xC1; 16]);
        want.extend_from_slice(&[0xAA; 32]);
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.push(0x01);
        assert_eq!(&*offer.encode(), &want[..]);
        assert_eq!(want.len(), 59);

        let ringing = CallSignal::Ringing { call_id: ID };
        assert_eq!(
            &*ringing.encode(),
            &[&[0x0B][..], &[0xC1; 16][..]].concat()[..]
        );

        let answer = CallSignal::Answer {
            call_id: ID,
            callee_rand: Zeroizing::new([0xBB; 32]),
        };
        assert_eq!(
            &*answer.encode(),
            &[&[0x0C][..], &[0xC1; 16][..], &[0xBB; 32][..]].concat()[..]
        );

        for (reason, byte) in [
            (EndReason::HangUp, 1),
            (EndReason::Declined, 2),
            (EndReason::Busy, 3),
            (EndReason::NoAnswer, 4),
            (EndReason::Failed, 5),
            (EndReason::Unreachable, 6),
        ] {
            let end = CallSignal::End {
                call_id: ID,
                reason,
            };
            assert_eq!(
                &*end.encode(),
                &[&[0x0D][..], &[0xC1; 16][..], &[byte][..]].concat()[..]
            );
            assert!(CallSignal::decode(&end.encode()) == Some(end));
        }
    }

    #[test]
    fn decode_refuses_anything_else() {
        let good = CallSignal::Offer {
            call_id: ID,
            caller_rand: Zeroizing::new([1; 32]),
            sent_at_ms: 5,
        }
        .encode()
        .to_vec();
        assert!(CallSignal::decode(&good).is_some());
        let mut v2 = good.clone();
        v2[1] = 2;
        assert!(CallSignal::decode(&v2).is_none(), "version 2");
        let mut video = good.clone();
        *video.last_mut().unwrap() = 0x02;
        assert!(CallSignal::decode(&video).is_none(), "video");
        assert!(CallSignal::decode(&good[..58]).is_none(), "short");
        assert!(
            CallSignal::decode(&[good.clone(), vec![0]].concat()).is_none(),
            "long"
        );
        assert!(
            CallSignal::decode(&[&[0x0D][..], &[0; 16][..], &[0][..]].concat()).is_none(),
            "reason 0"
        );
        assert!(
            CallSignal::decode(&[&[0x0D][..], &[0; 16][..], &[7][..]].concat()).is_none(),
            "reason 7"
        );
        assert!(CallSignal::decode(&[0x0E; 18]).is_none(), "0x0E reserved");
        assert!(
            is_call_type(0x0A) && is_call_type(0x0D) && !is_call_type(0x0E) && !is_call_type(0x09)
        );
    }
}
