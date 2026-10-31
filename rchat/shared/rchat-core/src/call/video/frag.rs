//! Splitting a video frame into fragments and putting it back together.
//!
//! Fragment header (11 bytes): `frame_no (4, BE) ‖ index ‖ count ‖ flags ‖
//! sent_ms (4, BE)`, flags bit 0 keyframe, bit 1 codec (0 H.265, 1 H.264),
//! bits 2-3 rotation in quarter-turns, bits 4-7 zero; `sent_ms` is when the
//! sender queued the frame, in ms since an arbitrary origin of its own
//! (wrapping), for the receiver's delay measure. Every fragment but the last of a frame
//! carries exactly `VIDEO_FRAGMENT_MAX` bytes, so a fragment's place in the
//! frame is `index * VIDEO_FRAGMENT_MAX` and nothing is allocated per
//! fragment: the reassembler owns four `VIDEO_MAX_FRAME` buffers.

use super::{VideoCodec, FRAG_HEADER, VIDEO_FRAGMENT_MAX, VIDEO_MAX_FRAGMENTS, VIDEO_MAX_FRAME};

const SLOTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragHeader {
    pub frame_no: u32,
    pub index: u8,
    pub count: u8,
    pub keyframe: bool,
    pub codec: VideoCodec,
    /// Quarter-turns, 0..=3.
    pub rotation: u8,
    /// When the sender queued the frame, ms since its own origin (wrapping).
    pub sent_ms: u32,
}

impl FragHeader {
    pub fn encode(&self) -> [u8; FRAG_HEADER] {
        let mut b = [0u8; FRAG_HEADER];
        b[..4].copy_from_slice(&self.frame_no.to_be_bytes());
        b[4] = self.index;
        b[5] = self.count;
        b[6] = u8::from(self.keyframe)
            | (u8::from(self.codec == VideoCodec::H264) << 1)
            | ((self.rotation & 3) << 2);
        b[7..].copy_from_slice(&self.sent_ms.to_be_bytes());
        b
    }

    /// `None` unless exactly 11 well-formed bytes (count 1..=48, index <
    /// count, reserved bits clear).
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; FRAG_HEADER] = b.try_into().ok()?;
        let (index, count, flags) = (b[4], b[5], b[6]);
        if count == 0 || count as usize > VIDEO_MAX_FRAGMENTS || index >= count || flags & 0xF0 != 0
        {
            return None;
        }
        Some(Self {
            frame_no: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            index,
            count,
            keyframe: flags & 1 != 0,
            codec: if flags & 2 != 0 {
                VideoCodec::H264
            } else {
                VideoCodec::H265
            },
            rotation: (flags >> 2) & 3,
            sent_ms: u32::from_be_bytes([b[7], b[8], b[9], b[10]]),
        })
    }
}

/// Fragments needed for a frame of `len` bytes; `None` for 0 or too large.
pub fn fragment_count(len: usize) -> Option<usize> {
    if len == 0 || len > VIDEO_MAX_FRAME {
        None
    } else {
        Some(len.div_ceil(VIDEO_FRAGMENT_MAX))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Assembled {
    /// Stored; the frame is not complete.
    Partial,
    /// A frame is ready for `pop_ready`.
    Complete,
    /// Refused or ignored (malformed, repeat, stale, or waiting for a keyframe).
    Dropped,
    /// A gap just began: ask the sender for a keyframe.
    NeedKeyframe,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TooSmall;

#[derive(Debug, PartialEq, Eq)]
pub struct ReadyFrame {
    pub frame_no: u32,
    pub len: usize,
    pub keyframe: bool,
    pub codec: VideoCodec,
    pub rotation: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Partial,
    Ready,
}

struct Slot {
    buf: Vec<u8>,
    state: State,
    frame_no: u32,
    count: u8,
    keyframe: bool,
    codec: VideoCodec,
    rotation: u8,
    have: u64,
    got: u8,
    /// Length of the final fragment, once it has arrived.
    last_len: usize,
    len: usize,
}

impl Slot {
    fn new() -> Self {
        Self {
            buf: vec![0; VIDEO_MAX_FRAME],
            state: State::Free,
            frame_no: 0,
            count: 0,
            keyframe: false,
            codec: VideoCodec::H265,
            rotation: 0,
            have: 0,
            got: 0,
            last_len: 0,
            len: 0,
        }
    }
}

/// `a` is later than `b` in wrapping frame numbers.
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

pub struct Reassembler {
    slots: [Slot; SLOTS],
    /// Newest frame number that completed (delivered or not).
    last: Option<u32>,
    waiting: bool,
    delivered: u64,
    lost: u64,
    /// Fragments dropped for belonging to a frame no newer than the last
    /// one completed (they arrived after a later frame: reordering).
    stale: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Nothing decodes before the first keyframe, so it starts waiting.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::new()),
            last: None,
            waiting: true,
            delivered: 0,
            lost: 0,
            stale: 0,
        }
    }

    pub fn waiting_for_keyframe(&self) -> bool {
        self.waiting
    }

    /// (frames delivered, frames lost): lost counts frame numbers skipped
    /// by a gap plus frames that completed but could not be used.
    pub fn stats(&self) -> (u64, u64) {
        (self.delivered, self.lost)
    }

    /// Fragments that arrived after a later frame had completed.
    pub fn stale_fragments(&self) -> u64 {
        self.stale
    }

    #[cfg(test)]
    pub fn in_flight(&self) -> usize {
        self.slots.iter().filter(|s| s.state != State::Free).count()
    }

    /// Begin (or stay in) the keyframe wait: every non-key frame still being
    /// assembled is useless. Returns true if the wait just began.
    fn start_wait(&mut self, drop_ready: bool) -> bool {
        let began = !self.waiting;
        self.waiting = true;
        for s in self.slots.iter_mut() {
            let drop = match s.state {
                State::Free => false,
                State::Partial => !s.keyframe,
                State::Ready => drop_ready && !s.keyframe,
            };
            if drop {
                s.state = State::Free;
            }
        }
        began
    }

    /// The decoder lost its place: wait for a fresh keyframe.
    pub fn force_keyframe_wait(&mut self) {
        self.start_wait(true);
    }

    fn need(&mut self, drop_ready: bool) -> Assembled {
        if self.start_wait(drop_ready) {
            Assembled::NeedKeyframe
        } else {
            Assembled::Dropped
        }
    }

    pub fn push(&mut self, h: FragHeader, payload: &[u8]) -> Assembled {
        let count = h.count as usize;
        if count == 0 || count > VIDEO_MAX_FRAGMENTS || h.index >= h.count || h.rotation > 3 {
            return Assembled::Dropped;
        }
        let last_frag = h.index + 1 == h.count;
        if payload.is_empty()
            || payload.len() > VIDEO_FRAGMENT_MAX
            || (!last_frag && payload.len() != VIDEO_FRAGMENT_MAX)
        {
            return Assembled::Dropped;
        }
        if let Some(l) = self.last {
            if !newer(h.frame_no, l) {
                self.stale = self.stale.saturating_add(1);
                return Assembled::Dropped;
            }
        }
        let existing = self
            .slots
            .iter()
            .position(|s| s.state != State::Free && s.frame_no == h.frame_no);
        let at = match existing {
            Some(i) => {
                let s = &self.slots[i];
                if s.state == State::Ready || s.have & (1u64 << h.index) != 0 {
                    return Assembled::Dropped;
                }
                if s.count != h.count
                    || s.keyframe != h.keyframe
                    || s.codec != h.codec
                    || s.rotation != h.rotation
                {
                    // One frame number, two stories: abandon it.
                    self.slots[i].state = State::Free;
                    return self.need(false);
                }
                i
            }
            None => {
                if self.waiting && !h.keyframe {
                    return Assembled::Dropped;
                }
                let i = match self.slots.iter().position(|s| s.state == State::Free) {
                    Some(i) => i,
                    None => {
                        // Evict the oldest frame, but never for an older one.
                        let mut oldest = 0;
                        for j in 1..SLOTS {
                            if newer(self.slots[oldest].frame_no, self.slots[j].frame_no) {
                                oldest = j;
                            }
                        }
                        if !newer(h.frame_no, self.slots[oldest].frame_no) {
                            return Assembled::Dropped;
                        }
                        let was_ready = self.slots[oldest].state == State::Ready;
                        if was_ready {
                            self.lost = self.lost.saturating_add(1);
                        }
                        self.slots[oldest].state = State::Free;
                        let r = self.need(was_ready);
                        if !h.keyframe {
                            return r;
                        }
                        oldest
                    }
                };
                let s = &mut self.slots[i];
                s.state = State::Partial;
                s.frame_no = h.frame_no;
                s.count = h.count;
                s.keyframe = h.keyframe;
                s.codec = h.codec;
                s.rotation = h.rotation;
                s.have = 0;
                s.got = 0;
                s.last_len = 0;
                s.len = 0;
                i
            }
        };
        let s = &mut self.slots[at];
        let off = h.index as usize * VIDEO_FRAGMENT_MAX;
        // off + payload.len() <= 48 * 8192 == VIDEO_MAX_FRAME
        s.buf[off..off + payload.len()].copy_from_slice(payload);
        s.have |= 1u64 << h.index;
        s.got += 1;
        if last_frag {
            s.last_len = payload.len();
        }
        if s.got < s.count {
            return Assembled::Partial;
        }
        s.len = (count - 1) * VIDEO_FRAGMENT_MAX + s.last_len;
        s.state = State::Ready;
        self.finish(at)
    }

    /// Slot `at` just completed.
    fn finish(&mut self, at: usize) -> Assembled {
        let (n, key) = (self.slots[at].frame_no, self.slots[at].keyframe);
        let gap = match self.last {
            Some(l) => {
                let skipped = n.wrapping_sub(l).wrapping_sub(1);
                self.lost = self.lost.saturating_add(u64::from(skipped));
                skipped != 0
            }
            None => false,
        };
        self.last = Some(n);
        // Anything still half-built that is older than this will never finish.
        for j in 0..SLOTS {
            if j != at && self.slots[j].state == State::Partial && newer(n, self.slots[j].frame_no)
            {
                self.slots[j].state = State::Free;
            }
        }
        if key {
            self.waiting = false;
            return Assembled::Complete;
        }
        if self.waiting || gap {
            self.slots[at].state = State::Free;
            self.lost = self.lost.saturating_add(1);
            return if self.start_wait(false) {
                Assembled::NeedKeyframe
            } else {
                Assembled::Dropped
            };
        }
        Assembled::Complete
    }

    /// The oldest complete frame, copied into `out`. If `out` is too small
    /// the frame is dropped and the keyframe wait begins.
    pub fn pop_ready(&mut self, out: &mut [u8]) -> Result<Option<ReadyFrame>, TooSmall> {
        let mut pick: Option<usize> = None;
        for (j, s) in self.slots.iter().enumerate() {
            if s.state == State::Ready
                && pick.map_or(true, |p| newer(self.slots[p].frame_no, s.frame_no))
            {
                pick = Some(j);
            }
        }
        let Some(i) = pick else {
            return Ok(None);
        };
        let s = &mut self.slots[i];
        s.state = State::Free;
        if out.len() < s.len {
            self.lost = self.lost.saturating_add(1);
            self.start_wait(true);
            return Err(TooSmall);
        }
        out[..s.len].copy_from_slice(&s.buf[..s.len]);
        self.delivered = self.delivered.saturating_add(1);
        Ok(Some(ReadyFrame {
            frame_no: s.frame_no,
            len: s.len,
            keyframe: s.keyframe,
            codec: s.codec,
            rotation: s.rotation,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(frame_no: u32, index: u8, count: u8, keyframe: bool) -> FragHeader {
        FragHeader {
            frame_no,
            index,
            count,
            keyframe,
            codec: VideoCodec::H265,
            rotation: 1,
            sent_ms: frame_no.wrapping_mul(33),
        }
    }
    fn full() -> Vec<u8> {
        vec![0x5A; VIDEO_FRAGMENT_MAX]
    }

    #[test]
    fn header_round_trips_and_refuses_bad_input() {
        for (k, c, r) in [(true, VideoCodec::H265, 0), (false, VideoCodec::H264, 3)] {
            let h = FragHeader {
                frame_no: 0xA1B2C3D4,
                index: 2,
                count: 5,
                keyframe: k,
                codec: c,
                rotation: r,
                sent_ms: 0xFFFF_FFF0,
            };
            let b = h.encode();
            assert_eq!(&b[..4], &0xA1B2C3D4u32.to_be_bytes());
            assert_eq!(&b[7..], &0xFFFF_FFF0u32.to_be_bytes());
            assert_eq!(FragHeader::decode(&b), Some(h));
        }
        let ok = hdr(1, 0, 1, true).encode();
        assert!(FragHeader::decode(&ok[..10]).is_none());
        assert!(FragHeader::decode(&[ok.as_slice(), &[0]].concat()).is_none());
        let mut b = ok;
        b[5] = 0;
        assert!(FragHeader::decode(&b).is_none(), "count 0");
        let mut b = ok;
        b[5] = 49;
        assert!(FragHeader::decode(&b).is_none());
        let mut b = ok;
        b[4] = 1;
        assert!(FragHeader::decode(&b).is_none(), "index >= count");
        let mut b = ok;
        b[6] |= 0x10;
        assert!(FragHeader::decode(&b).is_none(), "reserved bits");
    }

    #[test]
    fn fragment_count_bounds() {
        assert_eq!(fragment_count(1), Some(1));
        assert_eq!(fragment_count(8192), Some(1));
        assert_eq!(fragment_count(8193), Some(2));
        assert_eq!(fragment_count(VIDEO_MAX_FRAME), Some(48));
        assert_eq!(fragment_count(0), None);
        assert_eq!(fragment_count(VIDEO_MAX_FRAME + 1), None);
    }

    #[test]
    fn fragments_reassemble_in_any_order_and_out_of_order_frames_flag_a_gap() {
        let mut r = Reassembler::new();
        let mut orig = full();
        orig.extend(full());
        orig.extend(vec![7u8; 100]);
        orig[0] = 1;
        orig[8192] = 2;
        orig[16384] = 3;
        let part = |i: usize| &orig[i * 8192..((i + 1) * 8192).min(orig.len())];
        assert_eq!(r.push(hdr(0, 2, 3, true), part(2)), Assembled::Partial);
        assert_eq!(r.push(hdr(0, 0, 3, true), part(0)), Assembled::Partial);
        assert_eq!(r.push(hdr(0, 1, 3, true), part(1)), Assembled::Complete);
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        let f = r.pop_ready(&mut out).unwrap().unwrap();
        assert_eq!(
            (f.frame_no, f.len, f.keyframe, f.codec, f.rotation),
            (0, orig.len(), true, VideoCodec::H265, 1)
        );
        assert_eq!(&out[..f.len], &orig[..]);
        assert!(!r.waiting_for_keyframe());
        assert!(r.pop_ready(&mut out).unwrap().is_none());

        // too small: frame gone, keyframe wait begins
        assert_eq!(r.push(hdr(1, 0, 1, true), &[9; 40]), Assembled::Complete);
        let mut small = [0u8; 10];
        assert_eq!(r.pop_ready(&mut small), Err(TooSmall));
        assert!(r.waiting_for_keyframe());
        assert!(r.pop_ready(&mut out).unwrap().is_none());

        // gap: frame 3 partial, frame 4 complete -> NeedKeyframe
        assert_eq!(r.push(hdr(2, 0, 1, true), &[1; 5]), Assembled::Complete);
        assert!(!r.waiting_for_keyframe());
        r.pop_ready(&mut out).unwrap().unwrap();
        assert_eq!(r.push(hdr(3, 0, 2, false), &full()), Assembled::Partial);
        assert_eq!(
            r.push(hdr(4, 0, 1, false), &[1; 5]),
            Assembled::NeedKeyframe
        );
        assert!(r.waiting_for_keyframe());
        assert_eq!(r.push(hdr(5, 0, 1, false), &[1; 5]), Assembled::Dropped);
        assert_eq!(r.push(hdr(6, 0, 1, true), &[1; 5]), Assembled::Complete);
        assert!(!r.waiting_for_keyframe());
        let f = r.pop_ready(&mut out).unwrap().unwrap();
        assert_eq!(f.frame_no, 6);
        assert!(r.pop_ready(&mut out).unwrap().is_none());
        let (d, l) = r.stats();
        // delivered: frames 0, 2, 6. lost: the too-small frame, frame 3
        // (never completed), frame 4 (completed but undecodable), frame 5.
        assert_eq!((d, l), (3, 4));
    }

    #[test]
    fn reassembler_survives_hostile_fragments() {
        let mut r = Reassembler::new();
        let mut out = vec![0u8; VIDEO_MAX_FRAME];
        // keyframe 0 delivered first so later frames are in sequence
        assert_eq!(r.push(hdr(0, 0, 1, true), &[1; 9]), Assembled::Complete);
        r.pop_ready(&mut out).unwrap().unwrap();
        // header-level nonsense that bypassed decode
        assert_eq!(r.push(hdr(1, 0, 0, true), &[1; 9]), Assembled::Dropped);
        assert_eq!(r.push(hdr(1, 0, 49, true), &[1; 9]), Assembled::Dropped);
        assert_eq!(r.push(hdr(1, 2, 2, true), &[1; 9]), Assembled::Dropped);
        assert_eq!(
            r.push(hdr(1, 0, 2, true), &vec![0; VIDEO_FRAGMENT_MAX + 1]),
            Assembled::Dropped
        );
        assert_eq!(r.push(hdr(1, 0, 2, true), &[]), Assembled::Dropped);
        // a non-final fragment must be full-size
        assert_eq!(r.push(hdr(1, 0, 2, true), &[1; 9]), Assembled::Dropped);
        // count changes within one frame_no: the frame is abandoned
        assert_eq!(r.push(hdr(1, 0, 3, true), &full()), Assembled::Partial);
        assert_eq!(r.in_flight(), 1);
        assert_eq!(r.push(hdr(1, 1, 2, true), &full()), Assembled::NeedKeyframe);
        assert_eq!(r.in_flight(), 0, "the inconsistent frame is gone");
        // maximal frame is the exact limit
        let mut r2 = Reassembler::new();
        for i in 0..48u8 {
            let p = r2.push(hdr(0, i, 48, true), &full());
            assert_eq!(
                p,
                if i == 47 {
                    Assembled::Complete
                } else {
                    Assembled::Partial
                }
            );
        }
        assert_eq!(
            r2.pop_ready(&mut out).unwrap().unwrap().len,
            VIDEO_MAX_FRAME
        );
        // a flood of distinct frame numbers, 1 of 2 fragments each
        for n in 0..10_000u32 {
            let _ = r.push(hdr(10 + n, 0, 2, n % 2 == 0), &full());
            assert!(r.in_flight() <= 4);
        }
        // duplicate and replayed fragments, wild frame numbers
        for n in [u32::MAX, 0, 5, 1 << 31, (1 << 31) + 1] {
            let _ = r.push(hdr(n, 0, 2, true), &full());
            let _ = r.push(hdr(n, 0, 2, true), &full());
            assert!(r.in_flight() <= 4);
        }
        // a clean keyframe still assembles
        let k = 0x4000_0000;
        assert_eq!(r.push(hdr(k, 0, 2, true), &full()), Assembled::Partial);
        assert_eq!(r.push(hdr(k, 1, 2, true), &[3; 10]), Assembled::Complete);
        let mut f = None;
        while let Some(x) = r.pop_ready(&mut out).unwrap() {
            f = Some(x);
        }
        assert_eq!(
            f.map(|f| (f.frame_no, f.len)),
            Some((k, VIDEO_FRAGMENT_MAX + 10))
        );
        assert!(!r.waiting_for_keyframe());
    }

    #[test]
    fn force_wait_discards_non_key_and_waits_for_a_keyframe() {
        let mut r = Reassembler::new();
        assert!(
            r.waiting_for_keyframe(),
            "nothing decodes before the first keyframe"
        );
        assert_eq!(r.push(hdr(0, 0, 1, false), &[1]), Assembled::Dropped);
        assert_eq!(r.push(hdr(1, 0, 1, true), &[1]), Assembled::Complete);
        let mut out = [0u8; 16];
        r.pop_ready(&mut out).unwrap().unwrap();
        assert_eq!(r.push(hdr(2, 0, 1, false), &[1]), Assembled::Complete);
        assert_eq!(r.push(hdr(3, 0, 2, false), &full()), Assembled::Partial);
        r.force_keyframe_wait();
        assert!(r.waiting_for_keyframe());
        assert_eq!(r.in_flight(), 0);
        assert!(
            r.pop_ready(&mut out).unwrap().is_none(),
            "non-key ready frames are discarded"
        );
    }

    #[test]
    fn evicting_a_ready_frame_discards_the_non_key_frames_behind_it() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(hdr(0, 0, 1, true), &[1]), Assembled::Complete);
        for n in 1..4 {
            assert_eq!(r.push(hdr(n, 0, 1, false), &[1]), Assembled::Complete);
        }
        assert_eq!(r.in_flight(), 4);
        // all four slots hold unpopped frames; a newer keyframe evicts frame 0
        assert_eq!(r.push(hdr(9, 0, 2, true), &full()), Assembled::Partial);
        assert!(r.waiting_for_keyframe());
        let mut out = [0u8; 16];
        assert!(r.pop_ready(&mut out).unwrap().is_none());
        assert_eq!(r.in_flight(), 1, "only the new keyframe is left");
        assert_eq!(r.stats(), (0, 1));
    }
}
