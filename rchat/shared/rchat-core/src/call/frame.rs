//! Media frames (spec §4): `0x05 ‖ seq (8, BE) ‖ ChaCha20-Poly1305(key_dir,
//! nonce = 0x00000000 ‖ seq, aad = call_id ‖ seq, opus_frame)`. In place,
//! into caller buffers: nothing allocates per frame.

use super::{CallId, MAX_OPUS_BYTES, MAX_SEQ};
use crate::protocol::FRAME_TYPE_MEDIA;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

pub const FRAME_HEADER: usize = 1 + 8;
pub const TAG_LEN: usize = 16;
pub const MAX_WIRE_FRAME: usize = FRAME_HEADER + MAX_OPUS_BYTES + TAG_LEN;
/// Frames older than the newest by more than this are refused.
const WINDOW: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    SeqExhausted,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    Malformed,
    Tag,
    Duplicate,
    TooOld,
}

fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad(call_id: &CallId, seq: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..16].copy_from_slice(&call_id.0);
    a[16..].copy_from_slice(&seq.to_be_bytes());
    a
}

/// One direction's sealer; `seq` starts at 0 and never repeats.
/// (`ChaCha20Poly1305` wipes its key copy on drop: chacha20poly1305 0.10
/// depends on `zeroize` and implements it.)
pub struct FrameSealer {
    cipher: ChaCha20Poly1305,
    call_id: CallId,
    next_seq: u64,
}

impl FrameSealer {
    pub fn new(key: &[u8; 32], call_id: CallId) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            call_id,
            next_seq: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn starting_at(key: &[u8; 32], call_id: CallId, seq: u64) -> Self {
        Self {
            next_seq: seq,
            ..Self::new(key, call_id)
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn seal(&mut self, opus: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
        if self.next_seq >= MAX_SEQ {
            return Err(FrameError::SeqExhausted);
        }
        let n = FRAME_HEADER + opus.len() + TAG_LEN;
        if opus.len() > MAX_OPUS_BYTES || out.len() < n {
            return Err(FrameError::TooLarge);
        }
        let seq = self.next_seq;
        out[0] = FRAME_TYPE_MEDIA;
        out[1..FRAME_HEADER].copy_from_slice(&seq.to_be_bytes());
        let body = FRAME_HEADER..FRAME_HEADER + opus.len();
        out[body.clone()].copy_from_slice(opus);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce(seq)),
                &aad(&self.call_id, seq),
                &mut out[body.clone()],
            )
            .map_err(|_| FrameError::TooLarge)?;
        out[body.end..n].copy_from_slice(&tag);
        self.next_seq += 1;
        Ok(n)
    }
}

/// The other direction's opener: first copy of a seq wins (the same frame
/// arrives on both connections), a failed tag changes nothing.
pub struct FrameOpener {
    cipher: ChaCha20Poly1305,
    call_id: CallId,
    newest: Option<u64>,
    /// Bit i set: `newest - i` was opened.
    seen: u128,
}

impl FrameOpener {
    pub fn new(key: &[u8; 32], call_id: CallId) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            call_id,
            newest: None,
            seen: 0,
        }
    }

    fn check(&self, seq: u64) -> Result<(), OpenError> {
        let Some(newest) = self.newest else {
            return Ok(());
        };
        if seq > newest {
            return Ok(());
        }
        let back = newest - seq;
        if back >= WINDOW {
            return Err(OpenError::TooOld);
        }
        if self.seen & (1u128 << back) != 0 {
            return Err(OpenError::Duplicate);
        }
        Ok(())
    }

    fn commit(&mut self, seq: u64) {
        match self.newest {
            Some(newest) if seq <= newest => self.seen |= 1u128 << (newest - seq),
            Some(newest) => {
                let shift = seq - newest;
                self.seen = if shift >= WINDOW {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.newest = Some(seq);
            }
            None => {
                self.newest = Some(seq);
                self.seen = 1;
            }
        }
    }

    pub fn open(&mut self, frame: &[u8], out: &mut [u8]) -> Result<(u64, usize), OpenError> {
        self.open_inner(frame, out, false)
            .map(|(seq, len, _)| (seq, len))
    }

    /// As `open`, but a repeat of an already opened seq is authenticated
    /// too and returned with `false` ("not new") instead of `Duplicate`,
    /// so a caller can tell the second connection is alive. Forged repeats
    /// still fail the tag.
    pub fn open_counting_repeats(
        &mut self,
        frame: &[u8],
        out: &mut [u8],
    ) -> Result<(u64, usize, bool), OpenError> {
        self.open_inner(frame, out, true)
    }

    fn open_inner(
        &mut self,
        frame: &[u8],
        out: &mut [u8],
        repeats: bool,
    ) -> Result<(u64, usize, bool), OpenError> {
        if frame.len() < FRAME_HEADER + TAG_LEN || frame[0] != FRAME_TYPE_MEDIA {
            return Err(OpenError::Malformed);
        }
        let mut s = [0u8; 8];
        s.copy_from_slice(&frame[1..FRAME_HEADER]);
        let seq = u64::from_be_bytes(s);
        let len = frame.len() - FRAME_HEADER - TAG_LEN;
        if seq >= MAX_SEQ || len > MAX_OPUS_BYTES || out.len() < len {
            return Err(OpenError::Malformed);
        }
        let fresh = match self.check(seq) {
            Ok(()) => true,
            Err(OpenError::Duplicate) if repeats => false,
            Err(e) => return Err(e),
        };
        out[..len].copy_from_slice(&frame[FRAME_HEADER..FRAME_HEADER + len]);
        let tag = Tag::from_slice(&frame[FRAME_HEADER + len..]);
        if self
            .cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce(seq)),
                &aad(&self.call_id, seq),
                &mut out[..len],
                tag,
            )
            .is_err()
        {
            out[..len].fill(0);
            return Err(OpenError::Tag);
        }
        if fresh {
            self.commit(seq);
        }
        Ok((seq, len, fresh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::{keys, CallId, MAX_SEQ};

    fn id() -> CallId {
        CallId(core::array::from_fn(|i| i as u8 + 1))
    }

    fn key() -> [u8; 32] {
        *keys::derive(&id(), &[0x11; 32], &[0x22; 32], true).0.send
    }

    /// Spec §4 layout against a vector computed independently (a pure
    /// Python RFC 8439 ChaCha20-Poly1305, checked against RFC 8439 §2.8.2).
    #[test]
    fn a_frame_matches_the_fixed_vector() {
        let mut s = FrameSealer::starting_at(&key(), id(), 7);
        let mut out = [0u8; MAX_WIRE_FRAME];
        let n = s.seal(&[0xAB; 10], &mut out).unwrap();
        assert_eq!(
            hex::encode(&out[..n]),
            "05000000000000000726d4d3192da4668eead713e3579f0d2db06dda9a34df97d28647"
        );
        assert_eq!(n, 1 + 8 + 10 + 16, "about 24 bytes of overhead");
        let mut o = FrameOpener::new(&key(), id());
        let mut pt = [0u8; MAX_OPUS_BYTES];
        assert_eq!(o.open(&out[..n], &mut pt), Ok((7, 10)));
        assert_eq!(&pt[..10], &[0xAB; 10]);
    }

    #[test]
    fn tampered_frames_are_rejected() {
        let mut s = FrameSealer::new(&key(), id());
        let mut out = [0u8; MAX_WIRE_FRAME];
        let n = s.seal(&[0x55; 60], &mut out).unwrap();
        let mut pt = [0u8; MAX_OPUS_BYTES];
        for i in 1..n {
            let mut bad = out[..n].to_vec();
            bad[i] ^= 0x01;
            let mut o = FrameOpener::new(&key(), id());
            assert!(
                matches!(
                    o.open(&bad, &mut pt),
                    Err(OpenError::Tag) | Err(OpenError::Malformed)
                ),
                "byte {i}"
            );
        }
        let mut wrong_call = FrameOpener::new(&key(), CallId([9; 16]));
        assert_eq!(
            wrong_call.open(&out[..n], &mut pt),
            Err(OpenError::Tag),
            "aad binds the call id"
        );
        let mut wrong_key = FrameOpener::new(&[0; 32], id());
        assert_eq!(wrong_key.open(&out[..n], &mut pt), Err(OpenError::Tag));
        let mut wrong_type = out[..n].to_vec();
        wrong_type[0] = 0x02;
        assert_eq!(
            FrameOpener::new(&key(), id()).open(&wrong_type, &mut pt),
            Err(OpenError::Malformed)
        );
    }

    #[test]
    fn a_repeat_is_authenticated_and_reported_not_new() {
        let mut s = FrameSealer::new(&key(), id());
        let mut out = [0u8; MAX_WIRE_FRAME];
        let n = s.seal(&[1; 40], &mut out).unwrap();
        let mut o = FrameOpener::new(&key(), id());
        let mut pt = [0u8; MAX_OPUS_BYTES];
        assert_eq!(
            o.open_counting_repeats(&out[..n], &mut pt),
            Ok((0, 40, true))
        );
        assert_eq!(
            o.open_counting_repeats(&out[..n], &mut pt),
            Ok((0, 40, false))
        );
        // A forged repeat still fails the tag; plain `open` still says Duplicate.
        let mut forged = out[..n].to_vec();
        forged[n - 1] ^= 1;
        assert_eq!(
            o.open_counting_repeats(&forged, &mut pt),
            Err(OpenError::Tag)
        );
        assert_eq!(o.open(&out[..n], &mut pt), Err(OpenError::Duplicate));
    }

    #[test]
    fn duplicates_and_replays_are_rejected() {
        let mut s = FrameSealer::new(&key(), id());
        let mut frames = Vec::new();
        for _ in 0..300 {
            let mut out = [0u8; MAX_WIRE_FRAME];
            let n = s.seal(&[1; 40], &mut out).unwrap();
            frames.push(out[..n].to_vec());
        }
        let mut o = FrameOpener::new(&key(), id());
        let mut pt = [0u8; MAX_OPUS_BYTES];
        for f in &frames[..3] {
            assert!(o.open(f, &mut pt).is_ok());
        }
        // The same frame from the other connection: the first copy won.
        assert_eq!(o.open(&frames[1], &mut pt), Err(OpenError::Duplicate));
        // Out of order within the window is fine, once.
        assert_eq!(o.open(&frames[200], &mut pt).map(|r| r.0), Ok(200));
        assert_eq!(o.open(&frames[150], &mut pt).map(|r| r.0), Ok(150));
        assert_eq!(o.open(&frames[150], &mut pt), Err(OpenError::Duplicate));
        // More than 128 behind the newest: refused.
        assert_eq!(o.open(&frames[50], &mut pt), Err(OpenError::TooOld));
        // A failed tag changes nothing: the real frame still opens.
        let mut bad = frames[201].clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(o.open(&bad, &mut pt), Err(OpenError::Tag));
        assert_eq!(o.open(&frames[201], &mut pt).map(|r| r.0), Ok(201));
    }

    #[test]
    fn a_call_ends_at_2_pow_63_frames() {
        let mut s = FrameSealer::starting_at(&key(), id(), MAX_SEQ - 1);
        let mut out = [0u8; MAX_WIRE_FRAME];
        assert!(s.seal(&[0; 20], &mut out).is_ok());
        assert_eq!(s.seal(&[0; 20], &mut out), Err(FrameError::SeqExhausted));
        // A frame claiming seq >= 2^63 is malformed whatever its tag.
        let mut f = out.to_vec();
        f[1..9].copy_from_slice(&MAX_SEQ.to_be_bytes());
        let mut pt = [0u8; MAX_OPUS_BYTES];
        assert_eq!(
            FrameOpener::new(&key(), id()).open(&f[..45], &mut pt),
            Err(OpenError::Malformed)
        );
    }

    #[test]
    fn sealing_and_opening_allocate_nothing() {
        let mut s = FrameSealer::new(&key(), id());
        let mut o = FrameOpener::new(&key(), id());
        let (mut out, mut pt) = ([0u8; MAX_WIRE_FRAME], [0u8; MAX_OPUS_BYTES]);
        let bytes = crate::alloc_probe::bytes_allocated(|| {
            for _ in 0..50 {
                let n = s.seal(&[3; 60], &mut out).unwrap();
                o.open(&out[..n], &mut pt).unwrap();
            }
        });
        assert_eq!(bytes, 0);
    }
}
