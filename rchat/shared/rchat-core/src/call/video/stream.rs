//! Stream frames: `0x05 ‖ stream (1, >= 0x80) ‖ seq (8, BE) ‖
//! ChaCha20-Poly1305(key, nonce = 0^4 ‖ seq, aad = call_id ‖ stream ‖ seq,
//! body)`. One sealer per stream per direction for the call's life (its
//! key is never shared with another stream, so `seq` alone is a unique
//! nonce). Opening is in place into caller buffers.

use super::{MAX_VIDEO_WIRE, STREAM_HEADER};
use crate::call::frame::{FrameError, OpenError, TAG_LEN};
use crate::call::{CallId, MAX_SEQ};
use crate::protocol::FRAME_TYPE_MEDIA;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad(call_id: &CallId, stream: u8, seq: u64) -> [u8; 25] {
    let mut a = [0u8; 25];
    a[..16].copy_from_slice(&call_id.0);
    a[16] = stream;
    a[17..].copy_from_slice(&seq.to_be_bytes());
    a
}

pub struct StreamSealer {
    cipher: ChaCha20Poly1305,
    call_id: CallId,
    stream: u8,
    next_seq: u64,
}

impl StreamSealer {
    pub fn new(key: &[u8; 32], call_id: CallId, stream: u8) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            call_id,
            stream,
            next_seq: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn starting_at(key: &[u8; 32], call_id: CallId, stream: u8, seq: u64) -> Self {
        Self {
            next_seq: seq,
            ..Self::new(key, call_id, stream)
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn seal(&mut self, body: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
        if self.next_seq >= MAX_SEQ {
            return Err(FrameError::SeqExhausted);
        }
        let n = STREAM_HEADER + body.len() + TAG_LEN;
        if n > MAX_VIDEO_WIRE || out.len() < n {
            return Err(FrameError::TooLarge);
        }
        let seq = self.next_seq;
        out[0] = FRAME_TYPE_MEDIA;
        out[1] = self.stream;
        out[2..STREAM_HEADER].copy_from_slice(&seq.to_be_bytes());
        let b = STREAM_HEADER..STREAM_HEADER + body.len();
        out[b.clone()].copy_from_slice(body);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce(seq)),
                &aad(&self.call_id, self.stream, seq),
                &mut out[b.clone()],
            )
            .map_err(|_| FrameError::TooLarge)?;
        out[b.end..n].copy_from_slice(&tag);
        self.next_seq += 1;
        Ok(n)
    }
}

/// Sliding replay window of `window` sequence numbers: a bitmap indexed by
/// `seq % window`, allocated once.
pub(crate) struct ReplayWindow {
    bits: Vec<u64>,
    window: u64,
    newest: Option<u64>,
}

impl ReplayWindow {
    pub(crate) fn new(window: usize) -> Self {
        let window = window.max(1);
        Self {
            bits: vec![0; window.div_ceil(64)],
            window: window as u64,
            newest: None,
        }
    }

    fn get(&self, seq: u64) -> bool {
        let i = (seq % self.window) as usize;
        self.bits[i / 64] & (1 << (i % 64)) != 0
    }

    fn put(&mut self, seq: u64, on: bool) {
        let i = (seq % self.window) as usize;
        if on {
            self.bits[i / 64] |= 1 << (i % 64);
        } else {
            self.bits[i / 64] &= !(1 << (i % 64));
        }
    }

    pub(crate) fn check(&self, seq: u64) -> Result<(), OpenError> {
        let Some(newest) = self.newest else {
            return Ok(());
        };
        if seq > newest {
            return Ok(());
        }
        if newest - seq >= self.window {
            return Err(OpenError::TooOld);
        }
        if self.get(seq) {
            return Err(OpenError::Duplicate);
        }
        Ok(())
    }

    pub(crate) fn commit(&mut self, seq: u64) {
        match self.newest {
            Some(newest) if seq <= newest => {
                if newest - seq < self.window {
                    self.put(seq, true);
                }
            }
            Some(newest) => {
                let shift = seq - newest;
                if shift >= self.window {
                    self.bits.iter_mut().for_each(|w| *w = 0);
                } else {
                    for s in newest + 1..=seq {
                        self.put(s, false);
                    }
                }
                self.put(seq, true);
                self.newest = Some(seq);
            }
            None => {
                self.put(seq, true);
                self.newest = Some(seq);
            }
        }
    }
}

pub struct StreamOpener {
    cipher: ChaCha20Poly1305,
    call_id: CallId,
    stream: u8,
    window: ReplayWindow,
}

impl StreamOpener {
    pub fn new(key: &[u8; 32], call_id: CallId, stream: u8, window: usize) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            call_id,
            stream,
            window: ReplayWindow::new(window),
        }
    }

    /// The stream byte is not pre-checked: it is in the aad, so a frame of
    /// another stream fails the tag. A failed tag changes no state.
    pub fn open(&mut self, frame: &[u8], out: &mut [u8]) -> Result<(u64, usize), OpenError> {
        if frame.len() < STREAM_HEADER + TAG_LEN
            || frame.len() > MAX_VIDEO_WIRE
            || frame[0] != FRAME_TYPE_MEDIA
        {
            return Err(OpenError::Malformed);
        }
        let mut s = [0u8; 8];
        s.copy_from_slice(&frame[2..STREAM_HEADER]);
        let seq = u64::from_be_bytes(s);
        let len = frame.len() - STREAM_HEADER - TAG_LEN;
        if seq >= MAX_SEQ || out.len() < len {
            return Err(OpenError::Malformed);
        }
        self.window.check(seq)?;
        out[..len].copy_from_slice(&frame[STREAM_HEADER..STREAM_HEADER + len]);
        let tag = Tag::from_slice(&frame[STREAM_HEADER + len..]);
        if self
            .cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce(seq)),
                &aad(&self.call_id, frame[1], seq),
                &mut out[..len],
                tag,
            )
            .is_err()
        {
            out[..len].fill(0);
            return Err(OpenError::Tag);
        }
        // The aad used the frame's own stream byte; it must be ours.
        if frame[1] != self.stream {
            out[..len].fill(0);
            return Err(OpenError::Tag);
        }
        self.window.commit(seq);
        Ok((seq, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::frame::FrameSealer;
    use crate::call::keys;
    use crate::call::video::{is_stream_frame, STREAM_CONTROL, STREAM_VIDEO};

    fn id() -> CallId {
        CallId(core::array::from_fn(|i| i as u8 + 1))
    }
    fn vkeys() -> keys::VideoKeys {
        keys::derive(&id(), &[0x11; 32], &[0x22; 32], true).1
    }

    #[test]
    fn stream_frames_round_trip_and_reject_tamper_replay_duplicate() {
        let k = vkeys();
        let mut s = StreamSealer::new(&k.send, id(), STREAM_VIDEO);
        let mut o = StreamOpener::new(&k.send, id(), STREAM_VIDEO, 1024);
        let mut wire = [0u8; MAX_VIDEO_WIRE];
        let mut pt = [0u8; 8192];
        let n = s.seal(&[0xAB; 50], &mut wire).unwrap();
        assert_eq!(n, STREAM_HEADER + 50 + 16);
        assert_eq!((wire[0], wire[1]), (0x05, 0x81));
        assert_eq!(&wire[2..10], &0u64.to_be_bytes());
        assert_eq!(is_stream_frame(&wire[..n]), Some(STREAM_VIDEO));
        assert_eq!(o.open(&wire[..n], &mut pt), Ok((0, 50)));
        assert_eq!(&pt[..50], &[0xAB; 50]);
        // every byte flipped on a fresh, unopened frame is refused at the
        // AEAD (byte 0 is Malformed), and refusing changes no state
        let mut o = StreamOpener::new(&k.send, id(), STREAM_VIDEO, 1024);
        let mut s = StreamSealer::new(&k.send, id(), STREAM_VIDEO);
        let n = s.seal(&[0xAB; 50], &mut wire).unwrap();
        for i in 0..n {
            let mut bad = wire;
            bad[i] ^= 1;
            let r = o.open(&bad[..n], &mut pt);
            if i == 0 {
                assert_eq!(r, Err(OpenError::Malformed), "byte 0");
            } else {
                // a flipped seq byte is a still-fresh seq: the window lets
                // it through to the AEAD, which refuses it
                assert_eq!(r, Err(OpenError::Tag), "byte {i}");
            }
        }
        assert_eq!(o.open(&wire[..n], &mut pt), Ok((0, 50)), "no state changed");
        assert_eq!(o.open(&wire[..n], &mut pt), Err(OpenError::Duplicate));
        // seq 1..=1100 open; 0 is now too old
        for _ in 0..1100 {
            let m = s.seal(&[1], &mut wire).unwrap();
            let _ = o.open(&wire[..m], &mut pt).unwrap();
        }
        let mut old = StreamSealer::new(&k.send, id(), STREAM_VIDEO);
        let m = old.seal(&[0xAB; 50], &mut wire).unwrap();
        assert_eq!(o.open(&wire[..m], &mut pt), Err(OpenError::TooOld));
        // the control opener refuses a video frame at the tag
        let m = s.seal(&[2], &mut wire).unwrap();
        let mut c = StreamOpener::new(&k.send, id(), STREAM_CONTROL, 128);
        assert_eq!(c.open(&wire[..m], &mut pt), Err(OpenError::Tag));
    }

    #[test]
    fn replay_window_reordering_inside_the_window() {
        let mut w = ReplayWindow::new(1024);
        for q in [5u64, 3, 1023 + 5, 1000] {
            assert!(w.check(q).is_ok(), "{q}");
            w.commit(q);
        }
        assert_eq!(w.check(5), Err(OpenError::Duplicate));
        assert_eq!(w.check(3), Err(OpenError::TooOld));
        assert_eq!(w.check(1000), Err(OpenError::Duplicate));
        assert!(w.check(1001).is_ok());
        w.commit(1_000_000);
        assert_eq!(w.check(1_000_000), Err(OpenError::Duplicate));
        assert!(w.check(999_999).is_ok());
    }

    #[test]
    fn the_window_clears_bits_as_it_advances() {
        for seqs in [[5u64, 1000, 1100], [5, 1100, 1100]] {
            let mut w = ReplayWindow::new(1024);
            for q in seqs {
                if w.check(q).is_ok() {
                    w.commit(q);
                }
            }
            // 1029 shares a ring slot with 5; it is fresh, not a duplicate
            assert!(w.check(1029).is_ok(), "{seqs:?}");
        }
    }

    #[test]
    fn the_aad_binds_stream_and_call() {
        let k = vkeys();
        let mut s = StreamSealer::new(&k.send, id(), STREAM_VIDEO);
        let mut wire = [0u8; 64];
        let mut pt = [0u8; 64];
        let n = s.seal(&[3; 20], &mut wire).unwrap();
        // same key, same seq, byte 1 rewritten to the opener's own stream
        let mut f = wire;
        f[1] = STREAM_CONTROL;
        let mut c = StreamOpener::new(&k.send, id(), STREAM_CONTROL, 128);
        assert_eq!(c.open(&f[..n], &mut pt), Err(OpenError::Tag));
        // same key, another call
        let mut other = id();
        other.0[0] ^= 1;
        let mut o = StreamOpener::new(&k.send, other, STREAM_VIDEO, 128);
        assert_eq!(o.open(&wire[..n], &mut pt), Err(OpenError::Tag));
        assert_ne!(aad(&id(), STREAM_VIDEO, 1), aad(&id(), STREAM_CONTROL, 1));
        let mut ok = StreamOpener::new(&k.send, id(), STREAM_VIDEO, 128);
        assert_eq!(ok.open(&wire[..n], &mut pt), Ok((0, 20)));
    }

    #[test]
    fn audio_frames_are_never_stream_frames() {
        let k = keys::derive(&id(), &[0x11; 32], &[0x22; 32], true).0;
        for start in [0u64, 1, 0xFFFF, 1 << 40, MAX_SEQ - 1] {
            let mut s = FrameSealer::starting_at(&k.send, id(), start);
            let mut out = [0u8; crate::call::frame::MAX_WIRE_FRAME];
            let n = s.seal(&[7; 20], &mut out).unwrap();
            assert_eq!(is_stream_frame(&out[..n]), None, "seq {start}");
        }
        assert_eq!(is_stream_frame(&[0x05]), None);
        assert_eq!(is_stream_frame(&[0x06, 0x81]), None);
    }

    #[test]
    fn video_and_audio_keys_with_equal_seq_never_share_a_nonce_space() {
        let (ck, vk) = keys::derive(&id(), &[0x11; 32], &[0x22; 32], true);
        assert_ne!(*ck.send, *vk.send);
        assert_ne!(*vk.send, *vk.ctl_send);
        let mut a = StreamSealer::new(&ck.send, id(), STREAM_VIDEO);
        let mut v = StreamSealer::new(&vk.send, id(), STREAM_VIDEO);
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        let n = a.seal(&[9; 20], &mut x).unwrap();
        let m = v.seal(&[9; 20], &mut y).unwrap();
        assert_ne!(x[..n], y[..m]);
        let mut o = StreamOpener::new(&vk.send, id(), STREAM_VIDEO, 128);
        let mut pt = [0u8; 64];
        assert_eq!(o.open(&x[..n], &mut pt), Err(OpenError::Tag));
        assert_eq!(o.open(&y[..m], &mut pt), Ok((0, 20)));
    }

    #[test]
    fn the_sealer_stops_at_the_sequence_limit() {
        let k = vkeys();
        let mut s = StreamSealer::starting_at(&k.send, id(), STREAM_VIDEO, MAX_SEQ - 1);
        let mut wire = [0u8; 64];
        assert!(s.seal(&[1], &mut wire).is_ok());
        assert_eq!(s.seal(&[1], &mut wire), Err(FrameError::SeqExhausted));
        let mut small = [0u8; 10];
        let mut t = StreamSealer::new(&k.send, id(), STREAM_VIDEO);
        assert_eq!(t.seal(&[1], &mut small), Err(FrameError::TooLarge));
        assert_eq!(t.next_seq(), 0, "a refused seal burns no seq");
    }

    #[test]
    fn malformed_stream_frames_never_panic() {
        let k = vkeys();
        let mut o = StreamOpener::new(&k.send, id(), STREAM_VIDEO, 128);
        let mut pt = [0u8; 16];
        for len in [0usize, 1, 9, 10, 25, 26, 27] {
            let mut f = vec![0u8; len];
            if len > 1 {
                f[0] = 5;
                f[1] = 0x81;
            }
            assert!(o.open(&f, &mut pt).is_err());
        }
        let big = vec![5u8; MAX_VIDEO_WIRE + 1];
        assert_eq!(o.open(&big, &mut pt), Err(OpenError::Malformed));
        let mut f = vec![0u8; 100];
        f[0] = 5;
        f[1] = 0x81;
        f[2] = 0xFF; // seq >= MAX_SEQ
        assert_eq!(o.open(&f, &mut pt), Err(OpenError::Malformed));
    }
}
