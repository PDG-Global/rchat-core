//! The voice codec (spec §6) behind a trait, so it can be swapped later
//! (owner decision 2026-10-26: libopus now, maybe an in-house port later).
//! Fixed-size buffers only: nothing allocates per frame. libopus is behind
//! the `calls-codec` feature (D32): without it `OpusCodec` doesn't exist
//! and a call fails with `CodecError::Unavailable`.

use super::FRAME_SAMPLES;
#[cfg(feature = "calls-codec")]
use super::{BITRATE_NORMAL, EXPECTED_LOSS_PCT, MAX_OPUS_BYTES};
#[cfg(feature = "calls-codec")]
use opus_codec::types::{Application, Bitrate, Channels, SampleRate, Signal};
#[cfg(feature = "calls-codec")]
use opus_codec::{Decoder, Encoder};

/// Why the codec failed. `Debug` only: never shown to anyone.
#[derive(Debug)]
pub enum CodecError {
    /// This library was built without the `calls-codec` feature (D32).
    Unavailable,
    /// The codec produced fewer or more samples than one 20 ms frame; the
    /// playback path treats that as a missing frame.
    Short,
    /// `CallMedia::start` ran on a thread with no tokio runtime (the call
    /// connections need one; a spawn from outside it would panic).
    NoRuntime,
    /// libopus refused (a bad packet, a bad setting).
    #[cfg(feature = "calls-codec")]
    Opus(#[allow(dead_code)] opus_codec::Error),
}

#[cfg(feature = "calls-codec")]
impl From<opus_codec::Error> for CodecError {
    fn from(e: opus_codec::Error) -> Self {
        Self::Opus(e)
    }
}

pub trait Codec: Send {
    /// One 20 ms frame into `out`; returns the packet length.
    fn encode(&mut self, pcm: &[i16; FRAME_SAMPLES], out: &mut [u8]) -> Result<usize, CodecError>;
    fn decode(&mut self, packet: &[u8], out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError>;
    /// The frame *before* `next_packet`, from its in-band FEC.
    fn decode_fec(
        &mut self,
        next_packet: &[u8],
        out: &mut [i16; FRAME_SAMPLES],
    ) -> Result<(), CodecError>;
    /// Opus packet-loss concealment for one missing frame.
    fn conceal(&mut self, out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError>;
    fn set_bitrate(&mut self, bps: i32) -> Result<(), CodecError>;
    fn bitrate(&self) -> i32;
    /// Whether `packet` carries in-band FEC for the frame before it. The
    /// playback path checks this before `decode_fec`.
    fn packet_has_lbrr(&self, _packet: &[u8]) -> bool {
        true
    }
}

/// libopus through `opus-codec` (bundled 1.6.1).
#[cfg(feature = "calls-codec")]
pub struct OpusCodec {
    pub(crate) enc: Encoder,
    dec: Decoder,
    bitrate: i32,
}

#[cfg(feature = "calls-codec")]
impl OpusCodec {
    pub const APPLICATION: Application = Application::Voip;

    pub fn new() -> Result<Self, CodecError> {
        let mut enc = Encoder::new(SampleRate::Hz48000, Channels::Mono, Self::APPLICATION)?;
        enc.set_bitrate(Bitrate::Custom(BITRATE_NORMAL))?;
        enc.set_vbr(false)?;
        enc.set_inband_fec(true)?;
        enc.set_packet_loss_perc(EXPECTED_LOSS_PCT)?;
        enc.set_dtx(false)?;
        enc.set_signal(Signal::Voice)?;
        let dec = Decoder::new(SampleRate::Hz48000, Channels::Mono)?;
        Ok(Self {
            enc,
            dec,
            bitrate: BITRATE_NORMAL,
        })
    }
}

#[cfg(feature = "calls-codec")]
impl Codec for OpusCodec {
    fn encode(&mut self, pcm: &[i16; FRAME_SAMPLES], out: &mut [u8]) -> Result<usize, CodecError> {
        let cap = out.len().min(MAX_OPUS_BYTES);
        Ok(self.enc.encode(pcm, &mut out[..cap])?)
    }

    fn decode(&mut self, packet: &[u8], out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
        if packet.is_empty() {
            return Err(opus_codec::Error::BadArg.into());
        }
        full(self.dec.decode(packet, out, false)?)
    }

    fn decode_fec(
        &mut self,
        next_packet: &[u8],
        out: &mut [i16; FRAME_SAMPLES],
    ) -> Result<(), CodecError> {
        full(self.dec.decode(next_packet, out, true)?)
    }

    fn conceal(&mut self, out: &mut [i16; FRAME_SAMPLES]) -> Result<(), CodecError> {
        full(self.dec.decode(&[], out, false)?)
    }

    fn set_bitrate(&mut self, bps: i32) -> Result<(), CodecError> {
        self.enc.set_bitrate(Bitrate::Custom(bps))?;
        self.bitrate = bps;
        Ok(())
    }

    fn bitrate(&self) -> i32 {
        self.bitrate
    }

    fn packet_has_lbrr(&self, packet: &[u8]) -> bool {
        opus_codec::packet::packet_has_lbrr(packet).unwrap_or(false)
    }
}

/// libopus returns the samples it wrote; anything but a whole frame is a failure.
#[cfg(feature = "calls-codec")]
fn full(samples: usize) -> Result<(), CodecError> {
    if samples == FRAME_SAMPLES {
        Ok(())
    } else {
        Err(CodecError::Short)
    }
}

#[cfg(all(test, feature = "calls-codec"))]
mod tests {
    use super::*;
    use crate::call::{FRAME_SAMPLES, MAX_OPUS_BYTES};

    /// A speech-like, non-stationary test signal: two partials with a
    /// gliding pitch under a 4 Hz syllable envelope (PLC can't guess it).
    /// The envelope dips to near silence 8 times a second, as speech does.
    fn speech(frame: usize) -> [i16; FRAME_SAMPLES] {
        core::array::from_fn(|i| {
            let t = (frame * FRAME_SAMPLES + i) as f64 / 48_000.0;
            let f0 = 140.0 + 60.0 * (2.0 * std::f64::consts::PI * 0.7 * t).sin();
            let env = 0.5 + 0.5 * (2.0 * std::f64::consts::PI * 4.0 * t).sin();
            let s = (2.0 * std::f64::consts::PI * f0 * t).sin()
                + 0.4 * (2.0 * std::f64::consts::PI * 3.1 * f0 * t).sin();
            (s * env * 9000.0) as i16
        })
    }

    fn rms(pcm: &[i16]) -> f64 {
        (pcm.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / pcm.len() as f64).sqrt()
    }

    /// D30: a frame louder than this (RMS of 32768) is voiced. libopus
    /// sends no FEC for near-silent frames, so only voiced ones are checked.
    const VOICED_RMS: f64 = 2000.0;

    /// Energy (dB) in 24 bands of 250 Hz up to 6 kHz, from a direct DFT at
    /// 50 Hz bins: what a frame sounds like, without its phase (neither FEC
    /// nor PLC keeps the phase, so a waveform comparison means nothing).
    fn bands_db(pcm: &[i16]) -> [f64; 24] {
        core::array::from_fn(|band| {
            let mut energy = 0.0;
            for bin in band * 5 + 1..=band * 5 + 5 {
                let (mut re, mut im) = (0.0f64, 0.0f64);
                for (n, s) in pcm.iter().enumerate() {
                    let w = 2.0 * std::f64::consts::PI * bin as f64 * n as f64 / pcm.len() as f64;
                    re += f64::from(*s) * w.cos();
                    im -= f64::from(*s) * w.sin();
                }
                energy += re * re + im * im;
            }
            10.0 * (energy + 1.0).log10()
        })
    }

    /// Log-spectral distance in dB (root mean square over the bands).
    fn spectral_distance_db(reference: &[i16], test: &[i16]) -> f64 {
        let (r, t) = (bands_db(reference), bands_db(test));
        (r.iter().zip(&t).map(|(a, b)| (a - b).powi(2)).sum::<f64>() / r.len() as f64).sqrt()
    }

    /// How far the loudness is off, in dB.
    fn loudness_error_db(reference: &[i16], test: &[i16]) -> f64 {
        (20.0 * (rms(test).max(1.0) / rms(reference).max(1.0)).log10()).abs()
    }

    /// A decoder that has decoded `packets` in order; returns it and the last frame.
    fn decoded(packets: &[Vec<u8>]) -> (OpusCodec, [i16; FRAME_SAMPLES]) {
        let mut dec = OpusCodec::new().unwrap();
        let mut out = [0i16; FRAME_SAMPLES];
        for p in packets {
            dec.decode(p, &mut out).unwrap();
        }
        (dec, out)
    }

    /// Spec §6: VOIP, 48 kHz mono, CBR 24 kbps, FEC on, expected loss 10%, DTX off.
    #[test]
    fn the_encoder_is_set_up_as_the_spec_says() {
        let mut c = OpusCodec::new().unwrap();
        assert_eq!(
            OpusCodec::APPLICATION as i32,
            opus_codec::OPUS_APPLICATION_VOIP as i32
        );
        assert_eq!(c.enc.sample_rate(), opus_codec::types::SampleRate::Hz48000);
        assert_eq!(c.enc.channels(), opus_codec::types::Channels::Mono);
        assert_eq!(
            c.enc.bitrate().unwrap(),
            opus_codec::types::Bitrate::Custom(24_000)
        );
        assert!(!c.enc.vbr().unwrap(), "CBR");
        assert!(c.enc.inband_fec().unwrap(), "in-band FEC on");
        assert_eq!(c.enc.packet_loss_perc().unwrap(), 10);
        assert!(!c.enc.dtx().unwrap(), "DTX off");
        assert_eq!(c.bitrate(), 24_000);
    }

    /// CBR keeps packet sizes independent of what is said (§6): speech and
    /// silence give the same size, 60 bytes at 24 kbps and 40 at 16 kbps.
    #[test]
    fn packet_sizes_do_not_depend_on_the_audio() {
        let mut c = OpusCodec::new().unwrap();
        let mut out = [0u8; MAX_OPUS_BYTES];
        let mut sizes = std::collections::BTreeSet::new();
        for f in 0..50 {
            sizes.insert(c.encode(&speech(f), &mut out).unwrap());
            sizes.insert(c.encode(&[0; FRAME_SAMPLES], &mut out).unwrap());
        }
        assert_eq!(sizes.into_iter().collect::<Vec<_>>(), vec![60]);
        c.set_bitrate(16_000).unwrap();
        assert_eq!(c.bitrate(), 16_000);
        for f in 0..10 {
            assert_eq!(c.encode(&speech(f), &mut out).unwrap(), 40);
        }
    }

    /// Spec §6/§9, D30: most voiced frames have FEC in the next packet, and
    /// a lost voiced frame rebuilt from it sounds no worse than PLC, by
    /// spectrum and by loudness, on average over every such frame.
    #[test]
    fn a_missing_voiced_frame_is_rebuilt_from_the_next_packets_fec_no_worse_than_plc() {
        let mut enc = OpusCodec::new().unwrap();
        let mut packets = Vec::new();
        for f in 0..60 {
            let mut out = [0u8; MAX_OPUS_BYTES];
            let n = enc.encode(&speech(f), &mut out).unwrap();
            packets.push(out[..n].to_vec());
        }
        // Frames 10-57 (after warm-up, each with a next packet).
        let voiced: Vec<usize> = (10..58).filter(|&k| rms(&speech(k)) > VOICED_RMS).collect();
        let covered: Vec<usize> = voiced
            .iter()
            .copied()
            .filter(|&k| opus_codec::packet::packet_has_lbrr(&packets[k + 1]).unwrap())
            .collect();
        assert!(voiced.len() >= 20, "enough voiced frames: {}", voiced.len());
        assert!(
            covered.len() * 10 >= voiced.len() * 8,
            "FEC for at least 80% of voiced frames: {} of {}",
            covered.len(),
            voiced.len()
        );
        let (mut fec_sd, mut plc_sd, mut fec_ld, mut plc_ld) = (0.0, 0.0, 0.0, 0.0);
        for &lost in &covered {
            let (_, reference) = decoded(&packets[..=lost]);
            let (mut fec, _) = decoded(&packets[..lost]);
            let mut rebuilt = [0i16; FRAME_SAMPLES];
            fec.decode_fec(&packets[lost + 1], &mut rebuilt).unwrap();
            let (mut plc, _) = decoded(&packets[..lost]);
            let mut concealed = [0i16; FRAME_SAMPLES];
            plc.conceal(&mut concealed).unwrap();
            assert!(
                concealed.iter().any(|s| *s != 0),
                "PLC produced audio for frame {lost}"
            );
            fec_sd += spectral_distance_db(&reference, &rebuilt);
            plc_sd += spectral_distance_db(&reference, &concealed);
            fec_ld += loudness_error_db(&reference, &rebuilt);
            plc_ld += loudness_error_db(&reference, &concealed);
        }
        let n = covered.len() as f64;
        let (fec_sd, plc_sd, fec_ld, plc_ld) = (fec_sd / n, plc_sd / n, fec_ld / n, plc_ld / n);
        assert!(
            fec_sd <= plc_sd,
            "spectral distance: FEC {fec_sd:.2} dB vs PLC {plc_sd:.2} dB"
        );
        assert!(
            fec_ld <= plc_ld,
            "loudness error: FEC {fec_ld:.2} dB vs PLC {plc_ld:.2} dB"
        );
    }

    #[test]
    fn encode_and_decode_allocate_nothing() {
        let mut c = OpusCodec::new().unwrap();
        let (mut packet, mut pcm) = ([0u8; MAX_OPUS_BYTES], [0i16; FRAME_SAMPLES]);
        let input = speech(3);
        let bytes = crate::alloc_probe::bytes_allocated(|| {
            for _ in 0..50 {
                let n = c.encode(&input, &mut packet).unwrap();
                c.decode(&packet[..n], &mut pcm).unwrap();
            }
            c.conceal(&mut pcm).unwrap();
        });
        assert_eq!(bytes, 0);
    }

    /// A 10 ms packet decodes to 480 samples: an error, never half a frame
    /// passed off as a whole one.
    #[test]
    fn a_short_decode_is_an_error() {
        let mut c = OpusCodec::new().unwrap();
        let mut out = [0i16; FRAME_SAMPLES];
        // TOC 0xF0: CELT fullband, 10 ms, mono, one frame.
        let ten_ms = [0xF0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(matches!(
            c.decode(&ten_ms, &mut out),
            Err(CodecError::Short)
        ));
    }

    #[test]
    fn a_garbage_packet_is_an_error_not_a_crash() {
        let mut c = OpusCodec::new().unwrap();
        let mut pcm = [0i16; FRAME_SAMPLES];
        // TOC 0xFF is code 3 with a count byte of 63 frames (1.26 s): invalid.
        assert!(c.decode(&[0xFF; 3], &mut pcm).is_err());
        assert!(
            c.decode(&[], &mut pcm).is_err(),
            "empty is conceal(), not decode()"
        );
    }
}
