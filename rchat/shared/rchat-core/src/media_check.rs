//! Photo and voice checks that run before any platform decoder (file-safety
//! spec §4), so both apps use identical rules: a photo must be JPEG, PNG,
//! WebP or HEIF by its magic, within 16 Mpx when its header is readable
//! (Decision 14); a voice note must be MPEG-4 with a known brand whose
//! top-level boxes chain cleanly to a `moov` (Android's `isMpeg4`, ported),
//! and must contain only AAC audio: every audio track is `mp4a` with one
//! sample entry whose `esds` names MPEG-4 Audio (object type 0x40), and
//! there is no video, text or subtitle track.
//! This is a defence-in-depth gate, not the pixel cap: a header the check
//! cannot read passes on its magic, so the platform header pixel caps (iOS
//! `IncomingMedia`, Android `PhotoPrep`) are required and must stay on every
//! decode path.
//!
//! Linear, allocation-free, never panics: every offset taken from the file
//! goes through `get` or a checked add (`usize` is 32 bits on armeabi-v7a
//! and overflow checks are on). Uses `std` only (the fuzz crate compiles
//! this file by path).

use std::cell::Cell;

pub const KIND_PHOTO: i32 = 1;
pub const KIND_VOICE: i32 = 2;
/// 16 Mpx: about 64 MB decoded (both apps' `maxImagePixels`).
pub const MAX_PHOTO_PIXELS: u64 = 4096 * 4096;

const HEIF_BRANDS: [&[u8; 4]; 5] = [b"heic", b"heix", b"mif1", b"msf1", b"hevc"];
const AV1_BRANDS: [&[u8; 4]; 3] = [b"avif", b"avis", b"av01"];
const VOICE_BRANDS: [&[u8; 4]; 4] = [b"M4A ", b"mp42", b"mp41", b"isom"];
const MAX_FTYP: u64 = 4_096;
const MAX_BOXES: usize = 1_024;
const MAX_JPEG_SEGMENTS: usize = 1_024;
const PNG_IHDR_HEAD: [u8; 8] = [0, 0, 0, 13, b'I', b'H', b'D', b'R'];
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// `Some(passes)` for `KIND_PHOTO` or `KIND_VOICE`, `None` for another kind.
pub fn check(kind: i32, bytes: &[u8]) -> Option<bool> {
    match kind {
        KIND_PHOTO => Some(photo_ok(bytes)),
        KIND_VOICE => Some(voice_ok(bytes)),
        _ => None,
    }
}

fn slice(b: &[u8], at: usize, n: usize) -> Option<&[u8]> {
    b.get(at..)?.get(..n)
}
fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = slice(b, at, 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}
fn le16(b: &[u8], at: usize) -> Option<u16> {
    let s = slice(b, at, 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}
fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = slice(b, at, 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s = slice(b, at, 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le24(b: &[u8], at: usize) -> Option<u32> {
    let s = slice(b, at, 3)?;
    Some(u32::from(s[0]) | (u32::from(s[1]) << 8) | (u32::from(s[2]) << 16))
}
/// A 64-bit box size; anything past the signed range is no box of ours.
fn be64(b: &[u8], at: usize) -> Option<u64> {
    let high = be32(b, at)?;
    if high > 0x7FFF_FFFF {
        return None;
    }
    Some((u64::from(high) << 32) | u64::from(be32(b, at.checked_add(4)?)?))
}

fn is_jpeg(b: &[u8]) -> bool {
    b.starts_with(&[0xFF, 0xD8, 0xFF])
}
fn is_png(b: &[u8]) -> bool {
    b.starts_with(&PNG_SIGNATURE)
}
fn is_webp(b: &[u8]) -> bool {
    b.starts_with(b"RIFF") && b.get(8..12) == Some(&b"WEBP"[..])
}

/// A well-formed `ftyp` box: its major brand and its compatible-brand bytes
/// (after the minor version).
fn ftyp_box(b: &[u8]) -> Option<([u8; 4], &[u8])> {
    if b.get(4..8) != Some(&b"ftyp"[..]) {
        return None;
    }
    let (size, header) = match be32(b, 0)? {
        0 => (b.len() as u64, 8usize),
        1 => (be64(b, 8)?, 16usize),
        s => (u64::from(s), 8usize),
    };
    let header64 = header as u64;
    if size < header64 || size > b.len() as u64 || size - header64 < 4 {
        return None;
    }
    let whole = b.get(..usize::try_from(size).ok()?)?; // size <= b.len()
    let brand = slice(whole, header, 4)?;
    // header is 8 or 16, so `header + 8` cannot overflow.
    let compatible = whole.get(header + 8..).unwrap_or(&[]);
    Some(([brand[0], brand[1], brand[2], brand[3]], compatible))
}

/// The `ftyp` major brand (Android `HeifBoxes.majorBrand`).
pub fn heif_major_brand(b: &[u8]) -> Option<[u8; 4]> {
    ftyp_box(b).map(|(brand, _)| brand)
}

/// An accepted major brand, and no AV1 brand among the compatible ones (an
/// AVIF can label itself `mif1`).
fn is_heif(b: &[u8]) -> bool {
    let Some((brand, compatible)) = ftyp_box(b) else {
        return false;
    };
    HEIF_BRANDS.iter().any(|h| **h == brand)
        && !compatible
            .chunks_exact(4)
            .any(|c| AV1_BRANDS.iter().any(|a| &a[..] == c))
}

pub fn photo_ok(b: &[u8]) -> bool {
    if is_heif(b) {
        return true; // its dimensions stay with the platform decoder's header callback (spec §4)
    }
    if !(is_jpeg(b) || is_png(b) || is_webp(b)) {
        return false;
    }
    if is_png(b) && b.len() >= 16 && b.get(8..16) != Some(&PNG_IHDR_HEAD[..]) {
        return false; // the first chunk must be IHDR (length 13)
    }
    if is_jpeg(b) && jpeg_scan(b).is_err() {
        return false;
    }
    match photo_dimensions(b) {
        None => true,
        Some((w, h)) => w > 0 && h > 0 && u64::from(w) * u64::from(h) <= MAX_PHOTO_PIXELS,
    }
}

/// Width and height from the header, where it is cheap to read.
pub fn photo_dimensions(b: &[u8]) -> Option<(u32, u32)> {
    if is_jpeg(b) {
        jpeg_scan(b).ok().flatten()
    } else if is_png(b) {
        if b.get(12..16)? != b"IHDR" {
            return None;
        }
        Some((be32(b, 16)?, be32(b, 20)?))
    } else if is_webp(b) {
        match b.get(12..16)? {
            b"VP8 " => {
                if b.get(23..26)? != [0x9D, 0x01, 0x2A] {
                    return None;
                }
                Some((
                    u32::from(le16(b, 26)? & 0x3FFF),
                    u32::from(le16(b, 28)? & 0x3FFF),
                ))
            }
            b"VP8L" => {
                if *b.get(20)? != 0x2F {
                    return None;
                }
                let bits = le32(b, 21)?;
                Some(((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1))
            }
            b"VP8X" => Some((le24(b, 24)? + 1, le24(b, 27)? + 1)),
            _ => None,
        }
    } else {
        None
    }
}

/// Walks the segments from the start. `Ok(Some)` is the one frame header
/// (SOF0-SOF15 but DHT, JPG and DAC) before the scan; `Ok(None)` is a start
/// of scan or end of image with no frame header, or a file that ends first
/// (left to the platform cap). `Err` is a shape no encoder writes: a byte
/// that is not a marker where one must be, a second frame header, or more
/// segments than the cap.
#[allow(clippy::result_unit_err)]
fn jpeg_scan(b: &[u8]) -> Result<Option<(u32, u32)>, ()> {
    let mut at = 2usize;
    let mut frame = None;
    for _ in 0..MAX_JPEG_SEGMENTS {
        match b.get(at) {
            None => return Ok(frame),
            Some(0xFF) => {}
            Some(_) => return Err(()),
        }
        while b.get(at) == Some(&0xFF) {
            at = at.checked_add(1).ok_or(())?; // fill bytes
        }
        let Some(&code) = b.get(at) else {
            return Ok(frame);
        };
        at = at.checked_add(1).ok_or(())?;
        match code {
            0x01 | 0xD0..=0xD8 => continue, // standalone markers
            0xD9 | 0xDA => return Ok(frame),
            _ => {}
        }
        let Some(len) = be16(b, at).map(usize::from) else {
            return Ok(frame);
        };
        if len < 2 {
            return Ok(frame);
        }
        if (0xC0..=0xCF).contains(&code) && !matches!(code, 0xC4 | 0xC8 | 0xCC) {
            if frame.is_some() {
                return Err(());
            }
            if len < 8 {
                return Ok(None);
            }
            let (Some(h), Some(w)) = (
                be16(b, at.checked_add(3).ok_or(())?),
                be16(b, at.checked_add(5).ok_or(())?),
            ) else {
                return Ok(None);
            };
            frame = Some((u32::from(w), u32::from(h)));
        }
        at = at.checked_add(len).ok_or(())?;
    }
    Err(())
}

/// Android `IncomingVoice.isMpeg4`, ported: an `ftyp` box first, 16 bytes
/// to 4 KiB and inside the file, whose major or a compatible brand is
/// known; then top-level boxes that chain cleanly to a `moov` that holds
/// only AAC audio (`moov_is_aac_audio`).
pub fn voice_ok(d: &[u8]) -> bool {
    if d.len() < 16 || d.get(4..8) != Some(&b"ftyp"[..]) {
        return false;
    }
    let ftyp = be32(d, 0).map_or(0, u64::from);
    if ftyp < 16 || ftyp > (d.len() as u64).min(MAX_FTYP) {
        return false;
    }
    let ftyp = ftyp as usize; // at most 4096
    let known = |at: usize| {
        d.get(at..at + 4)
            .is_some_and(|b| VOICE_BRANDS.iter().any(|v| &v[..] == b))
    };
    let mut branded = known(8);
    let mut at = 16;
    while !branded && at + 4 <= ftyp {
        branded = known(at);
        at += 4;
    }
    if !branded {
        return false;
    }
    let budget = Cell::new(MAX_BOXES);
    for (kind, payload) in (Boxes {
        buf: d,
        off: 0,
        budget: &budget,
    }) {
        if &kind == b"moov" {
            return moov_is_aac_audio(payload, &budget);
        }
    }
    false
}

/// The child boxes of one box payload, in order. Ends at the first box that
/// is malformed or past its parent, and when the shared box budget runs out.
struct Boxes<'a, 'b> {
    buf: &'a [u8],
    off: usize,
    budget: &'b Cell<usize>,
}

impl<'a> Iterator for Boxes<'a, '_> {
    type Item = ([u8; 4], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let left = self.budget.get().checked_sub(1)?;
        self.budget.set(left);
        let rest = self.buf.get(self.off..)?;
        let (size, header) = match be32(rest, 0)? {
            0 => (rest.len() as u64, 8usize),
            1 => (be64(rest, 8)?, 16usize),
            s => (u64::from(s), 8usize),
        };
        if size < header as u64 || size > rest.len() as u64 {
            return None;
        }
        let size = usize::try_from(size).ok()?; // size <= rest.len()
        let kind = slice(rest, 4, 4)?;
        let payload = rest.get(..size)?.get(header..)?;
        self.off = self.off.checked_add(size)?;
        Some(([kind[0], kind[1], kind[2], kind[3]], payload))
    }
}

fn child<'a>(parent: &'a [u8], kind: &[u8; 4], budget: &Cell<usize>) -> Option<&'a [u8]> {
    Boxes {
        buf: parent,
        off: 0,
        budget,
    }
    .find(|(k, _)| k == kind)
    .map(|(_, p)| p)
}

/// Final review M1: every audio track must be AAC, and nothing else may be
/// in the file for a platform decoder to pick. Each `trak` must name its
/// handler; a `soun` track must list exactly one sample entry, `mp4a`, whose
/// `esds` names MPEG-4 Audio (`mp4a_is_aac`); a
/// `hint` or `meta` track is ignored; any other handler (`vide`, `text`,
/// `sbtl`, `subt`, `clcp`, …) refuses the note. At least one `soun`/`mp4a`
/// track is needed, and the `moov` box must chain cleanly to its end (a
/// malformed box could hide a later track).
fn moov_is_aac_audio(moov: &[u8], budget: &Cell<usize>) -> bool {
    let mut aac = false;
    let mut traks = Boxes {
        buf: moov,
        off: 0,
        budget,
    };
    for (kind, trak) in traks.by_ref() {
        if &kind != b"trak" {
            continue;
        }
        let Some(mdia) = child(trak, b"mdia", budget) else {
            return false;
        };
        // hdlr: version and flags, pre_defined, then the handler type.
        let Some(handler) = child(mdia, b"hdlr", budget).and_then(|h| slice(h, 8, 4)) else {
            return false;
        };
        match handler {
            b"soun" => {}
            b"hint" | b"meta" => continue,
            _ => return false,
        }
        // stsd: version and flags, entry count, then the first entry's size and type.
        let Some(stsd) = child(mdia, b"minf", budget)
            .and_then(|m| child(m, b"stbl", budget))
            .and_then(|t| child(t, b"stsd", budget))
        else {
            return false;
        };
        if be32(stsd, 4) != Some(1) || slice(stsd, 12, 4) != Some(&b"mp4a"[..]) {
            return false;
        }
        let Some(entries) = stsd.get(8..) else {
            return false;
        };
        let entry = Boxes {
            buf: entries,
            off: 0,
            budget,
        }
        .next();
        match entry {
            Some((kind, mp4a)) if &kind == b"mp4a" && mp4a_is_aac(mp4a, budget) => {}
            _ => return false,
        }
        aac = true;
    }
    // A walk cut short by the budget or a malformed box may have missed a
    // track.
    aac && budget.get() > 0 && traks.off == moov.len()
}

/// An `mp4a` sample entry whose `esds` says MPEG-4 Audio (object type
/// 0x40): AAC, not MP3 (0x6B, 0x69) or anything else a decoder would take
/// from an `mp4a` entry. The entry is an AudioSampleEntry (28 bytes, plus 16
/// for a QuickTime version 1 or 36 for version 2) followed by its child
/// boxes, one of which must be `esds`.
fn mp4a_is_aac(entry: &[u8], budget: &Cell<usize>) -> bool {
    let fixed = match be16(entry, 8) {
        Some(0) => 28,
        Some(1) => 44,
        Some(2) => 64,
        _ => return false,
    };
    let Some(children) = entry.get(fixed..) else {
        return false;
    };
    // Exactly one esds: a second could carry another codec.
    let esds_count = Boxes {
        buf: children,
        off: 0,
        budget,
    }
    .filter(|(k, _)| k == b"esds")
    .take(2)
    .count();
    esds_count == 1 && child(children, b"esds", budget).is_some_and(esds_is_aac)
}

/// Descriptor tags in an `esds` (ISO/IEC 14496-1 §7.2.6).
const ES_DESCRIPTOR: u8 = 0x03;
const DECODER_CONFIG: u8 = 0x04;
const OTI_MPEG4_AUDIO: u8 = 0x40;

/// One descriptor at `at` in `b`: its tag and its body, which must lie
/// inside `b`. The size is 1 to 4 bytes of 7 bits each, high bit set on all
/// but the last; every offset is checked (32-bit `usize`).
fn descriptor(b: &[u8], at: usize) -> Option<(u8, &[u8])> {
    let tag = *b.get(at)?;
    let mut size = 0usize;
    let mut pos = at.checked_add(1)?;
    for i in 0..4 {
        let byte = *b.get(pos)?;
        pos = pos.checked_add(1)?;
        size = (size << 7) | usize::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            break;
        }
        if i == 3 {
            return None;
        }
    }
    Some((tag, slice(b, pos, size)?))
}

/// `esds`: version and flags, then an ES_Descriptor whose
/// DecoderConfigDescriptor names MPEG-4 Audio. Missing, malformed or
/// truncated: not AAC.
fn esds_is_aac(esds: &[u8]) -> bool {
    let Some((ES_DESCRIPTOR, es)) = descriptor(esds, 4) else {
        return false;
    };
    // ES_ID (2 bytes), then flags: stream dependence adds a 2-byte id, a
    // URL a length-prefixed string, an OCR stream a 2-byte id.
    let Some(&flags) = es.get(2) else {
        return false;
    };
    let mut at = 3usize;
    if flags & 0x80 != 0 {
        at += 2;
    }
    if flags & 0x40 != 0 {
        let Some(&len) = es.get(at) else {
            return false;
        };
        at += 1 + usize::from(len);
    }
    if flags & 0x20 != 0 {
        at += 2;
    }
    let Some((DECODER_CONFIG, config)) = descriptor(es, at) else {
        return false;
    };
    if config.first() != Some(&OTI_MPEG4_AUDIO) {
        return false;
    }
    // After objectType, streamType, bufferSize (3), max and avg bitrate
    // (4 each): the DecoderSpecificInfo, whose audio object type must be
    // AAC (LC 2, SBR 5, PS 29); MP3-in-MPEG-4 (34), ALS (36) and the rest
    // are refused.
    let Some((DECODER_SPECIFIC, dsi)) = descriptor(config, 13) else {
        return false;
    };
    matches!(audio_object_type(dsi), Some(2 | 5 | 29))
}

const DECODER_SPECIFIC: u8 = 0x05;

/// The AudioSpecificConfig's audio object type: 5 bits, or 32 + the next 6
/// bits when they read 31 (ISO/IEC 14496-3 §1.6.2.1).
fn audio_object_type(dsi: &[u8]) -> Option<u8> {
    let first = *dsi.first()?;
    let aot = first >> 3;
    if aot != 31 {
        return Some(aot);
    }
    let second = *dsi.get(1)?;
    Some(32 + (((first & 0x07) << 3) | (second >> 5)))
}

#[cfg(test)]
mod tests;
