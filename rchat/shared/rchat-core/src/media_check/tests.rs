//! File safety spec §4 and §7: Android's accept and refuse vectors
//! (`ImageFormatsTest`, `IncomingVoiceTest`) pass through the core check,
//! and the header dimensions are read and capped.

use super::*;

fn ascii(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}
fn be32(v: u64) -> Vec<u8> {
    (v as u32).to_be_bytes().to_vec()
}
fn mp4_box(kind: &str, body: &[u8]) -> Vec<u8> {
    sized_box(kind, body, 8 + body.len() as u64)
}
fn sized_box(kind: &str, body: &[u8], size: u64) -> Vec<u8> {
    [be32(size), ascii(kind), body.to_vec()].concat()
}
fn ftyp(major: &str, compatible: &[&str]) -> Vec<u8> {
    let mut body = ascii(major);
    body.extend_from_slice(&[0; 4]);
    for c in compatible {
        body.extend_from_slice(c.as_bytes());
    }
    mp4_box("ftyp", &body)
}
/// An `esds` whose DecoderConfigDescriptor names object type `oti`, sizes
/// in the 4-byte form as afconvert and ffmpeg write them.
fn esds(oti: u8) -> Vec<u8> {
    // DecoderConfig (13 bytes) + a DecoderSpecificInfo for AAC-LC (object type 2).
    let config = [
        vec![0x04, 0x80, 0x80, 0x80, 17, oti, 0x15],
        vec![0; 11],
        vec![0x05, 2, 0x12, 0x10],
    ]
    .concat();
    let es = [
        vec![0x03, 0x80, 0x80, 0x80],
        vec![(3 + config.len()) as u8, 0, 1, 0],
        config,
    ]
    .concat();
    mp4_box("esds", &[vec![0; 4], es].concat())
}
/// A sample entry: an `mp4a` one carries an AAC `esds` after its 28 bytes.
fn sample_entry(entry: &str) -> Vec<u8> {
    if entry == "mp4a" {
        mp4_box(entry, &[vec![0; 28], esds(0x40)].concat())
    } else {
        mp4_box(entry, &[0; 28])
    }
}
fn track(handler: &str, entry: &str) -> Vec<u8> {
    let hdlr = mp4_box("hdlr", &[vec![0; 8], ascii(handler), vec![0; 13]].concat());
    let stsd = mp4_box(
        "stsd",
        &[vec![0, 0, 0, 0, 0, 0, 0, 1], sample_entry(entry)].concat(),
    );
    let minf = mp4_box("minf", &mp4_box("stbl", &stsd));
    mp4_box("trak", &mp4_box("mdia", &[hdlr, minf].concat()))
}
/// A moov as the recorders write it: one AAC audio track.
fn moov() -> Vec<u8> {
    mp4_box("moov", &track("soun", "mp4a"))
}
fn note() -> Vec<u8> {
    ftyp("M4A ", &["M4A ", "mp42", "isom"])
}

// --- ImageFormatsTest ------------------------------------------------------

#[test]
fn the_four_formats_pass() {
    assert!(photo_ok(&[0xFF, 0xD8, 0xFF, 0xE0]));
    assert!(photo_ok(&[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0
    ]));
    assert!(photo_ok(
        &[ascii("RIFF"), vec![0; 4], ascii("WEBPVP8 ")].concat()
    ));
    for brand in ["heic", "heix", "mif1", "msf1", "hevc"] {
        let heif = [vec![0, 0, 0, 16], ascii("ftyp"), ascii(brand), vec![0; 4]].concat();
        assert!(photo_ok(&heif), "{brand}");
    }
}

#[test]
fn everything_else_is_refused() {
    assert!(!photo_ok(&[ascii("GIF89a"), vec![0; 8]].concat()), "GIF");
    assert!(!photo_ok(&[ascii("BM"), vec![0; 12]].concat()), "BMP");
    let avif = [vec![0, 0, 0, 16], ascii("ftyp"), ascii("avif"), vec![0; 4]].concat();
    assert!(!photo_ok(&avif), "AVIF");
    assert!(
        !photo_ok(&[ascii("RIFF"), vec![0; 4], ascii("WAVE")].concat()),
        "RIFF that isn't WebP"
    );
    assert!(!photo_ok(&[]));
    assert!(!photo_ok(&[0xFF, 0xD8]));
    // Decision 15: a HEIF brand only as a compatible brand is not enough.
    let compat_only = [
        vec![0, 0, 0, 20],
        ascii("ftyp"),
        ascii("isom"),
        vec![0; 4],
        ascii("heic"),
    ]
    .concat();
    assert!(!photo_ok(&compat_only));
}

// --- dimensions (Decision 14) ---------------------------------------------

fn jpeg(width: u16, height: u16, sof: u8) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    v.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    v.extend_from_slice(&[0xFF, 0xFF, 0xC4, 0x00, 0x04, 0x00, 0x00]); // a fill byte, then a DHT
    v.extend_from_slice(&[0xFF, sof, 0x00, 0x11, 0x08]);
    v.extend_from_slice(&height.to_be_bytes());
    v.extend_from_slice(&width.to_be_bytes());
    v.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}
fn png(width: u32, height: u32) -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&width.to_be_bytes());
    v.extend_from_slice(&height.to_be_bytes());
    v.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0]);
    v
}
fn webp(chunk: &str, payload: &[u8]) -> Vec<u8> {
    [
        ascii("RIFF"),
        vec![0; 4],
        ascii("WEBP"),
        ascii(chunk),
        (payload.len() as u32).to_le_bytes().to_vec(),
        payload.to_vec(),
    ]
    .concat()
}
fn vp8x(width: u32, height: u32) -> Vec<u8> {
    let w = (width - 1).to_le_bytes();
    let h = (height - 1).to_le_bytes();
    webp("VP8X", &[0, 0, 0, 0, w[0], w[1], w[2], h[0], h[1], h[2]])
}
fn vp8l(width: u32, height: u32) -> Vec<u8> {
    let bits = (width - 1) | ((height - 1) << 14);
    webp("VP8L", &[&[0x2Fu8][..], &bits.to_le_bytes()[..]].concat())
}
fn vp8(width: u16, height: u16) -> Vec<u8> {
    webp(
        "VP8 ",
        &[
            &[0u8, 0, 0, 0x9D, 0x01, 0x2A][..],
            &width.to_le_bytes()[..],
            &height.to_le_bytes()[..],
        ]
        .concat(),
    )
}

#[test]
fn dimensions_are_read_from_each_header() {
    assert_eq!(photo_dimensions(&jpeg(640, 480, 0xC0)), Some((640, 480)));
    assert_eq!(
        photo_dimensions(&jpeg(640, 480, 0xC2)),
        Some((640, 480)),
        "progressive"
    );
    assert_eq!(photo_dimensions(&png(1600, 900)), Some((1600, 900)));
    assert_eq!(photo_dimensions(&vp8x(300, 200)), Some((300, 200)));
    assert_eq!(photo_dimensions(&vp8l(300, 200)), Some((300, 200)));
    assert_eq!(photo_dimensions(&vp8(300, 200)), Some((300, 200)));
}

#[test]
fn sixteen_megapixels_is_the_cap() {
    assert!(photo_ok(&jpeg(4096, 4096, 0xC0)));
    assert!(!photo_ok(&jpeg(4097, 4096, 0xC0)));
    assert!(!photo_ok(&jpeg(0, 10, 0xC0)), "a zero dimension");
    assert!(!photo_ok(&png(16_384, 16_384)), "the PNG bomb's header");
    assert!(photo_ok(&png(4096, 4096)));
    assert!(!photo_ok(&vp8x(5000, 5000)));
    assert!(!photo_ok(&vp8l(16_384, 16_384)));
    assert!(photo_ok(&vp8(4000, 3000)));
}

#[test]
fn an_unreadable_header_passes_on_its_magic() {
    // Start of scan before any frame header: left to the platform's cap.
    let sos_first = [0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0xFF, 0xD9];
    assert_eq!(photo_dimensions(&sos_first), None);
    assert!(photo_ok(&sos_first));
    // A segment length running past the end.
    assert!(photo_ok(&[0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, 0]));
}

// --- IncomingVoiceTest -----------------------------------------------------

#[test]
fn voice_notes_as_both_apps_write_them_pass() {
    assert!(voice_ok(
        &[note(), mp4_box("mdat", &[0; 40]), moov()].concat()
    ));
    assert!(voice_ok(
        &[
            ftyp("mp42", &["isom", "mp42"]),
            mp4_box("free", &[]),
            mp4_box("mdat", &[0; 40]),
            moov()
        ]
        .concat()
    ));
    assert!(
        voice_ok(&[note(), moov(), mp4_box("mdat", &[0; 8])].concat()),
        "moov first"
    );
    assert!(
        voice_ok(&[ftyp("abcd", &["isom"]), moov()].concat()),
        "a compatible brand is enough"
    );
    assert!(
        voice_ok(&[ftyp("mp41", &["mp41"]), moov()].concat()),
        "mp41"
    );
    let large = [be32(1), ascii("mdat"), be32(0), be32(24), vec![0; 8]].concat();
    assert!(
        voice_ok(&[note(), large, moov()].concat()),
        "a 64-bit mdat size"
    );
}

#[test]
fn other_containers_are_refused() {
    assert!(!voice_ok(&[ascii("caff"), vec![0; 60]].concat()), "CAF");
    assert!(
        !voice_ok(&[vec![0xFFu8, 0xF1], vec![0; 60]].concat()),
        "ADTS"
    );
    assert!(
        !voice_ok(
            &[
                ascii("ID3"),
                vec![4, 0, 0, 0, 0, 0, 0, 0xFF, 0xF1],
                vec![0; 60]
            ]
            .concat()
        ),
        "ID3 then ADTS"
    );
    assert!(!voice_ok(&[ascii("OggS"), vec![0; 60]].concat()), "Ogg");
    assert!(
        !voice_ok(&[ascii("RIFF"), vec![0; 4], ascii("WAVE"), vec![0; 40]].concat()),
        "WAVE"
    );
    assert!(
        !voice_ok(&[ftyp("qt  ", &["qt  "]), moov()].concat()),
        "QuickTime brand"
    );
    assert!(!voice_ok(&[]));
}

#[test]
fn an_ftyp_spoof_is_refused() {
    let adts = [
        vec![0xFFu8, 0xF1, 0x50, 0x80, 0x02, 0x1F, 0xFC],
        vec![0; 64],
    ]
    .concat();
    assert!(!voice_ok(&[note(), adts].concat()), "ftyp then ADTS frames");
    assert!(
        !voice_ok(&[note(), ascii("ID3"), vec![0; 40]].concat()),
        "ftyp then an ID3 tag"
    );
    assert!(
        !voice_ok(&[note(), mp4_box("mdat", &[0; 40])].concat()),
        "no moov"
    );
    assert!(
        !voice_ok(&[note(), sized_box("mdat", &[0; 8], 400), moov()].concat()),
        "a box past the end"
    );
    let wrapping = [
        be32(1),
        ascii("mdat"),
        vec![0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ]
    .concat();
    assert!(
        !voice_ok(&[note(), wrapping, moov()].concat()),
        "a 64-bit size that would wrap"
    );
    assert!(
        !voice_ok(&[note(), sized_box("mdat", &[], 4), moov()].concat()),
        "a box under 8 bytes"
    );
    assert!(
        !voice_ok(&[note(), sized_box("mdat", &[0; 8], 0), moov()].concat()),
        "to the end, not moov"
    );
}

#[test]
fn the_ftyp_box_must_be_sensibly_sized() {
    let body = [ascii("M4A "), vec![0; 4], ascii("M4A ")].concat();
    assert!(
        !voice_ok(&[sized_box("ftyp", &body, 12), vec![0; 4], moov()].concat()),
        "under 16"
    );
    assert!(
        !voice_ok(&[sized_box("ftyp", &body, 5_000), moov()].concat()),
        "past the file"
    );
    let huge = mp4_box(
        "ftyp",
        &[ascii("M4A "), vec![0; 4], vec![0; 5_000]].concat(),
    );
    assert!(!voice_ok(&[huge, moov()].concat()), "over 4 KiB");
}

#[test]
fn check_dispatches_by_kind() {
    assert_eq!(check(KIND_PHOTO, &[0xFF, 0xD8, 0xFF]), Some(true));
    assert_eq!(check(KIND_VOICE, &[0xFF, 0xD8, 0xFF]), Some(false));
    assert_eq!(check(3, &[]), None);
}

#[test]
fn fuzz_style_inputs_never_panic_or_allocate() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x3ED1A);
    let seeds = [
        jpeg(64, 64, 0xC0),
        png(10, 10),
        vp8x(9, 9),
        [note(), moov()].concat(),
    ];
    for i in 0..20_000 {
        let mut v = seeds[i % seeds.len()].clone();
        for _ in 0..rng.gen_range(0..6) {
            let at = rng.gen_range(0..v.len());
            v[at] = rng.gen();
        }
        v.truncate(rng.gen_range(0..=v.len()));
        let used = crate::alloc_probe::bytes_allocated(|| {
            let _ = (photo_ok(&v), voice_ok(&v), photo_dimensions(&v));
        });
        assert_eq!(used, 0);
    }
}

// --- hostile input (32-bit usize, overflow checks, panic = abort) ----------

#[test]
fn hostile_box_sizes_are_refused_not_followed() {
    for size in [0u32, 1, 7, 8, 0xFFFF_FFFF, 0xFFFF_FFF0, 0x8000_0000] {
        let first = [be32(u64::from(size)), ascii("mdat"), vec![0; 16]].concat();
        let v = [note(), first, moov()].concat();
        // Only a size that lands on the next box boundary can pass; none do.
        assert!(!voice_ok(&v), "size {size:#x}");
    }
    // The ftyp box itself with hostile sizes.
    for size in [0u32, 1, 0xFFFF_FFFF, 0xFFFF_FFF8] {
        let v = [
            be32(u64::from(size)),
            ascii("ftyp"),
            ascii("M4A "),
            vec![0; 20],
        ]
        .concat();
        assert!(!voice_ok(&v), "ftyp size {size:#x}");
    }
    // 64-bit size: truncated, tiny, huge, high bit set, near u64::MAX.
    for large in [
        vec![],
        vec![0; 4],
        vec![0, 0, 0, 0, 0, 0, 0, 12],
        vec![0, 0, 0, 1, 0, 0, 0, 0],
        vec![0xFF; 8],
        vec![0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0],
    ] {
        let v = [note(), be32(1), ascii("mdat"), large, moov()].concat();
        assert!(!voice_ok(&v));
    }
    // A 64-bit size cut off by the end of the file.
    assert!(!voice_ok(&[note(), be32(1), ascii("mdat")].concat()));
    assert!(!voice_ok(&[note(), be32(1)].concat()));
}

#[test]
fn a_box_chain_is_bounded() {
    // 2000 empty boxes then a moov: past the 1024-box cap, so refused.
    let mut v = note();
    for _ in 0..2_000 {
        v.extend_from_slice(&mp4_box("free", &[]));
    }
    v.extend_from_slice(&moov());
    assert!(!voice_ok(&v));
    // Within the cap it passes.
    let mut v = note();
    for _ in 0..500 {
        v.extend_from_slice(&mp4_box("free", &[]));
    }
    v.extend_from_slice(&moov());
    assert!(voice_ok(&v));
}

#[test]
fn truncated_headers_never_pass_by_accident() {
    let photos = [
        jpeg(64, 64, 0xC0),
        png(10, 10),
        vp8x(9, 9),
        vp8l(9, 9),
        vp8(9, 9),
    ];
    for full in &photos {
        let want = photo_dimensions(full);
        assert!(want.is_some());
        for n in 0..full.len() {
            let t = &full[..n];
            // A truncation never invents other dimensions, and a pass is only ever by magic.
            if let Some(d) = photo_dimensions(t) {
                assert_eq!(Some(d), want, "{n}");
            }
            assert!(!photo_ok(t) || is_jpeg(t) || is_png(t) || is_webp(t), "{n}");
            assert!(!voice_ok(t), "a photo is no voice note");
        }
    }
    let voice = [note(), moov()].concat();
    assert!(voice_ok(&voice));
    for n in 0..voice.len() {
        assert!(!voice_ok(&voice[..n]), "voice truncated to {n}");
        assert!(!photo_ok(&voice[..n]));
    }
    assert_eq!(photo_dimensions(&png(10, 10)[..20]), None);
    assert_eq!(photo_dimensions(&vp8x(9, 9)[..27]), None);
    assert_eq!(
        photo_dimensions(&[ascii("RIFF"), vec![0; 4], ascii("WEBP")].concat()),
        None
    );
}

#[test]
fn a_jpeg_marker_run_to_the_end_is_bounded_and_passes_on_magic() {
    let mut v = vec![0xFF, 0xD8];
    v.extend(std::iter::repeat_n(0xFF, 100_000));
    assert_eq!(photo_dimensions(&v), None);
    assert!(photo_ok(&v));
    // Thousands of tiny segments with no frame header: stops at the cap.
    let mut v = vec![0xFF, 0xD8];
    for _ in 0..5_000 {
        v.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x02]);
    }
    v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 8, 0, 0, 0, 0, 1, 1, 0, 0]);
    assert_eq!(photo_dimensions(&v), None);
    // A standalone-marker run (RSTn) is bounded too.
    let mut v = vec![0xFF, 0xD8];
    for _ in 0..5_000 {
        v.extend_from_slice(&[0xFF, 0xD0]);
    }
    assert_eq!(photo_dimensions(&v), None);
    // A frame header cut short, and one whose length is under its fixed part.
    assert_eq!(
        photo_dimensions(&[0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00]),
        None
    );
    assert_eq!(
        photo_dimensions(&[0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x03, 0x08, 0, 5, 0, 5]),
        None
    );
    // A zero segment length.
    assert_eq!(
        photo_dimensions(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0, 0]),
        None
    );
}

#[test]
fn png_and_webp_extremes() {
    assert!(!photo_ok(&png(0, 0)));
    assert!(!photo_ok(&png(0, 5)));
    assert!(!photo_ok(&png(5, 0)));
    assert!(!photo_ok(&png(u32::MAX, u32::MAX)));
    assert!(!photo_ok(&png(u32::MAX, 1)));
    assert!(photo_ok(&png(1, 1)));
    // A PNG whose first chunk is not IHDR is refused, the CgBI shape included.
    let mut p = png(u32::MAX, u32::MAX);
    p[12..16].copy_from_slice(b"CgBI");
    assert_eq!(photo_dimensions(&p), None);
    assert!(!photo_ok(&p));
    let mut p = png(10, 10);
    p[8..12].copy_from_slice(&[0, 0, 0, 12]);
    assert!(!photo_ok(&p), "IHDR with the wrong length");
    // Shorter than a chunk header: still left to the platform.
    assert!(photo_ok(&png(10, 10)[..15]));
    // Largest values the WebP headers can express.
    assert!(!photo_ok(&vp8x(1 << 24, 1 << 24)));
    assert!(!photo_ok(&vp8l(1 << 14, 1 << 14)));
    assert!(!photo_ok(&vp8(16_383, 16_383)));
    assert!(!photo_ok(&vp8(0, 10)));
    assert!(photo_ok(&vp8x(1, 1 << 24)), "exactly 16 Mpx");
    assert!(!photo_ok(&vp8x(2, 1 << 24)));
}

#[test]
fn webp_chunk_sizes_past_the_end_are_not_followed() {
    for size in [0u32, 1, 10, 0x7FFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFF] {
        let mut v = vp8x(10, 10);
        v[16..20].copy_from_slice(&size.to_le_bytes());
        let _ = photo_ok(&v);
        assert_eq!(
            photo_dimensions(&v),
            Some((10, 10)),
            "the header fields are read at fixed offsets"
        );
    }
    for size in [0u32, 0xFFFF_FFFF] {
        let mut v = [
            ascii("RIFF"),
            size.to_le_bytes().to_vec(),
            ascii("WEBPVP8 "),
            size.to_le_bytes().to_vec(),
        ]
        .concat();
        assert_eq!(photo_dimensions(&v), None);
        assert!(photo_ok(&v));
        v.extend_from_slice(&[0, 0, 0, 0x9D, 0x01, 0x2A, 1, 0, 1, 0]);
        assert_eq!(photo_dimensions(&v), Some((1, 1)));
    }
}

#[test]
fn offsets_near_the_top_of_the_range_do_not_wrap() {
    // The private readers take the offset a file hands over; none may wrap.
    let b = [0u8; 16];
    for at in [
        usize::MAX,
        usize::MAX - 1,
        usize::MAX - 3,
        u32::MAX as usize,
        (u32::MAX - 3) as usize,
    ] {
        assert_eq!(super::be16(&b, at), None);
        assert_eq!(super::le16(&b, at), None);
        assert_eq!(super::be32(&b, at), None);
        assert_eq!(super::le32(&b, at), None);
        assert_eq!(super::le24(&b, at), None);
        assert_eq!(super::be64(&b, at), None);
    }
    assert_eq!(super::be64(&[0, 0, 0, 0, 0, 0, 0, 5], 0), Some(5));
    assert_eq!(super::be64(&[0, 0, 0, 0, 0, 0, 0], 0), None);
}

#[test]
fn heif_brand_edge_cases() {
    assert_eq!(heif_major_brand(&[]), None);
    assert_eq!(heif_major_brand(&ascii("....ftyp")), None);
    for size in [0u32, 1, 8, 11, 12, 0xFFFF_FFFF] {
        let v = [
            be32(u64::from(size)),
            ascii("ftyp"),
            ascii("heic"),
            vec![0; 4],
        ]
        .concat();
        let _ = (heif_major_brand(&v), photo_ok(&v));
    }
    let v = [be32(0), ascii("ftyp"), ascii("heic")].concat();
    assert_eq!(
        heif_major_brand(&v),
        Some(*b"heic"),
        "size 0 runs to the end"
    );
    let big = [
        be32(1),
        ascii("ftyp"),
        vec![0, 0, 0, 0, 0, 0, 0, 20],
        ascii("heic"),
    ]
    .concat();
    assert_eq!(heif_major_brand(&big), Some(*b"heic"));
    let wrap = [
        be32(1),
        ascii("ftyp"),
        vec![0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ascii("heic"),
    ]
    .concat();
    assert_eq!(heif_major_brand(&wrap), None);
    let huge = [be32(1), ascii("ftyp"), vec![0xFF; 8], ascii("heic")].concat();
    assert_eq!(heif_major_brand(&huge), None);
}

// --- fix round 1 ------------------------------------------------------------

fn sof(code: u8, width: u16, height: u16) -> Vec<u8> {
    let mut v = vec![0xFF, code, 0x00, 0x11, 0x08];
    v.extend_from_slice(&height.to_be_bytes());
    v.extend_from_slice(&width.to_be_bytes());
    v.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
    v
}
fn app1(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xE1];
    v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn jpeg_decoys_are_refused() {
    // A decoy first frame header, the real one after it.
    let mut v = vec![0xFF, 0xD8];
    v.extend(sof(0xC0, 64, 64));
    v.extend(sof(0xC2, 4032, 3024));
    v.extend_from_slice(&[0xFF, 0xD9]);
    assert!(!photo_ok(&v), "a second SOF");
    // A stray byte where a marker belongs, before the frame header.
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0x00];
    v.extend(sof(0xC0, 4032, 3024));
    assert!(!photo_ok(&v), "a stray byte");
    // More segments than the cap before the frame header.
    let mut v = vec![0xFF, 0xD8];
    for _ in 0..1_100 {
        v.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x02]);
    }
    v.extend(sof(0xC0, 4032, 3024));
    assert!(!photo_ok(&v), "over 1024 segments");
    // The cap holds with a frame header already read.
    let mut v = vec![0xFF, 0xD8];
    v.extend(sof(0xC0, 64, 64));
    for _ in 0..1_100 {
        v.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x02]);
    }
    assert!(!photo_ok(&v));
    // Fill bytes are fine, and so is a truncation.
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x02, 0xFF, 0xFF];
    v.extend(sof(0xC0, 64, 64));
    assert!(photo_ok(&v));
    assert!(photo_ok(&v[..v.len() - 3]));
}

#[test]
fn real_jpeg_shapes_still_pass() {
    // An EXIF APP1 carrying its own thumbnail (with a SOF of its own) before the real SOF.
    let thumb = jpeg(160, 120, 0xC0);
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend_from_slice(&thumb);
    let mut v = vec![0xFF, 0xD8];
    v.extend(app1(&exif));
    v.extend(sof(0xC0, 4032, 3024));
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 1, 2, 3, 0xFF, 0xD9]);
    assert_eq!(photo_dimensions(&v), Some((4032, 3024)));
    assert!(photo_ok(&v));
    assert!(photo_ok(&jpeg(4032, 3024, 0xC2)), "progressive");
    assert!(photo_ok(&jpeg(1200, 800, 0xC1)), "extended sequential");
}

#[test]
fn an_avif_labelled_as_heif_is_refused() {
    for bad in ["avif", "avis", "av01"] {
        assert!(!photo_ok(&ftyp("mif1", &[bad])), "mif1 with {bad}");
        assert!(!photo_ok(&ftyp("heic", &["mif1", bad])), "heic with {bad}");
    }
    assert!(photo_ok(&ftyp("mif1", &["mif1", "miaf", "MiHB"])));
    assert!(photo_ok(&ftyp("heic", &["mif1", "heic"])));
    assert!(photo_ok(&ftyp("mif1", &[])));
    // A compatible brand past the box is not looked at.
    let v = [ftyp("mif1", &[]), ascii("avif")].concat();
    assert!(photo_ok(&v));
}

#[test]
fn only_aac_audio_voice_notes_pass() {
    let pass = |trak: Vec<u8>| {
        voice_ok(&[note(), mp4_box("mdat", &[0; 40]), mp4_box("moov", &trak)].concat())
    };
    assert!(pass(track("soun", "mp4a")));
    assert!(pass(
        [track("soun", "mp4a"), track("soun", "mp4a")].concat()
    ));
    assert!(pass(
        [mp4_box("mvhd", &[0; 20]), track("soun", "mp4a")].concat()
    ));
    // Hint and metadata tracks are ignored.
    assert!(pass(
        [
            track("soun", "mp4a"),
            track("hint", "rtp "),
            track("meta", "mett")
        ]
        .concat()
    ));
    assert!(!pass(track("soun", "Opus")), "Opus");
    assert!(!pass(track("soun", "alac")), "ALAC");
    assert!(!pass(track("vide", "avc1")), "H.264 video");
    assert!(
        !pass([track("soun", "mp4a"), track("vide", "avc1")].concat()),
        "audio and video"
    );
    assert!(!pass(vec![]), "no track");
    assert!(!pass(mp4_box("mvhd", &[0; 20])));
    assert!(!pass(track("text", "mp4a")), "wrong handler");
    assert!(!pass(mp4_box("trak", &[])));
    assert!(!pass(mp4_box("trak", &mp4_box("mdia", &[]))));
    // A trak with the stsd cut short.
    let short = mp4_box("stsd", &[0; 11]);
    let hdlr = mp4_box("hdlr", &[vec![0; 8], ascii("soun"), vec![0; 13]].concat());
    let minf = mp4_box("minf", &mp4_box("stbl", &short));
    assert!(!pass(mp4_box(
        "trak",
        &mp4_box("mdia", &[hdlr, minf].concat())
    )));
}

/// A `soun` track listing `entries` as its sample entries, with `count` as
/// the stsd entry count.
fn track_entries(entries: &[&str], count: u32) -> Vec<u8> {
    let hdlr = mp4_box("hdlr", &[vec![0; 8], ascii("soun"), vec![0; 13]].concat());
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&count.to_be_bytes());
    for e in entries {
        body.extend(sample_entry(e));
    }
    let minf = mp4_box("minf", &mp4_box("stbl", &mp4_box("stsd", &body)));
    mp4_box("trak", &mp4_box("mdia", &[hdlr, minf].concat()))
}

/// Final review M1: every audio track must be AAC, with one sample entry,
/// and no other kind of track may ride along.
#[test]
fn every_audio_track_must_be_aac_and_nothing_else_may_ride_along() {
    let pass = |trak: Vec<u8>| {
        voice_ok(&[note(), mp4_box("mdat", &[0; 40]), mp4_box("moov", &trak)].concat())
    };
    assert!(
        !pass([track("soun", "alac"), track("soun", "mp4a")].concat()),
        "ALAC first, AAC second"
    );
    assert!(
        !pass([track("soun", "mp4a"), track("soun", "ac-3")].concat()),
        "AAC first, AC-3 second"
    );
    assert!(
        !pass(track_entries(&["mp4a", "Opus"], 2)),
        "one track listing AAC then Opus"
    );
    assert!(
        !pass(track_entries(&["mp4a"], 2)),
        "a count of two with one entry"
    );
    assert!(!pass(track_entries(&["mp4a"], 0)), "a count of zero");
    assert!(pass(track_entries(&["mp4a"], 1)));
    for handler in [
        "text", "sbtl", "subt", "clcp", "vide", "auxv", "pict", "tmcd", "zzzz",
    ] {
        assert!(
            !pass([track("soun", "mp4a"), track(handler, "tx3g")].concat()),
            "{handler} after the audio"
        );
        assert!(
            !pass([track(handler, "tx3g"), track("soun", "mp4a")].concat()),
            "{handler} before the audio"
        );
    }
    // A trak without a readable handler is refused, not skipped.
    assert!(!pass(
        [
            track("soun", "mp4a"),
            mp4_box("trak", &mp4_box("tkhd", &[0; 20]))
        ]
        .concat()
    ));
    // A malformed box after the audio track could hide another track.
    let mut tail = track("soun", "mp4a");
    tail.extend_from_slice(&sized_box("trak", &[0; 4], 400));
    assert!(!pass(tail));
}

/// A `soun` track whose one sample entry is `mp4a` with `body` after the
/// box header.
fn mp4a_track(body: &[u8]) -> Vec<u8> {
    let hdlr = mp4_box("hdlr", &[vec![0; 8], ascii("soun"), vec![0; 13]].concat());
    let stsd = mp4_box(
        "stsd",
        &[vec![0, 0, 0, 0, 0, 0, 0, 1], mp4_box("mp4a", body)].concat(),
    );
    let minf = mp4_box("minf", &mp4_box("stbl", &stsd));
    mp4_box("trak", &mp4_box("mdia", &[hdlr, minf].concat()))
}

/// Coordinator ruling after the final review: the `mp4a` entry's `esds`
/// must name MPEG-4 Audio (0x40). MP3 in an `mp4a` entry, a missing esds,
/// and a malformed or truncated descriptor are refused.
#[test]
fn an_mp4a_track_must_carry_mpeg4_audio() {
    let pass = |trak: Vec<u8>| voice_ok(&[note(), mp4_box("moov", &trak)].concat());
    assert!(pass(mp4a_track(&[vec![0; 28], esds(0x40)].concat())));
    for oti in [0x6Bu8, 0x69, 0x67, 0x00, 0xFF] {
        assert!(
            !pass(mp4a_track(&[vec![0; 28], esds(oti)].concat())),
            "object type {oti:#x}"
        );
    }
    assert!(!pass(mp4a_track(&[0; 28])), "no esds");
    assert!(
        !pass(mp4a_track(
            &[
                vec![0; 28],
                mp4_box("free", &[]),
                mp4_box("wave", &esds(0x40))
            ]
            .concat()
        )),
        "an esds only inside a QuickTime wave box"
    );
    // Truncated: the esds box cut at every length (its size field kept honest).
    let full = esds(0x40);
    for cut in 8..full.len() {
        let short = mp4_box("esds", &full[8..cut]);
        assert!(
            !pass(mp4a_track(&[vec![0; 28], short].concat())),
            "esds cut to {cut}"
        );
    }
    // A descriptor size that runs past the box, or uses a fifth size byte.
    let mut long = full.clone();
    long[8 + 4 + 4] = 0x7F;
    assert!(
        !pass(mp4a_track(&[vec![0; 28], long].concat())),
        "ES size past the end"
    );
    let five = mp4_box(
        "esds",
        &[
            vec![0; 4],
            vec![0x03, 0x80, 0x80, 0x80, 0x80, 0x05],
            vec![0; 8],
        ]
        .concat(),
    );
    assert!(
        !pass(mp4a_track(&[vec![0; 28], five].concat())),
        "five size bytes"
    );
    // The wrong first tag, and a DecoderConfig not where the flags put it.
    let mut tag = full.clone();
    tag[12] = 0x05;
    assert!(
        !pass(mp4a_track(&[vec![0; 28], tag].concat())),
        "not an ES descriptor"
    );
    let mut flags = full.clone();
    flags[8 + 4 + 5 + 2] = 0x80; // stream dependence: two more bytes before the config
    assert!(
        !pass(mp4a_track(&[vec![0; 28], flags].concat())),
        "flags shift the config"
    );
    // One-byte sizes and the optional fields, as other writers lay them out.
    let config = [
        vec![0x04, 17, 0x40, 0x15],
        vec![0; 11],
        vec![0x05, 2, 0x12, 0x10],
    ]
    .concat();
    let es = [
        vec![
            0x03,
            (3 + 2 + 1 + 3 + 2 + config.len()) as u8,
            0,
            1,
            0xE0,
            0,
            7,
            3,
        ],
        b"abc".to_vec(),
        vec![0, 9],
        config,
    ]
    .concat();
    assert!(
        pass(mp4a_track(
            &[vec![0; 28], mp4_box("esds", &[vec![0; 4], es].concat())].concat()
        )),
        "all flags, short sizes"
    );
    // QuickTime sound description versions 1 and 2 (16 and 36 more bytes).
    let mut v1 = vec![0; 44];
    v1[9] = 1;
    assert!(pass(mp4a_track(&[v1, esds(0x40)].concat())), "version 1");
    let mut v2 = vec![0; 64];
    v2[9] = 2;
    assert!(pass(mp4a_track(&[v2, esds(0x40)].concat())), "version 2");
    let mut v3 = vec![0; 28];
    v3[9] = 3;
    assert!(!pass(mp4a_track(&[v3, esds(0x40)].concat())), "version 3");
}

/// Real writers (spec §7): afconvert (as iOS records, `M4A `) and ffmpeg
/// (`isom` and `mp42`, as Android's MediaRecorder brands its files) AAC
/// notes pass; ffmpeg's ALAC-then-AAC, AAC-plus-subtitle, Opus and
/// MP3-in-mp4a files are refused.
#[test]
fn real_voice_files() {
    for (what, bytes) in [
        (
            "afconvert",
            &include_bytes!("fixtures/voice_afconvert.m4a")[..],
        ),
        (
            "ffmpeg isom",
            &include_bytes!("fixtures/voice_ffmpeg_isom.m4a")[..],
        ),
        (
            "ffmpeg mp42",
            &include_bytes!("fixtures/voice_ffmpeg_mp42.m4a")[..],
        ),
    ] {
        assert!(voice_ok(bytes), "{what}");
    }
    for (what, bytes) in [
        (
            "ALAC then AAC",
            &include_bytes!("fixtures/voice_alac_then_aac.m4a")[..],
        ),
        (
            "AAC and a subtitle",
            &include_bytes!("fixtures/voice_aac_subtitle.m4a")[..],
        ),
        ("Opus", &include_bytes!("fixtures/voice_opus.m4a")[..]),
        (
            "MP3 in an mp4a entry (ffmpeg, object type 0x69)",
            &include_bytes!("fixtures/voice_mp3_in_mp4a.m4a")[..],
        ),
    ] {
        assert!(!voice_ok(bytes), "{what}");
    }
}

#[test]
fn the_nested_walk_is_bounded_and_checked() {
    // 2000 boxes inside the moov ahead of the track: the shared cap refuses.
    let mut inner = Vec::new();
    for _ in 0..2_000 {
        inner.extend_from_slice(&mp4_box("free", &[]));
    }
    inner.extend(track("soun", "mp4a"));
    assert!(!voice_ok(&[note(), mp4_box("moov", &inner)].concat()));
    // Hostile sizes inside the moov and the track.
    for size in [0u64, 1, 7, 8, 0x7FFF_FFFF, 0xFFFF_FFFF] {
        let bad = sized_box("trak", &track("soun", "mp4a"), size);
        let v = [note(), mp4_box("moov", &bad)].concat();
        let _ = voice_ok(&v);
        let mdia = [sized_box("mdia", &[0; 40], size)].concat();
        let _ = voice_ok(&[note(), mp4_box("moov", &mp4_box("trak", &mdia))].concat());
    }
    let wrap = [
        be32(1),
        ascii("trak"),
        vec![0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ]
    .concat();
    assert!(!voice_ok(&[note(), mp4_box("moov", &wrap)].concat()));
    // A fragmented file: an empty-moov style track description still counts.
    let frag = [
        note(),
        mp4_box(
            "moov",
            &[
                mp4_box("mvhd", &[0; 20]),
                track("soun", "mp4a"),
                mp4_box("mvex", &[0; 32]),
            ]
            .concat(),
        ),
        mp4_box("moof", &[0; 24]),
        mp4_box("mdat", &[0; 40]),
    ]
    .concat();
    assert!(voice_ok(&frag));
}

#[test]
fn a_video_track_hidden_past_the_box_budget_is_refused() {
    // An AAC track, then enough padding boxes to spend the budget, then video.
    let mut body = track("soun", "mp4a");
    for _ in 0..1100 {
        body.extend_from_slice(&mp4_box("free", &[]));
    }
    body.extend_from_slice(&track("vide", "avc1"));
    let mut d = note();
    d.extend_from_slice(&mp4_box("moov", &body));
    assert!(!voice_ok(&d));
    let mut ok = note();
    ok.extend_from_slice(&moov());
    assert!(voice_ok(&ok));
}

/// Re-review R-L1 and R-L2: the audio object type must be AAC, and an entry
/// carries exactly one esds.
#[test]
fn the_audio_object_type_must_be_aac_and_there_is_one_esds() {
    let pass = |trak: Vec<u8>| voice_ok(&[note(), mp4_box("moov", &trak)].concat());
    fn esds_with_aot(dsi: &[u8]) -> Vec<u8> {
        let config = [
            vec![0x04, (13 + 2 + dsi.len()) as u8, 0x40, 0x15],
            vec![0; 11],
            vec![0x05, dsi.len() as u8],
            dsi.to_vec(),
        ]
        .concat();
        let es = [vec![0x03, (3 + config.len()) as u8, 0, 1, 0], config].concat();
        mp4_box("esds", &[vec![0; 4], es].concat())
    }
    // 2 (LC), 5 (SBR), 29 (PS) pass; 34 (MP3 via escape) and 36 (ALS) don't.
    assert!(pass(mp4a_track(
        &[vec![0; 28], esds_with_aot(&[0x12, 0x10])].concat()
    )));
    assert!(pass(mp4a_track(
        &[vec![0; 28], esds_with_aot(&[0x2A, 0x10])].concat()
    )));
    assert!(pass(mp4a_track(
        &[vec![0; 28], esds_with_aot(&[0xEA, 0x10])].concat()
    )));
    // 34 = 31 escape then 6 bits of 2: 11111 000 | 010 00000
    assert!(!pass(mp4a_track(
        &[vec![0; 28], esds_with_aot(&[0xF8, 0x40])].concat()
    )));
    // 36 = 31 escape then 4: 11111 000 | 100 00000
    assert!(!pass(mp4a_track(
        &[vec![0; 28], esds_with_aot(&[0xF8, 0x80])].concat()
    )));
    assert!(
        !pass(mp4a_track(&[vec![0; 28], esds_with_aot(&[])].concat())),
        "empty DSI"
    );
    // AAC esds first, then a second esds: refused.
    assert!(!pass(mp4a_track(
        &[vec![0; 28], esds(0x40), esds(0x6B)].concat()
    )));
}
