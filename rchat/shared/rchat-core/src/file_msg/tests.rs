//! Task 13: file messages (`0x07`, protocol v3 §E.2, ruling R2): the exact
//! layout, the name sanitiser's rule order and outputs, the advisory MIME,
//! the size check before any allocation, the send limit, and a fuzz pass.

use super::*;

/// The layout, by hand: `0x07 ‖ expire_secs u32 BE ‖ name_len u16 BE ‖
/// name ‖ mime_len u8 ‖ mime ‖ size u64 BE ‖ bytes`.
fn hand_built(expire: u32, name: &[u8], mime: &[u8], size: u64, bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![FILE_TYPE];
    v.extend_from_slice(&expire.to_be_bytes());
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name);
    v.push(mime.len() as u8);
    v.extend_from_slice(mime);
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(bytes);
    v
}

#[test]
fn round_trip() {
    let bytes = b"%PDF-1.7\x00\x01\xff binary \x00 body".to_vec();
    let pt = encode_file("Quarterly report.pdf", "application/pdf", &bytes, 3600).unwrap();
    let msg = decode_file(&pt).unwrap();
    assert_eq!(
        msg,
        FileMsg {
            expire_secs: 3600,
            name: "Quarterly report.pdf".into(),
            mime: "application/pdf".into(),
            bytes,
        }
    );
    assert!(is_valid(&pt));
}

#[test]
fn layout_is_exact() {
    let pt = encode_file("a.txt", "text/plain", b"hi", 0x0102_0304).unwrap();
    assert_eq!(
        pt,
        hand_built(0x0102_0304, b"a.txt", b"text/plain", 2, b"hi")
    );
    assert_eq!(pt.len(), FILE_HEADER_LEN + 5 + 10 + 2);
    assert_eq!(&pt[..5], &[0x07, 0x01, 0x02, 0x03, 0x04]);
}

/// R2: every v3 message plaintext carries the timer; 0 means never.
#[test]
fn expire_secs_round_trips() {
    for expire in [0u32, 1, 300, 604_800, 2_419_200, u32::MAX] {
        let pt = encode_file("x", "", b"", expire).unwrap();
        assert_eq!(decode_file(&pt).unwrap().expire_secs, expire);
    }
}

/// An empty file and an empty MIME are allowed.
#[test]
fn empty_file_and_mime() {
    let pt = encode_file("empty", "", b"", 0).unwrap();
    let msg = decode_file(&pt).unwrap();
    assert_eq!((msg.mime.as_str(), msg.bytes.len()), ("", 0));
}

/// Review Focus 4: the rule order, with every exact output.
#[test]
fn hostile_file_names_are_sanitised() {
    let cases: Vec<(Vec<u8>, String)> = vec![
        // (b) then (c): `.._.._x`, leading dots stripped.
        (b"../../x".to_vec(), "_.._x".into()),
        (b"a\0b".to_vec(), "a_b".into()),
        ("\u{202E}".into(), "_".into()),
        ("\u{202E}gpj.exe".into(), "_gpj.exe".into()),
        (b"".to_vec(), "file".into()),
        (b".".to_vec(), "file".into()),
        (b"..".to_vec(), "file".into()),
        (b"...".to_vec(), "file".into()),
        (b".hidden".to_vec(), "hidden".into()),
        (b"a/b\\c".to_vec(), "a_b_c".into()),
        (b"/etc/passwd".to_vec(), "_etc_passwd".into()),
        (b"x\x01\x1f\x7f".to_vec(), "x___".into()),
        ("a\u{0085}b\u{009F}".into(), "a_b_".into()),
        (b"tab\there\nnl".to_vec(), "tab_here_nl".into()),
        // (a) lossy: an invalid byte is U+FFFD, kept.
        (b"a\xffb".to_vec(), "a\u{FFFD}b".into()),
        // (d) trailing spaces and dots.
        (b"report.".to_vec(), "report".into()),
        (b"report. . ".to_vec(), "report".into()),
        (b"a.txt.".to_vec(), "a.txt".into()),
        (b"   ".to_vec(), "file".into()),
        (b" lead".to_vec(), " lead".into()),
        (b". .".to_vec(), "file".into()),
        // Device names (step (d2)), case-insensitive on the stem.
        (b"CON".to_vec(), "_CON".into()),
        (b"con.txt".to_vec(), "_con.txt".into()),
        (b"Com1.tar.gz".to_vec(), "_Com1.tar.gz".into()),
        (b"LPT9".to_vec(), "_LPT9".into()),
        (b"nul".to_vec(), "_nul".into()),
        (b"aux ".to_vec(), "_aux".into()),
        (b"PRN.".to_vec(), "_PRN".into()),
        (b"CON .txt".to_vec(), "_CON .txt".into()),
        (b"COM0".to_vec(), "_COM0".into()),
        ("COM\u{00B9}.log".into(), "_COM\u{00B9}.log".into()),
        (b"conin$".to_vec(), "_conin$".into()),
        (b"...CON".to_vec(), "_CON".into()),
        (b"CONSOLE.txt".to_vec(), "CONSOLE.txt".into()),
        (b"COM10".to_vec(), "COM10".into()),
        (b"xCON".to_vec(), "xCON".into()),
        (
            b"ordinary name (1).jpg".to_vec(),
            "ordinary name (1).jpg".into(),
        ),
        (
            "caf\u{00E9} \u{1F600}.png".into(),
            "caf\u{00E9} \u{1F600}.png".into(),
        ),
    ];
    for (raw, want) in &cases {
        assert_eq!(
            &sanitise_name(raw),
            want,
            "input {:?}",
            String::from_utf8_lossy(raw)
        );
    }
    for c in [
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}', '\u{061C}',
    ] {
        assert_eq!(sanitise_name(format!("a{c}b").as_bytes()), "a_b", "{c:?}");
    }
}

/// R30 M-2: look-alike separators, every format (Cf) character in the
/// table, and the line and paragraph separators become `_` (replaced,
/// never deleted, so nothing hides between two visible characters).
#[test]
fn format_characters_and_separator_lookalikes_are_replaced() {
    assert_eq!(sanitise_name("\u{200B}".as_bytes()), "_");
    assert_eq!(sanitise_name("a\u{FF0F}b".as_bytes()), "a_b");
    // The zero-width space becomes `_`, so the stem is `CON_`: not a
    // device name, and nothing is hidden.
    assert_eq!(sanitise_name("CON\u{200B}.txt".as_bytes()), "CON_.txt");
    let singles = [
        '\u{FF0F}',
        '\u{FF3C}',
        '\u{FE68}',
        '\u{2215}',
        '\u{2044}',
        '\u{29F8}',
        '\u{29F9}',
        '\u{2216}',
        '\u{00AD}',
        '\u{061C}',
        '\u{06DD}',
        '\u{070F}',
        '\u{08E2}',
        '\u{180E}',
        '\u{FEFF}',
        '\u{110BD}',
        '\u{110CD}',
        '\u{E0001}',
        '\u{2028}',
        '\u{2029}',
    ];
    let ranges = [
        ('\u{0600}', '\u{0605}'),
        ('\u{0890}', '\u{0891}'),
        ('\u{200B}', '\u{200F}'),
        ('\u{202A}', '\u{202E}'),
        ('\u{2060}', '\u{2064}'),
        ('\u{2066}', '\u{206F}'),
        ('\u{FFF9}', '\u{FFFB}'),
        ('\u{13430}', '\u{1343F}'),
        ('\u{1BCA0}', '\u{1BCA3}'),
        ('\u{1D173}', '\u{1D17A}'),
        ('\u{E0020}', '\u{E007F}'),
    ];
    let all = singles
        .into_iter()
        .chain(ranges.into_iter().flat_map(|(a, b)| a..=b));
    for c in all {
        assert_eq!(
            sanitise_name(format!("a{c}b").as_bytes()),
            "a_b",
            "U+{:04X}",
            c as u32
        );
    }
    // Neighbours outside the table are kept.
    for c in [
        '\u{2065}',
        '\u{2070}',
        '\u{FFF8}',
        '\u{FFFC}',
        '\u{E0002}',
        '\u{2217}',
    ] {
        assert_eq!(
            sanitise_name(format!("a{c}b").as_bytes()),
            format!("a{c}b"),
            "U+{:04X}",
            c as u32
        );
    }
}

/// R30 M-1: a device name that only appears after the cut (e) is caught.
#[test]
fn device_name_exposed_by_truncation_is_prefixed() {
    let raw = format!("CON{}b", " ".repeat(300));
    assert_eq!(sanitise_name(raw.as_bytes()), "_CON");
}

/// (e): at most 255 bytes on a char boundary, the extension kept when it
/// is the last `.ext` of 16 bytes or fewer.
#[test]
fn long_names_are_truncated() {
    let a400 = "a".repeat(400);
    assert_eq!(sanitise_name(a400.as_bytes()), "a".repeat(255));
    // Extension kept under truncation.
    let with_ext = format!("{}.pdf", "a".repeat(396));
    assert_eq!(
        sanitise_name(with_ext.as_bytes()),
        format!("{}.pdf", "a".repeat(251))
    );
    // A 16-byte extension (dot included) is kept; a 17-byte one is not.
    let ext16 = format!("{}.{}", "a".repeat(300), "e".repeat(15));
    assert_eq!(
        sanitise_name(ext16.as_bytes()),
        format!("{}.{}", "a".repeat(239), "e".repeat(15))
    );
    let ext17 = format!("{}.{}", "a".repeat(300), "e".repeat(16));
    assert_eq!(sanitise_name(ext17.as_bytes()), "a".repeat(255));
    // Multi-byte: never split a character.
    let e200 = "\u{00E9}".repeat(200);
    assert_eq!(sanitise_name(e200.as_bytes()), "\u{00E9}".repeat(127));
    let e200_ext = format!("{}.txt", "\u{00E9}".repeat(200));
    assert_eq!(
        sanitise_name(e200_ext.as_bytes()),
        format!("{}.txt", "\u{00E9}".repeat(125))
    );
    // 255 invalid bytes become 85 U+FFFD (255 bytes).
    assert_eq!(sanitise_name(&[0xff; 255]), "\u{FFFD}".repeat(85));
    // A cut that leaves trailing spaces is trimmed again.
    let spaced = format!("a{}b", " ".repeat(300));
    assert_eq!(sanitise_name(spaced.as_bytes()), "a");
    // A device prefix comes before the cut, so the result still fits.
    let dev = format!("CON.{}", "x".repeat(300));
    assert_eq!(
        sanitise_name(dev.as_bytes()),
        format!("_CON.{}", "x".repeat(250))
    );
    for raw in [&a400, &with_ext, &ext16, &ext17, &e200, &e200_ext, &dev] {
        assert!(sanitise_name(raw.as_bytes()).len() <= MAX_NAME_BYTES);
    }
}

/// The receiver cleans the name too (it never trusts the sender's).
#[test]
fn decode_sanitises_the_name() {
    let pt = hand_built(0, b"../\xe2\x80\xaeevil", b"", 1, b"z");
    assert_eq!(decode_file(&pt).unwrap().name, "__evil");
    let pt = hand_built(0, b"", b"", 0, b"");
    assert_eq!(decode_file(&pt).unwrap().name, "file");
    // The sender cleans with the same rule: `../x` goes out as `_x`.
    let pt = encode_file("../x", "", b"", 0).unwrap();
    assert_eq!(&pt[5..9], &[0, 2, b'_', b'x']);
}

/// Names on the wire are at most 255 bytes (§E.2); a longer one is dropped.
#[test]
fn over_long_wire_name_dropped() {
    let pt = hand_built(0, &[b'a'; 256], b"", 0, b"");
    assert_eq!(decode_file(&pt), Err(FileError::NameTooLong));
    let pt = hand_built(0, &[b'a'; 255], b"", 0, b"");
    assert_eq!(decode_file(&pt).unwrap().name.len(), 255);
}

#[test]
fn size_mismatch_dropped() {
    let ok = hand_built(0, b"f", b"", 3, b"abc");
    assert!(decode_file(&ok).is_ok());
    for size in [0u64, 2, 4, 1 << 32, u64::MAX] {
        let pt = hand_built(0, b"f", b"", size, b"abc");
        assert_eq!(
            decode_file(&pt),
            Err(FileError::SizeMismatch),
            "size {size}"
        );
        assert!(!is_valid(&pt));
    }
    // A huge declared size allocates nothing near it.
    let pt = hand_built(0, b"f", b"", u64::MAX, b"abc");
    let used = crate::alloc_probe::bytes_allocated(|| {
        let _ = decode_file(&pt);
    });
    assert_eq!(used, 0, "a size mismatch is refused before any allocation");
}

#[test]
fn mime_is_advisory_only() {
    // Refused at encode: longer than 255, not ASCII, or not printable.
    let long = "a".repeat(256);
    assert_eq!(encode_file("f", &long, b"", 0), Err(FileError::MimeInvalid));
    assert!(encode_file("f", &"a".repeat(255), b"", 0).is_ok());
    for bad in [
        "image/p\u{00F1}g",
        "text/plain\n",
        "a\u{0}b",
        "x\u{7f}",
        "x\ty",
    ] {
        assert_eq!(
            encode_file("f", bad, b"", 0),
            Err(FileError::MimeInvalid),
            "{bad:?}"
        );
    }
    // Dropped at decode.
    for bad in [
        &b"image/p\xc3\xb1g"[..],
        b"text\n",
        b"a\x00b",
        b"\x7f",
        b"\xff",
    ] {
        let pt = hand_built(0, b"f", bad, 0, b"");
        assert_eq!(decode_file(&pt), Err(FileError::MimeInvalid), "{bad:?}");
    }
    // Never interpreted: any printable label passes with any bytes.
    let pt = encode_file("x.png", "image/png; charset=\"x\"", b"not a png", 0).unwrap();
    let msg = decode_file(&pt).unwrap();
    assert_eq!(msg.mime, "image/png; charset=\"x\"");
    assert_eq!(msg.bytes, b"not a png");
}

/// The whole plaintext must fit `MAX_FILE_PLAINTEXT` (the relay's 4 MiB
/// `max_message_bytes` minus overhead); larger is refused before sending.
#[test]
fn oversize_refused_before_send() {
    let (name, mime) = ("big.bin", "application/octet-stream");
    let fixed = FILE_HEADER_LEN + name.len() + mime.len();
    let fits = vec![0u8; MAX_FILE_PLAINTEXT - fixed];
    let pt = encode_file(name, mime, &fits, 0).unwrap();
    assert_eq!(pt.len(), MAX_FILE_PLAINTEXT);
    assert_eq!(decode_file(&pt).unwrap().bytes.len(), fits.len());
    let over = vec![0u8; MAX_FILE_PLAINTEXT - fixed + 1];
    assert_eq!(encode_file(name, mime, &over, 0), Err(FileError::TooLarge));
    // The limit leaves room for two padding steps and the envelope.
    assert_eq!(MAX_FILE_PLAINTEXT, (4 << 20) - 2 * 65_536 - 1);
}

#[test]
fn malformed_plaintexts_dropped_without_panic() {
    let good = encode_file("name.txt", "text/plain", b"body", 7).unwrap();
    for cut in 0..good.len() {
        let r = decode_file(&good[..cut]);
        assert!(r.is_err(), "prefix {cut} must not decode");
        assert!(!is_valid(&good[..cut]));
    }
    let mut wrong_type = good.clone();
    wrong_type[0] = 0x02;
    assert_eq!(decode_file(&wrong_type), Err(FileError::NotAFile));
    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(decode_file(&extra), Err(FileError::SizeMismatch));
}

/// Fuzz-style: random byte strings, and random mutations of a valid
/// plaintext, never panic, and never allocate more than the input plus a
/// fixed bound for the name and MIME work (255-byte name, up to 3 bytes per
/// lossy character in two buffers, plus the 255-byte MIME).
#[test]
fn decode_fuzz_never_panics_or_over_allocates() {
    use rand::{Rng, SeedableRng};
    const NAME_WORK: usize = 4 * 1024;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x0713);
    let seed = encode_file("seed.bin", "application/x", &[7u8; 64], 9).unwrap();
    for i in 0..20_000 {
        let input: Vec<u8> = if i % 2 == 0 {
            let len = rng.gen_range(0..600);
            let mut v: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            if !v.is_empty() && rng.gen_bool(0.7) {
                v[0] = FILE_TYPE;
            }
            v
        } else {
            let mut v = seed.clone();
            for _ in 0..rng.gen_range(1..6) {
                let at = rng.gen_range(0..v.len());
                v[at] = rng.gen();
            }
            v.truncate(rng.gen_range(0..=v.len()));
            v
        };
        let mut out = None;
        let used = crate::alloc_probe::bytes_allocated(|| {
            out = Some(decode_file(&input));
        });
        assert!(
            used <= input.len() + NAME_WORK,
            "allocated {used} for {} input bytes",
            input.len()
        );
        if let Some(Ok(msg)) = out {
            assert!(msg.name.len() <= MAX_NAME_BYTES && !msg.name.is_empty());
            assert!(msg.mime.len() <= MAX_MIME_BYTES);
            assert!(is_valid(&input));
        }
    }
}

// ---------------------------------------------------------------------------
// The receive path: routing, dedupe, receipts, the wire bound
// ---------------------------------------------------------------------------

mod flow {
    use super::*;
    use crate::test_support::*;
    use std::time::{Duration, Instant};

    fn files(log: &std::sync::Mutex<Vec<Ev>>) -> Vec<FileEv> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::File(f) => Some(f.clone()),
                _ => None,
            })
            .collect()
    }

    fn messages(log: &std::sync::Mutex<Vec<Ev>>) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Ev::Message(..)))
            .count()
    }

    /// A received 0x07 reaches only the file callback, with every field;
    /// a malformed one reaches nothing and is never receipted.
    #[test]
    fn files_reach_only_the_file_callback() {
        let mut p = establish(0xA1, 0xB2);
        p.b.receipt_delay_override = Some(Duration::from_secs(60));
        let good = encode_file("../notes.txt", "text/plain", b"hello\x00file", 300).unwrap();
        let bad_size = hand_built(0, b"x", b"", 99, b"short");
        let bad_mime = hand_built(0, b"x", b"\xff", 0, b"");
        let ids = [[0x31u8; 16], [0x32; 16], [0x33; 16]];
        for (id, pt) in ids.iter().zip([&good, &bad_size, &bad_mime]) {
            let msg = p.a.seal_ratchet(&p.pb.hex, *id, pt).unwrap();
            p.b.handle_sealed_payload(&msg.payload);
        }
        assert_eq!(
            files(&p.b_log),
            vec![FileEv {
                sender: p.pa.hex.clone(),
                id: hex::encode(ids[0]),
                name: "_notes.txt".into(),
                mime: "text/plain".into(),
                expire_secs: 300,
                bytes: b"hello\x00file".to_vec(),
            }]
        );
        assert_eq!(messages(&p.b_log), 0, "never the message callback");
        for id in ids {
            p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
        }
        let queued =
            p.b.pending_receipts
                .get(&(p.pa.hex.clone(), crate::receipts::DELIVERED))
                .cloned()
                .unwrap_or_default();
        assert_eq!(queued, vec![ids[0]], "a dropped file is never receipted");
    }

    /// The same sealed file twice (a relay replay) is delivered once.
    #[test]
    fn a_replayed_file_is_delivered_once() {
        let mut p = establish(0xA1, 0xB2);
        let pt = encode_file("a.bin", "", &[1, 2, 3], 0).unwrap();
        let msg = p.a.seal_ratchet(&p.pb.hex, [0x41; 16], &pt).unwrap();
        p.b.handle_sealed_payload(&msg.payload);
        p.b.handle_sealed_payload(&msg.payload);
        assert_eq!(files(&p.b_log).len(), 1);
        // Stored by the app: a later copy is not delivered again either.
        p.b.mark_seen_and_receipt(&p.pa.hex, [0x41; 16]).unwrap();
        p.b.handle_sealed_payload(&msg.payload);
        assert_eq!(files(&p.b_log).len(), 1);
    }

    /// The receiver's delivered receipt for a file reaches the sender's
    /// receipt callback: a file is recorded as sent like any message.
    #[test]
    fn file_receipts_reach_the_sender() {
        let mut p = establish(0xA1, 0xB2);
        let pt = encode_file("r.txt", "", b"r", 0).unwrap();
        let id = [0x51u8; 16];
        let packet = p.a.seal_ratchet(&p.pb.hex, id, &pt).unwrap();
        p.a.send_now(packet.encode_with_frame_type()).unwrap();
        relay_all(&mut p.a_rx, &mut p.b);
        assert_eq!(files(&p.b_log).len(), 1);
        p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
        p.b.fire_due_receipts(Instant::now() + Duration::from_secs(3));
        assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1);
        assert!(p.a_log.lock().unwrap().contains(&Ev::Receipt(
            p.pb.hex.clone(),
            hex::encode(id),
            crate::receipts::DELIVERED
        )));
    }

    /// Without an app attached the file is dropped (wiped), not queued.
    #[test]
    fn no_callbacks_no_panic() {
        let mut p = establish(0xA1, 0xB2);
        p.b.callbacks = None;
        let pt = encode_file("a", "", b"secret", 0).unwrap();
        let msg = p.a.seal_ratchet(&p.pb.hex, [0x61; 16], &pt).unwrap();
        p.b.handle_sealed_payload(&msg.payload);
        assert!(files(&p.b_log).is_empty());
    }

    /// R29, on a real pair: three maximum files and a text, sealed and
    /// tracked as the send path does, all stay tracked (no AckUnknown).
    #[test]
    fn max_files_do_not_evict_each_other_or_texts() {
        let p = establish(0xA1, 0xB2);
        let fixed = FILE_HEADER_LEN + 1;
        let pt = encode_file("m", "", &vec![0xCD; MAX_FILE_PLAINTEXT - fixed], 0).unwrap();
        let track = |id: [u8; 16], pt: &[u8]| {
            let packet = p.a.seal_ratchet(&p.pb.hex, id, pt).unwrap();
            p.a.track_sent(
                &p.pb.hex,
                &hex::encode(id),
                packet.circuit_id,
                packet.payload,
                pt,
            );
        };
        track([0x81; 16], b"\x01\0\0\0\0hello");
        for n in 0..3u8 {
            track([0x90 + n; 16], &pt);
        }
        let unknown = p
            .a_log
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Ev::Status(crate::status::StatusEvent::AckUnknown { .. })))
            .count();
        assert_eq!(unknown, 0);
        assert_eq!(p.a.acks.lock().unwrap().len(), 4);
    }

    /// The largest file plaintext still fits the relay's 4 MiB message on
    /// the wire, sealed normally and sealed as the session-init (padded
    /// twice), and it decrypts.
    #[test]
    fn largest_file_fits_the_relay_message() {
        let fixed = FILE_HEADER_LEN + 1;
        let pt = encode_file("m", "", &vec![0xAB; MAX_FILE_PLAINTEXT - fixed], 0).unwrap();
        assert_eq!(pt.len(), MAX_FILE_PLAINTEXT);

        // Normal seal.
        let mut p = establish(0xA1, 0xB2);
        let packet = p.a.seal_ratchet(&p.pb.hex, [0x71; 16], &pt).unwrap();
        let wire = packet.encode_with_frame_type().len();
        assert!(wire <= RELAY_MAX_MESSAGE_BYTES, "normal: {wire}");
        p.b.handle_sealed_payload(&packet.payload);
        assert_eq!(files(&p.b_log)[0].bytes.len(), MAX_FILE_PLAINTEXT - fixed);

        // As the session-init: a fresh pair, A's hello not yet sent.
        let (mut a, mut a_rx) = published(0xA3);
        let (mut b, _b_rx) = published(0xB4);
        let b_log = install_event_log(&mut b);
        let (pa, pb) = (peer(0xA3), peer(0xB4));
        a.peers.pin_card(&pb).unwrap();
        b.peers.pin_card(&pa).unwrap();
        let (ek_a, ek_b) = (
            crate::crypto::EphemeralKeyPair::generate(),
            crate::crypto::EphemeralKeyPair::generate(),
        );
        let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
        let now = Instant::now();
        a.peers.push_ask(&pb.hex, ek_a, now);
        b.peers.push_ask(&pa.hex, ek_b, now);
        feed(&mut a, created_v3(0, &pb.bundle, i_ek, r_ek));
        feed(&mut b, created_v3(1, &pa.bundle, i_ek, r_ek));
        drain(&mut a_rx); // the hello's init: dropped, so the file carries it
        a.session_manager
            .get_mut(&pb.hex)
            .unwrap()
            .init_out
            .as_mut()
            .expect("an unanswered init")
            .sent = None;
        let packet = a.seal_ratchet(&pb.hex, [0x72; 16], &pt).unwrap();
        let sent_as_init = a
            .session_manager
            .get_mut(&pb.hex)
            .unwrap()
            .init_out
            .as_ref()
            .and_then(|i| i.sent.as_ref().map(|s| s.id));
        assert_eq!(sent_as_init, Some([0x72; 16]), "sealed as the session-init");
        let wire = packet.encode_with_frame_type().len();
        assert!(wire <= RELAY_MAX_MESSAGE_BYTES, "session-init: {wire}");
        b.handle_sealed_payload(&packet.payload);
        assert_eq!(files(&b_log).len(), 1, "the init-wrapped file decrypts");
    }
}

// ---------------------------------------------------------------------------
// The send path
// ---------------------------------------------------------------------------

/// What the send path seals (`MessageType::File` behind its type byte) is
/// exactly the `encode_file` plaintext.
#[test]
fn send_path_seals_a_0x07_plaintext() {
    let body = encode_file_body("a/b.txt", "text/plain", b"xyz", 60).unwrap();
    let pt = crate::steady::message_plaintext(crate::protocol::MessageType::File, &body);
    assert_eq!(
        pt,
        encode_file("a/b.txt", "text/plain", b"xyz", 60).unwrap()
    );
    assert_eq!(decode_file(&pt).unwrap().name, "a_b.txt");
}

/// `send_file_message` refuses an oversize file or a bad MIME before
/// anything else (no peer, no connection needed); a good one gets as far
/// as the connection check.
#[test]
fn client_send_file_checks_before_sending() {
    use crate::{ClientConfig, RChatClient, RChatError};
    const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";
    let client = RChatClient::new(ClientConfig::default()).unwrap();
    let over = vec![0u8; MAX_FILE_PLAINTEXT];
    assert!(matches!(
        client.send_file_message(PEER.into(), "f".into(), "".into(), over),
        Err(RChatError::FileTooLarge { .. })
    ));
    assert!(matches!(
        client.send_file_message(PEER.into(), "f".into(), "bad\n".into(), vec![1]),
        Err(RChatError::InvalidParameter { .. })
    ));
    client
        .pin_peer_key(PEER.into(), PEER_AK.into(), None)
        .unwrap();
    assert!(matches!(
        client.send_file_message(PEER.into(), "f".into(), "".into(), vec![1]),
        Err(RChatError::NotConnected)
    ));
}

// ---------------------------------------------------------------------------
// R30 M-4: every plaintext copy on the file paths is wiped before it is
// freed (`alloc_probe`)
// ---------------------------------------------------------------------------

mod wipes {
    use super::*;
    use crate::alloc_probe::{freed_containing, freed_containing_any_thread};
    use crate::test_support::*;

    fn needle() -> [u8; 32] {
        rand::random()
    }

    /// A file body holding `n` (twice, so any slice copy holds it whole).
    fn body_with(n: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(66);
        b.extend_from_slice(n);
        b.extend_from_slice(b"--");
        b.extend_from_slice(n);
        b
    }

    /// `encode_file`'s intermediate body is wiped (the result is kept).
    #[test]
    fn encode_file_wipes_its_body() {
        let n = needle();
        let data = body_with(&n);
        let mut out = None;
        let hits = freed_containing(n, || {
            out = Some(encode_file("a", "", &data, 0).unwrap());
        });
        assert_eq!(hits, 0);
        assert!(out.is_some());
    }

    /// A received file with no app attached is wiped, never just freed;
    /// so is every plaintext copy on the receive path.
    #[test]
    fn received_file_without_an_app_is_wiped() {
        let mut p = establish(0xA1, 0xB2);
        p.b.callbacks = None;
        let n = needle();
        let pt = encode_file("a", "", &body_with(&n), 0).unwrap();
        let msg = p.a.seal_ratchet(&p.pb.hex, [0x62; 16], &pt).unwrap();
        let hits = freed_containing(n, || p.b.handle_sealed_payload(&msg.payload));
        assert_eq!(hits, 0);
    }

    /// `send_file_message` wipes the caller's `data`, and the encoded body
    /// (`send_payload`'s `content`) is wiped when the send fails, on
    /// whichever thread it ends.
    #[test]
    fn send_file_wipes_data_and_body() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        let n = needle();
        let data = body_with(&n);
        let hits = freed_containing_any_thread(n, || {
            let r = client.send_file_message(PEER.into(), "f".into(), "".into(), data);
            assert!(r.is_err(), "not connected");
        });
        assert_eq!(hits, 0);
    }

    /// Task 14: the same-id and checked file sends wipe the caller's data
    /// and the encoded body too, whichever way they end.
    #[test]
    fn same_id_file_sends_wipe_data_and_body() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        let id = "ab".repeat(16);
        for checked in [false, true] {
            let n = needle();
            let data = body_with(&n);
            let hits = freed_containing_any_thread(n, || {
                let r = if checked {
                    client.resend_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        "".into(),
                        data,
                        0,
                        id.clone(),
                    )
                } else {
                    client.send_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        "".into(),
                        data,
                        id.clone(),
                    )
                };
                assert!(r.is_err());
            });
            assert_eq!(hits, 0, "checked: {checked}");
        }
    }

    /// R31: the text and binary same-id sends leave no plaintext copy
    /// either (the send future is built on `block_on_async`'s own thread,
    /// so no caller stack lands in the heap box it travels in).
    #[test]
    fn same_id_text_and_binary_sends_wipe_their_content() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        let id = "ab".repeat(16);
        for kind in 0..4 {
            let n = ascii_needle();
            let hits = freed_containing_any_thread(n, || {
                let r = match kind {
                    0 => client.send_text_message_using_id(PEER.into(), text_with(&n), id.clone()),
                    1 => client.resend_text_message_using_id(
                        PEER.into(),
                        text_with(&n),
                        0,
                        id.clone(),
                    ),
                    2 => {
                        client.send_binary_message_using_id(PEER.into(), image_with(&n), id.clone())
                    }
                    _ => client.resend_binary_message_using_id(
                        PEER.into(),
                        image_with(&n),
                        0,
                        id.clone(),
                    ),
                };
                assert!(r.is_err());
            });
            assert_eq!(hits, 0, "kind {kind}");
        }
    }

    /// R31 M2: a refused id never drops the content unwiped, for files,
    /// texts and media.
    #[test]
    fn a_refused_id_wipes_the_content() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        for kind in 0..6 {
            let n = ascii_needle();
            let bad = "zz".to_string();
            let hits = freed_containing_any_thread(n, || {
                let r = match kind {
                    0 => client.send_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        "".into(),
                        body_with(&n),
                        bad,
                    ),
                    1 => client.resend_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        "".into(),
                        body_with(&n),
                        0,
                        bad,
                    ),
                    2 => client.send_text_message_using_id(PEER.into(), text_with(&n), bad),
                    3 => client.resend_text_message_using_id(PEER.into(), text_with(&n), 0, bad),
                    4 => client.send_binary_message_using_id(PEER.into(), image_with(&n), bad),
                    _ => client.resend_binary_message_using_id(PEER.into(), image_with(&n), 0, bad),
                };
                assert!(
                    matches!(r, Err(crate::RChatError::Internal { .. })),
                    "kind {kind}: {r:?}"
                );
            });
            assert_eq!(hits, 0, "kind {kind}");
        }
    }

    /// 32 random ASCII letters and digits (a needle a text can hold).
    fn ascii_needle() -> [u8; 32] {
        const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut n = [0u8; 32];
        for b in n.iter_mut() {
            *b = SET[rand::random::<usize>() % SET.len()];
        }
        n
    }

    fn text_with(n: &[u8; 32]) -> String {
        String::from_utf8(body_with(n)).unwrap()
    }

    /// Built before the probe is armed (its own temporaries are not wiped).
    fn image_with(n: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(70);
        v.extend_from_slice(b"IMG1");
        v.extend_from_slice(n);
        v.extend_from_slice(b"--");
        v.extend_from_slice(n);
        v
    }

    /// The ratchet plaintext `send_queued_message` builds is wiped.
    #[test]
    fn send_queued_message_wipes_its_plaintext() {
        let p = establish(0xA1, 0xB2);
        let peer = p.pb.hex.clone();
        let n = needle();
        let body = encode_file_body("a", "", &body_with(&n), 0).unwrap();
        let inner = std::sync::Arc::new(tokio::sync::RwLock::new(p.a));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut sent = None;
        let hits = freed_containing(n, || {
            sent = Some(rt.block_on(crate::RChatClient::send_queued_message(
                inner.clone(),
                peer,
                &body,
                crate::protocol::MessageType::File,
                [0x63; 16],
                false,
                false,
            )));
        });
        assert!(sent.unwrap().is_ok());
        assert_eq!(hits, 0);
    }

    /// A queued (pending) message's content is wiped when it goes.
    #[test]
    fn pending_message_content_is_wiped() {
        let n = needle();
        let hits = freed_containing(n, || {
            drop(crate::session::PendingMessage {
                id: crate::protocol::MessageId("00".repeat(16)),
                content: body_with(&n),
                msg_type: crate::protocol::MessageType::File,
                timestamp_ms: 0,
            });
        });
        assert_eq!(hits, 0);
    }
}

// ---------------------------------------------------------------------------
// Task 14 carry-over: same-id file sends (the app's Retry) and the checked
// automatic resend (spec §18.6 D38, final review H-1)
// ---------------------------------------------------------------------------

mod same_id {
    use super::*;
    use crate::test_support::*;
    use crate::RChatError;

    /// `send_file_message_using_id` seals a 0x07 under the given envelope
    /// id, and the receiver gets the file (cleaned name, MIME, and the
    /// contact's current timer, Task 14b).
    #[test]
    fn send_file_using_id_uses_the_given_envelope_id() {
        let mut p = establish(0xA1, 0xB2);
        drain(&mut p.a_rx);
        p.a.is_connected = true;
        p.a.websocket.as_ref().unwrap().set_connected_for_test();
        let peer_hex = p.pb.hex.clone();
        crate::disappearing::lock_timers(&p.a).insert(
            peer_hex.clone(),
            crate::disappearing::PeerTimer {
                secs: 300,
                changed_at_ms: 1,
                by_me: true,
                acked: true,
                out_id: None,
                resends: 0,
            },
        );
        let client = wrap(p.a);
        let id_hex = "0123456789abcdef0123456789abcdef".to_string();
        let sent = client.send_file_message_using_id(
            peer_hex.clone(),
            "../r.pdf".into(),
            "application/pdf".into(),
            b"%PDF".to_vec(),
            id_hex.clone(),
        );
        assert_eq!(sent.unwrap(), id_hex);
        let relays = sent_relays(&mut p.a_rx);
        assert_eq!(relays.len(), 1);
        assert_eq!(
            crate::sealed::peek_message_id(&relays[0].payload).map(hex::encode),
            Some(id_hex.clone())
        );
        p.b.handle_sealed_payload(&relays[0].payload);
        let got = flow_files(&p.b_log);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, id_hex);
        assert_eq!(got[0].name, "_r.pdf");
        assert_eq!(got[0].mime, "application/pdf");
        assert_eq!(got[0].expire_secs, 300);
        assert_eq!(got[0].bytes, b"%PDF".to_vec());
        assert!(client
            .send_file_message_using_id(peer_hex, "f".into(), "".into(), vec![1], "nothex".into())
            .is_err());
    }

    /// With a good id, the same-id and checked entries refuse an oversize
    /// file or a bad MIME, and a bad id with a good file, before any
    /// connection check (the id itself is checked first:
    /// `same_id_file_sends_check_the_id_first`).
    #[test]
    fn same_id_file_sends_check_before_sending() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        const PEER_AK: &str = "0100000000000000000000000000000000000000000000000000000000000001";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        let id = "ab".repeat(16);
        type Send = fn(
            &RChatClient,
            String,
            String,
            String,
            Vec<u8>,
            u32,
            String,
        ) -> Result<String, RChatError>;
        // The Retry takes the current timer (its `u32` is ignored here);
        // the checked resend the original one.
        fn retry(
            c: &RChatClient,
            r: String,
            n: String,
            m: String,
            d: Vec<u8>,
            _: u32,
            i: String,
        ) -> Result<String, RChatError> {
            c.send_file_message_using_id(r, n, m, d, i)
        }
        let entries: [Send; 2] = [retry, RChatClient::resend_file_message_using_id];
        for send in entries {
            let over = vec![0u8; MAX_FILE_PLAINTEXT];
            assert!(matches!(
                send(
                    &client,
                    PEER.into(),
                    "f".into(),
                    "".into(),
                    over,
                    0,
                    id.clone()
                ),
                Err(RChatError::FileTooLarge { .. })
            ));
            assert!(matches!(
                send(
                    &client,
                    PEER.into(),
                    "f".into(),
                    "bad\n".into(),
                    vec![1],
                    0,
                    id.clone()
                ),
                Err(RChatError::InvalidParameter { .. })
            ));
            assert!(matches!(
                send(
                    &client,
                    PEER.into(),
                    "f".into(),
                    "".into(),
                    vec![1],
                    0,
                    "zz".into()
                ),
                Err(RChatError::Internal { .. })
            ));
        }
        client
            .pin_peer_key(PEER.into(), PEER_AK.into(), None)
            .unwrap();
        // Pinned: the plain send gets as far as the connection check; the
        // checked one stops at H-1 first (nothing made this id eligible).
        assert!(matches!(
            client.send_file_message_using_id(
                PEER.into(),
                "f".into(),
                "".into(),
                vec![1],
                id.clone()
            ),
            Err(RChatError::NotConnected)
        ));
        assert!(matches!(
            client.resend_file_message_using_id(PEER.into(), "f".into(), "".into(), vec![1], 0, id),
            Err(RChatError::ResendRefused { .. })
        ));
    }

    /// R31 M2: the id is checked first: a bad id with an oversize file or
    /// a bad MIME is refused for the id.
    #[test]
    fn same_id_file_sends_check_the_id_first() {
        use crate::{ClientConfig, RChatClient};
        const PEER: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
        let client = RChatClient::new(ClientConfig::default()).unwrap();
        for checked in [false, true] {
            let send = |data: Vec<u8>, mime: &str| {
                if checked {
                    client.resend_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        mime.into(),
                        data,
                        0,
                        "zz".into(),
                    )
                } else {
                    client.send_file_message_using_id(
                        PEER.into(),
                        "f".into(),
                        mime.into(),
                        data,
                        "zz".into(),
                    )
                }
            };
            assert!(matches!(
                send(vec![0u8; MAX_FILE_PLAINTEXT], ""),
                Err(RChatError::Internal { .. })
            ));
            assert!(matches!(
                send(vec![1], "bad\n"),
                Err(RChatError::Internal { .. })
            ));
        }
    }

    /// H-1 for files: an id that was never made eligible is refused by the
    /// checked resend, and nothing is sent or parked.
    #[test]
    fn checked_file_resend_refused_without_eligibility() {
        let mut p = establish(0xA1, 0xB2);
        drain(&mut p.a_rx);
        p.a.is_connected = true;
        p.a.websocket.as_ref().unwrap().set_connected_for_test();
        let peer_hex = p.pb.hex.clone();
        let client = wrap(p.a);
        let sent = client.resend_file_message_using_id(
            peer_hex,
            "a.bin".into(),
            "".into(),
            vec![1, 2, 3],
            0,
            "cd".repeat(16),
        );
        assert!(
            matches!(sent, Err(RChatError::ResendRefused { .. })),
            "{sent:?}"
        );
        assert!(sent_relays(&mut p.a_rx).is_empty());
    }

    /// H-1: under the session that made the id eligible, the checked file
    /// resend goes, keeping the id and the original timer.
    #[test]
    fn checked_file_resend_goes_under_the_eligible_session() {
        let mut r = rv3_run_with_keys(1, Some(3), Some(3), |_, _| {});
        let id_hex = hex::encode(r.ids[0]);
        let a = std::mem::replace(
            &mut r.p.a,
            crate::ClientInner::new(crate::ClientConfig::default()),
        );
        let client = wrap(a);
        let sent = client.resend_file_message_using_id(
            r.p.pb.hex.clone(),
            "q0.txt".into(),
            "text/plain".into(),
            b"q0".to_vec(),
            3600,
            id_hex.clone(),
        );
        assert_eq!(sent.unwrap(), id_hex);
        let frames = sent_relays(&mut r.p.a_rx);
        assert_eq!(frames.len(), 1);
        feed(&mut r.b2, crate::protocol::Frame::Relay(frames[0].clone()));
        let got = flow_files(&r.b2_log);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, id_hex);
        assert_eq!(got[0].expire_secs, 3600);
        assert_eq!(got[0].bytes, b"q0".to_vec());
    }

    fn flow_files(log: &std::sync::Mutex<Vec<Ev>>) -> Vec<FileEv> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::File(f) => Some(f.clone()),
                _ => None,
            })
            .collect()
    }
}
