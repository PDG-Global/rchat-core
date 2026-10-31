//! File safety spec §3 and §7: a table of real samples per category,
//! ordinary files that must pass, extension-only and content-only cases,
//! malformed and hostile zips, and the bounds (bounded allocation, no panic).

use super::*;

// --- sample builders -------------------------------------------------------

/// One zip entry: name, bytes, general-purpose flags, method (0 stored).
struct E<'a>(&'a str, &'a [u8], u16, u16);

/// A zip as a writer lays it out: local headers and data, the central
/// directory, then the end record. CRCs are left 0 (never checked).
fn zip_of(entries: &[E]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for E(name, data, flags, method) in entries {
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // time, date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // made by
        central.extend_from_slice(&20u16.to_le_bytes()); // needed
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 4]); // time, date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 2]); // extra
        central.extend_from_slice(&[0; 2]); // comment
        central.extend_from_slice(&[0; 2]); // disk
        central.extend_from_slice(&[0; 2]); // internal attributes
        central.extend_from_slice(&[0; 4]); // external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    end_record(
        &mut out,
        entries.len() as u16,
        central.len() as u32,
        cd_offset,
        0,
    );
    out
}

fn end_record(out: &mut Vec<u8>, count: u16, size: u32, offset: u32, comment: u16) {
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]); // disk numbers
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&comment.to_le_bytes());
}

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    zip_of(
        &entries
            .iter()
            .map(|(n, d)| E(n, d, 0, 0))
            .collect::<Vec<_>>(),
    )
}

/// An OLE2 file: the header sector, then one directory sector holding
/// `entries` (UTF-16LE name, type: 1 storage, 2 stream, 5 root).
fn ole2(entries: &[(&str, u8)]) -> Vec<u8> {
    let mut v = vec![0u8; 512];
    v[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    let mut sector = vec![0u8; 512];
    for (i, (name, kind)) in entries.iter().enumerate() {
        let e = &mut sector[i * 128..(i + 1) * 128];
        let units: Vec<u16> = name.encode_utf16().collect();
        for (j, u) in units.iter().enumerate() {
            e[2 * j..2 * j + 2].copy_from_slice(&u.to_le_bytes());
        }
        e[64..66].copy_from_slice(&(((units.len() + 1) * 2) as u16).to_le_bytes());
        e[66] = *kind;
    }
    v.extend_from_slice(&sector);
    v
}

fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

const PDF: &[u8] = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n";
const JPEG: &[u8] = &[
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0,
];
const PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
];
const M4A: &[u8] = b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00M4A mp42\x00\x00\x00\x08moov";
const CSV: &[u8] = b"name,amount\nAnn,12\nBo,7\n";

// --- the sample table (spec §7) ------------------------------------------

#[test]
fn every_category_is_blocked_by_content() {
    let apk = zip(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00"),
        ("classes.dex", b"dex\n035\0"),
        ("resources.arsc", b""),
    ]);
    let apk_manifest_only = zip(&[("AndroidManifest.xml", b"x"), ("classes2.DEX", b"x")]);
    let ipa = zip(&[("Payload/", b""), ("Payload/Demo.app/Info.plist", b"<?xml")]);
    let profile = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"\">\n<plist version=\"1.0\"><dict><key>PayloadContent</key><array/><key>PayloadType</key><string>Configuration</string></dict></plist>";
    let mut signed_profile = vec![0x30, 0x82, 0x10, 0x00, 0x06, 0x09];
    signed_profile
        .extend_from_slice(b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02 ... <key>PayloadType</key>");
    let bplist = b"bplist00\xd1\x01\x02[PayloadType]Configuration";
    let docm = zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
        ("word/vbaProject.bin", b"\xd0\xcf"),
    ]);
    let xls_macros = ole2(&[
        ("Root Entry", 5),
        ("Workbook", 2),
        ("_VBA_PROJECT_CUR", 1),
        ("_VBA_PROJECT", 2),
    ]);
    let doc_macros = ole2(&[("Root Entry", 5), ("WordDocument", 2), ("Macros", 1)]);
    let nested_apk = zip(&[("readme.txt", b"hi"), ("tools/helper.apk", b"PK\x03\x04")]);
    let encrypted = zip_of(&[E("secret.pdf", PDF, 0x0001, 0)]);
    let strong = zip_of(&[E("secret.pdf", PDF, 0x0040, 0)]);
    let html_bom = "\u{FEFF}  \n\t<!DOCTYPE html><html><body>Pay here</body></html>"
        .as_bytes()
        .to_vec();
    let html_utf16 = utf16le_with_bom("  <HTML><body>x</body></HTML>");
    let svg =
        b"<?xml version=\"1.0\"?>\n<!-- drawn -->\n<SVG xmlns=\"http://www.w3.org/2000/svg\"/>";
    let bare_svg = b"<svg onload=\"x()\"></svg>";
    let table: &[(&str, &[u8], Verdict)] = &[
        ("app.zip", &apk, Verdict::AndroidApp),
        ("bundle.zip", &apk_manifest_only, Verdict::AndroidApp),
        ("classes.dat", b"dex\n035\0rest", Verdict::AndroidApp),
        ("game.zip", &ipa, Verdict::AppleAppOrProfile),
        ("settings.txt", profile, Verdict::AppleAppOrProfile),
        ("signed.p7", &signed_profile, Verdict::AppleAppOrProfile),
        ("x.dat", bplist, Verdict::AppleAppOrProfile),
        (
            "setup.pdf",
            b"MZ\x90\x00\x03\x00\x00\x00\x04",
            Verdict::Program,
        ),
        ("a.txt", b"\x7fELF\x02\x01\x01", Verdict::Program),
        ("m1", &[0xFE, 0xED, 0xFA, 0xCE, 0], Verdict::Program),
        ("m2", &[0xFE, 0xED, 0xFA, 0xCF, 0], Verdict::Program),
        ("m3", &[0xCE, 0xFA, 0xED, 0xFE, 0], Verdict::Program),
        ("m4", &[0xCF, 0xFA, 0xED, 0xFE, 0], Verdict::Program),
        ("fat", &[0xCA, 0xFE, 0xBA, 0xBE, 0], Verdict::Program),
        ("notes.txt", b"#!/bin/sh\necho hi\n", Verdict::Program),
        ("page.txt", &html_bom, Verdict::WebPage),
        ("page16.txt", &html_utf16, Verdict::WebPage),
        ("drawing.png", svg, Verdict::WebPage),
        ("x", bare_svg, Verdict::WebPage),
        ("report.docx", &docm, Verdict::MacroDocument),
        ("budget.xls", &xls_macros, Verdict::MacroDocument),
        ("letter.doc", &doc_macros, Verdict::MacroDocument),
        ("tools.zip", &nested_apk, Verdict::AndroidApp),
        ("locked.zip", &encrypted, Verdict::Unchecked),
        ("locked2.zip", &strong, Verdict::Unchecked),
        ("a.dat", b"Rar!\x1a\x07\x00", Verdict::Unchecked),
        ("b.dat", b"7z\xbc\xaf\x27\x1c\x00\x04", Verdict::Unchecked),
        ("c.dat", b"MSCF\0\0\0\0", Verdict::Unchecked),
    ];
    for (name, bytes, want) in table {
        assert_eq!(classify(name, bytes), *want, "{name}");
    }
}

#[test]
fn every_category_is_blocked_by_extension() {
    for name in [
        "x.apk",
        "x.apks",
        "x.xapk",
        "x.apkm",
        "x.aab",
        "x.dex",
        "x.ipa",
        "x.mobileconfig",
        "x.mobileprovision",
        "x.shortcut",
        "x.itms",
        "x.exe",
        "x.dll",
        "x.scr",
        "x.msi",
        "x.com",
        "x.bat",
        "x.cmd",
        "x.ps1",
        "x.psm1",
        "x.vbs",
        "x.vbe",
        "x.js",
        "x.jse",
        "x.wsf",
        "x.hta",
        "x.jar",
        "x.sh",
        "x.bash",
        "x.zsh",
        "x.command",
        "x.app",
        "x.pkg",
        "x.dmg",
        "x.run",
        "x.bin",
        "x.elf",
        "x.so",
        "x.dylib",
        "x.py",
        "x.pl",
        "x.rb",
        "x.lnk",
        "x.reg",
        "x.cpl",
        "x.inf",
        "x.scf",
        "x.url",
        "x.desktop",
        "x.html",
        "x.htm",
        "x.xhtml",
        "x.shtml",
        "x.mht",
        "x.mhtml",
        "x.svg",
        "x.svgz",
        "x.webarchive",
        "x.docm",
        "x.dotm",
        "x.xlsm",
        "x.xltm",
        "x.xlam",
        "x.xlsb",
        "x.pptm",
        "x.potm",
        "x.ppam",
        "x.ppsm",
        "x.sldm",
        "x.rar",
        "x.7z",
        "x.cab",
        "x.iso",
        "x.img",
        "x.war",
        "x.ear",
        "x.xpi",
        "x.crx",
        "x.appx",
        "x.appxbundle",
        "x.msix",
        "x.msixbundle",
    ] {
        assert!(classify(name, b"just text").is_blocked(), "{name}");
    }
}

/// Final review L8: more program and script types, by name and inside a
/// zip (the longest, `settingcontent-ms`, is 17 bytes).
#[test]
fn more_program_and_script_types_are_blocked() {
    for ext in [
        "scpt",
        "applescript",
        "workflow",
        "terminal",
        "webloc",
        "inetloc",
        "fileloc",
        "chm",
        "vhd",
        "vhdx",
        "one",
        "jnlp",
        "appref-ms",
        "application",
        "msp",
        "mst",
        "xll",
        "iqy",
        "slk",
        "settingcontent-ms",
    ] {
        let name = format!("Invoice.{}", ext.to_ascii_uppercase());
        assert_eq!(classify(&name, b"x"), Verdict::Program, "{name}");
        let inner = format!("docs/{ext}.{ext}");
        assert_eq!(
            classify("a.zip", &zip(&[(inner.as_str(), b"x")])),
            Verdict::Program,
            "{inner}"
        );
    }
    // An extension longer than any listed one is not cut short into a match.
    assert_eq!(classify("a.settingcontent-msx", b"x"), Verdict::Allowed);
    assert_eq!(classify("a.phone", b"x"), Verdict::Allowed);
}

#[test]
fn extension_only_cases_ignore_case_and_take_the_last_extension() {
    assert_eq!(classify("x.APK", b"hello"), Verdict::AndroidApp);
    assert_eq!(classify("invoice.pdf.apk", PDF), Verdict::AndroidApp);
    assert_eq!(classify("Setup.Exe", PDF), Verdict::Program);
    assert_eq!(classify("page.HTM", b"just text"), Verdict::WebPage);
    assert_eq!(classify("Report.DocM", PDF), Verdict::MacroDocument);
    // Only the last extension counts: these open as a PDF.
    assert_eq!(classify("program.exe.pdf", PDF), Verdict::Allowed);
    assert_eq!(
        classify("apk", PDF),
        Verdict::Allowed,
        "no dot, no extension"
    );
    assert_eq!(
        classify("photo.jpg", b"MZ\x90\x00"),
        Verdict::Program,
        "content-only"
    );
}

#[test]
fn ordinary_files_pass() {
    let zip_of_pdfs = zip(&[("a.pdf", PDF), ("b.pdf", PDF), ("notes/readme.txt", b"hi")]);
    let plain_doc = ole2(&[
        ("Root Entry", 5),
        ("WordDocument", 2),
        ("1Table", 2),
        ("SummaryInformation", 2),
    ]);
    for (name, bytes) in [
        ("Quarterly report.pdf", PDF),
        ("photo.jpg", JPEG),
        ("image.png", PNG),
        ("voice.m4a", M4A),
        ("data.csv", CSV),
        ("archive.zip", &zip_of_pdfs[..]),
        ("old.doc", &plain_doc[..]),
        ("empty.txt", &[][..]),
        ("notes.txt", &b"plain text, not MZ at the start"[..]),
        (
            "plist.xml",
            &b"<?xml version=\"1.0\"?><plist><dict><key>Name</key></dict></plist>"[..],
        ),
    ] {
        assert_eq!(classify(name, bytes), Verdict::Allowed, "{name}");
    }
}

/// Review Focus 1: Office, OpenDocument and EPUB files are zips of SVG,
/// `.bin` and XHTML parts; none of that blocks them (Decision 8).
#[test]
fn ordinary_office_and_epub_zips_pass() {
    let docx = zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", b"<Relationships/>"),
        ("word/document.xml", b"<w:document/>"),
        ("word/media/image1.svg", b"<svg/>"),
        ("word/media/image1.png", PNG),
        ("docProps/thumbnail.jpeg", JPEG),
    ]);
    let xlsx = zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("xl/workbook.xml", b"<workbook/>"),
        ("xl/printerSettings/printerSettings1.bin", b"\0\0"),
        ("xl/embeddings/oleObject1.bin", b"\xd0\xcf"),
        ("xl/embeddings/Microsoft_Word_Document.docx", b"PK\x03\x04"),
    ]);
    let odt = zip(&[
        ("mimetype", b"application/vnd.oasis.opendocument.text"),
        ("content.xml", b"<x/>"),
        ("Pictures/1.svg", b"<svg/>"),
    ]);
    let epub = zip(&[
        ("mimetype", b"application/epub+zip"),
        ("META-INF/container.xml", b"<c/>"),
        ("OEBPS/chapter1.xhtml", b"<html/>"),
        ("OEBPS/cover.svg", b"<svg/>"),
    ]);
    for (name, bytes) in [
        ("Report.docx", &docx),
        ("Budget.xlsx", &xlsx),
        ("Letter.odt", &odt),
        ("Book.epub", &epub),
    ] {
        assert_eq!(classify(name, bytes), Verdict::Allowed, "{name}");
    }
}

#[test]
fn inside_a_zip_programs_and_app_bundles_still_block() {
    assert_eq!(
        classify("a.zip", &zip(&[("bin/tool.exe", b"x")])),
        Verdict::Program
    );
    assert_eq!(
        classify("a.zip", &zip(&[("Tool.app/Contents/MacOS/Tool", b"x")])),
        Verdict::Program
    );
    assert_eq!(
        classify("a.zip", &zip(&[("scripts/run.SH", b"x")])),
        Verdict::Program
    );
    assert_eq!(
        classify("a.zip", &zip(&[("docs/report.xlsm", b"x")])),
        Verdict::MacroDocument
    );
    assert_eq!(
        classify("a.zip", &zip(&[("disk.iso", b"x")])),
        Verdict::Unchecked
    );
    // A bin part is never a program inside a zip (Decision 8).
    assert_eq!(
        classify("a.zip", &zip(&[("data/blob.bin", b"x")])),
        Verdict::Allowed
    );
}

/// Decision 8 (amended): web pages and SVG block in a plain zip, and only
/// a document container (listed marker part) is exempt.
#[test]
fn web_pages_in_plain_zips_block_but_not_in_document_containers() {
    assert_eq!(
        classify("a.zip", &zip(&[("invoice.html", b"<html/>")])),
        Verdict::WebPage
    );
    assert_eq!(
        classify("a.zip", &zip(&[("site/logo.svg", b"<svg/>")])),
        Verdict::WebPage
    );
    let docx = zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/media/image1.svg", b"<svg/>"),
    ]);
    assert_eq!(classify("Report.docx", &docx), Verdict::Allowed);
    let epub = zip(&[
        ("mimetype", b"application/epub+zip"),
        ("OEBPS/ch1.xhtml", b"<html/>"),
    ]);
    assert_eq!(classify("Book.epub", &epub), Verdict::Allowed);
    // The outer name must be a document type, whatever the zip holds.
    let faked = zip(&[("mimetype", b"x"), ("evil.html", b"<html/>")]);
    assert_eq!(classify("invoice.zip", &faked), Verdict::WebPage);
    let unmarked = zip(&[("a.html", b"<html/>")]);
    assert_eq!(classify("report.docx", &unmarked), Verdict::WebPage);
    let ct_svg = zip(&[("[Content_Types].xml", b"<Types/>"), ("a.svg", b"<svg/>")]);
    assert_eq!(classify("x.zip", &ct_svg), Verdict::WebPage);
    // The marker may come after the page in the directory.
    let late = zip(&[
        ("OEBPS/ch1.xhtml", b"<html/>"),
        ("META-INF/container.xml", b"<c/>"),
    ]);
    assert_eq!(classify("Book.epub", &late), Verdict::Allowed);
}

/// Decision 9: a stored nested zip is looked into one level; a
/// compressed or deeper one can't be checked.
#[test]
fn nested_zips_are_checked_one_level() {
    let inner_exe = zip(&[("a.exe", b"MZ")]);
    let inner_pdfs = zip(&[("a.pdf", PDF)]);
    assert_eq!(
        classify("o.zip", &zip(&[("inner.zip", &inner_exe)])),
        Verdict::Program
    );
    assert_eq!(
        classify("o.zip", &zip(&[("inner.zip", &inner_pdfs)])),
        Verdict::Allowed
    );
    assert_eq!(
        classify("o.zip", &zip(&[("inner.ZIP", &inner_exe)])),
        Verdict::Program,
        "any case"
    );
    let compressed = zip_of(&[E("inner.zip", &inner_pdfs, 0, 8)]);
    assert_eq!(classify("o.zip", &compressed), Verdict::Unchecked);
    let deeper = zip(&[("mid.zip", &zip(&[("inner.zip", &inner_pdfs)]))]);
    assert_eq!(classify("o.zip", &deeper), Verdict::Unchecked);
}

#[test]
fn ole2_text_mentioning_macros_is_not_a_macro() {
    let mut doc = ole2(&[("Root Entry", 5), ("WordDocument", 2)]);
    // "Macros" in UTF-16 inside the document's text, not in an entry slot.
    doc.extend_from_slice(&[0u8; 7]);
    for u in "Macros _VBA_PROJECT".encode_utf16() {
        doc.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(classify("old.doc", &doc), Verdict::Allowed);
}

#[test]
fn truncated_zips_are_never_allowed_and_never_panic() {
    let apk = zip(&[
        ("AndroidManifest.xml", b"m"),
        ("classes.dex", b"dex\n"),
        ("res/a.png", PNG),
    ]);
    for len in 4..apk.len() {
        assert_eq!(
            classify("a.zip", &apk[..len]),
            Verdict::Unchecked,
            "cut at {len}"
        );
    }
    let pdfs = zip(&[("a.pdf", PDF)]);
    for len in 0..pdfs.len() {
        let _ = classify("a.pdf", &pdfs[..len]);
    }
}

/// Review Focus 2: hostile directories are "can't be checked", in bounded
/// time and with bounded allocation (the one span list is sized by the
/// directory's real bytes, never by the count the end record claims).
#[test]
fn hostile_zip_directories_are_unchecked_with_bounded_allocation() {
    // 65,279 entries claimed in a one-entry directory.
    let mut bomb = zip(&[("a.pdf", PDF)]);
    let end = bomb.len() - 22;
    bomb[end + 8..end + 12].copy_from_slice(&[0xFF, 0xFE, 0xFF, 0xFE]);
    // The directory offset past the end of the file.
    let mut past = zip(&[("a.pdf", PDF)]);
    let end2 = past.len() - 22;
    past[end2 + 16..end2 + 20].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
    // Zip64 markers.
    let mut zip64 = zip(&[("a.pdf", PDF)]);
    let end3 = zip64.len() - 22;
    zip64[end3 + 8..end3 + 12].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    // A comment full of fake end records, none valid.
    let mut comments = b"PK\x03\x04".to_vec();
    for _ in 0..3000 {
        comments.extend_from_slice(b"PK\x05\x06garbage-");
    }
    // 17 stored nested zips (over MAX_NESTED_ZIPS).
    let inner = zip(&[("a.pdf", PDF)]);
    let names: Vec<String> = (0..=MAX_NESTED_ZIPS).map(|i| format!("n{i}.zip")).collect();
    let many = zip(&names
        .iter()
        .map(|n| (n.as_str(), &inner[..]))
        .collect::<Vec<_>>());
    // 4 MB of PK and zeros, no end record.
    let mut huge = b"PK\x03\x04".to_vec();
    huge.resize(4 << 20, 0);
    for (what, bytes) in [
        ("bomb", &bomb),
        ("past", &past),
        ("zip64", &zip64),
        ("comments", &comments),
        ("many", &many),
        ("huge", &huge),
    ] {
        let started = std::time::Instant::now();
        let mut verdict = Verdict::Allowed;
        let used = crate::alloc_probe::bytes_allocated(|| verdict = classify("a.zip", bytes));
        assert_eq!(verdict, Verdict::Unchecked, "{what}");
        assert!(used <= alloc_bound(bytes), "{what}: allocated {used}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{what}: {:?}",
            started.elapsed()
        );
    }
}

/// The most a classification may allocate: one span list per zip looked
/// into (the outer one and up to `MAX_NESTED_ZIPS` nested ones), each at
/// most 16 bytes per 46 bytes of the input.
fn alloc_bound(input: &[u8]) -> usize {
    (MAX_NESTED_ZIPS + 1) * (input.len() / 46) * 16
}

/// Random bytes and mutations of real samples: never a panic, allocation
/// bounded, and `is_blocked` agrees with `code`.
#[test]
fn fuzz_style_inputs_never_panic_and_allocate_little() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xF11E);
    let seeds = [
        zip(&[
            ("AndroidManifest.xml", b"m"),
            ("inner.zip", &zip(&[("a.pdf", PDF)])),
        ]),
        ole2(&[("Root Entry", 5), ("Macros", 1)]),
        PDF.to_vec(),
    ];
    for i in 0..20_000 {
        let input: Vec<u8> = if i % 2 == 0 {
            (0..rng.gen_range(0..700)).map(|_| rng.gen()).collect()
        } else {
            let mut v = seeds[i % seeds.len()].clone();
            for _ in 0..rng.gen_range(1..8) {
                let at = rng.gen_range(0..v.len());
                v[at] = rng.gen();
            }
            v.truncate(rng.gen_range(0..=v.len()));
            v
        };
        let mut v = Verdict::Allowed;
        let used = crate::alloc_probe::bytes_allocated(|| v = classify("f.bin.txt", &input));
        assert!(used <= alloc_bound(&input), "allocated {used}");
        assert_eq!(v.is_blocked(), v.code() != 0);
    }
}

// --- fix round 2: strict zips, checked offsets, more rules -----------------

/// A zip entry with every field a hostile writer can vary.
struct X<'a> {
    name: &'a [u8],
    local_name: Option<&'a [u8]>,
    data: &'a [u8],
    central_extra: &'a [u8],
    local_extra: &'a [u8],
    local_offset: Option<u32>,
}

impl<'a> X<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        X {
            name: name.as_bytes(),
            local_name: None,
            data,
            central_extra: &[],
            local_extra: &[],
            local_offset: None,
        }
    }
}

fn central_record(x: &X, offset: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    c.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    c.extend_from_slice(&(x.data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(x.data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(x.name.len() as u16).to_le_bytes());
    c.extend_from_slice(&(x.central_extra.len() as u16).to_le_bytes());
    c.extend_from_slice(&[0; 2 + 2 + 2 + 4]); // comment, disk, internal, external
    c.extend_from_slice(&x.local_offset.unwrap_or(offset).to_le_bytes());
    c.extend_from_slice(x.name);
    c.extend_from_slice(x.central_extra);
    c
}

/// A stored zip from `X` entries, laid out as a writer would.
fn zip_x(entries: &[X]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for x in entries {
        let offset = out.len() as u32;
        let local_name = x.local_name.unwrap_or(x.name);
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&(x.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(x.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(x.local_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(local_name);
        out.extend_from_slice(x.local_extra);
        out.extend_from_slice(x.data);
        central.extend_from_slice(&central_record(x, offset));
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    end_record(
        &mut out,
        entries.len() as u16,
        central.len() as u32,
        cd_offset,
        0,
    );
    out
}

fn unicode_path_field(name: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0x7075u16.to_le_bytes());
    f.extend_from_slice(&((5 + name.len()) as u16).to_le_bytes());
    f.push(1);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(name);
    f
}

/// What real tools wrote: the checked-in fixtures (small).
#[test]
fn real_writer_zips_and_office_packages_are_allowed() {
    for (name, bytes) in [
        (
            "photos.zip",
            &include_bytes!("fixtures/photos_zip_x.zip")[..],
        ),
        (
            "photos.zip",
            &include_bytes!("fixtures/photos_ditto.zip")[..],
        ),
        (
            "photos.zip",
            &include_bytes!("fixtures/photos_stream_dd.zip")[..],
        ),
        ("report.docx", &include_bytes!("fixtures/office.docx")[..]),
        ("budget.xlsx", &include_bytes!("fixtures/office.xlsx")[..]),
        ("deck.pptx", &include_bytes!("fixtures/office.pptx")[..]),
        (
            "zip64.docx",
            &include_bytes!("fixtures/office_zip64_placeholder.docx")[..],
        ),
        // Final review H1: WPS Office lists entries alphabetically, not in
        // the order it wrote them (same shape as a real WPS 12.1 docx).
        (
            "booking information.docx",
            &include_bytes!("fixtures/wps_order.docx")[..],
        ),
        // Final review M3: 24 zero bytes after the end record (a Google
        // Fonts download's shape), and JSZip's stored entries with data
        // descriptors (written by JSZip 3, `STORE` + `streamFiles`).
        (
            "fonts.zip",
            &include_bytes!("fixtures/fonts_zero_tail.zip")[..],
        ),
        (
            "photos.zip",
            &include_bytes!("fixtures/jszip_stored_dd.zip")[..],
        ),
    ] {
        assert_eq!(classify(name, bytes), Verdict::Allowed, "{name}");
    }
}

/// Every parser differential from the security review: whatever an
/// extractor might name the file, the answer is blocked.
#[test]
fn ambiguous_zips_are_unchecked() {
    let apk = b"data";
    // localdiff2: the central name is a photo, the local name a page.
    let mut localdiff = X::new("photo.jpg", b"<html><script>alert(1)</script></html>");
    localdiff.local_name = Some(b"evil.html");
    assert_eq!(classify("a.zip", &zip_x(&[localdiff])), Verdict::Unchecked);
    // fakecomment: a real zip of evil.apk whose end-record comment holds a
    // benign directory and a fake end record.
    let mut fake = zip_x(&[X::new("evil.apk", apk)]);
    let benign = central_record(&X::new("a.jpg", b""), 0);
    let comment_at = fake.len() as u32;
    let mut comment = benign.clone();
    end_record(&mut comment, 1, benign.len() as u32, comment_at, 0);
    let end = fake.len() - 2;
    fake[end..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
    fake.extend_from_slice(&comment);
    assert_eq!(classify("a.zip", &fake), Verdict::Unchecked);
    // countsize: the end record says 1 entry, the directory holds 2.
    let mut countsize = zip(&[("a.jpg", b"x"), ("evil.apk", b"y")]);
    let e = countsize.len() - 22;
    countsize[e + 8..e + 12].copy_from_slice(&[1, 0, 1, 0]);
    assert_eq!(classify("a.zip", &countsize), Verdict::Unchecked);
    // zip64loc: a locator before a benign classic end record.
    let mut z64 = zip(&[("a.jpg", b"x")]);
    let e = z64.len() - 22;
    let end_rec = z64.split_off(e);
    z64.extend_from_slice(b"PK\x06\x06");
    z64.extend_from_slice(&[0; 52]);
    z64.extend_from_slice(b"PK\x06\x07");
    z64.extend_from_slice(&[0; 16]);
    z64.extend_from_slice(&end_rec);
    assert_eq!(classify("a.zip", &z64), Verdict::Unchecked);
    // A NUL in a name: extractors cut `evil.apk\0.jpg` at the NUL.
    assert_eq!(
        classify("a.zip", &zip_x(&[X::new("evil.apk\0.jpg", apk)])),
        Verdict::Unchecked
    );
    // An extra field that doesn't parse.
    let mut bad_extra = X::new("a.jpg", apk);
    bad_extra.central_extra = &[0x75, 0x70, 0xFF, 0xFF, 1];
    assert_eq!(classify("a.zip", &zip_x(&[bad_extra])), Verdict::Unchecked);
    // A Zip64 extra next to ordinary sizes is a placeholder: allowed. A
    // size or offset at its maximum is real Zip64: unchecked.
    let mut z64_extra = X::new("a.jpg", apk);
    z64_extra.central_extra = &[1, 0, 0, 0];
    z64_extra.local_extra = &[1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(classify("a.zip", &zip_x(&[z64_extra])), Verdict::Allowed);
    for field in [20usize, 24, 42] {
        let mut z = zip_x(&[X::new("a.jpg", apk)]);
        let cd = z.len() - 22 - 46 - "a.jpg".len();
        z[cd + field..cd + field + 4].copy_from_slice(&[0xFF; 4]);
        assert_eq!(
            classify("a.zip", &z),
            Verdict::Unchecked,
            "central field {field}"
        );
    }
    // A local header that isn't one, and a local offset outside the file.
    let mut lonely = zip_x(&[X::new("a.jpg", apk)]);
    lonely[0] = b'Q';
    assert_eq!(classify("a.zip", &lonely), Verdict::Unchecked);
    // prefix_abs, prefix_rel: junk in front of a zip (SFX style).
    let inner = zip(&[("evil.apk", apk)]);
    let mut prefixed = vec![b'X'; 100];
    prefixed.extend_from_slice(&inner);
    assert_eq!(classify("x.zip", &prefixed), Verdict::Unchecked);
    let mut sfx = b"X".repeat(300);
    sfx.extend_from_slice(&zip(&[("evil.apk", apk)]));
    assert_eq!(classify("setup.dat", &sfx), Verdict::Unchecked);
    // pdfpoly: a PDF with a zip behind it.
    let mut poly = PDF.to_vec();
    poly.extend_from_slice(&inner);
    assert_eq!(classify("x.pdf", &poly), Verdict::Unchecked);
    // A nested zip with a junk prefix.
    let mut junk_inner = b"JUNK".to_vec();
    junk_inner.extend_from_slice(&inner);
    assert_eq!(
        classify("o.zip", &zip(&[("inner.zip", &junk_inner)])),
        Verdict::Unchecked
    );
    // Two end records that each end the file are ambiguous; so is a
    // second end record between the directory and the end.
    let mut twice = zip(&[("a.jpg", b"x")]);
    let again = twice[twice.len() - 22..].to_vec();
    let cut = twice.len() - 22;
    twice.splice(cut..cut, again);
    assert_eq!(classify("a.zip", &twice), Verdict::Unchecked);
    // The spanned-archive marker.
    assert_eq!(classify("a.zip", b"PK\x07\x08rest"), Verdict::Unchecked);
}

/// The Unicode Path field (0x7075) names the file for some extractors: the
/// name in it is classified too, from the central or the local extra.
#[test]
fn unicode_path_fields_are_classified() {
    let field = unicode_path_field(b"evil.apk");
    let mut central = X::new("photo.jpg", b"data");
    central.central_extra = &field;
    assert_eq!(classify("a.zip", &zip_x(&[central])), Verdict::AndroidApp);
    let mut local = X::new("photo.jpg", b"data");
    local.local_extra = &field;
    assert_eq!(classify("a.zip", &zip_x(&[local])), Verdict::AndroidApp);
    let benign = unicode_path_field("photo.jpg".as_bytes());
    let mut fine = X::new("photo.jpg", b"data");
    fine.central_extra = &benign;
    fine.local_extra = &benign;
    assert_eq!(classify("a.zip", &zip_x(&[fine])), Verdict::Allowed);
}

/// Review F1: offsets read from the file never overflow, even where
/// `usize` is 32 bits (every sum is checked; these shapes are what would
/// have wrapped).
#[test]
fn offsets_near_u32_max_are_unchecked_and_never_panic() {
    let inner = zip(&[("a.pdf", PDF)]);
    for local in [0xFFFF_FFFC_u32, 0xFFFF_FFFD, 0xFFFF_FFFE, 0xFFFF_FFFF] {
        let mut x = X::new("x.zip", &inner);
        x.local_offset = Some(local);
        assert_eq!(
            classify("o.zip", &zip_x(&[x])),
            Verdict::Unchecked,
            "{local:#x}"
        );
    }
    for (size, offset) in [
        (0xFFFF_FFFE_u32, 0u32),
        (0, 0xFFFF_FFFE),
        (0xFFFF_FFFD, 3),
        (8, 0xFFFF_FFF8),
    ] {
        let mut z = zip(&[("a.pdf", PDF)]);
        let e = z.len() - 22;
        z[e + 12..e + 16].copy_from_slice(&size.to_le_bytes());
        z[e + 16..e + 20].copy_from_slice(&offset.to_le_bytes());
        assert_eq!(
            classify("a.zip", &z),
            Verdict::Unchecked,
            "{size:#x} {offset:#x}"
        );
    }
    // Name and extra lengths past the end of the file.
    let mut z = zip(&[("a.pdf", PDF)]);
    z[26..28].copy_from_slice(&0xFFFFu16.to_le_bytes());
    z[28..30].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(classify("a.zip", &z), Verdict::Unchecked);
}

#[test]
fn entry_names_are_cleaned_like_the_sender_cleans() {
    assert_eq!(
        classify("a.zip", &zip(&[("evil.exe.", b"x")])),
        Verdict::Program
    );
    assert_eq!(
        classify("a.zip", &zip(&[("run.hta ", b"x")])),
        Verdict::Program
    );
    assert_eq!(
        classify("a.zip", &zip(&[("dir/evil.apk. . ", b"x")])),
        Verdict::AndroidApp
    );
    assert_eq!(
        classify("a.zip", &zip(&[(".apk", b"x")])),
        Verdict::AndroidApp
    );
    assert_eq!(
        classify("a.zip", &zip(&[("d/.apk", b"x")])),
        Verdict::AndroidApp
    );
    assert_eq!(classify(".apk", b"x"), Verdict::AndroidApp);
    assert_eq!(classify("photo.jpg.", b"x"), Verdict::Allowed);
}

#[test]
fn compressed_archives_are_unchecked() {
    for name in [
        "bundle.tgz",
        "a.tar",
        "a.gz",
        "a.bz2",
        "a.tbz",
        "a.tbz2",
        "a.xz",
        "a.txz",
        "a.zst",
        "a.tzst",
        "a.lz",
        "a.lzma",
        "a.Z",
    ] {
        assert_eq!(classify(name, b"text"), Verdict::Unchecked, "{name}");
    }
    let mut tar = vec![0u8; 512];
    tar[257..262].copy_from_slice(b"ustar");
    for (what, bytes) in [
        ("gzip", &[0x1F, 0x8B, 8, 0][..]),
        ("bzip2", &b"BZh91AY"[..]),
        ("xz", &[0xFD, b'7', b'z', b'X', b'Z', 0, 0][..]),
        ("zstd", &[0x28, 0xB5, 0x2F, 0xFD, 0][..]),
        ("tar", &tar[..]),
    ] {
        assert_eq!(classify("x.dat", bytes), Verdict::Unchecked, "{what}");
    }
    // A .tgz inside a zip.
    assert_eq!(
        classify("a.zip", &zip(&[("t/pack.tgz", b"x")])),
        Verdict::Unchecked
    );
}

#[test]
fn web_pages_are_found_past_comments_doctypes_and_long_subsets() {
    let long_dtd = {
        let mut v = b"<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY a \"".to_vec();
        v.extend_from_slice(&[b'A'; 1100]);
        v.extend_from_slice(b"\">]><svg onload=\"alert(1)\"/>");
        v
    };
    let huge_dtd = {
        let mut v = b"<!DOCTYPE svg [<!ENTITY a \"".to_vec();
        v.extend_from_slice(&[b'A'; 9000]);
        v.extend_from_slice(b"\">]><svg/>");
        v
    };
    let comment_then_svg = b"<!-- a --> <!-- b --><?pi x?><svg/>".to_vec();
    for (what, bytes) in [
        ("comment", &b"<!-- invoice --><html><script>alert(1)</script></html>"[..]),
        ("script", &b"<script>alert(1)</script>"[..]),
        ("doctype svg", &b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x\"><svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>"[..]),
        ("long dtd", &long_dtd[..]),
        ("dtd past the window", &huge_dtd[..]),
        ("comments", &comment_then_svg[..]),
        ("iframe", &b"  <IFRAME src=x></IFRAME>"[..]),
        ("object", &b"<object data=x>"[..]),
        ("embed", &b"<embed src=x>"[..]),
        ("head", &b"<head><title>x</title>"[..]),
        ("body", &b"<body onload=x()>"[..]),
        ("prefixed svg", &b"<svg:svg xmlns:svg=\"http://www.w3.org/2000/svg\"/>"[..]),
    ] {
        assert_eq!(classify("note.txt", bytes), Verdict::WebPage, "{what}");
    }
    // Ordinary text and XML that merely mention a tag are not pages.
    for bytes in [
        &b"<note><to>Ann</to></note>"[..],
        &b"<!-- a comment --><note>use <script> carefully"[..],
        &b"<rss><channel/></rss>"[..],
        &b"<!-- unterminated"[..],
        &b"<"[..],
    ] {
        assert_eq!(classify("note.txt", bytes), Verdict::Allowed, "{bytes:?}");
    }
}

#[test]
fn profiles_are_found_as_utf16_and_with_wider_der() {
    let plist16 = {
        let mut v = vec![0xFF, 0xFE];
        for u in "<?xml version='1.0' encoding='UTF-16'?><plist><dict><key>PayloadType</key></dict></plist>".encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    };
    let plist16be = {
        let mut v = vec![0xFE, 0xFF];
        for u in "<plist><dict><key>PayloadContent</key></dict></plist>".encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    };
    let mut signed84 = vec![0x30, 0x84, 0x00, 0x00, 0x10, 0x00, 0x06, 0x09];
    signed84.extend_from_slice(b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02...<key>PayloadType</key>");
    for (what, bytes) in [
        ("utf16 le", &plist16[..]),
        ("utf16 be", &plist16be[..]),
        ("30 84", &signed84[..]),
    ] {
        assert_eq!(
            classify("a.txt", bytes),
            Verdict::AppleAppOrProfile,
            "{what}"
        );
    }
    let plain16 = {
        let mut v = vec![0xFF, 0xFE];
        for u in "<plist><dict><key>Name</key></dict></plist>".encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    };
    assert_eq!(classify("a.txt", &plain16), Verdict::Allowed);
}

/// A zip with its central entries chosen: `listed[i]` says whether entry
/// `i` appears in the directory (the others are hidden local entries).
fn zip_listing(entries: &[X], listed: &[bool]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count = 0u16;
    for (x, show) in entries.iter().zip(listed) {
        let offset = out.len() as u32;
        let one = zip_x(std::slice::from_ref(x));
        let local_len = one.len() - 22 - central_record(x, 0).len();
        out.extend_from_slice(&one[..local_len]);
        if *show {
            central.extend_from_slice(&central_record(x, offset));
            count += 1;
        }
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    end_record(&mut out, count, central.len() as u32, cd_offset, 0);
    out
}

/// Rule: a reader that walks local headers sees only listed entries.
#[test]
fn local_headers_must_tile_the_archive() {
    let (a, evil, b) = (
        X::new("a.jpg", b"x"),
        X::new("evil.apk", b"y"),
        X::new("b.jpg", b"z"),
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_listing(
                &[X::new("a.jpg", b"x"), X::new("b.jpg", b"z")],
                &[true, true]
            )
        ),
        Verdict::Allowed
    );
    // A hidden local entry after, before and between the listed ones.
    assert_eq!(
        classify(
            "a.zip",
            &zip_listing(
                &[X::new("a.jpg", b"x"), X::new("evil.apk", b"y")],
                &[true, false]
            )
        ),
        Verdict::Unchecked,
        "after"
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_listing(
                &[X::new("evil.apk", b"y"), X::new("a.jpg", b"x")],
                &[false, true]
            )
        ),
        Verdict::Unchecked,
        "before"
    );
    assert_eq!(
        classify("a.zip", &zip_listing(&[a, evil, b], &[true, false, true])),
        Verdict::Unchecked,
        "between"
    );
    // Two central entries pointing at one local header (one hidden entry).
    let mut dup = X::new("a.jpg", b"x");
    dup.local_offset = Some(0);
    let pair = zip_listing(
        &[X::new("a.jpg", b"x"), X::new("evil.apk", b"y"), dup],
        &[true, false, true],
    );
    assert_eq!(
        classify("a.zip", &pair),
        Verdict::Unchecked,
        "duplicate pointers"
    );
    // Entries listed out of local order still tile: allowed (final
    // review H1, as WPS Office writes them).
    let mut swapped = zip_x(&[X::new("a.jpg", b"x"), X::new("b.jpg", b"z")]);
    let cd = swapped.len() - 22 - 2 * 46 - 10;
    let first: Vec<u8> = swapped[cd..cd + 46 + 5].to_vec();
    let second: Vec<u8> = swapped[cd + 46 + 5..cd + 2 * 46 + 10].to_vec();
    swapped.splice(cd..cd + 2 * 46 + 10, second.into_iter().chain(first));
    assert_eq!(
        classify("a.zip", &swapped),
        Verdict::Allowed,
        "out of order"
    );
    // Out of order and a hidden entry between, a duplicate pointer, or an
    // overlap: still unchecked.
    let hidden = zip_listing(
        &[
            X::new("a.jpg", b"x"),
            X::new("evil.apk", b"y"),
            X::new("b.jpg", b"z"),
        ],
        &[true, false, true],
    );
    let cd = hidden.len() - 22 - 2 * 46 - 10;
    let mut hidden_swapped = hidden.clone();
    hidden_swapped[cd..cd + 2 * 46 + 10].copy_from_slice(
        &[
            &hidden[cd + 46 + 5..cd + 2 * 46 + 10],
            &hidden[cd..cd + 46 + 5],
        ]
        .concat(),
    );
    assert_eq!(
        classify("a.zip", &hidden_swapped),
        Verdict::Unchecked,
        "out of order with a hidden entry"
    );
    let mut dup_last = X::new("a.jpg", b"x");
    dup_last.local_offset = Some(0);
    let mut dup_first = X::new("a.jpg", b"x");
    dup_first.local_offset = Some(0);
    assert_eq!(
        classify(
            "a.zip",
            &zip_listing(&[dup_first, X::new("b.jpg", b"z")], &[true, true])
        ),
        Verdict::Allowed,
        "control"
    );
    let pair_reversed = zip_listing(
        &[dup_last, X::new("a.jpg", b"x"), X::new("evil.apk", b"y")],
        &[true, true, false],
    );
    assert_eq!(
        classify("a.zip", &pair_reversed),
        Verdict::Unchecked,
        "duplicate pointers, any order"
    );
    // Overlap: the second entry's local header lies inside the first
    // entry's stored data.
    let inner = zip_x(&[X::new("b.jpg", b"z")]);
    let inner_local = &inner[..30 + 5 + 1];
    let mut overlap_b = X::new("b.jpg", b"z");
    overlap_b.local_offset = Some(30 + 5);
    let overlap = zip_listing(&[X::new("a.txt", inner_local), overlap_b], &[true, true]);
    assert_eq!(
        classify("a.zip", &overlap),
        Verdict::Unchecked,
        "overlapping entries"
    );
}

#[test]
fn local_header_fields_must_match_the_directory() {
    let base = zip_x(&[X::new("a.jpg", b"xyz")]);
    assert_eq!(classify("a.zip", &base), Verdict::Allowed);
    for (what, at, bytes) in [
        ("method", 8usize, &[8u8, 0][..]),
        ("compressed size", 18, &[9, 0, 0, 0][..]),
        ("uncompressed size", 22, &[9, 0, 0, 0][..]),
        ("crc", 14, &[1, 0, 0, 0][..]),
        ("flags bit 0", 6, &[1, 0][..]),
    ] {
        let mut z = base.clone();
        z[at..at + bytes.len()].copy_from_slice(bytes);
        assert_eq!(classify("a.zip", &z), Verdict::Unchecked, "{what}");
    }
    // The same on a stored nested zip.
    let inner = zip(&[("a.pdf", PDF)]);
    let mut z = zip_x(&[X::new("inner.zip", &inner)]);
    z[18..22].copy_from_slice(&((inner.len() - 1) as u32).to_le_bytes());
    assert_eq!(classify("o.zip", &z), Verdict::Unchecked);
}

/// One deflated entry written with a data descriptor: local sizes and CRC
/// zero, `descriptor` after the data.
fn zip_descriptor(name: &str, data: &[u8], crc: u32, descriptor: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[
        20, 0, 8, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(descriptor);
    let cd_at = out.len() as u32;
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    c.extend_from_slice(&[20, 0, 20, 0, 8, 0, 8, 0, 0, 0, 0, 0]);
    c.extend_from_slice(&crc.to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(data.len() as u32 + 7).to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    c.extend_from_slice(&[0; 2 + 2 + 2 + 2 + 4 + 4]);
    c.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&c);
    end_record(&mut out, 1, c.len() as u32, cd_at, 0);
    out
}

#[test]
fn data_descriptors_must_match_the_directory() {
    let data = b"\x4b\x4c\x4a\x06\x00"; // a tiny deflate stream, no signatures
    let desc = |sig: bool, crc: u32, c: u32, u: u32| {
        let mut d = Vec::new();
        if sig {
            d.extend_from_slice(b"PK\x07\x08");
        }
        for v in [crc, c, u] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d
    };
    let (n, u) = (data.len() as u32, data.len() as u32 + 7);
    assert_eq!(
        classify(
            "a.zip",
            &zip_descriptor("a.jpg", data, 0xAA, &desc(true, 0xAA, n, u))
        ),
        Verdict::Allowed,
        "with signature"
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_descriptor("a.jpg", data, 0xAA, &desc(false, 0xAA, n, u))
        ),
        Verdict::Allowed,
        "without signature"
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_descriptor("a.jpg", data, 0xAA, &desc(true, 0xAB, n, u))
        ),
        Verdict::Unchecked,
        "wrong crc"
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_descriptor("a.jpg", data, 0xAA, &desc(true, 0xAA, n + 1, u))
        ),
        Verdict::Unchecked,
        "wrong size"
    );
    assert_eq!(
        classify("a.zip", &zip_descriptor("a.jpg", data, 0xAA, &[])),
        Verdict::Unchecked,
        "missing"
    );
    assert_eq!(
        classify(
            "a.zip",
            &zip_descriptor("a.jpg", data, 0xAA, &desc(true, 0xAA, n, u)[..10])
        ),
        Verdict::Unchecked,
        "short"
    );
    // Bit 3 with a stored entry and no descriptor after it.
    let stored = zip_of(&[E("a.jpg", b"xyz", 0x0008, 0)]);
    assert_eq!(classify("a.zip", &stored), Verdict::Unchecked);
}

/// One stored entry written with a data descriptor (as JSZip streams it):
/// local CRC and sizes zero, `data`, then a descriptor with or without its
/// signature.
fn zip_stored_descriptor(name: &str, data: &[u8], signed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[20, 0, 8, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&[0; 12]); // crc, sizes
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    if signed {
        out.extend_from_slice(b"PK\x07\x08");
    }
    out.extend_from_slice(&0xAAu32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    let cd_at = out.len() as u32;
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    c.extend_from_slice(&[20, 0, 20, 0, 8, 0, 0, 0, 0, 0, 0, 0]);
    c.extend_from_slice(&0xAAu32.to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    c.extend_from_slice(&[0; 2 + 2 + 2 + 2 + 4 + 4]);
    c.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&c);
    end_record(&mut out, 1, c.len() as u32, cd_at, 0);
    out
}

/// Final review M3 (b): a stored entry with a descriptor is allowed when
/// its data holds no zip signature and a signed descriptor follows.
#[test]
fn stored_entries_with_descriptors() {
    assert_eq!(
        classify("a.zip", &zip_stored_descriptor("a.jpg", JPEG, true)),
        Verdict::Allowed
    );
    // Unsigned: a streaming reader can't find where the data ends.
    assert_eq!(
        classify("a.zip", &zip_stored_descriptor("a.jpg", JPEG, false)),
        Verdict::Unchecked,
        "unsigned"
    );
    for sig in [
        &b"PK\x07\x08"[..],
        b"PK\x03\x04",
        b"PK\x01\x02",
        b"PK\x05\x06",
    ] {
        let mut data = JPEG.to_vec();
        data.extend_from_slice(sig);
        data.extend_from_slice(&[0; 12]);
        assert_eq!(
            classify("a.zip", &zip_stored_descriptor("a.jpg", &data, true)),
            Verdict::Unchecked,
            "{sig:?}"
        );
    }
    // A nested zip stored this way holds signatures: unchecked.
    let inner = zip(&[("a.pdf", PDF)]);
    assert_eq!(
        classify("a.zip", &zip_stored_descriptor("inner.zip", &inner, true)),
        Verdict::Unchecked
    );
    // A blocked name is still blocked.
    assert_eq!(
        classify("a.zip", &zip_stored_descriptor("evil.apk", b"data", true)),
        Verdict::AndroidApp
    );
}

/// Final review M3 (a): only zero bytes may follow the end record.
#[test]
fn zero_bytes_after_the_end_record() {
    let base = zip(&[("a.jpg", JPEG), ("b.pdf", PDF)]);
    let with = |tail: &[u8]| [&base[..], tail].concat();
    assert_eq!(classify("a.zip", &with(&[0; 24])), Verdict::Allowed);
    assert_eq!(classify("a.zip", &with(&[0; 1])), Verdict::Allowed);
    assert_eq!(classify("a.zip", &with(b"x")), Verdict::Unchecked);
    let mut mixed = vec![0u8; 24];
    mixed[23] = 1;
    assert_eq!(classify("a.zip", &with(&mixed)), Verdict::Unchecked);
    assert_eq!(
        classify("a.zip", &with(&[0, 0, b'P', b'K', 5, 6])),
        Verdict::Unchecked
    );
    // Past the 64 KiB tail window the end record isn't found.
    assert_eq!(
        classify("a.zip", &with(&vec![0; TAIL_WINDOW])),
        Verdict::Unchecked
    );
    // A blocked entry is still blocked with a zero tail.
    let evil = [&zip(&[("evil.apk", b"y")])[..], &[0; 24]].concat();
    assert_eq!(classify("a.zip", &evil), Verdict::AndroidApp);
}

#[test]
fn deflated_data_with_a_zip_signature_directories_and_methods() {
    assert_eq!(
        classify("a.zip", &zip_of(&[E("a.jpg", b"abc", 0, 8)])),
        Verdict::Allowed
    );
    for sig in [&b"PK\x03\x04"[..], b"PK\x01\x02", b"PK\x05\x06"] {
        let mut data = b"abc".to_vec();
        data.extend_from_slice(sig);
        assert_eq!(
            classify("a.zip", &zip_of(&[E("a.jpg", &data, 0, 8)])),
            Verdict::Unchecked,
            "{sig:?}"
        );
        // Stored data is skipped by size: the signature is not a problem.
        assert_eq!(
            classify("a.zip", &zip_of(&[E("a.txt", &data, 0, 0)])),
            Verdict::Allowed,
            "stored {sig:?}"
        );
    }
    // A directory entry that carries data.
    assert_eq!(
        classify("a.zip", &zip_x(&[X::new("docs/", b"")])),
        Verdict::Allowed
    );
    assert_eq!(
        classify("a.zip", &zip_x(&[X::new("docs/", b"x")])),
        Verdict::Unchecked
    );
    // Methods other than stored and deflate (12 is bzip2, 14 LZMA, 93 zstd).
    for method in [1u16, 9, 12, 14, 93, 99] {
        assert_eq!(
            classify("a.zip", &zip_of(&[E("a.txt", b"x", 0, method)])),
            Verdict::Unchecked,
            "{method}"
        );
    }
}

#[test]
fn an_entry_named_like_a_backslash_directory_is_unchecked() {
    // Some extractors read a trailing backslash as a directory and skip
    // its data unscanned.
    let z = zip_of(&[
        E("photos\\", b"PK\x03\x04hidden", 0, 0),
        E("a.jpg", b"\xff\xd8\xff", 0, 0),
    ]);
    assert_eq!(classify("pics.zip", &z), Verdict::Unchecked);
    let ok = zip_of(&[
        E("photos/", b"", 0, 0),
        E("photos/a.jpg", b"\xff\xd8\xff", 0, 0),
    ]);
    assert_eq!(classify("pics.zip", &ok), Verdict::Allowed);
}
