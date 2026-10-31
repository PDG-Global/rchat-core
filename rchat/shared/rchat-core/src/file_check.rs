//! Blocked file types (file-safety spec §3): one classifier for the send
//! and the receive path, so both apps decide the same way. A file is
//! blocked when its cleaned name's last extension or its content says it
//! is an Android app, an iPhone app or profile, a program or script, a web
//! page or SVG, a document with macros, or an archive that can't be
//! checked (or holds any of these).
//!
//! Linear in the input (plus one sort of a zip's entries), never panics,
//! never decompresses. Allocation-bounded: the only allocation is one list
//! of a zip's entry spans, at most one per 46 bytes of its directory. A zip
//! is read from its central directory, and the local headers must agree
//! with it and, sorted by offset, tile the archive from offset 0 to the
//! directory (no gaps, no overlaps; the directory may list them in any
//! order), so a reader that walks local headers forward sees the same
//! entries. Only zero bytes may follow the end record. A stored entry with
//! a data descriptor is allowed when its data holds no zip signature and a
//! signed descriptor follows. Anything ambiguous, malformed, encrypted,
//! multi-disk, Zip64 or with a method other than stored or deflate can't be
//! checked. Uses `std` only, so the fuzz crate (`fuzz/`) compiles this file
//! by path.
//!
//! Known limits:
//! - leading comments over 8 KiB can push a web page's first element out
//!   of the sniff window;
//! - PowerPoint `.ppt` VBA and Excel 4.0 (XLM) macros are not detected;
//! - a PDF or other file that embeds a zip end record in its last 64 KiB
//!   is unchecked;
//! - a deflated entry whose compressed bytes happen to hold a zip
//!   signature is unchecked (a stream that ends early could hide one).

/// Why a file is blocked, or `Allowed`. The code crosses the FFI
/// (`rchat_file_check`); the apps show one sentence for any non-zero code
/// and never the category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Verdict {
    Allowed = 0,
    AndroidApp = 1,
    AppleAppOrProfile = 2,
    Program = 3,
    WebPage = 4,
    MacroDocument = 5,
    /// An archive that can't be checked, or a malformed one.
    Unchecked = 6,
}

impl Verdict {
    pub fn is_blocked(self) -> bool {
        self != Verdict::Allowed
    }

    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Nested zips looked into per file (Decision 9): keeps the check linear.
pub const MAX_NESTED_ZIPS: usize = 16;

const ANDROID_EXT: &[&str] = &["apk", "apks", "xapk", "apkm", "aab", "dex"];
const APPLE_EXT: &[&str] = &["ipa", "mobileconfig", "mobileprovision", "shortcut", "itms"];
const PROGRAM_EXT: &[&str] = &[
    "exe",
    "dll",
    "scr",
    "msi",
    "com",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "hta",
    "jar",
    "sh",
    "bash",
    "zsh",
    "command",
    "app",
    "pkg",
    "dmg",
    "run",
    "bin",
    "elf",
    "so",
    "dylib",
    "py",
    "pl",
    "rb",
    "lnk",
    "reg",
    "cpl",
    "inf",
    "scf",
    "url",
    "desktop",
    // Final review L8: Apple scripts, workflows and link files; Windows help,
    // disk images, OneNote, ClickOnce, installer patches, Excel add-ins,
    // web queries, SYLK and settings shortcuts.
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
];
const WEB_EXT: &[&str] = &[
    "html",
    "htm",
    "xhtml",
    "shtml",
    "mht",
    "mhtml",
    "svg",
    "svgz",
    "webarchive",
];
const MACRO_EXT: &[&str] = &[
    "docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm",
];
/// Archives rChat can't look into, and zip-wrapped packages (Decision 7).
const ARCHIVE_EXT: &[&str] = &[
    "rar",
    "7z",
    "cab",
    "iso",
    "img",
    "war",
    "ear",
    "xpi",
    "crx",
    "appx",
    "appxbundle",
    "msix",
    "msixbundle",
    // Archives and compressed streams that macOS and others extract on open.
    "tar",
    "gz",
    "tgz",
    "bz2",
    "tbz",
    "tbz2",
    "xz",
    "txz",
    "zst",
    "tzst",
    "lz",
    "lzma",
    "z",
];

/// The outer file names whose zip may hold web-page parts (Decision 8,
/// tightened): Office, OpenDocument and EPUB documents.
const DOCUMENT_EXT: &[&str] = &[
    "docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx", "odt", "ott", "ods", "ots", "odp",
    "otp", "odg", "epub",
];

fn is_document_name(name: &[u8]) -> bool {
    let mut buf = [0u8; EXT_MAX];
    last_extension(name, &mut buf).is_some_and(|ext| listed(DOCUMENT_EXT, ext))
}

const OLE2: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MACHO: [[u8; 4]; 5] = [
    [0xFE, 0xED, 0xFA, 0xCE],
    [0xFE, 0xED, 0xFA, 0xCF],
    [0xCE, 0xFA, 0xED, 0xFE],
    [0xCF, 0xFA, 0xED, 0xFE],
    [0xCA, 0xFE, 0xBA, 0xBE],
];

/// How much of a file's start is read for the web-page rules.
const WEB_WINDOW: usize = 8192;
/// Where the end record can lie: its own length plus a 64 KiB comment.
const TAIL_WINDOW: usize = 0xFFFF + 22;

/// `b[start..start + len]`, with no arithmetic that can overflow on a
/// 32-bit target: every offset and length read from a file goes through
/// here.
fn sub(b: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    b.get(start..)?.get(..len)
}

/// The verdict for a file named `name` (already cleaned by
/// `file_msg::sanitise_name`) holding `bytes`: blocked if either says so.
pub fn classify(name: &str, bytes: &[u8]) -> Verdict {
    let by_name = by_extension(name.as_bytes(), false, false);
    if by_name.is_blocked() {
        return by_name;
    }
    let mut nested = 0usize;
    by_content(bytes, 0, &mut nested, is_document_name(name.as_bytes()))
}

/// Without trailing dots and spaces (Windows drops them on extraction,
/// as `sanitise_name` does).
fn trim_name(name: &[u8]) -> &[u8] {
    let mut end = name.len();
    while end > 0 && (name[end - 1] == b'.' || name[end - 1] == b' ') {
        end -= 1;
    }
    &name[..end]
}

/// The longest extension looked at (`settingcontent-ms` is 17 bytes).
const EXT_MAX: usize = 24;

/// The last extension, ASCII-lowercased into `buf` (at most `EXT_MAX`
/// bytes). A name that is only a dot and an extension (`.apk`) counts.
fn last_extension<'b>(name: &[u8], buf: &'b mut [u8; EXT_MAX]) -> Option<&'b [u8]> {
    let name = trim_name(name);
    let dot = name.iter().rposition(|&b| b == b'.')?;
    let ext = name.get(dot + 1..)?;
    if ext.is_empty() || ext.len() > buf.len() {
        return None;
    }
    for (slot, b) in buf.iter_mut().zip(ext) {
        *slot = b.to_ascii_lowercase();
    }
    buf.get(..ext.len())
}

fn listed(list: &[&str], ext: &[u8]) -> bool {
    list.iter().any(|e| e.as_bytes() == ext)
}

/// `inside_zip`: an entry's own name, where `bin` doesn't block. `web_ok`:
/// the zip is a document container (Office, OpenDocument, EPUB), whose
/// web-page and SVG parts don't block (Decision 8, amended).
fn by_extension(name: &[u8], inside_zip: bool, web_ok: bool) -> Verdict {
    let mut buf = [0u8; EXT_MAX];
    let Some(ext) = last_extension(name, &mut buf) else {
        return Verdict::Allowed;
    };
    if listed(ANDROID_EXT, ext) {
        Verdict::AndroidApp
    } else if listed(APPLE_EXT, ext) {
        Verdict::AppleAppOrProfile
    } else if listed(PROGRAM_EXT, ext) && !(inside_zip && ext == b"bin") {
        Verdict::Program
    } else if listed(WEB_EXT, ext) && !web_ok {
        Verdict::WebPage
    } else if listed(MACRO_EXT, ext) {
        Verdict::MacroDocument
    } else if listed(ARCHIVE_EXT, ext) {
        Verdict::Unchecked
    } else {
        Verdict::Allowed
    }
}

fn by_content(b: &[u8], depth: u8, nested: &mut usize, doc_name: bool) -> Verdict {
    if b.starts_with(b"dex\n") {
        return Verdict::AndroidApp;
    }
    if b.starts_with(b"MZ") || b.starts_with(b"\x7fELF") || b.starts_with(b"#!") {
        return Verdict::Program;
    }
    if MACHO.iter().any(|m| b.starts_with(m)) {
        return Verdict::Program;
    }
    if b.starts_with(b"Rar!")
        || b.starts_with(b"7z\xBC\xAF\x27\x1C")
        || b.starts_with(b"MSCF")
        || b.starts_with(&[0x1F, 0x8B])
        || b.starts_with(b"BZh")
        || b.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00])
        || b.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
        || sub(b, 257, 5) == Some(&b"ustar"[..])
    {
        return Verdict::Unchecked;
    }
    if b.starts_with(&OLE2) {
        return if ole2_has_macros(b) {
            Verdict::MacroDocument
        } else {
            Verdict::Allowed
        };
    }
    if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        return zip_verdict(b, depth, nested, doc_name);
    }
    if b.starts_with(b"PK\x07\x08") {
        return Verdict::Unchecked;
    }
    // A zip that doesn't start as one (an SFX stub, a PDF/zip polyglot) is
    // opened as a zip by some extractors: ambiguous, so unchecked.
    if tail_holds(b, b"PK\x05\x06") {
        return Verdict::Unchecked;
    }
    let mut head = [0u8; WEB_WINDOW];
    let (n, bom16) = lowered_head(b, &mut head);
    let head = &head[..n];
    if is_web_page(head) {
        return Verdict::WebPage;
    }
    if is_profile(b, head, bom16) {
        return Verdict::AppleAppOrProfile;
    }
    Verdict::Allowed
}

/// Whether `sig` appears in the last `TAIL_WINDOW` bytes.
fn tail_holds(b: &[u8], sig: &[u8]) -> bool {
    contains(&b[b.len().saturating_sub(TAIL_WINDOW)..], sig)
}

/// The first `WEB_WINDOW` characters after a BOM and leading whitespace,
/// ASCII-lowercased; UTF-16 narrowed unit by unit (anything outside ASCII
/// becomes 0xFF). Returns the length and, for a UTF-16 BOM, which byte
/// order (1 little-endian, 2 big-endian), else 0. Decision 13.
fn lowered_head(b: &[u8], out: &mut [u8; WEB_WINDOW]) -> (usize, u8) {
    let (body, step, low, order) = if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        (rest, 1, 0, 0)
    } else if let Some(rest) = b.strip_prefix(&[0xFF, 0xFE]) {
        (rest, 2, 0, 1)
    } else if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        (rest, 2, 1, 2)
    } else {
        (b, 1, 0, 0)
    };
    let mut n = 0;
    let mut started = false;
    for unit in body.chunks_exact(step) {
        if n == WEB_WINDOW {
            break;
        }
        let c = if step == 2 {
            if unit[1 - low] == 0 {
                unit[low]
            } else {
                0xFF
            }
        } else {
            unit[0]
        };
        if !started && c.is_ascii_whitespace() {
            continue;
        }
        started = true;
        out[n] = c.to_ascii_lowercase();
        n += 1;
    }
    (n, order)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// `needle` (ASCII) as UTF-16 units at even offsets of `body`.
fn contains_utf16(body: &[u8], needle: &[u8], order: u8) -> bool {
    let (lo, hi) = if order == 1 { (0, 1) } else { (1, 0) };
    let units = body.len() / 2;
    let Some(last) = units.checked_sub(needle.len()) else {
        return false;
    };
    (0..=last).any(|u| {
        needle.iter().enumerate().all(|(j, &c)| {
            let at = (u + j) * 2;
            body[at + lo] == c && body[at + hi] == 0
        })
    })
}

/// The position after `pat` in `hay[from..]`.
fn find_after(hay: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    let rest = hay.get(from..)?;
    let at = rest.windows(pat.len()).position(|w| w == pat)?;
    Some(from + at + pat.len())
}

/// After a `<!doctype`, past the closing `>` (an internal subset in `[...]`
/// may hold `>`).
fn skip_doctype(h: &[u8], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = from;
    while let Some(&c) = h.get(at) {
        match c {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b'>' if depth == 0 => return Some(at + 1),
            _ => {}
        }
        at += 1;
    }
    None
}

const WEB_ROOTS: &[&[u8]] = &[
    b"html", b"head", b"body", b"script", b"svg", b"iframe", b"object", b"embed",
];

/// `head` is lowercased. A page is one whose first element (after comments,
/// processing instructions and the doctype) is a web root, or that declares
/// an html or svg doctype in the window.
fn is_web_page(head: &[u8]) -> bool {
    if contains(head, b"<!doctype html") || contains(head, b"<!doctype svg") {
        return true;
    }
    if head.starts_with(b"<?xml") && (contains(head, b"<svg") || contains(head, b"<html")) {
        return true;
    }
    let mut at = 0usize;
    loop {
        while head.get(at).is_some_and(|c| c.is_ascii_whitespace()) {
            at += 1;
        }
        let rest = &head[at..];
        let next = if rest.starts_with(b"<!--") {
            find_after(head, at + 4, b"-->")
        } else if rest.starts_with(b"<?") {
            find_after(head, at + 2, b"?>")
        } else if rest.starts_with(b"<!doctype") {
            skip_doctype(head, at + 9)
        } else {
            break;
        };
        match next {
            Some(n) => at = n,
            None => return false,
        }
    }
    let Some(rest) = head[at..].strip_prefix(b"<") else {
        return false;
    };
    let len = rest
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || *c == b':' || *c == b'-'))
        .unwrap_or(rest.len());
    let name = &rest[..len];
    let local = name.rsplit(|&c| c == b':').next().unwrap_or(name);
    WEB_ROOTS.contains(&local)
}

/// Decision 12: a plist or DER container naming a configuration payload,
/// also when written as UTF-16.
fn is_profile(b: &[u8], head: &[u8], bom16: u8) -> bool {
    let plist_xml = head.starts_with(b"<plist")
        || head.starts_with(b"<!doctype plist")
        || (head.starts_with(b"<?xml") && contains(head, b"<plist"));
    let der = b.first() == Some(&0x30) && matches!(b.get(1), Some(0x80 | 0x82 | 0x83 | 0x84));
    if !(plist_xml || b.starts_with(b"bplist00") || der) {
        return false;
    }
    let has = |needle: &[u8]| {
        contains(b, needle) || (bom16 != 0 && contains_utf16(&b[2..], needle, bom16))
    };
    has(b"PayloadType") || has(b"PayloadContent")
}

/// Decision 11: directory-entry slots only.
fn ole2_has_macros(b: &[u8]) -> bool {
    let mut at = 512usize;
    while let Some(e) = sub(b, at, 128) {
        let name_len = usize::from(u16::from_le_bytes([e[64], e[65]]));
        let kind = e[66];
        if (kind == 1 || kind == 2) && (4..=64).contains(&name_len) {
            let name = &e[..name_len - 2];
            if utf16_name_is(name, "_VBA_PROJECT") || utf16_name_is(name, "Macros") {
                return true;
            }
        }
        at = match at.checked_add(128) {
            Some(n) => n,
            None => return false,
        };
    }
    false
}

fn utf16_name_is(raw: &[u8], want: &str) -> bool {
    raw.len() == want.len() * 2
        && want
            .bytes()
            .enumerate()
            .all(|(i, c)| raw[2 * i].eq_ignore_ascii_case(&c) && raw[2 * i + 1] == 0)
}

fn le16(b: &[u8], at: usize) -> Option<usize> {
    let s = sub(b, at, 2)?;
    Some(usize::from(u16::from_le_bytes([s[0], s[1]])))
}

fn le32(b: &[u8], at: usize) -> Option<usize> {
    let s = sub(b, at, 4)?;
    usize::try_from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok()
}

struct CentralDirectory {
    offset: usize,
    /// One past the last byte of the directory.
    end: usize,
    count: usize,
}

const EOCD_LEN: usize = 22;

/// The one end record that describes a central directory inside the file,
/// or `None` when there is none or the file is ambiguous: a second record
/// that also ends the file, a record or entry signature inside the comment
/// or between the directory and the end record, or any Zip64 record or
/// locator in the tail (Decision 10, tightened).
fn central_directory(b: &[u8]) -> Option<CentralDirectory> {
    let last = b.len().checked_sub(EOCD_LEN)?;
    let lowest = b.len().saturating_sub(TAIL_WINDOW);
    let window = b.get(lowest..)?;
    if contains(window, b"PK\x06\x07") || contains(window, b"PK\x06\x06") {
        return None;
    }
    let mut found: Option<(usize, CentralDirectory)> = None;
    let mut at = last;
    loop {
        if sub(b, at, 4) == Some(&b"PK\x05\x06"[..]) {
            if let Some(dir) = end_record_at(b, at) {
                if found.is_some() {
                    return None;
                }
                found = Some((at, dir));
            }
        }
        if at == lowest {
            break;
        }
        at -= 1;
    }
    let (at, dir) = found?;
    let comment = b.get(at + EOCD_LEN..)?;
    if contains(comment, b"PK\x05\x06") || contains(comment, b"PK\x01\x02") {
        return None;
    }
    if contains(b.get(dir.offset..at)?, b"PK\x05\x06") {
        return None;
    }
    Some(dir)
}

/// An end record at `at` that ends the file, or is followed only by zero
/// bytes (some writers pad: a Google Fonts download has 24). Zeros hold no
/// signature, so every reader finds this same record.
fn end_record_at(b: &[u8], at: usize) -> Option<CentralDirectory> {
    let comment = le16(b, at.checked_add(20)?)?;
    let record_end = at.checked_add(EOCD_LEN)?.checked_add(comment)?;
    if b.get(record_end..)?.iter().any(|&z| z != 0) {
        return None;
    }
    let (disk, cd_disk) = (le16(b, at + 4)?, le16(b, at + 6)?);
    let (here, total) = (le16(b, at + 8)?, le16(b, at + 10)?);
    let (size, offset) = (le32(b, at + 12)?, le32(b, at + 16)?);
    if disk != 0 || cd_disk != 0 || here != total {
        return None;
    }
    if total == 0xFFFF || size == 0xFFFF_FFFF || offset == 0xFFFF_FFFF {
        return None; // Zip64
    }
    let end = offset.checked_add(size)?;
    if end > at {
        return None;
    }
    Some(CentralDirectory {
        offset,
        end,
        count: total,
    })
}

struct Flags {
    manifest: bool,
    dex: bool,
}

/// The size of a central directory entry without its name, extra field and
/// comment: no directory holds more entries than its size over this.
const CENTRAL_LEN: usize = 46;

/// A zip, from its central directory and each entry's local header.
///
/// The directory may list entries in any order (WPS Office writes it
/// alphabetically), but the entries' local records, sorted by offset, must
/// tile `[0, dir.offset)`: a reader that walks local headers from offset 0
/// (ditto, Java's `ZipInputStream`) then sees exactly the listed entries.
fn zip_verdict(b: &[u8], depth: u8, nested: &mut usize, doc_name: bool) -> Verdict {
    let Some(dir) = central_directory(b) else {
        return Verdict::Unchecked;
    };
    let web_ok = doc_name && is_document_container(b, &dir);
    let mut at = dir.offset;
    // (start, end) of each entry's local record. Capacity is bounded by the
    // directory's real size, never by the count the end record claims.
    let room = dir.end.saturating_sub(dir.offset) / CENTRAL_LEN;
    let mut spans: Vec<(usize, usize)> = Vec::with_capacity(dir.count.min(room));
    let mut flags = Flags {
        manifest: false,
        dex: false,
    };
    for _ in 0..dir.count {
        let Some(entry) = central_entry(b, at, dir.end) else {
            return Verdict::Unchecked;
        };
        if entry.flags & 0x0041 != 0 {
            return Verdict::Unchecked; // encrypted
        }
        let Some(local) = local_header(b, entry.local) else {
            return Verdict::Unchecked;
        };
        if local.name != entry.name || entry.name.contains(&0) {
            return Verdict::Unchecked;
        }
        match entry_span_end(b, &entry, &local) {
            Some(end) => spans.push((entry.local, end)),
            None => return Verdict::Unchecked,
        }
        let (Ok(central_alt), Ok(local_alt)) =
            (unicode_path(entry.extra), unicode_path(local.extra))
        else {
            return Verdict::Unchecked;
        };
        let mut is_zip = false;
        for name in [Some(entry.name), central_alt, local_alt]
            .into_iter()
            .flatten()
        {
            if name.contains(&0) {
                return Verdict::Unchecked;
            }
            let verdict = name_verdict(name, web_ok, &mut flags);
            if verdict.is_blocked() {
                return verdict;
            }
            let mut buf = [0u8; EXT_MAX];
            is_zip |= last_extension(leaf_of(name), &mut buf) == Some(&b"zip"[..]);
        }
        if is_zip {
            let verdict = nested_zip(b, &entry, &local, depth, nested);
            if verdict.is_blocked() {
                return verdict;
            }
        }
        at = entry.next;
    }
    if at != dir.end || !tiles(&mut spans, dir.offset) {
        // The count and the size disagree, or local data lies outside
        // the listed entries (a gap, an overlap, a shared header).
        return Verdict::Unchecked;
    }
    if flags.manifest && flags.dex {
        return Verdict::AndroidApp;
    }
    Verdict::Allowed
}

/// Sorted by start, the spans cover `[0, end)` exactly: the first starts
/// at 0, each starts where the one before ended, the last ends at `end`.
/// Every span is non-empty (a local header is 30 bytes), so a shared or
/// overlapping start fails.
fn tiles(spans: &mut [(usize, usize)], end: usize) -> bool {
    spans.sort_unstable();
    let mut expected = 0usize;
    for &(start, stop) in spans.iter() {
        if start != expected || stop <= start {
            return false;
        }
        expected = stop;
    }
    expected == end
}

/// The last non-empty path component, without trailing dots and spaces.
fn leaf_of(name: &[u8]) -> &[u8] {
    let leaf = name
        .rsplit(|&c| c == b'/' || c == b'\\')
        .find(|part| !part.is_empty())
        .unwrap_or(name);
    trim_name(leaf)
}

/// Every name-based rule for one name of one entry.
fn name_verdict(name: &[u8], web_ok: bool, flags: &mut Flags) -> Verdict {
    let leaf = leaf_of(name);
    if !name.contains(&b'/') && leaf.eq_ignore_ascii_case(b"AndroidManifest.xml") {
        flags.manifest = true;
    }
    if leaf.len() >= 11
        && leaf[..7].eq_ignore_ascii_case(b"classes")
        && leaf[leaf.len() - 4..].eq_ignore_ascii_case(b".dex")
    {
        flags.dex = true;
    }
    if is_ipa_payload(name) {
        return Verdict::AppleAppOrProfile;
    }
    if leaf.eq_ignore_ascii_case(b"vbaProject.bin") {
        return Verdict::MacroDocument;
    }
    let verdict = by_extension(leaf, true, web_ok);
    if verdict.is_blocked() {
        return verdict;
    }
    if has_app_bundle_dir(name) {
        return Verdict::Program;
    }
    Verdict::Allowed
}

/// Decision 8 (amended): the directory lists `[Content_Types].xml` (OOXML),
/// `mimetype` (OpenDocument, EPUB) or `META-INF/container.xml` (EPUB). A
/// malformed directory just ends the scan; the main walk reports it.
fn is_document_container(b: &[u8], dir: &CentralDirectory) -> bool {
    let mut at = dir.offset;
    for _ in 0..dir.count {
        let Some(entry) = central_entry(b, at, dir.end) else {
            return false;
        };
        if entry.name == b"[Content_Types].xml"
            || entry.name == b"mimetype"
            || entry.name == b"META-INF/container.xml"
        {
            return true;
        }
        at = entry.next;
    }
    false
}

const NO32: usize = 0xFFFF_FFFF;

/// Where this entry's local record (header, data, descriptor) ends, if it
/// agrees with the directory.
fn entry_span_end(b: &[u8], entry: &CentralEntry, local: &LocalHeader) -> Option<usize> {
    if entry.method != 0 && entry.method != 8 {
        return None;
    }
    // A 32-bit field at its maximum is a real Zip64 entry; a Zip64 extra
    // field next to ordinary values is only a placeholder.
    if [
        entry.compressed,
        entry.uncompressed,
        local.compressed,
        local.uncompressed,
    ]
    .contains(&NO32)
    {
        return None;
    }
    if local.method != entry.method || (local.flags ^ entry.flags) & 0x0049 != 0 {
        return None;
    }
    let descriptor = entry.flags & 0x0008 != 0;
    if !descriptor
        && (local.crc, local.compressed, local.uncompressed)
            != (entry.crc, entry.compressed, entry.uncompressed)
    {
        return None;
    }
    if entry.name.ends_with(b"/") && (entry.compressed != 0 || entry.uncompressed != 0) {
        return None;
    }
    // Some extractors read a trailing backslash as a directory too.
    if entry.name.ends_with(b"\\") {
        return None;
    }
    let data = sub(b, local.data, entry.compressed)?;
    // A deflate stream that ends early could hide a record. Stored data
    // with sizes is skipped by size, and a nested zip is classified on its
    // own. Stored data with a descriptor has no size in its local header:
    // a streaming reader looks for the descriptor's signature, so the data
    // must hold none of the signatures and the descriptor must be signed.
    let stored_streamed = descriptor && entry.method == 0;
    let hides_record = |w: &[u8]| {
        w == b"PK\x03\x04"
            || w == b"PK\x01\x02"
            || w == b"PK\x05\x06"
            || (stored_streamed && w == b"PK\x07\x08")
    };
    if (entry.method != 0 || stored_streamed) && data.windows(4).any(hides_record) {
        return None;
    }
    let data_end = local.data.checked_add(entry.compressed)?;
    if descriptor {
        let len = descriptor_len(b, data_end, entry)?;
        if stored_streamed && len != 16 {
            return None;
        }
        data_end.checked_add(len)
    } else {
        Some(data_end)
    }
}

/// A data descriptor at `at` (with or without its signature) whose CRC and
/// sizes equal the directory's: its length.
fn descriptor_len(b: &[u8], at: usize, entry: &CentralEntry) -> Option<usize> {
    let want = [entry.crc, entry.compressed, entry.uncompressed];
    let fields = |from: usize| {
        want.iter()
            .enumerate()
            .all(|(i, w)| from.checked_add(4 * i).and_then(|p| le32(b, p)) == Some(*w))
    };
    if sub(b, at, 4) == Some(&b"PK\x07\x08"[..]) && fields(at.checked_add(4)?) {
        Some(16)
    } else if fields(at) {
        Some(12)
    } else {
        None
    }
}

struct CentralEntry<'a> {
    flags: usize,
    method: usize,
    crc: usize,
    uncompressed: usize,
    compressed: usize,
    local: usize,
    name: &'a [u8],
    extra: &'a [u8],
    next: usize,
}

fn central_entry(b: &[u8], at: usize, end: usize) -> Option<CentralEntry<'_>> {
    if at.checked_add(46)? > end || sub(b, at, 4)? != b"PK\x01\x02" {
        return None;
    }
    let (n, m, k) = (le16(b, at + 28)?, le16(b, at + 30)?, le16(b, at + 32)?);
    let next = (at + 46).checked_add(n)?.checked_add(m)?.checked_add(k)?;
    if next > end {
        return None;
    }
    Some(CentralEntry {
        flags: le16(b, at + 8)?,
        method: le16(b, at + 10)?,
        crc: le32(b, at + 16)?,
        uncompressed: le32(b, at + 24)?,
        compressed: le32(b, at + 20)?,
        local: le32(b, at + 42)?,
        name: sub(b, at + 46, n)?,
        extra: sub(b, at + 46 + n, m)?,
        next,
    })
}

struct LocalHeader<'a> {
    flags: usize,
    method: usize,
    crc: usize,
    compressed: usize,
    uncompressed: usize,
    name: &'a [u8],
    extra: &'a [u8],
    data: usize,
}

/// The local header at `at`: its signature, and a name and extra field
/// that lie inside the file.
fn local_header(b: &[u8], at: usize) -> Option<LocalHeader<'_>> {
    if sub(b, at, 4)? != b"PK\x03\x04" {
        return None;
    }
    let (n, m) = (le16(b, at.checked_add(26)?)?, le16(b, at.checked_add(28)?)?);
    let name_at = at.checked_add(30)?;
    let extra_at = name_at.checked_add(n)?;
    Some(LocalHeader {
        flags: le16(b, at + 6)?,
        method: le16(b, at + 8)?,
        crc: le32(b, at + 14)?,
        compressed: le32(b, at + 18)?,
        uncompressed: le32(b, at + 22)?,
        name: sub(b, name_at, n)?,
        extra: sub(b, extra_at, m)?,
        data: extra_at.checked_add(m)?,
    })
}

/// The Info-ZIP Unicode Path field (0x7075), if any: some extractors name
/// the file by it. A malformed field list or a second such field is an
/// error. (A Zip64 field (0x0001) is only a placeholder
/// unless a 32-bit size is at its maximum, which `entry_span_end` rejects.)
fn unicode_path(extra: &[u8]) -> Result<Option<&[u8]>, ()> {
    let mut at = 0usize;
    let mut found = None;
    while at < extra.len() {
        let id = le16(extra, at).ok_or(())?;
        let len = le16(extra, at + 2).ok_or(())?;
        let data = sub(extra, at + 4, len).ok_or(())?;
        match id {
            0x7075 => {
                if found.is_some() || data.len() < 5 {
                    return Err(());
                }
                found = Some(&data[5..]);
            }
            _ => {}
        }
        at += 4 + len;
    }
    Ok(found)
}

/// `Payload/<name>.app/…`, as an IPA lays out its app.
fn is_ipa_payload(name: &[u8]) -> bool {
    let mut parts = name.split(|&c| c == b'/');
    let (Some(first), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    first.eq_ignore_ascii_case(b"Payload")
        && second.len() > 4
        && second[second.len() - 4..].eq_ignore_ascii_case(b".app")
}

/// A directory component ending in `.app` (a macOS or iOS app bundle).
fn has_app_bundle_dir(name: &[u8]) -> bool {
    let mut parts = name.split(|&c| c == b'/' || c == b'\\').peekable();
    while let Some(part) = parts.next() {
        let is_dir = parts.peek().is_some_and(|p| !p.is_empty());
        if is_dir && part.len() > 4 && part[part.len() - 4..].eq_ignore_ascii_case(b".app") {
            return true;
        }
    }
    false
}

/// Decision 9: a stored nested zip inside the outer file is classified
/// once, one level deep; anything else can't be checked.
fn nested_zip(
    b: &[u8],
    entry: &CentralEntry,
    local: &LocalHeader,
    depth: u8,
    nested: &mut usize,
) -> Verdict {
    *nested += 1;
    if depth > 0 || entry.method != 0 || *nested > MAX_NESTED_ZIPS {
        return Verdict::Unchecked;
    }
    let Some(data) = sub(b, local.data, entry.compressed) else {
        return Verdict::Unchecked;
    };
    // The nested entry is named `*.zip`, never a document type.
    by_content(data, depth + 1, nested, false)
}

#[cfg(test)]
mod tests;
