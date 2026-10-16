//! File messages (protocol v3 §E.2): ratchet plaintext type `0x07`.
//!
//! Layout (ruling R2: every v3 message plaintext carries the disappearing
//! timer right after its type byte, §I.2):
//!
//! ```text
//! 0x07 ‖ expire_secs(u32 BE, 0 = never) ‖ name_len(u16 BE) ‖ name
//!      ‖ mime_len(u8) ‖ mime ‖ size(u64 BE) ‖ bytes
//! ```
//!
//! - `name` is at most 255 bytes on the wire; a longer one is dropped.
//!   Both ends run it through [`sanitise_name`]; the receiver never trusts
//!   the sender's cleaning.
//! - `mime` is advisory only: printable ASCII (0x20-0x7E), at most 255
//!   bytes, refused at encode and dropped at decode otherwise. The core
//!   never interprets it, and nothing is ever opened because of it.
//! - `size` must equal the number of bytes that follow, otherwise the
//!   message is dropped. It is compared with the remaining length before
//!   anything is allocated, so a huge declared size costs nothing.
//! - The whole plaintext is at most [`MAX_FILE_PLAINTEXT`] bytes.

/// The ratchet plaintext type of a file message.
pub const FILE_TYPE: u8 = 0x07;
/// Largest name, in UTF-8 bytes, on the wire and after cleaning.
pub const MAX_NAME_BYTES: usize = 255;
/// Largest MIME label, in bytes (it is ASCII).
pub const MAX_MIME_BYTES: usize = 255;
/// The relay's default `max_message_bytes` (4 MiB): the largest WebSocket
/// message it accepts (the client's inbound cap,
/// `transport::MAX_INBOUND_MESSAGE_BYTES`, is this plus slack).
pub const RELAY_MAX_MESSAGE_BYTES: usize = 4 << 20;
/// Largest file plaintext (type byte included) the core sends: the relay's
/// 4 MiB minus overhead. The ratchet plaintext is padded up to a multiple
/// of 64 KiB (`padding::LARGE_STEP`, at least one pad byte), and when the
/// message travels as the session-init (§A.4) the KEM ciphertext, confirm
/// tag and ratchet body are padded again to the next 64 KiB step; the
/// sealed envelope, relay header and frame byte take a few hundred bytes
/// of the step left over. So the padded plaintext may use at most
/// 4 MiB - 128 KiB, and the plaintext one byte less (the pad marker).
pub const MAX_FILE_PLAINTEXT: usize = RELAY_MAX_MESSAGE_BYTES - 2 * crate::padding::LARGE_STEP - 1;
/// The fixed fields: type, expire_secs, name_len, mime_len, size.
pub const FILE_HEADER_LEN: usize = 1 + 4 + 2 + 1 + 8;

/// Why a file plaintext was refused (encode) or dropped (decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// Not a `0x07` plaintext.
    NotAFile,
    /// Ends before a field it declares.
    Truncated,
    /// A wire name over 255 bytes.
    NameTooLong,
    /// A MIME label over 255 bytes, or not printable ASCII.
    MimeInvalid,
    /// `size` is not the number of bytes that follow.
    SizeMismatch,
    /// Over `MAX_FILE_PLAINTEXT` (encode only).
    TooLarge,
}

/// A decoded file message: `name` is already cleaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMsg {
    pub expire_secs: u32,
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// Characters rule (b) replaces besides `/`, `\` and controls (R30):
/// - look-alike path separators: U+FF0F, U+FF3C, U+FE68, U+2215, U+2044,
///   U+29F8, U+29F9, U+2216;
/// - every format (Cf) character, as an explicit table (no Unicode data
///   dependency). It includes the bidi embeddings, overrides, isolates and
///   marks (U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C) and the
///   zero-width characters;
/// - the line and paragraph separators U+2028 and U+2029.
fn is_replaced(c: char) -> bool {
    matches!(
        c,
        // Look-alike separators.
        '\u{FF0F}' | '\u{FF3C}' | '\u{FE68}' | '\u{2215}' | '\u{2044}' | '\u{29F8}' | '\u{29F9}'
        | '\u{2216}'
        // Format (Cf) characters.
        | '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{0890}'..='\u{0891}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        // Line and paragraph separators.
        | '\u{2028}'
        | '\u{2029}'
    )
}

/// Windows device names, matched case-insensitively against the stem.
const DEVICE_NAMES: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{00B9}",
    "COM\u{00B2}",
    "COM\u{00B3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{00B9}",
    "LPT\u{00B2}",
    "LPT\u{00B3}",
];

/// The stem (before the first `.`, trailing spaces ignored) is a Windows
/// device name. Only ASCII letters differ in case among them.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    DEVICE_NAMES.iter().any(|d| d.eq_ignore_ascii_case(stem))
}

fn trim_trailing_spaces_and_dots(s: &mut String) {
    let keep = s.trim_end_matches([' ', '.']).len();
    s.truncate(keep);
}

/// The longest prefix of `s` of at most `max` bytes, on a char boundary.
fn floor_boundary(s: &str, max: usize) -> usize {
    if s.len() <= max {
        return s.len();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// (d2): prefix a device name with `_`; true if it did.
fn prefix_device_name(s: &mut String) -> bool {
    let hit = !s.is_empty() && is_device_name(s);
    if hit {
        s.insert(0, '_');
    }
    hit
}

/// (e): cut to `MAX_NAME_BYTES`, keeping a short extension.
fn truncate_to_limit(s: &mut String) {
    let ext_at = s.rfind('.').filter(|&dot| dot > 0 && s.len() - dot <= 16);
    match ext_at {
        Some(dot) => {
            let ext = s[dot..].to_string();
            let stem_end = floor_boundary(&s[..dot], MAX_NAME_BYTES - ext.len());
            s.truncate(stem_end);
            s.push_str(&ext);
        }
        None => {
            let end = floor_boundary(s, MAX_NAME_BYTES);
            s.truncate(end);
            trim_trailing_spaces_and_dots(s);
        }
    }
}

/// Clean a received (or outgoing) file name. The rules run in this order:
///
/// - (a) decode the bytes as UTF-8, lossily (an invalid sequence becomes
///   U+FFFD);
/// - (b) replace with `_` (one `_` per character, never deleted): `/`,
///   `\`, NUL, every C0 and C1 control (and DEL, which Unicode also classes
///   as a control), the look-alike separators, every format (Cf) character
///   (bidi controls and zero-width characters included) and U+2028/U+2029,
///   as listed on `is_replaced` (R30). So `CON` + U+200B + `.txt` becomes
///   `CON_.txt`, which is not a device name;
/// - (c) strip leading `.` characters (so `.` and `..` become empty, and
///   no hidden files);
/// - (d) trim trailing spaces and dots (Windows and the iOS Files app
///   mishandle them);
/// - (d2) a Windows device name (CON, PRN, AUX, NUL, CONIN$, CONOUT$,
///   COM0-9, LPT0-9 and COM/LPT with a superscript 1-3), matched
///   case-insensitively on the stem before the first `.` with trailing
///   spaces ignored, gets a `_` prefix (`con.txt` → `_con.txt`). It runs
///   before (e) and again after it (R30 M-1: a cut can expose one, as in
///   `CON` + 300 spaces + `b` → `_CON`); if that late prefix pushes the
///   name over 255 bytes, (e) runs once more;
/// - (e) truncate to at most 255 bytes on a char boundary. When the name
///   ends in an extension (its last `.`, not at the start, with the `.`
///   and what follows at most 16 bytes) the stem is cut and the extension
///   kept; otherwise the whole name is cut and then trimmed of trailing
///   spaces and dots again;
/// - (f) an empty result becomes `file`.
pub fn sanitise_name(raw: &[u8]) -> String {
    // (a) + (b)
    let mut s: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() || is_replaced(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    // (c)
    let lead = s.len() - s.trim_start_matches('.').len();
    s.drain(..lead);
    // (d)
    trim_trailing_spaces_and_dots(&mut s);
    // (d2)
    prefix_device_name(&mut s);
    // (e)
    if s.len() > MAX_NAME_BYTES {
        truncate_to_limit(&mut s);
        // (d2) again: the cut may have exposed a device name.
        if prefix_device_name(&mut s) && s.len() > MAX_NAME_BYTES {
            truncate_to_limit(&mut s);
        }
    }
    // (f)
    if s.is_empty() {
        s.push_str("file");
    }
    s
}

/// Printable ASCII, at most 255 bytes.
pub(crate) fn mime_ok(mime: &[u8]) -> bool {
    mime.len() <= MAX_MIME_BYTES && mime.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// The plaintext after its type byte (what `steady::message_plaintext`
/// puts behind `0x07`), with the name cleaned by `sanitise_name`.
pub(crate) fn encode_file_body(
    name: &str,
    mime: &str,
    bytes: &[u8],
    expire_secs: u32,
) -> Result<Vec<u8>, FileError> {
    if !mime_ok(mime.as_bytes()) {
        return Err(FileError::MimeInvalid);
    }
    // Checked before cleaning the name or copying anything: the cleaned
    // name is at most 255 bytes, so this bound is exact once it passes.
    if bytes.len() > MAX_FILE_PLAINTEXT {
        return Err(FileError::TooLarge);
    }
    let name = sanitise_name(name.as_bytes());
    let total = FILE_HEADER_LEN + name.len() + mime.len() + bytes.len();
    if total > MAX_FILE_PLAINTEXT {
        return Err(FileError::TooLarge);
    }
    let mut v = Vec::with_capacity(total - 1);
    v.extend_from_slice(&expire_secs.to_be_bytes());
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name.as_bytes());
    v.push(mime.len() as u8);
    v.extend_from_slice(mime.as_bytes());
    v.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    v.extend_from_slice(bytes);
    Ok(v)
}

/// Build a `0x07` plaintext. The name is cleaned (`sanitise_name`); the
/// MIME must be printable ASCII of at most 255 bytes (`MimeInvalid`); the
/// whole plaintext must fit `MAX_FILE_PLAINTEXT` (`TooLarge`).
pub fn encode_file(
    name: &str,
    mime: &str,
    bytes: &[u8],
    expire_secs: u32,
) -> Result<Vec<u8>, FileError> {
    // The intermediate copy is wiped (R30 M-3).
    let body = zeroize::Zeroizing::new(encode_file_body(name, mime, bytes, expire_secs)?);
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(FILE_TYPE);
    v.extend_from_slice(&body);
    Ok(v)
}

/// The fields of a `0x07` plaintext, borrowed and checked; nothing is
/// allocated.
struct FileView<'a> {
    expire_secs: u32,
    name: &'a [u8],
    mime: &'a [u8],
    bytes: &'a [u8],
}

/// Split `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], FileError> {
    if rest.len() < n {
        return Err(FileError::Truncated);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn parse(pt: &[u8]) -> Result<FileView<'_>, FileError> {
    let mut rest = pt;
    if take(&mut rest, 1)? != [FILE_TYPE] {
        return Err(FileError::NotAFile);
    }
    let e = take(&mut rest, 4)?;
    let expire_secs = u32::from_be_bytes([e[0], e[1], e[2], e[3]]);
    let n = take(&mut rest, 2)?;
    let name_len = usize::from(u16::from_be_bytes([n[0], n[1]]));
    if name_len > MAX_NAME_BYTES {
        return Err(FileError::NameTooLong);
    }
    let name = take(&mut rest, name_len)?;
    let mime_len = usize::from(take(&mut rest, 1)?[0]);
    let mime = take(&mut rest, mime_len)?;
    if !mime_ok(mime) {
        return Err(FileError::MimeInvalid);
    }
    let s = take(&mut rest, 8)?;
    let size = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
    // Compared with what is actually there, before anything is allocated.
    if u64::try_from(rest.len()).ok() != Some(size) {
        return Err(FileError::SizeMismatch);
    }
    Ok(FileView {
        expire_secs,
        name,
        mime,
        bytes: rest,
    })
}

/// Parse a `0x07` plaintext and clean its name. Any malformed field drops
/// the whole message. Allocates only after every check passed: the cleaned
/// name (bounded by the 255-byte wire name), the MIME and a copy of the
/// bytes (at most the input).
pub fn decode_file(pt: &[u8]) -> Result<FileMsg, FileError> {
    let v = parse(pt)?;
    Ok(FileMsg {
        expire_secs: v.expire_secs,
        name: sanitise_name(v.name),
        // Printable ASCII, checked by `parse`.
        mime: String::from_utf8_lossy(v.mime).into_owned(),
        bytes: v.bytes.to_vec(),
    })
}

/// `decode_file` would accept `pt`; nothing is allocated.
pub(crate) fn is_valid(pt: &[u8]) -> bool {
    parse(pt).is_ok()
}

#[cfg(test)]
mod tests;
