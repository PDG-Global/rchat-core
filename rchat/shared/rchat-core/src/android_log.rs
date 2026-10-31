//! Debug Android libraries only (the `dev-log` feature, which
//! android/build_rust.sh sets for the debug set): the core's connection and
//! pairing diagnostics go to logcat under the tag `rChatCore`. Only records
//! from the transport, blind-pairing and circuit modules are written, and
//! any word with a `/` in it (a URL, the websocket path) or a run of 16 or
//! more hex digits (an identity, a token) is replaced first.
//! A release library has none of this (build_rust.sh checks its exports).

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

const ANDROID_LOG_DEBUG: c_int = 3;
const MODULES: [&str; 3] = [
    "rchat_core::transport",
    "rchat_core::blind",
    "rchat_core::circuits",
];

struct CoreLog;

impl log::Log for CoreLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        let t = m.target();
        m.level() <= log::Level::Debug
            && MODULES
                .iter()
                .any(|p| t == *p || t.strip_prefix(p).is_some_and(|rest| rest.starts_with("::")))
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let (Ok(tag), Ok(text)) = (
            CString::new("rChatCore"),
            CString::new(redact(&r.args().to_string())),
        ) else {
            return;
        };
        // SAFETY: both pointers are valid NUL-terminated strings for the call.
        unsafe {
            __android_log_write(ANDROID_LOG_DEBUG, tag.as_ptr(), text.as_ptr());
        }
    }

    fn flush(&self) {}
}

/// Every word with a `/` in it, or with 16 or more hex digits in a row,
/// becomes `<redacted>`.
fn redact(s: &str) -> String {
    let hex_run = |w: &str| {
        w.as_bytes()
            .split(|b| !b.is_ascii_hexdigit())
            .any(|run| run.len() >= 16)
    };
    s.split(' ')
        .map(|w| {
            if w.contains('/') || hex_run(w) {
                "<redacted>"
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

static LOGGER: CoreLog = CoreLog;

/// Called once, from `JNI_OnLoad`.
pub(crate) fn install() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}
