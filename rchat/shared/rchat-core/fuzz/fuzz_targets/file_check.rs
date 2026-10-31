#![no_main]
//! The file classifier (file-safety spec §3, §7) on arbitrary input: the
//! first byte says how much of the rest is the name.

use libfuzzer_sys::fuzz_target;

#[path = "../../src/file_check.rs"]
#[allow(dead_code)]
mod file_check;

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let (name, bytes) = rest.split_at(usize::from(n).min(rest.len()));
    let name = String::from_utf8_lossy(name);
    let verdict = file_check::classify(&name, bytes);
    assert_eq!(verdict.is_blocked(), verdict.code() != 0);
});
