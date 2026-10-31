#![no_main]
//! The photo and voice checks (file-safety spec §4, §7) on arbitrary input.

use libfuzzer_sys::fuzz_target;

#[path = "../../src/media_check.rs"]
#[allow(dead_code)]
mod media_check;

fuzz_target!(|data: &[u8]| {
    let photo = media_check::photo_ok(data);
    let _ = media_check::voice_ok(data);
    let _ = media_check::heif_major_brand(data);
    if let Some((w, h)) = media_check::photo_dimensions(data) {
        if photo {
            assert!(u64::from(w) * u64::from(h) <= media_check::MAX_PHOTO_PIXELS);
        }
    }
});
