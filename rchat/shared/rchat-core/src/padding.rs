//! Ratchet plaintext padding (spec §5.6): ISO/IEC 7816-4 (0x80 then zeros)
//! up to 256 B, 1 KiB, 4 KiB, 16 KiB, then multiples of 64 KiB, so message
//! and receipt sizes reveal only their bucket. Knocks are never padded here.

pub(crate) const SMALL_BUCKETS: [usize; 4] = [256, 1024, 4096, 16_384];
pub(crate) const LARGE_STEP: usize = 65_536;

/// Padded length for a message of `len` bytes (at least one pad byte).
pub fn bucket(len: usize) -> usize {
    let need = len + 1;
    SMALL_BUCKETS
        .iter()
        .copied()
        .find(|b| need <= *b)
        .unwrap_or_else(|| need.div_ceil(LARGE_STEP) * LARGE_STEP)
}

pub fn pad(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bucket(msg.len()));
    out.extend_from_slice(msg);
    out.push(0x80);
    out.resize(bucket(msg.len()), 0);
    out
}

/// Pad to exactly `len` bytes (protocol v3 §B.1, steady slots), or `None`
/// when the message does not fit with its one marker byte. Such messages
/// go outside the steady shape, padded by `pad`.
pub fn pad_exact(msg: &[u8], len: usize) -> Option<Vec<u8>> {
    if msg.len() >= len {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(msg);
    out.push(0x80);
    out.resize(len, 0);
    Some(out)
}

/// Strip trailing zeros and the 0x80 marker; `None` if there is no marker
/// or the padded length is neither the bucket of the message length nor
/// the steady slot's exact length (`pad_exact` to 1 KiB, §B.1).
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().rposition(|b| *b != 0)?;
    let len_ok = padded.len() == bucket(end) || padded.len() == crate::steady::STEADY_PLAINTEXT_LEN;
    (padded[end] == 0x80 && len_ok).then(|| &padded[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(bucket(0), 256);
        assert_eq!(bucket(255), 256);
        assert_eq!(bucket(256), 1024, "always at least one padding byte");
        assert_eq!(bucket(1023), 1024);
        assert_eq!(bucket(1024), 4096);
        assert_eq!(bucket(16_383), 16_384);
        assert_eq!(bucket(16_384), 65_536);
        assert_eq!(bucket(65_535), 65_536);
        assert_eq!(bucket(65_536), 131_072);
        assert_eq!(bucket(200_000), 262_144);
    }

    #[test]
    fn pad_round_trip_including_trailing_zero_and_marker_bytes() {
        for msg in [
            &b""[..],
            b"hi",
            &[0x80u8, 0, 0][..],
            &[0u8; 300][..],
            &vec![0x80u8; 5000][..],
        ] {
            let p = pad(msg);
            assert_eq!(p.len(), bucket(msg.len()));
            assert_eq!(unpad(&p), Some(msg));
        }
    }

    #[test]
    fn unpad_rejects_malformed() {
        assert_eq!(unpad(&[]), None);
        assert_eq!(unpad(&[0u8; 256]), None, "no 0x80 marker");
        assert_eq!(unpad(&[1u8, 2, 3]), None, "no marker at the end");
        assert_eq!(
            unpad(&[1u8, 0x80, 0]),
            None,
            "marker, but not a bucket length"
        );
        let mut long = pad(b"hi");
        long.extend_from_slice(&[0u8; 3840]); // 4096 bytes: the wrong bucket for 2
        assert_eq!(unpad(&long), None, "padded past its bucket");
        // Exactly 1 KiB is the steady slot's length (§B.1): accepted for
        // any message that fits it, and nothing else in between buckets.
        let mut slot = pad(b"hi");
        slot.extend_from_slice(&[0u8; 768]);
        assert_eq!(unpad(&slot), Some(&b"hi"[..]), "steady slot length");
        let mut odd = pad(b"hi");
        odd.extend_from_slice(&[0u8; 100]);
        assert_eq!(unpad(&odd), None, "neither a bucket nor the slot length");
    }
}
