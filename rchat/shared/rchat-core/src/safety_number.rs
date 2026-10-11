//! Safety numbers (spec §4.7): a 60-digit number from both parties' pinned
//! identity and agreement keys, identical on both phones.

use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha512};

pub const SN_DOMAIN: &[u8; 23] = b"rchat/safety-number/v1\0";
pub const SN_VERSION: u16 = 1;
pub const SN_ITERATIONS: u32 = 5200;
pub const SN_DIGITS: usize = 60;
const TEXT_PREFIX: &str = "sn:1:";

/// 30 digits for one party: SHA-512 iterated 5200 times over the keys,
/// then six 40-bit big-endian chunks, each mod 100000.
pub fn party_fingerprint(identity_key: &[u8; 32], agreement_key: &[u8; 32]) -> String {
    let mut h = Sha512::new();
    h.update(SN_DOMAIN);
    h.update(SN_VERSION.to_be_bytes());
    h.update(identity_key);
    h.update(agreement_key);
    let mut digest = h.finalize();
    for _ in 1..SN_ITERATIONS {
        let mut h = Sha512::new();
        h.update(digest);
        h.update(identity_key);
        h.update(agreement_key);
        digest = h.finalize();
    }
    let mut out = String::with_capacity(30);
    for chunk in digest[..30].chunks(5) {
        let n = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        out.push_str(&format!("{:05}", n % 100_000));
    }
    out
}

/// The shared number: the two 30-digit fingerprints in string order.
pub fn safety_number(a_ik: &[u8; 32], a_ak: &[u8; 32], b_ik: &[u8; 32], b_ak: &[u8; 32]) -> String {
    let (a, b) = (party_fingerprint(a_ik, a_ak), party_fingerprint(b_ik, b_ak));
    if a <= b {
        a + &b
    } else {
        b + &a
    }
}

fn is_number(s: &str) -> bool {
    s.len() == SN_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

pub fn format_groups(number: &str) -> Vec<String> {
    number
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// Three lines of four groups (the sheet shows them unbroken).
pub fn format_lines(number: &str) -> Vec<String> {
    format_groups(number)
        .chunks(4)
        .map(|g| g.join(" "))
        .collect()
}

pub fn to_text_form(number: &str) -> String {
    format!("{TEXT_PREFIX}{number}")
}

pub fn parse_text_form(s: &str) -> Option<String> {
    let digits = s.strip_prefix(TEXT_PREFIX)?;
    is_number(digits).then(|| digits.to_string())
}

/// Constant-time equality of two numbers (different lengths are unequal).
pub fn numbers_equal(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Result of comparing a scanned safety-number QR (D22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ScanComparison {
    Match,
    Mismatch,
    /// Not an `sn:1:` code with 60 digits.
    Invalid,
}

/// Compare the other phone's scanned code with our number, in constant time.
pub fn compare_scanned(expected: &str, scanned: &str) -> ScanComparison {
    match parse_text_form(scanned.trim()) {
        None => ScanComparison::Invalid,
        Some(digits) if numbers_equal(expected, &digits) => ScanComparison::Match,
        Some(_) => ScanComparison::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_IK: [u8; 32] = [0x11; 32];
    const A_AK: [u8; 32] = [0x22; 32];
    const B_IK: [u8; 32] = [0x33; 32];
    const B_AK: [u8; 32] = [0x44; 32];

    /// SN1: golden vectors; the same number from either side.
    #[test]
    fn sn1_golden_vectors_and_order_independence() {
        assert_eq!(
            party_fingerprint(&A_IK, &A_AK),
            "311686637181083400395252065708"
        );
        assert_eq!(
            party_fingerprint(&B_IK, &B_AK),
            "207876968560055734126985141340"
        );
        let n = safety_number(&A_IK, &A_AK, &B_IK, &B_AK);
        assert_eq!(
            n,
            "207876968560055734126985141340311686637181083400395252065708"
        );
        assert_eq!(safety_number(&B_IK, &B_AK, &A_IK, &A_AK), n);
        let mut a_ak2 = A_AK;
        a_ak2[0] = 0x23;
        assert_eq!(
            party_fingerprint(&A_IK, &a_ak2),
            "035881228040029929743832583803"
        );
        assert_eq!(n.len(), SN_DIGITS);
    }

    /// SN2: every key byte matters; formatting; text form.
    #[test]
    fn sn2_inputs_formatting_and_text_form() {
        let n = safety_number(&A_IK, &A_AK, &B_IK, &B_AK);
        for which in 0..4 {
            for byte in [0usize, 31] {
                let mut keys = [A_IK, A_AK, B_IK, B_AK];
                keys[which][byte] ^= 1;
                assert_ne!(
                    safety_number(&keys[0], &keys[1], &keys[2], &keys[3]),
                    n,
                    "key {which} byte {byte}"
                );
            }
        }
        let groups = format_groups(&n);
        assert_eq!(groups.len(), 12);
        assert!(groups.iter().all(|g| g.len() == 5));
        assert_eq!(groups.concat(), n);
        let lines = format_lines(&n);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "20787 69685 60055 73412");
        let text = to_text_form(&n);
        assert_eq!(text, format!("sn:1:{n}"));
        assert_eq!(parse_text_form(&text).as_deref(), Some(n.as_str()));
        for bad in [
            "",
            "sn:2:207876968560055734126985141340311686637181083400395252065708",
            "sn:1:20787696856005573412698514134031168663718108340039525206570",
            "sn:1:20787696856005573412698514134031168663718108340039525206570x",
        ] {
            assert_eq!(parse_text_form(bad), None, "{bad}");
        }
    }

    /// SN3: constant-time equality semantics.
    #[test]
    fn sn3_numbers_equal() {
        let n = safety_number(&A_IK, &A_AK, &B_IK, &B_AK);
        assert!(numbers_equal(&n, &n.clone()));
        let mut off = n.clone().into_bytes();
        off[59] = if off[59] == b'0' { b'1' } else { b'0' };
        assert!(!numbers_equal(&n, std::str::from_utf8(&off).unwrap()));
        assert!(!numbers_equal(&n, &n[..59]));
        assert!(!numbers_equal(&n, &format!("{n}0")));
    }
}
