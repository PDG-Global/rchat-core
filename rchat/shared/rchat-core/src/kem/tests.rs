//! ML-KEM-768 wrapper: round trip, determinism, length and key checks,
//! implicit rejection, NIST ACVP known answers, and wiping on drop.

use super::*;

const KAT: &str = include_str!("kat_mlkem768.txt");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("KAT hex")
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("KAT field length")
}

/// Parses the KAT file into records of `(name, hex)` pairs.
fn kat_records() -> Vec<Vec<(String, String)>> {
    let mut records = Vec::new();
    let mut cur = Vec::new();
    for line in KAT.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                records.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line.split_once(" = ").expect("KAT line");
        cur.push((k.to_string(), v.to_string()));
    }
    records
}

fn field<'a>(rec: &'a [(String, String)], name: &str) -> &'a str {
    rec.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("KAT record lacks {name}"))
}

#[test]
fn round_trip() {
    let kp = KemKeyPair::generate();
    let (ct, ss) = encapsulate(kp.public()).unwrap();
    assert_eq!(ct.len(), KEM_CT_LEN);
    let ss2 = kp.decapsulate(&ct).unwrap();
    assert_eq!(*ss, *ss2);
    assert_ne!(*ss, [0u8; 32]);
}

#[test]
fn from_seed_is_deterministic() {
    let a = KemKeyPair::from_seed(&[7u8; 64]);
    let b = KemKeyPair::from_seed(&[7u8; 64]);
    assert_eq!(a.public(), b.public());
    assert_eq!(a.secret_bytes(), b.secret_bytes());
    let mut other = [7u8; 64];
    other[63] ^= 1; // differs only in z: same public key, different secret
    let c = KemKeyPair::from_seed(&other);
    assert_eq!(a.public(), c.public());
    assert_ne!(a.secret_bytes(), c.secret_bytes());
    other[0] ^= 1; // differs in d too
    let d = KemKeyPair::from_seed(&other);
    assert_ne!(a.public(), d.public());
    assert_ne!(
        KemKeyPair::generate().public(),
        KemKeyPair::generate().public()
    );
}

#[test]
fn wrong_lengths_refused() {
    let kp = KemKeyPair::generate();
    assert_eq!(
        encapsulate(&[0u8; KEM_PK_LEN - 1]).unwrap_err(),
        KemError::BadLength
    );
    assert_eq!(
        encapsulate(&[0u8; KEM_PK_LEN + 1]).unwrap_err(),
        KemError::BadLength
    );
    assert_eq!(encapsulate(&[]).unwrap_err(), KemError::BadLength);
    assert_eq!(
        kp.decapsulate(&[0u8; KEM_CT_LEN - 1]).unwrap_err(),
        KemError::BadLength
    );
    assert_eq!(
        kp.decapsulate(&[0u8; KEM_CT_LEN + 1]).unwrap_err(),
        KemError::BadLength
    );
}

#[test]
fn noncanonical_public_key_refused() {
    let kp = KemKeyPair::from_seed(&[3u8; 64]);
    // First coefficient set to 0xFFF (>= q).
    let mut bad = *kp.public();
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(encapsulate(&bad).unwrap_err(), KemError::BadKey);
    // Last coefficient of t set to q exactly.
    let mut bad = *kp.public();
    let i = EK_T_LEN - 3;
    bad[i + 1] = (bad[i + 1] & 0x0f) | (((Q & 0x0f) as u8) << 4);
    bad[i + 2] = (Q >> 4) as u8;
    assert_eq!(encapsulate(&bad).unwrap_err(), KemError::BadKey);
    // rho (the last 32 bytes) is unconstrained.
    let mut ok = *kp.public();
    ok[KEM_PK_LEN - 1] ^= 0xff;
    assert!(encapsulate(&ok).is_ok());
}

#[test]
fn tampered_ct_gives_different_secret() {
    let kp = KemKeyPair::generate();
    let (mut ct, ss) = encapsulate(kp.public()).unwrap();
    ct[100] ^= 0x01;
    let ss2 = kp
        .decapsulate(&ct)
        .expect("implicit rejection, not an error");
    assert_ne!(*ss, *ss2);
    // Implicit rejection is deterministic for the same key and ciphertext.
    assert_eq!(*ss2, *kp.decapsulate(&ct).unwrap());
}

#[test]
fn nist_kat() {
    let mut keygen = 0;
    let mut encap = 0;
    let mut decap = 0;
    let mut decap_key: Option<KemKeyPair> = None;
    for rec in kat_records() {
        match field(&rec, "kind") {
            "keygen" => {
                let mut seed = [0u8; 64];
                seed[..32].copy_from_slice(&arr::<32>(field(&rec, "d")));
                seed[32..].copy_from_slice(&arr::<32>(field(&rec, "z")));
                let kp = KemKeyPair::from_seed(&seed);
                assert_eq!(kp.public()[..], unhex(field(&rec, "ek"))[..], "keygen ek");
                assert_eq!(
                    kp.secret_bytes()[..],
                    unhex(field(&rec, "dk"))[..],
                    "keygen dk"
                );
                keygen += 1;
            }
            "encap" => {
                let (ct, ss) =
                    encapsulate_deterministic(&unhex(field(&rec, "ek")), &arr(field(&rec, "m")))
                        .unwrap();
                assert_eq!(ct[..], unhex(field(&rec, "c"))[..], "encap c");
                assert_eq!(ss[..], unhex(field(&rec, "k"))[..], "encap k");
                encap += 1;
            }
            "decap-key" => {
                decap_key = Some(KemKeyPair::from_raw(
                    [0u8; KEM_PK_LEN],
                    arr(field(&rec, "dk")),
                ));
            }
            "decap" => {
                let kp = decap_key.as_ref().expect("decap-key precedes decap");
                let ss = kp.decapsulate(&unhex(field(&rec, "c"))).unwrap();
                assert_eq!(ss[..], unhex(field(&rec, "k"))[..], "decap k");
                decap += 1;
            }
            other => panic!("unknown KAT kind {other}"),
        }
    }
    assert_eq!((keygen, encap, decap), (5, 5, 10));
}

#[test]
fn secret_is_zeroized_on_drop() {
    // The types that hold secrets wipe themselves.
    fn is_zeroizing<T: zeroize::Zeroize>(_: &Zeroizing<T>) {}
    fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroize_on_drop::<Dk>(); // needs ml-kem's `zeroize` feature

    let kp = KemKeyPair::from_seed(&[9u8; 64]);
    is_zeroizing(&kp.secret);
    let (ct, ss) = encapsulate(kp.public()).unwrap();
    is_zeroizing(&ss);
    is_zeroizing(&kp.decapsulate(&ct).unwrap());
    drop(kp);

    // Drop probe: the heap secret is wiped before it is freed. Positive
    // control first: an unwiped copy of the same bytes is caught.
    let kp = KemKeyPair::from_seed(&[9u8; 64]);
    let needle: [u8; 32] = kp.secret_bytes()[..32].try_into().unwrap();
    let raw = Box::new(*kp.secret_bytes());
    assert!(crate::alloc_probe::freed_containing(needle, || drop(raw)) >= 1);
    // A move copies only the pointer: the secret's heap address is stable.
    let addr = kp.secret_bytes().as_ptr();
    let moved = Box::new(kp);
    assert_eq!(moved.secret_bytes().as_ptr(), addr);
    assert_eq!(
        crate::alloc_probe::freed_containing(needle, || drop(moved)),
        0,
        "secret freed unwiped"
    );
}

#[test]
fn generate_with_seed_rebuilds() {
    let (kp, seed) = KemKeyPair::generate_with_seed();
    let again = KemKeyPair::from_seed(&seed);
    assert_eq!(kp.public(), again.public());
    assert_eq!(kp.secret_bytes(), again.secret_bytes());
    let (ct, ss) = encapsulate(kp.public()).unwrap();
    assert_eq!(*ss, *again.decapsulate(&ct).unwrap());
    let (other, other_seed) = KemKeyPair::generate_with_seed();
    assert_ne!(*seed, *other_seed);
    assert_ne!(kp.public(), other.public());
}

#[test]
fn validate_public_key_checks_length_and_modulus() {
    let kp = KemKeyPair::generate();
    assert_eq!(validate_public_key(kp.public()), Ok(()));
    assert_eq!(
        validate_public_key(&kp.public()[..KEM_PK_LEN - 1]),
        Err(KemError::BadLength)
    );
    assert_eq!(validate_public_key(&[]), Err(KemError::BadLength));
    let mut bad = *kp.public();
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(validate_public_key(&bad), Err(KemError::BadKey));
}

/// Sets coefficient 0 of `t` (bytes 0 and the low nibble of byte 1).
fn set_coeff0(pk: &mut [u8; KEM_PK_LEN], c: u16) {
    pk[0] = (c & 0xff) as u8;
    pk[1] = (pk[1] & 0xf0) | ((c >> 8) as u8 & 0x0f);
}

#[test]
fn modulus_boundary() {
    let kp = KemKeyPair::from_seed(&[4u8; 64]);
    let mut edge = *kp.public();
    set_coeff0(&mut edge, Q - 1); // 3328 is the largest canonical value
    assert_eq!(validate_public_key(&edge), Ok(()));
    assert!(encapsulate(&edge).is_ok());
    set_coeff0(&mut edge, Q); // 3329 is not
    assert_eq!(validate_public_key(&edge), Err(KemError::BadKey));
    assert_eq!(encapsulate(&edge).unwrap_err(), KemError::BadKey);
}

/// Only `src/kem.rs` and its tests may name the ML-KEM crate, so every use
/// goes through this module's checks.
#[test]
fn only_kem_module_names_the_crate() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    assert!(files.len() > 20, "scan found the sources");
    let needle = concat!("ml", "_kem");
    let mut offenders: Vec<String> = files
        .iter()
        .filter(|p| std::fs::read_to_string(p).unwrap().contains(needle))
        .map(|p| {
            p.strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|p| p != "kem.rs" && p != "kem/tests.rs")
        .collect();
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "files naming the ML-KEM crate: {offenders:?}"
    );
}

#[test]
fn debug_redacts_secret() {
    let kp = KemKeyPair::from_seed(&[5u8; 64]);
    let s = format!("{kp:?}");
    assert!(s.contains("[redacted]"));
    assert!(!s.contains(&hex::encode(&kp.public()[..8])));
    assert!(!s.contains(&hex::encode(&kp.secret_bytes()[..8])));
}
