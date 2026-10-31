//! Parity guard (Android sub-project 1, spec §6): every JNI export maps to
//! the C FFI function `JNI_TO_FFI` names, every such function exists, every
//! Kotlin `external fun` has an export with the same JNI signature, the
//! Kotlin error enum mirrors `ffi.rs`'s table and the event kinds match.

use std::collections::{BTreeMap, BTreeSet};

const JNI_RS: &str = include_str!("jni.rs");
const FFI_RS: &str = include_str!("ffi.rs");
const KT_CORE: &str =
    include_str!("../../../android/app/src/main/java/net/rchat/client/core/RChatCore.kt");
const KT_ERRORS: &str =
    include_str!("../../../android/app/src/main/java/net/rchat/client/core/CoreError.kt");
const KT_KINDS: &str =
    include_str!("../../../android/app/src/main/java/net/rchat/client/core/CoreEventKind.kt");

const EXPORT_PREFIX: &str = "fn Java_net_rchat_client_core_RChatCore_";

fn ident_at(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Each export: name → (parameter types after env/class, return type, body).
fn exports() -> BTreeMap<String, (Vec<String>, String, String)> {
    let mut out = BTreeMap::new();
    let mut rest = JNI_RS;
    while let Some(i) = rest.find(EXPORT_PREFIX) {
        let after = &rest[i + EXPORT_PREFIX.len()..];
        let name = ident_at(after);
        let open = after.find('(').unwrap();
        let close = after.find(')').unwrap();
        let params: Vec<String> = after[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.split(':').nth(1).unwrap().trim().to_string())
            .collect();
        let sig_end = after.find('{').unwrap();
        let ret = after[close + 1..sig_end]
            .trim()
            .trim_start_matches("->")
            .trim()
            .to_string();
        let body_end = after[sig_end..]
            .find("\n    }\n")
            .map(|e| sig_end + e)
            .unwrap_or(after.len());
        let dup = out.insert(
            name.clone(),
            (params, ret, after[sig_end..body_end].to_string()),
        );
        assert!(dup.is_none(), "duplicate export {name}");
        rest = &after[sig_end..];
    }
    out
}

/// Each Kotlin `external fun`: name → (parameter types, return type).
fn kotlin_externals() -> BTreeMap<String, (Vec<String>, String)> {
    let mut out = BTreeMap::new();
    for line in KT_CORE.lines() {
        let Some(i) = line.find("external fun ") else {
            continue;
        };
        let after = &line[i + "external fun ".len()..];
        let name = ident_at(after);
        let open = after.find('(').unwrap();
        let close = after.rfind(')').unwrap();
        let params: Vec<String> = after[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.split(':').nth(1).unwrap().trim().to_string())
            .collect();
        let ret = after[close + 1..]
            .trim()
            .trim_start_matches(':')
            .trim()
            .to_string();
        let dup = out.insert(name.clone(), (params, ret));
        assert!(
            dup.is_none(),
            "{name}: overloaded external fun (JNI mangling would differ)"
        );
    }
    out
}

/// `func` is defined in `ffi.rs` with `#[no_mangle]` among the three lines
/// above it (a `#[cfg(feature = …)]` may sit between them).
fn is_exported(ffi: &str, func: &str) -> bool {
    let def = ffi
        .find(&format!("pub unsafe extern \"C\" fn {func}("))
        .or_else(|| ffi.find(&format!("pub extern \"C\" fn {func}(")));
    let Some(at) = def else { return false };
    let before: Vec<&str> = ffi[..at].lines().rev().take(3).map(str::trim).collect();
    before.contains(&"#[no_mangle]")
}

fn jni_type(kotlin: &str) -> &'static str {
    match kotlin {
        "String" | "String?" => "jstring",
        "ByteArray" | "ByteArray?" => "jbyteArray",
        "IntArray" => "jintArray",
        "ShortArray" => "jshortArray",
        "Array<String?>" => "jobjectArray",
        "Boolean" => "jboolean",
        "Int" => "jint",
        "Long" => "jlong",
        "ByteBuffer" => "jobject",
        "CoreEventHandler" | "CoreEventHandler?" => "jobject",
        other => panic!("unmapped Kotlin type {other}"),
    }
}

#[test]
fn table_exports_and_kotlin_agree() {
    let table: BTreeMap<&str, &str> = crate::jni::JNI_TO_FFI.iter().copied().collect();
    assert_eq!(
        table.len(),
        crate::jni::JNI_TO_FFI.len(),
        "duplicate JNI name in JNI_TO_FFI"
    );
    let exports = exports();
    let kotlin = kotlin_externals();
    let t: BTreeSet<&str> = table.keys().copied().collect();
    let e: BTreeSet<&str> = exports.keys().map(String::as_str).collect();
    let k: BTreeSet<&str> = kotlin.keys().map(String::as_str).collect();
    assert_eq!(t, e, "JNI_TO_FFI vs exports");
    assert_eq!(t, k, "JNI_TO_FFI vs RChatCore.kt");
    let external_lines = KT_CORE
        .lines()
        .filter(|l| l.contains("external fun "))
        .count();
    assert_eq!(
        external_lines,
        kotlin.len(),
        "overloaded or repeated external fun"
    );
    assert_eq!(t.len(), 84);
}

#[test]
fn every_export_calls_exactly_its_c_function() {
    for (name, (_, _, body)) in exports() {
        let called: BTreeSet<String> = body
            .match_indices("rchat_")
            .map(|(i, _)| ident_at(&body[i..]))
            .filter(|f| f != "rchat_free_string")
            .collect();
        let want = crate::jni::JNI_TO_FFI
            .iter()
            .find(|(j, _)| *j == name)
            .unwrap()
            .1;
        assert_eq!(
            called,
            BTreeSet::from([want.to_string()]),
            "{name} must call {want} only"
        );
        assert!(
            is_exported(FFI_RS, want),
            "{want} is a #[no_mangle] C function in ffi.rs"
        );
    }
}

#[test]
fn every_export_takes_env_and_class_and_matches_kotlin_types() {
    let kotlin = kotlin_externals();
    for (name, (params, ret, _)) in exports() {
        assert!(params.len() >= 2, "{name}: env and class first");
        assert_eq!(params[0], "Env", "{name}: first parameter is the JNIEnv");
        assert_eq!(
            params[1], "jclass",
            "{name}: second parameter is the class/object"
        );
        let (kparams, kret) = &kotlin[&name];
        let want: Vec<&str> = kparams.iter().map(|p| jni_type(p)).collect();
        let got: Vec<&str> = params[2..].iter().map(String::as_str).collect();
        assert_eq!(got, want, "{name}: JNI parameter types");
        assert_eq!(ret.as_str(), jni_type(kret), "{name}: return type");
        if ret == "jstring" {
            assert_eq!(
                kret, "String?",
                "{name}: a jstring return is a nullable String"
            );
        }
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric()),
            "{name}: no '_' (JNI mangling)"
        );
    }
}

#[test]
fn kotlin_error_enum_mirrors_the_ffi_table() {
    let table_start = FFI_RS.find("/// Error codes:").unwrap();
    let ffi_codes: BTreeSet<i32> = FFI_RS[table_start..]
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("/// "))
        .filter_map(|l| {
            l.trim_start_matches("/// ")
                .split(" = ")
                .next()?
                .trim()
                .parse()
                .ok()
        })
        .collect();
    let kt_codes: BTreeSet<i32> = KT_ERRORS
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let open = l.find('(')?;
            let close = l.find(')')?;
            if !l[..open]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_')
                || open == 0
            {
                return None;
            }
            l[open + 1..close].parse().ok()
        })
        .collect();
    assert_eq!(
        ffi_codes,
        (0..=36).collect::<BTreeSet<_>>(),
        "ffi.rs documents 0..=36"
    );
    assert_eq!(kt_codes, ffi_codes, "CoreError.kt mirrors ffi.rs");
}

/// Kotlin name, code, and the `RChatError` variants `error_code_from_err`
/// maps to that code (none: the code is raised directly by `ffi.rs`).
const ERROR_NAMES: &[(&str, i32, &[&str])] = &[
    ("SUCCESS", 0, &[]),
    ("INVALID_CONFIG", 1, &[]),
    ("NETWORK_UNREACHABLE", 2, &["ConnectionFailed"]),
    ("AUTHENTICATION_FAILED", 3, &[]),
    ("INVALID_RECIPIENT", 4, &["InvalidRecipient"]),
    ("SESSION_NOT_ESTABLISHED", 5, &["SessionNotEstablished"]),
    ("ALREADY_CONNECTED", 6, &[]),
    ("NOT_CONNECTED", 7, &["NotConnected"]),
    (
        "INTERNAL",
        8,
        &[
            "EncryptionFailed",
            "DecryptionFailed",
            "MessageTimeout",
            "Internal",
        ],
    ),
    (
        "INVALID_PARAMETER",
        9,
        &["InvalidParameter", "InvalidSafetyNumber"],
    ),
    ("PEER_KEY_REJECTED", 10, &["PeerKeyRejected"]),
    ("PEER_KEY_UNVERIFIED", 11, &["PeerKeyUnverified"]),
    ("PEER_NOT_ACCEPTED", 12, &["PeerNotAccepted"]),
    ("PEER_BLOCKED", 13, &["PeerBlocked"]),
    ("KEY_AUTH_REJECTED", 14, &["KeyAuthRejected"]),
    ("SERVER_TOO_NEW", 15, &["ServerTooNew"]),
    ("NO_CHANNEL_BINDING", 16, &["NoChannelBinding"]),
    ("PIN_CONFLICT", 17, &["PinConflict"]),
    ("AGREEMENT_KEY_IN_USE", 18, &["AgreementKeyInUse"]),
    ("NO_PINNED_KEYS", 19, &["NoPinnedKeys"]),
    ("SAFETY_NUMBER_CHANGED", 20, &["SafetyNumberChanged"]),
    ("RELAY_IDENTITY_INVALID", 21, &["RelayIdentityInvalid"]),
    ("RELAY_PIN_REQUIRED", 22, &["RelayPinRequired"]),
    ("RELAY_IDENTITY_CHANGED", 23, &["RelayIdentityChanged"]),
    ("ROTATION_TOO_SOON", 24, &["RotationTooSoon"]),
    ("STATE_PERSIST_FAILED", 25, &["StatePersistFailed"]),
    ("RESEND_REFUSED", 26, &["ResendRefused"]),
    ("NO_KEM_KEY", 27, &["NoKemKey"]),
    ("FILE_TOO_LARGE", 28, &["FileTooLarge"]),
    ("FOREGROUND_CONNECTED", 29, &["ForegroundConnected"]),
    ("FILE_BLOCKED", 30, &["FileBlocked"]),
    ("RELAY_NO_CALLS", 31, &["RelayNoCalls"]),
    ("CALL_IN_PROGRESS", 32, &["CallInProgress"]),
    ("NO_SUCH_CALL", 33, &["NoSuchCall"]),
    ("VIDEO_UNAVAILABLE", 34, &["VideoUnavailable"]),
    ("RELAY_NO_VIDEO", 35, &["RelayNoVideo"]),
    ("VIDEO_TOO_SOON", 36, &["VideoTooSoon"]),
];

#[test]
fn kotlin_error_names_match_codes_and_error_mapping() {
    // Kotlin (name, code) pairs, no duplicates of either.
    let mut kt: Vec<(String, i32)> = Vec::new();
    for l in KT_ERRORS.lines() {
        let l = l.trim();
        let (Some(open), Some(close)) = (l.find('('), l.find(')')) else {
            continue;
        };
        let name = &l[..open];
        if open == 0 || !name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }
        if let Ok(code) = l[open + 1..close].parse() {
            kt.push((name.to_string(), code));
        }
    }
    let names: BTreeSet<&str> = kt.iter().map(|(n, _)| n.as_str()).collect();
    let codes: BTreeSet<i32> = kt.iter().map(|(_, c)| *c).collect();
    assert_eq!(names.len(), kt.len(), "duplicate CoreError name");
    assert_eq!(codes.len(), kt.len(), "duplicate CoreError code");
    let want: Vec<(String, i32)> = ERROR_NAMES
        .iter()
        .map(|(n, c, _)| (n.to_string(), *c))
        .collect();
    assert_eq!(kt, want, "CoreError.kt (name, code) pairs");

    // `error_code_from_err`: every arm is accounted for, with the same code.
    let start = FFI_RS.find("fn error_code_from_err(").unwrap();
    let body = &FFI_RS[start..start + FFI_RS[start..].find("\n}\n").unwrap()];
    let mut arms: BTreeMap<String, i32> = BTreeMap::new();
    for l in body.lines() {
        let l = l.trim();
        let Some(rest) = l.strip_prefix("RChatError::") else {
            continue;
        };
        let (variant, code) = rest.split_once("=>").expect("one arm per line");
        arms.insert(
            ident_at(variant),
            code.trim()
                .trim_end_matches(',')
                .parse()
                .expect("numeric code"),
        );
    }
    let mut listed: BTreeMap<String, i32> = BTreeMap::new();
    for (_, code, variants) in ERROR_NAMES {
        for v in *variants {
            assert!(
                listed.insert(v.to_string(), *code).is_none(),
                "{v} listed twice"
            );
        }
    }
    assert_eq!(arms, listed, "error_code_from_err vs the Kotlin names");
}

fn jvm_type(kotlin: &str) -> &'static str {
    match kotlin {
        "Int" => "I",
        "String" => "Ljava/lang/String;",
        "ByteArray" | "ByteArray?" => "[B",
        "Unit" => "V",
        other => panic!("unmapped Kotlin handler type {other}"),
    }
}

/// The `CoreEventHandler` methods the Rust trampolines look up by name and
/// descriptor must exist in Kotlin with exactly those descriptors.
#[test]
fn handler_descriptors_match_kotlin_interface() {
    let start = KT_CORE.find("interface CoreEventHandler {").unwrap();
    let body = &KT_CORE[start..start + KT_CORE[start..].find("\n}\n").unwrap()];
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for l in body.lines() {
        let Some(i) = l.find("    fun ") else {
            continue;
        };
        let after = &l[i + "    fun ".len()..];
        let name = ident_at(after);
        let open = after.find('(').unwrap();
        let close = after.rfind(')').unwrap();
        let params: String = after[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| jvm_type(p.split(':').nth(1).unwrap().trim()))
            .collect();
        let ret = after[close + 1..].trim().trim_start_matches(':').trim();
        let ret = if ret.is_empty() { "Unit" } else { ret };
        found.insert((name, format!("({params}){}", jvm_type(ret))));
    }
    assert_eq!(found.len(), 3, "CoreEventHandler has exactly 3 methods");
    let want: BTreeSet<(String, String)> = crate::jni::HANDLER_METHODS
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect();
    assert_eq!(
        found, want,
        "CoreEventHandler vs the trampolines' descriptors"
    );
}

#[test]
fn event_kinds_match() {
    use crate::jni::kind;
    let rust: BTreeMap<&str, i32> = BTreeMap::from([
        ("MESSAGE", kind::MESSAGE),
        ("STATE", kind::STATE),
        ("ERROR", kind::ERROR),
        ("CIRCUIT_ESTABLISHED", kind::CIRCUIT_ESTABLISHED),
        ("MESSAGE_DELIVERED", kind::MESSAGE_DELIVERED),
        ("RECONNECT", kind::RECONNECT),
        ("PEER_KEY", kind::PEER_KEY),
        ("MESSAGE_REQUEST", kind::MESSAGE_REQUEST),
        ("MESSAGE_RECEIPT", kind::MESSAGE_RECEIPT),
        ("PEER_ROTATED", kind::PEER_ROTATED),
        ("STATUS", kind::STATUS),
        ("FILE", kind::FILE),
        ("TIMER_CHANGED", kind::TIMER_CHANGED),
        ("FILE_BLOCKED", kind::FILE_BLOCKED),
    ]);
    let kt: BTreeMap<String, i32> = KT_KINDS
        .lines()
        .filter_map(|l| {
            let l = l.trim().strip_prefix("const val ")?;
            let (name, value) = l.split_once('=')?;
            Some((name.trim().to_string(), value.trim().parse().ok()?))
        })
        .collect();
    let kt: BTreeMap<&str, i32> = kt.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    assert_eq!(kt, rust);
}
