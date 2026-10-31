//! Trust roots for BoringSSL on Android (Android sub-project 1, spec §6).
//!
//! BoringSSL's `set_default_verify_paths` looks in OpenSSL's build-time
//! directories, which Android doesn't have, so without this every `wss://`
//! relay fails verification there. Android 14+ keeps the system CA
//! certificates in the Conscrypt APEX, one PEM certificate per file
//! followed by a text dump; older releases use `/system/etc/security/cacerts`.
//! User-installed CAs are not trusted, as for any app targeting API 24+;
//! system CAs the user disabled (`cacerts-removed`) are left out.

use boring::x509::store::X509Store;
#[cfg(any(target_os = "android", test))]
use std::path::Path;

/// Where Android keeps the system CA certificates, preferred first.
#[cfg(target_os = "android")]
pub(crate) const ANDROID_CA_DIRS: [&str; 2] = [
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
];

/// Largest CA file read; a real one is under 10 KiB.
#[cfg(any(target_os = "android", test))]
pub(crate) const MAX_CA_FILE_BYTES: u64 = 64 * 1024;

/// Where Android lists the system CAs the user `uid` runs as has disabled:
/// one file per disabled certificate, named like the system file. The
/// Android user number is the uid divided by 100000 (user 0 is the owner;
/// a secondary user or work profile has its own directory).
#[cfg(any(target_os = "android", test))]
fn removed_ca_dir_for_uid(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/data/misc/user/{}/cacerts-removed", uid / 100_000))
}

/// The certificates in `dir`, minus any whose file name is in `removed`
/// (a missing or unreadable `removed` excludes nothing). Files that aren't
/// PEM certificates, directories and files over the cap are skipped; the
/// cap is enforced on the read itself, not on a prior stat.
#[cfg(any(target_os = "android", test))]
fn certs_in(dir: &Path, removed: &Path) -> Vec<boring::x509::X509> {
    use std::io::Read;
    let removed: std::collections::HashSet<std::ffi::OsString> = std::fs::read_dir(removed)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut certs = Vec::new();
    for entry in entries.flatten() {
        if removed.contains(&entry.file_name()) {
            continue;
        }
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_CA_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_CA_FILE_BYTES
        {
            continue;
        }
        if let Ok(cert) = boring::x509::X509::from_pem(&bytes) {
            certs.push(cert);
        }
    }
    certs
}

/// A fresh store holding `certs`; None when it would be empty.
#[cfg(any(target_os = "android", test))]
fn store_from_certs(certs: &[boring::x509::X509]) -> Option<X509Store> {
    let mut builder = boring::x509::store::X509StoreBuilder::new().ok()?;
    let mut added = 0usize;
    for cert in certs {
        if builder.add_cert(cert.clone()).is_ok() {
            added += 1;
        }
    }
    (added > 0).then(|| builder.build())
}

/// A store holding every certificate in `dir` except those named in
/// `removed_dir`, and how many were added. None when nothing was added.
#[cfg(test)]
pub(crate) fn store_from_dir_excluding(
    dir: &Path,
    removed_dir: &Path,
) -> Option<(X509Store, usize)> {
    let certs = certs_in(dir, removed_dir);
    store_from_certs(&certs).map(|store| (store, certs.len()))
}

/// `store_from_dir_excluding` with nothing removed.
#[cfg(test)]
pub(crate) fn store_from_dir(dir: &Path) -> Option<(X509Store, usize)> {
    store_from_dir_excluding(dir, Path::new("/nonexistent-rchat-removed"))
}

/// The system CAs read once and kept; an empty result is never kept, so a
/// store that wasn't readable yet is tried again on the next connection.
#[cfg(target_os = "android")]
static SYSTEM_CERTS: std::sync::Mutex<Vec<boring::x509::X509>> = std::sync::Mutex::new(Vec::new());

/// The platform's trust roots where BoringSSL can't find them itself:
/// Android's system CA store without the CAs the user disabled. None when
/// nothing could be read; the caller then installs an empty store, so every
/// handshake fails closed.
#[cfg(target_os = "android")]
pub(crate) fn platform_store() -> Option<X509Store> {
    let mut cached = SYSTEM_CERTS.lock().unwrap_or_else(|p| p.into_inner());
    if cached.is_empty() {
        // SAFETY: getuid has no preconditions and cannot fail.
        let removed = removed_ca_dir_for_uid(unsafe { libc::getuid() });
        *cached = ANDROID_CA_DIRS
            .iter()
            .map(|d| certs_in(Path::new(d), &removed))
            .find(|c| !c.is_empty())
            .unwrap_or_default();
    }
    store_from_certs(&cached)
}

/// Forgets the system CAs read so far, so the next connection reads the
/// store again: a CA the user disabled in Settings since then stops being
/// trusted without a restart (the app calls this when it comes to the
/// foreground). Elsewhere nothing is kept, so there is nothing to forget.
pub(crate) fn forget_platform_store() {
    #[cfg(target_os = "android")]
    SYSTEM_CERTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
}

/// Elsewhere BoringSSL's default paths are used (None).
#[cfg(not(target_os = "android"))]
#[cfg_attr(target_os = "ios", allow(dead_code))]
pub(crate) fn platform_store() -> Option<X509Store> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Foreground refresh: forgetting the roots is always allowed and leaves the next read to fetch them again.
    #[test]
    fn refreshing_the_trust_store_is_harmless() {
        assert_eq!(crate::ffi::rchat_refresh_trust_store(), 0);
        assert_eq!(crate::ffi::rchat_refresh_trust_store(), 0);
    }
    use crate::tls_boring::{connect_resumable_with, TlsFingerprint};
    use crate::tls_resumption::test_server::TestTlsServer;
    use crate::tls_resumption::ResumptionStore;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("rchat-roots-{tag}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Android's CA files: one PEM certificate, then a text dump.
    fn android_format(pem: &[u8]) -> Vec<u8> {
        let mut v = pem.to_vec();
        v.extend_from_slice(b"Certificate:\n    Data:\n        Version: 3 (0x2)\n");
        v
    }

    #[tokio::test]
    async fn reads_android_format_and_skips_junk() {
        let server = TestTlsServer::start(true, false).await;
        let dir = temp_dir("junk");
        std::fs::write(dir.join("1a2b3c4d.0"), android_format(&server.cert_pem())).unwrap();
        std::fs::write(dir.join("README"), b"not a certificate").unwrap();
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        let (_, added) = store_from_dir(&dir).expect("one certificate");
        assert_eq!(added, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_or_missing_dir_gives_none() {
        let dir = temp_dir("empty");
        assert!(store_from_dir(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(store_from_dir(&dir).is_none());
    }

    #[tokio::test]
    async fn oversized_file_is_skipped() {
        let server = TestTlsServer::start(true, false).await;
        let dir = temp_dir("big");
        let mut big = android_format(&server.cert_pem());
        big.resize(MAX_CA_FILE_BYTES as usize + 1, b' ');
        std::fs::write(dir.join("ffffffff.0"), big).unwrap();
        assert!(store_from_dir(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn handshake_verifies_against_a_store_read_from_disk() {
        let server = TestTlsServer::start(true, false).await;
        let dir = temp_dir("hs");
        std::fs::write(dir.join("0a0b0c0d.0"), android_format(&server.cert_pem())).unwrap();
        let (store, _) = store_from_dir(&dir).unwrap();
        let rs = ResumptionStore::new();
        rs.bind(crate::tls_resumption::RelayKey {
            host: "localhost".into(),
            port: server.port(),
            pin: Some("rk:1:a".into()),
        });
        let tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let tls = connect_resumable_with(
            tcp,
            "localhost",
            server.port(),
            TlsFingerprint::Chrome,
            &rs,
            Some(store),
        )
        .await;
        assert!(tls.is_ok(), "the CA read from disk verifies the server");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn handshake_fails_against_a_store_without_the_cert() {
        let server = TestTlsServer::start(true, false).await;
        let other = TestTlsServer::start(true, false).await;
        let dir = temp_dir("other");
        std::fs::write(dir.join("0a0b0c0d.0"), android_format(&other.cert_pem())).unwrap();
        let (store, _) = store_from_dir(&dir).unwrap();
        let rs = ResumptionStore::new();
        rs.bind(crate::tls_resumption::RelayKey {
            host: "localhost".into(),
            port: server.port(),
            pin: Some("rk:1:a".into()),
        });
        let tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let tls = connect_resumable_with(
            tcp,
            "localhost",
            server.port(),
            TlsFingerprint::Chrome,
            &rs,
            Some(store),
        )
        .await;
        assert!(tls.is_err(), "an unknown CA is refused");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_removed_ca_directory_is_the_current_users() {
        use std::path::Path;
        let dir = |uid| removed_ca_dir_for_uid(uid);
        assert_eq!(dir(10_234), Path::new("/data/misc/user/0/cacerts-removed"));
        assert_eq!(dir(0), Path::new("/data/misc/user/0/cacerts-removed"));
        assert_eq!(
            dir(1_010_234),
            Path::new("/data/misc/user/10/cacerts-removed")
        );
        assert_eq!(
            dir(1_099_999),
            Path::new("/data/misc/user/10/cacerts-removed")
        );
        assert_eq!(
            dir(2_000_000),
            Path::new("/data/misc/user/20/cacerts-removed")
        );
    }

    #[test]
    fn platform_store_is_none_off_android() {
        assert!(platform_store().is_none());
    }

    #[tokio::test]
    async fn a_ca_the_user_disabled_is_excluded_and_the_handshake_fails() {
        let server = TestTlsServer::start(true, false).await;
        let dir = temp_dir("sys");
        let removed = temp_dir("removed");
        std::fs::write(dir.join("0a0b0c0d.0"), android_format(&server.cert_pem())).unwrap();
        assert!(store_from_dir_excluding(&dir, &removed).is_some());
        std::fs::write(removed.join("0a0b0c0d.0"), b"").unwrap();
        assert!(store_from_dir_excluding(&dir, &removed).is_none());
        // A second CA stays; the server's is still refused.
        let other = TestTlsServer::start(true, false).await;
        std::fs::write(dir.join("11111111.0"), android_format(&other.cert_pem())).unwrap();
        let (store, added) = store_from_dir_excluding(&dir, &removed).unwrap();
        assert_eq!(added, 1);
        let rs = ResumptionStore::new();
        rs.bind(crate::tls_resumption::RelayKey {
            host: "localhost".into(),
            port: server.port(),
            pin: Some("rk:1:a".into()),
        });
        let tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let tls = connect_resumable_with(
            tcp,
            "localhost",
            server.port(),
            TlsFingerprint::Chrome,
            &rs,
            Some(store),
        )
        .await;
        assert!(tls.is_err(), "a disabled CA is not trusted");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&removed).unwrap();
    }
}
