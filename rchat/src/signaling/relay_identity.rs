//! The relay's long-term identity (spec §4.9): an Ed25519 key separate from
//! TLS, pinned by clients. PRIVACY: the pin is public; the seed is never logged.

use crate::protocol::signaling::{RelayIdentityInfo, RelayLinkInfo};
use anyhow::{bail, Context};
use ed25519_dalek::SigningKey;
use rchat_core::relay_pin::{self, RelayLink, MAX_RELAY_CHAIN};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) struct RelayIdentity {
    signing: SigningKey,
    version: u32,
    pub(crate) chain: Vec<RelayLink>,
}

#[derive(Serialize, Deserialize, Default)]
struct ChainFile {
    version: u32,
    links: Vec<RelayLinkInfo>,
}

pub(crate) fn chain_path(key_path: &Path) -> PathBuf {
    key_path.with_file_name("relay_identity.chain")
}

/// The chain as it was before the last rotation (recovery copy).
fn chain_prev_path(key_path: &Path) -> PathBuf {
    key_path.with_file_name("relay_identity.chain.prev")
}

fn link_info(l: &RelayLink) -> RelayLinkInfo {
    RelayLinkInfo {
        prev_key: hex::encode(l.prev_key),
        new_key: hex::encode(l.new_key),
        version: l.version,
        signature: hex::encode(l.signature),
    }
}

fn link_from_info(i: &RelayLinkInfo) -> anyhow::Result<RelayLink> {
    let key = |s: &str| -> anyhow::Result<[u8; 32]> {
        hex::decode(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad key length"))
    };
    let sig: [u8; 64] = hex::decode(&i.signature)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad signature length"))?;
    Ok(RelayLink {
        prev_key: key(&i.prev_key)?,
        new_key: key(&i.new_key)?,
        version: i.version,
        signature: sig,
    })
}

fn random_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).expect("OS randomness unavailable");
    seed
}

/// Write `bytes` to `path` with `mode`, atomically (temp + rename, then a
/// directory fsync so the replacement is durable before the caller goes on).
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let tmp = fresh_temp(path, bytes, mode)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot replace {}", path.display()));
    }
    sync_parent(path)
}

/// A new temp file next to `path` holding `bytes` (fsynced). Its name is
/// unique to this call and it is opened with `create_new`, so a stale or
/// concurrent temp file (perhaps with a broader mode) is never reused.
fn fresh_temp(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<PathBuf> {
    let mut tmp_name = path
        .file_name()
        .context("path has no file name")?
        .to_os_string();
    tmp_name.push(format!(
        ".{}.{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let tmp = path.with_file_name(tmp_name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot write {}", tmp.display()));
    }
    Ok(tmp)
}

/// Make a rename/link in `path`'s directory durable before the next step
/// (POSIX does not order the durability of renames otherwise).
fn sync_parent(path: &Path) -> anyhow::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("cannot sync directory {}", dir.display()))
}

/// Replace a secret with mode 0600.
fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_atomic(path, bytes, 0o600)
}

/// Create a new secret at `path` (mode 0600) without ever replacing one:
/// `hard_link` fails with `AlreadyExists` if `path` appeared meanwhile, so
/// concurrent creators cannot each install (and print) a different key.
fn create_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = fresh_temp(path, bytes, 0o600).map_err(std::io::Error::other)?;
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    linked?;
    sync_parent(path).map_err(std::io::Error::other)
}

/// Open an existing key file without following a symlink (R-16).
fn open_key(path: &Path, write: bool) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {} (symlinks are refused)", path.display()))
}

/// Overwrite an open key file's contents with zeros and make that durable.
/// Called on the old seed's inode after rotation renamed the new key over
/// its path. Best effort on SSDs and copy-on-write filesystems, where the
/// old blocks may survive below the filesystem.
fn wipe_open_key(mut file: std::fs::File) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 64];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    file.sync_all()?;
    Ok(())
}

/// A temp file this old was left by a write that never finished.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// Zero-fill and remove temp files an interrupted write left next to `path`
/// (Task 10b minor: they may hold a seed). Only names `fresh_temp` makes
/// (`<name>.<pid>.<16 hex>.tmp`), only regular files never reached through
/// a symlink, and only ones older than `min_age`, so a write in progress
/// in another process is left alone. Best effort: errors are ignored.
fn sweep_stale_temps(path: &Path, min_age: std::time::Duration) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let n = file_name.to_string_lossy();
        let Some(rest) = n.strip_prefix(&prefix).and_then(|r| r.strip_suffix(".tmp")) else {
            continue;
        };
        let ours = rest.split_once('.').is_some_and(|(pid, rand)| {
            !pid.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && rand.len() == 16
                && rand.bytes().all(|b| b.is_ascii_hexdigit())
        });
        if !ours {
            continue;
        }
        let tmp = entry.path();
        let old_enough = std::fs::symlink_metadata(&tmp).is_ok_and(|m| {
            m.file_type().is_file()
                && m.modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age >= min_age)
        });
        if !old_enough {
            continue;
        }
        if let Ok(f) = open_key(&tmp, true) {
            let _ = wipe_open_key(f);
        }
        let _ = std::fs::remove_file(&tmp);
    }
}

fn read_seed(path: &Path) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    use std::io::Read;
    // Every check is made on the opened file (fstat), never on the path, so
    // a swap between the check and the read cannot load another file (R-16).
    let mut file = open_key(path, false)?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("{} must be a regular file", path.display());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} must be mode 0600 (it is {:o})",
            path.display(),
            meta.permissions().mode() & 0o777
        );
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        bail!(
            "{} must be owned by the service user (uid {euid})",
            path.display()
        );
    }
    // Read at most one byte past a seed, so a wrong length is detected
    // without reading an arbitrarily large file.
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    (&mut file).take(33).read_to_end(&mut bytes)?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must hold exactly 32 bytes", path.display()))?;
    Ok(Zeroizing::new(seed))
}

impl RelayIdentity {
    /// An in-memory identity (tests; `RelayState::new`).
    pub(crate) fn ephemeral() -> Self {
        Self {
            signing: SigningKey::from_bytes(&random_seed()),
            version: 0,
            chain: Vec::new(),
        }
    }

    /// Load the key (and chain), or create a new key on first start.
    pub(crate) fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        sweep_stale_temps(path, STALE_TEMP_AGE);
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            match create_secret(path, random_seed().as_slice()) {
                // Another process created it first: load that one.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                other => other.with_context(|| format!("cannot create {}", path.display()))?,
            }
        }
        let signing = SigningKey::from_bytes(&*read_seed(path)?);
        let chain_file: ChainFile = match std::fs::read_to_string(chain_path(path)) {
            Ok(s) => serde_json::from_str(&s).context("invalid relay_identity.chain")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChainFile::default(),
            Err(e) => return Err(e.into()),
        };
        let chain = chain_file
            .links
            .iter()
            .map(link_from_info)
            .collect::<anyhow::Result<Vec<_>>>()?;
        if chain.len() > MAX_RELAY_CHAIN {
            bail!("relay_identity.chain holds more than {MAX_RELAY_CHAIN} links");
        }
        // Serve only a chain clients will accept: every link verifies and
        // continues the previous one (+1 version each).
        for (i, link) in chain.iter().enumerate() {
            relay_pin::verify_relay_link(link)
                .context("relay_identity.chain has a link that does not verify")?;
            if let Some(prev) = i.checked_sub(1).map(|j| &chain[j]) {
                if link.prev_key != prev.new_key
                    || Some(link.version) != prev.version.checked_add(1)
                {
                    bail!("relay_identity.chain is not continuous");
                }
            }
        }
        match chain.last() {
            Some(last)
                if last.new_key != signing.verifying_key().to_bytes()
                    || last.version != chain_file.version =>
            {
                bail!(
                    "relay_identity.chain does not end at the current key; if a rotation was \
                     interrupted before it replaced the key, restore {} over {} and start again",
                    chain_prev_path(path).display(),
                    chain_path(path).display()
                );
            }
            Some(_) => {}
            None if chain_file.version != 0 => {
                bail!(
                    "relay_identity.chain claims version {} with no links",
                    chain_file.version
                );
            }
            None => {}
        }
        Ok(Self {
            signing,
            version: chain_file.version,
            chain,
        })
    }

    /// Config in use: the key must exist (round-2 L1).
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            bail!(
                "relay identity key missing at {}; run `rchat-server --init-relay-identity` once to create it \
                 (a new key makes every client that pinned this relay refuse it)",
                path.display()
            );
        }
        Self::load_or_create(path)
    }

    /// `--init-relay-identity`: create the key; never overwrite one.
    pub(crate) fn create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            bail!("{} already exists; refusing to replace a relay identity (use --rotate-relay-identity)", path.display());
        }
        if chain_path(path).exists() {
            bail!(
                "{} exists without its key; refusing to start a new identity over an old chain",
                chain_path(path).display()
            );
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        match create_secret(path, random_seed().as_slice()) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => bail!(
                "{} already exists; refusing to replace a relay identity (use --rotate-relay-identity)",
                path.display()
            ),
            other => other.with_context(|| format!("cannot create {}", path.display()))?,
        }
        Self::load_or_create(path)
    }

    /// The rotation ceremony: new key, link signed by the old key, version + 1,
    /// chain capped at 3. The old seed is not kept (round-2 L1).
    pub(crate) fn rotate(path: &Path) -> anyhow::Result<Self> {
        let old = Self::load(path)?;
        let new_signing = SigningKey::from_bytes(&random_seed());
        let new_key = new_signing.verifying_key().to_bytes();
        let version = old
            .version
            .checked_add(1)
            .context("relay identity version overflow")?;
        let mut chain = old.chain.clone();
        chain.push(relay_pin::sign_relay_link(&old.signing, &new_key, version));
        while chain.len() > MAX_RELAY_CHAIN {
            chain.remove(0);
        }
        let file = ChainFile {
            version,
            links: chain.iter().map(link_info).collect(),
        };
        // Recovery copy of the current (old) chain, public like the chain.
        let prev = ChainFile {
            version: old.version,
            links: old.chain.iter().map(link_info).collect(),
        };
        write_atomic(
            &chain_prev_path(path),
            &serde_json::to_vec_pretty(&prev)?,
            0o644,
        )?;
        // The chain is public (0644). Chain first, then key, each an atomic
        // replacement made durable (directory fsync) before the next: a crash
        // can leave the new chain with the old key (startup refuses and names
        // the .prev copy), never the new key with the old chain. The old seed
        // is erased, not kept (spec §4.9 L1, R-16): its inode is held open
        // across the atomic replacement and zero-filled afterwards, so the
        // key path always holds one complete key.
        let old_seed = open_key(path, true)?;
        write_atomic(&chain_path(path), &serde_json::to_vec_pretty(&file)?, 0o644)?;
        write_secret(path, Zeroizing::new(new_signing.to_bytes()).as_slice())?;
        wipe_open_key(old_seed).context("cannot erase the old relay identity seed")?;
        Ok(Self {
            signing: new_signing,
            version,
            chain,
        })
    }

    pub(crate) fn key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Seed for this relay's decoy site (built-in page and `--render-decoy`
    /// alike): `HKDF-SHA256(ikm = identity secret key, salt = normalised
    /// host bytes (empty with no host), info = "rchat/decoy-seed/v3")`
    /// (R27a, final review M2). Derived from the secret, never from public
    /// data alone (the host, the public key or the pin), so nobody can
    /// compute the design and use it to confirm the relay. The host still
    /// picks among one relay's designs; an empty salt is HKDF's default
    /// salt, so a relay without a host keeps the seed R27a gave it.
    pub(crate) fn decoy_seed(&self, host: Option<&str>) -> [u8; 32] {
        let salt = host
            .map(crate::decoy_render::normalize_host)
            .unwrap_or_default();
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt.as_bytes()), self.signing.as_bytes());
        let mut out = [0u8; 32];
        hk.expand(b"rchat/decoy-seed/v3", &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        out
    }

    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn pin(&self) -> String {
        relay_pin::encode_pin(&self.key())
    }

    /// `hello_response.relay_identity` for one connection.
    pub(crate) fn hello_info(&self, binding: &[u8; 32], challenge: &[u8; 32]) -> RelayIdentityInfo {
        RelayIdentityInfo {
            key: hex::encode(self.key()),
            version: self.version,
            signature: hex::encode(relay_pin::sign_relay_auth(
                &self.signing,
                binding,
                challenge,
                self.version,
            )),
            chain: self.chain.iter().map(link_info).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rchat_core::relay_pin::{pin_matches, verify_relay_auth, walk_relay_chain};
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> crate::ScratchDir {
        crate::ScratchDir::new(&format!("rchat-relay-id-{tag}"))
    }

    /// RP7: created (a configured path the server starts with) with 0600;
    /// the same key after a restart.
    #[test]
    fn rp7_created_0600_and_stable() {
        let d = temp_dir("create");
        let path = d.join("relay_identity.key");
        let a = RelayIdentity::load_or_create(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 32);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let b = RelayIdentity::load_or_create(&path).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!(a.version(), 0);
        assert!(pin_matches(&a.pin(), &a.key()));
    }

    /// RP7: a world-readable or wrong-length key file refuses startup.
    #[test]
    fn rp7_bad_mode_or_length_refused() {
        let d = temp_dir("bad");
        let path = d.join("relay_identity.key");
        RelayIdentity::load_or_create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RelayIdentity::load_or_create(&path).is_err());
        std::fs::write(&path, [1u8; 31]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(RelayIdentity::load_or_create(&path).is_err());
    }

    /// RP7: rotation writes a verifying link, bumps the version, keeps no old
    /// seed (L1), and caps the chain at 3.
    #[test]
    fn rp7_rotation_ceremony() {
        let d = temp_dir("rotate");
        let path = d.join("relay_identity.key");
        let v0 = RelayIdentity::load_or_create(&path).unwrap();
        let v1 = RelayIdentity::rotate(&path).unwrap();
        assert_eq!(v1.version(), 1);
        assert!(
            !d.join("relay_identity.key.v0").exists(),
            "old seed not kept (L1)"
        );
        assert!(walk_relay_chain(&v1.chain, &v0.pin(), 0, &v1.key(), 1).is_ok());
        let reloaded = RelayIdentity::load_or_create(&path).unwrap();
        assert_eq!(reloaded.key(), v1.key());
        assert_eq!(reloaded.version(), 1);
        for _ in 0..3 {
            RelayIdentity::rotate(&path).unwrap();
        }
        let v4 = RelayIdentity::load_or_create(&path).unwrap();
        assert_eq!(v4.version(), 4);
        assert_eq!(v4.chain.len(), 3, "only the last 3 links are kept");
    }

    /// RP7 (L1): with a config in use a missing key is an error; init creates once.
    #[test]
    fn rp7_load_requires_init_and_init_never_overwrites() {
        let d = temp_dir("init");
        let path = d.join("relay_identity.key");
        let err = RelayIdentity::load(&path)
            .err()
            .expect("missing key refused")
            .to_string();
        assert!(err.contains("--init-relay-identity"), "{err}");
        let a = RelayIdentity::create(&path).unwrap();
        assert!(RelayIdentity::create(&path).is_err(), "never overwrites");
        assert_eq!(RelayIdentity::load(&path).unwrap().key(), a.key());
    }

    /// Rotation leaves exactly the key and the chain on disk (no old seed, no
    /// temp files); the chain is 0644 and the key stays 0600.
    #[test]
    fn rotation_leaves_only_key_and_chain() {
        let d = temp_dir("files");
        let path = d.join("relay_identity.key");
        RelayIdentity::load_or_create(&path).unwrap();
        RelayIdentity::rotate(&path).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "relay_identity.chain",
                "relay_identity.chain.prev",
                "relay_identity.key"
            ]
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&chain_path(&path)), 0o644);
    }

    /// A stale, world-readable temp file is never reused for the key.
    #[test]
    fn stale_temp_file_mode_is_not_inherited() {
        let d = temp_dir("stale");
        let path = d.join("relay_identity.key");
        let tmp = d.join("relay_identity.key.tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        RelayIdentity::create(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            b"stale",
            "stale file not reused"
        );
        let leftovers = std::fs::read_dir(&d)
            .unwrap()
            .filter(|e| {
                let n = e.as_ref().unwrap().file_name();
                let n = n.to_string_lossy();
                n.ends_with(".tmp") && n != "relay_identity.key.tmp"
            })
            .count();
        assert_eq!(leftovers, 0, "no temp files of ours left behind");
    }

    /// Task 10b minor: temp files an interrupted write left (possibly a
    /// seed) are wiped and removed at the next start; young ones (a write in
    /// progress) and files that aren't ours are left alone.
    #[test]
    fn stale_temp_files_are_swept_at_start() {
        let d = temp_dir("sweep");
        let path = d.join("relay_identity.key");
        let stale = d.join("relay_identity.key.4242.0123456789abcdef.tmp");
        let foreign = d.join("relay_identity.key.tmp");
        std::fs::write(&stale, [7u8; 32]).unwrap();
        std::fs::write(&foreign, b"x").unwrap();
        let young = d.join("relay_identity.key.4243.0123456789abcdef.tmp");
        std::fs::write(&young, [8u8; 32]).unwrap();
        // Back-date the stale one.
        let c = std::ffi::CString::new(stale.as_os_str().as_encoded_bytes()).unwrap();
        let times = [libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        }; 2];
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) }, 0);
        RelayIdentity::load_or_create(&path).unwrap();
        assert!(!stale.exists(), "stale temp swept");
        assert!(young.exists(), "a write in progress is left alone");
        assert!(foreign.exists(), "not ours");
    }

    /// A tampered chain refuses startup; init refuses an orphaned chain.
    #[test]
    fn tampered_or_orphaned_chain_refused() {
        let d = temp_dir("tamper");
        let path = d.join("relay_identity.key");
        RelayIdentity::load_or_create(&path).unwrap();
        RelayIdentity::rotate(&path).unwrap();
        let chain = chain_path(&path);
        let mut file: ChainFile = serde_json::from_slice(&std::fs::read(&chain).unwrap()).unwrap();
        let mut sig = hex::decode(&file.links[0].signature).unwrap();
        sig[0] ^= 1;
        file.links[0].signature = hex::encode(sig);
        std::fs::write(&chain, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(RelayIdentity::load(&path).is_err(), "bad link signature");
        std::fs::remove_file(&path).unwrap();
        let err = RelayIdentity::create(&path)
            .err()
            .expect("orphaned chain refused")
            .to_string();
        assert!(err.contains("relay_identity.chain"), "{err}");
        assert!(!path.exists());
    }

    /// A rotation interrupted after the chain but before the key: startup
    /// refuses (no silent identity change) and names the `.prev` copy, which
    /// restores the old identity at its old version.
    #[test]
    fn interrupted_rotation_refused_and_recoverable_from_prev() {
        let d = temp_dir("interrupt");
        let path = d.join("relay_identity.key");
        let v0 = RelayIdentity::load_or_create(&path).unwrap();
        let old_seed = std::fs::read(&path).unwrap();
        RelayIdentity::rotate(&path).unwrap();
        write_secret(&path, &old_seed).unwrap(); // the key rename never landed
        let err = format!("{:#}", RelayIdentity::load(&path).err().expect("refused"));
        assert!(err.contains("relay_identity.chain.prev"), "{err}");
        std::fs::copy(chain_prev_path(&path), chain_path(&path)).unwrap();
        let back = RelayIdentity::load(&path).unwrap();
        assert_eq!((back.key(), back.version()), (v0.key(), 0));
    }

    /// A chain file claiming a version with no links is refused.
    #[test]
    fn version_without_links_refused() {
        let d = temp_dir("nolinks");
        let path = d.join("relay_identity.key");
        RelayIdentity::load_or_create(&path).unwrap();
        std::fs::write(chain_path(&path), br#"{"version": 2, "links": []}"#).unwrap();
        assert!(RelayIdentity::load(&path).is_err());
        std::fs::write(chain_path(&path), br#"{"version": 0, "links": []}"#).unwrap();
        assert!(RelayIdentity::load(&path).is_ok());
    }

    /// Concurrent inits: exactly one wins, and the key on disk is its key;
    /// concurrent first starts all end up with the same key.
    #[test]
    fn concurrent_create_has_one_winner() {
        let d = temp_dir("race");
        let path = d.join("relay_identity.key");
        let results: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| s.spawn(|| RelayIdentity::create(&path).map(|id| id.key())))
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(winners.len(), 1, "exactly one init succeeds");
        assert_eq!(RelayIdentity::load(&path).unwrap().key(), *winners[0]);

        let d = temp_dir("race2");
        let path = d.join("relay_identity.key");
        let keys: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| s.spawn(|| RelayIdentity::load_or_create(&path).unwrap().key()))
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(
            keys.iter().all(|k| *k == keys[0]),
            "one key for every starter"
        );
    }

    /// The hello info signs this connection's binding and challenge.
    #[test]
    fn hello_info_verifies() {
        let id = RelayIdentity::ephemeral();
        let info = id.hello_info(&[3; 32], &[4; 32]);
        let key: [u8; 32] = hex::decode(&info.key).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(&info.signature).unwrap().try_into().unwrap();
        assert!(verify_relay_auth(&key, &[3; 32], &[4; 32], info.version, &sig).is_ok());
    }

    /// R-16: the key is never read through a symlink, even one pointing at
    /// a valid 0600 key owned by the service user.
    #[test]
    fn a_symlinked_key_is_refused() {
        let d = temp_dir("symlink");
        let real = d.join("real.key");
        RelayIdentity::load_or_create(&real).unwrap();
        let link = d.join("relay_identity.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let Err(e) = RelayIdentity::load_or_create(&link) else {
            panic!("a symlinked key was loaded");
        };
        let err = format!("{e:#}");
        assert!(err.contains("symlinks are refused"), "{err}");
    }

    /// R-16: rotation erases the old seed: its inode (still open here) is
    /// zero-filled once the new key has replaced it at the path.
    #[test]
    fn rotation_zero_fills_the_old_seed() {
        use std::io::{Read, Seek, SeekFrom};
        let d = temp_dir("wipe");
        let path = d.join("relay_identity.key");
        let old = RelayIdentity::load_or_create(&path).unwrap();
        let mut held = std::fs::File::open(&path).unwrap();
        let mut before = Vec::new();
        held.read_to_end(&mut before).unwrap();
        assert_eq!(before.len(), 32);
        assert_ne!(before, vec![0u8; 32]);

        let new = RelayIdentity::rotate(&path).unwrap();
        assert_ne!(new.key(), old.key());
        held.seek(SeekFrom::Start(0)).unwrap();
        let mut after = Vec::new();
        held.read_to_end(&mut after).unwrap();
        assert_eq!(after, vec![0u8; 32], "old seed erased");
        // The path holds the new key.
        assert_eq!(RelayIdentity::load(&path).unwrap().key(), new.key());
    }

    /// R27a, final review M2: the decoy seed comes from the secret, with or
    /// without a host, is stable per identity and host, differs between
    /// identities and between hosts, and cannot be recomputed from public
    /// data (the host, the pin or the public key).
    #[test]
    fn decoy_seed_is_secret_derived_and_not_public() {
        use sha2::{Digest, Sha256};
        let (a, b) = (RelayIdentity::ephemeral(), RelayIdentity::ephemeral());
        let host = Some("chat.example.com");
        for h in [None, host] {
            assert_eq!(a.decoy_seed(h), a.decoy_seed(h));
            assert_ne!(a.decoy_seed(h), b.decoy_seed(h));
        }
        assert_ne!(a.decoy_seed(None), a.decoy_seed(host));
        assert_ne!(a.decoy_seed(host), a.decoy_seed(Some("other.example.com")));
        // The host is normalised as everywhere else.
        assert_eq!(
            a.decoy_seed(host),
            a.decoy_seed(Some(" Chat.Example.COM. "))
        );
        // An empty host is no host.
        assert_eq!(a.decoy_seed(None), a.decoy_seed(Some(" . ")));
        let seed = a.decoy_seed(host);
        let public = a.key();
        assert_ne!(seed, public);
        assert_ne!(seed, <[u8; 32]>::from(Sha256::digest(public)));
        // Not the old public seed SHA-256(host), nor anything over the pin.
        assert_ne!(seed, <[u8; 32]>::from(Sha256::digest(b"chat.example.com")));
        assert_ne!(seed, <[u8; 32]>::from(Sha256::digest(a.pin().as_bytes())));
        // HKDF over the public key with the same salt and info is not it either.
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"chat.example.com"), &public);
        let mut guess = [0u8; 32];
        hk.expand(b"rchat/decoy-seed/v3", &mut guess).unwrap();
        assert_ne!(seed, guess);
        // The same key file gives the same seed across loads.
        let dir = crate::ScratchDir::new("decoy-seed-id");
        let path = dir.join("relay_identity.key");
        let first = RelayIdentity::load_or_create(&path)
            .unwrap()
            .decoy_seed(host);
        assert_eq!(first, RelayIdentity::load(&path).unwrap().decoy_seed(host));
    }

    /// Final review M2: a relay's built-in page is the site of its identity's
    /// decoy seed for its configured host (the site `--render-decoy` writes),
    /// not a site anyone could compute from the host.
    #[tokio::test]
    async fn the_built_in_page_uses_the_identity_seed_for_the_host() {
        use super::super::test_support::{start, test_config};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = crate::ScratchDir::new("decoy-built-in");
        let path = dir.join("relay_identity.key");
        RelayIdentity::load_or_create(&path).unwrap();
        let mut config = test_config();
        config.relay_identity_path = Some(path.to_string_lossy().into_owned());
        config.decoy.host = Some("chat.example.com".into());
        let (addr, _state) = start(config).await;
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: chat.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let body_at = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let seed = RelayIdentity::load(&path)
            .unwrap()
            .decoy_seed(Some("chat.example.com"));
        let want = crate::decoy_render::render_site_for_seed(seed);
        assert_eq!(&resp[body_at..], want.get("index.html").unwrap());
    }

    /// Known answers: secret key 00 01 .. 1f gives these seeds, without a
    /// host and with host `chat.example.com`. The expected values were
    /// computed independently with Python's stdlib (`hmac`/`hashlib`:
    /// PRK = HMAC(salt or 0^32, ikm); T1 = HMAC(PRK, info || 01)), which pins
    /// the info string, the salt and the derivation. The no-host value is
    /// the one R27a shipped: an empty salt is HKDF's default salt.
    #[test]
    fn decoy_seed_known_answer() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let id = RelayIdentity {
            signing: SigningKey::from_bytes(&key),
            version: 0,
            chain: Vec::new(),
        };
        let hex = |s: [u8; 32]| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(id.decoy_seed(None)),
            "e69de924d6c3eb185992e8c09105cd314cc393dac7acc1b4f976bb0501026775"
        );
        assert_eq!(
            hex(id.decoy_seed(Some("Chat.Example.com."))),
            "c4a19becec148b51230a5a634d0c41609c8d0cae481e6bbf65beb0fdf34c59ce"
        );
    }
}
