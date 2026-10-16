//! RCQ2: opt-in encrypted persistence of the offline queue (spec §5.5).
//!
//! `"RCQ2" || 0x01 || nonce(24) || XChaCha20-Poly1305(K, nonce,
//! aad = "RCQ2"||0x01, bincode(PersistedQueuesV2))`. The key is 32 raw bytes
//! that must live on a memory filesystem (tmpfs, ramfs, mfs), owned by the
//! service user, mode 0600 or stricter, in another directory and on another
//! filesystem than the data. Records carry only a keyed recipient tag, the
//! enqueue time, the knock flag and the sealed payload.

use super::tags::{self, IdTag};
use super::{expired, requeue_salvaged, RelayState, StoredMessage};
use crate::config::OfflineQueueConfig;
use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"RCQ2";
const FORMAT_VERSION: u8 = 0x01;
const HEADER_LEN: usize = 4 + 1 + 24;
const AAD: [u8; 5] = [b'R', b'C', b'Q', b'2', FORMAT_VERSION];
/// Linux `statfs.f_type` values for tmpfs and ramfs.
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: u64 = 0x0102_1994;
#[cfg(target_os = "linux")]
const RAMFS_MAGIC: u64 = 0x8584_58f6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistPaths {
    pub data: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsKind {
    Memory,
    Disk,
}

/// What the startup checks ask of the operating system (injectable so the
/// refusals can be tested on a single-volume machine).
pub(crate) trait PathEnv {
    fn fs_kind(&self, path: &Path) -> std::io::Result<FsKind>;
    fn device(&self, path: &Path) -> std::io::Result<u64> {
        Ok(std::fs::metadata(path)?.dev())
    }
    fn euid(&self) -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }
}

/// The real system.
pub(crate) struct RealEnv;

impl PathEnv for RealEnv {
    fn fs_kind(&self, path: &Path) -> std::io::Result<FsKind> {
        fs_kind(path)
    }
}

#[cfg(test)]
struct ProbeEnv<'a>(&'a dyn Fn(&Path) -> std::io::Result<FsKind>);

#[cfg(test)]
impl PathEnv for ProbeEnv<'_> {
    fn fs_kind(&self, path: &Path) -> std::io::Result<FsKind> {
        (self.0)(path)
    }
}

/// Startup checks with the real device and uid and an injectable fs probe.
#[cfg(test)]
pub(crate) fn check_paths(
    cfg: &OfflineQueueConfig,
    probe: &dyn Fn(&Path) -> std::io::Result<FsKind>,
) -> Result<PersistPaths> {
    check_paths_with(cfg, &ProbeEnv(probe))
}

/// Canonicalise both paths, then refuse unless the key is a 32-byte file,
/// mode <= 0600, owned by the effective uid, in another directory and on
/// another filesystem than the data, and (unless `allow_persistent_key`) on
/// a memory filesystem.
pub(crate) fn check_paths_with(
    cfg: &OfflineQueueConfig,
    env: &dyn PathEnv,
) -> Result<PersistPaths> {
    let key_cfg = cfg
        .persist_key_path
        .as_ref()
        .context("offline_queue.persist_key_path is required when persist = true")?;
    let data_cfg = cfg
        .persist_path
        .as_ref()
        .context("offline_queue.persist_path is required when persist = true")?;
    let key = std::fs::canonicalize(key_cfg)
        .context("offline_queue.persist_key_path: the key file is missing")?;
    let data = if data_cfg.exists() {
        std::fs::canonicalize(data_cfg).context("offline_queue.persist_path cannot be resolved")?
    } else {
        let parent = data_cfg
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = data_cfg
            .file_name()
            .context("offline_queue.persist_path must name a file")?;
        std::fs::canonicalize(parent)
            .context("offline_queue.persist_path: its directory does not exist")?
            .join(name)
    };

    let meta = std::fs::metadata(&key).context("offline_queue.persist_key_path: cannot stat")?;
    if !meta.is_file() {
        bail!("offline_queue.persist_key_path is not a regular file");
    }
    if meta.len() != 32 {
        bail!("the queue key must be exactly 32 bytes");
    }
    if meta.permissions().mode() & 0o077 != 0 {
        bail!("the queue key's mode is broader than 0600");
    }
    if meta.uid() != env.euid() {
        bail!("the queue key is not owned by the service user (effective uid)");
    }
    let key_dir = key.parent().context("queue key has no directory")?;
    let data_dir = data.parent().context("queue data has no directory")?;
    if key_dir == data_dir {
        bail!("the queue key and the queue data are in the same directory");
    }
    if env.device(key_dir)? == env.device(data_dir)? {
        bail!("the queue key and the queue data are on the same filesystem");
    }
    if !cfg.allow_persistent_key && env.fs_kind(&key)? != FsKind::Memory {
        bail!(
            "the queue key is not on a memory filesystem (tmpfs, ramfs or mfs); set \
             allow_persistent_key = true only for development"
        );
    }
    Ok(PersistPaths { data, key })
}

/// Filesystem type of `path` via statfs(2).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn fs_kind(path: &Path) -> std::io::Result<FsKind> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: a zeroed statfs is a valid out-parameter; c is NUL-terminated.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: f_fstypename is a NUL-terminated C string filled by statfs.
    let name = unsafe { CStr::from_ptr(s.f_fstypename.as_ptr()) }.to_bytes();
    Ok(if name == b"tmpfs" || name == b"mfs" {
        FsKind::Memory
    } else {
        FsKind::Disk
    })
}

/// Filesystem type of `path` via statfs(2).
#[cfg(target_os = "linux")]
pub(crate) fn fs_kind(path: &Path) -> std::io::Result<FsKind> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: a zeroed statfs is a valid out-parameter; c is NUL-terminated.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let t = (s.f_type as u64) & 0xffff_ffff;
    Ok(if t == TMPFS_MAGIC || t == RAMFS_MAGIC {
        FsKind::Memory
    } else {
        FsKind::Disk
    })
}

/// Unknown platform: never claim a memory filesystem.
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "linux")))]
pub(crate) fn fs_kind(_path: &Path) -> std::io::Result<FsKind> {
    Ok(FsKind::Disk)
}

/// Read the 32-byte queue key (never follows a symlink; the path is the
/// canonical one from `check_paths_with`).
pub(crate) fn read_key(path: &Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("cannot read the queue key")?;
    // The startup checks looked at the path; check the file actually opened
    // too, so a swap in between can't slip in another file (Task 10 minor).
    let meta = f.metadata().context("cannot read the queue key")?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        bail!("the queue key's mode is broader than 0600");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if meta.uid() != unsafe { libc::geteuid() } {
        bail!("the queue key is not owned by the service user (effective uid)");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    f.take(33)
        .read_to_end(&mut bytes)
        .context("cannot read the queue key")?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("the queue key must be exactly 32 bytes"))?;
    Ok(key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedQueuesV2 {
    pub id_key: [u8; 32],
    pub saved_at_unix_secs: u64,
    pub queues: Vec<PersistedQueue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedQueue {
    pub tag: [u8; 32],
    pub messages: Vec<PersistedMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedMessage {
    pub enqueued_at_unix_secs: u64,
    pub is_knock: bool,
    pub payload: Vec<u8>,
}

pub(crate) fn encode_rcq2(key: &[u8; 32], body: &PersistedQueuesV2) -> Result<Vec<u8>> {
    let mut plain = bincode::serialize(body)?;
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce)?;
    let sealed = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("bad queue key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &AAD,
            },
        );
    plain.zeroize();
    let ct = sealed.map_err(|_| anyhow::anyhow!("queue encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn decode_rcq2(key: &[u8; 32], bytes: &[u8]) -> Result<PersistedQueuesV2> {
    if bytes.len() < HEADER_LEN + 16 || &bytes[..4] != MAGIC || bytes[4] != FORMAT_VERSION {
        bail!("not an RCQ2 file");
    }
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("bad queue key"))?
            .decrypt(
                XNonce::from_slice(&bytes[5..HEADER_LEN]),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("queue file does not decrypt"))?,
    );
    Ok(bincode::deserialize(&plain)?)
}

/// Fresh temp file (0600, never through a symlink), fsync, rename over
/// `path`, fsync the directory.
pub(crate) fn save_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("rcq2.tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        // create_new (O_EXCL) never follows a symlink planted at `tmp`.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Read (at most `max_bytes`), delete, then decrypt. The file is deleted
/// whether or not it decrypts: an unreadable or oversized file is abandoned
/// (the relay starts empty).
pub(crate) fn load_and_delete(
    paths: &PersistPaths,
    key: &[u8; 32],
    max_bytes: u64,
) -> Result<Option<PersistedQueuesV2>> {
    use std::io::Read;
    let f = match std::fs::File::open(&paths.data) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    let read = f.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes);
    std::fs::remove_file(&paths.data)?;
    read?;
    if bytes.len() as u64 > max_bytes {
        bail!("queue file is larger than any saved queue can be");
    }
    decode_rcq2(key, &bytes).map(Some)
}

/// Upper bound on a file this relay could have written: message and knock
/// budgets, doubled for record overhead (every record carries at least a
/// minimal sealed payload, far larger than its framing), plus slack.
fn max_file_bytes(state: &RelayState) -> u64 {
    let budgets = (state.config.offline_queue_max_total_bytes as u64)
        .saturating_add(state.config.offline_queue.knock_budget_bytes as u64);
    budgets.saturating_mul(2).saturating_add(1 << 20)
}

/// Paths plus the key, held for the process lifetime (zeroed on drop).
pub(crate) struct PersistCtx {
    pub paths: PersistPaths,
    pub key: Zeroizing<[u8; 32]>,
    /// Held for a whole save: the periodic and the SIGTERM/SIGINT saves
    /// share one temp file and must never interleave.
    save_lock: std::sync::Mutex<()>,
}

impl PersistCtx {
    pub(crate) fn new(paths: PersistPaths, key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            paths,
            key,
            save_lock: std::sync::Mutex::new(()),
        }
    }
}

/// The queues as persisted: tag, enqueue time, knock flag, payload. The
/// memory-only `knock_seq` is not written.
pub(crate) fn snapshot_queues(state: &RelayState, now_unix: u64) -> PersistedQueuesV2 {
    PersistedQueuesV2 {
        id_key: tags::id_key(),
        saved_at_unix_secs: now_unix,
        queues: state
            .message_queues
            .iter()
            .map(|e| PersistedQueue {
                tag: e.key().0,
                messages: e
                    .pending
                    .iter()
                    .map(|m| PersistedMessage {
                        enqueued_at_unix_secs: m.enqueued_at_unix_secs,
                        is_knock: m.is_knock,
                        payload: m.payload.clone(),
                    })
                    .collect(),
            })
            .filter(|q| !q.messages.is_empty())
            .collect(),
    }
}

/// Restore queues, dropping records whose age (from the stored time, never
/// rebuilt) exceeds the TTL — `knock_ttl_secs` for knocks. Future-dated
/// records count as enqueued now. Returns the number of records kept.
/// Messages are charged to the offline budget (`RelayState::offline_budget`); each restored knock is
/// accounted with a fresh `knock_seq` and no pair entry (the same path as a
/// re-queue after a failed drain).
pub(crate) fn restore_queues(body: PersistedQueuesV2, state: &RelayState, now_unix: u64) -> usize {
    let ttl = state.config.offline_queue.ttl_secs;
    let knock_ttl = state.config.knock_ttl_secs();
    let mut kept = 0usize;
    for q in body.queues {
        let msgs: Vec<StoredMessage> = q
            .messages
            .into_iter()
            .map(|m| StoredMessage {
                payload: m.payload,
                enqueued_at_unix_secs: m.enqueued_at_unix_secs.min(now_unix),
                is_knock: m.is_knock,
                knock_seq: 0,
            })
            .filter(|m| {
                let limit = if m.is_knock { knock_ttl } else { ttl };
                !expired(now_unix, m.enqueued_at_unix_secs, limit)
            })
            .collect();
        if msgs.is_empty() {
            continue;
        }
        // Through normal admission (Task 10 minor): budgets lowered since
        // the save are honoured, the excess dropped, not force-added.
        let n = msgs.len();
        kept += n - requeue_salvaged(IdTag(q.tag), msgs, state);
    }
    kept
}

/// Saves the queue on demand (periodic task, SIGTERM).
#[derive(Clone)]
pub(crate) struct QueueSaver {
    pub(crate) state: RelayState,
    pub(crate) ctx: Arc<PersistCtx>,
}

impl QueueSaver {
    /// Snapshot, seal and write atomically, one save at a time. Blocking
    /// (fsync): call from a blocking thread.
    pub(crate) fn save_now(&self) -> Result<()> {
        // A save that panicked left no state behind the lock to protect.
        let _one_at_a_time = self
            .ctx
            .save_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let body = snapshot_queues(&self.state, crate::protocol::timestamp());
        let bytes = encode_rcq2(&self.ctx.key, &body)?;
        save_atomic(&self.ctx.paths.data, &bytes)?;
        Ok(())
    }
}

/// Startup: checks, key, load-then-delete, restore. Returns the context to
/// keep for saving. Refusals are errors (the server does not start).
pub(crate) fn open_at_startup(
    state: &RelayState,
    env: &dyn PathEnv,
) -> Result<Option<Arc<PersistCtx>>> {
    let cfg = &state.config.offline_queue;
    if !cfg.persist {
        return Ok(None);
    }
    let paths = check_paths_with(cfg, env)?;
    if cfg.allow_persistent_key {
        warn!(
            "offline_queue.allow_persistent_key = true: the queue key is not checked for a \
             memory filesystem; website sentence 8 must not be used for this relay"
        );
    }
    let key = Zeroizing::new(read_key(&paths.key)?);
    match load_and_delete(&paths, &key, max_file_bytes(state)) {
        Ok(Some(body)) => {
            if tags::install_id_key(body.id_key) || tags::id_key() == body.id_key {
                let kept = restore_queues(body, state, crate::protocol::timestamp());
                info!(
                    "Restored {} queued items from the encrypted queue file",
                    kept
                );
            } else {
                warn!("Encrypted queue file was written under another tag key; starting empty");
            }
        }
        Ok(None) => {}
        // Fixed wording either way; which one says whether the file is
        // still there (Task 10 minor: a failed delete read as "starting empty").
        Err(_) if paths.data.exists() => {
            warn!("Encrypted queue file could not be deleted after reading; remove it by hand")
        }
        Err(_) => warn!("Encrypted queue file could not be read; starting empty"),
    }
    Ok(Some(Arc::new(PersistCtx::new(paths, key))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::signaling::test_support::{
        ask, authed, connect, eventually, hello, next_control, publish_message, test_config,
        TestIdentity, Ws, DEV_ORIGIN,
    };
    use crate::signaling::{tags, MessageQueue, RelayState, Server};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    /// Fake environment: paths under `memory` are a memory filesystem on
    /// device 1; under `data` device 3; anything else disk on device 2.
    struct FakeEnv {
        memory: PathBuf,
        data: PathBuf,
        euid: u32,
    }

    impl PathEnv for FakeEnv {
        fn fs_kind(&self, path: &Path) -> std::io::Result<FsKind> {
            Ok(if path.starts_with(&self.memory) {
                FsKind::Memory
            } else {
                FsKind::Disk
            })
        }
        fn device(&self, path: &Path) -> std::io::Result<u64> {
            Ok(if path.starts_with(&self.memory) {
                1
            } else if path.starts_with(&self.data) {
                3
            } else {
                2
            })
        }
        fn euid(&self) -> u32 {
            self.euid
        }
    }

    struct Scratch {
        root: PathBuf,
        memory: PathBuf,
        data: PathBuf,
        other: PathBuf,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn scratch() -> Scratch {
        let root = std::env::temp_dir().join(format!("rchat-rcq2-{}", rand::random::<u64>()));
        let (memory, data, other) = (root.join("mem"), root.join("data"), root.join("other"));
        for d in [&memory, &data, &other] {
            std::fs::create_dir_all(d).unwrap();
        }
        let root = std::fs::canonicalize(&root).unwrap();
        Scratch {
            memory: root.join("mem"),
            data: root.join("data"),
            other: root.join("other"),
            root,
        }
    }

    fn write_key(path: &Path, len: usize, mode: u32) {
        std::fs::write(path, vec![0x6b; len]).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn cfg(data: &Path, key: &Path) -> OfflineQueueConfig {
        OfflineQueueConfig {
            persist: true,
            persist_path: Some(data.to_path_buf()),
            persist_key_path: Some(key.to_path_buf()),
            ..OfflineQueueConfig::default()
        }
    }

    fn env(s: &Scratch) -> FakeEnv {
        FakeEnv {
            memory: s.memory.clone(),
            data: s.data.clone(),
            // SAFETY: geteuid has no preconditions and cannot fail.
            euid: unsafe { libc::geteuid() },
        }
    }

    fn refusal(r: anyhow::Result<PersistPaths>) -> String {
        format!("{:#}", r.expect_err("expected a startup refusal"))
    }

    #[test]
    fn accepts_a_key_on_a_memory_fs_owned_by_us_with_mode_0400() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o400);
        let paths = check_paths_with(&cfg(&s.data.join("queue.rcq"), &key), &env(&s)).unwrap();
        assert_eq!(paths.key, key);
        assert_eq!(paths.data, s.data.join("queue.rcq"));
    }

    #[test]
    fn p2_key_and_data_in_the_same_directory_are_refused() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o600);
        let e = refusal(check_paths_with(
            &cfg(&s.memory.join("queue.rcq"), &key),
            &env(&s),
        ));
        assert!(e.contains("same directory"), "{e}");
    }

    #[test]
    fn p2_key_and_data_on_the_same_filesystem_are_refused() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o600);
        let sub = s.memory.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let e = refusal(check_paths_with(
            &cfg(&sub.join("queue.rcq"), &key),
            &env(&s),
        ));
        assert!(e.contains("same filesystem"), "{e}");
    }

    #[test]
    fn p2_key_of_the_wrong_length_is_refused() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 31, 0o600);
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &key),
            &env(&s),
        ));
        assert!(e.contains("exactly 32 bytes"), "{e}");
    }

    #[test]
    fn p2_key_with_mode_0644_is_refused() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o644);
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &key),
            &env(&s),
        ));
        assert!(e.contains("0600"), "{e}");
    }

    #[test]
    fn p2_key_owned_by_another_user_is_refused() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o600);
        let mut other_user = env(&s);
        other_user.euid += 1;
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &key),
            &other_user,
        ));
        assert!(e.contains("owned by"), "{e}");
    }

    #[test]
    fn p2_missing_key_is_refused() {
        let s = scratch();
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &s.memory.join("nope")),
            &env(&s),
        ));
        assert!(e.contains("persist_key_path"), "{e}");
    }

    #[test]
    fn p4_key_on_a_disk_filesystem_is_refused() {
        let s = scratch();
        let key = s.other.join("queue.key");
        write_key(&key, 32, 0o600);
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &key),
            &env(&s),
        ));
        assert!(e.contains("memory filesystem"), "{e}");
    }

    #[test]
    fn p4_symlink_on_a_memory_fs_pointing_to_disk_is_refused_after_canonicalisation() {
        let s = scratch();
        let target = s.other.join("real.key");
        write_key(&target, 32, 0o600);
        let link = s.memory.join("queue.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = refusal(check_paths_with(
            &cfg(&s.data.join("q.rcq"), &link),
            &env(&s),
        ));
        assert!(e.contains("memory filesystem"), "{e}");
    }

    #[test]
    fn p4_allow_persistent_key_skips_only_the_memory_fs_check() {
        let s = scratch();
        let key = s.other.join("queue.key");
        write_key(&key, 32, 0o600);
        let mut c = cfg(&s.data.join("q.rcq"), &key);
        c.allow_persistent_key = true;
        assert!(check_paths_with(&c, &env(&s)).is_ok());
        write_key(&key, 32, 0o644);
        assert!(
            check_paths_with(&c, &env(&s)).is_err(),
            "other checks still apply"
        );
    }

    #[test]
    fn p4_real_probe_reports_the_repository_as_disk() {
        assert_eq!(
            fs_kind(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap(),
            FsKind::Disk
        );
    }

    #[test]
    fn check_paths_with_real_devices_refuses_key_and_data_on_one_volume() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o600);
        // A temp dir is a single volume: the real device check refuses even
        // when the injected probe claims a memory filesystem.
        let e = refusal(check_paths(
            &cfg(&s.data.join("q.rcq"), &key),
            &|_p: &Path| Ok(FsKind::Memory),
        ));
        assert!(e.contains("same filesystem"), "{e}");
    }

    #[test]
    fn rcq2_round_trips_and_is_unreadable_with_another_key() {
        let body = PersistedQueuesV2 {
            id_key: [9; 32],
            saved_at_unix_secs: 7,
            queues: vec![PersistedQueue {
                tag: [1; 32],
                messages: vec![PersistedMessage {
                    enqueued_at_unix_secs: 5,
                    is_knock: true,
                    payload: vec![0x02; 64],
                }],
            }],
        };
        let bytes = encode_rcq2(&[0x11; 32], &body).unwrap();
        assert_eq!(&bytes[..5], b"RCQ2\x01");
        let back = decode_rcq2(&[0x11; 32], &bytes).unwrap();
        assert_eq!(back.queues[0].messages[0].payload, vec![0x02; 64]);
        assert!(
            decode_rcq2(&[0x22; 32], &bytes).is_err(),
            "another key cannot read it"
        );
        let mut tampered = bytes.clone();
        tampered[4] = 0x02;
        assert!(
            decode_rcq2(&[0x11; 32], &tampered).is_err(),
            "header is authenticated"
        );
    }

    /// M1 on disk: a persisted record is exactly `{payload,
    /// enqueued_at_unix_secs, is_knock}` (exhaustive destructure: adding a
    /// field breaks this test). The in-memory `knock_seq` is not saved; a
    /// restored knock gets a fresh accounting handle.
    #[tokio::test]
    async fn m1_persisted_records_hold_only_payload_time_and_kind() {
        let state = plain_state().await;
        let now = 70_000_000u64;
        let body = PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: now,
            queues: vec![PersistedQueue {
                tag: [0x34; 32],
                messages: vec![msg(now, true)],
            }],
        };
        assert_eq!(restore_queues(body, &state, now), 1);
        let restored = state.message_queues.get(&tags::IdTag([0x34; 32])).unwrap();
        assert!(
            restored.pending[0].knock_seq > 0,
            "a fresh handle is assigned on load"
        );
        drop(restored);
        let snap = snapshot_queues(&state, now);
        let PersistedMessage {
            enqueued_at_unix_secs,
            is_knock,
            payload,
        } = &snap.queues[0].messages[0];
        assert_eq!(*enqueued_at_unix_secs, now);
        assert!(*is_knock);
        assert_eq!(payload, &vec![0x02; 200]);
    }

    fn msg(at: u64, knock: bool) -> PersistedMessage {
        PersistedMessage {
            enqueued_at_unix_secs: at,
            is_knock: knock,
            payload: vec![0x02; 200],
        }
    }

    async fn plain_state() -> RelayState {
        Server::new(test_config()).await.unwrap().state()
    }

    #[tokio::test]
    async fn m5b_ttl_is_strict_from_the_stored_time_and_never_extended() {
        let state = plain_state().await;
        let ttl = state.config.offline_queue.ttl_secs;
        let t = 50_000_000u64;
        let tag = [0x31; 32];
        let body = |m: Vec<PersistedMessage>| PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: t,
            queues: vec![PersistedQueue { tag, messages: m }],
        };

        // Reload at T + ttl - 1: kept.
        assert_eq!(
            restore_queues(body(vec![msg(t, false)]), &state, t + ttl - 1),
            1
        );
        // Save/load cycles keep the original time.
        let mut snap = snapshot_queues(&state, t + ttl - 1);
        state.message_queues.clear();
        for _ in 0..3 {
            restore_queues(snap, &state, t + ttl - 1);
            snap = snapshot_queues(&state, t + ttl - 1);
            state.message_queues.clear();
        }
        assert_eq!(
            snap.queues[0].messages[0].enqueued_at_unix_secs, t,
            "life never extended"
        );
        // Reload at T + ttl + 1: dropped.
        assert_eq!(restore_queues(snap, &state, t + ttl + 1), 0);
        assert!(state.message_queues.get(&tags::IdTag(tag)).is_none());
    }

    /// Task 10 minor: the opened key file itself is checked, not only the
    /// path the startup checks saw.
    #[test]
    fn read_key_checks_the_opened_file() {
        let dir = crate::ScratchDir::new("rchat-persist-key");
        let key = dir.join("key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key(&key).unwrap(), [7u8; 32]);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            read_key(&key).is_err(),
            "a world-readable key is refused at open"
        );
    }

    /// Task 10 minor: a snapshot saved under larger budgets is restored
    /// within the current ones; the excess is dropped, not force-added.
    #[tokio::test]
    async fn restore_honours_budgets_lowered_since_the_save() {
        let cost = StoredMessage {
            payload: vec![0x02; 200],
            enqueued_at_unix_secs: 0,
            is_knock: false,
            knock_seq: 0,
        }
        .budget_cost();
        let state = Server::new(ServerConfig {
            offline_queue_max_bytes_per_recipient: 3 * cost,
            ..test_config()
        })
        .await
        .unwrap()
        .state();
        let now = 50_000_000u64;
        let body = PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: now,
            queues: vec![PersistedQueue {
                tag: [0x33; 32],
                messages: (0..50).map(|_| msg(now, false)).collect(),
            }],
        };
        assert_eq!(restore_queues(body, &state, now), 3);
        let q = state.message_queues.get(&tags::IdTag([0x33; 32])).unwrap();
        assert_eq!(q.pending.len(), 3);
        assert!(q.bytes <= 3 * cost);
        assert_eq!(state.offline_budget.used(), 3 * cost);
    }

    #[tokio::test]
    async fn m5b_future_dated_record_is_treated_as_enqueued_now() {
        let state = plain_state().await;
        let now = 50_000_000u64;
        let body = PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: now,
            queues: vec![PersistedQueue {
                tag: [0x32; 32],
                messages: vec![msg(now + 10_000, false)],
            }],
        };
        assert_eq!(restore_queues(body, &state, now), 1);
        let q = state.message_queues.get(&tags::IdTag([0x32; 32])).unwrap();
        assert_eq!(q.pending[0].enqueued_at_unix_secs, now);
    }

    #[tokio::test]
    async fn m5_ttl_holds_across_save_and_load_for_knocks() {
        let state = plain_state().await;
        let kttl = state.config.knock_ttl_secs();
        let now = 60_000_000u64;
        let body = PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: now,
            queues: vec![PersistedQueue {
                tag: [0x33; 32],
                messages: vec![msg(now - kttl - 1, true), msg(now - kttl, true)],
            }],
        };
        assert_eq!(restore_queues(body, &state, now), 1);
        assert_eq!(state.knocks.index_len(), 0, "pair index starts empty");
        assert_eq!(
            state.knocks.used(),
            200,
            "restored knock counts toward the budget"
        );
        assert_eq!(state.knocks.count_for(tags::IdTag([0x33; 32])), 1);
        // Save and load again one second later: the stored time is kept, so
        // the surviving knock is now one second past the knock TTL and goes.
        let snap = snapshot_queues(&state, now + 1);
        assert_eq!(
            snap.queues[0].messages[0].enqueued_at_unix_secs,
            now - kttl,
            "save keeps the stored time"
        );
        state.message_queues.clear();
        assert_eq!(restore_queues(snap, &state, now + 1), 0);
    }

    /// M5b with one clock: a message enqueued at T, saved and restarted at
    /// T + 71 h (kept), is gone at the sweep at T + 73 h (72 h TTL).
    #[tokio::test]
    async fn m5b_enqueue_advance_71h_restart_advance_2h_sweep_drops_it() {
        let state = plain_state().await;
        assert_eq!(state.config.offline_queue.ttl_secs, 72 * 3600);
        let t = 80_000_000u64;
        let tag = tags::IdTag([0x35; 32]);
        state.message_queues.insert(
            tag,
            MessageQueue {
                pending: vec![StoredMessage {
                    payload: vec![0x02; 200],
                    enqueued_at_unix_secs: t,
                    is_knock: false,
                    knock_seq: 0,
                }],
                bytes: 0,
            },
        );
        let at_71h = t + 71 * 3600;
        let file = encode_rcq2(&[0x44; 32], &snapshot_queues(&state, at_71h)).unwrap();

        let restarted = plain_state().await;
        let body = decode_rcq2(&[0x44; 32], &file).unwrap();
        assert_eq!(restore_queues(body, &restarted, at_71h), 1, "kept at 71 h");
        crate::signaling::expire_queues(t + 72 * 3600, &restarted);
        assert!(
            restarted.message_queues.contains_key(&tag),
            "kept at exactly 72 h"
        );
        crate::signaling::expire_queues(t + 73 * 3600, &restarted);
        assert!(!restarted.message_queues.contains_key(&tag), "gone at 73 h");
    }

    /// Concurrent saves (periodic task and SIGTERM) never leave a torn or
    /// missing file: every round ends with one complete snapshot on disk.
    #[tokio::test]
    async fn concurrent_saves_always_leave_one_complete_snapshot() {
        let s = scratch();
        let state = plain_state().await;
        for i in 0..16u8 {
            state.message_queues.insert(
                tags::IdTag([i; 32]),
                MessageQueue {
                    pending: vec![
                        StoredMessage {
                            payload: vec![i; 16 * 1024],
                            enqueued_at_unix_secs: 1,
                            is_knock: false,
                            knock_seq: 0,
                        };
                        4
                    ],
                    bytes: 0,
                },
            );
        }
        let data = s.data.join("queue.rcq");
        let saver = QueueSaver {
            state,
            ctx: Arc::new(PersistCtx::new(
                PersistPaths {
                    data: data.clone(),
                    key: s.memory.join("unused.key"),
                },
                Zeroizing::new([0x42; 32]),
            )),
        };
        for round in 0..8 {
            let handles: Vec<_> = (0..3)
                .map(|_| {
                    let sv = saver.clone();
                    std::thread::spawn(move || sv.save_now().map_err(|e| format!("{e:#}")))
                })
                .collect();
            for h in handles {
                h.join()
                    .unwrap()
                    .unwrap_or_else(|e| panic!("round {round}: save failed: {e}"));
            }
            let bytes = std::fs::read(&data).unwrap();
            let body = decode_rcq2(&[0x42; 32], &bytes)
                .unwrap_or_else(|e| panic!("round {round}: torn file: {e:#}"));
            assert_eq!(body.queues.len(), 16);
            assert!(body.queues.iter().all(|q| q.messages.len() == 4));
        }
        assert!(!data.with_extension("rcq2.tmp").exists());
    }

    #[test]
    fn load_refuses_a_file_over_the_size_bound_and_deletes_it() {
        let s = scratch();
        let paths = PersistPaths {
            data: s.data.join("queue.rcq"),
            key: s.memory.join("unused.key"),
        };
        std::fs::write(&paths.data, vec![0u8; 4096]).unwrap();
        assert!(load_and_delete(&paths, &[1; 32], 1024).is_err());
        assert!(!paths.data.exists(), "an oversized file is abandoned");
        assert!(load_and_delete(&paths, &[1; 32], 1024).unwrap().is_none());
    }

    #[test]
    fn decode_never_panics_on_short_or_garbage_input() {
        for bytes in [
            &b""[..],
            b"RCQ2",
            b"RCQ2\x01",
            &[0u8; 64][..],
            &[0xff; 200][..],
        ] {
            assert!(decode_rcq2(&[1; 32], bytes).is_err());
        }
    }

    /// Task 10 minor: an authentic file whose plaintext is not a snapshot
    /// (malformed bincode), and a valid file cut short, are refused.
    #[test]
    fn decode_refuses_malformed_bincode_and_truncated_files() {
        let key = [9u8; 32];
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).unwrap();
        let sealed = XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &[0xff; 40],
                    aad: &AAD,
                },
            )
            .unwrap();
        let mut file = MAGIC.to_vec();
        file.push(FORMAT_VERSION);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);
        assert!(
            decode_rcq2(&key, &file).is_err(),
            "decrypts, but isn't a snapshot"
        );

        let good = encode_rcq2(
            &key,
            &PersistedQueuesV2 {
                id_key: [1; 32],
                saved_at_unix_secs: 5,
                queues: vec![PersistedQueue {
                    tag: [2; 32],
                    messages: vec![msg(5, false)],
                }],
            },
        )
        .unwrap();
        assert!(decode_rcq2(&key, &good).is_ok());
        for len in [good.len() - 1, good.len() / 2, HEADER_LEN + 16] {
            assert!(decode_rcq2(&key, &good[..len]).is_err(), "cut at {len}");
        }
    }

    #[test]
    fn save_atomic_writes_0600_and_never_follows_a_planted_temp_symlink() {
        let s = scratch();
        let path = s.data.join("queue.rcq");
        let victim = s.other.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("rcq2.tmp")).unwrap();
        save_atomic(&path, b"sealed").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"sealed");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep",
            "symlink target untouched"
        );
        assert!(!path.with_extension("rcq2.tmp").exists());
    }

    #[tokio::test]
    async fn an_undecryptable_file_is_deleted_and_the_relay_starts_empty() {
        let s = scratch();
        let key = s.memory.join("queue.key");
        write_key(&key, 32, 0o600);
        let data = s.data.join("queue.rcq");
        let foreign = PersistedQueuesV2 {
            id_key: tags::id_key(),
            saved_at_unix_secs: 1,
            queues: vec![PersistedQueue {
                tag: [0x36; 32],
                messages: vec![msg(crate::protocol::timestamp(), false)],
            }],
        };
        std::fs::write(&data, encode_rcq2(&[0x99; 32], &foreign).unwrap()).unwrap();
        let config = ServerConfig {
            offline_queue: cfg(&data, &key),
            ..test_config()
        };
        let server = Server::new_with_persist_env(config, &env(&s))
            .await
            .unwrap();
        assert!(!data.exists(), "deleted even though it does not decrypt");
        assert!(server.state().message_queues.is_empty());
        assert!(server.queue_saver().is_some());
    }

    async fn created(
        ws: &mut Ws,
    ) -> (
        crate::protocol::CircuitId,
        Vec<u8>,
        crate::protocol::CircuitId,
    ) {
        loop {
            match next_control(ws, Duration::from_secs(3)).await {
                Some(crate::protocol::unified::ControlMessage::CircuitCreatedV3 {
                    circuit_id,
                    token,
                    target_circuit_id,
                    ..
                }) => return (circuit_id, token, target_circuit_id),
                Some(_) => continue,
                None => panic!("no CircuitCreatedV3"),
            }
        }
    }

    fn relay_on(
        target: crate::protocol::CircuitId,
        my_token: &[u8],
        payload: Vec<u8>,
    ) -> tokio_tungstenite::tungstenite::Message {
        use crate::protocol::relay::{CircuitToken, RelayPacket};
        let mut key = [0u8; 32];
        key.copy_from_slice(my_token);
        let token = CircuitToken {
            circuit_id: target,
            key,
            expires_at: std::time::Instant::now() + Duration::from_secs(60),
        };
        let mut p = RelayPacket::new(target, payload.clone());
        p.auth_tag = token.authenticate(&target, &payload);
        crate::protocol::unified::UnifiedFrame::relay(p).encode()
    }

    #[tokio::test]
    async fn p1_rcq2_holds_no_identities_survives_restart_and_is_deleted_on_load() {
        use futures_util::{SinkExt, StreamExt};
        let s = scratch();
        let key_path = s.memory.join("queue.key");
        std::fs::write(&key_path, rand::random::<[u8; 32]>()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let data_path = s.data.join("queue.rcq");
        let config = ServerConfig {
            offline_queue: cfg(&data_path, &key_path),
            ..test_config()
        };

        // Run 1: a queued message for B (offline member) and a knock for C.
        let server = Server::new_with_persist_env(config.clone(), &env(&s))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let saver = server.queue_saver().expect("persistence on");
        let state = server.state();
        let run1 = tokio::spawn(server.run());
        let (a, b, c) = (
            TestIdentity::from_seed(0xd1),
            TestIdentity::from_seed(0xd2),
            TestIdentity::from_seed(0xd3),
        );
        let mut wa = authed(addr, &a).await;
        let mut wb = authed(addr, &b).await;
        wa.send(ask(&b, rand::random(), None)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        wb.send(ask(&a, rand::random(), None)).await.unwrap();
        let ca = created(&mut wa).await;
        drop(wb);
        let st = state.clone();
        let bb = b.bytes;
        eventually("B gone", move || {
            !st.connections.iter().any(|x| x.proven_identity == Some(bb))
        })
        .await;
        let message_id = [0x5e; 16];
        let mut payload = vec![0x02];
        payload.extend_from_slice(&message_id);
        payload.resize(200, 0x11);
        wa.send(relay_on(ca.2, &ca.1, payload.clone()))
            .await
            .unwrap();
        wa.send(ask(&c, rand::random(), None)).await.unwrap();
        let st = state.clone();
        let (bt, ct) = (tags::id_tag(&b.bytes), tags::id_tag(&c.bytes));
        eventually("both queued", move || {
            st.message_queues.contains_key(&bt) && st.message_queues.contains_key(&ct)
        })
        .await;
        saver.save_now().unwrap();
        run1.abort();

        // The file: no identities, no message ids, unreadable with another key.
        let bytes = std::fs::read(&data_path).unwrap();
        for id in [&a, &b, &c] {
            assert!(!bytes.windows(32).any(|w| w == id.bytes));
            assert!(!String::from_utf8_lossy(&bytes).contains(&id.hex));
        }
        assert!(
            !bytes.windows(16).any(|w| w == message_id),
            "message id not in clear"
        );
        let key = read_key(&key_path).unwrap();
        let body = decode_rcq2(&key, &bytes).unwrap();
        let PersistedQueuesV2 {
            id_key: _,
            saved_at_unix_secs: _,
            queues,
        } = &body;
        for q in queues {
            for id in [&a, &b, &c] {
                assert_ne!(q.tag, id.bytes, "queues are filed under keyed tags");
            }
        }
        assert!(decode_rcq2(&[0u8; 32], &bytes).is_err());

        // Run 2 on the same paths: loads, deletes the file, delivers.
        let server2 = Server::new_with_persist_env(config, &env(&s))
            .await
            .unwrap();
        assert!(!data_path.exists(), "file deleted on load");
        let state2 = server2.state();
        assert_eq!(
            state2.knocks.index_len(),
            0,
            "knock index empty after restart"
        );
        assert!(state2.knocks.used() > 0, "restored knock still accounted");
        let addr2 = server2.local_addr().unwrap();
        tokio::spawn(server2.run());

        // B publishes by hand so the QueuedMessage frames (sent before the
        // publish response) are observed.
        let mut wb2 = connect(addr2).await;
        let nonce = hello(&mut wb2).await;
        let binding = rchat_core::keyauth::dev_origin_binding(
            &rchat_core::keyauth::relay_origin(DEV_ORIGIN).unwrap(),
        )
        .unwrap();
        wb2.send(publish_message(&b, &nonce, &binding))
            .await
            .unwrap();
        // The publish response comes first; the queued frames follow it.
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), wb2.next())
                .await
                .expect("frames after publish")
                .unwrap()
                .unwrap();
            match crate::protocol::unified::UnifiedFrame::decode(&m) {
                Ok(crate::protocol::unified::UnifiedFrame::Control(
                    crate::protocol::unified::ControlMessage::QueuedMessage { .. },
                )) => panic!("queued frame before the publish response"),
                Ok(crate::protocol::unified::UnifiedFrame::Signaling(sig))
                    if sig.msg_type
                        == crate::protocol::signaling::MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE =>
                {
                    break
                }
                _ => {}
            }
        }
        let delivered: Vec<Vec<u8>> = crate::signaling::test_support::frames_until_quiet(
            &mut wb2,
            Duration::from_millis(300),
        )
        .await
        .into_iter()
        .filter_map(|f| match f {
            crate::protocol::unified::UnifiedFrame::Control(
                crate::protocol::unified::ControlMessage::QueuedMessage { payload },
            ) => Some(payload),
            _ => None,
        })
        .collect();
        assert!(
            delivered.contains(&payload),
            "queued message delivered after restart"
        );
        assert!(!state2.message_queues.contains_key(&bt));
    }

    #[tokio::test]
    async fn p4_allow_persistent_key_starts_with_a_warning() {
        use std::sync::{Arc as StdArc, Mutex};
        #[derive(Clone, Default)]
        struct Cap(StdArc<Mutex<Vec<u8>>>);
        impl std::io::Write for Cap {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let cap = Cap::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let s = scratch();
        let key = s.other.join("queue.key");
        write_key(&key, 32, 0o600);
        let mut oq = cfg(&s.data.join("q.rcq"), &key);
        oq.allow_persistent_key = true;
        let config = ServerConfig {
            offline_queue: oq,
            ..test_config()
        };
        assert!(Server::new_with_persist_env(config, &env(&s)).await.is_ok());
        let logs = String::from_utf8_lossy(&cap.0.lock().unwrap()).to_string();
        assert!(
            logs.contains("allow_persistent_key"),
            "warning logged: {logs}"
        );
    }
}
