//! Chat session management
//!
//! This module manages individual chat sessions with recipients,
//! including the Double Ratchet state, message queue, and delivery tracking.

use crate::crypto::{DoubleRatchet, RatchetHeader, RatchetSnapshotV1};
use crate::protocol::{CircuitId, MessageId, MessageType};
use crate::RChatError;
use std::collections::VecDeque;
use tokio::time::{Duration, Instant};

/// State for an individual chat session
pub struct ChatSession {
    /// Recipient's identity (public key hex)
    pub recipient_identity: String,
    /// Double Ratchet state for encryption
    pub ratchet: Option<DoubleRatchet>,
    /// Pending messages waiting to be sent (e.g., while establishing session)
    pub pending_messages: VecDeque<PendingMessage>,
    /// Whether the session is fully established
    pub is_established: bool,
    /// Whether we are the initiator (Alice) or responder (Bob)
    pub is_initiator: bool,
    /// Whether we need to send a hello sync message (initiator only)
    pub needs_hello_sync: bool,
    /// Circuit ID for this session (if using circuit relay)
    pub circuit_id: Option<CircuitId>,
    /// Target circuit ID (for sending to recipient)
    pub target_circuit_id: Option<CircuitId>,
    /// Session token for authentication
    pub session_token: Option<Vec<u8>>,
    /// When the session was created
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// AEAD associated data for our sends: IK_us || IK_peer (spec §4.4).
    ad_send: Option<[u8; 64]>,
    /// AEAD associated data for the peer's messages: IK_peer || IK_us.
    ad_recv: Option<[u8; 64]>,
    /// Transport epoch in which this session's circuit was set up (resume, §6.3).
    pub circuit_epoch: u64,
    /// This session replaced an established one (spec §18.6): local
    /// evidence for `SessionReplaced`.
    pub replaced_established: bool,
    /// The peer's `no_prior_session` verdict for this session has arrived:
    /// a notice or a receipt from the peer decrypted under this session
    /// while it was current. A receipt counts because the sender holds its
    /// receipts while a flagged notice is still owed, so a flagged notice
    /// always leaves before them (`send_receipts_now`). Persisted.
    pub peer_notice_heard: bool,
    /// `peer_notice_heard` was set and no write has carried it yet: the
    /// tick retries the write (`redrive_owed_sends`); any successful write
    /// of the peer's record clears it (`after_durable`). Memory only.
    pub heard_unrecorded: bool,
    /// What the peer's `no_prior_session` flag on this session reports
    /// (spec §18.6 D37): Some(t) is a reset whose reason-3 reports cover our
    /// sends before unix time t; None reports none. Set at install from the
    /// session it replaced. The peer's flag describes the last session it
    /// announced to us, so a replaced session that never heard the peer's
    /// notice hands its own value on (Task 11 follow-up). Cleared once the
    /// reset is raised. Persisted.
    pub reset_since_unix: Option<u64>,
    /// `SessionReplaced` is still owed: raised by the first successful
    /// write of this session (spec §18.6, D28 "durable before announced").
    pub replaced_unannounced: bool,
    /// This session answered an ask and is not on disk yet: the meta record
    /// keeps naming the ask until its first successful write (D33).
    pub ask_answered_unrecorded: bool,
    /// Agreement key of the bundle this session was made from (D38 guard 2).
    pub peer_ak: [u8; 32],
    /// Wall-clock creation time (spec §18.2).
    pub created_at_unix: u64,
    /// Our sent ids a notice under this session reported lost, with the
    /// reason last reported and whether this session made the id eligible
    /// for an automatic resend (D38). Gone with the session: a new install
    /// starts empty. Persisted with it, so a restart keeps it.
    pub reported_lost: std::collections::HashMap<[u8; 16], (u8, bool)>,
    /// `device_key::session_binding` of this session's X3DH secret, set at
    /// install and persisted: what a notice signature is bound to (D45).
    pub session_binding: [u8; 32],
    /// A session we initiated (role 0) whose session-init (§A.4) the peer
    /// has not yet answered: the first message sealed under the session
    /// travels as the init, and the init is re-sent byte for byte on each
    /// new transport until the peer's first reply (or `ASK_TTL`). Cleared
    /// by the first message decrypted from the peer under this session.
    /// Persisted.
    pub init_out: Option<Box<InitOut>>,
    /// The pair secret PS (§C.1), derived from SK at install on either
    /// role and wiped on drop. Never logged; this struct has no `Debug`.
    /// `None` only for a placeholder session with no ratchet. Persisted.
    pub pair_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// The pair epoch (§C.1): `(utc day at install, 0)` for a session from
    /// an identity ask; carried over (already advanced at the match) for a
    /// session from a blind match. Persisted.
    pub pair_epoch: crate::pairing::PairEpoch,
    /// This session came from a blind match (§C.2): its circuit is never
    /// resumed by id, and the peer is known to hold PS. Persisted.
    pub blinded: bool,
    /// Unix time of the first blind ask left unmatched since this session
    /// was installed (R20, §C.4): the identity fallback is due once it is
    /// `IDENTITY_FALLBACK_AFTER_SECS` old. A new session starts with none.
    /// Persisted.
    pub blind_since_unix: Option<u64>,
    /// Unix time of the last identity fallback ask to the peer (R20: at
    /// most one per `IDENTITY_FALLBACK_INTERVAL_SECS`), carried from session
    /// to session. Persisted.
    pub last_identity_fallback_unix: Option<u64>,
}

/// The initiator's session-init for one session (protocol v3 §A.4). Holds
/// no secret: `ct` went on the wire, and `confirm` is a MAC over it.
#[derive(Clone)]
pub struct InitOut {
    pub ct: Box<[u8; crate::kem::KEM_CT_LEN]>,
    pub confirm: [u8; 32],
    /// The sealed init once it was built: re-sent as these bytes.
    pub sent: Option<SentInit>,
}

/// A session-init as first sealed.
#[derive(Clone)]
pub struct SentInit {
    pub id: [u8; 16],
    pub payload: Vec<u8>,
    /// Transport epoch it was last sent on: it is re-sent on a later one.
    pub epoch: u64,
}

/// A message waiting to be sent
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: MessageId,
    pub content: Vec<u8>,
    pub msg_type: MessageType,
    pub timestamp_ms: u64,
}

/// The queued plaintext is wiped when the message goes (R30 M-3).
impl Drop for PendingMessage {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.content);
    }
}

/// Session establishment state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state - no session exists
    None,
    /// X3DH handshake in progress
    Handshaking,
    /// Session established, ready to send/receive
    Established,
    /// Session failed (e.g., recipient not found)
    Failed,
}

impl ChatSession {
    /// Create a new session for a recipient
    pub fn new(recipient_identity: String) -> Self {
        let now = Instant::now();
        Self {
            recipient_identity,
            ratchet: None,
            pending_messages: VecDeque::new(),
            is_established: false,
            is_initiator: false,
            needs_hello_sync: false,
            circuit_id: None,
            target_circuit_id: None,
            session_token: None,
            created_at: now,
            last_activity: now,
            ad_send: None,
            ad_recv: None,
            circuit_epoch: 0,
            replaced_established: false,
            peer_notice_heard: false,
            heard_unrecorded: false,
            reset_since_unix: None,
            replaced_unannounced: false,
            ask_answered_unrecorded: false,
            peer_ak: [0; 32],
            created_at_unix: crate::unix_now_secs(),
            reported_lost: std::collections::HashMap::new(),
            session_binding: [0; 32],
            init_out: None,
            pair_secret: None,
            pair_epoch: crate::pairing::PairEpoch { day: 0, counter: 0 },
            blinded: false,
            blind_since_unix: None,
            last_identity_fallback_unix: None,
        }
    }

    /// A one-way tag of the pair secret: equal for sessions of one PS
    /// lineage (an identity install and the blind re-pairs since). A
    /// message sealed under an earlier session of the same lineage may be
    /// re-sealed under this one (R19): only the holder of that PS can have
    /// matched the blind asks in between. Never logged.
    pub fn pair_lineage(&self) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let ps = self.pair_secret.as_ref()?;
        let mut h = Sha256::new();
        h.update(b"rchat/pair-lineage/v3\0");
        h.update(&ps[..]);
        Some(h.finalize().into())
    }

    pub fn set_identities(&mut self, our_ik: [u8; 32], peer_ik: [u8; 32]) {
        let mut send = [0u8; 64];
        send[..32].copy_from_slice(&our_ik);
        send[32..].copy_from_slice(&peer_ik);
        let mut recv = [0u8; 64];
        recv[..32].copy_from_slice(&peer_ik);
        recv[32..].copy_from_slice(&our_ik);
        self.ad_send = Some(send);
        self.ad_recv = Some(recv);
    }

    /// The peer's Ed25519 identity, once bound.
    pub fn peer_identity_key(&self) -> Option<[u8; 32]> {
        self.ad_recv.and_then(|r| r[..32].try_into().ok())
    }

    /// Initialize as Alice (initiator) with recipient's public key
    /// - root_key: X3DH shared secret
    /// - our_ephemeral_key: Our ephemeral secret key (from X3DH)
    /// - recipient_agreement_key: Recipient's X25519 public key
    ///
    /// Secrets are borrowed (Task 13 minor): the caller keeps them in
    /// wiped buffers, and no unwiped by-value copy is made at the call.
    pub fn initialize_alice(
        &mut self,
        root_key: &[u8; 32],
        our_ephemeral_key: &[u8; 32],
        recipient_agreement_key: [u8; 32],
    ) -> Result<(), RChatError> {
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

        let ephemeral_secret = X25519SecretKey::from(*our_ephemeral_key);
        let remote_key = X25519PublicKey::from(recipient_agreement_key);
        let mut ratchet = DoubleRatchet::new(*root_key);
        ratchet.initialize_alice(&ephemeral_secret, &remote_key)?;

        self.ratchet = Some(ratchet);
        self.is_initiator = true;
        self.is_established = true;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Initialize as Bob (responder)
    /// - root_key: X3DH shared secret
    /// - identity_key: Our X25519 identity secret key
    /// - alice_ephemeral_key: Alice's ephemeral public key (from X3DH)
    ///
    /// Secrets are borrowed, as in `initialize_alice`.
    pub fn initialize_bob(
        &mut self,
        root_key: &[u8; 32],
        identity_key: &[u8; 32],
        alice_ephemeral_key: [u8; 32],
    ) -> Result<(), RChatError> {
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

        let identity_secret = X25519SecretKey::from(*identity_key);
        let alice_ephemeral = X25519PublicKey::from(alice_ephemeral_key);
        let mut ratchet = DoubleRatchet::new(*root_key);
        ratchet.initialize_bob(&identity_secret, &alice_ephemeral)?;

        self.ratchet = Some(ratchet);
        self.is_initiator = false;
        self.is_established = true; // Session is established after X3DH completes
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Check if this session can send messages (has established ratchet with sending chain)
    pub fn can_send(&self) -> bool {
        if !self.is_established {
            return false;
        }
        self.ratchet
            .as_ref()
            .map(|r| r.has_sending_chain())
            .unwrap_or(false)
    }

    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, RatchetHeader), RChatError> {
        if !self.is_established {
            return Err(RChatError::SessionNotEstablished {
                identity: self.recipient_identity.clone(),
            });
        }
        let ad = self.ad_send.ok_or_else(|| RChatError::EncryptionFailed {
            message: "session identities not bound".to_string(),
        })?;
        let ratchet = self
            .ratchet
            .as_mut()
            .ok_or_else(|| RChatError::SessionNotEstablished {
                identity: self.recipient_identity.clone(),
            })?;
        let (ciphertext, header) = ratchet.encrypt(plaintext, &ad)?;
        self.last_activity = Instant::now();
        Ok((ciphertext, header))
    }

    /// Decrypt a message from this session (identities must be bound).
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        header: &RatchetHeader,
    ) -> Result<Vec<u8>, RChatError> {
        let ad = self.ad_recv.ok_or_else(|| RChatError::DecryptionFailed {
            message: "session identities not bound".to_string(),
        })?;
        let ratchet = self
            .ratchet
            .as_mut()
            .ok_or_else(|| RChatError::SessionNotEstablished {
                identity: self.recipient_identity.clone(),
            })?;
        let plaintext = ratchet.decrypt(ciphertext, header, &ad)?;
        self.last_activity = Instant::now();
        if !self.is_established {
            self.is_established = true;
        }
        Ok(plaintext)
    }

    /// Queue a message to be sent once session is established
    pub fn queue_message(&mut self, content: Vec<u8>, msg_type: MessageType) -> MessageId {
        let id = MessageId::new();
        let msg = PendingMessage {
            id: id.clone(),
            content,
            msg_type,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        self.pending_messages.push_back(msg);
        id
    }

    /// Get and clear pending messages (call after session is established)
    pub fn take_pending_messages(&mut self) -> VecDeque<PendingMessage> {
        std::mem::take(&mut self.pending_messages)
    }

    /// Check if session has timed out due to inactivity
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Set circuit information for relay
    pub fn set_circuit(
        &mut self,
        circuit_id: CircuitId,
        target_circuit_id: CircuitId,
        token: Vec<u8>,
    ) {
        self.circuit_id = Some(circuit_id);
        self.target_circuit_id = Some(target_circuit_id);
        self.session_token = Some(token);
    }

    /// Get the session token as a 32-byte array (for auth tag computation)
    pub fn get_token_key(&self) -> Option<[u8; 32]> {
        self.session_token.as_ref().and_then(|token| {
            if token.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&token[..32]);
                Some(key)
            } else {
                None
            }
        })
    }

    /// The ratchet's full snapshot (spec §18.2.1), if the session has one.
    pub fn ratchet_snapshot(&self) -> Option<RatchetSnapshotV1> {
        self.ratchet.as_ref().map(|r| r.snapshot())
    }
}

/// A replaced session kept decrypt-only (spec §4.4 rule 8): one per peer,
/// for at most 72 h or 1,000 messages.
pub const RETIRED_MAX_AGE: Duration = Duration::from_secs(72 * 3600);
pub const RETIRED_MAX_DECRYPTS: u32 = 1000;

struct RetiredSession {
    session: ChatSession,
    /// Wall clock, so the 72 h limit holds across restarts (D31).
    retired_at_unix: u64,
    decrypts: u32,
}

/// Which session decrypted a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptedBy {
    Current,
    Retired,
}

/// The retired session's ratchet, retirement time, decrypt count and the
/// agreement key it was made under.
pub type RetiredParts = (RatchetSnapshotV1, u64, u32, [u8; 32]);

/// The current ratchet, and the retired one with its decrypt count: what
/// a receive rolls back to when its write fails (D28).
pub type RatchetSnapshots = (Option<RatchetSnapshotV1>, Option<(RatchetSnapshotV1, u32)>);

/// A retirement time in the future (the clock stepped back) is re-stamped
/// to now, so the 72 h limit is never stretched (Task 1 clock ruling).
fn restamp_future(r: &mut RetiredSession, now_unix: u64) {
    r.retired_at_unix = r.retired_at_unix.min(now_unix);
}

fn identity_bytes(identity_hex: &str) -> Option<[u8; 32]> {
    hex::decode(identity_hex).ok()?.try_into().ok()
}

/// Manages all chat sessions
pub struct SessionManager {
    sessions: dashmap::DashMap<String, ChatSession>,
    /// How long before a session times out due to inactivity
    pub session_timeout: Duration,
    /// How long to wait for delivery confirmation before retry
    pub delivery_timeout: Duration,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// The single retired session per peer.
    retired: dashmap::DashMap<String, RetiredSession>,
    /// Our Ed25519 identity, bound into every session created from now on.
    our_identity: Option<[u8; 32]>,
    /// Tests: calls to `ratchet_snapshots`.
    #[cfg(test)]
    snapshot_calls: std::sync::atomic::AtomicU64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
            session_timeout: Duration::from_secs(3600), // 1 hour
            delivery_timeout: Duration::from_secs(30),
            max_retries: 3,
            retired: dashmap::DashMap::new(),
            our_identity: None,
            #[cfg(test)]
            snapshot_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get or create a session for a recipient. New sessions get both
    /// identities bound once ours is known and the id is 64 hex.
    pub fn get_or_create(
        &self,
        recipient_identity: String,
    ) -> dashmap::mapref::one::RefMut<'_, String, ChatSession> {
        let our = self.our_identity;
        let key = recipient_identity.clone();
        self.sessions.entry(key).or_insert_with(|| {
            let mut session = ChatSession::new(recipient_identity.clone());
            if let (Some(our_ik), Some(peer_ik)) = (our, identity_bytes(&recipient_identity)) {
                session.set_identities(our_ik, peer_ik);
            }
            session
        })
    }

    pub fn set_our_identity(&mut self, our_ik: [u8; 32]) {
        self.our_identity = Some(our_ik);
    }

    /// Install a session for a peer. An established predecessor becomes the
    /// one retired session; any older retired session is discarded.
    ///
    /// What the peer's `no_prior_session` flag on the new session will
    /// report (`reset_since_unix`): if the predecessor heard the peer's
    /// notice, the peer's next flag is about the new session, which reports
    /// a reset since now when it replaced an established session. If the
    /// predecessor never heard it, the peer's verdict for the predecessor
    /// is still owed and arrives on the new session (the peer keeps an owed
    /// flag across installs), so the predecessor's value carries over.
    pub fn install(&self, peer_hex: String, mut session: ChatSession) {
        if let Some(old) = self.sessions.get(&peer_hex) {
            session.replaced_established = old.is_established;
            session.reset_since_unix = if old.ratchet.is_none() {
                None // a placeholder is no session (F32)
            } else if old.peer_notice_heard {
                old.is_established.then_some(session.created_at_unix)
            } else {
                old.reset_since_unix
            };
        }
        if let Some(old) = self.sessions.insert(peer_hex.clone(), session) {
            if old.is_established {
                self.retired.insert(
                    peer_hex,
                    RetiredSession {
                        session: old,
                        retired_at_unix: crate::unix_now_secs(),
                        decrypts: 0,
                    },
                );
            }
        }
    }

    /// Decrypt a message from a peer: current session first, then the
    /// retired one. Failed attempts change neither (decrypt is transactional).
    pub fn decrypt_from(
        &self,
        peer_hex: &str,
        ciphertext: &[u8],
        header: &RatchetHeader,
    ) -> Result<(Vec<u8>, DecryptedBy), RChatError> {
        self.decrypt_bound(peer_hex, ciphertext, header)
            .map(|(plaintext, by, _)| (plaintext, by))
    }

    /// `decrypt_from`, also returning the `session_binding` of the session
    /// that decrypted, read from that very session: Some for the current
    /// session only (a notice's signature is checked against it, D46).
    pub fn decrypt_bound(
        &self,
        peer_hex: &str,
        ciphertext: &[u8],
        header: &RatchetHeader,
    ) -> Result<(Vec<u8>, DecryptedBy, Option<[u8; 32]>), RChatError> {
        let current = self.sessions.get_mut(peer_hex).map(|mut s| {
            s.decrypt_message(ciphertext, header)
                .map(|plaintext| (plaintext, s.session_binding))
        });
        let current = match current {
            Some(Ok((plaintext, binding))) => {
                return Ok((plaintext, DecryptedBy::Current, Some(binding)));
            }
            Some(Err(e)) => Some(Err::<(), _>(e)),
            None => None,
        };
        let now = crate::unix_now_secs();
        if let Some(mut r) = self.retired.get_mut(peer_hex) {
            restamp_future(&mut r, now);
        }
        // An exhausted retired session goes here, before a 1,001st decrypt,
        // not right after its 1,000th: that decrypt may still be rolled
        // back if its write fails (D28).
        self.retired.remove_if(peer_hex, |_, r| {
            now.saturating_sub(r.retired_at_unix) > RETIRED_MAX_AGE.as_secs()
                || r.decrypts >= RETIRED_MAX_DECRYPTS
        });
        let retired = self.retired.get_mut(peer_hex).map(|mut r| {
            let result = r.session.decrypt_message(ciphertext, header);
            if result.is_ok() {
                r.decrypts += 1;
            }
            result
        });
        match retired {
            Some(Ok(plaintext)) => Ok((plaintext, DecryptedBy::Retired, None)),
            Some(Err(e)) => Err(e),
            None => match current {
                Some(Err(e)) => Err(e),
                _ => Err(RChatError::SessionNotEstablished {
                    identity: peer_hex.to_string(),
                }),
            },
        }
    }

    /// Drop retired sessions past 72 h or 1,000 decrypts (C-13): their keys
    /// must not outlive the limit just because the peer went quiet.
    /// Returns the peers whose retired session went.
    pub fn purge_expired_retired(&self, now_unix: u64) -> Vec<String> {
        let mut dropped = Vec::new();
        self.retired.retain(|peer, r| {
            restamp_future(r, now_unix);
            let keep = now_unix.saturating_sub(r.retired_at_unix) <= RETIRED_MAX_AGE.as_secs()
                && r.decrypts < RETIRED_MAX_DECRYPTS;
            if !keep {
                dropped.push(peer.clone());
            }
            keep
        });
        dropped
    }

    /// Install a session and a retired one rebuilt from a stored record
    /// (spec §18.5); either may be absent.
    pub fn install_restored(
        &self,
        peer: String,
        current: Option<ChatSession>,
        retired: Option<(ChatSession, u64, u32)>,
    ) {
        // A session already in memory is newer than any record of it
        // (a second restore after `disconnect`/`connect`): kept.
        if let Some(c) = current {
            self.sessions.entry(peer.clone()).or_insert(c);
        }
        if let Some((session, retired_at_unix, decrypts)) = retired {
            self.retired.entry(peer).or_insert(RetiredSession {
                session,
                retired_at_unix,
                decrypts,
            });
        }
    }

    /// Purge expired skipped keys in every ratchet, current and retired
    /// (D31, on the tick); returns the peers changed.
    pub fn purge_expired_skipped(&self, now_unix: u64) -> Vec<String> {
        let mut changed = Vec::new();
        for mut e in self.sessions.iter_mut() {
            let purged = e
                .ratchet
                .as_mut()
                .map_or(0, |r| r.purge_expired_skipped(now_unix));
            if purged > 0 {
                changed.push(e.key().clone());
            }
        }
        for mut e in self.retired.iter_mut() {
            let purged = e
                .session
                .ratchet
                .as_mut()
                .map_or(0, |r| r.purge_expired_skipped(now_unix));
            if purged > 0 && !changed.contains(e.key()) {
                changed.push(e.key().clone());
            }
        }
        changed
    }

    /// Drop the peer's retired session once it has used its 1,000
    /// decrypts (call after that decrypt's write succeeded). True if dropped.
    pub fn drop_exhausted_retired(&self, peer: &str) -> bool {
        self.retired
            .remove_if(peer, |_, r| r.decrypts >= RETIRED_MAX_DECRYPTS)
            .is_some()
    }

    /// Expire the peer's skipped keys, current and retired, before a write
    /// (D31): the record never carries a key past its 72 h.
    pub fn purge_expired_skipped_for(&self, peer: &str, now_unix: u64) {
        if let Some(mut s) = self.sessions.get_mut(peer) {
            if let Some(r) = s.ratchet.as_mut() {
                r.purge_expired_skipped(now_unix);
            }
        }
        if let Some(mut r) = self.retired.get_mut(peer) {
            if let Some(ratchet) = r.session.ratchet.as_mut() {
                ratchet.purge_expired_skipped(now_unix);
            }
        }
    }

    /// The retired session's ratchet, retirement time and decrypt count.
    pub fn retired_parts(&self, peer: &str) -> Option<RetiredParts> {
        let r = self.retired.get(peer)?;
        Some((
            r.session.ratchet_snapshot()?,
            r.retired_at_unix,
            r.decrypts,
            r.session.peer_ak,
        ))
    }

    /// Ids of the messages queued on the peer's session (spec §18.2).
    pub fn pending_ids(&self, peer: &str) -> Vec<[u8; 16]> {
        self.sessions
            .get(peer)
            .map(|s| {
                s.pending_messages
                    .iter()
                    .filter_map(|m| crate::circuits::message_id_from_hex(&m.id.0))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn ratchet_snapshots(&self, peer: &str) -> RatchetSnapshots {
        #[cfg(test)]
        self.snapshot_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (
            self.sessions.get(peer).and_then(|s| s.ratchet_snapshot()),
            self.retired
                .get(peer)
                .and_then(|r| Some((r.session.ratchet_snapshot()?, r.decrypts))),
        )
    }

    /// Put back the ratchets `ratchet_snapshots` took (a failed write, D28).
    pub fn restore_ratchets(
        &self,
        peer: &str,
        before: RatchetSnapshots,
        id: Option<&x25519_dalek::StaticSecret>,
    ) {
        // A snapshot that does not restore leaves the ratchet as it is:
        // advanced, but never gone.
        if let (Some(s), Some(mut cur)) = (before.0, self.sessions.get_mut(peer)) {
            if let Ok(r) = DoubleRatchet::from_snapshot(&s, id) {
                cur.ratchet = Some(r);
            }
        }
        if let (Some((s, d)), Some(mut r)) = (before.1, self.retired.get_mut(peer)) {
            if let Ok(ratchet) = DoubleRatchet::from_snapshot(&s, id) {
                r.session.ratchet = Some(ratchet);
                r.decrypts = d;
            }
        }
    }

    pub fn retired_count(&self, peer_hex: &str) -> usize {
        usize::from(self.retired.contains_key(peer_hex))
    }

    #[cfg(test)]
    pub fn age_retired_for_test(&self, peer_hex: &str, by_secs: u64) {
        if let Some(mut r) = self.retired.get_mut(peer_hex) {
            r.retired_at_unix -= by_secs;
        }
    }

    #[cfg(test)]
    pub fn set_retired_for_test(&self, peer_hex: &str, retired_at_unix: u64, decrypts: u32) {
        if let Some(mut r) = self.retired.get_mut(peer_hex) {
            r.retired_at_unix = retired_at_unix;
            r.decrypts = decrypts;
        }
    }

    #[cfg(test)]
    pub fn retired_parts_for_test(&self, peer_hex: &str) -> Option<(u64, u32)> {
        self.retired
            .get(peer_hex)
            .map(|r| (r.retired_at_unix, r.decrypts))
    }

    #[cfg(test)]
    pub fn snapshot_calls(&self) -> u64 {
        self.snapshot_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get a session if it exists
    pub fn get(
        &self,
        recipient_identity: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, ChatSession>> {
        self.sessions.get(recipient_identity)
    }

    /// Get a mutable session if it exists
    pub fn get_mut(
        &self,
        recipient_identity: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, ChatSession>> {
        self.sessions.get_mut(recipient_identity)
    }

    /// Check if a session exists and is established
    pub fn has_established_session(&self, recipient_identity: &str) -> bool {
        self.sessions
            .get(recipient_identity)
            .map(|s| s.is_established)
            .unwrap_or(false)
    }

    /// Check if any session exists
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Get the first established recipient
    pub fn get_first_established_recipient(&self) -> Option<String> {
        for entry in self.sessions.iter() {
            if entry.value().is_established {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// Remove a session
    pub fn remove(&self, recipient_identity: &str) -> Option<ChatSession> {
        self.sessions.remove(recipient_identity).map(|(_, v)| v)
    }

    /// Take every message still queued for the peer, oldest first: the
    /// retired session's queue, then the current session's.
    pub fn take_pending(&self, peer_hex: &str) -> VecDeque<PendingMessage> {
        let mut out = self
            .retired
            .get_mut(peer_hex)
            .map(|mut r| r.session.take_pending_messages())
            .unwrap_or_default();
        if let Some(mut s) = self.sessions.get_mut(peer_hex) {
            out.extend(s.take_pending_messages());
        }
        out
    }

    /// Drop the peer's current and retired sessions (unpin, block).
    pub fn forget(&self, peer_hex: &str) {
        self.sessions.remove(peer_hex);
        self.retired.remove(peer_hex);
    }

    /// Drop every current and retired session (Reset Identity, rotation).
    pub fn forget_all(&self) {
        self.sessions.clear();
        self.retired.clear();
    }

    /// Clean up timed out sessions
    pub fn cleanup_timeouts(&self) -> Vec<String> {
        let mut to_remove = Vec::new();

        for entry in self.sessions.iter() {
            if entry.value().is_timed_out(self.session_timeout) {
                to_remove.push(entry.key().clone());
            }
        }

        for identity in &to_remove {
            self.sessions.remove(identity);
        }

        to_remove
    }

    /// Get count of established sessions
    pub fn established_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|e| e.value().is_established)
            .count()
    }

    /// Get total session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Find session by circuit ID
    pub fn find_by_circuit_id(&self, circuit_id: &CircuitId) -> Option<String> {
        for entry in self.sessions.iter() {
            if let Some(ref cid) = entry.value().circuit_id {
                if cid.0 == circuit_id.0 {
                    return Some(entry.key().clone());
                }
            }
        }
        None
    }

    /// Find session by target circuit ID
    pub fn find_by_target_circuit_id(&self, target_circuit_id: &CircuitId) -> Option<String> {
        for entry in self.sessions.iter() {
            if let Some(ref cid) = entry.value().target_circuit_id {
                if cid.0 == target_circuit_id.0 {
                    return Some(entry.key().clone());
                }
            }
        }
        None
    }

    /// Get all recipient identities (for debugging)
    pub fn get_all_recipients(&self) -> Vec<String> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get session debug info (for debugging)
    pub fn get_session_debug(&self, recipient: &str) -> Option<String> {
        self.sessions.get(recipient).map(|s| {
            format!(
                "Session for {}: circuit_id={:?}, target_circuit_id={:?}, is_established={}",
                recipient,
                s.circuit_id.as_ref().map(|c| hex::encode(&c.0)),
                s.target_circuit_id.as_ref().map(|c| hex::encode(&c.0)),
                s.is_established
            )
        })
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two established sessions (A initiator, B responder) for `secret`.
    fn established_pair(secret: [u8; 32]) -> (ChatSession, ChatSession) {
        use x25519_dalek::{PublicKey, StaticSecret};
        let bob_agreement = StaticSecret::from([0x22u8; 32]);
        let bob_pub = PublicKey::from(&bob_agreement).to_bytes();
        let alice_eph = StaticSecret::from([secret[0] ^ 0x33; 32]);
        let alice_eph_pub = PublicKey::from(&alice_eph).to_bytes();
        let (ik_a, ik_b) = ([0xAAu8; 32], [0xBBu8; 32]);
        let mut alice = ChatSession::new(hex::encode(ik_b));
        alice.set_identities(ik_a, ik_b);
        alice
            .initialize_alice(&secret, &alice_eph.to_bytes(), bob_pub)
            .unwrap();
        let mut bob = ChatSession::new(hex::encode(ik_a));
        bob.set_identities(ik_b, ik_a);
        bob.initialize_bob(&secret, &bob_agreement.to_bytes(), alice_eph_pub)
            .unwrap();
        (alice, bob)
    }

    #[test]
    fn sessions_bind_identities_into_the_aead() {
        let (mut alice, mut bob) = established_pair([1; 32]);
        assert_eq!(bob.peer_identity_key(), Some([0xAA; 32]));
        let (ct, header) = alice.encrypt_message(b"x").unwrap();
        assert_eq!(bob.decrypt_message(&ct, &header).unwrap(), b"x");
        let (mut unbound, _) = established_pair([2; 32]);
        unbound.ad_send = None;
        assert!(matches!(
            unbound.encrypt_message(b"x"),
            Err(RChatError::EncryptionFailed { .. })
        ));
    }

    /// K13 + S3: one retired session per peer; it decrypts late messages
    /// after a replacement; a second replacement discards the oldest.
    #[test]
    fn k13_only_one_retired_session_and_it_decrypts_late_messages() {
        let (mut alice1, bob1) = established_pair([1; 32]);
        let (mut alice2, bob2) = established_pair([2; 32]);
        let (mut alice3, bob3) = established_pair([3; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob1);
        assert_eq!(mgr.retired_count(&peer), 0);
        let (c1, h1) = alice1.encrypt_message(b"one").unwrap();
        assert!(!mgr.get(&peer).unwrap().replaced_established);
        mgr.install(peer.clone(), bob2);
        assert_eq!(mgr.retired_count(&peer), 1);
        assert!(
            mgr.get(&peer).unwrap().replaced_established,
            "the new session replaced an established one"
        );
        assert_eq!(
            mgr.decrypt_from(&peer, &c1, &h1).unwrap(),
            (b"one".to_vec(), DecryptedBy::Retired),
            "retired session decrypts"
        );
        let (c1_late, h1_late) = alice1.encrypt_message(b"late").unwrap();
        mgr.install(peer.clone(), bob3);
        assert_eq!(
            mgr.retired_count(&peer),
            1,
            "still exactly one retired session"
        );
        assert!(
            mgr.decrypt_from(&peer, &c1_late, &h1_late).is_err(),
            "the oldest was discarded"
        );
        let (c2, h2) = alice2.encrypt_message(b"two").unwrap();
        assert_eq!(
            mgr.decrypt_from(&peer, &c2, &h2).map(|(p, _)| p).unwrap(),
            b"two"
        );
        let (c3, h3) = alice3.encrypt_message(b"three").unwrap();
        assert_eq!(
            mgr.decrypt_from(&peer, &c3, &h3).unwrap(),
            (b"three".to_vec(), DecryptedBy::Current),
            "current still works"
        );
    }

    #[test]
    fn retired_session_expires_after_72_hours() {
        let (mut alice1, bob1) = established_pair([1; 32]);
        let (_, bob2) = established_pair([2; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob1);
        mgr.install(peer.clone(), bob2);
        mgr.age_retired_for_test(&peer, RETIRED_MAX_AGE.as_secs() + 1);
        let (c, h) = alice1.encrypt_message(b"too late").unwrap();
        assert!(mgr.decrypt_from(&peer, &c, &h).is_err());
        assert_eq!(mgr.retired_count(&peer), 0);
    }

    #[test]
    fn retired_session_is_dropped_after_1000_decrypts() {
        let (mut alice1, bob1) = established_pair([1; 32]);
        let (_, bob2) = established_pair([2; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob1);
        mgr.install(peer.clone(), bob2);
        for i in 0..RETIRED_MAX_DECRYPTS {
            let (c, h) = alice1.encrypt_message(&i.to_be_bytes()).unwrap();
            assert!(mgr.decrypt_from(&peer, &c, &h).is_ok(), "decrypt {i}");
        }
        // Kept until its last decrypt is durable (D28), then dropped by the
        // caller or the timer's purge; never used for a 1,001st decrypt.
        assert_eq!(mgr.retired_count(&peer), 1);
        let (c, h) = alice1.encrypt_message(b"one more").unwrap();
        assert!(mgr.decrypt_from(&peer, &c, &h).is_err(), "no 1,001st");
        assert_eq!(mgr.retired_count(&peer), 0);
    }

    #[test]
    fn exhausted_retired_session_is_purged_or_dropped() {
        let (_, bob1) = established_pair([1; 32]);
        let (_, bob2) = established_pair([2; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob1);
        mgr.install(peer.clone(), bob2);
        let now = crate::unix_now_secs();
        mgr.set_retired_for_test(&peer, now, RETIRED_MAX_DECRYPTS - 1);
        assert!(!mgr.drop_exhausted_retired(&peer), "one decrypt left");
        mgr.set_retired_for_test(&peer, now, RETIRED_MAX_DECRYPTS);
        assert!(mgr.drop_exhausted_retired(&peer));
        assert_eq!(mgr.retired_count(&peer), 0);
    }

    /// Task 1 clock ruling: a retirement stamped in the future (the clock
    /// stepped back) is re-stamped to now, so 72 h still ends it.
    #[test]
    fn future_dated_retired_session_is_restamped() {
        let (_, bob1) = established_pair([1; 32]);
        let (_, bob2) = established_pair([2; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob1);
        mgr.install(peer.clone(), bob2);
        let now = crate::unix_now_secs();
        mgr.set_retired_for_test(&peer, now + 1000 * 86_400, 0);
        mgr.purge_expired_retired(now);
        assert_eq!(mgr.retired_parts_for_test(&peer), Some((now, 0)));
        mgr.purge_expired_retired(now + RETIRED_MAX_AGE.as_secs() + 1);
        assert_eq!(mgr.retired_count(&peer), 0);
    }

    /// A snapshot that cannot be restored never leaves the session without
    /// a ratchet.
    #[test]
    fn restore_ratchets_keeps_the_ratchet_when_a_snapshot_is_refused() {
        let (_, bob) = established_pair([1; 32]);
        let peer = hex::encode([0xAAu8; 32]);
        let mgr = SessionManager::new();
        mgr.install(peer.clone(), bob);
        let (cur, _) = mgr.ratchet_snapshots(&peer);
        let mut bad = cur.unwrap();
        bad.max_skip = crate::crypto::MAX_SKIPPED_KEYS as u32 + 1;
        mgr.restore_ratchets(&peer, (Some(bad), None), None);
        assert!(mgr.get(&peer).unwrap().ratchet.is_some());
    }

    #[test]
    fn get_or_create_binds_identities_once_ours_is_known() {
        let mut mgr = SessionManager::new();
        mgr.set_our_identity([0x11; 32]);
        let peer = hex::encode([0x22u8; 32]);
        assert_eq!(
            mgr.get_or_create(peer.clone()).peer_identity_key(),
            Some([0x22; 32])
        );
        assert_eq!(
            mgr.get_or_create("not-hex".to_string()).peer_identity_key(),
            None
        );
    }

    #[test]
    fn test_session_creation() {
        let session = ChatSession::new("test_identity".to_string());
        assert!(!session.is_established);
        assert_eq!(session.recipient_identity, "test_identity");
    }

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new();

        // Create session
        {
            let session = manager.get_or_create("alice".to_string());
            assert!(!session.is_established);
        }

        // Check exists
        assert!(manager.get("alice").is_some());
        assert!(!manager.has_established_session("alice"));

        // Remove
        manager.remove("alice");
        assert!(manager.get("alice").is_none());
    }

    #[test]
    fn test_message_queue() {
        let mut session = ChatSession::new("bob".to_string());

        let _id = session.queue_message(b"Hello".to_vec(), MessageType::Text);
        assert_eq!(session.pending_messages.len(), 1);

        let pending = session.take_pending_messages();
        assert_eq!(pending.len(), 1);
        assert!(session.pending_messages.is_empty());
    }
}
