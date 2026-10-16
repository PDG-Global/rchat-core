//! Circuits on the client (spec §4.4, §6.3; protocol v3 §A.3–A.4): verify
//! the relay's `CircuitCreatedV3`, run X3DH v3 (X25519 + ML-KEM-768), send
//! or await the session-init, and keep pins, blocks and sessions in step.

use crate::crypto::{x3dh_v3_initiator, RatchetHeader};
use crate::kem::KEM_PK_LEN;
use crate::keyauth;
use crate::knock;
use crate::notice;
use crate::peers::{key_from_hex, AskKeys, PeerKeyState, PinError};
use crate::persistence::{
    push_capped, unpush_capped, MAX_DELIVERED_UNSTORED, MAX_RECEIVED_IDS, MAX_UNDECRYPTABLE,
};
use crate::protocol::{CircuitId, ControlMessage, PacketFlags, PeerBundle, RelayPacket};
use crate::receipts;
use crate::sealed::{self, Opened, KIND_RATCHET};
use crate::session::{ChatSession, DecryptedBy, InitOut};
use crate::state_store::SentIdV1;
use crate::status::StatusEvent;
use crate::{
    ClientInner, MessageRequest, PendingEncrypted, RChatError, MAX_PENDING_BYTES,
    MAX_PENDING_ENCRYPTED, MAX_PENDING_ENTRY_BYTES, MAX_PENDING_PER_SENDER,
};
use constant_time_eq::constant_time_eq;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Queued receipts kept per peer and kind.
pub(crate) const MAX_PENDING_RECEIPTS: usize = 1024;
/// DecryptFailed events raised per peer per tick (final review M-1); the
/// ids beyond are still listed and reported in the notice.
pub(crate) const MAX_DECRYPT_FAILED_PER_TICK: u32 = 32;
/// Sent message ids remembered per peer for receipt binding.
pub(crate) const MAX_SENT_IDS: usize = 4096;
/// How long a user ask stays in flight on one connection: a second user
/// ask to the same peer inside it is suppressed (spec §18.6 D33).
pub(crate) const ASK_IN_FLIGHT: Duration = Duration::from_secs(5);
/// How far back a peer's session reset reports unconfirmed sends (reason 3),
/// and how long a reported-lost id may pass the duplicate drop.
pub(crate) const RESET_REPORT_MAX_AGE_SECS: u64 = 72 * 3600;
/// Most automatic resends per peer in any 24 h (spec §18.6 D38 guard 6).
pub(crate) const MAX_AUTO_RESENDS_PER_DAY: usize = 50;
/// The window `MAX_AUTO_RESENDS_PER_DAY` counts over.
const AUTO_RESEND_WINDOW_SECS: u64 = 24 * 3600;
/// While a peer's writes fail, the tick's re-drive probes at most this often.
pub(crate) const REDRIVE_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Where `unlist_lost` found an id: (reported position and stamp, unreported position).
type UnlistedLost = (Option<(usize, u64)>, Option<usize>);

/// "No resume" on the wire (spec §5.7): the client always sends `Some`, so
/// every ask has the same size, and the relay treats the all-zero id as none (§5.3).
pub(crate) const ZERO_CIRCUIT: CircuitId = CircuitId([0; 16]);

/// How long a pinned contact's knock digest is remembered (M-2): a knock
/// is accepted up to ~73 h after it is issued.
pub(crate) const KNOCK_SEEN_SECS: u64 = 74 * 3600;
/// Knock digests remembered per contact (M-2); the oldest goes first.
pub(crate) const MAX_KNOCKS_SEEN_PER_PEER: usize = 64;

/// Closes kept for the next accepted publish (M-1); the oldest goes first.
pub(crate) const MAX_PENDING_CLOSES: usize = 256;

/// Inner ratchet plaintext type of a rotation notice: `0x04 || block` (spec §4.8).
pub(crate) const ROTATION_NOTICE_TYPE: u8 = 0x04;
/// Inner ratchet plaintext type of a cover packet (spec §5.7).
pub(crate) const COVER_TYPE: u8 = 0x05;
/// Second byte of a cover packet: a request (answered) or a reply (never answered).
pub(crate) const COVER_REQUEST: u8 = 0x00;
pub(crate) const COVER_REPLY: u8 = 0x01;
/// Round-2 M5: cover packets (requests and replies) per peer per hour.
pub(crate) const MAX_COVER_PER_HOUR: usize = 20;
/// Security review L-2: cover replies per peer per hour. An honest peer
/// sends at most `MAX_COVER_PER_HOUR` requests an hour, each answered by
/// at most two replies, so every honest request is still answered; a peer
/// sending requests faster gets no more than this.
pub(crate) const MAX_COVER_REPLIES_PER_HOUR: usize = 2 * MAX_COVER_PER_HOUR;
/// Round-2 M5: cover goes only to peers heard from this recently.
pub(crate) const COVER_HEARD_WINDOW: Duration = Duration::from_secs(60);
const COVER_CAP_WINDOW: Duration = Duration::from_secs(3600);

/// Time to the next cover request: Exp(mean 45 s) clamped to 10-180 s;
/// `u` uniform in [0, 1).
pub(crate) fn cover_delay_for(u: f64) -> Duration {
    let u = if u.is_nan() {
        0.0
    } else {
        u.clamp(0.0, 0.999_999_999)
    };
    let secs = (-45.0 * (1.0 - u).ln()).clamp(10.0, 180.0);
    Duration::from_millis((secs * 1000.0).round() as u64)
}

/// What started an ask: the user (sent now) or an automatic trigger (scheduled with backoff).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskTrigger {
    User,
    Auto,
}

/// The knock clock: whole hours since the Unix epoch.
pub(crate) fn now_hour() -> u64 {
    crate::unix_now_secs() / 3600
}

/// The fields of `ControlMessage::CircuitCreatedV3`.
pub(crate) struct CircuitCreatedV3Frame {
    pub circuit_id: CircuitId,
    pub token: Vec<u8>,
    pub target_circuit_id: CircuitId,
    pub role: u8,
    pub peer: PeerBundle,
    pub initiator_ephemeral_key: Vec<u8>,
    pub responder_ephemeral_key: Vec<u8>,
    /// ML-KEM-768 ephemeral public keys of both asks (§A.3). Task 3 checks
    /// only their shape; X3DH v3 (Task 4) encapsulates to the responder's.
    pub initiator_kem_ephemeral_pk: Vec<u8>,
    pub responder_kem_ephemeral_pk: Vec<u8>,
    /// Each asker's identity signature over its ephemerals (ruling R7).
    pub initiator_ephemeral_sig: Vec<u8>,
    pub responder_ephemeral_sig: Vec<u8>,
}

/// The longest a responder waits for a session-init, wall clock: the
/// relay's offline-queue TTL (72 h). Past it the init can no longer reach
/// us, so the wait is dropped and the pair asked again (ruling R8).
pub(crate) const PENDING_INIT_MAX_AGE_SECS: u64 = 72 * 3600;

/// A responder's wait for session-init (§A.3): the ask's ephemerals and
/// the circuit the relay set up. Secrets are wiped when it drops.
pub(crate) struct PendingInit {
    /// Our ask's ML-KEM-768 ephemeral, and the seed it was built from (R4).
    pub kem: crate::kem::KemKeyPair,
    pub kem_seed: Zeroizing<[u8; crate::kem::KEM_SEED_LEN]>,
    /// Our ask's X25519 ephemeral secret (wipes itself on drop).
    pub ek_r: crate::crypto::X25519SecretKey,
    /// The initiator's X25519 ephemeral (public).
    pub i_ek: [u8; 32],
    /// The agreement key of the verified, pinned bundle.
    pub peer_ak: [u8; 32],
    pub circuit_id: CircuitId,
    pub target_circuit_id: CircuitId,
    pub token: Zeroizing<[u8; 32]>,
    /// Transport epoch the circuit was set up (or resumed) in.
    pub circuit_epoch: u64,
    /// Unix time the wait ends: `ASK_TTL` of online time (pushed back on
    /// every reconnect and restore, ruling R8), never past
    /// `created_at_unix + PENDING_INIT_MAX_AGE_SECS`.
    pub expires_at_unix: u64,
    /// Unix time the circuit was set up.
    pub created_at_unix: u64,
    /// The ask the relay matched: a blind pair keeps its PS at install and
    /// raises no recovery warning (R14). Persisted.
    pub origin: crate::blind::InstallOrigin,
}

impl PendingInit {
    /// The wait can no longer be answered: older than the offline queue.
    pub(crate) fn too_old(&self, now_unix: u64) -> bool {
        now_unix
            >= self
                .created_at_unix
                .saturating_add(PENDING_INIT_MAX_AGE_SECS)
    }

    /// Ruling R8: the wait counts online time only. On a reconnect or a
    /// restore it is pushed back to `now + ASK_TTL`, capped at the
    /// offline-queue age.
    pub(crate) fn refresh(&mut self, now_unix: u64) {
        let cap = self
            .created_at_unix
            .saturating_add(PENDING_INIT_MAX_AGE_SECS);
        let wanted = now_unix.saturating_add(crate::peers::ASK_TTL.as_secs());
        self.expires_at_unix = self.expires_at_unix.max(wanted).min(cap);
    }
}

/// What `install_session` needs. `ek` is our ask's X25519 ephemeral
/// secret for the initiator, the initiator's ephemeral (public) for the
/// responder.
struct NewSession<'a> {
    role: u8,
    sk: &'a Zeroizing<[u8; 32]>,
    my_ik: [u8; 32],
    peer_ik: [u8; 32],
    peer_ak: [u8; 32],
    ek: Zeroizing<[u8; 32]>,
    circuit_id: CircuitId,
    target_circuit_id: CircuitId,
    token: Vec<u8>,
    circuit_epoch: u64,
    init_out: Option<Box<InitOut>>,
    answered: bool,
    /// Identity or blind match (R14), carried from the matched ask.
    origin: crate::blind::InstallOrigin,
}

/// 32 hex characters → 16 bytes.
pub(crate) fn message_id_from_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// A hex ML-KEM-768 public key (2368 hex digits) that passes the FIPS 203
/// encapsulation-key check; None otherwise.
pub(crate) fn parse_kem_hex(h: &str) -> Option<Box<[u8; KEM_PK_LEN]>> {
    let bytes = hex::decode(h).ok()?;
    crate::kem::validate_public_key(&bytes).ok()?;
    let mut k = Box::new([0u8; KEM_PK_LEN]);
    k.copy_from_slice(&bytes);
    Some(k)
}

/// `on_peer_key_event` code: a pinned contact's ML-KEM key was learned from
/// a bundle their identity signed (a knock); the third argument is the key
/// as 2368 hex. The app stores it with the pin (R11).
pub(crate) const KEM_KEY_LEARNED: u8 = 5;

/// The app-facing error for a refused pin.
pub(crate) fn pin_error(e: PinError) -> RChatError {
    match e {
        PinError::Conflict => RChatError::PinConflict,
        PinError::AgreementKeyInUse => RChatError::AgreementKeyInUse,
        PinError::RotationTooSoon => RChatError::RotationTooSoon,
    }
}

fn ek32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

impl ClientInner {
    /// Send `CloseCircuit`, or keep it for right after the next accepted
    /// publish (security review M-1). The relay acts only on a close from a
    /// proven connection, so one made before the publish on this connection
    /// was accepted (a reconnect in progress) or one that could not be
    /// queued (offline) would be lost; the session and its circuit id are
    /// usually dropped with it, so nothing else would close the pair.
    pub(crate) fn close_circuit_id(&mut self, circuit_id: &CircuitId) {
        let frame = ControlMessage::CloseCircuit {
            circuit_id: circuit_id.clone(),
        };
        if self.frame_gate_open() && self.send_control_now(frame).is_ok() {
            return;
        }
        log::debug!("[RUST] CloseCircuit kept for the next accepted publish");
        if self.pending_closes.contains(circuit_id) {
            return;
        }
        if self.pending_closes.len() >= MAX_PENDING_CLOSES {
            // The relay's sweep still ends a pair its member never resumes.
            self.pending_closes.remove(0);
        }
        self.pending_closes.push(circuit_id.clone());
        self.persist_meta();
    }

    /// Send the closes kept by `close_circuit_id` (first thing after an
    /// accepted publish, before any resume or ask).
    fn flush_pending_closes(&mut self) {
        let pending = std::mem::take(&mut self.pending_closes);
        if pending.is_empty() {
            return;
        }
        for cid in pending {
            self.close_circuit_id(&cid);
        }
        self.persist_meta();
    }

    pub(crate) fn emit_peer_key_event(&self, peer_hex: &str, code: u8, agreement_hex: &str) {
        if let Some(cb) = &self.callbacks {
            cb.on_peer_key_event(peer_hex.to_string(), code, agreement_hex.to_string());
        }
    }

    /// Ask the peer again, rate-limited by its backoff (M9).
    pub(crate) fn schedule_reask(&mut self, peer_hex: &str) {
        if self
            .ask(peer_hex, AskTrigger::Auto, Instant::now())
            .is_err()
        {
            log::debug!("[RUST] re-ask not scheduled for this peer");
        }
    }

    pub(crate) fn jitter(&self) -> f64 {
        self.ask_jitter_override
            .unwrap_or_else(|| rand::Rng::gen_range(&mut rand::thread_rng(), -0.2..=0.2))
    }

    /// The peer-state gate shared by `ask` and `set_intro`: only accepted
    /// peers (pinned, or pinned with a transient bad signature) may be asked.
    pub(crate) fn require_askable(&self, peer_hex: &str) -> Result<(), RChatError> {
        let identity = peer_hex.to_string();
        match self.peers.state(peer_hex) {
            PeerKeyState::Blocked => Err(RChatError::PeerBlocked { identity }),
            PeerKeyState::None => Err(RChatError::PeerNotAccepted { identity }),
            PeerKeyState::Mismatch => Err(RChatError::PeerKeyRejected { identity }),
            PeerKeyState::Pinned | PeerKeyState::BadSignature => Ok(()),
        }
    }

    /// Spec §6.3 Asking. A user ask is sent now (still counted by the
    /// backoff); an automatic one is scheduled. Nothing is sent while the
    /// circuit is live, and nothing before the publish on this connection
    /// is acknowledged (deferred to `after_publish_ok`).
    pub(crate) fn ask(
        &mut self,
        peer_hex: &str,
        trigger: AskTrigger,
        now: Instant,
    ) -> Result<(), RChatError> {
        self.require_askable(peer_hex)?;
        if self.has_live_circuit(peer_hex) || self.awaiting_live_init(peer_hex) {
            // A live pair needs no ask, and an ask without a valid resume
            // would make the relay tear it down (§6.2 step 2). A pair
            // waiting for its session-init is live too (§A.3).
            return Ok(());
        }
        let identity = peer_hex.to_string();
        // A background drain asks nothing (§H.1): kept for the next
        // foreground publish, like an ask made before one.
        if !self.is_key_bundle_published || self.in_drain() {
            if !self.deferred_asks.iter().any(|p| p == peer_hex) {
                self.deferred_asks.push(identity);
            }
            return Ok(());
        }
        // Fix round 1 M-2: an ask that can't carry a knock (no pinned KEM
        // key) charges no backoff. T5 N-1: it is kept in `deferred_asks`,
        // not dropped: the next accepted publish retries it, and a KEM key
        // arriving through a pin call asks at once (`ask_if_kem_arrived`).
        if self.peers.kem_pk_for(peer_hex).is_none() {
            if !self.deferred_asks.iter().any(|p| p == peer_hex) {
                self.deferred_asks.push(identity.clone());
            }
            return Err(RChatError::NoKemKey { identity });
        }
        let jitter = self.jitter();
        match trigger {
            AskTrigger::Auto => {
                if self.pending_reasks.contains_key(peer_hex) {
                    return Ok(());
                }
                let due = self.peers.backoff_mut(peer_hex).record(now, jitter);
                self.pending_reasks.insert(identity, due);
                Ok(())
            }
            AskTrigger::User => {
                if self.ask_in_flight_until(peer_hex, now).is_some() {
                    // Still answerable: a second ask would tear down a pair
                    // that just formed (spec §18.6 D33).
                    return Ok(());
                }
                self.peers.backoff_mut(peer_hex).record(now, jitter);
                self.pending_reasks.remove(peer_hex);
                self.send_ask(peer_hex, now)
            }
        }
    }

    /// Queue a first message to travel inside knocks to a pinned peer with
    /// no session yet (§6.5). Returns its 32-hex id, which the app reuses for
    /// the real message (`send_text_message_using_id`) so the recipient can
    /// de-duplicate. The intro is sealed to the recipient under a key from
    /// the static-static agreement-key DH: deniable (not signed; its aad binds
    /// the knock MAC) but NOT forward-secret — a later compromise of either
    /// agreement key reveals it. If an ask is outstanding, one new ask
    /// carrying the intro is sent now.
    pub(crate) fn set_intro(
        &mut self,
        peer_hex: &str,
        text: &str,
        now: Instant,
    ) -> Result<String, RChatError> {
        self.set_intro_with_id(peer_hex, text, None, now)
    }

    /// `set_intro` under a caller-chosen id (`preset`), for an app that
    /// re-arms an intro it already gave an id to before a relaunch: the
    /// recipient may hold that id already, so the real message must keep
    /// it. `None` mints a fresh id. Every other rule is `set_intro`'s.
    pub(crate) fn set_intro_with_id(
        &mut self,
        peer_hex: &str,
        text: &str,
        preset: Option<[u8; 16]>,
        now: Instant,
    ) -> Result<String, RChatError> {
        self.require_askable(peer_hex)?;
        // R33 I-2: an intro carries no disappearing timer, so none goes
        // while the conversation has one.
        if self.timer_secs(peer_hex) != 0 {
            return Err(RChatError::InvalidParameter {
                message: "no intro while disappearing messages are on".into(),
            });
        }
        if self.session_manager.get(peer_hex).is_some() {
            return Err(RChatError::Internal {
                message: "an intro only precedes the first circuit".into(),
            });
        }
        if knock::Intro::validate_text(text).is_err() {
            return Err(RChatError::Internal {
                message: "intro text must be 1-1024 bytes of UTF-8 without NUL".into(),
            });
        }
        if self.intros.contains_key(peer_hex) {
            return Err(RChatError::Internal {
                message: "an intro is already queued for this contact".into(),
            });
        }
        let message_id = preset.unwrap_or_else(|| {
            let mut fresh = [0u8; 16];
            OsRng.fill_bytes(&mut fresh);
            fresh
        });
        let sent_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.record_sent(peer_hex, message_id);
        self.intros.insert(
            peer_hex.to_string(),
            knock::Intro {
                message_id,
                sent_at_ms,
                text: text.to_string(),
            },
        );
        if self.peers.outstanding_asks(peer_hex) > 0 && self.is_key_bundle_published {
            if let Err(e) = self.send_ask(peer_hex, now) {
                // Not queued after all, so the caller can simply retry.
                self.intros.remove(peer_hex);
                return Err(e);
            }
        }
        Ok(hex::encode(message_id))
    }

    /// Build and send one `CircuitAsk`: fresh EK into the ring, 5120-byte
    /// knock v3, and the resume (or the all-zero id). The knock needs the
    /// peer's pinned ML-KEM key: without one this fails with `NoKemKey`
    /// before anything is built or charged, and there is no X25519-only
    /// fallback (§A.5, R1).
    /// A known contact (protocol v3 §C.3, Task 9) is asked blind instead:
    /// `CircuitAskBlind` under the pair token, no target and no knock.
    pub(crate) fn send_ask(&mut self, peer_hex: &str, now: Instant) -> Result<(), RChatError> {
        if self.in_drain() {
            // Never from a background drain (§H.1); callers keep it deferred.
            return Err(RChatError::NotConnected);
        }
        if self.blind_path(peer_hex) {
            if self.peers.pin_for(peer_hex).is_none() {
                return Err(RChatError::PeerNotAccepted {
                    identity: peer_hex.to_string(),
                });
            }
            return self.send_blind_plan(peer_hex, now, crate::blind::BlindPlan::Own);
        }
        let peer_ak = self
            .peers
            .pin_for(peer_hex)
            .ok_or_else(|| RChatError::PeerNotAccepted {
                identity: peer_hex.to_string(),
            })?;
        if self.peers.kem_pk_for(peer_hex).is_none() {
            return Err(RChatError::NoKemKey {
                identity: peer_hex.to_string(),
            });
        }
        let peer_ik = key_from_hex(peer_hex).ok_or_else(|| RChatError::InvalidRecipient {
            identity: peer_hex.to_string(),
        })?;
        let bundle = self.signed_bundle.clone().ok_or(RChatError::NotConnected)?;
        if self.identity.is_none() {
            return Err(RChatError::NotConnected);
        }
        // Round-2 M3: the rotation block goes only to identities pinned at
        // rotation time, within the daily quota; over quota the ask waits
        // under backoff.
        let rotation =
            if self.rotation_unreached.contains(peer_hex) && self.rotation_pending_reach() {
                if !self.take_rotation_knock(now) {
                    self.schedule_reask(peer_hex);
                    return Ok(());
                }
                self.rotation_block.clone()
            } else {
                None
            };
        let charged = rotation.is_some();
        let sent = self.build_and_send_ask(peer_hex, &bundle, &peer_ik, &peer_ak, rotation, now);
        if sent.is_err() && charged {
            // The rotation knock never left: give its daily slot back
            // (Task 17c minor).
            self.rotation_knocks.pop_back();
        }
        // Final re-review N-1: on a flagged knock's identity path, blind
        // asks run beside the identity ask while we still hold a PS.
        if sent.is_ok()
            && self.blind_alongside_due(peer_hex)
            && self
                .send_blind_plan(peer_hex, now, crate::blind::BlindPlan::Own)
                .is_err()
        {
            log::debug!("[RUST] blind ask beside the identity ask not sent");
        }
        sent
    }

    fn build_and_send_ask(
        &mut self,
        peer_hex: &str,
        bundle: &crate::keyauth::SignedBundle,
        peer_ik: &[u8; 32],
        peer_ak: &[u8; 32],
        rotation: Option<crate::rotation::RotationBlock>,
        now: Instant,
    ) -> Result<(), RChatError> {
        let identity = self.identity.as_ref().ok_or(RChatError::NotConnected)?;
        let peer_kem = self
            .peers
            .kem_pk_for(peer_hex)
            .ok_or_else(|| RChatError::NoKemKey {
                identity: peer_hex.to_string(),
            })?;
        let intro = self.intros.get(peer_hex).cloned();
        // R35: declare (under the knock MAC) that we hold no session with
        // the peer: first contact, lost sessions, or our new identity after
        // a rotation.
        let no_prior_session = self.rotation_unreached.contains(peer_hex)
            || !self
                .session_manager
                .get(peer_hex)
                .is_some_and(|s| s.ratchet.is_some() && s.is_established);
        let knock = knock::build_knock(
            identity,
            bundle,
            peer_ik,
            peer_ak,
            peer_kem,
            now_hour(),
            intro.as_ref(),
            rotation.as_ref(),
            no_prior_session,
        )
        .map_err(|e| RChatError::EncryptionFailed {
            message: e.to_string(),
        })?;
        // Protocol v3 (§A.3): fresh X25519 and ML-KEM-768 ephemerals per
        // ask, kept in the ask ring until the relay pairs the ask (or
        // `ASK_TTL`); the responder then keeps its pair for session-init.
        let keys = AskKeys::generate();
        let ek_pub = keys.ek.public_key().to_bytes();
        // R7: both ephemerals signed by our identity, so the peer can tell
        // a relay-substituted key from ours.
        let ephemeral_sig = keyauth::sign_ask_ephemerals(identity, &ek_pub, keys.kem.public());
        let resume_circuit = Some(self.resume_circuit_for(peer_hex).unwrap_or(ZERO_CIRCUIT));
        self.send_control_now(ControlMessage::CircuitAsk {
            target_identity: peer_ik.to_vec(),
            ephemeral_key: ek_pub.to_vec(),
            kem_ephemeral_pk: keys.kem.public().to_vec(),
            ephemeral_sig: ephemeral_sig.to_vec(),
            knock,
            resume_circuit,
        })?;
        self.peers.push_ask(peer_hex, keys, now);
        self.note_recent_ask(peer_hex, ek_pub, now, false);
        self.unanswered_asks
            .insert(peer_hex.to_string(), (now, self.transport_epoch));
        // Final review H-1: the first identity ask a pinned contact's knock
        // caused on this connection starts its clock (`fire_blind_timeouts`
        // sends the pair back to blind when it runs out unmatched).
        let epoch = self.transport_epoch;
        if let Some(w) = self.identity_wanted.get_mut(peer_hex) {
            if w.asked.map_or(true, |(_, e)| e != epoch) {
                w.asked = Some((now, epoch));
            }
        }
        self.persist_meta();
        Ok(())
    }

    /// When the peer's ask, sent on this connection less than
    /// `ASK_IN_FLIGHT` ago, stops being in flight; None when it isn't.
    fn ask_in_flight_until(&self, peer_hex: &str, now: Instant) -> Option<Instant> {
        let (at, epoch) = self.unanswered_asks.get(peer_hex)?;
        (*epoch == self.transport_epoch && now.saturating_duration_since(*at) < ASK_IN_FLIGHT)
            .then(|| *at + ASK_IN_FLIGHT)
    }

    /// Every unanswered ask goes back to `deferred_asks` (spec §18.6 D33):
    /// its frame, or the relay's answer, may have gone to a connection the
    /// core already retired.
    pub(crate) fn requeue_unanswered_asks(&mut self) {
        let peers: Vec<String> = self.unanswered_asks.keys().cloned().collect();
        for peer in peers {
            if self.require_askable(&peer).is_ok() && !self.deferred_asks.contains(&peer) {
                self.deferred_asks.push(peer);
            }
        }
    }

    /// The relay answered the peer's ask (any outcome), or the peer is gone.
    pub(crate) fn clear_unanswered(&mut self, peer_hex: &str) {
        if self.unanswered_asks.remove(peer_hex).is_some() {
            self.persist_meta();
        }
    }

    /// Send the scheduled re-asks that are due.
    pub(crate) fn fire_due_reasks(&mut self, now: Instant) {
        // Blind asks held their whole TTL without a match (§C.1, §C.4).
        self.fire_blind_timeouts(now);
        let due: Vec<String> = self
            .pending_reasks
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(p, _)| p.clone())
            .collect();
        for peer in due {
            self.pending_reasks.remove(&peer);
            if !self.is_key_bundle_published {
                // Reconnected, new publish not yet acknowledged: send it from `after_publish_ok`.
                if !self.deferred_asks.contains(&peer) {
                    self.deferred_asks.push(peer);
                }
                continue;
            }
            if let Some(until) = self.ask_in_flight_until(&peer, now) {
                // An ask is in flight (e.g. the re-send after a transport
                // replacement): firing now would tear down the pair it is
                // forming. Due again once the window ends.
                self.pending_reasks.insert(peer, until);
                continue;
            }
            let allowed = self.require_askable(&peer).is_ok() && !self.awaiting_live_init(&peer);
            if allowed && !self.has_live_circuit(&peer) && !self.ask_pacer.take(now) {
                // Paced (final review, RateLimited): due again when the
                // pacer has room.
                let at = self.ask_pacer.next_at(now);
                self.pending_reasks.insert(peer, at);
                continue;
            }
            if allowed && !self.has_live_circuit(&peer) && self.send_ask(&peer, now).is_err() {
                // Not lost: retried after the next publish acknowledgement.
                log::debug!("[RUST] scheduled re-ask could not be sent; deferred");
                if !self.deferred_asks.contains(&peer) {
                    self.deferred_asks.push(peer);
                }
            }
        }
    }

    /// Resume definition (M9): this run's established, current session,
    /// created before the transport last reconnected, and still holding its circuit.
    /// A blinded circuit is never resumed by id (§C.3), and a known contact
    /// on the blind path re-pairs blind instead: v2 resume stays for
    /// identity circuits before their first blind epoch only.
    pub(crate) fn resume_circuit_for(&self, peer_hex: &str) -> Option<CircuitId> {
        // A pair waiting for its session-init resumes its own circuit (§A.3).
        if let Some(p) = self.pending_inits.get(peer_hex) {
            if p.origin == crate::blind::InstallOrigin::Blind {
                return None;
            }
            return (p.circuit_epoch < self.transport_epoch).then(|| p.circuit_id.clone());
        }
        if self.blind_path(peer_hex) {
            return None;
        }
        let s = self.session_manager.get(peer_hex)?;
        if s.blinded {
            return None;
        }
        if s.is_established && s.circuit_epoch < self.transport_epoch {
            s.circuit_id.clone()
        } else {
            None
        }
    }

    /// The relay accepted our publish on this connection: send deferred asks
    /// and resume every circuit that predates the connection.
    pub(crate) fn after_publish_ok(&mut self, now: Instant) {
        self.drain_note_published(now);
        if self.in_drain() {
            // A background drain (§H.1) only receives: no resume, no blind
            // re-pair, no deferred ask, no close and no timer re-send. All
            // of it stays as it is for the next foreground publish.
            return;
        }
        // R33 M-3, round 2 N-1: a new connection gives timer re-sends a
        // fresh budget, and every unacknowledged state goes again now.
        self.reset_timer_resends();
        self.requeue_unacked_timers();
        // Closes that could not reach the relay go first (M-1), so a pair
        // the user blocked, unpinned or deleted in the meantime is torn down
        // before anything else is asked on this connection.
        self.flush_pending_closes();
        // R8: a responder's wait for a session-init counts online time only.
        let now_unix = crate::unix_now_secs();
        for w in self.pending_inits.values_mut() {
            w.refresh(now_unix);
        }
        let mut asked: Vec<String> = Vec::new();
        // §C.3: every known contact on the blind path re-pairs with a blind
        // ask under its next token, uncounted like a resume. A blind pair
        // still waiting for its session-init from an earlier connection
        // cannot resume its circuit, so it asks again too.
        for peer in self.session_manager.get_all_recipients() {
            if self.blind_path(&peer)
                && self.require_askable(&peer).is_ok()
                && !self.has_live_circuit(&peer)
                && !self.awaiting_live_init(&peer)
            {
                // An identity circuit from before this connection is closed
                // first, not resumed: the relay tears it down at once and
                // tells the peer, which re-asks blind and meets this ask
                // (one round trip, instead of the relay's unresumed-pair
                // grace). It names nothing the relay does not know: an
                // identity row is keyed by the identity pair already. A
                // blinded circuit's id is never presented again (§C.3).
                // Not while our session-init is unanswered: the peer may
                // still be waiting for it on that circuit (it then ends
                // after the relay's unresumed-pair grace).
                let stale_identity_circuit = self
                    .session_manager
                    .get(&peer)
                    .filter(|s| !s.blinded && s.init_out.is_none())
                    .and_then(|s| s.circuit_id.clone());
                if let Some(cid) = stale_identity_circuit {
                    self.close_circuit_id(&cid);
                    self.detach_circuit(&peer);
                }
                // Past the pacer's burst the re-pair waits its turn
                // (`fire_due_reasks`), uncounted like this one.
                if !self.ask_pacer.take(now) {
                    self.pending_reasks.insert(peer.clone(), now);
                    asked.push(peer);
                    continue;
                }
                self.pending_reasks.remove(&peer);
                if self.send_ask(&peer, now).is_err() {
                    log::debug!("[RUST] blind re-pair ask could not be sent");
                }
                asked.push(peer);
            }
        }
        // Resumes next, uncounted: a resume after a reconnect is not a
        // retry, so it must not push the peer's backoff towards the cap.
        let mut resumable = self.session_manager.get_all_recipients();
        for peer in self.pending_inits.keys() {
            if !resumable.contains(peer) {
                resumable.push(peer.clone());
            }
        }
        for peer in resumable {
            if asked.contains(&peer) {
                continue;
            }
            if self.resume_circuit_for(&peer).is_some()
                && self.require_askable(&peer).is_ok()
                && !self.has_live_circuit(&peer)
            {
                self.pending_reasks.remove(&peer);
                if self.send_ask(&peer, now).is_err() {
                    log::debug!("[RUST] resume ask could not be sent");
                }
                asked.push(peer);
            }
        }
        for peer in std::mem::take(&mut self.deferred_asks) {
            if asked.contains(&peer) {
                continue;
            }
            // An ask left unanswered by a replaced transport is sent again
            // uncounted, like a resume: it is not a retry (spec §18.6 D33).
            let sent = if self.unanswered_asks.contains_key(&peer) {
                if self.require_askable(&peer).is_ok()
                    && !self.has_live_circuit(&peer)
                    && !self.awaiting_live_init(&peer)
                {
                    self.pending_reasks.remove(&peer);
                    self.send_ask(&peer, now)
                } else {
                    Ok(())
                }
            } else {
                self.ask(&peer, AskTrigger::User, now)
            };
            if sent.is_err() {
                log::debug!("[RUST] deferred ask could not be sent");
                // Kept for the next accepted publish while the peer is still
                // askable (Task 14 minor: it used to be dropped here).
                if self.require_askable(&peer).is_ok() && !self.deferred_asks.contains(&peer) {
                    self.deferred_asks.push(peer);
                }
            }
        }
        // Spec §4.8, round-2 M3: on every accepted publish, ask each pinned
        // contact not yet reached under the new identity (no 72 h cutoff).
        if self.rotation_pending_reach() {
            let unreached: Vec<String> = self.rotation_unreached.iter().cloned().collect();
            for peer in unreached {
                if self.peers.pin_for(&peer).is_some() && !self.has_live_circuit(&peer) {
                    self.schedule_reask(&peer);
                }
            }
        }
    }

    /// Stop using the peer's circuit locally (the ratchet is kept).
    fn detach_circuit(&mut self, peer_hex: &str) {
        if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
            s.circuit_id = None;
            s.target_circuit_id = None;
            s.session_token = None;
        }
        // Best effort (D28 "detached"): a stale circuit on disk is only
        // resumed and refused.
        let _ = self.persist_peer(peer_hex);
    }

    /// Spec §6.3 Receiving a knock (a knock v3 envelope, §A.5 / R10).
    /// Nothing is ever sent for a request, and a knock that does not open
    /// or verify is dropped silently.
    pub(crate) fn handle_knock(&mut self, payload: &[u8]) {
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let Ok(opened) = sealed::open_knock(identity.agreement_secret(), identity.kem(), payload)
        else {
            log::debug!("[RUST] knock did not open");
            return;
        };
        // A contact's intro is never opened (spec §6.3): it would only be
        // dropped. The claimed sender is checked again once parsed.
        let want_intro = self
            .peers
            .pin_for(&hex::encode(opened.sender_identity_key))
            .is_none();
        let Ok(parsed) = knock::parse_knock(
            identity,
            opened,
            now_hour(),
            self.knock_ttl_hours,
            want_intro,
        ) else {
            log::debug!("[RUST] knock dropped");
            return;
        };
        let sender_hex = hex::encode(parsed.sender.identity_key);
        if self.peers.is_blocked(&sender_hex) {
            return;
        }
        // M-2: a pinned contact's knock is acted on once: a relay replaying
        // it (valid ~73 h) cannot turn the pair to the identity path again.
        if self.peers.pin_for(&sender_hex).is_some() && !self.note_knock_seen(&sender_hex, payload)
        {
            log::debug!("[RUST] replayed knock dropped");
            return;
        }
        // R11: a signed KEM key other than the pinned one is a mismatch,
        // like another agreement key.
        let kem_agrees = self.peers.kem_matches(&sender_hex, &parsed.sender.kem_pk);
        match self.peers.pin_for(&sender_hex) {
            Some(pin)
                if kem_agrees && constant_time_eq(&pin, &parsed.sender.identity_agreement_key) =>
            {
                // The contact's identity signed this KEM key: it fills a
                // missing one (§A.5 "an earlier session"); a pinned one is
                // never replaced from here.
                // N-2: a knock older than the last one acted on, or that
                // very knock, is ignored, also after a restart (persisted),
                // so a replay cannot force another identity ask past R20's
                // limit. A new knock of the same hour (a peer that lost its
                // sessions again) still counts.
                let digest: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(payload).into()
                };
                if self
                    .knock_acted
                    .get(&sender_hex)
                    .is_some_and(|(h, d)| parsed.issued_hour < *h || constant_time_eq(d, &digest))
                {
                    log::debug!(
                        "[RUST] knock older than, or the same as, the last acted on; dropped"
                    );
                    return;
                }
                self.knock_acted
                    .insert(sender_hex.clone(), (parsed.issued_hour, digest));
                let _ = self.persist_peer(&sender_hex);
                self.adopt_bundle_kem(&sender_hex, &parsed.sender);
                self.contact_knocked(&sender_hex, parsed.issued_hour, parsed.no_prior_session);
            }
            Some(_) => {
                // A knock no newer than the current pin may be a relay
                // replaying one made under the old key (valid ~73 h): it
                // must not flip a freshly re-pinned contact to mismatch.
                if self
                    .peers
                    .pin_hour(&sender_hex)
                    .is_some_and(|h| parsed.issued_hour <= h)
                {
                    return;
                }
                if self.peers.is_mismatch(&sender_hex) {
                    return; // no state change, no repeat event
                }
                self.peers.mark_mismatch(&sender_hex);
                self.close_circuit_with(&sender_hex);
                self.detach_circuit(&sender_hex);
                // C-8: no session from an ask made before the mismatch.
                if let Some(p) = self.pending_inits.remove(&sender_hex) {
                    self.close_circuit_id(&p.circuit_id);
                    let _ = self.persist_peer(&sender_hex);
                }
                self.emit_peer_key_event(
                    &sender_hex,
                    PeerKeyState::Mismatch as u8,
                    &hex::encode(parsed.sender.identity_agreement_key),
                );
            }
            None => {
                // Round-2 M1, security review L-1: only the chain inside this
                // sender-authenticated knock can re-pin (the knock proves
                // possession of the new keys, and the sender vouches for the
                // chain). A `0x04` ratchet notice is ignored and never stored:
                // link signatures come only from the old key, so any pinned
                // contact could name someone else's new keys, and a stored
                // notice applied on that identity's chainless knock would hand
                // it the contact. A failed chain falls through to a request.
                if let Some(block) = parsed.rotation.as_ref() {
                    // The new identity's KEM key comes from the bundle it
                    // signed in this knock, pinned with the rotation before
                    // the new identity is asked.
                    if self.try_peer_rotation(&parsed.sender, block) {
                        return;
                    }
                }
                if self
                    .peers
                    .pinned_elsewhere(&sender_hex, &parsed.sender.identity_agreement_key)
                {
                    return;
                }
                let intro_id = parsed.intro.as_ref().map(|i| i.message_id);
                let new_request =
                    self.peers
                        .note_request(&sender_hex, intro_id, parsed.issued_hour);
                // Kept for an accept under this agreement key (§A.5).
                self.peers.note_request_kem(
                    &sender_hex,
                    &parsed.sender.identity_agreement_key,
                    &parsed.sender.kem_pk,
                );
                if !new_request {
                    return;
                }
                // A version claim counts only with a chain ending at the sender.
                let key_version = parsed
                    .rotation
                    .as_ref()
                    .filter(|b| {
                        crate::rotation::verify_chain_to(
                            &b.links,
                            &parsed.sender.identity_key,
                            &parsed.sender.identity_agreement_key,
                        )
                        .is_ok()
                    })
                    .map_or(0, |b| b.current_version);
                // Intro text is untrusted peer input: passed through as-is
                // (already bounded and UTF-8 checked); the app sanitises it.
                let (intro_message_id_hex, intro_text, intro_sent_at_ms) = match parsed.intro {
                    Some(i) => (hex::encode(i.message_id), i.text, i.sent_at_ms),
                    None => (String::new(), String::new(), 0),
                };
                let request = MessageRequest {
                    identity_hex: sender_hex,
                    agreement_hex: hex::encode(parsed.sender.identity_agreement_key),
                    kem_hex: hex::encode(&parsed.sender.kem_pk[..]),
                    issued_hour: parsed.issued_hour,
                    intro_message_id_hex,
                    intro_text,
                    intro_sent_at_ms,
                    key_version,
                };
                self.drain_note_request();
                if let Some(cb) = &self.callbacks {
                    cb.on_message_request(request);
                }
            }
        }
    }

    /// Record a pinned contact's knock (M-2); false if it was seen within
    /// `KNOCK_SEEN_SECS` (a replay). Bounded per contact.
    fn note_knock_seen(&mut self, peer_hex: &str, payload: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let now_unix = crate::unix_now_secs();
        let q = self.seen_knocks.entry(peer_hex.to_string()).or_default();
        q.retain(|(_, at)| now_unix.saturating_sub(*at) <= KNOCK_SEEN_SECS);
        if q.iter().any(|(d, _)| constant_time_eq(d, &digest)) {
            return false;
        }
        if q.len() >= MAX_KNOCKS_SEEN_PER_PEER {
            q.pop_front();
        }
        q.push_back((digest, now_unix));
        true
    }

    /// A pinned contact's verified knock (Task 9, §C.4): the contact asked
    /// on the identity path (it lost its sessions, rotated, or fell back),
    /// where a blind ask can never meet it, so the answer is an identity
    /// ask. A live blinded circuit with it is then one it no longer uses:
    /// closed on this connection (its id is never carried to another) and
    /// the pair asked again. A live identity circuit is left alone (an
    /// identity ask without its resume already made the relay end it, §6.2
    /// step 2). A knock issued in an hour before the current session began
    /// is stale (queued at the relay up to 72 h) and changes the path of
    /// nothing; with no live circuit the pair is still re-asked.
    fn contact_knocked(&mut self, peer_hex: &str, issued_hour: u64, no_prior_session: bool) {
        let (fresh, blinded) = self
            .session_manager
            .get(peer_hex)
            .map_or((true, false), |s| {
                (issued_hour >= s.created_at_unix / 3600, s.blinded)
            });
        let live = self.has_live_circuit(peer_hex);
        if live && !(blinded && fresh) {
            return;
        }
        if fresh {
            if !self.knock_may_repair_by_identity(peer_hex, no_prior_session) {
                log::debug!("[RUST] contact knock: identity budget spent; staying blind");
                return;
            }
            // H-1: a flagged knock (no session on its side) keeps the pair
            // on the identity path; any other runs out like the fallback.
            let w = self.identity_wanted.entry(peer_hex.to_string()).or_insert(
                crate::blind::IdentityWanted {
                    no_prior_session,
                    asked: None,
                },
            );
            w.no_prior_session |= no_prior_session;
        }
        if live {
            self.close_circuit_with(peer_hex);
            self.detach_circuit(peer_hex);
        }
        self.schedule_reask(peer_hex);
    }

    /// Rulings R35 and M-1 (Task 16 fix round 1): whether a pinned
    /// contact's fresh knock may move the pair to the identity path. With
    /// no blind-capable session (no pair secret) the identity path is the
    /// only one: yes. Otherwise every such re-pair, flagged "no prior
    /// session" or not, draws on the pair's one identity re-pair per
    /// `IDENTITY_FALLBACK_INTERVAL_SECS` (`last_identity_fallback_unix`,
    /// persisted, shared with the timed fallback): the first one acts at once
    /// and stamps it, and any other within 24 h is ignored for re-pairing
    /// (the pair stays blind). So a relay that withholds genuine knocks,
    /// first-contact, reinstall and rotation knocks included, and delivers
    /// them after blind re-pairs can force at most one identity re-pair (and
    /// one `SessionReplaced`) per pair per 24 h; a genuine reinstall still
    /// re-pairs at once unless one already happened that day.
    fn knock_may_repair_by_identity(&mut self, peer_hex: &str, no_prior_session: bool) -> bool {
        let now_unix = self.pair_now_unix();
        let spent = match self.session_manager.get(peer_hex) {
            None => return true,
            Some(s) if s.pair_secret.is_none() => return true,
            Some(s) => s.last_identity_fallback_unix.is_some_and(|t| {
                now_unix.saturating_sub(t) < crate::blind::IDENTITY_FALLBACK_INTERVAL_SECS
            }),
        };
        if spent {
            log::debug!(
                "[RUST] contact knock (no prior session: {no_prior_session}): identity budget spent"
            );
            return false;
        }
        if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
            s.last_identity_fallback_unix = Some(now_unix);
        }
        let _ = self.persist_peer(peer_hex);
        true
    }

    /// Pin the KEM key of `bundle` (verified, signed by `peer_hex`) when
    /// `peer_hex` is pinned under the bundle's agreement key and has none.
    fn adopt_bundle_kem(&mut self, peer_hex: &str, bundle: &crate::keyauth::SignedBundle) {
        let same_ak = self
            .peers
            .pin_for(peer_hex)
            .is_some_and(|ak| constant_time_eq(&ak, &bundle.identity_agreement_key));
        if same_ak
            && self.peers.kem_pk_for(peer_hex).is_none()
            && self.peers.set_kem_pk(peer_hex, bundle.kem_pk.clone())
        {
            // The app stores it with the pin and re-pins it at launch (R11,
            // fix round 1 minor 2): a key event with code 5, the key as hex.
            self.emit_peer_key_event(peer_hex, KEM_KEY_LEARNED, &hex::encode(&bundle.kem_pk[..]));
        }
    }

    /// The relay tore our pair down: keep the ratchet (queued messages may
    /// still arrive) but stop sending on the circuit, and re-ask a pinned peer.
    pub(crate) fn handle_circuit_closed(&mut self, circuit_id: CircuitId) {
        if let Some((peer, _)) = self.pending_init_by_circuit(&circuit_id) {
            // The pair waiting for its session-init is gone (§A.3).
            self.abandon_pending_init(&peer, false);
            return;
        }
        let peer = self
            .session_manager
            .find_by_circuit_id(&circuit_id)
            .or_else(|| self.session_manager.find_by_target_circuit_id(&circuit_id));
        let Some(peer) = peer else {
            return;
        };
        self.detach_circuit(&peer);
        if self.require_askable(&peer).is_ok() {
            self.schedule_reask(&peer);
        }
    }

    /// Re-review R-1: the relay refused a packet because the circuit it
    /// named is unknown. If that is a circuit we believe is live, the pair
    /// is gone (for example torn down while our resume was in flight):
    /// handle it like `CircuitClosed`, so we detach it and re-ask with the
    /// usual backoff instead of staying stuck on a dead circuit (and
    /// ignoring the peer's knocks because of it). Anything else is ignored.
    pub(crate) fn handle_circuit_not_found(&mut self, message: &str) {
        let Some(circuit_id) = crate::protocol::circuit_not_found_id(message) else {
            return;
        };
        // Tracked sends on that circuit were refused, not accepted (spec
        // §18.7 D35): sent again once a live circuit exists.
        let refused = self
            .acks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_not_accepted(&circuit_id);
        for (peer, message_id) in refused {
            self.emit_status(crate::status::StatusEvent::SendNotAccepted { peer, message_id });
        }
        if let Some((peer, _)) = self.pending_init_by_circuit(&circuit_id) {
            self.abandon_pending_init(&peer, false);
            return;
        }
        let peer = self
            .session_manager
            .find_by_target_circuit_id(&circuit_id)
            .or_else(|| self.session_manager.find_by_circuit_id(&circuit_id));
        if peer.is_some_and(|p| self.has_live_circuit(&p)) {
            self.handle_circuit_closed(circuit_id);
        }
    }

    /// Our resume was accepted (or the peer resumed): the circuit is live on
    /// this connection again.
    pub(crate) fn handle_circuit_exists(
        &mut self,
        circuit_id: CircuitId,
        token: Vec<u8>,
        target_circuit_id: CircuitId,
    ) {
        if token.len() != 32 {
            return;
        }
        if let Some((peer, _)) = self.pending_init_by_circuit(&circuit_id) {
            // The pair waiting for its session-init resumed (§A.3).
            let epoch = self.transport_epoch;
            if let Some(p) = self.pending_inits.get_mut(&peer) {
                p.circuit_id = circuit_id;
                p.target_circuit_id = target_circuit_id;
                p.token = Zeroizing::new(token.as_slice().try_into().unwrap_or([0; 32]));
                p.circuit_epoch = epoch;
            }
            self.clear_unanswered(&peer);
            self.pending_reasks.remove(&peer);
            let _ = self.persist_peer(&peer);
            return;
        }
        let Some(peer) = self.session_manager.find_by_circuit_id(&circuit_id) else {
            return;
        };
        // Already live on this connection (the peer resumed): nothing was
        // lost on our side, so nothing is re-sent.
        let was_live = self.has_live_circuit(&peer);
        let epoch = self.transport_epoch;
        if let Some(mut s) = self.session_manager.get_mut(&peer) {
            s.set_circuit(circuit_id, target_circuit_id, token);
            s.circuit_epoch = epoch;
        }
        // The circuit is back: a success, like a new session.
        self.clear_unanswered(&peer);
        self.peers.backoff_mut(&peer).reset();
        self.pending_reasks.remove(&peer);
        // Best effort (D28 "resumed"): the new token for the next restart.
        let _ = self.persist_peer(&peer);
        // What the old connection may have lost goes first, in its order
        // (a tracked flagged notice before any receipt, I-1), then what is
        // owed now.
        if !was_live {
            self.resend_tracked(&peer);
        }
        self.flush_receipts(&peer);
    }

    pub(crate) fn record_sent(&self, peer_hex: &str, id: [u8; 16]) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        let q = all.entry(peer_hex.to_string()).or_default();
        // A same-id resend keeps `resent`: at most one automatic resend
        // per message (D38 guard 5).
        let resent = q.iter().any(|s| s.id == id && s.resent);
        let entry = SentIdV1 {
            id,
            sent_at_unix: crate::unix_now_secs(),
            delivered: false,
            pin_ak: self.peers.pin_for(peer_hex).unwrap_or([0; 32]),
            pin_version: self.peers.pin_version(peer_hex),
            resent,
        };
        if q.len() >= MAX_SENT_IDS {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Take back the newest entry for `id`: it never left the device.
    pub(crate) fn unrecord_sent(&self, peer_hex: &str, id: &[u8; 16]) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = all.get_mut(peer_hex) {
            if let Some(pos) = q.iter().rposition(|s| &s.id == id) {
                q.remove(pos);
            }
        }
    }

    pub(crate) fn was_sent_to(&self, peer_hex: &str, id: &[u8; 16]) -> bool {
        let all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        all.get(peer_hex)
            .is_some_and(|q| q.iter().any(|s| &s.id == id))
    }

    pub(crate) fn sent_ids_for(&self, peer_hex: &str) -> Vec<SentIdV1> {
        let all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        all.get(peer_hex)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Receipts owed to the peer and not yet sent, as `(kind, id)`.
    pub(crate) fn owed_receipts(&self, peer_hex: &str) -> Vec<(u8, [u8; 16])> {
        let mut owed: Vec<(u8, [u8; 16])> = self
            .pending_receipts
            .iter()
            .filter(|((p, _), _)| p == peer_hex)
            .flat_map(|((_, kind), ids)| ids.iter().map(move |id| (*kind, *id)))
            .collect();
        // Stable order whatever the map's: by kind, then queue order.
        owed.sort_by_key(|(kind, _)| *kind);
        owed
    }

    pub(crate) fn queue_receipt(&mut self, peer_hex: &str, kind: u8, ids: &[[u8; 16]]) {
        // Only for a pinned peer (Task 16 minor): receipts to anyone else
        // could never be flushed (sends need a pin), so they'd only wait.
        if self.peers.pin_for(peer_hex).is_none() {
            return;
        }
        let q = self
            .pending_receipts
            .entry((peer_hex.to_string(), kind))
            .or_default();
        for id in ids {
            if !q.contains(id) {
                q.push(*id);
            }
        }
        if q.len() > MAX_PENDING_RECEIPTS {
            let excess = q.len() - MAX_PENDING_RECEIPTS;
            q.drain(..excess);
        }
    }

    fn clear_receipts(&mut self, peer_hex: &str) {
        for kind in [receipts::DELIVERED, receipts::READ] {
            self.pending_receipts.remove(&(peer_hex.to_string(), kind));
        }
        self.receipt_due.remove(peer_hex); // cancels a pending delayed flush
        self.last_heard.remove(peer_hex);
        self.steady_unheard.remove(peer_hex);
        self.steady_message_turn.remove(peer_hex);
        self.cover_sent.remove(peer_hex);
        self.cover_replies_charged.remove(peer_hex);
        self.cover_replies_due.retain(|(p, _)| p != peer_hex);
    }

    /// Send the owed session notice, then queued receipts for `peer_hex`
    /// (batches of up to 32 ids), if it has a live circuit over a usable
    /// transport; otherwise keep them (the circuit's resume flushes them
    /// again). Nothing is sealed while the
    /// transport is down, so no chain key is spent on bytes that cannot leave.
    pub(crate) fn send_receipts_now(&mut self, peer_hex: &str) {
        match self.check_sendable(peer_hex) {
            Ok(()) => {}
            Err(RChatError::PeerKeyUnverified { .. }) => return, // transient: keep queued
            Err(_) => {
                self.clear_receipts(peer_hex); // terminal: never send
                return;
            }
        }
        if !self.has_live_circuit(peer_hex) || !self.transport_usable() {
            return;
        }
        // The notice goes first. While a flagged notice is still owed the
        // receipts wait with it: a receipt tells the peer our verdict for
        // this session arrived (`note_peer_notice_heard`), so it must never
        // overtake the `no_prior_session` flag. A notice owing only
        // reason-1/2 ids does not hold them.
        self.send_notice_now(peer_hex);
        if self.notice_due.contains(peer_hex) && self.notice_flag_pending.contains_key(peer_hex) {
            return;
        }
        self.send_receipt_batches(peer_hex, usize::MAX);
    }

    /// Seal and send up to `max_batches` batches (of up to 32 ids) of the
    /// receipts queued for `peer_hex`, delivered before read; what is not
    /// sent stays queued. The caller has checked the peer and its circuit.
    /// Returns how many batches the transport accepted.
    pub(crate) fn send_receipt_batches(&mut self, peer_hex: &str, max_batches: usize) -> usize {
        let mut sent = 0usize;
        for kind in [receipts::DELIVERED, receipts::READ] {
            let Some(ids) = self.pending_receipts.remove(&(peer_hex.to_string(), kind)) else {
                continue;
            };
            let mut unsent: Vec<[u8; 16]> = Vec::new();
            for chunk in ids.chunks(receipts::MAX_IDS) {
                // Checked per batch: a queue that filled since the last one
                // must not cost a chain key for a frame it then refuses.
                if sent >= max_batches || !self.transport_usable() {
                    unsent.extend_from_slice(chunk);
                    continue;
                }
                let Some(pt) = receipts::encode(kind, chunk) else {
                    continue;
                };
                let mut id = [0u8; 16];
                OsRng.fill_bytes(&mut id);
                let packet = match self.seal_ratchet(peer_hex, id, &pt) {
                    Ok(p) => p,
                    Err(_) => {
                        unsent.extend_from_slice(chunk); // nothing spent past a durable write
                        continue;
                    }
                };
                let (circuit, payload) = (packet.circuit_id.clone(), packet.payload.clone());
                if self.send_now(packet.encode_with_frame_type()).is_err() {
                    // Refused (review I-1): owed again here, sent by the
                    // next flush; its spent key is no worse than before.
                    unsent.extend_from_slice(chunk);
                    continue;
                }
                // Accepted: if its connection is replaced before the frame
                // leaves, the resume re-sends these bytes (same session) or
                // owes the ids again (another session).
                self.track_internal(
                    peer_hex,
                    &hex::encode(id),
                    circuit,
                    payload,
                    crate::acks::Internal::Receipt {
                        kind,
                        ids: chunk.to_vec(),
                    },
                );
                sent += 1;
            }
            if !unsent.is_empty() {
                self.pending_receipts
                    .insert((peer_hex.to_string(), kind), unsent);
            }
        }
        sent
    }

    /// Send the session notice owed to `peer_hex` (spec §18.6 D37), once
    /// the session can send on a live circuit over a usable transport: the
    /// unreported undecryptable (reason 1) and lost (reason 2) ids in
    /// batches of up to 32, or one empty notice; the first carries the flag.
    /// Ids leave their list only once their batch has left the device (a
    /// crash before then re-reports them, never drops them); a lost id
    /// then moves to `lost_reported`. A batch that cannot be sealed or sent
    /// stays owed, with the rest, for a later flush.
    /// True when a notice batch was handed to the transport.
    pub(crate) fn send_notice_now(&mut self, peer_hex: &str) -> bool {
        if !self.notice_due.contains(peer_hex)
            || !self.transport_usable()
            || !self.has_live_circuit(peer_hex)
            || !self
                .session_manager
                .get(peer_hex)
                .is_some_and(|s| s.can_send())
        {
            return false;
        }
        let list = |m: &std::collections::HashMap<String, std::collections::VecDeque<[u8; 16]>>| {
            m.get(peer_hex)
                .map(|q| q.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let mut batches: Vec<notice::Notice> = Vec::new();
        for (reason, ids) in [
            (notice::REASON_UNDECRYPTABLE, list(&self.undecryptable)),
            (notice::REASON_LOST_BEFORE_STORED, list(&self.lost_unstored)),
        ] {
            for chunk in ids.chunks(notice::MAX_IDS) {
                batches.push(notice::Notice {
                    flags: 0,
                    reason,
                    ids: chunk.to_vec(),
                    sig: None,
                });
            }
        }
        if batches.is_empty() {
            batches.push(notice::Notice {
                flags: 0,
                reason: notice::REASON_NONE,
                ids: vec![],
                sig: None,
            });
        }
        batches[0].flags = self.notice_flag_pending.get(peer_hex).copied().unwrap_or(0);
        let now_unix = crate::unix_now_secs();
        // Signed by this install's device key over the session-bound tbs
        // (D45); without a signer, or if it fails, the notice goes unsigned.
        let signing = match (
            self.device_signer.clone(),
            self.our_ik(),
            key_from_hex(peer_hex),
            self.session_manager
                .get(peer_hex)
                .map(|s| s.session_binding),
        ) {
            (Some(signer), Some(my_ik), Some(peer_ik), Some(binding)) => {
                Some((signer, my_ik, peer_ik, binding))
            }
            _ => None,
        };
        let more = batches.len() > 1;
        let mut handed = false;
        for mut n in batches.into_iter().take(1) {
            if let Some((signer, my_ik, peer_ik, binding)) = &signing {
                n.sig = notice::tbs(my_ik, peer_ik, binding, &n).and_then(|t| signer.sign(&t));
            }
            let Some(pt) = notice::encode(&n) else {
                continue;
            };
            let mut id = [0u8; 16];
            OsRng.fill_bytes(&mut id);
            let packet = match self.seal_ratchet(peer_hex, id, &pt) {
                Ok(p) => p,
                Err(_) => {
                    // Nothing left and no key spent past a durable write
                    // (D28): still owed, retried by a later flush.
                    log::debug!("[RUST] session notice not sealed; still owed");
                    return false;
                }
            };
            let (circuit, payload) = (packet.circuit_id.clone(), packet.payload.clone());
            if self.send_now(packet.encode_with_frame_type()).is_err() {
                // Its chain key is spent: the tick does not try this peer
                // again until the transport changes (`redrive_owed_sends`).
                log::debug!("[RUST] session notice not sent; still owed");
                self.notice_send_stalled
                    .insert(peer_hex.to_string(), self.transport_epoch);
                return false;
            }
            handed = true;
            // Handed to the transport: if its connection is replaced before
            // the frame leaves, the resume re-sends these bytes, ahead of
            // the receipts tracked after it (I-1).
            self.track_internal(
                peer_hex,
                &hex::encode(id),
                circuit,
                payload,
                crate::acks::Internal::Notice {
                    flags: n.flags,
                    reason: n.reason,
                    ids: n.ids.clone(),
                },
            );
            if n.flags != 0 {
                self.notice_flag_pending.remove(peer_hex);
            }
            let source = if n.reason == notice::REASON_LOST_BEFORE_STORED {
                &mut self.lost_unstored
            } else {
                &mut self.undecryptable
            };
            if let Some(q) = source.get_mut(peer_hex) {
                q.retain(|x| !n.ids.contains(x));
            }
            if n.reason == notice::REASON_LOST_BEFORE_STORED {
                // Reported: a same-id resend may now pass the duplicate drop.
                for id in &n.ids {
                    self.list_lost_reported(peer_hex, *id, now_unix);
                }
            }
            let _ = self.persist_peer(peer_hex);
        }
        self.notice_send_stalled.remove(peer_hex);
        if more {
            // Final review M-1: one batch (at most `notice::MAX_IDS` ids)
            // per flush; the next goes with the next tick's
            // `redrive_owed_sends`, so a flood of ids costs one notice per
            // tick, not one per id.
            return handed;
        }
        self.notice_due.remove(peer_hex);
        let _ = self.persist_peer(peer_hex);
        handed
    }

    /// A frame handed to the transport now would leave: connected, the
    /// relay gate and publish passed, and an open outgoing queue with room.
    /// Checked before sealing what nothing else would re-send, so a down
    /// transport burns no chain keys (the read loop's end closes the queue).
    pub(crate) fn transport_usable(&self) -> bool {
        // Final review L5: never in a background drain (§H.1), whose
        // `send_now` gate refuses everything but signaling anyway.
        self.is_connected
            && !self.in_drain()
            && self.frame_gate_open()
            && self
                .websocket
                .as_ref()
                .and_then(|ws| ws.outgoing_sender())
                .is_some_and(|tx| !tx.is_closed() && tx.capacity() > 0)
    }

    /// List `id` as reported lost (stamped `now_unix`), capped, oldest first.
    pub(crate) fn list_lost_reported(&mut self, peer: &str, id: [u8; 16], now_unix: u64) {
        let q = self.lost_reported.entry(peer.to_string()).or_default();
        if q.iter().any(|(x, _)| *x == id) {
            return;
        }
        if q.len() >= MAX_DELIVERED_UNSTORED {
            q.pop_front();
        }
        q.push_back((id, now_unix));
    }

    fn is_listed_lost(&self, peer: &str, id: &[u8; 16]) -> bool {
        self.lost_reported
            .get(peer)
            .is_some_and(|q| q.iter().any(|(x, _)| x == id))
            || self.lost_unstored.get(peer).is_some_and(|q| q.contains(id))
    }

    /// Drop reported-lost ids past `RESET_REPORT_MAX_AGE_SECS` (a resend
    /// after that is never eligible, D38), re-stamping future stamps to
    /// now (the Task 1 clock ruling). Returns the peers whose list changed.
    pub(crate) fn purge_lost_reported(&mut self, now_unix: u64) -> Vec<String> {
        let mut changed = Vec::new();
        self.lost_reported.retain(|peer, q| {
            let before: Vec<([u8; 16], u64)> = q.iter().copied().collect();
            for e in q.iter_mut() {
                e.1 = e.1.min(now_unix);
            }
            q.retain(|(_, at)| now_unix.saturating_sub(*at) <= RESET_REPORT_MAX_AGE_SECS);
            if q.iter().copied().ne(before.into_iter()) {
                changed.push(peer.clone());
            }
            !q.is_empty()
        });
        changed
    }

    /// The peer's `no_prior_session` verdict for the current session has
    /// arrived: a notice decrypted under it, or a receipt (the peer sends
    /// a flagged notice before any receipt, `send_receipts_now`). The next install
    /// reads it (`SessionManager::install`). True the first time; the
    /// caller persists.
    pub(crate) fn note_peer_notice_heard(&mut self, peer_hex: &str) -> bool {
        self.session_manager.get_mut(peer_hex).is_some_and(|mut s| {
            let first = !std::mem::replace(&mut s.peer_notice_heard, true);
            s.heard_unrecorded |= first;
            first
        })
    }

    /// A session notice from `sender` (spec §18.6 D37, sender side). Only
    /// under the current session; never answered, never a key event.
    ///
    /// Every id it proves lost (named with reason 1 or 2, or reason 3 after
    /// a reset) is then put to the D38 guards (`maybe_resend`). The `resent`
    /// marks are written before any `ResendEligible` is raised (D28: durable
    /// before announced); if that write fails they are taken back and none
    /// is raised, so the fallback (Not delivered) applies.
    ///
    /// `by` is `Current` only for a notice that decrypted under `sender`'s
    /// own current session: `try_ratchet` downgrades a notice decrypted
    /// under an old identity's session in the rotation grace to `Retired`.
    /// `binding` is the `session_binding` of the session that decrypted it,
    /// taken from that session at decrypt (`decrypt_bound`), never looked
    /// up again; guard 7 checks the signature against it.
    pub(crate) fn handle_notice(
        &mut self,
        sender: &str,
        n: notice::Notice,
        by: DecryptedBy,
        binding: Option<[u8; 32]>,
    ) {
        if by != DecryptedBy::Current {
            return; // an old session never speaks for a new one (D37)
        }
        // What a failed write takes back (below).
        let reported_before = self
            .session_manager
            .get(sender)
            .map(|s| s.reported_lost.clone());
        // In the notice's order, each id once.
        let mut named: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
        let mut lost: Vec<[u8; 16]> = Vec::new();
        for id in &n.ids {
            if named.insert(*id)
                && self.was_sent_to(sender, id)
                && self.note_reported(sender, id, n.reason)
            {
                self.emit_status(StatusEvent::PeerUndelivered {
                    peer: sender.to_string(),
                    message_id: hex::encode(id),
                    reason: n.reason,
                });
                lost.push(*id);
            }
        }
        // Persisted below (or retried by the tick, `heard_unrecorded`).
        let first_heard = self.note_peer_notice_heard(sender);
        // The flag reports a reset only against what this session's
        // install recorded: the session the peer's flag is about replaced
        // an established one (`reset_since_unix`).
        // R33 M-2: a peer with no prior session may have lost our shared
        // timer state; it goes again (a no-op if the peer still has it).
        if n.flags & notice::FLAG_NO_PRIOR_SESSION != 0 {
            self.timer_resync(sender);
        }
        let session_start = if n.flags & notice::FLAG_NO_PRIOR_SESSION != 0 {
            self.session_manager
                .get_mut(sender)
                .and_then(|mut s| s.reset_since_unix.take()) // once per session
        } else {
            None
        };
        let reset = session_start.is_some();
        if let Some(session_start) = session_start {
            self.emit_status(StatusEvent::PeerSessionReset {
                peer: sender.to_string(),
            });
            let now = crate::unix_now_secs();
            for e in self.sent_ids_for(sender) {
                // Strictly before the new session (ruling N4); at most 72 h
                // old; each id once.
                if !e.delivered
                    && e.sent_at_unix < session_start
                    && now.saturating_sub(e.sent_at_unix) <= RESET_REPORT_MAX_AGE_SECS
                    && named.insert(e.id)
                    && self.note_reported(sender, &e.id, notice::REASON_UNCONFIRMED_AT_RESET)
                {
                    self.emit_status(StatusEvent::PeerUndelivered {
                        peer: sender.to_string(),
                        message_id: hex::encode(e.id),
                        reason: notice::REASON_UNCONFIRMED_AT_RESET,
                    });
                    lost.push(e.id);
                }
            }
        }
        // D38 guard 1: the ids above are proven lost by a notice under the
        // current session. Guard 7 (D46) is checked once per notice and put
        // to every id with the others.
        let mut eligible: Vec<[u8; 16]> = Vec::new();
        let counted_before = self.auto_resends.get(sender).cloned();
        let resent_before: Vec<bool> = self.sent_ids_for(sender).iter().map(|e| e.resent).collect();
        let signed_ok = self.notice_passes_guard_7(sender, &n, binding.as_ref());
        for id in lost {
            if self.maybe_resend(sender, id, signed_ok) {
                eligible.push(id);
            }
        }
        self.set_made_eligible(sender, &eligible, true);
        if !reset && eligible.is_empty() {
            if first_heard {
                // On failure `heard_unrecorded` stays set: the tick retries,
                // and any later successful write carries it.
                let _ = self.persist_peer(sender);
            }
            return;
        }
        // One write: `reset_since_unix` cleared, the reported ids, the
        // `resent` marks and the bound's stamps. If it fails, the marks,
        // stamps and this notice's reports are taken back and nothing is
        // announced.
        // `reset_since_unix` stays cleared: `PeerSessionReset` and the
        // reason-3 reports were raised already, and the peer sets
        // `no_prior_session` on its first notice only, so restoring it would
        // re-raise the reset on nothing. Those reason-3 ids are left to the
        // fallback (Not delivered, one tap for a plainly pinned contact).
        if self.persist_peer(sender).is_err() && !eligible.is_empty() {
            self.restore_resent(sender, &resent_before);
            // Nothing this notice recorded is durable: a repeat may make
            // the ids eligible once writes succeed.
            if let (Some(before), Some(mut s)) =
                (reported_before, self.session_manager.get_mut(sender))
            {
                s.reported_lost = before;
            }
            match counted_before {
                Some(q) => self.auto_resends.insert(sender.to_string(), q),
                None => self.auto_resends.remove(sender),
            };
            return;
        }
        for id in eligible {
            self.emit_status(StatusEvent::ResendEligible {
                peer: sender.to_string(),
                message_id: hex::encode(id),
            });
        }
    }

    /// Whether this report of `id` with `reason` is new for the current
    /// session, recording it if so. Reason 2 (lost before stored) passes
    /// once per id per session (L-5), unless an earlier report had another
    /// reason. Otherwise an id this session made eligible is never
    /// reported again (its resend is under way), and an id already
    /// reported is reported again only from reason 3 to reason 1 (the
    /// peer confirms it never decrypted).
    fn note_reported(&mut self, peer: &str, id: &[u8; 16], reason: u8) -> bool {
        let Some(mut s) = self.session_manager.get_mut(peer) else {
            return false;
        };
        let prev = s.reported_lost.get(id).copied();
        let report = match prev {
            None => true,
            // Final review L-5: reason 2 once per id per session (a
            // repeated notice is noise; guard 5 stops a second resend).
            Some((prev_reason, _)) if reason == notice::REASON_LOST_BEFORE_STORED => {
                prev_reason != notice::REASON_LOST_BEFORE_STORED
            }
            Some((_, true)) => false,
            Some((prev_reason, false)) => {
                prev_reason == notice::REASON_UNCONFIRMED_AT_RESET
                    && reason == notice::REASON_UNDECRYPTABLE
            }
        };
        if report {
            let eligible = prev.is_some_and(|(_, e)| e);
            if prev.is_some() || s.reported_lost.len() < MAX_SENT_IDS {
                s.reported_lost.insert(*id, (reason, eligible));
            }
        }
        report
    }

    /// Record (or take back) that the current session made `ids` eligible.
    fn set_made_eligible(&mut self, peer: &str, ids: &[[u8; 16]], eligible: bool) {
        if ids.is_empty() {
            return;
        }
        if let Some(mut s) = self.session_manager.get_mut(peer) {
            for id in ids {
                if let Some(e) = s.reported_lost.get_mut(id) {
                    e.1 = eligible;
                } else if s.reported_lost.len() < MAX_SENT_IDS {
                    s.reported_lost
                        .insert(*id, (notice::REASON_LOST_BEFORE_STORED, eligible));
                }
            }
        }
    }

    /// D38 guard 7 (D46): the notice carries a valid signature by the
    /// contact's pinned device key (D44: only ever from their scanned card)
    /// over `notice_tbs`, built with the `binding` of the session the notice
    /// decrypted under (`handle_notice`'s `binding`, never looked up again).
    /// No DK pin, no signature, no binding or a bad signature: false. The
    /// only place guard 7 is decided; `handle_notice` calls it once per
    /// notice and passes the answer to `maybe_resend`.
    fn notice_passes_guard_7(
        &self,
        peer: &str,
        n: &notice::Notice,
        binding: Option<&[u8; 32]>,
    ) -> bool {
        let (Some(pin), Some(sig), Some(binding), Some(peer_ik), Some(my_ik)) = (
            self.peers.device_key(peer),
            n.sig.as_ref(),
            binding,
            key_from_hex(peer),
            self.our_ik(),
        ) else {
            return false;
        };
        notice::tbs(&peer_ik, &my_ik, binding, n)
            .is_some_and(|t| crate::device_key::verify_notice(pin, &t, sig))
    }

    /// D38 guards 2–7 for one sent entry. Guard 1 is the caller (an id a
    /// current-session notice proved lost); guard 7 arrives as `signed_ok`
    /// (`notice_passes_guard_7`). Keys are compared in constant time.
    fn resend_guards_hold(&self, peer: &str, e: &SentIdV1, now_unix: u64, signed_ok: bool) -> bool {
        let Some(pin) = self.peers.pin_for(peer) else {
            return false; // unpinned or blocked
        };
        // Guard 2: the session's bound identity and the agreement key of the
        // bundle it was made from equal the current pin.
        let session_ok = self.session_manager.get(peer).is_some_and(|s| {
            let ak_ok = constant_time_eq(&s.peer_ak, &pin);
            let ik_ok = match (s.peer_identity_key(), key_from_hex(peer)) {
                (Some(ik), Some(p)) => constant_time_eq(&ik, &p),
                _ => false,
            };
            ak_ok && ik_ok
        });
        // Guard 3: plainly Pinned (not Mismatch, BadSignature, blocked or
        // unpinned) and in no rotation, as the old identity or the new.
        let plainly_pinned = self.peers.state(peer) == PeerKeyState::Pinned;
        let rotating = self.rotated_from.contains_key(peer)
            || self.rotated_from.values().any(|(new, _)| new == peer);
        // Guard 4: the pin at send time is still the pin. It also carries
        // rotation safety after a restart: `rotated_from` is memory-only,
        // but entries moved to the new identity keep the old `pin_ak`.
        let pin_unchanged =
            constant_time_eq(&e.pin_ak, &pin) && e.pin_version == self.peers.pin_version(peer);
        // Guard 5: never delivered, at most 72 h old, never resent.
        let undelivered = !e.delivered
            && !e.resent
            && now_unix.saturating_sub(e.sent_at_unix) <= RESET_REPORT_MAX_AGE_SECS;
        // Guard 6: at most MAX_AUTO_RESENDS_PER_DAY in any 24 h.
        let recent = self.auto_resends.get(peer).map_or(0, |q| {
            q.iter()
                .filter(|t| now_unix.saturating_sub(**t) < AUTO_RESEND_WINDOW_SECS)
                .count()
        });
        session_ok
            && plainly_pinned
            && !rotating
            && pin_unchanged
            && undelivered
            && recent < MAX_AUTO_RESENDS_PER_DAY
            // Guard 7: signed by the contact's pinned device key (D46).
            && signed_ok
    }

    /// Final review H-1: an automatic resend of `id` goes only into the
    /// session that made it eligible. That session recorded it in its own
    /// `reported_lost` (session-scoped and persisted with the session and
    /// its `session_binding`; a new session starts with none), so a session
    /// made since, even with the contact's real keys by a seed thief, can
    /// never receive it. Also re-checked: plainly pinned and in no rotation
    /// (guard 3), the session's keys equal the pin (guard 2), and the sent
    /// entry is marked resent, undelivered, within 72 h and sent under the
    /// current pin (guards 4, 5). Guard 7 was decided against this session's
    /// binding when the id was made eligible.
    pub(crate) fn check_auto_resend(&self, peer: &str, id: &[u8; 16]) -> Result<(), RChatError> {
        let refused = || RChatError::ResendRefused {
            identity: peer.to_string(),
        };
        let pin = self.peers.pin_for(peer).ok_or_else(refused)?;
        let rotating = self.rotated_from.contains_key(peer)
            || self.rotated_from.values().any(|(new, _)| new == peer);
        if self.peers.state(peer) != PeerKeyState::Pinned || rotating {
            return Err(refused());
        }
        let session_ok = self.session_manager.get(peer).is_some_and(|s| {
            let eligible_here = s.reported_lost.get(id).is_some_and(|(_, e)| *e);
            let ak_ok = constant_time_eq(&s.peer_ak, &pin);
            let ik_ok = match (s.peer_identity_key(), key_from_hex(peer)) {
                (Some(ik), Some(p)) => constant_time_eq(&ik, &p),
                _ => false,
            };
            eligible_here && ak_ok && ik_ok
        });
        if !session_ok {
            return Err(refused());
        }
        let now = crate::unix_now_secs();
        let entry_ok = self
            .sent_ids_for(peer)
            .into_iter()
            .rev()
            .find(|e| e.id == *id)
            .is_some_and(|e| {
                e.resent
                    && !e.delivered
                    && now.saturating_sub(e.sent_at_unix) <= RESET_REPORT_MAX_AGE_SECS
                    && constant_time_eq(&e.pin_ak, &pin)
                    && e.pin_version == self.peers.pin_version(peer)
            });
        if !entry_ok {
            return Err(refused());
        }
        Ok(())
    }

    /// Put one lost id to guards 2–7 (`signed_ok`: guard 7). When they
    /// hold, the entry is marked `resent` and counted toward the daily
    /// bound, and true is returned: the caller persists, then raises
    /// `ResendEligible`.
    fn maybe_resend(&mut self, peer: &str, id: [u8; 16], signed_ok: bool) -> bool {
        let now = crate::unix_now_secs();
        self.restamp_future_sent(peer, now);
        // The newest entry: a same-id resend records the id again.
        let Some(entry) = self
            .sent_ids_for(peer)
            .into_iter()
            .rev()
            .find(|e| e.id == id)
        else {
            return false;
        };
        if !self.resend_guards_hold(peer, &entry, now, signed_ok) {
            return false;
        }
        debug_assert!(
            {
                let all = self.sent_ids_for(peer);
                let mut same = all.iter().filter(|e| e.id == id).map(|e| e.resent);
                let first = same.next();
                same.all(|r| Some(r) == first)
            },
            "entries for one id are all resent or none"
        );
        self.mark_sent_resent(peer, &id);
        let q = self.auto_resends.entry(peer.to_string()).or_default();
        q.retain(|t| now.saturating_sub(*t) < AUTO_RESEND_WINDOW_SECS);
        q.push_back(now);
        true
    }

    /// Mark every entry for `id` as automatically resent (D38 guard 5).
    pub(crate) fn mark_sent_resent(&self, peer: &str, id: &[u8; 16]) {
        self.set_sent_resent(peer, id, true);
    }

    fn set_sent_resent(&self, peer: &str, id: &[u8; 16], resent: bool) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = all.get_mut(peer) {
            for e in q.iter_mut().filter(|e| &e.id == id) {
                e.resent = resent;
            }
        }
    }

    /// Take back `mark_sent_resent` after a failed write: every entry's
    /// `resent` as it was (`before`, in entry order). Nothing else touches
    /// the entries in between (`&mut self`).
    fn restore_resent(&self, peer: &str, before: &[bool]) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = all.get_mut(peer) {
            debug_assert_eq!(q.len(), before.len());
            for (e, r) in q.iter_mut().zip(before) {
                e.resent = *r;
            }
        }
    }

    /// Re-stamp entries sent "in the future" (the clock went back) to now,
    /// so guard 5's 72 h bound still runs (the Task 1 clock ruling).
    fn restamp_future_sent(&self, peer: &str, now_unix: u64) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = all.get_mut(peer) {
            for e in q.iter_mut() {
                e.sent_at_unix = e.sent_at_unix.min(now_unix);
            }
        }
    }

    /// A delivered or read receipt arrived for `id`: it is never reported
    /// undelivered (D37). True when the entry changed (the caller persists).
    pub(crate) fn mark_sent_delivered(&self, peer: &str, id: &[u8; 16]) -> bool {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;
        if let Some(q) = all.get_mut(peer) {
            for e in q.iter_mut().filter(|e| &e.id == id && !e.delivered) {
                e.delivered = true;
                changed = true;
            }
        }
        changed
    }

    /// The app stored the message `id` from `sender` (D36): mark it seen,
    /// and queue its delivered receipt if it was handed over and not yet
    /// confirmed stored. Durable before the receipt can leave.
    pub(crate) fn mark_seen_and_receipt(
        &mut self,
        sender: &str,
        id: [u8; 16],
    ) -> Result<(), RChatError> {
        self.peers.mark_seen(sender, id);
        self.drain_note_stored(sender, id);
        let was_unstored = self.delivered_unstored.get_mut(sender).is_some_and(|q| {
            let before = q.len();
            q.retain(|x| x != &id);
            q.len() != before
        });
        if was_unstored {
            self.queue_receipt(sender, receipts::DELIVERED, &[id]);
        }
        self.persist_peer(sender)?;
        self.flush_receipts(sender);
        Ok(())
    }

    /// Messages queued for `peer_hex` whose session went before they could
    /// be put back (`flush_queued_sends`): they never left the device.
    pub(crate) fn report_queued_sends_lost(
        &self,
        peer_hex: &str,
        lost: &std::collections::VecDeque<crate::session::PendingMessage>,
    ) {
        log::warn!(
            "[RUST] {} queued message(s) dropped: their session is gone",
            lost.len()
        );
        for m in lost {
            self.emit_status(StatusEvent::QueuedSendLost {
                peer: peer_hex.to_string(),
                message_id: m.id.0.clone(),
            });
        }
    }

    /// Tick: re-send what a new session owes once writes succeed again: the
    /// initiator's hello sync (so the responder gets its sending chain
    /// without waiting for real traffic) and a notice no timer is waiting
    /// to send, only over a usable transport; and, with or without one, the
    /// write of a peer's heard verdict that failed (`heard_unrecorded`). A
    /// peer whose writes are failing is probed at most once per `REDRIVE_PROBE_INTERVAL` (across
    /// all peers), and a peer whose notice the transport refused waits for
    /// the next transport.
    pub(crate) fn redrive_owed_sends(&mut self, now: Instant) {
        let mut may_probe = self.last_redrive_probe.map_or(true, |at| {
            now.saturating_duration_since(at) >= REDRIVE_PROBE_INTERVAL
        });
        let mut gate = |this: &mut Self, peer: &str| -> bool {
            if !this.persist_failing(peer) {
                return true;
            }
            if !may_probe {
                return false;
            }
            may_probe = false;
            this.last_redrive_probe = Some(now);
            true
        };
        // A heard verdict whose write failed (no transport needed).
        let unrecorded: Vec<String> = self
            .session_manager
            .get_all_recipients()
            .into_iter()
            .filter(|p| {
                self.session_manager
                    .get(p)
                    .is_some_and(|s| s.heard_unrecorded)
            })
            .collect();
        for peer in unrecorded {
            if gate(self, &peer) {
                let _ = self.persist_peer(&peer);
            }
        }
        if !self.transport_usable() {
            return;
        }
        let owed: Vec<String> = self.hello_sync_due.iter().cloned().collect();
        for peer in owed {
            if self.check_sendable(&peer).is_err()
                || !self.has_live_circuit(&peer)
                || !gate(self, &peer)
            {
                continue;
            }
            if self.send_hello_sync(&peer) {
                self.hello_sync_due.remove(&peer);
            }
        }
        // Tracked re-sends held behind a session-init that is out now (M-3).
        let held: Vec<String> = self.resend_after_init.iter().cloned().collect();
        for peer in held {
            let init_out = self.session_manager.get(&peer).is_some_and(|s| {
                !s.init_out
                    .as_ref()
                    .is_some_and(|i| !matches!(&i.sent, Some(x) if !x.payload.is_empty()))
            });
            if init_out {
                self.resend_tracked(&peer);
            }
        }
        let due: Vec<String> = self
            .notice_due
            .iter()
            .filter(|p| !self.receipt_due.contains_key(*p) && !self.hello_sync_due.contains(*p))
            .filter(|p| self.notice_send_stalled.get(*p) != Some(&self.transport_epoch))
            .cloned()
            .collect();
        for peer in due {
            let ready = self.check_sendable(&peer).is_ok()
                && self.has_live_circuit(&peer)
                && self
                    .session_manager
                    .get(&peer)
                    .is_some_and(|s| s.can_send());
            if ready && gate(self, &peer) {
                self.flush_receipts(&peer);
            }
        }
    }

    /// Tests: make every message sent to `peer` look `by_secs` older.
    #[cfg(test)]
    pub(crate) fn age_sent_for_test(&self, peer: &str, by_secs: u64) {
        let mut all = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = all.get_mut(peer) {
            for e in q.iter_mut() {
                e.sent_at_unix = e.sent_at_unix.saturating_sub(by_secs);
            }
        }
    }

    /// Schedule queued receipts for `peer_hex` (spec §5.7): a 0.5-3 s window
    /// from the first one, sent at once when a full batch is waiting.
    pub(crate) fn flush_receipts(&mut self, peer_hex: &str) {
        if self.steady_holds(peer_hex) {
            // Steady traffic (§B.3): receipts and notices keep their
            // batching but drain through slots; they go this way again
            // when steady stops (`apply_steady`).
            return;
        }
        let queued: usize = [receipts::DELIVERED, receipts::READ]
            .iter()
            .filter_map(|k| self.pending_receipts.get(&(peer_hex.to_string(), *k)))
            .map(Vec::len)
            .sum::<usize>()
            // An owed session notice goes through the same timer (D37).
            + usize::from(self.notice_due.contains(peer_hex));
        if queued == 0 {
            return;
        }
        if queued >= receipts::MAX_IDS {
            self.receipt_due.remove(peer_hex);
            self.send_receipts_now(peer_hex);
            return;
        }
        // A window already open keeps its deadline; a delay is drawn only
        // for a new one (Task 16b minor).
        if self.receipt_due.contains_key(peer_hex) {
            return;
        }
        let delay = self.receipt_delay();
        if delay.is_zero() {
            self.send_receipts_now(peer_hex);
            return;
        }
        self.receipt_due
            .insert(peer_hex.to_string(), Instant::now() + delay);
    }

    /// Send every batch whose window has closed.
    pub(crate) fn fire_due_receipts(&mut self, now: Instant) {
        // Slots drain a held peer's receipts (§B.3); due again when steady
        // stops or the peer leaves the draw (R23).
        let due: Vec<String> = self
            .receipt_due
            .iter()
            .filter(|(p, at)| **at <= now && !self.steady_holds(p))
            .map(|(p, _)| p.clone())
            .collect();
        for peer in due {
            if !self.transport_usable() {
                // Nothing is sealed meanwhile: try again after a fresh
                // delay, so a queue that was only full is not stranded.
                let at = now + self.receipt_delay();
                self.receipt_due.insert(peer, at);
                continue;
            }
            self.receipt_due.remove(&peer);
            self.send_receipts_now(&peer);
        }
    }

    /// A fresh random receipt delay (also used for cover-traffic replies).
    pub(crate) fn receipt_delay(&self) -> Duration {
        self.receipt_delay_override
            .unwrap_or_else(|| receipt_delay_for(rand::random::<f64>()))
    }

    /// Cover requests sent to `peer_hex` within the last hour.
    fn cover_sent_last_hour(&self, peer_hex: &str, now: Instant) -> usize {
        self.cover_sent.get(peer_hex).map_or(0, |q| {
            q.iter()
                .filter(|at| now.saturating_duration_since(**at) < COVER_CAP_WINDOW)
                .count()
        })
    }

    /// Round-2 M5, for requests: sendable, live circuit, heard from within
    /// 60 s, and under 20 cover requests to this peer this hour. Replies are
    /// not capped here (see `fire_cover`).
    fn cover_eligible(&self, peer_hex: &str, now: Instant) -> bool {
        let heard = self
            .last_heard
            .get(peer_hex)
            .is_some_and(|at| now.saturating_duration_since(*at) <= COVER_HEARD_WINDOW);
        heard
            && self.check_sendable(peer_hex).is_ok()
            && self.has_live_circuit(peer_hex)
            && self.cover_sent_last_hour(peer_hex, now) < MAX_COVER_PER_HOUR
    }

    /// Send one cover packet (request or reply) to `peer_hex`: `0x05 ||
    /// flag || random`, 2-200 bytes before padding (so the 256-byte bucket).
    pub(crate) fn send_cover(
        &mut self,
        peer_hex: &str,
        reply: bool,
        now: Instant,
    ) -> Result<(), RChatError> {
        self.check_sendable(peer_hex)?;
        // Never sealed while the transport is down (no chain key spent); a
        // due reply waits (`fire_cover`).
        if !self.transport_usable() {
            return Err(RChatError::NotConnected);
        }
        let len = 2 + (OsRng.next_u32() % 199) as usize;
        let mut pt = vec![0u8; len];
        OsRng.fill_bytes(&mut pt);
        pt[0] = COVER_TYPE;
        pt[1] = if reply { COVER_REPLY } else { COVER_REQUEST };
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let packet = self.seal_ratchet(peer_hex, id, &pt)?;
        self.send_now(packet.encode_with_frame_type())?;
        if reply {
            // Replies are exempt from the cap: an unanswered request would
            // mark it as cover (real messages always get a receipt).
            return Ok(());
        }
        let q = self.cover_sent.entry(peer_hex.to_string()).or_default();
        q.push_back(now);
        while q
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= COVER_CAP_WINDOW)
        {
            q.pop_front();
        }
        Ok(())
    }

    /// Round-2 M4: answer a cover request the way a real message is
    /// answered: one reply at the receipt delay and, with probability 0.8,
    /// a second 2-30 s later (the read-receipt rate). Bounded per peer by
    /// the pending limit and by `MAX_COVER_REPLIES_PER_HOUR` replies
    /// scheduled in the last hour (security review L-2); a request past
    /// either is dropped silently.
    pub(crate) fn schedule_cover_replies(&mut self, peer_hex: &str, now: Instant) {
        if self.in_drain() {
            return; // no cover traffic from a background drain (§H.1)
        }
        let scheduled =
            |due: &Vec<(String, Instant)>| due.iter().filter(|(p, _)| p == peer_hex).count();
        if scheduled(&self.cover_replies_due) >= MAX_COVER_PER_HOUR
            || !self.charge_cover_reply(peer_hex, now)
        {
            return;
        }
        let first = now + self.receipt_delay();
        self.cover_replies_due.push((peer_hex.to_string(), first));
        let second = self
            .cover_reply_coin_override
            .unwrap_or_else(|| rand::random::<f64>() < 0.8);
        if second
            && scheduled(&self.cover_replies_due) < MAX_COVER_PER_HOUR
            && self.charge_cover_reply(peer_hex, now)
        {
            let secs = 2.0 + rand::random::<f64>() * 28.0;
            self.cover_replies_due
                .push((peer_hex.to_string(), now + Duration::from_secs_f64(secs)));
        }
    }

    /// Take one of the peer's hourly cover replies (L-2), if any is left.
    fn charge_cover_reply(&mut self, peer_hex: &str, now: Instant) -> bool {
        let q = self
            .cover_replies_charged
            .entry(peer_hex.to_string())
            .or_default();
        while q
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= COVER_CAP_WINDOW)
        {
            q.pop_front();
        }
        if q.len() >= MAX_COVER_REPLIES_PER_HOUR {
            return false;
        }
        q.push_back(now);
        true
    }

    /// Cover tick (spec §5.7): due replies always go out, whatever our own
    /// setting (bounded when scheduled: the pending limit and the hourly
    /// reply cap); like receipts, a reply due while the circuit is
    /// down waits for it, and one to an unsendable peer is dropped. Requests
    /// only while cover is enabled and in the foreground, one every
    /// `cover_delay_for` to a random eligible peer.
    pub(crate) fn fire_cover(&mut self, now: Instant) {
        if self.steady_active() {
            // Steady traffic replaces cover requests (§B.1): never both.
            // Due replies wait; a slot's cover packet to the peer stands
            // for one (`steady_send_cover`), the rest go when steady stops.
            self.cover_next = None;
            return;
        }
        let (due, mut later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.cover_replies_due)
            .into_iter()
            .partition(|(_, at)| *at <= now);
        for (peer, at) in due {
            match self.check_sendable(&peer) {
                Ok(()) => {}
                Err(RChatError::PeerKeyUnverified { .. }) => {
                    later.push((peer, at)); // transient: keep
                    continue;
                }
                Err(_) => continue, // terminal: never send
            }
            if !self.has_live_circuit(&peer) || self.send_cover(&peer, true, now).is_err() {
                log::debug!("[RUST] cover reply deferred");
                later.push((peer, at));
            }
        }
        self.cover_replies_due = later;
        if !(self.cover_enabled && self.cover_foreground) {
            self.cover_next = None;
            return;
        }
        match self.cover_next {
            None => self.cover_next = Some(now + cover_delay_for(rand::random::<f64>())),
            Some(due) if due <= now => {
                let eligible: Vec<String> = self
                    .session_manager
                    .get_all_recipients()
                    .into_iter()
                    .filter(|p| self.cover_eligible(p, now))
                    .collect();
                if !eligible.is_empty() {
                    let peer = &eligible[(OsRng.next_u32() as usize) % eligible.len()];
                    if self.send_cover(peer, false, now).is_err() {
                        log::debug!("[RUST] cover packet not sent");
                    }
                }
                self.cover_next = Some(now + cover_delay_for(rand::random::<f64>()));
            }
            Some(_) => {}
        }
    }

    /// Spec §4.4 steps 1–8, in order, with X3DH v3 (§A.3). Every outcome
    /// answers the peer's ask (spec §18.6 D33): on success the session's own
    /// meta write carries the cleared ask; on any other outcome (including a
    /// responder now waiting for session-init) the meta record is written here.
    pub(crate) fn handle_circuit_created_v3(&mut self, f: CircuitCreatedV3Frame) {
        let asks_before = self.unanswered_asks.len();
        let installed = self.circuit_created_v3_steps(f);
        if !installed && self.unanswered_asks.len() != asks_before {
            self.persist_meta();
        }
    }

    /// `handle_circuit_created_v3`'s steps; true when a session was
    /// installed (role 0; the meta record is written once it is durable).
    /// Role 1 installs nothing: it keeps a `PendingInit` until session-init.
    fn circuit_created_v3_steps(&mut self, f: CircuitCreatedV3Frame) -> bool {
        let now = Instant::now();
        // Shape first (RF4): nothing below may index past a short field.
        let (Some(i_ek), Some(r_ek)) = (
            ek32(&f.initiator_ephemeral_key),
            ek32(&f.responder_ephemeral_key),
        ) else {
            self.close_circuit_id(&f.circuit_id);
            return false;
        };
        let Ok(r_kem) = <&[u8; KEM_PK_LEN]>::try_from(f.responder_kem_ephemeral_pk.as_slice())
        else {
            self.close_circuit_id(&f.circuit_id);
            return false;
        };
        if f.role > 1
            || f.token.len() != 32
            || f.initiator_kem_ephemeral_pk.len() != KEM_PK_LEN
            || f.initiator_ephemeral_sig.len() != crate::protocol::ASK_EPH_SIG_LEN
            || f.responder_ephemeral_sig.len() != crate::protocol::ASK_EPH_SIG_LEN
        {
            self.close_circuit_id(&f.circuit_id);
            return false;
        }
        let Ok(bundle) = f.peer.to_signed() else {
            self.close_circuit_id(&f.circuit_id);
            return false;
        };
        let peer_hex = hex::encode(bundle.identity_key);
        // Every outcome below answers the peer's ask; the later steps return
        // early, so the clear comes first (in memory; see the caller).
        let answered = self.unanswered_asks.remove(&peer_hex).is_some();

        // 1. Unpinned, blocked or (sticky, §4.4) mismatched peer (C-8).
        let Some(pinned_ak) = self.peers.pin_for(&peer_hex) else {
            self.close_circuit_id(&f.circuit_id);
            return false;
        };
        if self.peers.is_blocked(&peer_hex) || self.peers.is_mismatch(&peer_hex) {
            self.close_circuit_id(&f.circuit_id);
            return false;
        }

        // 2. Echo check: my own outstanding EK must come back (H1, M9). Consumed on match.
        let mine = if f.role == 0 { i_ek } else { r_ek };
        let Some(ask) = self.peers.take_ask(&peer_hex, &mine, now) else {
            // A blind ask we retired while the relay held it, met by the
            // peer: our epoch follows the peer's before the re-ask, but
            // only for a frame the peer's keys verify (fix round 2 N-3):
            // a relay cannot move our counter with a forged one.
            if self.created_frame_verifies(&f, &bundle, &pinned_ak, &i_ek, &r_ek) {
                self.adopt_stray_blind_match(&peer_hex, &mine);
            }
            self.close_circuit_id(&f.circuit_id);
            self.schedule_reask(&peer_hex);
            return false;
        };
        let AskKeys {
            ek: my_ek,
            kem: my_kem,
            kem_seed,
            blind,
        } = ask;
        let origin = if blind.is_some() {
            crate::blind::InstallOrigin::Blind
        } else {
            crate::blind::InstallOrigin::Identity
        };

        // 3. Bad bundle signature (v3: ik, ak and kem_pk): transient (M1), re-ask.
        if keyauth::verify_bundle(&bundle).is_err() {
            self.peers.mark_bad_signature(&peer_hex, now);
            self.close_circuit_id(&f.circuit_id);
            self.emit_peer_key_event(&peer_hex, PeerKeyState::BadSignature as u8, "");
            self.schedule_reask(&peer_hex);
            return false;
        }

        // 4. Pin mismatch (constant time): sticky, no re-ask. The signed
        //    KEM key must equal the pinned one too (§A.6, R11).
        // 5. Agreement key pinned for another identity (M10): refused the same way.
        if !constant_time_eq(&pinned_ak, &bundle.identity_agreement_key)
            || !self.peers.kem_matches(&peer_hex, &bundle.kem_pk)
            || self
                .peers
                .pinned_elsewhere(&peer_hex, &bundle.identity_agreement_key)
        {
            self.peers.mark_mismatch(&peer_hex);
            self.close_circuit_id(&f.circuit_id);
            self.emit_peer_key_event(
                &peer_hex,
                PeerKeyState::Mismatch as u8,
                &hex::encode(bundle.identity_agreement_key),
            );
            return false;
        }

        // 5b (R7). The peer's ask ephemerals must carry its signature under
        // the pinned identity key, before any KEM operation: a relay cannot
        // substitute its own X25519 or KEM ephemeral for the peer's.
        let (peer_ek, peer_kem, peer_sig) = if f.role == 0 {
            (
                &r_ek,
                &f.responder_kem_ephemeral_pk,
                &f.responder_ephemeral_sig,
            )
        } else {
            (
                &i_ek,
                &f.initiator_kem_ephemeral_pk,
                &f.initiator_ephemeral_sig,
            )
        };
        if keyauth::verify_ask_ephemerals(&bundle.identity_key, peer_ek, peer_kem, peer_sig)
            .is_err()
        {
            self.close_circuit_id(&f.circuit_id);
            self.schedule_reask(&peer_hex);
            return false;
        }
        // M-4: the pair formed; the peer's other outstanding asks (their
        // X25519 and KEM secrets) are wiped now, not at `ASK_TTL`. A new
        // pair: an init awaited on an older one can no longer come. Only
        // after the bundle and the peer's ask signature verify (final
        // review L3): a forged frame wipes nothing.
        self.peers.drop_asks(&peer_hex);
        self.pending_inits.remove(&peer_hex);
        // §C.1, R14: a blind token is spent by this verified match; both
        // sides advance their epoch now, whether or not the session-init
        // comes. Only after the peer's signature checks (fix round 2 N-3):
        // a tampered frame never moves our counter.
        self.note_pair_match(&peer_hex, &mine, blind);

        let Some(identity) = self.identity.as_ref() else {
            self.close_circuit_id(&f.circuit_id);
            return false;
        };
        let my_ik = identity.public_signing_key().to_bytes();

        if f.role == 1 {
            // 6 (responder). The relay must echo our own KEM ephemeral as
            // the responder's (constant time): a swapped key would leave the
            // initiator encapsulating to someone else's key. Refused like an
            // EK that does not echo.
            // The X25519 half is checked now (L1, K17), although SK is
            // derived only once session-init brings the KEM ciphertext.
            let contributory = keyauth::dh_checked(my_ek.secret_key(), &i_ek).is_ok()
                && keyauth::dh_checked(identity.agreement_secret(), &i_ek).is_ok();
            if !constant_time_eq(my_kem.public(), r_kem) || !contributory {
                self.close_circuit_id(&f.circuit_id);
                self.schedule_reask(&peer_hex);
                return false;
            }
            // No session until session-init arrives (§A.3): the ask's
            // ephemerals wait for it, wiped when the entry goes.
            let pending = PendingInit {
                kem: my_kem,
                kem_seed,
                ek_r: my_ek.secret_key().clone(),
                i_ek,
                peer_ak: bundle.identity_agreement_key,
                circuit_id: f.circuit_id,
                target_circuit_id: f.target_circuit_id,
                token: Zeroizing::new(f.token.as_slice().try_into().unwrap_or([0; 32])),
                circuit_epoch: self.transport_epoch,
                expires_at_unix: crate::unix_now_secs() + crate::peers::ASK_TTL.as_secs(),
                created_at_unix: crate::unix_now_secs(),
                origin,
            };
            self.pending_inits.insert(peer_hex.clone(), pending);
            self.peers.clear_bad_signature(&peer_hex);
            // Best effort: a restart before the init arrives can still open it.
            let _ = self.persist_peer(&peer_hex);
            return false;
        }

        // 6 (initiator). Our own KEM ephemeral has no use once we are the
        // initiator: wiped now (ruling: §A.3 forward secrecy).
        drop(my_kem);
        drop(kem_seed);
        // Encapsulate to the responder's ask KEM key (FIPS 203 §7.2 check
        // first); then X3DH v3 with the verified keys only.
        let encaps = crate::kem::validate_public_key(r_kem)
            .and_then(|()| crate::kem::encapsulate(r_kem))
            .ok();
        let sk = encaps.as_ref().and_then(|(ct, ss)| {
            x3dh_v3_initiator(
                identity.agreement_secret(),
                my_ek.secret_key(),
                &bundle.identity_agreement_key,
                &r_ek,
                ss,
                r_kem,
                ct,
                &my_ik,
                &bundle.identity_key,
            )
            .ok()
        });
        let (Some((ct, _ss)), Some(sk)) = (encaps, sk) else {
            // A malformed responder KEM key or a non-contributory relay EK
            // (L1, K17): a handshake failure.
            self.close_circuit_id(&f.circuit_id);
            self.schedule_reask(&peer_hex);
            return false;
        };
        let confirm = crate::session_init::init_confirm(&sk, &ct);
        let ek_secret = Zeroizing::new(my_ek.secret_key().to_bytes());
        drop(my_ek);
        let installed = self.install_session(
            &peer_hex,
            NewSession {
                role: 0,
                sk: &sk,
                my_ik,
                peer_ik: bundle.identity_key,
                peer_ak: bundle.identity_agreement_key,
                ek: ek_secret,
                circuit_id: f.circuit_id.clone(),
                target_circuit_id: f.target_circuit_id,
                token: f.token,
                circuit_epoch: self.transport_epoch,
                init_out: Some(Box::new(InitOut {
                    ct: Box::new(ct),
                    confirm,
                    sent: None,
                })),
                answered,
                origin,
            },
        );
        if !installed {
            self.close_circuit_id(&f.circuit_id);
            return false;
        }
        // §A.4: the first packet on the circuit is session-init, carrying
        // the invisible first message (a cover message) when the app has
        // nothing to send yet.
        if !self.send_hello_sync(&peer_hex) {
            // Re-sent by the tick once writes succeed (`redrive_owed_sends`).
            self.hello_sync_due.insert(peer_hex.clone());
        }
        self.process_pending_encrypted(&peer_hex);
        // Tracked payloads first (sent before this session), then what the
        // new session owes, so nothing tracked just now is sent twice.
        self.resend_tracked(&peer_hex);
        self.flush_receipts(&peer_hex);
        true
    }

    /// The checks a `CircuitCreatedV3` must pass before it may move our
    /// pair epoch (N-3): the peer's bundle signature, its keys equal to the
    /// pins, and the peer's signature over its ask ephemerals (R7).
    fn created_frame_verifies(
        &self,
        f: &CircuitCreatedV3Frame,
        bundle: &crate::keyauth::SignedBundle,
        pinned_ak: &[u8; 32],
        i_ek: &[u8; 32],
        r_ek: &[u8; 32],
    ) -> bool {
        let peer_hex = hex::encode(bundle.identity_key);
        let (peer_ek, peer_kem, peer_sig) = if f.role == 0 {
            (
                r_ek,
                &f.responder_kem_ephemeral_pk,
                &f.responder_ephemeral_sig,
            )
        } else {
            (
                i_ek,
                &f.initiator_kem_ephemeral_pk,
                &f.initiator_ephemeral_sig,
            )
        };
        keyauth::verify_bundle(bundle).is_ok()
            && constant_time_eq(pinned_ak, &bundle.identity_agreement_key)
            && self.peers.kem_matches(&peer_hex, &bundle.kem_pk)
            && keyauth::verify_ask_ephemerals(&bundle.identity_key, peer_ek, peer_kem, peer_sig)
                .is_ok()
    }

    /// Steps 7–8 for a verified X3DH v3 secret, on either role: the session
    /// keyed by the peer's identity replaces the current one (which becomes
    /// the single retired session), owes its notice, and is written before
    /// it is announced (D28). False when the ratchet could not be set up.
    fn install_session(&mut self, peer_hex: &str, n: NewSession<'_>) -> bool {
        let initiator = n.role == 0;
        // 7. Session keyed by the peer's identity; never touch current_recipient (F4).
        let mut session = ChatSession::new(peer_hex.to_string());
        session.set_identities(n.my_ik, n.peer_ik);
        let init = if initiator {
            session.initialize_alice(n.sk, &n.ek, n.peer_ak)
        } else {
            let Some(identity) = self.identity.as_ref() else {
                return false;
            };
            let ak_secret = Zeroizing::new(identity.agreement_secret().to_bytes());
            let i_ek: [u8; 32] = *n.ek;
            session.initialize_bob(n.sk, &ak_secret, i_ek)
        };
        if init.is_err() {
            return false;
        }
        session.set_circuit(n.circuit_id, n.target_circuit_id, n.token);
        session.circuit_epoch = n.circuit_epoch;
        session.init_out = n.init_out;
        // Messages send_* accepted for the old session (or a retired one)
        // move to the new session, so they are still sent.
        session.pending_messages = self.session_manager.take_pending(peer_hex);
        session.peer_ak = n.peer_ak;
        // What this session's notice signatures are bound to (D45).
        session.session_binding = crate::device_key::session_binding(n.sk);
        // §C.1 and R14: an identity install derives PS from this SK, on
        // either role, and the epoch starts at (today, 0); a blind install
        // keeps the pair's PS and its epoch (advanced at the match).
        let blind = n.origin == crate::blind::InstallOrigin::Blind;
        let kept = blind
            .then(|| {
                self.session_manager
                    .get(peer_hex)
                    .and_then(|s| s.pair_secret.clone().map(|ps| (ps, s.pair_epoch)))
            })
            .flatten();
        match kept {
            Some((ps, epoch)) => {
                session.pair_secret = Some(ps);
                session.pair_epoch = epoch;
            }
            None => {
                if blind {
                    // Not expected (a blind ask needs PS): the fresh PS
                    // desyncs the tokens, which the identity fallback heals.
                    log::debug!("[RUST] blind install without a pair secret; derived anew");
                }
                session.pair_secret = Some(crate::pairing::pair_secret(n.sk));
                session.pair_epoch = crate::pairing::PairEpoch {
                    day: crate::pairing::utc_day(self.pair_now_unix()),
                    counter: 0,
                };
            }
        }
        session.blinded = blind;
        // R20: the fallback clock starts again with this verified install
        // (M-3: only here, never at the bare match); the last fallback's
        // time carries over, so at most one per interval.
        session.last_identity_fallback_unix = self
            .session_manager
            .get(peer_hex)
            .and_then(|s| s.last_identity_fallback_unix);
        self.identity_fallback.remove(peer_hex);
        if !blind {
            // M-4: a new pair secret: what was sealed under the old lineage
            // is never re-sealed (AK4), so its plaintext goes now.
            self.ack_tracker_drop_plaintexts(peer_hex, session.pair_lineage());
        }
        // A placeholder session (pending sends only, no ratchet) is not a
        // prior session (F32).
        let had_prior = self
            .session_manager
            .get(peer_hex)
            .is_some_and(|s| s.ratchet.is_some())
            || self.session_manager.retired_count(peer_hex) > 0;
        // 8. An existing session becomes the single retired, decrypt-only session.
        self.session_manager.install(peer_hex.to_string(), session);
        // R32: our timer change the peer hasn't acknowledged goes again on
        // the new session (identity or blind install alike).
        self.queue_timer_state_with(peer_hex, false);
        // Exactly one notice per new session (D37), persisted as
        // `notice_due` with the session; scheduled before the held bodies
        // are retried, so their failures join it.
        self.notice_due.insert(peer_hex.to_string());
        // This session's flag: set when we held no session with the peer,
        // or when the session we held was itself made with none and its
        // notice never left (the flag still owed). The peer has then heard
        // of no session of ours since the one it last knew, and it reads
        // the flag against the session it held when ours was announced
        // last (`ChatSession::reset_since_unix`), so a carried flag reports
        // a reset only if there truly was one (Task 11 follow-up).
        let owed = self
            .notice_flag_pending
            .get(peer_hex)
            .is_some_and(|f| f & notice::FLAG_NO_PRIOR_SESSION != 0);
        if !had_prior || owed {
            self.notice_flag_pending
                .insert(peer_hex.to_string(), notice::FLAG_NO_PRIOR_SESSION);
        } else {
            self.notice_flag_pending.remove(peer_hex);
        }
        self.hello_sync_due.remove(peer_hex);
        // D28: durable before it is announced. On failure the session stays
        // in memory and the next successful write carries it; that write
        // raises the owed `SessionReplaced` (`persist_peer`).
        // The answered ask leaves the meta record only once the session is
        // on disk (that write's `after_durable` writes the meta record): a
        // kill before then must still find the ask (D33).
        if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
            // A blind re-pair replaces the ratchet on every reconnect by
            // design (§C.3): never a `SessionReplaced` warning.
            s.replaced_unannounced = s.replaced_established && !blind;
            s.ask_answered_unrecorded = n.answered;
        }
        self.identity_wanted.remove(peer_hex);
        let persisted = self.persist_peer(peer_hex).is_ok();
        self.peers.clear_bad_signature(peer_hex);
        self.peers.backoff_mut(peer_hex).reset();
        self.pending_reasks.remove(peer_hex);
        // Round-2 M3: reached under our new identity; the app learns it from
        // `on_circuit_established` and persists the smaller set.
        self.rotation_reached(peer_hex);
        // The intro precedes only the first circuit; the app now sends its
        // text as an ordinary message under the intro id.
        self.intros.remove(peer_hex);
        self.is_e2ee_initiator = initiator;
        if persisted {
            if let Some(cb) = &self.callbacks {
                cb.on_circuit_established(peer_hex.to_string(), initiator);
            }
        }
        true
    }

    /// A responder is waiting for this peer's session-init (§A.3).
    pub(crate) fn awaiting_init(&self, peer_hex: &str) -> bool {
        self.pending_inits.contains_key(peer_hex)
    }

    /// The peer awaiting session-init on `circuit_id`, with that circuit's token.
    pub(crate) fn pending_init_by_circuit(
        &self,
        circuit_id: &CircuitId,
    ) -> Option<(String, [u8; 32])> {
        self.pending_inits
            .iter()
            .find(|(_, p)| p.circuit_id == *circuit_id || p.target_circuit_id == *circuit_id)
            .map(|(peer, p)| (peer.clone(), *p.token))
    }

    /// Stop waiting for the peer's session-init (its circuit went, or the
    /// wait ran out): the KEM and X25519 ephemerals are wiped, and an
    /// askable peer is asked again with the usual backoff (§A.3 failure
    /// handling). True if one was awaited.
    pub(crate) fn abandon_pending_init(&mut self, peer_hex: &str, close: bool) -> bool {
        let Some(p) = self.pending_inits.remove(peer_hex) else {
            return false;
        };
        if close {
            self.close_circuit_id(&p.circuit_id);
        }
        drop(p);
        let _ = self.persist_peer(peer_hex);
        if self.require_askable(peer_hex).is_ok() {
            self.schedule_reask(peer_hex);
        }
        true
    }

    /// Spec §A.3 / §A.4, responder: a session-init from `sender_hex`. With
    /// an init awaited from the sender, decapsulate, derive SK, check the
    /// confirmation tag (constant time) and only then install the session
    /// and process the embedded first message. Anything else is dropped
    /// silently: a replay or a re-send of an init already used (Review
    /// Focus 2: no second install, no ratchet reset, no event), or a
    /// session-init nobody awaits.
    pub(crate) fn handle_session_init(
        &mut self,
        sender_hex: &str,
        message_id: [u8; 16],
        body: &[u8],
        on_pending_circuit: bool,
    ) {
        let accepted = matches!(
            self.peers.state(sender_hex),
            PeerKeyState::Pinned | PeerKeyState::BadSignature
        );
        if !accepted {
            return; // unaccepted, blocked or mismatched sender (N5)
        }
        let already_received = self
            .received_ids
            .get(sender_hex)
            .is_some_and(|q| q.contains(&message_id));
        if already_received || !self.awaiting_init(sender_hex) {
            // Its first message was decrypted already (a relay replay or the
            // initiator's byte-identical re-send), or no init is awaited.
            // The app already stored that message: re-owe its receipt, as
            // for any duplicate envelope (spec §18.7).
            if already_received && self.peers.is_seen(sender_hex, &message_id) {
                self.queue_receipt(sender_hex, receipts::DELIVERED, &[message_id]);
                self.flush_receipts(sender_hex);
            }
            if !already_received {
                // Its first message is lost with it (review M-2): listed as
                // undecryptable, so the sender learns of it (D38 notice).
                self.record_undecryptable(sender_hex, message_id, false);
            }
            log::debug!("[RUST] session-init not awaited; dropped");
            return;
        }
        let Some((sk, first_msg)) = self.open_session_init(sender_hex, body) else {
            // A handshake failure (wrong length, decapsulation, confirmation):
            // no session (ruling R9). On the pending circuit itself (its
            // token verified, the sender its owner) the wait ends at once:
            // close and re-ask with backoff. From the offline queue (no
            // circuit, so anyone the relay forwards for) nothing changes:
            // a genuine init may still come, and the wait's TTL runs.
            if on_pending_circuit {
                self.abandon_pending_init(sender_hex, true);
            }
            log::debug!("[RUST] session-init refused");
            return;
        };
        let Some(p) = self.pending_inits.remove(sender_hex) else {
            return;
        };
        let (Some(peer_ik), Some(my_ik)) = (key_from_hex(sender_hex), self.our_ik()) else {
            return;
        };
        let origin = p.origin;
        let installed = self.install_session(
            sender_hex,
            NewSession {
                role: 1,
                sk: &sk,
                my_ik,
                peer_ik,
                peer_ak: p.peer_ak,
                ek: Zeroizing::new(p.i_ek),
                circuit_id: p.circuit_id.clone(),
                target_circuit_id: p.target_circuit_id.clone(),
                token: p.token.to_vec(),
                circuit_epoch: p.circuit_epoch,
                init_out: None,
                answered: false,
                origin: p.origin,
            },
        );
        // The ask's KEM and X25519 ephemerals are wiped here, right after use.
        drop(p);
        if !installed {
            let _ = self.persist_peer(sender_hex);
            if self.require_askable(sender_hex).is_ok() {
                self.schedule_reask(sender_hex);
            }
            return;
        }
        if origin == crate::blind::InstallOrigin::Blind {
            // R19: what we sent before is re-sealed under this session, and
            // a responder's ratchet can seal only once the embedded first
            // message gave it a sending chain: that message first, then the
            // payloads tracked before it (only those, so nothing tracked
            // under the new session is sent twice).
            let earlier = self.tracked_ids_for(sender_hex);
            self.handle_ratchet(sender_hex, message_id, &first_msg);
            self.resend_tracked_among(sender_hex, Some(&earlier));
        } else {
            // Tracked payloads first (sent before this session, so nothing
            // tracked under it is sent twice), then the embedded first
            // message under the new session, then what was held and what
            // is owed.
            self.resend_tracked(sender_hex);
            self.handle_ratchet(sender_hex, message_id, &first_msg);
        }
        if !self.has_live_circuit(sender_hex) {
            // Installed from the offline queue after the circuit's
            // connection was replaced: resume it.
            self.schedule_reask(sender_hex);
        }
        self.process_pending_encrypted(sender_hex);
        self.flush_receipts(sender_hex);
    }

    /// Parse a session-init body (padded `ct || confirm || ratchet_message`)
    /// with the peer's pending init, and return SK and the embedded ratchet
    /// message once the confirmation tag verifies. None on any failure.
    fn open_session_init(
        &self,
        sender_hex: &str,
        body: &[u8],
    ) -> Option<(Zeroizing<[u8; 32]>, Vec<u8>)> {
        let p = self.pending_inits.get(sender_hex)?;
        let identity = self.identity.as_ref()?;
        let peer_ik = key_from_hex(sender_hex)?;
        let my_ik = identity.public_signing_key().to_bytes();
        let unpadded = crate::padding::unpad(body)?;
        let mut pt = Vec::with_capacity(1 + unpadded.len());
        pt.push(crate::session_init::SESSION_INIT_TYPE);
        pt.extend_from_slice(unpadded);
        let (ct, confirm, msg) = crate::session_init::parse_session_init(&pt).ok()?;
        let ss = p.kem.decapsulate(ct).ok()?;
        let sk = crate::crypto::x3dh_v3_responder(
            identity.agreement_secret(),
            &p.ek_r,
            &p.peer_ak,
            &p.i_ek,
            &ss,
            p.kem.public(),
            ct,
            &peer_ik,
            &my_ik,
        )
        .ok()?;
        if !crate::session_init::verify_init_confirm(&sk, ct, confirm) {
            return None;
        }
        Some((sk, msg.to_vec()))
    }

    /// Drop the waits for session-init that ran out: past
    /// `expires_at_unix` while published (the wait counts online time only,
    /// R8), or older than the offline queue in any case. The circuit is
    /// closed and the pair asked again.
    pub(crate) fn purge_expired_pending_inits(&mut self, now_unix: u64) {
        let online = self.is_key_bundle_published;
        let expired: Vec<String> = self
            .pending_inits
            .iter()
            .filter(|(_, p)| p.too_old(now_unix) || (online && now_unix >= p.expires_at_unix))
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in expired {
            self.abandon_pending_init(&peer, true);
        }
    }

    /// An established session whose circuit was created or resumed on the
    /// current transport connection.
    pub(crate) fn has_live_circuit(&self, peer_hex: &str) -> bool {
        // While a new pair waits for its session-init (§A.3), the old
        // session's circuit is not the pair's any more.
        if self.awaiting_init(peer_hex) {
            return false;
        }
        self.session_manager
            .get(peer_hex)
            .map(|s| {
                s.is_established
                    && s.target_circuit_id.is_some()
                    && s.get_token_key().is_some()
                    && s.circuit_epoch == self.transport_epoch
            })
            .unwrap_or(false)
    }

    /// Spec §4.4 Sending: refuse before any wait.
    pub(crate) fn check_sendable(&self, peer_hex: &str) -> Result<(), RChatError> {
        let identity = peer_hex.to_string();
        match self.peers.state(peer_hex) {
            PeerKeyState::Pinned => Ok(()),
            PeerKeyState::Blocked => Err(RChatError::PeerBlocked { identity }),
            PeerKeyState::Mismatch => Err(RChatError::PeerKeyRejected { identity }),
            PeerKeyState::BadSignature => Err(RChatError::PeerKeyUnverified { identity }),
            PeerKeyState::None => Err(RChatError::PeerNotAccepted { identity }),
        }
    }

    /// Encrypt `plaintext` in the peer's ratchet, seal it (v2 envelope, §5.3)
    /// to the peer's pinned keys and wrap it for the peer's circuit.
    pub(crate) fn seal_ratchet(
        &self,
        peer_hex: &str,
        message_id: [u8; 16],
        plaintext: &[u8],
    ) -> Result<RelayPacket, RChatError> {
        let not_established = || RChatError::SessionNotEstablished {
            identity: peer_hex.to_string(),
        };
        let peer_ak = self
            .peers
            .pin_for(peer_hex)
            .ok_or_else(|| RChatError::PeerNotAccepted {
                identity: peer_hex.to_string(),
            })?;
        let peer_ik = key_from_hex(peer_hex).ok_or_else(|| RChatError::InvalidRecipient {
            identity: peer_hex.to_string(),
        })?;
        let my_ik = self
            .identity
            .as_ref()
            .ok_or(RChatError::NotConnected)?
            .public_signing_key()
            .to_bytes();
        // The peer's writes are failing: probe with a write first, so that
        // retried sends (a cover reply every tick, queued sends) do not burn
        // a chain key each while the disk stays full.
        if self.persist_failing(peer_hex) {
            self.persist_peer(peer_hex)?;
        }
        if self.awaiting_init(peer_hex) {
            // A new pair is forming (§A.3): nothing is sealed under the old
            // session for a circuit the relay already replaced.
            return Err(not_established());
        }
        let mut session = self
            .session_manager
            .get_mut(peer_hex)
            .ok_or_else(not_established)?;
        let target = session
            .target_circuit_id
            .clone()
            .ok_or_else(not_established)?;
        let token = session.get_token_key().ok_or_else(not_established)?;
        // A steady slot (§B.1) pads to exactly 1 KiB; the slot only seals
        // what fits, and anything else keeps its bucket.
        // The padded plaintext is wiped once encrypted (R30 M-3).
        let padded = zeroize::Zeroizing::new(if self.steady_padding {
            // Never a silent fall-back to a bucket inside the shape (M2):
            // refused, and the slot sends the item outside it explicitly.
            match crate::padding::pad_exact(plaintext, crate::steady::STEADY_PLAINTEXT_LEN) {
                Some(p) => p,
                None => {
                    debug_assert!(false, "a steady slot item over 1 KiB");
                    self.steady_oversize
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(RChatError::Internal {
                        message: "item does not fit a steady slot".into(),
                    });
                }
            }
        } else {
            crate::padding::pad(plaintext)
        });
        let (ciphertext, header) = session.encrypt_message(&padded)?;
        // §A.4: the first message sealed under a session we initiated
        // travels as its session-init. Claimed under this guard, so a
        // concurrent seal cannot make a second init.
        let epoch = self.transport_epoch;
        let init = match session.init_out.as_mut() {
            Some(i) if i.sent.is_none() => {
                i.sent = Some(crate::session::SentInit {
                    id: message_id,
                    payload: Vec::new(),
                    epoch,
                });
                Some((i.ct.clone(), i.confirm))
            }
            _ => None,
        };
        drop(session); // never persist while holding a session guard (lock order)
                       // An init that did not leave is unclaimed: the next seal makes it.
        let is_init = init.is_some();
        let set_init_payload = |payload: Option<&Vec<u8>>| {
            if !is_init {
                return;
            }
            if let Some(mut s) = self.session_manager.get_mut(peer_hex) {
                if let Some(i) = s.init_out.as_mut() {
                    if i.sent.as_ref().is_some_and(|x| x.id == message_id) {
                        match payload {
                            Some(p) => {
                                if let Some(x) = i.sent.as_mut() {
                                    x.payload = p.clone();
                                }
                            }
                            None => i.sent = None,
                        }
                    }
                }
            }
        };
        // Timer changes too (R32): their receipts and loss reports bind to
        // the peer like a message's, and the core acts on them.
        if matches!(
            plaintext.first(),
            Some(&(0x01 | 0x02 | crate::file_msg::FILE_TYPE | crate::disappearing::TIMER_TYPE))
        ) {
            self.record_sent(peer_hex, message_id);
        }
        if let Err(e) = self.persist_peer(peer_hex) {
            // Nothing leaves without a durable chain state (D28). The id was
            // never sent: take it back out of sent_ids.
            self.unrecord_sent(peer_hex, &message_id);
            set_init_payload(None);
            return Err(e);
        }
        let mut body = header.encode();
        body.extend_from_slice(&ciphertext);
        let payload = match &init {
            None => sealed::seal(message_id, &peer_ik, &peer_ak, &my_ik, KIND_RATCHET, &body),
            Some((ct, confirm)) => {
                // `0x08 || ct || confirm || ratchet_message`: the type is the
                // sealed kind, the rest the body, padded to the buckets.
                let pt = crate::session_init::build_with_confirm(ct, confirm, &body);
                let padded = crate::padding::pad(&pt[1..]);
                sealed::seal(
                    message_id,
                    &peer_ik,
                    &peer_ak,
                    &my_ik,
                    crate::session_init::SESSION_INIT_TYPE,
                    &padded,
                )
            }
        }
        .map_err(|e| {
            set_init_payload(None);
            RChatError::EncryptionFailed {
                message: e.to_string(),
            }
        })?;
        if is_init {
            set_init_payload(Some(&payload));
            // Best effort: a restart re-sends these very bytes.
            let _ = self.persist_peer(peer_hex);
        }
        Ok(RelayPacket::with_auth(
            target,
            payload,
            PacketFlags {
                encrypted: true,
                ..Default::default()
            },
            &token,
        ))
    }

    /// The initiator's invisible first message, so the responder's ratchet
    /// gets a sending chain: a cover reply (`0x05 0x01`, never answered,
    /// §A.4), which travels as the session-init when nothing went before
    /// it, and is then ack-tracked. False when it was not sealed (the
    /// session's write failed, D28): nothing left, so it is owed.
    pub(crate) fn send_hello_sync(&self, peer_hex: &str) -> bool {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        match self.seal_ratchet(peer_hex, id, &[COVER_TYPE, COVER_REPLY]) {
            Ok(packet) => {
                let is_init = self.session_manager.get(peer_hex).is_some_and(|s| {
                    s.init_out
                        .as_ref()
                        .and_then(|i| i.sent.as_ref())
                        .is_some_and(|x| x.id == id)
                });
                if is_init {
                    self.track_internal(
                        peer_hex,
                        &hex::encode(id),
                        packet.circuit_id.clone(),
                        packet.payload.clone(),
                        crate::acks::Internal::SessionInit,
                    );
                }
                if self.send_now(packet.encode_with_frame_type()).is_err() {
                    // Its chain key is spent and the bytes are gone; the
                    // responder still gets a chain from our next message.
                    log::debug!("[RUST] hello sync could not be queued");
                }
                true
            }
            Err(_) => {
                log::debug!("[RUST] hello sync could not be sealed");
                false
            }
        }
    }

    /// Send `CloseCircuit` for the peer's live circuit, if any (H2).
    pub(crate) fn close_circuit_with(&mut self, peer_hex: &str) {
        let cid = self
            .session_manager
            .get(peer_hex)
            .and_then(|s| s.circuit_id.clone());
        if let Some(cid) = cid {
            self.close_circuit_id(&cid);
        }
    }

    /// Close the live circuit and drop the current and retired sessions and
    /// anything held from the peer.
    fn forget_peer_session(&mut self, peer_hex: &str) {
        self.close_circuit_with(peer_hex);
        if let Some(p) = self.pending_inits.remove(peer_hex) {
            self.close_circuit_id(&p.circuit_id);
        }
        self.session_manager.forget(peer_hex);
        // Its ask is never re-sent (block, unpin, re-pin), and the meta
        // record stops naming it.
        self.clear_unanswered(peer_hex);
        self.forget_blind_state(peer_hex);
        self.delete_peer_record(peer_hex);
        self.clear_peer_tracking(peer_hex);
        self.intros.remove(peer_hex);
        self.clear_receipts(peer_hex);
        // The contact is gone: so is its disappearing timer (§I.2).
        crate::disappearing::lock_timers(self).remove(peer_hex);
        self.sent_ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(peer_hex);
        self.drop_held_from(peer_hex);
    }

    /// Drop the bodies held from the peer (the meta record follows).
    fn drop_held_from(&mut self, peer_hex: &str) {
        let before = self.pending_encrypted_messages.len();
        self.pending_encrypted_messages
            .retain(|p| p.sender_hex != peer_hex);
        if self.pending_encrypted_messages.len() != before {
            self.persist_meta();
        }
    }

    /// Re-pin to a different key (C-1): the session was derived under the
    /// old pin, possibly with an impostor's key, so it is closed and dropped
    /// outright, never kept as a decrypt-only retired session, and bodies
    /// held for the peer go too (they may be the impostor's). Queued
    /// outgoing messages wait in a bare placeholder session for the session
    /// made under the new pin (`take_pending`).
    fn drop_session_for_repin(&mut self, peer_hex: &str) {
        self.close_circuit_with(peer_hex);
        if let Some(p) = self.pending_inits.remove(peer_hex) {
            self.close_circuit_id(&p.circuit_id);
        }
        let queued = self.session_manager.take_pending(peer_hex);
        self.session_manager.forget(peer_hex);
        self.forget_blind_state(peer_hex);
        self.delete_peer_record(peer_hex);
        self.clear_peer_tracking(peer_hex);
        self.drop_held_from(peer_hex);
        // Receipts owed for what the old session decrypted, and the ids sent
        // over it, belong to the old key: not to the contact under the new
        // pin (N-6). Intros stay: they are re-sent under the new pin.
        self.clear_receipts(peer_hex);
        self.sent_ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(peer_hex);
        // R33 M-2: the session under the new pin starts with no shared
        // timer state; the current one goes again on it (install hook).
        if let Some(t) = crate::disappearing::lock_timers(self).get_mut(peer_hex) {
            t.acked = false;
            t.resends = 0;
        }
        let has_timer = crate::disappearing::lock_timers(self).contains_key(peer_hex);
        if !queued.is_empty() {
            self.session_manager
                .get_or_create(peer_hex.to_string())
                .pending_messages = queued;
            // The placeholder's queued ids, for a restart (best effort).
            let _ = self.persist_peer(peer_hex);
        } else if has_timer {
            // Round 2 N-3: the record just went; the timer (and that it is
            // owed again) is written now, so a restart before the new
            // install keeps it.
            let _ = self.persist_peer(peer_hex);
        }
    }

    fn parse_identity(&self, identity_hex: &str) -> Result<String, RChatError> {
        let id = identity_hex.to_lowercase();
        if key_from_hex(&id).is_none() {
            return Err(RChatError::InvalidRecipient { identity: id });
        }
        let me = self.identity.as_ref().map(|i| i.public_key_hex());
        if me.as_deref() == Some(id.as_str()) {
            return Err(RChatError::InvalidRecipient { identity: id });
        }
        Ok(id)
    }

    /// `set_recipient` semantics (§4.4 Pins): `Some(same)` is a no-op that
    /// keeps `mismatch` (L11); `Some(different)` re-pins from the contact's
    /// code; `None` needs an existing pin.
    pub(crate) fn apply_set_recipient(
        &mut self,
        identity_hex: &str,
        agreement_hex: Option<&str>,
    ) -> Result<(), RChatError> {
        if self.identity.is_none() {
            return Err(RChatError::InvalidRecipient {
                identity: identity_hex.to_lowercase(),
            });
        }
        let id = self.parse_identity(identity_hex)?;
        if self.peers.is_blocked(&id) {
            return Err(RChatError::PeerBlocked { identity: id });
        }
        match agreement_hex {
            Some(ak_hex) => {
                let ak = key_from_hex(ak_hex).ok_or_else(|| RChatError::InvalidRecipient {
                    identity: id.clone(),
                })?;
                let repinned = match self.peers.pin_for(&id) {
                    Some(existing) if constant_time_eq(&existing, &ak) => Ok(false),
                    Some(_) => self.peers.repin(&id, ak).map(|()| true),
                    None => self.peers.pin(&id, ak).map(|()| {
                        self.peers.set_pin_hour(&id, now_hour());
                        false
                    }),
                }
                .map_err(|e| match e {
                    PinError::AgreementKeyInUse => RChatError::AgreementKeyInUse,
                    PinError::Conflict => RChatError::PinConflict,
                    PinError::RotationTooSoon => RChatError::RotationTooSoon,
                })?;
                if repinned {
                    self.peers.set_pin_hour(&id, now_hour());
                    self.drop_session_for_repin(&id);
                }
            }
            None => {
                if self.peers.pin_for(&id).is_none() {
                    return Err(RChatError::PeerNotAccepted { identity: id });
                }
            }
        }
        self.current_recipient = Some(id.clone());
        if self.peers.state(&id) == PeerKeyState::Pinned
            && !self.has_live_circuit(&id)
            && self.ask(&id, AskTrigger::User, Instant::now()).is_err()
        {
            log::debug!("[RUST] ask after set_recipient could not be sent");
        }
        Ok(())
    }

    /// Pin (accept) `identity_hex` with its agreement key and, when the
    /// app has it, its ML-KEM key (hex, 1184 bytes: from their card, an
    /// accepted request or a rotation, or the app's stored copy of one).
    /// Both are taken or neither (§A.6, R11): a different agreement key or
    /// a different KEM key than the pinned ones is `PinConflict`, never a
    /// silent replacement; a key that is not a valid ML-KEM-768 key is
    /// `InvalidRecipient`. A peer whose ask waited for a KEM key is asked.
    pub(crate) fn pin_peer(
        &mut self,
        identity_hex: &str,
        agreement_hex: &str,
        kem_hex: Option<&str>,
    ) -> Result<(), RChatError> {
        let id = self.parse_identity(identity_hex)?;
        if self.peers.is_blocked(&id) {
            return Err(RChatError::PeerBlocked { identity: id });
        }
        let ak = key_from_hex(agreement_hex).ok_or_else(|| RChatError::InvalidRecipient {
            identity: id.clone(),
        })?;
        let kem = match kem_hex {
            Some(h) => Some(
                parse_kem_hex(h).ok_or_else(|| RChatError::InvalidRecipient {
                    identity: id.clone(),
                })?,
            ),
            None => None,
        };
        let new_pin = self.peers.pin_for(&id).is_none();
        self.peers
            .pin_with_kem(&id, ak, kem.as_deref())
            .map_err(pin_error)?;
        if new_pin {
            self.peers.set_pin_hour(&id, now_hour());
        }
        self.ask_if_kem_arrived(&id);
        Ok(())
    }

    /// Attach an ML-KEM key to an existing pin (R11): `PinConflict` if the
    /// identity is not pinned or a different key is; never replaces one.
    /// A peer whose ask waited for a KEM key is asked.
    pub(crate) fn pin_peer_kem(
        &mut self,
        identity_hex: &str,
        kem_pk: &[u8; KEM_PK_LEN],
    ) -> Result<(), RChatError> {
        let id = identity_hex.to_lowercase();
        self.peers.pin_kem(&id, kem_pk).map_err(pin_error)?;
        self.ask_if_kem_arrived(&id);
        Ok(())
    }

    /// T5 N-1: a peer deferred for want of a KEM key is asked as soon as
    /// one is pinned (on a connection whose publish was accepted; before
    /// that, the publish sends it).
    fn ask_if_kem_arrived(&mut self, id: &str) {
        if !self.is_key_bundle_published
            || self.peers.kem_pk_for(id).is_none()
            || !self.deferred_asks.iter().any(|p| p == id)
        {
            return;
        }
        self.deferred_asks.retain(|p| p != id);
        if self.ask(id, AskTrigger::User, Instant::now()).is_err() {
            log::debug!("[RUST] ask after a KEM key pin could not be sent");
            if self.require_askable(id).is_ok() && !self.deferred_asks.iter().any(|p| p == id) {
                self.deferred_asks.push(id.to_string());
            }
        }
    }

    /// Unpin: close any live circuit (H2), drop the session, forget the pin.
    pub(crate) fn unpin_peer(&mut self, identity_hex: &str) -> Result<(), RChatError> {
        let id = self.parse_identity(identity_hex)?;
        self.forget_peer_session(&id);
        self.peers.unpin(&id);
        Ok(())
    }

    /// Apply pin and block changes staged by the C FFI while this client
    /// connected. Every peer they unpin, re-pin or block first loses its
    /// circuit and session (`forget_peer_session`), as `unpin_peer` and
    /// `block_peer` do.
    pub(crate) fn apply_staged_peers(&mut self, newer: crate::peers::PeerBook) {
        for id in self.peers.overlay_drops(&newer) {
            self.forget_peer_session(&id);
        }
        let kem_ids = newer.kem_ids();
        self.peers.overlay(newer);
        // A KEM key staged while a connect ran asks a peer deferred for
        // want of one, as a live pin does (fix round 1, minor 6).
        for id in kem_ids {
            self.ask_if_kem_arrived(&id);
        }
    }

    /// Block: unpin, close any live circuit and drop everything from the peer.
    pub(crate) fn block_peer(
        &mut self,
        identity_hex: &str,
        blocked: bool,
    ) -> Result<(), RChatError> {
        let id = self.parse_identity(identity_hex)?;
        if blocked {
            self.forget_peer_session(&id);
        }
        self.peers.set_blocked(&id, blocked);
        Ok(())
    }

    /// Route an opened envelope by kind. A ratchet
    /// envelope is never knock-sized (5120 bytes; ratchet payloads are 202 +
    /// a padding bucket), so one that is came through the knock path and is
    /// dropped before it can be held (N-1).
    /// `on_pending_circuit`: it arrived on the sender's pending circuit, its
    /// token verified (a failed session-init there ends the wait, R9).
    pub(crate) fn dispatch_opened(
        &mut self,
        opened: Opened,
        payload_len: usize,
        on_pending_circuit: bool,
    ) {
        if opened.kind == KIND_RATCHET && payload_len == sealed::KNOCK_PAYLOAD_LEN {
            log::debug!("[RUST] knock-sized ratchet envelope dropped");
            return;
        }
        match opened.kind {
            KIND_RATCHET => {
                let sender = hex::encode(opened.sender_identity_key);
                self.handle_ratchet(&sender, opened.message_id, &opened.body);
            }
            crate::session_init::SESSION_INIT_TYPE => {
                let sender = hex::encode(opened.sender_identity_key);
                self.handle_session_init(
                    &sender,
                    opened.message_id,
                    &opened.body,
                    on_pending_circuit,
                );
            }
            _ => log::debug!("[RUST] unknown sealed kind dropped"),
        }
    }

    /// Hold a ratchet body whose sender has no session yet (capped,
    /// `push_held_capped`). True when the body was held (an oversize body
    /// is refused).
    fn hold_pending(&mut self, held: PendingEncrypted) -> bool {
        if !self.push_held_capped(held) {
            return false;
        }
        // Best effort (D28): written once on the tick, not once per body
        // (final review M-1: forged bodies drove a full meta rewrite each).
        self.meta_dirty = true;
        true
    }

    /// Hold a ratchet body within the per-sender, entry and byte caps
    /// (oldest evicted first; oversize bodies refused). A sender at its own
    /// cap loses its own oldest body, never another sender's (C-7). Used for
    /// bodies of senders without a session and for bodies whose write
    /// failed (D28); this is the only place the caps are enforced.
    /// True when the body was held.
    pub(crate) fn push_held_capped(&mut self, held: PendingEncrypted) -> bool {
        if held.body.len() > MAX_PENDING_ENTRY_BYTES {
            log::debug!("[RUST] Oversize held body dropped");
            return false;
        }
        let from_sender = self
            .pending_encrypted_messages
            .iter()
            .filter(|p| p.sender_hex == held.sender_hex)
            .count();
        if from_sender >= MAX_PENDING_PER_SENDER {
            if let Some(pos) = self
                .pending_encrypted_messages
                .iter()
                .position(|p| p.sender_hex == held.sender_hex)
            {
                self.pending_encrypted_messages.remove(pos);
            }
        }
        let mut total: usize = self
            .pending_encrypted_messages
            .iter()
            .map(|p| p.body.len())
            .sum();
        // Full: evict the oldest body of the largest holder (by entries, or
        // by bytes for the byte cap), so senders flooding the buffer under
        // claimed identities pay first and a quiet contact's few held bodies
        // survive (N-1). The incoming sender counts as holding one more.
        loop {
            let by_bytes = if self.pending_encrypted_messages.len() >= MAX_PENDING_ENCRYPTED {
                false
            } else if total + held.body.len() > MAX_PENDING_BYTES {
                true
            } else {
                break;
            };
            match self.evict_from_largest_holder(&held, by_bytes) {
                Some(freed) => total -= freed,
                None => break,
            }
        }
        self.pending_encrypted_messages.push_back(held);
        true
    }

    /// Remove the oldest held body of the sender holding the most entries
    /// (or bytes), counting `incoming` as already held. Returns its size.
    fn evict_from_largest_holder(
        &mut self,
        incoming: &PendingEncrypted,
        by_bytes: bool,
    ) -> Option<usize> {
        let weight = |p: &PendingEncrypted| if by_bytes { p.body.len() } else { 1 };
        let mut held: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for p in &self.pending_encrypted_messages {
            *held.entry(p.sender_hex.as_str()).or_default() += weight(p);
        }
        *held.entry(incoming.sender_hex.as_str()).or_default() += weight(incoming);
        // Largest holder that actually has something held; ties go to the
        // sender whose oldest body is oldest (plain FIFO among equals).
        let largest = self
            .pending_encrypted_messages
            .iter()
            .enumerate()
            .max_by_key(|(i, p)| (held[p.sender_hex.as_str()], std::cmp::Reverse(*i)))
            .map(|(_, p)| p.sender_hex.clone())?;
        let pos = self
            .pending_encrypted_messages
            .iter()
            .position(|p| p.sender_hex == largest)?;
        self.pending_encrypted_messages
            .remove(pos)
            .map(|p| p.body.len())
    }

    /// A ratchet message from `sender_hex` (identity taken from inside the
    /// envelope, F13). Dropped unless the sender is accepted (pinned, or
    /// pinned with a transient bad signature; N5); no session yet →
    /// held (capped, `hold_pending`).
    /// A contact that just rotated (spec §4.8): its old identity's in-flight
    /// messages are accepted for `ROTATION_GRACE_SECS` and reported as from
    /// the new identity, while the new identity is still accepted.
    pub(crate) fn handle_ratchet(&mut self, sender_hex: &str, message_id: [u8; 16], body: &[u8]) {
        if let Err(held) = self.try_ratchet(sender_hex, message_id, body, false) {
            self.push_held_capped(held);
            self.persist_meta();
        }
    }

    /// `handle_ratchet`, handing the body back when it must be retried: its
    /// write failed (rolled back, D28), or, unless `retrying`, the peer's
    /// writes are failing already, so it is not decrypted at all (a failed
    /// write would only roll it back; `retry_held` tries the oldest body).
    pub(crate) fn try_ratchet(
        &mut self,
        sender_hex: &str,
        message_id: [u8; 16],
        body: &[u8],
        retrying: bool,
    ) -> Result<(), PendingEncrypted> {
        let accepted =
            |s: PeerKeyState| matches!(s, PeerKeyState::Pinned | PeerKeyState::BadSignature);
        let report_as = if accepted(self.peers.state(sender_hex)) {
            sender_hex.to_string()
        } else {
            match self.rotated_from.get(sender_hex) {
                Some((new, at))
                    if self.peers.state(sender_hex) == PeerKeyState::None
                        && at.elapsed().as_secs() < crate::ROTATION_GRACE_SECS
                        && accepted(self.peers.state(new)) =>
                {
                    new.clone()
                }
                // Unaccepted, blocked or mismatched sender: dropped, no receipt (N5).
                _ => return Ok(()),
            }
        };
        let already_received = self
            .received_ids
            .get(sender_hex)
            .is_some_and(|q| q.contains(&message_id));
        // Decrypted once, then lost before the app stored it (reported or
        // still to report): the sender's same-id resend may pass, once
        // (§18.6). Undecryptable ids never reach `received_ids`.
        let lost_resend = already_received && self.is_listed_lost(&report_as, &message_id);
        if already_received && !lost_resend {
            // Already decrypted (a relay replay or an identical resend): never
            // decrypted twice (spec §18.4 Replay).
            // The app already stored it: re-owe the receipt (spec §18.7; the
            // first may have been lost). Seen ids live under `report_as`.
            if self.peers.is_seen(&report_as, &message_id) {
                self.queue_receipt(&report_as, receipts::DELIVERED, &[message_id]);
                self.flush_receipts(&report_as);
            }
            return Ok(());
        }
        let Some(header) = RatchetHeader::decode(body) else {
            return Ok(());
        };
        let ciphertext = &body[RatchetHeader::LEN..];
        let held = || PendingEncrypted {
            sender_hex: sender_hex.to_string(),
            message_id,
            body: body.to_vec(),
        };
        if !self.session_manager.has_established_session(sender_hex) {
            // A contact sent under a session we don't have (lost, or its
            // CircuitCreatedV3 went to a retired connection): ask again, for
            // this body's own sender (F30). `ask` applies the gates: only an
            // askable (pinned) sender is asked, so a sender accepted only
            // through the rotation grace (old identity, unpinned) is not.
            if self.hold_pending(held()) {
                self.schedule_reask(sender_hex);
            }
            return Ok(());
        }
        if !retrying && (self.persist_failing(sender_hex) || self.persist_failing(&report_as)) {
            return Err(held());
        }
        // What a failed write rolls back to (D28); nothing to roll back
        // with persistence off.
        let before = self
            .state
            .is_some()
            .then(|| self.session_manager.ratchet_snapshots(sender_hex));
        self.decrypt_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (padded, by, binding) = match self
            .session_manager
            .decrypt_bound(sender_hex, ciphertext, &header)
        {
            Ok(ok) => ok,
            Err(_) if self.awaiting_init(sender_hex) => {
                // Possibly under the session whose init is still on its way
                // (§A.3): held, retried once it is installed.
                if self.hold_pending(held()) {
                    self.schedule_reask(sender_hex);
                }
                return Ok(());
            }
            Err(_) => {
                self.record_undecryptable(&report_as, message_id, lost_resend);
                return Ok(());
            }
        };
        if by == DecryptedBy::Current {
            // The peer's first reply under a session we initiated: it has
            // our session-init, which is no longer re-sent (§A.4).
            if let Some(mut s) = self.session_manager.get_mut(sender_hex) {
                s.init_out = None;
            }
        }
        // Plaintext copies are wiped once handled (C-10).
        let padded = Zeroizing::new(padded);
        let Some(plaintext) = crate::padding::unpad(&padded) else {
            log::debug!("[RUST] ratchet plaintext without padding marker dropped");
            return Ok(());
        };
        let plaintext = Zeroizing::new(plaintext.to_vec());
        // A lost id's resend is in `received_ids` already: not pushed twice.
        let evicted_received = (!already_received).then(|| {
            push_capped(
                &mut self.received_ids,
                sender_hex,
                message_id,
                MAX_RECEIVED_IDS,
            )
        });
        // Its resend arrived: no longer lost, so no further pass.
        let unlisted = lost_resend.then(|| self.unlist_lost(&report_as, &message_id));
        // Final review L-1: a forged copy of this id may have listed it as
        // undecryptable; the genuine copy decrypted, so it is not reported
        // (a false report would make the sender resend). Taken back with
        // the rest if the write below fails.
        let was_undecryptable = self.undecryptable.get_mut(&report_as).and_then(|q| {
            let pos = q.iter().position(|x| *x == message_id)?;
            q.remove(pos).map(|_| pos)
        });
        // Handed to the app: a deliverable body not already stored (D36, F16).
        let to_app =
            crate::is_deliverable(&plaintext) && !self.peers.is_seen(&report_as, &message_id);
        let evicted_delivered = to_app.then(|| {
            push_capped(
                &mut self.delivered_unstored,
                &report_as,
                message_id,
                MAX_DELIVERED_UNSTORED,
            )
        });
        // In the rotation grace the record the app's delivery lives in
        // (`report_as`) is written first: a crash between the two writes
        // then reports the message as not stored, never loses it silently.
        let persisted = if report_as != sender_hex {
            self.persist_peer(&report_as)
                .and_then(|_| self.persist_peer(sender_hex))
        } else {
            self.persist_peer(sender_hex)
        };
        if persisted.is_err() {
            // Roll back exactly; the caller holds the body for a retry (D28).
            if let Some(before) = before {
                self.session_manager.restore_ratchets(
                    sender_hex,
                    before,
                    self.identity.as_ref().map(|i| i.agreement_secret()),
                );
            }
            if let Some(evicted) = evicted_received {
                unpush_capped(&mut self.received_ids, sender_hex, evicted);
            }
            if let Some(u) = unlisted {
                self.relist_lost(&report_as, message_id, u);
            }
            if let Some(pos) = was_undecryptable {
                let q = self.undecryptable.entry(report_as.clone()).or_default();
                q.insert(pos.min(q.len()), message_id);
            }
            if let Some(evicted) = evicted_delivered {
                unpush_capped(&mut self.delivered_unstored, &report_as, evicted);
            }
            return Err(held());
        }
        // Its 1,000th decrypt is durable: the retired session can go (C-13).
        // It leaves memory first, whatever the follow-up write does, so the
        // next successful write omits it even if this one fails.
        if by == DecryptedBy::Retired && self.session_manager.drop_exhausted_retired(sender_hex) {
            let _ = self.persist_peer(sender_hex);
        }
        // Decrypted under the old identity's session in the rotation grace:
        // never the reported identity's current session, so a notice in it
        // can never pass D38 guard 1 (or be checked against the wrong
        // session by guard 7).
        let (by, binding) = if report_as != sender_hex {
            (DecryptedBy::Retired, None)
        } else {
            (by, binding)
        };
        self.last_heard
            .insert(sender_hex.to_string(), Instant::now());
        // R23: the peer is live again; it rejoins the steady draw.
        self.steady_unheard.remove(sender_hex);
        self.handle_decrypted_message(&report_as, message_id, &plaintext, by, binding);
        // The receipt was queued under the identity it is reported
        // as (the new one in the rotation grace): flush that one
        // (Task 17c final-review triage).
        self.flush_receipts(&report_as);
        Ok(())
    }

    /// Spec §4.8, round-2 H2/M1: a chain from one of our plain `Pinned`
    /// contacts (identity and agreement key) to these keys → silent re-pin.
    /// Called only for a verified knock from the new identity (proof of
    /// possession). False → the caller continues with the normal flow.
    pub(crate) fn try_peer_rotation(
        &mut self,
        new_bundle: &crate::keyauth::SignedBundle,
        block: &crate::rotation::RotationBlock,
    ) -> bool {
        let (new_ik, new_ak) = (&new_bundle.identity_key, &new_bundle.identity_agreement_key);
        let new_hex = hex::encode(new_ik);
        if self.peers.pin_for(&new_hex).is_some()
            || self.peers.is_blocked(&new_hex)
            || self.peers.has_requested(&new_hex)
            || self.peers.pinned_elsewhere(&new_hex, new_ak)
        {
            return false;
        }
        for (pos, link) in block.links.iter().enumerate() {
            let old_hex = hex::encode(link.prev_identity_key);
            if self.peers.is_blocked(&old_hex) {
                // A blocked contact stays blocked under its new keys (round-2
                // M1), once the chain from it verifies. Silent.
                if crate::rotation::verify_chain_to(&block.links[pos..], new_ik, new_ak).is_err() {
                    continue;
                }
                self.peers.set_blocked(&new_hex, true);
                return true;
            }
            if self.peers.state(&old_hex) != PeerKeyState::Pinned {
                continue; // no pin, Mismatch or BadSignature: never silently
            }
            let Some(pinned_ak) = self.peers.pin_for(&old_hex) else {
                continue;
            };
            let pinned_version = self.peers.pin_version(&old_hex);
            if let Ok(v) = crate::rotation::walk_chain(
                &block.links,
                &link.prev_identity_key,
                &pinned_ak,
                pinned_version,
                new_ik,
                new_ak,
            ) {
                return self.apply_peer_rotation(&old_hex, new_bundle, v);
            }
        }
        false
    }

    /// Re-pin `old_hex` → the new keys (rate-limited), keep the old session
    /// decrypt-only for in-flight messages, tell the app and ask the new
    /// identity. Never resends anything (D23, H1).
    pub(crate) fn apply_peer_rotation(
        &mut self,
        old_hex: &str,
        new_bundle: &crate::keyauth::SignedBundle,
        version: u32,
    ) -> bool {
        let new_hex = hex::encode(new_bundle.identity_key);
        let now = Instant::now();
        if self
            .peers
            .rotate_pin(
                old_hex,
                &new_hex,
                new_bundle.identity_agreement_key,
                version,
                now,
            )
            .is_err()
        {
            return false;
        }
        // The new identity's KEM key, from the bundle it signed (§A.5),
        // before anything asks it. The app learns it from `on_peer_rotated`.
        if self.peers.kem_pk_for(&new_hex).is_none() {
            self.peers.set_kem_pk(&new_hex, new_bundle.kem_pk.clone());
        }
        // The old identity is gone: stop using its circuit and drop what
        // was waiting for it; its session stays for in-flight messages.
        self.close_circuit_with(old_hex);
        self.detach_circuit(old_hex);
        self.pending_reasks.remove(old_hex);
        self.deferred_asks.retain(|p| p != old_hex);
        self.intros.remove(old_hex);
        // Receipts still owed under the old identity go to the new one.
        for kind in [receipts::DELIVERED, receipts::READ] {
            if let Some(ids) = self.pending_receipts.remove(&(old_hex.to_string(), kind)) {
                self.queue_receipt(&new_hex, kind, &ids);
            }
        }
        self.clear_receipts(old_hex);
        // The conversation's disappearing timer moves with the contact (§I.2).
        {
            let mut timers = crate::disappearing::lock_timers(self);
            if let Some(t) = timers.remove(old_hex) {
                timers.entry(new_hex.clone()).or_insert(t);
            }
        }
        // R33 M-2: the new identity's install may not hold it; re-sent
        // (queued once its session exists, at the install).
        self.timer_resync(&new_hex);
        // Receipts for messages sent to the old identity bind to the new one.
        {
            let mut sent = self.sent_ids.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ids) = sent.remove(old_hex) {
                sent.insert(new_hex.clone(), ids);
            }
        }
        // The sent ids and owed receipts moved: the new identity's record
        // is written first, and the old one (without them) only once that
        // write succeeded. So the ids are always on disk under one of the
        // two (both at worst, after a crash in between), never on neither:
        // a failed new write leaves the old record, ids included, as it was
        // until the new identity's next successful write.
        if self.persist_peer(&new_hex).is_ok() {
            let _ = self.persist_peer(old_hex);
        }
        self.rotated_from
            .retain(|_, (_, at)| at.elapsed().as_secs() < crate::ROTATION_GRACE_SECS);
        self.rotated_from
            .insert(old_hex.to_string(), (new_hex.clone(), now));
        if let Some(cb) = &self.callbacks {
            // The new KEM key goes with the new agreement key (R11): the
            // app stores both and re-pins them at launch.
            cb.on_peer_rotated(
                old_hex.to_string(),
                new_hex.clone(),
                hex::encode(new_bundle.identity_agreement_key),
                hex::encode(&new_bundle.kem_pk[..]),
                version,
            );
        }
        self.schedule_reask(&new_hex);
        true
    }
    /// Send the `0x04` notice to every accepted peer with a live circuit
    /// (still as the old identity); returns how many were queued.
    pub(crate) fn announce_rotation(&mut self, block: &crate::rotation::RotationBlock) -> u32 {
        let Ok(raw) = block.encode() else {
            return 0;
        };
        let mut pt = Vec::with_capacity(1 + raw.len());
        pt.push(ROTATION_NOTICE_TYPE);
        pt.extend_from_slice(&raw);
        let peers: Vec<String> = self
            .session_manager
            .get_all_recipients()
            .into_iter()
            .filter(|p| self.require_askable(p).is_ok() && self.has_live_circuit(p))
            .collect();
        let mut sent = 0;
        for peer in peers {
            let mut id = [0u8; 16];
            OsRng.fill_bytes(&mut id);
            if self
                .seal_ratchet(&peer, id, &pt)
                .and_then(|pkt| self.send_now(pkt.encode_with_frame_type()))
                .is_ok()
            {
                sent += 1;
            }
        }
        sent
    }

    /// Wipe secrets that outlived their use (C-13), from the shared timer:
    /// retired sessions past their limits, asks past `ASK_TTL`, and the
    /// session of a contact's old identity once the rotation grace ends.
    pub(crate) fn purge_stale(&mut self, now: Instant) {
        let now_unix = crate::unix_now_secs();
        // Expired keys leave the stored records too (D31, C-13).
        let mut changed = self.session_manager.purge_expired_retired(now_unix);
        let more = self.session_manager.purge_expired_skipped(now_unix);
        for peer in more.into_iter().chain(self.purge_lost_reported(now_unix)) {
            if !changed.contains(&peer) {
                changed.push(peer);
            }
        }
        for peer in changed {
            let _ = self.persist_peer(&peer);
        }
        self.peers.purge_expired_asks(now);
        // A session-init that never came: its KEM ephemeral is wiped and
        // the pair asked again (§A.3).
        self.purge_expired_pending_inits(now_unix);
        self.purge_stranded_sends(now_unix);
        let grace = Duration::from_secs(crate::ROTATION_GRACE_SECS);
        let expired: Vec<String> = self
            .rotated_from
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) >= grace)
            .map(|(old, _)| old.clone())
            .collect();
        for old in expired {
            self.rotated_from.remove(&old);
            // Unless the old identity was accepted again in the meantime.
            if self.peers.state(&old) == PeerKeyState::None {
                self.forget_peer_session(&old);
            }
        }
    }

    /// R21: sends parked on a session (a re-pair in flight, a responder
    /// before its first incoming message) whose pair never formed: past the
    /// offline queue's 72 h they could no longer reach the peer even then,
    /// so they leave the queue and are reported (`QueuedSendLost`).
    fn purge_stranded_sends(&mut self, now_unix: u64) {
        let cutoff_ms = now_unix
            .saturating_sub(PENDING_INIT_MAX_AGE_SECS)
            .saturating_mul(1000);
        let peers: Vec<String> = self
            .session_manager
            .get_all_recipients()
            .into_iter()
            .filter(|p| !self.has_live_circuit(p))
            .collect();
        for peer in peers {
            let lost: std::collections::VecDeque<crate::session::PendingMessage> =
                match self.session_manager.get_mut(&peer) {
                    Some(mut s) => {
                        let (old, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut s.pending_messages)
                            .into_iter()
                            .partition(|m| m.timestamp_ms != 0 && m.timestamp_ms < cutoff_ms);
                        s.pending_messages = keep.into();
                        old.into()
                    }
                    None => continue,
                };
            if !lost.is_empty() {
                self.report_queued_sends_lost(&peer, &lost);
                let _ = self.persist_peer(&peer);
            }
        }
    }

    /// Retry buffered messages from `peer_hex` now that it has a session.
    pub(crate) fn process_pending_encrypted(&mut self, peer_hex: &str) {
        let (mine, rest): (Vec<_>, Vec<_>) = self
            .pending_encrypted_messages
            .drain(..)
            .partition(|p| p.sender_hex == peer_hex);
        self.pending_encrypted_messages.extend(rest);
        if mine.is_empty() {
            return;
        }
        // A held body that still fails right after the install (detail 2).
        self.retrying_held = true;
        self.release_held(mine);
        self.retrying_held = false;
        self.persist_meta();
    }

    /// A ratchet body from an accepted sender that decrypted under neither
    /// session (spec §18.6): recorded once (capped), reported to the app
    /// and, in the next session notice, to the sender (`peer`: the identity
    /// it is reported as). A replay of a lost message's original envelope
    /// (its key is spent) is a duplicate and raises nothing.
    fn record_undecryptable(&mut self, peer: &str, message_id: [u8; 16], lost_resend: bool) {
        log::debug!("[RUST] ratchet message did not decrypt");
        if lost_resend
            || self
                .undecryptable
                .get(peer)
                .is_some_and(|q| q.contains(&message_id))
        {
            return;
        }
        push_capped(&mut self.undecryptable, peer, message_id, MAX_UNDECRYPTABLE);
        // Final review M-1: at most `MAX_DECRYPT_FAILED_PER_TICK` events per
        // peer per tick (the id is listed and reported either way).
        let raised = self
            .decrypt_failed_this_tick
            .entry(peer.to_string())
            .or_insert(0);
        let first_this_tick = *raised == 0;
        if *raised < MAX_DECRYPT_FAILED_PER_TICK {
            *raised += 1;
            let detail = if self.retrying_held { 2 } else { 1 };
            self.emit_status(StatusEvent::DecryptFailed {
                peer: peer.to_string(),
                message_id: hex::encode(message_id),
                detail,
            });
        }
        self.notice_due.insert(peer.to_string());
        // Coalesced to the tick: no key was spent, and the notice's own
        // seal writes the record before anything leaves (D28).
        self.peers_dirty.insert(peer.to_string());
        // The first undecryptable id of a tick schedules the notice now;
        // later ones join it and the tick's redrive (M-1).
        if first_this_tick {
            self.flush_receipts(peer);
        }
    }

    /// Take `id` off the peer's lost lists; returns where it was listed
    /// (reported with its stamp, unreported) for an exact `relist_lost`.
    fn unlist_lost(&mut self, peer: &str, id: &[u8; 16]) -> UnlistedLost {
        let reported = self.lost_reported.get_mut(peer).and_then(|q| {
            let pos = q.iter().position(|(x, _)| x == id)?;
            q.remove(pos).map(|(_, at)| (pos, at))
        });
        let unreported = self.lost_unstored.get_mut(peer).and_then(|q| {
            let pos = q.iter().position(|x| x == id)?;
            q.remove(pos);
            Some(pos)
        });
        (reported, unreported)
    }

    /// Undo `unlist_lost` (the delivery's write failed, D28).
    fn relist_lost(&mut self, peer: &str, id: [u8; 16], (reported, unreported): UnlistedLost) {
        if let Some((pos, at)) = reported {
            let q = self.lost_reported.entry(peer.to_string()).or_default();
            q.insert(pos.min(q.len()), (id, at));
        }
        if let Some(pos) = unreported {
            let q = self.lost_unstored.entry(peer.to_string()).or_default();
            q.insert(pos.min(q.len()), id);
        }
    }

    /// Decrypt bodies taken out of the held queue; one whose write fails is
    /// held again. The caller writes the meta record once for the batch.
    pub(crate) fn release_held(&mut self, bodies: Vec<PendingEncrypted>) {
        for p in bodies {
            if let Err(held) = self.try_ratchet(&p.sender_hex, p.message_id, &p.body, false) {
                self.push_held_capped(held);
            }
        }
    }
}

/// 0.5 s + r x 2.5 s (spec §5.7).
pub(crate) fn receipt_delay_for(r: f64) -> Duration {
    Duration::from_millis(500 + (r.clamp(0.0, 1.0) * 2500.0).round() as u64)
}

#[cfg(test)]
#[path = "circuits_tests.rs"]
pub(crate) mod tests;
