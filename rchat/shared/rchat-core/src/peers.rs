//! Per-peer key policy (spec §4.4, §6.1): pins (pinned == accepted),
//! blocks, the sticky mismatch flag, the transient bad-signature flag (M1)
//! and the ring of outstanding ask ephemeral keys (M9). Pure data: no I/O
//! and no clock reads — callers pass `now`.

use crate::crypto::EphemeralKeyPair;
pub use crate::device_key::DevicePin;
use constant_time_eq::constant_time_eq;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Outstanding asks kept per peer.
pub const ASK_RING: usize = 3;
/// How long an ask's ephemeral key may be echoed back.
pub const ASK_TTL: Duration = Duration::from_secs(600);

/// Most identities remembered for request de-duplication (L8).
pub const REQUEST_DEDUPE_CAP: usize = 512;
/// Distinct intro ids from one identity reported per issued hour (C-12):
/// the intro id is chosen by the sender, so it cannot key the de-dup alone.
pub const REQUEST_INTROS_PER_HOUR: usize = 2;
/// Message ids per peer the app already has (spec §6.3 De-duplication),
/// kept in memory only.
pub const SEEN_IDS_CAP: usize = 256;
/// At most one silent re-pin per contact per 24 h (spec §4.8).
pub const SILENT_REPIN_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Per-peer exponential backoff for automatic re-asks (M9).
#[derive(Debug, Default, Clone)]
pub struct Backoff {
    attempts: u32,
}

impl Backoff {
    /// 2 s × 2^attempt, capped at 600 s, scaled by (1 + jitter) with jitter
    /// clamped to [-0.2, 0.2].
    pub fn delay(attempt: u32, jitter: f64) -> Duration {
        let base = 2u64.saturating_mul(1u64 << attempt.min(16)).min(600);
        Duration::from_secs_f64(base as f64 * (1.0 + jitter.clamp(-0.2, 0.2)))
    }

    /// Count an attempt; returns the earliest time of the next one.
    pub fn record(&mut self, now: Instant, jitter: f64) -> Instant {
        // The caller schedules the attempt (`pending_reasks`); the backoff
        // only counts (Task 14 minor: an unused stored deadline is gone).
        let next = now + Self::delay(self.attempts, jitter);
        self.attempts = self.attempts.saturating_add(1);
        next
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// One numbering for `rchat_peer_key_state` and key events (L6).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKeyState {
    None = 0,
    Pinned = 1,
    Mismatch = 2,
    BadSignature = 3,
    Blocked = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// A different agreement key is already pinned for this identity.
    Conflict,
    /// This agreement key is pinned for another identity (M10).
    AgreementKeyInUse,
    /// A silent re-pin of this contact happened less than 24 h ago.
    RotationTooSoon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyNumberError {
    /// Nothing pinned for this identity.
    NoPinnedKeys,
    /// The digits differ from the number computed from the pinned keys.
    Changed,
    /// Not a 64-hex identity.
    BadPeer,
    /// Not 60 ASCII digits (Task 13b minor: was one error with BadPeer).
    BadDigits,
}

/// Lowercase or uppercase 64-hex → 32 bytes.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// One identity in the request de-duplication LRU.
struct RequestSeen {
    identity: String,
    hour: u64,
    intros: Vec<[u8; 16]>,
}

#[derive(Default)]
pub struct PeerBook {
    pins: HashMap<String, [u8; 32]>,
    blocked: HashSet<String>,
    mismatch: HashSet<String>,
    bad_signature: HashMap<String, Instant>,
    asks: HashMap<String, VecDeque<(EphemeralKeyPair, Instant)>>,
    backoff: HashMap<String, Backoff>,
    /// LRU of identities already reported as requests (one entry each),
    /// with the newest issued hour seen and the intro ids reported for it.
    requests_seen: VecDeque<RequestSeen>,
    /// Knock hour at which the current pin was set (set by the caller).
    pin_hours: HashMap<String, u64>,
    /// Message ids the app already has, newest last, at most `SEEN_IDS_CAP` per peer.
    seen: HashMap<String, VecDeque<[u8; 16]>>,
    /// Pinned key version per identity (spec §4.8; 0 when unset).
    versions: HashMap<String, u32>,
    /// When each identity was pinned by a silent re-pin (rotation). Kept
    /// across unpin so the 24 h limit follows the contact.
    repinned_at: HashMap<String, Instant>,
    /// Identities whose most recent pin change was an unpin. Read only by
    /// `overlay`, so an unpin made in a staged book (while a connect runs)
    /// still reaches the client's book.
    unpinned: HashSet<String>,
    /// Identities whose most recent block change was an unblock (as above).
    unblocked: HashSet<String>,
    /// Device keys pinned from the contacts' scanned cards (D44). Set only
    /// by `pin_device_key`, which only the app's scan, paste or restore of a
    /// stored scan reaches; never from anything received.
    device_keys: HashMap<String, DevicePin>,
}

impl PeerBook {
    /// Pin (accept) `id` with agreement key `ak`. Re-pinning the same value
    /// leaves `mismatch` alone (L11) and keeps the session; it clears the
    /// transient bad-signature flag, as the user's re-confirmation of the
    /// key (an in-person re-scan, Task 9b re-review 2). Mismatch stays
    /// sticky: only `repin` (a new key from their code) clears it.
    pub fn pin(&mut self, id: &str, ak: [u8; 32]) -> Result<(), PinError> {
        if let Some(existing) = self.pins.get(id) {
            return if constant_time_eq(existing, &ak) {
                self.bad_signature.remove(id);
                Ok(())
            } else {
                Err(PinError::Conflict)
            };
        }
        if self.pinned_elsewhere(id, &ak) {
            return Err(PinError::AgreementKeyInUse);
        }
        self.pins.insert(id.to_string(), ak);
        Ok(())
    }

    /// Replace the pin with a value from the contact's code (QR is
    /// authoritative). Clears the mismatch and bad-signature flags.
    pub fn repin(&mut self, id: &str, ak: [u8; 32]) -> Result<(), PinError> {
        if self.pinned_elsewhere(id, &ak) {
            return Err(PinError::AgreementKeyInUse);
        }
        self.pins.insert(id.to_string(), ak);
        self.mismatch.remove(id);
        self.bad_signature.remove(id);
        Ok(())
    }

    /// Forget the pin and every per-peer flag and ask. Returns whether a pin existed.
    pub fn unpin(&mut self, id: &str) -> bool {
        self.mismatch.remove(id);
        self.bad_signature.remove(id);
        self.asks.remove(id);
        self.backoff.remove(id);
        self.pin_hours.remove(id);
        self.seen.remove(id);
        self.versions.remove(id);
        self.clear_device_key(id);
        self.unpinned.insert(id.to_string());
        self.pins.remove(id).is_some()
    }

    /// Blocking also unpins.
    pub fn set_blocked(&mut self, id: &str, blocked: bool) {
        if blocked {
            self.unpin(id);
            self.blocked.insert(id.to_string());
        } else {
            self.blocked.remove(id);
            self.unblocked.insert(id.to_string());
        }
    }

    /// Spec §4.7: the safety number from the pinned keys.
    pub fn safety_number(
        &self,
        peer: &str,
        my_ik: &[u8; 32],
        my_ak: &[u8; 32],
    ) -> Result<String, SafetyNumberError> {
        let peer_ik = key_from_hex(peer).ok_or(SafetyNumberError::BadPeer)?;
        let peer_ak = self
            .pin_for(&peer.to_lowercase())
            .ok_or(SafetyNumberError::NoPinnedKeys)?;
        Ok(crate::safety_number::safety_number(
            my_ik, my_ak, &peer_ik, &peer_ak,
        ))
    }

    /// The user compared `digits` with the peer. Clears a sticky mismatch
    /// (and a transient bad signature) only if they equal the number from
    /// the pinned keys. The pin itself is unchanged, so the clearing is
    /// cosmetic (round-2 L3): different keys from the relay raise it again.
    pub fn mark_safety_number_compared(
        &mut self,
        peer: &str,
        my_ik: &[u8; 32],
        my_ak: &[u8; 32],
        digits: &str,
    ) -> Result<(), SafetyNumberError> {
        if digits.len() != crate::safety_number::SN_DIGITS
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(SafetyNumberError::BadDigits);
        }
        let id = peer.to_lowercase();
        let expected = self.safety_number(&id, my_ik, my_ak)?;
        if !crate::safety_number::numbers_equal(&expected, digits) {
            return Err(SafetyNumberError::Changed);
        }
        let ak = self.pin_for(&id).ok_or(SafetyNumberError::NoPinnedKeys)?;
        self.repin(&id, ak)
            .map_err(|_| SafetyNumberError::NoPinnedKeys)
    }

    /// D22: compare the other phone's scanned QR with our number.
    pub fn compare_scanned_safety_number(
        &self,
        peer: &str,
        my_ik: &[u8; 32],
        my_ak: &[u8; 32],
        scanned: &str,
    ) -> Result<crate::safety_number::ScanComparison, SafetyNumberError> {
        let expected = self.safety_number(&peer.to_lowercase(), my_ik, my_ak)?;
        Ok(crate::safety_number::compare_scanned(&expected, scanned))
    }

    /// Apply the pin and block changes of `newer` on top of this book: the
    /// C FFI's staged book (changes made while a connect ran) onto the
    /// client's book, or the other way round when a connect fails. Unpins
    /// and unblocks travel as tombstones; an identity in both `pins` and
    /// `unpinned` was pinned last (an unpin removes the pin), so the pin
    /// wins, and likewise a block wins over an unblock. A pin whose
    /// agreement key this book holds for another identity is skipped.
    pub fn overlay(&mut self, newer: PeerBook) {
        for id in newer
            .unblocked
            .iter()
            .filter(|id| !newer.blocked.contains(*id))
        {
            self.set_blocked(id, false);
        }
        for id in newer
            .unpinned
            .iter()
            .filter(|id| !newer.pins.contains_key(*id))
        {
            self.unpin(id);
        }
        for id in &newer.blocked {
            self.set_blocked(id, true);
        }
        for (id, ak) in &newer.pins {
            if self.blocked.contains(id) || self.pinned_elsewhere(id, ak) {
                continue;
            }
            if self
                .pin_for(id)
                .is_some_and(|old| !constant_time_eq(&old, ak))
            {
                self.unpin(id);
            }
            // A staged same-key pin is a sync, not the user re-confirming
            // the key: it must not clear a bad-signature flag (`pin` would).
            let same = self
                .pin_for(id)
                .is_some_and(|old| constant_time_eq(&old, ak));
            if same || self.pin(id, *ak).is_ok() {
                if let Some(hour) = newer.pin_hours.get(id) {
                    self.set_pin_hour(id, *hour);
                }
            }
        }
        // Device keys travel like pins: one staged for an identity this book
        // has pinned (now) replaces the old one; an unpin above cleared it.
        for (id, dk) in newer.device_keys {
            if self.pins.contains_key(&id) && !self.blocked.contains(&id) {
                self.pin_device_key(&id, dk);
            }
        }
    }

    /// Identities whose current pin `overlay(newer)` would remove or replace,
    /// or that it would block (their sessions must go first).
    pub fn overlay_drops(&self, newer: &PeerBook) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for id in &newer.blocked {
            if !self.blocked.contains(id) {
                out.push(id.clone());
            }
        }
        for id in newer
            .unpinned
            .iter()
            .filter(|id| !newer.pins.contains_key(*id))
        {
            if self.pins.contains_key(id) && !out.contains(id) {
                out.push(id.clone());
            }
        }
        for (id, ak) in &newer.pins {
            // Only a pin `overlay` will actually replace: one whose key this
            // book holds for another identity is skipped there, so its old
            // pin (and session) stays (Task 19 minor).
            let replaced = self
                .pin_for(id)
                .is_some_and(|old| !constant_time_eq(&old, ak))
                && !self.pinned_elsewhere(id, ak);
            if replaced && !out.contains(id) {
                out.push(id.clone());
            }
        }
        out
    }

    pub fn pin_for(&self, id: &str) -> Option<[u8; 32]> {
        self.pins.get(id).copied()
    }

    /// Pin (or replace) `id`'s device key, from their scanned or pasted
    /// card, or the app's stored copy of one (D44). The caller has checked
    /// the card's binding (`keyauth::verify_device_key`).
    pub fn pin_device_key(&mut self, id: &str, pin: DevicePin) {
        self.device_keys.insert(id.to_string(), pin);
    }

    /// `id`'s pinned device key, if their card carried one (D46).
    pub fn device_key(&self, id: &str) -> Option<&DevicePin> {
        self.device_keys.get(id)
    }

    /// Forget `id`'s device key (unpin, block, their rotation: D44).
    pub fn clear_device_key(&mut self, id: &str) {
        self.device_keys.remove(id);
    }

    pub fn is_blocked(&self, id: &str) -> bool {
        self.blocked.contains(id)
    }

    /// Is `ak` pinned for an identity other than `id`? Compares every pin in
    /// constant time and does not stop at the first hit.
    pub fn pinned_elsewhere(&self, id: &str, ak: &[u8; 32]) -> bool {
        let mut found = false;
        for (other, pinned) in &self.pins {
            if other != id && constant_time_eq(pinned, ak) {
                found = true;
            }
        }
        found
    }

    /// Blocked > Mismatch > BadSignature > Pinned > None.
    pub fn state(&self, id: &str) -> PeerKeyState {
        if self.blocked.contains(id) {
            PeerKeyState::Blocked
        } else if !self.pins.contains_key(id) {
            PeerKeyState::None
        } else if self.mismatch.contains(id) {
            PeerKeyState::Mismatch
        } else if self.bad_signature.contains_key(id) {
            PeerKeyState::BadSignature
        } else {
            PeerKeyState::Pinned
        }
    }

    /// Sticky mismatch. Outstanding asks are dropped with it (C-8): no
    /// circuit may be set up from an ask made before the mismatch.
    pub fn mark_mismatch(&mut self, id: &str) {
        self.mismatch.insert(id.to_string());
        self.asks.remove(id);
    }

    pub fn is_mismatch(&self, id: &str) -> bool {
        self.mismatch.contains(id)
    }

    /// Transient (M1): never persisted, cleared by a good bundle or a re-pin.
    pub fn mark_bad_signature(&mut self, id: &str, now: Instant) {
        self.bad_signature.insert(id.to_string(), now);
    }

    pub fn clear_bad_signature(&mut self, id: &str) {
        self.bad_signature.remove(id);
    }

    /// Remember an ask's ephemeral key; only the last `ASK_RING` are kept.
    pub fn push_ask(&mut self, id: &str, ek: EphemeralKeyPair, now: Instant) {
        let ring = self.asks.entry(id.to_string()).or_default();
        ring.push_back((ek, now));
        while ring.len() > ASK_RING {
            ring.pop_front();
        }
    }

    /// Consume the outstanding ask whose public key is `ek_pub`, if it is
    /// younger than `ASK_TTL`. Expired entries are dropped on the way.
    pub fn take_ask(
        &mut self,
        id: &str,
        ek_pub: &[u8; 32],
        now: Instant,
    ) -> Option<EphemeralKeyPair> {
        let ring = self.asks.get_mut(id)?;
        ring.retain(|(_, at)| now.saturating_duration_since(*at) <= ASK_TTL);
        let pos = ring
            .iter()
            .position(|(ek, _)| constant_time_eq(ek.public_key().as_bytes(), ek_pub))?;
        ring.remove(pos).map(|(ek, _)| ek)
    }

    /// Drop every ask older than `ASK_TTL` (C-13), with its ephemeral secret.
    pub fn purge_expired_asks(&mut self, now: Instant) {
        self.asks.retain(|_, ring| {
            ring.retain(|(_, at)| now.saturating_duration_since(*at) <= ASK_TTL);
            !ring.is_empty()
        });
    }

    pub fn outstanding_asks(&self, id: &str) -> usize {
        self.asks.get(id).map_or(0, |r| r.len())
    }

    pub fn pinned_ids(&self) -> Vec<String> {
        self.pins.keys().cloned().collect()
    }

    pub fn backoff_mut(&mut self, id: &str) -> &mut Backoff {
        self.backoff.entry(id.to_string()).or_default()
    }

    /// True if this knock is a new request: the identity was not reported
    /// recently, the knock is from a newer `issued_hour`, or (same hour) it
    /// carries an intro id not yet reported, at most
    /// `REQUEST_INTROS_PER_HOUR` per hour (C-12). One LRU entry per
    /// identity, capped at `REQUEST_DEDUPE_CAP`, so one sender varying its
    /// intro id can neither repeat requests nor evict other identities.
    pub fn note_request(&mut self, id: &str, intro_id: Option<[u8; 16]>, issued_hour: u64) -> bool {
        let Some(pos) = self.requests_seen.iter().position(|r| r.identity == id) else {
            self.requests_seen.push_back(RequestSeen {
                identity: id.to_string(),
                hour: issued_hour,
                intros: intro_id.into_iter().collect(),
            });
            while self.requests_seen.len() > REQUEST_DEDUPE_CAP {
                self.requests_seen.pop_front();
            }
            return true;
        };
        let Some(mut seen) = self.requests_seen.remove(pos) else {
            return false;
        };
        let new = if issued_hour > seen.hour {
            seen.hour = issued_hour;
            seen.intros = intro_id.into_iter().collect();
            true
        } else if issued_hour < seen.hour {
            false
        } else {
            match intro_id {
                Some(intro)
                    if !seen.intros.contains(&intro)
                        && seen.intros.len() < REQUEST_INTROS_PER_HOUR =>
                {
                    seen.intros.push(intro);
                    true
                }
                _ => false,
            }
        };
        self.requests_seen.push_back(seen);
        new
    }

    /// Round-2 M1: is `id` in the request de-duplication set (Task 14)?
    pub fn has_requested(&self, id: &str) -> bool {
        self.requests_seen.iter().any(|r| r.identity == id)
    }

    /// The pinned key version of `id` (0 when unset).
    pub fn pin_version(&self, id: &str) -> u32 {
        self.versions.get(id).copied().unwrap_or(0)
    }

    pub fn set_pin_version(&mut self, id: &str, version: u32) {
        self.versions.insert(id.to_string(), version);
    }

    /// Move the pin from `old` to `new` after a verified rotation chain
    /// (spec §4.8). Refused within `SILENT_REPIN_INTERVAL` of the last silent
    /// re-pin that produced `old`, or if `new_ak` is pinned for another identity.
    pub fn rotate_pin(
        &mut self,
        old: &str,
        new: &str,
        new_ak: [u8; 32],
        new_version: u32,
        now: Instant,
    ) -> Result<(), PinError> {
        if let Some(at) = self.repinned_at.get(old) {
            if now.saturating_duration_since(*at) < SILENT_REPIN_INTERVAL {
                return Err(PinError::RotationTooSoon);
            }
        }
        if self.pins.contains_key(new) || self.blocked.contains(new) {
            return Err(PinError::Conflict);
        }
        if self.pinned_elsewhere(old, &new_ak) {
            return Err(PinError::AgreementKeyInUse);
        }
        // `unpin` clears the old identity's device key; the new identity
        // has none until the user scans their code (D44).
        self.unpin(old);
        self.clear_device_key(new);
        self.pins.insert(new.to_string(), new_ak);
        self.versions.insert(new.to_string(), new_version);
        self.repinned_at.insert(new.to_string(), now);
        Ok(())
    }

    /// Record the knock hour at which `id`'s current pin was set.
    pub fn set_pin_hour(&mut self, id: &str, hour: u64) {
        self.pin_hours.insert(id.to_string(), hour);
    }

    pub fn pin_hour(&self, id: &str) -> Option<u64> {
        self.pin_hours.get(id).copied()
    }

    pub fn request_dedupe_len(&self) -> usize {
        self.requests_seen.len()
    }

    /// Remember a message id the app already has (e.g. an intro shown on
    /// accept). Keeps the newest `SEEN_IDS_CAP` per peer.
    pub fn mark_seen(&mut self, id: &str, msg_id: [u8; 16]) {
        let ids = self.seen.entry(id.to_string()).or_default();
        if !ids.contains(&msg_id) {
            ids.push_back(msg_id);
        }
        while ids.len() > SEEN_IDS_CAP {
            ids.pop_front();
        }
    }

    /// The ids the app already has from `id`, oldest first.
    pub fn seen_ids(&self, id: &str) -> Vec<[u8; 16]> {
        self.seen
            .get(id)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn is_seen(&self, id: &str, msg_id: &[u8; 16]) -> bool {
        self.seen.get(id).is_some_and(|ids| ids.contains(msg_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EphemeralKeyPair;
    use std::time::{Duration, Instant};

    const A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn pin_same_value_is_noop_and_keeps_mismatch() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.mark_mismatch(A);
        assert_eq!(book.pin(A, [1; 32]), Ok(()));
        assert!(
            book.is_mismatch(A),
            "L11: same-value pin never clears mismatch"
        );
        assert_eq!(book.state(A), PeerKeyState::Mismatch);
    }

    /// C-8: a mismatch drops the peer's outstanding asks.
    #[test]
    fn mismatch_clears_outstanding_asks() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.push_ask(A, EphemeralKeyPair::generate(), Instant::now());
        book.mark_mismatch(A);
        assert_eq!(book.outstanding_asks(A), 0);
    }

    #[test]
    fn pin_different_value_conflicts() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(book.pin(A, [2; 32]), Err(PinError::Conflict));
        assert_eq!(book.pin_for(A), Some([1; 32]));
    }

    #[test]
    fn agreement_key_cannot_be_pinned_for_two_identities() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(book.pin(B, [1; 32]), Err(PinError::AgreementKeyInUse));
        assert_eq!(book.repin(B, [1; 32]), Err(PinError::AgreementKeyInUse));
        assert!(book.pinned_elsewhere(B, &[1; 32]));
        assert!(!book.pinned_elsewhere(A, &[1; 32]));
    }

    #[test]
    fn repin_replaces_and_clears_mismatch_and_bad_signature() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.mark_mismatch(A);
        book.mark_bad_signature(A, Instant::now());
        book.repin(A, [2; 32]).unwrap();
        assert_eq!(book.pin_for(A), Some([2; 32]));
        assert_eq!(book.state(A), PeerKeyState::Pinned);
    }

    /// Task 9b re-review 2: the same key pinned again (a re-scan) clears
    /// a transient bad signature, never a sticky mismatch, and keeps the pin.
    #[test]
    fn staged_same_key_pin_keeps_a_bad_signature() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.mark_bad_signature(A, Instant::now());
        let mut staged = PeerBook::default();
        staged.pin(A, [1; 32]).unwrap();
        book.overlay(staged);
        assert_eq!(
            book.state(A),
            PeerKeyState::BadSignature,
            "a sync is not a re-confirmation"
        );
        assert_eq!(book.pin_for(A), Some([1; 32]));
    }

    #[test]
    fn same_key_pin_clears_bad_signature_not_mismatch() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.mark_bad_signature(A, Instant::now());
        assert_eq!(book.state(A), PeerKeyState::BadSignature);
        assert_eq!(book.pin(A, [2; 32]), Err(PinError::Conflict));
        assert_eq!(
            book.state(A),
            PeerKeyState::BadSignature,
            "another key clears nothing"
        );
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(book.state(A), PeerKeyState::Pinned);
        assert_eq!(book.pin_for(A), Some([1; 32]));

        book.mark_mismatch(A);
        book.mark_bad_signature(A, Instant::now());
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(
            book.state(A),
            PeerKeyState::Mismatch,
            "mismatch stays sticky"
        );
        assert!(book.is_mismatch(A));
    }

    #[test]
    fn state_precedence_blocked_mismatch_badsig_pinned_none() {
        let mut book = PeerBook::default();
        assert_eq!(book.state(A), PeerKeyState::None);
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(book.state(A), PeerKeyState::Pinned);
        book.mark_bad_signature(A, Instant::now());
        assert_eq!(book.state(A), PeerKeyState::BadSignature);
        book.mark_mismatch(A);
        assert_eq!(book.state(A), PeerKeyState::Mismatch);
        book.set_blocked(A, true);
        assert_eq!(book.state(A), PeerKeyState::Blocked);
        assert_eq!(book.pin_for(A), None, "blocking unpins");
        book.set_blocked(A, false);
        assert_eq!(book.state(A), PeerKeyState::None);
        assert_eq!(PeerKeyState::Blocked as u8, 4);
        assert_eq!(PeerKeyState::BadSignature as u8, 3);
    }

    #[test]
    fn seen_ids_are_capped_per_peer_and_cleared_on_unpin() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        for i in 0..300u16 {
            let mut id = [0u8; 16];
            id[..2].copy_from_slice(&i.to_be_bytes());
            book.mark_seen(A, id);
        }
        let mut newest = [0u8; 16];
        newest[..2].copy_from_slice(&299u16.to_be_bytes());
        assert!(book.is_seen(A, &newest));
        assert!(
            !book.is_seen(A, &[0u8; 16]),
            "oldest beyond the 256 cap is forgotten"
        );
        assert!(!book.is_seen(B, &newest), "per peer");
        book.unpin(A);
        assert!(!book.is_seen(A, &newest));
    }

    #[test]
    fn unpin_clears_everything_about_the_peer() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.mark_mismatch(A);
        book.push_ask(A, EphemeralKeyPair::generate(), Instant::now());
        assert!(book.unpin(A));
        assert_eq!(book.state(A), PeerKeyState::None);
        assert_eq!(book.outstanding_asks(A), 0);
        assert!(!book.unpin(A));
    }

    #[test]
    fn k16_ring_keeps_last_three_each_valid_600s_and_consumes_on_match() {
        let mut book = PeerBook::default();
        let t0 = Instant::now();
        let eks: Vec<EphemeralKeyPair> = (0..4).map(|_| EphemeralKeyPair::generate()).collect();
        let pubs: Vec<[u8; 32]> = eks.iter().map(|e| e.public_key().to_bytes()).collect();
        for (i, ek) in eks.iter().take(3).enumerate() {
            book.push_ask(A, ek.clone(), t0 + Duration::from_secs(i as u64));
        }
        // Any of the three matches (take the middle one).
        assert!(book
            .take_ask(A, &pubs[1], t0 + Duration::from_secs(10))
            .is_some());
        // Consumed: a second match on the same EK is refused.
        assert!(book
            .take_ask(A, &pubs[1], t0 + Duration::from_secs(10))
            .is_none());
        // A fourth evicts the oldest once the ring is full again.
        book.push_ask(A, eks[1].clone(), t0 + Duration::from_secs(11));
        book.push_ask(A, eks[3].clone(), t0 + Duration::from_secs(12));
        assert_eq!(book.outstanding_asks(A), 3);
        assert!(
            book.take_ask(A, &pubs[0], t0 + Duration::from_secs(13))
                .is_none(),
            "oldest evicted"
        );
        assert!(book
            .take_ask(A, &pubs[3], t0 + Duration::from_secs(13))
            .is_some());
        // Expiry: older than 600 s is refused.
        book.push_ask(B, eks[2].clone(), t0);
        assert!(book
            .take_ask(B, &pubs[2], t0 + Duration::from_secs(601))
            .is_none());
    }

    #[test]
    fn key_from_hex_accepts_only_64_hex() {
        assert_eq!(key_from_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(key_from_hex(&"AB".repeat(32)), Some([0xab; 32]));
        assert_eq!(key_from_hex(&"ab".repeat(31)), None);
        assert_eq!(key_from_hex(&"zz".repeat(32)), None);
    }

    /// SN4: marking as compared clears a sticky mismatch only for the right digits.
    #[test]
    fn sn4_mark_compared_clears_mismatch_only_on_match() {
        let (my_ik, my_ak) = ([0x11u8; 32], [0x22u8; 32]);
        let peer = hex::encode([0x33u8; 32]);
        let mut book = PeerBook::default();
        assert_eq!(
            book.safety_number(&peer, &my_ik, &my_ak),
            Err(SafetyNumberError::NoPinnedKeys)
        );
        book.pin(&peer, [0x44; 32]).unwrap();
        book.mark_mismatch(&peer);
        let n = book.safety_number(&peer, &my_ik, &my_ak).unwrap();
        assert_eq!(
            n,
            "207876968560055734126985141340311686637181083400395252065708"
        );
        let wrong = format!("{}9", &n[..59]);
        let wrong = if wrong == n {
            format!("{}8", &n[..59])
        } else {
            wrong
        };
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, &wrong),
            Err(SafetyNumberError::Changed)
        );
        assert!(
            book.is_mismatch(&peer),
            "a wrong number leaves the mismatch"
        );
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, &n),
            Ok(())
        );
        assert!(!book.is_mismatch(&peer));
        assert_eq!(book.pin_for(&peer), Some([0x44; 32]), "pin unchanged");
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, "12"),
            Err(SafetyNumberError::BadDigits)
        );
    }

    /// Task 13b minors: bad digits and a bad peer are told apart; digits
    /// must be exactly 60 ASCII digits (no spaces, no non-ASCII digits);
    /// the peer may be uppercase hex; marking clears a bad signature too;
    /// nothing pinned (or only blocked) is NoPinnedKeys.
    #[test]
    fn sn_mark_input_cases() {
        let (my_ik, my_ak) = ([0x11u8; 32], [0x22u8; 32]);
        let peer = hex::encode([0x33u8; 32]);
        let mut book = PeerBook::default();
        assert_eq!(
            book.mark_safety_number_compared("12", &my_ik, &my_ak, &"1".repeat(60)),
            Err(SafetyNumberError::BadPeer)
        );
        // Unpinned, and blocked without a pin.
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, &"1".repeat(60)),
            Err(SafetyNumberError::NoPinnedKeys)
        );
        book.set_blocked(&peer, true);
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, &"1".repeat(60)),
            Err(SafetyNumberError::NoPinnedKeys)
        );
        book.set_blocked(&peer, false);
        book.pin(&peer, [0x44; 32]).unwrap();
        let n = book.safety_number(&peer, &my_ik, &my_ak).unwrap();
        let spaced = format!(" {n}");
        let arabic_indic: String = n
            .chars()
            .map(|c| char::from_u32(0x0660 + c.to_digit(10).unwrap()).unwrap())
            .collect();
        for bad in [spaced.as_str(), &n[..59], arabic_indic.as_str(), ""] {
            assert_eq!(
                book.mark_safety_number_compared(&peer, &my_ik, &my_ak, bad),
                Err(SafetyNumberError::BadDigits),
                "{bad:?}"
            );
        }
        book.mark_bad_signature(&peer, Instant::now());
        assert_eq!(book.state(&peer), PeerKeyState::BadSignature);
        assert_eq!(
            book.mark_safety_number_compared(&peer.to_uppercase(), &my_ik, &my_ak, &n),
            Ok(()),
            "uppercase peer hex is the same peer"
        );
        assert_eq!(
            book.state(&peer),
            PeerKeyState::Pinned,
            "bad signature cleared"
        );
    }

    /// SN5: after a re-pin the old digits no longer mark.
    #[test]
    fn sn5_old_digits_stop_matching_after_repin() {
        let (my_ik, my_ak) = ([0x11u8; 32], [0x22u8; 32]);
        let peer = hex::encode([0x33u8; 32]);
        let mut book = PeerBook::default();
        book.pin(&peer, [0x44; 32]).unwrap();
        let old = book.safety_number(&peer, &my_ik, &my_ak).unwrap();
        book.repin(&peer, [0x45; 32]).unwrap();
        assert_eq!(
            book.mark_safety_number_compared(&peer, &my_ik, &my_ak, &old),
            Err(SafetyNumberError::Changed)
        );
    }

    /// SN6 (D22): scanning the other phone's QR compares in constant time.
    #[test]
    fn sn6_scanned_qr_compare() {
        use crate::safety_number::{to_text_form, ScanComparison};
        let (my_ik, my_ak) = ([0x11u8; 32], [0x22u8; 32]);
        let peer = hex::encode([0x33u8; 32]);
        let mut book = PeerBook::default();
        assert_eq!(
            book.compare_scanned_safety_number(&peer, &my_ik, &my_ak, "sn:1:0"),
            Err(SafetyNumberError::NoPinnedKeys)
        );
        book.pin(&peer, [0x44; 32]).unwrap();
        let n = book.safety_number(&peer, &my_ik, &my_ak).unwrap();
        let cmp = |s: &str| {
            book.compare_scanned_safety_number(&peer, &my_ik, &my_ak, s)
                .unwrap()
        };
        assert_eq!(cmp(&to_text_form(&n)), ScanComparison::Match);
        assert_eq!(
            cmp(&format!(" {}\n", to_text_form(&n))),
            ScanComparison::Match,
            "surrounding whitespace ignored"
        );
        let off = format!("{}{}", &n[..59], if n.ends_with('0') { '1' } else { '0' });
        assert_eq!(cmp(&to_text_form(&off)), ScanComparison::Mismatch);
        let other = crate::safety_number::safety_number(&my_ik, &my_ak, &[0x55; 32], &[0x66; 32]);
        assert_eq!(
            cmp(&to_text_form(&other)),
            ScanComparison::Mismatch,
            "another pair's number"
        );
        for bad in [
            n.clone(),
            format!("sn:2:{n}"),
            format!("sn:1:{}", &n[..59]),
            format!("sn:1:{}x", &n[..59]),
        ] {
            assert_eq!(cmp(&bad), ScanComparison::Invalid, "{bad}");
        }
    }

    /// K15: 2, 4, 8 … capped at 600 s, ±20 % jitter, reset on success.
    #[test]
    fn k15_backoff_schedule_doubles_to_600s_with_jitter_and_resets() {
        let secs: Vec<u64> = (0..12).map(|a| Backoff::delay(a, 0.0).as_secs()).collect();
        assert_eq!(
            secs,
            vec![2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600, 600]
        );
        assert_eq!(Backoff::delay(0, 0.2).as_millis(), 2400);
        assert_eq!(Backoff::delay(0, -0.2).as_millis(), 1600);
        assert_eq!(
            Backoff::delay(0, 5.0).as_millis(),
            2400,
            "jitter is clamped to ±20 %"
        );
        let t0 = Instant::now();
        let mut b = Backoff::default();
        assert_eq!(b.record(t0, 0.0), t0 + Duration::from_secs(2));
        assert_eq!(b.record(t0, 0.0), t0 + Duration::from_secs(4));
        assert_eq!(b.attempts(), 2);
        b.reset();
        assert_eq!(b.attempts(), 0);
        assert_eq!(
            b.record(t0, 0.0),
            t0 + Duration::from_secs(2),
            "reset starts over"
        );
    }

    /// Task 19 minor: a staged pin that `overlay` skips (its key is pinned
    /// to another identity here) is not reported as replaced, so the live
    /// pin's session is not torn down for nothing.
    #[test]
    fn overlay_drops_skips_a_pin_overlay_will_skip() {
        let mut base = PeerBook::default();
        base.pin(A, [1; 32]).unwrap();
        base.pin(B, [2; 32]).unwrap();
        let mut newer = PeerBook::default();
        newer.pin(A, [2; 32]).unwrap(); // B's key: overlay skips it
        assert!(base.overlay_drops(&newer).is_empty());
        let mut newer = PeerBook::default();
        newer.pin(A, [3; 32]).unwrap(); // a real replacement
        assert_eq!(base.overlay_drops(&newer), vec![A.to_string()]);
        base.overlay(newer);
        assert_eq!(base.pin_for(A), Some([3; 32]));
    }

    #[test]
    fn unpin_resets_backoff() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.backoff_mut(A).record(Instant::now(), 0.0);
        book.unpin(A);
        assert_eq!(book.backoff_mut(A).attempts(), 0);
    }

    /// N15 (L8): 10,000 distinct requests never grow the de-duplication set past 512.
    #[test]
    fn n15_request_dedupe_is_an_lru_capped_at_512() {
        let mut book = PeerBook::default();
        for i in 0..10_000u32 {
            let id = format!("{:064x}", i);
            assert!(book.note_request(&id, None, 10), "new identity is new");
            assert!(book.request_dedupe_len() <= REQUEST_DEDUPE_CAP);
        }
        assert_eq!(book.request_dedupe_len(), REQUEST_DEDUPE_CAP);
        let recent = format!("{:064x}", 9_999u32);
        assert!(
            !book.note_request(&recent, None, 10),
            "recent duplicate suppressed"
        );
        let evicted = format!("{:064x}", 0u32);
        assert!(
            book.note_request(&evicted, None, 10),
            "evicted entry counts as new again"
        );
        assert!(
            book.note_request(&recent, Some([1; 16]), 10),
            "a new intro id is a new request"
        );
        assert!(!book.note_request(&recent, Some([1; 16]), 10));
    }

    /// C-12: one identity varying its intro id gets at most
    /// `REQUEST_INTROS_PER_HOUR` requests per hour and one LRU entry, so it
    /// cannot evict other identities.
    #[test]
    fn varying_intro_ids_neither_repeat_requests_nor_evict_others() {
        let mut book = PeerBook::default();
        assert!(book.note_request(B, None, 10));
        let mut reported = 0;
        for i in 0..600u32 {
            let mut intro = [0u8; 16];
            intro[..4].copy_from_slice(&i.to_be_bytes());
            if book.note_request(A, Some(intro), 10) {
                reported += 1;
            }
        }
        assert_eq!(reported, REQUEST_INTROS_PER_HOUR);
        assert_eq!(book.request_dedupe_len(), 2);
        assert!(book.has_requested(B), "other identity kept");
        assert!(!book.note_request(B, None, 10), "and still de-duplicated");
        assert!(book.note_request(A, Some([0xFF; 16]), 11), "a newer hour");
    }

    /// A strictly newer issued hour from the same identity is a new request
    /// (a genuine new knock after a deleted request); the same or an older
    /// hour is a duplicate. One entry per (identity, intro id).
    #[test]
    fn newer_issued_hour_passes_dedupe_without_growing_it() {
        let mut book = PeerBook::default();
        assert!(book.note_request(A, None, 10));
        assert!(!book.note_request(A, None, 10));
        assert!(!book.note_request(A, None, 9));
        assert!(book.note_request(A, None, 11));
        assert!(!book.note_request(A, None, 11));
        assert_eq!(book.request_dedupe_len(), 1);
    }

    #[test]
    fn rotate_pin_moves_the_pin_and_limits_to_one_per_day() {
        const C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";
        let mut book = PeerBook::default();
        let t0 = Instant::now();
        book.pin(A, [1; 32]).unwrap();
        book.set_pin_version(A, 4);
        assert_eq!(book.pin_version(A), 4);
        assert_eq!(book.pin_version(B), 0, "unset is 0");
        book.rotate_pin(A, B, [2; 32], 5, t0).unwrap();
        assert_eq!(book.pin_for(A), None);
        assert_eq!(book.pin_version(A), 0, "unpin forgets the version");
        assert_eq!(book.pin_for(B), Some([2; 32]));
        assert_eq!(book.pin_version(B), 5);
        assert_eq!(
            book.rotate_pin(B, C, [3; 32], 6, t0 + Duration::from_secs(23 * 3600)),
            Err(PinError::RotationTooSoon)
        );
        assert_eq!(book.pin_for(B), Some([2; 32]), "refusal changes nothing");
        book.rotate_pin(B, C, [3; 32], 6, t0 + SILENT_REPIN_INTERVAL)
            .unwrap();
        assert_eq!(book.pin_for(C), Some([3; 32]));
    }

    #[test]
    fn rotate_pin_refuses_a_taken_identity_or_agreement_key() {
        const C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";
        let mut book = PeerBook::default();
        let t0 = Instant::now();
        book.pin(A, [1; 32]).unwrap();
        book.pin(C, [3; 32]).unwrap();
        assert_eq!(
            book.rotate_pin(A, B, [3; 32], 1, t0),
            Err(PinError::AgreementKeyInUse)
        );
        assert_eq!(
            book.rotate_pin(A, C, [4; 32], 1, t0),
            Err(PinError::Conflict)
        );
        book.set_blocked(B, true);
        assert_eq!(
            book.rotate_pin(A, B, [4; 32], 1, t0),
            Err(PinError::Conflict)
        );
        assert_eq!(book.pin_for(A), Some([1; 32]));
    }

    #[test]
    fn has_requested_follows_the_dedupe_set() {
        let mut book = PeerBook::default();
        assert!(!book.has_requested(A));
        book.note_request(A, Some([1; 16]), 3);
        assert!(book.has_requested(A));
        assert!(!book.has_requested(B));
    }

    #[test]
    fn pin_hour_is_kept_until_unpin() {
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        assert_eq!(book.pin_hour(A), None);
        book.set_pin_hour(A, 7);
        assert_eq!(book.pin_hour(A), Some(7));
        book.unpin(A);
        assert_eq!(book.pin_hour(A), None);
    }

    /// D44: unpin, block and rotation clear the device key; `overlay`
    /// carries one staged for a pinned identity, as it carries pins.
    #[test]
    fn device_keys_follow_the_pin() {
        let dk = |b: u8| DevicePin {
            dk_pub: [b; 65],
            hardware: b & 1 == 0,
        };
        let mut book = PeerBook::default();
        book.pin(A, [1; 32]).unwrap();
        book.pin_device_key(A, dk(1));
        assert_eq!(book.device_key(A), Some(&dk(1)));
        book.pin_device_key(A, dk(2));
        assert_eq!(book.device_key(A), Some(&dk(2)), "a re-scan replaces it");
        book.unpin(A);
        assert_eq!(book.device_key(A), None, "unpin clears it");
        book.pin(A, [1; 32]).unwrap();
        book.pin_device_key(A, dk(1));
        book.set_blocked(A, true);
        assert_eq!(book.device_key(A), None, "block clears it");
        book.set_blocked(A, false);
        book.pin(A, [1; 32]).unwrap();
        book.pin_device_key(A, dk(1));
        book.pin_device_key(B, dk(3)); // stale: B is not pinned
        book.rotate_pin(A, B, [2; 32], 1, Instant::now()).unwrap();
        assert_eq!(book.device_key(A), None, "the old identity's DK goes");
        assert_eq!(book.device_key(B), None, "the new identity has none");
        book.pin_device_key(B, dk(3));
        book.clear_device_key(B);
        assert_eq!(book.device_key(B), None);

        // Staged DKs: carried for a pinned identity, dropped for an
        // unpinned one, and an unpin tombstone clears the old one.
        let mut base = PeerBook::default();
        base.pin(A, [1; 32]).unwrap();
        base.pin(B, [2; 32]).unwrap();
        base.pin_device_key(B, dk(5));
        let mut staged = PeerBook::default();
        staged.pin_device_key(A, dk(4));
        staged.pin_device_key("cc", dk(6));
        staged.unpin(B);
        base.overlay(staged);
        assert_eq!(base.device_key(A), Some(&dk(4)));
        assert_eq!(base.device_key("cc"), None, "not pinned here");
        assert_eq!(base.device_key(B), None, "unpinned in the staged book");
        // A staged pin with a new key and its DK replace both.
        let mut staged = PeerBook::default();
        staged.pin(A, [3; 32]).unwrap();
        staged.pin_device_key(A, dk(8));
        base.overlay(staged);
        assert_eq!(base.pin_for(A), Some([3; 32]));
        assert_eq!(base.device_key(A), Some(&dk(8)));
        // A staged re-pin without a DK clears the old DK (unpin first).
        let mut staged = PeerBook::default();
        staged.pin(A, [4; 32]).unwrap();
        base.overlay(staged);
        assert_eq!(base.device_key(A), None);
    }

    #[test]
    fn overlay_applies_tombstones_and_the_last_change_wins() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let mut base = PeerBook::default();
        base.pin(&a, [1; 32]).unwrap();
        base.set_blocked(&b, true);
        let mut newer = PeerBook::default();
        newer.unpin(&a);
        newer.set_blocked(&b, false);
        base.overlay(newer);
        assert_eq!(base.pin_for(&a), None, "unpin tombstone applied");
        assert!(!base.is_blocked(&b), "unblock tombstone applied");

        let mut newer = PeerBook::default();
        newer.unpin(&a);
        newer.pin(&a, [2; 32]).unwrap();
        newer.set_blocked(&b, false);
        newer.set_blocked(&b, true);
        base.overlay(newer);
        assert_eq!(base.pin_for(&a), Some([2; 32]), "a pin after an unpin wins");
        assert!(base.is_blocked(&b), "a block after an unblock wins");
    }
}
