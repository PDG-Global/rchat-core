//! Malicious-relay harness for end-to-end test E5 (spec §12.3).
//!
//! Compiled only with `--features test-mitm`. `main` refuses to start such a
//! build unless `RCHAT_MITM_I_UNDERSTAND=1` and the bind is loopback. Mode
//! from `RCHAT_MITM`:
//! * `ak`     — substitute the peer's agreement key and signed pre-key in
//!   every `CircuitCreatedV2` (signature left as is → bad signature);
//! * `ek`     — substitute both echoed ephemeral keys (echo checks fail);
//! * `replay` — record the first `CircuitCreatedV2` per recipient identity,
//!   replay it once when that identity publishes again on a new connection,
//!   and withhold every later genuine frame for it.
//!
//! Nothing here logs keys or frames.

use super::RelayState;
use crate::protocol::unified::{ControlMessage, UnifiedFrame};
use crate::protocol::ClientId;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MitmMode {
    Ak,
    Ek,
    Replay,
}

impl MitmMode {
    pub(crate) fn from_env_value(v: &str) -> Option<MitmMode> {
        match v {
            "ak" => Some(MitmMode::Ak),
            "ek" => Some(MitmMode::Ek),
            "replay" => Some(MitmMode::Replay),
            _ => None,
        }
    }
}

/// Relay-chosen substitutes (fixed so a failure is easy to recognise).
pub(crate) const RELAY_AK: [u8; 32] = [0x99; 32];
pub(crate) const RELAY_EK_I: [u8; 32] = [0x9a; 32];
pub(crate) const RELAY_EK_R: [u8; 32] = [0x9b; 32];

lazy_static::lazy_static! {
    static ref MODE: Option<MitmMode> = std::env::var("RCHAT_MITM")
        .ok()
        .and_then(|v| MitmMode::from_env_value(&v));
    static ref REPLAY: Mutex<ReplayBook> = Mutex::new(ReplayBook::default());
}

pub(crate) fn mode() -> Option<MitmMode> {
    *MODE
}

pub(crate) fn rewrite_ak(msg: &mut ControlMessage, ak: [u8; 32]) -> bool {
    match msg {
        ControlMessage::CircuitCreatedV2 { peer, .. } => {
            peer.identity_agreement_key = ak.to_vec();
            peer.signed_pre_key = ak.to_vec();
            true
        }
        _ => false,
    }
}

pub(crate) fn rewrite_eks(msg: &mut ControlMessage, ek_i: [u8; 32], ek_r: [u8; 32]) -> bool {
    match msg {
        ControlMessage::CircuitCreatedV2 {
            initiator_ephemeral_key,
            responder_ephemeral_key,
            ..
        } => {
            *initiator_ephemeral_key = ek_i.to_vec();
            *responder_ephemeral_key = ek_r.to_vec();
            true
        }
        _ => false,
    }
}

/// Recorded frames per recipient identity (raw identity bytes; test-only).
#[derive(Default)]
pub(crate) struct ReplayBook {
    recorded: HashMap<[u8; 32], ControlMessage>,
    replayed: HashSet<[u8; 32]>,
}

impl ReplayBook {
    /// A genuine frame for `identity`. Records the first; after a replay,
    /// withholds every genuine frame (returns false = drop).
    pub(crate) fn on_frame(&mut self, identity: [u8; 32], msg: &ControlMessage) -> bool {
        if self.replayed.contains(&identity) {
            return false;
        }
        self.recorded.entry(identity).or_insert_with(|| msg.clone());
        true
    }

    /// `identity` proved itself on a (new) connection: the frame to replay,
    /// at most once.
    pub(crate) fn on_publish(&mut self, identity: [u8; 32]) -> Option<ControlMessage> {
        if self.replayed.contains(&identity) {
            return None;
        }
        let msg = self.recorded.get(&identity).cloned()?;
        self.replayed.insert(identity);
        Some(msg)
    }
}

fn recipient_identity(to: ClientId, state: &RelayState) -> Option<[u8; 32]> {
    state.connections.get(&to).and_then(|c| c.proven_identity)
}

/// Tamper with an outgoing `CircuitCreatedV2`. Returns false to drop it.
pub(crate) fn mitm_rewrite(to: ClientId, msg: &mut ControlMessage, state: &RelayState) -> bool {
    match mode() {
        None => true,
        Some(MitmMode::Ak) => {
            if rewrite_ak(msg, RELAY_AK) {
                note_rewrite();
            }
            true
        }
        Some(MitmMode::Ek) => {
            if rewrite_eks(msg, RELAY_EK_I, RELAY_EK_R) {
                note_rewrite();
            }
            true
        }
        Some(MitmMode::Replay) => match recipient_identity(to, state) {
            Some(id) => REPLAY.lock().on_frame(id, msg),
            None => true,
        },
    }
}

/// The E5 script's positive evidence that a tampered frame went out (Task
/// 25 minor). Fixed wording, nothing about the frame.
fn note_rewrite() {
    tracing::warn!("TEST-MITM: rewrote a CircuitCreatedV2");
}

/// After a successful publish: in `replay` mode, resend the recorded frame.
pub(crate) fn mitm_after_publish(to: ClientId, identity: [u8; 32], state: &RelayState) {
    if mode() != Some(MitmMode::Replay) {
        return;
    }
    let Some(msg) = REPLAY.lock().on_publish(identity) else {
        return;
    };
    if let Some(conn) = state.connections.get(&to) {
        let _ = conn.ws_tx.send(UnifiedFrame::control(msg).encode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::unified::PeerBundle;
    use crate::protocol::CircuitId;
    use rchat_core::crypto::IdentityKeyPair;
    use rchat_core::keyauth::{golden, sign_bundle, verify_bundle, SignedBundle};

    fn frame() -> ControlMessage {
        let id = IdentityKeyPair::from_seed(&golden::seed_a()).unwrap();
        let b = sign_bundle(&id).unwrap();
        ControlMessage::CircuitCreatedV2 {
            circuit_id: CircuitId([1; 16]),
            token: vec![7; 32],
            target_circuit_id: CircuitId([2; 16]),
            role: 0,
            peer: PeerBundle {
                identity_key: b.identity_key.to_vec(),
                identity_agreement_key: b.identity_agreement_key.to_vec(),
                signed_pre_key: b.signed_pre_key.to_vec(),
                bundle_signature: b.bundle_signature.to_vec(),
            },
            initiator_ephemeral_key: vec![0x11; 32],
            responder_ephemeral_key: vec![0x22; 32],
        }
    }

    fn bundle_of(msg: &ControlMessage) -> SignedBundle {
        match msg {
            ControlMessage::CircuitCreatedV2 { peer, .. } => SignedBundle::from_slices(
                &peer.identity_key,
                &peer.identity_agreement_key,
                &peer.signed_pre_key,
                &peer.bundle_signature,
            )
            .unwrap(),
            _ => panic!("not CircuitCreatedV2"),
        }
    }

    #[test]
    fn mitm_mode_parses_only_known_values() {
        assert_eq!(MitmMode::from_env_value("ak"), Some(MitmMode::Ak));
        assert_eq!(MitmMode::from_env_value("ek"), Some(MitmMode::Ek));
        assert_eq!(MitmMode::from_env_value("replay"), Some(MitmMode::Replay));
        assert_eq!(MitmMode::from_env_value("AK"), None);
        assert_eq!(MitmMode::from_env_value(""), None);
    }

    /// E5 (ak): the substituted bundle no longer verifies, so a client sees
    /// a bad signature (transient, code 3) and never runs X3DH with it.
    #[test]
    fn mitm_ak_substitution_breaks_the_bundle_signature() {
        let mut msg = frame();
        verify_bundle(&bundle_of(&msg)).expect("genuine bundle verifies");
        assert!(rewrite_ak(&mut msg, RELAY_AK));
        let b = bundle_of(&msg);
        assert_eq!(b.identity_agreement_key, RELAY_AK);
        assert_eq!(b.signed_pre_key, RELAY_AK);
        assert!(verify_bundle(&b).is_err());
    }

    /// E5 (ek): both echoed ephemeral keys are relay-chosen, so neither
    /// side's echo check against its own outstanding asks can pass.
    #[test]
    fn mitm_ek_substitution_replaces_both_echoes() {
        let mut msg = frame();
        assert!(rewrite_eks(&mut msg, RELAY_EK_I, RELAY_EK_R));
        match msg {
            ControlMessage::CircuitCreatedV2 {
                initiator_ephemeral_key,
                responder_ephemeral_key,
                ..
            } => {
                assert_eq!(initiator_ephemeral_key, RELAY_EK_I.to_vec());
                assert_eq!(responder_ephemeral_key, RELAY_EK_R.to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn mitm_rewrites_ignore_other_frames() {
        let mut other = ControlMessage::QueuedMessage { payload: vec![1] };
        assert!(!rewrite_ak(&mut other, RELAY_AK));
        assert!(!rewrite_eks(&mut other, RELAY_EK_I, RELAY_EK_R));
    }

    /// E5 (replay): the first genuine frame is recorded and passed; after the
    /// identity proves itself on a new connection the recorded frame is
    /// replayed exactly once and later genuine frames are withheld, so the
    /// replay is the only frame that client could act on.
    #[test]
    fn mitm_replay_book_replays_once_then_withholds_genuine_frames() {
        let mut book = ReplayBook::default();
        let id = [0xAA; 32];
        assert!(book.on_publish(id).is_none(), "nothing recorded yet");
        assert!(book.on_frame(id, &frame()));
        assert!(
            book.on_frame(id, &frame()),
            "later genuine frames pass before a replay"
        );
        let replayed = book.on_publish(id).expect("recorded frame is replayed");
        assert!(matches!(replayed, ControlMessage::CircuitCreatedV2 { .. }));
        assert!(book.on_publish(id).is_none(), "replayed once");
        assert!(
            !book.on_frame(id, &frame()),
            "genuine frames withheld after the replay"
        );
        assert!(
            book.on_frame([0xBB; 32], &frame()),
            "other identities unaffected"
        );
    }
}
