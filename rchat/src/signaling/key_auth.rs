//! Publish authentication (spec §4.3). A publish counts only when its
//! bundle is signed by its identity key and the connection proves
//! possession of that key over this connection's nonce and channel
//! binding. Nothing about the connection changes until both checks pass.
//!
//! PRIVACY: nothing here logs. Callers log only content-free reasons.

use super::UnifiedConnection;
use crate::config::ServerConfig;
use crate::limits::ConnTx;
use crate::metrics;
use crate::protocol::signaling::{
    ErrorPayload, KeyBundle, Payload, PublishKeyBundlePayload, SignalingMessage, MSG_TYPE_ERROR,
};
use crate::protocol::unified::{PeerBundle, UnifiedFrame};
use crate::protocol::ErrorCode;
use rchat_core::keyauth::{self, SignedBundle};
use tokio_tungstenite::tungstenite::Message;

/// A publish that passed every check.
pub(super) struct VerifiedPublish {
    pub identity: [u8; 32],
    pub bundle: SignedBundle,
}

/// Why a publish was refused (never sent to the client in detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublishRejection {
    /// No v2 hello on this connection, or no unused nonce.
    NoChallenge,
    /// The connection is already proven as another identity (R7).
    IdentitySwitch,
    /// Malformed, weak or wrongly signed bundle.
    BadBundle,
    /// Connection proof does not verify (wrong key, nonce or binding).
    BadProof,
}

/// Run every check without touching any state.
pub(super) fn verify_publish(
    conn: &UnifiedConnection,
    payload: &PublishKeyBundlePayload,
) -> Result<VerifiedPublish, PublishRejection> {
    if conn.protocol_version != 2 {
        return Err(PublishRejection::NoChallenge);
    }
    let nonce = conn.auth_nonce.ok_or(PublishRejection::NoChallenge)?;
    let kb = &payload.key_bundle;
    let decode = |s: &str| hex::decode(s).map_err(|_| PublishRejection::BadBundle);
    let bundle = SignedBundle::from_slices(
        &decode(&kb.identity_key)?,
        &decode(&kb.identity_agreement_key)?,
        &decode(&kb.signed_pre_key)?,
        &decode(&kb.signed_pre_key_signature)?,
    )
    .map_err(|_| PublishRejection::BadBundle)?;
    if let Some(proven) = conn.proven_identity {
        if proven != bundle.identity_key {
            return Err(PublishRejection::IdentitySwitch);
        }
    }
    // v2: the signed pre-key IS the identity agreement key (spec §4.1, F7).
    // A bundle that names a different SPK is refused even if validly signed.
    if bundle.signed_pre_key != bundle.identity_agreement_key {
        return Err(PublishRejection::BadBundle);
    }
    // Order matters: the bundle signature is checked before the connection
    // proof, which is only meaningful over a verified bundle.
    keyauth::verify_bundle(&bundle).map_err(|_| PublishRejection::BadBundle)?;
    let sig = hex::decode(&payload.conn_signature).map_err(|_| PublishRejection::BadProof)?;
    keyauth::verify_conn(&nonce, &conn.channel_binding, &bundle, &sig)
        .map_err(|_| PublishRejection::BadProof)?;
    Ok(VerifiedPublish {
        identity: bundle.identity_key,
        bundle,
    })
}

/// A fresh 32-byte nonce.
pub(super) fn new_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS randomness unavailable");
    nonce
}

/// `knock_ttl_hours` announced in `hello_response`: the knock lifetime
/// (queue TTL capped at 72 h), in whole hours.
pub(super) fn knock_ttl_hours(config: &ServerConfig) -> u32 {
    (config.knock_ttl_secs() / 3_600) as u32
}

/// The stored (hex) form of a verified bundle.
pub(super) fn key_bundle_hex(b: &SignedBundle) -> KeyBundle {
    KeyBundle {
        identity_key: hex::encode(b.identity_key),
        identity_agreement_key: hex::encode(b.identity_agreement_key),
        signed_pre_key: hex::encode(b.signed_pre_key),
        signed_pre_key_signature: hex::encode(b.bundle_signature),
        one_time_pre_keys: Vec::new(),
    }
}

/// A signaling `error` with a fixed, content-free message.
pub(super) fn error_signal(code: ErrorCode, message: &str) -> SignalingMessage {
    SignalingMessage::new(
        MSG_TYPE_ERROR,
        Payload::new(
            MSG_TYPE_ERROR,
            ErrorPayload {
                code,
                message: message.to_string(),
                request_id: None,
            },
        ),
    )
}

/// Refuse a publish (spec §4.3): count it, burn the nonce, mark the
/// connection closing (its read loop handles nothing further), and queue a
/// content-free `AuthenticationFailed` error followed by a Close. Nothing
/// else about the connection or the relay changes.
pub(super) fn refuse_publish(conn: &mut UnifiedConnection) {
    refuse_with(conn, "key authentication failed");
}

/// Like `refuse_publish`, with a distinct message when the connection proof
/// itself failed: almost always a TLS-terminating proxy in front of the relay,
/// whose exporter the client signed instead of ours.
pub(super) fn refuse_publish_for(conn: &mut UnifiedConnection, why: PublishRejection) {
    if why == PublishRejection::BadProof {
        refuse_with(
            conn,
            "connection proof does not match this TLS session (TLS must terminate at the relay)",
        );
    } else {
        refuse_publish(conn);
    }
}

/// The one refusal path (Task 10b minor: was duplicated): counted, the
/// connection closing, its challenge spent, then a fixed message and Close.
fn refuse_with(conn: &mut UnifiedConnection, message: &'static str) {
    metrics::reject(metrics::REJECT_KEY_AUTH);
    conn.closing = true;
    conn.auth_nonce = None;
    let reply = error_signal(ErrorCode::AuthenticationFailed, message);
    close_with_error(&conn.ws_tx, UnifiedFrame::signaling(reply).encode());
}

/// Queue `frame`, then a WebSocket Close. The connection's writer stops
/// after writing a Close frame, which ends the connection, so the error is
/// delivered before the socket goes.
pub(super) fn close_with_error(tx: &ConnTx, frame: Message) {
    let _ = tx.send(frame);
    let _ = tx.send(Message::Close(None));
}

/// R5: the only way the relay builds a `PeerBundle` — from a bundle that
/// passed `verify_bundle` at publish.
pub(super) fn peer_bundle(b: &SignedBundle) -> PeerBundle {
    PeerBundle {
        identity_key: b.identity_key.to_vec(),
        identity_agreement_key: b.identity_agreement_key.to_vec(),
        signed_pre_key: b.signed_pre_key.to_vec(),
        bundle_signature: b.bundle_signature.to_vec(),
    }
}

/// The bundle a proven connection published (stored only after it
/// verified). `None` for an unproven connection.
pub(super) fn proven_bundle(conn: &UnifiedConnection) -> Option<SignedBundle> {
    let identity = conn.proven_identity?;
    let kb = conn.key_bundle.as_ref()?;
    let d = |s: &str| hex::decode(s).ok();
    let bundle = SignedBundle::from_slices(
        &d(&kb.identity_key)?,
        &d(&kb.identity_agreement_key)?,
        &d(&kb.signed_pre_key)?,
        &d(&kb.signed_pre_key_signature)?,
    )
    .ok()?;
    (bundle.identity_key == identity).then_some(bundle)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{bare_connection, key_bundle_of, TestIdentity};
    use super::*;

    const BINDING: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 32] = [0x4e; 32];

    fn payload(id: &TestIdentity, nonce: &[u8; 32], binding: &[u8; 32]) -> PublishKeyBundlePayload {
        let sig = keyauth::sign_conn(&id.keys, nonce, binding, &id.bundle).unwrap();
        PublishKeyBundlePayload {
            key_bundle: key_bundle_of(id),
            conn_signature: hex::encode(sig),
        }
    }

    fn challenged() -> UnifiedConnection {
        let (mut conn, _rx) = bare_connection(BINDING);
        conn.protocol_version = 2;
        conn.auth_nonce = Some(NONCE);
        conn
    }

    #[test]
    fn a_proper_publish_verifies() {
        let id = TestIdentity::from_seed(1);
        let v = verify_publish(&challenged(), &payload(&id, &NONCE, &BINDING)).unwrap();
        assert_eq!(v.identity, id.bytes);
        assert_eq!(v.bundle, id.bundle);
    }

    #[test]
    fn no_hello_or_no_nonce_is_refused() {
        let id = TestIdentity::from_seed(1);
        let (conn, _rx) = bare_connection(BINDING);
        assert_eq!(
            verify_publish(&conn, &payload(&id, &NONCE, &BINDING)).err(),
            Some(PublishRejection::NoChallenge)
        );
        let mut conn = challenged();
        conn.auth_nonce = None;
        assert_eq!(
            verify_publish(&conn, &payload(&id, &NONCE, &BINDING)).err(),
            Some(PublishRejection::NoChallenge)
        );
    }

    #[test]
    fn wrong_nonce_or_binding_is_refused() {
        let id = TestIdentity::from_seed(1);
        for p in [
            payload(&id, &[0x01; 32], &BINDING),
            payload(&id, &NONCE, &[0x02; 32]),
        ] {
            assert_eq!(
                verify_publish(&challenged(), &p).err(),
                Some(PublishRejection::BadProof)
            );
        }
    }

    #[test]
    fn tampered_bundle_is_refused() {
        let id = TestIdentity::from_seed(1);
        let mut p = payload(&id, &NONCE, &BINDING);
        p.key_bundle.identity_agreement_key = hex::encode([0x09; 32]);
        assert_eq!(
            verify_publish(&challenged(), &p).err(),
            Some(PublishRejection::BadBundle)
        );
    }

    #[test]
    fn a_validly_signed_bundle_with_a_distinct_signed_pre_key_is_refused() {
        use ed25519_dalek::{Signer, SigningKey};
        let id = TestIdentity::from_seed(1);
        let other_spk = TestIdentity::from_seed(2).bundle.identity_agreement_key;
        let t = keyauth::bundle_transcript(
            &id.bundle.identity_key,
            &id.bundle.identity_agreement_key,
            &other_spk,
        )
        .unwrap();
        let seed = id.keys.seed_bytes();
        let signer = SigningKey::from_bytes(&seed[..32].try_into().unwrap());
        let bundle = SignedBundle {
            signed_pre_key: other_spk,
            bundle_signature: signer.sign(&t).to_bytes(),
            ..id.bundle.clone()
        };
        keyauth::verify_bundle(&bundle).expect("the signature itself is valid");
        let sig = keyauth::sign_conn(&id.keys, &NONCE, &BINDING, &bundle).unwrap();
        let p = PublishKeyBundlePayload {
            key_bundle: key_bundle_hex(&bundle),
            conn_signature: hex::encode(sig),
        };
        assert_eq!(
            verify_publish(&challenged(), &p).err(),
            Some(PublishRejection::BadBundle)
        );
    }

    #[test]
    fn a_proven_connection_cannot_switch_identity() {
        let x = TestIdentity::from_seed(1);
        let y = TestIdentity::from_seed(2);
        let mut conn = challenged();
        conn.proven_identity = Some(x.bytes);
        assert_eq!(
            verify_publish(&conn, &payload(&y, &NONCE, &BINDING)).err(),
            Some(PublishRejection::IdentitySwitch)
        );
        assert!(verify_publish(&conn, &payload(&x, &NONCE, &BINDING)).is_ok());
    }
}
