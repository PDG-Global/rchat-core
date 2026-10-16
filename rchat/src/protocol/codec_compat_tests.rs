//! C1: the relay and rchat-core encode protocol v3 identically. Each frame
//! is built with one crate, decoded with the other, and re-encoded.

use super::signaling::{PublishKeyBundlePayload, SignalingMessage as ServerSignaling};
use super::unified::{ControlMessage as ServerControl, PeerBundle as ServerPeerBundle};
use super::CircuitId as ServerCircuitId;
use rchat_core::crypto::IdentityKeyPair;
use rchat_core::keyauth::{self, golden};
use rchat_core::protocol::{
    signaling_frame as core_signaling_frame, CircuitId as CoreCircuitId,
    ControlMessage as CoreControl, PeerBundle as CorePeerBundle, SignalingMessage as CoreSignaling,
};

fn core_peer() -> CorePeerBundle {
    CorePeerBundle {
        identity_key: vec![0x11; 32],
        identity_agreement_key: vec![0x22; 32],
        kem_pk: vec![0x33; 1184],
        bundle_signature: vec![0x44; 64],
    }
}

fn server_peer() -> ServerPeerBundle {
    ServerPeerBundle {
        identity_key: vec![0x11; 32],
        identity_agreement_key: vec![0x22; 32],
        kem_pk: vec![0x33; 1184],
        bundle_signature: vec![0x44; 64],
    }
}

#[test]
fn c1_circuit_created_v3_server_to_core() {
    let server = ServerControl::CircuitCreatedV3 {
        circuit_id: ServerCircuitId([1; 16]),
        token: vec![7; 32],
        target_circuit_id: ServerCircuitId([2; 16]),
        role: 1,
        peer: server_peer(),
        initiator_ephemeral_key: vec![0x55; 32],
        responder_ephemeral_key: vec![0x66; 32],
        initiator_kem_ephemeral_pk: vec![0x57; 1184],
        responder_kem_ephemeral_pk: vec![0x67; 1184],
        initiator_ephemeral_sig: vec![0x5f; 64],
        responder_ephemeral_sig: vec![0x6f; 64],
    };
    let bytes = server.encode();
    let core = CoreControl::decode_without_frame_type(&bytes).expect("core decodes");
    match &core {
        CoreControl::CircuitCreatedV3 {
            circuit_id,
            token,
            target_circuit_id,
            role,
            peer,
            initiator_ephemeral_key,
            responder_ephemeral_key,
            initiator_kem_ephemeral_pk,
            responder_kem_ephemeral_pk,
            initiator_ephemeral_sig,
            responder_ephemeral_sig,
        } => {
            assert_eq!(initiator_ephemeral_sig, &vec![0x5f; 64]);
            assert_eq!(responder_ephemeral_sig, &vec![0x6f; 64]);
            assert_eq!(circuit_id, &CoreCircuitId([1; 16]));
            assert_eq!(token, &vec![7; 32]);
            assert_eq!(target_circuit_id, &CoreCircuitId([2; 16]));
            assert_eq!(*role, 1);
            assert_eq!(peer, &core_peer());
            assert_eq!(initiator_ephemeral_key, &vec![0x55; 32]);
            assert_eq!(responder_ephemeral_key, &vec![0x66; 32]);
            assert_eq!(initiator_kem_ephemeral_pk, &vec![0x57; 1184]);
            assert_eq!(responder_kem_ephemeral_pk, &vec![0x67; 1184]);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    assert_eq!(core.encode(), bytes, "core re-encodes byte for byte");
}

#[test]
fn c1_queued_message_both_directions() {
    let server = ServerControl::QueuedMessage {
        payload: vec![0x02; 300],
    };
    let core = CoreControl::decode_without_frame_type(&server.encode()).unwrap();
    assert!(matches!(&core, CoreControl::QueuedMessage { payload } if payload == &vec![0x02; 300]));
    let back = ServerControl::decode(&core.encode()).unwrap();
    assert_eq!(back.encode(), server.encode());
}

#[test]
fn c1_circuit_ask_core_to_server_with_and_without_resume() {
    for resume in [None, Some(CoreCircuitId([9; 16]))] {
        let core = CoreControl::CircuitAsk {
            target_identity: vec![3; 32],
            ephemeral_key: vec![4; 32],
            kem_ephemeral_pk: vec![5; 1184],
            ephemeral_sig: vec![0x5e; 64],
            knock: vec![crate::validate::KNOCK_VERSION; crate::validate::KNOCK_BYTES],
            resume_circuit: resume.clone(),
        };
        let bytes = core.encode();
        let server = ServerControl::decode(&bytes).expect("server decodes");
        match &server {
            ServerControl::CircuitAsk {
                target_identity,
                ephemeral_key,
                kem_ephemeral_pk,
                ephemeral_sig,
                knock,
                resume_circuit,
            } => {
                assert_eq!(ephemeral_sig, &vec![0x5e; 64]);
                assert_eq!(target_identity, &vec![3; 32]);
                assert_eq!(ephemeral_key, &vec![4; 32]);
                assert_eq!(kem_ephemeral_pk, &vec![5; 1184]);
                assert_eq!(knock.len(), crate::validate::KNOCK_BYTES);
                assert_eq!(
                    resume_circuit.map(|c| c.0),
                    resume.as_ref().map(|c| c.0),
                    "resume_circuit survives"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(server.encode(), bytes, "server re-encodes byte for byte");
    }
}

/// v3 §C.2: CircuitAskBlind from the core decodes on the relay and
/// re-encodes byte for byte; the reserved error code `NotImplemented` (9)
/// decodes on the core.
#[test]
fn c1_circuit_ask_blind_core_to_server_and_not_implemented_back() {
    let core = CoreControl::CircuitAskBlind {
        pair_token: vec![0xB1; 32],
        ephemeral_key: vec![0xB2; 32],
        kem_ephemeral_pk: vec![0xB3; 1184],
        ephemeral_sig: vec![0x5e; 64],
        pad: vec![0; rchat_core::protocol::BLIND_PAD_LEN],
    };
    let bytes = core.encode();
    let server = ServerControl::decode(&bytes).expect("server decodes");
    assert!(matches!(
        &server,
        ServerControl::CircuitAskBlind { pair_token, ephemeral_key, kem_ephemeral_pk, ephemeral_sig, pad }
            if pair_token == &vec![0xB1; 32]
                && ephemeral_sig == &vec![0x5e; 64]
                && ephemeral_key == &vec![0xB2; 32]
                && kem_ephemeral_pk == &vec![0xB3; 1184]
                && pad.len() == crate::validate::BLIND_PAD_LEN
    ));
    assert_eq!(server.encode(), bytes);
    crate::validate::control(&server).expect("a well-formed blinded ask validates");

    let err = ServerControl::Error {
        code: super::unified::ControlErrorCode::NotImplemented,
        message: "x".into(),
    };
    match CoreControl::decode_without_frame_type(&err.encode()) {
        Some(CoreControl::Error { code, .. }) => {
            assert_eq!(code, rchat_core::protocol::ControlErrorCode::NotImplemented)
        }
        other => panic!("decoded {other:?}"),
    }
}

/// Ruling R22: the typed `PairTokenBusy` (variant 17) carries the refused
/// ask's X25519 ephemeral, and both crates encode it identically.
#[test]
fn c2b_typed_pair_token_busy_both_ways() {
    let server = ServerControl::PairTokenBusy {
        ephemeral_key: vec![0xE7; 32],
    };
    let bytes = server.encode();
    assert_eq!(bytes[..4], 17u32.to_le_bytes());
    match CoreControl::decode_without_frame_type(&bytes) {
        Some(CoreControl::PairTokenBusy { ephemeral_key }) => {
            assert_eq!(ephemeral_key, vec![0xE7; 32])
        }
        other => panic!("decoded {other:?}"),
    }
    let core = CoreControl::PairTokenBusy {
        ephemeral_key: vec![0xE7; 32],
    };
    let core_bytes = core.encode();
    assert_eq!(core_bytes, bytes, "identical encodings");
    match ServerControl::decode(&core_bytes) {
        Ok(ServerControl::PairTokenBusy { ephemeral_key }) => {
            assert_eq!(ephemeral_key, vec![0xE7; 32])
        }
        other => panic!("decoded {other:?}"),
    }
}

/// v3 §C.2: `PairTokenBusy` (10), the relay's answer to a third blinded ask
/// on a token, decodes on the core as the same code, and every relay error
/// code maps to the core code with the same number.
#[test]
fn c2_pair_token_busy_server_to_core() {
    use super::unified::ControlErrorCode as S;
    use rchat_core::protocol::ControlErrorCode as C;
    let err = ServerControl::Error {
        code: S::PairTokenBusy,
        message: "x".into(),
    };
    assert_eq!(err.encode()[4..8], 10u32.to_le_bytes());
    match CoreControl::decode_without_frame_type(&err.encode()) {
        Some(CoreControl::Error { code, .. }) => assert_eq!(code, C::PairTokenBusy),
        other => panic!("decoded {other:?}"),
    }
    let pairs = [
        (S::InvalidMessage, C::InvalidMessage),
        (S::UnsupportedVersion, C::UnsupportedVersion),
        (S::RateLimited, C::RateLimited),
        (S::CircuitNotFound, C::CircuitNotFound),
        (S::CircuitExists, C::CircuitExists),
        (S::AuthenticationFailed, C::AuthenticationFailed),
        (S::TargetOffline, C::TargetOffline),
        (S::TargetNotFound, C::TargetNotFound),
        (S::InternalError, C::InternalError),
        (S::NotImplemented, C::NotImplemented),
        (S::PairTokenBusy, C::PairTokenBusy),
    ];
    for (s, c) in pairs {
        assert_eq!(s as u8, c.to_u8(), "{s:?} and {c:?} share a number");
        let bytes = ServerControl::Error {
            code: s,
            message: String::new(),
        }
        .encode();
        match CoreControl::decode_without_frame_type(&bytes) {
            Some(CoreControl::Error { code, .. }) => assert_eq!(code, c),
            other => panic!("{s:?} decoded {other:?}"),
        }
    }
}

/// v3 §C.2: both crates agree on `ASK_WIRE_LEN` and the blind pad, and a
/// real core identity ask and blinded ask are that long on the relay.
/// The relay's knock size and version byte are the core's (carry-over:
/// checked at compile time, not only when the test runs).
const _: () = assert!(crate::validate::KNOCK_BYTES == rchat_core::sealed::KNOCK_PAYLOAD_LEN);
const _: () = assert!(crate::validate::KNOCK_VERSION == rchat_core::sealed::KNOCK_VERSION);

#[test]
fn c1_ask_wire_len_matches_between_crates() {
    assert_eq!(crate::validate::KNOCK_BYTES, 5120);
    assert_eq!(crate::validate::KNOCK_VERSION, 0x03);
    assert_eq!(
        (
            crate::validate::ASK_WIRE_LEN,
            crate::validate::BLIND_PAD_LEN
        ),
        (
            crate::validate::KNOCK_BYTES + 1373,
            crate::validate::KNOCK_BYTES + 17
        )
    );
    assert_eq!(
        crate::validate::ASK_WIRE_LEN,
        rchat_core::protocol::ASK_WIRE_LEN
    );
    assert_eq!(
        crate::validate::BLIND_PAD_LEN,
        rchat_core::protocol::BLIND_PAD_LEN
    );
    assert_eq!(
        crate::validate::KNOCK_BYTES,
        rchat_core::sealed::KNOCK_PAYLOAD_LEN
    );
    assert_eq!(crate::validate::KEM_PK_BYTES, rchat_core::kem::KEM_PK_LEN);
    let ask = CoreControl::CircuitAsk {
        target_identity: vec![3; 32],
        ephemeral_key: vec![4; 32],
        kem_ephemeral_pk: vec![5; 1184],
        ephemeral_sig: vec![0x5e; 64],
        knock: vec![crate::validate::KNOCK_VERSION; crate::validate::KNOCK_BYTES],
        resume_circuit: Some(CoreCircuitId([0; 16])),
    };
    let blind = CoreControl::CircuitAskBlind {
        pair_token: vec![1; 32],
        ephemeral_key: vec![2; 32],
        kem_ephemeral_pk: vec![3; 1184],
        ephemeral_sig: vec![0x5e; 64],
        pad: vec![0; crate::validate::BLIND_PAD_LEN],
    };
    for m in [ask, blind] {
        let bytes = m.encode();
        assert_eq!(bytes.len(), crate::validate::ASK_WIRE_LEN);
        assert_eq!(
            ServerControl::decode(&bytes).unwrap().encode().len(),
            crate::validate::ASK_WIRE_LEN
        );
    }
}

#[test]
fn c1_core_publish_json_parses_on_the_server_with_conn_signature() {
    let identity = IdentityKeyPair::from_seed(&golden::seed_a()).unwrap();
    let bundle = keyauth::sign_bundle(&identity).unwrap();
    let conn_sig =
        keyauth::sign_conn(&identity, &golden::NONCE, &golden::BINDING, &bundle).unwrap();
    // Exactly the bytes the core puts on the wire: 0x01 || JSON.
    let frame =
        core_signaling_frame(&CoreSignaling::publish_key_bundle(&bundle, &conn_sig)).unwrap();
    assert_eq!(frame[0], 0x01, "signaling frame type");
    let msg: ServerSignaling =
        serde_json::from_slice(&frame[1..]).expect("server parses core JSON");
    let p: PublishKeyBundlePayload = msg.payload.deserialize_data().expect("payload");
    assert_eq!(p.key_bundle.identity_key, hex::encode(bundle.identity_key));
    assert_eq!(
        p.key_bundle.identity_agreement_key,
        hex::encode(bundle.identity_agreement_key)
    );
    assert_eq!(
        crate::validate::decode_kem_pk(&p.key_bundle.kem_pk).as_deref(),
        Some(&bundle.kem_pk[..]),
        "kem_pk is standard base64 of the 1184-byte key"
    );
    assert_eq!(
        p.key_bundle.bundle_signature,
        hex::encode(bundle.bundle_signature)
    );
    assert!(p.key_bundle.one_time_pre_keys.is_empty());
    assert_eq!(p.conn_signature, hex::encode(conn_sig));
    crate::validate::signaling(&msg).expect("core's publish passes the relay validator");
}

/// Every truncation of `CircuitCreatedV3`, `CircuitAsk`, `CircuitAskBlind`
/// and `QueuedMessage` is refused by both crates, without a panic.
#[test]
fn c1_truncated_v3_frames_are_refused_by_both_crates() {
    let frames = [
        ServerControl::CircuitCreatedV3 {
            circuit_id: ServerCircuitId([1; 16]),
            token: vec![7; 32],
            target_circuit_id: ServerCircuitId([2; 16]),
            role: 1,
            peer: server_peer(),
            initiator_ephemeral_key: vec![0x55; 32],
            responder_ephemeral_key: vec![0x66; 32],
            initiator_kem_ephemeral_pk: vec![0x57; 40],
            responder_kem_ephemeral_pk: vec![0x67; 40],
            initiator_ephemeral_sig: vec![0x5f; 64],
            responder_ephemeral_sig: vec![0x6f; 64],
        },
        ServerControl::CircuitAsk {
            target_identity: vec![0x11; 32],
            ephemeral_key: vec![0x22; 32],
            kem_ephemeral_pk: vec![0x23; 40],
            ephemeral_sig: vec![0x5e; 64],
            knock: vec![0x33; 64],
            resume_circuit: Some(ServerCircuitId([3; 16])),
        },
        ServerControl::CircuitAskBlind {
            pair_token: vec![0x12; 32],
            ephemeral_key: vec![0x22; 32],
            kem_ephemeral_pk: vec![0x23; 40],
            ephemeral_sig: vec![0x5e; 64],
            pad: vec![0; 24],
        },
        ServerControl::QueuedMessage {
            payload: vec![0x44; 40],
        },
    ];
    for frame in frames {
        let bytes = frame.encode();
        assert!(ServerControl::decode(&bytes).is_ok());
        assert!(CoreControl::decode_without_frame_type(&bytes).is_some());
        for len in 0..bytes.len() {
            let cut = &bytes[..len];
            assert!(
                ServerControl::decode(cut).is_err(),
                "relay: {frame:?} cut at {len}"
            );
            assert!(
                CoreControl::decode_without_frame_type(cut).is_none(),
                "core: {frame:?} cut at {len}"
            );
        }
    }
}

/// R34a: `QueueHandedOver` (variant 18) is encoded identically by both
/// crates, with one fixed size and nothing but zeros in it.
#[test]
fn c2c_queue_handed_over_both_ways() {
    let server = ServerControl::QueueHandedOver {
        pad: vec![0; super::unified::QUEUE_HANDED_OVER_PAD_LEN],
    };
    let bytes = server.encode();
    assert_eq!(bytes[..4], 18u32.to_le_bytes());
    let core = CoreControl::QueueHandedOver {
        pad: vec![0; rchat_core::protocol::QUEUE_HANDED_OVER_PAD_LEN],
    };
    assert_eq!(core.encode(), bytes, "identical encodings");
    assert!(matches!(
        CoreControl::decode_without_frame_type(&bytes),
        Some(CoreControl::QueueHandedOver { pad }) if pad.iter().all(|b| *b == 0)
    ));
    assert!(matches!(
        ServerControl::decode(&core.encode()),
        Ok(ServerControl::QueueHandedOver { .. })
    ));
}
