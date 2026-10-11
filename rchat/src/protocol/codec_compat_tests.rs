//! C1: the relay and rchat-core encode protocol v2 identically. Each frame
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
        signed_pre_key: vec![0x33; 32],
        bundle_signature: vec![0x44; 64],
    }
}

fn server_peer() -> ServerPeerBundle {
    ServerPeerBundle {
        identity_key: vec![0x11; 32],
        identity_agreement_key: vec![0x22; 32],
        signed_pre_key: vec![0x33; 32],
        bundle_signature: vec![0x44; 64],
    }
}

#[test]
fn c1_circuit_created_v2_server_to_core() {
    let server = ServerControl::CircuitCreatedV2 {
        circuit_id: ServerCircuitId([1; 16]),
        token: vec![7; 32],
        target_circuit_id: ServerCircuitId([2; 16]),
        role: 1,
        peer: server_peer(),
        initiator_ephemeral_key: vec![0x55; 32],
        responder_ephemeral_key: vec![0x66; 32],
    };
    let bytes = server.encode();
    let core = CoreControl::decode_without_frame_type(&bytes).expect("core decodes");
    match &core {
        CoreControl::CircuitCreatedV2 {
            circuit_id,
            token,
            target_circuit_id,
            role,
            peer,
            initiator_ephemeral_key,
            responder_ephemeral_key,
        } => {
            assert_eq!(circuit_id, &CoreCircuitId([1; 16]));
            assert_eq!(token, &vec![7; 32]);
            assert_eq!(target_circuit_id, &CoreCircuitId([2; 16]));
            assert_eq!(*role, 1);
            assert_eq!(peer, &core_peer());
            assert_eq!(initiator_ephemeral_key, &vec![0x55; 32]);
            assert_eq!(responder_ephemeral_key, &vec![0x66; 32]);
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
            knock: vec![0x02; 2048],
            resume_circuit: resume.clone(),
        };
        let bytes = core.encode();
        let server = ServerControl::decode(&bytes).expect("server decodes");
        match &server {
            ServerControl::CircuitAsk {
                target_identity,
                ephemeral_key,
                knock,
                resume_circuit,
            } => {
                assert_eq!(target_identity, &vec![3; 32]);
                assert_eq!(ephemeral_key, &vec![4; 32]);
                assert_eq!(knock.len(), 2048);
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
        p.key_bundle.signed_pre_key,
        hex::encode(bundle.signed_pre_key)
    );
    assert_eq!(
        p.key_bundle.signed_pre_key_signature,
        hex::encode(bundle.bundle_signature)
    );
    assert!(p.key_bundle.one_time_pre_keys.is_empty());
    assert_eq!(p.conn_signature, hex::encode(conn_sig));
    crate::validate::signaling(&msg).expect("core's publish passes the relay validator");
}

/// Task 2 minor: every truncation of `CircuitCreatedV2`, `CircuitAsk` and
/// `QueuedMessage` is refused by both crates, without a panic.
#[test]
fn c1_truncated_v2_frames_are_refused_by_both_crates() {
    let frames = [
        ServerControl::CircuitCreatedV2 {
            circuit_id: ServerCircuitId([1; 16]),
            token: vec![7; 32],
            target_circuit_id: ServerCircuitId([2; 16]),
            role: 1,
            peer: server_peer(),
            initiator_ephemeral_key: vec![0x55; 32],
            responder_ephemeral_key: vec![0x66; 32],
        },
        ServerControl::CircuitAsk {
            target_identity: vec![0x11; 32],
            ephemeral_key: vec![0x22; 32],
            knock: vec![0x33; 64],
            resume_circuit: Some(ServerCircuitId([3; 16])),
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
