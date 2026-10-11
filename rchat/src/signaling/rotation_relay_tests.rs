//! KR10 (D21): the relay keeps no link between a rotated identity and its
//! successor. Rotation data in a publish is ignored.

use super::test_support::*;
use super::*;
use crate::protocol::unified::UnifiedFrame;
use futures_util::SinkExt;
use rchat_core::keyauth;
use rchat_core::rotation::sign_link;

fn publish_with_extra_rotation(
    id: &TestIdentity,
    nonce: &[u8; 32],
    link_hex: String,
) -> tokio_tungstenite::tungstenite::Message {
    let sig = keyauth::sign_conn(&id.keys, nonce, &dev_binding(), &id.bundle).expect("conn sig");
    let mut data = serde_json::json!({
        "key_bundle": key_bundle_of(id),
        "conn_signature": hex::encode(sig),
    });
    data["rotation"] = serde_json::json!({ "links": [link_hex] });
    UnifiedFrame::signaling(SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        SignalingPayload::new(MSG_TYPE_PUBLISH_KEY_BUNDLE, data),
    ))
    .encode()
}

#[tokio::test]
async fn kr10_relay_ignores_rotation_data_and_links_nothing() {
    let (addr, state) = start(test_config()).await;
    let (old, new) = (TestIdentity::from_seed(0x31), TestIdentity::from_seed(0x32));
    queue_test_message(&state, &old, vec![0x02; 300]);
    let link = hex::encode(
        sign_link(&old.keys, &new.bytes, &new.bundle.identity_agreement_key, 1).to_bytes(),
    );
    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    ws.send(publish_with_extra_rotation(&new, &nonce, link))
        .await
        .unwrap();
    let reply = next_signaling(
        &mut ws,
        MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        reply.is_some(),
        "publish succeeds; the extra field is ignored"
    );
    // Nothing reaches the new identity (Task 10c minor): no queued or
    // relayed frame, and no queue of its own.
    let after = frames_until_quiet(&mut ws, Duration::from_millis(300)).await;
    assert!(
        after.is_empty(),
        "nothing relayed to the new identity: {} frames",
        after.len()
    );
    assert_eq!(queued_len(&state, &new), 0, "no queue for the new identity");
    assert_eq!(
        queued_len(&state, &old),
        1,
        "the old identity's queue is not handed over"
    );
}
