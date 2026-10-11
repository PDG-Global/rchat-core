//! Spec §18.6 D34 (ruling F19): a packet for a member that is online but has
//! not resumed its pair goes to that member's live connection, decided under
//! the identity lock and sent after it is released; a failed send is
//! re-queued under the lock. RQ1-RQ4 and the failed-send path (RQ1b); RQ5
//! lives in `log_privacy_tests`.

use super::test_support::*;
use super::*;
use futures_util::{SinkExt, StreamExt};

async fn next_queued(ws: &mut Ws, wait: Duration) -> Option<Vec<u8>> {
    let until = tokio::time::Instant::now() + wait;
    while let Ok(Some(Ok(m))) = tokio::time::timeout_at(until, ws.next()).await {
        if let Ok(UnifiedFrame::Control(ControlMessage::QueuedMessage { payload })) =
            UnifiedFrame::decode(&m)
        {
            return Some(payload);
        }
    }
    None
}

async fn b_gone(state: &RelayState, b: &TestIdentity) {
    let st = state.clone();
    let bb = b.bytes;
    eventually("B gone", move || {
        !st.connections.iter().any(|c| c.proven_identity == Some(bb))
    })
    .await;
}

/// RQ1: B reconnects and publishes without resuming; A's packet goes to
/// B's new connection at once; A is acknowledged; B's queue stays empty.
#[tokio::test]
async fn rq1_online_unresumed_member_gets_packets_live() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x90), TestIdentity::from_seed(0x91));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let mut wb2 = authed(addr, &b).await;
    let payload = vec![0x02; 200];
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload.clone()))
        .await
        .unwrap();
    assert_eq!(
        next_queued(&mut wb2, Duration::from_secs(2)).await,
        Some(payload)
    );
    assert_eq!(queued_len(&state, &b), 0);
    let frames = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(frames
        .iter()
        .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))));
}

/// RQ2: B offline → queued and acknowledged as today.
#[tokio::test]
async fn rq2_offline_member_is_queued() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x92), TestIdentity::from_seed(0x93));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("queued", move || {
        st.message_queues
            .get(&btag)
            .is_some_and(|q| !q.pending.is_empty())
    })
    .await;
}

/// RQ3 (regression guard for the lock): a packet sent by A exactly between
/// B's identity mapping and its queue take is delivered to B once — drained
/// by the publish or forwarded after it — and never left in B's queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rq3_packet_racing_publish_is_never_stranded() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x94), TestIdentity::from_seed(0x95));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let frame = relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    super::tests_hook::set_after_identity_mapped_for(tags::id_tag(&b.bytes), move || {
        let _ = tx.send(()); // tell the sender: B is mapped, its queue not yet taken
        std::thread::sleep(Duration::from_millis(50)); // hold the identity guard while A's packet arrives
    });
    let sender = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || rx.recv().ok())
            .await
            .unwrap();
        wa.send(frame).await.unwrap();
        wa
    });
    let mut wb2 = authed(addr, &b).await;
    let _wa = sender.await.unwrap();
    assert!(
        next_queued(&mut wb2, Duration::from_secs(2))
            .await
            .is_some(),
        "delivered"
    );
    assert!(
        next_queued(&mut wb2, Duration::from_millis(300))
            .await
            .is_none(),
        "exactly once"
    );
    assert_eq!(queued_len(&state, &b), 0, "never stranded");
}

/// RQ4: A sees the same frames whether B is online-unresumed or offline.
#[tokio::test]
async fn rq4_sender_frames_identical() {
    async fn frames(online: bool, seed: u8) -> Vec<(u8, usize)> {
        let (addr, state) = start(test_config()).await;
        let (a, b) = (
            TestIdentity::from_seed(seed),
            TestIdentity::from_seed(seed + 1),
        );
        let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
        drop(wb);
        b_gone(&state, &b).await;
        let _keep = if online {
            Some(authed(addr, &b).await)
        } else {
            None
        };
        wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
            .await
            .unwrap();
        frames_until_quiet(&mut wa, Duration::from_millis(400))
            .await
            .iter()
            .map(|f| (f.frame_type(), f.encode().len()))
            .collect()
    }
    assert_eq!(frames(true, 0xA0).await, frames(false, 0xA2).await);
}

/// The failed-send path: B's "new connection" is mapped but its receiver is
/// gone, so the send fails → the payload is re-queued under the lock, not
/// lost, and A is still acknowledged.
#[tokio::test]
async fn rq1b_failed_forward_requeues() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x96), TestIdentity::from_seed(0x97));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let (_client, rx) = proven_bare(&state, &b, None);
    drop(rx); // the mapped connection can't receive: send_wait fails at once
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("re-queued", move || {
        st.message_queues
            .get(&btag)
            .is_some_and(|q| !q.pending.is_empty())
    })
    .await;
    let frames = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(frames
        .iter()
        .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))));
}

fn has_ack(frames: &[UnifiedFrame]) -> bool {
    frames
        .iter()
        .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. })))
}

fn has_queue_full(frames: &[UnifiedFrame]) -> bool {
    frames.iter().any(|f| {
        matches!(
            f,
            UnifiedFrame::Control(ControlMessage::Error {
                code: ControlErrorCode::RateLimited,
                ..
            })
        )
    })
}

/// RQ3b (the lock guard): the forward has decided "offline" and is about to
/// store when B publishes. Because the decision and the store hold B's
/// identity lock, the publish waits and then drains the packet: it reaches
/// B exactly once and is never left in B's queue. Without the lock the
/// publish takes an empty queue inside that window and the packet is
/// stranded.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn rq3b_publish_racing_the_offline_store_is_never_stranded() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x98), TestIdentity::from_seed(0x99));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    super::tests_hook::set_before_offline_store_for(tags::id_tag(&b.bytes), move || {
        let _ = tx.send(()); // the forward decided "offline" and has not stored yet
        std::thread::sleep(Duration::from_millis(500)); // B's publish runs in this window
    });
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || rx.recv().ok())
        .await
        .unwrap()
        .expect("the forward reached the offline store");
    let mut wb2 = authed(addr, &b).await;
    assert!(
        next_queued(&mut wb2, Duration::from_secs(2))
            .await
            .is_some(),
        "delivered"
    );
    assert!(
        next_queued(&mut wb2, Duration::from_millis(300))
            .await
            .is_none(),
        "exactly once"
    );
    assert_eq!(queued_len(&state, &b), 0, "never stranded");
}

/// RQ1c: the hand-over fails and B's queue has no room: the re-queue is
/// refused, so A gets the queue-full error and no acknowledgement.
#[tokio::test]
async fn rq1c_failed_forward_over_the_caps_is_refused_not_acked() {
    let mut config = test_config();
    config.offline_queue_max_bytes_per_recipient = 600;
    let (addr, state) = start(config).await;
    let (a, b) = (TestIdentity::from_seed(0x9a), TestIdentity::from_seed(0x9b));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    queue_test_message(&state, &b, vec![0x02; 400]); // 464 of 600 bytes
    let (_client, rx) = proven_bare(&state, &b, None);
    drop(rx);
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    let frames = frames_until_quiet(&mut wa, Duration::from_millis(500)).await;
    assert!(has_queue_full(&frames), "queue-full error: {frames:?}");
    assert!(!has_ack(&frames), "never acknowledged");
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("only the earlier message is queued", move || {
        st.message_queues
            .get(&btag)
            .is_some_and(|q| q.pending.len() == 1 && q.pending[0].payload.len() == 400)
    })
    .await;
}

/// RQ1d: the re-queue after a failed hand-over goes through admission
/// (`requeue_salvaged`): the message is charged to B's queue and to the
/// relay-wide offline budget, exactly once, and A is acknowledged.
#[tokio::test]
async fn rq1d_failed_forward_requeue_is_admitted_and_charged() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x9c), TestIdentity::from_seed(0x9d));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let (_client, rx) = proven_bare(&state, &b, None);
    drop(rx);
    let payload = vec![0x02; 200];
    let cost = crate::limits::OfflineBudget::message_cost(payload.len(), 0, 0);
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload.clone()))
        .await
        .unwrap();
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("admitted and charged once", move || {
        st.message_queues.get(&btag).is_some_and(|q| {
            q.pending.len() == 1
                && q.pending[0].payload == payload
                && !q.pending[0].is_knock
                && q.bytes == cost
        }) && st.offline_budget.used() == cost
    })
    .await;
    let frames = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(has_ack(&frames));
    assert!(!has_queue_full(&frames));
}

/// Final review L-2: with B's queue full, A gets the same answer whether B
/// is offline or online without having resumed (the queue-full error, no
/// acknowledgement): a full queue reveals no presence.
#[tokio::test]
async fn rq6_full_queue_answer_is_the_same_online_or_offline() {
    async fn frames(online: bool, seed: u8) -> Vec<(u8, usize)> {
        let mut config = test_config();
        config.offline_queue_max_bytes_per_recipient = 600;
        let (addr, state) = start(config).await;
        let (a, b) = (
            TestIdentity::from_seed(seed),
            TestIdentity::from_seed(seed + 1),
        );
        let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
        drop(wb);
        b_gone(&state, &b).await;
        queue_test_message(&state, &b, vec![0x02; 400]); // 464 of 600 bytes
        let _keep = if online {
            Some(authed(addr, &b).await)
        } else {
            None
        };
        // The publish drained B's queue: fill it again.
        if online {
            queue_test_message(&state, &b, vec![0x02; 400]);
        }
        wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
            .await
            .unwrap();
        let got = frames_until_quiet(&mut wa, Duration::from_millis(400)).await;
        assert!(has_queue_full(&got), "online={online}: {got:?}");
        assert!(!has_ack(&got), "online={online}: never acknowledged");
        got.iter()
            .map(|f| (f.frame_type(), f.encode().len()))
            .collect()
    }
    assert_eq!(frames(true, 0xB0).await, frames(false, 0xB2).await);
}

/// Final review L-2: a hand-over to B's live but stuck connection never
/// stalls A's read loop for `OUTBOUND_SEND_TIMEOUT`: it is re-queued at
/// once and A is acknowledged promptly.
#[tokio::test]
async fn rq7_a_stuck_unresumed_member_never_stalls_the_sender() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0xB4), TestIdentity::from_seed(0xB5));
    let (mut wa, wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    drop(wb);
    b_gone(&state, &b).await;
    let (client, _rx) = proven_bare(&state, &b, None); // never read
    let tx = state.connections.get(&client).unwrap().ws_tx.clone();
    while tx
        .try_send_or_return(tokio_tungstenite::tungstenite::Message::Binary(
            vec![0u8; 64 * 1024],
        ))
        .is_ok()
    {}
    let t0 = tokio::time::Instant::now();
    wa.send(relay_on(ca.target_circuit_id, &ca.token, vec![0x02; 200]))
        .await
        .unwrap();
    let frames = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(has_ack(&frames), "acknowledged: {frames:?}");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "A waited {:?} on B",
        t0.elapsed()
    );
    // Re-queued for B (the drain to the stuck connection may hold it a
    // while, then puts it back): never lost.
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually_within("re-queued for B", Duration::from_secs(15), move || {
        st.message_queues
            .get(&btag)
            .is_some_and(|q| q.pending.iter().any(|m| m.payload == vec![0x02; 200]))
    })
    .await;
}
