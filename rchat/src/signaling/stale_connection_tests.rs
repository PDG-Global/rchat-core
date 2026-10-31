//! Owner ruling 2026-10-26 (Task 8 A): a member's publish on a new
//! connection closes its older foreground connections (those that have
//! asked), so routing no longer reaches a socket that may have died
//! without a FIN. A background drain (never asks) is never closed this way,
//! and a later foreground publish leaves a live drain alone.

use super::test_support::*;
use super::*;
use futures_util::SinkExt;

/// Whether `ws` got a relay packet or `QueuedMessage` carrying `payload`.
fn carries(frames: &[UnifiedFrame], payload: &[u8]) -> bool {
    frames.iter().any(|f| match f {
        UnifiedFrame::Relay(p) => p.payload == payload,
        UnifiedFrame::Control(ControlMessage::QueuedMessage { payload: p }) => p == payload,
        _ => false,
    })
}

fn connections_of(state: &RelayState, id: &TestIdentity) -> Vec<(ClientId, bool)> {
    state
        .connections
        .iter()
        .filter(|c| c.proven_identity == Some(id.bytes))
        .map(|c| (*c.key(), c.has_asked))
        .collect()
}

/// The probe of the Task 8 report: B's first connection stays open but
/// unread (a phone that vanished without a FIN); B reconnects and
/// publishes. The stale connection is closed at once, and A's next packet
/// on the old circuit reaches B's new connection (D34 hand-over), not the
/// dead socket.
#[tokio::test]
async fn publish_closes_the_stale_foreground_connection_and_routes_to_the_new_one() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0xA0), TestIdentity::from_seed(0xA1));
    let (mut wa, mut wb_ghost, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let ghost = mapped_client(&state, &b).expect("B mapped");
    let mut wb2 = authed(addr, &b).await;
    let st = state.clone();
    eventually("stale connection removed", move || {
        !st.connections.contains_key(&ghost)
    })
    .await;
    assert!(
        closed_within(&mut wb_ghost, Duration::from_secs(2)).await,
        "the stale socket is closed"
    );
    let payload = vec![0x02; 200];
    wa.send(relay_on(ca.target_circuit_id, &ca.token, payload.clone()))
        .await
        .unwrap();
    let new_frames = frames_until_quiet(&mut wb2, Duration::from_millis(800)).await;
    assert!(carries(&new_frames, &payload), "the new connection has it");
    let a_frames = frames_until_quiet(&mut wa, Duration::from_millis(300)).await;
    assert!(a_frames
        .iter()
        .any(|f| matches!(f, UnifiedFrame::Control(ControlMessage::MessageAck { .. }))));
    assert_eq!(queued_len(&state, &b), 0, "handed over, not left queued");
}

/// A drain-style connection (publishes, never asks) next to a foreground
/// connection that has not asked yet: neither publish closes the other.
#[tokio::test]
async fn drain_and_unasked_foreground_leave_each_other_alone() {
    let (addr, state) = start(test_config()).await;
    let b = TestIdentity::from_seed(0xA3);
    let _drain = authed(addr, &b).await;
    let _main = authed(addr, &b).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(connections_of(&state, &b).len(), 2, "both stay open");
}

/// A foreground connection that publishes and asks never closes a live
/// drain connection of the same member, and the drain still gets its
/// queue and marker.
#[tokio::test]
async fn foreground_publish_and_ask_keep_a_live_drain() {
    let (addr, state) = start(test_config()).await;
    let (b, c) = (TestIdentity::from_seed(0xA4), TestIdentity::from_seed(0xA5));
    queue_test_message(&state, &b, vec![0x02; 120]);
    let mut drain = connect(addr).await;
    publish(&mut drain, &b).await;
    let got = frames_until_quiet(&mut drain, Duration::from_millis(400)).await;
    assert!(carries(&got, &[0x02; 120]), "the drain gets the queue");
    let mut main = connect(addr).await;
    let next = publish(&mut main, &b).await;
    main.send(ask(&c, [0x11; 32], None)).await.unwrap();
    let st = state.clone();
    let bb = b.bytes;
    eventually("main asked", move || {
        st.connections
            .iter()
            .any(|x| x.proven_identity == Some(bb) && x.has_asked)
    })
    .await;
    // A second publish by the main connection (a re-publish) still keeps
    // the drain: it has never asked.
    assert!(matches!(
        send_publish(&mut main, &b, &next, &dev_binding()).await,
        PublishReply::Ok(_)
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let conns = connections_of(&state, &b);
    assert_eq!(conns.len(), 2, "the drain stays: {conns:?}");
}

/// The core refuses a drain while connected, so an asked connection of the
/// same member still open when a drain publishes is stale: it is closed,
/// and the drain is not.
#[tokio::test]
async fn drain_publish_closes_only_a_stale_foreground_connection() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0xA6), TestIdentity::from_seed(0xA7));
    let (_wa, mut wb_ghost, _ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let ghost = mapped_client(&state, &b).expect("B mapped");
    let mut drain = connect(addr).await;
    publish(&mut drain, &b).await;
    let _ = frames_until_quiet(&mut drain, Duration::from_millis(400)).await;
    assert!(closed_within(&mut wb_ghost, Duration::from_secs(2)).await);
    let st = state.clone();
    eventually("stale removed", move || {
        !st.connections.contains_key(&ghost)
    })
    .await;
    let conns = connections_of(&state, &b);
    assert_eq!(conns.len(), 1, "only the drain is left: {conns:?}");
    assert!(!conns[0].1, "and it has not asked");
}
