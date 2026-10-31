//! Android calls spec §5 and §9 (relay): grants need circuit membership and
//! both members; an unknown, one-sided or expired token closes the joining
//! connection; one live token per circuit and two per chat connection;
//! every expiry path; a call connection never publishes, queues or sends
//! anything but media and keepalives.

use super::test_support::{
    ask_each_other, authed, call_connection, closed_within, dev_binding, eventually,
    frames_until_quiet, grant_message, granted, join_message, joined, joined_with_challenge,
    media_frame, next_media, next_media_control, pair_up, publish_message, start, test_config,
    until_created, TestIdentity,
};
use super::*;
use crate::protocol::unified::MEDIA_GRANT_REFUSED;
use tokio_tungstenite::tungstenite::Message as WsMessage;

fn refused(frames: &[UnifiedFrame]) -> bool {
    frames.iter().any(|f| {
        matches!(f, UnifiedFrame::Control(ControlMessage::Error { message, .. }) if message == MEDIA_GRANT_REFUSED)
    })
}

#[tokio::test]
async fn a_grant_from_a_non_member_is_refused() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let (_wa, _wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let mut wc = authed(addr, &c).await;
    wc.send(grant_message(ca.circuit_id, [7; 32]))
        .await
        .unwrap();
    assert!(refused(
        &frames_until_quiet(&mut wc, Duration::from_millis(500)).await
    ));
    assert_eq!(state.media.token_count(), 0);
    // An unpublished connection can't grant either.
    let mut anon = call_connection(addr).await;
    anon.send(grant_message(ca.circuit_id, [7; 32]))
        .await
        .unwrap();
    assert!(refused(
        &frames_until_quiet(&mut anon, Duration::from_millis(500)).await
    ));
    assert_eq!(state.media.token_count(), 0);
}

#[tokio::test]
async fn one_grant_is_held_but_a_join_on_it_is_refused() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, _wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    wa.send(grant_message(ca.circuit_id, [8; 32]))
        .await
        .unwrap();
    eventually("held", || state.media.token_count() == 1).await;
    assert!(!state.media.is_usable(&[8; 32]));
    let before = metrics::MEDIA_JOIN_REFUSED.get();
    let mut call = call_connection(addr).await;
    call.send(join_message([8; 32], 0, 0)).await.unwrap();
    assert!(closed_within(&mut call, Duration::from_secs(2)).await);
    assert!(metrics::MEDIA_JOIN_REFUSED.get() > before);
}

#[tokio::test]
async fn both_grants_make_the_token_usable_and_each_side_is_told_of_the_other() {
    let (addr, state) = start(test_config()).await;
    let token = [9; 32];
    let (_wa, _wb, _ca, _cb) = granted(&state, addr, token).await;
    let mut caller = joined(&state, addr, token, 0, 0).await;
    assert_eq!(
        state.media.lanes_of(&token),
        [[true, false, false, false], [false; 4]]
    );
    let mut callee = joined(&state, addr, token, 0, 1).await;
    assert!(matches!(
        next_media_control(&mut callee, Duration::from_secs(2)).await,
        Some(ControlMessage::MediaJoined)
    ));
    assert!(matches!(
        next_media_control(&mut caller, Duration::from_secs(2)).await,
        Some(ControlMessage::MediaJoined)
    ));
    // The callee's second lane joins: the caller already knows, nobody is told again.
    let mut callee1 = joined(&state, addr, token, 1, 1).await;
    assert!(matches!(
        next_media_control(&mut callee1, Duration::from_secs(2)).await,
        Some(ControlMessage::MediaJoined)
    ));
    assert!(next_media_control(&mut caller, Duration::from_millis(300))
        .await
        .is_none());
    // The callee's lanes leave: the caller hears MediaPeerGone once, after the last.
    drop(callee);
    assert!(next_media_control(&mut caller, Duration::from_millis(500))
        .await
        .is_none());
    drop(callee1);
    assert!(matches!(
        next_media_control(&mut caller, Duration::from_secs(2)).await,
        Some(ControlMessage::MediaPeerGone)
    ));
}

#[tokio::test]
async fn an_unknown_token_closes_the_connection_and_is_counted() {
    let (addr, _state) = start(test_config()).await;
    let before = metrics::MEDIA_JOIN_REFUSED.get();
    let mut call = call_connection(addr).await;
    call.send(join_message([0x42; 32], 0, 0)).await.unwrap();
    assert!(closed_within(&mut call, Duration::from_secs(2)).await);
    assert!(metrics::MEDIA_JOIN_REFUSED.get() > before);
}

#[tokio::test]
async fn a_join_with_a_bad_lane_or_role_closes_the_connection_and_is_counted() {
    let (addr, state) = start(test_config()).await;
    let token = [0x43; 32];
    let _pair = granted(&state, addr, token).await;
    for (lane, role) in [(4u8, 0u8), (0, 2), (255, 255)] {
        let before = metrics::MEDIA_JOIN_REFUSED.get();
        let mut call = call_connection(addr).await;
        call.send(join_message(token, lane, role)).await.unwrap();
        assert!(
            closed_within(&mut call, Duration::from_secs(2)).await,
            "lane {lane} role {role}"
        );
        assert!(metrics::MEDIA_JOIN_REFUSED.get() > before);
    }
    assert_eq!(state.media.lanes_of(&token), [[false; 4]; 2]);
}

#[tokio::test]
async fn a_published_connection_cannot_join() {
    let (addr, state) = start(test_config()).await;
    let token = [10; 32];
    let (mut wa, _wb, _ca, _cb) = granted(&state, addr, token).await;
    wa.send(join_message(token, 0, 0)).await.unwrap();
    assert!(closed_within(&mut wa, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_call_connection_may_send_only_media_and_keepalives() {
    let (addr, state) = start(test_config()).await;
    let token = [11; 32];
    let _pair = granted(&state, addr, token).await;
    // A keepalive ping is answered with a pong and the connection stays.
    let mut ok = joined(&state, addr, token, 0, 0).await;
    ok.send(UnifiedFrame::keepalive_ping().encode())
        .await
        .unwrap();
    // `frames_until_quiet` skips keepalives, so read the pong directly.
    let pong = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(m)) = ok.next().await {
            if matches!(
                UnifiedFrame::decode(&m),
                Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Pong { .. }))
            ) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(pong, Ok(true), "ping answered");
    assert!(!closed_within(&mut ok, Duration::from_millis(300)).await);
    // A real publish (signed over the hello's challenge) closes a call
    // connection, as a text frame and as a binary 0x01 frame, and never
    // proves an identity.
    for binary in [false, true] {
        let (lane, role) = (1, 0);
        let (mut ws, challenge) = joined_with_challenge(&state, addr, token, lane, role).await;
        let id = TestIdentity::random();
        let Message::Text(json) = publish_message(&id, &challenge, &dev_binding()) else {
            panic!("publish_message is a text frame");
        };
        let before = metrics::rejections(metrics::REJECT_CALL_FRAME);
        let msg = if binary {
            let mut b = vec![crate::protocol::unified::FRAME_TYPE_SIGNALING];
            b.extend_from_slice(json.as_bytes());
            Message::Binary(b)
        } else {
            Message::Text(json)
        };
        ws.send(msg).await.unwrap();
        assert!(
            closed_within(&mut ws, Duration::from_secs(2)).await,
            "binary {binary}"
        );
        assert!(
            metrics::rejections(metrics::REJECT_CALL_FRAME) > before,
            "binary {binary}"
        );
        assert!(
            !state
                .identity_to_client
                .contains_key(&tags::id_tag(&id.bytes)),
            "binary {binary}"
        );
    }
    // A relay packet (would be queued) closes it.
    let mut relay = joined(&state, addr, token, 0, 1).await;
    let before = metrics::rejections(metrics::REJECT_CALL_FRAME);
    relay
        .send(Message::Binary(vec![
            crate::protocol::unified::FRAME_TYPE_RELAY,
            1,
            2,
            3,
        ]))
        .await
        .unwrap();
    assert!(closed_within(&mut relay, Duration::from_secs(2)).await);
    assert!(metrics::rejections(metrics::REJECT_CALL_FRAME) > before);
    // A second join on the same connection closes it.
    let mut twice = joined(&state, addr, token, 1, 1).await;
    twice.send(join_message(token, 1, 1)).await.unwrap();
    assert!(closed_within(&mut twice, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn a_new_join_on_a_taken_lane_replaces_the_old_connection() {
    let (addr, state) = start(test_config()).await;
    let token = [12; 32];
    let _pair = granted(&state, addr, token).await;
    let mut first = joined(&state, addr, token, 0, 0).await;
    let _second = joined(&state, addr, token, 0, 0).await;
    assert!(closed_within(&mut first, Duration::from_secs(2)).await);
    assert_eq!(
        state.media.lanes_of(&token),
        [[true, false, false, false], [false; 4]]
    );
}

#[tokio::test]
async fn one_live_token_per_circuit_and_two_per_chat_connection() {
    let (addr, state) = start(test_config()).await;
    // Per circuit: a second token while the first has a call connection is refused...
    let (mut wa, _wb, ca, _cb) = granted(&state, addr, [13; 32]).await;
    let _lane = joined(&state, addr, [13; 32], 0, 0).await;
    wa.send(grant_message(ca.circuit_id, [14; 32]))
        .await
        .unwrap();
    assert!(refused(
        &frames_until_quiet(&mut wa, Duration::from_millis(500)).await
    ));
    assert_eq!(state.media.token_count(), 1);
    // ...and replaces it when it has none (D5).
    let (mut wx, _wy, cx, _cy) = granted(&state, addr, [15; 32]).await;
    wx.send(grant_message(cx.circuit_id, [16; 32]))
        .await
        .unwrap();
    eventually("replaced", || {
        !state.media.is_usable(&[15; 32]) && state.media.token_count() == 2
    })
    .await;
    // Per chat connection: a third live token is refused.
    let a = TestIdentity::random();
    let mut w = authed(addr, &a).await;
    let mut circuits = Vec::new();
    for _ in 0..3 {
        let b = TestIdentity::random();
        let mut wb = authed(addr, &b).await;
        ask_each_other(&state, &mut w, &a, &mut wb, &b).await;
        circuits.push((until_created(&mut w).await.circuit_id, wb));
    }
    for (i, (cid, _)) in circuits.iter().enumerate() {
        w.send(grant_message(*cid, [20 + i as u8; 32]))
            .await
            .unwrap();
    }
    assert!(
        refused(&frames_until_quiet(&mut w, Duration::from_millis(500)).await),
        "third grant refused"
    );
}

#[tokio::test]
async fn tokens_expire_on_every_path() {
    let (addr, state) = start(test_config()).await;
    // Usable, never joined: 60 s after the second grant.
    let _p1 = granted(&state, addr, [30; 32]).await;
    let now = Instant::now();
    assert_eq!(media::sweep(now + Duration::from_secs(58), &state), 0);
    assert_eq!(
        media::sweep(now + media::UNJOINED_TTL + Duration::from_secs(1), &state),
        1
    );
    // One grant only: 60 s after it.
    let (a, b) = (TestIdentity::random(), TestIdentity::random());
    let (mut wa, _wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    wa.send(grant_message(ca.circuit_id, [31; 32]))
        .await
        .unwrap();
    eventually("held", || state.media.token_count() == 1).await;
    assert_eq!(
        media::sweep(
            Instant::now() + media::UNJOINED_TTL + Duration::from_secs(1),
            &state
        ),
        1
    );
    // Joined, then every call connection gone: 30 s later.
    let _p3 = granted(&state, addr, [32; 32]).await;
    let lane = joined(&state, addr, [32; 32], 0, 0).await;
    drop(lane);
    eventually("lane gone", || {
        state.media.lanes_of(&[32; 32]) == [[false; 4]; 2]
    })
    .await;
    let gone = Instant::now();
    assert_eq!(media::sweep(gone + Duration::from_secs(28), &state), 0);
    assert_eq!(
        media::sweep(gone + media::EMPTY_TTL + Duration::from_secs(1), &state),
        1
    );
    // A member closes the circuit of a token nobody joined: it goes at once.
    let (mut wc, _wd, cc, _cd) = granted(&state, addr, [33; 32]).await;
    wc.send(
        UnifiedFrame::control(ControlMessage::CloseCircuit {
            circuit_id: cc.circuit_id,
        })
        .encode(),
    )
    .await
    .unwrap();
    eventually("closed token gone", || state.media.token_count() == 0).await;
}

/// Final review I1: a member's `CloseCircuit` (the core closes a blind-path
/// peer's old identity circuit after every chat reconnect) does not end a
/// call: a token with joined call connections keeps them, and then expires
/// on its own rules, 30 s after its last call connection leaves.
#[tokio::test]
async fn a_close_keeps_a_token_with_live_call_connections() {
    let (addr, state) = start(test_config()).await;
    let token = [35; 32];
    let (mut wa, _wb, ca, _cb) = granted(&state, addr, token).await;
    let mut a = joined(&state, addr, token, 0, 0).await;
    let mut b = joined(&state, addr, token, 0, 1).await;
    wa.send(
        UnifiedFrame::control(ControlMessage::CloseCircuit {
            circuit_id: ca.circuit_id,
        })
        .encode(),
    )
    .await
    .unwrap();
    eventually("pair closed", || {
        state.circuits.get(&ca.circuit_id).is_none()
    })
    .await;
    assert!(!closed_within(&mut a, Duration::from_millis(500)).await);
    assert!(state.media.is_usable(&token));
    // Frames still flow.
    a.send(media_frame(7, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut b, Duration::from_secs(2)).await.unwrap()),
        7
    );
    // A lane's reconnect can still join it.
    let a1 = joined(&state, addr, token, 1, 0).await;
    // Every call connection gone: 30 s later, like any joined token.
    drop((a, b, a1));
    eventually("lanes gone", || {
        state.media.lanes_of(&token) == [[false; 4]; 2]
    })
    .await;
    let gone = Instant::now();
    assert_eq!(media::sweep(gone + Duration::from_secs(28), &state), 0);
    assert_eq!(
        media::sweep(gone + media::EMPTY_TTL + Duration::from_secs(1), &state),
        1
    );
}

/// Review Focus 1, D4: a pair torn down by anything but a member's close
/// (a reconnect re-pairing a blinded circuit, the orphan sweep) keeps the
/// token and its call connections.
#[tokio::test]
async fn a_pair_torn_down_without_close_keeps_the_token() {
    let (addr, state) = start(test_config()).await;
    let token = [34; 32];
    let (_wa, _wb, ca, _cb) = granted(&state, addr, token).await;
    let mut lane = joined(&state, addr, token, 0, 0).await;
    let key = state.circuits.get(&ca.circuit_id).expect("routing").pair;
    circuits::teardown_key(key, &state, None);
    assert!(!closed_within(&mut lane, Duration::from_millis(500)).await);
    assert!(state.media.is_usable(&token));
    // A new call connection can still join it (the lane's reconnect).
    let _again = joined(&state, addr, token, 1, 0).await;
}

fn seq_of(frame: &[u8]) -> u64 {
    u64::from_be_bytes(frame[1..9].try_into().unwrap())
}

#[tokio::test]
async fn frames_go_to_the_same_lane_or_else_the_other() {
    let (addr, state) = start(test_config()).await;
    let token = [40; 32];
    let _pair = granted(&state, addr, token).await;
    let mut a0 = joined(&state, addr, token, 0, 0).await;
    let mut a1 = joined(&state, addr, token, 1, 0).await;
    let mut b0 = joined(&state, addr, token, 0, 1).await;
    let mut b1 = joined(&state, addr, token, 1, 1).await;
    // Lane to lane.
    a0.send(media_frame(1, 60)).await.unwrap();
    a1.send(media_frame(2, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut b0, Duration::from_secs(2)).await.unwrap()),
        1
    );
    assert_eq!(
        seq_of(&next_media(&mut b1, Duration::from_secs(2)).await.unwrap()),
        2
    );
    // B's lane 1 gone: A's lane 1 falls back to B's lane 0.
    drop(b1);
    eventually("b1 gone", || {
        state.media.lanes_of(&token)[1] == [true, false, false, false]
    })
    .await;
    a1.send(media_frame(3, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut b0, Duration::from_secs(2)).await.unwrap()),
        3
    );
    // And back the other way.
    b0.send(media_frame(4, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut a0, Duration::from_secs(2)).await.unwrap()),
        4
    );
}

#[tokio::test]
async fn frames_over_64_kbps_are_dropped_and_counted() {
    let (addr, state) = start(test_config()).await;
    let token = [41; 32];
    let _pair = granted(&state, addr, token).await;
    let mut a = joined(&state, addr, token, 0, 0).await;
    let mut b = joined(&state, addr, token, 0, 1).await;
    let dropped = || {
        metrics::MEDIA_FRAMES_DROPPED
            .with_label_values(&[metrics::MEDIA_DROP_RATE])
            .get()
    };
    let before = dropped();
    // 40 frames of 1009 bytes at once: the 16 KiB burst takes 16 of them.
    for seq in 0..40 {
        a.send(media_frame(seq, 1000)).await.unwrap();
    }
    let mut got = 0;
    while next_media(&mut b, Duration::from_millis(300))
        .await
        .is_some()
    {
        got += 1;
    }
    // At most the burst (plus a few ms of refill) gets through; some of that
    // may still meet B's 4 KiB media queue (D7), so only the upper bound and
    // the rate drops are exact.
    assert!(got <= 17, "forwarded {got}");
    assert!(dropped() >= before + 23, "rate drops counted");
    // The connection stays: excess is dropped, never a reason to close.
    assert!(!closed_within(&mut a, Duration::from_millis(200)).await);
}

#[tokio::test]
async fn a_frame_for_a_full_or_missing_target_is_dropped_not_queued() {
    let (addr, state) = start(test_config()).await;
    let token = [42; 32];
    let _pair = granted(&state, addr, token).await;
    let _a = joined(&state, addr, token, 0, 0).await;
    // This relay's only call connection so far (each test starts its own relay).
    let a_id = state
        .connections
        .iter()
        .find(|c| c.media.is_some())
        .map(|c| *c.key())
        .expect("call connection");
    let frame = || {
        let mut f = vec![crate::protocol::unified::FRAME_TYPE_MEDIA];
        f.extend_from_slice(&1u64.to_be_bytes());
        f.resize(1 + 8 + 60, 0xEE);
        f
    };
    // No callee connection yet: dropped (counted as `full`, D7), not queued.
    assert!(matches!(
        media::on_media_frame(a_id, frame(), &state, Instant::now()),
        media::FrameVerdict::Dropped
    ));
    // Nothing waits for a callee that joins later.
    let mut b = joined(&state, addr, token, 0, 1).await;
    assert!(next_media(&mut b, Duration::from_millis(400))
        .await
        .is_none());
    // With the callee there, the same frame is forwarded.
    assert!(matches!(
        media::on_media_frame(a_id, frame(), &state, Instant::now()),
        media::FrameVerdict::Forwarded
    ));
    assert!(next_media(&mut b, Duration::from_secs(2)).await.is_some());
}

#[test]
fn try_send_media_refuses_past_the_media_queue_cap() {
    let (tx, _rx, _kill) = crate::limits::ConnTx::channel();
    let frame = || Message::Binary(vec![0x05; 1000]);
    for _ in 0..4 {
        assert!(tx
            .try_send_media(frame(), crate::limits::MEDIA_QUEUED_MAX_BYTES, None)
            .is_ok());
    }
    assert!(
        tx.try_send_media(frame(), crate::limits::MEDIA_QUEUED_MAX_BYTES, None)
            .is_err(),
        "over 4 KiB queued"
    );
    assert!(!tx.is_closed(), "the recipient stays connected");
}

#[tokio::test]
async fn media_from_a_connection_that_joined_nothing_closes_it() {
    let (addr, _state) = start(test_config()).await;
    let mut anon = call_connection(addr).await;
    anon.send(media_frame(1, 60)).await.unwrap();
    assert!(closed_within(&mut anon, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn join_refuses_an_out_of_range_lane_or_role_itself() {
    let (addr, state) = start(test_config()).await;
    let token = [43; 32];
    let _pair = granted(&state, addr, token).await;
    let _ws = call_connection(addr).await;
    let id = state
        .connections
        .iter()
        .find(|c| c.media.is_none() && c.proven_identity.is_none())
        .map(|c| *c.key())
        .expect("fresh connection");
    for (lane, role) in [(4, 0), (0, 2), (255, 255)] {
        assert!(matches!(
            media::join(id, &token, lane, role, &state, Instant::now()),
            media::Join::Refused
        ));
    }
    assert_eq!(state.media.lanes_of(&token), [[false; 4]; 2]);
}

#[tokio::test]
async fn a_grant_with_a_foreign_token_keeps_the_callers_own_token() {
    let (addr, state) = start(test_config()).await;
    let (a, b, c, d) = (
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
        TestIdentity::random(),
    );
    let (mut wa, _wb, ca, _cb) = pair_up(&state, addr, &a, &b).await;
    let (mut wc, _wd, cc, _cd) = pair_up(&state, addr, &c, &d).await;
    wa.send(grant_message(ca.circuit_id, [50; 32]))
        .await
        .unwrap();
    wc.send(grant_message(cc.circuit_id, [51; 32]))
        .await
        .unwrap();
    eventually("two tokens", || state.media.token_count() == 2).await;
    // A offers C's token on its own circuit: refused, and A's own stays.
    wa.send(grant_message(ca.circuit_id, [51; 32]))
        .await
        .unwrap();
    assert!(refused(
        &frames_until_quiet(&mut wa, Duration::from_millis(500)).await
    ));
    assert_eq!(state.media.token_count(), 2);
}

fn video_dropped(reason: &str) -> u64 {
    metrics::MEDIA_VIDEO_FRAMES_DROPPED
        .with_label_values(&[reason])
        .get()
}

#[tokio::test]
async fn video_lanes_join_and_forward_to_the_same_lane_or_else_the_other_video_lane() {
    let (addr, state) = start(test_config()).await;
    let token = [60; 32];
    let _pair = granted(&state, addr, token).await;
    let mut a2 = joined(&state, addr, token, 2, 0).await;
    let mut a3 = joined(&state, addr, token, 3, 0).await;
    let mut b3 = joined(&state, addr, token, 3, 1).await;
    assert_eq!(
        state.media.lanes_of(&token),
        [[false, false, true, true], [false, false, false, true]]
    );
    // Caller lane 2: callee has no lane 2, so it falls to the callee's lane 3.
    a2.send(media_frame(1, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut b3, Duration::from_secs(2)).await.unwrap()),
        1
    );
    // Callee lane 3 reaches the caller's lane 3.
    b3.send(media_frame(2, 60)).await.unwrap();
    assert_eq!(
        seq_of(&next_media(&mut a3, Duration::from_secs(2)).await.unwrap()),
        2
    );
    assert!(next_media(&mut a2, Duration::from_millis(300))
        .await
        .is_none());
}

#[tokio::test]
async fn video_and_audio_lanes_never_cross() {
    let (addr, state) = start(test_config()).await;
    let token = [61; 32];
    let _pair = granted(&state, addr, token).await;
    let mut a0 = joined(&state, addr, token, 0, 0).await;
    let mut a2 = joined(&state, addr, token, 2, 0).await;
    let b0 = joined(&state, addr, token, 0, 1).await;
    // Audio with only video on the other side: dropped as full.
    let _b3 = joined(&state, addr, token, 3, 1).await;
    drop(b0);
    eventually("b0 gone", || !state.media.lanes_of(&token)[1][0]).await;
    let before = metrics::MEDIA_FRAMES_DROPPED
        .with_label_values(&[metrics::MEDIA_DROP_FULL])
        .get();
    a0.send(media_frame(1, 60)).await.unwrap();
    eventually("audio dropped", || {
        metrics::MEDIA_FRAMES_DROPPED
            .with_label_values(&[metrics::MEDIA_DROP_FULL])
            .get()
            > before
    })
    .await;
    // And video with only audio on the other side.
    let mut b0 = joined(&state, addr, token, 0, 1).await;
    drop(_b3);
    eventually("b3 gone", || !state.media.lanes_of(&token)[1][3]).await;
    let vbefore = video_dropped(metrics::MEDIA_DROP_FULL);
    a2.send(media_frame(2, 60)).await.unwrap();
    eventually("video dropped", || {
        video_dropped(metrics::MEDIA_DROP_FULL) > vbefore
    })
    .await;
    assert!(next_media(&mut b0, Duration::from_millis(300))
        .await
        .is_none());
}

#[tokio::test]
async fn video_frames_over_4_mbps_are_dropped_and_counted() {
    let (addr, state) = start(test_config()).await;
    let token = [62; 32];
    let _pair = granted(&state, addr, token).await;
    let mut a = joined(&state, addr, token, 2, 0).await;
    let mut b = joined(&state, addr, token, 2, 1).await;
    let rate_before = video_dropped(metrics::MEDIA_DROP_RATE);
    let start_at = std::time::Instant::now();
    // 600 KB in 8 KiB frames, as fast as the socket takes them.
    for seq in 0..75 {
        a.send(media_frame(seq, 8 * 1024 - 9)).await.unwrap();
    }
    let mut got_bytes = 0usize;
    while let Some(f) = next_media(&mut b, Duration::from_millis(400)).await {
        got_bytes += f.len();
    }
    let elapsed = start_at.elapsed().as_secs_f64();
    assert!(
        got_bytes as f64 <= 256.0 * 1024.0 + 500_000.0 * elapsed,
        "forwarded {got_bytes} bytes in {elapsed}s"
    );
    assert!(got_bytes > 0);
    assert!(video_dropped(metrics::MEDIA_DROP_RATE) > rate_before);
    assert!(!closed_within(&mut a, Duration::from_millis(200)).await);
}

#[test]
fn a_backed_up_video_lane_queues_up_to_256_kib_then_drops() {
    let (tx, _rx, _kill) = crate::limits::ConnTx::channel();
    let frame = || WsMessage::Binary(vec![0x05; 8 * 1024]);
    let mut queued = 0usize;
    let mut refused = 0;
    for _ in 0..40 {
        match tx.try_send_media(frame(), crate::limits::VIDEO_QUEUED_MAX_BYTES, None) {
            Ok(()) => queued += 8 * 1024,
            Err(_) => refused += 1,
        }
    }
    assert_eq!(queued, crate::limits::VIDEO_QUEUED_MAX_BYTES);
    assert_eq!(refused, 8);
    assert!(!tx.is_closed(), "the recipient stays connected");
}

#[tokio::test]
async fn a_full_video_target_counts_a_video_full_drop() {
    let (addr, state) = start(test_config()).await;
    let token = [63; 32];
    let _pair = granted(&state, addr, token).await;
    let _a = joined(&state, addr, token, 2, 0).await;
    let a_id = state
        .connections
        .iter()
        .find(|c| c.media.is_some())
        .map(|c| *c.key())
        .expect("call connection");
    let before = video_dropped(metrics::MEDIA_DROP_FULL);
    // No callee yet: dropped as full on the video counter.
    let mut f = vec![crate::protocol::unified::FRAME_TYPE_MEDIA];
    f.resize(70, 0);
    assert!(matches!(
        media::on_media_frame(a_id, f, &state, Instant::now()),
        media::FrameVerdict::Dropped
    ));
    assert!(video_dropped(metrics::MEDIA_DROP_FULL) > before);
}

#[tokio::test]
async fn hello_response_announces_video_v1() {
    let (addr, _state) = start(test_config()).await;
    let mut ws = super::test_support::connect(addr).await;
    ws.send(super::test_support::hello_message(vec![3]))
        .await
        .unwrap();
    let reply = super::test_support::next_signaling(
        &mut ws,
        crate::protocol::MSG_TYPE_HELLO_RESPONSE,
        Duration::from_secs(5),
    )
    .await
    .expect("hello_response");
    let p: crate::protocol::HelloResponsePayload =
        reply.payload.deserialize_data().expect("hello payload");
    let caps = p.server_info.capabilities;
    assert!(caps.contains(&"video-v1".to_string()) && caps.contains(&"calls-v1".to_string()));
}

#[tokio::test]
async fn video_connection_gauge_follows_joins_and_closes() {
    let (addr, state) = start(test_config()).await;
    let token = [64; 32];
    let _pair = granted(&state, addr, token).await;
    let all_before = metrics::MEDIA_CONNECTIONS_ACTIVE.get();
    let video_before = metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.get();
    let _a0 = joined(&state, addr, token, 0, 0).await;
    let a2 = joined(&state, addr, token, 2, 0).await;
    let _b3 = joined(&state, addr, token, 3, 1).await;
    let _b1 = joined(&state, addr, token, 1, 1).await;
    // Other tests run in parallel and also move these gauges: deltas only.
    eventually("gauges up", || {
        metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.get() >= video_before + 2
            && metrics::MEDIA_CONNECTIONS_ACTIVE.get() >= all_before + 4
    })
    .await;
    let video_peak = metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.get();
    drop(a2);
    eventually("video gauge down", || {
        metrics::MEDIA_VIDEO_CONNECTIONS_ACTIVE.get() < video_peak
    })
    .await;
    eventually("lane gone", || !state.media.lanes_of(&token)[0][2]).await;
    assert_eq!(
        state.media.lanes_of(&token),
        [[true, false, false, false], [false, true, false, true]]
    );
}
