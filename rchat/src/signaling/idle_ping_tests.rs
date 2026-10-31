//! Owner decision 2026-10-26 (Task 8 C): the relay pings a connection only
//! after it has gone quiet (`IDLE_PING` = 262 s ± 8 s, capped 30 s before
//! `connection_timeout_secs`, never under 60 s), not every 25-35 s. A
//! client that pings on its own (every 30 s in the foreground, 240 s in
//! the background) never gets a relay ping; one that stops answering is
//! still closed, after the idle ping plus the pong window. The idle-ping
//! bounds are in `limits_tests::idle_ping_is_262_s_jittered_and_leaves_30_s_to_answer`.

use super::test_support::*;
use super::*;
use futures_util::{SinkExt, StreamExt};

fn idle(state: &RelayState) -> Duration {
    idle_ping_after(0.5, state.config.connection_timeout())
}

fn set_last_activity(state: &RelayState, client: ClientId, at: Instant) {
    state.connections.get_mut(&client).unwrap().last_activity = at;
}

/// A connection silent since `t0` is not pinged at about 30 s (the old
/// schedule), only once 262 s have passed.
#[tokio::test]
async fn an_idle_connection_is_pinged_after_262_s_not_30_s() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, mut rx) = bare_connection([0u8; 32]);
    let client = conn.client_id;
    state.connections.insert(client, conn);
    let t0 = Instant::now();
    set_last_activity(&state, client, t0);
    let after = idle(&state);
    assert_eq!(after, Duration::from_secs(262));

    let next = keepalive_tick(
        client,
        &state.connections,
        t0 + Duration::from_secs(30),
        PONG_TIMEOUT,
        None,
        after,
    );
    assert_eq!(next, Some(Duration::from_secs(232)), "sleeps until 262 s");
    assert!(rx.try_recv().is_err(), "no ping at 30 s");
    assert!(state
        .connections
        .get(&client)
        .unwrap()
        .pending_ping
        .is_none());

    let next = keepalive_tick(
        client,
        &state.connections,
        t0 + after,
        PONG_TIMEOUT,
        None,
        after,
    );
    assert!(next.is_some());
    assert!(rx.try_recv().is_ok(), "pinged at 262 s");
    assert!(state
        .connections
        .get(&client)
        .unwrap()
        .pending_ping
        .is_some());
}

/// A client that sends its own keepalive every 30 s is never pinged by
/// the relay, over half an hour of rounds.
#[tokio::test]
async fn a_client_pinging_every_30_s_is_never_pinged() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, mut rx) = bare_connection([0u8; 32]);
    let client = conn.client_id;
    state.connections.insert(client, conn);
    let t0 = Instant::now();
    let after = idle(&state);
    let mut now = t0;
    while now < t0 + Duration::from_secs(1800) {
        // The client's ping arrives (any data frame sets last_activity).
        set_last_activity(&state, client, now);
        for step in [1u64, 15, 29] {
            let at = now + Duration::from_secs(step);
            let next = keepalive_tick(client, &state.connections, at, PONG_TIMEOUT, None, after);
            assert!(next.is_some());
        }
        now += Duration::from_secs(30);
    }
    assert!(rx.try_recv().is_err(), "the relay never pinged");
}

/// Worst case for a silently vanished client: it is pinged after 262 s
/// of silence and closed once the ping has gone unanswered for the pong
/// window (in production the 300 s idle timeout closes it first, 30 s or
/// more after the ping).
#[tokio::test]
async fn an_unanswered_idle_ping_closes_after_the_pong_window() {
    let state = RelayState::new(Arc::new(test_config()));
    let (conn, mut rx) = bare_connection([0u8; 32]);
    let tx = conn.ws_tx.clone();
    let client = conn.client_id;
    state.connections.insert(client, conn);
    let t0 = Instant::now();
    set_last_activity(&state, client, t0);
    let after = idle(&state);
    let ping_at = t0 + after;
    assert!(keepalive_tick(
        client,
        &state.connections,
        ping_at,
        PONG_TIMEOUT,
        None,
        after
    )
    .is_some());
    assert!(rx.try_recv().is_ok());
    let written = Some(ping_at);
    let just_in = ping_at + PONG_TIMEOUT;
    assert!(keepalive_tick(
        client,
        &state.connections,
        just_in,
        PONG_TIMEOUT,
        written,
        after
    )
    .is_some());
    assert!(!tx.is_closed());
    let late = just_in + Duration::from_millis(5);
    assert!(keepalive_tick(
        client,
        &state.connections,
        late,
        PONG_TIMEOUT,
        written,
        after
    )
    .is_none());
    assert!(
        tx.is_closed(),
        "closed after the idle ping plus the pong window"
    );
}

async fn start_tuned(
    config: ServerConfig,
    tune: impl FnOnce(&mut RelayState),
) -> (SocketAddr, RelayState) {
    let mut server = Server::new(config).await.expect("server starts");
    tune(&mut server.state);
    let addr = server.local_addr().expect("bound");
    let state = server.state();
    tokio::spawn(server.run());
    (addr, state)
}

/// The scaled live relay: idle ping after 400 ms of silence, pong window
/// 500 ms.
fn scaled(s: &mut RelayState) {
    s.writer_stall = Duration::from_secs(600);
    s.keepalive_ping_every = Some(Duration::from_millis(400));
    s.pong_timeout = Duration::from_millis(500);
}

fn is_relay_ping(m: &Message) -> bool {
    matches!(
        UnifiedFrame::decode(m),
        Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Ping { .. }))
    )
}

/// Live: a client pinging four times per idle period never sees a relay
/// ping (it gets pongs), and stays connected.
#[tokio::test]
async fn live_a_chatty_client_never_gets_a_relay_ping() {
    let (addr, state) = start_tuned(test_config(), scaled).await;
    let id = TestIdentity::from_seed(0xC0);
    let mut ws = authed(addr, &id).await;
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut pongs = 0;
    while tokio::time::Instant::now() < until {
        ws.send(Frame::keepalive_ping().encode()).await.unwrap();
        let tick = tokio::time::Instant::now() + Duration::from_millis(100);
        while let Ok(Some(Ok(m))) = tokio::time::timeout_at(tick, ws.next()).await {
            assert!(!is_relay_ping(&m), "the relay pinged a chatty client");
            if matches!(
                UnifiedFrame::decode(&m),
                Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Pong { .. }))
            ) {
                pongs += 1;
            }
        }
    }
    assert!(pongs > 5, "the client's pings were answered");
    assert!(mapped_client(&state, &id).is_some(), "still connected");
}

/// Live: a silent client is pinged only after the idle threshold, and,
/// not answering, is closed after the idle ping plus the pong window.
#[tokio::test]
async fn live_a_silent_client_is_pinged_late_then_closed() {
    let (addr, _state) = start_tuned(test_config(), scaled).await;
    let id = TestIdentity::from_seed(0xC1);
    let mut ws = authed(addr, &id).await;
    let quiet_since = tokio::time::Instant::now();
    let mut first_ping = None;
    let closed_at = loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(m))) if is_relay_ping(&m) => {
                first_ping.get_or_insert_with(tokio::time::Instant::now);
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                break tokio::time::Instant::now();
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => panic!("still open after 5 s"),
        }
    };
    let pinged = first_ping.expect("a relay ping") - quiet_since;
    assert!(
        pinged >= Duration::from_millis(350),
        "pinged after {pinged:?}, not before the idle threshold"
    );
    let closed = closed_at - quiet_since;
    assert!(
        closed >= Duration::from_millis(850) && closed < Duration::from_secs(3),
        "closed after {closed:?}: about the idle ping plus the pong window"
    );
}
