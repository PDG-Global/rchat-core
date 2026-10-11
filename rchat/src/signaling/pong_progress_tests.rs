//! Debug-voice-loss: the relay's keepalive must not close a healthy
//! recipient whose ping is still queued behind a large frame it is
//! reading slowly, and must still close a peer that is truly gone. Over
//! real sockets, with short keepalive timings; the slow reader sits behind
//! a throttling proxy that reads from the relay at a fixed rate.

use super::test_support::*;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PART: usize = 5 << 20;
const PARTS: usize = 3;

fn big_config() -> ServerConfig {
    ServerConfig {
        rate_limit_bps: 1 << 30,
        max_message_bytes: 8 << 20,
        ..test_config()
    }
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

/// Pings every 200 ms, a 2 s pong timeout, no writer stall in the way.
fn short_keepalive(s: &mut RelayState) {
    s.writer_stall = Duration::from_secs(600);
    s.keepalive_ping_every = Some(Duration::from_millis(200));
    s.pong_timeout = Duration::from_secs(2);
}

/// A TCP proxy to `relay` that reads from the relay at `bytes_per_sec`
/// (client to relay unthrottled). Returns its address.
async fn throttling_proxy(relay: SocketAddr, bytes_per_sec: usize) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        // A small receive buffer keeps what the kernel holds between the
        // relay and the proxy small, so the throttle sets the pace.
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(64 << 10).unwrap();
        let upstream = sock.connect(relay).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        });
        const CHUNK: usize = 64 << 10;
        let pause = Duration::from_secs_f64(CHUNK as f64 / bytes_per_sec as f64);
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match ur.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            tokio::time::sleep(pause).await;
        }
    });
    addr
}

fn payload(len: usize, fill: u8) -> Vec<u8> {
    let mut p = vec![fill; len];
    p[0] = 0x02;
    p
}

/// A recipient reading 15 MiB at 2 MiB/s answers every ping as soon as it
/// reaches it; the relay's pings wait behind the large frames for longer
/// than the pong timeout (about 4 s against 2 s: the timeout counted from
/// queueing closed it). It must stay connected and get every frame.
#[tokio::test]
async fn a_slow_healthy_reader_is_not_closed_behind_large_frames() {
    let (addr, state) = start_tuned(big_config(), short_keepalive).await;
    let (s_id, r_id) = (TestIdentity::random(), TestIdentity::random());
    let proxy = throttling_proxy(addr, 2 << 20).await;
    let mut ws_s = authed(addr, &s_id).await;
    let mut ws_r = authed(proxy, &r_id).await;
    ask_each_other(&state, &mut ws_s, &s_id, &mut ws_r, &r_id).await;
    let cs = created(&mut ws_s).await;
    let _ = created(&mut ws_r).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");

    // R: answer pings, count the large packets.
    let reader = tokio::spawn(async move {
        let mut got = 0usize;
        while got < PARTS {
            match tokio::time::timeout(Duration::from_secs(20), ws_r.next()).await {
                Ok(Some(Ok(msg))) => match UnifiedFrame::decode(&msg) {
                    Ok(UnifiedFrame::Keepalive(KeepaliveMessage::Ping { timestamp })) => {
                        let pong = UnifiedFrame::keepalive_pong(timestamp).encode();
                        if ws_r.send(pong).await.is_err() {
                            return got;
                        }
                    }
                    Ok(UnifiedFrame::Relay(p)) if p.payload.len() == PART => got += 1,
                    _ => {}
                },
                _ => return got,
            }
        }
        got
    });

    for i in 0..PARTS {
        ws_s.send(relay_on(cs.2, &cs.1, payload(PART, i as u8 + 1)))
            .await
            .unwrap();
    }
    let got = reader.await.unwrap();
    assert_eq!(got, PARTS, "R must get every frame on one connection");
    assert!(
        state.connections.contains_key(&r_client),
        "a healthy slow reader must stay connected"
    );
}

/// A peer that neither reads nor answers is still closed by the pong
/// timeout (the writer stall is out of the way).
#[tokio::test]
async fn a_peer_that_never_answers_is_still_closed() {
    let (addr, state) = start_tuned(big_config(), short_keepalive).await;
    let r_id = TestIdentity::random();
    let ws_r = authed(addr, &r_id).await;
    let r_client = mapped_client(&state, &r_id).expect("R is mapped");
    let st = state.clone();
    eventually_within("R is closed", Duration::from_secs(10), move || {
        !st.connections.contains_key(&r_client)
    })
    .await;
    drop(ws_r);
}
