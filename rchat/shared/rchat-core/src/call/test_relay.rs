//! A fake relay for call-connection tests: answers hello signed by the
//! test relay key, records each `MediaJoin`, and then (by `Mode`) echoes
//! media back, refuses, stalls or drops the connection.

use super::lanes::LaneConfig;
use crate::protocol::{
    signaling_frame, ControlMessage, KeepaliveMessage, FRAME_TYPE_KEEPALIVE, FRAME_TYPE_MEDIA,
};
use crate::test_support::{hello_response_bound, test_relay};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// MediaJoined, then every media frame back to its sender.
    Echo,
    /// Close right after the join (an unknown token).
    Refuse,
    /// Refuse the first n joins (all lanes together), then behave as Echo:
    /// a callee that joins before the caller's grant has landed.
    RefuseFirst(usize),
    /// Never read after the join (no write progress for the client).
    Stall,
    /// Answer the hello only after this long (a slow connect), then refuse.
    SlowRefuse(Duration),
    /// Echo, then drop the connection after this long (a network change).
    DropAfter(Duration),
    /// MediaJoined, a keepalive ping, then MediaPeerGone.
    PeerComesAndGoes,
    /// Two phones through one relay: media from a role goes to the other
    /// role's connection on the same lane, else on the partner lane.
    Pair,
    /// MediaJoined, then never read that lane (no write progress), while
    /// every other lane echoes.
    StallLane(u8),
    /// As `Pair`, but the nth media frame (from 1) on the video lanes (2
    /// and 3, both phones counted together) is dropped.
    DropNth(usize),
    /// As `Pair`, but the video lanes (2 and 3) are never read after the
    /// join (a video backlog), while the audio lanes pair as usual.
    PairStallVideo,
    /// MediaJoined, then never read, while a media frame goes to the client
    /// every 20 ms for 5 s (a peer talking to a phone whose uplink is full).
    DeafTalker,
}

type Registry = Arc<Mutex<HashMap<([u8; 32], u8, u8), mpsc::UnboundedSender<Vec<u8>>>>>;

#[derive(Default, Debug)]
pub(crate) struct Seen {
    pub joins: Vec<([u8; 32], u8, u8)>,
    pub pongs: usize,
    pub media_in: usize,
    /// Media frames in, by lane.
    pub lane_in: [usize; 4],
}

pub(crate) fn lane_config(url: &str) -> LaneConfig {
    LaneConfig {
        server_url: url.to_string(),
        dev_origin: None,
        relay_pin: crate::relay_pin::encode_pin(&test_relay().verifying_key().to_bytes()),
        relay_pin_version: None,
        tls_fingerprint: Default::default(),
        resumption: None,
    }
}

pub(crate) async fn fake_relay(mode: Mode) -> (String, Arc<Mutex<Seen>>) {
    // A small receive buffer (inherited by accepted sockets) so a relay that
    // stops reading stalls the client's writes within a few hundred KiB.
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(8 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(64).unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let registry: Registry = Arc::default();
    let (u, s) = (url.clone(), seen.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (u, s, reg) = (u.clone(), s.clone(), registry.clone());
            tokio::spawn(async move {
                let _ = serve_one(tcp, &u, mode, s, reg).await;
            });
        }
    });
    (url, seen)
}

async fn serve_one(
    tcp: tokio::net::TcpStream,
    url: &str,
    mode: Mode,
    seen: Arc<Mutex<Seen>>,
    registry: Registry,
) -> Option<()> {
    let mut ws = tokio_tungstenite::accept_async(tcp).await.ok()?;
    let _hello = ws.next().await?.ok()?;
    if let Mode::SlowRefuse(d) = mode {
        tokio::time::sleep(d).await;
    }
    let binding = crate::transport::plain_channel_binding(url, None).ok()?;
    let resp = hello_response_bound([0x3C; 32], binding);
    ws.send(Message::Binary(signaling_frame(&resp).ok()?))
        .await
        .ok()?;
    let Message::Binary(b) = ws.next().await?.ok()? else {
        return None;
    };
    let Some(ControlMessage::MediaJoin { token, lane, role }) = ControlMessage::decode(&b) else {
        return None;
    };
    let joins = {
        let mut seen = seen.lock();
        seen.joins.push((token, lane, role));
        seen.joins.len()
    };
    let refuse = match mode {
        Mode::Refuse | Mode::SlowRefuse(_) => true,
        Mode::RefuseFirst(n) => joins <= n,
        _ => false,
    };
    if refuse {
        let _ = ws.send(Message::Close(None)).await;
        return None;
    }
    if mode == Mode::Stall {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return None;
    }
    ws.send(Message::Binary(
        ControlMessage::MediaJoined.encode_with_frame_type(),
    ))
    .await
    .ok()?;
    if mode == Mode::DeafTalker {
        for _ in 0..250 {
            let frame = vec![FRAME_TYPE_MEDIA, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
            ws.send(Message::Binary(frame)).await.ok()?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
        return None;
    }
    if mode == Mode::StallLane(lane) || (mode == Mode::PairStallVideo && lane >= 2) {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return None;
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let pair = matches!(mode, Mode::Pair | Mode::DropNth(_) | Mode::PairStallVideo);
    if pair {
        registry.lock().insert((token, lane, role), out_tx);
    }
    if mode == Mode::PeerComesAndGoes {
        let ping = KeepaliveMessage::Ping { timestamp: 1 }.encode_with_frame_type();
        ws.send(Message::Binary(ping)).await.ok()?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        ws.send(Message::Binary(
            ControlMessage::MediaPeerGone.encode_with_frame_type(),
        ))
        .await
        .ok()?;
    }
    let started = Instant::now();
    loop {
        let m = tokio::select! {
            m = ws.next() => m?.ok()?,
            Some(b) = out_rx.recv() => {
                ws.send(Message::Binary(b)).await.ok()?;
                continue;
            }
        };
        if let Mode::DropAfter(d) = mode {
            if started.elapsed() >= d {
                return None;
            }
        }
        if let Message::Binary(b) = m {
            match b.first() {
                Some(&FRAME_TYPE_MEDIA) => {
                    let drop = {
                        let mut s = seen.lock();
                        s.media_in += 1;
                        s.lane_in[usize::from(lane & 3)] += 1;
                        matches!(mode, Mode::DropNth(n) if lane >= 2 && s.lane_in[2] + s.lane_in[3] == n)
                    };
                    if matches!(
                        mode,
                        Mode::Echo | Mode::RefuseFirst(_) | Mode::DropAfter(_) | Mode::StallLane(_)
                    ) {
                        ws.send(Message::Binary(b)).await.ok()?;
                    } else if pair && !drop {
                        let reg = registry.lock();
                        let peer = reg
                            .get(&(token, lane, 1 - role))
                            .or_else(|| reg.get(&(token, lane ^ 1, 1 - role)));
                        if let Some(peer) = peer {
                            let _ = peer.send(b);
                        }
                    }
                }
                Some(&FRAME_TYPE_KEEPALIVE) => {
                    if matches!(
                        KeepaliveMessage::decode(&b),
                        Some(KeepaliveMessage::Pong { .. })
                    ) {
                        seen.lock().pongs += 1;
                    }
                }
                _ => {}
            }
        }
    }
}
