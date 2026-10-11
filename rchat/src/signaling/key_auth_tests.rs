//! Publish authentication against a real relay: spec §4.3 and tests A1,
//! A2, A2b, A3, A7, A9, K1 (relay side) and RF1 (mapping part).

use super::circuits::{assert_r4_undelivered, assert_r7};
use super::test_support::*;
use super::*;
use rchat_core::crypto::IdentityKeyPair;
use rchat_core::keyauth::{self, golden};
use std::io::Write;
use std::sync::Mutex;

const WAIT: Duration = Duration::from_secs(5);

fn has_delivery(frames: &[UnifiedFrame]) -> bool {
    frames.iter().any(|f| {
        matches!(
            f,
            UnifiedFrame::Relay(_) | UnifiedFrame::Control(ControlMessage::QueuedMessage { .. })
        )
    })
}

/// A1: publishing someone else's (public) bundle without their key fails,
/// closes the connection, and leaves their mapping and queue untouched.
#[tokio::test]
async fn a1_impersonation_publish_is_refused_and_changes_nothing() {
    let (addr, state) = start(test_config()).await;
    let victim = TestIdentity::random();
    let attacker = TestIdentity::random();
    queue_test_message(&state, &victim, b"QUEUED-FOR-VICTIM".to_vec());

    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    // Victim's bundle, proof made with the attacker's own key.
    let attacker_proof =
        keyauth::sign_conn(&attacker.keys, &nonce, &dev_binding(), &attacker.bundle).unwrap();
    ws.send(raw_publish(key_bundle_of(&victim), &attacker_proof))
        .await
        .unwrap();
    let frames = frames_until_closed(&mut ws, WAIT).await;

    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("AuthenticationFailed")
    );
    assert!(
        !has_delivery(&frames),
        "the victim's queue reached the attacker"
    );
    assert!(mapped_client(&state, &victim).is_none(), "mapping changed");
    assert_r4_undelivered(&state, tags::id_tag(&victim.bytes), 1, &frames);
}

/// A2: a proof replayed on another connection is refused.
#[tokio::test]
async fn a2_replayed_proof_on_another_connection_is_refused() {
    let (addr, state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut first = connect(addr).await;
    let nonce = hello(&mut first).await;
    let proof = publish_message(&id, &nonce, &dev_binding());
    first.send(proof.clone()).await.unwrap();
    assert!(matches!(
        publish_reply(&mut first).await,
        PublishReply::Ok(_)
    ));
    let first_client = mapped_client(&state, &id).unwrap();

    let mut second = connect(addr).await;
    let _other_nonce = hello(&mut second).await;
    second.send(proof).await.unwrap();
    let frames = frames_until_closed(&mut second, WAIT).await;
    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("AuthenticationFailed")
    );
    assert_eq!(mapped_client(&state, &id), Some(first_client));
}

/// A2: the same proof again on the same connection is refused (the nonce
/// was consumed).
#[tokio::test]
async fn a2_replayed_proof_on_the_same_connection_is_refused() {
    let (addr, _state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    let proof = publish_message(&id, &nonce, &dev_binding());
    ws.send(proof.clone()).await.unwrap();
    assert!(matches!(publish_reply(&mut ws).await, PublishReply::Ok(_)));
    ws.send(proof).await.unwrap();
    let frames = frames_until_closed(&mut ws, WAIT).await;
    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("AuthenticationFailed")
    );
}

/// A2: re-publishing over `next_challenge` is accepted, and yields a fresh one.
#[tokio::test]
async fn a2_next_challenge_republish_is_accepted() {
    let (addr, _state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut ws = connect(addr).await;
    let next = publish(&mut ws, &id).await;
    match send_publish(&mut ws, &id, &next, &dev_binding()).await {
        PublishReply::Ok(next2) => assert_ne!(next2, next),
        other => panic!("re-publish refused: {other:?}"),
    }
}

// ---- A2b: channel binding ------------------------------------------------

/// A2b: over TLS, a proof made with another session's exporter (a relayed
/// proof) is refused; a proof over this session's exporter is accepted.
#[tokio::test]
async fn a2b_proof_bound_to_another_tls_session_is_refused() {
    let (addr, _state) = tls_relay().await;
    let id = TestIdentity::random();
    let (mut s1, b1) = tls_ws(addr).await;
    let (_s2, b2) = tls_ws(addr).await;
    assert_ne!(b1, b2, "each TLS session has its own exporter");

    let n1 = hello(&mut s1).await;
    match send_publish(&mut s1, &id, &n1, &b2).await {
        PublishReply::Error(e) => assert!(e.contains("AuthenticationFailed"), "{e}"),
        other => panic!("relayed proof accepted: {other:?}"),
    }
    assert!(closed_within(&mut s1, WAIT).await);

    let (mut s3, b3) = tls_ws(addr).await;
    let n3 = hello(&mut s3).await;
    assert!(matches!(
        send_publish(&mut s3, &id, &n3, &b3).await,
        PublishReply::Ok(_)
    ));
}

/// A2b: in `--no-tls` mode a proof made for another `dev_origin` is refused.
#[tokio::test]
async fn a2b_no_tls_proof_for_another_dev_origin_is_refused() {
    let (addr, _state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    let other = keyauth::dev_origin_binding("ws://relay.example:18443").unwrap();
    match send_publish(&mut ws, &id, &nonce, &other).await {
        PublishReply::Error(e) => assert!(e.contains("AuthenticationFailed"), "{e}"),
        other => panic!("proof for another origin accepted: {other:?}"),
    }
    assert!(closed_within(&mut ws, WAIT).await);
}

/// A2b: `--no-tls` without `dev_origin` refuses to start.
#[tokio::test]
async fn a2b_no_tls_without_dev_origin_refuses_to_start() {
    let cfg = ServerConfig {
        dev_origin: None,
        ..test_config()
    };
    let e = format!("{:#}", cfg.validate().unwrap_err());
    assert!(e.contains("dev_origin"), "{e}");
    assert!(Server::new(cfg).await.is_err());
}

// ---- A3 --------------------------------------------------------------------

/// A3: a publish before any hello is refused and the connection closed.
#[tokio::test]
async fn a3_publish_before_hello_is_refused() {
    let (addr, state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut ws = connect(addr).await;
    ws.send(publish_message(&id, &[0u8; 32], &dev_binding()))
        .await
        .unwrap();
    let frames = frames_until_closed(&mut ws, WAIT).await;
    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("AuthenticationFailed")
    );
    assert!(mapped_client(&state, &id).is_none());
}

/// A3: a hello that does not offer version 2 is refused and closed.
#[tokio::test]
async fn a3_hello_without_version_2_is_refused() {
    let (addr, _state) = start(test_config()).await;
    let mut ws = connect(addr).await;
    ws.send(hello_message(vec![1])).await.unwrap();
    let frames = frames_until_closed(&mut ws, WAIT).await;
    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("VersionMismatch")
    );
    let text = format!("{frames:?}");
    assert!(text.contains("client too old; update rChat"));
}

// ---- A7 --------------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(self.0.clone())
    }
}

/// A7: a refused proof increments `rejections{reason="key_auth"}`, and no
/// log line at any level carries key material.
#[tokio::test]
async fn a7_refused_proof_counts_a_metric_and_logs_no_keys() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    // tracing-core treats a lone registered dispatcher as the global one and
    // computes callsite interest from the registering thread's default, so a
    // callsite first hit on another test thread would cache "never" for this
    // thread's subscriber too. A second, inert dispatcher kept alive for the
    // test makes it consult every live dispatcher instead.
    let _inert = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _guard = tracing::subscriber::set_default(subscriber);

    let before = metrics::rejections(metrics::REJECT_KEY_AUTH);
    let (addr, _state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    let wrong_binding = [0x99u8; 32];
    let proof = keyauth::sign_conn(&id.keys, &nonce, &wrong_binding, &id.bundle).unwrap();
    assert!(matches!(
        send_publish(&mut ws, &id, &nonce, &wrong_binding).await,
        PublishReply::Error(_)
    ));
    assert!(closed_within(&mut ws, WAIT).await);
    assert!(metrics::rejections(metrics::REJECT_KEY_AUTH) > before);

    let logs = capture.0.lock().unwrap().clone();
    let logs = String::from_utf8_lossy(&logs).to_lowercase();
    assert!(logs.contains("listening"), "capture not wired up: {logs}");
    for (what, needle) in [
        ("identity key", id.hex.clone()),
        (
            "agreement key",
            hex::encode(id.bundle.identity_agreement_key),
        ),
        ("bundle signature", hex::encode(id.bundle.bundle_signature)),
        ("connection proof", hex::encode(proof)),
        ("nonce", hex::encode(nonce)),
    ] {
        assert!(!logs.contains(&needle), "logs leak the {what}");
    }
}

// ---- A9 --------------------------------------------------------------------

/// A9: a connection proven as X that publishes Y (valid Y signatures over
/// `next_challenge`) is refused and closed; X is cleaned up as on any
/// disconnect; Y gains nothing.
#[tokio::test]
async fn a9_identity_switch_on_one_connection_is_refused() {
    let (addr, state) = start(test_config()).await;
    let x = TestIdentity::random();
    let y = TestIdentity::random();
    let mut ws = connect(addr).await;
    let next = publish(&mut ws, &x).await;
    let x_client = mapped_client(&state, &x).expect("X mapped");

    match send_publish(&mut ws, &y, &next, &dev_binding()).await {
        PublishReply::Error(e) => assert!(e.contains("AuthenticationFailed"), "{e}"),
        other => panic!("identity switch accepted: {other:?}"),
    }
    // R7 on the connection record itself is asserted deterministically in
    // `a9_refused_switch_keeps_the_proven_identity_and_stops_the_connection`
    // (here the record may already be gone by the time the error arrives).
    assert!(mapped_client(&state, &y).is_none(), "Y gained a mapping");
    assert!(closed_within(&mut ws, WAIT).await);

    let s = state.clone();
    let x_tag = tags::id_tag(&x.bytes);
    eventually("X cleaned up as on a normal disconnect", move || {
        !s.connections.contains_key(&x_client) && !s.identity_to_client.contains_key(&x_tag)
    })
    .await;
    assert!(mapped_client(&state, &y).is_none());
}

/// A9 / R7, driven through the handler on a connection record with no
/// socket (so it cannot be reaped mid-assertion): the refused switch leaves
/// the proven identity as it was, burns the nonce, marks the connection as
/// closing, and queues exactly the error and a Close.
#[tokio::test]
async fn a9_refused_switch_keeps_the_proven_identity_and_stops_the_connection() {
    const BINDING: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 32] = [0x4e; 32];
    let state = RelayState::new(Arc::new(test_config()));
    let x = TestIdentity::random();
    let y = TestIdentity::random();
    let (mut conn, mut rx) = bare_connection(BINDING);
    conn.protocol_version = 2;
    conn.auth_nonce = Some(NONCE);
    conn.proven_identity = Some(x.bytes);
    conn.identity_key = Some(x.hex.clone());
    conn.identified = true;
    let client = conn.client_id;
    state.connections.insert(client, conn);

    let proof = keyauth::sign_conn(&y.keys, &NONCE, &BINDING, &y.bundle).unwrap();
    let msg = SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        SignalingPayload::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            PublishKeyBundlePayload {
                key_bundle: key_bundle_of(&y),
                conn_signature: hex::encode(proof),
            },
        ),
    );
    handle_signaling_message(client, msg, &state).await.unwrap();

    let conn = state
        .connections
        .get(&client)
        .expect("the connection record is still there");
    assert_eq!(conn.identity_key.as_deref(), Some(x.hex.as_str()));
    assert!(conn.closing, "the refused connection is marked closing");
    assert_eq!(conn.auth_nonce, None, "the nonce is burned");
    drop(conn);
    assert_r7(&state, client, x.bytes);
    assert!(mapped_client(&state, &y).is_none(), "Y gained a mapping");

    let mut queued = Vec::new();
    while let Ok((m, _permit)) = rx.try_recv() {
        queued.push(m);
    }
    assert_eq!(queued.len(), 2, "exactly an error and a Close: {queued:?}");
    match UnifiedFrame::decode(&queued[0]) {
        Ok(UnifiedFrame::Signaling(s)) => {
            let p: crate::protocol::signaling::ErrorPayload = s.payload.deserialize_data().unwrap();
            assert_eq!(format!("{:?}", p.code), "AuthenticationFailed");
        }
        other => panic!("expected a signaling error, got {other:?}"),
    }
    assert!(matches!(queued[1], Message::Close(_)));
}

/// §4.3: once a publish fails, nothing the client pipelined behind it is
/// handled - not a valid re-publish over the same nonce, not a circuit
/// request.
#[tokio::test]
async fn pipelined_frames_after_a_failed_publish_are_never_handled() {
    let (addr, state) = start(test_config()).await;
    let x = TestIdentity::random();
    let y = TestIdentity::random();
    let offline = TestIdentity::random();
    let mut ws = connect(addr).await;
    let next = publish(&mut ws, &x).await;

    // Identity switch (refused), then a valid X re-publish over the same
    // nonce, then a circuit request to an offline peer - all in one burst.
    ws.feed(publish_message(&y, &next, &dev_binding()))
        .await
        .unwrap();
    ws.feed(publish_message(&x, &next, &dev_binding()))
        .await
        .unwrap();
    ws.feed(ask(&offline, [0x44; 32], None)).await.unwrap();
    ws.flush().await.unwrap();

    let frames = frames_until_closed(&mut ws, WAIT).await;
    assert_eq!(
        signaling_error_code(&frames).as_deref(),
        Some("AuthenticationFailed")
    );
    let replies = frames
        .iter()
        .filter(|f| matches!(f, UnifiedFrame::Signaling(_) | UnifiedFrame::Control(_)))
        .count();
    assert_eq!(replies, 1, "only the refusal is answered: {frames:?}");
    assert!(
        state.pending_asks.is_empty() && queued_knocks(&state, &offline) == 0,
        "a circuit ask after the refusal was handled"
    );
    assert!(mapped_client(&state, &y).is_none());
}

/// R1/R4: two connections proving the same identity at the same instant
/// leave exactly one mapping, pointing at a connection proven as that
/// identity; the loser closing later does not unmap the winner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_publishes_of_one_identity_leave_one_consistent_mapping() {
    fn local_addr(ws: &Ws) -> SocketAddr {
        match ws.get_ref() {
            tokio_tungstenite::MaybeTlsStream::Plain(s) => s.local_addr().unwrap(),
            _ => unreachable!("plaintext test relay"),
        }
    }
    let (addr, state) = start(test_config()).await;
    for round in 0..8 {
        let id = TestIdentity::random();
        let (mut a, mut b) = (connect(addr).await, connect(addr).await);
        let (na, nb) = (hello(&mut a).await, hello(&mut b).await);
        let (ia, ib) = (id.clone(), id.clone());
        let ta = tokio::spawn(async move {
            let r = send_publish(&mut a, &ia, &na, &dev_binding()).await;
            (a, r)
        });
        let tb = tokio::spawn(async move {
            let r = send_publish(&mut b, &ib, &nb, &dev_binding()).await;
            (b, r)
        });
        let ((a, ra), (b, rb)) = (ta.await.unwrap(), tb.await.unwrap());
        assert!(matches!(ra, PublishReply::Ok(_)), "round {round}: {ra:?}");
        assert!(matches!(rb, PublishReply::Ok(_)), "round {round}: {rb:?}");

        let winner = mapped_client(&state, &id).expect("mapped");
        let winner_addr = {
            let conn = state.connections.get(&winner).expect("winner connected");
            assert_eq!(conn.proven_identity, Some(id.bytes), "round {round}: R1");
            assert_eq!(conn.identity_key.as_deref(), Some(id.hex.as_str()));
            conn._addr
        };
        let (mut loser, winner_ws) = if local_addr(&a) == winner_addr {
            (b, a)
        } else {
            (a, b)
        };
        loser.close(None).await.unwrap();
        let s = state.clone();
        let (w, idb) = (winner, id.bytes);
        eventually("loser gone", move || {
            s.connections
                .iter()
                .filter(|c| c.proven_identity == Some(idb) && *c.key() != w)
                .count()
                == 0
        })
        .await;
        assert_eq!(
            mapped_client(&state, &id),
            Some(winner),
            "round {round}: the loser's close unmapped the winner"
        );
        drop(winner_ws);
    }
}

// ---- K1 (relay side) ---------------------------------------------------------

/// K1: the relay links the same keyauth code and reproduces the golden
/// vectors byte for byte.
#[test]
fn k1_relay_reproduces_the_core_golden_vectors() {
    let a = IdentityKeyPair::from_seed(&golden::seed_a()).unwrap();
    let b = IdentityKeyPair::from_seed(&golden::seed_b()).unwrap();
    let ba = keyauth::sign_bundle(&a).unwrap();
    let bb = keyauth::sign_bundle(&b).unwrap();
    assert_eq!(
        hex::encode(ba.identity_key),
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    );
    assert_eq!(
        hex::encode(bb.identity_key),
        "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
    );
    assert_eq!(
        hex::encode(ba.bundle_signature),
        "757d468b446b196d23b8bf1a1519df6c59460c127185f1c9cda4d0694eaeffc5801f480abe88e57d255de0a94e3af05bcce8490185423cbdce8f11e722c20202"
    );
    let ct = keyauth::conn_transcript(&golden::NONCE, &golden::BINDING, &ba).unwrap();
    assert_eq!(
        hex::encode(ct),
        "72636861742f636f6e6e2d617574682f7631004e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e424242424242424242424242424242424242424242424242424242424242424203a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254757d468b446b196d23b8bf1a1519df6c59460c127185f1c9cda4d0694eaeffc5801f480abe88e57d255de0a94e3af05bcce8490185423cbdce8f11e722c20202"
    );
    let cs = keyauth::sign_conn(&a, &golden::NONCE, &golden::BINDING, &ba).unwrap();
    assert_eq!(
        hex::encode(cs),
        "5706c4c3096a4fa75addb47103cfbe9b0ed489bf3216f6f85ee3d3d0d541e81e52b0e7c122b634e2461f7ee4e4a9a43e2061f6bcce4f9b3a6e4d7c4d02f2d20d"
    );
    let env = x25519_dalek::StaticSecret::from(golden::ENV_EPH_SECRET);
    let env_pub = x25519_dalek::PublicKey::from(&env).to_bytes();
    let keys = keyauth::knock_keys(
        a.agreement_secret(),
        &bb.identity_agreement_key,
        &env_pub,
        &ba.identity_key,
        &bb.identity_key,
    )
    .unwrap();
    assert_eq!(
        hex::encode(keys.k_mac),
        "4a649bbf8ffdaac549ee4df04f3c16a67b520ce45a8f0f7b552b25f34b0ff63b"
    );
    assert_eq!(
        hex::encode(keys.k_intro),
        "026a515c2fd7cdab458c6b36f12e264b9b39d469242a6d5a757d9768f4e4bbd9"
    );
    let mac = keyauth::knock_mac(&keys.k_mac, &bb.identity_key, &ba, golden::ISSUED_HOUR).unwrap();
    assert_eq!(
        hex::encode(mac),
        "d1062fec33ae743591f1158f3b85f8c3b980dd906b33c8820754db8e0d0614fc"
    );
    assert_eq!(
        hex::encode(keyauth::dev_origin_binding("ws://127.0.0.1:8443").unwrap()),
        "dc0d2d9890cc672819a084e35d4f242202c9bb548e2f76d0fa3222b9a9475725"
    );
}

// ---- RF1 (mapping part) --------------------------------------------------------

/// RF1: the same identity proven on a second connection (a phone switching
/// networks before the old socket is reaped) takes over the routing slot;
/// the old socket closing later does not unmap it.
#[tokio::test]
async fn rf1_second_connection_proving_same_identity_takes_over_mapping() {
    let (addr, state) = start(test_config()).await;
    let id = TestIdentity::random();
    let mut first = authed(addr, &id).await;
    let c1 = mapped_client(&state, &id).expect("first mapped");
    let _second = authed(addr, &id).await;
    let c2 = mapped_client(&state, &id).expect("second mapped");
    assert_ne!(c1, c2, "the newer connection owns the mapping");
    assert_eq!(
        state.connections.get(&c2).and_then(|c| c.proven_identity),
        Some(id.bytes),
        "R1: mapping points at a connection proven as this identity"
    );

    first.close(None).await.unwrap();
    let s = state.clone();
    eventually("first connection gone", move || {
        !s.connections.contains_key(&c1)
    })
    .await;
    assert_eq!(
        mapped_client(&state, &id),
        Some(c2),
        "old close kept the new mapping"
    );
}

/// Say hello and return the full hello_response payload.
async fn hello_payload<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> HelloResponsePayload
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ws.send(hello_message(vec![2])).await.expect("send hello");
    let reply = next_signaling(ws, MSG_TYPE_HELLO_RESPONSE, WAIT)
        .await
        .expect("hello_response");
    reply.payload.deserialize_data().expect("hello payload")
}

/// Verify `p.relay_identity` against `binding` and `p.auth_challenge`.
fn relay_identity_verifies(p: &HelloResponsePayload, binding: &[u8; 32]) -> bool {
    let info = p.relay_identity.as_ref().expect("relay_identity");
    let key: [u8; 32] = hex::decode(&info.key).unwrap().try_into().unwrap();
    let sig: [u8; 64] = hex::decode(&info.signature).unwrap().try_into().unwrap();
    let challenge: [u8; 32] = hex::decode(p.auth_challenge.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    rchat_core::relay_pin::verify_relay_auth(&key, binding, &challenge, info.version, &sig).is_ok()
}

/// RP9: hello_response carries a relay identity signed over this
/// connection's channel binding and challenge; two connections differ.
#[tokio::test]
async fn rp9_relay_identity_signed_per_connection() {
    let (addr, _state) = start(test_config()).await;
    let mut a = connect(addr).await;
    let mut b = connect(addr).await;
    let (pa, pb) = (hello_payload(&mut a).await, hello_payload(&mut b).await);
    let (ia, ib) = (
        pa.relay_identity.clone().expect("relay_identity"),
        pb.relay_identity.clone().expect("relay_identity"),
    );
    assert_eq!(ia.key, ib.key, "one relay identity");
    assert_ne!(ia.signature, ib.signature, "per-connection proof");
    assert!(relay_identity_verifies(&pa, &dev_binding()));
    assert!(
        !relay_identity_verifies(&pa, &[0u8; 32]),
        "bound to the binding"
    );
}

/// RP9 over real TLS: the relay signs the TLS exporter the client sees, so a
/// TLS-terminating middlebox cannot relay the proof.
#[tokio::test]
async fn rp9_relay_identity_bound_to_tls_exporter() {
    let (addr, _state) = tls_relay().await;
    let (mut ws, binding) = tls_ws(addr).await;
    let p = hello_payload(&mut ws).await;
    assert!(relay_identity_verifies(&p, &binding));
}

/// RP12 (round-2 M7): a connection proof over the wrong binding gets the
/// distinct "does not match this TLS session" error.
#[tokio::test]
async fn rp12_wrong_binding_gets_the_tls_termination_error() {
    let (addr, _state) = start(test_config()).await;
    let mut ws = connect(addr).await;
    let nonce = hello(&mut ws).await;
    let id = TestIdentity::from_seed(0x61);
    ws.send(publish_message(&id, &nonce, &[0u8; 32]))
        .await
        .unwrap(); // not this connection's binding
    let err = next_signaling(&mut ws, MSG_TYPE_ERROR, WAIT)
        .await
        .expect("error");
    let p: ErrorPayload = err.payload.deserialize_data().unwrap();
    assert!(
        p.message.contains("does not match this TLS session"),
        "{}",
        p.message
    );
}

/// RP12: other refusals keep the generic message.
#[tokio::test]
async fn rp12_other_refusals_keep_the_generic_error() {
    let (addr, _state) = start(test_config()).await;
    let mut ws = connect(addr).await;
    let id = TestIdentity::from_seed(0x62);
    // No hello, so no challenge: refused before any proof is checked.
    ws.send(publish_message(&id, &[0u8; 32], &dev_binding()))
        .await
        .unwrap();
    let err = next_signaling(&mut ws, MSG_TYPE_ERROR, WAIT)
        .await
        .expect("error");
    let p: ErrorPayload = err.payload.deserialize_data().unwrap();
    assert_eq!(p.message, "key authentication failed");
}

/// R-9: a knock delivered live the moment the publish maps the identity
/// (the hook runs right after the routing slot is inserted) still reaches
/// the wire after the publish response, so the client does not drop it.
#[tokio::test]
async fn r9_a_live_knock_racing_the_publish_follows_the_response() {
    const BINDING: [u8; 32] = [0x43; 32];
    const NONCE: [u8; 32] = [0x4f; 32];
    let state = RelayState::new(Arc::new(test_config()));
    let x = TestIdentity::random();
    let (mut conn, mut rx) = bare_connection(BINDING);
    conn.protocol_version = 2;
    conn.auth_nonce = Some(NONCE);
    let client = conn.client_id;
    state.connections.insert(client, conn);

    let hook_state = state.clone();
    let x_tag = tags::id_tag(&x.bytes);
    super::tests_hook::set_after_identity_mapped(move || {
        circuits::deliver_knock(x_tag, PairTag([9; 32]), knock(0x77), None, &hook_state);
    });
    let proof = keyauth::sign_conn(&x.keys, &NONCE, &BINDING, &x.bundle).unwrap();
    let msg = SignalingMessage::new(
        MSG_TYPE_PUBLISH_KEY_BUNDLE,
        SignalingPayload::new(
            MSG_TYPE_PUBLISH_KEY_BUNDLE,
            PublishKeyBundlePayload {
                key_bundle: key_bundle_of(&x),
                conn_signature: hex::encode(proof),
            },
        ),
    );
    handle_signaling_message(client, msg, &state).await.unwrap();

    let mut queued = Vec::new();
    while let Ok((m, _permit)) = rx.try_recv() {
        queued.push(UnifiedFrame::decode(&m).expect("relay frame"));
    }
    assert_eq!(queued.len(), 2, "the response and the knock: {queued:?}");
    assert!(
        matches!(&queued[0], UnifiedFrame::Signaling(s)
            if s.msg_type == MSG_TYPE_PUBLISH_KEY_BUNDLE_RESPONSE),
        "first frame is the publish response: {queued:?}"
    );
    assert!(matches!(
        &queued[1],
        UnifiedFrame::Control(ControlMessage::QueuedMessage { .. })
    ));
}
