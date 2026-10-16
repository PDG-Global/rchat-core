//! Spec §D.1 in the client: the lifetime of the TLS ticket store held by
//! the client, and that no ticket ever reaches the state store.

use crate::relay_pin::{encode_pin, sign_relay_link};
use crate::test_support::*;
use crate::tls_resumption::test_server::TestTlsServer;
use crate::ClientInner;
use ed25519_dalek::SigningKey;

/// A runtime for the TLS server, kept alive by the caller.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Point `inner` at `server` (pinned to `pin`) and give it the tickets of a
/// real TLS connection to it, as `connect()` does.
fn give_tickets(
    rt: &tokio::runtime::Runtime,
    inner: &mut ClientInner,
    server: &TestTlsServer,
    pin: Option<String>,
) {
    inner.config.server_url = format!("wss://localhost:{}/", server.port());
    inner.config.relay_pin = pin;
    inner.bind_tls_tickets();
    let store = inner.tls_tickets.clone();
    rt.block_on(async { drop(server.dial(&store).await) });
    assert!(!inner.tls_tickets.is_empty(), "tickets taken in");
}

fn test_relay_pin() -> String {
    encode_pin(&test_relay().verifying_key().to_bytes())
}

/// The store goes with `disconnect()` and with every change of relay (host,
/// port or pin), with a refused relay and with the identity; it stays for a
/// transport-only reconnect, which is what it is for.
#[test]
fn store_dropped_on_disconnect_and_relay_switch() {
    let rt = runtime();
    let server = rt.block_on(TestTlsServer::start(true, false));
    let other = rt.block_on(TestTlsServer::start(true, false));

    // disconnect_transport_only keeps the tickets; disconnect() drops them.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    let client = wrap(inner);
    let held = client.tls_ticket_count();
    client.disconnect_transport_only().unwrap();
    assert_eq!(client.tls_ticket_count(), held, "kept for a fast reconnect");
    client.disconnect().unwrap();
    assert_eq!(client.tls_ticket_count(), 0, "disconnect() drops tickets");

    // Relay switch: another port (or host) drops every ticket.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    inner.config.server_url = format!("wss://localhost:{}/", other.port());
    inner.bind_tls_tickets();
    assert!(inner.tls_tickets.is_empty(), "relay switch drops tickets");
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    inner.config.server_url = format!("wss://127.0.0.1:{}/", server.port());
    inner.bind_tls_tickets();
    assert!(inner.tls_tickets.is_empty(), "another host drops tickets");

    // Pin change by a valid relay rotation: the relay is accepted and the
    // tickets held under the old pin are dropped.
    let old = SigningKey::from_bytes(&[0x21; 32]);
    let link = sign_relay_link(&old, &test_relay().verifying_key().to_bytes(), 1);
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(
        &rt,
        &mut inner,
        &server,
        Some(encode_pin(&old.verifying_key().to_bytes())),
    );
    inner.config.relay_pin_version = Some(0);
    feed_signaling(
        &mut inner,
        hello_response_from([0x4e; 32], &test_relay(), 1, &[link]),
    );
    assert!(inner.is_connected, "rotation accepted");
    assert_eq!(inner.config.relay_pin, Some(test_relay_pin()));
    assert!(inner.tls_tickets.is_empty(), "pin change drops tickets");

    // First use (no pin yet): the pin it learns is a change too.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, None);
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected);
    assert!(inner.tls_tickets.is_empty(), "first pin drops tickets");

    // The same pin proved again keeps them.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    let held = inner.tls_tickets.len();
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(inner.is_connected);
    assert_eq!(inner.tls_tickets.len(), held, "same pin: kept");

    // A relay that fails the pin check (resumed or not): refused, and
    // nothing from it is offered again.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(
        &rt,
        &mut inner,
        &server,
        Some(encode_pin(&old.verifying_key().to_bytes())),
    );
    feed_signaling(&mut inner, hello_response([0x4e; 32]));
    assert!(!inner.is_connected, "wrong relay identity refused");
    assert!(
        inner.tls_tickets.is_empty(),
        "refused relay: tickets dropped"
    );

    // Identity wipe (Reset Identity) and identity change.
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    inner.clear_state_now();
    assert!(inner.tls_tickets.is_empty(), "identity wipe drops tickets");
    let (mut inner, _rx) = inner_with_identity(0xA1);
    give_tickets(&rt, &mut inner, &server, Some(test_relay_pin()));
    inner.websocket = None;
    inner.is_connected = false;
    let client = wrap(inner);
    client.generate_identity_from_seed(&[0x33; 32]).unwrap();
    assert_eq!(client.tls_ticket_count(), 0, "new identity drops tickets");
}

/// Tickets are memory only: with a state store attached and records
/// written, no write carries a ticket or a session's resumption master
/// secret, sealed or opened.
#[test]
fn tickets_never_persisted() {
    let rt = runtime();
    let server = rt.block_on(TestTlsServer::start(true, false));
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    give_tickets(&rt, &mut p.a, &server, Some(test_relay_pin()));
    // A second connection: tickets from a resumed session too.
    let store = p.a.tls_tickets.clone();
    rt.block_on(async { assert!(server.dial(&store).await.session_reused()) });
    let tickets = p.a.tls_tickets.ticket_bytes();
    assert!(!tickets.is_empty() && tickets.iter().all(|t| t.len() >= 32));
    // The resumption master secrets too: a persisted secret would be as bad
    // as a persisted ticket (and worse for past traffic).
    let secrets = p.a.tls_tickets.master_keys();
    assert!(secrets.len() == tickets.len() && secrets.iter().all(|k| k.len() >= 32));
    let needles: Vec<&[u8]> = tickets
        .iter()
        .chain(secrets.iter())
        .flat_map(|t| [&t[..], &t[..16]])
        .collect();

    // Records written after the tickets exist: the peer, meta, deferred.
    sa.history.lock().unwrap().clear();
    push_text(&p.a, &p.pb.hex, "after the tickets");
    p.a.persist_peer(&p.pb.hex).unwrap();
    p.a.persist_meta();
    p.a.flush_deferred_writes();
    let history = sa.history.lock().unwrap().clone();
    assert!(!history.is_empty(), "records were written");

    let keys = crate::state_store::StateKeys::new(TEST_STATE_KEY);
    let our_ik = peer(0xA1).bundle.identity_key;
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    for (key, sealed) in &history {
        assert!(crate::state_store::is_valid_record_key(key), "{key}");
        let body = if sealed.is_empty() {
            Vec::new()
        } else {
            keys.open(&our_ik, key, sealed)
                .expect("our record")
                .2
                .to_vec()
        };
        // Each ticket and secret, whole and its first 16 bytes, sealed or
        // opened.
        for needle in &needles {
            assert!(!contains(sealed, needle), "ticket or secret in {key}");
            assert!(!contains(&body, needle), "ticket or secret in {key}");
        }
    }
}
