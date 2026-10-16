//! Offline queue v2 (spec §5.3, §5.5): record shape, strict TTL, the asker
//! quota end to end, the legacy file wipe and the removed plaintext path.

use super::test_support::{
    ask, ask_each_other, authed, created, eventually, next_control, queue_test_message, relay_on,
    start, test_config, TestIdentity,
};
use super::*;
use std::io::Read;

/// Exhaustive destructure: adding a field to the record breaks this test (M1).
/// The spec's three fields plus `knock_seq`, a memory-only knock-accounting
/// counter (0 for messages) that is never persisted and names nobody; Task 10
/// checks that the persisted record is exactly the spec's three fields.
fn assert_record_fields(m: &StoredMessage) -> (&Vec<u8>, u64, bool, u64) {
    let StoredMessage {
        payload,
        enqueued_at_unix_secs,
        is_knock,
        knock_seq,
    } = m;
    (payload, *enqueued_at_unix_secs, *is_knock, *knock_seq)
}

#[tokio::test]
async fn m1_stored_records_hold_only_payload_time_and_kind() {
    let (addr, state) = start(test_config()).await;
    let (a, b) = (TestIdentity::from_seed(0x91), TestIdentity::from_seed(0x92));
    let mut wa = authed(addr, &a).await;
    let mut wb = authed(addr, &b).await;
    ask_each_other(&state, &mut wa, &a, &mut wb, &b).await;
    let ca = created(&mut wa).await;
    drop(wb);
    let st = state.clone();
    let bb = b.bytes;
    eventually("B gone", move || {
        !st.connections.iter().any(|c| c.proven_identity == Some(bb))
    })
    .await;

    let mut payload = vec![0x02];
    payload.extend_from_slice(&[0x5e; 16]);
    payload.resize(200, 0x11);
    wa.send(relay_on(ca.2, &ca.1, payload.clone()))
        .await
        .unwrap();
    let st = state.clone();
    let btag = tags::id_tag(&b.bytes);
    eventually("queued", move || st.message_queues.get(&btag).is_some()).await;

    let q = state.message_queues.get(&tags::id_tag(&b.bytes)).unwrap();
    let (p, at, knock, seq) = assert_record_fields(&q.pending[0]);
    assert_eq!(
        p, &payload,
        "the record is the sealed payload, byte for byte"
    );
    assert!(!knock);
    assert_eq!(seq, 0);
    assert!(crate::protocol::timestamp().abs_diff(at) <= 5);
}

#[tokio::test]
async fn messages_expire_by_strict_comparison_with_the_stored_time() {
    let server = Server::new(test_config()).await.unwrap();
    let state = server.state();
    let ttl = state.config.offline_queue.ttl_secs;
    let tag = tags::id_tag(&TestIdentity::from_seed(0x93).bytes);
    let msg = |at: u64| StoredMessage {
        payload: vec![0x02; 200],
        enqueued_at_unix_secs: at,
        is_knock: false,
        knock_seq: 0,
    };
    let now = 10_000_000u64;
    let pending = vec![msg(now - ttl), msg(now - ttl - 1), msg(now + 3_600)];
    let bytes: usize = pending.iter().map(StoredMessage::budget_cost).sum();
    state.offline_budget.force_add(bytes);
    state
        .message_queues
        .insert(tag, MessageQueue { pending, bytes });

    expire_queues(now, &state);
    let q = state.message_queues.get(&tag).unwrap();
    let kept: Vec<u64> = q.pending.iter().map(|m| m.enqueued_at_unix_secs).collect();
    assert_eq!(
        kept,
        vec![now - ttl, now + 3_600],
        "age == ttl kept, ttl+1 dropped, future kept"
    );
}

#[tokio::test]
async fn q7_over_quota_ask_is_not_queued_but_still_matches() {
    let (addr, state) = start(ServerConfig {
        max_pending_circuit_targets: 1_000,
        max_pending_per_connection: 200,
        ..test_config()
    })
    .await;
    let a = TestIdentity::from_seed(0x94);
    let mut wa = authed(addr, &a).await;
    let targets: Vec<TestIdentity> = (0..101).map(|_| TestIdentity::random()).collect();
    for t in &targets {
        wa.send(ask(t, rand::random(), None)).await.unwrap();
    }
    let st = state.clone();
    eventually("101 pending asks", move || st.pending_asks.len() == 101).await;
    // A pending ask is recorded before its knock is filed: a barrier on the
    // same connection (asks run in order) makes sure the 101st ask is done,
    // so "not queued" can't pass early (Task 9 minor).
    wa.send(ask(&a, rand::random(), None)).await.unwrap();
    assert!(matches!(
        next_control(&mut wa, std::time::Duration::from_secs(5)).await,
        Some(ControlMessage::Error { .. })
    ));
    let knock_count = |t: &TestIdentity| {
        state
            .message_queues
            .get(&tags::id_tag(&t.bytes))
            .map(|q| q.pending.iter().filter(|m| m.is_knock).count())
            .unwrap_or(0)
    };
    assert_eq!(knock_count(&targets[99]), 1, "100th new entry queued");
    assert_eq!(knock_count(&targets[100]), 0, "101st new entry not queued");

    // The pending ask still matches when the 101st target asks back.
    let mut wt = authed(addr, &targets[100]).await;
    wt.send(ask(&a, rand::random(), None)).await.unwrap();
    let _ = created(&mut wt).await;
    let _ = created(&mut wa).await;
}

#[test]
fn knock_ttl_hours_follow_the_offline_queue_ttl() {
    let mut config = ServerConfig::default();
    assert_eq!(key_auth::knock_ttl_hours(&config), 72);
    config.offline_queue.ttl_secs = 3_600;
    assert_eq!(key_auth::knock_ttl_hours(&config), 1);
    // Defence in depth: `validate` refuses a TTL over 72 h (R33 M-6), but
    // the knock cap must hold even for a config built without it.
    config.offline_queue.ttl_secs = 604_800;
    assert_eq!(
        key_auth::knock_ttl_hours(&config),
        72,
        "knock TTL is capped at 72 h"
    );
}

#[test]
fn legacy_plaintext_queue_file_is_zero_filled_and_unlinked() {
    let dir = std::env::temp_dir().join(format!("rchat-legacy-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("message_queues.json");
    let secret = b"{\"queues\":[{\"identity\":\"secret-identity\"}]}";
    std::fs::write(&path, secret).unwrap();
    let mut still_open = std::fs::File::open(&path).unwrap();

    assert!(wipe_legacy_queue_file(&path).unwrap());
    assert!(!path.exists(), "unlinked");
    let mut contents = Vec::new();
    still_open.read_to_end(&mut contents).unwrap();
    assert_eq!(contents.len(), secret.len());
    assert!(
        contents.iter().all(|b| *b == 0),
        "zero-filled before unlink"
    );
    assert!(
        !wipe_legacy_queue_file(&path).unwrap(),
        "absent file: nothing to do"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn legacy_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rchat-legacy-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn legacy_wipe_never_follows_a_symlink() {
    let dir = legacy_dir();
    let target = dir.join("precious.json");
    let original = b"{\"queues\":[], \"keep\": \"me\"}";
    std::fs::write(&target, original).unwrap();
    let link = dir.join("message_queues.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(
        wipe_legacy_queue_file(&link).is_err(),
        "a symlink is refused"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        original,
        "target untouched"
    );
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "the link is left in place"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_wipe_refuses_a_directory_and_a_file_that_is_not_queue_json() {
    let dir = legacy_dir();
    let sub = dir.join("message_queues.json");
    std::fs::create_dir_all(&sub).unwrap();
    assert!(
        wipe_legacy_queue_file(&sub).is_err(),
        "a directory is refused"
    );
    assert!(sub.is_dir());

    let other = dir.join("other.json");
    let contents = b"[1, 2, 3] not a queue";
    std::fs::write(&other, contents).unwrap();
    assert!(
        wipe_legacy_queue_file(&other).is_err(),
        "unknown content refused"
    );
    assert_eq!(std::fs::read(&other).unwrap(), contents, "left intact");

    let pretty = dir.join("pretty.json");
    std::fs::write(&pretty, b"{\n  \"queues\": [],\n  \"saved_at\": 1\n}").unwrap();
    assert!(
        wipe_legacy_queue_file(&pretty).unwrap(),
        "pretty JSON is the old format"
    );
    assert!(!pretty.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// P3: the plaintext save path no longer exists.
#[test]
fn p3_plaintext_queue_persistence_code_is_gone() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/signaling/mod.rs"))
        .unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for symbol in [
        "save_queues_to_disk",
        "PersistedQueues ",
        "PersistedQueues {",
        "StoredMessageSerializable",
        "message_queues.json\")",
    ] {
        assert!(
            !code.contains(symbol),
            "plaintext persistence symbol still present: {symbol}"
        );
    }
}

/// H3 / L2: a knock flood is charged only to the knock store — the message
/// charge of every recipient stays exactly what its messages cost, its
/// messages stay queued — and knocks expire at the knock TTL (72 h), well
/// before the 7-day message TTL configured here.
#[tokio::test]
async fn knock_flood_leaves_the_message_budget_untouched_and_expires_at_the_knock_ttl() {
    let mut config = test_config();
    // Defence in depth: `validate` refuses a TTL over 72 h (R33 M-6); this
    // config is built without it to show knocks still expire at their own
    // 72 h cap whatever the message TTL.
    config.offline_queue.ttl_secs = 604_800;
    config.offline_queue.knock_budget_bytes = 64 * validate::KNOCK_BYTES;
    let server = Server::new(config).await.unwrap();
    let state = server.state();
    let knock_ttl = state.config.knock_ttl_secs();
    assert_eq!(knock_ttl, 259_200, "knock TTL capped at 72 h");

    let targets: Vec<TestIdentity> = (0..3).map(|i| TestIdentity::from_seed(0xa0 + i)).collect();
    for t in &targets {
        queue_test_message(&state, t, vec![0x02; 300]);
    }
    let charge = |t: &TestIdentity| {
        let q = state.message_queues.get(&tags::id_tag(&t.bytes)).unwrap();
        let msgs = q.pending.iter().filter(|m| !m.is_knock).count();
        (q.bytes, msgs)
    };
    let before: Vec<(usize, usize)> = targets.iter().map(charge).collect();
    assert!(before.iter().all(|(bytes, n)| *bytes > 0 && *n == 1));

    let t0 = crate::protocol::timestamp();
    for i in 0..1_000u32 {
        let target = tags::id_tag(&targets[(i % 3) as usize].bytes);
        let mut knock = vec![(i % 251) as u8; validate::KNOCK_BYTES];
        knock[0] = validate::KNOCK_VERSION;
        circuits::deliver_knock(target, PairTag(rand::random()), knock, None, &state);
    }
    let after: Vec<(usize, usize)> = targets.iter().map(charge).collect();
    assert_eq!(after, before, "no message charge moved, no message evicted");
    assert!(
        state.knocks.used() <= 64 * validate::KNOCK_BYTES,
        "knock budget holds"
    );
    let knocks: usize = targets
        .iter()
        .map(|t| state.knocks.count_for(tags::id_tag(&t.bytes)))
        .sum();
    assert_eq!(knocks, 64, "the knock budget is full of the newest knocks");

    // Age == knock TTL: kept (strict comparison).
    expire_queues(t0 + knock_ttl, &state);
    assert_eq!(state.knocks.used(), 64 * validate::KNOCK_BYTES);
    // Past the knock TTL: every knock gone; the messages (7-day TTL) stay.
    let now = crate::protocol::timestamp();
    expire_queues(now + knock_ttl + 1, &state);
    assert_eq!(state.knocks.used(), 0);
    assert_eq!(state.knocks.index_len(), 0);
    for t in &targets {
        let q = state.message_queues.get(&tags::id_tag(&t.bytes)).unwrap();
        assert!(q.pending.iter().all(|m| !m.is_knock), "knocks expired");
    }
    let expired_after: Vec<(usize, usize)> = targets.iter().map(charge).collect();
    assert_eq!(expired_after, before, "messages kept past the knock TTL");
}

/// The asker quota is no presence oracle: an attacker spends 99 new asks on
/// never-online ids, asks T, then asks its own offline C and looks for C's
/// knock. Whether T is online (live knock) or offline (stored knock), T's
/// ask costs the same, and C's ask is over quota either way: no knock for C,
/// live or stored. T's knock itself arrives on both paths.
#[tokio::test]
async fn q7_asker_quota_costs_the_same_for_online_and_offline_targets() {
    async fn probe(t_online: bool) -> (bool, bool) {
        let (addr, state) = start(ServerConfig {
            max_pending_circuit_targets: 1_000,
            max_pending_per_connection: 200,
            ..test_config()
        })
        .await;
        let a = TestIdentity::random();
        let t = TestIdentity::random();
        let c = TestIdentity::random();
        let mut wa = authed(addr, &a).await;
        let mut wt = if t_online {
            Some(authed(addr, &t).await)
        } else {
            None
        };
        for _ in 0..99 {
            wa.send(ask(&TestIdentity::random(), rand::random(), None))
                .await
                .unwrap();
        }
        wa.send(ask(&t, rand::random(), None)).await.unwrap();
        wa.send(ask(&c, rand::random(), None)).await.unwrap();
        // A re-ask of C must not slip a knock past the quota either.
        wa.send(ask(&c, rand::random(), None)).await.unwrap();
        let st = state.clone();
        eventually("101 pending asks", move || st.pending_asks.len() == 101).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let t_got = match wt.as_mut() {
            Some(ws) => loop {
                match next_control(ws, Duration::from_secs(2)).await {
                    Some(ControlMessage::QueuedMessage { .. }) => break true,
                    Some(_) => continue,
                    None => break false,
                }
            },
            None => state
                .message_queues
                .get(&tags::id_tag(&t.bytes))
                .is_some_and(|q| q.pending.iter().any(|m| m.is_knock)),
        };
        let c_got = state
            .message_queues
            .get(&tags::id_tag(&c.bytes))
            .is_some_and(|q| q.pending.iter().any(|m| m.is_knock));
        (t_got, c_got)
    }
    let online = probe(true).await;
    let offline = probe(false).await;
    assert_eq!(online, (true, false), "T knocked live; C over quota");
    assert_eq!(offline, (true, false), "T knock stored; C over quota");
}

/// R-10: relay packets (acknowledged to their senders) and queued records
/// still in a dead connection's outbound queue go back to the front of the
/// identity's offline queue, in order; other frames are discarded.
#[tokio::test]
async fn unsent_relayed_messages_of_a_dead_connection_are_requeued() {
    let state = RelayState::new(Arc::new(test_config()));
    let x = TestIdentity::random();
    queue_test_message(&state, &x, vec![0x02, 0xee]); // queued later, by someone else
    let (tx, rx, _kill) = ConnTx::channel();
    let relay = |b: u8| {
        UnifiedFrame::relay(RelayPacket::new(CircuitId::generate(), vec![0x02, b])).encode()
    };
    tx.send(relay(1)).unwrap();
    tx.send(FrameBuilder::queued_message(vec![0x02, 2]).encode())
        .unwrap();
    tx.send(FrameBuilder::error(ControlErrorCode::RateLimited, "x").encode())
        .unwrap();
    tx.send(relay(3)).unwrap();

    salvage_unsent(None, rx, tags::id_tag(&x.bytes), &state).await;

    let q = state.message_queues.get(&tags::id_tag(&x.bytes)).unwrap();
    let payloads: Vec<Vec<u8>> = q.pending.iter().map(|m| m.payload.clone()).collect();
    assert_eq!(
        payloads,
        vec![
            vec![0x02, 1],
            vec![0x02, 2],
            vec![0x02, 3],
            vec![0x02, 0xee]
        ]
    );
    assert!(q.pending.iter().all(|m| !m.is_knock));
}

/// A relay frame carrying `len` bytes of payload starting with `b`.
fn relay_frame(b: u8, len: usize) -> Message {
    let mut payload = vec![b; len];
    payload[0] = 0x02;
    UnifiedFrame::relay(RelayPacket::new(CircuitId::generate(), payload)).encode()
}

/// M-1: salvaged messages are re-admitted through the relay-wide offline
/// budget; what does not fit is dropped, and the budget never exceeds its
/// cap (it used to be force-added, uncapped).
#[tokio::test]
async fn salvage_is_admitted_through_the_offline_budget() {
    let mut config = test_config();
    config.offline_queue_max_total_bytes = 2_000;
    let state = RelayState::new(Arc::new(config));
    // Someone else's queue already holds 1,064 of the 2,000 bytes.
    queue_test_message(&state, &TestIdentity::random(), vec![0x02; 1_000]);
    let x = TestIdentity::random();
    let (tx, rx, _kill) = ConnTx::channel();
    for b in 0..10u8 {
        tx.send(relay_frame(b, 200)).unwrap(); // 264 budget bytes each
    }

    salvage_unsent(None, rx, tags::id_tag(&x.bytes), &state).await;

    assert!(
        state.offline_budget.used() <= 2_000,
        "offline budget overrun: {}",
        state.offline_budget.used()
    );
    let q = state.message_queues.get(&tags::id_tag(&x.bytes)).unwrap();
    assert_eq!(q.pending.len(), 3, "only what fits in the budget");
    assert_eq!(q.bytes, 3 * 264);
    assert_eq!(state.offline_budget.used(), 1_064 + 3 * 264);
    // The oldest salvaged messages are the ones kept.
    let firsts: Vec<u8> = q.pending.iter().map(|m| m.payload[1]).collect();
    assert_eq!(firsts, vec![0, 1, 2]);
}

/// M-1: the per-recipient byte cap applies to salvage as well, and a
/// salvaged knock goes back to the knock store, not the message budget.
#[tokio::test]
async fn salvage_respects_the_per_recipient_cap_and_keeps_knocks_as_knocks() {
    let mut config = test_config();
    config.offline_queue_max_bytes_per_recipient = 600;
    let state = RelayState::new(Arc::new(config));
    let x = TestIdentity::random();
    let (tx, rx, _kill) = ConnTx::channel();
    for b in 0..5u8 {
        tx.send(relay_frame(b, 200)).unwrap();
    }
    tx.send(FrameBuilder::queued_message(super::test_support::knock(0x33)).encode())
        .unwrap();

    salvage_unsent(None, rx, tags::id_tag(&x.bytes), &state).await;

    let q = state.message_queues.get(&tags::id_tag(&x.bytes)).unwrap();
    let messages = q.pending.iter().filter(|m| !m.is_knock).count();
    assert_eq!(messages, 2, "600 bytes hold two 264-byte messages");
    assert_eq!(q.bytes, 2 * 264);
    assert_eq!(state.offline_budget.used(), 2 * 264);
    assert_eq!(q.pending.iter().filter(|m| m.is_knock).count(), 1);
    drop(q);
    assert_eq!(state.knocks.count_for(tags::id_tag(&x.bytes)), 1);
    assert_eq!(state.knocks.used(), validate::KNOCK_BYTES);
}

/// M-2 (R-4's denial effect, through the real ask handler): one source
/// churning through new identities cannot stop another source's first
/// contact. Its askers beyond its share of the quota table get no knock;
/// the other source's knock is still stored for the offline target.
#[tokio::test]
async fn an_asker_quota_flood_from_one_source_does_not_deny_other_sources() {
    use super::test_support::{ask_direct, proven_bare, queued_knocks, source_key};
    let state = RelayState {
        knocks: Arc::new(knock_store::KnockStore::with_quota_cap(16 << 20, 64)),
        ..RelayState::new(Arc::new(test_config()))
    };
    let mut keep = Vec::new();
    let flood_target = TestIdentity::random();
    for _ in 0..100 {
        let id = TestIdentity::random();
        let (c, rx) = proven_bare(&state, &id, Some(source_key(1)));
        keep.push(rx);
        ask_direct(&state, c, &flood_target).await;
    }
    assert_eq!(
        state.knocks.quota_len(),
        64 / knock_store::QUOTA_SOURCE_SHARES
    );

    let (asker, target) = (TestIdentity::random(), TestIdentity::random());
    let (c, rx) = proven_bare(&state, &asker, Some(source_key(2)));
    keep.push(rx);
    ask_direct(&state, c, &target).await;
    assert_eq!(
        queued_knocks(&state, &target),
        1,
        "first contact still works"
    );
}
