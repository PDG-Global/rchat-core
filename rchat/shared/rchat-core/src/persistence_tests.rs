use super::*;
use crate::protocol::{ControlMessage, Frame};
use crate::state_store::MAX_RECORD_BYTES;
use crate::test_support::*;
use crate::ClientInner;
use std::sync::atomic::Ordering;

/// SP5: a failing sink → the seal fails, the id is not recorded as sent;
/// once fixed, the receiver decrypts the next message across the gap.
#[test]
fn sp5_failing_sink_sends_nothing() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    sa.fail.store(true, Ordering::SeqCst);
    let err =
        p.a.seal_ratchet(&p.pb.hex, [1; 16], b"\x01\0\0\0\0lost")
            .unwrap_err();
    assert!(matches!(err, RChatError::StatePersistFailed));
    assert!(
        !p.a.was_sent_to(&p.pb.hex, &[1; 16]),
        "a message that never left is not 'sent'"
    );
    sa.fail.store(false, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "after");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"after".to_vec()]);
}

/// SP6: a failing sink on receive delivers nothing and rolls the session
/// back; the tick's held-body retry delivers it once the sink recovers.
#[test]
fn sp6_failing_sink_delivers_nothing_and_rolls_back() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let before =
        bincode::serialize(&p.b.peer_record(&p.pa.hex).unwrap().session.unwrap().ratchet).unwrap();
    push_text(&p.a, &p.pb.hex, "held");
    sb.fail.store(true, Ordering::SeqCst);
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(texts(&p.b_log).is_empty());
    assert!(statuses(&p.b_log)
        .iter()
        .any(|s| matches!(s, crate::status::StatusEvent::StatePersistFailed { .. })));
    let now =
        bincode::serialize(&p.b.peer_record(&p.pa.hex).unwrap().session.unwrap().ratchet).unwrap();
    assert_eq!(before, now, "rolled back");
    p.b.retry_held(); // still failing: nothing
    assert!(texts(&p.b_log).is_empty());
    sb.fail.store(false, Ordering::SeqCst);
    p.b.retry_held(); // what the ticker calls every tick
    assert_eq!(texts(&p.b_log), vec![b"held".to_vec()]);
    p.b.retry_held();
    assert_eq!(texts(&p.b_log).len(), 1, "exactly once");
}

/// SP7: the stored chain covers every packet before it leaves, and every
/// delivered id is in the stored record before the callback.
#[test]
fn sp7_writes_precede_sends_and_deliveries() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    for i in 0..3 {
        push_text(&p.a, &p.pb.hex, &format!("m{i}"));
        let pk = sent_relays(&mut p.a_rx).remove(0);
        // The record on disk at this moment (the packet is queued, not yet relayed).
        let stored = open_record(&sa, 0xA1, &p.pb).session.unwrap().ratchet;
        let opened = crate::sealed::open(
            &p.pb.bundle.identity_key,
            p.pb.id.agreement_secret(),
            &pk.payload,
        )
        .unwrap();
        let hdr = crate::crypto::RatchetHeader::decode(&opened.body).unwrap();
        assert!(
            stored.ns > hdr.message_number,
            "chain state on disk is past message {}",
            hdr.message_number
        );
        feed(&mut p.b, Frame::Relay(pk));
        let rec = open_record(&sb, 0xB2, &p.pa);
        assert!(rec.received_ids.contains(&opened.message_id));
        assert!(rec.delivered_unstored.contains(&opened.message_id));
    }
}

/// SP14: concurrent seals write strictly increasing counters, and the last
/// write is the newest state. (Through `seal_ratchet`, the one point every
/// send path shares: `send_text_message` needs a live runtime and socket.)
#[test]
fn sp14_concurrent_sends_never_write_an_older_state() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let peer = p.pb.hex.clone();
    let a = Arc::new(p.a);
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let (a, peer) = (a.clone(), peer.clone());
            std::thread::spawn(move || {
                for _ in 0..200 {
                    a.seal_ratchet(&peer, rand::random(), b"\x01\0\0\0\0c")
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let key = a
        .state
        .as_ref()
        .unwrap()
        .keys
        .record_key_for(&p.pb.bundle.identity_key);
    let counters: Vec<u64> = sa
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k == key)
        .map(|(_, c)| *c)
        .collect();
    assert!(
        counters.windows(2).all(|w| w[0] < w[1]),
        "strictly increasing"
    );
    // Every write in order: the stored chain never goes backwards.
    let ns: Vec<u32> = sa
        .history
        .lock()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k == key)
        .map(|(k, sealed)| open_sealed(0xA1, k, sealed).session.unwrap().ratchet.ns)
        .collect();
    assert!(ns.len() > 400, "every seal wrote");
    assert!(ns.windows(2).all(|w| w[0] <= w[1]), "ns never decreases");
    let on_disk = open_record(&sa, 0xA1, &p.pb).session.unwrap().ratchet.ns;
    assert_eq!(
        on_disk,
        a.peer_record(&peer).unwrap().session.unwrap().ratchet.ns
    );
}

fn persist_failures(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| matches!(s, crate::status::StatusEvent::StatePersistFailed { .. }))
        .count()
}

/// Ruling N3: `StatePersistFailed` is raised once per failure episode, not
/// on every retry while the disk stays full; a new episode raises it again.
#[test]
fn persist_failure_is_reported_once_per_episode() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    sb.fail.store(true, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "one");
    push_text(&p.a, &p.pb.hex, "two");
    relay_all(&mut p.a_rx, &mut p.b);
    for _ in 0..5 {
        p.b.retry_held(); // the ticker, every 250 ms
    }
    // One event per record per episode: A's record, and the meta record
    // that holds the rolled-back bodies (carry-over f).
    assert_eq!(
        persist_failures(&p.b_log),
        2,
        "one episode, one event per record"
    );
    assert_eq!(meta_persist_failures(&p.b_log), 1);
    assert!(texts(&p.b_log).is_empty());
    sb.fail.store(false, Ordering::SeqCst);
    p.b.retry_held();
    assert_eq!(texts(&p.b_log), vec![b"one".to_vec(), b"two".to_vec()]);
    sb.fail.store(true, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "three");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(persist_failures(&p.b_log), 4, "a new episode is reported");
    assert_eq!(meta_persist_failures(&p.b_log), 2);
}

fn meta_persist_failures(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| {
            matches!(
                s,
                crate::status::StatusEvent::StatePersistFailed { peer: None }
            )
        })
        .count()
}

/// Carry-over (d): a sealed record over `MAX_RECORD_BYTES` is a persist
/// failure and is never written.
#[test]
fn oversize_record_is_a_persist_failure_and_never_written() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let key =
        p.a.state
            .as_ref()
            .unwrap()
            .keys
            .record_key_for(&p.pb.bundle.identity_key);
    let writes = sa.log.lock().unwrap().len();
    let huge = vec![0u8; MAX_RECORD_BYTES + 1];
    let err = p.a.write_record(&key, &huge, Some(&p.pb.hex)).unwrap_err();
    assert!(matches!(err, RChatError::StatePersistFailed));
    assert_eq!(sa.log.lock().unwrap().len(), writes, "nothing written");
    assert_eq!(persist_failures(&p.a_log), 1);
}

/// D28: a session whose write failed raises no `on_circuit_established`;
/// it stays in memory and the next successful write carries it.
#[test]
fn new_session_without_a_durable_write_is_not_announced() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    sa.fail.store(true, Ordering::SeqCst);
    let (ek_a, ek_b) = (
        crate::crypto::EphemeralKeyPair::generate(),
        crate::crypto::EphemeralKeyPair::generate(),
    );
    let (i_ek, r_ek) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers
        .push_ask(&p.pb.hex, ek_a, std::time::Instant::now());
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i_ek, r_ek));
    assert!(
        !p.a_log
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Ev::Established(..))),
        "no callback without a durable write"
    );
    assert!(p.a.session_manager.has_established_session(&p.pb.hex));
    assert!(sent_relays(&mut p.a_rx).is_empty(), "no hello sync left");
    sa.fail.store(false, Ordering::SeqCst);
    p.a.persist_peer(&p.pb.hex).unwrap();
    let rec = open_record(&sa, 0xA1, &p.pb).session.unwrap();
    assert!(rec.replaced_established, "the new session replaced one");
}

/// The stored session carries the bundle's agreement key and the circuit.
#[test]
fn stored_session_carries_peer_ak_and_circuit() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let _p = stored_pair(&sa, &sb);
    let pb = peer(0xB2);
    let s = open_record(&sa, 0xA1, &pb).session.unwrap();
    assert_eq!(s.peer_ak, pb.bundle.identity_agreement_key);
    let c = s.circuit.as_ref().expect("circuit stored");
    assert_eq!(
        (c.circuit_id, c.target_circuit_id, c.token),
        (C1.0, C2.0, TOKEN)
    );
    assert!(s.is_established && s.is_initiator && !s.replaced_established);
}

fn ns_of(inner: &ClientInner, peer_hex: &str) -> u32 {
    inner
        .peer_record(peer_hex)
        .unwrap()
        .session
        .unwrap()
        .ratchet
        .ns
}

/// Review fix 1: sends retried while the peer's writes fail (a cover reply
/// every tick) burn no chain key; after recovery the peer still decrypts.
#[test]
fn retried_seals_while_writes_fail_burn_no_chain_keys() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let ns0 = ns_of(&p.a, &p.pb.hex);
    sa.fail.store(true, Ordering::SeqCst);
    for _ in 0..200 {
        let r = p.a.send_cover(&p.pb.hex, true, std::time::Instant::now());
        assert!(matches!(r, Err(RChatError::StatePersistFailed)));
    }
    assert_eq!(
        ns_of(&p.a, &p.pb.hex),
        ns0 + 1,
        "only the attempt that found the failure used a key"
    );
    assert!(sent_relays(&mut p.a_rx).is_empty());
    sa.fail.store(false, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "after");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"after".to_vec()]);
}

/// Review fix 2: a queued send whose write fails stays queued, in order,
/// and goes out on a later tick.
#[test]
fn queued_sends_survive_a_failed_write() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let (mut a, b, mut b_rx, pa, a_log) = (p.a, p.b, p.b_rx, p.pa, p.a_log);
    for (i, t) in [(1, "q1"), (2, "q2")] {
        b.session_manager
            .get_mut(&pa.hex)
            .unwrap()
            .pending_messages
            .push_back(pending_msg(i, t));
    }
    sb.fail.store(true, Ordering::SeqCst);
    let mut b = process_pending_on(b); // a tick
    assert!(sent_relays(&mut b_rx).is_empty());
    let queued: Vec<String> = b
        .session_manager
        .get(&pa.hex)
        .unwrap()
        .pending_messages
        .iter()
        .map(|m| m.id.0.clone())
        .collect();
    assert_eq!(queued, vec![hex::encode([1u8; 16]), hex::encode([2u8; 16])]);
    sb.fail.store(false, Ordering::SeqCst);
    b = process_pending_on(b); // the next tick
    relay_all(&mut b_rx, &mut a);
    assert_eq!(texts(&a_log), vec![b"q1".to_vec(), b"q2".to_vec()]);
    assert!(b
        .session_manager
        .get(&pa.hex)
        .unwrap()
        .pending_messages
        .is_empty());
}

/// Review fix 3: while a peer's writes fail its bodies are held within the
/// caps and not decrypted; each tick retries only the oldest one.
#[test]
fn held_bodies_stay_within_the_caps_while_writes_fail() {
    use crate::{MAX_PENDING_BYTES, MAX_PENDING_PER_SENDER};
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let before = p.b.decrypt_attempts.load(Ordering::Relaxed);
    sb.fail.store(true, Ordering::SeqCst);
    let n = MAX_PENDING_PER_SENDER + 20;
    for i in 0..n {
        push_text(&p.a, &p.pb.hex, &format!("m{i}"));
    }
    relay_all(&mut p.a_rx, &mut p.b);
    let held = |b: &ClientInner, from: &str| {
        let from: Vec<_> = b
            .pending_encrypted_messages
            .iter()
            .filter(|h| h.sender_hex == from)
            .collect();
        (from.len(), from.iter().map(|h| h.body.len()).sum::<usize>())
    };
    let (count, bytes) = held(&p.b, &p.pa.hex);
    assert_eq!(count, MAX_PENDING_PER_SENDER, "per-sender cap");
    assert!(bytes <= MAX_PENDING_BYTES);
    assert_eq!(
        p.b.decrypt_attempts.load(Ordering::Relaxed),
        before + 1,
        "only the first body was decrypted"
    );
    for _ in 0..5 {
        p.b.retry_held();
    }
    assert_eq!(
        p.b.decrypt_attempts.load(Ordering::Relaxed),
        before + 6,
        "one body per tick"
    );
    assert_eq!(held(&p.b, &p.pa.hex).0, MAX_PENDING_PER_SENDER);
    sb.fail.store(false, Ordering::SeqCst);
    p.b.retry_held();
    let expected: Vec<Vec<u8>> = (n - MAX_PENDING_PER_SENDER..n)
        .map(|i| format!("m{i}").into_bytes())
        .collect();
    assert_eq!(texts(&p.b_log), expected, "the held bodies, in order");
}

/// Review fix 4: a retired session's 1,000th decrypt whose write fails is
/// rolled back and delivered on retry; the session goes once it is durable.
#[test]
fn retired_sessions_last_decrypt_survives_a_failed_write() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    // B alone gets a new session: its old one (A's current) is retired.
    // B initiates here, so it installs at once (a responder would wait
    // for session-init, §A.3); its session-init is never relayed.
    let ek_b = crate::crypto::EphemeralKeyPair::generate();
    let i_ek = ek_b.public_key().to_bytes();
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    p.b.peers
        .push_ask(&p.pa.hex, ek_b, std::time::Instant::now());
    feed(&mut p.b, created_v3(0, &p.pa.bundle, i_ek, r_ek));
    drain(&mut p.b_rx);
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 1);
    let now = crate::unix_now_secs();
    let last = crate::session::RETIRED_MAX_DECRYPTS - 1;
    p.b.session_manager
        .set_retired_for_test(&p.pa.hex, now, last);
    sb.fail.store(true, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "last");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(texts(&p.b_log).is_empty());
    assert_eq!(
        p.b.session_manager.retired_parts_for_test(&p.pa.hex),
        Some((now, last)),
        "rolled back"
    );
    sb.fail.store(false, Ordering::SeqCst);
    p.b.retry_held();
    assert_eq!(texts(&p.b_log), vec![b"last".to_vec()]);
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    assert!(
        open_record(&sb, 0xB2, &p.pa).retired.is_none(),
        "and on disk"
    );
}

/// Review fix 5: a binary body with an unknown magic never reaches the
/// app, so it is not recorded as delivered-unstored.
#[test]
fn undeliverable_binary_is_not_recorded_as_delivered() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = [9u8; 16];
    let pk = p.a.seal_ratchet(&p.pb.hex, id, b"\x02ZZZZjunk").unwrap();
    p.a.send_now(pk.encode_with_frame_type()).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(texts(&p.b_log).is_empty());
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(rec.received_ids.contains(&id));
    assert!(!rec.delivered_unstored.contains(&id));
}

/// Review minor 1: a rollback with both queues at their caps restores them
/// exactly (the evicted oldest entry comes back).
#[test]
fn rollback_at_the_caps_is_exact() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let fill = |n: usize| -> std::collections::VecDeque<[u8; 16]> {
        (0..n as u32)
            .map(|i| {
                let mut id = [0xEE; 16];
                id[..4].copy_from_slice(&i.to_be_bytes());
                id
            })
            .collect()
    };
    let received = fill(MAX_RECEIVED_IDS);
    let delivered = fill(MAX_DELIVERED_UNSTORED);
    p.b.received_ids.insert(p.pa.hex.clone(), received.clone());
    p.b.delivered_unstored
        .insert(p.pa.hex.clone(), delivered.clone());
    sb.fail.store(true, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "x");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(texts(&p.b_log).is_empty());
    assert_eq!(p.b.received_ids[&p.pa.hex], received);
    assert_eq!(p.b.delivered_unstored[&p.pa.hex], delivered);
}

/// Review minor 3: in the rotation grace the new identity's record (where
/// the delivery is tracked) is written before the old identity's.
#[test]
fn rotation_grace_writes_the_reported_identity_first() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let pn = peer(0x77);
    p.b.peers.unpin(&p.pa.hex);
    p.b.peers.pin_card(&pn).unwrap();
    p.b.rotated_from.insert(
        p.pa.hex.clone(),
        (pn.hex.clone(), std::time::Instant::now()),
    );
    sb.log.lock().unwrap().clear();
    push_text(&p.a, &p.pb.hex, "grace");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"grace".to_vec()]);
    let keys = crate::state_store::StateKeys::new(TEST_STATE_KEY);
    let (new_key, old_key) = (
        keys.record_key_for(&pn.bundle.identity_key),
        keys.record_key_for(&p.pa.bundle.identity_key),
    );
    let order: Vec<String> = sb
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(order[..2], [new_key, old_key]);
}

/// Review minor 4: with persistence off, receiving takes no snapshots.
#[test]
fn no_rollback_snapshots_without_a_store() {
    let mut p = establish(0xA1, 0xB2);
    let before = p.b.session_manager.snapshot_calls();
    push_text(&p.a, &p.pb.hex, "plain");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"plain".to_vec()]);
    assert_eq!(p.b.session_manager.snapshot_calls(), before);
}

/// Re-review N1: senders without a session (or still failing) ahead in the
/// held queue never starve a later sender whose writes have recovered.
#[test]
fn retry_held_reaches_a_sender_behind_many_held_bodies() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let stranger = peer(0x55).hex;
    for i in 0..40u8 {
        p.b.pending_encrypted_messages
            .push_back(crate::PendingEncrypted {
                sender_hex: stranger.clone(),
                message_id: [i; 16],
                body: vec![0; 64],
            });
    }
    sb.fail.store(true, Ordering::SeqCst);
    push_text(&p.a, &p.pb.hex, "behind");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(texts(&p.b_log).is_empty());
    assert_eq!(
        p.b.pending_encrypted_messages.back().unwrap().sender_hex,
        p.pa.hex,
        "held behind the 40"
    );
    sb.fail.store(false, Ordering::SeqCst);
    p.b.retry_held();
    assert_eq!(texts(&p.b_log), vec![b"behind".to_vec()]);
}

/// Re-review N1: with more waiting senders than one tick takes, the
/// rotation reaches every one of them, even when the same senders stay
/// waiting tick after tick.
#[test]
fn retry_sender_rotation_reaches_everyone() {
    let all: Vec<String> = (0..MAX_RETRY_SENDERS + 8).map(|i| i.to_string()).collect();
    let mut cursor = 0;
    let mut reached = std::collections::HashSet::new();
    for _ in 0..2 {
        let mut senders = all.clone();
        cursor = pick_retry_senders(&mut senders, cursor);
        assert_eq!(senders.len(), MAX_RETRY_SENDERS);
        reached.extend(senders);
    }
    assert_eq!(reached.len(), all.len(), "everyone within two ticks");
    let mut few: Vec<String> = all[..3].to_vec();
    assert_eq!(pick_retry_senders(&mut few, 17), 0);
    assert_eq!(few.len(), 3, "all of them when they fit");
}

/// Re-review N3: an exhausted retired session whose follow-up write fails
/// is already out of memory, so the next successful write omits it.
#[test]
fn exhausted_retired_session_stays_out_when_its_write_fails() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    // B initiates here, so it installs at once (a responder would wait
    // for session-init, §A.3); its session-init is never relayed.
    let ek_b = crate::crypto::EphemeralKeyPair::generate();
    let i_ek = ek_b.public_key().to_bytes();
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    p.b.peers
        .push_ask(&p.pa.hex, ek_b, std::time::Instant::now());
    feed(&mut p.b, created_v3(0, &p.pa.bundle, i_ek, r_ek));
    drain(&mut p.b_rx);
    let last = crate::session::RETIRED_MAX_DECRYPTS - 1;
    p.b.session_manager
        .set_retired_for_test(&p.pa.hex, crate::unix_now_secs(), last);
    // The delivery write succeeds; the follow-up write fails.
    *sb.budget.lock().unwrap() = Some(1);
    push_text(&p.a, &p.pb.hex, "last");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(texts(&p.b_log), vec![b"last".to_vec()]);
    assert_eq!(p.b.session_manager.retired_count(&p.pa.hex), 0);
    assert!(
        open_record(&sb, 0xB2, &p.pa).retired.is_some(),
        "the failed write left the stale one on disk"
    );
    *sb.budget.lock().unwrap() = None;
    p.b.persist_peer(&p.pa.hex).unwrap();
    assert!(open_record(&sb, 0xB2, &p.pa).retired.is_none());
}

/// SP8: B restarts from its sink and decrypts what A sent meanwhile; the
/// same when A restarts while B is offline.
#[test]
fn sp8_restart_with_a_queue_delivers() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    push_text(&p.a, &p.pb.hex, "q1");
    push_text(&p.a, &p.pb.hex, "q2");
    let queued_payloads: Vec<_> = sent_relays(&mut p.a_rx)
        .into_iter()
        .map(|r| r.payload)
        .collect();
    let (mut b2, _rx, log) = restart_from(0xB2, 0xA1, &sb);
    for payload in queued_payloads {
        feed(&mut b2, queued(payload));
    }
    assert_eq!(texts(&log), vec![b"q1".to_vec(), b"q2".to_vec()]);

    // A restarts; its restored session still encrypts for B2.
    let (mut a2, mut a2_rx, _alog) = restart_from(0xA1, 0xB2, &sa);
    a2.receipt_delay_override = Some(std::time::Duration::ZERO);
    push_text(&a2, &p.pb.hex, "from a2");
    relay_all(&mut a2_rx, &mut b2);
    assert_eq!(texts(&log).last(), Some(&b"from a2".to_vec()));
}

/// SP9: the restored session resumes after the first accepted publish; one
/// restored without a circuit asks with the all-zero resume. Task 9: a
/// known contact on the blind path re-pairs blind instead (never a resume
/// of its circuit), so this is the identity path's behaviour.
#[test]
fn sp9_restored_session_resumes() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (mut b2, mut rx, _log) = restart_from(0xB2, 0xA1, &sb);
    keep_identity_path(&mut b2, &p.pa.hex);
    b2.after_publish_ok(std::time::Instant::now());
    let resumes: Vec<_> = sent_controls(&mut rx)
        .into_iter()
        .filter_map(|c| match c {
            ControlMessage::CircuitAsk { resume_circuit, .. } => resume_circuit,
            _ => None,
        })
        .collect();
    assert_eq!(resumes, vec![C2], "B (role 1) owns C2");

    p.b.handle_circuit_closed(C2); // detaches B's circuit
    p.b.persist_peer(&p.pa.hex).unwrap();
    let (mut b3, mut rx3, _log) = restart_from(0xB2, 0xA1, &sb);
    keep_identity_path(&mut b3, &p.pa.hex);
    b3.ask(
        &p.pa.hex,
        crate::circuits::AskTrigger::User,
        std::time::Instant::now(),
    )
    .unwrap();
    let asks: Vec<_> = sent_controls(&mut rx3)
        .into_iter()
        .filter_map(|c| match c {
            ControlMessage::CircuitAsk { resume_circuit, .. } => resume_circuit,
            _ => None,
        })
        .collect();
    assert_eq!(asks, vec![crate::circuits::ZERO_CIRCUIT]);
    // Without the identity-path mark, a restored known contact re-pairs
    // blind and never names its circuit (Task 9).
    let (mut b1, mut rx1, _log) = restart_from(0xB2, 0xA1, &sb);
    b1.after_publish_ok(std::time::Instant::now());
    let sent = sent_controls(&mut rx1);
    assert_eq!(
        blind_asks_in(&sent),
        1,
        "blind re-pair of the restored session"
    );
    assert!(sent
        .iter()
        .all(|m| !matches!(m, ControlMessage::CircuitAsk { .. })));
}

/// SP10 (amends K12): replays after a restart are dropped by received_ids
/// before any decrypt, and a replayed CircuitCreatedV3 is still refused.
#[test]
fn sp10_replay_after_restart_is_dropped_before_decrypt() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let once = push_text(&p.a, &p.pb.hex, "once");
    let packets = sent_relays(&mut p.a_rx);
    for pk in packets.clone() {
        feed(&mut p.b, Frame::Relay(pk));
    }
    // Stored by the app: not lost, so no same-id resend may pass (§18.6).
    p.b.mark_seen_and_receipt(&p.pa.hex, once).unwrap();
    let (mut b2, mut b2_rx, log) = restart_from(0xB2, 0xA1, &sb);
    let attempts = b2.decrypt_attempts.load(Ordering::Relaxed);
    for pk in packets {
        feed(&mut b2, Frame::Relay(pk));
    }
    assert!(texts(&log).is_empty());
    assert_eq!(
        b2.decrypt_attempts.load(Ordering::Relaxed),
        attempts,
        "never decrypted twice"
    );
    let replay = created_v3(1, &p.pa.bundle, [1; 32], [2; 32]);
    feed(&mut b2, replay);
    assert!(
        sent_controls(&mut b2_rx)
            .iter()
            .any(|c| matches!(c, ControlMessage::CloseCircuit { .. })),
        "EK unknown → refused"
    );
}

/// SP11: wipes. Unpin deletes the record; a record for an unpinned identity
/// is deleted at restore; a record under our old identity fails and is
/// deleted; clear_state empties memory.
#[test]
fn sp11_wipes() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let key =
        p.a.state
            .as_ref()
            .unwrap()
            .keys
            .record_key_for(&p.pb.bundle.identity_key);
    assert!(sa.files.lock().unwrap().contains_key(&key));
    p.a.unpin_peer(&p.pb.hex).unwrap();
    assert!(!sa.files.lock().unwrap().contains_key(&key));

    // B restores without a pin for A: deleted.
    let (mut fresh, _rx) = published(0xB2);
    with_store(&mut fresh, &sb);
    fresh.state.as_mut().unwrap().staged = sb.files.lock().unwrap().clone().into_iter().collect();
    fresh.restore_staged_state();
    assert!(fresh.session_manager.get(&p.pa.hex).is_none());
    assert!(sb
        .files
        .lock()
        .unwrap()
        .keys()
        .all(|k| k == crate::state_store::META_KEY));

    // A record sealed for another identity (our old one) fails and goes.
    let sc = MemorySink::default();
    let q = stored_pair(&sc, &MemorySink::default());
    let (mut other, _rx) = published(0xC3); // a different identity reading A's files
    other.receipt_delay_override = Some(std::time::Duration::ZERO);
    let olog = install_event_log(&mut other);
    with_store(&mut other, &sc);
    other.state.as_mut().unwrap().staged = sc.files.lock().unwrap().clone().into_iter().collect();
    other.restore_staged_state();
    assert!(statuses(&olog).iter().any(|s| matches!(
        s,
        crate::status::StatusEvent::StateRestoreFailed { reason: 1 }
    )));
    assert!(sc.files.lock().unwrap().is_empty());
    drop(q);

    // clear_state empties every piece of per-identity state.
    fill_identity_state(&mut p.b, &p.pa.hex);
    p.b.clear_state_now();
    assert_identity_state_empty(&p.b);
}

fn intro() -> crate::knock::Intro {
    crate::knock::Intro {
        message_id: [6; 16],
        sent_at_ms: 0,
        text: "hi".into(),
    }
}

/// Fill everything `clear_state_now` must empty, for `peer_hex`.
fn fill_identity_state(inner: &mut ClientInner, peer_hex: &str) {
    let now = std::time::Instant::now();
    fill_tracking(inner, peer_hex);
    inner.record_sent(peer_hex, [2; 16]);
    inner.pending_receipts.insert(
        (peer_hex.to_string(), crate::receipts::DELIVERED),
        vec![[3; 16]],
    );
    inner.receipt_due.insert(peer_hex.to_string(), now);
    inner
        .pending_encrypted_messages
        .push_back(crate::PendingEncrypted {
            sender_hex: peer_hex.to_string(),
            message_id: [4; 16],
            body: vec![1],
        });
    inner.pending_closes.push(C1);
    inner.deferred_asks.push(peer_hex.to_string());
    inner.pending_reasks.insert(peer_hex.to_string(), now);
    inner.intros.insert(peer_hex.to_string(), intro());
    inner
        .rotated_from
        .insert(peer(0x77).hex, (peer_hex.to_string(), now));
    inner.last_heard.insert(peer_hex.to_string(), now);
    inner.cover_sent.insert(
        peer_hex.to_string(),
        std::collections::VecDeque::from(vec![now]),
    );
    inner.cover_replies_due.push((peer_hex.to_string(), now));
    inner.acks.lock().unwrap().track(
        "ee".repeat(16),
        crate::acks::Tracked {
            peer: peer_hex.to_string(),
            payload: vec![5],
            circuit: C1,
            first_sent: now,
            attempts: 1,
            not_accepted: false,
            connected_for: std::time::Duration::ZERO,
            internal: None,
            binding: [0; 32],
            expire_after: crate::acks::ACK_UNKNOWN_AFTER,
            plaintext: None,
            lineage: None,
        },
    );
    inner.cover_replies_charged.insert(
        peer_hex.to_string(),
        std::collections::VecDeque::from(vec![now]),
    );
    if let Some(store) = inner.state.as_ref() {
        store.failing.lock().unwrap().insert("ab".repeat(16));
        store
            .failing
            .lock()
            .unwrap()
            .insert(crate::state_store::META_KEY.into());
    }
    if let Some(store) = inner.state.as_mut() {
        store.staged.push(("cd".repeat(16), vec![1]));
    }
}

fn assert_identity_state_empty(inner: &ClientInner) {
    assert!(inner.session_manager.is_empty(), "sessions");
    assert!(inner.received_ids.is_empty() && inner.delivered_unstored.is_empty());
    assert!(inner.lost_unstored.is_empty() && inner.undecryptable.is_empty());
    assert!(inner.notice_due.is_empty() && inner.auto_resends.is_empty());
    assert!(inner.lost_reported.is_empty() && inner.notice_flag_pending.is_empty());
    assert!(inner.hello_sync_due.is_empty(), "owed hello syncs");
    assert!(inner.unanswered_asks.is_empty(), "unanswered asks");
    assert_eq!(inner.acks.lock().unwrap().len(), 0, "tracked acks");
    assert!(inner.sent_ids.lock().unwrap().is_empty(), "sent ids");
    assert!(inner.pending_receipts.is_empty() && inner.receipt_due.is_empty());
    assert!(inner.pending_encrypted_messages.is_empty(), "held bodies");
    assert!(inner.pending_closes.is_empty(), "closes");
    assert!(inner.deferred_asks.is_empty() && inner.pending_reasks.is_empty());
    assert!(inner.intros.is_empty() && inner.rotated_from.is_empty());
    assert!(inner.last_heard.is_empty(), "last heard");
    assert!(inner.cover_sent.is_empty() && inner.cover_replies_due.is_empty());
    assert!(inner.cover_replies_charged.is_empty());
    if let Some(store) = inner.state.as_ref() {
        assert!(store.failing.lock().unwrap().is_empty(), "failing set");
        assert!(store.staged.is_empty(), "staged");
    }
}

/// SP12: the retired session's 72 h limit is wall-clock and holds across a restart.
#[test]
fn sp12_retired_limit_survives_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let replacement = crate::session::ChatSession::new(p.pa.hex.clone());
    p.b.session_manager.install(p.pa.hex.clone(), replacement);
    p.b.session_manager
        .age_retired_for_test(&p.pa.hex, 71 * 3600);
    p.b.persist_peer(&p.pa.hex).unwrap();
    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.session_manager.retired_count(&p.pa.hex), 1, "71 h: kept");
    p.b.session_manager
        .age_retired_for_test(&p.pa.hex, 2 * 3600);
    p.b.persist_peer(&p.pa.hex).unwrap();
    let (b3, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(
        b3.session_manager.retired_count(&p.pa.hex),
        0,
        "73 h: dropped at restore"
    );
}

/// The meta record `our_seed`'s client stored, opened.
fn open_meta(sink: &MemorySink, our_seed: u8) -> crate::state_store::MetaRecordV1 {
    let sealed = sink
        .files
        .lock()
        .unwrap()
        .get(crate::state_store::META_KEY)
        .cloned()
        .expect("meta written");
    let our_ik = peer(our_seed).bundle.identity_key;
    let (_, _, body) = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .open(&our_ik, crate::state_store::META_KEY, &sealed)
        .unwrap();
    bincode::deserialize(&body).unwrap()
}

/// Seal `body` as `our_seed`'s client would, under `key` with `kind`.
fn seal_as(our_seed: u8, key: &str, kind: u8, counter: u64, body: &[u8]) -> Vec<u8> {
    crate::state_store::StateKeys::new(TEST_STATE_KEY).seal(
        &peer(our_seed).bundle.identity_key,
        key,
        kind,
        counter,
        body,
    )
}

fn parse_failures(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| {
            matches!(
                s,
                crate::status::StatusEvent::StateRestoreFailed { reason: 3 }
            )
        })
        .count()
}

/// Carry-over (b): a record whose kind does not match its key, or a peer
/// record filed under another peer's key, is refused and deleted.
#[test]
fn restore_refuses_kind_and_key_mismatches() {
    let sink = MemorySink::default();
    let keys = crate::state_store::StateKeys::new(TEST_STATE_KEY);
    let (pa, pc) = (peer(0xA1), peer(0xC3));
    let rec = |ik: [u8; 32]| {
        crate::state_store::encode_body(&crate::state_store::PeerRecordV2 {
            peer_ik: ik,
            received_ids: vec![[9; 16]],
            ..Default::default()
        })
        .unwrap()
    };
    let key_a = keys.record_key_for(&pa.bundle.identity_key);
    let key_c = keys.record_key_for(&pc.bundle.identity_key);
    let meta_body = crate::state_store::encode_body(&crate::state_store::MetaRecordV1 {
        pending_closes: vec![[4; 16]],
        ..Default::default()
    })
    .unwrap();
    let staged = vec![
        // A meta body sealed under a peer key.
        (
            key_a.clone(),
            seal_as(0xB2, &key_a, crate::state_store::KIND_META, 1, &meta_body),
        ),
        // A peer record sealed as the meta record.
        (
            crate::state_store::META_KEY.to_string(),
            seal_as(
                0xB2,
                crate::state_store::META_KEY,
                crate::state_store::KIND_PEER,
                1,
                &rec(pa.bundle.identity_key),
            ),
        ),
        // A's record filed under C's key.
        (
            key_c.clone(),
            seal_as(
                0xB2,
                &key_c,
                crate::state_store::KIND_PEER,
                1,
                &rec(pa.bundle.identity_key),
            ),
        ),
    ];
    for (k, v) in &staged {
        sink.files.lock().unwrap().insert(k.clone(), v.clone());
    }
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers.pin_card(&pa).unwrap();
    b.peers.pin_card(&pc).unwrap();
    with_store(&mut b, &sink);
    b.state.as_mut().unwrap().staged = staged;
    b.restore_staged_state();
    assert_eq!(parse_failures(&log), 3);
    assert!(sink.files.lock().unwrap().is_empty(), "all three deleted");
    assert!(b.pending_closes.is_empty());
    assert!(b.received_ids.is_empty());
}

/// Carry-over (c): for a duplicate key the higher counter wins, and the
/// next write continues from the restored counter.
#[test]
fn higher_counter_wins_and_seeds_the_next_write() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let key =
        p.b.state
            .as_ref()
            .unwrap()
            .keys
            .record_key_for(&p.pa.bundle.identity_key);
    let old = sb.files.lock().unwrap()[&key].clone();
    push_text(&p.b, &p.pa.hex, "advance");
    let newer = sb.files.lock().unwrap()[&key].clone();
    let counter = |s: &[u8]| u64::from_be_bytes(s[6..14].try_into().unwrap());
    assert!(counter(&newer) > counter(&old));

    let (mut b2, _rx) = published(0xB2);
    b2.peers.pin_card(&p.pa).unwrap();
    with_store(&mut b2, &sb);
    let store = b2.state.as_mut().unwrap();
    store.stage_keep_higher(key.clone(), newer.clone());
    store.stage_keep_higher(key.clone(), old.clone()); // older: ignored
    assert_eq!(store.staged.len(), 1);
    assert_eq!(store.staged[0].1, newer);
    let mut store2 = b2.state.take().unwrap();
    store2.staged.clear();
    store2.stage_keep_higher(key.clone(), old.clone());
    store2.stage_keep_higher(key.clone(), newer.clone()); // newer: replaces
    assert_eq!(store2.staged, vec![(key.clone(), newer.clone())]);
    b2.state = Some(store2);
    b2.restore_staged_state();
    // The restore writes once (F4); that write follows the restored counter.
    assert_eq!(
        counter(&sb.files.lock().unwrap()[&key]),
        counter(&newer) + 1
    );
    assert_eq!(ns_of(&b2, &p.pa.hex), ns_of(&p.b, &p.pa.hex));
}

/// Carry-over (d): a retired snapshot that has used its 1,000 decrypts is
/// dropped at restore.
#[test]
fn exhausted_retired_snapshot_is_dropped_at_restore() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let replacement = crate::session::ChatSession::new(p.pa.hex.clone());
    p.b.session_manager.install(p.pa.hex.clone(), replacement);
    let now = crate::unix_now_secs();
    p.b.session_manager.set_retired_for_test(
        &p.pa.hex,
        now,
        crate::session::RETIRED_MAX_DECRYPTS - 1,
    );
    p.b.persist_peer(&p.pa.hex).unwrap();
    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.session_manager.retired_count(&p.pa.hex), 1, "999: kept");
    p.b.session_manager
        .set_retired_for_test(&p.pa.hex, now, crate::session::RETIRED_MAX_DECRYPTS);
    p.b.persist_peer(&p.pa.hex).unwrap();
    let (b3, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(
        b3.session_manager.retired_count(&p.pa.hex),
        0,
        "1,000: dropped"
    );
    assert!(
        open_record(&sb, 0xB2, &p.pa).retired.is_none(),
        "and not rewritten"
    );
}

/// §18.5 step 4 (F4): ids handed to the app and never confirmed stored are
/// lost-unstored after a restart, the notice is due, and both are durable
/// before anything else happens; queued sends that died are reported.
#[test]
fn restore_moves_delivered_unstored_to_lost_and_reports_lost_sends() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "unstored");
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(open_record(&sb, 0xB2, &p.pa)
        .delivered_unstored
        .contains(&id));
    // A message queued on B's session when B "crashes".
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(0x33, "queued"));
    p.b.persist_peer(&p.pa.hex).unwrap();

    let (b2, _rx, log) = restart_from(0xB2, 0xA1, &sb);
    assert!(b2.lost_unstored[&p.pa.hex].contains(&id));
    assert!(b2.notice_due.contains(&p.pa.hex));
    assert_eq!(
        b2.delivered_unstored.get(&p.pa.hex).map_or(0, |q| q.len()),
        0
    );
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(rec.lost_unstored_ids.contains(&id) && rec.delivered_unstored.is_empty());
    assert!(rec.notice_due);
    assert!(rec.pending_send_ids.is_empty());
    assert!(
        statuses(&log).contains(&crate::status::StatusEvent::QueuedSendLost {
            peer: p.pa.hex.clone(),
            message_id: hex::encode([0x33; 16]),
        })
    );
    // The rest of the record comes back too.
    assert!(b2.received_ids[&p.pa.hex].contains(&id));
}

/// Carry-over (e): a resumed circuit is written (D28 "resumed"), and so is
/// a detached one.
#[test]
fn resume_and_detach_are_persisted() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let (mut b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: vec![8; 32],
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    let circuit = open_record(&sb, 0xB2, &p.pa).session.unwrap().circuit;
    assert_eq!(
        circuit.as_ref().map(|c| c.token),
        Some([8; 32]),
        "resumed token stored"
    );
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitClosed {
            circuit_id: C2,
            reason: crate::protocol::CircuitCloseReason::Normal,
        }),
    );
    assert!(
        open_record(&sb, 0xB2, &p.pa)
            .session
            .unwrap()
            .circuit
            .is_none(),
        "detached circuit stored"
    );
}

/// Carry-over (f): the meta record follows the held bodies, held and
/// released; held bodies come back at restore and the tick delivers them.
#[test]
fn held_bodies_are_in_the_meta_record_and_survive_a_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let session = p.b.session_manager.remove(&p.pa.hex).unwrap();
    push_text(&p.a, &p.pb.hex, "held");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.flush_deferred_writes(); // the meta write is coalesced to the tick (M-1)
    assert_eq!(open_meta(&sb, 0xB2).held.len(), 1, "held: written");

    // B restarts holding it: re-held, and the tick delivers it.
    let (mut b2, _rx, log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.pending_encrypted_messages.len(), 1);
    b2.retry_held();
    assert_eq!(texts(&log), vec![b"held".to_vec()]);
    assert!(open_meta(&sb, 0xB2).held.is_empty(), "released: written");

    // Released in place, without a restart.
    p.b.session_manager.install(p.pa.hex.clone(), session);
    p.b.process_pending_encrypted(&p.pa.hex);
    assert_eq!(texts(&p.b_log), vec![b"held".to_vec()]);
    assert!(open_meta(&sb, 0xB2).held.is_empty());
}

/// The meta record's closes and unanswered asks come back at restore.
#[test]
fn meta_closes_and_unanswered_asks_are_restored() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    drop(dead_rx);
    p.b.websocket
        .as_ref()
        .unwrap()
        .install_outgoing_for_test(dead_tx);
    p.b.close_circuit_with(&p.pa.hex);
    assert_eq!(open_meta(&sb, 0xB2).pending_closes, vec![C2.0]);
    p.b.unanswered_asks
        .insert(p.pa.hex.clone(), (std::time::Instant::now(), 1));
    p.b.persist_meta();
    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.pending_closes, vec![C2]);
    assert_eq!(b2.deferred_asks, vec![p.pa.hex.clone()]);
}

fn fill_tracking(inner: &mut ClientInner, peer_hex: &str) {
    let q = || std::collections::VecDeque::from(vec![[1u8; 16]]);
    inner.received_ids.insert(peer_hex.to_string(), q());
    inner.delivered_unstored.insert(peer_hex.to_string(), q());
    inner.lost_unstored.insert(peer_hex.to_string(), q());
    inner.undecryptable.insert(peer_hex.to_string(), q());
    inner.notice_due.insert(peer_hex.to_string());
    inner.lost_reported.insert(
        peer_hex.to_string(),
        [([1u8; 16], 1u64)].into_iter().collect(),
    );
    inner.notice_flag_pending.insert(peer_hex.to_string(), 1);
    inner.hello_sync_due.insert(peer_hex.to_string());
    inner.auto_resends.insert(
        peer_hex.to_string(),
        std::collections::VecDeque::from(vec![1]),
    );
    inner
        .unanswered_asks
        .insert(peer_hex.to_string(), (std::time::Instant::now(), 1));
}

fn tracking_cleared(inner: &ClientInner, peer_hex: &str) -> bool {
    !inner.received_ids.contains_key(peer_hex)
        && !inner.delivered_unstored.contains_key(peer_hex)
        && !inner.lost_unstored.contains_key(peer_hex)
        && !inner.undecryptable.contains_key(peer_hex)
        && !inner.lost_reported.contains_key(peer_hex)
        && !inner.notice_flag_pending.contains_key(peer_hex)
        && !inner.hello_sync_due.contains(peer_hex)
        && !inner.notice_due.contains(peer_hex)
        && !inner.auto_resends.contains_key(peer_hex)
        && !inner.unanswered_asks.contains_key(peer_hex)
}

/// Carry-over (g): every forget path (unpin, block, re-pin, the end of the
/// rotation grace) clears the seven tracking fields and deletes the record;
/// a re-pin keeps the queued messages' placeholder on disk.
#[test]
fn forget_paths_clear_tracking_and_delete_the_record() {
    let key_of = |p: &Peer| {
        crate::state_store::StateKeys::new(TEST_STATE_KEY).record_key_for(&p.bundle.identity_key)
    };
    // Unpin and block.
    for block in [false, true] {
        let (sa, sb) = (MemorySink::default(), MemorySink::default());
        let mut p = stored_pair(&sa, &sb);
        fill_tracking(&mut p.b, &p.pa.hex);
        if block {
            p.b.block_peer(&p.pa.hex, true).unwrap();
        } else {
            p.b.unpin_peer(&p.pa.hex).unwrap();
        }
        assert!(tracking_cleared(&p.b, &p.pa.hex), "block={block}");
        assert!(!sb.files.lock().unwrap().contains_key(&key_of(&p.pa)));
    }

    // Re-pin: the old session's record goes; the placeholder with the
    // queued message is written again.
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    fill_tracking(&mut p.b, &p.pa.hex);
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .pending_messages
        .push_back(pending_msg(0x44, "queued"));
    let before = std::time::Instant::now();
    p.b.apply_set_recipient(&p.pa.hex, Some(&hex::encode([0x99; 32])))
        .unwrap();
    // R1: the new keys' card brings its ML-KEM key; then the ask goes.
    assert!(p.b.peers.set_kem_pk(&p.pa.hex, p.pa.bundle.kem_pk.clone()));
    p.b.ask(
        &p.pa.hex,
        crate::circuits::AskTrigger::User,
        std::time::Instant::now(),
    )
    .unwrap();
    // The old pin's ask is gone; the one sent under the new pin is in
    // flight (Task 4).
    let fresh = p.b.unanswered_asks.remove(&p.pa.hex);
    assert!(fresh.is_some_and(|(at, _)| at >= before), "new pin's ask");
    assert!(tracking_cleared(&p.b, &p.pa.hex));
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(rec.session.is_none() && rec.retired.is_none());
    assert_eq!(rec.pending_send_ids, vec![[0x44; 16]]);
    assert!(rec.received_ids.is_empty() && rec.sent_ids.is_empty());

    // The rotation grace ends: the old identity's record goes.
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    fill_tracking(&mut p.b, &p.pa.hex);
    p.b.record_sent(&p.pa.hex, [2; 16]);
    p.b.pending_receipts.insert(
        (p.pa.hex.clone(), crate::receipts::DELIVERED),
        vec![[3; 16]],
    );
    p.b.intros.insert(p.pa.hex.clone(), intro());
    p.b.peers.unpin(&p.pa.hex);
    let now = std::time::Instant::now();
    p.b.rotated_from
        .insert(p.pa.hex.clone(), (peer(0x77).hex, now));
    p.b.purge_stale(now + std::time::Duration::from_secs(crate::ROTATION_GRACE_SECS + 1));
    assert!(p.b.session_manager.get(&p.pa.hex).is_none());
    assert!(tracking_cleared(&p.b, &p.pa.hex));
    assert!(!p.b.was_sent_to(&p.pa.hex, &[2; 16]), "sent ids");
    assert!(p.b.owed_receipts(&p.pa.hex).is_empty(), "receipts");
    assert!(!p.b.intros.contains_key(&p.pa.hex), "intro");
    assert!(!sb.files.lock().unwrap().contains_key(&key_of(&p.pa)));
}

/// Carry-over (h): the tick purges expired skipped keys (and expired retired
/// sessions) and writes the peers it changed, so no expired key stays on disk.
#[test]
fn tick_purges_expired_keys_from_the_stored_record() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    push_text(&p.a, &p.pb.hex, "skipped");
    sent_relays(&mut p.a_rx); // lost in transit: B keeps a skipped key
    push_text(&p.a, &p.pb.hex, "arrives");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(
        open_record(&sb, 0xB2, &p.pa)
            .session
            .unwrap()
            .ratchet
            .skipped
            .len(),
        1
    );
    p.b.session_manager
        .get_mut(&p.pa.hex)
        .unwrap()
        .ratchet
        .as_mut()
        .unwrap()
        .age_skipped_for_test(crate::crypto::SKIPPED_KEY_MAX_AGE_SECS + 1);
    p.b.purge_stale(std::time::Instant::now());
    assert!(open_record(&sb, 0xB2, &p.pa)
        .session
        .unwrap()
        .ratchet
        .skipped
        .is_empty());

    // An expired retired session leaves the record on the tick too.
    let replacement = crate::session::ChatSession::new(p.pa.hex.clone());
    p.b.session_manager.install(p.pa.hex.clone(), replacement);
    p.b.persist_peer(&p.pa.hex).unwrap();
    assert!(open_record(&sb, 0xB2, &p.pa).retired.is_some());
    p.b.session_manager
        .age_retired_for_test(&p.pa.hex, crate::session::RETIRED_MAX_AGE.as_secs() + 1);
    p.b.purge_stale(std::time::Instant::now());
    assert!(open_record(&sb, 0xB2, &p.pa).retired.is_none());
}

/// A record whose session was made under another agreement key than the
/// one now pinned (a re-pin whose delete failed) is not restored (C-1).
#[test]
fn session_made_under_an_old_pin_is_not_restored() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let (mut b2, _rx) = published(0xB2);
    b2.peers.pin(&p.pa.hex, [0x99; 32]).unwrap();
    with_store(&mut b2, &sb);
    let files: Vec<_> = sb.files.lock().unwrap().clone().into_iter().collect();
    b2.state.as_mut().unwrap().staged = files;
    b2.restore_staged_state();
    assert!(b2.session_manager.get(&p.pa.hex).is_none());
    assert!(b2.session_manager.retired_count(&p.pa.hex) == 0);
    let key = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .record_key_for(&p.pa.bundle.identity_key);
    assert!(!sb.files.lock().unwrap().contains_key(&key), "deleted");
}

/// The client API: `set_state_store` before `import_state_records` stages
/// valid records only (bad key, empty, oversize skipped); `clear_state`
/// forgets every session and staged record.
#[test]
fn client_api_stages_and_clears() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let files: Vec<(String, Vec<u8>)> = sb.files.lock().unwrap().clone().into_iter().collect();
    let n = files.len();
    let (mut b2, _rx) = published(0xB2);
    b2.peers.pin_card(&p.pa).unwrap();
    let client = wrap(b2);
    client.import_state_records(files.clone()); // no store yet: ignored
    assert!(client.inner.try_read().unwrap().state.is_none());
    client.set_state_store(&TEST_STATE_KEY, Arc::new(sb.clone()));
    let mut records = files;
    records.push(("../escape".into(), vec![1]));
    records.push((("ab".repeat(16)), Vec::new()));
    records.push((("cd".repeat(16)), vec![0; MAX_RECORD_BYTES + 1]));
    client.import_state_records(records);
    // Setting the store again keeps what is staged.
    client.set_state_store(&TEST_STATE_KEY, Arc::new(sb.clone()));
    {
        let g = client.inner.try_read().unwrap();
        assert_eq!(g.state.as_ref().unwrap().staged.len(), n);
    }
    client.inner.try_write().unwrap().restore_staged_state();
    assert!(client
        .inner
        .try_read()
        .unwrap()
        .session_manager
        .has_established_session(&p.pa.hex));
    client.import_state_records(sb.files.lock().unwrap().clone().into_iter().collect());
    client.clear_state();
    let g = client.inner.try_read().unwrap();
    assert!(g.session_manager.is_empty());
    assert!(g.state.as_ref().unwrap().staged.is_empty());
    assert!(g.received_ids.is_empty() && g.notice_due.is_empty());
}

/// Review I1: the meta record stays within `MAX_RECORD_BYTES` however much
/// is held: the oldest bodies that fit go in, the rest stay in memory, and
/// the closes and asks always survive a restart.
#[test]
fn meta_record_fits_however_much_is_held() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    for i in 0..3u8 {
        p.b.pending_encrypted_messages
            .push_back(crate::PendingEncrypted {
                sender_hex: p.pa.hex.clone(),
                message_id: [i; 16],
                body: vec![i; 1 << 20],
            });
    }
    p.b.pending_closes.push(C1);
    p.b.unanswered_asks
        .insert(p.pa.hex.clone(), (std::time::Instant::now(), 1));
    p.b_log.lock().unwrap().clear();
    p.b.persist_meta();
    assert_eq!(
        meta_persist_failures(&p.b_log),
        0,
        "the meta write succeeds"
    );
    let sealed_len = sb.files.lock().unwrap()[crate::state_store::META_KEY].len();
    assert!(sealed_len <= MAX_RECORD_BYTES);
    let meta = open_meta(&sb, 0xB2);
    let ids: Vec<[u8; 16]> = meta.held.iter().map(|h| h.message_id).collect();
    assert_eq!(ids, vec![[0; 16]], "oldest first, only what fits");
    assert_eq!(
        p.b.pending_encrypted_messages.len(),
        3,
        "all kept in memory"
    );

    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.pending_closes, vec![C1]);
    assert_eq!(b2.deferred_asks, vec![p.pa.hex.clone()]);
    assert_eq!(b2.pending_encrypted_messages.len(), 1);
}

/// Review m1: a second restore (records imported again after
/// `disconnect`/`connect`) duplicates nothing, and ids handed to the app in
/// this run stay delivered-unstored rather than lost.
#[test]
fn second_restore_duplicates_nothing() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let session = p.b.session_manager.remove(&p.pa.hex).unwrap();
    push_text(&p.a, &p.pb.hex, "held");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.session_manager.install(p.pa.hex.clone(), session);
    p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[5; 16]]);
    push_text(&p.b, &p.pa.hex, "sent by b");
    assert_eq!(open_record(&sb, 0xB2, &p.pa).sent_ids.len(), 1);

    let (mut b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    let id = push_text(&p.a, &p.pb.hex, "this run");
    let mut a_rx = std::mem::replace(&mut p.a_rx, tokio::sync::mpsc::channel(1).1);
    relay_all(&mut a_rx, &mut b2);
    assert!(b2.delivered_unstored[&p.pa.hex].contains(&id));
    let snapshot = |b: &ClientInner| {
        (
            b.pending_encrypted_messages.len(),
            b.owed_receipts(&p.pa.hex),
            b.received_ids[&p.pa.hex].len(),
            b.sent_ids_for(&p.pa.hex).len(),
            b.lost_unstored.get(&p.pa.hex).map_or(0, |q| q.len()),
        )
    };
    let before = snapshot(&b2);
    // Again, as after disconnect/connect with the records imported anew.
    let files = sb.files.lock().unwrap().clone();
    for (k, v) in files {
        b2.state.as_mut().unwrap().stage_keep_higher(k, v);
    }
    b2.restore_staged_state();
    assert_eq!(snapshot(&b2), before, "nothing added twice");
    assert!(b2.delivered_unstored[&p.pa.hex].contains(&id));
    assert!(
        !b2.lost_unstored
            .get(&p.pa.hex)
            .is_some_and(|q| q.contains(&id)),
        "this run's id is not lost"
    );
}

/// Review m2: setting the store again keeps the counters written.
#[test]
fn set_state_store_again_keeps_counters() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let key =
        p.b.state
            .as_ref()
            .unwrap()
            .keys
            .record_key_for(&p.pa.bundle.identity_key);
    let written = p.b.state.as_ref().unwrap().counters.lock().unwrap()[&key];
    let peer_hex = p.pa.hex.clone();
    let client = wrap(p.b);
    client.set_state_store(&TEST_STATE_KEY, Arc::new(sb.clone()));
    let g = client.inner.try_read().unwrap();
    assert_eq!(
        g.state.as_ref().unwrap().counters.lock().unwrap()[&key],
        written
    );
    g.persist_peer(&peer_hex).unwrap();
    let sealed = sb.files.lock().unwrap()[&key].clone();
    assert_eq!(
        u64::from_be_bytes(sealed[6..14].try_into().unwrap()),
        written + 1
    );
}

/// Review m4: a failed delete names the peer.
#[test]
fn failed_delete_names_the_peer() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    sb.fail.store(true, Ordering::SeqCst);
    p.b_log.lock().unwrap().clear();
    p.b.unpin_peer(&p.pa.hex).unwrap();
    assert!(
        statuses(&p.b_log).contains(&crate::status::StatusEvent::StatePersistFailed {
            peer: Some(p.pa.hex.clone())
        })
    );
}

/// Review m7: a retired session made under another pin is not restored
/// either (the current one under the pin, or none).
#[test]
fn retired_session_made_under_an_old_pin_is_not_restored() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    p.b.session_manager.install(
        p.pa.hex.clone(),
        crate::session::ChatSession::new(p.pa.hex.clone()),
    );
    p.b.persist_peer(&p.pa.hex).unwrap();
    let rec = open_record(&sb, 0xB2, &p.pa);
    assert!(rec.session.is_none() && rec.retired.is_some());
    assert_eq!(
        rec.retired.as_ref().unwrap().peer_ak,
        p.pa.bundle.identity_agreement_key
    );
    let (mut b2, _rx) = published(0xB2);
    b2.peers.pin(&p.pa.hex, [0x99; 32]).unwrap();
    with_store(&mut b2, &sb);
    b2.state.as_mut().unwrap().staged = sb.files.lock().unwrap().clone().into_iter().collect();
    b2.restore_staged_state();
    assert_eq!(b2.session_manager.retired_count(&p.pa.hex), 0);
    let key = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .record_key_for(&p.pa.bundle.identity_key);
    assert!(!sb.files.lock().unwrap().contains_key(&key), "deleted");
}

/// Task 3b re-review carry-over, Task 4 review fix 5: a record's sent id
/// missing from memory is merged by its send time (the list is oldest
/// first), and the merged list stays within `MAX_SENT_IDS`, dropping the
/// oldest entry.
#[test]
fn restore_merges_sent_ids_by_time_and_capped() {
    // `n` in-memory ids sent `offset` seconds after the record's id, then
    // the records restored again. Returns the merged list and the record id.
    let run = |n: usize, offset: i64| {
        let (sa, sb) = (MemorySink::default(), MemorySink::default());
        let mut p = stored_pair(&sa, &sb);
        let stored = push_text(&p.b, &p.pa.hex, "sent by b");
        let t0 = open_record(&sb, 0xB2, &p.pa).sent_ids[0].sent_at_unix;
        p.b.sent_ids.lock().unwrap().remove(&p.pa.hex);
        for i in 0..n as u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[15] = 0xEE;
            p.b.record_sent(&p.pa.hex, id);
        }
        for s in p.b.sent_ids.lock().unwrap().get_mut(&p.pa.hex).unwrap() {
            s.sent_at_unix = (t0 as i64 + offset) as u64;
        }
        let files = sb.files.lock().unwrap().clone();
        for (k, v) in files {
            p.b.state.as_mut().unwrap().stage_keep_higher(k, v);
        }
        p.b.restore_staged_state();
        (p.b.sent_ids_for(&p.pa.hex), stored)
    };
    let max = crate::circuits::MAX_SENT_IDS;
    // Room, memory newer: the record's id goes first.
    let (ids, stored) = run(2, 10);
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0].id, stored, "oldest first");
    // Full, memory newer: the record's id is the oldest, so it is the one dropped.
    let (ids, stored) = run(max, 10);
    assert_eq!(ids.len(), max, "capped");
    assert!(!ids.iter().any(|s| s.id == stored), "oldest dropped");
    // Full, memory older: the record's id is newest; the oldest memory id goes.
    let (ids, stored) = run(max, -10);
    assert_eq!(ids.len(), max, "capped");
    assert_eq!(ids[max - 1].id, stored, "newest last");
    assert!(!ids
        .iter()
        .any(|s| s.id[..4] == [0, 0, 0, 0] && s.id[15] == 0xEE));
}

/// Review fix 2a: on success, the session's record is written before the
/// meta record, and the meta record (carrying the answered ask) only once.
#[test]
fn answered_ask_meta_write_follows_the_session_write_once() {
    let sink = MemorySink::default();
    let (mut a, mut rx) = published(0xA1);
    with_store(&mut a, &sink);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    a.ask(
        &b.hex,
        crate::circuits::AskTrigger::User,
        std::time::Instant::now(),
    )
    .unwrap();
    let ek = sent_controls(&mut rx)
        .into_iter()
        .find_map(|c| match c {
            ControlMessage::CircuitAsk { ephemeral_key, .. } => {
                <[u8; 32]>::try_from(ephemeral_key.as_slice()).ok()
            }
            _ => None,
        })
        .unwrap();
    sink.log.lock().unwrap().clear();
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    feed(&mut a, created_v3(0, &b.bundle, ek, r_ek));
    assert!(a.has_live_circuit(&b.hex));
    let meta = crate::state_store::META_KEY;
    let keys: Vec<String> = sink
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(
        keys.iter().filter(|k| k.as_str() == meta).count(),
        1,
        "{keys:?}"
    );
    let first_peer = keys
        .iter()
        .position(|k| k != meta)
        .expect("session written");
    let meta_at = keys.iter().position(|k| k == meta).unwrap();
    assert!(first_peer < meta_at, "session before meta: {keys:?}");
    assert!(open_meta(&sink, 0xA1).unanswered_asks.is_empty());

    // A refusal still writes the cleared ask.
    let (mut a, mut rx) = published(0xA1);
    with_store(&mut a, &sink);
    a.peers.pin_card(&b).unwrap();
    a.ask(
        &b.hex,
        crate::circuits::AskTrigger::User,
        std::time::Instant::now(),
    )
    .unwrap();
    drop(sent_controls(&mut rx));
    assert_eq!(open_meta(&sink, 0xA1).unanswered_asks.len(), 1);
    feed(&mut a, created_v3(0, &b.bundle, [0x42; 32], r_ek));
    assert!(
        open_meta(&sink, 0xA1).unanswered_asks.is_empty(),
        "echo refusal"
    );
}

/// Review fix 2b: a restored ask is unanswered again, so a meta write
/// before the publish keeps it, and its re-send after the publish is
/// uncounted.
#[test]
fn restored_ask_survives_a_meta_write_and_is_resent_uncounted() {
    let sink = MemorySink::default();
    let (mut a, mut rx) = published(0xA1);
    with_store(&mut a, &sink);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    a.ask(
        &b.hex,
        crate::circuits::AskTrigger::User,
        std::time::Instant::now(),
    )
    .unwrap();
    drop(sent_controls(&mut rx));

    let (mut a2, mut rx2, _log) = restart_from(0xA1, 0xB2, &sink);
    a2.is_key_bundle_published = false;
    a2.persist_meta(); // e.g. a close or a held body before the publish
    assert_eq!(
        open_meta(&sink, 0xA1).unanswered_asks,
        vec![b.bundle.identity_key],
        "still named"
    );
    let attempts = a2.peers.backoff_mut(&b.hex).attempts();
    a2.is_key_bundle_published = true;
    a2.after_publish_ok(std::time::Instant::now());
    let asks = sent_controls(&mut rx2)
        .iter()
        .filter(|c| matches!(c, ControlMessage::CircuitAsk { .. }))
        .count();
    assert_eq!(asks, 1);
    assert_eq!(
        a2.peers.backoff_mut(&b.hex).attempts(),
        attempts,
        "uncounted"
    );
}

/// Task 4 (spec §18.6 D33): a real ask is written to the meta record, so a
/// restart re-sends it; its answer and a block each take it out again.
#[test]
fn unanswered_ask_is_in_the_meta_record_until_answered_or_blocked() {
    let sink = MemorySink::default();
    let (mut a, mut rx) = published(0xA1);
    with_store(&mut a, &sink);
    let b = peer(0xB2);
    a.peers.pin_card(&b).unwrap();
    let ask_ek = |a: &mut ClientInner, rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>| {
        a.unanswered_asks.clear(); // past the in-flight window
        a.ask(
            &b.hex,
            crate::circuits::AskTrigger::User,
            std::time::Instant::now(),
        )
        .unwrap();
        sent_controls(rx)
            .into_iter()
            .find_map(|c| match c {
                ControlMessage::CircuitAsk { ephemeral_key, .. } => {
                    <[u8; 32]>::try_from(ephemeral_key.as_slice()).ok()
                }
                _ => None,
            })
            .expect("an ask")
    };
    let ek = ask_ek(&mut a, &mut rx);
    assert_eq!(
        open_meta(&sink, 0xA1).unanswered_asks,
        vec![b.bundle.identity_key]
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sink);
    assert_eq!(
        a2.deferred_asks,
        vec![b.hex.clone()],
        "asked again after a restart"
    );

    // Answered.
    let r_ek = crate::crypto::EphemeralKeyPair::generate()
        .public_key()
        .to_bytes();
    feed(&mut a, created_v3(0, &b.bundle, ek, r_ek));
    assert!(a.has_live_circuit(&b.hex));
    assert!(
        open_meta(&sink, 0xA1).unanswered_asks.is_empty(),
        "answered"
    );

    // Blocked while an ask is in flight.
    a.session_manager.remove(&b.hex);
    ask_ek(&mut a, &mut rx);
    assert_eq!(open_meta(&sink, 0xA1).unanswered_asks.len(), 1);
    a.block_peer(&b.hex, true).unwrap();
    assert!(open_meta(&sink, 0xA1).unanswered_asks.is_empty(), "blocked");
}

/// Task 4 re-review: when the new session's write fails, the answered ask
/// stays in the meta record, so a kill before the next good write still
/// finds it (and asks again) instead of losing both.
#[test]
fn answered_ask_stays_on_disk_while_the_session_write_fails() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let (ek_a, ek_b) = (
        crate::crypto::EphemeralKeyPair::generate(),
        crate::crypto::EphemeralKeyPair::generate(),
    );
    let (i, r) = (ek_a.public_key().to_bytes(), ek_b.public_key().to_bytes());
    p.a.peers
        .push_ask(&p.pb.hex, ek_a, std::time::Instant::now());
    p.a.unanswered_asks
        .insert(p.pb.hex.clone(), (std::time::Instant::now(), 1));
    p.a.persist_meta();
    assert_eq!(open_meta(&sa, 0xA1).unanswered_asks.len(), 1);
    // Only the peer record's write fails; a meta write would go through.
    let key = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .record_key_for(&p.pb.bundle.identity_key);
    sa.fail_keys.lock().unwrap().insert(key);
    feed(&mut p.a, created_v3(0, &p.pb.bundle, i, r));
    assert!(!p.a.unanswered_asks.contains_key(&p.pb.hex), "answered");
    assert_eq!(
        open_meta(&sa, 0xA1).unanswered_asks,
        vec![p.pb.bundle.identity_key],
        "still on disk"
    );
    // Review minor 4: an unrelated meta write keeps naming it.
    p.a.persist_meta();
    assert_eq!(
        open_meta(&sa, 0xA1).unanswered_asks,
        vec![p.pb.bundle.identity_key],
        "an unrelated meta write keeps it"
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    assert_eq!(a2.deferred_asks, vec![p.pb.hex.clone()], "asked again");
    // The session's first good write drops it from the meta record.
    sa.fail_keys.lock().unwrap().clear();
    p.a.persist_peer(&p.pb.hex).unwrap();
    assert!(open_meta(&sa, 0xA1).unanswered_asks.is_empty(), "durable");
}

/// RV3: B loses all state while A has 3 queued messages for it.
#[test]
fn rv3_reinstall_recovery() {
    let r = rv3_run(3, |_, _| {});
    let Rv3 {
        mut p,
        ids,
        earlier,
        receipted,
        b2,
        b2_log,
        ..
    } = r;
    let b_fail = statuses(&b2_log)
        .iter()
        .filter(|s| {
            matches!(
                s,
                crate::status::StatusEvent::DecryptFailed { detail: 2, .. }
            )
        })
        .count();
    assert_eq!(b_fail, 3, "held bodies failed after install");
    let a_ev = statuses(&p.a_log);
    for id in &ids {
        assert!(a_ev.contains(&crate::status::StatusEvent::PeerUndelivered {
            peer: p.pb.hex.clone(),
            message_id: hex::encode(id),
            reason: 1
        }));
    }
    assert!(
        a_ev.contains(&crate::status::StatusEvent::PeerSessionReset {
            peer: p.pb.hex.clone()
        })
    );
    assert!(a_ev.contains(&crate::status::StatusEvent::PeerUndelivered {
        peer: p.pb.hex.clone(),
        message_id: hex::encode(earlier),
        reason: 3
    }));
    assert!(
        !a_ev.iter().any(|e| matches!(e, crate::status::StatusEvent::PeerUndelivered { message_id, .. } if *message_id == hex::encode(receipted))),
        "a receipted message is never reported"
    );
    // RV6: no key event, pin unchanged, no request. (audit tag: fn rv6_ is asserted here, inside rv3_reinstall_recovery)
    assert!(!p
        .a_log
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Ev::PeerKey(..) | Ev::Request(_))));
    assert_eq!(
        p.a.peers.state(&p.pb.hex),
        crate::peers::PeerKeyState::Pinned
    );
    // The reset is raised once per session, whatever the peer sends next.
    let again = crate::notice::encode(&crate::notice::Notice {
        flags: crate::notice::FLAG_NO_PRIOR_SESSION,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = b2.seal_ratchet(&p.pa.hex, [3; 16], &again).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    let resets = statuses(&p.a_log)
        .iter()
        .filter(|s| matches!(s, crate::status::StatusEvent::PeerSessionReset { .. }))
        .count();
    assert_eq!(resets, 1, "once per session");
}

/// The companion of `rv3_reinstall_recovery` (fix round 1 (e)): the
/// queued sends left a second or more before the new session, as they
/// usually do in real use. A's reset report takes them (reason 3) and
/// makes them eligible; B's later reason-1 notice for them is then not
/// reported again, and nothing is made eligible twice.
#[test]
fn rv3_queued_sends_older_than_the_session_are_reason_3_once() {
    let r = rv3_run(3, |a, b| a.age_sent_for_test(&b.hex, 1));
    let a_ev = statuses(&r.p.a_log);
    for id in &r.ids {
        let hex_id = hex::encode(id);
        let reasons: Vec<u8> = a_ev
            .iter()
            .filter_map(|e| match e {
                crate::status::StatusEvent::PeerUndelivered {
                    message_id, reason, ..
                } if *message_id == hex_id => Some(*reason),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, vec![3], "reason 3 only, once");
        let eligible = a_ev
            .iter()
            .filter(|e| matches!(e, crate::status::StatusEvent::ResendEligible { message_id, .. } if *message_id == hex_id))
            .count();
        assert_eq!(eligible, 1, "made eligible once: no duplicate resend");
    }
}

/// SP13: decrypted, then a crash before the app stored it → reason 2.
#[test]
fn sp13_lost_before_stored_is_reported() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "never stored");
    relay_all(&mut p.a_rx, &mut p.b); // no mark_seen_and_receipt: the app died
    let (mut b2, mut b2_rx, _log) = restart_from(0xB2, 0xA1, &sb);
    keep_identity_path(&mut b2, &p.pa.hex); // resumes its identity circuit (Task 9)
    b2.after_publish_ok(std::time::Instant::now());
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    b2.fire_due_receipts(std::time::Instant::now() + std::time::Duration::from_secs(5));
    relay_all(&mut b2_rx, &mut p.a);
    assert!(
        statuses(&p.a_log).contains(&crate::status::StatusEvent::PeerUndelivered {
            peer: p.pb.hex.clone(),
            message_id: hex::encode(id),
            reason: 2
        })
    );
}

/// RV7: no delivered receipt without mark_message_seen; one with it; an
/// already-seen id (an intro) gets its receipt at decrypt.
#[test]
fn rv7_delivered_after_stored() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "store me");
    relay_all(&mut p.a_rx, &mut p.b);
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 0, "no receipt at decrypt");
    p.b.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    assert_eq!(relay_all(&mut p.b_rx, &mut p.a), 1);
    let intro: [u8; 16] = [0x1d; 16];
    p.b.peers.mark_seen(&p.pa.hex, intro);
    let pk =
        p.a.seal_ratchet(&p.pb.hex, intro, b"\x01\0\0\0\0intro text")
            .unwrap();
    feed(&mut p.b, Frame::Relay(pk));
    assert_eq!(
        relay_all(&mut p.b_rx, &mut p.a),
        1,
        "seen id: receipt at decrypt"
    );
}

/// RV8: the responder queues sends before its sending chain → QueuedSendLost
/// after a restart; no plaintext in any record.
#[test]
fn rv8_queued_sends_lost_are_reported_without_plaintext() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    {
        let mut s = p.b.session_manager.get_mut(&p.pa.hex).unwrap();
        for i in 0..2u8 {
            s.pending_messages
                .push_back(crate::session::PendingMessage {
                    id: crate::protocol::MessageId(hex::encode([i; 16])),
                    content: b"SECRET-PLAINTEXT".to_vec(),
                    msg_type: crate::protocol::MessageType::Text,
                    timestamp_ms: 0,
                });
        }
    }
    p.b.persist_peer(&p.pa.hex).unwrap();
    assert!(sb
        .files
        .lock()
        .unwrap()
        .values()
        .all(|v| !v.windows(16).any(|w| w == b"SECRET-PLAINTEXT")));
    let (_b2, _rx, log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(
        statuses(&log)
            .iter()
            .filter(|s| matches!(s, crate::status::StatusEvent::QueuedSendLost { .. }))
            .count(),
        2
    );
}

/// OB2: no key, token or record bytes in logs or events, and no line with
/// two identity values (R6), over SP8, RV3 and AK1's flow.
#[test]
fn ob2_no_secrets_in_logs_or_events() {
    let cap = LogCapture::start();
    sp8_restart_with_a_queue_delivers();
    rv3_reinstall_recovery();
    crate::circuits::tests::ak1_flow_for_ob2();
    let captured = cap.take();
    let mut needles = vec![hex::encode(TEST_STATE_KEY), hex::encode(TOKEN)];
    for s in [0xA1u8, 0xB2] {
        needles.push(hex::encode(peer(s).id.agreement_secret().to_bytes()));
    }
    // Log lines and status events alike.
    for needle in &needles {
        assert!(!captured.contains(needle.as_str()));
    }
    let (events, logs): (Vec<&str>, Vec<&str>) =
        captured.lines().partition(|l| l.starts_with("EVENT "));
    let ids: Vec<String> = [0xA1u8, 0xB2].iter().map(|s| peer(*s).hex).collect();
    assert!(logs.iter().all(|l| identity_values_in(l, &ids) < 2), "R6");
    assert!(!logs.is_empty(), "the capture saw the flows' log lines");
    assert!(
        events.iter().any(|e| e.contains("PeerUndelivered")),
        "the capture saw the flows' events"
    );
}

/// Carry-over: a message lost before it was stored (reported, reason 2)
/// passes the duplicate drop once when its sender resends it under the
/// same id, also after another restart; a replay of the original envelope
/// raises nothing, and every other replay is still dropped before decrypt.
#[test]
fn lost_id_resend_passes_the_duplicate_drop_and_other_replays_do_not() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let stored = push_text(&p.a, &p.pb.hex, "stored");
    relay_all(&mut p.a_rx, &mut p.b);
    p.b.mark_seen_and_receipt(&p.pa.hex, stored).unwrap();
    let id = push_text(&p.a, &p.pb.hex, "never stored");
    let original = sent_relays(&mut p.a_rx);
    let stored_replay = original.clone();
    for pk in original.clone() {
        feed(&mut p.b, Frame::Relay(pk));
    }
    let (mut b2, mut b2_rx, b2_log) = restart_from(0xB2, 0xA1, &sb);
    keep_identity_path(&mut b2, &p.pa.hex); // resumes its identity circuit (Task 9)
    b2.after_publish_ok(std::time::Instant::now());
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    relay_all(&mut b2_rx, &mut p.a); // the reason-2 notice
    assert!(b2
        .lost_unstored
        .get(&p.pa.hex)
        .map_or(true, |q| q.is_empty()));
    assert!(
        b2.lost_reported[&p.pa.hex].iter().any(|(x, _)| *x == id),
        "still listed lost"
    );
    // A replay of the original envelope: its key is spent; nothing raised.
    for pk in stored_replay {
        feed(&mut b2, Frame::Relay(pk));
    }
    assert!(texts(&b2_log).is_empty());
    assert!(statuses(&b2_log)
        .iter()
        .all(|s| !matches!(s, crate::status::StatusEvent::DecryptFailed { .. })));
    // Every other replay is dropped before decrypt: the stored message's id.
    let attempts = |c: &ClientInner| c.decrypt_attempts.load(Ordering::Relaxed);
    let stored_again =
        p.a.seal_ratchet(&p.pb.hex, stored, b"\x01\0\0\0\0stored")
            .unwrap();
    let before = attempts(&b2);
    feed(&mut b2, Frame::Relay(stored_again));
    assert_eq!(
        attempts(&b2),
        before,
        "a non-lost id is never decrypted twice"
    );
    // Restart again: the lost listing survives on disk.
    drop(b2);
    let (mut b3, _b3_rx, b3_log) = restart_from(0xB2, 0xA1, &sb);
    let resend =
        p.a.seal_ratchet(&p.pb.hex, id, b"\x01\0\0\0\0never stored")
            .unwrap();
    let resend_replay = resend.clone();
    feed(&mut b3, Frame::Relay(resend));
    assert_eq!(
        texts(&b3_log),
        vec![b"never stored".to_vec()],
        "resend delivered"
    );
    assert!(!b3
        .lost_reported
        .get(&p.pa.hex)
        .is_some_and(|q| q.iter().any(|(x, _)| *x == id)));
    let before = attempts(&b3);
    feed(&mut b3, Frame::Relay(resend_replay));
    assert_eq!(texts(&b3_log).len(), 1, "the resend's replay is dropped");
    assert_eq!(attempts(&b3), before, "before decrypt");
}

/// A notice whose send fails keeps its ids: once writes succeed the tick
/// re-sends it and the sender learns of the undecryptable message.
#[test]
fn notice_ids_survive_a_failed_send() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    give_device_keys(&mut p.a, &mut p.b, &p.pb.hex);
    let id = push_text(&p.a, &p.pb.hex, "mangled on the way");
    drain(&mut p.a_rx);
    let body = [vec![0u8; crate::crypto::RatchetHeader::LEN], vec![1u8; 64]].concat();
    let mangled = crate::sealed::seal(
        id,
        &p.pb.bundle.identity_key,
        &p.pb.bundle.identity_agreement_key,
        &p.pa.bundle.identity_key,
        crate::sealed::KIND_RATCHET,
        &body,
    )
    .unwrap();
    sb.fail.store(true, Ordering::SeqCst);
    feed(&mut p.b, queued(mangled));
    assert!(
        sent_relays(&mut p.b_rx).is_empty(),
        "nothing leaves unpersisted"
    );
    assert_eq!(p.b.undecryptable[&p.pa.hex].len(), 1, "the id is kept");
    sb.fail.store(false, Ordering::SeqCst);
    p.b.redrive_owed_sends(std::time::Instant::now());
    relay_all(&mut p.b_rx, &mut p.a);
    assert_eq!(
        statuses(&p.a_log),
        vec![
            crate::status::StatusEvent::PeerUndelivered {
                peer: p.pb.hex.clone(),
                message_id: hex::encode(id),
                reason: 1
            },
            // Every D38 guard holds (plainly pinned, same keys, fresh,
            // signed by the pinned DK).
            crate::status::StatusEvent::ResendEligible {
                peer: p.pb.hex.clone(),
                message_id: hex::encode(id),
            }
        ]
    );
    assert!(!p.b.notice_due.contains(&p.pa.hex));
}

/// A message lost before it was stored, then reported: its listing
/// expires after 72 h (tick and restore); a replay of the original is then
/// dropped before decrypt. A future stamp is re-stamped to now.
#[test]
fn reported_lost_ids_expire_after_72_hours() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "never stored");
    let original = sent_relays(&mut p.a_rx);
    for pk in original.clone() {
        feed(&mut p.b, Frame::Relay(pk));
    }
    let (mut b2, mut b2_rx, _log) = restart_from(0xB2, 0xA1, &sb);
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    relay_all(&mut b2_rx, &mut p.a); // the reason-2 notice
    let a_hex = p.pa.hex.clone();
    let now = crate::unix_now_secs();
    // A future stamp comes back to now.
    b2.lost_reported.get_mut(&a_hex).unwrap()[0].1 = now + 1_000_000;
    b2.purge_stale(std::time::Instant::now());
    let at = b2.lost_reported[&a_hex][0].1;
    assert!(at <= crate::unix_now_secs() && at + 5 >= now, "re-stamped");
    // Aged past 72 h, persisted as such, then a restart drops it at restore.
    b2.lost_reported.get_mut(&a_hex).unwrap()[0].1 =
        now - crate::circuits::RESET_REPORT_MAX_AGE_SECS - 1;
    b2.persist_peer(&a_hex).unwrap();
    let (b3, _b3_rx, _l3) = restart_from(0xB2, 0xA1, &sb);
    assert!(
        b3.lost_reported.get(&a_hex).map_or(true, |q| q.is_empty()),
        "restore"
    );
    // And the tick drops it, on disk too.
    b2.purge_stale(std::time::Instant::now());
    assert!(!b2.lost_reported.contains_key(&a_hex), "tick");
    assert!(open_record(&sb, 0xB2, &p.pa).lost_reported.is_empty());
    let before = b2.decrypt_attempts.load(Ordering::Relaxed);
    for pk in original {
        feed(&mut b2, Frame::Relay(pk));
    }
    assert_eq!(
        b2.decrypt_attempts.load(Ordering::Relaxed),
        before,
        "an expired lost id is a plain duplicate again"
    );
    let _ = id;
}

/// With no usable transport (a closed outgoing queue, or none), an owed
/// notice is never sealed: no chain key burnt, no write, however many ticks.
#[test]
fn owed_notice_burns_nothing_while_the_transport_is_down() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let Pair {
        mut a, a_rx, pb, ..
    } = p;
    drop(a_rx); // the read loop ended: the queue is closed
    a.notice_due.insert(pb.hex.clone());
    let ns = |a: &ClientInner| {
        a.session_manager
            .get(&pb.hex)
            .unwrap()
            .ratchet_snapshot()
            .unwrap()
            .ns
    };
    let (ns0, tried0) = (ns(&a), sa.tried.load(Ordering::SeqCst));
    let t0 = std::time::Instant::now();
    for round in 0..2 {
        if round == 1 {
            a.websocket = None; // no transport at all
        }
        for i in 0..100u64 {
            let t = t0 + std::time::Duration::from_millis(250 * i);
            a.redrive_owed_sends(t);
            a.fire_due_receipts(t);
            a.flush_receipts(&pb.hex);
        }
        assert_eq!(ns(&a), ns0, "no chain key spent");
        assert_eq!(sa.tried.load(Ordering::SeqCst), tried0, "no write storm");
        assert!(a.notice_due.contains(&pb.hex), "still owed");
    }
}

/// A notice that is still owed after a restart keeps its no-prior-session flag.
#[test]
fn owed_notice_flag_survives_a_restart() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    b.receipt_delay_override = Some(std::time::Duration::from_secs(60)); // B's notice waits
    reestablish(&mut a, &mut b, &pa, &pb);
    relay_all(&mut a_rx, &mut b); // session-init: B installs (v3, §A.3)
    assert_eq!(open_record(&sb, 0xB2, &pa).notice_flags, 1);
    let (b2, _rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert!(b2.notice_due.contains(&pa.hex));
    assert_eq!(b2.notice_flag_pending.get(&pa.hex), Some(&1));
}

/// No write ever leaves a lost id in neither list: it stays in
/// `lost_unstored` until its notice left, then is in `lost_reported`.
#[test]
fn a_lost_id_is_always_on_one_list_on_disk() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "never stored");
    relay_all(&mut p.a_rx, &mut p.b);
    let (mut b2, mut b2_rx, _log) = restart_from(0xB2, 0xA1, &sb);
    let from = sb.history.lock().unwrap().len();
    feed(
        &mut b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
    assert_eq!(relay_all(&mut b2_rx, &mut p.a), 1, "the notice left");
    let key = crate::state_store::StateKeys::new(TEST_STATE_KEY)
        .record_key_for(&p.pa.bundle.identity_key);
    let writes: Vec<_> = sb.history.lock().unwrap()[from..]
        .iter()
        .filter(|(k, _)| *k == key)
        .map(|(k, sealed)| open_sealed(0xB2, k, sealed))
        .collect();
    assert!(writes.len() >= 2, "the seal's write and the report's");
    for rec in &writes {
        let listed =
            rec.lost_unstored_ids.contains(&id) || rec.lost_reported.iter().any(|(x, _)| *x == id);
        assert!(listed, "never in neither list");
    }
    assert!(writes
        .last()
        .unwrap()
        .lost_reported
        .iter()
        .any(|(x, _)| *x == id));
}

/// A sink whose first failing write has another thread remove the peer's
/// session (queued for the write lock before the write returns), so the
/// session is gone when `flush_queued_sends` puts the batch back.
struct SessionRemovingSink {
    inner: MemorySink,
    client: Arc<std::sync::OnceLock<std::sync::Weak<tokio::sync::RwLock<ClientInner>>>>,
    peer: String,
    armed: std::sync::atomic::AtomicBool,
}

impl crate::state_store::StateSink for SessionRemovingSink {
    fn write(&self, key: &str, sealed: &[u8]) -> Result<(), String> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return self.inner.write(key, sealed);
        }
        let client = self.client.get().and_then(|w| w.upgrade()).unwrap();
        let (remover, peer) = (client.clone(), self.peer.clone());
        std::thread::spawn(move || {
            remover.blocking_write().session_manager.forget(&peer);
        });
        // A queued writer turns new readers away: wait for that.
        let start = std::time::Instant::now();
        while client.try_read().is_ok() && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::yield_now();
        }
        Err("disk full".into())
    }
}

/// The `QueuedSendLost` call site: `flush_queued_sends` drives a batch, a
/// write fails, and the session is gone when the batch would go back.
#[test]
fn flush_queued_sends_reports_a_batch_whose_session_went() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    {
        let mut s = p.b.session_manager.get_mut(&p.pa.hex).unwrap();
        s.pending_messages.push_back(pending_msg(1, "x"));
        s.pending_messages.push_back(pending_msg(2, "y"));
    }
    let slot = Arc::new(std::sync::OnceLock::new());
    p.b.state = Some(StateStore {
        keys: StateKeys::new(TEST_STATE_KEY),
        sink: Arc::new(SessionRemovingSink {
            inner: sb.clone(),
            client: slot.clone(),
            peer: p.pa.hex.clone(),
            armed: std::sync::atomic::AtomicBool::new(true),
        }),
        counters: Default::default(),
        failing: Default::default(),
        staged: Vec::new(),
    });
    let b_log = p.b_log.clone();
    let a_hex = p.pa.hex.clone();
    if let Some(ws) = &p.b.websocket {
        ws.set_connected_for_test();
    }
    let client = wrap(p.b);
    let _ = slot.set(Arc::downgrade(&client.inner));
    client.process_pending().unwrap();
    assert!(client
        .inner
        .try_read()
        .unwrap()
        .session_manager
        .get(&a_hex)
        .is_none());
    let lost: Vec<_> = statuses(&b_log)
        .into_iter()
        .filter_map(|s| match s {
            crate::status::StatusEvent::QueuedSendLost { peer, message_id } if peer == a_hex => {
                Some(message_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(lost, vec![hex::encode([1u8; 16]), hex::encode([2u8; 16])]);
}

// ---- D38 guards for automatic resend (spec §18.6, RS1-RS8) ----

use crate::circuits::MAX_AUTO_RESENDS_PER_DAY;
use crate::peers::PeerKeyState;
use crate::status::StatusEvent;

fn eligible(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| matches!(s, StatusEvent::ResendEligible { .. }))
        .count()
}

/// A reason-1 notice naming `ids`, handed straight to `handle_notice` as
/// if it decrypted under `by`: past `try_ratchet`'s sender filter, so the
/// D38 guards alone decide.
fn notice_direct(
    a: &mut ClientInner,
    peer: &str,
    ids: &[[u8; 16]],
    by: crate::session::DecryptedBy,
) {
    let n = crate::notice::Notice {
        flags: 0,
        reason: crate::notice::REASON_UNDECRYPTABLE,
        ids: ids.to_vec(),
        sig: None,
    };
    let (n, binding) = signed_by_pinned_dk(a, peer, n);
    a.handle_notice(peer, n, by, binding);
}

/// A pins `b_hex`'s software DK (seed 1) and `b` signs with it (guard 7).
fn give_device_keys(a: &mut ClientInner, b: &mut ClientInner, b_hex: &str) {
    use crate::device_key::test_keys::{soft_dk, SoftSigner};
    a.peers.pin_device_key(b_hex, soft_dk(1).1);
    b.device_signer = Some(Arc::new(SoftSigner(soft_dk(1).0)));
}

/// `n` signed by `sender`'s device signer for its current session with
/// `recipient`, exactly as `send_notice_now` signs.
fn signed_as(
    sender: &ClientInner,
    recipient: &str,
    mut n: crate::notice::Notice,
) -> crate::notice::Notice {
    let binding = sender
        .session_manager
        .get(recipient)
        .unwrap()
        .session_binding;
    let tbs = crate::notice::tbs(
        &sender.our_ik().unwrap(),
        &crate::peers::key_from_hex(recipient).unwrap(),
        &binding,
        &n,
    )
    .unwrap();
    n.sig = sender.device_signer.as_ref().unwrap().sign(&tbs);
    n
}

/// `n` as `peer` would send it under A's current session with them, signed
/// by the DK from seed 1, pinned for `peer` here when they are pinned and
/// have none (guard 7 holds, so guards 1–6 decide), with that session's
/// binding.
fn signed_by_pinned_dk(
    a: &mut ClientInner,
    peer: &str,
    mut n: crate::notice::Notice,
) -> (crate::notice::Notice, Option<[u8; 32]>) {
    use p256::ecdsa::signature::Signer;
    let (sk, pin) = crate::device_key::test_keys::soft_dk(1);
    if a.peers.pin_for(peer).is_some() && a.peers.device_key(peer).is_none() {
        a.peers.pin_device_key(peer, pin);
    }
    let binding = a.session_manager.get(peer).map(|s| s.session_binding);
    if let (Some(b), Some(my_ik), Some(peer_ik)) =
        (binding, a.our_ik(), crate::peers::key_from_hex(peer))
    {
        let sig: p256::ecdsa::Signature =
            sk.sign(&crate::notice::tbs(&peer_ik, &my_ik, &b, &n).unwrap());
        n.sig = Some(sig.to_bytes().into());
    }
    (n, binding)
}

/// RS1: all guards hold → one ResendEligible per lost id; persisted as
/// resent, so a restart and a repeated notice raise none.
#[test]
fn rs1_eligible_once() {
    let r = rv3_run(3, |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 3 + 1, "3 queued + 1 reason-3");
    let mut want: Vec<String> = r.ids.iter().map(hex::encode).collect();
    want.push(hex::encode(r.earlier));
    let mut got: Vec<String> = statuses(&r.p.a_log)
        .into_iter()
        .filter_map(|s| match s {
            StatusEvent::ResendEligible { peer, message_id } => {
                assert_eq!(peer, r.p.pb.hex);
                Some(message_id)
            }
            _ => None,
        })
        .collect();
    want.sort();
    got.sort();
    assert_eq!(got, want, "exactly the lost ids, each once");
    let rec = r.p.a.peer_record(&r.p.pb.hex).unwrap();
    assert_eq!(rec.sent_ids.iter().filter(|e| e.resent).count(), 4);
    let stored = open_record(&r.sa, 0xA1, &r.p.pb);
    assert_eq!(
        stored.sent_ids.iter().filter(|e| e.resent).count(),
        4,
        "durable"
    );
    assert_eq!(stored.auto_resends_unix.len(), 4, "counted for the bound");
    let (mut a2, _rx, a2_log) = restart_from(0xA1, 0xB2, &r.sa);
    // The app restores the DK it stored from the scan (D44 syncPins).
    a2.peers
        .pin_device_key(&r.p.pb.hex, crate::device_key::test_keys::soft_dk(1).1);
    // One id the notice names for the first time, so it visibly counts.
    let fresh: [u8; 16] = [0xF5; 16];
    a2.record_sent(&r.p.pb.hex, fresh);
    let mut named = r.ids.clone();
    named.push(fresh);
    let (b2, mut b2_rx) = (r.b2, r.b2_rx);
    // Signed under the session A restored: its binding survived the restart.
    let pt = crate::notice::encode(&signed_as(
        &b2,
        &r.p.pa.hex,
        crate::notice::Notice {
            flags: 0,
            reason: 1,
            ids: named,
            sig: None,
        },
    ))
    .unwrap();
    assert!(
        sent_relays(&mut b2_rx).is_empty(),
        "B's notices all reached A"
    );
    let pk = b2.seal_ratchet(&r.p.pa.hex, rand::random(), &pt).unwrap();
    feed(&mut a2, Frame::Relay(pk));
    // The session's reported ids are persisted with it: the ids it made
    // eligible are not reported again after the restart (their resend is
    // under way), and never made eligible twice.
    assert_eq!(
        statuses(&a2_log),
        vec![
            StatusEvent::PeerUndelivered {
                peer: r.p.pb.hex.clone(),
                message_id: hex::encode(fresh),
                reason: 1
            },
            StatusEvent::ResendEligible {
                peer: r.p.pb.hex.clone(),
                message_id: hex::encode(fresh),
            }
        ],
        "only the fresh id; never twice, across a restart"
    );
}

/// RS1 (write-ahead, D28): `resent` is durable before the event is
/// raised. A failed write raises none and leaves the entries unmarked, so
/// the next notice can still make them eligible.
#[test]
fn rs1_resend_is_announced_only_once_durable() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let done = push_text(&p.a, &p.pb.hex, "lost earlier, resent");
    let id = push_text(&p.a, &p.pb.hex, "lost");
    drain(&mut p.a_rx);
    let peer_hex = p.pb.hex.clone();
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[done],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 1);
    p.a_log.lock().unwrap().clear();
    sa.fail.store(true, Ordering::SeqCst);
    notice_direct(
        &mut p.a,
        &p.pb.hex.clone(),
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 0, "not durable: not announced");
    let resent = |p: &Pair, x: [u8; 16]| {
        p.a.sent_ids_for(&p.pb.hex)
            .iter()
            .find(|e| e.id == x)
            .unwrap()
            .resent
    };
    assert!(!resent(&p, id), "rolled back");
    assert!(resent(&p, done), "an earlier mark is restored as it was");
    assert_eq!(p.a.auto_resends[&peer_hex].len(), 1, "uncounted");
    sa.fail.store(false, Ordering::SeqCst);
    notice_direct(
        &mut p.a,
        &p.pb.hex.clone(),
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 1, "the repeat may make it eligible");
    assert!(open_record(&sa, 0xA1, &p.pb)
        .sent_ids
        .iter()
        .any(|e| e.id == id && e.resent));
}

/// RS1: a same-id resend is recorded as sent again; that entry inherits
/// `resent`, so a later loss never makes the message eligible twice.
#[test]
fn rs1_same_id_resend_is_never_eligible_again() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "lost");
    drain(&mut p.a_rx);
    let peer_hex = p.pb.hex.clone();
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 1);
    // The app resends with the same id (the `seal_ratchet` path the FFI's
    // same-id send uses records it again).
    let pk =
        p.a.seal_ratchet(&peer_hex, id, b"\x01\0\0\0\0lost")
            .unwrap();
    drop(pk);
    assert_eq!(p.a.sent_ids_for(&peer_hex).len(), 2, "recorded again");
    // A later session (its reported set starts empty) loses it again.
    p.a.session_manager
        .get_mut(&peer_hex)
        .unwrap()
        .reported_lost
        .clear();
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(
        eligible(&p.a_log),
        1,
        "at most one automatic resend per message"
    );
}

/// A real rotation of A's contact `old` → `new` (spec §4.8): a knock from
/// `new` to `us` carrying a version-1 chain from `old`.
fn rotate_contact(a: &mut ClientInner, old: &Peer, new: &Peer, us: &Peer) {
    let blk = crate::rotation::RotationBlock {
        current_version: 1,
        links: vec![crate::rotation::sign_link(
            &old.id,
            &new.bundle.identity_key,
            &new.bundle.identity_agreement_key,
            1,
        )],
    };
    feed(
        a,
        queued(knock_from_rotating(
            new,
            us,
            crate::circuits::now_hour(),
            &blk,
        )),
    );
    assert!(a.rotated_from.contains_key(&old.hex), "rotation applied");
}

fn undelivered_count(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    statuses(log)
        .iter()
        .filter(|s| matches!(s, StatusEvent::PeerUndelivered { .. }))
        .count()
}

/// Guard 1 in the rotation grace: a notice decrypted under the old
/// identity's session is not the new identity's current session, so it
/// reports nothing and makes nothing eligible.
#[test]
fn guard1_old_identity_session_notice_in_the_grace_counts_for_nothing() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "before the rotation");
    drain(&mut p.a_rx);
    let new = peer(0xB9);
    rotate_contact(&mut p.a, &p.pb, &new, &p.pa);
    assert!(
        p.a.was_sent_to(&new.hex, &id),
        "the id moved to the new identity"
    );
    // The new identity already has its own session with A; the old one's
    // session still decrypts in-flight messages.
    let (mut b9, mut b9_rx) = published(0xB9);
    b9.peers.pin_card(&p.pa).unwrap();
    reestablish(&mut p.a, &mut b9, &p.pa, &new);
    relay_all(&mut p.a_rx, &mut b9);
    drain(&mut b9_rx);
    assert!(p.a.session_manager.has_established_session(&new.hex));
    p.a_log.lock().unwrap().clear();
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 1,
        ids: vec![id],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, rand::random(), &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    assert_eq!(undelivered_count(&p.a_log), 0);
    assert_eq!(eligible(&p.a_log), 0);
}

/// RS2: an applied rotation (either direction) → zero.
#[test]
fn rs2_rotation_guard() {
    let r = rv3_run(3, |a, b| {
        a.rotated_from
            .insert(b.hex.clone(), ("ff".repeat(32), std::time::Instant::now()));
    });
    assert_eq!(eligible(&r.p.a_log), 0, "the peer is the old identity");
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    let r = rv3_run(3, |a, b| {
        a.rotated_from
            .insert("ee".repeat(32), (b.hex.clone(), std::time::Instant::now()));
    });
    assert_eq!(eligible(&r.p.a_log), 0, "the peer is the new identity");
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    // A real rotation before B's notices: they decrypt under the old
    // identity's session (guard 1).
    let r = rv3_run(3, |a, b| rotate_contact(a, b, &peer(0xB9), &peer(0xA1)));
    assert_eq!(eligible(&r.p.a_log), 0, "real rotation, old session");
    // Then the new identity's own session reports a pre-rotation id: still
    // in the rotation (and sent under the old pin).
    let mut r = r;
    let new = peer(0xB9);
    let (mut b9, mut b9_rx) = published(0xB9);
    b9.peers.pin_card(&r.p.pa).unwrap();
    reestablish(&mut r.p.a, &mut b9, &r.p.pa, &new);
    relay_all(&mut r.p.a_rx, &mut b9);
    drain(&mut b9_rx);
    r.p.a_log.lock().unwrap().clear();
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 1,
        ids: r.ids.clone(),
        sig: None,
    })
    .unwrap();
    let pk = b9.seal_ratchet(&r.p.pa.hex, rand::random(), &pt).unwrap();
    feed(&mut r.p.a, Frame::Relay(pk));
    assert_eq!(undelivered_count(&r.p.a_log), 3, "processed");
    assert_eq!(eligible(&r.p.a_log), 0, "real rotation, new session");
}

/// Guard 4 carries rotation safety after a restart (`rotated_from` is
/// memory-only): ids sent under the old identity's pin are never eligible
/// under the new identity's session.
#[test]
fn rotation_then_restart_reason_3_is_never_eligible() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "before the rotation");
    drain(&mut p.a_rx);
    p.a.age_sent_for_test(&p.pb.hex, 10);
    let new = peer(0xB9);
    rotate_contact(&mut p.a, &p.pb, &new, &p.pa);
    let (mut a2, mut a2_rx, a2_log) = restart_from(0xA1, 0xB9, &sa);
    assert!(a2.rotated_from.is_empty(), "the rotation is forgotten");
    assert!(a2.was_sent_to(&new.hex, &id), "the id survived the restart");
    let (mut b9, mut b9_rx) = published(0xB9);
    b9.peers.pin_card(&p.pa).unwrap();
    reestablish(&mut a2, &mut b9, &p.pa, &new);
    relay_all(&mut a2_rx, &mut b9);
    drain(&mut b9_rx);
    {
        let mut s = a2.session_manager.get_mut(&new.hex).unwrap();
        s.reset_since_unix = Some(s.created_at_unix);
    }
    a2_log.lock().unwrap().clear();
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: crate::notice::FLAG_NO_PRIOR_SESSION,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = b9.seal_ratchet(&p.pa.hex, rand::random(), &pt).unwrap();
    feed(&mut a2, Frame::Relay(pk));
    assert!(statuses(&a2_log).contains(&StatusEvent::PeerUndelivered {
        peer: new.hex.clone(),
        message_id: hex::encode(id),
        reason: 3
    }));
    assert_eq!(eligible(&a2_log), 0, "sent under the old identity's pin");
}

/// Guard 5's age runs from now for an entry stamped in the future (the
/// clock went back): it is re-stamped to now (the Task 1 clock ruling).
#[test]
fn future_dated_sends_are_restamped_to_now() {
    let mut p = establish(0xA1, 0xB2);
    let id = push_text(&p.a, &p.pb.hex, "sent before the clock went back");
    drain(&mut p.a_rx);
    let now = crate::unix_now_secs();
    for e in
        p.a.sent_ids
            .lock()
            .unwrap()
            .get_mut(&p.pb.hex)
            .unwrap()
            .iter_mut()
    {
        e.sent_at_unix = now + 100 * 3600;
    }
    let peer_hex = p.pb.hex.clone();
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 1);
    assert!(p.a.sent_ids_for(&peer_hex)[0].sent_at_unix <= crate::unix_now_secs());
}

/// One report per id per session: an eligible id is never reported again;
/// a repeat with the same reason is dropped; reason 2 always passes.
#[test]
fn each_lost_id_is_reported_once_per_session() {
    let mut p = establish(0xA1, 0xB2);
    let a_id = push_text(&p.a, &p.pb.hex, "eligible");
    let b_id = push_text(&p.a, &p.pb.hex, "over the bound");
    drain(&mut p.a_rx);
    let peer_hex = p.pb.hex.clone();
    let send = |p: &mut Pair, reason: u8, ids: &[[u8; 16]]| {
        let n = crate::notice::Notice {
            flags: 0,
            reason,
            ids: ids.to_vec(),
            sig: None,
        };
        let (n, binding) = signed_by_pinned_dk(&mut p.a, &peer_hex, n);
        p.a.handle_notice(&peer_hex, n, crate::session::DecryptedBy::Current, binding);
    };
    send(&mut p, 1, &[a_id]);
    assert_eq!((undelivered_count(&p.a_log), eligible(&p.a_log)), (1, 1));
    send(&mut p, 1, &[a_id]);
    assert_eq!(undelivered_count(&p.a_log), 1, "eligible: not again");
    send(&mut p, 2, &[a_id]);
    assert_eq!(undelivered_count(&p.a_log), 2, "reason 2 always passes");
    assert_eq!(eligible(&p.a_log), 1, "never twice");
    let now = crate::unix_now_secs();
    p.a.auto_resends.insert(
        peer_hex.clone(),
        (0..MAX_AUTO_RESENDS_PER_DAY as u64).map(|_| now).collect(),
    );
    send(&mut p, 1, &[b_id]);
    send(&mut p, 1, &[b_id]);
    assert_eq!(undelivered_count(&p.a_log), 3, "a same-reason repeat drops");
    assert_eq!(eligible(&p.a_log), 1);
}

/// RS3: Mismatch → zero. Through the wire the notice never reaches
/// `handle_notice` (N5 drop); handed to it directly, the guard refuses.
#[test]
fn rs3_mismatch_guard() {
    let mut r = rv3_run(3, |a, b| a.peers.mark_mismatch(&b.hex));
    assert_eq!(eligible(&r.p.a_log), 0);
    let undelivered = |log: &Arc<std::sync::Mutex<Vec<Ev>>>| {
        statuses(log)
            .iter()
            .filter(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. }))
            .count()
    };
    assert_eq!(
        undelivered(&r.p.a_log),
        0,
        "dropped before handle_notice (N5)"
    );
    let peer_hex = r.p.pb.hex.clone();
    notice_direct(
        &mut r.p.a,
        &peer_hex,
        &r.ids,
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(undelivered(&r.p.a_log), 3, "reported undelivered");
    assert_eq!(eligible(&r.p.a_log), 0, "but never eligible");
}

/// RS4: blocked → zero. Re-pinned to a different key while the session
/// lives (ruling N5) → zero. Unpinned and re-pinned to the same key → the
/// unpin reset the entries, so zero.
#[test]
fn rs4_block_and_repin_guard() {
    let mut r = rv3_run(3, |a, b| a.peers.set_blocked(&b.hex, true));
    assert_eq!(eligible(&r.p.a_log), 0);
    let peer_hex = r.p.pb.hex.clone();
    notice_direct(
        &mut r.p.a,
        &peer_hex,
        &r.ids,
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&r.p.a_log), 0, "blocked, handed over directly");

    let r = rv3_run(3, |a, b| {
        a.peers.repin(&b.hex, [0x5a; 32]).unwrap();
        assert!(
            a.session_manager.has_established_session(&b.hex),
            "session kept"
        );
    });
    assert!(
        statuses(&r.p.a_log)
            .iter()
            .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })),
        "the notice was processed"
    );
    assert_eq!(eligible(&r.p.a_log), 0, "re-pinned to a new key");

    let r = rv3_run(3, |a, b| {
        let ak = a.peers.pin_for(&b.hex).unwrap();
        a.unpin_peer(&b.hex).unwrap();
        assert!(
            a.sent_ids_for(&b.hex).is_empty(),
            "the unpin reset the entries"
        );
        a.peers.pin(&b.hex, ak).unwrap();
    });
    assert_eq!(
        eligible(&r.p.a_log),
        0,
        "unpinned and re-pinned to the same key"
    );
}

/// RS5: a key change between send and loss → zero: a version bump, and
/// a re-scan to ak2 with the session made under ak2 (only the pin at send
/// time differs).
#[test]
fn rs5_key_change_between_send_and_loss() {
    let r = rv3_run(3, |a, b| {
        a.peers
            .set_pin_version(&b.hex, a.peers.pin_version(&b.hex) + 1)
    });
    assert_eq!(eligible(&r.p.a_log), 0, "version bump");
    let r = rv3_run(3, |a, b| {
        let ak2 = [0x5b; 32];
        a.peers.repin(&b.hex, ak2).unwrap();
        a.session_manager.get_mut(&b.hex).unwrap().peer_ak = ak2;
    });
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    assert_eq!(eligible(&r.p.a_log), 0, "sent under ak1, now ak2");
}

/// RS6: an attacker without the pinned keys cannot trigger a resend.
#[test]
fn rs6_attacker_without_pinned_keys() {
    let r = rv3_run(3, |a, b| {
        a.session_manager.get_mut(&b.hex).unwrap().peer_ak = [0x99; 32];
    });
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    assert_eq!(
        eligible(&r.p.a_log),
        0,
        "session made from a bundle that isn't the pin"
    );
    let mut q = establish(0xA1, 0xB2);
    let impostor = bundle_with_ak(&q.pb, peer(0xC3).bundle.identity_agreement_key);
    let ek = crate::crypto::EphemeralKeyPair::generate();
    let i = ek.public_key().to_bytes();
    q.a.peers.push_ask(&q.pb.hex, ek, std::time::Instant::now());
    feed(&mut q.a, created_v3(0, &impostor, i, [9; 32]));
    assert_eq!(q.a.peers.state(&q.pb.hex), PeerKeyState::Mismatch);
    assert_eq!(eligible(&q.a_log), 0);
    // A notice under the retired session (RV4), or naming ids never sent
    // (RV5): zero.
    let mut q = establish(0xA1, 0xB2);
    let id = push_text(&q.a, &q.pb.hex, "lost");
    drain(&mut q.a_rx);
    let peer_hex = q.pb.hex.clone();
    notice_direct(
        &mut q.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Retired,
    );
    notice_direct(
        &mut q.a,
        &peer_hex,
        &[[0xEE; 16]],
        crate::session::DecryptedBy::Current,
    );
    assert!(statuses(&q.a_log).is_empty());
    // A session bound to another identity than the pinned peer's (guard
    // 2, identity half; unreachable through X3DH v2, so set directly).
    q.a.session_manager
        .get_mut(&peer_hex)
        .unwrap()
        .set_identities(q.pa.bundle.identity_key, peer(0xC3).bundle.identity_key);
    notice_direct(
        &mut q.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(statuses(&q.a_log).len(), 1, "reported undelivered");
    assert_eq!(eligible(&q.a_log), 0, "session bound to another identity");
}

/// RS7: bounds. More lost ids than the daily bound → exactly the bound
/// eligible; ids older than 72 h or receipted are reported but never
/// eligible.
#[test]
fn rs7_bounds() {
    // B holds at most MAX_PENDING_PER_SENDER bodies from A.
    let queued = 60.min(crate::MAX_PENDING_PER_SENDER);
    let candidates = queued + 1; // plus the reason-3 id
    assert!(
        candidates > MAX_AUTO_RESENDS_PER_DAY,
        "the bound is reached"
    );
    let batch = crate::notice::MAX_IDS; // B's first notice names these
    assert!(queued > batch, "B sends two notices");
    let n_reports = |r: &Rv3| {
        let mut m: std::collections::HashMap<String, usize> = Default::default();
        for s in statuses(&r.p.a_log) {
            if let StatusEvent::PeerUndelivered { message_id, .. } = s {
                *m.entry(message_id).or_default() += 1;
            }
        }
        m
    };
    let eligible_ids = |r: &Rv3| -> std::collections::HashSet<String> {
        statuses(&r.p.a_log)
            .into_iter()
            .filter_map(|s| match s {
                StatusEvent::ResendEligible { message_id, .. } => Some(message_id),
                _ => None,
            })
            .collect()
    };
    // Same second: the new session starts no later than the queued sends,
    // so only `earlier` is reason 3. Each id is reported exactly once.
    let r = rv3_run(queued, |a, b| {
        // The reason-3 boundary is `reset_since_unix` (set at install);
        // pin it too, or a second ticking over between the queued sends
        // and the install makes them reason 3 as well.
        let first = a.sent_ids_for(&b.hex)[2].sent_at_unix; // the first queued
        let mut s = a.session_manager.get_mut(&b.hex).unwrap();
        s.created_at_unix = first;
        s.reset_since_unix = Some(first);
    });
    assert_eq!(eligible(&r.p.a_log), MAX_AUTO_RESENDS_PER_DAY);
    let m = n_reports(&r);
    assert_eq!(
        m.len(),
        candidates,
        "the rest are reported undelivered only"
    );
    assert!(m.values().all(|n| *n == 1), "each id once: {m:?}");
    // Reason 3 forced: every queued send is before the new session. The
    // first notice names the first batch (reason 1) and reports the rest
    // and `earlier` as reason 3; the bound runs out among those. The second
    // notice names the rest with reason 1: an id made eligible is not
    // reported again; one that was not is (reason 3 → 1).
    let r = rv3_run(queued, |a, b| a.age_sent_for_test(&b.hex, 10));
    let el = eligible_ids(&r);
    assert_eq!(el.len(), MAX_AUTO_RESENDS_PER_DAY);
    let m = n_reports(&r);
    assert_eq!(m.len(), candidates);
    let rest_eligible = MAX_AUTO_RESENDS_PER_DAY - batch - 1; // minus `earlier`
    assert_eq!(m[&hex::encode(r.earlier)], 1);
    assert!(el.contains(&hex::encode(r.earlier)));
    for (i, id) in r.ids.iter().enumerate() {
        // The first batch, then the reason-3 ids the bound still allowed.
        let (want_n, want_el) = if i < batch + rest_eligible {
            (1, true)
        } else {
            (2, false)
        };
        let h = hex::encode(id);
        assert_eq!(m[&h], want_n, "id {i}");
        assert_eq!(el.contains(&h), want_el, "id {i}");
    }
    let r = rv3_run(2, |a, b| {
        a.age_sent_for_test(&b.hex, 73 * 3600); // every id now older than 72 h
    });
    assert_eq!(eligible(&r.p.a_log), 0);
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    let r = rv3_run(1, |a, b| {
        let id = a.sent_ids_for(&b.hex).last().unwrap().id;
        a.mark_sent_delivered(&b.hex, &id);
    });
    assert_eq!(
        eligible(&r.p.a_log),
        1,
        "only the reason-3 id; the receipted queued one is excluded"
    );
}

/// RS7: the bound is per peer over 24 h, counted from persisted stamps:
/// 50 resends in the last day leave none; once a day old, they free up.
#[test]
fn rs7_daily_bound_counts_the_last_24_hours() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "lost");
    let id2 = push_text(&p.a, &p.pb.hex, "lost a day later");
    drain(&mut p.a_rx);
    let peer_hex = p.pb.hex.clone();
    let now = crate::unix_now_secs();
    p.a.auto_resends.insert(
        peer_hex.clone(),
        (0..MAX_AUTO_RESENDS_PER_DAY as u64)
            .map(|i| now - i)
            .collect(),
    );
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[id],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 0, "the day's bound is spent");
    p.a.auto_resends.insert(
        peer_hex.clone(),
        (0..MAX_AUTO_RESENDS_PER_DAY as u64)
            .map(|i| now - 24 * 3600 - i)
            .collect(),
    );
    notice_direct(
        &mut p.a,
        &peer_hex,
        &[id2],
        crate::session::DecryptedBy::Current,
    );
    assert_eq!(eligible(&p.a_log), 1, "a day later");
    assert_eq!(p.a.auto_resends[&peer_hex].len(), 1, "old stamps pruned");
}

/// RS8: BadSignature → zero.
#[test]
fn rs8_bad_signature_guard() {
    let r = rv3_run(3, |a, b| {
        a.peers
            .mark_bad_signature(&b.hex, std::time::Instant::now())
    });
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, StatusEvent::PeerUndelivered { reason: 1, .. })));
    assert_eq!(eligible(&r.p.a_log), 0);
}

/// DK2: a notice signed for another session's binding fails.
#[test]
fn dk2_signature_bound_to_session() {
    let r = rv3_run_with(3, DkSetup::Matching, |a, b| {
        a.session_manager.get_mut(&b.hex).unwrap().session_binding = [0xEE; 32];
    });
    assert_eq!(eligible(&r.p.a_log), 0);
}

/// DK3: seed-only attacker — the same identity keys, a different DK → zero resends.
#[test]
fn dk3_seed_only_attacker_gets_no_resend() {
    let r = rv3_run_with(3, DkSetup::Thief, |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 0);
    assert_eq!(
        r.p.a.peers.device_key(&r.p.pb.hex),
        Some(&crate::device_key::test_keys::soft_dk(1).1),
        "a notice signed by another DK changes no pin (D44)"
    );
    assert!(statuses(&r.p.a_log)
        .iter()
        .any(|s| matches!(s, crate::status::StatusEvent::PeerUndelivered { .. })));
}

/// `src` up to its first inline test module (`#[cfg(test)]` followed by
/// `mod name {` or `pub(crate) mod name {`). `#[cfg(test)] mod x;` file
/// declarations are not cut.
fn strip_inline_tests(src: &str) -> &str {
    let lines: Vec<&str> = src.split_inclusive('\n').collect();
    let mut at = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let t = lines.get(i + 1).map_or("", |l| l.trim());
            if (t.starts_with("mod ") || t.starts_with("pub(crate) mod ")) && t.ends_with('{') {
                return &src[..at];
            }
        }
        at += line.len();
    }
    src
}

/// DK4: the DK pin is never taken from the network.
#[test]
fn dk4_device_key_never_taken_from_the_network() {
    let (_, pin) = crate::device_key::test_keys::soft_dk(1);
    let mut p = establish(0xA1, 0xB2);
    p.a.peers.pin_device_key(&p.pb.hex, pin.clone());
    feed(
        &mut p.a,
        queued(knock_from(&p.pb, &p.pa, crate::circuits::now_hour())),
    );
    let ek_a = crate::crypto::EphemeralKeyPair::generate();
    let ek_a_pub = ek_a.public_key().to_bytes();
    p.a.peers
        .push_ask(&p.pb.hex, ek_a, std::time::Instant::now());
    feed(
        &mut p.a,
        created_v3(
            0,
            &p.pb.bundle,
            ek_a_pub,
            crate::crypto::EphemeralKeyPair::generate()
                .public_key()
                .to_bytes(),
        ),
    );
    relay_all(&mut p.b_rx, &mut p.a); // notices from B
    assert_eq!(p.a.peers.device_key(&p.pb.hex), Some(&pin));
    // Source scan: the exact non-test call sites of the setter across every
    // file of the crate. Test-only files and inline `#[cfg(test)] mod … {`
    // blocks are skipped; definitions (`fn pin_device_key(`) are not calls.
    // `ffi.rs` (`rchat_pin_device_key`: the staged and the live client
    // path) is the C entry for the app's scan, paste and restore paths.
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    let mut sites: Vec<(String, usize)> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "test_support.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let code = strip_inline_tests(&src);
        let calls = code.matches("pin_device_key(").count()
            - code.matches("fn pin_device_key(").count()
            - code.matches("fn rchat_pin_device_key(").count();
        if calls > 0 {
            sites.push((name, calls));
        }
    }
    sites.sort();
    assert_eq!(
        sites,
        vec![
            ("ffi.rs".to_string(), 2),
            ("lib.rs".to_string(), 1),
            ("peers.rs".to_string(), 1)
        ],
        "only rchat_pin_device_key, RChatClient::pin_device_key and PeerBook::overlay set a DK pin"
    );
}

/// DK5: a re-scan replaces the DK: the old key's signature fails, the new one passes.
#[test]
fn dk5_rescan_updates_device_key() {
    let r = rv3_run_with(3, DkSetup::Rescanned, |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 0, "signed by the replaced key");
    // After a re-scan to seed 3, with B signing with seed 3: passes.
    let r = rv3_run_with_keys(3, Some(3), Some(3), |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 3 + 1);
}

/// DK6: no DK pinned (an old card) → zero.  DK7: unsigned → zero, ids still reported.
#[test]
fn dk6_no_pin_gets_no_resend() {
    let r = rv3_run_with(3, DkSetup::NoPin, |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 0);
}
#[test]
fn dk7_unsigned_notice_gets_no_resend() {
    let r = rv3_run_with(3, DkSetup::NoSigner, |_, _| {});
    assert_eq!(eligible(&r.p.a_log), 0);
    assert!(statuses(&r.p.a_log).iter().any(|s| matches!(
        s,
        crate::status::StatusEvent::PeerUndelivered { reason: 1, .. }
    )));
}

/// DK7 (the signer fails): the notice goes out unsigned → zero resends,
/// and its ids are still reported.
#[test]
fn dk7_failing_signer_sends_the_notice_unsigned() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    give_device_keys(&mut p.a, &mut p.b, &p.pb.hex);
    p.b.device_signer = Some(Arc::new(crate::device_key::test_keys::FailingSigner));
    let id = push_text(&p.a, &p.pb.hex, "mangled on the way");
    drain(&mut p.a_rx);
    let body = [vec![0u8; crate::crypto::RatchetHeader::LEN], vec![1u8; 64]].concat();
    let mangled = crate::sealed::seal(
        id,
        &p.pb.bundle.identity_key,
        &p.pb.bundle.identity_agreement_key,
        &p.pa.bundle.identity_key,
        crate::sealed::KIND_RATCHET,
        &body,
    )
    .unwrap();
    feed(&mut p.b, queued(mangled));
    relay_all(&mut p.b_rx, &mut p.a);
    assert_eq!(
        statuses(&p.a_log),
        vec![crate::status::StatusEvent::PeerUndelivered {
            peer: p.pb.hex.clone(),
            message_id: hex::encode(id),
            reason: 1
        }],
        "reported, never eligible"
    );
}

/// D45: both sides derive the same binding from SK at install, it differs
/// per session, and it is written and restored with the session.
#[test]
fn session_binding_matches_both_sides_and_survives_a_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let a_side = p.a.session_manager.get(&p.pb.hex).unwrap().session_binding;
    let b_side = p.b.session_manager.get(&p.pa.hex).unwrap().session_binding;
    assert_eq!(a_side, b_side);
    assert_ne!(a_side, [0; 32]);
    assert_eq!(
        open_record(&sa, 0xA1, &p.pb)
            .session
            .unwrap()
            .session_binding,
        a_side,
        "written"
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    assert_eq!(
        a2.session_manager.get(&p.pb.hex).unwrap().session_binding,
        a_side,
        "restored"
    );
    let other = establish(0xA1, 0xB2);
    assert_ne!(
        other
            .a
            .session_manager
            .get(&other.pb.hex)
            .unwrap()
            .session_binding,
        a_side,
        "another session, another binding"
    );
}

/// Carry-over (6c): a contact's rotation writes both records, the new
/// identity's with the moved sent ids, so a restart finds them there and
/// the old record no longer holds them. The rotation also clears that
/// contact's DK pin (D44): the new identity has none until a re-scan.
#[test]
fn rotation_persists_both_records_and_clears_the_device_key() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    p.a.peers
        .pin_device_key(&p.pb.hex, crate::device_key::test_keys::soft_dk(1).1);
    let id = push_text(&p.a, &p.pb.hex, "before the rotation");
    drain(&mut p.a_rx);
    assert!(open_record(&sa, 0xA1, &p.pb)
        .sent_ids
        .iter()
        .any(|e| e.id == id));
    let new = peer(0xB9);
    rotate_contact(&mut p.a, &p.pb, &new, &p.pa);
    assert_eq!(p.a.peers.device_key(&p.pb.hex), None, "old identity's DK");
    assert_eq!(
        p.a.peers.device_key(&new.hex),
        None,
        "none taken from the chain"
    );
    assert!(
        open_record(&sa, 0xA1, &new)
            .sent_ids
            .iter()
            .any(|e| e.id == id),
        "the new identity's record holds the moved ids"
    );
    assert!(
        !open_record(&sa, 0xA1, &p.pb)
            .sent_ids
            .iter()
            .any(|e| e.id == id),
        "the old record no longer does"
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB9, &sa);
    assert!(a2.was_sent_to(&new.hex, &id), "the id survived the restart");
}

/// Fix round (6b review): a rotation whose new-record write fails leaves
/// the old record, ids included, untouched; the ids are on disk under one
/// of the two, and reach the new record on its next successful write.
#[test]
fn rotation_with_a_failed_new_write_keeps_the_ids_on_disk() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let id = push_text(&p.a, &p.pb.hex, "before the rotation");
    drain(&mut p.a_rx);
    let new = peer(0xB9);
    let new_key =
        crate::state_store::StateKeys::new(TEST_STATE_KEY).record_key_for(&new.bundle.identity_key);
    sa.fail_keys.lock().unwrap().insert(new_key.clone());
    rotate_contact(&mut p.a, &p.pb, &new, &p.pa);
    assert!(
        !sa.files.lock().unwrap().contains_key(&new_key),
        "new write failed"
    );
    assert!(
        open_record(&sa, 0xA1, &p.pb)
            .sent_ids
            .iter()
            .any(|e| e.id == id),
        "the old record still holds the moved ids"
    );
    sa.fail_keys.lock().unwrap().clear();
    p.a.persist_peer(&new.hex).unwrap();
    assert!(open_record(&sa, 0xA1, &new)
        .sent_ids
        .iter()
        .any(|e| e.id == id));
}

/// Task 11 follow-up: what the peer's flag will report, and whether its
/// verdict arrived, survive a restart with the session.
#[test]
fn peer_notice_heard_and_reset_since_survive_a_restart() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [8; 16], &pt).unwrap();
    feed(&mut p.a, Frame::Relay(pk));
    let rec = open_record(&sa, 0xA1, &p.pb);
    let s = rec.session.as_ref().unwrap();
    assert!(s.peer_notice_heard, "written when first heard");
    assert_eq!(s.reset_since_unix, None, "first contact reports no reset");
    p.a.session_manager
        .get_mut(&p.pb.hex)
        .unwrap()
        .reset_since_unix = Some(1234);
    p.a.persist_peer(&p.pb.hex).unwrap();
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    let s = a2.session_manager.get(&p.pb.hex).unwrap();
    assert!(s.peer_notice_heard);
    assert_eq!(s.reset_since_unix, Some(1234));
}

/// Task 11 follow-up: with no usable transport (a closed outgoing queue,
/// or none), owed receipts and due cover replies are never sealed: the
/// ticks advance no chain index, and the ids and replies stay owed.
#[test]
fn owed_receipts_and_cover_replies_burn_nothing_while_the_transport_is_down() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let Pair {
        mut a,
        a_rx,
        mut b,
        mut b_rx,
        pa,
        pb,
        ..
    } = p;
    let id = push_text(&b, &pa.hex, "to be receipted");
    relay_all(&mut b_rx, &mut a);
    a.receipt_delay_override = Some(std::time::Duration::from_secs(1));
    drop(a_rx); // the read loop ended: the queue is closed
    a.mark_seen_and_receipt(&pb.hex, id).unwrap();
    a.cover_replies_due
        .push((pb.hex.clone(), std::time::Instant::now()));
    let ns = |a: &ClientInner| {
        a.session_manager
            .get(&pb.hex)
            .unwrap()
            .ratchet_snapshot()
            .unwrap()
            .ns
    };
    let owed = |a: &ClientInner| {
        a.pending_receipts
            .get(&(pb.hex.clone(), crate::receipts::DELIVERED))
            .cloned()
            .unwrap_or_default()
    };
    let ns0 = ns(&a);
    let t0 = std::time::Instant::now();
    for round in 0..2 {
        if round == 1 {
            a.websocket = None; // no transport at all
        }
        for i in 0..100u64 {
            let t = t0 + std::time::Duration::from_millis(250 * i);
            a.fire_due_receipts(t);
            a.fire_cover(t);
            a.redrive_owed_sends(t);
            a.flush_receipts(&pb.hex);
        }
        assert_eq!(ns(&a), ns0, "no chain key spent");
        assert_eq!(owed(&a), vec![id], "the receipt is still owed");
        assert_eq!(a.cover_replies_due.len(), 1, "the cover reply is still due");
    }
    let _ = (&mut b, sb);
}

/// Fails exactly the `nth` write (1-based) it sees; every other write goes
/// through to `inner`.
struct FailNth {
    inner: MemorySink,
    seen: std::sync::atomic::AtomicUsize,
    nth: usize,
}

impl crate::state_store::StateSink for FailNth {
    fn write(&self, key: &str, sealed: &[u8]) -> Result<(), String> {
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.nth {
            return Err("transient".into());
        }
        self.inner.write(key, sealed)
    }
}

/// Fix round 1 (review I-1 refinement): receipts wait only for an owed
/// flagged notice, never for a notice that still owes reason-1/2 ids.
#[test]
fn receipts_are_not_held_for_a_notice_owing_only_ids() {
    let mut p = establish(0xA1, 0xB2);
    p.a.receipt_delay_override = Some(std::time::Duration::from_secs(60));
    let m = push_text(&p.b, &p.pa.hex, "to be receipted");
    relay_all(&mut p.b_rx, &mut p.a);
    p.a.mark_seen_and_receipt(&p.pb.hex, m).unwrap();
    // 33 unreported ids: two reason-1 batches; no flag owed.
    let ids: std::collections::VecDeque<[u8; 16]> = (0..33u8).map(|i| [i; 16]).collect();
    p.a.undecryptable.insert(p.pb.hex.clone(), ids);
    p.a.notice_due.insert(p.pb.hex.clone());
    assert!(!p.a.notice_flag_pending.contains_key(&p.pb.hex));
    // One batch per flush (final review M-1): the second batch is owed to
    // the next tick, and the receipt does not wait for it.
    p.a.state = Some(crate::persistence::StateStore {
        keys: crate::state_store::StateKeys::new(TEST_STATE_KEY),
        sink: std::sync::Arc::new(FailNth {
            inner: MemorySink::default(),
            seen: Default::default(),
            nth: 1000,
        }),
        counters: std::sync::Mutex::new(Default::default()),
        failing: std::sync::Mutex::new(Default::default()),
        staged: Vec::new(),
    });
    p.a.send_receipts_now(&p.pb.hex);
    assert!(
        p.a.notice_due.contains(&p.pb.hex),
        "the second batch is owed"
    );
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(p.b_log.lock().unwrap().contains(&Ev::Receipt(
        p.pa.hex.clone(),
        hex::encode(m),
        crate::receipts::DELIVERED
    )));
}

/// Fix round 1 (review M-2): when the write that records a heard verdict
/// fails, the tick retries it, so a restart does not lose it.
#[test]
fn a_heard_verdict_whose_write_failed_is_retried() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let pt = crate::notice::encode(&crate::notice::Notice {
        flags: 0,
        reason: 0,
        ids: vec![],
        sig: None,
    })
    .unwrap();
    let pk = p.b.seal_ratchet(&p.pa.hex, [8; 16], &pt).unwrap();
    // The decrypt's own write succeeds; the heard verdict's write fails.
    *sa.budget.lock().unwrap() = Some(1);
    feed(&mut p.a, Frame::Relay(pk));
    assert!(
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .peer_notice_heard
    );
    assert!(p.a.session_manager.get(&p.pb.hex).unwrap().heard_unrecorded);
    assert!(
        !open_record(&sa, 0xA1, &p.pb)
            .session
            .unwrap()
            .peer_notice_heard
    );
    *sa.budget.lock().unwrap() = None;
    p.a.websocket = None; // no transport needed
    p.a.redrive_owed_sends(std::time::Instant::now() + crate::circuits::REDRIVE_PROBE_INTERVAL);
    assert!(!p.a.session_manager.get(&p.pb.hex).unwrap().heard_unrecorded);
    assert!(
        open_record(&sa, 0xA1, &p.pb)
            .session
            .unwrap()
            .peer_notice_heard
    );
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    assert!(a2.session_manager.get(&p.pb.hex).unwrap().peer_notice_heard);
}

/// Fix round 1 (review I-1): while a flagged notice is still owed (here
/// its seal's write failed once), no receipt is sealed or sent.
#[test]
fn receipts_wait_for_an_owed_flagged_notice() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    for c in [&mut a, &mut b] {
        c.receipt_delay_override = Some(std::time::Duration::from_secs(60));
    }
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    reestablish(&mut a, &mut b, &pa, &pb); // first contact
    relay_all(&mut a_rx, &mut b); // A's hello sync
    b.fire_due_receipts(std::time::Instant::now() + std::time::Duration::from_secs(120));
    relay_all(&mut b_rx, &mut a); // B's notice
    let m = push_text(&b, &pa.hex, "to be receipted");
    relay_all(&mut b_rx, &mut a);
    a.mark_seen_and_receipt(&pb.hex, m).unwrap();
    assert_eq!(a.notice_flag_pending.get(&pb.hex), Some(&1));
    a.state = Some(crate::persistence::StateStore {
        keys: crate::state_store::StateKeys::new(TEST_STATE_KEY),
        sink: std::sync::Arc::new(FailNth {
            inner: MemorySink::default(),
            seen: Default::default(),
            nth: 1,
        }),
        counters: std::sync::Mutex::new(Default::default()),
        failing: std::sync::Mutex::new(Default::default()),
        staged: Vec::new(),
    });
    a.send_receipts_now(&pb.hex);
    assert!(
        drain(&mut a_rx).is_empty(),
        "nothing left ahead of the notice"
    );
    assert!(a.notice_due.contains(&pb.hex));
    assert_eq!(
        a.pending_receipts
            .get(&(pb.hex.clone(), crate::receipts::DELIVERED))
            .map(Vec::as_slice),
        Some(&[m][..]),
        "the receipt is still owed"
    );
    // Writes succeed again: the notice, then the receipt.
    a.send_receipts_now(&pb.hex);
    assert_eq!(relay_all(&mut a_rx, &mut b), 2);
    assert!(!a.notice_due.contains(&pb.hex));
}

/// Delivered receipts `log` reported.
fn delivered_receipts(log: &Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Receipt(_, _, 1)))
        .count()
}

/// The relay's answer to B's resume after a restart.
fn resumed(b2: &mut ClientInner) {
    feed(
        b2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C2,
            token: TOKEN.to_vec(),
            target_circuit_id: C1,
            is_initiator: false,
        }),
    );
}

/// Two-simulator D1/F1 shape (debug-receipts-hang report): B is killed, A
/// sends 2 (queued for B), B restarts from its store and gets them before
/// its resume. The app marks them seen only after the resume, with a real
/// receipt window: both delivered receipts still reach A.
#[test]
fn a_restarted_receiver_receipts_texts_queued_while_it_was_down() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let ids = [
        push_text(&p.a, &p.pb.hex, "d1"),
        push_text(&p.a, &p.pb.hex, "d2"),
    ];
    let (mut b2, mut b2_rx, b2_log) = restart_from(0xB2, 0xA1, &sb);
    b2.receipt_delay_override = None;
    for pkt in sent_relays(&mut p.a_rx) {
        feed(&mut b2, queued(pkt.payload));
    }
    assert_eq!(texts(&b2_log).len(), 2);
    resumed(&mut b2);
    for id in ids {
        b2.mark_seen_and_receipt(&p.pa.hex, id).unwrap();
    }
    let later = std::time::Instant::now() + std::time::Duration::from_secs(5);
    b2.fire_due_receipts(later);
    relay_all(&mut b2_rx, &mut p.a);
    assert_eq!(delivered_receipts(&p.a_log), 2);
}

/// Hypothesis (b) of the debug-receipts-hang report: B is killed while its
/// flagged notice for a re-made session is still owed. After the restart
/// the notice is re-driven by the resume, so the receipts it holds back
/// still leave, behind it.
#[test]
fn receipts_held_by_an_owed_flagged_notice_leave_after_a_restart() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let a_log = install_event_log(&mut a);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    b.receipt_delay_override = Some(std::time::Duration::from_secs(60)); // B's notice waits
    reestablish(&mut a, &mut b, &pa, &pb);
    relay_all(&mut a_rx, &mut b); // session-init: B installs (v3, §A.3)
    assert_eq!(open_record(&sb, 0xB2, &pa).notice_flags, 1);
    let ids = [push_text(&a, &pb.hex, "d1"), push_text(&a, &pb.hex, "d2")];
    let (mut b2, mut b2_rx, b2_log) = restart_from(0xB2, 0xA1, &sb);
    assert_eq!(b2.notice_flag_pending.get(&pa.hex), Some(&1));
    for pkt in sent_relays(&mut a_rx) {
        feed(&mut b2, queued(pkt.payload));
    }
    assert_eq!(texts(&b2_log).len(), 2, "both texts delivered to the app");
    for id in ids {
        b2.mark_seen_and_receipt(&pa.hex, id).unwrap();
    }
    resumed(&mut b2);
    relay_all(&mut b2_rx, &mut a);
    assert_eq!(delivered_receipts(&a_log), 2);
    assert!(
        !b2.notice_flag_pending.contains_key(&pa.hex),
        "the notice left first"
    );
}

/// One core tick, as the timer runs it (the parts that write).
fn m1_tick(c: &mut ClientInner, at: std::time::Instant) {
    c.fire_due_receipts(at);
    c.redrive_owed_sends(at);
    c.flush_deferred_writes();
}

fn m1_forged(sender: &Peer, to: &Peer, id: [u8; 16], body_len: usize) -> Vec<u8> {
    let header = crate::crypto::RatchetHeader {
        message_number: 0,
        previous_chain_length: 0,
        dh_public_key: rand::random(),
    };
    let mut body = header.encode().to_vec();
    body.resize(body.len() + body_len, 0x5a);
    crate::sealed::seal(
        id,
        &to.bundle.identity_key,
        &to.bundle.identity_agreement_key,
        &sender.bundle.identity_key,
        crate::sealed::KIND_RATCHET,
        &body,
    )
    .unwrap()
}

/// Final review M-1 (`audit_forged_envelope_amplification`): forged
/// envelopes "from" a contact with a session (through the offline queue,
/// which no circuit check can cover) cost no write each: their record
/// write is coalesced to the tick, at most one notice leaves per tick
/// (up to 32 ids), and DecryptFailed is raised for at most 32 ids per peer
/// per tick.
#[test]
fn m1_forged_envelopes_cost_o1_writes_per_tick() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let before = sb.tried.load(Ordering::SeqCst);
    for _ in 0..200 {
        feed(
            &mut p.b,
            queued(m1_forged(&p.pa, &p.pb, rand::random(), 64)),
        );
    }
    // The first id of the tick schedules one notice (zero receipt delay
    // here: it leaves at once, 3 writes); the other 199 write nothing.
    let injected = sb.tried.load(Ordering::SeqCst) - before;
    assert!(injected <= 4, "{injected} writes for 200 forged envelopes");
    assert!(
        sent_relays(&mut p.b_rx).len() <= 1,
        "one notice, not one per envelope"
    );
    let failed = |log: &Arc<std::sync::Mutex<Vec<Ev>>>| {
        statuses(log)
            .iter()
            .filter(|s| matches!(s, crate::status::StatusEvent::DecryptFailed { .. }))
            .count()
    };
    assert!(failed(&p.b_log) <= 32, "{} DecryptFailed", failed(&p.b_log));
    let t0 = std::time::Instant::now();
    for i in 0..10u64 {
        let w0 = sb.tried.load(Ordering::SeqCst);
        m1_tick(&mut p.b, t0 + std::time::Duration::from_millis(250 * i));
        let writes = sb.tried.load(Ordering::SeqCst) - w0;
        assert!(writes <= 4, "tick {i}: {writes} writes");
        assert!(
            sent_relays(&mut p.b_rx).len() <= 1,
            "tick {i}: one notice at most"
        );
    }
}

/// M-1 (`audit_forged_envelope_no_session_meta_writes`): forged bodies
/// held for a pinned contact with no session rewrite the meta record at
/// most once per tick, not once per body.
#[test]
fn m1_held_forged_bodies_rewrite_meta_once_per_tick() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let c = peer(0xC3);
    p.b.peers.pin_card(&c).unwrap();
    let before = sb.tried.load(Ordering::SeqCst);
    for _ in 0..300 {
        feed(&mut p.b, queued(m1_forged(&c, &p.pb, rand::random(), 1024)));
    }
    assert_eq!(
        sb.tried.load(Ordering::SeqCst) - before,
        0,
        "no write per held body"
    );
    let w0 = sb.tried.load(Ordering::SeqCst);
    m1_tick(&mut p.b, std::time::Instant::now());
    assert_eq!(sb.tried.load(Ordering::SeqCst) - w0, 1, "one meta write");
    let w1 = sb.tried.load(Ordering::SeqCst);
    m1_tick(&mut p.b, std::time::Instant::now());
    assert_eq!(
        sb.tried.load(Ordering::SeqCst) - w1,
        0,
        "nothing new: no write"
    );
}

/// M-1: on a circuit, an envelope whose claimed sender is not the
/// circuit's peer is dropped before any decrypt, hold or write. (Queued
/// delivery has no circuit and is unaffected.)
#[test]
fn m1_a_relay_frame_from_another_sender_than_the_circuit_peer_is_dropped() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let c = peer(0xC3);
    p.b.peers.pin_card(&c).unwrap();
    let genuine =
        p.a.seal_ratchet(&p.pb.hex, rand::random(), b"\x01\0\0\0\0hi")
            .unwrap();
    let token =
        p.a.session_manager
            .get(&p.pb.hex)
            .unwrap()
            .get_token_key()
            .unwrap();
    let flags = crate::protocol::PacketFlags {
        encrypted: true,
        ..Default::default()
    };
    let before = sb.tried.load(Ordering::SeqCst);
    for from in [&c, &p.pa] {
        let pk = crate::protocol::RelayPacket::with_auth(
            genuine.circuit_id.clone(),
            m1_forged(from, &p.pb, rand::random(), 64),
            flags,
            &token,
        );
        feed(&mut p.b, Frame::Relay(pk));
    }
    assert!(
        p.b.pending_encrypted_messages.is_empty(),
        "C's body was not held"
    );
    let failed: Vec<String> = statuses(&p.b_log)
        .into_iter()
        .filter_map(|s| match s {
            crate::status::StatusEvent::DecryptFailed { peer, .. } => Some(peer),
            _ => None,
        })
        .collect();
    assert_eq!(
        failed,
        vec![p.pa.hex.clone()],
        "only the circuit peer's forgery is handled (as before)"
    );
    // Genuine traffic on the circuit still flows.
    feed(&mut p.b, Frame::Relay(genuine));
    assert_eq!(texts(&p.b_log), vec![b"hi".to_vec()]);
    let _ = before;
}

/// M-1: the core's own timer (`spawn_ticker`) flushes the coalesced writes
/// and starts the per-tick limits again, with no direct flush call: held
/// bodies reach disk, and DecryptFailed resumes after the per-tick cap.
#[test]
fn the_timer_flushes_coalesced_writes_and_resets_the_tick_limits() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let mut p = stored_pair(&sa, &sb);
    let c = peer(0xC3);
    p.b.peers.pin_card(&c).unwrap();
    for _ in 0..3 {
        feed(&mut p.b, queued(m1_forged(&c, &p.pb, rand::random(), 64)));
    }
    p.b.set_connected(false); // notices wait; only the counts matter here
    for _ in 0..40 {
        feed(
            &mut p.b,
            queued(m1_forged(&p.pa, &p.pb, rand::random(), 64)),
        );
    }
    let failed = |log: &Arc<std::sync::Mutex<Vec<Ev>>>| {
        statuses(log)
            .iter()
            .filter(|s| matches!(s, crate::status::StatusEvent::DecryptFailed { .. }))
            .count()
    };
    assert_eq!(failed(&p.b_log), 32, "capped in this tick");
    assert!(sb
        .files
        .lock()
        .unwrap()
        .get(crate::state_store::META_KEY)
        .is_none());
    let b = std::mem::replace(
        &mut p.b,
        crate::ClientInner::new(crate::ClientConfig::default()),
    );
    let client = wrap(b);
    crate::spawn_ticker(&client.runtime, Arc::downgrade(&client.inner));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while sb
        .files
        .lock()
        .unwrap()
        .get(crate::state_store::META_KEY)
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the timer never wrote the meta record"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        open_meta(&sb, 0xB2).held.len(),
        3,
        "the held bodies reached disk"
    );
    std::thread::sleep(std::time::Duration::from_millis(600)); // a tick or two
    {
        let mut g = client.inner.blocking_write();
        for _ in 0..5 {
            feed(&mut g, queued(m1_forged(&p.pa, &p.pb, rand::random(), 64)));
        }
    }
    assert_eq!(
        failed(&p.b_log),
        37,
        "DecryptFailed resumes in a later tick"
    );
}

// ---- Protocol v3 (Task 4): session-init state in the records ----

/// §A.3: a responder restarted before the session-init arrives still opens
/// it: the wait is in the peer record, with the KEM ephemeral as its
/// 64-byte seed (R4), never the expanded secret. The queued init then
/// installs the session, the pair resumes its circuit after the publish,
/// and the record no longer holds the wait.
#[test]
fn pending_session_init_survives_a_restart() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    reestablish(&mut a, &mut b, &pa, &pb);
    let rec = open_record(&sb, 0xB2, &pa);
    let pending = rec.pending_init.as_ref().expect("the wait is stored");
    assert_eq!(pending.kem_seed.len(), crate::kem::KEM_SEED_LEN);
    assert!(rec.session.is_none(), "no session before the init");
    let from_a = sent_relays(&mut a_rx);
    drop(b);
    let (mut b2, mut b2_rx, b2_log) = restart_from(0xB2, 0xA1, &sb);
    assert!(b2.awaiting_init(&pa.hex));
    // After the publish the pair's circuit is resumed, not asked afresh.
    b2.after_publish_ok(std::time::Instant::now());
    let resumes: Vec<_> = sent_controls(&mut b2_rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk { resume_circuit, .. } => resume_circuit,
            _ => None,
        })
        .collect();
    assert_eq!(resumes, vec![C2], "the pending circuit is resumed");
    for pkt in from_a {
        feed(&mut b2, queued(pkt.payload));
    }
    assert!(!b2.awaiting_init(&pa.hex));
    assert!(b2.session_manager.get(&pa.hex).unwrap().is_established);
    assert!(open_record(&sb, 0xB2, &pa).pending_init.is_none());
    push_text(&a, &pb.hex, "after restart");
    for pkt in sent_relays(&mut a_rx) {
        feed(&mut b2, queued(pkt.payload));
    }
    assert_eq!(texts(&b2_log), vec![b"after restart".to_vec()]);
}

/// Ruling R8 / review M-5: a wait older than the offline queue (72 h) is
/// dropped at restore exactly as an expired wait is: its circuit is closed
/// and the pair asked again. A record whose wait names another agreement
/// key than the pin is deleted (C-1).
#[test]
fn an_expired_or_repinned_pending_init_is_not_restored() {
    let (mut a, _a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    reestablish(&mut a, &mut b, &pa, &pb);
    let now = crate::unix_now_secs();
    {
        let w = b.pending_inits.get_mut(&pa.hex).unwrap();
        w.created_at_unix = now - crate::circuits::PENDING_INIT_MAX_AGE_SECS - 3600;
        w.expires_at_unix = now - 1;
    }
    b.persist_peer(&pa.hex).unwrap();
    let rec = open_record(&sb, 0xB2, &pa);
    assert!(rec.pending_init.is_some(), "the old wait is on disk");
    let (b2, mut b2_rx, _log) = restart_from(0xB2, 0xA1, &sb);
    assert!(!b2.awaiting_init(&pa.hex));
    let closed: Vec<_> = sent_controls(&mut b2_rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CloseCircuit { circuit_id } => Some(circuit_id),
            _ => None,
        })
        .collect();
    assert_eq!(closed, vec![C2], "the half-made circuit is closed");
    assert!(
        b2.pending_reasks.contains_key(&pa.hex) || b2.deferred_asks.contains(&pa.hex),
        "the pair is asked again"
    );
    let key =
        crate::state_store::StateKeys::new(TEST_STATE_KEY).record_key_for(&pa.bundle.identity_key);
    let left = sb.files.lock().unwrap().get(&key).cloned();
    assert!(
        left.is_none()
            || open_sealed(0xB2, &key, &left.unwrap())
                .pending_init
                .is_none(),
        "the dropped wait left the record (an empty record is deleted)"
    );

    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    reestablish(&mut a, &mut b, &pa, &pb);
    b.persist_peer(&pa.hex).unwrap();
    // Restarted with A pinned under another key: the record goes.
    let (mut c, _rx) = published(0xB2);
    c.peers
        .pin(&pa.hex, peer(0x66).bundle.identity_agreement_key)
        .unwrap();
    with_store(&mut c, &sb);
    let files = sb.files.lock().unwrap().clone();
    for (key, sealed) in files {
        c.state.as_mut().unwrap().stage_keep_higher(key, sealed);
    }
    c.restore_staged_state();
    assert!(!c.awaiting_init(&pa.hex));
}

/// Ruling R8 (the review's scenario): B waits for a session-init on a
/// second pair (distinct circuits from the first), then is suspended for
/// 30 min, past the wait's online TTL. The wait counts online time only:
/// after the restart it is still there, the queued init opens, and the
/// text sent meanwhile arrives.
#[test]
fn a_wait_survives_thirty_minutes_offline() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    // First pair, fully confirmed.
    reestablish(&mut a, &mut b, &pa, &pb);
    for pkt in sent_relays(&mut a_rx) {
        feed(&mut b, queued(pkt.payload));
    }
    push_text(&b, &pa.hex, "hi");
    for pkt in sent_relays(&mut b_rx) {
        feed(&mut a, queued(pkt.payload));
    }
    assert!(b.session_manager.get(&pa.hex).unwrap().is_established);
    // Second pair on its own circuits: B waits, then sleeps 30 min.
    let (c3, c4) = (
        crate::protocol::CircuitId([0xC3; 16]),
        crate::protocol::CircuitId([0xC4; 16]),
    );
    reestablish_on(&mut a, &mut b, &pa, &pb, (c3, c4.clone()));
    assert!(b.awaiting_init(&pa.hex));
    let now = crate::unix_now_secs();
    {
        let w = b.pending_inits.get_mut(&pa.hex).unwrap();
        w.created_at_unix = now - 1800;
        w.expires_at_unix = now - 1200;
    }
    b.persist_peer(&pa.hex).unwrap();
    drop(b);
    push_text(&a, &pb.hex, "while you were away");
    let from_a = sent_relays(&mut a_rx);
    let (mut b2, mut b2_rx, b2_log) = restart_from(0xB2, 0xA1, &sb);
    assert!(b2.awaiting_init(&pa.hex), "online time only: still waiting");
    assert!(
        b2.pending_inits.get(&pa.hex).unwrap().expires_at_unix
            >= now + crate::peers::ASK_TTL.as_secs()
    );
    b2.after_publish_ok(std::time::Instant::now());
    let resumes: Vec<_> = sent_controls(&mut b2_rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk { resume_circuit, .. } => resume_circuit,
            _ => None,
        })
        .collect();
    assert_eq!(resumes, vec![c4], "B resumes the second pair's circuit");
    for pkt in from_a {
        feed(&mut b2, queued(pkt.payload));
    }
    assert!(!b2.awaiting_init(&pa.hex));
    assert_eq!(texts(&b2_log), vec![b"while you were away".to_vec()]);
    assert!(
        !statuses(&b2_log)
            .iter()
            .any(|e| matches!(e, crate::status::StatusEvent::DecryptFailed { .. })),
        "nothing undecryptable"
    );
}

/// §A.4: the initiator's unanswered session-init is in its record, so a
/// restart re-sends the very same bytes at the first resume.
#[test]
fn unanswered_session_init_is_resent_after_a_restart() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sa = MemorySink::default();
    with_store(&mut a, &sa);
    reestablish(&mut a, &mut b, &pa, &pb);
    let init = sent_relays(&mut a_rx).remove(0);
    let rec = open_record(&sa, 0xA1, &pb);
    let stored = rec.session.as_ref().unwrap().init_out.as_ref().unwrap();
    assert_eq!(stored.sent_payload, init.payload);
    assert!(stored.sent_payload.len() > 4096);
    assert!(rec.session.as_ref().unwrap().pair_secret.is_some());
    let (mut a2, mut a2_rx, _log) = restart_from(0xA1, 0xB2, &sa);
    a2.is_key_bundle_published = true;
    feed(
        &mut a2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
    let again = sent_relays(&mut a2_rx);
    assert_eq!(again[0].payload, init.payload, "the same bytes, first");
    feed(&mut b, Frame::Relay(again[0].clone()));
    assert!(b.session_manager.get(&pa.hex).unwrap().can_send());
}

// ---- Task 4 fix round 2 (N-1, N-2) ----

/// Review N-1: a too-old wait dropped at restore must not write a
/// half-merged peer record. Every write of the peer's record made during
/// the restore carries all it held (no delete, no lost ids), and the wait
/// is gone from the final record; the circuit is closed and re-asked.
#[test]
fn a_wait_dropped_at_restore_never_writes_a_partial_record() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, mut b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    reestablish(&mut a, &mut b, &pa, &pb);
    for pkt in sent_relays(&mut a_rx) {
        feed(&mut b, queued(pkt.payload));
    }
    push_text(&a, &pb.hex, "hello b");
    for pkt in sent_relays(&mut a_rx) {
        feed(&mut b, queued(pkt.payload));
    }
    push_text(&b, &pa.hex, "hi a");
    let _ = sent_relays(&mut b_rx);
    let (c3, c4) = (
        crate::protocol::CircuitId([0xC3; 16]),
        crate::protocol::CircuitId([0xC4; 16]),
    );
    reestablish_on(&mut a, &mut b, &pa, &pb, (c3, c4.clone()));
    assert!(b.awaiting_init(&pa.hex));
    let now = crate::unix_now_secs();
    b.pending_inits.get_mut(&pa.hex).unwrap().created_at_unix =
        now - crate::circuits::PENDING_INIT_MAX_AGE_SECS - 3600;
    b.persist_peer(&pa.hex).unwrap();
    let before = open_record(&sb, 0xB2, &pa);
    assert!(!before.received_ids.is_empty() && !before.sent_ids.is_empty());
    assert!(before.pending_init.is_some());
    drop(b);
    let hlen = sb.history.lock().unwrap().len();
    let (b2, mut b2_rx, _log) = restart_from(0xB2, 0xA1, &sb);
    let key =
        crate::state_store::StateKeys::new(TEST_STATE_KEY).record_key_for(&pa.bundle.identity_key);
    let writes: Vec<Vec<u8>> = sb.history.lock().unwrap()[hlen..]
        .iter()
        .filter(|(k, _)| *k == key)
        .map(|(_, b)| b.clone())
        .collect();
    assert!(!writes.is_empty());
    for w in &writes {
        assert!(!w.is_empty(), "the record is never deleted");
        let r = open_sealed(0xB2, &key, w);
        assert_eq!(r.received_ids, before.received_ids, "received ids kept");
        assert_eq!(r.sent_ids.len(), before.sent_ids.len(), "sent ids kept");
        assert_eq!(r.seen_ids, before.seen_ids);
        assert!(r.session.is_some());
    }
    let after = open_record(&sb, 0xB2, &pa);
    assert!(after.pending_init.is_none(), "the wait is gone");
    assert!(!b2.awaiting_init(&pa.hex));
    let closed: Vec<_> = sent_controls(&mut b2_rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CloseCircuit { circuit_id } => Some(circuit_id),
            _ => None,
        })
        .collect();
    assert_eq!(closed, vec![c4], "the wait's circuit is closed");
    // B still holds the first pair's session: the publish asks for it (a
    // blind re-pair of that known contact, Task 9), so the pair is formed
    // again.
    let mut b2 = b2;
    b2.after_publish_ok(std::time::Instant::now());
    assert_eq!(blind_asks_in(&sent_controls(&mut b2_rx)), 1);
}

/// Review N-1: an unpublished restore that applies the peer record before
/// the meta record, with a too-old wait. The close is kept for the next
/// publish, and the meta record on disk keeps what it held (a pending
/// close, a held body and an unanswered ask) plus the new close: no meta
/// write happens before the staged meta is applied.
#[test]
fn a_wait_dropped_at_restore_keeps_the_staged_meta() {
    let (mut a, _a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    let pc = peer(0xC3);
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    b.peers.pin_card(&pc).unwrap();
    let sb = MemorySink::default();
    with_store(&mut b, &sb);
    reestablish(&mut a, &mut b, &pa, &pb);
    let now = crate::unix_now_secs();
    b.pending_inits.get_mut(&pa.hex).unwrap().created_at_unix =
        now - crate::circuits::PENDING_INIT_MAX_AGE_SECS - 3600;
    b.persist_peer(&pa.hex).unwrap();
    let marker = crate::protocol::CircuitId([0x5a; 16]);
    b.pending_closes.push(marker.clone());
    b.unanswered_asks.insert(
        pc.hex.clone(),
        (std::time::Instant::now(), b.transport_epoch),
    );
    b.pending_encrypted_messages
        .push_back(crate::PendingEncrypted {
            sender_hex: pc.hex.clone(),
            message_id: [0x77; 16],
            body: vec![1, 2, 3],
        });
    b.persist_meta();
    drop(b);
    let keys = crate::state_store::StateKeys::new(TEST_STATE_KEY);
    let our_ik = pb.bundle.identity_key;
    let meta_on_disk = |sealed: &[u8]| -> crate::state_store::MetaRecordV1 {
        let (_, _, body) = keys
            .open(&our_ik, crate::state_store::META_KEY, sealed)
            .unwrap();
        bincode::deserialize(&body).unwrap()
    };
    let hlen = sb.history.lock().unwrap().len();
    let (mut b2, _rx) = inner_with_identity(0xB2);
    b2.bypass_frame_gate = false;
    b2.is_key_bundle_published = false;
    b2.peers.pin_card(&pa).unwrap();
    b2.peers.pin_card(&pc).unwrap();
    with_store(&mut b2, &sb);
    let mut files: Vec<_> = sb.files.lock().unwrap().clone().into_iter().collect();
    files.sort_by_key(|(k, _)| k == crate::state_store::META_KEY); // peer first
    let store = b2.state.as_mut().unwrap();
    for (k, s) in files {
        store.stage_keep_higher(k, s);
    }
    b2.restore_staged_state();
    assert!(!b2.awaiting_init(&pa.hex));
    // Every meta write of the restore keeps the staged contents.
    let meta_writes: Vec<Vec<u8>> = sb.history.lock().unwrap()[hlen..]
        .iter()
        .filter(|(k, _)| k == crate::state_store::META_KEY)
        .map(|(_, b)| b.clone())
        .collect();
    assert!(!meta_writes.is_empty(), "the close was recorded");
    for w in &meta_writes {
        let m = meta_on_disk(w);
        assert!(m.pending_closes.contains(&marker.0), "pending close kept");
        assert!(
            m.unanswered_asks.contains(&pc.bundle.identity_key),
            "ask kept"
        );
        assert!(
            m.held.iter().any(|h| h.message_id == [0x77; 16]),
            "held body kept"
        );
    }
    let last = meta_on_disk(meta_writes.last().unwrap());
    assert!(
        last.pending_closes.contains(&C2.0),
        "the wait's close is kept"
    );
    assert!(b2.pending_closes.contains(&C2));
}

/// Review N-2: a restored session whose session-init was never sealed
/// owes the hello that carries it; the tick sends it, the init first,
/// and the tracked re-sends held behind it follow.
#[test]
fn a_restored_unsent_init_owes_its_hello() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sa = MemorySink::default();
    with_store(&mut a, &sa);
    reestablish(&mut a, &mut b, &pa, &pb);
    let _ = sent_relays(&mut a_rx);
    // As if the hello's seal had failed before the kill: unclaimed init.
    a.session_manager
        .get_mut(&pb.hex)
        .unwrap()
        .init_out
        .as_mut()
        .unwrap()
        .sent = None;
    a.persist_peer(&pb.hex).unwrap();
    drop(a);
    let (mut a2, mut a2_rx, _log) = restart_from(0xA1, 0xB2, &sa);
    assert!(a2.hello_sync_due.contains(&pb.hex), "the hello is owed");
    a2.is_key_bundle_published = true;
    feed(
        &mut a2,
        Frame::Control(ControlMessage::CircuitExists {
            circuit_id: C1,
            token: TOKEN.to_vec(),
            target_circuit_id: C2,
            is_initiator: true,
        }),
    );
    if let Some(ws) = &a2.websocket {
        ws.set_connected_for_test();
    }
    a2.redrive_owed_sends(std::time::Instant::now() + std::time::Duration::from_secs(10));
    let sent = sent_relays(&mut a2_rx);
    assert!(!sent.is_empty(), "the hello left");
    let b_id = b.identity.clone().unwrap();
    let first = crate::sealed::open(
        &b_id.public_signing_key().to_bytes(),
        b_id.agreement_secret(),
        &sent[0].payload,
    )
    .unwrap();
    assert_eq!(first.kind, crate::session_init::SESSION_INIT_TYPE);
    assert!(!a2.hello_sync_due.contains(&pb.hex));
}

/// Final review L7: a message that expired while it was still the payload
/// of our unanswered session-init is not re-sent with it. The init is
/// rebuilt around a cover message (a new hello) and the stored record
/// drops the old payload, so neither a resume nor a restart sends the
/// expired message again.
#[test]
fn forgetting_the_init_message_rebuilds_the_init_around_cover() {
    let (mut a, mut a_rx) = published(0xA1);
    let (mut b, _b_rx) = published(0xB2);
    let (pa, pb) = (peer(0xA1), peer(0xB2));
    a.peers.pin_card(&pb).unwrap();
    b.peers.pin_card(&pa).unwrap();
    let sa = MemorySink::default();
    with_store(&mut a, &sa);
    reestablish(&mut a, &mut b, &pa, &pb);
    let _ = sent_relays(&mut a_rx);
    // The init is unclaimed, and a text is the first seal: it travels as
    // the session-init.
    a.session_manager
        .get_mut(&pb.hex)
        .unwrap()
        .init_out
        .as_mut()
        .unwrap()
        .sent = None;
    let id = push_text(&a, &pb.hex, "expires soon");
    let init_id = |a: &ClientInner| {
        a.session_manager
            .get(&pb.hex)
            .unwrap()
            .init_out
            .as_ref()
            .and_then(|i| i.sent.as_ref().map(|s| (s.id, s.payload.clone())))
    };
    let (first, old_payload) = init_id(&a).unwrap();
    assert_eq!(first, id, "the text is the init");
    let _ = sent_relays(&mut a_rx);
    a.forget_message(&hex::encode(id));
    let (now_id, payload) = init_id(&a).expect("an init is out again");
    assert_ne!(now_id, id, "rebuilt around another message");
    assert_ne!(payload, old_payload);
    assert!(!payload.is_empty());
    let rec = open_record(&sa, 0xA1, &pb);
    let stored = rec.session.as_ref().unwrap().init_out.as_ref().unwrap();
    assert_ne!(stored.sent_id, Some(id), "the record no longer holds it");
    assert_ne!(stored.sent_payload, old_payload);
}
