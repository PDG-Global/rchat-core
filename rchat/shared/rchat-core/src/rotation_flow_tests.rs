//! KR3–KR9, KR11–KR15: contact key rotation (spec §4.8, round-2 H2/M1/M3/L4).

use crate::circuits::now_hour;
use crate::knock::{self, Intro, MAX_INTRO_BYTES};
use crate::protocol::{ControlMessage, Frame};
use crate::rotation::{sign_link, RotationBlock};
use crate::sealed;
use crate::test_support::*;
use crate::{ClientConfig, RChatError};
use std::time::Instant;

fn block(old: &Peer, new: &Peer, version: u32) -> RotationBlock {
    RotationBlock {
        current_version: version,
        links: vec![sign_link(
            &old.id,
            &new.bundle.identity_key,
            &new.bundle.identity_agreement_key,
            version,
        )],
    }
}

/// A config after rotating `old` → `new` with a version-1 link, claiming
/// `identity_version` (normally 1).
fn rotated_config(old: &Peer, new: &Peer, identity_version: u32) -> ClientConfig {
    ClientConfig {
        identity_version,
        rotation_links_hex: Some(hex::encode(
            sign_link(
                &old.id,
                &new.bundle.identity_key,
                &new.bundle.identity_agreement_key,
                1,
            )
            .to_bytes(),
        )),
        ..ClientConfig::default()
    }
}

fn rotated(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<(String, String, u32)> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Rotated(o, n, _, v) => Some((o.clone(), n.clone(), *v)),
            _ => None,
        })
        .collect()
}

fn requests(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Ev::Request(_)))
        .count()
}

/// KR3: a knock from the new identity with a valid chain re-pins silently.
#[test]
fn kr3_knock_with_valid_chain_repins_silently() {
    let (old, new) = (peer(0xA1), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    let me = peer(0xB2);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &me,
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert_eq!(b.peers.pin_for(&old.hex), None, "old identity unpinned");
    assert_eq!(
        b.peers.pin_for(&new.hex),
        Some(new.bundle.identity_agreement_key)
    );
    assert_eq!(b.peers.pin_version(&new.hex), 1);
    assert_eq!(rotated(&log), vec![(old.hex.clone(), new.hex.clone(), 1)]);
    assert_eq!(requests(&log), 0, "not a request");
    assert!(
        b.pending_reasks.contains_key(&new.hex),
        "asks the new identity"
    );
}

/// KR4: a chain not signed by the pinned key is a request, never a re-pin.
#[test]
fn kr4_forged_chain_is_a_request() {
    let (old, new, stranger) = (peer(0xA1), peer(0xA9), peer(0xC5));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    let forged = RotationBlock {
        current_version: 1,
        links: vec![sign_link(
            &stranger.id,
            &new.bundle.identity_key,
            &new.bundle.identity_agreement_key,
            1,
        )],
    };
    feed(
        &mut b,
        queued(knock_from_rotating(&new, &peer(0xB2), now_hour(), &forged)),
    );
    assert_eq!(
        b.peers.pin_for(&old.hex),
        Some(old.bundle.identity_agreement_key),
        "old pin kept"
    );
    assert_eq!(b.peers.pin_for(&new.hex), None);
    assert!(rotated(&log).is_empty());
    assert_eq!(requests(&log), 1);
}

/// KR5: a link whose version is not pinned + 1 is ignored.
#[test]
fn kr5_replayed_or_stale_link_is_ignored() {
    let (old, new) = (peer(0xA1), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    b.peers.set_pin_version(&old.hex, 1);
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty());
    assert_eq!(
        b.peers.pin_for(&old.hex),
        Some(old.bundle.identity_agreement_key)
    );
}

/// KR6 (round-2 M1, security review L-1): a `0x04` notice changes nothing
/// and is not stored: a later chainless knock from the new identity is a
/// plain request. Only the new identity's knock carrying its own chain
/// applies the rotation.
#[test]
fn kr6_ratchet_notice_changes_nothing_and_only_a_knock_chain_repins() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    let notice = |blk: &RotationBlock| {
        let mut pt = vec![0x04];
        pt.extend_from_slice(&blk.encode().unwrap());
        pt
    };
    let good = block(&p.pa, &new, 1);
    let pkt =
        p.a.seal_ratchet(&p.pb.hex, [2; 16], &notice(&good))
            .unwrap();
    feed(&mut p.b, Frame::Relay(pkt));
    assert!(
        rotated(&p.b_log).is_empty(),
        "no re-pin from a notice alone"
    );
    assert_eq!(
        p.b.peers.pin_for(&p.pa.hex),
        Some(p.pa.bundle.identity_agreement_key)
    );
    // The notice is not applied to the new identity's chainless knock.
    feed(&mut p.b, queued(knock_from(&new, &p.pb, now_hour())));
    assert!(rotated(&p.b_log).is_empty(), "a notice is never applied");
    assert_eq!(requests(&p.b_log), 1, "a chainless knock is a request");
    assert_eq!(p.b.peers.pin_for(&new.hex), None);
    assert_eq!(
        p.b.peers.pin_for(&p.pa.hex),
        Some(p.pa.bundle.identity_agreement_key)
    );
    assert!(
        p.b_log
            .lock()
            .unwrap()
            .iter()
            .all(|e| !matches!(e, Ev::Message(..))),
        "a notice is not a message"
    );
}

/// KR6, the positive half: the new identity's knock with its own chain
/// re-pins, with or without an earlier notice.
#[test]
fn kr6_knock_with_its_own_chain_repins_after_a_notice() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    let good = block(&p.pa, &new, 1);
    let mut pt = vec![0x04];
    pt.extend_from_slice(&good.encode().unwrap());
    let pkt = p.a.seal_ratchet(&p.pb.hex, [3; 16], &pt).unwrap();
    feed(&mut p.b, Frame::Relay(pkt));
    feed(
        &mut p.b,
        queued(knock_from_rotating(&new, &p.pb, now_hour(), &good)),
    );
    assert_eq!(
        rotated(&p.b_log),
        vec![(p.pa.hex.clone(), new.hex.clone(), 1)]
    );
    assert_eq!(
        p.b.peers.pin_for(&new.hex),
        Some(new.bundle.identity_agreement_key)
    );
}

/// KR11 (round-2 H2): a contact in Mismatch never follows a rotation.
#[test]
fn kr11_mismatch_blocks_silent_rotation() {
    let (old, new) = (peer(0xA1), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    b.peers.mark_mismatch(&old.hex);
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty());
    assert!(b.peers.is_mismatch(&old.hex), "Mismatch stays");
    assert_eq!(b.peers.pin_for(&new.hex), None);
}

/// KR12 (round-2 H2): the first link must start at the pinned agreement key.
#[test]
fn kr12_chain_must_start_at_the_pinned_agreement_key() {
    let (old, new) = (peer(0xA1), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers.pin(&old.hex, [0x77; 32]).unwrap(); // not old's real agreement key
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty());
    assert_eq!(b.peers.pin_for(&old.hex), Some([0x77; 32]));
}

/// KR13 (round-2 M1): refusals, and blocking carries over.
#[test]
fn kr13_refusals_and_block_propagation() {
    let (old, new) = (peer(0xA1), peer(0xA9));
    // Already requested.
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    b.peers.note_request(&new.hex, None, now_hour());
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty(), "new identity already requested");
    // Agreement key pinned elsewhere.
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    b.peers
        .pin(&peer(0xC7).hex, new.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty(), "agreement key pinned elsewhere");
    // Blocked old identity: the new one is blocked too, silently.
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers.set_blocked(&old.hex, true);
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(b.peers.is_blocked(&new.hex));
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .all(|e| !matches!(e, Ev::Request(_) | Ev::Rotated(..))));
}

/// KR7: one rotation per 24 h on both sides.
#[test]
fn kr7_rate_limits() {
    let (mut a, _rx) = published(0xA1);
    a.config.rotated_at_unix = Some(crate::unix_now_secs() - 3600);
    let client = wrap(a);
    assert!(matches!(
        client.prepare_rotation(),
        Err(RChatError::RotationTooSoon)
    ));

    let (old, mid, new) = (peer(0xA1), peer(0xA8), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers
        .pin(&old.hex, old.bundle.identity_agreement_key)
        .unwrap();
    feed(
        &mut b,
        queued(knock_from_rotating(
            &mid,
            &peer(0xB2),
            now_hour(),
            &block(&old, &mid, 1),
        )),
    );
    assert_eq!(rotated(&log).len(), 1);
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&mid, &new, 2),
        )),
    );
    assert_eq!(
        rotated(&log).len(),
        1,
        "second silent re-pin within 24 h refused"
    );
    assert_eq!(
        b.peers.pin_for(&mid.hex),
        Some(mid.bundle.identity_agreement_key)
    );
    assert_eq!(requests(&log), 1, "the newer identity arrives as a request");
}

/// KR8 (D21): no hand-over to the relay; a just-rotated contact's old
/// identity is accepted only through `rotated_from`.
#[test]
fn kr8_no_relay_handover_after_rotation() {
    let old_me = peer(0xB2);
    let new_me = peer(0xB9);
    let cfg = ClientConfig {
        rotated_at_unix: Some(crate::unix_now_secs() - 60),
        ..rotated_config(&old_me, &new_me, 1)
    };
    let (mut b, mut rx) = published_with_config(0xB9, cfg);
    b.publish_requested = true;
    b.auth_challenge = Some([0x4e; 32]);
    b.publish_in_flight = false;
    let _ = b.try_publish();
    let publishes: Vec<_> = sent_signaling(&mut rx)
        .into_iter()
        .filter(|m| m.msg_type == "publish_key_bundle")
        .collect();
    assert_eq!(publishes.len(), 1);
    assert!(
        publishes[0].payload.inner["data"].get("rotation").is_none(),
        "no rotation data for the relay"
    );
    // A pinned contact still knocking on our old identity cannot reach us: it does not open.
    let contact = peer(0xC3);
    b.peers
        .pin(&contact.hex, contact.bundle.identity_agreement_key)
        .unwrap();
    feed(&mut b, queued(knock_from(&contact, &old_me, now_hour())));
    assert!(
        !b.pending_reasks.contains_key(&contact.hex),
        "payloads to the old keys are not opened"
    );
}

/// KR9: the largest intro and a 3-link block fit in one 2048-byte knock.
#[test]
fn kr9_max_intro_and_full_chain_fit() {
    let (a, b2, c, d) = (peer(0xA1), peer(0xA2), peer(0xA3), peer(0xA4));
    let blk = RotationBlock {
        current_version: 3,
        links: vec![
            sign_link(
                &a.id,
                &b2.bundle.identity_key,
                &b2.bundle.identity_agreement_key,
                1,
            ),
            sign_link(
                &b2.id,
                &c.bundle.identity_key,
                &c.bundle.identity_agreement_key,
                2,
            ),
            sign_link(
                &c.id,
                &d.bundle.identity_key,
                &d.bundle.identity_agreement_key,
                3,
            ),
        ],
    };
    let r = peer(0xB2);
    let intro = Intro {
        message_id: [9; 16],
        sent_at_ms: 1,
        text: "x".repeat(MAX_INTRO_BYTES),
    };
    let k = knock::build_knock(
        &d.id,
        &d.bundle,
        &r.bundle.identity_key,
        &r.bundle.identity_agreement_key,
        now_hour(),
        Some(&intro),
        Some(&blk),
    )
    .unwrap();
    assert_eq!(k.len(), sealed::KNOCK_PAYLOAD_LEN);
    let opened = sealed::open(&r.bundle.identity_key, r.id.agreement_secret(), &k).unwrap();
    let parsed = knock::parse_knock(&r.id, &opened, now_hour(), 72, true).unwrap();
    assert_eq!(parsed.intro.unwrap().text.len(), MAX_INTRO_BYTES);
    assert_eq!(parsed.rotation, Some(blk));
}

/// KR14 (round-2 M3): the block goes only to unreached contacts; quota; reach.
#[test]
fn kr14_unreached_set_quota_and_reach() {
    let (old_me, new_me, b_peer, c_peer) = (peer(0xA1), peer(0xA9), peer(0xB2), peer(0xC3));
    let cfg = ClientConfig {
        rotated_at_unix: Some(crate::unix_now_secs() - 100 * 3600), // past 72 h: still re-asked
        rotation_unreached_hex: Some(vec![b_peer.hex.clone()]),
        ..rotated_config(&old_me, &new_me, 1)
    };
    let (mut a, mut rx) = published_with_config(0xA9, cfg);
    a.peers
        .pin(&b_peer.hex, b_peer.bundle.identity_agreement_key)
        .unwrap();
    a.peers
        .pin(&c_peer.hex, c_peer.bundle.identity_agreement_key)
        .unwrap();
    a.after_publish_ok(Instant::now());
    assert!(
        a.pending_reasks.contains_key(&b_peer.hex),
        "unreached peer re-asked after 72 h"
    );
    assert!(
        !a.pending_reasks.contains_key(&c_peer.hex),
        "only unreached peers"
    );
    let tail_of = |knock: &[u8], to: &Peer| {
        let opened =
            sealed::open(&to.bundle.identity_key, to.id.agreement_secret(), knock).unwrap();
        knock::parse_knock(&to.id, &opened, now_hour(), 72, true)
            .unwrap()
            .rotation
    };
    drain(&mut rx);
    a.ask(
        &b_peer.hex,
        crate::circuits::AskTrigger::User,
        Instant::now(),
    )
    .unwrap();
    a.ask(
        &c_peer.hex,
        crate::circuits::AskTrigger::User,
        Instant::now(),
    )
    .unwrap();
    let knocks: Vec<(Vec<u8>, Vec<u8>)> = sent_controls(&mut rx)
        .into_iter()
        .filter_map(|m| match m {
            ControlMessage::CircuitAsk {
                target_identity,
                knock,
                ..
            } => Some((target_identity, knock)),
            _ => None,
        })
        .collect();
    let to_b = &knocks
        .iter()
        .find(|(t, _)| t.as_slice() == b_peer.bundle.identity_key)
        .unwrap()
        .1;
    let to_c = &knocks
        .iter()
        .find(|(t, _)| t.as_slice() == c_peer.bundle.identity_key)
        .unwrap()
        .1;
    assert!(
        tail_of(to_b, &b_peer).is_some(),
        "block to an unreached contact"
    );
    assert!(
        tail_of(to_c, &c_peer).is_none(),
        "no block (no old identities) to anyone else"
    );
    // Quota: 90 rotation knocks in the last 24 h → the next is rescheduled, not sent.
    // (Past the first ask's in-flight window, so the user ask is not suppressed.)
    let later = Instant::now() + crate::circuits::ASK_IN_FLIGHT;
    a.rotation_knocks = (0..crate::MAX_ROTATION_KNOCKS_PER_DAY)
        .map(|_| Instant::now())
        .collect();
    a.ask(&b_peer.hex, crate::circuits::AskTrigger::User, later)
        .unwrap();
    assert!(sent_controls(&mut rx).is_empty(), "over quota: not sent");
    assert!(a.pending_reasks.contains_key(&b_peer.hex));
    // Task 17c minor: a rotation knock that fails to send gives its slot back.
    a.rotation_knocks.clear();
    drop(rx);
    assert!(a
        .ask(&b_peer.hex, crate::circuits::AskTrigger::User, later)
        .is_err());
    assert!(a.rotation_knocks.is_empty(), "slot given back");
    // Reached.
    a.rotation_reached(&b_peer.hex);
    assert!(!a.rotation_unreached.contains(&b_peer.hex));
}

/// KR15 (round-2 L4): the new seed never appears in the JSON; it is handed out once.
#[test]
fn kr15_seed_handoff_is_single_use() {
    let (a, _rx) = published(0xA1);
    let client = wrap(a);
    let json: serde_json::Value =
        serde_json::from_str(&client.prepare_rotation().unwrap()).unwrap();
    assert!(json.get("new_seed").is_none());
    let mut buf = [0u8; 64];
    assert!(client.take_rotation_seed(&mut buf));
    assert_ne!(buf, [0u8; 64]);
    let new = crate::crypto::IdentityKeyPair::from_seed(&buf).unwrap();
    assert_eq!(
        hex::encode(new.public_signing_key().to_bytes()),
        json["new_identity"].as_str().unwrap()
    );
    let mut again = [0u8; 64];
    assert!(!client.take_rotation_seed(&mut again), "single use");
    assert_eq!(again, [0u8; 64]);
}

fn messages(log: &std::sync::Arc<std::sync::Mutex<Vec<Ev>>>) -> Vec<(String, Vec<u8>)> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Message(s, c, _) => Some((s.clone(), c.clone())),
            _ => None,
        })
        .collect()
}

/// Spec §4.8: in-flight messages from the old identity are accepted after
/// the re-pin and reported as from the new identity; nothing is resent (H1).
#[test]
fn in_flight_message_from_the_old_identity_is_reported_as_the_new_one() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    let late = push_text(&p.a, &p.pb.hex, "late");
    // B's own message to the old identity, never confirmed.
    let sent_id = push_text(&p.b, &p.pa.hex, "unconfirmed");
    drain(&mut p.b_rx);
    feed(
        &mut p.b,
        queued(knock_from_rotating(
            &new,
            &p.pb,
            now_hour(),
            &block(&p.pa, &new, 1),
        )),
    );
    assert_eq!(rotated(&p.b_log).len(), 1);
    let after: Vec<_> = sent_relays(&mut p.b_rx);
    assert!(after.is_empty(), "nothing is resent automatically (H1)");
    p.b.receipt_delay_override = Some(std::time::Duration::from_secs(2));
    assert_eq!(relay_all(&mut p.a_rx, &mut p.b), 1);
    assert_eq!(
        messages(&p.b_log),
        vec![(new.hex.clone(), b"late".to_vec())]
    );
    // The app stores it under the identity it was reported as (D36).
    p.b.mark_seen_and_receipt(&new.hex, late).unwrap();
    assert!(
        p.b.was_sent_to(&new.hex, &sent_id),
        "receipts bind to the new identity"
    );
    assert!(!p.b.was_sent_to(&p.pa.hex, &sent_id));
    // Task 17c triage: the delivered receipt for "late" is queued and
    // scheduled under the identity it is reported as, not the old one.
    assert!(p
        .b
        .pending_receipts
        .contains_key(&(new.hex.clone(), crate::receipts::DELIVERED)));
    assert!(
        p.b.receipt_due.contains_key(&new.hex),
        "its flush is scheduled under the new identity"
    );
    assert!(!p.b.receipt_due.contains_key(&p.pa.hex));
}

/// Once the new identity is blocked, the old identity's messages are dropped too.
#[test]
fn old_identity_messages_stop_when_the_new_identity_is_blocked() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    push_text(&p.a, &p.pb.hex, "late");
    feed(
        &mut p.b,
        queued(knock_from_rotating(
            &new,
            &p.pb,
            now_hour(),
            &block(&p.pa, &new, 1),
        )),
    );
    p.b.block_peer(&new.hex, true).unwrap();
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(messages(&p.b_log).is_empty());
}

/// `announce_rotation` sends the notice over live circuits; the peer shows
/// nothing and changes nothing (L-1), from a Mismatch contact too.
#[test]
fn announce_rotation_reaches_live_peers_and_changes_nothing() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    let blk = block(&p.pa, &new, 1);
    assert_eq!(p.a.announce_rotation(&blk), 1);
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(rotated(&p.b_log).is_empty());
    assert!(messages(&p.b_log).is_empty());

    let mut p = establish(0xA1, 0xB2);
    p.b.peers.mark_mismatch(&p.pa.hex);
    assert_eq!(p.a.announce_rotation(&blk), 1);
    relay_all(&mut p.a_rx, &mut p.b);
    assert!(rotated(&p.b_log).is_empty(), "Mismatch never follows");
    assert!(p.b.peers.is_mismatch(&p.pa.hex));
}

/// `MessageRequest.key_version`: the block's version when its chain ends at
/// the sender, else 0.
#[test]
fn request_carries_the_key_version() {
    let (old, mid, new) = (peer(0xA1), peer(0xA8), peer(0xA9));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &peer(0xB2),
            now_hour(),
            &block(&mid, &new, 2),
        )),
    );
    feed(
        &mut b,
        queued(knock_from_rotating(
            &mid,
            &peer(0xB2),
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    feed(&mut b, queued(knock_from(&old, &peer(0xB2), now_hour())));
    let versions: Vec<(String, u32)> = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Ev::Request(r) => Some((r.identity_hex.clone(), r.key_version)),
            _ => None,
        })
        .collect();
    assert_eq!(
        versions,
        vec![
            (new.hex.clone(), 2),
            (mid.hex.clone(), 0),
            (old.hex.clone(), 0)
        ]
    );
}

/// The own-side API: prepared links verify from the current identity;
/// `announce_rotation` refuses links from another identity;
/// `set_peer_key_version` needs a pin.
#[test]
fn own_rotation_api() {
    let (a, _rx) = published(0xA1);
    let me = peer(0xA1);
    let client = wrap(a);
    let json: serde_json::Value =
        serde_json::from_str(&client.prepare_rotation().unwrap()).unwrap();
    assert_eq!(json["new_version"], 1);
    let links = crate::parse_links_hex(json["links"].as_str().unwrap());
    assert_eq!(links.len(), 1);
    let nik = crate::peers::key_from_hex(json["new_identity"].as_str().unwrap()).unwrap();
    let nak = crate::peers::key_from_hex(json["new_agreement"].as_str().unwrap()).unwrap();
    assert_eq!(
        crate::rotation::walk_chain(
            &links,
            &me.bundle.identity_key,
            &me.bundle.identity_agreement_key,
            0,
            &nik,
            &nak
        ),
        Ok(1)
    );
    assert_eq!(
        client
            .announce_rotation(json["links"].as_str().unwrap().to_string())
            .unwrap(),
        0
    );
    let (other, other_new) = (peer(0xC1), peer(0xC9));
    let foreign = hex::encode(
        sign_link(
            &other.id,
            &other_new.bundle.identity_key,
            &other_new.bundle.identity_agreement_key,
            1,
        )
        .to_bytes(),
    );
    assert!(
        client.announce_rotation(foreign).is_err(),
        "not our rotation"
    );
    assert!(client.announce_rotation("zz".into()).is_err());
    let c = peer(0xC3);
    assert!(matches!(
        client.set_peer_key_version(c.hex.clone(), 3),
        Err(RChatError::NoPinnedKeys { .. })
    ));
    client
        .pin_peer_key(c.hex.clone(), hex::encode(c.bundle.identity_agreement_key))
        .unwrap();
    client
        .set_peer_key_version(c.hex.to_uppercase(), 3)
        .unwrap();
    let inner = client.inner.clone();
    let v = client
        .runtime
        .block_on(async move { inner.read().await.peers.pin_version(&c.hex) });
    assert_eq!(v, 3);
}

/// A chain in the config that does not match `identity_version` is not carried.
#[test]
fn inconsistent_rotation_config_is_not_carried() {
    let (old_me, new_me) = (peer(0xA1), peer(0xA9));
    let cfg = ClientConfig {
        rotation_unreached_hex: Some(vec![peer(0xB2).hex]),
        ..rotated_config(&old_me, &new_me, 2)
    };
    let (a, _rx) = published_with_config(0xA9, cfg);
    assert!(a.rotation_block.is_none());
    assert!(!a.rotation_pending_reach());
}

/// Seal a `0x04` notice carrying `blk` from `from` to `to_hex`.
fn notice_from(from: &crate::ClientInner, to_hex: &str, blk: &RotationBlock) -> Frame {
    let mut pt = vec![0x04];
    pt.extend_from_slice(&blk.encode().unwrap());
    Frame::Relay(from.seal_ratchet(to_hex, rand::random(), &pt).unwrap())
}

/// Fix round 1 (1): a pinned contact's notice naming someone else's new keys
/// cannot capture them when the real owner's own chain fails (Mismatch).
#[test]
fn foreign_notice_cannot_capture_a_new_identity() {
    // B pins A (0xA1, later Mismatch) and M (established pair, 0xD1).
    let mut p = establish(0xD1, 0xB2);
    let (m, a, a_new) = (p.pa.hex.clone(), peer(0xA1), peer(0xA9));
    p.b.peers
        .pin(&a.hex, a.bundle.identity_agreement_key)
        .unwrap();
    p.b.peers.mark_mismatch(&a.hex);
    let mallory = peer(0xD1);
    let capture = block(&mallory, &a_new, 1);
    let frame = notice_from(&p.a, &p.pb.hex, &capture);
    feed(&mut p.b, frame);
    feed(
        &mut p.b,
        queued(knock_from_rotating(
            &a_new,
            &p.pb,
            now_hour(),
            &block(&a, &a_new, 1),
        )),
    );
    assert!(rotated(&p.b_log).is_empty(), "no Rotated(M, A_new)");
    assert_eq!(requests(&p.b_log), 1, "A_new arrives as a request");
    assert_eq!(
        p.b.peers.pin_for(&m),
        Some(mallory.bundle.identity_agreement_key)
    );
    assert_eq!(p.b.peers.pin_for(&a_new.hex), None);
    assert!(p.b.peers.is_mismatch(&a.hex), "Mismatch untouched");
}

/// Fix round 1 (2, 3): M's notice naming Carol's keys; Carol knocks without a
/// chain → a request, M's slot untouched; blocking M then never blocks Carol.
#[test]
fn notice_naming_a_stranger_is_inert_and_blocking_the_sender_spares_them() {
    let mut p = establish(0xD1, 0xB2);
    let (mallory, carol) = (peer(0xD1), peer(0xCA));
    let frame = notice_from(&p.a, &p.pb.hex, &block(&mallory, &carol, 1));
    feed(&mut p.b, frame);
    feed(&mut p.b, queued(knock_from(&carol, &p.pb, now_hour())));
    assert!(rotated(&p.b_log).is_empty());
    assert_eq!(requests(&p.b_log), 1);
    assert_eq!(
        p.b.peers.pin_for(&mallory.hex),
        Some(mallory.bundle.identity_agreement_key)
    );
    assert_eq!(p.b.peers.pin_for(&carol.hex), None);
    p.b.block_peer(&mallory.hex, true).unwrap();
    assert!(
        !p.b.peers.is_blocked(&carol.hex),
        "a third party is never blocked"
    );
}

/// Fix round 1 (4): marking the safety number compared clears Mismatch, but a
/// rotation still needs the pinned agreement key to match.
#[test]
fn rotation_after_mark_compared_still_needs_the_pinned_agreement_key() {
    let (old, new, me) = (peer(0xA1), peer(0xA9), peer(0xB2));
    let (mut b, _rx) = published(0xB2);
    let log = install_event_log(&mut b);
    b.peers.pin(&old.hex, [0x77; 32]).unwrap();
    b.peers.mark_mismatch(&old.hex);
    let (my_ik, my_ak) = (me.bundle.identity_key, me.bundle.identity_agreement_key);
    let digits = b.peers.safety_number(&old.hex, &my_ik, &my_ak).unwrap();
    b.peers
        .mark_safety_number_compared(&old.hex, &my_ik, &my_ak, &digits)
        .unwrap();
    assert!(!b.peers.is_mismatch(&old.hex));
    feed(
        &mut b,
        queued(knock_from_rotating(
            &new,
            &me,
            now_hour(),
            &block(&old, &new, 1),
        )),
    );
    assert!(rotated(&log).is_empty());
    assert_eq!(b.peers.pin_for(&old.hex), Some([0x77; 32]));
    assert_eq!(requests(&log), 1);
}

/// Fix round 1: delivered receipts still owed to the old identity are
/// re-queued for the new identity, not dropped.
#[test]
fn owed_receipts_move_to_the_new_identity() {
    let mut p = establish(0xA1, 0xB2);
    let new = peer(0xA9);
    p.b.queue_receipt(&p.pa.hex, crate::receipts::DELIVERED, &[[5; 16]]);
    feed(
        &mut p.b,
        queued(knock_from_rotating(
            &new,
            &p.pb,
            now_hour(),
            &block(&p.pa, &new, 1),
        )),
    );
    assert_eq!(rotated(&p.b_log).len(), 1);
    assert_eq!(
        p.b.pending_receipts
            .get(&(new.hex.clone(), crate::receipts::DELIVERED)),
        Some(&vec![[5u8; 16]])
    );
    assert!(!p
        .b
        .pending_receipts
        .contains_key(&(p.pa.hex.clone(), crate::receipts::DELIVERED)));
}
