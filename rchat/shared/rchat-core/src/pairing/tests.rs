use super::*;
use crate::test_support::*;

const SK: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn ep(day: u32, counter: u32) -> PairEpoch {
    PairEpoch { day, counter }
}

/// Independent Python (hmac, hashlib, hand-written HKDF) produced these.
#[test]
fn golden_vectors_match_independent_python() {
    let ps = pair_secret(&SK);
    assert_eq!(
        hex::encode(*ps),
        "f2cb91431560687537ad8c88a21bc727df54e5b6d5bcf75bdcff6f9eb70d1622"
    );
    // R40-M3: the 10-minute slot follows the counter (u32 BE). Day 20000
    // starts at slot 20000 * 144 = 2_880_000.
    assert_eq!(
        hex::encode(pair_token(&ps, ep(20000, 3), 2_880_000)),
        "74fdc8196c152e697852d678c54486e2886ec2e10a31878196a724a871b69fea"
    );
    assert_eq!(
        hex::encode(pair_token(&ps, ep(20000, 3), 2_880_001)),
        "fe339af72950cb7fcd5b9c4197ec95ca4f98b6d0b07e8a4254680ab863c0e029"
    );
    assert_eq!(
        hex::encode(pair_token(&ps, ep(0, 0), 0)),
        "9af407b39dc22892186921c0d807e97bab3516c13550808e63365f67016d4622"
    );
}

/// R40-M3: the token changes at each 10-minute slot boundary and stays
/// the same within a slot; tokens hours apart differ.
#[test]
fn token_changes_at_the_slot_boundary() {
    let ps = pair_secret(&SK);
    let e = ep(20000, 0);
    let start = 20_000u64 * 86_400 + 12 * 3600; // a slot boundary (noon)
    assert_eq!(pair_slot(start - 1) + 1, pair_slot(start));
    assert_eq!(pair_slot(start), pair_slot(start + 599));
    assert_eq!(pair_slot(start + 600), pair_slot(start) + 1);
    let t = |unix: u64| pair_token(&ps, e, pair_slot(unix));
    assert_eq!(t(start), t(start + 599));
    assert_ne!(t(start - 1), t(start));
    assert_ne!(t(start + 599), t(start + 600));
    assert_ne!(t(start), t(start + 3 * 3600), "hours apart");
    // Day boundaries are slot boundaries (86400 = 144 * 600).
    assert_eq!(pair_slot(20_001 * 86_400), 20_001 * 144);
    assert_eq!(u64::from(pair_slot(u64::MAX)), u64::from(u32::MAX));
}

#[test]
fn token_is_deterministic() {
    let ps = pair_secret(&SK);
    assert_eq!(pair_token(&ps, ep(5, 1), 7), pair_token(&ps, ep(5, 1), 7));
    assert_ne!(*ps, SK);
    assert_ne!(*pair_secret(&[9; 32]), *ps);
    assert_ne!(
        pair_token(&pair_secret(&[9; 32]), ep(5, 1), 7),
        pair_token(&ps, ep(5, 1), 7)
    );
}

#[test]
fn day_or_counter_change_changes_token() {
    let ps = pair_secret(&SK);
    let t = pair_token(&ps, ep(5, 1), 9);
    assert_ne!(t, pair_token(&ps, ep(6, 1), 9));
    assert_ne!(t, pair_token(&ps, ep(5, 2), 9));
    assert_ne!(t, pair_token(&ps, ep(5, 1), 10));
    // day, counter and slot are not interchangeable
    assert_ne!(pair_token(&ps, ep(1, 2), 3), pair_token(&ps, ep(2, 1), 3));
    assert_ne!(pair_token(&ps, ep(1, 2), 3), pair_token(&ps, ep(1, 3), 2));
}

#[test]
fn advance_increments_then_resets_on_new_day() {
    let mut e = ep(10, 0);
    e.advance(10);
    assert_eq!(e, ep(10, 1));
    e.advance(10);
    assert_eq!(e, ep(10, 2));
    e.advance(11);
    assert_eq!(e, ep(11, 0));
    e.advance(11);
    assert_eq!(e, ep(11, 1));
}

#[test]
fn advance_with_clock_going_backwards_keeps_day_and_counts() {
    let mut e = ep(10, 4);
    e.advance(9);
    assert_eq!(e, ep(10, 5));
}

#[test]
fn advance_saturates_the_counter() {
    let mut e = ep(10, u32::MAX);
    e.advance(10);
    assert_eq!(e, ep(10, u32::MAX));
}

#[test]
fn near_boundary_and_neighbour_day() {
    let d = 20_000u64;
    let base = d * 86_400;
    // 23:55 UTC: near, neighbour = day + 1
    let t = base + 23 * 3600 + 55 * 60;
    assert!(near_day_boundary(t));
    assert_eq!(utc_day(t), 20_000);
    assert_eq!(neighbour_day(t), 20_001);
    // 00:04 UTC: near, neighbour = day - 1
    let t = base + 4 * 60;
    assert!(near_day_boundary(t));
    assert_eq!(neighbour_day(t), 19_999);
    // 12:00: not near, the current day
    let t = base + 12 * 3600;
    assert!(!near_day_boundary(t));
    assert_eq!(neighbour_day(t), 20_000);
}

#[test]
fn exact_edges_of_the_600_second_window() {
    let next = 20_001u64 * 86_400;
    assert!(!near_day_boundary(next - 601));
    assert_eq!(neighbour_day(next - 601), 20_000);
    assert!(near_day_boundary(next - 600));
    assert_eq!(neighbour_day(next - 600), 20_001);
    assert!(near_day_boundary(next - 1));
    assert!(near_day_boundary(next + 599));
    assert_eq!(neighbour_day(next + 599), 20_000);
    assert!(!near_day_boundary(next + 600));
    assert_eq!(neighbour_day(next + 600), 20_001);
    assert!(near_day_boundary(next));
}

#[test]
fn day_zero_does_not_underflow() {
    assert_eq!(utc_day(0), 0);
    assert!(near_day_boundary(240));
    assert_eq!(neighbour_day(240), 0);
    assert_eq!(neighbour_day(0), 0);
    assert_eq!(utc_day(u64::MAX), u32::MAX);
}

#[test]
fn both_sides_derive_same_ps() {
    let p = establish(0xA1, 0xB2);
    let a = p.a.session_manager.get(&p.pb.hex).unwrap();
    let b = p.b.session_manager.get(&p.pa.hex).unwrap();
    let (pa, pb) = (
        a.pair_secret.as_ref().unwrap(),
        b.pair_secret.as_ref().unwrap(),
    );
    assert_eq!(**pa, **pb);
    assert_ne!(**pa, [0; 32]);
    assert_eq!(a.pair_epoch, b.pair_epoch);
    assert_eq!(a.pair_epoch.day, utc_day(crate::unix_now_secs()));
    assert_eq!(a.pair_epoch.counter, 0);
    assert_eq!(
        pair_token(pa, a.pair_epoch, 1),
        pair_token(pb, b.pair_epoch, 1)
    );
}

#[test]
fn pair_secret_persists_round_trip() {
    let (sa, sb) = (MemorySink::default(), MemorySink::default());
    let p = stored_pair(&sa, &sb);
    let (ps, epoch) = {
        let mut s = p.a.session_manager.get_mut(&p.pb.hex).unwrap();
        let day = s.pair_epoch.day;
        s.pair_epoch.advance(day);
        (**s.pair_secret.as_ref().unwrap(), s.pair_epoch)
    };
    assert_eq!(epoch.counter, 1);
    p.a.persist_peer(&p.pb.hex).unwrap();
    let rec = open_record(&sa, 0xA1, &p.pb);
    let snap = rec.session.as_ref().unwrap();
    assert_eq!(snap.pair_secret.as_ref().unwrap().0, ps);
    assert_eq!(snap.pair_epoch, epoch);
    let (a2, _rx, _log) = restart_from(0xA1, 0xB2, &sa);
    let s = a2.session_manager.get(&p.pb.hex).unwrap();
    assert_eq!(**s.pair_secret.as_ref().unwrap(), ps);
    assert_eq!(s.pair_epoch, epoch);
}

#[test]
fn session_debug_output_never_prints_the_pair_secret() {
    let p = establish(0xA1, 0xB2);
    let ps = **p
        .a
        .session_manager
        .get(&p.pb.hex)
        .unwrap()
        .pair_secret
        .as_ref()
        .unwrap();
    let dbg = p.a.session_manager.get_session_debug(&p.pb.hex).unwrap();
    assert!(!dbg.contains(&hex::encode(ps)));
    assert!(!dbg.contains(&format!("{ps:?}")));
}
