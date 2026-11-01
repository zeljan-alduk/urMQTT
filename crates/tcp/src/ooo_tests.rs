//! Tests of the out-of-order range list (ADR-215).

use alloc::vec::Vec;

use crate::ooo::{MAX_RANGES, Ooo};

fn bytes(a: u32, n: usize) -> Vec<u8> {
    (0..n).map(|i| (a as usize + i) as u8).collect()
}

#[test]
fn separate_ranges_stay_sorted_and_adjacent_ones_merge() {
    let mut o = Ooo::default();
    assert_eq!(o.insert(300, &bytes(300, 100)), Some(100));
    assert_eq!(o.insert(100, &bytes(100, 50)), Some(50));
    assert_eq!(o.ranges(), 2);
    // Touches the first range's end: 100..150 becomes 100..200.
    assert_eq!(o.insert(150, &bytes(150, 50)), Some(50));
    assert_eq!(o.ranges(), 2);
    // Bridges both: 100..200 and 300..400 with 200..300 in between.
    assert_eq!(o.insert(200, &bytes(200, 100)), Some(100));
    assert_eq!(o.ranges(), 1);
    assert_eq!(o.bytes(), 300);
    assert_eq!(o.take_front(100).unwrap(), bytes(100, 300));
    assert_eq!(o.bytes(), 0);
    assert!(o.take_front(400).is_none());
}

#[test]
fn duplicates_and_overlaps_add_only_new_bytes() {
    let mut o = Ooo::default();
    assert_eq!(o.insert(100, &bytes(100, 100)), Some(100));
    assert_eq!(o.insert(100, &bytes(100, 100)), Some(0));
    assert_eq!(o.insert(120, &bytes(120, 20)), Some(0));
    assert_eq!(o.insert(150, &bytes(150, 100)), Some(50));
    assert_eq!(o.bytes(), 150);
    assert_eq!(o.ranges(), 1);
}

#[test]
fn take_front_skips_what_rcv_nxt_has_passed() {
    let mut o = Ooo::default();
    o.insert(100, &bytes(100, 100));
    o.insert(300, &bytes(300, 10));
    // A longer retransmission advanced rcv_nxt into the first range.
    assert_eq!(o.take_front(150).unwrap(), bytes(150, 50));
    // Not reachable yet.
    assert!(o.take_front(200).is_none());
    assert_eq!(o.bytes(), 10);
    // Entirely below rcv_nxt: dropped, the next one is returned.
    o.insert(250, &bytes(250, 10));
    assert_eq!(o.take_front(300).unwrap(), bytes(300, 10));
    assert_eq!(o.bytes(), 0);
}

#[test]
fn the_range_list_is_bounded() {
    let mut o = Ooo::default();
    for i in 0..MAX_RANGES as u32 {
        assert!(o.insert(1000 + i * 20, &bytes(0, 10)).is_some());
    }
    assert_eq!(o.insert(5000, &bytes(0, 10)), None);
    // A segment that merges into an existing range still fits.
    assert!(o.insert(1010, &bytes(0, 10)).is_some());
}

#[test]
fn works_across_the_sequence_wrap() {
    let mut o = Ooo::default();
    let a = u32::MAX - 49;
    o.insert(a, &bytes(a, 100));
    o.insert(a.wrapping_add(200), &bytes(0, 10));
    assert_eq!(o.ranges(), 2);
    assert_eq!(o.take_front(a).unwrap().len(), 100);
}

#[test]
fn sack_blocks_put_the_latest_range_first() {
    let mut o = Ooo::default();
    o.insert(100, &bytes(0, 10));
    o.insert(200, &bytes(0, 10));
    o.insert(300, &bytes(0, 10));
    o.insert(400, &bytes(0, 10));
    o.insert(210, &bytes(0, 10));
    let (b, n) = o.blocks();
    assert_eq!(n, 3);
    assert_eq!(b[0], (200, 220));
    assert_eq!(b[1], (100, 110));
    assert_eq!(b[2], (300, 310));
}
