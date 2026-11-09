//! The table of established connections per source address (NOW-14, ADR-280)
//! under arbitrary sequences of operations, against a model. Byte 0..4 pick
//! the capacity (one to eight buckets), the limit (1 to 8) and the hash key;
//! every following byte is an operation: the low two bits say SYN check, open
//! or close, the rest picks one of 24 addresses (IPv4 and IPv6 /64 keys
//! alike). The table must agree with the model on every verdict of a SYN
//! check and every refusal, never count a connection it let through
//! untracked, never forget a live address, and be empty again when every
//! counted connection was closed.
#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use urmqtt_net::source_limit::{Open, SourceKey, SourceTable};

fn key(i: u8) -> SourceKey {
    if i % 3 == 0 {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[7] = i;
        // The low half differs; the key must ignore it.
        a[15] = i.wrapping_mul(7);
        SourceKey::v6(a)
    } else {
        SourceKey::v4([10, 0, i / 8, i])
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((head, ops)) = data.split_at_checked(4) else {
        return;
    };
    let capacity = (usize::from(head[0] % 8) + 1) * 8;
    let max = u32::from(head[1] % 8) + 1;
    let seed = u64::from(u16::from_le_bytes([head[2], head[3]]));
    let mut t = SourceTable::new(capacity, seed, max);
    // What the model believes is counted, and which connections the table let
    // through untracked (those must never be closed).
    let mut counted: HashMap<u8, u32> = HashMap::new();
    let mut untracked: HashMap<u8, u32> = HashMap::new();
    for &op in ops.iter().take(4096) {
        let who = (op >> 2) % 24;
        let k = key(who);
        let n = counted.get(&who).copied().unwrap_or(0);
        match op & 3 {
            0 => {
                // A SYN: never changes anything, and an address at the limit
                // is the only one refused.
                assert_eq!(t.syn_ok(k), t.connections(k) < max);
                if n >= max {
                    assert!(!t.syn_ok(k));
                }
            }
            1 | 2 => match t.open(k) {
                Open::Counted => {
                    assert!(n < max, "counted over the limit");
                    *counted.entry(who).or_default() += 1;
                }
                Open::TooMany => assert!(n >= max, "refused under the limit"),
                Open::Untracked => {
                    // Only with no slot: the address holds nothing counted.
                    assert_eq!(n, 0);
                    *untracked.entry(who).or_default() += 1;
                }
            },
            _ => {
                if n > 0 {
                    t.close(k);
                    *counted.entry(who).or_default() -= 1;
                }
            }
        }
        // Different `who` can share a key only for IPv6 /64 equals, which the
        // key function above never produces.
        assert_eq!(t.connections(k), counted.get(&who).copied().unwrap_or(0));
    }
    let live: u64 = counted.values().map(|&n| u64::from(n)).sum();
    assert_eq!(t.stats().established, live);
    for (who, n) in counted {
        for _ in 0..n {
            t.close(key(who));
        }
    }
    let s = t.stats();
    assert_eq!((s.established, s.addresses), (0, 0));
});
