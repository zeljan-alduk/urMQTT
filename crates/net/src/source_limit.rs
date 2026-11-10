//! The table of established connections per source address (NOW-14, ADR-280).
//!
//! `limits.max_connections_per_ip` bounds how many TLS connections one source
//! address may hold *established* (from the final ACK to the close). It is the
//! second half of a pair: [`crate::admission`] bounds the handshakes of an
//! address that are still in flight, this table bounds what it keeps after
//! them. The two compose in one order (the kernel's `MqttService`):
//!
//! 1. **SYN** ([`SourceTable::syn_ok`], read-only): over this limit, the SYN
//!    gets no answer. No state, no packet, no token, no crypto.
//! 2. **Final ACK** ([`SourceTable::open`]): the connection is counted here
//!    first (a refusal burns no handshake token), then admission counts it
//!    in flight; if admission refuses, the count is given back
//!    ([`SourceTable::close`]).
//! 3. **Close**: every path that forgets a connection (peer close, reset,
//!    TCP timeout, handshake timeout, watchdog abort) ends in one function
//!    that calls [`SourceTable::close`] once.
//!
//! One table serves all cores (the kernel wraps it in a spin lock): a client's
//! connections spread over the cores by the hash of the 4-tuple, so a limit
//! each core kept for itself would be `cores` times the limit.
//!
//! The table is a fixed set of buckets of eight slots, indexed by a hash of the
//! key under a per-boot random key, so an attacker who picks source addresses
//! cannot aim them at one bucket. A slot is entered only by a connection that
//! reached the final ACK (never by a SYN, so a flood of spoofed SYNs leaves no
//! trace), and freed when its count reaches 0. A slot with a live connection is
//! never evicted. If a bucket is full, the new connection is let through
//! *untracked* ([`Open::Untracked`], counted): refusing it would turn a hash
//! collision into an outage for a legitimate device, and an address that
//! already has a slot cannot lose it, so the address the limit is meant for is
//! always counted.

use alloc::vec;
use alloc::vec::Vec;

/// Slots per bucket.
const WAYS: usize = 8;

/// The identity the limit counts: one IPv4 address, or (NEXT-1) the /64
/// prefix of an IPv6 address, since one subscriber holds a whole /64. Both
/// fit 128 bits without overlap: an IPv4 address is `::ffff:a.b.c.d`
/// (the high 64 bits are 0 and the low 32 bits are the address behind
/// `0xffff`), an IPv6 prefix has its /64 in the high half and 0 in the low.
/// The only value both could take, 0, is not a valid key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceKey {
    hi: u64,
    lo: u64,
}

impl SourceKey {
    /// The key of an IPv4 source address.
    pub const fn v4(ip: [u8; 4]) -> Self {
        Self {
            hi: 0,
            lo: 0xffff_0000_0000 | (u32::from_be_bytes(ip) as u64),
        }
    }

    /// The key of an IPv6 source address: its /64 prefix (ADR-332).
    pub const fn v6(ip: [u8; 16]) -> Self {
        let [a, b, c, d, e, f, g, h, ..] = ip;
        Self {
            hi: u64::from_be_bytes([a, b, c, d, e, f, g, h]),
            lo: 0,
        }
    }

    /// The key of a source address of either family: an IPv4 address, or
    /// the /64 of an IPv6 one (NEXT-1, ADR-332).
    pub const fn of(a: crate::addr::Addr) -> Self {
        match a.as_v4() {
            Some(v4) => Self::v4(v4),
            None => Self::v6(a.octets()),
        }
    }

    const fn is_none(self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    const NONE: Self = Self { hi: 0, lo: 0 };

    fn hash(self, key: u64) -> u64 {
        let a = (self.hi ^ key).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let b = (self.lo ^ a.rotate_left(29)).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        b ^ (b >> 32)
    }
}

/// The result of counting a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Open {
    /// Counted: the caller calls [`SourceTable::close`] once when it ends.
    Counted,
    /// The address already holds as many as it may.
    TooMany,
    /// The bucket is full of live addresses: let through, not counted; the
    /// caller must **not** call `close` for it.
    Untracked,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    key: SourceKey,
    conns: u32,
}

const EMPTY: Slot = Slot {
    key: SourceKey::NONE,
    conns: 0,
};

/// What the table did, for `$SYS`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections counted now.
    pub established: u64,
    /// Distinct addresses holding at least one.
    pub addresses: u32,
    /// The most one address has held at once since boot.
    pub peak: u32,
    /// Connections let through untracked (a full bucket) since boot.
    pub untracked: u64,
}

pub struct SourceTable {
    slots: Vec<Slot>,
    /// Buckets, a power of two.
    buckets: usize,
    key: u64,
    max: u32,
    stats: Stats,
}

impl SourceTable {
    /// A table for at least `capacity` addresses (rounded up to a power of
    /// two buckets of eight, at least one bucket), hashing under `key`, that
    /// lets one address hold `max` connections (`max >= 1`; 0 would refuse
    /// everything, the kernel does not build a table for "no limit").
    pub fn new(capacity: usize, key: u64, max: u32) -> Self {
        let buckets = (capacity / WAYS).max(1).next_power_of_two();
        Self {
            slots: vec![EMPTY; buckets * WAYS],
            buckets,
            key,
            max,
            stats: Stats::default(),
        }
    }

    pub fn max(&self) -> u32 {
        self.max
    }

    /// Slots in the table.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn base(&self, k: SourceKey) -> usize {
        ((k.hash(self.key) as usize) & (self.buckets - 1)) * WAYS
    }

    fn find(&self, k: SourceKey) -> Option<usize> {
        let b = self.base(k);
        self.slots
            .get(b..b + WAYS)?
            .iter()
            .position(|s| s.key == k)
            .map(|i| b + i)
    }

    /// Connections counted for `k`.
    pub fn connections(&self, k: SourceKey) -> u32 {
        self.find(k)
            .and_then(|i| self.slots.get(i))
            .map_or(0, |s| s.conns)
    }

    /// Whether a SYN from `k` may be answered. Never changes the table. An
    /// address with no slot is always allowed (the final ACK decides).
    pub fn syn_ok(&self, k: SourceKey) -> bool {
        self.connections(k) < self.max
    }

    /// A connection from `k` reached the final ACK: counts it or says why not.
    pub fn open(&mut self, k: SourceKey) -> Open {
        if k.is_none() {
            return Open::Untracked;
        }
        let max = self.max;
        let b = self.base(k);
        let Some(bucket) = self.slots.get_mut(b..b + WAYS) else {
            return Open::Untracked;
        };
        let i = match bucket.iter().position(|s| s.key == k) {
            Some(i) => i,
            None => match bucket.iter().position(|s| s.key.is_none()) {
                Some(i) => i,
                None => {
                    self.stats.untracked += 1;
                    return Open::Untracked;
                }
            },
        };
        let Some(s) = bucket.get_mut(i) else {
            return Open::Untracked;
        };
        if s.conns >= max {
            return Open::TooMany;
        }
        if s.conns == 0 {
            s.key = k;
            self.stats.addresses += 1;
        }
        s.conns += 1;
        self.stats.established += 1;
        self.stats.peak = self.stats.peak.max(s.conns);
        Open::Counted
    }

    /// A counted connection from `k` ended. Call once per [`Open::Counted`].
    pub fn close(&mut self, k: SourceKey) {
        let Some(i) = self.find(k) else {
            return;
        };
        let Some(s) = self.slots.get_mut(i) else {
            return;
        };
        if s.conns == 0 {
            return;
        }
        s.conns -= 1;
        self.stats.established = self.stats.established.saturating_sub(1);
        if s.conns == 0 {
            *s = EMPTY;
            self.stats.addresses = self.stats.addresses.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    fn t(max: u32) -> SourceTable {
        SourceTable::new(64, 0x1234_5678_9abc_def0, max)
    }

    #[test]
    fn many_connections_from_one_address_stop_at_the_bound() {
        let mut t = t(100);
        let a = SourceKey::v4(A);
        for i in 0..100 {
            assert!(t.syn_ok(a), "SYN {i}");
            assert_eq!(t.open(a), Open::Counted, "ACK {i}");
        }
        assert!(!t.syn_ok(a));
        assert_eq!(t.open(a), Open::TooMany);
        assert_eq!(t.connections(a), 100);
        // Another address is not affected.
        let b = SourceKey::v4(B);
        assert!(t.syn_ok(b));
        assert_eq!(t.open(b), Open::Counted);
        let s = t.stats();
        assert_eq!((s.established, s.addresses, s.peak), (101, 2, 100));
        // One close frees exactly one place.
        t.close(a);
        assert!(t.syn_ok(a));
        assert_eq!(t.open(a), Open::Counted);
        assert_eq!(t.open(a), Open::TooMany);
    }

    #[test]
    fn closing_everything_frees_the_slots() {
        let mut t = t(3);
        let ips: Vec<_> = (0..40u8).map(|i| SourceKey::v4([10, 0, 1, i])).collect();
        for k in &ips {
            for _ in 0..3 {
                assert_eq!(t.open(*k), Open::Counted);
            }
            assert_eq!(t.open(*k), Open::TooMany);
        }
        assert_eq!(t.stats().established, 120);
        for k in &ips {
            for _ in 0..3 {
                t.close(*k);
            }
        }
        let s = t.stats();
        assert_eq!((s.established, s.addresses), (0, 0));
        assert!(t.slots.iter().all(|s| s.conns == 0 && s.key.is_none()));
        // A close nobody counted changes nothing (never underflows).
        t.close(ips[0]);
        assert_eq!(t.stats().established, 0);
    }

    #[test]
    fn the_syn_check_never_changes_the_table() {
        let t = t(1);
        for i in 0..=255u8 {
            assert!(t.syn_ok(SourceKey::v4([192, 168, 0, i])));
        }
        assert_eq!(t.stats(), Stats::default());
        assert!(t.slots.iter().all(|s| s.key.is_none()));
    }

    #[test]
    fn a_full_bucket_lets_a_new_address_through_untracked_never_an_old_one() {
        // One bucket of eight slots: nine addresses cannot all fit.
        let mut t = SourceTable::new(8, 7, 2);
        assert_eq!(t.capacity(), 8);
        let mut tracked = Vec::new();
        for i in 0..8u8 {
            let k = SourceKey::v4([10, 1, 0, i]);
            assert_eq!(t.open(k), Open::Counted);
            tracked.push(k);
        }
        let ninth = SourceKey::v4([10, 1, 0, 99]);
        assert_eq!(t.open(ninth), Open::Untracked);
        assert_eq!(t.stats().untracked, 1);
        assert_eq!(t.connections(ninth), 0);
        // The addresses with slots are still limited: the one that matters
        // cannot be pushed out by newcomers.
        for k in &tracked {
            assert_eq!(t.open(*k), Open::Counted);
            assert_eq!(t.open(*k), Open::TooMany);
        }
        // Closing an untracked connection is a no-op for the tracked ones.
        t.close(ninth);
        assert_eq!(t.stats().established, 16);
        // A freed slot is reused.
        t.close(tracked[0]);
        t.close(tracked[0]);
        assert_eq!(t.open(ninth), Open::Counted);
    }

    #[test]
    fn the_zero_key_is_never_stored() {
        let mut t = t(5);
        assert_eq!(t.open(SourceKey::NONE), Open::Untracked);
        assert_eq!(t.stats().established, 0);
        // 0.0.0.0 is a valid IPv4 key (::ffff:0.0.0.0), not the zero key.
        assert_ne!(SourceKey::v4([0; 4]), SourceKey::NONE);
        assert_eq!(t.open(SourceKey::v4([0; 4])), Open::Counted);
    }

    #[test]
    fn ipv6_keys_use_the_64_bit_prefix_and_never_meet_ipv4_keys() {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]);
        let mut same_net = a;
        same_net[8..].copy_from_slice(&[9; 8]);
        let mut other = a;
        other[7] = 3;
        assert_eq!(SourceKey::v6(a), SourceKey::v6(same_net));
        assert_ne!(SourceKey::v6(a), SourceKey::v6(other));
        // No IPv4 address has the key of an IPv6 prefix.
        for ip in [[0, 0, 0, 0], [255, 255, 255, 255], [32, 1, 13, 184]] {
            assert_ne!(SourceKey::v4(ip), SourceKey::v6(a));
        }
        let mut t = t(2);
        assert_eq!(t.open(SourceKey::v6(a)), Open::Counted);
        assert_eq!(t.open(SourceKey::v6(same_net)), Open::Counted);
        assert_eq!(t.open(SourceKey::v6(a)), Open::TooMany);
        assert_eq!(t.open(SourceKey::v6(other)), Open::Counted);
    }

    /// The table against a plain map, over a random sequence of opens and
    /// closes of a few addresses: same counts, same refusals.
    #[test]
    fn agrees_with_a_model() {
        let mut t = SourceTable::new(256, 99, 5);
        let mut model: std::collections::HashMap<u8, u32> = Default::default();
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let ip = (x % 9) as u8;
            let k = SourceKey::v4([10, 0, 0, ip]);
            let n = model.entry(ip).or_default();
            if (x >> 20) % 3 == 0 {
                if *n > 0 {
                    *n -= 1;
                    t.close(k);
                }
            } else {
                let want = if *n >= 5 {
                    Open::TooMany
                } else {
                    Open::Counted
                };
                assert_eq!(t.syn_ok(k), *n < 5);
                assert_eq!(t.open(k), want);
                if want == Open::Counted {
                    *n += 1;
                }
            }
            assert_eq!(t.connections(k), *n);
        }
        let total: u32 = model.values().sum();
        assert_eq!(t.stats().established, u64::from(total));
        assert_eq!(
            t.stats().addresses as usize,
            model.values().filter(|n| **n > 0).count()
        );
    }

    /// The case the roadmap names: thousands of connections from one address.
    #[test]
    fn thousands_from_one_address() {
        let mut t = SourceTable::new(1024, 5, 1024);
        let a = SourceKey::v4(A);
        let mut ok = 0;
        let mut refused = 0;
        for _ in 0..5000 {
            match t.open(a) {
                Open::Counted => ok += 1,
                Open::TooMany => refused += 1,
                Open::Untracked => panic!("untracked"),
            }
        }
        assert_eq!((ok, refused), (1024, 5000 - 1024));
        assert_eq!(t.stats().peak, 1024);
    }
}
