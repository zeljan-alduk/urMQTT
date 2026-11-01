//! The table of source addresses of the plaintext listener: for each address
//! that holds a connection or failed a login lately, how many connections it
//! holds, how many logins it failed in the current window and until when it is
//! locked out.
//!
//! One table serves all cores (the kernel wraps it in a spin lock), because a
//! client's connections spread over the cores by the hash of the 4-tuple and a
//! lock-out that only one core knew would be a lock-out in name only.
//!
//! The table is a fixed set of buckets of eight slots, indexed by a hash of the
//! address under a per-boot random key (so an attacker who chooses source
//! addresses cannot aim them at one bucket). An address is **only** entered
//! when it opens a connection that passed the allow-list or fails a login, never
//! for a SYN: a flood of SYNs from refused or unknown sources leaves no trace
//! here. A slot is freed as soon as it holds nothing worth keeping, and a full
//! bucket makes room by dropping a slot that holds nothing but an old, expired
//! failure count; a slot with a live connection or an active lock-out is never
//! dropped.

use alloc::vec;
use alloc::vec::Vec;

/// Slots per bucket.
const WAYS: usize = 8;

/// The limits (from the configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections one address may hold at once.
    pub max_per_ip: u32,
    /// Failed logins within `lockout_s` that lock an address out.
    pub max_failures: u32,
    /// How long a locked-out address gets no answer; also the window in which
    /// failures are counted.
    pub lockout_s: u32,
}

/// What a SYN from an address meets (read-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syn {
    Allow,
    /// Locked out: no answer.
    LockedOut,
    /// It already holds as many connections as it may.
    TooMany,
}

/// The result of opening a connection from an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Open {
    Ok,
    LockedOut,
    TooMany,
    /// No slot could be had (all eight of its bucket hold live connections or
    /// lock-outs): the connection is refused rather than left untracked.
    Full,
}

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    /// 0: free (0.0.0.0 is never a peer).
    ip: u32,
    conns: u16,
    fails: u16,
    /// Start of the current failure window, seconds.
    window_start: u32,
    /// Locked out while `now < locked_until`, seconds.
    locked_until: u32,
}

impl Slot {
    /// Holds nothing that matters at `now`: no connection, no lock-out and no
    /// failure still inside its window.
    fn idle(&self, now: u32, window: u32) -> bool {
        self.conns == 0
            && self.locked_until <= now
            && (self.fails == 0 || self.window_start.saturating_add(window) <= now)
    }
}

pub struct Sources {
    slots: Vec<Slot>,
    /// A power of two.
    buckets: usize,
    key: u64,
    limits: Limits,
}

impl Sources {
    /// A table for about `capacity` addresses (rounded up to a power of two of
    /// buckets, at least 8 buckets). `key` is random per boot.
    pub fn new(capacity: usize, key: u64, limits: Limits) -> Self {
        let buckets = capacity.div_ceil(WAYS).max(8).next_power_of_two();
        Self {
            slots: vec![Slot::default(); buckets * WAYS],
            buckets,
            key,
            limits,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Slots in the table.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Slots in use (O(n); for tests and statistics).
    pub fn used(&self) -> usize {
        self.slots.iter().filter(|s| s.ip != 0).count()
    }

    fn base(&self, ip: u32) -> usize {
        let h = (u64::from(ip) ^ self.key).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        ((h >> 32) as usize & (self.buckets - 1)) * WAYS
    }

    fn bucket(&self, ip: u32) -> &[Slot] {
        let b = self.base(ip);
        self.slots.get(b..b + WAYS).unwrap_or(&[])
    }

    fn find(&self, ip: u32) -> Option<usize> {
        let b = self.base(ip);
        self.bucket(ip)
            .iter()
            .position(|s| s.ip == ip)
            .map(|i| b + i)
    }

    /// The slot of `ip`, made if there is room: a free slot, else an idle one.
    fn find_or_make(&mut self, ip: u32, now: u32) -> Option<usize> {
        if let Some(i) = self.find(ip) {
            return Some(i);
        }
        let window = self.limits.lockout_s;
        let b = self.base(ip);
        let pick = {
            let bucket = self.bucket(ip);
            bucket
                .iter()
                .position(|s| s.ip == 0)
                // The idle slot with the oldest failure window goes first.
                .or_else(|| {
                    bucket
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.idle(now, window))
                        .min_by_key(|(_, s)| s.window_start)
                        .map(|(i, _)| i)
                })
        }?;
        let slot = self.slots.get_mut(b + pick)?;
        *slot = Slot {
            ip,
            ..Slot::default()
        };
        Some(b + pick)
    }

    /// What a SYN from `ip` meets. Never changes the table.
    pub fn syn(&self, ip: [u8; 4], now: u32) -> Syn {
        let ip = u32::from_be_bytes(ip);
        match self.find(ip).and_then(|i| self.slots.get(i)) {
            Some(s) if s.locked_until > now => Syn::LockedOut,
            Some(s) if u32::from(s.conns) >= self.limits.max_per_ip => Syn::TooMany,
            _ => Syn::Allow,
        }
    }

    /// A connection from `ip` was accepted: counts it, or says why not.
    pub fn open(&mut self, ip: [u8; 4], now: u32) -> Open {
        let ip = u32::from_be_bytes(ip);
        if ip == 0 {
            return Open::Full;
        }
        let max = self.limits.max_per_ip;
        let Some(i) = self.find_or_make(ip, now) else {
            return Open::Full;
        };
        let Some(s) = self.slots.get_mut(i) else {
            return Open::Full;
        };
        if s.locked_until > now {
            return Open::LockedOut;
        }
        if u32::from(s.conns) >= max {
            return Open::TooMany;
        }
        s.conns = s.conns.saturating_add(1);
        Open::Ok
    }

    /// A counted connection from `ip` ended.
    pub fn close(&mut self, ip: [u8; 4], now: u32) {
        let ip = u32::from_be_bytes(ip);
        let window = self.limits.lockout_s;
        if let Some(i) = self.find(ip)
            && let Some(s) = self.slots.get_mut(i)
        {
            s.conns = s.conns.saturating_sub(1);
            if s.idle(now, window) {
                *s = Slot::default();
            }
        }
    }

    /// `ip` failed a login. Returns true if this one locked it out.
    pub fn failed(&mut self, ip: [u8; 4], now: u32) -> bool {
        let ip = u32::from_be_bytes(ip);
        if ip == 0 {
            return false;
        }
        let Limits {
            max_failures,
            lockout_s,
            ..
        } = self.limits;
        let Some(i) = self.find_or_make(ip, now) else {
            return false;
        };
        let Some(s) = self.slots.get_mut(i) else {
            return false;
        };
        if s.fails == 0 || s.window_start.saturating_add(lockout_s) <= now {
            s.window_start = now;
            s.fails = 0;
        }
        s.fails = s.fails.saturating_add(1);
        if u32::from(s.fails) >= max_failures {
            s.locked_until = now.saturating_add(lockout_s);
            s.fails = 0;
            true
        } else {
            false
        }
    }

    /// `ip` logged in: its failure count starts again.
    pub fn succeeded(&mut self, ip: [u8; 4]) {
        let ip = u32::from_be_bytes(ip);
        if let Some(i) = self.find(ip)
            && let Some(s) = self.slots.get_mut(i)
        {
            s.fails = 0;
        }
    }

    /// Whether `ip` is locked out at `now`.
    pub fn locked_out(&self, ip: [u8; 4], now: u32) -> bool {
        self.syn(ip, now) == Syn::LockedOut
    }

    /// Connections the table counts for `ip`.
    pub fn connections(&self, ip: [u8; 4]) -> u32 {
        let ip = u32::from_be_bytes(ip);
        self.find(ip)
            .and_then(|i| self.slots.get(i))
            .map_or(0, |s| u32::from(s.conns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    fn table(per_ip: u32, fails: u32, lockout: u32) -> Sources {
        Sources::new(
            64,
            0x1234_5678,
            Limits {
                max_per_ip: per_ip,
                max_failures: fails,
                lockout_s: lockout,
            },
        )
    }

    #[test]
    fn a_syn_leaves_no_trace_and_an_unknown_address_is_allowed() {
        let t = table(2, 3, 60);
        for i in 0..1000u32 {
            let ip = [10, (i >> 8) as u8, i as u8, 7];
            assert_eq!(t.syn(ip, 5), Syn::Allow);
        }
        assert_eq!(t.used(), 0);
    }

    #[test]
    fn connections_are_counted_per_address() {
        let mut t = table(2, 3, 60);
        assert_eq!(t.open(A, 0), Open::Ok);
        assert_eq!(t.syn(A, 0), Syn::Allow);
        assert_eq!(t.open(A, 0), Open::Ok);
        assert_eq!(t.syn(A, 0), Syn::TooMany);
        assert_eq!(t.open(A, 0), Open::TooMany);
        assert_eq!(t.connections(A), 2);
        // Another address is not affected.
        assert_eq!(t.syn(B, 0), Syn::Allow);
        assert_eq!(t.open(B, 0), Open::Ok);
        t.close(A, 1);
        assert_eq!(t.syn(A, 1), Syn::Allow);
        assert_eq!(t.open(A, 1), Open::Ok);
        t.close(A, 2);
        t.close(A, 2);
        assert_eq!(t.connections(A), 0);
        // A slot with nothing to remember is given back at once.
        assert_eq!(t.used(), 1, "only B is left");
        // A spurious close never goes below zero.
        t.close(A, 3);
        t.close(B, 3);
        t.close(B, 3);
        assert_eq!(t.used(), 0);
    }

    #[test]
    fn failures_in_the_window_lock_the_address_out() {
        let mut t = table(8, 3, 100);
        assert!(!t.failed(A, 10));
        assert!(!t.failed(A, 11));
        assert_eq!(t.syn(A, 12), Syn::Allow);
        assert!(t.failed(A, 12), "the third failure locks");
        for now in [12, 50, 111] {
            assert_eq!(t.syn(A, now), Syn::LockedOut, "{now}");
            assert_eq!(t.open(A, now), Open::LockedOut, "{now}");
        }
        assert!(t.locked_out(A, 111));
        // It is over at 112 (12 + 100), and the count starts again.
        assert_eq!(t.syn(A, 112), Syn::Allow);
        assert_eq!(t.open(A, 112), Open::Ok);
        assert!(!t.failed(A, 113));
        assert!(!t.failed(A, 114));
        assert!(t.failed(A, 115));
        // Another address is untouched.
        assert_eq!(t.syn(B, 115), Syn::Allow);
    }

    #[test]
    fn old_failures_expire_and_a_login_clears_the_count() {
        let mut t = table(8, 3, 100);
        assert!(!t.failed(A, 0));
        assert!(!t.failed(A, 50));
        // The window (100 s from the first failure) ran out: this is failure 1 again.
        assert!(!t.failed(A, 100));
        assert!(!t.failed(A, 101));
        assert!(t.failed(A, 102));
        let mut t = table(8, 3, 100);
        assert!(!t.failed(A, 0));
        assert!(!t.failed(A, 1));
        t.succeeded(A);
        assert!(!t.failed(A, 2));
        assert!(!t.failed(A, 3));
        assert!(t.failed(A, 4));
    }

    #[test]
    fn one_failure_locks_when_that_is_the_limit() {
        let mut t = table(8, 1, 30);
        assert!(t.failed(A, 5));
        assert_eq!(t.syn(A, 34), Syn::LockedOut);
        assert_eq!(t.syn(A, 35), Syn::Allow);
    }

    #[test]
    fn a_lockout_does_not_end_a_live_connection_but_blocks_new_ones() {
        let mut t = table(8, 2, 60);
        assert_eq!(t.open(A, 0), Open::Ok);
        assert!(!t.failed(A, 1));
        assert!(t.failed(A, 2));
        assert_eq!(
            t.connections(A),
            1,
            "the connection that exists stays counted"
        );
        assert_eq!(t.open(A, 3), Open::LockedOut);
        t.close(A, 4);
        // The slot stays while the lock-out runs, and is free after it.
        assert_eq!(t.used(), 1);
        assert_eq!(t.syn(A, 4), Syn::LockedOut);
        assert_eq!(t.syn(A, 62), Syn::Allow);
        assert_eq!(t.open(A, 62), Open::Ok);
    }

    #[test]
    fn a_failure_count_of_many_does_not_wrap() {
        let mut t = table(8, 1000, 600);
        for i in 0..999 {
            assert!(!t.failed(A, i / 10), "{i}");
        }
        assert!(t.failed(A, 99));
        assert_eq!(t.syn(A, 100), Syn::LockedOut);
    }

    #[test]
    fn the_address_zero_is_never_tracked() {
        let mut t = table(8, 3, 60);
        assert_eq!(t.open([0; 4], 0), Open::Full);
        assert!(!t.failed([0; 4], 0));
        assert_eq!(t.used(), 0);
    }

    /// Eight live connections in one bucket leave no room for a ninth address
    /// of that bucket, and the table says so instead of losing track of it.
    #[test]
    fn a_full_bucket_refuses_rather_than_forgets() {
        let mut t = Sources::new(
            8,
            7,
            Limits {
                max_per_ip: 4,
                max_failures: 3,
                lockout_s: 60,
            },
        );
        assert_eq!(t.capacity(), 64, "at least 8 buckets");
        // Find addresses of one bucket.
        let mut same: Vec<[u8; 4]> = Vec::new();
        let target = t.base(u32::from_be_bytes([10, 0, 0, 1]));
        let mut n = 0u32;
        while same.len() < 9 {
            let ip = (10u32 << 24) + n;
            n += 1;
            if t.base(ip) == target {
                same.push(ip.to_be_bytes());
            }
        }
        for ip in same.iter().take(8) {
            assert_eq!(t.open(*ip, 0), Open::Ok);
        }
        let ninth = *same.last().unwrap();
        assert_eq!(t.open(ninth, 0), Open::Full);
        assert!(!t.failed(ninth, 0), "cannot record it either");
        // A live connection ending makes room.
        t.close(*same.first().unwrap(), 1);
        assert_eq!(t.open(ninth, 1), Open::Ok);
    }

    /// An idle slot (an old, expired failure count) is dropped to make room;
    /// a slot with a lock-out never is.
    #[test]
    fn a_full_bucket_drops_only_idle_slots() {
        let mut t = Sources::new(
            8,
            9,
            Limits {
                max_per_ip: 4,
                max_failures: 2,
                lockout_s: 60,
            },
        );
        let target = t.base(u32::from_be_bytes([10, 0, 0, 1]));
        let mut same: Vec<[u8; 4]> = Vec::new();
        let mut n = 0u32;
        while same.len() < 10 {
            let ip = (10u32 << 24) + n;
            n += 1;
            if t.base(ip) == target {
                same.push(ip.to_be_bytes());
            }
        }
        // Eight addresses with one failure each (not yet locked, window running).
        for ip in same.iter().take(8) {
            assert!(!t.failed(*ip, 0));
        }
        // While their windows run they are kept: the ninth cannot be recorded.
        assert!(!t.failed(same[8], 10));
        assert_eq!(t.used(), 8);
        // After the window the old counts are idle and make room.
        assert!(!t.failed(same[8], 61));
        assert_eq!(t.used(), 8);
        // A locked-out address is never dropped to make room.
        let mut t = Sources::new(
            8,
            9,
            Limits {
                max_per_ip: 4,
                max_failures: 1,
                lockout_s: 600,
            },
        );
        for ip in same.iter().take(8) {
            assert!(t.failed(*ip, 0));
        }
        assert!(!t.failed(same[9], 100), "no room, nothing dropped");
        for ip in same.iter().take(8) {
            assert!(t.locked_out(*ip, 100));
        }
        assert!(!t.locked_out(same[9], 100));
        // When the lock-outs end the slots are reusable again.
        assert!(t.failed(same[9], 700));
        assert!(t.locked_out(same[9], 701));
    }

    /// The table against a plain model, with room for every address (so no
    /// eviction), over random sequences of events and time.
    #[test]
    fn it_matches_a_model() {
        #[derive(Clone, Copy, Default)]
        struct M {
            conns: u32,
            fails: u32,
            window_start: u32,
            locked_until: u32,
        }
        let limits = Limits {
            max_per_ip: 3,
            max_failures: 4,
            lockout_s: 50,
        };
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as u32
        };
        for seed in 0..40u32 {
            let mut t = Sources::new(4096, u64::from(seed) * 77 + 1, limits);
            let mut m = std::collections::HashMap::<u32, M>::new();
            let mut now = 0u32;
            for _ in 0..3000 {
                now += next() % 20;
                let ip = [10, 0, 0, 1 + (next() % 6) as u8];
                let k = u32::from_be_bytes(ip);
                let e = m.entry(k).or_default();
                match next() % 6 {
                    0 | 1 => {
                        let want = if e.locked_until > now {
                            Open::LockedOut
                        } else if e.conns >= limits.max_per_ip {
                            Open::TooMany
                        } else {
                            e.conns += 1;
                            Open::Ok
                        };
                        assert_eq!(t.open(ip, now), want, "open {ip:?} at {now}");
                    }
                    2 => {
                        if e.conns > 0 {
                            e.conns -= 1;
                            t.close(ip, now);
                        }
                    }
                    3 | 4 => {
                        if e.fails == 0 || e.window_start + limits.lockout_s <= now {
                            e.window_start = now;
                            e.fails = 0;
                        }
                        e.fails += 1;
                        let locks = e.fails >= limits.max_failures;
                        if locks {
                            e.locked_until = now + limits.lockout_s;
                            e.fails = 0;
                        }
                        assert_eq!(t.failed(ip, now), locks, "failed {ip:?} at {now}");
                    }
                    _ => {
                        e.fails = 0;
                        t.succeeded(ip);
                    }
                }
                for probe in 1..=6u8 {
                    let ip = [10, 0, 0, probe];
                    let e = m.get(&u32::from_be_bytes(ip)).copied().unwrap_or_default();
                    let want = if e.locked_until > now {
                        Syn::LockedOut
                    } else if e.conns >= limits.max_per_ip {
                        Syn::TooMany
                    } else {
                        Syn::Allow
                    };
                    assert_eq!(t.syn(ip, now), want, "syn {ip:?} at {now}");
                }
            }
        }
    }
}
