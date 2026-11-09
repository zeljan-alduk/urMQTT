//! Per-core connection admission (PROMPT section 6, ADR-032, PERF ADR-080):
//! the token bucket, the in-flight handshake limits (per core and per
//! source address) and the counters that say what admission did.
//!
//! Pure logic over plain values, so it is tested on the host. The kernel
//! supplies the clock and the two facts only it knows (is there heap
//! left, is the DB core behind) and calls
//!
//! - [`Admission::syn_check`] for every SYN, *before* a SYN-ACK is sent: a
//!   refusal here costs no state and no packet, and the client's own TCP
//!   retransmits after its backoff;
//! - [`Admission::admit`] at the final ACK, which also takes a handshake
//!   token and counts the connection as in flight;
//! - [`Admission::leave`] exactly once when that connection is no longer in
//!   flight (handshake done, closed, or timed out).
//!
//! Every operation is O(1) except the per-address lookup, which scans the
//! distinct addresses in flight (at most the per-core limit).

use alloc::vec::Vec;

/// Why a connection was (or would be) refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No handshake token (`limits.handshakes_per_core_per_sec`).
    Rate = 0,
    /// `limits.max_handshakes_in_flight_per_core` reached.
    InFlight = 1,
    /// Free heap below the reserve.
    Memory = 2,
    /// The DB core is behind.
    Storage = 3,
    /// `limits.max_handshakes_in_flight_per_ip` reached for the address.
    PerIp = 4,
    /// `limits.max_connections_per_ip` established connections reached for
    /// the address (NOW-14, ADR-280). Decided by the kernel against the
    /// shared [`crate::source_limit::SourceTable`], counted here per core.
    PerIpEstablished = 5,
}

/// How many [`Reason`]s there are (the length of the counter arrays).
pub const REASONS: usize = 6;

impl Reason {
    pub const ALL: [Reason; REASONS] = [
        Self::Rate,
        Self::InFlight,
        Self::Memory,
        Self::Storage,
        Self::PerIp,
        Self::PerIpEstablished,
    ];

    /// For log lines.
    pub const fn text(self) -> &'static str {
        match self {
            Self::Rate => "handshake rate limit",
            Self::InFlight => "too many handshakes in flight",
            Self::Memory => "heap below the free reserve",
            Self::Storage => "the DB core is behind",
            Self::PerIp => "too many handshakes in flight from one address",
            Self::PerIpEstablished => "too many established connections from one address",
        }
    }

    /// For metric names.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rate => "rate",
            Self::InFlight => "in_flight",
            Self::Memory => "memory",
            Self::Storage => "storage",
            Self::PerIp => "per_ip",
            Self::PerIpEstablished => "per_ip_established",
        }
    }
}

/// How a connection that was in flight stopped being so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The handshake completed (or, on a plaintext port, the CONNECT came)
    /// after this many milliseconds.
    Done { latency_ms: u32 },
    /// It ended before: reset, TLS error, refused after the handshake.
    Failed,
    /// It did not finish within the handshake timeout.
    TimedOut,
}

/// The limits, from the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_core: u32,
    pub per_ip: u32,
    pub rate_per_sec: u32,
}

/// Upper bounds of the latency buckets, milliseconds; one more bucket
/// holds everything above the last.
pub const LATENCY_BOUNDS_MS: [u32; 5] = [25, 50, 100, 250, 1000];

/// What admission did, since boot (counters) or since the last
/// [`Admission::take_window`] (the `window_*` maxima).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections admitted.
    pub started: u64,
    /// Handshakes completed.
    pub done: u64,
    /// Ended before completing (reset, error, refused after the handshake).
    pub failed: u64,
    /// Not finished within the timeout.
    pub timed_out: u64,
    /// Refused at the final ACK, by [`Reason`].
    pub refused: [u64; REASONS],
    /// SYNs dropped without a SYN-ACK, by [`Reason`].
    pub syn_dropped: [u64; REASONS],
    /// Sum of the latencies of completed handshakes (accept to done), ms.
    pub latency_sum_ms: u64,
    /// Completed handshakes per latency bucket ([`LATENCY_BOUNDS_MS`]).
    pub latency_buckets: [u64; 6],
    /// Largest latency of a completed handshake in the window, ms.
    pub window_latency_max_ms: u32,
    /// Most connections in flight at once in the window.
    pub window_in_flight_max: u32,
}

impl Stats {
    /// Everything refused at the final ACK.
    pub fn refused_total(&self) -> u64 {
        self.refused.iter().sum()
    }

    /// Everything dropped at the SYN.
    pub fn syn_dropped_total(&self) -> u64 {
        self.syn_dropped.iter().sum()
    }

    /// Completed handshakes slower than `LATENCY_BOUNDS_MS[from]`.
    pub fn slower_than(&self, from: usize) -> u64 {
        self.latency_buckets.iter().skip(from + 1).sum()
    }
}

pub struct Admission {
    limits: Limits,
    tokens: u32,
    last_ms: u64,
    in_flight: u32,
    /// (address, connections in flight from it), distinct addresses only.
    ips: Vec<(u32, u32)>,
    stats: Stats,
}

impl Admission {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            tokens: limits.rate_per_sec,
            last_ms: 0,
            in_flight: 0,
            ips: Vec::new(),
            stats: Stats::default(),
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Connections admitted and not yet [`leave`](Self::leave)d.
    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Of those, the ones from `ip`.
    pub fn from_ip(&self, ip: [u8; 4]) -> u32 {
        let ip = u32::from_be_bytes(ip);
        self.ips
            .iter()
            .find(|(a, _)| *a == ip)
            .map_or(0, |(_, n)| *n)
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The counters, with the window maxima reset to the present state.
    pub fn take_window(&mut self) -> Stats {
        let s = self.stats;
        self.stats.window_latency_max_ms = 0;
        self.stats.window_in_flight_max = self.in_flight;
        s
    }

    fn refill(&mut self, now_ms: u64) {
        let rate = self.limits.rate_per_sec;
        let elapsed = now_ms.saturating_sub(self.last_ms);
        let refill = (elapsed * u64::from(rate) / 1000).min(u64::from(u32::MAX)) as u32;
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(rate);
            self.last_ms = now_ms;
        }
    }

    /// What would refuse a connection from `ip` now, without counting
    /// anything. `tls`: a handshake token is needed (the plaintext dev port
    /// has none).
    fn verdict(
        &mut self,
        ip: [u8; 4],
        tls: bool,
        now_ms: u64,
        heap_ok: bool,
        db_behind: bool,
    ) -> Option<Reason> {
        if !heap_ok {
            Some(Reason::Memory)
        } else if db_behind {
            Some(Reason::Storage)
        } else if self.in_flight >= self.limits.per_core {
            Some(Reason::InFlight)
        } else if self.from_ip(ip) >= self.limits.per_ip {
            Some(Reason::PerIp)
        } else if tls {
            self.refill(now_ms);
            (self.tokens == 0).then_some(Reason::Rate)
        } else {
            None
        }
    }

    /// A SYN dropped for `r` by a check that lives outside this struct (the
    /// established-connections table, ADR-280): counted with the others.
    pub fn count_syn_dropped(&mut self, r: Reason) {
        bump(&mut self.stats.syn_dropped, r);
    }

    /// A connection refused at the final ACK for `r` by a check that lives
    /// outside this struct: counted with the others.
    pub fn count_refused(&mut self, r: Reason) {
        bump(&mut self.stats.refused, r);
    }

    /// A SYN from `ip`: whether to answer it. A refusal is counted as a
    /// dropped SYN; nothing else changes (no token is taken).
    pub fn syn_check(
        &mut self,
        ip: [u8; 4],
        tls: bool,
        now_ms: u64,
        heap_ok: bool,
        db_behind: bool,
    ) -> Result<(), Reason> {
        match self.verdict(ip, tls, now_ms, heap_ok, db_behind) {
            None => Ok(()),
            Some(r) => {
                bump(&mut self.stats.syn_dropped, r);
                Err(r)
            }
        }
    }

    /// The final ACK from `ip`: admits the connection (it is in flight until
    /// [`leave`](Self::leave)) or says why not.
    pub fn admit(
        &mut self,
        ip: [u8; 4],
        tls: bool,
        now_ms: u64,
        heap_ok: bool,
        db_behind: bool,
    ) -> Result<(), Reason> {
        if let Some(r) = self.verdict(ip, tls, now_ms, heap_ok, db_behind) {
            bump(&mut self.stats.refused, r);
            return Err(r);
        }
        if tls {
            self.tokens -= 1;
        }
        self.in_flight += 1;
        let a = u32::from_be_bytes(ip);
        match self.ips.iter_mut().find(|(x, _)| *x == a) {
            Some((_, n)) => *n += 1,
            None => self.ips.push((a, 1)),
        }
        self.stats.started += 1;
        self.stats.window_in_flight_max = self.stats.window_in_flight_max.max(self.in_flight);
        Ok(())
    }

    /// An admitted connection from `ip` is no longer in flight. Call once
    /// per admitted connection; a second call for the same one would free a
    /// slot it does not hold, so the caller keeps a flag.
    pub fn leave(&mut self, ip: [u8; 4], how: Outcome) {
        self.in_flight = self.in_flight.saturating_sub(1);
        let a = u32::from_be_bytes(ip);
        if let Some(i) = self.ips.iter().position(|(x, _)| *x == a)
            && let Some((_, n)) = self.ips.get_mut(i)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.ips.swap_remove(i);
            }
        }
        match how {
            Outcome::Done { latency_ms } => {
                self.stats.done += 1;
                self.stats.latency_sum_ms += u64::from(latency_ms);
                let b = LATENCY_BOUNDS_MS
                    .iter()
                    .position(|&bound| latency_ms <= bound)
                    .unwrap_or(LATENCY_BOUNDS_MS.len());
                if let Some(n) = self.stats.latency_buckets.get_mut(b) {
                    *n += 1;
                }
                self.stats.window_latency_max_ms = self.stats.window_latency_max_ms.max(latency_ms);
            }
            Outcome::Failed => self.stats.failed += 1,
            Outcome::TimedOut => self.stats.timed_out += 1,
        }
    }
}

fn bump(counts: &mut [u64; REASONS], r: Reason) {
    if let Some(n) = counts.get_mut(r as usize) {
        *n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    fn adm(per_core: u32, per_ip: u32, rate: u32) -> Admission {
        Admission::new(Limits {
            per_core,
            per_ip,
            rate_per_sec: rate,
        })
    }

    #[test]
    fn per_ip_limit_counts_only_that_address() {
        let mut a = adm(100, 3, 1000);
        for _ in 0..3 {
            assert!(a.admit(A, true, 0, true, false).is_ok());
        }
        assert_eq!(a.admit(A, true, 0, true, false), Err(Reason::PerIp));
        assert!(a.admit(B, true, 0, true, false).is_ok());
        assert_eq!((a.in_flight(), a.from_ip(A), a.from_ip(B)), (4, 3, 1));
        a.leave(A, Outcome::Done { latency_ms: 10 });
        assert!(a.admit(A, true, 0, true, false).is_ok());
        assert_eq!(a.stats().refused[Reason::PerIp as usize], 1);
    }

    /// ADR-280: the established-connections limit lives in the kernel's shared
    /// table, but its refusals are counted per core with the others, under
    /// their own reason, and never change in-flight state.
    #[test]
    fn established_per_address_refusals_are_counted_under_their_own_reason() {
        let mut a = adm(10, 10, 10);
        a.count_syn_dropped(Reason::PerIpEstablished);
        a.count_syn_dropped(Reason::PerIpEstablished);
        a.count_refused(Reason::PerIpEstablished);
        let s = a.stats();
        let i = Reason::PerIpEstablished as usize;
        assert_eq!((s.syn_dropped[i], s.refused[i]), (2, 1));
        assert_eq!((s.syn_dropped_total(), s.refused_total()), (2, 1));
        // The in-flight per-address reason is a different counter.
        assert_eq!(s.refused[Reason::PerIp as usize], 0);
        assert_eq!((a.in_flight(), s.started), (0, 0));
        assert_eq!(Reason::ALL.len(), REASONS);
        assert_eq!(Reason::PerIpEstablished.name(), "per_ip_established");
        // Names are unique (they are metric names).
        for x in Reason::ALL {
            assert_eq!(
                Reason::ALL.iter().filter(|y| y.name() == x.name()).count(),
                1
            );
            assert_eq!(Reason::ALL.get(x as usize), Some(&x));
        }
    }

    #[test]
    fn per_core_limit_and_leaving_frees_slots() {
        let mut a = adm(2, 10, 1000);
        assert!(a.admit(A, true, 0, true, false).is_ok());
        assert!(a.admit(B, true, 0, true, false).is_ok());
        assert_eq!(
            a.admit([1, 1, 1, 1], true, 0, true, false),
            Err(Reason::InFlight)
        );
        a.leave(B, Outcome::Failed);
        assert_eq!(a.in_flight(), 1);
        assert!(a.admit([1, 1, 1, 1], true, 0, true, false).is_ok());
        let s = a.stats();
        assert_eq!((s.started, s.failed, s.refused_total()), (3, 1, 1));
    }

    #[test]
    fn syn_check_does_not_take_tokens_or_slots() {
        let mut a = adm(10, 10, 2);
        for _ in 0..50 {
            assert!(a.syn_check(A, true, 0, true, false).is_ok());
        }
        assert_eq!(a.in_flight(), 0);
        // Both tokens are still there.
        assert!(a.admit(A, true, 0, true, false).is_ok());
        assert!(a.admit(A, true, 0, true, false).is_ok());
        assert_eq!(a.admit(A, true, 0, true, false), Err(Reason::Rate));
        // Now the SYN gate closes too, and counts what it drops.
        assert_eq!(a.syn_check(A, true, 0, true, false), Err(Reason::Rate));
        assert_eq!(a.stats().syn_dropped[Reason::Rate as usize], 1);
        assert_eq!(a.stats().syn_dropped_total(), 1);
    }

    #[test]
    fn token_bucket_refills_with_time_and_is_capped() {
        let mut a = adm(100, 100, 10);
        for _ in 0..10 {
            assert!(a.admit(A, true, 0, true, false).is_ok());
        }
        assert_eq!(a.admit(A, true, 0, true, false), Err(Reason::Rate));
        // 50 ms is half a token: not yet; 100 ms is one.
        assert_eq!(a.admit(A, true, 50, true, false), Err(Reason::Rate));
        assert!(a.admit(A, true, 100, true, false).is_ok());
        // A long pause refills to the rate, not beyond.
        a.refill(1_000_000);
        assert_eq!(a.tokens, 10);
    }

    #[test]
    fn plaintext_port_takes_no_token() {
        let mut a = adm(100, 100, 1);
        for _ in 0..5 {
            assert!(a.admit(A, false, 0, true, false).is_ok());
        }
    }

    #[test]
    fn memory_and_storage_refusals_come_first() {
        let mut a = adm(1, 1, 1);
        assert_eq!(a.admit(A, true, 0, false, false), Err(Reason::Memory));
        assert_eq!(a.admit(A, true, 0, true, true), Err(Reason::Storage));
        assert_eq!(a.in_flight(), 0);
        assert_eq!(a.stats().refused_total(), 2);
    }

    #[test]
    fn latency_statistics_and_window() {
        let mut a = adm(100, 100, 1000);
        for ms in [10, 40, 90, 200, 900, 5000] {
            assert!(a.admit(A, true, 0, true, false).is_ok());
            a.leave(A, Outcome::Done { latency_ms: ms });
        }
        let s = a.take_window();
        assert_eq!(s.done, 6);
        assert_eq!(s.latency_sum_ms, 10 + 40 + 90 + 200 + 900 + 5000);
        assert_eq!(s.latency_buckets, [1, 1, 1, 1, 1, 1]);
        assert_eq!(s.window_latency_max_ms, 5000);
        assert_eq!(s.slower_than(3), 2);
        // The window restarts; counters do not.
        let t = a.take_window();
        assert_eq!((t.window_latency_max_ms, t.done), (0, 6));
        assert_eq!(a.admit(A, true, 0, true, false), Ok(()));
        assert_eq!(a.take_window().window_in_flight_max, 1);
    }

    #[test]
    fn timeouts_and_double_leave_do_not_underflow() {
        let mut a = adm(10, 10, 1000);
        assert!(a.admit(A, true, 0, true, false).is_ok());
        a.leave(A, Outcome::TimedOut);
        a.leave(A, Outcome::TimedOut);
        assert_eq!((a.in_flight(), a.from_ip(A)), (0, 0));
        assert_eq!(a.stats().timed_out, 2);
    }

    #[test]
    fn many_addresses_in_flight_stay_exact() {
        let mut a = adm(256, 4, 100_000);
        for i in 0..200u8 {
            assert!(a.admit([10, 0, 1, i], true, 0, true, false).is_ok());
        }
        assert_eq!(a.in_flight(), 200);
        for i in (0..200u8).rev() {
            a.leave([10, 0, 1, i], Outcome::Failed);
            assert_eq!(a.from_ip([10, 0, 1, i]), 0);
        }
        assert_eq!(a.in_flight(), 0);
        assert!(a.ips.is_empty());
    }
}
