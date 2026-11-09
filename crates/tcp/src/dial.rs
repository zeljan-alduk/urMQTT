//! The reconnect policy of one outbound connection (NEXT-7, ADR-316).
//!
//! Sans-IO, like the stack: the owner calls [`Dialer::poll`] from its loop
//! and does what the returned [`Action`] says (ask ARP for the next hop,
//! open the connection, abort it), then reports what happened
//! ([`Dialer::started`], [`Dialer::failed`], [`Dialer::up`],
//! [`Dialer::closed`]). The dialer decides when to try again:
//!
//! - the first attempt is at once; after a failure the next waits
//!   `min(max, min_delay · 2^(failures-1))`, half of it fixed and half
//!   random ("equal jitter"), so a sink that went away is not hammered and
//!   several brokers do not reconnect in step;
//! - the next hop's MAC is asked for (`resolve_tries` ARP requests,
//!   `resolve_every_ms` apart) before a SYN goes out: a SYN to an unknown
//!   neighbour would be dropped by the interface;
//! - a connection must be **up** (the owner decides: for TLS, the handshake
//!   done) within `connect_timeout_ms` of its start, or it is aborted;
//! - a connection that was up for `stable_ms` or longer resets the backoff
//!   when it ends; one that ends sooner counts as a failure, so a peer that
//!   accepts and closes at once is retried at the backoff's pace, not in a
//!   loop.

use crate::ConnId;

/// The tunables of a [`Dialer`]; [`Policy::DEFAULT`] is what the kernel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The wait after the first failure, ms.
    pub min_delay_ms: u64,
    /// The longest wait, ms.
    pub max_delay_ms: u64,
    /// ARP requests for the next hop before an attempt counts as failed, ...
    pub resolve_tries: u8,
    /// ... this far apart, ms.
    pub resolve_every_ms: u64,
    /// From the SYN to "up", at most, ms.
    pub connect_timeout_ms: u64,
    /// A connection up this long resets the backoff when it ends, ms.
    pub stable_ms: u64,
}

impl Policy {
    pub const DEFAULT: Policy = Policy {
        min_delay_ms: 1_000,
        max_delay_ms: 300_000,
        resolve_tries: 3,
        resolve_every_ms: 1_000,
        connect_timeout_ms: 30_000,
        stable_ms: 10_000,
    };
}

/// Where the dialer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting until this time (ms) to try again (or for the first time).
    Waiting { until: u64 },
    /// ARP requests sent for the next hop: `tries` so far, the next at `next`.
    Resolving { next: u64, tries: u8 },
    /// The owner was told to connect and has not said how it went.
    Dialing,
    /// A connection is being made, and must be up by `deadline`.
    Connecting { c: ConnId, deadline: u64 },
    /// Up since `since`.
    Up { c: ConnId, since: u64 },
}

/// What the owner should do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing.
    None,
    /// Send an ARP request for the next hop of the destination.
    Resolve,
    /// Open the connection now and report [`Dialer::started`] or
    /// [`Dialer::failed`] before the next poll.
    Connect,
    /// The connection did not come up in time: abort it (the dialer has
    /// already counted the failure).
    Abort(ConnId),
}

/// Counters for the log and `$SYS`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DialStats {
    /// Connections started (SYN sent).
    pub attempts: u64,
    /// Connections that came up.
    pub up: u64,
    /// Attempts that failed: no neighbour, refused, timed out, closed
    /// before they were stable.
    pub failures: u64,
}

pub struct Dialer {
    policy: Policy,
    phase: Phase,
    /// Failures in a row.
    failures: u32,
    /// xorshift64 state for the jitter (not a secret: it only spreads the
    /// retries).
    rng: u64,
    pub stats: DialStats,
}

impl Dialer {
    /// A dialer that tries at once; `seed` spreads its retries.
    pub fn new(policy: Policy, now_ms: u64, seed: u64) -> Self {
        Self {
            policy,
            phase: Phase::Waiting { until: now_ms },
            failures: 0,
            rng: seed | 1,
            stats: DialStats::default(),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Failures in a row since the last stable connection.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// The connection, while one is being made or is up.
    pub fn conn(&self) -> Option<ConnId> {
        match self.phase {
            Phase::Connecting { c, .. } | Phase::Up { c, .. } => Some(c),
            _ => None,
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up { .. })
    }

    /// When the next attempt is due, while waiting.
    pub fn retry_at(&self) -> Option<u64> {
        match self.phase {
            Phase::Waiting { until } => Some(until),
            _ => None,
        }
    }

    fn random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// The wait after the `n`-th failure in a row (n ≥ 1), before jitter.
    pub fn delay_for(policy: &Policy, n: u32) -> u64 {
        let shift = n.saturating_sub(1).min(32);
        policy
            .min_delay_ms
            .saturating_mul(1u64 << shift)
            .min(policy.max_delay_ms)
    }

    fn fail(&mut self, now_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        self.stats.failures += 1;
        let d = Self::delay_for(&self.policy, self.failures);
        let half = d / 2;
        let jitter = self.random() % (d - half + 1);
        self.phase = Phase::Waiting {
            until: now_ms.saturating_add(half + jitter),
        };
    }

    /// What to do now. `reachable`: the next hop's MAC is known (and we have
    /// an address).
    pub fn poll(&mut self, now_ms: u64, reachable: bool) -> Action {
        match self.phase {
            Phase::Waiting { until } if now_ms >= until => {
                if reachable {
                    self.phase = Phase::Dialing;
                    Action::Connect
                } else {
                    self.phase = Phase::Resolving {
                        next: now_ms.saturating_add(self.policy.resolve_every_ms),
                        tries: 1,
                    };
                    Action::Resolve
                }
            }
            Phase::Resolving { next, tries } => {
                if reachable {
                    self.phase = Phase::Dialing;
                    Action::Connect
                } else if now_ms < next {
                    Action::None
                } else if tries >= self.policy.resolve_tries {
                    self.fail(now_ms);
                    Action::None
                } else {
                    self.phase = Phase::Resolving {
                        next: now_ms.saturating_add(self.policy.resolve_every_ms),
                        tries: tries + 1,
                    };
                    Action::Resolve
                }
            }
            Phase::Connecting { c, deadline } if now_ms >= deadline => {
                self.fail(now_ms);
                Action::Abort(c)
            }
            _ => Action::None,
        }
    }

    /// The connection asked for by [`Action::Connect`] was started.
    pub fn started(&mut self, c: ConnId, now_ms: u64) {
        self.stats.attempts += 1;
        self.phase = Phase::Connecting {
            c,
            deadline: now_ms.saturating_add(self.policy.connect_timeout_ms),
        };
    }

    /// The connection asked for by [`Action::Connect`] could not be started
    /// (no port, table full, no address): tried again after the backoff.
    pub fn failed(&mut self, now_ms: u64) {
        if self.phase == Phase::Dialing {
            self.fail(now_ms);
        }
    }

    /// `c` is up (for TLS: the handshake is done).
    pub fn up(&mut self, c: ConnId, now_ms: u64) {
        if let Phase::Connecting { c: x, .. } = self.phase
            && x == c
        {
            self.stats.up += 1;
            self.phase = Phase::Up { c, since: now_ms };
        }
    }

    /// `c` ended (closed, reset, timed out, or aborted by its owner). Another
    /// connection's end is ignored.
    pub fn closed(&mut self, c: ConnId, now_ms: u64) {
        match self.phase {
            Phase::Up { c: x, since } if x == c => {
                if now_ms.saturating_sub(since) >= self.policy.stable_ms {
                    // It worked for a while: start over at the shortest wait.
                    self.failures = 0;
                    self.phase = Phase::Waiting {
                        until: now_ms.saturating_add(self.policy.min_delay_ms),
                    };
                } else {
                    self.fail(now_ms);
                }
            }
            Phase::Connecting { c: x, .. } if x == c => self.fail(now_ms),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Policy = Policy::DEFAULT;

    #[test]
    fn first_attempt_is_at_once_and_asks_arp_first() {
        let mut d = Dialer::new(P, 100, 7);
        assert_eq!(d.poll(100, false), Action::Resolve);
        assert_eq!(d.poll(500, false), Action::None);
        assert_eq!(d.poll(600, true), Action::Connect);
        d.started(3, 600);
        assert_eq!(d.conn(), Some(3));
        d.up(3, 700);
        assert!(d.is_up());
        assert_eq!(
            d.stats,
            DialStats {
                attempts: 1,
                up: 1,
                failures: 0
            }
        );
    }

    #[test]
    fn an_unresolved_next_hop_is_a_failure_after_the_tries() {
        let mut d = Dialer::new(P, 0, 7);
        assert_eq!(d.poll(0, false), Action::Resolve);
        assert_eq!(d.poll(1000, false), Action::Resolve);
        assert_eq!(d.poll(2000, false), Action::Resolve);
        assert_eq!(d.poll(3000, false), Action::None);
        assert_eq!(d.failures(), 1);
        let until = d.retry_at().unwrap();
        assert!((3500..=4000).contains(&until), "{until}");
    }

    #[test]
    fn backoff_doubles_with_jitter_up_to_the_cap() {
        for n in 1..40 {
            let d = Dialer::delay_for(&P, n);
            assert!(d <= P.max_delay_ms);
            assert!(d >= P.min_delay_ms);
        }
        assert_eq!(Dialer::delay_for(&P, 1), 1000);
        assert_eq!(Dialer::delay_for(&P, 2), 2000);
        assert_eq!(Dialer::delay_for(&P, 9), 256_000);
        assert_eq!(Dialer::delay_for(&P, 10), 300_000);
        assert_eq!(Dialer::delay_for(&P, u32::MAX), 300_000);
        // Every wait lies between half and all of the delay.
        let mut d = Dialer::new(P, 0, 99);
        let mut now = 0;
        for n in 1..20u32 {
            assert_eq!(d.poll(now, true), Action::Connect);
            d.started(n, now);
            d.closed(n, now + 5);
            let until = d.retry_at().unwrap();
            let full = Dialer::delay_for(&P, n);
            let wait = until - (now + 5);
            assert!(wait >= full / 2 && wait <= full, "{n}: {wait} of {full}");
            assert_eq!(d.poll(until - 1, true), Action::None);
            now = until;
        }
        assert_eq!(d.stats.failures, 19);
    }

    #[test]
    fn a_connection_that_does_not_come_up_is_aborted() {
        let mut d = Dialer::new(P, 0, 1);
        assert_eq!(d.poll(0, true), Action::Connect);
        d.started(5, 0);
        assert_eq!(d.poll(29_999, true), Action::None);
        assert_eq!(d.poll(30_000, true), Action::Abort(5));
        assert_eq!(d.failures(), 1);
        // Its late close is not counted twice.
        d.closed(5, 30_001);
        assert_eq!(d.failures(), 1);
        assert_eq!(d.conn(), None);
    }

    #[test]
    fn a_stable_connection_resets_the_backoff_a_short_one_does_not() {
        let mut d = Dialer::new(P, 0, 1);
        let mut now = 0;
        for i in 0..5 {
            assert_eq!(d.poll(now, true), Action::Connect);
            d.started(i, now);
            d.up(i, now + 10);
            d.closed(i, now + 20);
            now = d.retry_at().unwrap();
        }
        assert_eq!(d.failures(), 5);
        assert_eq!(d.poll(now, true), Action::Connect);
        d.started(9, now);
        d.up(9, now);
        d.closed(9, now + 10_000);
        assert_eq!(d.failures(), 0);
        assert_eq!(d.retry_at(), Some(now + 10_000 + 1000));
    }

    #[test]
    fn failed_start_and_foreign_events() {
        let mut d = Dialer::new(P, 0, 1);
        // Reports without a matching state change nothing.
        d.failed(0);
        d.up(1, 0);
        d.closed(1, 0);
        assert_eq!(d.failures(), 0);
        assert_eq!(d.poll(0, true), Action::Connect);
        d.failed(0);
        assert_eq!(d.failures(), 1);
        assert!(d.retry_at().is_some());
        // Another connection's end does not touch this one.
        let t = d.retry_at().unwrap();
        assert_eq!(d.poll(t, true), Action::Connect);
        d.started(2, t);
        d.closed(3, t);
        assert_eq!(d.conn(), Some(2));
    }
}
