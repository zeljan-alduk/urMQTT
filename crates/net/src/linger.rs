//! Close deadlines (ADR-355): a connection the broker has closed gets a few
//! seconds for TCP to finish (the last bytes, the FIN and its ACK); one still
//! open after that is reset.
//!
//! A close relies on the peer: it must take the remaining bytes and
//! acknowledge the FIN. A peer that shuts its window (or answers nothing)
//! held such a connection, and its share of the heap, for minutes, or for
//! ever behind a zero window (NETDOS-1, NETDOS-2): every close the broker
//! starts (a refused handshake, a refused CONNECT or WebSocket upgrade, a
//! metrics answer, a keepalive or protocol close) leaves the handshake
//! deadlines, and nothing else bounded it.
//!
//! Entries are kept in the order they were added; the clock does not go
//! back, so the oldest is at the front and `expire` stops at the first one
//! not yet due. An entry whose connection has ended meanwhile (or whose
//! slot now holds another connection: the tag differs) is dropped when it
//! reaches the front.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// How long a closing connection may take to finish (ms).
pub const CLOSE_LINGER_MS: u64 = 5_000;

#[derive(Clone, Copy)]
struct Entry {
    at_ms: u64,
    c: u32,
    tag: u64,
}

/// Connections being closed, oldest first.
pub struct Linger {
    q: VecDeque<Entry>,
    limit_ms: u64,
}

impl Default for Linger {
    fn default() -> Self {
        Self::new(CLOSE_LINGER_MS)
    }
}

impl Linger {
    pub fn new(limit_ms: u64) -> Self {
        Self {
            q: VecDeque::new(),
            limit_ms,
        }
    }

    /// `c` (with the tag that tells this connection from a later one in the
    /// same slot) starts closing now. Callers add a connection once.
    pub fn start(&mut self, now_ms: u64, c: u32, tag: u64) {
        self.q.push_back(Entry {
            at_ms: now_ms,
            c,
            tag,
        });
    }

    /// Moves the connections whose deadline has passed and that are still
    /// open (`open(c, tag)`) into `due`.
    pub fn expire(
        &mut self,
        now_ms: u64,
        mut open: impl FnMut(u32, u64) -> bool,
        due: &mut Vec<u32>,
    ) {
        while let Some(&e) = self.q.front() {
            if !open(e.c, e.tag) {
                self.q.pop_front();
                continue;
            }
            if now_ms.saturating_sub(e.at_ms) <= self.limit_ms {
                break;
            }
            self.q.pop_front();
            due.push(e.c);
        }
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// Returns the memory a past peak left behind.
    pub fn shrink(&mut self) {
        if self.q.is_empty() {
            self.q.shrink_to_fit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn a_closing_connection_still_open_after_the_deadline_is_due() {
        let mut l = Linger::new(5_000);
        l.start(1_000, 7, 70);
        let mut due = Vec::new();
        l.expire(6_000, |_, _| true, &mut due);
        assert!(due.is_empty(), "not before the deadline");
        l.expire(6_001, |_, _| true, &mut due);
        assert_eq!(due, [7]);
        assert!(l.is_empty());
    }

    #[test]
    fn a_connection_that_finished_is_not_reset() {
        let mut l = Linger::new(5_000);
        l.start(0, 1, 10);
        l.start(0, 2, 20);
        let mut due = Vec::new();
        // Connection 1 ended normally; slot 2 now holds a newer connection.
        l.expire(10_000, |c, tag| c == 2 && tag == 21, &mut due);
        assert!(due.is_empty());
        assert!(l.is_empty());
    }

    /// NETDOS-1 / NETDOS-2: a stream of closes whose peers never finish
    /// (zero window) holds at most the closes of the last `limit` ms, not
    /// every one since boot.
    #[test]
    fn closes_that_never_finish_are_bounded_by_the_deadline() {
        // Miri runs the same property over a tenth of the time span (the full
        // one took 50 minutes there); the bound is the same function of it.
        let (limit, span) = if cfg!(miri) {
            (500u64, 3_000u64)
        } else {
            (5_000, 60_000)
        };
        let mut l = Linger::new(limit);
        let mut open: BTreeSet<u32> = BTreeSet::new();
        let mut held_max = 0;
        let mut due = Vec::new();
        for t in 0..span {
            // 2 new zombie connections per millisecond (2 000 per second).
            for i in 0..2 {
                let c = (t * 2 + i) as u32;
                open.insert(c);
                l.start(t, c, u64::from(c));
            }
            if t % 100 == 0 {
                due.clear();
                l.expire(t, |c, _| open.contains(&c), &mut due);
                for c in &due {
                    open.remove(c);
                }
            }
            held_max = held_max.max(open.len());
        }
        // The deadline plus one 100 ms tick of them (5.1 s in the full run).
        let bound = 2 * (limit as usize + 101);
        assert!(held_max <= bound, "{held_max} held");
        assert!(l.len() <= bound);
    }

    #[test]
    fn the_order_is_kept_when_the_front_is_not_due() {
        let mut l = Linger::new(100);
        l.start(0, 1, 1);
        l.start(50, 2, 2);
        let mut due = Vec::new();
        l.expire(120, |_, _| true, &mut due);
        assert_eq!(due, [1]);
        l.expire(151, |_, _| true, &mut due);
        assert_eq!(due, [1, 2]);
    }
}
