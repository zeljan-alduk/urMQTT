//! Deadlines per session: offline sessions with a finite Session Expiry
//! Interval and Wills armed with a Will Delay Interval (ADR-273 rules 4 and
//! 6, ADR-274). An ordered set keyed by (deadline, session) plus the reverse
//! map, so a session that comes back cancels its deadline by its id: the
//! 64-byte session holds no timer handle, and only sessions that wait for
//! something pay (two tree entries each).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::SessionId;

#[derive(Default)]
pub(crate) struct Deadlines {
    by_sid: BTreeMap<SessionId, u64>,
    queue: BTreeSet<(u64, SessionId)>,
}

impl Deadlines {
    /// Sets (or moves) the deadline of `sid`.
    pub fn arm(&mut self, sid: SessionId, at_ms: u64) {
        self.cancel(sid);
        self.by_sid.insert(sid, at_ms);
        self.queue.insert((at_ms, sid));
    }

    /// Removes the deadline of `sid`; true if it had one.
    pub fn cancel(&mut self, sid: SessionId) -> bool {
        match self.by_sid.remove(&sid) {
            Some(at) => {
                self.queue.remove(&(at, sid));
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.by_sid.len()
    }

    /// Takes up to `max` sessions whose deadline is at or before `now_ms`,
    /// earliest first: a bounded step, so one tick never does unbounded work
    /// (the rest are taken by the next ticks).
    pub fn take_due(&mut self, now_ms: u64, max: usize, out: &mut Vec<SessionId>) {
        while out.len() < max {
            let Some(&(at, sid)) = self.queue.first() else {
                return;
            };
            if at > now_ms {
                return;
            }
            self.queue.pop_first();
            self.by_sid.remove(&sid);
            out.push(sid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_sessions_come_out_in_order_and_bounded() {
        let mut d = Deadlines::default();
        d.arm(1, 30);
        d.arm(2, 10);
        d.arm(3, 20);
        d.arm(1, 5); // moved
        assert!(d.cancel(3));
        assert!(!d.cancel(3));
        let mut out = Vec::new();
        d.take_due(9, 8, &mut out);
        assert_eq!(out, [1]);
        out.clear();
        d.arm(4, 10);
        d.take_due(100, 1, &mut out);
        assert_eq!(out, [2]);
        out.clear();
        d.take_due(100, 8, &mut out);
        assert_eq!(out, [4]);
        assert_eq!(d.len(), 0);
    }
}
