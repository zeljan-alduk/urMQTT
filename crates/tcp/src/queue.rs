//! A bounded queue of whole records for an outbound connection (NEXT-7,
//! ADR-316): what a sender keeps while its peer is unreachable or slow.
//!
//! The bound is in bytes. A record that does not fit pushes out the oldest
//! whole records (they are counted, never cut), so the queue keeps the
//! newest; a record larger than the whole bound is refused and counted. The
//! sender takes whole records from the front, as many as fit a byte budget.
//! Nothing here ever grows past the bound: a stalled peer costs the bound and
//! no more (the NEXT-8 rule "a stalled upstream must not grow the heap").

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub struct RecordQueue {
    bytes: VecDeque<u8>,
    lens: VecDeque<u32>,
    cap: usize,
    /// Records pushed out or refused, and their bytes.
    pub dropped: u64,
    pub dropped_bytes: u64,
}

impl RecordQueue {
    /// A queue of at most `cap` bytes of records.
    pub fn new(cap: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            lens: VecDeque::new(),
            cap,
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Bytes queued.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Records queued.
    pub fn records(&self) -> usize {
        self.lens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    fn drop_front(&mut self) {
        if let Some(n) = self.lens.pop_front() {
            let n = n as usize;
            self.bytes.drain(..n.min(self.bytes.len()));
            self.dropped += 1;
            self.dropped_bytes += n as u64;
        }
    }

    /// Queues `rec` (whole), dropping the oldest records to make room.
    /// Returns false if `rec` alone is larger than the bound (it is dropped).
    pub fn push(&mut self, rec: &[u8]) -> bool {
        if rec.len() > self.cap || u32::try_from(rec.len()).is_err() {
            self.dropped += 1;
            self.dropped_bytes += rec.len() as u64;
            return false;
        }
        while self.bytes.len() + rec.len() > self.cap {
            self.drop_front();
        }
        self.bytes.extend(rec);
        self.lens.push_back(rec.len() as u32);
        true
    }

    /// Moves whole records from the front into `out` while they fit in
    /// `budget` bytes; at least one if any is queued and `budget` is not 0
    /// (a record larger than the budget still goes, alone). Returns the
    /// records moved.
    pub fn take(&mut self, budget: usize, out: &mut Vec<u8>) -> usize {
        let mut used = 0usize;
        let mut n = 0;
        while let Some(&len) = self.lens.front() {
            let len = len as usize;
            if budget == 0 || (n > 0 && used + len > budget) {
                break;
            }
            self.lens.pop_front();
            out.extend(self.bytes.drain(..len.min(self.bytes.len())));
            used += len;
            n += 1;
            if used >= budget {
                break;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_newest_whole_records_within_the_bound() {
        let mut q = RecordQueue::new(10);
        assert!(q.push(b"aaaa"));
        assert!(q.push(b"bbbb"));
        assert_eq!((q.len(), q.records()), (8, 2));
        // 4 more do not fit: the oldest goes, whole.
        assert!(q.push(b"cccc"));
        assert_eq!(
            (q.len(), q.records(), q.dropped, q.dropped_bytes),
            (8, 2, 1, 4)
        );
        // Larger than the bound: refused, counted, nothing else lost.
        assert!(!q.push(b"0123456789x"));
        assert_eq!((q.records(), q.dropped), (2, 2));
        // Exactly the bound: everything else goes.
        assert!(q.push(b"0123456789"));
        assert_eq!((q.len(), q.records(), q.dropped), (10, 1, 4));
        let mut out = Vec::new();
        assert_eq!(q.take(100, &mut out), 1);
        assert_eq!(out, b"0123456789");
        assert!(q.is_empty());
    }

    #[test]
    fn take_moves_whole_records_up_to_the_budget() {
        let mut q = RecordQueue::new(1000);
        for r in [&b"one"[..], b"two", b"three", b"four"] {
            q.push(r);
        }
        let mut out = Vec::new();
        assert_eq!(q.take(0, &mut out), 0);
        assert_eq!(q.take(7, &mut out), 2);
        assert_eq!(out, b"onetwo");
        out.clear();
        // A record larger than the budget still goes, alone.
        assert_eq!(q.take(2, &mut out), 1);
        assert_eq!(out, b"three");
        out.clear();
        assert_eq!(q.take(100, &mut out), 1);
        assert_eq!(out, b"four");
        assert_eq!(q.take(100, &mut out), 0);
    }

    #[test]
    fn never_exceeds_the_bound_under_any_sequence() {
        let mut q = RecordQueue::new(300);
        let mut x = 12345u32;
        let mut out = Vec::new();
        for i in 0..10_000u32 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let len = (x % 120) as usize;
            q.push(&alloc::vec![i as u8; len]);
            assert!(q.len() <= 300);
            assert_eq!(q.len(), q.lens.iter().map(|&n| n as usize).sum::<usize>());
            if x % 7 == 0 {
                out.clear();
                q.take((x % 200) as usize, &mut out);
            }
        }
    }
}
