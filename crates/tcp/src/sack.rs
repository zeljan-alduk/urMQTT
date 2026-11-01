//! What the peer told us it holds beyond a hole (RFC 2018) and which of the
//! holes are lost (RFC 6675), for the sending side (ADR-265).
//!
//! The scoreboard is a few disjoint byte ranges above the cumulative ACK. A
//! hole is **lost** when the data SACKed above it is more than two segments or
//! lies in three ranges (RFC 6675 `IsLost`); until then it may be reordering.
//! Recovery retransmits lost holes only, one segment at a time and each once
//! (`next` is the frontier), and counts what is still in the network as the
//! *pipe*: what is in flight, less what the peer holds and what is lost and not
//! yet sent again. A cumulative ACK that stops short of `recover` does not by
//! itself make the next segment a loss: acknowledgements that arrive in a
//! burst after a stall used to make NewReno retransmit a dozen segments that
//! were not lost.
//!
//! Sequence numbers compare with the wrap-around arithmetic of `seq`; all
//! ranges lie within one window of the left edge.

use crate::seq::{ge, gt, lt};

/// Most ranges kept; a block that needs another one is ignored (the peer
/// repeats it).
pub const MAX_RANGES: usize = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Bytes the peer holds above the cumulative ACK.
    pub sacked: u32,
    /// Bytes of holes that count as lost.
    pub lost: u32,
    /// Of those, the bytes already sent again in this recovery.
    pub resent: u32,
}

#[derive(Debug, Clone)]
pub struct Board {
    /// Ascending, disjoint, not touching (start, end).
    r: [(u32, u32); MAX_RANGES],
    n: u8,
    /// When (ms, wrapping) evidence of a loss was first seen: the hole must
    /// outlast the reordering window before it is acted on.
    pub since: u32,
    /// Retransmission frontier: holes below it were sent again once.
    pub next: u32,
}

impl Board {
    pub fn new(now_ms: u32, una: u32) -> Self {
        Self {
            r: [(0, 0); MAX_RANGES],
            n: 0,
            since: now_ms,
            next: una,
        }
    }

    fn ranges(&self) -> &[(u32, u32)] {
        self.r.get(..usize::from(self.n)).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        usize::from(self.n)
    }

    /// Adds the block `[l, r)` (already inside `(una, snd_max]`), merging with
    /// what it overlaps or touches. Returns whether the peer told something
    /// new.
    pub fn insert(&mut self, l: u32, r: u32) -> bool {
        if !lt(l, r) {
            return false;
        }
        let n = usize::from(self.n);
        // Ranges that overlap or touch [l, r): from the first that ends at or
        // after l to the last that starts at or before r.
        let first = self
            .ranges()
            .iter()
            .position(|&(_, e)| ge(e, l))
            .unwrap_or(n);
        let mut last = first;
        let (mut lo, mut hi) = (l, r);
        let mut covered = true;
        while let Some(&(a, e)) = self.r.get(last) {
            if last >= n || gt(a, r) {
                break;
            }
            // New information unless an existing range already holds all of [l, r).
            if gt(a, l) || lt(e, r) {
                covered = false;
            }
            if lt(a, lo) {
                lo = a;
            }
            if gt(e, hi) {
                hi = e;
            }
            last += 1;
        }
        if first == last {
            // Nothing to merge with: a new range between `first - 1` and `first`.
            if n == MAX_RANGES {
                return false;
            }
            for i in (first..n).rev() {
                if let Some(&v) = self.r.get(i)
                    && let Some(slot) = self.r.get_mut(i + 1)
                {
                    *slot = v;
                }
            }
            if let Some(slot) = self.r.get_mut(first) {
                *slot = (lo, hi);
            }
            self.n += 1;
            return true;
        }
        // Replace ranges first..last by the merged one.
        if let Some(slot) = self.r.get_mut(first) {
            *slot = (lo, hi);
        }
        let removed = last - first - 1;
        for i in last..n {
            if let Some(&v) = self.r.get(i)
                && let Some(slot) = self.r.get_mut(i - removed)
            {
                *slot = v;
            }
        }
        self.n -= removed as u8;
        !covered
    }

    /// The cumulative ACK moved to `una`: what it covers is no longer news.
    pub fn advance(&mut self, una: u32) {
        let n = usize::from(self.n);
        let keep = self
            .ranges()
            .iter()
            .position(|&(_, e)| gt(e, una))
            .unwrap_or(n);
        if keep > 0 {
            for i in keep..n {
                if let Some(&v) = self.r.get(i)
                    && let Some(slot) = self.r.get_mut(i - keep)
                {
                    *slot = v;
                }
            }
            self.n -= keep as u8;
        }
        if let Some(first) = self.r.first_mut()
            && self.n > 0
            && lt(first.0, una)
        {
            first.0 = una;
        }
        if lt(self.next, una) {
            self.next = una;
        }
    }

    /// Whether `[a, b)`, a hole with `above` bytes in `ranges_above` ranges
    /// SACKed beyond it, is lost (RFC 6675 `IsLost`, DupThresh 3).
    fn lost(above: u32, ranges_above: usize, mss: u32) -> bool {
        above > 2 * mss || ranges_above >= 3
    }

    /// The holes below the highest range that count as lost, and the totals.
    pub fn tally(&self, una: u32, mss: u32) -> Tally {
        let total: u32 = self.ranges().iter().map(|&(a, e)| e.wrapping_sub(a)).sum();
        let mut t = Tally {
            sacked: total,
            ..Tally::default()
        };
        let (mut before, mut gap_start) = (0u32, una);
        for (i, &(a, e)) in self.ranges().iter().enumerate() {
            if lt(gap_start, a) {
                let len = a.wrapping_sub(gap_start);
                if Self::lost(total - before, self.ranges().len() - i, mss) {
                    t.lost += len;
                    if gt(self.next, gap_start) {
                        t.resent += self.next.wrapping_sub(gap_start).min(len);
                    }
                }
            }
            before += e.wrapping_sub(a);
            gap_start = e;
        }
        t
    }

    /// The next lost byte not yet sent again: `(seq, len)` with `len <= mss`.
    pub fn next_hole(&self, una: u32, mss: u32) -> Option<(u32, u32)> {
        let total: u32 = self.ranges().iter().map(|&(a, e)| e.wrapping_sub(a)).sum();
        let (mut before, mut gap_start) = (0u32, una);
        for (i, &(a, e)) in self.ranges().iter().enumerate() {
            if lt(gap_start, a) && Self::lost(total - before, self.ranges().len() - i, mss) {
                let from = if gt(self.next, gap_start) {
                    self.next
                } else {
                    gap_start
                };
                if lt(from, a) {
                    return Some((from, a.wrapping_sub(from).min(mss)));
                }
            }
            before += e.wrapping_sub(a);
            gap_start = e;
        }
        None
    }

    /// Whether the first hole (at `una`) is lost by the rules above.
    pub fn first_hole_lost(&self, una: u32, mss: u32) -> bool {
        let total: u32 = self.ranges().iter().map(|&(a, e)| e.wrapping_sub(a)).sum();
        match self.ranges().first() {
            Some(&(a, _)) if lt(una, a) => Self::lost(total, self.ranges().len(), mss),
            _ => false,
        }
    }

    /// Whether `seq` is inside a SACKed range.
    #[cfg(test)]
    pub fn holds(&self, seq: u32) -> bool {
        self.ranges()
            .iter()
            .any(|&(a, e)| crate::seq::le(a, seq) && lt(seq, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1000;

    fn board(blocks: &[(u32, u32)]) -> Board {
        let mut b = Board::new(0, 0);
        for &(l, r) in blocks {
            b.insert(l, r);
        }
        b
    }

    fn all(b: &Board) -> Vec<(u32, u32)> {
        b.ranges().to_vec()
    }

    #[test]
    fn blocks_merge_when_they_overlap_or_touch() {
        let mut b = Board::new(0, 0);
        assert!(b.insert(3000, 4000));
        assert!(b.insert(6000, 7000));
        assert!(b.insert(4000, 5000), "touching: one range");
        assert_eq!(all(&b), [(3000, 5000), (6000, 7000)]);
        assert!(b.insert(4500, 6500), "bridges the two");
        assert_eq!(all(&b), [(3000, 7000)]);
        assert!(!b.insert(3500, 4000), "inside what is known: nothing new");
        assert!(!b.insert(3000, 7000));
        assert!(b.insert(2000, 3000), "extends to the left");
        assert!(b.insert(7000, 7500), "and to the right");
        assert_eq!(all(&b), [(2000, 7500)]);
        assert!(!b.insert(5, 5), "an empty block");
    }

    #[test]
    fn the_board_holds_a_few_ranges_and_ignores_the_rest() {
        let mut b = Board::new(0, 0);
        for i in 0..MAX_RANGES as u32 {
            assert!(b.insert(2000 + i * 2000, 2500 + i * 2000));
        }
        assert_eq!(b.count(), MAX_RANGES);
        assert!(
            !b.insert(90_000, 90_500),
            "full: ignored, the peer repeats it"
        );
        // A block that merges still fits.
        assert!(b.insert(2500, 3000));
        assert_eq!(b.count(), MAX_RANGES);
    }

    #[test]
    fn a_cumulative_ack_trims_the_ranges() {
        let mut b = board(&[(3000, 4000), (6000, 7000)]);
        b.advance(3500);
        assert_eq!(all(&b), [(3500, 4000), (6000, 7000)]);
        b.advance(4000);
        assert_eq!(all(&b), [(6000, 7000)]);
        b.advance(9000);
        assert!(b.is_empty());
        assert_eq!(b.next, 9000);
    }

    #[test]
    fn a_hole_is_lost_with_three_segments_above_it_not_before() {
        // Hole [0, 1000); 2 segments (2000 bytes) SACKed above: reordering.
        let b = board(&[(1000, 3000)]);
        assert_eq!(
            b.tally(0, MSS),
            Tally {
                sacked: 2000,
                lost: 0,
                resent: 0
            }
        );
        assert!(!b.first_hole_lost(0, MSS));
        assert_eq!(b.next_hole(0, MSS), None);
        // More than two segments above it: lost.
        let b = board(&[(1000, 3001)]);
        assert!(b.first_hole_lost(0, MSS));
        assert_eq!(b.next_hole(0, MSS), Some((0, 1000)));
        // Three ranges above it: lost, whatever their size.
        let b = board(&[(1000, 1100), (2000, 2100), (3000, 3100)]);
        assert!(b.first_hole_lost(0, MSS));
        // Only the first hole has three ranges above it.
        assert_eq!(b.tally(0, MSS).lost, 1000);
    }

    #[test]
    fn holes_are_sent_again_once_each_from_the_frontier() {
        let mut b = board(&[(2000, 3500), (4500, 6000)]);
        // Holes [0,2000) and [3500,4500); 1500 + 1500 = 3000 bytes SACKed.
        let t = b.tally(0, MSS);
        assert_eq!(
            t,
            Tally {
                sacked: 3000,
                lost: 2000,
                resent: 0
            }
        );
        // Only the first hole has more than 2 MSS above it (3000); the second has 1500.
        assert_eq!(b.next_hole(0, MSS), Some((0, 1000)));
        b.next = 1000;
        assert_eq!(b.next_hole(0, MSS), Some((1000, 1000)));
        assert_eq!(b.tally(0, MSS).resent, 1000);
        b.next = 2000;
        assert_eq!(
            b.next_hole(0, MSS),
            None,
            "the first hole is done; the second is not lost yet"
        );
        // More arrives above the second hole: it is lost now.
        b.insert(6000, 8000);
        assert_eq!(b.next_hole(0, MSS), Some((3500, 1000)));
        assert_eq!(b.tally(0, MSS).lost, 2000 + 1000);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut b = Board::new(0, u32::MAX - 500);
        assert!(b.insert(500, 4000));
        assert!(b.first_hole_lost(u32::MAX - 500, MSS));
        assert_eq!(
            b.next_hole(u32::MAX - 500, MSS),
            Some((u32::MAX - 500, 1000))
        );
        b.advance(1000);
        assert_eq!(all(&b), [(1000, 4000)]);
        assert!(b.holds(1000) && b.holds(3999) && !b.holds(4000) && !b.holds(999));
    }

    /// Random blocks never break the invariants: ascending, disjoint, not touching.
    #[test]
    fn random_blocks_keep_the_board_tidy() {
        let mut x = 0x2545_f491_u32;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        let mut b = Board::new(0, 0);
        let mut model = [false; 40];
        for step in 0..4000 {
            let l = next() % 38;
            let len = 1 + next() % 5;
            let r = (l + len).min(40);
            let added = b.insert(l * 100 + 100, r * 100 + 100);
            // The model: bytes (in units of 100) marked; a block can only fail to be
            // recorded when the board is full of other ranges.
            let before = model.iter().filter(|&&v| v).count();
            for i in l..r {
                if let Some(m) = model.get_mut(i as usize) {
                    *m = true;
                }
            }
            let _ = (added, before);
            let rs = all(&b);
            for w in rs.windows(2) {
                assert!(
                    w[0].1 < w[1].0,
                    "ranges touch or overlap at step {step}: {rs:?}"
                );
            }
            for &(a, e) in &rs {
                assert!(a < e);
            }
            assert!(rs.len() <= MAX_RANGES);
            if step % 17 == 0 {
                b.advance(100 + (next() % 20) * 100);
            }
        }
    }
}
