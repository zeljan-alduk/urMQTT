//! Data that arrived beyond a hole (PERF, ADR-222): a sorted list of
//! non-overlapping byte ranges, kept until the hole before them fills.
//!
//! The list is small (at most [`MAX_RANGES`] ranges) and allocated when the
//! first out-of-order segment arrives and dropped when it empties, so an idle
//! or healthy connection pays nothing. Bytes are bounded by the caller
//! (per connection and per core). All ranges lie within one receive window,
//! so sequence numbers compare with the wrap-around arithmetic of `seq`.

use alloc::vec::Vec;

use crate::seq::{ge, gt, le, lt};

/// Most ranges a connection keeps; a segment that needs another one is
/// dropped (the peer retransmits it).
pub const MAX_RANGES: usize = 16;

#[derive(Default)]
pub struct Ooo {
    /// (first sequence number, bytes), ascending, neither overlapping nor adjacent.
    ranges: Vec<(u32, Vec<u8>)>,
    bytes: usize,
    /// First sequence number of the range that received the latest segment
    /// (RFC 2018 §4: it is reported first).
    recent: u32,
}

impl Ooo {
    /// Bytes held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub fn ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Adds `data` starting at `seq`, merging with the ranges it overlaps or
    /// touches. Returns the number of bytes that were new, or `None` if a new
    /// range was needed and the list is full.
    pub fn insert(&mut self, seq: u32, data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return Some(0);
        }
        let end = seq.wrapping_add(data.len() as u32);
        // The first range that ends at or after `seq`.
        let first = self
            .ranges
            .iter()
            .position(|(a, v)| ge(a.wrapping_add(v.len() as u32), seq))
            .unwrap_or(self.ranges.len());
        // ... and the ones from there that start at or before `end`.
        let mut last = first;
        let (mut lo, mut hi) = (seq, end);
        while let Some((a, v)) = self.ranges.get(last) {
            if gt(*a, end) {
                break;
            }
            let b = a.wrapping_add(v.len() as u32);
            if lt(*a, lo) {
                lo = *a;
            }
            if gt(b, hi) {
                hi = b;
            }
            last += 1;
        }
        if first == last {
            if self.ranges.len() >= MAX_RANGES {
                return None;
            }
            self.ranges.insert(first, (seq, data.to_vec()));
            self.bytes += data.len();
            self.recent = seq;
            return Some(data.len());
        }
        // One merged range; old bytes first, the new segment over them (a
        // retransmission carries the same bytes).
        let mut merged = alloc::vec![0u8; hi.wrapping_sub(lo) as usize];
        let mut old = 0;
        for (a, v) in self.ranges.drain(first..last) {
            old += v.len();
            let at = a.wrapping_sub(lo) as usize;
            if let Some(d) = merged.get_mut(at..at + v.len()) {
                d.copy_from_slice(&v);
            }
        }
        let at = seq.wrapping_sub(lo) as usize;
        if let Some(d) = merged.get_mut(at..at + data.len()) {
            d.copy_from_slice(data);
        }
        let added = merged.len() - old;
        self.bytes += added;
        self.ranges.insert(first, (lo, merged));
        self.recent = lo;
        Some(added)
    }

    /// The bytes now in order at `rcv_nxt`, if the first range reaches it
    /// (what lies below it is discarded). The caller advances `rcv_nxt` by the
    /// length of what it gets.
    pub fn take_front(&mut self, rcv_nxt: u32) -> Option<Vec<u8>> {
        loop {
            let (a, v) = self.ranges.first()?;
            if gt(*a, rcv_nxt) {
                return None;
            }
            let end = a.wrapping_add(v.len() as u32);
            let (a, mut v) = self.ranges.remove(0);
            self.bytes -= v.len();
            if le(end, rcv_nxt) {
                // Entirely old: the hole was filled by a longer segment.
                continue;
            }
            let skip = rcv_nxt.wrapping_sub(a) as usize;
            v.drain(..skip.min(v.len()));
            return Some(v);
        }
    }

    /// SACK blocks to report (RFC 2018): the range with the latest segment
    /// first, then the others from the lowest, at most three.
    pub fn blocks(&self) -> ([(u32, u32); 3], u8) {
        let mut out = [(0u32, 0u32); 3];
        let mut n = 0;
        let edge = |(a, v): &(u32, Vec<u8>)| (*a, a.wrapping_add(v.len() as u32));
        if let Some(r) = self.ranges.iter().find(|(a, _)| *a == self.recent) {
            out[0] = edge(r);
            n = 1;
        }
        for r in self.ranges.iter().filter(|(a, _)| *a != self.recent) {
            if n >= out.len() {
                break;
            }
            if let Some(slot) = out.get_mut(n) {
                *slot = edge(r);
                n += 1;
            }
        }
        (out, n as u8)
    }
}
