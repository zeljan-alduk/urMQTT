//! Hierarchical timing wheel for TCP and MQTT timers (M14, PROMPT §5.2).
//!
//! Four levels of 64 slots each; a level-0 slot is one tick (the caller's
//! unit, 1 ms in the kernel), so the wheel spans 64^4 ticks (about 4.6 h
//! at 1 ms) before deadlines are clamped and re-placed on cascade.
//!
//! Insert and cancel are O(1): entries live in a slab with intrusive
//! doubly-linked slot lists, and a [`TimerId`] carries a generation so a
//! stale id never cancels someone else's timer. [`Wheel::advance`] does
//! work proportional to the ticks that actually hold timers: empty
//! stretches are skipped level by level.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

use alloc::vec::Vec;

const LEVELS: usize = 4;
const BITS: u32 = 6;
const SLOTS: usize = 1 << BITS;
const MASK: u64 = SLOTS as u64 - 1;
const NIL: u32 = u32::MAX;
/// `place` of an entry whose deadline had already passed when inserted.
const OVERDUE: u32 = u32::MAX - 1;

/// Handle of a scheduled timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId {
    index: u32,
    generation: u32,
}

#[derive(Debug, Clone, Copy)]
struct Entry<K> {
    deadline: u64,
    key: K,
    prev: u32,
    next: u32,
    /// `level * SLOTS + slot`, or `NIL` when free.
    place: u32,
    generation: u32,
}

pub struct Wheel<K: Copy> {
    now: u64,
    heads: [[u32; SLOTS]; LEVELS],
    per_level: [usize; LEVELS],
    entries: Vec<Entry<K>>,
    free: u32,
    live: usize,
    /// Inserted with a deadline ≤ `now`: fired by the next `advance`.
    overdue: Vec<u32>,
}

impl<K: Copy> Wheel<K> {
    /// A wheel whose current time is `now` (ticks).
    pub fn new(now: u64) -> Self {
        Self {
            now,
            heads: [[NIL; SLOTS]; LEVELS],
            per_level: [0; LEVELS],
            entries: Vec::new(),
            free: NIL,
            live: 0,
            overdue: Vec::new(),
        }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Schedules `key` to fire at tick `deadline` (or on the next advance,
    /// even to the same tick, if it has passed).
    pub fn insert(&mut self, deadline: u64, key: K) -> TimerId {
        let index = if self.free != NIL {
            let i = self.free;
            self.free = self.entries.get(i as usize).map_or(NIL, |e| e.next);
            if let Some(e) = self.entries.get_mut(i as usize) {
                e.deadline = deadline;
                e.key = key;
                e.generation = e.generation.wrapping_add(1);
            }
            i
        } else {
            self.entries.push(Entry {
                deadline,
                key,
                prev: NIL,
                next: NIL,
                place: NIL,
                generation: 0,
            });
            (self.entries.len() - 1) as u32
        };
        self.live += 1;
        let overdue = deadline <= self.now;
        if overdue {
            if let Some(e) = self.entries.get_mut(index as usize) {
                e.place = OVERDUE;
            }
            self.overdue.push(index);
        } else {
            self.place(index);
        }
        TimerId {
            index,
            generation: self.entries.get(index as usize).map_or(0, |e| e.generation),
        }
    }

    /// Cancels a timer; returns its key if it was still pending.
    pub fn cancel(&mut self, id: TimerId) -> Option<K> {
        let e = *self.entries.get(id.index as usize)?;
        if e.place == NIL || e.generation != id.generation {
            return None;
        }
        self.unlink(id.index);
        self.release(id.index);
        Some(e.key)
    }

    /// The deadline of a pending timer.
    pub fn deadline(&self, id: TimerId) -> Option<u64> {
        let e = self.entries.get(id.index as usize)?;
        (e.place != NIL && e.generation == id.generation).then_some(e.deadline)
    }

    /// Advances to tick `now`, calling `fire` for every timer whose
    /// deadline is ≤ `now`, in deadline order per tick.
    pub fn advance(&mut self, now: u64, mut fire: impl FnMut(K)) {
        for i in core::mem::take(&mut self.overdue) {
            if let Some(e) = self.entries.get(i as usize).copied()
                && e.place == OVERDUE
            {
                self.release(i);
                fire(e.key);
            }
        }
        while self.now < now {
            if self.live == 0 {
                self.now = now;
                return;
            }
            // Skip whole level-L slots that hold nothing below them.
            if let Some(next) = self.skip_target(now) {
                self.now = next;
                self.cascade();
                self.expire(&mut fire);
                continue;
            }
            self.now += 1;
            self.cascade();
            self.expire(&mut fire);
        }
    }

    /// When the lower levels are empty, the next tick at which something can
    /// happen is the next boundary of the lowest non-empty level.
    fn skip_target(&self, limit: u64) -> Option<u64> {
        if self.per_level.first().copied().unwrap_or(0) != 0 {
            return None;
        }
        let mut level = 1;
        while level < LEVELS && self.per_level.get(level).copied().unwrap_or(0) == 0 {
            level += 1;
        }
        // Entries only in level `level`: jump to its next slot boundary.
        let span = 1u64 << (BITS * level.min(LEVELS - 1) as u32);
        let next = (self.now / span + 1) * span;
        (next > self.now + 1).then_some(next.min(limit))
    }

    fn slot_of(&self, deadline: u64) -> (usize, usize) {
        let d = deadline.max(self.now + 1);
        let delta = d - self.now;
        let mut level = 0;
        while level + 1 < LEVELS && delta >= 1u64 << (BITS * (level as u32 + 1)) {
            level += 1;
        }
        let d = if level == LEVELS - 1 {
            // Beyond the wheel: park at the furthest slot, re-placed on cascade.
            d.min(self.now + (1u64 << (BITS * LEVELS as u32)) - 1)
        } else {
            d
        };
        (level, ((d >> (BITS * level as u32)) & MASK) as usize)
    }

    fn place(&mut self, i: u32) {
        let Some(deadline) = self.entries.get(i as usize).map(|e| e.deadline) else {
            return;
        };
        // Re-placed during a cascade at its own deadline: the current
        // level-0 slot, which `expire` processes right after.
        let (level, slot) = if deadline <= self.now {
            (0, (self.now & MASK) as usize)
        } else {
            self.slot_of(deadline)
        };
        let head = self
            .heads
            .get(level)
            .and_then(|l| l.get(slot))
            .copied()
            .unwrap_or(NIL);
        if let Some(e) = self.entries.get_mut(i as usize) {
            e.prev = NIL;
            e.next = head;
            e.place = (level * SLOTS + slot) as u32;
        }
        if let Some(h) = self.entries.get_mut(head as usize) {
            h.prev = i;
        }
        if let Some(h) = self.heads.get_mut(level).and_then(|l| l.get_mut(slot)) {
            *h = i;
        }
        if let Some(c) = self.per_level.get_mut(level) {
            *c += 1;
        }
    }

    fn unlink(&mut self, i: u32) {
        let Some(e) = self.entries.get(i as usize).copied() else {
            return;
        };
        if e.place == NIL {
            return;
        }
        if e.place == OVERDUE {
            self.overdue.retain(|&x| x != i);
            if let Some(x) = self.entries.get_mut(i as usize) {
                x.place = NIL;
            }
            return;
        }
        let (level, slot) = (e.place as usize / SLOTS, e.place as usize % SLOTS);
        match self.entries.get_mut(e.prev as usize) {
            Some(p) => p.next = e.next,
            None => {
                if let Some(h) = self.heads.get_mut(level).and_then(|l| l.get_mut(slot)) {
                    *h = e.next;
                }
            }
        }
        if let Some(n) = self.entries.get_mut(e.next as usize) {
            n.prev = e.prev;
        }
        if let Some(x) = self.entries.get_mut(i as usize) {
            x.place = NIL;
        }
        if let Some(c) = self.per_level.get_mut(level) {
            *c -= 1;
        }
    }

    fn release(&mut self, i: u32) {
        if let Some(e) = self.entries.get_mut(i as usize) {
            e.place = NIL;
            e.next = self.free;
        }
        self.free = i;
        self.live -= 1;
    }

    /// Takes the list of one slot.
    fn take(&mut self, level: usize, slot: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = self
            .heads
            .get(level)
            .and_then(|l| l.get(slot))
            .copied()
            .unwrap_or(NIL);
        while i != NIL {
            let next = self.entries.get(i as usize).map_or(NIL, |e| e.next);
            self.unlink(i);
            out.push(i);
            i = next;
        }
        out
    }

    /// Moves the entries of every higher-level slot that starts at `now`
    /// down the hierarchy (highest level first).
    fn cascade(&mut self) {
        for level in (1..LEVELS).rev() {
            let span = 1u64 << (BITS * level as u32);
            if !self.now.is_multiple_of(span) {
                continue;
            }
            let slot = ((self.now >> (BITS * level as u32)) & MASK) as usize;
            for i in self.take(level, slot) {
                self.place(i);
            }
        }
    }

    fn expire(&mut self, fire: &mut impl FnMut(K)) {
        let slot = (self.now & MASK) as usize;
        let mut due = self.take(0, slot);
        due.sort_by_key(|&i| self.entries.get(i as usize).map_or(0, |e| e.deadline));
        for i in due {
            let Some(e) = self.entries.get(i as usize).copied() else {
                continue;
            };
            if e.deadline <= self.now {
                self.release(i);
                fire(e.key);
            } else {
                self.place(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn fires_in_order_and_cancels() {
        let mut w: Wheel<u32> = Wheel::new(0);
        let a = w.insert(5, 1);
        w.insert(3, 2);
        w.insert(70, 3);
        w.insert(5000, 4);
        assert_eq!(w.cancel(a), Some(1));
        assert_eq!(w.cancel(a), None);
        let mut got = Vec::new();
        w.advance(10, |k| got.push(k));
        assert_eq!(got, [2]);
        w.advance(100, |k| got.push(k));
        assert_eq!(got, [2, 3]);
        w.advance(10_000, |k| got.push(k));
        assert_eq!(got, [2, 3, 4]);
        assert!(w.is_empty());
        // Past deadlines fire on the next advance.
        w.insert(1, 9);
        w.advance(10_001, |k| got.push(k));
        assert_eq!(got.last(), Some(&9));
    }

    #[test]
    fn stale_ids_never_cancel_a_reused_entry() {
        let mut w: Wheel<u32> = Wheel::new(0);
        let a = w.insert(10, 1);
        w.advance(10, |_| {});
        let b = w.insert(20, 2);
        assert_eq!(w.cancel(a), None);
        assert_eq!(w.deadline(b), Some(20));
    }

    /// Random inserts, cancels and advances against a reference model.
    #[test]
    fn matches_a_reference_model() {
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut w: Wheel<u64> = Wheel::new(1000);
        let mut model: BTreeMap<u64, (u64, TimerId)> = BTreeMap::new();
        let mut now = 1000u64;
        // Miri is for the memory model; the full run stays in the normal suite.
        let ops = if cfg!(miri) { 500 } else { 20_000u64 };
        for key in 0..ops {
            match next() % 10 {
                0..=5 => {
                    let span = [10, 100, 5_000, 300_000, 20_000_000][(next() % 5) as usize];
                    let d = now + next() % span;
                    let id = w.insert(d, key);
                    model.insert(key, (d, id));
                }
                6 => {
                    if let Some((&k, &(_, id))) = model
                        .iter()
                        .nth((next() % (model.len() as u64 + 1)) as usize)
                    {
                        assert_eq!(w.cancel(id), Some(k));
                        model.remove(&k);
                    }
                }
                _ => {
                    let step = [1, 7, 64, 4096, 300_000][(next() % 5) as usize];
                    now += next() % step;
                    let mut fired = Vec::new();
                    w.advance(now, |k| fired.push(k));
                    let mut want: Vec<u64> = model
                        .iter()
                        .filter(|(_, (d, _))| *d <= now)
                        .map(|(k, _)| *k)
                        .collect();
                    for k in &want {
                        model.remove(k);
                    }
                    fired.sort_unstable();
                    want.sort_unstable();
                    assert_eq!(fired, want, "at {now}");
                }
            }
            assert_eq!(w.len(), model.len());
        }
    }
}
