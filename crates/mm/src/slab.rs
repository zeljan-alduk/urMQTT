//! A slab of `T` in chunks with a free list (M15): ids are dense `u32`s,
//! insert and remove are O(1), and capacity grows one chunk at a time, so
//! unused capacity stays below one chunk however many connections there
//! are (a doubling `Vec` wastes up to half). A chunk holds as many entries
//! as fit one 8 KiB heap block, so the buddy heap's power-of-two rounding
//! costs well under 1 % instead of up to a third.
//!
//! Free ids are handed out lowest first, so after a peak (a reconnect
//! storm) the entries left gather at the front and [`Slab::shrink`] can
//! return the empty chunks at the end to the heap (M16).

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Reverse;

/// Bytes per chunk: one buddy block.
pub const CHUNK_BYTES: usize = 8192;

pub struct Slab<T> {
    chunks: Vec<Box<[Option<T>]>>,
    /// Entries per chunk, so empty chunks are found without a scan.
    counts: Vec<u16>,
    /// Free ids of `insert`, lowest first.
    free: BinaryHeap<Reverse<u32>>,
    len: usize,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Slab<T> {
    /// Entries per chunk.
    pub const CHUNK: usize = {
        let size = core::mem::size_of::<Option<T>>();
        if size == 0 || size >= CHUNK_BYTES {
            1
        } else {
            CHUNK_BYTES / size
        }
    };

    pub const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            counts: Vec::new(),
            free: BinaryHeap::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot(&self, k: u32) -> Option<&Option<T>> {
        let k = k as usize;
        self.chunks.get(k / Self::CHUNK)?.get(k % Self::CHUNK)
    }

    fn slot_mut(&mut self, k: u32) -> Option<&mut Option<T>> {
        let k = k as usize;
        self.chunks
            .get_mut(k / Self::CHUNK)?
            .get_mut(k % Self::CHUNK)
    }

    fn add_chunk(&mut self) {
        self.chunks.push((0..Self::CHUNK).map(|_| None).collect());
        self.counts.push(0);
    }

    fn grow(&mut self) {
        let base = (self.chunks.len() * Self::CHUNK) as u32;
        self.add_chunk();
        self.free
            .extend((base..base + Self::CHUNK as u32).map(Reverse));
    }

    fn count(&mut self, k: u32, delta: i32) {
        if let Some(c) = self.counts.get_mut(k as usize / Self::CHUNK) {
            *c = (i32::from(*c) + delta) as u16;
        }
    }

    /// Returns the empty chunks at the end to the heap; the number freed.
    /// Callers run it periodically (it is O(free ids) when it frees).
    pub fn shrink(&mut self) -> usize {
        let before = self.chunks.len();
        while self.counts.last() == Some(&0) {
            self.chunks.pop();
            self.counts.pop();
        }
        let freed = before - self.chunks.len();
        if freed > 0 {
            let limit = (self.chunks.len() * Self::CHUNK) as u32;
            let mut ids = core::mem::take(&mut self.free).into_vec();
            ids.retain(|Reverse(k)| *k < limit);
            ids.shrink_to_fit();
            self.free = BinaryHeap::from(ids);
            self.chunks.shrink_to_fit();
            self.counts.shrink_to_fit();
        }
        freed
    }

    pub fn get(&self, k: u32) -> Option<&T> {
        self.slot(k)?.as_ref()
    }

    pub fn get_mut(&mut self, k: u32) -> Option<&mut T> {
        self.slot_mut(k)?.as_mut()
    }

    pub fn contains(&self, k: u32) -> bool {
        self.get(k).is_some()
    }

    /// Stores `v` under a free id and returns it.
    pub fn insert(&mut self, v: T) -> u32 {
        loop {
            if self.free.is_empty() {
                self.grow();
            }
            let Some(Reverse(k)) = self.free.pop() else {
                continue;
            };
            if let Some(slot) = self.slot_mut(k)
                && slot.is_none()
            {
                *slot = Some(v);
                self.len += 1;
                self.count(k, 1);
                return k;
            }
        }
    }

    /// Stores `v` under the id `k` chosen elsewhere (e.g. a TCP connection
    /// id); replaces what was there.
    pub fn insert_at(&mut self, k: u32, v: T) {
        while (k as usize) >= self.chunks.len() * Self::CHUNK {
            self.add_chunk();
        }
        let mut added = false;
        if let Some(slot) = self.slot_mut(k) {
            added = slot.is_none();
            *slot = Some(v);
        }
        if added {
            self.len += 1;
            self.count(k, 1);
        }
    }

    pub fn remove(&mut self, k: u32) -> Option<T> {
        let v = self.slot_mut(k)?.take()?;
        self.len -= 1;
        self.count(k, -1);
        self.free.push(Reverse(k));
        Some(v)
    }

    /// Removes an entry stored with `insert_at` (its id is not reused by
    /// `insert`, the caller owns the id space).
    pub fn take_at(&mut self, k: u32) -> Option<T> {
        let v = self.slot_mut(k)?.take()?;
        self.len -= 1;
        self.count(k, -1);
        Some(v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        self.chunks.iter().enumerate().flat_map(|(c, ch)| {
            ch.iter()
                .enumerate()
                .filter_map(move |(i, v)| v.as_ref().map(|v| ((c * Self::CHUNK + i) as u32, v)))
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut T)> {
        self.chunks.iter_mut().enumerate().flat_map(|(c, ch)| {
            ch.iter_mut()
                .enumerate()
                .filter_map(move |(i, v)| v.as_mut().map(|v| ((c * Self::CHUNK + i) as u32, v)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn behaves_like_a_map_and_reuses_ids() {
        let mut s: Slab<u64> = Slab::new();
        let mut m: HashMap<u32, u64> = HashMap::new();
        let mut x = 3u64;
        for i in 0..100_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if x % 3 == 0 && !m.is_empty() {
                let k = *m.keys().next().unwrap();
                assert_eq!(s.remove(k), m.remove(&k));
            } else {
                let k = s.insert(i);
                assert!(m.insert(k, i).is_none(), "id {k} handed out twice");
            }
            assert_eq!(s.len(), m.len());
        }
        for (k, v) in &m {
            assert_eq!(s.get(*k), Some(v));
        }
        assert_eq!(s.iter().count(), m.len());
        // Capacity stays within a chunk of the peak.
        assert!(s.chunks.len() * Slab::<u64>::CHUNK < m.len().max(1) * 3 + Slab::<u64>::CHUNK);
        s.insert_at(1000, 7);
        assert_eq!(s.get(1000), Some(&7));
        assert_eq!(s.take_at(1000), Some(7));
    }

    #[test]
    fn ids_lowest_first_and_tail_chunks_freed() {
        let mut s: Slab<u64> = Slab::new();
        let per = Slab::<u64>::CHUNK as u32;
        let ids: Vec<u32> = (0..per * 5).map(|i| s.insert(u64::from(i))).collect();
        assert_eq!(ids, (0..per * 5).collect::<Vec<_>>());
        // A storm leaves a few scattered entries; the rest go.
        for k in 0..per * 5 {
            if k % 7 != 0 || k >= per * 2 {
                s.remove(k);
            }
        }
        assert_eq!(s.shrink(), 3, "the three empty chunks at the end");
        assert_eq!(s.chunks.len(), 2);
        // New entries fill the holes at the front first.
        assert_eq!(s.insert(1), 1);
        s.insert_at(per * 4, 9);
        assert_eq!(s.get(per * 4), Some(&9));
        assert_eq!(s.shrink(), 0);
        assert_eq!(s.take_at(per * 4), Some(9));
        assert_eq!(s.shrink(), 3);
        for (k, _) in s.iter().map(|(k, v)| (k, *v)).collect::<Vec<_>>() {
            s.remove(k);
        }
        assert_eq!(s.shrink(), 2);
        assert!(s.is_empty());
        assert_eq!(s.insert(5), 0);
    }

    #[test]
    fn chunks_fill_one_heap_block() {
        assert_eq!(Slab::<[u8; 96]>::CHUNK, 84);
        assert_eq!(Slab::<u32>::CHUNK, 1024);
        assert_eq!(Slab::<[u8; 9000]>::CHUNK, 1);
        assert_eq!(Slab::<()>::CHUNK, 8192);
    }
}
