//! Per-core connection table: open addressing with linear probing on the
//! 4-tuple (remote address and port, local port), O(1) expected lookup,
//! tombstones on removal, rebuilt when tombstones accumulate.

use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub addr: [u8; 4],
    pub rport: u16,
    pub lport: u16,
}

const EMPTY: u32 = u32::MAX;
const TOMB: u32 = u32::MAX - 1;

pub struct Table {
    /// Connection indices, `EMPTY` or `TOMB`.
    slots: Vec<u32>,
    keys: Vec<Key>,
    len: usize,
    tombs: usize,
    seed: u64,
}

fn mix(k: &Key, seed: u64) -> u64 {
    let mut h = seed ^ 0x9e37_79b9_7f4a_7c15;
    let v = u64::from(u32::from_be_bytes(k.addr))
        | (u64::from(k.rport) << 32)
        | (u64::from(k.lport) << 48);
    h ^= v;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 31;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 29)
}

impl Table {
    /// A table for up to `capacity` connections (kept at most half full).
    pub fn new(capacity: usize, seed: u64) -> Self {
        let n = (capacity.max(8) * 2).next_power_of_two();
        Self {
            slots: vec![EMPTY; n],
            keys: vec![
                Key {
                    addr: [0; 4],
                    rport: 0,
                    lport: 0
                };
                n
            ],
            len: 0,
            tombs: 0,
            seed,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether another entry fits (half-full limit).
    pub fn has_room(&self) -> bool {
        (self.len + 1) * 2 <= self.slots.len()
    }

    fn mask(&self) -> usize {
        self.slots.len() - 1
    }

    pub fn get(&self, k: &Key) -> Option<u32> {
        let mut i = (mix(k, self.seed) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                EMPTY => return None,
                TOMB => {}
                v => {
                    if self.keys.get(i) == Some(k) {
                        return Some(v);
                    }
                }
            }
            i = (i + 1) & self.mask();
        }
        None
    }

    /// Inserts a new key (callers check `get` first). False if full.
    pub fn insert(&mut self, k: Key, v: u32) -> bool {
        if !self.has_room() {
            return false;
        }
        if (self.len + self.tombs + 1) * 4 > self.slots.len() * 3 {
            self.rebuild();
        }
        let mut i = (mix(&k, self.seed) as usize) & self.mask();
        loop {
            match self.slots.get(i).copied() {
                Some(EMPTY) | Some(TOMB) => {
                    if self.slots.get(i) == Some(&TOMB) {
                        self.tombs -= 1;
                    }
                    if let (Some(s), Some(key)) = (self.slots.get_mut(i), self.keys.get_mut(i)) {
                        *s = v;
                        *key = k;
                    }
                    self.len += 1;
                    return true;
                }
                Some(_) => i = (i + 1) & self.mask(),
                None => return false,
            }
        }
    }

    pub fn remove(&mut self, k: &Key) -> Option<u32> {
        let mut i = (mix(k, self.seed) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                EMPTY => return None,
                TOMB => {}
                v => {
                    if self.keys.get(i) == Some(k) {
                        if let Some(s) = self.slots.get_mut(i) {
                            *s = TOMB;
                        }
                        self.len -= 1;
                        self.tombs += 1;
                        return Some(v);
                    }
                }
            }
            i = (i + 1) & self.mask();
        }
        None
    }

    fn rebuild(&mut self) {
        let old: Vec<(Key, u32)> = self
            .slots
            .iter()
            .zip(&self.keys)
            .filter(|(s, _)| **s != EMPTY && **s != TOMB)
            .map(|(s, k)| (*k, *s))
            .collect();
        self.slots.fill(EMPTY);
        self.len = 0;
        self.tombs = 0;
        for (k, v) in old {
            let mut i = (mix(&k, self.seed) as usize) & self.mask();
            while self.slots.get(i).is_some_and(|s| *s != EMPTY) {
                i = (i + 1) & self.mask();
            }
            if let (Some(s), Some(key)) = (self.slots.get_mut(i), self.keys.get_mut(i)) {
                *s = v;
                *key = k;
            }
            self.len += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn behaves_like_a_map_under_churn() {
        let mut t = Table::new(1000, 42);
        let mut m: HashMap<Key, u32> = HashMap::new();
        let mut x = 1u64;
        for i in 0..200_000u32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let k = Key {
                addr: [10, 0, (x >> 8) as u8 & 3, (x >> 16) as u8],
                rport: (x >> 24) as u16 % 2000,
                lport: 8883,
            };
            if x % 3 == 0 || m.len() >= 1000 {
                assert_eq!(t.remove(&k), m.remove(&k));
            } else if let std::collections::hash_map::Entry::Vacant(e) = m.entry(k) {
                assert!(t.insert(k, i));
                e.insert(i);
            }
            assert_eq!(t.get(&k), m.get(&k).copied());
            assert_eq!(t.len(), m.len());
        }
        for (k, v) in &m {
            assert_eq!(t.get(k), Some(*v));
        }
    }
}
