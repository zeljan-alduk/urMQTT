//! Per-core connection table: open addressing with linear probing on the
//! 4-tuple (remote address and port, local port), O(1) expected lookup,
//! tombstones on removal. Slots hold only the connection index (4 bytes);
//! the key lives in the connection and is read back through `key_of`
//! (M15: 8 bytes per connection at the half-full limit instead of 24).

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
    len: usize,
    tombs: usize,
    seed: u64,
    /// Most entries ever allowed.
    max: usize,
}

pub(crate) fn mix(k: &Key, seed: u64) -> u64 {
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
    /// It starts small and doubles as connections arrive, so an idle stack
    /// costs a few KiB however large `capacity` is.
    pub fn new(capacity: usize, seed: u64) -> Self {
        let n = (capacity.max(8) * 2).next_power_of_two().min(1024);
        Self {
            max: capacity.max(8),
            slots: vec![EMPTY; n],
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

    /// Whether another entry fits.
    pub fn has_room(&self) -> bool {
        self.len < self.max
    }

    fn mask(&self) -> usize {
        self.slots.len() - 1
    }

    pub fn get(&self, k: &Key, key_of: impl Fn(u32) -> Option<Key>) -> Option<u32> {
        let mut i = (mix(k, self.seed) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                EMPTY => return None,
                TOMB => {}
                v => {
                    if key_of(v).as_ref() == Some(k) {
                        return Some(v);
                    }
                }
            }
            i = (i + 1) & self.mask();
        }
        None
    }

    /// Inserts connection `v` (whose key `key_of(v)` must already return
    /// `k`; callers check `get` first). False if full.
    pub fn insert(&mut self, k: Key, v: u32, key_of: impl Fn(u32) -> Option<Key>) -> bool {
        if !self.has_room() {
            return false;
        }
        if (self.len + 1) * 2 > self.slots.len() {
            self.rebuild(self.slots.len() * 2, &key_of);
        } else if (self.len + self.tombs + 1) * 4 > self.slots.len() * 3 {
            self.rebuild(self.slots.len(), &key_of);
        }
        let mut i = (mix(&k, self.seed) as usize) & self.mask();
        loop {
            match self.slots.get(i).copied() {
                Some(EMPTY) | Some(TOMB) => {
                    if self.slots.get(i) == Some(&TOMB) {
                        self.tombs -= 1;
                    }
                    if let Some(s) = self.slots.get_mut(i) {
                        *s = v;
                    }
                    self.len += 1;
                    return true;
                }
                Some(_) => i = (i + 1) & self.mask(),
                None => return false,
            }
        }
    }

    pub fn remove(&mut self, k: &Key, key_of: impl Fn(u32) -> Option<Key>) -> Option<u32> {
        let mut i = (mix(k, self.seed) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                EMPTY => return None,
                TOMB => {}
                v => {
                    if key_of(v).as_ref() == Some(k) {
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

    /// Halves the table (repeatedly) while it is less than 1/8 full, down
    /// to the initial size, so a past peak does not keep its slots (M16).
    pub fn shrink(&mut self, key_of: impl Fn(u32) -> Option<Key>) {
        let n = (self.len * 4).next_power_of_two().max(1024);
        if n < self.slots.len() && self.len * 8 < self.slots.len() {
            self.rebuild(n, &key_of);
            self.slots.shrink_to_fit();
        }
    }

    fn rebuild(&mut self, n: usize, key_of: &impl Fn(u32) -> Option<Key>) {
        let old: Vec<u32> = self
            .slots
            .iter()
            .copied()
            .filter(|&s| s != EMPTY && s != TOMB)
            .collect();
        self.slots = vec![EMPTY; n];
        self.len = 0;
        self.tombs = 0;
        for v in old {
            let Some(k) = key_of(v) else { continue };
            let mut i = (mix(&k, self.seed) as usize) & self.mask();
            while self.slots.get(i).is_some_and(|s| *s != EMPTY) {
                i = (i + 1) & self.mask();
            }
            if let Some(s) = self.slots.get_mut(i) {
                *s = v;
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
        // The connections' keys, as the stack keeps them.
        let mut keys: HashMap<u32, Key> = HashMap::new();
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
                let snap = keys.clone();
                let got = t.remove(&k, |v| snap.get(&v).copied());
                assert_eq!(got, m.remove(&k));
                if let Some(v) = got {
                    keys.remove(&v);
                }
            } else if let std::collections::hash_map::Entry::Vacant(e) = m.entry(k) {
                keys.insert(i, k);
                let snap = keys.clone();
                assert!(t.insert(k, i, |v| snap.get(&v).copied()));
                e.insert(i);
            }
            let snap = keys.clone();
            assert_eq!(t.get(&k, |v| snap.get(&v).copied()), m.get(&k).copied());
            assert_eq!(t.len(), m.len());
        }
    }
}
