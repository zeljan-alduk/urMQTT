//! Compact per-connection building blocks (M15): buffers that cost one
//! pointer while empty, and an open-addressing client-id index that stores
//! 4 bytes per session instead of a second copy of the id.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// A byte buffer that is 8 bytes and allocation-free while empty.
#[derive(Default)]
#[allow(clippy::box_collection)]
pub struct Buf(Option<Box<Vec<u8>>>);

impl Buf {
    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }

    /// The vector, allocating it if needed. Call [`Buf::release`] after
    /// shrinking it.
    pub fn vec_mut(&mut self) -> &mut Vec<u8> {
        self.0.get_or_insert_with(Default::default)
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.vec_mut().extend_from_slice(data);
        }
    }

    /// Drops the first `n` bytes; frees the buffer once empty.
    pub fn consume(&mut self, n: usize) {
        if let Some(v) = self.0.as_mut() {
            v.drain(..n.min(v.len()));
        }
        self.release();
    }

    /// Frees the allocation if the buffer is empty.
    pub fn release(&mut self) {
        if self.0.as_ref().is_some_and(|v| v.is_empty()) {
            self.0 = None;
        }
    }

    /// Takes the contents out (the buffer is empty afterwards).
    pub fn take(&mut self) -> Vec<u8> {
        self.0.take().map(|b| *b).unwrap_or_default()
    }

    /// Puts contents back (an empty vector frees the buffer).
    pub fn set(&mut self, v: Vec<u8>) {
        self.0 = (!v.is_empty()).then(|| Box::new(v));
    }
}

const NIL: u32 = u32::MAX;
const TOMB: u32 = u32::MAX - 1;

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Client id → session id, open addressing with linear probing. The ids
/// themselves live in the sessions; lookups compare through `name_of`.
pub struct Index {
    slots: Vec<u32>,
    len: usize,
    tombs: usize,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            slots: vec![NIL; 16],
            len: 0,
            tombs: 0,
        }
    }
}

impl Index {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.len
    }

    fn mask(&self) -> usize {
        self.slots.len() - 1
    }

    pub fn get<'a>(&self, id: &str, name_of: impl Fn(u32) -> Option<&'a str>) -> Option<u32> {
        let mut i = (fnv1a(id) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                NIL => return None,
                TOMB => {}
                v => {
                    if name_of(v) == Some(id) {
                        return Some(v);
                    }
                }
            }
            i = (i + 1) & self.mask();
        }
        None
    }

    /// Inserts `sid` under `id` (which must not be present yet).
    pub fn insert<'a>(&mut self, id: &str, sid: u32, name_of: impl Fn(u32) -> Option<&'a str>) {
        if (self.len + self.tombs + 1) * 2 > self.slots.len() {
            let n = if (self.len + 1) * 4 > self.slots.len() {
                self.slots.len() * 2
            } else {
                self.slots.len()
            };
            self.rebuild(n, &name_of);
        }
        let mut i = (fnv1a(id) as usize) & self.mask();
        loop {
            match self.slots.get(i).copied() {
                Some(NIL) | Some(TOMB) => {
                    if self.slots.get(i) == Some(&TOMB) {
                        self.tombs -= 1;
                    }
                    if let Some(s) = self.slots.get_mut(i) {
                        *s = sid;
                    }
                    self.len += 1;
                    return;
                }
                Some(_) => i = (i + 1) & self.mask(),
                None => return,
            }
        }
    }

    pub fn remove<'a>(
        &mut self,
        id: &str,
        name_of: impl Fn(u32) -> Option<&'a str>,
    ) -> Option<u32> {
        let mut i = (fnv1a(id) as usize) & self.mask();
        for _ in 0..self.slots.len() {
            match self.slots.get(i).copied()? {
                NIL => return None,
                TOMB => {}
                v => {
                    if name_of(v) == Some(id) {
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

    /// Halves the table (repeatedly) while it is less than 1/8 full, so a
    /// past peak does not keep its slots (M16).
    pub fn shrink<'a>(&mut self, name_of: impl Fn(u32) -> Option<&'a str>) {
        let n = (self.len * 4).next_power_of_two().max(16);
        if n < self.slots.len() && self.len * 8 < self.slots.len() {
            self.rebuild(n, &name_of);
            self.slots.shrink_to_fit();
        }
    }

    fn rebuild<'a>(&mut self, n: usize, name_of: &impl Fn(u32) -> Option<&'a str>) {
        let old: Vec<u32> = self
            .slots
            .iter()
            .copied()
            .filter(|&v| v != NIL && v != TOMB)
            .collect();
        self.slots = vec![NIL; n.max(16)];
        self.len = 0;
        self.tombs = 0;
        for v in old {
            let Some(id) = name_of(v) else { continue };
            let mut i = (fnv1a(id) as usize) & self.mask();
            while self.slots.get(i).is_some_and(|s| *s != NIL) {
                i = (i + 1) & self.mask();
            }
            if let Some(s) = self.slots.get_mut(i) {
                *s = v;
            }
            self.len += 1;
        }
    }
}

/// A short list kept for its owner's lifetime (a session's subscriptions):
/// one element inline — the common device case, no heap block at all —
/// more on the heap, exactly sized (they change rarely).
pub enum Small<T: Copy> {
    One(T),
    /// Also the empty list (an empty box does not allocate).
    Many(Box<[T]>),
}

impl<T: Copy> Default for Small<T> {
    fn default() -> Self {
        Self::Many(Box::default())
    }
}

impl<T: Copy> Small<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(t) => core::slice::from_ref(t),
            Self::Many(b) => b,
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Self::One(t) => core::slice::from_mut(t),
            Self::Many(b) => b,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn set(&mut self, mut v: Vec<T>) {
        *self = match v.as_slice() {
            [one] => Self::One(*one),
            _ => {
                v.shrink_to_fit();
                Self::Many(v.into_boxed_slice())
            }
        };
    }

    pub fn push(&mut self, t: T) {
        let mut v = self.as_slice().to_vec();
        v.push(t);
        self.set(v);
    }

    pub fn remove(&mut self, i: usize) -> Option<T> {
        let mut v = self.as_slice().to_vec();
        let t = (i < v.len()).then(|| v.remove(i));
        self.set(v);
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn buf_frees_when_empty() {
        let mut b = Buf::default();
        assert!(b.is_empty() && b.0.is_none());
        b.extend_from_slice(b"abc");
        b.consume(2);
        assert_eq!(b.as_slice(), b"c");
        b.consume(5);
        assert!(b.0.is_none());
        b.set(Vec::new());
        assert!(b.0.is_none());
        assert_eq!(core::mem::size_of::<Buf>(), 8);
    }

    #[test]
    fn index_matches_a_map() {
        let names: Vec<String> = (0..5000).map(|i| format!("device-{i:05}")).collect();
        let mut live: HashMap<u32, usize> = HashMap::new();
        let mut idx = Index::default();
        let mut x = 7u64;
        for step in 0..60_000u32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % names.len() as u64) as usize;
            let present = live.values().any(|&v| v == n);
            // Session ids are recycled like the broker's slots.
            let sid = step % 4096;
            if present {
                let sid = *live.iter().find(|(_, v)| **v == n).unwrap().0;
                let snapshot = live.clone();
                assert_eq!(
                    idx.remove(&names[n], |s| snapshot.get(&s).map(|&i| names[i].as_str())),
                    Some(sid)
                );
                live.remove(&sid);
            } else if let std::collections::hash_map::Entry::Vacant(e) = live.entry(sid) {
                e.insert(n);
                let snapshot = live.clone();
                idx.insert(&names[n], sid, |s| {
                    snapshot.get(&s).map(|&i| names[i].as_str())
                });
            }
            let snapshot = live.clone();
            let got = idx.get(&names[n], |s| snapshot.get(&s).map(|&i| names[i].as_str()));
            assert_eq!(got, live.iter().find(|(_, v)| **v == n).map(|(k, _)| *k));
        }
        assert_eq!(idx.len(), live.len());
    }

    #[test]
    fn small_list_keeps_one_inline() {
        let mut l: Small<u64> = Small::default();
        assert!(l.is_empty());
        l.push(1);
        assert!(matches!(l, Small::One(1)));
        l.push(2);
        l.push(3);
        assert_eq!(l.as_slice(), &[1, 2, 3]);
        l.as_mut_slice()[0] = 9;
        assert_eq!(l.remove(1), Some(2));
        assert_eq!(l.remove(5), None);
        assert_eq!(l.as_slice(), &[9, 3]);
        assert_eq!(l.remove(0), Some(9));
        assert!(matches!(l, Small::One(3)));
        assert_eq!(l.remove(0), Some(3));
        assert!(l.is_empty());
    }
}
