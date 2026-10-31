//! The key slab (H4, ADR-170): fixed slots for long-lived secrets, outside
//! the heap, zeroed when freed.
//!
//! Why not the heap: a secret on the heap shares pages and neighbours with
//! everything else, travels through `Vec` growth and moves, and is wiped
//! only if every owner remembers to. Here a secret is written once into a
//! slot that never moves, read through a closure (so no copy is handed
//! out), and the slot is overwritten with zeros (volatile writes, then a
//! fence) when it is freed. A handle is a slot index plus a generation:
//! freeing bumps the generation, so a stale handle (use after free, double
//! free) is refused instead of reading or wiping whatever lives there now.

#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, compiler_fence};

use urmqtt_sync::sync::SpinLock;

/// Handle to a stored key. Not `Clone`: one owner, freed once.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a key left in the slab is never wiped"]
pub struct KeyHandle {
    index: u16,
    generation: u32,
}

impl KeyHandle {
    /// The parts of the handle, for tests that present a stale one.
    pub fn raw(&self) -> (u16, u32) {
        (self.index, self.generation)
    }

    /// A handle made from its parts (the stale-handle tests).
    pub fn from_raw(index: u16, generation: u32) -> Self {
        Self { index, generation }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Every slot is in use.
    Full,
    /// The handle is not (or no longer) a live slot: freed already, or never
    /// issued.
    Stale,
}

struct Slot<const BYTES: usize> {
    generation: u32,
    live: bool,
    data: [u8; BYTES],
}

/// `SLOTS` secrets of `BYTES` bytes each.
pub struct KeySlab<const BYTES: usize, const SLOTS: usize> {
    slots: SpinLock<[Slot<BYTES>; SLOTS]>,
}

/// Overwrites `buf` with zeros in a way the compiler may not remove.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl<const BYTES: usize, const SLOTS: usize> KeySlab<BYTES, SLOTS> {
    pub const fn new() -> Self {
        Self {
            slots: SpinLock::new(
                [const {
                    Slot {
                        generation: 0,
                        live: false,
                        data: [0; BYTES],
                    }
                }; SLOTS],
            ),
        }
    }

    /// Copies `key` into a free slot. The caller wipes its own copy.
    pub fn store(&self, key: &[u8; BYTES]) -> Result<KeyHandle, KeyError> {
        let mut g = self.slots.lock();
        let (i, s) = g
            .iter_mut()
            .enumerate()
            .find(|(_, s)| !s.live)
            .ok_or(KeyError::Full)?;
        s.data = *key;
        s.live = true;
        Ok(KeyHandle {
            index: i as u16,
            generation: s.generation,
        })
    }

    /// Runs `f` on the key, in place.
    pub fn with<R>(&self, h: &KeyHandle, f: impl FnOnce(&[u8; BYTES]) -> R) -> Result<R, KeyError> {
        let g = self.slots.lock();
        let s = g.get(h.index as usize).ok_or(KeyError::Stale)?;
        if !s.live || s.generation != h.generation {
            return Err(KeyError::Stale);
        }
        Ok(f(&s.data))
    }

    /// Wipes the slot and invalidates every handle to it.
    pub fn free(&self, h: KeyHandle) -> Result<(), KeyError> {
        let mut g = self.slots.lock();
        let s = g.get_mut(h.index as usize).ok_or(KeyError::Stale)?;
        if !s.live || s.generation != h.generation {
            return Err(KeyError::Stale);
        }
        wipe(&mut s.data);
        s.live = false;
        s.generation = s.generation.wrapping_add(1);
        Ok(())
    }

    /// Live slots.
    pub fn live(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.live).count()
    }

    /// Whether every byte of every slot that is not live is zero: the
    /// property the dev hook and the tests check ("zero on free").
    pub fn free_slots_are_zero(&self) -> bool {
        self.slots
            .lock()
            .iter()
            .filter(|s| !s.live)
            .all(|s| s.data.iter().all(|&b| b == 0))
    }

    /// Number of free slots checked by [`free_slots_are_zero`](Self::free_slots_are_zero).
    pub fn free_slots(&self) -> usize {
        SLOTS - self.live()
    }
}

impl<const BYTES: usize, const SLOTS: usize> Default for KeySlab<BYTES, SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0xA5; 32];

    #[test]
    fn store_read_free_and_the_slot_is_zero() {
        let s: KeySlab<32, 4> = KeySlab::new();
        let h = s.store(&KEY).unwrap_or_else(|_| unreachable!());
        assert_eq!(s.live(), 1);
        assert_eq!(s.with(&h, |k| *k), Ok(KEY));
        assert!(s.free_slots_are_zero());
        assert_eq!(s.free(h), Ok(()));
        assert_eq!(s.live(), 0);
        // Every slot is zero again, including the one that held the key.
        assert!(s.free_slots_are_zero());
        assert_eq!(s.free_slots(), 4);
    }

    #[test]
    fn stale_handles_are_refused() {
        let s: KeySlab<32, 2> = KeySlab::new();
        let h = s.store(&KEY).unwrap_or_else(|_| unreachable!());
        let (i, g) = h.raw();
        assert_eq!(s.free(h), Ok(()));
        // Double free and use after free through a copy of the old handle.
        assert_eq!(s.free(KeyHandle::from_raw(i, g)), Err(KeyError::Stale));
        assert_eq!(
            s.with(&KeyHandle::from_raw(i, g), |k| *k),
            Err(KeyError::Stale)
        );
        // The slot is reused under a new generation; the old handle still
        // does not reach the new key, and cannot wipe it.
        let h2 = s.store(&[7; 32]).unwrap_or_else(|_| unreachable!());
        assert_eq!(h2.raw().0, i);
        assert_ne!(h2.raw().1, g);
        assert_eq!(s.free(KeyHandle::from_raw(i, g)), Err(KeyError::Stale));
        assert_eq!(s.with(&h2, |k| k[0]), Ok(7));
        assert_eq!(s.free(h2), Ok(()));
        // Out of range.
        assert_eq!(s.free(KeyHandle::from_raw(99, 0)), Err(KeyError::Stale));
    }

    #[test]
    fn fills_up_and_recovers() {
        let s: KeySlab<16, 3> = KeySlab::new();
        let hs: Vec<_> = (0..3)
            .map(|i| {
                s.store(&[i as u8 + 1; 16])
                    .unwrap_or_else(|_| unreachable!())
            })
            .collect();
        assert!(matches!(s.store(&[9; 16]), Err(KeyError::Full)));
        for h in hs {
            assert_eq!(s.free(h), Ok(()));
        }
        assert!(s.free_slots_are_zero());
        assert!(s.store(&[9; 16]).is_ok());
    }

    #[test]
    fn wipe_clears_a_buffer() {
        let mut b = [0xFFu8; 100];
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
    }
}
