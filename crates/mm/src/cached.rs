//! Per-CPU allocation caches in front of the global buddy heap (M13, the
//! "per-core slabs" of PROMPT §7.2, ADR-032).
//!
//! Small blocks (≤ 2 KiB, 7 power-of-two classes matching the buddy
//! orders) come from the current CPU's free lists. Refills and drains move
//! [`BATCH`] blocks under the global lock at once, so on the data path the
//! lock is taken roughly once per sixteen small allocations. A block freed on
//! another CPU simply joins that CPU's cache. With a ticket lock and
//! virtual CPUs, that cut is what keeps cores from queueing behind a
//! descheduled lock holder.
//!
//! The local lists are touched with IRQs masked, so an interrupt handler
//! on the same CPU can never see them half updated.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;

use urmqtt_arch_aarch64::sync::OnceCell;

use crate::LockedHeap;

/// Block sizes, one per buddy order from `buddy::MIN_ORDER`.
pub const CLASSES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];
pub const MAX_CPUS: usize = 64;
/// Blocks moved per refill or drain.
pub const BATCH: usize = 16;
/// Bytes a CPU keeps per class before it returns half.
pub const KEEP_BYTES: usize = 32 * 1024;

/// How the cache learns the current CPU and keeps interrupts out.
pub struct Hooks {
    pub cpu: fn() -> usize,
    pub irq_save: fn() -> u64,
    pub irq_restore: fn(u64),
}

#[derive(Clone, Copy)]
struct List {
    /// First free block; each free block stores the next pointer.
    head: *mut u8,
    count: usize,
}

struct Cache {
    lists: [List; CLASSES.len()],
}

pub struct CachedHeap {
    global: LockedHeap,
    caches: [UnsafeCell<Cache>; MAX_CPUS],
    hooks: OnceCell<Hooks>,
}

// SAFETY: each `caches[i]` is only touched by CPU `i` with IRQs masked
// (see `with_cache`), and the global heap has its own lock.
unsafe impl Sync for CachedHeap {}

/// Class index for a layout, if it is small enough to cache. The class is
/// the buddy block the global heap would hand out for this layout.
pub fn class_of(layout: Layout) -> Option<usize> {
    let need = layout
        .size()
        .max(layout.align())
        .max(CLASSES[0])
        .checked_next_power_of_two()?;
    CLASSES.iter().position(|&c| c == need)
}

impl CachedHeap {
    pub const fn new() -> Self {
        Self {
            global: LockedHeap::new(),
            caches: [const {
                UnsafeCell::new(Cache {
                    lists: [List {
                        head: null_mut(),
                        count: 0,
                    }; CLASSES.len()],
                })
            }; MAX_CPUS],
            hooks: OnceCell::new(),
        }
    }

    pub fn init(&self, heap: crate::buddy::BuddyHeap) {
        self.global.init(heap);
    }

    /// Turns the per-CPU caches on. Before this every request goes to the
    /// global heap.
    pub fn enable(&self, hooks: Hooks) {
        let _ = self.hooks.set(hooks);
    }

    /// (free bytes, capacity) of the global heap (cached blocks count as used).
    pub fn stats(&self) -> Option<(usize, usize)> {
        self.global.stats()
    }

    /// Runs `f` on the current CPU's cache with IRQs masked.
    fn with_cache<R>(&self, f: impl FnOnce(&mut Cache) -> R) -> Option<R> {
        let h = self.hooks.get()?;
        let flags = (h.irq_save)();
        let cpu = (h.cpu)();
        let r = self.caches.get(cpu).map(|c| {
            // SAFETY: only this CPU uses `caches[cpu]`, and IRQs are masked,
            // so nothing else on this CPU can run in between.
            f(unsafe { &mut *c.get() })
        });
        (h.irq_restore)(flags);
        r
    }

    fn refill(&self, list: &mut List, size: usize) {
        let Ok(layout) = Layout::from_size_align(size, size) else {
            return;
        };
        for _ in 0..BATCH {
            // SAFETY: a valid, non-zero layout.
            let p = unsafe { self.global.alloc(layout) };
            if p.is_null() {
                break;
            }
            // SAFETY: `p` is a fresh block of `size` >= 32 bytes, aligned to
            // `size`, so it can hold the next pointer.
            unsafe { p.cast::<*mut u8>().write(list.head) };
            list.head = p;
            list.count += 1;
        }
    }

    fn drain(&self, list: &mut List, size: usize, keep: usize) {
        let Ok(layout) = Layout::from_size_align(size, size) else {
            return;
        };
        while list.count > keep && !list.head.is_null() {
            let p = list.head;
            // SAFETY: `p` is a free block of this list holding the next pointer.
            list.head = unsafe { p.cast::<*mut u8>().read() };
            list.count -= 1;
            // SAFETY: every block in a class list was allocated from the
            // global heap with exactly this layout (see `class_of`).
            unsafe { self.global.dealloc(p, layout) };
        }
    }
}

impl Default for CachedHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: small blocks are buddy blocks of their class (`class_of` matches
// the buddy's own rounding), so a block may be served from or returned to
// any CPU's list and finally to the global heap with the class layout.
unsafe impl GlobalAlloc for CachedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(c) = class_of(layout) {
            let size = CLASSES.get(c).copied().unwrap_or(0);
            let r = self.with_cache(|cache| {
                let list = cache.lists.get_mut(c)?;
                if list.head.is_null() {
                    self.refill(list, size);
                }
                let p = list.head;
                if p.is_null() {
                    return None;
                }
                // SAFETY: `p` is a free block of this list holding the next pointer.
                list.head = unsafe { p.cast::<*mut u8>().read() };
                list.count -= 1;
                Some(p)
            });
            if let Some(p) = r {
                return p.unwrap_or(null_mut());
            }
        }
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.global.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(c) = class_of(layout) {
            let size = CLASSES.get(c).copied().unwrap_or(0);
            let done = self.with_cache(|cache| {
                let Some(list) = cache.lists.get_mut(c) else {
                    return false;
                };
                // SAFETY: `ptr` is a block of `size` bytes we own again.
                unsafe { ptr.cast::<*mut u8>().write(list.head) };
                list.head = ptr;
                list.count += 1;
                if list.count * size > KEEP_BYTES {
                    let keep = list.count.saturating_sub(BATCH);
                    self.drain(list, size, keep);
                }
                true
            });
            if done == Some(true) {
                return;
            }
        }
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.global.dealloc(ptr, layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_match_buddy_rounding() {
        let l = |s, a| Layout::from_size_align(s, a).unwrap();
        assert_eq!(class_of(l(1, 1)), Some(0));
        assert_eq!(class_of(l(32, 8)), Some(0));
        assert_eq!(class_of(l(33, 8)), Some(1));
        assert_eq!(class_of(l(16, 64)), Some(1));
        assert_eq!(class_of(l(2048, 8)), Some(6));
        assert_eq!(class_of(l(2049, 8)), None);
        assert_eq!(class_of(l(8, 4096)), None);
    }
}
