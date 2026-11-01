//! Physical frame allocator, kernel heap, per-CPU slab allocators and buffer pools.
//!
//! - [`BumpFrames`]: early allocator used before the memory map is processed.
//! - [`frames::FrameAllocator`]: bitmap allocator for all physical RAM.
//! - [`buddy::BuddyHeap`] behind [`LockedHeap`]: the kernel `GlobalAlloc`.
//!
//! - [`CachedHeap`]: per-CPU caches of small blocks in front of it (M13).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

pub mod buddy;
pub mod cached;
pub mod frames;
pub mod keyslab;
pub mod slab;

pub use cached::CachedHeap;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use urmqtt_sync::frame::{FrameSource, PAGE_SIZE};
use urmqtt_sync::sync::SpinLock;

/// Hands out frames downwards from the top of one physical range. Frames are
/// never freed; the range is retired when the real allocator takes over.
#[derive(Debug, Clone)]
pub struct BumpFrames {
    base: u64,
    top: u64,
}

impl BumpFrames {
    /// `[base, base + len)` rounded inwards to page boundaries.
    pub fn new(base: u64, len: u64) -> Self {
        let (Some(start), Some(end)) = (
            base.checked_next_multiple_of(PAGE_SIZE),
            base.checked_add(len),
        ) else {
            return Self { base: 0, top: 0 };
        };
        let end = end / PAGE_SIZE * PAGE_SIZE;
        Self {
            base: start,
            top: end.max(start),
        }
    }

    /// The range still unused, as (base, len).
    pub fn remaining(&self) -> (u64, u64) {
        (self.base, self.top - self.base)
    }
}

impl FrameSource for BumpFrames {
    fn alloc_frame(&mut self) -> Option<u64> {
        if self.top - self.base < PAGE_SIZE {
            return None;
        }
        self.top -= PAGE_SIZE;
        Some(self.top)
    }
}

/// The kernel heap: a buddy allocator behind a spinlock, installed with
/// `#[global_allocator]`. Allocation before [`LockedHeap::init`] fails.
pub struct LockedHeap {
    inner: SpinLock<Option<buddy::BuddyHeap>>,
}

/// A hardening check failed (ADR-170): the heap is damaged or was misused.
/// Raised after the heap lock is released, so the panic handler can print.
#[cold]
#[inline(never)]
#[allow(clippy::panic)]
pub fn heap_fault(f: buddy::HeapFault) -> ! {
    // Fixed strings, one per fault: a formatted message would be withheld
    // by the production fault policy (ADR-172), and these name no data.
    match f {
        buddy::HeapFault::DoubleFree => panic!("heap: double free"),
        buddy::HeapFault::InvalidFree => {
            panic!("heap: invalid free (not the start of a live allocation of that size)")
        }
        buddy::HeapFault::FreeListCorrupted => panic!("heap: free list corrupted"),
        buddy::HeapFault::WriteAfterFree => panic!("heap: write after free (poison overwritten)"),
        buddy::HeapFault::RedZoneDamaged => {
            panic!("heap: heap overflow (red zone behind a large allocation damaged)")
        }
    }
}

impl LockedHeap {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(None),
        }
    }

    pub fn init(&self, heap: buddy::BuddyHeap) {
        *self.inner.lock() = Some(heap);
    }

    /// The address of the heap's lock (to tell it from other locks in the
    /// contention statistics).
    pub fn lock_addr(&self) -> usize {
        &self.inner as *const _ as usize
    }

    /// (free bytes, capacity), or `None` before `init`.
    pub fn stats(&self) -> Option<(usize, usize)> {
        self.inner
            .lock()
            .as_ref()
            .map(|h| (h.free_bytes(), h.capacity()))
    }

    /// Allocates up to `n` blocks of `layout` under one hold of the lock and
    /// calls `put` for each (the poison check of each runs after the lock is
    /// released). Returns how many it got.
    ///
    /// # Safety
    /// As `GlobalAlloc::alloc`.
    #[allow(unsafe_code)]
    pub unsafe fn alloc_many(
        &self,
        layout: Layout,
        n: usize,
        mut put: impl FnMut(*mut u8),
    ) -> usize {
        let mut got: [Option<(NonNull<u8>, usize)>; 32] = [None; 32];
        let n = n.min(got.len());
        let fault = {
            let mut g = self.inner.lock();
            let mut fault = None;
            if let Some(h) = g.as_mut() {
                for slot in got.iter_mut().take(n) {
                    *slot = h.alloc_deferred(layout);
                    if slot.is_none() {
                        break;
                    }
                }
                fault = h.take_fault();
            }
            fault
        };
        if let Some(f) = fault {
            heap_fault(f);
        }
        let mut count = 0;
        for (p, verify) in got.iter().take(n).flatten() {
            // SAFETY: as in `alloc`.
            if *verify > 0 && !unsafe { buddy::check_poison(*p, *verify) } {
                heap_fault(buddy::HeapFault::WriteAfterFree);
            }
            put(p.as_ptr());
            count += 1;
        }
        count
    }

    /// Frees `n` blocks of `layout` (poisoned by the caller after their
    /// headers, see [`buddy::BuddyHeap::dealloc_ex`]) under one hold of the
    /// lock.
    ///
    /// # Safety
    /// As `GlobalAlloc::dealloc` for each block.
    #[allow(unsafe_code)]
    pub unsafe fn dealloc_many(&self, layout: Layout, blocks: &[*mut u8]) {
        let fault = {
            let mut g = self.inner.lock();
            let mut fault = None;
            if let Some(h) = g.as_mut() {
                for &p in blocks {
                    if let Some(p) = NonNull::new(p) {
                        // SAFETY: GlobalAlloc's contract; poisoned as announced.
                        if let Err(f) = unsafe { h.dealloc_ex(p, layout, true) } {
                            fault.get_or_insert(f);
                        }
                    }
                }
            }
            fault
        };
        if let Some(f) = fault {
            heap_fault(f);
        }
    }

    /// Frees a block the caller may already have poisoned (see
    /// [`buddy::BuddyHeap::dealloc_ex`]).
    ///
    /// # Safety
    /// As `GlobalAlloc::dealloc`.
    #[allow(unsafe_code)]
    pub unsafe fn dealloc_ex(&self, ptr: *mut u8, layout: Layout, poisoned: bool) {
        let fault = {
            let mut g = self.inner.lock();
            match (g.as_mut(), NonNull::new(ptr)) {
                // SAFETY: GlobalAlloc's contract: `ptr` came from `alloc`
                // with this `layout`; violations are detected, not UB.
                (Some(h), Some(p)) => unsafe { h.dealloc_ex(p, layout, poisoned) }.err(),
                _ => None,
            }
        };
        if let Some(f) = fault {
            heap_fault(f);
        }
    }
}

impl Default for LockedHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(unsafe_code)]
// SAFETY: `BuddyHeap` hands out disjoint, correctly aligned blocks and the
// spinlock serializes all access to it.
unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let (p, fault) = {
            let mut g = self.inner.lock();
            match g.as_mut() {
                Some(h) => {
                    let p = h.alloc_deferred(layout);
                    (p, h.take_fault())
                }
                None => (None, None),
            }
        };
        if let Some(f) = fault {
            heap_fault(f);
        }
        let Some((p, verify)) = p else {
            return core::ptr::null_mut();
        };
        // The poison check reads up to 16 KiB: after the lock, not inside it
        // (ADR-230). The block is ours; a block that fails is a write after free.
        // SAFETY: `p` and `verify` are what `alloc_deferred` returned.
        if verify > 0 && !unsafe { buddy::check_poison(p, verify) } {
            heap_fault(buddy::HeapFault::WriteAfterFree);
        }
        p.as_ptr()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.dealloc_ex(ptr, layout, false) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_downwards_aligned_until_empty() {
        let mut b = BumpFrames::new(0x1001, 3 * PAGE_SIZE);
        assert_eq!(b.remaining(), (0x2000, 2 * PAGE_SIZE));
        assert_eq!(b.alloc_frame(), Some(0x3000));
        assert_eq!(b.alloc_frame(), Some(0x2000));
        assert_eq!(b.alloc_frame(), None);
        assert_eq!(b.remaining().1, 0);
    }

    #[test]
    fn degenerate_ranges() {
        assert_eq!(BumpFrames::new(0x1800, 0x100).alloc_frame(), None);
        assert_eq!(BumpFrames::new(u64::MAX - 10, 100).alloc_frame(), None);
    }
}
