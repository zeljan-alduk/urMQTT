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

pub mod buddy;
pub mod cached;
pub mod frames;

pub use cached::CachedHeap;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use urmqtt_arch_aarch64::paging::{FrameSource, PAGE_SIZE};
use urmqtt_arch_aarch64::sync::SpinLock;

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

impl LockedHeap {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(None),
        }
    }

    pub fn init(&self, heap: buddy::BuddyHeap) {
        *self.inner.lock() = Some(heap);
    }

    /// (free bytes, capacity), or `None` before `init`.
    pub fn stats(&self) -> Option<(usize, usize)> {
        self.inner
            .lock()
            .as_ref()
            .map(|h| (h.free_bytes(), h.capacity()))
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
        self.inner
            .lock()
            .as_mut()
            .and_then(|h| h.alloc(layout))
            .map_or(core::ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let (Some(h), Some(p)) = (self.inner.lock().as_mut(), NonNull::new(ptr)) {
            // SAFETY: GlobalAlloc's contract: `ptr` came from `alloc` with
            // this `layout`.
            unsafe { h.dealloc(p, layout) };
        }
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
