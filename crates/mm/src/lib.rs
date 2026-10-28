//! Physical frame allocator, kernel heap, per-CPU slab allocators and buffer pools.
//!
//! **Status:** M1 provides [`BumpFrames`], an early allocator used before the
//! real frame allocator exists. The frame allocator, heap, slabs and pools
//! arrive in M2/M13; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use urmqtt_arch_aarch64::paging::{FrameSource, PAGE_SIZE};

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
