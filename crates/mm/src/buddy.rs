//! Binary buddy allocator for the kernel heap.
//!
//! The heap is one naturally aligned power-of-two region. Free blocks of
//! each order sit on an intrusive doubly linked list; one bit per block and
//! order records "free" so merging can check a buddy in O(1). Blocks carry
//! no header: `dealloc` recomputes the order from the `Layout`, which Rust
//! guarantees to be the one used for `alloc`.
//!
//! Hot-path allocations do not come from here (per-core slabs, M13); this
//! serves boot-time structures and TLS handshakes.

#![allow(unsafe_code)]

use core::alloc::Layout;
use core::ptr::{self, NonNull};

/// Smallest block: 32 bytes (room for the two list pointers).
pub const MIN_ORDER: u32 = 5;
/// Largest supported heap: 1 GiB.
pub const MAX_ORDER: u32 = 30;
const ORDERS: usize = (MAX_ORDER - MIN_ORDER + 1) as usize;

#[repr(C)]
struct FreeBlock {
    next: *mut FreeBlock,
    prev: *mut FreeBlock,
}

/// Bytes of bookkeeping bitmap needed for a heap of `2^order` bytes.
pub const fn bitmap_bytes(order: u32) -> usize {
    // Order k has 2^(order - k) blocks; sum over k in MIN..=order bits.
    let mut bits = 0usize;
    let mut k = MIN_ORDER;
    while k <= order {
        bits += 1 << (order - k);
        k += 1;
    }
    bits.div_ceil(64) * 8
}

pub struct BuddyHeap {
    base: usize,
    order: u32,
    heads: [*mut FreeBlock; ORDERS],
    /// Concatenated per-order bitmaps, order MIN first.
    bits: *mut u64,
    bit_words: usize,
    free_bytes: usize,
}

// SAFETY: the raw pointers refer to memory owned exclusively by this heap;
// callers wrap it in a lock before sharing it between cores.
unsafe impl Send for BuddyHeap {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    BadRegion,
    BitmapTooSmall,
}

impl BuddyHeap {
    /// # Safety
    /// `[base, base + 2^order)` must be valid, writable memory used by nothing
    /// else for the heap's lifetime, `base` aligned to `2^order`, and
    /// `bitmap` (`bitmap_words` u64s) likewise exclusively owned.
    pub unsafe fn new(
        base: usize,
        order: u32,
        bitmap: *mut u64,
        bitmap_words: usize,
    ) -> Result<Self, HeapError> {
        if !(MIN_ORDER..=MAX_ORDER).contains(&order) || !base.is_multiple_of(1usize << order) {
            return Err(HeapError::BadRegion);
        }
        if bitmap_words * 8 < bitmap_bytes(order) {
            return Err(HeapError::BitmapTooSmall);
        }
        // SAFETY: the caller owns `bitmap_words` words at `bitmap`.
        unsafe { ptr::write_bytes(bitmap, 0, bitmap_words) };
        let mut heap = Self {
            base,
            order,
            heads: [ptr::null_mut(); ORDERS],
            bits: bitmap,
            bit_words: bitmap_words,
            free_bytes: 0,
        };
        // The whole region starts as one free block of the top order.
        // SAFETY: the region is owned and aligned per the contract.
        unsafe { heap.push(order, base) };
        heap.free_bytes = 1 << order;
        Ok(heap)
    }

    pub fn free_bytes(&self) -> usize {
        self.free_bytes
    }

    pub fn capacity(&self) -> usize {
        1 << self.order
    }

    fn bit_offset(&self, order: u32) -> usize {
        // Bits used by orders MIN..order.
        (MIN_ORDER..order).map(|k| 1usize << (self.order - k)).sum()
    }

    fn bit_index(&self, order: u32, addr: usize) -> usize {
        self.bit_offset(order) + ((addr - self.base) >> order)
    }

    fn get_bit(&self, order: u32, addr: usize) -> bool {
        let i = self.bit_index(order, addr);
        if i / 64 >= self.bit_words {
            return false;
        }
        // SAFETY: index checked against the bitmap length.
        unsafe { *self.bits.wrapping_add(i / 64) & (1 << (i % 64)) != 0 }
    }

    fn set_bit(&mut self, order: u32, addr: usize, v: bool) {
        let i = self.bit_index(order, addr);
        if i / 64 >= self.bit_words {
            return;
        }
        // SAFETY: index checked against the bitmap length.
        let w = unsafe { &mut *self.bits.wrapping_add(i / 64) };
        if v {
            *w |= 1 << (i % 64);
        } else {
            *w &= !(1 << (i % 64));
        }
    }

    const fn slot(order: u32) -> usize {
        (order - MIN_ORDER) as usize
    }

    /// # Safety
    /// `addr` must be a free, unlisted block of `order` inside the heap.
    unsafe fn push(&mut self, order: u32, addr: usize) {
        let s = Self::slot(order);
        let block = addr as *mut FreeBlock;
        let head = self.heads.get(s).copied().unwrap_or(ptr::null_mut());
        // SAFETY: the block is owned heap memory, large enough for FreeBlock.
        unsafe {
            block.write(FreeBlock {
                next: head,
                prev: ptr::null_mut(),
            });
        }
        if !head.is_null() {
            // SAFETY: list members are valid free blocks.
            unsafe { (*head).prev = block };
        }
        if let Some(h) = self.heads.get_mut(s) {
            *h = block;
        }
        self.set_bit(order, addr, true);
    }

    /// # Safety
    /// `addr` must be on the free list of `order`.
    unsafe fn unlink(&mut self, order: u32, addr: usize) {
        let s = Self::slot(order);
        let block = addr as *mut FreeBlock;
        // SAFETY: `block` is a listed free block.
        let FreeBlock { next, prev } = unsafe { block.read() };
        if prev.is_null() {
            if let Some(h) = self.heads.get_mut(s) {
                *h = next;
            }
        } else {
            // SAFETY: neighbours are listed free blocks.
            unsafe { (*prev).next = next };
        }
        if !next.is_null() {
            // SAFETY: as above.
            unsafe { (*next).prev = prev };
        }
        self.set_bit(order, addr, false);
    }

    /// Order of the block that serves `layout`, or `None` if it cannot fit.
    pub fn order_for(&self, layout: Layout) -> Option<u32> {
        let need = layout.size().max(layout.align()).max(1 << MIN_ORDER);
        let order = need.checked_next_power_of_two()?.trailing_zeros();
        (order <= self.order).then_some(order)
    }

    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let order = self.order_for(layout)?;
        let mut k = order;
        while self.heads.get(Self::slot(k)).is_none_or(|h| h.is_null()) {
            k += 1;
            if k > self.order {
                return None;
            }
        }
        let addr = self.heads.get(Self::slot(k)).copied()? as usize;
        // SAFETY: `addr` is the head of order k's list.
        unsafe { self.unlink(k, addr) };
        // Split down to the requested order, freeing the upper halves.
        while k > order {
            k -= 1;
            // SAFETY: the upper half of a block we own is free and unlisted.
            unsafe { self.push(k, addr + (1 << k)) };
        }
        self.free_bytes -= 1 << order;
        NonNull::new(addr as *mut u8)
    }

    /// # Safety
    /// `ptr` must come from `alloc` on this heap with the same `layout` and
    /// not have been freed since.
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let Some(mut order) = self.order_for(layout) else {
            return;
        };
        let mut addr = ptr.as_ptr() as usize;
        self.free_bytes += 1 << order;
        while order < self.order {
            let buddy = self.base + ((addr - self.base) ^ (1 << order));
            if !self.get_bit(order, buddy) {
                break;
            }
            // SAFETY: the bit says the buddy is listed at this order.
            unsafe { self.unlink(order, buddy) };
            addr = addr.min(buddy);
            order += 1;
        }
        // SAFETY: the (merged) block is ours and not listed.
        unsafe { self.push(order, addr) };
    }
}

#[cfg(test)]
// Test scaffolding: every unsafe call below operates on a region the test
// allocated itself with the matching layout, which is the whole contract.
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc as sys_dealloc};

    struct Region {
        mem: *mut u8,
        mem_layout: Layout,
        bits: Vec<u64>,
        heap: BuddyHeap,
    }

    impl Region {
        fn new(order: u32) -> Self {
            let mem_layout = Layout::from_size_align(1 << order, 1 << order).unwrap();
            let mem = unsafe { alloc_zeroed(mem_layout) };
            let mut bits = vec![0u64; bitmap_bytes(order) / 8];
            let heap =
                unsafe { BuddyHeap::new(mem as usize, order, bits.as_mut_ptr(), bits.len()) }
                    .unwrap();
            Self {
                mem,
                mem_layout,
                bits,
                heap,
            }
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            let _ = &self.bits;
            unsafe { sys_dealloc(self.mem, self.mem_layout) };
        }
    }

    #[test]
    fn alloc_split_and_full_coalesce() {
        let mut r = Region::new(16);
        let l = Layout::from_size_align(100, 8).unwrap();
        let a = r.heap.alloc(l).unwrap();
        let b = r.heap.alloc(l).unwrap();
        assert_eq!(r.heap.free_bytes(), (1 << 16) - 256);
        assert_ne!(a, b);
        unsafe {
            r.heap.dealloc(a, l);
            r.heap.dealloc(b, l);
        }
        assert_eq!(r.heap.free_bytes(), 1 << 16);
        // Fully coalesced: the whole heap is available as one block again.
        let big = Layout::from_size_align(1 << 16, 1).unwrap();
        let p = r.heap.alloc(big).unwrap();
        assert_eq!(p.as_ptr() as usize, r.mem as usize);
    }

    #[test]
    fn alignment_and_exhaustion() {
        let mut r = Region::new(14);
        let l = Layout::from_size_align(32, 4096).unwrap();
        let p = r.heap.alloc(l).unwrap();
        assert_eq!(p.as_ptr() as usize % 4096, 0);
        let too_big = Layout::from_size_align(1 << 15, 1).unwrap();
        assert!(r.heap.alloc(too_big).is_none());
        let mut n = 0;
        while r
            .heap
            .alloc(Layout::from_size_align(32, 1).unwrap())
            .is_some()
        {
            n += 1;
        }
        assert_eq!(n, ((1 << 14) - 4096) / 32);
        assert_eq!(r.heap.free_bytes(), 0);
    }

    #[test]
    fn construction_checks() {
        let mut bits = vec![0u64; 1];
        assert_eq!(
            unsafe { BuddyHeap::new(0x1000, 16, bits.as_mut_ptr(), 1) }.err(),
            Some(HeapError::BadRegion)
        );
        assert_eq!(
            unsafe { BuddyHeap::new(0x10000, 16, bits.as_mut_ptr(), 1) }.err(),
            Some(HeapError::BitmapTooSmall)
        );
        assert_eq!(
            unsafe { BuddyHeap::new(0, 4, bits.as_mut_ptr(), 1) }.err(),
            Some(HeapError::BadRegion)
        );
    }

    proptest::proptest! {
        #[test]
        fn random_workload_never_overlaps_and_coalesces(
            ops in proptest::collection::vec((0usize..3000, 0u32..8, proptest::bool::ANY), 1..300)
        ) {
            let mut r = Region::new(18);
            let base = r.mem as usize;
            let mut live: Vec<(usize, Layout)> = Vec::new();
            for (size, align_pow, free_one) in ops {
                if free_one && !live.is_empty() {
                    let (p, l) = live.swap_remove(size % live.len());
                    unsafe { r.heap.dealloc(NonNull::new(p as *mut u8).unwrap(), l) };
                    continue;
                }
                let l = Layout::from_size_align(size.max(1), 1 << align_pow).unwrap();
                if let Some(p) = r.heap.alloc(l) {
                    let p = p.as_ptr() as usize;
                    proptest::prop_assert_eq!(p % l.align(), 0);
                    proptest::prop_assert!(p >= base && p + l.size() <= base + (1 << 18));
                    for &(q, ql) in &live {
                        proptest::prop_assert!(p + l.size() <= q || q + ql.size() <= p, "overlap");
                    }
                    // Scribble over the block to catch list corruption.
                    unsafe { core::ptr::write_bytes(p as *mut u8, 0xa5, l.size()) };
                    live.push((p, l));
                }
            }
            for (p, l) in live.drain(..) {
                unsafe { r.heap.dealloc(NonNull::new(p as *mut u8).unwrap(), l) };
            }
            proptest::prop_assert_eq!(r.heap.free_bytes(), 1 << 18);
            let whole = Layout::from_size_align(1 << 18, 1).unwrap();
            proptest::prop_assert!(r.heap.alloc(whole).is_some());
        }
    }
}
