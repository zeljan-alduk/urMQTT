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
//!
//! # Hardening (H4, ADR-170)
//!
//! - **Poison on free.** A freed block is filled with [`POISON`] (so a
//!   secret does not outlive its owner, and a stale read sees a pattern, not
//!   data). A block that is still entirely poison when it is handed out
//!   again proves nothing wrote to it while it was free; a write after free
//!   is reported when the block is reused ([`HeapFault::WriteAfterFree`]).
//! - **Double-free and invalid-free detection.** A second bitmap, one bit
//!   per 32-byte granule, marks the first granule of every live allocation.
//!   A free whose pointer is outside the heap, misaligned for its size, not
//!   the start of a live allocation, or whose size spans another live
//!   allocation is refused ([`HeapFault::DoubleFree`], [`HeapFault::InvalidFree`]).
//! - **Free-list integrity.** The list links and a state tag in a free
//!   block are stored XOR a per-boot key and the block's own address (so a
//!   leaked or overwritten link is neither readable as a pointer nor
//!   forgeable without the key), decoded values must point into the heap,
//!   and unlinking checks both neighbours point back ("safe unlinking").

#![allow(unsafe_code)]

use core::alloc::Layout;
use core::fmt;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU64, Ordering};

/// Smallest block: 32 bytes (room for the free-block header).
pub const MIN_ORDER: u32 = 5;
/// Largest supported heap: 1 GiB.
pub const MAX_ORDER: u32 = 30;
const ORDERS: usize = (MAX_ORDER - MIN_ORDER + 1) as usize;

/// What freed memory is filled with.
pub const POISON: u8 = 0xdf;
pub(crate) const POISON_WORD: u64 = u64::from_ne_bytes([POISON; 8]);
/// Bytes at the start of a free block that hold the list header instead of
/// poison.
pub const HEADER: usize = 32;
/// How much of a freed block is poisoned (and checked at reuse): the first
/// `POISON_LIMIT` bytes. Poisoning a megabyte buffer on every free costs
/// more than the memory it protects; blocks up to this size are wiped
/// whole. See ADR-170 for the measured cost.
pub const POISON_LIMIT: usize = 16 * 1024;

/// Bytes of a block of `size` that are poisoned when it is freed.
const fn prange(size: usize) -> usize {
    if size < POISON_LIMIT {
        size
    } else {
        POISON_LIMIT
    }
}

/// A free block's header. Every field is stored XOR the heap key and the
/// field's own address.
#[repr(C)]
struct FreeBlock {
    next: usize,
    prev: usize,
    tag: usize,
    _pad: usize,
}

/// The state of the block behind a free-list entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Contents unknown (carved from never-used memory).
    Pristine,
    /// The first `prange(size)` bytes after the header are [`POISON`].
    Poisoned,
}

const TAG_PRISTINE: usize = 0x5052_4953_5449_4e45;
const TAG_POISONED: usize = 0x504f_4953_4f4e_4544;

/// What a hardening check found. The allocator never continues after one:
/// the global allocator turns it into a panic (after releasing its lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapFault {
    /// A block that is already free was freed again.
    DoubleFree,
    /// A pointer that is not the start of a live allocation of that size.
    InvalidFree,
    /// A free-list link or tag is not what this boot wrote.
    FreeListCorrupted,
    /// A freed block was written to before it was reused.
    WriteAfterFree,
    /// The canary behind a large allocation was overwritten.
    RedZoneDamaged,
}

impl fmt::Display for HeapFault {
    /// No addresses and no contents: fault reports must not help an
    /// attacker or leak secrets (ADR-172).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DoubleFree => "double free",
            Self::InvalidFree => "invalid free (not the start of a live allocation of that size)",
            Self::FreeListCorrupted => "free list corrupted",
            Self::WriteAfterFree => "write after free (poison overwritten)",
            Self::RedZoneDamaged => "heap overflow (red zone behind a large allocation damaged)",
        })
    }
}

/// Bytes of bookkeeping bitmap needed for a heap of `2^order` bytes: the
/// free bits of every order, then the allocation map.
pub const fn bitmap_bytes(order: u32) -> usize {
    // Order k has 2^(order - k) blocks; sum over k in MIN..=order bits.
    let mut bits = 0usize;
    let mut k = MIN_ORDER;
    while k <= order {
        bits += 1 << (order - k);
        k += 1;
    }
    // The allocation map: one bit per minimum block.
    bits += 1 << (order - MIN_ORDER);
    bits.div_ceil(64) * 8
}

pub struct BuddyHeap {
    base: usize,
    order: u32,
    heads: [usize; ORDERS],
    /// Concatenated per-order bitmaps, order MIN first, then the map.
    bits: *mut u64,
    bit_words: usize,
    /// Bit offset of each order's bitmap.
    offsets: [usize; ORDERS],
    /// Bit offset of the allocation map.
    alloc_off: usize,
    free_bytes: usize,
    key: usize,
    fault: Option<HeapFault>,
}

// SAFETY: the raw pointers refer to memory owned exclusively by this heap;
// callers wrap it in a lock before sharing it between cores.
unsafe impl Send for BuddyHeap {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    BadRegion,
    BitmapTooSmall,
}

/// Read-only, lock-free view of the allocation map, for the per-CPU caches
/// (which free small blocks without taking the heap lock).
#[derive(Clone, Copy)]
pub struct AllocView {
    base: usize,
    size: usize,
    map: *const AtomicU64,
    words: usize,
    /// Bit offset of the allocation map inside the bitmap.
    off: usize,
}

// SAFETY: the view only reads the map through atomics, and the map lives as
// long as the heap (the kernel never frees it).
unsafe impl Send for AllocView {}
// SAFETY: as above.
unsafe impl Sync for AllocView {}

impl AllocView {
    /// Whether `addr` is inside the heap and the start of a live block.
    pub fn is_live_start(&self, addr: usize) -> bool {
        if addr < self.base || addr - self.base >= self.size {
            return false;
        }
        let i = self.off + ((addr - self.base) >> MIN_ORDER);
        if i / 64 >= self.words {
            return false;
        }
        // SAFETY: `i / 64 < words`, inside the map.
        let w = unsafe { &*self.map.wrapping_add(i / 64) };
        // Relaxed: the bit of a block its caller owns changes only by that
        // caller's own alloc/free.
        w.load(Ordering::Relaxed) & (1 << (i % 64)) != 0
    }

    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr - self.base < self.size
    }

    /// The first address of the heap.
    pub fn base(&self) -> usize {
        self.base
    }
}

impl BuddyHeap {
    /// # Safety
    /// `[base, base + 2^order)` must be valid, writable memory used by nothing
    /// else for the heap's lifetime, `base` aligned to `2^order`, and
    /// `bitmap` (`bitmap_words` u64s) likewise exclusively owned.
    ///
    /// `key` obfuscates the free-list links (any value works; a random one
    /// per boot is the point).
    pub unsafe fn new(
        base: usize,
        order: u32,
        bitmap: *mut u64,
        bitmap_words: usize,
        key: u64,
    ) -> Result<Self, HeapError> {
        if !(MIN_ORDER..=MAX_ORDER).contains(&order) || !base.is_multiple_of(1usize << order) {
            return Err(HeapError::BadRegion);
        }
        if bitmap_words * 8 < bitmap_bytes(order) {
            return Err(HeapError::BitmapTooSmall);
        }
        // SAFETY: the caller owns `bitmap_words` words at `bitmap`.
        unsafe { ptr::write_bytes(bitmap, 0, bitmap_words) };
        let mut offsets = [0usize; ORDERS];
        let mut off = 0usize;
        for (i, o) in offsets.iter_mut().enumerate() {
            *o = off;
            let k = MIN_ORDER + i as u32;
            if k <= order {
                off += 1 << (order - k);
            }
        }
        let mut heap = Self {
            base,
            order,
            heads: [0; ORDERS],
            bits: bitmap,
            bit_words: bitmap_words,
            offsets,
            alloc_off: off,
            free_bytes: 0,
            key: (key as usize) | 1,
            fault: None,
        };
        // The whole region starts as one free block of the top order.
        // SAFETY: the region is owned and aligned per the contract.
        unsafe { heap.push(order, base, State::Pristine) };
        heap.free_bytes = 1 << order;
        Ok(heap)
    }

    pub fn free_bytes(&self) -> usize {
        self.free_bytes
    }

    pub fn capacity(&self) -> usize {
        1 << self.order
    }

    /// The first hardening fault found, if any (cleared by reading it).
    pub fn take_fault(&mut self) -> Option<HeapFault> {
        self.fault.take()
    }

    /// A lock-free reader of the allocation map.
    pub fn alloc_view(&self) -> AllocView {
        AllocView {
            base: self.base,
            size: 1 << self.order,
            map: self.bits.cast::<AtomicU64>(),
            words: self.bit_words,
            off: self.alloc_off,
        }
    }

    fn flag(&mut self, f: HeapFault) {
        if self.fault.is_none() {
            self.fault = Some(f);
        }
    }

    fn bit_index(&self, order: u32, addr: usize) -> usize {
        self.offsets
            .get((order - MIN_ORDER) as usize)
            .copied()
            .unwrap_or(0)
            + ((addr - self.base) >> order)
    }

    fn word(&self, i: usize) -> Option<&AtomicU64> {
        if i / 64 >= self.bit_words {
            return None;
        }
        // SAFETY: index checked against the bitmap length; `AtomicU64` has
        // the layout of `u64` and the bitmap is owned by this heap.
        Some(unsafe { &*self.bits.cast::<AtomicU64>().wrapping_add(i / 64) })
    }

    fn get_bit_at(&self, i: usize) -> bool {
        // Relaxed: the map is read under the heap lock, or (the allocation
        // map) by the owner of the block.
        self.word(i)
            .is_some_and(|w| w.load(Ordering::Relaxed) & (1 << (i % 64)) != 0)
    }

    fn set_bit_at(&self, i: usize, v: bool) {
        if let Some(w) = self.word(i) {
            // Relaxed: mutated under the heap lock; lock-free readers only
            // look at bits of blocks they own.
            if v {
                w.fetch_or(1 << (i % 64), Ordering::Relaxed);
            } else {
                w.fetch_and(!(1 << (i % 64)), Ordering::Relaxed);
            }
        }
    }

    fn get_bit(&self, order: u32, addr: usize) -> bool {
        self.get_bit_at(self.bit_index(order, addr))
    }

    fn set_bit(&mut self, order: u32, addr: usize, v: bool) {
        self.set_bit_at(self.bit_index(order, addr), v);
    }

    fn alloc_bit(&self, addr: usize) -> usize {
        self.alloc_off + ((addr - self.base) >> MIN_ORDER)
    }

    /// Whether any allocation starts in `[from, to)` (granule aligned).
    fn alloc_any(&self, from: usize, to: usize) -> bool {
        (self.alloc_bit(from)..self.alloc_bit(to)).any(|i| self.get_bit_at(i))
    }

    const fn slot(order: u32) -> usize {
        (order - MIN_ORDER) as usize
    }

    fn enc(&self, v: usize, at: usize) -> usize {
        v ^ self.key ^ at
    }

    fn tag_of(&self, st: State, at: usize) -> usize {
        self.enc(
            match st {
                State::Pristine => TAG_PRISTINE,
                State::Poisoned => TAG_POISONED,
            },
            at,
        )
    }

    /// Decodes a list link read from the field at `at`; 0 is the end.
    fn dec(&mut self, raw: usize, at: usize) -> usize {
        let v = raw ^ self.key ^ at;
        let end = self.base + (1 << self.order);
        if v != 0 && (v < self.base || v >= end || !(v - self.base).is_multiple_of(1 << MIN_ORDER))
        {
            self.flag(HeapFault::FreeListCorrupted);
            return 0;
        }
        v
    }

    /// # Safety
    /// `addr` must be a free, unlisted block of `order` inside the heap.
    unsafe fn push(&mut self, order: u32, addr: usize, st: State) {
        let s = Self::slot(order);
        let block = addr as *mut FreeBlock;
        let head = self.heads.get(s).copied().unwrap_or(0);
        // SAFETY: the block is owned heap memory, large enough for FreeBlock.
        unsafe {
            block.write(FreeBlock {
                next: self.enc(head, addr),
                prev: self.enc(0, addr + 8),
                tag: self.tag_of(st, addr + 16),
                _pad: 0,
            });
        }
        if head != 0 {
            // SAFETY: list members are valid free blocks.
            unsafe { (*(head as *mut FreeBlock)).prev = self.enc(addr, head + 8) };
        }
        if let Some(h) = self.heads.get_mut(s) {
            *h = addr;
        }
        self.set_bit(order, addr, true);
    }

    /// Removes a listed block and reports its state.
    ///
    /// # Safety
    /// `addr` must be on the free list of `order`.
    unsafe fn unlink(&mut self, order: u32, addr: usize) -> Option<State> {
        let s = Self::slot(order);
        let block = addr as *mut FreeBlock;
        // SAFETY: `block` is a listed free block.
        let FreeBlock {
            next, prev, tag, ..
        } = unsafe { block.read() };
        let st = if tag == self.tag_of(State::Poisoned, addr + 16) {
            State::Poisoned
        } else if tag == self.tag_of(State::Pristine, addr + 16) {
            State::Pristine
        } else {
            self.flag(HeapFault::FreeListCorrupted);
            return None;
        };
        let next = self.dec(next, addr);
        let prev = self.dec(prev, addr + 8);
        if self.fault.is_some() {
            return None;
        }
        // Safe unlinking: both neighbours must point back at this block.
        if next != 0 {
            // SAFETY: `next` was decoded as an in-heap block address.
            let back = unsafe { (*(next as *mut FreeBlock)).prev };
            if self.dec(back, next + 8) != addr {
                self.flag(HeapFault::FreeListCorrupted);
                return None;
            }
        }
        if prev != 0 {
            // SAFETY: as above.
            let fwd = unsafe { (*(prev as *mut FreeBlock)).next };
            if self.dec(fwd, prev) != addr {
                self.flag(HeapFault::FreeListCorrupted);
                return None;
            }
        } else if self.heads.get(s).copied() != Some(addr) {
            self.flag(HeapFault::FreeListCorrupted);
            return None;
        }
        if prev == 0 {
            if let Some(h) = self.heads.get_mut(s) {
                *h = next;
            }
        } else {
            // SAFETY: checked above.
            unsafe { (*(prev as *mut FreeBlock)).next = self.enc(next, prev) };
        }
        if next != 0 {
            // SAFETY: checked above.
            unsafe { (*(next as *mut FreeBlock)).prev = self.enc(prev, next + 8) };
        }
        self.set_bit(order, addr, false);
        (self.fault.is_none()).then_some(st)
    }

    /// Order of the block that serves `layout`, or `None` if it cannot fit.
    pub fn order_for(&self, layout: Layout) -> Option<u32> {
        let need = layout.size().max(layout.align()).max(1 << MIN_ORDER);
        let order = need.checked_next_power_of_two()?.trailing_zeros();
        (order <= self.order).then_some(order)
    }

    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if self.fault.is_some() {
            return None;
        }
        let order = self.order_for(layout)?;
        let mut k = order;
        while self.heads.get(Self::slot(k)).is_none_or(|&h| h == 0) {
            k += 1;
            if k > self.order {
                return None;
            }
        }
        let head = self.heads.get(Self::slot(k)).copied()?;
        // SAFETY: `head` is the head of order k's list.
        let st = unsafe { self.unlink(k, head) }?;
        let addr = head;
        // Split down to the requested order, freeing the upper halves. An
        // upper half is poisoned (in the sense of its own `prange`) when
        // the poisoned prefix of the original block covers it.
        let prefix = if st == State::Poisoned {
            prange(1usize << k)
        } else {
            0
        };
        while k > order {
            k -= 1;
            let child = 1usize << k;
            let cst = if child + prange(child) <= prefix {
                State::Poisoned
            } else {
                State::Pristine
            };
            // SAFETY: the upper half of a block we own is free and unlisted.
            unsafe { self.push(k, addr + child, cst) };
        }
        let size = 1usize << order;
        if st == State::Poisoned {
            // SAFETY: the block is ours; the poisoned prefix after the
            // header is poison.
            let intact = unsafe { all_poison(addr + HEADER, prange(size) - HEADER) };
            if !intact {
                self.flag(HeapFault::WriteAfterFree);
                return None;
            }
        }
        // SAFETY: the block is ours; the header is stale list data.
        unsafe { ptr::write_bytes(addr as *mut u8, POISON, HEADER.min(size)) };
        self.set_bit_at(self.alloc_bit(addr), true);
        self.free_bytes -= size;
        NonNull::new(addr as *mut u8)
    }

    /// # Safety
    /// `ptr` must come from `alloc` on this heap with the same `layout` and
    /// not have been freed since. (Violations are detected, not undefined:
    /// the result says so.)
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) -> Result<(), HeapFault> {
        // SAFETY: forwarded contract.
        unsafe { self.dealloc_ex(ptr, layout, false) }
    }

    /// As [`dealloc`](Self::dealloc); `poisoned` says the caller already
    /// filled the block after its first [`HEADER`] bytes with [`POISON`].
    ///
    /// # Safety
    /// As `dealloc`.
    pub unsafe fn dealloc_ex(
        &mut self,
        ptr: NonNull<u8>,
        layout: Layout,
        poisoned: bool,
    ) -> Result<(), HeapFault> {
        if let Some(f) = self.fault {
            return Err(f);
        }
        let fail = |this: &mut Self, f| {
            this.flag(f);
            Err(f)
        };
        let Some(mut order) = self.order_for(layout) else {
            return fail(self, HeapFault::InvalidFree);
        };
        let mut addr = ptr.as_ptr() as usize;
        let size = 1usize << order;
        if addr < self.base
            || addr - self.base >= 1 << self.order
            || !(addr - self.base).is_multiple_of(size)
        {
            return fail(self, HeapFault::InvalidFree);
        }
        if !self.get_bit_at(self.alloc_bit(addr)) {
            // Not live: free already (the block or a block containing it is
            // on a free list), or never ours.
            let free_above = (order..=self.order).any(|k| {
                let a = self.base + (((addr - self.base) >> k) << k);
                self.get_bit(k, a)
            });
            let f = if free_above {
                HeapFault::DoubleFree
            } else {
                HeapFault::InvalidFree
            };
            return fail(self, f);
        }
        // A size larger than the allocation's would swallow its neighbours.
        if size > 1 << MIN_ORDER && self.alloc_any(addr + (1 << MIN_ORDER), addr + size) {
            return fail(self, HeapFault::InvalidFree);
        }
        self.set_bit_at(self.alloc_bit(addr), false);
        // Poison: the whole block, or what the caller left of it.
        // SAFETY: the block was live and is ours again.
        unsafe {
            let n = if poisoned {
                HEADER.min(size)
            } else {
                prange(size)
            };
            ptr::write_bytes(addr as *mut u8, POISON, n);
        }
        self.free_bytes += size;
        let mut st = State::Poisoned;
        while order < self.order {
            let buddy = self.base + ((addr - self.base) ^ (1 << order));
            if !self.get_bit(order, buddy) {
                break;
            }
            // SAFETY: the bit says the buddy is listed at this order.
            let Some(bst) = (unsafe { self.unlink(order, buddy) }) else {
                return Err(self.fault.unwrap_or(HeapFault::FreeListCorrupted));
            };
            if bst == State::Poisoned {
                // The buddy's header becomes interior of the merged block.
                // SAFETY: the buddy was just unlinked and is ours.
                unsafe { ptr::write_bytes(buddy as *mut u8, POISON, HEADER) };
            }
            // The merged block is poisoned over its prefix if its lower
            // half is, and its upper half is too unless the prefix ends
            // inside the lower half.
            let (lower, upper) = if buddy < addr { (bst, st) } else { (st, bst) };
            let half = 1usize << order;
            st = if lower == State::Poisoned && (half >= POISON_LIMIT || upper == State::Poisoned) {
                State::Poisoned
            } else {
                State::Pristine
            };
            addr = addr.min(buddy);
            order += 1;
        }
        // SAFETY: the (merged) block is ours and not listed.
        unsafe { self.push(order, addr, st) };
        Ok(())
    }
}

/// Whether `len` bytes at `addr` (32-byte aligned, a multiple of 8 long) are
/// all [`POISON`].
///
/// # Safety
/// The range must be readable memory.
unsafe fn all_poison(addr: usize, len: usize) -> bool {
    // SAFETY: the caller guarantees the range is readable; `u64` reads at an
    // 8-aligned address.
    let words = unsafe { core::slice::from_raw_parts(addr as *const u64, len / 8) };
    words.iter().fold(0u64, |acc, &w| acc | (w ^ POISON_WORD)) == 0
}

#[cfg(test)]
// Test scaffolding: every unsafe call below operates on a region the test
// allocated itself with the matching layout, which is the whole contract.
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc as sys_dealloc};

    pub(crate) struct Region {
        pub mem: *mut u8,
        mem_layout: Layout,
        bits: Vec<u64>,
        pub heap: BuddyHeap,
    }

    impl Region {
        pub(crate) fn new(order: u32) -> Self {
            Self::keyed(order, 0x1234_5678_9abc_def0)
        }

        pub(crate) fn keyed(order: u32, key: u64) -> Self {
            let mem_layout = Layout::from_size_align(1 << order, 1 << order).unwrap();
            let mem = unsafe { alloc_zeroed(mem_layout) };
            let mut bits = vec![0u64; bitmap_bytes(order) / 8];
            let heap =
                unsafe { BuddyHeap::new(mem as usize, order, bits.as_mut_ptr(), bits.len(), key) }
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

    fn l(size: usize) -> Layout {
        Layout::from_size_align(size, 8).unwrap()
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
            r.heap.dealloc(a, l).unwrap();
            r.heap.dealloc(b, l).unwrap();
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
            unsafe { BuddyHeap::new(0x1000, 16, bits.as_mut_ptr(), 1, 0) }.err(),
            Some(HeapError::BadRegion)
        );
        assert_eq!(
            unsafe { BuddyHeap::new(0x10000, 16, bits.as_mut_ptr(), 1, 0) }.err(),
            Some(HeapError::BitmapTooSmall)
        );
        assert_eq!(
            unsafe { BuddyHeap::new(0, 4, bits.as_mut_ptr(), 1, 0) }.err(),
            Some(HeapError::BadRegion)
        );
    }

    // ---- H4: poison -------------------------------------------------

    #[test]
    fn freed_memory_is_poisoned_and_wiped() {
        let mut r = Region::new(16);
        let lay = l(256);
        let p = r.heap.alloc(lay).unwrap();
        unsafe { ptr::write_bytes(p.as_ptr(), 0x42, 256) };
        unsafe { r.heap.dealloc(p, lay).unwrap() };
        // Behind the header everything the block held is poison, and no
        // 0x42 survives anywhere.
        let all = unsafe { core::slice::from_raw_parts(r.mem, 1 << 16) };
        assert!(all[HEADER..256].iter().all(|&b| b == POISON));
        assert!(!all[HEADER..256].contains(&0x42));
    }

    #[test]
    fn write_after_free_is_found_when_the_block_is_reused() {
        let mut r = Region::new(16);
        let lay = l(256);
        let a = r.heap.alloc(lay).unwrap();
        let keep = r.heap.alloc(lay).unwrap(); // so `a` does not merge away
        unsafe { r.heap.dealloc(a, lay).unwrap() };
        // The use-after-free: one byte written into the freed block.
        unsafe { *a.as_ptr().add(100) = 0x41 };
        // Allocate until the freed block comes back.
        let mut found = None;
        for _ in 0..8 {
            match r.heap.alloc(lay) {
                Some(p) if p == a => {
                    found = Some(p);
                    break;
                }
                Some(_) => {}
                None => break,
            }
        }
        assert!(found.is_none(), "a damaged block must not be handed out");
        assert_eq!(r.heap.take_fault(), Some(HeapFault::WriteAfterFree));
        let _ = keep;
    }

    #[test]
    fn untouched_freed_blocks_are_reused_cleanly() {
        let mut r = Region::new(16);
        let lay = l(1000);
        for round in 0..50 {
            let p = r.heap.alloc(lay).unwrap();
            if round > 0 {
                // Memory that was freed reads as poison, not as old data.
                assert_eq!(unsafe { *p.as_ptr().add(500) }, POISON);
            }
            unsafe { ptr::write_bytes(p.as_ptr(), 7, 1000) };
            unsafe { r.heap.dealloc(p, lay).unwrap() };
        }
        assert!(r.heap.take_fault().is_none());
    }

    // ---- H4: double free and invalid free -----------------------------

    #[test]
    fn double_free_is_detected_even_after_coalescing() {
        let mut r = Region::new(16);
        let lay = l(100);
        let p = r.heap.alloc(lay).unwrap();
        unsafe { r.heap.dealloc(p, lay).unwrap() };
        // The heap is one block again: the second free is inside a free block.
        assert_eq!(
            unsafe { r.heap.dealloc(p, lay) },
            Err(HeapFault::DoubleFree)
        );
        let mut r = Region::new(16);
        let p = r.heap.alloc(lay).unwrap();
        let q = r.heap.alloc(lay).unwrap();
        unsafe { r.heap.dealloc(p, lay).unwrap() };
        // `p` is a free block of its own now (its buddy `q` is live).
        assert_eq!(
            unsafe { r.heap.dealloc(p, lay) },
            Err(HeapFault::DoubleFree)
        );
        let _ = q;
    }

    #[test]
    fn invalid_frees_are_refused() {
        let lay = l(256);
        let base_of = |r: &Region| r.mem as usize;
        // Offsets from the heap base: an interior pointer, a misaligned one,
        // one outside the heap, a block that was never allocated.
        for off in [64isize, 8, (1 << 16) + 256, -256, 8192] {
            let mut r = Region::new(16);
            let _p = r.heap.alloc(lay).unwrap();
            let target = base_of(&r).wrapping_add_signed(off);
            let res = unsafe {
                r.heap
                    .dealloc(NonNull::new(target as *mut u8).unwrap(), lay)
            };
            assert!(
                matches!(res, Err(HeapFault::InvalidFree | HeapFault::DoubleFree)),
                "offset {off}: {res:?}"
            );
        }
        // A layout larger than the allocation would swallow its neighbour.
        let mut r = Region::new(16);
        let p = r.heap.alloc(lay).unwrap();
        let _q = r.heap.alloc(lay).unwrap();
        assert_eq!(
            unsafe { r.heap.dealloc(p, l(512)) },
            Err(HeapFault::InvalidFree)
        );
    }

    // ---- H4: free-list integrity ----------------------------------------

    #[test]
    fn free_list_links_are_not_stored_as_pointers() {
        let mut r = Region::new(16);
        let lay = l(256);
        let a = r.heap.alloc(lay).unwrap();
        let b = r.heap.alloc(lay).unwrap();
        let c = r.heap.alloc(lay).unwrap();
        let _d = r.heap.alloc(lay).unwrap();
        unsafe { r.heap.dealloc(a, lay).unwrap() };
        unsafe { r.heap.dealloc(c, lay).unwrap() };
        // `c` heads the order-8 list and points at `a`: the stored word is
        // neither pointer.
        let next = unsafe { *(c.as_ptr() as *const usize) };
        assert_ne!(next, a.as_ptr() as usize);
        assert_ne!(next, 0);
        let _ = b;
    }

    #[test]
    fn a_forged_link_is_caught_before_it_is_followed() {
        let mut r = Region::new(16);
        let lay = l(256);
        let a = r.heap.alloc(lay).unwrap();
        let _b = r.heap.alloc(lay).unwrap();
        let c = r.heap.alloc(lay).unwrap();
        let _d = r.heap.alloc(lay).unwrap();
        unsafe { r.heap.dealloc(a, lay).unwrap() };
        unsafe { r.heap.dealloc(c, lay).unwrap() };
        // A write-after-free that sets the next link to an address of the
        // attacker's choosing (the classic freelist poisoning), here a
        // plain pointer into the heap.
        let evil = r.mem as usize + 4096;
        unsafe { *(c.as_ptr() as *mut usize) = evil };
        assert!(r.heap.alloc(lay).is_none());
        assert_eq!(r.heap.take_fault(), Some(HeapFault::FreeListCorrupted));
    }

    #[test]
    fn a_forged_tag_is_caught() {
        let mut r = Region::new(16);
        let lay = l(256);
        let a = r.heap.alloc(lay).unwrap();
        let _b = r.heap.alloc(lay).unwrap();
        unsafe { r.heap.dealloc(a, lay).unwrap() };
        unsafe { *(a.as_ptr().add(16) as *mut usize) = 0 };
        assert!(r.heap.alloc(lay).is_none());
        assert_eq!(r.heap.take_fault(), Some(HeapFault::FreeListCorrupted));
    }

    #[test]
    fn the_key_changes_the_stored_links() {
        let word = |key| {
            let mut r = Region::keyed(16, key);
            let lay = l(256);
            let a = r.heap.alloc(lay).unwrap();
            let _b = r.heap.alloc(lay).unwrap();
            let c = r.heap.alloc(lay).unwrap();
            let _d = r.heap.alloc(lay).unwrap();
            unsafe { r.heap.dealloc(a, lay).unwrap() };
            unsafe { r.heap.dealloc(c, lay).unwrap() };
            // Same layout in two regions differs by the base: compare the
            // word XOR the address of the field.
            unsafe { *(c.as_ptr() as *const usize) ^ (c.as_ptr() as usize) }
        };
        assert_ne!(word(1), word(2));
    }

    #[test]
    fn the_allocation_map_view_follows_alloc_and_free() {
        let mut r = Region::new(16);
        let view = r.heap.alloc_view();
        let lay = l(256);
        let p = r.heap.alloc(lay).unwrap();
        assert!(view.is_live_start(p.as_ptr() as usize));
        assert!(!view.is_live_start(p.as_ptr() as usize + 32));
        assert!(!view.is_live_start(0));
        unsafe { r.heap.dealloc(p, lay).unwrap() };
        assert!(!view.is_live_start(p.as_ptr() as usize));
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
                    unsafe { r.heap.dealloc(NonNull::new(p as *mut u8).unwrap(), l).unwrap() };
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
                unsafe { r.heap.dealloc(NonNull::new(p as *mut u8).unwrap(), l).unwrap() };
            }
            proptest::prop_assert!(r.heap.take_fault().is_none());
            proptest::prop_assert_eq!(r.heap.free_bytes(), 1 << 18);
            let whole = Layout::from_size_align(1 << 18, 1).unwrap();
            proptest::prop_assert!(r.heap.alloc(whole).is_some());
        }

        /// Blocks around and above the poison limit split and merge without
        /// a false write-after-free.
        #[test]
        fn big_blocks_and_the_poison_limit_never_misfire(
            ops in proptest::collection::vec((1usize..140_000, proptest::bool::ANY), 1..120)
        ) {
            let mut r = Region::new(21);
            let mut live: Vec<(NonNull<u8>, Layout, u8)> = Vec::new();
            for (n, free_one) in ops {
                if free_one && !live.is_empty() {
                    let (p, lay, fill) = live.swap_remove(n % live.len());
                    // Nobody else wrote to it.
                    let body = unsafe { core::slice::from_raw_parts(p.as_ptr(), lay.size()) };
                    proptest::prop_assert!(body.iter().all(|&b| b == fill));
                    unsafe { r.heap.dealloc(p, lay).unwrap() };
                    continue;
                }
                let lay = Layout::from_size_align(n, 8).unwrap();
                if let Some(p) = r.heap.alloc(lay) {
                    let fill = (live.len() % 200) as u8 + 1;
                    unsafe { core::ptr::write_bytes(p.as_ptr(), fill, n) };
                    live.push((p, lay, fill));
                }
                proptest::prop_assert!(r.heap.take_fault().is_none());
            }
            for (p, lay, _) in live.drain(..) {
                unsafe { r.heap.dealloc(p, lay).unwrap() };
            }
            proptest::prop_assert!(r.heap.take_fault().is_none());
            proptest::prop_assert_eq!(r.heap.free_bytes(), 1 << 21);
        }
    }

    #[test]
    fn only_the_first_poison_limit_bytes_of_a_big_block_are_wiped() {
        let mut r = Region::new(20);
        let lay = l(64 * 1024);
        let p = r.heap.alloc(lay).unwrap();
        unsafe { ptr::write_bytes(p.as_ptr(), 0x42, 64 * 1024) };
        unsafe { r.heap.dealloc(p, lay).unwrap() };
        let all = unsafe { core::slice::from_raw_parts(r.mem, 64 * 1024) };
        assert!(all[HEADER..POISON_LIMIT].iter().all(|&b| b == POISON));
        // The documented limit: the rest is not touched.
        assert!(all[POISON_LIMIT..].iter().all(|&b| b == 0x42));
    }
}
