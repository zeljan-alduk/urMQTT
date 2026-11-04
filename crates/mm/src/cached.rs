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
//!
//! # Hardening (H4, ADR-170)
//!
//! A block in a cache list carries a small header: the next link and a
//! state tag, both XOR a per-boot key and their own address. A block freed
//! by its owner is filled with [`POISON`] behind the header and tagged
//! `FREED`; a block taken from the heap for the cache is tagged `FRESH`.
//! Freeing a block that already carries a tag is a double free; taking a
//! `FREED` block out whose poison was disturbed is a write after free; a
//! block that is not the start of a live heap block (checked against the
//! heap's allocation map, lock-free) is an invalid free. Allocations of
//! 32 KiB and more, and any allocation whose block has the room, get a
//! canary gap behind them that is checked at free.
//!
//! With memory tagging (ADR-174) a live allocation is also given a random
//! allocation tag over its bytes rounded up to 16, the pointer returned
//! carries it, and freeing sets the tags back to zero: a stale pointer or an
//! overflow faults in hardware, at the instruction. All of the allocator's
//! own accesses use the untagged address, which the hardware does not check.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use urmqtt_sync::sync::OnceCell;

use crate::LockedHeap;
use crate::buddy::{AllocView, HeapFault, POISON, POISON_WORD};

/// Block sizes, one per buddy order from `buddy::MIN_ORDER`.
pub const CLASSES: [usize; 7] = [32, 64, 128, 256, 512, 1024, 2048];
pub const MAX_CPUS: usize = 64;
/// Blocks moved per refill or drain.
pub const BATCH: usize = 16;
/// Bytes a CPU keeps per class before it returns half.
pub const KEEP_BYTES: usize = 32 * 1024;
/// Bytes of canary behind a large allocation.
pub const GAP: usize = 32;
/// Allocations of at least this many bytes always get the canary gap, even
/// if that costs a larger block; smaller ones only when their block has the
/// room (the common case costs nothing).
pub const GAP_ALWAYS: usize = 32 * 1024;
/// Bytes of the cache header at the start of a free small block: the next
/// link, the state tag, and how far the poison reaches.
const CHEAD: usize = 24;

const TAG_FREED: usize = 0x4652_4545_4445_4421;
const TAG_FRESH: usize = 0x4652_4553_4821_2121;

/// A cache list entry's header, decoded and checked.
struct Header {
    next: *mut u8,
    /// Freed by its owner (poisoned) rather than fresh from the heap.
    freed: bool,
    /// Poison reaches this far from the block's start (freed blocks).
    plen: usize,
}

/// Whether every byte is [`POISON`]. Branch-free over words, so it
/// vectorises: the check runs on every reuse of a freed block.
fn all_poison(b: &[u8]) -> bool {
    let (words, tail) = b.as_chunks::<8>();
    let diff = words
        .iter()
        .fold(0u64, |acc, w| acc | (u64::from_ne_bytes(*w) ^ POISON_WORD));
    diff == 0 && tail.iter().all(|&x| x == POISON)
}

/// Writes a word at `p + off`.
///
/// # Safety
/// The word is inside a block the caller owns.
unsafe fn put(p: *mut u8, off: usize, v: usize) {
    // SAFETY: per the contract (blocks are at least 8-aligned).
    unsafe { p.wrapping_add(off).cast::<usize>().write(v) }
}

/// Reads the word at `p + off`.
///
/// # Safety
/// The word is inside a block the caller owns.
unsafe fn get(p: *mut u8, off: usize) -> usize {
    // SAFETY: per the contract.
    unsafe { p.wrapping_add(off).cast::<usize>().read() }
}

/// Memory tagging, supplied by the architecture (aarch64 MTE).
#[derive(Clone, Copy)]
pub struct Tagging {
    /// Gives `[p, p + len)` (`p` 16-aligned, `len` a multiple of 16) a fresh
    /// random allocation tag and returns `p` carrying the matching tag.
    pub retag: unsafe fn(*mut u8, usize) -> *mut u8,
    /// Sets the allocation tags of `[p, p + len)` back to 0 (free).
    pub clear: unsafe fn(*mut u8, usize),
}

/// Allocations above this many bytes are not tagged: a tag store per 16
/// bytes of a huge buffer costs more than it protects.
pub const TAG_MAX: usize = 1 << 20;
/// Bits 59:56 of a pointer: the logical tag.
const TAG_BITS: usize = 0xf << 56;

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
    view: OnceCell<AllocView>,
    tagging: OnceCell<Tagging>,
    /// Per-boot key for the cache links, tags and canaries.
    key: AtomicUsize,
    /// Bytes requested and not yet freed, per CPU (a block freed on another
    /// CPU makes that CPU's counter go negative; the sum is exact).
    live: [AtomicI64; MAX_CPUS],
    /// The same in heap blocks: what those requests really occupy.
    blocks: [AtomicI64; MAX_CPUS],
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

/// Bytes the buddy heap hands out for `layout` (its rounding, as
/// `buddy::BuddyHeap::order_for`).
pub fn block_size(layout: Layout) -> usize {
    layout
        .size()
        .max(layout.align())
        .max(CLASSES[0])
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX)
}

/// The layout actually requested from the heap for a request too big for
/// the caches: the request plus a canary gap if there is room for it or the
/// request is large. Deterministic, so `dealloc` derives the same one.
pub fn padded(layout: Layout) -> Option<Layout> {
    let size = layout.size();
    let with_gap = size.checked_add(GAP)?;
    let want = if size >= GAP_ALWAYS || with_gap <= block_size(layout) {
        with_gap
    } else {
        size
    };
    Layout::from_size_align(want, layout.align()).ok()
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
            view: OnceCell::new(),
            tagging: OnceCell::new(),
            key: AtomicUsize::new(0x9e37_79b9_7f4a_7c15),
            live: [const { AtomicI64::new(0) }; MAX_CPUS],
            blocks: [const { AtomicI64::new(0) }; MAX_CPUS],
        }
    }

    /// Bytes currently allocated by callers (requested sizes, exact), for
    /// the per-connection memory report (M15).
    pub fn live_bytes(&self) -> i64 {
        // Relaxed: a statistic; each CPU's counter is exact on its own.
        self.live.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Heap occupied by the live allocations (block sizes, so including the
    /// rounding of every request to its buddy block).
    pub fn block_bytes(&self) -> i64 {
        // Relaxed: as `live_bytes`.
        self.blocks.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    fn account(&self, layout: Layout, block: Layout, sign: i64) {
        let cpu = self.hooks.get().map_or(0, |h| (h.cpu)());
        if let (Some(l), Some(b)) = (self.live.get(cpu), self.blocks.get(cpu)) {
            // Relaxed: only this CPU writes its own counters (or CPU 0
            // before the hooks exist, also single-threaded).
            l.fetch_add(sign * layout.size() as i64, Ordering::Relaxed);
            b.fetch_add(sign * block_size(block) as i64, Ordering::Relaxed);
        }
    }

    /// Installs the heap. `key` seeds the cache links, tags and canaries
    /// (the buddy heap has its own key); it must be set before the caches
    /// are enabled and not changed while they hold blocks.
    pub fn init(&self, heap: crate::buddy::BuddyHeap, key: u64) {
        let _ = self.view.set(heap.alloc_view());
        let k = (key.rotate_left(29) ^ 0x2545_f491_4f6c_dd1d) as usize | 1;
        // Relaxed: nothing is cached yet; the caches are enabled after.
        self.key.store(k, Ordering::Relaxed);
        self.global.init(heap);
    }

    /// Turns the per-CPU caches on. Before this every request goes to the
    /// global heap.
    pub fn enable(&self, hooks: Hooks) {
        let _ = self.hooks.set(hooks);
    }

    /// Turns memory tagging on: from now on live allocations of up to
    /// [`TAG_MAX`] bytes are tagged. Call once the architecture has enabled
    /// tag checking on every CPU that allocates (the boot CPU, before the
    /// others start) and the heap is mapped as tagged memory.
    pub fn enable_tagging(&self, t: Tagging) {
        let _ = self.tagging.set(t);
    }

    /// Tags the allocation `p` of `size` bytes, if tagging is on.
    fn tag_out(&self, p: *mut u8, size: usize) -> *mut u8 {
        match self.tagging.get() {
            Some(t) if !p.is_null() && size <= TAG_MAX => {
                // SAFETY: `p` is a fresh allocation of at least `size`
                // bytes, 16-aligned (blocks are 32-aligned), in tagged memory.
                unsafe { (t.retag)(p, size.next_multiple_of(16)) }
            }
            _ => p,
        }
    }

    /// The untagged address of a pointer handed out by [`tag_out`](Self::tag_out),
    /// with its allocation tags cleared.
    fn tag_in(&self, p: *mut u8, size: usize) -> *mut u8 {
        let (Some(t), Some(v)) = (self.tagging.get(), self.view.get()) else {
            return p;
        };
        // The heap's own logical tag bits are what "untagged" means.
        let plain = (p as usize & !TAG_BITS) | (v.base() & TAG_BITS);
        let plain = plain as *mut u8;
        if size <= TAG_MAX && v.contains(plain as usize) {
            // SAFETY: the allocation is being freed; its granules are ours.
            unsafe { (t.clear)(plain, size.next_multiple_of(16)) };
        }
        plain
    }

    /// (free bytes, capacity) of the global heap (cached blocks count as used).
    pub fn stats(&self) -> Option<(usize, usize)> {
        self.global.stats()
    }

    /// [`stats`](Self::stats) without waiting (interrupt context).
    pub fn try_stats(&self) -> Option<(usize, usize)> {
        self.global.try_stats()
    }

    fn key(&self) -> usize {
        // Relaxed: written once at init, before any cache holds a block.
        self.key.load(Ordering::Relaxed)
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

    /// Writes the header of a free small block.
    ///
    /// # Safety
    /// `p` is a block of at least [`CHEAD`] bytes owned by the caller.
    unsafe fn put_header(&self, p: *mut u8, next: *mut u8, tag: usize, plen: usize) {
        let (k, a) = (self.key(), p as usize);
        // SAFETY: per the contract.
        unsafe { put(p, 0, next as usize ^ k ^ a) };
        // SAFETY: as above.
        unsafe { put(p, 8, tag ^ k ^ (a + 8)) };
        // SAFETY: as above.
        unsafe { put(p, 16, plen) };
    }

    /// Reads and validates the header of the block at the head of a list.
    ///
    /// # Safety
    /// `p` is a free small block of the cache.
    unsafe fn get_header(&self, p: *mut u8, size: usize) -> Result<Header, HeapFault> {
        let (k, a) = (self.key(), p as usize);
        // SAFETY: per the contract.
        let next = unsafe { get(p, 0) };
        // SAFETY: as above.
        let tag = unsafe { get(p, 8) };
        // SAFETY: as above.
        let plen = unsafe { get(p, 16) };
        let freed = tag == TAG_FREED ^ k ^ (a + 8);
        if !freed && tag != TAG_FRESH ^ k ^ (a + 8) {
            return Err(HeapFault::FreeListCorrupted);
        }
        let next = next ^ k ^ a;
        // A cached block is a live heap block of the class: a link to
        // anything else was not written by this allocator.
        if next != 0
            && !self
                .view
                .get()
                .is_some_and(|v| next.is_multiple_of(size) && v.is_live_start(next))
        {
            return Err(HeapFault::FreeListCorrupted);
        }
        if freed && !(CHEAD..=size).contains(&plen) {
            return Err(HeapFault::FreeListCorrupted);
        }
        Ok(Header {
            next: next as *mut u8,
            freed,
            plen,
        })
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
            // `size`, so it can hold the header.
            unsafe { self.put_header(p, list.head, TAG_FRESH, 0) };
            list.head = p;
            list.count += 1;
        }
    }

    fn drain(&self, list: &mut List, size: usize, keep: usize) -> Result<(), HeapFault> {
        let Ok(layout) = Layout::from_size_align(size, size) else {
            return Ok(());
        };
        while list.count > keep && !list.head.is_null() {
            let p = list.head;
            // SAFETY: `p` is a free block of this list.
            let h = unsafe { self.get_header(p, size)? };
            list.head = h.next;
            list.count -= 1;
            // SAFETY: every block in a class list was allocated from the
            // global heap with exactly this layout (see `class_of`); one
            // poisoned to its end is poisoned behind its header.
            unsafe { self.global.dealloc_ex(p, layout, h.freed && h.plen == size) };
        }
        Ok(())
    }

    /// Takes a block from the class list `c` (refilling it), checking it.
    fn take(&self, c: usize) -> Option<Result<*mut u8, HeapFault>> {
        let size = CLASSES.get(c).copied().unwrap_or(0);
        self.with_cache(|cache| {
            let list = cache.lists.get_mut(c)?;
            if list.head.is_null() {
                self.refill(list, size);
            }
            let p = list.head;
            if p.is_null() {
                return Some(Ok(null_mut()));
            }
            // SAFETY: `p` is a free block of this list.
            let h = match unsafe { self.get_header(p, size) } {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            if h.freed {
                // SAFETY: the block is ours; behind the header, as far as
                // its last owner used it, it is poison unless something
                // wrote to it while it was free.
                let body =
                    unsafe { core::slice::from_raw_parts(p.wrapping_add(CHEAD), h.plen - CHEAD) };
                if !all_poison(body) {
                    return Some(Err(HeapFault::WriteAfterFree));
                }
            }
            list.head = h.next;
            list.count -= 1;
            // SAFETY: the block is ours; nothing of the list stays in it.
            unsafe { core::ptr::write_bytes(p, POISON, CHEAD) };
            Some(Ok(p))
        })?
    }

    /// Puts a block back on the class list `c`, checking it.
    ///
    /// # Safety
    /// `ptr` is what the caller got from `alloc` with a layout of class `c`.
    unsafe fn give(&self, ptr: *mut u8, c: usize, used: usize) -> Option<Result<(), HeapFault>> {
        let size = CLASSES.get(c).copied().unwrap_or(0);
        let addr = ptr as usize;
        let live = self
            .view
            .get()
            .is_some_and(|v| v.is_live_start(addr) && addr.is_multiple_of(size));
        self.with_cache(|cache| {
            let Some(list) = cache.lists.get_mut(c) else {
                return Err(HeapFault::InvalidFree);
            };
            if !live {
                return Err(HeapFault::InvalidFree);
            }
            let k = self.key();
            // SAFETY: a live block of `size` bytes; the tag word is inside.
            let tag = unsafe { get(ptr, 8) };
            if tag == TAG_FREED ^ k ^ (addr + 8) || tag == TAG_FRESH ^ k ^ (addr + 8) {
                return Err(HeapFault::DoubleFree);
            }
            // What the owner can have written is what it asked for; wiping
            // that much wipes every secret it held, and costs what it used.
            let plen = used.next_multiple_of(8).clamp(CHEAD, size);
            // SAFETY: `ptr` is a block of `size` bytes we own again.
            unsafe { core::ptr::write_bytes(ptr.wrapping_add(CHEAD), POISON, plen - CHEAD) };
            // SAFETY: as above.
            unsafe { self.put_header(ptr, list.head, TAG_FREED, plen) };
            list.head = ptr;
            list.count += 1;
            if list.count * size > KEEP_BYTES {
                let keep = list.count.saturating_sub(BATCH);
                self.drain(list, size, keep)?;
            }
            Ok(())
        })
    }

    fn canary_byte(&self, addr: usize, i: usize) -> u8 {
        let c = (self.key() ^ addr).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        ((c >> ((i % 8) * 8)) as u8) ^ (i as u8).wrapping_mul(0x4b) ^ 0x5c
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
            self.account(layout, layout, 1);
            if let Some(r) = self.take(c) {
                match r {
                    Ok(p) if !p.is_null() => return self.tag_out(p, layout.size()),
                    Ok(_) => {}
                    Err(f) => crate::heap_fault(f),
                }
            }
            // SAFETY: forwarded GlobalAlloc contract.
            let p = unsafe { self.global.alloc(layout) };
            return self.tag_out(p, layout.size());
        }
        let Some(real) = padded(layout) else {
            return null_mut();
        };
        self.account(layout, real, 1);
        // SAFETY: forwarded GlobalAlloc contract.
        let p = unsafe { self.global.alloc(real) };
        if !p.is_null() && real.size() > layout.size() {
            let a = p as usize;
            for i in 0..GAP {
                let c = self.canary_byte(a, i);
                // SAFETY: inside the block (`real.size()` bytes).
                unsafe { p.wrapping_add(layout.size() + i).write(c) };
            }
        }
        self.tag_out(p, layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let ptr = self.tag_in(ptr, layout.size());
        if let Some(c) = class_of(layout) {
            self.account(layout, layout, -1);
            // SAFETY: forwarded contract: `ptr` has a layout of class `c`.
            match unsafe { self.give(ptr, c, layout.size()) } {
                Some(Ok(())) => return,
                Some(Err(f)) => crate::heap_fault(f),
                None => {}
            }
            // SAFETY: forwarded GlobalAlloc contract.
            return unsafe { self.global.dealloc(ptr, layout) };
        }
        let Some(real) = padded(layout) else {
            return;
        };
        self.account(layout, real, -1);
        // A block that is not live is the heap's to report (double or
        // invalid free); its canary is gone with its contents.
        let live = self
            .view
            .get()
            .is_none_or(|v| v.is_live_start(ptr as usize));
        if live && real.size() > layout.size() {
            let a = ptr as usize;
            let intact = (0..GAP).all(|i| {
                // SAFETY: inside the block (`real.size()` bytes).
                let b = unsafe { ptr.wrapping_add(layout.size() + i).read() };
                b == self.canary_byte(a, i)
            });
            if !intact {
                crate::heap_fault(HeapFault::RedZoneDamaged);
            }
        }
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.global.dealloc(ptr, real) }
    }
}

#[cfg(test)]
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::buddy::{self, BuddyHeap};
    use std::alloc::{alloc_zeroed, dealloc as sys_dealloc};
    use std::panic::{AssertUnwindSafe, catch_unwind};

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

    struct Rig {
        heap: Box<CachedHeap>,
        mem: *mut u8,
        mem_layout: Layout,
        _bits: Vec<u64>,
    }

    impl Rig {
        fn new() -> Self {
            let order = 20;
            let mem_layout = Layout::from_size_align(1 << order, 1 << order).unwrap();
            let mem = unsafe { alloc_zeroed(mem_layout) };
            let mut bits = vec![0u64; buddy::bitmap_bytes(order) / 8];
            let b = unsafe {
                BuddyHeap::new(
                    mem as usize,
                    order,
                    bits.as_mut_ptr(),
                    bits.len(),
                    0xfeed_f00d,
                )
            }
            .unwrap();
            let heap = Box::new(CachedHeap::new());
            heap.init(b, 0xbeef_cafe);
            heap.enable(Hooks {
                cpu: || 0,
                irq_save: || 0,
                irq_restore: |_| {},
            });
            Self {
                heap,
                mem,
                mem_layout,
                _bits: bits,
            }
        }
        fn alloc(&self, size: usize) -> *mut u8 {
            unsafe { self.heap.alloc(Layout::from_size_align(size, 8).unwrap()) }
        }
        fn free(&self, p: *mut u8, size: usize) {
            unsafe {
                self.heap
                    .dealloc(p, Layout::from_size_align(size, 8).unwrap());
            }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            unsafe { sys_dealloc(self.mem, self.mem_layout) };
        }
    }

    /// The panic message of `f`, which must panic.
    fn panic_of(f: impl FnOnce()) -> String {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = catch_unwind(AssertUnwindSafe(f));
        std::panic::set_hook(prev);
        let e = r.expect_err("expected a heap fault");
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default()
    }

    #[test]
    fn small_blocks_are_poisoned_when_freed() {
        let r = Rig::new();
        let p = r.alloc(100);
        unsafe { core::ptr::write_bytes(p, 0x42, 100) };
        r.free(p, 100);
        let blk = unsafe { core::slice::from_raw_parts(p, 128) };
        // Poisoned as far as the 100 bytes it held reach (rounded to 8).
        assert!(blk[CHEAD..104].iter().all(|&b| b == POISON));
        // Nothing of what the owner wrote survives behind the header. (The header itself holds the
        // obfuscated free-list link: random bytes, which contain 0x42 now and then, so it is not looked at.)
        assert!(!blk[CHEAD..].contains(&0x42));
        // The same block comes back, and what it held is gone.
        let q = r.alloc(100);
        assert_eq!(q, p);
        assert!(
            unsafe { core::slice::from_raw_parts(q, 104) }
                .iter()
                .all(|&b| b == POISON)
        );
        r.free(q, 100);
    }

    #[test]
    fn small_double_free_is_detected() {
        let r = Rig::new();
        let p = r.alloc(48);
        r.free(p, 48);
        let m = panic_of(|| r.free(p, 48));
        assert!(m.contains("double free"), "{m}");
    }

    #[test]
    fn small_invalid_free_is_detected() {
        let r = Rig::new();
        let p = r.alloc(128);
        // An interior pointer, a pointer outside the heap, a misaligned one.
        for bad in [unsafe { p.add(64) }, 0x1000 as *mut u8, unsafe { p.add(8) }] {
            let m = panic_of(|| r.free(bad, 64));
            assert!(m.contains("invalid free"), "{m}");
        }
        r.free(p, 128);
    }

    #[test]
    fn small_write_after_free_is_detected_on_reuse() {
        let r = Rig::new();
        let p = r.alloc(200);
        r.free(p, 200);
        unsafe { *p.add(77) = 1 };
        let m = panic_of(|| {
            let _ = r.alloc(200);
        });
        assert!(m.contains("write after free"), "{m}");
    }

    #[test]
    fn a_forged_cache_link_is_detected() {
        let r = Rig::new();
        let a = r.alloc(64);
        let b = r.alloc(64);
        r.free(a, 64);
        r.free(b, 64);
        // Overwrite the head's link with a plain pointer, as an overflow
        // from the neighbouring block would.
        unsafe { (b as *mut usize).write(a as usize) };
        let m = panic_of(|| {
            let _ = r.alloc(64);
        });
        assert!(m.contains("free list corrupted"), "{m}");
    }

    #[test]
    fn the_cache_still_balances() {
        let r = Rig::new();
        let (free0, _) = r.heap.stats().unwrap();
        let ps: Vec<_> = (0..500)
            .map(|i| (r.alloc(32 + i % 900), 32 + i % 900))
            .collect();
        for (p, n) in ps {
            r.free(p, n);
        }
        let (free1, _) = r.heap.stats().unwrap();
        // Cached blocks count as used; nothing is lost beyond the caches.
        assert!(free0 - free1 <= 7 * KEEP_BYTES + 7 * BATCH * 2048);
        assert_eq!(r.heap.live_bytes(), 0);
    }

    #[test]
    fn large_allocations_get_a_canary_gap() {
        let r = Rig::new();
        // With room in the block: 3000 B in a 4096 B block.
        let p = r.alloc(3000);
        unsafe { *p.add(3000) ^= 0xff }; // one byte past the end
        let m = panic_of(|| r.free(p, 3000));
        assert!(m.contains("heap overflow"), "{m}");
        // Always for 32 KiB and up, at the price of a larger block.
        let big = Layout::from_size_align(32 * 1024, 8).unwrap();
        assert_eq!(padded(big).unwrap().size(), 32 * 1024 + GAP);
        let p = r.alloc(32 * 1024);
        unsafe { *p.add(32 * 1024 + GAP - 1) ^= 0xff };
        let m = panic_of(|| r.free(p, 32 * 1024));
        assert!(m.contains("heap overflow"), "{m}");
        // An exact power of two below the threshold does not grow.
        let l = Layout::from_size_align(4096, 8).unwrap();
        assert_eq!(padded(l).unwrap().size(), 4096);
        // Clean use is not disturbed.
        let p = r.alloc(3000);
        unsafe { core::ptr::write_bytes(p, 1, 3000) };
        r.free(p, 3000);
    }

    use core::sync::atomic::{AtomicUsize, Ordering as O};
    static RETAGS: AtomicUsize = AtomicUsize::new(0);
    static CLEARED: AtomicUsize = AtomicUsize::new(0);
    unsafe fn fake_retag(p: *mut u8, len: usize) -> *mut u8 {
        RETAGS.fetch_add(len, O::SeqCst);
        // A logical tag of 3 in bits 59:56.
        ((p as usize & !(0xf << 56)) | (3 << 56)) as *mut u8
    }
    unsafe fn fake_clear(_p: *mut u8, len: usize) {
        CLEARED.fetch_add(len, O::SeqCst);
    }

    #[test]
    fn tagging_hooks_see_rounded_sizes_and_frees_take_tagged_pointers() {
        let r = Rig::new();
        r.heap.enable_tagging(Tagging {
            retag: fake_retag,
            clear: fake_clear,
        });
        let (a0, c0) = (RETAGS.load(O::SeqCst), CLEARED.load(O::SeqCst));
        let p = r.alloc(100); // small path
        let q = r.alloc(5000); // large path
        assert_eq!(p as usize >> 56 & 0xf, 3);
        assert_eq!(q as usize >> 56 & 0xf, 3);
        assert_eq!(RETAGS.load(O::SeqCst) - a0, 112 + 5008);
        // The allocator accepts the tagged pointers back (it works on the
        // untagged address), and clears the tags of what was tagged.
        r.free(p, 100);
        r.free(q, 5000);
        assert_eq!(CLEARED.load(O::SeqCst) - c0, 112 + 5008);
        // A double free through a tagged pointer is still a double free.
        let m = panic_of(|| r.free(p, 100));
        assert!(m.contains("double free"), "{m}");
    }

    #[test]
    fn large_double_free_is_detected() {
        let r = Rig::new();
        let p = r.alloc(5000);
        r.free(p, 5000);
        let m = panic_of(|| r.free(p, 5000));
        assert!(m.contains("double free"), "{m}");
    }
}
