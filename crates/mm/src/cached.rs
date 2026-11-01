//! Per-CPU allocation caches in front of the global buddy heap (M13, the
//! "per-core slabs" of PROMPT §7.2, ADR-032).
//!
//! Blocks of up to 128 KiB (13 power-of-two classes matching the buddy
//! orders) come from the current CPU's free lists. Refills and drains move
//! a batch (16 small blocks, fewer big ones: [`batch_of`]) under the global
//! lock at once, so on the data path the lock is taken roughly once per
//! sixteen small or eight to two big allocations. A block freed on another
//! CPU simply joins that CPU's cache. With a ticket lock and virtual CPUs,
//! that cut is what keeps cores from queueing behind a descheduled lock
//! holder (ADR-230: the record and segment buffers of 2 to 64 KiB, a
//! thousand a second on a busy flow, used to take the lock every time).
//! Blocks above 2 KiB keep the canary gap of the large path.
//!
//! Between the CPUs' lists and the buddy heap sits a **depot** per class: full
//! magazines (a list of exactly one batch) that a CPU with too many blocks
//! leaves and a CPU with none takes, one pointer each under a lock of its own
//! that is held for a few nanoseconds. A flow whose messages are allocated on
//! one core and freed on another (every message a broker relays) used to visit
//! the heap's lock sixteen thousand times a second per core, and on a VPS whose
//! vCPUs the host preempts that lock was the first thing the data cores waited
//! for (40 % of two cores' time in the worst second); a visit now is the
//! splice of a list (ADR-230).
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
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};

use urmqtt_sync::sync::{OnceCell, SpinLock};

use crate::LockedHeap;
use crate::buddy::{AllocView, HeapFault, POISON, POISON_WORD};

/// Block sizes, one per buddy order from `buddy::MIN_ORDER`.
pub const CLASSES: [usize; 13] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
];
/// The largest block of the small path (no canary gap); bigger ones are
/// "large" allocations, cached as well but padded with the canary.
pub const SMALL_MAX: usize = 2048;
pub const MAX_CPUS: usize = 64;
/// Most blocks moved per refill or drain.
pub const BATCH: usize = 16;
/// Bytes moved per refill or drain of a class of big blocks.
pub const BATCH_BYTES: usize = 32 * 1024;
/// Bytes a CPU keeps per class of small blocks before it returns a batch.
pub const KEEP_BYTES: usize = 32 * 1024;
/// Bytes a class's depot keeps (magazines of other CPUs' blocks); the depot
/// absorbs the bursts of one core's frees (a pass frees dozens of messages
/// at once) against the steady takes of another.
pub const DEPOT_BYTES: usize = 2 * 1024 * 1024;
/// Magazines a depot holds at most.
const DEPOT_MAGS: usize = 128;
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
    /// A monotonic clock, for the statistics of time spent in the global heap.
    pub clock: fn() -> u64,
    pub cpu: fn() -> usize,
    pub irq_save: fn() -> u64,
    pub irq_restore: fn(u64),
}

#[derive(Clone, Copy)]
struct List {
    /// First free block; each free block stores the next pointer.
    head: *mut u8,
    count: usize,
    /// Something was taken from or given to the list since the last
    /// [`CachedHeap::trim`].
    touched: bool,
}

struct Cache {
    lists: [List; CLASSES.len()],
}

/// The magazines one class's depot holds (heads of lists of `batch_of` blocks,
/// as addresses).
struct Depot {
    mags: [usize; DEPOT_MAGS],
    n: usize,
}

pub struct CachedHeap {
    global: LockedHeap,
    caches: [UnsafeCell<Cache>; MAX_CPUS],
    depots: [SpinLock<Depot>; CLASSES.len()],
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
    /// Per CPU, since the last [`take_ops`](Self::take_ops): allocations too
    /// large for the caches, the KiB they took, refills and drains of the
    /// caches (each one a visit to the global lock).
    ops: [[AtomicU64; 7]; MAX_CPUS],
    /// The heap is short of memory: blocks above [`SMALL_MAX`] are not kept
    /// in the caches (see [`set_pressure`](Self::set_pressure)).
    pressure: AtomicBool,
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

/// The class of a layout of the small path: blocks of up to [`SMALL_MAX`].
pub fn small_class(layout: Layout) -> Option<usize> {
    class_of(layout).filter(|&c| CLASSES.get(c).is_some_and(|&s| s <= SMALL_MAX))
}

/// Blocks a refill or drain of the class of `size`-byte blocks moves:
/// [`BATCH`] small ones, [`BATCH_BYTES`] worth of big ones (at least one).
pub const fn batch_of(size: usize) -> usize {
    let n = BATCH_BYTES / size;
    if n < 1 {
        1
    } else if n > BATCH {
        BATCH
    } else {
        n
    }
}

/// Magazines the depot of the class of `size`-byte blocks holds at most.
pub const fn depot_mags(size: usize) -> usize {
    let bytes = if size <= SMALL_MAX {
        DEPOT_BYTES
    } else {
        DEPOT_BYTES / 2
    };
    let n = bytes / (batch_of(size) * size);
    if n < 1 {
        1
    } else if n > DEPOT_MAGS {
        DEPOT_MAGS
    } else {
        n
    }
}

/// Bytes a CPU keeps per class before it returns a batch: [`KEEP_BYTES`] of
/// small blocks, two batches of big ones, one block of 64 KiB and more (a
/// buffer that big is rare and a cache of them is a lot of memory idle).
pub const fn keep_of(size: usize) -> usize {
    if size <= SMALL_MAX {
        KEEP_BYTES
    } else if size >= 64 * 1024 {
        size
    } else {
        2 * batch_of(size) * size
    }
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
                        touched: false,
                    }; CLASSES.len()],
                })
            }; MAX_CPUS],
            hooks: OnceCell::new(),
            view: OnceCell::new(),
            tagging: OnceCell::new(),
            key: AtomicUsize::new(0x9e37_79b9_7f4a_7c15),
            live: [const { AtomicI64::new(0) }; MAX_CPUS],
            blocks: [const { AtomicI64::new(0) }; MAX_CPUS],
            ops: [const { [const { AtomicU64::new(0) }; 7] }; MAX_CPUS],
            depots: [const {
                SpinLock::new(Depot {
                    mags: [0; DEPOT_MAGS],
                    n: 0,
                })
            }; CLASSES.len()],
            pressure: AtomicBool::new(false),
        }
    }

    /// Tells the caches whether the heap is short of memory. Blocks above
    /// [`SMALL_MAX`] can be a lot of memory (up to 672 KiB per CPU) that
    /// the admission control, which counts the free memory of the global
    /// heap, cannot see; with the flag set they go straight back to the
    /// heap, and [`trim`](Self::trim) returns the ones already cached.
    pub fn set_pressure(&self, on: bool) {
        // Relaxed: a hint, read on every free of a big block.
        self.pressure.store(on, Ordering::Relaxed);
    }

    /// Whether the heap was reported short of memory.
    pub fn pressure(&self) -> bool {
        // Relaxed: as above.
        self.pressure.load(Ordering::Relaxed)
    }

    /// Returns this CPU's cached blocks above [`SMALL_MAX`] to the heap: all
    /// of them under pressure, otherwise the lists nothing took from or gave
    /// to since the last call. A cache is for a flow that goes on, not for
    /// what was used once; every data core calls this every few seconds.
    pub fn trim(&self) {
        let pressure = self.pressure();
        let r = self.with_cache(|cache| -> Result<(), HeapFault> {
            for (c, list) in cache.lists.iter_mut().enumerate() {
                let size = CLASSES.get(c).copied().unwrap_or(0);
                // Under pressure every class goes, small ones too; otherwise
                // only the big ones nothing used lately.
                if size <= SMALL_MAX && !pressure {
                    continue;
                }
                let used = core::mem::take(&mut list.touched);
                if list.count > 0 && (pressure || !used) {
                    self.drain(list, c, 0, true)?;
                }
                if pressure {
                    // The magazines other CPUs left come back as well.
                    while let Some(head) = self.depot_pop(c) {
                        let mut mag = List {
                            head: head as *mut u8,
                            count: batch_of(size),
                            touched: false,
                        };
                        self.drain(&mut mag, c, 0, true)?;
                    }
                }
            }
            Ok(())
        });
        if let Some(Err(f)) = r {
            crate::heap_fault(f);
        }
    }

    /// Runs `f` (a call into the global heap) and adds the time it took.
    fn timed<R>(&self, f: impl FnOnce() -> R) -> R {
        let Some(h) = self.hooks.get() else {
            return f();
        };
        let t0 = (h.clock)();
        let r = f();
        let dt = (h.clock)().saturating_sub(t0);
        if let Some(c) = self.ops.get((h.cpu)()).and_then(|o| o.get(4)) {
            // Relaxed: a statistic, written by its own CPU.
            c.fetch_add(dt, Ordering::Relaxed);
        }
        r
    }

    fn note(&self, kind: usize, n: u64) {
        let cpu = self.hooks.get().map_or(0, |h| (h.cpu)());
        if let Some(c) = self.ops.get(cpu).and_then(|o| o.get(kind)) {
            // Relaxed: a statistic, written by its own CPU.
            c.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Visits to the global lock this CPU made since the last call:
    /// `[large allocations, their KiB, cache refills, cache drains, clock
    /// ticks spent inside the global heap (waiting for its lock and holding it),
    /// refills from a depot, drains to a depot]` (the last two do not touch the
    /// global heap).
    pub fn take_ops(&self, cpu: usize) -> [u64; 7] {
        let mut out = [0; 7];
        if let Some(o) = self.ops.get(cpu) {
            for (v, c) in out.iter_mut().zip(o) {
                // Relaxed: a statistic.
                *v = c.swap(0, Ordering::Relaxed);
            }
        }
        out
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
    /// The address of the global heap's lock (see `LockedHeap::lock_addr`).
    pub fn lock_addr(&self) -> usize {
        self.global.lock_addr()
    }

    pub fn stats(&self) -> Option<(usize, usize)> {
        self.global.stats()
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
        if freed && !(CHEAD..=crate::buddy::prange(size)).contains(&plen) {
            return Err(HeapFault::FreeListCorrupted);
        }
        Ok(Header {
            next: next as *mut u8,
            freed,
            plen,
        })
    }

    /// Takes a full magazine out of the depot of class `c`, if one is there.
    fn depot_pop(&self, c: usize) -> Option<usize> {
        let mut d = self.depots.get(c)?.lock();
        let n = d.n.checked_sub(1)?;
        d.n = n;
        d.mags.get(n).copied()
    }

    /// Whether the depot of class `c` has room for a magazine.
    fn depot_has_room(&self, c: usize) -> bool {
        let size = CLASSES.get(c).copied().unwrap_or(usize::MAX);
        self.depots
            .get(c)
            .is_some_and(|d| d.lock().n < depot_mags(size))
    }

    /// Puts a magazine into the depot of class `c`; false if it is full.
    fn depot_push(&self, c: usize, head: usize) -> bool {
        let size = CLASSES.get(c).copied().unwrap_or(usize::MAX);
        let Some(d) = self.depots.get(c) else {
            return false;
        };
        let mut d = d.lock();
        let n = d.n;
        if n >= depot_mags(size) {
            return false;
        }
        if let Some(slot) = d.mags.get_mut(n) {
            *slot = head;
            d.n = n + 1;
            return true;
        }
        false
    }

    fn refill(&self, list: &mut List, c: usize) {
        let size = CLASSES.get(c).copied().unwrap_or(0);
        // A magazine another CPU left: a splice, no work in the global heap.
        if list.head.is_null()
            && let Some(head) = self.depot_pop(c)
        {
            list.head = head as *mut u8;
            list.count += batch_of(size);
            self.note(5, 1);
            return;
        }
        let Ok(layout) = Layout::from_size_align(size, size) else {
            return;
        };
        self.note(2, 1);
        // One hold of the global lock for the whole batch.
        let mut got: [*mut u8; BATCH] = [null_mut(); BATCH];
        let mut n = 0;
        self.timed(|| {
            // SAFETY: a valid, non-zero layout.
            unsafe {
                self.global.alloc_many(layout, batch_of(size), |p| {
                    if let Some(slot) = got.get_mut(n) {
                        *slot = p;
                        n += 1;
                    }
                })
            }
        });
        for &p in got.iter().take(n) {
            // SAFETY: `p` is a fresh block of `size` >= 32 bytes, aligned to
            // `size`, so it can hold the header.
            unsafe { self.put_header(p, list.head, TAG_FRESH, 0) };
            list.head = p;
            list.count += 1;
        }
    }

    /// Cuts the first `batch` blocks off the list as a magazine and hands it
    /// to the depot of class `c`. Returns whether it did (the list is as it
    /// was if not).
    fn to_depot(&self, list: &mut List, c: usize, size: usize) -> Result<bool, HeapFault> {
        let batch = batch_of(size);
        if list.count < batch || !self.depot_has_room(c) {
            return Ok(false);
        }
        let head = list.head;
        let (mut p, mut tail, mut after) = (head, head, null_mut());
        for _ in 0..batch {
            // SAFETY: `p` is a free block of this list.
            let h = unsafe { self.get_header(p, size) }?;
            (tail, after, p) = (p, h.next, h.next);
        }
        // SAFETY: `tail` is a free block of this list.
        let t = unsafe { self.get_header(tail, size) }?;
        let tag = if t.freed { TAG_FREED } else { TAG_FRESH };
        // The magazine ends at `tail`.
        // SAFETY: a block of the class that we own.
        unsafe { self.put_header(tail, null_mut(), tag, t.plen) };
        if self.depot_push(c, head as usize) {
            list.head = after;
            list.count -= batch;
            self.note(6, 1);
            Ok(true)
        } else {
            // The depot filled up meanwhile: the list as it was.
            // SAFETY: as above.
            unsafe { self.put_header(tail, after, tag, t.plen) };
            Ok(false)
        }
    }

    /// Drains the list of class `c` down to `keep` blocks: whole magazines to
    /// the depot (unless `to_heap`), the rest to the global heap.
    fn drain(
        &self,
        list: &mut List,
        c: usize,
        keep: usize,
        to_heap: bool,
    ) -> Result<(), HeapFault> {
        let size = CLASSES.get(c).copied().unwrap_or(0);
        let Ok(layout) = Layout::from_size_align(size, size) else {
            return Ok(());
        };
        while !to_heap && list.count > keep && self.to_depot(list, c, size)? {}
        if list.count <= keep || list.head.is_null() {
            return Ok(());
        }
        // The blocks leave in groups of up to 16, each group under one hold of
        // the global lock; what is left to poison is poisoned before it.
        self.note(3, 1);
        let mut group: [*mut u8; BATCH] = [null_mut(); BATCH];
        let mut n = 0;
        let mut fault = None;
        while list.count > keep && !list.head.is_null() {
            let p = list.head;
            // SAFETY: `p` is a free block of this list.
            let h = match unsafe { self.get_header(p, size) } {
                Ok(h) => h,
                Err(e) => {
                    fault = Some(e);
                    break;
                }
            };
            list.head = h.next;
            list.count -= 1;
            if !(h.freed && h.plen == crate::buddy::prange(size)) {
                // SAFETY: a block of `size` bytes of ours, about to be freed.
                unsafe { crate::buddy::poison_for_free(p, size) };
            }
            if let Some(slot) = group.get_mut(n) {
                *slot = p;
                n += 1;
            }
            if n == group.len() {
                // SAFETY: every block in a class list was allocated from the
                // global heap with exactly this layout (see `class_of`) and is
                // poisoned behind its header.
                unsafe { self.timed(|| self.global.dealloc_many(layout, &group)) };
                n = 0;
            }
        }
        if n > 0 {
            // SAFETY: as above.
            unsafe {
                self.timed(|| {
                    self.global
                        .dealloc_many(layout, group.get(..n).unwrap_or(&[]))
                })
            };
        }
        match fault {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Takes a block from the class list `c` (refilling it), checking it.
    fn take(&self, c: usize) -> Option<Result<*mut u8, HeapFault>> {
        let size = CLASSES.get(c).copied().unwrap_or(0);
        self.with_cache(|cache| {
            let list = cache.lists.get_mut(c)?;
            list.touched = true;
            if list.head.is_null() {
                self.refill(list, c);
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
        if size > SMALL_MAX && self.pressure() {
            // Not kept: the caller frees it to the heap.
            return None;
        }
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
            list.touched = true;
            // SAFETY: a live block of `size` bytes; the tag word is inside.
            if unsafe { self.is_free_in_cache(ptr) } {
                return Err(HeapFault::DoubleFree);
            }
            // What the owner can have written is what it asked for; wiping
            // that much wipes every secret it held, and costs what it used.
            let plen = used
                .next_multiple_of(8)
                .clamp(CHEAD, crate::buddy::prange(size));
            // SAFETY: `ptr` is a block of `size` bytes we own again.
            unsafe { core::ptr::write_bytes(ptr.wrapping_add(CHEAD), POISON, plen - CHEAD) };
            // SAFETY: as above.
            unsafe { self.put_header(ptr, list.head, TAG_FREED, plen) };
            list.head = ptr;
            list.count += 1;
            if list.count * size > keep_of(size) {
                let keep = list.count.saturating_sub(batch_of(size));
                self.drain(list, c, keep, self.pressure())?;
            }
            Ok(())
        })
    }

    /// Whether `ptr`, a live heap block, is one a cache holds free (its tag
    /// word says so): freeing it again is a double free.
    ///
    /// # Safety
    /// `ptr` is a live heap block (of at least 32 bytes).
    unsafe fn is_free_in_cache(&self, ptr: *mut u8) -> bool {
        let (k, addr) = (self.key(), ptr as usize);
        // SAFETY: per the contract the tag word is inside the block.
        let tag = unsafe { get(ptr, 8) };
        tag == TAG_FREED ^ k ^ (addr + 8) || tag == TAG_FRESH ^ k ^ (addr + 8)
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

impl CachedHeap {
    /// A block of class `c` for the (padded) layout `real`: from this CPU's
    /// cache, refilled when empty, else from the global heap.
    ///
    /// # Safety
    /// As `GlobalAlloc::alloc`; `c` is `class_of(real)`.
    unsafe fn alloc_class(&self, c: usize, real: Layout) -> *mut u8 {
        if let Some(r) = self.take(c) {
            match r {
                Ok(p) if !p.is_null() => return p,
                Ok(_) => {}
                Err(f) => crate::heap_fault(f),
            }
        }
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.timed(|| self.global.alloc(real)) }
    }
}

// SAFETY: blocks of up to 128 KiB are buddy blocks of their class (`class_of`
// matches the buddy's own rounding), so a block may be served from or
// returned to any CPU's list and finally to the global heap with the class
// layout.
unsafe impl GlobalAlloc for CachedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(c) = small_class(layout) {
            self.account(layout, layout, 1);
            if let Some(r) = self.take(c) {
                match r {
                    Ok(p) if !p.is_null() => return self.tag_out(p, layout.size()),
                    Ok(_) => {}
                    Err(f) => crate::heap_fault(f),
                }
            }
            // SAFETY: forwarded GlobalAlloc contract.
            let p = unsafe { self.timed(|| self.global.alloc(layout)) };
            return self.tag_out(p, layout.size());
        }
        let Some(real) = padded(layout) else {
            return null_mut();
        };
        self.account(layout, real, 1);
        let p = match class_of(real) {
            // SAFETY: forwarded GlobalAlloc contract.
            Some(c) => unsafe { self.alloc_class(c, real) },
            None => {
                self.note(0, 1);
                self.note(1, (real.size() as u64) >> 10);
                // SAFETY: forwarded GlobalAlloc contract.
                unsafe { self.timed(|| self.global.alloc(real)) }
            }
        };
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
        if let Some(c) = small_class(layout) {
            self.account(layout, layout, -1);
            // SAFETY: forwarded contract: `ptr` has a layout of class `c`.
            match unsafe { self.give(ptr, c, layout.size()) } {
                Some(Ok(())) => return,
                Some(Err(f)) => crate::heap_fault(f),
                None => {}
            }
            // SAFETY: forwarded GlobalAlloc contract.
            return unsafe { self.timed(|| self.global.dealloc(ptr, layout)) };
        }
        let Some(real) = padded(layout) else {
            return;
        };
        self.account(layout, real, -1);
        // A block that is not live is the heap's to report (double or
        // invalid free); its canary is gone with its contents. So is one a
        // cache holds free: its poison covers the canary (`give` reports it).
        let live = self
            .view
            .get()
            .is_none_or(|v| v.is_live_start(ptr as usize));
        // SAFETY: a live heap block has at least 32 bytes.
        if live && real.size() > layout.size() && !unsafe { self.is_free_in_cache(ptr) } {
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
        if let Some(c) = class_of(real) {
            // SAFETY: forwarded contract: `ptr` has a layout of class `c`
            // (`real` is what `alloc` asked for).
            match unsafe { self.give(ptr, c, layout.size()) } {
                Some(Ok(())) => return,
                Some(Err(f)) => crate::heap_fault(f),
                None => {}
            }
            // SAFETY: forwarded GlobalAlloc contract.
            return unsafe { self.timed(|| self.global.dealloc(ptr, real)) };
        }
        if live {
            // The poison fill (up to 16 KiB) runs here, before the lock, and
            // the heap is told it is done (ADR-230): inside the lock it made
            // every large free hold every other core up for microseconds. The
            // block is a live block of its own start (checked above), so
            // nothing but its own bytes is written.
            if let Some(order_size) = real
                .size()
                .max(real.align())
                .max(1)
                .checked_next_power_of_two()
                .map(|s| s.max(crate::buddy::HEADER))
            {
                // SAFETY: a live block of `order_size` bytes, about to be freed.
                unsafe { crate::buddy::poison_for_free(ptr, order_size) };
                // SAFETY: forwarded GlobalAlloc contract; poisoned as announced.
                return unsafe { self.timed(|| self.global.dealloc_ex(ptr, real, true)) };
            }
        }
        // SAFETY: forwarded GlobalAlloc contract.
        unsafe { self.timed(|| self.global.dealloc(ptr, real)) }
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
        assert_eq!(small_class(l(2048, 8)), Some(6));
        assert_eq!(class_of(l(2049, 8)), Some(7));
        assert_eq!(small_class(l(2049, 8)), None);
        assert_eq!(class_of(l(8, 4096)), Some(7));
        assert_eq!(class_of(l(131072, 8)), Some(12));
        assert_eq!(class_of(l(131073, 8)), None);
        // 64 KiB of small blocks per refill, 32 KiB of big ones.
        assert_eq!(batch_of(32), BATCH);
        assert_eq!(batch_of(2048), BATCH);
        assert_eq!(batch_of(4096), 8);
        assert_eq!(batch_of(32768), 1);
        assert_eq!(batch_of(131072), 1);
        assert_eq!(keep_of(2048), KEEP_BYTES);
        assert_eq!(keep_of(4096), 64 * 1024);
        assert_eq!(keep_of(32768), 64 * 1024);
        assert_eq!(keep_of(65536), 65536);
        assert_eq!(keep_of(131072), 131072);
    }

    struct Rig {
        heap: Box<CachedHeap>,
        mem: *mut u8,
        mem_layout: Layout,
        _bits: Vec<u64>,
    }

    impl Rig {
        fn new() -> Self {
            Self::with_cpu(|| 0)
        }
        fn with_cpu(cpu: fn() -> usize) -> Self {
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
                clock: || 0,
                cpu,
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
        assert!(!blk.contains(&0x42));
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
        let slack: usize = CLASSES
            .iter()
            .map(|&s| keep_of(s) + batch_of(s) * s + depot_mags(s) * batch_of(s) * s)
            .sum();
        assert!(free0 - free1 <= slack);
        assert_eq!(r.heap.live_bytes(), 0);
    }

    #[test]
    fn blocks_freed_on_another_cpu_reach_the_first_through_the_depot() {
        use core::sync::atomic::{AtomicUsize, Ordering as O};
        static CUR: AtomicUsize = AtomicUsize::new(0);
        let r = Rig::with_cpu(|| CUR.load(O::SeqCst));
        r.heap.take_ops(0);
        r.heap.take_ops(1);
        // CPU 0 allocates, CPU 1 frees, again and again: 100-byte blocks (the 128
        // class), 20 000 of them.
        let (mut through_depot, mut heap_visits) = (0, 0);
        for _ in 0..200 {
            let mut v = Vec::new();
            CUR.store(0, O::SeqCst);
            for _ in 0..100 {
                v.push(r.alloc(100));
            }
            CUR.store(1, O::SeqCst);
            for p in v {
                r.free(p, 100);
            }
            let (a, b) = (r.heap.take_ops(0), r.heap.take_ops(1));
            through_depot += a[5] + b[6];
            heap_visits += a[2] + a[3] + b[2] + b[3];
        }
        assert!(
            through_depot > 100,
            "magazines moved through the depot: {through_depot}"
        );
        // The heap's lock was visited at the start and at the edges of the depot,
        // not for every sixteen blocks (there were 1 250 batches each way).
        assert!(heap_visits < 100, "{heap_visits} visits to the heap");
        CUR.store(0, O::SeqCst);
        assert_eq!(r.heap.live_bytes(), 0);
    }

    #[test]
    fn a_depot_gives_its_blocks_back_to_the_heap_under_pressure() {
        use core::sync::atomic::{AtomicUsize, Ordering as O};
        static CUR: AtomicUsize = AtomicUsize::new(0);
        let r = Rig::with_cpu(|| CUR.load(O::SeqCst));
        let (free0, _) = r.heap.stats().unwrap();
        CUR.store(0, O::SeqCst);
        let v: Vec<_> = (0..64).map(|_| r.alloc(100)).collect();
        CUR.store(1, O::SeqCst);
        for p in v {
            r.free(p, 100);
        }
        // CPU 1 holds some, the depot others; nothing is back in the heap yet.
        let (free1, _) = r.heap.stats().unwrap();
        assert!(free0 - free1 >= 48 * 128);
        r.heap.set_pressure(true);
        r.heap.trim();
        let (free2, _) = r.heap.stats().unwrap();
        assert!(free2 > free1);
        // CPU 0's own lists have what it took in batches; the rest is back.
        CUR.store(0, O::SeqCst);
        r.heap.trim();
        let (free3, _) = r.heap.stats().unwrap();
        assert_eq!(free3, free0, "everything is back");
        assert_eq!(r.heap.live_bytes(), 0);
    }

    #[test]
    fn big_blocks_are_cached_poisoned_and_checked_like_small_ones() {
        let r = Rig::new();
        // 5000 bytes: a 8 KiB block, room for the canary.
        let p = r.alloc(5000);
        unsafe { core::ptr::write_bytes(p, 0x42, 5000) };
        r.free(p, 5000);
        let blk = unsafe { core::slice::from_raw_parts(p, 8192) };
        assert!(blk[CHEAD..5000].iter().all(|&b| b == POISON));
        // The same block comes back (no visit to the global lock for it).
        r.heap.take_ops(0);
        let q = r.alloc(5000);
        assert_eq!(q, p);
        assert_eq!(
            r.heap.take_ops(0)[0],
            0,
            "a big block is not a large allocation"
        );
        // A write after free is found at the reuse.
        r.free(q, 5000);
        unsafe { *q.add(4000) = 1 };
        let m = panic_of(|| {
            let _ = r.alloc(5000);
        });
        assert!(m.contains("write after free"), "{m}");
    }

    #[test]
    fn big_blocks_are_not_kept_under_pressure_and_idle_ones_are_trimmed() {
        let r = Rig::new();
        let (free0, _) = r.heap.stats().unwrap();
        // Normally a freed big block stays in the cache (the heap does not get it back).
        let p = r.alloc(20_000);
        r.free(p, 20_000);
        let (free1, _) = r.heap.stats().unwrap();
        assert!(free0 - free1 >= 32 * 1024, "{}", free0 - free1);
        // A flow that goes on keeps its list; an idle one is returned.
        let q = r.alloc(20_000);
        r.free(q, 20_000);
        r.heap.trim();
        let (free2, _) = r.heap.stats().unwrap();
        assert!(free0 - free2 >= 32 * 1024, "used since the last call: kept");
        r.heap.trim();
        let (free3, _) = r.heap.stats().unwrap();
        // Everything above the small classes is back (the small caches of the
        // earlier tests' use hold what they hold).
        assert!(free3 > free2, "idle: returned");
        assert!(free0 - free3 < 32 * 1024, "{}", free0 - free3);
        // Under pressure a freed big block goes straight back; small ones are cached.
        r.heap.set_pressure(true);
        let (a, _) = r.heap.stats().unwrap();
        let p = r.alloc(20_000);
        r.free(p, 20_000);
        let (b, _) = r.heap.stats().unwrap();
        assert_eq!(a, b, "not kept");
        let s = r.alloc(100);
        r.free(s, 100);
        let (c, _) = r.heap.stats().unwrap();
        assert!(c < b, "small blocks are still cached");
        // And what is cached is let go by the next trim.
        r.heap.set_pressure(false);
        let p = r.alloc(20_000);
        r.free(p, 20_000);
        r.heap.set_pressure(true);
        let (d0, _) = r.heap.stats().unwrap();
        r.heap.trim();
        let (d1, _) = r.heap.stats().unwrap();
        assert!(d1 > d0, "trimmed under pressure");
        assert_eq!(r.heap.live_bytes(), 0);
    }

    #[test]
    fn big_blocks_keep_the_canary_and_the_double_free_check() {
        let r = Rig::new();
        let p = r.alloc(3000);
        unsafe { *p.add(3000) ^= 0xff };
        let m = panic_of(|| r.free(p, 3000));
        assert!(m.contains("heap overflow"), "{m}");
        let p = r.alloc(20_000);
        r.free(p, 20_000);
        let m = panic_of(|| r.free(p, 20_000));
        assert!(m.contains("double free"), "{m}");
        // Beyond the poison limit the block is not poisoned (as in the heap).
        let p = r.alloc(40_000);
        unsafe { core::ptr::write_bytes(p, 0x42, 40_000) };
        r.free(p, 40_000);
        let blk = unsafe { core::slice::from_raw_parts(p, 40_000) };
        assert!(blk[CHEAD..buddy::POISON_LIMIT].iter().all(|&b| b == POISON));
        assert!(blk[buddy::POISON_LIMIT..40_000].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn big_blocks_freed_on_another_cpu_balance_through_the_global_heap() {
        use core::sync::atomic::{AtomicUsize, Ordering as O};
        static CUR: AtomicUsize = AtomicUsize::new(0);
        let r = Rig::with_cpu(|| CUR.load(O::SeqCst));
        let (free0, _) = r.heap.stats().unwrap();
        r.heap.take_ops(0);
        r.heap.take_ops(1);
        for round in 0..40 {
            let mut v = Vec::new();
            CUR.store(0, O::SeqCst);
            for i in 0..24 {
                v.push((r.alloc(2100 + 90 * i + round), 2100 + 90 * i + round));
            }
            CUR.store(1, O::SeqCst);
            for (p, n) in v {
                r.free(p, n);
            }
        }
        CUR.store(0, O::SeqCst);
        let (free1, _) = r.heap.stats().unwrap();
        let slack: usize = CLASSES
            .iter()
            .map(|&s| 2 * (keep_of(s) + batch_of(s) * s) + depot_mags(s) * batch_of(s) * s)
            .sum();
        assert!(free0 - free1 <= slack, "{} > {slack}", free0 - free1);
        assert_eq!(r.heap.live_bytes(), 0);
        // CPU 0 filled its cache by refills, CPU 1 emptied its by drains (mostly
        // through the depot); neither went to the heap for a single block.
        let (a, b) = (r.heap.take_ops(0), r.heap.take_ops(1));
        assert_eq!(a[0] + b[0], 0);
        assert!(a[2] + a[5] > 0 && b[3] + b[6] > 0, "{a:?} {b:?}");
        assert!(a[2] + a[5] < 24 * 40 / 2, "refills batch the lock: {a:?}");
        assert!(a[5] > a[2], "the depot served most of them: {a:?}");
    }

    /// A random workload on three CPUs, blocks allocated on one and freed on
    /// another, pressure switching on and off and trims between: every block
    /// keeps its contents while live, and at the end everything is back.
    #[test]
    fn random_workload_across_cpus_depots_and_pressure_keeps_every_block_intact() {
        use core::sync::atomic::{AtomicUsize, Ordering as O};
        static CUR: AtomicUsize = AtomicUsize::new(0);
        let r = Rig::with_cpu(|| CUR.load(O::SeqCst));
        let (free0, _) = r.heap.stats().unwrap();
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        // (pointer, size, fill byte)
        let mut live: Vec<(*mut u8, usize, u8)> = Vec::new();
        for step in 0..30_000u32 {
            CUR.store((next() % 3) as usize, O::SeqCst);
            match next() % 100 {
                0..=54 if live.len() < 120 => {
                    let size = match next() % 10 {
                        0..=5 => 1 + (next() % 300) as usize,
                        6..=7 => 300 + (next() % 3000) as usize,
                        8 => 3000 + (next() % 20_000) as usize,
                        _ => 1 + (next() % 60) as usize,
                    };
                    let p = r.alloc(size);
                    assert!(!p.is_null(), "step {step}: {size} bytes");
                    let fill = (next() % 251) as u8 + 1;
                    unsafe { core::ptr::write_bytes(p, fill, size) };
                    live.push((p, size, fill));
                }
                55..=94 if !live.is_empty() => {
                    let i = (next() as usize) % live.len();
                    let (p, size, fill) = live.swap_remove(i);
                    let body = unsafe { core::slice::from_raw_parts(p, size) };
                    assert!(
                        body.iter().all(|&b| b == fill),
                        "step {step}: block damaged"
                    );
                    r.free(p, size);
                }
                95..=96 => r.heap.trim(),
                97 => r.heap.set_pressure(next() % 4 == 0),
                _ => {}
            }
        }
        for (p, size, fill) in live.drain(..) {
            let body = unsafe { core::slice::from_raw_parts(p, size) };
            assert!(body.iter().all(|&b| b == fill));
            r.free(p, size);
        }
        r.heap.set_pressure(true);
        for cpu in 0..3 {
            CUR.store(cpu, O::SeqCst);
            r.heap.trim();
        }
        let (free1, _) = r.heap.stats().unwrap();
        assert_eq!(free1, free0, "every block came back");
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
