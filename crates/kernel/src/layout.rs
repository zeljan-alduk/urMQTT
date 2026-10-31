//! Kernel virtual address layout (TTBR1 / the upper half of CR3's tree,
//! 48-bit canonical addresses; every base below is canonical on both).
//!
//! ```text
//! 0xffff_0000_0000_0000  HHDM (offset chosen by Limine, kept as is)
//! 0xffff_c000_0000_0000  MMIO window        (1 GiB, device memory)       } each region sits at a
//! 0xffff_d000_0000_0000  kernel heap        (buddy region)                 } random place inside
//! 0xffff_d800_0000_0000  heap bookkeeping   (buddy bitmaps)                } its window at every
//! 0xffff_e000_0000_0000  per-CPU stacks     (1 MiB stride, guard pages)    } boot (ADR-173); the
//! 0xffff_f000_0000_0000  page-table alias   (RW view of the table pool)    } rest is unmapped
//! 0xffff_ffff_8000_0000  kernel image       (RX text, R rodata, RW data/bss; linker.ld;
//!                                            slid by Limine on aarch64, ADR-173)
//! ```
//! The lower half (TTBR0) is disabled with `TCR_EL1.EPD0`; on x86_64 the
//! root simply has no lower-half entries. Limine's x86_64 HHDM starts at
//! `0xffff_8000_0000_0000` (the first canonical upper-half address).

use core::sync::atomic::{AtomicU64, Ordering};

/// Where each region's window begins; the region itself sits at a random,
/// aligned place inside its window, chosen at every boot ([`randomise`],
/// ADR-173). The windows do not overlap and are far above the HHDM.
pub const MMIO_WINDOW: u64 = 0xffff_c000_0000_0000;
pub const MMIO_SIZE: u64 = 1 << 30;
pub const HEAP_WINDOW: u64 = 0xffff_d000_0000_0000;
pub const HEAP_META_WINDOW: u64 = 0xffff_d800_0000_0000;
pub const STACKS_WINDOW: u64 = 0xffff_e000_0000_0000;
pub const PT_ALIAS_WINDOW: u64 = 0xffff_f000_0000_0000;
/// The room each of the last four windows has to move in: 4 TiB.
const WINDOW_SPAN: u64 = 1 << 42;
/// The MMIO region moves inside its 512 GiB top-level slot, by whole GiB.
const MMIO_SPAN: u64 = 1 << 39;

static MMIO_AT: AtomicU64 = AtomicU64::new(MMIO_WINDOW);
static HEAP_AT: AtomicU64 = AtomicU64::new(HEAP_WINDOW);
static HEAP_META_AT: AtomicU64 = AtomicU64::new(HEAP_META_WINDOW);
static STACKS_AT: AtomicU64 = AtomicU64::new(STACKS_WINDOW);
static PT_ALIAS_AT: AtomicU64 = AtomicU64::new(PT_ALIAS_WINDOW);

// Relaxed everywhere below: the bases are written once on the boot CPU,
// before the kernel's page tables are built, and read after.
pub fn mmio_base() -> u64 {
    MMIO_AT.load(Ordering::Relaxed)
}
pub fn heap_base() -> u64 {
    HEAP_AT.load(Ordering::Relaxed)
}
pub fn heap_meta_base() -> u64 {
    HEAP_META_AT.load(Ordering::Relaxed)
}
pub fn stacks_base() -> u64 {
    STACKS_AT.load(Ordering::Relaxed)
}
pub fn pt_alias_base() -> u64 {
    PT_ALIAS_AT.load(Ordering::Relaxed)
}

/// Entropy of each region's placement, in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub mmio_bits: u32,
    pub heap_bits: u32,
    pub heap_meta_bits: u32,
    pub stacks_bits: u32,
    pub pt_alias_bits: u32,
}

/// Picks the base of every region: the MMIO window by whole GiB inside its
/// slot, the heap by multiples of its own size (the buddy heap needs that
/// alignment), the rest by 2 MiB. `rand` yields independent 64-bit values.
pub fn randomise(heap_bytes: u64, mut rand: impl FnMut() -> u64) -> Placement {
    let mut pick = |span: u64, align: u64| {
        let slots = (span / align).max(1);
        (rand() % slots * align, slots.ilog2())
    };
    let (m, mmio_bits) = pick(MMIO_SPAN, 1 << 30);
    let (h, heap_bits) = pick(WINDOW_SPAN, heap_bytes.max(1 << 21));
    let (hm, heap_meta_bits) = pick(WINDOW_SPAN, 1 << 21);
    let (st, stacks_bits) = pick(WINDOW_SPAN, 1 << 21);
    let (pa, pt_alias_bits) = pick(WINDOW_SPAN, 1 << 21);
    MMIO_AT.store(MMIO_WINDOW + m, Ordering::Relaxed);
    HEAP_AT.store(HEAP_WINDOW + h, Ordering::Relaxed);
    HEAP_META_AT.store(HEAP_META_WINDOW + hm, Ordering::Relaxed);
    STACKS_AT.store(STACKS_WINDOW + st, Ordering::Relaxed);
    PT_ALIAS_AT.store(PT_ALIAS_WINDOW + pa, Ordering::Relaxed);
    Placement {
        mmio_bits,
        heap_bits,
        heap_meta_bits,
        stacks_bits,
        pt_alias_bits,
    }
}

const PAGE: u64 = 4096;
/// Per-CPU stack slot:
/// `[guard][exception stack][guard][main stack][unmapped rest]`.
pub const STACK_STRIDE: u64 = 1 << 20;
/// AArch64 runs every exception on this stack; on x86 it holds the four
/// IST stacks of an application processor (`arch-x86_64::gdt`).
pub const EXC_STACK_SIZE: u64 = if cfg!(target_arch = "x86_64") {
    64 << 10
} else {
    32 << 10
};
pub const MAIN_STACK_SIZE: u64 = 128 << 10;

/// Address ranges of CPU `cpu`'s stacks: (exception, main) as `[lo, hi)`.
pub fn stacks(cpu: u64) -> ((u64, u64), (u64, u64)) {
    let base = stacks_base() + cpu * STACK_STRIDE;
    let exc_lo = base + PAGE;
    let exc_hi = exc_lo + EXC_STACK_SIZE;
    let main_lo = exc_hi + PAGE;
    let main_hi = main_lo + MAIN_STACK_SIZE;
    ((exc_lo, exc_hi), (main_lo, main_hi))
}

/// Explains a faulting address that falls into a known guard region.
pub fn describe(far: u64) -> Option<(&'static str, u64)> {
    if (stacks_base()..stacks_base() + 256 * STACK_STRIDE).contains(&far) {
        let cpu = (far - stacks_base()) / STACK_STRIDE;
        let ((exc_lo, _), (main_lo, main_hi)) = stacks(cpu);
        return Some(if far < exc_lo {
            ("exception stack guard page (overflow)", cpu)
        } else if far < main_lo && far >= main_lo - PAGE {
            ("main stack guard page (stack overflow)", cpu)
        } else if far >= main_hi {
            ("above main stack (unmapped)", cpu)
        } else {
            ("stack region", cpu)
        });
    }
    if far < 0x1_0000_0000_0000 {
        return Some((
            if cfg!(target_arch = "x86_64") {
                "lower half (no mappings, likely a null or user pointer)"
            } else {
                "lower half (TTBR0 disabled, likely a null or user pointer)"
            },
            0,
        ));
    }
    None
}
