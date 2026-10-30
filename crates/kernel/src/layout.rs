//! Kernel virtual address layout (TTBR1 / the upper half of CR3's tree,
//! 48-bit canonical addresses; every base below is canonical on both).
//!
//! ```text
//! 0xffff_0000_0000_0000  HHDM (offset chosen by Limine, kept as is)
//! 0xffff_c000_0000_0000  MMIO window        (1 GiB, device memory)
//! 0xffff_d000_0000_0000  kernel heap        (buddy region, guard-free above/below: unmapped)
//! 0xffff_d800_0000_0000  heap bookkeeping   (buddy bitmaps)
//! 0xffff_e000_0000_0000  per-CPU stacks     (1 MiB stride, guard pages, see below)
//! 0xffff_f000_0000_0000  page-table alias   (RW view of the table pool, removed at lock)
//! 0xffff_ffff_8000_0000  kernel image       (RX text, R rodata, RW data/bss; linker.ld)
//! ```
//! The lower half (TTBR0) is disabled with `TCR_EL1.EPD0`; on x86_64 the
//! root simply has no lower-half entries. Limine's x86_64 HHDM starts at
//! `0xffff_8000_0000_0000` (the first canonical upper-half address).

pub const MMIO_BASE: u64 = 0xffff_c000_0000_0000;
pub const MMIO_SIZE: u64 = 1 << 30;
pub const HEAP_BASE: u64 = 0xffff_d000_0000_0000;
pub const HEAP_META_BASE: u64 = 0xffff_d800_0000_0000;
pub const STACKS_BASE: u64 = 0xffff_e000_0000_0000;
pub const PT_ALIAS_BASE: u64 = 0xffff_f000_0000_0000;

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
pub const fn stacks(cpu: u64) -> ((u64, u64), (u64, u64)) {
    let base = STACKS_BASE + cpu * STACK_STRIDE;
    let exc_lo = base + PAGE;
    let exc_hi = exc_lo + EXC_STACK_SIZE;
    let main_lo = exc_hi + PAGE;
    let main_hi = main_lo + MAIN_STACK_SIZE;
    ((exc_lo, exc_hi), (main_lo, main_hi))
}

/// Explains a faulting address that falls into a known guard region.
pub fn describe(far: u64) -> Option<(&'static str, u64)> {
    if (STACKS_BASE..STACKS_BASE + 256 * STACK_STRIDE).contains(&far) {
        let cpu = (far - STACKS_BASE) / STACK_STRIDE;
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
