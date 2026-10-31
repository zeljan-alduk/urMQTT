//! Memory tagging (FEAT_MTE2), H4 (ADR-174).
//!
//! Every 16-byte granule of tagged memory has a 4-bit allocation tag, and a
//! pointer carries a 4-bit logical tag in bits 59:56. A load or store
//! through a pointer whose tag differs from the granule's is a synchronous
//! "tag check fault" at the instruction that made it.
//!
//! How the kernel uses it:
//! - Kernel pointers are untagged when their tag bits are `0b1111` (they
//!   are canonical upper-half addresses). `TCR_EL1.TCMA1` makes that value
//!   match every allocation tag, so the allocator's own accesses (headers,
//!   poison, canaries), which use plain addresses, are never checked.
//! - A live allocation is given a random tag from 1 to 14 (`GCR_EL1`
//!   excludes 0 and 15) over its bytes rounded up to 16, and the pointer it
//!   is returned as carries that tag. Freed memory goes back to tag 0, which
//!   no pointer handed out can carry, so a stale pointer and an overflow
//!   into free memory fault every time; into a neighbouring allocation they
//!   fault unless the two random tags are equal (1 in 14).
//! - `TCR_EL1.TBI1` makes the translation ignore the tag byte.

#![allow(unsafe_code)]

use crate::regs;

/// Bits 59:56 of a pointer.
pub const TAG_MASK: u64 = 0xf << 56;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TCMA1: u64 = 1 << 58;
const SCTLR_ATA: u64 = 1 << 43;
const SCTLR_TCF_SHIFT: u32 = 40;
/// Tags 0 and 15 are never drawn: 0 is "free", 15 is "untagged".
const GCR_EXCLUDE: u64 = 0x8001;

/// What happens on a tag mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A synchronous exception at the faulting instruction.
    Sync = 1,
    /// Recorded in `TFSR_EL1`, reported later (not reported by this kernel).
    Async = 2,
}

/// Turns tag checking on for the executing CPU: `TBI1` and `TCMA1` in
/// `TCR_EL1`, `ATA` and `TCF` in `SCTLR_EL1`. The other cores take these
/// registers from the boot CPU when they start.
///
/// # Safety
/// FEAT_MTE2 must be implemented, and the memory that will be tagged must be
/// mapped Normal Tagged (see `MemType::NormalTagged`).
pub unsafe fn enable_checking(mode: Mode) {
    // SAFETY: the caller guarantees the feature; TBI1 only makes the top
    // byte of upper-half addresses ignored by translation, and TCMA1 makes
    // the kernel's untagged pointers (tag 0b1111) unchecked.
    unsafe { regs::set_tcr_el1(regs::tcr_el1() | TCR_TBI1 | TCR_TCMA1) };
    // SAFETY: as above; ATA allows the tag instructions, TCF selects the
    // reaction to a mismatch.
    unsafe {
        regs::set_sctlr_el1(regs::sctlr_el1() | SCTLR_ATA | ((mode as u64) << SCTLR_TCF_SHIFT));
    }
    crate::cpu::isb();
}

/// Per-CPU state of the tag generator: `GCR_EL1` (which tags `irg` may
/// draw) and the seed of `irg`'s generator (`RGSR_EL1`, never zero).
///
/// # Safety
/// FEAT_MTE2 must be implemented.
pub unsafe fn init_cpu(seed: u16) {
    let rgsr = (u64::from(seed.max(1))) << 8;
    // SAFETY: GCR_EL1 (S3_0_C1_C0_6) only selects the tags `irg` draws.
    unsafe {
        core::arch::asm!("msr S3_0_C1_C0_6, {}", in(reg) GCR_EXCLUDE, options(nostack, preserves_flags));
    }
    // SAFETY: RGSR_EL1 (S3_0_C1_C0_5) is the generator's seed.
    unsafe {
        core::arch::asm!("msr S3_0_C1_C0_5, {}", in(reg) rgsr, options(nostack, preserves_flags));
    }
    crate::cpu::isb();
}

/// Gives the `len` bytes at `p` (a multiple of 16, `p` 16-aligned) a fresh
/// random allocation tag and returns `p` carrying it.
///
/// # Safety
/// FEAT_MTE2 with `init_cpu` done on this CPU, and `[p, p + len)` inside
/// tagged memory that nobody uses.
pub unsafe fn retag(p: *mut u8, len: usize) -> *mut u8 {
    if len == 0 {
        return p;
    }
    let tagged: *mut u8;
    // SAFETY: `irg` only computes a pointer; the `stg` loop writes the
    // allocation tags of the granules of the caller's region.
    unsafe {
        core::arch::asm!(
            ".arch_extension memtag",
            "irg {t}, {p}",
            "mov {c}, {t}",
            "2:",
            "stg {c}, [{c}], #16",
            "subs {n}, {n}, #16",
            "b.hi 2b",
            t = out(reg) tagged,
            c = out(reg) _,
            p = in(reg) p,
            n = inout(reg) len => _,
            options(nostack)
        );
    }
    tagged
}

/// Sets the allocation tags of the `len` bytes at `p` back to 0 (free).
///
/// # Safety
/// As [`retag`]; `p` may carry any tag.
pub unsafe fn clear(p: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    // Tag bits 59:56 of the pointer are what `stg` stores: zero them.
    let zero_tagged = ((p as u64) & !TAG_MASK) as *mut u8;
    // SAFETY: the `stg` loop writes the allocation tags of the caller's
    // region.
    unsafe {
        core::arch::asm!(
            ".arch_extension memtag",
            "2:",
            "stg {p}, [{p}], #16",
            "subs {n}, {n}, #16",
            "b.hi 2b",
            p = inout(reg) zero_tagged => _,
            n = inout(reg) len => _,
            options(nostack)
        );
    }
}
