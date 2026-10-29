//! Turning the kernel's translation tables on (the register side of
//! [`crate::paging`], which only builds tables).

#![allow(unsafe_code)]

use crate::paging::MemType;
use crate::{cpu, regs};

const TCR_EPD0: u64 = 1 << 7;
const SCTLR_WXN: u64 = 1 << 19;
const TTBR_BADDR: u64 = 0x0000_ffff_ffff_fffe;

/// Adds the kernel's memory attributes to `MAIR_EL1`, keeping the
/// bootloader's indices, so device mappings can be made in the
/// bootloader's tables.
pub fn merge_memory_attributes() {
    // SAFETY: MAIR indices 0 and 1 (used by the bootloader's mappings) are
    // preserved; the kernel's indices were unused until now.
    unsafe { regs::set_mair_el1(MemType::merge_into_mair(regs::mair_el1())) };
    cpu::isb();
}

/// Physical address of the active upper-half (kernel) root table.
pub fn kernel_root() -> u64 {
    regs::ttbr1_el1() & TTBR_BADDR
}

/// Switches the upper half to the tables at `root`, disables the lower
/// half and turns on WXN, then flushes the TLB.
///
/// # Safety
/// The tables at `root` must map the kernel image, the current stack and
/// every live mapping at the same addresses as the active tables, and no
/// mapping may be both writable and executable.
pub unsafe fn activate(root: u64) {
    cpu::dsb_ishst();
    // SAFETY: the caller guarantees the new tables map everything in use.
    unsafe { regs::set_ttbr1_el1(root) };
    // SAFETY: nothing uses the lower half (TTBR0) once the bootloader's
    // identity assumptions are gone; walks there now fault.
    unsafe { regs::set_tcr_el1(regs::tcr_el1() | TCR_EPD0) };
    // SAFETY: the caller guarantees no W+X mapping, so enforcing WXN
    // changes nothing for valid code.
    unsafe { regs::set_sctlr_el1(regs::sctlr_el1() | SCTLR_WXN) };
    cpu::isb();
    cpu::tlb_flush_all();
}
