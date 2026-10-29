//! Per-CPU identity and application-processor bring-up.
//!
//! `TPIDR_EL1` holds the logical CPU index (0 = boot CPU). An AP enters
//! `urmqtt_ap_entry` in the bootloader's tables, with `x0` pointing at the
//! Limine MP info whose `extra_argument` is an [`ApBoot`]. The assembly stub
//! switches it to the kernel's tables, keys, vector table and stacks before
//! any compiled code runs, exactly mirroring the boot CPU's configuration,
//! and calls `ApBoot.entry(cpu)`.

#![allow(unsafe_code)]

use crate::regs;

/// Logical index of the executing CPU, as set by [`set_current`]
/// (0 before that).
#[inline]
pub fn current() -> usize {
    regs::tpidr_el1() as usize
}

/// Records the logical index of the executing CPU.
///
/// # Safety
/// `TPIDR_EL1` must be reserved for this purpose; nothing else may use it.
#[inline]
pub unsafe fn set_current(id: usize) {
    // SAFETY: forwarded to the caller.
    unsafe { regs::set_tpidr_el1(id as u64) };
}

/// The firmware's identifier of the executing CPU (MPIDR affinity), the
/// form Limine, PSCI, ACPI and the GIC use.
#[inline]
pub fn hw_id() -> u64 {
    regs::mpidr_affinity()
}

/// Everything an AP needs to join, read by `urmqtt_ap_entry`.
/// Field offsets are hard-coded in the assembly below.
#[repr(C)]
pub struct ApBoot {
    mair: u64,
    tcr: u64,
    ttbr1: u64,
    sctlr: u64,
    vbar: u64,
    key_lo: u64,
    key_hi: u64,
    exc_top: u64,
    main_top: u64,
    cpu: u64,
    entry: u64,
    /// Non-zero if the CPU has pointer authentication: only then may the
    /// key registers be written (they are UNDEFINED otherwise, e.g. on
    /// Neoverse N1 / Ampere Altra).
    pac: u64,
}

/// First compiled code an AP runs, on its main stack with exceptions on
/// its exception stack. Receives the logical CPU index.
pub type ApEntry = extern "C" fn(u64) -> !;

impl ApBoot {
    pub const fn empty() -> Self {
        Self {
            mair: 0,
            tcr: 0,
            ttbr1: 0,
            sctlr: 0,
            vbar: 0,
            key_lo: 0,
            key_hi: 0,
            exc_top: 0,
            main_top: 0,
            cpu: 0,
            entry: 0,
            pac: 0,
        }
    }

    /// Fills the block from the executing (boot) CPU's configuration:
    /// translation, system control and vector registers, plus the PAC key
    /// if the CPU has PAC. `exc_top` and `main_top` are the AP's stacks.
    pub fn capture(
        &mut self,
        cpu: usize,
        exc_top: u64,
        main_top: u64,
        entry: ApEntry,
        pac_key: Option<(u64, u64)>,
    ) {
        let (key_lo, key_hi) = pac_key.unwrap_or((0, 0));
        *self = Self {
            mair: regs::mair_el1(),
            tcr: regs::tcr_el1(),
            ttbr1: regs::ttbr1_el1(),
            sctlr: regs::sctlr_el1(),
            vbar: regs::vbar_el1(),
            key_lo,
            key_hi,
            exc_top,
            main_top,
            cpu: cpu as u64,
            entry: entry as *const () as u64,
            pac: u64::from(pac_key.is_some()),
        };
    }
}

const _: () = {
    assert!(core::mem::offset_of!(ApBoot, sctlr) == 24);
    assert!(core::mem::offset_of!(ApBoot, key_lo) == 40);
    assert!(core::mem::offset_of!(ApBoot, exc_top) == 56);
    assert!(core::mem::offset_of!(ApBoot, entry) == 80);
    assert!(core::mem::offset_of!(ApBoot, pac) == 88);
};

// The kernel declares `urmqtt_ap_entry` with the bootloader's MP info type
// and passes it to Limine as the AP's goto address.
core::arch::global_asm!(
    ".text",
    ".global urmqtt_ap_entry",
    "urmqtt_ap_entry:",
    "hint #34", // bti c
    "mrs x9, cpacr_el1",
    "orr x9, x9, #(3 << 20)", // FP/SIMD on before any compiled code
    "msr cpacr_el1, x9",
    "isb",
    "ldr x1, [x0, #32]", // MpInfo.extra_argument -> &ApBoot
    "ldr x2, [x1, #0]",
    "msr mair_el1, x2",
    "ldr x2, [x1, #8]",
    "msr tcr_el1, x2",
    "isb",
    "ldr x2, [x1, #16]",
    "msr ttbr1_el1, x2", // same VAs for kernel text: execution continues
    "isb",
    "tlbi vmalle1",
    "dsb nsh",
    "isb",
    "ldr x2, [x1, #88]",
    "cbz x2, 2f", // no FEAT_PAuth: the key registers do not exist
    "ldr x2, [x1, #40]",
    "msr S3_0_C2_C1_0, x2", // APIAKeyLo_EL1
    "ldr x2, [x1, #48]",
    "msr S3_0_C2_C1_1, x2", // APIAKeyHi_EL1
    "2:",
    "ldr x2, [x1, #32]",
    "msr vbar_el1, x2",
    "ldr x2, [x1, #24]",
    "msr sctlr_el1, x2", // WXN, EnIA as on the boot CPU
    "isb",
    "msr spsel, #1",
    "ldr x2, [x1, #56]",
    "mov sp, x2", // SP_EL1: exception stack
    "ldr x2, [x1, #64]",
    "msr sp_el0, x2", // SP_EL0: main stack
    "msr spsel, #0",
    "ldr x0, [x1, #72]",
    "ldr x3, [x1, #80]",
    "mov x29, xzr",
    "mov x30, xzr",
    "blr x3",
    "1: wfi",
    "b 1b",
);
