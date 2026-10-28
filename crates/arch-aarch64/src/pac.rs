//! Pointer authentication keys and the stack switch that turns PAC on.
//!
//! PAC cannot be enabled from a function compiled with `pac-ret`: its
//! prologue ran with PAC off (LR unsigned) and its epilogue would then fail
//! to authenticate. [`switch_to`] therefore enables `SCTLR_EL1.EnIA` in
//! assembly and jumps to a fresh, never-returning entry on a new stack.

#![allow(unsafe_code)]

use crate::features::IdRegs;

/// Reads the ID registers used by [`crate::features::Features::decode`].
pub fn id_regs() -> IdRegs {
    let isar2: u64;
    // SAFETY: reading ID_AA64ISAR2_EL1 (S3_0_C0_C6_2) has no side effects;
    // it reads as zero on CPUs that predate it.
    unsafe { core::arch::asm!("mrs {}, S3_0_C0_C6_2", out(reg) isar2, options(nomem, nostack)) };
    IdRegs {
        isar0: crate::regs::id_aa64isar0_el1(),
        isar1: crate::regs::id_aa64isar1_el1(),
        isar2,
        pfr0: crate::regs::id_aa64pfr0_el1(),
        pfr1: crate::regs::id_aa64pfr1_el1(),
    }
}

/// Programs the instruction A key (APIAKey, used by `paciasp`/`autiasp`).
///
/// # Safety
/// Must only be called before PAC is enabled; changing the key while signed
/// return addresses are live makes every return fault.
pub unsafe fn set_ia_key(lo: u64, hi: u64) {
    // SAFETY: forwarded to the caller. APIAKeyLo/Hi_EL1 = S3_0_C2_C1_{0,1}.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C2_C1_0, {lo}",
            "msr S3_0_C2_C1_1, {hi}",
            "isb",
            lo = in(reg) lo, hi = in(reg) hi, options(nostack)
        )
    };
}

/// Entry point run on the new stack. Must never return.
pub type Continuation = extern "C" fn(u64) -> !;

unsafe extern "C" {
    fn urmqtt_switch_to(
        main_top: u64,
        exc_top: u64,
        arg: u64,
        f: Continuation,
        enable_pac: u64,
    ) -> !;
}

/// Switches to `main_top` (SP_EL0, normal execution) and `exc_top` (SP_EL1,
/// exception handling), optionally enables PAC, and calls `f(arg)`.
///
/// # Safety
/// Both stacks must be mapped, writable and 16-byte aligned at the top; the
/// caller's stack frames are abandoned. If `enable_pac`, the IA key must be set.
pub unsafe fn switch_to(
    main_top: u64,
    exc_top: u64,
    arg: u64,
    f: Continuation,
    enable_pac: bool,
) -> ! {
    // SAFETY: forwarded to the caller.
    unsafe { urmqtt_switch_to(main_top, exc_top, arg, f, u64::from(enable_pac)) }
}

core::arch::global_asm!(
    ".text",
    ".global urmqtt_switch_to",
    "urmqtt_switch_to:",
    "msr spsel, #1",
    "mov sp, x1",     // SP_EL1: exception stack
    "msr sp_el0, x0", // SP_EL0: main stack
    "cbz x4, 1f",
    "mrs x9, sctlr_el1",
    "orr x9, x9, #(1 << 31)", // EnIA
    "msr sctlr_el1, x9",
    "isb",
    "1:",
    "msr spsel, #0", // run on SP_EL0; exceptions switch to SP_EL1
    "mov x0, x2",
    "mov x29, xzr",
    "mov x30, xzr",
    "blr x3",
    "2: wfi",
    "b 2b",
);
