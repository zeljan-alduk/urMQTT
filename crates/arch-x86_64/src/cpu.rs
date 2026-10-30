//! The executing CPU (X2): interrupt masking, waiting, halting, the
//! extended register state.

#![allow(unsafe_code)]

use core::arch::asm;

/// RFLAGS.IF.
const IF: u64 = 1 << 9;

/// Stops this CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: masks interrupts and halts; nothing is accessed.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Waits for an interrupt: `sti; hlt` (the instruction after `sti` runs
/// before any interrupt is taken, so a wake-up cannot be missed), then
/// masks again. With interrupts masked on entry this still returns on the
/// first one that fires, like `wfi`.
pub fn wait_for_interrupt() {
    // SAFETY: only changes IF and halts until an interrupt arrives.
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

/// Enables interrupts (`sti`).
///
/// # Safety
/// The IDT and the interrupt controller must be ready.
pub unsafe fn enable_interrupts() {
    // SAFETY: forwarded to the caller.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Disables interrupts and returns the previous RFLAGS.
pub fn irq_save() -> u64 {
    let flags: u64;
    // SAFETY: reads RFLAGS through the stack and clears IF.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    flags
}

/// Restores the interrupt state [`irq_save`] returned.
pub fn irq_restore(flags: u64) {
    if flags & IF != 0 {
        // SAFETY: the state being restored had interrupts enabled, so the
        // handlers they need were ready then.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

/// The current privilege level (CS.RPL).
pub fn privilege_level() -> u8 {
    let cs: u16;
    // SAFETY: reads a segment register.
    unsafe { asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    (cs & 3) as u8
}

/// Programs the return-address signing key (aarch64 PAC). x86 has none.
///
/// # Safety
/// Never called on x86.
pub unsafe fn set_return_address_key(_lo: u64, _hi: u64) {}

/// Where [`switch_to`] continues (a never-returning entry).
pub type Continuation = extern "C" fn(u64) -> !;

/// Switches to a fresh stack and calls `entry(arg)`.
///
/// # Safety
/// `stack_top` must be a valid, mapped, 16-byte-aligned stack top.
pub unsafe fn switch_to(
    stack_top: u64,
    arg: u64,
    _unused: u64,
    entry: Continuation,
    _pac: bool,
) -> ! {
    // SAFETY: the caller provides the stack; the old frame is abandoned
    // and `entry` never returns.
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {entry}",
            "ud2",
            top = in(reg) stack_top,
            entry = in(reg) entry,
            in("rdi") arg,
            options(noreturn),
        )
    }
}

fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: reads a control register.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn write_cr4(v: u64) {
    // SAFETY: only called to set CR4 bits the CPU reports as supported.
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nomem, nostack, preserves_flags)) };
}

/// Turns on XSAVE (CR4.OSXSAVE) and sets XCR0 to x87 | SSE, plus AVX if the
/// CPU has it (ADR-042: AVX-512 only when a dispatched kernel needs it).
/// Returns XCR0, or 0 on a CPU without XSAVE. Call once per CPU, before
/// [`crate::features::read`], which reports the result.
pub fn enable_extended_state() -> u64 {
    let l1 = crate::features::cpuid(1, 0);
    const XSAVE: u32 = 1 << 26;
    const AVX: u32 = 1 << 28;
    if l1.ecx & XSAVE == 0 {
        return 0;
    }
    write_cr4(read_cr4() | (1 << 18));
    let mut xcr0: u64 = 0b11;
    if l1.ecx & AVX != 0 {
        xcr0 |= 0b100;
    }
    // SAFETY: OSXSAVE is set; bits 0 and 1 are always valid, bit 2 only
    // when CPUID reports AVX.
    unsafe {
        asm!("xsetbv", in("ecx") 0, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack, preserves_flags));
    }
    xcr0
}
