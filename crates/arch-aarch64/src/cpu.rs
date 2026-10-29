//! CPU control: barriers, wait instructions, interrupt masking, halting.

#![allow(unsafe_code)]

use core::arch::asm;

#[inline(always)]
pub fn isb() {
    // SAFETY: a barrier has no effect besides ordering.
    unsafe { asm!("isb", options(nostack, preserves_flags)) };
}

#[inline(always)]
pub fn dsb_ish() {
    // SAFETY: a barrier has no effect besides ordering.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
}

#[inline(always)]
pub fn dsb_ishst() {
    // SAFETY: a barrier has no effect besides ordering.
    unsafe { asm!("dsb ishst", options(nostack, preserves_flags)) };
}

#[inline(always)]
pub fn dsb_sy() {
    // SAFETY: a barrier has no effect besides ordering.
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
}

#[inline(always)]
pub fn wfi() {
    // SAFETY: waits for an interrupt; no memory or register effects.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn wfe() {
    // SAFETY: waits for an event; no memory or register effects.
    unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) };
}

#[inline(always)]
pub fn sev() {
    // SAFETY: signals an event to all cores; no memory effects.
    unsafe { asm!("sev", options(nomem, nostack, preserves_flags)) };
}

/// Masks IRQ, FIQ, SError and debug exceptions on this core.
#[inline(always)]
pub fn mask_all_interrupts() {
    // SAFETY: only changes PSTATE.DAIF.
    unsafe {
        asm!(
            "msr daifset, #0xf",
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// Unmasks IRQs (and SError) on this core.
///
/// # Safety
/// A vector table able to handle IRQs must be installed.
#[inline(always)]
pub unsafe fn unmask_irq() {
    // SAFETY: forwarded to the caller.
    unsafe {
        asm!(
            "msr daifclr, #0x6",
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// Masks IRQs and returns the previous DAIF value for [`irq_restore`].
#[inline(always)]
pub fn irq_save() -> u64 {
    let daif: u64;
    // SAFETY: reads and sets PSTATE.DAIF only.
    unsafe {
        asm!("mrs {}, daif", "msr daifset, #0x2", out(reg) daif, options(nomem, nostack, preserves_flags))
    };
    daif
}

/// Restores the DAIF value returned by [`irq_save`].
#[inline(always)]
pub fn irq_restore(daif: u64) {
    // SAFETY: restores a previously valid PSTATE.DAIF.
    unsafe { asm!("msr daif, {}", in(reg) daif, options(nomem, nostack, preserves_flags)) };
}

/// Sleeps with interrupts enabled until one arrives, forever.
///
/// # Safety
/// The vector table and interrupt controller must be ready for IRQs.
pub unsafe fn idle() -> ! {
    // SAFETY: forwarded to the caller.
    unsafe { unmask_irq() };
    loop {
        wfi();
    }
}

/// Stops this core forever with interrupts masked.
pub fn halt() -> ! {
    mask_all_interrupts();
    loop {
        wfi();
    }
}

/// Invalidates the TLB entry for `va` on all cores in the inner-shareable
/// domain and waits for completion.
pub fn tlb_flush_va(va: u64) {
    dsb_ishst();
    // SAFETY: TLB maintenance has no memory side effects beyond the TLB.
    unsafe { asm!("tlbi vaae1is, {}", in(reg) va >> 12, options(nostack, preserves_flags)) };
    dsb_ish();
    isb();
}

/// Invalidates all stage-1 EL1 TLB entries on all inner-shareable cores.
pub fn tlb_flush_all() {
    dsb_ishst();
    // SAFETY: TLB maintenance has no memory side effects beyond the TLB.
    unsafe { asm!("tlbi vmalle1is", options(nostack, preserves_flags)) };
    dsb_ish();
    isb();
}
