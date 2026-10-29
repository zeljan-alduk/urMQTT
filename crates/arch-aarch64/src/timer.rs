//! ARM generic timer: monotonic counter and the EL1 virtual timer (CNTV).

#![allow(unsafe_code)]

use core::arch::asm;

/// Counter frequency in Hz (CNTFRQ_EL0).
#[inline]
pub fn frequency() -> u64 {
    crate::regs::cntfrq_el0().max(1)
}

/// Current virtual count. The `isb` keeps the read from being speculated
/// ahead of earlier instructions, so timestamps are ordered.
#[inline]
pub fn now() -> u64 {
    let v: u64;
    // SAFETY: reads the virtual counter; no side effects.
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

pub fn ticks_to_ns(ticks: u64) -> u64 {
    ((u128::from(ticks) * 1_000_000_000) / u128::from(frequency())) as u64
}

pub fn ns_to_ticks(ns: u64) -> u64 {
    ((u128::from(ns) * u128::from(frequency())) / 1_000_000_000) as u64
}

/// Nanoseconds since the counter started.
pub fn uptime_ns() -> u64 {
    ticks_to_ns(now())
}

/// Arms the virtual timer to fire when the count reaches `deadline`.
pub fn set_deadline(deadline: u64) {
    // SAFETY: programs this core's virtual timer; its PPI is handled by the
    // kernel's IRQ path.
    unsafe {
        asm!(
            "msr cntv_cval_el0, {d}",
            "mov {t}, #1", // ENABLE, IMASK = 0
            "msr cntv_ctl_el0, {t}",
            "isb",
            d = in(reg) deadline, t = out(reg) _,
            options(nomem, nostack)
        )
    };
}

/// The currently programmed deadline.
pub fn deadline() -> u64 {
    let v: u64;
    // SAFETY: reads this core's timer compare value.
    unsafe { asm!("mrs {}, cntv_cval_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Stops the virtual timer (and deasserts its interrupt).
pub fn disable() {
    // SAFETY: disables this core's virtual timer.
    unsafe { asm!("msr cntv_ctl_el0, xzr", "isb", options(nomem, nostack)) };
}
