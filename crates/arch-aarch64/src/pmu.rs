//! The PMU cycle counter as a fine-grained clock (CPU-jitter entropy,
//! ADR-038). Hypervisors may hide the PMU; the generic timer is then the
//! finest clock.

#![allow(unsafe_code)]

use crate::timer;

/// ID_AA64DFR0_EL1.PMUVer: a PMU is implemented (not absent, not IMPDEF).
fn has_pmu() -> bool {
    let dfr0: u64;
    // SAFETY: reading an ID register has no side effects.
    unsafe { core::arch::asm!("mrs {}, S3_0_C0_C5_0", out(reg) dfr0, options(nomem, nostack)) };
    matches!((dfr0 >> 8) & 0xf, 1..=0xe)
}

fn cycles() -> u64 {
    let v: u64;
    // SAFETY: PMCCNTR_EL0 exists (checked by `has_pmu`) and was enabled by
    // `enable_cycle_counter`; reading it has no side effects.
    unsafe { core::arch::asm!("mrs {}, S3_3_C9_C13_0", out(reg) v, options(nomem, nostack)) };
    v
}

fn enable_cycle_counter() {
    // SAFETY: the PMU exists (`has_pmu`). PMCCFILTR_EL0 = 0 counts at
    // every EL; PMCNTENSET_EL0 bit 31 enables the cycle counter; PMCR_EL0
    // E (bit 0) and LC (bit 6) start it as a 64-bit counter. Only this
    // module uses the PMU.
    unsafe {
        core::arch::asm!(
            "msr S3_3_C14_C15_7, xzr",
            "msr S3_3_C9_C12_1, {en}",
            "mrs {t}, S3_3_C9_C12_0",
            "orr {t}, {t}, {bits}",
            "msr S3_3_C9_C12_0, {t}",
            "isb",
            en = in(reg) 1u64 << 31,
            bits = in(reg) 0x41u64,
            t = out(reg) _,
            options(nostack)
        )
    };
}

/// The finest clock and its name: the cycle counter if it exists and
/// runs, else the generic timer's counter.
pub fn finest_clock() -> (fn() -> u64, &'static str) {
    if has_pmu() {
        enable_cycle_counter();
        let a = cycles();
        let mut x = 0u64;
        for i in 0..1000u64 {
            x = core::hint::black_box(x.wrapping_add(i));
        }
        if cycles() != a {
            return (cycles, "PMU cycle counter");
        }
    }
    (timer::now, "generic timer")
}
