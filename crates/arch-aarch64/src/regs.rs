//! System register access.
//!
//! Each accessor is a single `mrs`/`msr`. Reads have no side effects on the
//! registers used here, so they are exposed as safe functions. Writes change
//! machine state and stay `unsafe`.

#![allow(unsafe_code)]

macro_rules! read_sysreg {
    ($(#[$m:meta])* $fn:ident, $reg:literal) => {
        $(#[$m])*
        #[inline(always)]
        pub fn $fn() -> u64 {
            let v: u64;
            // SAFETY: reading this system register has no side effects and
            // does not touch memory.
            unsafe { core::arch::asm!(concat!("mrs {}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
    };
}

macro_rules! write_sysreg {
    ($(#[$m:meta])* $fn:ident, $reg:literal) => {
        $(#[$m])*
        ///
        /// # Safety
        /// Changes processor state; the caller must uphold the architectural
        /// requirements for the register and follow it with the right barrier.
        #[inline(always)]
        pub unsafe fn $fn(v: u64) {
            // SAFETY: forwarded to the caller.
            unsafe { core::arch::asm!(concat!("msr ", $reg, ", {}"), in(reg) v, options(nostack, preserves_flags)) };
        }
    };
}

read_sysreg!(current_el_raw, "CurrentEL");
read_sysreg!(mpidr_el1, "mpidr_el1");
read_sysreg!(midr_el1, "midr_el1");
read_sysreg!(esr_el1, "esr_el1");
read_sysreg!(far_el1, "far_el1");
read_sysreg!(elr_el1, "elr_el1");
read_sysreg!(spsr_el1, "spsr_el1");
read_sysreg!(sctlr_el1, "sctlr_el1");
read_sysreg!(tcr_el1, "tcr_el1");
read_sysreg!(ttbr0_el1, "ttbr0_el1");
read_sysreg!(ttbr1_el1, "ttbr1_el1");
read_sysreg!(mair_el1, "mair_el1");
read_sysreg!(vbar_el1, "vbar_el1");
read_sysreg!(cpacr_el1, "cpacr_el1");
read_sysreg!(cntfrq_el0, "cntfrq_el0");
read_sysreg!(cntpct_el0, "cntpct_el0");
read_sysreg!(cntvct_el0, "cntvct_el0");
read_sysreg!(id_aa64isar0_el1, "id_aa64isar0_el1");
read_sysreg!(id_aa64isar1_el1, "id_aa64isar1_el1");
read_sysreg!(id_aa64pfr0_el1, "id_aa64pfr0_el1");
read_sysreg!(id_aa64pfr1_el1, "id_aa64pfr1_el1");
read_sysreg!(id_aa64mmfr0_el1, "id_aa64mmfr0_el1");
read_sysreg!(tpidr_el1, "tpidr_el1");
read_sysreg!(cntkctl_el1, "cntkctl_el1");

write_sysreg!(set_vbar_el1, "vbar_el1");
write_sysreg!(set_mair_el1, "mair_el1");
write_sysreg!(set_tcr_el1, "tcr_el1");
write_sysreg!(set_ttbr0_el1, "ttbr0_el1");
write_sysreg!(set_ttbr1_el1, "ttbr1_el1");
write_sysreg!(set_sctlr_el1, "sctlr_el1");
write_sysreg!(set_cpacr_el1, "cpacr_el1");
write_sysreg!(set_tpidr_el1, "tpidr_el1");
write_sysreg!(set_cntkctl_el1, "cntkctl_el1");

/// Current exception level (1 or 2).
pub fn current_el() -> u8 {
    ((current_el_raw() >> 2) & 0b11) as u8
}

/// MPIDR affinity fields (Aff3..Aff0) with all other bits cleared, the form
/// used by Limine, PSCI and ACPI.
pub fn mpidr_affinity() -> u64 {
    mpidr_el1() & 0xff_00ff_ffff
}
