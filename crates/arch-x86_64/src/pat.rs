//! The page-attribute table (PAT): which cache type each PTE index means.
//!
//! A leaf entry selects one of eight PAT entries with `PAT:PCD:PWT`. The
//! kernel only ever uses indices 0..=3 (the PAT bit of a leaf stays clear),
//! so 4 KiB and 2 MiB entries encode the type in the same bits and a decoded
//! entry needs no level to be read back.
//!
//! | index | type | kernel use |
//! |---|---|---|
//! | 0 | WB  | RAM |
//! | 1 | WC  | framebuffer (the reset default is WT, which nothing uses) |
//! | 2 | UC- | device memory (an MTRR can still make it UC) |
//! | 3 | UC  | strongly ordered device memory |
//!
//! Entries 4..=7 are left as the bootloader set them: the kernel never
//! selects them.

#![allow(unsafe_code)]

/// Encodings of the `IA32_PAT` memory types.
pub const UC: u8 = 0x00;
pub const WC: u8 = 0x01;
pub const WT: u8 = 0x04;
pub const WP: u8 = 0x05;
pub const WB: u8 = 0x06;
pub const UC_MINUS: u8 = 0x07;

/// The kernel's types for PAT entries 0..=3, in index order.
pub const KERNEL_ENTRIES: [u8; 4] = [WB, WC, UC_MINUS, UC];

/// Returns `pat` with entries 0..=3 set to the kernel's types and entries
/// 4..=7 untouched.
pub const fn merge(pat: u64) -> u64 {
    let mut low = 0u64;
    let mut i = 0;
    while i < 4 {
        low |= (KERNEL_ENTRIES[i] as u64) << (8 * i);
        i += 1;
    }
    (pat & !0xffff_ffff) | low
}

/// `IA32_PAT`.
#[cfg(target_os = "none")]
const MSR_PAT: u32 = 0x277;

/// Reads a model-specific register.
///
/// # Safety
/// `msr` must exist on this CPU (a missing one raises #GP).
#[cfg(target_os = "none")]
pub(crate) unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller guarantees the MSR exists; reading has no effect on
    // memory.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

/// Writes a model-specific register.
///
/// # Safety
/// `msr` must exist and `value` must be valid for it; the write may change
/// how memory behaves.
#[cfg(target_os = "none")]
pub(crate) unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: the caller guarantees the MSR and value are valid.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// Programs the PAT of the executing CPU (every CPU needs this once).
/// Requires CPUID.1:EDX.PAT, which every x86-64 CPU has.
#[cfg(target_os = "none")]
pub fn program() {
    // SAFETY: IA32_PAT exists on every x86-64 CPU.
    let old = unsafe { rdmsr(MSR_PAT) };
    // SAFETY: only entry 1 changes meaning (WT to WC) and no mapping uses
    // it before the kernel's tables do.
    unsafe { wrmsr(MSR_PAT, merge(old)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_sets_low_entries_and_keeps_high_ones() {
        let reset = 0x0007_0406_0007_0406u64;
        let m = merge(reset);
        assert_eq!(m & 0xff, u64::from(WB));
        assert_eq!((m >> 8) & 0xff, u64::from(WC));
        assert_eq!((m >> 16) & 0xff, u64::from(UC_MINUS));
        assert_eq!((m >> 24) & 0xff, u64::from(UC));
        assert_eq!(m >> 32, reset >> 32);
        assert_eq!(merge(m), m, "idempotent");
        // A bootloader that put something else in the high entries keeps it.
        assert_eq!(merge(0x0105_0000_dead_beef) >> 32, 0x0105_0000);
    }

    #[test]
    fn merge_differs_from_the_reset_value_only_in_entry_1() {
        // Reset: WB WT UC- UC WB WT UC- UC.
        let reset = 0x0007_0406_0007_0406u64;
        assert_eq!(merge(reset) ^ reset, u64::from(WC ^ WT) << 8);
    }
}
