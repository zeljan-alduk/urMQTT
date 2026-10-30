//! Port I/O and the CPU identity PCI bring-up needs (X7): configuration
//! mechanism #1 talks to 0xCF8/0xCFC, and an MSI names its target CPU by
//! APIC ID.

#![allow(unsafe_code)]

/// Writes a 32-bit value to I/O port `port`.
///
/// Only meaningful for ports the caller owns (the PCI configuration ports);
/// the kernel runs in ring 0, so the instruction itself cannot fault.
pub fn outl(port: u16, value: u32) {
    // SAFETY: `out` touches no memory and no flags; a write to an unowned
    // port would only reach the device behind it, and the callers pass the
    // PCI configuration ports.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value,
            options(nomem, nostack, preserves_flags));
    }
}

/// Reads a 32-bit value from I/O port `port`.
pub fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: as in `outl`; `in` has no effect beyond the device's own.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

/// The executing CPU's initial (xAPIC) ID, CPUID.1:EBX[31:24]: the 8-bit
/// destination an MSI address can carry without interrupt remapping.
pub fn initial_apic_id() -> u8 {
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8
}
