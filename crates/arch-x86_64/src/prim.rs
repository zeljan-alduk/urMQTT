//! Small wrappers over privileged x86 instructions: the one place the X4
//! files reach the hardware through (CPUID, MSRs, port I/O, MMIO, TSC).

#![allow(unsafe_code)]

use core::arch::asm;

/// CPUID leaf/subleaf as (eax, ebx, ecx, edx).
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    // SAFETY: CPUID exists on every x86_64 CPU and has no side effects.
    #[allow(unused_unsafe)]
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// The highest basic CPUID leaf.
pub fn max_leaf() -> u32 {
    cpuid(0, 0).0
}

/// The highest hypervisor CPUID leaf, 0 if not running under one.
pub fn hypervisor_max_leaf() -> u32 {
    if cpuid(1, 0).2 & (1 << 31) == 0 {
        return 0;
    }
    cpuid(0x4000_0000, 0).0
}

/// The hypervisor signature (ebx, ecx, edx of leaf 0x4000_0000) as 12 bytes.
pub fn hypervisor_signature() -> [u8; 12] {
    let mut s = [0u8; 12];
    if hypervisor_max_leaf() == 0 {
        return s;
    }
    let (_, b, c, d) = cpuid(0x4000_0000, 0);
    s[0..4].copy_from_slice(&b.to_le_bytes());
    s[4..8].copy_from_slice(&c.to_le_bytes());
    s[8..12].copy_from_slice(&d.to_le_bytes());
    s
}

pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the callers pass MSRs that exist on the CPU they run on
    // (architectural APIC/TSC-deadline MSRs, or ones a CPUID bit announced).
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
             options(nomem, nostack, preserves_flags))
    };
    (hi as u64) << 32 | lo as u64
}

pub fn wrmsr(msr: u32, val: u64) {
    // SAFETY: as for `rdmsr`; the callers write values built by the pure
    // encoders in this crate.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32,
             options(nostack, preserves_flags))
    };
}

pub fn outb(port: u16, val: u8) {
    // SAFETY: port writes to the legacy PIC/PIT/PM-timer ports; they do not
    // touch memory.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags))
    };
}

pub fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: a port read of a legacy device register.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags))
    };
    v
}

pub fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: a port read of the ACPI PM timer register.
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// A short delay for slow legacy chips (a write to the unused POST port).
pub fn io_wait() {
    outb(0x80, 0);
}

/// Volatile 32-bit MMIO read.
///
/// The caller passes the address of a mapped device register, 4-aligned.
pub fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: `addr` is a mapped, aligned device register (the APIC, I/O
    // APIC and HPET bases come from the platform tables and were mapped
    // uncached by the kernel before use).
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

pub fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: as for `mmio_read32`.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
}

pub fn mmio_read64(addr: usize) -> u64 {
    // SAFETY: as for `mmio_read32`; the HPET's 64-bit registers are aligned.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

pub fn mmio_write64(addr: usize, val: u64) {
    // SAFETY: as for `mmio_read32`.
    unsafe { core::ptr::write_volatile(addr as *mut u64, val) };
}

pub fn mfence() {
    // SAFETY: a fence has no preconditions.
    unsafe { asm!("mfence", options(nostack, preserves_flags)) };
}

/// The TSC, ordered after earlier instructions (`lfence; rdtsc`), so
/// timestamps taken in program order do not reorder.
pub fn rdtsc_ordered() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reads the TSC; CR4.TSD is never set by this kernel.
    unsafe {
        asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi,
             options(nomem, nostack, preserves_flags))
    };
    (hi as u64) << 32 | lo as u64
}

/// Saves RFLAGS and disables interrupts.
pub fn save_flags_cli() -> u64 {
    let f: u64;
    // SAFETY: pushes and pops one word on the stack, then `cli`.
    unsafe { asm!("pushfq", "pop {f}", "cli", f = out(reg) f, options(preserves_flags)) };
    f
}

/// Restores the interrupt flag saved by [`save_flags_cli`].
pub fn restore_flags(flags: u64) {
    if flags & (1 << 9) != 0 {
        // SAFETY: re-enables interrupts that were enabled when saved.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

/// RDRAND: `None` when the instruction reports no data (CF = 0).
pub fn rdrand64() -> Option<u64> {
    let (v, ok): (u64, u8);
    // SAFETY: the callers checked CPUID.1:ECX.RDRAND.
    unsafe {
        asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack))
    };
    (ok != 0).then_some(v)
}

/// RDSEED: `None` when the instruction reports no data (CF = 0).
pub fn rdseed64() -> Option<u64> {
    let (v, ok): (u64, u8);
    // SAFETY: the callers checked CPUID.7:EBX.RDSEED.
    unsafe {
        asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack))
    };
    (ok != 0).then_some(v)
}
