//! System power control (X2, ADR-044).
//!
//! Power-off and reset without ACPI tables, which is what QEMU, KVM and
//! most hypervisors need. ACPI S5 for real hardware (the `\_S5` object and
//! the FADT reset register) arrives with X6; until then bare metal halts on
//! power-off and relies on the reset ports.
//!
//! Reset: the PCI reset-control port 0xCF9 (q35, ICH and every Intel/AMD
//! chipset since), then the 8042 pulse, then a triple fault.
//!
//! Power-off: QEMU's ACPI PM1a control (0x604 on q35/pc, 0xB004 on old
//! QEMU and Bochs), only under a hypervisor, since on real hardware those
//! ports belong to nothing we know. In smoke mode, if QEMU is still
//! running afterwards, the `isa-debug-exit` device (dev runs attach it).

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};

use crate::port::{outb, outl, outw};

/// How firmware services are reached (aarch64: HVC/SMC for PSCI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduit {
    Acpi,
}

pub fn set_conduit(_c: Conduit) {}

pub fn conduit_name() -> &'static str {
    "acpi"
}

/// The firmware interface version (aarch64: the PSCI version).
pub fn firmware_version() -> Option<(u16, u16)> {
    None
}

/// QEMU's `-device isa-debug-exit,iobase=0xf4,iosize=0x04`.
const DEBUG_EXIT_PORT: u16 = 0xf4;

// Relaxed: set once on the boot CPU before anything can power off.
static DEBUG_EXIT: AtomicBool = AtomicBool::new(false);

/// Allows [`off`] to write the debug-exit port as a last resort. Dev
/// images in smoke mode only: a production image never writes it.
pub fn set_debug_exit(on: bool) {
    // Relaxed: see DEBUG_EXIT.
    DEBUG_EXIT.store(on, Ordering::Relaxed);
}

fn under_hypervisor() -> bool {
    crate::features::cpuid(1, 0).ecx & (1 << 31) != 0
}

/// Powers off; halts if nothing took effect.
pub fn off() -> ! {
    crate::serial::flush();
    if under_hypervisor() {
        for port in [0x604, 0xb004] {
            // SAFETY: QEMU's ACPI PM1a control ports; under a hypervisor
            // an unclaimed port ignores the write.
            unsafe { outw(port, 0x2000) };
        }
        // Relaxed: see DEBUG_EXIT.
        if DEBUG_EXIT.load(Ordering::Relaxed) {
            // SAFETY: the dev-only debug-exit device; unclaimed otherwise.
            unsafe { outl(DEBUG_EXIT_PORT, 0) };
        }
    }
    crate::cpu::halt()
}

/// Resets the machine; halts if nothing took effect.
pub fn reset() -> ! {
    crate::serial::flush();
    // SAFETY: the PCI reset-control register: 0x02 selects a hard reset,
    // 0x06 starts it (RST_CPU | SYS_RST).
    unsafe { outb(0xcf9, 0x02) };
    // SAFETY: as above.
    unsafe { outb(0xcf9, 0x06) };
    // SAFETY: the 8042 keyboard controller's "pulse the reset line" command.
    unsafe { outb(0x64, 0xfe) };
    triple_fault()
}

/// Loads an empty IDT and raises an exception: #BP cannot be delivered,
/// then #DF cannot either, which resets the CPU.
fn triple_fault() -> ! {
    let empty: [u64; 2] = [0, 0];
    // SAFETY: deliberately resets the CPU; nothing runs afterwards.
    unsafe {
        core::arch::asm!("lidt [{}]", "int3", in(reg) empty.as_ptr(), options(noreturn));
    }
}
