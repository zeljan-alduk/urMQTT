//! System power control (X2, ADR-044).
//!
//! Power-off and reset without ACPI tables, which is what QEMU, KVM and
//! most hypervisors need. ACPI S5 for real hardware (the `\_S5` object and
//! the FADT reset register) arrives with X6; until then bare metal halts on
//! power-off and relies on the reset ports.
//!
//! Reset: the FADT's reset register when it is a port (X6 data, see
//! [`set_acpi`]), then the PCI reset-control port 0xCF9 (q35, ICH and every
//! Intel/AMD chipset since), then the 8042 pulse, then a triple fault.
//!
//! Power-off: ACPI S5 from the FADT's PM1 control blocks and the DSDT's
//! `\_S5` sleep type when the platform description has them; then QEMU's
//! ACPI PM1a control (0x604 on q35/pc, 0xB004 on old QEMU and Bochs), only
//! under a hypervisor, since on real hardware those ports belong to
//! nothing we know. In smoke mode, if QEMU is still running afterwards, the
//! `isa-debug-exit` device (dev runs attach it).
//!
//! The ACPI path has run under QEMU only (where it writes the register the
//! fallback writes); real hardware is untested.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::port::{outb, outl, outw};

/// How firmware services are reached (aarch64: HVC/SMC for PSCI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduit {
    Acpi,
}

pub fn set_conduit(_c: Conduit) {}

/// Power-control facts from the FADT and DSDT (the platform description).
#[derive(Debug, Clone, Copy, Default)]
pub struct Acpi {
    /// PM1a and PM1b control block ports.
    pub pm1a_cnt: Option<u16>,
    pub pm1b_cnt: Option<u16>,
    /// `SLP_TYPa` and `SLP_TYPb` of S5, from the `\_S5` package.
    pub s5: Option<(u8, u8)>,
    /// The FADT reset register when it is an I/O port: (port, value).
    pub reset_port: Option<(u16, u8)>,
}

// Relaxed: written once on the boot CPU before anything can power off. 0
// means "absent" (port 0 and SLP_TYP packing never collide with a real value
// because the valid bit is set).
const VALID: u32 = 1 << 31;
static PM1A: AtomicU32 = AtomicU32::new(0);
static PM1B: AtomicU32 = AtomicU32::new(0);
static S5: AtomicU32 = AtomicU32::new(0);
static RESET: AtomicU32 = AtomicU32::new(0);

/// Records what the platform description says about power control.
pub fn set_acpi(a: &Acpi) {
    let port = |p: Option<u16>| p.map_or(0, |p| VALID | u32::from(p));
    PM1A.store(port(a.pm1a_cnt), Ordering::Relaxed);
    PM1B.store(port(a.pm1b_cnt), Ordering::Relaxed);
    S5.store(
        a.s5.map_or(0, |(x, y)| VALID | u32::from(x) << 8 | u32::from(y)),
        Ordering::Relaxed,
    );
    RESET.store(
        a.reset_port
            .map_or(0, |(p, v)| VALID | u32::from(v) << 16 | u32::from(p)),
        Ordering::Relaxed,
    );
}

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

/// Waits about 200 ms (by the TSC once it is calibrated, else a bounded
/// number of spins) for a power-off request to take effect.
fn settle() {
    let hz = crate::time::frequency();
    let start = crate::time::now();
    for _ in 0..200_000_000u32 {
        if hz > 1 && crate::time::now().wrapping_sub(start) > hz / 5 {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Writes the S5 request to the PM1 control blocks the platform described,
/// then waits for it to take effect. Returns if it did not (or there is
/// nothing to write).
fn acpi_s5() {
    // Relaxed: see `set_acpi`.
    let (a, b, typ) = (
        PM1A.load(Ordering::Relaxed),
        PM1B.load(Ordering::Relaxed),
        S5.load(Ordering::Relaxed),
    );
    if a & VALID == 0 || typ & VALID == 0 {
        return;
    }
    for (port, slp) in [(a, (typ >> 8) as u8), (b, typ as u8)] {
        if port & VALID != 0 {
            // SAFETY: the PM1 control block the FADT names, written with
            // the sleep type the DSDT gives for S5: the firmware's own
            // power-off recipe.
            unsafe { outw(port as u16, crate::pm::sleep_value(slp)) };
        }
    }
    settle();
}

/// Powers off; halts if nothing took effect.
pub fn off() -> ! {
    crate::serial::flush();
    acpi_s5();
    if under_hypervisor() {
        for port in [0x604, 0xb004] {
            // SAFETY: QEMU's ACPI PM1a control ports; under a hypervisor
            // an unclaimed port ignores the write.
            unsafe { outw(port, 0x2000) };
        }
        // Relaxed: see DEBUG_EXIT.
        if DEBUG_EXIT.load(Ordering::Relaxed) {
            // QEMU handles the power-off request in its main loop: give it
            // time, or the exit below wins the race and the status is 1.
            settle();
            // SAFETY: the dev-only debug-exit device; unclaimed otherwise.
            unsafe { outl(DEBUG_EXIT_PORT, 0) };
        }
    }
    crate::cpu::halt()
}

/// Resets the machine; halts if nothing took effect.
pub fn reset() -> ! {
    crate::serial::flush();
    // Relaxed: see `set_acpi`.
    let r = RESET.load(Ordering::Relaxed);
    if r & VALID != 0 {
        // SAFETY: the FADT's reset register (an I/O port), with the value
        // the FADT gives: the firmware's own reset recipe.
        unsafe { outb(r as u16, (r >> 16) as u8) };
        settle();
    }
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
