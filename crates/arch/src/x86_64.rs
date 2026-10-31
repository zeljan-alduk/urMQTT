//! The facade over `urmqtt-arch-x86_64`. Same module list and signatures as
//! the aarch64 facade (`contract.rs` checks both); concepts that only exist
//! on one architecture are inert on the other.

use urmqtt_arch_x86_64 as imp;

/// The executing CPU: interrupt masking, waiting, halting, privilege.
#[cfg(target_os = "none")]
pub mod cpu {
    pub use super::imp::cpu::{
        Continuation, enable_extended_state, enable_interrupts, halt, irq_restore, irq_save,
        privilege_level, set_return_address_key, switch_to, wait_for_interrupt,
    };
}

/// The interrupt controller (local APIC and I/O APIC).
#[cfg(target_os = "none")]
pub mod irq {
    pub use super::imp::irq::{Ack, Config, Controller, Error, GICV2_MAX_CPUS, Local, mode_name};
}

/// Inter-processor interrupt vectors.
pub mod ipi {
    pub const PING: u32 = 0xf1;
    pub const PONG: u32 = 0xf2;
    pub const WAKE: u32 = 0xf3;
}

/// Checksums with CPU instructions (dispatched).
pub mod crc {
    pub use super::imp::crc::crc32c_update;
}

/// Message-signalled interrupts.
pub mod msi {
    pub use super::imp::msi::{Frame, TYPER};
}

/// Per-CPU identity and secondary-CPU start.
#[cfg(target_os = "none")]
pub mod percpu {
    pub use super::imp::percpu::{ApBoot, ApEntry, current, hw_id, set_current};
}

/// Monotonic time and the per-CPU deadline timer.
#[cfg(target_os = "none")]
pub mod time {
    pub use super::imp::time::{
        Error, Info, PmTimer, Sources, deadline, finest_clock, frequency, init, now, ns_to_ticks,
        set_deadline, ticks_to_ns, timer_is_fallback, uptime_ns,
    };
}

/// Page tables: entry encoding and walking (pure), and turning them on.
pub mod paging {
    pub use super::imp::paging::*;
    #[cfg(target_os = "none")]
    pub use super::imp::paging::{
        activate, kernel_root, merge_memory_attributes, publish, tlb_flush_all, tlb_flush_va,
    };
}

/// Exception entry, the trap frame and deliberate test faults.
pub mod trap {
    pub use super::imp::trap::{Event, Registers, TrapFrame, Vector};
    #[cfg(target_os = "none")]
    pub use super::imp::trap::{
        RET_INSN, branch_to_non_landing_pad, breakpoint, double_fault, forged_return,
        general_protection, install, set_handler, undefined_instruction,
    };
}

/// The CPU's own random number source.
#[cfg(target_os = "none")]
pub mod entropy {
    pub use super::imp::entropy::hw_random;
}

/// The interrupt vector map (x86 only, so not part of the contract).
pub mod vectors {
    pub use super::imp::vectors::*;
}

/// Port I/O and CPU identity for PCI bring-up (x86 only, so not part of
/// the contract).
#[cfg(target_os = "none")]
pub mod pio {
    pub use super::imp::pio::{initial_apic_id, inl, outl};
}

/// System power control.
#[cfg(target_os = "none")]
pub mod power {
    pub use super::imp::power::{
        Acpi, Conduit, conduit_name, firmware_version, off, reset, set_acpi, set_conduit,
        set_debug_exit,
    };
}

/// The 16550 UART at COM1 (x86 only).
#[cfg(target_os = "none")]
pub mod serial {
    pub use super::imp::serial::{COM1, flush, init, read_byte, write_byte, write_bytes};
}

/// The PS/2 keyboard controller (x86 only; the diagnostic prompt, O4).
#[cfg(target_os = "none")]
pub mod ps2 {
    pub use super::imp::ps2::poll;
}

/// CPU features.
pub mod features {
    pub use super::imp::features::{
        BASELINE_ECX, Census, Features, IdRegs, Identity, Missing, baseline_missing,
        family_model_stepping,
    };

    /// Reads the executing CPU's CPUID leaves and XCR0 (after
    /// `cpu::enable_extended_state`).
    #[cfg(target_os = "none")]
    pub use super::imp::features::read as read_id_regs;

    /// Reads and decodes the executing CPU's features (CPUID, XGETBV).
    #[cfg(target_os = "none")]
    pub fn detect() -> Features {
        Features::decode(read_id_regs())
    }
}
