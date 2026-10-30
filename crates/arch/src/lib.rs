//! The architecture facade (ADR-040).
//!
//! The kernel and its crates name architecture services only through this
//! crate's modules. Each module re-exports the implementation of the target
//! architecture (`urmqtt-arch-aarch64` today, `urmqtt-arch-x86_64` from X1)
//! under the same names. [`contract`] binds every item to an explicit
//! signature, so an architecture that lacks one, or changes its shape,
//! fails to compile instead of drifting. Dispatch is static: no traits, no
//! generic parameters, no cost.
//!
//! Items that touch hardware exist only on bare metal
//! (`target_os = "none"`). Host builds get the pure parts (descriptor
//! encoding, MSI composition, feature decoding) and the barrier, which
//! falls back to a fence.
//!
//! The boot entry (`_start`, which calls the kernel's `urmqtt_kmain`) and
//! the secondary-CPU trampoline (`urmqtt_ap_entry`) are assembly in the
//! architecture crate; the linker pulls them in as the ELF entry and as a
//! referenced symbol.
//!
//! Some items are AArch64 concepts with no x86 counterpart yet (PAC keys,
//! the PSCI conduit, the GIC version). They are reached through these
//! modules for now; X1 decides per item whether x86 gets an equivalent or
//! the kernel call site becomes architecture-conditional.

#![no_std]
#![deny(unsafe_code)]

#[cfg(target_arch = "aarch64")]
use urmqtt_arch_aarch64 as imp;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
mod contract;

/// Memory ordering between the CPU and devices.
pub mod barrier {
    /// Makes earlier stores to normal memory (ring updates) visible before
    /// a later device write (the doorbell).
    #[inline(always)]
    pub fn doorbell() {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        super::imp::cpu::dsb_st();
        #[cfg(not(target_os = "none"))]
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// The executing CPU: interrupt masking, waiting, halting, privilege.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod cpu {
    pub use super::imp::cpu::{
        halt, irq_restore, irq_save, unmask_irq as enable_interrupts, wfi as wait_for_interrupt,
    };
    pub use super::imp::pac::{Continuation, set_ia_key as set_return_address_key, switch_to};
    pub use super::imp::regs::current_el as privilege_level;
}

/// The interrupt controller.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod irq {
    pub use super::imp::gic::GicError as Error;
    pub use super::imp::irq::{Ack, Controller, GICV2_MAX_CPUS, Local};
}

/// Inter-processor interrupt numbers (SGIs on AArch64).
#[cfg(target_arch = "aarch64")]
pub mod ipi {
    pub const PING: u32 = 1;
    pub const PONG: u32 = 2;
    pub const WAKE: u32 = 3;
}

/// Checksums with CPU instructions (dispatched, X0b).
#[cfg(target_arch = "aarch64")]
pub mod crc {
    pub use super::imp::crc::crc32c_update;
}

/// Message-signalled interrupts.
#[cfg(target_arch = "aarch64")]
pub mod msi {
    pub use super::imp::msi::{Frame, TYPER};
}

/// Per-CPU identity and secondary-CPU start.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod percpu {
    pub use super::imp::percpu::{ApBoot, ApEntry, current, hw_id, set_current};
}

/// Monotonic time and the per-CPU deadline timer.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod time {
    pub use super::imp::pmu::finest_clock;
    pub use super::imp::timer::{
        deadline, frequency, now, ns_to_ticks, set_deadline, ticks_to_ns, uptime_ns,
    };
}

/// Translation tables: descriptor encoding and walking (pure), and turning
/// them on (bare metal).
#[cfg(target_arch = "aarch64")]
pub mod paging {
    #[cfg(target_os = "none")]
    pub use super::imp::cpu::{tlb_flush_all, tlb_flush_va};
    #[cfg(target_os = "none")]
    pub use super::imp::mmu::{activate, kernel_root, merge_memory_attributes};
    pub use super::imp::paging::*;

    /// Makes table updates visible to the table walker before the new
    /// mappings are used.
    #[cfg(target_os = "none")]
    #[inline(always)]
    pub fn publish() {
        super::imp::cpu::dsb_ishst();
        super::imp::cpu::isb();
    }
}

/// Exception entry, the trap frame and deliberate test faults.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod trap {
    pub use super::imp::esr::Vector;
    pub use super::imp::exception::{Event, Registers, TrapFrame, install, set_handler};
    pub use super::imp::faults::{
        RET_INSN, branch_to_non_landing_pad, breakpoint, forged_return, undefined_instruction,
    };
}

/// The CPU's own random number source.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod entropy {
    pub use super::imp::entropy::hw_random;
}

/// System power control.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod power {
    pub use super::imp::power::{conduit_name, firmware_version, off, reset, set_conduit};
    pub use super::imp::psci::Conduit;
}

/// CPU features.
#[cfg(target_arch = "aarch64")]
pub mod features {
    pub use super::imp::features::{Features, IdRegs};

    /// Reads and decodes the executing CPU's features.
    #[cfg(target_os = "none")]
    pub fn detect() -> Features {
        Features::decode(super::imp::pac::id_regs())
    }
}
