//! The facade over `urmqtt-arch-aarch64`.

use urmqtt_arch_aarch64 as imp;

/// The executing CPU: interrupt masking, waiting, halting, privilege.
#[cfg(target_os = "none")]
pub mod cpu {
    pub use super::imp::cpu::{
        halt, irq_restore, irq_save, unmask_irq as enable_interrupts, wfi as wait_for_interrupt,
    };
    pub use super::imp::pac::{Continuation, set_ia_key as set_return_address_key, switch_to};
    pub use super::imp::regs::current_el as privilege_level;
}

/// The interrupt controller.
#[cfg(target_os = "none")]
pub mod irq {
    pub use super::imp::gic::GicError as Error;
    pub use super::imp::irq::{Ack, Controller, GICV2_MAX_CPUS, Local};
}

/// Inter-processor interrupt numbers (SGIs on AArch64).
pub mod ipi {
    pub const PING: u32 = 1;
    pub const PONG: u32 = 2;
    pub const WAKE: u32 = 3;
}

/// Checksums with CPU instructions (dispatched, X0b).
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
    pub use super::imp::pmu::finest_clock;
    pub use super::imp::timer::{
        deadline, frequency, now, ns_to_ticks, set_deadline, ticks_to_ns, uptime_ns,
    };
}

/// Translation tables: descriptor encoding and walking (pure), and turning
/// them on (bare metal).
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
#[cfg(target_os = "none")]
pub mod trap {
    pub use super::imp::esr::Vector;
    pub use super::imp::exception::{Event, Registers, TrapFrame, install, set_handler};
    pub use super::imp::faults::{
        RET_INSN, branch_to_non_landing_pad, breakpoint, forged_return, undefined_instruction,
    };
}

/// The CPU's own random number source.
#[cfg(target_os = "none")]
pub mod entropy {
    pub use super::imp::entropy::hw_random;
}

/// System power control.
#[cfg(target_os = "none")]
pub mod power {
    pub use super::imp::power::{conduit_name, firmware_version, off, reset, set_conduit};
    pub use super::imp::psci::Conduit;
}

/// CPU features.
pub mod features {
    pub use super::imp::features::{Features, IdRegs};

    /// MIDR_EL1: implementer, variant, architecture, part and revision.
    #[cfg(target_os = "none")]
    pub fn midr() -> u64 {
        super::imp::features::midr()
    }

    /// Reads and decodes the executing CPU's features.
    #[cfg(target_os = "none")]
    pub fn detect() -> Features {
        Features::decode(super::imp::pac::id_regs())
    }
}
