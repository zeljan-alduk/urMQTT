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

#[cfg(target_os = "none")]
mod contract;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

/// Memory ordering between the CPU and devices.
pub mod barrier {
    /// Makes earlier stores to normal memory (ring updates) visible before
    /// a later device write (the doorbell).
    #[inline(always)]
    pub fn doorbell() {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        urmqtt_arch_aarch64::cpu::dsb_st();
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(not(target_os = "none"))]
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}
