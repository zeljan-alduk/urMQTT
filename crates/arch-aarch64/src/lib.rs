//! AArch64 support: boot glue, EL1 exception vectors, MMU, GICv3 and GICv2,
//! generic timer, PSCI, per-CPU data, PAC/BTI.
//!
//! The kernel reaches this crate only through the `urmqtt-arch` facade
//! (ADR-040), and every instruction or system register that is specific to
//! AArch64 lives here (`scripts/check-arch-leaks.sh`).
//!
//! Pure logic (ESR decoding, descriptor encoding, MSI composition) is
//! host-testable.
//! Everything that executes system instructions is compiled only for the
//! bare-metal target (`target_os = "none"`).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod esr;
pub mod features;
pub mod msi;
pub mod paging;

#[cfg(target_os = "none")]
pub mod boot;
#[cfg(target_os = "none")]
pub mod cpu;
#[cfg(target_os = "none")]
pub mod entropy;
#[cfg(target_os = "none")]
pub mod exception;
#[cfg(target_os = "none")]
pub mod faults;
#[cfg(target_os = "none")]
pub mod gic;
#[cfg(target_os = "none")]
pub mod irq;
#[cfg(target_os = "none")]
pub mod mmu;
#[cfg(target_os = "none")]
pub mod pac;
#[cfg(target_os = "none")]
pub mod percpu;
#[cfg(target_os = "none")]
pub mod pmu;
#[cfg(target_os = "none")]
pub mod power;
#[cfg(target_os = "none")]
pub mod psci;
#[cfg(target_os = "none")]
pub mod regs;
#[cfg(target_os = "none")]
pub mod timer;
