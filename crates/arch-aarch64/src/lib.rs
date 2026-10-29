//! AArch64 support: boot glue, EL1 exception vectors, MMU, GICv3, generic
//! timer, PSCI, per-CPU data, PAC/BTI.
//!
//! Pure logic (ESR decoding, descriptor encoding, locks) is host-testable.
//! Everything that executes system instructions is compiled only for the
//! bare-metal target (`target_os = "none"`).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod esr;
pub mod features;
pub mod paging;
pub mod spsc;
pub mod sync;

#[cfg(target_os = "none")]
pub mod cpu;
#[cfg(target_os = "none")]
pub mod exception;
#[cfg(target_os = "none")]
pub mod gic;
#[cfg(target_os = "none")]
pub mod pac;
#[cfg(target_os = "none")]
pub mod psci;
#[cfg(target_os = "none")]
pub mod regs;
#[cfg(target_os = "none")]
pub mod timer;
