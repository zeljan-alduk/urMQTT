//! The contract between the kernel and the dbworker (ADR-210, ADR-211):
//! the worker's address-space layout, its system calls and the format of the
//! shared window. Pure constants and arithmetic, so both sides (and the host
//! tests) read the same numbers; the only code is the system-call stub the
//! worker uses, in assembly, here because architecture-specific instructions
//! may live only in architecture crates and leaf crates like this one.

#![no_std]

pub mod abi;
pub mod layout;
pub mod proto;
#[cfg(target_os = "none")]
pub mod stub;
