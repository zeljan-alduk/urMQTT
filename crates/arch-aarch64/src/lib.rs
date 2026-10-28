//! AArch64 support: boot glue, EL1 exception vectors, MMU, GICv3, generic timer, PSCI, per-CPU data, PAC/BTI.
//!
//! **Status: stub (M0).** Implementation lands in M1–M4; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
