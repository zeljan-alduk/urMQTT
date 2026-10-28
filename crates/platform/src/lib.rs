//! Hardware discovery over device tree (FDT) and ACPI (MADT, GTDT, MCFG, SPCR) behind one abstraction.
//!
//! **Status: stub (M0).** Implementation lands in M1 (UART discovery) and M5; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
