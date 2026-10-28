//! Lock-free per-CPU log rings drained to UART, framebuffer and UDP syslog sinks.
//!
//! **Status: stub (M0).** Implementation lands in M1 (sinks) and M13 (per-CPU rings); see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
