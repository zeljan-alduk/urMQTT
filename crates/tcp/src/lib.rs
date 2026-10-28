//! Server-only TCP stack with SYN cookies and per-core connection tables.
//!
//! **Status: stub (M0).** Implementation lands in M14; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
