//! SQLite FFI, raw-disk VFS over virtio-blk, telemetry log and data disk layout.
//!
//! **Status: stub (M0).** Implementation lands in M11 and M12; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
