//! Zero-copy MQTT 3.1.1 / 5.0 packet parser and encoder.
//!
//! **Status: stub (M0).** Implementation lands in M8; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
