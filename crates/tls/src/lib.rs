//! TLS 1.3 server: rustls handshake followed by a minimal in-house record layer.
//!
//! **Status: stub (M0).** Implementation lands in M10; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
