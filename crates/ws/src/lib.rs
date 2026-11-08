//! MQTT over WebSocket (RFC 6455; MQTT 3.1.1 section 6), the transport only
//! (ADR-272).
//!
//! Two pieces, both `no_std`, `forbid(unsafe_code)`, without allocation and
//! fuzzed (`fuzz/fuzz_targets/ws_upgrade`, `ws_frames`):
//!
//! - [`upgrade`]: the opening handshake. One bounded HTTP/1.1 request
//!   (4 KiB, 32 header lines), checked to be exactly a WebSocket upgrade to
//!   the configured path offering the `mqtt` subprotocol from an allowed
//!   origin; the answer is `101` or a fixed refusal.
//! - [`frame`]: the frame codec of a server. Client frames are unmasked in
//!   place and their payload streamed out (MQTT needs no message boundaries),
//!   control frames answered by the caller, every violation of RFC 6455
//!   mapped to its close code.
//!
//! The MQTT bytes inside go to the broker's own parser with the broker's own
//! limits: this crate never looks at them.
//!
//! [`sha1`] exists only for `Sec-WebSocket-Accept` and is not exported.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod frame;
mod sha1;
pub mod upgrade;

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;
