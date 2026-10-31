//! TLS 1.3 server: rustls handshake (mutual authentication) followed by a
//! minimal in-house record layer (PROMPT §6, ADR-029).
//!
//! - [`provider`]: rustls crypto provider on RustCrypto primitives.
//! - [`server`]: sans-IO per-connection state machine.
//! - [`record`]: post-handshake record layer with KeyUpdate.
//! - [`identity`]: device identity from the client certificate.
//! - [`rng`]: the kernel CSPRNG.
//! - [`ticket`]: rotating session-ticket keys (H2).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate alloc;

pub mod bench;
#[cfg(feature = "client")]
pub mod client;
pub mod identity;
pub mod kat;
pub mod probe;
pub mod provider;
pub mod record;
pub mod rng;
pub mod server;
pub mod ticket;

pub use identity::IdentityField;
pub use server::{
    CertRole, Event, RevocationList, ServerSetup, TlsError, TlsServer, TlsSession, serial_tag,
    set_clock,
};
pub use ticket::TicketKeys;

#[cfg(kani)]
mod proofs;
