//! Plaintext MQTT for trusted networks (P1, ADR-229, ADR-230): the pure logic
//! behind the listener, so that it is tested on the host.
//!
//! - [`allow::AllowList`]: which source addresses may even start a TCP
//!   connection. The kernel asks at the SYN, before any SYN-ACK: a refused
//!   address gets no answer and the broker keeps no state for it.
//! - [`sources::Sources`]: one small fixed table for all cores, keyed by source
//!   address: how many connections it holds, how many logins it failed lately
//!   and until when it is locked out.
//! - [`auth::Authenticator`]: who a CONNECT is, in the three modes (password,
//!   anonymous, per-network identity), with a work factor that does not say
//!   whether a user name exists.
//!
//! Nothing here touches a clock, a lock or a socket; the kernel passes time in
//! and wraps [`sources::Sources`] in its spin lock.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

pub mod allow;
pub mod auth;
pub mod sources;

pub use allow::{AllowList, Exposure};
pub use auth::{Account, Accounts, Authenticator, Rejection, Verdict};
pub use sources::{Limits, Open, Sources, Syn};
