//! MQTT broker core: sessions, topic tree, subscriptions, routing, QoS, retained messages, LWT, ACL and limits.
//!
//! **Status: stub (M0).** Implementation lands in M9; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
