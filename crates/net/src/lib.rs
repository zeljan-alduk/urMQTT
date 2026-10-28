//! Ethernet, ARP, IPv4, ICMP and DHCPv4 handling with dispatch to TCP.
//!
//! **Status: stub (M0).** Implementation lands in M7 (prototype) and M14; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
