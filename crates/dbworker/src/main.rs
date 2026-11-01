//! The unprivileged database worker (ADR-210): everything in this program
//! runs at EL0 / ring 3 in an address space of its own. It cannot see the
//! kernel; it talks to it through the shared window and the system calls of
//! `urmqtt-usys`.
//!
//! On the host the binary only exists so workspace-wide `cargo clippy`
//! works.

#![cfg_attr(target_os = "none", no_std, no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "none")]
mod user;

#[cfg(not(target_os = "none"))]
use urmqtt_usys as _;

#[cfg(not(target_os = "none"))]
fn main() {}
