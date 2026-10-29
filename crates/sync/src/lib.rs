//! Architecture-neutral building blocks shared by the kernel and its
//! crates: a ticket spinlock and once-cell, the SPSC ring between cores,
//! and the frame-source trait page-table builders allocate from.
//!
//! Nothing here executes architecture-specific instructions, so every
//! crate that needs only these builds on any host without the arch facade
//! (ADR-040).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod frame;
pub mod spsc;
pub mod sync;
