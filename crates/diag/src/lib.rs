//! The diagnostic boot entry (O4, ADR-063): everything that can be decided
//! without hardware. The kernel (`crates/kernel/src/diag.rs`) detects and
//! measures; this crate turns the figures into statistics, text, bars, the
//! JSON document and the dashboard, and decides whether a disk may be
//! written. Nothing here touches a device, so the parts that protect data
//! (`space`, `guard`) run under host tests.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod bars;
pub mod dash;
pub mod fmt;
pub mod guard;
pub mod json;
pub mod keys;
pub mod names;
pub mod report;
pub mod space;
pub mod stats;
pub mod time;
