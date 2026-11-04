//! The `urmqtt-cfg` configuration blob (C1, ADR-215).
//!
//! A compact, versioned, canonical binary form of a validated urMQTT
//! configuration. The release kernel is built once; the blob is data the
//! bootloader hands it (a Limine module), so the same kernel runs everyone's
//! configuration. This crate is `no_std` and shared by:
//!
//! - the kernel, which parses and re-validates the blob at boot and refuses
//!   anything it does not understand (fail closed);
//! - `urmqtt-config-schema`, which builds blobs from TOML and exports the
//!   field table as JSON for the web form;
//! - the host tool `urmqtt-config` and the browser (WebAssembly).
//!
//! [`fields::FIELDS`] is the one table of fields, defaults and ranges.
//! [`check::check`] holds the rules that span fields.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

pub mod blake2b;
pub mod blob;
#[cfg(any(test, feature = "alloc"))]
pub mod build;
pub mod check;
pub mod diskkey;
pub mod drivers;
pub mod fields;
pub mod net;
pub mod passwd;
pub mod plain;

pub use blob::{
    BASE_VERSION, Blob, DISK_MARKER, FORMAT_MIN, FORMAT_VERSION, MAGIC, MAX_BLOB, SLOT_MARKER,
    SLOT_SIZE, SlotKind,
};

use core::fmt;

/// Why a blob (or a configuration) is refused: the field's key and a fixed
/// reason, so the kernel can print it before any allocator exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgError {
    pub key: &'static str,
    pub msg: &'static str,
}

pub(crate) const fn err(key: &'static str, msg: &'static str) -> CfgError {
    CfgError { key, msg }
}

impl fmt::Display for CfgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.msg)
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for CfgError {}

#[cfg(test)]
mod tests;
