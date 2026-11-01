//! The urMQTT builder as a WebAssembly module (C1e, ADR-220).
//!
//! The page that configures a template ISO in the browser needs the very same
//! logic the command line tool has: the field table and its defaults, the
//! validation, packing the blob, patching the ISO, BLAKE2b and SHA-256, the
//! optional Ed25519 signature and the minisign check of a release. This crate
//! does not re-implement any of it: [`core`] calls `urmqtt-cfg`,
//! `urmqtt-config-schema` and `urmqtt-config-tool` (the library behind the
//! `urmqtt-config` binary), and the test in `tools/builder/test` packs the
//! same input with the binary and with this module and compares the bytes.
//!
//! [`exports`] is a plain C ABI on buffer handles (no wasm-bindgen, no
//! JavaScript glue generator); see its documentation. The module has no
//! imports: it needs no clock, no randomness and no I/O (the page supplies
//! the time and the random seed for a new signing key).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
// `exports` allows `unsafe_code` for the attribute that names its symbols.
#![deny(unsafe_code)]

pub mod core;
pub mod exports;
mod json;

#[cfg(test)]
mod tests;
