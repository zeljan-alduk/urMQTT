//! virtio-pci modern transport, split virtqueues and the net, blk and rng devices.
//!
//! **Status: stub (M0).** Implementation lands in M6; see `docs/PROGRESS.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
