//! The open edition's kernel image: the kernel library with nothing added
//! (NOW-18, ADR-335). Another repository builds its own image the same way,
//! naming its own `urmqtt_kernel::ext::Edition` (docs/EDITIONS.md §5).
//!
//! On the host the binary only exists so workspace-wide `cargo clippy` works;
//! the real kernel is built for `aarch64-unknown-none` (`make build`).

#![cfg_attr(target_os = "none", no_std, no_main)]
#![deny(unsafe_code)]

urmqtt_kernel::image!(urmqtt_kernel::ext::Edition::OPEN);
