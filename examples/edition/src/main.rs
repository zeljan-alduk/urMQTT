//! The example edition's kernel image (NOW-18): the open kernel plus a PCI
//! driver for QEMU's `edu` test device (1234:11e8), two configuration keys
//! and every boot hook. Built by `make edition-example`, booted by the
//! smoke group `edition` with `-device edu`.

#![cfg_attr(target_os = "none", no_std, no_main)]
#![deny(unsafe_code)]

#[cfg(target_os = "none")]
mod edu;

#[cfg(target_os = "none")]
urmqtt_kernel::image!(edu::EDITION);

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!("urmqtt-example is a bare-metal kernel: build it with `make edition-example`");
    std::process::exit(2);
}
