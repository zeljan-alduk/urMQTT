//! urMQTT kernel: boot sequence, per-core loop and wiring of all crates.
//!
//! On the host the binary only exists so workspace-wide `cargo clippy` works;
//! the real kernel is built for `aarch64-unknown-none` (`make build`).

#![cfg_attr(target_os = "none", no_std, no_main)]
#![deny(unsafe_code)]

#[cfg(target_os = "none")]
extern crate alloc;

// Crates not wired in yet are still linked so the bare-metal build checks them.
use urmqtt_broker as _;
use urmqtt_mqtt as _;
use urmqtt_net as _;
use urmqtt_store as _;
use urmqtt_tcp as _;

mod cmdline;

#[cfg(target_os = "none")]
mod boot;
#[cfg(target_os = "none")]
mod console;
#[cfg(target_os = "none")]
mod dataplane;
#[cfg(target_os = "none")]
mod db;
#[cfg(target_os = "none")]
mod devices;
#[cfg(all(target_os = "none", feature = "selftest"))]
mod dpbench;
#[cfg(target_os = "none")]
mod irq;
#[cfg(target_os = "none")]
mod layout;
#[cfg(target_os = "none")]
mod memory;
#[cfg(target_os = "none")]
mod mqtt_service;
#[cfg(target_os = "none")]
mod netproto;
#[cfg(target_os = "none")]
mod ops;
#[cfg(target_os = "none")]
mod power;
#[cfg(target_os = "none")]
mod selftest;
#[cfg(target_os = "none")]
mod smp;
#[cfg(target_os = "none")]
mod tick;
#[cfg(target_os = "none")]
mod trap;
#[cfg(target_os = "none")]
mod vm;
#[cfg(target_os = "none")]
mod watchdog;

/// Image version: `git describe` passed in by the Makefile, else the crate version.
pub const VERSION: &str = match option_env!("URMQTT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[cfg(not(target_os = "none"))]
fn main() {
    let _ = cmdline::BootOptions::parse("", false);
    eprintln!(
        "urmqtt {VERSION} ({} build) is a bare-metal kernel; build it with `make build` and boot it with `make run`",
        urmqtt_config::CONFIG.env
    );
    std::process::exit(2);
}
