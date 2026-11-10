//! urMQTT kernel: boot sequence, per-core loop and wiring of all crates, as a
//! library (NOW-18, ADR-335).
//!
//! A kernel image is a binary crate that names its [`ext::Edition`] with
//! [`image!`]: the open edition's binary is `src/main.rs` of this package
//! ([`ext::Edition::OPEN`], nothing added); another repository builds its own
//! image the same way, with PCI drivers, configuration keys in the reserved
//! range and boot hooks of its own (docs/EDITIONS.md §5,
//! docs/ARCHITECTURE.md "The kernel as a library"). Everything else the kernel
//! does is this library's and is the same in every edition.
//!
//! On the host the library holds only what host tests need (the command line
//! parser) and the binary only exists so workspace-wide `cargo clippy` works;
//! the real kernel is built for `aarch64-unknown-none` (`make build`).

#![cfg_attr(target_os = "none", no_std)]
#![deny(unsafe_code)]

extern crate alloc;

// Crates not wired in yet are still linked so the bare-metal build checks them.
use urmqtt_broker as _;
use urmqtt_http as _;
use urmqtt_mqtt as _;
use urmqtt_net as _;
use urmqtt_plain as _;
use urmqtt_store as _;
use urmqtt_tcp as _;
use urmqtt_ws as _;

#[doc(hidden)]
pub mod cmdline;

#[cfg(target_os = "none")]
mod backpressure;
#[cfg(target_os = "none")]
mod boot;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
mod boot_aarch64;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod boot_x86;
#[cfg(target_os = "none")]
mod bootslot;
#[cfg(target_os = "none")]
mod conn_limit;
#[cfg(target_os = "none")]
mod console;
#[cfg(target_os = "none")]
mod control;
#[cfg(target_os = "none")]
mod cpu_dispatch;
#[cfg(all(target_os = "none", feature = "selftest"))]
mod crypto_bench;
#[cfg(target_os = "none")]
mod dataplane;
#[cfg(target_os = "none")]
mod db;
#[cfg(target_os = "none")]
mod dbsandbox;
#[cfg(target_os = "none")]
mod devices;
#[cfg(target_os = "none")]
mod diag;
#[cfg(all(target_os = "none", feature = "selftest"))]
mod dpbench;
pub mod ext;
#[cfg(all(target_os = "none", feature = "virtio-gpu"))]
mod gpucon;
#[cfg(target_os = "none")]
mod hardening;
#[cfg(all(target_os = "none", feature = "selftest"))]
mod hardtest;
#[cfg(target_os = "none")]
mod install;
#[cfg(target_os = "none")]
mod iommu;
#[cfg(target_os = "none")]
mod irq;
#[cfg(target_os = "none")]
mod jitter;
#[cfg(target_os = "none")]
mod layout;
#[cfg(target_os = "none")]
mod live;
#[cfg(target_os = "none")]
mod logship;
#[cfg(target_os = "none")]
mod logtest;
#[cfg(target_os = "none")]
mod memory;
#[cfg(all(target_os = "none", feature = "memprof", target_arch = "x86_64"))]
mod memprof;
#[cfg(target_os = "none")]
mod metrics;
#[cfg(target_os = "none")]
mod mqtt5;
#[cfg(target_os = "none")]
mod mqtt_service;
#[cfg(target_os = "none")]
mod netproto;
#[cfg(target_os = "none")]
mod ops;
#[cfg(target_os = "none")]
mod outbound;
#[cfg(target_os = "none")]
mod plain;
#[cfg(target_os = "none")]
mod power;
#[cfg(target_os = "none")]
mod selftest;
#[cfg(all(target_os = "none", feature = "selftest"))]
mod simd_irq;
#[cfg(target_os = "none")]
mod smp;
#[cfg(target_os = "none")]
mod sys;
#[cfg(target_os = "none")]
mod tick;
#[cfg(target_os = "none")]
mod time_sync;
#[cfg(target_os = "none")]
mod trap;
#[cfg(target_os = "none")]
mod unlock;
#[cfg(target_os = "none")]
mod vdev;
#[cfg(target_os = "none")]
mod vm;
#[cfg(target_os = "none")]
mod watchdog;
#[cfg(target_os = "none")]
mod websocket;

/// Image version: `git describe` passed in by the Makefile, else the crate version.
pub const VERSION: &str = match option_env!("URMQTT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// The crates an edition's drivers build on, re-exported so that an edition
/// uses exactly the versions this kernel was built with (ADR-335).
pub use urmqtt_cfg as cfg;
#[cfg(target_os = "none")]
pub use urmqtt_log as log;
#[cfg(target_os = "none")]
pub use urmqtt_pci as pci;

/// The kernel's entry for [`image!`]: the boot CPU's `urmqtt_kmain` calls it
/// with the image's edition. Not for other callers.
#[cfg(target_os = "none")]
#[doc(hidden)]
pub use boot::kmain as __kmain;

/// What a kernel binary does on the host (it only exists there so that
/// workspace-wide `cargo clippy` and `cargo test` build it). Not for other callers.
#[cfg(not(target_os = "none"))]
#[doc(hidden)]
pub fn __host_main() -> ! {
    let _ = cmdline::BootOptions::parse("", false);
    eprintln!(
        "urmqtt {VERSION} ({} build) is a bare-metal kernel; build it with `make build` and boot it with `make run`",
        urmqtt_config::CONFIG.env
    );
    std::process::exit(2);
}
