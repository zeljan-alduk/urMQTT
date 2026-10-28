//! urMQTT kernel entry point.
//!
//! **Status: M0 skeleton.** On `aarch64-unknown-none` this links every crate
//! into one bare-metal ELF so `make build` proves the whole tree is `no_std`
//! clean. The entry point parks the CPU; the Limine boot path arrives in M1.
//! On the host the binary only exists so workspace-wide `cargo clippy` works.

#![cfg_attr(target_os = "none", no_std, no_main)]

// Keep every crate linked so the bare-metal build checks all of them.
use urmqtt_arch_aarch64 as _;
use urmqtt_broker as _;
use urmqtt_log as _;
use urmqtt_mm as _;
use urmqtt_mqtt as _;
use urmqtt_net as _;
use urmqtt_pci as _;
use urmqtt_platform as _;
use urmqtt_store as _;
use urmqtt_tcp as _;
use urmqtt_timer_wheel as _;
use urmqtt_tls as _;
use urmqtt_virtio as _;

/// Build-time environment baked into this image.
const ENV: &str = urmqtt_config::CONFIG.env;

#[cfg(target_os = "none")]
mod bare {
    use core::panic::PanicInfo;

    /// M0 placeholder entry: parks the CPU. Replaced by the Limine entry in M1.
    #[unsafe(no_mangle)]
    extern "C" fn _start() -> ! {
        let _ = super::ENV;
        park()
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        park()
    }

    fn park() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!(
        "urmqtt ({ENV} build) is a bare-metal kernel; build it with `make build` and boot it with `make run`"
    );
    std::process::exit(2);
}
