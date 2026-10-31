//! System power control (PSCI on AArch64, through `arch::power`).

use core::sync::atomic::{AtomicBool, Ordering};

use urmqtt_arch::power as arch_power;
#[cfg(target_arch = "aarch64")]
use urmqtt_arch::power::Conduit;
#[cfg(target_arch = "aarch64")]
use urmqtt_platform::PsciMethod;

// Relaxed: written once on the boot CPU before anything reads it from an
// exception path on the same CPU.
static SMOKE: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "aarch64")]
pub fn set_conduit(m: PsciMethod) {
    arch_power::set_conduit(match m {
        PsciMethod::Hvc => Conduit::Hvc,
        PsciMethod::Smc => Conduit::Smc,
    });
}

pub fn set_smoke(smoke: bool) {
    SMOKE.store(smoke, Ordering::Relaxed);
    // Only a dev image in smoke mode may write QEMU's debug-exit port.
    #[cfg(target_arch = "x86_64")]
    arch_power::set_debug_exit(urmqtt_config::CONFIG.env == "dev" && smoke);
}

/// Whether this is a dev image booted in smoke mode (tests end the run).
pub fn smoke() -> bool {
    SMOKE.load(Ordering::Relaxed)
}

/// Powers off; halts if the firmware is unavailable or refuses.
pub fn off() -> ! {
    urmqtt_log::flush();
    arch_power::off()
}

/// A requested reboot (the console's `reboot`, O2): the log is flushed and
/// the machine resets. Durable state is crash-safe, so nothing else is
/// needed; the caller waits a moment for its reply to leave first.
pub fn reboot() -> ! {
    urmqtt_log::flush();
    arch_power::reset()
}

// Relaxed: written once on the boot CPU after the boot medium is known.
static HALT_ON_FATAL: AtomicBool = AtomicBool::new(false);

/// Booted from the installation medium: a fatal error there is not cured by
/// a reset (it would loop, menu to kernel to reset), so it halts instead.
pub fn set_halt_on_fatal(halt: bool) {
    HALT_ON_FATAL.store(halt, Ordering::Relaxed);
}

/// How long a production VM keeps a fatal message on the console before it
/// resets: long enough to read over a VNC console.
const RESET_DELAY_NS: u64 = 60_000_000_000;

/// After a fatal error: power off in smoke mode (so the harness sees an exit);
/// from the installation medium halt with the message on screen; otherwise
/// leave the message readable for 60 s and reset, so a production VM comes
/// back by itself.
pub fn fatal() -> ! {
    if SMOKE.load(Ordering::Relaxed) {
        off()
    }
    if HALT_ON_FATAL.load(Ordering::Relaxed) {
        urmqtt_log::emergency(format_args!(
            "\n=== Booted from read-only media. Reboot and choose \"Install urMQTT on this machine's disk\" in the boot menu, then boot from the disk. Halted. ===\n"
        ));
        urmqtt_log::flush();
        urmqtt_arch::cpu::halt()
    }
    urmqtt_log::emergency(format_args!("resetting in 60 s\n"));
    urmqtt_log::flush();
    let end = urmqtt_arch::time::uptime_ns().saturating_add(RESET_DELAY_NS);
    // Bounded by iterations too: before the clock runs it does not advance.
    for _ in 0..4_000_000_000u64 {
        if urmqtt_arch::time::uptime_ns() >= end {
            break;
        }
        core::hint::spin_loop();
    }
    arch_power::reset()
}
