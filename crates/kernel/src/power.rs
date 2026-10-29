//! System power control (PSCI on AArch64, through `arch::power`).

use core::sync::atomic::{AtomicBool, Ordering};

use urmqtt_arch::power::{self as arch_power, Conduit};
use urmqtt_platform::PsciMethod;

// Relaxed: written once on the boot CPU before anything reads it from an
// exception path on the same CPU.
static SMOKE: AtomicBool = AtomicBool::new(false);

pub fn set_conduit(m: PsciMethod) {
    arch_power::set_conduit(match m {
        PsciMethod::Hvc => Conduit::Hvc,
        PsciMethod::Smc => Conduit::Smc,
    });
}

pub fn set_smoke(smoke: bool) {
    SMOKE.store(smoke, Ordering::Relaxed);
}

/// Powers off; halts if the firmware is unavailable or refuses.
pub fn off() -> ! {
    arch_power::off()
}

/// After a fatal error: power off in smoke mode (so the harness sees an exit),
/// otherwise reset so a production VM comes back by itself.
pub fn fatal() -> ! {
    if SMOKE.load(Ordering::Relaxed) {
        off()
    } else {
        arch_power::reset()
    }
}
