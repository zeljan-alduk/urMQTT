//! System power control through PSCI.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use urmqtt_arch_aarch64::cpu;
use urmqtt_arch_aarch64::psci::{self, Conduit};
use urmqtt_platform::PsciMethod;

const NONE: u8 = 0;
const HVC: u8 = 1;
const SMC: u8 = 2;

// Relaxed everywhere: written once on the boot CPU before anything reads
// them from an exception path on the same CPU.
static CONDUIT: AtomicU8 = AtomicU8::new(NONE);
static SMOKE: AtomicBool = AtomicBool::new(false);

pub fn set_conduit(m: PsciMethod) {
    let v = match m {
        PsciMethod::Hvc => HVC,
        PsciMethod::Smc => SMC,
    };
    CONDUIT.store(v, Ordering::Relaxed);
}

pub fn set_smoke(smoke: bool) {
    SMOKE.store(smoke, Ordering::Relaxed);
}

pub fn conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Relaxed) {
        HVC => Some(Conduit::Hvc),
        SMC => Some(Conduit::Smc),
        _ => None,
    }
}

pub fn psci_version() -> Option<(u16, u16)> {
    psci::version(conduit()?).ok()
}

/// Powers off; halts if PSCI is unavailable or refuses.
pub fn off() -> ! {
    if let Some(c) = conduit() {
        let _ = psci::system_off(c);
    }
    cpu::halt()
}

/// Resets; halts if PSCI is unavailable or refuses.
pub fn reset() -> ! {
    if let Some(c) = conduit() {
        let _ = psci::system_reset(c);
    }
    cpu::halt()
}

/// After a fatal error: power off in smoke mode (so the harness sees an exit),
/// otherwise reset so a production VM comes back by itself.
pub fn fatal() -> ! {
    if SMOKE.load(Ordering::Relaxed) {
        off()
    } else {
        reset()
    }
}
