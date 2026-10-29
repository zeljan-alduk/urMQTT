//! System power control through PSCI, over the conduit the firmware
//! description names.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu;
use crate::psci::{self, Conduit};

const NONE: u8 = 0;
const HVC: u8 = 1;
const SMC: u8 = 2;

// Relaxed everywhere: written once on the boot CPU before anything reads
// it from an exception path on the same CPU.
static CONDUIT: AtomicU8 = AtomicU8::new(NONE);

pub fn set_conduit(c: Conduit) {
    let v = match c {
        Conduit::Hvc => HVC,
        Conduit::Smc => SMC,
    };
    CONDUIT.store(v, Ordering::Relaxed);
}

pub fn conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Relaxed) {
        HVC => Some(Conduit::Hvc),
        SMC => Some(Conduit::Smc),
        _ => None,
    }
}

/// Short name of the firmware interface, for the boot log.
pub fn conduit_name() -> &'static str {
    match conduit() {
        Some(Conduit::Hvc) => "hvc",
        Some(Conduit::Smc) => "smc",
        None => "?",
    }
}

/// PSCI (major, minor), if the firmware answers.
pub fn firmware_version() -> Option<(u16, u16)> {
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
