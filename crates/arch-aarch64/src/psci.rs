//! PSCI (Arm DEN 0022) calls through HVC or SMC.

#![allow(unsafe_code)]

use core::arch::asm;

/// How PSCI is reached, as described by the DTB `method` or ACPI FADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduit {
    Hvc,
    Smc,
}

pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const CPU_ON_64: u32 = 0xc400_0003;
pub const SYSTEM_OFF: u32 = 0x8400_0008;
pub const SYSTEM_RESET: u32 = 0x8400_0009;

/// PSCI return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciError {
    NotSupported,
    InvalidParameters,
    Denied,
    AlreadyOn,
    OnPending,
    InternalFailure,
    NotPresent,
    Disabled,
    InvalidAddress,
    Unknown(i64),
}

impl PsciError {
    fn from_code(code: i64) -> Result<u64, Self> {
        Err(match code {
            c if c >= 0 => return Ok(c as u64),
            -1 => Self::NotSupported,
            -2 => Self::InvalidParameters,
            -3 => Self::Denied,
            -4 => Self::AlreadyOn,
            -5 => Self::OnPending,
            -6 => Self::InternalFailure,
            -7 => Self::NotPresent,
            -8 => Self::Disabled,
            -9 => Self::InvalidAddress,
            c => Self::Unknown(c),
        })
    }
}

/// Raw SMCCC call with up to three arguments.
///
/// # Safety
/// The function id and arguments must form a valid PSCI/SMCCC call whose
/// effects (e.g. starting a CPU at an address) the caller accepts.
pub unsafe fn call(conduit: Conduit, fid: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let mut x0 = u64::from(fid);
    match conduit {
        // SAFETY: SMCCC preserves x18-x30 and SP; x0-x17 may be clobbered.
        Conduit::Hvc => unsafe {
            asm!("hvc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
                out("x15") _, out("x16") _, out("x17") _, options(nostack))
        },
        // SAFETY: as above.
        Conduit::Smc => unsafe {
            asm!("smc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
                out("x15") _, out("x16") _, out("x17") _, options(nostack))
        },
    }
    x0 as i64
}

/// PSCI version as (major, minor).
pub fn version(conduit: Conduit) -> Result<(u16, u16), PsciError> {
    // SAFETY: PSCI_VERSION has no side effects.
    let v = PsciError::from_code(unsafe { call(conduit, PSCI_VERSION, 0, 0, 0) })?;
    Ok(((v >> 16) as u16, (v & 0xffff) as u16))
}

/// Powers the system off. Only returns if the firmware refused.
pub fn system_off(conduit: Conduit) -> PsciError {
    // SAFETY: shutting down is the intended effect.
    let r = unsafe { call(conduit, SYSTEM_OFF, 0, 0, 0) };
    PsciError::from_code(r)
        .err()
        .unwrap_or(PsciError::Unknown(r))
}

/// Resets the system. Only returns if the firmware refused.
pub fn system_reset(conduit: Conduit) -> PsciError {
    // SAFETY: resetting is the intended effect.
    let r = unsafe { call(conduit, SYSTEM_RESET, 0, 0, 0) };
    PsciError::from_code(r)
        .err()
        .unwrap_or(PsciError::Unknown(r))
}

/// Starts the CPU with affinity `mpidr` at physical address `entry_pa`.
///
/// # Safety
/// `entry_pa` must be valid code for a CPU entering with the MMU off.
pub unsafe fn cpu_on(
    conduit: Conduit,
    mpidr: u64,
    entry_pa: u64,
    context: u64,
) -> Result<(), PsciError> {
    // SAFETY: forwarded to the caller.
    PsciError::from_code(unsafe { call(conduit, CPU_ON_64, mpidr, entry_pa, context) }).map(|_| ())
}
