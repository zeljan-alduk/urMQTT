//! System power control (X2, ADR-044): the ACPI reset register and S5.

/// How firmware services are reached (aarch64: HVC/SMC for PSCI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduit {
    Acpi,
}

pub fn set_conduit(_c: Conduit) {}

pub fn conduit_name() -> &'static str {
    "acpi"
}

/// The firmware interface version (aarch64: the PSCI version).
pub fn firmware_version() -> Option<(u16, u16)> {
    None
}

pub fn off() -> ! {
    unimplemented_until!("X2 (power)")
}

pub fn reset() -> ! {
    unimplemented_until!("X2 (power)")
}
