//! Hardware discovery over device tree (FDT) and ACPI behind one abstraction.
//!
//! Both sources are untrusted-format input (firmware can be buggy), so all
//! parsing is bounds-checked and panic-free. The full `PlatformInfo` (CPUs,
//! GIC, timer, PCIe) arrives in M5; M1 needs the console UART and PSCI.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod acpi;
pub mod fdt;

use acpi::{Acpi, PhysMemory};
use fdt::Fdt;

/// Where hardware information came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    DeviceTree,
    Acpi,
}

/// How PSCI is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciMethod {
    Hvc,
    Smc,
}

/// A PL011-compatible UART.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uart {
    /// Physical MMIO base.
    pub base: u64,
}

/// What early boot needs before memory management exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyPlatform {
    pub source: Source,
    pub uart: Option<Uart>,
    pub psci: Option<PsciMethod>,
}

/// Early discovery from a device tree.
pub fn early_from_fdt(fdt: &Fdt<'_>) -> Result<EarlyPlatform, fdt::FdtError> {
    let uart = fdt
        .find_compatible("arm,pl011")?
        .map(|n| n.reg(0))
        .transpose()?
        .flatten()
        .map(|(base, _)| Uart { base });
    let psci = match fdt.find_path("/psci")? {
        Some(n) => match n.prop_str("method")? {
            Some("hvc") => Some(PsciMethod::Hvc),
            Some("smc") => Some(PsciMethod::Smc),
            _ => None,
        },
        None => None,
    };
    Ok(EarlyPlatform {
        source: Source::DeviceTree,
        uart,
        psci,
    })
}

/// Early discovery from ACPI (SPCR for the console, FADT for PSCI).
pub fn early_from_acpi<M: PhysMemory>(
    acpi: &Acpi<'_, M>,
) -> Result<EarlyPlatform, acpi::AcpiError> {
    let uart = acpi
        .find(b"SPCR")?
        .as_ref()
        .and_then(acpi::parse_spcr)
        .filter(|s| s.pl011_compatible)
        .map(|s| Uart { base: s.base });
    let psci = acpi
        .find(b"FACP")?
        .as_ref()
        .and_then(acpi::parse_fadt_arm_boot_arch)
        .filter(|f| f.psci_compliant)
        .map(|f| {
            if f.psci_use_hvc {
                PsciMethod::Hvc
            } else {
                PsciMethod::Smc
            }
        });
    Ok(EarlyPlatform {
        source: Source::Acpi,
        uart,
        psci,
    })
}
