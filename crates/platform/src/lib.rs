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

/// GICv3 register frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gic {
    pub gicd: u64,
    /// Redistributor region: (base, length).
    pub gicr: (u64, u64),
    /// GICv3 ITS (MSI translation), if present (TCG, KVM).
    pub its: Option<u64>,
    /// GICv2m MSI frame, if present (QEMU under HVF).
    pub v2m: Option<u64>,
}

/// Generic timer interrupt IDs (INTIDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerIrqs {
    /// EL1 virtual timer (CNTV), the one the kernel uses.
    pub virt: u32,
    /// EL1 non-secure physical timer (CNTP).
    pub phys: u32,
}

/// Interrupt controller and timer description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupts {
    pub gic: Gic,
    pub timer: TimerIrqs,
}

/// What early boot needs before memory management exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyPlatform {
    pub source: Source,
    pub uart: Option<Uart>,
    pub psci: Option<PsciMethod>,
    pub interrupts: Option<Interrupts>,
}

/// PPI number (0-15) in a DTB interrupt specifier → INTID.
const PPI_BASE: u32 = 16;
/// GICv3 redistributor stride with VLPI frames absent (RD + SGI frames).
pub const GICR_STRIDE: u64 = 0x2_0000;

fn interrupts_from_fdt(fdt: &Fdt<'_>) -> Result<Option<Interrupts>, fdt::FdtError> {
    let Some(gic) = fdt.find_compatible("arm,gic-v3")? else {
        return Ok(None);
    };
    let (Some((gicd, _)), Some(gicr)) = (gic.reg(0)?, gic.reg(1)?) else {
        return Ok(None);
    };
    let its = fdt
        .find_compatible("arm,gic-v3-its")?
        .map(|n| n.reg(0))
        .transpose()?
        .flatten()
        .map(|r| r.0);
    let v2m = fdt
        .find_compatible("arm,gic-v2m-frame")?
        .map(|n| n.reg(0))
        .transpose()?
        .flatten()
        .map(|r| r.0);
    let Some(timer) = fdt.find_compatible("arm,armv8-timer")? else {
        return Ok(None);
    };
    let Some(spec) = timer.prop("interrupts")? else {
        return Ok(None);
    };
    // Four (type, number, flags) triplets: secure phys, NS phys, virt, hyp.
    let ppi = |i: usize| fdt::read_cells(spec, i * 12 + 4, 1) as u32 + PPI_BASE;
    if spec.len() < 36 {
        return Ok(None);
    }
    Ok(Some(Interrupts {
        gic: Gic {
            gicd,
            gicr,
            its,
            v2m,
        },
        timer: TimerIrqs {
            virt: ppi(2),
            phys: ppi(1),
        },
    }))
}

fn interrupts_from_acpi<M: PhysMemory>(
    acpi: &Acpi<'_, M>,
) -> Result<Option<Interrupts>, acpi::AcpiError> {
    let (Some(madt), Some(gtdt)) = (acpi.find(b"APIC")?, acpi.find(b"GTDT")?) else {
        return Ok(None);
    };
    let m = acpi::parse_madt(&madt);
    let Some(t) = acpi::parse_gtdt(&gtdt) else {
        return Ok(None);
    };
    let gicr = match (m.gicr_range, m.gicc_gicr_base) {
        (Some(r), _) => r,
        (None, Some(base)) => (base, GICR_STRIDE * m.cpus.max(1) as u64),
        (None, None) => return Ok(None),
    };
    if m.gicd == 0 || (m.version != 0 && m.version < 3) {
        return Ok(None);
    }
    Ok(Some(Interrupts {
        gic: Gic {
            gicd: m.gicd,
            gicr,
            its: m.its,
            v2m: m.msi_frame.map(|f| f.0),
        },
        timer: TimerIrqs {
            virt: t.el1_virt,
            phys: t.el1_phys,
        },
    }))
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
        interrupts: interrupts_from_fdt(fdt)?,
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
        interrupts: interrupts_from_acpi(acpi)?,
    })
}
