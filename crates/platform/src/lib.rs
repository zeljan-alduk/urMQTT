//! Hardware discovery over device tree (FDT) and ACPI behind one abstraction.
//!
//! Both sources are untrusted-format input (firmware can be buggy), so all
//! parsing is bounds-checked and panic-free. Either path produces the same
//! [`PlatformInfo`]; its `Display` form is the "platform summary" that must be
//! identical for a machine described by DTB and by ACPI.

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

/// Upper bound on CPUs described (matches the kernel's per-CPU slots).
pub const MAX_CPUS: usize = 64;

/// MPIDR affinity values of the CPUs, boot CPU included, firmware order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuList {
    mpidrs: [u64; MAX_CPUS],
    count: usize,
    /// CPUs described beyond `MAX_CPUS`.
    pub dropped: usize,
}

impl CpuList {
    pub const fn new() -> Self {
        Self {
            mpidrs: [0; MAX_CPUS],
            count: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, mpidr: u64) {
        match self.mpidrs.get_mut(self.count) {
            Some(slot) => {
                *slot = mpidr;
                self.count += 1;
            }
            None => self.dropped += 1,
        }
    }

    pub fn as_slice(&self) -> &[u64] {
        self.mpidrs.get(..self.count).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for CpuList {
    fn default() -> Self {
        Self::new()
    }
}

/// A PCIe host bridge with an ECAM configuration window.
///
/// BAR windows are not part of the description: on both QEMU and cloud
/// firmware, UEFI has already assigned BARs, which the kernel reads from
/// config space (and ACPI would need AML for the windows anyway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pcie {
    pub ecam: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

impl Pcie {
    /// Size of the ECAM window for the bus range (1 MiB per bus).
    pub fn ecam_size(&self) -> u64 {
        (u64::from(self.bus_end) - u64::from(self.bus_start) + 1) << 20
    }
}

/// Everything the kernel learns about the machine from firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformInfo {
    pub source: Source,
    pub uart: Option<Uart>,
    pub psci: Option<PsciMethod>,
    pub interrupts: Option<Interrupts>,
    pub cpus: CpuList,
    pub pcie: Option<Pcie>,
}

/// Early discovery used to be a subset; it is now the full description.
pub type EarlyPlatform = PlatformInfo;

impl core::fmt::Display for PlatformInfo {
    /// Source-independent summary, e.g.
    /// `uart=0x9000000 psci=hvc gicd=0x8000000 gicr=0x80a0000 msi=v2m@0x8020000
    ///  timer=27/30 cpus=4[0x0,0x1,0x2,0x3] pcie=0x4010000000/0:0-255`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.uart {
            Some(u) => write!(f, "uart={:#x}", u.base)?,
            None => f.write_str("uart=none")?,
        }
        f.write_str(match self.psci {
            Some(PsciMethod::Hvc) => " psci=hvc",
            Some(PsciMethod::Smc) => " psci=smc",
            None => " psci=none",
        })?;
        match self.interrupts {
            Some(i) => {
                write!(f, " gicd={:#x} gicr={:#x}", i.gic.gicd, i.gic.gicr.0)?;
                match (i.gic.its, i.gic.v2m) {
                    (Some(its), _) => write!(f, " msi=its@{its:#x}")?,
                    (None, Some(v2m)) => write!(f, " msi=v2m@{v2m:#x}")?,
                    (None, None) => f.write_str(" msi=none")?,
                }
                write!(f, " timer={}/{}", i.timer.virt, i.timer.phys)?;
            }
            None => f.write_str(" gic=none")?,
        }
        write!(f, " cpus={}[", self.cpus.len())?;
        for (i, m) in self.cpus.as_slice().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{m:#x}")?;
        }
        f.write_str("]")?;
        match self.pcie {
            Some(p) => write!(
                f,
                " pcie={:#x}/{}:{}-{}",
                p.ecam, p.segment, p.bus_start, p.bus_end
            ),
            None => f.write_str(" pcie=none"),
        }
    }
}

fn cpus_from_fdt(fdt: &Fdt<'_>) -> Result<CpuList, fdt::FdtError> {
    let mut cpus = CpuList::new();
    let mut in_cpus = false;
    let mut err = None;
    fdt.for_each_node(|n| {
        if n.depth == 1 {
            in_cpus = n.name == "cpus";
        } else if in_cpus && n.depth == 2 {
            match (n.prop_str("device_type"), n.reg(0)) {
                (Ok(Some("cpu")), Ok(Some((mpidr, _)))) => cpus.push(mpidr & 0xff_00ff_ffff),
                (Err(e), _) | (_, Err(e)) => {
                    err = Some(e);
                    return fdt::Visit::Stop;
                }
                _ => {}
            }
        }
        fdt::Visit::Continue
    })?;
    err.map_or(Ok(cpus), Err)
}

fn pcie_from_fdt(fdt: &Fdt<'_>) -> Result<Option<Pcie>, fdt::FdtError> {
    let Some(n) = fdt.find_compatible("pci-host-ecam-generic")? else {
        return Ok(None);
    };
    let Some((ecam, _)) = n.reg(0)? else {
        return Ok(None);
    };
    let (bus_start, bus_end) = match n.prop("bus-range")? {
        Some(v) if v.len() >= 8 => (
            fdt::read_cells(v, 0, 1).min(255) as u8,
            fdt::read_cells(v, 4, 1).min(255) as u8,
        ),
        _ => (0, 255),
    };
    let segment = n.prop_u32("linux,pci-domain")?.unwrap_or(0) as u16;
    Ok(Some(Pcie {
        ecam,
        segment,
        bus_start,
        bus_end,
    }))
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
    // PPI numbers are 0..16; anything else is a malformed tree.
    let ppi = |i: usize| {
        let n = fdt::read_cells(spec, i * 12 + 4, 1);
        (n < 16).then(|| n as u32 + PPI_BASE)
    };
    if spec.len() < 36 {
        return Ok(None);
    }
    let (Some(virt), Some(phys)) = (ppi(2), ppi(1)) else {
        return Ok(None);
    };
    Ok(Some(Interrupts {
        gic: Gic {
            gicd,
            gicr,
            its,
            v2m,
        },
        timer: TimerIrqs { virt, phys },
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
    Ok(PlatformInfo {
        source: Source::DeviceTree,
        uart,
        psci,
        interrupts: interrupts_from_fdt(fdt)?,
        cpus: cpus_from_fdt(fdt)?,
        pcie: pcie_from_fdt(fdt)?,
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
    let mut cpus = CpuList::new();
    if let Some(madt) = acpi.find(b"APIC")? {
        for m in acpi::madt_cpus(&madt) {
            cpus.push(m);
        }
    }
    let pcie = acpi.find(b"MCFG")?.and_then(|t| {
        acpi::mcfg_entries(&t).next().map(|e| Pcie {
            ecam: e.base,
            segment: e.segment,
            bus_start: e.bus_start,
            bus_end: e.bus_end,
        })
    });
    Ok(PlatformInfo {
        source: Source::Acpi,
        uart,
        psci,
        interrupts: interrupts_from_acpi(acpi)?,
        cpus,
        pcie,
    })
}
