//! Panic-free reader for the ACPI tables used for hardware discovery
//! (RSDP, XSDT/RSDT, SPCR, FADT, later MADT/GTDT/MCFG).
//!
//! Tables are reached through [`PhysMemory`], which only hands out memory the
//! kernel knows is mapped, so a corrupt pointer in firmware tables cannot
//! fault the kernel. Every table is checksum- and bounds-checked.

/// Read access to physical memory that is known to be mapped.
pub trait PhysMemory {
    /// `len` bytes at physical address `pa`, or `None` if not accessible.
    fn bytes(&self, pa: u64, len: usize) -> Option<&[u8]>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    Unmapped(u64),
    BadSignature,
    BadChecksum([u8; 4]),
    BadLength,
    TooOld,
}

/// Largest table accepted; real tables are a few KiB.
const MAX_TABLE: usize = 1 << 20;
const HEADER_LEN: usize = 36;

fn u8_at(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let lo = u32_at(b, off)?;
    let hi = u32_at(b, off.checked_add(4)?)?;
    Some(u64::from(lo) | (u64::from(hi) << 32))
}

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |acc, &x| acc.wrapping_add(x)) == 0
}

/// A validated system description table.
#[derive(Debug, Clone, Copy)]
pub struct Sdt<'a> {
    pub signature: [u8; 4],
    pub revision: u8,
    /// The whole table including the 36-byte header.
    pub data: &'a [u8],
}

impl<'a> Sdt<'a> {
    /// Body after the common header.
    pub fn body(&self) -> &'a [u8] {
        self.data.get(HEADER_LEN..).unwrap_or(&[])
    }
}

/// Entry point to the tables, starting from the RSDP.
pub struct Acpi<'m, M: PhysMemory> {
    mem: &'m M,
    /// (address of XSDT or RSDT, entry width in bytes)
    root: (u64, usize),
}

impl<'m, M: PhysMemory> Acpi<'m, M> {
    pub fn new(mem: &'m M, rsdp_pa: u64) -> Result<Self, AcpiError> {
        let v1 = mem.bytes(rsdp_pa, 20).ok_or(AcpiError::Unmapped(rsdp_pa))?;
        if v1.get(..8) != Some(b"RSD PTR ".as_slice()) {
            return Err(AcpiError::BadSignature);
        }
        if !checksum_ok(v1) {
            return Err(AcpiError::BadChecksum(*b"RSDP"));
        }
        let revision = u8_at(v1, 15).ok_or(AcpiError::BadLength)?;
        let root = if revision >= 2 {
            let v2 = mem.bytes(rsdp_pa, 36).ok_or(AcpiError::Unmapped(rsdp_pa))?;
            if !checksum_ok(v2) {
                return Err(AcpiError::BadChecksum(*b"RSDP"));
            }
            (u64_at(v2, 24).ok_or(AcpiError::BadLength)?, 8)
        } else {
            (u64::from(u32_at(v1, 16).ok_or(AcpiError::BadLength)?), 4)
        };
        Ok(Self { mem, root })
    }

    /// Validates and returns the table at `pa`.
    pub fn table_at(&self, pa: u64) -> Result<Sdt<'m>, AcpiError> {
        let header = self
            .mem
            .bytes(pa, HEADER_LEN)
            .ok_or(AcpiError::Unmapped(pa))?;
        let len = u32_at(header, 4).ok_or(AcpiError::BadLength)? as usize;
        if !(HEADER_LEN..=MAX_TABLE).contains(&len) {
            return Err(AcpiError::BadLength);
        }
        let data = self.mem.bytes(pa, len).ok_or(AcpiError::Unmapped(pa))?;
        let mut signature = [0u8; 4];
        signature.copy_from_slice(data.get(..4).ok_or(AcpiError::BadLength)?);
        if !checksum_ok(data) {
            return Err(AcpiError::BadChecksum(signature));
        }
        Ok(Sdt {
            signature,
            revision: u8_at(data, 8).ok_or(AcpiError::BadLength)?,
            data,
        })
    }

    /// Physical addresses listed in the XSDT/RSDT.
    pub fn table_addresses(&self) -> Result<impl Iterator<Item = u64> + 'm, AcpiError> {
        let root = self.table_at(self.root.0)?;
        let width = self.root.1;
        let body = root.body();
        Ok(body.chunks_exact(width).map(move |c| {
            if width == 8 {
                u64_at(c, 0).unwrap_or(0)
            } else {
                u64::from(u32_at(c, 0).unwrap_or(0))
            }
        }))
    }

    /// First valid table with `signature`. Invalid tables are skipped.
    pub fn find(&self, signature: &[u8; 4]) -> Result<Option<Sdt<'m>>, AcpiError> {
        for pa in self.table_addresses()? {
            if let Ok(t) = self.table_at(pa)
                && &t.signature == signature
            {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }
}

/// UART described by the SPCR table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpcrUart {
    pub interface_type: u8,
    pub base: u64,
    /// True for the PL011-compatible interface types.
    pub pl011_compatible: bool,
}

/// SPCR interface types that are register-compatible with PL011 for output.
const SPCR_PL011: u8 = 0x03;
const SPCR_SBSA_32BIT: u8 = 0x0d;
const SPCR_SBSA: u8 = 0x0e;

pub fn parse_spcr(t: &Sdt<'_>) -> Option<SpcrUart> {
    let interface_type = u8_at(t.data, 36)?;
    let space_id = u8_at(t.data, 40)?;
    if space_id != 0 {
        // Only system-memory MMIO UARTs are supported.
        return None;
    }
    let base = u64_at(t.data, 44)?;
    Some(SpcrUart {
        interface_type,
        base,
        pl011_compatible: matches!(interface_type, SPCR_PL011 | SPCR_SBSA_32BIT | SPCR_SBSA),
    })
}

/// FADT `ARM_BOOT_ARCH` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmBootArch {
    pub psci_compliant: bool,
    pub psci_use_hvc: bool,
}

pub fn parse_fadt_arm_boot_arch(t: &Sdt<'_>) -> Option<ArmBootArch> {
    let flags = u16_at(t.data, 129)?;
    Some(ArmBootArch {
        psci_compliant: flags & 1 != 0,
        psci_use_hvc: flags & 2 != 0,
    })
}

/// GIC description from the MADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MadtGic {
    pub version: u8,
    pub gicd: u64,
    /// First GICR discovery range (base, length), if the MADT has one.
    pub gicr_range: Option<(u64, u64)>,
    /// GICR base of the first GICC entry (used when no GICR range exists).
    pub gicc_gicr_base: Option<u64>,
    /// GICv2 CPU interface base of the first GICC entry.
    pub gicc_base: Option<u64>,
    /// Number of enabled GICC (CPU interface) entries.
    pub cpus: usize,
    /// GICv3 ITS base, if present.
    pub its: Option<u64>,
    /// GICv2m MSI frame (base, first SPI, SPI count), if present.
    pub msi_frame: Option<(u64, u16, u16)>,
}

const MADT_GICC: u8 = 0x0b;
const MADT_GICD: u8 = 0x0c;
const MADT_MSI_FRAME: u8 = 0x0d;
const MADT_GICR: u8 = 0x0e;
const MADT_ITS: u8 = 0x0f;
const GICC_ENABLED: u32 = 1;
const GICC_ONLINE_CAPABLE: u32 = 1 << 3;

/// Iterates MADT interrupt-controller structures as (type, bytes).
pub fn madt_entries<'a>(t: &Sdt<'a>) -> impl Iterator<Item = (u8, &'a [u8])> + 'a {
    let body = t.data.get(44..).unwrap_or(&[]);
    let mut off = 0usize;
    core::iter::from_fn(move || {
        let ty = *body.get(off)?;
        let len = usize::from(*body.get(off + 1)?);
        if len < 2 {
            return None;
        }
        let entry = body.get(off..off + len)?;
        off += len;
        Some((ty, entry))
    })
}

/// MPIDRs of the enabled (or online-capable) CPUs in the MADT, in order.
pub fn madt_cpus<'a>(t: &Sdt<'a>) -> impl Iterator<Item = u64> + 'a {
    madt_entries(t).filter_map(|(ty, e)| {
        if ty != MADT_GICC {
            return None;
        }
        let flags = u32_at(e, 12)?;
        if flags & (GICC_ENABLED | GICC_ONLINE_CAPABLE) == 0 {
            return None;
        }
        u64_at(e, 68).map(|m| m & 0xff_00ff_ffff)
    })
}

/// One PCIe ECAM region from the MCFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McfgEntry {
    pub base: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

/// Iterates the MCFG allocation entries (16 bytes each after 8 reserved).
pub fn mcfg_entries<'a>(t: &Sdt<'a>) -> impl Iterator<Item = McfgEntry> + 'a {
    t.data
        .get(44..)
        .unwrap_or(&[])
        .as_chunks::<16>()
        .0
        .iter()
        .filter_map(|c| {
            Some(McfgEntry {
                base: u64_at(c, 0)?,
                segment: u16_at(c, 8)?,
                bus_start: u8_at(c, 10)?,
                bus_end: u8_at(c, 11)?,
            })
        })
}

pub fn parse_madt(t: &Sdt<'_>) -> MadtGic {
    let mut g = MadtGic::default();
    for (ty, e) in madt_entries(t) {
        match ty {
            MADT_GICC => {
                let flags = u32_at(e, 12).unwrap_or(0);
                if flags & (GICC_ENABLED | GICC_ONLINE_CAPABLE) != 0 {
                    g.cpus += 1;
                    if g.gicc_gicr_base.is_none() {
                        g.gicc_gicr_base = u64_at(e, 60).filter(|&b| b != 0);
                    }
                    if g.gicc_base.is_none() {
                        g.gicc_base = u64_at(e, 32).filter(|&b| b != 0);
                    }
                }
            }
            MADT_GICD => {
                g.gicd = u64_at(e, 8).unwrap_or(0);
                g.version = u8_at(e, 20).unwrap_or(0);
            }
            MADT_GICR if g.gicr_range.is_none() => {
                if let (Some(b), Some(l)) = (u64_at(e, 4), u32_at(e, 12)) {
                    g.gicr_range = Some((b, u64::from(l)));
                }
            }
            MADT_ITS if g.its.is_none() => g.its = u64_at(e, 8),
            MADT_MSI_FRAME if g.msi_frame.is_none() => {
                if let (Some(b), Some(base), Some(n)) = (u64_at(e, 8), u16_at(e, 22), u16_at(e, 20))
                {
                    g.msi_frame = Some((b, base, n));
                }
            }
            _ => {}
        }
    }
    g
}

/// Generic timer interrupts (GSIVs, i.e. INTIDs) from the GTDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtdtTimers {
    pub el1_phys: u32,
    pub el1_virt: u32,
    pub el2_phys: u32,
}

pub fn parse_gtdt(t: &Sdt<'_>) -> Option<GtdtTimers> {
    Some(GtdtTimers {
        el1_phys: u32_at(t.data, 56)?,
        el1_virt: u32_at(t.data, 64)?,
        el2_phys: u32_at(t.data, 72)?,
    })
}
