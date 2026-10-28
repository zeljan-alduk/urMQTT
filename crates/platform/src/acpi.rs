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
