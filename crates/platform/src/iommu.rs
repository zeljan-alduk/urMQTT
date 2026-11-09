//! IOMMU discovery (H4b, ADR-305): Intel VT-d from the ACPI DMAR table, AMD-Vi
//! from IVRS, Arm SMMUv3 from IORT or the device tree (`arm,smmu-v3` and the
//! PCIe host's `iommu-map`).
//!
//! The result is plain data: the units (register base, PCI segment) and which
//! PCI requester IDs each one translates, with the ID the unit sees for them
//! (the stream ID of an SMMU, the device ID of AMD-Vi, the requester ID itself
//! for VT-d). Firmware tables are untrusted-format input: every parser is
//! bounds-checked and panic-free, and whatever it cannot represent (a device
//! scope behind a bridge, an ACPI namespace device, a variable-length IVRS
//! entry it does not know) is counted in `unsupported`, never guessed at.
//! Reserved regions the firmware asks to keep mapped (VT-d RMRR, AMD IVMD, Arm
//! RMR) are counted, not honoured: the kernel drives only virtio devices, which
//! have none (the kernel logs the count).

use crate::acpi::{Sdt, u8_at, u16_at, u32_at, u64_at};
use crate::fdt::{self, Fdt, FdtError, Visit};
use crate::x86::FixedVec;

/// Most IOMMU units described (further ones are counted in `dropped`).
pub const MAX_UNITS: usize = 4;
/// Most requester-ID ranges per unit.
pub const MAX_RANGES: usize = 32;

/// The kind of an IOMMU unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    /// Intel VT-d DMA remapping hardware unit (DMAR DRHD).
    #[default]
    VtD,
    /// AMD-Vi (IVRS IVHD).
    AmdVi,
    /// Arm SMMUv3 (IORT node type 4, or `arm,smmu-v3`).
    SmmuV3,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::VtD => "VT-d",
            Self::AmdVi => "AMD-Vi",
            Self::SmmuV3 => "SMMUv3",
        }
    }
}

/// `count` requester IDs from `first` reach the unit as `out_base + (rid - first)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IdRange {
    pub first: u16,
    /// 1..=65536.
    pub count: u32,
    pub out_base: u32,
    /// Every ID of the range reaches the unit as `out_base` (an IVRS alias).
    pub alias: bool,
}

impl IdRange {
    /// The ID the unit sees for `rid`, if `rid` is in the range.
    pub fn translate(&self, rid: u16) -> Option<u32> {
        let off = u32::from(rid).checked_sub(u32::from(self.first))?;
        (off < self.count).then(|| {
            if self.alias {
                self.out_base
            } else {
                self.out_base.wrapping_add(off)
            }
        })
    }
}

/// One IOMMU unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Unit {
    pub kind: Kind,
    /// Physical address of the register frame.
    pub base: u64,
    pub segment: u16,
    /// Translates every requester ID of its segment not claimed by another
    /// unit (VT-d `INCLUDE_PCI_ALL`, IVRS "all"), identity IDs.
    pub all: bool,
    pub ranges: FixedVec<IdRange, MAX_RANGES>,
    /// The firmware says the unit's table walks are cache coherent (IORT
    /// COHACC override, `dma-coherent`); VT-d and AMD-Vi report it in their
    /// registers.
    pub coherent: bool,
    /// AMD-Vi: the IOMMU's own PCI function (bus, device, function).
    pub self_id: u16,
    /// Scope entries that could not be represented (bridges, namespace
    /// devices, unknown entry types): the devices they name are treated as
    /// not translated.
    pub unsupported: u16,
}

impl Unit {
    /// The ID this unit sees for `rid` through an explicit range.
    pub fn explicit(&self, rid: u16) -> Option<u32> {
        self.ranges.as_slice().iter().find_map(|r| r.translate(rid))
    }
}

/// Everything the firmware says about IOMMUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IommuInfo {
    pub units: FixedVec<Unit, MAX_UNITS>,
    /// VT-d RMRR, AMD-Vi IVMD and Arm RMR entries (not honoured, counted).
    pub reserved_regions: u16,
    /// VT-d: host address width (DMAR `HAW + 1`), 0 elsewhere.
    pub address_bits: u8,
    /// VT-d: DMAR flags (bit 0 interrupt remapping, 1 x2APIC opt-out, 2 DMA
    /// control opt-in).
    pub dmar_flags: u8,
    /// Root complexes whose devices reach no IOMMU (IORT mappings that go
    /// straight to an ITS group, a PCIe host without `iommu-map`).
    pub untranslated_hosts: u16,
}

impl IommuInfo {
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// The unit that translates PCI function `rid` of `segment` and the ID it
    /// sees: an explicit scope first, then a unit that takes all the rest.
    pub fn unit_for(&self, segment: u16, rid: u16) -> Option<(usize, u32)> {
        let units = self.units.as_slice();
        let seg = |u: &&Unit| u.segment == segment;
        units
            .iter()
            .enumerate()
            .filter(|(_, u)| seg(u))
            .find_map(|(i, u)| u.explicit(rid).map(|id| (i, id)))
            .or_else(|| {
                units
                    .iter()
                    .enumerate()
                    .find(|(_, u)| seg(u) && u.all)
                    .map(|(i, _)| (i, u32::from(rid)))
            })
    }

    /// Adds `u`, or merges it into a unit already listed at the same
    /// address (IVRS lists one IOMMU in several IVHD types).
    fn add(&mut self, u: Unit) {
        if self.units.as_slice().iter().any(|o| o.base == u.base) {
            return;
        }
        self.units.push(u);
    }
}

const HDR: usize = 36;

fn rid(bus: u8, dev: u8, func: u8) -> u16 {
    (u16::from(bus) << 8) | (u16::from(dev & 0x1f) << 3) | u16::from(func & 7)
}

/// Iterates `(type, bytes)` of a list of structures with a u16 type and u16
/// length at offsets 0 and 2 (DMAR), stopping at the first malformed one.
fn dmar_structs(b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut off = 0usize;
    core::iter::from_fn(move || {
        let ty = u16_at(b, off)?;
        let len = usize::from(u16_at(b, off + 2)?);
        if len < 4 {
            return None;
        }
        let s = b.get(off..off.checked_add(len)?)?;
        off += len;
        Some((ty, s))
    })
}

/// DMAR (VT-d): DRHD units with their device scopes; RMRRs counted.
pub fn parse_dmar(t: &Sdt<'_>) -> IommuInfo {
    let mut info = IommuInfo::default();
    let d = t.data;
    info.address_bits = u8_at(d, HDR).map_or(0, |h| h.saturating_add(1));
    info.dmar_flags = u8_at(d, HDR + 1).unwrap_or(0);
    for (ty, s) in dmar_structs(d.get(48..).unwrap_or(&[])) {
        match ty {
            0 => {
                let (Some(flags), Some(segment), Some(base)) =
                    (u8_at(s, 4), u16_at(s, 6), u64_at(s, 8))
                else {
                    continue;
                };
                let mut u = Unit {
                    kind: Kind::VtD,
                    base,
                    segment,
                    all: flags & 1 != 0,
                    ..Unit::default()
                };
                dmar_scopes(s.get(16..).unwrap_or(&[]), &mut u);
                info.add(u);
            }
            1 => info.reserved_regions = info.reserved_regions.saturating_add(1),
            _ => {}
        }
    }
    info
}

/// DRHD device scopes: a PCI endpoint directly on its start bus becomes a
/// one-ID range; everything else that is a DMA master (a bridge's
/// sub-hierarchy, a longer path, a namespace device) is counted.
fn dmar_scopes(mut b: &[u8], u: &mut Unit) {
    while let (Some(ty), Some(len)) = (u8_at(b, 0), u8_at(b, 1)) {
        let len = usize::from(len);
        let Some(s) = b.get(..len).filter(|_| len >= 6) else {
            u.unsupported = u.unsupported.saturating_add(1);
            return;
        };
        b = b.get(len..).unwrap_or(&[]);
        match ty {
            // I/O APIC and HPET: interrupt sources, not DMA masters we drive.
            3 | 4 => {}
            1 if len == 8 => {
                let (Some(bus), Some(dev), Some(func)) = (u8_at(s, 5), u8_at(s, 6), u8_at(s, 7))
                else {
                    continue;
                };
                let r = rid(bus, dev, func);
                u.ranges.push(IdRange {
                    first: r,
                    count: 1,
                    out_base: u32::from(r),
                    alias: false,
                });
            }
            _ => u.unsupported = u.unsupported.saturating_add(1),
        }
    }
}

/// IVRS (AMD-Vi): IVHD blocks (types 0x10, 0x11, 0x40) with their device
/// entries; IVMD blocks (0x20 to 0x22) counted.
pub fn parse_ivrs(t: &Sdt<'_>) -> IommuInfo {
    let mut info = IommuInfo::default();
    let mut b = t.data.get(48..).unwrap_or(&[]);
    while let (Some(ty), Some(len)) = (u8_at(b, 0), u16_at(b, 2)) {
        let len = usize::from(len);
        let Some(block) = b.get(..len).filter(|_| len >= 4) else {
            break;
        };
        b = b.get(len..).unwrap_or(&[]);
        match ty {
            0x10 | 0x11 | 0x40 => {
                let (Some(self_id), Some(base), Some(segment)) =
                    (u16_at(block, 4), u64_at(block, 8), u16_at(block, 16))
                else {
                    continue;
                };
                let mut u = Unit {
                    kind: Kind::AmdVi,
                    base,
                    segment,
                    self_id,
                    ..Unit::default()
                };
                let start = if ty == 0x10 { 24 } else { 40 };
                ivhd_entries(block.get(start..).unwrap_or(&[]), &mut u);
                info.add(u);
            }
            0x20..=0x22 => info.reserved_regions = info.reserved_regions.saturating_add(1),
            _ => {}
        }
    }
    info
}

fn ivhd_entries(mut b: &[u8], u: &mut Unit) {
    // An open range: (first device ID, alias or None).
    let mut open: Option<(u16, Option<u16>)> = None;
    while let Some(ty) = u8_at(b, 0) {
        let len = match ty {
            0..=63 => 4,
            64..=127 => 8,
            0xf0 => match u8_at(b, 21) {
                Some(uid) => 22 + usize::from(uid),
                None => break,
            },
            _ => {
                // Variable length we do not know: nothing after it can be read.
                u.unsupported = u.unsupported.saturating_add(1);
                return;
            }
        };
        let Some(e) = b.get(..len) else {
            u.unsupported = u.unsupported.saturating_add(1);
            return;
        };
        b = b.get(len..).unwrap_or(&[]);
        let id = u16_at(e, 1).unwrap_or(0);
        let one = |u: &mut Unit, first: u16, out: u16| {
            u.ranges.push(IdRange {
                first,
                count: 1,
                out_base: u32::from(out),
                alias: false,
            });
        };
        match ty {
            0 => {}
            1 => u.all = true,
            2 | 0x46 => one(u, id, id),
            3 | 0x47 => open = Some((id, None)),
            0x42 => one(u, id, u16_at(e, 5).unwrap_or(id)),
            0x43 => open = Some((id, Some(u16_at(e, 5).unwrap_or(id)))),
            4 => match open.take() {
                Some((first, alias)) if id >= first => {
                    // An alias range: every device in it uses the alias's ID.
                    u.ranges.push(IdRange {
                        first,
                        count: u32::from(id - first) + 1,
                        out_base: u32::from(alias.unwrap_or(first)),
                        alias: alias.is_some(),
                    });
                }
                _ => u.unsupported = u.unsupported.saturating_add(1),
            },
            // Special devices (I/O APIC, HPET) and ACPI namespace devices.
            0x48 => {}
            _ => u.unsupported = u.unsupported.saturating_add(1),
        }
    }
}

/// IORT node types.
const IORT_ITS: u8 = 0;
const IORT_RC: u8 = 2;
const IORT_SMMUV3: u8 = 4;
const IORT_RMR: u8 = 6;

/// IORT (Arm): SMMUv3 nodes and the root-complex ID mappings that lead to
/// them. A root complex mapping straight to an ITS group means its devices are
/// not translated (counted in `untranslated_hosts`).
pub fn parse_iort(t: &Sdt<'_>) -> IommuInfo {
    let mut info = IommuInfo::default();
    let d = t.data;
    let (Some(count), Some(first)) = (u32_at(d, HDR), u32_at(d, HDR + 4)) else {
        return info;
    };
    let node = |off: usize| -> Option<(u8, &[u8])> {
        let ty = u8_at(d, off)?;
        let len = usize::from(u16_at(d, off + 1)?);
        (len >= 16).then_some(())?;
        Some((ty, d.get(off..off.checked_add(len)?)?))
    };
    // Pass 1: SMMUv3 nodes, by offset.
    let mut smmus: FixedVec<(u32, usize), MAX_UNITS> = FixedVec::default();
    let mut off = first as usize;
    for _ in 0..count.min(256) {
        let Some((ty, n)) = node(off) else { break };
        match ty {
            IORT_SMMUV3 => {
                if let (Some(base), Some(flags)) = (u64_at(n, 16), u32_at(n, 24)) {
                    let before = info.units.len();
                    info.add(Unit {
                        kind: Kind::SmmuV3,
                        base,
                        coherent: flags & 1 != 0,
                        ..Unit::default()
                    });
                    if info.units.len() > before {
                        smmus.push((off as u32, before));
                    }
                }
            }
            IORT_RMR => info.reserved_regions = info.reserved_regions.saturating_add(1),
            _ => {}
        }
        off += n.len();
    }
    // Pass 2: root complexes and their ID mappings.
    let mut off = first as usize;
    for _ in 0..count.min(256) {
        let Some((ty, n)) = node(off) else { break };
        off += n.len();
        if ty != IORT_RC {
            continue;
        }
        let segment = u32_at(n, 28).unwrap_or(0) as u16;
        let (Some(maps), Some(at)) = (u32_at(n, 8), u32_at(n, 12)) else {
            continue;
        };
        let mut translated = false;
        let mut untranslated = false;
        for i in 0..maps.min(64) as usize {
            let m = at as usize + i * 20;
            let (Some(input), Some(num), Some(output), Some(target), Some(flags)) = (
                u32_at(n, m),
                u32_at(n, m + 4),
                u32_at(n, m + 8),
                u32_at(n, m + 12),
                u32_at(n, m + 16),
            ) else {
                break;
            };
            let target_type = node(target as usize).map(|(t, _)| t);
            match smmus.as_slice().iter().find(|(o, _)| *o == target) {
                Some((_, idx)) if flags & 1 == 0 && input <= 0xffff => {
                    translated = true;
                    if let Some(u) = info.units.as_mut_slice().get_mut(*idx) {
                        u.segment = segment;
                        let count = num.saturating_add(1).min(0x1_0000 - input);
                        u.ranges.push(IdRange {
                            first: input as u16,
                            count,
                            out_base: output,
                            alias: false,
                        });
                    }
                }
                Some((_, idx)) => {
                    if let Some(u) = info.units.as_mut_slice().get_mut(*idx) {
                        u.unsupported = u.unsupported.saturating_add(1);
                    }
                }
                None if target_type == Some(IORT_ITS) => untranslated = true,
                None => {}
            }
        }
        if untranslated || !translated {
            info.untranslated_hosts = info.untranslated_hosts.saturating_add(1);
        }
    }
    info
}

/// Device tree: every `arm,smmu-v3` node, and the `iommu-map` of the
/// generic PCIe host (`<rid-base &iommu iommu-base length>`, one IOMMU cell).
pub fn from_fdt(f: &Fdt<'_>) -> Result<IommuInfo, FdtError> {
    let mut info = IommuInfo::default();
    let mut phandles: FixedVec<(u32, usize), MAX_UNITS> = FixedVec::default();
    let mut err = None;
    f.for_each_node(|n| {
        match (|| -> Result<(), FdtError> {
            if !n.is_compatible("arm,smmu-v3")? {
                return Ok(());
            }
            let Some((base, _)) = n.reg(0)? else {
                return Ok(());
            };
            let before = info.units.len();
            info.add(Unit {
                kind: Kind::SmmuV3,
                base,
                coherent: n.prop("dma-coherent")?.is_some(),
                ..Unit::default()
            });
            if info.units.len() > before
                && let Some(p) = n.prop_u32("phandle")?
            {
                phandles.push((p, before));
            }
            Ok(())
        })() {
            Ok(()) => Visit::Continue,
            Err(e) => {
                err = Some(e);
                Visit::Stop
            }
        }
    })?;
    if let Some(e) = err {
        return Err(e);
    }
    if info.units.is_empty() {
        return Ok(info);
    }
    let Some(host) = f.find_compatible("pci-host-ecam-generic")? else {
        return Ok(info);
    };
    let segment = host.prop_u32("linux,pci-domain")?.unwrap_or(0) as u16;
    let map = host.prop("iommu-map")?.unwrap_or(&[]);
    let mut translated = false;
    for e in map.as_chunks::<16>().0 {
        let rid_base = fdt::read_cells(e, 0, 1) as u32;
        let ph = fdt::read_cells(e, 4, 1) as u32;
        let out = fdt::read_cells(e, 8, 1) as u32;
        let len = fdt::read_cells(e, 12, 1) as u32;
        let Some((_, idx)) = phandles.as_slice().iter().find(|(p, _)| *p == ph) else {
            continue;
        };
        if rid_base > 0xffff || len == 0 {
            continue;
        }
        if let Some(u) = info.units.as_mut_slice().get_mut(*idx) {
            translated = true;
            u.segment = segment;
            u.ranges.push(IdRange {
                first: rid_base as u16,
                count: len.min(0x1_0000 - rid_base),
                out_base: out,
                alias: false,
            });
        }
    }
    if !translated {
        info.untranslated_hosts = 1;
    }
    Ok(info)
}

impl core::fmt::Display for IommuInfo {
    /// `VT-d@0xfed90000/0:all haw=48 reserved=0` per unit.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.units.is_empty() {
            return f.write_str("none");
        }
        for (i, u) in self.units.as_slice().iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{}@{:#x}/{}:", u.kind.name(), u.base, u.segment)?;
            if u.all {
                f.write_str("all")?;
            }
            for (j, r) in u.ranges.as_slice().iter().enumerate() {
                if j > 0 || u.all {
                    f.write_str(",")?;
                }
                write!(f, "{:#x}+{}->{:#x}", r.first, r.count, r.out_base)?;
            }
            if u.ranges.dropped > 0 || u.unsupported > 0 {
                write!(
                    f,
                    "(+{} not representable)",
                    u.ranges.dropped + usize::from(u.unsupported)
                )?;
            }
        }
        if self.units.dropped > 0 {
            write!(f, " +{} unit(s) not used", self.units.dropped)?;
        }
        if self.address_bits > 0 {
            write!(f, " haw={}", self.address_bits)?;
        }
        write!(f, " reserved={}", self.reserved_regions)?;
        if self.untranslated_hosts > 0 {
            write!(f, " untranslated-hosts={}", self.untranslated_hosts)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "iommu_tests.rs"]
mod tests;
