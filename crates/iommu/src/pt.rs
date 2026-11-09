//! The I/O page tables: a radix tree of 4 KiB tables of 512 doublewords,
//! 3 to 5 levels, in one of three encodings. Mappings are identity (the I/O
//! virtual address is the physical address) and 4 KiB granular; nothing is
//! ever unmapped (the kernel's DMA memory lives as long as the device).

use crate::{Env, Error, PAGE};

/// The entry encoding of a unit's tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// VT-d second-level: R (bit 0) and W (bit 1) on every level.
    VtdSecondLevel,
    /// AMD-Vi v1 host tables: PR (bit 0), Next Level (11:9), IR (61), IW (62)
    /// on every level.
    AmdV1,
    /// Arm VMSAv8-64 stage 1, 4 KiB granule, MAIR index 0 normal memory and 1
    /// device memory (`smmuv3::MAIR`).
    ArmStage1,
}

/// Bits 51:12 of an entry: the next table or the page.
pub const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Access a mapping grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub write: bool,
    /// Arm only: device memory (an MSI doorbell), never cached.
    pub device: bool,
}

impl Access {
    pub const RW: Self = Self {
        write: true,
        device: false,
    };
    pub const DOORBELL: Self = Self {
        write: true,
        device: true,
    };
}

mod arm {
    pub const VALID_TABLE: u64 = 0b11;
    pub const ATTR_INDEX_SHIFT: u32 = 2;
    /// AP[1]: unprivileged access too (a PCI request may be either).
    pub const AP_EL0: u64 = 1 << 6;
    /// AP[2]: read only.
    pub const AP_RO: u64 = 1 << 7;
    pub const SH_INNER: u64 = 0b11 << 8;
    pub const AF: u64 = 1 << 10;
    pub const PXN: u64 = 1 << 53;
    pub const UXN: u64 = 1 << 54;
}

mod amd {
    pub const PR: u64 = 1;
    pub const NEXT_SHIFT: u32 = 9;
    pub const IR: u64 = 1 << 61;
    pub const IW: u64 = 1 << 62;
}

impl Format {
    /// An entry at `level` (2 or more) that points to the table at `next`.
    pub const fn table(self, next: u64, level: u8) -> u64 {
        let a = next & ADDR_MASK;
        match self {
            Self::VtdSecondLevel => a | 0b11,
            Self::AmdV1 => {
                a | amd::PR | ((level as u64 - 1) << amd::NEXT_SHIFT) | amd::IR | amd::IW
            }
            Self::ArmStage1 => a | arm::VALID_TABLE,
        }
    }

    /// A level-1 entry mapping the page at `pa`.
    pub const fn leaf(self, pa: u64, access: Access) -> u64 {
        let a = pa & ADDR_MASK;
        match self {
            Self::VtdSecondLevel => a | 1 | if access.write { 2 } else { 0 },
            Self::AmdV1 => a | amd::PR | amd::IR | if access.write { amd::IW } else { 0 },
            Self::ArmStage1 => {
                let attr = if access.device { 1 } else { 0 };
                a | arm::VALID_TABLE
                    | (attr << arm::ATTR_INDEX_SHIFT)
                    | arm::AP_EL0
                    | if access.write { 0 } else { arm::AP_RO }
                    | if access.device { 0 } else { arm::SH_INNER }
                    | arm::AF
                    | arm::PXN
                    | arm::UXN
            }
        }
    }

    pub const fn present(self, e: u64) -> bool {
        match self {
            Self::VtdSecondLevel => e & 0b11 != 0,
            Self::AmdV1 => e & amd::PR != 0,
            Self::ArmStage1 => e & 1 != 0,
        }
    }

    /// Whether a present leaf allows writes.
    pub const fn writable(self, e: u64) -> bool {
        match self {
            Self::VtdSecondLevel => e & 2 != 0,
            Self::AmdV1 => e & amd::IW != 0,
            Self::ArmStage1 => e & arm::AP_RO == 0,
        }
    }
}

/// The index into the table of `level` (1 = the leaf tables) for `iova`.
pub const fn index(iova: u64, level: u8) -> u64 {
    (iova >> (12 + 9 * (level as u32 - 1))) & 0x1ff
}

/// One domain's tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tables {
    pub root: u64,
    pub levels: u8,
    pub format: Format,
    /// Tables allocated, the root included (4 KiB each).
    pub tables: u32,
    /// Pages mapped.
    pub pages: u32,
}

impl Tables {
    /// An empty domain: nothing translates.
    pub fn new<E: Env>(env: &mut E, levels: u8, format: Format) -> Result<Self, Error> {
        if !(3..=5).contains(&levels) {
            return Err(Error::Unsupported("page-table depth"));
        }
        let root = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        env.flush(root, PAGE as usize);
        Ok(Self {
            root,
            levels,
            format,
            tables: 1,
            pages: 0,
        })
    }

    /// The bits of address the tables translate.
    pub const fn address_bits(&self) -> u32 {
        12 + 9 * self.levels as u32
    }

    /// Maps `[pa, pa + len)` (rounded out to pages) at the same I/O virtual
    /// address. A page already mapped is mapped again with `access`.
    pub fn map<E: Env>(
        &mut self,
        env: &mut E,
        pa: u64,
        len: u64,
        access: Access,
    ) -> Result<(), Error> {
        if len == 0 {
            return Ok(());
        }
        let first = pa & !(PAGE - 1);
        let end = pa.checked_add(len).ok_or(Error::AddressTooWide)?;
        if end > (1u64 << self.address_bits()) || end > ADDR_MASK + PAGE {
            return Err(Error::AddressTooWide);
        }
        let mut page = first;
        while page < end {
            self.map_page(env, page, access)?;
            page += PAGE;
        }
        Ok(())
    }

    fn map_page<E: Env>(&mut self, env: &mut E, iova: u64, access: Access) -> Result<(), Error> {
        let mut table = self.root;
        let mut level = self.levels;
        while level > 1 {
            let slot = table + 8 * index(iova, level);
            let e = env.read(slot);
            table = if self.format.present(e) {
                e & ADDR_MASK
            } else {
                let next = env.alloc(1, 1).ok_or(Error::NoMemory)?;
                env.flush(next, PAGE as usize);
                self.tables += 1;
                env.write(slot, self.format.table(next, level));
                env.flush(slot, 8);
                next
            };
            level -= 1;
        }
        let slot = table + 8 * index(iova, 1);
        if !self.format.present(env.read(slot)) {
            self.pages += 1;
        }
        env.write(slot, self.format.leaf(iova, access));
        env.flush(slot, 8);
        Ok(())
    }

    /// Walks the tables as the unit would: the physical address `iova`
    /// reaches and whether it may be written, or `None` (a fault).
    pub fn translate<E: Env>(&self, env: &E, iova: u64) -> Option<(u64, bool)> {
        if iova >> self.address_bits() != 0 {
            return None;
        }
        let mut table = self.root;
        let mut level = self.levels;
        loop {
            let e = env.read(table + 8 * index(iova, level));
            if !self.format.present(e) {
                return None;
            }
            if level == 1 {
                return Some((
                    (e & ADDR_MASK) | (iova & (PAGE - 1)),
                    self.format.writable(e),
                ));
            }
            table = e & ADDR_MASK;
            level -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mem;

    #[test]
    fn maps_exactly_the_pages_asked_for() {
        for format in [Format::VtdSecondLevel, Format::AmdV1, Format::ArmStage1] {
            for levels in [3u8, 4] {
                let mut m = Mem::default();
                let mut t = Tables::new(&mut m, levels, format).unwrap();
                // Two pages straddling a 2 MiB boundary, starting mid-page.
                t.map(&mut m, 0x1f_f800, 0x1000, Access::RW).unwrap();
                assert_eq!(t.pages, 2);
                assert_eq!(t.translate(&m, 0x1f_f000), Some((0x1f_f000, true)));
                assert_eq!(t.translate(&m, 0x20_0abc), Some((0x20_0abc, true)));
                assert_eq!(t.translate(&m, 0x20_1000), None);
                assert_eq!(t.translate(&m, 0x1f_e000), None);
                assert_eq!(t.translate(&m, 0), None);
                // Mapping again is idempotent.
                t.map(&mut m, 0x1f_f000, 0x2000, Access::RW).unwrap();
                assert_eq!(t.pages, 2);
                // Out of the address width.
                assert_eq!(
                    t.map(&mut m, 1u64 << t.address_bits(), 1, Access::RW),
                    Err(Error::AddressTooWide)
                );
                assert_eq!(t.translate(&m, 1u64 << t.address_bits()), None);
            }
        }
    }

    #[test]
    fn read_only_and_device_leaves() {
        let f = Format::ArmStage1;
        let ro = f.leaf(
            0x5000,
            Access {
                write: false,
                device: false,
            },
        );
        assert!(f.present(ro) && !f.writable(ro));
        let db = f.leaf(0x0809_0000, Access::DOORBELL);
        assert_eq!((db >> 2) & 7, 1, "MAIR index 1 (device)");
        assert_eq!(db & (1 << 10), 1 << 10, "access flag");
        assert_eq!(db & (3 << 53), 3 << 53, "never executable");
        assert!(
            !Format::VtdSecondLevel.writable(Format::VtdSecondLevel.leaf(
                0,
                Access {
                    write: false,
                    device: false
                }
            ))
        );
        // AMD-Vi tables say the next level in every directory entry.
        assert_eq!((Format::AmdV1.table(0x1000, 4) >> 9) & 7, 3);
        assert_eq!((Format::AmdV1.leaf(0x1000, Access::RW) >> 9) & 7, 0);
    }

    #[test]
    fn depth_is_bounded() {
        let mut m = Mem::default();
        assert!(Tables::new(&mut m, 2, Format::AmdV1).is_err());
        assert!(Tables::new(&mut m, 6, Format::AmdV1).is_err());
    }
}
