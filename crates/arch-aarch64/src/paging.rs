//! Stage-1 translation tables, 4 KiB granule, 48-bit VA (4 levels).
//!
//! Descriptor encoding and table walking are pure logic over a
//! [`TableMemory`] abstraction so they can be tested on the host; the kernel
//! supplies an implementation that reaches table frames through the HHDM.

/// Size of a translation granule / page.
pub const PAGE_SIZE: u64 = 4096;
/// Entries per table.
pub const ENTRIES: usize = 512;

const VALID: u64 = 1 << 0;
const TABLE_OR_PAGE: u64 = 1 << 1;
const ATTR_INDX_SHIFT: u64 = 2;
const AP_RO: u64 = 1 << 7; // AP[2]: read-only
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const GP: u64 = 1 << 50; // BTI guarded page
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

/// `MAIR_EL1` attribute indices used by the kernel.
///
/// Index 0 and 1 match what Limine guarantees for base revision >= 4
/// (normal write-back, framebuffer); 2..4 are claimed by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemType {
    /// Normal, inner/outer write-back read/write-allocate (`0xff`).
    Normal = 0,
    /// Framebuffer caching chosen by the bootloader.
    Framebuffer = 1,
    /// Device-nGnRE (`0x04`), for MMIO.
    Device = 2,
    /// Device-nGnRnE (`0x00`), strongest ordering.
    DeviceStrict = 3,
    /// Normal non-cacheable (`0x44`).
    NonCacheable = 4,
}

impl MemType {
    /// The `MAIR_EL1` byte for each index the kernel owns.
    pub const MAIR_DEVICE: u64 = 0x04;
    pub const MAIR_DEVICE_STRICT: u64 = 0x00;
    pub const MAIR_NON_CACHEABLE: u64 = 0x44;
    pub const MAIR_NORMAL_WB: u64 = 0xff;

    /// Returns `mair` with indices 2..=4 set to the kernel's attributes,
    /// keeping indices 0 and 1 (owned by the bootloader) untouched.
    pub const fn merge_into_mair(mair: u64) -> u64 {
        let keep = mair & 0xffff;
        keep | (Self::MAIR_DEVICE << 16)
            | (Self::MAIR_DEVICE_STRICT << 24)
            | (Self::MAIR_NON_CACHEABLE << 32)
    }
}

/// Access permissions for a kernel mapping. EL0 never has access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read + execute (kernel text). Never writable.
    ReadExecute,
    /// Read only, never executable.
    ReadOnly,
    /// Read + write, never executable.
    ReadWrite,
}

/// Attributes of a leaf mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageAttrs {
    pub access: Access,
    pub mem: MemType,
    /// Mark executable pages as BTI-guarded (only meaningful with FEAT_BTI).
    pub bti_guarded: bool,
}

impl PageAttrs {
    pub const fn mmio() -> Self {
        Self {
            access: Access::ReadWrite,
            mem: MemType::Device,
            bti_guarded: false,
        }
    }

    pub const fn data() -> Self {
        Self {
            access: Access::ReadWrite,
            mem: MemType::Normal,
            bti_guarded: false,
        }
    }

    pub const fn rodata() -> Self {
        Self {
            access: Access::ReadOnly,
            mem: MemType::Normal,
            bti_guarded: false,
        }
    }

    pub const fn text(bti: bool) -> Self {
        Self {
            access: Access::ReadExecute,
            mem: MemType::Normal,
            bti_guarded: bti,
        }
    }
}

/// Encodes a level-3 page descriptor. W^X holds by construction: there is
/// no attribute combination that is both writable and executable.
pub const fn page_descriptor(pa: u64, attrs: PageAttrs) -> u64 {
    let mut d = (pa & ADDR_MASK) | VALID | TABLE_OR_PAGE | AF | UXN;
    d |= (attrs.mem as u64) << ATTR_INDX_SHIFT;
    if !matches!(attrs.mem, MemType::Device | MemType::DeviceStrict) {
        d |= SH_INNER;
    }
    match attrs.access {
        Access::ReadExecute => {
            d |= AP_RO;
            if attrs.bti_guarded {
                d |= GP;
            }
        }
        Access::ReadOnly => d |= AP_RO | PXN,
        Access::ReadWrite => d |= PXN,
    }
    d
}

/// Size of a level-2 block mapping.
pub const BLOCK_2M: u64 = 2 << 20;

/// Encodes a level-2 (2 MiB) block descriptor with the same attributes as
/// [`page_descriptor`].
pub const fn block_descriptor(pa: u64, attrs: PageAttrs) -> u64 {
    (page_descriptor(0, attrs) & !TABLE_OR_PAGE) | (pa & ADDR_MASK & !(BLOCK_2M - 1))
}

/// Encodes a table descriptor pointing at the next-level table.
pub const fn table_descriptor(table_pa: u64) -> u64 {
    (table_pa & ADDR_MASK) | VALID | TABLE_OR_PAGE
}

/// Decoded view of a leaf descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    pub pa: u64,
    pub writable: bool,
    pub executable: bool,
    pub attr_index: u8,
}

impl Leaf {
    pub const fn decode(desc: u64) -> Self {
        Self {
            pa: desc & ADDR_MASK,
            writable: desc & AP_RO == 0,
            executable: desc & PXN == 0,
            attr_index: ((desc >> ATTR_INDX_SHIFT) & 0b111) as u8,
        }
    }
}

/// Index into the table at `level` (0..=3) for `va`.
pub const fn index(va: u64, level: u8) -> usize {
    let shift = 39 - 9 * (level as u64);
    ((va >> shift) & 0x1ff) as usize
}

/// Access to translation-table frames by physical address.
pub trait TableMemory {
    fn read(&self, table_pa: u64, idx: usize) -> u64;
    fn write(&mut self, table_pa: u64, idx: usize, value: u64);
}

/// Source of zeroed frames for new tables.
pub trait FrameSource {
    /// Physical address of a fresh, page-aligned frame, or `None` if exhausted.
    fn alloc_frame(&mut self) -> Option<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Address not page aligned.
    Unaligned,
    /// Virtual address is not canonical for a 48-bit address space.
    NonCanonical,
    /// A different mapping already exists at this address.
    AlreadyMapped,
    /// A block mapping at a higher level covers this address.
    BlockInTheWay,
    /// No frame available for an intermediate table.
    OutOfFrames,
}

/// With 48-bit regions (T0SZ = T1SZ = 16), TTBR0 covers addresses whose top
/// 16 bits are zero and TTBR1 those whose top 16 bits are all ones.
const fn is_canonical(va: u64) -> bool {
    let top = va >> 48;
    top == 0 || top == 0xffff
}

/// Walks and edits one translation regime rooted at `root` (TTBRn base).
pub struct Mapper<'m, M: TableMemory> {
    mem: &'m mut M,
    root: u64,
}

impl<'m, M: TableMemory> Mapper<'m, M> {
    pub fn new(mem: &'m mut M, root: u64) -> Self {
        Self { mem, root }
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    /// Maps one 4 KiB page. Remapping to the identical descriptor is a no-op.
    pub fn map_page<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        if !va.is_multiple_of(PAGE_SIZE) || !pa.is_multiple_of(PAGE_SIZE) {
            return Err(MapError::Unaligned);
        }
        if !is_canonical(va) {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in 0..3u8 {
            table = self.next_table(table, index(va, level), frames)?;
        }
        let idx = index(va, 3);
        let new = page_descriptor(pa, attrs);
        let old = self.mem.read(table, idx);
        if old & VALID != 0 {
            return if old == new {
                Ok(())
            } else {
                Err(MapError::AlreadyMapped)
            };
        }
        self.mem.write(table, idx, new);
        Ok(())
    }

    /// Maps `len` bytes starting at `va`/`pa` (both rounded to pages).
    pub fn map_range<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        len: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        let pages = len.div_ceil(PAGE_SIZE);
        for i in 0..pages {
            let off = i * PAGE_SIZE;
            self.map_page(va + off, pa + off, attrs, frames)?;
        }
        Ok(())
    }

    /// Maps one 2 MiB block at level 2.
    pub fn map_block_2m<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        if !va.is_multiple_of(BLOCK_2M) || !pa.is_multiple_of(BLOCK_2M) {
            return Err(MapError::Unaligned);
        }
        if !is_canonical(va) {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in 0..2u8 {
            table = self.next_table(table, index(va, level), frames)?;
        }
        let idx = index(va, 2);
        let new = block_descriptor(pa, attrs);
        let old = self.mem.read(table, idx);
        if old & VALID != 0 {
            return if old == new {
                Ok(())
            } else {
                Err(MapError::AlreadyMapped)
            };
        }
        self.mem.write(table, idx, new);
        Ok(())
    }

    /// Like [`map_range`](Self::map_range) but uses 2 MiB blocks wherever
    /// both addresses are block aligned and a whole block remains.
    pub fn map_range_auto<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        len: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        let end = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let mut off = 0;
        while off < end {
            let (v, p) = (va + off, pa + off);
            if v.is_multiple_of(BLOCK_2M) && p.is_multiple_of(BLOCK_2M) && end - off >= BLOCK_2M {
                self.map_block_2m(v, p, attrs, frames)?;
                off += BLOCK_2M;
            } else {
                self.map_page(v, p, attrs, frames)?;
                off += PAGE_SIZE;
            }
        }
        Ok(())
    }

    fn next_table<F: FrameSource>(
        &mut self,
        table: u64,
        idx: usize,
        frames: &mut F,
    ) -> Result<u64, MapError> {
        let desc = self.mem.read(table, idx);
        if desc & VALID == 0 {
            let new = frames.alloc_frame().ok_or(MapError::OutOfFrames)?;
            for i in 0..ENTRIES {
                self.mem.write(new, i, 0);
            }
            self.mem.write(table, idx, table_descriptor(new));
            Ok(new)
        } else if desc & TABLE_OR_PAGE == 0 {
            Err(MapError::BlockInTheWay)
        } else {
            Ok(desc & ADDR_MASK)
        }
    }

    /// Changes the access permissions of an existing 4 KiB page, keeping
    /// its address and memory type. Used to make page tables read-only.
    pub fn set_page_access(&mut self, va: u64, access: Access) -> Result<(), MapError> {
        let mut table = self.root;
        for level in 0..3u8 {
            let desc = self.mem.read(table, index(va, level));
            if desc & VALID == 0 || desc & TABLE_OR_PAGE == 0 {
                return Err(MapError::BlockInTheWay);
            }
            table = desc & ADDR_MASK;
        }
        let idx = index(va, 3);
        let old = self.mem.read(table, idx);
        if old & VALID == 0 {
            return Err(MapError::BlockInTheWay);
        }
        let attrs = PageAttrs {
            access,
            mem: match Leaf::decode(old).attr_index {
                1 => MemType::Framebuffer,
                2 => MemType::Device,
                3 => MemType::DeviceStrict,
                4 => MemType::NonCacheable,
                _ => MemType::Normal,
            },
            bti_guarded: old & GP != 0,
        };
        self.mem
            .write(table, idx, page_descriptor(old & ADDR_MASK, attrs));
        Ok(())
    }

    /// Calls `f(va, descriptor, level)` for every valid leaf. `upper` selects
    /// how VAs are formed (TTBR1 upper half vs TTBR0 lower half).
    pub fn for_each_leaf<G: FnMut(u64, u64, u8)>(&self, upper: bool, mut f: G) {
        self.walk(
            self.root,
            0,
            if upper { 0xffff_0000_0000_0000 } else { 0 },
            &mut f,
        );
    }

    fn walk<G: FnMut(u64, u64, u8)>(&self, table: u64, level: u8, va_base: u64, f: &mut G) {
        let shift = 39 - 9 * u64::from(level);
        for i in 0..ENTRIES {
            let desc = self.mem.read(table, i);
            if desc & VALID == 0 {
                continue;
            }
            let va = va_base | ((i as u64) << shift);
            if level == 3 || desc & TABLE_OR_PAGE == 0 {
                f(va, desc, level);
            } else {
                self.walk(desc & ADDR_MASK, level + 1, va, f);
            }
        }
    }

    /// Translates `va` through the tables: the leaf descriptor and the level
    /// it was found at (1 or 2 for blocks, 3 for pages).
    pub fn lookup(&self, va: u64) -> Option<(u64, u8)> {
        if !is_canonical(va) {
            return None;
        }
        let mut table = self.root;
        for level in 0..4u8 {
            let desc = self.mem.read(table, index(va, level));
            if desc & VALID == 0 {
                return None;
            }
            let is_leaf = level == 3 || desc & TABLE_OR_PAGE == 0;
            if is_leaf {
                return Some((desc, level));
            }
            table = desc & ADDR_MASK;
        }
        None
    }

    /// Physical address of the table consulted at `level` (0 = root) when
    /// translating `va`, if the walk reaches that level.
    pub fn table_at_level(&self, va: u64, level: u8) -> Option<u64> {
        let mut table = self.root;
        for l in 0..level {
            let desc = self.mem.read(table, index(va, l));
            if desc & VALID == 0 || desc & TABLE_OR_PAGE == 0 {
                return None;
            }
            table = desc & ADDR_MASK;
        }
        Some(table)
    }

    /// Physical address `va` maps to, if any.
    pub fn translate(&self, va: u64) -> Option<u64> {
        let (desc, level) = self.lookup(va)?;
        let block = match level {
            1 => 1u64 << 30,
            2 => 1u64 << 21,
            _ => PAGE_SIZE,
        };
        Some((desc & ADDR_MASK & !(block - 1)) | (va & (block - 1)))
    }

    /// Index of the first unused level-0 entry in `range`, if any.
    pub fn free_l0_slot(&self, range: core::ops::Range<usize>) -> Option<usize> {
        range
            .into_iter()
            .find(|&i| self.mem.read(self.root, i) & VALID == 0)
    }
}

/// Virtual base address covered by level-0 slot `slot` in the upper half.
pub const fn upper_half_l0_base(slot: usize) -> u64 {
    0xffff_0000_0000_0000 | ((slot as u64 & 0x1ff) << 39)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeMem(HashMap<(u64, usize), u64>);

    impl TableMemory for FakeMem {
        fn read(&self, t: u64, i: usize) -> u64 {
            *self.0.get(&(t, i)).unwrap_or(&0)
        }
        fn write(&mut self, t: u64, i: usize, v: u64) {
            self.0.insert((t, i), v);
        }
    }

    struct Bump(u64, u64);

    impl FrameSource for Bump {
        fn alloc_frame(&mut self) -> Option<u64> {
            if self.0 >= self.1 {
                return None;
            }
            let f = self.0;
            self.0 += PAGE_SIZE;
            Some(f)
        }
    }

    const ROOT: u64 = 0x10_0000;

    #[test]
    fn indices() {
        let va = 0xffff_ffff_8000_1000;
        assert_eq!(index(va, 0), 511);
        assert_eq!(index(va, 1), 510);
        assert_eq!(index(va, 2), 0);
        assert_eq!(index(va, 3), 1);
        assert_eq!(upper_half_l0_base(511), 0xffff_ff80_0000_0000);
    }

    #[test]
    fn wx_never_both() {
        for access in [Access::ReadExecute, Access::ReadOnly, Access::ReadWrite] {
            for mem in [MemType::Normal, MemType::Device] {
                let d = page_descriptor(
                    0x4000,
                    PageAttrs {
                        access,
                        mem,
                        bti_guarded: true,
                    },
                );
                let leaf = Leaf::decode(d);
                assert!(!(leaf.writable && leaf.executable), "{access:?} {mem:?}");
                assert_ne!(d & UXN, 0, "EL0 must never execute");
            }
        }
        let text = Leaf::decode(page_descriptor(0x4000, PageAttrs::text(false)));
        assert!(text.executable && !text.writable);
        let data = Leaf::decode(page_descriptor(0x4000, PageAttrs::data()));
        assert!(data.writable && !data.executable);
        let ro = Leaf::decode(page_descriptor(0x4000, PageAttrs::rodata()));
        assert!(!ro.writable && !ro.executable);
    }

    #[test]
    fn bti_bit_only_on_text() {
        assert_ne!(page_descriptor(0, PageAttrs::text(true)) & GP, 0);
        assert_eq!(page_descriptor(0, PageAttrs::text(false)) & GP, 0);
    }

    #[test]
    fn device_mapping_is_not_shareable_cacheable() {
        let d = page_descriptor(0x0900_0000, PageAttrs::mmio());
        assert_eq!(Leaf::decode(d).attr_index, MemType::Device as u8);
        assert_eq!(d & SH_INNER, 0);
    }

    #[test]
    fn mair_merge_preserves_bootloader_entries() {
        let m = MemType::merge_into_mair(0xdead_beef_cafe_44ff);
        assert_eq!(m & 0xffff, 0x44ff);
        assert_eq!((m >> 16) & 0xff, 0x04);
        assert_eq!((m >> 24) & 0xff, 0x00);
        assert_eq!((m >> 32) & 0xff, 0x44);
        assert_eq!(m >> 40, 0);
    }

    #[test]
    fn map_and_translate() {
        let mut mem = FakeMem::default();
        let mut frames = Bump(0x20_0000, 0x30_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(300) + 0x5000;
        m.map_page(va, 0x0900_0000, PageAttrs::mmio(), &mut frames)
            .unwrap();
        assert_eq!(m.translate(va + 0x18), Some(0x0900_0018));
        assert_eq!(m.translate(va + PAGE_SIZE), None);
        // Three intermediate tables were allocated.
        assert_eq!(frames.0, 0x20_0000 + 3 * PAGE_SIZE);
        // Identical remap is fine, a different one is rejected.
        m.map_page(va, 0x0900_0000, PageAttrs::mmio(), &mut frames)
            .unwrap();
        assert_eq!(
            m.map_page(va, 0x0a00_0000, PageAttrs::mmio(), &mut frames),
            Err(MapError::AlreadyMapped)
        );
        assert_eq!(m.free_l0_slot(299..302), Some(299));
        assert_eq!(m.free_l0_slot(300..301), None);
    }

    #[test]
    fn map_range_spans_tables() {
        let mut mem = FakeMem::default();
        let mut frames = Bump(0x20_0000, 0x30_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(256) + (2 << 20) - PAGE_SIZE;
        m.map_range(
            va,
            0x8000_0000,
            3 * PAGE_SIZE,
            PageAttrs::data(),
            &mut frames,
        )
        .unwrap();
        for i in 0..3 {
            assert_eq!(
                m.translate(va + i * PAGE_SIZE),
                Some(0x8000_0000 + i * PAGE_SIZE)
            );
        }
    }

    #[test]
    fn errors() {
        let mut mem = FakeMem::default();
        let mut frames = Bump(0x20_0000, 0x20_0000 + PAGE_SIZE);
        let mut m = Mapper::new(&mut mem, ROOT);
        assert_eq!(
            m.map_page(0x1001, 0, PageAttrs::data(), &mut frames),
            Err(MapError::Unaligned)
        );
        assert_eq!(
            m.map_page(0x0001_0000_0000_0000, 0, PageAttrs::data(), &mut frames),
            Err(MapError::NonCanonical)
        );
        assert_eq!(
            m.map_page(0x1000, 0, PageAttrs::data(), &mut frames),
            Err(MapError::OutOfFrames)
        );
    }

    #[test]
    fn auto_ranges_use_blocks_and_walk_finds_everything() {
        let mut mem = FakeMem::default();
        let mut frames = Bump(0x20_0000, 0x40_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(0);
        // 1 page + 2 blocks + 1 page.
        m.map_range_auto(
            va + BLOCK_2M - PAGE_SIZE,
            0x4000_0000 + BLOCK_2M - PAGE_SIZE,
            2 * BLOCK_2M + 2 * PAGE_SIZE,
            PageAttrs::data(),
            &mut frames,
        )
        .unwrap();
        let mut seen = Vec::new();
        m.for_each_leaf(true, |va, d, level| {
            seen.push((va, Leaf::decode(d).pa, level))
        });
        assert_eq!(seen.len(), 4);
        assert_eq!(seen.iter().filter(|s| s.2 == 2).count(), 2);
        assert_eq!(
            m.translate(va + BLOCK_2M + 0x1234),
            Some(0x4000_0000 + BLOCK_2M + 0x1234)
        );
        assert_eq!(seen[1], (va + BLOCK_2M, 0x4000_0000 + BLOCK_2M, 2));
        assert!(seen.iter().all(|s| s.0 >> 48 == 0xffff));
    }

    #[test]
    fn set_page_access_downgrades_in_place() {
        let mut mem = FakeMem::default();
        let mut frames = Bump(0x20_0000, 0x30_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(10);
        m.map_page(va, 0x5000, PageAttrs::data(), &mut frames)
            .unwrap();
        m.set_page_access(va, Access::ReadOnly).unwrap();
        let (d, _) = m.lookup(va).unwrap();
        let leaf = Leaf::decode(d);
        assert_eq!(
            (leaf.pa, leaf.writable, leaf.executable),
            (0x5000, false, false)
        );
        assert_eq!(
            m.set_page_access(va + PAGE_SIZE, Access::ReadOnly),
            Err(MapError::BlockInTheWay)
        );
        m.map_block_2m(upper_half_l0_base(11), 0, PageAttrs::data(), &mut frames)
            .unwrap();
        assert_eq!(
            m.set_page_access(upper_half_l0_base(11), Access::ReadOnly),
            Err(MapError::BlockInTheWay)
        );
    }

    #[test]
    fn block_descriptor_keeps_wx_rules() {
        let d = block_descriptor(0x4020_0000, PageAttrs::data());
        assert_eq!(d & 0b11, 0b01);
        assert_eq!(Leaf::decode(d).pa, 0x4020_0000);
        assert!(!Leaf::decode(d).executable);
        assert_eq!(
            Mapper::new(&mut FakeMem::default(), ROOT).map_block_2m(
                0x1000,
                0,
                PageAttrs::data(),
                &mut Bump(0, 0)
            ),
            Err(MapError::Unaligned)
        );
    }

    #[test]
    fn block_mappings_are_walked_and_respected() {
        let mut mem = FakeMem::default();
        // L0[0] -> L1 table at 0x1000; L1[1] is a 1 GiB block at 0x4000_0000.
        mem.write(ROOT, 0, table_descriptor(0x1000));
        mem.write(0x1000, 1, 0x4000_0000 | VALID | AF);
        let mut frames = Bump(0x20_0000, 0x30_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        assert_eq!(m.translate(0x4000_1234), Some(0x4000_1234));
        assert_eq!(m.lookup(0x4000_1234).map(|(_, l)| l), Some(1));
        assert_eq!(
            m.map_page(0x4000_0000, 0, PageAttrs::data(), &mut frames),
            Err(MapError::BlockInTheWay)
        );
    }
}
