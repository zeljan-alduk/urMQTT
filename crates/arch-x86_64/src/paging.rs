//! x86_64 4-level paging, 4 KiB granule, 48-bit virtual addresses.
//!
//! Entry encoding and table walking are pure logic over a [`TableMemory`]
//! abstraction so they can be tested on the host; the kernel supplies an
//! implementation that reaches table frames through the HHDM. The register
//! side (EFER, CR0, CR3, CR4, TLB) sits at the end of the file and exists on
//! bare metal only.
//!
//! Differences from the AArch64 module that the shapes hide:
//! - One root covers both halves of the address space. The kernel's root
//!   never has a lower-half entry, which is what "no lower-half mappings"
//!   means here; `for_each_leaf(upper, ..)` visits one half.
//! - Permissions of the levels above a leaf combine (writable only if every
//!   level is, NX if any level is). Table entries are therefore maximally
//!   permissive and the leaf alone decides.
//! - Ring 3 never has access: no entry the kernel writes sets U/S.
//! - Accessed and dirty are pre-set so the walker never has to write an
//!   entry, which keeps read-only page tables read-only.
//! - Cache types come from the PAT ([`crate::pat`]); only its first four
//!   entries are used, so the PAT bit of a leaf stays clear.

#![allow(unsafe_code)]

pub use urmqtt_sync::frame::{FrameSource, PAGE_SIZE};

/// Entries per table.
pub const ENTRIES: usize = 512;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
/// In levels 1 and 2: this entry is a leaf (1 GiB / 2 MiB page).
const PAGE_SIZE_BIT: u64 = 1 << 7;
const NX: u64 = 1 << 63;
/// Physical address bits of an entry (bits 12..=51).
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
/// Physical addresses are at most 52 bits.
const MAX_PA: u64 = 1 << 52;

/// Memory types, as indices into the PAT (see [`crate::pat`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemType {
    /// Write-back RAM.
    Normal = 0,
    /// Write-combining, for the framebuffer.
    Framebuffer = 1,
    /// Uncached (UC-), for MMIO.
    Device = 2,
    /// Strongly uncached (UC).
    DeviceStrict = 3,
    /// Not cached, not strongly ordered. x86 has no separate type for it;
    /// it shares write-combining with [`Framebuffer`](Self::Framebuffer)
    /// and decodes back as that.
    NonCacheable = 4,
}

impl MemType {
    /// The PAT index (`PAT:PCD:PWT`, 0..=3) that selects this type.
    pub const fn pat_index(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Framebuffer | Self::NonCacheable => 1,
            Self::Device => 2,
            Self::DeviceStrict => 3,
        }
    }

    /// The type a PAT index decodes to.
    pub const fn from_pat_index(index: u8) -> Self {
        match index {
            1 => Self::Framebuffer,
            2 => Self::Device,
            3 => Self::DeviceStrict,
            _ => Self::Normal,
        }
    }
}

/// Access permissions for a kernel mapping. Ring 3 never has access.
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
    /// Unused on x86 (no BTI); IBT is a compiler matter (ADR-047).
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

/// The flag bits of a leaf with `attrs` (no address). W^X holds by
/// construction: no attribute combination is both writable and executable,
/// and the user bit is never set.
const fn leaf_flags(attrs: PageAttrs) -> u64 {
    let mut f = PRESENT | ACCESSED | DIRTY;
    match attrs.access {
        Access::ReadExecute => {}
        Access::ReadOnly => f |= NX,
        Access::ReadWrite => f |= NX | WRITABLE,
    }
    let pat = attrs.mem.pat_index();
    if pat & 1 != 0 {
        f |= PWT;
    }
    if pat & 2 != 0 {
        f |= PCD;
    }
    f
}

/// Encodes a level-3 (4 KiB) entry.
pub const fn page_descriptor(pa: u64, attrs: PageAttrs) -> u64 {
    (pa & ADDR_MASK) | leaf_flags(attrs)
}

/// Size of a level-2 block mapping.
pub const BLOCK_2M: u64 = 2 << 20;

/// Encodes a level-2 (2 MiB) entry with the same attributes as
/// [`page_descriptor`].
pub const fn block_descriptor(pa: u64, attrs: PageAttrs) -> u64 {
    (pa & ADDR_MASK & !(BLOCK_2M - 1)) | leaf_flags(attrs) | PAGE_SIZE_BIT
}

/// Encodes an entry pointing at the next-level table. Maximally permissive
/// so the leaf decides (see the module comment).
pub const fn table_descriptor(table_pa: u64) -> u64 {
    (table_pa & ADDR_MASK) | PRESENT | WRITABLE | ACCESSED
}

/// Decoded view of a leaf entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    pub pa: u64,
    pub writable: bool,
    pub executable: bool,
    /// The PAT index (0..=3, see [`MemType::from_pat_index`]).
    pub attr_index: u8,
}

impl Leaf {
    pub const fn decode(entry: u64) -> Self {
        Self {
            // The PAT bit (12) of a 2 MiB entry is never set by this module,
            // so one mask serves every level.
            pa: entry & ADDR_MASK,
            writable: entry & WRITABLE != 0,
            executable: entry & NX == 0,
            attr_index: ((entry & PWT != 0) as u8) | (((entry & PCD != 0) as u8) << 1),
        }
    }
}

/// Index into the table at `level` (0 = PML4 .. 3 = PT) for `va`.
pub const fn index(va: u64, level: u8) -> usize {
    let shift = 39 - 9 * (level as u64);
    ((va >> shift) & 0x1ff) as usize
}

/// Access to page-table frames by physical address.
pub trait TableMemory {
    fn read(&self, table_pa: u64, idx: usize) -> u64;
    fn write(&mut self, table_pa: u64, idx: usize, value: u64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Address not page (or block) aligned, or a physical address beyond
    /// 52 bits.
    Unaligned,
    /// Virtual address is not canonical (bits 63..=47 differ).
    NonCanonical,
    /// A different mapping already exists at this address.
    AlreadyMapped,
    /// A large page covers this address, or nothing is mapped where a
    /// page was expected.
    BlockInTheWay,
    /// No frame available for an intermediate table.
    OutOfFrames,
}

/// Whether bits 63..=47 of `va` are all equal.
pub const fn is_canonical(va: u64) -> bool {
    ((va as i64) << 16 >> 16) as u64 == va
}

/// Whether the entry at `level` is a leaf (levels 1 and 2 can hold large
/// pages; level 0 cannot).
const fn is_leaf(entry: u64, level: u8) -> bool {
    level == 3 || (level >= 1 && entry & PAGE_SIZE_BIT != 0)
}

/// Walks and edits one address space rooted at `root` (the CR3 base).
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

    /// Maps one 4 KiB page. Remapping to the identical entry is a no-op.
    pub fn map_page<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        if !va.is_multiple_of(PAGE_SIZE) || !pa.is_multiple_of(PAGE_SIZE) || pa >= MAX_PA {
            return Err(MapError::Unaligned);
        }
        if !is_canonical(va) {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in 0..3u8 {
            table = self.next_table(table, level, index(va, level), frames)?;
        }
        self.install(table, index(va, 3), page_descriptor(pa, attrs))
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

    /// Maps one 2 MiB page at level 2.
    pub fn map_block_2m<F: FrameSource>(
        &mut self,
        va: u64,
        pa: u64,
        attrs: PageAttrs,
        frames: &mut F,
    ) -> Result<(), MapError> {
        if !va.is_multiple_of(BLOCK_2M) || !pa.is_multiple_of(BLOCK_2M) || pa >= MAX_PA {
            return Err(MapError::Unaligned);
        }
        if !is_canonical(va) {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in 0..2u8 {
            table = self.next_table(table, level, index(va, level), frames)?;
        }
        self.install(table, index(va, 2), block_descriptor(pa, attrs))
    }

    /// Like [`map_range`](Self::map_range) but uses 2 MiB pages wherever
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

    /// Writes `new` into an empty slot; an identical entry is a no-op.
    fn install(&mut self, table: u64, idx: usize, new: u64) -> Result<(), MapError> {
        let old = self.mem.read(table, idx);
        if old & PRESENT != 0 {
            return if old == new {
                Ok(())
            } else {
                Err(MapError::AlreadyMapped)
            };
        }
        self.mem.write(table, idx, new);
        Ok(())
    }

    fn next_table<F: FrameSource>(
        &mut self,
        table: u64,
        level: u8,
        idx: usize,
        frames: &mut F,
    ) -> Result<u64, MapError> {
        let entry = self.mem.read(table, idx);
        if entry & PRESENT == 0 {
            let new = frames.alloc_frame().ok_or(MapError::OutOfFrames)?;
            for i in 0..ENTRIES {
                self.mem.write(new, i, 0);
            }
            self.mem.write(table, idx, table_descriptor(new));
            Ok(new)
        } else if is_leaf(entry, level) {
            Err(MapError::BlockInTheWay)
        } else {
            Ok(entry & ADDR_MASK)
        }
    }

    /// Changes the access permissions of an existing 4 KiB page, keeping
    /// its address and memory type. Used to make page tables read-only.
    pub fn set_page_access(&mut self, va: u64, access: Access) -> Result<(), MapError> {
        if !is_canonical(va) {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in 0..3u8 {
            let entry = self.mem.read(table, index(va, level));
            if entry & PRESENT == 0 || is_leaf(entry, level) {
                return Err(MapError::BlockInTheWay);
            }
            table = entry & ADDR_MASK;
        }
        let idx = index(va, 3);
        let old = self.mem.read(table, idx);
        if old & PRESENT == 0 {
            return Err(MapError::BlockInTheWay);
        }
        let attrs = PageAttrs {
            access,
            mem: MemType::from_pat_index(Leaf::decode(old).attr_index),
            bti_guarded: false,
        };
        self.mem
            .write(table, idx, page_descriptor(old & ADDR_MASK, attrs));
        Ok(())
    }

    /// Calls `f(va, entry, level)` for every present leaf of one half of the
    /// address space: the upper (kernel) half if `upper`, else the lower.
    pub fn for_each_leaf<G: FnMut(u64, u64, u8)>(&self, upper: bool, mut f: G) {
        let slots = if upper { 256..ENTRIES } else { 0..256 };
        for i in slots {
            let entry = self.mem.read(self.root, i);
            if entry & PRESENT != 0 {
                self.walk(entry, 0, upper_half_l0_base(i), &mut f);
            }
        }
    }

    /// Visits the entry `entry` found at `level` (its slot's base is `va`).
    fn walk<G: FnMut(u64, u64, u8)>(&self, entry: u64, level: u8, va: u64, f: &mut G) {
        if is_leaf(entry, level) {
            f(va, entry, level);
            return;
        }
        let table = entry & ADDR_MASK;
        let shift = 39 - 9 * u64::from(level + 1);
        for i in 0..ENTRIES {
            let e = self.mem.read(table, i);
            if e & PRESENT != 0 {
                self.walk(e, level + 1, va | ((i as u64) << shift), f);
            }
        }
    }

    /// Translates `va` through the tables: the leaf entry and the level it
    /// was found at (1 for 1 GiB, 2 for 2 MiB, 3 for 4 KiB).
    pub fn lookup(&self, va: u64) -> Option<(u64, u8)> {
        if !is_canonical(va) {
            return None;
        }
        let mut table = self.root;
        for level in 0..4u8 {
            let entry = self.mem.read(table, index(va, level));
            if entry & PRESENT == 0 {
                return None;
            }
            if is_leaf(entry, level) {
                return Some((entry, level));
            }
            table = entry & ADDR_MASK;
        }
        None
    }

    /// Physical address of the table consulted at `level` (0 = root) when
    /// translating `va`, if the walk reaches that level.
    pub fn table_at_level(&self, va: u64, level: u8) -> Option<u64> {
        let mut table = self.root;
        for l in 0..level {
            let entry = self.mem.read(table, index(va, l));
            if entry & PRESENT == 0 || is_leaf(entry, l) {
                return None;
            }
            table = entry & ADDR_MASK;
        }
        Some(table)
    }

    /// Physical address `va` maps to, if any.
    pub fn translate(&self, va: u64) -> Option<u64> {
        let (entry, level) = self.lookup(va)?;
        let size = match level {
            1 => 1u64 << 30,
            2 => 1u64 << 21,
            _ => PAGE_SIZE,
        };
        Some((entry & ADDR_MASK & !(size - 1)) | (va & (size - 1)))
    }

    /// Index of the first unused level-0 entry in `range`, if any.
    pub fn free_l0_slot(&self, range: core::ops::Range<usize>) -> Option<usize> {
        range
            .into_iter()
            .find(|&i| self.mem.read(self.root, i) & PRESENT == 0)
    }
}

/// Virtual base address covered by PML4 slot `slot` in the upper half.
/// Only slots 256..=511 are canonical there; the slot number is taken
/// modulo 512, and lower-half slots yield the canonical lower-half base.
pub const fn upper_half_l0_base(slot: usize) -> u64 {
    let base = (slot as u64 & 0x1ff) << 39;
    if base & (1 << 47) != 0 {
        0xffff_0000_0000_0000 | base
    } else {
        base
    }
}

/// Which protections [`activate`] could turn on (the rest are logged by the
/// kernel as unavailable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protections {
    /// `EFER.NXE`: the NX bit is honoured (without it bit 63 is reserved).
    pub nx: bool,
    /// `CR0.WP`: supervisor writes honour read-only pages.
    pub wp: bool,
    /// `CR4.SMEP`: no execution of user pages from ring 0.
    pub smep: bool,
    /// `CR4.SMAP`: no access to user pages from ring 0 (unless EFLAGS.AC).
    pub smap: bool,
    /// `CR4.UMIP`: ring 3 cannot read descriptor-table registers.
    pub umip: bool,
}

/// CR0 bit 16: write protect.
pub const CR0_WP: u64 = 1 << 16;
/// CR4 bits.
pub const CR4_UMIP: u64 = 1 << 11;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
/// `IA32_EFER.NXE`.
pub const EFER_NXE: u64 = 1 << 11;

impl Protections {
    /// What CPUID offers: leaf 7 (EBX, ECX) and extended leaf 0x80000001
    /// (EDX). WP is architectural and always available.
    pub const fn from_cpuid(l7_ebx: u32, l7_ecx: u32, ext1_edx: u32) -> Self {
        Self {
            nx: ext1_edx & (1 << 20) != 0,
            wp: true,
            smep: l7_ebx & (1 << 7) != 0,
            smap: l7_ebx & (1 << 20) != 0,
            umip: l7_ecx & (1 << 2) != 0,
        }
    }

    /// `cr4` with the available protections added.
    pub const fn apply_cr4(self, cr4: u64) -> u64 {
        let mut v = cr4;
        if self.smep {
            v |= CR4_SMEP;
        }
        if self.smap {
            v |= CR4_SMAP;
        }
        if self.umip {
            v |= CR4_UMIP;
        }
        v
    }

    /// `cr0` with write protect on.
    pub const fn apply_cr0(self, cr0: u64) -> u64 {
        cr0 | CR0_WP
    }
}

/// Physical-address bits of a CR3 value (the PCID and flag bits below 12 and
/// the reserved bits above 51 are not part of the root).
pub const fn cr3_root(cr3: u64) -> u64 {
    cr3 & ADDR_MASK
}

#[cfg(target_os = "none")]
mod hw {
    use super::{Protections, cr3_root};
    use crate::pat::{rdmsr, wrmsr};
    use core::arch::asm;
    use core::sync::atomic::{AtomicU8, Ordering};

    const MSR_EFER: u32 = 0xc000_0080;

    fn read_cr0() -> u64 {
        let v: u64;
        // SAFETY: reading a control register has no side effect.
        unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    fn read_cr3() -> u64 {
        let v: u64;
        // SAFETY: reading a control register has no side effect.
        unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    fn read_cr4() -> u64 {
        let v: u64;
        // SAFETY: reading a control register has no side effect.
        unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    /// # Safety
    /// The value must keep the running code valid (CR0 bits, here WP only).
    unsafe fn write_cr0(v: u64) {
        // SAFETY: forwarded contract.
        unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    /// # Safety
    /// Only bits the CPU supports may be set.
    unsafe fn write_cr4(v: u64) {
        // SAFETY: forwarded contract.
        unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    /// # Safety
    /// `v` must be the root of tables that map the running code and stack.
    unsafe fn write_cr3(v: u64) {
        // SAFETY: forwarded contract; the write flushes the non-global TLB.
        unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    static ENABLED: AtomicU8 = AtomicU8::new(0);

    fn pack(p: Protections) -> u8 {
        u8::from(p.nx)
            | u8::from(p.wp) << 1
            | u8::from(p.smep) << 2
            | u8::from(p.smap) << 3
            | u8::from(p.umip) << 4
    }

    fn unpack(v: u8) -> Protections {
        Protections {
            nx: v & 1 != 0,
            wp: v & 2 != 0,
            smep: v & 4 != 0,
            smap: v & 8 != 0,
            umip: v & 16 != 0,
        }
    }

    /// What the last [`activate`] enabled on the boot CPU.
    pub fn protections() -> Protections {
        // Relaxed: written before the other CPUs start, read for logging.
        unpack(ENABLED.load(Ordering::Relaxed))
    }

    fn probe() -> Protections {
        use core::arch::x86_64::{__cpuid, __cpuid_count};
        // CPUID exists on every x86-64 CPU; leaves above the maximum are
        // not queried.
        let l7 = if __cpuid(0).eax >= 7 {
            let r = __cpuid_count(7, 0);
            (r.ebx, r.ecx)
        } else {
            (0, 0)
        };
        let ext1 = if __cpuid(0x8000_0000).eax >= 0x8000_0001 {
            __cpuid(0x8000_0001).edx
        } else {
            0
        };
        Protections::from_cpuid(l7.0, l7.1, ext1)
    }

    /// Turns `EFER.NXE` on (a no-op if the bootloader did, as Limine does).
    /// Entries with bit 63 set are invalid without it.
    pub fn enable_nx() -> bool {
        if !probe().nx {
            return false;
        }
        // SAFETY: EFER exists on every x86-64 CPU.
        let efer = unsafe { rdmsr(MSR_EFER) };
        if efer & super::EFER_NXE == 0 {
            // SAFETY: only NXE is added.
            unsafe { wrmsr(MSR_EFER, efer | super::EFER_NXE) };
        }
        true
    }

    /// Switches to the tables at `root` and turns the protections on.
    ///
    /// # Safety
    /// See [`super::activate`].
    pub unsafe fn activate(root: u64) {
        let p = probe();
        // NXE first: the new tables carry NX bits.
        enable_nx();
        // SAFETY: the caller guarantees the new tables map everything in use.
        unsafe { write_cr3(cr3_root(root)) };
        // SAFETY: the CR4 bits only restrict ring 0 (no user mappings exist)
        // and a CPU that lacks a bit never gets it (CPUID checked above).
        unsafe { write_cr4(p.apply_cr4(read_cr4())) };
        // SAFETY: the new tables map no page both writable and executable, and
        // honouring read-only pages is the point.
        unsafe { write_cr0(p.apply_cr0(read_cr0())) };
        ENABLED.store(pack(p), Ordering::Relaxed);
    }

    pub fn kernel_root() -> u64 {
        cr3_root(read_cr3())
    }

    pub fn flush_all() {
        // SAFETY: rewriting CR3 with its own value flushes every non-global
        // entry (the kernel marks none global) and changes no mapping.
        unsafe { write_cr3(read_cr3()) };
    }

    pub fn flush_va(va: u64) {
        // SAFETY: INVLPG on any address is harmless; it only drops a TLB entry.
        unsafe { asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
    }
}

#[cfg(target_os = "none")]
pub use hw::protections;

/// Activates a new root: enables NX, loads CR3, then sets SMEP/SMAP/UMIP
/// (where CPUID has them) and CR0.WP. Loading CR3 flushes the TLB.
///
/// # Safety
/// `root` must map the running code, the stack and every live mapping at the
/// same addresses as the active tables, and no mapping may be both writable
/// and executable.
#[cfg(target_os = "none")]
pub unsafe fn activate(root: u64) {
    // SAFETY: forwarded contract.
    unsafe { hw::activate(root) }
}

/// Physical address of the active root table (CR3).
#[cfg(target_os = "none")]
pub fn kernel_root() -> u64 {
    hw::kernel_root()
}

/// Programs the PAT so the kernel's memory types exist (aarch64: MAIR) and
/// makes sure `EFER.NXE` is on, so the bootloader's tables can be extended
/// with kernel entries. Every CPU must run this once.
#[cfg(target_os = "none")]
pub fn merge_memory_attributes() {
    crate::pat::program();
    hw::enable_nx();
    hw::flush_all();
}

#[cfg(target_os = "none")]
pub fn tlb_flush_all() {
    hw::flush_all();
}

/// Drops the translation of `va` on the executing CPU. Other CPUs are the
/// caller's business (shootdown arrives with SMP, X5).
#[cfg(target_os = "none")]
pub fn tlb_flush_va(va: u64) {
    hw::flush_va(va);
}

/// Makes table updates visible before the new mappings are used (x86: the
/// walker snoops the caches, so a compiler fence suffices; the TLB is
/// flushed explicitly).
#[cfg(target_os = "none")]
#[inline(always)]
pub fn publish() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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
    const ACCESSES: [Access; 3] = [Access::ReadExecute, Access::ReadOnly, Access::ReadWrite];
    const MEMS: [MemType; 5] = [
        MemType::Normal,
        MemType::Framebuffer,
        MemType::Device,
        MemType::DeviceStrict,
        MemType::NonCacheable,
    ];

    fn fresh() -> (FakeMem, Bump) {
        (FakeMem::default(), Bump(0x20_0000, 0x80_0000))
    }

    #[test]
    fn indices() {
        let va = 0xffff_ffff_8000_1000;
        assert_eq!(index(va, 0), 511);
        assert_eq!(index(va, 1), 510);
        assert_eq!(index(va, 2), 0);
        assert_eq!(index(va, 3), 1);
        assert_eq!(upper_half_l0_base(511), 0xffff_ff80_0000_0000);
        assert_eq!(upper_half_l0_base(256), 0xffff_8000_0000_0000);
        assert_eq!(upper_half_l0_base(255), 0x0000_7f80_0000_0000);
        assert_eq!(upper_half_l0_base(0), 0);
    }

    #[test]
    fn canonical_addresses() {
        for ok in [
            0,
            0x1000,
            0x0000_7fff_ffff_f000,
            0xffff_8000_0000_0000,
            0xffff_ffff_8000_0000,
            u64::MAX,
        ] {
            assert!(is_canonical(ok), "{ok:#x}");
        }
        for bad in [
            0x0000_8000_0000_0000,
            0x0001_0000_0000_0000,
            0xffff_7fff_ffff_f000,
            0x8000_0000_0000_0000,
            0xfffe_ffff_ffff_ffff,
        ] {
            assert!(!is_canonical(bad), "{bad:#x}");
        }
    }

    #[test]
    fn wx_never_both_for_any_attribute_combination() {
        for access in ACCESSES {
            for mem in MEMS {
                for bti in [false, true] {
                    let attrs = PageAttrs {
                        access,
                        mem,
                        bti_guarded: bti,
                    };
                    for d in [
                        page_descriptor(0x4000, attrs),
                        block_descriptor(0x20_0000, attrs),
                    ] {
                        let leaf = Leaf::decode(d);
                        assert!(!(leaf.writable && leaf.executable), "{access:?} {mem:?}");
                        assert_eq!(d & (1 << 2), 0, "ring 3 must never have access");
                        assert_ne!(d & PRESENT, 0);
                        assert_eq!(leaf.writable, access == Access::ReadWrite);
                        assert_eq!(leaf.executable, access == Access::ReadExecute);
                        assert_eq!(d & (1 << 8), 0, "no global pages");
                    }
                }
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
    fn table_entries_never_restrict_the_leaf() {
        let t = table_descriptor(0x7000);
        assert_eq!(t & NX, 0);
        assert_ne!(t & WRITABLE, 0);
        assert_eq!(t & PAGE_SIZE_BIT, 0);
        assert_eq!(t & (1 << 2), 0);
        assert_eq!(t & ADDR_MASK, 0x7000);
    }

    #[test]
    fn pat_bit_stays_clear_and_memory_types_round_trip() {
        for mem in MEMS {
            let attrs = PageAttrs {
                access: Access::ReadWrite,
                mem,
                bti_guarded: false,
            };
            let p = page_descriptor(0x1000, attrs);
            let b = block_descriptor(0x20_0000, attrs);
            assert_eq!(p & PAGE_SIZE_BIT, 0, "bit 7 is the PAT bit in a PTE");
            assert_eq!(p & (1 << 12), 0x1000 & (1 << 12));
            assert_ne!(b & PAGE_SIZE_BIT, 0);
            assert_eq!(b & (1 << 12), 0, "bit 12 is the PAT bit in a 2 MiB entry");
            let idx = Leaf::decode(p).attr_index;
            assert_eq!(idx, mem.pat_index());
            assert_eq!(Leaf::decode(b).attr_index, idx);
            assert_eq!(MemType::from_pat_index(idx).pat_index(), idx);
        }
        // Normal memory is write-back: no cache bits at all.
        assert_eq!(page_descriptor(0, PageAttrs::data()) & (PWT | PCD), 0);
        // Device memory is UC- (PCD only); the strict type is UC (PCD+PWT).
        assert_eq!(page_descriptor(0, PageAttrs::mmio()) & (PWT | PCD), PCD);
        let strict = PageAttrs {
            mem: MemType::DeviceStrict,
            ..PageAttrs::mmio()
        };
        assert_eq!(page_descriptor(0, strict) & (PWT | PCD), PWT | PCD);
    }

    #[test]
    fn leaf_decode_of_a_two_mib_entry_gives_its_base() {
        let d = block_descriptor(0x4020_0000, PageAttrs::data());
        assert_eq!(Leaf::decode(d).pa, 0x4020_0000);
        // The low bits of the address are dropped, never smuggled into flags.
        let d = block_descriptor(0x4020_5000, PageAttrs::data());
        assert_eq!(Leaf::decode(d).pa, 0x4020_0000);
    }

    #[test]
    fn nx_bit_position_is_63() {
        assert_eq!(page_descriptor(0, PageAttrs::rodata()) >> 63, 1);
        assert_eq!(page_descriptor(0, PageAttrs::text(true)) >> 63, 0);
    }

    #[test]
    fn map_and_translate() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(300) + 0x5000;
        m.map_page(va, 0xfee0_0000, PageAttrs::mmio(), &mut frames)
            .unwrap();
        assert_eq!(m.translate(va + 0x18), Some(0xfee0_0018));
        assert_eq!(m.translate(va + PAGE_SIZE), None);
        // Three intermediate tables were allocated.
        assert_eq!(frames.0, 0x20_0000 + 3 * PAGE_SIZE);
        // Identical remap is fine, a different one is rejected.
        m.map_page(va, 0xfee0_0000, PageAttrs::mmio(), &mut frames)
            .unwrap();
        assert_eq!(
            m.map_page(va, 0xfec0_0000, PageAttrs::mmio(), &mut frames),
            Err(MapError::AlreadyMapped)
        );
        assert_eq!(
            m.map_page(va, 0xfee0_0000, PageAttrs::data(), &mut frames),
            Err(MapError::AlreadyMapped)
        );
        assert_eq!(m.free_l0_slot(299..302), Some(299));
        assert_eq!(m.free_l0_slot(300..301), None);
    }

    #[test]
    fn map_range_spans_tables() {
        let (mut mem, mut frames) = fresh();
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
            m.map_page(0x1000, 0x10_0001, PageAttrs::data(), &mut frames),
            Err(MapError::Unaligned)
        );
        assert_eq!(
            m.map_page(0x1000, MAX_PA, PageAttrs::data(), &mut frames),
            Err(MapError::Unaligned)
        );
        for bad in [
            0x0000_8000_0000_0000u64,
            0x0001_0000_0000_0000,
            0xffff_7fff_ffff_f000,
        ] {
            assert_eq!(
                m.map_page(bad, 0, PageAttrs::data(), &mut frames),
                Err(MapError::NonCanonical)
            );
            assert_eq!(
                m.map_block_2m(bad & !(BLOCK_2M - 1), 0, PageAttrs::data(), &mut frames),
                Err(MapError::NonCanonical)
            );
            assert_eq!(m.lookup(bad), None);
            assert_eq!(
                m.set_page_access(bad, Access::ReadOnly),
                Err(MapError::NonCanonical)
            );
        }
        assert_eq!(
            m.map_page(0x1000, 0, PageAttrs::data(), &mut frames),
            Err(MapError::OutOfFrames)
        );
    }

    #[test]
    fn auto_ranges_use_blocks_and_walk_finds_everything() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(256);
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
        // Nothing is in the lower half.
        let mut lower = 0;
        m.for_each_leaf(false, |_, _, _| lower += 1);
        assert_eq!(lower, 0);
    }

    #[test]
    fn halves_are_walked_separately_with_canonical_addresses() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let lo = 0x0000_7fff_ffff_f000;
        let hi = 0xffff_ffff_8000_0000;
        m.map_page(lo, 0x1000, PageAttrs::data(), &mut frames)
            .unwrap();
        m.map_page(hi, 0x2000, PageAttrs::text(false), &mut frames)
            .unwrap();
        let (mut l, mut u) = (Vec::new(), Vec::new());
        m.for_each_leaf(false, |va, _, _| l.push(va));
        m.for_each_leaf(true, |va, _, _| u.push(va));
        assert_eq!(l, [lo]);
        assert_eq!(u, [hi]);
        assert_eq!(m.translate(hi + 0x10), Some(0x2010));
        assert_eq!(m.translate(lo), Some(0x1000));
    }

    #[test]
    fn set_page_access_downgrades_in_place_and_keeps_the_memory_type() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(266);
        m.map_page(va, 0x5000, PageAttrs::data(), &mut frames)
            .unwrap();
        m.set_page_access(va, Access::ReadOnly).unwrap();
        let (d, _) = m.lookup(va).unwrap();
        let leaf = Leaf::decode(d);
        assert_eq!(
            (leaf.pa, leaf.writable, leaf.executable),
            (0x5000, false, false)
        );
        // Device and framebuffer types survive a permission change.
        for mem_type in [MemType::Device, MemType::DeviceStrict, MemType::Framebuffer] {
            let v = va + PAGE_SIZE * (1 + mem_type as u64);
            let attrs = PageAttrs {
                access: Access::ReadWrite,
                mem: mem_type,
                bti_guarded: false,
            };
            m.map_page(v, 0x9000, attrs, &mut frames).unwrap();
            m.set_page_access(v, Access::ReadOnly).unwrap();
            let (d, _) = m.lookup(v).unwrap();
            assert_eq!(Leaf::decode(d).attr_index, mem_type.pat_index());
            assert!(!Leaf::decode(d).writable && !Leaf::decode(d).executable);
        }
        assert_eq!(
            m.set_page_access(va + 40 * PAGE_SIZE, Access::ReadOnly),
            Err(MapError::BlockInTheWay)
        );
        m.map_block_2m(upper_half_l0_base(267), 0, PageAttrs::data(), &mut frames)
            .unwrap();
        assert_eq!(
            m.set_page_access(upper_half_l0_base(267), Access::ReadOnly),
            Err(MapError::BlockInTheWay)
        );
    }

    #[test]
    fn set_page_access_never_produces_wx() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(280);
        let mut n = 0;
        for from in ACCESSES {
            for to in ACCESSES {
                let v = va + n * PAGE_SIZE;
                n += 1;
                let attrs = PageAttrs {
                    access: from,
                    mem: MemType::Normal,
                    bti_guarded: false,
                };
                m.map_page(v, 0x3000, attrs, &mut frames).unwrap();
                m.set_page_access(v, to).unwrap();
                let leaf = Leaf::decode(m.lookup(v).unwrap().0);
                assert!(!(leaf.writable && leaf.executable));
                assert_eq!(leaf.executable, to == Access::ReadExecute);
                assert_eq!(leaf.writable, to == Access::ReadWrite);
            }
        }
    }

    #[test]
    fn block_descriptor_keeps_wx_rules() {
        let d = block_descriptor(0x4020_0000, PageAttrs::data());
        assert_ne!(d & PAGE_SIZE_BIT, 0);
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
    fn large_pages_block_pages_and_pages_block_large_pages() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = upper_half_l0_base(300);
        m.map_block_2m(va, 0x20_0000, PageAttrs::data(), &mut frames)
            .unwrap();
        // A page inside a 2 MiB mapping, and a second block on top of it.
        assert_eq!(
            m.map_page(va + PAGE_SIZE, 0x5000, PageAttrs::data(), &mut frames),
            Err(MapError::BlockInTheWay)
        );
        assert_eq!(
            m.map_block_2m(va, 0x40_0000, PageAttrs::data(), &mut frames),
            Err(MapError::AlreadyMapped)
        );
        m.map_block_2m(va, 0x20_0000, PageAttrs::data(), &mut frames)
            .unwrap();
        // A block over a table of pages.
        let next = va + BLOCK_2M;
        m.map_page(next + PAGE_SIZE, 0x5000, PageAttrs::data(), &mut frames)
            .unwrap();
        assert_eq!(
            m.map_block_2m(next, 0x60_0000, PageAttrs::data(), &mut frames),
            Err(MapError::AlreadyMapped)
        );
        // table_at_level stops at a leaf.
        assert!(m.table_at_level(va, 2).is_some());
        assert_eq!(m.table_at_level(va, 3), None);
        assert!(m.table_at_level(next, 3).is_some());
        assert_eq!(m.lookup(va).map(|(_, l)| l), Some(2));
        assert_eq!(m.lookup(next + PAGE_SIZE).map(|(_, l)| l), Some(3));
    }

    #[test]
    fn gigabyte_pages_from_the_bootloader_are_walked_and_respected() {
        let mut mem = FakeMem::default();
        // PML4[256] -> PDPT at 0x1000; PDPT[1] is a 1 GiB page at 0x4000_0000
        // (what Limine builds for the HHDM).
        let hhdm = upper_half_l0_base(256);
        mem.write(ROOT, 256, table_descriptor(0x1000));
        mem.write(
            0x1000,
            1,
            0x4000_0000 | PRESENT | WRITABLE | PAGE_SIZE_BIT | NX,
        );
        let mut frames = Bump(0x20_0000, 0x30_0000);
        let mut m = Mapper::new(&mut mem, ROOT);
        let va = hhdm + (1 << 30) + 0x1234;
        assert_eq!(m.translate(va), Some(0x4000_1234));
        assert_eq!(m.lookup(va).map(|(_, l)| l), Some(1));
        assert_eq!(
            m.map_page(va & !0xfff, 0, PageAttrs::data(), &mut frames),
            Err(MapError::BlockInTheWay)
        );
        assert_eq!(
            m.map_block_2m(
                (va & !0xfff) & !(BLOCK_2M - 1),
                0,
                PageAttrs::data(),
                &mut frames
            ),
            Err(MapError::BlockInTheWay)
        );
        let mut seen = Vec::new();
        m.for_each_leaf(true, |v, d, l| seen.push((v, Leaf::decode(d).pa, l)));
        assert_eq!(seen, [(hhdm + (1 << 30), 0x4000_0000, 1)]);
    }

    #[test]
    fn page_size_bit_in_a_pml4_entry_is_not_a_leaf() {
        // Bit 7 is reserved-zero at level 0; a table is still a table.
        assert!(!is_leaf(PRESENT | PAGE_SIZE_BIT, 0));
        assert!(is_leaf(PRESENT | PAGE_SIZE_BIT, 1));
        assert!(is_leaf(PRESENT | PAGE_SIZE_BIT, 2));
        // At level 3 the same bit is the PAT bit and the entry is a leaf.
        assert!(is_leaf(PRESENT, 3));
    }

    #[test]
    fn null_page_and_lower_half_stay_unmapped_in_a_kernel_style_tree() {
        let (mut mem, mut frames) = fresh();
        let mut m = Mapper::new(&mut mem, ROOT);
        m.map_range_auto(
            0xffff_8000_0000_0000,
            0,
            4 * BLOCK_2M,
            PageAttrs::data(),
            &mut frames,
        )
        .unwrap();
        m.map_range(
            0xffff_ffff_8000_0000,
            0x20_0000,
            4 * PAGE_SIZE,
            PageAttrs::text(false),
            &mut frames,
        )
        .unwrap();
        assert_eq!(m.translate(0), None);
        assert_eq!(m.translate(0x1000), None);
        assert_eq!(m.free_l0_slot(0..256), Some(0));
        let mut lower = 0;
        m.for_each_leaf(false, |_, _, _| lower += 1);
        assert_eq!(lower, 0);
    }

    /// A deterministic pseudo-random mapping workload: whatever is mapped,
    /// no leaf the walk finds is writable and executable, nothing user
    /// accessible, and every translation matches what was requested.
    #[test]
    fn random_workload_keeps_wx_and_translates_back() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let (mut mem, mut frames) = (FakeMem::default(), Bump(0x100_0000, 0x400_0000));
        let mut m = Mapper::new(&mut mem, ROOT);
        let mut expect: Vec<(u64, u64, Access)> = Vec::new();
        for _ in 0..400 {
            let r = next();
            let slot = 256 + (r % 200) as usize;
            let va = upper_half_l0_base(slot) + ((r >> 8) % 64) * PAGE_SIZE;
            let pa = ((r >> 20) % 0x1_0000) * PAGE_SIZE;
            let access = ACCESSES[(r >> 40) as usize % 3];
            let attrs = PageAttrs {
                access,
                mem: MEMS[(r >> 44) as usize % 5],
                bti_guarded: r & 1 != 0,
            };
            if m.map_page(va, pa, attrs, &mut frames).is_ok() {
                if let Some(e) = expect.iter_mut().find(|e| e.0 == va) {
                    // Only identical remaps succeed.
                    assert_eq!((e.1, e.2), (pa, access));
                } else {
                    expect.push((va, pa, access));
                }
            }
        }
        assert!(expect.len() > 300);
        let mut leaves = 0;
        m.for_each_leaf(true, |_, d, level| {
            let leaf = Leaf::decode(d);
            assert!(!(leaf.writable && leaf.executable));
            assert_eq!(d & (1 << 2), 0);
            assert_eq!(level, 3);
            leaves += 1;
        });
        assert_eq!(leaves, expect.len());
        for (va, pa, access) in expect {
            assert_eq!(m.translate(va | 0x123), Some(pa | 0x123));
            let leaf = Leaf::decode(m.lookup(va).unwrap().0);
            assert_eq!(leaf.writable, access == Access::ReadWrite);
            assert_eq!(leaf.executable, access == Access::ReadExecute);
        }
    }

    #[test]
    fn protections_follow_cpuid() {
        // SMEP (leaf 7 EBX bit 7), SMAP (bit 20), UMIP (ECX bit 2), NX (ext
        // EDX bit 20).
        let all = Protections::from_cpuid(1 << 7 | 1 << 20, 1 << 2, 1 << 20);
        assert_eq!(
            all,
            Protections {
                nx: true,
                wp: true,
                smep: true,
                smap: true,
                umip: true
            }
        );
        let none = Protections::from_cpuid(0, 0, 0);
        assert!(none.wp && !none.nx && !none.smep && !none.smap && !none.umip);
        assert_eq!(none.apply_cr4(0x20), 0x20, "nothing added without CPUID");
        assert_eq!(all.apply_cr4(0x20), 0x20 | CR4_SMEP | CR4_SMAP | CR4_UMIP);
        let smep_only = Protections::from_cpuid(1 << 7, 0, 1 << 20);
        assert_eq!(smep_only.apply_cr4(0), CR4_SMEP);
        assert_eq!(none.apply_cr0(0x8000_0011), 0x8001_0011);
        // Never touches PGE (we map nothing global) or PCIDE.
        assert_eq!(all.apply_cr4(0) & ((1 << 7) | (1 << 17)), 0);
    }

    #[test]
    fn cr3_root_strips_flags_and_reserved_bits() {
        assert_eq!(cr3_root(0x1234_5000 | 0x18), 0x1234_5000);
        assert_eq!(cr3_root(0xfff0_0000_0000_0000 | 0x1000), 0x1000);
        assert_eq!(cr3_root(0x000f_ffff_ffff_f000), 0x000f_ffff_ffff_f000);
    }
}
