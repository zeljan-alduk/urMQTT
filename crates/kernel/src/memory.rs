//! Boot-time view of memory: the Limine memory map, the HHDM and an MMIO
//! window carved into the bootloader's higher-half tables.
//!
//! M2 replaces the bootloader tables with the kernel's own W^X tables; until
//! then this module is the only place that touches translation tables.

#![allow(unsafe_code)]

use limine::memmap::{
    Entry, MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_FRAMEBUFFER, MEMMAP_MAPPED_RESERVED, MEMMAP_USABLE,
};
use urmqtt_arch_aarch64::paging::{
    self, MapError, Mapper, MemType, PAGE_SIZE, PageAttrs, TableMemory,
};
use urmqtt_arch_aarch64::{cpu, regs};
use urmqtt_log::info;
use urmqtt_mm::BumpFrames;
use urmqtt_platform::acpi::PhysMemory;
use urmqtt_platform::fdt::Fdt;

/// Frames reserved for MMIO page tables before the real allocator exists.
const EARLY_TABLE_FRAMES: u64 = 64;
/// Size of the MMIO window (one level-0 slot is 512 GiB; we use 1 GiB).
const MMIO_WINDOW: u64 = 1 << 30;

pub struct BootMemory {
    hhdm: u64,
    map: &'static [&'static Entry],
}

/// Memory types that base revision >= 4 maps into the HHDM.
const fn hhdm_mapped(kind: u64) -> bool {
    matches!(
        kind,
        MEMMAP_USABLE
            | MEMMAP_BOOTLOADER_RECLAIMABLE
            | MEMMAP_EXECUTABLE_AND_MODULES
            | MEMMAP_FRAMEBUFFER
            | MEMMAP_ACPI_RECLAIMABLE
            | MEMMAP_ACPI_NVS
            | MEMMAP_MAPPED_RESERVED
    )
}

const fn kind_name(kind: u64) -> &'static str {
    match kind {
        MEMMAP_USABLE => "usable",
        MEMMAP_BOOTLOADER_RECLAIMABLE => "bootloader-reclaimable",
        MEMMAP_EXECUTABLE_AND_MODULES => "kernel",
        MEMMAP_FRAMEBUFFER => "framebuffer",
        MEMMAP_ACPI_RECLAIMABLE => "acpi-reclaimable",
        MEMMAP_ACPI_NVS => "acpi-nvs",
        MEMMAP_MAPPED_RESERVED => "reserved-mapped",
        _ => "reserved",
    }
}

impl BootMemory {
    pub fn new(hhdm: u64, map: &'static [&'static Entry]) -> Self {
        Self { hhdm, map }
    }

    /// RAM the kernel can eventually use: usable plus reclaimable regions.
    pub fn ram_bytes(&self) -> u64 {
        self.map
            .iter()
            .filter(|e| {
                matches!(
                    e.type_,
                    MEMMAP_USABLE
                        | MEMMAP_BOOTLOADER_RECLAIMABLE
                        | MEMMAP_EXECUTABLE_AND_MODULES
                        | MEMMAP_ACPI_RECLAIMABLE
                )
            })
            .map(|e| e.length)
            .sum()
    }

    pub fn virt_to_phys(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.hhdm)
    }

    /// Whether `[pa, pa + len)` lies inside one HHDM-mapped region.
    fn is_mapped(&self, pa: u64, len: u64) -> bool {
        let Some(end) = pa.checked_add(len) else {
            return false;
        };
        self.map
            .iter()
            .any(|e| hhdm_mapped(e.type_) && pa >= e.base && end <= e.base + e.length)
    }

    /// The device tree at HHDM address `va`, bounded by its header size.
    pub fn fdt(&self, va: u64) -> Option<Fdt<'_>> {
        let pa = self.virt_to_phys(va)?;
        let header = self.bytes(pa, 40)?;
        let size = Fdt::total_size(header).ok()?;
        Fdt::new(self.bytes(pa, size)?).ok()
    }

    /// Steals `EARLY_TABLE_FRAMES` frames from the top of the largest usable
    /// region. M2's frame allocator must treat them as allocated.
    fn early_frames(&self) -> Option<BumpFrames> {
        let largest = self
            .map
            .iter()
            .filter(|e| e.type_ == MEMMAP_USABLE)
            .max_by_key(|e| e.length)?;
        let len = (EARLY_TABLE_FRAMES * PAGE_SIZE).min(largest.length);
        Some(BumpFrames::new(largest.base + largest.length - len, len))
    }

    pub fn log_summary(&self) {
        for e in self.map {
            info!(
                "memmap {:#014x}-{:#014x} {:>8} KiB {}",
                e.base,
                e.base + e.length,
                e.length >> 10,
                kind_name(e.type_)
            );
        }
    }
}

impl PhysMemory for BootMemory {
    fn bytes(&self, pa: u64, len: usize) -> Option<&[u8]> {
        if !self.is_mapped(pa, len as u64) {
            return None;
        }
        // SAFETY: the range is inside a region the bootloader mapped into the
        // HHDM, and firmware tables / the DTB are not modified while borrowed.
        Some(unsafe { core::slice::from_raw_parts((self.hhdm + pa) as *const u8, len) })
    }
}

/// Translation tables reached through the HHDM.
struct HhdmTables {
    hhdm: u64,
}

impl HhdmTables {
    /// Virtual address of entry `idx` (taken modulo 512) of a table frame.
    fn entry_addr(&self, table_pa: u64, idx: usize) -> u64 {
        self.hhdm + table_pa + 8 * (idx % paging::ENTRIES) as u64
    }
}

impl TableMemory for HhdmTables {
    fn read(&self, table_pa: u64, idx: usize) -> u64 {
        // SAFETY: table frames come from TTBR1 or from our early frames, both
        // in HHDM-mapped RAM; idx < 512 keeps the access inside the frame.
        unsafe { (self.entry_addr(table_pa, idx) as *const u64).read_volatile() }
    }

    fn write(&mut self, table_pa: u64, idx: usize, value: u64) {
        // SAFETY: as in `read`. Writes become visible to the walker after
        // the barrier in `MmioWindow::map`.
        unsafe { (self.entry_addr(table_pa, idx) as *mut u64).write_volatile(value) }
    }
}

/// A range of kernel virtual addresses for device mappings.
pub struct MmioWindow {
    base: u64,
    next: u64,
    root: u64,
    tables: HhdmTables,
    frames: BumpFrames,
}

impl MmioWindow {
    /// Claims a free level-0 slot of the higher-half tables and programs the
    /// kernel's MAIR attributes. `None` if no slot or no frames are free.
    pub fn new(mem: &BootMemory) -> Option<Self> {
        // SAFETY: indices 0 and 1 (used by the bootloader's mappings) are
        // preserved; the kernel's indices were unused until now.
        unsafe { regs::set_mair_el1(MemType::merge_into_mair(regs::mair_el1())) };
        cpu::isb();
        let root = regs::ttbr1_el1() & 0x0000_ffff_ffff_fffe;
        let mut tables = HhdmTables { hhdm: mem.hhdm };
        let slot = Mapper::new(&mut tables, root).free_l0_slot(256..511)?;
        let base = paging::upper_half_l0_base(slot);
        Some(Self {
            base,
            next: base,
            root,
            tables,
            frames: mem.early_frames()?,
        })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    /// Maps `len` bytes of device memory at `pa`; returns the virtual address.
    pub fn map(&mut self, _mem: &BootMemory, pa: u64, len: u64) -> Result<u64, MapError> {
        let page_off = pa % PAGE_SIZE;
        let pages = (page_off + len).div_ceil(PAGE_SIZE);
        let va = self.next;
        if va + pages * PAGE_SIZE > self.base + MMIO_WINDOW - PAGE_SIZE {
            return Err(MapError::OutOfFrames);
        }
        Mapper::new(&mut self.tables, self.root).map_range(
            va,
            pa - page_off,
            pages * PAGE_SIZE,
            PageAttrs::mmio(),
            &mut self.frames,
        )?;
        cpu::dsb_ishst();
        cpu::isb();
        self.next += pages * PAGE_SIZE;
        Ok(va + page_off)
    }

    /// An address inside the window that is guaranteed to be unmapped.
    pub fn unmapped_probe(&self) -> u64 {
        self.base + MMIO_WINDOW - PAGE_SIZE
    }
}
