//! Boot-time view of memory: the Limine memory map, the HHDM, and the MMIO
//! registry that works both before and after the kernel's own page tables
//! take over (see `vm`).

#![allow(unsafe_code)]

use limine::memmap::{
    Entry, MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_FRAMEBUFFER, MEMMAP_MAPPED_RESERVED, MEMMAP_USABLE,
};
use urmqtt_arch_aarch64::paging::{
    self, MapError, Mapper, MemType, PAGE_SIZE, PageAttrs, TableMemory,
};
use urmqtt_arch_aarch64::sync::SpinLock;
use urmqtt_arch_aarch64::{cpu, regs};
use urmqtt_log::info;
use urmqtt_mm::BumpFrames;
use urmqtt_platform::acpi::PhysMemory;
use urmqtt_platform::fdt::Fdt;

use crate::layout::{MMIO_BASE, MMIO_SIZE};

/// Frames for page tables extending the bootloader's tables before the
/// frame allocator exists (MMIO mappings only).
const EARLY_TABLE_FRAMES: u64 = 64;
const MAX_MMIO_MAPPINGS: usize = 64;

pub struct BootMemory {
    hhdm: u64,
    map: &'static [&'static Entry],
}

/// Memory types that base revision >= 4 maps into the HHDM.
pub const fn hhdm_mapped(kind: u64) -> bool {
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

/// RAM-like types: what the kernel can eventually use.
pub const fn is_ram(kind: u64) -> bool {
    matches!(
        kind,
        MEMMAP_USABLE
            | MEMMAP_BOOTLOADER_RECLAIMABLE
            | MEMMAP_EXECUTABLE_AND_MODULES
            | MEMMAP_ACPI_RECLAIMABLE
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

    pub fn hhdm(&self) -> u64 {
        self.hhdm
    }

    pub fn entries(&self) -> &'static [&'static Entry] {
        self.map
    }

    pub fn ram_bytes(&self) -> u64 {
        self.map
            .iter()
            .filter(|e| is_ram(e.type_))
            .map(|e| e.length)
            .sum()
    }

    pub fn virt_to_phys(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.hhdm)
    }

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

    /// `EARLY_TABLE_FRAMES` frames from the top of the largest usable
    /// region. The frame allocator reserves them until they are retired.
    pub fn early_frames_range(&self) -> Option<(u64, u64)> {
        let largest = self
            .map
            .iter()
            .filter(|e| e.type_ == MEMMAP_USABLE)
            .max_by_key(|e| e.length)?;
        let len = (EARLY_TABLE_FRAMES * PAGE_SIZE).min(largest.length);
        Some((largest.base + largest.length - len, len))
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
        // SAFETY: the range is inside a region mapped into the HHDM (by the
        // bootloader, and identically by the kernel's tables), and firmware
        // tables / the DTB are not modified while borrowed.
        Some(unsafe { core::slice::from_raw_parts((self.hhdm + pa) as *const u8, len) })
    }
}

/// Translation tables reached through the HHDM.
pub struct HhdmTables {
    pub hhdm: u64,
}

impl HhdmTables {
    /// Virtual address of entry `idx` (taken modulo 512) of a table frame.
    fn entry_addr(&self, table_pa: u64, idx: usize) -> u64 {
        self.hhdm + table_pa + 8 * (idx % paging::ENTRIES) as u64
    }
}

impl TableMemory for HhdmTables {
    fn read(&self, table_pa: u64, idx: usize) -> u64 {
        // SAFETY: table frames are HHDM-mapped RAM (bootloader tables, early
        // frames or the kernel's page-table pool); the address stays inside
        // the 4 KiB frame.
        unsafe { (self.entry_addr(table_pa, idx) as *const u64).read_volatile() }
    }

    fn write(&mut self, table_pa: u64, idx: usize, value: u64) {
        // SAFETY: as in `read`; callers issue the barriers that make the
        // new entry visible to the table walker.
        unsafe { (self.entry_addr(table_pa, idx) as *mut u64).write_volatile(value) }
    }
}

#[derive(Clone, Copy)]
struct MmioMapping {
    va: u64,
    pa: u64,
    len: u64,
}

/// All device mappings, so they can be replayed into the kernel's tables.
struct Mmio {
    maps: [MmioMapping; MAX_MMIO_MAPPINGS],
    count: usize,
    next: u64,
    hhdm: u64,
    early: Option<(u64, BumpFrames)>,
}

static MMIO: SpinLock<Option<Mmio>> = SpinLock::new(None);

/// Prepares device mappings in the bootloader's tables. Returns false if the
/// MMIO slot is taken or no frames are available.
pub fn init_early_mmio(mem: &BootMemory) -> bool {
    // SAFETY: MAIR indices 0 and 1 (used by the bootloader's mappings) are
    // preserved; the kernel's indices were unused until now.
    unsafe { regs::set_mair_el1(MemType::merge_into_mair(regs::mair_el1())) };
    cpu::isb();
    let root = regs::ttbr1_el1() & 0x0000_ffff_ffff_fffe;
    let mut tables = HhdmTables { hhdm: mem.hhdm };
    let slot = paging::index(MMIO_BASE, 0);
    if Mapper::new(&mut tables, root)
        .free_l0_slot(slot..slot + 1)
        .is_none()
    {
        return false;
    }
    let Some((base, len)) = mem.early_frames_range() else {
        return false;
    };
    *MMIO.lock() = Some(Mmio {
        maps: [MmioMapping {
            va: 0,
            pa: 0,
            len: 0,
        }; MAX_MMIO_MAPPINGS],
        count: 0,
        next: MMIO_BASE,
        hhdm: mem.hhdm,
        early: Some((root, BumpFrames::new(base, len))),
    });
    true
}

/// Maps `len` bytes of device memory at `pa`; returns the virtual address.
/// Before the kernel tables are active this edits the bootloader's tables;
/// afterwards it goes through `vm` (and fails once the tables are locked).
pub fn map_mmio(pa: u64, len: u64) -> Result<u64, MapError> {
    let mut guard = MMIO.lock();
    let m = guard.as_mut().ok_or(MapError::OutOfFrames)?;
    let page_off = pa % PAGE_SIZE;
    let base = pa - page_off;
    let size = (page_off + len).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    // Large, block-aligned regions (PCIe ECAM) get a block-aligned VA so
    // they can be mapped with 2 MiB blocks instead of thousands of pages.
    let block = urmqtt_arch_aarch64::paging::BLOCK_2M;
    let va = if size >= block && base.is_multiple_of(block) {
        m.next.next_multiple_of(block)
    } else {
        m.next
    };
    if va + size > MMIO_BASE + MMIO_SIZE - PAGE_SIZE || m.count >= MAX_MMIO_MAPPINGS {
        return Err(MapError::OutOfFrames);
    }
    let hhdm = m.hhdm;
    match m.early.as_mut() {
        Some((root, frames)) => {
            let mut tables = HhdmTables { hhdm };
            Mapper::new(&mut tables, *root).map_range_auto(
                va,
                base,
                size,
                PageAttrs::mmio(),
                frames,
            )?;
            cpu::dsb_ishst();
            cpu::isb();
        }
        None => crate::vm::map_device(va, base, size)?,
    }
    if let Some(slot) = m.maps.get_mut(m.count) {
        *slot = MmioMapping {
            va,
            pa: base,
            len: size,
        };
    }
    m.count += 1;
    // Leave an unmapped page between mappings to catch overruns.
    m.next = va + size + PAGE_SIZE;
    Ok(va + page_off)
}

/// Replays every device mapping into a new table tree.
pub fn replay_mmio<M: TableMemory, F: paging::FrameSource>(
    mapper: &mut Mapper<'_, M>,
    frames: &mut F,
) -> Result<(), MapError> {
    let guard = MMIO.lock();
    let Some(m) = guard.as_ref() else {
        return Ok(());
    };
    for map in m.maps.iter().take(m.count) {
        mapper.map_range_auto(map.va, map.pa, map.len, PageAttrs::mmio(), frames)?;
    }
    Ok(())
}

/// Called once the kernel tables are active: later mappings go through `vm`.
pub fn retire_early_mmio() {
    if let Some(m) = MMIO.lock().as_mut() {
        m.early = None;
    }
}

/// An address in the MMIO window that is never mapped (for fault tests).
pub fn unmapped_mmio_probe() -> u64 {
    MMIO_BASE + MMIO_SIZE - PAGE_SIZE
}

/// Number of MMIO mappings and bytes mapped.
pub fn mmio_stats() -> (usize, u64) {
    MMIO.lock().as_ref().map_or((0, 0), |m| {
        (m.count, m.maps.iter().take(m.count).map(|x| x.len).sum())
    })
}
