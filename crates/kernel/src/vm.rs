//! The kernel's own address space (M2).
//!
//! Built once on the boot CPU from the Limine memory map, then activated by
//! switching TTBR1. Guarantees:
//! - W^X: text RX, rodata R, everything else RW-NX, plus `SCTLR_EL1.WXN`.
//!   The HHDM alias of the kernel image is read-only.
//! - The lower half is disabled (`TCR_EL1.EPD0`): null and user pointers fault.
//! - Every stack has unmapped guard pages; exceptions run on a separate stack.
//! - After [`lock`], page-table frames are read-only in the HHDM and every
//!   mapping request fails: nothing is ever remapped at runtime.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use limine::memmap::{
    MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_FRAMEBUFFER, MEMMAP_MAPPED_RESERVED, MEMMAP_USABLE,
};
use urmqtt_arch_aarch64::paging::{
    Access, BLOCK_2M, Leaf, MapError, Mapper, MemType, PAGE_SIZE, PageAttrs,
};
use urmqtt_arch_aarch64::sync::SpinLock;
use urmqtt_arch_aarch64::{cpu, regs};
use urmqtt_mm::BumpFrames;
use urmqtt_mm::buddy::{self, BuddyHeap};
use urmqtt_mm::frames::{self, FrameAllocator};

use crate::layout;
use crate::memory::{BootMemory, HhdmTables, is_ram};

/// Physical frames for everything except page tables.
pub static FRAMES: SpinLock<Option<FrameAllocator<'static>>> = SpinLock::new(None);

struct KernelSpace {
    root: u64,
    /// Page-table frames: (base, len), 2 MiB aligned. Read-only in the HHDM;
    /// writable only through the alias at `PT_ALIAS_BASE` until `lock`.
    pool: (u64, u64),
    pool_frames: BumpFrames,
}

impl KernelSpace {
    /// Table accessor through the writable alias of the pool.
    fn tables(&self) -> HhdmTables {
        HhdmTables {
            hhdm: layout::PT_ALIAS_BASE.wrapping_sub(self.pool.0),
        }
    }
}

static SPACE: SpinLock<Option<KernelSpace>> = SpinLock::new(None);
static LOCKED: AtomicBool = AtomicBool::new(false);
static HHDM: AtomicU64 = AtomicU64::new(0);

/// HHDM offset (valid once `build` has run or the boot code set it).
pub fn hhdm() -> u64 {
    // Relaxed: written once on the boot CPU before any reader.
    HHDM.load(Ordering::Relaxed)
}

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

fn sym(s: &'static u8) -> u64 {
    core::ptr::from_ref(s) as u64
}

/// Kernel image sections as `[start, end)` virtual addresses.
pub fn kernel_sections() -> [(u64, u64, PageAttrs, &'static str); 3] {
    // SAFETY: linker-defined symbols; only their addresses are taken.
    let (ts, te, rs, re, ds, ke) = unsafe {
        (
            sym(&__text_start),
            sym(&__text_end),
            sym(&__rodata_start),
            sym(&__rodata_end),
            sym(&__data_start),
            sym(&__kernel_end),
        )
    };
    [
        (ts, te, PageAttrs::text(false), "text"),
        (rs, re, PageAttrs::rodata(), "rodata"),
        (ds, ke, PageAttrs::data(), "data"),
    ]
}

/// What `build` produced for the boot CPU.
pub struct Built {
    pub main_top: u64,
    pub exc_top: u64,
    pub heap_order: u32,
    pub heap_meta_words: usize,
    pub pt_frames: u64,
    pub free_frames: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum BuildError {
    NoRam,
    HhdmOverlapsLayout,
    NoBitmapSpace,
    NoPool,
    OutOfFrames,
    // Read through `Debug` in the fatal boot message.
    #[allow(dead_code)]
    Map(MapError),
}

impl From<MapError> for BuildError {
    fn from(e: MapError) -> Self {
        Self::Map(e)
    }
}

/// Allocates a fresh frame from the global allocator (for data pages).
fn data_frame() -> Result<u64, BuildError> {
    FRAMES
        .lock()
        .as_mut()
        .and_then(FrameAllocator::alloc)
        .ok_or(BuildError::OutOfFrames)
}

/// Builds the kernel address space. Nothing changes for the CPU until
/// [`activate`].
pub fn build(
    mem: &BootMemory,
    phys_base: u64,
    virt_base: u64,
    bti: bool,
    heap_mb: u32,
) -> Result<Built, BuildError> {
    let hhdm = mem.hhdm();
    // Relaxed: see `hhdm`.
    HHDM.store(hhdm, Ordering::Relaxed);
    let entries = mem.entries();

    // 1. Frame allocator over the span of RAM.
    let (lo, hi) = entries
        .iter()
        .filter(|e| is_ram(e.type_))
        .fold((u64::MAX, 0u64), |(lo, hi), e| {
            (lo.min(e.base), hi.max(e.base + e.length))
        });
    if lo >= hi {
        return Err(BuildError::NoRam);
    }
    if hhdm
        .checked_add(hi)
        .is_none_or(|end| end > layout::MMIO_BASE)
    {
        return Err(BuildError::HhdmOverlapsLayout);
    }
    let lo = lo / PAGE_SIZE * PAGE_SIZE;
    let span_frames = (hi - lo).div_ceil(PAGE_SIZE) as usize;
    let bitmap_len = frames::bitmap_bytes(hi - lo) as u64;
    let bitmap_pages = bitmap_len.div_ceil(PAGE_SIZE);
    let early = mem.early_frames_range().unwrap_or((0, 0));
    let bitmap_pa = entries
        .iter()
        .filter(|e| e.type_ == MEMMAP_USABLE && e.base % PAGE_SIZE == 0)
        .find(|e| {
            e.length >= bitmap_pages * PAGE_SIZE
                && (e.base + bitmap_pages * PAGE_SIZE <= early.0 || e.base >= early.0 + early.1)
        })
        .map(|e| e.base)
        .ok_or(BuildError::NoBitmapSpace)?;
    // SAFETY: `bitmap_pa` starts a usable RAM region mapped in the HHDM,
    // reserved below so nothing else ever gets these frames.
    let bitmap: &'static mut [u64] = unsafe {
        core::slice::from_raw_parts_mut((hhdm + bitmap_pa) as *mut u64, (bitmap_len / 8) as usize)
    };
    let mut fa = FrameAllocator::new(bitmap, lo, span_frames).ok_or(BuildError::NoBitmapSpace)?;
    for e in entries.iter().filter(|e| e.type_ == MEMMAP_USABLE) {
        fa.add_free_range(e.base, e.length);
    }
    fa.reserve_range(bitmap_pa, bitmap_pages * PAGE_SIZE);
    fa.reserve_range(early.0, early.1);

    // 2. A contiguous pool for every page table of the new address space.
    let heap_bytes = u64::from(heap_mb) << 20;
    let heap_order = heap_bytes.trailing_zeros();
    let meta_bytes = buddy::bitmap_bytes(heap_order) as u64;
    let span_gib = (hi - lo).div_ceil(1 << 30);
    let need = 128 + 4 * span_gib + (heap_bytes + meta_bytes) / (PAGE_SIZE * 512) + 8;
    // Whole 2 MiB blocks so the pool can be aliased and unaliased with block
    // mappings (see `lock`).
    let pool_frames = need.next_multiple_of(512);
    let pool_pa = fa
        .alloc_contiguous(pool_frames as usize, 512)
        .ok_or(BuildError::NoPool)?;
    let pool = (pool_pa, pool_frames * PAGE_SIZE);
    let mut pt = BumpFrames::new(pool.0, pool.1);
    *FRAMES.lock() = Some(fa);

    let mut tables = HhdmTables { hhdm };
    let root =
        urmqtt_arch_aarch64::paging::FrameSource::alloc_frame(&mut pt).ok_or(BuildError::NoPool)?;
    for i in 0..512 {
        urmqtt_arch_aarch64::paging::TableMemory::write(&mut tables, root, i, 0);
    }
    let mut m = Mapper::new(&mut tables, root);

    // 3. Kernel image.
    for (start, end, mut attrs, _) in kernel_sections() {
        if matches!(attrs.access, Access::ReadExecute) {
            attrs.bti_guarded = bti;
        }
        let pa = start - virt_base + phys_base;
        m.map_range(start, pa, end - start, attrs, &mut pt)?;
    }

    // 4. HHDM, same offset as the bootloader's so its pointers stay valid.
    for e in entries {
        let attrs = match e.type_ {
            MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE => PageAttrs::data(),
            MEMMAP_FRAMEBUFFER => PageAttrs {
                access: Access::ReadWrite,
                mem: MemType::Framebuffer,
                bti_guarded: false,
            },
            // The kernel image's alias must not be writable (W^X), firmware
            // tables are only ever read.
            MEMMAP_EXECUTABLE_AND_MODULES
            | MEMMAP_ACPI_RECLAIMABLE
            | MEMMAP_ACPI_NVS
            | MEMMAP_MAPPED_RESERVED => PageAttrs::rodata(),
            _ => continue,
        };
        let start = e.base / PAGE_SIZE * PAGE_SIZE;
        let end = (e.base + e.length).next_multiple_of(PAGE_SIZE);
        map_hhdm_range(&mut m, hhdm, start, end, attrs, pool, &mut pt)?;
    }

    // 5. Device mappings made so far.
    crate::memory::replay_mmio(&mut m, &mut pt)?;

    // 5b. Writable alias of the page-table pool (removed by `lock`).
    for off in (0..pool.1).step_by(BLOCK_2M as usize) {
        m.map_block_2m(
            layout::PT_ALIAS_BASE + off,
            pool.0 + off,
            PageAttrs::data(),
            &mut pt,
        )?;
    }

    // 6. Boot CPU stacks (guard pages stay unmapped).
    let ((exc_lo, exc_hi), (main_lo, main_hi)) = layout::stacks(0);
    for va in (exc_lo..exc_hi)
        .step_by(PAGE_SIZE as usize)
        .chain((main_lo..main_hi).step_by(PAGE_SIZE as usize))
    {
        m.map_page(va, data_frame()?, PageAttrs::data(), &mut pt)?;
    }

    // 7. Heap and its bookkeeping.
    for off in (0..heap_bytes).step_by(PAGE_SIZE as usize) {
        m.map_page(
            layout::HEAP_BASE + off,
            data_frame()?,
            PageAttrs::data(),
            &mut pt,
        )?;
    }
    let meta_size = meta_bytes.next_multiple_of(PAGE_SIZE);
    for off in (0..meta_size).step_by(PAGE_SIZE as usize) {
        m.map_page(
            layout::HEAP_META_BASE + off,
            data_frame()?,
            PageAttrs::data(),
            &mut pt,
        )?;
    }

    let used_pt = pool_frames - pt.remaining().1 / PAGE_SIZE;
    let free_frames = FRAMES
        .lock()
        .as_ref()
        .map_or(0, FrameAllocator::free_frames);
    *SPACE.lock() = Some(KernelSpace {
        root,
        pool,
        pool_frames: pt,
    });
    Ok(Built {
        main_top: main_hi,
        exc_top: exc_hi,
        heap_order,
        heap_meta_words: (meta_bytes / 8) as usize,
        pt_frames: used_pt,
        free_frames,
    })
}

/// Maps `[start, end)` of physical memory at `hhdm + pa`, with 2 MiB blocks
/// where possible, the page-table pool read-only, and tolerating overlap at
/// unaligned edges.
fn map_hhdm_range(
    m: &mut Mapper<'_, HhdmTables>,
    hhdm: u64,
    start: u64,
    end: u64,
    attrs: PageAttrs,
    pool: (u64, u64),
    pt: &mut BumpFrames,
) -> Result<(), MapError> {
    let mut pa = start;
    while pa < end {
        let in_pool = pa >= pool.0 && pa < pool.0 + pool.1;
        let attrs = if in_pool { PageAttrs::rodata() } else { attrs };
        if pa.is_multiple_of(BLOCK_2M) && end - pa >= BLOCK_2M {
            m.map_block_2m(hhdm + pa, pa, attrs, pt)?;
            pa += BLOCK_2M;
            continue;
        }
        match m.map_page(hhdm + pa, pa, attrs, pt) {
            // An unaligned neighbour already mapped the shared page.
            Ok(()) | Err(MapError::AlreadyMapped) => {}
            Err(e) => return Err(e),
        }
        pa += PAGE_SIZE;
    }
    Ok(())
}

const TCR_EPD0: u64 = 1 << 7;
const SCTLR_WXN: u64 = 1 << 19;

/// Switches TTBR1 to the kernel tables, disables the lower half and turns
/// on WXN. The current stack (bootloader memory) stays mapped.
pub fn activate() {
    let Some(root) = SPACE.lock().as_ref().map(|s| s.root) else {
        return;
    };
    cpu::dsb_ishst();
    // SAFETY: the new tables map the kernel image, the HHDM (including the
    // current stack) and all MMIO at the same addresses as before.
    unsafe { regs::set_ttbr1_el1(root) };
    // SAFETY: nothing uses the lower half (TTBR0) once the bootloader's
    // identity assumptions are gone; walks there now fault.
    unsafe { regs::set_tcr_el1(regs::tcr_el1() | TCR_EPD0) };
    // SAFETY: no mapping is both writable and executable (audited later),
    // so enforcing WXN changes nothing for valid code.
    unsafe { regs::set_sctlr_el1(regs::sctlr_el1() | SCTLR_WXN) };
    cpu::isb();
    cpu::tlb_flush_all();
    crate::memory::retire_early_mmio();
}

/// Maps device pages into the kernel tables (after `activate`, before `lock`).
pub fn map_device(va: u64, pa: u64, len: u64) -> Result<(), MapError> {
    if LOCKED.load(Ordering::Acquire) {
        return Err(MapError::AlreadyMapped);
    }
    let mut guard = SPACE.lock();
    let s = guard.as_mut().ok_or(MapError::OutOfFrames)?;
    let mut tables = s.tables();
    Mapper::new(&mut tables, s.root).map_range_auto(
        va,
        pa,
        len,
        PageAttrs::mmio(),
        &mut s.pool_frames,
    )?;
    cpu::dsb_ishst();
    cpu::isb();
    Ok(())
}

/// Maps the stacks of CPU `cpu` (before `lock`).
pub fn map_stacks(cpu: u64) -> Result<(), MapError> {
    if LOCKED.load(Ordering::Acquire) {
        return Err(MapError::AlreadyMapped);
    }
    let mut guard = SPACE.lock();
    let s = guard.as_mut().ok_or(MapError::OutOfFrames)?;
    let mut tables = s.tables();
    let mut m = Mapper::new(&mut tables, s.root);
    let ((exc_lo, exc_hi), (main_lo, main_hi)) = layout::stacks(cpu);
    for va in (exc_lo..exc_hi)
        .step_by(PAGE_SIZE as usize)
        .chain((main_lo..main_hi).step_by(PAGE_SIZE as usize))
    {
        let frame = data_frame().map_err(|_| MapError::OutOfFrames)?;
        m.map_page(va, frame, PageAttrs::data(), &mut s.pool_frames)?;
    }
    cpu::dsb_ishst();
    cpu::isb();
    Ok(())
}

/// Zeroed, physically contiguous frames for device DMA, reached through
/// the HHDM: (virtual address, physical address, bytes).
pub fn dma_alloc(bytes: usize) -> Option<(usize, u64, usize)> {
    let pages = bytes.div_ceil(PAGE_SIZE as usize).max(1);
    let pa = FRAMES.lock().as_mut()?.alloc_contiguous(pages, 1)?;
    let va = (hhdm() + pa) as usize;
    let len = pages * PAGE_SIZE as usize;
    // SAFETY: freshly allocated RAM, mapped RW in the HHDM, owned by the caller.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, len) };
    Some((va, pa, len))
}

/// Returns the frames lent to the bootloader-table extensions.
pub fn retire_early_frames(range: (u64, u64)) {
    if let Some(fa) = FRAMES.lock().as_mut() {
        fa.add_free_range(range.0, range.1);
    }
}

/// Removes the only writable mapping of the page tables and refuses further
/// mappings. Returns the size of the (now read-only) page-table pool.
pub fn lock() -> Result<u64, MapError> {
    let mut guard = SPACE.lock();
    let s = guard.as_mut().ok_or(MapError::OutOfFrames)?;
    // Release: pairs with the Acquire in `map_device`; once set, no new
    // mapping is attempted.
    LOCKED.store(true, Ordering::Release);
    let mut tables = s.tables();
    let m = Mapper::new(&mut tables, s.root);
    // The level-2 table holding the alias's block entries lives in the pool
    // too; every write below goes through the alias, so the block that maps
    // that table itself must be removed last.
    let l2 = l2_table_of(&m, layout::PT_ALIAS_BASE).ok_or(MapError::BlockInTheWay)?;
    let blocks = s.pool.1 / BLOCK_2M;
    let own = (l2 - s.pool.0) / BLOCK_2M;
    let alias = s.tables();
    let mut writer = AliasWriter { tables: alias, l2 };
    for b in (0..blocks).filter(|&b| b != own) {
        writer.unmap(b);
    }
    writer.unmap(own);
    cpu::tlb_flush_all();
    Ok(s.pool.1)
}

/// Clears level-2 entries of the alias region.
struct AliasWriter {
    tables: HhdmTables,
    l2: u64,
}

impl AliasWriter {
    fn unmap(&mut self, block: u64) {
        let idx = urmqtt_arch_aarch64::paging::index(layout::PT_ALIAS_BASE + block * BLOCK_2M, 2);
        urmqtt_arch_aarch64::paging::TableMemory::write(&mut self.tables, self.l2, idx, 0);
        cpu::tlb_flush_va(layout::PT_ALIAS_BASE + block * BLOCK_2M);
    }
}

/// Physical address of the level-2 table covering `va` (which must be
/// mapped by a 2 MiB block).
fn l2_table_of(m: &Mapper<'_, HhdmTables>, va: u64) -> Option<u64> {
    let (_, level) = m.lookup(va)?;
    if level != 2 {
        return None;
    }
    m.table_at_level(va, 2)
}

/// Decoded leaf mapping `va` in the kernel tables, if any.
pub fn leaf_at(va: u64) -> Option<Leaf> {
    let guard = SPACE.lock();
    let s = guard.as_ref()?;
    let mut tables = HhdmTables { hhdm: hhdm() };
    let m = Mapper::new(&mut tables, s.root);
    m.lookup(va).map(|(d, _)| Leaf::decode(d))
}

/// Whether any page of the kernel image is writable through the HHDM.
pub fn kernel_alias_writable() -> bool {
    let [(ts, _, _, _), _, (_, ke, _, _)] = kernel_sections();
    let Some(text_pa) = phys_of(ts) else {
        return true;
    };
    let pages = (ke - ts).div_ceil(PAGE_SIZE);
    (0..pages).any(|i| leaf_at(hhdm() + text_pa + i * PAGE_SIZE).is_some_and(|l| l.writable))
}

fn phys_of(va: u64) -> Option<u64> {
    let guard = SPACE.lock();
    let s = guard.as_ref()?;
    let mut tables = HhdmTables { hhdm: hhdm() };
    Mapper::new(&mut tables, s.root).translate(va)
}

/// Result of a full walk of the kernel tables.
pub struct Audit {
    pub leaves: u64,
    pub writable_and_executable: u64,
    pub executable_outside_text: u64,
}

/// Walks every leaf and checks W^X and that only kernel text is executable.
pub fn audit() -> Option<Audit> {
    let guard = SPACE.lock();
    let s = guard.as_ref()?;
    // Reads go through the HHDM, which maps the pool read-only.
    let mut tables = HhdmTables { hhdm: hhdm() };
    let m = Mapper::new(&mut tables, s.root);
    let [(ts, te, _, _), ..] = kernel_sections();
    let mut a = Audit {
        leaves: 0,
        writable_and_executable: 0,
        executable_outside_text: 0,
    };
    m.for_each_leaf(true, |va, desc, _| {
        let leaf = Leaf::decode(desc);
        a.leaves += 1;
        if leaf.writable && leaf.executable {
            a.writable_and_executable += 1;
        }
        if leaf.executable && !(ts..te).contains(&va) {
            a.executable_outside_text += 1;
        }
    });
    Some(a)
}

/// The kernel heap allocator.
#[global_allocator]
pub static HEAP: urmqtt_mm::LockedHeap = urmqtt_mm::LockedHeap::new();

/// Initialises the heap mapped by `build`.
pub fn init_heap(order: u32, meta_words: usize) -> Result<(), buddy::HeapError> {
    // SAFETY: `build` mapped `2^order` bytes at HEAP_BASE and `meta_words`
    // words at HEAP_META_BASE, RW and used by nothing else; HEAP_BASE is
    // aligned far beyond `2^order`.
    let heap = unsafe {
        BuddyHeap::new(
            layout::HEAP_BASE as usize,
            order,
            layout::HEAP_META_BASE as *mut u64,
            meta_words,
        )
    }?;
    HEAP.init(heap);
    Ok(())
}
