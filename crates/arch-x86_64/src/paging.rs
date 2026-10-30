//! x86_64 4-level paging (X3). X1 provides the types and operations the
//! kernel's memory code names, with the aarch64 shapes; the walking and the
//! PTE encoding stop with a message until X3.

#![allow(unsafe_code)]

pub use urmqtt_sync::frame::{FrameSource, PAGE_SIZE};

/// Entries per table.
pub const ENTRIES: usize = 512;

/// Memory types (PAT indices in X3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemType {
    Normal = 0,
    Framebuffer = 1,
    Device = 2,
    DeviceStrict = 3,
    NonCacheable = 4,
}

/// Access permissions for a kernel mapping. Ring 3 never has access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadExecute,
    ReadOnly,
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

pub const BLOCK_2M: u64 = 2 << 20;

/// Decoded view of a leaf entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    pub pa: u64,
    pub writable: bool,
    pub executable: bool,
    pub attr_index: u8,
}

impl Leaf {
    pub const fn decode(_entry: u64) -> Self {
        panic!("x86_64: not implemented until X3 (paging)")
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
    Unaligned,
    NonCanonical,
    AlreadyMapped,
    BlockInTheWay,
    OutOfFrames,
}

/// Walks and edits one translation regime rooted at `root` (CR3 base).
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

    pub fn map_page<F: FrameSource>(
        &mut self,
        _va: u64,
        _pa: u64,
        _attrs: PageAttrs,
        _frames: &mut F,
    ) -> Result<(), MapError> {
        let _ = &self.mem;
        unimplemented_until!("X3 (paging)")
    }

    pub fn map_range<F: FrameSource>(
        &mut self,
        _va: u64,
        _pa: u64,
        _len: u64,
        _attrs: PageAttrs,
        _frames: &mut F,
    ) -> Result<(), MapError> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn map_block_2m<F: FrameSource>(
        &mut self,
        _va: u64,
        _pa: u64,
        _attrs: PageAttrs,
        _frames: &mut F,
    ) -> Result<(), MapError> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn map_range_auto<F: FrameSource>(
        &mut self,
        _va: u64,
        _pa: u64,
        _len: u64,
        _attrs: PageAttrs,
        _frames: &mut F,
    ) -> Result<(), MapError> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn set_page_access(&mut self, _va: u64, _access: Access) -> Result<(), MapError> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn for_each_leaf<G: FnMut(u64, u64, u8)>(&self, _upper: bool, _f: G) {
        unimplemented_until!("X3 (paging)")
    }

    pub fn lookup(&self, _va: u64) -> Option<(u64, u8)> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn table_at_level(&self, _va: u64, _level: u8) -> Option<u64> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn translate(&self, _va: u64) -> Option<u64> {
        unimplemented_until!("X3 (paging)")
    }

    pub fn free_l0_slot(&self, _range: core::ops::Range<usize>) -> Option<usize> {
        unimplemented_until!("X3 (paging)")
    }
}

/// Virtual base address covered by PML4 slot `slot` in the upper half.
pub const fn upper_half_l0_base(slot: usize) -> u64 {
    0xffff_0000_0000_0000 | ((slot as u64 & 0x1ff) << 39)
}

/// Activates a new root (CR3).
///
/// # Safety
/// `root` must map the running code, stack and data.
#[cfg(target_os = "none")]
pub unsafe fn activate(_root: u64) {
    unimplemented_until!("X3 (paging)")
}

#[cfg(target_os = "none")]
pub fn kernel_root() -> u64 {
    unimplemented_until!("X3 (paging)")
}

/// Merges the kernel's memory types into the PAT (aarch64: MAIR).
#[cfg(target_os = "none")]
pub fn merge_memory_attributes() {
    unimplemented_until!("X3 (PAT)")
}

#[cfg(target_os = "none")]
pub fn tlb_flush_all() {
    unimplemented_until!("X3 (paging)")
}

#[cfg(target_os = "none")]
pub fn tlb_flush_va(_va: u64) {
    unimplemented_until!("X3 (paging)")
}

/// Makes table updates visible before the new mappings are used (x86: a
/// compiler fence suffices; the TLB is flushed explicitly).
#[cfg(target_os = "none")]
#[inline(always)]
pub fn publish() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
