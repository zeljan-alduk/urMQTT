//! Physical frames as page-table builders and allocators see them.

/// Size of a page and of a physical frame (4 KiB on every supported
/// architecture).
pub const PAGE_SIZE: u64 = 4096;

/// Source of zeroed frames for new tables.
pub trait FrameSource {
    /// Physical address of a fresh, page-aligned frame, or `None` if exhausted.
    fn alloc_frame(&mut self) -> Option<u64>;
}
