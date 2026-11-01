//! Fixed virtual addresses of the worker's address space. Everything is in
//! the lower half; nothing here is a kernel address.

/// Start of the image (code, then read-only data, then data and bss).
pub const IMAGE_BASE: u64 = 0x0040_0000;
/// The image, including its bss, must end below this address.
pub const IMAGE_LIMIT: u64 = 0x0400_0000;
/// The shared window: one header page, then the I/O area.
pub const SHM_BASE: u64 = 0x1000_0000;
/// The header page of the shared window.
pub const SHM_HEADER: usize = 4096;
/// Bytes of the I/O area behind the header (1 MiB).
pub const SHM_IO: usize = 1 << 20;
/// Total bytes of the shared window.
pub const SHM_LEN: usize = SHM_HEADER + SHM_IO;
/// Lowest address of the worker's stack; a guard page lies below it.
pub const STACK_BASE: u64 = 0x2000_0000;
/// Bytes of the stack (SQLite's deepest recursion with a margin).
pub const STACK_LEN: usize = 256 * 1024;
/// The SQLite heap.
pub const HEAP_BASE: u64 = 0x4000_0000;

/// Top of the stack (initial stack pointer).
pub const STACK_TOP: u64 = STACK_BASE + STACK_LEN as u64;
