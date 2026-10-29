//! SQLite inside the kernel (PROMPT §8, ADR-030): the vendored amalgamation
//! compiled freestanding, a raw-disk VFS over a block device, the data
//! disk layout and the broker's durable store. The telemetry log (M12)
//! will live in its own region of the same disk.
//!
//! Unsafe code is confined to the FFI layer (`ffi`, `vfs`, `db`, `libc`
//! and `init` below); layout, CRC, disk and store logic are safe Rust.

#![cfg_attr(not(test), no_std)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)
)]

extern crate alloc;

pub mod crc;
pub mod db;
pub mod disk;
mod ffi;
pub mod layout;
#[cfg(target_os = "none")]
mod libc;
pub mod schema;
pub mod store;
pub mod telemetry;
pub mod vfs;

use core::ffi::{CStr, c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

pub use disk::{BlockDevice, Disk, DiskError, IoError, MemDisk, Opened};
pub use store::{OpenInfo, Queued, Retained, SessionRecord, Store, StoreError, open};
pub use vfs::Platform;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Installs `disk` as the VFS backing store and, on first use, gives SQLite
/// its fixed `memsys5` heap and initialises the library. Later calls (host
/// tests) only swap the disk; the heap of the first call stays in use.
pub fn init(heap: &'static mut [u8], disk: Disk, platform: Platform) -> Result<(), StoreError> {
    vfs::install(disk, platform);
    // Relaxed: initialisation happens on one core before any other use.
    if INITIALIZED.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let len = c_int::try_from(heap.len()).map_err(|_| StoreError::Init(ffi::SQLITE_NOMEM))?;
    // SAFETY: the region is `'static`, exclusively ours, 8-byte aligned
    // (page-aligned in the kernel) and configured before initialisation.
    let rc = unsafe {
        ffi::sqlite3_config(
            ffi::SQLITE_CONFIG_HEAP,
            heap.as_mut_ptr().cast::<c_void>(),
            len,
            64 as c_int,
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(StoreError::Init(rc));
    }
    // Memory statistics for the boot log and M15 (one core: no lock cost).
    // SAFETY: boolean option, before initialisation.
    let rc = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_MEMSTATUS, 1 as c_int) };
    if rc != ffi::SQLITE_OK {
        return Err(StoreError::Init(rc));
    }
    let cb: ffi::LogCallback = log_callback;
    // SAFETY: a valid callback that outlives SQLite, and a null context.
    let rc =
        unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_LOG, cb, core::ptr::null_mut::<c_void>()) };
    if rc != ffi::SQLITE_OK {
        return Err(StoreError::Init(rc));
    }
    // SAFETY: configured above; registers our VFS through `sqlite3_os_init`.
    let rc = unsafe { ffi::sqlite3_initialize() };
    if rc != ffi::SQLITE_OK {
        return Err(StoreError::Init(rc));
    }
    Ok(())
}

unsafe extern "C" fn log_callback(_ctx: *mut c_void, code: c_int, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    // SAFETY: SQLite passes a NUL-terminated message valid for this call.
    let m = unsafe { CStr::from_ptr(msg) };
    if let Some(p) = vfs::platform() {
        (p.log)(code, m.to_str().unwrap_or("(invalid utf-8)"));
    }
}
