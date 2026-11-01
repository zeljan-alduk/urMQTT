//! SQLite and the broker's durable store (PROMPT §8, ADR-030): a raw-disk
//! VFS over a block device, the data disk layout and the store itself.
//!
//! In the kernel the SQLite C library is **not linked**: it runs in the
//! unprivileged dbworker (ADR-210) and this crate talks to it through
//! `remote` (calls the kernel's transport carries into user mode) and
//! serves its VFS system calls (`vfs::syscall`). On the host, in the tests,
//! SQLite is linked directly, as before; with the `loopback` feature the
//! tests run through the same protocol, the worker's code in process. The
//! `worker` feature (set by the dbworker) builds the worker's half.
//!
//! Unsafe code is confined to the FFI layer (`ffi`, `csqlite`, `remote`,
//! `worker`, `vfs`, `db`, `libc` and `init` below); layout, CRC, disk and
//! store logic are safe Rust.

#![cfg_attr(not(test), no_std)]
// Unsafe code is allowed only in the modules named below (AUDIT.md H0-W7).
#![deny(unsafe_code)]
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

pub mod backup;
pub mod crc;
#[cfg(any(not(sandboxed), feature = "loopback"))]
#[allow(unsafe_code)] // the C library's functions
mod csqlite;
#[allow(unsafe_code)] // SQLite C API wrappers
pub mod db;
pub mod disk;
pub mod fault;
#[allow(unsafe_code)] // SQLite FFI declarations
mod ffi;
pub mod gpt;
pub mod install;
pub mod layout;
#[cfg(all(target_os = "none", feature = "worker"))]
#[allow(unsafe_code)] // libc functions SQLite links against
mod libc;
pub mod mig;
pub mod part;
pub mod ram;
#[cfg(sandboxed)]
#[allow(unsafe_code)] // the SQLite API as calls into the worker
pub mod remote;
pub mod schema;
pub mod scrub;
pub mod store;
pub mod telemetry;
#[allow(unsafe_code)] // the VFS SQLite calls back into
pub mod vfs;
#[cfg(any(feature = "worker", feature = "loopback"))]
#[allow(unsafe_code)] // the worker's half: dispatcher and VFS shim
pub mod worker;

#[cfg(direct_vfs)]
use core::ffi::{CStr, c_char, c_int, c_void};
#[cfg(any(direct_vfs, feature = "loopback"))]
use core::sync::atomic::{AtomicBool, Ordering};

pub use disk::{BlockDevice, Disk, DiskError, IoError, MemDisk, Opened};
pub use ram::RamDisk;
pub use store::{OpenInfo, Queued, Retained, SessionRecord, Store, StoreError, open};
pub use vfs::Platform;

#[cfg(any(direct_vfs, feature = "loopback"))]
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Installs `disk` as the VFS backing store and, on first use, gives SQLite
/// its fixed `memsys5` heap and initialises the library. Later calls (host
/// tests) only swap the disk; the heap of the first call stays in use.
///
/// Sandboxed (the kernel): the heap lives in the worker, `heap` is only a
/// placeholder, and SQLite is initialised in the worker on first use (and
/// again after every restart of the worker, by `remote`).
#[cfg(direct_vfs)]
#[allow(unsafe_code)] // SQLite configuration calls
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

/// See above. In the kernel the transport is installed by the caller
/// (`remote::install`) before this; with `loopback` the transport is the
/// in-process worker, installed here with `heap` as its SQLite heap.
#[cfg(sandboxed)]
pub fn init(heap: &'static mut [u8], disk: Disk, platform: Platform) -> Result<(), StoreError> {
    vfs::install(disk, platform);
    #[cfg(feature = "loopback")]
    // Relaxed: initialisation happens on one core before any other use.
    if !INITIALIZED.swap(true, Ordering::Relaxed) {
        worker::install_loopback(heap);
    }
    #[cfg(not(feature = "loopback"))]
    let _ = heap;
    remote::init().map_err(StoreError::Init)
}

#[cfg(direct_vfs)]
#[allow(unsafe_code)] // called by SQLite
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
