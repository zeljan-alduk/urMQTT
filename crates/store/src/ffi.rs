//! Types and constants of the SQLite C API subset we use (checked against
//! the vendored `sqlite3.h`, 3.54.1), and the functions: the C library's
//! (`csqlite`, linked into the dbworker and the host tests) or calls into
//! the worker (`remote`, in the kernel; ADR-210).

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_void};

pub type sqlite3_int64 = i64;

#[repr(C)]
pub struct sqlite3_file {
    pub methods: *const sqlite3_io_methods,
}

#[repr(C)]
pub struct sqlite3_io_methods {
    pub version: c_int,
    pub close: Option<unsafe extern "C" fn(*mut sqlite3_file) -> c_int>,
    pub read:
        Option<unsafe extern "C" fn(*mut sqlite3_file, *mut c_void, c_int, sqlite3_int64) -> c_int>,
    pub write: Option<
        unsafe extern "C" fn(*mut sqlite3_file, *const c_void, c_int, sqlite3_int64) -> c_int,
    >,
    pub truncate: Option<unsafe extern "C" fn(*mut sqlite3_file, sqlite3_int64) -> c_int>,
    pub sync: Option<unsafe extern "C" fn(*mut sqlite3_file, c_int) -> c_int>,
    pub file_size: Option<unsafe extern "C" fn(*mut sqlite3_file, *mut sqlite3_int64) -> c_int>,
    pub lock: Option<unsafe extern "C" fn(*mut sqlite3_file, c_int) -> c_int>,
    pub unlock: Option<unsafe extern "C" fn(*mut sqlite3_file, c_int) -> c_int>,
    pub check_reserved_lock: Option<unsafe extern "C" fn(*mut sqlite3_file, *mut c_int) -> c_int>,
    pub file_control: Option<unsafe extern "C" fn(*mut sqlite3_file, c_int, *mut c_void) -> c_int>,
    pub sector_size: Option<unsafe extern "C" fn(*mut sqlite3_file) -> c_int>,
    pub device_characteristics: Option<unsafe extern "C" fn(*mut sqlite3_file) -> c_int>,
    // Version 2 (shared memory) and 3 (mmap) are not provided: WAL runs in
    // exclusive locking mode without a shared-memory index (ADR-030).
    pub shm_map: Option<unsafe extern "C" fn()>,
    pub shm_lock: Option<unsafe extern "C" fn()>,
    pub shm_barrier: Option<unsafe extern "C" fn()>,
    pub shm_unmap: Option<unsafe extern "C" fn()>,
    pub fetch: Option<unsafe extern "C" fn()>,
    pub unfetch: Option<unsafe extern "C" fn()>,
}

#[repr(C)]
pub struct sqlite3_vfs {
    pub version: c_int,
    pub os_file_size: c_int,
    pub max_pathname: c_int,
    pub next: *mut sqlite3_vfs,
    pub name: *const c_char,
    pub app_data: *mut c_void,
    pub open: Option<
        unsafe extern "C" fn(
            *mut sqlite3_vfs,
            *const c_char,
            *mut sqlite3_file,
            c_int,
            *mut c_int,
        ) -> c_int,
    >,
    pub delete: Option<unsafe extern "C" fn(*mut sqlite3_vfs, *const c_char, c_int) -> c_int>,
    pub access:
        Option<unsafe extern "C" fn(*mut sqlite3_vfs, *const c_char, c_int, *mut c_int) -> c_int>,
    pub full_pathname:
        Option<unsafe extern "C" fn(*mut sqlite3_vfs, *const c_char, c_int, *mut c_char) -> c_int>,
    pub dl_open: Option<unsafe extern "C" fn()>,
    pub dl_error: Option<unsafe extern "C" fn()>,
    pub dl_sym: Option<unsafe extern "C" fn()>,
    pub dl_close: Option<unsafe extern "C" fn()>,
    pub randomness: Option<unsafe extern "C" fn(*mut sqlite3_vfs, c_int, *mut c_char) -> c_int>,
    pub sleep: Option<unsafe extern "C" fn(*mut sqlite3_vfs, c_int) -> c_int>,
    pub current_time: Option<unsafe extern "C" fn(*mut sqlite3_vfs, *mut f64) -> c_int>,
    pub get_last_error: Option<unsafe extern "C" fn(*mut sqlite3_vfs, c_int, *mut c_char) -> c_int>,
    pub current_time_int64:
        Option<unsafe extern "C" fn(*mut sqlite3_vfs, *mut sqlite3_int64) -> c_int>,
    pub set_system_call: Option<unsafe extern "C" fn()>,
    pub get_system_call: Option<unsafe extern "C" fn()>,
    pub next_system_call: Option<unsafe extern "C" fn()>,
}

pub const SQLITE_OK: c_int = 0;
pub const SQLITE_ERROR: c_int = 1;
pub const SQLITE_BUSY: c_int = 5;
pub const SQLITE_LOCKED: c_int = 6;
pub const SQLITE_NOMEM: c_int = 7;
pub const SQLITE_IOERR: c_int = 10;
pub const SQLITE_CORRUPT: c_int = 11;
pub const SQLITE_NOTFOUND: c_int = 12;
pub const SQLITE_FULL: c_int = 13;
pub const SQLITE_CANTOPEN: c_int = 14;
pub const SQLITE_NOTADB: c_int = 26;
pub const SQLITE_ROW: c_int = 100;
pub const SQLITE_DONE: c_int = 101;
pub const SQLITE_IOERR_READ: c_int = SQLITE_IOERR | (1 << 8);
pub const SQLITE_IOERR_SHORT_READ: c_int = SQLITE_IOERR | (2 << 8);
pub const SQLITE_IOERR_WRITE: c_int = SQLITE_IOERR | (3 << 8);
pub const SQLITE_IOERR_FSYNC: c_int = SQLITE_IOERR | (4 << 8);
pub const SQLITE_IOERR_TRUNCATE: c_int = SQLITE_IOERR | (6 << 8);
pub const SQLITE_IOERR_DELETE: c_int = SQLITE_IOERR | (10 << 8);

pub const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
pub const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
pub const SQLITE_OPEN_MAIN_DB: c_int = 0x0000_0100;
pub const SQLITE_OPEN_MAIN_JOURNAL: c_int = 0x0000_0800;
pub const SQLITE_OPEN_WAL: c_int = 0x0008_0000;
pub const SQLITE_OPEN_EXRESCODE: c_int = 0x0200_0000;

pub const SQLITE_ACCESS_EXISTS: c_int = 0;

pub const SQLITE_RANGE: c_int = 25;
pub const SQLITE_TOOBIG: c_int = 18;
pub const SQLITE_MISUSE: c_int = 21;
pub const SQLITE_FLOAT: c_int = 2;
pub const SQLITE_TEXT: c_int = 3;
pub const SQLITE_CONFIG_HEAP: c_int = 8;
pub const SQLITE_CONFIG_MEMSTATUS: c_int = 9;
pub const SQLITE_CONFIG_LOG: c_int = 16;
pub const SQLITE_DBCONFIG_ENABLE_TRIGGER: c_int = 1003;
pub const SQLITE_DBCONFIG_DEFENSIVE: c_int = 1010;
pub const SQLITE_DBCONFIG_ENABLE_VIEW: c_int = 1015;
pub const SQLITE_DBCONFIG_TRUSTED_SCHEMA: c_int = 1017;
pub const SQLITE_PREPARE_PERSISTENT: u32 = 0x01;

pub const SQLITE_INTEGER: c_int = 1;
pub const SQLITE_BLOB: c_int = 4;
pub const SQLITE_NULL: c_int = 5;
pub const SQLITE_STATUS_MEMORY_USED: c_int = 0;

/// `SQLITE_TRANSIENT`: SQLite copies the bound value before returning.
pub const SQLITE_TRANSIENT: isize = -1;

pub type LogCallback = unsafe extern "C" fn(*mut c_void, c_int, *const c_char);

#[cfg(not(sandboxed))]
pub use crate::csqlite::*;
#[cfg(sandboxed)]
pub use crate::remote::*;
