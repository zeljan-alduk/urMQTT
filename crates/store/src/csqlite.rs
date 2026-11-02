//! The SQLite C library's functions, as the linker sees them (linked into
//! the dbworker and, on the host, into the test binaries; ADR-210).

#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_void};

use crate::ffi::{sqlite3_int64, sqlite3_vfs};

#[repr(C)]
pub struct sqlite3 {
    _private: [u8; 0],
}

#[repr(C)]
pub struct sqlite3_stmt {
    _private: [u8; 0],
}

#[repr(C)]
pub struct sqlite3_backup {
    _private: [u8; 0],
}

// SAFETY: the C declarations of the vendored SQLite amalgamation; each is called from `db.rs` /
// `lib.rs` with live handles and NUL-terminated strings, as the C API requires.
unsafe extern "C" {
    pub fn sqlite3_config(op: c_int, ...) -> c_int;
    pub fn sqlite3_initialize() -> c_int;
    pub fn sqlite3_vfs_register(vfs: *mut sqlite3_vfs, make_default: c_int) -> c_int;
    pub fn sqlite3_libversion() -> *const c_char;
    pub fn sqlite3_open_v2(
        filename: *const c_char,
        db: *mut *mut sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    pub fn sqlite3_close_v2(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_db_config(db: *mut sqlite3, op: c_int, ...) -> c_int;
    pub fn sqlite3_extended_result_codes(db: *mut sqlite3, onoff: c_int) -> c_int;
    pub fn sqlite3_exec(
        db: *mut sqlite3,
        sql: *const c_char,
        callback: *const c_void,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    pub fn sqlite3_prepare_v3(
        db: *mut sqlite3,
        sql: *const c_char,
        nbyte: c_int,
        flags: u32,
        stmt: *mut *mut sqlite3_stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    pub fn sqlite3_bind_int64(stmt: *mut sqlite3_stmt, i: c_int, v: sqlite3_int64) -> c_int;
    pub fn sqlite3_bind_text(
        stmt: *mut sqlite3_stmt,
        i: c_int,
        v: *const c_char,
        n: c_int,
        destructor: isize,
    ) -> c_int;
    pub fn sqlite3_bind_blob(
        stmt: *mut sqlite3_stmt,
        i: c_int,
        v: *const c_void,
        n: c_int,
        destructor: isize,
    ) -> c_int;
    pub fn sqlite3_bind_null(stmt: *mut sqlite3_stmt, i: c_int) -> c_int;
    pub fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_clear_bindings(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_column_count(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_column_type(stmt: *mut sqlite3_stmt, i: c_int) -> c_int;
    pub fn sqlite3_column_int64(stmt: *mut sqlite3_stmt, i: c_int) -> sqlite3_int64;
    pub fn sqlite3_column_text(stmt: *mut sqlite3_stmt, i: c_int) -> *const u8;
    pub fn sqlite3_column_blob(stmt: *mut sqlite3_stmt, i: c_int) -> *const c_void;
    pub fn sqlite3_column_bytes(stmt: *mut sqlite3_stmt, i: c_int) -> c_int;
    pub fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
    pub fn sqlite3_errstr(code: c_int) -> *const c_char;
    pub fn sqlite3_extended_errcode(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_changes64(db: *mut sqlite3) -> sqlite3_int64;
    pub fn sqlite3_free(p: *mut c_void);
    pub fn sqlite3_backup_init(
        dest: *mut sqlite3,
        dest_name: *const c_char,
        src: *mut sqlite3,
        src_name: *const c_char,
    ) -> *mut sqlite3_backup;
    pub fn sqlite3_backup_step(p: *mut sqlite3_backup, pages: c_int) -> c_int;
    pub fn sqlite3_backup_finish(p: *mut sqlite3_backup) -> c_int;
    pub fn sqlite3_backup_remaining(p: *mut sqlite3_backup) -> c_int;
    pub fn sqlite3_backup_pagecount(p: *mut sqlite3_backup) -> c_int;
    pub fn sqlite3_bind_parameter_count(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_status64(
        op: c_int,
        current: *mut sqlite3_int64,
        highwater: *mut sqlite3_int64,
        reset: c_int,
    ) -> c_int;
}

/// `sqlite3_db_config` for the boolean options (the C function is variadic).
///
/// # Safety
/// A live connection and a valid `out` pointer.
pub unsafe fn db_config_flag(db: *mut sqlite3, option: c_int, on: c_int, out: *mut c_int) -> c_int {
    // SAFETY: the boolean options take (int, int*).
    unsafe { sqlite3_db_config(db, option, on, out) }
}
