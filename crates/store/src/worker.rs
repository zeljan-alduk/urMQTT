//! The worker's half of the store (ADR-210, ADR-211): the dispatcher that
//! turns requests in the shared window into SQLite calls, and the VFS shim
//! whose callbacks are system calls to the kernel. It runs in the
//! unprivileged dbworker (EL0 / ring 3); with the `loopback` feature the
//! host tests run it in process, so the whole protocol is exercised by the
//! store's test suite.
//!
//! The worker has no allocator: handles live in fixed tables, SQL is copied
//! to a fixed buffer before it is used (SQLite does I/O, which reuses the
//! I/O area, while it parses), and the SQLite heap is the region the kernel
//! mapped for it.

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};

use urmqtt_usys::abi::hdr;
use urmqtt_usys::layout::{SHM_HEADER, SHM_IO};
use urmqtt_usys::proto::{self, Bind, Reader, Writer, op, vfs as v};

use crate::csqlite::*;
use crate::ffi::{
    LogCallback, SQLITE_ACCESS_EXISTS, SQLITE_CANTOPEN, SQLITE_CONFIG_HEAP, SQLITE_CONFIG_LOG,
    SQLITE_CONFIG_MEMSTATUS, SQLITE_DONE, SQLITE_ERROR, SQLITE_FULL, SQLITE_IOERR,
    SQLITE_IOERR_DELETE, SQLITE_IOERR_FSYNC, SQLITE_IOERR_READ, SQLITE_IOERR_SHORT_READ,
    SQLITE_IOERR_TRUNCATE, SQLITE_IOERR_WRITE, SQLITE_MISUSE, SQLITE_NOMEM, SQLITE_NOTFOUND,
    SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_EXRESCODE, SQLITE_OPEN_READWRITE, SQLITE_RANGE,
    SQLITE_ROW, SQLITE_TOOBIG, SQLITE_TRANSIENT, sqlite3_file, sqlite3_int64, sqlite3_io_methods,
    sqlite3_vfs,
};

/// What the worker needs from its environment.
#[derive(Clone, Copy)]
pub struct Ops {
    /// The shared window: `SHM_HEADER` bytes of header, then the I/O area.
    pub shm: *mut u8,
    /// Issues a system call (aarch64 `svc`, x86_64 `int 0xf0`; the host
    /// tests call the kernel's handler directly).
    pub sys: fn(u64, [u64; 6]) -> u64,
}

struct Global<T>(UnsafeCell<T>);
// SAFETY: the worker is single-threaded (and the host tests serialise).
unsafe impl<T> Sync for Global<T> {}

static OPS: Global<Option<Ops>> = Global(UnsafeCell::new(None));

/// Installs the environment. Call once before the first request.
///
/// # Safety
/// `ops.shm` must point to `SHM_HEADER + SHM_IO` bytes valid for the life of
/// the program, used by nothing else while a request runs.
pub unsafe fn install(ops: Ops) {
    // SAFETY: single-threaded start-up.
    unsafe { *OPS.0.get() = Some(ops) };
}

fn ops() -> Option<Ops> {
    // SAFETY: written once at start-up.
    unsafe { *OPS.0.get() }
}

fn sys(nr: u64, a: [u64; 6]) -> u64 {
    ops().map_or(u64::MAX, |o| (o.sys)(nr, a))
}

/// The I/O area. At most one borrow is alive at a time (see the module
/// comment: SQL is copied out before SQLite runs).
fn io() -> &'static mut [u8] {
    match ops() {
        // SAFETY: the window is valid for the life of the program and the
        // caller keeps to one borrow at a time.
        Some(o) => unsafe {
            core::slice::from_raw_parts_mut(o.shm.wrapping_add(SHM_HEADER), SHM_IO)
        },
        None => &mut [],
    }
}

fn hdr_get(off: usize) -> u64 {
    ops().map_or(0, |o| {
        // SAFETY: inside the header page of the window.
        unsafe { o.shm.wrapping_add(off).cast::<u64>().read_unaligned() }
    })
}

fn hdr_set(off: usize, v: u64) {
    if let Some(o) = ops() {
        // SAFETY: inside the header page of the window.
        unsafe { o.shm.wrapping_add(off).cast::<u64>().write_unaligned(v) };
    }
}

// ---- handle tables ----

const MAX_DB: usize = 64;
const MAX_STMT: usize = 4096;
const MAX_BACKUP: usize = 16;

struct Tables {
    dbs: [*mut sqlite3; MAX_DB],
    stmts: [*mut sqlite3_stmt; MAX_STMT],
    backups: [*mut sqlite3_backup; MAX_BACKUP],
}

static TABLES: Global<Tables> = Global(UnsafeCell::new(Tables {
    dbs: [core::ptr::null_mut(); MAX_DB],
    stmts: [core::ptr::null_mut(); MAX_STMT],
    backups: [core::ptr::null_mut(); MAX_BACKUP],
}));

fn tables() -> &'static mut Tables {
    // SAFETY: single-threaded.
    unsafe { &mut *TABLES.0.get() }
}

/// Stores `p` in a free slot; the handle is the index plus one (0: none).
fn put<T>(table: &mut [*mut T], p: *mut T) -> u64 {
    match table.iter().position(|s| s.is_null()) {
        Some(i) => {
            if let Some(slot) = table.get_mut(i) {
                *slot = p;
            }
            i as u64 + 1
        }
        None => 0,
    }
}

fn get<T>(table: &[*mut T], id: u64) -> *mut T {
    usize::try_from(id)
        .ok()
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| table.get(i))
        .copied()
        .unwrap_or(core::ptr::null_mut())
}

fn take<T>(table: &mut [*mut T], id: u64) -> *mut T {
    let p = get(table, id);
    if !p.is_null()
        && let Some(slot) = (id as usize).checked_sub(1).and_then(|i| table.get_mut(i))
    {
        *slot = core::ptr::null_mut();
    }
    p
}

// ---- the dispatcher ----

/// SQL is copied here before SQLite sees it.
static SQL: Global<[u8; 16 * 1024]> = Global(UnsafeCell::new([0; 16 * 1024]));

/// Copies the SQL of the request (the first `hdr::LEN` bytes of the I/O
/// area) to the private buffer, NUL-terminated.
fn take_sql() -> Option<(&'static [u8], &'static CStr)> {
    let n = usize::try_from(hdr_get(hdr::LEN)).ok()?;
    let src = io().get(..n)?;
    // SAFETY: single-threaded.
    let buf = unsafe { &mut *SQL.0.get() };
    let dst = buf.get_mut(..n)?;
    dst.copy_from_slice(src);
    *buf.get_mut(n)? = 0;
    let all = buf.get(..=n)?;
    let c = CStr::from_bytes_with_nul(all).ok()?;
    Some((all.get(..n)?, c))
}

/// Serves the request in the window; returns the exit code for the kernel
/// (0: answered, even if the answer is an error code).
pub fn dispatch() -> u64 {
    let o = hdr_get(hdr::OP);
    let mut a = [0u64; 6];
    for (i, w) in a.iter_mut().enumerate() {
        *w = hdr_get(hdr::ARG + 8 * i);
    }
    let (ret, ret2, len) = handle(o, a);
    hdr_set(hdr::RET, ret);
    hdr_set(hdr::RET2, ret2);
    hdr_set(hdr::LEN, len as u64);
    0
}

fn rc(r: c_int) -> (u64, u64, usize) {
    (r as u64, 0, 0)
}

fn handle(o: u64, a: [u64; 6]) -> (u64, u64, usize) {
    let t = tables();
    match o {
        op::INIT => rc(init(a[0], a[1])),
        op::VERSION => {
            // SAFETY: no preconditions.
            let p = unsafe { sqlite3_libversion() };
            // SAFETY: a static NUL-terminated string.
            let s = unsafe { CStr::from_ptr(p) }.to_bytes();
            let out = io();
            let n = s.len().min(out.len());
            if let (Some(d), Some(sp)) = (out.get_mut(..n), s.get(..n)) {
                d.copy_from_slice(sp);
            }
            (0, 0, n)
        }
        op::OPEN => {
            let name = if a[0] == v::FILE_BACKUP {
                crate::vfs::BACKUP_NAME
            } else {
                crate::vfs::DB_NAME
            };
            let mut db = core::ptr::null_mut();
            let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXRESCODE;
            // SAFETY: valid NUL-terminated names and an out pointer.
            let r = unsafe {
                sqlite3_open_v2(name.as_ptr(), &mut db, flags, crate::vfs::VFS_NAME.as_ptr())
            };
            let id = if db.is_null() { 0 } else { put(&mut t.dbs, db) };
            if id == 0 && !db.is_null() {
                // SAFETY: the connection we just opened.
                unsafe { sqlite3_close_v2(db) };
                return (SQLITE_NOMEM as u64, 0, 0);
            }
            (r as u64, id, 0)
        }
        op::CLOSE => {
            let db = take(&mut t.dbs, a[0]);
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a connection of ours, closed once.
            rc(unsafe { sqlite3_close_v2(db) })
        }
        op::DBCONFIG => {
            let db = get(&t.dbs, a[0]);
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            let mut out: c_int = 0;
            // SAFETY: a connection of ours and a valid out pointer.
            let r = unsafe { db_config_flag(db, a[1] as c_int, a[2] as c_int, &mut out) };
            (r as u64, out as u64, 0)
        }
        op::EXTENDED => {
            let db = get(&t.dbs, a[0]);
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a connection of ours.
            rc(unsafe { sqlite3_extended_result_codes(db, a[1] as c_int) })
        }
        op::EXEC => {
            let db = get(&t.dbs, a[0]);
            let Some((_, sql)) = take_sql() else {
                return rc(SQLITE_TOOBIG);
            };
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a connection of ours and a NUL-terminated copy.
            rc(unsafe {
                sqlite3_exec(
                    db,
                    sql.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            })
        }
        op::PREPARE => {
            let db = get(&t.dbs, a[0]);
            let Some((text, _)) = take_sql() else {
                return rc(SQLITE_TOOBIG);
            };
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            let mut stmt = core::ptr::null_mut();
            // SAFETY: a connection of ours and `text.len()` readable bytes.
            let r = unsafe {
                sqlite3_prepare_v3(
                    db,
                    text.as_ptr().cast(),
                    text.len() as c_int,
                    a[1] as u32,
                    &mut stmt,
                    core::ptr::null_mut(),
                )
            };
            if r != SQLITE_OK || stmt.is_null() {
                return rc(r);
            }
            let id = put(&mut t.stmts, stmt);
            if id == 0 {
                // SAFETY: the statement we just prepared.
                unsafe { sqlite3_finalize(stmt) };
                return rc(SQLITE_NOMEM);
            }
            // SAFETY: the statement we just prepared.
            let params = unsafe { sqlite3_bind_parameter_count(stmt) } as u64;
            (0, id | params << 32, 0)
        }
        op::STEP => step(t, a),
        op::RESET => {
            let s = get(&t.stmts, a[0]);
            if s.is_null() {
                return rc(SQLITE_MISUSE);
            }
            reset_clear(s);
            rc(SQLITE_OK)
        }
        op::FINALIZE => {
            let s = take(&mut t.stmts, a[0]);
            if s.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a statement of ours, finalised once.
            rc(unsafe { sqlite3_finalize(s) })
        }
        op::ERRMSG => {
            let db = get(&t.dbs, a[0]);
            if db.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a connection of ours.
            let code = unsafe { sqlite3_extended_errcode(db) };
            // SAFETY: a connection of ours.
            let m = unsafe { sqlite3_errmsg(db) };
            // SAFETY: NUL-terminated, valid until the next call.
            let msg = unsafe { CStr::from_ptr(m) }.to_bytes();
            let out = io();
            let n = msg.len().min(255).min(out.len());
            if let (Some(d), Some(s)) = (out.get_mut(..n), msg.get(..n)) {
                d.copy_from_slice(s);
            }
            (code as u64, 0, n)
        }
        op::CHANGES => {
            let db = get(&t.dbs, a[0]);
            if db.is_null() {
                return (0, 0, 0);
            }
            // SAFETY: a connection of ours.
            (unsafe { sqlite3_changes64(db) } as u64, 0, 0)
        }
        op::BACKUP_INIT => {
            let (dest, src) = (get(&t.dbs, a[0]), get(&t.dbs, a[1]));
            if dest.is_null() || src.is_null() {
                return (0, 0, 0);
            }
            // SAFETY: two connections of ours and NUL-terminated names.
            let b = unsafe { sqlite3_backup_init(dest, c"main".as_ptr(), src, c"main".as_ptr()) };
            if b.is_null() {
                return (0, 0, 0);
            }
            let id = put(&mut t.backups, b);
            if id == 0 {
                // SAFETY: the backup we just started.
                unsafe { sqlite3_backup_finish(b) };
            }
            (0, id, 0)
        }
        op::BACKUP_STEP => {
            let b = get(&t.backups, a[0]);
            if b.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a backup of ours.
            let r = unsafe { sqlite3_backup_step(b, a[1] as c_int) };
            // SAFETY: as above.
            let rem = unsafe { sqlite3_backup_remaining(b) };
            // SAFETY: as above.
            let tot = unsafe { sqlite3_backup_pagecount(b) };
            (r as u64, (rem.max(0) as u64) << 32 | tot.max(0) as u64, 0)
        }
        op::BACKUP_FINISH => {
            let b = take(&mut t.backups, a[0]);
            if b.is_null() {
                return rc(SQLITE_MISUSE);
            }
            // SAFETY: a backup of ours, finished once.
            rc(unsafe { sqlite3_backup_finish(b) })
        }
        op::FETCH => (0, 0, usize::try_from(a[0]).unwrap_or(0).min(SHM_IO)),
        op::STATUS => {
            let (mut cur, mut hi) = (0i64, 0i64);
            // SAFETY: valid out pointers.
            unsafe { sqlite3_status64(a[0] as c_int, &mut cur, &mut hi, 0) };
            (cur as u64, hi as u64, 0)
        }
        _ => rc(SQLITE_MISUSE),
    }
}

/// Configures and initialises SQLite: heap, statistics, error log, and the
/// VFS (registered by `sqlite3_os_init` during `sqlite3_initialize`).
fn init(heap_len: u64, heap_base: u64) -> c_int {
    let Ok(len) = c_int::try_from(heap_len) else {
        return SQLITE_NOMEM;
    };
    // SAFETY: the heap region belongs to SQLite from here on; configuration
    // happens before `sqlite3_initialize`.
    let r = unsafe {
        sqlite3_config(
            SQLITE_CONFIG_HEAP,
            heap_base as *mut c_void,
            len,
            64 as c_int,
        )
    };
    if r != SQLITE_OK {
        return r;
    }
    // SAFETY: boolean option, before initialisation.
    let r = unsafe { sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 1 as c_int) };
    if r != SQLITE_OK {
        return r;
    }
    let cb: LogCallback = log_callback;
    // SAFETY: a valid callback that outlives SQLite and a null context.
    let r = unsafe { sqlite3_config(SQLITE_CONFIG_LOG, cb, core::ptr::null_mut::<c_void>()) };
    if r != SQLITE_OK {
        return r;
    }
    // SAFETY: configured above.
    unsafe { sqlite3_initialize() }
}

unsafe extern "C" fn log_callback(_ctx: *mut c_void, code: c_int, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    // SAFETY: SQLite passes a NUL-terminated message valid for this call.
    let m = unsafe { CStr::from_ptr(msg) }.to_bytes();
    let out = io();
    let n = m.len().min(400).min(out.len());
    if let (Some(d), Some(s)) = (out.get_mut(..n), m.get(..n)) {
        d.copy_from_slice(s);
    }
    sys(v::LOG, [code as u64, n as u64, n as u64, 0, 0, 0]);
}

/// Resets a statement and clears its bindings.
fn reset_clear(s: *mut sqlite3_stmt) {
    // SAFETY: a statement of ours.
    unsafe { sqlite3_reset(s) };
    // SAFETY: as above.
    unsafe { sqlite3_clear_bindings(s) };
}

/// Binds one value; SQLite copies it (`SQLITE_TRANSIENT`) before returning.
fn bind(s: *mut sqlite3_stmt, i: c_int, b: Bind<'_>) -> c_int {
    match b {
        // SAFETY: a statement of ours.
        Bind::Null => unsafe { sqlite3_bind_null(s, i) },
        // SAFETY: as above.
        Bind::Int(v) => unsafe { sqlite3_bind_int64(s, i, v) },
        Bind::Text(t) => {
            let (p, n) = (t.as_ptr().cast(), t.len() as c_int);
            // SAFETY: `n` readable bytes at `p`.
            unsafe { sqlite3_bind_text(s, i, p, n, SQLITE_TRANSIENT) }
        }
        Bind::Blob(t) => {
            // A zero-length blob is still a blob, not NULL.
            let p: *const c_void = if t.is_empty() {
                c"".as_ptr().cast()
            } else {
                t.as_ptr().cast()
            };
            // SAFETY: `t.len()` readable bytes at `p`.
            unsafe { sqlite3_bind_blob(s, i, p, t.len() as c_int, SQLITE_TRANSIENT) }
        }
    }
}

/// The bytes of a column of the current row, as text or as a blob (the
/// pointer is fetched before the length, as SQLite requires).
fn column_pointer(s: *mut sqlite3_stmt, c: c_int, text: bool) -> *const c_void {
    if text {
        // SAFETY: a statement positioned on a row and a column in range.
        unsafe { sqlite3_column_text(s, c) }.cast::<c_void>()
    } else {
        // SAFETY: as above.
        unsafe { sqlite3_column_blob(s, c) }
    }
}

fn step(t: &mut Tables, a: [u64; 6]) -> (u64, u64, usize) {
    let s = get(&t.stmts, a[0]);
    if s.is_null() {
        return rc(SQLITE_MISUSE);
    }
    if a[1] & proto::STEP_RESET != 0 {
        reset_clear(s);
    }
    // The binds, if any, are the first thing in the I/O area.
    let n = usize::try_from(hdr_get(hdr::LEN)).unwrap_or(0);
    if n >= 2 {
        let Some(buf) = io().get(..n) else {
            return rc(SQLITE_MISUSE);
        };
        let mut r = Reader::new(buf);
        let count = r.u16().unwrap_or(0);
        for _ in 0..count {
            let Some((idx, b)) = proto::decode_bind(&mut r) else {
                return rc(SQLITE_MISUSE);
            };
            let br = bind(s, c_int::from(idx), b);
            if br != SQLITE_OK {
                return rc(br);
            }
        }
    }
    // SAFETY: a statement of ours.
    let r = unsafe { sqlite3_step(s) };
    if r != SQLITE_ROW {
        return rc(r);
    }
    // SAFETY: a statement positioned on a row.
    let cols = unsafe { sqlite3_column_count(s) };
    if !(0..=64).contains(&cols) {
        return rc(SQLITE_TOOBIG);
    }
    let mut w = Writer::new(io());
    let mut ok = w.u16(cols as u16);
    for c in 0..cols {
        // SAFETY: a statement positioned on a row and a column in range.
        let ty = unsafe { sqlite3_column_type(s, c) };
        // SAFETY: as above.
        let int = unsafe { sqlite3_column_int64(s, c) };
        let ty = u8::try_from(ty).unwrap_or(proto::T_NULL);
        let data: &[u8] = if ty == proto::T_TEXT || ty == proto::T_BLOB {
            let p = column_pointer(s, c, ty == proto::T_TEXT);
            // SAFETY: as above.
            let len = unsafe { sqlite3_column_bytes(s, c) };
            if p.is_null() || len <= 0 {
                &[]
            } else {
                // SAFETY: SQLite guarantees `len` bytes at `p` until the next
                // step, reset or finalize.
                unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len as usize) }
            }
        } else {
            &[]
        };
        ok &= proto::encode_column(&mut w, ty, int, data);
    }
    if !ok {
        return rc(SQLITE_TOOBIG);
    }
    (SQLITE_ROW as u64, 0, w.len())
}

// ---- the VFS shim ----

#[repr(C)]
struct File {
    base: sqlite3_file,
    which: u64,
}

fn which_of(name: &[u8]) -> Option<u64> {
    let db = crate::vfs::DB_NAME.to_bytes();
    if name == crate::vfs::BACKUP_NAME.to_bytes() {
        return Some(v::FILE_BACKUP);
    }
    match name.strip_prefix(db)? {
        b"" => Some(v::FILE_DB),
        b"-wal" => Some(v::FILE_WAL),
        b"-journal" => Some(v::FILE_JOURNAL),
        _ => None,
    }
}

/// # Safety
/// `name` is null or a NUL-terminated string from SQLite.
unsafe fn name_which(name: *const c_char) -> Option<u64> {
    if name.is_null() {
        return None;
    }
    // SAFETY: non-null, NUL-terminated (SQLite contract).
    which_of(unsafe { CStr::from_ptr(name) }.to_bytes())
}

/// # Safety
/// `f` is a `File` this VFS opened.
unsafe fn file_which(f: *mut sqlite3_file) -> u64 {
    // SAFETY: SQLite passes back the object we filled in `x_open`.
    unsafe { (*f.cast::<File>()).which }
}

unsafe extern "C" fn x_open(
    _vfs: *mut sqlite3_vfs,
    name: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let f = file.cast::<File>();
    // SAFETY: `file` points to `szOsFile` writable bytes (SQLite contract);
    // methods stay null on failure so SQLite will not call `xClose`.
    unsafe { (*f).base.methods = core::ptr::null() };
    // SAFETY: `name` comes from SQLite.
    let Some(which) = (unsafe { name_which(name) }) else {
        return SQLITE_CANTOPEN;
    };
    if sys(v::OPEN, [which, 0, 0, 0, 0, 0]) != 0 {
        return SQLITE_CANTOPEN;
    }
    // SAFETY: as above; the object is ours to initialise.
    unsafe { (*f).which = which };
    // SAFETY: as above.
    unsafe { (*f).base.methods = &IO_METHODS };
    if !out_flags.is_null() {
        // SAFETY: non-null out pointer from SQLite.
        unsafe { *out_flags = flags };
    }
    SQLITE_OK
}

unsafe extern "C" fn x_delete(_vfs: *mut sqlite3_vfs, name: *const c_char, _sync: c_int) -> c_int {
    // SAFETY: `name` comes from SQLite.
    let Some(which) = (unsafe { name_which(name) }) else {
        return SQLITE_IOERR_DELETE;
    };
    if sys(v::DELETE, [which, 0, 0, 0, 0, 0]) == 0 {
        SQLITE_OK
    } else {
        SQLITE_IOERR_DELETE
    }
}

unsafe extern "C" fn x_access(
    _vfs: *mut sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    // SAFETY: `name` comes from SQLite.
    let exists = match unsafe { name_which(name) } {
        Some(w) if flags == SQLITE_ACCESS_EXISTS => sys(v::EXISTS, [w, 0, 0, 0, 0, 0]) == 1,
        Some(_) => true,
        None => false,
    };
    // SAFETY: `out` is a valid out pointer (SQLite contract).
    unsafe { *out = c_int::from(exists) };
    SQLITE_OK
}

unsafe extern "C" fn x_full_pathname(
    _vfs: *mut sqlite3_vfs,
    name: *const c_char,
    n_out: c_int,
    out: *mut c_char,
) -> c_int {
    if name.is_null() || n_out <= 0 {
        return SQLITE_CANTOPEN;
    }
    // SAFETY: non-null, NUL-terminated.
    let src = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    if src.len() > n_out as usize {
        return SQLITE_CANTOPEN;
    }
    // SAFETY: `out` has `n_out` writable bytes and `src.len() <= n_out`;
    // the buffers are distinct (SQLite allocates `out`).
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().cast::<c_char>(), out, src.len()) };
    SQLITE_OK
}

unsafe extern "C" fn x_randomness(_vfs: *mut sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let Ok(len) = usize::try_from(n) else {
        return 0;
    };
    let area = io();
    if len == 0 || out.is_null() || len > area.len() {
        return 0;
    }
    sys(v::RANDOM, [len as u64, 0, len as u64, 0, 0, 0]);
    if let Some(src) = area.get(..len) {
        // SAFETY: SQLite passes `n` writable bytes at `out`.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), out.cast::<u8>(), len) };
    }
    n
}

unsafe extern "C" fn x_sleep(_vfs: *mut sqlite3_vfs, us: c_int) -> c_int {
    sys(v::SLEEP, [us.max(0) as u64, 0, 0, 0, 0, 0]);
    us
}

/// Julian day number of the Unix epoch, in milliseconds.
const UNIX_EPOCH_JD_MS: i64 = 210_866_760_000_000;

fn now_jd_ms() -> i64 {
    UNIX_EPOCH_JD_MS + sys(v::TIME, [0; 6]) as i64
}

unsafe extern "C" fn x_current_time_int64(
    _vfs: *mut sqlite3_vfs,
    out: *mut sqlite3_int64,
) -> c_int {
    // SAFETY: valid out pointer from SQLite.
    unsafe { *out = now_jd_ms() };
    SQLITE_OK
}

unsafe extern "C" fn x_current_time(_vfs: *mut sqlite3_vfs, out: *mut f64) -> c_int {
    // SAFETY: valid out pointer from SQLite.
    unsafe { *out = now_jd_ms() as f64 / 86_400_000.0 };
    SQLITE_OK
}

unsafe extern "C" fn x_get_last_error(_vfs: *mut sqlite3_vfs, _n: c_int, _o: *mut c_char) -> c_int {
    0
}

unsafe extern "C" fn x_close(_f: *mut sqlite3_file) -> c_int {
    SQLITE_OK
}

unsafe extern "C" fn x_read(
    f: *mut sqlite3_file,
    buf: *mut c_void,
    amt: c_int,
    off: sqlite3_int64,
) -> c_int {
    // SAFETY: `f` is one of our files.
    let which = unsafe { file_which(f) };
    let (Ok(amt), Ok(off)) = (usize::try_from(amt), u64::try_from(off)) else {
        return SQLITE_IOERR_READ;
    };
    // SAFETY: SQLite passes `amt` writable bytes at `buf`.
    let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), amt) };
    let area = io();
    let mut short = false;
    let mut done = 0;
    while done < out.len() {
        let n = (out.len() - done).min(area.len());
        let r = sys(v::READ, [which, off + done as u64, n as u64, 0, 0, 0]);
        match (r, area.get(..n), out.get_mut(done..done + n)) {
            (v::RC_OK | v::RC_SHORT, Some(src), Some(dst)) => {
                dst.copy_from_slice(src);
                short |= r == v::RC_SHORT;
            }
            _ => return SQLITE_IOERR_READ,
        }
        done += n;
    }
    if short {
        SQLITE_IOERR_SHORT_READ
    } else {
        SQLITE_OK
    }
}

unsafe extern "C" fn x_write(
    f: *mut sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    off: sqlite3_int64,
) -> c_int {
    // SAFETY: `f` is one of our files.
    let which = unsafe { file_which(f) };
    let (Ok(amt), Ok(off)) = (usize::try_from(amt), u64::try_from(off)) else {
        return SQLITE_IOERR_WRITE;
    };
    // SAFETY: SQLite passes `amt` readable bytes at `buf`.
    let data = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), amt) };
    let area = io();
    let mut done = 0;
    while done < data.len() {
        let n = (data.len() - done).min(area.len());
        let (Some(dst), Some(src)) = (area.get_mut(..n), data.get(done..done + n)) else {
            return SQLITE_IOERR_WRITE;
        };
        dst.copy_from_slice(src);
        match sys(v::WRITE, [which, off + done as u64, n as u64, 0, 0, 0]) {
            v::RC_OK => {}
            v::RC_FULL => return SQLITE_FULL,
            _ => return SQLITE_IOERR_WRITE,
        }
        done += n;
    }
    SQLITE_OK
}

unsafe extern "C" fn x_truncate(f: *mut sqlite3_file, size: sqlite3_int64) -> c_int {
    // SAFETY: `f` is one of our files.
    let which = unsafe { file_which(f) };
    let Ok(size) = u64::try_from(size) else {
        return SQLITE_IOERR_TRUNCATE;
    };
    match sys(v::TRUNCATE, [which, size, 0, 0, 0, 0]) {
        v::RC_OK => SQLITE_OK,
        v::RC_FULL => SQLITE_FULL,
        _ => SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn x_sync(_f: *mut sqlite3_file, _flags: c_int) -> c_int {
    if sys(v::SYNC, [0; 6]) == v::RC_OK {
        SQLITE_OK
    } else {
        SQLITE_IOERR_FSYNC
    }
}

unsafe extern "C" fn x_file_size(f: *mut sqlite3_file, out: *mut sqlite3_int64) -> c_int {
    // SAFETY: `f` is one of our files.
    let which = unsafe { file_which(f) };
    let size = sys(v::SIZE, [which, 0, 0, 0, 0, 0]);
    // SAFETY: valid out pointer from SQLite.
    unsafe { *out = i64::try_from(size).unwrap_or(0) };
    SQLITE_OK
}

/// Single owner, single connection: locks always succeed (ADR-030).
unsafe extern "C" fn x_lock(_f: *mut sqlite3_file, _level: c_int) -> c_int {
    SQLITE_OK
}

unsafe extern "C" fn x_check_reserved_lock(_f: *mut sqlite3_file, out: *mut c_int) -> c_int {
    // SAFETY: valid out pointer from SQLite.
    unsafe { *out = 0 };
    SQLITE_OK
}

unsafe extern "C" fn x_file_control(_f: *mut sqlite3_file, _op: c_int, _arg: *mut c_void) -> c_int {
    SQLITE_NOTFOUND
}

unsafe extern "C" fn x_sector_size(_f: *mut sqlite3_file) -> c_int {
    512
}

/// Conservative: no atomic writes, no safe append, no powersafe overwrite,
/// so SQLite assumes a torn sector can damage its neighbours.
unsafe extern "C" fn x_device_characteristics(_f: *mut sqlite3_file) -> c_int {
    0
}

static IO_METHODS: sqlite3_io_methods = sqlite3_io_methods {
    version: 1,
    close: Some(x_close),
    read: Some(x_read),
    write: Some(x_write),
    truncate: Some(x_truncate),
    sync: Some(x_sync),
    file_size: Some(x_file_size),
    lock: Some(x_lock),
    unlock: Some(x_lock),
    check_reserved_lock: Some(x_check_reserved_lock),
    file_control: Some(x_file_control),
    sector_size: Some(x_sector_size),
    device_characteristics: Some(x_device_characteristics),
    shm_map: None,
    shm_lock: None,
    shm_barrier: None,
    shm_unmap: None,
    fetch: None,
    unfetch: None,
};

/// SQLite links the registered VFS into a list (`pNext`), so the object
/// must be mutable and live forever.
struct VfsCell(UnsafeCell<sqlite3_vfs>);

// SAFETY: only SQLite touches the object, from the one thread running it.
unsafe impl Sync for VfsCell {}

static VFS: VfsCell = VfsCell(UnsafeCell::new(sqlite3_vfs {
    version: 2,
    os_file_size: core::mem::size_of::<File>() as c_int,
    max_pathname: 64,
    next: core::ptr::null_mut(),
    name: crate::vfs::VFS_NAME.as_ptr(),
    app_data: core::ptr::null_mut(),
    open: Some(x_open),
    delete: Some(x_delete),
    access: Some(x_access),
    full_pathname: Some(x_full_pathname),
    dl_open: None,
    dl_error: None,
    dl_sym: None,
    dl_close: None,
    randomness: Some(x_randomness),
    sleep: Some(x_sleep),
    current_time: Some(x_current_time),
    get_last_error: Some(x_get_last_error),
    current_time_int64: Some(x_current_time_int64),
    set_system_call: None,
    get_system_call: None,
    next_system_call: None,
}));

/// Called by `sqlite3_initialize` (`SQLITE_OS_OTHER`): registers our VFS
/// as the default.
#[unsafe(no_mangle)]
pub extern "C" fn sqlite3_os_init() -> c_int {
    // SAFETY: `VFS` lives forever; SQLite takes ownership of `pNext`.
    unsafe { sqlite3_vfs_register(VFS.0.get(), 1) }
}

#[unsafe(no_mangle)]
pub extern "C" fn sqlite3_os_end() -> c_int {
    SQLITE_OK
}

// ---- the host tests' in-process worker ----

#[cfg(feature = "loopback")]
mod loopback {
    use alloc::vec::Vec;

    use super::*;
    use crate::remote::{Failure, Reply, Transport};

    struct Window(UnsafeCell<[u8; urmqtt_usys::layout::SHM_LEN]>);
    // SAFETY: the tests serialise their calls.
    unsafe impl Sync for Window {}
    static WINDOW: Window = Window(UnsafeCell::new([0; urmqtt_usys::layout::SHM_LEN]));

    fn sys_call(nr: u64, a: [u64; 6]) -> u64 {
        // The kernel's handler, on the same window.
        // SAFETY: the tests serialise their calls; the worker is paused in
        // the call, as it would be in the kernel.
        let io = unsafe {
            core::slice::from_raw_parts_mut(
                WINDOW.0.get().cast::<u8>().wrapping_add(SHM_HEADER),
                SHM_IO,
            )
        };
        crate::vfs::syscall(nr, a, io).unwrap_or(u64::MAX)
    }

    fn call(o: u64, a: [u64; 6], input: &[u8], output: &mut [u8]) -> Result<Reply, Failure> {
        if input.len() > SHM_IO {
            return Err(Failure::Died);
        }
        let base = WINDOW.0.get().cast::<u8>();
        put(base, hdr::OP, o);
        for (i, w) in a.iter().enumerate() {
            put(base, hdr::ARG + 8 * i, *w);
        }
        put(base, hdr::LEN, input.len() as u64);
        copy_in(base, input);
        dispatch();
        let (ret, ret2) = (get(base, hdr::RET), get(base, hdr::RET2));
        let len = get(base, hdr::LEN) as usize;
        let n = len.min(output.len()).min(SHM_IO);
        copy_out(base, output.get_mut(..n).unwrap_or(&mut []));
        Ok(Reply { ret, ret2, len })
    }

    fn epoch() -> u64 {
        0
    }

    // The window is a static; the tests serialise their calls.
    fn put(base: *mut u8, off: usize, v: u64) {
        // SAFETY: inside the header page of the window.
        unsafe { base.wrapping_add(off).cast::<u64>().write_unaligned(v) };
    }

    fn get(base: *mut u8, off: usize) -> u64 {
        // SAFETY: inside the header page of the window.
        unsafe { base.wrapping_add(off).cast::<u64>().read_unaligned() }
    }

    fn copy_in(base: *mut u8, input: &[u8]) {
        // SAFETY: `input` fits the I/O area (checked by the caller).
        unsafe {
            core::ptr::copy_nonoverlapping(
                input.as_ptr(),
                base.wrapping_add(SHM_HEADER),
                input.len(),
            )
        };
    }

    fn copy_out(base: *mut u8, out: &mut [u8]) {
        // SAFETY: `out` is at most the I/O area.
        unsafe {
            core::ptr::copy_nonoverlapping(
                base.wrapping_add(SHM_HEADER),
                out.as_mut_ptr(),
                out.len(),
            )
        };
    }

    /// Installs the in-process worker as the store's transport; `heap` is
    /// SQLite's heap.
    pub fn install_loopback(heap: &'static mut [u8]) {
        // SAFETY: the window is a static; the tests serialise their calls.
        unsafe {
            super::install(Ops {
                shm: WINDOW.0.get().cast::<u8>(),
                sys: sys_call,
            });
        }
        crate::remote::install(Transport {
            call,
            epoch,
            heap: (heap.as_mut_ptr() as u64, heap.len()),
        });
        let _: Vec<u8> = Vec::new();
    }
}

#[cfg(feature = "loopback")]
pub use loopback::install_loopback;

#[allow(dead_code)]
const _: (c_int, c_int, c_int) = (SQLITE_ERROR, SQLITE_DONE, SQLITE_IOERR);
#[allow(dead_code)]
const _RANGE: c_int = SQLITE_RANGE;
