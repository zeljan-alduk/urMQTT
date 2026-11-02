//! The SQLite C API as calls into the unprivileged worker (ADR-210,
//! ADR-211). Every function here has the name and the signature of the C
//! function it replaces, so `db.rs` is unchanged; the "pointers" it hands
//! out (`*mut sqlite3`, `*mut sqlite3_stmt`, `*mut sqlite3_backup`) are
//! boxes of the kernel's own bookkeeping, never addresses of the worker.
//!
//! What crosses the boundary is bytes, checked on the way back: a row is
//! decoded with bounds and type checks ([`urmqtt_usys::proto::decode_row`]),
//! a handle is a small number the worker chose and the kernel only returns
//! to it, an error message is cut at a fixed length. A worker that lies can
//! make the broker see wrong data; it cannot make the kernel read or write
//! anything it should not.
//!
//! Binds are not sent when they are made: they ride with the next
//! `sqlite3_step`, and `reset` rides with the next step too, so one write
//! of a record costs one entry into the worker.

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_sync::sync::SpinLock;
use urmqtt_usys::layout::SHM_IO;
use urmqtt_usys::proto::{self, Bind, Column, Writer, op};

use crate::ffi::*;

/// What a call into the worker answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub ret: u64,
    pub ret2: u64,
    pub len: usize,
}

/// Why a call produced no answer: the worker died during it (and was
/// restarted, losing every handle), or there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Died,
    Absent,
}

/// `call(op, args, input, output)`.
pub type CallFn = fn(u64, [u64; 6], &[u8], &mut [u8]) -> Result<Reply, Failure>;

/// How the store reaches the worker. The kernel installs one that enters
/// user mode; the host tests install one that runs the worker's code in
/// process.
#[derive(Clone, Copy)]
pub struct Transport {
    /// `call(op, args, input, output)`: input bytes go to the I/O area
    /// first; the reply's `len` bytes (at most `output.len()`) come back.
    pub call: CallFn,
    /// Counts the worker's restarts (and starts); handles of an earlier
    /// epoch are dead.
    pub epoch: fn() -> u64,
    /// Base address (in the worker) and length of the SQLite heap.
    pub heap: (u64, usize),
}

static TRANSPORT: SpinLock<Option<Transport>> = SpinLock::new(None);
/// The epoch SQLite was last initialised in (`u64::MAX`: never).
static INITED: AtomicU64 = AtomicU64::new(u64::MAX);

/// Installs the transport. Must happen before the first SQLite call.
pub fn install(t: Transport) {
    *TRANSPORT.lock() = Some(t);
    INITED.store(u64::MAX, Ordering::Relaxed);
}

/// The worker's restart count, for code that holds long-lived handles.
pub fn epoch() -> u64 {
    transport().map_or(0, |t| (t.epoch)())
}

fn transport() -> Option<Transport> {
    *TRANSPORT.lock()
}

/// The result a call made while the worker is dead or restarted returns.
pub const SQLITE_WORKER_DEAD: c_int = SQLITE_IOERR | (0x7f << 8);

/// One call; a worker that is dead (or restarted since `epoch`) answers
/// [`SQLITE_WORKER_DEAD`].
fn rpc(
    epoch: Option<u64>,
    op: u64,
    args: [u64; 6],
    input: &[u8],
    output: &mut [u8],
) -> Result<Reply, c_int> {
    let t = transport().ok_or(SQLITE_WORKER_DEAD)?;
    if epoch.is_some_and(|e| e != (t.epoch)()) {
        return Err(SQLITE_WORKER_DEAD);
    }
    if op != op::INIT {
        ensure_init(&t)?;
    }
    (t.call)(op, args, input, output).map_err(|_| SQLITE_WORKER_DEAD)
}

/// Configures and initialises SQLite in the current worker, once per epoch.
fn ensure_init(t: &Transport) -> Result<(), c_int> {
    let now = (t.epoch)();
    if INITED.load(Ordering::Relaxed) == now {
        return Ok(());
    }
    let r = (t.call)(
        op::INIT,
        [t.heap.1 as u64, t.heap.0, 0, 0, 0, 0],
        &[],
        &mut [],
    )
    .map_err(|_| SQLITE_WORKER_DEAD)?;
    if r.ret as c_int != SQLITE_OK {
        return Err(r.ret as c_int);
    }
    // The call itself may have restarted the worker: only the epoch seen
    // after it counts.
    INITED.store((t.epoch)(), Ordering::Relaxed);
    Ok(())
}

/// Initialises SQLite in the worker (the boot-time `init`).
pub fn init() -> Result<(), c_int> {
    let t = transport().ok_or(SQLITE_WORKER_DEAD)?;
    ensure_init(&t)
}

/// Bytes of a row the first call brings back; a bigger row is fetched.
const ROW_FIRST: usize = 4096;

/// Bytes the kernel keeps of an error message.
const MSG_MAX: usize = 256;

pub struct sqlite3 {
    id: u64,
    epoch: u64,
    /// The message of the last `extended_errcode` call, NUL-terminated, kept
    /// for the `errmsg` that follows it.
    msg: Vec<u8>,
    msg_fresh: bool,
}

/// A prepared statement.
pub struct sqlite3_stmt {
    id: u64,
    epoch: u64,
    params: u32,
    /// Encoded binds waiting for the next step, and their count.
    binds: Vec<u8>,
    nbinds: u16,
    bind_error: c_int,
    /// Reset (and clear) before the next step.
    reset: bool,
    /// The last step returned a row: the statement is mid-execution in the
    /// worker (and holds its locks) until it is reset.
    active: bool,
    /// The current row and where its columns are.
    row: Vec<u8>,
    cols: Vec<Col>,
    scratch: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Col {
    ty: u8,
    int: i64,
    off: usize,
    len: usize,
}

pub struct sqlite3_backup {
    id: u64,
    epoch: u64,
    remaining: u32,
    total: u32,
}

// SAFETY (caller contract): none beyond the C signature; there are no arguments, and the returned
// pointer is to a `CString` in a static that is never freed.
pub unsafe fn sqlite3_libversion() -> *const c_char {
    static VERSION: urmqtt_sync::sync::OnceCell<CString> = urmqtt_sync::sync::OnceCell::new();
    if let Some(v) = VERSION.get() {
        return v.as_ptr();
    }
    let mut buf = [0u8; 32];
    let text = match rpc(None, op::VERSION, [0; 6], &[], &mut buf) {
        Ok(r) => {
            let n = r.len.min(buf.len());
            buf.get(..n)
                .filter(|b| b.iter().all(|c| c.is_ascii_graphic()))
                .map_or(Vec::new(), <[u8]>::to_vec)
        }
        Err(_) => Vec::new(),
    };
    let s = CString::new(text).unwrap_or_default();
    let _ = VERSION.set(s);
    VERSION.get().map_or(c"?".as_ptr(), |v| v.as_ptr())
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_open_v2(
    filename: *const c_char,
    db: *mut *mut sqlite3,
    _flags: c_int,
    _vfs: *const c_char,
) -> c_int {
    // SAFETY: a NUL-terminated name from the caller.
    let name = unsafe { CStr::from_ptr(filename) };
    let file = if name == crate::vfs::BACKUP_NAME {
        proto::vfs::FILE_BACKUP
    } else {
        proto::vfs::FILE_DB
    };
    let epoch_now = epoch();
    match rpc(None, op::OPEN, [file, 0, 0, 0, 0, 0], &[], &mut []) {
        Ok(r) => {
            // A connection that failed to open is still returned (when the
            // worker made one), so that its error message can be read.
            let handle = if r.ret2 != 0 {
                Box::into_raw(Box::new(sqlite3 {
                    id: r.ret2,
                    epoch: epoch_now,
                    msg: Vec::new(),
                    msg_fresh: false,
                }))
            } else {
                core::ptr::null_mut()
            };
            // SAFETY: a valid out pointer from the caller.
            unsafe { *db = handle };
            if r.ret as c_int == SQLITE_OK && handle.is_null() {
                SQLITE_CANTOPEN
            } else {
                r.ret as c_int
            }
        }
        Err(rc) => {
            // SAFETY: a valid out pointer from the caller.
            unsafe { *db = core::ptr::null_mut() };
            rc
        }
    }
}

pub unsafe fn sqlite3_close_v2(db: *mut sqlite3) -> c_int {
    if db.is_null() {
        return SQLITE_OK;
    }
    // SAFETY: a box made in `sqlite3_open_v2`, closed exactly once.
    let b = unsafe { Box::from_raw(db) };
    let _ = rpc(
        Some(b.epoch),
        op::CLOSE,
        [b.id, 0, 0, 0, 0, 0],
        &[],
        &mut [],
    );
    SQLITE_OK
}

/// `sqlite3_db_config` for the boolean options (the C function is variadic).
// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn db_config_flag(db: *mut sqlite3, option: c_int, on: c_int, out: *mut c_int) -> c_int {
    // SAFETY: a live connection box from `sqlite3_open_v2`.
    let d = unsafe { &*db };
    match rpc(
        Some(d.epoch),
        op::DBCONFIG,
        [d.id, option as u64, on as u64, 0, 0, 0],
        &[],
        &mut [],
    ) {
        Ok(r) => {
            // SAFETY: a valid out pointer from the caller.
            unsafe { *out = r.ret2 as c_int };
            r.ret as c_int
        }
        Err(rc) => rc,
    }
}

pub unsafe fn sqlite3_extended_result_codes(db: *mut sqlite3, onoff: c_int) -> c_int {
    // SAFETY: a live connection box.
    let d = unsafe { &*db };
    match rpc(
        Some(d.epoch),
        op::EXTENDED,
        [d.id, onoff as u64, 0, 0, 0, 0],
        &[],
        &mut [],
    ) {
        Ok(r) => r.ret as c_int,
        Err(rc) => rc,
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_exec(
    db: *mut sqlite3,
    sql: *const c_char,
    _callback: *const c_void,
    _arg: *mut c_void,
    errmsg: *mut *mut c_char,
) -> c_int {
    if !errmsg.is_null() {
        // SAFETY: a valid out pointer; no message is returned.
        unsafe { *errmsg = core::ptr::null_mut() };
    }
    // SAFETY: a live connection box.
    let d = unsafe { &*db };
    // SAFETY: a NUL-terminated statement.
    let text = unsafe { CStr::from_ptr(sql) };
    match rpc(
        Some(d.epoch),
        op::EXEC,
        [d.id, 0, 0, 0, 0, 0],
        text.to_bytes(),
        &mut [],
    ) {
        Ok(r) => r.ret as c_int,
        Err(rc) => rc,
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_prepare_v3(
    db: *mut sqlite3,
    sql: *const c_char,
    nbyte: c_int,
    flags: u32,
    stmt: *mut *mut sqlite3_stmt,
    tail: *mut *const c_char,
) -> c_int {
    // SAFETY: a valid out pointer from the caller.
    unsafe { *stmt = core::ptr::null_mut() };
    if !tail.is_null() {
        // SAFETY: non-null, a valid out pointer from the caller.
        unsafe { *tail = core::ptr::null() };
    }
    let Ok(n) = usize::try_from(nbyte) else {
        return SQLITE_MISUSE;
    };
    // SAFETY: a live connection box.
    let d = unsafe { &*db };
    // SAFETY: `sql` has `n` readable bytes.
    let text = unsafe { core::slice::from_raw_parts(sql.cast::<u8>(), n) };
    match rpc(
        Some(d.epoch),
        op::PREPARE,
        [d.id, u64::from(flags), 0, 0, 0, 0],
        text,
        &mut [],
    ) {
        Ok(r) if r.ret as c_int == SQLITE_OK && r.ret2 & 0xffff_ffff != 0 => {
            let b = Box::new(sqlite3_stmt {
                id: r.ret2 & 0xffff_ffff,
                epoch: d.epoch,
                params: (r.ret2 >> 32) as u32,
                binds: Vec::new(),
                nbinds: 0,
                bind_error: SQLITE_OK,
                reset: false,
                active: false,
                row: Vec::new(),
                cols: Vec::new(),
                scratch: Vec::new(),
            });
            // SAFETY: a valid out pointer from the caller.
            unsafe { *stmt = Box::into_raw(b) };
            SQLITE_OK
        }
        Ok(r) if r.ret as c_int == SQLITE_OK => SQLITE_OK,
        Ok(r) => r.ret as c_int,
        Err(rc) => rc,
    }
}

/// Queues one bind for the next step.
fn bind(stmt: *mut sqlite3_stmt, i: c_int, b: Bind<'_>) -> c_int {
    // SAFETY: a live statement box from `sqlite3_prepare_v3`.
    let s = unsafe { &mut *stmt };
    let idx = match u16::try_from(i) {
        Ok(v) if v >= 1 && u32::from(v) <= s.params => v,
        _ => return SQLITE_RANGE,
    };
    if s.binds.is_empty() {
        s.binds.extend_from_slice(&[0, 0]);
    }
    let extra = match b {
        Bind::Text(t) | Bind::Blob(t) => t.len(),
        _ => 0,
    };
    // idx (2) + kind (1) + a value of at most 8 bytes or a length (4) and
    // the bytes.
    let before = s.binds.len();
    if before + extra + 16 > SHM_IO {
        s.bind_error = SQLITE_TOOBIG;
        return SQLITE_TOOBIG;
    }
    s.binds.resize(before + extra + 16, 0);
    let wrote = match s.binds.get_mut(before..) {
        Some(tail) => {
            let mut w = Writer::new(tail);
            proto::encode_bind(&mut w, idx, b).then(|| w.len())
        }
        None => None,
    };
    match wrote {
        Some(n) => {
            s.binds.truncate(before + n);
            s.nbinds = s.nbinds.saturating_add(1);
            SQLITE_OK
        }
        None => {
            s.binds.truncate(before);
            s.bind_error = SQLITE_TOOBIG;
            SQLITE_TOOBIG
        }
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_bind_int64(stmt: *mut sqlite3_stmt, i: c_int, v: sqlite3_int64) -> c_int {
    bind(stmt, i, Bind::Int(v))
}

pub unsafe fn sqlite3_bind_null(stmt: *mut sqlite3_stmt, i: c_int) -> c_int {
    bind(stmt, i, Bind::Null)
}

pub unsafe fn sqlite3_bind_text(
    stmt: *mut sqlite3_stmt,
    i: c_int,
    v: *const c_char,
    n: c_int,
    _destructor: isize,
) -> c_int {
    let Ok(n) = usize::try_from(n) else {
        return SQLITE_MISUSE;
    };
    // SAFETY: the caller's `n` readable bytes (SQLITE_TRANSIENT: copied now).
    let t = unsafe { core::slice::from_raw_parts(v.cast::<u8>(), n) };
    bind(stmt, i, Bind::Text(t))
}

pub unsafe fn sqlite3_bind_blob(
    stmt: *mut sqlite3_stmt,
    i: c_int,
    v: *const c_void,
    n: c_int,
    _destructor: isize,
) -> c_int {
    let Ok(n) = usize::try_from(n) else {
        return SQLITE_MISUSE;
    };
    // SAFETY: the caller's `n` readable bytes (SQLITE_TRANSIENT: copied now).
    let t = unsafe { core::slice::from_raw_parts(v.cast::<u8>(), n) };
    bind(stmt, i, Bind::Blob(t))
}

pub unsafe fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int {
    // SAFETY: a live statement box.
    let s = unsafe { &mut *stmt };
    s.cols.clear();
    s.row.clear();
    if s.bind_error != SQLITE_OK {
        let e = s.bind_error;
        s.bind_error = SQLITE_OK;
        s.binds.clear();
        s.nbinds = 0;
        return e;
    }
    let flags = if s.reset { proto::STEP_RESET } else { 0 };
    if s.binds.len() >= 2 {
        let n = s.nbinds;
        if let Some(h) = s.binds.get_mut(..2) {
            h.copy_from_slice(&n.to_le_bytes());
        }
    }
    let mut first = [0u8; ROW_FIRST];
    let r = rpc(
        Some(s.epoch),
        op::STEP,
        [s.id, flags, 0, 0, 0, 0],
        &s.binds,
        &mut first,
    );
    s.binds.clear();
    s.nbinds = 0;
    s.reset = false;
    s.active = false;
    let r = match r {
        Ok(r) => r,
        Err(rc) => return rc,
    };
    let rc = r.ret as c_int;
    if rc != SQLITE_ROW {
        return rc;
    }
    s.active = true;
    // The row is the worker's word: decode it with every check, or fail. A
    // row that did not fit the stack buffer is fetched, at its exact size.
    let len = r.len;
    let mut big = Vec::new();
    let bytes: &[u8] = if len <= ROW_FIRST {
        first.get(..len).unwrap_or(&[])
    } else if len <= SHM_IO {
        big.resize(len, 0);
        match rpc(
            Some(s.epoch),
            op::FETCH,
            [len as u64, 0, 0, 0, 0, 0],
            &[],
            &mut big,
        ) {
            Ok(f) if f.len == len => &big,
            _ => return SQLITE_CORRUPT,
        }
    } else {
        return SQLITE_CORRUPT;
    };
    let mut cols = [Column {
        ty: 0,
        int: 0,
        data: &[],
    }; 64];
    let Some(n) = proto::decode_row(bytes, 64, &mut cols) else {
        return SQLITE_CORRUPT;
    };
    s.row.extend_from_slice(bytes);
    let base = bytes.as_ptr() as usize;
    for c in cols.iter().take(n) {
        let off = if c.data.is_empty() {
            0
        } else {
            (c.data.as_ptr() as usize).wrapping_sub(base)
        };
        s.cols.push(Col {
            ty: c.ty,
            int: c.int,
            off,
            len: c.data.len(),
        });
    }
    SQLITE_ROW
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int {
    // SAFETY: a live statement box.
    let s = unsafe { &mut *stmt };
    s.binds.clear();
    s.nbinds = 0;
    s.bind_error = SQLITE_OK;
    s.cols.clear();
    if s.active {
        // Mid-row: SQLite holds the statement's locks until it is reset, so
        // this cannot wait for the next step.
        s.active = false;
        s.reset = false;
        return match rpc(
            Some(s.epoch),
            op::RESET,
            [s.id, 0, 0, 0, 0, 0],
            &[],
            &mut [],
        ) {
            Ok(r) => r.ret as c_int,
            Err(rc) => rc,
        };
    }
    // Finished (done or failed): nothing is held; the reset rides with the
    // next step.
    s.reset = true;
    SQLITE_OK
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_clear_bindings(stmt: *mut sqlite3_stmt) -> c_int {
    // Bindings are cleared with the reset (which `db.rs` always makes
    // first): nothing more to do here.
    // SAFETY: a live statement box.
    let s = unsafe { &mut *stmt };
    s.binds.clear();
    s.nbinds = 0;
    SQLITE_OK
}

pub unsafe fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int {
    if stmt.is_null() {
        return SQLITE_OK;
    }
    // SAFETY: a box made in `sqlite3_prepare_v3`, finalised exactly once.
    let s = unsafe { Box::from_raw(stmt) };
    let _ = rpc(
        Some(s.epoch),
        op::FINALIZE,
        [s.id, 0, 0, 0, 0, 0],
        &[],
        &mut [],
    );
    SQLITE_OK
}

pub unsafe fn sqlite3_column_count(stmt: *mut sqlite3_stmt) -> c_int {
    // SAFETY: a live statement box.
    unsafe { (*stmt).cols.len() as c_int }
}

fn col(stmt: *mut sqlite3_stmt, i: c_int) -> Option<(&'static mut sqlite3_stmt, Col)> {
    // SAFETY: a live statement box; the borrow ends with the caller's use.
    let s: &'static mut sqlite3_stmt = unsafe { &mut *stmt };
    let c = usize::try_from(i)
        .ok()
        .and_then(|i| s.cols.get(i).copied())?;
    Some((s, c))
}

pub unsafe fn sqlite3_column_type(stmt: *mut sqlite3_stmt, i: c_int) -> c_int {
    col(stmt, i).map_or(SQLITE_NULL, |(_, c)| c_int::from(c.ty))
}

pub unsafe fn sqlite3_column_int64(stmt: *mut sqlite3_stmt, i: c_int) -> sqlite3_int64 {
    col(stmt, i).map_or(0, |(_, c)| c.int)
}

/// The bytes of a column as text or blob: the stored bytes of a TEXT or
/// BLOB column, the decimal digits of an INTEGER, nothing otherwise.
fn column_bytes_of(stmt: *mut sqlite3_stmt, i: c_int) -> Option<(*const u8, usize)> {
    let (s, c) = col(stmt, i)?;
    match c.ty {
        proto::T_TEXT | proto::T_BLOB => {
            let b = s.row.get(c.off..c.off.checked_add(c.len)?)?;
            Some((b.as_ptr(), b.len()))
        }
        proto::T_INTEGER => {
            use core::fmt::Write as _;
            struct V<'a>(&'a mut Vec<u8>);
            impl core::fmt::Write for V<'_> {
                fn write_str(&mut self, t: &str) -> core::fmt::Result {
                    self.0.extend_from_slice(t.as_bytes());
                    Ok(())
                }
            }
            s.scratch.clear();
            let _ = write!(V(&mut s.scratch), "{}", c.int);
            Some((s.scratch.as_ptr(), s.scratch.len()))
        }
        _ => None,
    }
}

// SAFETY (caller contract): `stmt` is a live statement box; the returned pointer is valid until the
// next step, reset or finalize of that statement, as in SQLite.
pub unsafe fn sqlite3_column_text(stmt: *mut sqlite3_stmt, i: c_int) -> *const u8 {
    column_bytes_of(stmt, i).map_or(core::ptr::null(), |(p, _)| p)
}

pub unsafe fn sqlite3_column_blob(stmt: *mut sqlite3_stmt, i: c_int) -> *const c_void {
    column_bytes_of(stmt, i).map_or(core::ptr::null(), |(p, _)| p.cast())
}

pub unsafe fn sqlite3_column_bytes(stmt: *mut sqlite3_stmt, i: c_int) -> c_int {
    column_bytes_of(stmt, i).map_or(0, |(_, n)| n as c_int)
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char {
    // SAFETY: a live connection box.
    let d = unsafe { &mut *db };
    if !d.msg_fresh {
        fetch_error(d);
    }
    d.msg_fresh = false;
    d.msg.as_ptr().cast()
}

pub unsafe fn sqlite3_extended_errcode(db: *mut sqlite3) -> c_int {
    // SAFETY: a live connection box.
    let d = unsafe { &mut *db };
    let code = fetch_error(d);
    d.msg_fresh = true;
    code
}

/// Asks the worker for the connection's last error and keeps the message.
fn fetch_error(d: &mut sqlite3) -> c_int {
    let mut buf = [0u8; MSG_MAX];
    match rpc(
        Some(d.epoch),
        op::ERRMSG,
        [d.id, 0, 0, 0, 0, 0],
        &[],
        &mut buf,
    ) {
        Ok(r) => {
            let n = r.len.min(MSG_MAX - 1);
            d.msg.clear();
            // Printable ASCII only: the text is the worker's.
            d.msg.extend(buf.iter().take(n).map(|&c| {
                if c.is_ascii_graphic() || c == b' ' {
                    c
                } else {
                    b'?'
                }
            }));
            d.msg.push(0);
            r.ret as c_int
        }
        Err(rc) => {
            d.msg.clear();
            d.msg
                .extend_from_slice(b"the database worker failed and was restarted\0");
            rc
        }
    }
}

// SAFETY (caller contract): none beyond the C signature; the pointer is into a static table.
pub unsafe fn sqlite3_errstr(code: c_int) -> *const c_char {
    errstr(code).as_ptr()
}

/// SQLite's own text for a result code (the table of `sqlite3ErrStr`),
/// answered here so that it works while the worker is down.
fn errstr(code: c_int) -> &'static CStr {
    const TABLE: [&CStr; 29] = [
        c"not an error",
        c"SQL logic error",
        c"unknown error",
        c"access permission denied",
        c"query aborted",
        c"database is locked",
        c"database table is locked",
        c"out of memory",
        c"attempt to write a readonly database",
        c"interrupted",
        c"disk I/O error",
        c"database disk image is malformed",
        c"unknown operation",
        c"database or disk is full",
        c"unable to open database file",
        c"locking protocol",
        c"unknown error",
        c"database schema has changed",
        c"string or blob too big",
        c"constraint failed",
        c"datatype mismatch",
        c"bad parameter or other API misuse",
        c"unknown error",
        c"authorization denied",
        c"unknown error",
        c"column index out of range",
        c"file is not a database",
        c"notification message",
        c"warning message",
    ];
    match code {
        516 => c"abort due to ROLLBACK",
        SQLITE_ROW => c"another row available",
        SQLITE_DONE => c"no more rows available",
        _ => TABLE
            .get((code & 0xff) as usize)
            .copied()
            .unwrap_or(c"unknown error"),
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_changes64(db: *mut sqlite3) -> sqlite3_int64 {
    // SAFETY: a live connection box.
    let d = unsafe { &*db };
    rpc(
        Some(d.epoch),
        op::CHANGES,
        [d.id, 0, 0, 0, 0, 0],
        &[],
        &mut [],
    )
    .map_or(0, |r| r.ret as i64)
}

pub unsafe fn sqlite3_free(_p: *mut c_void) {}

// SAFETY (caller contract): `_p` is ignored; nothing this module returns needs freeing (strings
// are static or owned by their handle).
pub unsafe fn sqlite3_backup_init(
    dest: *mut sqlite3,
    _dest_name: *const c_char,
    src: *mut sqlite3,
    _src_name: *const c_char,
) -> *mut sqlite3_backup {
    // SAFETY: a live connection box.
    let d = unsafe { &*dest };
    // SAFETY: a live connection box.
    let s = unsafe { &*src };
    match rpc(
        Some(d.epoch),
        op::BACKUP_INIT,
        [d.id, s.id, 0, 0, 0, 0],
        &[],
        &mut [],
    ) {
        Ok(r) if r.ret2 != 0 => Box::into_raw(Box::new(sqlite3_backup {
            id: r.ret2,
            epoch: d.epoch,
            remaining: 0,
            total: 0,
        })),
        _ => core::ptr::null_mut(),
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_backup_step(p: *mut sqlite3_backup, pages: c_int) -> c_int {
    // SAFETY: a live backup box.
    let b = unsafe { &mut *p };
    match rpc(
        Some(b.epoch),
        op::BACKUP_STEP,
        [b.id, pages as u64, 0, 0, 0, 0],
        &[],
        &mut [],
    ) {
        Ok(r) => {
            b.remaining = (r.ret2 >> 32) as u32;
            b.total = r.ret2 as u32;
            r.ret as c_int
        }
        Err(rc) => rc,
    }
}

// SAFETY (caller contract): stands in for the C function of that name (see the module doc): handles
// are the live boxes this module made, strings NUL-terminated, out pointers writable.
pub unsafe fn sqlite3_backup_finish(p: *mut sqlite3_backup) -> c_int {
    if p.is_null() {
        return SQLITE_OK;
    }
    // SAFETY: a box made in `sqlite3_backup_init`, finished exactly once.
    let b = unsafe { Box::from_raw(p) };
    rpc(
        Some(b.epoch),
        op::BACKUP_FINISH,
        [b.id, 0, 0, 0, 0, 0],
        &[],
        &mut [],
    )
    .map_or_else(|rc| rc, |r| r.ret as c_int)
}

pub unsafe fn sqlite3_backup_remaining(p: *mut sqlite3_backup) -> c_int {
    // SAFETY: a live backup box.
    unsafe { (*p).remaining as c_int }
}

pub unsafe fn sqlite3_backup_pagecount(p: *mut sqlite3_backup) -> c_int {
    // SAFETY: a live backup box.
    unsafe { (*p).total as c_int }
}

pub unsafe fn sqlite3_status64(
    option: c_int,
    current: *mut sqlite3_int64,
    highwater: *mut sqlite3_int64,
    _reset: c_int,
) -> c_int {
    match rpc(
        None,
        op::STATUS,
        [option as u64, 0, 0, 0, 0, 0],
        &[],
        &mut [],
    ) {
        Ok(r) => {
            // SAFETY: a valid out pointer from the caller.
            unsafe { *current = r.ret as i64 };
            // SAFETY: a valid out pointer from the caller.
            unsafe { *highwater = r.ret2 as i64 };
            SQLITE_OK
        }
        Err(rc) => rc,
    }
}
