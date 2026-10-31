//! Safe wrapper over the SQLite C API: [`Db`] and prepared [`Stmt`]s with
//! typed binds and columns. All SQL is fixed at compile time (PROMPT §8).

use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::{CStr, c_int};
use core::ptr;

use crate::ffi::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Extended result code.
    pub code: i32,
    pub message: String,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn code_error(code: c_int) -> Error {
    // SAFETY: any code is accepted.
    let p = unsafe { sqlite3_errstr(code) };
    // SAFETY: `sqlite3_errstr` returns a static NUL-terminated string.
    let msg = unsafe { CStr::from_ptr(p) };
    Error {
        code,
        message: msg.to_string_lossy().into_owned(),
    }
}

/// An open database connection. SQLite is built single-threaded
/// (`SQLITE_THREADSAFE=0`), so a connection may move between cores but is
/// only ever used by one at a time.
pub struct Db {
    raw: *mut sqlite3,
}

// SAFETY: see the type documentation; `&mut self` / ownership serialise use.
unsafe impl Send for Db {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Row,
    Done,
}

impl Db {
    /// Opens (creating if needed) the main database on the `urmqtt` VFS.
    pub fn open() -> Result<Self> {
        Self::open_named(crate::vfs::DB_NAME)
    }

    /// Opens the backup slot the VFS has attached as a database file
    /// (S5): the destination of an online backup.
    pub fn open_backup_target() -> Result<Self> {
        Self::open_named(crate::vfs::BACKUP_NAME)
    }

    fn open_named(name: &CStr) -> Result<Self> {
        let mut raw = ptr::null_mut();
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXRESCODE;
        // SAFETY: valid NUL-terminated names and an out pointer.
        let rc = unsafe {
            sqlite3_open_v2(
                name.as_ptr(),
                &mut raw,
                flags,
                crate::vfs::VFS_NAME.as_ptr(),
            )
        };
        let db = Self { raw };
        if rc != SQLITE_OK {
            return Err(if raw.is_null() {
                code_error(rc)
            } else {
                db.error(rc)
            });
        }
        Ok(db)
    }

    fn error(&self, rc: c_int) -> Error {
        // SAFETY: `raw` is an open connection.
        let code = unsafe { sqlite3_extended_errcode(self.raw) };
        // SAFETY: as above.
        let p = unsafe { sqlite3_errmsg(self.raw) };
        // SAFETY: NUL-terminated, valid until the next API call.
        let msg = unsafe { CStr::from_ptr(p) };
        Error {
            code: if code == 0 { rc } else { code },
            message: msg.to_string_lossy().into_owned(),
        }
    }

    fn check(&self, rc: c_int) -> Result<()> {
        if rc == SQLITE_OK {
            Ok(())
        } else {
            Err(self.error(rc))
        }
    }

    /// Runs one or more statements without results.
    pub fn exec(&self, sql: &str) -> Result<()> {
        let sql = CString::new(sql).map_err(|_| code_error(SQLITE_ERROR))?;
        // SAFETY: open connection, NUL-terminated SQL, no callback.
        let rc = unsafe {
            sqlite3_exec(
                self.raw,
                sql.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        self.check(rc)
    }

    /// Sets a boolean `sqlite3_db_config` option.
    pub fn config_flag(&self, op: c_int, on: bool) -> Result<()> {
        let mut out: c_int = 0;
        // SAFETY: the boolean options take (int, int*).
        let rc =
            unsafe { sqlite3_db_config(self.raw, op, c_int::from(on), &mut out as *mut c_int) };
        self.check(rc)?;
        if (out != 0) == on {
            Ok(())
        } else {
            Err(code_error(SQLITE_ERROR))
        }
    }

    pub fn prepare(&self, sql: &str) -> Result<Stmt> {
        let mut raw = ptr::null_mut();
        let len = c_int::try_from(sql.len()).map_err(|_| code_error(SQLITE_ERROR))?;
        // SAFETY: open connection; `sql` is `len` bytes (no NUL needed).
        let rc = unsafe {
            sqlite3_prepare_v3(
                self.raw,
                sql.as_ptr().cast(),
                len,
                SQLITE_PREPARE_PERSISTENT,
                &mut raw,
                ptr::null_mut(),
            )
        };
        if rc != SQLITE_OK || raw.is_null() {
            return Err(self.error(rc));
        }
        Ok(Stmt { raw, db: self.raw })
    }

    /// Rows changed by the last statement.
    pub fn changes(&self) -> i64 {
        // SAFETY: open connection.
        unsafe { sqlite3_changes64(self.raw) }
    }

    /// Runs a single-value query (`PRAGMA`s, counts).
    pub fn query_text(&self, sql: &str) -> Result<String> {
        let mut s = self.prepare(sql)?;
        match s.step()? {
            Step::Row => Ok(s.text(0).into()),
            Step::Done => Ok(String::new()),
        }
    }

    pub fn query_i64(&self, sql: &str) -> Result<i64> {
        let mut s = self.prepare(sql)?;
        match s.step()? {
            Step::Row => Ok(s.i64(0)),
            Step::Done => Ok(0),
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        // SAFETY: `close_v2` defers the close until every statement is
        // finalised, so drop order with `Stmt`s does not matter.
        unsafe { sqlite3_close_v2(self.raw) };
    }
}

/// What one [`Backup::step`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupStep {
    /// Pages remain.
    More,
    /// Every page is copied and committed to the destination.
    Done,
    /// A lock is held somewhere; try again later.
    Busy,
}

/// An online backup (the SQLite backup API) from one open database into
/// another, copied in bounded steps. Drop it before the destination (and
/// the source) closes.
pub struct Backup {
    raw: *mut sqlite3_backup,
}

// SAFETY: as for `Db`.
unsafe impl Send for Backup {}

impl Backup {
    /// Starts copying `src`'s main database into `dest`'s.
    pub fn new(dest: &Db, src: &Db) -> Result<Self> {
        // SAFETY: two open connections and NUL-terminated names.
        let raw =
            unsafe { sqlite3_backup_init(dest.raw, c"main".as_ptr(), src.raw, c"main".as_ptr()) };
        if raw.is_null() {
            return Err(dest.error(SQLITE_ERROR));
        }
        Ok(Self { raw })
    }

    /// Copies up to `pages` pages (at least one).
    pub fn step(&mut self, pages: u32) -> Result<BackupStep> {
        let n = c_int::try_from(pages.max(1)).unwrap_or(c_int::MAX);
        // SAFETY: a live backup handle.
        match unsafe { sqlite3_backup_step(self.raw, n) } {
            SQLITE_OK => Ok(BackupStep::More),
            SQLITE_DONE => Ok(BackupStep::Done),
            rc if rc & 0xff == SQLITE_BUSY || rc & 0xff == SQLITE_LOCKED => Ok(BackupStep::Busy),
            rc => Err(code_error(rc)),
        }
    }

    /// (pages still to copy, pages in the source), as of the last step.
    pub fn progress(&self) -> (u32, u32) {
        // SAFETY: a live backup handle.
        let r = unsafe { sqlite3_backup_remaining(self.raw) };
        // SAFETY: as above.
        let t = unsafe { sqlite3_backup_pagecount(self.raw) };
        (r.max(0) as u32, t.max(0) as u32)
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        // SAFETY: valid handle, finished exactly once (an unfinished backup
        // is rolled back, which is what a dropped job wants).
        unsafe { sqlite3_backup_finish(self.raw) };
    }
}

/// A prepared statement. It must not outlive its `Db` in use; `Db`'s drop
/// is deferred by SQLite until all statements are finalised.
pub struct Stmt {
    raw: *mut sqlite3_stmt,
    db: *mut sqlite3,
}

// SAFETY: as for `Db`.
unsafe impl Send for Stmt {}

impl Stmt {
    fn check(&self, rc: c_int) -> Result<()> {
        if rc == SQLITE_OK {
            return Ok(());
        }
        // SAFETY: the connection outlives its statements (see `Db::drop`).
        let p = unsafe { sqlite3_errmsg(self.db) };
        // SAFETY: NUL-terminated, valid until the next API call.
        let msg = unsafe { CStr::from_ptr(p) };
        Err(Error {
            code: rc,
            message: msg.to_string_lossy().into_owned(),
        })
    }

    pub fn bind_i64(&mut self, i: c_int, v: i64) -> Result<()> {
        // SAFETY: valid statement; out-of-range indexes return an error.
        let rc = unsafe { sqlite3_bind_int64(self.raw, i, v) };
        self.check(rc)
    }

    pub fn bind_text(&mut self, i: c_int, v: &str) -> Result<()> {
        let n = c_int::try_from(v.len()).map_err(|_| code_error(SQLITE_ERROR))?;
        // SAFETY: `v` is `n` bytes; SQLITE_TRANSIENT makes SQLite copy it.
        let rc = unsafe { sqlite3_bind_text(self.raw, i, v.as_ptr().cast(), n, SQLITE_TRANSIENT) };
        self.check(rc)
    }

    pub fn bind_blob(&mut self, i: c_int, v: &[u8]) -> Result<()> {
        let n = c_int::try_from(v.len()).map_err(|_| code_error(SQLITE_ERROR))?;
        // A zero-length blob still binds as a blob, not NULL: pass a
        // non-null pointer.
        let p = if v.is_empty() {
            c"".as_ptr().cast()
        } else {
            v.as_ptr().cast()
        };
        // SAFETY: `p` covers `n` bytes; SQLITE_TRANSIENT makes SQLite copy.
        let rc = unsafe { sqlite3_bind_blob(self.raw, i, p, n, SQLITE_TRANSIENT) };
        self.check(rc)
    }

    pub fn step(&mut self) -> Result<Step> {
        // SAFETY: valid statement.
        match unsafe { sqlite3_step(self.raw) } {
            SQLITE_ROW => Ok(Step::Row),
            SQLITE_DONE => Ok(Step::Done),
            rc => {
                let e = self.check(rc).err().unwrap_or_else(|| code_error(rc));
                // SAFETY: valid statement; makes it reusable after an error.
                unsafe { sqlite3_reset(self.raw) };
                Err(e)
            }
        }
    }

    /// Resets the statement and clears its bindings for the next use.
    pub fn reset(&mut self) {
        // SAFETY: valid statement. Errors were already reported by `step`.
        unsafe { sqlite3_reset(self.raw) };
        // SAFETY: valid statement.
        unsafe { sqlite3_clear_bindings(self.raw) };
    }

    /// Steps to completion, then resets (INSERT/UPDATE/DELETE).
    pub fn run(&mut self) -> Result<()> {
        let r = loop {
            match self.step() {
                Ok(Step::Row) => {}
                Ok(Step::Done) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        self.reset();
        r
    }

    pub fn i64(&self, col: c_int) -> i64 {
        // SAFETY: valid statement positioned on a row; bad columns yield 0.
        unsafe { sqlite3_column_int64(self.raw, col) }
    }

    pub fn is_null(&self, col: c_int) -> bool {
        // SAFETY: as above.
        unsafe { sqlite3_column_type(self.raw, col) == SQLITE_NULL }
    }

    pub fn blob(&self, col: c_int) -> &[u8] {
        // SAFETY: as above; the pointer is fetched before the length, as
        // the SQLite documentation requires.
        let p = unsafe { sqlite3_column_blob(self.raw, col) };
        // SAFETY: as above.
        let n = unsafe { sqlite3_column_bytes(self.raw, col) };
        if p.is_null() || n <= 0 {
            return &[];
        }
        // SAFETY: SQLite guarantees `n` bytes at `p` until the next step,
        // reset or finalize, all of which need `&mut self`.
        unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n as usize) }
    }

    /// Text column; invalid UTF-8 (impossible for our own writes) yields "".
    pub fn text(&self, col: c_int) -> &str {
        // SAFETY: as for `blob`.
        let p = unsafe { sqlite3_column_text(self.raw, col) };
        // SAFETY: as above.
        let n = unsafe { sqlite3_column_bytes(self.raw, col) };
        if p.is_null() || n <= 0 {
            return "";
        }
        // SAFETY: as for `blob`.
        let b = unsafe { core::slice::from_raw_parts(p, n as usize) };
        core::str::from_utf8(b).unwrap_or("")
    }
}

impl Drop for Stmt {
    fn drop(&mut self) {
        // SAFETY: valid statement, finalised exactly once.
        unsafe { sqlite3_finalize(self.raw) };
    }
}

/// SQLite's version string.
pub fn version() -> &'static str {
    // SAFETY: no preconditions.
    let p = unsafe { sqlite3_libversion() };
    // SAFETY: static NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().unwrap_or("?")
}

/// Bytes currently allocated from the SQLite heap, and the high-water mark.
pub fn memory_used() -> (i64, i64) {
    let (mut cur, mut hi) = (0i64, 0i64);
    // SAFETY: valid out pointers. Needs SQLITE_DEFAULT_MEMSTATUS for exact
    // numbers; memsys5 still tracks its own totals.
    unsafe { sqlite3_status64(SQLITE_STATUS_MEMORY_USED, &mut cur, &mut hi, 0) };
    (cur, hi)
}
