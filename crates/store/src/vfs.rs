//! The `urmqtt` SQLite VFS: three fixed files (main db, WAL, rollback
//! journal) mapped onto disk regions, no filesystem (PROMPT §8, ADR-030).
//!
//! SQLite runs on one core only (the DB core), so callbacks never race.
//! The state still sits behind a spin lock, so ownership can move between
//! cores at boot and the disk can be inspected from tests. No callback calls
//! back into SQLite while holding it.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};

use urmqtt_sync::sync::SpinLock;

use crate::disk::{Disk, DiskError, DiskStats};
use crate::ffi::*;
use crate::layout::{FileKind, RegionKind};

/// Name of the main database file; the WAL and journal derive from it.
pub const DB_NAME: &CStr = c"urmqtt.db";
pub const VFS_NAME: &CStr = c"urmqtt";

/// Services the VFS needs from its environment.
#[derive(Clone, Copy)]
pub struct Platform {
    /// Fills the buffer from the CSPRNG.
    pub random: fn(&mut [u8]),
    /// Wall-clock time in Unix milliseconds, if known.
    pub now_unix_ms: fn() -> Option<u64>,
    pub delay_us: fn(u32),
    /// SQLite's error log (`SQLITE_CONFIG_LOG`).
    pub log: fn(i32, &str),
}

struct Vfs {
    disk: Disk,
    platform: Platform,
}

static STATE: SpinLock<Option<Vfs>> = SpinLock::new(None);

/// Installs the disk and platform hooks. Must happen before
/// `sqlite3_initialize` (which registers the VFS).
pub fn install(disk: Disk, platform: Platform) {
    *STATE.lock() = Some(Vfs { disk, platform });
}

/// Runs `f` on the installed disk (layout inspection, telemetry in M12).
pub fn with_disk<R>(f: impl FnOnce(&mut Disk) -> R) -> Option<R> {
    STATE.lock().as_mut().map(|v| f(&mut v.disk))
}

pub fn disk_stats() -> DiskStats {
    with_disk(|d| d.stats).unwrap_or_default()
}

pub(crate) fn platform() -> Option<Platform> {
    STATE.lock().as_ref().map(|v| v.platform)
}

fn with<R>(f: impl FnOnce(&mut Vfs) -> R) -> Option<R> {
    STATE.lock().as_mut().map(f)
}

/// A file opened through this VFS: SQLite allocates `szOsFile` bytes and
/// we keep which region it maps to after the base struct.
#[repr(C)]
struct File {
    base: sqlite3_file,
    kind: FileKind,
}

fn kind_of(name: &[u8]) -> Option<FileKind> {
    let db = DB_NAME.to_bytes();
    let rest = name.strip_prefix(db)?;
    match rest {
        b"" => Some(FileKind::Db),
        b"-wal" => Some(FileKind::Wal),
        b"-journal" => Some(FileKind::Journal),
        _ => None,
    }
}

/// # Safety
/// `name` is null or a NUL-terminated string from SQLite.
unsafe fn name_kind(name: *const c_char) -> Option<FileKind> {
    if name.is_null() {
        return None;
    }
    // SAFETY: non-null, NUL-terminated (SQLite contract).
    let s = unsafe { CStr::from_ptr(name) };
    kind_of(s.to_bytes())
}

/// # Safety
/// `f` is a `File` this VFS opened.
unsafe fn file_kind(f: *mut sqlite3_file) -> FileKind {
    // SAFETY: SQLite passes back the `szOsFile`-sized object we filled in
    // `x_open`, whose layout is `File`.
    unsafe { (*f.cast::<File>()).kind }
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
    let Some(kind) = (unsafe { name_kind(name) }) else {
        return SQLITE_CANTOPEN;
    };
    if with(|_| ()).is_none() {
        return SQLITE_CANTOPEN;
    }
    // SAFETY: as above; the object is ours to initialise.
    unsafe { (*f).kind = kind };
    // SAFETY: as above.
    unsafe { (*f).base.methods = &IO_METHODS };
    if !out_flags.is_null() {
        // SAFETY: non-null out pointer from SQLite.
        unsafe { *out_flags = flags };
    }
    SQLITE_OK
}

unsafe extern "C" fn x_delete(
    _vfs: *mut sqlite3_vfs,
    name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    // SAFETY: `name` comes from SQLite.
    let Some(kind) = (unsafe { name_kind(name) }) else {
        return SQLITE_IOERR_DELETE;
    };
    let r = with(|v| {
        v.disk.set_file_size(kind, 0);
        v.disk.sync()
    });
    match r {
        Some(Ok(())) => SQLITE_OK,
        _ => SQLITE_IOERR_DELETE,
    }
}

unsafe extern "C" fn x_access(
    _vfs: *mut sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    // SAFETY: `name` comes from SQLite.
    let kind = unsafe { name_kind(name) };
    let exists = match kind {
        Some(k) if flags == SQLITE_ACCESS_EXISTS => {
            with(|v| v.disk.file_size(k) > 0).unwrap_or(false)
        }
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
    let Some(p) = platform() else { return 0 };
    if n <= 0 || out.is_null() {
        return 0;
    }
    // SAFETY: SQLite passes `n` writable bytes at `out`.
    let buf = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), n as usize) };
    (p.random)(buf);
    n
}

unsafe extern "C" fn x_sleep(_vfs: *mut sqlite3_vfs, us: c_int) -> c_int {
    if let Some(p) = platform() {
        (p.delay_us)(us.max(0) as u32);
    }
    us
}

/// Julian day number of the Unix epoch, in milliseconds.
const UNIX_EPOCH_JD_MS: i64 = 210_866_760_000_000;

fn now_jd_ms() -> i64 {
    let ms = platform().and_then(|p| (p.now_unix_ms)()).unwrap_or(0);
    UNIX_EPOCH_JD_MS + ms as i64
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

unsafe extern "C" fn x_get_last_error(
    _vfs: *mut sqlite3_vfs,
    _n: c_int,
    _out: *mut c_char,
) -> c_int {
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
    let kind = unsafe { file_kind(f) };
    if amt < 0 || off < 0 {
        return SQLITE_IOERR_READ;
    }
    // SAFETY: SQLite passes `amt` writable bytes at `buf`.
    let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), amt as usize) };
    let off = off as u64;
    let r = with(|v| {
        let size = v.disk.file_size(kind);
        let avail = size.saturating_sub(off).min(out.len() as u64) as usize;
        let (have, rest) = out.split_at_mut(avail);
        rest.fill(0);
        if avail > 0 {
            v.disk.read_at(RegionKind::of_file(kind), off, have)?;
        }
        Ok::<bool, DiskError>(avail == out.len())
    });
    match r {
        Some(Ok(true)) => SQLITE_OK,
        // Short reads must zero-fill the rest (done above).
        Some(Ok(false)) => SQLITE_IOERR_SHORT_READ,
        _ => SQLITE_IOERR_READ,
    }
}

unsafe extern "C" fn x_write(
    f: *mut sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    off: sqlite3_int64,
) -> c_int {
    // SAFETY: `f` is one of our files.
    let kind = unsafe { file_kind(f) };
    if amt < 0 || off < 0 {
        return SQLITE_IOERR_WRITE;
    }
    // SAFETY: SQLite passes `amt` readable bytes at `buf`.
    let data = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), amt as usize) };
    let off = off as u64;
    let r = with(|v| {
        // A write past the end leaves a gap that reads as zeros, whatever
        // the disk holds there (stale data, or anything after a discard).
        let size = v.disk.file_size(kind);
        if off > size {
            v.disk.zero_fill(RegionKind::of_file(kind), size, off)?;
        }
        v.disk.write_at(RegionKind::of_file(kind), off, data)?;
        let end = off + data.len() as u64;
        if end > v.disk.file_size(kind) {
            v.disk.set_file_size(kind, end);
        }
        Ok::<(), DiskError>(())
    });
    match r {
        Some(Ok(())) => SQLITE_OK,
        Some(Err(DiskError::Full)) => SQLITE_FULL,
        _ => SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn x_truncate(f: *mut sqlite3_file, size: sqlite3_int64) -> c_int {
    // SAFETY: `f` is one of our files.
    let kind = unsafe { file_kind(f) };
    if size < 0 {
        return SQLITE_IOERR_TRUNCATE;
    }
    let size = size as u64;
    let r = with(|v| {
        // Growing by truncate exposes zeros, not what the disk held.
        let cur = v.disk.file_size(kind);
        if size > cur {
            v.disk.zero_fill(RegionKind::of_file(kind), cur, size)?;
        }
        v.disk.set_file_size(kind, size);
        Ok::<(), DiskError>(())
    });
    match r {
        Some(Ok(())) => SQLITE_OK,
        Some(Err(DiskError::Full)) => SQLITE_FULL,
        _ => SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn x_sync(_f: *mut sqlite3_file, _flags: c_int) -> c_int {
    match with(|v| v.disk.sync()) {
        Some(Ok(())) => SQLITE_OK,
        _ => SQLITE_IOERR_FSYNC,
    }
}

unsafe extern "C" fn x_file_size(f: *mut sqlite3_file, out: *mut sqlite3_int64) -> c_int {
    // SAFETY: `f` is one of our files.
    let kind = unsafe { file_kind(f) };
    let size = with(|v| v.disk.file_size(kind)).unwrap_or(0);
    // SAFETY: valid out pointer from SQLite.
    unsafe { *out = size as sqlite3_int64 };
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

// SAFETY: only SQLite touches the object, from the one core running it.
unsafe impl Sync for VfsCell {}

static VFS: VfsCell = VfsCell(UnsafeCell::new(sqlite3_vfs {
    version: 2,
    os_file_size: core::mem::size_of::<File>() as c_int,
    max_pathname: 64,
    next: core::ptr::null_mut(),
    name: VFS_NAME.as_ptr(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_map_to_files() {
        assert_eq!(kind_of(b"urmqtt.db"), Some(FileKind::Db));
        assert_eq!(kind_of(b"urmqtt.db-wal"), Some(FileKind::Wal));
        assert_eq!(kind_of(b"urmqtt.db-journal"), Some(FileKind::Journal));
        assert_eq!(kind_of(b"urmqtt.db-shm"), None);
        assert_eq!(kind_of(b"other.db"), None);
        assert_eq!(kind_of(b""), None);
    }
}
