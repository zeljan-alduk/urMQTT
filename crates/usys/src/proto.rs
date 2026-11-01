//! The SQLite protocol between the kernel's store and the worker (ADR-211):
//! operation numbers, the system calls of the VFS, and the byte formats of
//! binds and rows in the I/O area. Pure code, tested on the host.
//!
//! Handles (`db`, `stmt`, `backup`) are small integers chosen by the worker;
//! the kernel keeps them as opaque numbers and never dereferences anything.
//! Every number that comes back from the worker is checked by the reader.

/// Operations the kernel asks of the worker (see `abi::op` for the test
/// operations below 32).
pub mod op {
    /// `a0` = heap length. Configures and initialises SQLite; `ret` = rc.
    pub const INIT: u64 = 32;
    /// The version string in the I/O area.
    pub const VERSION: u64 = 33;
    /// `a0` = which file (0 main, 3 backup): `ret` = rc, `ret2` = db handle.
    pub const OPEN: u64 = 34;
    /// `a0` = db.
    pub const CLOSE: u64 = 35;
    /// `a0` = db, `a1` = option, `a2` = on: `ret` = rc, `ret2` = value read back.
    pub const DBCONFIG: u64 = 36;
    /// `a0` = db, `a1` = on.
    pub const EXTENDED: u64 = 37;
    /// `a0` = db, SQL in the I/O area: `ret` = rc.
    pub const EXEC: u64 = 38;
    /// `a0` = db, `a1` = flags, SQL in the I/O area: `ret` = rc, `ret2` =
    /// stmt handle | parameter count << 32.
    pub const PREPARE: u64 = 39;
    /// `a0` = stmt, `a1` = flags ([`STEP_RESET`]), binds in the I/O area
    /// ([`encode_bind`]): `ret` = rc; on `SQLITE_ROW` the row in the I/O
    /// area ([`RowWriter`]).
    pub const STEP: u64 = 40;
    /// `a0` = stmt: reset and clear bindings; `ret` = rc.
    pub const RESET: u64 = 41;
    /// `a0` = stmt.
    pub const FINALIZE: u64 = 42;
    /// `a0` = db: `ret` = extended error code, message in the I/O area.
    pub const ERRMSG: u64 = 43;
    /// `a0` = code: the text in the I/O area.
    pub const ERRSTR: u64 = 44;
    /// `a0` = db: `ret` = rows changed by the last statement.
    pub const CHANGES: u64 = 45;
    /// `a0` = dest db, `a1` = source db: `ret2` = backup handle (0: failed).
    pub const BACKUP_INIT: u64 = 46;
    /// `a0` = backup, `a1` = pages: `ret` = rc.
    pub const BACKUP_STEP: u64 = 47;
    /// `a0` = backup.
    pub const BACKUP_FINISH: u64 = 48;
    /// `a0` = backup: `ret` = pages remaining, `ret2` = page count.
    pub const BACKUP_PROGRESS: u64 = 49;
    /// `a0` = status option: `ret` = current, `ret2` = high-water mark.
    pub const STATUS: u64 = 50;
}

/// System calls of the VFS (the worker asks, the kernel serves); they
/// follow `abi::sys` (0 and 1).
pub mod vfs {
    /// `a0` = file: `ret` = 0 (the file may be opened) or 1 (it may not).
    pub const OPEN: u64 = 2;
    /// `a0` = file: `ret` = 0 ok, 1 failed.
    pub const DELETE: u64 = 3;
    /// `a0` = file: `ret` = 1 if it exists (non-zero size), else 0.
    pub const EXISTS: u64 = 4;
    /// `a0` = file, `a1` = offset, `a2` = length: the bytes in the I/O area
    /// (short reads zero-filled); `ret` = [`RC_OK`], [`RC_SHORT`] or [`RC_ERR`].
    pub const READ: u64 = 5;
    /// `a0` = file, `a1` = offset, `a2` = length, bytes in the I/O area:
    /// `ret` = [`RC_OK`], [`RC_FULL`] or [`RC_ERR`].
    pub const WRITE: u64 = 6;
    /// `a0` = file, `a1` = size: `ret` = [`RC_OK`], [`RC_FULL`] or [`RC_ERR`].
    pub const TRUNCATE: u64 = 7;
    /// `ret` = [`RC_OK`] or [`RC_ERR`].
    pub const SYNC: u64 = 8;
    /// `a0` = file: `ret` = size in bytes.
    pub const SIZE: u64 = 9;
    /// `a0` = length: random bytes in the I/O area.
    pub const RANDOM: u64 = 10;
    /// `ret` = Unix milliseconds (0 if the clock is unknown).
    pub const TIME: u64 = 11;
    /// `a0` = microseconds.
    pub const SLEEP: u64 = 12;
    /// `a0` = SQLite's log code, `a1` = length, text in the I/O area.
    pub const LOG: u64 = 13;

    pub const RC_OK: u64 = 0;
    pub const RC_SHORT: u64 = 1;
    pub const RC_FULL: u64 = 2;
    pub const RC_ERR: u64 = 3;
    /// Files, as the worker names them.
    pub const FILE_DB: u64 = 0;
    pub const FILE_WAL: u64 = 1;
    pub const FILE_JOURNAL: u64 = 2;
    pub const FILE_BACKUP: u64 = 3;
}

/// [`op::STEP`] flag: reset the statement and clear its bindings first.
pub const STEP_RESET: u64 = 1;

/// Column types in a row (SQLite's own numbers).
pub const T_INTEGER: u8 = 1;
pub const T_FLOAT: u8 = 2;
pub const T_TEXT: u8 = 3;
pub const T_BLOB: u8 = 4;
pub const T_NULL: u8 = 5;

/// A bind value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind<'a> {
    Null,
    Int(i64),
    Text(&'a [u8]),
    Blob(&'a [u8]),
}

const B_NULL: u8 = 0;
const B_INT: u8 = 1;
const B_TEXT: u8 = 2;
const B_BLOB: u8 = 3;

/// Appends bytes to a fixed buffer; fails (returns `false`) when full.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn put(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(bytes.len()) else {
            return false;
        };
        match self.buf.get_mut(self.len..end) {
            Some(dst) => {
                dst.copy_from_slice(bytes);
                self.len = end;
                true
            }
            None => false,
        }
    }

    pub fn u8(&mut self, v: u8) -> bool {
        self.put(&[v])
    }

    pub fn u16(&mut self, v: u16) -> bool {
        self.put(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> bool {
        self.put(&v.to_le_bytes())
    }

    pub fn i64(&mut self, v: i64) -> bool {
        self.put(&v.to_le_bytes())
    }

    /// A length-prefixed byte string.
    pub fn bytes(&mut self, b: &[u8]) -> bool {
        u32::try_from(b.len()).is_ok_and(|n| self.u32(n)) && self.put(b)
    }

    /// Overwrites the two bytes at `at` (a count written afterwards).
    pub fn patch_u16(&mut self, at: usize, v: u16) {
        if let Some(dst) = self.buf.get_mut(at..at + 2) {
            dst.copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// Reads from a byte slice; every read is bounds-checked and returns `None`
/// past the end, which is how corrupt data from the worker is refused.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|b| b.first().copied())
    }

    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A length-prefixed byte string.
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Appends one bind (parameter `idx`, 1-based) to a [`op::STEP`] request.
/// The request starts with a `u16` count the caller patches at offset 0.
pub fn encode_bind(w: &mut Writer<'_>, idx: u16, b: Bind<'_>) -> bool {
    w.u16(idx)
        && match b {
            Bind::Null => w.u8(B_NULL),
            Bind::Int(v) => w.u8(B_INT) && w.i64(v),
            Bind::Text(t) => w.u8(B_TEXT) && w.bytes(t),
            Bind::Blob(t) => w.u8(B_BLOB) && w.bytes(t),
        }
}

/// Reads the next bind of a [`op::STEP`] request.
pub fn decode_bind<'a>(r: &mut Reader<'a>) -> Option<(u16, Bind<'a>)> {
    let idx = r.u16()?;
    let b = match r.u8()? {
        B_NULL => Bind::Null,
        B_INT => Bind::Int(r.i64()?),
        B_TEXT => Bind::Text(r.bytes()?),
        B_BLOB => Bind::Blob(r.bytes()?),
        _ => return None,
    };
    Some((idx, b))
}

/// One column of a decoded row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column<'a> {
    pub ty: u8,
    /// `sqlite3_column_int64` (SQLite's own conversion).
    pub int: i64,
    /// The bytes of a TEXT or BLOB column; empty otherwise.
    pub data: &'a [u8],
}

/// Writes a row: `u16` column count, then per column its type, its integer
/// value and, for TEXT and BLOB, the bytes.
pub fn encode_column(w: &mut Writer<'_>, ty: u8, int: i64, data: &[u8]) -> bool {
    w.u8(ty) && w.i64(int) && (ty != T_TEXT && ty != T_BLOB || w.bytes(data))
}

/// Decodes a row into `out` (cleared first); `None` if it is malformed,
/// has a column type SQLite does not have, or more than `max` columns.
pub fn decode_row<'a>(buf: &'a [u8], max: usize, out: &mut [Column<'a>]) -> Option<usize> {
    let mut r = Reader::new(buf);
    let n = r.u16()? as usize;
    if n > max || n > out.len() {
        return None;
    }
    for slot in out.iter_mut().take(n) {
        let ty = r.u8()?;
        let int = r.i64()?;
        let data = if ty == T_TEXT || ty == T_BLOB {
            r.bytes()?
        } else if (T_INTEGER..=T_NULL).contains(&ty) {
            &[]
        } else {
            return None;
        };
        *slot = Column { ty, int, data };
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_round_trip() {
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        assert!(w.u16(4));
        assert!(encode_bind(&mut w, 1, Bind::Text(b"a/b")));
        assert!(encode_bind(&mut w, 2, Bind::Blob(b"")));
        assert!(encode_bind(&mut w, 3, Bind::Int(-5)));
        assert!(encode_bind(&mut w, 4, Bind::Null));
        let n = w.len();
        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.u16(), Some(4));
        assert_eq!(decode_bind(&mut r), Some((1, Bind::Text(b"a/b"))));
        assert_eq!(decode_bind(&mut r), Some((2, Bind::Blob(b""))));
        assert_eq!(decode_bind(&mut r), Some((3, Bind::Int(-5))));
        assert_eq!(decode_bind(&mut r), Some((4, Bind::Null)));
        assert_eq!(decode_bind(&mut r), None, "nothing left");
    }

    #[test]
    fn truncated_or_unknown_binds_are_refused() {
        let mut r = Reader::new(&[1, 0, 9]);
        assert_eq!(decode_bind(&mut r), None, "unknown kind");
        let mut r = Reader::new(&[1, 0, 2, 255, 255, 0, 0]);
        assert_eq!(decode_bind(&mut r), None, "length past the end");
    }

    #[test]
    fn rows_round_trip_and_reject_garbage() {
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        assert!(w.u16(3));
        assert!(encode_column(&mut w, T_INTEGER, 42, &[]));
        assert!(encode_column(&mut w, T_TEXT, 0, b"hi"));
        assert!(encode_column(&mut w, T_NULL, 0, &[]));
        let n = w.len();
        let mut cols = [Column {
            ty: 0,
            int: 0,
            data: &[],
        }; 4];
        assert_eq!(decode_row(&buf[..n], 4, &mut cols), Some(3));
        assert_eq!(cols[0].int, 42);
        assert_eq!(cols[1].data, b"hi");
        assert_eq!(cols[2].ty, T_NULL);
        assert_eq!(decode_row(&buf[..n - 1], 4, &mut cols), None, "truncated");
        assert_eq!(
            decode_row(&buf[..n], 2, &mut cols),
            None,
            "too many columns"
        );
        // A column type SQLite does not have.
        let mut bad = [0u8; 16];
        bad[0] = 1;
        bad[2] = 9;
        assert_eq!(decode_row(&bad, 4, &mut cols), None);
    }

    #[test]
    fn writer_stops_at_the_end() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        assert!(w.u32(1));
        assert!(!w.u8(1));
        assert!(!w.bytes(b"x"));
    }
}
