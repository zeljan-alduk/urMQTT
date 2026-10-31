//! The broker's durable state on SQLite: device registry, revocations,
//! retained messages and persistent sessions (PROMPT §7.4, §8).
//!
//! Every statement is prepared once at open. Writes are grouped into
//! transactions by the caller ([`Store::begin`] / [`Store::commit`]), which
//! is how the DB core batches work from the data cores.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::crc::crc32c;
use crate::db::{Db, Error, Step, Stmt};
use crate::disk::DiskError;
use crate::ffi::{SQLITE_DBCONFIG_DEFENSIVE, SQLITE_DBCONFIG_TRUSTED_SCHEMA};
use crate::layout::RegionKind;
use crate::schema;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Disk(DiskError),
    Sql(Error),
    /// `PRAGMA quick_check` did not return "ok".
    Corrupt(String),
    /// WAL could not be enabled (journal mode returned instead).
    NotWal(String),
    /// The database was written by a newer schema.
    TooNew(i64),
    /// `sqlite3_initialize` or configuration failed.
    Init(i32),
}

impl From<Error> for StoreError {
    fn from(e: Error) -> Self {
        Self::Sql(e)
    }
}

impl From<DiskError> for StoreError {
    fn from(e: DiskError) -> Self {
        Self::Disk(e)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disk(e) => write!(f, "disk: {e:?}"),
            Self::Sql(e) => write!(f, "sqlite: {e}"),
            Self::Corrupt(s) => write!(f, "quick_check failed: {s}"),
            Self::NotWal(m) => write!(f, "WAL mode unavailable (journal_mode={m})"),
            Self::TooNew(v) => write!(
                f,
                "schema version {v} is newer than this build ({})",
                schema::VERSION
            ),
            Self::Init(rc) => write!(f, "sqlite initialisation failed (rc={rc})"),
        }
    }
}

pub type Result<T> = core::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retained {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRecord {
    pub client_id: String,
    pub subscriptions: Vec<(String, u8)>,
    pub queued: Vec<Queued>,
}

/// What [`Store::open`] did, for the boot log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenInfo {
    pub schema_from: i64,
    pub schema_to: i64,
    pub pages: i64,
}

struct Stmts {
    begin: Stmt,
    commit: Stmt,
    rollback: Stmt,
    device_seen: Stmt,
    device_count: Stmt,
    revoked_add: Stmt,
    revoked_del: Stmt,
    revoked_all: Stmt,
    control_seq: Stmt,
    control_seq_set: Stmt,
    allow_add: Stmt,
    allow_del: Stmt,
    allow_all: Stmt,
    retained_set: Stmt,
    retained_del: Stmt,
    retained_all: Stmt,
    session_upsert: Stmt,
    session_del: Stmt,
    session_all: Stmt,
    sub_set: Stmt,
    sub_del: Stmt,
    sub_all: Stmt,
    queue_push: Stmt,
    queue_clear: Stmt,
    queue_all: Stmt,
    selftest_ins: Stmt,
    selftest_all: Stmt,
    selftest_clear: Stmt,
}

pub struct Store {
    // Statements before the connection: dropped (finalised) first.
    s: Stmts,
    db: Db,
    in_txn: bool,
}

/// Opens the database: exclusive locking + WAL, defensive mode, integrity
/// check, migrations, prepared statements.
pub fn open() -> Result<(Store, OpenInfo)> {
    let db = Db::open()?;
    db.config_flag(SQLITE_DBCONFIG_DEFENSIVE, true)?;
    db.config_flag(SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    // Exclusive locking first: WAL then needs no shared-memory index, which
    // this VFS does not provide (ADR-030).
    let lock = db.query_text("PRAGMA locking_mode = EXCLUSIVE")?;
    if !lock.eq_ignore_ascii_case("exclusive") {
        return Err(StoreError::NotWal(lock));
    }
    let mode = db.query_text("PRAGMA journal_mode = WAL")?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::NotWal(mode));
    }
    db.exec("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA cell_size_check = ON;")?;
    // Checkpoint while the WAL is at most half its region (frames are a
    // 24-byte header plus one 4 KiB page), so a large transaction still fits.
    let wal_bytes = crate::vfs::with_disk(|d| d.bytes(RegionKind::Wal)).unwrap_or(0);
    let frames = (wal_bytes / (4096 + 24) / 2).clamp(32, 1000);
    db.exec(&format!("PRAGMA wal_autocheckpoint = {frames}"))?;
    let qc = db.query_text("PRAGMA quick_check")?;
    if qc != "ok" {
        return Err(StoreError::Corrupt(qc));
    }
    let from = db.query_i64("PRAGMA user_version")?;
    if from > schema::VERSION {
        return Err(StoreError::TooNew(from));
    }
    for (i, m) in schema::MIGRATIONS
        .iter()
        .enumerate()
        .skip(from.max(0) as usize)
    {
        db.exec("BEGIN")?;
        let r = db
            .exec(m)
            .and_then(|()| db.exec(&format!("PRAGMA user_version = {}", i + 1)))
            .and_then(|()| db.exec("COMMIT"));
        if let Err(e) = r {
            let _ = db.exec("ROLLBACK");
            return Err(e.into());
        }
    }
    let pages = db.query_i64("PRAGMA page_count")?;
    let s = Stmts {
        begin: db.prepare("BEGIN")?,
        commit: db.prepare("COMMIT")?,
        rollback: db.prepare("ROLLBACK")?,
        device_seen: db.prepare(
            "INSERT INTO devices (id, first_seen, last_seen, connects) VALUES (?1, ?2, ?2, 1)
             ON CONFLICT (id) DO UPDATE SET last_seen = excluded.last_seen, connects = connects + 1",
        )?,
        device_count: db.prepare("SELECT count(*) FROM devices")?,
        revoked_add: db.prepare(
            "INSERT INTO revoked (serial, source, revoked_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (serial) DO NOTHING",
        )?,
        revoked_all: db.prepare("SELECT serial FROM revoked ORDER BY serial")?,
        // Serials the image lists are re-seeded at every boot; they are
        // never removed here.
        revoked_del: db.prepare("DELETE FROM revoked WHERE serial = ?1 AND source <> 'config'")?,
        control_seq: db.prepare("SELECT seq FROM control_state WHERE id = 1")?,
        control_seq_set: db.prepare("UPDATE control_state SET seq = ?1 WHERE id = 1 AND seq < ?1")?,
        allow_add: db.prepare(
            "INSERT INTO allowlist (id, added_at, seq) VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET seq = excluded.seq",
        )?,
        allow_del: db.prepare("DELETE FROM allowlist WHERE id = ?1")?,
        allow_all: db.prepare("SELECT id FROM allowlist ORDER BY id")?,
        retained_set: db.prepare(
            "INSERT INTO retained (topic, payload, qos) VALUES (?1, ?2, ?3)
             ON CONFLICT (topic) DO UPDATE SET payload = excluded.payload, qos = excluded.qos",
        )?,
        retained_del: db.prepare("DELETE FROM retained WHERE topic = ?1")?,
        retained_all: db.prepare("SELECT topic, payload, qos FROM retained ORDER BY topic")?,
        session_upsert: db.prepare(
            "INSERT INTO sessions (client_id, updated) VALUES (?1, ?2)
             ON CONFLICT (client_id) DO UPDATE SET updated = excluded.updated",
        )?,
        session_del: db.prepare("DELETE FROM sessions WHERE client_id = ?1")?,
        session_all: db.prepare("SELECT client_id FROM sessions ORDER BY client_id")?,
        sub_set: db.prepare(
            "INSERT INTO subscriptions (client_id, filter, qos) VALUES (?1, ?2, ?3)
             ON CONFLICT (client_id, filter) DO UPDATE SET qos = excluded.qos",
        )?,
        sub_del: db.prepare("DELETE FROM subscriptions WHERE client_id = ?1 AND filter = ?2")?,
        sub_all: db.prepare("SELECT client_id, filter, qos FROM subscriptions ORDER BY client_id, filter")?,
        queue_push: db.prepare(
            "INSERT INTO queued (client_id, topic, payload, qos) VALUES (?1, ?2, ?3, ?4)",
        )?,
        queue_clear: db.prepare("DELETE FROM queued WHERE client_id = ?1")?,
        queue_all: db.prepare("SELECT client_id, topic, payload, qos FROM queued ORDER BY client_id, seq")?,
        selftest_ins: db.prepare("INSERT INTO selftest (seq, data, crc) VALUES (?1, ?2, ?3)")?,
        selftest_all: db.prepare("SELECT seq, data, crc FROM selftest ORDER BY seq")?,
        selftest_clear: db.prepare("DELETE FROM selftest")?,
    };
    let info = OpenInfo {
        schema_from: from,
        schema_to: schema::VERSION,
        pages,
    };
    Ok((
        Store {
            s,
            db,
            in_txn: false,
        },
        info,
    ))
}

fn qos_of(v: i64) -> u8 {
    u8::from(v == 1)
}

impl Store {
    pub fn begin(&mut self) -> Result<()> {
        if !self.in_txn {
            self.s.begin.run()?;
            self.in_txn = true;
        }
        Ok(())
    }

    /// Commits the open transaction (durable on return: WAL + FULL sync).
    pub fn commit(&mut self) -> Result<()> {
        if self.in_txn {
            self.in_txn = false;
            if let Err(e) = self.s.commit.run() {
                let _ = self.s.rollback.run();
                return Err(e.into());
            }
        }
        Ok(())
    }

    pub fn in_transaction(&self) -> bool {
        self.in_txn
    }

    pub fn device_seen(&mut self, id: &str, now_unix: i64) -> Result<()> {
        let s = &mut self.s.device_seen;
        s.bind_text(1, id)?;
        s.bind_i64(2, now_unix)?;
        Ok(s.run()?)
    }

    pub fn device_count(&mut self) -> Result<i64> {
        let s = &mut self.s.device_count;
        let n = match s.step()? {
            Step::Row => s.i64(0),
            Step::Done => 0,
        };
        s.reset();
        Ok(n)
    }

    pub fn revoke(&mut self, serial_hex: &str, source: &str, now_unix: i64) -> Result<()> {
        let s = &mut self.s.revoked_add;
        s.bind_text(1, serial_hex)?;
        s.bind_text(2, source)?;
        s.bind_i64(3, now_unix)?;
        Ok(s.run()?)
    }

    /// Removes a runtime revocation (one the image does not list).
    pub fn unrevoke(&mut self, serial_hex: &str) -> Result<()> {
        let s = &mut self.s.revoked_del;
        s.bind_text(1, serial_hex)?;
        Ok(s.run()?)
    }

    /// The last accepted control sequence number (0: none yet).
    pub fn control_seq(&mut self) -> Result<u64> {
        let s = &mut self.s.control_seq;
        let n = match s.step()? {
            Step::Row => s.i64(0),
            Step::Done => 0,
        };
        s.reset();
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Raises the control sequence number (never lowers it). Call inside
    /// the transaction that applies the message's effect.
    pub fn set_control_seq(&mut self, seq: u64) -> Result<()> {
        let s = &mut self.s.control_seq_set;
        s.bind_i64(1, i64::try_from(seq).unwrap_or(i64::MAX))?;
        Ok(s.run()?)
    }

    pub fn allow(&mut self, id: &str, seq: u64, now_unix: i64) -> Result<()> {
        let s = &mut self.s.allow_add;
        s.bind_text(1, id)?;
        s.bind_i64(2, now_unix)?;
        s.bind_i64(3, i64::try_from(seq).unwrap_or(i64::MAX))?;
        Ok(s.run()?)
    }

    pub fn disallow(&mut self, id: &str) -> Result<()> {
        let s = &mut self.s.allow_del;
        s.bind_text(1, id)?;
        Ok(s.run()?)
    }

    pub fn allowlist(&mut self) -> Result<Vec<String>> {
        let s = &mut self.s.allow_all;
        let mut out = Vec::new();
        let r = (|| {
            while s.step()? == Step::Row {
                out.push(String::from(s.text(0)));
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(out)
    }

    /// Discards the open transaction.
    pub fn rollback(&mut self) {
        if self.in_txn {
            self.in_txn = false;
            let _ = self.s.rollback.run();
        }
    }

    pub fn revoked(&mut self) -> Result<Vec<String>> {
        let s = &mut self.s.revoked_all;
        let mut out = Vec::new();
        let r = (|| {
            while s.step()? == Step::Row {
                out.push(String::from(s.text(0)));
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(out)
    }

    /// Stores a retained message; an empty payload deletes it (§3.3.1.3).
    pub fn retain(&mut self, topic: &str, payload: &[u8], qos: u8) -> Result<()> {
        if payload.is_empty() {
            let s = &mut self.s.retained_del;
            s.bind_text(1, topic)?;
            return Ok(s.run()?);
        }
        let s = &mut self.s.retained_set;
        s.bind_text(1, topic)?;
        s.bind_blob(2, payload)?;
        s.bind_i64(3, i64::from(qos.min(1)))?;
        Ok(s.run()?)
    }

    pub fn retained(&mut self) -> Result<Vec<Retained>> {
        let s = &mut self.s.retained_all;
        let mut out = Vec::new();
        let r = (|| {
            while s.step()? == Step::Row {
                out.push(Retained {
                    topic: s.text(0).into(),
                    payload: s.blob(1).into(),
                    qos: qos_of(s.i64(2)),
                });
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(out)
    }

    pub fn session_upsert(&mut self, client_id: &str, now_unix: i64) -> Result<()> {
        let s = &mut self.s.session_upsert;
        s.bind_text(1, client_id)?;
        s.bind_i64(2, now_unix)?;
        Ok(s.run()?)
    }

    /// Deletes a session with its subscriptions and queue (cascade).
    pub fn session_delete(&mut self, client_id: &str) -> Result<()> {
        let s = &mut self.s.session_del;
        s.bind_text(1, client_id)?;
        Ok(s.run()?)
    }

    pub fn subscribe(&mut self, client_id: &str, filter: &str, qos: u8) -> Result<()> {
        let s = &mut self.s.sub_set;
        s.bind_text(1, client_id)?;
        s.bind_text(2, filter)?;
        s.bind_i64(3, i64::from(qos.min(1)))?;
        Ok(s.run()?)
    }

    pub fn unsubscribe(&mut self, client_id: &str, filter: &str) -> Result<()> {
        let s = &mut self.s.sub_del;
        s.bind_text(1, client_id)?;
        s.bind_text(2, filter)?;
        Ok(s.run()?)
    }

    pub fn queue_push(
        &mut self,
        client_id: &str,
        topic: &str,
        payload: &[u8],
        qos: u8,
    ) -> Result<()> {
        let s = &mut self.s.queue_push;
        s.bind_text(1, client_id)?;
        s.bind_text(2, topic)?;
        s.bind_blob(3, payload)?;
        s.bind_i64(4, i64::from(qos.min(1)))?;
        Ok(s.run()?)
    }

    pub fn queue_clear(&mut self, client_id: &str) -> Result<()> {
        let s = &mut self.s.queue_clear;
        s.bind_text(1, client_id)?;
        Ok(s.run()?)
    }

    /// Every persistent session with its subscriptions and queue.
    pub fn sessions(&mut self) -> Result<Vec<SessionRecord>> {
        let mut out: Vec<SessionRecord> = Vec::new();
        {
            let s = &mut self.s.session_all;
            let r = (|| {
                while s.step()? == Step::Row {
                    out.push(SessionRecord {
                        client_id: s.text(0).into(),
                        ..SessionRecord::default()
                    });
                }
                Ok::<(), Error>(())
            })();
            s.reset();
            r?;
        }
        // Both lists are ordered by client id, like `out`.
        let find = |out: &mut Vec<SessionRecord>, id: &str| {
            out.binary_search_by(|r| r.client_id.as_str().cmp(id)).ok()
        };
        {
            let s = &mut self.s.sub_all;
            let r = (|| {
                while s.step()? == Step::Row {
                    if let Some(i) = find(&mut out, s.text(0))
                        && let Some(rec) = out.get_mut(i)
                    {
                        rec.subscriptions.push((s.text(1).into(), qos_of(s.i64(2))));
                    }
                }
                Ok::<(), Error>(())
            })();
            s.reset();
            r?;
        }
        {
            let s = &mut self.s.queue_all;
            let r = (|| {
                while s.step()? == Step::Row {
                    if let Some(i) = find(&mut out, s.text(0))
                        && let Some(rec) = out.get_mut(i)
                    {
                        rec.queued.push(Queued {
                            topic: s.text(1).into(),
                            payload: s.blob(2).into(),
                            qos: qos_of(s.i64(3)),
                        });
                    }
                }
                Ok::<(), Error>(())
            })();
            s.reset();
            r?;
        }
        Ok(out)
    }

    // ---- self-tests (boot benchmark, crash consistency) -------------------

    /// Inserts self-test row `seq` with a payload derived from it.
    pub fn selftest_insert(&mut self, seq: i64, len: usize) -> Result<()> {
        let data = selftest_payload(seq, len);
        let s = &mut self.s.selftest_ins;
        s.bind_i64(1, seq)?;
        s.bind_blob(2, &data)?;
        s.bind_i64(3, i64::from(crc32c(&data)))?;
        Ok(s.run()?)
    }

    /// Checks every self-test row: sequence numbers must be exactly 1..=n
    /// and each payload must match its CRC and its sequence number.
    /// Returns `n`, or a description of the first inconsistency.
    pub fn selftest_verify(&mut self) -> Result<core::result::Result<i64, String>> {
        let s = &mut self.s.selftest_all;
        let mut expect = 1i64;
        let mut bad = None;
        let r = (|| {
            while s.step()? == Step::Row {
                let (seq, data, crc) = (s.i64(0), s.blob(1), s.i64(2));
                if seq != expect {
                    bad = Some(format!("gap: expected seq {expect}, found {seq}"));
                    break;
                }
                if i64::from(crc32c(data)) != crc
                    || data != selftest_payload(seq, data.len()).as_slice()
                {
                    bad = Some(format!("row {seq}: payload does not match"));
                    break;
                }
                expect += 1;
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(match bad {
            Some(b) => Err(b),
            None => Ok(expect - 1),
        })
    }

    pub fn selftest_clear(&mut self) -> Result<()> {
        Ok(self.s.selftest_clear.run()?)
    }

    pub fn db(&self) -> &Db {
        &self.db
    }
}

fn selftest_payload(seq: i64, len: usize) -> Vec<u8> {
    let mut x = (seq as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
