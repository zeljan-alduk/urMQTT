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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Retained {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    /// Its MQTT 5.0 properties (schema 4, ADR-274); `None`: none.
    pub props: Option<Vec<u8>>,
    /// When its Message Expiry Interval ends, wall-clock seconds; `None`:
    /// never.
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Queued {
    pub topic: String,
    pub payload: Vec<u8>,
    /// 1 or 2 (0 and anything else are read as 1 by the broker).
    pub qos: u8,
    /// The packet id it was in flight with when the session went offline;
    /// 0: not sent yet (schema 3, ADR-271; every row of schema 2 is 0).
    pub pid: u16,
    /// Its MQTT 5.0 properties (schema 4, ADR-274); `None`: none.
    pub props: Option<Vec<u8>>,
    /// When its Message Expiry Interval ends, wall-clock seconds; `None`:
    /// never.
    pub expires_at: Option<i64>,
}

/// A message to queue, borrowed ([`Store::queue_push_v5`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedRef<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub qos: u8,
    pub pid: u16,
    pub props: Option<&'a [u8]>,
    pub expires_at: Option<i64>,
}

impl Queued {
    pub fn as_ref(&self) -> QueuedRef<'_> {
        QueuedRef {
            topic: &self.topic,
            payload: &self.payload,
            qos: self.qos,
            pid: self.pid,
            props: self.props.as_deref(),
            expires_at: self.expires_at,
        }
    }
}

/// A packet id of an unfinished QoS 2 flow (schema 3, ADR-271).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Qos2Id {
    /// false: received from the client, awaiting its PUBREL; true: released
    /// to the client, awaiting its PUBCOMP.
    pub released: bool,
    pub pid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRecord {
    pub client_id: String,
    /// (filter, Subscription Options byte): its QoS in bits 0-1; a row of
    /// schema 3 or older holds its QoS alone (schema 4, ADR-274).
    pub subscriptions: Vec<(String, u8)>,
    /// (filter, Subscription Identifier) of the subscriptions that have one
    /// (schema 5, ADR-275), in the order of `subscriptions`.
    pub sub_ids: Vec<(String, u32)>,
    pub queued: Vec<Queued>,
    pub qos2_ids: Vec<Qos2Id>,
    /// Its Session Expiry Interval; `None`: stored before schema 4 (the
    /// configured 3.1.1 default applies).
    pub expiry_s: Option<u32>,
    /// When it went offline, wall-clock seconds; `None`: it was online (the
    /// broker stopped with it connected) or the time is not known.
    pub offline_since: Option<i64>,
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
    account_set: Stmt,
    account_del: Stmt,
    account_all: Stmt,
    account_count: Stmt,
    retained_set: Stmt,
    retained_del: Stmt,
    retained_all: Stmt,
    session_upsert: Stmt,
    session_offline: Stmt,
    session_del: Stmt,
    session_all: Stmt,
    sub_set: Stmt,
    sub_del: Stmt,
    sub_all: Stmt,
    queue_push: Stmt,
    queue_clear: Stmt,
    queue_all: Stmt,
    qos2_add: Stmt,
    qos2_clear: Stmt,
    qos2_all: Stmt,
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
    open_inner().map_err(|e| match e {
        // A database file that is not a database, or fails SQLite's own
        // structural checks, is corruption: the case a backup can mend (S5).
        StoreError::Sql(ref s) if is_corruption(s.code) => StoreError::Corrupt(format!("{s}")),
        e => e,
    })
}

/// SQLite's "the file is damaged" result codes (SQLITE_CORRUPT and
/// SQLITE_NOTADB, with their extended forms).
fn is_corruption(code: i32) -> bool {
    matches!(code & 0xff, 11 | 26)
}

fn open_inner() -> Result<(Store, OpenInfo)> {
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
        account_set: db.prepare(
            "INSERT INTO accounts (id, hash, class, added_at, seq) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET hash = excluded.hash, class = excluded.class,
                 seq = excluded.seq",
        )?,
        account_del: db.prepare("DELETE FROM accounts WHERE id = ?1")?,
        account_all: db.prepare("SELECT id, hash, class FROM accounts ORDER BY id")?,
        account_count: db.prepare("SELECT count(*) FROM accounts")?,
        retained_set: db.prepare(
            "INSERT INTO retained (topic, payload, qos, props, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (topic) DO UPDATE SET payload = excluded.payload, qos = excluded.qos,
                 props = excluded.props, expires_at = excluded.expires_at",
        )?,
        retained_del: db.prepare("DELETE FROM retained WHERE topic = ?1")?,
        retained_all: db.prepare(
            "SELECT topic, payload, qos, props, expires_at FROM retained ORDER BY topic",
        )?,
        // Online again (or new): no offline time.
        session_upsert: db.prepare(
            "INSERT INTO sessions (client_id, updated, expiry_s, offline_since) VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT (client_id) DO UPDATE SET updated = excluded.updated,
                 expiry_s = excluded.expiry_s, offline_since = NULL",
        )?,
        session_offline: db.prepare(
            "UPDATE sessions SET offline_since = ?2, updated = ?2 WHERE client_id = ?1",
        )?,
        session_del: db.prepare("DELETE FROM sessions WHERE client_id = ?1")?,
        session_all: db.prepare(
            "SELECT client_id, expiry_s, offline_since FROM sessions ORDER BY client_id",
        )?,
        sub_set: db.prepare(
            "INSERT INTO subscriptions (client_id, filter, qos, options, sub_id) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (client_id, filter) DO UPDATE SET qos = excluded.qos, options = excluded.options,
                 sub_id = excluded.sub_id",
        )?,
        sub_del: db.prepare("DELETE FROM subscriptions WHERE client_id = ?1 AND filter = ?2")?,
        sub_all: db.prepare("SELECT client_id, filter, options, sub_id FROM subscriptions ORDER BY client_id, filter")?,
        queue_push: db.prepare(
            "INSERT INTO queued (client_id, topic, payload, qos, pid, props, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?,
        queue_clear: db.prepare("DELETE FROM queued WHERE client_id = ?1")?,
        queue_all: db.prepare(
            "SELECT client_id, topic, payload, qos, pid, props, expires_at FROM queued ORDER BY client_id, seq",
        )?,
        qos2_add: db.prepare(
            "INSERT INTO qos2_ids (client_id, released, pid) VALUES (?1, ?2, ?3)
             ON CONFLICT (client_id, released, pid) DO NOTHING",
        )?,
        qos2_clear: db.prepare("DELETE FROM qos2_ids WHERE client_id = ?1")?,
        qos2_all: db.prepare("SELECT client_id, released, pid FROM qos2_ids ORDER BY client_id, released, pid")?,
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

/// A stored QoS; anything outside 0..=2 (the CHECK forbids it) reads as 0.
fn qos_of(v: i64) -> u8 {
    u8::try_from(v).ok().filter(|q| *q <= 2).unwrap_or(0)
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

    /// Adds a password account or replaces its hash and class (NOW-15,
    /// ADR-285). `hash` is the stored PBKDF2 text, never a password. Call
    /// inside the transaction that applies the control message.
    pub fn account_set(
        &mut self,
        id: &str,
        hash: &str,
        class: u8,
        seq: u64,
        now_unix: i64,
    ) -> Result<()> {
        let s = &mut self.s.account_set;
        s.bind_text(1, id)?;
        s.bind_text(2, hash)?;
        s.bind_i64(3, i64::from(class))?;
        s.bind_i64(4, now_unix)?;
        s.bind_i64(5, i64::try_from(seq).unwrap_or(i64::MAX))?;
        Ok(s.run()?)
    }

    /// Removes a run-time account (no error if there is none).
    pub fn account_del(&mut self, id: &str) -> Result<()> {
        let s = &mut self.s.account_del;
        s.bind_text(1, id)?;
        Ok(s.run()?)
    }

    /// Every run-time account as `(id, hash, class)`, ordered by id.
    pub fn accounts(&mut self) -> Result<Vec<(String, String, u8)>> {
        let s = &mut self.s.account_all;
        let mut out = Vec::new();
        let r = (|| {
            while s.step()? == Step::Row {
                let class = u8::try_from(s.i64(2)).unwrap_or(u8::MAX);
                out.push((String::from(s.text(0)), String::from(s.text(1)), class));
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(out)
    }

    /// How many run-time accounts there are.
    pub fn account_count(&mut self) -> Result<i64> {
        let s = &mut self.s.account_count;
        let n = match s.step()? {
            Step::Row => s.i64(0),
            Step::Done => 0,
        };
        s.reset();
        Ok(n)
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
        self.retain_v5(topic, payload, qos, None, None)
    }

    /// Stores a retained message with its MQTT 5.0 properties and expiry
    /// (wall-clock seconds); an empty payload deletes it.
    pub fn retain_v5(
        &mut self,
        topic: &str,
        payload: &[u8],
        qos: u8,
        props: Option<&[u8]>,
        expires_at: Option<i64>,
    ) -> Result<()> {
        if payload.is_empty() {
            let s = &mut self.s.retained_del;
            s.bind_text(1, topic)?;
            return Ok(s.run()?);
        }
        let s = &mut self.s.retained_set;
        s.bind_text(1, topic)?;
        s.bind_blob(2, payload)?;
        s.bind_i64(3, i64::from(qos.min(2)))?;
        // Unbound parameters are NULL (`reset` clears the bindings).
        if let Some(p) = props {
            s.bind_blob(4, p)?;
        }
        if let Some(t) = expires_at {
            s.bind_i64(5, t)?;
        }
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
                    props: (!s.is_null(3)).then(|| s.blob(3).into()),
                    expires_at: (!s.is_null(4)).then(|| s.i64(4)),
                });
            }
            Ok::<(), Error>(())
        })();
        s.reset();
        r?;
        Ok(out)
    }

    /// Creates or updates a session without a Session Expiry Interval (as
    /// before schema 4: the 3.1.1 default applies), online.
    pub fn session_upsert(&mut self, client_id: &str, now_unix: i64) -> Result<()> {
        self.session_upsert_expiry(client_id, now_unix, None)
    }

    /// Creates or updates a session with its Session Expiry Interval and
    /// marks it online (no offline time).
    pub fn session_upsert_expiry(
        &mut self,
        client_id: &str,
        now_unix: i64,
        expiry_s: Option<u32>,
    ) -> Result<()> {
        let s = &mut self.s.session_upsert;
        s.bind_text(1, client_id)?;
        s.bind_i64(2, now_unix)?;
        if let Some(e) = expiry_s {
            s.bind_i64(3, i64::from(e))?;
        }
        Ok(s.run()?)
    }

    /// The session went offline at `now_unix`: its expiry runs from there.
    pub fn session_offline(&mut self, client_id: &str, now_unix: i64) -> Result<()> {
        let s = &mut self.s.session_offline;
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

    /// A subscription with its QoS alone (a 3.1.1 one).
    pub fn subscribe(&mut self, client_id: &str, filter: &str, qos: u8) -> Result<()> {
        self.subscribe_options(client_id, filter, qos.min(2))
    }

    /// A subscription with its Subscription Options byte (QoS in bits 0-1).
    pub fn subscribe_options(&mut self, client_id: &str, filter: &str, options: u8) -> Result<()> {
        self.subscribe_v5(client_id, filter, options, 0)
    }

    /// A subscription with its Subscription Options byte and Subscription
    /// Identifier (0: none; schema 5, ADR-275). Re-subscribing replaces
    /// both.
    pub fn subscribe_v5(
        &mut self,
        client_id: &str,
        filter: &str,
        options: u8,
        sub_id: u32,
    ) -> Result<()> {
        let s = &mut self.s.sub_set;
        s.bind_text(1, client_id)?;
        s.bind_text(2, filter)?;
        s.bind_i64(3, i64::from((options & 3).min(2)))?;
        s.bind_i64(4, i64::from(options))?;
        s.bind_i64(5, i64::from(sub_id))?;
        Ok(s.run()?)
    }

    pub fn unsubscribe(&mut self, client_id: &str, filter: &str) -> Result<()> {
        let s = &mut self.s.sub_del;
        s.bind_text(1, client_id)?;
        s.bind_text(2, filter)?;
        Ok(s.run()?)
    }

    /// Queues a message that was not sent yet.
    pub fn queue_push(
        &mut self,
        client_id: &str,
        topic: &str,
        payload: &[u8],
        qos: u8,
    ) -> Result<()> {
        self.queue_push_sent(client_id, topic, payload, qos, 0)
    }

    /// Queues a message that was in flight with packet id `pid` (0: not
    /// sent), at `qos` 1 or 2.
    pub fn queue_push_sent(
        &mut self,
        client_id: &str,
        topic: &str,
        payload: &[u8],
        qos: u8,
        pid: u16,
    ) -> Result<()> {
        self.queue_push_v5(
            client_id,
            QueuedRef {
                topic,
                payload,
                qos,
                pid,
                props: None,
                expires_at: None,
            },
        )
    }

    /// Queues a message with everything it carries (schema 4).
    pub fn queue_push_v5(&mut self, client_id: &str, m: QueuedRef<'_>) -> Result<()> {
        let s = &mut self.s.queue_push;
        s.bind_text(1, client_id)?;
        s.bind_text(2, m.topic)?;
        s.bind_blob(3, m.payload)?;
        s.bind_i64(4, i64::from(m.qos.min(2)))?;
        s.bind_i64(5, i64::from(m.pid))?;
        if let Some(p) = m.props {
            s.bind_blob(6, p)?;
        }
        if let Some(t) = m.expires_at {
            s.bind_i64(7, t)?;
        }
        Ok(s.run()?)
    }

    /// Records a packet id of an unfinished QoS 2 flow (ADR-271). Id 0 is
    /// not one, and is not stored.
    pub fn qos2_id(&mut self, client_id: &str, id: Qos2Id) -> Result<()> {
        if id.pid == 0 {
            return Ok(());
        }
        let s = &mut self.s.qos2_add;
        s.bind_text(1, client_id)?;
        s.bind_i64(2, i64::from(id.released))?;
        s.bind_i64(3, i64::from(id.pid))?;
        Ok(s.run()?)
    }

    /// Clears the queue and the QoS 2 packet ids of a session.
    pub fn queue_clear(&mut self, client_id: &str) -> Result<()> {
        let s = &mut self.s.queue_clear;
        s.bind_text(1, client_id)?;
        s.run()?;
        let s = &mut self.s.qos2_clear;
        s.bind_text(1, client_id)?;
        Ok(s.run()?)
    }

    /// Every persistent session with its subscriptions, queue and QoS 2
    /// packet ids.
    pub fn sessions(&mut self) -> Result<Vec<SessionRecord>> {
        let mut out: Vec<SessionRecord> = Vec::new();
        {
            let s = &mut self.s.session_all;
            let r = (|| {
                while s.step()? == Step::Row {
                    out.push(SessionRecord {
                        client_id: s.text(0).into(),
                        expiry_s: (!s.is_null(1))
                            .then(|| u32::try_from(s.i64(1)).ok())
                            .flatten(),
                        offline_since: (!s.is_null(2)).then(|| s.i64(2)),
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
                        // The options byte (the CHECK keeps it in 0..=255).
                        let options = u8::try_from(s.i64(2)).unwrap_or(0);
                        rec.subscriptions.push((s.text(1).into(), options));
                        // The CHECK keeps it in 0..=268 435 455.
                        let id = u32::try_from(s.i64(3)).unwrap_or(0);
                        if id != 0 {
                            rec.sub_ids.push((s.text(1).into(), id));
                        }
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
                            pid: u16::try_from(s.i64(4)).unwrap_or(0),
                            props: (!s.is_null(5)).then(|| s.blob(5).into()),
                            expires_at: (!s.is_null(6)).then(|| s.i64(6)),
                        });
                    }
                }
                Ok::<(), Error>(())
            })();
            s.reset();
            r?;
        }
        {
            let s = &mut self.s.qos2_all;
            let r = (|| {
                while s.step()? == Step::Row {
                    if let Some(i) = find(&mut out, s.text(0))
                        && let Some(rec) = out.get_mut(i)
                        && let Ok(pid) = u16::try_from(s.i64(2))
                    {
                        rec.qos2_ids.push(Qos2Id {
                            released: s.i64(1) != 0,
                            pid,
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
