//! Embedded schema migrations. `PRAGMA user_version` records how many have
//! been applied. Migrations are append-only: never edit a released one.

/// Migration `i` takes the schema from version `i` to `i + 1`.
pub const MIGRATIONS: &[&str] = &[
    // 1 (M11): device registry, revocations, retained messages, persistent
    // sessions with subscriptions and queued QoS 1 messages, and the table
    // used by the storage self-tests.
    "
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        connects INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE revoked (
        serial TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        revoked_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE retained (
        topic TEXT PRIMARY KEY,
        payload BLOB NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1))
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE sessions (
        client_id TEXT PRIMARY KEY,
        updated INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE subscriptions (
        client_id TEXT NOT NULL REFERENCES sessions (client_id) ON DELETE CASCADE,
        filter TEXT NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1)),
        PRIMARY KEY (client_id, filter)
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE queued (
        seq INTEGER PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES sessions (client_id) ON DELETE CASCADE,
        topic TEXT NOT NULL,
        payload BLOB NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1))
    ) STRICT;
    CREATE INDEX queued_by_client ON queued (client_id, seq);

    CREATE TABLE selftest (
        seq INTEGER PRIMARY KEY,
        data BLOB NOT NULL,
        crc INTEGER NOT NULL
    ) STRICT;
    ",
];

pub const VERSION: i64 = MIGRATIONS.len() as i64;
