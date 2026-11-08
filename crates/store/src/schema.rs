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
    // 2 (H1): the control channel's last accepted sequence number (anti-
    // replay, updated in the same transaction as each effect) and the
    // device allowlist.
    "
    CREATE TABLE control_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        seq INTEGER NOT NULL CHECK (seq >= 0)
    ) STRICT;
    INSERT INTO control_state (id, seq) VALUES (1, 0);

    CREATE TABLE allowlist (
        id TEXT PRIMARY KEY,
        added_at INTEGER NOT NULL,
        seq INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    ",
    // 3 (ADR-271): QoS 2. Retained messages, subscriptions and queued
    // messages may be QoS 2 (a CHECK cannot be altered in SQLite: the three
    // tables are rebuilt with every row, in the migration's transaction); a
    // queued message records the packet id it was in flight with (0: not
    // sent yet); `qos2_ids` holds the packet ids of unfinished QoS 2 flows:
    // received from the client and awaiting its PUBREL (`released` 0), or
    // released to it and awaiting its PUBCOMP (`released` 1).
    "
    CREATE TABLE retained_v3 (
        topic TEXT PRIMARY KEY,
        payload BLOB NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1, 2))
    ) STRICT, WITHOUT ROWID;
    INSERT INTO retained_v3 (topic, payload, qos) SELECT topic, payload, qos FROM retained;
    DROP TABLE retained;
    ALTER TABLE retained_v3 RENAME TO retained;

    CREATE TABLE subscriptions_v3 (
        client_id TEXT NOT NULL REFERENCES sessions (client_id) ON DELETE CASCADE,
        filter TEXT NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1, 2)),
        PRIMARY KEY (client_id, filter)
    ) STRICT, WITHOUT ROWID;
    INSERT INTO subscriptions_v3 (client_id, filter, qos)
        SELECT client_id, filter, qos FROM subscriptions;
    DROP TABLE subscriptions;
    ALTER TABLE subscriptions_v3 RENAME TO subscriptions;

    CREATE TABLE queued_v3 (
        seq INTEGER PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES sessions (client_id) ON DELETE CASCADE,
        topic TEXT NOT NULL,
        payload BLOB NOT NULL,
        qos INTEGER NOT NULL CHECK (qos IN (0, 1, 2)),
        pid INTEGER NOT NULL DEFAULT 0 CHECK (pid BETWEEN 0 AND 65535)
    ) STRICT;
    INSERT INTO queued_v3 (seq, client_id, topic, payload, qos)
        SELECT seq, client_id, topic, payload, qos FROM queued;
    DROP TABLE queued;
    ALTER TABLE queued_v3 RENAME TO queued;
    CREATE INDEX queued_by_client ON queued (client_id, seq);

    CREATE TABLE qos2_ids (
        client_id TEXT NOT NULL REFERENCES sessions (client_id) ON DELETE CASCADE,
        released INTEGER NOT NULL CHECK (released IN (0, 1)),
        pid INTEGER NOT NULL CHECK (pid BETWEEN 1 AND 65535),
        PRIMARY KEY (client_id, released, pid)
    ) STRICT, WITHOUT ROWID;
    ",
];

pub const VERSION: i64 = MIGRATIONS.len() as i64;
