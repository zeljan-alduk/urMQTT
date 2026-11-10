//! Golden database schema 6 (run-time password accounts, NOW-15, ADR-285).
//!
//! Schema 6 adds one table, `accounts`: the PBKDF2 hash (the stored text,
//! never a password), the ACL class (0 full, 1 read-only, 2 write-only), the
//! time and the control message that wrote it. Four checks:
//!
//! 1. The frozen schema 5 database `schema5-shared` (written by the code
//!    before schema 6) opens, is migrated in one transaction, keeps every
//!    row, and has an empty `accounts` table. Accounts can be written,
//!    replaced and removed, the constraints hold, and the database opens
//!    again as schema 6 without migrating twice.
//! 2. The code still writes the same bytes for a schema 6 database holding
//!    that state (`schema6-accounts`): `golden_schema6_bytes.rs`.
//! 3. That frozen file opens and hands back exactly that state, which also
//!    survives a reopen.
//! 4. A power cut at any write of the 5 to 6 migration leaves schema 5 or 6
//!    with every row.

mod schema3_fixture;

use schema3_fixture::{
    HASH_A, load, lock, mount, want_accounts, want_mqtt5_session, want_qos2_session,
    want_shared_session, write_accounts_state,
};
use urmqtt_store::open;

fn want_sessions() -> Vec<urmqtt_store::SessionRecord> {
    vec![
        want_shared_session(),
        want_qos2_session(),
        want_mqtt5_session(),
    ]
}

#[test]
fn a_schema_5_database_migrates_and_keeps_every_row() {
    let _g = lock();
    let m = load("schema5-shared");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (5, 6));
    assert_eq!(s.sessions().unwrap(), want_sessions());
    assert_eq!(s.retained().unwrap().len(), 2);
    assert_eq!(s.accounts().unwrap(), vec![], "no account before schema 6");
    assert_eq!(s.account_count().unwrap(), 0);
    write_accounts_state(&mut s);
    assert_eq!(s.accounts().unwrap(), want_accounts());
    assert_eq!(s.account_count().unwrap(), 2);
    assert_eq!(s.control_seq().unwrap(), 12);
    // The constraints: class 0..=2, a hash is there and at most 150 bytes,
    // an id is unique.
    s.begin().unwrap();
    assert!(s.account_set("x", HASH_A, 3, 13, 0).is_err(), "class 3");
    s.rollback();
    s.begin().unwrap();
    assert!(s.account_set("x", "", 0, 13, 0).is_err(), "empty hash");
    s.rollback();
    s.begin().unwrap();
    assert!(
        s.account_set("x", &"h".repeat(151), 0, 13, 0).is_err(),
        "hash too long"
    );
    s.rollback();
    // Removing what is not there is not an error.
    s.begin().unwrap();
    s.account_del("nobody").unwrap();
    s.commit().unwrap();
    assert_eq!(s.accounts().unwrap(), want_accounts());
    // A rolled-back transaction leaves nothing.
    s.begin().unwrap();
    s.account_set("temp", HASH_A, 0, 13, 0).unwrap();
    s.rollback();
    assert_eq!(s.account_count().unwrap(), 2);
    drop(s);
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (6, 6));
    assert_eq!(s.accounts().unwrap(), want_accounts());
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
    assert_eq!(
        s.db()
            .query_text("PRAGMA foreign_key_check")
            .unwrap_or_default(),
        ""
    );
}

#[test]
fn the_frozen_schema6_image_holds_its_accounts() {
    let _g = lock();
    let m = load("schema6-accounts");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (6, 6));
    assert_eq!(s.accounts().unwrap(), want_accounts());
    assert_eq!(s.sessions().unwrap(), want_sessions());
    assert_eq!(s.control_seq().unwrap(), 12);
    // Only hashes are in the file: the text of a stored account has the
    // shape of a PBKDF2 hash, and nothing in the table looks like a password.
    for (_, hash, _) in s.accounts().unwrap() {
        assert!(hash.starts_with("pbkdf2-sha256$"));
    }
}

/// A power cut at every write of the 5 to 6 migration (cut or torn, the
/// device's cache dropped or kept): the next open finds schema 5 or 6, never
/// anything in between, migrates if needed, and every row is there.
#[test]
fn a_power_cut_during_the_migration_leaves_schema_5_or_6() {
    use urmqtt_store::Disk;
    use urmqtt_store::fault::{FaultDevice, FaultSpec};
    let _g = lock();
    let base = load("schema5-shared");
    let probe = base.fork();
    let before = probe.write_count();
    mount(&probe);
    drop(open().unwrap());
    let total = probe.write_count() - before;
    assert!(total > 0);
    let (mut old, mut new) = (0, 0);
    for n in 1..=total {
        for torn in [false, true] {
            for keep in [false, true] {
                let m = base.fork();
                let spec = if torn {
                    FaultSpec {
                        tear_write: Some((n, 1)),
                        ..FaultSpec::default()
                    }
                } else {
                    FaultSpec {
                        stop_after_writes: Some(n),
                        ..FaultSpec::default()
                    }
                };
                let (disk, _) =
                    Disk::open(Box::new(FaultDevice::new(m.device(), spec)), || [0; 16]).unwrap();
                urmqtt_store::init(schema3_fixture::heap(), disk, schema3_fixture::platform())
                    .unwrap();
                let _ = open();
                m.crash(|_| keep);
                mount(&m);
                let (mut s, info) =
                    open().unwrap_or_else(|e| panic!("write {n} torn={torn} keep={keep}: {e}"));
                match info.schema_from {
                    5 => old += 1,
                    6 => new += 1,
                    v => panic!("write {n}: schema {v}"),
                }
                assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
                assert_eq!(s.sessions().unwrap(), want_sessions(), "write {n}");
                assert_eq!(s.retained().unwrap().len(), 2, "write {n}");
                assert_eq!(s.accounts().unwrap(), vec![], "write {n}");
            }
        }
    }
    assert!(
        old > 0 && new > 0,
        "both outcomes seen: {old} at 5, {new} at 6"
    );
}
