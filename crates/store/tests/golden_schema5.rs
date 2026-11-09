//! Golden database schema 5 (MQTT 5.0 part 3, ADR-275).
//!
//! Schema 5 adds one column: a subscription's Subscription Identifier (0:
//! none). Shared subscriptions are rows like any other. Three checks:
//!
//! 1. The frozen schema 4 database `schema4-mqtt5` (written by the code
//!    before schema 5) opens, is migrated in one transaction, and keeps every
//!    row: no subscription has an identifier. Shared subscriptions with
//!    identifiers can be written to it afterwards, and it opens again as
//!    schema 5 without migrating twice.
//! 2. The code still writes the same bytes for a schema 5 database holding
//!    that state (`schema5-shared`): `golden_schema5_bytes.rs`.
//! 3. That frozen file opens and hands back exactly that state.
//!
//! And a power cut at any write of the 4 to 6 migration leaves schema 4, 5 or
//! 6 with every row.

mod schema3_fixture;

use schema3_fixture::{
    load, lock, mount, want_mqtt5_session, want_qos2_session, want_shared_session,
    write_shared_state,
};
use urmqtt_store::open;

#[test]
fn a_schema_4_database_migrates_and_keeps_every_row() {
    let _g = lock();
    let m = load("schema4-mqtt5");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (4, 6));
    let before = vec![want_qos2_session(), want_mqtt5_session()];
    assert_eq!(s.sessions().unwrap(), before);
    assert!(s.sessions().unwrap().iter().all(|r| r.sub_ids.is_empty()));
    assert_eq!(
        s.db()
            .query_text("SELECT group_concat(sub_id, ',') FROM subscriptions")
            .unwrap(),
        "0,0",
        "older rows have no identifier"
    );
    write_shared_state(&mut s);
    let mut want = before.clone();
    want.insert(0, want_shared_session());
    assert_eq!(s.sessions().unwrap(), want);
    // Re-subscribing replaces the identifier; 0 removes it.
    s.begin().unwrap();
    s.subscribe_v5("backend", "fleet/#", 2, 0).unwrap();
    s.commit().unwrap();
    assert_eq!(s.sessions().unwrap()[0].sub_ids.len(), 1);
    assert!(
        s.db()
            .exec("UPDATE subscriptions SET sub_id = 268435456")
            .is_err(),
        "CHECK on sub_id"
    );
    assert!(
        s.db().exec("UPDATE subscriptions SET sub_id = -1").is_err(),
        "CHECK on sub_id"
    );
    drop(s);
    mount(&m);
    let (s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (6, 6));
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
    assert_eq!(
        s.db()
            .query_text("PRAGMA foreign_key_check")
            .unwrap_or_default(),
        ""
    );
}

#[test]
fn the_frozen_schema5_image_holds_its_shared_state() {
    let _g = lock();
    let m = load("schema5-shared");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (5, 6));
    assert_eq!(
        s.sessions().unwrap(),
        vec![
            want_shared_session(),
            want_qos2_session(),
            want_mqtt5_session()
        ]
    );
}

/// A power cut at every write of the 4 to 6 migration (cut or torn, the
/// device's cache dropped or kept): the next open finds schema 4, 5 or 6, never
/// anything in between, migrates if needed, and every row is there.
#[test]
fn a_power_cut_during_the_migration_leaves_schema_4_or_5() {
    use urmqtt_store::Disk;
    use urmqtt_store::fault::{FaultDevice, FaultSpec};
    let _g = lock();
    let base = load("schema4-mqtt5");
    let probe = base.fork();
    let before = probe.write_count();
    mount(&probe);
    drop(open().unwrap());
    let total = probe.write_count() - before;
    assert!(total > 0);
    let (mut old, mut new, mut six) = (0, 0, 0);
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
                    4 => old += 1,
                    5 => new += 1,
                    6 => six += 1,
                    v => panic!("write {n}: schema {v}"),
                }
                assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
                assert_eq!(
                    s.sessions().unwrap(),
                    vec![want_qos2_session(), want_mqtt5_session()],
                    "write {n}"
                );
                assert_eq!(s.retained().unwrap().len(), 2, "write {n}");
            }
        }
    }
    assert!(
        old > 0 && new > 0 && six > 0,
        "every outcome seen: {old} at 4, {new} at 5, {six} at 6"
    );
}
