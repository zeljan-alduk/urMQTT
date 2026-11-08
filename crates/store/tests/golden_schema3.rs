//! Golden database schema 3 (QoS 2, ADR-271), and the way on to schema 4
//! (MQTT 5.0, ADR-274: `golden_schema4.rs`) and 5 (ADR-275:
//! `golden_schema5.rs`).
//!
//! Schema 3 rebuilds the `retained`, `subscriptions` and `queued` tables
//! (their QoS CHECK allows 2; a queued row records the packet id it was in
//! flight with) and adds `qos2_ids`. Three checks:
//!
//! 1. The frozen schema 2 database (the one inside `v2-data`, written before
//!    schema 3 existed) opens, is migrated (one transaction per version, to
//!    the current one), and keeps every row: retained messages, the device,
//!    the session with its subscription and queued message (not in flight).
//!    QoS 2 state can be written to it afterwards, and it opens again
//!    without migrating twice.
//! 2. `schema3-qos2` is frozen since schema 4: the schema 3 database with
//!    QoS 2 state that the code wrote then, the input of the 3 to 4
//!    migration tests (`golden_schema4.rs`).
//! 3. That frozen file opens and hands back exactly that state.

mod schema3_fixture;

use schema3_fixture::{load, lock, mount, want_qos2_session, write_qos2_state};
use urmqtt_store::{Queued, SessionRecord, open};

#[test]
fn a_schema_2_database_migrates_and_keeps_every_row() {
    let _g = lock();
    let m = load("v2-data");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (2, 5));
    assert_eq!(urmqtt_store::schema::VERSION, 5);
    let r = s.retained().unwrap();
    assert_eq!(
        r.iter()
            .map(|r| (r.topic.as_str(), r.payload.as_slice(), r.qos))
            .collect::<Vec<_>>(),
        [
            ("fleet/config", &b"{\"rate\":5}"[..], 1),
            ("fleet/mode", &b"normal"[..], 0)
        ]
    );
    assert_eq!(s.device_count().unwrap(), 1);
    assert_eq!(
        s.sessions().unwrap(),
        vec![SessionRecord {
            client_id: "device-001".into(),
            subscriptions: vec![("fleet/#".into(), 1)],
            queued: vec![Queued {
                topic: "fleet/config".into(),
                payload: b"x".to_vec(),
                qos: 1,
                pid: 0,
                ..Queued::default()
            }],
            qos2_ids: vec![],
            ..SessionRecord::default()
        }]
    );
    // The rebuilt tables check for schema 3's QoS values.
    let sql = s
        .db()
        .query_text("SELECT group_concat(sql, ';') FROM sqlite_master WHERE name IN ('retained', 'subscriptions', 'queued')")
        .unwrap();
    assert_eq!(sql.matches("qos IN (0, 1, 2)").count(), 3, "{sql}");
    assert_eq!(
        s.db()
            .query_text("SELECT name FROM sqlite_master WHERE name = 'queued_by_client'")
            .unwrap(),
        "queued_by_client"
    );
    // QoS 2 state goes in, and the session's foreign keys still cascade.
    write_qos2_state(&mut s);
    let sessions = s.sessions().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[1], want_qos2_session());
    assert_eq!(
        s.db()
            .query_text("PRAGMA foreign_key_check")
            .unwrap_or_default(),
        ""
    );
    s.begin().unwrap();
    s.queue_clear("device-002").unwrap();
    s.commit().unwrap();
    let after = s.sessions().unwrap();
    assert!(after[1].queued.is_empty() && after[1].qos2_ids.is_empty());
    write_qos2_state(&mut s);
    s.begin().unwrap();
    s.session_delete("device-002").unwrap();
    s.commit().unwrap();
    assert_eq!(
        s.db().query_i64("SELECT count(*) FROM qos2_ids").unwrap(),
        0,
        "deleted with its session"
    );
    drop(s);
    // Reopened: current already, nothing to migrate.
    mount(&m);
    let (s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (5, 5));
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
}

#[test]
fn the_frozen_schema3_image_holds_its_qos2_state() {
    let _g = lock();
    let m = load("schema3-qos2");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (3, 5));
    assert_eq!(s.sessions().unwrap(), vec![want_qos2_session()]);
    let r = s.retained().unwrap();
    assert_eq!((r[0].topic.as_str(), r[0].qos), ("fleet/fw", 2));
}

/// A power cut at every write of the migrations (cut or torn, the device's
/// cache dropped or kept): the next open finds schema 2, 3, 4 or 5, never
/// anything in between, migrates if needed, and every row is there.
#[test]
fn a_power_cut_during_the_migration_leaves_schema_2_or_3() {
    use urmqtt_store::Disk;
    use urmqtt_store::fault::{FaultDevice, FaultSpec};
    let _g = lock();
    let base = load("v2-data");
    let probe = base.fork();
    let before = probe.write_count();
    mount(&probe);
    drop(open().unwrap());
    let total = probe.write_count() - before;
    assert!(total > 0);
    let (mut old, mut mid, mut mid4, mut new) = (0, 0, 0, 0);
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
                    2 => old += 1,
                    3 => mid += 1,
                    4 => mid4 += 1,
                    5 => new += 1,
                    v => panic!("write {n}: schema {v}"),
                }
                assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
                let sess = s.sessions().unwrap();
                assert_eq!(sess.len(), 1, "write {n}");
                assert_eq!(sess[0].queued.len(), 1, "write {n}");
                assert_eq!(sess[0].subscriptions.len(), 1, "write {n}");
                assert_eq!(s.retained().unwrap().len(), 2, "write {n}");
            }
        }
    }
    assert!(
        old > 0 && mid > 0 && mid4 > 0 && new > 0,
        "every outcome seen: {old} at 2, {mid} at 3, {mid4} at 4, {new} at 5"
    );
}
