//! Golden database schema 4 (MQTT 5.0, ADR-274).
//!
//! Schema 4 adds columns: the session's Session Expiry Interval and the
//! wall-clock time it went offline, the subscription's options byte, the
//! retained and queued messages' properties and expiry. Three checks:
//!
//! 1. The frozen schema 3 database `schema3-qos2` (written by the code before
//!    schema 4) opens, is migrated in one transaction, and keeps every row:
//!    the session's expiry is unknown (`None`: the configured 3.1.1 default
//!    applies), its subscription's options are its QoS, its messages have no
//!    properties and no expiry. MQTT 5.0 state can be written to it
//!    afterwards, and it opens again as schema 4 without migrating twice.
//! 2. The code still writes the same bytes for a schema 4 database holding
//!    QoS 2 and MQTT 5.0 state (`schema4-mqtt5`): `golden_schema4_bytes.rs`.
//! 3. That frozen file opens and hands back exactly that state.
//!
//! And a power cut at any write of the 3 to 4 migration leaves schema 3 or
//! 4 with every row.

mod schema3_fixture;

use schema3_fixture::{
    NOW, PROPS, load, lock, mount, want_mqtt5_session, want_qos2_session, write_mqtt5_state,
};
use urmqtt_store::open;

#[test]
fn a_schema_3_database_migrates_and_keeps_every_row() {
    let _g = lock();
    let m = load("schema3-qos2");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (3, 4));
    let sessions = s.sessions().unwrap();
    let want = want_qos2_session();
    assert_eq!(sessions, vec![want.clone()]);
    assert_eq!(sessions[0].expiry_s, None, "stored before schema 4");
    assert_eq!(sessions[0].offline_since, None);
    // Options = QoS for every older subscription.
    assert_eq!(sessions[0].subscriptions, want.subscriptions);
    assert!(
        sessions[0]
            .queued
            .iter()
            .all(|q| q.props.is_none() && q.expires_at.is_none())
    );
    let r = s.retained().unwrap();
    assert_eq!(
        (r[0].topic.as_str(), r[0].qos, &r[0].props),
        ("fleet/fw", 2, &None)
    );
    let cols = s
        .db()
        .query_text(
            "SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_table_info('sessions') \
             UNION ALL SELECT name FROM pragma_table_info('subscriptions') \
             UNION ALL SELECT name FROM pragma_table_info('queued') \
             UNION ALL SELECT name FROM pragma_table_info('retained'))",
        )
        .unwrap();
    for c in [
        "expiry_s",
        "offline_since",
        "options",
        "props",
        "expires_at",
    ] {
        assert!(cols.contains(c), "{c} in {cols}");
    }
    // MQTT 5.0 state goes in; the CHECK constraints hold.
    write_mqtt5_state(&mut s);
    let sessions = s.sessions().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[1], want_mqtt5_session());
    s.begin().unwrap();
    assert!(
        s.subscribe_options("device-005", "x", 0).is_ok()
            && s.session_upsert_expiry("device-005", NOW as i64, Some(u32::MAX))
                .is_ok(),
        "the full ranges are accepted"
    );
    s.commit().unwrap();
    assert!(
        s.db()
            .exec("UPDATE sessions SET expiry_s = -1 WHERE client_id = 'device-005'")
            .is_err(),
        "CHECK on expiry_s"
    );
    assert!(
        s.db()
            .exec("UPDATE subscriptions SET options = 256")
            .is_err(),
        "CHECK on options"
    );
    // Back online: no offline time.
    s.begin().unwrap();
    s.session_upsert_expiry("device-005", NOW as i64, Some(10))
        .unwrap();
    s.commit().unwrap();
    let back = &s.sessions().unwrap()[1];
    assert_eq!((back.expiry_s, back.offline_since), (Some(10), None));
    drop(s);
    mount(&m);
    let (s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (4, 4));
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
    assert_eq!(
        s.db()
            .query_text("PRAGMA foreign_key_check")
            .unwrap_or_default(),
        ""
    );
}

#[test]
fn the_frozen_schema4_image_holds_its_mqtt5_state() {
    let _g = lock();
    let m = load("schema4-mqtt5");
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (4, 4));
    assert_eq!(
        s.sessions().unwrap(),
        vec![want_qos2_session(), want_mqtt5_session()]
    );
    let r = s.retained().unwrap();
    let notice = r.iter().find(|r| r.topic == "fleet/notice").unwrap();
    assert_eq!(notice.props.as_deref(), Some(&PROPS[..]));
    assert_eq!(notice.expires_at, Some(NOW as i64 + 3600));
}

/// A power cut at every write of the 3 to 4 migration (cut or torn, the
/// device's cache dropped or kept): the next open finds schema 3 or 4, never
/// anything in between, migrates if needed, and every row is there.
#[test]
fn a_power_cut_during_the_migration_leaves_schema_3_or_4() {
    use urmqtt_store::Disk;
    use urmqtt_store::fault::{FaultDevice, FaultSpec};
    let _g = lock();
    let base = load("schema3-qos2");
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
                    3 => old += 1,
                    4 => new += 1,
                    v => panic!("write {n}: schema {v}"),
                }
                assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
                assert_eq!(
                    s.sessions().unwrap(),
                    vec![want_qos2_session()],
                    "write {n}"
                );
                assert_eq!(s.retained().unwrap().len(), 1, "write {n}");
            }
        }
    }
    assert!(
        old > 0 && new > 0,
        "both outcomes seen: {old} old, {new} new"
    );
}
