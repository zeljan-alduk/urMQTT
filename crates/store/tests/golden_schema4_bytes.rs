//! Golden database schema 4 (MQTT 5.0, ADR-274), the bytes: a fresh disk
//! with the QoS 2 state of schema 3 and the MQTT 5.0 state of
//! `golden_schema4.rs` must come out as `tests/golden/schema4-mqtt5.txt`. The
//! only test of its process: SQLite's random state (the WAL salts) is per
//! process, so another store opened first would change the bytes.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_schema4_bytes`
//! rewrites the file. Only do that together with a schema bump.
//! (`schema3-qos2.txt`, which this test wrote before schema 4, is frozen: the
//! input of the 3 to 4 migration tests.)

mod schema3_fixture;

use schema3_fixture::{
    DISK_BYTES, lock, mount, path, sparse_titled, write_mqtt5_state, write_qos2_state,
};
use urmqtt_store::{MemDisk, open};

#[test]
fn schema4_with_qos2_and_mqtt5_state() {
    let _g = lock();
    let m = MemDisk::new(DISK_BYTES);
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (0, 4));
    write_qos2_state(&mut s);
    write_mqtt5_state(&mut s);
    drop(s);
    let got = sparse_titled(&m, "database schema 4 (MQTT 5.0)");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path("schema4-mqtt5"), &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path("schema4-mqtt5"))
        .unwrap_or_else(|e| panic!("schema4-mqtt5: {e} (UPDATE_GOLDEN=1 creates it)"));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!("schema4-mqtt5: the bytes differ from schema 4 ({first})");
    }
}
