//! Golden database schema 5 (MQTT 5.0 part 3, ADR-275), the bytes: a fresh
//! disk with the QoS 2 state of schema 3, the MQTT 5.0 state of schema 4 and
//! the shared subscription and Subscription Identifiers of schema 5 must come
//! out as `tests/golden/schema5-shared.txt`. The only test of its process:
//! SQLite's random state (the WAL salts) is per process, so another store
//! opened first would change the bytes.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_schema5_bytes`
//! rewrites the file. Only do that together with a schema bump.
//! (`schema4-mqtt5.txt`, which this test wrote before schema 5, is frozen:
//! the input of the 4 to 5 migration tests; `schema3-qos2.txt` likewise for
//! 3 to 4.)

mod schema3_fixture;

use schema3_fixture::{
    DISK_BYTES, lock, mount, path, sparse_titled, write_mqtt5_state, write_qos2_state,
    write_shared_state,
};
use urmqtt_store::{MemDisk, open};

#[test]
fn schema5_with_qos2_mqtt5_and_shared_state() {
    let _g = lock();
    let m = MemDisk::new(DISK_BYTES);
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (0, 5));
    write_qos2_state(&mut s);
    write_mqtt5_state(&mut s);
    write_shared_state(&mut s);
    drop(s);
    let got = sparse_titled(&m, "database schema 5 (MQTT 5.0 part 3)");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path("schema5-shared"), &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path("schema5-shared"))
        .unwrap_or_else(|e| panic!("schema5-shared: {e} (UPDATE_GOLDEN=1 creates it)"));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!("schema5-shared: the bytes differ from schema 5 ({first})");
    }
}
