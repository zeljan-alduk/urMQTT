//! Golden database schema 3 (QoS 2, ADR-271), the bytes: a fresh disk with
//! the QoS 2 state of `golden_schema3.rs` must come out as
//! `tests/golden/schema3-qos2.txt`. The only test of its process: SQLite's
//! random state (the WAL salts) is per process, so another store opened
//! first would change the bytes.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_schema3_bytes`
//! rewrites the file. Only do that together with a schema bump.

mod schema3_fixture;

use schema3_fixture::{DISK_BYTES, lock, mount, path, sparse, write_qos2_state};
use urmqtt_store::{MemDisk, open};

#[test]
fn schema3_with_qos2_state() {
    let _g = lock();
    let m = MemDisk::new(DISK_BYTES);
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (0, 3));
    write_qos2_state(&mut s);
    drop(s);
    let got = sparse(&m);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path("schema3-qos2"), &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path("schema3-qos2"))
        .unwrap_or_else(|e| panic!("schema3-qos2: {e} (UPDATE_GOLDEN=1 creates it)"));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!("schema3-qos2: the bytes differ from schema 3 ({first})");
    }
}
