//! Golden database schema 6 (run-time password accounts, ADR-285), the bytes:
//! a fresh disk with the QoS 2 state of schema 3, the MQTT 5.0 state of
//! schema 4, the shared subscription and Subscription Identifiers of schema 5
//! and the accounts of schema 6 must come out as
//! `tests/golden/schema6-accounts.txt`. The only test of its process:
//! SQLite's random state (the WAL salts) is per process, so another store
//! opened first would change the bytes.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_schema6_bytes`
//! rewrites the file. Only do that together with a schema bump.
//! (`schema5-shared.txt`, which this test wrote before schema 6, is frozen:
//! the input of the 5 to 6 migration tests; `schema4-mqtt5.txt` likewise for
//! 4 to 5 and `schema3-qos2.txt` for 3 to 4.)

mod schema3_fixture;

use schema3_fixture::{
    DISK_BYTES, lock, mount, path, sparse_titled, write_accounts_state, write_mqtt5_state,
    write_qos2_state, write_shared_state,
};
use urmqtt_store::{MemDisk, open};

#[test]
fn schema6_with_qos2_mqtt5_shared_and_account_state() {
    let _g = lock();
    let m = MemDisk::new(DISK_BYTES);
    mount(&m);
    let (mut s, info) = open().unwrap();
    assert_eq!((info.schema_from, info.schema_to), (0, 6));
    write_qos2_state(&mut s);
    write_mqtt5_state(&mut s);
    write_shared_state(&mut s);
    write_accounts_state(&mut s);
    drop(s);
    let got = sparse_titled(&m, "database schema 6 (run-time accounts)");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path("schema6-accounts"), &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path("schema6-accounts"))
        .unwrap_or_else(|e| panic!("schema6-accounts: {e} (UPDATE_GOLDEN=1 creates it)"));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!("schema6-accounts: the bytes differ from schema 6 ({first})");
    }
}
