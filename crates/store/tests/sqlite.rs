//! SQLite end to end over the urmqtt VFS on an in-memory disk with a
//! volatile write cache: schema, the broker store, persistence across
//! reopen, and consistency after simulated power loss.

use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::{Disk, MemDisk, Opened, Platform, Store, StoreError, open};

fn platform() -> Platform {
    Platform {
        random: |b| {
            b.iter_mut()
                .enumerate()
                .for_each(|(i, x)| *x = (i * 31 + 7) as u8)
        },
        now_unix_ms: || Some(1_761_696_000_000),
        delay_us: |_| {},
        log: |code, msg| eprintln!("sqlite log {code}: {msg}"),
    }
}

/// SQLite is a process-wide singleton here (one heap, one VFS state).
fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn heap() -> &'static mut [u8] {
    // Crashed connections are leaked on purpose, so leave room for them.
    Box::leak(vec![0u8; 256 << 20].into_boxed_slice())
}

fn mount(m: &MemDisk) -> (Store, Opened) {
    let (disk, how) = Disk::open(m.device(), || [9; 16]).unwrap();
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    let (store, info) = open().unwrap();
    assert_eq!(info.schema_to, urmqtt_store::schema::VERSION);
    (store, how)
}

#[test]
fn broker_state_survives_reopen() {
    let _g = lock();
    let m = MemDisk::new(32 << 20);
    {
        let (mut s, how) = mount(&m);
        assert_eq!(how, Opened::Formatted);
        assert_eq!(s.db().query_text("PRAGMA journal_mode").unwrap(), "wal");
        assert_eq!(
            s.db().query_text("PRAGMA locking_mode").unwrap(),
            "exclusive"
        );
        s.begin().unwrap();
        s.device_seen("device-001", 100).unwrap();
        s.device_seen("device-001", 200).unwrap();
        s.device_seen("device-002", 150).unwrap();
        s.revoke("0a1b", "config", 100).unwrap();
        s.revoke("0a1b", "config", 101).unwrap();
        s.retain("devices/device-001/fw", b"1.2.3", 1).unwrap();
        s.retain("devices/device-002/fw", b"9", 0).unwrap();
        s.retain("devices/device-002/fw", b"", 0).unwrap();
        s.retain("empty/payload/kept", b"x", 0).unwrap();
        s.session_upsert("device-002", 100).unwrap();
        s.subscribe("device-002", "devices/device-002/cmd/#", 1)
            .unwrap();
        s.subscribe("device-002", "fleet/all", 0).unwrap();
        s.subscribe("device-002", "fleet/all", 1).unwrap();
        s.queue_push("device-002", "devices/device-002/cmd/reboot", b"now", 1)
            .unwrap();
        s.queue_push("device-002", "devices/device-002/cmd/led", b"", 1)
            .unwrap();
        s.session_upsert("gone", 100).unwrap();
        s.subscribe("gone", "a/b", 0).unwrap();
        s.queue_push("gone", "a/b", b"1", 1).unwrap();
        s.session_delete("gone").unwrap();
        s.commit().unwrap();
        // A subscription for a session that does not exist violates the
        // foreign key and changes nothing.
        assert!(s.subscribe("nobody", "x", 0).is_err());
    }
    // Power loss right after the commit returned: nothing may be lost.
    m.crash(|_| false);
    let (mut s, how) = mount(&m);
    assert_eq!(how, Opened::Existing);
    assert_eq!(s.device_count().unwrap(), 2);
    assert_eq!(
        s.db()
            .query_i64("SELECT connects FROM devices WHERE id = 'device-001'")
            .unwrap(),
        2
    );
    assert_eq!(s.revoked().unwrap(), vec!["0a1b".to_string()]);
    let r = s.retained().unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].topic, "devices/device-001/fw");
    assert_eq!(r[0].payload, b"1.2.3");
    assert_eq!(r[0].qos, 1);
    let sessions = s.sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    let d2 = &sessions[0];
    assert_eq!(d2.client_id, "device-002");
    assert_eq!(
        d2.subscriptions,
        vec![
            ("devices/device-002/cmd/#".to_string(), 1),
            ("fleet/all".to_string(), 1)
        ]
    );
    assert_eq!(d2.queued.len(), 2);
    assert_eq!(d2.queued[0].topic, "devices/device-002/cmd/reboot");
    assert_eq!(d2.queued[1].payload, b"");
    s.begin().unwrap();
    s.queue_clear("device-002").unwrap();
    s.unsubscribe("device-002", "fleet/all").unwrap();
    s.commit().unwrap();
    let sessions = s.sessions().unwrap();
    assert!(sessions[0].queued.is_empty());
    assert_eq!(sessions[0].subscriptions.len(), 1);
}

#[test]
fn uncommitted_work_is_rolled_back_by_power_loss() {
    let _g = lock();
    let m = MemDisk::new(32 << 20);
    {
        let (mut s, _) = mount(&m);
        s.begin().unwrap();
        for i in 1..=50 {
            s.selftest_insert(i, 300).unwrap();
        }
        s.commit().unwrap();
        s.begin().unwrap();
        for i in 51..=400 {
            s.selftest_insert(i, 300).unwrap();
        }
        // No commit: the process dies with the transaction open.
        std::mem::forget(s);
    }
    m.crash(|_| true);
    let (mut s, _) = mount(&m);
    assert_eq!(s.selftest_verify().unwrap(), Ok(50));
}

/// Power fails at many points of a long write sequence, with the volatile
/// cache partially applied in arbitrary order. After every crash the
/// database must pass quick_check and contain exactly a prefix of the
/// committed transactions (every acknowledged commit is present).
#[test]
fn crash_at_random_points_keeps_the_database_consistent() {
    let _g = lock();
    let m = MemDisk::new(32 << 20);
    let mut committed = 0i64;
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for round in 0..12 {
        let (mut s, _) = mount(&m);
        let found = s
            .selftest_verify()
            .unwrap()
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert!(
            found >= committed,
            "round {round}: lost commits ({found} < {committed})"
        );
        committed = found;
        // A few transactions of varying size, then die mid-way through one.
        let txns = 1 + next() % 4;
        let mut seq = committed;
        for t in 0..=txns {
            s.begin().unwrap();
            for _ in 0..(1 + next() % 120) {
                seq += 1;
                s.selftest_insert(seq, 64 + (next() % 900) as usize)
                    .unwrap();
            }
            if t < txns {
                s.commit().unwrap();
                committed = seq;
            }
        }
        // The last transaction is still open (and maybe spilled to the WAL).
        std::mem::forget(s);
        let keep = next();
        m.crash(|i| (keep >> (i % 64)) & 1 == 1);
    }
    let (mut s, _) = mount(&m);
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
    assert!(s.selftest_verify().unwrap().unwrap() >= committed);
}

#[test]
fn foreign_data_is_not_formatted() {
    let _g = lock();
    let m = MemDisk::new(32 << 20);
    {
        let (mut s, _) = mount(&m);
        s.begin().unwrap();
        s.device_seen("x", 1).unwrap();
        s.commit().unwrap();
    }
    // Destroy the superblock's checksum: the disk must be refused, not
    // silently reformatted.
    let mut dev = m.device();
    let mut sb = vec![0u8; 4096];
    dev.read(0, &mut sb).unwrap();
    sb[200] ^= 0xff;
    dev.write(0, &sb).unwrap();
    dev.flush().unwrap();
    assert!(matches!(
        Disk::open(m.device(), || [0; 16]),
        Err(urmqtt_store::DiskError::Layout(
            urmqtt_store::layout::LayoutError::BadChecksum
        ))
    ));
    let _ = StoreError::Init(0);
}

/// H1: the control sequence number, runtime revocations and the allowlist
/// survive power loss; the sequence number never goes down; image-listed
/// revocations cannot be removed; a v1 database is migrated in place.
#[test]
fn control_state_survives_and_migrates() {
    let _g = lock();
    let m = MemDisk::new(32 << 20);
    {
        let (mut s, _) = mount(&m);
        assert_eq!(s.control_seq().unwrap(), 0);
        s.begin().unwrap();
        s.revoke("0c", "config", 1).unwrap();
        s.revoke("0d", "control", 1).unwrap();
        s.set_control_seq(5).unwrap();
        s.allow("device-001", 5, 1).unwrap();
        s.allow("device-002", 5, 1).unwrap();
        s.commit().unwrap();
        // Lower and equal values do not move it.
        s.begin().unwrap();
        s.set_control_seq(3).unwrap();
        s.set_control_seq(5).unwrap();
        s.commit().unwrap();
        assert_eq!(s.control_seq().unwrap(), 5);
        // A rolled-back message leaves no trace.
        s.begin().unwrap();
        s.set_control_seq(9).unwrap();
        s.disallow("device-001").unwrap();
        s.rollback();
        assert_eq!(s.control_seq().unwrap(), 5);
        s.begin().unwrap();
        s.unrevoke("0c").unwrap();
        s.unrevoke("0d").unwrap();
        s.disallow("device-002").unwrap();
        s.set_control_seq(6).unwrap();
        s.commit().unwrap();
    }
    m.crash(|_| false);
    {
        let (mut s, _) = mount(&m);
        assert_eq!(s.control_seq().unwrap(), 6);
        assert_eq!(
            s.revoked().unwrap(),
            vec!["0c".to_string()],
            "image-listed stays"
        );
        assert_eq!(s.allowlist().unwrap(), vec!["device-001".to_string()]);
        // Turn it back into a v1 database (as an M17 image left it).
        s.db()
            .exec("DROP TABLE control_state; DROP TABLE allowlist; PRAGMA user_version = 1;")
            .unwrap();
    }
    let (mut s, _) = mount(&m);
    assert_eq!(
        s.control_seq().unwrap(),
        0,
        "fresh control state after migration"
    );
    assert!(s.allowlist().unwrap().is_empty());
    assert_eq!(s.revoked().unwrap(), vec!["0c".to_string()], "v1 data kept");
    assert_eq!(s.db().query_i64("PRAGMA user_version").unwrap(), 2);
}
