//! The in-disk database backup (STORAGE-PLAN S5, ADR-160 to ADR-164).
//!
//! 1. A disk formatted before S5 (the frozen v2.0 images) gets its backup
//!    region with one superblock write, at every power-cut point, and
//!    nothing it held is lost.
//! 2. Snapshots alternate between the two slots, are consistent when the
//!    database changes between steps, and never touch the slot that holds
//!    the previous good one.
//! 3. A power cut at every write of a backup (cut cleanly or torn, volatile
//!    cache dropped or applied) leaves the previous good slot intact and the
//!    live database unharmed.
//! 4. Restore: a damaged database is replaced by the newest intact snapshot;
//!    a cut at every write of the restore ends in the restored database
//!    (the "restoring" mark makes the next boot finish it).
//! 5. Released (discarded) space: a slot is only ever valid by its header
//!    and CRCs; the DB tail discards never reach the backup region.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::backup::{self, BackupError, BackupJob, Progress, SlotHeader};
use urmqtt_store::disk::{BackupRegion, DiscardCaps, DiscardKind, Released};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::layout::{FileKind, Layout, MINOR, RegionKind, SB_SLOT_LBA, SECTOR};
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, MemDisk, Platform, Store, StoreError, open};

const MIB: u64 = 1 << 20;
const NOW: u64 = 1_761_696_000;
const RET: u64 = 30 * 86_400_000;
const SCHEMA: u32 = urmqtt_store::schema::VERSION as u32;

fn platform() -> Platform {
    Platform {
        random: |b| {
            b.iter_mut()
                .enumerate()
                .for_each(|(i, x)| *x = (i * 31 + 7) as u8)
        },
        now_unix_ms: || Some(NOW * 1000),
        delay_us: |_| {},
        log: |_, _| {},
    }
}

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// SQLite's heap is configured once per process; later mounts only swap the
/// disk.
fn heap() -> &'static mut [u8] {
    static GIVEN: AtomicBool = AtomicBool::new(false);
    if GIVEN.swap(true, Ordering::Relaxed) {
        return &mut [];
    }
    Box::leak(vec![0u8; 48 << 20].into_boxed_slice())
}

fn mount_disk(disk: Disk) -> Store {
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    open().unwrap().0
}

/// A 64 MiB disk, formatted, with the backup region.
fn fresh() -> MemDisk {
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    assert!(matches!(
        d.ensure_backup().unwrap(),
        BackupRegion::Added { .. }
    ));
    m
}

fn mount(m: &MemDisk) -> Store {
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    d.ensure_backup().unwrap();
    mount_disk(d)
}

fn with<R>(f: impl FnOnce(&mut Disk) -> R) -> R {
    urmqtt_store::vfs::with_disk(f).unwrap()
}

/// Retained messages `from..to`, 1 KiB each, in one transaction.
fn put(s: &mut Store, from: u32, to: u32) {
    s.begin().unwrap();
    for i in from..to {
        let payload: Vec<u8> = (0..1024u32).map(|b| ((b + i) % 251) as u8).collect();
        s.retain(&format!("k/{i:05}"), &payload, 1).unwrap();
    }
    s.commit().unwrap();
}

fn count(s: &mut Store) -> i64 {
    s.db().query_i64("SELECT count(*) FROM retained").unwrap()
}

fn checkpoint(s: &Store) {
    s.db().exec("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
}

/// Runs a backup to the end, calling `between` after every step.
fn backup_now(
    s: &mut Store,
    trusted: Option<u64>,
    mut between: impl FnMut(&mut Store, u32),
) -> Result<(SlotHeader, usize), BackupError> {
    let mut job = BackupJob::start(trusted, NOW)?;
    for n in 0.. {
        match job.step(s.db(), 8, 64 * 1024)? {
            Progress::Done(h, slot) => return Ok((h, slot)),
            Progress::Working => between(s, n),
        }
    }
    unreachable!()
}

fn headers(m: &MemDisk) -> backup::Slots {
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    backup::scan(&mut d).unwrap()
}

/// The whole of slot `slot` (header and payload area), as the disk holds it.
fn slot_bytes(d: &mut Disk, slot: usize) -> Vec<u8> {
    let g = d.layout().backup().unwrap();
    let mut v = vec![0u8; g.slot_bytes as usize];
    d.read_at(RegionKind::Backup, g.slot_offset(slot), &mut v)
        .unwrap();
    v
}

// ---- 1. the backup region on a disk that has none --------------------------

fn load(name: &str) -> MemDisk {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect();
    let text = std::fs::read_to_string(path).unwrap();
    let mut img = vec![0u8; 16 << 20];
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("size"))
    {
        let (lba, hex) = line.split_once(' ').unwrap();
        let at = lba.parse::<usize>().unwrap() * SECTOR as usize;
        for (i, b) in img[at..at + SECTOR as usize].iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    MemDisk::from_image(img)
}

#[test]
fn a_v2_0_disk_gets_its_backup_region_with_one_superblock_write() {
    let _g = lock();
    for name in ["v2-fresh", "v2-data"] {
        let m = load(name);
        let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
        let old = d.layout().clone();
        assert_eq!((old.minor, d.sb_slot()), (0, 0), "{name}");
        let before = m.write_count();
        let r = d.ensure_backup().unwrap();
        let BackupRegion::Added { bytes, slot_bytes } = r else {
            panic!("{name}: {r:?}");
        };
        // Three header blocks are zeroed first, then the superblock: the
        // only write that changes what the disk means.
        assert_eq!(m.write_count() - before, 4, "{name}");
        let new = d.layout().clone();
        assert_eq!((new.minor, new.generation), (MINOR, old.generation + 1));
        assert_eq!(d.sb_slot(), 1, "the slot not in force took it");
        let b = new.region(RegionKind::Backup).unwrap();
        assert_eq!(b.bytes(), bytes);
        assert_eq!(slot_bytes, new.backup().unwrap().slot_bytes);
        // Everything else is where it was; the database lost only its tail.
        for kind in [RegionKind::Wal, RegionKind::Journal, RegionKind::Telemetry] {
            assert_eq!(new.region(kind), old.region(kind), "{name}: {kind:?}");
        }
        let (old_db, new_db) = (
            old.region(RegionKind::Db).unwrap(),
            new.region(RegionKind::Db).unwrap(),
        );
        assert_eq!(new_db.start, old_db.start);
        assert_eq!(new_db.end(), b.start);
        assert_eq!(b.end(), old_db.end());
        assert_eq!(b.start % u64::from(new.align_sectors), 0);
        // Idempotent, and a reopen sees it.
        assert_eq!(d.ensure_backup().unwrap(), BackupRegion::Present);
        let (d2, how) = Disk::open(m.device(), || [0; 16]).unwrap();
        assert_eq!(how, urmqtt_store::Opened::Existing);
        assert_eq!(d2.layout(), &new);
        // The slots are empty.
        assert_eq!(headers(&m), backup::Slots::default(), "{name}");
    }
}

#[test]
fn the_data_of_a_v2_0_disk_survives_the_upgrade() {
    let _g = lock();
    let m = load("v2-data");
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    d.ensure_backup().unwrap();
    let (log, rec) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    assert_eq!((rec.records, rec.torn_tails), (40, 0));
    drop(log);
    let mut s = mount_disk(d);
    assert_eq!(count(&mut s), 2);
    let r = s.retained().unwrap();
    assert_eq!(
        r.iter().map(|r| r.topic.as_str()).collect::<Vec<_>>(),
        ["fleet/config", "fleet/mode"]
    );
    assert_eq!(s.device_count().unwrap(), 1);
    // And a backup of it works at once.
    let (h, slot) = backup_now(&mut s, None, |_, _| {}).unwrap();
    assert_eq!((h.seq, slot, h.schema_version), (1, 0, SCHEMA));
}

#[test]
fn a_database_with_no_room_to_give_keeps_its_layout() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [1; 16]).unwrap();
    // A database file that fills most of its region.
    let db = d.bytes(RegionKind::Db);
    d.set_file_size(FileKind::Db, db - MIB);
    d.sync().unwrap();
    let generation = d.layout().generation;
    assert_eq!(d.ensure_backup().unwrap(), BackupRegion::NoRoom);
    assert_eq!((d.layout().generation, d.layout().minor), (generation, 0));
    assert!(d.layout().backup().is_none());
}

/// A power cut at every write of the upgrade (cut or torn, cache dropped or
/// applied): the disk is the old layout or the new one with all its data,
/// and the next boot finishes the upgrade.
#[test]
fn a_power_cut_at_every_write_of_the_upgrade_leaves_the_old_or_the_new_layout() {
    let _g = lock();
    let base = load("v2-data");
    let (mut d, _) = Disk::open(base.device(), || [0; 16]).unwrap();
    let old = d.layout().clone();
    let probe = base.fork();
    let (mut pd, _) = Disk::open(probe.device(), || [0; 16]).unwrap();
    pd.ensure_backup().unwrap();
    let total = probe.write_count();
    assert_eq!(total, 4);
    d.sync().unwrap();
    let (mut old_seen, mut new_seen) = (0, 0);
    for n in 1..=total + 1 {
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
                let (mut fd, _) =
                    Disk::open(Box::new(FaultDevice::new(m.device(), spec)), || [0; 16]).unwrap();
                let _ = fd.ensure_backup();
                drop(fd);
                m.crash(|_| keep);
                let (mut d2, _) = Disk::open(m.device(), || [0; 16])
                    .unwrap_or_else(|e| panic!("write {n} torn={torn} keep={keep}: {e:?}"));
                if d2.layout().minor == 0 {
                    old_seen += 1;
                    assert_eq!(d2.layout(), &old, "write {n}: the old layout, unchanged");
                } else {
                    new_seen += 1;
                    assert_eq!(d2.layout().generation, old.generation + 1);
                }
                // Data intact either way.
                let (_, rec) = TelemetryLog::open(&mut d2, NOW, RET).unwrap();
                assert_eq!(rec.records, 40, "write {n}");
                // The next boot completes it, and the result is the same
                // layout whatever happened before.
                d2.ensure_backup().unwrap();
                assert!(d2.layout().backup().is_some());
                assert_eq!(headers(&m), backup::Slots::default());
            }
        }
    }
    eprintln!("upgrade fault injection: {old_seen} old, {new_seen} new layouts, none corrupt");
    assert!(old_seen > 0 && new_seen > 0);
}

// ---- 2. snapshots -------------------------------------------------------------

#[test]
fn snapshots_alternate_and_never_touch_the_other_slot() {
    let _g = lock();
    let m = fresh();
    let mut s = mount(&m);
    put(&mut s, 0, 20);
    let mut last: Option<(usize, Vec<u8>)> = None;
    for round in 1..=4u64 {
        let (h, slot) = backup_now(&mut s, last.as_ref().map(|_| round - 1), |_, _| {}).unwrap();
        assert_eq!((h.seq, slot), (round, ((round - 1) % 2) as usize));
        assert_eq!(
            (h.created, h.schema_version, h.page_size),
            (NOW, SCHEMA, 4096)
        );
        assert_eq!(h.payload_bytes, h.page_count * 4096);
        if let Some((prev_slot, prev)) = &last {
            assert_eq!(
                &with(|d| slot_bytes(d, *prev_slot)),
                prev,
                "round {round}: the previous slot is untouched"
            );
        }
        assert!(with(|d| backup::verify_slot(d, slot, &h)).unwrap());
        last = Some((slot, with(|d| slot_bytes(d, slot))));
        put(&mut s, 20 * round as u32, 20 * round as u32 + 5);
    }
    let sl = headers(&m);
    assert_eq!(sl.header[0].map(|h| h.seq), Some(3));
    assert_eq!(sl.header[1].map(|h| h.seq), Some(4));
    assert_eq!(sl.newest(), Some(1));
}

/// Transactions commit between the steps (the data plane does not wait for
/// the backup). The snapshot is one consistent state: a counter row and the
/// rows it counts always agree.
#[test]
fn a_backup_taken_while_the_database_changes_is_consistent() {
    let _g = lock();
    let m = fresh();
    let mut s = mount(&m);
    s.db()
        .exec("CREATE TABLE IF NOT EXISTS ticks (n INTEGER); CREATE TABLE IF NOT EXISTS total (n INTEGER); INSERT INTO total VALUES (0)")
        .unwrap();
    put(&mut s, 0, 300);
    let mut committed = 0;
    let (h, slot) = backup_now(&mut s, None, |s, n| {
        // Some steps change the database, in transactions of their own.
        if n % 2 == 0 {
            s.begin().unwrap();
            s.db()
                .exec("INSERT INTO ticks VALUES (1); UPDATE total SET n = n + 1")
                .unwrap();
            put_inline(s, 1000 + n);
            s.commit().unwrap();
            committed += 1;
        }
    })
    .unwrap();
    assert!(
        committed > 3,
        "the backup took {committed} steps with commits between"
    );
    // Restore the snapshot into a forked disk and look.
    let f = m.fork();
    let (mut fd, _) = Disk::open(f.device(), || [0; 16]).unwrap();
    backup::restore(&mut fd, SCHEMA).unwrap();
    let r = mount_disk(fd);
    let (ticks, total) = (
        r.db().query_i64("SELECT count(*) FROM ticks").unwrap(),
        r.db().query_i64("SELECT n FROM total").unwrap(),
    );
    assert_eq!(ticks, total, "one consistent state");
    assert_eq!(r.db().query_text("PRAGMA quick_check").unwrap(), "ok");
    assert!(ticks <= committed, "{ticks} ticks, {committed} committed");
    let _ = (h, slot);
}

fn put_inline(s: &mut Store, i: u32) {
    let payload = vec![(i % 251) as u8; 600];
    s.retain(&format!("k/{i:05}"), &payload, 0).unwrap();
}

#[test]
fn a_database_larger_than_a_slot_is_refused_and_nothing_is_written() {
    let _g = lock();
    let m = fresh();
    let mut s = mount(&m);
    put(&mut s, 0, 10);
    let (_, _) = backup_now(&mut s, None, |_, _| {}).unwrap();
    let cap = with(|d| d.backup_payload(0).unwrap().1);
    let before = with(|d| (slot_bytes(d, 0), slot_bytes(d, 1)));
    // More data than a slot holds.
    let mut i = 100;
    while s.db().query_i64("PRAGMA page_count").unwrap() * 4096 <= cap as i64 {
        put(&mut s, i, i + 200);
        i += 200;
    }
    let e = backup_now(&mut s, Some(1), |_, _| {}).unwrap_err();
    assert!(matches!(e, BackupError::TooLarge { .. }), "{e}");
    assert_eq!(before, with(|d| (slot_bytes(d, 0), slot_bytes(d, 1))));
}

#[test]
fn a_snapshot_that_fails_its_crc_is_replaced_and_the_older_good_one_is_kept() {
    let _g = lock();
    let m = fresh();
    let mut s = mount(&m);
    put(&mut s, 0, 10);
    backup_now(&mut s, None, |_, _| {}).unwrap();
    put(&mut s, 10, 20);
    let (h2, slot2) = backup_now(&mut s, Some(1), |_, _| {}).unwrap();
    assert_eq!((h2.seq, slot2), (2, 1));
    // A bit flips in the newest payload.
    with(|d| {
        let g = d.layout().backup().unwrap();
        let at = g.slot_offset(1) + 4096 + 5000;
        let mut b = [0u8; 1];
        d.read_at(RegionKind::Backup, at, &mut b).unwrap();
        b[0] ^= 0x10;
        d.write_at(RegionKind::Backup, at, &b).unwrap();
        d.sync().unwrap();
        assert!(!backup::verify_slot(d, 1, &h2).unwrap());
    });
    let good1 = with(|d| slot_bytes(d, 0));
    // The next backup does not trust the newest header (the caller knows no
    // sequence as good), finds it bad and overwrites it, not the good one.
    let (h3, slot3) = backup_now(&mut s, None, |_, _| {}).unwrap();
    assert_eq!((h3.seq, slot3), (3, 1));
    assert_eq!(good1, with(|d| slot_bytes(d, 0)));
    // A restore with only the older one intact would pick it too.
    let f = m.fork();
    let (mut fd, _) = Disk::open(f.device(), || [0; 16]).unwrap();
    with(|d| {
        let g = d.layout().backup().unwrap();
        let _ = g;
    });
    assert_eq!(backup::restore(&mut fd, SCHEMA).unwrap().header.seq, 3);
}

// ---- 3. faults during a backup ------------------------------------------------

#[test]
fn a_power_cut_at_every_write_of_a_backup_never_harms_the_previous_good_slot() {
    let _g = lock();
    // Two good snapshots (12 and 14 rows), then 20 rows live.
    let base = fresh();
    let (h2, good2) = {
        let mut s = mount(&base);
        put(&mut s, 0, 12);
        backup_now(&mut s, None, |_, _| {}).unwrap();
        put(&mut s, 12, 14);
        let (h2, slot2) = backup_now(&mut s, Some(1), |_, _| {}).unwrap();
        assert_eq!(slot2, 1);
        put(&mut s, 14, 20);
        checkpoint(&s);
        (h2, with(|d| slot_bytes(d, 1)))
    };
    base.crash(|_| false);

    let run = |m: &MemDisk, spec: FaultSpec| {
        let (d, _) = Disk::open(Box::new(FaultDevice::new(m.device(), spec)), || [0; 16]).unwrap();
        urmqtt_store::init(heap(), d, platform()).unwrap();
        if let Ok((mut s, _)) = open() {
            let _ = backup_now(&mut s, Some(2), |_, _| {});
        }
    };
    let probe = base.fork();
    run(&probe, FaultSpec::default());
    let total = probe.write_count();
    assert!(total > 20, "{total}");

    let (mut cases, mut kept_old, mut got_new) = (0, 0, 0);
    for n in 1..=total + 1 {
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
                run(&m, spec);
                m.crash(|_| keep);
                cases += 1;
                let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
                // The previous good slot: same header, same bytes, intact.
                let sl = backup::scan(&mut d).unwrap();
                assert_eq!(sl.header[1], Some(h2), "write {n} torn={torn} keep={keep}");
                assert_eq!(slot_bytes(&mut d, 1), good2, "write {n}: slot 1 untouched");
                assert!(backup::verify_slot(&mut d, 1, &h2).unwrap());
                // The slot being written is valid only if it is complete.
                if let Some(h3) = sl.header[0] {
                    assert!(
                        backup::verify_slot(&mut d, 0, &h3).unwrap(),
                        "write {n}: a valid header means a valid payload"
                    );
                    if h3.seq == 3 {
                        got_new += 1;
                    } else {
                        kept_old += 1;
                    }
                }
                // The live database is unharmed by the backup.
                let mut s = mount_disk(d);
                assert_eq!(s.db().query_text("PRAGMA quick_check").unwrap(), "ok");
                assert_eq!(count(&mut s), 20, "write {n}");
                // Restoring right now picks the newest intact snapshot.
                let f = m.fork();
                let (mut fd, _) = Disk::open(f.device(), || [0; 16]).unwrap();
                let r = backup::restore(&mut fd, SCHEMA).unwrap();
                assert!(r.header.seq == 2 || r.header.seq == 3);
            }
        }
    }
    eprintln!(
        "backup fault injection: {cases} cases over {total} writes; the older slot survived every one ({kept_old} with the target still the previous snapshot, {got_new} with a finished new one)"
    );
    assert!(got_new > 0);
}

// ---- 4. restore ---------------------------------------------------------------

/// The database file is damaged: page 1 and the next page are garbage.
fn damage(m: &MemDisk) {
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let junk: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    d.write_at(RegionKind::Db, 0, &junk).unwrap();
    d.sync().unwrap();
}

/// A disk with a snapshot of 12 rows, 20 rows live, the database file
/// checkpointed and then damaged.
fn damaged() -> MemDisk {
    let m = fresh();
    {
        let mut s = mount(&m);
        put(&mut s, 0, 12);
        backup_now(&mut s, None, |_, _| {}).unwrap();
        put(&mut s, 12, 20);
        checkpoint(&s);
    }
    m.crash(|_| false);
    damage(&m);
    m
}

#[test]
fn a_damaged_database_is_refused_without_auto_restore_and_restored_with_it() {
    let _g = lock();
    let m = damaged();
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    // Without auto_restore: corruption, as before S5; nothing was changed.
    let before = m.fork();
    let e = backup::open_or_restore(false).err().unwrap();
    assert!(matches!(e, StoreError::Corrupt(_)), "{e}");
    let (mut a, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let (mut b, _) = Disk::open(before.device(), || [0; 16]).unwrap();
    assert_eq!(slot_bytes(&mut a, 0), slot_bytes(&mut b, 0));
    // With it: restored from the snapshot, 12 rows, quick_check clean.
    let (mut s, _, report) = backup::open_or_restore(true).unwrap();
    let r = report.expect("restored");
    assert_eq!(
        (r.restored.slot, r.restored.header.seq, r.restored.resumed),
        (0, 1, false)
    );
    assert!(!r.reason.is_empty());
    assert_eq!(count(&mut s), 12);
    assert_eq!(s.db().query_text("PRAGMA quick_check").unwrap(), "ok");
    // The new database takes writes, and a backup of it works.
    put(&mut s, 100, 105);
    let (h, slot) = backup_now(&mut s, None, |_, _| {}).unwrap();
    assert_eq!((h.seq, slot), (2, 1));
    drop(s);
    // A clean boot afterwards restores nothing.
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    let (mut s, _, report) = backup::open_or_restore(true).unwrap();
    assert!(report.is_none());
    assert_eq!(count(&mut s), 17);
}

#[test]
fn with_no_intact_backup_the_corruption_is_still_refused() {
    let _g = lock();
    let m = damaged();
    // The only snapshot goes bad too.
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let g = d.layout().backup().unwrap();
    d.write_at(
        RegionKind::Backup,
        g.slot_offset(0) + 4096 + 100,
        &[0xff; 8],
    )
    .unwrap();
    d.sync().unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    let e = backup::open_or_restore(true).err().unwrap();
    assert!(
        matches!(&e, StoreError::Corrupt(t) if t.contains("restoring from a backup failed")),
        "{e}"
    );
    // A disk that never had a backup says the same.
    let m = MemDisk::sparse(64 * MIB);
    let (d, _) = Disk::open(m.device(), || [3; 16]).unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    let mut s = open().unwrap().0;
    put(&mut s, 0, 5);
    checkpoint(&s);
    drop(s);
    damage(&m);
    let (d, _) = Disk::open(m.device(), || [3; 16]).unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    let e = backup::open_or_restore(true).err().unwrap();
    assert!(matches!(e, StoreError::Corrupt(_)), "{e}");
}

#[test]
fn a_snapshot_of_a_newer_schema_is_not_restored() {
    let _g = lock();
    let m = damaged();
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let err = backup::restore(&mut d, SCHEMA - 1).unwrap_err();
    assert_eq!(err, BackupError::TooNew(SCHEMA));
}

/// A power cut at every write of the restore (cut or torn, cache dropped or
/// applied): the next boot ends with the restored database, never with a
/// mixture of the damaged file and the snapshot.
#[test]
fn a_power_cut_at_every_write_of_a_restore_ends_in_the_restored_database() {
    let _g = lock();
    let base = damaged();
    let boot = |m: &MemDisk, spec: FaultSpec| -> Result<i64, String> {
        let (d, _) = Disk::open(Box::new(FaultDevice::new(m.device(), spec)), || [0; 16])
            .map_err(|e| format!("{e:?}"))?;
        urmqtt_store::init(heap(), d, platform()).map_err(|e| format!("{e}"))?;
        let (mut s, _, _) = backup::open_or_restore(true).map_err(|e| format!("{e}"))?;
        Ok(count(&mut s))
    };
    let probe = base.fork();
    assert_eq!(boot(&probe, FaultSpec::default()), Ok(12));
    let total = probe.write_count();
    assert!(total >= 6, "{total}");
    let (mut cases, mut pending_seen) = (0, 0);
    for n in 1..=total + 1 {
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
                let _ = boot(&m, spec);
                m.crash(|_| keep);
                cases += 1;
                {
                    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
                    if backup::restore_pending(&mut d).unwrap().is_some() {
                        pending_seen += 1;
                    }
                    // The snapshot itself is never harmed by a restore.
                    let sl = backup::scan(&mut d).unwrap();
                    let h = sl.header[0].expect("snapshot header");
                    assert!(backup::verify_slot(&mut d, 0, &h).unwrap(), "write {n}");
                }
                assert_eq!(
                    boot(&m, FaultSpec::default()),
                    Ok(12),
                    "write {n} torn={torn} keep={keep}: the next boot ends restored"
                );
                // And once done, a further boot restores nothing.
                let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
                assert_eq!(backup::restore_pending(&mut d).unwrap(), None);
            }
        }
    }
    eprintln!(
        "restore fault injection: {cases} cases over {total} writes ({pending_seen} with the restore mark set): all end restored"
    );
    assert!(pending_seen > 0);
}

// ---- 5. released space --------------------------------------------------------

fn caps() -> DiscardCaps {
    DiscardCaps {
        kind: DiscardKind::Discard,
        max_sectors: 1 << 16,
        max_ranges: 16,
        granularity: 8,
    }
}

/// A slot is valid only by its header and CRCs: garbage where a snapshot was
/// (what a device may return for a range it unmapped) is never taken for a
/// backup, and never restored.
#[test]
fn garbage_in_a_slot_is_never_a_backup() {
    let _g = lock();
    let m = fresh();
    {
        let mut s = mount(&m);
        put(&mut s, 0, 12);
        backup_now(&mut s, None, |_, _| {}).unwrap();
        put(&mut s, 12, 20);
        backup_now(&mut s, Some(1), |_, _| {}).unwrap();
    }
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let r = d.layout().region(RegionKind::Backup).unwrap();
    let g = d.layout().backup().unwrap();
    drop(d);
    // Slot 1 (newest) becomes garbage entirely; slot 0 keeps its header and
    // gets garbage payload; then each case in turn.
    let slot_lba = |i: usize| r.start + g.slot_offset(i) / SECTOR;
    m.scribble(slot_lba(1), g.slot_bytes / SECTOR, 7);
    let sl = headers(&m);
    assert_eq!(sl.header[1], None, "garbage has no valid header");
    assert_eq!(sl.newest(), Some(0));
    {
        let f = m.fork();
        let (mut fd, _) = Disk::open(f.device(), || [0; 16]).unwrap();
        assert_eq!(backup::restore(&mut fd, SCHEMA).unwrap().header.seq, 1);
    }
    m.scribble(slot_lba(0) + 8, 64, 9);
    let f = m.fork();
    let (mut fd, _) = Disk::open(f.device(), || [0; 16]).unwrap();
    assert_eq!(
        backup::restore(&mut fd, SCHEMA).unwrap_err(),
        BackupError::NoBackup
    );
    // The control block as garbage is the idle state.
    m.scribble(r.start, 8, 3);
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    assert_eq!(backup::restore_pending(&mut d).unwrap(), None);
}

/// Discards of the database's tail (a truncate, a deleted journal) can never
/// reach the backup region, which was carved out of that tail: the ranges
/// are computed from the database's extents, which no longer include it.
/// Pending discards from before the carve are cancelled by it.
#[test]
fn discards_of_the_database_tail_stay_out_of_the_backup_region() {
    let _g = lock();
    let m = MemDisk::sparse(128 * MIB).with_discard(caps(), Released::Garbage);
    let (mut d, _) = Disk::open(m.device(), || [5; 16]).unwrap();
    assert!(d.set_discard(true).is_some());
    // The database file grew to 20 MiB and was cut back: its tail up to the
    // end of the region is queued for release before the carve.
    d.set_file_size(FileKind::Db, 20 * MIB);
    d.sync().unwrap();
    d.set_file_size(FileKind::Db, 2 * MIB);
    d.sync().unwrap();
    assert!(d.discard_pending());
    let old_db = d.layout().region(RegionKind::Db).unwrap();
    assert!(matches!(
        d.ensure_backup().unwrap(),
        BackupRegion::Added { .. }
    ));
    let b = d.layout().region(RegionKind::Backup).unwrap();
    assert!(b.start > old_db.start);
    // Later truncates and every queued range stay below the backup region.
    d.set_file_size(FileKind::Db, MIB);
    d.sync().unwrap();
    while d.discard_pending() {
        d.run_discards(4).unwrap();
        d.sync().unwrap();
    }
    for (lba, n) in m.discard_log() {
        assert!(
            lba + n <= b.start || lba >= b.end(),
            "a discard of LBA {lba}+{n} reaches the backup region {}..{}",
            b.start,
            b.end()
        );
    }
    assert_eq!(m.discard_violations(), 0);
}

/// A restore onto a database region whose tail was released (it reads back
/// as garbage) works: it overwrites the head and sets the size, and nothing
/// beyond the new size is ever read.
#[test]
fn restoring_over_released_space_works() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB).with_discard(caps(), Released::Garbage);
    {
        let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
        d.ensure_backup().unwrap();
        assert!(d.set_discard(true).is_some());
        let mut s = mount_disk(d);
        put(&mut s, 0, 12);
        backup_now(&mut s, None, |_, _| {}).unwrap();
        put(&mut s, 12, 40);
        checkpoint(&s);
    }
    m.crash(|_| false);
    damage(&m);
    // Garbage across the database region beyond the head.
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let r = d.layout().region(RegionKind::Db).unwrap();
    drop(d);
    m.scribble(r.start + 64, 2048, 11);
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    urmqtt_store::init(heap(), d, platform()).unwrap();
    let (mut s, _, report) = backup::open_or_restore(true).unwrap();
    assert!(report.is_some());
    assert_eq!(count(&mut s), 12);
    assert_eq!(s.db().query_text("PRAGMA quick_check").unwrap(), "ok");
}

// ---- the superblock ----------------------------------------------------------

#[test]
fn the_minor_version_is_in_the_superblock_and_an_older_reader_refuses_it() {
    let _g = lock();
    let m = fresh();
    let mut sb = [0u8; 4096];
    let mut dev = m.device();
    // Slot B holds the upgraded layout.
    dev.read(SB_SLOT_LBA[1], &mut sb).unwrap();
    assert_eq!(u32::from_le_bytes(sb[60..64].try_into().unwrap()), MINOR);
    // The check a build that predates minors makes (S4's `decode`): a
    // non-zero reserved word is `Inconsistent`, so it refuses the disk
    // instead of mistaking the backup region for something else.
    assert_ne!(u32::from_le_bytes(sb[60..64].try_into().unwrap()), 0);
    // This build reads it, and refuses a minor it does not know.
    let l = Layout::decode(&sb, 64 * MIB / SECTOR).unwrap().unwrap();
    assert_eq!(l.minor, MINOR);
    let mut future = sb;
    future[60..64].copy_from_slice(&(MINOR + 1).to_le_bytes());
    let crc = urmqtt_store::crc::crc32c(&future[..4092]);
    future[4092..].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        Layout::decode(&future, 64 * MIB / SECTOR),
        Err(urmqtt_store::layout::LayoutError::UnsupportedMinor(
            MINOR + 1
        ))
    );
}

// ---- measurement (ADR-161) ----------------------------------------------------

/// `cargo test --release -p urmqtt-store --test backup -- --ignored --nocapture`
///
/// The cost of a snapshot to the one thread that serves the database, on the
/// host's `MemDisk` (so only SQLite and the VFS count, not a device): the
/// SQLite online backup API in steps of 16 pages against `VACUUM INTO` (one
/// call that cannot be split), for a database of about 24 MiB.
#[test]
#[ignore = "a measurement, not a test"]
fn backup_cost_against_vacuum_into() {
    let _g = lock();
    let m = MemDisk::sparse(1024 * MIB);
    let mut s = mount(&m);
    s.begin().unwrap();
    for i in 0..6000u32 {
        let payload = vec![(i % 251) as u8; 3800];
        s.retain(&format!("k/{i:05}"), &payload, 1).unwrap();
    }
    s.commit().unwrap();
    checkpoint(&s);
    let pages = s.db().query_i64("PRAGMA page_count").unwrap();

    // The online backup API, bounded steps.
    let mut job = BackupJob::start(None, NOW).unwrap();
    let (mut steps, mut longest, mut total) =
        (0u32, std::time::Duration::ZERO, std::time::Duration::ZERO);
    let t0 = std::time::Instant::now();
    loop {
        let t = std::time::Instant::now();
        let p = job.step(s.db(), 16, 128 * 1024).unwrap();
        let d = t.elapsed();
        longest = longest.max(d);
        total += d;
        steps += 1;
        if matches!(p, Progress::Done(..)) {
            break;
        }
    }
    let wall = t0.elapsed();

    // The same copy as one SQLite call: the backup API with no step limit.
    let mut one = BackupJob::start(Some(1), NOW).unwrap();
    let mut one_longest = std::time::Duration::ZERO;
    loop {
        let t = std::time::Instant::now();
        let p = one.step(s.db(), 1 << 30, usize::MAX / 2).unwrap();
        one_longest = one_longest.max(t.elapsed());
        if matches!(p, Progress::Done(..)) {
            break;
        }
    }

    // VACUUM INTO the backup file. This build has SQLITE_MAX_ATTACHED=0
    // (no ATTACH, one database per connection), and VACUUM INTO needs an
    // attachment inside: it fails, whatever it would cost.
    assert!(urmqtt_store::vfs::backup_attach(0));
    let t = std::time::Instant::now();
    let vacuum = s.db().exec("VACUUM INTO 'urmqtt-backup.db'");
    let vacuum_t = t.elapsed();
    let vacuum_bytes = urmqtt_store::vfs::backup_detach();
    eprintln!(
        "backup cost, {pages} pages ({} MiB): online backup API in {steps} steps of 16 pages: longest step {longest:?}, all steps {total:?}, wall {wall:?}; \
         the same API in one call: {one_longest:?}; VACUUM INTO: {} after {vacuum_t:?} ({} KiB written)",
        (pages * 4096) >> 20,
        match &vacuum {
            Ok(()) => "worked (one call, cannot be split)".to_string(),
            Err(e) => format!("FAILED: {e}"),
        },
        vacuum_bytes >> 10
    );
    let _ = (RET, SECTOR, SB_SLOT_LBA, FileKind::Db);
}
