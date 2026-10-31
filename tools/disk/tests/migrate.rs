//! `urmqtt-disk migrate` (STORAGE-PLAN S2, ADR-141).
//!
//! - every golden v1 image is migrated and verified;
//! - a v1 disk with a real SQLite database and a telemetry ring (built by the
//!   same code the fixture command uses) is migrated and compared table by
//!   table;
//! - a power cut at every write of `migrate`, cut cleanly or torn, with the
//!   volatile cache dropped or applied: the disk is a valid v1 or a valid v2
//!   disk with all its data, `--resume` finishes it, `--rollback` returns to
//!   the byte-identical v1 state.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_disk::dev::{Overlay, Shared};
use urmqtt_disk::host::{self, TelemetryDigest};
use urmqtt_disk::migrate::{self, Found, Options};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::layout::{Layout, RegionKind, SB_SLOT_LBA, SECTOR, v1};
use urmqtt_store::mig;
use urmqtt_store::{Disk, MemDisk, Opened};

const DISK: usize = 16 << 20;

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// A fresh path for a rollback file.
fn rb_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    dir.join(format!(
        "rollback-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn golden(name: &str) -> MemDisk {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "crates",
        "store",
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect();
    let text = std::fs::read_to_string(&path).unwrap();
    let mut img = vec![0u8; DISK];
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

/// The SQLite fixture: a layout-v1 disk the way a serving v1 kernel left it.
fn sqlite_fixture() -> MemDisk {
    let m = MemDisk::new(DISK);
    let mut dev = m.device();
    host::format_v1(dev.as_mut(), [0x5a; 16]).unwrap();
    let disk = Disk::open_v1(m.device()).unwrap();
    host::populate(disk).unwrap();
    m.crash(|_| false);
    m
}

#[derive(Debug, PartialEq, Eq)]
struct Digest {
    tel: TelemetryDigest,
    db: u32,
    wal: u32,
    sizes: [u64; 3],
}

fn digest_of(d: &mut Disk) -> Digest {
    let sizes = d.sizes().sizes;
    Digest {
        tel: host::telemetry_digest(d).unwrap(),
        db: host::file_digest(d, RegionKind::Db, sizes[0]).unwrap(),
        wal: host::file_digest(d, RegionKind::Wal, sizes[1]).unwrap(),
        sizes,
    }
}

/// Digest of a v1 disk, on a copy-on-write view (nothing is written).
fn digest_v1(m: &MemDisk) -> Digest {
    let mut d = Disk::open_v1(Box::new(Overlay::new(m.device()))).unwrap();
    digest_of(&mut d)
}

fn digest_v2(m: &MemDisk) -> Digest {
    let (mut d, how) = Disk::open(Box::new(Overlay::new(m.device())), || [0; 16]).unwrap();
    assert_eq!(how, Opened::Existing);
    digest_of(&mut d)
}

fn counts(m: &MemDisk, v1_view: bool) -> Vec<(String, i64)> {
    let ov = Overlay::new(m.device());
    let disk = if v1_view {
        Disk::open_v1(Box::new(ov)).unwrap()
    } else {
        Disk::open(Box::new(ov), || [0; 16]).unwrap().0
    };
    let store = host::open_store(disk).unwrap();
    assert_eq!(
        store.db().query_text("PRAGMA integrity_check").unwrap(),
        "ok"
    );
    host::table_counts(&store).unwrap()
}

fn opts(check_db: bool) -> Options {
    Options {
        check_db,
        ..Options::default()
    }
}

fn class(m: &MemDisk) -> Found {
    migrate::classify(m.device().as_mut()).unwrap()
}

fn lba0(m: &MemDisk) -> Vec<u8> {
    m.raw(0, 4096)
}

#[test]
fn every_golden_v1_image_migrates_and_verifies() {
    let _g = lock();
    for name in ["v1-fresh", "v1-telemetry", "v1-torn"] {
        let m = golden(name);
        assert_eq!(class(&m), Found::V1, "{name}");
        let want = digest_v1(&m);
        let rb = rb_path();
        let rep = migrate::run(&Shared::new(m.device()), &opts(false), Some(&rb)).unwrap();
        assert!(
            rep.steps.iter().any(|s| s.contains("state done")),
            "{name}: {rep:?}"
        );
        assert!(rb.exists(), "{name}: the rollback file");
        assert_eq!(m.unflushed(), 0, "{name}: everything flushed");
        assert_eq!(
            class(&m),
            Found::V2 {
                generation: 2,
                slot: 0
            },
            "{name}"
        );
        // The v2 parser opens it; the data are the same.
        assert_eq!(digest_v2(&m), want, "{name}");
        let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
        let l = d.layout();
        assert!(l.legacy_telemetry());
        for r in l.regions.iter().filter(|r| r.kind != RegionKind::Scratch) {
            if r.kind != RegionKind::Telemetry {
                assert_eq!(r.start % 2048, 0, "{name}: {r:?} is 1 MiB aligned");
            }
        }
        // The files the migration moved are in new aligned regions, and the
        // old space is database space.
        assert!(l.bytes(RegionKind::Db) > 2 << 20);
        let rec = migrate::read_record(m.device().as_mut()).unwrap().unwrap();
        assert_eq!(rec.state, mig::DONE);
        // A second run is refused.
        let err = migrate::run(&Shared::new(m.device()), &opts(false), None).unwrap_err();
        assert!(
            err.contains("v2 already") || err.contains("interrupted"),
            "{name}: {err}"
        );
        // Telemetry keeps working on the migrated disk (new segments carry
        // the layout's UUID, the old ones are accepted in band 0).
        if name == "v1-telemetry" {
            assert_eq!(want.tel.records, 40);
        }
    }
}

#[test]
fn a_real_sqlite_database_survives_with_every_row_count() {
    let _g = lock();
    let m = sqlite_fixture();
    let want = digest_v1(&m);
    let want_counts = counts(&m, true);
    assert!(
        want_counts.iter().any(|(n, c)| n == "devices" && *c == 40),
        "{want_counts:?}"
    );
    assert_eq!(want.tel.records, 600);
    migrate::run(&Shared::new(m.device()), &opts(true), Some(&rb_path())).unwrap();
    assert_eq!(digest_v2(&m), want);
    assert_eq!(counts(&m, false), want_counts);
    // And the broker can keep writing: the migrated layout is a normal v2.
    let (disk, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let mut store = host::open_store(disk).unwrap();
    store.begin().unwrap();
    store.device_seen("device-new", 5).unwrap();
    store.commit().unwrap();
    assert_eq!(store.device_count().unwrap(), 41);
}

#[test]
fn the_dry_run_plan_writes_nothing_and_says_what_it_needs() {
    let _g = lock();
    let m = golden("v1-telemetry");
    let writes = m.write_count();
    let mut dev = m.device();
    let sb = migrate::read_block(dev.as_mut(), 0).unwrap();
    let plan = migrate::plan(dev.as_mut(), &sb, &Options::default()).unwrap();
    assert_eq!(m.write_count(), writes);
    assert_eq!(plan.bytes_to_copy, 8 * 4096 + 4096 + 32);
    assert!(plan.free_sectors >= plan.needed_sectors);
    let text = plan.describe();
    for want in [
        "old regions",
        "new regions",
        "copied:",
        "free space needed",
        "telemetry ring stays in place",
    ] {
        assert!(text.contains(want), "{text}");
    }
    // The plan is a valid v2 layout that encodes and decodes.
    let b = plan.v2.encode();
    assert_eq!(
        Layout::decode(&b, DISK as u64 / SECTOR).unwrap(),
        Some(plan.v2.clone())
    );
}

#[test]
fn preconditions_refuse_what_is_not_safe() {
    let _g = lock();
    // A rollback journal that is not empty.
    let m = golden("v1-fresh");
    let mut dev = m.device();
    let mut st = migrate::read_sizes(dev.as_mut()).unwrap();
    st.seq += 1;
    st.sizes[2] = 512;
    dev.write(16, &st.encode()).unwrap();
    dev.flush().unwrap();
    let err = migrate::run(&Shared::new(m.device()), &opts(false), None).unwrap_err();
    assert!(err.contains("rollback journal"), "{err}");
    assert_eq!(class(&m), Found::V1);
    assert!(migrate::read_record(m.device().as_mut()).unwrap().is_none());
    // A file larger than its region.
    let m = golden("v1-fresh");
    let mut dev = m.device();
    let mut st = migrate::read_sizes(dev.as_mut()).unwrap();
    st.seq += 1;
    st.sizes[0] = 1 << 40;
    dev.write(16, &st.encode()).unwrap();
    dev.flush().unwrap();
    let err = migrate::run(&Shared::new(m.device()), &opts(false), None).unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
    // A disk whose live data leaves no room for the new regions.
    let m = golden("v1-fresh");
    let mut dev = m.device();
    let mut st = migrate::read_sizes(dev.as_mut()).unwrap();
    st.seq += 1;
    st.sizes[0] = 7 << 20; // nearly the whole 8 MiB database region
    dev.write(16, &st.encode()).unwrap();
    dev.flush().unwrap();
    let writes = m.write_count();
    let err = migrate::run(&Shared::new(m.device()), &opts(false), None).unwrap_err();
    assert!(err.contains("not enough free space"), "{err}");
    assert_eq!(m.write_count(), writes, "refused before the first write");
    // A SQLite database that is not one.
    let m = golden("v1-telemetry"); // 32 KiB of zeros declared as the database
    let err = migrate::run(&Shared::new(m.device()), &opts(true), None).unwrap_err();
    assert!(err.contains("verify"), "{err}");
    assert_eq!(class(&m), Found::V1);
    // An existing rollback file is never overwritten.
    let m = golden("v1-fresh");
    let rb = rb_path();
    std::fs::write(&rb, b"precious").unwrap();
    let writes = m.write_count();
    assert!(migrate::run(&Shared::new(m.device()), &opts(false), Some(&rb)).is_err());
    assert_eq!(m.write_count(), writes);
    assert_eq!(std::fs::read(&rb).unwrap(), b"precious");
}

#[test]
fn resume_and_rollback_without_a_migration_say_so() {
    let _g = lock();
    let m = golden("v1-fresh");
    let e = migrate::resume(&Shared::new(m.device()), &opts(false)).unwrap_err();
    assert!(e.contains("nothing to resume"), "{e}");
    let e = migrate::rollback(&Shared::new(m.device()), &opts(false), None).unwrap_err();
    assert!(e.contains("nothing to roll back"), "{e}");
}

#[test]
fn rollback_after_the_switch_needs_force_and_restores_v1_exactly() {
    let _g = lock();
    let m = golden("v1-telemetry");
    let orig = lba0(&m);
    let want = digest_v1(&m);
    migrate::run(&Shared::new(m.device()), &opts(false), Some(&rb_path())).unwrap();
    let e = migrate::rollback(&Shared::new(m.device()), &opts(false), None).unwrap_err();
    assert!(e.contains("--force"), "{e}");
    assert!(matches!(class(&m), Found::V2 { .. }));
    let force = Options {
        force: true,
        ..opts(false)
    };
    migrate::rollback(&Shared::new(m.device()), &force, None).unwrap();
    assert_eq!(class(&m), Found::V1);
    assert_eq!(lba0(&m), orig, "LBA 0 is byte-identical to the original");
    assert!(
        m.raw(24 * 512, 4096).iter().all(|&b| b == 0),
        "slot B empty"
    );
    for lba in [mig::BACKUP_LBA, mig::STATE_LBA[0], mig::STATE_LBA[1]] {
        assert!(
            m.raw(lba as usize * 512, 4096).iter().all(|&b| b == 0),
            "LBA {lba}"
        );
    }
    assert_eq!(digest_v1(&m), want);
    // And the whole thing can be done again.
    migrate::run(&Shared::new(m.device()), &opts(false), Some(&rb_path())).unwrap();
    assert_eq!(digest_v2(&m), want);
}

#[test]
fn the_rollback_file_restores_when_the_disk_copy_is_gone() {
    let _g = lock();
    let m = golden("v1-telemetry");
    let orig = lba0(&m);
    let rb = rb_path();
    migrate::run(&Shared::new(m.device()), &opts(false), Some(&rb)).unwrap();
    // The saved copy on the disk is destroyed.
    let mut dev = m.device();
    dev.write(mig::BACKUP_LBA, &[0u8; 4096]).unwrap();
    dev.flush().unwrap();
    let force = Options {
        force: true,
        ..opts(false)
    };
    let e = migrate::rollback(&Shared::new(m.device()), &force, None).unwrap_err();
    assert!(e.contains("rollback file"), "{e}");
    migrate::rollback(&Shared::new(m.device()), &force, Some(&rb)).unwrap();
    assert_eq!(class(&m), Found::V1);
    assert_eq!(lba0(&m), orig);
}

/// A power cut at every write of `migrate` (STORAGE-PLAN S2: fault injection
/// at every write). `check_db` selects the golden images (no database) or
/// the SQLite fixture.
fn every_write(base: &MemDisk, check_db: bool, label: &str) {
    let want = digest_v1(base);
    let want_counts = check_db.then(|| counts(base, true));
    let orig = lba0(base);
    // How many device writes does a clean run take?
    let probe = base.fork();
    let spy = FaultDevice::new(probe.device(), FaultSpec::default());
    let dev = Shared::new(Box::new(spy));
    migrate::run(&dev, &opts(check_db), Some(&rb_path())).unwrap();
    let total = probe.write_count();
    assert!(total >= 6, "{label}: {total} writes");

    let (mut cases, mut v1_cases, mut v2_cases, mut resumed, mut rolled) = (0, 0, 0, 0, 0);
    for n in 1..=total + 1 {
        for torn in [false, true] {
            for keep in [false, true] {
                if torn && n > total {
                    continue;
                }
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
                let dev = Shared::new(Box::new(FaultDevice::new(m.device(), spec)));
                let r = migrate::run(&dev, &opts(check_db), Some(&rb_path()));
                drop(dev);
                if n > total {
                    r.as_ref().unwrap();
                } else if !torn {
                    // Stopping after the last write still completes the run.
                    assert!(r.is_err() || n == total, "{label}: write {n}");
                }
                m.crash(|_| keep);
                cases += 1;
                let ctx = format!("{label}: write {n} torn={torn} keep={keep}");
                // 1. A valid v1 or a valid v2 disk, with all its data.
                match class(&m) {
                    Found::V1 => {
                        v1_cases += 1;
                        assert_eq!(digest_v1(&m), want, "{ctx}: v1 data");
                        assert_eq!(lba0(&m), orig, "{ctx}: v1 superblock untouched");
                    }
                    Found::V2 { .. } => {
                        v2_cases += 1;
                        assert_eq!(digest_v2(&m), want, "{ctx}: v2 data");
                        if let Some(c) = &want_counts {
                            assert_eq!(&counts(&m, false), c, "{ctx}: row counts");
                        }
                    }
                    other => panic!("{ctx}: corrupt disk: {other:?}"),
                }
                // 2. Finishing: --resume (or a fresh run when nothing was
                //    recorded yet) ends in a verified v2 disk.
                let f = m.fork();
                let fdev = Shared::new(f.device());
                if migrate::read_record(f.device().as_mut()).unwrap().is_some() {
                    migrate::resume(&fdev, &opts(check_db))
                        .unwrap_or_else(|e| panic!("{ctx}: resume: {e}"));
                    resumed += 1;
                } else {
                    migrate::run(&fdev, &opts(check_db), Some(&rb_path()))
                        .unwrap_or_else(|e| panic!("{ctx}: run again: {e}"));
                }
                assert!(matches!(class(&f), Found::V2 { .. }), "{ctx}");
                assert_eq!(digest_v2(&f), want, "{ctx}: after resume");
                if let Some(c) = &want_counts {
                    assert_eq!(&counts(&f, false), c, "{ctx}: row counts after resume");
                }
                // 3. Rolling back ends in the byte-identical v1 disk.
                let g = m.fork();
                let gdev = Shared::new(g.device());
                let force = Options {
                    force: true,
                    ..opts(check_db)
                };
                match migrate::rollback(&gdev, &force, None) {
                    Ok(_) => {
                        rolled += 1;
                        assert_eq!(class(&g), Found::V1, "{ctx}: rolled back");
                        assert_eq!(lba0(&g), orig, "{ctx}: LBA 0 restored");
                        assert_eq!(digest_v1(&g), want, "{ctx}: v1 data after rollback");
                        // The state blocks are gone: the next run starts clean.
                        assert!(migrate::read_record(g.device().as_mut()).unwrap().is_none());
                    }
                    Err(e) => {
                        // Only a disk that was never touched has nothing to roll back.
                        assert!(e.contains("nothing to roll back"), "{ctx}: {e}");
                        assert_eq!(class(&g), Found::V1);
                    }
                }
            }
        }
    }
    eprintln!(
        "migrate fault injection ({label}): {cases} cases over {total} writes: {v1_cases} left a v1 disk, {v2_cases} a v2 disk, none corrupt; {resumed} resumed, {rolled} rolled back"
    );
    assert!(v1_cases > 0 && v2_cases > 0, "{label}: both outcomes occur");
}

#[test]
fn a_power_cut_at_every_write_of_migrate_golden_images() {
    let _g = lock();
    for name in ["v1-fresh", "v1-telemetry", "v1-torn"] {
        every_write(&golden(name), false, name);
    }
}

#[test]
fn a_power_cut_at_every_write_of_migrate_with_a_real_database() {
    let _g = lock();
    every_write(&sqlite_fixture(), true, "sqlite-fixture");
}

#[test]
fn slot_a_and_b_roles_after_the_migration() {
    let _g = lock();
    let m = golden("v1-fresh");
    migrate::run(&Shared::new(m.device()), &opts(false), None).unwrap();
    let mut dev = m.device();
    let a = migrate::read_block(dev.as_mut(), SB_SLOT_LBA[0]).unwrap();
    let b = migrate::read_block(dev.as_mut(), SB_SLOT_LBA[1]).unwrap();
    let (la, lb) = (
        Layout::decode(&a, DISK as u64 / SECTOR).unwrap().unwrap(),
        Layout::decode(&b, DISK as u64 / SECTOR).unwrap().unwrap(),
    );
    assert_eq!((la.generation, lb.generation), (2, 1));
    assert_eq!(la.regions, lb.regions);
    // The kernel's first grow would now go to slot B.
    let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    assert_eq!(d.sb_slot(), 0);
    let _ = v1::VERSION;
}
