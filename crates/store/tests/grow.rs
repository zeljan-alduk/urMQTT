//! Growing the disk (STORAGE-PLAN S3, ADR-142).
//!
//! 1. 1 GiB -> 4 GiB -> 64 GiB with the broker's SQLite state and a
//!    telemetry log on the disk: nothing is lost or moved, the new space is
//!    used.
//! 2. A power cut at every write of the whole grow procedure (the GPT: backup
//!    to the new end, data partition extended; then the superblock), cut
//!    cleanly or torn, with the volatile cache dropped or applied: the disk
//!    is always the old layout or the new one, with all data, and the next
//!    boot finishes the job.

use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::gpt::{self, DataPartition};
use urmqtt_store::layout::{FileKind, Layout, RegionKind, SB_SLOT_LBA, SECTOR};
use urmqtt_store::part::Partition;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{BlockDevice, Disk, MemDisk, Opened, Platform, Store, open};

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
const NOW: u64 = 1_761_696_000;
const RET: u64 = 30 * 86_400_000;

fn platform() -> Platform {
    Platform {
        random: |b| {
            b.iter_mut()
                .enumerate()
                .for_each(|(i, x)| *x = (i * 31 + 7) as u8)
        },
        now_unix_ms: || Some(NOW * 1000),
        delay_us: |_| {},
        log: |code, msg| eprintln!("sqlite log {code}: {msg}"),
    }
}

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn heap() -> &'static mut [u8] {
    Box::leak(vec![0u8; 64 << 20].into_boxed_slice())
}

/// A boot disk of `bytes`: the raw image (GPT, a 1 MiB ESP) on a larger
/// medium, as a cloud server gets it.
fn image(bytes: u64) -> MemDisk {
    let esp = vec![0xe5u8; MIB as usize];
    let img = gpt::raw_image(&esp).unwrap();
    let m = MemDisk::sparse(bytes);
    let mut dev = m.device();
    // The image is written in 1 MiB pieces (the sparse disk costs only what
    // is non-zero).
    for (i, chunk) in img.chunks(MIB as usize).enumerate() {
        if chunk.iter().any(|&b| b != 0) {
            dev.write(i as u64 * MIB / SECTOR, chunk).unwrap();
        }
    }
    dev.flush().unwrap();
    m
}

struct Booted {
    disk: Disk,
    part: DataPartition,
    steps: gpt::Steps,
    opened: Opened,
    grown: Option<urmqtt_store::disk::Grown>,
}

/// What the kernel does at boot before the store: the GPT first-boot and
/// grow steps, the data partition window, the layout, the grow.
fn boot(dev: Box<dyn BlockDevice>, grow: bool) -> Result<Booted, String> {
    let mut dev = dev;
    let mut n = 0u8;
    let (part, steps) = gpt::prepare(dev.as_mut(), || {
        n += 1;
        [n; 16]
    })
    .map_err(|e| format!("gpt: {e:?}"))?;
    let window = Partition::new(dev, part.first_lba, part.sectors()).ok_or("window")?;
    let (mut disk, opened) = Disk::open_with(Box::new(window), || [0x42; 16], 8)
        .map_err(|e| format!("layout: {e:?}"))?;
    let grown = if grow {
        disk.grow(50).map_err(|e| format!("grow: {e:?}"))?
    } else {
        None
    };
    Ok(Booted {
        disk,
        part,
        steps,
        opened,
        grown,
    })
}

fn mount(disk: Disk) -> Store {
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    open().unwrap().0
}

#[test]
fn grow_1_gib_to_4_gib_to_64_gib_with_data_present() {
    let _g = lock();
    let m = image(GIB);
    // --- 1 GiB: formatted, data written.
    let b = boot(m.device(), true).unwrap();
    assert_eq!(b.opened, Opened::Formatted);
    assert!(b.grown.is_none());
    let l1 = b.disk.layout().clone();
    let mut s = mount(b.disk);
    s.begin().unwrap();
    for i in 0..300 {
        s.device_seen(&format!("device-{i:04}"), 100 + i).unwrap();
    }
    s.retain("devices/device-0001/fw", b"1.2.3", 1).unwrap();
    s.commit().unwrap();
    let mut log =
        urmqtt_store::vfs::with_disk(|d| TelemetryLog::open(d, NOW, RET).unwrap().0).unwrap();
    let log_records = urmqtt_store::vfs::with_disk(|d| {
        for i in 0..3000u64 {
            log.append(
                d,
                (i % 8) as usize,
                NOW * 1000 + i,
                "devices/d/t",
                &i.to_le_bytes(),
            )
            .unwrap();
        }
        log.flush(d).unwrap()
    })
    .unwrap();
    assert_eq!(log_records, 3000);
    drop(log);
    drop(s);
    m.crash(|_| false);

    for (step, size) in [(1, 4 * GIB), (2, 64 * GIB)] {
        m.grow_to(size);
        let b = boot(m.device(), true).unwrap();
        assert_eq!(b.opened, Opened::Existing, "step {step}");
        assert!(
            b.steps.moved_backup && b.steps.extended_partition,
            "step {step}: {:?}",
            b.steps
        );
        let g = b.grown.expect("the layout grows");
        let l = b.disk.layout().clone();
        // The partition covers the disk, the layout covers the partition.
        assert_eq!(
            l.total_sectors,
            b.part.sectors() / 8 * 8,
            "step {step}: the layout fills the partition"
        );
        assert!(b.part.last_lba + 33 < size / SECTOR);
        // Nothing that existed moved.
        for r in l1.regions.iter().filter(|r| r.kind != RegionKind::Scratch) {
            assert!(
                l.regions.contains(r) || l.extents(r.kind).any(|e| e.start == r.start),
                "{r:?}"
            );
        }
        assert_eq!(g.generation, step as u64 + 1);
        assert!(g.db_sectors > 0 && g.telemetry_sectors > 0);
        assert_eq!(l.bytes(RegionKind::Wal), l1.bytes(RegionKind::Wal));
        assert_eq!(l.bytes(RegionKind::Journal), l1.bytes(RegionKind::Journal));
        // Data present: SQLite rows, retained message, every telemetry record.
        let mut s = mount(b.disk);
        assert_eq!(s.device_count().unwrap(), 299 + step, "step {step}");
        assert_eq!(s.retained().unwrap().len(), 1);
        assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
        let (n, per_part_cap) = urmqtt_store::vfs::with_disk(|d| {
            let (mut log, rec) = TelemetryLog::open(d, NOW, RET).unwrap();
            let cap = log.capacity_bytes();
            // The grown ring takes new records too.
            log.append(d, 0, NOW * 1000 + 9_000_000, "devices/d/t", b"after-grow")
                .unwrap();
            log.flush(d).unwrap();
            (rec.records, cap)
        })
        .unwrap();
        assert_eq!(
            n,
            3000 + (step as u64 - 1),
            "step {step}: every record survived"
        );
        // The ring is larger than the 1 GiB one.
        assert!(per_part_cap > 100 * MIB, "step {step}: {per_part_cap}");
        s.begin().unwrap();
        s.device_seen(&format!("device-new-{step}"), 999).unwrap();
        s.commit().unwrap();
        drop(s);
        m.crash(|_| false);
    }
    // Final reopen without growing: the 64 GiB layout is what was written.
    let b = boot(m.device(), true).unwrap();
    assert!(b.grown.is_none(), "nothing left to grow");
    assert_eq!(b.disk.layout().generation, 3);
    assert!(b.disk.layout().total_sectors > 60 * GIB / SECTOR);
    let mut s = mount(b.disk);
    assert_eq!(s.device_count().unwrap(), 302);
    // The database can now hold more than the old region: write across the
    // old end and read it back.
    let old_db = l1.bytes(RegionKind::Db);
    urmqtt_store::vfs::with_disk(|d| {
        let pat: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        d.write_at(RegionKind::Db, old_db - 5_000, &pat).unwrap();
        let mut back = vec![0u8; pat.len()];
        d.read_at(RegionKind::Db, old_db - 5_000, &mut back)
            .unwrap();
        assert_eq!(back, pat);
        assert!(d.bytes(RegionKind::Db) > 20 * GIB);
    })
    .unwrap();
    drop(s);
}

/// The state of a crashed disk, read without repairing anything.
struct Seen {
    layout: Layout,
    records: u64,
    pattern_ok: bool,
}

const PATTERN_AT: u64 = 7_777;

fn pattern() -> Vec<u8> {
    (0..90_000u32).map(|i| (i % 251) as u8 ^ 0x5a).collect()
}

/// Reads the layout and data of a (crashed) disk the way a boot does, but
/// with no repair: the primary or the backup GPT, the data partition as the
/// table describes it, the superblock choice, the data.
fn look(m: &MemDisk) -> Result<Seen, String> {
    let mut dev = m.device();
    let t = match gpt::read_table(dev.as_mut(), 1).map_err(|e| format!("{e:?}"))? {
        Some(t) => t,
        None => {
            let last = dev.sectors() - 1;
            gpt::read_table(dev.as_mut(), last)
                .map_err(|e| format!("{e:?}"))?
                .ok_or("no valid GPT copy")?
        }
    };
    let e = t.data_partition().ok_or("no data partition")?;
    let window = Partition::new(m.device(), e.first_lba, e.sectors()).ok_or("window")?;
    // Refuse to use a layout that does not fit the partition the table gives.
    let (mut disk, _) = Disk::open_with(Box::new(window), || [0; 16], 8)
        .map_err(|err| format!("layout: {err:?}"))?;
    let mut back = vec![0u8; pattern().len()];
    disk.read_at(RegionKind::Wal, PATTERN_AT, &mut back)
        .map_err(|err| format!("{err:?}"))?;
    let (_, rec) = TelemetryLog::open(&mut disk, NOW, RET).map_err(|err| format!("{err:?}"))?;
    Ok(Seen {
        layout: disk.layout().clone(),
        records: rec.records,
        pattern_ok: back == pattern(),
    })
}

#[test]
fn a_power_cut_at_every_write_of_the_grow_leaves_the_old_or_the_new_layout() {
    let _g = lock();
    let small = 64 * MIB;
    let big = 192 * MIB;
    // The disk as it was before the volume grew: booted once, data present.
    let base = image(small);
    {
        let mut b = boot(base.device(), true).unwrap();
        b.disk
            .write_at(RegionKind::Wal, PATTERN_AT, &pattern())
            .unwrap();
        b.disk
            .set_file_size(FileKind::Wal, PATTERN_AT + pattern().len() as u64);
        b.disk.sync().unwrap();
        let (mut log, _) = TelemetryLog::open(&mut b.disk, NOW, RET).unwrap();
        for i in 0..400u64 {
            log.append(
                &mut b.disk,
                (i % 8) as usize,
                NOW * 1000 + i,
                "t/x",
                &i.to_le_bytes(),
            )
            .unwrap();
        }
        log.flush(&mut b.disk).unwrap();
    }
    base.crash(|_| false);
    let old = look(&base).expect("the base disk is fine");
    assert_eq!(old.records, 400);
    assert!(old.pattern_ok);
    let old_total = old.layout.total_sectors;

    // How many writes does the whole procedure take?
    let probe = base.fork();
    probe.grow_to(big);
    let mut counter = FaultDevice::new(probe.device(), FaultSpec::default());
    {
        let mut n = 0u8;
        let (part, _) = gpt::prepare(&mut counter, || {
            n += 1;
            [n; 16]
        })
        .unwrap();
        let w = Partition::new(Box::new(counter), part.first_lba, part.sectors()).unwrap();
        let (mut d, _) = Disk::open_with(Box::new(w), || [0; 16], 8).unwrap();
        d.grow(50).unwrap().unwrap();
    }
    let total_writes = probe.write_count();
    assert!(total_writes >= 8, "{total_writes}");

    let mut cases = 0;
    let mut saw_old = 0;
    let mut saw_new = 0;
    for n in 1..=total_writes + 1 {
        for torn in [false, true] {
            for keep in [false, true] {
                let m = base.fork();
                m.grow_to(big);
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
                let r = boot(Box::new(FaultDevice::new(m.device(), spec)), true);
                let finished = r.is_ok();
                drop(r);
                m.crash(|_| keep);
                cases += 1;
                // 1. Old or new layout, never anything else; all data there.
                let seen = look(&m).unwrap_or_else(|e| {
                    panic!("write {n} torn={torn} keep={keep}: unreadable disk: {e}")
                });
                assert!(seen.pattern_ok, "write {n}: WAL data");
                assert_eq!(seen.records, 400, "write {n}: telemetry records");
                if seen.layout.total_sectors == old_total {
                    saw_old += 1;
                    assert_eq!(
                        seen.layout, old.layout,
                        "write {n}: the old layout, unchanged"
                    );
                } else {
                    saw_new += 1;
                    assert_eq!(
                        seen.layout.generation,
                        old.layout.generation + 1,
                        "write {n}"
                    );
                    assert!(seen.layout.total_sectors > old_total);
                }
                if finished && !torn {
                    assert!(
                        seen.layout.total_sectors > old_total,
                        "completed boot, write {n}"
                    );
                }
                // 2. The next boot, with no fault, ends in the new layout.
                let b = boot(m.device(), true)
                    .unwrap_or_else(|e| panic!("write {n} torn={torn} keep={keep}: recovery: {e}"));
                assert!(
                    b.disk.layout().total_sectors > old_total,
                    "write {n}: grown after recovery"
                );
                assert_eq!(b.disk.layout().generation, old.layout.generation + 1);
                m.crash(|_| false);
                let again = look(&m).unwrap();
                assert_eq!(again.records, 400);
                assert!(again.pattern_ok);
                assert_eq!(again.layout.total_sectors, b.disk.layout().total_sectors);
            }
        }
    }
    eprintln!(
        "grow fault injection: {cases} cases over {total_writes} writes: {saw_old} old, {saw_new} new layouts, none corrupt"
    );
    assert!(saw_old > 0 && saw_new > 0, "both outcomes were exercised");
}

/// The superblock slots alternate with every grow and the older slot stays
/// a valid previous layout until the next one overwrites it.
#[test]
fn superblock_slots_alternate() {
    let _g = lock();
    let m = image(GIB);
    let b = boot(m.device(), true).unwrap();
    assert_eq!(b.disk.sb_slot(), 0);
    drop(b);
    m.grow_to(2 * GIB);
    let b = boot(m.device(), true).unwrap();
    assert_eq!(b.disk.sb_slot(), 1);
    drop(b);
    m.grow_to(3 * GIB);
    let b = boot(m.device(), true).unwrap();
    assert_eq!(b.disk.sb_slot(), 0);
    let first = b.part.first_lba;
    drop(b);
    // Both slots are valid layouts of consecutive generations.
    let mut dev = m.device();
    let mut a = [0u8; 4096];
    let mut c = [0u8; 4096];
    dev.read(first + SB_SLOT_LBA[0], &mut a).unwrap();
    dev.read(first + SB_SLOT_LBA[1], &mut c).unwrap();
    let la = Layout::decode(&a, 4 * GIB / SECTOR).unwrap().unwrap();
    let lb = Layout::decode(&c, 4 * GIB / SECTOR).unwrap().unwrap();
    assert_eq!((la.generation, lb.generation), (3, 2));
}

/// The telemetry ring keeps working across a grow: a ring that has wrapped
/// keeps its newest records in order, takes new ones, and uses the new band
/// once it gets there. The segments of an earlier incarnation in the claimed
/// space do not come back.
#[test]
fn the_telemetry_ring_continues_across_a_grow() {
    let _g = lock();
    let m = MemDisk::sparse(32 * MIB);
    // A ring with another UUID, to be copied to where the grown band will be.
    let old_ring = {
        let s = MemDisk::sparse(96 * MIB);
        let (mut d, _) = Disk::open(s.device(), || [0x77; 16]).unwrap();
        let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
        for i in 0..20_000u64 {
            log.append(&mut d, 0, 5_000 + i, "stale", &[9u8; 100])
                .unwrap();
        }
        log.flush(&mut d).unwrap();
        s
    };
    let (mut d, _) = Disk::open(m.device(), || [0x11; 16]).unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, u64::MAX).unwrap();
    let cap1 = log.capacity_bytes();
    let per = urmqtt_store::telemetry::record_size("w", &[0u8; 120]) as u64;
    let n1 = cap1 / per * 5 / 2; // wraps twice
    for i in 0..n1 {
        log.append(&mut d, 0, i, "w", &[3u8; 120]).unwrap();
        if i % 200 == 0 {
            log.flush(&mut d).unwrap();
        }
    }
    log.flush(&mut d).unwrap();
    drop(log);
    drop(d);
    // The volume grows to 96 MiB; the other ring's bytes are where the new
    // telemetry band will be (past the old layout).
    m.grow_to(96 * MIB);
    {
        let mut src = old_ring.device();
        let mut dst = m.device();
        let mut buf = vec![0u8; MIB as usize];
        for mb in 32..96u64 {
            src.read(mb * MIB / SECTOR, &mut buf).unwrap();
            if buf.iter().any(|&b| b != 0) {
                dst.write(mb * MIB / SECTOR, &buf).unwrap();
            }
        }
        dst.flush().unwrap();
    }
    let (mut d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let g = d.grow(0).unwrap().expect("grows, all to telemetry");
    assert!(g.telemetry_sectors > 0 && g.db_sectors == 0);
    let (mut log, rec) = TelemetryLog::open(&mut d, NOW, u64::MAX).unwrap();
    assert!(log.capacity_bytes() > 2 * cap1, "the ring is larger");
    // Nothing of the other ring was taken for ours.
    let mut foreign = 0;
    log.scan(&mut d, 0, u64::MAX, |r| {
        if r.topic == "stale" {
            foreign += 1;
        }
    })
    .unwrap();
    assert_eq!(foreign, 0);
    assert!(rec.records > 0);
    let old_segments = rec.segments;
    // Keep writing: past the old band into the new one.
    let n2 = (log.capacity_bytes() / per) * 2;
    for i in 0..n2 {
        log.append(&mut d, 0, n1 + i, "w", &[3u8; 120]).unwrap();
        if i % 500 == 0 {
            log.flush(&mut d).unwrap();
        }
    }
    log.flush(&mut d).unwrap();
    drop(log);
    let (log, rec) = TelemetryLog::open(&mut d, NOW, u64::MAX).unwrap();
    let mut ts = Vec::new();
    log.scan(&mut d, 0, u64::MAX, |r| ts.push(r.ts_ms)).unwrap();
    assert_eq!(*ts.last().unwrap(), n1 + n2 - 1);
    // Oldest first, strictly increasing, and the newest records form one
    // contiguous run: nothing lost in the middle of what the ring retains.
    assert!(ts.windows(2).all(|w| w[0] < w[1]));
    let run = ts.windows(2).rev().take_while(|w| w[1] == w[0] + 1).count();
    assert!(run as u64 + 1 >= n2.min(ts.len() as u64) - 1, "run {run}");
    assert_eq!(rec.torn_tails, 0);
    // The new band was used: more segments than the old band holds.
    assert!(
        rec.segments > old_segments,
        "{} <= {old_segments}",
        rec.segments
    );
}

/// Online grow (ADR-143): the store is running when the disk gets larger.
/// The partition table steps run on the whole disk behind the window, the
/// window follows, the layout grows, the telemetry ring takes the new band,
/// and a power cut at any write of it leaves the old or the new layout.
#[test]
fn online_grow_while_the_store_runs() {
    let _g = lock();
    let m = image(64 * MIB);
    let mut b = boot(m.device(), true).unwrap();
    let pattern = pattern();
    b.disk
        .write_at(RegionKind::Wal, PATTERN_AT, &pattern)
        .unwrap();
    b.disk
        .set_file_size(FileKind::Wal, PATTERN_AT + pattern.len() as u64);
    b.disk.sync().unwrap();
    let (mut log, _) = TelemetryLog::open(&mut b.disk, NOW, RET).unwrap();
    for i in 0..400u64 {
        log.append(
            &mut b.disk,
            (i % 8) as usize,
            NOW * 1000 + i,
            "t/x",
            &i.to_le_bytes(),
        )
        .unwrap();
    }
    log.flush(&mut b.disk).unwrap();
    // Nothing changed: nothing to do.
    assert_eq!(b.disk.grow_online(50, || [9; 16]).unwrap(), None);
    // The volume is enlarged while everything is open.
    let old_total = b.disk.layout().total_sectors;
    m.grow_to(192 * MIB);
    let g = b
        .disk
        .grow_online(50, || [9; 16])
        .unwrap()
        .expect("grows online");
    assert!(g.new_total > old_total && g.telemetry_sectors > 0 && g.db_sectors > 0);
    assert_eq!(b.disk.layout().total_sectors, g.new_total);
    log.refresh_geometry(&b.disk).unwrap();
    // The ring takes records in its new band (more than the old one holds)
    // and the old ones are all still there.
    let per = urmqtt_store::telemetry::record_size("t/y", &[0u8; 100]) as u64;
    for i in 0..(log.capacity_bytes() / per) {
        log.append(&mut b.disk, 0, NOW * 1000 + 10_000 + i, "t/y", &[7u8; 100])
            .unwrap();
        if i % 300 == 0 {
            log.flush(&mut b.disk).unwrap();
        }
    }
    log.flush(&mut b.disk).unwrap();
    drop(log);
    drop(b);
    m.crash(|_| false);
    // A fresh boot (nothing left to grow) sees the grown layout and the data.
    let seen = look(&m).unwrap();
    assert_eq!(seen.layout.total_sectors, g.new_total);
    assert!(seen.pattern_ok);
    assert!(seen.records >= 400);
    let again = boot(m.device(), true).unwrap();
    assert!(again.grown.is_none());
    assert!(!again.steps.moved_backup && !again.steps.extended_partition);
}

/// A power cut at every write of the online grow ends in the old or the new
/// layout; the next boot finishes it.
#[test]
fn online_grow_survives_a_power_cut_at_every_write() {
    let _g = lock();
    let base = image(64 * MIB);
    {
        let mut b = boot(base.device(), true).unwrap();
        b.disk
            .write_at(RegionKind::Wal, PATTERN_AT, &pattern())
            .unwrap();
        b.disk
            .set_file_size(FileKind::Wal, PATTERN_AT + pattern().len() as u64);
        b.disk.sync().unwrap();
    }
    base.crash(|_| false);
    let old = look(&base).unwrap();
    for n in 1..=12u64 {
        for keep in [false, true] {
            let m = base.fork();
            let dev: Box<dyn BlockDevice> = Box::new(FaultDevice::new(
                m.device(),
                FaultSpec {
                    stop_after_writes: Some(n),
                    ..FaultSpec::default()
                },
            ));
            // Boot on the small disk first (no faults reached: no writes
            // are needed), then the volume grows and the cut falls inside
            // the online grow.
            let mut dev = dev;
            let mut c = 0u8;
            let (part, _) = gpt::prepare(dev.as_mut(), || {
                c += 1;
                [c; 16]
            })
            .unwrap();
            let window = Partition::new(dev, part.first_lba, part.sectors()).unwrap();
            let (mut disk, _) = Disk::open_with(Box::new(window), || [0; 16], 8).unwrap();
            m.grow_to(192 * MIB);
            let r = disk.grow_online(50, || [9; 16]);
            drop(disk);
            m.crash(|_| keep);
            let seen =
                look(&m).unwrap_or_else(|e| panic!("write {n} keep={keep}: unreadable: {e}"));
            assert!(seen.pattern_ok, "write {n}");
            if seen.layout.total_sectors == old.layout.total_sectors {
                assert_eq!(seen.layout, old.layout, "write {n}: the old layout");
            } else {
                assert!(r.is_ok() || n >= 10, "write {n}");
                assert_eq!(seen.layout.generation, old.layout.generation + 1);
            }
            let b = boot(m.device(), true).unwrap();
            assert!(
                b.disk.layout().total_sectors > old.layout.total_sectors,
                "write {n}"
            );
        }
    }
}
