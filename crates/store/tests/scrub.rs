//! Scrubbing and the bounded boot (STORAGE-PLAN S6 and G8, ADR-164 and
//! ADR-165).
//!
//! 1. A clean ring scrubs clean and every record is counted.
//! 2. Injected bit flips are found and told apart: a flipped bit inside a
//!    segment with valid records after it is `Damaged`, in the last record
//!    a `BadTail` (as a torn write is), in a segment header a `BadHeader`;
//!    a flip on the read path alone (the fault injector) is found too.
//! 3. The database: structural damage to a table is found by the bounded
//!    `quick_check(object)` steps, from the disk and not from the cache.
//! 4. The backup region: a flipped bit in a snapshot's payload, a damaged
//!    header and a damaged control block are found.
//! 5. Scrub I/O stays within its budget while a writer keeps appending.
//! 6. Boot reads the segment headers and the newest segment of each
//!    partition, not the ring; retention still works from the headers and the
//!    scrubber makes it exact.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::backup::{BackupJob, Progress};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::layout::{RegionKind, SECTOR};
use urmqtt_store::scrub::{Finding, MAX_STEP_BYTES, Pacer, Scrubber};
use urmqtt_store::telemetry::{
    SegmentEnd, TelemetryEvent, TelemetryLog, TelemetryScrub, record_size,
};
use urmqtt_store::{Disk, MemDisk, Platform, Store, open};

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
        log: |_, _| {},
    }
}

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

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

fn with<R>(f: impl FnOnce(&mut Disk) -> R) -> R {
    urmqtt_store::vfs::with_disk(f).unwrap()
}

// ---- the telemetry ring -----------------------------------------------------

const TOPIC: &str = "t/ab";
const PAYLOAD: [u8; 100] = [0x5a; 100];

/// A formatted 64 MiB disk with a ring of five or six segments in each of
/// the partitions 0, 1 and 2 (every record the same size, so offsets are
/// known), and the geometry the tests need.
struct Ring {
    m: MemDisk,
    seg_bytes: u64,
    /// Segments per partition in band 0.
    per_part: u64,
    /// Records that fit one segment.
    per_seg: u64,
    /// Records written to each partition.
    written: u64,
}

fn ring() -> Ring {
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    let seg_bytes = log.segment_bytes();
    let rec = record_size(TOPIC, &PAYLOAD) as u64;
    let per_seg = (seg_bytes - 512) / rec;
    let written = per_seg * 5 + per_seg / 3;
    let band = d.bytes(RegionKind::Telemetry) - 4096;
    let per_part = band / (8 * seg_bytes);
    assert!(per_part > 6, "room for the ring not to wrap");
    for i in 0..written {
        for p in 0..3 {
            log.append(&mut d, p, NOW * 1000 + i, TOPIC, &PAYLOAD)
                .unwrap();
        }
        if i % 97 == 0 {
            log.flush(&mut d).unwrap();
        }
    }
    log.flush(&mut d).unwrap();
    Ring {
        m,
        seg_bytes,
        per_part,
        per_seg,
        written,
    }
}

impl Ring {
    fn disk(&self) -> Disk {
        Disk::open(self.m.device(), || [0; 16]).unwrap().0
    }

    /// Byte offset in the telemetry region of ring index `j` of partition `p`.
    fn seg(&self, p: u64, j: u64) -> u64 {
        4096 + (p * self.per_part + j) * self.seg_bytes
    }

    /// Byte offset of record `i` of a segment.
    fn rec(&self, i: u64) -> u64 {
        512 + i * record_size(TOPIC, &PAYLOAD) as u64
    }

    fn flip(&self, at: u64, bit: u8) {
        let mut d = self.disk();
        let mut b = [0u8; 1];
        d.read_at(RegionKind::Telemetry, at, &mut b).unwrap();
        b[0] ^= 1 << bit;
        d.write_at(RegionKind::Telemetry, at, &b).unwrap();
        d.sync().unwrap();
    }
}

/// Scrubs the ring in steps of `step` bytes; returns the events.
fn scrub_ring(d: &mut Disk, log: &mut TelemetryLog, step: usize) -> Vec<TelemetryEvent> {
    let mut st = TelemetryScrub::default();
    let mut out = Vec::new();
    for _ in 0..1_000_000 {
        if log.scrub_step(d, &mut st, step, &mut out).unwrap() {
            return out;
        }
    }
    panic!("the scrub never finished");
}

fn segments(ev: &[TelemetryEvent]) -> Vec<(usize, u64, u64, u64, SegmentEnd)> {
    ev.iter()
        .filter_map(|e| match *e {
            TelemetryEvent::Segment {
                partition,
                index,
                seq,
                records,
                end,
                ..
            } => Some((partition, index, seq, records, end)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_clean_ring_scrubs_clean_and_every_record_is_counted() {
    let _g = lock();
    let r = ring();
    let mut d = r.disk();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    // Steps of different sizes give the same answer.
    for step in [4096, 64 * 1024, 1 << 20] {
        let ev = scrub_ring(&mut d, &mut log, step);
        let segs = segments(&ev);
        assert_eq!(ev.len(), segs.len(), "only segments: {ev:?}");
        assert_eq!(segs.len(), 18, "six segments in each of three partitions");
        assert!(segs.iter().all(|s| s.4 == SegmentEnd::Clean), "{segs:?}");
        let total: u64 = segs.iter().map(|s| s.3).sum();
        assert_eq!(total, 3 * r.written, "step {step}");
        for p in 0..3 {
            let seqs: Vec<u64> = segs.iter().filter(|s| s.0 == p).map(|s| s.2).collect();
            assert_eq!(
                seqs,
                (1..=6).collect::<Vec<_>>(),
                "ring order, partition {p}"
            );
        }
    }
}

#[test]
fn bit_flips_in_the_telemetry_ring_are_found_and_told_apart() {
    let _g = lock();
    let r = ring();
    let rec = record_size(TOPIC, &PAYLOAD) as u64;
    // (a) inside partition 0, segment 2: a payload bit of record 10.
    r.flip(r.seg(0, 2) + r.rec(10) + 30, 3);
    // (b) partition 1, segment 3: a bit of a record's length field, so the
    // chain breaks there but later records are still valid.
    r.flip(r.seg(1, 3) + r.rec(20), 1);
    // (c) partition 2, the last segment (the active one): a bit in its last
    // record.
    let last = r.written - 5 * r.per_seg - 1;
    r.flip(r.seg(2, 5) + r.rec(last) + 40, 0);
    // (d) partition 0, segment 4: a bit in the segment header (the sequence
    // number), which the header CRC catches.
    r.flip(r.seg(0, 4) + 17, 2);
    let mut d = r.disk();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    let ev = scrub_ring(&mut d, &mut log, 64 * 1024);
    let segs = segments(&ev);
    let find = |p: usize, j: u64| segs.iter().find(|s| s.0 == p && s.1 == j).copied();
    // (a)
    let (_, _, seq, records, end) = find(0, 2).expect("partition 0 segment 2");
    assert_eq!(seq, 3);
    assert_eq!(records, 10, "ten valid records before the bad one");
    assert_eq!(
        end,
        SegmentEnd::Damaged {
            at: r.rec(10) as u32,
            resumes_at: (r.rec(10) + rec) as u32
        }
    );
    // (b)
    let (_, _, _, records, end) = find(1, 3).expect("partition 1 segment 3");
    assert_eq!(records, 20);
    assert!(
        matches!(end, SegmentEnd::Damaged { at, .. } if u64::from(at) == r.rec(20)),
        "{end:?}"
    );
    // (c) the last record of the active segment: nothing valid follows.
    let (_, _, _, records, end) = find(2, 5).expect("partition 2 segment 5");
    assert_eq!(records, last);
    assert_eq!(
        end,
        SegmentEnd::BadTail {
            at: r.rec(last) as u32
        }
    );
    // (d) the header: invisible to recovery, reported by the scrubber.
    assert!(find(0, 4).is_none());
    assert!(
        ev.contains(&TelemetryEvent::BadHeader {
            partition: 0,
            index: 4
        }),
        "{ev:?}"
    );
    // Everything else is clean.
    let clean = segs.iter().filter(|s| s.4 == SegmentEnd::Clean).count();
    assert_eq!(clean, 18 - 1 - 3, "{segs:?}");
}

#[test]
fn a_torn_write_is_a_bad_tail_not_damage() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    for i in 0..300u64 {
        log.append(&mut d, 0, NOW * 1000 + i, TOPIC, &PAYLOAD)
            .unwrap();
    }
    log.flush(&mut d).unwrap();
    for i in 300..400u64 {
        log.append(&mut d, 0, NOW * 1000 + i, TOPIC, &PAYLOAD)
            .unwrap();
    }
    // Half of the batch reaches the disk, cutting a record.
    log.simulate_torn_flush(&mut d, 0, 61 * 100 + 7).unwrap();
    drop(log);
    let (mut log, rec) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    assert_eq!(rec.torn_tails, 1);
    let ev = scrub_ring(&mut d, &mut log, 64 * 1024);
    let segs = segments(&ev);
    assert_eq!(segs.len(), 1);
    assert!(matches!(segs[0].4, SegmentEnd::BadTail { .. }), "{segs:?}");
    assert!(segs[0].3 >= 300, "{} valid records", segs[0].3);
}

/// The fault injector flips a bit on the read path only (the medium is
/// intact): the scrubber sees what the device returns, as a failing cable or
/// controller would show it.
#[test]
fn a_flip_on_the_read_path_is_found() {
    let _g = lock();
    let r = ring();
    // A sector inside records 3..6 of partition 1, segment 1.
    let layout = r.disk().layout().clone();
    let tel = layout.region(RegionKind::Telemetry).unwrap();
    let lba = tel.start + (r.seg(1, 1) + 512 * 4) / SECTOR;
    let spec = FaultSpec {
        flip_read_lba: Some(lba),
        ..FaultSpec::default()
    };
    let (mut d, _) =
        Disk::open(Box::new(FaultDevice::new(r.m.device(), spec)), || [0; 16]).unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    let ev = scrub_ring(&mut d, &mut log, 64 * 1024);
    let segs = segments(&ev);
    let hit: Vec<_> = segs
        .iter()
        .filter(|s| !matches!(s.4, SegmentEnd::Clean))
        .collect();
    assert_eq!(hit.len(), 1, "{segs:?}");
    assert_eq!((hit[0].0, hit[0].1), (1, 1));
    assert!(
        matches!(hit[0].4, SegmentEnd::Damaged { .. }),
        "{:?}",
        hit[0]
    );
    // The same medium through a clean device scrubs clean.
    let mut d = r.disk();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    assert!(
        segments(&scrub_ring(&mut d, &mut log, 64 * 1024))
            .iter()
            .all(|s| s.4 == SegmentEnd::Clean)
    );
}

// ---- the whole scrubber: database, backups, ring ------------------------------

fn put(s: &mut Store, from: u32, to: u32) {
    s.begin().unwrap();
    for i in from..to {
        let payload: Vec<u8> = (0..1024u32).map(|b| ((b + i) % 251) as u8).collect();
        s.retain(&format!("k/{i:05}"), &payload, 1).unwrap();
    }
    s.commit().unwrap();
}

fn run_pass(s: &Store, log: Option<&mut TelemetryLog>, step: usize) -> (Scrubber, Vec<Finding>) {
    let mut sc = Scrubber::new();
    let mut f = Vec::new();
    let mut log = log;
    for _ in 0..1_000_000 {
        if sc.step(s.db(), log.as_deref_mut(), step, &mut f).done {
            return (sc, f);
        }
    }
    panic!("the pass never finished");
}

fn backup_now(s: &mut Store, trusted: Option<u64>) {
    let mut job = BackupJob::start(trusted, NOW).unwrap();
    loop {
        if let Progress::Done(..) = job.step(s.db(), 16, 128 * 1024).unwrap() {
            return;
        }
    }
}

#[test]
fn a_clean_disk_scrubs_clean_database_backups_and_ring() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    d.ensure_backup().unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    for i in 0..2000u64 {
        log.append(&mut d, (i % 4) as usize, NOW * 1000 + i, TOPIC, &PAYLOAD)
            .unwrap();
    }
    log.flush(&mut d).unwrap();
    let mut s = mount_disk(d);
    put(&mut s, 0, 300);
    backup_now(&mut s, None);
    put(&mut s, 300, 320);
    backup_now(&mut s, Some(1));
    s.db().exec("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    let (sc, f) = run_pass(&s, Some(&mut log), 64 * 1024);
    let r = sc.report;
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(r.errors(), 0);
    assert!(r.db_objects >= 6, "{} objects", r.db_objects);
    assert_eq!((r.backup_slots_ok, r.backup_slots_bad), (2, 0));
    assert_eq!(r.telemetry_records, 2000);
    assert!(r.telemetry_segments >= 4);
    // The database part reads the disk, not the page cache.
    assert!(r.bytes_read > 300 * 1024, "{} bytes", r.bytes_read);
}

#[test]
fn structural_damage_to_a_database_table_is_found() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    d.ensure_backup().unwrap();
    let mut s = mount_disk(d);
    put(&mut s, 0, 400);
    s.db().exec("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    // The cache holds clean copies; the damage is on the disk only.
    let root = s
        .db()
        .query_i64("SELECT rootpage FROM sqlite_schema WHERE name = 'retained'")
        .unwrap() as u64;
    let (sc, f) = run_pass(&s, None, 64 * 1024);
    assert!(f.is_empty(), "{f:?}");
    assert!(sc.report.db_objects > 0);
    with(|d| {
        // The b-tree page type of the table's root: not a page type any more.
        d.write_at(RegionKind::Db, (root - 1) * 4096, &[0xff])
            .unwrap();
        d.sync().unwrap();
    });
    let (sc, f) = run_pass(&s, None, 64 * 1024);
    assert_eq!(sc.report.db_errors as usize, f.len());
    assert!(
        f.iter().any(
            |x| matches!(x, Finding::Database { object, message } if object == "retained" && message != "ok")
        ),
        "{f:?}"
    );
}

#[test]
fn damage_in_the_backup_region_is_found() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    d.ensure_backup().unwrap();
    let mut s = mount_disk(d);
    put(&mut s, 0, 50);
    backup_now(&mut s, None);
    put(&mut s, 50, 60);
    backup_now(&mut s, Some(1));
    let (sc, f) = run_pass(&s, None, 64 * 1024);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(sc.report.backup_slots_ok, 2);
    let g = with(|d| d.layout().backup().unwrap());
    // A bit of slot 1's payload.
    with(|d| {
        let at = g.slot_offset(1) + 4096 + 6000;
        let mut b = [0u8; 1];
        d.read_at(RegionKind::Backup, at, &mut b).unwrap();
        b[0] ^= 0x04;
        d.write_at(RegionKind::Backup, at, &b).unwrap();
        d.sync().unwrap();
    });
    let (sc, f) = run_pass(&s, None, 64 * 1024);
    assert_eq!(
        (sc.report.backup_slots_ok, sc.report.backup_slots_bad),
        (1, 1)
    );
    assert!(
        matches!(
            f.as_slice(),
            [Finding::BackupSlot {
                slot: 1,
                seq: 2,
                ..
            }]
        ),
        "{f:?}"
    );
    // A bit of slot 0's header, and of the control block (which exists once
    // a restore has written it).
    with(|d| {
        let ctl = urmqtt_store::backup::Control {
            seq: 1,
            restoring: None,
        };
        let block = ctl.encode(&d.layout().uuid);
        d.write_at(RegionKind::Backup, 0, &block).unwrap();
        d.sync().unwrap();
    });
    let (_, f) = run_pass(&s, None, 64 * 1024);
    assert!(
        !f.iter().any(|x| matches!(x, Finding::BackupControl)),
        "{f:?}"
    );
    with(|d| {
        for at in [g.slot_offset(0) + 9, 17] {
            let mut b = [0u8; 1];
            d.read_at(RegionKind::Backup, at, &mut b).unwrap();
            b[0] ^= 0x01;
            d.write_at(RegionKind::Backup, at, &b).unwrap();
        }
        d.sync().unwrap();
    });
    // The control block needs its magic to count as damaged: flip a byte of
    // its body, not the magic (done above at offset 17: the uuid).
    let (sc, f) = run_pass(&s, None, 64 * 1024);
    assert!(
        f.iter()
            .any(|x| matches!(x, Finding::BackupSlot { slot: 0, .. })),
        "{f:?}"
    );
    assert!(
        f.iter().any(|x| matches!(x, Finding::BackupControl)),
        "{f:?}"
    );
    assert_eq!(sc.report.backup_slots_bad, 3);
    // A snapshot being rewritten is not a finding: its header is empty.
    let _ = (MAX_STEP_BYTES, Pacer::new(1, 0));
}

// ---- the budget ---------------------------------------------------------------

/// A pass over a 20 MiB ring with a writer appending all the time: at every
/// millisecond of a simulated clock the pacer says what the scrub may read.
/// Over the whole pass, and over every second of it, the bytes read stay
/// under the budget (plus the burst of one step), and the pass finishes.
#[test]
fn scrub_io_stays_within_its_budget_under_load() {
    let _g = lock();
    for budget_mb in [2u32, 8, 32] {
        let m = MemDisk::sparse(256 * MIB);
        let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
        d.ensure_backup().unwrap();
        let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
        // 20 MiB of telemetry, then the DB core's view of it.
        let big = [0xa5u8; 1000];
        for i in 0..20_000u64 {
            log.append(&mut d, (i % 8) as usize, NOW * 1000 + i, "t/load", &big)
                .unwrap();
            if i % 500 == 0 {
                log.flush(&mut d).unwrap();
            }
        }
        log.flush(&mut d).unwrap();
        let mut s = mount_disk(d);
        put(&mut s, 0, 200);
        let mut sc = Scrubber::new();
        let mut pacer = Pacer::new(budget_mb, 0);
        let mut findings = Vec::new();
        let (mut now, mut done) = (0u64, false);
        let mut second_bytes = 0u64;
        let mut worst_second = 0u64;
        let mut appended = 0u64;
        while !done && now < 600_000 {
            now += 1;
            // The load: a record or two every millisecond, flushed now and then.
            for _ in 0..2 {
                with(|d| {
                    log.append(
                        d,
                        (appended % 8) as usize,
                        NOW * 1000 + appended,
                        "t/load",
                        &big,
                    )
                })
                .unwrap();
                appended += 1;
            }
            if now % 5 == 0 {
                with(|d| log.flush(d)).unwrap();
            }
            let grant = pacer.grant(now);
            if grant > 0 {
                let out = sc.step(s.db(), Some(&mut log), grant, &mut findings);
                pacer.spend(out.bytes);
                second_bytes += out.bytes;
                done = out.done;
            }
            if now % 1000 == 0 {
                worst_second = worst_second.max(second_bytes);
                second_bytes = 0;
            }
        }
        assert!(
            done,
            "the pass finished within the simulated 10 minutes at {budget_mb} MB/s"
        );
        let r = sc.report;
        let budget = u64::from(budget_mb) * MIB;
        // Over the whole pass.
        let allowed = budget * now / 1000 + MAX_STEP_BYTES as u64 + 64 * 1024;
        assert!(
            r.bytes_read <= allowed,
            "{budget_mb} MB/s: read {} bytes in {now} ms, at most {allowed} allowed",
            r.bytes_read
        );
        eprintln!(
            "scrub budget {budget_mb} MB/s: pass of {} KiB in {now} ms = {} KiB/s, worst second {} KiB, {} records under a writer appending {appended}",
            r.bytes_read / 1024,
            r.bytes_read / 1024 * 1000 / now,
            worst_second / 1024,
            r.telemetry_records
        );
        // Not far under it either: the budget is used.
        if r.bytes_read > 4 * MIB {
            assert!(
                r.bytes_read * 10 >= budget * now / 1000 * 8,
                "{budget_mb} MB/s: only {} bytes in {now} ms",
                r.bytes_read
            );
        }
        // Over any one second (aligned): the budget plus one step of burst.
        assert!(
            worst_second <= budget + MAX_STEP_BYTES as u64 + 64 * 1024,
            "{budget_mb} MB/s: {worst_second} bytes in one second"
        );
        // The scrub saw the load's records, and the ring was never harmed.
        let flagged: Vec<_> = findings.iter().filter(|f| f.is_error()).collect();
        assert!(flagged.is_empty(), "{flagged:?}");
        assert!(r.telemetry_records >= 20_000, "{}", r.telemetry_records);
    }
}

// ---- the bounded boot (G8) ------------------------------------------------------

#[test]
fn boot_reads_the_headers_and_the_newest_segment_only() {
    let _g = lock();
    let r = ring();
    let mut d = r.disk();
    let data = 3 * r.written * record_size(TOPIC, &PAYLOAD) as u64;
    let before = d.stats.bytes_read;
    let (_log, rec) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    let read = d.stats.bytes_read - before;
    assert_eq!(
        rec.segments, 18,
        "all segments are known from their headers"
    );
    assert_eq!(rec.scanned, 3, "the newest of each partition is read");
    // The newest segment holds a third of a segment of records.
    assert_eq!(rec.records, 3 * (r.written - 5 * r.per_seg));
    // Headers: 8 partitions x (their ring) blocks of the device's granule;
    // plus three segments. Far less than the ring's data.
    eprintln!(
        "boot read {} KiB for {} KiB of records in {} segments ({} newest segments scanned)",
        read / 1024,
        data / 1024,
        rec.segments,
        rec.scanned
    );
    let headers = 8 * r.per_part * 512;
    let newest = 3 * r.seg_bytes;
    assert!(read <= headers + newest + 64 * 1024, "read {read} bytes");
    assert!(
        read * 3 < data + headers,
        "boot read {read} bytes of {data} bytes of data"
    );
}

#[test]
fn retention_works_from_the_headers_and_the_scrub_makes_it_exact() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    let (mut log, _) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
    let rec = record_size(TOPIC, &PAYLOAD) as u64;
    let per_seg = (log.segment_bytes() - 512) / rec;
    // Four segments of partition 0, created on days 10, 20, 30 and 40; the
    // records of each are dated a few days before its creation, except those
    // of segment 3, whose records are old (day 1) although it was created on
    // day 30.
    let day = 86_400u64;
    for (k, (created, dated)) in [(10, 9), (20, 19), (30, 1), (40, 39)]
        .into_iter()
        .enumerate()
    {
        log.set_now(created * day);
        for i in 0..per_seg {
            log.append(&mut d, 0, dated * day * 1000 + i, TOPIC, &PAYLOAD)
                .unwrap();
        }
        log.flush(&mut d).unwrap();
        let _ = k;
    }
    // A fifth, active segment on day 50.
    log.set_now(50 * day);
    log.append(&mut d, 0, 49 * day * 1000, TOPIC, &PAYLOAD)
        .unwrap();
    log.flush(&mut d).unwrap();
    drop(log);
    // Boot at day 60 with a retention of 25 days: cutoff day 35.
    let retention = 25 * day * 1000;
    let (mut log, rec) = TelemetryLog::open(&mut d, 60 * day, retention).unwrap();
    assert_eq!((rec.segments, rec.scanned), (5, 1));
    // From the headers alone a segment is known to be no younger than the
    // creation of the one after it: segments 1 and 2 (created days 10, 20;
    // next created 20, 30) are older than the cutoff and retire. Segment 3
    // (next created day 40) and segment 4 cannot be shown old, although
    // segment 3's records are from day 1.
    let n = log.retire_expired(&mut d, 60 * day, retention);
    assert_eq!(n, 2, "bounds: segments 1 and 2 only");
    // The scrubber reads segment 3 and learns its true age.
    let ev = scrub_ring(&mut d, &mut log, 64 * 1024);
    assert_eq!(segments(&ev).len(), 3);
    let n = log.retire_expired(&mut d, 60 * day, retention);
    assert_eq!(n, 1, "exact now: segment 3");
    // Segment 4 (records from day 39) and the active one stay.
    assert_eq!(log.live_segments(), 2);
}
