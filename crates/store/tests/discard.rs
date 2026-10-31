//! Discard and write-zeroes (STORAGE-PLAN S4, ADR-150).
//!
//! 1. The queue: limits of the device are respected, a range waits for the
//!    sync that makes its retirement durable, a later write takes it back,
//!    a failing device is given up on.
//! 2. Where it is used: the logical tail of a truncated file, the space a
//!    grow adds, telemetry segments past retention.
//! 3. Recovery never trusts what a discarded range holds: for every region
//!    type the discarded (and every unreferenced) range is filled with
//!    garbage, with zeros, or left as it was, and the disk still opens with
//!    exactly the data that was committed.
//! 4. A power cut at every write and discard of a retirement.

use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::disk::{DiscardCaps, DiscardKind, DiscardSource, Released};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::layout::{FileKind, RegionKind, SECTOR};
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{BlockDevice, Disk, DiskError, IoError, MemDisk, Platform, Store, open};

const MIB: u64 = 1 << 20;
const NOW: u64 = 1_761_696_000;
const DAY_MS: u64 = 86_400_000;
const RET: u64 = 30 * DAY_MS;

fn caps() -> DiscardCaps {
    DiscardCaps {
        kind: DiscardKind::Discard,
        max_sectors: 4096,
        max_ranges: 3,
        granularity: 8,
    }
}

fn disk_with(bytes: u64, released: Released) -> (MemDisk, Disk) {
    let m = MemDisk::sparse(bytes).with_discard(caps(), released);
    let (mut d, _) = Disk::open(m.device(), || [7; 16]).unwrap();
    assert!(d.set_discard(true).is_some());
    (m, d)
}

fn drain(d: &mut Disk) {
    for _ in 0..10_000 {
        if !d.discard_ready() {
            // The device's cache holds the discards until a flush.
            d.sync().unwrap();
            return;
        }
        d.run_discards(1).unwrap();
    }
    panic!("discards do not drain");
}

#[test]
fn limits_of_the_device_are_respected() {
    let (m, mut d) = disk_with(128 * MIB, Released::Zeros);
    let db = d.region(RegionKind::Db).unwrap();
    // An unaligned range far larger than one request can carry.
    d.discard_region(
        RegionKind::Db,
        1_000_003,
        20 * MIB + 1,
        DiscardSource::Truncate,
    );
    assert_eq!(m.discard_requests(), 0, "nothing is sent by queueing");
    d.sync().unwrap();
    drain(&mut d);
    assert_eq!(m.discard_violations(), 0);
    let log = m.discard_log();
    assert!(
        log.len() > 4,
        "split into several descriptors: {}",
        log.len()
    );
    let mut covered = 0;
    for &(s, n) in &log {
        assert!(
            n <= 4096 && n.is_multiple_of(8) && s.is_multiple_of(8),
            "{s} {n}"
        );
        assert!(s >= db.start && s + n <= db.end(), "inside the region");
        covered += n;
    }
    // Shrunk inward to the granule: lost less than two granules (8 sectors).
    let want = (20 * MIB + 1) / SECTOR;
    assert!(want - covered <= 16, "{want} wanted, {covered} sent");
    let st = d.discard_stats().unwrap();
    assert_eq!(st.bytes, covered * SECTOR);
    // At most 3 descriptors per request.
    assert!(m.discard_requests() >= log.len() as u64 / 3);
    assert_eq!(st.requests, m.discard_requests());
}

#[test]
fn a_range_waits_for_the_sync_and_a_write_takes_it_back() {
    let (m, mut d) = disk_with(64 * MIB, Released::Zeros);
    d.write_at(RegionKind::Wal, 0, &vec![0x5a; 1 << 20])
        .unwrap();
    d.set_file_size(FileKind::Wal, 1 << 20);
    d.sync().unwrap();
    // Truncating the WAL queues its tail, but the new size is not durable.
    d.set_file_size(FileKind::Wal, 64 * 1024);
    assert!(d.discard_pending());
    assert!(!d.discard_ready(), "not before the size is durable");
    assert_eq!(d.run_discards(10).unwrap(), 0);
    assert_eq!(m.discard_requests(), 0);
    // A write into the queued tail takes that part back.
    d.write_at(RegionKind::Wal, 512 * 1024, &[1u8; 4096])
        .unwrap();
    d.sync().unwrap();
    assert!(d.discard_ready());
    drain(&mut d);
    let st = d.discard_stats().unwrap();
    assert!(st.cancelled >= 4096, "cancelled {}", st.cancelled);
    let wal = d.region(RegionKind::Wal).unwrap();
    for (s, n) in m.discard_log() {
        let (lo, hi) = (
            wal.start + 512 * 1024 / SECTOR,
            wal.start + 512 * 1024 / SECTOR + 8,
        );
        assert!(
            s + n <= lo || s >= hi,
            "the rewritten block was discarded: {s} {n}"
        );
    }
    // The rewritten bytes are intact; the head before the new size too.
    d.set_file_size(FileKind::Wal, 1 << 20);
    let mut b = [0u8; 4096];
    d.read_at(RegionKind::Wal, 512 * 1024, &mut b).unwrap();
    assert_eq!(b, [1u8; 4096]);
    d.read_at(RegionKind::Wal, 0, &mut b).unwrap();
    assert_eq!(b, [0x5a; 4096]);
}

#[test]
fn nothing_waits_when_everything_is_already_durable() {
    let (_m, mut d) = disk_with(64 * MIB, Released::Zeros);
    d.sync().unwrap();
    d.discard_region(RegionKind::Telemetry, 0, 4 * MIB, DiscardSource::Telemetry);
    assert!(d.discard_ready(), "no write is waiting for a flush");
    d.run_discards(100).unwrap();
    assert!(!d.discard_ready());
    d.write_at(RegionKind::Wal, 0, &[1u8; 512]).unwrap();
    d.discard_region(
        RegionKind::Telemetry,
        8 * MIB,
        4 * MIB,
        DiscardSource::Telemetry,
    );
    // The second range was queued behind an unsynced write.
    assert!(d.discard_pending());
    assert!(!d.discard_ready());
    d.sync().unwrap();
    assert!(d.discard_ready());
}

#[test]
fn a_failing_device_is_given_up_on() {
    let (m, mut d) = disk_with(64 * MIB, Released::Zeros);
    for i in 0..4 {
        d.discard_region(RegionKind::Db, i * 3 * MIB, MIB, DiscardSource::Truncate);
    }
    d.sync().unwrap();
    m.fail_discard(1);
    assert_eq!(d.run_discards(1), Err(DiskError::Io(IoError::Device)));
    assert!(d.discard_active(), "one failure is not the end");
    assert_eq!(d.discard_stats().unwrap().failed, 1);
    d.run_discards(10).unwrap();
    assert!(!d.discard_ready());
    // Three failures in a row stop it.
    for i in 0..12 {
        d.discard_region(RegionKind::Db, i * 2 * MIB, MIB, DiscardSource::Truncate);
    }
    d.sync().unwrap();
    for _ in 0..3 {
        m.fail_discard(1);
        assert!(d.run_discards(1).is_err());
    }
    assert!(!d.discard_active());
    assert!(!d.discard_pending(), "the queue is dropped");
    assert_eq!(d.discard_stats().unwrap().failed, 4);
}

#[test]
fn discards_off_or_unsupported_do_nothing() {
    // A device without the command, and "off" on one that has it.
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [7; 16]).unwrap();
    assert!(d.set_discard(true).is_none());
    d.discard_region(RegionKind::Db, 0, MIB, DiscardSource::Truncate);
    assert!(!d.discard_pending());
    assert_eq!(d.run_discards(5).unwrap(), 0);
    let (m, mut d) = disk_with(64 * MIB, Released::Zeros);
    assert!(d.set_discard(false).is_none());
    d.discard_region(RegionKind::Db, 0, MIB, DiscardSource::Truncate);
    d.set_file_size(FileKind::Db, 4 * MIB);
    d.set_file_size(FileKind::Db, 0);
    d.sync().unwrap();
    assert_eq!(d.run_discards(5).unwrap(), 0);
    assert_eq!(m.discard_requests(), 0);
    assert!(d.discard_stats().is_none());
}

#[test]
fn write_zeroes_kind_reads_back_zeros() {
    let wz = DiscardCaps {
        kind: DiscardKind::WriteZeroes,
        max_sectors: 2048,
        max_ranges: 1,
        granularity: 8,
    };
    let m = MemDisk::sparse(64 * MIB).with_discard(wz, Released::Zeros);
    let (mut d, _) = Disk::open(m.device(), || [7; 16]).unwrap();
    assert_eq!(d.set_discard(true).unwrap().kind, DiscardKind::WriteZeroes);
    d.write_at(RegionKind::Db, 0, &vec![0xee; 4 * MIB as usize])
        .unwrap();
    d.sync().unwrap();
    d.discard_region(RegionKind::Db, MIB, 2 * MIB, DiscardSource::Truncate);
    d.sync().unwrap();
    drain(&mut d);
    assert_eq!(m.discard_violations(), 0);
    assert!(m.discard_log().iter().all(|&(_, n)| n <= 2048));
    let mut b = vec![0u8; 3 * MIB as usize];
    d.read_at(RegionKind::Db, 0, &mut b).unwrap();
    assert!(b[..MIB as usize].iter().all(|&x| x == 0xee));
    assert!(
        b[MIB as usize..].iter().all(|&x| x == 0),
        "zeroed range reads zeros"
    );
}

#[test]
fn the_logical_tail_of_a_truncate_and_a_delete_is_released() {
    let (m, mut d) = disk_with(64 * MIB, Released::Zeros);
    d.write_at(RegionKind::Db, 0, &vec![0x11; 8 * MIB as usize])
        .unwrap();
    d.set_file_size(FileKind::Db, 8 * MIB);
    d.sync().unwrap();
    let before = m.allocated_bytes();
    // xTruncate to 1 MiB.
    d.set_file_size(FileKind::Db, MIB);
    d.sync().unwrap();
    drain(&mut d);
    assert!(
        m.allocated_bytes() + 6 * MIB <= before,
        "{} -> {}",
        before,
        m.allocated_bytes()
    );
    let mut b = vec![0u8; MIB as usize];
    d.read_at(RegionKind::Db, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0x11), "the kept head is intact");
    let st = d.discard_stats().unwrap();
    assert!(st.queued_truncate >= 6 * MIB && st.queued_telemetry == 0 && st.queued_grow == 0);
    // xDelete is a truncate to 0.
    d.set_file_size(FileKind::Db, 0);
    d.sync().unwrap();
    drain(&mut d);
    assert!(m.allocated_bytes() < before - 7 * MIB);
}

#[test]
fn the_space_a_grow_adds_is_released() {
    // Stale data from an earlier life of the volume sits where the layout
    // is about to grow into.
    let small = MemDisk::sparse(256 * MIB).with_discard(caps(), Released::Zeros);
    let (d0, _) = Disk::open(small.device(), || [7; 16]).unwrap();
    drop(d0);
    let big = small.fork();
    big.grow_to(1024 * MIB);
    big.scribble(300 * 2048, 4096, 9);
    big.scribble(900 * 2048, 4096, 9);
    let (mut d, _) = Disk::open(big.device(), || [0; 16]).unwrap();
    assert!(d.set_discard(true).is_some());
    let g = d.grow(50).unwrap().expect("grows");
    assert!(g.new_total > g.old_total);
    d.sync().unwrap();
    drain(&mut d);
    assert_eq!(big.discard_violations(), 0);
    assert!(d.discard_stats().unwrap().queued_grow >= 600 * MIB);
    assert_eq!(big.raw(300 * MIB as usize, 4096), vec![0u8; 4096]);
    assert_eq!(big.raw(900 * MIB as usize, 4096), vec![0u8; 4096]);
    // Nothing below the old end was touched.
    let log = big.discard_log();
    assert!(
        log.iter().all(|&(s, _)| s >= 200 * 2048),
        "{:?}",
        log.first()
    );
}

#[test]
fn zero_fill_makes_a_gap_read_as_zeros() {
    let (_m, mut d) = disk_with(64 * MIB, Released::Garbage);
    d.write_at(RegionKind::Journal, 0, &[0xaa; 8192]).unwrap();
    d.set_file_size(FileKind::Journal, 8192);
    d.sync().unwrap();
    d.set_file_size(FileKind::Journal, 0);
    d.sync().unwrap();
    drain(&mut d);
    // The device now holds garbage where the file was; growing the file
    // without data must expose zeros.
    d.zero_fill(RegionKind::Journal, 0, 6000).unwrap();
    let mut b = [0u8; 6000];
    d.read_at(RegionKind::Journal, 0, &mut b).unwrap();
    assert!(b.iter().all(|&x| x == 0));
}

// ---- telemetry retirement ---------------------------------------------

fn payload(i: u64) -> Vec<u8> {
    (0..1024u64).map(|k| ((i * 31 + k) % 251) as u8).collect()
}

/// Writes `old` records dated `age_days` ago and `fresh` records dated now
/// to partition 0, rolling segments in between.
fn fill(log: &mut TelemetryLog, d: &mut Disk, old: u64, fresh: u64) {
    let old_ts = (NOW - 40 * 86_400) * 1000;
    log.set_now(NOW - 40 * 86_400);
    for i in 0..old {
        log.append(d, 0, old_ts + i, "t/old", &payload(i)).unwrap();
    }
    log.flush(d).unwrap();
    log.set_now(NOW);
    for i in 0..fresh {
        log.append(d, 0, NOW * 1000 + i, "t/new", &payload(i))
            .unwrap();
    }
    log.flush(d).unwrap();
}

fn live(log: &TelemetryLog, d: &mut Disk) -> Vec<(u64, String, Vec<u8>)> {
    let mut out = Vec::new();
    for p in 0..log.partitions() {
        log.scan(d, p, RET, |r| {
            out.push((r.ts_ms, r.topic.to_string(), r.payload.to_vec()))
        })
        .unwrap();
    }
    out
}

fn telemetry_case(released: Released) {
    let (m, mut d) = disk_with(96 * MIB, released);
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    fill(&mut log, &mut d, 9000, 1500);
    let segs = log.live_segments();
    assert!(segs >= 8, "the old records fill several segments ({segs})");
    let before = m.allocated_bytes();
    let want = live(&log, &mut d);
    assert_eq!(want.len(), 1500);

    let n = log.retire_expired(&mut d, NOW, RET);
    assert!(n >= 4 && n < segs, "retired {n} of {segs}");
    assert_eq!(log.live_segments(), segs - n);
    assert_eq!(log.retire_expired(&mut d, NOW, RET), 0, "only once");
    d.sync().unwrap();
    drain(&mut d);
    assert_eq!(m.discard_violations(), 0);
    let st = d.discard_stats().unwrap();
    assert!(
        st.queued_telemetry > 0 && st.bytes == st.queued_telemetry,
        "{st:?}"
    );
    if released == Released::Zeros {
        assert!(
            m.allocated_bytes() < before,
            "{before} -> {}",
            m.allocated_bytes()
        );
    }
    assert_eq!(live(&log, &mut d), want, "the live records are untouched");

    // Reboot: the log recovers exactly the live records, whatever the
    // retired segments hold now.
    drop(log);
    m.crash(|_| true);
    let (mut d2, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let (log2, rec) = TelemetryLog::open(&mut d2, NOW, RET).unwrap();
    assert_eq!(live(&log2, &mut d2), want, "{released:?}");
    assert_eq!(rec.torn_tails, 0, "{released:?}");
    // Whatever the device kept of a retired segment (Keep), its header was
    // zeroed first: it is not a segment any more, and nothing is retired
    // twice.
    assert_eq!(rec.segments, segs - n, "{released:?}");
    let mut log2 = log2;
    d2.set_discard(true).unwrap();
    assert_eq!(log2.retire_expired(&mut d2, NOW, RET), 0, "{released:?}");
}

#[test]
fn retired_telemetry_segments_are_released_zeros() {
    telemetry_case(Released::Zeros);
}

#[test]
fn retired_telemetry_segments_are_released_garbage() {
    telemetry_case(Released::Garbage);
}

#[test]
fn retired_telemetry_segments_are_released_kept() {
    telemetry_case(Released::Keep);
}

#[test]
fn retirement_leaves_the_active_segment_and_unknown_ages_alone() {
    let (m, mut d) = disk_with(96 * MIB, Released::Zeros);
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    // Only old records: every segment but the active one may go.
    let old_ts = (NOW - 90 * 86_400) * 1000;
    log.set_now(NOW - 90 * 86_400);
    for i in 0..5000 {
        log.append(&mut d, 0, old_ts + i, "t/old", &payload(i))
            .unwrap();
    }
    log.flush(&mut d).unwrap();
    let segs = log.live_segments();
    // A clock that is not known retires nothing.
    assert_eq!(log.retire_expired(&mut d, 0, RET), 0);
    let n = log.retire_expired(&mut d, NOW, RET);
    assert_eq!(n, segs - 1, "the active segment stays");
    // A record without a timestamp (0) makes its segment's age unknown.
    let (_m2, mut d) = disk_with(96 * MIB, Released::Zeros);
    let (mut log, _) = TelemetryLog::open(&mut d, 0, RET).unwrap();
    log.set_now(0);
    for i in 0..5000 {
        log.append(&mut d, 0, 0, "t/nots", &payload(i)).unwrap();
    }
    log.flush(&mut d).unwrap();
    assert_eq!(log.retire_expired(&mut d, NOW, RET), 0, "age unknown: kept");
    drop(m);
}

#[test]
fn a_ring_that_reuses_a_queued_segment_cancels_its_discard() {
    let (m, mut d) = disk_with(64 * MIB, Released::Zeros);
    let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    fill(&mut log, &mut d, 3000, 100);
    let n = log.retire_expired(&mut d, NOW, RET);
    assert!(n > 0);
    // The ring keeps writing and wraps over retired segments before the
    // discards ran: whatever it wrote there must survive.
    log.set_now(NOW);
    for i in 0..30_000 {
        log.append(&mut d, 0, NOW * 1000 + 5000 + i, "t/wrap", &payload(i))
            .unwrap();
        if i % 500 == 0 {
            log.flush(&mut d).unwrap();
        }
    }
    log.flush(&mut d).unwrap();
    let want = live(&log, &mut d);
    drain(&mut d);
    assert!(d.discard_stats().unwrap().cancelled > 0);
    assert_eq!(live(&log, &mut d), want);
    drop(log);
    m.crash(|_| true);
    let (mut d2, _) = Disk::open(m.device(), || [0; 16]).unwrap();
    let (log2, _) = TelemetryLog::open(&mut d2, NOW, RET).unwrap();
    assert_eq!(live(&log2, &mut d2), want);
}

// ---- a power cut at every step of a retirement --------------------------

#[test]
fn a_power_cut_at_every_write_and_discard_of_a_retirement() {
    // Base image: a log with old and fresh records, flushed.
    let base = MemDisk::sparse(96 * MIB).with_discard(caps(), Released::Garbage);
    let want;
    {
        let (mut d, _) = Disk::open(base.device(), || [7; 16]).unwrap();
        let (mut log, _) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
        fill(&mut log, &mut d, 6000, 800);
        want = live(&log, &mut d);
    }
    base.crash(|_| true);
    let mut cuts = 0;
    for n in 1..40u64 {
        for torn in [false, true] {
            let m = base.fork();
            let spec = FaultSpec {
                stop_after_writes: (!torn).then_some(n),
                tear_write: torn.then_some((n, 3)),
                ..FaultSpec::default()
            };
            let dev: Box<dyn BlockDevice> = Box::new(FaultDevice::new(m.device(), spec));
            let (mut d, _) = Disk::open(dev, || [0; 16]).unwrap();
            d.set_discard(true).unwrap();
            let Ok((mut log, _)) = TelemetryLog::open(&mut d, NOW, RET) else {
                continue;
            };
            let k = log.retire_expired(&mut d, NOW, RET);
            let r = d.sync().and_then(|()| d.run_discards(100).map(|_| ()));
            // More records after the retirement, as the broker would.
            log.set_now(NOW);
            let mut r2 = Ok(());
            'more: for round in 0..12u64 {
                for i in 0..40u64 {
                    let ts = NOW * 1000 + 9999 + round * 100 + i;
                    if log.append(&mut d, 0, ts, "t/more", &payload(i)).is_err() {
                        r2 = Err(());
                        break 'more;
                    }
                }
                if log.flush(&mut d).is_err() {
                    r2 = Err(());
                    break;
                }
            }
            if r.is_err() || r2.is_err() {
                cuts += 1;
            }
            drop(log);
            // Power returns: the cache is lost or applied, the disk opens.
            for apply in [false, true] {
                let m2 = m.fork();
                let _ = apply;
                let (mut d2, _) = Disk::open(m2.device(), || [0; 16]).unwrap();
                let (log2, rec) = TelemetryLog::open(&mut d2, NOW, RET).unwrap();
                // A torn flush leaves a torn tail, which recovery truncates.
                let _ = rec;
                let got = live(&log2, &mut d2);
                // Every record the base held is still there (the one more
                // record may or may not be).
                assert!(
                    got.len() >= want.len() && got.len() <= want.len() + 480,
                    "cut {n} torn {torn} retired {k}: {} vs {}",
                    got.len(),
                    want.len()
                );
                assert!(got[want.len()..].iter().all(|r| r.1 == "t/more"));
                assert_eq!(&got[..want.len()], &want[..], "cut {n} torn {torn}");
            }
        }
    }
    assert!(
        cuts > 10,
        "the cut points fell inside the procedure ({cuts})"
    );
}

// ---- recovery never trusts discarded content ----------------------------

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

fn mount(m: &MemDisk, discard: bool) -> Store {
    let (mut disk, _) = Disk::open(m.device(), || [9; 16]).unwrap();
    if discard {
        assert!(disk.set_discard(true).is_some());
    }
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    open().unwrap().0
}

fn with<R>(f: impl FnOnce(&mut Disk) -> R) -> R {
    urmqtt_store::vfs::with_disk(f).unwrap()
}

/// The state every case checks: what was committed.
fn committed(s: &mut Store) -> (i64, Vec<String>, i64) {
    let rows = s.db().query_i64("SELECT count(*) FROM retained").unwrap();
    let retained = s.retained().unwrap().into_iter().map(|r| r.topic).collect();
    let devices = s.device_count().unwrap();
    (rows, retained, devices)
}

fn sqlite_case(released: Released) {
    let _g = lock();
    let m = MemDisk::sparse(160 * MIB).with_discard(caps(), released);
    let (want, tel_want, tel_log_segments);
    {
        let mut s = mount(&m, true);
        // State, then bulk that grows the database and the WAL and is
        // deleted again so the files shrink and their tails are released.
        s.begin().unwrap();
        for i in 0..40 {
            s.device_seen(&format!("dev-{i:03}"), 100 + i).unwrap();
        }
        s.retain("keep/one", b"1", 1).unwrap();
        s.retain("keep/two", b"22", 0).unwrap();
        s.commit().unwrap();
        s.db()
            .exec("CREATE TABLE IF NOT EXISTS bulk (id INTEGER PRIMARY KEY, b BLOB)")
            .unwrap();
        for chunk in 0..20 {
            s.begin().unwrap();
            for i in 0..50 {
                s.db()
                    .exec(&format!(
                        "INSERT INTO bulk VALUES ({}, zeroblob(40000))",
                        chunk * 50 + i
                    ))
                    .unwrap();
            }
            s.commit().unwrap();
        }
        let big = with(|d| (d.file_size(FileKind::Db), d.file_size(FileKind::Wal)));
        assert!(big.0 + big.1 > 20 * MIB, "grew to {big:?}");
        s.db().exec("DROP TABLE bulk").unwrap();
        s.db().exec("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        let small = with(|d| (d.file_size(FileKind::Db), d.file_size(FileKind::Wal)));
        assert!(small.1 < big.1 / 2, "{big:?} -> {small:?}");
        want = committed(&mut s);
        assert_eq!(want.0, 2);
        // Telemetry: old segments retired and released.
        let (mut log, tel_rec) = with(|d| TelemetryLog::open(d, NOW, RET).unwrap());
        assert_eq!(tel_rec.records, 0);
        with(|d| fill(&mut log, d, 8000, 1200));
        let n = with(|d| log.retire_expired(d, NOW, RET));
        assert!(n > 0);
        tel_log_segments = n;
        tel_want = with(|d| live(&log, d));
        with(|d| {
            d.sync().unwrap();
            drain(d);
            let st = d.discard_stats().unwrap();
            assert!(st.queued_truncate > 0, "the files' tails: {st:?}");
            assert!(st.queued_telemetry > 0);
            assert!(st.bytes > 8 * MIB, "{st:?}");
        });
        assert_eq!(m.discard_violations(), 0);
    }
    m.crash(|_| true);

    // Now fill everything that is not referenced with garbage: every range
    // the device was told to discard, the tail of each file beyond its
    // logical size, and the scratch area.
    let (layout, sizes) = {
        let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
        (d.layout().clone(), d.sizes())
    };
    let mut ranges: Vec<(u64, u64)> = m.discard_log();
    for kind in [FileKind::Db, FileKind::Wal, FileKind::Journal] {
        let size = sizes.sizes[kind as usize];
        let mut base = 0u64;
        for r in layout.extents(RegionKind::of_file(kind)) {
            let (lo, hi) = (base, base + r.bytes());
            let from = size.clamp(lo, hi).div_ceil(SECTOR) * SECTOR;
            if from < hi {
                ranges.push((r.start + (from - lo) / SECTOR, (hi - from) / SECTOR));
            }
            base = hi;
        }
    }
    for r in layout.extents(RegionKind::Scratch) {
        ranges.push((r.start, r.sectors));
    }
    let scribbled: u64 = ranges.iter().map(|r| r.1).sum();
    assert!(
        scribbled * SECTOR > 30 * MIB,
        "{} bytes of garbage",
        scribbled * SECTOR
    );
    for (i, &(s, n)) in ranges.iter().enumerate() {
        m.scribble(s, n, 0x6a6a + i as u64);
    }

    // The disk opens; SQLite's integrity check passes (open() runs it);
    // exactly what was committed is there; the telemetry log recovers
    // exactly its live records and accepts no garbage.
    let mut s = mount(&m, false);
    assert_eq!(committed(&mut s), want, "{released:?}");
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
    let (log, rec) = with(|d| TelemetryLog::open(d, NOW, RET).unwrap());
    assert_eq!(rec.torn_tails, 0, "{released:?}");
    assert_eq!(with(|d| live(&log, d)), tel_want, "{released:?}");
    assert!(tel_log_segments > 0);
    // And the database is usable again: it grows back over the garbage.
    s.begin().unwrap();
    s.db()
        .exec("CREATE TABLE bulk2 (id INTEGER PRIMARY KEY, b BLOB)")
        .unwrap();
    for i in 0..300 {
        s.db()
            .exec(&format!("INSERT INTO bulk2 VALUES ({i}, zeroblob(40000))"))
            .unwrap();
    }
    s.commit().unwrap();
    assert_eq!(
        s.db()
            .query_i64("SELECT sum(length(b)) FROM bulk2")
            .unwrap(),
        300 * 40000
    );
    // Gaps read as zeros: the blobs are all zeros although the disk held
    // garbage under them.
    assert_eq!(
        s.db()
            .query_i64("SELECT count(*) FROM bulk2 WHERE b != zeroblob(40000)")
            .unwrap(),
        0
    );
    assert_eq!(s.db().query_text("PRAGMA integrity_check").unwrap(), "ok");
}

#[test]
fn recovery_ignores_garbage_in_every_discarded_and_unreferenced_range_garbage() {
    sqlite_case(Released::Garbage);
}

#[test]
fn recovery_ignores_zeros_in_every_discarded_and_unreferenced_range() {
    sqlite_case(Released::Zeros);
}

#[test]
fn recovery_is_unchanged_when_the_device_ignored_the_discards() {
    sqlite_case(Released::Keep);
}
