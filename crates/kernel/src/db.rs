//! Durable storage (M11, ADR-030): SQLite on the data disk, owned by the
//! DB core.
//!
//! At boot the boot CPU opens the store (integrity check, migrations),
//! seeds the revocation table from the build-time list and loads the
//! broker state. After SMP bring-up the store moves to the DB core: the
//! highest-numbered CPU when there are at least two, which runs nothing
//! else. With one CPU the network loop calls [`poll`] between iterations.
//!
//! The data plane talks to the DB core only through SPSC rings: requests
//! and responses, plus one telemetry ring per source core. Writes are
//! batched into one transaction per [`BATCH_MS`] or [`BATCH_OPS`]
//! operations, whichever comes first. Telemetry records go to the source
//! core's partition of the telemetry log (M12, ADR-031) and are flushed
//! every [`LOG_FLUSH_MS`] or [`LOG_FLUSH_BYTES`].

#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use urmqtt_arch::{cpu, time};
use urmqtt_broker::{Msg, MsgInner, PersistOp};
use urmqtt_config::CONFIG;
use urmqtt_log::{error, info, warn};
use urmqtt_store::layout::LayoutError;
use urmqtt_store::telemetry::{Recovery, TelemetryLog};
use urmqtt_store::{Disk, DiskError, Opened, Platform, Retained, SessionRecord, Store, StoreError};
use urmqtt_sync::spsc::{Consumer, Producer, Spsc};
use urmqtt_sync::sync::SpinLock;

use crate::cmdline::DbTest;
use crate::devices;
use crate::{smp, vm};

/// Longest a write waits for its transaction to commit.
pub const BATCH_MS: u64 = 5;
/// Most operations per transaction.
pub const BATCH_OPS: u32 = 512;
const STATS_EVERY_MS: u64 = 10_000;
/// Longest a telemetry record waits to become durable.
pub const LOG_FLUSH_MS: u64 = 5;
/// Flush the telemetry log once this much is pending.
pub const LOG_FLUSH_BYTES: usize = 256 * 1024;

/// Telemetry records from one core: (Unix ms, message).
pub type LogBatch = Vec<(u64, Msg)>;
const LOG_RING: usize = 64;
static LOG_RINGS: [Spsc<LogBatch, LOG_RING>; smp::MAX_CPUS] =
    [const { Spsc::new() }; smp::MAX_CPUS];
/// `test=log-crash`: report durable totals.
static LOG_CRASH: AtomicBool = AtomicBool::new(false);
/// Telemetry partitions of the opened layout (source core `c` writes
/// partition `c % PARTS`).
static PARTS: AtomicUsize = AtomicUsize::new(8);

/// The telemetry partition source core `core` writes.
pub fn partition_of(core: usize) -> usize {
    // Relaxed: set once at boot before the data cores start.
    core % PARTS.load(Ordering::Relaxed).max(1)
}

/// The message a v1 data disk is refused with (STORAGE-PLAN S2).
const V1_REFUSAL: &str =
    "data disk is layout v1; this image needs v2: run urmqtt-disk migrate (docs/DEPLOY.md)";

/// A request from the data plane.
pub enum DbReq {
    Persist(PersistOp),
    DeviceSeen {
        id: Box<str>,
        unix: i64,
    },
    /// A control message as published (H1), authenticated by the worker.
    Control {
        from: Box<str>,
        payload: Box<[u8]>,
    },
}

/// A response to the data plane.
pub enum DbResp {
    Committed { ops: u32, us: u32 },
    Failed { ops: u32 },
    LogDurable { records: u64 },
}

/// Per data core: requests to the DB core and its responses (built in
/// [`start`], once the number of cores is known).
struct Rings {
    req: Vec<Box<Spsc<DbReq, 4096>>>,
    resp: Vec<Box<Spsc<DbResp, 256>>>,
}

static RINGS: urmqtt_sync::sync::OnceCell<Rings> = urmqtt_sync::sync::OnceCell::new();

/// The DB worker, handed from the boot CPU to whichever core runs it.
static WORKER: SpinLock<Option<Worker>> = SpinLock::new(None);
/// The core running the worker (`usize::MAX`: the network loop, inline).
static DB_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// State restored from the store at boot.
pub struct Restored {
    pub revoked: Vec<String>,
    /// The device allowlist (H1).
    pub allowlist: Vec<String>,
    pub retained: Vec<Retained>,
    pub sessions: Vec<SessionRecord>,
}

/// Whether durable storage is in use (false: memory only, dev builds).
pub fn active() -> bool {
    // Relaxed: set once at boot before the data plane starts.
    ACTIVE.load(Ordering::Relaxed)
}

/// Data core `core`'s ends of its DB rings (taken once by its MQTT service).
pub fn endpoints(
    core: usize,
) -> Option<(
    Producer<'static, DbReq, 4096>,
    Consumer<'static, DbResp, 256>,
)> {
    let r = RINGS.get()?;
    Some((r.req.get(core)?.producer()?, r.resp.get(core)?.consumer()?))
}

/// The telemetry ring of `core` (its producer end, taken once).
pub fn log_producer(core: usize) -> Option<Producer<'static, LogBatch, LOG_RING>> {
    LOG_RINGS.get(core)?.producer()
}

/// Wakes the DB core after requests were queued.
pub fn notify() {
    // Relaxed: set once in `start`; the ring orders the data itself.
    let cpu = DB_CPU.load(Ordering::Relaxed);
    if cpu != usize::MAX {
        crate::dataplane::wake(cpu);
    }
}

fn now_ms() -> u64 {
    time::uptime_ns() / 1_000_000
}

fn now_unix() -> i64 {
    crate::boot::now_unix().unwrap_or(0) as i64
}

fn platform() -> Platform {
    Platform {
        random: |buf| {
            if urmqtt_tls::rng::fill_global(buf).is_err() {
                // Unreachable after boot (entropy is required to run);
                // never hand SQLite predictable bytes silently.
                buf.fill(0);
                error!("db: CSPRNG unavailable for SQLite randomness");
            }
        },
        now_unix_ms: crate::boot::now_unix_ms,
        delay_us: |us| {
            let until = time::uptime_ns() + u64::from(us) * 1000;
            while time::uptime_ns() < until {
                core::hint::spin_loop();
            }
        },
        log: |code, msg| {
            // 283/284: WAL recovery and auto-index notices are normal.
            if code & 0xff == 27 || code & 0xff == 28 {
                info!("sqlite: {msg}");
            } else {
                warn!("sqlite ({code}): {msg}");
            }
        },
    }
}

/// Refuses to serve, or (where the configuration allows it) falls back to
/// running without persistence.
fn refuse_or_degrade(allowed: bool, what: core::fmt::Arguments<'_>) -> Option<Restored> {
    if allowed {
        error!("storage: {what}; running WITHOUT persistence (dev configuration)");
        None
    } else {
        crate::boot::fatal_fmt(format_args!("storage: {what}; refusing to serve"))
    }
}

/// Opens the store and loads the broker state. `None` means memory-only
/// operation (only where the configuration allows it).
pub fn init(test: Option<DbTest>, cpus: usize) -> Option<Restored> {
    let cfg = &CONFIG.storage;
    // The data partition of the boot disk (single-disk model, STORAGE-PLAN
    // §2a), prepared by `devices::prepare_boot_disk`.
    let Some(boot) = devices::DEVICES.lock().boot.take() else {
        return refuse_or_degrade(
            !cfg.require_data_disk,
            format_args!("no data partition: {}", devices::no_boot_disk_reason()),
        );
    };
    let part = boot.partition;
    let faulty = boot.faulty;
    let Some(dev) = urmqtt_store::part::Partition::new(boot.dev, part.first_lba, part.sectors())
    else {
        return refuse_or_degrade(false, format_args!("data partition outside the disk"));
    };
    let dev = Box::new(dev);
    let uuid = || {
        let mut u = [0u8; 16];
        let _ = urmqtt_tls::rng::fill_global(&mut u);
        u
    };
    // Telemetry partitions of a disk formatted now: one per core, at least
    // 8 (G4); an existing layout keeps its own.
    let partitions = cpus.next_power_of_two().clamp(8, 64) as u32;
    let (mut disk, how) = match Disk::open_with(dev, uuid, partitions) {
        Ok(d) => d,
        Err(DiskError::Layout(LayoutError::OldVersion(v))) => {
            // An older layout is never converted at boot: refused before
            // anything is written (the migration is offline and explicit).
            error!("storage: refused reason=layout-v{v}: {V1_REFUSAL}");
            return refuse_or_degrade(false, format_args!("{V1_REFUSAL}"));
        }
        Err(DiskError::Layout(e)) => {
            // Never format over data we do not recognise: a damaged data
            // partition is refused, never re-formatted (S5 restores it).
            return refuse_or_degrade(
                !cfg.refuse_on_corruption,
                format_args!("data partition is damaged, left as it is: {e:?}"),
            );
        }
        Err(e) if faulty => {
            warn!(
                "disk-fault: power cut injected while opening the data partition ({e:?}), powering off"
            );
            crate::power::off()
        }
        Err(e) => {
            return refuse_or_degrade(false, format_args!("data partition unreadable: {e:?}"));
        }
    };
    // S3: a larger device than the layout covers (the cloud volume grew, the
    // GPT step has extended the partition): the new space goes to the
    // database and the telemetry ring by `storage.grow_ratio_db`. One
    // superblock write; a cut leaves the old layout or the new one.
    let spare = disk.spare_sectors();
    match disk.grow(cfg.grow_ratio_db) {
        Ok(Some(g)) => log_grown(&g, ""),
        Ok(None) => {
            if spare * 512 >= 1 << 20 {
                info!(
                    "storage: {} MiB of the device are not in the layout (less than one alignment unit of new space, not grown)",
                    (spare * 512) >> 20
                );
            }
        }
        Err(e) if faulty => {
            warn!("disk-fault: power cut injected during the grow ({e:?}), powering off");
            crate::power::off()
        }
        Err(e) => {
            // The old layout is intact (the update is one block write).
            warn!("storage: growing the layout failed ({e:?}); running on the old layout");
        }
    }
    log_layout(&disk, how);
    PARTS.store(disk.layout().partitions as usize, Ordering::Relaxed);
    // Relaxed: statistics for `$SYS/broker/disk/total` (O1).
    crate::sys::DISK_TOTAL.store(disk.layout().total_sectors * 512, Ordering::Relaxed);

    let heap_bytes = (cfg.sqlite_heap_mb as usize) << 20;
    let Some((va, _pa, len)) = vm::dma_alloc(heap_bytes) else {
        return refuse_or_degrade(
            false,
            format_args!("cannot allocate the {} MiB SQLite heap", cfg.sqlite_heap_mb),
        );
    };
    // SAFETY: freshly allocated, zeroed RAM in the HHDM, page aligned,
    // owned exclusively by SQLite from here on and never freed.
    let heap = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };
    if let Err(e) = urmqtt_store::init(heap, disk, platform()) {
        return refuse_or_degrade(false, format_args!("{e}"));
    }
    let t0 = time::uptime_ns();
    let (mut store, info) = match urmqtt_store::open() {
        Ok(s) => s,
        Err(e @ StoreError::Corrupt(_)) => {
            return refuse_or_degrade(!cfg.refuse_on_corruption, format_args!("{e}"));
        }
        Err(e) => return refuse_or_degrade(false, format_args!("{e}")),
    };
    info!(
        "db: sqlite {} on the {}: WAL, exclusive locking, quick_check ok in {} ms, \
         schema v{} (from v{}), {} page(s), heap {} MiB",
        urmqtt_store::db::version(),
        if crate::live::ephemeral() {
            "RAM store (EPHEMERAL)"
        } else {
            "data disk"
        },
        (time::uptime_ns() - t0) / 1_000_000,
        info.schema_to,
        info.schema_from,
        info.pages,
        cfg.sqlite_heap_mb
    );

    let retention_ms = u64::from(cfg.retention_days) * 86_400_000;
    let now_s = crate::boot::now_unix().unwrap_or(0);
    let t1 = time::uptime_ns();
    let log = match urmqtt_store::vfs::with_disk(|d| TelemetryLog::open(d, now_s, retention_ms)) {
        Some(Ok((log, rec))) => {
            log_recovery(&rec, &log, (time::uptime_ns() - t1) / 1_000_000);
            Some(log)
        }
        Some(Err(e)) => {
            return refuse_or_degrade(
                !cfg.refuse_on_corruption,
                format_args!("telemetry log rejected: {e:?}"),
            );
        }
        None => None,
    };
    let mut log = log;
    match (test, log.as_mut()) {
        (Some(DbTest::LogVerify), Some(l)) => log_verify(l, retention_ms),
        (Some(DbTest::LogTear), Some(l)) => {
            log_tear(l);
            // The torn write is on disk; the in-memory log is stale.
            log = None;
        }
        _ => {}
    }
    LOG_CRASH.store(test == Some(DbTest::LogCrash), Ordering::Relaxed);
    log_io_stats("after startup");

    match test {
        Some(DbTest::Bench) => bench(&mut store),
        Some(DbTest::Crash) => crash_writer(&mut store),
        Some(DbTest::Verify) => match store.selftest_verify() {
            Ok(Ok(n)) => info!("db-verify: {n} rows consistent"),
            Ok(Err(e)) => error!("db-verify: INCONSISTENT: {e}"),
            Err(e) => error!("db-verify: failed: {e}"),
        },
        _ => {}
    }

    let restored = match load(&mut store) {
        Ok(r) => r,
        Err(e) => return refuse_or_degrade(false, format_args!("loading state failed: {e}")),
    };
    let devices = store.device_count().unwrap_or(0);
    let control_seq = match store.control_seq() {
        Ok(s) => s,
        Err(e) => {
            return refuse_or_degrade(false, format_args!("loading control state failed: {e}"));
        }
    };
    info!(
        "db: restored {} retained message(s), {} persistent session(s) with {} queued message(s), \
         {} revoked serial(s), {devices} known device(s), control seq {control_seq}",
        restored.retained.len(),
        restored.sessions.len(),
        restored
            .sessions
            .iter()
            .map(|s| s.queued.len())
            .sum::<usize>(),
        restored.revoked.len()
    );
    let log_rx = LOG_RINGS.iter().filter_map(Spsc::consumer).collect();
    *WORKER.lock() = Some(Worker {
        store,
        rx: Vec::new(),
        tx: Vec::new(),
        txn_start_ms: 0,
        txn_ops: 0,
        stats: Stats::default(),
        last_stats_ms: now_ms(),
        grow_irqs_seen: devices::blk_irqs(),
        grow_looked_ms: now_ms(),
        log,
        log_rx,
        log_since_ms: None,
        log_reported: 0,
        control_seq,
    });
    // Relaxed: read only after the data plane starts (later in boot).
    ACTIVE.store(true, Ordering::Relaxed);
    Some(restored)
}

fn log_recovery(rec: &Recovery, log: &TelemetryLog, ms: u64) {
    info!(
        "telemetry: log recovered in {ms} ms: {} record(s) in {} segment(s), {} torn tail(s) truncated, \
         {} expired; {} partitions of {} MiB",
        rec.records,
        rec.segments,
        rec.torn_tails,
        rec.expired,
        log.partitions(),
        log.capacity_bytes() >> 20
    );
}

/// `test=log-tear`: 10 000 durable records on core 0's partition, then
/// 1000 more of which only half the bytes reach the disk.
fn log_tear(log: &mut TelemetryLog) {
    let topic = "selftest/core-0";
    let ts = crate::boot::now_unix_ms().unwrap_or(0);
    let payload = |seq: u64| {
        let mut p = [0u8; 16];
        p[..8].copy_from_slice(&seq.to_le_bytes());
        p
    };
    let r = urmqtt_store::vfs::with_disk(|d| {
        for seq in 1..=10_000u64 {
            log.append(d, 0, ts, topic, &payload(seq))?;
        }
        let durable = log.flush(d)?;
        for seq in 10_001..=11_000u64 {
            log.append(d, 0, ts, topic, &payload(seq))?;
        }
        let half = urmqtt_store::telemetry::record_size(topic, &payload(0)) * 500 + 7;
        log.simulate_torn_flush(d, 0, half)?;
        Ok::<u64, urmqtt_store::telemetry::LogError>(durable)
    });
    match r {
        Some(Ok(n)) => {
            info!("log-tear: {n} records durable, then a torn write cutting record 10501 in half")
        }
        other => error!("log-tear: failed: {:?}", other.map(|x| x.err())),
    }
}

/// `test=log-verify`: every core's self-test records must form one
/// contiguous sequence 1..=n (nothing lost in the middle, no duplicates).
fn log_verify(log: &TelemetryLog, retention_ms: u64) {
    let mut next = [1u64; smp::MAX_CPUS];
    let mut bad: Option<(usize, u64, u64)> = None;
    let mut total = 0u64;
    let r = urmqtt_store::vfs::with_disk(|d| {
        for p in 0..log.partitions() {
            log.scan(d, p, retention_ms, |rec| {
                let (Some(core), Some(seq)) = (
                    rec.topic
                        .strip_prefix("selftest/core-")
                        .and_then(|c| c.parse::<usize>().ok()),
                    rec.payload
                        .get(..8)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_le_bytes),
                ) else {
                    return;
                };
                total += 1;
                if let Some(n) = next.get_mut(core) {
                    if seq != *n && bad.is_none() {
                        bad = Some((core, *n, seq));
                    }
                    *n = seq + 1;
                }
            })?;
        }
        Ok::<(), urmqtt_store::telemetry::LogError>(())
    });
    match (r, bad) {
        (Some(Ok(())), None) => {
            info!("log-verify: {total} records, every core's sequence contiguous")
        }
        (Some(Ok(())), Some((c, want, got))) => {
            error!("log-verify: INCONSISTENT: core {c} expected record {want}, found {got}")
        }
        (other, _) => error!("log-verify: scan failed: {:?}", other.map(|x| x.err())),
    }
}

fn log_layout(disk: &Disk, how: Opened) {
    let l = disk.layout();
    let mib = |k| disk.bytes(k) >> 20;
    use urmqtt_store::layout::RegionKind as K;
    let medium = if crate::live::ephemeral() {
        "RAM store (EPHEMERAL: lost on reboot)"
    } else {
        "data disk"
    };
    info!(
        "storage: {medium} {} ({} MiB, uuid {:02x}{:02x}{:02x}{:02x}…): db {} MiB, wal {} MiB, \
         journal {} MiB, telemetry {} MiB; {} telemetry partition(s), aligned to {} KiB, generation {}",
        match how {
            Opened::Existing => "opened",
            Opened::Formatted => "formatted (was blank)",
        },
        (l.total_sectors * 512) >> 20,
        l.uuid[0],
        l.uuid[1],
        l.uuid[2],
        l.uuid[3],
        mib(K::Db),
        mib(K::Wal),
        mib(K::Journal),
        mib(K::Telemetry),
        l.partitions,
        l.align_sectors / 2,
        l.generation
    );
}

/// The write path's alignment counter (S2): device requests that did not
/// start and end on a physical block. Smoke requires 0.
pub fn log_io_stats(when: &str) {
    let s = urmqtt_store::vfs::disk_stats();
    let t = urmqtt_store::vfs::with_disk(|d| (d.topology(), d.write_gran())).unwrap_or_default();
    info!(
        "storage: misaligned_writes={} of {} device writes {when} (physical block {} B, write granularity {} B, optimal I/O {} B)",
        s.misaligned_writes, s.device_writes, t.0.physical, t.1, t.0.opt_io
    );
}

fn load(store: &mut Store) -> Result<Restored, StoreError> {
    let now = now_unix();
    store.begin()?;
    for serial in CONFIG.tls.revoked_serials {
        store.revoke(serial, "config", now)?;
    }
    store.commit()?;
    Ok(Restored {
        revoked: store.revoked()?,
        allowlist: store.allowlist()?,
        retained: store.retained()?,
        sessions: store.sessions()?,
    })
}

/// Batched vs one-commit-per-write throughput (PROMPT M11: "batched writes
/// measured").
fn bench(store: &mut Store) {
    const ROWS: i64 = 5000;
    const PER_TXN: i64 = 100;
    const SINGLE: i64 = 100;
    let r = (|| {
        store.selftest_clear()?;
        let t0 = time::uptime_ns();
        for t in 0..ROWS / PER_TXN {
            store.begin()?;
            for i in 0..PER_TXN {
                store.selftest_insert(t * PER_TXN + i + 1, 200)?;
            }
            store.commit()?;
        }
        let batched = time::uptime_ns() - t0;
        let t1 = time::uptime_ns();
        for i in 0..SINGLE {
            store.begin()?;
            store.selftest_insert(ROWS + i + 1, 200)?;
            store.commit()?;
        }
        let single = time::uptime_ns() - t1;
        let n = store.selftest_verify()?.map_err(StoreError::Corrupt)?;
        store.begin()?;
        store.selftest_clear()?;
        store.commit()?;
        Ok::<_, StoreError>((batched, single, n))
    })();
    match r {
        Ok((batched, single, n)) => {
            let ops = |count: i64, ns: u64| count as u64 * 1_000_000_000 / ns.max(1);
            let d = urmqtt_store::vfs::disk_stats();
            info!(
                "db-bench: {ROWS} inserts in {} transactions: {} ops/s ({} us per commit); \
                 1 insert per transaction: {} ops/s; {n} rows verified; disk {} writes, {} flushes",
                ROWS / PER_TXN,
                ops(ROWS, batched),
                batched / 1000 / (ROWS / PER_TXN) as u64,
                ops(SINGLE, single),
                d.writes,
                d.flushes
            );
        }
        Err(e) => error!("db-bench: failed: {e}"),
    }
    log_io_stats("after db-bench");
}

/// Commits transactions of 100 rows forever; the host kills the VM at an
/// arbitrary point and a `test=db-verify` boot checks consistency.
fn crash_writer(store: &mut Store) -> ! {
    let mut seq = match store.selftest_verify() {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            crate::boot::fatal_fmt(format_args!("db-crash: existing rows inconsistent: {e}"))
        }
        Err(e) => crate::boot::fatal_fmt(format_args!("db-crash: {e}")),
    };
    info!("db-crash: writing from row {}", seq + 1);
    let mut commits = 0u64;
    loop {
        let r = (|| {
            store.begin()?;
            for _ in 0..100 {
                seq += 1;
                store.selftest_insert(seq, 64 + (seq % 512) as usize)?;
            }
            store.commit()
        })();
        if let Err(e) = r {
            crate::boot::fatal_fmt(format_args!("db-crash: write failed: {e}"));
        }
        commits += 1;
        if commits.is_multiple_of(10) {
            // Logged only after the commit returned (durable).
            info!("db-crash: committed {seq}");
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Stats {
    ops: u64,
    commits: u64,
    errors: u64,
    commit_us_total: u64,
    commit_us_max: u64,
}

struct Worker {
    store: Store,
    /// One request ring and one response ring per data core.
    rx: Vec<Consumer<'static, DbReq, 4096>>,
    tx: Vec<Producer<'static, DbResp, 256>>,
    txn_start_ms: u64,
    txn_ops: u32,
    stats: Stats,
    last_stats_ms: u64,
    log: Option<TelemetryLog>,
    /// Consumers of every core's telemetry ring, in core order.
    log_rx: Vec<Consumer<'static, LogBatch, LOG_RING>>,
    /// When the oldest unflushed telemetry record arrived.
    log_since_ms: Option<u64>,
    log_reported: u64,
    /// The last accepted control sequence number (H1).
    control_seq: u64,
    /// Online grow (S3): the boot disk's interrupt count at the last look,
    /// and when that was.
    grow_irqs_seen: u64,
    grow_looked_ms: u64,
}

/// Logs what a grow did (at boot or online).
fn log_grown(g: &urmqtt_store::disk::Grown, how: &str) {
    info!(
        "storage: grew the layout{how} from {} MiB to {} MiB (generation {}): database +{} MiB, telemetry +{} MiB, split {}% database",
        (g.old_total * 512) >> 20,
        (g.new_total * 512) >> 20,
        g.generation,
        (g.db_sectors * 512) >> 20,
        (g.telemetry_sectors * 512) >> 20,
        CONFIG.storage.grow_ratio_db
    );
}

impl Worker {
    /// Online grow (S3, ADR-143): the disk raised an interrupt that no
    /// request of ours explains, or just a completion; at most every 250 ms
    /// and only when the interrupt count moved, ask the device whether it got
    /// larger. If so, the partition table steps, the layout grow and the
    /// telemetry ring's new band, one after the other on this core.
    fn check_online_grow(&mut self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.grow_looked_ms) < 250 {
            return false;
        }
        let irqs = devices::blk_irqs();
        if irqs == self.grow_irqs_seen {
            return false;
        }
        self.grow_looked_ms = now_ms;
        self.grow_irqs_seen = irqs;
        let ratio = CONFIG.storage.grow_ratio_db;
        let random = || {
            let mut u = [0u8; 16];
            let _ = urmqtt_tls::rng::fill_global(&mut u);
            u
        };
        match urmqtt_store::vfs::with_disk(|d| d.grow_online(ratio, random)) {
            Some(Ok(Some(g))) => {
                log_grown(&g, " online");
                let log = self.log.as_mut();
                let r = urmqtt_store::vfs::with_disk(|d| {
                    crate::sys::DISK_TOTAL.store(d.layout().total_sectors * 512, Ordering::Relaxed);
                    log.map(|l| l.refresh_geometry(d)).transpose()
                });
                if let Some(Err(e)) = r {
                    error!("telemetry: taking up the grown layout failed: {e:?}");
                }
                true
            }
            Some(Err(e)) => {
                warn!("storage: online grow failed ({e:?}); the old layout stays in force");
                false
            }
            _ => false,
        }
    }

    /// Applies queued requests and commits when the batch is due. Returns
    /// whether there was any work.
    fn step(&mut self, now_ms: u64) -> bool {
        let mut did = false;
        let mut core = 0;
        let mut idle_rings = 0;
        while self.txn_ops < BATCH_OPS && idle_rings < self.rx.len() {
            // Round-robin over the data cores' rings.
            let req = self.rx.get_mut(core).and_then(Consumer::pop);
            core = (core + 1) % self.rx.len().max(1);
            let Some(req) = req else {
                idle_rings += 1;
                continue;
            };
            idle_rings = 0;
            did = true;
            // A control message gets a transaction of its own: its effect
            // and sequence number commit together, before anything acts
            // on them (H1).
            if let DbReq::Control { from, payload } = req {
                if self.store.in_transaction() {
                    self.commit();
                }
                crate::control::handle(&mut self.store, &mut self.control_seq, &from, &payload);
                continue;
            }
            if !self.store.in_transaction() {
                if let Err(e) = self.store.begin() {
                    self.fail(&e);
                    continue;
                }
                self.txn_start_ms = now_ms;
            }
            if let Err(e) = self.apply(req) {
                self.fail(&e);
            }
            self.txn_ops += 1;
        }
        if self.store.in_transaction()
            && (self.txn_ops >= BATCH_OPS || now_ms.saturating_sub(self.txn_start_ms) >= BATCH_MS)
        {
            self.commit();
            did = true;
        }
        did |= self.step_log(now_ms);
        did |= self.check_online_grow(now_ms);
        if now_ms.saturating_sub(self.last_stats_ms) >= STATS_EVERY_MS {
            self.refresh_disk_used();
            self.log_stats(now_ms);
        }
        did
    }

    /// Appends queued telemetry and flushes when due.
    fn step_log(&mut self, now_ms: u64) -> bool {
        let Some(log) = self.log.as_mut() else {
            // No log: drop batches so producers never stall.
            for rx in &mut self.log_rx {
                while rx.pop().is_some() {}
            }
            return false;
        };
        let mut did = false;
        let unix_ms = crate::boot::now_unix_ms().unwrap_or(0);
        for (core, rx) in self.log_rx.iter_mut().enumerate() {
            // Bounded per step so SQLite work is not starved.
            for _ in 0..8 {
                let Some(batch) = rx.pop() else { break };
                did = true;
                let p = log.partition_of(core);
                let r = urmqtt_store::vfs::with_disk(|d| {
                    for (ts, m) in &batch {
                        log.append(d, p, *ts, &m.topic, &m.payload)?;
                    }
                    Ok::<(), urmqtt_store::telemetry::LogError>(())
                });
                if let Some(Err(e)) = r {
                    self.stats.errors += 1;
                    error!("telemetry: append failed: {e:?}");
                }
                self.log_since_ms.get_or_insert(now_ms);
            }
        }
        let due = self.log_since_ms.is_some_and(|t| {
            now_ms.saturating_sub(t) >= LOG_FLUSH_MS || log.pending_bytes() >= LOG_FLUSH_BYTES
        });
        if due {
            log.set_now(unix_ms / 1000);
            match urmqtt_store::vfs::with_disk(|d| log.flush(d)) {
                Some(Ok(n)) => {
                    for tx in &mut self.tx {
                        let _ = tx.push(DbResp::LogDurable { records: n });
                    }
                    // Relaxed: a test-mode flag set once at boot.
                    if LOG_CRASH.load(Ordering::Relaxed)
                        && log.durable_records / 100_000 > self.log_reported / 100_000
                    {
                        // Logged only after the flush returned (durable).
                        info!("log-crash: durable {}", log.durable_records);
                        self.log_reported = log.durable_records;
                    }
                }
                Some(Err(e)) => {
                    self.stats.errors += 1;
                    error!("telemetry: flush failed: {e:?}");
                }
                None => {}
            }
            self.log_since_ms = None;
            did = true;
        }
        did
    }

    /// Whether any data core has queued work for the DB core.
    fn pending(&self) -> bool {
        self.rx.iter().any(|c| !c.is_empty()) || self.log_rx.iter().any(|c| !c.is_empty())
    }

    fn apply(&mut self, req: DbReq) -> Result<(), StoreError> {
        let s = &mut self.store;
        match req {
            DbReq::DeviceSeen { id, unix } => s.device_seen(&id, unix),
            // Handled in `step`, never batched.
            DbReq::Control { .. } => Ok(()),
            DbReq::Persist(op) => match op {
                PersistOp::Retain { msg, qos } => s.retain(&msg.topic, &msg.payload, qos as u8),
                PersistOp::SessionUpsert { client_id } => s.session_upsert(&client_id, now_unix()),
                PersistOp::SessionDelete { client_id } => s.session_delete(&client_id),
                PersistOp::Subscribe {
                    client_id,
                    filter,
                    qos,
                } => s.subscribe(&client_id, &filter, qos as u8),
                PersistOp::Unsubscribe { client_id, filter } => s.unsubscribe(&client_id, &filter),
                PersistOp::QueuePush { client_id, msg } => {
                    s.queue_push(&client_id, &msg.topic, &msg.payload, 1)
                }
                PersistOp::QueueClear { client_id } => s.queue_clear(&client_id),
            },
        }
    }

    fn commit(&mut self) {
        let t0 = time::uptime_ns();
        let ops = self.txn_ops;
        self.txn_ops = 0;
        let resp = match self.store.commit() {
            Ok(()) => {
                let us = (time::uptime_ns() - t0) / 1000;
                self.stats.ops += u64::from(ops);
                self.stats.commits += 1;
                self.stats.commit_us_total += us;
                self.stats.commit_us_max = self.stats.commit_us_max.max(us);
                DbResp::Committed {
                    ops,
                    us: us.min(u64::from(u32::MAX)) as u32,
                }
            }
            Err(e) => {
                self.fail(&e);
                DbResp::Failed { ops }
            }
        };
        // A full response ring only loses statistics. Commits mix all
        // cores' work, so every core gets the report.
        for tx in &mut self.tx {
            let _ = tx.push(match &resp {
                DbResp::Committed { ops, us } => DbResp::Committed { ops: *ops, us: *us },
                DbResp::Failed { ops } => DbResp::Failed { ops: *ops },
                DbResp::LogDurable { records } => DbResp::LogDurable { records: *records },
            });
        }
    }

    fn fail(&mut self, e: &StoreError) {
        self.stats.errors += 1;
        if self.stats.errors <= 10 || self.stats.errors.is_power_of_two() {
            error!("db: {e} ({} error(s) so far)", self.stats.errors);
        }
    }

    /// What SQLite uses of the data partition (its database, WAL and
    /// journal), for `$SYS/broker/disk/used`. The telemetry log is a ring
    /// of fixed size that overwrites itself and is not counted.
    fn refresh_disk_used(&self) {
        use urmqtt_store::layout::FileKind;
        let used = urmqtt_store::vfs::with_disk(|d| {
            [FileKind::Db, FileKind::Wal, FileKind::Journal]
                .iter()
                .map(|&k| d.file_size(k))
                .sum::<u64>()
        });
        if let Some(u) = used {
            // Relaxed: statistics.
            crate::sys::DISK_USED.store(u, Ordering::Relaxed);
        }
    }

    fn log_stats(&mut self, now_ms: u64) {
        let s = core::mem::take(&mut self.stats);
        self.last_stats_ms = now_ms;
        if s.commits == 0 && s.errors == 0 {
            return;
        }
        info!(
            "db: {} op(s) in {} commit(s) over {} s (avg {} us, max {} us per commit), {} error(s)",
            s.ops,
            s.commits,
            STATS_EVERY_MS / 1000,
            s.commit_us_total / s.commits.max(1),
            s.commit_us_max,
            s.errors
        );
    }
}

/// The DB core picks `cpu` (highest index) when there are two or more
/// CPUs; with one CPU the network loop runs the worker inline. Builds the
/// rings for `data_cores` data cores and hands the worker its ends.
pub fn start(cpus: usize, data_cores: usize) {
    if !active() {
        return;
    }
    let rings = Rings {
        req: (0..data_cores).map(|_| Spsc::new_boxed()).collect(),
        resp: (0..data_cores).map(|_| Spsc::new_boxed()).collect(),
    };
    if RINGS.set(rings).is_err() {
        return;
    }
    if let (Some(r), Some(w)) = (RINGS.get(), WORKER.lock().as_mut()) {
        w.rx = r.req.iter().filter_map(|q| q.consumer()).collect();
        w.tx = r.resp.iter().filter_map(|q| q.producer()).collect();
    }
    if cpus >= 2 {
        let cpu = cpus - 1;
        // Relaxed: the worker itself is published through `WORKER`'s lock.
        DB_CPU.store(cpu, Ordering::Relaxed);
        smp::start_db_core(cpu);
        info!("db: DB core is cpu {cpu} (batches of {BATCH_OPS} ops or {BATCH_MS} ms)");
    } else {
        info!("db: single CPU, DB work runs between network iterations");
    }
}

/// Runs the DB worker on this core forever.
pub fn run_core() -> ! {
    let Some(mut w) = WORKER.lock().take() else {
        warn!("db: DB core started without a worker");
        loop {
            cpu::wait_for_interrupt();
        }
    };
    info!("db: worker running on cpu {}", smp::current());
    let mut idle = crate::dataplane::Idle::new();
    loop {
        let worked = w.step(now_ms());
        // An open transaction or pending telemetry must commit within its
        // batch delay: keep polling until then (the tick is 10 ms).
        let due = w.store.in_transaction() || w.log_since_ms.is_some();
        idle.pass(worked || due, || w.pending());
    }
}

/// One-CPU systems: runs pending DB work from the network loop.
pub fn poll() {
    // Relaxed: set once in `start`.
    if DB_CPU.load(Ordering::Relaxed) != usize::MAX {
        return;
    }
    if let Some(w) = WORKER.lock().as_mut() {
        w.step(now_ms());
    }
}

/// `test=log-crash` writer: appends numbered records to this core's
/// telemetry ring forever (the host kills the VM).
pub fn log_writer(core: usize) -> ! {
    let Some(mut tx) = log_producer(core) else {
        crate::boot::fatal("log-crash: telemetry ring already taken");
    };
    let topic: Box<str> = alloc::format!("selftest/core-{core}").into();
    info!("log-crash: core {core} writing");
    let mut seq = 1u64;
    loop {
        let ts = crate::boot::now_unix_ms().unwrap_or(0);
        let mut batch: LogBatch = Vec::with_capacity(256);
        for _ in 0..256 {
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&seq.to_le_bytes());
            payload[8..].copy_from_slice(&(core as u64).to_le_bytes());
            batch.push((
                ts,
                alloc::sync::Arc::new(MsgInner {
                    topic: topic.clone(),
                    payload: Box::new(payload),
                }),
            ));
            seq += 1;
        }
        while let Err(b) = tx.push(batch) {
            batch = b;
            notify();
            core::hint::spin_loop();
        }
        notify();
    }
}

/// Starts the `test=log-crash` writers on every core but the DB core; the
/// calling (boot) CPU becomes one of them.
pub fn start_log_crash(cpus: usize) -> ! {
    // Relaxed: set once in `start`.
    let db = DB_CPU.load(Ordering::Relaxed);
    if db == usize::MAX {
        crate::boot::fatal("log-crash needs at least two CPUs (one for the DB core)");
    }
    for c in 1..cpus {
        if c != db {
            smp::start_log_writer(c);
        }
    }
    log_writer(smp::current())
}
