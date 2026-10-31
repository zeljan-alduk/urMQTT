//! SQLite and the telemetry log on the host: the same vendored amalgamation
//! and compile options as the kernel, the same recovery code.

use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use urmqtt_store::crc::{crc32c, update};
use urmqtt_store::layout::SECTOR;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, Platform, Store};

pub fn platform() -> Platform {
    Platform {
        random: |b| {
            if let Ok(mut f) = File::open("/dev/urandom") {
                let _ = f.read_exact(b);
            }
        },
        now_unix_ms: || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64)
        },
        delay_us: |us| std::thread::sleep(std::time::Duration::from_micros(u64::from(us))),
        log: |code, msg| {
            if code & 0xff != 27 && code & 0xff != 28 {
                eprintln!("sqlite ({code}): {msg}");
            }
        },
    }
}

/// Installs `disk` under SQLite and opens the broker's store on it. The
/// SQLite heap is allocated once per process; later calls only swap the
/// disk.
pub fn open_store(disk: Disk) -> Result<Store, String> {
    static FIRST: AtomicBool = AtomicBool::new(true);
    let heap: &'static mut [u8] = if FIRST.swap(false, Ordering::Relaxed) {
        Box::leak(vec![0u8; 256 << 20].into_boxed_slice())
    } else {
        Box::leak(Vec::new().into_boxed_slice())
    };
    urmqtt_store::init(heap, disk, platform()).map_err(|e| e.to_string())?;
    urmqtt_store::open()
        .map(|(s, _)| s)
        .map_err(|e| e.to_string())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Row count of every table of the broker's database, by name.
pub fn table_counts(store: &Store) -> Result<Vec<(String, i64)>, String> {
    let names = store
        .db()
        .query_text(
            "SELECT coalesce(group_concat(name, ','), '') FROM \
             (SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name)",
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for n in names.split(',').filter(|n| !n.is_empty()) {
        let c = store
            .db()
            .query_i64(&format!("SELECT count(*) FROM \"{n}\""))
            .map_err(|e| e.to_string())?;
        out.push((n.to_string(), c));
    }
    Ok(out)
}

/// What the telemetry log of a disk holds, comparable between two disks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryDigest {
    pub records: u64,
    pub segments: u32,
    pub torn_tails: u32,
    /// CRC-32C over every live record (partition, time, topic, payload) in
    /// scan order.
    pub digest: u32,
}

/// Opens the log (recovery included) and digests it. `retention` is long
/// enough to keep every record.
pub fn telemetry_digest(disk: &mut Disk) -> Result<TelemetryDigest, String> {
    let retention = u64::MAX / 4;
    let (log, rec) =
        TelemetryLog::open(disk, now_unix(), retention).map_err(|e| format!("telemetry: {e:?}"))?;
    let mut crc = 0u32;
    let mut scanned = 0u64;
    for p in 0..log.partitions() {
        scanned += log
            .scan(disk, p, retention, |r| {
                crc = update(crc, &(p as u32).to_le_bytes());
                crc = update(crc, &r.ts_ms.to_le_bytes());
                crc = update(crc, &(r.topic.len() as u32).to_le_bytes());
                crc = update(crc, r.topic.as_bytes());
                crc = update(crc, &(r.payload.len() as u32).to_le_bytes());
                crc = update(crc, r.payload);
            })
            .map_err(|e| format!("telemetry partition {p}: {e:?}"))?;
    }
    if scanned != rec.records {
        return Err(format!(
            "telemetry: scan found {scanned} record(s), recovery counted {}",
            rec.records
        ));
    }
    Ok(TelemetryDigest {
        records: rec.records,
        segments: rec.segments,
        torn_tails: rec.torn_tails,
        digest: crc32c(&crc.to_le_bytes()),
    })
}

/// CRC-32C of the first `len` bytes of a logical file, for comparing the
/// raw database and WAL before and after a migration.
pub fn file_digest(
    disk: &mut Disk,
    kind: urmqtt_store::layout::RegionKind,
    len: u64,
) -> Result<u32, String> {
    let mut crc = 0u32;
    let mut off = 0u64;
    let mut buf = vec![0u8; 256 << 10];
    while off < len {
        let n = ((len - off) as usize).min(buf.len());
        let part = buf.get_mut(..n).ok_or("buffer")?;
        disk.read_at(kind, off, part)
            .map_err(|e| format!("read {kind:?} at {off}: {e:?}"))?;
        crc = update(crc, part);
        off += n as u64;
    }
    Ok(crc32c(&crc.to_le_bytes()))
}

pub fn mib(sectors: u64) -> u64 {
    (sectors * SECTOR) >> 20
}

/// Formats a layout-v1 data partition the way layout v1's `Disk::open` did
/// (size table slot A, slot B zeros, flush, then the superblock, flush).
/// Fixtures for the migration only: the kernel never writes v1.
pub fn format_v1(
    dev: &mut dyn urmqtt_store::BlockDevice,
    uuid: [u8; 16],
) -> Result<urmqtt_store::layout::Layout, String> {
    use urmqtt_store::layout::{SizeTable, v1};
    let l = v1::plan(dev.sectors() / 8 * 8, uuid).map_err(|e| format!("{e:?}"))?;
    let w = |e: urmqtt_store::IoError| format!("write: {e:?}");
    dev.write(8, &SizeTable::default().encode()).map_err(w)?;
    dev.write(16, &[0u8; 4096]).map_err(w)?;
    dev.flush().map_err(w)?;
    dev.write(0, &v1::encode(&l)).map_err(w)?;
    dev.flush().map_err(w)?;
    Ok(l)
}

/// Fills a v1 (or any) disk with broker state and telemetry the way a
/// serving broker would: devices, retained messages, a persistent session
/// with a queued message, 600 telemetry records over the 8 partitions.
pub fn populate(mut disk: Disk) -> Result<(), String> {
    let (mut log, _) = TelemetryLog::open(&mut disk, now_unix(), u64::MAX / 4)
        .map_err(|e| format!("telemetry: {e:?}"))?;
    let base = now_unix() * 1000;
    for i in 0..600u64 {
        log.append(
            &mut disk,
            (i % 8) as usize,
            base + i,
            &format!("devices/device-{:03}/telemetry/fixture", i % 7),
            format!("{{\"n\":{i}}}").as_bytes(),
        )
        .map_err(|e| format!("telemetry: {e:?}"))?;
    }
    log.flush(&mut disk)
        .map_err(|e| format!("telemetry: {e:?}"))?;
    drop(log);
    let mut store = open_store(disk)?;
    store.begin().map_err(|e| e.to_string())?;
    let now = now_unix() as i64;
    for i in 0..40 {
        store
            .device_seen(&format!("device-{i:03}"), now)
            .map_err(|e| e.to_string())?;
    }
    store
        .retain("fleet/fixture/fw", b"1.0.0", 1)
        .map_err(|e| e.to_string())?;
    store
        .retain("fleet/fixture/cfg", b"on", 0)
        .map_err(|e| e.to_string())?;
    store
        .session_upsert("device-007", now)
        .map_err(|e| e.to_string())?;
    store
        .subscribe("device-007", "devices/device-007/cmd/#", 1)
        .map_err(|e| e.to_string())?;
    store
        .queue_push("device-007", "devices/device-007/cmd/reboot", b"now", 1)
        .map_err(|e| e.to_string())?;
    store.commit().map_err(|e| e.to_string())?;
    urmqtt_store::vfs::with_disk(|d| d.sync())
        .ok_or("store not installed")?
        .map_err(|e| format!("{e:?}"))
}
