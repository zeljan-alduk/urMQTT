//! Golden layout-v1 disk images (STORAGE-PLAN S0).
//!
//! Each scenario builds a small disk with the real code in its layout-v1
//! mode (`layout::v1`, `Disk::open_v1`, the telemetry log over a v1 view),
//! deterministically, and compares every non-zero sector with the frozen
//! copy in `tests/golden/<name>.txt`. A change to the v1 structures, or to
//! the code paths that must keep reading and writing them byte for byte,
//! fails here. The frozen files are the inputs of S2's migration tests
//! (`tools/disk/tests/migrate.rs`) and were not changed by S2.
//!
//! Only urMQTT's own structures are frozen (superblock, size tables,
//! telemetry). SQLite's files are SQLite's format, checked semantically by
//! `tests/sqlite.rs`.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_v1` rewrites
//! the files. Only do that together with a format version bump.

use std::fmt::Write as _;
use std::path::PathBuf;

use urmqtt_store::layout::{FileKind, Layout, LayoutError, SECTOR, SizeTable, v1};
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, MemDisk};

/// The smallest supported disk (16 MiB), so the files stay small.
const DISK_BYTES: usize = 16 << 20;
const UUID: [u8; 16] = *b"urmqtt-golden-v1";
const NOW: u64 = 1_761_696_000;
const RETENTION_MS: u64 = 30 * 86_400_000;

fn sparse(m: &MemDisk) -> String {
    let mut out = String::from(
        "# urMQTT data disk, layout v1: every non-zero 512-byte sector as `lba hex`\n",
    );
    let _ = writeln!(out, "size {DISK_BYTES}");
    let sector = SECTOR as usize;
    for lba in 0..DISK_BYTES / sector {
        let s = m.raw(lba * sector, sector);
        if s.iter().any(|&b| b != 0) {
            let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(out, "{lba} {hex}");
        }
    }
    out
}

fn compare(name: &str, m: &MemDisk) {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect();
    let got = sparse(m);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (UPDATE_GOLDEN=1 creates it)", path.display()));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!(
            "{name}: the on-disk bytes differ from layout v1 ({first}); a format change needs a version bump and a migration"
        );
    }
}

/// Formats a v1 disk the way layout v1's `Disk::open` did: size table slot
/// A, slot B zeros, flush, then the superblock, flush.
fn format_v1(m: &MemDisk) {
    let l = v1::plan(DISK_BYTES as u64 / SECTOR, UUID).unwrap();
    let mut dev = m.device();
    dev.write(8, &SizeTable::default().encode()).unwrap();
    dev.write(16, &[0u8; 4096]).unwrap();
    dev.flush().unwrap();
    dev.write(0, &v1::encode(&l)).unwrap();
    dev.flush().unwrap();
}

/// A freshly formatted disk with an opened (formatted) telemetry log.
fn fresh() -> (MemDisk, Disk, TelemetryLog) {
    let m = MemDisk::new(DISK_BYTES);
    format_v1(&m);
    // The kernel refuses it; the tool's view reads it.
    assert_eq!(
        Disk::open(m.device(), || UUID).err(),
        Some(urmqtt_store::DiskError::Layout(LayoutError::OldVersion(1)))
    );
    let mut disk = Disk::open_v1(m.device()).unwrap();
    let (log, rec) = TelemetryLog::open(&mut disk, NOW, RETENTION_MS).unwrap();
    assert_eq!(rec.records, 0);
    (m, disk, log)
}

fn publish(disk: &mut Disk, log: &mut TelemetryLog) {
    for i in 0..40u64 {
        let p = [0usize, 1, 7][(i % 3) as usize];
        let topic = format!("devices/device-{:03}/telemetry/temp", i % 5);
        let payload = format!("{{\"t\":{}.{}}}", 20 + i % 7, i % 10);
        log.append(disk, p, NOW * 1000 + i * 250, &topic, payload.as_bytes())
            .unwrap();
    }
    log.flush(disk).unwrap();
    // A size-table update, as SQLite growing its files would cause.
    disk.set_file_size(FileKind::Db, 8 * 4096);
    disk.set_file_size(FileKind::Wal, 4096 + 32);
    disk.sync().unwrap();
}

fn reopen(m: &MemDisk) -> urmqtt_store::telemetry::Recovery {
    let mut disk = Disk::open_v1(m.device()).unwrap();
    TelemetryLog::open(&mut disk, NOW + 60, RETENTION_MS)
        .unwrap()
        .1
}

#[test]
fn v1_fresh() {
    let (m, _, _) = fresh();
    compare("v1-fresh", &m);
    assert_eq!(reopen(&m).records, 0);
}

#[test]
fn v1_with_telemetry() {
    let (m, mut disk, mut log) = fresh();
    publish(&mut disk, &mut log);
    compare("v1-telemetry", &m);
    let disk2 = Disk::open_v1(m.device()).unwrap();
    assert_eq!(disk2.file_size(FileKind::Db), 8 * 4096);
    let rec = reopen(&m);
    assert_eq!((rec.records, rec.torn_tails), (40, 0));
}

#[test]
fn v1_torn_tail() {
    let (m, mut disk, mut log) = fresh();
    publish(&mut disk, &mut log);
    // A batch of three records in partition 1, of which only 40 bytes reach
    // the disk: recovery keeps the 40 earlier records and truncates the tail.
    for i in 0..3u64 {
        log.append(
            &mut disk,
            1,
            NOW * 1000 + 20_000 + i,
            "devices/device-009/telemetry/x",
            b"torn",
        )
        .unwrap();
    }
    log.simulate_torn_flush(&mut disk, 1, 40).unwrap();
    compare("v1-torn", &m);
    let rec = reopen(&m);
    assert_eq!((rec.records, rec.torn_tails), (40, 1));
}

/// The frozen files themselves are valid layout-v1 disks that the v2 parser
/// names as such (and never writes to).
#[test]
fn the_frozen_files_are_v1_disks() {
    for name in ["v1-fresh", "v1-telemetry", "v1-torn"] {
        let m = load(name);
        let mut sb = [0u8; 4096];
        m.device().read(0, &mut sb).unwrap();
        assert_eq!(
            Layout::decode(&sb, DISK_BYTES as u64 / SECTOR),
            Err(LayoutError::OldVersion(1)),
            "{name}"
        );
        assert!(
            v1::decode(&sb, DISK_BYTES as u64 / SECTOR)
                .unwrap()
                .is_some()
        );
    }
}

/// Loads a frozen golden file into a disk.
fn load(name: &str) -> MemDisk {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect();
    let text = std::fs::read_to_string(&path).unwrap();
    let mut img = vec![0u8; DISK_BYTES];
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
