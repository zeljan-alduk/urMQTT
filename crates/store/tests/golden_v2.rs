//! Golden layout-v2.0 disk images (STORAGE-PLAN S5, ADR-160).
//!
//! These were frozen from the code as it was before the backup region
//! existed (S4's tree). They are what every disk formatted before S5 looks
//! like, and S5 must keep reading, writing and (explicitly) upgrading them.
//! Two checks:
//!
//! 1. The code still writes the same bytes when it formats a disk or stores
//!    data with no backup region (so a v2.0 disk that is never upgraded stays
//!    exactly as it was).
//! 2. The frozen files, loaded as disks, open; `Disk::ensure_backup` adds
//!    the backup region with one superblock write; and the data they hold is
//!    still there afterwards (`tests/backup.rs` goes on from there).
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_v2` rewrites the
//! files. Only do that together with a format version bump.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::layout::{FileKind, SECTOR};
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, MemDisk, Platform, open};

const DISK_BYTES: usize = 16 << 20;
const UUID: [u8; 16] = *b"urmqtt-golden-v2";
const NOW: u64 = 1_761_696_000;
const RETENTION_MS: u64 = 30 * 86_400_000;

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
    Box::leak(vec![0u8; 32 << 20].into_boxed_slice())
}

fn sparse(m: &MemDisk) -> String {
    let mut out = String::from(
        "# urMQTT data disk, layout v2.0 (before the backup region): every non-zero 512-byte sector as `lba hex`\n",
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

fn path(name: &str) -> PathBuf {
    [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect()
}

fn compare(name: &str, m: &MemDisk) {
    let got = sparse(m);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path(name), &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path(name))
        .unwrap_or_else(|e| panic!("{name}: {e} (UPDATE_GOLDEN=1 creates it)"));
    if got != want {
        let first = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .map_or_else(|| "line count".to_string(), |i| format!("line {}", i + 1));
        panic!("{name}: the bytes differ from layout v2.0 ({first})");
    }
}

/// Loads a frozen golden file into a disk.
fn load(name: &str) -> MemDisk {
    let text = std::fs::read_to_string(path(name)).unwrap();
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

fn format() -> (MemDisk, Disk) {
    let m = MemDisk::new(DISK_BYTES);
    let (disk, _) = Disk::open(m.device(), || UUID).unwrap();
    (m, disk)
}

#[test]
fn v2_fresh() {
    let _g = lock();
    let (m, mut disk) = format();
    let (_log, rec) = TelemetryLog::open(&mut disk, NOW, RETENTION_MS).unwrap();
    assert_eq!(rec.records, 0);
    compare("v2-fresh", &m);
}

#[test]
fn v2_with_data() {
    let _g = lock();
    let (m, mut disk) = format();
    let (mut log, _) = TelemetryLog::open(&mut disk, NOW, RETENTION_MS).unwrap();
    for i in 0..40u64 {
        let p = [0usize, 1, 7][(i % 3) as usize];
        let topic = format!("devices/device-{:03}/telemetry/temp", i % 5);
        let payload = format!("{{\"t\":{}.{}}}", 20 + i % 7, i % 10);
        log.append(
            &mut disk,
            p,
            NOW * 1000 + i * 250,
            &topic,
            payload.as_bytes(),
        )
        .unwrap();
    }
    log.flush(&mut disk).unwrap();
    drop(log);
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    let (mut store, _) = open().unwrap();
    store.begin().unwrap();
    store.retain("fleet/config", b"{\"rate\":5}", 1).unwrap();
    store.retain("fleet/mode", b"normal", 0).unwrap();
    store.device_seen("device-001", NOW as i64).unwrap();
    store.session_upsert("device-001", NOW as i64).unwrap();
    store.subscribe("device-001", "fleet/#", 1).unwrap();
    store
        .queue_push("device-001", "fleet/config", b"x", 1)
        .unwrap();
    store.commit().unwrap();
    drop(store);
    compare("v2-data", &m);
}

/// The frozen files open as v2 disks, and carry the data they were made with.
#[test]
fn the_frozen_files_open_and_hold_their_data() {
    let _g = lock();
    for name in ["v2-fresh", "v2-data"] {
        let m = load(name);
        let (disk, how) = Disk::open(m.device(), || [9; 16]).unwrap();
        assert_eq!(how, urmqtt_store::Opened::Existing, "{name}");
        assert_eq!(disk.layout().uuid, UUID, "{name}");
        assert!(
            disk.layout()
                .region(urmqtt_store::layout::RegionKind::Backup)
                .is_none(),
            "{name}: a v2.0 disk has no backup region"
        );
        assert_eq!(disk.layout().minor, 0, "{name}");
        if name == "v2-data" {
            assert!(disk.file_size(FileKind::Db) > 0);
        }
    }
}
