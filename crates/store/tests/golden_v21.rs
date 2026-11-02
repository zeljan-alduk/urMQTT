//! Golden layout-v2.1 and encrypted disk images (STORAGE-PLAN S8, ADR-160, ADR-240).
//!
//! Frozen from the code as of S7. A disk with a backup region (layout 2.1) and
//! an encrypted disk (flag and key check in the superblock, ciphertext
//! everywhere else) must keep the same bytes, and the frozen files must keep
//! opening: the encrypted one only with its key. Together with `golden_v1`
//! and `golden_v2` this is a golden image for every layout version.
//!
//! `UPDATE_GOLDEN=1 cargo test -p urmqtt-store --test golden_v21` rewrites the
//! files. Only do that together with a format version bump.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::layout::SECTOR;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{BackupRegion, Disk, DiskError, MemDisk, Platform, open};

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

fn sparse(m: &MemDisk) -> String {
    let mut out = String::from(
        "# urMQTT data disk, layout v2.1 or encrypted: every non-zero 512-byte sector as `lba hex`\n",
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
        panic!("{name}: the bytes differ from the frozen image ({first})");
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

fn key() -> [u8; KEY_BYTES] {
    let mut k = [0u8; KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(5);
    }
    k
}

fn fill(disk: &mut Disk) {
    let (mut log, _) = TelemetryLog::open(disk, NOW, RETENTION_MS).unwrap();
    for i in 0..40u64 {
        let p = [0usize, 1, 7][(i % 3) as usize];
        let topic = format!("devices/device-{:03}/telemetry/temp", i % 5);
        let payload = format!("{{\"t\":{}.{}}}", 20 + i % 7, i % 10);
        log.append(disk, p, NOW * 1000 + i, &topic, payload.as_bytes())
            .unwrap();
    }
    log.flush(disk).unwrap();
}

fn plain_with_backup() -> MemDisk {
    let m = MemDisk::new(DISK_BYTES);
    let (mut disk, _) = Disk::open(m.device(), || UUID).unwrap();
    assert!(matches!(
        disk.ensure_backup().unwrap(),
        BackupRegion::Added { .. }
    ));
    fill(&mut disk);
    disk.sync().unwrap();
    m
}

fn encrypted() -> MemDisk {
    let m = MemDisk::new(DISK_BYTES);
    let k = key();
    let (mut disk, _) = Disk::open_keyed(m.device(), || UUID, 8, Some(&k)).unwrap();
    assert!(matches!(
        disk.ensure_backup().unwrap(),
        BackupRegion::Added { .. }
    ));
    fill(&mut disk);
    disk.sync().unwrap();
    m
}

#[test]
fn v21_with_backup_region_and_data() {
    let _g = lock();
    compare("v21-backup", &plain_with_backup());
}

#[test]
fn encrypted_with_backup_region_and_data() {
    let _g = lock();
    compare("encrypted-v21", &encrypted());
}

#[test]
fn the_frozen_v21_image_opens_and_holds_its_data() {
    let _g = lock();
    let m = load("v21-backup");
    let (mut disk, how) = Disk::open(m.device(), || [0; 16]).unwrap();
    assert_eq!(how, urmqtt_store::Opened::Existing);
    assert!(!disk.layout().encrypted());
    assert!(disk.layout().minor >= 1);
    assert_eq!(disk.ensure_backup().unwrap(), BackupRegion::Present);
    let (_, rec) = TelemetryLog::open(&mut disk, NOW, RETENTION_MS).unwrap();
    assert_eq!(rec.records, 40);
    // A key for a plain disk is refused.
    let k = key();
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).err(),
        Some(DiskError::NotEncrypted)
    );
}

#[test]
fn the_frozen_encrypted_image_opens_only_with_its_key() {
    let _g = lock();
    let m = load("encrypted-v21");
    let k = key();
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, None).err(),
        Some(DiskError::KeyRequired)
    );
    let mut wrong = key();
    wrong[0] ^= 1;
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, Some(&wrong)).err(),
        Some(DiskError::WrongKey)
    );
    let (mut disk, how) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    assert_eq!(how, urmqtt_store::Opened::Existing);
    assert!(disk.layout().encrypted());
    assert_eq!(disk.ensure_backup().unwrap(), BackupRegion::Present);
    let (_, rec) = TelemetryLog::open(&mut disk, NOW, RETENTION_MS).unwrap();
    assert_eq!(rec.records, 40);
    // The medium shows no telemetry payload.
    let raw = m.raw(0, DISK_BYTES);
    assert!(!raw.windows(11).any(|w| w == b"telemetry/t"));
}

#[test]
fn sqlite_runs_on_the_frozen_encrypted_image() {
    let _g = lock();
    let m = load("encrypted-v21");
    let k = key();
    let (disk, _) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    urmqtt_store::init(
        Box::leak(vec![0u8; 32 << 20].into_boxed_slice()),
        disk,
        platform(),
    )
    .unwrap();
    let (store, _) = open().unwrap();
    drop(store);
}
