//! Encryption at rest (STORAGE-PLAN S7, ADR-240): a disk formatted with a
//! key is ciphertext on the medium (no SQLite header, no telemetry payload),
//! opens only with its key, and works as before above the crypt layer
//! (the telemetry ring, the scrubber and SQLite itself).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::layout::RegionKind;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, DiskError, MemDisk, Platform, open};

const MIB: u64 = 1 << 20;
const NOW: u64 = 1_761_696_000;
const RET: u64 = 30 * 86_400_000;
const PAYLOAD: [u8; 64] = *b"SECRET-PAYLOAD-SECRET-PAYLOAD-SECRET-PAYLOAD-SECRET-PAYLOAD-0123";

fn key(seed: u8) -> [u8; KEY_BYTES] {
    let mut k = [0u8; KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(29).wrapping_add(seed);
    }
    k
}

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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn image(m: &MemDisk) -> Vec<u8> {
    m.raw(0, m.len() as usize)
}

fn fill_ring(d: &mut Disk, n: u64) {
    let (mut log, _) = TelemetryLog::open(d, NOW, RET).unwrap();
    for i in 0..n {
        log.append(d, 0, NOW * 1000 + i, "t/ab", &PAYLOAD).unwrap();
    }
    log.flush(d).unwrap();
}

#[test]
fn a_keyed_blank_disk_is_formatted_encrypted_and_reopens_only_with_its_key() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let k = key(1);
    let (mut d, how) = Disk::open_keyed(m.device(), || [0x42; 16], 8, Some(&k)).unwrap();
    assert_eq!(how, urmqtt_store::Opened::Formatted);
    assert!(d.layout().encrypted());
    fill_ring(&mut d, 200);
    d.sync().unwrap();
    drop(d);

    // The medium shows neither the payload nor a size table.
    assert!(!contains(&image(&m), b"SECRET-PAYLOAD"));

    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, None).err(),
        Some(DiskError::KeyRequired)
    );
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, Some(&key(2))).err(),
        Some(DiskError::WrongKey)
    );
    let (mut d, how) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    assert_eq!(how, urmqtt_store::Opened::Existing);
    let (log, info) = TelemetryLog::open(&mut d, NOW, RET).unwrap();
    drop(log);
    assert!(format!("{info:?}").len() > 0);
    // Reading the ring back through the layer gives the payload.
    let mut buf = vec![0u8; 64 * 1024];
    d.read_at(RegionKind::Telemetry, 4096, &mut buf).unwrap();
    assert!(contains(&buf, &PAYLOAD));
}

#[test]
fn a_plain_disk_refuses_a_key_and_stays_plain() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    fill_ring(&mut d, 50);
    d.sync().unwrap();
    drop(d);
    assert!(contains(&image(&m), b"SECRET-PAYLOAD"));
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, Some(&key(1))).err(),
        Some(DiskError::NotEncrypted)
    );
}

#[test]
fn sqlite_runs_on_an_encrypted_disk_and_the_medium_has_no_database_header() {
    let _g = lock();
    let m = MemDisk::sparse(64 * MIB);
    let k = key(5);
    let (disk, _) = Disk::open_keyed(m.device(), || [0x42; 16], 8, Some(&k)).unwrap();
    urmqtt_store::init(heap(), disk, platform()).unwrap();
    let (store, _) = open().unwrap();
    drop(store);
    urmqtt_store::vfs::with_disk(|d| d.sync()).unwrap().unwrap();
    let img = image(&m);
    assert!(!contains(&img, b"SQLite format 3"));
    assert!(!contains(&img, b"CREATE TABLE"));
}
