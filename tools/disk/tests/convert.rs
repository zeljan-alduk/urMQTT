//! `urmqtt-disk encrypt | decrypt | rekey` (STORAGE-PLAN S7, ADR-240):
//! - a populated disk is encrypted, rekeyed and decrypted with every table
//!   and the telemetry ring intact, and the medium shows no plaintext while
//!   it is encrypted;
//! - a power cut (clean or torn, cache dropped or kept) at every write of
//!   each procedure, then `--resume`: the disk ends converted with all its
//!   data; before the resume the kernel's open refuses it.

use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_disk::convert::{self, Key, MemJournal};
use urmqtt_disk::host::{self, TelemetryDigest};
use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::layout::RegionKind;
use urmqtt_store::{Disk, DiskError, MemDisk, Opened};

const DISK: usize = 16 << 20;

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn key(seed: u8) -> Key {
    let mut k = [0u8; KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(seed);
    }
    k
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

fn open(m: &MemDisk, k: Option<&Key>) -> Result<Disk, DiskError> {
    let (d, how) = Disk::open_keyed(m.device(), || [0; 16], 8, k)?;
    assert_eq!(how, Opened::Existing);
    Ok(d)
}

fn digest(m: &MemDisk, k: Option<&Key>) -> Digest {
    // On a copy: the digest opens the telemetry log, which may write.
    let f = m.fork();
    digest_of(&mut open(&f, k).unwrap())
}

fn populated() -> MemDisk {
    let m = MemDisk::sparse(DISK as u64);
    let (d, _) = Disk::open(m.device(), || [0x42; 16]).unwrap();
    host::populate(d).unwrap();
    m
}

fn contains(m: &MemDisk, needle: &[u8]) -> bool {
    m.raw(0, m.len() as usize)
        .windows(needle.len())
        .any(|w| w == needle)
}

fn run(
    m: &MemDisk,
    from: Option<&Key>,
    to: Option<&Key>,
    j: &mut MemJournal,
    resume: bool,
) -> Result<convert::Report, String> {
    let mut dev = m.device();
    convert::convert(dev.as_mut(), from, to, j, resume, |_, _| {})
}

#[test]
fn encrypt_rekey_and_decrypt_keep_every_byte_of_the_data() {
    let _g = lock();
    let m = populated();
    let want = digest(&m, None);
    assert!(contains(&m, b"SQLite format 3"));

    let (k1, k2) = (key(1), key(2));
    let mut j = MemJournal::default();
    let r = run(&m, None, Some(&k1), &mut j, false).unwrap();
    assert!(r.sectors_rewritten > 0 && !r.resumed);
    assert!(!contains(&m, b"SQLite format 3"));
    assert!(!contains(&m, b"fixture/fw"));
    assert_eq!(digest(&m, Some(&k1)), want);
    assert_eq!(open(&m, None).err(), Some(DiskError::KeyRequired));
    assert_eq!(open(&m, Some(&k2)).err(), Some(DiskError::WrongKey));

    run(&m, Some(&k1), Some(&k2), &mut j, false).unwrap();
    assert_eq!(digest(&m, Some(&k2)), want);
    assert_eq!(open(&m, Some(&k1)).err(), Some(DiskError::WrongKey));

    run(&m, Some(&k2), None, &mut j, false).unwrap();
    assert_eq!(digest(&m, None), want);
    assert!(contains(&m, b"SQLite format 3"));
    assert_eq!(open(&m, Some(&k1)).err(), Some(DiskError::NotEncrypted));
}

#[test]
fn refusals() {
    let _g = lock();
    let m = populated();
    let k = key(3);
    let mut j = MemJournal::default();
    assert!(run(&m, None, None, &mut j, false).is_err());
    assert!(run(&m, Some(&k), None, &mut j, false).is_err()); // not encrypted
    assert!(run(&m, None, Some(&k), &mut j, true).is_err()); // nothing to resume
    run(&m, None, Some(&k), &mut j, false).unwrap();
    assert!(run(&m, None, Some(&key(4)), &mut j, false).is_err()); // encrypted, no key
    assert!(run(&m, Some(&key(4)), None, &mut j, false).is_err()); // wrong key
    assert!(run(&m, Some(&k), Some(&k), &mut j, false).is_err());
}

fn cut_loop(from: Option<Key>, to: Option<Key>) {
    let base = populated();
    // Start from the `from` state.
    if let Some(k) = &from {
        run(&base, None, Some(k), &mut MemJournal::default(), false).unwrap();
    }
    let want = digest(&base, from.as_ref());
    // Writes of one uninterrupted run.
    let total = {
        let m = base.fork();
        let probe = FaultDevice::new(m.device(), FaultSpec::default());
        let mut dev = probe;
        convert::convert(
            &mut dev,
            from.as_ref(),
            to.as_ref(),
            &mut MemJournal::default(),
            false,
            |_, _| {},
        )
        .unwrap();
        dev.writes()
    };
    assert!(total > 5, "writes: {total}");
    let mut cases = 0;
    for n in 1..=total {
        for torn in [false, true] {
            for keep in [false, true] {
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
                let mut j = MemJournal::default();
                let mut dev = FaultDevice::new(m.device(), spec);
                let r = convert::convert(
                    &mut dev,
                    from.as_ref(),
                    to.as_ref(),
                    &mut j,
                    false,
                    |_, _| {},
                );
                drop(dev);
                m.crash(|_| keep);
                cases += 1;
                let ctx = format!("write {n} torn={torn} keep={keep}");
                if r.is_err() {
                    match open(&m, from.as_ref()) {
                        // The cut came before the record: untouched.
                        Ok(_) => {
                            assert_eq!(digest(&m, from.as_ref()), want, "{ctx}: untouched");
                            run(&m, from.as_ref(), to.as_ref(), &mut j, false)
                                .unwrap_or_else(|e| panic!("{ctx}: rerun: {e}"));
                        }
                        // Half converted: refused until resumed.
                        Err(DiskError::ConversionPending) => {
                            run(&m, from.as_ref(), to.as_ref(), &mut j, true)
                                .unwrap_or_else(|e| panic!("{ctx}: resume: {e}"));
                        }
                        // Cut after the last write that matters.
                        Err(_) => {}
                    }
                }
                assert_eq!(digest(&m, to.as_ref()), want, "{ctx}: data after resume");
            }
        }
    }
    assert!(cases >= 4 * total as usize - 4);
}

#[test]
fn encrypt_survives_a_power_cut_at_every_write() {
    let _g = lock();
    cut_loop(None, Some(key(1)));
}

#[test]
fn rekey_survives_a_power_cut_at_every_write() {
    let _g = lock();
    cut_loop(Some(key(1)), Some(key(2)));
}

#[test]
fn decrypt_survives_a_power_cut_at_every_write() {
    let _g = lock();
    cut_loop(Some(key(1)), None);
}
