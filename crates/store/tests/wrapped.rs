//! A disk key that is not in the image (LATER-7, ADR-325 to ADR-329): the
//! disk key wrapped in the superblock's key slots under passphrases.
//!
//! - a blank disk is formatted with a wrapped key, opens with the passphrase
//!   and with nothing else (a wrong passphrase, no key, another disk's slot);
//! - the header is checked: every edit of a slot, the key check, the flags
//!   or the cost is refused, with or without a recomputed CRC;
//! - the passphrase rotates without touching data, and no superblock keeps
//!   the old wrap afterwards; a recovery slot; the last slot cannot go;
//! - a power cut at every write of a rotation (clean and torn, the volatile
//!   cache lost and kept) leaves the old passphrase or the new one working,
//!   never neither, and the data intact; the next open's scrub wipes the
//!   old wrap from the older superblock;
//! - a disk with an image key is wrapped without a rewrite, and unwrapped
//!   back.

use urmqtt_store::crc::crc32c;
use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::disk::{Probe, probe, unlock};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::keyslot::{KeySlot, MIN_ITERATIONS, SLOT_BYTES};
use urmqtt_store::layout::{BLOCK, KEY_SLOTS_AT, Layout, LayoutError, RegionKind, SB_SLOT_LBA};
use urmqtt_store::{BlockDevice, Disk, DiskError, MemDisk, Opened};

const MIB: u64 = 1 << 20;
const UUID: [u8; 16] = [0x42; 16];
const OLD: &[u8] = b"old passphrase 1";
const NEW: &[u8] = b"new passphrase 2";
const RECOVERY: &[u8] = b"recovery passphrase 3";
const DATA: &[u8] = b"DATA-THAT-MUST-SURVIVE-EVERY-KEY-CHANGE";

fn key(seed: u8) -> [u8; KEY_BYTES] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
}

fn slot(k: &[u8; KEY_BYTES], pass: &[u8], uuid: &[u8; 16], salt: u8) -> KeySlot {
    KeySlot::seal(k, pass, uuid, [salt; 32], MIN_ITERATIONS)
}

/// A blank 64 MiB disk formatted with `key(1)` wrapped under OLD, and DATA
/// written into the database region.
fn wrapped_disk() -> MemDisk {
    let m = MemDisk::sparse(64 * MIB);
    let k = key(1);
    let mut d = Disk::format_sealed(m.device(), || UUID, 8, &k, |u| slot(&k, OLD, u, 9)).unwrap();
    assert!(d.layout().encrypted() && d.layout().wrapped());
    d.write_at(RegionKind::Db, 0, DATA).unwrap();
    d.set_file_size(urmqtt_store::layout::FileKind::Db, DATA.len() as u64);
    d.sync().unwrap();
    m
}

fn data_of(m: &MemDisk, pass: &[u8]) -> Result<Vec<u8>, DiskError> {
    let (k, _) = unlock(m.device().as_mut(), pass)?;
    let (mut d, how) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k))?;
    assert_eq!(how, Opened::Existing);
    let mut b = vec![0u8; DATA.len()];
    d.read_at(RegionKind::Db, 0, &mut b)?;
    Ok(b)
}

fn sb(m: &MemDisk, i: usize) -> [u8; BLOCK] {
    m.raw(SB_SLOT_LBA[i] as usize * 512, BLOCK)
        .try_into()
        .unwrap()
}

fn put_sb(m: &MemDisk, i: usize, b: &[u8; BLOCK]) {
    m.device().write(SB_SLOT_LBA[i], b).unwrap();
}

fn recrc(b: &mut [u8; BLOCK]) {
    let c = crc32c(&b[..BLOCK - 4]);
    b[BLOCK - 4..].copy_from_slice(&c.to_le_bytes());
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_wrapped_disk_opens_with_its_passphrase_and_nothing_else() {
    let m = wrapped_disk();
    assert_eq!(data_of(&m, OLD).unwrap(), DATA);
    match probe(m.device().as_mut()).unwrap() {
        Probe::Encrypted { uuid, slots } => {
            assert_eq!(uuid, UUID);
            assert_eq!(slots, [true, false]);
        }
        p => panic!("{p:?}"),
    }
    assert_eq!(data_of(&m, NEW).err(), Some(DiskError::WrongPassphrase));
    assert_eq!(data_of(&m, b"").err(), Some(DiskError::WrongPassphrase));
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, None).err(),
        Some(DiskError::KeyRequired)
    );
    assert_eq!(
        Disk::open_keyed(m.device(), || [0; 16], 8, Some(&key(2))).err(),
        Some(DiskError::WrongKey)
    );
    // The disk key itself (what an image key would be) opens it too.
    assert!(Disk::open_keyed(m.device(), || [0; 16], 8, Some(&key(1))).is_ok());
    // Neither the key nor DATA is on the medium.
    let img = m.raw(0, 64 * MIB as usize);
    assert!(!contains(&img, &key(1)[..32]) && !contains(&img, &key(1)[32..]));
    assert!(!contains(&img, DATA));
    // A plain disk, a blank one, one with an image key only.
    let p = MemDisk::sparse(64 * MIB);
    assert_eq!(
        unlock(p.device().as_mut(), OLD).err(),
        Some(DiskError::Blank)
    );
    assert_eq!(probe(p.device().as_mut()).unwrap(), Probe::Blank);
    drop(Disk::open(p.device(), || UUID).unwrap());
    assert_eq!(probe(p.device().as_mut()).unwrap(), Probe::Plain);
    assert_eq!(
        unlock(p.device().as_mut(), OLD).err(),
        Some(DiskError::NotEncrypted)
    );
    let e = MemDisk::sparse(64 * MIB);
    drop(Disk::open_keyed(e.device(), || UUID, 8, Some(&key(1))).unwrap());
    assert_eq!(
        unlock(e.device().as_mut(), OLD).err(),
        Some(DiskError::NotWrapped)
    );
    // format_sealed never formats over anything.
    let k = key(3);
    assert_eq!(
        Disk::format_sealed(e.device(), || UUID, 8, &k, |u| slot(&k, OLD, u, 1)).err(),
        Some(DiskError::Layout(LayoutError::UnknownData))
    );
}

#[test]
fn an_edited_header_is_refused() {
    let m = wrapped_disk();
    let at = KEY_SLOTS_AT;
    let base = sb(&m, 0);
    // Both slots hold the same superblock after the format? Only slot A is
    // written by a format; B is blank.
    assert!(sb(&m, 1).iter().all(|&b| b == 0));
    type Edit = (&'static str, fn(&mut [u8; BLOCK]), Option<DiskError>);
    let edits: [Edit; 7] = [
        // A byte of the wrapped key: the key wrap's check fails.
        (
            "wrapped key",
            |b| b[KEY_SLOTS_AT + 50] ^= 1,
            Some(DiskError::WrongPassphrase),
        ),
        // The salt: another derived key.
        (
            "salt",
            |b| b[KEY_SLOTS_AT + 8] ^= 1,
            Some(DiskError::WrongPassphrase),
        ),
        // The key check: the slot opens, the key does not match it.
        (
            "key check",
            |b| b[KEY_SLOTS_AT - 1] ^= 1,
            Some(DiskError::KeySlotMismatch),
        ),
        // A cheaper cost than the format allows.
        (
            "iterations",
            |b| b[KEY_SLOTS_AT + 4..KEY_SLOTS_AT + 8].copy_from_slice(&1u32.to_le_bytes()),
            None,
        ),
        // The wrapped flag without the encrypted one.
        ("flags", |b| b[56] = 4, None),
        // Bytes in the empty slot.
        ("empty slot", |b| b[KEY_SLOTS_AT + SLOT_BYTES + 3] = 1, None),
        // An unknown slot kind.
        ("kind", |b| b[KEY_SLOTS_AT] = 7, None),
    ];
    for (what, edit, want) in edits {
        let mut b = base;
        edit(&mut b);
        // Without a new CRC the slot is damaged and nothing else is valid.
        put_sb(&m, 0, &b);
        assert_eq!(
            unlock(m.device().as_mut(), OLD).err(),
            Some(DiskError::Layout(LayoutError::BadChecksum)),
            "{what}"
        );
        recrc(&mut b);
        put_sb(&m, 0, &b);
        let got = unlock(m.device().as_mut(), OLD).err();
        match want {
            Some(e) => assert_eq!(got, Some(e), "{what}"),
            None => assert_eq!(
                got,
                Some(DiskError::Layout(LayoutError::Inconsistent)),
                "{what}"
            ),
        }
    }
    // The wrapped flag with no slot at all.
    let mut b = base;
    b[at..at + 2 * SLOT_BYTES].fill(0);
    recrc(&mut b);
    put_sb(&m, 0, &b);
    assert_eq!(
        unlock(m.device().as_mut(), OLD).err(),
        Some(DiskError::Layout(LayoutError::Inconsistent))
    );
    // Slot bytes on a disk without the flag.
    let mut b = base;
    b[56] = 2;
    recrc(&mut b);
    put_sb(&m, 0, &b);
    assert!(matches!(
        unlock(m.device().as_mut(), OLD).err(),
        Some(DiskError::Layout(LayoutError::Inconsistent))
    ));
    // Another disk's slot (same passphrase, same key, another UUID) put in.
    let k = key(1);
    let foreign = slot(&k, OLD, &[0x43; 16], 9);
    let mut b = base;
    KeySlot::encode(Some(&foreign), &mut b[at..at + SLOT_BYTES]);
    recrc(&mut b);
    put_sb(&m, 0, &b);
    assert_eq!(
        unlock(m.device().as_mut(), OLD).err(),
        Some(DiskError::WrongPassphrase)
    );
    // Another disk key wrapped for this disk under the passphrase (an
    // attacker who knows the passphrase but swaps the key): key check.
    let swapped = slot(&key(7), OLD, &UUID, 9);
    let mut b = base;
    KeySlot::encode(Some(&swapped), &mut b[at..at + SLOT_BYTES]);
    recrc(&mut b);
    put_sb(&m, 0, &b);
    assert_eq!(
        unlock(m.device().as_mut(), OLD).err(),
        Some(DiskError::KeySlotMismatch)
    );
    put_sb(&m, 0, &base);
    assert_eq!(data_of(&m, OLD).unwrap(), DATA);
    // The decoder agrees with the reader.
    assert!(Layout::decode(&base, 1 << 30).unwrap().unwrap().wrapped());
}

#[test]
fn the_passphrase_rotates_without_a_rewrite_and_no_superblock_keeps_the_old_wrap() {
    let m = wrapped_disk();
    let old_wrap = sb(&m, 0)[KEY_SLOTS_AT + 40..KEY_SLOTS_AT + 112].to_vec();
    let before = m.write_count();
    let (k, i) = unlock(m.device().as_mut(), OLD).unwrap();
    assert_eq!(i, 0);
    let (mut d, _) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    d.set_key_slot(0, Some(slot(&k, NEW, &UUID, 10))).unwrap();
    drop(d);
    // Two superblock writes, nothing else.
    assert_eq!(m.write_count() - before, 2);
    assert_eq!(data_of(&m, OLD).err(), Some(DiskError::WrongPassphrase));
    assert_eq!(data_of(&m, NEW).unwrap(), DATA);
    for s in 0..2 {
        assert!(!contains(&sb(&m, s), &old_wrap), "superblock {s}");
    }
    // A recovery passphrase in the second slot; both open.
    let (mut d, _) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    d.set_key_slot(1, Some(slot(&k, RECOVERY, &UUID, 11)))
        .unwrap();
    drop(d);
    assert_eq!(unlock(m.device().as_mut(), RECOVERY).unwrap().1, 1);
    assert_eq!(data_of(&m, NEW).unwrap(), DATA);
    // The daily slot removed; the last one cannot be.
    let (mut d, _) = Disk::open_keyed(m.device(), || [0; 16], 8, Some(&k)).unwrap();
    d.set_key_slot(0, None).unwrap();
    assert_eq!(d.set_key_slot(1, None).err(), Some(DiskError::LastKeySlot));
    assert_eq!(
        d.set_key_slot(2, None).err(),
        Some(DiskError::Layout(LayoutError::Inconsistent))
    );
    drop(d);
    assert_eq!(data_of(&m, NEW).err(), Some(DiskError::WrongPassphrase));
    assert_eq!(data_of(&m, RECOVERY).unwrap(), DATA);
}

#[test]
fn an_image_key_disk_is_wrapped_in_place_and_unwrapped_back() {
    let m = MemDisk::sparse(64 * MIB);
    let k = key(4);
    let (mut d, _) = Disk::open_keyed(m.device(), || UUID, 8, Some(&k)).unwrap();
    d.write_at(RegionKind::Db, 0, DATA).unwrap();
    d.set_file_size(urmqtt_store::layout::FileKind::Db, DATA.len() as u64);
    d.sync().unwrap();
    assert_eq!(d.unwrap_key_slots().err(), Some(DiskError::NotWrapped));
    let before = m.write_count();
    d.set_key_slot(1, Some(slot(&k, OLD, &UUID, 3))).unwrap();
    assert_eq!(m.write_count() - before, 2);
    drop(d);
    assert_eq!(data_of(&m, OLD).unwrap(), DATA);
    let (mut d, _) = Disk::open_keyed(m.device(), || UUID, 8, Some(&k)).unwrap();
    d.unwrap_key_slots().unwrap();
    assert!(!d.layout().wrapped() && d.layout().encrypted());
    drop(d);
    assert_eq!(
        unlock(m.device().as_mut(), OLD).err(),
        Some(DiskError::NotWrapped)
    );
    for s in 0..2 {
        assert!(
            sb(&m, s)[KEY_SLOTS_AT..KEY_SLOTS_AT + 2 * SLOT_BYTES]
                .iter()
                .all(|&b| b == 0)
        );
    }
    // A plain disk cannot take a slot.
    let p = MemDisk::sparse(64 * MIB);
    let (mut d, _) = Disk::open(p.device(), || UUID).unwrap();
    assert_eq!(
        d.set_key_slot(0, Some(slot(&k, OLD, &UUID, 3))).err(),
        Some(DiskError::NotEncrypted)
    );
}

/// Rotation under a power cut at every write: clean or torn, the volatile
/// cache lost or kept. The disk opens with OLD or NEW (never neither), the
/// data is intact, and once NEW is in force the next open's scrub leaves no
/// superblock with OLD's wrap.
#[test]
fn a_power_cut_during_a_rotation_leaves_one_passphrase_working() {
    let m = wrapped_disk();
    let image = m.raw(0, 64 * MIB as usize);
    let old_wrap = sb(&m, 0)[KEY_SLOTS_AT + 40..KEY_SLOTS_AT + 112].to_vec();
    let k = key(1);
    let rotate = |dev: Box<dyn BlockDevice>| -> Result<(), DiskError> {
        let (mut d, _) = Disk::open_keyed(dev, || [0; 16], 8, Some(&k))?;
        d.set_key_slot(0, Some(slot(&k, NEW, &UUID, 10)))
    };
    let count = MemDisk::from_image(image.clone());
    let f = FaultDevice::new(count.device(), FaultSpec::default());
    rotate(Box::new(f)).unwrap();
    let writes = 2u64;
    let (mut saw_old, mut saw_new) = (0, 0);
    for n in 1..=writes {
        for spec in [
            FaultSpec {
                stop_after_writes: Some(n),
                ..FaultSpec::default()
            },
            FaultSpec {
                tear_write: Some((n, 1)),
                ..FaultSpec::default()
            },
            FaultSpec {
                stop_after_flushes: Some(n),
                ..FaultSpec::default()
            },
        ] {
            for keep in [false, true] {
                let m = MemDisk::from_image(image.clone());
                let f = FaultDevice::new(m.device(), spec);
                let r = rotate(Box::new(f));
                m.crash(|_| keep);
                let old = data_of(&m, OLD);
                let new = data_of(&m, NEW);
                match (&old, &new) {
                    (Ok(a), Err(DiskError::WrongPassphrase)) => {
                        assert_eq!(a, DATA);
                        saw_old += 1;
                    }
                    (Err(DiskError::WrongPassphrase), Ok(b)) => {
                        assert_eq!(b, DATA);
                        saw_new += 1;
                        // What the kernel does after every open.
                        let (kk, _) = unlock(m.device().as_mut(), NEW).unwrap();
                        let (mut d, _) =
                            Disk::open_keyed(m.device(), || [0; 16], 8, Some(&kk)).unwrap();
                        d.scrub_key_slots().unwrap();
                        assert!(
                            !d.scrub_key_slots().unwrap(),
                            "a second scrub writes nothing"
                        );
                        drop(d);
                        for s in 0..2 {
                            assert!(
                                !contains(&sb(&m, s), &old_wrap),
                                "{spec:?} keep={keep} sb {s}"
                            );
                        }
                        assert_eq!(data_of(&m, NEW).unwrap(), DATA);
                    }
                    _ => panic!("{spec:?} keep={keep} r={r:?}: old {old:?}, new {new:?}"),
                }
            }
        }
    }
    assert!(saw_old > 0 && saw_new > 0, "{saw_old} {saw_new}");
}

/// A cut while a blank disk is formatted wrapped: blank again (formatted
/// at the next boot) or formatted and openable with the passphrase.
#[test]
fn a_power_cut_during_the_sealed_format_leaves_blank_or_formatted() {
    let k = key(6);
    for n in 1..=4u64 {
        for keep in [false, true] {
            let m = MemDisk::sparse(64 * MIB);
            let f = FaultDevice::new(
                m.device(),
                FaultSpec {
                    stop_after_writes: Some(n),
                    ..FaultSpec::default()
                },
            );
            let _ = Disk::format_sealed(Box::new(f), || UUID, 8, &k, |u| slot(&k, OLD, u, 2));
            m.crash(|_| keep);
            match probe(m.device().as_mut()).unwrap() {
                Probe::Blank => {}
                Probe::Encrypted { .. } => {
                    assert!(unlock(m.device().as_mut(), OLD).is_ok());
                }
                p => panic!("{n} {keep}: {p:?}"),
            }
        }
    }
}
