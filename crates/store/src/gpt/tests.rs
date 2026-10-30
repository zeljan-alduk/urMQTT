use super::*;
use alloc::boxed::Box;

use crate::disk::MemDisk;
use crate::fault::{FaultDevice, FaultSpec};

const MIB: usize = 1 << 20;

/// A fake ESP of `sectors` sectors with recognisable content.
fn esp(sectors: usize) -> Vec<u8> {
    (0..sectors * 512).map(|i| (i * 7 % 251) as u8).collect()
}

/// The raw image of `esp` extended to `bytes` (what `truncate` does to a
/// copy of the image on a larger disk).
fn disk(esp: &[u8], bytes: usize) -> MemDisk {
    let mut img = raw_image(esp).unwrap();
    img.resize(bytes, 0);
    MemDisk::from_image(img)
}

fn counter() -> impl FnMut() -> [u8; 16] {
    let mut n = 0u8;
    move || {
        n = n.wrapping_add(1);
        [n; 16]
    }
}

#[test]
fn crc32_check_value() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn guid_text_form_is_rfc_order() {
    assert_eq!(
        DATA_TYPE.to_string(),
        "58d3f720-bdf5-4db7-99ec-de26c8b8850f"
    );
    assert_eq!(ESP_TYPE.to_string(), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    let g = Guid::random([0xff; 16]).to_string();
    assert_eq!(&g[14..15], "4", "version 4: {g}");
}

#[test]
fn raw_image_is_a_valid_gpt_disk() {
    let e = esp(3000);
    let img = raw_image(&e).unwrap();
    assert_eq!(img.len() % MIB, 0);
    assert_eq!(raw_image_len(e.len() as u64), img.len() as u64);
    let m = MemDisk::from_image(img.clone());
    let mut d = m.device();
    let p = read_table(d.as_mut(), 1).unwrap().unwrap();
    let last = d.sectors() - 1;
    let b = read_table(d.as_mut(), last).unwrap().unwrap();
    assert_eq!(p.entries, b.entries);
    assert_eq!(p.header.disk_guid, b.header.disk_guid);
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].type_guid, ESP_TYPE);
    assert_eq!(p.entries[0].first_lba, ALIGN);
    assert_eq!(&img[ALIGN as usize * 512..][..e.len()], &e[..]);
    assert_eq!(&img[510..512], &[0x55, 0xaa]);
    // Same ESP, same bytes (reproducible builds).
    assert_eq!(raw_image(&e).unwrap(), img);
    assert!(raw_image(&e[..511]).is_none());
}

#[test]
fn first_boot_moves_backup_creates_partition_and_is_idempotent() {
    let e = esp(3000);
    let img_len = raw_image(&e).unwrap().len();
    let m = disk(&e, 64 * MIB);
    let before = read_table(m.device().as_mut(), 1).unwrap().unwrap();
    let (part, steps) = prepare(m.device().as_mut(), counter()).unwrap();
    assert_eq!(
        steps,
        Steps {
            repaired_primary: false,
            moved_backup: true,
            repaired_backup: false,
            created_partition: true
        }
    );
    let total = (64 * MIB / 512) as u64;
    assert_eq!(part.first_lba % ALIGN, 0);
    assert!(part.first_lba >= ALIGN + 3000);
    let last_usable = total - 1 - ENTRY_SECTORS - 1;
    assert!(part.last_lba <= last_usable && last_usable - part.last_lba < 8);
    assert_eq!(part.sectors() % 8, 0, "whole 4 KiB blocks");
    let mut d = m.device();
    let p = read_table(d.as_mut(), 1).unwrap().unwrap();
    let b = read_table(d.as_mut(), total - 1).unwrap().unwrap();
    assert_eq!(p.entries, b.entries, "both copies agree");
    assert_eq!(p.header.backup_lba, total - 1);
    assert_ne!(
        p.header.disk_guid, before.header.disk_guid,
        "fresh disk GUID"
    );
    assert_eq!(p.data_partition().unwrap().first_lba, part.first_lba);
    assert_eq!(p.entries[0], before.entries[0], "ESP untouched");
    // The image's old backup header is gone from the new free space.
    let old_backup = (img_len / 512 - 1) * 512;
    assert_ne!(&m.raw(old_backup, 8)[..], b"EFI PART");
    // Second boot: nothing to do, same partition.
    let (again, steps) = prepare(m.device().as_mut(), counter()).unwrap();
    assert_eq!((again, steps), (part, Steps::default()));
}

#[test]
fn a_disk_of_exactly_the_image_size_has_no_room() {
    let e = esp(3000);
    let len = raw_image(&e).unwrap().len();
    let m = disk(&e, len);
    assert_eq!(
        prepare(m.device().as_mut(), counter()),
        Err(GptError::TooSmall)
    );
    // Nothing was written.
    assert_eq!(m.raw(0, len), raw_image(&e).unwrap());
}

#[test]
fn foreign_and_shrunk_disks_are_refused() {
    let blank = MemDisk::new(64 * MIB);
    assert_eq!(
        prepare(blank.device().as_mut(), counter()),
        Err(GptError::NoGpt)
    );
    // A prepared disk cut short (the backup and the partition end are gone).
    let e = esp(3000);
    let m = disk(&e, 64 * MIB);
    prepare(m.device().as_mut(), counter()).unwrap();
    let mut img = m.raw(0, 64 * MIB);
    img.truncate(40 * MIB);
    let cut = MemDisk::from_image(img);
    assert_eq!(
        prepare(cut.device().as_mut(), counter()),
        Err(GptError::Shrunk)
    );
}

#[test]
fn a_torn_primary_is_repaired_from_the_backup() {
    let e = esp(3000);
    let m = disk(&e, 64 * MIB);
    let (part, _) = prepare(m.device().as_mut(), counter()).unwrap();
    // Corrupt the primary header's CRC.
    let mut img = m.raw(0, 64 * MIB);
    img[512 + 16] ^= 0xff;
    let m = MemDisk::from_image(img);
    let (again, steps) = prepare(m.device().as_mut(), counter()).unwrap();
    assert!(steps.repaired_primary && !steps.created_partition);
    assert_eq!(again, part);
    assert!(read_table(m.device().as_mut(), 1).unwrap().is_some());
}

/// The partition head is zeroed before the entry exists, whatever the
/// disk held there before ("the whole disk belongs to urMQTT").
#[test]
fn old_data_under_the_new_partition_does_not_survive_the_head() {
    let e = esp(3000);
    let mut img = raw_image(&e).unwrap();
    img.resize(64 * MIB, 0xa5);
    let m = MemDisk::from_image(img);
    let (part, _) = prepare(m.device().as_mut(), counter()).unwrap();
    let head = m.raw(
        part.first_lba as usize * 512,
        (CLEARED_SECTORS * 512) as usize,
    );
    assert!(head.iter().all(|&b| b == 0));
}

/// Power loss after every single write of the first boot (and torn writes
/// of every multi-sector write): the next boot always ends with both
/// copies valid, equal and holding one data partition; the ESP is never
/// touched.
#[test]
fn first_boot_survives_a_crash_at_every_write() {
    let e = esp(3000);
    let pristine = disk(&e, 64 * MIB).raw(0, 64 * MIB);
    // How many writes a clean first boot does.
    let probe = MemDisk::from_image(pristine.clone());
    let mut f = FaultDevice::new(probe.device(), FaultSpec::default());
    prepare(&mut f, counter()).unwrap();
    let writes = f.writes();
    assert!(writes >= 6, "{writes}");
    let mut cases = 0;
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
        ] {
            for keep_unflushed in [false, true] {
                let m = MemDisk::from_image(pristine.clone());
                let mut f = FaultDevice::new(m.device(), spec);
                assert!(
                    prepare(&mut f, counter()).is_err(),
                    "{spec:?} must hit the fault"
                );
                m.crash(|_| keep_unflushed);
                let (part, _) = prepare(m.device().as_mut(), counter())
                    .unwrap_or_else(|err| panic!("{spec:?} keep={keep_unflushed}: {err:?}"));
                let mut d = m.device();
                let total = d.sectors();
                let p = read_table(d.as_mut(), 1).unwrap().unwrap();
                let b = read_table(d.as_mut(), total - 1).unwrap().unwrap();
                assert_eq!(p.entries, b.entries);
                assert_eq!(p.header.disk_guid, b.header.disk_guid);
                assert_eq!(
                    p.entries
                        .iter()
                        .filter(|x| x.type_guid == DATA_TYPE)
                        .count(),
                    1
                );
                assert_eq!(p.data_partition().unwrap().first_lba, part.first_lba);
                let esp_at = ALIGN as usize * 512;
                assert_eq!(m.raw(esp_at, e.len()), e, "{spec:?}: ESP changed");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, writes * 4);
}

#[test]
fn headers_with_any_changed_field_are_rejected() {
    let e = esp(64);
    let img = raw_image(&e).unwrap();
    let total = (img.len() / 512) as u64;
    let hdr = &img[512..1024];
    assert!(Header::decode(hdr, 1, total).is_some());
    for i in 0..92 {
        let mut h = hdr.to_vec();
        h[i] ^= 0x01;
        assert!(Header::decode(&h, 1, total).is_none(), "byte {i}");
    }
    // Right bytes, wrong place.
    assert!(Header::decode(hdr, 2, total).is_none());
}

#[test]
fn overlapping_or_out_of_range_entries_are_rejected() {
    let e = esp(64);
    let m = MemDisk::from_image(raw_image(&e).unwrap());
    let mut d = m.device();
    let t = read_table(d.as_mut(), 1).unwrap().unwrap();
    for bad in [
        vec![
            t.entries[0],
            Entry::new(DATA_TYPE, Guid([1; 16]), ALIGN + 10, ALIGN + 20, "x"),
        ],
        vec![Entry::new(DATA_TYPE, Guid([1; 16]), 1, 100, "x")],
        vec![Entry::new(DATA_TYPE, Guid([1; 16]), 3000, 2900, "x")],
    ] {
        let raw = encode_entries(&bad);
        let h = Header {
            entries_crc: crc32(&raw),
            ..t.header
        };
        d.write(2, &raw).unwrap();
        d.write(1, &h.encode()).unwrap();
        d.flush().unwrap();
        assert!(read_table(d.as_mut(), 1).unwrap().is_none(), "{bad:?}");
    }
}

#[test]
fn primary_guid_reads_identification_from_the_head() {
    let e = esp(64);
    let img = raw_image(&e).unwrap();
    let total = (img.len() / 512) as u64;
    let head = &img[512..(1 + HEAD_SECTORS as usize) * 512];
    let t = read_table(MemDisk::from_image(img.clone()).device().as_mut(), 1)
        .unwrap()
        .unwrap();
    assert_eq!(primary_guid(head, total), Some(t.header.disk_guid));
    let mut bad = head.to_vec();
    bad[600] ^= 1; // an entry byte: entries CRC fails
    assert_eq!(primary_guid(&bad, total), None);
    assert_eq!(primary_guid(&head[..512], total), None);
    assert_eq!(primary_guid(&[0u8; 17 * 1024], total), None);
}

/// The partition the first boot creates is formatted by the real layout
/// code (end to end on the host).
#[test]
fn the_new_partition_formats_and_reopens() {
    use crate::disk::{Disk, Opened};
    use crate::part::Partition;
    for size in [64 * MIB, 64 * MIB + 3 * 512, 100 * MIB + 512] {
        let m = disk(&esp(3000), size);
        let (part, _) = prepare(m.device().as_mut(), counter()).unwrap();
        let p = Partition::new(m.device(), part.first_lba, part.sectors()).unwrap();
        let (_, how) = Disk::open(Box::new(p), || [7; 16]).unwrap();
        assert_eq!(how, Opened::Formatted, "{size}");
        let p = Partition::new(m.device(), part.first_lba, part.sectors()).unwrap();
        let (_, how) = Disk::open(Box::new(p), || [8; 16]).unwrap();
        assert_eq!(how, Opened::Existing, "{size}");
    }
}

/// A valid primary whose backup at the end is gone (an interrupted
/// reinstall clears it first) gets its backup back.
#[test]
fn a_missing_backup_is_rewritten_from_the_primary() {
    let m = disk(&esp(3000), 64 * MIB);
    let (part, _) = prepare(m.device().as_mut(), counter()).unwrap();
    let mut img = m.raw(0, 64 * MIB);
    let end = img.len();
    img[end - 33 * 512..].fill(0);
    let m = MemDisk::from_image(img);
    let (again, steps) = prepare(m.device().as_mut(), counter()).unwrap();
    assert!(steps.repaired_backup && !steps.created_partition);
    assert_eq!(again, part);
    let last = (64 * MIB / 512 - 1) as u64;
    let b = read_table(m.device().as_mut(), last).unwrap().unwrap();
    assert_eq!(b.data_partition().unwrap().first_lba, part.first_lba);
}
