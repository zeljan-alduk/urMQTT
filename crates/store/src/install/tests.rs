use super::*;
use crate::disk::MemDisk;
use crate::fault::{FaultDevice, FaultSpec};

const MIB: usize = 1 << 20;

fn esp() -> Vec<u8> {
    (0..8 * MIB).map(|i| (i * 31 % 251) as u8).collect()
}

fn disk(c: (u64, bool, bool)) -> Candidate {
    Candidate {
        sectors: c.0,
        read_only: c.1,
        boot_medium: c.2,
    }
}

#[test]
fn target_selection_rules() {
    let img = 10 * MIB as u64;
    let need = needed_sectors(img);
    let big = need;
    assert_eq!(choose(&[disk((big, false, false))], img), Choice::Target(0));
    // The boot medium, a read-only disk and a small one never qualify.
    let skip = [
        disk((big * 4, false, true)),
        disk((big * 4, true, false)),
        disk((need - 1, false, false)),
    ];
    assert_eq!(choose(&skip, img), Choice::None);
    let mut with_one = skip.to_vec();
    with_one.push(disk((big, false, false)));
    assert_eq!(choose(&with_one, img), Choice::Target(3));
    // Two possible targets: refuse, name both.
    let two = [disk((big, false, false)), disk((big * 2, false, false))];
    assert_eq!(choose(&two, img), Choice::Several(vec![0, 1]));
    assert_eq!(choose(&[], img), Choice::None);
}

/// The installed disk starts with exactly the bytes of the raw image
/// (`mkraw.py`-identical, tested in tests/gpt_mkraw.rs), whatever the disk
/// held before, and its first boot then works as for a `dd` of the image.
#[test]
fn installed_disk_is_the_raw_image_and_boots() {
    let e = esp();
    let img = gpt::raw_image(&e).unwrap();
    // A disk that held an older urMQTT install with data.
    let old = MemDisk::new(64 * MIB);
    let mut d = old.device();
    write_image(d.as_mut(), &esp()[..4 * MIB]).unwrap();
    gpt::prepare(d.as_mut(), || [3; 16]).unwrap();
    assert!(holds_urmqtt_data(d.as_mut()));
    let n = write_image(d.as_mut(), &e).unwrap();
    assert_eq!(n as usize, img.len());
    assert_eq!(old.raw(0, img.len()), img);
    // The old tables at the disk's end are gone.
    assert!(
        old.raw(64 * MIB - 33 * 512, 33 * 512)
            .iter()
            .all(|&b| b == 0)
    );
    assert!(!holds_urmqtt_data(d.as_mut()));
    let (part, steps) = gpt::prepare(d.as_mut(), || [4; 16]).unwrap();
    assert!(steps.moved_backup && steps.created_partition);
    assert!(part.first_lba as usize * 512 >= img.len() - MIB);
}

#[test]
fn too_small_or_bad_images_are_refused() {
    let small = MemDisk::new(12 * MIB);
    assert_eq!(
        write_image(small.device().as_mut(), &esp()),
        Err(InstallError::TooSmall)
    );
    assert!(
        small.raw(0, 12 * MIB).iter().all(|&b| b == 0),
        "nothing written"
    );
    let m = MemDisk::new(64 * MIB);
    assert_eq!(
        write_image(m.device().as_mut(), &[1, 2, 3]),
        Err(InstallError::BadImage)
    );
    assert_eq!(
        write_image(m.device().as_mut(), &[]),
        Err(InstallError::BadImage)
    );
}

/// A power cut at any write of the installation leaves either the old disk
/// untouched, or a disk without a valid primary GPT and without a backup
/// at its end: firmware does not boot it, and the first-boot code refuses
/// it. Installing again works.
#[test]
fn an_interrupted_install_never_boots_and_can_be_redone() {
    // Small sizes: the loop below copies the disk for every write.
    let e: Vec<u8> = esp()[..MIB].to_vec();
    let img = gpt::raw_image(&e).unwrap();
    let size = img.len() + 18 * MIB;
    // A disk that already booted once (its backup at the end, a data
    // partition): the worst case to leave half-overwritten.
    let base = MemDisk::new(size);
    write_image(base.device().as_mut(), &e).unwrap();
    gpt::prepare(base.device().as_mut(), || [5; 16]).unwrap();
    let start = base.raw(0, size);
    let probe = MemDisk::from_image(start.clone());
    let mut f = FaultDevice::new(probe.device(), FaultSpec::default());
    write_image(&mut f, &e).unwrap();
    let writes = f.writes();
    for n in 1..writes {
        for keep in [false, true] {
            let m = MemDisk::from_image(start.clone());
            let spec = FaultSpec {
                stop_after_writes: Some(n),
                ..FaultSpec::default()
            };
            let mut f = FaultDevice::new(m.device(), spec);
            assert!(
                write_image(&mut f, &e).is_err(),
                "write {n} must hit the fault"
            );
            m.crash(|_| keep);
            let mut d = m.device();
            let last = d.sectors() - 1;
            // Either the old install still boots with its ESP and data
            // untouched (only its backup table was cleared), or the disk
            // does not boot at all: never a mix of old and new.
            if gpt::read_table(d.as_mut(), 1).unwrap().is_some() {
                let esp_at = gpt::ALIGN as usize * 512;
                assert_eq!(
                    m.raw(esp_at, e.len()),
                    start[esp_at..esp_at + e.len()],
                    "write {n}"
                );
                let (part, steps) = gpt::prepare(d.as_mut(), || [6; 16]).unwrap();
                assert!(
                    !steps.created_partition,
                    "write {n}: the old data partition is kept"
                );
                assert!(
                    gpt::read_table(d.as_mut(), last).unwrap().is_some(),
                    "write {n}: backup repaired"
                );
                assert_eq!(
                    part,
                    gpt::prepare(base.device().as_mut(), || [7; 16]).unwrap().0
                );
            } else {
                assert!(
                    gpt::read_table(d.as_mut(), last).unwrap().is_none(),
                    "write {n}: backup at the end"
                );
                assert!(
                    gpt::prepare(d.as_mut(), || [6; 16]).is_err(),
                    "write {n}: boots"
                );
            }
            write_image(d.as_mut(), &e).unwrap();
            assert_eq!(m.raw(0, img.len()), img, "write {n}: reinstall");
        }
    }
}

/// The universal ISO's install module (X10) is a finished disk image: boot
/// code in sector 0 and data in the gap before the ESP must arrive byte for
/// byte, and an image that is not a GPT disk is refused before anything is
/// written.
#[test]
fn a_prebuilt_boot_image_is_written_verbatim_and_checked() {
    let mut img = gpt::raw_image(&esp()[..2 * MIB]).unwrap();
    // Boot code in the MBR (the partition table at 446.. stays) and a stage
    // in the gap between the tables and the ESP.
    for (i, b) in img.iter_mut().take(446).enumerate() {
        *b = (i % 253) as u8 + 1;
    }
    for (i, b) in img[34 * 512..2048 * 512].iter_mut().enumerate() {
        *b = (i % 249) as u8;
    }
    let m = MemDisk::new(64 * MIB);
    let n = write_boot_image(m.device().as_mut(), &img).unwrap();
    assert_eq!(n as usize, img.len());
    assert_eq!(m.raw(0, img.len()), img);

    let blank = MemDisk::new(64 * MIB);
    let mut no_header = img.clone();
    no_header[512] = b'X';
    let mut wrong_backup = img.clone();
    wrong_backup[512 + 32] ^= 1;
    let mut no_signature = img.clone();
    no_signature[510] = 0;
    for bad in [
        no_header,
        wrong_backup,
        no_signature,
        img[..img.len() - 512].to_vec(),
    ] {
        assert_eq!(
            write_boot_image(blank.device().as_mut(), &bad),
            Err(InstallError::BadImage)
        );
    }
    assert!(
        blank.raw(0, 64 * MIB).iter().all(|&b| b == 0),
        "nothing written"
    );
}

// --- the configuration slot (C1c, ADR-217) -------------------------------

use urmqtt_cfg::blob::{DISK_MARKER, SLOT_SIZE, SlotKind, make_slot};
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

fn slots() -> (Vec<u8>, Vec<u8>) {
    let empty = Builder::new().finish(false).unwrap();
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 9999).unwrap();
    let mine = b.finish(false).unwrap();
    let mut template = make_slot(SlotKind::Boot, &empty).unwrap();
    template[..16].copy_from_slice(&DISK_MARKER);
    (template, make_slot(SlotKind::Boot, &mine).unwrap())
}

/// An ESP with the template slot at a sector boundary, and some bytes that
/// look like the marker (the kernel carries the constant).
fn esp_with_template(template: &[u8]) -> Vec<u8> {
    let mut e = esp();
    e[3000..3016].copy_from_slice(&DISK_MARKER); // a stray marker, not a slot
    e[MIB..MIB + SLOT_SIZE].copy_from_slice(template);
    e
}

/// The installer puts the slot it booted with where the image's template slot
/// is, and the read-back compares the disk with the image as patched.
#[test]
fn the_installed_disk_carries_the_configuration_of_the_installer() {
    let (template, mine) = slots();
    let e = esp_with_template(&template);
    let m = MemDisk::new(64 * MIB);
    let n = write_image_with(m.device().as_mut(), &e, Some(&mine)).unwrap();
    let img = gpt::raw_image(&e).unwrap();
    assert_eq!(n as usize, img.len());
    let on_disk = m.raw(0, img.len());
    // Everything is the image's, except the slot, which is the installer's.
    let off = urmqtt_cfg::blob::find_slots(&img, SlotKind::Disk)[0];
    assert_eq!(&on_disk[off..off + SLOT_SIZE], &mine[..]);
    assert_eq!(&on_disk[..off], &img[..off]);
    assert_eq!(&on_disk[off + SLOT_SIZE..], &img[off + SLOT_SIZE..]);
    // Without a slot to carry, the image is written as it is.
    let plain = MemDisk::new(64 * MIB);
    write_image_with(plain.device().as_mut(), &e, None).unwrap();
    assert_eq!(plain.raw(0, img.len()), img);
    // The same through a finished boot image (the universal ISO's module).
    let whole = MemDisk::new(64 * MIB);
    write_boot_image_with(whole.device().as_mut(), &img, Some(&mine)).unwrap();
    assert_eq!(whole.raw(0, img.len()), on_disk);
}

/// A slot that is not a boot slot, or an image without exactly one template
/// slot, is refused before anything is written.
#[test]
fn a_missing_or_wrong_configuration_slot_writes_nothing() {
    let (template, mine) = slots();
    let blank = MemDisk::new(64 * MIB);
    // The image has no template slot.
    assert_eq!(
        write_image_with(blank.device().as_mut(), &esp(), Some(&mine)),
        Err(InstallError::NoConfigSlot)
    );
    // The image has two.
    let mut two = esp_with_template(&template);
    two[2 * MIB..2 * MIB + SLOT_SIZE].copy_from_slice(&template);
    assert_eq!(
        write_image_with(blank.device().as_mut(), &two, Some(&mine)),
        Err(InstallError::NoConfigSlot)
    );
    // The slot to carry is garbage, or the template itself.
    let one = esp_with_template(&template);
    for bad in [vec![0u8; SLOT_SIZE], template.clone(), mine[..100].to_vec()] {
        assert_eq!(
            write_image_with(blank.device().as_mut(), &one, Some(&bad)),
            Err(InstallError::NoConfigSlot)
        );
    }
    assert!(
        blank.raw(0, 64 * MIB).iter().all(|&b| b == 0),
        "nothing written"
    );
}

/// A power cut at any write of an installation that carries a slot still
/// leaves a disk that does not boot, never a half-new one that does: the slot
/// is written before the primary header, like the rest of the image.
#[test]
fn an_interrupted_install_with_a_slot_never_boots() {
    let (template, mine) = slots();
    // Small ESP: the loop below installs once per write.
    let mut e = esp()[..2 * MIB].to_vec();
    e[MIB / 2..MIB / 2 + SLOT_SIZE].copy_from_slice(&template);
    let probe = MemDisk::new(24 * MIB);
    let mut f = FaultDevice::new(probe.device(), FaultSpec::default());
    write_image_with(&mut f, &e, Some(&mine)).unwrap();
    let writes = f.writes();
    assert!(writes > 8, "{writes} writes");
    for n in 1..writes {
        let m = MemDisk::new(24 * MIB);
        let spec = FaultSpec {
            stop_after_writes: Some(n),
            ..FaultSpec::default()
        };
        let mut f = FaultDevice::new(m.device(), spec);
        assert!(
            write_image_with(&mut f, &e, Some(&mine)).is_err(),
            "write {n}"
        );
        m.crash(|_| true);
        let mut d = m.device();
        assert!(
            gpt::read_table(d.as_mut(), 1).unwrap().is_none(),
            "a cut after write {n} left a valid primary GPT"
        );
    }
}

/// LATER-6 (ADR-320): an installation image sealed for Secure Boot pins the configuration module
/// in its `limine.conf`. It is installed only with exactly that configuration; any other (or
/// none) would leave a disk its own loader refuses, so nothing is written.
#[test]
fn a_sealed_image_installs_only_its_own_configuration() {
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    let (template, mine) = slots();
    let (_, other) = {
        let mut b = Builder::new();
        b.uint(tag::NET_TLS_PORT, 7777).unwrap();
        let o = make_slot(SlotKind::Boot, &b.finish(false).unwrap()).unwrap();
        ((), o)
    };
    let seal = |e: &mut Vec<u8>, slot: &[u8]| {
        let conf = format!(
            "# Generated by scripts/mkiso.sh --universal. No menu\n    module_path: boot():/boot/urmqtt.cfg#{}\n# end of limine.conf\n",
            hex(&urmqtt_cfg::blake2b::hash(slot))
        );
        // Two copies, as the ESP has (EFI/BOOT and boot/limine).
        e[4096..4096 + conf.len()].copy_from_slice(conf.as_bytes());
        e[2 * MIB + 4096..2 * MIB + 4096 + conf.len()].copy_from_slice(conf.as_bytes());
    };
    let mut sealed = esp_with_template(&template);
    seal(&mut sealed, &mine);
    // Its own configuration: installed, and the disk holds it.
    let ok = MemDisk::new(64 * MIB);
    write_image_with(ok.device().as_mut(), &sealed, Some(&mine)).unwrap();
    let img = gpt::raw_image(&sealed).unwrap();
    write_boot_image_with(MemDisk::new(64 * MIB).device().as_mut(), &img, Some(&mine)).unwrap();
    // Another configuration, or none: refused before the first write.
    for (slot, what) in [(Some(&other[..]), "another"), (None, "none")] {
        let blank = MemDisk::new(64 * MIB);
        assert_eq!(
            write_image_with(blank.device().as_mut(), &sealed, slot),
            Err(InstallError::SealedToOther),
            "{what}"
        );
        assert_eq!(
            write_boot_image_with(blank.device().as_mut(), &img, slot),
            Err(InstallError::SealedToOther),
            "{what}"
        );
        assert!(
            blank.raw(0, 64 * MIB).iter().all(|&b| b == 0),
            "{what}: nothing written"
        );
    }
    // One copy of limine.conf changed to another pin is a refusal too (the loader reads either).
    let mut mixed = sealed.clone();
    let conf_other = format!("cfg#{}", hex(&urmqtt_cfg::blake2b::hash(&other)));
    let at = 2 * MIB
        + 4096
        + mixed[2 * MIB + 4096..]
            .windows(4)
            .position(|w| w == b"cfg#")
            .unwrap();
    mixed[at..at + conf_other.len()].copy_from_slice(conf_other.as_bytes());
    assert_eq!(
        write_image_with(
            MemDisk::new(64 * MIB).device().as_mut(),
            &mixed,
            Some(&mine)
        ),
        Err(InstallError::SealedToOther)
    );
    // An open image (no pin) takes any configuration, as before.
    write_image_with(
        MemDisk::new(64 * MIB).device().as_mut(),
        &esp_with_template(&template),
        Some(&other),
    )
    .unwrap();
}
