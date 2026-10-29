//! The boot disk's GPT (S1): headers and entries come from a disk that may
//! be damaged or hostile. The input patches a valid boot image on a larger
//! disk (byte patches over the tables, optionally with the CRCs fixed up
//! afterwards, so the fuzzer reaches the table semantics and not only the
//! checksums). Parsing must never panic, and when the first-boot steps
//! succeed, the next boot must accept the disk as it is (idempotent, both
//! copies valid and equal).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_store::MemDisk;
use urmqtt_store::gpt::{self, HEAD_SECTORS, crc32};

const SECTORS: usize = 40 * 1024;

fn fix_crcs(img: &mut [u8], header_lba: usize) {
    let h = header_lba * 512;
    let entries_lba = u64::from_le_bytes(img[h + 72..h + 80].try_into().unwrap());
    let range = usize::try_from(entries_lba)
        .ok()
        .and_then(|l| l.checked_mul(512))
        .and_then(|a| Some(a..a.checked_add(128 * 128)?));
    if let Some(e) = range.and_then(|r| img.get(r)) {
        let c = crc32(e);
        img[h + 88..h + 92].copy_from_slice(&c.to_le_bytes());
    }
    img[h + 16..h + 20].fill(0);
    let c = crc32(&img[h..h + 92]);
    img[h + 16..h + 20].copy_from_slice(&c.to_le_bytes());
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, patches)) = data.split_first() else {
        return;
    };
    let esp = vec![0x5au8; 512 * (1 + usize::from(flags >> 4))];
    let mut img = gpt::raw_image(&esp).unwrap();
    let image_len = img.len();
    if flags & 1 != 0 {
        img.resize(SECTORS * 512, 0);
    }
    let total = (img.len() / 512) as u64;
    // Patches: (u16 offset into the first 34 sectors or, with the high bit,
    // into the image's last 33 sectors) and a byte.
    for p in patches.chunks_exact(3) {
        let off = usize::from(u16::from_le_bytes([p[0], p[1]]));
        let at = if off & 0x8000 != 0 {
            image_len - 33 * 512 + (off & 0x7fff) % (33 * 512)
        } else {
            off % (34 * 512)
        };
        img[at] = p[2];
    }
    if flags & 2 != 0 {
        fix_crcs(&mut img, 1);
    }
    if flags & 4 != 0 {
        fix_crcs(&mut img, image_len / 512 - 1);
    }
    let _ = gpt::primary_guid(&img[512..(1 + HEAD_SECTORS as usize) * 512], total);
    let m = MemDisk::from_image(img);
    let mut dev = m.device();
    let _ = gpt::read_table(dev.as_mut(), 1);
    let _ = gpt::read_table(dev.as_mut(), total - 1);
    let mut k = 0u8;
    let random = || {
        k = k.wrapping_add(1);
        [k; 16]
    };
    if let Ok((part, _)) = gpt::prepare(dev.as_mut(), random) {
        let p = gpt::read_table(dev.as_mut(), 1)
            .unwrap()
            .expect("primary valid");
        let b = gpt::read_table(dev.as_mut(), total - 1)
            .unwrap()
            .expect("backup valid");
        assert_eq!(p.entries, b.entries);
        assert_eq!(p.header.disk_guid, b.header.disk_guid);
        assert!(part.last_lba < p.header.backup_lba);
        let (again, steps) = gpt::prepare(dev.as_mut(), || [9; 16]).expect("second boot");
        assert_eq!(again, part);
        assert_eq!(steps, gpt::Steps::default(), "not idempotent");
    }
});
