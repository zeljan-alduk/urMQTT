//! A/B boot slots (NEXT-11, ADR-295): the slot state, the entry names and the
//! table around them come from a disk that may be damaged or hostile, and the
//! build note from an image downloaded by the operator. The input patches the
//! entries of an A/B disk (with the CRCs fixed up, so the fuzzer reaches the
//! slot semantics), then drives the kernel's boot step and the operations on
//! it. Nothing may panic; whatever an operation writes must leave a table the
//! next read accepts, with one ESP and one standby of equal size, the regions
//! unmoved; the note decoder must accept only what it would write.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_store::MemDisk;
use urmqtt_store::gpt::{self, Guid, Options, crc32};
use urmqtt_store::slots::{self, Activation, Init, State};

const ESP_SECTORS: usize = 64;
const DISK_BYTES: usize = 24 << 20;

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

/// An A/B disk, prepared once per process (kept whole; each run rebuilds
/// its disk from the pieces that are not zero).
fn base() -> &'static [u8] {
    static BASE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let esp = vec![0x5au8; ESP_SECTORS * 512];
        let mut img = gpt::raw_image(&esp).unwrap();
        img.resize(DISK_BYTES, 0);
        let m = MemDisk::from_image(img);
        gpt::prepare_with(
            m.device().as_mut(),
            || [3; 16],
            Options {
                boot_slot: Some(Init {
                    label: "v0.6.0",
                    schema: 5,
                }),
            },
        )
        .unwrap();
        m.raw(0, DISK_BYTES)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    // The build note decoder on raw bytes: what it accepts encodes back to
    // the same note. (Not `build_note`, which writes this tree's protocol:
    // the decoder also reads a kernel of another protocol, which the tool
    // then refuses by name.)
    for n in slots::find_notes(rest) {
        assert_eq!(slots::parse_note(&n.encode()).as_ref(), Some(&n));
    }
    let _ = slots::parse_version(&String::from_utf8_lossy(rest));
    // Patches over the primary entry array (its first sector: the three
    // entries), then both copies made consistent so the slot code runs.
    // Only the tables and the first slot's region hold anything: the disk is
    // built from those pieces (fast), not copied whole.
    let base = base();
    let mut img = base.to_vec();
    let total = DISK_BYTES / 512;
    for p in rest.chunks_exact(2) {
        img[1024 + usize::from(p[0]) % 384] = p[1];
    }
    let entries: Vec<u8> = img[1024..1024 + 128 * 128].to_vec();
    let backup_entries = (total - 33) * 512;
    img[backup_entries..backup_entries + 128 * 128].copy_from_slice(&entries);
    fix_crcs(&mut img, 1);
    fix_crcs(&mut img, total - 1);
    let m = MemDisk::sparse(DISK_BYTES as u64);
    let mut dev = m.device();
    for (lba, n) in [(0, 34), (2048, ESP_SECTORS), (total - 33, 33)] {
        dev.write(lba as u64, &img[lba * 512..(lba + n) * 512])
            .unwrap();
    }
    dev.flush().unwrap();
    let before = gpt::read_table(dev.as_mut(), 1).ok().flatten();
    let Ok(Some(s)) = slots::read(dev.as_mut()) else {
        return;
    };
    let regions = |s: &slots::Slots| {
        let mut r = [s.active().first_lba, s.standby_slot().first_lba];
        r.sort_unstable();
        r
    };
    let start = regions(&s);
    let _ = slots::State::decode(s.table.entries[s.esp].attributes).encode();
    let schema = flags >> 4;
    let booted = match flags & 3 {
        0 => Some(s.esp_guid()),
        1 => Some(s.standby_guid()),
        2 => Some(Guid([flags; 16])),
        _ => None,
    };
    let r = match (flags >> 2) & 3 {
        0 => slots::boot_step(dev.as_mut(), booted, schema).map(|_| ()),
        1 => slots::confirm(dev.as_mut()).map(|_| ()),
        2 => slots::rollback(dev.as_mut()).map(|_| ()),
        _ => slots::activate(
            dev.as_mut(),
            Activation {
                tries: flags,
                one_way: flags & 1 != 0,
                retry: flags & 2 != 0,
            },
        )
        .map(|_| ()),
    };
    let after = slots::read(dev.as_mut())
        .expect("the table after an operation reads")
        .expect("still an A/B disk");
    assert_eq!(regions(&after), start, "regions moved");
    if r.is_err() {
        // A refusal writes nothing.
        assert_eq!(gpt::read_table(dev.as_mut(), 1).ok().flatten(), before);
    }
    let a = after.active();
    assert!(a.state.tries <= slots::MAX_TRIES);
    let _: State = a.state;
});
