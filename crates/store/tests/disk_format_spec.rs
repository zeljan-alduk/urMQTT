//! docs/DISK-FORMAT.md against the code (STORAGE-PLAN S0).
//!
//! Every table marked `<!-- struct: NAME size=N -->` in the spec is parsed.
//! Each structure is then encoded by the real code with distinctive values,
//! and the test checks both directions:
//! - every listed field holds the expected bytes at its offset;
//! - every non-zero byte the encoder wrote belongs to a listed field.
//!
//! A field added to the code without the spec, or to the spec without the
//! code, fails here.

use std::collections::BTreeMap;

use urmqtt_store::crc::{crc32c, update};
use urmqtt_store::layout::{BLOCK, Layout, Params, RegionKind, SECTOR, SizeTable, v1};
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{Disk, MemDisk};

const SPEC: &str = include_str!("../../../docs/DISK-FORMAT.md");

#[derive(Debug, Clone)]
struct Field {
    offset: String,
    size: String,
    kind: String,
    name: String,
}

/// struct name → (declared size, fields in table order).
fn spec() -> BTreeMap<String, (String, Vec<Field>)> {
    let mut out = BTreeMap::new();
    let lines: Vec<&str> = SPEC.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().strip_prefix("<!-- struct: ") else {
            continue;
        };
        let rest = rest.trim_end_matches("-->").trim();
        let (name, size) = rest
            .split_once(" size=")
            .expect("struct marker: NAME size=N");
        let mut fields = Vec::new();
        // The table follows: header, separator, then rows until a non-table line.
        for row in lines.iter().skip(i + 3) {
            let row = row.trim();
            if !row.starts_with('|') {
                break;
            }
            let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
            assert!(cells.len() >= 4, "bad row in {name}: {row}");
            fields.push(Field {
                offset: cells[0].to_string(),
                size: cells[1].to_string(),
                kind: cells[2].to_string(),
                name: cells[3].to_string(),
            });
        }
        assert!(!fields.is_empty(), "struct {name} has no fields");
        out.insert(name.to_string(), (size.to_string(), fields));
    }
    out
}

/// Evaluates an offset or size cell: integers, `+`, `-` and the variables
/// given (e.g. `18+topic_len`, `len-10-topic_len`).
fn eval(expr: &str, vars: &BTreeMap<&str, usize>) -> usize {
    let mut total: i64 = 0;
    let mut sign = 1;
    let mut term = String::new();
    let flush = |term: &mut String, sign: i64, total: &mut i64| {
        if term.is_empty() {
            return;
        }
        let v = term.parse::<i64>().unwrap_or_else(|_| {
            *vars
                .get(term.as_str())
                .unwrap_or_else(|| panic!("unknown variable {term} in {expr}")) as i64
        });
        *total += sign * v;
        term.clear();
    };
    for c in expr.chars() {
        match c {
            '+' | '-' => {
                flush(&mut term, sign, &mut total);
                sign = if c == '+' { 1 } else { -1 };
            }
            c if c.is_whitespace() => {}
            c => term.push(c),
        }
    }
    flush(&mut term, sign, &mut total);
    usize::try_from(total).expect("non-negative")
}

/// Checks `bytes` against the spec of `name` with `expect` (field → bytes).
/// Fields of type `region[]` repeat a sub-struct; their expected bytes are
/// given whole.
fn check(name: &str, bytes: &[u8], expect: &BTreeMap<&str, Vec<u8>>, vars: &BTreeMap<&str, usize>) {
    let spec = spec();
    let (size, fields) = spec
        .get(name)
        .unwrap_or_else(|| panic!("struct {name} not in spec"));
    if size != "variable" {
        assert_eq!(bytes.len(), size.parse::<usize>().unwrap(), "{name}: size");
    }
    let mut covered = vec![false; bytes.len()];
    for f in fields {
        let off = eval(&f.offset, vars);
        let want = expect.get(f.name.as_str()).unwrap_or_else(|| {
            panic!(
                "{name}.{}: in the spec but not checked here (add it)",
                f.name
            )
        });
        let len = if f.kind.ends_with("[]") {
            want.len()
        } else {
            eval(&f.size, vars)
        };
        assert_eq!(
            want.len(),
            len,
            "{name}.{}: spec size {} vs expected value",
            f.name,
            f.size
        );
        let got = bytes
            .get(off..off + len)
            .unwrap_or_else(|| panic!("{name}.{}: beyond the structure", f.name));
        assert_eq!(got, &want[..], "{name}.{} at offset {off}", f.name);
        for c in covered.iter_mut().skip(off).take(len) {
            assert!(!*c, "{name}.{}: overlaps another field", f.name);
            *c = true;
        }
    }
    for k in expect.keys() {
        assert!(
            fields.iter().any(|f| f.name == *k),
            "{name}.{k}: checked here but missing from the spec"
        );
    }
    for (i, b) in bytes.iter().enumerate() {
        assert!(
            covered[i] || *b == 0,
            "{name}: byte {i} = {b:#04x} is written but in no spec field"
        );
    }
}

fn le32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn le64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn crc_of(b: &[u8], n: usize) -> Vec<u8> {
    le32(crc32c(&b[..n - 4]))
}

#[test]
fn crc32c_matches_the_spec_check_value() {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
}

#[test]
fn superblock_and_region_entries() {
    let uuid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0,
        0x01,
    ];
    let total = 4 * 1024 * 1024 * 1024 / SECTOR; // 4 GiB
    let params = Params {
        partitions: 12,
        align_sectors: 4096,
    };
    let mut l = Layout::plan(total, uuid, params).unwrap();
    // A grown disk has extra extents and a higher generation; the legacy
    // flag is set by migration only. Exercise every field.
    l = l.grown(total + 40960, 50, 0).unwrap().unwrap();
    // Layout v2.1: the backup region carved from the database's tail.
    l = l.with_backup(0).unwrap();
    assert_eq!(l.minor, urmqtt_store::layout::MINOR);
    l.flags = urmqtt_store::layout::FLAG_LEGACY_TELEMETRY;
    let b = l.encode();
    let mut regions = Vec::new();
    for (i, r) in l.regions.iter().enumerate() {
        let entry = b[64 + 24 * i..64 + 24 * (i + 1)].to_vec();
        let mut e = BTreeMap::new();
        e.insert("kind", le32(r.kind as u32));
        e.insert("start", le64(r.start));
        e.insert("sectors", le64(r.sectors));
        check("region", &entry, &e, &BTreeMap::new());
        regions.extend(entry);
    }
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQTTDK".to_vec());
    e.insert("version", le32(2));
    e.insert("region_count", le32(l.regions.len() as u32));
    e.insert("uuid", uuid.to_vec());
    e.insert("total_sectors", le64(l.total_sectors));
    e.insert("generation", le64(l.generation));
    e.insert("partitions", le32(12));
    e.insert("align_sectors", le32(4096));
    e.insert("flags", le32(1));
    e.insert("minor", le32(1));
    e.insert("regions", regions);
    e.insert("crc", crc_of(&b, BLOCK));
    check("superblock", &b, &e, &BTreeMap::new());
    assert_eq!(Layout::decode(&b, l.total_sectors).unwrap(), Some(l));
}

/// The frozen layout-v1 superblock (read by `urmqtt-disk migrate` only).
#[test]
fn superblock_v1() {
    let uuid = [7u8; 16];
    let total = 4 * 1024 * 1024 * 1024 / SECTOR;
    let l = v1::plan(total, uuid).unwrap();
    let b = v1::encode(&l);
    let mut regions = Vec::new();
    for (i, r) in l.regions.iter().enumerate() {
        let entry = b[40 + 24 * i..40 + 24 * (i + 1)].to_vec();
        let mut e = BTreeMap::new();
        e.insert("kind", le32(r.kind as u32));
        e.insert("start", le64(r.start));
        e.insert("sectors", le64(r.sectors));
        check("region", &entry, &e, &BTreeMap::new());
        regions.extend(entry);
    }
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQTTDK".to_vec());
    e.insert("version", le32(1));
    e.insert("region_count", le32(l.regions.len() as u32));
    e.insert("uuid", uuid.to_vec());
    e.insert("total_sectors", le64(total));
    e.insert("regions", regions);
    e.insert("crc", crc_of(&b, BLOCK));
    check("superblock_v1", &b, &e, &BTreeMap::new());
}

#[test]
fn region_plan_follows_the_spec_formula() {
    const MIB: u64 = 1024 * 1024 / SECTOR;
    let align_down = |x: u64, a: u64| x - x % a;
    for (a, parts) in [(MIB, 8), (4 * MIB, 8), (MIB, 24)] {
        for total in [32 * 1024, 64 * MIB, 16 * 1024 * MIB, 1024 * 1024 * MIB] {
            if a > MIB && total < 64 * MIB {
                continue;
            }
            let p = Params {
                partitions: parts,
                align_sectors: a as u32,
            };
            let l = Layout::plan(total, [7; 16], p).unwrap();
            let end = align_down(total - 8, a);
            let usable = end - a;
            let journal = a.max(MIB.div_ceil(a) * a);
            let wal = align_down((usable / 8).clamp(2 * MIB, 64 * MIB), a).max(a);
            let db = align_down(usable / 2, a);
            let tel = usable - journal - wal - db;
            let want = [
                (RegionKind::Db, a, db),
                (RegionKind::Wal, a + db, wal),
                (RegionKind::Journal, a + db + wal, journal),
                (RegionKind::Telemetry, a + db + wal + journal, tel),
                (RegionKind::Scratch, total - 8, 8),
            ];
            let got: Vec<_> = l
                .regions
                .iter()
                .map(|r| (r.kind, r.start, r.sectors))
                .collect();
            assert_eq!(got, want, "total {total} align {a}");
            assert_eq!(l.partitions, parts);
            assert_eq!(l.generation, 1);
        }
    }
    // A size that is not a multiple of 4 KiB is rounded down (spec §2, G7).
    let r = Layout::plan(32 * 1024 + 5, [7; 16], Params::default()).unwrap();
    assert_eq!(r.total_sectors, 32 * 1024);
}

#[test]
fn size_table() {
    let t = SizeTable {
        seq: 0x0102_0304_0506_0708,
        sizes: [4096 * 3, 4128, 0],
    };
    let b = t.encode();
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQSZT1".to_vec());
    e.insert("seq", le64(t.seq));
    e.insert("file_count", le32(3));
    e.insert("size_db", le64(t.sizes[0]));
    e.insert("size_wal", le64(t.sizes[1]));
    e.insert("size_journal", le64(t.sizes[2]));
    e.insert("crc", crc_of(&b, BLOCK));
    check("size_table", &b, &e, &BTreeMap::new());
    // Slot rules: the higher seq wins, slot A on a tie, next write alternates.
    let a = SizeTable {
        seq: 5,
        sizes: [1, 0, 0],
    };
    let bb = SizeTable {
        seq: 5,
        sizes: [2, 0, 0],
    };
    assert_eq!(SizeTable::newest(Some(a), Some(bb)), Some(a));
    assert_eq!(
        SizeTable::newest(Some(a), Some(SizeTable { seq: 6, ..bb }))
            .unwrap()
            .seq,
        6
    );
    assert_eq!(a.next_slot(), 0);
    assert_eq!(SizeTable { seq: 6, ..a }.next_slot(), 1);
}

/// A backup snapshot slot's header and the backup control block (S5).
#[test]
fn backup_slot_header_and_control_block() {
    use urmqtt_store::backup::{Control, SlotHeader};
    let uuid = [0x5a; 16];
    let h = SlotHeader {
        seq: 0x0102_0304_0506_0708,
        created: 1_761_696_000,
        schema_version: 3,
        page_size: 4096,
        page_count: 300,
        payload_bytes: 300 * 4096,
        payload_crc: 0xdead_beef,
    };
    let b = h.encode(&uuid);
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQBKP1".to_vec());
    e.insert("seq", le64(h.seq));
    e.insert("created", le64(h.created));
    e.insert("uuid", uuid.to_vec());
    e.insert("schema_version", le32(3));
    e.insert("page_size", le32(4096));
    e.insert("page_count", le64(300));
    e.insert("payload_bytes", le64(300 * 4096));
    e.insert("payload_crc", le32(0xdead_beef));
    e.insert("crc", crc_of(&b, BLOCK));
    check("backup_slot_header", &b, &e, &BTreeMap::new());
    assert_eq!(SlotHeader::decode(&b, &uuid, 1 << 30), Some(h));
    // Another disk's snapshot, or one that does not fit, is not valid.
    assert_eq!(SlotHeader::decode(&b, &[0; 16], 1 << 30), None);
    assert_eq!(SlotHeader::decode(&b, &uuid, 1000), None);

    let c = Control {
        seq: 0x1122_3344_5566_7788,
        restoring: Some((1, 0x99aa_bbcc)),
    };
    let b = c.encode(&uuid);
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQBKC1".to_vec());
    e.insert("seq", le64(c.seq));
    e.insert("uuid", uuid.to_vec());
    e.insert("state", le32(1));
    e.insert("slot", le32(1));
    e.insert("backup_seq", le64(0x99aa_bbcc));
    e.insert("crc", crc_of(&b, BLOCK));
    check("backup_control", &b, &e, &BTreeMap::new());
    assert_eq!(Control::decode(&b, &uuid), Some(c));
    assert_eq!(Control::decode(&b, &[1; 16]), None);
}

#[test]
fn migration_record() {
    let r = urmqtt_store::mig::Record {
        seq: 0x0102_0304_0506_0708,
        state: urmqtt_store::mig::COPIED,
        v1_crc: 0xaabb_ccdd,
        v2_crc: 0x1122_3344,
    };
    let b = r.encode();
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQMIG1".to_vec());
    e.insert("seq", le64(r.seq));
    e.insert("state", le32(2));
    e.insert("v1_crc", le32(r.v1_crc));
    e.insert("v2_crc", le32(r.v2_crc));
    e.insert("crc", crc_of(&b, BLOCK));
    check("migration_record", &b, &e, &BTreeMap::new());
    // The fixed places the spec names.
    assert_eq!(urmqtt_store::mig::BACKUP_LBA, 32);
    assert_eq!(urmqtt_store::mig::STATE_LBA, [40, 48]);
    assert_eq!(urmqtt_store::layout::SB_SLOT_LBA, [0, 24]);
    assert_eq!(urmqtt_store::layout::SIZE_SLOT_LBA, [8, 16]);
}

#[test]
fn telemetry_header_segment_header_and_record() {
    let m = MemDisk::new(64 << 20);
    let (mut disk, _) = Disk::open(m.device(), || [3; 16]).unwrap();
    let now = 1_761_696_000;
    let (mut log, _) = TelemetryLog::open(&mut disk, now, 30 * 86_400_000).unwrap();
    let (topic, payload, ts) = (
        "devices/device-001/telemetry/temp",
        b"21.5".as_slice(),
        1_761_696_000_123u64,
    );
    log.append(&mut disk, 0, ts, topic, payload).unwrap();
    log.flush(&mut disk).unwrap();

    let region = disk.region(RegionKind::Telemetry).unwrap();
    let base = (region.start * SECTOR) as usize;
    let region_bytes = region.sectors * SECTOR;

    // Log header, with the geometry recomputed from the spec formula.
    let part = (region_bytes - 4096) / 8;
    let seg = (part / 8).clamp(64 * 1024, 8 * 1024 * 1024) / 4096 * 4096;
    let segments = part / seg;
    let h = m.raw(base, BLOCK);
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQTLH1".to_vec());
    e.insert("version", le32(2));
    e.insert("partitions", le32(8));
    e.insert("segment_bytes", le64(seg));
    e.insert("segments", le64(segments));
    e.insert("crc", crc_of(&h, BLOCK));
    check("telemetry_header", &h, &e, &BTreeMap::new());

    // Segment 0 of partition 0.
    let s0 = base + 4096;
    let sh = m.raw(s0, SECTOR as usize);
    let mut e = BTreeMap::new();
    e.insert("magic", b"URMQTSG1".to_vec());
    e.insert("partition", le32(0));
    e.insert("seq", le64(1));
    e.insert("created", le64(now));
    e.insert("uuid", disk.layout().uuid.to_vec());
    e.insert("crc", crc_of(&sh, SECTOR as usize));
    check("segment_header", &sh, &e, &BTreeMap::new());

    // The record, and the CRC as the spec defines it (salted with seq).
    let rec_len = 18 + topic.len() + payload.len();
    let r = m.raw(s0 + SECTOR as usize, rec_len);
    let len = 10 + topic.len() + payload.len();
    let mut e = BTreeMap::new();
    e.insert("len", le32(len as u32));
    e.insert("crc", le32(update(crc32c(&1u64.to_le_bytes()), &r[8..])));
    e.insert("ts_ms", le64(ts));
    e.insert("topic_len", (topic.len() as u16).to_le_bytes().to_vec());
    e.insert("topic", topic.as_bytes().to_vec());
    e.insert("payload", payload.to_vec());
    let vars = BTreeMap::from([("topic_len", topic.len()), ("len", len)]);
    check("record", &r, &e, &vars);
    // Zero padding to the sector end, then the clean end marker.
    assert!(
        m.raw(s0 + SECTOR as usize + rec_len, SECTOR as usize - rec_len)
            .iter()
            .all(|&b| b == 0)
    );
}

/// Regenerates the seeds of the `disk_layout` fuzz target
/// (`WRITE_FUZZ_SEEDS=1 cargo test -p urmqtt-store --test disk_format_spec -- --ignored`).
/// Each seed is the disk size (8 bytes), then the first slot, then a second slot.
#[test]
#[ignore = "writes files under fuzz/seeds"]
fn fuzz_seeds_for_disk_layout() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/disk_layout");
    let total = 64 * 1024 * 1024 / SECTOR;
    let a = Layout::plan(total, [3; 16], Params::default()).unwrap();
    let grown = a.grown(total * 4, 50, 0).unwrap().unwrap();
    let old = v1::encode(&v1::plan(total, [4; 16]).unwrap());
    let seed = |first: &[u8], second: &[u8]| {
        let mut s = (total * 4).to_le_bytes().to_vec();
        s.extend_from_slice(first);
        s.extend_from_slice(second);
        s
    };
    let files = [
        ("superblock-v2-64m", seed(&a.encode(), &[0u8; BLOCK])),
        (
            "superblock-v2-grown-pair",
            seed(&a.encode(), &grown.encode()),
        ),
        ("superblock-v1-64m", seed(&old, &grown.encode())),
    ];
    if std::env::var_os("WRITE_FUZZ_SEEDS").is_none() {
        panic!("set WRITE_FUZZ_SEEDS=1 to write the seeds");
    }
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
