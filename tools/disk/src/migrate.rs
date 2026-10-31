//! Offline migration of a layout-v1 data partition to layout v2
//! (STORAGE-PLAN S2, ADR-141).
//!
//! The device given to every function is the **data partition's window**
//! (LBA 0 = the layout's first sector). The kernel never calls any of this;
//! it refuses a v1 disk before writing anything.
//!
//! **What moves.** The live bytes of the SQLite database, the WAL and the
//! journal are copied into new, 1 MiB aligned regions carved out of the dead
//! tail of the old database region (the live database sits at its head), so
//! no source byte is overwritten before the switch: copy-then-switch. The
//! telemetry ring stays where it is, as extent 0 of the new layout (flag
//! `legacy telemetry`), and the space the old files leave becomes database
//! extents. The v1 header and the new superblock share no block: slot B
//! (LBA 24) is free in v1, slot A (LBA 0) holds v1.
//!
//! **Order of writes** (each flushed): the rollback file (host), the saved v1
//! superblock (LBA 32) and state `planned`; the copies, read back and
//! compared, then state `copied`; **slot B := v2 (the switch)**, state
//! `switched`; slot A := v2 (so no v1 reader opens the disk), state `done`.
//! Until slot B is complete and valid the disk is a valid v1 disk; from then
//! on it is a valid v2 disk. `resume` finishes from the recorded state;
//! `rollback` returns to v1.

use std::io::Write as _;
use std::path::Path;

use urmqtt_store::crc::crc32c;
use urmqtt_store::layout::{
    BLOCK, FLAG_LEGACY_TELEMETRY, FileKind, Layout, MIB_SECTORS, Region, RegionKind, SB_SLOT_LBA,
    SIZE_SLOT_LBA, SizeTable, v1,
};
use urmqtt_store::mig::{self, Record};
use urmqtt_store::{BlockDevice, Disk};

use crate::dev::{Overlay, Shared};
use crate::host;

type Res<T> = Result<T, String>;

const CHUNK: usize = 256 << 10;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Alignment unit of the new regions, sectors (a multiple of 1 MiB).
    pub align_sectors: u32,
    /// Open the database with SQLite in the preconditions and the
    /// verification (off only for fixtures that hold no real database).
    pub check_db: bool,
    /// Roll back a migration that already switched (the v1 data is then
    /// the state before the migration; later changes are lost).
    pub force: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            align_sectors: MIB_SECTORS as u32,
            check_db: true,
            force: false,
        }
    }
}

/// What a migration would do.
#[derive(Debug, Clone)]
pub struct Plan {
    pub v1: Layout,
    pub sizes: SizeTable,
    pub v1_sb: [u8; BLOCK],
    pub v2: Layout,
    /// Logical bytes copied per file (database, WAL, journal).
    pub copies: [u64; 3],
    pub bytes_to_copy: u64,
    /// Sectors free for the new regions (the dead tail of the old database
    /// region) and sectors the new regions need at least.
    pub free_sectors: u64,
    pub needed_sectors: u64,
    /// Sectors of old space that become database extents.
    pub reclaimed_sectors: u64,
}

fn name(kind: RegionKind) -> &'static str {
    match kind {
        RegionKind::Db => "database",
        RegionKind::Wal => "wal",
        RegionKind::Journal => "journal",
        RegionKind::Telemetry => "telemetry",
        RegionKind::Scratch => "scratch",
        RegionKind::Backup => "backup",
    }
}

fn state_name(s: u32) -> &'static str {
    match s {
        mig::PLANNED => "planned",
        mig::COPIED => "copied",
        mig::SWITCHED => "switched",
        mig::DONE => "done",
        _ => "?",
    }
}

const fn align_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

const fn align_down(x: u64, a: u64) -> u64 {
    x - x % a
}

fn io<T>(r: Result<T, urmqtt_store::IoError>, what: &str) -> Res<T> {
    r.map_err(|e| format!("{what}: {e:?}"))
}

pub fn read_block(dev: &mut dyn BlockDevice, lba: u64) -> Res<[u8; BLOCK]> {
    let mut b = [0u8; BLOCK];
    io(dev.read(lba, &mut b), &format!("read LBA {lba}"))?;
    Ok(b)
}

/// One metadata block, written and flushed.
fn put(dev: &mut dyn BlockDevice, lba: u64, b: &[u8; BLOCK]) -> Res<()> {
    io(dev.write(lba, b), &format!("write LBA {lba}"))?;
    io(dev.flush(), "flush")
}

pub fn read_sizes(dev: &mut dyn BlockDevice) -> Res<SizeTable> {
    let a = SizeTable::decode(&read_block(dev, SIZE_SLOT_LBA[0])?);
    let b = SizeTable::decode(&read_block(dev, SIZE_SLOT_LBA[1])?);
    SizeTable::newest(a, b).ok_or_else(|| "both size-table slots are invalid".to_string())
}

/// The newest valid migration state block, if any.
pub fn read_record(dev: &mut dyn BlockDevice) -> Res<Option<Record>> {
    let a = Record::decode(&read_block(dev, mig::STATE_LBA[0])?);
    let b = Record::decode(&read_block(dev, mig::STATE_LBA[1])?);
    Ok(Record::newest(a, b))
}

fn write_record(dev: &mut dyn BlockDevice, r: &Record) -> Res<()> {
    put(dev, mig::STATE_LBA[(r.seq % 2) as usize], &r.encode())
}

fn sectors_of(bytes: u64) -> u64 {
    align_up(bytes.div_ceil(512), 8)
}

/// Plans the migration of the v1 disk whose superblock block is `v1_sb`:
/// where the new regions go, what is copied, what is reclaimed. Reads the
/// size table; writes nothing.
pub fn plan(dev: &mut dyn BlockDevice, v1_sb: &[u8; BLOCK], opts: &Options) -> Res<Plan> {
    let total = dev.sectors();
    let l1 = v1::decode(v1_sb, total)
        .map_err(|e| format!("not a valid layout-v1 superblock: {e:?}"))?
        .ok_or("the data partition is blank")?;
    let st = read_sizes(dev)?;
    let a = u64::from(opts.align_sectors);
    if a < MIB_SECTORS || !a.is_multiple_of(MIB_SECTORS) || a > 131_072 {
        return Err("the alignment must be a whole number of MiB, at most 64".into());
    }
    let one = |k: RegionKind| -> Res<Region> {
        let mut it = l1.extents(k);
        match (it.next(), it.next()) {
            (Some(r), None) => Ok(r),
            _ => Err(format!("the v1 layout has no single {} region", name(k))),
        }
    };
    let (db1, wal1, jrn1, tel1) = (
        one(RegionKind::Db)?,
        one(RegionKind::Wal)?,
        one(RegionKind::Journal)?,
        one(RegionKind::Telemetry)?,
    );
    let scr1 = one(RegionKind::Scratch)?;
    let live = [
        st.sizes.first().copied().unwrap_or(0),
        st.sizes.get(1).copied().unwrap_or(0),
        st.sizes.get(2).copied().unwrap_or(0),
    ];
    for (i, (r, k)) in [(db1, "database"), (wal1, "wal"), (jrn1, "journal")]
        .iter()
        .enumerate()
    {
        if live[i] > r.bytes() {
            return Err(format!("the {k} size in the size table exceeds its region"));
        }
    }
    // The dead tail of the old database region: after the live head, up to
    // the old WAL region, in whole alignment units.
    let lo = align_up(db1.start + sectors_of(live[0]), a);
    let hi = align_down(db1.end(), a);
    let free = hi.saturating_sub(lo);
    let jrn_n = align_up(MIB_SECTORS, a);
    let wal_min = align_up(sectors_of(live[1]).max(2 * MIB_SECTORS), a);
    let db_min = align_up(sectors_of(live[0]), a).max(a);
    let needed = jrn_n + wal_min + db_min;
    if free < needed {
        return Err(format!(
            "not enough free space for the new regions: need at least {} MiB inside the old database region after its live data, have {} MiB; \
             grow the volume (docs/DEPLOY.md) and run the migration again",
            host::mib(needed),
            host::mib(free)
        ));
    }
    let wal_n = align_down(wal1.sectors, a)
        .max(wal_min)
        .min(free - jrn_n - db_min);
    let db_n = free - jrn_n - wal_n;
    let mut regions = vec![Region {
        kind: RegionKind::Db,
        start: lo + jrn_n + wal_n,
        sectors: db_n,
    }];
    // Old space that becomes database extents: the part of the old WAL and
    // journal area up to the telemetry ring (whole units), then the head of
    // the old database region. A touching extent extends the previous one.
    let mut reclaimed = 0;
    let r2 = (align_up(wal1.start, a), align_down(tel1.start, a));
    let r1 = (a, lo);
    for (s, e) in [r2, r1] {
        if e >= s + a {
            let last = regions.last_mut().filter(|r| r.end() == s);
            match last {
                Some(prev) => prev.sectors += e - s,
                None => regions.push(Region {
                    kind: RegionKind::Db,
                    start: s,
                    sectors: e - s,
                }),
            }
            reclaimed += e - s;
        }
    }
    regions.push(Region {
        kind: RegionKind::Wal,
        start: lo + jrn_n,
        sectors: wal_n,
    });
    regions.push(Region {
        kind: RegionKind::Journal,
        start: lo,
        sectors: jrn_n,
    });
    regions.push(tel1);
    regions.push(scr1);
    let v2 = Layout {
        uuid: l1.uuid,
        total_sectors: l1.total_sectors,
        regions,
        partitions: l1.partitions,
        align_sectors: opts.align_sectors,
        minor: 0,
        generation: 1,
        flags: FLAG_LEGACY_TELEMETRY,
    };
    v2.validate()
        .map_err(|e| format!("the planned v2 layout is invalid: {e:?}"))?;
    Ok(Plan {
        v1: l1,
        sizes: st,
        v1_sb: *v1_sb,
        v2,
        copies: live,
        bytes_to_copy: live.iter().sum(),
        free_sectors: free,
        needed_sectors: needed,
        reclaimed_sectors: reclaimed,
    })
}

impl Plan {
    /// The plan as text (the dry run).
    pub fn describe(&self) -> String {
        use std::fmt::Write as _;
        let mut o = String::new();
        let _ = writeln!(
            o,
            "layout v1 -> v2 (alignment {} MiB)",
            host::mib(u64::from(self.v2.align_sectors))
        );
        let _ = writeln!(o, "old regions (partition sectors):");
        for r in &self.v1.regions {
            let _ = writeln!(
                o,
                "  {:<9} {:>10} .. {:>10}  {:>6} MiB",
                name(r.kind),
                r.start,
                r.end(),
                host::mib(r.sectors)
            );
        }
        let _ = writeln!(o, "new regions:");
        for r in &self.v2.regions {
            let _ = writeln!(
                o,
                "  {:<9} {:>10} .. {:>10}  {:>6} MiB",
                name(r.kind),
                r.start,
                r.end(),
                host::mib(r.sectors)
            );
        }
        let _ = writeln!(
            o,
            "copied: database {} B, wal {} B, journal {} B = {} B; the telemetry ring stays in place (4 KiB aligned, not 1 MiB aligned)",
            self.copies[0], self.copies[1], self.copies[2], self.bytes_to_copy
        );
        let _ = writeln!(
            o,
            "free space needed {} MiB (dead tail of the old database region), available {} MiB; {} MiB of old space become database extents",
            host::mib(self.needed_sectors),
            host::mib(self.free_sectors),
            host::mib(self.reclaimed_sectors)
        );
        o
    }
}

/// What a finished or resumed run did.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub steps: Vec<String>,
    pub bytes_copied: u64,
}

/// The v2 superblock images: slot B (generation 1) and slot A (generation 2).
fn v2_blocks(plan: &Plan) -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut a = plan.v2.clone();
    a.generation = 2;
    (plan.v2.encode(), a.encode())
}

/// Checks everything that must hold before the first write; returns notes.
pub fn preconditions(dev: &Shared, plan: &Plan, opts: &Options) -> Res<Vec<String>> {
    let mut notes = Vec::new();
    if plan.copies[2] != 0 {
        return Err(format!(
            "the rollback journal holds {} byte(s): boot the old image once so SQLite recovers it, power off cleanly, then migrate",
            plan.copies[2]
        ));
    }
    if plan.copies[1] != 0 {
        notes.push(format!(
            "the WAL holds {} byte(s): it is copied as it is and replayed by the next boot",
            plan.copies[1]
        ));
    }
    // verify, on a copy-on-write view: nothing is written to the disk.
    let ov = Overlay::new(Box::new(dev.clone()));
    let mut disk = Disk::with_layout(Box::new(ov.view()), plan.v1.clone(), plan.sizes, 0);
    let t = host::telemetry_digest(&mut disk).map_err(|e| format!("verify: {e}"))?;
    notes.push(format!(
        "telemetry: {} record(s) in {} segment(s){}",
        t.records,
        t.segments,
        if t.torn_tails > 0 {
            format!(
                ", {} torn tail(s) (the next boot truncates them)",
                t.torn_tails
            )
        } else {
            String::new()
        }
    ));
    if opts.check_db && plan.copies[0] > 0 {
        let store = host::open_store(Disk::with_layout(
            Box::new(ov.view()),
            plan.v1.clone(),
            plan.sizes,
            0,
        ))
        .map_err(|e| format!("verify: the database does not open: {e}"))?;
        let ic = store
            .db()
            .query_text("PRAGMA integrity_check")
            .map_err(|e| e.to_string())?;
        if ic != "ok" {
            return Err(format!("verify: sqlite integrity_check: {ic}"));
        }
        notes.push("sqlite integrity_check ok (WAL replayed in memory only)".into());
    }
    Ok(notes)
}

/// Copies the live bytes of the three files from the v1 regions into the
/// new ones, flushes, then reads both back and compares.
fn copy_and_verify(dev: &Shared, plan: &Plan) -> Res<u64> {
    let mut src = Disk::with_layout(Box::new(dev.clone()), plan.v1.clone(), plan.sizes, 0);
    let mut dst = Disk::with_layout(Box::new(dev.clone()), plan.v2.clone(), plan.sizes, 1);
    let mut copied = 0;
    let mut buf = vec![0u8; CHUNK];
    let mut back = vec![0u8; CHUNK];
    for (i, kind) in [FileKind::Db, FileKind::Wal, FileKind::Journal]
        .into_iter()
        .enumerate()
    {
        let region = RegionKind::of_file(kind);
        let len = plan.copies.get(i).copied().unwrap_or(0);
        let mut off = 0;
        while off < len {
            let n = ((len - off) as usize).min(CHUNK);
            let b = buf.get_mut(..n).ok_or("buffer")?;
            src.read_at(region, off, b)
                .map_err(|e| format!("read {kind:?} at {off}: {e:?}"))?;
            dst.write_at(region, off, b)
                .map_err(|e| format!("write {kind:?} at {off}: {e:?}"))?;
            off += n as u64;
            copied += n as u64;
        }
    }
    io(dev.clone().flush(), "flush")?;
    // Read back from the device (the staged layout) and compare.
    let mut check = Disk::with_layout(Box::new(dev.clone()), plan.v2.clone(), plan.sizes, 1);
    for (i, kind) in [FileKind::Db, FileKind::Wal, FileKind::Journal]
        .into_iter()
        .enumerate()
    {
        let region = RegionKind::of_file(kind);
        let len = plan.copies.get(i).copied().unwrap_or(0);
        let mut off = 0;
        while off < len {
            let n = ((len - off) as usize).min(CHUNK);
            let (a, b) = (
                buf.get_mut(..n).ok_or("buffer")?,
                back.get_mut(..n).ok_or("buffer")?,
            );
            src.read_at(region, off, a)
                .map_err(|e| format!("verify read {kind:?}: {e:?}"))?;
            check
                .read_at(region, off, b)
                .map_err(|e| format!("verify read-back {kind:?}: {e:?}"))?;
            if a != b {
                return Err(format!(
                    "verify: the copy of the {kind:?} differs at offset {off}"
                ));
            }
            off += n as u64;
        }
    }
    Ok(copied)
}

/// The rollback file: the blocks the migration may change, to restore them
/// when the on-disk copy is gone.
const RB_MAGIC: &[u8; 8] = b"URMQRBF1";
const RB_LBAS: [u64; 5] = [0, 24, 32, 40, 48];

fn write_rollback_file(path: &Path, dev: &mut dyn BlockDevice) -> Res<()> {
    let mut out = Vec::new();
    out.extend_from_slice(RB_MAGIC);
    out.extend_from_slice(&(RB_LBAS.len() as u32).to_le_bytes());
    for lba in RB_LBAS {
        out.extend_from_slice(&lba.to_le_bytes());
        out.extend_from_slice(&read_block(dev, lba)?);
    }
    let crc = crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e} (it must not exist yet)", path.display()))?;
    f.write_all(&out)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_rollback_file(path: &Path) -> Res<Vec<(u64, [u8; BLOCK])>> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let body = b
        .get(..b.len().saturating_sub(4))
        .ok_or("rollback file too short")?;
    let crc = b
        .get(b.len().saturating_sub(4)..)
        .and_then(|c| c.try_into().ok())
        .map(u32::from_le_bytes);
    if body.get(..8) != Some(&RB_MAGIC[..]) || crc != Some(crc32c(body)) {
        return Err(format!("{}: not a valid rollback file", path.display()));
    }
    let mut out = Vec::new();
    let mut at = 12;
    while at + 8 + BLOCK <= body.len() {
        let lba = u64::from_le_bytes(
            body.get(at..at + 8)
                .and_then(|x| x.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let mut blk = [0u8; BLOCK];
        blk.copy_from_slice(
            body.get(at + 8..at + 8 + BLOCK)
                .ok_or("rollback file truncated")?,
        );
        out.push((lba, blk));
        at += 8 + BLOCK;
    }
    Ok(out)
}

/// Runs the whole migration on a v1 data partition.
pub fn run(dev: &Shared, opts: &Options, rollback_file: Option<&Path>) -> Res<Report> {
    let mut d = dev.clone();
    if let Some(r) = read_record(&mut d)?
        && r.state != mig::DONE
    {
        return Err(format!(
            "an earlier migration was interrupted (state {}): use --resume or --rollback",
            state_name(r.state)
        ));
    }
    match classify(&mut d)? {
        Found::V1 => {}
        Found::V2 { .. } => return Err("the data partition is layout v2 already".into()),
        other => return Err(format!("not a layout-v1 data partition: {other:?}")),
    }
    let sb = read_block(&mut d, SB_SLOT_LBA[0])?;
    let b = read_block(&mut d, SB_SLOT_LBA[1])?;
    if !b.iter().all(|&x| x == 0) {
        return Err("superblock slot B is not empty: this is not a plain v1 disk".into());
    }
    let plan = plan(&mut d, &sb, opts)?;
    let notes = preconditions(dev, &plan, opts)?;
    let mut rep = Report::default();
    rep.steps.extend(notes);
    if let Some(p) = rollback_file {
        write_rollback_file(p, &mut d)?;
        rep.steps
            .push(format!("rollback file {} written", p.display()));
    }
    let (v2b, _) = v2_blocks(&plan);
    let mut rec = Record {
        seq: 0,
        state: mig::PLANNED,
        v1_crc: crc32c(&plan.v1_sb),
        v2_crc: crc32c(&v2b),
    };
    put(&mut d, mig::BACKUP_LBA, &plan.v1_sb)?;
    rec.seq = 1;
    write_record(&mut d, &rec)?;
    rep.steps.push("v1 superblock saved, state planned".into());
    finish(dev, &plan, rec, &mut rep)?;
    Ok(rep)
}

/// Continues from the recorded state through `done`.
fn finish(dev: &Shared, plan: &Plan, mut rec: Record, rep: &mut Report) -> Res<()> {
    let mut d = dev.clone();
    let (v2b, v2a) = v2_blocks(plan);
    // The switch may have been written just before the record that says so
    // was: then the disk is v2 already, and the copy is never repeated (a
    // v2 kernel may have written to it since).
    let slot_b = read_block(&mut d, SB_SLOT_LBA[1])?;
    if rec.state < mig::SWITCHED && slot_b == v2b {
        rec = Record {
            seq: rec.seq + 1,
            state: mig::SWITCHED,
            ..rec
        };
        write_record(&mut d, &rec)?;
        rep.steps
            .push("slot B already holds v2: state switched".into());
    } else if rec.state < mig::SWITCHED
        && Layout::decode(&slot_b, dev.sectors()).is_ok_and(|l| l.is_some())
    {
        // A torn or empty slot B is the normal state before the switch;
        // another valid layout there is not ours.
        return Err(
            "superblock slot B holds a valid layout other than the planned v2 superblock".into(),
        );
    }
    if rec.state == mig::PLANNED {
        rep.bytes_copied = copy_and_verify(dev, plan)?;
        rec = Record {
            seq: rec.seq + 1,
            state: mig::COPIED,
            ..rec
        };
        write_record(&mut d, &rec)?;
        rep.steps.push(format!(
            "{} byte(s) copied and compared, state copied",
            rep.bytes_copied
        ));
    } else if rec.state == mig::COPIED {
        // Compare again: the copies must still be what they were.
        rep.bytes_copied = copy_and_verify(dev, plan)?;
    }
    if rec.state == mig::COPIED {
        put(&mut d, SB_SLOT_LBA[1], &v2b)?;
        rec = Record {
            seq: rec.seq + 1,
            state: mig::SWITCHED,
            ..rec
        };
        write_record(&mut d, &rec)?;
        rep.steps
            .push("v2 superblock written to slot B: the disk is v2, state switched".into());
    }
    if rec.state == mig::SWITCHED {
        put(&mut d, SB_SLOT_LBA[0], &v2a)?;
        rec = Record {
            seq: rec.seq + 1,
            state: mig::DONE,
            ..rec
        };
        write_record(&mut d, &rec)?;
        rep.steps.push(
            "v2 superblock written to slot A (v1 can no longer open the disk), state done".into(),
        );
    }
    Ok(())
}

/// Finishes an interrupted migration.
pub fn resume(dev: &Shared, opts: &Options) -> Res<Report> {
    let mut d = dev.clone();
    let Some(rec) = read_record(&mut d)? else {
        return Err("no interrupted migration is recorded: nothing to resume".into());
    };
    if rec.state == mig::DONE {
        return Ok(Report {
            steps: vec!["the migration is already done".into()],
            bytes_copied: 0,
        });
    }
    let saved = read_block(&mut d, mig::BACKUP_LBA)?;
    if crc32c(&saved) != rec.v1_crc {
        return Err("the saved v1 superblock does not match the migration record".into());
    }
    let plan = plan(&mut d, &saved, opts)?;
    let (v2b, _) = v2_blocks(&plan);
    if crc32c(&v2b) != rec.v2_crc {
        return Err(
            "the plan differs from the recorded one (another alignment or tool version?)".into(),
        );
    }
    let mut rep = Report::default();
    rep.steps
        .push(format!("resuming from state {}", state_name(rec.state)));
    finish(dev, &plan, rec, &mut rep)?;
    Ok(rep)
}

/// Returns an interrupted or finished migration to the v1 disk it started
/// from: restores slot A, empties slot B and the migration blocks. A
/// migration that already switched (state `switched` or `done`) is rolled
/// back only with `opts.force`, because the disk was v2 from then on.
pub fn rollback(dev: &Shared, opts: &Options, rollback_file: Option<&Path>) -> Res<Report> {
    let mut d = dev.clone();
    let rec = read_record(&mut d)?;
    let backup = read_block(&mut d, mig::BACKUP_LBA)?;
    let backup_ok = v1::decode(&backup, d.sectors()).is_ok_and(|l| l.is_some());
    let from_file = match rollback_file {
        Some(p) if p.exists() => Some(read_rollback_file(p)?),
        _ => None,
    };
    let v1_block = if backup_ok {
        backup
    } else if let Some(blocks) = &from_file {
        let (_, b) = blocks
            .iter()
            .find(|(lba, _)| *lba == 0)
            .ok_or("the rollback file has no superblock")?;
        *b
    } else if rec.is_none() {
        return Err(
            "no migration is recorded and there is no saved superblock: nothing to roll back"
                .into(),
        );
    } else {
        return Err(
            "the saved v1 superblock is gone: give the rollback file (--rollback-file)".into(),
        );
    };
    if v1::decode(&v1_block, d.sectors()).map_or(true, |l| l.is_none()) {
        return Err("the saved superblock is not a valid layout-v1 superblock".into());
    }
    let slot_b = read_block(&mut d, SB_SLOT_LBA[1])?;
    let b_is_v2 = Layout::decode(&slot_b, d.sectors()).is_ok_and(|l| l.is_some());
    if (rec.is_some_and(|r| r.state >= mig::SWITCHED) || b_is_v2) && !opts.force {
        return Err(
            "the migration already switched the disk to v2; rolling back restores the old files and loses every change made since (--force)"
                .into(),
        );
    }
    let mut rep = Report::default();
    // Slot A first (v1 back in force, v2 in B still wins), then slot B, then
    // the migration's own blocks: a cut anywhere leaves a valid disk and the
    // same command finishes the job.
    put(&mut d, SB_SLOT_LBA[0], &v1_block)?;
    put(&mut d, SB_SLOT_LBA[1], &[0u8; BLOCK])?;
    for lba in [mig::STATE_LBA[0], mig::STATE_LBA[1], mig::BACKUP_LBA] {
        put(&mut d, lba, &[0u8; BLOCK])?;
    }
    rep.steps
        .push("v1 superblock restored, slot B and the migration blocks cleared".into());
    Ok(rep)
}

/// What a data partition holds, for `info` and the fault-injection checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Blank,
    V1,
    V2 { generation: u64, slot: usize },
    Other(String),
}

/// Classifies the partition by its superblock slots.
pub fn classify(dev: &mut dyn BlockDevice) -> Res<Found> {
    let a = read_block(dev, SB_SLOT_LBA[0])?;
    let b = read_block(dev, SB_SLOT_LBA[1])?;
    let total = dev.sectors();
    Ok(match Layout::select(&a, &b, total) {
        Ok(None) => Found::Blank,
        Ok(Some((l, slot))) => Found::V2 {
            generation: l.generation,
            slot,
        },
        Err(urmqtt_store::layout::LayoutError::OldVersion(_)) => Found::V1,
        Err(e) => Found::Other(format!("{e:?}")),
    })
}
