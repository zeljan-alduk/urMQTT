//! The in-disk database backup (STORAGE-PLAN S5, ADR-160 to ADR-164).
//!
//! The backup region (layout v2.1) holds a control block and two snapshot
//! slots, written alternately:
//!
//! ```text
//! [ control 4 KiB ][ slot 0: header 4 KiB + payload ][ slot 1: the same ]
//! ```
//!
//! A snapshot is a complete SQLite database file (the payload), copied by
//! SQLite's online backup API in bounded steps while the broker keeps
//! working, plus a header written last: sequence, time, schema version,
//! page geometry and the CRC-32C of the payload, all under the header's own
//! CRC and tied to this disk by its UUID. The order of writes is the whole
//! safety argument:
//!
//! 1. the slot **not** holding the newest good snapshot gets its header
//!    block zeroed (the other slot is never touched);
//! 2. the payload is copied in and flushed;
//! 3. the payload is read back and its CRC computed;
//! 4. the header is written and flushed.
//!
//! A cut at any point leaves the previous good slot as it was; the slot
//! being written is invalid until step 4 completes in one block. A restore
//! writes a "restoring" mark in the control block first, so an interrupted
//! restore is finished at the next boot instead of leaving a mixture of the
//! old and the restored file.

use alloc::vec;
use alloc::vec::Vec;

use crate::crc::{crc32c, update};
use crate::db::{self, Backup, BackupStep, Db};
use crate::disk::{Disk, DiskError};
use crate::layout::{BACKUP_HEADER_BYTES, BLOCK, BackupGeometry, FileKind, RegionKind};
use crate::vfs;

pub const SLOT_MAGIC: [u8; 8] = *b"URMQBKP1";
pub const CONTROL_MAGIC: [u8; 8] = *b"URMQBKC1";
/// Bytes read per I/O when a payload is read back, verified or restored.
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    Disk(DiskError),
    Sql(db::Error),
    /// The layout has no backup region (not yet carved, or no room).
    NoRegion,
    /// There is no valid snapshot to restore.
    NoBackup,
    /// The database is larger than a slot can hold.
    TooLarge {
        bytes: u64,
        capacity: u64,
    },
    /// The snapshot the job just wrote is not a database file.
    BadSnapshot(&'static str),
    /// The newest snapshot is for a newer schema than this build knows.
    TooNew(u32),
}

impl From<DiskError> for BackupError {
    fn from(e: DiskError) -> Self {
        Self::Disk(e)
    }
}

impl From<db::Error> for BackupError {
    fn from(e: db::Error) -> Self {
        Self::Sql(e)
    }
}

impl core::fmt::Display for BackupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disk(e) => write!(f, "disk: {e:?}"),
            Self::Sql(e) => write!(f, "sqlite: {e}"),
            Self::NoRegion => write!(f, "the layout has no backup region"),
            Self::NoBackup => write!(f, "no valid backup"),
            Self::TooLarge { bytes, capacity } => write!(
                f,
                "the database ({} KiB) does not fit a backup slot ({} KiB)",
                bytes >> 10,
                capacity >> 10
            ),
            Self::BadSnapshot(w) => write!(f, "the snapshot is not a database file: {w}"),
            Self::TooNew(v) => write!(
                f,
                "the backup has schema version {v}, newer than this build"
            ),
        }
    }
}

type Result<T> = core::result::Result<T, BackupError>;

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn crc_ok(b: &[u8; BLOCK]) -> bool {
    crc32c(b.get(..BLOCK - 4).unwrap_or(&[])) == u32_at(b, BLOCK - 4)
}

fn seal(b: &mut [u8; BLOCK]) {
    let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
    put(b, BLOCK - 4, &crc.to_le_bytes());
}

/// A snapshot slot's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotHeader {
    /// Increases by one with every snapshot; the highest valid one is the
    /// newest.
    pub seq: u64,
    /// Unix seconds when the snapshot finished (0: the clock was unknown).
    pub created: u64,
    /// `PRAGMA user_version` of the snapshot: the broker's schema version.
    pub schema_version: u32,
    pub page_size: u32,
    pub page_count: u64,
    /// `page_size * page_count`: the snapshot file's length.
    pub payload_bytes: u64,
    /// CRC-32C of the payload.
    pub payload_crc: u32,
}

impl SlotHeader {
    pub fn encode(&self, uuid: &[u8; 16]) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &SLOT_MAGIC);
        put(&mut b, 8, &self.seq.to_le_bytes());
        put(&mut b, 16, &self.created.to_le_bytes());
        put(&mut b, 24, uuid);
        put(&mut b, 40, &self.schema_version.to_le_bytes());
        put(&mut b, 44, &self.page_size.to_le_bytes());
        put(&mut b, 48, &self.page_count.to_le_bytes());
        put(&mut b, 56, &self.payload_bytes.to_le_bytes());
        put(&mut b, 64, &self.payload_crc.to_le_bytes());
        seal(&mut b);
        b
    }

    /// Decodes a slot header block: `None` unless the magic, CRC and the
    /// disk's `uuid` match and the fields are consistent with a slot of
    /// `capacity` payload bytes.
    pub fn decode(b: &[u8; BLOCK], uuid: &[u8; 16], capacity: u64) -> Option<Self> {
        if b.get(..8) != Some(&SLOT_MAGIC[..]) || !crc_ok(b) || b.get(24..40) != Some(&uuid[..]) {
            return None;
        }
        let h = Self {
            seq: u64_at(b, 8),
            created: u64_at(b, 16),
            schema_version: u32_at(b, 40),
            page_size: u32_at(b, 44),
            page_count: u64_at(b, 48),
            payload_bytes: u64_at(b, 56),
            payload_crc: u32_at(b, 64),
        };
        let ok = h.seq > 0
            && h.page_size.is_power_of_two()
            && (512..=65536).contains(&h.page_size)
            && h.page_count > 0
            && h.page_count.checked_mul(u64::from(h.page_size)) == Some(h.payload_bytes)
            && h.payload_bytes <= capacity;
        ok.then_some(h)
    }
}

/// What the control block says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Control {
    /// Increases by one with every write of the block.
    pub seq: u64,
    /// A restore from `slot`, whose snapshot has sequence `backup_seq`, was
    /// started and not finished.
    pub restoring: Option<(usize, u64)>,
}

impl Control {
    pub fn encode(&self, uuid: &[u8; 16]) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &CONTROL_MAGIC);
        put(&mut b, 8, &self.seq.to_le_bytes());
        put(&mut b, 16, uuid);
        let (state, slot, bseq) = match self.restoring {
            Some((slot, seq)) => (1u32, slot as u32, seq),
            None => (0, 0, 0),
        };
        put(&mut b, 32, &state.to_le_bytes());
        put(&mut b, 36, &slot.to_le_bytes());
        put(&mut b, 40, &bseq.to_le_bytes());
        seal(&mut b);
        b
    }

    /// `None`: not a control block of this disk (blank, torn or foreign).
    pub fn decode(b: &[u8; BLOCK], uuid: &[u8; 16]) -> Option<Self> {
        if b.get(..8) != Some(&CONTROL_MAGIC[..]) || !crc_ok(b) || b.get(16..32) != Some(&uuid[..])
        {
            return None;
        }
        let restoring = match (u32_at(b, 32), u32_at(b, 36)) {
            (0, _) => None,
            (1, s) if s <= 1 => Some((s as usize, u64_at(b, 40))),
            _ => return None,
        };
        Some(Self {
            seq: u64_at(b, 8),
            restoring,
        })
    }
}

/// The two slots' headers, as the disk shows them (payloads not checked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Slots {
    pub header: [Option<SlotHeader>; 2],
}

impl Slots {
    /// The slot with the highest sequence number.
    pub fn newest(&self) -> Option<usize> {
        match (
            self.header.first().copied().flatten(),
            self.header.get(1).copied().flatten(),
        ) {
            (Some(a), Some(b)) => Some(usize::from(b.seq > a.seq)),
            (Some(_), None) => Some(0),
            (None, Some(_)) => Some(1),
            (None, None) => None,
        }
    }

    /// Slots with a valid header, newest first.
    pub fn by_age(&self) -> Vec<(usize, SlotHeader)> {
        let mut v: Vec<(usize, SlotHeader)> = self
            .header
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.map(|h| (i, h)))
            .collect();
        v.sort_by_key(|(_, h)| core::cmp::Reverse(h.seq));
        v
    }
}

fn geometry(disk: &Disk) -> Result<BackupGeometry> {
    disk.layout().backup().ok_or(BackupError::NoRegion)
}

/// Reads both slot headers. `NoRegion` if the layout has none.
pub fn scan(disk: &mut Disk) -> Result<Slots> {
    let g = geometry(disk)?;
    let uuid = disk.layout().uuid;
    let mut out = Slots::default();
    for (i, h) in out.header.iter_mut().enumerate() {
        let mut b = [0u8; BLOCK];
        disk.read_at(RegionKind::Backup, g.slot_offset(i), &mut b)?;
        *h = SlotHeader::decode(&b, &uuid, g.payload_capacity());
    }
    Ok(out)
}

/// What a slot's header block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// All zeros, or nothing that looks like a header (never used, being
    /// rewritten, or released space).
    Empty,
    /// Has the header magic but fails its checks (a flipped bit, a torn
    /// write, another disk's snapshot).
    Damaged,
    Valid(SlotHeader),
}

/// Classifies slot `slot`'s header block (for the scrubber).
pub fn slot_state(disk: &mut Disk, slot: usize) -> Result<SlotState> {
    let g = geometry(disk)?;
    let uuid = disk.layout().uuid;
    let mut b = [0u8; BLOCK];
    disk.read_at(RegionKind::Backup, g.slot_offset(slot), &mut b)?;
    Ok(match SlotHeader::decode(&b, &uuid, g.payload_capacity()) {
        Some(h) => SlotState::Valid(h),
        None if b.get(..8) == Some(&SLOT_MAGIC[..]) => SlotState::Damaged,
        None => SlotState::Empty,
    })
}

/// Whether the control block has its magic but is not valid (the scrubber
/// reports it; the broker treats it as idle).
pub fn control_damaged(disk: &mut Disk) -> Result<bool> {
    geometry(disk)?;
    let mut b = [0u8; BLOCK];
    disk.read_at(RegionKind::Backup, 0, &mut b)?;
    Ok(
        b.get(..8) == Some(&CONTROL_MAGIC[..])
            && Control::decode(&b, &disk.layout().uuid).is_none(),
    )
}

/// Reads the control block (an absent or damaged one is the idle state).
pub fn read_control(disk: &mut Disk) -> Result<Control> {
    geometry(disk)?;
    let mut b = [0u8; BLOCK];
    disk.read_at(RegionKind::Backup, 0, &mut b)?;
    Ok(Control::decode(&b, &disk.layout().uuid).unwrap_or_default())
}

fn write_control(disk: &mut Disk, c: &Control) -> Result<()> {
    let b = c.encode(&disk.layout().uuid);
    disk.write_at(RegionKind::Backup, 0, &b)?;
    disk.sync()?;
    Ok(())
}

/// Reads a payload back in steps and computes its CRC-32C.
#[derive(Debug, Clone)]
pub struct Verifier {
    slot: usize,
    bytes: u64,
    done: u64,
    crc: u32,
}

impl Verifier {
    /// Over the first `bytes` bytes of slot `slot`'s payload.
    pub fn new(slot: usize, bytes: u64) -> Self {
        Self {
            slot,
            bytes,
            done: 0,
            crc: 0,
        }
    }

    /// Reads up to `max_bytes` more. `Ok(Some(crc))` once the whole payload
    /// has been read.
    pub fn step(&mut self, disk: &mut Disk, max_bytes: usize) -> Result<Option<u32>> {
        let g = geometry(disk)?;
        let base = g.slot_offset(self.slot) + BACKUP_HEADER_BYTES;
        let mut buf = vec![0u8; CHUNK];
        let mut budget = max_bytes.max(BLOCK);
        while self.done < self.bytes && budget > 0 {
            let n = ((self.bytes - self.done) as usize)
                .min(buf.len())
                .min(budget);
            let part = buf.get_mut(..n).ok_or(BackupError::NoRegion)?;
            disk.read_at(RegionKind::Backup, base + self.done, part)?;
            self.crc = update(self.crc, part);
            self.done += n as u64;
            budget -= n;
        }
        Ok((self.done >= self.bytes).then_some(self.crc))
    }

    pub fn progress(&self) -> (u64, u64) {
        (self.done, self.bytes)
    }
}

/// Whether slot `slot`'s payload matches its header (reads all of it).
pub fn verify_slot(disk: &mut Disk, slot: usize, h: &SlotHeader) -> Result<bool> {
    let mut v = Verifier::new(slot, h.payload_bytes);
    loop {
        if let Some(crc) = v.step(disk, CHUNK)? {
            return Ok(crc == h.payload_crc);
        }
    }
}

/// Parses the database header of a snapshot (SQLite file format, big
/// endian): (page size, page count, user_version).
fn sqlite_header(b: &[u8]) -> Option<(u32, u64, u32)> {
    if b.get(..16) != Some(b"SQLite format 3\0") {
        return None;
    }
    let ps = u16::from_be_bytes(b.get(16..18)?.try_into().ok()?);
    let page_size = if ps == 1 { 65536 } else { u32::from(ps) };
    let pages = u32::from_be_bytes(b.get(28..32)?.try_into().ok()?);
    let user_version = u32::from_be_bytes(b.get(60..64)?.try_into().ok()?);
    Some((page_size, u64::from(pages), user_version))
}

/// One online backup, run in bounded steps by the DB core. Create it with
/// [`BackupJob::start`], call [`step`](Self::step) until it reports
/// `Done`; drop it to abandon (the slot being written stays invalid, the
/// other is untouched).
pub struct BackupJob {
    phase: Phase,
    now_unix: u64,
    /// Highest header sequence at the start; the new snapshot is one more.
    seq: u64,
    /// Steps that found a lock (retried).
    pub busy: u32,
    /// Pages in the source, as of the last copy step.
    pub pages: u32,
}

enum Phase {
    /// Reading the newest existing snapshot back before it is trusted as
    /// the one to keep.
    Check {
        slot: usize,
        header: SlotHeader,
        v: Verifier,
    },
    /// Everything is decided but nothing written yet. `keep` is the slot
    /// that holds the good snapshot (untouchable); the other one is the
    /// target. `bad` is a slot whose header is valid but whose payload is
    /// not: it is the target if there is no `keep`.
    Prepare {
        keep: Option<usize>,
        bad: Option<usize>,
    },
    /// Copying pages. The handle is declared first: it is dropped first.
    Copy {
        handle: Backup,
        dest: Db,
        slot: usize,
    },
    /// Reading the finished payload back for its CRC.
    Verify {
        slot: usize,
        v: Verifier,
        geom: (u32, u64, u32),
    },
    Finished,
}

/// What a step of a [`BackupJob`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// More steps are needed.
    Working,
    /// The snapshot is complete and valid on the disk, in this slot.
    Done(SlotHeader, usize),
}

impl BackupJob {
    /// Begins a backup. `trusted` is the sequence number of a snapshot
    /// already known to be good (read back earlier in this boot): the newest
    /// snapshot is only read back first if it is not that one. Reads the
    /// slot headers; nothing is written until a [`step`](Self::step) has
    /// decided which slot is the target.
    pub fn start(trusted: Option<u64>, now_unix: u64) -> Result<Self> {
        let slots = vfs::with_disk(scan).ok_or(BackupError::NoRegion)??;
        let newest = slots.by_age().first().copied();
        let phase = match newest {
            Some((slot, header)) if trusted != Some(header.seq) => Phase::Check {
                slot,
                header,
                v: Verifier::new(slot, header.payload_bytes),
            },
            Some((slot, _)) => Phase::Prepare {
                keep: Some(slot),
                bad: None,
            },
            None => Phase::Prepare {
                keep: None,
                bad: None,
            },
        };
        Ok(Self {
            phase,
            now_unix,
            seq: newest.map_or(0, |(_, h)| h.seq),
            busy: 0,
            pages: 0,
        })
    }

    /// The slot being written, once known.
    pub fn target(&self) -> Option<usize> {
        match &self.phase {
            Phase::Copy { slot, .. } | Phase::Verify { slot, .. } => Some(*slot),
            _ => None,
        }
    }

    /// Does one bounded piece of work: reading back at most `read_bytes`,
    /// or copying at most `pages` pages of `src`. `src` is the open store
    /// connection, which must not be inside a transaction.
    pub fn step(&mut self, src: &Db, pages: u32, read_bytes: usize) -> Result<Progress> {
        let r = self.step_inner(src, pages, read_bytes);
        if r.is_err() {
            self.abandon();
        }
        r
    }

    /// Stops the job: releases the SQLite handles and the backup file. The
    /// slot being written stays invalid (its header was zeroed first).
    pub fn abandon(&mut self) {
        self.phase = Phase::Finished;
        vfs::backup_detach();
    }

    fn step_inner(&mut self, src: &Db, pages: u32, read_bytes: usize) -> Result<Progress> {
        match core::mem::replace(&mut self.phase, Phase::Finished) {
            Phase::Check {
                slot,
                header,
                mut v,
            } => {
                let crc =
                    vfs::with_disk(|d| v.step(d, read_bytes)).ok_or(BackupError::NoRegion)??;
                self.phase = match crc {
                    None => Phase::Check { slot, header, v },
                    Some(c) if c == header.payload_crc => Phase::Prepare {
                        keep: Some(slot),
                        bad: None,
                    },
                    Some(_) => Phase::Prepare {
                        keep: None,
                        bad: Some(slot),
                    },
                };
                Ok(Progress::Working)
            }
            Phase::Prepare { keep, bad } => {
                let slot = match (keep, bad) {
                    (Some(k), _) => 1 - k.min(1),
                    (None, Some(b)) => b,
                    (None, None) => 0,
                };
                let pages_src = src.query_i64("PRAGMA page_count")?.max(0) as u64;
                let page_size = src.query_i64("PRAGMA page_size")?.max(0) as u64;
                let need = pages_src * page_size;
                let cap = vfs::with_disk(|d| d.backup_payload(slot).map(|(_, c)| c))
                    .flatten()
                    .ok_or(BackupError::NoRegion)?;
                if need > cap {
                    return Err(BackupError::TooLarge {
                        bytes: need,
                        capacity: cap,
                    });
                }
                // The target is invalid from here until the header is written
                // last; the other slot is not touched at all.
                vfs::with_disk(|d| -> Result<()> {
                    let g = geometry(d)?;
                    d.write_at(RegionKind::Backup, g.slot_offset(slot), &[0u8; BLOCK])?;
                    d.sync()?;
                    Ok(())
                })
                .ok_or(BackupError::NoRegion)??;
                if !vfs::backup_attach(slot) {
                    return Err(BackupError::NoRegion);
                }
                let dest = Db::open_backup_target()?;
                dest.exec(
                    "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA cache_size = -256",
                )?;
                let handle = Backup::new(&dest, src)?;
                self.phase = Phase::Copy { handle, dest, slot };
                Ok(Progress::Working)
            }
            Phase::Copy {
                mut handle,
                dest,
                slot,
            } => match handle.step(pages) {
                Err(e) => {
                    // The destination must outlive its backup handle (a
                    // handle finished after its connection closed is a use
                    // after free): drop them in that order, not the order
                    // the bindings go out of scope in.
                    drop(handle);
                    drop(dest);
                    Err(e.into())
                }
                Ok(BackupStep::More) => {
                    self.pages = handle.progress().1;
                    self.phase = Phase::Copy { handle, dest, slot };
                    Ok(Progress::Working)
                }
                Ok(BackupStep::Busy) => {
                    self.busy += 1;
                    self.phase = Phase::Copy { handle, dest, slot };
                    Ok(Progress::Working)
                }
                Ok(BackupStep::Done) => {
                    self.pages = handle.progress().1;
                    drop(handle);
                    drop(dest);
                    let bytes = vfs::backup_detach();
                    let geom = vfs::with_disk(|d| -> Result<(u32, u64, u32)> {
                        // The copy is on the device before it is read back.
                        d.sync()?;
                        let g = geometry(d)?;
                        let mut head = [0u8; 100];
                        let base = g.slot_offset(slot) + BACKUP_HEADER_BYTES;
                        d.read_at(RegionKind::Backup, base, &mut head)?;
                        let (ps, pc, uv) = sqlite_header(&head)
                            .ok_or(BackupError::BadSnapshot("no SQLite header"))?;
                        if u64::from(ps) * pc != bytes || bytes == 0 {
                            return Err(BackupError::BadSnapshot("size does not match the header"));
                        }
                        Ok((ps, pc, uv))
                    })
                    .ok_or(BackupError::NoRegion)??;
                    self.phase = Phase::Verify {
                        slot,
                        v: Verifier::new(slot, bytes),
                        geom,
                    };
                    Ok(Progress::Working)
                }
            },
            Phase::Verify { slot, mut v, geom } => {
                let crc =
                    vfs::with_disk(|d| v.step(d, read_bytes)).ok_or(BackupError::NoRegion)??;
                let Some(crc) = crc else {
                    self.phase = Phase::Verify { slot, v, geom };
                    return Ok(Progress::Working);
                };
                let header = SlotHeader {
                    seq: self.seq + 1,
                    created: self.now_unix,
                    schema_version: geom.2,
                    page_size: geom.0,
                    page_count: geom.1,
                    payload_bytes: v.progress().1,
                    payload_crc: crc,
                };
                vfs::with_disk(|d| -> Result<()> {
                    let g = geometry(d)?;
                    let block = header.encode(&d.layout().uuid);
                    d.write_at(RegionKind::Backup, g.slot_offset(slot), &block)?;
                    d.sync()?;
                    Ok(())
                })
                .ok_or(BackupError::NoRegion)??;
                Ok(Progress::Done(header, slot))
            }
            Phase::Finished => Err(BackupError::NoBackup),
        }
    }
}

impl Drop for BackupJob {
    fn drop(&mut self) {
        if !matches!(self.phase, Phase::Finished) {
            self.abandon();
        }
    }
}

/// What a restore did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restored {
    pub slot: usize,
    pub header: SlotHeader,
    /// The restore finished one that an earlier boot had started.
    pub resumed: bool,
}

/// Picks the newest snapshot whose payload is intact and whose schema this
/// build can read (`max_schema`).
fn pick(
    disk: &mut Disk,
    max_schema: u32,
    only: Option<(usize, u64)>,
) -> Result<(usize, SlotHeader)> {
    let slots = scan(disk)?;
    let mut too_new = None;
    for (slot, h) in slots.by_age() {
        if let Some((s, seq)) = only
            && (s != slot || seq != h.seq)
        {
            continue;
        }
        if h.schema_version > max_schema {
            too_new = Some(h.schema_version);
            continue;
        }
        if verify_slot(disk, slot, &h)? {
            return Ok((slot, h));
        }
    }
    Err(too_new.map_or(BackupError::NoBackup, BackupError::TooNew))
}

/// Whether a restore was started and not finished (an earlier boot was cut
/// mid-restore). Without a backup region: `Ok(None)`.
pub fn restore_pending(disk: &mut Disk) -> Result<Option<(usize, u64)>> {
    if disk.layout().backup().is_none() {
        return Ok(None);
    }
    Ok(read_control(disk)?.restoring)
}

/// Replaces the database with the newest intact snapshot, or finishes the
/// restore an earlier boot started. The snapshot slot is only read, so a
/// cut at any point leaves it intact and the next boot repeats this. Order:
/// the "restoring" mark, the WAL and journal emptied, the payload copied and
/// flushed, the database size set, the mark cleared. Call it with the store
/// closed.
pub fn restore(disk: &mut Disk, max_schema: u32) -> Result<Restored> {
    let g = geometry(disk)?;
    let mut ctl = read_control(disk)?;
    let resumed = ctl.restoring.is_some();
    let (slot, h) = pick(disk, max_schema, ctl.restoring)?;
    if h.payload_bytes > disk.bytes(RegionKind::Db) {
        return Err(BackupError::TooLarge {
            bytes: h.payload_bytes,
            capacity: disk.bytes(RegionKind::Db),
        });
    }
    ctl = Control {
        seq: ctl.seq + 1,
        restoring: Some((slot, h.seq)),
    };
    write_control(disk, &ctl)?;
    // No stale WAL frame may be applied to the restored file.
    disk.set_file_size(FileKind::Wal, 0);
    disk.set_file_size(FileKind::Journal, 0);
    disk.sync()?;
    let base = g.slot_offset(slot) + BACKUP_HEADER_BYTES;
    let mut buf = vec![0u8; CHUNK];
    let mut at = 0u64;
    let mut crc = 0u32;
    while at < h.payload_bytes {
        let n = ((h.payload_bytes - at) as usize).min(CHUNK);
        let part = buf.get_mut(..n).ok_or(BackupError::NoRegion)?;
        disk.read_at(RegionKind::Backup, base + at, part)?;
        crc = update(crc, part);
        disk.write_at(RegionKind::Db, at, part)?;
        at += n as u64;
    }
    if crc != h.payload_crc {
        // The snapshot changed under us: do not declare the restore done.
        return Err(BackupError::NoBackup);
    }
    disk.sync()?;
    disk.set_file_size(FileKind::Db, h.payload_bytes);
    disk.sync()?;
    ctl = Control {
        seq: ctl.seq + 1,
        restoring: None,
    };
    write_control(disk, &ctl)?;
    Ok(Restored {
        slot,
        header: h,
        resumed,
    })
}

/// A restore that [`open_or_restore`] performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub restored: Restored,
    /// Why: `quick_check` failed (its text), or an earlier restore was cut.
    pub reason: alloc::string::String,
}

/// Opens the store the way a boot does. An interrupted restore is finished
/// first. If the database then fails its integrity check and `auto_restore`
/// is set, the newest intact backup replaces it and the store is opened
/// again. Without `auto_restore`, or without an intact backup, the
/// corruption is returned for the caller to refuse (`StoreError::Corrupt`).
///
/// The VFS must be installed ([`crate::init`]).
pub fn open_or_restore(
    auto_restore: bool,
) -> core::result::Result<
    (
        crate::store::Store,
        crate::store::OpenInfo,
        Option<RestoreReport>,
    ),
    crate::store::StoreError,
> {
    use crate::store::StoreError;
    let max = u32::try_from(crate::schema::VERSION).unwrap_or(u32::MAX);
    let fail = |why: &str, e: BackupError| {
        StoreError::Corrupt(alloc::format!("{why}; restoring from a backup failed: {e}"))
    };
    let mut report = None;
    let pending = vfs::with_disk(restore_pending).ok_or(StoreError::Init(-1))?;
    if matches!(pending, Ok(Some(_))) {
        let r = vfs::with_disk(|d| restore(d, max)).ok_or(StoreError::Init(-1))?;
        match r {
            Ok(restored) => {
                report = Some(RestoreReport {
                    restored,
                    reason: "an earlier restore was interrupted".into(),
                });
            }
            Err(e) => return Err(fail("a restore was interrupted", e)),
        }
    }
    match crate::store::open() {
        Ok((s, info)) => Ok((s, info, report)),
        Err(StoreError::Corrupt(why)) if auto_restore && report.is_none() => {
            let r = vfs::with_disk(|d| restore(d, max)).ok_or(StoreError::Init(-1))?;
            match r {
                Ok(restored) => {
                    let (s, info) = crate::store::open()?;
                    Ok((
                        s,
                        info,
                        Some(RestoreReport {
                            restored,
                            reason: why,
                        }),
                    ))
                }
                Err(e) => Err(fail(&why, e)),
            }
        }
        Err(e) => Err(e),
    }
}
