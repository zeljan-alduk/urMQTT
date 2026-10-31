//! Byte-addressed access to the regions of a sector device, with logical
//! file sizes persisted in the double-buffered size table (ADR-030), the
//! topology-aware write path (ADR-140), the crash-safe grow (ADR-142) and
//! the discard queue (ADR-150).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use urmqtt_sync::sync::SpinLock;

use crate::layout::{
    BLOCK, FileKind, Layout, LayoutError, Params, Region, RegionKind, SB_SLOT_LBA, SECTOR,
    SIZE_SLOT_LBA, SizeTable, Topology,
};

/// A 512-byte-sector block device (virtio-blk in the kernel, memory in tests).
pub trait BlockDevice: Send {
    fn sectors(&self) -> u64;
    /// Reads whole sectors; `buf.len()` is a multiple of 512.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError>;
    /// Writes whole sectors; `buf.len()` is a multiple of 512.
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError>;
    /// Makes every completed write durable.
    fn flush(&mut self) -> Result<(), IoError>;
    /// Largest single request in bytes.
    fn max_io(&self) -> usize {
        64 * 1024
    }
    /// Block sizes and I/O hints of the underlying device.
    fn topology(&self) -> Topology {
        Topology::default()
    }
    /// Where sector 0 of this device lies on the physical disk (a partition
    /// window's first sector), so alignment is judged on the real disk.
    fn base_lba(&self) -> u64 {
        0
    }
    /// Asks the device for its current size (after a configuration-change
    /// notification). `Some(sectors)` if it grew since the last answer; the
    /// device never reports a shrink.
    fn refresh_size(&mut self) -> Option<u64> {
        None
    }
    /// The whole disk behind a partition window, for the partition table
    /// steps of an online grow. `None` where there is no such disk.
    fn whole_disk(&mut self) -> Option<&mut dyn BlockDevice> {
        None
    }
    /// A partition window follows the partition table: now `sectors` long.
    fn resize_window(&mut self, _sectors: u64) {}
    /// What the device can unmap, and its limits (S4). `None`: nothing.
    fn discard_caps(&self) -> Option<DiscardCaps> {
        None
    }
    /// Tells the device the ranges (first sector, sectors) hold no data any
    /// more. The caller has split them to the limits of
    /// [`discard_caps`](Self::discard_caps). What the sectors read back as
    /// afterwards is up to the device (zeros, the old data or anything).
    fn discard(&mut self, _ranges: &[(u64, u64)]) -> Result<(), IoError> {
        Err(IoError::Unsupported)
    }
}

/// How a device releases space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardKind {
    /// DISCARD (virtio-blk), UNMAP (SCSI), TRIM, Deallocate.
    Discard,
    /// WRITE ZEROES with the unmap flag (WRITE SAME with UNMAP): the
    /// sectors read back as zeros.
    WriteZeroes,
}

/// The limits of a device's discard command (STORAGE-PLAN S4). Sizes in
/// 512-byte sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardCaps {
    pub kind: DiscardKind,
    /// Largest single range.
    pub max_sectors: u64,
    /// Ranges per request.
    pub max_ranges: u32,
    /// Start and length of a range are multiples of this (at least 1).
    pub granularity: u64,
}

/// Why space is released; counted separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardSource {
    /// A retired telemetry segment.
    Telemetry,
    /// The logical tail of a file the VFS truncated.
    Truncate,
    /// Space a grow added to the layout.
    Grow,
}

/// Counters of the discard path, all in bytes except the request counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DiscardStats {
    pub queued_telemetry: u64,
    pub queued_truncate: u64,
    pub queued_grow: u64,
    /// Requests sent to the device and descriptors in them.
    pub requests: u64,
    pub ranges: u64,
    /// Bytes the device was told to release.
    pub bytes: u64,
    /// Queued bytes a later write took back before they were sent.
    pub cancelled: u64,
    /// Bytes not queued because the queue was full (space is merely not
    /// released).
    pub dropped: u64,
    /// Requests the device failed.
    pub failed: u64,
    /// The device said it does not support the command: discards stopped.
    pub unsupported: bool,
}

/// A range of device sectors, `[start, end)`.
type Span = (u64, u64);

/// Longest list of waiting ranges; further ones are dropped.
const MAX_SPANS: usize = 512;
/// Largest range sent in one descriptor (16 MiB): a long discard blocks
/// the device for a while, so the work is cut into pieces.
const MAX_CHUNK_SECTORS: u64 = 32_768;
/// After this many failed requests in a row discards stop for the boot.
const MAX_FAILURES: u32 = 3;

struct DiscardState {
    caps: DiscardCaps,
    /// Ranges queued since the last sync: they may still be referenced by
    /// state that is not durable (a size table not yet written).
    staged: Vec<Span>,
    /// Ranges released by a sync: the next `run_discards` sends them.
    ready: Vec<Span>,
    stats: DiscardStats,
    failures: u32,
    stopped: bool,
}

/// Adds `[s, e)` to a sorted list of disjoint spans, merging neighbours.
/// `false` if the list is full (nothing added).
fn span_add(list: &mut Vec<Span>, s: u64, e: u64) -> bool {
    if s >= e {
        return true;
    }
    let (mut s, mut e) = (s, e);
    let mut keep = Vec::with_capacity(list.len() + 1);
    for &(a, b) in list.iter() {
        if b < s || a > e {
            keep.push((a, b));
        } else {
            s = s.min(a);
            e = e.max(b);
        }
    }
    keep.push((s, e));
    keep.sort_unstable();
    if keep.len() > MAX_SPANS {
        return false;
    }
    *list = keep;
    true
}

/// Removes `[s, e)` from the list; returns the sectors removed.
fn span_cut(list: &mut Vec<Span>, s: u64, e: u64) -> u64 {
    let mut cut = 0;
    let mut out = Vec::with_capacity(list.len() + 1);
    for &(a, b) in list.iter() {
        if b <= s || a >= e {
            out.push((a, b));
            continue;
        }
        cut += b.min(e) - a.max(s);
        if a < s {
            out.push((a, s));
        }
        if b > e {
            out.push((e, b));
        }
    }
    *list = out;
    cut
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    Device,
    OutOfRange,
    NoFlush,
    /// The device does not implement the command.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    Io(IoError),
    Layout(LayoutError),
    /// A write would go past the end of its region.
    Full,
}

impl From<IoError> for DiskError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl From<LayoutError> for DiskError {
    fn from(e: LayoutError) -> Self {
        Self::Layout(e)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DiskStats {
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub size_table_writes: u64,
    /// Requests the store sent to the device, including its own metadata.
    pub device_writes: u64,
    /// Of those, writes that did not start and end on a physical block of
    /// the device (STORAGE-PLAN S2: must stay 0 on the data partition).
    pub misaligned_writes: u64,
}

pub struct Disk {
    dev: Box<dyn BlockDevice>,
    layout: Layout,
    sizes: SizeTable,
    /// Sizes changed since the table was last persisted.
    dirty: bool,
    /// Superblock slot holding `layout`.
    sb_slot: usize,
    /// I/O granularity in bytes: the physical block (512..4096), at least
    /// the logical block. Every device write is a multiple of it.
    gran: usize,
    topo: Topology,
    /// Written since the last flush.
    unsynced: bool,
    /// The discard queue (S4); `None` while discards are off.
    discard: Option<DiscardState>,
    pub stats: DiskStats,
}

/// What [`Disk::open`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    Existing,
    Formatted,
}

/// What [`Disk::ensure_backup`] found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupRegion {
    /// The layout has a backup region already.
    Present,
    /// It was added.
    Added { bytes: u64, slot_bytes: u64 },
    /// The database has no room to give (it would have to keep twice its
    /// size plus 1 MiB): the layout is as it was.
    NoRoom,
}

/// What [`Disk::grow`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grown {
    pub old_total: u64,
    pub new_total: u64,
    pub generation: u64,
    /// Sectors added to the database and to the telemetry ring.
    pub db_sectors: u64,
    pub telemetry_sectors: u64,
}

impl Disk {
    /// Opens the data disk with the default 8 telemetry partitions,
    /// formatting it if (and only if) it is blank.
    pub fn open(
        dev: Box<dyn BlockDevice>,
        uuid: impl FnOnce() -> [u8; 16],
    ) -> Result<(Self, Opened), DiskError> {
        Self::open_with(dev, uuid, Params::default().partitions)
    }

    /// Like [`open`](Self::open), with the telemetry partition count a blank
    /// disk is formatted with (an existing layout keeps its own).
    ///
    /// A disk of an older layout version is refused (`OldVersion`) before
    /// anything is written.
    pub fn open_with(
        mut dev: Box<dyn BlockDevice>,
        uuid: impl FnOnce() -> [u8; 16],
        partitions: u32,
    ) -> Result<(Self, Opened), DiskError> {
        let total = dev.sectors();
        let topo = dev.topology();
        let gran = gran_of(&topo);
        let (a, b) = read_slots(dev.as_mut())?;
        match Layout::select(&a, &b, total)? {
            Some((layout, slot)) => {
                let sizes = read_sizes(dev.as_mut())?;
                let disk = Self::assemble(dev, layout, sizes, slot, gran, topo);
                Ok((disk, Opened::Existing))
            }
            None => {
                let params = Params {
                    partitions,
                    align_sectors: topo.layout_align_sectors(),
                };
                let layout = Layout::plan(total, uuid(), params)?;
                let sizes = SizeTable::default();
                let mut disk = Self::assemble(dev, layout, sizes, 0, gran, topo);
                // Size table first, superblock last: a crash in between
                // leaves a blank-looking disk that is formatted again.
                let size_a = disk.sizes.encode();
                disk.write_dev(SIZE_SLOT_LBA[0], &size_a)?;
                disk.write_dev(SIZE_SLOT_LBA[1], &[0u8; BLOCK])?;
                disk.dev.flush()?;
                let sb = disk.layout.encode();
                disk.write_dev(SB_SLOT_LBA[0], &sb)?;
                disk.dev.flush()?;
                Ok((disk, Opened::Formatted))
            }
        }
    }

    /// The read-only view of a layout-v1 disk, for the offline migration
    /// tool. The kernel never calls this.
    pub fn open_v1(mut dev: Box<dyn BlockDevice>) -> Result<Self, DiskError> {
        let total = dev.sectors();
        let topo = dev.topology();
        let mut sb = [0u8; BLOCK];
        dev.read(SB_SLOT_LBA[0], &mut sb)?;
        let layout = crate::layout::v1::decode(&sb, total)?.ok_or(LayoutError::UnknownData)?;
        let sizes = read_sizes(dev.as_mut())?;
        Ok(Self::assemble(dev, layout, sizes, 0, gran_of(&topo), topo))
    }

    /// A disk over `dev` with the given layout and sizes, nothing read or
    /// written. For tools that stage a layout before it is switched on.
    pub fn with_layout(
        dev: Box<dyn BlockDevice>,
        layout: Layout,
        sizes: SizeTable,
        sb_slot: usize,
    ) -> Self {
        let topo = dev.topology();
        let gran = gran_of(&topo);
        Self::assemble(dev, layout, sizes, sb_slot, gran, topo)
    }

    fn assemble(
        dev: Box<dyn BlockDevice>,
        layout: Layout,
        sizes: SizeTable,
        sb_slot: usize,
        gran: usize,
        topo: Topology,
    ) -> Self {
        Self {
            dev,
            layout,
            sizes,
            dirty: false,
            sb_slot,
            gran,
            topo,
            unsynced: false,
            discard: None,
            stats: DiskStats::default(),
        }
    }

    /// Turns the discard queue on (`storage.discard = "auto"`) or off. On
    /// only if the device offers a command. Returns the device's limits
    /// when discards are on. Calling it with `false` drops what is queued.
    pub fn set_discard(&mut self, on: bool) -> Option<DiscardCaps> {
        self.discard = None;
        if !on {
            return None;
        }
        let mut caps = self.dev.discard_caps()?;
        caps.granularity = caps.granularity.max(1);
        caps.max_ranges = caps.max_ranges.max(1);
        if caps.max_sectors < caps.granularity {
            return None;
        }
        self.discard = Some(DiscardState {
            caps,
            staged: Vec::new(),
            ready: Vec::new(),
            stats: DiscardStats::default(),
            failures: 0,
            stopped: false,
        });
        Some(caps)
    }

    /// Whether discards are on and have not been stopped by the device.
    pub fn discard_active(&self) -> bool {
        self.discard.as_ref().is_some_and(|d| !d.stopped)
    }

    pub fn discard_stats(&self) -> Option<DiscardStats> {
        self.discard.as_ref().map(|d| d.stats)
    }

    /// Whether ranges wait to be sent (staged ranges wait for a sync).
    pub fn discard_pending(&self) -> bool {
        self.discard
            .as_ref()
            .is_some_and(|d| !d.stopped && !(d.ready.is_empty() && d.staged.is_empty()))
    }

    /// Whether ranges are ready to be sent now.
    pub fn discard_ready(&self) -> bool {
        self.discard
            .as_ref()
            .is_some_and(|d| !d.stopped && !d.ready.is_empty())
    }

    /// Queues the byte range `[offset, offset + len)` of region `kind` to
    /// be released (a retired telemetry segment). Nothing is sent now: the
    /// range waits for the next [`sync`](Self::sync) (what retired it is
    /// durable by then) and for [`run_discards`](Self::run_discards), and a
    /// write to it in the meantime takes it back. The range is shrunk to
    /// the device's granularity and to whole physical blocks.
    pub fn discard_region(
        &mut self,
        kind: RegionKind,
        offset: u64,
        len: u64,
        source: DiscardSource,
    ) {
        if self.discard.is_none() || len == 0 {
            return;
        }
        let Ok(len_us) = usize::try_from(len) else {
            return;
        };
        let Ok(pieces) = self.pieces(kind, offset, len_us) else {
            return;
        };
        for (lba0, off, n) in pieces {
            let s = lba0 + off.div_ceil(SECTOR);
            let e = lba0 + (off + n as u64) / SECTOR;
            self.discard_sectors(s, e, source);
        }
    }

    /// Queues the device sectors `[start, end)` (relative to this device)
    /// as [`discard_region`](Self::discard_region) does.
    fn discard_sectors(&mut self, start: u64, end: u64, source: DiscardSource) {
        let base = self.dev.base_lba();
        let total = self.dev.sectors();
        // With nothing waiting to become durable there is nothing the
        // retirement could still depend on: the range is ready at once.
        let durable = !self.unsynced && !self.dirty;
        let Some(d) = self.discard.as_mut() else {
            return;
        };
        if d.stopped {
            return;
        }
        // Inward to the granule, judged on the physical disk, and to the
        // write granularity: a partial physical block is never released.
        let g = d.caps.granularity;
        let wg = (self.gran as u64 / SECTOR).max(1);
        let unit = g / gcd(g, wg) * wg;
        let a = (base + start).div_ceil(unit) * unit;
        let b = (base + end.min(total)) / unit * unit;
        let (Some(a), Some(b)) = (a.checked_sub(base), b.checked_sub(base)) else {
            return;
        };
        if b <= a {
            return;
        }
        let bytes = (b - a) * SECTOR;
        let list = if durable { &mut d.ready } else { &mut d.staged };
        if span_add(list, a, b) {
            match source {
                DiscardSource::Telemetry => d.stats.queued_telemetry += bytes,
                DiscardSource::Truncate => d.stats.queued_truncate += bytes,
                DiscardSource::Grow => d.stats.queued_grow += bytes,
            }
        } else {
            d.stats.dropped += bytes;
        }
    }

    /// A write to `[lba, lba + sectors)` takes back queued ranges there.
    fn discard_cancel(&mut self, lba: u64, sectors: u64) {
        let Some(d) = self.discard.as_mut() else {
            return;
        };
        if d.staged.is_empty() && d.ready.is_empty() {
            return;
        }
        let e = lba + sectors;
        let cut = span_cut(&mut d.staged, lba, e) + span_cut(&mut d.ready, lba, e);
        d.stats.cancelled += cut * SECTOR;
    }

    /// Sends at most `max_requests` discard requests for ranges a sync has
    /// released, each within the device's limits. Called by the owner of
    /// the disk when it is idle: never between a write and the flush that
    /// makes it durable, and never in front of a commit. Returns the bytes
    /// the device was told to release. A failing device is given up on
    /// after a few errors (counted in the stats).
    pub fn run_discards(&mut self, max_requests: usize) -> Result<u64, DiskError> {
        let mut sent = 0u64;
        for _ in 0..max_requests {
            let Some(d) = self.discard.as_mut().filter(|d| !d.stopped) else {
                break;
            };
            let caps = d.caps;
            let chunk = caps
                .max_sectors
                .min(MAX_CHUNK_SECTORS)
                .max(caps.granularity);
            let chunk = chunk / caps.granularity * caps.granularity;
            let mut batch: Vec<(u64, u64)> = Vec::new();
            while batch.len() < caps.max_ranges as usize {
                let Some(first) = d.ready.first_mut() else {
                    break;
                };
                let n = (first.1 - first.0).min(chunk);
                batch.push((first.0, n));
                first.0 += n;
                if first.0 >= first.1 {
                    d.ready.remove(0);
                }
            }
            if batch.is_empty() {
                break;
            }
            let bytes: u64 = batch.iter().map(|b| b.1 * SECTOR).sum();
            let ranges = batch.len() as u64;
            match self.dev.discard(&batch) {
                Ok(()) => {
                    if let Some(d) = self.discard.as_mut() {
                        d.stats.requests += 1;
                        d.stats.ranges += ranges;
                        d.stats.bytes += bytes;
                        d.failures = 0;
                    }
                    sent += bytes;
                }
                Err(e) => {
                    if let Some(d) = self.discard.as_mut() {
                        d.stats.failed += 1;
                        d.failures += 1;
                        if e == IoError::Unsupported {
                            d.stats.unsupported = true;
                            d.stopped = true;
                        }
                        if d.failures >= MAX_FAILURES {
                            d.stopped = true;
                        }
                        if d.stopped {
                            d.ready.clear();
                            d.staged.clear();
                        }
                    }
                    return Err(DiskError::Io(e));
                }
            }
        }
        Ok(sent)
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn sizes(&self) -> SizeTable {
        self.sizes
    }

    pub fn topology(&self) -> Topology {
        self.topo
    }

    /// The superblock slot (0 = A at LBA 0, 1 = B at LBA 24) in force.
    pub fn sb_slot(&self) -> usize {
        self.sb_slot
    }

    /// Granularity of device writes (and reads), bytes.
    pub fn write_gran(&self) -> usize {
        self.gran
    }

    /// The first extent of `kind`.
    pub fn region(&self, kind: RegionKind) -> Option<Region> {
        self.layout.region(kind)
    }

    /// Logical size in bytes of all extents of `kind`.
    pub fn bytes(&self, kind: RegionKind) -> u64 {
        self.layout.bytes(kind)
    }

    pub fn file_size(&self, f: FileKind) -> u64 {
        self.sizes.sizes.get(f as usize).copied().unwrap_or(0)
    }

    pub fn set_file_size(&mut self, f: FileKind, size: u64) {
        let Some(s) = self.sizes.sizes.get_mut(f as usize) else {
            return;
        };
        if *s == size {
            return;
        }
        let old = *s;
        *s = size;
        self.dirty = true;
        // The logical tail of a truncated file is free (xTruncate, ADR-150).
        if size < old {
            self.discard_region(
                RegionKind::of_file(f),
                size,
                old - size,
                DiscardSource::Truncate,
            );
        }
    }

    /// The device sectors beyond the formatted layout: what a grow would
    /// add (0 when the device is not larger).
    pub fn spare_sectors(&self) -> u64 {
        self.dev.sectors().saturating_sub(self.layout.total_sectors)
    }

    pub fn device_sectors(&self) -> u64 {
        self.dev.sectors()
    }

    /// Writes to the device, counting requests that are not whole physical
    /// blocks on the real disk.
    fn write_dev(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        let g = self.gran as u64;
        let abs = (self.dev.base_lba() + lba) * SECTOR;
        let shift = u64::from(self.topo.align_offset) % g;
        self.stats.device_writes += 1;
        if !abs.wrapping_sub(shift).is_multiple_of(g) || !(buf.len() as u64).is_multiple_of(g) {
            self.stats.misaligned_writes += 1;
        }
        self.discard_cancel(lba, (buf.len() as u64).div_ceil(SECTOR));
        self.unsynced = true;
        self.dev.write(lba, buf)
    }

    /// Flushes data, then persists changed file sizes and flushes again, so
    /// a size never covers data that is not yet durable.
    pub fn sync(&mut self) -> Result<(), DiskError> {
        self.dev.flush()?;
        self.stats.flushes += 1;
        if self.dirty {
            let next = SizeTable {
                seq: self.sizes.seq + 1,
                sizes: self.sizes.sizes,
            };
            let lba = SIZE_SLOT_LBA
                .get(self.sizes.next_slot())
                .copied()
                .unwrap_or(SIZE_SLOT_LBA[0]);
            self.write_dev(lba, &next.encode())?;
            self.dev.flush()?;
            self.stats.flushes += 1;
            self.stats.size_table_writes += 1;
            self.sizes = next;
            self.dirty = false;
        }
        // Everything that retired the staged ranges is durable now.
        self.unsynced = false;
        if let Some(d) = self.discard.as_mut() {
            for (a, b) in core::mem::take(&mut d.staged) {
                if !span_add(&mut d.ready, a, b) {
                    d.stats.dropped += (b - a) * SECTOR;
                }
            }
        }
        Ok(())
    }

    /// Grows the layout into the space a larger device offers (S3). The new
    /// space is split by `ratio_db_pct` between the database and the
    /// telemetry ring as new extents; nothing that exists moves. The whole
    /// update is one write of the superblock slot not in force, then a
    /// flush: a crash leaves the old layout (slot torn or not yet written)
    /// or the new one, never a mixture (ADR-142). `Ok(None)`: nothing to add.
    pub fn grow(&mut self, ratio_db_pct: u32) -> Result<Option<Grown>, DiskError> {
        if self.layout.is_v1_view() {
            return Err(LayoutError::OldVersion(1).into());
        }
        let unit = crate::telemetry::band_unit(self)?;
        let Some(next) = self.layout.grown(self.dev.sectors(), ratio_db_pct, unit)? else {
            return Ok(None);
        };
        // Everything written so far is durable before the layout that may
        // reference new space; the new space itself holds nothing yet.
        self.dev.flush()?;
        let slot = 1 - self.sb_slot;
        let sb = next.encode();
        self.write_dev(
            SB_SLOT_LBA.get(slot).copied().unwrap_or(SB_SLOT_LBA[0]),
            &sb,
        )?;
        self.dev.flush()?;
        let info = Grown {
            old_total: self.layout.total_sectors,
            new_total: next.total_sectors,
            generation: next.generation,
            db_sectors: next
                .bytes(RegionKind::Db)
                .saturating_sub(self.layout.bytes(RegionKind::Db))
                / SECTOR,
            telemetry_sectors: next
                .bytes(RegionKind::Telemetry)
                .saturating_sub(self.layout.bytes(RegionKind::Telemetry))
                / SECTOR,
        };
        // The added space may hold what an earlier life of the volume left
        // there: release it (nothing references it yet).
        let top = |l: &Layout| {
            l.regions
                .iter()
                .filter(|r| r.kind != RegionKind::Scratch)
                .map(Region::end)
                .max()
                .unwrap_or(0)
        };
        let (from, to) = (top(&self.layout), top(&next));
        self.layout = next;
        self.sb_slot = slot;
        self.discard_sectors(from, to, DiscardSource::Grow);
        Ok(Some(info))
    }

    /// Where slot `slot`'s payload sits in the backup region: (offset of
    /// its first byte, bytes it can hold). `None`: no backup region or no
    /// such slot.
    pub fn backup_payload(&self, slot: usize) -> Option<(u64, u64)> {
        if slot > 1 {
            return None;
        }
        let g = self.layout.backup()?;
        Some((
            g.slot_offset(slot) + crate::layout::BACKUP_HEADER_BYTES,
            g.payload_capacity(),
        ))
    }

    /// Gives a layout without a backup region one (layout v2.0 -> v2.1, S5,
    /// ADR-160): the tail of the database's last extent beyond its logical
    /// end becomes the control block and two snapshot slots. Their header
    /// blocks are zeroed (and flushed) first, so whatever the bytes held
    /// reads as "no backup"; then the new superblock goes to the slot not in
    /// force, the only write that matters. A crash before it leaves the old
    /// layout, a torn write leaves the old slot in force, a completed one
    /// the new layout. Nothing moves.
    pub fn ensure_backup(&mut self) -> Result<BackupRegion, DiskError> {
        if self.layout.region(RegionKind::Backup).is_some() {
            return Ok(BackupRegion::Present);
        }
        let db_bytes = self
            .file_size(FileKind::Db)
            .max(self.sizes.sizes.first().copied().unwrap_or(0));
        let Some(next) = self.layout.with_backup(db_bytes) else {
            return Ok(BackupRegion::NoRoom);
        };
        let Some(r) = next.region(RegionKind::Backup) else {
            return Ok(BackupRegion::NoRoom);
        };
        let g = next.backup().ok_or(LayoutError::Inconsistent)?;
        // Whatever the DB's dead tail held is not a backup.
        let zeros = [0u8; BLOCK];
        for off in [0, g.slot_offset(0), g.slot_offset(1)] {
            self.write_dev(r.start + off / SECTOR, &zeros)?;
        }
        self.dev.flush()?;
        let slot = 1 - self.sb_slot;
        self.write_dev(
            SB_SLOT_LBA.get(slot).copied().unwrap_or(SB_SLOT_LBA[0]),
            &next.encode(),
        )?;
        self.dev.flush()?;
        self.discard_cancel(r.start, r.sectors);
        self.layout = next;
        self.sb_slot = slot;
        Ok(BackupRegion::Added {
            bytes: r.bytes(),
            slot_bytes: g.slot_bytes,
        })
    }

    /// Writes zeros over the bytes `[from, to)` of region `kind`: a file
    /// that grows without being written (a write past its end, a truncate
    /// to a larger size) must read as zeros there, and the device may hold
    /// anything after a discard (ADR-150).
    pub fn zero_fill(&mut self, kind: RegionKind, from: u64, to: u64) -> Result<(), DiskError> {
        const STEP: u64 = 64 * 1024;
        let zeros = vec![0u8; STEP as usize];
        let mut at = from;
        while at < to {
            let n = (to - at).min(STEP) as usize;
            self.write_at(kind, at, zeros.get(..n).unwrap_or(&[]))?;
            at += n as u64;
        }
        Ok(())
    }

    /// Online grow (S3, ADR-143), after a configuration-change notification
    /// said the device may have grown: the partition table steps on the
    /// whole disk (backup table to the new end, data partition extended), the
    /// window follows, then [`grow`](Self::grow). Nothing else touches the
    /// disk meanwhile (the caller owns it). `Ok(None)`: the device did not
    /// get larger, or the layout has nothing to add.
    pub fn grow_online(
        &mut self,
        ratio_db_pct: u32,
        random: impl FnMut() -> [u8; 16],
    ) -> Result<Option<Grown>, DiskError> {
        if self.dev.refresh_size().is_none() {
            return Ok(None);
        }
        let part = {
            let whole = self.dev.whole_disk().ok_or(IoError::Device)?;
            crate::gpt::prepare(whole, random)
                .map_err(|_| IoError::Device)?
                .0
        };
        self.dev.resize_window(part.sectors());
        self.grow(ratio_db_pct)
    }

    /// Splits the byte range `[offset, offset + len)` of the logical region
    /// `kind` (all its extents back to back) into pieces inside one extent:
    /// (first sector of the extent, offset inside it, bytes).
    fn pieces(
        &self,
        kind: RegionKind,
        offset: u64,
        len: usize,
    ) -> Result<Vec<(u64, u64, usize)>, DiskError> {
        let end = offset.checked_add(len as u64).ok_or(DiskError::Full)?;
        if self.layout.region(kind).is_none() {
            return Err(LayoutError::Inconsistent.into());
        }
        let mut out = Vec::new();
        let mut base = 0u64;
        for r in self.layout.extents(kind) {
            let top = base + r.bytes();
            if offset < top && end > base {
                let from = offset.max(base);
                let to = end.min(top);
                out.push((r.start, from - base, (to - from) as usize));
            }
            base = top;
        }
        if base < end {
            return Err(DiskError::Full);
        }
        Ok(out)
    }

    /// Reads `buf.len()` bytes at byte `offset` of region `kind`.
    pub fn read_at(
        &mut self,
        kind: RegionKind,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), DiskError> {
        let mut done = 0usize;
        for (lba0, off, n) in self.pieces(kind, offset, buf.len())? {
            let dst = buf.get_mut(done..done + n).ok_or(DiskError::Full)?;
            self.read_extent(lba0, off, dst)?;
            done += n;
        }
        Ok(())
    }

    fn read_extent(&mut self, lba0: u64, offset: u64, buf: &mut [u8]) -> Result<(), DiskError> {
        let g = self.gran as u64;
        let chunk = self.chunk_bytes() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let blk = pos - pos % g;
            let skip = (pos - blk) as usize;
            let want = ((buf.len() - done) as u64).min(chunk - (pos - blk)) as usize;
            let span = (skip + want).div_ceil(self.gran) * self.gran;
            let mut bounce = vec![0u8; span];
            self.dev.read(lba0 + blk / SECTOR, &mut bounce)?;
            self.stats.reads += 1;
            self.stats.bytes_read += span as u64;
            let src = bounce.get(skip..skip + want).ok_or(DiskError::Full)?;
            buf.get_mut(done..done + want)
                .ok_or(DiskError::Full)?
                .copy_from_slice(src);
            done += want;
        }
        Ok(())
    }

    /// Writes `data` at byte `offset` of region `kind`. Every device write
    /// covers whole physical blocks: the partial blocks at the edges are
    /// read first (read-modify-write).
    pub fn write_at(
        &mut self,
        kind: RegionKind,
        offset: u64,
        data: &[u8],
    ) -> Result<(), DiskError> {
        let mut done = 0usize;
        for (lba0, off, n) in self.pieces(kind, offset, data.len())? {
            let src = data.get(done..done + n).ok_or(DiskError::Full)?;
            self.write_extent(lba0, off, src)?;
            done += n;
        }
        Ok(())
    }

    fn write_extent(&mut self, lba0: u64, offset: u64, data: &[u8]) -> Result<(), DiskError> {
        let g = self.gran;
        let gu = g as u64;
        let max_span = (self.chunk_bytes() / g).max(1) as u64 * gu;
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let blk = pos - pos % gu;
            let skip = (pos - blk) as usize;
            let want = ((data.len() - done) as u64).min(max_span - (pos - blk)) as usize;
            let end = pos + want as u64;
            let span_end = end.div_ceil(gu) * gu;
            let span = (span_end - blk) as usize;
            let mut bounce = vec![0u8; span];
            if skip != 0 {
                let head = bounce.get_mut(..g).ok_or(DiskError::Full)?;
                self.dev.read(lba0 + blk / SECTOR, head)?;
                self.stats.reads += 1;
            }
            let tail_partial = !end.is_multiple_of(gu);
            if tail_partial && !(skip != 0 && span == g) {
                let tail = bounce.get_mut(span - g..).ok_or(DiskError::Full)?;
                self.dev.read(lba0 + (span_end - gu) / SECTOR, tail)?;
                self.stats.reads += 1;
            }
            let src = data.get(done..done + want).ok_or(DiskError::Full)?;
            bounce
                .get_mut(skip..skip + want)
                .ok_or(DiskError::Full)?
                .copy_from_slice(src);
            self.write_dev(lba0 + blk / SECTOR, &bounce)?;
            self.stats.writes += 1;
            self.stats.bytes_written += span as u64;
            done += want;
        }
        Ok(())
    }

    fn chunk_bytes(&self) -> usize {
        let s = SECTOR as usize;
        ((self.dev.max_io() / s).max(2) * s).max(self.gran)
    }

    /// The device, for the offline tools that stage their own writes.
    pub fn device_mut(&mut self) -> &mut dyn BlockDevice {
        self.dev.as_mut()
    }
}

fn gran_of(t: &Topology) -> usize {
    t.write_gran().max(t.logical as usize)
}

fn read_slots(dev: &mut dyn BlockDevice) -> Result<([u8; BLOCK], [u8; BLOCK]), DiskError> {
    let mut a = [0u8; BLOCK];
    let mut b = [0u8; BLOCK];
    dev.read(SB_SLOT_LBA[0], &mut a)?;
    dev.read(SB_SLOT_LBA[1], &mut b)?;
    Ok((a, b))
}

fn read_sizes(dev: &mut dyn BlockDevice) -> Result<SizeTable, DiskError> {
    let mut a = [0u8; BLOCK];
    let mut b = [0u8; BLOCK];
    dev.read(SIZE_SLOT_LBA[0], &mut a)?;
    dev.read(SIZE_SLOT_LBA[1], &mut b)?;
    Ok(
        SizeTable::newest(SizeTable::decode(&a), SizeTable::decode(&b))
            .ok_or(LayoutError::SizeTableLost)?,
    )
}

/// What a [`MemDisk`] returns for sectors it was told to discard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// Zeros (a thin-provisioned disk, WRITE ZEROES).
    Zeros,
    /// Pseudo-random bytes: the contents are undefined, and recovery must
    /// not trust them.
    Garbage,
    /// The old data: the device ignored the command.
    Keep,
}

/// A discard-capable [`MemDisk`]: strict about the limits it advertises.
struct MemDiscard {
    caps: DiscardCaps,
    released: Released,
    /// Every range accepted, in order.
    log: Vec<(u64, u64)>,
    requests: u64,
    /// Requests that broke the advertised limits (and were refused).
    violations: u64,
    /// Fail the request that would be this number (1-based), once.
    fail_request: Option<u64>,
}

/// One unflushed operation of the volatile cache.
enum CacheOp {
    Write(u64, Vec<u8>),
    Discard(u64, u64),
}

/// In-memory block device for host tests, with a volatile write cache:
/// writes become durable only on `flush`, and [`MemDisk::crash`] throws
/// the cache away (or keeps a chosen subset) like a power loss. The medium
/// is sparse (4 KiB blocks, zero until written), so a 64 GiB disk costs
/// only what is written to it.
#[derive(Clone)]
pub struct MemDisk {
    inner: Arc<SpinLock<MemInner>>,
}

struct MemInner {
    bytes: u64,
    durable: BTreeMap<u64, Box<[u8; BLOCK]>>,
    /// Completed but unflushed writes and discards, in order.
    cache: Vec<CacheOp>,
    discard: Option<MemDiscard>,
    writes: u64,
    fail_after_writes: Option<u64>,
    topo: Topology,
    /// The size `refresh_size` last reported.
    seen_bytes: u64,
    /// Reject requests that are not whole logical blocks (a 4Kn disk).
    strict: bool,
    /// Writes that were not whole physical blocks, seen by the medium (an
    /// oracle independent of the store's own counter).
    misaligned: u64,
    flushes: u64,
}

impl MemDisk {
    pub fn new(bytes: usize) -> Self {
        Self::sparse(bytes as u64)
    }

    /// A disk of `bytes` (which may be far larger than memory).
    pub fn sparse(bytes: u64) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(MemInner {
                bytes,
                durable: BTreeMap::new(),
                cache: Vec::new(),
                discard: None,
                writes: 0,
                fail_after_writes: None,
                topo: Topology::default(),
                seen_bytes: bytes,
                strict: false,
                misaligned: 0,
                flushes: 0,
            })),
        }
    }

    /// A disk with the given topology; `strict` rejects reads and writes
    /// that are not whole logical blocks (as a 4Kn device does).
    pub fn with_topology(bytes: u64, topo: Topology, strict: bool) -> Self {
        let d = Self::sparse(bytes);
        {
            let mut g = d.inner.lock();
            g.topo = topo;
            g.strict = strict;
        }
        d
    }

    /// A disk whose medium holds `image` (fuzzing recovery from damaged
    /// images; the length should be a multiple of the sector size).
    pub fn from_image(image: Vec<u8>) -> Self {
        let d = Self::sparse(image.len() as u64);
        {
            let mut g = d.inner.lock();
            for (i, chunk) in image.chunks(BLOCK).enumerate() {
                if chunk.iter().any(|&b| b != 0) {
                    let mut blk = Box::new([0u8; BLOCK]);
                    if let Some(dst) = blk.get_mut(..chunk.len()) {
                        dst.copy_from_slice(chunk);
                    }
                    g.durable.insert(i as u64, blk);
                }
            }
        }
        d
    }

    /// An independent disk holding what is durable now (unflushed writes
    /// are not copied), with the same topology.
    pub fn fork(&self) -> Self {
        let g = self.inner.lock();
        Self {
            inner: Arc::new(SpinLock::new(MemInner {
                bytes: g.bytes,
                durable: g.durable.clone(),
                cache: Vec::new(),
                discard: g.discard.as_ref().map(|d| MemDiscard {
                    caps: d.caps,
                    released: d.released,
                    log: Vec::new(),
                    requests: 0,
                    violations: 0,
                    fail_request: None,
                }),
                writes: 0,
                fail_after_writes: None,
                topo: g.topo,
                seen_bytes: g.bytes,
                strict: g.strict,
                misaligned: 0,
                flushes: 0,
            })),
        }
    }

    /// Simulates power loss: unflushed writes whose index `keep(i)` returns
    /// false are lost, the others reach the medium (in any real order).
    pub fn crash(&self, mut keep: impl FnMut(usize) -> bool) {
        let mut g = self.inner.lock();
        let cache = core::mem::take(&mut g.cache);
        let released = g.discard.as_ref().map(|d| d.released);
        for (i, op) in cache.into_iter().enumerate() {
            if keep(i) {
                apply_op(&mut g.durable, op, released);
            }
        }
        g.fail_after_writes = None;
    }

    /// Fails every write after `n` more writes (an I/O error, then a crash).
    pub fn fail_after(&self, n: u64) {
        let mut g = self.inner.lock();
        g.fail_after_writes = Some(g.writes + n);
    }

    pub fn unflushed(&self) -> usize {
        self.inner.lock().cache.len()
    }

    /// Writes the medium has accepted so far.
    pub fn write_count(&self) -> u64 {
        self.inner.lock().writes
    }

    /// Writes the medium saw that were not whole physical blocks.
    pub fn misaligned_writes(&self) -> u64 {
        self.inner.lock().misaligned
    }

    /// The durable bytes at `offset` (what a reboot would see, ignoring
    /// the cache).
    pub fn raw(&self, offset: usize, len: usize) -> Vec<u8> {
        let g = self.inner.lock();
        let mut out = vec![0u8; len];
        read_blocks(&g.durable, offset as u64, &mut out);
        out
    }

    pub fn len(&self) -> u64 {
        self.inner.lock().bytes
    }

    /// Makes the disk larger (a cloud volume that was enlarged). Opened
    /// disks see the new size at once. Never smaller.
    pub fn grow_to(&self, bytes: u64) {
        let mut g = self.inner.lock();
        g.bytes = g.bytes.max(bytes);
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn device(&self) -> Box<dyn BlockDevice> {
        Box::new(self.clone())
    }

    /// Makes the disk accept discards within `caps`, returning `released`
    /// for what it discarded. Requests outside the limits are refused and
    /// counted by [`discard_violations`](Self::discard_violations).
    #[must_use]
    pub fn with_discard(self, caps: DiscardCaps, released: Released) -> Self {
        self.inner.lock().discard = Some(MemDiscard {
            caps,
            released,
            log: Vec::new(),
            requests: 0,
            violations: 0,
            fail_request: None,
        });
        self
    }

    /// Every range the disk accepted to discard (first sector, sectors).
    pub fn discard_log(&self) -> Vec<(u64, u64)> {
        self.inner
            .lock()
            .discard
            .as_ref()
            .map(|d| d.log.clone())
            .unwrap_or_default()
    }

    pub fn discard_requests(&self) -> u64 {
        self.inner.lock().discard.as_ref().map_or(0, |d| d.requests)
    }

    /// Requests that broke the advertised limits.
    pub fn discard_violations(&self) -> u64 {
        self.inner
            .lock()
            .discard
            .as_ref()
            .map_or(0, |d| d.violations)
    }

    /// Fails the n-th discard request from now (1-based), once.
    pub fn fail_discard(&self, n: u64) {
        if let Some(d) = self.inner.lock().discard.as_mut() {
            d.fail_request = Some(d.requests + n);
        }
    }

    /// Bytes of the medium that hold anything (4 KiB blocks present): what
    /// a thin-provisioned volume would have allocated.
    pub fn allocated_bytes(&self) -> u64 {
        self.inner.lock().durable.len() as u64 * BLOCK as u64
    }

    /// Overwrites sectors of the durable medium with pseudo-random bytes
    /// (what an unmapped range may read back as).
    pub fn scribble(&self, lba: u64, sectors: u64, seed: u64) {
        let mut g = self.inner.lock();
        garbage(&mut g.durable, lba, sectors, seed);
    }
}

const GARBAGE_SEED: u64 = 0x0d15_ca2d;

/// Pseudo-random bytes (xorshift) into `[lba, lba + sectors)`.
fn garbage(durable: &mut BTreeMap<u64, Box<[u8; BLOCK]>>, lba: u64, sectors: u64, seed: u64) {
    // Each sector's bytes depend only on its number, so a read of part of a
    // discarded range sees what the flush will write.
    let mut buf = vec![0u8; (sectors * SECTOR) as usize];
    for (i, sector) in buf.chunks_mut(SECTOR as usize).enumerate() {
        let mut x = (seed ^ (lba + i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1;
        for b in sector {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x >> 24) as u8;
        }
    }
    apply(durable, lba, &buf);
}

/// Zeros into `[lba, lba + sectors)`; whole blocks leave the map.
fn zero_range(durable: &mut BTreeMap<u64, Box<[u8; BLOCK]>>, lba: u64, sectors: u64) {
    let (mut at, end) = (lba * SECTOR, (lba + sectors) * SECTOR);
    let bs = BLOCK as u64;
    while at < end {
        let idx = at / bs;
        let off = (at % bs) as usize;
        let n = (bs - off as u64).min(end - at) as usize;
        if off == 0 && n == BLOCK {
            durable.remove(&idx);
        } else if let Some(blk) = durable.get_mut(&idx)
            && let Some(d) = blk.get_mut(off..off + n)
        {
            d.fill(0);
        }
        at += n as u64;
    }
}

fn apply_op(
    durable: &mut BTreeMap<u64, Box<[u8; BLOCK]>>,
    op: CacheOp,
    released: Option<Released>,
) {
    match op {
        CacheOp::Write(lba, data) => apply(durable, lba, &data),
        CacheOp::Discard(lba, n) => match released {
            Some(Released::Zeros) => zero_range(durable, lba, n),
            Some(Released::Garbage) => garbage(durable, lba, n, GARBAGE_SEED),
            Some(Released::Keep) | None => {}
        },
    }
}

fn read_blocks(m: &BTreeMap<u64, Box<[u8; BLOCK]>>, mut at: u64, out: &mut [u8]) {
    let mut done = 0usize;
    while done < out.len() {
        let idx = at / BLOCK as u64;
        let off = (at % BLOCK as u64) as usize;
        let n = (BLOCK - off).min(out.len() - done);
        if let (Some(blk), Some(dst)) = (m.get(&idx), out.get_mut(done..done + n))
            && let Some(src) = blk.get(off..off + n)
        {
            dst.copy_from_slice(src);
        }
        done += n;
        at += n as u64;
    }
}

fn apply(durable: &mut BTreeMap<u64, Box<[u8; BLOCK]>>, lba: u64, data: &[u8]) {
    let mut at = lba * SECTOR;
    let mut done = 0usize;
    while done < data.len() {
        let idx = at / BLOCK as u64;
        let off = (at % BLOCK as u64) as usize;
        let n = (BLOCK - off).min(data.len() - done);
        let blk = durable.entry(idx).or_insert_with(|| Box::new([0u8; BLOCK]));
        if let (Some(dst), Some(src)) = (blk.get_mut(off..off + n), data.get(done..done + n)) {
            dst.copy_from_slice(src);
        }
        done += n;
        at += n as u64;
    }
}

impl BlockDevice for MemDisk {
    fn sectors(&self) -> u64 {
        self.inner.lock().bytes / SECTOR
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let g = self.inner.lock();
        let at = lba * SECTOR;
        if at + buf.len() as u64 > g.bytes {
            return Err(IoError::OutOfRange);
        }
        let lb = u64::from(g.topo.logical);
        if g.strict && (!at.is_multiple_of(lb) || !(buf.len() as u64).is_multiple_of(lb)) {
            return Err(IoError::Device);
        }
        read_blocks(&g.durable, at, buf);
        // Reads see cached writes and discards, newest last.
        let released = g.discard.as_ref().map(|d| d.released);
        for op in &g.cache {
            let (rs, re) = (lba * SECTOR, lba * SECTOR + buf.len() as u64);
            match op {
                CacheOp::Write(wlba, data) => {
                    let (ws, we) = (*wlba * SECTOR, *wlba * SECTOR + data.len() as u64);
                    let (s, e) = (ws.max(rs), we.min(re));
                    if s < e {
                        let dst = buf.get_mut((s - rs) as usize..(e - rs) as usize);
                        let src = data.get((s - ws) as usize..(e - ws) as usize);
                        if let (Some(d), Some(x)) = (dst, src) {
                            d.copy_from_slice(x);
                        }
                    }
                }
                CacheOp::Discard(dlba, n) => {
                    let (ds, de) = (*dlba * SECTOR, (*dlba + *n) * SECTOR);
                    let (s, e) = (ds.max(rs), de.min(re));
                    if s < e && released != Some(Released::Keep) {
                        // Evaluate on a scratch map so reads and the
                        // eventual flush agree byte for byte.
                        let mut tmp = BTreeMap::new();
                        let first = s / SECTOR;
                        let cnt = (e - s).div_ceil(SECTOR);
                        if released == Some(Released::Garbage) {
                            garbage(&mut tmp, first, cnt, GARBAGE_SEED);
                        }
                        let mut out = vec![0u8; (cnt * SECTOR) as usize];
                        read_blocks(&tmp, first * SECTOR, &mut out);
                        let dst = buf.get_mut((s - rs) as usize..(e - rs) as usize);
                        if let Some(d) = dst {
                            let from = (s - first * SECTOR) as usize;
                            d.copy_from_slice(out.get(from..from + d.len()).unwrap_or(&[]));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        let mut g = self.inner.lock();
        let at = lba * SECTOR;
        if at + buf.len() as u64 > g.bytes {
            return Err(IoError::OutOfRange);
        }
        let lb = u64::from(g.topo.logical);
        if g.strict && (!at.is_multiple_of(lb) || !(buf.len() as u64).is_multiple_of(lb)) {
            return Err(IoError::Device);
        }
        if g.fail_after_writes.is_some_and(|n| g.writes >= n) {
            return Err(IoError::Device);
        }
        let ph = u64::from(g.topo.physical).clamp(SECTOR, BLOCK as u64);
        if !at.is_multiple_of(ph) || !(buf.len() as u64).is_multiple_of(ph) {
            g.misaligned += 1;
        }
        g.writes += 1;
        g.cache.push(CacheOp::Write(lba, buf.to_vec()));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        let mut g = self.inner.lock();
        let cache = core::mem::take(&mut g.cache);
        g.flushes += 1;
        let released = g.discard.as_ref().map(|d| d.released);
        for op in cache {
            apply_op(&mut g.durable, op, released);
        }
        Ok(())
    }

    fn discard_caps(&self) -> Option<DiscardCaps> {
        self.inner.lock().discard.as_ref().map(|d| d.caps)
    }

    fn discard(&mut self, ranges: &[(u64, u64)]) -> Result<(), IoError> {
        let mut g = self.inner.lock();
        let total = g.bytes / SECTOR;
        let cut = g.fail_after_writes.is_some_and(|n| g.writes >= n);
        let Some(d) = g.discard.as_mut() else {
            return Err(IoError::Unsupported);
        };
        d.requests += 1;
        let c = d.caps;
        let ok = !ranges.is_empty()
            && ranges.len() <= c.max_ranges as usize
            && ranges.iter().all(|&(s, n)| {
                n > 0
                    && n <= c.max_sectors
                    && s.is_multiple_of(c.granularity)
                    && n.is_multiple_of(c.granularity)
                    && s + n <= total
            });
        if !ok {
            d.violations += 1;
            return Err(IoError::Device);
        }
        if d.fail_request == Some(d.requests) {
            d.fail_request = None;
            return Err(IoError::Device);
        }
        if cut {
            return Err(IoError::Device);
        }
        d.log.extend_from_slice(ranges);
        g.writes += 1;
        for &(s, n) in ranges {
            g.cache.push(CacheOp::Discard(s, n));
        }
        Ok(())
    }

    fn max_io(&self) -> usize {
        // Small, so tests exercise chunking.
        8 * 1024
    }

    fn topology(&self) -> Topology {
        self.inner.lock().topo
    }

    fn refresh_size(&mut self) -> Option<u64> {
        let mut g = self.inner.lock();
        (g.bytes > g.seen_bytes).then(|| {
            g.seen_bytes = g.bytes;
            g.bytes / SECTOR
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::MIB_SECTORS;

    fn disk() -> (MemDisk, Disk) {
        let m = MemDisk::new(16 << 20);
        let (d, how) = Disk::open(m.device(), || [3; 16]).unwrap();
        assert_eq!(how, Opened::Formatted);
        (m, d)
    }

    #[test]
    fn unaligned_io_round_trips_across_chunks() {
        let (_m, mut d) = disk();
        let data: Vec<u8> = (0..30_000u32).map(|i| (i * 7 + 3) as u8).collect();
        for off in [0u64, 1, 511, 512, 4095, 9000] {
            d.write_at(RegionKind::Wal, off, &data).unwrap();
            let mut back = vec![0u8; data.len()];
            d.read_at(RegionKind::Wal, off, &mut back).unwrap();
            assert_eq!(back, data, "offset {off}");
        }
        // Neighbouring bytes survive a small unaligned write.
        d.write_at(RegionKind::Wal, 0, &data).unwrap();
        d.write_at(RegionKind::Wal, 100, &[0xaa; 3]).unwrap();
        let mut b = [0u8; 8];
        d.read_at(RegionKind::Wal, 98, &mut b).unwrap();
        assert_eq!(b[..2], data[98..100]);
        assert_eq!(b[2..5], [0xaa; 3]);
        assert_eq!(b[5..], data[103..106]);
    }

    #[test]
    fn bounds_are_enforced() {
        let (_m, mut d) = disk();
        let r = d.region(RegionKind::Journal).unwrap();
        assert_eq!(
            d.write_at(RegionKind::Journal, r.bytes() - 1, &[1, 2]),
            Err(DiskError::Full)
        );
        assert!(
            d.write_at(RegionKind::Journal, r.bytes() - 2, &[1, 2])
                .is_ok()
        );
    }

    #[test]
    fn sizes_persist_only_after_sync_and_survive_reopen() {
        let (m, mut d) = disk();
        d.set_file_size(FileKind::Db, 8192);
        drop(d);
        m.crash(|_| true);
        let (mut d, how) = Disk::open(m.device(), || [0; 16]).unwrap();
        assert_eq!(how, Opened::Existing);
        assert_eq!(d.file_size(FileKind::Db), 0);
        d.set_file_size(FileKind::Db, 8192);
        d.set_file_size(FileKind::Wal, 4120);
        d.sync().unwrap();
        d.set_file_size(FileKind::Db, 12288);
        d.sync().unwrap();
        d.set_file_size(FileKind::Db, 99);
        drop(d);
        m.crash(|_| false);
        let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
        assert_eq!(d.file_size(FileKind::Db), 12288);
        assert_eq!(d.file_size(FileKind::Wal), 4120);
        assert_eq!(d.layout().uuid, [3; 16]);
    }

    #[test]
    fn torn_size_table_falls_back_to_previous_slot() {
        let (m, mut d) = disk();
        d.set_file_size(FileKind::Db, 4096);
        d.sync().unwrap();
        d.set_file_size(FileKind::Db, 8192);
        // Power fails while the next size-table write is in the cache.
        d.dev.flush().unwrap();
        let next = SizeTable {
            seq: d.sizes.seq + 1,
            sizes: [8192, 0, 0],
        };
        let mut torn = next.encode();
        torn[2000] ^= 0x5a;
        d.dev
            .write(SIZE_SLOT_LBA[d.sizes.next_slot()], &torn)
            .unwrap();
        drop(d);
        m.crash(|_| true);
        let (d, _) = Disk::open(m.device(), || [0; 16]).unwrap();
        assert_eq!(d.file_size(FileKind::Db), 4096);
    }

    #[test]
    fn foreign_disk_is_never_formatted() {
        let m = MemDisk::new(16 << 20);
        let mut dev = m.device();
        let mut junk = [0u8; 512];
        junk[0] = 0xeb;
        dev.write(0, &junk).unwrap();
        dev.flush().unwrap();
        assert_eq!(
            Disk::open(m.device(), || [0; 16]).err(),
            Some(DiskError::Layout(LayoutError::UnknownData))
        );
        assert_eq!(m.raw(0, 1), [0xeb]);
        // Junk in the second slot is foreign data as well.
        let m = MemDisk::new(16 << 20);
        let mut dev = m.device();
        dev.write(SB_SLOT_LBA[1], &junk).unwrap();
        dev.flush().unwrap();
        assert_eq!(
            Disk::open(m.device(), || [0; 16]).err(),
            Some(DiskError::Layout(LayoutError::UnknownData))
        );
    }

    #[test]
    fn a_v1_disk_is_refused_and_nothing_is_written() {
        let m = MemDisk::new(16 << 20);
        let mut dev = m.device();
        let l = crate::layout::v1::plan(32 * 1024, [9; 16]).unwrap();
        dev.write(0, &crate::layout::v1::encode(&l)).unwrap();
        dev.write(SIZE_SLOT_LBA[0], &SizeTable::default().encode())
            .unwrap();
        dev.flush().unwrap();
        let before = m.raw(0, 16 << 20);
        let writes = m.write_count();
        assert_eq!(
            Disk::open(m.device(), || [0; 16]).err(),
            Some(DiskError::Layout(LayoutError::OldVersion(1)))
        );
        assert_eq!(m.write_count(), writes, "no write attempted");
        assert_eq!(m.unflushed(), 0);
        assert!(m.raw(0, 16 << 20) == before, "the disk is unchanged");
        // The tool's view reads it.
        let d = Disk::open_v1(m.device()).unwrap();
        assert!(d.layout().is_v1_view());
    }

    #[test]
    fn grow_is_one_superblock_write_and_keeps_the_data() {
        let m = MemDisk::sparse(1 << 30);
        let (mut d, _) = Disk::open(m.device(), || [4; 16]).unwrap();
        let pat: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        d.write_at(RegionKind::Db, 12_345, &pat).unwrap();
        d.set_file_size(FileKind::Db, 100_000);
        d.sync().unwrap();
        assert_eq!(d.grow(50).unwrap(), None, "nothing to add yet");
        drop(d);
        // The device becomes 4 GiB (the same sparse medium, larger).
        let big = MemDisk::sparse(4 << 30);
        copy_durable(&m, &big);
        let (mut d, _) = Disk::open(big.device(), || [0; 16]).unwrap();
        assert_eq!(d.layout().total_sectors, (1 << 30) / SECTOR);
        let before = big.write_count();
        let g = d.grow(50).unwrap().expect("grows");
        assert_eq!(big.write_count() - before, 1, "one device write");
        assert_eq!(g.new_total, (4u64 << 30) / SECTOR);
        assert_eq!(d.sb_slot(), 1);
        let mut back = vec![0u8; pat.len()];
        d.read_at(RegionKind::Db, 12_345, &mut back).unwrap();
        assert_eq!(back, pat);
        assert!(d.bytes(RegionKind::Db) > 1 << 30);
        // The new database space is writable across the extent boundary.
        let old_db = Layout::plan((1 << 30) / SECTOR, [0; 16], Params::default())
            .unwrap()
            .bytes(RegionKind::Db);
        d.write_at(RegionKind::Db, old_db - 100, &[7u8; 300])
            .unwrap();
        let mut x = [0u8; 300];
        d.read_at(RegionKind::Db, old_db - 100, &mut x).unwrap();
        assert_eq!(x, [7u8; 300]);
        drop(d);
        let (d2, _) = Disk::open(big.device(), || [0; 16]).unwrap();
        assert_eq!(d2.layout().generation, 2);
        assert_eq!(d2.sb_slot(), 1);
        assert_eq!(d2.file_size(FileKind::Db), 100_000);
    }

    fn copy_durable(from: &MemDisk, to: &MemDisk) {
        let src = from.inner.lock();
        to.inner.lock().durable = src.durable.clone();
    }

    #[test]
    fn writes_cover_whole_physical_blocks() {
        for (logical, physical, strict) in
            [(512, 512, false), (512, 4096, false), (4096, 4096, true)]
        {
            let topo = Topology {
                logical,
                physical,
                align_offset: 0,
                min_io: physical,
                opt_io: 0,
            };
            let m = MemDisk::with_topology(64 << 20, topo, strict);
            let (mut d, _) = Disk::open(m.device(), || [5; 16]).unwrap();
            let data: Vec<u8> = (0..30_000u32).map(|i| (i * 7 + 3) as u8).collect();
            for off in [0u64, 1, 511, 512, 4095, 9000, 100_003] {
                d.write_at(RegionKind::Wal, off, &data).unwrap();
                let mut back = vec![0u8; data.len()];
                d.read_at(RegionKind::Wal, off, &mut back).unwrap();
                assert_eq!(back, data, "{logical}/{physical} offset {off}");
            }
            d.set_file_size(FileKind::Db, 777);
            d.sync().unwrap();
            assert_eq!(d.stats.misaligned_writes, 0, "{logical}/{physical}");
            assert_eq!(
                m.misaligned_writes(),
                0,
                "{logical}/{physical}: the medium agrees"
            );
            assert!(d.stats.device_writes > 10);
        }
        // The counter does count: a 512-byte write on a 4 KiB device.
        let topo = Topology {
            logical: 512,
            physical: 4096,
            align_offset: 0,
            min_io: 4096,
            opt_io: 0,
        };
        let m = MemDisk::with_topology(64 << 20, topo, false);
        let mut dev = m.device();
        dev.write(1, &[0u8; 512]).unwrap();
        assert_eq!(m.misaligned_writes(), 1);
    }

    #[test]
    fn regions_follow_the_optimal_io_size() {
        let topo = Topology {
            logical: 512,
            physical: 4096,
            align_offset: 0,
            min_io: 4096,
            opt_io: 2 << 20,
        };
        let m = MemDisk::with_topology(256 << 20, topo, false);
        let (d, _) = Disk::open(m.device(), || [6; 16]).unwrap();
        assert_eq!(u64::from(d.layout().align_sectors), 2 * MIB_SECTORS);
        for r in &d.layout().regions {
            if r.kind != RegionKind::Scratch {
                assert_eq!(r.start % (2 * MIB_SECTORS), 0);
            }
        }
    }
}
