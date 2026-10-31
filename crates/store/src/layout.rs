//! Data disk layout, version 2 (STORAGE-PLAN S2, ADR-140): two superblock
//! slots (A/B, the highest valid generation wins), a double-buffered
//! file-size table, then the regions themselves, every one aligned to 1 MiB
//! and to the device's optimal I/O size. No filesystem. Layout version 1
//! (S0/S1) survives only as the read-only view in [`v1`], for the offline
//! migration tool; the kernel refuses a v1 disk before writing anything.
//!
//! ```text
//! LBA 0      superblock slot A (4 KiB)
//! LBA 8, 16  file-size table slots A and B (4 KiB each, highest valid seq wins)
//! LBA 24     superblock slot B (4 KiB)
//! LBA 32..63 reserved for the offline migration record (zero on a fresh disk)
//! LBA align  regions, each aligned to `align_sectors` (>= 1 MiB): SQLite main
//!            db (one or more extents), WAL, rollback journal, telemetry
//!            (one or more extents)
//! last 8     scratch for the boot block-device self-test
//! ```

use alloc::vec::Vec;

use crate::crc::crc32c;

pub const SECTOR: u64 = 512;
pub const BLOCK: usize = 4096;
pub const BLOCK_SECTORS: u64 = BLOCK as u64 / SECTOR;
pub const MAGIC: [u8; 8] = *b"URMQTTDK";
pub const VERSION: u32 = 2;
pub const SIZE_MAGIC: [u8; 8] = *b"URMQSZT1";
/// The fixed metadata blocks live in the first 32 KiB: both superblock
/// slots, both size-table slots and the migration record. A new data
/// partition zeroes this much so it classifies as blank.
pub const HEADER_SECTORS: u64 = 64;
/// Superblock slots A and B.
pub const SB_SLOT_LBA: [u64; 2] = [0, 24];
pub const SIZE_SLOT_LBA: [u64; 2] = [8, 16];
/// 1 MiB in sectors: the smallest alignment unit of a v2 layout.
pub const MIB_SECTORS: u64 = 1024 * 1024 / SECTOR;
/// Scratch area at the end of the disk (the boot self-test writes there).
pub const SCRATCH_SECTORS: u64 = 8;
/// Smallest supported data disk: 16 MiB.
pub const MIN_SECTORS: u64 = 32 * 1024;
/// Region entries a superblock holds.
pub const MAX_REGIONS: usize = 128;
/// Telemetry partitions a layout may have.
pub const MAX_PARTITIONS: u32 = 64;
/// Largest alignment unit accepted (64 MiB).
pub const MAX_ALIGN_SECTORS: u32 = 131_072;
const REGION_BYTES: usize = 24;
const REGIONS_AT: usize = 64;

/// The telemetry ring of this layout started as a v1 ring that stays where
/// it is (segment headers without a layout UUID, header version 1).
pub const FLAG_LEGACY_TELEMETRY: u32 = 1;
/// Never stored: this layout is the read-only view of a v1 disk.
pub const FLAG_V1_VIEW: u32 = 1 << 31;
const STORED_FLAGS: u32 = FLAG_LEGACY_TELEMETRY;

/// Files the VFS maps onto regions. Their logical sizes live in the size
/// table, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Db = 0,
    Wal = 1,
    Journal = 2,
}

pub const FILES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    Db = 1,
    Wal = 2,
    Journal = 3,
    Telemetry = 4,
    Scratch = 5,
}

impl RegionKind {
    fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Db,
            2 => Self::Wal,
            3 => Self::Journal,
            4 => Self::Telemetry,
            5 => Self::Scratch,
            _ => return None,
        })
    }

    pub fn of_file(f: FileKind) -> Self {
        match f {
            FileKind::Db => Self::Db,
            FileKind::Wal => Self::Wal,
            FileKind::Journal => Self::Journal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub kind: RegionKind,
    pub start: u64,
    pub sectors: u64,
}

impl Region {
    pub fn bytes(&self) -> u64 {
        self.sectors * SECTOR
    }

    pub fn end(&self) -> u64 {
        self.start + self.sectors
    }
}

/// What the device reports about its blocks (virtio-blk `F_TOPOLOGY`,
/// virtio-scsi READ CAPACITY (16) and the Block Limits VPD page). All in
/// bytes. The default is a plain 512-byte device that reports nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    pub logical: u32,
    pub physical: u32,
    /// Offset of the first aligned logical block, bytes.
    pub align_offset: u32,
    pub min_io: u32,
    pub opt_io: u32,
}

impl Default for Topology {
    fn default() -> Self {
        Self {
            logical: SECTOR as u32,
            physical: SECTOR as u32,
            align_offset: 0,
            min_io: 0,
            opt_io: 0,
        }
    }
}

impl Topology {
    /// Granularity of the store's device writes: the physical block,
    /// within 512 B..4 KiB and a power of two (a larger "physical" size
    /// does not make partial writes wrong, only slower, so 4 KiB is the cap).
    pub fn write_gran(&self) -> usize {
        let p = (self.physical as usize).clamp(SECTOR as usize, BLOCK);
        if p.is_power_of_two() { p } else { BLOCK }
    }

    /// Alignment unit for the regions of a new layout, in sectors: the
    /// least common multiple of 1 MiB, the physical block and the optimal
    /// I/O size. An absurd result (over 64 MiB) falls back to 1 MiB.
    pub fn layout_align_sectors(&self) -> u32 {
        fn gcd(a: u64, b: u64) -> u64 {
            if b == 0 { a } else { gcd(b, a % b) }
        }
        let mut a = MIB_SECTORS * SECTOR;
        for x in [u64::from(self.physical), u64::from(self.opt_io)] {
            if x > 0 {
                a = a / gcd(a, x) * x;
                if a > u64::from(MAX_ALIGN_SECTORS) * SECTOR {
                    return MIB_SECTORS as u32;
                }
            }
        }
        (a / SECTOR) as u32
    }
}

/// Choices made when a disk is formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Telemetry partitions (source core `c` writes partition `c % n`).
    pub partitions: u32,
    pub align_sectors: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            partitions: 8,
            align_sectors: MIB_SECTORS as u32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub uuid: [u8; 16],
    /// Formatted size in sectors: at most the device, a multiple of 8.
    pub total_sectors: u64,
    /// In table order. Several entries of kind `Db` or `Telemetry` are the
    /// extents of one logical region, concatenated in this order.
    pub regions: Vec<Region>,
    /// Telemetry partitions.
    pub partitions: u32,
    /// Alignment unit of the regions, sectors.
    pub align_sectors: u32,
    /// Bumped by every superblock write; the higher valid slot wins.
    pub generation: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    TooSmall(u64),
    /// Non-zero data without our magic: never formatted over.
    UnknownData,
    BadChecksum,
    UnsupportedVersion(u32),
    /// A valid superblock of an older layout version. The kernel refuses it
    /// before writing anything; `urmqtt-disk migrate` converts it.
    OldVersion(u32),
    /// Regions overlap, are unaligned or lie beyond the disk.
    Inconsistent,
    /// Both size-table slots are invalid on a formatted disk.
    SizeTableLost,
    /// The region table has no room for another extent.
    TooManyRegions,
}

const fn align_down(x: u64, a: u64) -> u64 {
    x - x % a
}

const fn align_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

impl Layout {
    /// Plans the regions of a fresh disk of `device_sectors` (rounded down
    /// to a multiple of 8): database, WAL, journal, telemetry, each starting
    /// on an alignment boundary, then the scratch sectors at the end.
    pub fn plan(device_sectors: u64, uuid: [u8; 16], p: Params) -> Result<Self, LayoutError> {
        let total = device_sectors - device_sectors % BLOCK_SECTORS;
        if total < MIN_SECTORS {
            return Err(LayoutError::TooSmall(device_sectors));
        }
        check_params(p.partitions, p.align_sectors)?;
        let a = u64::from(p.align_sectors);
        let data_end = align_down(total - SCRATCH_SECTORS, a);
        if data_end <= a {
            return Err(LayoutError::TooSmall(device_sectors));
        }
        let usable = data_end - a;
        let journal = align_up(MIB_SECTORS, a);
        let wal = align_down((usable / 8).clamp(2 * MIB_SECTORS, 64 * MIB_SECTORS), a).max(a);
        let db = align_down(usable / 2, a);
        let telemetry = usable
            .checked_sub(journal + wal + db)
            .filter(|&t| t >= a)
            .ok_or(LayoutError::TooSmall(device_sectors))?;
        let mut at = a;
        let mut regions = Vec::new();
        for (kind, sectors) in [
            (RegionKind::Db, db),
            (RegionKind::Wal, wal),
            (RegionKind::Journal, journal),
            (RegionKind::Telemetry, telemetry),
        ] {
            regions.push(Region {
                kind,
                start: at,
                sectors,
            });
            at += sectors;
        }
        regions.push(Region {
            kind: RegionKind::Scratch,
            start: total - SCRATCH_SECTORS,
            sectors: SCRATCH_SECTORS,
        });
        let l = Self {
            uuid,
            total_sectors: total,
            regions,
            partitions: p.partitions,
            align_sectors: p.align_sectors,
            generation: 1,
            flags: 0,
        };
        l.validate()?;
        Ok(l)
    }

    /// The first extent of `kind`.
    pub fn region(&self, kind: RegionKind) -> Option<Region> {
        self.regions.iter().copied().find(|r| r.kind == kind)
    }

    /// Extents of `kind`, in logical order.
    pub fn extents(&self, kind: RegionKind) -> impl Iterator<Item = Region> + '_ {
        self.regions.iter().copied().filter(move |r| r.kind == kind)
    }

    /// Bytes of all extents of `kind`.
    pub fn bytes(&self, kind: RegionKind) -> u64 {
        self.extents(kind).map(|r| r.bytes()).sum()
    }

    pub fn is_v1_view(&self) -> bool {
        self.flags & FLAG_V1_VIEW != 0
    }

    pub fn legacy_telemetry(&self) -> bool {
        self.flags & FLAG_LEGACY_TELEMETRY != 0
    }

    pub fn validate(&self) -> Result<(), LayoutError> {
        let v1 = self.is_v1_view();
        let a = u64::from(self.align_sectors);
        let header_end = if v1 { HEADER_SECTORS } else { a };
        if !self.total_sectors.is_multiple_of(BLOCK_SECTORS) || self.regions.len() > MAX_REGIONS {
            return Err(LayoutError::Inconsistent);
        }
        if !v1 && check_params(self.partitions, self.align_sectors).is_err() {
            return Err(LayoutError::Inconsistent);
        }
        let mut sorted: Vec<Region> = self.regions.clone();
        sorted.sort_by_key(|r| r.start);
        let mut end = header_end;
        for r in &sorted {
            let legacy_ring = self.legacy_telemetry()
                && r.kind == RegionKind::Telemetry
                && self.extents(RegionKind::Telemetry).next() == Some(*r);
            let aligned = v1 || legacy_ring || r.kind == RegionKind::Scratch || r.start % a == 0;
            if r.start < end
                || r.sectors == 0
                || r.start % BLOCK_SECTORS != 0
                || r.sectors % BLOCK_SECTORS != 0
                || !aligned
            {
                return Err(LayoutError::Inconsistent);
            }
            end = r
                .start
                .checked_add(r.sectors)
                .ok_or(LayoutError::Inconsistent)?;
        }
        if end > self.total_sectors {
            return Err(LayoutError::Inconsistent);
        }
        for k in [RegionKind::Db, RegionKind::Wal, RegionKind::Journal] {
            if self.region(k).is_none() {
                return Err(LayoutError::Inconsistent);
            }
        }
        // The files with one flat range each, and one scratch area.
        for k in [RegionKind::Wal, RegionKind::Journal, RegionKind::Scratch] {
            if self.extents(k).count() > 1 {
                return Err(LayoutError::Inconsistent);
            }
        }
        Ok(())
    }

    /// Adds the space a larger device offers (STORAGE-PLAN S3): the new
    /// space, from the first alignment boundary after the last data region
    /// to the new end minus the scratch sectors, is split by `ratio_db_pct`
    /// between the database and the telemetry ring, each as an extent after
    /// the existing ones, so no byte that exists moves. WAL and journal keep
    /// their size. `tel_unit` is the smallest telemetry extent worth adding
    /// (partitions times the segment size): a smaller share goes to the
    /// database. The scratch area moves to the new end, the generation is
    /// bumped. `Ok(None)`: the device is not larger by a whole alignment
    /// unit. Never shrinks.
    pub fn grown(
        &self,
        device_sectors: u64,
        ratio_db_pct: u32,
        tel_unit: u64,
    ) -> Result<Option<Self>, LayoutError> {
        let total = device_sectors - device_sectors % BLOCK_SECTORS;
        let a = u64::from(self.align_sectors);
        let old_end = self
            .regions
            .iter()
            .filter(|r| r.kind != RegionKind::Scratch)
            .map(Region::end)
            .max()
            .unwrap_or(a);
        let from = align_up(old_end, a);
        let to = align_down(total.saturating_sub(SCRATCH_SECTORS), a);
        if total <= self.total_sectors || to < from + a {
            return Ok(None);
        }
        let new_len = to - from;
        let mut db = align_down(new_len * u64::from(ratio_db_pct.min(100)) / 100, a);
        let mut tel = new_len - db;
        if tel * SECTOR < tel_unit.max(1) {
            db += tel;
            tel = 0;
        }
        let mut regions: Vec<Region> = self
            .regions
            .iter()
            .copied()
            .filter(|r| r.kind != RegionKind::Scratch)
            .collect();
        // The region that already ends the disk gets its share first, so a
        // database extent merges with the previous one when they touch.
        let last_is_db = self
            .regions
            .iter()
            .filter(|r| r.kind != RegionKind::Scratch)
            .max_by_key(|r| r.end())
            .is_some_and(|r| r.kind == RegionKind::Db);
        let mut at = from;
        let order = if last_is_db {
            [RegionKind::Db, RegionKind::Telemetry]
        } else {
            [RegionKind::Telemetry, RegionKind::Db]
        };
        for kind in order {
            let sectors = if kind == RegionKind::Db { db } else { tel };
            if sectors == 0 {
                continue;
            }
            // A telemetry extent is a band of the ring of its own and is
            // never merged; a database extent is a flat range and is.
            let merge = if kind == RegionKind::Db {
                regions
                    .iter_mut()
                    .rev()
                    .find(|r| r.kind == RegionKind::Db)
                    .filter(|r| r.end() == at)
            } else {
                None
            };
            if let Some(prev) = merge {
                prev.sectors += sectors;
            } else {
                regions.push(Region {
                    kind,
                    start: at,
                    sectors,
                });
            }
            at += sectors;
        }
        regions.push(Region {
            kind: RegionKind::Scratch,
            start: total - SCRATCH_SECTORS,
            sectors: SCRATCH_SECTORS,
        });
        if regions.len() > MAX_REGIONS {
            return Err(LayoutError::TooManyRegions);
        }
        let l = Self {
            uuid: self.uuid,
            total_sectors: total,
            regions,
            partitions: self.partitions,
            align_sectors: self.align_sectors,
            generation: self.generation + 1,
            flags: self.flags & STORED_FLAGS,
        };
        l.validate()?;
        Ok(Some(l))
    }

    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &MAGIC);
        put(&mut b, 8, &VERSION.to_le_bytes());
        put(&mut b, 12, &(self.regions.len() as u32).to_le_bytes());
        put(&mut b, 16, &self.uuid);
        put(&mut b, 32, &self.total_sectors.to_le_bytes());
        put(&mut b, 40, &self.generation.to_le_bytes());
        put(&mut b, 48, &self.partitions.to_le_bytes());
        put(&mut b, 52, &self.align_sectors.to_le_bytes());
        put(&mut b, 56, &(self.flags & STORED_FLAGS).to_le_bytes());
        for (i, r) in self.regions.iter().take(MAX_REGIONS).enumerate() {
            let at = REGIONS_AT + i * REGION_BYTES;
            put(&mut b, at, &(r.kind as u32).to_le_bytes());
            put(&mut b, at + 8, &r.start.to_le_bytes());
            put(&mut b, at + 16, &r.sectors.to_le_bytes());
        }
        let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
        put(&mut b, BLOCK - 4, &crc.to_le_bytes());
        b
    }

    /// Decodes one superblock slot. `Ok(None)` means a blank (all-zero)
    /// slot. A valid superblock of layout v1 is [`LayoutError::OldVersion`].
    pub fn decode(b: &[u8; BLOCK], total_sectors: u64) -> Result<Option<Self>, LayoutError> {
        if b.iter().all(|&x| x == 0) {
            return Ok(None);
        }
        if b.get(..8) != Some(&MAGIC[..]) {
            return Err(LayoutError::UnknownData);
        }
        if crc32c(b.get(..BLOCK - 4).unwrap_or(&[])) != u32_at(b, BLOCK - 4) {
            return Err(LayoutError::BadChecksum);
        }
        let version = u32_at(b, 8);
        if version == v1::VERSION {
            return Err(LayoutError::OldVersion(version));
        }
        if version != VERSION {
            return Err(LayoutError::UnsupportedVersion(version));
        }
        let n = u32_at(b, 12) as usize;
        if n > MAX_REGIONS || u32_at(b, 60) != 0 || u32_at(b, 56) & !STORED_FLAGS != 0 {
            return Err(LayoutError::Inconsistent);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(b.get(16..32).unwrap_or(&[0; 16]));
        let formatted = u64_at(b, 32);
        if formatted > total_sectors {
            return Err(LayoutError::Inconsistent);
        }
        let mut regions = Vec::with_capacity(n);
        for i in 0..n {
            let at = REGIONS_AT + i * REGION_BYTES;
            let kind = RegionKind::from_u32(u32_at(b, at)).ok_or(LayoutError::Inconsistent)?;
            regions.push(Region {
                kind,
                start: u64_at(b, at + 8),
                sectors: u64_at(b, at + 16),
            });
        }
        let l = Self {
            uuid,
            total_sectors: formatted,
            regions,
            generation: u64_at(b, 40),
            partitions: u32_at(b, 48),
            align_sectors: u32_at(b, 52),
            flags: u32_at(b, 56),
        };
        l.validate()?;
        Ok(Some(l))
    }

    /// Chooses the current superblock of the two slots: the valid one with
    /// the higher generation (slot A on a tie). Returns the layout and its
    /// slot. `Ok(None)`: both slots blank. If neither is valid the error
    /// says why, an old layout version first.
    pub fn select(
        a: &[u8; BLOCK],
        b: &[u8; BLOCK],
        total_sectors: u64,
    ) -> Result<Option<(Self, usize)>, LayoutError> {
        let ra = Self::decode(a, total_sectors);
        let rb = Self::decode(b, total_sectors);
        match (ra, rb) {
            (Ok(None), Ok(None)) => Ok(None),
            (Ok(Some(x)), Ok(Some(y))) => Ok(Some(if y.generation > x.generation {
                (y, 1)
            } else {
                (x, 0)
            })),
            (Ok(Some(x)), _) => Ok(Some((x, 0))),
            (_, Ok(Some(y))) => Ok(Some((y, 1))),
            (Err(e), Ok(None)) | (Ok(None), Err(e)) => Err(e),
            (Err(x), Err(y)) => {
                let rank = |e: &LayoutError| match e {
                    LayoutError::OldVersion(_) => 0,
                    LayoutError::UnknownData => 2,
                    _ => 1,
                };
                Err(if rank(&y) < rank(&x) { y } else { x })
            }
        }
    }
}

fn check_params(partitions: u32, align_sectors: u32) -> Result<(), LayoutError> {
    let a = u64::from(align_sectors);
    if partitions == 0
        || partitions > MAX_PARTITIONS
        || a < MIB_SECTORS
        || a % MIB_SECTORS != 0
        || align_sectors > MAX_ALIGN_SECTORS
    {
        return Err(LayoutError::Inconsistent);
    }
    Ok(())
}

/// Layout version 1 (S0/S1): kept as a read-only view for `urmqtt-disk
/// migrate` and as a writer for test fixtures. The kernel does not call
/// anything in here; it only recognises the version and refuses.
pub mod v1 {
    use super::*;

    pub const VERSION: u32 = 1;
    const MAX_REGIONS: usize = 16;
    const REGIONS_AT: usize = 40;

    /// Plans a v1 disk (regions from LBA 64, 4 KiB aligned). Fixtures only.
    pub fn plan(total_sectors: u64, uuid: [u8; 16]) -> Result<Layout, LayoutError> {
        if total_sectors < MIN_SECTORS {
            return Err(LayoutError::TooSmall(total_sectors));
        }
        let scratch = total_sectors - SCRATCH_SECTORS;
        let usable = align_down(scratch - HEADER_SECTORS, BLOCK_SECTORS);
        let journal = MIB_SECTORS;
        let wal = align_down(
            (usable / 8).clamp(2 * MIB_SECTORS, 64 * MIB_SECTORS),
            BLOCK_SECTORS,
        );
        let db = align_down(usable / 2, BLOCK_SECTORS);
        let telemetry = usable - journal - wal - db;
        let mut at = HEADER_SECTORS;
        let mut regions = Vec::new();
        for (kind, sectors) in [
            (RegionKind::Db, db),
            (RegionKind::Wal, wal),
            (RegionKind::Journal, journal),
            (RegionKind::Telemetry, telemetry),
        ] {
            regions.push(Region {
                kind,
                start: at,
                sectors,
            });
            at += sectors;
        }
        regions.push(Region {
            kind: RegionKind::Scratch,
            start: scratch,
            sectors: SCRATCH_SECTORS,
        });
        let l = view(uuid, total_sectors, regions);
        l.validate()?;
        Ok(l)
    }

    fn view(uuid: [u8; 16], total_sectors: u64, regions: Vec<Region>) -> Layout {
        Layout {
            uuid,
            total_sectors,
            regions,
            partitions: 8,
            align_sectors: BLOCK_SECTORS as u32,
            generation: 0,
            flags: FLAG_V1_VIEW | FLAG_LEGACY_TELEMETRY,
        }
    }

    /// The v1 superblock bytes of a v1 view.
    pub fn encode(l: &Layout) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &MAGIC);
        put(&mut b, 8, &VERSION.to_le_bytes());
        put(&mut b, 12, &(l.regions.len() as u32).to_le_bytes());
        put(&mut b, 16, &l.uuid);
        put(&mut b, 32, &l.total_sectors.to_le_bytes());
        for (i, r) in l.regions.iter().take(MAX_REGIONS).enumerate() {
            let at = REGIONS_AT + i * REGION_BYTES;
            put(&mut b, at, &(r.kind as u32).to_le_bytes());
            put(&mut b, at + 8, &r.start.to_le_bytes());
            put(&mut b, at + 16, &r.sectors.to_le_bytes());
        }
        let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
        put(&mut b, BLOCK - 4, &crc.to_le_bytes());
        b
    }

    /// Decodes a v1 superblock into its view. `Ok(None)`: blank.
    pub fn decode(b: &[u8; BLOCK], total_sectors: u64) -> Result<Option<Layout>, LayoutError> {
        if b.iter().all(|&x| x == 0) {
            return Ok(None);
        }
        if b.get(..8) != Some(&MAGIC[..]) {
            return Err(LayoutError::UnknownData);
        }
        if crc32c(b.get(..BLOCK - 4).unwrap_or(&[])) != u32_at(b, BLOCK - 4) {
            return Err(LayoutError::BadChecksum);
        }
        let version = u32_at(b, 8);
        if version != VERSION {
            return Err(LayoutError::UnsupportedVersion(version));
        }
        let n = u32_at(b, 12) as usize;
        if n > MAX_REGIONS {
            return Err(LayoutError::Inconsistent);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(b.get(16..32).unwrap_or(&[0; 16]));
        let formatted = u64_at(b, 32);
        if formatted > total_sectors {
            return Err(LayoutError::Inconsistent);
        }
        let mut regions = Vec::with_capacity(n);
        for i in 0..n {
            let at = REGIONS_AT + i * REGION_BYTES;
            let kind = RegionKind::from_u32(u32_at(b, at)).ok_or(LayoutError::Inconsistent)?;
            regions.push(Region {
                kind,
                start: u64_at(b, at + 8),
                sectors: u64_at(b, at + 16),
            });
        }
        let l = view(uuid, formatted, regions);
        l.validate()?;
        Ok(Some(l))
    }
}

/// Logical sizes of the VFS files, double-buffered: a write goes to the
/// slot not holding the newest valid copy, so a torn write loses at most
/// the update in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SizeTable {
    pub seq: u64,
    pub sizes: [u64; FILES],
}

impl SizeTable {
    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &SIZE_MAGIC);
        put(&mut b, 8, &self.seq.to_le_bytes());
        put(&mut b, 16, &(FILES as u32).to_le_bytes());
        for (i, s) in self.sizes.iter().enumerate() {
            put(&mut b, 24 + i * 8, &s.to_le_bytes());
        }
        let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
        put(&mut b, BLOCK - 4, &crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; BLOCK]) -> Option<Self> {
        if b.get(..8) != Some(&SIZE_MAGIC[..])
            || crc32c(b.get(..BLOCK - 4).unwrap_or(&[])) != u32_at(b, BLOCK - 4)
            || u32_at(b, 16) as usize != FILES
        {
            return None;
        }
        let mut sizes = [0u64; FILES];
        for (i, s) in sizes.iter_mut().enumerate() {
            *s = u64_at(b, 24 + i * 8);
        }
        Some(Self {
            seq: u64_at(b, 8),
            sizes,
        })
    }

    /// The newer of two slots; `None` if neither is valid.
    pub fn newest(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(x), Some(y)) => Some(if y.seq > x.seq { y } else { x }),
            (x, y) => x.or(y),
        }
    }

    /// Slot index the next write (with `seq + 1`) goes to.
    pub fn next_slot(&self) -> usize {
        ((self.seq + 1) % 2) as usize
    }
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut x = [0u8; 4];
    x.copy_from_slice(b.get(at..at + 4).unwrap_or(&[0; 4]));
    u32::from_le_bytes(x)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(b.get(at..at + 8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK: u64 = 64 * 1024 * 1024 / SECTOR;

    #[test]
    fn plan_round_trips_and_is_aligned() {
        let l = Layout::plan(DISK, [7; 16], Params::default()).unwrap();
        let db = l.region(RegionKind::Db).unwrap();
        let wal = l.region(RegionKind::Wal).unwrap();
        assert_eq!(db.start, MIB_SECTORS);
        assert!(db.bytes() >= 30 << 20);
        assert!(wal.bytes() >= 2 << 20);
        for r in &l.regions {
            if r.kind != RegionKind::Scratch {
                assert_eq!(r.start % MIB_SECTORS, 0, "{r:?}");
                assert_eq!(r.sectors % MIB_SECTORS, 0, "{r:?}");
            }
        }
        assert_eq!(
            l.region(RegionKind::Scratch).unwrap().start,
            DISK - SCRATCH_SECTORS
        );
        let enc = l.encode();
        assert_eq!(Layout::decode(&enc, DISK).unwrap(), Some(l));
    }

    #[test]
    fn plan_honours_the_optimal_io_size() {
        let t = Topology {
            logical: 512,
            physical: 4096,
            align_offset: 0,
            min_io: 4096,
            opt_io: 3 << 20,
        };
        // lcm(1 MiB, 4 KiB, 3 MiB) = 3 MiB.
        assert_eq!(u64::from(t.layout_align_sectors()), 3 * MIB_SECTORS);
        let p = Params {
            partitions: 8,
            align_sectors: t.layout_align_sectors(),
        };
        let l = Layout::plan(1024 * MIB_SECTORS, [1; 16], p).unwrap();
        for r in &l.regions {
            if r.kind != RegionKind::Scratch {
                assert_eq!(r.start % (3 * MIB_SECTORS), 0, "{r:?}");
            }
        }
        // An absurd value falls back to 1 MiB.
        let t = Topology {
            opt_io: 1 << 30,
            ..t
        };
        assert_eq!(u64::from(t.layout_align_sectors()), MIB_SECTORS);
        assert_eq!(Topology::default().write_gran(), 512);
        assert_eq!(t.write_gran(), 4096);
    }

    #[test]
    fn decode_rejects_damage_foreign_data_and_old_versions() {
        let l = Layout::plan(DISK, [1; 16], Params::default()).unwrap();
        assert_eq!(Layout::decode(&[0; BLOCK], DISK), Ok(None));
        let mut b = l.encode();
        b[100] ^= 1;
        assert_eq!(Layout::decode(&b, DISK), Err(LayoutError::BadChecksum));
        let mut foreign = [0u8; BLOCK];
        foreign[510] = 0x55;
        assert_eq!(
            Layout::decode(&foreign, DISK),
            Err(LayoutError::UnknownData)
        );
        // A superblock from a larger disk does not fit a smaller one.
        assert_eq!(
            Layout::decode(&l.encode(), DISK / 2),
            Err(LayoutError::Inconsistent)
        );
        assert_eq!(
            Layout::plan(MIN_SECTORS - 1, [0; 16], Params::default()),
            Err(LayoutError::TooSmall(MIN_SECTORS - 1))
        );
        // Not a multiple of 4 KiB: the formatted size is rounded down.
        let r = Layout::plan(MIN_SECTORS + 5, [0; 16], Params::default()).unwrap();
        assert_eq!(r.total_sectors, MIN_SECTORS);
        // A v1 superblock is recognised and refused as such.
        let v1l = v1::plan(MIN_SECTORS, [2; 16]).unwrap();
        assert_eq!(
            Layout::decode(&v1::encode(&v1l), MIN_SECTORS),
            Err(LayoutError::OldVersion(1))
        );
        assert_eq!(
            v1::decode(&v1::encode(&v1l), MIN_SECTORS).unwrap(),
            Some(v1l)
        );
    }

    #[test]
    fn select_picks_the_higher_valid_generation() {
        let a = Layout::plan(DISK, [1; 16], Params::default()).unwrap();
        let mut b = a.clone();
        b.generation = 2;
        let (ea, eb) = (a.encode(), b.encode());
        let zero = [0u8; BLOCK];
        assert_eq!(Layout::select(&zero, &zero, DISK), Ok(None));
        assert_eq!(Layout::select(&ea, &zero, DISK).unwrap().unwrap().1, 0);
        assert_eq!(Layout::select(&zero, &eb, DISK).unwrap().unwrap().1, 1);
        assert_eq!(Layout::select(&ea, &eb, DISK).unwrap().unwrap().0, b);
        assert_eq!(Layout::select(&eb, &ea, DISK).unwrap().unwrap().1, 0);
        // A torn newer slot falls back to the older one.
        let mut torn = eb;
        torn[200] ^= 0xff;
        assert_eq!(Layout::select(&ea, &torn, DISK).unwrap().unwrap().0, a);
        assert_eq!(Layout::select(&torn, &ea, DISK).unwrap().unwrap().1, 1);
        // Nothing valid: the old version is named first.
        let old = v1::encode(&v1::plan(DISK, [3; 16]).unwrap());
        assert_eq!(
            Layout::select(&old, &zero, DISK),
            Err(LayoutError::OldVersion(1))
        );
        assert_eq!(
            Layout::select(&torn, &old, DISK),
            Err(LayoutError::OldVersion(1))
        );
        assert_eq!(
            Layout::select(&torn, &zero, DISK),
            Err(LayoutError::BadChecksum)
        );
        // v2 beats a stale v1 in the other slot (a finished migration).
        assert_eq!(Layout::select(&old, &ea, DISK).unwrap().unwrap().1, 1);
    }

    #[test]
    fn grown_splits_new_space_and_moves_nothing() {
        let l = Layout::plan(1024 * MIB_SECTORS, [1; 16], Params::default()).unwrap();
        let g = l.grown(4096 * MIB_SECTORS, 50, 64 << 20).unwrap().unwrap();
        assert_eq!(g.generation, l.generation + 1);
        assert_eq!(g.total_sectors, 4096 * MIB_SECTORS);
        // Every old non-scratch region is unchanged.
        for r in l.regions.iter().filter(|r| r.kind != RegionKind::Scratch) {
            assert!(g.regions.contains(r), "{r:?}");
        }
        let new_db = g.bytes(RegionKind::Db) - l.bytes(RegionKind::Db);
        let new_tel = g.bytes(RegionKind::Telemetry) - l.bytes(RegionKind::Telemetry);
        assert!(new_db > 1400 << 20 && new_tel > 1400 << 20);
        assert_eq!(g.bytes(RegionKind::Wal), l.bytes(RegionKind::Wal));
        assert_eq!(g.bytes(RegionKind::Journal), l.bytes(RegionKind::Journal));
        assert_eq!(
            g.region(RegionKind::Scratch).unwrap().start,
            4096 * MIB_SECTORS - SCRATCH_SECTORS
        );
        g.validate().unwrap();
        // Growing again merges the database extent with the previous one
        // when they touch and adds exactly one telemetry band.
        let g2 = g
            .grown(65_536 * MIB_SECTORS, 50, 64 << 20)
            .unwrap()
            .unwrap();
        assert_eq!(g2.extents(RegionKind::Telemetry).count(), 3);
        assert!(g2.extents(RegionKind::Db).count() <= 2);
        // Never shrinks, and a device that did not grow changes nothing.
        assert_eq!(g2.grown(1024 * MIB_SECTORS, 50, 0).unwrap(), None);
        assert_eq!(g2.grown(g2.total_sectors, 50, 0).unwrap(), None);
        assert_eq!(g2.grown(g2.total_sectors + 7, 50, 0).unwrap(), None);
        // Ratio 100 gives everything to the database, 0 to the telemetry.
        let all_db = l.grown(4096 * MIB_SECTORS, 100, 0).unwrap().unwrap();
        assert_eq!(
            all_db.bytes(RegionKind::Telemetry),
            l.bytes(RegionKind::Telemetry)
        );
        let all_tel = l.grown(4096 * MIB_SECTORS, 0, 0).unwrap().unwrap();
        assert_eq!(all_tel.bytes(RegionKind::Db), l.bytes(RegionKind::Db));
        // A telemetry share smaller than one segment row goes to the database.
        let small = l
            .grown(1024 * MIB_SECTORS + 8 * MIB_SECTORS, 50, 64 << 20)
            .unwrap()
            .unwrap();
        assert_eq!(
            small.bytes(RegionKind::Telemetry),
            l.bytes(RegionKind::Telemetry)
        );
    }

    #[test]
    fn size_table_newest_and_slots() {
        let a = SizeTable {
            seq: 4,
            sizes: [1, 2, 3],
        };
        let b = SizeTable {
            seq: 5,
            sizes: [9, 9, 9],
        };
        assert_eq!(SizeTable::decode(&a.encode()), Some(a));
        assert_eq!(SizeTable::newest(Some(a), Some(b)), Some(b));
        assert_eq!(SizeTable::newest(None, Some(a)), Some(a));
        let mut torn = b.encode();
        torn[30] ^= 0xff;
        assert_eq!(SizeTable::decode(&torn), None);
        assert_ne!(a.next_slot(), b.next_slot());
    }
}
