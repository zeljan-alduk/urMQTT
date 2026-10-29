//! Data disk layout (PROMPT §8, ADR-030): a superblock with a region table,
//! a double-buffered file-size table, then the regions themselves. No
//! filesystem.
//!
//! ```text
//! LBA 0      superblock (4 KiB): magic, version, uuid, regions, CRC-32C
//! LBA 8, 16  file-size table slots A and B (4 KiB each, highest valid seq wins)
//! LBA 64     regions, 4 KiB aligned: SQLite main db, WAL, rollback journal,
//!            telemetry log (M12)
//! last 8     scratch for the boot block-device self-test
//! ```

use alloc::vec::Vec;

use crate::crc::crc32c;

pub const SECTOR: u64 = 512;
pub const BLOCK: usize = 4096;
pub const BLOCK_SECTORS: u64 = BLOCK as u64 / SECTOR;
pub const MAGIC: [u8; 8] = *b"URMQTTDK";
pub const VERSION: u32 = 1;
pub const SIZE_MAGIC: [u8; 8] = *b"URMQSZT1";
/// Superblock and size-table slots live in the first 32 KiB.
pub const HEADER_SECTORS: u64 = 64;
pub const SIZE_SLOT_LBA: [u64; 2] = [8, 16];
/// Scratch area at the end of the disk (the boot self-test writes there).
pub const SCRATCH_SECTORS: u64 = 8;
/// Smallest supported data disk: 16 MiB.
pub const MIN_SECTORS: u64 = 32 * 1024;
const MAX_REGIONS: usize = 16;
const REGION_BYTES: usize = 24;
const REGIONS_AT: usize = 40;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub uuid: [u8; 16],
    pub total_sectors: u64,
    pub regions: Vec<Region>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    TooSmall(u64),
    /// Non-zero data without our magic: never formatted over.
    UnknownData,
    BadChecksum,
    UnsupportedVersion(u32),
    /// Regions overlap, are unaligned or lie beyond the disk.
    Inconsistent,
    /// Both size-table slots are invalid on a formatted disk.
    SizeTableLost,
}

const fn align_down(x: u64) -> u64 {
    x - x % BLOCK_SECTORS
}

impl Layout {
    /// Plans the regions of a fresh disk of `total_sectors`.
    pub fn plan(total_sectors: u64, uuid: [u8; 16]) -> Result<Self, LayoutError> {
        if total_sectors < MIN_SECTORS {
            return Err(LayoutError::TooSmall(total_sectors));
        }
        let scratch = total_sectors - SCRATCH_SECTORS;
        let usable = align_down(scratch - HEADER_SECTORS);
        let mib = 1024 * 1024 / SECTOR;
        let journal = mib;
        let wal = align_down((usable / 8).clamp(2 * mib, 64 * mib));
        let db = align_down(usable / 2);
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
        let l = Self {
            uuid,
            total_sectors,
            regions,
        };
        l.validate()?;
        Ok(l)
    }

    pub fn region(&self, kind: RegionKind) -> Option<Region> {
        self.regions.iter().copied().find(|r| r.kind == kind)
    }

    fn validate(&self) -> Result<(), LayoutError> {
        let mut sorted: Vec<Region> = self.regions.clone();
        sorted.sort_by_key(|r| r.start);
        let mut end = HEADER_SECTORS;
        for r in &sorted {
            if r.start < end || r.sectors == 0 || r.start % BLOCK_SECTORS != 0 {
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
        Ok(())
    }

    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &MAGIC);
        put(&mut b, 8, &VERSION.to_le_bytes());
        put(&mut b, 12, &(self.regions.len() as u32).to_le_bytes());
        put(&mut b, 16, &self.uuid);
        put(&mut b, 32, &self.total_sectors.to_le_bytes());
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

    /// Decodes a superblock. `Ok(None)` means a blank (all-zero) disk.
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
        let l = Self {
            uuid,
            total_sectors: formatted,
            regions,
        };
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
    fn plan_round_trips_and_is_consistent() {
        let l = Layout::plan(DISK, [7; 16]).unwrap();
        let db = l.region(RegionKind::Db).unwrap();
        let wal = l.region(RegionKind::Wal).unwrap();
        assert_eq!(db.start, HEADER_SECTORS);
        assert!(db.bytes() >= 30 << 20);
        assert!(wal.bytes() >= 2 << 20);
        assert_eq!(
            l.region(RegionKind::Scratch).unwrap().start,
            DISK - SCRATCH_SECTORS
        );
        let enc = l.encode();
        assert_eq!(Layout::decode(&enc, DISK).unwrap(), Some(l));
    }

    #[test]
    fn decode_rejects_damage_and_foreign_data() {
        let l = Layout::plan(DISK, [1; 16]).unwrap();
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
            Layout::plan(MIN_SECTORS - 1, [0; 16]),
            Err(LayoutError::TooSmall(MIN_SECTORS - 1))
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
