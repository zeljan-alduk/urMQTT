//! Byte-addressed access to the regions of a sector device, with logical
//! file sizes persisted in the double-buffered size table (ADR-030).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use urmqtt_arch_aarch64::sync::SpinLock;

use crate::layout::{
    BLOCK, FileKind, Layout, LayoutError, Region, RegionKind, SECTOR, SIZE_SLOT_LBA, SizeTable,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    Device,
    OutOfRange,
    NoFlush,
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
}

pub struct Disk {
    dev: Box<dyn BlockDevice>,
    layout: Layout,
    sizes: SizeTable,
    /// Sizes changed since the table was last persisted.
    dirty: bool,
    pub stats: DiskStats,
}

/// What [`Disk::open`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    Existing,
    Formatted,
}

impl Disk {
    /// Opens the data disk, formatting it if (and only if) it is blank.
    pub fn open(
        mut dev: Box<dyn BlockDevice>,
        uuid: impl FnOnce() -> [u8; 16],
    ) -> Result<(Self, Opened), DiskError> {
        let total = dev.sectors();
        let mut sb = [0u8; BLOCK];
        dev.read(0, &mut sb)?;
        match Layout::decode(&sb, total)? {
            Some(layout) => {
                let mut a = [0u8; BLOCK];
                let mut b = [0u8; BLOCK];
                dev.read(SIZE_SLOT_LBA[0], &mut a)?;
                dev.read(SIZE_SLOT_LBA[1], &mut b)?;
                let sizes = SizeTable::newest(SizeTable::decode(&a), SizeTable::decode(&b))
                    .ok_or(LayoutError::SizeTableLost)?;
                let disk = Self {
                    dev,
                    layout,
                    sizes,
                    dirty: false,
                    stats: DiskStats::default(),
                };
                Ok((disk, Opened::Existing))
            }
            None => {
                let layout = Layout::plan(total, uuid())?;
                // Size table first, superblock last: a crash in between
                // leaves a blank-looking disk that is formatted again.
                let sizes = SizeTable::default();
                dev.write(SIZE_SLOT_LBA[0], &sizes.encode())?;
                dev.write(SIZE_SLOT_LBA[1], &[0u8; BLOCK])?;
                dev.flush()?;
                dev.write(0, &layout.encode())?;
                dev.flush()?;
                let disk = Self {
                    dev,
                    layout,
                    sizes,
                    dirty: false,
                    stats: DiskStats::default(),
                };
                Ok((disk, Opened::Formatted))
            }
        }
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn region(&self, kind: RegionKind) -> Option<Region> {
        self.layout.region(kind)
    }

    pub fn file_size(&self, f: FileKind) -> u64 {
        self.sizes.sizes.get(f as usize).copied().unwrap_or(0)
    }

    pub fn set_file_size(&mut self, f: FileKind, size: u64) {
        if let Some(s) = self.sizes.sizes.get_mut(f as usize)
            && *s != size
        {
            *s = size;
            self.dirty = true;
        }
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
            self.dev.write(lba, &next.encode())?;
            self.dev.flush()?;
            self.stats.flushes += 1;
            self.stats.size_table_writes += 1;
            self.sizes = next;
            self.dirty = false;
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes at byte `offset` of region `kind`.
    pub fn read_at(
        &mut self,
        kind: RegionKind,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), DiskError> {
        let r = self.region(kind).ok_or(LayoutError::Inconsistent)?;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(DiskError::Full)?;
        if end > r.bytes() {
            return Err(DiskError::Full);
        }
        let chunk = self.chunk_bytes();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let first = pos / SECTOR;
            let skip = (pos % SECTOR) as usize;
            let want = (buf.len() - done).min(chunk - skip);
            let span = (skip + want).div_ceil(SECTOR as usize) * SECTOR as usize;
            let mut bounce = vec![0u8; span];
            self.dev.read(r.start + first, &mut bounce)?;
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

    /// Writes `data` at byte `offset` of region `kind` (read-modify-write
    /// for partial sectors).
    pub fn write_at(
        &mut self,
        kind: RegionKind,
        offset: u64,
        data: &[u8],
    ) -> Result<(), DiskError> {
        let r = self.region(kind).ok_or(LayoutError::Inconsistent)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(DiskError::Full)?;
        if end > r.bytes() {
            return Err(DiskError::Full);
        }
        let chunk = self.chunk_bytes();
        let sector = SECTOR as usize;
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            let first = pos / SECTOR;
            let skip = (pos % SECTOR) as usize;
            let want = (data.len() - done).min(chunk - skip);
            let span = (skip + want).div_ceil(sector) * sector;
            let mut bounce = vec![0u8; span];
            if skip != 0 {
                let head = bounce.get_mut(..sector).ok_or(DiskError::Full)?;
                self.dev.read(r.start + first, head)?;
                self.stats.reads += 1;
            }
            let tail_partial = !(skip + want).is_multiple_of(sector);
            if tail_partial && (span > sector || skip == 0) {
                let last = (span / sector - 1) as u64;
                let tail = bounce.get_mut(span - sector..).ok_or(DiskError::Full)?;
                self.dev.read(r.start + first + last, tail)?;
                self.stats.reads += 1;
            }
            let src = data.get(done..done + want).ok_or(DiskError::Full)?;
            bounce
                .get_mut(skip..skip + want)
                .ok_or(DiskError::Full)?
                .copy_from_slice(src);
            self.dev.write(r.start + first, &bounce)?;
            self.stats.writes += 1;
            self.stats.bytes_written += span as u64;
            done += want;
        }
        Ok(())
    }

    fn chunk_bytes(&self) -> usize {
        let s = SECTOR as usize;
        (self.dev.max_io() / s).max(2) * s
    }
}

/// In-memory block device for host tests, with a volatile write cache:
/// writes become durable only on `flush`, and [`MemDisk::crash`] throws
/// the cache away (or keeps a chosen subset) like a power loss.
#[derive(Clone)]
pub struct MemDisk {
    inner: Arc<SpinLock<MemInner>>,
}

struct MemInner {
    durable: Vec<u8>,
    /// Completed but unflushed writes, in order.
    cache: Vec<(u64, Vec<u8>)>,
    writes: u64,
    fail_after_writes: Option<u64>,
}

impl MemDisk {
    pub fn new(bytes: usize) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(MemInner {
                durable: vec![0u8; bytes],
                cache: Vec::new(),
                writes: 0,
                fail_after_writes: None,
            })),
        }
    }

    /// A disk whose medium holds `image` (fuzzing recovery from damaged
    /// images; the length should be a multiple of the sector size).
    pub fn from_image(image: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(SpinLock::new(MemInner {
                durable: image,
                cache: Vec::new(),
                writes: 0,
                fail_after_writes: None,
            })),
        }
    }

    /// Simulates power loss: unflushed writes whose index `keep(i)` returns
    /// false are lost, the others reach the medium (in any real order).
    pub fn crash(&self, mut keep: impl FnMut(usize) -> bool) {
        let mut g = self.inner.lock();
        let cache = core::mem::take(&mut g.cache);
        for (i, (lba, data)) in cache.into_iter().enumerate() {
            if keep(i) {
                apply(&mut g.durable, lba, &data);
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

    pub fn raw(&self, offset: usize, len: usize) -> Vec<u8> {
        let g = self.inner.lock();
        g.durable
            .get(offset..offset + len)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    pub fn device(&self) -> Box<dyn BlockDevice> {
        Box::new(self.clone())
    }
}

fn apply(durable: &mut [u8], lba: u64, data: &[u8]) {
    let at = (lba * SECTOR) as usize;
    if let Some(d) = durable.get_mut(at..at + data.len()) {
        d.copy_from_slice(data);
    }
}

impl BlockDevice for MemDisk {
    fn sectors(&self) -> u64 {
        self.inner.lock().durable.len() as u64 / SECTOR
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let g = self.inner.lock();
        let at = (lba * SECTOR) as usize;
        let src = g
            .durable
            .get(at..at + buf.len())
            .ok_or(IoError::OutOfRange)?;
        buf.copy_from_slice(src);
        // Reads see cached writes, newest last.
        for (wlba, data) in &g.cache {
            let (ws, we) = (*wlba * SECTOR, *wlba * SECTOR + data.len() as u64);
            let (rs, re) = (lba * SECTOR, lba * SECTOR + buf.len() as u64);
            let (s, e) = (ws.max(rs), we.min(re));
            if s < e {
                let dst = buf.get_mut((s - rs) as usize..(e - rs) as usize);
                let src = data.get((s - ws) as usize..(e - ws) as usize);
                if let (Some(d), Some(x)) = (dst, src) {
                    d.copy_from_slice(x);
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        let mut g = self.inner.lock();
        if (lba * SECTOR) as usize + buf.len() > g.durable.len() {
            return Err(IoError::OutOfRange);
        }
        if g.fail_after_writes.is_some_and(|n| g.writes >= n) {
            return Err(IoError::Device);
        }
        g.writes += 1;
        g.cache.push((lba, buf.to_vec()));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        let mut g = self.inner.lock();
        let cache = core::mem::take(&mut g.cache);
        for (lba, data) in cache {
            apply(&mut g.durable, lba, &data);
        }
        Ok(())
    }

    fn max_io(&self) -> usize {
        // Small, so tests exercise chunking.
        8 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
