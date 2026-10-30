//! The in-memory block device of the live mode (O3, ADR-054) and the math
//! of how much RAM it takes.
//!
//! [`RamDisk`] is an ordinary [`BlockDevice`] over RAM the kernel reserved
//! at boot, so the data layout, SQLite's VFS and the telemetry log run on it
//! unchanged. It has no write cache (a write is complete when it returns,
//! `flush` has nothing to do) and nothing survives a reboot: that is the
//! point, and the kernel says so loudly.
//!
//! The memory comes as equally sized chunks (the kernel takes them in runs
//! of 2 MiB: physical memory is rarely one contiguous stretch), each a
//! `'static` slice.

use alloc::vec::Vec;

use crate::disk::{BlockDevice, IoError};
use crate::layout::{MIN_SECTORS, SECTOR};

const MIB: u64 = 1 << 20;

pub struct RamDisk {
    chunks: Vec<&'static mut [u8]>,
    chunk_bytes: usize,
    sectors: u64,
}

impl RamDisk {
    /// A device over `chunks`, which must all have the same length, a
    /// non-zero multiple of the sector size. `None` otherwise.
    pub fn new(chunks: Vec<&'static mut [u8]>) -> Option<Self> {
        let chunk_bytes = chunks.first()?.len();
        let ss = SECTOR as usize;
        if chunk_bytes == 0
            || !chunk_bytes.is_multiple_of(ss)
            || chunks.iter().any(|c| c.len() != chunk_bytes)
        {
            return None;
        }
        let sectors = (chunks.len() as u64) * (chunk_bytes as u64 / SECTOR);
        Some(Self {
            chunks,
            chunk_bytes,
            sectors,
        })
    }

    /// Visits the byte range of the request chunk by chunk.
    fn each(
        &mut self,
        lba: u64,
        len: usize,
        mut f: impl FnMut(&mut [u8], usize) -> Option<()>,
    ) -> Result<(), IoError> {
        let end_sector = lba
            .checked_add((len as u64).div_ceil(SECTOR))
            .ok_or(IoError::OutOfRange)?;
        if !len.is_multiple_of(SECTOR as usize) || end_sector > self.sectors {
            return Err(IoError::OutOfRange);
        }
        let mut at = usize::try_from(lba * SECTOR).map_err(|_| IoError::OutOfRange)?;
        let mut done = 0usize;
        while done < len {
            let chunk = self
                .chunks
                .get_mut(at / self.chunk_bytes)
                .ok_or(IoError::OutOfRange)?;
            let off = at % self.chunk_bytes;
            let n = (len - done).min(self.chunk_bytes - off);
            let part = chunk.get_mut(off..off + n).ok_or(IoError::OutOfRange)?;
            f(part, done).ok_or(IoError::Device)?;
            at += n;
            done += n;
        }
        Ok(())
    }
}

impl BlockDevice for RamDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let len = buf.len();
        self.each(lba, len, |part, done| {
            buf.get_mut(done..done + part.len())?.copy_from_slice(part);
            Some(())
        })
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        self.each(lba, buf.len(), |part, done| {
            part.copy_from_slice(buf.get(done..done + part.len())?);
            Some(())
        })
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }

    fn max_io(&self) -> usize {
        // No queue to respect: as large as the layout code asks.
        1024 * 1024
    }
}

/// How much RAM the live mode takes and what is left for the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    /// Bytes of the in-memory data store.
    pub ram_bytes: u64,
    /// Kernel heap in MiB after subtracting the store: the configured one,
    /// or the largest power of two that fits.
    pub heap_mb: u32,
    /// The heap had to shrink below the configured size.
    pub heap_shrunk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// `percent` of the machine's RAM is below the data layout's minimum.
    StoreTooSmall { ram_bytes: u64, min_bytes: u64 },
    /// Nothing usable is left for the heap after the store.
    NoRoomForHeap { left_mb: u64, need_mb: u32 },
}

/// RAM the kernel needs besides its heap, the SQLite heap and the store:
/// image, page tables and their pool, frame bitmap, per-core stacks and
/// what the bootloader keeps. A fixed allowance, deliberately generous.
pub const OVERHEAD_MB: u64 = 128;

/// The data store's size: `percent` of `total_ram` bytes, in whole MiB.
pub fn store_bytes(total_ram: u64, percent: u32) -> u64 {
    let b = (u128::from(total_ram) * u128::from(percent) / 100) as u64;
    b / MIB * MIB
}

/// Plans the live mode's memory: the store takes `percent` of
/// `total_ram`; the heap (`heap_mb`, a power of two, `min_heap_mb` the
/// least it may shrink to) keeps its size when it still fits next to the
/// store, the SQLite heap (`sqlite_mb`) and [`OVERHEAD_MB`], and otherwise
/// shrinks to the largest power of two that does.
pub fn plan(
    total_ram: u64,
    percent: u32,
    heap_mb: u32,
    sqlite_mb: u32,
    min_heap_mb: u32,
) -> Result<Reservation, ReserveError> {
    let ram_bytes = store_bytes(total_ram, percent);
    let min_bytes = MIN_SECTORS * SECTOR;
    if ram_bytes < min_bytes {
        return Err(ReserveError::StoreTooSmall {
            ram_bytes,
            min_bytes,
        });
    }
    let left_mb = (total_ram.saturating_sub(ram_bytes) / MIB)
        .saturating_sub(u64::from(sqlite_mb) + OVERHEAD_MB);
    let fit = if left_mb >= u64::from(heap_mb) {
        heap_mb
    } else if left_mb == 0 {
        0
    } else {
        // Largest power of two not above `left_mb`.
        1u32 << left_mb.ilog2()
    };
    if fit < min_heap_mb.max(1) {
        return Err(ReserveError::NoRoomForHeap {
            left_mb,
            need_mb: min_heap_mb.max(1),
        });
    }
    Ok(Reservation {
        ram_bytes,
        heap_mb: fit,
        heap_shrunk: fit < heap_mb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::{Disk, Opened};
    use alloc::boxed::Box;
    use alloc::vec;

    fn ram(chunks: usize, chunk_bytes: usize) -> RamDisk {
        let v = (0..chunks)
            .map(|_| &mut *Box::leak(vec![0u8; chunk_bytes].into_boxed_slice()))
            .collect();
        RamDisk::new(v).unwrap()
    }

    #[test]
    fn reads_back_what_was_written_across_chunk_boundaries() {
        let mut d = ram(4, 4096);
        assert_eq!(d.sectors(), 32);
        // A request that starts in chunk 0 and ends in chunk 2.
        let data: Vec<u8> = (0..(9 * 512)).map(|i| (i * 7 % 251) as u8).collect();
        d.write(6, &data).unwrap();
        d.flush().unwrap();
        let mut back = vec![0u8; data.len()];
        d.read(6, &mut back).unwrap();
        assert_eq!(back, data);
        // Neighbours untouched.
        let mut z = [1u8; 512];
        d.read(5, &mut z).unwrap();
        assert_eq!(z, [0u8; 512]);
        d.read(15, &mut z).unwrap();
        assert_eq!(z, [0u8; 512]);
    }

    #[test]
    fn bounds_and_shapes_are_enforced() {
        let mut d = ram(2, 4096);
        assert_eq!(d.sectors(), 16);
        let mut b = [0u8; 512];
        assert_eq!(d.read(16, &mut b), Err(IoError::OutOfRange));
        assert_eq!(d.write(15, &[0u8; 1024]), Err(IoError::OutOfRange));
        assert_eq!(d.read(u64::MAX, &mut b), Err(IoError::OutOfRange));
        assert_eq!(d.write(0, &[0u8; 100]), Err(IoError::OutOfRange));
        assert!(d.write(15, &[9u8; 512]).is_ok());
        assert!(RamDisk::new(Vec::new()).is_none());
        let odd = Box::leak(vec![0u8; 1000].into_boxed_slice());
        assert!(RamDisk::new(vec![odd]).is_none());
        let a = Box::leak(vec![0u8; 512].into_boxed_slice());
        let b = Box::leak(vec![0u8; 1024].into_boxed_slice());
        assert!(RamDisk::new(vec![a, b]).is_none(), "unequal chunks");
    }

    /// The whole storage stack runs on the RAM device: format, use, and a
    /// "reboot" (a new RAM device) finds nothing.
    #[test]
    fn the_data_layout_formats_and_reopens_on_ram() {
        let mut chunks = Vec::new();
        for _ in 0..16 {
            chunks.push(&mut *Box::leak(vec![0u8; 2 << 20].into_boxed_slice()));
        }
        let (disk, how) = Disk::open(Box::new(RamDisk::new(chunks).unwrap()), || [7; 16]).unwrap();
        assert_eq!(how, Opened::Formatted);
        assert_eq!(disk.layout().total_sectors, 32 * 2048);
        // A 32 MiB store is above the layout's 16 MiB minimum.
        let small = ram(4, 1 << 20);
        assert!(Disk::open(Box::new(small), || [0; 16]).is_err());
        // A fresh RAM device is blank again: formatted, not "existing".
        let again = ram(32, 1 << 20);
        let (_, how) = Disk::open(Box::new(again), || [1; 16]).unwrap();
        assert_eq!(how, Opened::Formatted);
    }

    #[test]
    fn store_is_a_whole_number_of_mib() {
        assert_eq!(store_bytes(1024 * MIB, 10), 102 * MIB);
        assert_eq!(store_bytes(4096 * MIB, 10), 409 * MIB);
        assert_eq!(store_bytes(512 * MIB, 2), 10 * MIB);
        assert_eq!(store_bytes(0, 10), 0);
        assert_eq!(
            store_bytes(u64::MAX, 50),
            9_223_372_036_853_775_808 / MIB * MIB
        );
    }

    #[test]
    fn the_heap_keeps_its_size_when_it_fits() {
        // 4 GiB, 10 %: 409 MiB store, 1024 MiB heap needs 1024 + 8 + 128.
        let r = plan(4096 * MIB, 10, 1024, 8, 4).unwrap();
        assert_eq!(
            r,
            Reservation {
                ram_bytes: 409 * MIB,
                heap_mb: 1024,
                heap_shrunk: false
            }
        );
    }

    #[test]
    fn the_store_is_subtracted_from_the_heap_when_memory_is_tight() {
        // 1 GiB: 102 MiB store, 8 + 128 for the rest: 786 MiB left, the
        // 1024 MiB heap becomes 512.
        let r = plan(1024 * MIB, 10, 1024, 8, 4).unwrap();
        assert_eq!(
            (r.ram_bytes, r.heap_mb, r.heap_shrunk),
            (102 * MIB, 512, true)
        );
        // The bigger the share, the smaller the heap: 50 % of 1 GiB.
        let r = plan(1024 * MIB, 50, 1024, 8, 4).unwrap();
        assert_eq!((r.heap_mb, r.heap_shrunk), (256, true));
        // Exactly at the edge keeps the size.
        let need = 1024 + 8 + 128;
        let total = (need * 100 / 90 + 2) * MIB; // 10 % off the top
        let r = plan(total, 10, 1024, 8, 4).unwrap();
        assert_eq!(r.heap_mb, 1024, "left {}", total / MIB);
    }

    #[test]
    fn refusals_say_what_is_wrong() {
        // 100 MiB of RAM: a 2 % store is 2 MiB, below the layout minimum.
        assert!(matches!(
            plan(100 * MIB, 2, 32, 8, 4),
            Err(ReserveError::StoreTooSmall { .. })
        ));
        // 16 MiB exactly is allowed.
        assert!(plan(800 * MIB, 2, 32, 8, 4).is_ok());
        // 512 MiB at 50 %: 256 store, 136 other, nothing left to speak of
        // for a heap that must keep at least 128.
        assert!(matches!(
            plan(512 * MIB, 50, 256, 8, 128),
            Err(ReserveError::NoRoomForHeap { .. })
        ));
        assert!(matches!(
            plan(140 * MIB, 12, 256, 8, 4),
            Err(ReserveError::NoRoomForHeap { .. })
        ));
    }

    #[test]
    fn dev_machine_fits() {
        // The smoke VM: 512 MiB, dev heap 32 MiB, SQLite heap 32 MiB.
        let r = plan(512 * MIB, 10, 32, 32, 4).unwrap();
        assert_eq!(
            (r.ram_bytes, r.heap_mb, r.heap_shrunk),
            (51 * MIB, 32, false)
        );
    }
}
