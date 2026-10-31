//! A partition as a block device: LBAs relative to its first sector, and
//! nothing outside it reachable. The data layout (DISK-FORMAT.md) lives in
//! the boot disk's data partition through this window.

use alloc::boxed::Box;

use crate::disk::{BlockDevice, IoError};

pub struct Partition {
    inner: Box<dyn BlockDevice>,
    first: u64,
    sectors: u64,
}

impl Partition {
    /// The `sectors` sectors from `first` of `inner`. `None` if the range
    /// does not fit the device.
    pub fn new(inner: Box<dyn BlockDevice>, first: u64, sectors: u64) -> Option<Self> {
        let end = first.checked_add(sectors)?;
        (sectors > 0 && end <= inner.sectors()).then_some(Self {
            inner,
            first,
            sectors,
        })
    }

    pub fn first_lba(&self) -> u64 {
        self.first
    }

    fn check(&self, lba: u64, len: usize) -> Result<u64, IoError> {
        let n = (len as u64).div_ceil(crate::layout::SECTOR);
        match lba.checked_add(n) {
            Some(end) if end <= self.sectors => Ok(self.first + lba),
            _ => Err(IoError::OutOfRange),
        }
    }
}

impl BlockDevice for Partition {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let at = self.check(lba, buf.len())?;
        self.inner.read(at, buf)
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        let at = self.check(lba, buf.len())?;
        self.inner.write(at, buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.inner.flush()
    }

    fn max_io(&self) -> usize {
        self.inner.max_io()
    }

    fn topology(&self) -> crate::layout::Topology {
        self.inner.topology()
    }

    fn base_lba(&self) -> u64 {
        self.inner.base_lba() + self.first
    }

    fn refresh_size(&mut self) -> Option<u64> {
        self.inner.refresh_size()
    }

    fn discard_caps(&self) -> Option<crate::disk::DiscardCaps> {
        self.inner.discard_caps()
    }

    fn discard(&mut self, ranges: &[(u64, u64)]) -> Result<(), IoError> {
        // Nothing outside the window is ever released.
        let mut abs = alloc::vec::Vec::with_capacity(ranges.len());
        for &(lba, n) in ranges {
            match lba.checked_add(n) {
                Some(end) if end <= self.sectors => abs.push((self.first + lba, n)),
                _ => return Err(IoError::OutOfRange),
            }
        }
        self.inner.discard(&abs)
    }

    fn whole_disk(&mut self) -> Option<&mut dyn BlockDevice> {
        Some(self.inner.as_mut())
    }

    fn resize_window(&mut self, sectors: u64) {
        // Never smaller, never beyond the disk.
        if sectors > self.sectors && self.first + sectors <= self.inner.sectors() {
            self.sectors = sectors;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;

    #[test]
    fn window_is_relative_and_bounded() {
        let m = MemDisk::new(64 * 512);
        let mut p = Partition::new(m.device(), 10, 20).unwrap();
        assert_eq!(p.sectors(), 20);
        p.write(0, &[7u8; 512]).unwrap();
        p.write(19, &[9u8; 512]).unwrap();
        p.flush().unwrap();
        assert_eq!(m.raw(10 * 512, 1), vec![7]);
        assert_eq!(m.raw(29 * 512, 1), vec![9]);
        assert_eq!(p.write(20, &[0u8; 512]), Err(IoError::OutOfRange));
        assert_eq!(p.write(19, &[0u8; 1024]), Err(IoError::OutOfRange));
        assert_eq!(p.read(u64::MAX, &mut [0u8; 512]), Err(IoError::OutOfRange));
        assert!(Partition::new(m.device(), 60, 5).is_none());
        // Discards stay inside the window too.
        assert_eq!(p.discard(&[(19, 2)]), Err(IoError::OutOfRange));
        assert_eq!(p.discard_caps(), None);
        assert!(Partition::new(m.device(), 0, 0).is_none());
    }
}
