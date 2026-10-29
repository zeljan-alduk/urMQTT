//! Fault injection on a block device (STORAGE-PLAN §4): power loss after
//! the N-th write or flush, a torn write, a dropped flush, bit flips on
//! read. Host tests wrap `MemDisk` in it; dev kernels wrap the data
//! partition when `test=disk-fault:<spec>` is given (never in prod).

use alloc::boxed::Box;

use crate::disk::{BlockDevice, IoError};

/// What to inject, counting operations from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FaultSpec {
    /// The device dies after this many writes complete: every later
    /// operation fails, as if the power went.
    pub stop_after_writes: Option<u64>,
    /// The device dies after this many flushes complete.
    pub stop_after_flushes: Option<u64>,
    /// The N-th write reaches the device only partly: its first `sectors`
    /// sectors, then the device dies.
    pub tear_write: Option<(u64, u64)>,
    /// The N-th flush returns success without flushing.
    pub drop_flush: Option<u64>,
    /// Every read of this LBA comes back with bit 0 of its first byte
    /// inverted.
    pub flip_read_lba: Option<u64>,
}

impl FaultSpec {
    /// Parses `stop-after-write=N`, `stop-after-flush=N`, `tear-write=N:K`,
    /// `drop-flush=N` and `flip-read=LBA`, comma separated.
    pub fn parse(s: &str) -> Option<Self> {
        let mut f = Self::default();
        for part in s.split(',').filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=')?;
            let n = || v.parse::<u64>().ok();
            match k {
                "stop-after-write" => f.stop_after_writes = Some(n()?),
                "stop-after-flush" => f.stop_after_flushes = Some(n()?),
                "drop-flush" => f.drop_flush = Some(n()?),
                "flip-read" => f.flip_read_lba = Some(n()?),
                "tear-write" => {
                    let (a, b) = v.split_once(':')?;
                    f.tear_write = Some((a.parse().ok()?, b.parse().ok()?));
                }
                _ => return None,
            }
        }
        Some(f)
    }
}

pub struct FaultDevice {
    inner: Box<dyn BlockDevice>,
    spec: FaultSpec,
    writes: u64,
    flushes: u64,
    dead: bool,
}

impl FaultDevice {
    pub fn new(inner: Box<dyn BlockDevice>, spec: FaultSpec) -> Self {
        Self {
            inner,
            spec,
            writes: 0,
            flushes: 0,
            dead: false,
        }
    }

    /// Whether the injected power loss has happened.
    pub fn dead(&self) -> bool {
        self.dead
    }

    pub fn writes(&self) -> u64 {
        self.writes
    }
}

impl BlockDevice for FaultDevice {
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError::Device);
        }
        self.inner.read(lba, buf)?;
        if let Some(f) = self.spec.flip_read_lba {
            let n = (buf.len() as u64).div_ceil(crate::layout::SECTOR);
            if f >= lba && f < lba + n {
                let at = ((f - lba) * crate::layout::SECTOR) as usize;
                if let Some(b) = buf.get_mut(at) {
                    *b ^= 1;
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError::Device);
        }
        let n = self.writes + 1;
        if let Some((at, sectors)) = self.spec.tear_write
            && at == n
        {
            let keep = ((sectors * crate::layout::SECTOR) as usize).min(buf.len());
            if keep > 0 {
                self.inner.write(lba, buf.get(..keep).unwrap_or(&[]))?;
                self.inner.flush()?;
            }
            self.dead = true;
            return Err(IoError::Device);
        }
        self.inner.write(lba, buf)?;
        self.writes = n;
        if self.spec.stop_after_writes.is_some_and(|s| n >= s) {
            self.dead = true;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError::Device);
        }
        let n = self.flushes + 1;
        self.flushes = n;
        if self.spec.drop_flush == Some(n) {
            return Ok(());
        }
        self.inner.flush()?;
        if self.spec.stop_after_flushes.is_some_and(|s| n >= s) {
            self.dead = true;
        }
        Ok(())
    }

    fn max_io(&self) -> usize {
        self.inner.max_io()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;

    #[test]
    fn spec_parses_and_rejects() {
        let f =
            FaultSpec::parse("stop-after-write=3,tear-write=5:2,drop-flush=1,flip-read=9").unwrap();
        assert_eq!(f.stop_after_writes, Some(3));
        assert_eq!(f.tear_write, Some((5, 2)));
        assert_eq!(f.drop_flush, Some(1));
        assert_eq!(f.flip_read_lba, Some(9));
        assert_eq!(FaultSpec::parse(""), Some(FaultSpec::default()));
        for bad in ["x=1", "stop-after-write", "tear-write=1", "drop-flush=a"] {
            assert!(FaultSpec::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn faults_behave_as_specified() {
        let m = MemDisk::new(32 * 512);
        let spec = FaultSpec::parse("stop-after-write=2").unwrap();
        let mut d = FaultDevice::new(m.device(), spec);
        d.write(0, &[1; 512]).unwrap();
        d.write(1, &[2; 512]).unwrap();
        assert!(d.dead());
        assert_eq!(d.write(2, &[3; 512]), Err(IoError::Device));
        assert_eq!(d.flush(), Err(IoError::Device));
        // Unflushed writes are lost with the power.
        m.crash(|_| false);
        assert_eq!(m.raw(0, 1), vec![0]);

        let m = MemDisk::new(32 * 512);
        let mut d = FaultDevice::new(m.device(), FaultSpec::parse("tear-write=1:1").unwrap());
        assert!(d.write(0, &[5; 1024]).is_err());
        assert_eq!((m.raw(0, 1), m.raw(512, 1)), (vec![5], vec![0]));

        let m = MemDisk::new(32 * 512);
        let mut d = FaultDevice::new(
            m.device(),
            FaultSpec::parse("drop-flush=1,flip-read=0").unwrap(),
        );
        d.write(0, &[4; 512]).unwrap();
        d.flush().unwrap();
        assert_eq!(m.unflushed(), 1, "the flush was dropped");
        let mut b = [0u8; 512];
        d.read(0, &mut b).unwrap();
        assert_eq!(b[0], 5, "bit 0 flipped");
    }
}
