//! Block devices of the host tool: an image file or block device, a
//! copy-on-write view for the read-only commands, a shareable handle, and
//! the fault injection wrapper the tests (and `--fault`) put around them.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use urmqtt_store::layout::{SECTOR, Topology};
use urmqtt_store::{BlockDevice, IoError};

pub const S: usize = SECTOR as usize;

/// An image file or block device. Writes need `writable`.
pub struct FileDisk {
    f: File,
    sectors: u64,
    writable: bool,
}

impl FileDisk {
    pub fn open(path: &str, writable: bool) -> Result<Self, String> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)
            .map_err(|e| format!("{path}: {e}"))?;
        let bytes = f
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("{path}: {e}"))?;
        if bytes == 0 || bytes % SECTOR != 0 {
            return Err(format!(
                "{path}: {bytes} bytes is not a whole number of 512-byte sectors (on macOS use /dev/rdiskN)"
            ));
        }
        Ok(Self {
            f,
            sectors: bytes / SECTOR,
            writable,
        })
    }
}

impl BlockDevice for FileDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if lba + (buf.len() / S) as u64 > self.sectors {
            return Err(IoError::OutOfRange);
        }
        self.f
            .seek(SeekFrom::Start(lba * SECTOR))
            .and_then(|_| self.f.read_exact(buf))
            .map_err(|_| IoError::Device)
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        if !self.writable {
            return Err(IoError::Device);
        }
        if lba + (buf.len() / S) as u64 > self.sectors {
            return Err(IoError::OutOfRange);
        }
        self.f
            .seek(SeekFrom::Start(lba * SECTOR))
            .and_then(|_| self.f.write_all(buf))
            .map_err(|_| IoError::Device)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if !self.writable {
            return Ok(());
        }
        self.f.sync_all().map_err(|_| IoError::Device)
    }
}

/// A device several holders use at once (the staged layout and the source
/// view in the migration share one device and one fault counter).
#[derive(Clone)]
pub struct Shared {
    inner: Arc<Mutex<Box<dyn BlockDevice>>>,
    sectors: u64,
    topo: Topology,
    max_io: usize,
}

impl Shared {
    pub fn new(dev: Box<dyn BlockDevice>) -> Self {
        let (sectors, topo, max_io) = (dev.sectors(), dev.topology(), dev.max_io());
        Self {
            inner: Arc::new(Mutex::new(dev)),
            sectors,
            topo,
            max_io,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Box<dyn BlockDevice>>, IoError> {
        self.inner.lock().map_err(|_| IoError::Device)
    }
}

impl BlockDevice for Shared {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.lock()?.read(lba, buf)
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        self.lock()?.write(lba, buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.lock()?.flush()
    }

    fn max_io(&self) -> usize {
        self.max_io
    }

    fn topology(&self) -> Topology {
        self.topo
    }
}

type Dirty = Arc<Mutex<BTreeMap<u64, Box<[u8; S]>>>>;

/// Copy-on-write over a device: writes stay in memory, the device is never
/// changed. Used by every read-only command that needs SQLite or the
/// telemetry recovery to run.
#[derive(Clone)]
pub struct Overlay {
    base: Shared,
    dirty: Dirty,
}

impl Overlay {
    pub fn new(base: Box<dyn BlockDevice>) -> Self {
        Self {
            base: Shared::new(base),
            dirty: Dirty::default(),
        }
    }

    /// Another view of the same device and the same in-memory changes.
    pub fn view(&self) -> Self {
        self.clone()
    }
}

impl BlockDevice for Overlay {
    fn sectors(&self) -> u64 {
        self.base.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.base.read(lba, buf)?;
        let d = self.dirty.lock().map_err(|_| IoError::Device)?;
        for (i, chunk) in buf.chunks_mut(S).enumerate() {
            if let Some(s) = d.get(&(lba + i as u64)) {
                chunk.copy_from_slice(&s[..]);
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        if lba + (buf.len() / S) as u64 > self.base.sectors {
            return Err(IoError::OutOfRange);
        }
        let mut d = self.dirty.lock().map_err(|_| IoError::Device)?;
        for (i, chunk) in buf.chunks(S).enumerate() {
            let mut s = Box::new([0u8; S]);
            s.copy_from_slice(chunk);
            d.insert(lba + i as u64, s);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }

    fn max_io(&self) -> usize {
        self.base.max_io
    }

    fn topology(&self) -> Topology {
        self.base.topo
    }
}
