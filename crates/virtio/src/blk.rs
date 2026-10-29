//! virtio-blk (virtio 1.x §5.2): synchronous read, write and flush through a
//! bounce buffer.

use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::transport::Transport;
use crate::{Env, F_VERSION_1, VirtioError, wait_used};

pub const F_RO: u64 = 1 << 5;
pub const F_BLK_SIZE: u64 = 1 << 6;
pub const F_FLUSH: u64 = 1 << 9;

pub const SECTOR: u64 = 512;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;

const QUEUE_SIZE: u16 = 16;
/// Largest single request (bounce buffer size).
pub const MAX_IO: usize = 64 << 10;
const TIMEOUT_NS: u64 = 5_000_000_000;

pub struct VirtioBlk {
    t: Transport,
    q: SplitQueue,
    notify_off: usize,
    /// [header 16][status 1 .. pad to 64][data MAX_IO]
    io: DmaRegion,
    pub capacity_sectors: u64,
    pub block_size: u32,
    pub has_flush: bool,
    pub read_only: bool,
}

const HDR: usize = 0;
const STATUS: usize = 16;
const DATA: usize = 64;

impl VirtioBlk {
    pub fn new<E: Env>(t: Transport, env: &E) -> Result<Self, VirtioError> {
        Self::new_with_msix(t, env, None)
    }

    /// Like [`new`](Self::new), with queue 0 signalling MSI-X vector `msix`
    /// (MSI-X must already be enabled in PCI config space).
    pub fn new_with_msix<E: Env>(
        t: Transport,
        env: &E,
        msix: Option<u16>,
    ) -> Result<Self, VirtioError> {
        let features = t.init(env, F_RO | F_BLK_SIZE | F_FLUSH, F_VERSION_1)?;
        let size = QUEUE_SIZE.min(t.queue_max(0));
        let mem = env
            .dma_alloc(crate::queue::Layout::new(size).total)
            .ok_or(VirtioError::NoDma)?;
        // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
        #[allow(unsafe_code)]
        let q = unsafe { SplitQueue::new(mem, size) }?;
        let notify_off = t.setup_queue(0, &q, msix)?;
        let io = env.dma_alloc(DATA + MAX_IO).ok_or(VirtioError::NoDma)?;
        let capacity_sectors =
            u64::from(t.device.read32(0)) | (u64::from(t.device.read32(4)) << 32);
        let block_size = if features & F_BLK_SIZE != 0 {
            t.device.read32(20).max(512)
        } else {
            512
        };
        t.driver_ok()?;
        Ok(Self {
            t,
            q,
            notify_off,
            io,
            capacity_sectors,
            block_size,
            has_flush: features & F_FLUSH != 0,
            read_only: features & F_RO != 0,
        })
    }

    #[allow(unsafe_code)]
    fn io_bytes(&mut self, off: usize, len: usize) -> &mut [u8] {
        let len = len.min(self.io.len.saturating_sub(off));
        // SAFETY: inside our DMA bounce region; the device does not touch it
        // while no request is in flight.
        unsafe { core::slice::from_raw_parts_mut((self.io.va + off) as *mut u8, len) }
    }

    fn submit<E: Env>(
        &mut self,
        env: &E,
        kind: u32,
        sector: u64,
        data_len: usize,
    ) -> Result<(), VirtioError> {
        let mut hdr = [0u8; 16];
        if let Some(h) = hdr.get_mut(0..4) {
            h.copy_from_slice(&kind.to_le_bytes());
        }
        if let Some(h) = hdr.get_mut(8..16) {
            h.copy_from_slice(&sector.to_le_bytes());
        }
        self.io_bytes(HDR, 16).copy_from_slice(&hdr);
        if let Some(s) = self.io_bytes(STATUS, 1).first_mut() {
            *s = 0xff;
        }
        let pa = self.io.pa;
        let header = Buf {
            pa: pa + HDR as u64,
            len: 16,
            device_writes: false,
        };
        let status = Buf {
            pa: pa + STATUS as u64,
            len: 1,
            device_writes: true,
        };
        let data = Buf {
            pa: pa + DATA as u64,
            len: data_len as u32,
            device_writes: kind == T_IN,
        };
        if data_len == 0 {
            self.q.add(&[header, status])?;
        } else {
            self.q.add(&[header, data, status])?;
        }
        self.t.notify(self.notify_off, 0);
        wait_used(env, &mut self.q, TIMEOUT_NS, "blk")?;
        match self.io_bytes(STATUS, 1).first().copied() {
            Some(S_OK) => Ok(()),
            Some(s) => Err(VirtioError::Io(s)),
            None => Err(VirtioError::Io(0xff)),
        }
    }

    fn check(&self, sector: u64, len: usize) -> Result<(), VirtioError> {
        let sectors = (len as u64).div_ceil(SECTOR);
        if len > MAX_IO
            || !len.is_multiple_of(SECTOR as usize)
            || sector.saturating_add(sectors) > self.capacity_sectors
        {
            return Err(VirtioError::OutOfRange);
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes (a multiple of 512, at most `MAX_IO`).
    pub fn read<E: Env>(
        &mut self,
        env: &E,
        sector: u64,
        buf: &mut [u8],
    ) -> Result<(), VirtioError> {
        self.check(sector, buf.len())?;
        self.submit(env, T_IN, sector, buf.len())?;
        buf.copy_from_slice(self.io_bytes(DATA, buf.len()));
        Ok(())
    }

    pub fn write<E: Env>(&mut self, env: &E, sector: u64, data: &[u8]) -> Result<(), VirtioError> {
        if self.read_only {
            return Err(VirtioError::ReadOnly);
        }
        self.check(sector, data.len())?;
        self.io_bytes(DATA, data.len()).copy_from_slice(data);
        self.submit(env, T_OUT, sector, data.len())
    }

    /// Makes previous writes durable. Fails if the device cannot flush.
    pub fn flush<E: Env>(&mut self, env: &E) -> Result<(), VirtioError> {
        if !self.has_flush {
            return Err(VirtioError::MissingFeatures(F_FLUSH));
        }
        self.submit(env, T_FLUSH, 0, 0)
    }
}
