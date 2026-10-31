//! virtio-scsi (virtio 1.x §5.6): a polled host adapter for direct-access
//! disks, enough to use one LUN as the data disk.
//!
//! Many clouds attach every disk through virtio-scsi rather than virtio-blk
//! (PROMPT §5.3 targets, docs/DEPLOY.md). Only the request queue is used,
//! with one command in flight at a time and a bounce buffer, like `blk`:
//! INQUIRY and READ CAPACITY to find disks, READ/WRITE (10 or 16) and
//! SYNCHRONIZE CACHE. Unit attentions after reset are retried. CD-ROMs and
//! other device types are ignored, as are disks whose logical block is not
//! 512 bytes (the store addresses 512-byte sectors).

use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::transport::Transport;
use crate::{BlockTopology, Env, F_VERSION_1, UnmapLimits, VirtioError, wait_used};

pub const SECTOR: u64 = 512;
/// Largest single transfer (bounce buffer size).
pub const MAX_IO: usize = 64 << 10;
const QUEUE_SIZE: u16 = 16;
const REQUEST_QUEUE: u16 = 2;
const TIMEOUT_NS: u64 = 5_000_000_000;
/// Disks remembered by a scan.
pub const MAX_DISKS: usize = 8;
/// Targets and LUNs probed (QEMU and clouds use low numbers).
const MAX_TARGETS: u16 = 16;
const MAX_LUNS: u32 = 8;

// Device configuration (virtio 1.x §5.6.4).
const CFG_MAX_SECTORS: usize = 8;
const CFG_SENSE_SIZE: usize = 20;
const CFG_CDB_SIZE: usize = 24;
const CFG_MAX_TARGET: usize = 30;
const CFG_MAX_LUN: usize = 32;

// Response codes (virtio 1.x §5.6.6.1).
pub const S_OK: u8 = 0;
pub const S_BAD_TARGET: u8 = 3;
// SCSI status.
const GOOD: u8 = 0;
const CHECK_CONDITION: u8 = 2;
const UNIT_ATTENTION: u8 = 6;

// DMA layout: [request 0..256][response 256..768][data 768..].
const REQ: usize = 0;
const RESP: usize = 256;
const DATA: usize = 768;
const REQ_FIXED: usize = 19;
const RESP_FIXED: usize = 12;

/// Single-level LUN address (virtio 1.x §5.6.6.1).
pub fn lun_bytes(target: u16, lun: u32) -> [u8; 8] {
    let target = target.min(255) as u8;
    let lun = lun.min(0x3fff) as u16;
    [1, target, 0x40 | (lun >> 8) as u8, lun as u8, 0, 0, 0, 0]
}

/// READ or WRITE CDB for `blocks` 512-byte blocks at `lba`: the 10-byte
/// form when it fits, the 16-byte form otherwise.
pub fn rw_cdb(write: bool, lba: u64, blocks: u32) -> ([u8; 16], usize) {
    let mut c = [0u8; 16];
    if lba <= u64::from(u32::MAX) && blocks <= u32::from(u16::MAX) {
        c[0] = if write { 0x2a } else { 0x28 };
        c[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
        c[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
        (c, 10)
    } else {
        c[0] = if write { 0x8a } else { 0x88 };
        c[2..10].copy_from_slice(&lba.to_be_bytes());
        c[10..14].copy_from_slice(&blocks.to_be_bytes());
        (c, 16)
    }
}

/// UNMAP parameter list (SBC-4 5.30) for the ranges (LBA, blocks): an
/// 8-byte header and one 16-byte descriptor per range. Returns the length
/// written to `out`, or `None` if it does not fit.
pub fn unmap_list(ranges: &[(u64, u32)], out: &mut [u8]) -> Option<usize> {
    let len = 8 + ranges.len() * 16;
    let list = out.get_mut(..len)?;
    list.fill(0);
    // UNMAP DATA LENGTH counts the bytes after itself; BLOCK DESCRIPTOR
    // DATA LENGTH the descriptors.
    list.get_mut(0..2)?
        .copy_from_slice(&u16::try_from(len - 2).ok()?.to_be_bytes());
    list.get_mut(2..4)?
        .copy_from_slice(&u16::try_from(len - 8).ok()?.to_be_bytes());
    for (d, &(lba, n)) in list
        .get_mut(8..)?
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(ranges)
    {
        let (a, b) = d.split_at_mut(8);
        a.copy_from_slice(&lba.to_be_bytes());
        b.get_mut(..4)?.copy_from_slice(&n.to_be_bytes());
    }
    Some(len)
}

/// UNMAP CDB with a parameter list of `len` bytes.
pub fn unmap_cdb(len: u16) -> [u8; 10] {
    let mut c = [0u8; 10];
    c[0] = 0x42;
    c[7..9].copy_from_slice(&len.to_be_bytes());
    c
}

/// WRITE SAME (16) with UNMAP set, `blocks` blocks from `lba`: the data-out
/// buffer is one block of zeros.
pub fn write_same_unmap_cdb(lba: u64, blocks: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[0] = 0x93;
    c[1] = 0x08; // UNMAP
    c[2..10].copy_from_slice(&lba.to_be_bytes());
    c[10..14].copy_from_slice(&blocks.to_be_bytes());
    c
}

/// Peripheral device type of a connected LUN from standard INQUIRY data
/// (`None`: no device at this LUN).
pub fn inquiry_type(data: &[u8]) -> Option<u8> {
    let b = *data.first()?;
    (b >> 5 == 0).then_some(b & 0x1f)
}

/// (last LBA, block length) from READ CAPACITY (10) data.
pub fn capacity10(d: &[u8]) -> Option<(u64, u32)> {
    let lba = u32::from_be_bytes(d.get(0..4)?.try_into().ok()?);
    let len = u32::from_be_bytes(d.get(4..8)?.try_into().ok()?);
    Some((u64::from(lba), len))
}

/// (last LBA, block length) from READ CAPACITY (16) data.
pub fn capacity16(d: &[u8]) -> Option<(u64, u32)> {
    let lba = u64::from_be_bytes(d.get(0..8)?.try_into().ok()?);
    let len = u32::from_be_bytes(d.get(8..12)?.try_into().ok()?);
    Some((lba, len))
}

/// Sense key of fixed or descriptor format sense data.
pub fn sense_key(sense: &[u8]) -> Option<u8> {
    match sense.first()? & 0x7f {
        0x70 | 0x71 => Some(sense.get(2)? & 0x0f),
        0x72 | 0x73 => Some(sense.get(1)? & 0x0f),
        _ => None,
    }
}

/// A disk found by [`VirtioScsi::scan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskInfo {
    pub target: u16,
    pub lun: u32,
    pub sectors: u64,
    /// Physical block size and I/O hints (READ CAPACITY (16), Block Limits
    /// VPD page), or the defaults of a plain 512-byte disk.
    pub topology: BlockTopology,
    /// UNMAP and WRITE SAME (16) support and limits (S4).
    pub unmap: UnmapLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    None,
    In,
    Out,
}

struct Outcome {
    response: u8,
    status: u8,
    sense_key: Option<u8>,
}

/// The host adapter, before a disk is chosen.
pub struct VirtioScsi {
    t: Transport,
    q: SplitQueue,
    notify_off: usize,
    io: DmaRegion,
    cdb_size: usize,
    sense_size: usize,
    max_io: usize,
    max_target: u16,
    max_lun: u32,
    tag: u64,
}

/// One LUN of a [`VirtioScsi`] adapter used as a block device.
pub struct ScsiDisk {
    hba: VirtioScsi,
    lun: [u8; 8],
    pub target: u16,
    pub lun_id: u32,
    pub capacity_sectors: u64,
    pub topology: BlockTopology,
    pub unmap: UnmapLimits,
}

impl VirtioScsi {
    pub fn new<E: Env>(t: Transport, env: &E) -> Result<Self, VirtioError> {
        t.init(env, 0, F_VERSION_1)?;
        if t.num_queues() <= REQUEST_QUEUE {
            return Err(VirtioError::QueueUnavailable(REQUEST_QUEUE));
        }
        let size = QUEUE_SIZE.min(t.queue_max(REQUEST_QUEUE));
        let mem = env
            .dma_alloc(crate::queue::Layout::new(size).total)
            .ok_or(VirtioError::NoDma)?;
        // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
        #[allow(unsafe_code)]
        let q = unsafe { SplitQueue::new(mem, size) }?;
        let notify_off = t.setup_queue(REQUEST_QUEUE, &q, None)?;
        let cdb_size = t.device.read32(CFG_CDB_SIZE) as usize;
        let sense_size = t.device.read32(CFG_SENSE_SIZE) as usize;
        // The fixed layout holds up to 237-byte CDBs and 500-byte sense data;
        // READ (16) needs 16 bytes of CDB.
        if !(16..=RESP - REQ_FIXED).contains(&cdb_size) || sense_size > DATA - RESP - RESP_FIXED {
            return Err(VirtioError::DeviceFailed(0));
        }
        let max_sectors = (t.device.read32(CFG_MAX_SECTORS) as usize).max(1);
        let max_target = t.device.read16(CFG_MAX_TARGET).min(MAX_TARGETS - 1);
        let max_lun = t.device.read32(CFG_MAX_LUN).min(MAX_LUNS - 1);
        let io = env.dma_alloc(DATA + MAX_IO).ok_or(VirtioError::NoDma)?;
        t.driver_ok()?;
        Ok(Self {
            t,
            q,
            notify_off,
            io,
            cdb_size,
            sense_size,
            max_io: MAX_IO.min(max_sectors * SECTOR as usize),
            max_target,
            max_lun,
            tag: 0,
        })
    }

    #[allow(unsafe_code)]
    fn io_bytes(&mut self, off: usize, len: usize) -> &mut [u8] {
        let len = len.min(self.io.len.saturating_sub(off));
        // SAFETY: inside our DMA bounce region; the device does not touch it
        // while no request is in flight.
        unsafe { core::slice::from_raw_parts_mut((self.io.va + off) as *mut u8, len) }
    }

    fn command<E: Env>(
        &mut self,
        env: &E,
        lun: [u8; 8],
        cdb: &[u8],
        dir: Dir,
        len: usize,
    ) -> Result<Outcome, VirtioError> {
        if cdb.len() > self.cdb_size || len > MAX_IO {
            return Err(VirtioError::OutOfRange);
        }
        self.tag = self.tag.wrapping_add(1);
        let (req_len, resp_len) = (REQ_FIXED + self.cdb_size, RESP_FIXED + self.sense_size);
        let tag = self.tag;
        let req = self.io_bytes(REQ, req_len);
        req.fill(0);
        if let Some(l) = req.get_mut(0..8) {
            l.copy_from_slice(&lun);
        }
        if let Some(t) = req.get_mut(8..16) {
            t.copy_from_slice(&tag.to_le_bytes());
        }
        // task_attr SIMPLE (0), prio 0, crn 0, then the CDB.
        if let Some(c) = req.get_mut(REQ_FIXED..REQ_FIXED + cdb.len()) {
            c.copy_from_slice(cdb);
        }
        self.io_bytes(RESP, resp_len).fill(0xff);
        let pa = self.io.pa;
        let request = Buf {
            pa: pa + REQ as u64,
            len: req_len as u32,
            device_writes: false,
        };
        let response = Buf {
            pa: pa + RESP as u64,
            len: resp_len as u32,
            device_writes: true,
        };
        let data = Buf {
            pa: pa + DATA as u64,
            len: len as u32,
            device_writes: dir == Dir::In,
        };
        // Device-readable buffers first (request, data-out), then
        // device-writable ones (response, data-in) (§5.6.6).
        match dir {
            Dir::None => self.q.add(&[request, response])?,
            Dir::Out => self.q.add(&[request, data, response])?,
            Dir::In => self.q.add(&[request, response, data])?,
        };
        self.t.notify(self.notify_off, REQUEST_QUEUE);
        wait_used(env, &mut self.q, TIMEOUT_NS, "scsi")?;
        let sense_size = self.sense_size;
        let resp = self.io_bytes(RESP, resp_len);
        let sense_len = resp
            .get(0..4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes) as usize;
        let sense = resp
            .get(RESP_FIXED..RESP_FIXED + sense_len.min(sense_size))
            .unwrap_or(&[]);
        Ok(Outcome {
            status: resp.get(10).copied().unwrap_or(0xff),
            response: resp.get(11).copied().unwrap_or(0xff),
            sense_key: sense_key(sense),
        })
    }

    /// Runs a command, retrying unit attentions (reset, media change).
    fn checked<E: Env>(
        &mut self,
        env: &E,
        lun: [u8; 8],
        cdb: &[u8],
        dir: Dir,
        len: usize,
    ) -> Result<(), VirtioError> {
        for _ in 0..4 {
            let o = self.command(env, lun, cdb, dir, len)?;
            if o.response != S_OK {
                return Err(VirtioError::Io(o.response));
            }
            match o.status {
                GOOD => return Ok(()),
                CHECK_CONDITION if o.sense_key == Some(UNIT_ATTENTION) => continue,
                s => return Err(VirtioError::Io(s)),
            }
        }
        Err(VirtioError::Io(CHECK_CONDITION))
    }

    /// The direct-access disks with 512-byte blocks, in target/LUN order.
    pub fn scan<E: Env>(&mut self, env: &E) -> ([Option<DiskInfo>; MAX_DISKS], usize) {
        let mut out = [None; MAX_DISKS];
        let mut n = 0;
        for target in 0..=self.max_target {
            for lun in 0..=self.max_lun {
                let addr = lun_bytes(target, lun);
                let inquiry = [0x12, 0, 0, 0, 36, 0];
                match self.command(env, addr, &inquiry, Dir::In, 36) {
                    Ok(o) if o.response == S_BAD_TARGET => break,
                    Ok(o) if o.response == S_OK && o.status == GOOD => {}
                    _ => continue,
                }
                if inquiry_type(self.io_bytes(DATA, 36)) != Some(0) {
                    continue;
                }
                let Some(sectors) = self.capacity(env, addr) else {
                    continue;
                };
                let (topology, unmap) = self.topology(env, addr);
                if let Some(slot) = out.get_mut(n) {
                    *slot = Some(DiskInfo {
                        target,
                        lun,
                        sectors,
                        topology,
                        unmap,
                    });
                    n += 1;
                }
            }
        }
        (out, n)
    }

    /// Physical block size and I/O hints of a 512-byte-block disk, and what
    /// it can unmap (READ CAPACITY (16), Block Limits B0h, Logical Block
    /// Provisioning B2h); what the device does not answer stays at the
    /// defaults.
    fn topology<E: Env>(&mut self, env: &E, lun: [u8; 8]) -> (BlockTopology, UnmapLimits) {
        let mut c = [0u8; 16];
        c[0] = 0x9e;
        c[1] = 0x10;
        c[13] = 32;
        let cap16 = self.checked(env, lun, &c, Dir::In, 32).ok().map(|()| {
            let mut d = [0u8; 32];
            d.copy_from_slice(self.io_bytes(DATA, 32));
            d
        });
        // INQUIRY, EVPD, page B0h (Block Limits), 64 bytes.
        let b0 = self
            .checked(env, lun, &[0x12, 1, 0xb0, 0, 64, 0], Dir::In, 64)
            .ok()
            .map(|()| {
                let mut d = [0u8; 64];
                d.copy_from_slice(self.io_bytes(DATA, 64));
                d
            });
        let b2 = self
            .checked(env, lun, &[0x12, 1, 0xb2, 0, 8, 0], Dir::In, 8)
            .ok()
            .map(|()| {
                let mut d = [0u8; 8];
                d.copy_from_slice(self.io_bytes(DATA, 8));
                d
            });
        (
            BlockTopology::from_scsi(
                SECTOR as u32,
                cap16.as_ref().map(|d| &d[..]),
                b0.as_ref().map(|d| &d[..]),
            ),
            UnmapLimits::from_scsi(
                cap16.as_ref().map(|d| &d[..]),
                b0.as_ref().map(|d| &d[..]),
                b2.as_ref().map(|d| &d[..]),
            ),
        )
    }

    /// Size in 512-byte sectors; `None` for other block sizes.
    fn capacity<E: Env>(&mut self, env: &E, lun: [u8; 8]) -> Option<u64> {
        let tur = [0u8; 6];
        let _ = self.checked(env, lun, &tur, Dir::None, 0);
        self.checked(env, lun, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], Dir::In, 8)
            .ok()?;
        let (mut last, mut len) = capacity10(self.io_bytes(DATA, 8))?;
        if last == u64::from(u32::MAX) {
            let mut c = [0u8; 16];
            c[0] = 0x9e;
            c[1] = 0x10;
            c[13] = 32;
            self.checked(env, lun, &c, Dir::In, 32).ok()?;
            (last, len) = capacity16(self.io_bytes(DATA, 32))?;
        }
        (len == SECTOR as u32).then_some(last.saturating_add(1))
    }

    /// Uses `disk` (from [`scan`](Self::scan)) as the block device.
    pub fn into_disk(self, disk: DiskInfo) -> ScsiDisk {
        ScsiDisk {
            hba: self,
            lun: lun_bytes(disk.target, disk.lun),
            target: disk.target,
            lun_id: disk.lun,
            capacity_sectors: disk.sectors,
            topology: disk.topology,
            unmap: disk.unmap,
        }
    }

    /// Reads from `disk` before choosing it (to recognise a boot disk).
    pub fn read<E: Env>(
        &mut self,
        env: &E,
        disk: DiskInfo,
        sector: u64,
        buf: &mut [u8],
    ) -> Result<(), VirtioError> {
        self.rw(
            env,
            lun_bytes(disk.target, disk.lun),
            disk.sectors,
            false,
            sector,
            buf.len(),
        )?;
        buf.copy_from_slice(self.io_bytes(DATA, buf.len()));
        Ok(())
    }

    fn rw<E: Env>(
        &mut self,
        env: &E,
        lun: [u8; 8],
        capacity: u64,
        write: bool,
        sector: u64,
        len: usize,
    ) -> Result<(), VirtioError> {
        let blocks = (len as u64) / SECTOR;
        if len > self.max_io
            || !len.is_multiple_of(SECTOR as usize)
            || sector.saturating_add(blocks) > capacity
        {
            return Err(VirtioError::OutOfRange);
        }
        let (cdb, n) = rw_cdb(write, sector, blocks as u32);
        let dir = if write { Dir::Out } else { Dir::In };
        self.checked(env, lun, cdb.get(..n).unwrap_or(&[]), dir, len)
    }
}

impl ScsiDisk {
    pub fn max_io(&self) -> usize {
        self.hba.max_io
    }

    /// Reads `buf.len()` bytes (a multiple of 512, at most [`max_io`](Self::max_io)).
    pub fn read<E: Env>(
        &mut self,
        env: &E,
        sector: u64,
        buf: &mut [u8],
    ) -> Result<(), VirtioError> {
        let (lun, cap) = (self.lun, self.capacity_sectors);
        self.hba.rw(env, lun, cap, false, sector, buf.len())?;
        buf.copy_from_slice(self.hba.io_bytes(DATA, buf.len()));
        Ok(())
    }

    pub fn write<E: Env>(&mut self, env: &E, sector: u64, data: &[u8]) -> Result<(), VirtioError> {
        let (lun, cap) = (self.lun, self.capacity_sectors);
        if data.len() > self.hba.max_io {
            return Err(VirtioError::OutOfRange);
        }
        self.hba.io_bytes(DATA, data.len()).copy_from_slice(data);
        self.hba.rw(env, lun, cap, true, sector, data.len())
    }

    fn check_unmap(
        &self,
        ranges: &[(u64, u32)],
        max_sectors: u32,
        max_ranges: u32,
    ) -> Result<(), VirtioError> {
        if ranges.is_empty() || ranges.len() > max_ranges as usize || 8 + ranges.len() * 16 > MAX_IO
        {
            return Err(VirtioError::OutOfRange);
        }
        for &(lba, n) in ranges {
            if n == 0 || n > max_sectors || lba.saturating_add(u64::from(n)) > self.capacity_sectors
            {
                return Err(VirtioError::OutOfRange);
            }
        }
        Ok(())
    }

    /// UNMAP of the (LBA, blocks) ranges, within the device's limits. What
    /// an unmapped block reads back as is up to the device.
    pub fn discard<E: Env>(&mut self, env: &E, ranges: &[(u64, u32)]) -> Result<(), VirtioError> {
        if !self.unmap.discard {
            return Err(VirtioError::OutOfRange);
        }
        self.check_unmap(
            ranges,
            self.unmap.max_discard_sectors,
            self.unmap.max_discard_ranges,
        )?;
        let lun = self.lun;
        let n =
            unmap_list(ranges, self.hba.io_bytes(DATA, MAX_IO)).ok_or(VirtioError::OutOfRange)?;
        let cdb = unmap_cdb(u16::try_from(n).map_err(|_| VirtioError::OutOfRange)?);
        self.hba.checked(env, lun, &cdb, Dir::Out, n)
    }

    /// WRITE SAME (16) with UNMAP of one range: the blocks read back as
    /// zeros and the device may deallocate them.
    pub fn write_zeroes<E: Env>(
        &mut self,
        env: &E,
        ranges: &[(u64, u32)],
    ) -> Result<(), VirtioError> {
        if !self.unmap.zeroes {
            return Err(VirtioError::OutOfRange);
        }
        self.check_unmap(
            ranges,
            self.unmap.max_zeroes_sectors,
            self.unmap.max_zeroes_ranges,
        )?;
        let lun = self.lun;
        for &(lba, n) in ranges {
            self.hba.io_bytes(DATA, SECTOR as usize).fill(0);
            let cdb = write_same_unmap_cdb(lba, n);
            self.hba
                .checked(env, lun, &cdb, Dir::Out, SECTOR as usize)?;
        }
        Ok(())
    }

    /// SYNCHRONIZE CACHE (10) over the whole disk: previous writes durable.
    pub fn flush<E: Env>(&mut self, env: &E) -> Result<(), VirtioError> {
        let lun = self.lun;
        self.hba
            .checked(env, lun, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Dir::None, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lun_addressing() {
        assert_eq!(lun_bytes(0, 0), [1, 0, 0x40, 0, 0, 0, 0, 0]);
        assert_eq!(lun_bytes(3, 0x123), [1, 3, 0x41, 0x23, 0, 0, 0, 0]);
    }

    #[test]
    fn read_write_cdbs() {
        let (c, n) = rw_cdb(false, 0x1234_5678, 128);
        assert_eq!(
            (n, &c[..10]),
            (10, &[0x28, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 128, 0][..])
        );
        let (c, n) = rw_cdb(true, 1 << 33, 8);
        assert_eq!(n, 16);
        assert_eq!(c[0], 0x8a);
        assert_eq!(&c[2..10], &(1u64 << 33).to_be_bytes());
        assert_eq!(&c[10..14], &8u32.to_be_bytes());
    }

    #[test]
    fn unmap_commands() {
        let mut buf = [0xffu8; 64];
        let n = unmap_list(&[(0x1000, 8), (1 << 33, 0x100)], &mut buf).unwrap();
        assert_eq!(n, 8 + 32);
        assert_eq!(&buf[0..4], &[0, 38, 0, 32]);
        assert_eq!(&buf[4..8], &[0; 4], "reserved bytes are zero");
        assert_eq!(&buf[8..16], &0x1000u64.to_be_bytes());
        assert_eq!(&buf[16..20], &8u32.to_be_bytes());
        assert_eq!(&buf[20..24], &[0; 4]);
        assert_eq!(&buf[24..32], &(1u64 << 33).to_be_bytes());
        assert_eq!(
            unmap_list(&[(0, 1); 4], &mut [0u8; 40]),
            None,
            "does not fit"
        );
        assert_eq!(unmap_cdb(40), [0x42, 0, 0, 0, 0, 0, 0, 0, 40, 0]);
        let c = write_same_unmap_cdb(0x1234, 16);
        assert_eq!((c[0], c[1]), (0x93, 0x08));
        assert_eq!(&c[2..10], &0x1234u64.to_be_bytes());
        assert_eq!(&c[10..14], &16u32.to_be_bytes());
    }

    #[test]
    fn inquiry_and_capacity_and_sense() {
        assert_eq!(inquiry_type(&[0x00, 0, 5]), Some(0)); // disk
        assert_eq!(inquiry_type(&[0x05]), Some(5)); // CD-ROM
        assert_eq!(inquiry_type(&[0x7f]), None); // no LUN
        assert_eq!(inquiry_type(&[]), None);
        assert_eq!(
            capacity10(&[0, 0, 0x1f, 0xff, 0, 0, 2, 0]),
            Some((0x1fff, 512))
        );
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&(1u64 << 40).to_be_bytes());
        d[8..12].copy_from_slice(&4096u32.to_be_bytes());
        assert_eq!(capacity16(&d), Some((1 << 40, 4096)));
        assert_eq!(capacity10(&[0; 7]), None);
        assert_eq!(
            sense_key(&[0x70, 0, 0x06, 0, 0, 0, 0, 10]),
            Some(UNIT_ATTENTION)
        );
        assert_eq!(sense_key(&[0x72, 0x05]), Some(5));
        assert_eq!(sense_key(&[0x00]), None);
    }
}
