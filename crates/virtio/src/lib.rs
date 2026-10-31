//! virtio-pci modern transport, split virtqueues and the net, blk, scsi
//! and rng devices (virtio 1.x).
//!
//! Devices are driven synchronously by polling in M6; interrupts (MSI-X)
//! are wired per queue by the caller. Everything a device returns (used
//! ring indices, lengths, config values) is validated before use.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod blk;
pub mod net;
pub mod queue;
pub mod rng;
pub mod scsi;
pub mod transport;

pub use queue::{Buf, DmaRegion, QueueError, SplitQueue};
pub use transport::{Region, Support, Transport, VirtioCaps, find_caps};

pub const VENDOR: u16 = 0x1af4;
pub const F_VERSION_1: u64 = 1 << 32;

/// Device types (virtio 1.x §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Net,
    Block,
    Entropy,
    Scsi,
    Other(u16),
}

impl DeviceType {
    /// Type of a PCI function: modern IDs are 0x1040 + type, transitional
    /// IDs 0x1000..0x103f carry the type in the subsystem ID.
    pub fn from_pci(vendor: u16, device: u16, subsystem: u16) -> Option<Self> {
        if vendor != VENDOR {
            return None;
        }
        let t = match device {
            0x1040..=0x107f => device - 0x1040,
            0x1000..=0x103f => subsystem,
            _ => return None,
        };
        Some(match t {
            1 => Self::Net,
            2 => Self::Block,
            4 => Self::Entropy,
            8 => Self::Scsi,
            other => Self::Other(other),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioError {
    MissingFeatures(u64),
    FeaturesRejected,
    QueueUnavailable(u16),
    MsixRejected,
    DeviceFailed(u8),
    NoDma,
    Queue(QueueError),
    Timeout(&'static str),
    /// The device reported an I/O error status.
    Io(u8),
    /// Request outside the device (sector range, oversized buffer).
    OutOfRange,
    ReadOnly,
}

impl From<QueueError> for VirtioError {
    fn from(e: QueueError) -> Self {
        Self::Queue(e)
    }
}

/// What a driver needs from the kernel.
pub trait Env {
    /// Zeroed, physically contiguous memory the device may access.
    fn dma_alloc(&self, bytes: usize) -> Option<DmaRegion>;
    /// Monotonic nanoseconds, for timeouts.
    fn now_ns(&self) -> u64;
}

/// Block sizes and I/O hints of a storage device, in bytes (S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTopology {
    pub logical: u32,
    pub physical: u32,
    /// Offset of the first aligned logical block.
    pub align_offset: u32,
    pub min_io: u32,
    pub opt_io: u32,
}

impl Default for BlockTopology {
    fn default() -> Self {
        Self {
            logical: 512,
            physical: 512,
            align_offset: 0,
            min_io: 0,
            opt_io: 0,
        }
    }
}

/// Sizes a device reports in logical blocks, scaled by `scale` bytes and
/// bounded so a hostile or broken value cannot overflow.
fn scaled(blocks: u32, scale: u32) -> u32 {
    blocks.saturating_mul(scale).min(1 << 30)
}

impl BlockTopology {
    /// From virtio-blk `F_TOPOLOGY` (virtio 1.x §5.2.4): `exp` is log2 of
    /// physical blocks per logical block; the other fields are in logical
    /// blocks. Absurd exponents mean "nothing reported".
    pub fn from_blk(blk_size: u32, exp: u8, align: u8, min_io: u16, opt_io: u32) -> Self {
        let logical = blk_size.clamp(512, 1 << 16);
        let physical = if exp <= 8 {
            scaled(1 << exp, logical)
        } else {
            logical
        };
        Self {
            logical,
            physical: physical.max(logical),
            align_offset: scaled(u32::from(align), logical),
            min_io: scaled(u32::from(min_io), logical),
            opt_io: scaled(opt_io, logical),
        }
    }

    /// From SCSI: READ CAPACITY (16) data (`cap16`, logical blocks per
    /// physical block exponent in byte 13, lowest aligned LBA in bytes
    /// 14..16) and the Block Limits VPD page (`b0`: optimal transfer length
    /// granularity at 6, optimal transfer length at 12), either of which may
    /// be missing.
    pub fn from_scsi(logical: u32, cap16: Option<&[u8]>, b0: Option<&[u8]>) -> Self {
        let logical = logical.clamp(512, 1 << 16);
        let mut t = Self {
            logical,
            physical: logical,
            ..Self::default()
        };
        if let Some(c) = cap16 {
            let exp = c.get(13).map_or(0, |b| b & 0x0f);
            if exp <= 8 {
                t.physical = scaled(1 << exp, logical).max(logical);
            }
            if let (Some(&hi), Some(&lo)) = (c.get(14), c.get(15)) {
                let lowest = (u32::from(hi & 0x3f) << 8) | u32::from(lo);
                // The lowest aligned LBA is counted from the start of a
                // physical block; as an offset it is (physical - lba*logical)
                // modulo physical, but only the zero case matters to us.
                t.align_offset = scaled(lowest, logical) % t.physical.max(1);
            }
        }
        if let Some(b) = b0.filter(|b| b.get(1) == Some(&0xb0) && b.len() >= 16) {
            let gran = b
                .get(6..8)
                .and_then(|x| x.try_into().ok())
                .map_or(0, u16::from_be_bytes);
            let opt = b
                .get(12..16)
                .and_then(|x| x.try_into().ok())
                .map_or(0, u32::from_be_bytes);
            t.min_io = scaled(u32::from(gran), logical);
            t.opt_io = scaled(opt, logical);
        }
        t
    }
}

/// What a device can unmap or zero, with its limits (S4, ADR-150). Sizes
/// are in 512-byte sectors. A device that does not offer a command has
/// all its fields zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnmapLimits {
    /// DISCARD (virtio-blk) or UNMAP (SCSI) is usable.
    pub discard: bool,
    /// Largest range of one discard descriptor.
    pub max_discard_sectors: u32,
    /// Descriptors in one discard request.
    pub max_discard_ranges: u32,
    /// Start and length of a discarded range should be multiples of this.
    pub discard_align: u32,
    /// WRITE ZEROES that may deallocate (the unmap flag is honoured).
    pub zeroes: bool,
    pub max_zeroes_sectors: u32,
    pub max_zeroes_ranges: u32,
}

/// Bounds that keep a hostile or broken device from making the driver
/// compute with absurd numbers. A range above 2^31 sectors (1 TiB) or an
/// alignment above 1 GiB is clamped, and a segment count above 256 is
/// cut (the bounce buffer holds fewer anyway).
const UNMAP_MAX_SECTORS: u32 = 1 << 31;
const UNMAP_MAX_ALIGN: u32 = 1 << 21;
const UNMAP_MAX_RANGES: u32 = 256;

impl UnmapLimits {
    /// From virtio-blk (§5.2.4): the negotiated features, the five words at
    /// config offsets 36..56 (`max_discard_sectors`, `max_discard_seg`,
    /// `discard_sector_alignment`, `max_write_zeroes_sectors`,
    /// `max_write_zeroes_seg`) and `write_zeroes_may_unmap`.
    pub fn from_blk(f_discard: bool, f_zeroes: bool, w: [u32; 5], zeroes_may_unmap: bool) -> Self {
        let [
            max_discard_sectors,
            max_discard_seg,
            discard_align,
            max_zeroes_sectors,
            max_zeroes_seg,
        ] = w;
        let mut u = Self::default();
        if f_discard && max_discard_sectors > 0 && max_discard_seg > 0 {
            u.discard = true;
            u.max_discard_sectors = max_discard_sectors.min(UNMAP_MAX_SECTORS);
            u.max_discard_ranges = max_discard_seg.min(UNMAP_MAX_RANGES);
            u.discard_align = discard_align.clamp(1, UNMAP_MAX_ALIGN);
        }
        if f_zeroes && zeroes_may_unmap && max_zeroes_sectors > 0 && max_zeroes_seg > 0 {
            u.zeroes = true;
            u.max_zeroes_sectors = max_zeroes_sectors.min(UNMAP_MAX_SECTORS);
            u.max_zeroes_ranges = max_zeroes_seg.min(UNMAP_MAX_RANGES);
            // Alignment of a zeroing range follows the discard alignment
            // when there is one; otherwise one sector.
            u.discard_align = u.discard_align.max(1);
        }
        u
    }

    /// From SCSI, for a 512-byte-block disk: READ CAPACITY (16) data
    /// (`LBPME` is bit 7 of byte 14), the Block Limits page B0h and the
    /// Logical Block Provisioning page B2h (`LBPU` bit 7 and `LBPWS` bit 6
    /// of byte 5). Any of them may be missing: then nothing is offered.
    pub fn from_scsi(cap16: Option<&[u8]>, b0: Option<&[u8]>, b2: Option<&[u8]>) -> Self {
        let mut u = Self::default();
        let lbpme = cap16.and_then(|c| c.get(14)).is_some_and(|b| b & 0x80 != 0);
        let b2 = b2.filter(|b| b.get(1) == Some(&0xb2));
        let b0 = b0.filter(|b| b.get(1) == Some(&0xb0) && b.len() >= 44);
        let (Some(b0), true) = (b0, lbpme) else {
            return u;
        };
        let be32 = |at: usize| {
            b0.get(at..at + 4)
                .and_then(|x| x.try_into().ok())
                .map_or(0, u32::from_be_bytes)
        };
        let lbpu = b2.and_then(|b| b.get(5)).is_some_and(|b| b & 0x80 != 0);
        let lbpws = b2.and_then(|b| b.get(5)).is_some_and(|b| b & 0x40 != 0);
        // Maximum unmap LBA count, maximum unmap block descriptor count,
        // optimal unmap granularity, unmap granularity alignment (bit 31:
        // valid). 0 means unsupported, 0xffff_ffff no limit.
        let (lba_count, descs) = (be32(20), be32(24));
        let gran = be32(28).max(1);
        if lbpu && lba_count > 0 && descs > 0 {
            u.discard = true;
            u.max_discard_sectors = lba_count.min(UNMAP_MAX_SECTORS);
            u.max_discard_ranges = descs.min(UNMAP_MAX_RANGES);
            u.discard_align = gran.clamp(1, UNMAP_MAX_ALIGN);
        }
        // WRITE SAME (16) with UNMAP, one range per command; the maximum
        // write same length (0: no limit besides the command's 32 bits).
        let ws = b0
            .get(36..44)
            .and_then(|x| x.try_into().ok())
            .map_or(0, u64::from_be_bytes);
        if lbpws {
            u.zeroes = true;
            u.max_zeroes_sectors = if ws == 0 {
                UNMAP_MAX_SECTORS
            } else {
                ws.min(u64::from(UNMAP_MAX_SECTORS)) as u32
            };
            u.max_zeroes_ranges = 1;
            u.discard_align = u.discard_align.max(1);
        }
        u
    }
}

/// Polls `q` until a completion arrives or `timeout_ns` passes.
pub fn wait_used<E: Env>(
    env: &E,
    q: &mut SplitQueue,
    timeout_ns: u64,
    what: &'static str,
) -> Result<(u16, u32), VirtioError> {
    let deadline = env.now_ns().saturating_add(timeout_ns);
    loop {
        if let Some(done) = q.pop_used()? {
            return Ok(done);
        }
        if env.now_ns() > deadline {
            return Err(VirtioError::Timeout(what));
        }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_from_virtio_blk() {
        // 512e: 4 KiB physical, 512 logical, optimal I/O 64 KiB.
        let t = BlockTopology::from_blk(512, 3, 0, 8, 128);
        assert_eq!((t.logical, t.physical), (512, 4096));
        assert_eq!((t.min_io, t.opt_io, t.align_offset), (4096, 65536, 0));
        // 4Kn: logical 4096, one block per physical block.
        let t = BlockTopology::from_blk(4096, 0, 0, 1, 0);
        assert_eq!((t.logical, t.physical, t.min_io), (4096, 4096, 4096));
        // An absurd exponent, a tiny blk_size and overflow are tamed.
        let t = BlockTopology::from_blk(0, 200, 255, u16::MAX, u32::MAX);
        assert_eq!((t.logical, t.physical), (512, 512));
        assert!(t.opt_io <= 1 << 30 && t.align_offset <= 255 * 512);
    }

    #[test]
    fn unmap_limits_from_blk() {
        let u = UnmapLimits::from_blk(true, true, [1 << 20, 4, 8, 1 << 20, 4], true);
        assert!(u.discard && u.zeroes);
        assert_eq!(
            (u.max_discard_sectors, u.max_discard_ranges, u.discard_align),
            (1 << 20, 4, 8)
        );
        // Neither feature: nothing offered, whatever the config says.
        assert_eq!(
            UnmapLimits::from_blk(false, false, [9; 5], true),
            UnmapLimits::default()
        );
        // Zero limits mean unusable; zeroing needs may_unmap.
        let u = UnmapLimits::from_blk(true, true, [0, 1, 1, 100, 1], false);
        assert!(!u.discard && !u.zeroes);
        // Hostile numbers are tamed.
        let u = UnmapLimits::from_blk(true, false, [u32::MAX; 5], false);
        assert_eq!(u.max_discard_ranges, 256);
        assert_eq!(u.discard_align, 1 << 21);
        assert_eq!(u.max_discard_sectors, 1 << 31);
        // Alignment 0 is one sector.
        assert_eq!(
            UnmapLimits::from_blk(true, false, [8, 1, 0, 0, 0], false).discard_align,
            1
        );
    }

    #[test]
    fn unmap_limits_from_scsi_pages() {
        let mut cap = [0u8; 32];
        cap[14] = 0x80; // LBPME
        let mut b0 = [0u8; 64];
        b0[1] = 0xb0;
        b0[20..24].copy_from_slice(&0x10000u32.to_be_bytes());
        b0[24..28].copy_from_slice(&32u32.to_be_bytes());
        b0[28..32].copy_from_slice(&8u32.to_be_bytes());
        b0[36..44].copy_from_slice(&0x8000u64.to_be_bytes());
        let mut b2 = [0u8; 8];
        b2[1] = 0xb2;
        b2[5] = 0xc0; // LBPU and LBPWS
        let u = UnmapLimits::from_scsi(Some(&cap), Some(&b0), Some(&b2));
        assert!(u.discard && u.zeroes);
        assert_eq!(
            (u.max_discard_sectors, u.max_discard_ranges, u.discard_align),
            (0x10000, 32, 8)
        );
        assert_eq!((u.max_zeroes_sectors, u.max_zeroes_ranges), (0x8000, 1));
        // No LBPME or a missing page: nothing.
        cap[14] = 0;
        assert_eq!(
            UnmapLimits::from_scsi(Some(&cap), Some(&b0), Some(&b2)),
            UnmapLimits::default()
        );
        cap[14] = 0x80;
        assert_eq!(
            UnmapLimits::from_scsi(Some(&cap), None, Some(&b2)),
            UnmapLimits::default()
        );
        // LBPU only: discard but no zeroing.
        b2[5] = 0x80;
        let u = UnmapLimits::from_scsi(Some(&cap), Some(&b0), Some(&b2));
        assert!(u.discard && !u.zeroes);
        // A page with the wrong code is ignored.
        b2[1] = 0xb1;
        assert!(!UnmapLimits::from_scsi(Some(&cap), Some(&b0), Some(&b2)).discard);
    }

    #[test]
    fn topology_from_scsi_pages() {
        let mut cap = [0u8; 32];
        cap[13] = 3; // 8 logical blocks per physical block
        let mut b0 = [0u8; 64];
        b0[1] = 0xb0;
        b0[6..8].copy_from_slice(&8u16.to_be_bytes());
        b0[12..16].copy_from_slice(&2048u32.to_be_bytes());
        let t = BlockTopology::from_scsi(512, Some(&cap), Some(&b0));
        assert_eq!((t.physical, t.min_io, t.opt_io), (4096, 4096, 1 << 20));
        // Neither page: a plain 512-byte disk.
        assert_eq!(
            BlockTopology::from_scsi(512, None, None),
            BlockTopology::default()
        );
        // A wrong page code is ignored.
        b0[1] = 0xb1;
        assert_eq!(BlockTopology::from_scsi(512, None, Some(&b0)).opt_io, 0);
    }

    #[test]
    fn device_types() {
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1041, 0),
            Some(DeviceType::Net)
        );
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1001, 2),
            Some(DeviceType::Block)
        );
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1005, 4),
            Some(DeviceType::Entropy)
        );
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1044, 0),
            Some(DeviceType::Entropy)
        );
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1048, 0),
            Some(DeviceType::Scsi)
        );
        assert_eq!(
            DeviceType::from_pci(VENDOR, 0x1049, 0),
            Some(DeviceType::Other(9))
        );
        assert_eq!(DeviceType::from_pci(0x8086, 0x1041, 0), None);
        assert_eq!(DeviceType::from_pci(VENDOR, 0x2000, 0), None);
    }
}
