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
