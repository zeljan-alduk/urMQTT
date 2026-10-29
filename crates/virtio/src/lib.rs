//! virtio-pci modern transport, split virtqueues and the net, blk and rng
//! devices (virtio 1.x).
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
pub mod transport;

pub use queue::{Buf, DmaRegion, QueueError, SplitQueue};
pub use transport::{Region, Transport, VirtioCaps, find_caps};

pub const VENDOR: u16 = 0x1af4;
pub const F_VERSION_1: u64 = 1 << 32;

/// Device types (virtio 1.x §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Net,
    Block,
    Entropy,
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
            Some(DeviceType::Other(8))
        );
        assert_eq!(DeviceType::from_pci(0x8086, 0x1041, 0), None);
        assert_eq!(DeviceType::from_pci(VENDOR, 0x2000, 0), None);
    }
}
