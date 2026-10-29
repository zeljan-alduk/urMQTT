//! virtio-pci modern transport (virtio 1.x §4.1): capability discovery,
//! feature negotiation, queue setup and notification.

#![allow(unsafe_code)]

use urmqtt_pci::{Bdf, CAP_VENDOR, ConfigSpace, capabilities};

use crate::queue::SplitQueue;
use crate::{Env, VirtioError};

pub const CAP_COMMON: u8 = 1;
pub const CAP_NOTIFY: u8 = 2;
pub const CAP_ISR: u8 = 3;
pub const CAP_DEVICE: u8 = 4;

/// Where one capability's structure lives: BAR index, offset, length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapLoc {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioCaps {
    pub common: Option<CapLoc>,
    pub notify: Option<CapLoc>,
    pub notify_multiplier: u32,
    pub isr: Option<CapLoc>,
    pub device: Option<CapLoc>,
}

/// Collects the virtio vendor capabilities of a function. The first
/// capability of each type wins (virtio 1.x §4.1.4).
pub fn find_caps<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> VirtioCaps {
    let mut caps = VirtioCaps::default();
    for (off, id) in capabilities(cfg, bdf) {
        if id != CAP_VENDOR {
            continue;
        }
        let cfg_type = cfg.read8(bdf, off + 3);
        let loc = CapLoc {
            bar: cfg.read8(bdf, off + 4),
            offset: cfg.read32(bdf, off + 8),
            length: cfg.read32(bdf, off + 12),
        };
        if loc.bar > 5 {
            continue;
        }
        match cfg_type {
            CAP_COMMON if caps.common.is_none() => caps.common = Some(loc),
            CAP_NOTIFY if caps.notify.is_none() => {
                caps.notify = Some(loc);
                caps.notify_multiplier = cfg.read32(bdf, off + 16);
            }
            CAP_ISR if caps.isr.is_none() => caps.isr = Some(loc),
            CAP_DEVICE if caps.device.is_none() => caps.device = Some(loc),
            _ => {}
        }
    }
    caps
}

/// A mapped MMIO window with bounds-checked volatile access.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    va: usize,
    len: usize,
}

impl Region {
    /// # Safety
    /// `[va, va + len)` must be mapped device memory for the region's
    /// lifetime.
    pub const unsafe fn new(va: usize, len: usize) -> Self {
        Self { va, len }
    }

    fn ok(&self, off: usize, size: usize) -> bool {
        off.checked_add(size).is_some_and(|end| end <= self.len)
    }

    pub fn read8(&self, off: usize) -> u8 {
        if !self.ok(off, 1) {
            return 0;
        }
        // SAFETY: bounds checked against the mapped window.
        unsafe { ((self.va + off) as *const u8).read_volatile() }
    }

    pub fn read16(&self, off: usize) -> u16 {
        if !self.ok(off, 2) {
            return 0;
        }
        // SAFETY: as in `read8`.
        unsafe { ((self.va + off) as *const u16).read_volatile() }
    }

    pub fn read32(&self, off: usize) -> u32 {
        if !self.ok(off, 4) {
            return 0;
        }
        // SAFETY: as in `read8`.
        unsafe { ((self.va + off) as *const u32).read_volatile() }
    }

    pub fn write8(&self, off: usize, v: u8) {
        if self.ok(off, 1) {
            // SAFETY: as in `read8`.
            unsafe { ((self.va + off) as *mut u8).write_volatile(v) }
        }
    }

    pub fn write16(&self, off: usize, v: u16) {
        if self.ok(off, 2) {
            // SAFETY: as in `read8`.
            unsafe { ((self.va + off) as *mut u16).write_volatile(v) }
        }
    }

    pub fn write32(&self, off: usize, v: u32) {
        if self.ok(off, 4) {
            // SAFETY: as in `read8`.
            unsafe { ((self.va + off) as *mut u32).write_volatile(v) }
        }
    }

    /// 64-bit fields of the common configuration are written as two halves
    /// (virtio 1.x §4.1.3.1: drivers may use 32-bit accesses).
    pub fn write64(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off + 4, (v >> 32) as u32);
    }
}

// Common configuration structure offsets.
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0c;
const CONFIG_MSIX_VECTOR: usize = 0x10;
const NUM_QUEUES: usize = 0x12;
const DEVICE_STATUS: usize = 0x14;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_MSIX_VECTOR: usize = 0x1a;
const QUEUE_ENABLE: usize = 0x1c;
const QUEUE_NOTIFY_OFF: usize = 0x1e;
const QUEUE_DESC: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

pub const NO_VECTOR: u16 = 0xffff;
const RESET_TIMEOUT_NS: u64 = 1_000_000_000;

/// The three regions every device needs plus its device-specific config.
pub struct Transport {
    pub common: Region,
    pub notify: Region,
    pub notify_multiplier: u32,
    pub device: Region,
}

/// Picks the features to accept: `required` must all be offered.
pub fn negotiate_features(offered: u64, wanted: u64, required: u64) -> Result<u64, VirtioError> {
    if offered & required != required {
        return Err(VirtioError::MissingFeatures(required & !offered));
    }
    Ok(offered & (wanted | required))
}

impl Transport {
    fn status(&self) -> u8 {
        self.common.read8(DEVICE_STATUS)
    }

    fn add_status(&self, bits: u8) {
        self.common.write8(DEVICE_STATUS, self.status() | bits);
    }

    /// Resets the device and negotiates features (virtio 1.x §3.1.1, steps
    /// 1–6). Returns the accepted feature set.
    pub fn init<E: Env>(&self, env: &E, wanted: u64, required: u64) -> Result<u64, VirtioError> {
        self.common.write8(DEVICE_STATUS, 0);
        let deadline = env.now_ns() + RESET_TIMEOUT_NS;
        while self.status() != 0 {
            if env.now_ns() > deadline {
                return Err(VirtioError::Timeout("reset"));
            }
            core::hint::spin_loop();
        }
        self.add_status(STATUS_ACKNOWLEDGE);
        self.add_status(STATUS_DRIVER);
        let mut offered = 0u64;
        for half in 0..2u32 {
            self.common.write32(DEVICE_FEATURE_SELECT, half);
            offered |= u64::from(self.common.read32(DEVICE_FEATURE)) << (32 * half);
        }
        let accepted = match negotiate_features(offered, wanted, required) {
            Ok(f) => f,
            Err(e) => {
                self.add_status(STATUS_FAILED);
                return Err(e);
            }
        };
        for half in 0..2u32 {
            self.common.write32(DRIVER_FEATURE_SELECT, half);
            self.common
                .write32(DRIVER_FEATURE, (accepted >> (32 * half)) as u32);
        }
        self.add_status(STATUS_FEATURES_OK);
        if self.status() & STATUS_FEATURES_OK == 0 {
            self.add_status(STATUS_FAILED);
            return Err(VirtioError::FeaturesRejected);
        }
        self.common.write16(CONFIG_MSIX_VECTOR, NO_VECTOR);
        Ok(accepted)
    }

    pub fn num_queues(&self) -> u16 {
        self.common.read16(NUM_QUEUES)
    }

    /// Largest size the device supports for queue `idx` (0 = unavailable).
    pub fn queue_max(&self, idx: u16) -> u16 {
        self.common.write16(QUEUE_SELECT, idx);
        self.common.read16(QUEUE_SIZE)
    }

    /// Programs and enables queue `idx`; returns its notification offset.
    pub fn setup_queue(
        &self,
        idx: u16,
        q: &SplitQueue,
        msix: Option<u16>,
    ) -> Result<usize, VirtioError> {
        self.common.write16(QUEUE_SELECT, idx);
        if self.common.read16(QUEUE_SIZE) == 0 {
            return Err(VirtioError::QueueUnavailable(idx));
        }
        self.common.write16(QUEUE_SIZE, q.size());
        let (desc, driver, device) = q.addresses();
        self.common.write64(QUEUE_DESC, desc);
        self.common.write64(QUEUE_DRIVER, driver);
        self.common.write64(QUEUE_DEVICE, device);
        self.common
            .write16(QUEUE_MSIX_VECTOR, msix.unwrap_or(NO_VECTOR));
        if msix.is_some() && self.common.read16(QUEUE_MSIX_VECTOR) == NO_VECTOR {
            return Err(VirtioError::MsixRejected);
        }
        let off =
            usize::from(self.common.read16(QUEUE_NOTIFY_OFF)) * self.notify_multiplier as usize;
        self.common.write16(QUEUE_ENABLE, 1);
        Ok(off)
    }

    pub fn driver_ok(&self) -> Result<(), VirtioError> {
        self.add_status(STATUS_DRIVER_OK);
        if self.status() & (STATUS_NEEDS_RESET | STATUS_FAILED) != 0 {
            return Err(VirtioError::DeviceFailed(self.status()));
        }
        Ok(())
    }

    /// Kicks queue `idx` at notification offset `off`.
    pub fn notify(&self, off: usize, idx: u16) {
        // Ring updates (normal memory) must be visible before the device
        // sees the doorbell (device memory).
        #[cfg(target_os = "none")]
        // SAFETY: a barrier has no other effect.
        unsafe {
            core::arch::asm!("dsb st", options(nostack, preserves_flags))
        };
        #[cfg(not(target_os = "none"))]
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.notify.write16(off, idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{F_VERSION_1, VirtioError};

    #[test]
    fn feature_negotiation() {
        let offered = F_VERSION_1 | (1 << 5) | (1 << 9) | (1 << 28);
        assert_eq!(
            negotiate_features(offered, (1 << 5) | (1 << 7), F_VERSION_1),
            Ok(F_VERSION_1 | (1 << 5))
        );
        assert_eq!(
            negotiate_features(1 << 5, 0, F_VERSION_1),
            Err(VirtioError::MissingFeatures(F_VERSION_1))
        );
    }

    #[test]
    fn region_bounds() {
        let mut mem = [0u32; 4];
        // SAFETY: `mem` is 16 bytes, owned by the test, outlives `r`.
        let r = unsafe { Region::new(mem.as_mut_ptr() as usize, 16) };
        r.write32(12, 0xdead_beef);
        assert_eq!(r.read32(12), 0xdead_beef);
        r.write32(14, 1); // straddles the end: ignored
        assert_eq!(r.read32(16), 0);
        r.write64(0, 0x1122_3344_5566_7788);
        assert_eq!((r.read32(0), r.read32(4)), (0x5566_7788, 0x1122_3344));
        assert_eq!(mem[3], 0xdead_beef);
    }
}
