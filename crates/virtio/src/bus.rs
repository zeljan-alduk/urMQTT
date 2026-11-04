//! What a driver of the newer device family needs from the transport
//! (ADR-257): the virtio-pci [`Transport`] in the kernel, a fake device in
//! the host tests ([`crate::fake`]). The drivers of the console, balloon,
//! input and vsock devices are generic over it, so every byte they read from
//! the device can come from a test.

use crate::queue::SplitQueue;
use crate::transport::Transport;
use crate::{Env, VirtioError};

pub trait Bus {
    /// Reset and feature negotiation (virtio 1.x §3.1.1, steps 1-6).
    fn init<E: Env>(&self, env: &E, wanted: u64, required: u64) -> Result<u64, VirtioError>;
    /// Largest size the device supports for queue `idx` (0: unavailable).
    fn queue_max(&self, idx: u16) -> u16;
    /// Programs and enables queue `idx`; returns its notification offset.
    fn setup_queue(
        &self,
        idx: u16,
        q: &SplitQueue,
        msix: Option<u16>,
    ) -> Result<usize, VirtioError>;
    fn driver_ok(&self) -> Result<(), VirtioError>;
    /// Kicks queue `idx` at notification offset `off`.
    fn notify(&self, off: usize, idx: u16);
    /// The configuration generation (§4.1.4.5).
    fn config_generation(&self) -> u8;
    /// Device-specific configuration, bounds-checked (0 outside it).
    fn cfg_read8(&self, off: usize) -> u8;
    fn cfg_read16(&self, off: usize) -> u16;
    fn cfg_read32(&self, off: usize) -> u32;
    fn cfg_write8(&self, off: usize, v: u8);
    fn cfg_write32(&self, off: usize, v: u32);
}

impl Bus for Transport {
    fn init<E: Env>(&self, env: &E, wanted: u64, required: u64) -> Result<u64, VirtioError> {
        Transport::init(self, env, wanted, required)
    }
    fn queue_max(&self, idx: u16) -> u16 {
        Transport::queue_max(self, idx)
    }
    fn setup_queue(
        &self,
        idx: u16,
        q: &SplitQueue,
        msix: Option<u16>,
    ) -> Result<usize, VirtioError> {
        Transport::setup_queue(self, idx, q, msix)
    }
    fn driver_ok(&self) -> Result<(), VirtioError> {
        Transport::driver_ok(self)
    }
    fn notify(&self, off: usize, idx: u16) {
        Transport::notify(self, off, idx);
    }
    fn config_generation(&self) -> u8 {
        Transport::config_generation(self)
    }
    fn cfg_read8(&self, off: usize) -> u8 {
        self.device.read8(off)
    }
    fn cfg_read16(&self, off: usize) -> u16 {
        self.device.read16(off)
    }
    fn cfg_read32(&self, off: usize) -> u32 {
        self.device.read32(off)
    }
    fn cfg_write8(&self, off: usize, v: u8) {
        self.device.write8(off, v);
    }
    fn cfg_write32(&self, off: usize, v: u32) {
        self.device.write32(off, v);
    }
}

/// A borrowed bus is a bus (the tests keep the fake device to play it).
impl<T: Bus> Bus for &T {
    fn init<E: Env>(&self, env: &E, wanted: u64, required: u64) -> Result<u64, VirtioError> {
        (**self).init(env, wanted, required)
    }
    fn queue_max(&self, idx: u16) -> u16 {
        (**self).queue_max(idx)
    }
    fn setup_queue(
        &self,
        idx: u16,
        q: &SplitQueue,
        msix: Option<u16>,
    ) -> Result<usize, VirtioError> {
        (**self).setup_queue(idx, q, msix)
    }
    fn driver_ok(&self) -> Result<(), VirtioError> {
        (**self).driver_ok()
    }
    fn notify(&self, off: usize, idx: u16) {
        (**self).notify(off, idx);
    }
    fn config_generation(&self) -> u8 {
        (**self).config_generation()
    }
    fn cfg_read8(&self, off: usize) -> u8 {
        (**self).cfg_read8(off)
    }
    fn cfg_read16(&self, off: usize) -> u16 {
        (**self).cfg_read16(off)
    }
    fn cfg_read32(&self, off: usize) -> u32 {
        (**self).cfg_read32(off)
    }
    fn cfg_write8(&self, off: usize, v: u8) {
        (**self).cfg_write8(off, v);
    }
    fn cfg_write32(&self, off: usize, v: u32) {
        (**self).cfg_write32(off, v);
    }
}

/// Reads a multi-field configuration consistently: retried while the
/// generation changes, at most 8 times (a device that never settles gets the
/// last read).
pub fn cfg_consistent<B: Bus, T>(bus: &B, mut read: impl FnMut(&B) -> T) -> T {
    let mut v = read(bus);
    for _ in 0..8 {
        let before = bus.config_generation();
        v = read(bus);
        if bus.config_generation() == before {
            break;
        }
    }
    v
}

/// A queue of `want` entries (capped by what the device offers, rounded
/// down to a power of two), in fresh DMA memory, programmed into the device.
/// Returns the queue and its notification offset.
pub fn make_queue<B: Bus, E: Env>(
    bus: &B,
    env: &E,
    idx: u16,
    want: u16,
) -> Result<(SplitQueue, usize), VirtioError> {
    let max = bus.queue_max(idx);
    if max == 0 {
        return Err(VirtioError::QueueUnavailable(idx));
    }
    let n = want.min(max).min(crate::queue::MAX_QUEUE);
    // Largest power of two not above `n` (a device may offer any size).
    let size = 1u16 << (15 - n.leading_zeros().min(15));
    let mem = env
        .dma_alloc(crate::queue::Layout::new(size).total)
        .ok_or(VirtioError::NoDma)?;
    // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
    #[allow(unsafe_code)]
    let q = unsafe { SplitQueue::new(mem, size) }?;
    let off = bus.setup_queue(idx, &q, None)?;
    Ok((q, off))
}

/// Copies `out.len()` bytes at `off` of DMA memory `r` into `out`; `false`
/// (nothing copied) if the range is outside it.
pub fn dma_read(r: &crate::DmaRegion, off: usize, out: &mut [u8]) -> bool {
    if off.checked_add(out.len()).is_none_or(|end| end > r.len) {
        return false;
    }
    // SAFETY: inside the DMA region, which the driver owns for its lifetime;
    // the device may write it concurrently only while the buffer is posted,
    // and callers read a buffer only after the device returned it.
    #[allow(unsafe_code)]
    let src = unsafe { core::slice::from_raw_parts((r.va + off) as *const u8, out.len()) };
    out.copy_from_slice(src);
    true
}

/// Copies `data` to `off` of DMA memory `r`; `false` (nothing written) if
/// the range is outside it.
pub fn dma_write(r: &crate::DmaRegion, off: usize, data: &[u8]) -> bool {
    if off.checked_add(data.len()).is_none_or(|end| end > r.len) {
        return false;
    }
    // SAFETY: as in `dma_read`; callers write a buffer only while it is not
    // posted to the device.
    #[allow(unsafe_code)]
    let dst = unsafe { core::slice::from_raw_parts_mut((r.va + off) as *mut u8, data.len()) };
    dst.copy_from_slice(data);
    true
}

/// Bytes received from a device and not yet read: a fixed ring that drops
/// what does not fit (counted), so a device that floods cannot grow memory.
#[derive(Debug, Clone)]
pub struct ByteRing {
    buf: [u8; BYTE_RING],
    head: usize,
    len: usize,
    pub dropped: u64,
}

pub const BYTE_RING: usize = 256;

impl Default for ByteRing {
    fn default() -> Self {
        Self {
            buf: [0; BYTE_RING],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }
}

impl ByteRing {
    pub fn push(&mut self, b: u8) {
        if self.len == BYTE_RING {
            self.dropped += 1;
            return;
        }
        if let Some(slot) = self.buf.get_mut((self.head + self.len) % BYTE_RING) {
            *slot = b;
        }
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let b = self.buf.get(self.head).copied();
        self.head = (self.head + 1) % BYTE_RING;
        self.len -= 1;
        b
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_byte_ring_keeps_order_and_drops_what_does_not_fit() {
        let mut r = ByteRing::default();
        for i in 0..300u32 {
            r.push(i as u8);
        }
        assert_eq!((r.len(), r.dropped), (BYTE_RING, 44));
        for i in 0..BYTE_RING as u32 {
            assert_eq!(r.pop(), Some(i as u8));
        }
        assert!(r.is_empty() && r.pop().is_none());
    }

    #[test]
    fn dma_copies_are_bounds_checked() {
        let mut mem = [0u8; 16];
        let r = crate::DmaRegion {
            va: mem.as_mut_ptr() as usize,
            pa: 0,
            len: 16,
        };
        assert!(dma_write(&r, 12, &[1, 2, 3, 4]));
        assert!(!dma_write(&r, 13, &[1, 2, 3, 4]));
        assert!(!dma_write(&r, usize::MAX, &[1]));
        let mut out = [0u8; 4];
        assert!(dma_read(&r, 12, &mut out));
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(!dma_read(&r, 14, &mut out));
    }

    #[test]
    fn queues_are_a_power_of_two_the_device_allows() {
        let env = crate::fake::FakeEnv::default();
        let bus = crate::fake::FakeBus::new(0, &[6, 0, 256], 0);
        assert_eq!(make_queue(&bus, &env, 0, 8).unwrap().0.size(), 4);
        assert_eq!(
            make_queue(&bus, &env, 1, 8).err(),
            Some(VirtioError::QueueUnavailable(1))
        );
        assert_eq!(make_queue(&bus, &env, 2, 16).unwrap().0.size(), 16);
        assert_eq!(
            make_queue(&bus, &env, 3, 16).err(),
            Some(VirtioError::QueueUnavailable(3))
        );
    }
}
