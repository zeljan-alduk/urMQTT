//! A fake virtio device for the host tests of the [`Bus`] drivers
//! (ADR-257): an in-memory device configuration, the queue addresses the
//! driver programs, and a device side that pops the driver's buffers and
//! completes them, as a hypervisor would, including hostile answers.
//!
//! DMA memory is host memory whose "physical" address is its address, so
//! the device side reads and writes the driver's buffers directly.

#![allow(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::multiple_unsafe_ops_per_block
)]

use std::boxed::Box;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec::Vec;

use crate::bus::{Bus, Kick};
use crate::queue::{DESC_F_NEXT, DESC_F_WRITE, Layout, SplitQueue};
use crate::{DmaRegion, Env, VirtioError};

/// Host memory as DMA memory (freed with the environment, which must
/// outlive the driver); a clock that advances on every reading.
#[derive(Default)]
pub struct FakeEnv {
    pub now: Cell<u64>,
    /// Refuse allocations after this many (None: never).
    pub dma_budget: Cell<Option<usize>>,
    /// What the last negotiation said about VIRTIO_F_ACCESS_PLATFORM.
    pub platform: Cell<Option<bool>>,
    mem: RefCell<Vec<Vec<u64>>>,
}

impl Env for FakeEnv {
    fn dma_alloc(&self, bytes: usize) -> Option<DmaRegion> {
        if let Some(n) = self.dma_budget.get() {
            if n == 0 {
                return None;
            }
            self.dma_budget.set(Some(n - 1));
        }
        let words = bytes.div_ceil(8).max(1);
        let mut buf = vec![0u64; words];
        // The heap buffer does not move when the outer list grows.
        let va = buf.as_mut_ptr() as usize;
        self.mem.borrow_mut().push(buf);
        Some(DmaRegion {
            va,
            pa: va as u64,
            len: words * 8,
        })
    }

    fn platform_access(&self, offered: bool) {
        self.platform.set(Some(offered));
    }

    fn now_ns(&self) -> u64 {
        let t = self.now.get() + 1_000;
        self.now.set(t);
        t
    }
}

/// What the driver programmed for one queue, and the device's cursor.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueState {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    pub size: u16,
    pub last_avail: u16,
    pub used_idx: u16,
    pub enabled: bool,
}

/// One buffer of a chain the device popped: address, length, device writes.
pub type Seg = (u64, u32, bool);

pub struct FakeBus {
    /// Offered feature bits.
    pub offered: u64,
    pub accepted: Cell<u64>,
    /// Refuse FEATURES_OK.
    pub reject_features: bool,
    /// Largest size per queue (0: absent).
    pub queue_max: Vec<u16>,
    pub queues: RefCell<Vec<QueueState>>,
    pub cfg: RefCell<Vec<u8>>,
    pub generation: Cell<u8>,
    /// Queues kicked, in order (shared with the doorbells queues take away).
    pub notified: Rc<RefCell<Vec<u16>>>,
    pub driver_ok: Cell<bool>,
    /// Plays the device when the driver kicks a queue through the bus (a
    /// control queue that the driver waits on): called with the queue.
    #[allow(clippy::type_complexity)]
    pub responder: RefCell<Option<Box<dyn FnMut(&FakeBus, u16)>>>,
}

/// The doorbell of a queue that left the driver: records the kicks.
#[derive(Clone)]
pub struct FakeKick(Rc<RefCell<Vec<u16>>>);

impl Kick for FakeKick {
    fn kick(&self, _off: usize, idx: u16) {
        self.0.borrow_mut().push(idx);
    }
}

impl FakeBus {
    pub fn new(offered: u64, queue_max: &[u16], cfg_len: usize) -> Self {
        Self {
            offered,
            accepted: Cell::new(0),
            reject_features: false,
            queue_max: queue_max.to_vec(),
            queues: RefCell::new(vec![QueueState::default(); queue_max.len()]),
            cfg: RefCell::new(vec![0; cfg_len]),
            generation: Cell::new(0),
            notified: Rc::new(RefCell::new(Vec::new())),
            driver_ok: Cell::new(false),
            responder: RefCell::new(None),
        }
    }

    pub fn set_cfg(&self, off: usize, bytes: &[u8]) {
        self.cfg.borrow_mut()[off..off + bytes.len()].copy_from_slice(bytes);
        self.generation.set(self.generation.get().wrapping_add(1));
    }

    fn rd16(addr: u64) -> u16 {
        // SAFETY: `addr` is inside ring memory the driver programmed (host memory, pa == va, owned by the FakeEnv).
        unsafe { (addr as *const u16).read_volatile() }
    }

    /// Pops the next chain the driver made available on queue `q`.
    pub fn pop(&self, q: u16) -> Option<(u16, Vec<Seg>)> {
        let mut qs = self.queues.borrow_mut();
        let s = &mut qs[usize::from(q)];
        if !s.enabled || Self::rd16(s.avail + 2) == s.last_avail {
            return None;
        }
        let head = Self::rd16(s.avail + 4 + 2 * u64::from(s.last_avail % s.size));
        s.last_avail = s.last_avail.wrapping_add(1);
        let mut segs = Vec::new();
        let mut i = head;
        for _ in 0..s.size {
            let d = s.desc + 16 * u64::from(i);
            // SAFETY: descriptor `i < size` of the table the driver programmed (FakeEnv memory).
            let (pa, len, flags, next) = unsafe {
                (
                    (d as *const u64).read(),
                    ((d + 8) as *const u32).read(),
                    ((d + 12) as *const u16).read(),
                    ((d + 14) as *const u16).read(),
                )
            };
            segs.push((pa, len, flags & DESC_F_WRITE != 0));
            if flags & DESC_F_NEXT == 0 {
                break;
            }
            i = next;
        }
        Some((head, segs))
    }

    /// Completes chain `head` on queue `q` with `len` bytes written.
    pub fn complete(&self, q: u16, head: u32, len: u32) {
        let mut qs = self.queues.borrow_mut();
        let s = &mut qs[usize::from(q)];
        if !s.enabled {
            return;
        }
        let e = s.used + 4 + 8 * u64::from(s.used_idx % s.size);
        // SAFETY: used-ring element `used_idx % size` of the ring the driver programmed.
        unsafe {
            (e as *mut u32).write(head);
            ((e + 4) as *mut u32).write(len);
        }
        s.used_idx = s.used_idx.wrapping_add(1);
        // SAFETY: the used ring's index field, inside the ring the driver programmed.
        unsafe { ((s.used + 2) as *mut u16).write_volatile(s.used_idx) };
    }

    /// Writes `data` into the buffers of a chain (device-writable ones),
    /// returning the bytes written.
    pub fn fill(segs: &[Seg], data: &[u8]) -> u32 {
        let mut at = 0usize;
        for &(pa, len, w) in segs {
            if !w {
                continue;
            }
            let n = (len as usize).min(data.len() - at);
            // SAFETY: `n <= len`, a device-writable buffer the driver posted (FakeEnv memory, pa == va).
            unsafe { core::ptr::copy_nonoverlapping(data[at..].as_ptr(), pa as *mut u8, n) };
            at += n;
            if at == data.len() {
                break;
            }
        }
        at as u32
    }

    /// The bytes of the driver-readable buffers of a chain.
    pub fn read(segs: &[Seg]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(pa, len, w) in segs {
            if w {
                continue;
            }
            // SAFETY: a driver-readable buffer of `len` bytes the driver posted (FakeEnv memory, pa == va).
            let s = unsafe { core::slice::from_raw_parts(pa as *const u8, len as usize) };
            out.extend_from_slice(s);
        }
        out
    }
}

impl Bus for FakeBus {
    type Kick = FakeKick;
    fn kicker(&self) -> FakeKick {
        FakeKick(Rc::clone(&self.notified))
    }
    fn init<E: Env>(&self, env: &E, wanted: u64, required: u64) -> Result<u64, VirtioError> {
        // As `Transport::init` does (ADR-305).
        env.platform_access(self.offered & crate::F_ACCESS_PLATFORM != 0);
        let f = crate::transport::negotiate_features(
            self.offered,
            wanted | crate::F_ACCESS_PLATFORM,
            required,
        )?;
        if self.reject_features {
            return Err(VirtioError::FeaturesRejected);
        }
        self.accepted.set(f);
        Ok(f)
    }

    fn queue_max(&self, idx: u16) -> u16 {
        self.queue_max.get(usize::from(idx)).copied().unwrap_or(0)
    }

    fn setup_queue(
        &self,
        idx: u16,
        q: &SplitQueue,
        _msix: Option<u16>,
    ) -> Result<usize, VirtioError> {
        if self.queue_max(idx) == 0 || q.size() > self.queue_max(idx) {
            return Err(VirtioError::QueueUnavailable(idx));
        }
        let (desc, avail, used) = q.addresses();
        assert_eq!(used - desc, Layout::new(q.size()).used as u64);
        self.queues.borrow_mut()[usize::from(idx)] = QueueState {
            desc,
            avail,
            used,
            size: q.size(),
            last_avail: 0,
            used_idx: 0,
            enabled: true,
        };
        Ok(usize::from(idx) * 4)
    }

    fn driver_ok(&self) -> Result<(), VirtioError> {
        self.driver_ok.set(true);
        Ok(())
    }

    fn notify(&self, _off: usize, idx: u16) {
        self.notified.borrow_mut().push(idx);
        // The responder may complete buffers (it borrows the queues), so it
        // is taken out while it runs.
        let r = self.responder.borrow_mut().take();
        if let Some(mut r) = r {
            r(self, idx);
            *self.responder.borrow_mut() = Some(r);
        }
    }

    fn config_generation(&self) -> u8 {
        self.generation.get()
    }

    fn cfg_read8(&self, off: usize) -> u8 {
        self.cfg.borrow().get(off).copied().unwrap_or(0)
    }

    fn cfg_read16(&self, off: usize) -> u16 {
        let c = self.cfg.borrow();
        match c.get(off..off + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    fn cfg_read32(&self, off: usize) -> u32 {
        let c = self.cfg.borrow();
        match c.get(off..off + 4) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }

    fn cfg_write8(&self, off: usize, v: u8) {
        if let Some(b) = self.cfg.borrow_mut().get_mut(off) {
            *b = v;
        }
    }

    fn cfg_write32(&self, off: usize, v: u32) {
        if let Some(b) = self.cfg.borrow_mut().get_mut(off..off + 4) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }
}
