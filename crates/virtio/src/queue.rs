//! Split virtqueue (virtio 1.x §2.7) over device-visible DMA memory.
//!
//! The rings live in one physically contiguous allocation, followed by the
//! driver's two private tables (the free-list next-pointers and the length of
//! each in-flight chain), so that a `SplitQueue` is a few words whatever its
//! size: with `MAX_QUEUE` at 1 024 (ADR-266) the tables as inline arrays
//! made a queue 4 KiB and a driver with three queues overflowed the 128 KiB
//! main stack while it was built at probe time (aarch64, virtio-balloon).
//! The driver side here owns the descriptor free list; the device consumes
//! the available ring and fills the used ring. Every index read from the
//! used ring is validated, because a buggy or hostile device must not make
//! the driver index out of bounds; a device that scribbles over the tables
//! (it was never told about them, but they share the DMA memory) can only
//! make descriptors of its own queue overlap, which it could do through the
//! used ring anyway.

#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, fence};

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;
/// `VIRTQ_AVAIL_F_NO_INTERRUPT`: the driver does not want an interrupt for
/// used buffers (virtio 1.x §2.7.7).
pub const AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Largest queue the driver will use. The network queues ask for 1 024
/// descriptors where the device offers them (ADR-266); the others stay small.
pub const MAX_QUEUE: u16 = 1024;

/// A buffer for one descriptor: physical address, length, device writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Buf {
    pub pa: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// DMA memory the queue lives in.
#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    /// Kernel virtual address.
    pub va: usize,
    /// Address the device uses.
    pub pa: u64,
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    BadSize,
    RegionTooSmall,
    NoDescriptors,
    /// The device returned an id or index that cannot be ours.
    DeviceProtocol,
}

/// Byte layout of the three rings for a queue of `size` entries, then the
/// driver's two private tables (`u16` each per descriptor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub desc: usize,
    pub avail: usize,
    pub used: usize,
    /// Next-pointers of the free list (driver-private).
    pub next: usize,
    /// Descriptors per in-flight chain, indexed by head (driver-private).
    pub chain_len: usize,
    pub total: usize,
}

impl Layout {
    pub const fn new(size: u16) -> Self {
        let n = size as usize;
        let desc = 0;
        let avail = desc + 16 * n;
        // Used ring aligned to 4 bytes (virtio 1.x), we use 64 for cache lines.
        let used = (avail + 6 + 2 * n).next_multiple_of(64);
        let next = (used + 6 + 8 * n).next_multiple_of(64);
        let chain_len = next + 2 * n;
        let total = chain_len + 2 * n;
        Self {
            desc,
            avail,
            used,
            next,
            chain_len,
            total,
        }
    }
}

pub struct SplitQueue {
    mem: DmaRegion,
    layout: Layout,
    size: u16,
    /// Next-pointers of free descriptors (driver-private copy).
    free_head: u16,
    num_free: u16,
    avail_idx: u16,
    last_used: u16,
}

impl SplitQueue {
    /// # Safety
    /// `mem` must be zeroed, device-accessible memory of at least
    /// `Layout::new(size).total` bytes, owned by this queue for its lifetime.
    pub unsafe fn new(mem: DmaRegion, size: u16) -> Result<Self, QueueError> {
        if size == 0 || size > MAX_QUEUE || !size.is_power_of_two() {
            return Err(QueueError::BadSize);
        }
        let layout = Layout::new(size);
        if mem.len < layout.total {
            return Err(QueueError::RegionTooSmall);
        }
        let q = Self {
            mem,
            layout,
            size,
            free_head: 0,
            num_free: size,
            avail_idx: 0,
            last_used: 0,
        };
        // The free list threads every descriptor; the chain lengths are the
        // zeroes the memory came with.
        for i in 0..size {
            q.set_next(i, (i + 1) % size);
        }
        Ok(q)
    }

    /// Driver-private next-pointer of descriptor `i` (free list, chains).
    fn next(&self, i: u16) -> u16 {
        self.load(self.layout.next + 2 * usize::from(i % self.size))
    }

    fn set_next(&self, i: u16, n: u16) {
        self.store(self.layout.next + 2 * usize::from(i % self.size), n);
    }

    /// Driver-private length of the chain whose head is `head` (0: none).
    fn chain_len(&self, head: u16) -> u16 {
        self.load(self.layout.chain_len + 2 * usize::from(head % self.size))
    }

    fn set_chain_len(&self, head: u16, n: u16) {
        self.store(self.layout.chain_len + 2 * usize::from(head % self.size), n);
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub fn num_free(&self) -> u16 {
        self.num_free
    }

    /// Device addresses of (descriptor table, available ring, used ring).
    pub fn addresses(&self) -> (u64, u64, u64) {
        let pa = self.mem.pa;
        (
            pa + self.layout.desc as u64,
            pa + self.layout.avail as u64,
            pa + self.layout.used as u64,
        )
    }

    /// Volatile store into the ring memory; out-of-range offsets are ignored
    /// (they cannot happen for valid layouts, and must not corrupt memory).
    fn store<T: Copy>(&self, off: usize, v: T) {
        if off + core::mem::size_of::<T>() <= self.mem.len {
            // SAFETY: in bounds of the queue's DMA region, which the queue owns.
            unsafe { ((self.mem.va + off) as *mut T).write_volatile(v) }
        }
    }

    /// Volatile load from the ring memory (zero when out of range).
    fn load<T: Copy + Default>(&self, off: usize) -> T {
        if off + core::mem::size_of::<T>() <= self.mem.len {
            // SAFETY: as in `store`.
            unsafe { ((self.mem.va + off) as *const T).read_volatile() }
        } else {
            T::default()
        }
    }

    fn write_desc(&mut self, i: u16, b: Buf, flags: u16, next: u16) {
        let base = self.layout.desc + 16 * usize::from(i % self.size);
        self.store(base, b.pa);
        self.store(base + 8, b.len);
        self.store(base + 12, flags);
        self.store(base + 14, next);
    }

    /// Makes a descriptor chain available. Returns its head id. The caller
    /// must notify the device afterwards.
    pub fn add(&mut self, bufs: &[Buf]) -> Result<u16, QueueError> {
        let n = u16::try_from(bufs.len()).map_err(|_| QueueError::NoDescriptors)?;
        if n == 0 || n > self.num_free {
            return Err(QueueError::NoDescriptors);
        }
        let head = self.free_head;
        let mut cur = head;
        for (k, b) in bufs.iter().enumerate() {
            let last = k + 1 == bufs.len();
            let nxt = self.next(cur);
            let mut flags = if b.device_writes { DESC_F_WRITE } else { 0 };
            if !last {
                flags |= DESC_F_NEXT;
            }
            self.write_desc(cur, *b, flags, if last { 0 } else { nxt });
            if last {
                self.free_head = nxt;
            } else {
                cur = nxt;
            }
        }
        self.num_free -= n;
        self.set_chain_len(head, n);
        let slot = self.layout.avail + 4 + 2 * usize::from(self.avail_idx % self.size);
        self.store(slot, head);
        // Descriptors and ring entry must be visible before the index.
        fence(Ordering::Release);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.store(self.layout.avail + 2, self.avail_idx);
        Ok(head)
    }

    /// Whether the device has completed a chain not yet popped.
    pub fn has_used(&self) -> bool {
        let used_idx: u16 = self.load(self.layout.used + 2);
        used_idx != self.last_used
    }

    /// How many completed chains wait to be popped.
    pub fn used_pending(&self) -> u16 {
        let used_idx: u16 = self.load(self.layout.used + 2);
        used_idx.wrapping_sub(self.last_used)
    }

    /// The descriptor `add` will use next for a one-descriptor chain, so a
    /// driver can fill the buffer that belongs to it first.
    pub fn next_free(&self) -> Option<u16> {
        (self.num_free > 0).then_some(self.free_head)
    }

    /// Whether the device wants a notification for newly available buffers
    /// (`VIRTQ_USED_F_NO_NOTIFY` clear, virtio 1.x §2.7.10).
    pub fn device_wants_notify(&self) -> bool {
        // The new available index must be visible before reading the flag
        // the device sets while it is already processing.
        fence(Ordering::SeqCst);
        let flags: u16 = self.load(self.layout.used);
        flags & 1 == 0
    }

    /// Asks the device not to interrupt for used buffers
    /// (`VIRTQ_AVAIL_F_NO_INTERRUPT`, virtio 1.x §2.7.7). Without
    /// `VIRTIO_F_EVENT_IDX` (not negotiated) it is a hint the device may
    /// ignore, so an interrupt can still arrive; it never storms, because a
    /// driver keeps the flag set while it is busy (ADR-270).
    pub fn suppress_interrupts(&self) {
        self.store(self.layout.avail, AVAIL_F_NO_INTERRUPT);
    }

    /// Asks for an interrupt at the next used buffer, then re-checks the used
    /// ring. `true`: a buffer is already there, and the caller must not wait
    /// for the interrupt (the device may have looked at the flag before it
    /// was cleared and decided not to send one). The flag store and the index
    /// load are ordered by a full fence, as the device orders its index store
    /// and its flag load (virtio 1.x §2.7.10), so either the driver sees the
    /// buffer or the device sees the cleared flag: no lost wake-up.
    pub fn enable_interrupts(&self) -> bool {
        self.store(self.layout.avail, 0u16);
        fence(Ordering::SeqCst);
        self.has_used()
    }

    /// Whether [`suppress_interrupts`](Self::suppress_interrupts) is in force.
    pub fn interrupts_suppressed(&self) -> bool {
        let flags: u16 = self.load(self.layout.avail);
        flags & AVAIL_F_NO_INTERRUPT != 0
    }

    /// Returns the next completed chain as (head id, bytes written by the
    /// device), freeing its descriptors.
    pub fn pop_used(&mut self) -> Result<Option<(u16, u32)>, QueueError> {
        let used_idx: u16 = self.load(self.layout.used + 2);
        if used_idx == self.last_used {
            return Ok(None);
        }
        if used_idx.wrapping_sub(self.last_used) > self.size {
            return Err(QueueError::DeviceProtocol);
        }
        // The element must be read after the index that published it.
        fence(Ordering::Acquire);
        let elem = self.layout.used + 4 + 8 * usize::from(self.last_used % self.size);
        let id: u32 = self.load(elem);
        let len: u32 = self.load(elem + 4);
        let head = u16::try_from(id).map_err(|_| QueueError::DeviceProtocol)?;
        if head >= self.size {
            return Err(QueueError::DeviceProtocol);
        }
        let n = self.chain_len(head);
        if n == 0 || n > self.size - self.num_free {
            return Err(QueueError::DeviceProtocol);
        }
        self.last_used = self.last_used.wrapping_add(1);
        // Return the chain to the free list using our private next-pointers.
        let mut tail = head;
        for _ in 1..n {
            tail = self.next(tail);
        }
        self.set_next(tail, self.free_head);
        self.free_head = head;
        self.num_free += n;
        self.set_chain_len(head, 0);
        Ok(Some((head, len)))
    }
}

#[cfg(test)]
// Test scaffolding plays the device: raw accesses into a Vec the test owns.
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]
mod tests {
    use super::*;

    /// A driver builds its queues on the main stack at probe time (balloon:
    /// three of them, ADR-266 made the tables 4x larger); the tables live in
    /// the DMA memory so that the struct stays a few words.
    #[test]
    fn a_queue_is_small_whatever_max_queue_is() {
        assert!(core::mem::size_of::<SplitQueue>() <= 128);
        let l = Layout::new(MAX_QUEUE);
        assert_eq!(l.chain_len - l.next, 2 * usize::from(MAX_QUEUE));
        assert_eq!(l.total - l.chain_len, 2 * usize::from(MAX_QUEUE));
        assert_eq!(l.next % 64, 0);
    }

    /// Memory plus a toy device that echoes: it reads every readable
    /// buffer, XORs it into the writable ones and reports bytes written.
    struct Rig {
        mem: Vec<u64>,
        q: SplitQueue,
        dev_last_avail: u16,
        dev_used: u16,
    }

    impl Rig {
        fn new(size: u16) -> Self {
            let words = Layout::new(size).total.div_ceil(8) + 1;
            let mut mem = vec![0u64; words];
            let va = mem.as_mut_ptr() as usize;
            let region = DmaRegion {
                va,
                pa: va as u64,
                len: words * 8,
            };
            let q = unsafe { SplitQueue::new(region, size) }.unwrap();
            Self {
                mem,
                q,
                dev_last_avail: 0,
                dev_used: 0,
            }
        }

        fn base(&self) -> usize {
            self.mem.as_ptr() as usize
        }

        fn rd16(&self, off: usize) -> u16 {
            unsafe { ((self.base() + off) as *const u16).read_volatile() }
        }

        /// Processes everything available, like a device would.
        fn device_run(&mut self) {
            let l = self.q.layout;
            let size = self.q.size;
            while self.rd16(l.avail + 2) != self.dev_last_avail {
                let head = self.rd16(l.avail + 4 + 2 * usize::from(self.dev_last_avail % size));
                self.dev_last_avail = self.dev_last_avail.wrapping_add(1);
                let mut i = head;
                let mut written = 0u32;
                let mut acc = 0u8;
                loop {
                    let d = self.base() + l.desc + 16 * usize::from(i);
                    let (pa, len, flags, next) = unsafe {
                        (
                            (d as *const u64).read(),
                            ((d + 8) as *const u32).read(),
                            ((d + 12) as *const u16).read(),
                            ((d + 14) as *const u16).read(),
                        )
                    };
                    let buf =
                        unsafe { core::slice::from_raw_parts_mut(pa as *mut u8, len as usize) };
                    if flags & DESC_F_WRITE != 0 {
                        buf.fill(acc);
                        written += len;
                    } else {
                        acc = buf.iter().fold(acc, |a, b| a ^ b);
                    }
                    if flags & DESC_F_NEXT == 0 {
                        break;
                    }
                    i = next;
                }
                let e = self.base() + l.used + 4 + 8 * usize::from(self.dev_used % size);
                unsafe {
                    (e as *mut u32).write(u32::from(head));
                    ((e + 4) as *mut u32).write(written);
                }
                self.dev_used = self.dev_used.wrapping_add(1);
                unsafe { ((self.base() + l.used + 2) as *mut u16).write(self.dev_used) };
            }
        }
    }

    #[test]
    fn layout_alignment() {
        let l = Layout::new(256);
        assert_eq!(l.avail, 4096);
        assert_eq!(l.used % 64, 0);
        assert_eq!(l.next, (l.used + 6 + 8 * 256).next_multiple_of(64));
        assert_eq!(l.total, l.next + 4 * 256);
    }

    #[test]
    fn request_response_roundtrip_and_reuse() {
        let mut rig = Rig::new(8);
        let mut out = [0x12u8, 0x34];
        let mut inp = [0u8; 3];
        for round in 0..100 {
            out[0] = round as u8;
            let head = rig
                .q
                .add(&[
                    Buf {
                        pa: out.as_ptr() as u64,
                        len: 2,
                        device_writes: false,
                    },
                    Buf {
                        pa: inp.as_mut_ptr() as u64,
                        len: 3,
                        device_writes: true,
                    },
                ])
                .unwrap();
            assert_eq!(rig.q.num_free(), 6);
            assert_eq!(rig.q.pop_used().unwrap(), None);
            rig.device_run();
            assert_eq!(rig.q.pop_used().unwrap(), Some((head, 3)));
            assert_eq!(inp, [round as u8 ^ 0x34; 3]);
            assert_eq!(rig.q.num_free(), 8);
        }
    }

    #[test]
    fn exhaustion_and_many_in_flight() {
        let mut rig = Rig::new(4);
        let mut bufs = [[0u8; 4]; 4];
        let mut heads = Vec::new();
        for b in &mut bufs {
            heads.push(
                rig.q
                    .add(&[Buf {
                        pa: b.as_mut_ptr() as u64,
                        len: 4,
                        device_writes: true,
                    }])
                    .unwrap(),
            );
        }
        assert_eq!(
            rig.q.add(&[Buf {
                pa: 0,
                len: 1,
                device_writes: true
            }]),
            Err(QueueError::NoDescriptors)
        );
        rig.device_run();
        let mut done = Vec::new();
        while let Some((h, _)) = rig.q.pop_used().unwrap() {
            done.push(h);
        }
        assert_eq!(done, heads);
        assert_eq!(rig.q.num_free(), 4);
    }

    impl Rig {
        /// The device's decision after publishing used buffers: interrupt
        /// unless the driver set `VIRTQ_AVAIL_F_NO_INTERRUPT`.
        fn device_would_interrupt(&self) -> bool {
            self.rd16(self.q.layout.avail) & AVAIL_F_NO_INTERRUPT == 0
        }

        fn post_rx(&mut self, buf: &mut [u8; 4]) {
            self.q
                .add(&[Buf {
                    pa: buf.as_mut_ptr() as u64,
                    len: 4,
                    device_writes: true,
                }])
                .unwrap();
        }
    }

    /// ADR-270: the dispatcher's sleep protocol. Suppressed while it works;
    /// enabled just before it sleeps; a buffer that arrived first is found by
    /// the re-check, one that arrives after interrupts.
    #[test]
    fn interrupt_suppression_and_recheck() {
        let mut rig = Rig::new(8);
        let mut bufs = [[0u8; 4]; 3];
        assert!(
            !rig.q.interrupts_suppressed(),
            "a fresh queue wants interrupts"
        );
        rig.q.suppress_interrupts();
        assert!(rig.q.interrupts_suppressed());
        // Busy: the device completes, and does not interrupt.
        rig.post_rx(&mut bufs[0]);
        rig.device_run();
        assert!(!rig.device_would_interrupt());
        // About to sleep with a completion not yet popped: the re-check finds
        // it, so the caller does not sleep.
        assert!(rig.q.enable_interrupts());
        assert!(rig.q.pop_used().unwrap().is_some());
        rig.q.suppress_interrupts();
        // About to sleep with nothing there: armed, and nothing pending.
        rig.post_rx(&mut bufs[1]);
        assert!(!rig.q.enable_interrupts());
        assert!(!rig.q.interrupts_suppressed());
        // The frame arrives while asleep: the device sees the cleared flag.
        rig.device_run();
        assert!(rig.device_would_interrupt());
        // Awake: suppressed again before the work, so a flood does not storm.
        rig.q.suppress_interrupts();
        rig.post_rx(&mut bufs[2]);
        rig.device_run();
        assert!(!rig.device_would_interrupt());
        assert_eq!(rig.q.used_pending(), 2);
    }

    /// Enabling never touches the available index or the free list.
    #[test]
    fn interrupt_flag_leaves_the_ring_alone() {
        let mut rig = Rig::new(4);
        let mut b = [0u8; 4];
        rig.post_rx(&mut b);
        let idx = rig.rd16(rig.q.layout.avail + 2);
        for _ in 0..3 {
            rig.q.suppress_interrupts();
            let _ = rig.q.enable_interrupts();
        }
        assert_eq!(rig.rd16(rig.q.layout.avail + 2), idx);
        assert_eq!(rig.q.num_free(), 3);
    }

    #[test]
    fn rejects_bogus_device_answers() {
        let mut rig = Rig::new(4);
        let l = rig.q.layout;
        let base = rig.base();
        // Device claims a completion we never submitted.
        unsafe {
            ((base + l.used + 4) as *mut u32).write(3);
            ((base + l.used + 2) as *mut u16).write(1);
        }
        assert_eq!(rig.q.pop_used(), Err(QueueError::DeviceProtocol));
        // Device jumps the index far ahead.
        unsafe { ((base + l.used + 2) as *mut u16).write(100) };
        assert_eq!(rig.q.pop_used(), Err(QueueError::DeviceProtocol));
    }

    #[test]
    fn bad_construction() {
        let mut m = vec![0u8; 64];
        let r = DmaRegion {
            va: m.as_mut_ptr() as usize,
            pa: 0,
            len: 64,
        };
        assert_eq!(
            unsafe { SplitQueue::new(r, 3) }.err(),
            Some(QueueError::BadSize)
        );
        assert_eq!(
            unsafe { SplitQueue::new(r, 2048) }.err(),
            Some(QueueError::BadSize)
        );
        assert_eq!(
            unsafe { SplitQueue::new(r, 8) }.err(),
            Some(QueueError::RegionTooSmall)
        );
    }
}
