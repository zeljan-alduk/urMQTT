//! virtio-net (virtio 1.x §5.1), one RX/TX queue pair, no offloads.
//!
//! Transmit is asynchronous: each TX descriptor has its own bounce buffer,
//! completed ones are reclaimed lazily, and the device is kicked once per
//! batch ([`VirtioNet::queue`] + [`VirtioNet::flush`]) and only when it asks
//! for notifications. Received buffers are recycled the same way (M13:
//! one VM exit per batch instead of two per frame).

use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::transport::Transport;
use crate::{Env, F_VERSION_1, VirtioError};

pub const F_MAC: u64 = 1 << 5;
pub const F_STATUS: u64 = 1 << 16;
pub const F_MQ: u64 = 1 << 22;
pub const F_RSS: u64 = 1 << 60;

/// `virtio_net_hdr` with VERSION_1 (includes `num_buffers`).
pub const HDR_LEN: usize = 12;
/// Ethernet frame without FCS, plus header.
pub const BUF_LEN: usize = 2048;
pub const MTU_FRAME: usize = 1514;
/// Shortest Ethernet frame without the FCS; shorter ones are zero-padded.
pub const MIN_FRAME: usize = 60;
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const RX_BUFFERS: u16 = 256;
const TX_BUFFERS: u16 = 256;

pub struct VirtioNet {
    t: Transport,
    rx: SplitQueue,
    tx: SplitQueue,
    rx_notify: usize,
    tx_notify: usize,
    rx_bufs: DmaRegion,
    tx_bufs: DmaRegion,
    /// Buffers made available since the last kick.
    rx_unkicked: bool,
    tx_unkicked: bool,
    pub mac: [u8; 6],
    pub features: u64,
    /// Frames dropped because every TX descriptor was in flight.
    pub tx_full: u64,
}

impl VirtioNet {
    pub fn new<E: Env>(t: Transport, env: &E) -> Result<Self, VirtioError> {
        let features = t.init(env, F_MAC | F_STATUS, F_VERSION_1)?;
        let rx_size = RX_BUFFERS.min(t.queue_max(RX_QUEUE));
        let tx_size = TX_BUFFERS.min(t.queue_max(TX_QUEUE));
        let alloc_q = |size: u16| -> Result<SplitQueue, VirtioError> {
            let mem = env
                .dma_alloc(crate::queue::Layout::new(size).total)
                .ok_or(VirtioError::NoDma)?;
            // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
            #[allow(unsafe_code)]
            let q = unsafe { SplitQueue::new(mem, size) }?;
            Ok(q)
        };
        let mut rx = alloc_q(rx_size)?;
        let tx = alloc_q(tx_size)?;
        let rx_notify = t.setup_queue(RX_QUEUE, &rx, None)?;
        let tx_notify = t.setup_queue(TX_QUEUE, &tx, None)?;
        let rx_bufs = env
            .dma_alloc(BUF_LEN * usize::from(rx_size))
            .ok_or(VirtioError::NoDma)?;
        let tx_bufs = env
            .dma_alloc(BUF_LEN * usize::from(tx_size))
            .ok_or(VirtioError::NoDma)?;
        let mut mac = [0u8; 6];
        if features & F_MAC != 0 {
            for (i, b) in mac.iter_mut().enumerate() {
                *b = t.device.read8(i);
            }
        }
        for i in 0..rx_size {
            rx.add(&[Buf {
                pa: rx_bufs.pa + u64::from(i) * BUF_LEN as u64,
                len: BUF_LEN as u32,
                device_writes: true,
            }])?;
        }
        t.driver_ok()?;
        t.notify(rx_notify, RX_QUEUE);
        Ok(Self {
            t,
            rx,
            tx,
            rx_notify,
            tx_notify,
            rx_bufs,
            tx_bufs,
            rx_unkicked: false,
            tx_unkicked: false,
            mac,
            features,
            tx_full: 0,
        })
    }

    /// Link up according to the device (always true without F_STATUS).
    pub fn link_up(&self) -> bool {
        self.features & F_STATUS == 0 || self.t.device.read16(6) & 1 != 0
    }

    /// Sends one Ethernet frame (without FCS) right away.
    pub fn send<E: Env>(&mut self, env: &E, frame: &[u8]) -> Result<(), VirtioError> {
        let _ = env;
        self.queue(frame)?;
        self.flush();
        Ok(())
    }

    /// Queues one frame for transmission without kicking the device. Fails
    /// with `NoDescriptors` when every TX buffer is in flight.
    pub fn queue(&mut self, frame: &[u8]) -> Result<(), VirtioError> {
        if frame.len() > MTU_FRAME {
            return Err(VirtioError::OutOfRange);
        }
        // Reclaim what the device has finished with.
        while self.tx.pop_used()?.is_some() {}
        let Some(id) = self.tx.next_free() else {
            self.tx_full += 1;
            return Err(VirtioError::Queue(crate::queue::QueueError::NoDescriptors));
        };
        let off = usize::from(id) * BUF_LEN;
        #[allow(unsafe_code)]
        // SAFETY: descriptor `id` is free, so its bounce buffer (BUF_LEN bytes
        // at `off`, inside `tx_bufs`) is not owned by the device.
        let buf =
            unsafe { core::slice::from_raw_parts_mut((self.tx_bufs.va + off) as *mut u8, BUF_LEN) };
        if let Some(h) = buf.get_mut(..HDR_LEN) {
            h.fill(0);
        }
        if let Some(d) = buf.get_mut(HDR_LEN..HDR_LEN + frame.len()) {
            d.copy_from_slice(frame);
        }
        // Ethernet's 60-byte minimum (without FCS): a hardware NIC pads for us,
        // but a hypervisor bridge may drop runts (ARP, bare TCP ACKs/RSTs).
        let len = frame.len().max(MIN_FRAME);
        if let Some(pad) = buf.get_mut(HDR_LEN + frame.len()..HDR_LEN + len) {
            pad.fill(0);
        }
        self.tx.add(&[Buf {
            pa: self.tx_bufs.pa + off as u64,
            len: (HDR_LEN + len) as u32,
            device_writes: false,
        }])?;
        self.tx_unkicked = true;
        Ok(())
    }

    /// Kicks the device for queued TX frames and recycled RX buffers.
    pub fn flush(&mut self) {
        if self.tx_unkicked {
            self.tx_unkicked = false;
            if self.tx.device_wants_notify() {
                self.t.notify(self.tx_notify, TX_QUEUE);
            }
        }
        if self.rx_unkicked {
            self.rx_unkicked = false;
            if self.rx.device_wants_notify() {
                self.t.notify(self.rx_notify, RX_QUEUE);
            }
        }
    }

    /// Whether a received frame is waiting (cheap: one ring index read).
    pub fn rx_pending(&self) -> bool {
        self.rx.has_used()
    }

    /// Copies one received frame into `out` and recycles its buffer.
    /// Returns the frame length, or `None` if nothing arrived.
    pub fn recv(&mut self, out: &mut [u8]) -> Result<Option<usize>, VirtioError> {
        let Some((head, len)) = self.rx.pop_used()? else {
            return Ok(None);
        };
        let total = (len as usize).min(BUF_LEN);
        let frame_len = total.saturating_sub(HDR_LEN);
        // With one descriptor per buffer the head id is the buffer index.
        let off = usize::from(head) * BUF_LEN;
        #[allow(unsafe_code)]
        // SAFETY: the device returned buffer `head` (< queue size, checked by
        // `pop_used`), which lies inside `rx_bufs`.
        let src = unsafe {
            core::slice::from_raw_parts((self.rx_bufs.va + off + HDR_LEN) as *const u8, frame_len)
        };
        let n = frame_len.min(out.len());
        if let (Some(d), Some(s)) = (out.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
        self.rx.add(&[Buf {
            pa: self.rx_bufs.pa + off as u64,
            len: BUF_LEN as u32,
            device_writes: true,
        }])?;
        // Kicked with the next `flush`.
        self.rx_unkicked = true;
        Ok(Some(n))
    }
}
