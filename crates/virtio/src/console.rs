//! virtio-console (virtio 1.x §5.3), port 0 only (ADR-258): a log sink and
//! a byte source for the Diagnostic entry's prompts.
//!
//! `VIRTIO_CONSOLE_F_MULTIPORT` is not negotiated, so the device has one
//! port, 0, on queues 0 (receive) and 1 (transmit), and no control queue;
//! QEMU marks port 0 open as soon as the driver is ready. `F_SIZE` and
//! `F_EMERG_WRITE` are not used either.
//!
//! Nothing here waits for the device: [`VirtioConsole::write`] puts what
//! fits into free transmit buffers and drops (and counts) the rest, so a
//! host that never reads its end cannot stall the log. Received bytes go
//! into a fixed [`ByteRing`]; a length the device reports is clamped to the
//! buffer it was given.

use crate::bus::{Bus, ByteRing, dma_read, dma_write, make_queue};
use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::{Env, F_VERSION_1, VirtioError};

pub const F_SIZE: u64 = 1 << 0;
pub const F_MULTIPORT: u64 = 1 << 1;
pub const F_EMERG_WRITE: u64 = 1 << 2;

const RXQ: u16 = 0;
const TXQ: u16 = 1;
/// Receive buffers and their size.
pub const RX_BUFS: usize = 8;
pub const RX_BUF: usize = 64;
/// Transmit buffers and their size: 4 KiB of log in flight at most.
pub const TX_BUFS: usize = 8;
pub const TX_BUF: usize = 512;
/// The queues are never larger than this (slot maps are fixed arrays).
const QMAX: u16 = 8;

pub struct VirtioConsole<B: Bus> {
    bus: B,
    rx: SplitQueue,
    rx_off: usize,
    tx: SplitQueue,
    tx_off: usize,
    rx_mem: DmaRegion,
    tx_mem: DmaRegion,
    /// Receive slot of each descriptor head (u8::MAX: none).
    rx_slot: [u8; QMAX as usize],
    /// Transmit slot of each in-flight head (u8::MAX: none).
    tx_slot: [u8; QMAX as usize],
    /// Free transmit slots, one bit each.
    tx_free: u16,
    tx_slots: usize,
    /// The transmit slot being filled and its length, not yet posted.
    pending: Option<(usize, usize)>,
    input: ByteRing,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    pub rx_bytes: u64,
    /// Completions the device sent for a buffer it did not have.
    pub protocol_errors: u64,
}

impl<B: Bus> VirtioConsole<B> {
    pub fn new<E: Env>(bus: B, env: &E) -> Result<Self, VirtioError> {
        bus.init(env, 0, F_VERSION_1)?;
        let (rx, rx_off) = make_queue(&bus, env, RXQ, QMAX)?;
        let (tx, tx_off) = make_queue(&bus, env, TXQ, QMAX)?;
        let rx_mem = env.dma_alloc(RX_BUFS * RX_BUF).ok_or(VirtioError::NoDma)?;
        let tx_mem = env.dma_alloc(TX_BUFS * TX_BUF).ok_or(VirtioError::NoDma)?;
        let tx_slots = TX_BUFS.min(usize::from(tx.size()));
        let mut c = Self {
            bus,
            rx,
            rx_off,
            tx,
            tx_off,
            rx_mem,
            tx_mem,
            rx_slot: [u8::MAX; QMAX as usize],
            tx_slot: [u8::MAX; QMAX as usize],
            tx_free: ((1u32 << tx_slots) - 1) as u16,
            tx_slots,
            pending: None,
            input: ByteRing::default(),
            tx_bytes: 0,
            tx_dropped: 0,
            rx_bytes: 0,
            protocol_errors: 0,
        };
        for slot in 0..RX_BUFS.min(usize::from(c.rx.size())) {
            c.post_rx(slot)?;
        }
        c.bus.driver_ok()?;
        c.bus.notify(c.rx_off, RXQ);
        Ok(c)
    }

    fn post_rx(&mut self, slot: usize) -> Result<(), VirtioError> {
        let head = self
            .rx
            .next_free()
            .ok_or(VirtioError::Queue(crate::QueueError::NoDescriptors))?;
        self.rx.add(&[Buf {
            pa: self.rx_mem.pa + (slot * RX_BUF) as u64,
            len: RX_BUF as u32,
            device_writes: true,
        }])?;
        if let Some(s) = self.rx_slot.get_mut(usize::from(head)) {
            *s = slot as u8;
        }
        Ok(())
    }

    /// Moves what the device received into the input ring and gives the
    /// buffers back. Bounded by the queue size.
    pub fn poll(&mut self) {
        let mut reposted = false;
        for _ in 0..self.rx.size() {
            let (head, len) = match self.rx.pop_used() {
                Ok(Some(d)) => d,
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            };
            let Some(slot) = self
                .rx_slot
                .get_mut(usize::from(head))
                .map(|s| core::mem::replace(s, u8::MAX))
                .filter(|&s| usize::from(s) < RX_BUFS)
            else {
                self.protocol_errors += 1;
                continue;
            };
            let n = (len as usize).min(RX_BUF);
            let mut buf = [0u8; RX_BUF];
            if let Some(b) = buf.get_mut(..n)
                && dma_read(&self.rx_mem, usize::from(slot) * RX_BUF, b)
            {
                for &x in b.iter() {
                    self.input.push(x);
                }
                self.rx_bytes += n as u64;
            }
            if self.post_rx(usize::from(slot)).is_ok() {
                reposted = true;
            }
        }
        if reposted {
            self.bus.notify(self.rx_off, RXQ);
        }
    }

    /// One received byte, if any (call [`poll`](Self::poll) first).
    pub fn read_byte(&mut self) -> Option<u8> {
        self.input.pop()
    }

    /// Bytes the input ring dropped because nobody read them.
    pub fn input_dropped(&self) -> u64 {
        self.input.dropped
    }

    fn reap_tx(&mut self) {
        for _ in 0..self.tx.size() {
            match self.tx.pop_used() {
                Ok(Some((head, _))) => {
                    match self
                        .tx_slot
                        .get_mut(usize::from(head))
                        .map(|s| core::mem::replace(s, u8::MAX))
                    {
                        Some(s) if usize::from(s) < self.tx_slots => self.tx_free |= 1 << s,
                        _ => self.protocol_errors += 1,
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            }
        }
    }

    /// Queues as much of `data` as free buffers hold; the rest is dropped
    /// and counted. Never waits. Small writes (the log writes a line in
    /// pieces) fill one buffer, which goes to the device when it is full,
    /// when `data` ends a line, or at [`flush`](Self::flush). Returns the
    /// bytes taken.
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.reap_tx();
        let mut done = 0;
        while done < data.len() {
            let (slot, len) = match self.pending {
                Some(p) => p,
                None if self.tx_free != 0 => (self.tx_free.trailing_zeros() as usize, 0),
                None => break,
            };
            let rest = data.get(done..).unwrap_or(&[]);
            let n = rest.len().min(TX_BUF - len);
            let Some(chunk) = rest.get(..n) else { break };
            if !dma_write(&self.tx_mem, slot * TX_BUF + len, chunk) {
                break;
            }
            self.tx_free &= !(1 << slot);
            self.pending = Some((slot, len + n));
            done += n;
            if len + n == TX_BUF {
                self.post_pending();
            }
        }
        if data.last() == Some(&b'\n') {
            self.post_pending();
        }
        self.tx_bytes += done as u64;
        self.tx_dropped += (data.len() - done) as u64;
        done
    }

    /// Sends the partly filled buffer, if there is one.
    pub fn flush(&mut self) {
        self.post_pending();
    }

    fn post_pending(&mut self) {
        let Some((slot, len)) = self.pending.take() else {
            return;
        };
        let head = self.tx.next_free();
        let added = head.is_some()
            && self
                .tx
                .add(&[Buf {
                    pa: self.tx_mem.pa + (slot * TX_BUF) as u64,
                    len: len as u32,
                    device_writes: false,
                }])
                .is_ok();
        match head {
            Some(h) if added => {
                if let Some(s) = self.tx_slot.get_mut(usize::from(h)) {
                    *s = slot as u8;
                }
                self.bus.notify(self.tx_off, TXQ);
            }
            _ => {
                // Cannot happen (a free slot has a free descriptor): the
                // bytes are lost, the slot is free again.
                self.tx_dropped += len as u64;
                self.tx_free |= 1 << slot;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeBus, FakeEnv};

    fn device() -> (FakeBus, FakeEnv) {
        (
            FakeBus::new(F_VERSION_1 | F_MULTIPORT, &[64, 64], 12),
            FakeEnv::default(),
        )
    }

    #[test]
    fn port_0_only_and_receive_buffers_are_posted() {
        let (bus, env) = device();
        let c = VirtioConsole::new(&bus, &env).unwrap();
        // MULTIPORT is offered but not taken: no control queue.
        assert_eq!(bus.accepted.get(), F_VERSION_1);
        assert!(bus.driver_ok.get());
        assert_eq!(bus.queues.borrow()[0].size, 8);
        let mut posted = 0;
        while let Some((_, segs)) = bus.pop(RXQ) {
            assert_eq!(segs, vec![(segs[0].0, RX_BUF as u32, true)]);
            posted += 1;
        }
        assert_eq!(posted, RX_BUFS);
        assert_eq!(c.rx_bytes, 0);
    }

    #[test]
    fn writes_reach_the_device_and_what_does_not_fit_is_dropped() {
        let (bus, env) = device();
        let mut c = VirtioConsole::new(&bus, &env).unwrap();
        assert_eq!(c.write(b"hello, host\n"), 12);
        let (head, segs) = bus.pop(TXQ).unwrap();
        assert_eq!(FakeBus::read(&segs), b"hello, host\n");
        bus.complete(TXQ, u32::from(head), 0);
        // A host that never reads: 8 buffers of 512 bytes, then drops.
        let big = vec![b'x'; 10 * TX_BUF];
        assert_eq!(c.write(&big), TX_BUFS * TX_BUF);
        assert_eq!(c.tx_dropped, (2 * TX_BUF) as u64);
        assert_eq!(c.write(b"more"), 0);
        // The host reads one: room for one more buffer.
        let (head, segs) = bus.pop(TXQ).unwrap();
        assert_eq!(segs[0].1, TX_BUF as u32);
        bus.complete(TXQ, u32::from(head), 0);
        assert_eq!(c.write(b"more"), 4);
        assert_eq!(c.protocol_errors, 0);
    }

    #[test]
    fn a_line_written_in_pieces_is_one_buffer() {
        let (bus, env) = device();
        let mut c = VirtioConsole::new(&bus, &env).unwrap();
        for piece in [&b"[    1.000000] "[..], b"INFO ", b"virtio: ", b"hello"] {
            c.write(piece);
        }
        assert!(bus.pop(TXQ).is_none(), "nothing until the line ends");
        c.write(b"\n");
        let (_, segs) = bus.pop(TXQ).unwrap();
        assert_eq!(FakeBus::read(&segs), b"[    1.000000] INFO virtio: hello\n");
        assert!(bus.pop(TXQ).is_none());
        c.write(b"no newline");
        c.flush();
        let (_, segs) = bus.pop(TXQ).unwrap();
        assert_eq!(FakeBus::read(&segs), b"no newline");
        // A long line spans buffers.
        let long = vec![b'z'; TX_BUF + 10];
        c.write(&long);
        c.write(b"\n");
        let (_, a) = bus.pop(TXQ).unwrap();
        let (_, b) = bus.pop(TXQ).unwrap();
        assert_eq!((a[0].1 as usize, b[0].1), (TX_BUF, 11));
    }

    #[test]
    fn received_bytes_come_out_in_order_and_lengths_are_clamped() {
        let (bus, env) = device();
        let mut c = VirtioConsole::new(&bus, &env).unwrap();
        let (h1, s1) = bus.pop(RXQ).unwrap();
        let n = FakeBus::fill(&s1, b"WIPE\r");
        bus.complete(RXQ, u32::from(h1), n);
        // A device that claims more than the buffer holds.
        let (h2, s2) = bus.pop(RXQ).unwrap();
        FakeBus::fill(&s2, &[b'y'; RX_BUF]);
        bus.complete(RXQ, u32::from(h2), u32::MAX);
        c.poll();
        let got: Vec<u8> = core::iter::from_fn(|| c.read_byte()).collect();
        assert_eq!(&got[..5], b"WIPE\r");
        assert_eq!(got.len(), 5 + RX_BUF);
        // Both buffers were given back.
        assert!(bus.pop(RXQ).is_some());
        assert_eq!(c.rx_bytes, (5 + RX_BUF) as u64);
    }

    #[test]
    fn hostile_completions_are_counted_not_followed() {
        let (bus, env) = device();
        let mut c = VirtioConsole::new(&bus, &env).unwrap();
        // A completion for a head that was never posted on the tx queue.
        bus.complete(TXQ, 5, 0);
        assert_eq!(c.write(b"a"), 1);
        assert_eq!(c.protocol_errors, 1);
        // An index far ahead: refused by the queue, counted.
        bus.complete(RXQ, 0, 1);
        {
            let qs = bus.queues.borrow();
            let used = qs[0].used;
            // SAFETY: the test owns the fake ring memory.
            #[allow(unsafe_code)]
            unsafe {
                ((used + 2) as *mut u16).write_volatile(200)
            };
        }
        c.poll();
        assert!(c.protocol_errors >= 2);
    }

    #[test]
    fn a_device_without_version_1_is_refused() {
        let bus = FakeBus::new(0, &[8, 8], 12);
        assert_eq!(
            VirtioConsole::new(&bus, &FakeEnv::default()).err(),
            Some(VirtioError::MissingFeatures(F_VERSION_1))
        );
        let bus = FakeBus::new(F_VERSION_1, &[8, 0], 12);
        assert_eq!(
            VirtioConsole::new(&bus, &FakeEnv::default()).err(),
            Some(VirtioError::QueueUnavailable(TXQ))
        );
    }
}
