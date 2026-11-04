//! virtio-vsock (virtio 1.x §5.10), the stream transport only (ADR-258),
//! for one read-only service: a host that connects to [`DIAG_PORT`] gets a
//! document (the Diagnostic report) and the connection is closed.
//!
//! The protocol state lives in [`Stack`], which does no I/O, so the host
//! tests and the fuzz target drive it with any packet sequence. It accepts
//! connections from the host to one port only (anything else gets a
//! reset), at most [`MAX_CONNS`] at a time, sends within the peer's credit
//! (`buf_alloc - (tx_cnt - fwd_cnt)`), discards what the peer sends (a
//! read-only service), and closes every connection after a bounded time.
//!
//! **Untested against a real device**: a vsock device needs vhost-vsock on
//! a Linux host; the tests here use a fake device.

use crate::bus::{Bus, cfg_consistent, dma_read, dma_write, make_queue};
use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::{Env, F_VERSION_1, VirtioError};

pub const F_STREAM: u64 = 1 << 0;
pub const F_SEQPACKET: u64 = 1 << 1;

pub const HDR_LEN: usize = 44;
pub const TYPE_STREAM: u16 = 1;
pub const TYPE_SEQPACKET: u16 = 2;
pub const OP_REQUEST: u16 = 1;
pub const OP_RESPONSE: u16 = 2;
pub const OP_RST: u16 = 3;
pub const OP_SHUTDOWN: u16 = 4;
pub const OP_RW: u16 = 5;
pub const OP_CREDIT_UPDATE: u16 = 6;
pub const OP_CREDIT_REQUEST: u16 = 7;
pub const SHUTDOWN_RCV: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;
pub const HOST_CID: u64 = 2;
pub const EVENT_TRANSPORT_RESET: u32 = 0;

/// The port of the read-only Diagnostic report service.
pub const DIAG_PORT: u32 = 2883;
/// Connections served at once; more get a reset.
pub const MAX_CONNS: usize = 4;
/// What we tell peers we can buffer: everything they send is discarded at
/// once, so this only paces them.
pub const OUR_BUF_ALLOC: u32 = 16 * 1024;
/// A connection that has made no progress for this long is reset.
pub const IDLE_NS: u64 = 10_000_000_000;
/// After our SHUTDOWN, how long the peer has to answer before a reset.
pub const CLOSE_NS: u64 = 2_000_000_000;
/// Control packets waiting to be sent.
const CTRL: usize = 8;

/// A packet header (all fields little-endian on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hdr {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub ty: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

impl Hdr {
    /// `None` unless `b` holds a whole header.
    pub fn parse(b: &[u8]) -> Option<Self> {
        Some(Self {
            src_cid: le64(b, 0)?,
            dst_cid: le64(b, 8)?,
            src_port: le32(b, 16)?,
            dst_port: le32(b, 20)?,
            len: le32(b, 24)?,
            ty: le16(b, 28)?,
            op: le16(b, 30)?,
            flags: le32(b, 32)?,
            buf_alloc: le32(b, 36)?,
            fwd_cnt: le32(b, 40)?,
        })
    }

    pub fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        let mut put = |at: usize, v: &[u8]| {
            if let Some(d) = b.get_mut(at..at + v.len()) {
                d.copy_from_slice(v);
            }
        };
        put(0, &self.src_cid.to_le_bytes());
        put(8, &self.dst_cid.to_le_bytes());
        put(16, &self.src_port.to_le_bytes());
        put(20, &self.dst_port.to_le_bytes());
        put(24, &self.len.to_le_bytes());
        put(28, &self.ty.to_le_bytes());
        put(30, &self.op.to_le_bytes());
        put(32, &self.flags.to_le_bytes());
        put(36, &self.buf_alloc.to_le_bytes());
        put(40, &self.fwd_cnt.to_le_bytes());
        b
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Sending the document.
    Sending,
    /// Our SHUTDOWN is out (since the given time); waiting for the peer.
    Closing(u64),
}

#[derive(Debug, Clone, Copy)]
struct Conn {
    peer_cid: u64,
    peer_port: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    /// Payload bytes we sent (wrapping, as the specification counts).
    tx_cnt: u32,
    /// Payload bytes the peer sent us (all discarded), our `fwd_cnt`.
    rx_cnt: u32,
    /// `rx_cnt` when we last told the peer.
    rx_reported: u32,
    /// Offset into the document.
    sent: usize,
    phase: Phase,
    /// Last progress (ns).
    last_ns: u64,
    credit_requested: bool,
}

impl Conn {
    /// Bytes the peer can take now.
    fn credit(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }
}

/// Counters for the boot log and the Diagnostic report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub accepted: u64,
    pub refused: u64,
    pub served: u64,
    pub resets_sent: u64,
    pub timeouts: u64,
    pub ignored: u64,
}

/// The stream protocol of one listening port, without I/O.
pub struct Stack {
    pub guest_cid: u64,
    pub port: u32,
    conns: [Option<Conn>; MAX_CONNS],
    ctrl: [Option<Hdr>; CTRL],
    pub stats: Stats,
}

impl Stack {
    pub fn new(guest_cid: u64, port: u32) -> Self {
        Self {
            guest_cid,
            port,
            conns: [None; MAX_CONNS],
            ctrl: [None; CTRL],
            stats: Stats::default(),
        }
    }

    /// Open connections.
    pub fn open(&self) -> usize {
        self.conns.iter().flatten().count()
    }

    /// A transport reset (the event queue): every connection is gone.
    pub fn reset(&mut self, guest_cid: u64) {
        self.guest_cid = guest_cid;
        self.conns = [None; MAX_CONNS];
        self.ctrl = [None; CTRL];
    }

    fn reply(&self, to: &Hdr, op: u16, flags: u32, fwd_cnt: u32) -> Hdr {
        Hdr {
            src_cid: self.guest_cid,
            dst_cid: to.src_cid,
            src_port: to.dst_port,
            dst_port: to.src_port,
            len: 0,
            ty: TYPE_STREAM,
            op,
            flags,
            buf_alloc: OUR_BUF_ALLOC,
            fwd_cnt,
        }
    }

    fn queue_ctrl(&mut self, h: Hdr) -> bool {
        match self.ctrl.iter_mut().find(|c| c.is_none()) {
            Some(slot) => {
                *slot = Some(h);
                true
            }
            None => false,
        }
    }

    fn rst(&mut self, to: &Hdr) {
        // A reset is never answered with a reset.
        if to.op == OP_RST {
            return;
        }
        let h = self.reply(to, OP_RST, 0, 0);
        if self.queue_ctrl(h) {
            self.stats.resets_sent += 1;
        }
    }

    fn find(&self, h: &Hdr) -> Option<usize> {
        self.conns
            .iter()
            .position(|c| c.is_some_and(|c| c.peer_cid == h.src_cid && c.peer_port == h.src_port))
    }

    /// Handles one received packet whose payload held `payload` bytes (the
    /// device's length, not the header's claim).
    pub fn on_packet(&mut self, h: &Hdr, payload: u32, now: u64) {
        if h.dst_cid != self.guest_cid || h.dst_port != self.port {
            if h.dst_cid == self.guest_cid {
                self.rst(h);
            } else {
                self.stats.ignored += 1;
            }
            return;
        }
        if h.ty != TYPE_STREAM {
            self.rst(h);
            return;
        }
        let Some(i) = self.find(h) else {
            if h.op != OP_REQUEST {
                self.rst(h);
                return;
            }
            let free = self.conns.iter().position(Option::is_none);
            let room = self.ctrl.iter().any(Option::is_none);
            match free {
                Some(f) if room && h.src_cid == HOST_CID => {
                    let resp = self.reply(h, OP_RESPONSE, 0, 0);
                    self.queue_ctrl(resp);
                    if let Some(slot) = self.conns.get_mut(f) {
                        *slot = Some(Conn {
                            peer_cid: h.src_cid,
                            peer_port: h.src_port,
                            peer_buf_alloc: h.buf_alloc,
                            peer_fwd_cnt: h.fwd_cnt,
                            tx_cnt: 0,
                            rx_cnt: 0,
                            rx_reported: 0,
                            sent: 0,
                            phase: Phase::Sending,
                            last_ns: now,
                            credit_requested: false,
                        });
                    }
                    self.stats.accepted += 1;
                }
                _ => {
                    self.stats.refused += 1;
                    self.rst(h);
                }
            }
            return;
        };
        let Some(mut c) = self.conns.get(i).copied().flatten() else {
            return;
        };
        // Every packet carries the peer's credit.
        c.peer_buf_alloc = h.buf_alloc;
        if h.fwd_cnt != c.peer_fwd_cnt {
            c.peer_fwd_cnt = h.fwd_cnt;
            c.credit_requested = false;
            c.last_ns = now;
        }
        let mut keep = true;
        match h.op {
            OP_RW => {
                // Read-only service: the bytes are counted and dropped.
                c.rx_cnt = c.rx_cnt.wrapping_add(payload);
                if c.rx_cnt.wrapping_sub(c.rx_reported) >= OUR_BUF_ALLOC / 2 {
                    let u = self.reply(h, OP_CREDIT_UPDATE, 0, c.rx_cnt);
                    if self.queue_ctrl(u) {
                        c.rx_reported = c.rx_cnt;
                    }
                }
            }
            OP_CREDIT_REQUEST => {
                let u = self.reply(h, OP_CREDIT_UPDATE, 0, c.rx_cnt);
                if self.queue_ctrl(u) {
                    c.rx_reported = c.rx_cnt;
                }
            }
            OP_CREDIT_UPDATE => {}
            OP_SHUTDOWN => {
                if h.flags & SHUTDOWN_RCV != 0 || matches!(c.phase, Phase::Closing(_)) {
                    // The peer reads no more, or both sides are done.
                    let r = self.reply(h, OP_RST, 0, c.rx_cnt);
                    if self.queue_ctrl(r) {
                        self.stats.resets_sent += 1;
                    }
                    if matches!(c.phase, Phase::Closing(_)) {
                        self.stats.served += 1;
                    }
                    keep = false;
                }
            }
            OP_RST => {
                if matches!(c.phase, Phase::Closing(_)) {
                    self.stats.served += 1;
                }
                keep = false;
            }
            _ => {
                // REQUEST on an open connection, RESPONSE (we never
                // connect), anything unknown: a protocol error.
                let r = self.reply(h, OP_RST, 0, c.rx_cnt);
                if self.queue_ctrl(r) {
                    self.stats.resets_sent += 1;
                }
                keep = false;
            }
        }
        if let Some(slot) = self.conns.get_mut(i) {
            *slot = keep.then_some(c);
        }
    }

    /// The next packet to send: control replies first, then the document in
    /// chunks of at most `max_payload` within the peer's credit, then our
    /// SHUTDOWN; resets for connections that time out. The payload is
    /// `doc[range]`.
    pub fn next_packet(
        &mut self,
        doc: &[u8],
        max_payload: usize,
        now: u64,
    ) -> Option<(Hdr, core::ops::Range<usize>)> {
        if let Some(h) = self.ctrl.iter_mut().find_map(Option::take) {
            return Some((h, 0..0));
        }
        let (guest_cid, port) = (self.guest_cid, self.port);
        for slot in self.conns.iter_mut() {
            let Some(c) = slot.as_mut() else { continue };
            let base = Hdr {
                src_cid: guest_cid,
                dst_cid: c.peer_cid,
                src_port: port,
                dst_port: c.peer_port,
                len: 0,
                ty: TYPE_STREAM,
                op: OP_RW,
                flags: 0,
                buf_alloc: OUR_BUF_ALLOC,
                fwd_cnt: c.rx_cnt,
            };
            match c.phase {
                Phase::Closing(since) if now.saturating_sub(since) > CLOSE_NS => {
                    *slot = None;
                    self.stats.timeouts += 1;
                    self.stats.resets_sent += 1;
                    return Some((Hdr { op: OP_RST, ..base }, 0..0));
                }
                Phase::Closing(_) => continue,
                Phase::Sending => {}
            }
            if now.saturating_sub(c.last_ns) > IDLE_NS {
                *slot = None;
                self.stats.timeouts += 1;
                self.stats.resets_sent += 1;
                return Some((Hdr { op: OP_RST, ..base }, 0..0));
            }
            let left = doc.len().saturating_sub(c.sent);
            if left == 0 {
                c.phase = Phase::Closing(now);
                return Some((
                    Hdr {
                        op: OP_SHUTDOWN,
                        flags: SHUTDOWN_RCV | SHUTDOWN_SEND,
                        ..base
                    },
                    0..0,
                ));
            }
            let credit = c.credit() as usize;
            if credit == 0 {
                if !c.credit_requested {
                    c.credit_requested = true;
                    return Some((
                        Hdr {
                            op: OP_CREDIT_REQUEST,
                            ..base
                        },
                        0..0,
                    ));
                }
                continue;
            }
            let n = left.min(credit).min(max_payload);
            if n == 0 {
                continue;
            }
            let range = c.sent..c.sent + n;
            c.sent += n;
            c.tx_cnt = c.tx_cnt.wrapping_add(n as u32);
            c.last_ns = now;
            return Some((
                Hdr {
                    len: n as u32,
                    ..base
                },
                range,
            ));
        }
        None
    }
}

const RXQ: u16 = 0;
const TXQ: u16 = 1;
const EVQ: u16 = 2;
/// Receive buffers: a header and up to 1004 payload bytes each.
pub const RX_BUFS: usize = 8;
pub const RX_BUF: usize = 1024 + HDR_LEN;
/// Transmit buffers: a header and up to [`TX_PAYLOAD`] bytes.
pub const TX_BUFS: usize = 8;
pub const TX_PAYLOAD: usize = 1024;
const TX_BUF: usize = HDR_LEN + TX_PAYLOAD;
const EV_BUFS: usize = 4;
const EV_BUF: usize = 8;
const QMAX: u16 = 8;
/// Received packets handled per [`VirtioVsock::poll`].
pub const POLL_PACKETS: usize = 16;

/// A configuration CID the driver accepts: 0, 1 and 2 are reserved, the
/// top values are "any" and invalid (§5.10.4).
pub fn cid_ok(cid: u64) -> bool {
    (3..=0xffff_fffe).contains(&cid)
}

pub struct VirtioVsock<B: Bus> {
    bus: B,
    rx: (SplitQueue, usize),
    tx: (SplitQueue, usize),
    ev: (SplitQueue, usize),
    rx_mem: DmaRegion,
    tx_mem: DmaRegion,
    ev_mem: DmaRegion,
    rx_slot: [u8; QMAX as usize],
    tx_slot: [u8; QMAX as usize],
    ev_slot: [u8; QMAX as usize],
    tx_free: u16,
    tx_slots: usize,
    pub stack: Stack,
    pub transport_resets: u64,
    pub protocol_errors: u64,
}

fn read_cid<B: Bus>(bus: &B) -> u64 {
    cfg_consistent(bus, |b| {
        u64::from(b.cfg_read32(0)) | (u64::from(b.cfg_read32(4)) << 32)
    })
}

impl<B: Bus> VirtioVsock<B> {
    pub fn new<E: Env>(bus: B, env: &E, port: u32) -> Result<Self, VirtioError> {
        bus.init(env, F_STREAM, F_VERSION_1)?;
        let cid = read_cid(&bus);
        if !cid_ok(cid) {
            return Err(VirtioError::OutOfRange);
        }
        let rx = make_queue(&bus, env, RXQ, QMAX)?;
        let tx = make_queue(&bus, env, TXQ, QMAX)?;
        let ev = make_queue(&bus, env, EVQ, QMAX)?;
        let rx_mem = env.dma_alloc(RX_BUFS * RX_BUF).ok_or(VirtioError::NoDma)?;
        let tx_mem = env.dma_alloc(TX_BUFS * TX_BUF).ok_or(VirtioError::NoDma)?;
        let ev_mem = env.dma_alloc(EV_BUFS * EV_BUF).ok_or(VirtioError::NoDma)?;
        let tx_slots = TX_BUFS.min(usize::from(tx.0.size()));
        let mut v = Self {
            bus,
            rx,
            tx,
            ev,
            rx_mem,
            tx_mem,
            ev_mem,
            rx_slot: [u8::MAX; QMAX as usize],
            tx_slot: [u8::MAX; QMAX as usize],
            ev_slot: [u8::MAX; QMAX as usize],
            tx_free: ((1u32 << tx_slots) - 1) as u16,
            tx_slots,
            stack: Stack::new(cid, port),
            transport_resets: 0,
            protocol_errors: 0,
        };
        for s in 0..RX_BUFS.min(usize::from(v.rx.0.size())) {
            v.post(RXQ, s)?;
        }
        for s in 0..EV_BUFS.min(usize::from(v.ev.0.size())) {
            v.post(EVQ, s)?;
        }
        v.bus.driver_ok()?;
        v.bus.notify(v.rx.1, RXQ);
        v.bus.notify(v.ev.1, EVQ);
        Ok(v)
    }

    fn post(&mut self, q: u16, s: usize) -> Result<(), VirtioError> {
        let (queue, mem, size, slots) = if q == RXQ {
            (&mut self.rx.0, &self.rx_mem, RX_BUF, &mut self.rx_slot)
        } else {
            (&mut self.ev.0, &self.ev_mem, EV_BUF, &mut self.ev_slot)
        };
        let head = queue
            .next_free()
            .ok_or(VirtioError::Queue(crate::QueueError::NoDescriptors))?;
        queue.add(&[Buf {
            pa: mem.pa + (s * size) as u64,
            len: size as u32,
            device_writes: true,
        }])?;
        if let Some(x) = slots.get_mut(usize::from(head)) {
            *x = s as u8;
        }
        Ok(())
    }

    /// Takes the slot of a completed head of `slots` (bounded by `n`).
    fn take_slot(slots: &mut [u8; QMAX as usize], head: u16, n: usize) -> Option<usize> {
        slots
            .get_mut(usize::from(head))
            .map(|x| core::mem::replace(x, u8::MAX))
            .map(usize::from)
            .filter(|&s| s < n)
    }

    /// One pass: transport events, up to [`POLL_PACKETS`] received packets,
    /// completed transmissions, then as many packets as there are free
    /// transmit buffers. `doc` is what a connection is served. Never waits.
    pub fn poll(&mut self, doc: &[u8], now: u64) {
        // Transport reset: the host forgot every connection.
        let mut ev_posted = false;
        for _ in 0..EV_BUFS {
            match self.ev.0.pop_used() {
                Ok(Some((head, len))) => {
                    let Some(s) = Self::take_slot(&mut self.ev_slot, head, EV_BUFS) else {
                        self.protocol_errors += 1;
                        continue;
                    };
                    let mut b = [0u8; 4];
                    if len >= 4
                        && dma_read(&self.ev_mem, s * EV_BUF, &mut b)
                        && u32::from_le_bytes(b) == EVENT_TRANSPORT_RESET
                    {
                        self.transport_resets += 1;
                        let cid = read_cid(&self.bus);
                        self.stack.reset(if cid_ok(cid) { cid } else { 0 });
                    }
                    if self.post(EVQ, s).is_ok() {
                        ev_posted = true;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            }
        }
        if ev_posted {
            self.bus.notify(self.ev.1, EVQ);
        }
        let mut rx_posted = false;
        for _ in 0..POLL_PACKETS {
            let (head, len) = match self.rx.0.pop_used() {
                Ok(Some(d)) => d,
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            };
            let Some(s) = Self::take_slot(&mut self.rx_slot, head, RX_BUFS) else {
                self.protocol_errors += 1;
                continue;
            };
            let got = (len as usize).min(RX_BUF);
            let mut hb = [0u8; HDR_LEN];
            if got >= HDR_LEN && dma_read(&self.rx_mem, s * RX_BUF, &mut hb) {
                if let Some(h) = Hdr::parse(&hb) {
                    // The payload the device delivered, never the header's claim.
                    let payload = (h.len as usize).min(got - HDR_LEN) as u32;
                    self.stack.on_packet(&h, payload, now);
                }
            } else {
                self.protocol_errors += 1;
            }
            if self.post(RXQ, s).is_ok() {
                rx_posted = true;
            }
        }
        if rx_posted {
            self.bus.notify(self.rx.1, RXQ);
        }
        // Completed transmissions free their buffers.
        for _ in 0..self.tx.0.size() {
            match self.tx.0.pop_used() {
                Ok(Some((head, _))) => {
                    match Self::take_slot(&mut self.tx_slot, head, self.tx_slots) {
                        Some(s) => self.tx_free |= 1 << s,
                        None => self.protocol_errors += 1,
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            }
        }
        let mut sent = false;
        while self.tx_free != 0 {
            let Some(head) = self.tx.0.next_free() else {
                break;
            };
            let Some((h, range)) = self.stack.next_packet(doc, TX_PAYLOAD, now) else {
                break;
            };
            let s = self.tx_free.trailing_zeros() as usize;
            let payload = doc.get(range).unwrap_or(&[]);
            let hdr = Hdr {
                len: payload.len() as u32,
                ..h
            };
            let base = s * TX_BUF;
            if !dma_write(&self.tx_mem, base, &hdr.encode())
                || !dma_write(&self.tx_mem, base + HDR_LEN, payload)
            {
                break;
            }
            if self
                .tx
                .0
                .add(&[Buf {
                    pa: self.tx_mem.pa + base as u64,
                    len: (HDR_LEN + payload.len()) as u32,
                    device_writes: false,
                }])
                .is_err()
            {
                break;
            }
            self.tx_free &= !(1 << s);
            if let Some(x) = self.tx_slot.get_mut(usize::from(head)) {
                *x = s as u8;
            }
            sent = true;
        }
        if sent {
            self.bus.notify(self.tx.1, TXQ);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeBus, FakeEnv};

    const CID: u64 = 42;

    fn from_host(op: u16, port: u32) -> Hdr {
        Hdr {
            src_cid: HOST_CID,
            dst_cid: CID,
            src_port: 50_000,
            dst_port: port,
            len: 0,
            ty: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: 4096,
            fwd_cnt: 0,
        }
    }

    /// Drains the stack like a device with an unlimited queue; returns the
    /// packets and the payload bytes the host received.
    fn drain(s: &mut Stack, doc: &[u8], now: u64) -> (Vec<Hdr>, Vec<u8>) {
        let mut hs = Vec::new();
        let mut data = Vec::new();
        for _ in 0..10_000 {
            let Some((h, r)) = s.next_packet(doc, 1024, now) else {
                break;
            };
            data.extend_from_slice(&doc[r]);
            hs.push(h);
        }
        (hs, data)
    }

    #[test]
    fn headers_round_trip_and_short_ones_are_refused() {
        let h = Hdr {
            src_cid: 1 << 40,
            dst_cid: 7,
            src_port: 1,
            dst_port: 2,
            len: 3,
            ty: 1,
            op: 5,
            flags: 9,
            buf_alloc: 10,
            fwd_cnt: 11,
        };
        assert_eq!(Hdr::parse(&h.encode()), Some(h));
        assert_eq!(Hdr::parse(&h.encode()[..43]), None);
    }

    #[test]
    fn a_host_connection_gets_the_document_within_its_credit_then_a_shutdown() {
        let doc: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let mut s = Stack::new(CID, DIAG_PORT);
        s.on_packet(&from_host(OP_REQUEST, DIAG_PORT), 0, 0);
        let (hs, data) = drain(&mut s, &doc, 1);
        assert_eq!(hs[0].op, OP_RESPONSE);
        assert_eq!((hs[0].dst_port, hs[0].src_port), (50_000, DIAG_PORT));
        // 4096 bytes of credit: four packets, then a credit request.
        assert_eq!(data, doc[..4096]);
        assert!(hs[1..5].iter().all(|h| h.op == OP_RW && h.len == 1024));
        assert_eq!(hs[5].op, OP_CREDIT_REQUEST);
        assert_eq!(hs.len(), 6);
        // The host read it all: credit for the rest.
        let mut all = data;
        let mut fwd = 4096u32;
        loop {
            let mut u = from_host(OP_CREDIT_UPDATE, DIAG_PORT);
            u.fwd_cnt = fwd;
            s.on_packet(&u, 0, 2);
            let (hs, data) = drain(&mut s, &doc, 2);
            all.extend_from_slice(&data);
            fwd += data.len() as u32;
            if hs.iter().any(|h| h.op == OP_SHUTDOWN) {
                let last = hs.last().unwrap();
                assert_eq!(last.flags, SHUTDOWN_RCV | SHUTDOWN_SEND);
                break;
            }
            assert!(!data.is_empty(), "no progress");
        }
        assert_eq!(all, doc);
        // The host resets: served and gone.
        s.on_packet(&from_host(OP_RST, DIAG_PORT), 0, 3);
        assert_eq!((s.open(), s.stats.served), (0, 1));
        assert!(drain(&mut s, &doc, 4).0.is_empty());
    }

    #[test]
    fn everything_else_is_reset_or_ignored() {
        let mut s = Stack::new(CID, DIAG_PORT);
        // Another port.
        s.on_packet(&from_host(OP_REQUEST, 22), 0, 0);
        // Another guest's CID: not ours to answer.
        s.on_packet(
            &Hdr {
                dst_cid: 9,
                ..from_host(OP_REQUEST, DIAG_PORT)
            },
            0,
            0,
        );
        // SEQPACKET.
        s.on_packet(
            &Hdr {
                ty: TYPE_SEQPACKET,
                ..from_host(OP_REQUEST, DIAG_PORT)
            },
            0,
            0,
        );
        // Data for a connection that does not exist; a stray reset.
        s.on_packet(&from_host(OP_RW, DIAG_PORT), 10, 0);
        s.on_packet(&from_host(OP_RST, DIAG_PORT), 0, 0);
        // A request from another guest (not the host).
        s.on_packet(
            &Hdr {
                src_cid: 77,
                ..from_host(OP_REQUEST, DIAG_PORT)
            },
            0,
            0,
        );
        let (hs, _) = drain(&mut s, b"doc", 1);
        assert!(hs.iter().all(|h| h.op == OP_RST), "{hs:?}");
        assert_eq!(hs.len(), 4);
        assert_eq!((s.stats.ignored, s.stats.refused, s.open()), (1, 1, 0));
    }

    #[test]
    fn connections_are_bounded_and_time_out() {
        let mut s = Stack::new(CID, DIAG_PORT);
        for p in 0..6u32 {
            let mut r = from_host(OP_REQUEST, DIAG_PORT);
            r.src_port = 1000 + p;
            r.buf_alloc = 0; // a peer that never gives credit
            s.on_packet(&r, 0, 0);
            drain(&mut s, b"doc", 0);
        }
        assert_eq!(
            (s.open(), s.stats.accepted, s.stats.refused),
            (MAX_CONNS, 4, 2)
        );
        // No credit, no progress: reset after IDLE_NS.
        let (hs, _) = drain(&mut s, b"doc", IDLE_NS + 1);
        assert_eq!(hs.iter().filter(|h| h.op == OP_RST).count(), MAX_CONNS);
        assert_eq!((s.open(), s.stats.timeouts), (0, 4));
    }

    #[test]
    fn a_peer_that_never_answers_the_shutdown_is_reset() {
        let mut s = Stack::new(CID, DIAG_PORT);
        s.on_packet(&from_host(OP_REQUEST, DIAG_PORT), 0, 0);
        let (hs, _) = drain(&mut s, b"tiny", 0);
        assert_eq!(hs.last().unwrap().op, OP_SHUTDOWN);
        assert_eq!(drain(&mut s, b"tiny", CLOSE_NS).0.len(), 0);
        let (hs, _) = drain(&mut s, b"tiny", CLOSE_NS + 1);
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].op, OP_RST);
        assert_eq!(s.open(), 0);
    }

    #[test]
    fn data_from_the_peer_is_discarded_with_credit_updates_and_shutdowns_end_it() {
        let doc = vec![0u8; 100_000];
        let mut s = Stack::new(CID, DIAG_PORT);
        s.on_packet(&from_host(OP_REQUEST, DIAG_PORT), 0, 0);
        drain(&mut s, &doc, 0);
        for _ in 0..9 {
            s.on_packet(&from_host(OP_RW, DIAG_PORT), 1000, 1);
        }
        let (hs, _) = drain(&mut s, &doc, 1);
        let u = hs.iter().find(|h| h.op == OP_CREDIT_UPDATE).unwrap();
        assert_eq!(u.fwd_cnt, 9000);
        s.on_packet(&from_host(OP_CREDIT_REQUEST, DIAG_PORT), 0, 1);
        assert_eq!(drain(&mut s, &doc, 1).0[0].op, OP_CREDIT_UPDATE);
        // The peer will not receive: reset and gone, though the document
        // is not finished.
        let mut sd = from_host(OP_SHUTDOWN, DIAG_PORT);
        sd.flags = SHUTDOWN_RCV;
        s.on_packet(&sd, 0, 2);
        assert_eq!((s.open(), s.stats.served), (0, 0));
        assert_eq!(drain(&mut s, &doc, 2).0[0].op, OP_RST);
    }

    #[test]
    fn credit_never_goes_negative_whatever_the_peer_claims() {
        let mut s = Stack::new(CID, DIAG_PORT);
        let mut r = from_host(OP_REQUEST, DIAG_PORT);
        r.buf_alloc = 100;
        s.on_packet(&r, 0, 0);
        let (_, data) = drain(&mut s, &[1u8; 1000], 0);
        assert_eq!(data.len(), 100);
        // A peer that claims to have forwarded more than was sent.
        let mut u = from_host(OP_CREDIT_UPDATE, DIAG_PORT);
        u.buf_alloc = 100;
        u.fwd_cnt = 5_000_000;
        s.on_packet(&u, 0, 1);
        let (_, data) = drain(&mut s, &[1u8; 1000], 1);
        assert!(data.len() <= 900);
    }

    fn vsock_device() -> FakeBus {
        let bus = FakeBus::new(F_VERSION_1 | F_STREAM | F_SEQPACKET, &[8, 8, 8], 8);
        bus.set_cfg(0, &CID.to_le_bytes());
        bus
    }

    fn send(bus: &FakeBus, h: &Hdr, payload: &[u8]) {
        let (head, segs) = bus.pop(RXQ).unwrap();
        let mut b = h.encode().to_vec();
        b.extend_from_slice(payload);
        let n = FakeBus::fill(&segs, &b);
        bus.complete(RXQ, u32::from(head), n);
    }

    #[test]
    fn the_driver_serves_a_connection_through_the_device() {
        let bus = vsock_device();
        let env = FakeEnv::default();
        let mut v = VirtioVsock::new(&bus, &env, DIAG_PORT).unwrap();
        assert_eq!(bus.accepted.get(), F_VERSION_1 | F_STREAM);
        assert_eq!(v.stack.guest_cid, CID);
        let doc = br#"{"urmqtt_diag":1}"#;
        send(&bus, &from_host(OP_REQUEST, DIAG_PORT), &[]);
        v.poll(doc, 1);
        let mut ops = Vec::new();
        let mut got = Vec::new();
        while let Some((head, segs)) = bus.pop(TXQ) {
            let b = FakeBus::read(&segs);
            let h = Hdr::parse(&b).unwrap();
            assert_eq!(b.len(), HDR_LEN + h.len as usize);
            got.extend_from_slice(&b[HDR_LEN..]);
            ops.push(h.op);
            bus.complete(TXQ, u32::from(head), 0);
        }
        assert_eq!(ops, [OP_RESPONSE, OP_RW, OP_SHUTDOWN]);
        assert_eq!(got, doc);
        send(&bus, &from_host(OP_RST, DIAG_PORT), &[]);
        v.poll(doc, 2);
        assert_eq!((v.stack.stats.served, v.protocol_errors), (1, 0));
    }

    #[test]
    fn a_header_that_claims_more_payload_than_arrived_counts_only_what_arrived() {
        let bus = vsock_device();
        let env = FakeEnv::default();
        let mut v = VirtioVsock::new(&bus, &env, DIAG_PORT).unwrap();
        send(&bus, &from_host(OP_REQUEST, DIAG_PORT), &[]);
        v.poll(&[0u8; 1 << 20], 1);
        let mut h = from_host(OP_RW, DIAG_PORT);
        h.len = u32::MAX;
        for _ in 0..9 {
            send(&bus, &h, &[7u8; 1000]);
            v.poll(&[0u8; 1 << 20], 1);
        }
        // Short packets are protocol errors.
        let (head, segs) = bus.pop(RXQ).unwrap();
        FakeBus::fill(&segs, &[0u8; 10]);
        bus.complete(RXQ, u32::from(head), 10);
        v.poll(&[], 1);
        assert_eq!(v.protocol_errors, 1);
    }

    #[test]
    fn a_transport_reset_drops_every_connection_and_bad_cids_are_refused() {
        let bus = vsock_device();
        let env = FakeEnv::default();
        let mut v = VirtioVsock::new(&bus, &env, DIAG_PORT).unwrap();
        send(&bus, &from_host(OP_REQUEST, DIAG_PORT), &[]);
        v.poll(&[0u8; 1 << 20], 1);
        assert_eq!(v.stack.open(), 1);
        let (head, segs) = bus.pop(EVQ).unwrap();
        let n = FakeBus::fill(&segs, &EVENT_TRANSPORT_RESET.to_le_bytes());
        bus.complete(EVQ, u32::from(head), n);
        v.poll(&[], 2);
        assert_eq!((v.stack.open(), v.transport_resets), (0, 1));
        for cid in [0u64, 1, 2, u64::MAX, 0xffff_ffff] {
            let bus = FakeBus::new(F_VERSION_1, &[8, 8, 8], 8);
            bus.set_cfg(0, &cid.to_le_bytes());
            assert_eq!(
                VirtioVsock::new(&bus, &env, DIAG_PORT).err(),
                Some(VirtioError::OutOfRange)
            );
        }
    }
}
