//! virtio-net (virtio 1.x §5.1): queue pairs without offloads.
//!
//! One receive/transmit pair by default. With `VIRTIO_NET_F_MQ`,
//! `VIRTIO_NET_F_CTRL_VQ` and `VIRTIO_NET_F_RSS` offered, and more than one
//! pair asked for, the driver sets up one pair per data core and later
//! programs the device's receive-side scaling through the control queue
//! (NEXT-6, ADR-310 to ADR-312): the device then puts every TCP/IPv4 frame
//! on the queue its Toeplitz hash names, with the same key and indirection
//! table the kernel's software steering uses, and everything else on queue
//! 0. A device that offers less, refuses the configuration or has no room
//! for a pair per core gets the single pair, exactly as before.
//!
//! Each pair is a [`NetQueue`] that can move to the core that owns it with
//! its own doorbell ([`Kick`]). Transmit is asynchronous: each TX
//! descriptor has its own bounce buffer, completed ones are reclaimed
//! lazily, and the device is kicked once per batch ([`NetQueue::queue`] +
//! [`NetQueue::flush`]) and only when it asks for notifications. Received
//! buffers are recycled the same way (M13: one VM exit per batch instead of
//! two per frame). A receive queue can signal an MSI-X vector that wakes the
//! sleeping core that owns it (ADR-270, per queue since ADR-311).

use crate::bus::{Bus, Kick};
use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::{Env, F_VERSION_1, VirtioError};

pub const F_MAC: u64 = 1 << 5;
pub const F_STATUS: u64 = 1 << 16;
pub const F_CTRL_VQ: u64 = 1 << 17;
pub const F_MQ: u64 = 1 << 22;
/// The device reports the hash in each header (not negotiated, ADR-310).
pub const F_HASH_REPORT: u64 = 1 << 57;
pub const F_RSS: u64 = 1 << 60;

/// `virtio_net_hdr` with VERSION_1 (includes `num_buffers`).
pub const HDR_LEN: usize = 12;
/// Ethernet frame without FCS, plus header.
pub const BUF_LEN: usize = 2048;
pub const MTU_FRAME: usize = 1514;
/// Shortest Ethernet frame without the FCS; shorter ones are zero-padded.
pub const MIN_FRAME: usize = 60;
/// Descriptors asked for (the device may offer fewer): a deeper receive ring is
/// what a core that is descheduled for some milliseconds can afford (ADR-266).
const RX_BUFFERS: u16 = 1024;
const TX_BUFFERS: u16 = 1024;

/// Most queue pairs the driver sets up (a data core each; ADR-310): 16 pairs
/// of 1 024-descriptor queues are 64 MiB of bounce buffers.
pub const MAX_PAIRS: usize = 16;
/// Entries of the RSS indirection table the driver programs; the kernel's
/// software steering uses a table of the same length (ADR-311).
pub const RSS_TABLE_LEN: usize = 128;
/// The RSS key length (the Microsoft key, 40 bytes).
pub const RSS_KEY_LEN: usize = 40;
/// `VIRTIO_NET_RSS_HASH_TYPE_TCPv4`: the 4-tuple of TCP over IPv4.
pub const HASH_TCPV4: u32 = 1 << 1;

// Device configuration (§5.1.4).
const CFG_STATUS: usize = 6;
const CFG_MAX_PAIRS: usize = 8;
const CFG_RSS_MAX_KEY: usize = 17;
const CFG_RSS_MAX_TABLE: usize = 18;
const CFG_HASH_TYPES: usize = 20;

// Control queue (§5.1.6.5).
const CTRL_CLASS_MQ: u8 = 4;
const CTRL_MQ_RSS_CONFIG: u8 = 1;
const CTRL_OK: u8 = 0;
/// The RSS_CONFIG command: class, command, then the configuration.
pub const RSS_COMMAND_LEN: usize = 2 + 4 + 2 + 2 + 2 * RSS_TABLE_LEN + 2 + 1 + RSS_KEY_LEN;
const CTRL_TIMEOUT_NS: u64 = 1_000_000_000;
/// Where the device writes its one-byte answer in the command buffer.
const CTRL_ACK_OFF: usize = 512;

/// Why the driver uses one queue pair (ADR-310's boot line names it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Single {
    /// One pair was asked for (one data core, or `devices.virtio_net_queues
    /// = "single"`).
    NotAsked,
    /// The device does not offer `VIRTIO_NET_F_MQ`.
    NoMq,
    /// The device offers multiqueue but not RSS (or no control queue): it
    /// would place flows by its own hash, which the kernel cannot match.
    NoRss,
    /// The device offers one pair only (`max_virtqueue_pairs` < 2).
    OnePair,
    /// The device's RSS cannot take the 40-byte key, the 128-entry table or
    /// the TCP/IPv4 hash.
    RssLimits,
    /// A queue of the second pair or the control queue could not be set up.
    QueueSetup,
    /// The device refused the RSS configuration (or did not answer).
    Refused,
}

impl Single {
    /// For the boot log.
    pub const fn text(self) -> &'static str {
        match self {
            Self::NotAsked => "one queue pair asked for",
            Self::NoMq => "the device offers one queue pair (no VIRTIO_NET_F_MQ)",
            Self::NoRss => {
                "the device offers multiqueue without RSS, so it cannot steer flows as the kernel does"
            }
            Self::OnePair => "the device offers one queue pair (max_virtqueue_pairs < 2)",
            Self::RssLimits => {
                "the device's RSS cannot take a 40-byte key, a 128-entry table and the TCP/IPv4 hash"
            }
            Self::QueueSetup => {
                "the device could not set up a second queue pair or the control queue"
            }
            Self::Refused => "the device refused the RSS configuration",
        }
    }
}

/// What the device says about multiqueue and RSS, read from its
/// configuration (untrusted: [`plan`] checks every field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceLimits {
    pub max_pairs: u16,
    pub rss_max_key: u8,
    pub rss_max_table: u16,
    pub hash_types: u32,
}

impl DeviceLimits {
    /// Reads the fields (consistently, §4.1.4.5). They exist only when the
    /// device offers MQ or RSS; the caller reads them only then.
    pub fn read<B: Bus>(bus: &B) -> Self {
        crate::bus::cfg_consistent(bus, |b| Self {
            max_pairs: b.cfg_read16(CFG_MAX_PAIRS),
            rss_max_key: b.cfg_read8(CFG_RSS_MAX_KEY),
            rss_max_table: b.cfg_read16(CFG_RSS_MAX_TABLE),
            hash_types: b.cfg_read32(CFG_HASH_TYPES),
        })
    }
}

/// How many queue pairs to set up: `Ok(n)` with `n >= 2`, or why one.
/// `accepted` is the negotiated feature set, `want` the pairs asked for.
pub fn plan(accepted: u64, limits: DeviceLimits, want: usize) -> Result<usize, Single> {
    if want < 2 {
        return Err(Single::NotAsked);
    }
    if accepted & F_MQ == 0 {
        return Err(Single::NoMq);
    }
    if accepted & (F_RSS | F_CTRL_VQ) != F_RSS | F_CTRL_VQ {
        return Err(Single::NoRss);
    }
    // §5.1.4: max_virtqueue_pairs is 1 to 0x8000.
    if limits.max_pairs < 2 || limits.max_pairs > 0x8000 {
        return Err(Single::OnePair);
    }
    if usize::from(limits.rss_max_key) < RSS_KEY_LEN
        || usize::from(limits.rss_max_table) < RSS_TABLE_LEN
        || limits.hash_types & HASH_TCPV4 == 0
    {
        return Err(Single::RssLimits);
    }
    Ok(want.min(MAX_PAIRS).min(usize::from(limits.max_pairs)))
}

/// The `VIRTIO_NET_CTRL_MQ_RSS_CONFIG` command (§5.1.6.5.7.1): TCP/IPv4
/// hashing only, `table` (queue per entry), unclassified frames to queue 0,
/// `pairs` transmit queues, and `key`.
pub fn rss_command(
    table: &[u16; RSS_TABLE_LEN],
    pairs: u16,
    key: &[u8; RSS_KEY_LEN],
) -> [u8; RSS_COMMAND_LEN] {
    let mut c = [0u8; RSS_COMMAND_LEN];
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| {
        if let Some(d) = c.get_mut(at..at + bytes.len()) {
            d.copy_from_slice(bytes);
        }
        at += bytes.len();
    };
    put(&[CTRL_CLASS_MQ, CTRL_MQ_RSS_CONFIG]);
    put(&HASH_TCPV4.to_le_bytes());
    put(&((RSS_TABLE_LEN - 1) as u16).to_le_bytes());
    // unclassified_queue: ARP, ICMP, UDP (DHCP, SNTP) go to core 0.
    put(&0u16.to_le_bytes());
    for q in table {
        put(&q.to_le_bytes());
    }
    put(&pairs.to_le_bytes());
    put(&[RSS_KEY_LEN as u8]);
    put(key);
    c
}

/// Index of the receive and transmit queue of pair `k`, and of the control
/// queue of a device with `max_pairs` pairs (§5.1.2).
pub const fn rx_index(k: u16) -> u16 {
    2 * k
}
pub const fn tx_index(k: u16) -> u16 {
    2 * k + 1
}
/// `None` when the index does not fit a 16-bit queue number: §5.1.4 allows
/// `max_virtqueue_pairs` up to 0x8000, whose control queue (0x10000) no
/// `queue_select` can name; such a device gets one pair (wrapping to 0 would
/// set up pair 0's receive queue a second time as the control queue).
pub const fn ctrl_index(max_pairs: u16) -> Option<u16> {
    max_pairs.checked_mul(2)
}

/// Per-queue counters, kept by the core that owns the queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Frames taken from the receive queue.
    pub received: u64,
    /// Frames queued for transmission.
    pub sent: u64,
    /// Frames not sent because every transmit descriptor was in flight.
    pub tx_full: u64,
}

/// One receive/transmit queue pair and its buffers.
pub struct NetQueue<K: Kick> {
    kick: K,
    /// The pair's index (queue 2k receives, 2k+1 transmits).
    pub pair: u16,
    rx: SplitQueue,
    tx: SplitQueue,
    rx_notify: usize,
    tx_notify: usize,
    rx_bufs: DmaRegion,
    tx_bufs: DmaRegion,
    /// Buffers made available since the last kick.
    rx_unkicked: bool,
    tx_unkicked: bool,
    /// Frames dropped because every TX descriptor was in flight.
    pub tx_full: u64,
    /// Descriptors of the receive and the transmit queue (what the device
    /// allows, at most 1 024).
    pub rx_size: u16,
    pub tx_size: u16,
    /// The receive queue signals an MSI-X vector (ADR-270); `false`: polled.
    pub rx_irq: bool,
    /// The device refused the vector it was offered (the queue is polled).
    pub msix_rejected: bool,
    pub stats: QueueStats,
}

impl<K: Kick> NetQueue<K> {
    /// Sets up pair `pair` (both rings, their bounce buffers and the posted
    /// receive buffers); the receive queue signals MSI-X entry `msix` if
    /// given and accepted. Interrupts start suppressed on both queues.
    fn new<B: Bus<Kick = K>, E: Env>(
        bus: &B,
        env: &E,
        pair: u16,
        msix: Option<u16>,
    ) -> Result<Self, VirtioError> {
        let (rxi, txi) = (rx_index(pair), tx_index(pair));
        let rx_size = RX_BUFFERS.min(bus.queue_max(rxi));
        let tx_size = TX_BUFFERS.min(bus.queue_max(txi));
        if rx_size == 0 {
            return Err(VirtioError::QueueUnavailable(rxi));
        }
        if tx_size == 0 {
            return Err(VirtioError::QueueUnavailable(txi));
        }
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
        rx.suppress_interrupts();
        tx.suppress_interrupts();
        let (rx_notify, msix_rejected) = match bus.setup_queue(rxi, &rx, msix) {
            Ok(off) => (off, false),
            // Refused before the queue was enabled: set it up again, polled.
            Err(VirtioError::MsixRejected) => (bus.setup_queue(rxi, &rx, None)?, true),
            Err(e) => return Err(e),
        };
        let tx_notify = bus.setup_queue(txi, &tx, None)?;
        let rx_bufs = env
            .dma_alloc(BUF_LEN * usize::from(rx_size))
            .ok_or(VirtioError::NoDma)?;
        let tx_bufs = env
            .dma_alloc(BUF_LEN * usize::from(tx_size))
            .ok_or(VirtioError::NoDma)?;
        for i in 0..rx_size {
            rx.add(&[Buf {
                pa: rx_bufs.pa + u64::from(i) * BUF_LEN as u64,
                len: BUF_LEN as u32,
                device_writes: true,
            }])?;
        }
        Ok(Self {
            kick: bus.kicker(),
            pair,
            rx,
            tx,
            rx_notify,
            tx_notify,
            rx_bufs,
            tx_bufs,
            // The posted buffers are announced after DRIVER_OK.
            rx_unkicked: true,
            tx_unkicked: false,
            tx_full: 0,
            rx_size,
            tx_size,
            rx_irq: msix.is_some() && !msix_rejected,
            msix_rejected,
            stats: QueueStats::default(),
        })
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
            self.stats.tx_full += 1;
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
        self.stats.sent += 1;
        Ok(())
    }

    /// Kicks the device for queued TX frames and recycled RX buffers.
    pub fn flush(&mut self) {
        if self.tx_unkicked {
            self.tx_unkicked = false;
            if self.tx.device_wants_notify() {
                self.kick.kick(self.tx_notify, tx_index(self.pair));
            }
        }
        if self.rx_unkicked {
            self.rx_unkicked = false;
            if self.rx.device_wants_notify() {
                self.kick.kick(self.rx_notify, rx_index(self.pair));
            }
        }
    }

    /// Whether a received frame is waiting (cheap: one ring index read).
    pub fn rx_pending(&self) -> bool {
        self.rx.has_used()
    }

    /// Before the owning core sleeps: asks for the receive interrupt and
    /// re-checks the ring. `true`: a frame is already there, do not sleep.
    /// Polled queues (no vector) only re-check.
    pub fn rx_irq_arm(&self) -> bool {
        if self.rx_irq {
            self.rx.enable_interrupts()
        } else {
            self.rx.has_used()
        }
    }

    /// After the sleep: no receive interrupts while the core works.
    pub fn rx_irq_disarm(&self) {
        self.rx.suppress_interrupts();
    }

    /// How many received frames wait in the queue, unread.
    pub fn rx_queued(&self) -> u16 {
        self.rx.used_pending()
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
        // `pop_used`), which lies inside `rx_bufs`; `frame_len` is at most
        // BUF_LEN - HDR_LEN, so the slice stays inside that buffer.
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
        self.stats.received += 1;
        Ok(Some(n))
    }
}

/// The device: its first queue pair (which the driver keeps; [`Deref`]
/// reaches it), the others until their cores take them, and the control
/// queue.
///
/// [`Deref`]: core::ops::Deref
pub struct VirtioNet<B: Bus = crate::transport::Transport> {
    bus: B,
    q0: NetQueue<B::Kick>,
    /// Pairs 1.. until [`take_queue`](Self::take_queue).
    more: [Option<NetQueue<B::Kick>>; MAX_PAIRS],
    ctrl: Option<(SplitQueue, usize, u16)>,
    cmd: Option<DmaRegion>,
    pub mac: [u8; 6],
    pub features: u64,
    /// Queue pairs set up (1 without multiqueue).
    pub pairs: u16,
    /// Pairs the device steers to (1 until [`enable_rss`](Self::enable_rss)).
    pub active: u16,
    /// Why one pair, when one.
    pub single: Option<Single>,
    /// What the device said (zero without MQ/RSS).
    pub limits: DeviceLimits,
}

impl<B: Bus> core::ops::Deref for VirtioNet<B> {
    type Target = NetQueue<B::Kick>;
    fn deref(&self) -> &Self::Target {
        &self.q0
    }
}

impl<B: Bus> core::ops::DerefMut for VirtioNet<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.q0
    }
}

impl<B: Bus> VirtioNet<B> {
    pub fn new<E: Env>(t: B, env: &E) -> Result<Self, VirtioError> {
        Self::new_with_msix(t, env, None)
    }

    /// Like [`new`](Self::new), with the receive queue signalling MSI-X
    /// vector `msix` (MSI-X must already be enabled in PCI config space). A
    /// device that refuses the vector gets a polled queue instead
    /// ([`msix_rejected`](NetQueue::msix_rejected)). Interrupts start
    /// suppressed on both queues: the transmit queue never asks for one (its
    /// descriptors are reclaimed lazily, and a core with frames waiting for
    /// them does not sleep), the receive queue only while the core sleeps
    /// ([`rx_irq_arm`](NetQueue::rx_irq_arm)).
    pub fn new_with_msix<E: Env>(t: B, env: &E, msix: Option<u16>) -> Result<Self, VirtioError> {
        Self::new_multi(t, env, 1, |k| if k == 0 { msix } else { None })
    }

    /// Up to `want` queue pairs (ADR-310): multiqueue and RSS are negotiated
    /// only when `want >= 2` and the device offers all three of MQ, the
    /// control queue and RSS; otherwise the device is driven exactly as with
    /// one pair. `vector(k)` is the MSI-X entry of pair `k`'s receive queue.
    /// The device steers to one pair until [`enable_rss`](Self::enable_rss).
    pub fn new_multi<E: Env>(
        t: B,
        env: &E,
        want: usize,
        vector: impl Fn(u16) -> Option<u16>,
    ) -> Result<Self, VirtioError> {
        let mq = F_MQ | F_CTRL_VQ | F_RSS;
        let wanted = F_MAC | F_STATUS | if want >= 2 { mq } else { 0 };
        let features = t.init(env, wanted, F_VERSION_1)?;
        // All three or none: a device with only some of them is driven as
        // one without (MQ alone is harmless, §5.1.6.5.5: multiqueue starts
        // disabled; the boot line still says why).
        let limits = if features & (F_MQ | F_RSS) != 0 {
            DeviceLimits::read(&t)
        } else {
            DeviceLimits::default()
        };
        let mut planned = plan(features, limits, want);
        let q0 = NetQueue::new(&t, env, 0, vector(0))?;
        let mut more: [Option<NetQueue<B::Kick>>; MAX_PAIRS] = core::array::from_fn(|_| None);
        let mut pairs = 1u16;
        let mut ctrl = None;
        let mut cmd = None;
        if let Ok(n) = planned {
            match Self::setup_more(&t, env, n, limits.max_pairs, &vector, &mut more) {
                Ok((c, region)) => {
                    pairs = n as u16;
                    ctrl = Some(c);
                    cmd = Some(region);
                }
                Err(()) => {
                    more = core::array::from_fn(|_| None);
                    planned = Err(Single::QueueSetup);
                }
            }
        }
        let mut mac = [0u8; 6];
        if features & F_MAC != 0 {
            for (i, b) in mac.iter_mut().enumerate() {
                *b = t.cfg_read8(i);
            }
        }
        t.driver_ok()?;
        let mut net = Self {
            bus: t,
            q0,
            more,
            ctrl,
            cmd,
            mac,
            features,
            pairs,
            active: 1,
            single: planned.err(),
            limits,
        };
        net.q0.flush();
        for q in net.more.iter_mut().flatten() {
            q.flush();
        }
        Ok(net)
    }

    /// Pairs 1..n and the control queue (before DRIVER_OK, §3.1.1).
    #[allow(clippy::type_complexity)]
    fn setup_more<E: Env>(
        bus: &B,
        env: &E,
        n: usize,
        max_pairs: u16,
        vector: &impl Fn(u16) -> Option<u16>,
        more: &mut [Option<NetQueue<B::Kick>>; MAX_PAIRS],
    ) -> Result<((SplitQueue, usize, u16), DmaRegion), ()> {
        // Checked first: no pair is set up for a control queue that cannot be.
        let ci = ctrl_index(max_pairs).ok_or(())?;
        for k in 1..n {
            let pair = k as u16;
            let q = NetQueue::new(bus, env, pair, vector(pair)).map_err(|_| ())?;
            if let Some(slot) = more.get_mut(k) {
                *slot = Some(q);
            }
        }
        let (q, off) = crate::bus::make_queue(bus, env, ci, 8).map_err(|_| ())?;
        let region = env.dma_alloc(4096).ok_or(())?;
        Ok(((q, off, ci), region))
    }

    /// Link up according to the device (always true without F_STATUS).
    pub fn link_up(&self) -> bool {
        self.features & F_STATUS == 0 || self.bus.cfg_read16(CFG_STATUS) & 1 != 0
    }

    /// Programs the device's RSS (ADR-311): `table[i]` is the pair that
    /// frames whose hash has low bits `i` go to, `active` the pairs in use
    /// (every entry must be below it), `key` the Toeplitz key. On success the
    /// device spreads TCP/IPv4 frames over the pairs; on failure it keeps
    /// using pair 0 alone ([`single`](Self::single) says why) and the other
    /// pairs must not be used.
    pub fn enable_rss<E: Env>(
        &mut self,
        env: &E,
        table: &[u16; RSS_TABLE_LEN],
        active: u16,
        key: &[u8; RSS_KEY_LEN],
    ) -> Result<(), Single> {
        let ok = active >= 2 && active <= self.pairs && table.iter().all(|q| *q < active);
        if !ok || self.ctrl.is_none() {
            return Err(self.fail(Single::NotAsked));
        }
        let Some(cmd) = self.cmd else {
            return Err(self.fail(Single::NotAsked));
        };
        let bytes = rss_command(table, active, key);
        let ack_off = CTRL_ACK_OFF;
        // A value the device must overwrite: an answer that is not written
        // counts as a refusal.
        let posted =
            crate::bus::dma_write(&cmd, 0, &bytes) && crate::bus::dma_write(&cmd, ack_off, &[0xff]);
        if !posted {
            return Err(self.fail(Single::Refused));
        }
        let Some((q, off, ci)) = self.ctrl.as_mut() else {
            return Err(self.fail(Single::NotAsked));
        };
        let head = q.add(&[
            Buf {
                pa: cmd.pa,
                len: RSS_COMMAND_LEN as u32,
                device_writes: false,
            },
            Buf {
                pa: cmd.pa + ack_off as u64,
                len: 1,
                device_writes: true,
            },
        ]);
        let (off, ci) = (*off, *ci);
        let Ok(head) = head else {
            return Err(self.fail(Single::Refused));
        };
        self.bus.notify(off, ci);
        let done = match self.ctrl.as_mut() {
            Some((q, _, _)) => crate::wait_used(env, q, CTRL_TIMEOUT_NS, "virtio-net control"),
            None => Err(VirtioError::QueueUnavailable(ci)),
        };
        let mut ack = [0xffu8];
        let read = crate::bus::dma_read(&cmd, ack_off, &mut ack);
        match done {
            Ok((id, written)) if id == head && written >= 1 && read && ack[0] == CTRL_OK => {
                self.active = active;
                self.single = None;
                Ok(())
            }
            _ => Err(self.fail(Single::Refused)),
        }
    }

    fn fail(&mut self, why: Single) -> Single {
        self.active = 1;
        self.single = Some(why);
        self.more = core::array::from_fn(|_| None);
        why
    }

    /// Hands pair `k` (1 ≤ k < [`active`](Self::active)) to the core that
    /// will own it; `None` if there is none or it was taken.
    pub fn take_queue(&mut self, k: u16) -> Option<NetQueue<B::Kick>> {
        if k == 0 || k >= self.active {
            return None;
        }
        self.more.get_mut(usize::from(k))?.take()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests;
