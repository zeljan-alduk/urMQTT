//! Multicore data plane (M13, ADR-032).
//!
//! Data cores are CPUs `0..n`; the DB core, if any, is the last CPU. Every
//! data core runs its own event loop: its own smoltcp instance (TCP state),
//! TLS sessions and a broker *shard*. With two or more data cores, core 0
//! is the dispatcher only and cores `1..n` are the MQTT workers
//! ([`workers`]). Cores share nothing but SPSC rings:
//!
//! - **Frames:** core 0 owns the single virtio-net queue pair. It steers
//!   each received TCP frame to the core chosen by the Toeplitz hash of the
//!   4-tuple, sending the buffer itself (no further copy) over a 0→c ring.
//!   Cores send their frames back over a c→0 ring for transmission.
//! - **Sessions:** a session lives on its *home* core, `fnv1a(client id) %
//!   n`, so takeover and persistence stay core-local. A connection accepted
//!   on another core (its *transport* core keeps TCP and TLS) is relayed to
//!   the home core as plaintext MQTT bytes, with credit-based flow control
//!   for the replies.
//! - **Fan-out:** every message a shard routes is offered to all other
//!   shards, which route it to their own subscribers (and update their
//!   replica of retained messages).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use urmqtt_arch::{cpu, time};
use urmqtt_broker::Msg;
use urmqtt_mqtt::QoS;
use urmqtt_sync::spsc::{Consumer, Producer, Spsc};
use urmqtt_sync::sync::OnceCell;
use urmqtt_virtio::net::MTU_FRAME;

pub const MSG_RING: usize = 512;
pub const FRAME_RING: usize = 512;
/// Frame buffers a core keeps for reuse; extra ones are freed.
pub const POOL_MAX: usize = 512;

/// A frame buffer that moves between cores without copying.
pub struct FrameBuf {
    pub len: usize,
    pub data: [u8; MTU_FRAME],
}

pub type Frame = Box<FrameBuf>;

/// Frame buffers alive (in rings, pools or in use): a bounded, load-
/// dependent amount reported apart from per-connection memory.
pub static FRAMES: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

pub fn new_frame() -> Frame {
    // Relaxed: statistics.
    FRAMES.fetch_add(1, Ordering::Relaxed);
    Box::new(FrameBuf {
        len: 0,
        data: [0; MTU_FRAME],
    })
}

impl Drop for FrameBuf {
    fn drop(&mut self) {
        // Relaxed: statistics.
        FRAMES.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection relayed between a transport core and a home core is named
/// by the transport core's slot and a generation, so a late message never
/// reaches a reused slot.
pub type Tconn = u64;

/// Messages between data cores (one ring per ordered pair).
pub enum CoreMsg {
    /// Transport → home: a new connection (identity from TLS, if any).
    Open {
        tconn: Tconn,
        identity: Option<Box<str>>,
        /// The certificate came from a bootstrap anchor (H1).
        bootstrap: bool,
    },
    /// Transport → home: plaintext MQTT bytes from the client.
    Input { tconn: Tconn, data: Vec<u8> },
    /// Transport → home: the connection is gone.
    Closed { tconn: Tconn },
    /// Transport → home: this many reply bytes were taken; send more.
    Credit { tconn: Tconn, bytes: u32 },
    /// Home → transport: plaintext MQTT bytes for the client.
    Output { tconn: Tconn, data: Vec<u8> },
    /// Home → transport: close after the pending output.
    Close { tconn: Tconn },
    /// Shard → shard: a message routed at its origin.
    Route { msg: Msg, qos: QoS, retain: bool },
    /// Core 0 → all: the interface address changed (DHCP).
    IpConfig {
        addr: Option<([u8; 4], u8)>,
        router: Option<[u8; 4]>,
    },
}

struct Mesh {
    n: usize,
    /// `from * n + to`.
    msgs: Vec<Box<Spsc<CoreMsg, MSG_RING>>>,
    /// Index `c`: core 0 → core c (received frames).
    rx: Vec<Box<Spsc<Frame, FRAME_RING>>>,
    /// Index `c`: core c → core 0 (frames to transmit).
    tx: Vec<Box<Spsc<Frame, FRAME_RING>>>,
}

static MESH: OnceCell<Mesh> = OnceCell::new();

/// Adaptive polling (PROMPT §7.2): a core busy-polls while there is work
/// and for [`SPIN_NS`] after it, then sleeps in WFI. WFE cannot be used:
/// under HVF, QEMU treats it as a no-op, so idle cores would spin at 100 %
/// of a host CPU and slow the busy ones down (ADR-032).
pub const SPIN_NS: u64 = 100_000;

/// Set by a core right before it sleeps; producers wake it with an SGI.
static SLEEPING: [AtomicBool; crate::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::smp::MAX_CPUS];

/// Wakes `cpu` if it is (about to be) asleep. Call after making work
/// visible to it (a ring push).
pub fn wake(cpu: usize) {
    // SeqCst fence + load: either the sleeper's re-check sees our work, or
    // we see its flag (the store-load order both sides need).
    fence(Ordering::SeqCst);
    if SLEEPING.get(cpu).is_some_and(|f| f.load(Ordering::Relaxed)) {
        crate::smp::send_wake(cpu);
    }
}

/// One core's idle state and load statistics.
pub struct Idle {
    last_work_ns: u64,
    /// Time spent asleep in WFI since `window_start_ns`.
    slept_ns: u64,
    window_start_ns: u64,
    passes: u64,
}

/// Nanoseconds this core spent in TLS processing (handshakes, records),
/// for the load statistics.
pub static TLS_NS: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];
/// Frames moved by the dispatcher (core 0), for the load statistics.
pub static DISPATCHED: AtomicU64 = AtomicU64::new(0);
/// Connections accepted per core.
pub static ACCEPTED: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];
const STATS_WINDOW_NS: u64 = 5_000_000_000;

impl Idle {
    pub fn new() -> Self {
        Self {
            last_work_ns: 0,
            slept_ns: 0,
            window_start_ns: time::uptime_ns(),
            passes: 0,
        }
    }

    /// Logs this core's load every 5 s while it has accepted connections.
    fn stats(&mut self, now: u64) {
        self.passes += 1;
        let window = now.saturating_sub(self.window_start_ns);
        if window < STATS_WINDOW_NS {
            return;
        }
        let me = crate::smp::current();
        // Relaxed: statistics only, written by this core.
        let tls = TLS_NS.get(me).map_or(0, |a| a.swap(0, Ordering::Relaxed));
        let acc = ACCEPTED.get(me).map_or(0, |a| a.swap(0, Ordering::Relaxed));
        let frames = if me == 0 {
            DISPATCHED.swap(0, Ordering::Relaxed)
        } else {
            0
        };
        if acc > 0 || tls > 0 || frames > 0 {
            urmqtt_log::info!(
                "dataplane: core {me}: busy {}%, tls {}%, {acc} connection(s) accepted, {frames} frame(s) dispatched, \
                 {} loop passes in {} ms",
                100 - (self.slept_ns * 100 / window.max(1)).min(100),
                tls * 100 / window.max(1),
                self.passes,
                window / 1_000_000
            );
        }
        self.slept_ns = 0;
        self.passes = 0;
        self.window_start_ns = now;
    }

    /// Called once per loop pass. Sleeps when there was no work for a
    /// while and `pending()` (re-checked after announcing the sleep) finds
    /// none. The 10 ms tick and wake SGIs end the sleep.
    pub fn pass(&mut self, worked: bool, pending: impl Fn() -> bool) {
        if let Some(l) = LOOPS.get(crate::smp::current()) {
            // Relaxed: a progress counter for the health check.
            l.fetch_add(1, Ordering::Relaxed);
        }
        let now = time::uptime_ns();
        self.stats(now);
        if worked {
            self.last_work_ns = now;
            return;
        }
        if now.saturating_sub(self.last_work_ns) < SPIN_NS {
            core::hint::spin_loop();
            return;
        }
        let me = crate::smp::current();
        let Some(flag) = SLEEPING.get(me) else { return };
        // Relaxed + SeqCst fence: pairs with the fence in `wake`.
        flag.store(true, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        if !pending() {
            cpu::wait_for_interrupt();
        }
        flag.store(false, Ordering::Relaxed);
        self.last_work_ns = time::uptime_ns();
        self.slept_ns += self.last_work_ns.saturating_sub(now);
    }
}

impl Default for Idle {
    fn default() -> Self {
        Self::new()
    }
}

/// Loop passes per core: the health check's evidence of progress (M16).
pub static LOOPS: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];

/// TCP connections per core (for the memory report).
pub static CONNECTIONS: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];
/// Frame-buffer bytes (requested, in heap blocks) at the baseline.
static FRAMES_AT_BASELINE: [core::sync::atomic::AtomicI64; 2] =
    [const { core::sync::atomic::AtomicI64::new(0) }; 2];
/// Live heap bytes (requested, in heap blocks) when the data plane started
/// or was last idle.
pub static BASELINE: [core::sync::atomic::AtomicI64; 2] =
    [const { core::sync::atomic::AtomicI64::new(0) }; 2];
const MEM_REPORT_MS: u64 = 10_000;

/// Heap in use now: (requested bytes, bytes in heap blocks).
fn heap_usage() -> [i64; 2] {
    [crate::vm::HEAP.live_bytes(), crate::vm::HEAP.block_bytes()]
}

/// Frame buffers alive: (requested bytes, bytes in heap blocks).
fn frame_usage() -> [i64; 2] {
    let layout = core::alloc::Layout::new::<FrameBuf>();
    // Relaxed: statistics.
    let n = FRAMES.load(Ordering::Relaxed);
    [
        n * layout.size() as i64,
        n * urmqtt_mm::cached::block_size(layout) as i64,
    ]
}

/// Free heap bytes below which new connections are refused
/// (`memory.min_free_mb`, M16).
static HEAP_RESERVE: AtomicU64 = AtomicU64::new(0);

/// Sets the free-heap reserve; a dev `heap_limit_mb=` pretends the heap is
/// only that large (the rest counts as reserved).
pub fn set_heap_reserve(limit_mb: Option<u32>) {
    let min_free = u64::from(urmqtt_config::CONFIG.memory.min_free_mb) << 20;
    let capacity = crate::vm::HEAP.stats().map_or(0, |(_, c)| c as u64);
    let hidden = limit_mb.map_or(0, |mb| capacity.saturating_sub(u64::from(mb) << 20));
    // Relaxed: set once before the data cores start (their start is the
    // synchronising event), read as a plain threshold afterwards.
    HEAP_RESERVE.store(min_free + hidden, Ordering::Relaxed);
    let used = crate::vm::HEAP
        .stats()
        .map_or(0, |(free, cap)| (cap - free) as u64);
    urmqtt_log::info!(
        "mem: heap {} MiB, {} KiB in use; new connections refused below {} MiB free{}",
        capacity >> 20,
        used >> 10,
        (min_free + hidden) >> 20,
        if limit_mb.is_some() {
            " (dev heap_limit_mb)"
        } else {
            ""
        }
    );
}

/// Whether the heap can take another connection: free bytes (the global
/// heap; blocks cached per CPU count as used) above the reserve.
pub fn heap_has_room() -> bool {
    // Relaxed: see `set_heap_reserve`.
    let reserve = HEAP_RESERVE.load(Ordering::Relaxed);
    crate::vm::HEAP
        .stats()
        .is_none_or(|(free, _)| free as u64 >= reserve)
}

/// Records the idle heap the next reports are measured against.
pub fn set_baseline() {
    for (b, v) in BASELINE.iter().zip(heap_usage()) {
        // Relaxed: read only by `mem_report` on core 0.
        b.store(v, Ordering::Relaxed);
    }
    for (b, v) in FRAMES_AT_BASELINE.iter().zip(frame_usage()) {
        // Relaxed: as above.
        b.store(v, Ordering::Relaxed);
    }
}

/// Core 0, every 10 s while connections exist: heap above the idle
/// baseline, divided by the connections across all cores (PROMPT M15).
/// Reported as requested bytes and as the heap blocks they occupy (the
/// honest figure: allocator rounding included); frame buffers are a
/// bounded pool, reported apart.
pub fn mem_report(now_ms: u64, last: &mut u64, last_conns: &mut u64) {
    if now_ms.saturating_sub(*last) < MEM_REPORT_MS {
        return;
    }
    *last = now_ms;
    // Relaxed: statistics written by each core for itself.
    let conns: u64 = CONNECTIONS.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    if conns == 0 {
        set_baseline();
        if *last_conns == 0 {
            return;
        }
    }
    *last_conns = conns;
    let (heap, frames) = (heap_usage(), frame_usage());
    // Relaxed: written by this core only.
    let base = BASELINE.each_ref().map(|b| b.load(Ordering::Relaxed));
    let fbase = FRAMES_AT_BASELINE
        .each_ref()
        .map(|b| b.load(Ordering::Relaxed));
    let per = |i: usize| {
        let b = (heap[i] - base[i]) - (frames[i] - fbase[i]);
        if conns > 0 { b / conns as i64 } else { 0 }
    };
    urmqtt_log::info!(
        "mem: {conns} connection(s), heap {} KiB in blocks ({} KiB requested), frame buffers {} KiB: \
         {} B per connection in heap blocks ({} B requested), frame buffers excluded",
        heap[1] / 1024,
        heap[0] / 1024,
        frames[1] / 1024,
        per(1),
        per(0)
    );
}

/// Connections refused by admission, by `mqtt_service::Refusal`
/// (statistics, all cores).
pub static REFUSED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub fn count_refusal(kind: usize) {
    if let Some(r) = REFUSED.get(kind) {
        // Relaxed: statistics.
        r.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts an accepted connection on `core` (statistics).
pub fn count_accept(core: usize) {
    if let Some(a) = ACCEPTED.get(core) {
        // Relaxed: statistics.
        a.fetch_add(1, Ordering::Relaxed);
    }
}

/// Adds TLS processing time on `core` (statistics).
pub fn tls_time(core: usize, ns: u64) {
    if let Some(a) = TLS_NS.get(core) {
        // Relaxed: statistics.
        a.fetch_add(ns, Ordering::Relaxed);
    }
}

/// Frames dropped because a ring was full (TCP retransmits them).
pub static DROPPED_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Builds the rings for `n` data cores (once, before they start).
pub fn init(n: usize) {
    let n = n.max(1);
    let mesh = Mesh {
        n,
        msgs: (0..n * n).map(|_| Spsc::new_boxed()).collect(),
        rx: (0..n).map(|_| Spsc::new_boxed()).collect(),
        tx: (0..n).map(|_| Spsc::new_boxed()).collect(),
    };
    let _ = MESH.set(mesh);
}

/// The MQTT workers among `n` data cores: core 0 alone serves everything
/// when it is the only data core; otherwise it only runs the NIC and the
/// dispatcher, so it never delays the other cores' frames with TLS work.
pub fn workers(n: usize) -> core::ops::Range<usize> {
    if n <= 1 { 0..1 } else { 1..n }
}

fn pick(h: u32, n: usize) -> usize {
    let w = workers(n);
    w.start + (h as usize) % w.len().max(1)
}

/// FNV-1a: stable across boots, so restored sessions find their home.
pub fn home_of(client_id: &str, n: usize) -> usize {
    let mut h: u32 = 0x811c_9dc5;
    for b in client_id.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    pick(h, n)
}

/// The data core that owns a TCP flow (dispatcher and NIC RSS agree).
pub fn core_of_flow(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, n: usize) -> usize {
    pick(urmqtt_net::rss::ipv4_tcp(src, dst, sport, dport), n)
}

/// One core's ends of the mesh.
pub struct Link {
    pub n: usize,
    to: Vec<Option<Producer<'static, CoreMsg, MSG_RING>>>,
    from: Vec<Option<Consumer<'static, CoreMsg, MSG_RING>>>,
    /// Messages waiting for ring space, per destination (order kept).
    backlog: Vec<VecDeque<CoreMsg>>,
    /// Pushed to this peer since the last `flush` (it needs a wake-up).
    pushed: Vec<bool>,
    /// Core c ≥ 1: received frames from core 0 and frames to transmit.
    pub frames_in: Option<Consumer<'static, Frame, FRAME_RING>>,
    pub frames_out: Option<Producer<'static, Frame, FRAME_RING>>,
    /// Core 0: frames to core c, and frames from core c.
    pub steer: Vec<Option<Producer<'static, Frame, FRAME_RING>>>,
    pub collect: Vec<Option<Consumer<'static, Frame, FRAME_RING>>>,
}

impl Link {
    /// Takes this core's ends; `None` if they were taken already.
    pub fn take(me: usize) -> Option<Self> {
        let m = MESH.get()?;
        let n = m.n;
        let mut to = Vec::with_capacity(n);
        let mut from = Vec::with_capacity(n);
        for peer in 0..n {
            if peer == me {
                to.push(None);
                from.push(None);
            } else {
                to.push(Some(m.msgs.get(me * n + peer)?.producer()?));
                from.push(Some(m.msgs.get(peer * n + me)?.consumer()?));
            }
        }
        let (mut steer, mut collect) = (Vec::new(), Vec::new());
        let (mut frames_in, mut frames_out) = (None, None);
        if me == 0 {
            steer.push(None);
            collect.push(None);
            for c in 1..n {
                steer.push(Some(m.rx.get(c)?.producer()?));
                collect.push(Some(m.tx.get(c)?.consumer()?));
            }
        } else {
            frames_in = Some(m.rx.get(me)?.consumer()?);
            frames_out = Some(m.tx.get(me)?.producer()?);
        }
        Some(Self {
            n,
            to,
            from,
            backlog: (0..n).map(|_| VecDeque::new()).collect(),
            pushed: vec![false; n],
            frames_in,
            frames_out,
            steer,
            collect,
        })
    }

    /// Sends `msg` to `peer` in order, never blocking (a full ring spills
    /// into a per-peer backlog).
    pub fn send(&mut self, peer: usize, msg: CoreMsg) {
        let Some(backlog) = self.backlog.get_mut(peer) else {
            return;
        };
        let msg = if backlog.is_empty() {
            match self.to.get_mut(peer).and_then(Option::as_mut) {
                Some(tx) => match tx.push(msg) {
                    Ok(()) => {
                        if let Some(p) = self.pushed.get_mut(peer) {
                            *p = true;
                        }
                        return;
                    }
                    Err(m) => m,
                },
                None => return,
            }
        } else {
            msg
        };
        backlog.push_back(msg);
    }

    /// Messages waiting for `peer` (for flow control by the sender).
    pub fn backlog_len(&self, peer: usize) -> usize {
        self.backlog.get(peer).map_or(0, VecDeque::len)
    }

    /// Moves backlogs into the rings and wakes the peers that got messages.
    pub fn flush(&mut self) {
        for (peer, backlog) in self.backlog.iter_mut().enumerate() {
            let Some(tx) = self.to.get_mut(peer).and_then(Option::as_mut) else {
                continue;
            };
            let mut sent = false;
            while let Some(m) = backlog.pop_front() {
                if let Err(m) = tx.push(m) {
                    backlog.push_front(m);
                    break;
                }
                sent = true;
            }
            if sent || core::mem::take(&mut self.pushed[peer]) {
                wake(peer);
            }
        }
    }

    /// Whether any peer has queued messages or frames for this core.
    pub fn pending(&self) -> bool {
        self.from.iter().flatten().any(|c| !c.is_empty())
            || self.frames_in.as_ref().is_some_and(|c| !c.is_empty())
            || self.collect.iter().flatten().any(|c| !c.is_empty())
    }

    /// The next message from any peer, round-robin by peer.
    pub fn recv(&mut self, peer: usize) -> Option<CoreMsg> {
        self.from.get_mut(peer)?.as_mut()?.pop()
    }
}
