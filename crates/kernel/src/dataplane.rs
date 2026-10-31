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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, fence};

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

/// Where a core's working time went in the current statistics window
/// (nanoseconds; PERF, ADR-080). TLS time is counted apart in [`TLS_NS`]
/// and included in `rx`, which is everything done for received frames
/// (Ethernet, IP, TCP, TLS, MQTT).
#[derive(Default, Clone, Copy)]
pub struct Prof {
    /// Received frames: `iface.receive` + `tcp.input` and the callbacks.
    pub rx: u64,
    /// `MqttService::poll`: timers, broker output, relays, DB and log pumps.
    pub poll: u64,
    /// TCP timers, aborts and the output flush.
    pub tcp: u64,
    /// Messages from the other cores.
    pub mesh: u64,
    /// Core 0: NIC receive, steering and transmit.
    pub disp: u64,
}

impl Prof {
    fn work(&self) -> u64 {
        self.rx + self.poll + self.tcp + self.mesh + self.disp
    }
}

/// One core's idle state and load statistics.
pub struct Idle {
    last_work_ns: u64,
    /// Time spent asleep in WFI since `window_start_ns`.
    slept_ns: u64,
    window_start_ns: u64,
    passes: u64,
    /// Where the time went in this window.
    pub prof: Prof,
    /// Start of the previous pass, and whether it ended in sleep.
    last_entry_ns: u64,
    slept_last: bool,
    /// The longest gap between two passes that did not sleep in between:
    /// a stall of this core (a long handler), which delays every frame it
    /// has queued.
    max_gap_ns: u64,
    /// Frames dropped (by [`DropSite`]) at the last report, core 0 only.
    last_dropped: [u64; 4],
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
/// Connections accepted per core since boot (`ACCEPTED` is reset every
/// statistics window): shows how evenly the flows spread over the cores.
pub static ACCEPTED_TOTAL: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];
const STATS_WINDOW_NS: u64 = 5_000_000_000;

impl Idle {
    pub fn new() -> Self {
        Self {
            last_work_ns: 0,
            slept_ns: 0,
            window_start_ns: time::uptime_ns(),
            passes: 0,
            prof: Prof::default(),
            last_entry_ns: 0,
            slept_last: true,
            max_gap_ns: 0,
            last_dropped: [0; 4],
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
        let busy = 100 - (self.slept_ns * 100 / window.max(1)).min(100);
        // Relaxed: statistics, for `$SYS/broker/cpu/busy/<core>` (O1).
        if let Some(b) = crate::sys::BUSY.get(me) {
            b.store(busy as u8, Ordering::Relaxed);
        }
        let p = core::mem::take(&mut self.prof);
        let pct = |ns: u64| ns * 100 / window.max(1);
        if acc > 0 || tls > 0 || frames > 0 {
            urmqtt_log::info!(
                "dataplane: core {me}: busy {busy}%, work {}% (rx {}%, of it tls {}%, poll {}%, tcp {}%, mesh {}%, nic {}%), \
                 {acc} connection(s) accepted ({} us of work, {} us of it TLS, each), {frames} frame(s) dispatched, \
                 {} loop passes in {} ms, longest stall {} us",
                pct(p.work()),
                pct(p.rx),
                pct(tls),
                pct(p.poll),
                pct(p.tcp),
                pct(p.mesh),
                pct(p.disp),
                p.work().checked_div(acc).unwrap_or(0) / 1000,
                tls.checked_div(acc).unwrap_or(0) / 1000,
                self.passes,
                window / 1_000_000,
                self.max_gap_ns / 1000
            );
        }
        // Relaxed: statistics.
        let dropped: [u64; 4] = DROPPED_BY.each_ref().map(|d| d.load(Ordering::Relaxed));
        if me == 0 && dropped != self.last_dropped {
            let at = |a: &[u64; 4], i: usize| a.get(i).copied().unwrap_or(0);
            let d = |i: usize| at(&dropped, i).saturating_sub(at(&self.last_dropped, i));
            urmqtt_log::warn!(
                "dataplane: frames dropped in {} ms: {} for a worker core that is behind, {} for the dispatcher, \
                 {} for a full NIC queue (workers' frames), {} for a full NIC queue (core 0's own); TCP retransmits them",
                window / 1_000_000,
                d(DropSite::Steer as usize),
                d(DropSite::WorkerTx as usize),
                d(DropSite::NicTx as usize),
                d(DropSite::NicTxLocal as usize)
            );
        }
        self.last_dropped = dropped;
        self.max_gap_ns = 0;
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
        if !self.slept_last && self.last_entry_ns != 0 {
            self.max_gap_ns = self.max_gap_ns.max(now.saturating_sub(self.last_entry_ns));
        }
        self.last_entry_ns = now;
        self.slept_last = false;
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
        self.slept_last = true;
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

/// What one core's admission did, published for `$SYS`, statsd and the
/// other cores' reports (PERF, ADR-080). The owning core stores its own
/// plain counters here every 100 ms (`MqttService::publish_admission`);
/// readers sum over the cores. All relaxed: statistics.
pub struct HsShared {
    pub started: AtomicU64,
    pub done: AtomicU64,
    pub failed: AtomicU64,
    pub timed_out: AtomicU64,
    /// Refused at the final ACK, by `urmqtt_net::admission::Reason`.
    pub refused: [AtomicU64; 5],
    /// SYNs dropped without a SYN-ACK, by reason.
    pub syn_dropped: [AtomicU64; 5],
    pub latency_sum_ms: AtomicU64,
    /// Completed handshakes slower than 250 ms.
    pub slow: AtomicU64,
    /// Admitted and not finished now.
    pub in_flight: AtomicU32,
    /// The largest accept-to-done time of the last 5 s window, ms.
    pub latency_max_ms: AtomicU32,
    /// The most handshakes in flight in the last 5 s window.
    pub in_flight_max: AtomicU32,
}

impl HsShared {
    const fn new() -> Self {
        Self {
            started: AtomicU64::new(0),
            done: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
            refused: [const { AtomicU64::new(0) }; 5],
            syn_dropped: [const { AtomicU64::new(0) }; 5],
            latency_sum_ms: AtomicU64::new(0),
            slow: AtomicU64::new(0),
            in_flight: AtomicU32::new(0),
            latency_max_ms: AtomicU32::new(0),
            in_flight_max: AtomicU32::new(0),
        }
    }
}

pub static HS: [HsShared; crate::smp::MAX_CPUS] = [const { HsShared::new() }; crate::smp::MAX_CPUS];

/// Sums a counter over all cores.
pub fn hs_sum(f: impl Fn(&HsShared) -> u64) -> u64 {
    HS.iter().map(f).sum()
}

/// Connections refused at the final ACK by admission, all cores.
pub fn refused_total() -> u64 {
    hs_sum(|h| h.refused.iter().map(|r| r.load(Ordering::Relaxed)).sum())
}

/// Refusals at the final ACK, per `Reason`, all cores.
pub fn refused_by_reason() -> [u64; 5] {
    core::array::from_fn(|i| hs_sum(|h| h.refused.get(i).map_or(0, |r| r.load(Ordering::Relaxed))))
}

/// SYNs dropped without an answer, per `Reason`, all cores.
pub fn syn_dropped_by_reason() -> [u64; 5] {
    core::array::from_fn(|i| {
        hs_sum(|h| {
            h.syn_dropped
                .get(i)
                .map_or(0, |r| r.load(Ordering::Relaxed))
        })
    })
}

/// The handshake numbers of all cores, for `$SYS` and statsd.
pub fn handshake_totals() -> HsTotals {
    // Relaxed: statistics.
    let max = |f: fn(&HsShared) -> &AtomicU32| {
        HS.iter()
            .map(|h| f(h).load(Ordering::Relaxed))
            .max()
            .unwrap_or(0)
    };
    HsTotals {
        started: hs_sum(|h| h.started.load(Ordering::Relaxed)),
        done: hs_sum(|h| h.done.load(Ordering::Relaxed)),
        failed: hs_sum(|h| h.failed.load(Ordering::Relaxed)),
        timed_out: hs_sum(|h| h.timed_out.load(Ordering::Relaxed)),
        refused: refused_total(),
        syn_dropped: syn_dropped_by_reason().iter().sum(),
        in_flight: hs_sum(|h| u64::from(h.in_flight.load(Ordering::Relaxed))),
        latency_sum_ms: hs_sum(|h| h.latency_sum_ms.load(Ordering::Relaxed)),
        slow: hs_sum(|h| h.slow.load(Ordering::Relaxed)),
        latency_max_ms: max(|h| &h.latency_max_ms),
        in_flight_max: max(|h| &h.in_flight_max),
    }
}

/// [`handshake_totals`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HsTotals {
    pub started: u64,
    pub done: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub refused: u64,
    pub syn_dropped: u64,
    pub in_flight: u64,
    pub latency_sum_ms: u64,
    pub slow: u64,
    pub latency_max_ms: u32,
    pub in_flight_max: u32,
}

/// Counts an accepted connection on `core` (statistics).
pub fn count_accept(core: usize) {
    if let Some(a) = ACCEPTED.get(core) {
        // Relaxed: statistics.
        a.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(a) = ACCEPTED_TOTAL.get(core) {
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

/// Where a frame was dropped (the index into [`DROPPED_BY`]).
#[derive(Clone, Copy)]
pub enum DropSite {
    /// Core 0 → worker ring full: the worker is behind.
    Steer = 0,
    /// Worker → core 0 ring full: the dispatcher is behind.
    WorkerTx = 1,
    /// The NIC's transmit queue was full (frames from the workers).
    NicTx = 2,
    /// The NIC's transmit queue was full (core 0's own frames).
    NicTxLocal = 3,
}

pub const DROP_SITES: [&str; 4] = ["steer", "worker_tx", "nic_tx", "nic_tx_local"];
pub static DROPPED_BY: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Counts a dropped frame (statistics).
pub fn drop_frame(site: DropSite) {
    // Relaxed: statistics.
    DROPPED_FRAMES.fetch_add(1, Ordering::Relaxed);
    if let Some(d) = DROPPED_BY.get(site as usize) {
        d.fetch_add(1, Ordering::Relaxed);
    }
}

/// Builds the rings for `n` data cores (once, before they start).
pub fn init(n: usize) {
    let n = n.max(1);
    // Relaxed: set before any other data core runs.
    DISPATCHER_SERVES.store(
        n > 1 && urmqtt_config::CONFIG.cpu.dispatcher_serves,
        Ordering::Relaxed,
    );
    let mesh = Mesh {
        n,
        msgs: (0..n * n).map(|_| Spsc::new_boxed()).collect(),
        rx: (0..n).map(|_| Spsc::new_boxed()).collect(),
        tx: (0..n).map(|_| Spsc::new_boxed()).collect(),
    };
    let _ = MESH.set(mesh);
}

/// `cpu.dispatcher_serves` was set and there are at least two data cores:
/// core 0 serves its share of the flows next to the NIC work (ADR-081).
static DISPATCHER_SERVES: AtomicBool = AtomicBool::new(false);

/// `limits=bench` on a dev command line: relaxed handshake limits for load
/// tests from one source address (ADR-082). Never set in production.
static BENCH_LIMITS: AtomicBool = AtomicBool::new(false);

/// The bench limits (`deploy/bench/config.toml` has the same values).
pub const BENCH_ADMISSION: urmqtt_net::admission::Limits = urmqtt_net::admission::Limits {
    per_core: 4096,
    per_ip: 4096,
    rate_per_sec: 100_000,
};

/// Switches the relaxed limits on (dev command line only) before the data
/// cores start.
pub fn set_bench_limits(on: bool) {
    // Relaxed: set before the data cores start.
    BENCH_LIMITS.store(on, Ordering::Relaxed);
    if on {
        urmqtt_log::warn!(
            "limits: BENCH LIMITS on (dev command line): {} handshakes in flight per core and per address, {} handshakes/s per core; never for production",
            BENCH_ADMISSION.per_core,
            BENCH_ADMISSION.rate_per_sec
        );
    }
}

/// The handshake limits in force: the configuration's, or the bench ones.
pub fn admission_limits() -> urmqtt_net::admission::Limits {
    // Relaxed: see `set_bench_limits`.
    if BENCH_LIMITS.load(Ordering::Relaxed) {
        return BENCH_ADMISSION;
    }
    let l = &urmqtt_config::CONFIG.limits;
    urmqtt_net::admission::Limits {
        per_core: l.max_handshakes_in_flight_per_core,
        per_ip: l.max_handshakes_in_flight_per_ip,
        rate_per_sec: l.handshakes_per_core_per_sec,
    }
}

/// Whether core 0 serves connections although it also dispatches.
pub fn dispatcher_serves() -> bool {
    // Relaxed: written once in `init`, before the other cores start.
    DISPATCHER_SERVES.load(Ordering::Relaxed)
}

/// The MQTT workers among `n` data cores: core 0 alone serves everything
/// when it is the only data core; otherwise it only runs the NIC and the
/// dispatcher, so it never delays the other cores' frames with TLS work,
/// unless `cpu.dispatcher_serves` asks it to take a share (ADR-081).
pub fn workers(n: usize) -> core::ops::Range<usize> {
    if n <= 1 || dispatcher_serves() {
        0..n.max(1)
    } else {
        1..n
    }
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
