//! Per-core periodic tick on the EL1 virtual timer, with IRQ latency stats.
//!
//! The tick re-arms itself from the previous deadline (no drift). Latency is
//! the time from the programmed deadline to the handler's first instruction
//! that reads the counter, i.e. interrupt delivery + vector entry.

use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_arch::time;

static PERIOD_TICKS: AtomicU64 = AtomicU64::new(0);
static INTID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
static LAT_MIN: AtomicU64 = AtomicU64::new(u64::MAX);
static LAT_MAX: AtomicU64 = AtomicU64::new(0);
static LAT_SUM: AtomicU64 = AtomicU64::new(0);
/// Latency histogram, bucket i counts latencies in [2^i, 2^(i+1)) ns.
static LAT_HIST: [AtomicU64; 40] = [const { AtomicU64::new(0) }; 40];

// Relaxed throughout: all counters are written by this core's IRQ handler
// and read by the same core's main loop after a `wfi` wake-up; the values
// are statistics, never used to synchronise other memory.

fn on_tick(_intid: u32) {
    let now = time::now();
    let deadline = time::deadline();
    let ns = time::ticks_to_ns(now.saturating_sub(deadline));
    LAT_MIN.fetch_min(ns, Ordering::Relaxed);
    LAT_MAX.fetch_max(ns, Ordering::Relaxed);
    LAT_SUM.fetch_add(ns, Ordering::Relaxed);
    let bucket = (63 - ns.max(1).leading_zeros()) as usize;
    if let Some(b) = LAT_HIST.get(bucket.min(LAT_HIST.len() - 1)) {
        b.fetch_add(1, Ordering::Relaxed);
    }
    let period = PERIOD_TICKS.load(Ordering::Relaxed);
    let mut next = deadline + period;
    if next <= now {
        // We fell behind (e.g. a long-masked section): skip, don't burst.
        next = now + period;
    }
    time::set_deadline(next);
    TICKS.fetch_add(1, Ordering::Relaxed);
    crate::smp::this().ticks.fetch_add(1, Ordering::Relaxed);
    crate::watchdog::check();
}

/// Starts the tick with `period_ns` on this core, delivered as `intid`.
pub fn start(intid: u32, period_ns: u64) {
    PERIOD_TICKS.store(time::ns_to_ticks(period_ns).max(1), Ordering::Relaxed);
    INTID.store(intid, Ordering::Relaxed);
    crate::irq::register(intid, on_tick);
    crate::irq::enable_private(intid);
    time::set_deadline(time::now() + PERIOD_TICKS.load(Ordering::Relaxed));
}

/// Starts this (secondary) core's own tick with the boot CPU's settings.
pub fn start_secondary() {
    let intid = INTID.load(Ordering::Relaxed);
    if intid == 0 {
        return;
    }
    crate::irq::enable_private(intid);
    time::set_deadline(time::now() + PERIOD_TICKS.load(Ordering::Relaxed));
}

/// Clears the latency statistics (the tick keeps running).
pub fn reset_stats() {
    LAT_MIN.store(u64::MAX, Ordering::Relaxed);
    LAT_MAX.store(0, Ordering::Relaxed);
    LAT_SUM.store(0, Ordering::Relaxed);
    for b in &LAT_HIST {
        b.store(0, Ordering::Relaxed);
    }
    SAMPLE_BASE.store(TICKS.load(Ordering::Relaxed), Ordering::Relaxed);
}

static SAMPLE_BASE: AtomicU64 = AtomicU64::new(0);

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub struct Latency {
    pub samples: u64,
    pub min_ns: u64,
    pub avg_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

/// Snapshot of the latency statistics (p99 is a power-of-two bucket bound).
pub fn latency() -> Latency {
    let samples = TICKS.load(Ordering::Relaxed) - SAMPLE_BASE.load(Ordering::Relaxed);
    let mut p99 = 0;
    let target = samples - samples / 100;
    let mut seen = 0;
    for (i, b) in LAT_HIST.iter().enumerate() {
        seen += b.load(Ordering::Relaxed);
        if seen >= target.max(1) {
            p99 = 1u64 << (i + 1);
            break;
        }
    }
    Latency {
        samples,
        min_ns: LAT_MIN.load(Ordering::Relaxed),
        avg_ns: LAT_SUM.load(Ordering::Relaxed) / samples.max(1),
        p99_ns: p99,
        max_ns: LAT_MAX.load(Ordering::Relaxed),
    }
}
