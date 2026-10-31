//! Dev load generator for the log path (`test=log-flood:MS`, ADR-090).
//!
//! Every core that reaches an idle pass logs one numbered line every MS
//! milliseconds from inside a watched output handler, as a handler that
//! logs would. With sinks made slow (`test=slow-log:US`) the synchronous
//! path queues the cores behind the sink lock and the watchdog reports the
//! handlers; the asynchronous path must not. The numbers (`core N seq K`)
//! let the host check that no line is lost and that each core's lines are
//! in order. Production ignores the word like every `test=` word.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use urmqtt_arch::time;

use crate::smp::MAX_CPUS;
use crate::watchdog::{self, Phase};

/// The flood period in ms; 0 is off.
static PERIOD_MS: AtomicU32 = AtomicU32::new(0);
static NEXT_NS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static SEQ: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Starts the flood on every core.
pub fn start(ms: u32) {
    // Relaxed: set once at boot, before the data cores start.
    PERIOD_MS.store(ms, Ordering::Relaxed);
}

/// From an idle pass: logs one line if this core's period is up. Always
/// `false`: it must not keep the core awake.
pub fn flood() -> bool {
    // Relaxed: see `start`.
    let ms = PERIOD_MS.load(Ordering::Relaxed);
    if ms == 0 {
        return false;
    }
    let me = crate::smp::current();
    let (Some(next), Some(seq)) = (NEXT_NS.get(me), SEQ.get(me)) else {
        return false;
    };
    let now = time::uptime_ns();
    // Relaxed: per-core state, touched by its own core only.
    if now < next.load(Ordering::Relaxed) {
        return false;
    }
    next.store(now + u64::from(ms) * 1_000_000, Ordering::Relaxed);
    let n = seq.fetch_add(1, Ordering::Relaxed);
    let _watched = watchdog::enter(Phase::Output, None);
    urmqtt_log::info!("logflood: core {me} seq {n}");
    false
}
