//! Handler watchdog (PROMPT §4.1, M16, ADR-035).
//!
//! The data path is cooperative: one handler that runs too long stalls
//! every connection on its core. Handlers mark themselves with [`enter`]
//! (phase and connection), and the per-core 10 ms tick checks the mark
//! from its interrupt. Past `watchdog.handler_budget_ms` it logs core,
//! connection and phase once and applies `watchdog.action`:
//!
//! - `log`: nothing more.
//! - `drop`: the connection is aborted as soon as the handler returns
//!   ([`take_drop`], polled by the core loop).
//! - `reset`: the VM resets (a fresh boot is the recovery).
//!
//! Whatever the action, a handler still running after [`STUCK_MS`] (or
//! 100 budgets, if more) means a stuck core: the VM resets, since nothing
//! on that core can recover by itself.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use urmqtt_arch::time;
use urmqtt_config::{CONFIG, WatchdogAction};
use urmqtt_log::{error, warn};

use crate::smp::MAX_CPUS;

/// Handlers reported over budget (metrics).
pub static FIRED: AtomicU64 = AtomicU64::new(0);

/// A handler running this long means the core is stuck.
pub const STUCK_MS: u64 = 1_000;
const NO_CONN: u64 = u64::MAX;

/// What a core is doing (for the report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// TCP data in: TLS records, handshakes, MQTT packets.
    Input = 1,
    /// Broker output, relays and timers.
    Output = 2,
    /// `test=watchdog` (dev).
    SelfTest = 3,
}

impl Phase {
    fn name(v: u8) -> &'static str {
        match v {
            1 => "input",
            2 => "output",
            3 => "self-test",
            _ => "?",
        }
    }
}

struct Slot {
    /// Counter ticks when the handler started; 0 while idle.
    since: AtomicU64,
    conn: AtomicU64,
    phase: AtomicU8,
    /// Reported (once per handler run).
    fired: AtomicBool,
    /// Connection to abort once the handler returns (`drop`).
    drop: AtomicU64,
}

// Relaxed throughout: each slot is written by its own core and read by the
// same core's tick interrupt, which observes the core's own program order;
// `fired` and `drop` go the other way on the same core.
static SLOTS: [Slot; MAX_CPUS] = [const {
    Slot {
        since: AtomicU64::new(0),
        conn: AtomicU64::new(NO_CONN),
        phase: AtomicU8::new(0),
        fired: AtomicBool::new(false),
        drop: AtomicU64::new(NO_CONN),
    }
}; MAX_CPUS];

/// Restores the enclosing mark (or idle) when the handler returns, so
/// nested handlers keep the outer one watched from its own start.
pub struct Guard {
    slot: &'static Slot,
    since: u64,
    conn: u64,
    phase: u8,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.slot.conn.store(self.conn, Ordering::Relaxed);
        self.slot.phase.store(self.phase, Ordering::Relaxed);
        self.slot.since.store(self.since, Ordering::Relaxed);
    }
}

/// Marks this core as running `phase` for connection `conn`.
pub fn enter(phase: Phase, conn: Option<u64>) -> Option<Guard> {
    let slot = SLOTS.get(crate::smp::current())?;
    let guard = Guard {
        slot,
        since: slot.since.load(Ordering::Relaxed),
        conn: slot.conn.load(Ordering::Relaxed),
        phase: slot.phase.load(Ordering::Relaxed),
    };
    // `since` last: the tick must never pair a new start with an old phase.
    slot.since.store(0, Ordering::Relaxed);
    slot.conn.store(conn.unwrap_or(NO_CONN), Ordering::Relaxed);
    slot.phase.store(phase as u8, Ordering::Relaxed);
    slot.fired.store(false, Ordering::Relaxed);
    slot.since.store(time::now().max(1), Ordering::Relaxed);
    Some(guard)
}

/// A connection the watchdog asked to abort (`drop` action), once.
pub fn take_drop() -> Option<u64> {
    let slot = SLOTS.get(crate::smp::current())?;
    let c = slot.drop.swap(NO_CONN, Ordering::Relaxed);
    (c != NO_CONN).then_some(c)
}

/// From the tick interrupt: checks this core's running handler.
pub fn check() {
    let Some(slot) = SLOTS.get(crate::smp::current()) else {
        return;
    };
    let since = slot.since.load(Ordering::Relaxed);
    if since == 0 {
        return;
    }
    let ms = time::ticks_to_ns(time::now().saturating_sub(since)) / 1_000_000;
    let budget = u64::from(CONFIG.watchdog.handler_budget_ms);
    let conn = slot.conn.load(Ordering::Relaxed);
    let phase = Phase::name(slot.phase.load(Ordering::Relaxed));
    if ms >= STUCK_MS.max(budget * 100) {
        error!(
            "watchdog: core {} stuck in {phase} for {ms} ms (conn {}), resetting",
            crate::smp::current(),
            ConnName(conn)
        );
        crate::power::fatal();
    }
    if ms <= budget || slot.fired.swap(true, Ordering::Relaxed) {
        return;
    }
    let action = CONFIG.watchdog.action;
    // Relaxed: statistics.
    FIRED.fetch_add(1, Ordering::Relaxed);
    warn!(
        "watchdog: core {} {phase} handler for conn {} over budget: {ms} ms > {budget} ms (action: {action:?})",
        crate::smp::current(),
        ConnName(conn)
    );
    match action {
        WatchdogAction::Log => {}
        WatchdogAction::Drop => slot.drop.store(conn, Ordering::Relaxed),
        WatchdogAction::Reset => crate::power::fatal(),
    }
}

struct ConnName(u64);

impl core::fmt::Display for ConnName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 == NO_CONN {
            f.write_str("-")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// `test=watchdog`: a handler that overruns its budget on purpose.
pub fn self_test() {
    let _g = enter(Phase::SelfTest, Some(42));
    let end = time::now() + time::ns_to_ticks(50_000_000);
    while time::now() < end {
        core::hint::spin_loop();
    }
}
