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
//! Handlers have a class (ADR-071). Ordinary ones (MQTT packets, output,
//! timers) keep `handler_budget_ms`. A TLS handshake step ([`Phase::Handshake`])
//! costs public-key math that scales with the CPU and the crypto backend, so
//! it has its own budget: `watchdog.handshake_budget_ms`, or, when that is 0,
//! a multiple of the handshake cost measured at boot ([`calibrate`]).
//!
//! Whatever the class or the action, a handler still running after
//! [`STUCK_MS`] (or 100 ordinary budgets, if more) means a stuck core: the VM
//! resets, since nothing on that core can recover by itself. That hard cap
//! is why no handshake budget exceeds 900 ms.
//!
//! # Running time, not elapsed time (ROBUST, ADR-214)
//!
//! A handler is judged on the time the core really spent in it. On a shared
//! VPS the host can take the virtual CPU away for tens of milliseconds; the
//! guest sees its clock jump, the handler looks slow, and an elapsed-time
//! check drops a healthy connection. Two kinds of time are therefore not
//! charged to the handler:
//!
//! - **a stalled core**: the tick is programmed for a deadline, so a tick that
//!   arrives much later than that deadline (more than [`STALL_MIN_NS`]) tells
//!   the core was not running. The late part, and one tick period for the
//!   part of the stall that came before the deadline, are credited;
//! - **a wait for a spin lock** ([`lock_wait`]): the holder may be a core the
//!   host has descheduled.
//!
//! A handler that really runs past the budget, interrupts enabled, still
//! fires: nothing is credited for it. The stuck-core reset uses the same
//! running time.
//!
//! The drop action needs a victim: output and timer handlers serve many
//! connections (no connection recorded), so over budget they are reported
//! and nothing is aborted.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

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
    /// A TLS handshake step (ClientHello .. client Finished): the budget of
    /// its own class.
    Handshake = 4,
}

impl Phase {
    fn name(v: u8) -> &'static str {
        match v {
            1 => "input",
            2 => "output",
            3 => "self-test",
            4 => "handshake",
            _ => "?",
        }
    }
}

/// Budget of [`Phase::Handshake`] in ms; 0 until [`calibrate`] ran (the
/// ordinary budget applies then).
static HANDSHAKE_BUDGET_MS: AtomicU32 = AtomicU32::new(0);

/// Sets the handshake class's budget from the configuration and the cost
/// measured at boot (`urmqtt_tls::bench`). Returns it.
pub fn calibrate(handshake_ns: u64) -> u32 {
    let ms =
        urmqtt_tls::bench::handshake_budget_ms(CONFIG.watchdog.handshake_budget_ms, handshake_ns);
    // Relaxed: set once at boot, before the data cores run.
    HANDSHAKE_BUDGET_MS.store(ms, Ordering::Relaxed);
    ms
}

/// The budget of a handler of class `phase` (a [`Phase`] value).
fn budget_ms(phase: u8) -> u64 {
    let ordinary = u64::from(CONFIG.watchdog.handler_budget_ms);
    if phase == Phase::Handshake as u8 {
        // Never below the ordinary budget, whatever was calibrated.
        // Relaxed: see `calibrate`.
        return u64::from(HANDSHAKE_BUDGET_MS.load(Ordering::Relaxed)).max(ordinary);
    }
    ordinary
}

/// Ticks of this core's time that were not the handler's (stalls, lock
/// waits), cumulative: a handler subtracts what accrued since it started.
static DISCOUNT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// A tick later than this after its deadline is a stalled core (a healthy
/// interrupt arrives within tens of microseconds; the boot log has seen
/// 2.3 ms on the VPS).
pub const STALL_MIN_NS: u64 = 4_000_000;

/// Stall statistics of the current report window, per core (the dataplane
/// line swaps them to zero): late ticks, the worst lateness and the sum of
/// the lateness, in ns.
pub struct StallStats {
    pub count: AtomicU64,
    pub worst_ns: AtomicU64,
    pub total_ns: AtomicU64,
    /// Time spent waiting for spin locks, ns.
    pub lock_wait_ns: AtomicU64,
}

pub static STALLS: [StallStats; MAX_CPUS] = [const {
    StallStats {
        count: AtomicU64::new(0),
        worst_ns: AtomicU64::new(0),
        total_ns: AtomicU64::new(0),
        lock_wait_ns: AtomicU64::new(0),
    }
}; MAX_CPUS];

/// Handlers excused from a report because a stall was credited (metrics).
pub static EXCUSED: AtomicU64 = AtomicU64::new(0);

/// Called when a spin lock wait ends: `ticks` of this core's time were
/// spent waiting for another core.
fn lock_wait(ticks: u64) {
    let me = crate::smp::current();
    if let Some(d) = DISCOUNT.get(me) {
        // Relaxed: read by this core's own tick.
        d.fetch_add(ticks, Ordering::Relaxed);
    }
    if let Some(s) = STALLS.get(me) {
        s.lock_wait_ns
            .fetch_add(time::ticks_to_ns(ticks), Ordering::Relaxed);
    }
}

/// Installs the spin-lock contention accounting (once, at boot).
pub fn install_lock_accounting() {
    urmqtt_sync::sync::set_contention_hooks(time::now, lock_wait);
}

struct Slot {
    /// Counter ticks when the handler started; 0 while idle.
    since: AtomicU64,
    /// `DISCOUNT` of this core when the handler started.
    disc0: AtomicU64,
    conn: AtomicU64,
    phase: AtomicU8,
    /// What the handler was doing last ([`Step`]), for the report.
    step: AtomicU8,
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
        step: AtomicU8::new(0),
        fired: AtomicBool::new(false),
        drop: AtomicU64::new(NO_CONN),
        disc0: AtomicU64::new(0),
    }
}; MAX_CPUS];

/// Restores the enclosing mark (or idle) when the handler returns, so
/// nested handlers keep the outer one watched from its own start.
pub struct Guard {
    slot: &'static Slot,
    since: u64,
    disc0: u64,
    conn: u64,
    phase: u8,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.slot.disc0.store(self.disc0, Ordering::Relaxed);
        self.slot.conn.store(self.conn, Ordering::Relaxed);
        self.slot.phase.store(self.phase, Ordering::Relaxed);
        self.slot.since.store(self.since, Ordering::Relaxed);
    }
}

/// Marks this core as running `phase` for connection `conn`.
pub fn enter(phase: Phase, conn: Option<u64>) -> Option<Guard> {
    let slot = SLOTS.get(crate::smp::current())?;
    let me = crate::smp::current();
    let guard = Guard {
        slot,
        since: slot.since.load(Ordering::Relaxed),
        disc0: slot.disc0.load(Ordering::Relaxed),
        conn: slot.conn.load(Ordering::Relaxed),
        phase: slot.phase.load(Ordering::Relaxed),
    };
    // `since` last: the tick must never pair a new start with an old phase.
    slot.since.store(0, Ordering::Relaxed);
    slot.conn.store(conn.unwrap_or(NO_CONN), Ordering::Relaxed);
    slot.phase.store(phase as u8, Ordering::Relaxed);
    slot.step.store(0, Ordering::Relaxed);
    slot.fired.store(false, Ordering::Relaxed);
    slot.disc0.store(
        DISCOUNT.get(me).map_or(0, |d| d.load(Ordering::Relaxed)),
        Ordering::Relaxed,
    );
    slot.since.store(time::now().max(1), Ordering::Relaxed);
    Some(guard)
}

/// Where a long output handler is (named in the report).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Step {
    Timers = 1,
    Shrink,
    Sys,
    Ready,
    Tcp,
    Routes,
    Control,
    Persist,
    Telemetry,
}

impl Step {
    fn name(v: u8) -> &'static str {
        match v {
            1 => "timers",
            2 => "shrink",
            3 => "sys",
            4 => "ready",
            5 => "tcp",
            6 => "routes",
            7 => "control",
            8 => "persist",
            9 => "telemetry",
            _ => "-",
        }
    }
}

/// Notes the step this core's handler is in; shown if it runs over budget.
pub fn step(s: Step) {
    if let Some(slot) = SLOTS.get(crate::smp::current()) {
        slot.step.store(s as u8, Ordering::Relaxed);
    }
}

/// A connection the watchdog asked to abort (`drop` action), once.
pub fn take_drop() -> Option<u64> {
    let slot = SLOTS.get(crate::smp::current())?;
    let c = slot.drop.swap(NO_CONN, Ordering::Relaxed);
    (c != NO_CONN).then_some(c)
}

/// From the tick interrupt: checks this core's running handler. `late` is how
/// long after its programmed deadline the tick arrived, `period` the tick
/// period (both in counter ticks).
pub fn check(late: u64, period: u64) {
    let me = crate::smp::current();
    let (Some(slot), Some(disc)) = (SLOTS.get(me), DISCOUNT.get(me)) else {
        return;
    };
    let late_ns = time::ticks_to_ns(late);
    if late_ns >= STALL_MIN_NS {
        // The core was not running for at least `late`; the stall began up
        // to one period before the deadline.
        // Relaxed: read by this core only (its handlers and this tick).
        disc.fetch_add(late.saturating_add(period), Ordering::Relaxed);
        if let Some(st) = STALLS.get(me) {
            st.count.fetch_add(1, Ordering::Relaxed);
            st.total_ns.fetch_add(late_ns, Ordering::Relaxed);
            st.worst_ns.fetch_max(late_ns, Ordering::Relaxed);
        }
    }
    let since = slot.since.load(Ordering::Relaxed);
    if since == 0 {
        return;
    }
    let wall = time::now().saturating_sub(since);
    let credited = disc
        .load(Ordering::Relaxed)
        .saturating_sub(slot.disc0.load(Ordering::Relaxed));
    let wall_ms = time::ticks_to_ns(wall) / 1_000_000;
    let ms = time::ticks_to_ns(wall.saturating_sub(credited)) / 1_000_000;
    let phase_id = slot.phase.load(Ordering::Relaxed);
    let budget = budget_ms(phase_id);
    let conn = slot.conn.load(Ordering::Relaxed);
    let phase = Phase::name(phase_id);
    // The stuck-core reset is the hard cap of every class (running time).
    if ms >= STUCK_MS.max(u64::from(CONFIG.watchdog.handler_budget_ms) * 100) {
        error!(
            "watchdog: core {} stuck in {phase} for {ms} ms running ({wall_ms} ms elapsed, conn {}), resetting",
            crate::smp::current(),
            ConnName(conn)
        );
        crate::power::fatal();
    }
    if ms <= budget {
        if wall_ms > budget && !slot.fired.load(Ordering::Relaxed) {
            // Over budget in elapsed time only: the core was not running.
            // Relaxed: statistics.
            EXCUSED.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    if slot.fired.swap(true, Ordering::Relaxed) {
        return;
    }
    let action = CONFIG.watchdog.action;
    // Relaxed: statistics.
    FIRED.fetch_add(1, Ordering::Relaxed);
    warn!(
        "watchdog: core {} {phase} handler (step {}) for conn {} over budget: {ms} ms > {budget} ms (action: {action:?}{}); {wall_ms} ms elapsed, {} ms not running (stalls, lock waits)",
        crate::smp::current(),
        Step::name(slot.step.load(Ordering::Relaxed)),
        ConnName(conn),
        if conn == NO_CONN && action == WatchdogAction::Drop {
            ", no single connection to drop"
        } else {
            ""
        },
        wall_ms.saturating_sub(ms)
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

/// `test=watchdog-handshake` (dev): a handshake-class handler that stays at
/// half its budget (nothing is reported: the ordinary 20 ms budget would
/// have fired), then one that overruns it (reported against the handshake
/// budget).
pub fn self_test_handshake() {
    let budget = budget_ms(Phase::Handshake as u8);
    let spin = |ms: u64| {
        let _g = enter(Phase::Handshake, Some(43));
        let end = time::now() + time::ns_to_ticks(ms * 1_000_000);
        while time::now() < end {
            core::hint::spin_loop();
        }
    };
    spin(budget / 2);
    // Let a tick run; the report, if any, would be in the log by now.
    spin(budget + 30);
}

/// `test=watchdog`: a handler that overruns its budget on purpose.
pub fn self_test() {
    let _g = enter(Phase::SelfTest, Some(42));
    let end = time::now() + time::ns_to_ticks(50_000_000);
    while time::now() < end {
        core::hint::spin_loop();
    }
}

/// `test=watchdog-stall` (dev): a handler that is stalled for 45 ms (interrupts
/// masked, so the tick arrives late exactly as after a descheduled virtual
/// CPU) must not be reported: its running time is far below the budget. A
/// second handler that really runs for 50 ms with interrupts on must be.
pub fn self_test_stall() {
    {
        let _g = enter(Phase::SelfTest, Some(44));
        let flags = urmqtt_arch::cpu::irq_save();
        let end = time::now() + time::ns_to_ticks(45_000_000);
        while time::now() < end {
            core::hint::spin_loop();
        }
        urmqtt_arch::cpu::irq_restore(flags);
        // The late tick is delivered here; give it time to run.
        let end = time::now() + time::ns_to_ticks(3_000_000);
        while time::now() < end {
            core::hint::spin_loop();
        }
    }
    let _g = enter(Phase::SelfTest, Some(45));
    let end = time::now() + time::ns_to_ticks(50_000_000);
    while time::now() < end {
        core::hint::spin_loop();
    }
}
