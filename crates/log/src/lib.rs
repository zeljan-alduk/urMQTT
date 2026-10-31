//! Kernel logging: lines to the UART and framebuffer sinks, and records for
//! the UDP syslog sink.
//!
//! Before the cores run (boot) one lock-protected writer writes each line
//! to the sinks directly. Once [`start`] switched to the asynchronous mode
//! (ADR-090) a log call only formats into its own core's ring
//! ([`ring::Ring`], single producer, never waits for a sink or a lock
//! another core can hold) and one designated core drains all rings in
//! timestamp order into the sinks ([`service`]); overflow drops the newest
//! line and is counted and reported (`log: N line(s) dropped`). Audit lines
//! never wait in a full ring: they fall back to a synchronous write. The
//! panic and fatal paths ([`emergency`], [`flush`], [`raw`]) drain first and
//! write synchronously. Lines are rate-limited per core
//! ([`RATE_PER_S`], burst [`BURST`]): a flood, e.g. a warning
//! per refused connection, cannot stall a core on the UART. What is
//! suppressed is counted and reported with the next line. With a syslog
//! collector configured, every line is also kept as a [`Record`] in a fixed
//! ring (no allocation) that the network core drains ([`drain_records`]).
//! A second ring serves the MQTT console (O2): readers keep their own cursor
//! ([`console_read`]), so a slow or absent reader never blocks a writer and
//! loses lines instead, counted. The ring has a lock of its own, held only
//! for a copy of a few records, because the sink lock is held for as long as
//! the serial port and the framebuffer take for a line (milliseconds on a
//! hypervisor): a reader must never queue behind that (ADR-072). Logs must never contain secrets or payloads.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod fbcon;
pub mod pl011;
pub mod ring;

use core::fmt::{self, Write};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub use urmqtt_config::LogLevel as Level;
use urmqtt_sync::sync::{OnceCell, SpinLock};

use fbcon::FbConsole;
use pl011::Pl011;

/// Lines per second after the burst is spent.
pub const RATE_PER_S: u64 = 100;
pub const BURST: u64 = 300;
/// Records kept for the syslog sink, and bytes of text per record.
pub const RECORDS: usize = 128;
pub const RECORD_TEXT: usize = 254;
/// Cores with a ring of their own (the kernel's `MAX_CPUS`).
pub const LOG_CPUS: usize = 64;
/// Lines one core can have queued before the drain catches up.
pub const RING_LINES: usize = 64;
/// Lines the console ring keeps for readers that are behind.
pub const CONSOLE_LINES: usize = 128;

/// One line for the syslog sink.
#[derive(Clone, Copy)]
pub struct Record {
    pub level: Level,
    pub cpu: u8,
    /// Nanoseconds since boot.
    pub ns: u64,
    len: u8,
    /// Text was cut at [`RECORD_TEXT`] bytes.
    cut: bool,
    text: [u8; RECORD_TEXT],
}

impl Record {
    pub(crate) const EMPTY: Self = Self {
        // `Error` is the all-zero level: an empty record is all zeros.
        level: Level::Error,
        cpu: 0,
        ns: 0,
        len: 0,
        cut: false,
        text: [0; RECORD_TEXT],
    };

    /// Marks a cut line with `...` at its end (at a char boundary).
    fn finish(&mut self) {
        if !self.cut {
            return;
        }
        let mut at = usize::from(self.len).min(RECORD_TEXT - 3);
        while at > 0 && !self.text.get(at).is_none_or(|b| (b & 0xC0) != 0x80) {
            at -= 1;
        }
        if let Some(dst) = self.text.get_mut(at..at + 3) {
            dst.copy_from_slice(b"...");
            self.len = (at + 3) as u8;
        }
    }

    /// The message (truncated to [`RECORD_TEXT`] bytes at a char boundary).
    pub fn text(&self) -> &str {
        let b = self.text.get(..usize::from(self.len)).unwrap_or(&[]);
        core::str::from_utf8(b).unwrap_or("")
    }
}

impl Write for Record {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            let mut buf = [0u8; 4];
            let enc = ch.encode_utf8(&mut buf).as_bytes();
            let at = usize::from(self.len);
            match self.text.get_mut(at..at + enc.len()) {
                Some(dst) => dst.copy_from_slice(enc),
                None => {
                    self.cut = true;
                    return Ok(());
                }
            }
            self.len += enc.len() as u8;
        }
        Ok(())
    }
}

struct Records {
    on: bool,
    ring: [Record; RECORDS],
    head: usize,
    len: usize,
    /// Overwritten before the network core took them.
    lost: u64,
}

/// The console ring: every line since the console was enabled, numbered.
struct Console {
    ring: [Record; CONSOLE_LINES],
    /// The number the next line gets; the ring holds the last
    /// `min(next, CONSOLE_LINES)` lines.
    next: u64,
}

/// The console ring's own lock (nested inside `SINKS` by writers, never
/// the other way round; readers take this one only).
static CONSOLE: SpinLock<Console> = SpinLock::new(Console {
    ring: [Record::EMPTY; CONSOLE_LINES],
    next: 0,
});
/// The console ring is being kept.
static CONSOLE_ON: AtomicBool = AtomicBool::new(false);

/// [`Console::next`] outside the lock, so a reader with nothing new to read
/// (every network loop pass) does not touch the lock the writers use.
static CONSOLE_NEXT: AtomicU64 = AtomicU64::new(0);

/// The serial sink: a memory-mapped PL011, or COM1 through port I/O (x86).
#[derive(Clone, Copy)]
enum Uart {
    Pl011(Pl011),
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    Com1,
}

impl Uart {
    fn write_bytes(&self, s: &[u8]) {
        match self {
            Self::Pl011(u) => u.write_bytes(s),
            #[cfg(all(target_os = "none", target_arch = "x86_64"))]
            Self::Com1 => urmqtt_arch::serial::write_bytes(s),
        }
    }

    fn read_byte(&self) -> Option<u8> {
        match self {
            Self::Pl011(u) => u.read_byte(),
            #[cfg(all(target_os = "none", target_arch = "x86_64"))]
            Self::Com1 => urmqtt_arch::serial::read_byte(),
        }
    }

    fn flush(&self) {
        match self {
            Self::Pl011(u) => u.flush(),
            #[cfg(all(target_os = "none", target_arch = "x86_64"))]
            Self::Com1 => urmqtt_arch::serial::flush(),
        }
    }
}

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

struct Sinks {
    uart: Option<Uart>,
    fb: Option<FbConsole<'static>>,
    /// Log lines go to the framebuffer (off while the diagnostic dashboard owns it).
    fb_log: bool,
    /// Rate limit of the synchronous mode (the asynchronous mode has one
    /// per core, in its ring).
    limiter: ring::Limiter,
}

static SINKS: SpinLock<Sinks> = SpinLock::new(Sinks {
    uart: None,
    fb: None,
    fb_log: true,
    limiter: ring::Limiter::new(),
});

/// The syslog records, under a lock of their own for the same reason as the
/// console ring: the network core drains them and must never queue behind
/// a sink (ADR-072, ADR-090). Nested inside `SINKS` by writers, taken alone
/// (IRQs masked) by the reader.
static RECORDS_RING: SpinLock<Records> = SpinLock::new(Records {
    on: false,
    ring: [Record::EMPTY; RECORDS],
    head: 0,
    len: 0,
    lost: 0,
});

/// The monotonic clock and the current-CPU query, readable without a lock.
static CLOCK: OnceCell<fn() -> u64> = OnceCell::new();
static CPU: OnceCell<fn() -> usize> = OnceCell::new();

fn now_ns() -> u64 {
    CLOCK.get().map_or(0, |c| c())
}

fn current_cpu() -> usize {
    CPU.get().map_or(0, |c| c())
}

/// UART base kept outside the lock for [`emergency`] output.
static EMERGENCY_UART: AtomicUsize = AtomicUsize::new(0);
/// Whether the serial sink is COM1 (no base address to keep).
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static EMERGENCY_COM1: AtomicBool = AtomicBool::new(false);

/// Most verbose level that is emitted, from the build-time configuration.
pub const MAX_LEVEL: Level = urmqtt_config::CONFIG.observability.log_level;

/// Run-time level (`log=` on a dev command line); never above `MAX_LEVEL`.
static LEVEL: AtomicU8 = AtomicU8::new(MAX_LEVEL as u8);

/// Lowers (never raises past the build-time maximum) the emitted level.
pub fn set_level(level: Level) {
    let l = level.min(MAX_LEVEL);
    // Relaxed: a filter; a line logged at the old level during the switch
    // is harmless.
    LEVEL.store(l as u8, Ordering::Relaxed);
}

/// The level currently emitted (never above [`MAX_LEVEL`]).
pub fn level() -> Level {
    // Relaxed: see `set_level`.
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Whether `level` is currently emitted.
pub fn enabled(level: Level) -> bool {
    // Relaxed: see `set_level`.
    level <= MAX_LEVEL && (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

pub fn set_uart(uart: Pl011, base: usize) {
    SINKS.lock().uart = Some(Uart::Pl011(uart));
    // Relaxed: only an address; `emergency` tolerates seeing it late.
    EMERGENCY_UART.store(base, Ordering::Relaxed);
}

/// Uses COM1 (initialised by `urmqtt_arch::serial::init`) as the serial sink.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn set_com1() {
    SINKS.lock().uart = Some(Uart::Com1);
    // Relaxed: see `set_uart`.
    EMERGENCY_COM1.store(true, Ordering::Relaxed);
}

pub fn set_framebuffer(fb: FbConsole<'static>) {
    SINKS.lock().fb = Some(fb);
}

/// Runs `f` on the framebuffer console with the log sinks locked (IRQs
/// masked meanwhile); `None` if there is no framebuffer. For the diagnostic
/// dashboard (O4).
pub fn with_framebuffer<R>(f: impl FnOnce(&mut FbConsole<'static>) -> R) -> Option<R> {
    let mut locked = Locked::acquire();
    locked.sinks().fb.as_mut().map(f)
}

/// Whether log lines are also written to the framebuffer (default yes).
pub fn set_framebuffer_logging(on: bool) {
    Locked::acquire().sinks().fb_log = on;
}

/// One byte received on the serial port, if any (never blocks). Only the
/// diagnostic prompt reads input (O4).
pub fn read_serial_byte() -> Option<u8> {
    let uart = SINKS.lock().uart;
    uart.and_then(|u| u.read_byte())
}

/// Installs the monotonic clock used for timestamps (nanoseconds since boot).
pub fn set_clock(clock_ns: fn() -> u64) {
    let _ = CLOCK.set(clock_ns);
}

/// Installs the current-CPU query used in records.
pub fn set_cpu(cpu: fn() -> usize) {
    let _ = CPU.set(cpu);
}

/// Starts keeping records for a syslog collector.
pub fn enable_records() {
    RECORDS_RING.lock().on = true;
}

/// Starts keeping lines for the MQTT console (O2).
pub fn enable_console() {
    // Relaxed: a switch set once at boot.
    CONSOLE_ON.store(true, Ordering::Relaxed);
}

/// The number the next console line will get: a reader whose cursor is
/// equal has nothing to read. Lock-free.
pub fn console_next() -> u64 {
    // Relaxed: a hint; a reader that misses the newest line sees it on its
    // next pass.
    CONSOLE_NEXT.load(Ordering::Relaxed)
}

/// Hands up to `max` console lines from `*cursor` on to `f`, oldest first,
/// and advances the cursor. Returns how many lines the reader missed because
/// they were overwritten before it came. Start a new reader at
/// [`console_next`] (or 0 for the whole ring).
pub fn console_read(cursor: &mut u64, max: usize, mut f: impl FnMut(&Record)) -> u64 {
    let mut batch = [Record::EMPTY; 8];
    let mut lost = 0;
    let mut left = max;
    while left > 0 {
        let mut n = 0;
        {
            // IRQs masked: the tick's watchdog report logs, and would spin on a
            // ring lock its own core holds.
            #[cfg(target_os = "none")]
            let irq_state = urmqtt_arch::cpu::irq_save();
            let c = CONSOLE.lock();
            let oldest = c.next.saturating_sub(CONSOLE_LINES as u64);
            if *cursor < oldest {
                lost += oldest - *cursor;
                *cursor = oldest;
            }
            while n < batch.len().min(left) && *cursor < c.next {
                if let (Some(dst), Some(src)) = (
                    batch.get_mut(n),
                    c.ring.get((*cursor % CONSOLE_LINES as u64) as usize),
                ) {
                    *dst = *src;
                }
                *cursor += 1;
                n += 1;
            }
            drop(c);
            #[cfg(target_os = "none")]
            urmqtt_arch::cpu::irq_restore(irq_state);
        }
        for rec in batch.get(..n).unwrap_or(&[]) {
            f(rec);
        }
        left -= n;
        if n < batch.len() {
            break;
        }
    }
    lost
}

/// Hands the kept records to `f`, oldest first, and returns how many were
/// lost to overwriting since the last call.
pub fn drain_records(mut f: impl FnMut(&Record)) -> u64 {
    // Copy out under the lock, send without it.
    let mut batch = [Record::EMPTY; 8];
    let mut lost = 0;
    loop {
        let mut n = 0;
        {
            // IRQs masked: the tick's report logs, and a drain pass in this
            // core's interrupt would spin on a lock its own core holds.
            #[cfg(target_os = "none")]
            let irq_state = urmqtt_arch::cpu::irq_save();
            let mut r = RECORDS_RING.lock();
            lost += core::mem::take(&mut r.lost);
            while n < batch.len() && r.len > 0 {
                let at = (r.head + RECORDS - r.len) % RECORDS;
                if let (Some(dst), Some(src)) = (batch.get_mut(n), r.ring.get(at)) {
                    *dst = *src;
                }
                r.len -= 1;
                n += 1;
            }
            drop(r);
            #[cfg(target_os = "none")]
            urmqtt_arch::cpu::irq_restore(irq_state);
        }
        for rec in batch.get(..n).unwrap_or(&[]) {
            f(rec);
        }
        if n < batch.len() {
            return lost;
        }
    }
}

pub fn has_uart() -> bool {
    SINKS.lock().uart.is_some()
}

/// Holds the sink lock with IRQs masked on this core, so an interrupt
/// handler can never spin on a lock its own core holds.
struct Locked {
    #[cfg(target_os = "none")]
    irq_state: u64,
    guard: Option<urmqtt_sync::sync::SpinGuard<'static, Sinks>>,
}

impl Locked {
    fn acquire() -> Self {
        #[cfg(target_os = "none")]
        let irq_state = urmqtt_arch::cpu::irq_save();
        Self {
            #[cfg(target_os = "none")]
            irq_state,
            guard: Some(SINKS.lock()),
        }
    }

    fn sinks(&mut self) -> &mut Sinks {
        // The guard is only taken out in `drop`.
        match self.guard.as_mut() {
            Some(g) => g,
            None => unreachable_sinks(),
        }
    }
}

#[cold]
fn unreachable_sinks() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        drop(self.guard.take());
        #[cfg(target_os = "none")]
        urmqtt_arch::cpu::irq_restore(self.irq_state);
    }
}

struct Tee<'a>(&'a mut Sinks);

impl Write for Tee<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if let Some(u) = self.0.uart.as_mut() {
            u.write_str(s)?;
        }
        if self.0.fb_log
            && let Some(fb) = self.0.fb.as_mut()
        {
            fb.write_str(s)?;
        }
        Ok(())
    }
}

const fn tag(level: Level) -> &'static str {
    match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN ",
        Level::Info => "INFO ",
        Level::Debug => "DEBUG",
        Level::Trace => "TRACE",
    }
}

/// Takes a rate-limit token at `ns`.
fn take_token(l: &mut ring::Limiter, ns: u64) -> bool {
    if !l.primed {
        l.primed = true;
        l.tokens = BURST;
    }
    let refill = ns.saturating_sub(l.refilled_ns) * RATE_PER_S / 1_000_000_000;
    if refill > 0 {
        l.tokens = (l.tokens + refill).min(BURST);
        l.refilled_ns = ns;
    }
    if l.tokens == 0 {
        return false;
    }
    l.tokens -= 1;
    true
}

/// Microseconds every line holds the sink lock extra (dev `test=slow-log:US`).
/// A hypervisor's trapped serial port and a scrolling framebuffer make a
/// real line cost milliseconds; this reproduces that in the emulator.
static SINK_DELAY_US: AtomicU32 = AtomicU32::new(0);

/// Makes every log line take at least `us` more while it is written to the
/// sinks (tests only).
pub fn set_sink_delay_us(us: u32) {
    // Relaxed: a test switch set once at boot.
    SINK_DELAY_US.store(us, Ordering::Relaxed);
}

/// Writes one finished record to the sinks, the console ring and the
/// syslog records. The only place a line reaches them.
fn emit_record(sinks: &mut Sinks, rec: &Record, full: Option<fmt::Arguments<'_>>) {
    // Sinks never fail; a formatting error just truncates the line.
    let _ = match full {
        // The synchronous path still has the arguments: the sinks get the
        // whole line however long it is, as before the rings.
        Some(args) => writeln!(
            Tee(sinks),
            "[{:>5}.{:06}] {} {}",
            rec.ns / 1_000_000_000,
            (rec.ns / 1_000) % 1_000_000,
            tag(rec.level),
            args
        ),
        None => writeln!(
            Tee(sinks),
            "[{:>5}.{:06}] {} {}",
            rec.ns / 1_000_000_000,
            (rec.ns / 1_000) % 1_000_000,
            tag(rec.level),
            rec.text()
        ),
    };
    // Relaxed: see `set_sink_delay_us`.
    let delay_us = SINK_DELAY_US.load(Ordering::Relaxed);
    if delay_us > 0
        && let Some(clock) = CLOCK.get()
    {
        let until = clock().saturating_add(u64::from(delay_us) * 1_000);
        while clock() < until {
            core::hint::spin_loop();
        }
    }
    // Relaxed: see `enable_console`.
    if CONSOLE_ON.load(Ordering::Relaxed) {
        let mut c = CONSOLE.lock();
        let at = (c.next % CONSOLE_LINES as u64) as usize;
        if let Some(slot) = c.ring.get_mut(at) {
            *slot = *rec;
        }
        c.next += 1;
        // Relaxed: see `console_next`.
        CONSOLE_NEXT.store(c.next, Ordering::Relaxed);
        drop(c);
    }
    let mut r = RECORDS_RING.lock();
    if r.on {
        let head = r.head;
        if let Some(slot) = r.ring.get_mut(head) {
            *slot = *rec;
        }
        r.head = (head + 1) % RECORDS;
        if r.len == RECORDS {
            r.lost += 1;
        } else {
            r.len += 1;
        }
    }
    drop(r);
}

/// Builds a record from format arguments.
fn make_record(cpu: usize, ns: u64, level: Level, args: fmt::Arguments<'_>) -> Record {
    let mut rec = Record {
        level,
        cpu: cpu.min(255) as u8,
        ns,
        ..Record::EMPTY
    };
    let _ = rec.write_fmt(args);
    rec.finish();
    rec
}

/// Writes one log line if `level` is enabled and the rate limit allows.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    log_line(level, args, false);
}

/// An audit line (every console command, O2): written whatever the level
/// is set to, so lowering the level cannot hide what an operator did. It is
/// exempt from the rate limit and never dropped from a full ring: it is
/// then written synchronously.
pub fn audit(args: fmt::Arguments<'_>) {
    log_line(Level::Warn, args, true);
}

fn log_line(level: Level, args: fmt::Arguments<'_>, audit: bool) {
    // Relaxed: a dev switch.
    let measure = MEASURE.load(Ordering::Relaxed);
    let t0 = if measure { now_ns() } else { 0 };
    // Acquire: pairs with the Release in `start`.
    if ASYNC.load(Ordering::Acquire) {
        let cpu = current_cpu();
        // IRQs masked: the tick's watchdog report logs too, and the ring's
        // producer end is not re-entrant.
        #[cfg(target_os = "none")]
        let irq_state = urmqtt_arch::cpu::irq_save();
        let pushed = HUB.push(cpu, now_ns(), level, args, audit);
        #[cfg(target_os = "none")]
        urmqtt_arch::cpu::irq_restore(irq_state);
        if pushed == Push::Dropped && audit {
            log_sync(level, args, true);
        }
    } else {
        log_sync(level, args, audit);
    }
    if measure {
        let dt = now_ns().saturating_sub(t0);
        // Relaxed: statistics.
        COST_CALLS.fetch_add(1, Ordering::Relaxed);
        COST_NS.fetch_add(dt, Ordering::Relaxed);
        COST_MAX.fetch_max(dt, Ordering::Relaxed);
    }
}

/// The synchronous path: the line goes to the sinks now, under their lock.
fn log_sync(level: Level, args: fmt::Arguments<'_>, audit: bool) {
    let mut locked = Locked::acquire();
    let sinks = locked.sinks();
    let ns = now_ns();
    let cpu = current_cpu();
    if !audit && !take_token(&mut sinks.limiter, ns) {
        sinks.limiter.suppressed += 1;
        return;
    }
    let suppressed = core::mem::take(&mut sinks.limiter.suppressed);
    if suppressed > 0 {
        let rec = make_record(
            cpu,
            ns,
            Level::Warn,
            format_args!("log: {suppressed} line(s) suppressed by the rate limit"),
        );
        emit_record(sinks, &rec, None);
    }
    emit_record(sinks, &make_record(cpu, ns, level, args), Some(args));
}

/// What became of a line given to [`Hub::push`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Push {
    Queued,
    /// Refused by the rate limit (counted, reported with the next line).
    Suppressed,
    /// The ring was full or busy (counted, reported by the drain).
    Dropped,
}

/// What the drain hands to the sinks.
pub enum Item<'a> {
    Line(&'a Record),
    /// `n` lines of `cpu` were dropped since the last note.
    Dropped {
        cpu: usize,
        n: u64,
    },
}

struct CoreLog {
    ring: ring::Ring<RING_LINES>,
}

/// Every core's ring and the masks that tell the drain where to look.
pub struct Hub {
    cores: [CoreLog; LOG_CPUS],
    /// Bit `c`: ring `c` may hold lines.
    nonempty: AtomicU64,
    /// Bit `c`: ring `c` dropped lines not yet reported.
    dropmask: AtomicU64,
}

impl Hub {
    pub const fn new() -> Self {
        Self {
            cores: [const {
                CoreLog {
                    ring: ring::Ring::new(),
                }
            }; LOG_CPUS],
            nonempty: AtomicU64::new(0),
            dropmask: AtomicU64::new(0),
        }
    }

    /// Formats a line into `cpu`'s ring. Never waits: a full ring, or a
    /// producer end in use, drops the line and counts it. Lines below
    /// warning level may fill only three quarters of the ring, so a
    /// flood of information cannot push out a warning.
    pub fn push(
        &self,
        cpu: usize,
        ns: u64,
        level: Level,
        args: fmt::Arguments<'_>,
        audit: bool,
    ) -> Push {
        let idx = cpu.min(LOG_CPUS - 1);
        let bit = 1u64 << idx;
        let Some(core) = self.cores.get(idx) else {
            return Push::Dropped;
        };
        let out = core.ring.produce(|lim, q| {
            if !audit && !take_token(lim, ns) {
                lim.suppressed += 1;
                return Push::Suppressed;
            }
            let suppressed = core::mem::take(&mut lim.suppressed);
            if suppressed > 0 {
                q.push(RING_LINES, true, |r| {
                    r.level = Level::Warn;
                    r.cpu = cpu.min(255) as u8;
                    r.ns = ns;
                    let _ = write!(r, "log: {suppressed} line(s) suppressed by the rate limit");
                });
            }
            let limit = if audit || level <= Level::Warn {
                RING_LINES
            } else {
                RING_LINES * 3 / 4
            };
            let queued = q.push(limit, !audit, |r| {
                r.level = level;
                r.cpu = cpu.min(255) as u8;
                r.ns = ns;
                let _ = r.write_fmt(args);
                r.finish();
            });
            if queued { Push::Queued } else { Push::Dropped }
        });
        match out {
            Some(Push::Queued) => {
                // Release: the drain that sees the bit sees the line.
                self.nonempty.fetch_or(bit, Ordering::Release);
                Push::Queued
            }
            Some(p @ Push::Suppressed) => p,
            Some(Push::Dropped) | None => {
                // An audit line is not counted: its caller writes it
                // synchronously instead.
                if !audit {
                    if out.is_none() {
                        core.ring.count_dropped();
                    }
                    self.dropmask.fetch_or(bit, Ordering::Release);
                }
                Push::Dropped
            }
        }
    }

    /// Whether anything waits for the drain.
    pub fn pending(&self) -> bool {
        self.nonempty.load(Ordering::Acquire) != 0 || self.dropmask.load(Ordering::Acquire) != 0
    }

    /// Hands up to `max` items to `emit`: drop notes first, then lines,
    /// oldest timestamp first across all rings. Single consumer at a time
    /// (the caller arbitrates); returns how many items were handed over.
    pub fn drain(&self, max: usize, emit: &mut dyn FnMut(Item<'_>)) -> usize {
        let mut n = 0;
        let mut drops = self.dropmask.swap(0, Ordering::AcqRel);
        while drops != 0 && n < max {
            let idx = drops.trailing_zeros() as usize;
            drops &= drops - 1;
            if let Some(c) = self.cores.get(idx) {
                let lost = c.ring.take_dropped();
                if lost > 0 {
                    emit(Item::Dropped { cpu: idx, n: lost });
                    n += 1;
                }
            }
        }
        if drops != 0 {
            // Not reported yet (`max` reached): keep them for the next call.
            self.dropmask.fetch_or(drops, Ordering::Release);
        }
        while n < max {
            let mask = self.nonempty.load(Ordering::Acquire);
            let mut best: Option<(usize, u64)> = None;
            let mut m = mask;
            while m != 0 {
                let idx = m.trailing_zeros() as usize;
                let bit = 1u64 << idx;
                m &= m - 1;
                let Some(c) = self.cores.get(idx) else {
                    continue;
                };
                match c.ring.head_ns() {
                    Some(ns) if best.is_none_or(|(_, b)| ns < b) => best = Some((idx, ns)),
                    Some(_) => {}
                    None => {
                        if c.ring.is_empty() {
                            self.nonempty.fetch_and(!bit, Ordering::AcqRel);
                            // A push between the check and the clear
                            // would have set the bit before the clear.
                            if !c.ring.is_empty() {
                                self.nonempty.fetch_or(bit, Ordering::Release);
                            }
                        }
                    }
                }
            }
            let Some((idx, _)) = best else { break };
            let Some(c) = self.cores.get(idx) else { break };
            if c.ring.pop(|rec| emit(Item::Line(rec))).is_none() {
                break;
            }
            n += 1;
        }
        n
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

static HUB: Hub = Hub::new();
/// Lines go through the rings (set by [`start`]).
static ASYNC: AtomicBool = AtomicBool::new(false);
/// The core that drains (`usize::MAX`: none yet).
static CONSUMER: AtomicUsize = AtomicUsize::new(usize::MAX);
/// A drain is running (only one at a time).
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Lines a drain pass hands over at most, and the time after which it
/// stops (at least one line is always written).
const PASS_LINES: usize = 16;
const PASS_NS: u64 = 2_000_000;
/// Lines the panic, flush and raw paths write out of the rings at most.
const SYNC_DRAIN_LINES: usize = 512;
/// How long [`raw`] waits for a drain pass in progress.
const RAW_WAIT_NS: u64 = 100_000_000;

/// Switches to the asynchronous mode: log calls only queue, and `consumer`
/// (a core that calls [`service`] between its handlers) writes the sinks.
/// `queue = false` keeps the synchronous mode but still names the consumer
/// core for the cost report (dev `test=log-sync`).
pub fn start(consumer: usize, queue: bool) {
    // Relaxed: ordered by the Release store of `ASYNC`.
    CONSUMER.store(consumer, Ordering::Relaxed);
    // The cost window starts here: boot-time calls (synchronous, all cores
    // in the same lock) are not what the report is about.
    COST_CALLS.store(0, Ordering::Relaxed);
    COST_NS.store(0, Ordering::Relaxed);
    COST_MAX.store(0, Ordering::Relaxed);
    // Release: pairs with the Acquire load in `log_line`.
    ASYNC.store(queue, Ordering::Release);
}

/// Whether log calls queue (the asynchronous mode).
pub fn is_async() -> bool {
    ASYNC.load(Ordering::Acquire)
}

fn emit_item(sinks: &mut Sinks, item: Item<'_>) {
    match item {
        Item::Line(rec) => emit_record(sinks, rec, None),
        Item::Dropped { cpu, n } => {
            let rec = make_record(
                cpu,
                now_ns(),
                Level::Warn,
                format_args!("log: {n} line(s) dropped on cpu {cpu} (log ring full)"),
            );
            emit_record(sinks, &rec, None);
        }
    }
}

/// Drains up to `max` items into the sinks, stopping after `budget_ns`
/// (checked after each line). With `held` the caller already holds the
/// sinks; otherwise each line takes them on its own. Returns the number of
/// items written, 0 if another drain is running.
fn drain(max: usize, budget_ns: u64, held: Option<&mut Sinks>) -> usize {
    if DRAINING.swap(true, Ordering::Acquire) {
        return 0;
    }
    let total = drain_claimed(max, budget_ns, held);
    DRAINING.store(false, Ordering::Release);
    total
}

/// [`drain`] with the drain claim already taken by the caller.
fn drain_claimed(max: usize, budget_ns: u64, mut held: Option<&mut Sinks>) -> usize {
    let start = now_ns();
    let mut total = 0;
    loop {
        let mut one = |item: Item<'_>| match held.as_deref_mut() {
            Some(s) => emit_item(s, item),
            None => {
                let mut l = Locked::acquire();
                emit_item(l.sinks(), item);
            }
        };
        let n = HUB.drain(1, &mut one);
        total += n;
        if n == 0 || total >= max || now_ns().saturating_sub(start) >= budget_ns {
            break;
        }
    }
    total
}

/// Called by the consumer core between handlers (the idle pass): writes
/// some queued lines to the sinks and, with the dev measurement on, reports
/// the cost of log calls. Returns whether it wrote anything (the core
/// should not sleep then). Does nothing on other cores.
pub fn service() -> bool {
    // Relaxed: set once at boot.
    let consumer = CONSUMER.load(Ordering::Relaxed);
    if consumer == usize::MAX || current_cpu() != consumer {
        return false;
    }
    if MEASURE.load(Ordering::Relaxed) {
        cost_report();
    }
    if !ASYNC.load(Ordering::Acquire) || !HUB.pending() {
        return false;
    }
    drain(PASS_LINES, PASS_NS, None) > 0
}

/// Whether lines wait for the drain (the consumer must not sleep).
pub fn pending() -> bool {
    HUB.pending()
}

/// Writes out everything queued (bounded), for the paths that are about to
/// stop or reset the machine.
pub fn drain_all() {
    if ASYNC.load(Ordering::Acquire) {
        drain(SYNC_DRAIN_LINES, u64::MAX, None);
    }
}

/// Dev measurement of the cost of a log call (`test=slow-log`, `log-sync`).
static MEASURE: AtomicBool = AtomicBool::new(false);
static COST_CALLS: AtomicU64 = AtomicU64::new(0);
static COST_NS: AtomicU64 = AtomicU64::new(0);
static COST_MAX: AtomicU64 = AtomicU64::new(0);
static COST_NEXT_NS: AtomicU64 = AtomicU64::new(0);
const COST_WINDOW_NS: u64 = 5_000_000_000;

/// Measures the cost of every log call (dev only) and has the consumer
/// report it every 5 s as `log: cost ...`.
pub fn set_measure(on: bool) {
    // Relaxed: a dev switch set once at boot.
    MEASURE.store(on, Ordering::Relaxed);
}

fn cost_report() {
    let now = now_ns();
    // Relaxed: statistics.
    if now < COST_NEXT_NS.load(Ordering::Relaxed) {
        return;
    }
    COST_NEXT_NS.store(now + COST_WINDOW_NS, Ordering::Relaxed);
    let calls = COST_CALLS.swap(0, Ordering::Relaxed);
    let total = COST_NS.swap(0, Ordering::Relaxed);
    let max = COST_MAX.swap(0, Ordering::Relaxed);
    if let Some(mean) = total.checked_div(calls) {
        log(
            Level::Info,
            format_args!(
                "log: cost: {calls} call(s) in 5 s, mean {} ns, worst {} ns ({} mode)",
                mean,
                max,
                if is_async() { "async" } else { "sync" }
            ),
        );
    }
}

/// Writes raw text (no prefix) regardless of level, e.g. boot markers that
/// test harnesses wait for. Lines queued before it are written first.
pub fn raw(args: fmt::Arguments<'_>) {
    // Wait (bounded, and before taking the sinks, which the running drain
    // needs) for a drain in progress, so the marker follows the lines that
    // were logged before it.
    let mut claimed = false;
    if ASYNC.load(Ordering::Acquire) {
        let give_up = now_ns().saturating_add(RAW_WAIT_NS);
        // Bounded by passes too, in case the clock does not advance.
        for _ in 0..50_000_000u32 {
            if !DRAINING.swap(true, Ordering::Acquire) {
                claimed = true;
                break;
            }
            if now_ns() >= give_up {
                break;
            }
            core::hint::spin_loop();
        }
    }
    let mut locked = Locked::acquire();
    if claimed {
        drain_claimed(SYNC_DRAIN_LINES, u64::MAX, Some(locked.sinks()));
        DRAINING.store(false, Ordering::Release);
    }
    let _ = Tee(locked.sinks()).write_fmt(args);
}

/// Waits until the UART has sent everything written so far (before a
/// power-off or reset, which would cut off the last lines).
pub fn flush() {
    drain_all();
    if let Some(sinks) = SINKS.try_lock()
        && let Some(u) = sinks.uart
    {
        u.flush();
    }
}

/// Last-resort output for exception and panic reports. Uses the normal sinks
/// if the lock is free (queued lines first), otherwise writes straight to
/// the UART so a fault while logging cannot deadlock the report.
pub fn emergency(args: fmt::Arguments<'_>) {
    if let Some(mut sinks) = SINKS.try_lock() {
        if ASYNC.load(Ordering::Acquire) {
            drain(SYNC_DRAIN_LINES, u64::MAX, Some(&mut *sinks));
        }
        let _ = Tee(&mut sinks).write_fmt(args);
        if let Some(u) = sinks.uart {
            u.flush();
        }
        return;
    }
    // Relaxed: see `set_uart`.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    if EMERGENCY_COM1.load(Ordering::Relaxed) {
        let _ = Uart::Com1.write_fmt(args);
        Uart::Com1.flush();
        return;
    }
    let base = EMERGENCY_UART.load(Ordering::Relaxed);
    if base != 0 {
        #[allow(unsafe_code)]
        // SAFETY: `base` was registered by `set_uart` together with a Pl011
        // whose constructor's contract guarantees the mapping.
        let mut u = unsafe { Pl011::new(base) };
        let _ = u.write_fmt(args);
        u.flush();
    }
}

#[macro_export]
macro_rules! error { ($($t:tt)*) => { $crate::log($crate::Level::Error, format_args!($($t)*)) } }
#[macro_export]
macro_rules! warn { ($($t:tt)*) => { $crate::log($crate::Level::Warn, format_args!($($t)*)) } }
#[macro_export]
macro_rules! info { ($($t:tt)*) => { $crate::log($crate::Level::Info, format_args!($($t)*)) } }
#[macro_export]
macro_rules! debug { ($($t:tt)*) => { $crate::log($crate::Level::Debug, format_args!($($t)*)) } }
#[macro_export]
macro_rules! trace { ($($t:tt)*) => { $crate::log($crate::Level::Trace, format_args!($($t)*)) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_truncate_at_a_char_boundary() {
        let mut r = Record::EMPTY;
        let long = "é".repeat(RECORD_TEXT);
        let _ = write!(r, "{long}");
        assert!(r.text().len() >= RECORD_TEXT - 1);
        assert!(r.text().chars().all(|c| c == 'é'));
    }

    /// O2: the console ring numbers lines, readers keep their own cursor and
    /// count what they missed; writers never wait for them.
    #[test]
    fn console_ring_serves_independent_readers() {
        enable_console();
        let mut early = console_next();
        let mut late = console_next();
        for i in 0..5 {
            log(Level::Info, format_args!("console test line {i}"));
        }
        let mut got = std::vec::Vec::new();
        assert_eq!(
            console_read(&mut early, 100, |r| got.push(r.text().to_owned())),
            0
        );
        assert_eq!(got.len(), 5);
        assert!(got[0].ends_with("console test line 0"));
        assert_eq!(early, console_next());
        // Nothing new: nothing read.
        assert_eq!(console_read(&mut early, 100, |_| panic!("no new line")), 0);
        // A bounded read leaves the rest for the next call.
        let mut n = 0;
        console_read(&mut late, 2, |_| n += 1);
        assert_eq!(n, 2);
        console_read(&mut late, 100, |_| n += 1);
        assert_eq!(n, 5);
        // A reader that falls more than a ring behind loses the oldest and
        // is told how many.
        let mut slow = early;
        for i in 0..(CONSOLE_LINES + 10) {
            log(Level::Info, format_args!("flood {i}"));
        }
        let mut seen = 0;
        let lost = console_read(&mut slow, usize::MAX, |_| seen += 1);
        assert_eq!((lost, seen), (10, CONSOLE_LINES));
        // The audit line is kept whatever the level.
        set_level(Level::Error);
        let mut c = console_next();
        audit(format_args!("audited"));
        log(Level::Info, format_args!("hidden"));
        let mut lines = std::vec::Vec::new();
        console_read(&mut c, 10, |r| lines.push(r.text().to_owned()));
        set_level(MAX_LEVEL);
        assert_eq!(lines, ["audited"]);
    }

    /// ADR-072: a console reader never waits for the sink lock, which a line
    /// holds for as long as the serial port and the framebuffer take. With
    /// the lock held (here: by this thread, so waiting would hang forever)
    /// a read still completes.
    #[test]
    fn console_readers_do_not_wait_for_the_sinks() {
        enable_console();
        let mut cursor = 0;
        let sinks = SINKS.lock();
        let mut n = 0;
        // The read returns (before the fix it spun on the lock forever).
        console_read(&mut cursor, 8, |_| n += 1);
        let _ = console_next();
        drop(sinks);
        assert!(cursor >= n);
    }

    #[test]
    fn rate_limit_allows_a_burst_then_the_rate() {
        let mut s = ring::Limiter::new();
        let passed = (0..1000).filter(|_| take_token(&mut s, 1)).count() as u64;
        assert_eq!(passed, BURST);
        // One second later: RATE_PER_S more.
        let passed = (0..1000)
            .filter(|_| take_token(&mut s, 1_000_000_001))
            .count() as u64;
        assert_eq!(passed, RATE_PER_S);
    }

    #[test]
    fn cut_lines_end_in_dots_at_a_char_boundary() {
        let long = "é".repeat(RECORD_TEXT);
        let r = make_record(0, 0, Level::Info, format_args!("{long}"));
        assert!(r.text().len() <= RECORD_TEXT);
        assert!(r.text().ends_with("..."));
        let body = r.text().trim_end_matches("...");
        assert!(body.chars().all(|c| c == 'é'));
        let short = make_record(0, 0, Level::Info, format_args!("short"));
        assert_eq!(short.text(), "short");
    }

    /// A hub is a megabyte: build it on a thread with room for it.
    fn big(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn drain_all_items(
        h: &Hub,
        max: usize,
    ) -> (std::vec::Vec<(u8, u64, std::string::String)>, u64) {
        let mut lines = std::vec::Vec::new();
        let mut dropped = 0;
        while h.drain(max, &mut |it| match it {
            Item::Line(r) => lines.push((r.cpu, r.ns, r.text().to_owned())),
            Item::Dropped { n, .. } => dropped += n,
        }) > 0
        {}
        (lines, dropped)
    }

    /// ADR-090: lines of several cores come out in timestamp order, none
    /// lost while the rings are not overrun.
    #[test]
    fn hub_merges_rings_by_timestamp_and_loses_nothing() {
        big(|| {
            let h = Hub::new();
            // Interleaved timestamps over four cores, pushed core by core.
            for cpu in 0..4usize {
                for i in 0..40u64 {
                    let ns = i * 4 + cpu as u64 + 1;
                    assert_eq!(
                        h.push(
                            cpu,
                            ns * 1_000,
                            Level::Info,
                            format_args!("c{cpu} l{i}"),
                            true
                        ),
                        Push::Queued
                    );
                }
            }
            assert!(h.pending());
            let (lines, dropped) = drain_all_items(&h, 7);
            assert_eq!(dropped, 0);
            assert_eq!(lines.len(), 160);
            assert!(lines.windows(2).all(|w| w[0].1 < w[1].1), "timestamp order");
            assert!(!h.pending());
            // Per core the order of emission is kept.
            for cpu in 0..4u8 {
                let mine: std::vec::Vec<_> = lines.iter().filter(|l| l.0 == cpu).collect();
                assert_eq!(mine.len(), 40);
                assert!(mine.windows(2).all(|w| w[0].1 < w[1].1));
            }
        });
    }

    /// An overrun ring drops the newest lines and says how many; what was
    /// queued stays in order.
    #[test]
    fn hub_overflow_is_counted() {
        big(|| {
            let h = Hub::new();
            let total = RING_LINES + 25;
            let mut queued = 0;
            for i in 0..total {
                let r = h.push(
                    2,
                    (i as u64 + 1) * 10_000_000,
                    Level::Warn,
                    format_args!("w{i}"),
                    false,
                );
                if r == Push::Queued {
                    queued += 1;
                }
            }
            assert_eq!(queued, RING_LINES);
            let (lines, dropped) = drain_all_items(&h, 100);
            assert_eq!(lines.len(), RING_LINES);
            assert_eq!(dropped, 25);
            assert_eq!(lines[0].2, "w0");
            assert_eq!(lines[RING_LINES - 1].2, format!("w{}", RING_LINES - 1));
            // Reported once.
            let (_, again) = drain_all_items(&h, 100);
            assert_eq!(again, 0);
        });
    }

    /// Information may fill three quarters of a ring; warnings still find
    /// room after that, and an audit line is refused only by a full ring
    /// (its caller then writes it synchronously).
    #[test]
    fn hub_keeps_room_for_warnings() {
        big(|| {
            let h = Hub::new();
            let mut info_in = 0;
            for i in 0..RING_LINES {
                // Fresh timestamps far apart: the limiter always has a token.
                let ns = (i as u64 + 1) * 1_000_000_000;
                if h.push(1, ns, Level::Info, format_args!("i{i}"), false) == Push::Queued {
                    info_in += 1;
                }
            }
            assert_eq!(info_in, RING_LINES * 3 / 4);
            assert_eq!(
                h.push(1, 100_000_000_000, Level::Warn, format_args!("warn"), false),
                Push::Queued
            );
            let (lines, dropped) = drain_all_items(&h, 1000);
            assert_eq!(dropped, (RING_LINES - RING_LINES * 3 / 4) as u64);
            assert_eq!(lines.len(), RING_LINES * 3 / 4 + 1);
        });
    }

    /// The per-core rate limit suppresses a flood and says so; audit lines
    /// are exempt.
    #[test]
    fn hub_rate_limits_per_core_and_exempts_audit() {
        big(|| {
            let h = Hub::new();
            let mut queued = 0;
            let mut drained = 0;
            for i in 0..(BURST * 3) {
                // All at the same instant: only the burst passes.
                if h.push(0, 5, Level::Warn, format_args!("flood {i}"), false) == Push::Queued {
                    queued += 1;
                }
                if i % 32 == 31 {
                    drained += drain_all_items(&h, 1000).0.len() as u64;
                }
            }
            assert_eq!(queued, BURST);
            assert_eq!(drained + drain_all_items(&h, 1000).0.len() as u64, BURST);
            // Another core has its own bucket.
            assert_eq!(
                h.push(1, 5, Level::Warn, format_args!("other core"), false),
                Push::Queued
            );
            // An audit line passes with the bucket empty, and it carries the
            // count of what the limiter swallowed.
            assert_eq!(
                h.push(0, 5, Level::Warn, format_args!("audited"), true),
                Push::Queued
            );
            let (lines, _) = drain_all_items(&h, 1000);
            let texts: std::vec::Vec<_> = lines.iter().map(|l| l.2.as_str()).collect();
            assert!(texts.contains(&"audited"));
            assert!(
                texts
                    .iter()
                    .any(|t| t.contains("suppressed by the rate limit"))
            );
        });
    }

    /// Several producer threads (one ring each) and one draining thread:
    /// every line is either delivered exactly once, in its core's order, or
    /// counted as dropped.
    #[test]
    fn hub_concurrent_producers_and_a_drain_lose_nothing_uncounted() {
        big(|| {
            use std::sync::Arc;
            use std::sync::atomic::AtomicBool as Flag;
            let h = Arc::new(Hub::new());
            let done = Arc::new(Flag::new(false));
            let per = 20_000u64;
            let producers: std::vec::Vec<_> = (0..6usize)
                .map(|cpu| {
                    let h = Arc::clone(&h);
                    std::thread::spawn(move || {
                        let mut queued = 0u64;
                        for i in 0..per {
                            if h.push(
                                cpu,
                                (i + 1) * 10_000_000,
                                Level::Warn,
                                format_args!("{i}"),
                                false,
                            ) == Push::Queued
                            {
                                queued += 1;
                            }
                            if i % 64 == 0 {
                                std::thread::yield_now();
                            }
                        }
                        queued
                    })
                })
                .collect();
            let drainer = {
                let h = Arc::clone(&h);
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    let mut last = [None::<u64>; 6];
                    let (mut got, mut dropped) = (0u64, 0u64);
                    loop {
                        let finished = done.load(Ordering::Acquire);
                        h.drain(32, &mut |it| match it {
                            Item::Line(r) => {
                                let v: u64 = r.text().parse().unwrap();
                                let slot = &mut last[usize::from(r.cpu)];
                                assert!(slot.is_none_or(|p| v > p), "per-core order");
                                *slot = Some(v);
                                got += 1;
                            }
                            Item::Dropped { n, .. } => dropped += n,
                        });
                        if finished && !h.pending() {
                            break;
                        }
                    }
                    (got, dropped)
                })
            };
            let queued: u64 = producers.into_iter().map(|t| t.join().unwrap()).sum();
            done.store(true, Ordering::Release);
            let (got, dropped) = drainer.join().unwrap();
            assert_eq!(got, queued, "every queued line delivered once");
            assert_eq!(
                got + dropped,
                per * 6,
                "every other line counted as dropped"
            );
        });
    }

    /// A producer end that is already in use (an interrupt that was not
    /// masked) loses the line instead of corrupting a slot.
    #[test]
    fn a_busy_producer_end_refuses_without_waiting() {
        let r: ring::Ring<4> = ring::Ring::new();
        let inner = r.produce(|_, _| r.produce(|_, _| ()));
        assert_eq!(inner, Some(None));
    }
}
