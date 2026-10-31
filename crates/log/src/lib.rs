//! Kernel logging: lines to the UART and framebuffer sinks, and records for
//! the UDP syslog sink.
//!
//! One lock-protected writer (IRQs masked while it is held). Lines are
//! rate-limited ([`RATE_PER_S`], burst [`BURST`]): a flood, e.g. a warning
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

use core::fmt::{self, Write};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub use urmqtt_config::LogLevel as Level;
use urmqtt_sync::sync::SpinLock;

use fbcon::FbConsole;
use pl011::Pl011;

/// Lines per second after the burst is spent.
pub const RATE_PER_S: u64 = 100;
pub const BURST: u64 = 300;
/// Records kept for the syslog sink, and bytes of text per record.
pub const RECORDS: usize = 128;
pub const RECORD_TEXT: usize = 200;
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
    text: [u8; RECORD_TEXT],
}

impl Record {
    const EMPTY: Self = Self {
        level: Level::Info,
        cpu: 0,
        ns: 0,
        len: 0,
        text: [0; RECORD_TEXT],
    };

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
                None => return Ok(()),
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
    clock_ns: Option<fn() -> u64>,
    cpu: Option<fn() -> usize>,
    /// Rate limit: tokens (lines) and when they were last refilled.
    tokens: u64,
    refilled_ns: u64,
    suppressed: u64,
    records: Records,
}

static SINKS: SpinLock<Sinks> = SpinLock::new(Sinks {
    uart: None,
    fb: None,
    fb_log: true,
    clock_ns: None,
    cpu: None,
    tokens: BURST,
    refilled_ns: 0,
    suppressed: 0,
    records: Records {
        on: false,
        ring: [Record::EMPTY; RECORDS],
        head: 0,
        len: 0,
        lost: 0,
    },
});

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
    SINKS.lock().clock_ns = Some(clock_ns);
}

/// Installs the current-CPU query used in records.
pub fn set_cpu(cpu: fn() -> usize) {
    SINKS.lock().cpu = Some(cpu);
}

/// Starts keeping records for a syslog collector.
pub fn enable_records() {
    Locked::acquire().sinks().records.on = true;
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
            let mut locked = Locked::acquire();
            let r = &mut locked.sinks().records;
            lost += core::mem::take(&mut r.lost);
            while n < batch.len() && r.len > 0 {
                let at = (r.head + RECORDS - r.len) % RECORDS;
                if let (Some(dst), Some(src)) = (batch.get_mut(n), r.ring.get(at)) {
                    *dst = *src;
                }
                r.len -= 1;
                n += 1;
            }
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
fn take_token(sinks: &mut Sinks, ns: u64) -> bool {
    let refill = ns.saturating_sub(sinks.refilled_ns) * RATE_PER_S / 1_000_000_000;
    if refill > 0 {
        sinks.tokens = (sinks.tokens + refill).min(BURST);
        sinks.refilled_ns = ns;
    }
    if sinks.tokens == 0 {
        return false;
    }
    sinks.tokens -= 1;
    true
}

/// Microseconds every line holds the sink lock extra (dev `test=slow-log:US`).
/// A hypervisor's trapped serial port and a scrolling framebuffer make a
/// real line cost milliseconds; this reproduces that in the emulator.
static SINK_DELAY_US: AtomicU32 = AtomicU32::new(0);

/// Makes every log line take at least `us` more while the sink lock is held
/// (tests only).
pub fn set_sink_delay_us(us: u32) {
    // Relaxed: a test switch set once at boot.
    SINK_DELAY_US.store(us, Ordering::Relaxed);
}

fn line(sinks: &mut Sinks, ns: u64, level: Level, args: fmt::Arguments<'_>) {
    // Sinks never fail; a formatting error just truncates the line.
    let _ = writeln!(
        Tee(sinks),
        "[{:>5}.{:06}] {} {}",
        ns / 1_000_000_000,
        (ns / 1_000) % 1_000_000,
        tag(level),
        args
    );
    // Relaxed: see `set_sink_delay_us`.
    let delay_us = SINK_DELAY_US.load(Ordering::Relaxed);
    if delay_us > 0
        && let Some(clock) = sinks.clock_ns
    {
        let until = clock().saturating_add(u64::from(delay_us) * 1_000);
        while clock() < until {
            core::hint::spin_loop();
        }
    }
    // Relaxed: see `enable_console`.
    let console_on = CONSOLE_ON.load(Ordering::Relaxed);
    if sinks.records.on || console_on {
        let mut rec = Record {
            level,
            cpu: sinks.cpu.map_or(0, |c| c()) as u8,
            ns,
            ..Record::EMPTY
        };
        let _ = rec.write_fmt(args);
        if console_on {
            let mut c = CONSOLE.lock();
            let at = (c.next % CONSOLE_LINES as u64) as usize;
            if let Some(slot) = c.ring.get_mut(at) {
                *slot = rec;
            }
            c.next += 1;
            // Relaxed: see `console_next`.
            CONSOLE_NEXT.store(c.next, Ordering::Relaxed);
            drop(c);
        }
        if sinks.records.on {
            let r = &mut sinks.records;
            if let Some(slot) = r.ring.get_mut(r.head) {
                *slot = rec;
            }
            r.head = (r.head + 1) % RECORDS;
            if r.len == RECORDS {
                r.lost += 1;
            } else {
                r.len += 1;
            }
        }
    }
}

/// Writes one log line if `level` is enabled and the rate limit allows.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    log_line(level, args);
}

/// An audit line (every console command, O2): written whatever the level
/// is set to, so lowering the level cannot hide what an operator did. The
/// rate limit still applies.
pub fn audit(args: fmt::Arguments<'_>) {
    log_line(Level::Warn, args);
}

fn log_line(level: Level, args: fmt::Arguments<'_>) {
    let mut locked = Locked::acquire();
    let sinks = locked.sinks();
    let ns = sinks.clock_ns.map_or(0, |c| c());
    if !take_token(sinks, ns) {
        sinks.suppressed += 1;
        return;
    }
    let suppressed = core::mem::take(&mut sinks.suppressed);
    if suppressed > 0 {
        line(
            sinks,
            ns,
            Level::Warn,
            format_args!("log: {suppressed} line(s) suppressed by the rate limit"),
        );
    }
    line(sinks, ns, level, args);
}

/// Writes raw text (no prefix) regardless of level, e.g. boot markers that
/// test harnesses wait for.
pub fn raw(args: fmt::Arguments<'_>) {
    let mut locked = Locked::acquire();
    let _ = Tee(locked.sinks()).write_fmt(args);
}

/// Waits until the UART has sent everything written so far (before a
/// power-off or reset, which would cut off the last lines).
pub fn flush() {
    if let Some(sinks) = SINKS.try_lock()
        && let Some(u) = sinks.uart
    {
        u.flush();
    }
}

/// Last-resort output for exception and panic reports. Uses the normal sinks
/// if the lock is free, otherwise writes straight to the UART so a fault
/// while logging cannot deadlock the report.
pub fn emergency(args: fmt::Arguments<'_>) {
    if let Some(mut sinks) = SINKS.try_lock() {
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
        assert_eq!(r.text().len(), RECORD_TEXT);
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
        let mut s = Sinks {
            uart: None,
            fb: None,
            fb_log: true,
            clock_ns: None,
            cpu: None,
            tokens: BURST,
            refilled_ns: 0,
            suppressed: 0,
            records: Records {
                on: false,
                ring: [Record::EMPTY; RECORDS],
                head: 0,
                len: 0,
                lost: 0,
            },
        };
        let passed = (0..1000).filter(|_| take_token(&mut s, 1)).count() as u64;
        assert_eq!(passed, BURST);
        // One second later: RATE_PER_S more.
        let passed = (0..1000)
            .filter(|_| take_token(&mut s, 1_000_000_001))
            .count() as u64;
        assert_eq!(passed, RATE_PER_S);
    }
}
