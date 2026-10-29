//! Kernel logging: lines to the UART and framebuffer sinks, and records for
//! the UDP syslog sink.
//!
//! One lock-protected writer (IRQs masked while it is held). Lines are
//! rate-limited ([`RATE_PER_S`], burst [`BURST`]): a flood, e.g. a warning
//! per refused connection, cannot stall a core on the UART. What is
//! suppressed is counted and reported with the next line. With a syslog
//! collector configured, every line is also kept as a [`Record`] in a fixed
//! ring (no allocation) that the network core drains ([`drain_records`]).
//! Logs must never contain secrets or payloads.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod fbcon;
pub mod pl011;

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

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

struct Sinks {
    uart: Option<Pl011>,
    fb: Option<FbConsole<'static>>,
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

/// Whether `level` is currently emitted.
pub fn enabled(level: Level) -> bool {
    // Relaxed: see `set_level`.
    level <= MAX_LEVEL && (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

pub fn set_uart(uart: Pl011, base: usize) {
    SINKS.lock().uart = Some(uart);
    // Relaxed: only an address; `emergency` tolerates seeing it late.
    EMERGENCY_UART.store(base, Ordering::Relaxed);
}

pub fn set_framebuffer(fb: FbConsole<'static>) {
    SINKS.lock().fb = Some(fb);
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
        if let Some(fb) = self.0.fb.as_mut() {
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
    if sinks.records.on {
        let mut rec = Record {
            level,
            cpu: sinks.cpu.map_or(0, |c| c()) as u8,
            ns,
            ..Record::EMPTY
        };
        let _ = rec.write_fmt(args);
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

/// Writes one log line if `level` is enabled and the rate limit allows.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
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

    #[test]
    fn rate_limit_allows_a_burst_then_the_rate() {
        let mut s = Sinks {
            uart: None,
            fb: None,
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
