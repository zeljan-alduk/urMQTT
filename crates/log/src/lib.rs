//! Kernel logging: structured lines to the UART and framebuffer sinks.
//!
//! **Status:** M1 provides a single global, lock-protected writer used during
//! boot. Lock-free per-CPU rings and the UDP syslog sink arrive with SMP (M4)
//! and observability (M16). Logs must never contain secrets or payloads.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod fbcon;
pub mod pl011;

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

use urmqtt_arch_aarch64::sync::SpinLock;
pub use urmqtt_config::LogLevel as Level;

use fbcon::FbConsole;
use pl011::Pl011;

struct Sinks {
    uart: Option<Pl011>,
    fb: Option<FbConsole<'static>>,
    clock_ns: Option<fn() -> u64>,
}

static SINKS: SpinLock<Sinks> = SpinLock::new(Sinks {
    uart: None,
    fb: None,
    clock_ns: None,
});

/// UART base kept outside the lock for [`emergency`] output.
static EMERGENCY_UART: AtomicUsize = AtomicUsize::new(0);

/// Most verbose level that is emitted, from the build-time configuration.
pub const MAX_LEVEL: Level = urmqtt_config::CONFIG.observability.log_level;

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

pub fn has_uart() -> bool {
    SINKS.lock().uart.is_some()
}

/// Holds the sink lock with IRQs masked on this core, so an interrupt
/// handler can never spin on a lock its own core holds.
struct Locked {
    #[cfg(target_os = "none")]
    daif: u64,
    guard: Option<urmqtt_arch_aarch64::sync::SpinGuard<'static, Sinks>>,
}

impl Locked {
    fn acquire() -> Self {
        #[cfg(target_os = "none")]
        let daif = urmqtt_arch_aarch64::cpu::irq_save();
        Self {
            #[cfg(target_os = "none")]
            daif,
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
        urmqtt_arch_aarch64::cpu::irq_restore(self.daif);
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

/// Writes one log line if `level` is enabled.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if level > MAX_LEVEL {
        return;
    }
    let mut locked = Locked::acquire();
    let sinks = locked.sinks();
    let ns = sinks.clock_ns.map_or(0, |c| c());
    let mut out = Tee(sinks);
    // Sinks never fail; a formatting error just truncates the line.
    let _ = writeln!(
        out,
        "[{:>5}.{:06}] {} {}",
        ns / 1_000_000_000,
        (ns / 1_000) % 1_000_000,
        tag(level),
        args
    );
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
