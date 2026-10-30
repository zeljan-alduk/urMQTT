//! Remote operation over MQTT (O1, O2, ADR-060): the numbers behind
//! `$SYS/broker/...`, the console and its fixed command set.
//!
//! Every data core runs this for its own broker shard, on its own timer, and
//! publishes into that shard only: a subscriber meets the copy of the shard
//! its session lives on. Nothing crosses cores but relaxed counters, which
//! the shards and the DB core write for themselves and everybody reads.
//!
//! The command set is closed (`urmqtt_broker::sys::parse`): `help`,
//! `status`, `log level <lvl>` and `reboot`. There is no shell and nothing
//! that runs operator-supplied code; every command, accepted or refused, is
//! audit-logged, and the rate is limited.

use alloc::string::String;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use urmqtt_broker::sys::{self, Command, Info, Level, Limiter, Refused};
use urmqtt_broker::{Broker, SysKind, SysRequest};
use urmqtt_config::LogLevel;
use urmqtt_log::{debug, warn};

use crate::dataplane;
use crate::smp::MAX_CPUS;

/// `$SYS/broker/...` is refreshed this often.
pub const REFRESH_MS: u64 = 10_000;
/// A shard publishes its own counters this often.
const STATS_MS: u64 = 1_000;
/// Console lines one shard publishes per loop pass; the rest follows on the
/// next one, so a log flood never holds the data plane.
const LINES_PER_PASS: usize = 16;
/// The console accepts a burst of commands, then one every two seconds.
const BURST: u32 = 5;
const PERIOD_MS: u64 = 2_000;
/// How long a `reboot` waits, so that its reply leaves the machine.
const REBOOT_DELAY_MS: u64 = 1_000;

/// What one shard reports about itself.
pub struct Shard {
    online: AtomicU64,
    sessions: AtomicU64,
    subscriptions: AtomicU64,
    retained: AtomicU64,
    published: AtomicU64,
    delivered: AtomicU64,
}

impl Shard {
    const fn new() -> Self {
        Self {
            online: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
            subscriptions: AtomicU64::new(0),
            retained: AtomicU64::new(0),
            published: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
        }
    }
}

// Relaxed throughout: statistics, each written by one core.
static SHARDS: [Shard; MAX_CPUS] = [const { Shard::new() }; MAX_CPUS];
/// Percent busy per core over the last window (`dataplane::Idle`).
pub static BUSY: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];
/// The data partition and what SQLite uses of it (the DB core writes them).
pub static DISK_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DISK_USED: AtomicU64 = AtomicU64::new(0);
/// Console lines a reader was too slow for, all shards.
static CONSOLE_DROPPED: AtomicU64 = AtomicU64::new(0);

/// The per-core state of the system topics and the console.
pub struct Sys {
    me: usize,
    /// This core's shard reports and publishes (the dispatcher core of a
    /// multicore system has no sessions).
    active: bool,
    cursor: u64,
    next_stats_ms: u64,
    next_refresh_ms: u64,
    limiter: Limiter,
    /// Commands refused by the rate limit, for the rate-limited log.
    limited: u64,
    reboot_at_ms: Option<u64>,
}

impl Sys {
    pub fn new(me: usize, n: usize) -> Self {
        Self {
            me,
            active: dataplane::workers(n).contains(&me),
            // From the start: a new subscriber replays what was logged
            // before this shard existed (the ring's size).
            cursor: 0,
            next_stats_ms: 0,
            next_refresh_ms: 0,
            limiter: Limiter::new(BURST, PERIOD_MS),
            limited: 0,
            reboot_at_ms: None,
        }
    }

    /// One loop pass: counters, console lines, due topics, requests.
    pub fn poll(&mut self, broker: &mut Broker, now_ms: u64) {
        if !self.active {
            return;
        }
        if now_ms >= self.next_stats_ms {
            self.next_stats_ms = now_ms + STATS_MS;
            self.report(broker);
        }
        if now_ms >= self.next_refresh_ms {
            self.next_refresh_ms = now_ms + REFRESH_MS;
            let mut busy = [0u8; MAX_CPUS];
            let info = collect(&mut busy);
            sys::topics(&info, |t, v| broker.sys_publish_retained(t, v.as_bytes()));
        }
        self.console(broker);
        let requests: alloc::vec::Vec<SysRequest> = broker.drain_sys_requests().collect();
        for r in requests {
            match r.kind {
                SysKind::Query => self.query(broker, &r, now_ms),
                SysKind::Console => self.command(broker, &r, now_ms),
            }
        }
        if self.reboot_at_ms.is_some_and(|t| now_ms >= t) {
            crate::power::reboot();
        }
    }

    /// Writes this shard's counters for the readers.
    fn report(&self, broker: &Broker) {
        let st = broker.stats();
        let Some(s) = SHARDS.get(self.me) else { return };
        s.online.store(st.online as u64, Ordering::Relaxed);
        s.sessions.store(st.sessions as u64, Ordering::Relaxed);
        s.subscriptions
            .store(st.subscriptions as u64, Ordering::Relaxed);
        s.retained.store(st.retained as u64, Ordering::Relaxed);
        s.published.store(st.published, Ordering::Relaxed);
        s.delivered.store(st.delivered, Ordering::Relaxed);
    }

    /// New kernel log lines to `$SYS/console/out`.
    fn console(&mut self, broker: &mut Broker) {
        if urmqtt_log::console_next() == self.cursor {
            return;
        }
        let lost = urmqtt_log::console_read(&mut self.cursor, LINES_PER_PASS, |r| {
            let mut line = String::new();
            let ns = r.ns;
            let _ = core::fmt::Write::write_fmt(
                &mut line,
                format_args!(
                    "[{:>5}.{:06}] {} {}",
                    ns / 1_000_000_000,
                    (ns / 1_000) % 1_000_000,
                    tag(r.level),
                    r.text()
                ),
            );
            broker.console_line(&line);
        });
        if lost > 0 {
            CONSOLE_DROPPED.fetch_add(lost, Ordering::Relaxed);
            let mut line = String::new();
            let _ = core::fmt::Write::write_fmt(
                &mut line,
                format_args!("console: {lost} line(s) dropped, the reader was behind"),
            );
            broker.console_line(&line);
        }
    }

    fn query(&mut self, broker: &mut Broker, r: &SysRequest, now_ms: u64) {
        if !self.limiter.allow(now_ms) {
            self.limited += 1;
            return;
        }
        debug!("console: {} queried $SYS/query/info", r.from);
        let mut busy = [0u8; MAX_CPUS];
        let info = collect(&mut busy);
        broker.sys_publish(sys::QUERY_INFO_RESPONSE, sys::json(&info).as_bytes());
    }

    fn command(&mut self, broker: &mut Broker, r: &SysRequest, now_ms: u64) {
        let shown = printable(&r.payload);
        if !self.limiter.allow(now_ms) {
            self.limited += 1;
            if self.limited.is_power_of_two() {
                urmqtt_log::audit(format_args!(
                    "console: {} command refused: rate limit ({} so far)",
                    r.from, self.limited
                ));
            }
            broker.console_line("error: rate limit, try again in a few seconds");
            return;
        }
        let cmd = match sys::parse(&r.payload) {
            Ok(c) => c,
            Err(why) => {
                urmqtt_log::audit(format_args!(
                    "console: {} command refused ({}): {:?}",
                    r.from,
                    why.reason(),
                    shown
                ));
                broker.console_line(&refusal_text(why));
                return;
            }
        };
        urmqtt_log::audit(format_args!("console: {} ran {:?}", r.from, shown));
        match cmd {
            Command::Help => {
                for l in sys::HELP {
                    broker.console_line(l);
                }
            }
            Command::Status => {
                let mut busy = [0u8; MAX_CPUS];
                let info = collect(&mut busy);
                for l in sys::status_lines(
                    &info,
                    level_name(urmqtt_log::level()),
                    level_name(urmqtt_log::MAX_LEVEL),
                ) {
                    broker.console_line(&l);
                }
            }
            Command::LogLevel(l) => {
                urmqtt_log::set_level(to_log_level(l));
                let mut line = String::new();
                let _ = core::fmt::Write::write_fmt(
                    &mut line,
                    format_args!(
                        "log level is now {} (build maximum {})",
                        level_name(urmqtt_log::level()),
                        level_name(urmqtt_log::MAX_LEVEL)
                    ),
                );
                broker.console_line(&line);
            }
            Command::Reboot => {
                warn!("console: rebooting at the request of {}", r.from);
                broker.console_line("rebooting in 1 s");
                self.reboot_at_ms = Some(now_ms + REBOOT_DELAY_MS);
            }
        }
    }
}

/// The numbers of all cores: what `$SYS/broker/...`, `status` and the query
/// report. `busy` holds the per-core percentages (and bounds the core count).
pub fn collect(busy: &mut [u8; MAX_CPUS]) -> Info<'_> {
    let cores = crate::smp::count().clamp(1, MAX_CPUS);
    for (b, a) in busy.iter_mut().zip(BUSY.iter()) {
        *b = a.load(Ordering::Relaxed);
    }
    let (mut online, mut sessions, mut subs, mut published, mut delivered) = (0, 0, 0, 0, 0);
    let mut retained = 0;
    for s in SHARDS.iter() {
        online += s.online.load(Ordering::Relaxed);
        sessions += s.sessions.load(Ordering::Relaxed);
        subs += s.subscriptions.load(Ordering::Relaxed);
        published += s.published.load(Ordering::Relaxed);
        delivered += s.delivered.load(Ordering::Relaxed);
        // Every shard holds a replica of the retained messages.
        retained = retained.max(s.retained.load(Ordering::Relaxed));
    }
    let (free, cap) = crate::vm::HEAP.stats().unwrap_or((0, 0));
    Info {
        version: crate::VERSION,
        uptime_s: urmqtt_arch::time::uptime_ns() / 1_000_000_000,
        arch: crate::boot::ARCH,
        busy: busy.get(..cores).unwrap_or(&[]),
        memory_total: cap as u64,
        memory_used: cap.saturating_sub(free) as u64,
        disk_total: DISK_TOTAL.load(Ordering::Relaxed),
        disk_used: DISK_USED.load(Ordering::Relaxed),
        clients_connected: online,
        clients_total: sessions,
        subscriptions: subs,
        retained,
        messages_received: published,
        messages_sent: delivered,
        connections_refused: dataplane::REFUSED
            .iter()
            .map(|r| r.load(Ordering::Relaxed))
            .sum(),
        server_cert_days: crate::ops::server_cert_days(),
        console_dropped: CONSOLE_DROPPED.load(Ordering::Relaxed),
    }
}

/// The command text for the audit log: printable ASCII only, else a note.
fn printable(payload: &[u8]) -> String {
    if payload.len() <= sys::MAX_COMMAND && payload.iter().all(|b| (0x20..0x7f).contains(b)) {
        String::from_utf8_lossy(payload).into_owned()
    } else {
        alloc::format!("<{} byte(s), not a plain command>", payload.len())
    }
}

fn refusal_text(why: Refused) -> String {
    alloc::format!("error: {}; try: help", why.reason())
}

const fn tag(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN ",
        LogLevel::Info => "INFO ",
        LogLevel::Debug => "DEBUG",
        LogLevel::Trace => "TRACE",
    }
}

const fn level_name(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

const fn to_log_level(l: Level) -> LogLevel {
    match l {
        Level::Error => LogLevel::Error,
        Level::Warn => LogLevel::Warn,
        Level::Info => LogLevel::Info,
        Level::Debug => LogLevel::Debug,
        Level::Trace => LogLevel::Trace,
    }
}
