//! Observability on the network core (M16, ADR-035): log records to a
//! syslog collector (RFC 5424 over UDP, RFC 5426), metrics to a statsd
//! collector, and the periodic health check. Collectors are private
//! addresses from the build-time configuration; nothing listens here.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

use urmqtt_config::{CONFIG, LogLevel, SocketAddrV4};
use urmqtt_log::{Record, error, info, warn};
use urmqtt_net::iface::Iface;

use crate::dataplane;
use crate::smp::MAX_CPUS;

const SYSLOG_SPORT: u16 = 40514;
const STATSD_SPORT: u16 = 48125;
const SYSLOG_EVERY_MS: u64 = 100;
const METRICS_EVERY_MS: u64 = 10_000;
const HEALTH_EVERY_MS: u64 = 10_000;
/// Health checks in a row without progress before a core counts as stuck.
const STALLED_CHECKS: u8 = 2;
/// Largest statsd datagram (fits any Ethernet MTU).
const STATSD_MAX: usize = 1400;
/// RFC 5424 facility local0.
const FACILITY: u8 = 16;

pub struct Ops {
    syslog: Option<SocketAddrV4>,
    metrics: Option<SocketAddrV4>,
    last_syslog_ms: u64,
    last_metrics_ms: u64,
    last_health_ms: u64,
    last_resolve_ms: u64,
    /// Per core: loop passes at the last check, checks without progress.
    loops: [u64; MAX_CPUS],
    stalled: [u8; MAX_CPUS],
    healthy: bool,
    /// Counter values at the last metrics push (statsd counters are deltas).
    sent: Counters,
    unsent: u64,
    lost: u64,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    accepted: u64,
    refused: [u64; 5],
    syn_dropped: [u64; 5],
    hs: dataplane::HsTotals,
    dropped_by: [u64; 4],
    watchdog: u64,
    verify_hits: u64,
    dropped_frames: u64,
    lost: u64,
    unsent: u64,
    control_rejected: [u64; urmqtt_control::Reject::ALL.len()],
    control_applied: u64,
    registry_refused: u64,
    live_closed: u64,
    tickets: urmqtt_tls::ticket::TicketStats,
    retained_refused: [u64; 2],
}

fn counters(lost: u64, unsent: u64) -> Counters {
    // Relaxed throughout: statistics.
    Counters {
        accepted: dataplane::ACCEPTED_TOTAL
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .sum(),
        refused: dataplane::refused_by_reason(),
        syn_dropped: dataplane::syn_dropped_by_reason(),
        hs: dataplane::handshake_totals(),
        dropped_by: dataplane::DROPPED_BY
            .each_ref()
            .map(|r| r.load(Ordering::Relaxed)),
        watchdog: crate::watchdog::FIRED.load(Ordering::Relaxed),
        verify_hits: urmqtt_tls::provider::verify_cache_hits(),
        dropped_frames: dataplane::DROPPED_FRAMES.load(Ordering::Relaxed),
        lost,
        unsent,
        control_rejected: crate::control::REJECTED
            .each_ref()
            .map(|r| r.load(Ordering::Relaxed)),
        control_applied: crate::control::APPLIED.load(Ordering::Relaxed),
        registry_refused: crate::control::REGISTRY_REFUSED.load(Ordering::Relaxed),
        live_closed: crate::control::LIVE_CLOSED.load(Ordering::Relaxed),
        tickets: crate::mqtt_service::ticket_stats(),
        retained_refused: crate::mqtt_service::RETAINED_REFUSED
            .each_ref()
            .map(|r| r.load(Ordering::Relaxed)),
    }
}

/// Days until the server certificate expires (negative: expired), if the
/// wall clock is known.
pub(crate) fn server_cert_days() -> Option<i64> {
    let now = crate::boot::now_unix()?;
    let after = urmqtt_config::CONFIG.tls.server_cert_not_after;
    Some((after as i64 - now as i64).div_euclid(86_400))
}

/// The warning thresholds (H1): a warning each time the remaining days
/// fall to or below the next one, and once more when expired.
const CERT_WARN_DAYS: [i64; 4] = [60, 30, 7, 1];
static CERT_WARNED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn check_server_cert() {
    let Some(days) = server_cert_days() else {
        return;
    };
    let level = CERT_WARN_DAYS.iter().filter(|&&t| days <= t).count() + usize::from(days < 0);
    // Relaxed: only core 0's ops loop uses it.
    if level > CERT_WARNED.load(Ordering::Relaxed) {
        CERT_WARNED.store(level, Ordering::Relaxed);
        if days < 0 {
            error!(
                "tls: the server certificate EXPIRED {} day(s) ago: devices will refuse the broker; deploy an image with a new certificate",
                -days
            );
        } else {
            warn!(
                "tls: the server certificate expires in {days} day(s): deploy an image with a new certificate"
            );
        }
    }
}

impl Ops {
    pub fn new(now_ms: u64) -> Self {
        let o = &CONFIG.observability;
        info!(
            "ops: syslog {}, statsd {}, health check every {} s",
            Addr(o.syslog_udp),
            Addr(o.metrics_udp),
            HEALTH_EVERY_MS / 1000
        );
        match server_cert_days() {
            Some(d) => info!(
                "tls: server certificate valid for {d} more day(s) (warnings from {} days)",
                CERT_WARN_DAYS[0]
            ),
            None => warn!("tls: server certificate lifetime unknown (no wall clock)"),
        }
        check_server_cert();
        Self {
            syslog: o.syslog_udp,
            metrics: o.metrics_udp,
            last_syslog_ms: now_ms,
            last_metrics_ms: now_ms,
            last_health_ms: now_ms,
            last_resolve_ms: 0,
            loops: [0; MAX_CPUS],
            stalled: [0; MAX_CPUS],
            healthy: true,
            sent: Counters::default(),
            unsent: 0,
            lost: 0,
        }
    }

    /// Called from the network core's loop.
    pub fn poll(&mut self, iface: &mut Iface, now_ms: u64, out: &mut impl FnMut(&[u8])) {
        if now_ms.saturating_sub(self.last_health_ms) >= HEALTH_EVERY_MS {
            self.last_health_ms = now_ms;
            self.health();
            check_server_cert();
        }
        if let Some(dst) = self.syslog
            && now_ms.saturating_sub(self.last_syslog_ms) >= SYSLOG_EVERY_MS
        {
            self.last_syslog_ms = now_ms;
            // Records stay in the ring until the collector is reachable.
            if self.reachable(iface, dst, now_ms, out) {
                let host = iface.addr();
                let mut buf = String::new();
                let mut unsent = 0;
                self.lost += urmqtt_log::drain_records(|r| {
                    buf.clear();
                    syslog_line(&mut buf, r, host);
                    if !iface.send_udp(dst.addr, SYSLOG_SPORT, dst.port, buf.as_bytes(), out) {
                        unsent += 1;
                    }
                });
                self.unsent += unsent;
            }
        }
        if let Some(dst) = self.metrics
            && now_ms.saturating_sub(self.last_metrics_ms) >= METRICS_EVERY_MS
        {
            self.last_metrics_ms = now_ms;
            if self.reachable(iface, dst, now_ms, out) {
                for d in self.metrics_datagrams() {
                    if !iface.send_udp(dst.addr, STATSD_SPORT, dst.port, d.as_bytes(), out) {
                        self.unsent += 1;
                    }
                }
            }
        }
    }

    /// Whether `dst` can be sent to now; asks for its next hop (once a
    /// second) if not.
    fn reachable(
        &mut self,
        iface: &mut Iface,
        dst: SocketAddrV4,
        now_ms: u64,
        out: &mut impl FnMut(&[u8]),
    ) -> bool {
        if iface.can_reach(dst.addr) {
            return true;
        }
        if let Some(hop) = iface.next_hop(dst.addr)
            && iface.addr().is_some()
            && now_ms.saturating_sub(self.last_resolve_ms) >= 1000
        {
            self.last_resolve_ms = now_ms;
            iface.resolve(hop, out);
        }
        false
    }

    fn metrics_datagrams(&mut self) -> Vec<String> {
        // Relaxed: statistics.
        let conns: u64 = dataplane::CONNECTIONS
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let (free, cap) = crate::vm::HEAP.stats().unwrap_or((0, 0));
        let now = counters(self.lost, self.unsent);
        let prev = core::mem::replace(&mut self.sent, now);
        let d = |a: u64, b: u64| a.saturating_sub(b);
        let mut lines: Vec<String> = Vec::new();
        let mut add = |name: &str, v: u64, kind: &str| {
            lines.push(alloc::format!("urmqtt.{name}:{v}|{kind}"));
        };
        add("connections", conns, "g");
        add("heap.capacity_bytes", cap as u64, "g");
        add("heap.used_bytes", (cap - free) as u64, "g");
        add(
            "heap.live_bytes",
            crate::vm::HEAP.block_bytes().max(0) as u64,
            "g",
        );
        add(
            "frames",
            dataplane::FRAMES.load(Ordering::Relaxed).max(0) as u64,
            "g",
        );
        add("health", u64::from(self.healthy), "g");
        // Live mode (O3): 1 while the data lives in RAM and is lost at a reboot.
        add(
            "storage.ephemeral",
            u64::from(crate::live::ephemeral()),
            "g",
        );
        add("storage.ram_bytes", crate::live::store_bytes(), "g");
        // In-disk database backup (S5): gauges, so a missed datagram costs
        // nothing. `age_s` is what an alert wants: seconds since the newest
        // snapshot on the disk (absent while there is none or the clock is
        // unknown).
        {
            let b = &crate::db::BACKUP;
            add("backup.enabled", b.enabled.load(Ordering::Relaxed), "g");
            add("backup.snapshots_done", b.done.load(Ordering::Relaxed), "g");
            add("backup.failed", b.failed.load(Ordering::Relaxed), "g");
            add("backup.restored", b.restored.load(Ordering::Relaxed), "g");
            add(
                "backup.last_bytes",
                b.last_bytes.load(Ordering::Relaxed),
                "g",
            );
            let last = b.last_unix.load(Ordering::Relaxed);
            if let (true, Some(now)) = (last > 0, crate::boot::now_unix()) {
                add("backup.age_s", now.saturating_sub(last), "g");
            }
        }
        if let Some(days) = server_cert_days() {
            add("tls.server_cert_days", days.max(0) as u64, "g");
        }
        add(
            "control.applied",
            d(now.control_applied, prev.control_applied),
            "c",
        );
        for (r, (a, b)) in urmqtt_control::Reject::ALL.iter().zip(
            now.control_rejected
                .iter()
                .zip(prev.control_rejected.iter()),
        ) {
            add(
                &alloc::format!("control.rejected.{}", r.reason()),
                d(*a, *b),
                "c",
            );
        }
        add(
            "registry.refused",
            d(now.registry_refused, prev.registry_refused),
            "c",
        );
        add(
            "revocation.live_closed",
            d(now.live_closed, prev.live_closed),
            "c",
        );
        let (t, pt) = (&now.tickets, &prev.tickets);
        add("tls.tickets_issued", d(t.issued, pt.issued), "c");
        add("tls.resumed", d(t.opened, pt.opened), "c");
        add("tls.ticket_keys_rotated", d(t.rotations, pt.rotations), "c");
        add(
            "tls.tickets_not_issued",
            d(t.not_issued, pt.not_issued),
            "c",
        );
        for (r, (a, b)) in urmqtt_tls::ticket::Refused::ALL
            .iter()
            .zip(t.refused.iter().zip(pt.refused.iter()))
        {
            add(
                &alloc::format!("tls.resume_refused.{}", r.reason()),
                d(*a, *b),
                "c",
            );
        }
        for (i, why) in ["device_limit", "byte_budget"].iter().enumerate() {
            let (a, b) = (now.retained_refused.get(i), prev.retained_refused.get(i));
            add(
                &alloc::format!("broker.retained_refused.{why}"),
                d(a.copied().unwrap_or(0), b.copied().unwrap_or(0)),
                "c",
            );
        }
        add("accepted", d(now.accepted, prev.accepted), "c");
        for r in urmqtt_net::admission::Reason::ALL {
            let i = r as usize;
            let (a, b) = (now.refused.get(i), prev.refused.get(i));
            add(
                &alloc::format!("refused.{}", r.name()),
                d(a.copied().unwrap_or(0), b.copied().unwrap_or(0)),
                "c",
            );
            let (a, b) = (now.syn_dropped.get(i), prev.syn_dropped.get(i));
            add(
                &alloc::format!("syn_dropped.{}", r.name()),
                d(a.copied().unwrap_or(0), b.copied().unwrap_or(0)),
                "c",
            );
        }
        // Handshakes (PERF, ADR-080): started at the final ACK, done = TLS
        // established, in flight now, and accept-to-done latency.
        let (h, ph) = (&now.hs, &prev.hs);
        add("handshakes.started", d(h.started, ph.started), "c");
        add("handshakes.done", d(h.done, ph.done), "c");
        add("handshakes.failed", d(h.failed, ph.failed), "c");
        add("handshakes.timed_out", d(h.timed_out, ph.timed_out), "c");
        add("handshakes.slow", d(h.slow, ph.slow), "c");
        add(
            "handshakes.latency_ms_sum",
            d(h.latency_sum_ms, ph.latency_sum_ms),
            "c",
        );
        add("handshakes.in_flight", h.in_flight, "g");
        add("handshakes.in_flight_max", u64::from(h.in_flight_max), "g");
        add(
            "handshakes.latency_max_ms",
            u64::from(h.latency_max_ms),
            "g",
        );
        for (i, site) in dataplane::DROP_SITES.iter().enumerate() {
            let (a, b) = (now.dropped_by.get(i), prev.dropped_by.get(i));
            add(
                &alloc::format!("frames.dropped.{site}"),
                d(a.copied().unwrap_or(0), b.copied().unwrap_or(0)),
                "c",
            );
        }
        add("watchdog.fired", d(now.watchdog, prev.watchdog), "c");
        // Certificate signatures not verified again (X9, verify memo).
        add(
            "tls.verify_memo_hits",
            d(now.verify_hits, prev.verify_hits),
            "c",
        );
        add(
            "frames.dropped",
            d(now.dropped_frames, prev.dropped_frames),
            "c",
        );
        add("log.lost", d(now.lost, prev.lost), "c");
        add("ops.unsent", d(now.unsent, prev.unsent), "c");
        // Pack lines into datagrams below the size limit.
        let mut out: Vec<String> = Vec::new();
        let mut cur = String::new();
        for l in lines {
            if !cur.is_empty() && cur.len() + 1 + l.len() > STATSD_MAX {
                out.push(core::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push('\n');
            }
            cur.push_str(&l);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    /// Every core must keep making progress (its loop passes), and the
    /// heap must stay above the admission reserve. A core stuck with
    /// interrupts masked cannot report itself, so this check resets the VM.
    fn health(&mut self) {
        let mut problems: Vec<String> = Vec::new();
        for c in 1..crate::smp::count().min(MAX_CPUS) {
            // Relaxed: a progress counter.
            let n = dataplane::LOOPS
                .get(c)
                .map_or(0, |l| l.load(Ordering::Relaxed));
            let (Some(last), Some(stalled)) = (self.loops.get_mut(c), self.stalled.get_mut(c))
            else {
                continue;
            };
            if n == 0 {
                // Not running a loop (yet): nothing to watch.
                continue;
            }
            if n == *last {
                *stalled += 1;
                if *stalled >= STALLED_CHECKS {
                    error!(
                        "health: core {c} made no progress for {} s, resetting",
                        HEALTH_EVERY_MS / 1000 * u64::from(*stalled)
                    );
                    crate::power::fatal();
                }
                problems.push(alloc::format!("core {c} stalled"));
            } else {
                *stalled = 0;
            }
            *last = n;
        }
        if !dataplane::heap_has_room() {
            problems.push("heap below the free reserve".into());
        }
        let healthy = problems.is_empty();
        if healthy != self.healthy {
            if healthy {
                info!("health: ok again");
            } else {
                warn!("health: degraded: {}", problems.join(", "));
            }
        }
        self.healthy = healthy;
    }
}

struct Addr(Option<SocketAddrV4>);

impl core::fmt::Display for Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(a) => {
                let [x, y, z, w] = a.addr;
                write!(f, "{x}.{y}.{z}.{w}:{}", a.port)
            }
            None => f.write_str("off"),
        }
    }
}

const fn severity(l: LogLevel) -> u8 {
    match l {
        LogLevel::Error => 3,
        LogLevel::Warn => 4,
        LogLevel::Info => 6,
        LogLevel::Debug | LogLevel::Trace => 7,
    }
}

/// Days since 1970-01-01 → (year, month, day) (H. Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// RFC 3339 UTC timestamp with milliseconds.
fn rfc3339(out: &mut String, unix_ms: u64) {
    let secs = (unix_ms / 1000) as i64;
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    let _ = write!(
        out,
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        t / 3600,
        t / 60 % 60,
        t % 60,
        unix_ms % 1000
    );
}

/// One RFC 5424 message: `<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG`.
/// MSGID is the subsystem prefix of the line (`tls`, `mem`, …); the
/// structured data carries the uptime (RFC 5424 §7.3.2, centiseconds).
fn syslog_line(out: &mut String, r: &Record, host: Option<[u8; 4]>) {
    let pri = FACILITY * 8 + severity(r.level);
    let _ = write!(out, "<{pri}>1 ");
    // The record's time: wall clock now minus its age.
    let now_ns = urmqtt_arch::time::uptime_ns();
    match crate::boot::now_unix_ms() {
        Some(ms) => rfc3339(
            out,
            ms.saturating_sub(now_ns.saturating_sub(r.ns) / 1_000_000),
        ),
        None => out.push('-'),
    }
    match host {
        Some([a, b, c, d]) => {
            let _ = write!(out, " {a}.{b}.{c}.{d}");
        }
        None => out.push_str(" -"),
    }
    let text = r.text();
    let msgid = text
        .split_once(": ")
        .map(|(m, _)| m)
        .filter(|m| {
            !m.is_empty()
                && m.len() <= 32
                && m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .unwrap_or("-");
    let _ = write!(
        out,
        " urmqtt cpu{} {msgid} [meta sysUpTime=\"{}\"] {text}",
        r.cpu,
        r.ns / 10_000_000
    );
}
