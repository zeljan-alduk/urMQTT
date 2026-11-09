//! The Prometheus endpoint, the kernel's side (NEXT-9, ADR-290).
//!
//! The listener is off unless the image's configuration switches it on
//! (`metrics.enabled`). One short HTTP/1.1 exchange per connection: the
//! request is read by `urmqtt-http` (bounded, fuzzed), the answer is the text
//! `urmqtt_broker::metrics::render` makes from the same `Info` the `$SYS`
//! topics and the info query report, and the connection closes. Plain TCP,
//! no TLS, no login: the protection is the allow-list, applied to the SYN
//! (an address outside `metrics.allow_from` gets no answer and costs no
//! state), the per-core and per-address limits, a scrape rate, and a
//! deadline from the accept to the end of the answer.
//!
//! Where a connection stops:
//!
//! 1. **At the SYN** ([`MetricsState::syn_ok`]): the allow-list, then the
//!    core's admission (connections, per address, scrape rate, memory).
//! 2. **At the final ACK** ([`MetricsState::accept`]): the same again.
//! 3. **At the request**: [`urmqtt_http::scan`] bounds what is buffered; a
//!    malformed or unsupported request gets a fixed refusal and a close;
//!    `GET /metrics` gets the metrics.
//! 4. **At the deadline** ([`MetricsState::expire`]): a connection that has
//!    not finished by `metrics.request_timeout_s` is reset (slowloris, a
//!    reader that never takes the answer).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_broker::metrics::Own;
use urmqtt_config::CONFIG;
use urmqtt_http::{Format, Method, Refusal, Scan};
use urmqtt_log::warn;
use urmqtt_net::admission::{Admission, Limits as AdmissionLimits, Outcome};
use urmqtt_plain::AllowList;
use urmqtt_sync::sync::OnceCell;

/// The one path served.
pub const PATH: &str = "/metrics";
/// Scrapes one core admits per second (a token each, burst of the same): far
/// above any scraper's interval, far below what could make the rendering a
/// load.
const SCRAPES_PER_SEC: u32 = 20;

/// Counters since boot, all cores.
pub struct Stats {
    pub open: AtomicU64,
    pub accepted: AtomicU64,
    pub refused_source: AtomicU64,
    pub refused_limit: AtomicU64,
    pub ok: AtomicU64,
    /// By `urmqtt_http::Refusal::index`.
    pub refused: [AtomicU64; 5],
    pub timeouts: AtomicU64,
}

pub static STATS: Stats = Stats {
    open: AtomicU64::new(0),
    accepted: AtomicU64::new(0),
    refused_source: AtomicU64::new(0),
    refused_limit: AtomicU64::new(0),
    ok: AtomicU64::new(0),
    refused: [const { AtomicU64::new(0) }; 5],
    timeouts: AtomicU64::new(0),
};

const _: () = assert!(Refusal::ALL.len() == 5);

/// Adds one to a statistic (Relaxed: statistics).
fn bump(a: &AtomicU64) -> u64 {
    a.fetch_add(1, Ordering::Relaxed) + 1
}

struct Shared {
    allow: AllowList,
    allow_text: alloc::string::String,
}

static SHARED: OnceCell<Shared> = OnceCell::new();

/// The metrics port, if the endpoint is on.
pub fn port() -> Option<u16> {
    let m = &CONFIG.metrics;
    m.enabled.then_some(m.port)
}

/// Makes what the cores share, if the endpoint is on. Boot calls it once,
/// before the data cores start.
pub fn init() {
    let m = &CONFIG.metrics;
    if !m.enabled {
        return;
    }
    // Never "anywhere": the configuration check refuses an empty list, and a
    // list that were empty anyway would allow nobody.
    let allow = AllowList::new(m.allow_from, false);
    let allow_text = allow.describe();
    let _ = SHARED.set(Shared { allow, allow_text });
}

/// The listener's own numbers for the exposition.
pub fn own() -> Own {
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    Own {
        port: CONFIG.metrics.port,
        connections: g(&STATS.open),
        accepted: g(&STATS.accepted),
        refused_source: g(&STATS.refused_source),
        refused_limit: g(&STATS.refused_limit),
        ok: g(&STATS.ok),
        refused: core::array::from_fn(|i| STATS.refused.get(i).map_or(0, g)),
        timeouts: g(&STATS.timeouts),
    }
}

/// The boot line (once, from one core) and the warnings that go with it.
pub fn announce(cores: usize) {
    let m = &CONFIG.metrics;
    if !m.enabled {
        return;
    }
    let allow = SHARED.get().map_or("", |s| s.allow_text.as_str());
    warn!(
        "metrics: Prometheus endpoint on port {} (plain HTTP, NOT ENCRYPTED, no login: GET {PATH}); scrapes allowed from {allow}; \
         at most {} connection(s), {} per address, per core; {SCRAPES_PER_SEC} scrape(s)/s per core; answer within {} s; {cores} data core(s). \
         The numbers say how loaded the broker is, never who is connected: no client id, user, topic or address is in them.",
        m.port, m.max_connections, m.max_connections_per_ip, m.request_timeout_s
    );
    if SHARED.get().is_some_and(|s| s.allow.reaches_public()) {
        warn!(
            "metrics: metrics.allow_from includes public addresses: anyone there can read the broker's load and counters. Narrow it to the monitoring host."
        );
    }
}

/// One metrics connection of this core.
struct MConn {
    ip: [u8; 4],
    /// Accepted at (ms): the deadline's start, and the queue's check that an
    /// entry is still this connection.
    at_ms: u64,
}

/// The metrics endpoint of one data core.
pub struct MetricsState {
    port: u16,
    adm: Admission,
    conns: urmqtt_mm::slab::Slab<MConn>,
    /// Connections in the order they were accepted (`at_ms`, id).
    waiting: VecDeque<(u64, u32)>,
    deadline_ms: u64,
    /// Refusals already logged, by kind (logged at powers of two).
    logged: [u64; 2],
}

/// What a complete request earned.
pub enum Answer {
    /// The whole answer (head and body), then close.
    Send(Vec<u8>),
    /// Waiting for more of the request.
    Wait,
}

impl MetricsState {
    /// The state of a core, if the endpoint is on and `init` ran.
    pub fn new() -> Option<Box<Self>> {
        let m = &CONFIG.metrics;
        SHARED.get()?;
        if !m.enabled {
            return None;
        }
        Some(Box::new(Self {
            port: m.port,
            adm: Admission::new(AdmissionLimits {
                per_core: m.max_connections,
                per_ip: m.max_connections_per_ip,
                rate_per_sec: SCRAPES_PER_SEC,
            }),
            conns: urmqtt_mm::slab::Slab::new(),
            waiting: VecDeque::new(),
            deadline_ms: u64::from(m.request_timeout_s) * 1000,
            logged: [0; 2],
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether `c` is a connection of this endpoint.
    pub fn has(&self, c: u32) -> bool {
        self.conns.contains(c)
    }

    fn log_every_power_of_two(&mut self, kind: usize, n: u64, text: &str) {
        if n.is_power_of_two()
            && let Some(l) = self.logged.get_mut(kind)
            && n > *l
        {
            *l = n;
            warn!("metrics: {n} {text}");
        }
    }

    /// A SYN for the metrics port from `ip`: whether to answer it. A refused
    /// SYN keeps no state.
    pub fn syn_ok(&mut self, ip: [u8; 4], now_ms: u64, heap_ok: bool) -> bool {
        let Some(shared) = SHARED.get() else {
            return false;
        };
        if !shared.allow.allows(ip) {
            let n = bump(&STATS.refused_source);
            self.log_every_power_of_two(
                0,
                n,
                "SYN(s) from addresses outside metrics.allow_from dropped without an answer",
            );
            return false;
        }
        // Relaxed: statistics; the exact bound per core is the admission's.
        match self.adm.syn_check(ip, true, now_ms, heap_ok, false) {
            Ok(()) => true,
            Err(_) => {
                let n = bump(&STATS.refused_limit);
                self.log_every_power_of_two(
                    1,
                    n,
                    "metrics SYN(s) or connection(s) dropped for a limit (connections, per address, scrape rate, memory)",
                );
                false
            }
        }
    }

    /// The final ACK of a connection `c` from `ip`: admits and counts it, or
    /// says no (the peer gets a RST).
    pub fn accept(&mut self, c: u32, ip: [u8; 4], now_ms: u64, heap_ok: bool) -> bool {
        let Some(shared) = SHARED.get() else {
            return false;
        };
        if !shared.allow.allows(ip) {
            bump(&STATS.refused_source);
            return false;
        }
        if self.adm.admit(ip, true, now_ms, heap_ok, false).is_err() {
            bump(&STATS.refused_limit);
            return false;
        }
        STATS.open.fetch_add(1, Ordering::AcqRel);
        bump(&STATS.accepted);
        self.conns.insert_at(c, MConn { ip, at_ms: now_ms });
        self.waiting.push_back((now_ms, c));
        true
    }

    /// The connection `c` is gone: gives its place back.
    pub fn release(&mut self, c: u32) {
        let Some(m) = self.conns.take_at(c) else {
            return;
        };
        self.adm.leave(m.ip, Outcome::Failed);
        STATS.open.fetch_sub(1, Ordering::AcqRel);
    }

    /// Connections that did not finish within the deadline (the caller resets
    /// them): counted as timeouts.
    pub fn expire(&mut self, now_ms: u64) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(&(at, c)) = self.waiting.front() {
            if !self.conns.get(c).is_some_and(|m| m.at_ms == at) {
                self.waiting.pop_front();
                continue;
            }
            if now_ms.saturating_sub(at) <= self.deadline_ms {
                break;
            }
            self.waiting.pop_front();
            bump(&STATS.timeouts);
            out.push(c);
        }
        if self.waiting.is_empty() && self.waiting.capacity() > 64 {
            self.waiting.shrink_to_fit();
        }
        out
    }

    /// The bytes received so far on `c`: what to do about them.
    pub fn request(&mut self, buf: &[u8]) -> Answer {
        let end = match urmqtt_http::scan(buf) {
            Scan::Incomplete => return Answer::Wait,
            Scan::TooLarge => return Answer::Send(self.refuse(Refusal::TooLarge)),
            Scan::Complete { end } => end,
        };
        let req = match urmqtt_http::parse(buf.get(..end).unwrap_or(&[])) {
            Ok(r) => r,
            Err(r) => return Answer::Send(self.refuse(r)),
        };
        if req.target != PATH {
            return Answer::Send(self.refuse(Refusal::NotFound));
        }
        bump(&STATS.ok);
        Answer::Send(scrape(req.method, req.format))
    }

    fn refuse(&mut self, why: Refusal) -> Vec<u8> {
        if let Some(c) = STATS.refused.get(why.index()) {
            bump(c);
        }
        why.response().to_vec()
    }

    /// Returns memory a past peak left.
    pub fn shrink(&mut self) {
        self.conns.shrink();
    }
}

/// The answer to `GET /metrics`: the head and (for GET) the body.
fn scrape(method: Method, format: Format) -> Vec<u8> {
    let mut busy = [0u8; crate::smp::MAX_CPUS];
    let mut accepted = [0u64; crate::smp::MAX_CPUS];
    let t0 = urmqtt_arch::time::uptime_ns();
    let info = crate::sys::collect(&mut busy, &mut accepted);
    let body = urmqtt_broker::metrics::render(&info, &own(), matches!(format, Format::OpenMetrics));
    urmqtt_log::debug!(
        "metrics: scrape rendered {} bytes in {} us",
        body.len(),
        urmqtt_arch::time::uptime_ns().saturating_sub(t0) / 1000
    );
    let mut head = [0u8; urmqtt_http::MAX_HEAD];
    let n = urmqtt_http::ok_head(format, body.len(), &mut head);
    let mut out = Vec::with_capacity(n + body.len());
    out.extend_from_slice(head.get(..n).unwrap_or(&[]));
    if method == Method::Get {
        out.extend_from_slice(body.as_bytes());
    }
    out
}
