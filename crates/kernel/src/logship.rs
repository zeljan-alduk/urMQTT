//! Log shipping over TLS (NEXT-7, ADR-318): the first user of the outbound
//! TCP client. With `observability.log_tls` set, core 0 keeps one TLS 1.3
//! connection to that collector and sends it every log record as an RFC 5424
//! syslog message in the RFC 5425 framing (`MSG-LEN SP SYSLOG-MSG`), the
//! same message the UDP path sends. Off by default.
//!
//! Records wait in a queue of `observability.log_tls_queue_kb` while the
//! collector is unreachable; beyond it the oldest are dropped and counted.
//! What was written into a connection that then breaks may be lost (at most
//! what TLS and TCP held, see [`TlsLink::room`]): delivery is at most once,
//! as over UDP, with the loss counted where it can be.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use urmqtt_config::CONFIG;
use urmqtt_log::{error, info, warn};
use urmqtt_net::iface::Iface;
use urmqtt_tcp::queue::RecordQueue;
use urmqtt_tcp::{CloseReason, ConnId, Endpoint, TcpStack};

use crate::outbound::TlsLink;

/// For statsd (`urmqtt.logtls.*`): records sent and dropped, whether the
/// connection is up, connections made, attempts failed. Relaxed: statistics.
pub static SENT: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
pub static UP: AtomicU64 = AtomicU64::new(0);
pub static CONNECTS: AtomicU64 = AtomicU64::new(0);
pub static FAILURES: AtomicU64 = AtomicU64::new(0);
/// Whether log shipping over TLS is configured (statsd says nothing of it
/// otherwise).
pub fn configured() -> bool {
    CONFIG.observability.log_tls.is_some()
}

/// How often the dropped records are reported in the log, at most.
const DROP_REPORT_MS: u64 = 60_000;

pub struct LogShip {
    link: TlsLink,
    queue: RecordQueue,
    out: Vec<u8>,
    sent: u64,
    reported_drops: u64,
    last_drop_report: u64,
}

/// `MSG-LEN SP SYSLOG-MSG` (RFC 5425 §4.3).
pub fn frame(line: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(alloc::format!("{} ", line.len()).as_bytes());
    out.extend_from_slice(line.as_bytes());
}

impl LogShip {
    /// The shipper the configuration asks for, if any. A configuration the
    /// kernel cannot use (anchors that do not parse) is said and leaves the
    /// shipper off: the broker serves without it.
    pub fn from_config(now_ms: u64) -> Option<Self> {
        let o = &CONFIG.observability;
        let dst = o.log_tls?;
        let ep = Endpoint {
            addr: dst.addr,
            port: dst.port,
        };
        match TlsLink::new("logtls", ep, o.log_tls_name, o.log_tls_ca, now_ms) {
            Ok(link) => {
                info!(
                    "logtls: shipping log records over TLS to {}.{}.{}.{}:{} (certificate name {}, {} trust anchor file(s), queue {} KiB)",
                    dst.addr[0],
                    dst.addr[1],
                    dst.addr[2],
                    dst.addr[3],
                    dst.port,
                    if o.log_tls_name.is_empty() {
                        "the address"
                    } else {
                        o.log_tls_name
                    },
                    o.log_tls_ca.len(),
                    o.log_tls_queue_kb
                );
                Some(Self {
                    link,
                    queue: RecordQueue::new(o.log_tls_queue_kb as usize * 1024),
                    out: Vec::new(),
                    sent: 0,
                    reported_drops: 0,
                    last_drop_report: now_ms,
                })
            }
            Err(m) => {
                error!("logtls: log shipping over TLS is OFF: {m}");
                None
            }
        }
    }

    pub fn link(&mut self) -> &mut TlsLink {
        &mut self.link
    }

    pub fn owns(&self, c: ConnId) -> bool {
        self.link.owns(c)
    }

    /// One formatted syslog message, framed and queued.
    pub fn push(&mut self, line: &str) {
        self.out.clear();
        frame(line, &mut self.out);
        let rec = core::mem::take(&mut self.out);
        self.queue.push(&rec);
        self.out = rec;
    }

    /// Core 0's loop: the link, then as many queued records as it has room
    /// for.
    pub fn poll(
        &mut self,
        now_ms: u64,
        iface: &mut Iface,
        tcp: &mut TcpStack,
        reserved: &impl Fn(u16) -> bool,
        emit: &mut impl FnMut(&[u8]),
    ) {
        self.link.poll(now_ms, iface, tcp, reserved, emit);
        let room = self.link.room(tcp);
        if room > 0 && !self.queue.is_empty() {
            self.out.clear();
            let n = self.queue.take(room, &mut self.out);
            let out = core::mem::take(&mut self.out);
            if self.link.write(&out) {
                self.sent += n as u64;
            } else {
                // The link went down between the two calls: those records
                // are lost, counted.
                self.queue.dropped += n as u64;
            }
            self.out = out;
            // The ciphertext goes to the stack now, not at the next pass.
            self.link.poll(now_ms, iface, tcp, reserved, emit);
        }
        let s = self.link.stats();
        SENT.store(self.sent, Ordering::Relaxed);
        DROPPED.store(self.queue.dropped, Ordering::Relaxed);
        UP.store(u64::from(self.link.is_up()), Ordering::Relaxed);
        CONNECTS.store(s.up, Ordering::Relaxed);
        FAILURES.store(s.failures, Ordering::Relaxed);
        if self.queue.dropped > self.reported_drops
            && now_ms.saturating_sub(self.last_drop_report) >= DROP_REPORT_MS
        {
            warn!(
                "logtls: {} log record(s) dropped since the last report (queue of {} KiB full, or lost with a broken connection); {} queued",
                self.queue.dropped - self.reported_drops,
                self.queue.cap() / 1024,
                self.queue.records()
            );
            self.reported_drops = self.queue.dropped;
            self.last_drop_report = now_ms;
        }
    }

    pub fn on_connected(&mut self, c: ConnId) {
        self.link.on_connected(c);
    }

    pub fn on_data(&mut self, c: ConnId, data: &[u8], now_ms: u64) {
        self.link.on_data(c, data, now_ms);
        // A collector has nothing to say; what it sends is not kept.
        let _ = self.link.take_received();
    }

    pub fn on_peer_closed(&mut self, c: ConnId) {
        self.link.on_peer_closed(c);
    }

    pub fn on_closed(&mut self, c: ConnId, why: CloseReason, now_ms: u64) {
        self.link.on_closed(c, why, now_ms);
    }
}
