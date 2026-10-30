//! Remote operation over MQTT (O1, ADR-060): the numbers behind
//! `$SYS/broker/...` and the info query.
//!
//! Every data core runs this for its own broker shard, on its own timer, and
//! publishes into that shard only: a subscriber meets the copy of the shard
//! its session lives on. Nothing crosses cores but relaxed counters, which
//! the shards and the DB core write for themselves and everybody reads.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use urmqtt_broker::sys::{self, Info, Limiter};
use urmqtt_broker::{Broker, SysKind, SysRequest};
use urmqtt_log::debug;

use crate::dataplane;
use crate::smp::MAX_CPUS;

/// `$SYS/broker/...` is refreshed this often.
pub const REFRESH_MS: u64 = 10_000;
/// A shard publishes its own counters this often.
const STATS_MS: u64 = 1_000;
/// A burst of requests, then one every two seconds.
const BURST: u32 = 5;
const PERIOD_MS: u64 = 2_000;
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
/// The per-core state of the system topics.
pub struct Sys {
    me: usize,
    /// This core's shard reports and publishes (the dispatcher core of a
    /// multicore system has no sessions).
    active: bool,
    next_stats_ms: u64,
    next_refresh_ms: u64,
    limiter: Limiter,
}

impl Sys {
    pub fn new(me: usize, n: usize) -> Self {
        Self {
            me,
            active: dataplane::workers(n).contains(&me),
            next_stats_ms: 0,
            next_refresh_ms: 0,
            limiter: Limiter::new(BURST, PERIOD_MS),
        }
    }

    /// One loop pass: counters, due topics, requests.
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
        let requests: alloc::vec::Vec<SysRequest> = broker.drain_sys_requests().collect();
        for r in requests {
            match r.kind {
                SysKind::Query => self.query(broker, &r, now_ms),
                // The console arrives with O2: nothing acts on it yet.
                SysKind::Console => {}
            }
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

    fn query(&mut self, broker: &mut Broker, r: &SysRequest, now_ms: u64) {
        if !self.limiter.allow(now_ms) {
            return;
        }
        debug!("console: {} queried $SYS/query/info", r.from);
        let mut busy = [0u8; MAX_CPUS];
        let info = collect(&mut busy);
        broker.sys_publish(sys::QUERY_INFO_RESPONSE, sys::json(&info).as_bytes());
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
        console_dropped: 0,
    }
}
