//! MQTT service on the own TCP stack (M14): the TLS listener
//! (`network.mqtt_tls_port`, mTLS, identity from the client certificate)
//! and, in dev builds only, the plaintext listener. Each data core runs one
//! instance with its broker *shard* (M13, ADR-032).
//!
//! The service is event driven: TCP hands it accepted connections and
//! in-order data synchronously ([`urmqtt_tcp::App`]), the broker reports
//! the connections with new output ([`Broker::drain_ready`]), and nothing
//! on the per-packet path scans all connections.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::Ordering;
use urmqtt_broker::{Acl, Broker, Buf, CloseReason, Config, ConnId};
use urmqtt_config::CONFIG;
use urmqtt_log::{debug, info, warn};
use urmqtt_mqtt::{Limits, QoS};
use urmqtt_net::admission::{Admission, Outcome, REASONS, Reason};
use urmqtt_sync::spsc::{Consumer, Producer};
use urmqtt_sync::sync::OnceCell;
use urmqtt_tcp::{Addr, Endpoint, TcpStack};
use urmqtt_tls::{CertRole, Event, IdentityField, ServerSetup, TicketKeys, TlsServer, TlsSession};

use crate::conn_limit;
use crate::dataplane::{self, CoreMsg, Link, Tconn};
use crate::db::{self, DbReq, DbResp, LogBatch, Restored};
use crate::watchdog;

/// The WebSocket listener's connections (ADR-272).
mod ws;

/// Reply bytes in flight from a home core to one relayed connection.
const RELAY_CREDIT: usize = 32 * 1024;
const RELAY_CHUNK: usize = 16 * 1024;
/// QoS 0 fan-out to a core is dropped beyond this backlog (QoS 1 is kept).
const ROUTE_BACKLOG: usize = 16_384;
/// Telemetry records held back while the log ring is full; beyond this
/// they are dropped and counted (the data plane never blocks).
const LOG_BACKLOG_MAX: usize = 65_536;
/// Hand a telemetry batch to the DB core at this size or age.
const LOG_BATCH: usize = 256;
const LOG_BATCH_MS: u64 = 1;
/// Ciphertext queued for TCP per connection before we stop taking replies.
const TX_BUF: usize = 32 * 1024;
/// Device-registry updates are skipped (counted) while this many DB
/// requests wait for the ring: they are statistics, and a reconnect storm
/// must not queue one per connection without bound (M16).
const SEEN_BACKLOG_MAX: usize = 4_096;
/// New connections are refused while this many DB requests wait: durable
/// state changes are never dropped, so admission is the backpressure.
const DB_BACKLOG_REFUSE: usize = 16_384;
/// A handshake (or, on the dev port, the CONNECT) must arrive within this.
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// How long a connection of a revoked certificate may stay open while its
/// broker says DISCONNECT 0x98 (ADR-275); then the transport cuts it.
const REVOKE_GRACE_MS: u64 = 1_000;
/// ... or within this while the core is under pressure (three quarters of
/// its in-flight limit are taken): a handshake that has not finished in 3 s
/// then is almost surely a dead peer, and its slot is worth more to a
/// client that is there (ADR-080).
const HANDSHAKE_TIMEOUT_PRESSURE_MS: u64 = 3_000;
/// How often memory left by a past peak is returned (M16).
const SHRINK_MS: u64 = 10_000;
/// Connections per core (TLS and plaintext together).
pub const MAX_CONNS: usize = 1 << 20;

/// Where a connection's MQTT session lives.
#[derive(Clone, Copy)]
enum Peer {
    /// In this core's broker shard.
    Local(ConnId),
    /// In another core's shard, relayed over the mesh.
    Remote { home: u16 },
}

/// A dense map from ids chosen elsewhere (TCP or broker connection ids)
/// to values, on the chunked slab: no tree nodes, slack under one chunk
/// (M15).
struct Slab<T>(urmqtt_mm::slab::Slab<T>);

impl<T> Slab<T> {
    const fn new() -> Self {
        Self(urmqtt_mm::slab::Slab::new())
    }

    fn get(&self, k: &u32) -> Option<&T> {
        self.0.get(*k)
    }

    fn get_mut(&mut self, k: &u32) -> Option<&mut T> {
        self.0.get_mut(*k)
    }

    fn insert(&mut self, k: u32, v: T) {
        self.0.insert_at(k, v);
    }

    fn remove(&mut self, k: &u32) -> Option<T> {
        self.0.take_at(*k)
    }

    fn contains_key(&self, k: &u32) -> bool {
        self.0.contains(*k)
    }
}

/// One TCP connection on this core (its transport side).
struct Conn {
    tls: bool,
    session: Option<TlsSession>,
    peer: Option<Peer>,
    tconn: Tconn,
    /// Bytes for TCP (ciphertext, or plaintext on the dev port) that the
    /// stack has not taken yet.
    pending: Buf,
    /// Dev plaintext port: bytes held until the CONNECT names the client.
    early: Buf,
    /// Relayed replies waiting for room in `pending` (relayed connections).
    #[allow(clippy::box_collection)]
    outq: Option<Box<VecDeque<Vec<u8>>>>,
    /// The home core asked to close after its replies.
    remote_close: bool,
    /// We are closing: close_notify and FIN after `pending`.
    closing: bool,
    fin_sent: bool,
    /// The low 32 bits of `urmqtt_tls::serial_tag` of the client
    /// certificate (0: none yet, or plaintext), to find the live
    /// connections of a revoked serial (H1). 32 bits fit the struct's
    /// padding, so a connection costs nothing more; a collision only
    /// closes an unrelated connection, which reconnects and is verified in
    /// full.
    serial_tag: u32,
}

/// A connection counted by [`Admission`] as a handshake in flight. Kept
/// beside the connection, not in it: only a few exist at a time and `Conn`
/// has a byte budget (ADR-034).
struct Flight {
    /// The peer's address, for the per-address limit.
    ip: Addr,
    /// When the connection was accepted (ms, wrapping), for the latency.
    t0_ms: u32,
}

// Per-connection budget (M15, ADR-034), checked at compile time: the
// kernel crate has no host tests.
const _: () = assert!(core::mem::size_of::<Conn>() <= 152);
const _: () = assert!(core::mem::size_of::<Remote>() <= 16);

/// An accepted connection waiting for its handshake (and CONNECT).
#[derive(Clone, Copy)]
struct Pending {
    at_ms: u64,
    c: u32,
    tconn: Tconn,
}

impl Pending {
    /// Still waiting: the same connection, not attached, not closing.
    fn pending(&self, conns: &Slab<Conn>) -> bool {
        conns
            .get(&self.c)
            .is_some_and(|k| k.tconn == self.tconn && k.peer.is_none() && !k.closing)
    }
}

/// How a connection stops being a handshake in flight.
#[derive(Clone, Copy)]
enum Leave {
    Done,
    Failed,
    TimedOut,
}

/// How often admission's numbers are reported.
const REPORT_MS: u64 = 5_000;

/// A connection relayed from another core's transport (home side).
struct Remote {
    tconn: Tconn,
    /// Reply bytes the transport core will still accept.
    credit: u32,
    /// The transport core.
    from: u16,
    close_sent: bool,
}

pub struct MqttService {
    /// This data core and the number of data cores.
    me: usize,
    n: usize,
    /// This core's broker shard: the sessions whose home is this core.
    broker: Broker,
    tls: Option<TlsServer>,
    tls_port: u16,
    plain_port: Option<u16>,
    conns: Slab<Conn>,
    /// Broker connection → TCP connection (local sessions).
    by_broker: Slab<u32>,
    /// Connections whose `pending` could not all be handed to TCP.
    blocked: Vec<u32>,
    /// Accepted connections not yet attached to a session, oldest first.
    handshakes: VecDeque<Pending>,
    app: Vec<u8>,
    /// Handshake admission: limits, in-flight counts, statistics (ADR-080).
    adm: Admission,
    /// The connections `adm` counts as in flight.
    flights: Slab<Flight>,
    /// Established TLS connections of this core that the per-address table
    /// counts (NOW-14, ADR-280): connection id to its source address. Given
    /// back in `drop_conn`, the one place every close path ends in.
    sources: Slab<Addr>,
    /// `sources`' length (how many this core holds), for the report.
    sources_held: u32,
    /// Refusals and dropped SYNs already logged, by [`Reason`]: the log
    /// lines come at powers of two.
    logged: [u64; REASONS],
    logged_syn: [u64; REASONS],
    /// The heap check takes the allocator's global lock; once per
    /// millisecond is enough for a reserve of megabytes.
    heap_ok: bool,
    heap_checked_ms: u64,
    last_report_ms: u64,
    report_prev: urmqtt_net::admission::Stats,
    db: Option<DbLink>,
    log: Option<LogLink>,
    /// Home side: connections relayed from transport cores.
    remote: Slab<Remote>,
    /// Per transport core: its connection id → (relay id, broker connection).
    by_tconn: Vec<Slab<(Tconn, ConnId)>>,
    slot_gen: u32,
    dropped_routes: u64,
    last_tick_ms: u64,
    last_shrink_ms: u64,
    ready: Vec<ConnId>,
    /// Connections to reset (handshake timeouts), for the network loop.
    aborts: Vec<u32>,
    /// The control epoch this core last acted on (H1).
    control_epoch: u64,
    /// The broker's unauthorized-control counter at the last report.
    dropped_control_seen: u64,
    /// Retained refusals already counted: (identity limit, byte budget).
    retained_refused_seen: (u64, u64),
    /// Refused tickets already logged (first worker core only).
    tickets_refused_seen: u64,
    ticket_rotations_seen: u64,
    /// `$SYS/` topics, the console and the operator's commands (O1, O2).
    sys: crate::sys::Sys,
    /// The plaintext listener (P1, ADR-230); `None` unless the image's
    /// configuration switches it on.
    plain: Option<Box<crate::plain::PlainState>>,
    /// The WebSocket listener (ADR-272); `None` unless switched on.
    ws: Option<Box<crate::websocket::WsState>>,
    /// The run-time accounts this core last applied (ADR-285), to tell which
    /// changed.
    accounts_seen: urmqtt_plain::Accounts,
    /// The Prometheus endpoint (ADR-290); `None` unless switched on.
    metrics: Option<Box<crate::metrics::MetricsState>>,
    /// Publisher back-pressure: window changes and notes to other shards
    /// (ADR-269).
    flow: crate::backpressure::FlowLink,
    /// Connections of a revoked certificate, told by their broker, and when
    /// the transport cuts them anyway: (connection, its tconn, deadline).
    revoking: Vec<(u32, Tconn, u64)>,
}

/// This core's telemetry ring to the DB core.
struct LogLink {
    tx: Producer<'static, LogBatch, 64>,
    batch: LogBatch,
    since_ms: u64,
    dropped: u64,
}

impl LogLink {
    fn add(&mut self, msg: urmqtt_broker::Msg, now_ms: u64) {
        if self.batch.len() >= LOG_BACKLOG_MAX {
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                warn!(
                    "telemetry: log backlog full, {} record(s) dropped",
                    self.dropped
                );
            }
            return;
        }
        if self.batch.is_empty() {
            self.since_ms = now_ms;
        }
        let unix_ms = crate::boot::now_unix_ms().unwrap_or(0);
        self.batch.push((unix_ms, msg));
    }

    fn pump(&mut self, now_ms: u64) {
        if self.batch.is_empty()
            || (self.batch.len() < LOG_BATCH && now_ms.saturating_sub(self.since_ms) < LOG_BATCH_MS)
        {
            return;
        }
        let batch = core::mem::take(&mut self.batch);
        match self.tx.push(batch) {
            Ok(()) => db::notify(),
            // Ring full: keep accumulating and retry on the next pass.
            Err(b) => self.batch = b,
        }
    }
}

/// The data plane's side of the DB rings.
struct DbLink {
    tx: Producer<'static, DbReq, 4096>,
    rx: Consumer<'static, DbResp, 256>,
    /// Requests waiting for room in the ring. Durable changes are never
    /// dropped; registry updates are skipped beyond `SEEN_BACKLOG_MAX`.
    backlog: VecDeque<DbReq>,
    seen_skipped: u64,
    committed_ops: u64,
    failed_ops: u64,
    max_commit_us: u32,
    log_durable: u64,
    /// Something was queued since the DB core was last woken.
    sent: bool,
}

impl DbLink {
    /// Records that device `id` connected, unless the DB is far behind.
    fn seen(&mut self, id: &str) {
        if self.backlog.len() >= SEEN_BACKLOG_MAX {
            self.seen_skipped += 1;
            if self.seen_skipped.is_power_of_two() {
                warn!(
                    "db: {} device-registry update(s) skipped, the DB core is behind",
                    self.seen_skipped
                );
            }
            return;
        }
        self.send(DbReq::DeviceSeen {
            id: id.into(),
            unix: crate::boot::now_unix().unwrap_or(0) as i64,
        });
    }

    fn send(&mut self, req: DbReq) {
        // Keep order: nothing overtakes the backlog.
        let rejected = if self.backlog.is_empty() {
            let r = self.tx.push(req).err();
            self.sent |= r.is_none();
            r
        } else {
            Some(req)
        };
        if let Some(r) = rejected {
            self.backlog.push_back(r);
        }
    }

    /// Moves the backlog into the ring, collects responses, wakes the DB.
    fn pump(&mut self) {
        while let Some(r) = self.backlog.pop_front() {
            if let Err(r) = self.tx.push(r) {
                self.backlog.push_front(r);
                break;
            }
            self.sent = true;
        }
        while let Some(resp) = self.rx.pop() {
            match resp {
                DbResp::Committed { ops, us } => {
                    self.committed_ops += u64::from(ops);
                    self.max_commit_us = self.max_commit_us.max(us);
                }
                DbResp::Failed { ops } => self.failed_ops += u64::from(ops),
                DbResp::LogDurable { records } => self.log_durable += records,
            }
        }
        if core::mem::take(&mut self.sent) {
            db::notify();
        }
    }
}

/// A configured `u32` limit as the `u16` the MQTT codec takes, saturating:
/// `as u16` turned 65 536 into 0 (every topic refused) and 65 537 into 1
/// (ADR-346).
pub(crate) fn limit16(v: u32) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

pub fn broker_config(max_connections: usize, fanout: bool) -> Config {
    let l = CONFIG.limits;
    Config {
        limits: Limits {
            max_packet_size: l.max_packet_size,
            max_topic_len: limit16(l.max_topic_len),
            max_topic_levels: limit16(l.max_topic_levels),
            // Identities become topic levels, so the topic bound applies.
            max_client_id_len: limit16(l.max_topic_len),
            max_topics_per_packet: limit16(l.max_subscriptions_per_session),
        },
        max_connections: max_connections.min(l.max_connections_per_core as usize),
        max_subscriptions_per_session: l.max_subscriptions_per_session as usize,
        max_inflight: l.max_inflight_qos1 as usize,
        max_queued: l.max_queued_per_offline_session as usize,
        max_retained_per_device: l.max_retained_per_device as usize,
        max_retained_bytes: l.max_retained_bytes as usize,
        rate_tokens: l.publish_rate_per_device.tokens,
        rate_period_ms: l.publish_rate_per_device.per_ms,
        max_outbound_bytes: TX_BUF,
        acl: Acl {
            device_publish: CONFIG.acl.device_publish,
            device_subscribe: CONFIG.acl.device_subscribe,
            service_ids: CONFIG.acl.service_ids,
            service_publish: CONFIG.acl.service_publish,
            service_subscribe: CONFIG.acl.service_subscribe,
            operator_ids: CONFIG.acl.operator_ids,
        },
        persist: db::active(),
        telemetry: CONFIG.storage.telemetry_topics,
        fanout,
        control_ids: CONFIG.control.service_ids,
        plain: crate::plain::broker_policy(),
        web: crate::websocket::broker_policy(),
        publisher_backpressure: if CONFIG.limits.publisher_backpressure {
            urmqtt_broker::PublisherBackpressure::Single
        } else {
            urmqtt_broker::PublisherBackpressure::Off
        },
        mqtt5: crate::mqtt5::broker_policy(),
    }
}

#[cfg(feature = "selftest")]
/// The TLS server as configured (build-time revocation list), for
/// `test=dp-bench`.
pub fn tls_server_for_bench() -> Option<TlsServer> {
    tls_server()
}

/// Retained messages refused for retention, all cores: (identity limit,
/// byte budget), for the metrics (H3).
pub static RETAINED_REFUSED: [core::sync::atomic::AtomicU64; 2] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 2];

/// The session-ticket keys every core's server shares (H2, ADR-054).
static TICKETS: OnceCell<Arc<TicketKeys>> = OnceCell::new();

fn uptime_s() -> u64 {
    urmqtt_arch::time::uptime_ns() / 1_000_000_000
}

/// Creates the shared ticket keys: rotation every 12 h, or `rotate_s`
/// (dev `test=ticket-rotate:S`). Called once, before the data cores start.
pub fn init_tickets(rotate_s: Option<u64>) {
    let interval = rotate_s.unwrap_or(urmqtt_tls::ticket::INTERVAL_S);
    let _ = TICKETS.set(Arc::new(TicketKeys::new(interval, uptime_s)));
}

fn tickets() -> Arc<TicketKeys> {
    match TICKETS.get() {
        Some(t) => t.clone(),
        // Only before `init_tickets` (self-tests): keys of their own.
        None => Arc::new(TicketKeys::new(urmqtt_tls::ticket::INTERVAL_S, uptime_s)),
    }
}

/// Session-ticket counters for the metrics (`ops`).
pub fn ticket_stats() -> urmqtt_tls::ticket::TicketStats {
    TICKETS.get().map(|t| t.stats()).unwrap_or_default()
}

/// Builds the trust anchors' verification tables once, on the boot CPU before
/// the data cores start (ADR-261): they are shared by every core's server, and
/// the heap line that follows (`set_heap_reserve`) then includes them. Logs
/// what they cost, measured on the heap (blocks, allocator rounding included).
pub fn prepare_trust_anchors() {
    if CONFIG.network.mqtt_tls_port == 0 {
        return;
    }
    let free = || crate::vm::HEAP.stats().map_or(0, |(f, _)| f);
    let before = free();
    let (n, bytes) = urmqtt_tls::server::prepare_trust_anchors(&[
        urmqtt_config::CONFIG.trust.operational,
        urmqtt_config::CONFIG.trust.bootstrap,
    ]);
    info!(
        "tls: {n} trust-anchor verification table(s), {} KiB of heap ({} KiB requested)",
        before.saturating_sub(free()) >> 10,
        bytes >> 10
    );
}

/// This core's TLS server: the image's trust anchors by role and the
/// revocation list shared with the control channel (H1).
fn tls_server() -> Option<TlsServer> {
    tls_server_with(true)
}

/// `client_auth` false: the same server asking for no client certificate,
/// for the WebSocket listener's password mode (ADR-272).
fn tls_server_with(client_auth: bool) -> Option<TlsServer> {
    let setup = ServerSetup {
        operational_ca_pems: urmqtt_config::CONFIG.trust.operational,
        bootstrap_ca_pems: urmqtt_config::CONFIG.trust.bootstrap,
        cert_pem: urmqtt_config::CONFIG.tls.cert_pem,
        key_pem: urmqtt_config::CONFIG.tls.key_pem,
        identity_field: match CONFIG.tls.identity_field {
            urmqtt_config::IdentityField::Cn => IdentityField::Cn,
            urmqtt_config::IdentityField::SanUri => IdentityField::SanUri,
        },
        resumption: CONFIG.tls.resumption,
        revocations: crate::control::revocations(),
        tickets: tickets(),
    };
    let made = if client_auth {
        TlsServer::new(&setup)
    } else {
        TlsServer::new_server_only(&setup)
    };
    match made {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("tls: server setup failed: {e:?}");
            None
        }
    }
}

impl MqttService {
    /// The MQTT service of data core `me` (of `n`): the broker shard for
    /// the sessions whose home is `me`, and the connections TCP accepts on
    /// this core's stack.
    pub fn new(restored: Option<&Restored>, me: usize, n: usize) -> Self {
        // The revocation list is shared with the control channel; it was
        // filled from the store (seeded from the image) or the image.
        // The TLS listener is off when its port is 0 (plaintext only, ADR-233): no server is even set up.
        let tls = if CONFIG.network.mqtt_tls_port == 0 {
            None
        } else {
            tls_server()
        };
        if me == dataplane::workers(n).start {
            if CONFIG.network.mqtt_tls_port == 0 {
                info!(
                    "mqtt: TLS listener off (plaintext only: no mutual TLS, so no operator, service or control rights, no $SYS and no certificate checks; every identity comes from the plaintext login)"
                );
            } else if tls.is_some() {
                info!(
                    "mqtt: TLS 1.3 listener on port {} (mutual TLS, identity = certificate {:?}, {} revoked serial(s), {} operational and {} bootstrap CA file(s))",
                    CONFIG.network.mqtt_tls_port,
                    CONFIG.tls.identity_field,
                    crate::control::revocations().len(),
                    urmqtt_config::CONFIG.trust.operational.len(),
                    urmqtt_config::CONFIG.trust.bootstrap.len()
                );
                if CONFIG.tls.resumption {
                    let iv = tickets().interval();
                    info!(
                        "tls: session tickets under random per-boot keys, rotated every {} s of uptime (ticket lifetime {} s)",
                        iv, iv
                    );
                }
            }
            if let Some(port) = CONFIG.network.mqtt_plain_port {
                warn!(
                    "mqtt: PLAINTEXT listener on port {port} (dev build only, identity = client id)"
                );
            }
            crate::plain::announce(dataplane::workers(n).len());
            crate::websocket::announce(dataplane::workers(n).len());
            crate::metrics::announce(dataplane::workers(n).len());
            // A/B (ADR-296): the listeners are up, a trial boot's health
            // clock starts (a TLS listener whose setup failed is not up).
            if CONFIG.network.mqtt_tls_port == 0 || tls.is_some() {
                crate::bootslot::set_listening();
            }
            // ADR-269: what a slow single subscriber does to its publisher.
            info!(
                "mqtt: publisher back-pressure {}",
                if CONFIG.limits.publisher_backpressure {
                    "single (a publisher whose QoS 0 message has one full subscriber is paused, 500 ms at most)"
                } else {
                    "off (QoS 0 to a full subscriber is dropped)"
                }
            );
        }
        let mut broker = Broker::new(broker_config(MAX_CONNS * n, n > 1));
        // The ACL class of a run-time password account (ADR-285).
        broker.set_login_class(crate::control::account_class);
        // Shared groups are owned by the worker shards (ADR-275); set before
        // the restore, whose sessions join their groups again.
        let w = dataplane::workers(n);
        broker.set_shards(me as u16, w.start as u16, w.len() as u16);
        let mut homed = 0;
        let mut expired = 0;
        if let Some(r) = restored {
            crate::mqtt5::restore(&mut broker, r, me, n, &mut homed, &mut expired);
        }
        let db = db::endpoints(me)
            .filter(|_| db::active())
            .map(|(tx, rx)| DbLink {
                tx,
                rx,
                backlog: VecDeque::new(),
                seen_skipped: 0,
                committed_ops: 0,
                failed_ops: 0,
                max_commit_us: 0,
                log_durable: 0,
                sent: false,
            });
        let log = db::log_producer(me)
            .filter(|_| db::active() && !CONFIG.storage.telemetry_topics.is_empty())
            .map(|tx| LogLink {
                tx,
                batch: Vec::new(),
                since_ms: 0,
                dropped: 0,
            });
        if dataplane::workers(n).contains(&me) {
            info!(
                "mqtt: shard {me}/{n} ready: {homed} persistent session(s) homed here ({expired} expired while down, dropped), telemetry partition {}",
                if log.is_some() {
                    db::partition_of(me) as isize
                } else {
                    -1
                }
            );
        }
        let mut svc = Self {
            me,
            n,
            broker,
            tls,
            tls_port: CONFIG.network.mqtt_tls_port,
            plain_port: CONFIG.network.mqtt_plain_port,
            conns: Slab::new(),
            by_broker: Slab::new(),
            blocked: Vec::new(),
            handshakes: VecDeque::new(),
            app: Vec::new(),
            flights: Slab::new(),
            sources: Slab::new(),
            sources_held: 0,
            adm: Admission::new(dataplane::admission_limits()),
            logged: [0; REASONS],
            logged_syn: [0; REASONS],
            heap_ok: true,
            heap_checked_ms: u64::MAX,
            last_report_ms: 0,
            report_prev: urmqtt_net::admission::Stats::default(),
            db,
            log,
            remote: Slab::new(),
            by_tconn: (0..n).map(|_| Slab::new()).collect(),
            slot_gen: 0,
            dropped_routes: 0,
            last_tick_ms: 0,
            last_shrink_ms: 0,
            ready: Vec::new(),
            aborts: Vec::new(),
            control_epoch: crate::control::epoch(),
            dropped_control_seen: 0,
            retained_refused_seen: (0, 0),
            tickets_refused_seen: 0,
            ticket_rotations_seen: 0,
            sys: crate::sys::Sys::new(me, n),
            plain: crate::plain::PlainState::new(),
            ws: crate::websocket::WsState::new(|| tls_server_with(false)),
            accounts_seen: crate::control::accounts(),
            metrics: crate::metrics::MetricsState::new(),
            flow: crate::backpressure::FlowLink::new(),
            revoking: Vec::new(),
        };
        // The first `$SYS` pass is made here, not in the watched loop (ADR-072).
        svc.sys
            .start(&mut svc.broker, urmqtt_arch::time::uptime_ns() / 1_000_000);
        svc
    }

    /// Retained messages delivered but not retained (H3): counted for the
    /// metrics, logged at powers of two per core.
    fn count_retained_refusals(&mut self) {
        let (dev, bytes, held) = self.broker.retained_refused();
        let now = (dev, bytes);
        if now == self.retained_refused_seen {
            return;
        }
        let (d, b) = (
            now.0 - self.retained_refused_seen.0,
            now.1 - self.retained_refused_seen.1,
        );
        // Relaxed: statistics.
        RETAINED_REFUSED[0].fetch_add(d, core::sync::atomic::Ordering::Relaxed);
        RETAINED_REFUSED[1].fetch_add(b, core::sync::atomic::Ordering::Relaxed);
        let total = now.0 + now.1;
        if (self.retained_refused_seen.0 + self.retained_refused_seen.1 + 1..=total)
            .any(u64::is_power_of_two)
        {
            warn!(
                "broker: {total} retained message(s) not retained on core {} ({} over an identity's limit of {}, {} over the {} B budget; {} B held)",
                self.me,
                now.0,
                CONFIG.limits.max_retained_per_device,
                now.1,
                CONFIG.limits.max_retained_bytes,
                held
            );
        }
        self.retained_refused_seen = now;
    }

    /// Key rotations, and refused session tickets (full handshakes
    /// instead) at powers of two by reason; from one core, as the keys are
    /// shared.
    fn log_ticket_refusals(&mut self) {
        if self.me != dataplane::workers(self.n).start {
            return;
        }
        let s = ticket_stats();
        if s.rotations > self.ticket_rotations_seen {
            self.ticket_rotations_seen = s.rotations;
            info!(
                "tls: session-ticket keys rotated ({} key change(s) since boot)",
                s.rotations
            );
        }
        let total: u64 = s.refused.iter().sum();
        if total > self.tickets_refused_seen {
            self.tickets_refused_seen = total;
            if total.is_power_of_two() {
                let [expired, unknown, invalid, malformed] = s.refused;
                info!(
                    "tls: {total} session ticket(s) refused, full handshake instead (expired {expired}, unknown key {unknown}, invalid {invalid}, malformed {malformed})"
                );
            }
        }
    }

    /// Connections the network loop must reset (`TcpStack::abort`).
    pub fn take_aborts(&mut self) -> Vec<u32> {
        core::mem::take(&mut self.aborts)
    }

    /// The TCP ports this service listens on.
    pub fn ports(&self) -> Vec<u16> {
        let mut p = Vec::new();
        if self.tls.is_some() {
            p.push(self.tls_port);
        }
        if let Some(x) = self.plain_port {
            p.push(x);
        }
        if let Some(pl) = &self.plain {
            p.push(pl.port());
        }
        if let Some(w) = &self.ws {
            p.push(w.port());
        }
        if let Some(m) = &self.metrics {
            p.push(m.port());
        }
        p
    }

    /// Whether the DB core is so far behind that new connections wait.
    fn db_behind(&self) -> bool {
        self.db
            .as_ref()
            .is_some_and(|d| d.backlog.len() >= DB_BACKLOG_REFUSE)
    }

    /// Free heap above the reserve, looked up at most once per millisecond.
    fn heap_ok(&mut self, now_ms: u64) -> bool {
        if now_ms != self.heap_checked_ms {
            self.heap_checked_ms = now_ms;
            self.heap_ok = dataplane::heap_has_room();
        }
        self.heap_ok
    }

    /// A SYN: answer it only if a connection from `ip` would be admitted
    /// now (PERF, ADR-080). A refusal here costs no state and no packet,
    /// and the client's TCP retries after its backoff instead of at once.
    pub fn syn_ok(&mut self, port: u16, ip: Addr, now_ms: u64) -> bool {
        // The plaintext port: its allow-list, lock-out and limits (P1).
        if self.is_plain_policy_port(port) {
            let (heap_ok, behind) = (self.heap_ok(now_ms), self.db_behind());
            return self
                .plain
                .as_mut()
                .is_some_and(|p| p.syn_ok(ip, now_ms, heap_ok, behind));
        }
        // The metrics port: its allow-list and limits only (ADR-290).
        if self.is_metrics_port(port) {
            let heap_ok = self.heap_ok(now_ms);
            return self
                .metrics
                .as_mut()
                .is_some_and(|m| m.syn_ok(ip, now_ms, heap_ok));
        }
        // The WebSocket port: its own limits first, then the TLS admission
        // like any TLS connection (ADR-272).
        if self.is_ws_port(port) && !self.ws.as_mut().is_some_and(|w| w.syn_ok(ip, now_ms)) {
            return false;
        }
        let tls = Some(port) != self.plain_port;
        // Established connections per address (ADR-280), before anything
        // that costs: no token, no state, no packet.
        let r = if tls && !conn_limit::syn_ok(ip) {
            self.adm.count_syn_dropped(Reason::PerIpEstablished);
            Reason::PerIpEstablished
        } else {
            let (heap_ok, behind) = (self.heap_ok(now_ms), self.db_behind());
            let Err(r) = self.adm.syn_check(ip, tls, now_ms, heap_ok, behind) else {
                return true;
            };
            r
        };
        let n = self
            .adm
            .stats()
            .syn_dropped
            .get(r as usize)
            .copied()
            .unwrap_or(0);
        if let Some(l) = self.logged_syn.get_mut(r as usize)
            && n.is_power_of_two()
            && n > *l
        {
            *l = n;
            warn!(
                "admission: {n} SYN(s) dropped without an answer on core {}: {}",
                self.me,
                r.text()
            );
        }
        false
    }

    /// Whether `port` is the plaintext listener of the image's configuration
    /// (not the development port, which has no policy).
    fn is_plain_policy_port(&self, port: u16) -> bool {
        self.plain.as_ref().is_some_and(|p| p.port() == port)
    }

    /// Whether `port` is the Prometheus endpoint's.
    fn is_metrics_port(&self, port: u16) -> bool {
        self.metrics.as_ref().is_some_and(|m| m.port() == port)
    }

    /// Admission for a new connection (PROMPT §6, M16): free heap above the
    /// reserve, fewer than the in-flight limits, and for TLS a handshake
    /// token. Refusals cost no crypto work and are logged rate-limited.
    ///
    /// For TLS the established-connections table (ADR-280) is asked first, so
    /// a refusal for it burns no handshake token; if admission then refuses,
    /// the place is given back. On success the connection `c` is remembered in
    /// `sources` when the table counted it.
    fn admit(&mut self, c: u32, tls: bool, ip: Addr, now_ms: u64) -> bool {
        use conn_limit::Counted;
        let placed = if tls {
            conn_limit::open(ip)
        } else {
            Counted::No
        };
        let r = if placed == Counted::Refuse {
            self.adm.count_refused(Reason::PerIpEstablished);
            Reason::PerIpEstablished
        } else {
            let (heap_ok, behind) = (self.heap_ok(now_ms), self.db_behind());
            match self.adm.admit(ip, tls, now_ms, heap_ok, behind) {
                Ok(()) => {
                    if placed == Counted::Yes {
                        self.sources.insert(c, ip);
                        self.sources_held += 1;
                    }
                    return true;
                }
                Err(r) => {
                    if placed == Counted::Yes {
                        conn_limit::close(ip);
                    }
                    r
                }
            }
        };
        let n = self
            .adm
            .stats()
            .refused
            .get(r as usize)
            .copied()
            .unwrap_or(0);
        // Rate-limited log: 1st, 2nd, 4th, 8th, ... refusal of each kind.
        if let Some(l) = self.logged.get_mut(r as usize)
            && n.is_power_of_two()
            && n > *l
        {
            *l = n;
            warn!("admission: {n} connection(s) refused: {}", r.text());
        }
        false
    }

    /// The connection `c` stops counting as a handshake in flight (once).
    fn leave_flight(&mut self, c: u32, how: Leave, now_ms: u64) {
        let outcome = |t0_ms: u32| match how {
            Leave::Done => Outcome::Done {
                latency_ms: (now_ms as u32).wrapping_sub(t0_ms),
            },
            Leave::Failed => Outcome::Failed,
            Leave::TimedOut => Outcome::TimedOut,
        };
        if let Some(f) = self.flights.remove(&c) {
            self.adm.leave(f.ip, outcome(f.t0_ms));
        } else if let Some(p) = self.plain.as_mut() {
            // A plaintext connection waiting for its CONNECT (P1).
            p.leave_flight(c, outcome);
        }
    }

    /// Gives back the place `c` holds in the per-address table, once.
    fn release_source(&mut self, c: u32) {
        if let Some(ip) = self.sources.remove(&c) {
            self.sources_held = self.sources_held.saturating_sub(1);
            conn_limit::close(ip);
        }
    }

    /// Forgets the connection `c`: gives back what the plaintext listener
    /// and the per-address table counted for it, and drops the transport
    /// state. Every way a connection ends (peer close, reset, TCP timeout,
    /// handshake timeout, watchdog abort) comes here.
    fn drop_conn(&mut self, c: u32, now_ms: u64) {
        self.release_source(c);
        if let Some(p) = self.plain.as_mut() {
            p.release(c, (now_ms / 1000) as u32);
        }
        if let Some(w) = self.ws.as_mut() {
            w.release(c, now_ms);
        }
        if let Some(m) = self.metrics.as_mut() {
            m.release(c);
        }
        self.conns.remove(&c);
    }

    /// Mirrors this core's admission counters into the shared statistics
    /// (every 100 ms) and, every 5 s, says what admission did.
    fn publish_admission(&mut self, now_ms: u64) {
        let me = self.me;
        let Some(h) = dataplane::HS.get(me) else {
            return;
        };
        let s = *self.adm.stats();
        // Relaxed: statistics.
        let st = |a: &core::sync::atomic::AtomicU64, v: u64| a.store(v, Ordering::Relaxed);
        st(&h.started, s.started);
        st(&h.done, s.done);
        st(&h.failed, s.failed);
        st(&h.timed_out, s.timed_out);
        for (a, v) in h.refused.iter().zip(s.refused) {
            st(a, v);
        }
        for (a, v) in h.syn_dropped.iter().zip(s.syn_dropped) {
            st(a, v);
        }
        st(&h.latency_sum_ms, s.latency_sum_ms);
        st(&h.slow, s.slower_than(3));
        h.in_flight.store(self.adm.in_flight(), Ordering::Relaxed);
        if now_ms.saturating_sub(self.last_report_ms) < REPORT_MS {
            return;
        }
        self.last_report_ms = now_ms;
        let w = self.adm.take_window();
        let prev = core::mem::replace(&mut self.report_prev, w);
        h.latency_max_ms
            .store(w.window_latency_max_ms, Ordering::Relaxed);
        h.in_flight_max
            .store(w.window_in_flight_max, Ordering::Relaxed);
        let d = |a: u64, b: u64| a.saturating_sub(b);
        let done = d(w.done, prev.done);
        let started = d(w.started, prev.started);
        let syn = d(w.syn_dropped_total(), prev.syn_dropped_total());
        let refused = d(w.refused_total(), prev.refused_total());
        if started
            + done
            + syn
            + refused
            + d(w.failed, prev.failed)
            + d(w.timed_out, prev.timed_out)
            == 0
        {
            return;
        }
        let by = |a: &[u64; REASONS], b: &[u64; REASONS]| {
            let g = |i: usize| {
                a.get(i)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(b.get(i).copied().unwrap_or(0))
            };
            (g(0), g(1), g(4), g(2), g(3), g(5))
        };
        let (r, c, i, m, db, e) = by(&w.refused, &prev.refused);
        let (sr, sc, si, sm, sdb, se) = by(&w.syn_dropped, &prev.syn_dropped);
        info!(
            "handshakes: core {me}: {started} started, {done} done, {} failed, {} timed out; \
             {refused} refused at the ACK (rate {r}, core {c}, address {i}, memory {m}, storage {db}, established per address {e}); \
             {syn} SYN(s) dropped (rate {sr}, core {sc}, address {si}, memory {sm}, storage {sdb}, established per address {se}); \
             in flight {} now / {} at most, {} established from counted addresses; accept to done: mean {} ms, max {} ms, {} over 250 ms, {} over 1 s",
            d(w.failed, prev.failed),
            d(w.timed_out, prev.timed_out),
            self.adm.in_flight(),
            w.window_in_flight_max,
            self.sources_held,
            d(w.latency_sum_ms, prev.latency_sum_ms) / done.max(1),
            w.window_latency_max_ms,
            d(w.slower_than(3), prev.slower_than(3)),
            d(w.slower_than(4), prev.slower_than(4)),
        );
    }

    // ---- TCP events (called from the stack, see `TcpEvents`) -------------

    fn on_accept(&mut self, c: u32, port: u16, ip: Addr, now_ms: u64) -> bool {
        // The plaintext port has an admission of its own (P1, ADR-230).
        let policy = self.is_plain_policy_port(port);
        // The Prometheus endpoint: plain HTTP with an admission of its own
        // (ADR-290); no TLS, no handshake, no session.
        let metrics = self.is_metrics_port(port);
        let tls = !policy && !metrics && Some(port) != self.plain_port;
        if metrics {
            let heap_ok = self.heap_ok(now_ms);
            let admitted = self
                .metrics
                .as_mut()
                .is_some_and(|m| m.accept(c, ip, now_ms, heap_ok));
            if !admitted {
                return false;
            }
        } else if policy {
            let (heap_ok, behind) = (self.heap_ok(now_ms), self.db_behind());
            let admitted = self
                .plain
                .as_mut()
                .is_some_and(|p| p.accept(c, ip, now_ms, heap_ok, behind));
            if !admitted {
                return false;
            }
        } else if !self.admit(c, tls, ip, now_ms) {
            return false;
        }
        // The WebSocket listener counts its own connections (ADR-272).
        let ws = self.is_ws_port(port);
        if ws && !self.ws.as_mut().is_some_and(|w| w.accept(c, ip, now_ms)) {
            self.adm.leave(ip, Outcome::Failed);
            self.release_source(c);
            return false;
        }
        let session = if tls {
            // Password mode over WebSocket: the server without client
            // certificates; otherwise the TLS port's.
            let server = match self.ws.as_ref().and_then(|w| w.server_only()) {
                Some(s) if ws => Some(s),
                _ => self.tls.as_ref(),
            };
            match server.and_then(|t| t.accept().ok()) {
                Some(s) => Some(s),
                None => {
                    // Admitted but no session could be built: give the slot back.
                    self.adm.leave(ip, Outcome::Failed);
                    self.release_source(c);
                    if let Some(w) = self.ws.as_mut() {
                        w.release(c, now_ms);
                    }
                    return false;
                }
            }
        } else {
            None
        };
        self.slot_gen = self.slot_gen.wrapping_add(1);
        let tconn = (u64::from(self.slot_gen) << 32) | u64::from(c);
        self.conns.insert(
            c,
            Conn {
                tls,
                session,
                peer: None,
                tconn,
                pending: Buf::default(),
                early: Buf::default(),
                outq: None,
                remote_close: false,
                closing: false,
                fin_sent: false,
                serial_tag: 0,
            },
        );
        // (A plaintext connection's flight is kept by its listener; a metrics
        // connection has none, only a deadline of its own.)
        if !policy && !metrics {
            self.flights.insert(
                c,
                Flight {
                    ip,
                    t0_ms: now_ms as u32,
                },
            );
        }
        // The queue only serves the timeout; entries of connections that
        // left it are dropped here when they pile up behind an old one.
        if self.handshakes.len() > 2 * self.adm.limits().per_core as usize + 16 {
            let conns = &self.conns;
            self.handshakes.retain(|p| p.pending(conns));
        }
        if !metrics {
            self.handshakes.push_back(Pending {
                at_ms: now_ms,
                c,
                tconn,
            });
        }
        dataplane::count_accept(self.me);
        true
    }

    /// Is `c` a TLS connection whose handshake has not finished, or a
    /// plaintext one whose login (a password check costs about as much as a
    /// handshake step) has not been decided?
    fn is_handshaking(&self, c: u32) -> bool {
        self.conns
            .get(&c)
            .is_some_and(|k| match k.session.as_ref() {
                // A WebSocket connection is handshaking until its upgrade (and
                // in password mode its login, a password check) is done.
                Some(s) => !s.is_established() || (k.peer.is_none() && self.is_ws(c)),
                None => k.peer.is_none() && self.plain.as_ref().is_some_and(|p| p.has(c)),
            })
    }

    fn on_data(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        if k.closing && k.peer.is_none() {
            // Session already ended: whatever still arrives is dropped.
            return;
        }
        let Some(sess) = k.session.as_mut() else {
            if k.peer.is_some() {
                self.deliver(c, data, link, now_ms);
            } else {
                self.sniff_connect(c, data, link, now_ms);
            }
            return;
        };
        self.app.clear();
        let t0 = urmqtt_arch::time::uptime_ns();
        let r = sess.input(data, k.pending.vec_mut(), &mut self.app);
        dataplane::tls_time(self.me, urmqtt_arch::time::uptime_ns() - t0);
        match r {
            Ok(Event::Established {
                identity,
                suite,
                resumed,
                role,
                serial_tag,
            }) => {
                k.serial_tag = crate::control::tag32(serial_tag);
                let bootstrap = role == CertRole::Bootstrap;
                // Registry (H1): in allowlist mode an unknown operational
                // identity is refused once it has proven who it is.
                // Bootstrap identities exist to become known.
                if !bootstrap && !crate::control::admitted(&identity) {
                    let n = crate::control::REGISTRY_REFUSED
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                        + 1;
                    if n.is_power_of_two() {
                        warn!("registry: {identity} is not on the allowlist, refused ({n} so far)");
                    }
                    self.start_close(c);
                    self.mark_blocked(c);
                    return;
                }
                // WebSocket (ADR-272): the session waits for the upgrade (whose
                // request may already be in `self.app`, handled below).
                if self.is_ws(c) {
                    self.ws_tls_done(c, Some((identity, bootstrap)));
                } else {
                    let home = dataplane::home_of(&identity, self.n);
                    if let Some(dbl) = self.db.as_mut()
                        && !bootstrap
                    {
                        dbl.seen(&identity);
                    }
                    debug!(
                        "tls: {identity} authenticated ({suite}{}{}) on core {}, session on core {home}",
                        if resumed { ", resumed" } else { "" },
                        if bootstrap { ", bootstrap role" } else { "" },
                        self.me
                    );
                    if self.attach(c, home, Some(&identity), bootstrap, link, now_ms) {
                        self.leave_flight(c, Leave::Done, now_ms);
                    } else {
                        self.start_close(c);
                    }
                }
            }
            // Only the WebSocket listener's password mode has such sessions.
            Ok(Event::EstablishedServerOnly { .. }) if self.is_ws(c) => self.ws_tls_done(c, None),
            Ok(Event::EstablishedServerOnly { .. }) => self.start_close(c),
            Ok(Event::PeerClosed) => self.start_close(c),
            Ok(Event::None) => {}
            Err(e) => {
                warn!("tls: connection refused: {e:?}");
                self.start_close(c);
            }
        }
        if !self.app.is_empty() {
            let mut app = core::mem::take(&mut self.app);
            if self.is_ws(c) {
                self.ws_input(c, &mut app, link, now_ms);
            } else {
                self.deliver(c, &app, link, now_ms);
            }
            app.clear();
            self.app = app;
        }
        self.mark_blocked(c);
    }

    /// The peer sent FIN: the session ends now (MQTT has no half-close).
    fn on_peer_closed(&mut self, c: u32, link: &mut Link, now_ms: u64) {
        if let Some(w) = self.ws.as_mut() {
            w.peer_gone(c);
        }
        self.detach(c, link, now_ms);
        self.start_close(c);
        self.mark_blocked(c);
    }

    /// TCP is done with the connection (normal close, reset or timeout).
    fn on_closed(&mut self, c: u32, link: &mut Link, now_ms: u64) {
        self.detach(c, link, now_ms);
        self.leave_flight(c, Leave::Failed, now_ms);
        self.drop_conn(c, now_ms);
    }

    // ---- sessions -----------------------------------------------------------

    /// Attaches a connection to its session's home shard (here or relayed).
    fn attach(
        &mut self,
        c: u32,
        home: usize,
        identity: Option<&str>,
        bootstrap: bool,
        link: &mut Link,
        now_ms: u64,
    ) -> bool {
        let Some(k) = self.conns.get_mut(&c) else {
            return false;
        };
        if home == self.me {
            let Some(b) = self.broker.open(now_ms) else {
                return false;
            };
            if let Some(id) = identity {
                self.broker.set_identity(b, id, bootstrap);
            }
            k.peer = Some(Peer::Local(b));
            self.by_broker.insert(b, c);
        } else {
            link.send(
                home,
                CoreMsg::Open {
                    tconn: k.tconn,
                    identity: identity.map(Into::into),
                    bootstrap,
                },
            );
            k.peer = Some(Peer::Remote { home: home as u16 });
        }
        true
    }

    /// Hands plaintext from the client to its session.
    fn deliver(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get(&c) else { return };
        match k.peer {
            Some(Peer::Local(b)) => self.broker.input(b, data, now_ms),
            Some(Peer::Remote { home }) => link.send(
                usize::from(home),
                CoreMsg::Input {
                    tconn: k.tconn,
                    data: data.to_vec(),
                },
            ),
            None => {}
        }
    }

    /// Dev plaintext port: holds bytes until the CONNECT names the client,
    /// then attaches to its home shard. Garbage goes to this core's shard,
    /// which rejects it.
    fn sniff_connect(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        if self.metrics.as_ref().is_some_and(|m| m.has(c)) {
            return self.metrics_input(c, data);
        }
        if self.plain.as_ref().is_some_and(|p| p.has(c)) {
            return self.plain_connect(c, data, link, now_ms);
        }
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let limit = CONFIG.limits.max_packet_size as usize + 5;
        // Either version (ADR-273 rule 1); a 5.0 client without a client id
        // is named by the shard it lands on: this one.
        let home = match crate::mqtt5::peek_connect(
            k.early.as_slice(),
            &urmqtt_mqtt::Limits::PROTOCOL_MAX,
            limit,
        ) {
            crate::mqtt5::Peek::Connect(p) if !p.client_id.is_empty() => {
                Some(dataplane::home_of(p.client_id, self.n))
            }
            crate::mqtt5::Peek::Wait => None,
            _ => Some(self.me),
        };
        let Some(home) = home.map(|h| {
            if dataplane::workers(self.n).contains(&h) {
                h
            } else {
                self.me
            }
        }) else {
            return;
        };
        let early = k.early.take();
        if self.attach(c, home, None, false, link, now_ms) {
            self.leave_flight(c, Leave::Done, now_ms);
            self.deliver(c, &early, link, now_ms);
        } else {
            self.start_close(c);
        }
    }

    /// Bytes of a metrics connection (ADR-290): held until the request is
    /// complete (at most 2 KiB are kept), then answered once and closed.
    fn metrics_input(&mut self, c: u32, data: &[u8]) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let Some(answer) = self.metrics.as_mut().map(|m| m.request(k.early.as_slice())) else {
            return;
        };
        match answer {
            crate::metrics::Answer::Wait => {}
            crate::metrics::Answer::Send(bytes) => {
                k.early.take();
                k.pending.extend_from_slice(&bytes);
                self.start_close(c);
                self.mark_blocked(c);
            }
        }
    }

    /// Metrics connections that did not finish by their deadline: reset.
    fn metrics_expire(&mut self, now_ms: u64) {
        let Some(late) = self.metrics.as_mut().map(|m| m.expire(now_ms)) else {
            return;
        };
        for c in late {
            self.drop_conn(c, now_ms);
            self.aborts.push(c);
        }
    }

    /// The plaintext listener's first packet (P1, ADR-230): holds bytes until
    /// the CONNECT is complete, decides who the client is, and only then lets
    /// the broker see it, as a session of that identity on its home shard. A
    /// refusal is answered here, with a CONNACK, and the connection closes.
    fn plain_connect(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let limit = CONFIG.plaintext.max_packet_size as usize + 5;
        // Either version: the protocol level picks the decoder (ADR-273).
        let decoded =
            crate::mqtt5::peek_connect(k.early.as_slice(), &crate::plain::mqtt_limits(), limit);
        // What to do once the borrow of the packet is over.
        enum Next {
            Wait,
            Refuse(u8, bool),
            Garbage,
            Accept {
                identity: String,
                key: String,
                no_id: bool,
            },
        }
        let next = match decoded {
            crate::mqtt5::Peek::Connect(p) => {
                match self.plain.as_mut().map(|pl| pl.decide(c, &p, now_ms)) {
                    Some(crate::plain::Decision::Accept(identity)) => Next::Accept {
                        key: urmqtt_broker::plain_session_key(&identity, p.client_id),
                        identity,
                        no_id: p.client_id.is_empty(),
                    },
                    Some(crate::plain::Decision::Refuse(code)) => Next::Refuse(code, p.v5),
                    None => Next::Refuse(3, p.v5),
                }
            }
            crate::mqtt5::Peek::Wait => Next::Wait,
            // A protocol level this broker does not take: told so, not a bad login.
            crate::mqtt5::Peek::Unsupported { v5 } => Next::Refuse(1, v5),
            crate::mqtt5::Peek::Garbage => Next::Garbage,
        };
        match next {
            Next::Wait => {}
            Next::Refuse(code, v5) => self.refuse_plain(c, code, v5),
            Next::Garbage => {
                if let Some(pl) = self.plain.as_mut() {
                    pl.garbage(c, now_ms);
                }
                self.refuse_plain(c, 0, false);
            }
            Next::Accept {
                identity,
                key,
                no_id,
            } => {
                // A client without an id is given a unique one by the shard it
                // lands on, so any shard will do: this one.
                let home = if no_id {
                    self.me
                } else {
                    dataplane::home_of(&key, self.n)
                };
                let home = if dataplane::workers(self.n).contains(&home) {
                    home
                } else {
                    self.me
                };
                let early = self
                    .conns
                    .get_mut(&c)
                    .map(|k| k.early.take())
                    .unwrap_or_default();
                if self.attach_plain(c, home, &identity, false, link, now_ms) {
                    self.leave_flight(c, Leave::Done, now_ms);
                    self.deliver(c, &early, link, now_ms);
                } else {
                    self.start_close(c);
                }
            }
        }
    }

    /// Answers a refused plaintext CONNECT (`code` 0: nothing to say, as for
    /// bytes that are no MQTT) in the client's version and closes after it.
    fn refuse_plain(&mut self, c: u32, code: u8, v5: bool) {
        if let Some(k) = self.conns.get_mut(&c) {
            k.early.take();
            if code != 0 {
                // CONNACK: session not present, the return (reason) code.
                let (bytes, n) = crate::mqtt5::refusal(code, v5);
                k.pending
                    .extend_from_slice(bytes.get(..n).unwrap_or_default());
            }
        }
        self.start_close(c);
        self.mark_blocked(c);
    }

    /// Like `attach`, for a plaintext connection of `identity`, or (`web`) a
    /// WebSocket password connection (ADR-272).
    fn attach_plain(
        &mut self,
        c: u32,
        home: usize,
        identity: &str,
        web: bool,
        link: &mut Link,
        now_ms: u64,
    ) -> bool {
        let Some(k) = self.conns.get_mut(&c) else {
            return false;
        };
        if home == self.me {
            let Some(b) = self.broker.open(now_ms) else {
                return false;
            };
            let bound = if web {
                self.broker.set_web_identity(b, identity)
            } else {
                self.broker.set_plain_identity(b, identity)
            };
            if !bound {
                self.broker.closed(b, now_ms);
                return false;
            }
            k.peer = Some(Peer::Local(b));
            self.by_broker.insert(b, c);
        } else {
            link.send(
                home,
                CoreMsg::OpenPlain {
                    tconn: k.tconn,
                    identity: identity.into(),
                    web,
                },
            );
            k.peer = Some(Peer::Remote { home: home as u16 });
        }
        true
    }

    /// Ends the MQTT session of a connection (persistence snapshot, will)
    /// as soon as it is closing, without waiting for TCP.
    fn detach(&mut self, c: u32, link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        match k.peer.take() {
            Some(Peer::Local(b)) => {
                self.by_broker.remove(&b);
                finish(&mut self.broker, b, now_ms);
            }
            Some(Peer::Remote { home }) => {
                link.send(usize::from(home), CoreMsg::Closed { tconn: k.tconn })
            }
            None => {}
        }
    }

    fn start_close(&mut self, c: u32) {
        if let Some(k) = self.conns.get_mut(&c)
            && !k.closing
        {
            k.closing = true;
            if let Some(sess) = k.session.as_mut() {
                // A WebSocket connection says goodbye in a close frame first.
                if let Some(w) = self.ws.as_mut() {
                    w.send_close(c, sess, k.pending.vec_mut());
                }
                sess.close(k.pending.vec_mut());
            }
            self.blocked.push(c);
        }
        // Closing before the handshake finished: no longer in flight.
        self.leave_flight(c, Leave::Failed, 0);
    }

    fn mark_blocked(&mut self, c: u32) {
        if self
            .conns
            .get(&c)
            .is_some_and(|k| !k.pending.is_empty() || k.closing)
        {
            self.blocked.push(c);
        }
    }

    /// Handles a message from data core `peer` (everything but IpConfig).
    pub fn on_msg(&mut self, peer: usize, msg: CoreMsg, link: &mut Link, now_ms: u64) {
        match msg {
            CoreMsg::Open {
                tconn,
                identity,
                bootstrap,
            } => match self.broker.open(now_ms) {
                Some(b) => {
                    if let Some(id) = &identity {
                        self.broker.set_identity(b, id, bootstrap);
                    }
                    self.remote.insert(
                        b,
                        Remote {
                            from: peer as u16,
                            tconn,
                            credit: RELAY_CREDIT as u32,
                            close_sent: false,
                        },
                    );
                    if let Some(t) = self.by_tconn.get_mut(peer) {
                        t.insert(tconn as u32, (tconn, b));
                    }
                }
                None => link.send(peer, CoreMsg::Close { tconn }),
            },
            CoreMsg::OpenPlain {
                tconn,
                identity,
                web,
            } => match self.broker.open(now_ms) {
                Some(b)
                    if if web {
                        self.broker.set_web_identity(b, &identity)
                    } else {
                        self.broker.set_plain_identity(b, &identity)
                    } =>
                {
                    self.remote.insert(
                        b,
                        Remote {
                            from: peer as u16,
                            tconn,
                            credit: RELAY_CREDIT as u32,
                            close_sent: false,
                        },
                    );
                    if let Some(t) = self.by_tconn.get_mut(peer) {
                        t.insert(tconn as u32, (tconn, b));
                    }
                }
                Some(b) => {
                    self.broker.closed(b, now_ms);
                    link.send(peer, CoreMsg::Close { tconn });
                }
                None => link.send(peer, CoreMsg::Close { tconn }),
            },
            CoreMsg::Input { tconn, data } => {
                if let Some(b) = self.relay_of(peer, tconn) {
                    self.broker.input(b, &data, now_ms);
                }
            }
            CoreMsg::Revoked { tconn } => {
                if let Some(b) = self.relay_of(peer, tconn) {
                    self.broker.disconnect_conn(b, CloseReason::Disallowed);
                }
            }
            CoreMsg::Closed { tconn } => {
                if let Some(b) = self.relay_of(peer, tconn) {
                    if let Some(t) = self.by_tconn.get_mut(peer) {
                        t.remove(&(tconn as u32));
                    }
                    self.remote.remove(&b);
                    finish(&mut self.broker, b, now_ms);
                }
            }
            CoreMsg::Credit { tconn, bytes } => {
                if let Some(b) = self.relay_of(peer, tconn) {
                    if let Some(r) = self.remote.get_mut(&b) {
                        r.credit = r.credit.saturating_add(bytes);
                    }
                    // More may be waiting for the credit.
                    self.ready.push(b);
                }
            }
            CoreMsg::Output { tconn, data } => {
                if let Some(c) = self.conn_of(tconn) {
                    if let Some(k) = self.conns.get_mut(&c) {
                        k.outq.get_or_insert_with(Default::default).push_back(data);
                    }
                    self.blocked.push(c);
                }
            }
            CoreMsg::Close { tconn } => {
                if let Some(c) = self.conn_of(tconn) {
                    if let Some(k) = self.conns.get_mut(&c) {
                        k.remote_close = true;
                    }
                    self.blocked.push(c);
                }
            }
            CoreMsg::Route {
                msg,
                qos,
                retain,
                origin,
            } => {
                let from =
                    (origin != crate::backpressure::NO_ORIGIN).then_some((peer as u16, origin));
                let n = self
                    .broker
                    .route_remote_from(&msg, qos, retain, from, now_ms);
                self.flow.delivered(peer, origin, n, link, now_ms);
            }
            // ---- shared subscriptions (ADR-275) ----
            CoreMsg::Shared(m) => self.broker.shared_input(peer as u16, m, now_ms),
            // ---- publisher back-pressure (ADR-269) ----
            CoreMsg::Seen { conn, n } => {
                self.broker
                    .note_remote_recipients(conn, peer as u16, n, now_ms)
            }
            CoreMsg::Hold { conn, full } => {
                if full {
                    self.broker.remote_full(conn, peer as u16, now_ms);
                } else {
                    self.broker.remote_drained(conn, peer as u16, now_ms);
                }
            }
            CoreMsg::Flow { tconn, closed } => {
                if let Some(c) = self.conn_of(tconn) {
                    self.flow.window(c, tconn, closed);
                }
            }
            CoreMsg::IpConfig { .. } | CoreMsg::Ip6Config(_) => {}
        }
    }

    /// The broker connection relaying `tconn` from transport core `peer`.
    fn relay_of(&self, peer: usize, tconn: Tconn) -> Option<ConnId> {
        let (t, b) = *self.by_tconn.get(peer)?.get(&(tconn as u32))?;
        (t == tconn).then_some(b)
    }

    fn conn_of(&self, tconn: Tconn) -> Option<u32> {
        let c = (tconn & 0xffff_ffff) as u32;
        self.conns
            .get(&c)
            .filter(|k| k.tconn == tconn && matches!(k.peer, Some(Peer::Remote { .. })))
            .map(|_| c)
    }

    /// End of a loop pass: broker output into TLS and TCP, relays, closes,
    /// fan-out, persistence and telemetry. Returns whether anything moved.
    /// Returns the memory a past peak (a reconnect storm) left in this
    /// core's tables, so the free-heap admission sees it again.
    fn shrink(&mut self, tcp: &mut TcpStack) {
        let before = crate::vm::HEAP.block_bytes();
        self.shrink_inner(tcp);
        let after = crate::vm::HEAP.block_bytes();
        if before - after >= 64 * 1024 {
            // Other cores allocate meanwhile: an estimate, for debugging.
            debug!(
                "mem: core {} returned about {} KiB after a peak",
                self.me,
                (before - after) >> 10
            );
        }
    }

    fn shrink_inner(&mut self, tcp: &mut TcpStack) {
        tcp.shrink();
        self.broker.shrink();
        self.flow.shrink();
        self.conns.0.shrink();
        self.by_broker.0.shrink();
        self.flights.0.shrink();
        self.remote.0.shrink();
        if let Some(w) = self.ws.as_mut() {
            w.shrink();
        }
        if let Some(m) = self.metrics.as_mut() {
            m.shrink();
        }
        for t in &mut self.by_tconn {
            t.0.shrink();
        }
        if self.handshakes.is_empty() {
            self.handshakes.shrink_to_fit();
        }
        if self.blocked.is_empty() {
            self.blocked.shrink_to_fit();
        }
    }

    pub fn poll(&mut self, tcp: &mut TcpStack, link: &mut Link, now_ms: u64) -> bool {
        let _wd = watchdog::enter(watchdog::Phase::Output, None);
        let mut activity = false;
        if let Some(c) = watchdog::take_drop().and_then(|c| u32::try_from(c).ok())
            && self.conns.contains_key(&c)
        {
            warn!("watchdog: aborting connection {c}");
            self.detach(c, link, now_ms);
            self.leave_flight(c, Leave::Failed, now_ms);
            self.drop_conn(c, now_ms);
            self.aborts.push(c);
        }
        watchdog::step(watchdog::Step::Timers);
        if now_ms.saturating_sub(self.last_tick_ms) >= 100 {
            self.last_tick_ms = now_ms;
            self.broker.tick(now_ms);
            self.cut_revoked(now_ms);
            self.expire_handshakes(link, now_ms);
            self.ws_expire(link, now_ms);
            self.metrics_expire(now_ms);
            self.publish_admission(now_ms);
            if let Some(p) = self.plain.as_mut() {
                // The plaintext listener judges its exposure from the address
                // the interface has now (one core says it).
                let first = self.me == dataplane::workers(self.n).start;
                p.tick(tcp.local_addr(), first);
                p.tick6(tcp.local6().global, first);
            }
        }
        watchdog::step(watchdog::Step::Shrink);
        if now_ms.saturating_sub(self.last_shrink_ms) >= SHRINK_MS {
            self.last_shrink_ms = now_ms;
            self.shrink(tcp);
        }
        watchdog::step(watchdog::Step::Sys);
        self.sys.poll(&mut self.broker, now_ms);
        watchdog::step(watchdog::Step::Ready);
        // Publishers whose pause ended: a slice of their held input (ADR-269).
        self.broker.poll_flow(now_ms);
        let mut ready = core::mem::take(&mut self.ready);
        self.broker.drain_ready(&mut ready);
        for b in ready.drain(..) {
            activity = true;
            if let Some(&c) = self.by_broker.get(&b) {
                self.local_output(c, b, now_ms);
            } else if self.remote.contains_key(&b) {
                self.remote_output(b, link, now_ms);
            }
        }
        // `local_output` and `remote_output` list a connection again when they
        // could not move all of its output (TLS buffer full, no relay credit)
        // by pushing it on `self.ready`; keep those for the next pass. Putting
        // the drained list back over them forgot the request, and a subscriber
        // whose output buffer was full then never got another pass: every QoS 0
        // message to it was dropped until something else (a PINGRESP) woke it
        // (ADR-223).
        let mut again = core::mem::take(&mut self.ready);
        self.ready = ready;
        self.ready.append(&mut again);
        self.flow_windows(tcp, link);
        // Hand pending bytes to TCP; finish closes.
        watchdog::step(watchdog::Step::Tcp);
        let mut blocked = core::mem::take(&mut self.blocked);
        blocked.sort_unstable();
        blocked.dedup();
        let mut still = Vec::new();
        for c in blocked {
            activity = true;
            if self.push_to_tcp(c, tcp, link) {
                still.push(c);
            }
        }
        self.blocked.append(&mut still);
        watchdog::step(watchdog::Step::Routes);
        for (msg, qos, retain, origin) in self.broker.drain_routes() {
            for peer in dataplane::workers(self.n).filter(|&p| p != self.me) {
                if qos == QoS::AtMostOnce && link.backlog_len(peer) > ROUTE_BACKLOG {
                    self.dropped_routes += 1;
                    // Relaxed: statistics.
                    dataplane::ROUTE_DROPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if self.dropped_routes.is_power_of_two() {
                        warn!(
                            "mqtt: {} QoS 0 fan-out message(s) dropped (core {peer} behind)",
                            self.dropped_routes
                        );
                    }
                    continue;
                }
                link.send(
                    peer,
                    CoreMsg::Route {
                        msg: msg.clone(),
                        qos,
                        retain,
                        origin: origin.unwrap_or(crate::backpressure::NO_ORIGIN),
                    },
                );
            }
        }
        // Shared subscriptions: joins, leaves and deliveries for other
        // shards (ADR-275). A QoS 0 delivery to a core that is behind is
        // dropped like a QoS 0 route (counted with them), so a flood cannot
        // grow the backlog without bound; everything else is sent.
        for (to, m) in self.broker.drain_shared() {
            let peer = usize::from(to);
            if matches!(
                m,
                urmqtt_broker::SharedMsg::Deliver {
                    qos: QoS::AtMostOnce,
                    ..
                }
            ) && link.backlog_len(peer) > ROUTE_BACKLOG
            {
                self.dropped_routes += 1;
                // Relaxed: statistics.
                dataplane::ROUTE_DROPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                continue;
            }
            link.send(peer, CoreMsg::Shared(m));
        }
        watchdog::step(watchdog::Step::Control);
        // Control messages go to the DB core unchanged; it authenticates
        // them. Without durable storage they are refused (H1).
        for m in self.broker.drain_control() {
            match self.db.as_mut() {
                Some(dbl) => dbl.send(DbReq::Control {
                    from: m.from,
                    payload: m.payload,
                }),
                None => crate::control::refuse_without_storage(&m.from),
            }
        }
        self.log_ticket_refusals();
        self.count_retained_refusals();
        let dropped = self.broker.dropped_control();
        if dropped > self.dropped_control_seen {
            crate::control::REJECTED
                .get(urmqtt_control::Reject::Unauthorized.index())
                .map(|c| {
                    c.fetch_add(
                        dropped - self.dropped_control_seen,
                        core::sync::atomic::Ordering::Relaxed,
                    )
                });
            if dropped.is_power_of_two() {
                warn!(
                    "control: {dropped} publish(es) to $urmqtt/ by identities without control rights dropped on core {}",
                    self.me
                );
            }
            self.dropped_control_seen = dropped;
        }
        if crate::control::epoch() != self.control_epoch {
            activity = true;
            self.apply_control(link, now_ms);
        }
        watchdog::step(watchdog::Step::Persist);
        if let Some(dbl) = self.db.as_mut() {
            for op in self.broker.drain_persist() {
                dbl.send(DbReq::Persist(op));
            }
            dbl.pump();
        }
        watchdog::step(watchdog::Step::Telemetry);
        match self.log.as_mut() {
            Some(log) => {
                for msg in self.broker.drain_telemetry() {
                    log.add(msg, now_ms);
                }
                log.pump(now_ms);
            }
            None => self.broker.drain_telemetry().for_each(drop),
        }
        activity
    }

    /// A control change was applied (H1): closes this core's live
    /// connections whose certificate serial is now revoked (transport
    /// side) and the sessions homed here whose identity left the allowlist.
    fn apply_control(&mut self, link: &mut Link, now_ms: u64) {
        self.control_epoch = crate::control::epoch();
        let tags = crate::control::revoked_tags();
        let revoked: Vec<(u32, Option<Peer>, Tconn)> = self
            .conns
            .0
            .iter()
            .filter(|(_, k)| {
                k.tls
                    && !k.closing
                    && k.serial_tag != 0
                    && tags.binary_search(&k.serial_tag).is_ok()
            })
            .map(|(c, k)| (c, k.peer, k.tconn))
            .collect();
        let mut closed = revoked.len() as u64;
        for (c, peer, tconn) in revoked {
            // A session is told why first (5.0: DISCONNECT 0x98), by the
            // broker that holds it; the transport cuts it anyway after
            // REVOKE_GRACE_MS (ADR-275). Before its CONNECT: cut now.
            match peer {
                Some(Peer::Local(b)) => {
                    self.broker.disconnect_conn(b, CloseReason::Disallowed);
                    self.revoking.push((c, tconn, now_ms + REVOKE_GRACE_MS));
                }
                Some(Peer::Remote { home }) => {
                    link.send(usize::from(home), CoreMsg::Revoked { tconn });
                    self.revoking.push((c, tconn, now_ms + REVOKE_GRACE_MS));
                }
                None => self.start_close(c),
            }
        }
        if crate::control::allowlist_mode() {
            // (Plaintext logins are identities too: P1.)
            closed += self.broker.disconnect_unless(
                |id, role| {
                    !matches!(
                        role,
                        urmqtt_broker::Role::Device
                            | urmqtt_broker::Role::Plain
                            | urmqtt_broker::Role::Web
                    ) || crate::control::admitted(id)
                },
                CloseReason::Disallowed,
            ) as u64;
        }
        closed += self.apply_accounts();
        if closed > 0 {
            crate::control::LIVE_CLOSED.fetch_add(closed, core::sync::atomic::Ordering::Relaxed);
            info!(
                "control: core {}: {closed} live connection(s) closed (revoked or no longer allowed)",
                self.me
            );
        }
    }

    /// The run-time password accounts changed (ADR-285): hands the new table
    /// to this core's plaintext and WebSocket listeners and closes the live
    /// logins of an account that was removed or whose password or class
    /// changed (the sessions homed here; a closed one gets a 5.0 DISCONNECT
    /// 0x98). Returns how many.
    fn apply_accounts(&mut self) -> u64 {
        let new = crate::control::accounts();
        if Arc::ptr_eq(&new, &self.accounts_seen) {
            return 0;
        }
        let old = core::mem::replace(&mut self.accounts_seen, new.clone());
        if let Some(p) = self.plain.as_mut() {
            p.set_accounts(new.clone());
        }
        if let Some(w) = self.ws.as_mut() {
            w.set_accounts(new.clone());
        }
        let changed: Vec<&str> = old
            .iter()
            .filter(|a| new.iter().find(|b| b.id == a.id) != Some(*a))
            .map(|a| a.id.as_str())
            .collect();
        if changed.is_empty() {
            return 0;
        }
        self.broker.disconnect_unless(
            |id, role| {
                !matches!(role, urmqtt_broker::Role::Plain | urmqtt_broker::Role::Web)
                    || !changed.contains(&id)
            },
            CloseReason::Disallowed,
        ) as u64
    }

    /// Revoked connections still open after their grace: cut at the
    /// transport, whatever the broker did.
    fn cut_revoked(&mut self, now_ms: u64) {
        if self.revoking.is_empty() {
            return;
        }
        let due: Vec<(u32, Tconn)> = self
            .revoking
            .iter()
            .filter(|r| now_ms >= r.2)
            .map(|r| (r.0, r.1))
            .collect();
        self.revoking.retain(|r| now_ms < r.2);
        for (c, tconn) in due {
            if self.conns.get(&c).is_some_and(|k| k.tconn == tconn) {
                self.start_close(c);
            }
        }
    }

    // ---- publisher back-pressure (ADR-269) ----------------------------------

    /// The broker's receive-window decisions: applied to this core's TCP for
    /// a local session, sent to the transport core for a relayed one.
    fn flow_windows(&mut self, tcp: &mut TcpStack, link: &mut Link) {
        let mut events = Vec::new();
        self.broker.drain_flow(&mut events);
        for (b, closed) in events {
            if let Some(&c) = self.by_broker.get(&b) {
                if let Some(k) = self.conns.get(&c) {
                    self.flow.window(c, k.tconn, closed);
                }
            } else if let Some(r) = self.remote.get(&b) {
                link.send(
                    usize::from(r.from),
                    CoreMsg::Flow {
                        tconn: r.tconn,
                        closed,
                    },
                );
            }
        }
        // Pauses and resumes asked of other shards' publishers.
        let mut asks = Vec::new();
        self.broker.drain_remote_flow(&mut asks);
        for (shard, conn, full) in asks {
            link.send(usize::from(shard), CoreMsg::Hold { conn, full });
        }
        let conns = &self.conns;
        self.flow.apply(tcp, |c, tconn| {
            conns.get(&c).is_some_and(|k| k.tconn == tconn)
        });
    }

    // ---- end of publisher back-pressure ------------------------------------

    /// Broker output of a local session → TLS → `pending`.
    fn local_output(&mut self, c: u32, b: ConnId, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        if k.pending.len() < TX_BUF {
            let out = self.broker.output(b);
            if !out.is_empty() {
                let n = out.len();
                match k.session.as_mut() {
                    Some(sess) => {
                        // WebSocket: in a binary frame (ADR-272).
                        let r = match self.ws.as_mut().filter(|w| w.framed(c)) {
                            Some(w) => w.send(
                                c,
                                sess,
                                urmqtt_ws::frame::op::BINARY,
                                out,
                                k.pending.vec_mut(),
                            ),
                            None => sess.send(out, k.pending.vec_mut()),
                        };
                        if r.is_err() {
                            k.closing = true;
                        }
                    }
                    None => k.pending.extend_from_slice(out),
                }
                self.broker.consumed(b, n);
            }
        }
        if !self.broker.output(b).is_empty() {
            // More than fits now: try again next pass.
            self.ready.push(b);
        }
        let done = self.broker.close_requested(b).is_some() && self.broker.output(b).is_empty();
        self.blocked.push(c);
        if done {
            // The broker closed it (keep alive, a protocol error, a 5.0
            // DISCONNECT) and its last bytes are handed over: the session ends
            // now, so its Will goes out now (MQTT 3.1.2.5, 5.0 3.1.2.5), not
            // when TCP is done, which a client that never closes its socket
            // drags out to the FIN_WAIT2 timeout (ADR-274).
            if let Some(k) = self.conns.get_mut(&c)
                && matches!(k.peer, Some(Peer::Local(x)) if x == b)
            {
                k.peer = None;
                self.by_broker.remove(&b);
                finish(&mut self.broker, b, now_ms);
            }
            self.start_close(c);
        }
    }

    /// Home side: replies (within credit) and close requests for a relayed
    /// connection.
    fn remote_output(&mut self, b: ConnId, link: &mut Link, now_ms: u64) {
        let Some(r) = self.remote.get_mut(&b) else {
            return;
        };
        let out = self.broker.output(b);
        if !out.is_empty() && r.credit > 0 {
            let n = out.len().min(r.credit as usize).min(RELAY_CHUNK);
            let data = out.get(..n).unwrap_or(&[]).to_vec();
            self.broker.consumed(b, n);
            r.credit -= n as u32;
            link.send(
                usize::from(r.from),
                CoreMsg::Output {
                    tconn: r.tconn,
                    data,
                },
            );
        }
        if !self.broker.output(b).is_empty() && r.credit > 0 {
            self.ready.push(b);
        }
        if !r.close_sent
            && self.broker.close_requested(b).is_some()
            && self.broker.output(b).is_empty()
        {
            r.close_sent = true;
            let (from, tconn) = (usize::from(r.from), r.tconn);
            link.send(from, CoreMsg::Close { tconn });
            // As for a local connection: the session ends now (its Will goes
            // out), the transport core closes TCP; its later Closed finds no
            // relay any more.
            self.remote.remove(&b);
            if let Some(t) = self.by_tconn.get_mut(from) {
                t.remove(&(tconn as u32));
            }
            finish(&mut self.broker, b, now_ms);
        }
    }

    /// Moves relayed replies and pending bytes into TCP and finishes a
    /// close. Returns whether bytes are still waiting.
    fn push_to_tcp(&mut self, c: u32, tcp: &mut TcpStack, link: &mut Link) -> bool {
        let Some(k) = self.conns.get_mut(&c) else {
            return false;
        };
        if let Some(Peer::Remote { home }) = k.peer {
            while k.pending.len() < TX_BUF {
                let Some(data) = k.outq.as_mut().and_then(|q| q.pop_front()) else {
                    k.outq = None;
                    break;
                };
                match k.session.as_mut() {
                    Some(sess) => {
                        let r = match self.ws.as_mut().filter(|w| w.framed(c)) {
                            Some(w) => w.send(
                                c,
                                sess,
                                urmqtt_ws::frame::op::BINARY,
                                &data,
                                k.pending.vec_mut(),
                            ),
                            None => sess.send(&data, k.pending.vec_mut()),
                        };
                        if r.is_err() {
                            k.closing = true;
                        }
                    }
                    None => k.pending.extend_from_slice(&data),
                }
                link.send(
                    usize::from(home),
                    CoreMsg::Credit {
                        tconn: k.tconn,
                        bytes: data.len() as u32,
                    },
                );
            }
            if k.remote_close && k.outq.is_none() && !k.closing {
                k.closing = true;
                if let Some(sess) = k.session.as_mut() {
                    if let Some(w) = self.ws.as_mut() {
                        w.send_close(c, sess, k.pending.vec_mut());
                    }
                    sess.close(k.pending.vec_mut());
                }
            }
        }
        if !k.pending.is_empty() {
            let n = tcp.send(c, k.pending.as_slice());
            // Idle connections keep no buffer (M15).
            k.pending.consume(n);
        }
        k.pending.release();
        if k.closing && k.pending.is_empty() && !k.fin_sent {
            k.fin_sent = true;
            tcp.close(c);
        }
        !k.pending.is_empty() || k.outq.is_some()
    }

    /// Closes connections that never finished their handshake (or, on the
    /// dev port, never sent CONNECT).
    fn expire_handshakes(&mut self, link: &mut Link, now_ms: u64) {
        while let Some(&Pending {
            at_ms: at,
            c,
            tconn,
            ..
        }) = self.handshakes.front()
        {
            let attached = self
                .conns
                .get(&c)
                .is_none_or(|k| k.tconn != tconn || k.peer.is_some() || k.closing);
            if attached {
                self.handshakes.pop_front();
                continue;
            }
            let pressure =
                u64::from(self.adm.in_flight()) * 4 >= u64::from(self.adm.limits().per_core) * 3;
            let limit = if pressure {
                HANDSHAKE_TIMEOUT_PRESSURE_MS
            } else {
                HANDSHAKE_TIMEOUT_MS
            };
            if now_ms.saturating_sub(at) <= limit {
                break;
            }
            self.handshakes.pop_front();
            // Logged at powers of two: a storm of dead peers must not turn
            // into a storm of log lines (each one is a serial-port write).
            let n = self.adm.stats().timed_out + 1;
            if n.is_power_of_two() {
                if self.conns.get(&c).is_some_and(|k| k.tls) {
                    warn!(
                        "tls: handshake timed out on core {} ({n} so far, limit {} ms)",
                        self.me, limit
                    );
                } else {
                    warn!(
                        "mqtt: no CONNECT within {} s on core {} ({n} so far)",
                        limit / 1000,
                        self.me
                    );
                }
            }
            self.detach(c, link, now_ms);
            self.leave_flight(c, Leave::TimedOut, now_ms);
            self.drop_conn(c, now_ms);
            self.aborts.push(c);
        }
    }
}

/// Adapts the service to [`urmqtt_tcp::App`] for one `input`/`poll` call.
pub struct TcpEvents<'a> {
    pub mqtt: &'a mut MqttService,
    pub link: &'a mut Link,
    pub now_ms: u64,
}

impl urmqtt_tcp::App for TcpEvents<'_> {
    fn syn_ok(&mut self, port: u16, remote: Addr) -> bool {
        self.mqtt.syn_ok(port, remote, self.now_ms)
    }

    fn accept(&mut self, c: urmqtt_tcp::ConnId, port: u16, remote: Endpoint) -> bool {
        self.mqtt.on_accept(c, port, remote.addr, self.now_ms)
    }

    fn data(&mut self, c: urmqtt_tcp::ConnId, data: &[u8]) {
        // A handshake step has a budget of its own (ADR-071).
        let phase = if self.mqtt.is_handshaking(c) {
            watchdog::Phase::Handshake
        } else {
            watchdog::Phase::Input
        };
        let _wd = watchdog::enter(phase, Some(u64::from(c)));
        self.mqtt.on_data(c, data, self.link, self.now_ms);
    }

    fn peer_closed(&mut self, c: urmqtt_tcp::ConnId) {
        self.mqtt.on_peer_closed(c, self.link, self.now_ms);
    }

    fn closed(&mut self, c: urmqtt_tcp::ConnId, _why: urmqtt_tcp::CloseReason) {
        self.mqtt.on_closed(c, self.link, self.now_ms);
    }
}

fn finish(broker: &mut Broker, c: ConnId, now_ms: u64) {
    let who: Option<String> = broker.client_id(c).map(String::from);
    let reason = broker.close_requested(c);
    broker.closed(c, now_ms);
    let st = broker.stats();
    // Per-connection events are debug: at production rates the console
    // would become the bottleneck (ADR-032).
    debug!(
        "mqtt: {} disconnected ({}), {} session(s), {} retained",
        who.as_deref().unwrap_or("<no session>"),
        match reason {
            Some(CloseReason::ClientDisconnect) => "clean",
            Some(CloseReason::KeepAliveTimeout) => "keepalive timeout",
            Some(CloseReason::TakenOver) => "taken over",
            Some(CloseReason::ProtocolError) => "protocol error",
            Some(CloseReason::Rejected) => "rejected",
            Some(CloseReason::Unsupported) => "unsupported",
            Some(CloseReason::Disallowed) => "no longer on the allowlist",
            Some(CloseReason::Refused(_)) => "refused (MQTT 5.0 DISCONNECT)",
            None => "network closed, will published if set",
        },
        st.sessions,
        st.retained
    );
}
