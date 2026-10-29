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
use alloc::vec::Vec;

use urmqtt_arch_aarch64::spsc::{Consumer, Producer};
use urmqtt_broker::{Acl, Broker, Buf, CloseReason, Config, ConnId};
use urmqtt_config::CONFIG;
use urmqtt_log::{debug, info, warn};
use urmqtt_mqtt::{Limits, QoS};
use urmqtt_tcp::{Endpoint, TcpStack};
use urmqtt_tls::{Event, IdentityField, ServerSetup, TlsServer, TlsSession};

use crate::dataplane::{self, CoreMsg, Link, Tconn};
use crate::db::{self, DbReq, DbResp, LogBatch, Restored};
use crate::watchdog;

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
    ip: [u8; 4],
}

impl Pending {
    /// Still waiting: the same connection, not attached, not closing.
    fn pending(&self, conns: &Slab<Conn>) -> bool {
        conns
            .get(&self.c)
            .is_some_and(|k| k.tconn == self.tconn && k.peer.is_none() && !k.closing)
    }
}

/// Why a new connection was refused.
#[derive(Debug, Clone, Copy)]
pub enum Refusal {
    Rate = 0,
    InFlight = 1,
    Memory = 2,
    Storage = 3,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Rate => "handshake rate limit",
            Self::InFlight => "too many handshakes in flight",
            Self::Memory => "heap below the free reserve",
            Self::Storage => "the DB core is behind",
        }
    }
}

/// Per-core handshake admission (token bucket, PROMPT §6).
struct Admission {
    tokens: u32,
    last_ms: u64,
}

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
    admission: Admission,
    /// New connections refused, by [`Refusal`].
    refused: [u64; 4],
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

pub fn broker_config(max_connections: usize, fanout: bool) -> Config {
    let l = CONFIG.limits;
    Config {
        limits: Limits {
            max_packet_size: l.max_packet_size,
            max_topic_len: l.max_topic_len as u16,
            max_topic_levels: l.max_topic_levels as u16,
            // Identities become topic levels, so the topic bound applies.
            max_client_id_len: l.max_topic_len as u16,
            max_topics_per_packet: l.max_subscriptions_per_session as u16,
        },
        max_connections: max_connections.min(l.max_connections_per_core as usize),
        max_subscriptions_per_session: l.max_subscriptions_per_session as usize,
        max_inflight: l.max_inflight_qos1 as usize,
        max_queued: l.max_queued_per_offline_session as usize,
        rate_tokens: l.publish_rate_per_device.tokens,
        rate_period_ms: l.publish_rate_per_device.per_ms,
        max_outbound_bytes: TX_BUF,
        acl: Acl {
            device_publish: CONFIG.acl.device_publish,
            device_subscribe: CONFIG.acl.device_subscribe,
            service_ids: CONFIG.acl.service_ids,
            service_publish: CONFIG.acl.service_publish,
            service_subscribe: CONFIG.acl.service_subscribe,
        },
        persist: db::active(),
        telemetry: CONFIG.storage.telemetry_topics,
        fanout,
    }
}

/// The TLS server as configured (build-time revocation list), for
/// `test=dp-bench`.
pub fn tls_server_for_bench() -> Option<TlsServer> {
    tls_server(CONFIG.tls.revoked_serials)
}

fn tls_server(revoked: &[&str]) -> Option<TlsServer> {
    let setup = ServerSetup {
        ca_pem: urmqtt_config::CA_PEM,
        cert_pem: urmqtt_config::SERVER_CERT_PEM,
        key_pem: urmqtt_config::SERVER_KEY_PEM,
        identity_field: match CONFIG.tls.identity_field {
            urmqtt_config::IdentityField::Cn => IdentityField::Cn,
            urmqtt_config::IdentityField::SanUri => IdentityField::SanUri,
        },
        resumption: CONFIG.tls.resumption,
        revoked_hex: revoked,
        version: crate::VERSION,
    };
    match TlsServer::new(&setup) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("tls: server setup failed: {e:?}");
            None
        }
    }
}

fn qos_of(q: u8) -> QoS {
    if q == 1 {
        QoS::AtLeastOnce
    } else {
        QoS::AtMostOnce
    }
}

impl MqttService {
    /// The MQTT service of data core `me` (of `n`): the broker shard for
    /// the sessions whose home is `me`, and the connections TCP accepts on
    /// this core's stack.
    pub fn new(restored: Option<&Restored>, me: usize, n: usize) -> Self {
        // The revocation list comes from the store (seeded from the
        // build-time list) or, without storage, from the build directly.
        let revoked: Vec<&str> = match restored {
            Some(r) => r.revoked.iter().map(String::as_str).collect(),
            None => CONFIG.tls.revoked_serials.to_vec(),
        };
        let tls = tls_server(&revoked);
        if me == dataplane::workers(n).start {
            if tls.is_some() {
                info!(
                    "mqtt: TLS 1.3 listener on port {} (mutual TLS, identity = certificate {:?}, {} revoked serial(s))",
                    CONFIG.network.mqtt_tls_port,
                    CONFIG.tls.identity_field,
                    revoked.len()
                );
            }
            if let Some(port) = CONFIG.network.mqtt_plain_port {
                warn!(
                    "mqtt: PLAINTEXT listener on port {port} (dev build only, identity = client id)"
                );
            }
        }
        let mut broker = Broker::new(broker_config(MAX_CONNS * n, n > 1));
        let mut homed = 0;
        if let Some(r) = restored {
            // Every shard keeps a replica of the retained messages; each
            // persistent session goes to its home shard.
            for m in &r.retained {
                broker.restore_retained(&m.topic, &m.payload, qos_of(m.qos));
            }
            for sess in r
                .sessions
                .iter()
                .filter(|s| dataplane::home_of(&s.client_id, n) == me)
            {
                homed += 1;
                broker.restore_session(
                    &sess.client_id,
                    sess.subscriptions
                        .iter()
                        .map(|(f, q)| (f.as_str(), qos_of(*q))),
                    sess.queued
                        .iter()
                        .map(|q| (q.topic.as_str(), q.payload.as_slice())),
                );
            }
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
                "mqtt: shard {me}/{n} ready: {homed} persistent session(s) homed here, telemetry partition {}",
                if log.is_some() {
                    urmqtt_store::telemetry::TelemetryLog::partition_of(me) as isize
                } else {
                    -1
                }
            );
        }
        Self {
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
            admission: Admission {
                tokens: CONFIG.limits.handshakes_per_core_per_sec,
                last_ms: 0,
            },
            refused: [0; 4],
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
        p
    }

    /// A handshake token (`limits.handshakes_per_core_per_sec`).
    fn take_token(&mut self, now_ms: u64) -> bool {
        let rate = CONFIG.limits.handshakes_per_core_per_sec;
        let elapsed = now_ms.saturating_sub(self.admission.last_ms);
        let refill = (elapsed * u64::from(rate) / 1000) as u32;
        if refill > 0 {
            self.admission.tokens = self.admission.tokens.saturating_add(refill).min(rate);
            self.admission.last_ms = now_ms;
        }
        if self.admission.tokens == 0 {
            return false;
        }
        self.admission.tokens -= 1;
        true
    }

    /// Connections accepted and not yet attached to a session. The queue
    /// keeps attached entries until they reach its front, so it is pruned
    /// first when it looks full.
    fn in_flight(&mut self) -> usize {
        let cap = CONFIG.limits.max_handshakes_in_flight_per_core as usize;
        if self.handshakes.len() >= cap {
            let conns = &self.conns;
            self.handshakes.retain(|p| p.pending(conns));
        }
        self.handshakes.len()
    }

    /// Of the connections in flight, those from `ip` (the queue holds at
    /// most the per-core limit, so the scan is short).
    fn in_flight_from(&self, ip: [u8; 4]) -> usize {
        self.handshakes
            .iter()
            .filter(|p| p.ip == ip && p.pending(&self.conns))
            .count()
    }

    /// Admission for a new connection (PROMPT §6, M16): free heap above the
    /// reserve, fewer than the in-flight limit, and for TLS a handshake
    /// token. Refusals cost no crypto work and are logged rate-limited.
    fn admit(&mut self, tls: bool, ip: [u8; 4], now_ms: u64) -> bool {
        let cap = CONFIG.limits.max_handshakes_in_flight_per_core as usize;
        let per_ip = CONFIG.limits.max_handshakes_in_flight_per_ip as usize;
        let db_behind = self
            .db
            .as_ref()
            .is_some_and(|d| d.backlog.len() >= DB_BACKLOG_REFUSE);
        let refusal = if !dataplane::heap_has_room() {
            Some(Refusal::Memory)
        } else if db_behind {
            Some(Refusal::Storage)
        } else if self.in_flight() >= cap || self.in_flight_from(ip) >= per_ip {
            Some(Refusal::InFlight)
        } else if tls && !self.take_token(now_ms) {
            Some(Refusal::Rate)
        } else {
            None
        };
        let Some(r) = refusal else { return true };
        let n = self.refused.get_mut(r as usize).map_or(0, |n| {
            *n += 1;
            *n
        });
        // Rate-limited log: 1st, 2nd, 4th, 8th, ... refusal of each kind.
        if n.is_power_of_two() {
            warn!("admission: {n} connection(s) refused: {}", r.reason());
        }
        dataplane::count_refusal(r as usize);
        false
    }

    // ---- TCP events (called from the stack, see `TcpEvents`) -------------

    fn on_accept(&mut self, c: u32, port: u16, ip: [u8; 4], now_ms: u64) -> bool {
        let tls = Some(port) != self.plain_port;
        if !self.admit(tls, ip, now_ms) {
            return false;
        }
        let session = if tls {
            match self.tls.as_ref().and_then(|t| t.accept().ok()) {
                Some(s) => Some(s),
                None => return false,
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
            },
        );
        self.handshakes.push_back(Pending {
            at_ms: now_ms,
            c,
            tconn,
            ip,
        });
        dataplane::count_accept(self.me);
        true
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
        let t0 = urmqtt_arch_aarch64::timer::uptime_ns();
        let r = sess.input(data, k.pending.vec_mut(), &mut self.app);
        dataplane::tls_time(self.me, urmqtt_arch_aarch64::timer::uptime_ns() - t0);
        match r {
            Ok(Event::Established {
                identity,
                suite,
                resumed,
            }) => {
                let home = dataplane::home_of(&identity, self.n);
                if let Some(dbl) = self.db.as_mut() {
                    dbl.seen(&identity);
                }
                debug!(
                    "tls: {identity} authenticated ({suite}{}) on core {}, session on core {home}",
                    if resumed { ", resumed" } else { "" },
                    self.me
                );
                if !self.attach(c, home, Some(&identity), link, now_ms) {
                    self.start_close(c);
                }
            }
            Ok(Event::PeerClosed) => self.start_close(c),
            Ok(Event::None) => {}
            Err(e) => {
                warn!("tls: connection refused: {e:?}");
                self.start_close(c);
            }
        }
        if !self.app.is_empty() {
            let app = core::mem::take(&mut self.app);
            self.deliver(c, &app, link, now_ms);
            self.app = app;
        }
        self.mark_blocked(c);
    }

    /// The peer sent FIN: the session ends now (MQTT has no half-close).
    fn on_peer_closed(&mut self, c: u32, link: &mut Link, now_ms: u64) {
        self.detach(c, link, now_ms);
        self.start_close(c);
        self.mark_blocked(c);
    }

    /// TCP is done with the connection (normal close, reset or timeout).
    fn on_closed(&mut self, c: u32, link: &mut Link, now_ms: u64) {
        self.detach(c, link, now_ms);
        self.conns.remove(&c);
    }

    // ---- sessions -----------------------------------------------------------

    /// Attaches a connection to its session's home shard (here or relayed).
    fn attach(
        &mut self,
        c: u32,
        home: usize,
        identity: Option<&str>,
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
                self.broker.set_identity(b, id);
            }
            k.peer = Some(Peer::Local(b));
            self.by_broker.insert(b, c);
        } else {
            link.send(
                home,
                CoreMsg::Open {
                    tconn: k.tconn,
                    identity: identity.map(Into::into),
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
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let limit = CONFIG.limits.max_packet_size as usize + 5;
        let home = match urmqtt_mqtt::decode(k.early.as_slice(), &urmqtt_mqtt::Limits::PROTOCOL_MAX)
        {
            Ok((urmqtt_mqtt::Packet::Connect(p), _)) => {
                Some(dataplane::home_of(p.client_id, self.n))
            }
            Err(urmqtt_mqtt::Error::Incomplete(_)) if k.early.len() <= limit => None,
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
        if self.attach(c, home, None, link, now_ms) {
            self.deliver(c, &early, link, now_ms);
        } else {
            self.start_close(c);
        }
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
                sess.close(k.pending.vec_mut());
            }
            self.blocked.push(c);
        }
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
            CoreMsg::Open { tconn, identity } => match self.broker.open(now_ms) {
                Some(b) => {
                    if let Some(id) = &identity {
                        self.broker.set_identity(b, id);
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
            CoreMsg::Input { tconn, data } => {
                if let Some(b) = self.relay_of(peer, tconn) {
                    self.broker.input(b, &data, now_ms);
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
            CoreMsg::Route { msg, qos, retain } => self.broker.route_remote(&msg, qos, retain),
            CoreMsg::IpConfig { .. } => {}
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
        self.conns.0.shrink();
        self.by_broker.0.shrink();
        self.remote.0.shrink();
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
            self.conns.remove(&c);
            self.aborts.push(c);
        }
        if now_ms.saturating_sub(self.last_tick_ms) >= 100 {
            self.last_tick_ms = now_ms;
            self.broker.tick(now_ms);
            self.expire_handshakes(link, now_ms);
        }
        if now_ms.saturating_sub(self.last_shrink_ms) >= SHRINK_MS {
            self.last_shrink_ms = now_ms;
            self.shrink(tcp);
        }
        let mut ready = core::mem::take(&mut self.ready);
        self.broker.drain_ready(&mut ready);
        for b in ready.drain(..) {
            activity = true;
            if let Some(&c) = self.by_broker.get(&b) {
                self.local_output(c, b);
            } else if self.remote.contains_key(&b) {
                self.remote_output(b, link);
            }
        }
        self.ready = ready;
        // Hand pending bytes to TCP; finish closes.
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
        for (msg, qos, retain) in self.broker.drain_routes() {
            for peer in dataplane::workers(self.n).filter(|&p| p != self.me) {
                if qos == QoS::AtMostOnce && link.backlog_len(peer) > ROUTE_BACKLOG {
                    self.dropped_routes += 1;
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
                    },
                );
            }
        }
        if let Some(dbl) = self.db.as_mut() {
            for op in self.broker.drain_persist() {
                dbl.send(DbReq::Persist(op));
            }
            dbl.pump();
        }
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

    /// Broker output of a local session → TLS → `pending`.
    fn local_output(&mut self, c: u32, b: ConnId) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        if k.pending.len() < TX_BUF {
            let out = self.broker.output(b);
            if !out.is_empty() {
                let n = out.len();
                match k.session.as_mut() {
                    Some(sess) => {
                        if sess.send(out, k.pending.vec_mut()).is_err() {
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
            self.start_close(c);
        }
    }

    /// Home side: replies (within credit) and close requests for a relayed
    /// connection.
    fn remote_output(&mut self, b: ConnId, link: &mut Link) {
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
            link.send(usize::from(r.from), CoreMsg::Close { tconn: r.tconn });
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
                        if sess.send(&data, k.pending.vec_mut()).is_err() {
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
            if now_ms.saturating_sub(at) <= HANDSHAKE_TIMEOUT_MS {
                break;
            }
            self.handshakes.pop_front();
            if self.conns.get(&c).is_some_and(|k| k.tls) {
                warn!("tls: handshake timed out");
            } else {
                warn!("mqtt: no CONNECT within {} s", HANDSHAKE_TIMEOUT_MS / 1000);
            }
            self.detach(c, link, now_ms);
            self.conns.remove(&c);
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
    fn accept(&mut self, c: urmqtt_tcp::ConnId, port: u16, remote: Endpoint) -> bool {
        self.mqtt.on_accept(c, port, remote.addr, self.now_ms)
    }

    fn data(&mut self, c: urmqtt_tcp::ConnId, data: &[u8]) {
        let _wd = watchdog::enter(watchdog::Phase::Input, Some(u64::from(c)));
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
            None => "network closed, will published if set",
        },
        st.sessions,
        st.retained
    );
}
