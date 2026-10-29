//! MQTT service on smoltcp: the TLS listener (`network.mqtt_tls_port`, mTLS,
//! identity from the client certificate) and, in dev builds only, the
//! plaintext listener. Both feed one sans-IO broker.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use urmqtt_arch_aarch64::spsc::{Consumer, Producer};
use urmqtt_broker::{Acl, Broker, CloseReason, Config, ConnId};
use urmqtt_config::CONFIG;
use urmqtt_log::{debug, info, warn};
use urmqtt_mqtt::Limits;
use urmqtt_mqtt::QoS;
use urmqtt_tls::{Event, IdentityField, ServerSetup, TlsServer, TlsSession};

use crate::dataplane::{self, CoreMsg, Link, Tconn};
use crate::db::{self, DbReq, DbResp, LogBatch, Restored};

/// Reply bytes in flight from a home core to one relayed connection.
const RELAY_CREDIT: usize = TX_BUF;
const RELAY_CHUNK: usize = 16 * 1024;
/// Stop reading a relayed socket while this many messages wait for the
/// home core (TCP flow control then pushes back on the client).
const RELAY_BACKLOG: usize = 64;
/// QoS 0 fan-out to a core is dropped beyond this backlog (QoS 1 is kept).
const ROUTE_BACKLOG: usize = 16_384;

/// Telemetry records held back while the log ring is full; beyond this
/// they are dropped and counted (the data plane never blocks).
const LOG_BACKLOG_MAX: usize = 65_536;
/// Hand a telemetry batch to the DB core at this size or age.
const LOG_BATCH: usize = 256;
const LOG_BATCH_MS: u64 = 1;

const TLS_SOCKETS: usize = 32;
/// Plaintext connections (dev only).
const PLAIN_SOCKETS: usize = 16;
const RX_BUF: usize = 8 * 1024;
const TX_BUF: usize = 32 * 1024;
/// A handshake must finish within this time (PROMPT §6).
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Where a transport slot's MQTT session lives.
#[derive(Clone, Copy)]
enum Peer {
    /// In this core's broker shard.
    Local(ConnId),
    /// In another core's shard, relayed over the mesh.
    Remote { home: usize },
}

struct Slot {
    handle: SocketHandle,
    port: u16,
    tls: bool,
    session: Option<Box<TlsSession>>,
    peer: Option<Peer>,
    tconn: Tconn,
    /// Ciphertext (or plaintext on the dev port) not yet taken by the socket.
    pending: Vec<u8>,
    /// Dev plaintext port: bytes held until the CONNECT names the client.
    early: Vec<u8>,
    /// Relayed replies waiting for room in `pending`.
    outq: VecDeque<Vec<u8>>,
    /// The home core asked to close after its replies.
    remote_close: bool,
    accepted_ms: u64,
    closing: bool,
}

/// Per-core handshake admission (token bucket, PROMPT §6).
struct Admission {
    tokens: u32,
    last_ms: u64,
}

pub struct MqttService {
    /// This data core and the number of data cores.
    me: usize,
    n: usize,
    /// This core's broker shard: the sessions whose home is this core.
    broker: Broker,
    tls: Option<TlsServer>,
    slots: Vec<Slot>,
    buf: Vec<u8>,
    app: Vec<u8>,
    admission: Admission,
    refused: u64,
    db: Option<DbLink>,
    log: Option<LogLink>,
    /// Home side: connections relayed from transport cores.
    remote: BTreeMap<ConnId, Remote>,
    by_tconn: BTreeMap<(usize, Tconn), ConnId>,
    /// Slot generations, so late relay messages never hit a reused slot.
    slot_gen: u16,
    dropped_routes: u64,
}

/// A connection relayed from another core's transport (home side).
struct Remote {
    from: usize,
    tconn: Tconn,
    /// Reply bytes the transport core will still accept.
    credit: usize,
    close_sent: bool,
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
    /// Requests waiting for room in the ring (never dropped).
    backlog: VecDeque<DbReq>,
    committed_ops: u64,
    failed_ops: u64,
    max_commit_us: u32,
    log_durable: u64,
    /// Something was queued since the DB core was last woken.
    sent: bool,
}

impl DbLink {
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

fn new_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; RX_BUF]),
        tcp::SocketBuffer::new(vec![0; TX_BUF]),
    )
}

fn add_slots(sockets: &mut SocketSet<'_>, slots: &mut Vec<Slot>, n: usize, port: u16, tls: bool) {
    for _ in 0..n {
        slots.push(Slot {
            handle: sockets.add(new_socket()),
            port,
            tls,
            session: None,
            peer: None,
            tconn: 0,
            pending: Vec::new(),
            early: Vec::new(),
            outq: VecDeque::new(),
            remote_close: false,
            accepted_ms: 0,
            closing: false,
        });
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
    /// The MQTT service of data core `me` (of `n`): listeners on this
    /// core's network stack, and the broker shard for the sessions whose
    /// home is `me`.
    pub fn new(
        sockets: &mut SocketSet<'_>,
        restored: Option<&Restored>,
        me: usize,
        n: usize,
    ) -> Self {
        let mut slots = Vec::new();
        // The revocation list comes from the store (seeded from the
        // build-time list) or, without storage, from the build directly.
        let revoked: Vec<&str> = match restored {
            Some(r) => r.revoked.iter().map(String::as_str).collect(),
            None => CONFIG.tls.revoked_serials.to_vec(),
        };
        let tls = tls_server(&revoked);
        if tls.is_some() {
            add_slots(
                sockets,
                &mut slots,
                TLS_SOCKETS,
                CONFIG.network.mqtt_tls_port,
                true,
            );
            if me == 0 {
                info!(
                    "mqtt: TLS 1.3 listener on port {} (mutual TLS, identity = certificate {:?}, {} revoked serial(s))",
                    CONFIG.network.mqtt_tls_port,
                    CONFIG.tls.identity_field,
                    revoked.len()
                );
            }
        }
        if let Some(port) = CONFIG.network.mqtt_plain_port {
            add_slots(sockets, &mut slots, PLAIN_SOCKETS, port, false);
            if me == 0 {
                warn!(
                    "mqtt: PLAINTEXT listener on port {port} (dev build only, identity = client id)"
                );
            }
        }
        let mut broker = Broker::new(broker_config((TLS_SOCKETS + PLAIN_SOCKETS) * n, n > 1));
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
        info!(
            "mqtt: shard {me}/{n} ready: {} socket(s), {homed} persistent session(s) homed here, telemetry partition {}",
            slots.len(),
            if log.is_some() {
                urmqtt_store::telemetry::TelemetryLog::partition_of(me) as isize
            } else {
                -1
            }
        );
        Self {
            me,
            n,
            broker,
            tls,
            slots,
            buf: vec![0; RX_BUF],
            app: Vec::new(),
            admission: Admission {
                tokens: CONFIG.limits.handshakes_per_core_per_sec,
                last_ms: 0,
            },
            refused: 0,
            db,
            log,
            remote: BTreeMap::new(),
            by_tconn: BTreeMap::new(),
            slot_gen: 0,
            dropped_routes: 0,
        }
    }

    /// One pass over every socket and relayed connection. Returns true if
    /// any bytes moved.
    pub fn poll(&mut self, sockets: &mut SocketSet<'_>, link: &mut Link, now_ms: u64) -> bool {
        let mut activity = false;
        self.broker.tick(now_ms);
        for i in 0..self.slots.len() {
            activity |= self.poll_slot(i, sockets, link, now_ms);
        }
        activity |= self.pump_remote(link);
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
        link.flush();
        activity
    }

    /// Home side: sends replies (within credit) and close requests to the
    /// transport cores of relayed connections.
    fn pump_remote(&mut self, link: &mut Link) -> bool {
        let mut activity = false;
        for (&c, r) in self.remote.iter_mut() {
            let out = self.broker.output(c);
            if !out.is_empty() && r.credit > 0 {
                let n = out.len().min(r.credit).min(RELAY_CHUNK);
                let data = out.get(..n).unwrap_or(&[]).to_vec();
                self.broker.consumed(c, n);
                r.credit -= n;
                link.send(
                    r.from,
                    CoreMsg::Output {
                        tconn: r.tconn,
                        data,
                    },
                );
                activity = true;
            }
            if !r.close_sent
                && self.broker.close_requested(c).is_some()
                && self.broker.output(c).is_empty()
            {
                r.close_sent = true;
                link.send(r.from, CoreMsg::Close { tconn: r.tconn });
            }
        }
        activity
    }

    /// Handles a message from data core `peer` (everything but IpConfig).
    pub fn on_msg(&mut self, peer: usize, msg: CoreMsg, link: &mut Link, now_ms: u64) {
        match msg {
            CoreMsg::Open { tconn, identity } => match self.broker.open(now_ms) {
                Some(c) => {
                    if let Some(id) = &identity {
                        self.broker.set_identity(c, id);
                    }
                    self.remote.insert(
                        c,
                        Remote {
                            from: peer,
                            tconn,
                            credit: RELAY_CREDIT,
                            close_sent: false,
                        },
                    );
                    self.by_tconn.insert((peer, tconn), c);
                }
                None => link.send(peer, CoreMsg::Close { tconn }),
            },
            CoreMsg::Input { tconn, data } => {
                if let Some(&c) = self.by_tconn.get(&(peer, tconn)) {
                    self.broker.input(c, &data, now_ms);
                }
            }
            CoreMsg::Closed { tconn } => {
                if let Some(c) = self.by_tconn.remove(&(peer, tconn)) {
                    self.remote.remove(&c);
                    finish(&mut self.broker, c, now_ms);
                }
            }
            CoreMsg::Credit { tconn, bytes } => {
                if let Some(r) = self
                    .by_tconn
                    .get(&(peer, tconn))
                    .and_then(|c| self.remote.get_mut(c))
                {
                    r.credit += bytes as usize;
                }
            }
            CoreMsg::Output { tconn, data } => {
                if let Some(slot) = self.slot_of(tconn) {
                    slot.outq.push_back(data);
                }
            }
            CoreMsg::Close { tconn } => {
                if let Some(slot) = self.slot_of(tconn) {
                    slot.remote_close = true;
                }
            }
            CoreMsg::Route { msg, qos, retain } => self.broker.route_remote(&msg, qos, retain),
            CoreMsg::IpConfig { .. } => {}
        }
    }

    fn slot_of(&mut self, tconn: Tconn) -> Option<&mut Slot> {
        let slot = self.slots.get_mut((tconn & 0xffff) as usize)?;
        (slot.tconn == tconn && matches!(slot.peer, Some(Peer::Remote { .. }))).then_some(slot)
    }

    /// Ends the MQTT session of a slot (persistence snapshot, will) as
    /// soon as we close our side, without waiting for TCP to finish: a
    /// simultaneous close can keep smoltcp in CLOSING for a retransmission
    /// timeout (ADR-032).
    fn detach(broker: &mut Broker, slot: &mut Slot, link: &mut Link, now_ms: u64) {
        match slot.peer.take() {
            Some(Peer::Local(c)) => finish(broker, c, now_ms),
            Some(Peer::Remote { home }) => link.send(home, CoreMsg::Closed { tconn: slot.tconn }),
            None => {}
        }
    }

    /// Ends whatever the slot was serving and makes it reusable.
    fn reset_slot(broker: &mut Broker, slot: &mut Slot, link: &mut Link, now_ms: u64) {
        Self::detach(broker, slot, link, now_ms);
        slot.session = None;
        slot.pending.clear();
        slot.early.clear();
        slot.outq.clear();
        slot.remote_close = false;
        slot.closing = false;
        slot.tconn = 0;
    }

    /// Attaches the slot to the session's home shard (here or relayed).
    fn attach(
        &mut self,
        i: usize,
        home: usize,
        identity: Option<&str>,
        link: &mut Link,
        now_ms: u64,
    ) -> bool {
        let Some(slot) = self.slots.get_mut(i) else {
            return false;
        };
        if home == self.me {
            let Some(c) = self.broker.open(now_ms) else {
                return false;
            };
            if let Some(id) = identity {
                self.broker.set_identity(c, id);
            }
            slot.peer = Some(Peer::Local(c));
        } else {
            link.send(
                home,
                CoreMsg::Open {
                    tconn: slot.tconn,
                    identity: identity.map(Into::into),
                },
            );
            slot.peer = Some(Peer::Remote { home });
        }
        true
    }

    /// Hands plaintext from the client to its session.
    fn deliver(&mut self, i: usize, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        match slot.peer {
            Some(Peer::Local(c)) => self.broker.input(c, data, now_ms),
            Some(Peer::Remote { home }) => link.send(
                home,
                CoreMsg::Input {
                    tconn: slot.tconn,
                    data: data.to_vec(),
                },
            ),
            None => {}
        }
    }

    /// Dev plaintext port: holds bytes until the CONNECT names the client,
    /// then attaches to its home shard. Garbage goes to this core's shard,
    /// which rejects it.
    fn sniff_connect(&mut self, i: usize, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(slot) = self.slots.get_mut(i) else {
            return;
        };
        slot.early.extend_from_slice(data);
        let limit = CONFIG.limits.max_packet_size as usize + 5;
        let home = match urmqtt_mqtt::decode(&slot.early, &urmqtt_mqtt::Limits::PROTOCOL_MAX) {
            Ok((urmqtt_mqtt::Packet::Connect(c), _)) => {
                Some(dataplane::home_of(c.client_id, self.n))
            }
            Err(urmqtt_mqtt::Error::Incomplete(_)) if slot.early.len() <= limit => None,
            _ => Some(self.me),
        };
        let Some(home) = home else { return };
        let early = core::mem::take(&mut slot.early);
        if self.attach(i, home, None, link, now_ms) {
            self.deliver(i, &early, link, now_ms);
        } else if let Some(slot) = self.slots.get_mut(i) {
            slot.closing = true;
        }
    }

    fn poll_slot(
        &mut self,
        i: usize,
        sockets: &mut SocketSet<'_>,
        link: &mut Link,
        now_ms: u64,
    ) -> bool {
        let Some(slot) = self.slots.get_mut(i) else {
            return false;
        };
        let s = sockets.get_mut::<tcp::Socket>(slot.handle);
        if !s.is_open() {
            Self::reset_slot(&mut self.broker, slot, link, now_ms);
            let _ = s.listen(slot.port);
            return false;
        }
        let mut activity = false;
        // `tconn == 0`: not accepted yet (it is set below and cleared by
        // `reset_slot`).
        let fresh = slot.tconn == 0 && s.may_recv() && !slot.closing;
        if fresh {
            self.slot_gen = self.slot_gen.wrapping_add(1).max(1);
            slot.tconn = (u32::from(self.slot_gen) << 16) | i as u32;
            slot.accepted_ms = now_ms;
            if let Some(a) = dataplane::ACCEPTED.get(self.me) {
                // Relaxed: statistics.
                a.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            if slot.tls {
                let admitted = {
                    let rate = CONFIG.limits.handshakes_per_core_per_sec;
                    let elapsed = now_ms.saturating_sub(self.admission.last_ms);
                    let refill = (elapsed * u64::from(rate) / 1000) as u32;
                    if refill > 0 {
                        self.admission.tokens =
                            self.admission.tokens.saturating_add(refill).min(rate);
                        self.admission.last_ms = now_ms;
                    }
                    self.admission.tokens > 0
                };
                let session = self.tls.as_ref().and_then(|t| t.accept().ok());
                match (admitted, session) {
                    (true, Some(sess)) => {
                        self.admission.tokens -= 1;
                        slot.session = Some(Box::new(sess));
                    }
                    _ => {
                        self.refused += 1;
                        // Rate-limited log: 1st, 2nd, 4th, 8th, ... refusal.
                        if self.refused.is_power_of_two() {
                            warn!(
                                "tls: {} handshake(s) refused by admission control",
                                self.refused
                            );
                        }
                        s.abort();
                        return false;
                    }
                }
            }
        }

        // A listening (or not yet accepted) socket has nothing more to do;
        // in particular it must not be mistaken for a closed peer below.
        if slot.tconn == 0 {
            return activity;
        }

        // Inbound. A relayed connection stops reading while the home core
        // is behind, so TCP flow control pushes back on the client.
        loop {
            let Some(slot) = self.slots.get_mut(i) else {
                return activity;
            };
            let s = sockets.get_mut::<tcp::Socket>(slot.handle);
            if !s.can_recv() {
                break;
            }
            if let Some(Peer::Remote { home }) = slot.peer
                && link.backlog_len(home) > RELAY_BACKLOG
            {
                break;
            }
            let n = s.recv_slice(&mut self.buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            activity = true;
            if slot.closing && slot.peer.is_none() {
                // Session already ended: whatever still arrives is dropped.
                continue;
            }
            let data = self.buf.get(..n).unwrap_or(&[]).to_vec();
            if let Some(sess) = slot.session.as_mut() {
                self.app.clear();
                let t0 = urmqtt_arch_aarch64::timer::uptime_ns();
                let r = sess.input(&data, &mut slot.pending, &mut self.app);
                if let Some(a) = dataplane::TLS_NS.get(self.me) {
                    // Relaxed: statistics.
                    a.fetch_add(
                        urmqtt_arch_aarch64::timer::uptime_ns() - t0,
                        core::sync::atomic::Ordering::Relaxed,
                    );
                }
                match r {
                    Ok(Event::Established {
                        identity,
                        suite,
                        resumed,
                    }) => {
                        let home = dataplane::home_of(&identity, self.n);
                        if let Some(dbl) = self.db.as_mut() {
                            dbl.send(DbReq::DeviceSeen {
                                id: identity.as_str().into(),
                                unix: crate::boot::now_unix().unwrap_or(0) as i64,
                            });
                        }
                        debug!(
                            "tls: {identity} authenticated ({suite}{}) on core {}, session on core {home}",
                            if resumed { ", resumed" } else { "" },
                            self.me
                        );
                        if !self.attach(i, home, Some(&identity), link, now_ms)
                            && let Some(slot) = self.slots.get_mut(i)
                        {
                            slot.closing = true;
                        }
                    }
                    Ok(Event::PeerClosed) => slot.closing = true,
                    Ok(Event::None) => {}
                    Err(e) => {
                        warn!("tls: connection refused: {e:?}");
                        slot.closing = true;
                        s.abort();
                        return true;
                    }
                }
                if !self.app.is_empty() {
                    let app = core::mem::take(&mut self.app);
                    self.deliver(i, &app, link, now_ms);
                    self.app = app;
                }
            } else if slot.peer.is_some() {
                self.deliver(i, &data, link, now_ms);
            } else {
                self.sniff_connect(i, &data, link, now_ms);
            }
        }

        let Some(slot) = self.slots.get_mut(i) else {
            return activity;
        };
        let s = sockets.get_mut::<tcp::Socket>(slot.handle);
        // Handshake deadline.
        if slot.peer.is_none()
            && !slot.closing
            && now_ms.saturating_sub(slot.accepted_ms) > HANDSHAKE_TIMEOUT_MS
        {
            if slot.tls {
                warn!("tls: handshake timed out");
            } else {
                warn!("mqtt: no CONNECT within {} s", HANDSHAKE_TIMEOUT_MS / 1000);
            }
            s.abort();
            Self::reset_slot(&mut self.broker, slot, link, now_ms);
            return true;
        }

        // Outbound: session -> (TLS) -> socket.
        match slot.peer {
            Some(Peer::Local(c)) if slot.pending.len() < TX_BUF => {
                let out = self.broker.output(c);
                if !out.is_empty() {
                    let n = out.len();
                    match slot.session.as_mut() {
                        Some(sess) => {
                            if sess.send(out, &mut slot.pending).is_err() {
                                slot.closing = true;
                            }
                        }
                        None => slot.pending.extend_from_slice(out),
                    }
                    self.broker.consumed(c, n);
                }
            }
            Some(Peer::Remote { home }) => {
                while slot.pending.len() < TX_BUF {
                    let Some(data) = slot.outq.pop_front() else {
                        break;
                    };
                    match slot.session.as_mut() {
                        Some(sess) => {
                            if sess.send(&data, &mut slot.pending).is_err() {
                                slot.closing = true;
                            }
                        }
                        None => slot.pending.extend_from_slice(&data),
                    }
                    link.send(
                        home,
                        CoreMsg::Credit {
                            tconn: slot.tconn,
                            bytes: data.len() as u32,
                        },
                    );
                    activity = true;
                }
            }
            _ => {}
        }
        if !slot.pending.is_empty() && s.can_send() {
            let n = s.send_slice(&slot.pending).unwrap_or(0);
            if n > 0 {
                activity = true;
                slot.pending.drain(..n);
            }
        }

        // Closing.
        let peer_gone = (!s.may_recv() && !s.may_send()) || s.state() == tcp::State::CloseWait;
        let session_done = match slot.peer {
            Some(Peer::Local(c)) => {
                self.broker.close_requested(c).is_some() && self.broker.output(c).is_empty()
            }
            Some(Peer::Remote { .. }) => slot.remote_close && slot.outq.is_empty(),
            None => false,
        };
        if (session_done || peer_gone || slot.closing)
            && slot.pending.is_empty()
            && s.state() != tcp::State::Closed
        {
            // close_notify even after the peer's FIN (CloseWait still allows
            // sending): clients like mosquitto half-close right after
            // DISCONNECT and OpenSSL 3 treats a missing close_notify as an error.
            if let Some(sess) = slot.session.as_mut()
                && s.may_send()
            {
                sess.close(&mut slot.pending);
                if !slot.pending.is_empty() && s.can_send() {
                    let n = s.send_slice(&slot.pending).unwrap_or(0);
                    slot.pending.drain(..n);
                }
            }
            if !slot.closing || session_done || peer_gone {
                slot.closing = true;
                s.close();
                Self::detach(&mut self.broker, slot, link, now_ms);
            }
        }
        // Once both FINs are exchanged the session is over. Aborting here
        // would send a RST that can overtake our close_notify (OpenSSL 3 then
        // reports "unexpected eof"), and smoltcp keeps TIME_WAIT for 10 s,
        // which would hold the slot. So a socket in TIME_WAIT is replaced by
        // a fresh listening one; a late duplicate from the old connection
        // just gets a RST from the stack (ADR-032).
        // CLOSING (simultaneous close: both FINs sent, ours not yet seen as
        // acknowledged by smoltcp, which waits a full retransmission timeout)
        // is treated the same way.
        if slot.closing
            && matches!(
                s.state(),
                tcp::State::TimeWait | tcp::State::Closing | tcp::State::Closed
            )
        {
            let replace = s.state() != tcp::State::Closed;
            Self::reset_slot(&mut self.broker, slot, link, now_ms);
            if replace {
                sockets.remove(slot.handle);
                slot.handle = sockets.add(new_socket());
                let _ = sockets
                    .get_mut::<tcp::Socket>(slot.handle)
                    .listen(slot.port);
            }
        }
        activity
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
