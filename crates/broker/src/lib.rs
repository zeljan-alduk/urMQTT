//! MQTT 3.1.1 broker core: sessions, topic tree, subscriptions, routing,
//! QoS 0/1, retained messages, Last Will, keepalive, ACL and limits.
//!
//! The broker is *sans-IO*: the transport feeds bytes in with [`Broker::input`]
//! and drains bytes from [`Broker::output`]; time comes in as milliseconds.
//! That keeps it host-testable end to end over an in-memory transport and
//! independent of the TCP stack (smoltcp now, the own stack in M14).
//!
//! **Status:** M9 is single-core and favours correctness. Compact per-core
//! structures (≤ 64 B hot session state, interned device-scoped topics) are
//! M15; cross-core fan-out is M13.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

pub mod acl;
mod topics;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use urmqtt_mqtt::{
    ConnAck, Connect, ConnectReturnCode, Error as CodecError, Limits, Packet, Publish, QoS,
    SUBACK_FAILURE, SubAck, decode, encode, encoded_len, is_valid_topic_filter,
    is_valid_topic_name,
};

pub use acl::{Acl, Role};
pub use topics::{NodeId, Topics};

pub type ConnId = u32;
pub type SessionId = u32;

/// A published message, stored once and shared by every delivery.
#[derive(Debug)]
pub struct MsgInner {
    pub topic: Box<str>,
    pub payload: Box<[u8]>,
}

pub type Msg = Arc<MsgInner>;

/// Broker limits and policy (from the build-time configuration).
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub limits: Limits,
    pub max_connections: usize,
    pub max_subscriptions_per_session: usize,
    pub max_inflight: usize,
    pub max_queued: usize,
    /// Token bucket per session: `rate_tokens` per `rate_period_ms`.
    pub rate_tokens: u32,
    pub rate_period_ms: u32,
    /// Bytes buffered for one connection before QoS 0 is dropped and
    /// QoS 1 is queued instead.
    pub max_outbound_bytes: usize,
    pub acl: Acl,
    /// Record state changes for the durable store ([`Broker::drain_persist`]).
    pub persist: bool,
    /// Accepted PUBLISHes on these topic filters go to the telemetry log
    /// ([`Broker::drain_telemetry`]).
    pub telemetry: &'static [&'static str],
    /// Other broker shards exist: every message routed from here is also
    /// handed out for them ([`Broker::drain_routes`], M13).
    pub fanout: bool,
}

/// A change to durable broker state, for the DB core (ADR-030).
///
/// Persistent sessions are stored with their subscriptions; their queued
/// QoS 1 messages are stored while they are offline (a snapshot at
/// disconnect, then each new message). While a session is online its
/// in-flight state lives in RAM only.
#[derive(Debug, Clone)]
pub enum PersistOp {
    /// Set a retained message; an empty payload clears it.
    Retain {
        msg: Msg,
        qos: QoS,
    },
    SessionUpsert {
        client_id: Box<str>,
    },
    /// Deletes the session with its subscriptions and queue.
    SessionDelete {
        client_id: Box<str>,
    },
    Subscribe {
        client_id: Box<str>,
        filter: Box<str>,
        qos: QoS,
    },
    Unsubscribe {
        client_id: Box<str>,
        filter: Box<str>,
    },
    QueuePush {
        client_id: Box<str>,
        msg: Msg,
    },
    QueueClear {
        client_id: Box<str>,
    },
}

/// Why a connection is (being) closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    ClientDisconnect,
    ProtocolError,
    KeepAliveTimeout,
    TakenOver,
    Rejected,
    Unsupported,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub connections: usize,
    pub sessions: usize,
    pub subscriptions: usize,
    pub retained: usize,
    pub topic_nodes: usize,
    pub published: u64,
    pub delivered: u64,
    pub dropped_acl: u64,
    pub dropped_rate: u64,
    pub dropped_queue_full: u64,
    pub dropped_backpressure: u64,
    pub wills_published: u64,
}

struct Will {
    msg: Msg,
    qos: QoS,
    retain: bool,
}

struct Conn {
    session: Option<SessionId>,
    /// Authenticated identity (TLS client certificate); the client id must
    /// equal it. `None` only for the dev plaintext listener.
    identity: Option<Box<str>>,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    keepalive_ms: u64,
    last_rx_ms: u64,
    will: Option<Will>,
    close: Option<CloseReason>,
    /// Listed in `ready` since the last `drain_ready`.
    ready: bool,
}

struct Bucket {
    tokens: u32,
    last_ms: u64,
}

struct Session {
    client_id: Box<str>,
    role: Role,
    clean: bool,
    conn: Option<ConnId>,
    subs: Vec<(Box<str>, NodeId, QoS)>,
    inflight: Vec<(u16, Msg)>,
    queue: VecDeque<Msg>,
    next_pid: u16,
    bucket: Bucket,
    /// The session exists in the durable store.
    persisted: bool,
}

pub struct Broker {
    cfg: Config,
    conns: Vec<Option<Conn>>,
    sessions: Vec<Option<Session>>,
    by_client: BTreeMap<Box<str>, SessionId>,
    topics: Topics,
    stats: Stats,
    scratch: Vec<(SessionId, QoS)>,
    ops: Vec<PersistOp>,
    telemetry: Vec<Msg>,
    routes: Vec<(Msg, QoS, bool)>,
    /// Connections with new output or a close request.
    ready: Vec<ConnId>,
}

/// Stored topics are re-checked on restore: limits may have changed.
fn within_limits(t: &str, limits: &Limits, valid: fn(&str) -> bool) -> bool {
    valid(t)
        && !t.contains('\0')
        && t.len() <= usize::from(limits.max_topic_len)
        && t.split('/').count() <= usize::from(limits.max_topic_levels)
}

/// Bytes kept per connection for an incomplete inbound packet beyond the
/// packet limit itself (fixed header).
const INBUF_SLACK: usize = 5;

impl Broker {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            conns: Vec::new(),
            sessions: Vec::new(),
            by_client: BTreeMap::new(),
            topics: Topics::new(),
            stats: Stats::default(),
            scratch: Vec::new(),
            ops: Vec::new(),
            telemetry: Vec::new(),
            routes: Vec::new(),
            ready: Vec::new(),
        }
    }

    /// Connections that got output or a close request since the last call,
    /// so the transport never has to scan every connection.
    pub fn drain_ready(&mut self, out: &mut Vec<ConnId>) {
        for &c in &self.ready {
            if let Some(k) = self.conns.get_mut(c as usize).and_then(Option::as_mut) {
                k.ready = false;
                out.push(c);
            }
        }
        self.ready.clear();
    }

    fn make_ready(&mut self, c: ConnId) {
        if let Some(k) = self.conns.get_mut(c as usize).and_then(Option::as_mut)
            && !k.ready
        {
            k.ready = true;
            self.ready.push(c);
        }
    }

    /// Takes the messages routed here since the last call, for the other
    /// shards: (message, publish QoS, retain).
    pub fn drain_routes(&mut self) -> alloc::vec::Drain<'_, (Msg, QoS, bool)> {
        self.routes.drain(..)
    }

    /// Routes a message accepted by another shard to this shard's
    /// subscribers. A retained message updates this shard's replica; the
    /// originating shard alone persists it.
    pub fn route_remote(&mut self, msg: &Msg, qos: QoS, retain: bool) {
        self.route_local(msg, qos, retain, false);
    }

    /// Takes the accepted telemetry PUBLISHes since the last call (in order).
    pub fn drain_telemetry(&mut self) -> alloc::vec::Drain<'_, Msg> {
        self.telemetry.drain(..)
    }

    /// Takes the state changes recorded since the last call (in order).
    pub fn drain_persist(&mut self) -> alloc::vec::Drain<'_, PersistOp> {
        self.ops.drain(..)
    }

    fn emit(&mut self, op: PersistOp) {
        if self.cfg.persist {
            self.ops.push(op);
        }
    }

    /// Restores a retained message from the store (no persist op).
    pub fn restore_retained(&mut self, topic: &str, payload: &[u8], qos: QoS) {
        if payload.is_empty() || !within_limits(topic, &self.cfg.limits, is_valid_topic_name) {
            return;
        }
        let msg = Arc::new(MsgInner {
            topic: topic.into(),
            payload: payload.into(),
        });
        self.topics
            .set_retained(topic, msg, qos.min(QoS::AtLeastOnce));
    }

    /// Restores an offline persistent session from the store. Subscriptions
    /// the current ACL no longer allows are dropped (and removed from the
    /// store); limits apply as for live sessions. Returns false if the
    /// client id is not acceptable any more (the session is deleted).
    pub fn restore_session<'a>(
        &mut self,
        client_id: &str,
        subs: impl IntoIterator<Item = (&'a str, QoS)>,
        queued: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> bool {
        if !Self::valid_identity(client_id) || self.by_client.contains_key(client_id) {
            self.emit(PersistOp::SessionDelete {
                client_id: client_id.into(),
            });
            return false;
        }
        let role = self.cfg.acl.role(client_id);
        let sid = self.insert_session(client_id, role, false, 0);
        let (max_subs, max_queued) = (self.cfg.max_subscriptions_per_session, self.cfg.max_queued);
        for (filter, qos) in subs {
            let ok = within_limits(filter, &self.cfg.limits, is_valid_topic_filter)
                && self.cfg.acl.may_subscribe(role, client_id, filter)
                && self.session(sid).is_some_and(|s| s.subs.len() < max_subs);
            if !ok {
                self.emit(PersistOp::Unsubscribe {
                    client_id: client_id.into(),
                    filter: filter.into(),
                });
                continue;
            }
            let qos = qos.min(QoS::AtLeastOnce);
            let node = self.topics.intern(filter);
            self.topics.subscribe(node, sid, qos);
            if let Some(s) = self.session(sid) {
                s.subs.push((filter.into(), node, qos));
            }
        }
        if let Some(s) = self.session(sid) {
            s.persisted = true;
            for (topic, payload) in queued {
                if s.queue.len() >= max_queued {
                    break;
                }
                s.queue.push_back(Arc::new(MsgInner {
                    topic: topic.into(),
                    payload: payload.into(),
                }));
            }
        }
        true
    }

    pub fn stats(&self) -> Stats {
        Stats {
            connections: self.conns.iter().flatten().count(),
            sessions: self.sessions.iter().flatten().count(),
            subscriptions: self.sessions.iter().flatten().map(|s| s.subs.len()).sum(),
            retained: self.topics.retained_count(),
            topic_nodes: self.topics.node_count(),
            ..self.stats
        }
    }

    // ---- transport interface -------------------------------------------

    /// A new network connection. `None` when the connection limit is hit
    /// (the transport should refuse or reset it).
    pub fn open(&mut self, now_ms: u64) -> Option<ConnId> {
        if self.conns.iter().flatten().count() >= self.cfg.max_connections {
            return None;
        }
        let conn = Conn {
            session: None,
            identity: None,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            keepalive_ms: 0,
            last_rx_ms: now_ms,
            will: None,
            close: None,
            ready: false,
        };
        let slot = self.conns.iter().position(Option::is_none);
        Some(match slot {
            Some(i) => {
                if let Some(s) = self.conns.get_mut(i) {
                    *s = Some(conn);
                }
                i as ConnId
            }
            None => {
                self.conns.push(Some(conn));
                (self.conns.len() - 1) as ConnId
            }
        })
    }

    /// Binds the authenticated identity of `c` (before its CONNECT).
    pub fn set_identity(&mut self, c: ConnId, identity: &str) {
        if let Some(k) = self.conn(c) {
            k.identity = Some(identity.into());
        }
    }

    fn conn(&mut self, c: ConnId) -> Option<&mut Conn> {
        self.conns.get_mut(c as usize).and_then(Option::as_mut)
    }

    fn session(&mut self, s: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(s as usize).and_then(Option::as_mut)
    }

    /// Bytes received on `c`. Processes every complete packet.
    pub fn input(&mut self, c: ConnId, data: &[u8], now_ms: u64) {
        let limit = self.cfg.limits.max_packet_size as usize + INBUF_SLACK;
        let Some(conn) = self.conn(c) else { return };
        if conn.close.is_some() {
            return;
        }
        conn.last_rx_ms = now_ms;
        conn.inbuf.extend_from_slice(data);
        loop {
            let Some(conn) = self.conn(c) else { return };
            if conn.close.is_some() {
                return;
            }
            let buf = core::mem::take(&mut conn.inbuf);
            let limits = self.cfg.limits;
            match decode(&buf, &limits) {
                Ok((packet, used)) => {
                    self.handle(c, packet, now_ms);
                    if let Some(conn) = self.conn(c) {
                        conn.inbuf = buf;
                        conn.inbuf.drain(..used.min(conn.inbuf.len()));
                    }
                }
                Err(CodecError::Incomplete(_)) => {
                    let too_big = buf.len() > limit;
                    if let Some(conn) = self.conn(c) {
                        conn.inbuf = buf;
                        if too_big {
                            conn.close = Some(CloseReason::ProtocolError);
                        }
                    }
                    return;
                }
                Err(CodecError::UnsupportedProtocolLevel(_)) => {
                    self.send(
                        c,
                        &Packet::ConnAck(ConnAck {
                            session_present: false,
                            code: ConnectReturnCode::UnacceptableProtocolVersion,
                        }),
                    );
                    self.mark_close(c, CloseReason::Unsupported);
                    return;
                }
                Err(_) => {
                    self.mark_close(c, CloseReason::ProtocolError);
                    return;
                }
            }
        }
    }

    /// Bytes waiting to be sent on `c`.
    pub fn output(&self, c: ConnId) -> &[u8] {
        self.conns
            .get(c as usize)
            .and_then(Option::as_ref)
            .map_or(&[], |k| k.outbuf.as_slice())
    }

    /// The transport sent the first `n` bytes of [`output`](Self::output).
    pub fn consumed(&mut self, c: ConnId, n: usize) {
        if let Some(conn) = self.conn(c) {
            let n = n.min(conn.outbuf.len());
            conn.outbuf.drain(..n);
        }
        // Space freed: move queued QoS 1 messages into flight.
        if let Some(s) = self.conn(c).and_then(|k| k.session) {
            self.pump(s);
        }
    }

    /// Whether the broker wants `c` closed (after flushing `output`).
    pub fn close_requested(&self, c: ConnId) -> Option<CloseReason> {
        self.conns
            .get(c as usize)
            .and_then(Option::as_ref)
            .and_then(|k| k.close)
    }

    /// The network connection is gone. Publishes the Last Will unless the
    /// client sent DISCONNECT (§3.1.2.5).
    pub fn closed(&mut self, c: ConnId, _now_ms: u64) {
        let Some(conn) = self.conns.get_mut(c as usize).and_then(Option::take) else {
            return;
        };
        if conn.close != Some(CloseReason::ClientDisconnect)
            && let Some(w) = conn.will
        {
            self.stats.wills_published += 1;
            self.route(&w.msg, w.qos, w.retain);
        }
        if let Some(sid) = conn.session {
            let (detach, clean) = match self.session(sid) {
                Some(s) if s.conn == Some(c) => (true, s.clean),
                _ => (false, false),
            };
            if detach {
                if clean {
                    self.remove_session(sid);
                } else if let Some(s) = self.session(sid) {
                    s.conn = None;
                    // Snapshot what the device has not acknowledged yet:
                    // in-flight first (older), then the queue.
                    if s.persisted {
                        let cid = s.client_id.clone();
                        let msgs: Vec<Msg> = s
                            .inflight
                            .iter()
                            .map(|(_, m)| m.clone())
                            .chain(s.queue.iter().cloned())
                            .collect();
                        self.emit(PersistOp::QueueClear {
                            client_id: cid.clone(),
                        });
                        for msg in msgs {
                            self.emit(PersistOp::QueuePush {
                                client_id: cid.clone(),
                                msg,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Enforces keepalive (1.5 × the client's interval, §3.1.2.10).
    /// Callers run this periodically (every 100 ms is plenty); it scans the
    /// connections, so it is kept off the per-packet path.
    pub fn tick(&mut self, now_ms: u64) {
        for (i, k) in self.conns.iter_mut().enumerate() {
            if let Some(k) = k
                && k.close.is_none()
                && k.keepalive_ms > 0
                && now_ms.saturating_sub(k.last_rx_ms) > k.keepalive_ms * 3 / 2
            {
                k.close = Some(CloseReason::KeepAliveTimeout);
                if !k.ready {
                    k.ready = true;
                    self.ready.push(i as ConnId);
                }
            }
        }
    }

    // ---- packet handling -------------------------------------------------

    fn mark_close(&mut self, c: ConnId, why: CloseReason) {
        if let Some(conn) = self.conn(c)
            && conn.close.is_none()
        {
            conn.close = Some(why);
        }
        self.make_ready(c);
    }

    fn send(&mut self, c: ConnId, p: &Packet<'_>) {
        let n = encoded_len(p);
        if let Some(conn) = self.conn(c) {
            let start = conn.outbuf.len();
            conn.outbuf.resize(start + n, 0);
            let ok = conn
                .outbuf
                .get_mut(start..)
                .is_some_and(|dst| encode(p, dst).is_ok());
            if !ok {
                conn.outbuf.truncate(start);
            }
        }
        self.make_ready(c);
    }

    fn handle(&mut self, c: ConnId, packet: Packet<'_>, now_ms: u64) {
        let connected = self.conn(c).is_some_and(|k| k.session.is_some());
        match packet {
            Packet::Connect(p) if !connected => self.on_connect(c, &p, now_ms),
            // A second CONNECT, or anything before CONNECT (§3.1.0).
            Packet::Connect(_) => self.mark_close(c, CloseReason::ProtocolError),
            _ if !connected => self.mark_close(c, CloseReason::ProtocolError),
            Packet::Publish(p) => self.on_publish(c, &p, now_ms),
            Packet::PubAck(id) => self.on_puback(c, id),
            Packet::Subscribe(s) => {
                let topics: Vec<(&str, QoS)> = s.topics.iter().collect();
                self.on_subscribe(c, s.packet_id, &topics);
            }
            Packet::Unsubscribe(u) => {
                let topics: Vec<&str> = u.topics.iter().collect();
                self.on_unsubscribe(c, u.packet_id, &topics);
            }
            Packet::PingReq => self.send(c, &Packet::PingResp),
            Packet::Disconnect => {
                if let Some(k) = self.conn(c) {
                    k.will = None;
                }
                self.mark_close(c, CloseReason::ClientDisconnect);
            }
            // QoS 2 is not supported yet (PROMPT §7.1, documented); server-
            // to-client packet types from a client are protocol errors.
            Packet::PubRec(_)
            | Packet::PubRel(_)
            | Packet::PubComp(_)
            | Packet::ConnAck(_)
            | Packet::SubAck(_)
            | Packet::UnsubAck(_)
            | Packet::PingResp => self.mark_close(c, CloseReason::ProtocolError),
        }
    }

    fn reject(&mut self, c: ConnId, code: ConnectReturnCode) {
        self.send(
            c,
            &Packet::ConnAck(ConnAck {
                session_present: false,
                code,
            }),
        );
        self.mark_close(c, CloseReason::Rejected);
    }

    /// Identities become topic levels via `{id}`: forbid wildcard and
    /// separator characters.
    fn valid_identity(id: &str) -> bool {
        !id.is_empty() && !id.contains(['/', '+', '#']) && !id.starts_with('$')
    }

    fn on_connect(&mut self, c: ConnId, p: &Connect<'_>, now_ms: u64) {
        if !Self::valid_identity(p.client_id) {
            return self.reject(c, ConnectReturnCode::IdentifierRejected);
        }
        // PROMPT §7.1: the client id must equal the certificate identity.
        let mismatch = self
            .conns
            .get(c as usize)
            .and_then(Option::as_ref)
            .and_then(|k| k.identity.as_deref())
            .is_some_and(|id| id != p.client_id);
        if mismatch {
            return self.reject(c, ConnectReturnCode::IdentifierRejected);
        }
        let role = self.cfg.acl.role(p.client_id);
        let will = match &p.will {
            Some(w) if !self.cfg.acl.may_publish(role, p.client_id, w.topic) => {
                return self.reject(c, ConnectReturnCode::NotAuthorized);
            }
            Some(w) => Some(Will {
                msg: Arc::new(MsgInner {
                    topic: w.topic.into(),
                    payload: w.payload.into(),
                }),
                qos: w.qos.min(QoS::AtLeastOnce),
                retain: w.retain,
            }),
            None => None,
        };

        // Session takeover (§3.1.4): the existing connection is closed.
        let existing = self.by_client.get(p.client_id).copied();
        if let Some(sid) = existing
            && let Some(old) = self.session(sid).and_then(|s| s.conn)
            && old != c
        {
            self.mark_close(old, CloseReason::TakenOver);
            if let Some(s) = self.session(sid) {
                s.conn = None;
            }
        }
        let session_present = match existing {
            Some(sid) if p.clean_session => {
                self.remove_session(sid);
                false
            }
            Some(_) => true,
            None => false,
        };
        let sid = match self.by_client.get(p.client_id).copied() {
            Some(sid) => sid,
            None => self.create_session(p.client_id, role, p.clean_session, now_ms),
        };
        let mut newly_persistent = None;
        if let Some(s) = self.session(sid) {
            s.conn = Some(c);
            s.clean = p.clean_session;
            if !s.clean && !s.persisted {
                s.persisted = true;
                newly_persistent = Some((
                    s.client_id.clone(),
                    s.subs
                        .iter()
                        .map(|(f, _, q)| (f.clone(), *q))
                        .collect::<Vec<_>>(),
                ));
            }
        }
        if let Some((cid, subs)) = newly_persistent {
            self.emit(PersistOp::SessionUpsert {
                client_id: cid.clone(),
            });
            for (filter, qos) in subs {
                self.emit(PersistOp::Subscribe {
                    client_id: cid.clone(),
                    filter,
                    qos,
                });
            }
        } else if session_present {
            // The stored queue is back in RAM (delivered or in flight).
            self.emit(PersistOp::QueueClear {
                client_id: p.client_id.into(),
            });
        }
        if let Some(k) = self.conn(c) {
            k.session = Some(sid);
            k.keepalive_ms = u64::from(p.keep_alive) * 1000;
            k.will = will;
        }
        self.send(
            c,
            &Packet::ConnAck(ConnAck {
                session_present,
                code: ConnectReturnCode::Accepted,
            }),
        );
        if session_present {
            self.resend_inflight(sid);
            self.pump(sid);
        }
    }

    fn create_session(&mut self, id: &str, role: Role, clean: bool, now_ms: u64) -> SessionId {
        // Persistence of a new persistent session is recorded by the
        // caller (`on_connect`) once the session is attached.
        self.insert_session(id, role, clean, now_ms)
    }

    fn insert_session(&mut self, id: &str, role: Role, clean: bool, now_ms: u64) -> SessionId {
        let s = Session {
            client_id: id.into(),
            role,
            clean,
            conn: None,
            subs: Vec::new(),
            inflight: Vec::new(),
            queue: VecDeque::new(),
            next_pid: 1,
            bucket: Bucket {
                tokens: self.cfg.rate_tokens,
                last_ms: now_ms,
            },
            persisted: false,
        };
        let sid = match self.sessions.iter().position(Option::is_none) {
            Some(i) => {
                if let Some(slot) = self.sessions.get_mut(i) {
                    *slot = Some(s);
                }
                i as SessionId
            }
            None => {
                self.sessions.push(Some(s));
                (self.sessions.len() - 1) as SessionId
            }
        };
        self.by_client.insert(id.into(), sid);
        sid
    }

    fn remove_session(&mut self, sid: SessionId) {
        let Some(s) = self.sessions.get_mut(sid as usize).and_then(Option::take) else {
            return;
        };
        for (_, node, _) in &s.subs {
            self.topics.unsubscribe(*node, sid);
        }
        self.by_client.remove(&s.client_id);
        if s.persisted {
            self.emit(PersistOp::SessionDelete {
                client_id: s.client_id,
            });
        }
    }

    fn take_token(&mut self, sid: SessionId, now_ms: u64) -> bool {
        let (rate, period) = (
            self.cfg.rate_tokens,
            u64::from(self.cfg.rate_period_ms.max(1)),
        );
        let Some(s) = self.session(sid) else {
            return false;
        };
        let elapsed = now_ms.saturating_sub(s.bucket.last_ms);
        let refill = (elapsed * u64::from(rate) / period) as u32;
        if refill > 0 {
            s.bucket.tokens = s.bucket.tokens.saturating_add(refill).min(rate);
            s.bucket.last_ms = now_ms;
        }
        if s.bucket.tokens == 0 {
            return false;
        }
        s.bucket.tokens -= 1;
        true
    }

    fn on_publish(&mut self, c: ConnId, p: &Publish<'_>, now_ms: u64) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if p.qos == QoS::ExactlyOnce {
            // Not supported in v1 (PROMPT §7.1): no way to refuse in 3.1.1.
            return self.mark_close(c, CloseReason::Unsupported);
        }
        // §3.3.5: an unauthorised publish is acknowledged and dropped.
        if let Some(id) = p.packet_id {
            self.send(c, &Packet::PubAck(id));
        }
        let Some((role, allowed)) = self.session(sid).map(|s| (s.role, s.client_id.clone())) else {
            return;
        };
        if !self.cfg.acl.may_publish(role, &allowed, p.topic) {
            self.stats.dropped_acl += 1;
            return;
        }
        if !self.take_token(sid, now_ms) {
            self.stats.dropped_rate += 1;
            return;
        }
        self.stats.published += 1;
        let msg = Arc::new(MsgInner {
            topic: p.topic.into(),
            payload: p.payload.into(),
        });
        if self
            .cfg
            .telemetry
            .iter()
            .any(|f| urmqtt_mqtt::topic_matches(f, p.topic))
        {
            self.telemetry.push(msg.clone());
        }
        self.route(&msg, p.qos, p.retain);
    }

    /// Delivers `msg` to every matching subscriber; retains it if asked.
    fn route(&mut self, msg: &Msg, qos: QoS, retain: bool) {
        if self.cfg.fanout {
            self.routes.push((msg.clone(), qos, retain));
        }
        self.route_local(msg, qos, retain, true);
    }

    fn route_local(&mut self, msg: &Msg, qos: QoS, retain: bool, origin: bool) {
        if retain {
            self.topics.set_retained(&msg.topic, msg.clone(), qos);
            if origin {
                self.emit(PersistOp::Retain {
                    msg: msg.clone(),
                    qos: qos.min(QoS::AtLeastOnce),
                });
            }
        }
        let mut subs = core::mem::take(&mut self.scratch);
        self.topics.subscribers(&msg.topic, &mut subs);
        for &(sid, sub_qos) in &subs {
            self.deliver(sid, msg, qos.min(sub_qos), false);
        }
        self.scratch = subs;
    }

    fn alloc_pid(s: &mut Session) -> u16 {
        loop {
            let id = s.next_pid;
            s.next_pid = s.next_pid.checked_add(1).unwrap_or(1);
            if !s.inflight.iter().any(|(p, _)| *p == id) {
                return id;
            }
        }
    }

    fn deliver(&mut self, sid: SessionId, msg: &Msg, qos: QoS, retain: bool) {
        enum Action {
            Send0(ConnId),
            Send1(ConnId, u16),
            Queue,
            Drop,
        }
        let max_inflight = self.cfg.max_inflight;
        let max_queued = self.cfg.max_queued;
        let max_out = self.cfg.max_outbound_bytes;
        let Some(conn) = self
            .sessions
            .get(sid as usize)
            .and_then(Option::as_ref)
            .map(|s| s.conn)
        else {
            return;
        };
        let room = conn
            .and_then(|c| self.conns.get(c as usize).and_then(Option::as_ref))
            .is_some_and(|k| k.close.is_none() && k.outbuf.len() < max_out);
        let Some(s) = self.session(sid) else { return };
        let action = match (qos, conn) {
            (QoS::AtMostOnce, Some(c)) if room => Action::Send0(c),
            (QoS::AtMostOnce, _) => Action::Drop,
            (_, Some(c)) if room && s.inflight.len() < max_inflight && s.queue.is_empty() => {
                let pid = Self::alloc_pid(s);
                s.inflight.push((pid, msg.clone()));
                Action::Send1(c, pid)
            }
            // Offline persistent session, full window or backpressure.
            (_, Some(_)) => Action::Queue,
            (_, None) if !s.clean => Action::Queue,
            (_, None) => Action::Drop,
        };
        match action {
            Action::Send0(c) => self.send_publish(c, msg, QoS::AtMostOnce, None, retain, false),
            Action::Send1(c, pid) => {
                self.send_publish(c, msg, QoS::AtLeastOnce, Some(pid), retain, false)
            }
            Action::Queue => {
                let mut stored = None;
                if let Some(s) = self.session(sid) {
                    if s.queue.len() >= max_queued {
                        self.stats.dropped_queue_full += 1;
                    } else {
                        s.queue.push_back(msg.clone());
                        // Offline: the store holds the queue (see PersistOp).
                        if s.conn.is_none() && s.persisted {
                            stored = Some(s.client_id.clone());
                        }
                    }
                }
                if let Some(client_id) = stored {
                    self.emit(PersistOp::QueuePush {
                        client_id,
                        msg: msg.clone(),
                    });
                }
            }
            Action::Drop => self.stats.dropped_backpressure += 1,
        }
    }

    fn send_publish(
        &mut self,
        c: ConnId,
        msg: &Msg,
        qos: QoS,
        pid: Option<u16>,
        retain: bool,
        dup: bool,
    ) {
        self.stats.delivered += 1;
        self.send(
            c,
            &Packet::Publish(Publish {
                dup,
                qos,
                retain,
                topic: &msg.topic,
                packet_id: pid,
                payload: &msg.payload,
            }),
        );
    }

    /// Re-sends unacknowledged QoS 1 messages with DUP set (§4.4).
    fn resend_inflight(&mut self, sid: SessionId) {
        let Some(s) = self.session(sid) else { return };
        let Some(c) = s.conn else { return };
        let pending: Vec<(u16, Msg)> = s.inflight.clone();
        for (pid, msg) in pending {
            self.send_publish(c, &msg, QoS::AtLeastOnce, Some(pid), false, true);
        }
    }

    /// Moves queued messages into flight while the window and buffer allow.
    fn pump(&mut self, sid: SessionId) {
        let max_inflight = self.cfg.max_inflight;
        let max_out = self.cfg.max_outbound_bytes;
        loop {
            let Some(s) = self.session(sid) else { return };
            let Some(c) = s.conn else { return };
            if s.inflight.len() >= max_inflight || s.queue.is_empty() {
                return;
            }
            let room = self
                .conns
                .get(c as usize)
                .and_then(Option::as_ref)
                .is_some_and(|k| k.close.is_none() && k.outbuf.len() < max_out);
            if !room {
                return;
            }
            let Some(s) = self.session(sid) else { return };
            let Some(msg) = s.queue.pop_front() else {
                return;
            };
            let pid = Self::alloc_pid(s);
            s.inflight.push((pid, msg.clone()));
            self.send_publish(c, &msg, QoS::AtLeastOnce, Some(pid), false, false);
        }
    }

    fn on_puback(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if let Some(s) = self.session(sid) {
            s.inflight.retain(|(p, _)| *p != pid);
        }
        self.pump(sid);
    }

    fn on_subscribe(&mut self, c: ConnId, packet_id: u16, topics: &[(&str, QoS)]) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        let max_subs = self.cfg.max_subscriptions_per_session;
        let acl = self.cfg.acl;
        let mut codes: Vec<u8> = Vec::with_capacity(topics.len());
        let mut granted: Vec<(&str, QoS)> = Vec::new();
        for &(filter, want) in topics {
            let Some(s) = self.session(sid) else { return };
            let existing = s.subs.iter().position(|(f, _, _)| &**f == filter);
            let allowed = acl.may_subscribe(s.role, &s.client_id, filter);
            if !allowed || (existing.is_none() && s.subs.len() >= max_subs) {
                codes.push(SUBACK_FAILURE);
                continue;
            }
            // QoS 2 is granted as 1 (§3.9.3 permits a lower grant).
            let qos = want.min(QoS::AtLeastOnce);
            let node = self.topics.intern(filter);
            self.topics.subscribe(node, sid, qos);
            if let Some(s) = self.session(sid) {
                match existing {
                    Some(i) => {
                        if let Some(e) = s.subs.get_mut(i) {
                            e.2 = qos;
                        }
                    }
                    None => s.subs.push((filter.into(), node, qos)),
                }
            }
            codes.push(qos as u8);
            granted.push((filter, qos));
            if let Some(s) = self.session(sid)
                && s.persisted
            {
                let client_id = s.client_id.clone();
                self.emit(PersistOp::Subscribe {
                    client_id,
                    filter: filter.into(),
                    qos,
                });
            }
        }
        self.send(
            c,
            &Packet::SubAck(SubAck {
                packet_id,
                return_codes: &codes,
            }),
        );
        // Retained messages for the new subscriptions, RETAIN set (§3.3.1.3).
        let mut retained = Vec::new();
        for (filter, qos) in granted {
            retained.clear();
            self.topics.retained_matching(filter, &mut retained);
            for (msg, rq) in retained.drain(..) {
                self.deliver(sid, &msg, rq.min(qos), true);
            }
        }
    }

    fn on_unsubscribe(&mut self, c: ConnId, packet_id: u16, topics: &[&str]) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        for f in topics {
            let node = self
                .session(sid)
                .and_then(|s| s.subs.iter().find(|(x, _, _)| &**x == *f).map(|e| e.1));
            if let Some(node) = node {
                self.topics.unsubscribe(node, sid);
                let mut stored = None;
                if let Some(s) = self.session(sid) {
                    s.subs.retain(|(x, _, _)| &**x != *f);
                    if s.persisted {
                        stored = Some(s.client_id.clone());
                    }
                }
                if let Some(client_id) = stored {
                    self.emit(PersistOp::Unsubscribe {
                        client_id,
                        filter: (*f).into(),
                    });
                }
            }
        }
        self.send(c, &Packet::UnsubAck(packet_id));
    }

    /// Client ID of the session attached to `c` (for logs).
    pub fn client_id(&self, c: ConnId) -> Option<&str> {
        let sid = self.conns.get(c as usize)?.as_ref()?.session?;
        Some(&self.sessions.get(sid as usize)?.as_ref()?.client_id)
    }
}

#[cfg(test)]
mod tests;
