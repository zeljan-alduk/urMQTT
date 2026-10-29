//! MQTT 3.1.1 broker core: sessions, topic tree, subscriptions, routing,
//! QoS 0/1, retained messages, Last Will, keepalive, ACL and limits.
//!
//! The broker is *sans-IO*: the transport feeds bytes in with [`Broker::input`]
//! and drains bytes from [`Broker::output`]; time comes in as milliseconds.
//! That keeps it host-testable end to end over an in-memory transport and
//! independent of the TCP stack (smoltcp now, the own stack in M14).
//!
//! Per-connection state is compact (M15, ADR-034): 48 B per connection and
//! 64 B per session inline, rare fields boxed, buffers released when empty,
//! subscriptions as interned node ids and device-scoped filters without
//! per-device trie nodes. Cross-core fan-out is M13.

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
mod compact;
mod topics;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use urmqtt_mqtt::{
    ConnAck, Connect, ConnectReturnCode, Error as CodecError, Limits, Packet, Publish, QoS,
    SUBACK_FAILURE, SubAck, decode, encode, encoded_len, is_valid_topic_filter,
    is_valid_topic_name,
};

pub use acl::{Acl, Role};
pub use topics::{NodeId, Topics};

pub use compact::Buf;
use compact::{Index, Small};
use urmqtt_mm::slab::Slab;

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
    /// Rarely present state, boxed so the common connection does not pay
    /// for it (M15).
    extra: Option<Box<Extra>>,
    inbuf: Buf,
    outbuf: Buf,
    last_rx_ms: u64,
    /// The client's keepalive (≤ 65 535 s, so 32 bits of ms suffice).
    keepalive_ms: u32,
    close: Option<CloseReason>,
    /// Listed in `ready` since the last `drain_ready`.
    ready: bool,
}

#[derive(Default)]
struct Extra {
    /// Authenticated identity (TLS client certificate) until CONNECT
    /// checks the client id against it. Never set on the dev plaintext
    /// listener.
    identity: Option<Box<str>>,
    will: Option<Will>,
}

impl Conn {
    fn extra_mut(&mut self) -> &mut Extra {
        self.extra.get_or_insert_with(Default::default)
    }

    /// Frees the box once nothing is left in it.
    fn release_extra(&mut self) {
        if self
            .extra
            .as_ref()
            .is_some_and(|e| e.identity.is_none() && e.will.is_none())
        {
            self.extra = None;
        }
    }
}

#[derive(Default)]
struct Pending {
    inflight: Vec<(u16, Msg)>,
    queue: VecDeque<Msg>,
}

impl Session {
    fn inflight(&self) -> &[(u16, Msg)] {
        self.pending
            .as_deref()
            .map_or(&[], |p| p.inflight.as_slice())
    }

    fn queue_len(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.queue.len())
    }

    fn pending_mut(&mut self) -> &mut Pending {
        self.pending.get_or_insert_with(Default::default)
    }

    /// Frees the queues once both are empty.
    fn release_pending(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.inflight.is_empty() && p.queue.is_empty())
        {
            self.pending = None;
        }
    }
}

/// One subscription: an interned filter. A device-scoped filter
/// (`<scope>/<own client id>/<rest>`, PROMPT §7.3) is stored as `rest`,
/// interned once for all devices in `Broker::scoped`, so devices cost no
/// trie nodes of their own; the scope is implied by the session's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sub {
    node: NodeId,
    qos: QoS,
    scoped: bool,
}

struct Session {
    client_id: Box<str>,
    /// One subscription inline, more exactly sized on the heap.
    subs: Small<Sub>,
    /// Unacknowledged and queued QoS 1 messages; absent while there are none
    /// (an idle session pays 8 bytes, M15).
    pending: Option<Box<Pending>>,
    /// Publish token bucket: tokens left and when it was last refilled.
    refilled_ms: u64,
    tokens: u32,
    /// The attached connection, as id + 1 (`None` while offline).
    conn: Option<NonZeroU32>,
    next_pid: u16,
    role: Role,
    clean: bool,
    /// The session exists in the durable store.
    persisted: bool,
}

impl Session {
    fn conn(&self) -> Option<ConnId> {
        self.conn.map(|c| c.get() - 1)
    }

    fn set_conn(&mut self, c: Option<ConnId>) {
        self.conn = c.and_then(|c| NonZeroU32::new(c.wrapping_add(1)));
    }
}

pub struct Broker {
    cfg: Config,
    conns: Slab<Conn>,
    sessions: Slab<Session>,
    /// Client id → session (the id itself lives in the session).
    by_client: Index,
    topics: Topics,
    /// First topic level of device-scoped topics (`<scope>/<id>/…`), from
    /// the device ACL; empty if the ACL has none.
    scope: &'static str,
    /// Relative device-scoped filters, shared by every device.
    scoped: Topics,
    stats: Stats,
    scratch: Vec<(SessionId, QoS)>,
    ops: Vec<PersistOp>,
    telemetry: Vec<Msg>,
    routes: Vec<(Msg, QoS, bool)>,
    /// Connections with new output or a close request.
    ready: Vec<ConnId>,
}

/// The scope level of the device ACL: the first level of a device
/// subscribe pattern of the form `<scope>/{id}/…` (`devices` by default).
fn device_scope(acl: &Acl) -> &'static str {
    acl.device_subscribe
        .iter()
        .chain(acl.device_publish)
        .find_map(|p| {
            let mut l = p.split('/');
            let first = l.next()?;
            let ok =
                l.next() == Some(acl::ID) && !first.is_empty() && !first.contains(['+', '#', '{']);
            ok.then_some(first)
        })
        .unwrap_or("")
}

/// `filter` relative to `id`'s scope: `<scope>/<id>/<rest>` → `rest`.
fn scoped_part<'a>(scope: &str, id: &str, filter: &'a str) -> Option<&'a str> {
    if scope.is_empty() {
        return None;
    }
    filter
        .strip_prefix(scope)?
        .strip_prefix('/')?
        .strip_prefix(id)?
        .strip_prefix('/')
}

/// The device id and remainder of a topic under the scope (`None` for
/// `<scope>/<id>` itself).
fn scoped_topic<'a>(scope: &str, topic: &'a str) -> Option<(&'a str, Option<&'a str>)> {
    if scope.is_empty() {
        return None;
    }
    let rest = topic.strip_prefix(scope)?.strip_prefix('/')?;
    Some(match rest.split_once('/') {
        Some((id, r)) => (id, Some(r)),
        None => (rest, None),
    })
}

fn session_name(sessions: &Slab<Session>, sid: SessionId) -> Option<&str> {
    sessions.get(sid).map(|s| &*s.client_id)
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
            conns: Slab::new(),
            sessions: Slab::new(),
            by_client: Index::default(),
            topics: Topics::new(),
            scope: device_scope(&cfg.acl),
            scoped: Topics::new(),
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
            if let Some(k) = self.conns.get_mut(c) {
                k.ready = false;
                out.push(c);
            }
        }
        self.ready.clear();
    }

    fn make_ready(&mut self, c: ConnId) {
        if let Some(k) = self.conns.get_mut(c)
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

    fn find_session(&self, client_id: &str) -> Option<SessionId> {
        let sessions = &self.sessions;
        self.by_client.get(client_id, |x| session_name(sessions, x))
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
        if !Self::valid_identity(client_id) || self.find_session(client_id).is_some() {
            self.emit(PersistOp::SessionDelete {
                client_id: client_id.into(),
            });
            return false;
        }
        let role = self.cfg.acl.role(client_id);
        let sid = self.insert_session(client_id, role, false, 0);
        let max_queued = self.cfg.max_queued;
        for (filter, qos) in subs {
            let ok = within_limits(filter, &self.cfg.limits, is_valid_topic_filter)
                && self.cfg.acl.may_subscribe(role, client_id, filter)
                && self.add_sub(sid, filter, qos.min(QoS::AtLeastOnce));
            if !ok {
                self.emit(PersistOp::Unsubscribe {
                    client_id: client_id.into(),
                    filter: filter.into(),
                });
            }
        }
        if let Some(s) = self.session(sid) {
            s.persisted = true;
            for (topic, payload) in queued {
                if s.queue_len() >= max_queued {
                    break;
                }
                s.pending_mut().queue.push_back(Arc::new(MsgInner {
                    topic: topic.into(),
                    payload: payload.into(),
                }));
            }
        }
        true
    }

    /// Index of `filter` among the subscriptions of `sid`.
    fn sub_index(&self, sid: SessionId, filter: &str) -> Option<usize> {
        let s = self.sessions.get(sid)?;
        let (trie, f, scoped) = match scoped_part(self.scope, &s.client_id, filter) {
            Some(rel) => (&self.scoped, rel, true),
            None => (&self.topics, filter, false),
        };
        s.subs
            .as_slice()
            .iter()
            .position(|x| x.scoped == scoped && trie.path(x.node) == Some(f))
    }

    /// Subscribes `sid` to `filter` or updates the granted QoS. False if
    /// the session is at its subscription limit.
    fn add_sub(&mut self, sid: SessionId, filter: &str, qos: QoS) -> bool {
        let existing = self.sub_index(sid, filter);
        let max = self.cfg.max_subscriptions_per_session;
        let Some(s) = self.sessions.get_mut(sid) else {
            return false;
        };
        if let Some(e) = existing.and_then(|i| s.subs.as_mut_slice().get_mut(i)) {
            e.qos = qos;
            if !e.scoped {
                self.topics.subscribe(e.node, sid, qos);
            }
            return true;
        }
        if s.subs.len() >= max {
            return false;
        }
        let sub = match scoped_part(self.scope, &s.client_id, filter) {
            Some(rel) => Sub {
                node: self.scoped.intern_filter(rel),
                qos,
                scoped: true,
            },
            None => {
                let node = self.topics.intern_filter(filter);
                self.topics.subscribe(node, sid, qos);
                Sub {
                    node,
                    qos,
                    scoped: false,
                }
            }
        };
        s.subs.push(sub);
        true
    }

    /// Removes `filter` from `sid`; false if it was not subscribed.
    fn remove_sub(&mut self, sid: SessionId, filter: &str) -> bool {
        let Some(i) = self.sub_index(sid, filter) else {
            return false;
        };
        let Some(s) = self.sessions.get_mut(sid) else {
            return false;
        };
        if let Some(sub) = s.subs.remove(i)
            && !sub.scoped
        {
            self.topics.unsubscribe(sub.node, sid);
        }
        true
    }

    /// Every filter of session `s` with its QoS, as the client sent it.
    fn filters_of(&self, s: &Session) -> Vec<(Box<str>, QoS)> {
        s.subs
            .as_slice()
            .iter()
            .filter_map(|x| {
                let f: Box<str> = if x.scoped {
                    let rel = self.scoped.path(x.node)?;
                    alloc::format!("{}/{}/{rel}", self.scope, s.client_id).into()
                } else {
                    self.topics.path(x.node)?.into()
                };
                Some((f, x.qos))
            })
            .collect()
    }

    /// Adds the device-scoped subscribers of `topic` to `out` (the device
    /// named by the topic, if its session lives here). True if any.
    fn scoped_subscribers(&self, topic: &str, out: &mut Vec<(SessionId, QoS)>) -> bool {
        let Some((id, rest)) = scoped_topic(self.scope, topic) else {
            return false;
        };
        let Some(sid) = self.find_session(id) else {
            return false;
        };
        let Some(s) = self.sessions.get(sid).filter(|s| !s.subs.is_empty()) else {
            return false;
        };
        let before = out.len();
        for x in s.subs.as_slice().iter().filter(|x| x.scoped) {
            if self
                .scoped
                .path(x.node)
                .is_some_and(|f| topics::filter_matches(f, rest))
            {
                out.push((sid, x.qos));
            }
        }
        out.len() > before
    }

    pub fn stats(&self) -> Stats {
        Stats {
            connections: self.conns.len(),
            sessions: self.sessions.len(),
            subscriptions: self.sessions.iter().map(|(_, s)| s.subs.len()).sum(),
            retained: self.topics.retained_count(),
            topic_nodes: self.topics.node_count(),
            ..self.stats
        }
    }

    // ---- transport interface -------------------------------------------

    /// A new network connection. `None` when the connection limit is hit
    /// (the transport should refuse or reset it).
    pub fn open(&mut self, now_ms: u64) -> Option<ConnId> {
        if self.conns.len() >= self.cfg.max_connections {
            return None;
        }
        let conn = Conn {
            session: None,
            extra: None,
            inbuf: Buf::default(),
            outbuf: Buf::default(),
            last_rx_ms: now_ms,
            keepalive_ms: 0,
            close: None,
            ready: false,
        };
        Some(self.conns.insert(conn))
    }

    /// Binds the authenticated identity of `c` (before its CONNECT).
    pub fn set_identity(&mut self, c: ConnId, identity: &str) {
        if let Some(k) = self.conn(c) {
            k.extra_mut().identity = Some(identity.into());
        }
    }

    fn conn(&mut self, c: ConnId) -> Option<&mut Conn> {
        self.conns.get_mut(c)
    }

    fn session(&mut self, s: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(s)
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
            let buf = conn.inbuf.take();
            let limits = self.cfg.limits;
            match decode(&buf, &limits) {
                Ok((packet, used)) => {
                    self.handle(c, packet, now_ms);
                    if let Some(conn) = self.conn(c) {
                        let mut buf = buf;
                        buf.drain(..used.min(buf.len()));
                        // Idle connections keep no buffer (M15).
                        conn.inbuf.set(buf);
                    }
                }
                Err(CodecError::Incomplete(_)) => {
                    let too_big = buf.len() > limit;
                    if let Some(conn) = self.conn(c) {
                        conn.inbuf.set(buf);
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
        self.conns.get(c).map_or(&[], |k| k.outbuf.as_slice())
    }

    /// The transport sent the first `n` bytes of [`output`](Self::output).
    pub fn consumed(&mut self, c: ConnId, n: usize) {
        if let Some(conn) = self.conn(c) {
            conn.outbuf.consume(n);
        }
        // Space freed: move queued QoS 1 messages into flight.
        if let Some(s) = self.conn(c).and_then(|k| k.session) {
            self.pump(s);
        }
    }

    /// Whether the broker wants `c` closed (after flushing `output`).
    pub fn close_requested(&self, c: ConnId) -> Option<CloseReason> {
        self.conns.get(c).and_then(|k| k.close)
    }

    /// The network connection is gone. Publishes the Last Will unless the
    /// client sent DISCONNECT (§3.1.2.5).
    pub fn closed(&mut self, c: ConnId, _now_ms: u64) {
        let Some(conn) = self.conns.remove(c) else {
            return;
        };
        if conn.close != Some(CloseReason::ClientDisconnect)
            && let Some(w) = conn.extra.and_then(|e| e.will)
        {
            self.stats.wills_published += 1;
            self.route(&w.msg, w.qos, w.retain);
        }
        if let Some(sid) = conn.session {
            let (detach, clean) = match self.session(sid) {
                Some(s) if s.conn() == Some(c) => (true, s.clean),
                _ => (false, false),
            };
            if detach {
                if clean {
                    self.remove_session(sid);
                } else if let Some(s) = self.session(sid) {
                    s.set_conn(None);
                    // Snapshot what the device has not acknowledged yet:
                    // in-flight first (older), then the queue.
                    if s.persisted {
                        let cid = s.client_id.clone();
                        let msgs: Vec<Msg> = s
                            .inflight()
                            .iter()
                            .map(|(_, m)| m.clone())
                            .chain(s.pending.iter().flat_map(|p| p.queue.iter().cloned()))
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

    /// Returns memory a past peak left behind (empty slab chunks, index
    /// slots, scratch capacity; M16). Callers run it every few seconds.
    pub fn shrink(&mut self) {
        self.conns.shrink();
        self.sessions.shrink();
        let sessions = &self.sessions;
        self.by_client.shrink(|x| session_name(sessions, x));
        if self.ready.is_empty() {
            self.ready.shrink_to_fit();
        }
        if self.scratch.is_empty() {
            self.scratch.shrink_to_fit();
        }
    }

    /// Enforces keepalive (1.5 × the client's interval, §3.1.2.10).
    /// Callers run this periodically (every 100 ms is plenty); it scans the
    /// connections, so it is kept off the per-packet path.
    pub fn tick(&mut self, now_ms: u64) {
        for (i, k) in self.conns.iter_mut() {
            if k.close.is_none()
                && k.keepalive_ms > 0
                && now_ms.saturating_sub(k.last_rx_ms) > u64::from(k.keepalive_ms) * 3 / 2
            {
                k.close = Some(CloseReason::KeepAliveTimeout);
                if !k.ready {
                    k.ready = true;
                    self.ready.push(i);
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
            let out = conn.outbuf.vec_mut();
            let start = out.len();
            out.resize(start + n, 0);
            let ok = out
                .get_mut(start..)
                .is_some_and(|dst| encode(p, dst).is_ok());
            if !ok {
                out.truncate(start);
            }
            conn.outbuf.release();
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
                if let Some(k) = self.conn(c)
                    && let Some(e) = &mut k.extra
                {
                    e.will = None;
                    k.release_extra();
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
            .get(c)
            .and_then(|k| k.extra.as_ref()?.identity.as_deref())
            .is_some_and(|id| id != p.client_id);
        if mismatch {
            return self.reject(c, ConnectReturnCode::IdentifierRejected);
        }
        // Checked: the session keeps the (equal) client id, so the
        // connection's copy is freed (M15).
        if let Some(k) = self.conn(c)
            && let Some(e) = &mut k.extra
        {
            e.identity = None;
            k.release_extra();
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
        let existing = self.find_session(p.client_id);
        if let Some(sid) = existing
            && let Some(old) = self.session(sid).and_then(|s| s.conn())
            && old != c
        {
            self.mark_close(old, CloseReason::TakenOver);
            if let Some(s) = self.session(sid) {
                s.set_conn(None);
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
        let sid = match self.find_session(p.client_id) {
            Some(sid) => sid,
            None => self.create_session(p.client_id, role, p.clean_session, now_ms),
        };
        let mut newly_persistent = None;
        if let Some(s) = self.sessions.get(sid)
            && !p.clean_session
            && !s.persisted
        {
            newly_persistent = Some((s.client_id.clone(), self.filters_of(s)));
        }
        if let Some(s) = self.session(sid) {
            s.set_conn(Some(c));
            s.clean = p.clean_session;
            s.persisted |= newly_persistent.is_some();
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
            k.keepalive_ms = u32::from(p.keep_alive) * 1000;
            if will.is_some() {
                k.extra_mut().will = will;
            }
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
            subs: Small::default(),
            pending: None,
            refilled_ms: now_ms,
            tokens: self.cfg.rate_tokens,
            next_pid: 1,
            persisted: false,
        };
        let sid = self.sessions.insert(s);
        let sessions = &self.sessions;
        self.by_client
            .insert(id, sid, |x| session_name(sessions, x));
        sid
    }

    fn remove_session(&mut self, sid: SessionId) {
        let Some(s) = self.sessions.remove(sid) else {
            return;
        };
        for x in s.subs.as_slice().iter().filter(|x| !x.scoped) {
            self.topics.unsubscribe(x.node, sid);
        }
        let sessions = &self.sessions;
        let gone: &str = &s.client_id;
        self.by_client.remove(gone, |x| {
            if x == sid {
                Some(gone)
            } else {
                session_name(sessions, x)
            }
        });
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
        let elapsed = now_ms.saturating_sub(s.refilled_ms);
        let refill = (elapsed * u64::from(rate) / period) as u32;
        if refill > 0 {
            s.tokens = s.tokens.saturating_add(refill).min(rate);
            s.refilled_ms = now_ms;
        }
        if s.tokens == 0 {
            return false;
        }
        s.tokens -= 1;
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
        if self.scoped_subscribers(&msg.topic, &mut subs) {
            // One delivery per session at the highest QoS, as in the trie.
            subs.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            subs.dedup_by_key(|e| e.0);
        }
        for &(sid, sub_qos) in &subs {
            self.deliver(sid, msg, qos.min(sub_qos), false);
        }
        self.scratch = subs;
    }

    fn alloc_pid(s: &mut Session) -> u16 {
        loop {
            let id = s.next_pid;
            s.next_pid = s.next_pid.checked_add(1).unwrap_or(1);
            if !s.inflight().iter().any(|(p, _)| *p == id) {
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
        let Some(conn) = self.sessions.get(sid).map(|s| s.conn()) else {
            return;
        };
        let room = conn
            .and_then(|c| self.conns.get(c))
            .is_some_and(|k| k.close.is_none() && k.outbuf.len() < max_out);
        let Some(s) = self.session(sid) else { return };
        let action = match (qos, conn) {
            (QoS::AtMostOnce, Some(c)) if room => Action::Send0(c),
            (QoS::AtMostOnce, _) => Action::Drop,
            (_, Some(c)) if room && s.inflight().len() < max_inflight && (s.queue_len() == 0) => {
                let pid = Self::alloc_pid(s);
                s.pending_mut().inflight.push((pid, msg.clone()));
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
                    if s.queue_len() >= max_queued {
                        self.stats.dropped_queue_full += 1;
                    } else {
                        s.pending_mut().queue.push_back(msg.clone());
                        // Offline: the store holds the queue (see PersistOp).
                        if s.conn().is_none() && s.persisted {
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
        let Some(c) = s.conn() else { return };
        let pending: Vec<(u16, Msg)> = s.inflight().to_vec();
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
            let Some(c) = s.conn() else { return };
            if s.inflight().len() >= max_inflight || (s.queue_len() == 0) {
                return;
            }
            let room = self
                .conns
                .get(c)
                .is_some_and(|k| k.close.is_none() && k.outbuf.len() < max_out);
            if !room {
                return;
            }
            let Some(s) = self.session(sid) else { return };
            let Some(msg) = s.pending.as_mut().and_then(|p| p.queue.pop_front()) else {
                return;
            };
            let pid = Self::alloc_pid(s);
            s.pending_mut().inflight.push((pid, msg.clone()));
            self.send_publish(c, &msg, QoS::AtLeastOnce, Some(pid), false, false);
        }
    }

    fn on_puback(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if let Some(s) = self.session(sid) {
            if let Some(p) = s.pending.as_mut() {
                p.inflight.retain(|(x, _)| *x != pid);
            }
            s.release_pending();
        }
        self.pump(sid);
    }

    fn on_subscribe(&mut self, c: ConnId, packet_id: u16, topics: &[(&str, QoS)]) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        let acl = self.cfg.acl;
        let mut codes: Vec<u8> = Vec::with_capacity(topics.len());
        let mut granted: Vec<(&str, QoS)> = Vec::new();
        for &(filter, want) in topics {
            let Some(s) = self.sessions.get(sid) else {
                return;
            };
            // QoS 2 is granted as 1 (§3.9.3 permits a lower grant).
            let qos = want.min(QoS::AtLeastOnce);
            if !acl.may_subscribe(s.role, &s.client_id, filter) || !self.add_sub(sid, filter, qos) {
                codes.push(SUBACK_FAILURE);
                continue;
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
            if self.remove_sub(sid, f) {
                let stored = self
                    .sessions
                    .get(sid)
                    .filter(|s| s.persisted)
                    .map(|s| s.client_id.clone());
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
        let sid = self.conns.get(c)?.session?;
        Some(&self.sessions.get(sid)?.client_id)
    }
}

#[cfg(test)]
mod tests;
