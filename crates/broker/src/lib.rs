//! MQTT 3.1.1 broker core: sessions, topic tree, subscriptions, routing,
//! QoS 0/1/2, retained messages, Last Will, keepalive, ACL and limits.
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
mod flow;
pub mod sys;
mod topics;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use urmqtt_mqtt::{
    ConnAck, Connect, ConnectReturnCode, Error as CodecError, Limits, Packet, Publish, QoS,
    SUBACK_FAILURE, SubAck, decode, encode, encoded_len, is_valid_topic_filter,
    is_valid_topic_name,
};

pub use acl::{Acl, Role};
pub use flow::{FlowStats, PublisherBackpressure};
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
    /// Retained messages one identity may hold (H3, H0-W1). 0: none.
    pub max_retained_per_device: usize,
    /// Retained bytes this shard may hold in all
    /// ([`topics::retained_cost`]: topic, payload and a fixed overhead).
    pub max_retained_bytes: usize,
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
    /// Operational identities that may publish control messages to
    /// `$urmqtt/control` ([`Broker::drain_control`], H1).
    pub control_ids: &'static [&'static str],
    /// The rules of plaintext sessions (P1, ADR-230); `None`: this broker
    /// serves none, and a connection that claims to be one is refused.
    pub plain: Option<PlainPolicy>,
    /// The rules of password sessions on the WebSocket listener (ADR-272);
    /// `None`: this broker serves none.
    pub web: Option<PlainPolicy>,
    /// Stop reading a publisher whose only recipient cannot keep up, instead
    /// of dropping its QoS 0 messages (NOW-13, ADR-269; [`flow`]).
    pub publisher_backpressure: PublisherBackpressure,
}

/// What a plaintext session may do and how much (P1, ADR-229, ADR-230). The
/// ACL is the configuration's `plaintext.acl_*`; a plaintext client never
/// holds the service, operator or control role, whatever its name.
#[derive(Debug, Clone, Copy)]
pub struct PlainPolicy {
    /// Topic filters it may publish to; `{id}` is its identity.
    pub publish: &'static [&'static str],
    /// Topic filters it may subscribe to.
    pub subscribe: &'static [&'static str],
    /// Largest MQTT packet it may send.
    pub max_packet_size: u32,
    /// Publish token bucket of its sessions.
    pub rate_tokens: u32,
    pub rate_period_ms: u32,
    /// May it publish retained messages (a retained publish is delivered but
    /// not retained when not).
    pub retain: bool,
}

impl Config {
    /// The policy of a login role (plaintext, WebSocket password), if this
    /// broker serves it.
    fn login_policy(&self, role: Role) -> Option<&PlainPolicy> {
        match role {
            Role::Plain => self.plain.as_ref(),
            Role::Web => self.web.as_ref(),
            _ => None,
        }
    }

    /// May the session of `role` and ACL name `id` publish to `topic`? The
    /// login roles have their own patterns.
    fn may_publish(&self, role: Role, id: &str, topic: &str) -> bool {
        match role {
            Role::Plain | Role::Web => self
                .login_policy(role)
                .is_some_and(|p| acl::plain_may_publish(p.publish, id, topic)),
            _ => self.acl.may_publish(role, id, topic),
        }
    }

    fn may_subscribe(&self, role: Role, id: &str, filter: &str) -> bool {
        match role {
            Role::Plain | Role::Web => self
                .login_policy(role)
                .is_some_and(|p| acl::plain_may_subscribe(p.subscribe, id, filter)),
            _ => self.acl.may_subscribe(role, id, filter),
        }
    }

    /// May a session of `role` publish retained messages?
    fn may_retain(&self, role: Role) -> bool {
        match role {
            Role::Plain | Role::Web => self.login_policy(role).is_some_and(|p| p.retain),
            _ => true,
        }
    }
}

/// Session-key prefix of bootstrap identities (H1). A real client id can
/// never start with `$` or contain `/`, so a bootstrap session never meets
/// an operational session of the same id: it can neither take it over nor
/// read its queue.
const BOOTSTRAP_KEY: &str = "$bootstrap/";

/// Session-key prefix of plaintext sessions (P1, ADR-230): the key is
/// `$plain/<identity>/<client id>`. A certificate identity never starts with
/// `$` or contains `/`, so a plaintext client cannot take over a TLS device's
/// session by choosing its client id, and the sessions of two plaintext
/// identities never meet either. Plaintext sessions are clean: nothing of
/// them is persisted.
pub const PLAIN_KEY: &str = "$plain/";

/// The session key of the plaintext client `client_id` of `identity`.
pub fn plain_session_key(identity: &str, client_id: &str) -> alloc::string::String {
    alloc::format!("{PLAIN_KEY}{identity}/{client_id}")
}

/// Session-key prefix of password sessions on the WebSocket listener
/// (ADR-272), for the same reasons as [`PLAIN_KEY`]: `$ws/<identity>/<client
/// id>` meets neither a certificate's session nor a plaintext one.
pub const WEB_KEY: &str = "$ws/";

/// The session key of the WebSocket password client `client_id` of
/// `identity`.
pub fn web_session_key(identity: &str, client_id: &str) -> alloc::string::String {
    alloc::format!("{WEB_KEY}{identity}/{client_id}")
}

/// The control topic (H1); see `urmqtt_control::TOPIC`.
pub const CONTROL_TOPIC: &str = "$urmqtt/control";

/// Control messages held between drains; beyond this they are dropped
/// (counted), so a flooding control service costs bounded work.
const MAX_CONTROL_BACKLOG: usize = 64;

/// What an operator asked for on a `$SYS/` request topic (O1, O2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysKind {
    /// One console command ([`sys::CONSOLE_IN`]).
    Console,
    /// The info query ([`sys::QUERY_INFO`]).
    Query,
}

/// An operator's request, for the kernel to answer ([`Broker::drain_sys_requests`]).
pub struct SysRequest {
    pub kind: SysKind,
    pub from: Box<str>,
    pub payload: Box<[u8]>,
}

/// A control message as received: the publisher's identity and the
/// payload, unauthenticated until the control handler verifies it.
pub struct ControlMsg {
    pub from: Box<str>,
    pub payload: Box<[u8]>,
}

/// A QoS 2 packet identifier a session holds between two packets of the
/// exactly-once flow (MQTT 3.1.1 4.3.3, ADR-271).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Qos2Id {
    /// Received from the client with a QoS 2 PUBLISH (PUBREC sent), awaiting
    /// its PUBREL. A PUBLISH with this id is a duplicate until then.
    Received(u16),
    /// Sent to the client: it acknowledged the PUBLISH with PUBREC, the PUBREL
    /// is sent, its PUBCOMP is awaited. The message itself is delivered.
    Released(u16),
}

/// A message of a stored session, as the store hands it back
/// ([`Broker::restore_session`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredMsg<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    /// The QoS it is delivered at: 1 or 2.
    pub qos: QoS,
    /// In flight when the session went offline: the PUBLISH was sent with
    /// this packet id and not acknowledged (no PUBACK, no PUBREC). It is
    /// sent again with that id and DUP set (4.4). `None`: queued, not sent.
    pub pid: Option<u16>,
}

/// A change to durable broker state, for the DB core (ADR-030).
///
/// Persistent sessions are stored with their subscriptions; their queued
/// QoS 1 and 2 messages are stored while they are offline (a snapshot at
/// disconnect, then each new message), with the packet ids of unfinished
/// flows (ADR-271). While a session is online its in-flight state lives in
/// RAM only.
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
    /// Appends a message to the session's stored queue: at `qos` (1 or 2),
    /// in flight with packet id `pid` or (`None`) not sent yet.
    QueuePush {
        client_id: Box<str>,
        msg: Msg,
        qos: QoS,
        pid: Option<u16>,
    },
    /// Records a packet id of an unfinished QoS 2 flow (ADR-271).
    Qos2 {
        client_id: Box<str>,
        id: Qos2Id,
    },
    /// Clears the stored queue and the QoS 2 packet ids of the session.
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
    /// Its identity left the allowlist (H1).
    Disallowed,
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
    /// QoS 0 messages not delivered because the subscriber's output buffer
    /// was full (it reads slower than the topic is published to), or its
    /// connection was closing.
    pub dropped_backpressure: u64,
    /// QoS 0 messages for a subscription whose client is not connected (a
    /// QoS 0 message is never stored).
    pub dropped_offline: u64,
    pub wills_published: u64,
    /// Publishes to the reserved namespace by identities without control
    /// rights, dropped (H1).
    pub dropped_control: u64,
    /// Control messages handed to the control handler.
    pub control_received: u64,
    /// Retained messages not retained: the identity's limit (H3).
    pub retained_refused_device: u64,
    /// Retained messages not retained: the shard's byte budget (H3).
    pub retained_refused_bytes: u64,
    pub retained_bytes: usize,
    /// Connections with a session (CONNECT accepted), not those still
    /// handshaking.
    pub online: usize,
    /// Operator requests dropped: the backlog was full or the session's
    /// publish rate was exceeded (O1, O2).
    pub dropped_sys: u64,
    /// QoS 2 PUBLISHes received with a new packet id (PUBREC sent; routed
    /// unless the ACL or the rate refused them), ADR-271.
    pub qos2_received: u64,
    /// QoS 2 PUBLISHes with a packet id still awaiting its PUBREL: answered
    /// with PUBREC again and not routed again.
    pub qos2_duplicates: u64,
    /// Outbound QoS 2 deliveries completed (PUBCOMP received).
    pub qos2_completed: u64,
    /// Connections closed because they held more QoS 2 packet ids awaiting
    /// PUBREL than [`Broker::qos2_id_limit`] allows.
    pub qos2_inbound_full: u64,
}

struct Will {
    msg: Msg,
    qos: QoS,
    retain: bool,
    /// The identity whose will it is (charged for a retained will).
    owner: Box<str>,
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
    /// Publisher back-pressure state ([`flow`], ADR-269): 0 while input is
    /// parsed as it arrives.
    flow: u8,
    /// Sessions on this shard the last PUBLISH went to (saturating; 255
    /// before the first), for a pause asked by another shard (ADR-269).
    last_local: u8,
}

#[derive(Default)]
struct Extra {
    /// Authenticated identity (TLS client certificate) until CONNECT
    /// checks the client id against it. Never set on the dev plaintext
    /// listener.
    identity: Option<Box<str>>,
    /// The identity comes from a bootstrap trust anchor (H1).
    bootstrap: bool,
    /// A plaintext connection (P1): the identity is the login's, not a
    /// certificate's. Stays set for the connection's life: it selects the
    /// packet limit, the rate and the rules.
    plain: bool,
    /// A password connection of the WebSocket listener (ADR-272), as `plain`
    /// with the WebSocket policy.
    web: bool,
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
            .is_some_and(|e| e.identity.is_none() && e.will.is_none() && !e.plain && !e.web)
        {
            self.extra = None;
        }
    }

    /// The login role of a connection whose identity came from a password
    /// (or a plaintext login mode), if it is one.
    fn login(&self) -> Option<Role> {
        match self.extra.as_ref() {
            Some(e) if e.plain => Some(Role::Plain),
            Some(e) if e.web => Some(Role::Web),
            _ => None,
        }
    }
}

/// Where an outbound QoS 1 or 2 delivery stands (MQTT 3.1.1 4.3.2, 4.3.3;
/// the state machine of ADR-271).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// QoS 1: PUBLISH sent, awaiting PUBACK.
    Puback,
    /// QoS 2: PUBLISH sent, awaiting PUBREC.
    Pubrec,
    /// QoS 2: PUBREL sent, awaiting PUBCOMP. The message is delivered and
    /// no longer held.
    Pubcomp,
}

/// One outbound delivery in flight (16 bytes, as the QoS 1 pair it replaces).
#[derive(Debug, Clone)]
struct Flight {
    pid: u16,
    flow: Flow,
    /// A retained message replayed for a new subscription (RETAIN set,
    /// 3.3.1.3), also when it is sent again.
    retain: bool,
    /// `None` once the PUBREL is sent.
    msg: Option<Msg>,
}

#[derive(Default)]
struct Pending {
    /// Sent and not completed, in the order sent (resent in this order).
    inflight: Vec<Flight>,
    /// Not sent yet, with the QoS each is delivered at (1 or 2) and whether
    /// it is a retained replay (sent with RETAIN when its turn comes).
    queue: VecDeque<(Msg, QoS, bool)>,
    /// QoS 2 packet ids received from the client and acknowledged with
    /// PUBREC, awaiting its PUBREL (method B of 4.3.3: the message is routed
    /// on arrival and only the id is kept). Bounded by
    /// [`Broker::qos2_id_limit`].
    received: Vec<u16>,
}

impl Session {
    fn inflight(&self) -> &[Flight] {
        self.pending
            .as_deref()
            .map_or(&[], |p| p.inflight.as_slice())
    }

    fn queue_len(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.queue.len())
    }

    fn received(&self) -> &[u16] {
        self.pending
            .as_deref()
            .map_or(&[], |p| p.received.as_slice())
    }

    fn pending_mut(&mut self) -> &mut Pending {
        self.pending.get_or_insert_with(Default::default)
    }

    /// Frees the queues once all are empty.
    fn release_pending(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.inflight.is_empty() && p.queue.is_empty() && p.received.is_empty())
        {
            self.pending = None;
        }
    }
}

/// The fewest QoS 2 packet ids a session may hold awaiting PUBREL, whatever
/// `max_inflight` says: common clients pipeline up to 20 QoS 2 publishes
/// (mosquitto's and paho's default windows), ADR-271.
pub const MIN_QOS2_IDS: usize = 64;

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

impl Flow {
    /// The QoS of the PUBLISH this flow delivers.
    fn qos(self) -> QoS {
        match self {
            Flow::Puback => QoS::AtLeastOnce,
            Flow::Pubrec | Flow::Pubcomp => QoS::ExactlyOnce,
        }
    }
}

impl Qos2Id {
    /// The packet identifier.
    pub fn pid(self) -> u16 {
        match self {
            Qos2Id::Received(p) | Qos2Id::Released(p) => p,
        }
    }
}

impl Session {
    /// The identity the ACL's `{id}` stands for (the client id without the
    /// bootstrap session prefix; for a plaintext session the identity of
    /// `$plain/<identity>/<client id>`).
    fn acl_id(&self) -> &str {
        match self.role {
            Role::Bootstrap => self
                .client_id
                .strip_prefix(BOOTSTRAP_KEY)
                .unwrap_or_default(),
            Role::Plain => self
                .client_id
                .strip_prefix(PLAIN_KEY)
                .and_then(|r| r.split('/').next())
                .unwrap_or_default(),
            Role::Web => self
                .client_id
                .strip_prefix(WEB_KEY)
                .and_then(|r| r.split('/').next())
                .unwrap_or_default(),
            _ => &self.client_id,
        }
    }

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
    routes: Vec<(Msg, QoS, bool, Option<ConnId>)>,
    control: Vec<ControlMsg>,
    /// Retained messages held per identity, for identities homed here.
    retained_by: BTreeMap<Box<str>, u32>,
    /// Connections with new output or a close request.
    ready: Vec<ConnId>,
    /// Subscriptions over all sessions, kept up to date so that
    /// [`Broker::stats`] stays O(1).
    subs_total: usize,
    /// Connections with a session.
    online: usize,
    /// The `$SYS/` topics this shard holds retained (injected by the
    /// kernel, never stored or counted against the device budgets), with
    /// their cost.
    sys_topics: BTreeMap<Box<str>, usize>,
    sys_bytes: usize,
    /// The last console lines, replayed to a new `$SYS/console/out`
    /// subscriber.
    console: VecDeque<Msg>,
    sys_in: Vec<SysRequest>,
    /// Counter for the client ids this shard gives plaintext clients that
    /// bring none (MQTT 3.1.1 3.1.3.1; mosquitto's tools send none).
    plain_seq: u64,
    /// Publishers paused for their only recipient (ADR-269).
    flow: flow::Flow,
    /// While a routed message is delivered: a connection that may take it
    /// beyond `max_outbound_bytes`, up to the given length (ADR-269).
    flow_allow: Option<(ConnId, usize)>,
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
            control: Vec::new(),
            retained_by: BTreeMap::new(),
            ready: Vec::new(),
            subs_total: 0,
            online: 0,
            sys_topics: BTreeMap::new(),
            sys_bytes: 0,
            console: VecDeque::new(),
            sys_in: Vec::new(),
            plain_seq: 0,
            flow: flow::Flow::default(),
            flow_allow: None,
        }
    }

    /// Retained bytes of devices (the budget applies to these, not to the
    /// few `$SYS/` topics the kernel injects).
    fn device_retained_bytes(&self) -> usize {
        self.topics.retained_bytes().saturating_sub(self.sys_bytes)
    }

    /// Sets a retained `$SYS/` topic on this shard and delivers it to the
    /// matching subscribers (QoS 0). Not stored, not counted against the
    /// device budgets, not offered to other shards: every shard publishes
    /// its own copy (O1). `payload` must not be empty.
    pub fn sys_publish_retained(&mut self, topic: &str, payload: &[u8]) {
        if payload.is_empty() || !acl::sys(topic) {
            return;
        }
        let msg = Arc::new(MsgInner {
            topic: topic.into(),
            payload: payload.into(),
        });
        let cost = topics::retained_cost(topic, payload.len());
        if let Some(old) = self.sys_topics.insert(topic.into(), cost) {
            self.sys_bytes -= old;
        }
        self.sys_bytes += cost;
        self.store_retained(&msg, QoS::AtMostOnce, None);
        self.route_local(&msg, QoS::AtMostOnce, false, true);
    }

    /// Delivers a `$SYS/` message that is not retained (a query reply).
    pub fn sys_publish(&mut self, topic: &str, payload: &[u8]) {
        if !acl::sys(topic) {
            return;
        }
        let msg = Arc::new(MsgInner {
            topic: topic.into(),
            payload: payload.into(),
        });
        self.route_local(&msg, QoS::AtMostOnce, false, true);
    }

    /// Publishes one console line on [`sys::CONSOLE_OUT`] and keeps it in
    /// the replay ring (the oldest line makes room). Never blocks: a
    /// subscriber that cannot take it loses it (QoS 0, counted by
    /// `dropped_backpressure`).
    pub fn console_line(&mut self, text: &str) {
        let msg = Arc::new(MsgInner {
            topic: sys::CONSOLE_OUT.into(),
            payload: text.as_bytes().into(),
        });
        if self.console.len() >= sys::CONSOLE_RING {
            self.console.pop_front();
        }
        self.console.push_back(msg.clone());
        self.route_local(&msg, QoS::AtMostOnce, false, true);
    }

    /// Takes the operators' requests received since the last call.
    pub fn drain_sys_requests(&mut self) -> alloc::vec::Drain<'_, SysRequest> {
        self.sys_in.drain(..)
    }

    /// Takes the control messages received since the last call (H1).
    pub fn drain_control(&mut self) -> alloc::vec::Drain<'_, ControlMsg> {
        self.control.drain(..)
    }

    /// Closes every online session whose identity and role `keep` rejects
    /// (an allowlist change, H1). Returns how many were closed.
    pub fn disconnect_unless(
        &mut self,
        keep: impl Fn(&str, Role) -> bool,
        why: CloseReason,
    ) -> usize {
        let doomed: Vec<ConnId> = self
            .sessions
            .iter()
            .filter(|(_, s)| !keep(s.acl_id(), s.role))
            .filter_map(|(_, s)| s.conn())
            .collect();
        for &c in &doomed {
            self.mark_close(c, why);
        }
        doomed.len()
    }

    /// Closes the connection of the session named `id` (operational or
    /// bootstrap), if one is online. Returns whether one was.
    pub fn disconnect_identity(&mut self, id: &str, why: CloseReason) -> bool {
        let boot = alloc::format!("{BOOTSTRAP_KEY}{id}");
        let mut any = false;
        for key in [id, boot.as_str()] {
            if let Some(c) = self
                .find_session(key)
                .and_then(|sid| self.sessions.get(sid))
                .and_then(Session::conn)
            {
                self.mark_close(c, why);
                any = true;
            }
        }
        any
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
    /// The fourth field is the publishing connection (ADR-269: the shards
    /// that deliver it say so, [`Broker::note_remote_recipients`]).
    pub fn drain_routes(&mut self) -> alloc::vec::Drain<'_, (Msg, QoS, bool, Option<ConnId>)> {
        self.routes.drain(..)
    }

    /// Routes a message accepted by another shard to this shard's
    /// subscribers. A retained message updates this shard's replica; the
    /// originating shard alone persists it. Returns how many sessions here
    /// it was for.
    pub fn route_remote(&mut self, msg: &Msg, qos: QoS, retain: bool) -> usize {
        self.route_local(msg, qos, retain, false).n
    }

    /// [`Broker::route_remote`] for a message whose publisher is known:
    /// connection `origin.1` on shard `origin.0`. If it went to one session
    /// here and that one is full, the origin is asked to pause the publisher
    /// ([`Broker::drain_remote_flow`], ADR-269).
    pub fn route_remote_from(
        &mut self,
        msg: &Msg,
        qos: QoS,
        retain: bool,
        origin: Option<(u16, ConnId)>,
        now_ms: u64,
    ) -> usize {
        // A subscriber whose publisher was asked to pause takes what is
        // already on its way beyond the usual buffer (ADR-269).
        self.flow_allow = origin.and_then(|o| self.overshoot_for(o));
        let to = self.route_local(msg, qos, retain, false);
        self.flow_allow = None;
        if let Some(o) = origin {
            self.remote_single(o, to, now_ms);
        }
        to.n
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
        // No owner: counts start empty after a restart; the byte budget
        // still applies to what comes back.
        if self.device_retained_bytes() + topics::retained_cost(topic, payload.len())
            > self.cfg.max_retained_bytes
        {
            self.stats.retained_refused_bytes += 1;
            return;
        }
        self.topics.set_retained(topic, msg, qos, None);
    }

    /// How many QoS 2 packet ids a session may hold awaiting the client's
    /// PUBREL (`max_inflight`, at least [`MIN_QOS2_IDS`]). A client that
    /// opens one more is disconnected (`qos2_inbound_full`); it sends the
    /// PUBLISH again when it reconnects.
    pub fn qos2_id_limit(&self) -> usize {
        self.cfg.max_inflight.max(MIN_QOS2_IDS)
    }

    /// Restores an offline persistent session from the store. Subscriptions
    /// the current ACL no longer allows are dropped (and removed from the
    /// store); limits apply as for live sessions. Messages that were in
    /// flight go back into flight with their packet ids (up to the window;
    /// the rest are queued), then the queue; `ids` are the packet ids of
    /// unfinished QoS 2 flows (ADR-271). Returns false if the client id is
    /// not acceptable any more (the session is deleted).
    pub fn restore_session<'a>(
        &mut self,
        client_id: &str,
        subs: impl IntoIterator<Item = (&'a str, QoS)>,
        queued: impl IntoIterator<Item = StoredMsg<'a>>,
        ids: impl IntoIterator<Item = Qos2Id>,
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
        let max_inflight = self.cfg.max_inflight;
        let id_limit = self.qos2_id_limit();
        for (filter, qos) in subs {
            let ok = within_limits(filter, &self.cfg.limits, is_valid_topic_filter)
                && self.cfg.acl.may_subscribe(role, client_id, filter)
                && self.add_sub(sid, filter, qos);
            if !ok {
                self.emit(PersistOp::Unsubscribe {
                    client_id: client_id.into(),
                    filter: filter.into(),
                });
            }
        }
        if let Some(s) = self.session(sid) {
            s.persisted = true;
            // Released ids first: their PUBLISH went out before any message
            // still in flight. Duplicates and ids beyond the bound (the store
            // is not trusted to keep them) are skipped.
            let mut ids: Vec<Qos2Id> = ids.into_iter().filter(|i| i.pid() != 0).collect();
            ids.sort_unstable();
            ids.dedup();
            for id in ids {
                let p = s.pending_mut();
                match id {
                    Qos2Id::Received(pid) if p.received.len() < id_limit => p.received.push(pid),
                    Qos2Id::Released(pid) if p.inflight.len() < id_limit => {
                        p.inflight.push(Flight {
                            pid,
                            flow: Flow::Pubcomp,
                            retain: false,
                            msg: None,
                        })
                    }
                    _ => {}
                }
            }
            for m in queued {
                let qos = m.qos.clamp(QoS::AtLeastOnce, QoS::ExactlyOnce);
                let msg = Arc::new(MsgInner {
                    topic: m.topic.into(),
                    payload: m.payload.into(),
                });
                let p = s.pending_mut();
                let pid = m.pid.filter(|&id| {
                    id != 0
                        && p.inflight.len() < max_inflight
                        && !p.inflight.iter().any(|f| f.pid == id)
                });
                if let Some(pid) = pid {
                    let flow = if qos == QoS::ExactlyOnce {
                        Flow::Pubrec
                    } else {
                        Flow::Puback
                    };
                    p.inflight.push(Flight {
                        pid,
                        flow,
                        retain: false,
                        msg: Some(msg),
                    });
                } else if p.queue.len() < max_queued {
                    p.queue.push_back((msg, qos, false));
                }
            }
            s.release_pending();
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
        self.subs_total += 1;
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
        if let Some(sub) = s.subs.remove(i) {
            self.subs_total = self.subs_total.saturating_sub(1);
            if !sub.scoped {
                self.topics.unsubscribe(sub.node, sid);
            }
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

    /// Publishes to the reserved namespace dropped so far (H1). Cheap,
    /// unlike [`Self::stats`], which walks every session.
    pub fn dropped_control(&self) -> u64 {
        self.stats.dropped_control
    }

    /// Retained messages refused for retention so far: (identity limit,
    /// byte budget), and the bytes held. Cheap, unlike [`Broker::stats`].
    pub fn retained_refused(&self) -> (u64, u64, usize) {
        (
            self.stats.retained_refused_device,
            self.stats.retained_refused_bytes,
            self.device_retained_bytes(),
        )
    }

    pub fn stats(&self) -> Stats {
        Stats {
            connections: self.conns.len(),
            sessions: self.sessions.len(),
            subscriptions: self.subs_total,
            retained: self
                .topics
                .retained_count()
                .saturating_sub(self.sys_topics.len()),
            retained_bytes: self.device_retained_bytes(),
            online: self.online,
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
            flow: 0,
            last_local: u8::MAX,
        };
        Some(self.conns.insert(conn))
    }

    /// Binds the authenticated identity of `c` (before its CONNECT).
    /// `bootstrap`: the certificate comes from a bootstrap trust anchor, so
    /// the session gets the bootstrap role (H1).
    pub fn set_identity(&mut self, c: ConnId, identity: &str, bootstrap: bool) {
        if let Some(k) = self.conn(c) {
            let e = k.extra_mut();
            e.identity = Some(identity.into());
            e.bootstrap = bootstrap;
        }
    }

    /// Binds the identity the login of plaintext connection `c` established
    /// (before its CONNECT, P1). The connection then has the plaintext limits
    /// and the plaintext role, and its client id is free: the session is named
    /// `$plain/<identity>/<client id>` ([`plain_session_key`]). Returns false
    /// when this broker serves no plaintext sessions; the caller closes the
    /// connection.
    pub fn set_plain_identity(&mut self, c: ConnId, identity: &str) -> bool {
        self.set_login_identity(c, identity, Role::Plain)
    }

    /// Binds the identity a WebSocket password login established (before its
    /// CONNECT, ADR-272): as [`set_plain_identity`](Self::set_plain_identity),
    /// with the WebSocket policy and the session name `$ws/<identity>/<client
    /// id>` ([`web_session_key`]). Returns false when this broker serves no
    /// such sessions.
    pub fn set_web_identity(&mut self, c: ConnId, identity: &str) -> bool {
        self.set_login_identity(c, identity, Role::Web)
    }

    fn set_login_identity(&mut self, c: ConnId, identity: &str, role: Role) -> bool {
        if self.cfg.login_policy(role).is_none() {
            return false;
        }
        if let Some(k) = self.conn(c) {
            let e = k.extra_mut();
            e.identity = Some(identity.into());
            e.plain = role == Role::Plain;
            e.web = role == Role::Web;
        }
        true
    }

    fn conn(&mut self, c: ConnId) -> Option<&mut Conn> {
        self.conns.get_mut(c)
    }

    fn session(&mut self, s: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(s)
    }

    /// Bytes received on `c`. Processes every complete packet, unless the
    /// connection's input is held for back-pressure (ADR-269): then the bytes
    /// wait for [`Broker::poll_flow`].
    pub fn input(&mut self, c: ConnId, data: &[u8], now_ms: u64) {
        let Some(conn) = self.conn(c) else { return };
        if conn.close.is_some() {
            return;
        }
        conn.last_rx_ms = now_ms;
        conn.inbuf.extend_from_slice(data);
        if conn.flow != 0 {
            self.held_input(c, now_ms);
            return;
        }
        self.parse(c, now_ms, usize::MAX);
    }

    /// Processes the complete packets in `c`'s input buffer, at most about
    /// `budget` bytes of them; stops early when `c` gets paused (ADR-269).
    fn parse(&mut self, c: ConnId, now_ms: u64, budget: usize) -> flow::Stop {
        // A login connection (plaintext, P1; WebSocket password, ADR-272) has
        // a packet limit of its own. For every other connection this costs
        // the test of a box that is `None` once the connection is attached.
        let limits = match self
            .conns
            .get(c)
            .and_then(Conn::login)
            .and_then(|r| self.cfg.login_policy(r))
        {
            Some(p) => Limits {
                max_packet_size: p.max_packet_size,
                ..self.cfg.limits
            },
            None => self.cfg.limits,
        };
        let limit = limits.max_packet_size as usize + INBUF_SLACK;
        let Some(conn) = self.conn(c) else {
            return flow::Stop::Gone;
        };
        // Decoded in place, consumed once at the end: a held input (ADR-269)
        // can be a megabyte of small packets.
        let buf = conn.inbuf.take();
        let mut off = 0usize;
        let mut keep = true;
        let stop = loop {
            let Some(conn) = self.conns.get(c) else {
                break flow::Stop::Gone;
            };
            if conn.close.is_some() {
                break flow::Stop::Gone;
            }
            if conn.flow & flow::PAUSED != 0 {
                break flow::Stop::Paused;
            }
            if off >= budget {
                break flow::Stop::Budget;
            }
            let rest = buf.get(off..).unwrap_or(&[]);
            match decode(rest, &limits) {
                Ok((packet, used)) => {
                    self.handle(c, packet, now_ms);
                    off += used;
                }
                Err(CodecError::Incomplete(_)) => {
                    if rest.len() > limit
                        && let Some(conn) = self.conn(c)
                    {
                        conn.close = Some(CloseReason::ProtocolError);
                    }
                    break flow::Stop::Incomplete;
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
                    keep = false;
                    break flow::Stop::Gone;
                }
                Err(_) => {
                    self.mark_close(c, CloseReason::ProtocolError);
                    keep = false;
                    break flow::Stop::Gone;
                }
            }
        };
        if keep && let Some(conn) = self.conn(c) {
            let mut buf = buf;
            buf.drain(..off.min(buf.len()));
            // Idle connections keep no buffer (M15).
            conn.inbuf.set(buf);
        }
        stop
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
        self.flow_forget(c);
        if conn.session.is_some() {
            self.online = self.online.saturating_sub(1);
        }
        if conn.close != Some(CloseReason::ClientDisconnect)
            && let Some(w) = conn.extra.and_then(|e| e.will)
        {
            self.stats.wills_published += 1;
            self.route(&w.msg, w.qos, w.retain.then_some(&*w.owner), None);
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
                    // in-flight first (older, with their packet ids), then
                    // the queue, then the QoS 2 ids of unfinished flows.
                    if s.persisted {
                        let cid = s.client_id.clone();
                        let mut ops = alloc::vec![PersistOp::QueueClear {
                            client_id: cid.clone(),
                        }];
                        for f in s.inflight() {
                            ops.push(match (&f.msg, f.flow) {
                                (Some(msg), flow) => PersistOp::QueuePush {
                                    client_id: cid.clone(),
                                    msg: msg.clone(),
                                    qos: flow.qos(),
                                    pid: Some(f.pid),
                                },
                                (None, _) => PersistOp::Qos2 {
                                    client_id: cid.clone(),
                                    id: Qos2Id::Released(f.pid),
                                },
                            });
                        }
                        for (msg, qos, _) in s.pending.iter().flat_map(|p| p.queue.iter()) {
                            ops.push(PersistOp::QueuePush {
                                client_id: cid.clone(),
                                msg: msg.clone(),
                                qos: *qos,
                                pid: None,
                            });
                        }
                        for &pid in s.received() {
                            ops.push(PersistOp::Qos2 {
                                client_id: cid.clone(),
                                id: Qos2Id::Received(pid),
                            });
                        }
                        for op in ops {
                            self.emit(op);
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
            // A connection whose input is held for back-pressure is alive:
            // its PINGREQ waits in the held bytes (ADR-269).
            if k.close.is_none()
                && k.flow == 0
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
            Packet::PubRec(id) => self.on_pubrec(c, id),
            Packet::PubRel(id) => self.on_pubrel(c, id),
            Packet::PubComp(id) => self.on_pubcomp(c, id),
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
            // Server-to-client packet types from a client are protocol errors.
            Packet::ConnAck(_) | Packet::SubAck(_) | Packet::UnsubAck(_) | Packet::PingResp => {
                self.mark_close(c, CloseReason::ProtocolError)
            }
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
        // A plaintext connection (P1, ADR-230): the identity is what its login
        // established and its client id is free. Taken here; cleared below.
        // (A WebSocket password connection, ADR-272, is the same with its own
        // policy and session prefix.)
        let login = self.conn(c).and_then(|k| k.login());
        let plain_conn = login.is_some();
        // A certificate identity becomes a topic level (`{id}`), so it may not
        // hold `/`, `+`, `#` or start with `$`. A plaintext client id is only the
        // tail of a session name (mosquitto's own default, `mosqpub/4711-host`,
        // has a slash): anything will do, and nothing too (the broker names a
        // clean session that brings no id, 3.1.3.1).
        let usable = if plain_conn {
            !p.client_id.is_empty() || p.clean_session
        } else {
            Self::valid_identity(p.client_id)
        };
        if !usable {
            return self.reject(c, ConnectReturnCode::IdentifierRejected);
        }
        let plain_id: Option<Box<str>> = self
            .conns
            .get(c)
            .and_then(|k| k.extra.as_ref())
            .filter(|e| e.plain || e.web)
            .and_then(|e| e.identity.clone());
        if plain_conn && plain_id.is_none() {
            return self.reject(c, ConnectReturnCode::NotAuthorized);
        }
        // PROMPT §7.1: the client id must equal the certificate identity.
        let mismatch = !plain_conn
            && self
                .conns
                .get(c)
                .and_then(|k| k.extra.as_ref()?.identity.as_deref())
                .is_some_and(|id| id != p.client_id);
        if mismatch {
            return self.reject(c, ConnectReturnCode::IdentifierRejected);
        }
        let bootstrap = self
            .conns
            .get(c)
            .and_then(|k| k.extra.as_ref())
            .is_some_and(|e| e.bootstrap);
        // The operator role needs a certificate: a client id alone (the dev
        // plaintext port) never earns it (O1, O2).
        let authenticated = self
            .conns
            .get(c)
            .and_then(|k| k.extra.as_ref())
            .is_some_and(|e| e.identity.is_some());
        // Checked: the session keeps the (equal) client id, so the
        // connection's copy is freed (M15).
        if let Some(k) = self.conn(c)
            && let Some(e) = &mut k.extra
        {
            e.identity = None;
            e.bootstrap = false;
            k.release_extra();
        }
        // A bootstrap session is never persistent: it holds nothing worth
        // keeping and must not leave state behind (H1).
        if bootstrap && !p.clean_session {
            return self.reject(c, ConnectReturnCode::NotAuthorized);
        }
        // Nor is a plaintext session: nothing of it is kept once it is over, so
        // a client that asks for a stored session is told it cannot have one.
        if plain_conn && !p.clean_session {
            return self.reject(c, ConnectReturnCode::NotAuthorized);
        }
        let role = if let Some(r) = login {
            r
        } else if bootstrap {
            Role::Bootstrap
        } else {
            match self.cfg.acl.role(p.client_id) {
                Role::Operator if !authenticated => Role::Device,
                r => r,
            }
        };
        let (boot_key, plain_key);
        let key: &str = if let Some(id) = plain_id.as_deref() {
            let tail = if p.client_id.is_empty() {
                self.plain_seq += 1;
                alloc::format!("auto-{}", self.plain_seq)
            } else {
                p.client_id.into()
            };
            plain_key = if login == Some(Role::Web) {
                web_session_key(id, &tail)
            } else {
                plain_session_key(id, &tail)
            };
            &plain_key
        } else if bootstrap {
            boot_key = alloc::format!("{BOOTSTRAP_KEY}{}", p.client_id);
            &boot_key
        } else {
            p.client_id
        };
        // The name the ACL's `{id}` stands for: the certificate's identity (the
        // client id, equal to it), or the login's for a plaintext client.
        let acl_name: &str = plain_id.as_deref().unwrap_or(p.client_id);
        let will = match &p.will {
            // A will is published by the broker on the client's behalf: it
            // must never be a way into `$SYS/` (the console input).
            Some(w) if acl::sys(w.topic) || !self.cfg.may_publish(role, acl_name, w.topic) => {
                return self.reject(c, ConnectReturnCode::NotAuthorized);
            }
            Some(w) => Some(Will {
                msg: Arc::new(MsgInner {
                    topic: w.topic.into(),
                    payload: w.payload.into(),
                }),
                qos: w.qos,
                retain: w.retain && self.cfg.may_retain(role),
                owner: acl_name.into(),
            }),
            None => None,
        };

        // Session takeover (§3.1.4): the existing connection is closed.
        let existing = self.find_session(key);
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
        let sid = match self.find_session(key) {
            Some(sid) => sid,
            None => self.create_session(key, role, p.clean_session, now_ms),
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
            // A restored session was created without the certificate.
            s.role = role;
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
            self.online += 1;
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
            tokens: match self.cfg.login_policy(role) {
                Some(p) => p.rate_tokens,
                None => self.cfg.rate_tokens,
            },
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
        self.subs_total = self.subs_total.saturating_sub(s.subs.len());
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
        let (mut rate, mut period) = (
            self.cfg.rate_tokens,
            u64::from(self.cfg.rate_period_ms.max(1)),
        );
        let (plain, web) = (self.cfg.plain, self.cfg.web);
        let Some(s) = self.session(sid) else {
            return false;
        };
        // A login session has a publish rate of its own (P1, ADR-272).
        let policy = match s.role {
            Role::Plain => plain,
            Role::Web => web,
            _ => None,
        };
        if let Some(p) = policy {
            (rate, period) = (p.rate_tokens, u64::from(p.rate_period_ms.max(1)));
        }
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
        // §3.3.5: an unauthorised publish is acknowledged and dropped. At
        // QoS 2 the id is kept until PUBREL whatever happens to the message
        // (ADR-271, method B): a duplicate is answered and never routed, and
        // a refused message completes its handshake like an accepted one.
        match (p.qos, p.packet_id) {
            (QoS::ExactlyOnce, Some(id)) => {
                let limit = self.qos2_id_limit();
                let Some(s) = self.session(sid) else { return };
                if s.received().contains(&id) {
                    self.stats.qos2_duplicates += 1;
                    return self.send(c, &Packet::PubRec(id));
                }
                if s.received().len() >= limit {
                    self.stats.qos2_inbound_full += 1;
                    return self.mark_close(c, CloseReason::ProtocolError);
                }
                s.pending_mut().received.push(id);
                self.stats.qos2_received += 1;
                self.send(c, &Packet::PubRec(id));
            }
            (_, Some(id)) => self.send(c, &Packet::PubAck(id)),
            (_, None) => {}
        }
        let Some((role, allowed)) = self
            .session(sid)
            .map(|s| (s.role, Box::<str>::from(s.acl_id())))
        else {
            return;
        };
        // H1: the reserved namespace bypasses routing entirely. Only an
        // operational control identity reaches the control handler, and
        // only on the exact control topic; everything else is dropped.
        if acl::reserved(p.topic) {
            // (Not a plaintext client, whatever its name: P1.)
            let control = !matches!(role, Role::Bootstrap | Role::Plain | Role::Web)
                && p.topic == CONTROL_TOPIC
                && self.cfg.control_ids.iter().any(|id| **id == *allowed);
            if control && self.control.len() < MAX_CONTROL_BACKLOG {
                self.stats.control_received += 1;
                self.control.push(ControlMsg {
                    from: allowed,
                    payload: p.payload.into(),
                });
            } else {
                self.stats.dropped_control += 1;
            }
            return;
        }
        // O1, O2: `$SYS/` belongs to operators. What they publish there is
        // a request to the kernel, never routed and never retained.
        if acl::sys(p.topic) {
            if !self.cfg.may_publish(role, &allowed, p.topic) {
                self.stats.dropped_acl += 1;
            } else if !self.take_token(sid, now_ms) || self.sys_in.len() >= sys::MAX_REQUESTS {
                self.stats.dropped_sys += 1;
            } else {
                let kind = if p.topic == sys::QUERY_INFO {
                    SysKind::Query
                } else {
                    SysKind::Console
                };
                self.sys_in.push(SysRequest {
                    kind,
                    from: allowed,
                    payload: p.payload.into(),
                });
            }
            return;
        }
        if !self.cfg.may_publish(role, &allowed, p.topic) {
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
        // A retained publish of a plaintext client is delivered but not
        // retained unless the configuration allows it (P1).
        let retain = p.retain && self.cfg.may_retain(role);
        let to = self.route(&msg, p.qos, retain.then_some(&*allowed), Some(c));
        self.after_publish(c, to, now_ms);
    }

    /// Delivers `msg` to every matching subscriber; retains it for `owner`
    /// if asked and within the limits. Other shards retain it only if this
    /// one did.
    fn route(
        &mut self,
        msg: &Msg,
        qos: QoS,
        retain_for: Option<&str>,
        origin: Option<ConnId>,
    ) -> flow::Recipients {
        let retain = retain_for.is_some_and(|o| self.retain(msg, qos, o));
        if self.cfg.fanout {
            self.routes.push((msg.clone(), qos, retain, origin));
        }
        self.route_local(msg, qos, retain, true)
    }

    /// Retains `msg` for `owner` here, within the per-identity limit and
    /// the byte budget (H3, H0-W1). A refused message is still delivered,
    /// just not retained: MQTT 3.1.1 has no way to refuse it.
    fn retain(&mut self, msg: &Msg, qos: QoS, owner: &str) -> bool {
        let old = self.topics.retained_at(&msg.topic);
        let old_cost = old.map_or(0, |(c, _)| c);
        let replaces_own = old.and_then(|(_, o)| o) == Some(owner);
        if !msg.payload.is_empty() {
            let held = self.retained_by.get(owner).copied().unwrap_or(0) as usize;
            if !replaces_own && held >= self.cfg.max_retained_per_device {
                self.stats.retained_refused_device += 1;
                return false;
            }
            let cost = topics::retained_cost(&msg.topic, msg.payload.len());
            if self.device_retained_bytes() - old_cost + cost > self.cfg.max_retained_bytes {
                self.stats.retained_refused_bytes += 1;
                return false;
            }
        }
        self.store_retained(msg, qos, Some(owner));
        self.emit(PersistOp::Retain {
            msg: msg.clone(),
            qos,
        });
        true
    }

    /// Sets or clears the retained message, keeping the per-identity
    /// counts of this shard right (a replica from another shard clears the
    /// local owner of what it replaces).
    fn store_retained(&mut self, msg: &Msg, qos: QoS, owner: Option<&str>) {
        let new_owner = (!msg.payload.is_empty()).then_some(owner).flatten();
        let old = self
            .topics
            .set_retained(&msg.topic, msg.clone(), qos, new_owner);
        if let Some(Some(o)) = old
            && let Some(n) = self.retained_by.get_mut(&o)
        {
            *n -= 1;
            if *n == 0 {
                self.retained_by.remove(&o);
            }
        }
        if let Some(o) = new_owner {
            *self.retained_by.entry(o.into()).or_insert(0) += 1;
        }
    }

    fn route_local(&mut self, msg: &Msg, qos: QoS, retain: bool, origin: bool) -> flow::Recipients {
        if retain && !origin {
            // A replica of what another shard accepted (it checked the
            // limits; the shards hold the same set).
            self.store_retained(msg, qos, None);
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
        let to = flow::Recipients {
            n: subs.len(),
            one: match subs.as_slice() {
                [(sid, sub_qos)] => Some((*sid, qos.min(*sub_qos))),
                _ => None,
            },
        };
        self.scratch = subs;
        to
    }

    /// The next packet id not in flight (the window is far below 65 535).
    fn alloc_pid(s: &mut Session) -> u16 {
        loop {
            let id = s.next_pid;
            s.next_pid = s.next_pid.checked_add(1).unwrap_or(1);
            if !s.inflight().iter().any(|f| f.pid == id) {
                return id;
            }
        }
    }

    /// Puts `msg` into flight at `qos` (1 or 2) with a new packet id.
    fn start_flight(s: &mut Session, msg: &Msg, qos: QoS, retain: bool) -> u16 {
        let pid = Self::alloc_pid(s);
        let flow = if qos == QoS::ExactlyOnce {
            Flow::Pubrec
        } else {
            Flow::Puback
        };
        s.pending_mut().inflight.push(Flight {
            pid,
            flow,
            retain,
            msg: Some(msg.clone()),
        });
        pid
    }

    fn deliver(&mut self, sid: SessionId, msg: &Msg, qos: QoS, retain: bool) {
        enum Action {
            Send0(ConnId),
            Send(ConnId, u16),
            Queue,
            Drop,
            DropOffline,
        }
        let max_inflight = self.cfg.max_inflight;
        let max_queued = self.cfg.max_queued;
        let max_out = self.cfg.max_outbound_bytes;
        let Some(conn) = self.sessions.get(sid).map(|s| s.conn()) else {
            return;
        };
        let allow = self.flow_allow;
        let room = conn
            .and_then(|c| Some((c, self.conns.get(c)?)))
            .is_some_and(|(c, k)| {
                k.close.is_none()
                    && (k.outbuf.len() < max_out
                        || allow.is_some_and(|(a, cap)| a == c && k.outbuf.len() < cap))
            });
        let Some(s) = self.session(sid) else { return };
        let action = match (qos, conn) {
            (QoS::AtMostOnce, Some(c)) if room => Action::Send0(c),
            (QoS::AtMostOnce, Some(_)) => Action::Drop,
            (QoS::AtMostOnce, None) => Action::DropOffline,
            (_, Some(c)) if room && s.inflight().len() < max_inflight && (s.queue_len() == 0) => {
                Action::Send(c, Self::start_flight(s, msg, qos, retain))
            }
            // Offline persistent session, full window or backpressure.
            (_, Some(_)) => Action::Queue,
            (_, None) if !s.clean => Action::Queue,
            (_, None) => Action::DropOffline,
        };
        match action {
            Action::Send0(c) => self.send_publish(c, msg, QoS::AtMostOnce, None, retain, false),
            Action::Send(c, pid) => self.send_publish(c, msg, qos, Some(pid), retain, false),
            Action::Queue => {
                let mut stored = None;
                if let Some(s) = self.session(sid) {
                    if s.queue_len() >= max_queued {
                        self.stats.dropped_queue_full += 1;
                    } else {
                        s.pending_mut().queue.push_back((msg.clone(), qos, retain));
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
                        qos,
                        pid: None,
                    });
                }
            }
            Action::Drop => self.stats.dropped_backpressure += 1,
            Action::DropOffline => self.stats.dropped_offline += 1,
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

    /// Re-sends what is in flight, in the order it was first sent (4.4):
    /// unacknowledged PUBLISHes with DUP set and their original packet ids,
    /// and the PUBRELs of QoS 2 flows awaiting PUBCOMP.
    fn resend_inflight(&mut self, sid: SessionId) {
        let Some(s) = self.session(sid) else { return };
        let Some(c) = s.conn() else { return };
        let pending: Vec<Flight> = s.inflight().to_vec();
        for f in pending {
            match f.msg {
                Some(msg) => self.send_publish(c, &msg, f.flow.qos(), Some(f.pid), f.retain, true),
                None => self.send(c, &Packet::PubRel(f.pid)),
            }
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
            let Some((msg, qos, retain)) = s.pending.as_mut().and_then(|p| p.queue.pop_front())
            else {
                return;
            };
            let pid = Self::start_flight(s, &msg, qos, retain);
            self.send_publish(c, &msg, qos, Some(pid), retain, false);
        }
    }

    /// Ends the flight `pid` if it awaits `flow`'s acknowledgement; true if
    /// it did. An acknowledgement of another kind (a PUBACK for a QoS 2
    /// delivery, a PUBCOMP before the PUBREL) changes nothing.
    fn complete(&mut self, sid: SessionId, pid: u16, flow: Flow) -> bool {
        let Some(s) = self.session(sid) else {
            return false;
        };
        let mut done = false;
        if let Some(p) = s.pending.as_mut()
            && let Some(i) = p
                .inflight
                .iter()
                .position(|f| f.pid == pid && f.flow == flow)
        {
            p.inflight.remove(i);
            done = true;
        }
        s.release_pending();
        done
    }

    fn on_puback(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if self.complete(sid, pid, Flow::Puback) {
            self.pump(sid);
        }
    }

    /// The client has the QoS 2 message (4.3.3): it is released, the
    /// PUBREL goes out, the id stays in flight until PUBCOMP. A PUBREC for
    /// an id already released or unknown (state lost) is answered with
    /// PUBREL as well, so the client can complete; one for a QoS 1 flight
    /// is ignored.
    fn on_pubrec(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        let Some(s) = self.session(sid) else { return };
        let flight = s
            .pending
            .as_mut()
            .and_then(|p| p.inflight.iter_mut().find(|f| f.pid == pid));
        match flight {
            Some(f) if f.flow == Flow::Puback => return,
            Some(f) => {
                f.flow = Flow::Pubcomp;
                f.msg = None;
            }
            None => {}
        }
        self.send(c, &Packet::PubRel(pid));
    }

    /// The client releases a QoS 2 message it sent (4.3.3): the id is
    /// forgotten and PUBCOMP sent, also for an id not held (a PUBREL sent
    /// again after our PUBCOMP was lost).
    fn on_pubrel(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if let Some(s) = self.session(sid) {
            if let Some(p) = s.pending.as_mut() {
                p.received.retain(|&x| x != pid);
            }
            s.release_pending();
        }
        self.send(c, &Packet::PubComp(pid));
    }

    fn on_pubcomp(&mut self, c: ConnId, pid: u16) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        if self.complete(sid, pid, Flow::Pubcomp) {
            self.stats.qos2_completed += 1;
            self.pump(sid);
        }
    }

    fn on_subscribe(&mut self, c: ConnId, packet_id: u16, topics: &[(&str, QoS)]) {
        let Some(sid) = self.conn(c).and_then(|k| k.session) else {
            return;
        };
        let cfg = self.cfg;
        let mut codes: Vec<u8> = Vec::with_capacity(topics.len());
        let mut granted: Vec<(&str, QoS)> = Vec::new();
        for &(filter, want) in topics {
            let Some(s) = self.sessions.get(sid) else {
                return;
            };
            let qos = want;
            if !cfg.may_subscribe(s.role, s.acl_id(), filter) || !self.add_sub(sid, filter, qos) {
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
            // The console's last lines (O2), as live messages.
            if acl::sys(filter) && urmqtt_mqtt::topic_matches(filter, sys::CONSOLE_OUT) {
                let lines: Vec<Msg> = self.console.iter().cloned().collect();
                for msg in lines {
                    self.deliver(sid, &msg, QoS::AtMostOnce, false);
                }
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
