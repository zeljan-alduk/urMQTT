//! Stateful ACL model for the broker (H5): a structured sequence of
//! operations from several identities is applied to a [`Broker`] and an
//! independent oracle checks the invariants after every step.
//!
//! Shared by the deterministic proptest (`tests/acl_invariants.rs`, part of
//! `make check`) and the cargo-fuzz target `broker_acl`
//! (`fuzz/fuzz_targets/broker_acl.rs`), so a fuzz finding replays as a
//! unit test and every fuzz seed doubles as a regression test.
//!
//! The oracle does not use `urmqtt_broker::acl`: the rights of each
//! identity are written out again below as predicates over topic levels
//! ([`may_pub`], [`may_sub_topic`]), and filters are judged by enumerating
//! a finite universe of topics ([`filter_allowed`]) rather than by the
//! broker's `covers`. What it checks, after each step:
//!
//! 1. A publish is accepted (`stats.published`) iff the publisher's rights
//!    cover its topic; otherwise it is counted as dropped and never routed.
//! 2. The reserved `$urmqtt/` namespace reaches the control queue only from
//!    an operational control identity on the exact control topic, never
//!    from a bootstrap session of the same name, and routes nowhere.
//! 3. Everything an identity receives lies inside its subscribe rights,
//!    matches a filter its session was granted, and was published by
//!    someone allowed to (or is a will registered by an allowed owner). In
//!    particular no device receives another device's topics.
//! 4. A SUBACK grants a filter only if every topic it can match is inside
//!    the subscriber's rights.
//! 5. CONNACK codes (identity spoofing, bootstrap rules, will rights) and
//!    `session_present` follow the session model; RETAIN is set only on
//!    the replay after a SUBSCRIBE; in-flight QoS 1 and 2 stay within the
//!    window; retained state stays within the configured limits.
//! 6. QoS 2 (ADR-271): a PUBLISH whose id the session still holds (no
//!    PUBREL yet, across reconnects, takeovers and a restore) is answered
//!    with PUBREC and neither routed nor counted again; one id too many
//!    closes the connection; every PUBREC answers an id the session holds
//!    and every PUBREL is answered with PUBCOMP. Outbound, a message is
//!    delivered to a session in one flow only: it is sent again only with
//!    DUP and the same id, and never after the client's PUBREC; a PUBREL
//!    comes only after our PUBREC.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use std::sync::Arc;

use std::collections::BTreeMap;

use urmqtt_broker::{
    Acl, Broker, CONTROL_TOPIC, CloseReason, Config, ConnId, MIN_QOS2_IDS, MsgInner, Qos2Id, Stats,
    StoredMsg,
};
use urmqtt_mqtt::{
    Connect, Error, Limits, Packet, Publish, QoS, Subscribe, SubscribeTopics, Unsubscribe,
    UnsubscribeTopics, Will, decode, encode, encoded_len,
};

// ---- configuration under test ------------------------------------------

/// The patterns that grant `$urmqtt/#` and `$SYS/#` are a deliberate
/// misconfiguration: the reserved namespace must stay closed, and `$SYS/`
/// closed to everyone but an operator, whatever the patterns say. No
/// operator is configured here: the operator role and `$SYS/` requests are
/// the subject of `tests/acl_model.rs`.
pub const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#", "fleet/hello", "$urmqtt/#", "$SYS/#"],
    device_subscribe: &["devices/{id}/cmd/#", "fleet/all", "$urmqtt/#", "$SYS/#"],
    service_ids: &["svc", "exp", "sx-*"],
    service_publish: &["devices/+/cmd/#", "fleet/#", "$urmqtt/#", "$SYS/#"],
    service_subscribe: &[
        "devices/+/telemetry/#",
        "devices/+/state/+",
        "fleet/#",
        "$urmqtt/#",
        "$SYS/#",
    ],
    operator_ids: &[],
};

pub const MAX_INFLIGHT: usize = 2;
/// QoS 2 ids a session may hold awaiting PUBREL.
pub const QOS2_IDS: usize = if MAX_INFLIGHT > MIN_QOS2_IDS {
    MAX_INFLIGHT
} else {
    MIN_QOS2_IDS
};
pub const MAX_SUBS: usize = 4;
pub const MAX_RETAINED_PER_DEVICE: usize = 2;
pub const MAX_RETAINED_BYTES: usize = 600;

pub fn config() -> Config {
    Config {
        limits: Limits {
            max_packet_size: 1024,
            max_topic_len: 64,
            max_topic_levels: 8,
            max_client_id_len: 23,
            max_topics_per_packet: 4,
        },
        max_connections: 8,
        max_subscriptions_per_session: MAX_SUBS,
        max_inflight: MAX_INFLIGHT,
        max_queued: 3,
        max_retained_per_device: MAX_RETAINED_PER_DEVICE,
        max_retained_bytes: MAX_RETAINED_BYTES,
        // The rate limit is not under test here: never reached.
        rate_tokens: 1_000_000,
        rate_period_ms: 1000,
        max_outbound_bytes: 16 * 1024,
        acl: ACL,
        persist: true,
        telemetry: &["devices/+/telemetry/#"],
        fanout: true,
        control_ids: &["svc"],
        // No plaintext listener: every connection here has a TLS identity.
        plain: None,
        web: None,
    }
}

// ---- the oracle's own statement of the rights --------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Device,
    Service,
    Bootstrap,
}

/// Identities a connection can be bound to (the TLS layer's job): two
/// devices, a control service, a service without control rights, and
/// bootstrap certificates named like a device and like the control service.
pub const WHO: [(&str, Kind); 10] = [
    ("d1", Kind::Device),
    ("d2", Kind::Device),
    ("svc", Kind::Service),
    ("exp", Kind::Service),
    ("d1", Kind::Bootstrap),
    ("svc", Kind::Bootstrap),
    // A service by prefix pattern, and a device just short of it.
    ("sx-1", Kind::Service),
    ("sx", Kind::Device),
    // Identities that would be topic levels with wildcards or separators.
    ("+", Kind::Device),
    ("a/b", Kind::Device),
];

/// Identities the broker must refuse at CONNECT: they would become topic
/// levels (`{id}`) with a wildcard, a separator or the reserved prefix.
pub fn invalid_identity(id: &str) -> bool {
    id.is_empty() || id.contains(['/', '+', '#']) || id.starts_with('$')
}

fn levels(t: &str) -> Vec<&str> {
    t.split('/').collect()
}

pub fn is_reserved(topic: &str) -> bool {
    levels(topic)[0] == "$urmqtt"
}

/// `$SYS/`: closed to every identity here (no operator is configured).
pub fn is_sys(topic: &str) -> bool {
    levels(topic)[0] == "$SYS"
}

/// May the identity publish to `topic`?
pub fn may_pub(kind: Kind, id: &str, topic: &str) -> bool {
    let l = levels(topic);
    if l[0] == "$urmqtt" || l[0] == "$SYS" {
        return false;
    }
    match kind {
        Kind::Device => {
            (l.len() >= 2 && l[0] == "devices" && l[1] == id) || l == ["fleet", "hello"]
        }
        Kind::Service => (l.len() >= 3 && l[0] == "devices" && l[2] == "cmd") || l[0] == "fleet",
        Kind::Bootstrap => l.len() >= 2 && l[0] == "provision" && l[1] == id,
    }
}

/// May the identity receive messages on `topic` (the subscribe rights)?
pub fn may_sub_topic(kind: Kind, id: &str, topic: &str) -> bool {
    let l = levels(topic);
    if l[0] == "$urmqtt" || l[0] == "$SYS" {
        return false;
    }
    match kind {
        Kind::Device => {
            (l.len() >= 3 && l[0] == "devices" && l[1] == id && l[2] == "cmd")
                || (l.len() == 2 && l[0] == "fleet" && l[1] == "all")
        }
        Kind::Service => {
            (l.len() >= 3 && l[0] == "devices" && l[2] == "telemetry")
                || (l.len() == 4 && l[0] == "devices" && l[2] == "state")
                || l[0] == "fleet"
        }
        Kind::Bootstrap => l.len() >= 2 && l[0] == "provision" && l[1] == id,
    }
}

/// Plain MQTT matching of a topic by a filter.
pub fn matches(filter: &str, topic: &str) -> bool {
    let f = levels(filter);
    let t = levels(topic);
    let mut i = 0;
    loop {
        match (f.get(i), t.get(i)) {
            (Some(&"#"), _) => return true,
            (Some(&"+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
        i += 1;
    }
}

/// Topics up to four levels over the alphabet the generators draw from.
fn universe() -> &'static Vec<String> {
    // A process-wide lazy static, not a leaked Box per thread: LeakSanitizer
    // (scripts/sanitize.sh) reported the leak.
    static U: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        const A: [&str; 13] = [
            "devices",
            "d1",
            "d2",
            "cmd",
            "fleet",
            "all",
            "provision",
            "$urmqtt",
            "$SYS",
            "x",
            "telemetry",
            "state",
            "hello",
        ];
        let mut all: Vec<String> = Vec::new();
        let mut cur: Vec<Vec<&str>> = vec![vec![]];
        for _ in 0..4 {
            let mut next = Vec::new();
            for p in &cur {
                for a in A {
                    let mut q = p.clone();
                    q.push(a);
                    all.push(q.join("/"));
                    next.push(q);
                }
            }
            cur = next;
        }
        all
    });
    &U
}

type FilterCache = RefCell<HashMap<(u8, String, String), bool>>;

/// Every topic `filter` can match is inside the identity's subscribe rights.
pub fn filter_allowed(kind: Kind, id: &str, filter: &str) -> bool {
    thread_local! {
        static CACHE: FilterCache = RefCell::new(HashMap::new());
    }
    let key = (kind as u8, id.to_string(), filter.to_string());
    if let Some(v) = CACHE.with(|c| c.borrow().get(&key).copied()) {
        return v;
    }
    let ok = universe()
        .iter()
        .all(|t| !matches(filter, t) || may_sub_topic(kind, id, t));
    CACHE.with(|c| c.borrow_mut().insert(key, ok));
    ok
}

// ---- operations ----------------------------------------------------------

pub const SLOTS: usize = 4;

#[derive(Clone, Debug)]
pub enum Op {
    Connect {
        slot: usize,
        who: usize,
        /// The CONNECT client id: another identity's means spoofing.
        claim: usize,
        clean: bool,
        will: Option<(String, bool, QoS)>,
    },
    Publish {
        slot: usize,
        topic: String,
        qos: QoS,
        retain: bool,
        empty: bool,
        extra: usize,
    },
    Subscribe {
        slot: usize,
        filters: Vec<(String, QoS)>,
    },
    Unsubscribe {
        slot: usize,
        filters: Vec<String>,
    },
    /// Acknowledges every delivery in flight: PUBACK (QoS 1), PUBREC (QoS 2
    /// not yet received), PUBCOMP (QoS 2 after the broker's PUBREL).
    Ack {
        slot: usize,
    },
    /// Sends PUBREL for every QoS 2 id the slot's session holds.
    Release {
        slot: usize,
    },
    /// Sends again, with DUP, the QoS 2 PUBLISH of an id the session holds.
    Dup {
        slot: usize,
    },
    Disconnect {
        slot: usize,
    },
    /// The transport drops without DISCONNECT.
    Drop {
        slot: usize,
    },
    Tick {
        ms: u64,
    },
    Ping {
        slot: usize,
    },
    /// The store hands back a persistent session (startup).
    Restore {
        who: usize,
        subs: Vec<(String, QoS)>,
        queued: usize,
        /// The queued messages are QoS 2.
        qos2: bool,
        /// QoS 2 ids received from the client, awaiting its PUBREL: 1..=n.
        ids: u16,
    },
    /// The store hands back a retained message.
    RestoreRetained {
        topic: String,
    },
    /// The identity left the allowlist: its connections are closed.
    Revoke {
        who: usize,
    },
    /// Another shard routed a message here.
    Remote {
        topic: String,
        qos: QoS,
    },
    Garbage {
        slot: usize,
        bytes: Vec<u8>,
    },
}

const TOPICS: [&str; 26] = [
    "fleet/hello",
    "fleet/hello/x",
    "devices/d1/telemetry/t",
    "devices/d1",
    "devices/d1/cmd/reboot",
    "devices/d2/telemetry/t",
    "devices/d2/cmd/reboot",
    "devices/d2/cmd",
    "devices/d1/cmd",
    "devices/x/cmd/y",
    "devices/d1/state",
    "devices",
    "devices//cmd/x",
    "fleet/all",
    "fleet/x/y",
    "fleet",
    "provision/d1/csr",
    "provision/svc/csr",
    "provision/d2/csr",
    "$urmqtt/control",
    "$urmqtt",
    "$urmqtt/x/y",
    "$urmqtt/control/x",
    "$SYS/broker",
    "svc/x",
    "x",
];

const FILTERS: [&str; 28] = [
    "devices/+/state/+",
    "devices/d1/telemetry/#",
    "devices/+/state/#",
    "devices/+/cmd/x",
    "#",
    "+/#",
    "devices/#",
    "devices/+/cmd/#",
    "devices/d1/cmd/#",
    "devices/d1/#",
    "devices/d1/+",
    "devices/d2/cmd/#",
    "devices/+/telemetry/#",
    "devices/d1/cmd",
    "fleet/#",
    "fleet/all",
    "fleet/+",
    "$urmqtt/#",
    "$urmqtt/control",
    "$urmqtt/+",
    "+/control",
    "provision/#",
    "provision/d1/#",
    "provision/svc/#",
    "provision/+/csr",
    "devices/+",
    "+/d1/cmd/#",
    "$SYS/#",
];

const ALPHA: [&str; 15] = [
    "devices",
    "d1",
    "d2",
    "cmd",
    "fleet",
    "all",
    "provision",
    "$urmqtt",
    "x",
    "svc",
    "",
    "+",
    "telemetry",
    "state",
    "hello",
];

struct Src<'a> {
    d: &'a [u8],
    i: usize,
}

impl Src<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }

    fn done(&self) -> bool {
        self.i >= self.d.len()
    }

    fn qos(b: u8) -> QoS {
        match b & 3 {
            1 => QoS::AtLeastOnce,
            2 => QoS::ExactlyOnce,
            _ => QoS::AtMostOnce,
        }
    }

    /// A topic name or, with `filter`, a filter: from the curated lists or
    /// built level by level (wildcards only in filters).
    fn topic(&mut self, filter: bool) -> String {
        let t = self.u8();
        if t < 128 {
            let list: &[&str] = if filter { &FILTERS } else { &TOPICS };
            return list[usize::from(t) % list.len()].to_string();
        }
        let n = 1 + usize::from(t & 3);
        let mut parts: Vec<&str> = Vec::new();
        for k in 0..n {
            let b = usize::from(self.u8());
            let sym = ALPHA[b % ALPHA.len()];
            parts.push(match sym {
                "+" if !filter => "x",
                "" if n == 1 => "x",
                s => s,
            });
            if filter && b & 0x80 != 0 && k + 1 == n {
                parts.push("#");
            }
        }
        parts.join("/")
    }
}

/// Decodes `data` into operations; short input is padded with zeros.
pub fn decode_ops(data: &[u8]) -> Vec<Op> {
    let mut s = Src { d: data, i: 0 };
    let mut ops = Vec::new();
    while !s.done() && ops.len() < 400 {
        let b0 = s.u8();
        let b1 = s.u8();
        let slot = usize::from(b1 & 3);
        let op = match b0 % 14 {
            0 => {
                let who = usize::from(b1 >> 2) % WHO.len();
                let f = s.u8();
                let claim = if f & 2 != 0 {
                    usize::from((f >> 4) & 7) % WHO.len()
                } else {
                    who
                };
                let will = (f & 4 != 0).then(|| {
                    let t = s.topic(false);
                    (t, f & 0x80 != 0, Src::qos(f >> 3))
                });
                Op::Connect {
                    slot,
                    who,
                    claim,
                    clean: f & 1 != 0,
                    will,
                }
            }
            1 => {
                let topic = s.topic(false);
                Op::Publish {
                    slot,
                    topic,
                    qos: Src::qos(b1 >> 2),
                    retain: b1 & 0x10 != 0,
                    empty: b1 & 0x20 != 0,
                    extra: usize::from(s.u8() % 32),
                }
            }
            2 => {
                let n = 1 + usize::from((b1 >> 2) & 3) % 3;
                let filters = (0..n).map(|_| (s.topic(true), Src::qos(b1 >> 4))).collect();
                Op::Subscribe { slot, filters }
            }
            3 => {
                let n = 1 + usize::from((b1 >> 2) & 3) % 2;
                Op::Unsubscribe {
                    slot,
                    filters: (0..n).map(|_| s.topic(true)).collect(),
                }
            }
            4 => Op::Ack { slot },
            5 => Op::Disconnect { slot },
            6 => Op::Drop { slot },
            7 => Op::Tick {
                ms: u64::from(s.u8()) * 500,
            },
            8 => Op::Ping { slot },
            9 if b1 & 0x30 == 0x10 => Op::Release { slot },
            9 if b1 & 0x30 == 0x20 => Op::Dup { slot },
            10 => {
                let who = usize::from(b1 >> 2) % WHO.len();
                let n = usize::from(b1 >> 6) % 3;
                let subs = (0..n).map(|_| (s.topic(true), Src::qos(b1))).collect();
                let q = s.u8();
                Op::Restore {
                    who,
                    subs,
                    queued: usize::from(q % 3),
                    qos2: q & 4 != 0,
                    ids: u16::from(q >> 4) % 4,
                }
            }
            11 => Op::RestoreRetained {
                topic: s.topic(false),
            },
            12 => Op::Revoke {
                who: usize::from(b1 >> 2) % WHO.len(),
            },
            13 => Op::Remote {
                topic: s.topic(false),
                qos: Src::qos(b1 >> 2),
            },
            _ => {
                let n = usize::from(s.u8() % 12);
                let mut bytes: Vec<u8> = (0..n).map(|_| s.u8()).collect();
                // Never a PUBLISH: the oracle knows every publish it sends.
                if let Some(b) = bytes.first_mut()
                    && *b >> 4 == 3
                {
                    *b |= 0xF0;
                }
                Op::Garbage { slot, bytes }
            }
        };
        ops.push(op);
    }
    ops
}

// ---- the harness ---------------------------------------------------------

const MAGIC: [u8; 3] = *b"ACL";

/// A message the harness sent (or registered as a will).
struct Sent {
    topic: String,
    allowed: bool,
}

struct Expect {
    code: u8,
    present: bool,
    clean: bool,
}

/// A delivery to this connection that is not complete.
#[derive(Clone, Copy, Debug)]
struct Out {
    qos: QoS,
    /// QoS 2: our PUBREC is sent.
    rec: bool,
    /// QoS 2: the broker's PUBREL arrived.
    rel: bool,
    /// The registry entry of its payload, if it has one.
    seq: Option<u32>,
}

struct Slot {
    c: ConnId,
    who: usize,
    /// Session key as the model sees it (bootstrap sessions are separate).
    key: String,
    accepted: bool,
    expect: Option<Expect>,
    inflight: BTreeMap<u16, Out>,
    /// PUBRELs sent and not yet answered with PUBCOMP.
    released: Vec<u16>,
    next_pid: u16,
    rx: Vec<u8>,
    /// Garbage may have left half a packet in the broker's input buffer.
    dirty: bool,
}

#[derive(Default)]
struct Sess {
    clean: bool,
    conn: Option<ConnId>,
    /// Every filter granted to this session since it was created: a queued
    /// message may outlive an UNSUBSCRIBE.
    granted: HashSet<String>,
    /// QoS 2 ids this client published and has not released: the broker
    /// holds exactly these (method B).
    awaiting: BTreeSet<u16>,
    /// A QoS 2 publish went out on a connection with garbage in its input
    /// buffer: what the broker holds is not known any more.
    uncertain: bool,
    /// QoS 2 deliveries to this session (not retained replays): payload
    /// registry entry -> (packet id, our PUBREC sent).
    q2: HashMap<u32, (u16, bool)>,
}

/// What a QoS 2 PUBLISH should do, by the session model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Q2 {
    /// Not QoS 2.
    No,
    /// A new id: PUBREC, then the same as QoS 1.
    Fresh,
    /// An id the session holds: PUBREC, nothing else.
    Dup,
    /// One id too many: the connection is closed, nothing else.
    Full,
    /// Not modelled (garbage before it).
    Unknown,
}

/// A packet from the broker, owned.
enum Rx {
    ConnAck(u8, bool),
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: QoS,
        pid: Option<u16>,
        retain: bool,
        dup: bool,
    },
    SubAck(Vec<u8>),
    PubRec(u16),
    PubRel(u16),
    PubComp(u16),
    Other,
}

pub struct Harness {
    pub b: Broker,
    now: u64,
    slots: [Option<Slot>; SLOTS],
    sent: Vec<Sent>,
    sessions: HashMap<String, Sess>,
    /// The SUBSCRIBE being processed: its slot and filters.
    sub: Option<(usize, Vec<(String, QoS)>)>,
    control_seen: u64,
    /// Retained messages handed back by `restore_retained` (no owner).
    restored: usize,
    /// Payloads published, willed or restored with RETAIN: the only ones a
    /// RETAIN delivery may carry.
    retained_seqs: HashSet<u32>,
    pub steps: usize,
}

fn wire(p: &Packet<'_>) -> Vec<u8> {
    let mut v = vec![0u8; encoded_len(p)];
    encode(p, &mut v).expect("encodable");
    v
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Self {
        Harness {
            b: Broker::new(config()),
            now: 0,
            slots: [None, None, None, None],
            sent: Vec::new(),
            sessions: HashMap::new(),
            sub: None,
            control_seen: 0,
            restored: 0,
            retained_seqs: HashSet::new(),
            steps: 0,
        }
    }

    /// A payload that names its registry entry.
    fn payload(&mut self, topic: &str, allowed: bool, extra: usize) -> Vec<u8> {
        let seq = self.sent.len() as u32;
        self.sent.push(Sent {
            topic: topic.to_string(),
            allowed,
        });
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&seq.to_le_bytes());
        p.resize(7 + extra, 0xEE);
        p
    }

    fn feed(&mut self, slot: usize, p: &Packet<'_>) {
        if let Some(s) = &self.slots[slot] {
            self.b.input(s.c, &wire(p), self.now);
        }
    }

    fn accepted(&self, slot: usize) -> bool {
        self.slots[slot].as_ref().is_some_and(|s| s.accepted)
    }

    /// Applies one operation, then checks every invariant.
    pub fn step(&mut self, op: &Op) {
        self.steps += 1;
        let before = self.b.stats();
        // For a PUBLISH: the model's verdict, for the counter check.
        let mut verdict: Option<(&str, bool, bool, Q2)> = None;
        match op {
            Op::Connect {
                slot,
                who,
                claim,
                clean,
                will,
            } => {
                if self.slots[*slot].is_some() {
                    return self.settle();
                }
                let (id, kind) = WHO[*who];
                let boot = kind == Kind::Bootstrap;
                let claim_id = WHO[*claim].0;
                let bad_will = will.as_ref().is_some_and(|(t, _, _)| !may_pub(kind, id, t));
                let code = if claim_id != id || invalid_identity(claim_id) {
                    2
                } else if (boot && !clean) || bad_will {
                    5
                } else {
                    0
                };
                let key = if boot {
                    format!("$bootstrap/{id}")
                } else {
                    id.to_string()
                };
                let present = code == 0 && !clean && self.sessions.contains_key(&key);
                let body = match will {
                    Some((t, retain, _)) => {
                        if *retain {
                            self.retained_seqs.insert(self.sent.len() as u32);
                        }
                        self.payload(t, true, 0)
                    }
                    None => Vec::new(),
                };
                let c = self.b.open(self.now).expect("a free connection");
                self.b.set_identity(c, id, boot);
                self.slots[*slot] = Some(Slot {
                    c,
                    who: *who,
                    key,
                    accepted: false,
                    expect: Some(Expect {
                        code,
                        present,
                        clean: *clean,
                    }),
                    inflight: BTreeMap::new(),
                    released: Vec::new(),
                    next_pid: 1,
                    rx: Vec::new(),
                    dirty: false,
                });
                let will_pkt = will.as_ref().map(|(t, retain, qos)| Will {
                    topic: t,
                    payload: &body,
                    qos: *qos,
                    retain: *retain,
                });
                self.feed(
                    *slot,
                    &Packet::Connect(Connect {
                        protocol_level: 4,
                        clean_session: *clean,
                        keep_alive: 10,
                        client_id: claim_id,
                        will: will_pkt,
                        username: None,
                        password: None,
                    }),
                );
            }
            Op::Publish {
                slot,
                topic,
                qos,
                retain,
                empty,
                extra,
            } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let s = self.slots[*slot].as_mut().expect("accepted");
                let (id, kind) = WHO[s.who];
                let dirty = s.dirty;
                let pid = if *qos == QoS::AtMostOnce {
                    None
                } else {
                    s.next_pid = s.next_pid.wrapping_add(1).max(1);
                    Some(s.next_pid)
                };
                let key = s.key.clone();
                let q2 = match (qos, pid, self.sessions.get_mut(&key)) {
                    (QoS::ExactlyOnce, Some(p), Some(sess)) => {
                        if dirty {
                            sess.uncertain = true;
                        }
                        if sess.uncertain {
                            sess.awaiting.insert(p);
                            Q2::Unknown
                        } else if sess.awaiting.contains(&p) {
                            Q2::Dup
                        } else if sess.awaiting.len() >= QOS2_IDS {
                            Q2::Full
                        } else {
                            sess.awaiting.insert(p);
                            Q2::Fresh
                        }
                    }
                    (QoS::ExactlyOnce, _, _) => Q2::Unknown,
                    _ => Q2::No,
                };
                let allowed = may_pub(kind, id, topic);
                let control = topic == CONTROL_TOPIC && kind != Kind::Bootstrap && id == "svc";
                let body = if *empty {
                    Vec::new()
                } else {
                    if *retain {
                        self.retained_seqs.insert(self.sent.len() as u32);
                    }
                    self.payload(topic, allowed, *extra)
                };
                if !dirty && q2 != Q2::Unknown {
                    verdict = Some((topic, allowed, control, q2));
                }
                self.feed(
                    *slot,
                    &Packet::Publish(Publish {
                        dup: false,
                        qos: *qos,
                        retain: *retain,
                        topic,
                        packet_id: pid,
                        payload: &body,
                    }),
                );
            }
            Op::Subscribe { slot, filters } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                self.sub = Some((*slot, filters.clone()));
                let list: Vec<(&str, QoS)> =
                    filters.iter().map(|(f, q)| (f.as_str(), *q)).collect();
                self.feed(
                    *slot,
                    &Packet::Subscribe(Subscribe {
                        packet_id: 7,
                        topics: SubscribeTopics::List(&list),
                    }),
                );
            }
            Op::Unsubscribe { slot, filters } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let list: Vec<&str> = filters.iter().map(String::as_str).collect();
                self.feed(
                    *slot,
                    &Packet::Unsubscribe(Unsubscribe {
                        packet_id: 9,
                        topics: UnsubscribeTopics::List(&list),
                    }),
                );
            }
            Op::Ack { slot } => {
                let mut acks = Vec::new();
                if let Some(s) = self.slots[*slot].as_mut() {
                    let key = s.key.clone();
                    // Garbage may have left half a packet in the broker's input
                    // buffer: then our PUBREC may never be read as one.
                    let dirty = s.dirty;
                    for (&p, o) in s.inflight.iter_mut() {
                        match (o.qos, o.rec, o.rel) {
                            (QoS::ExactlyOnce, false, _) => {
                                o.rec = true;
                                // Our PUBREC: the PUBLISH may not come again.
                                if !dirty
                                    && let Some(seq) = o.seq
                                    && let Some(e) =
                                        self.sessions.get_mut(&key).and_then(|x| x.q2.get_mut(&seq))
                                {
                                    e.1 = true;
                                }
                                acks.push(Packet::PubRec(p));
                            }
                            (QoS::ExactlyOnce, true, true) => acks.push(Packet::PubComp(p)),
                            (QoS::ExactlyOnce, true, false) => {}
                            _ => acks.push(Packet::PubAck(p)),
                        }
                    }
                    s.inflight
                        .retain(|_, o| o.qos == QoS::ExactlyOnce && !(o.rec && o.rel));
                }
                for a in acks {
                    self.feed(*slot, &a);
                }
            }
            Op::Release { slot } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let s = self.slots[*slot].as_mut().expect("accepted");
                let dirty = s.dirty;
                let ids: Vec<u16> = self
                    .sessions
                    .get_mut(&s.key)
                    .map(|x| {
                        // Behind garbage our PUBRELs may never be read as such:
                        // what the broker still holds is not known any more.
                        x.uncertain |= dirty;
                        std::mem::take(&mut x.awaiting).into_iter().collect()
                    })
                    .unwrap_or_default();
                s.released.extend(&ids);
                for p in ids {
                    self.feed(*slot, &Packet::PubRel(p));
                }
            }
            Op::Dup { slot } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let s = self.slots[*slot].as_ref().expect("accepted");
                let (dirty, key) = (s.dirty, s.key.clone());
                let Some(sess) = self.sessions.get(&key) else {
                    return self.settle();
                };
                let Some(&p) = sess.awaiting.iter().next() else {
                    return self.settle();
                };
                let uncertain = sess.uncertain;
                let topic = TOPICS[2];
                // Never deliverable: a duplicate is never routed.
                let body = self.payload(topic, false, 1);
                if !dirty && !uncertain {
                    verdict = Some((topic, false, false, Q2::Dup));
                }
                self.feed(
                    *slot,
                    &Packet::Publish(Publish {
                        dup: true,
                        qos: QoS::ExactlyOnce,
                        retain: false,
                        topic,
                        packet_id: Some(p),
                        payload: &body,
                    }),
                );
            }
            Op::Disconnect { slot } => self.feed(*slot, &Packet::Disconnect),
            Op::Drop { slot } => {
                self.collect();
                if let Some(s) = self.slots[*slot].take() {
                    self.close_model(&s);
                    self.b.closed(s.c, self.now);
                }
            }
            Op::Tick { ms } => {
                self.now += ms;
                self.b.tick(self.now);
                if *ms == 0 {
                    self.b.shrink();
                }
            }
            Op::Restore {
                who,
                subs,
                queued,
                qos2,
                ids,
            } => {
                let (id, kind) = WHO[*who];
                if kind == Kind::Bootstrap {
                    return self.settle();
                }
                let want = !invalid_identity(id) && !self.sessions.contains_key(id);
                // What the store holds was delivered under the rules before.
                let msgs: Vec<(String, Vec<u8>)> = TOPICS
                    .iter()
                    .filter(|t| may_sub_topic(kind, id, t))
                    .take(*queued)
                    .map(|t| (t.to_string(), self.payload(t, true, 0)))
                    .collect();
                let qos = if *qos2 {
                    QoS::ExactlyOnce
                } else {
                    QoS::AtLeastOnce
                };
                let ok = self.b.restore_session(
                    id,
                    subs.iter().map(|(f, q)| (f.as_str(), *q)),
                    msgs.iter().map(|(t, p)| StoredMsg {
                        topic: t,
                        payload: p,
                        qos,
                        pid: None,
                    }),
                    (1..=*ids).map(Qos2Id::Received),
                );
                assert_eq!(ok, want, "restore_session({id:?})");
                if ok {
                    let sess = self.sessions.entry(id.to_string()).or_default();
                    // A queued message is owed to the session whatever it
                    // subscribes to now: its own topic counts as a filter.
                    sess.granted = subs.iter().map(|(f, _)| f.clone()).collect();
                    sess.granted.extend(msgs.iter().map(|(t, _)| t.clone()));
                    sess.awaiting = (1..=*ids).collect();
                }
            }
            Op::RestoreRetained { topic } => {
                // The store and the other shards are trusted: only the
                // receiver's rights apply.
                let allowed = !is_reserved(topic);
                self.retained_seqs.insert(self.sent.len() as u32);
                let body = self.payload(topic, allowed, 3);
                self.b.restore_retained(topic, &body, QoS::AtLeastOnce);
                self.restored += 1;
            }
            Op::Revoke { who } => {
                let id = WHO[*who].0;
                let want = self
                    .slots
                    .iter()
                    .flatten()
                    .any(|s| s.accepted && WHO[s.who].0 == id);
                let got = self.b.disconnect_identity(id, CloseReason::Disallowed);
                assert_eq!(got, want, "disconnect_identity({id:?})");
            }
            Op::Remote { topic, qos } => {
                // The store and the other shards are trusted: only the
                // receiver's rights apply.
                let allowed = !is_reserved(topic);
                let msg = Arc::new(MsgInner {
                    topic: topic.as_str().into(),
                    payload: self.payload(topic, allowed, 2).into(),
                });
                self.b.route_remote(&msg, *qos, false);
            }
            Op::Ping { slot } => self.feed(*slot, &Packet::PingReq),
            Op::Garbage { slot, bytes } => {
                if let Some(s) = self.slots[*slot].as_mut() {
                    s.dirty = true;
                    // From here on the broker may read any packet in what this
                    // connection sends (a PUBREL among them): the session's
                    // QoS 2 ids are not known any more.
                    if let Some(sess) = self.sessions.get_mut(&s.key)
                        && sess.conn == Some(s.c)
                    {
                        sess.uncertain = true;
                    }
                    self.b.input(s.c, bytes, self.now);
                }
            }
        }
        self.settle();
        self.sub = None;
        if let Some((topic, allowed, control, q2)) = verdict {
            self.check_deltas(&before, topic, allowed, control, q2);
        }
        self.check_global();
    }

    /// Counters after a PUBLISH against the model's verdict.
    fn check_deltas(&self, before: &Stats, topic: &str, allowed: bool, control: bool, q2: Q2) {
        let after = self.b.stats();
        let d = |a: u64, b: u64| a - b;
        let published = d(after.published, before.published);
        let acl = d(after.dropped_acl, before.dropped_acl);
        let ctl = d(after.control_received, before.control_received);
        let dropped_ctl = d(after.dropped_control, before.dropped_control);
        let q2_counts = (
            d(after.qos2_received, before.qos2_received),
            d(after.qos2_duplicates, before.qos2_duplicates),
            d(after.qos2_inbound_full, before.qos2_inbound_full),
        );
        let q2_want = match q2 {
            Q2::Fresh => (1, 0, 0),
            Q2::Dup => (0, 1, 0),
            Q2::Full => (0, 0, 1),
            Q2::No | Q2::Unknown => (0, 0, 0),
        };
        assert_eq!(
            q2_counts, q2_want,
            "QoS 2 publish to {topic:?} ({q2:?}): (received, duplicates, inbound_full)"
        );
        let want = if matches!(q2, Q2::Dup | Q2::Full) {
            // Answered (or refused) without being looked at again.
            (0, 0, 0, 0)
        } else if is_reserved(topic) {
            if control { (0, 0, 1, 0) } else { (0, 0, 0, 1) }
        } else if allowed {
            (1, 0, 0, 0)
        } else {
            (0, 1, 0, 0)
        };
        assert_eq!(
            (published, acl, ctl, dropped_ctl),
            want,
            "publish to {topic:?}: (published, dropped_acl, control, dropped_control)"
        );
    }

    fn check_global(&mut self) {
        let st = self.b.stats();
        assert!(
            st.retained_bytes <= MAX_RETAINED_BYTES,
            "retained bytes {} over the budget",
            st.retained_bytes
        );
        assert!(
            st.retained <= MAX_RETAINED_PER_DEVICE * WHO.len() + self.restored,
            "retained count {} over the per-identity limits",
            st.retained
        );
        assert!(st.subscriptions <= st.sessions * MAX_SUBS);
        assert!(st.connections <= SLOTS);
        // Every control message came from a control identity, and exactly
        // those counted as received were queued.
        let mut n = 0;
        for m in self.b.drain_control() {
            assert_eq!(&*m.from, "svc", "control message from {:?}", m.from);
            n += 1;
        }
        self.control_seen += n;
        assert_eq!(self.control_seen, st.control_received);
        // Without an operator nothing reaches the kernel through `$SYS/`.
        assert_eq!(self.b.drain_sys_requests().count(), 0, "$SYS request");
        self.b.drain_persist().for_each(drop);
        let _ = self.b.drain_telemetry().count();
        let _ = self.b.drain_routes().count();
        let mut ready = Vec::new();
        self.b.drain_ready(&mut ready);
    }

    fn close_model(&mut self, s: &Slot) {
        if !s.accepted {
            return;
        }
        if let Some(sess) = self.sessions.get_mut(&s.key)
            && sess.conn == Some(s.c)
        {
            if sess.clean {
                self.sessions.remove(&s.key);
            } else {
                sess.conn = None;
            }
        }
    }

    /// Reads all output and closes what the broker asks to close, until
    /// quiet (a closing connection may publish a will to the others).
    fn settle(&mut self) {
        for _ in 0..4 {
            self.collect();
            let mut closed = false;
            for i in 0..SLOTS {
                let Some(s) = &self.slots[i] else { continue };
                if self.b.close_requested(s.c).is_some() {
                    let s = self.slots[i].take().expect("present");
                    self.close_model(&s);
                    self.b.closed(s.c, self.now);
                    closed = true;
                }
            }
            if !closed {
                break;
            }
        }
        self.collect();
    }

    fn collect(&mut self) {
        for i in 0..SLOTS {
            let Some(s) = self.slots[i].as_mut() else {
                continue;
            };
            let out = self.b.output(s.c).to_vec();
            self.b.consumed(s.c, out.len());
            s.rx.extend_from_slice(&out);
            let mut got = Vec::new();
            let mut used = 0;
            loop {
                let rest = &s.rx[used..];
                match decode(rest, &Limits::PROTOCOL_MAX) {
                    Ok((p, n)) => {
                        got.push(match p {
                            Packet::ConnAck(a) => Rx::ConnAck(a.code as u8, a.session_present),
                            Packet::Publish(p) => Rx::Publish {
                                topic: p.topic.to_string(),
                                payload: p.payload.to_vec(),
                                qos: p.qos,
                                pid: p.packet_id,
                                retain: p.retain,
                                dup: p.dup,
                            },
                            Packet::SubAck(a) => Rx::SubAck(a.return_codes.to_vec()),
                            Packet::PubRec(p) => Rx::PubRec(p),
                            Packet::PubRel(p) => Rx::PubRel(p),
                            Packet::PubComp(p) => Rx::PubComp(p),
                            _ => Rx::Other,
                        });
                        used += n;
                    }
                    Err(Error::Incomplete(_)) => break,
                    Err(e) => panic!("broker sent an undecodable packet: {e:?}"),
                }
            }
            s.rx.drain(..used);
            for rx in got {
                self.on_rx(i, rx);
            }
        }
    }

    fn on_rx(&mut self, i: usize, rx: Rx) {
        match rx {
            Rx::ConnAck(code, present) => self.on_connack(i, code, present),
            Rx::SubAck(codes) => self.on_suback(i, &codes),
            Rx::Publish {
                topic,
                payload,
                qos,
                pid,
                retain,
                dup,
            } => self.on_delivery(i, &topic, &payload, qos, pid, retain, dup),
            Rx::PubRec(p) => {
                // Only for an id this client published at QoS 2 and holds.
                let s = self.slots[i].as_ref().expect("slot");
                let sess = self.sessions.get(&s.key).expect("session");
                assert!(
                    sess.uncertain || sess.awaiting.contains(&p),
                    "{:?}: PUBREC {p} for an id it does not hold",
                    s.key
                );
            }
            Rx::PubRel(p) => {
                let s = self.slots[i].as_mut().expect("slot");
                let o = s.inflight.entry(p).or_insert(Out {
                    // Sent again after a reconnect: the flow started on an
                    // earlier connection.
                    qos: QoS::ExactlyOnce,
                    rec: true,
                    rel: false,
                    seq: None,
                });
                assert!(
                    o.qos == QoS::ExactlyOnce && o.rec,
                    "{:?}: PUBREL {p} before our PUBREC",
                    s.key
                );
                o.rel = true;
                assert!(s.inflight.len() <= MAX_INFLIGHT, "{:?}: window", s.key);
            }
            Rx::PubComp(p) => {
                let s = self.slots[i].as_mut().expect("slot");
                let at = s.released.iter().position(|&x| x == p);
                assert!(at.is_some(), "{:?}: PUBCOMP {p} without our PUBREL", s.key);
                if let Some(at) = at {
                    s.released.remove(at);
                }
            }
            Rx::Other => {}
        }
    }

    fn on_connack(&mut self, i: usize, code: u8, present: bool) {
        let s = self.slots[i].as_mut().expect("slot");
        let e = s.expect.take().expect("one CONNACK per connection");
        assert_eq!(
            code, e.code,
            "CONNACK for {:?} on {:?}: want code {}",
            WHO[s.who], s.key, e.code
        );
        if code != 0 {
            return;
        }
        assert_eq!(present, e.present, "session_present for {:?}", s.key);
        s.accepted = true;
        let sess = self.sessions.entry(s.key.clone()).or_default();
        if e.clean || !e.present {
            *sess = Sess::default();
        }
        sess.clean = e.clean;
        sess.conn = Some(s.c);
    }

    fn on_suback(&mut self, i: usize, codes: &[u8]) {
        let (slot, filters) = self.sub.clone().expect("SUBACK only after a SUBSCRIBE");
        assert_eq!(slot, i);
        assert_eq!(codes.len(), filters.len());
        let s = self.slots[i].as_ref().expect("slot");
        let (id, kind) = WHO[s.who];
        for (code, (filter, want)) in codes.iter().zip(&filters) {
            if *code == 0x80 {
                continue;
            }
            assert!(
                filter_allowed(kind, id, filter),
                "{:?} was granted filter {filter:?} that reaches topics outside its rights",
                WHO[s.who]
            );
            assert!(*code <= 2 && *code <= *want as u8);
            let key = s.key.clone();
            self.sessions
                .get_mut(&key)
                .expect("session")
                .granted
                .insert(filter.clone());
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_delivery(
        &mut self,
        i: usize,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        pid: Option<u16>,
        retain: bool,
        dup: bool,
    ) {
        let s = self.slots[i].as_mut().expect("slot");
        assert!(s.accepted, "PUBLISH before CONNACK");
        let who = WHO[s.who];
        let (id, kind) = who;
        let ctx = format!("{who:?} received {topic:?}");
        // No device receives another device's topics.
        if kind == Kind::Device {
            let l = levels(topic);
            assert!(
                !(l[0] == "devices" && l.len() >= 2 && l[1] != id && ["d1", "d2"].contains(&l[1])),
                "{ctx}: another device's topic"
            );
        }
        assert!(!is_reserved(topic), "{ctx}: reserved namespace");
        assert!(!is_sys(topic), "{ctx}: $SYS without an operator");
        assert!(may_sub_topic(kind, id, topic), "{ctx}: outside its rights");
        let granted = &self.sessions.get(&s.key).expect("session").granted;
        assert!(
            granted.iter().any(|f| matches(f, topic)),
            "{ctx}: no granted filter matches"
        );
        // RETAIN marks a replay for a SUBSCRIBE: sent during it, or (QoS 1 and
        // 2) later from the queue when the window was full, or again after a
        // reconnect; and only a message that was published retained.
        assert!(
            !retain
                || qos != QoS::AtMostOnce
                || self.sub.as_ref().is_some_and(|(slot, _)| *slot == i),
            "{ctx}: RETAIN outside a SUBSCRIBE replay"
        );
        if retain && payload.len() >= 7 && payload[..3] == MAGIC {
            let seq = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
            assert!(
                self.retained_seqs.contains(&seq),
                "{ctx}: RETAIN on message {seq}, never published retained"
            );
        }
        // Provenance: a message we sent (or a will) by someone allowed to.
        if payload.len() >= 7 && payload[..3] == MAGIC {
            let seq = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
            let m = self.sent.get(seq as usize).expect("known message");
            assert_eq!(m.topic, topic, "{ctx}: payload belongs to {:?}", m.topic);
            assert!(
                m.allowed,
                "{ctx}: delivered though the publisher had no right"
            );
        } else {
            assert!(
                WHO.iter().any(|(pid_, k)| may_pub(*k, pid_, topic)),
                "{ctx}: nobody may publish it"
            );
        }
        let seq = (payload.len() >= 7 && payload[..3] == MAGIC)
            .then(|| u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]));
        if qos == QoS::AtMostOnce {
            return;
        }
        let pid = pid.expect("QoS 1 and 2 have an id");
        let key = s.key.clone();
        // Exactly once: one flow per message and session; the PUBLISH comes
        // again only with DUP, the same id, before our PUBREC.
        if qos == QoS::ExactlyOnce
            && !retain
            && let Some(seq) = seq
        {
            let sess = self.sessions.get_mut(&key).expect("session");
            match sess.q2.get(&seq) {
                Some(&(p, rec)) => {
                    assert!(
                        dup && p == pid && !rec,
                        "{ctx}: QoS 2 message {seq} delivered again (id {pid}, first {p}, dup {dup}, PUBREC sent {rec})"
                    );
                }
                None => {
                    sess.q2.insert(seq, (pid, false));
                }
            }
        }
        let s = self.slots[i].as_mut().expect("slot");
        assert!(
            !s.inflight.contains_key(&pid),
            "{ctx}: id {pid} reused while in flight"
        );
        s.inflight.insert(
            pid,
            Out {
                qos,
                rec: false,
                rel: false,
                seq,
            },
        );
        assert!(
            s.inflight.len() <= MAX_INFLIGHT,
            "{ctx}: {} unacknowledged",
            s.inflight.len()
        );
    }
}

/// Runs `ops` against a fresh broker.
pub fn run(ops: &[Op]) -> Harness {
    let mut h = Harness::new();
    for op in ops {
        h.step(op);
    }
    h
}
