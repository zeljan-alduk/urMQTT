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
//! 7. MQTT 5.0 (ADR-274): connections speak 3.1.1 or 5.0 on one broker.
//!    A 5.0 client is told 0x87 exactly for what it may not publish (and a
//!    refused QoS 2 id is not held); one QoS 2 id above the announced
//!    Receive Maximum is DISCONNECT 0x93; its own Receive Maximum bounds
//!    what is in flight to it; a session ends when its Session Expiry
//!    Interval has run while it was offline (both versions: 3.1.1 persistent
//!    sessions have the configured default), so a later CONNECT finds none;
//!    No Local keeps a session's own messages from it unless a matching
//!    subscription without No Local was granted; RETAIN on a live delivery
//!    only through Retain As Published; a retained replay only as Retain
//!    Handling allows; nothing is delivered after its Message Expiry
//!    Interval, and a 5.0 receiver is told what is left of it.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use std::sync::Arc;

use std::collections::BTreeMap;

use urmqtt_broker::{
    Acl, Broker, CONTROL_TOPIC, CloseReason, Config, ConnId, MIN_QOS2_IDS, MsgInner,
    PublisherBackpressure, Qos2Id, Stats, StoredMsg,
};
use urmqtt_mqtt::v5 as m5;
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
/// The Receive Maximum announced to 5.0 clients (QoS 2 ids they may hold).
pub const RM_IN: usize = 4;
/// The Session Expiry Interval of a 3.1.1 persistent session (s).
pub const DEFAULT_EXPIRY: u32 = 600;
/// The longest Session Expiry Interval granted (s).
pub const MAX_EXPIRY: u32 = 2_592_000;
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
        mqtt5: urmqtt_broker::Mqtt5Policy {
            receive_maximum: RM_IN as u16,
            default_session_expiry_s: DEFAULT_EXPIRY,
            max_session_expiry_s: MAX_EXPIRY,
            ..urmqtt_broker::Mqtt5Policy::DEFAULT
        },
        web: None,
        publisher_backpressure: PublisherBackpressure::Single,
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
    /// An MQTT 5.0 CONNECT: as `Connect`, with a Session Expiry Interval,
    /// a Receive Maximum and a Will Delay Interval.
    Connect5 {
        slot: usize,
        who: usize,
        claim: usize,
        clean: bool,
        will: Option<(String, bool, QoS)>,
        expiry: u32,
        rm: u16,
        will_delay: u32,
    },
    /// SUBSCRIBE with Subscription Options (a 3.1.1 connection sends the
    /// QoS bits alone).
    Subscribe5 {
        slot: usize,
        filters: Vec<(String, u8)>,
    },
    /// PUBLISH with a Message Expiry Interval and, on a 5.0 connection,
    /// through a Topic Alias when `alias`.
    Publish5 {
        slot: usize,
        topic: String,
        qos: QoS,
        retain: bool,
        expiry: Option<u32>,
        alias: bool,
    },
    /// A 5.0 DISCONNECT: with its will (0x04), and/or ending the session
    /// (Session Expiry Interval 0). Plain DISCONNECT on 3.1.1.
    Disconnect5 {
        slot: usize,
        will: bool,
        end: bool,
    },
}

pub const TOPICS: [&str; 26] = [
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

pub const FILTERS: [&str; 28] = [
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
            // MQTT 5.0 (ADR-274).
            9 if b1 & 0x30 == 0x30 => match s.u8() % 4 {
                0 => {
                    let who = usize::from(b1 >> 2) % WHO.len();
                    let f = s.u8();
                    let v = s.u8();
                    let claim = if f & 2 != 0 {
                        usize::from((f >> 4) & 7) % WHO.len()
                    } else {
                        who
                    };
                    let will = (f & 4 != 0).then(|| {
                        let t = s.topic(false);
                        (t, f & 0x80 != 0, Src::qos(f >> 3))
                    });
                    Op::Connect5 {
                        slot,
                        who,
                        claim,
                        clean: f & 1 != 0,
                        will,
                        expiry: [0, 1, 3, 600, u32::MAX][usize::from(v & 7) % 5],
                        rm: 1 + u16::from((v >> 3) & 3),
                        will_delay: u32::from(v >> 5) % 4,
                    }
                }
                1 => {
                    let n = 1 + usize::from(s.u8() % 3);
                    let filters = (0..n)
                        .map(|_| {
                            let o = s.u8();
                            // QoS 0-2, No Local, Retain As Published, Retain
                            // Handling 0-2.
                            let opts = ((o & 3) % 3) | (o & 0x0c) | ((((o >> 4) & 3) % 3) << 4);
                            (s.topic(true), opts)
                        })
                        .collect();
                    Op::Subscribe5 { slot, filters }
                }
                2 => {
                    let f = s.u8();
                    Op::Publish5 {
                        slot,
                        topic: s.topic(false),
                        qos: Src::qos(f),
                        retain: f & 4 != 0,
                        expiry: [None, Some(1), Some(2), Some(30)][usize::from((f >> 3) & 3)],
                        alias: f & 0x20 != 0,
                    }
                }
                _ => {
                    let f = s.u8();
                    Op::Disconnect5 {
                        slot,
                        will: f & 1 != 0,
                        end: f & 2 != 0,
                    }
                }
            },
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
                // Never a PUBLISH or a SUBSCRIBE: the oracle knows every
                // publish it sends and matches each SUBACK to its SUBSCRIBE.
                // (Acknowledgements in garbage are allowed: the checks of a
                // dirty connection allow for the broker's answers to them.)
                if let Some(b) = bytes.first_mut()
                    && matches!(*b >> 4, 3 | 8)
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
    /// The publisher's session (No Local); `None` for wills, restored and
    /// remote messages.
    from: Option<String>,
    /// When its Message Expiry Interval ends (ms, the harness clock).
    expires_at: Option<u64>,
}

struct Expect {
    code: u8,
    present: bool,
    clean: bool,
    /// The Session Expiry Interval the session gets (s).
    expiry: u32,
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
    /// MQTT 5.0: the client's Receive Maximum.
    v5: Option<u16>,
    /// The topic its Topic Alias 1 stands for (5.0).
    alias: Option<String>,
    /// 5.0 QoS 1 and 2 publishes: the PUBACK/PUBREC code they must get.
    acks: HashMap<u16, u8>,
    /// The CONNECT asked for Session Expiry 0 (5.0).
    asked_zero: bool,
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
    /// Session Expiry Interval (s): 0 ends it with its connection.
    expiry: u32,
    /// When it went offline (ms).
    offline_since: u64,
    /// Filters granted at some point without No Local / with Retain As
    /// Published.
    granted_local: HashSet<String>,
    granted_rap: HashSet<String>,
    /// Its subscriptions now (Retain Handling 1).
    current: HashSet<String>,
    /// Retained messages a SUBSCRIBE of this session may have replayed: a
    /// replay that waits in the queue (window full) arrives later, after
    /// the SUBSCRIBE, and No Local does not apply to it.
    replayed: HashSet<u32>,
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
        /// The Message Expiry Interval it says (5.0).
        expiry: Option<u32>,
    },
    SubAck(Vec<u8>),
    /// Acknowledgements of the client's publishes, with their code (0 for
    /// 3.1.1).
    PubAck(u16, u8),
    PubRec(u16, u8),
    PubRel(u16),
    PubComp(u16),
    /// A server DISCONNECT (5.0).
    Disconnect(u8),
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
    /// Its options, and whether each filter was new to the session (Retain
    /// Handling 1).
    sub_opts: Vec<(u8, bool)>,
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
            sub_opts: Vec::new(),
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
            from: None,
            expires_at: None,
        });
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&seq.to_le_bytes());
        p.resize(7 + extra, 0xEE);
        p
    }

    fn feed(&mut self, slot: usize, p: &Packet<'_>) {
        if let Some(s) = &self.slots[slot] {
            let bytes = if s.v5.is_some() { wire5_of(p) } else { wire(p) };
            self.b.input(s.c, &bytes, self.now);
        }
    }

    fn feed5(&mut self, slot: usize, p: &m5::Packet<'_>) {
        if let Some(s) = &self.slots[slot] {
            self.b.input(s.c, &wire5(p), self.now);
        }
    }

    fn is_v5(&self, slot: usize) -> bool {
        self.slots[slot].as_ref().is_some_and(|s| s.v5.is_some())
    }

    fn accepted(&self, slot: usize) -> bool {
        self.slots[slot].as_ref().is_some_and(|s| s.accepted)
    }

    /// Applies one operation, then checks every invariant.
    pub fn step(&mut self, op: &Op) {
        // A plain PUBLISH on a 5.0 connection is a 5.0 one without the
        // extras: its refusals and QoS 2 ids follow the 5.0 rules.
        let as5;
        let op = match op {
            Op::Publish {
                slot,
                topic,
                qos,
                retain,
                ..
            } if self.is_v5(*slot) => {
                as5 = Op::Publish5 {
                    slot: *slot,
                    topic: topic.clone(),
                    qos: *qos,
                    retain: *retain,
                    expiry: None,
                    alias: false,
                };
                &as5
            }
            op => op,
        };
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
                        expiry: if *clean { 0 } else { DEFAULT_EXPIRY },
                    }),
                    inflight: BTreeMap::new(),
                    released: Vec::new(),
                    next_pid: 1,
                    rx: Vec::new(),
                    dirty: false,
                    v5: None,
                    alias: None,
                    acks: HashMap::new(),
                    asked_zero: false,
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
                let s = self.slots[*slot].as_ref().expect("accepted");
                if let Some(sess) = self.sessions.get_mut(&s.key) {
                    for f in filters {
                        sess.current.remove(f);
                    }
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
                let (dirty, key, (id, kind)) = (s.dirty, s.key.clone(), WHO[s.who]);
                let Some(sess) = self.sessions.get(&key) else {
                    return self.settle();
                };
                let Some(&p) = sess.awaiting.iter().next() else {
                    return self.settle();
                };
                let uncertain = sess.uncertain;
                let topic = TOPICS[2];
                // A duplicate is never routed: its payload is never
                // deliverable. When the held ids are not known (garbage on a
                // connection of this session), the broker may not hold this
                // id and rightly takes the PUBLISH as a new message: then the
                // publisher's rights decide, as for any publish.
                let body = self.payload(topic, (dirty || uncertain) && may_pub(kind, id, topic), 1);
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
            Op::Connect5 {
                slot,
                who,
                claim,
                clean,
                will,
                expiry,
                rm,
                will_delay,
            } => {
                if self.slots[*slot].is_some() {
                    return self.settle();
                }
                let (id, kind) = WHO[*who];
                let boot = kind == Kind::Bootstrap;
                let claim_id = WHO[*claim].0;
                let bad_will = will.as_ref().is_some_and(|(t, _, _)| !may_pub(kind, id, t));
                // 5.0 codes; a bootstrap session is granted expiry 0, not
                // refused.
                let code = if claim_id != id || invalid_identity(claim_id) {
                    0x85
                } else if bad_will {
                    0x87
                } else {
                    0
                };
                let key = if boot {
                    format!("$bootstrap/{id}")
                } else {
                    id.to_string()
                };
                let present = code == 0 && !clean && self.sessions.contains_key(&key);
                let granted = if boot { 0 } else { (*expiry).min(MAX_EXPIRY) };
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
                        clean: granted == 0,
                        expiry: granted,
                    }),
                    inflight: BTreeMap::new(),
                    released: Vec::new(),
                    next_pid: 1,
                    rx: Vec::new(),
                    dirty: false,
                    v5: Some(*rm),
                    alias: None,
                    acks: HashMap::new(),
                    asked_zero: *expiry == 0,
                });
                let props = [
                    m5::Property::SessionExpiryInterval(*expiry),
                    m5::Property::ReceiveMaximum(*rm),
                ];
                let wprops = [m5::Property::WillDelayInterval(*will_delay)];
                let will_pkt = will.as_ref().map(|(t, retain, qos)| m5::Will {
                    properties: m5::Properties::List(&wprops),
                    topic: t,
                    payload: &body,
                    qos: *qos,
                    retain: *retain,
                });
                self.feed5(
                    *slot,
                    &m5::Packet::Connect(m5::Connect {
                        clean_start: *clean,
                        keep_alive: 10,
                        properties: m5::Properties::List(&props),
                        client_id: claim_id,
                        will: will_pkt,
                        username: None,
                        password: None,
                    }),
                );
            }
            Op::Subscribe5 { slot, filters } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let s = self.slots[*slot].as_ref().expect("accepted");
                let current = self
                    .sessions
                    .get(&s.key)
                    .map(|x| x.current.clone())
                    .unwrap_or_default();
                let mut seen = HashSet::new();
                // A 3.1.1 connection sends the QoS alone.
                let mask = if self.is_v5(*slot) { 0xff } else { 0x03 };
                self.sub_opts = filters
                    .iter()
                    .map(|(f, o)| (*o & mask, !current.contains(f) && seen.insert(f.clone())))
                    .collect();
                self.sub = Some((
                    *slot,
                    filters
                        .iter()
                        .map(|(f, o)| (f.clone(), Src::qos(*o)))
                        .collect(),
                ));
                if self.is_v5(*slot) {
                    // By hand: a filter the encoder would refuse must reach
                    // the broker too.
                    let mut body = 7u16.to_be_bytes().to_vec();
                    body.push(0);
                    for (f, o) in filters {
                        body.extend_from_slice(&(f.len() as u16).to_be_bytes());
                        body.extend_from_slice(f.as_bytes());
                        body.push(*o);
                    }
                    let bytes = frame(0x82, &body);
                    let c = self.slots[*slot].as_ref().expect("accepted").c;
                    self.b.input(c, &bytes, self.now);
                } else {
                    let list: Vec<(&str, QoS)> = filters
                        .iter()
                        .map(|(f, o)| (f.as_str(), Src::qos(*o)))
                        .collect();
                    self.feed(
                        *slot,
                        &Packet::Subscribe(Subscribe {
                            packet_id: 7,
                            topics: SubscribeTopics::List(&list),
                        }),
                    );
                }
            }
            Op::Publish5 {
                slot,
                topic,
                qos,
                retain,
                expiry,
                alias,
            } => {
                if !self.accepted(*slot) {
                    return self.settle();
                }
                let s = self.slots[*slot].as_mut().expect("accepted");
                let (id, kind) = WHO[s.who];
                let dirty = s.dirty;
                let v5 = s.v5.is_some();
                let pid = if *qos == QoS::AtMostOnce {
                    None
                } else {
                    s.next_pid = s.next_pid.wrapping_add(1).max(1);
                    Some(s.next_pid)
                };
                let key = s.key.clone();
                let limit = if v5 { RM_IN } else { QOS2_IDS };
                let allowed = may_pub(kind, id, topic);
                let control = topic == CONTROL_TOPIC && kind != Kind::Bootstrap && id == "svc";
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
                        } else if sess.awaiting.len() >= limit {
                            Q2::Full
                        } else {
                            // A 5.0 PUBREC with a failure code ends the flow:
                            // the id is not held.
                            if !v5 || allowed || control {
                                sess.awaiting.insert(p);
                            }
                            Q2::Fresh
                        }
                    }
                    (QoS::ExactlyOnce, _, _) => Q2::Unknown,
                    _ => Q2::No,
                };
                if *retain {
                    self.retained_seqs.insert(self.sent.len() as u32);
                }
                let body = self.payload(topic, allowed, 1);
                let seq = self.sent.len() - 1;
                if v5 {
                    self.sent[seq].from = Some(key.clone());
                    if let Some(e) = expiry.filter(|e| *e > 0) {
                        self.sent[seq].expires_at = Some(self.now + u64::from(e) * 1000);
                    }
                }
                if !dirty && q2 != Q2::Unknown {
                    verdict = Some((topic, allowed, control, q2));
                }
                let s = self.slots[*slot].as_mut().expect("accepted");
                if v5 && let (Some(p), true) = (pid, matches!(q2, Q2::No | Q2::Fresh)) {
                    s.acks.insert(p, if allowed || control { 0 } else { 0x87 });
                }
                if !v5 {
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
                } else {
                    let mut props = Vec::new();
                    let mut t: &str = topic;
                    if *alias {
                        if s.alias.as_deref() == Some(topic.as_str()) {
                            t = "";
                        } else {
                            s.alias = Some(topic.clone());
                        }
                        props.push(m5::Property::TopicAlias(1));
                    }
                    if let Some(e) = expiry {
                        props.push(m5::Property::MessageExpiryInterval(*e));
                    }
                    props.push(m5::Property::UserProperty("seq", "x"));
                    self.feed5(
                        *slot,
                        &m5::Packet::Publish(m5::Publish {
                            dup: false,
                            qos: *qos,
                            retain: *retain,
                            topic: t,
                            packet_id: pid,
                            properties: m5::Properties::List(&props),
                            payload: &body,
                        }),
                    );
                }
            }
            Op::Disconnect5 { slot, will, end } => {
                let Some(s) = self.slots[*slot].as_ref() else {
                    return self.settle();
                };
                if s.v5.is_none() {
                    self.feed(*slot, &Packet::Disconnect);
                    return self.settle();
                }
                let key = s.key.clone();
                let mine = self.sessions.get(&key).is_some_and(|x| x.conn == Some(s.c));
                // Behind garbage the DISCONNECT may be read as the body of a
                // half packet: its expiry change is not sent then.
                let end = *end && !s.dirty;
                if end
                    && mine
                    && let Some(sess) = self.sessions.get_mut(&key)
                {
                    sess.expiry = 0;
                }
                let props = [m5::Property::SessionExpiryInterval(0)];
                self.feed5(
                    *slot,
                    &m5::Packet::Disconnect(m5::Disconnect {
                        reason: if *will {
                            m5::ReasonCode::DisconnectWithWillMessage
                        } else {
                            m5::ReasonCode::Success
                        },
                        properties: if end {
                            m5::Properties::List(&props)
                        } else {
                            m5::Properties::EMPTY
                        },
                    }),
                );
            }
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
                self.b.poll_flow(self.now);
                if *ms == 0 {
                    self.b.shrink();
                }
                // Offline sessions whose expiry has run are gone.
                let now = self.now;
                self.sessions.retain(|_, x| {
                    x.conn.is_some()
                        || x.expiry == u32::MAX
                        || now - x.offline_since < u64::from(x.expiry) * 1000
                });
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
                    msgs.iter().map(|(t, p)| StoredMsg::plain(t, p, qos, None)),
                    (1..=*ids).map(Qos2Id::Received),
                );
                assert_eq!(ok, want, "restore_session({id:?})");
                if ok {
                    let now = self.now;
                    let sess = self.sessions.entry(id.to_string()).or_default();
                    // A queued message is owed to the session whatever it
                    // subscribes to now: its own topic counts as a filter.
                    sess.granted = subs.iter().map(|(f, _)| f.clone()).collect();
                    sess.granted.extend(msgs.iter().map(|(t, _)| t.clone()));
                    sess.granted_local = sess.granted.clone();
                    sess.current = subs.iter().map(|(f, _)| f.clone()).collect();
                    sess.awaiting = (1..=*ids).collect();
                    // Stored before schema 4: the 3.1.1 default, from now.
                    sess.expiry = DEFAULT_EXPIRY;
                    sess.offline_since = now;
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
                let msg = Arc::new(MsgInner::new(topic, &self.payload(topic, allowed, 2)));
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
        self.sub_opts.clear();
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
            if sess.expiry == 0 {
                self.sessions.remove(&s.key);
            } else {
                sess.conn = None;
                sess.offline_since = self.now;
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
                if s.v5.is_none() {
                    break;
                }
                let rest = &s.rx[used..];
                match m5::decode(rest, &m5::Limits::PROTOCOL_MAX) {
                    Ok((p, n)) => {
                        got.push(match p {
                            m5::Packet::ConnAck(a) => {
                                Rx::ConnAck(a.reason as u8, a.session_present)
                            }
                            m5::Packet::Publish(p) => {
                                assert!(
                                    !p.topic.is_empty() && p.properties.topic_alias().is_none(),
                                    "the broker sent a topic alias"
                                );
                                Rx::Publish {
                                    topic: p.topic.to_string(),
                                    payload: p.payload.to_vec(),
                                    qos: p.qos,
                                    pid: p.packet_id,
                                    retain: p.retain,
                                    dup: p.dup,
                                    expiry: p.properties.message_expiry_interval(),
                                }
                            }
                            m5::Packet::SubAck(a) => Rx::SubAck(a.reason_codes.to_vec()),
                            m5::Packet::PubAck(a) => Rx::PubAck(a.packet_id, a.reason as u8),
                            m5::Packet::PubRec(a) => Rx::PubRec(a.packet_id, a.reason as u8),
                            m5::Packet::PubRel(a) => Rx::PubRel(a.packet_id),
                            m5::Packet::PubComp(a) => Rx::PubComp(a.packet_id),
                            m5::Packet::Disconnect(d) => Rx::Disconnect(d.reason as u8),
                            _ => Rx::Other,
                        });
                        used += n;
                    }
                    Err(m5::Error::Incomplete(_)) => break,
                    Err(e) => panic!("broker sent an undecodable 5.0 packet: {e:?}"),
                }
            }
            loop {
                if s.v5.is_some() {
                    break;
                }
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
                                expiry: None,
                            },
                            Packet::SubAck(a) => Rx::SubAck(a.return_codes.to_vec()),
                            Packet::PubAck(p) => Rx::PubAck(p, 0),
                            Packet::PubRec(p) => Rx::PubRec(p, 0),
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
                expiry,
            } => {
                self.check_v5_delivery(i, &topic, &payload, qos, retain, dup, expiry);
                self.on_delivery(i, &topic, &payload, qos, pid, retain, dup)
            }
            Rx::PubAck(p, code) => self.check_ack_code(i, p, code),
            Rx::PubRec(p, code) => {
                self.check_ack_code(i, p, code);
                // A success only for an id this client published at QoS 2
                // and holds.
                let s = self.slots[i].as_ref().expect("slot");
                let sess = self.sessions.get(&s.key).expect("session");
                assert!(
                    code != 0 || sess.uncertain || sess.awaiting.contains(&p),
                    "{:?}: PUBREC {p} for an id it does not hold",
                    s.key
                );
            }
            Rx::Disconnect(code) => {
                let s = self.slots[i].as_ref().expect("slot");
                assert!(s.v5.is_some(), "DISCONNECT to a 3.1.1 client");
                assert!(code >= 0x80, "server DISCONNECT {code:#x}");
            }
            Rx::PubRel(p) => {
                let s = self.slots[i].as_mut().expect("slot");
                // The broker answers a PUBREC for an id it does not have in
                // flight with PUBREL too (so a client that kept state the
                // broker lost can finish, 4.3.3); the id stays free. On a
                // connection with garbage such a PUBREC may have been in the
                // garbage: nothing is in flight then.
                if s.dirty && !s.inflight.contains_key(&p) {
                    return;
                }
                let o = s.inflight.entry(p).or_insert(Out {
                    // Sent again after a reconnect: the flow started on an
                    // earlier connection.
                    qos: QoS::ExactlyOnce,
                    rec: true,
                    rel: false,
                    seq: None,
                });
                // Garbage on this connection may itself have been a
                // well-formed PUBREC (or PUBACK, PUBCOMP) that the broker
                // answered as 4.3.3 requires: then neither the order nor the
                // window can be judged from our own acknowledgements.
                assert!(
                    o.qos == QoS::ExactlyOnce && (o.rec || s.dirty),
                    "{:?}: PUBREL {p} before our PUBREC",
                    s.key
                );
                o.rec = true;
                o.rel = true;
                assert!(
                    s.dirty || s.inflight.len() <= MAX_INFLIGHT,
                    "{:?}: window",
                    s.key
                );
            }
            Rx::PubComp(p) => {
                let s = self.slots[i].as_mut().expect("slot");
                let at = s.released.iter().position(|&x| x == p);
                // (Garbage may itself have been a PUBREL, which the broker
                // answers whatever the id, 4.3.3.)
                assert!(
                    at.is_some() || s.dirty,
                    "{:?}: PUBCOMP {p} without our PUBREL",
                    s.key
                );
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
        if !e.present {
            *sess = Sess::default();
        }
        sess.clean = e.clean;
        sess.expiry = e.expiry;
        sess.conn = Some(s.c);
    }

    fn on_suback(&mut self, i: usize, codes: &[u8]) {
        let (slot, filters) = self.sub.clone().expect("SUBACK only after a SUBSCRIBE");
        assert_eq!(slot, i);
        assert_eq!(codes.len(), filters.len());
        let s = self.slots[i].as_ref().expect("slot");
        let (id, kind) = WHO[s.who];
        let v5 = s.v5.is_some();
        for (k, (code, (filter, want))) in codes.iter().zip(&filters).enumerate() {
            if v5 {
                // 5.0: why a filter was refused.
                assert!(
                    matches!(code, 0..=2 | 0x87 | 0x97 | 0x9e),
                    "{:?}: SUBACK code {code:#x}",
                    WHO[s.who]
                );
            }
            if *code >= 0x80 {
                continue;
            }
            let opts = self.sub_opts.get(k).map_or(*want as u8, |o| o.0);
            let key = s.key.clone();
            let sess = self.sessions.get_mut(&key).expect("session");
            sess.current.insert(filter.clone());
            sess.replayed.extend(self.retained_seqs.iter().filter(|q| {
                self.sent
                    .get(**q as usize)
                    .is_some_and(|m| matches(filter, &m.topic))
            }));
            if opts & 0x04 == 0 {
                sess.granted_local.insert(filter.clone());
            }
            if opts & 0x08 != 0 {
                sess.granted_rap.insert(filter.clone());
            }
            let s = self.slots[i].as_ref().expect("slot");
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
        let rap = self
            .sessions
            .get(&s.key)
            .is_some_and(|x| x.granted_rap.iter().any(|f| matches(f, topic)));
        assert!(
            !retain
                || qos != QoS::AtMostOnce
                || rap
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
        // (Garbage may have completed a flight with a PUBACK or PUBCOMP of
        // its own: on such a connection the broker may rightly reuse the id.)
        assert!(
            s.dirty || !s.inflight.contains_key(&pid),
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
        let window =
            s.v5.map_or(MAX_INFLIGHT, |rm| MAX_INFLIGHT.min(usize::from(rm)));
        assert!(
            s.dirty || s.inflight.len() <= window,
            "{ctx}: {} unacknowledged, window {window}",
            s.inflight.len()
        );
    }

    /// The code of a PUBACK or PUBREC for a 5.0 publish: 0x87 exactly when
    /// the oracle forbids it.
    fn check_ack_code(&mut self, i: usize, pid: u16, code: u8) {
        let s = self.slots[i].as_mut().expect("slot");
        if s.v5.is_none() {
            return;
        }
        if let Some(want) = s.acks.remove(&pid) {
            assert_eq!(code, want, "{:?}: acknowledgement of {pid}", WHO[s.who]);
        } else {
            // A duplicate or one we sent behind garbage: no failure code
            // unless we expected one.
            assert!(
                code == 0 || code == 0x87,
                "{:?}: code {code:#x}",
                WHO[s.who]
            );
        }
    }

    /// What MQTT 5.0 adds to a delivery: No Local, Retain Handling, Message
    /// Expiry (and the rest of the rules hold for every version).
    #[allow(clippy::too_many_arguments)]
    fn check_v5_delivery(
        &self,
        i: usize,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        retain: bool,
        dup: bool,
        expiry: Option<u32>,
    ) {
        let s = self.slots[i].as_ref().expect("slot");
        let ctx = format!("{:?} received {topic:?}", WHO[s.who]);
        let sess = self.sessions.get(&s.key).expect("session");
        let entry = (payload.len() >= 7 && payload[..3] == MAGIC)
            .then(|| u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]))
            .and_then(|seq| self.sent.get(seq as usize));
        let replay = retain && self.sub.as_ref().is_some_and(|(slot, _)| *slot == i);
        if let Some(m) = entry {
            // No Local: its own message only through a subscription without.
            let queued_replay = retain
                && (payload.len() >= 7)
                && sess.replayed.contains(&u32::from_le_bytes([
                    payload[3], payload[4], payload[5], payload[6],
                ]));
            if m.from.as_deref() == Some(s.key.as_str()) && !replay && !queued_replay {
                assert!(
                    sess.granted_local.iter().any(|f| matches(f, topic)),
                    "{ctx}: its own message despite No Local"
                );
            }
            // Message Expiry: never after the deadline (a resend of what
            // was already on its way is not a new delivery).
            if let Some(at) = m.expires_at
                && !dup
            {
                assert!(self.now < at, "{ctx}: delivered after its expiry");
                if s.v5.is_some() {
                    let left = (at - self.now).div_ceil(1000).max(1) as u32;
                    assert_eq!(expiry, Some(left), "{ctx}: remaining expiry");
                }
            }
        }
        // Retain Handling: a QoS 0 replay during this SUBSCRIBE comes from a
        // filter that asked for it (0, or 1 and new to the session).
        if replay && qos == QoS::AtMostOnce {
            let filters = &self.sub.as_ref().expect("subscribe").1;
            let ok = filters
                .iter()
                .zip(&self.sub_opts)
                .any(|((f, _), (o, new))| {
                    matches(f, topic) && ((o >> 4) & 3 == 0 || ((o >> 4) & 3 == 1 && *new))
                })
                || self.sub_opts.is_empty();
            assert!(ok, "{ctx}: retained replay that Retain Handling refuses");
        }
    }
}

/// The 5.0 form of a packet the 3.1.1 ops send (no properties).
fn wire5_of(p: &Packet<'_>) -> Vec<u8> {
    let ack = |packet_id| m5::Ack {
        packet_id,
        reason: m5::ReasonCode::Success,
        properties: m5::Properties::EMPTY,
    };
    let p5 = match *p {
        Packet::Publish(p) => m5::Packet::Publish(m5::Publish {
            dup: p.dup,
            qos: p.qos,
            retain: p.retain,
            topic: p.topic,
            packet_id: p.packet_id,
            properties: m5::Properties::EMPTY,
            payload: p.payload,
        }),
        Packet::PubAck(i) => m5::Packet::PubAck(ack(i)),
        Packet::PubRec(i) => m5::Packet::PubRec(ack(i)),
        Packet::PubRel(i) => m5::Packet::PubRel(ack(i)),
        Packet::PubComp(i) => m5::Packet::PubComp(ack(i)),
        Packet::PingReq => m5::Packet::PingReq,
        Packet::Disconnect => m5::Packet::Disconnect(m5::Disconnect {
            reason: m5::ReasonCode::Success,
            properties: m5::Properties::EMPTY,
        }),
        Packet::Subscribe(s) => {
            let mut body = s.packet_id.to_be_bytes().to_vec();
            body.push(0);
            for (f, q) in s.topics.iter() {
                body.extend_from_slice(&(f.len() as u16).to_be_bytes());
                body.extend_from_slice(f.as_bytes());
                body.push(q as u8);
            }
            return frame(0x82, &body);
        }
        Packet::Unsubscribe(u) => {
            let mut body = u.packet_id.to_be_bytes().to_vec();
            body.push(0);
            for f in u.topics.iter() {
                body.extend_from_slice(&(f.len() as u16).to_be_bytes());
                body.extend_from_slice(f.as_bytes());
            }
            return frame(0xa2, &body);
        }
        other => panic!("no 5.0 form here for {other:?}"),
    };
    wire5(&p5)
}

fn wire5(p: &m5::Packet<'_>) -> Vec<u8> {
    let mut v = vec![0u8; m5::encoded_len(p).expect("encodable")];
    m5::encode(p, &mut v).expect("encodable");
    v
}

/// A packet from its first byte and body.
fn frame(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    let mut n = body.len();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    out
}

/// Runs `ops` against a fresh broker.
pub fn run(ops: &[Op]) -> Harness {
    let mut h = Harness::new();
    for op in ops {
        h.step(op);
    }
    h
}
