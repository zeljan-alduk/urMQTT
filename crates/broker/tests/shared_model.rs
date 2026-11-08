//! Shared subscriptions and Subscription Identifiers against a reference
//! model (ADR-275), across shards as the kernel runs them: three brokers,
//! each client homed on one, the shards' routes and shared-subscription
//! messages carried between them as the mesh does. Random sequences of
//! connects, subscribes (each SUBSCRIBE one filter with a fresh Subscription
//! Identifier, so every delivery says which subscriptions it came through),
//! unsubscribes, publishes and dropped connections by two devices and two
//! services, all MQTT 5.0. The model is written from MQTT 5.0 §4.8.2 and
//! §3.3.4 and the ACL below, not from the broker. After every publish:
//!
//! 1. each shared group (role class, group, filter) whose filter matches
//!    gets the message exactly once, through one of its members (a group of
//!    devices and a group of services of the same name and filter are two
//!    groups: no delivery crosses roles), at the QoS of that member's
//!    subscription bounded by the publish;
//! 2. each session with ordinary matching subscriptions gets exactly one
//!    copy carrying the identifiers of all of them (and of no shared one),
//!    at the highest of their QoS bounded by the publish;
//! 3. a delivery through a shared subscription carries that subscription's
//!    identifier alone;
//! 4. a shared subscription is granted iff the filter inside it is within
//!    the subscriber's rights (the group name is not a topic), and the round
//!    robin spreads a group's messages over its members.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::test_runner::{Config as PtConfig, RngAlgorithm, RngSeed};
use urmqtt_broker::{Acl, Broker, Config, ConnId, Mqtt5Policy, PublisherBackpressure};
use urmqtt_mqtt::v5::{
    self as m5, Ack, Connect, Packet as P5, Properties, Property, Publish, ReasonCode, Subscribe,
    SubscribeTopics, SubscriptionOptions, Unsubscribe, UnsubscribeTopics,
};
use urmqtt_mqtt::{Limits, QoS};

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/cmd/#", "fleet/all"],
    service_ids: &["backend", "backend2"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    service_subscribe: &["devices/#", "fleet/#"],
    operator_ids: &[],
};

const SHARDS: u16 = 3;
/// (client id, is a service, home shard).
const WHO: [(&str, bool, usize); 4] = [
    ("d1", false, 0),
    ("d2", false, 1),
    ("backend", true, 2),
    ("backend2", true, 1),
];

const FILTERS: [&str; 12] = [
    "fleet/all",
    "fleet/#",
    "devices/+/telemetry",
    "devices/d1/cmd/#",
    "$share/g/fleet/all",
    "$share/g/fleet/#",
    "$share/h/fleet/all",
    "$share/g/devices/+/telemetry",
    "$share/g/devices/d1/cmd/#",
    "$share/g/devices/d2/cmd/#",
    "$share/fleet/fleet/all",
    "$share/g/#",
];

const TOPICS: [&str; 6] = [
    "fleet/all",
    "fleet/x",
    "devices/d1/telemetry",
    "devices/d2/telemetry",
    "devices/d1/cmd/go",
    "devices/d2/cmd/go",
];

fn cfg() -> Config {
    Config {
        limits: Limits {
            max_packet_size: 4096,
            max_topic_len: 64,
            max_topic_levels: 8,
            max_client_id_len: 23,
            max_topics_per_packet: 4,
        },
        max_connections: 16,
        max_subscriptions_per_session: 16,
        max_inflight: 16,
        max_queued: 16,
        max_retained_per_device: 4,
        max_retained_bytes: 1 << 16,
        rate_tokens: 1_000_000,
        rate_period_ms: 1000,
        max_outbound_bytes: 1 << 20,
        acl: ACL,
        persist: false,
        telemetry: &[],
        fanout: true,
        control_ids: &[],
        plain: None,
        web: None,
        mqtt5: Mqtt5Policy::DEFAULT,
        publisher_backpressure: PublisherBackpressure::Off,
    }
}

fn levels(t: &str) -> Vec<&str> {
    t.split('/').collect()
}

fn matches(filter: &str, topic: &str) -> bool {
    let (f, t) = (levels(filter), levels(topic));
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

/// The subscribe rights, written out per level.
fn may_receive(service: bool, id: &str, topic: &str) -> bool {
    let l = levels(topic);
    if service {
        l[0] == "devices" || l[0] == "fleet"
    } else {
        (l.len() >= 3 && l[0] == "devices" && l[1] == id && l[2] == "cmd") || l == ["fleet", "all"]
    }
}

fn may_publish(service: bool, id: &str, topic: &str) -> bool {
    let l = levels(topic);
    if service {
        (l.len() >= 3 && l[0] == "devices" && l[2] == "cmd") || l[0] == "fleet"
    } else {
        l.len() >= 2 && l[0] == "devices" && l[1] == id
    }
}

/// Every topic the filter can match (over a small universe) is allowed.
fn filter_allowed(service: bool, id: &str, filter: &str) -> bool {
    const A: [&str; 8] = [
        "devices",
        "d1",
        "d2",
        "cmd",
        "fleet",
        "all",
        "telemetry",
        "x",
    ];
    let mut all: Vec<String> = Vec::new();
    let mut cur: Vec<String> = vec![String::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for p in &cur {
            for a in A {
                let t = if p.is_empty() {
                    a.to_string()
                } else {
                    format!("{p}/{a}")
                };
                all.push(t.clone());
                next.push(t);
            }
        }
        cur = next;
    }
    all.iter()
        .all(|t| !matches(filter, t) || may_receive(service, id, t))
}

fn split_share(f: &str) -> Option<(&str, &str)> {
    f.strip_prefix("$share/")?.split_once('/')
}

#[derive(Clone, Debug)]
enum Op {
    Connect(usize),
    Subscribe(usize, usize, u8),
    Unsubscribe(usize, usize),
    Publish(usize, usize, u8),
    Drop(usize),
}

fn op() -> impl Strategy<Value = Op> {
    let who = 0..WHO.len();
    prop_oneof![
        2 => who.clone().prop_map(Op::Connect),
        4 => (who.clone(), 0..FILTERS.len(), 0u8..3).prop_map(|(w, f, q)| Op::Subscribe(w, f, q)),
        1 => (who.clone(), 0..FILTERS.len()).prop_map(|(w, f)| Op::Unsubscribe(w, f)),
        6 => (who.clone(), 0..TOPICS.len(), 0u8..3).prop_map(|(w, t, q)| Op::Publish(w, t, q)),
        1 => who.prop_map(Op::Drop),
    ]
}

/// Shared groups (class, group, filter) → members (client, identifier,
/// QoS).
type Groups = BTreeMap<(bool, String, String), Vec<(usize, u32, u8)>>;

/// One client's connection and what the model says its session holds.
struct Client {
    c: ConnId,
    rx: Vec<u8>,
    /// Filter → (Subscription Identifier, QoS).
    subs: BTreeMap<String, (u32, u8)>,
}

/// A received PUBLISH.
#[derive(Debug, Clone)]
struct Got {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    pid: Option<u16>,
    ids: BTreeSet<u32>,
}

struct World {
    b: Vec<Broker>,
    clients: Vec<Option<Client>>,
    next_id: u32,
    seq: u32,
    now: u64,
    /// Deliveries per group member (for the round-robin check):
    /// (class, group, filter) → client → count.
    spread: BTreeMap<(bool, String, String), BTreeMap<usize, u32>>,
}

fn enc(p: &P5<'_>) -> Vec<u8> {
    let mut v = vec![0u8; m5::encoded_len(p).unwrap()];
    m5::encode(p, &mut v).unwrap();
    v
}

impl World {
    fn new() -> Self {
        let b = (0..SHARDS)
            .map(|i| {
                let mut b = Broker::new(cfg());
                b.set_shards(i, 0, SHARDS);
                b
            })
            .collect();
        World {
            b,
            clients: (0..WHO.len()).map(|_| None).collect(),
            next_id: 1,
            seq: 0,
            now: 0,
            spread: BTreeMap::new(),
        }
    }

    fn home(w: usize) -> usize {
        WHO[w].2
    }

    /// Carries routes and shared-subscription messages until nothing moves.
    fn pump(&mut self) {
        loop {
            let mut any = false;
            for i in 0..self.b.len() {
                let routes: Vec<_> = self.b[i].drain_routes().collect();
                for (msg, qos, retain, _) in routes {
                    for j in 0..self.b.len() {
                        if j != i {
                            self.b[j].route_remote(&msg, qos, retain);
                        }
                    }
                    any = true;
                }
                let shared: Vec<_> = self.b[i].drain_shared().collect();
                for (to, m) in shared {
                    assert_ne!(usize::from(to), i);
                    self.b[usize::from(to)].shared_input(i as u16, m, self.now);
                    any = true;
                }
            }
            if !any {
                return;
            }
        }
    }

    fn send(&mut self, w: usize, p: &P5<'_>) {
        let bytes = enc(p);
        let c = self.clients[w].as_ref().unwrap().c;
        self.b[Self::home(w)].input(c, &bytes, self.now);
    }

    /// Everything client `w` received since the last call.
    fn recv(&mut self, w: usize) -> Vec<P5Owned> {
        let h = Self::home(w);
        let Some(cl) = self.clients[w].as_mut() else {
            return Vec::new();
        };
        let out = self.b[h].output(cl.c).to_vec();
        self.b[h].consumed(cl.c, out.len());
        cl.rx.extend_from_slice(&out);
        let mut got = Vec::new();
        loop {
            match m5::decode(&cl.rx, &m5::Limits::PROTOCOL_MAX) {
                Ok((p, n)) => {
                    got.push(P5Owned::of(&p));
                    cl.rx.drain(..n);
                }
                Err(m5::Error::Incomplete(_)) => return got,
                Err(e) => panic!("{e:?}"),
            }
        }
    }

    fn connected(&self, w: usize) -> bool {
        self.clients[w].is_some()
    }

    fn drop_conn(&mut self, w: usize) {
        if let Some(cl) = self.clients[w].take() {
            self.b[Self::home(w)].closed(cl.c, self.now);
            self.pump();
        }
    }

    fn step(&mut self, op: &Op) {
        self.now += 10;
        match *op {
            Op::Connect(w) => {
                self.drop_conn(w);
                let h = Self::home(w);
                let c = self.b[h].open(self.now).unwrap();
                self.clients[w] = Some(Client {
                    c,
                    rx: Vec::new(),
                    subs: BTreeMap::new(),
                });
                self.send(
                    w,
                    &P5::Connect(Connect {
                        clean_start: true,
                        keep_alive: 0,
                        properties: Properties::EMPTY,
                        client_id: WHO[w].0,
                        will: None,
                        username: None,
                        password: None,
                    }),
                );
                let got = self.recv(w);
                assert!(matches!(got.first(), Some(P5Owned::ConnAck(0))), "{got:?}");
            }
            Op::Subscribe(w, f, q) if self.connected(w) => {
                let filter = FILTERS[f];
                let id = self.next_id;
                self.next_id += 1;
                let qos = QoS::from_bits(q).unwrap();
                let opts = [(filter, SubscriptionOptions::qos(qos))];
                let props = [Property::SubscriptionIdentifier(id)];
                self.send(
                    w,
                    &P5::Subscribe(Subscribe {
                        packet_id: 1,
                        properties: Properties::List(&props),
                        topics: SubscribeTopics::List(&opts),
                    }),
                );
                self.pump();
                let got = self.recv(w);
                let (name, service, _) = WHO[w];
                let inner = split_share(filter).map_or(filter, |(_, f)| f);
                let ok = filter_allowed(service, name, inner);
                let want = if ok { q } else { 0x87 };
                // A retained message may follow (none is published here).
                assert!(
                    matches!(got.first(), Some(P5Owned::SubAck(c)) if *c == want),
                    "{} subscribes {filter}: {got:?}",
                    WHO[w].0
                );
                if ok {
                    let cl = self.clients[w].as_mut().unwrap();
                    cl.subs.insert(filter.to_string(), (id, q));
                }
            }
            Op::Unsubscribe(w, f) if self.connected(w) => {
                let filter = FILTERS[f];
                let topics = [filter];
                self.send(
                    w,
                    &P5::Unsubscribe(Unsubscribe {
                        packet_id: 2,
                        properties: Properties::EMPTY,
                        topics: UnsubscribeTopics::List(&topics),
                    }),
                );
                self.pump();
                let got = self.recv(w);
                let had = self.clients[w]
                    .as_mut()
                    .unwrap()
                    .subs
                    .remove(filter)
                    .is_some();
                let want = if had { 0 } else { 0x11 };
                assert!(
                    matches!(got.first(), Some(P5Owned::UnsubAck(c)) if *c == want),
                    "{got:?}"
                );
            }
            Op::Publish(w, t, q) if self.connected(w) => self.publish(w, TOPICS[t], q),
            Op::Drop(w) => self.drop_conn(w),
            _ => {}
        }
    }

    fn publish(&mut self, from: usize, topic: &str, q: u8) {
        self.seq += 1;
        let payload = self.seq.to_be_bytes();
        let qos = QoS::from_bits(q).unwrap();
        self.send(
            from,
            &P5::Publish(Publish {
                dup: false,
                qos,
                retain: false,
                topic,
                packet_id: (q > 0).then_some(7),
                properties: Properties::EMPTY,
                payload: &payload,
            }),
        );
        self.pump();
        let (name, service, _) = WHO[from];
        let allowed = may_publish(service, name, topic);
        // Collect every client's deliveries of this message (and acknowledge).
        let mut got: Vec<(usize, Got)> = Vec::new();
        #[allow(clippy::needless_range_loop)] // `w` is also the client's index
        for w in 0..WHO.len() {
            for p in self.recv(w) {
                if let P5Owned::Publish(g) = p {
                    assert_eq!(g.payload, payload, "an older message late to {}", WHO[w].0);
                    if let Some(pid) = g.pid {
                        let ack = Ack {
                            packet_id: pid,
                            reason: ReasonCode::Success,
                            properties: Properties::EMPTY,
                        };
                        let pk = if g.qos == 1 {
                            P5::PubAck(ack)
                        } else {
                            P5::PubRec(ack)
                        };
                        self.send(w, &pk);
                        if g.qos == 2 {
                            let rel = Ack {
                                packet_id: pid,
                                reason: ReasonCode::Success,
                                properties: Properties::EMPTY,
                            };
                            self.recv(w); // the PUBREL
                            self.send(w, &P5::PubComp(rel));
                        }
                    }
                    got.push((w, g));
                }
            }
        }
        // The publisher's own acknowledgement is not under test here; a QoS
        // 2 publish is released so its id is free again.
        if q == 2 {
            let rel = Ack {
                packet_id: 7,
                reason: ReasonCode::Success,
                properties: Properties::EMPTY,
            };
            self.send(from, &P5::PubRel(rel));
            self.recv(from);
        }
        if !allowed {
            assert!(got.is_empty(), "a refused publish was delivered: {got:?}");
            return;
        }
        // The model: ordinary subscriptions per client, shared groups.
        let mut groups: Groups = BTreeMap::new();
        for (w, cl) in self.clients.iter().enumerate() {
            let Some(cl) = cl else { continue };
            for (f, &(id, sq)) in &cl.subs {
                if let Some((g, inner)) = split_share(f) {
                    groups
                        .entry((WHO[w].1, g.to_string(), inner.to_string()))
                        .or_default()
                        .push((w, id, sq));
                }
            }
        }
        // 2. Ordinary deliveries.
        for (w, cl) in self.clients.iter().enumerate() {
            let Some(cl) = cl else { continue };
            let normal: Vec<(u32, u8)> = cl
                .subs
                .iter()
                .filter(|(f, _)| split_share(f).is_none() && matches(f, topic))
                .map(|(_, &x)| x)
                .collect();
            let ids: BTreeSet<u32> = normal.iter().map(|x| x.0).collect();
            let mine: Vec<&Got> = got
                .iter()
                .filter(|(x, g)| {
                    *x == w && g.ids.iter().all(|i| ids.contains(i)) && !g.ids.is_empty()
                })
                .map(|(_, g)| g)
                .collect();
            if normal.is_empty() {
                assert!(
                    mine.is_empty(),
                    "{} got {mine:?} with no subscription",
                    WHO[w].0
                );
                continue;
            }
            assert_eq!(
                mine.len(),
                1,
                "{} (subs {:?}) got {mine:?}",
                WHO[w].0,
                cl.subs
            );
            assert_eq!(mine[0].ids, ids, "every matching identifier, once");
            let want_q = normal.iter().map(|x| x.1).max().unwrap().min(q);
            assert_eq!(mine[0].qos, want_q);
            assert_eq!(mine[0].topic, topic);
        }
        // 1, 3. Shared groups: exactly one member, its identifier alone.
        for ((service, g, inner), members) in &groups {
            if !matches(inner, topic) {
                continue;
            }
            let ids: BTreeMap<u32, (usize, u8)> =
                members.iter().map(|&(w, id, sq)| (id, (w, sq))).collect();
            let through: Vec<&(usize, Got)> = got
                .iter()
                .filter(|(_, x)| x.ids.iter().any(|i| ids.contains_key(i)))
                .collect();
            assert_eq!(
                through.len(),
                1,
                "group ({service}, {g}, {inner}) of {members:?} got {through:?}"
            );
            let (w, x) = through[0];
            assert_eq!(
                x.ids.len(),
                1,
                "a shared delivery carries its identifier alone"
            );
            let id = *x.ids.iter().next().unwrap();
            let (member, sq) = ids[&id];
            assert_eq!(*w, member, "the identifier of another session");
            assert_eq!(WHO[*w].1, *service, "a delivery crossed roles");
            assert_eq!(x.qos, sq.min(q));
            *self
                .spread
                .entry((*service, g.clone(), inner.clone()))
                .or_default()
                .entry(*w)
                .or_default() += 1;
        }
        // Nothing else: every delivery is one of the above.
        let shared_ids: BTreeSet<u32> = groups.values().flatten().map(|x| x.1).collect();
        for (w, x) in &got {
            let cl = self.clients[*w].as_ref().unwrap();
            let own: BTreeSet<u32> = cl.subs.values().map(|v| v.0).collect();
            assert!(
                x.ids.iter().all(|i| own.contains(i)),
                "{} got identifiers {:?} it does not hold ({own:?})",
                WHO[*w].0,
                x.ids
            );
            assert!(
                !x.ids.is_empty(),
                "every subscription here has an identifier"
            );
            let _ = &shared_ids;
        }
    }
}

/// A decoded packet, owned.
#[derive(Debug)]
enum P5Owned {
    ConnAck(u8),
    SubAck(u8),
    UnsubAck(u8),
    Publish(Got),
    Other,
}

impl P5Owned {
    fn of(p: &P5<'_>) -> Self {
        match p {
            P5::ConnAck(a) => P5Owned::ConnAck(a.reason as u8),
            P5::SubAck(s) => P5Owned::SubAck(s.reason_codes.first().copied().unwrap_or(0xff)),
            P5::UnsubAck(s) => P5Owned::UnsubAck(s.reason_codes.first().copied().unwrap_or(0xff)),
            P5::Publish(p) => P5Owned::Publish(Got {
                topic: p.topic.into(),
                payload: p.payload.into(),
                qos: p.qos as u8,
                pid: p.packet_id,
                ids: p
                    .properties
                    .iter()
                    .filter_map(|x| match x {
                        Property::SubscriptionIdentifier(i) => Some(i),
                        _ => None,
                    })
                    .collect(),
            }),
            _ => P5Owned::Other,
        }
    }
}

proptest! {
    #![proptest_config(PtConfig {
        cases: 300,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x0275_0001),
        failure_persistence: None,
        ..PtConfig::default()
    })]

    #[test]
    fn shared_groups_and_identifiers_follow_the_model(ops in proptest::collection::vec(op(), 1..150)) {
        let mut w = World::new();
        for i in 0..WHO.len() {
            w.step(&Op::Connect(i));
        }
        for op in &ops {
            w.step(op);
        }
    }
}

/// The round robin spreads a busy group's messages over all its members
/// (a fixed scenario: two services in one group, both on other shards than
/// the group's owner or not, 40 messages).
#[test]
fn the_round_robin_spreads_over_the_members() {
    let mut w = World::new();
    for i in 0..WHO.len() {
        w.step(&Op::Connect(i));
    }
    w.step(&Op::Subscribe(2, 5, 1)); // backend: $share/g/fleet/#
    w.step(&Op::Subscribe(3, 5, 1)); // backend2
    for _ in 0..40 {
        w.step(&Op::Publish(2, 1, 1)); // fleet/x
    }
    let spread = &w.spread[&(true, "g".into(), "fleet/#".into())];
    assert_eq!(spread.values().copied().collect::<Vec<_>>(), [20, 20]);
}
