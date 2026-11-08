//! QoS 2 against a reference model (ADR-271): random sequences of what a
//! persistent device can do (QoS 2 publishes with chosen ids and DUP,
//! PUBREL, every acknowledgement for any id, dropping, reconnecting clean
//! or not) and what the rest of the system does (a backend publishing at
//! each QoS, the broker restarting from its store while the device is
//! away) are applied to a [`Broker`] and to the small model below, written
//! from MQTT 3.1.1 4.3.3 and 4.4 rather than from the broker's code. After
//! every step the packets the device and the backend received must be
//! exactly the model's, and every message the device published must have
//! reached the backend exactly once.
//!
//! MQTT 5.0 (ADR-274): half the cases run the device as a 5.0 client with
//! a Receive Maximum of its own (the broker's window to it), the broker's
//! announced Receive Maximum (a QoS 2 id above it is DISCONNECT 0x93) and a
//! Session Expiry Interval that time (`Advance`) and restarts measure; the
//! backend stays a 3.1.1 client, so every case mixes the versions. A 3.1.1
//! persistent device has the configured default expiry.
//!
//! Shared subscriptions (ADR-275): in half the cases the backend receives
//! through `$share/up/devices/d1/up`, the only member of its group, and
//! must see exactly what it would see through the plain filter.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use proptest::prelude::*;
use proptest::test_runner::{Config as PtConfig, RngAlgorithm, RngSeed};
use urmqtt_broker::{
    Acl, Broker, Config, ConnId, Mqtt5Policy, PersistOp, Qos2Id, StoredMsg, StoredSession as Stored,
};
use urmqtt_mqtt::v5 as m5;
use urmqtt_mqtt::{
    Connect, Limits, Packet, Publish, QoS, Subscribe, SubscribeTopics, decode, encode, encoded_len,
};

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/cmd/#"],
    service_ids: &["backend"],
    service_publish: &["devices/+/cmd/#"],
    service_subscribe: &["devices/#"],
    operator_ids: &[],
};

const WINDOW: usize = 2;
const QUEUE: usize = 3;
const CMD: &str = "devices/d1/cmd/x";
/// The Receive Maximum the broker announces to 5.0 clients.
const RM_IN: usize = 3;
/// Session Expiry Interval of a persistent session, both versions (s).
const EXPIRY: u32 = 5;
const UP: &str = "devices/d1/up";

fn cfg() -> Config {
    Config {
        limits: Limits {
            max_packet_size: 1024,
            max_topic_len: 64,
            max_topic_levels: 8,
            max_client_id_len: 23,
            max_topics_per_packet: 4,
        },
        max_connections: 8,
        max_subscriptions_per_session: 4,
        max_inflight: WINDOW,
        max_queued: QUEUE,
        max_retained_per_device: 4,
        max_retained_bytes: 4096,
        rate_tokens: u32::MAX,
        rate_period_ms: 1,
        max_outbound_bytes: 1 << 20,
        acl: ACL,
        persist: true,
        telemetry: &[],
        fanout: false,
        control_ids: &[],
        plain: None,
        mqtt5: Mqtt5Policy {
            receive_maximum: RM_IN as u16,
            default_session_expiry_s: EXPIRY,
            ..Mqtt5Policy::DEFAULT
        },
        web: None,
        publisher_backpressure: urmqtt_broker::PublisherBackpressure::Single,
    }
}

#[derive(Debug, Clone)]
enum Op {
    /// The device publishes at QoS 2 with this id.
    Publish {
        pid: u16,
        dup: bool,
    },
    PubRel(u16),
    PubAck(u16),
    PubRec(u16),
    PubComp(u16),
    /// The backend publishes a command to the device at this QoS.
    Command(u8),
    /// The device's connection drops (no DISCONNECT).
    Drop,
    /// The device connects (if it is not connected).
    Connect {
        clean: bool,
    },
    /// The broker restarts from its store (only while the device is away).
    Restart,
    /// Time passes (seconds) and the broker ticks: offline sessions expire.
    Advance(u8),
}

fn op() -> impl Strategy<Value = Op> {
    let pid = 1u16..5;
    prop_oneof![
        3 => (pid.clone(), any::<bool>()).prop_map(|(pid, dup)| Op::Publish { pid, dup }),
        2 => pid.clone().prop_map(Op::PubRel),
        1 => pid.clone().prop_map(Op::PubAck),
        2 => pid.clone().prop_map(Op::PubRec),
        2 => pid.prop_map(Op::PubComp),
        3 => (0u8..3).prop_map(Op::Command),
        1 => Just(Op::Drop),
        2 => Just(Op::Connect { clean: false }),
        1 => Just(Op::Connect { clean: true }),
        1 => Just(Op::Restart),
        2 => (0u8..4).prop_map(Op::Advance),
    ]
}

/// A packet as a client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Got {
    ConnAck(bool),
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        pid: Option<u16>,
        dup: bool,
    },
    PubAck(u16),
    PubRec(u16),
    PubRel(u16),
    PubComp(u16),
    SubAck,
    /// A server DISCONNECT (5.0) with this reason code.
    Disconnect(u8),
}

// ---- the reference model --------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// QoS 1 PUBLISH out, PUBACK awaited.
    Ack,
    /// QoS 2 PUBLISH out, PUBREC awaited.
    Rec,
    /// PUBREL out, PUBCOMP awaited.
    Comp,
}

#[derive(Debug, Clone)]
struct Flight {
    pid: u16,
    stage: Stage,
    payload: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
struct Model {
    /// A session exists (persistent, or clean while connected).
    exists: bool,
    online: bool,
    clean: bool,
    /// Inbound: ids held until PUBREL.
    held: BTreeSet<u16>,
    /// Outbound, in the order first sent.
    flights: Vec<Flight>,
    queue: VecDeque<(Vec<u8>, u8)>,
    next_pid: u16,
    /// The window of deliveries: `WINDOW`, and for a 5.0 device at most its
    /// Receive Maximum.
    window: usize,
    /// When the device went offline (ms).
    offline_at: u64,
}

impl Model {
    fn reset(&mut self) {
        *self = Model {
            next_pid: 1,
            window: self.window,
            ..Model::default()
        };
    }

    fn alloc(&mut self) -> u16 {
        loop {
            let id = self.next_pid;
            self.next_pid = if id == u16::MAX { 1 } else { id + 1 };
            if !self.flights.iter().any(|f| f.pid == id) {
                return id;
            }
        }
    }

    fn send(&mut self, payload: Vec<u8>, qos: u8, out: &mut Vec<Got>) {
        let pid = self.alloc();
        self.flights.push(Flight {
            pid,
            stage: if qos == 2 { Stage::Rec } else { Stage::Ack },
            payload: payload.clone(),
        });
        out.push(Got::Publish {
            topic: CMD.into(),
            payload,
            qos,
            pid: Some(pid),
            dup: false,
        });
    }

    fn pump(&mut self, out: &mut Vec<Got>) {
        while self.online && self.flights.len() < self.window {
            let Some((p, q)) = self.queue.pop_front() else {
                return;
            };
            self.send(p, q, out);
        }
    }

    /// The backend's command at `qos` reaches a QoS 2 subscription.
    fn command(&mut self, payload: Vec<u8>, qos: u8, out: &mut Vec<Got>) {
        if !self.exists {
            return;
        }
        if qos == 0 {
            if self.online {
                out.push(Got::Publish {
                    topic: CMD.into(),
                    payload,
                    qos: 0,
                    pid: None,
                    dup: false,
                });
            }
            return;
        }
        if self.online && self.flights.len() < self.window && self.queue.is_empty() {
            self.send(payload, qos, out);
        } else if self.queue.len() < QUEUE {
            self.queue.push_back((payload, qos));
        }
    }
}

// ---- the system under test -------------------------------------------------

struct Client {
    c: ConnId,
    rx: Vec<u8>,
    v5: bool,
}

fn wire(p: &Packet<'_>) -> Vec<u8> {
    let mut v = vec![0u8; encoded_len(p)];
    encode(p, &mut v).expect("encodable");
    v
}

fn wire5(p: &m5::Packet<'_>) -> Vec<u8> {
    let mut v = vec![0u8; m5::encoded_len(p).expect("encodable")];
    m5::encode(p, &mut v).expect("encodable");
    v
}

/// The bytes of `p` in the client's version (the 3.1.1 packets the model
/// sends have 5.0 forms with no properties and reason 0x00).
fn wire_for(cl: &Client, p: &Packet<'_>) -> Vec<u8> {
    if !cl.v5 {
        return wire(p);
    }
    let ack = |packet_id| m5::Ack {
        packet_id,
        reason: m5::ReasonCode::Success,
        properties: m5::Properties::EMPTY,
    };
    let opts;
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
        Packet::Subscribe(s) => {
            opts = s
                .topics
                .iter()
                .map(|(f, q)| (f, m5::SubscriptionOptions::qos(q)))
                .collect::<Vec<_>>();
            m5::Packet::Subscribe(m5::Subscribe {
                packet_id: s.packet_id,
                properties: m5::Properties::EMPTY,
                topics: m5::SubscribeTopics::List(&opts),
            })
        }
        other => panic!("no 5.0 form for {other:?} in this model"),
    };
    wire5(&p5)
}

fn recv5(b: &mut Broker, cl: &mut Client) -> Vec<Got> {
    let out = b.output(cl.c).to_vec();
    b.consumed(cl.c, out.len());
    cl.rx.extend_from_slice(&out);
    let mut got = Vec::new();
    loop {
        match m5::decode(&cl.rx, &m5::Limits::PROTOCOL_MAX) {
            Ok((p, n)) => {
                let ok = |a: m5::Ack<'_>| {
                    assert_eq!(a.reason, m5::ReasonCode::Success, "{a:?}");
                    a.packet_id
                };
                got.push(match p {
                    m5::Packet::ConnAck(a) => Got::ConnAck(a.session_present),
                    m5::Packet::Publish(p) => Got::Publish {
                        topic: p.topic.into(),
                        payload: p.payload.into(),
                        qos: p.qos as u8,
                        pid: p.packet_id,
                        dup: p.dup,
                    },
                    m5::Packet::PubAck(a) => Got::PubAck(ok(a)),
                    m5::Packet::PubRec(a) => Got::PubRec(ok(a)),
                    m5::Packet::PubRel(a) => Got::PubRel(ok(a)),
                    m5::Packet::PubComp(a) => Got::PubComp(ok(a)),
                    m5::Packet::SubAck(_) => Got::SubAck,
                    m5::Packet::Disconnect(d) => Got::Disconnect(d.reason as u8),
                    other => panic!("unexpected {other:?}"),
                });
                cl.rx.drain(..n);
            }
            Err(m5::Error::Incomplete(_)) => return got,
            Err(e) => panic!("{e:?}"),
        }
    }
}

fn recv(b: &mut Broker, cl: &mut Client) -> Vec<Got> {
    if cl.v5 {
        return recv5(b, cl);
    }
    let out = b.output(cl.c).to_vec();
    b.consumed(cl.c, out.len());
    cl.rx.extend_from_slice(&out);
    let mut got = Vec::new();
    loop {
        match decode(&cl.rx, &Limits::PROTOCOL_MAX) {
            Ok((p, n)) => {
                got.push(match p {
                    Packet::ConnAck(a) => Got::ConnAck(a.session_present),
                    Packet::Publish(p) => Got::Publish {
                        topic: p.topic.into(),
                        payload: p.payload.into(),
                        qos: p.qos as u8,
                        pid: p.packet_id,
                        dup: p.dup,
                    },
                    Packet::PubAck(i) => Got::PubAck(i),
                    Packet::PubRec(i) => Got::PubRec(i),
                    Packet::PubRel(i) => Got::PubRel(i),
                    Packet::PubComp(i) => Got::PubComp(i),
                    Packet::SubAck(_) => Got::SubAck,
                    other => panic!("unexpected {other:?}"),
                });
                cl.rx.drain(..n);
            }
            Err(urmqtt_mqtt::Error::Incomplete(_)) => return got,
            Err(e) => panic!("{e:?}"),
        }
    }
}

/// Connects `id`: 3.1.1 (`rm` None), or 5.0 with Receive Maximum `rm` and
/// Session Expiry `EXPIRY` (0 for a clean session).
fn connect(b: &mut Broker, id: &str, clean: bool, rm: Option<u16>, now: u64) -> Client {
    let c = b.open(now).expect("a free connection");
    let bytes = match rm {
        None => wire(&Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: clean,
            keep_alive: 0,
            client_id: id,
            will: None,
            username: None,
            password: None,
        })),
        Some(rm) => {
            let props = [
                m5::Property::SessionExpiryInterval(if clean { 0 } else { EXPIRY }),
                m5::Property::ReceiveMaximum(rm),
            ];
            wire5(&m5::Packet::Connect(m5::Connect {
                clean_start: clean,
                keep_alive: 0,
                properties: m5::Properties::List(&props),
                client_id: id,
                will: None,
                username: None,
                password: None,
            }))
        }
    };
    b.input(c, &bytes, now);
    Client {
        c,
        rx: Vec::new(),
        v5: rm.is_some(),
    }
}

/// The durable store, as the SQLite store applies the persist ops.
#[derive(Default)]
struct Store {
    sessions: BTreeMap<String, StoredSession>,
}

#[derive(Default)]
struct StoredSession {
    subs: Vec<(String, QoS)>,
    queue: Vec<(String, Vec<u8>, QoS, Option<u16>)>,
    ids: BTreeSet<Qos2Id>,
    expiry: Option<u32>,
    /// When it went offline, wall-clock seconds (the world's clock).
    offline_s: Option<u64>,
}

impl Store {
    fn apply(&mut self, b: &mut Broker, now: u64) {
        for op in b.drain_persist() {
            match op {
                PersistOp::SessionUpsert {
                    client_id,
                    expiry_s,
                } => {
                    let s = self.sessions.entry(client_id.to_string()).or_default();
                    s.expiry = Some(expiry_s);
                    s.offline_s = None;
                }
                PersistOp::SessionDelete { client_id } => {
                    self.sessions.remove(&*client_id);
                }
                PersistOp::Subscribe {
                    client_id,
                    filter,
                    qos,
                    ..
                } => {
                    let s = self.sessions.get_mut(&*client_id).expect("FK");
                    s.subs.retain(|(f, _)| *f != *filter);
                    s.subs.push((filter.to_string(), qos));
                }
                PersistOp::Unsubscribe { client_id, filter } => {
                    if let Some(s) = self.sessions.get_mut(&*client_id) {
                        s.subs.retain(|(f, _)| *f != *filter);
                    }
                }
                PersistOp::QueuePush {
                    client_id,
                    msg,
                    qos,
                    pid,
                } => {
                    let s = self.sessions.get_mut(&*client_id).expect("FK");
                    s.queue
                        .push((msg.topic.to_string(), msg.payload.to_vec(), qos, pid));
                }
                PersistOp::Qos2 { client_id, id } => {
                    let s = self.sessions.get_mut(&*client_id).expect("FK");
                    assert!(s.ids.insert(id), "primary key ({client_id}, {id:?})");
                }
                PersistOp::SessionOffline { client_id } => {
                    let s = self.sessions.get_mut(&*client_id).expect("FK");
                    s.offline_s = Some(now / 1000);
                }
                PersistOp::QueueClear { client_id } => {
                    if let Some(s) = self.sessions.get_mut(&*client_id) {
                        s.queue.clear();
                        s.ids.clear();
                    }
                }
                PersistOp::Retain { .. } => {}
            }
        }
    }

    /// A new broker from the store at `now`: a session whose expiry ran out
    /// while it was down is not restored.
    fn restore(&self, now: u64) -> Broker {
        let mut b = Broker::new(cfg());
        for (id, s) in &self.sessions {
            let offline_for_s = s.offline_s.map_or(0, |t| now / 1000 - t);
            let expiry = s.expiry.expect("written with schema 4");
            let ok = b.restore_session_v5(
                id,
                Stored {
                    expiry_s: Some(expiry),
                    offline_for_s,
                    now_ms: now,
                },
                s.subs.iter().map(|(f, q)| (f.as_str(), *q as u8)),
                s.queue
                    .iter()
                    .map(|(t, p, qos, pid)| StoredMsg::plain(t, p, *qos, *pid)),
                s.ids.iter().copied(),
            );
            assert_eq!(ok, offline_for_s < u64::from(expiry), "restore {id}");
        }
        b
    }
}

struct World {
    /// The backend receives through a shared subscription (ADR-275).
    shared: bool,
    b: Broker,
    store: Store,
    m: Model,
    dev: Option<Client>,
    backend: Client,
    seq: u32,
    /// Device publishes routed so far, by payload.
    routed: BTreeMap<Vec<u8>, u32>,
    /// What each held id of the device carried when it was first sent.
    sent: BTreeMap<u16, Vec<u8>>,
    backend_pid: u16,
    /// The device's version: 3.1.1, or 5.0 with this Receive Maximum.
    rm: Option<u16>,
    /// The world's clock (ms, whole seconds).
    now: u64,
}

/// The backend, subscribed to what the device publishes: directly, or
/// (`shared`) as the one member of a shared group (ADR-275), which must
/// make no difference to what it receives.
fn backend(b: &mut Broker, now: u64, shared: bool) -> Client {
    let mut cl = connect(b, "backend", true, None, now);
    let filter = if shared {
        "$share/up/devices/d1/up"
    } else {
        UP
    };
    b.input(
        cl.c,
        &wire(&Packet::Subscribe(Subscribe {
            packet_id: 1,
            topics: SubscribeTopics::List(&[(filter, QoS::AtMostOnce)]),
        })),
        now,
    );
    assert_eq!(recv(b, &mut cl), vec![Got::ConnAck(false), Got::SubAck]);
    cl
}

impl World {
    fn new(rm: Option<u16>, shared: bool) -> Self {
        let mut b = Broker::new(cfg());
        let backend = backend(&mut b, 0, shared);
        let mut m = Model {
            window: rm.map_or(WINDOW, |r| WINDOW.min(usize::from(r))),
            ..Model::default()
        };
        m.reset();
        World {
            b,
            store: Store::default(),
            m,
            dev: None,
            backend,
            seq: 0,
            routed: BTreeMap::new(),
            sent: BTreeMap::new(),
            backend_pid: 0,
            rm,
            now: 0,
            shared,
        }
    }

    fn payload(&mut self) -> Vec<u8> {
        self.seq += 1;
        self.seq.to_be_bytes().to_vec()
    }

    fn dev_send(&mut self, p: &Packet<'_>) -> Vec<Got> {
        let Some(d) = self.dev.as_mut() else {
            return Vec::new();
        };
        self.b.input(d.c, &wire_for(d, p), self.now);
        recv(&mut self.b, d)
    }

    /// The device's connection is gone (dropped, or closed by the broker).
    fn offline(&mut self) {
        if let Some(d) = self.dev.take() {
            self.b.closed(d.c, self.now);
        }
        self.m.online = false;
        self.m.offline_at = self.now;
        if self.m.clean {
            self.m.reset();
        }
    }

    fn step(&mut self, op: &Op) {
        let mut want = Vec::new();
        let got = match *op {
            Op::Publish { pid, dup } => {
                if !self.m.online {
                    return;
                }
                let held = self.m.held.contains(&pid);
                // A 5.0 device above the broker's Receive Maximum: 0x93, and
                // the connection is closed (the message is not routed).
                if self.rm.is_some() && !held && self.m.held.len() >= RM_IN {
                    let payload = self.payload();
                    let got = self.dev_send(&Packet::Publish(Publish {
                        dup,
                        qos: QoS::ExactlyOnce,
                        retain: false,
                        topic: UP,
                        packet_id: Some(pid),
                        payload: &payload,
                    }));
                    assert_eq!(got, [Got::Disconnect(0x93)], "after {op:?}");
                    self.offline();
                    return self.after(op);
                }
                let payload = if held && dup {
                    // A real duplicate carries what the first one did.
                    self.sent
                        .get(&pid)
                        .cloned()
                        .unwrap_or_else(|| self.payload())
                } else {
                    self.payload()
                };
                if !held {
                    self.m.held.insert(pid);
                    self.sent.insert(pid, payload.clone());
                    *self.routed.entry(payload.clone()).or_default() += 1;
                }
                want.push(Got::PubRec(pid));
                self.dev_send(&Packet::Publish(Publish {
                    dup,
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: UP,
                    packet_id: Some(pid),
                    payload: &payload,
                }))
            }
            Op::PubRel(pid) => {
                if !self.m.online {
                    return;
                }
                self.m.held.remove(&pid);
                want.push(Got::PubComp(pid));
                self.dev_send(&Packet::PubRel(pid))
            }
            Op::PubAck(pid) => {
                if !self.m.online {
                    return;
                }
                let m = &mut self.m;
                if let Some(i) = m
                    .flights
                    .iter()
                    .position(|f| f.pid == pid && f.stage == Stage::Ack)
                {
                    m.flights.remove(i);
                    m.pump(&mut want);
                }
                self.dev_send(&Packet::PubAck(pid))
            }
            Op::PubRec(pid) => {
                if !self.m.online {
                    return;
                }
                let m = &mut self.m;
                match m.flights.iter_mut().find(|f| f.pid == pid) {
                    Some(f) if f.stage == Stage::Ack => {}
                    Some(f) => {
                        f.stage = Stage::Comp;
                        want.push(Got::PubRel(pid));
                    }
                    None => want.push(Got::PubRel(pid)),
                }
                self.dev_send(&Packet::PubRec(pid))
            }
            Op::PubComp(pid) => {
                if !self.m.online {
                    return;
                }
                let m = &mut self.m;
                if let Some(i) = m
                    .flights
                    .iter()
                    .position(|f| f.pid == pid && f.stage == Stage::Comp)
                {
                    m.flights.remove(i);
                    m.pump(&mut want);
                }
                self.dev_send(&Packet::PubComp(pid))
            }
            Op::Command(q) => {
                let payload = self.payload();
                self.m.command(payload.clone(), q, &mut want);
                let qos = QoS::from_bits(q).expect("0..3");
                self.backend_pid = self.backend_pid % 1000 + 1;
                let pid = (q > 0).then_some(self.backend_pid);
                self.b.input(
                    self.backend.c,
                    &wire(&Packet::Publish(Publish {
                        dup: false,
                        qos,
                        retain: false,
                        topic: CMD,
                        packet_id: pid,
                        payload: &payload,
                    })),
                    self.now,
                );
                if let (QoS::ExactlyOnce, Some(p)) = (qos, pid) {
                    self.b
                        .input(self.backend.c, &wire(&Packet::PubRel(p)), self.now);
                }
                let _ = recv(&mut self.b, &mut self.backend);
                match self.dev.as_mut() {
                    Some(d) => recv(&mut self.b, d),
                    None => Vec::new(),
                }
            }
            Op::Drop => {
                if self.dev.is_none() {
                    return;
                }
                self.offline();
                Vec::new()
            }
            Op::Advance(secs) => {
                self.now += u64::from(secs) * 1000;
                self.b.tick(self.now);
                // An offline session ends when its expiry has passed.
                let m = &mut self.m;
                if m.exists && !m.online && self.now - m.offline_at >= u64::from(EXPIRY) * 1000 {
                    m.reset();
                }
                Vec::new()
            }
            Op::Connect { clean } => {
                if self.dev.is_some() {
                    return;
                }
                let present = self.m.exists && !clean;
                if !present {
                    self.m.reset();
                }
                self.m.exists = true;
                self.m.online = true;
                self.m.clean = clean;
                want.push(Got::ConnAck(present));
                if present {
                    for f in self.m.flights.clone() {
                        want.push(match f.stage {
                            Stage::Comp => Got::PubRel(f.pid),
                            s => Got::Publish {
                                topic: CMD.into(),
                                payload: f.payload,
                                qos: if s == Stage::Rec { 2 } else { 1 },
                                pid: Some(f.pid),
                                dup: true,
                            },
                        });
                    }
                    self.m.pump(&mut want);
                }
                let mut d = connect(&mut self.b, "d1", clean, self.rm, self.now);
                let mut got = recv(&mut self.b, &mut d);
                if !present {
                    let sub = Packet::Subscribe(Subscribe {
                        packet_id: 1,
                        topics: SubscribeTopics::List(&[("devices/d1/cmd/#", QoS::ExactlyOnce)]),
                    });
                    self.b.input(d.c, &wire_for(&d, &sub), self.now);
                    got.extend(recv(&mut self.b, &mut d));
                    want.push(Got::SubAck);
                }
                self.dev = Some(d);
                got
            }
            Op::Restart => {
                if self.dev.is_some() {
                    return;
                }
                self.store.apply(&mut self.b, self.now);
                self.b = self.store.restore(self.now);
                self.backend = backend(&mut self.b, self.now, self.shared);
                // A clean session never reaches the store.
                if self.m.clean {
                    self.m.reset();
                }
                // What a restart changes: released ids are restored before
                // the messages still in flight, and the ids start again at 1.
                let (rel, rest): (Vec<Flight>, Vec<Flight>) = self
                    .m
                    .flights
                    .drain(..)
                    .partition(|f| f.stage == Stage::Comp);
                self.m.flights = rel.into_iter().chain(rest).collect();
                self.m.next_pid = 1;
                Vec::new()
            }
        };
        assert_eq!(got, want, "after {op:?}; model {:?}", self.m);
        self.after(op);
    }

    /// What every step checks afterwards.
    fn after(&mut self, op: &Op) {
        let _ = op;
        self.store.apply(&mut self.b, self.now);
        // Exactly once: every device publish reached the backend once.
        let mut seen: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
        for g in recv(&mut self.b, &mut self.backend) {
            if let Got::Publish { payload, .. } = g {
                *seen.entry(payload).or_default() += 1;
            }
        }
        for (p, n) in seen {
            assert_eq!(n, 1, "a publish routed {n} times in one step");
            let e = self.routed.get(&p).copied().unwrap_or(0);
            assert_eq!(e, 1, "routed {p:?} that the model did not route");
            self.routed.insert(p, 2);
        }
    }

    fn finish(&mut self) {
        // Everything the model routed reached the backend.
        assert!(
            self.routed.values().all(|&n| n == 2),
            "routed by the model but never delivered: {:?}",
            self.routed
        );
    }
}

proptest! {
    #![proptest_config(PtConfig {
        cases: 400,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x0271_0002),
        failure_persistence: None,
        ..PtConfig::default()
    })]

    #[test]
    fn the_broker_follows_the_reference_model(
        ops in proptest::collection::vec(op(), 1..120),
        rm in prop_oneof![Just(None), (1u16..4).prop_map(Some)],
        shared in any::<bool>(),
    ) {
        let mut w = World::new(rm, shared);
        w.step(&Op::Connect { clean: false });
        for op in &ops {
            w.step(op);
        }
        w.finish();
    }
}
