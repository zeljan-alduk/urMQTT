//! Stateful ACL fuzzing (H5): random operation sequences against the broker,
//! checked against an independent oracle of what each identity may do.
//!
//! The oracle restates the access rules of the configuration below in the
//! plainest form (prefix checks, no wildcard matching), so it does not share
//! code with `acl.rs`. Every message the test publishes carries a tag in its
//! payload that names its publisher, topic and whether the oracle allows it.
//! After each step every byte the broker hands out is decoded and checked:
//!
//! 1. a device receives only `devices/<own id>/cmd/...`, nobody but an
//!    authenticated operator receives `$SYS/...`, nobody receives
//!    `$urmqtt/...` (no device receives another device's topics);
//! 2. a message the oracle forbids never appears anywhere: not delivered, not
//!    routed to other shards, not in the telemetry log, not in the persist ops;
//! 3. control messages come only from a control identity, and `$SYS`
//!    requests only from an authenticated operator;
//! 4. a TLS identity cannot connect under another client id, and a will the
//!    publisher could not publish is refused.
//!
//! Environment: `ACL_FUZZ_SECS` (default 3), `ACL_FUZZ_SEED` (default 1),
//! `ACL_FUZZ_OPS` (operations per sequence, default 300). Run it long with
//! `make acl-fuzz` (default 600 s).

use std::collections::HashMap;
use std::time::{Duration, Instant};
use urmqtt_broker::{Acl, Broker, Config, ConnId, PersistOp};
use urmqtt_mqtt::{
    Connect, ConnectReturnCode, Limits, Packet, Publish, QoS, Subscribe, SubscribeTopics,
    Unsubscribe, UnsubscribeTopics, Will, decode, encode, encoded_len,
};

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/cmd/#"],
    service_ids: &["backend"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    // `$SYS/#` is configured on purpose: only an operator may reach it.
    service_subscribe: &["devices/#", "fleet/#", "$SYS/#", "$urmqtt/#"],
    operator_ids: &["ops"],
};

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
        max_subscriptions_per_session: 6,
        max_inflight: 2,
        max_queued: 3,
        max_retained_per_device: 4,
        max_retained_bytes: 4096,
        rate_tokens: 1000,
        rate_period_ms: 1000,
        max_outbound_bytes: 8 * 1024,
        acl: ACL,
        persist: true,
        telemetry: &["devices/+/telemetry/#"],
        fanout: true,
        control_ids: &["backend"],
    }
}

/// Small deterministic generator (xorshift64*), so a failure replays from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

const IDS: &[&str] = &["d1", "d2", "d3", "backend", "ops", "bd1"];
const TOPICS: &[&str] = &[
    "devices/d1/cmd/x",
    "devices/d1/cmd",
    "devices/d1/telemetry/t",
    "devices/d1/state",
    "devices/d2/cmd/x",
    "devices/d2/cmd/y/z",
    "devices/d2/telemetry/t",
    "devices/d3/state",
    "devices/ops/cmd/x",
    "devices/backend/cmd/x",
    "devices//cmd/x",
    "Devices/d1/cmd/x",
    "fleet/all",
    "fleet/d1",
    "other/x",
    "provision/bd1/x",
    "provision/d1/x",
    "provision/bd1",
    "$SYS/console/in",
    "$SYS/query/info",
    "$SYS/stats",
    "$SYS/console/out",
    "$urmqtt/control",
    "$urmqtt/control/x",
    "$urmqtt",
];
const FILTERS: &[&str] = &[
    "#",
    "+/#",
    "+/+/cmd/#",
    "devices/#",
    "devices/+/cmd/#",
    "devices/+/#",
    "devices/d1/#",
    "devices/d1/cmd/#",
    "devices/d2/cmd/#",
    "devices/d2/#",
    "devices/+/telemetry/#",
    "fleet/#",
    "fleet/+",
    "provision/#",
    "provision/bd1/#",
    "$SYS/#",
    "$SYS/console/out",
    "$urmqtt/#",
    "$urmqtt/control",
    "$+/#",
    "devices/d1/cmd/x",
    "devices/d2/cmd/x",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Device,
    Service,
    Operator,
    Bootstrap,
}

/// What the oracle says about one published message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    /// May be routed to subscribers (and logged as telemetry).
    Routed,
    /// May reach the control handler.
    Control,
    /// May reach the kernel as an operator request.
    Sys,
    /// Nothing may ever come out of it.
    Nothing,
}

fn has_prefix(topic: &str, prefix: &str) -> bool {
    topic == prefix || topic.starts_with(&format!("{prefix}/"))
}

fn is_reserved(topic: &str) -> bool {
    topic.split('/').next() == Some("$urmqtt")
}
fn is_sys(topic: &str) -> bool {
    topic.split('/').next() == Some("$SYS")
}

/// Where the oracle lets `role`/`id` publish.
fn may_publish(role: Role, id: &str, topic: &str) -> Verdict {
    if is_reserved(topic) {
        let control = role != Role::Bootstrap && id == "backend" && topic == "$urmqtt/control";
        return if control {
            Verdict::Control
        } else {
            Verdict::Nothing
        };
    }
    if is_sys(topic) {
        let ok =
            role == Role::Operator && (topic == "$SYS/console/in" || topic == "$SYS/query/info");
        return if ok { Verdict::Sys } else { Verdict::Nothing };
    }
    let ok = match role {
        Role::Device => has_prefix(topic, &format!("devices/{id}")),
        Role::Service => {
            has_prefix(topic, "fleet")
                || topic
                    .strip_prefix("devices/")
                    .and_then(|r| r.split_once('/'))
                    .is_some_and(|(_, rest)| has_prefix(rest, "cmd"))
        }
        Role::Operator => false,
        Role::Bootstrap => has_prefix(topic, &format!("provision/{id}")),
    };
    if ok {
        Verdict::Routed
    } else {
        Verdict::Nothing
    }
}

/// Where the oracle lets `role`/`id` receive messages from.
fn may_receive(role: Role, id: &str, topic: &str) -> bool {
    if is_reserved(topic) {
        return false;
    }
    if is_sys(topic) {
        return role == Role::Operator;
    }
    match role {
        Role::Device => has_prefix(topic, &format!("devices/{id}/cmd")),
        Role::Service => has_prefix(topic, "devices") || has_prefix(topic, "fleet"),
        Role::Operator => false,
        Role::Bootstrap => has_prefix(topic, &format!("provision/{id}")),
    }
}

/// The client side of one connection.
struct Conn {
    id: ConnId,
    /// The identity bound before CONNECT (TLS), if any, and whether it is a
    /// bootstrap identity.
    tls: Option<(String, bool)>,
    /// Set when CONNECT was sent: the id and oracle role.
    pending: Option<(String, Role)>,
    /// Set when the broker accepted CONNECT.
    active: Option<(String, Role)>,
    rx: Vec<u8>,
}

#[derive(Default)]
struct Stats {
    sequences: u64,
    ops: u64,
    delivered: u64,
    forbidden_published: u64,
    allowed_published: u64,
    control_seen: u64,
    sys_seen: u64,
    connects_ok: u64,
    connects_refused: u64,
    wills_refused: u64,
    subs_granted: u64,
    subs_refused: u64,
}

struct Run<'a> {
    seed: u64,
    rng: Rng,
    b: Broker,
    conns: Vec<Option<Conn>>,
    /// payload tag -> (publisher id, role, topic, verdict)
    tags: HashMap<u64, (String, Role, String, Verdict)>,
    next_tag: u64,
    now: u64,
    pid: u16,
    log: Vec<String>,
    st: &'a mut Stats,
}

fn payload(tag: u64) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[..4].copy_from_slice(b"TAG:");
    p[4..].copy_from_slice(&tag.to_le_bytes());
    p
}

impl Run<'_> {
    fn fail(&self, what: &str) -> ! {
        let tail = self.log.len().saturating_sub(40);
        panic!(
            "ACL invariant violated: {what}\nseed {} (replay: ACL_FUZZ_SEED={} ACL_FUZZ_SECS=0)\nlast operations:\n{}",
            self.seed,
            self.seed,
            self.log[tail..].join("\n")
        );
    }

    fn send(&mut self, slot: usize, p: &Packet<'_>) {
        let mut out = vec![0u8; encoded_len(p)];
        encode(p, &mut out).unwrap();
        let id = self.conns[slot].as_ref().unwrap().id;
        if self.rng.chance(30) {
            for byte in &out {
                self.b.input(id, std::slice::from_ref(byte), self.now);
            }
        } else {
            self.b.input(id, &out, self.now);
        }
    }

    fn oracle_role(c: &Conn, id: &str) -> Role {
        match &c.tls {
            Some((_, true)) => Role::Bootstrap,
            tls => match id {
                "backend" => Role::Service,
                "ops" if tls.is_some() => Role::Operator,
                _ => Role::Device,
            },
        }
    }

    fn step(&mut self) {
        self.st.ops += 1;
        self.now += self.rng.below(400) as u64;
        let slot = self.rng.below(self.conns.len());
        let op = self.rng.below(100);
        // Open a connection and CONNECT.
        if self.conns[slot].is_none() {
            let Some(id) = self.b.open(self.now) else {
                return;
            };
            let mut tls = None;
            if self.rng.chance(60) {
                let ident = (*self.rng.pick(IDS)).to_string();
                let bootstrap = ident == "bd1" || self.rng.chance(5);
                self.b.set_identity(id, &ident, bootstrap);
                tls = Some((ident, bootstrap));
            }
            self.log
                .push(format!("open slot {slot} conn {id} tls {tls:?}"));
            self.conns[slot] = Some(Conn {
                id,
                tls,
                pending: None,
                active: None,
                rx: Vec::new(),
            });
            self.connect(slot);
            return;
        }
        let active = self.conns[slot].as_ref().unwrap().active.clone();
        match op {
            0..=6 => self.close(slot, op < 3),
            7..=10 => {
                self.log.push(format!("tick {}", self.now));
                self.b.tick(self.now);
            }
            11..=12 => self.b.shrink(),
            13..=17 => self.connect(slot),
            18..=52 => self.publish(slot, &active),
            53..=77 => self.subscribe(slot),
            78..=84 => {
                let f = (*self.rng.pick(FILTERS)).to_string();
                self.log.push(format!("slot {slot} unsubscribe {f}"));
                self.pid = self.pid.wrapping_add(1).max(1);
                let list = [f.as_str()];
                let p = Packet::Unsubscribe(Unsubscribe {
                    packet_id: self.pid,
                    topics: UnsubscribeTopics::List(&list),
                });
                self.send(slot, &p);
            }
            _ => {
                self.log.push(format!("slot {slot} pingreq"));
                self.send(slot, &Packet::PingReq);
            }
        }
    }

    fn close(&mut self, slot: usize, polite: bool) {
        self.log.push(format!("slot {slot} close polite={polite}"));
        if polite {
            self.send(slot, &Packet::Disconnect);
        }
        let c = self.conns[slot].take().unwrap();
        self.b.closed(c.id, self.now);
    }

    fn connect(&mut self, slot: usize) {
        let c = self.conns[slot].as_ref().unwrap();
        // A TLS client mostly connects under its own identity.
        let id = match &c.tls {
            Some((ident, _)) if self.rng.chance(85) => ident.clone(),
            _ => (*self.rng.pick(IDS)).to_string(),
        };
        let role = Self::oracle_role(c, &id);
        let clean = self.rng.chance(50);
        let mut will = None;
        if self.rng.chance(35) {
            let topic = *self.rng.pick(TOPICS);
            let v = may_publish(role, &id, topic);
            let tag = self.new_tag(&id, role, topic, v);
            will = Some((topic, tag, v));
        }
        let pl = will.map(|(_, tag, _)| payload(tag));
        let retain = self.rng.chance(40);
        let wm = will.map(|(topic, ..)| Will {
            topic,
            payload: pl.as_ref().map_or(&[][..], |p| &p[..]),
            qos: QoS::AtLeastOnce,
            retain,
        });
        self.log.push(format!(
            "slot {slot} connect id {id} clean {clean} role {role:?} will {:?}",
            wm.map(|w| w.topic)
        ));
        let p = Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: clean,
            keep_alive: 10,
            client_id: &id,
            will: wm,
            username: None,
            password: None,
        });
        if let Some(c) = self.conns[slot].as_mut() {
            c.pending = Some((id.clone(), role));
        }
        self.send(slot, &p);
        // A will the oracle forbids must have been refused.
        if let Some((topic, _, Verdict::Nothing)) = will {
            let cid = self.conns[slot].as_ref().unwrap().id;
            let out = self.b.output(cid).to_vec();
            if let Ok((Packet::ConnAck(a), _)) = decode(&out, &Limits::PROTOCOL_MAX)
                && a.code == ConnectReturnCode::Accepted
            {
                self.fail(&format!("will on {topic} accepted for {id} ({role:?})"));
            }
            self.st.wills_refused += 1;
        }
    }

    fn new_tag(&mut self, id: &str, role: Role, topic: &str, v: Verdict) -> u64 {
        self.next_tag += 1;
        self.tags
            .insert(self.next_tag, (id.to_string(), role, topic.to_string(), v));
        self.next_tag
    }

    fn publish(&mut self, slot: usize, active: &Option<(String, Role)>) {
        let Some((id, role)) = active.clone() else {
            return;
        };
        // Mostly topics near the identity's own rights.
        let topic = if self.rng.chance(40) {
            match role {
                Role::Device => format!(
                    "devices/{id}/{}",
                    self.rng.pick(&["cmd/x", "telemetry/t", "state"])
                ),
                Role::Service => format!("devices/{}/cmd/x", self.rng.pick(&["d1", "d2", "d3"])),
                Role::Operator => (*self.rng.pick(&["$SYS/console/in", "$SYS/query/info"])).into(),
                Role::Bootstrap => format!("provision/{id}/x"),
            }
        } else {
            (*self.rng.pick(TOPICS)).to_string()
        };
        let v = may_publish(role, &id, &topic);
        if v == Verdict::Nothing {
            self.st.forbidden_published += 1;
        } else {
            self.st.allowed_published += 1;
        }
        let tag = self.new_tag(&id, role, &topic, v);
        let pl = payload(tag);
        let qos = if self.rng.chance(50) {
            QoS::AtLeastOnce
        } else {
            QoS::AtMostOnce
        };
        self.pid = self.pid.wrapping_add(1).max(1);
        let retain = self.rng.chance(35);
        self.log.push(format!(
            "slot {slot} ({id} {role:?}) publish {topic} qos {qos:?} retain {retain} tag {tag} verdict {v:?}"
        ));
        let p = Packet::Publish(Publish {
            dup: false,
            qos,
            retain,
            topic: &topic,
            packet_id: (qos == QoS::AtLeastOnce).then_some(self.pid),
            payload: &pl,
        });
        self.send(slot, &p);
    }

    fn subscribe(&mut self, slot: usize) {
        let n = 1 + self.rng.below(3);
        let mut filters: Vec<(&str, QoS)> = Vec::new();
        for _ in 0..n {
            let q = if self.rng.chance(50) {
                QoS::AtLeastOnce
            } else {
                QoS::AtMostOnce
            };
            filters.push((*self.rng.pick(FILTERS), q));
        }
        self.pid = self.pid.wrapping_add(1).max(1);
        self.log.push(format!("slot {slot} subscribe {filters:?}"));
        let p = Packet::Subscribe(Subscribe {
            packet_id: self.pid,
            topics: SubscribeTopics::List(&filters),
        });
        self.send(slot, &p);
    }

    /// Reads everything the broker produced and checks the invariants.
    fn drain(&mut self) {
        for slot in 0..self.conns.len() {
            let Some(c) = self.conns[slot].as_mut() else {
                continue;
            };
            let out = self.b.output(c.id).to_vec();
            self.b.consumed(c.id, out.len());
            c.rx.extend_from_slice(&out);
            let mut acks = Vec::new();
            let mut checks = Vec::new();
            let mut connack = None;
            let mut sub_ok = 0u64;
            let mut sub_no = 0u64;
            let mut bad = None;
            loop {
                match decode(&c.rx, &Limits::PROTOCOL_MAX) {
                    Ok((p, n)) => {
                        match p {
                            Packet::ConnAck(a) => connack = Some(a.code),
                            Packet::Publish(p) => {
                                checks.push((p.topic.to_string(), p.payload.to_vec()));
                                if let Some(id) = p.packet_id {
                                    acks.push(id);
                                }
                            }
                            Packet::SubAck(s) => {
                                for rc in s.return_codes {
                                    if *rc == 0x80 {
                                        sub_no += 1;
                                    } else {
                                        sub_ok += 1;
                                    }
                                }
                            }
                            _ => {}
                        }
                        c.rx.drain(..n);
                    }
                    Err(urmqtt_mqtt::Error::Incomplete(_)) => break,
                    Err(e) => {
                        bad = Some(format!("broker produced an undecodable packet: {e:?}"));
                        break;
                    }
                }
            }
            if let Some(msg) = bad {
                self.fail(&msg);
            }
            self.st.subs_granted += sub_ok;
            self.st.subs_refused += sub_no;
            let c = self.conns[slot].as_ref().unwrap();
            let pending = c.pending.clone();
            let tls = c.tls.clone();
            let cid = c.id;
            match connack {
                Some(ConnectReturnCode::Accepted) => {
                    self.st.connects_ok += 1;
                    let Some((id, role)) = pending else {
                        self.fail("CONNACK without a CONNECT");
                    };
                    // A TLS identity cannot be used under another client id.
                    if let Some((ident, _)) = &tls
                        && *ident != id
                    {
                        self.fail(&format!("TLS identity {ident} connected as {id}"));
                    }
                    self.conns[slot].as_mut().unwrap().active = Some((id, role));
                }
                Some(_) => {
                    self.st.connects_refused += 1;
                    self.conns[slot].as_mut().unwrap().active = None;
                }
                None => {}
            }
            let active = self.conns[slot].as_ref().unwrap().active.clone();
            for (topic, pl) in checks {
                self.st.delivered += 1;
                let Some((id, role)) = active.clone() else {
                    self.fail(&format!(
                        "publish {topic} delivered to a connection that is not connected"
                    ));
                };
                if !may_receive(role, &id, &topic) {
                    self.fail(&format!(
                        "{id} ({role:?}) received {topic}, which its rights do not cover"
                    ));
                }
                self.check_payload(&pl, &topic, Verdict::Routed, "delivered");
            }
            for pid in acks {
                if self.rng.chance(60) {
                    self.send(slot, &Packet::PubAck(pid));
                }
            }
            // The broker closes connections itself; the transport follows.
            if self.b.close_requested(cid).is_some() {
                self.b.closed(cid, self.now);
                self.conns[slot] = None;
            }
        }
        // Everything else the broker hands out.
        let routes: Vec<_> = self.b.drain_routes().collect();
        for (m, _, _) in routes {
            self.check_payload(
                &m.payload,
                &m.topic,
                Verdict::Routed,
                "routed to other shards",
            );
        }
        let tel: Vec<_> = self.b.drain_telemetry().collect();
        for m in tel {
            self.check_payload(
                &m.payload,
                &m.topic,
                Verdict::Routed,
                "in the telemetry log",
            );
        }
        let ops: Vec<_> = self.b.drain_persist().collect();
        for op in ops {
            match op {
                PersistOp::Retain { msg, .. } | PersistOp::QueuePush { msg, .. } => {
                    if !msg.payload.is_empty() {
                        self.check_payload(&msg.payload, &msg.topic, Verdict::Routed, "persisted");
                    }
                }
                PersistOp::Subscribe {
                    client_id, filter, ..
                } => {
                    // A persisted subscription is an access grant. The
                    // reserved namespace is never grantable, and `$SYS/` only
                    // to the operator identity.
                    let bad = is_reserved(&filter) || (is_sys(&filter) && &*client_id != "ops");
                    if bad {
                        self.fail(&format!("persisted subscription {filter} for {client_id}"));
                    }
                }
                _ => {}
            }
        }
        let mut ctl = Vec::new();
        for m in self.b.drain_control() {
            ctl.push((m.from.to_string(), m.payload.to_vec()));
        }
        for (from, pl) in ctl {
            self.st.control_seen += 1;
            self.check_payload(
                &pl,
                "$urmqtt/control",
                Verdict::Control,
                &format!("as control from {from}"),
            );
        }
        let mut sysr = Vec::new();
        for r in self.b.drain_sys_requests() {
            sysr.push((r.from.to_string(), r.payload.to_vec()));
        }
        for (from, pl) in sysr {
            self.st.sys_seen += 1;
            self.check_payload(
                &pl,
                "$SYS request",
                Verdict::Sys,
                &format!("as a $SYS request from {from}"),
            );
        }
    }

    /// `pl` came out of the broker as `what`; the oracle must allow `want`.
    fn check_payload(&self, pl: &[u8], topic: &str, want: Verdict, what: &str) {
        let tag = (pl.len() == 12 && &pl[..4] == b"TAG:")
            .then(|| u64::from_le_bytes(pl[4..].try_into().unwrap()));
        let Some(tag) = tag else {
            self.fail(&format!("payload of unknown origin {what} on {topic}"));
        };
        let Some((id, role, ptopic, v)) = self.tags.get(&tag) else {
            self.fail(&format!("unknown tag {tag} {what} on {topic}"));
        };
        if *v != want {
            self.fail(&format!(
                "message {ptopic} by {id} ({role:?}, oracle verdict {v:?}) appeared {what}"
            ));
        }
        if want == Verdict::Routed && ptopic != topic {
            self.fail(&format!(
                "message published on {ptopic} appeared on {topic} {what}"
            ));
        }
    }
}

fn run_sequence(seed: u64, ops: usize, st: &mut Stats) {
    let mut r = Run {
        seed,
        rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
        b: Broker::new(cfg()),
        conns: (0..5).map(|_| None).collect(),
        tags: HashMap::new(),
        next_tag: 0,
        now: 1000,
        pid: 0,
        log: Vec::new(),
        st,
    };
    for _ in 0..ops {
        r.step();
        r.drain();
    }
    r.st.sequences += 1;
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn acl_invariants_hold_under_random_operations() {
    let secs = env("ACL_FUZZ_SECS", if cfg!(miri) { 0 } else { 3 });
    let base = env("ACL_FUZZ_SEED", 1);
    let ops = env("ACL_FUZZ_OPS", 300) as usize;
    let mut st = Stats::default();
    let start = Instant::now();
    let mut seed = base;
    // Always at least one sequence (so `ACL_FUZZ_SECS=0` replays one seed).
    loop {
        run_sequence(seed, ops, &mut st);
        seed += 1;
        if start.elapsed() >= Duration::from_secs(secs) {
            break;
        }
    }
    println!(
        "acl_model: seeds {base}..{seed}: {} sequences, {} ops, {} deliveries checked, \
         {} allowed / {} forbidden publishes, {} control, {} $SYS requests, \
         connects {} ok / {} refused, {} forbidden wills refused, subscriptions {} granted / {} refused, {:.1}s",
        st.sequences,
        st.ops,
        st.delivered,
        st.allowed_published,
        st.forbidden_published,
        st.control_seen,
        st.sys_seen,
        st.connects_ok,
        st.connects_refused,
        st.wills_refused,
        st.subs_granted,
        st.subs_refused,
        start.elapsed().as_secs_f64()
    );
}
