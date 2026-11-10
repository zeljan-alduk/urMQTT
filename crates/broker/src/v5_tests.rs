//! MQTT 5.0 broker semantics (ADR-273 part 2, ADR-274) over the in-memory
//! transport: one scripted client per rule and per reason-code path.

use super::*;
use urmqtt_mqtt::v5::{
    Ack, Connect as Connect5, Disconnect as Disconnect5, Packet as P5, Properties as Props,
    Property as Prop, PropertyId as Pid, Publish as Publish5, RetainHandling, Subscribe as Sub5,
    SubscribeTopics as SubTopics5, SubscriptionOptions as Opts, Unsubscribe as Unsub5,
    UnsubscribeTopics as UnsubTopics5, Will as Will5,
};
use urmqtt_mqtt::{Connect, Subscribe, SubscribeTopics};

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/cmd/#", "devices/{id}/echo/#"],
    service_ids: &["backend", "backend2"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    service_subscribe: &["devices/#", "fleet/#"],
    operator_ids: &["ops"],
};

fn cfg() -> Config {
    Config {
        limits: Limits {
            max_packet_size: 4096,
            max_topic_len: 256,
            max_topic_levels: 16,
            max_client_id_len: 64,
            max_topics_per_packet: 8,
        },
        max_connections: 32,
        max_subscriptions_per_session: 4,
        max_inflight: 8,
        max_queued: 16,
        max_retained_per_device: 4,
        max_retained_bytes: 1 << 16,
        rate_tokens: 100,
        rate_period_ms: 1000,
        max_outbound_bytes: 64 * 1024,
        acl: ACL,
        persist: false,
        telemetry: &[],
        fanout: false,
        control_ids: &[],
        plain: None,
        web: None,
        mqtt5: Mqtt5Policy::DEFAULT,
        publisher_backpressure: PublisherBackpressure::Single,
    }
}

fn plain() -> PlainPolicy {
    PlainPolicy {
        publish: &["lan/{id}/#"],
        subscribe: &["lan/#"],
        max_packet_size: 512,
        rate_tokens: 100,
        rate_period_ms: 1000,
        retain: false,
    }
}

/// What a 5.0 client received, owned.
#[derive(Debug, Clone, PartialEq)]
enum G {
    ConnAck {
        present: bool,
        code: u8,
        props: Vec<u8>,
    },
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        pid: Option<u16>,
        retain: bool,
        dup: bool,
        props: Vec<u8>,
    },
    /// PUBACK (4), PUBREC (5), PUBREL (6), PUBCOMP (7): packet id, code.
    Ack(u8, u16, u8),
    SubAck(u16, Vec<u8>),
    UnsubAck(u16, Vec<u8>),
    Disconnect(u8, Option<String>),
    PingResp,
}

impl G {
    fn props(&self) -> Props<'_> {
        match self {
            G::ConnAck { props, .. } | G::Publish { props, .. } => Props::Raw(props),
            _ => Props::EMPTY,
        }
    }

    fn code(&self) -> u8 {
        match self {
            G::ConnAck { code, .. } => *code,
            G::Disconnect(c, _) => *c,
            other => panic!("no code in {other:?}"),
        }
    }
}

fn raw(p: &Props<'_>) -> Vec<u8> {
    match p {
        Props::Raw(r) => r.to_vec(),
        _ => panic!("decoded blocks are raw"),
    }
}

struct C5 {
    c: ConnId,
    rx: Vec<u8>,
    /// Received after the CONNACK, not yet returned by `recv`.
    pending: Vec<G>,
}

impl C5 {
    fn open(b: &mut Broker, now: u64) -> C5 {
        C5 {
            c: b.open(now).unwrap(),
            rx: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn send(&self, b: &mut Broker, p: &P5<'_>, now: u64) {
        let n = urmqtt_mqtt::v5::encoded_len(p).unwrap();
        let mut out = vec![0u8; n];
        urmqtt_mqtt::v5::encode(p, &mut out).unwrap();
        b.input(self.c, &out, now);
    }

    fn recv(&mut self, b: &mut Broker) -> Vec<G> {
        let out = b.output(self.c).to_vec();
        b.consumed(self.c, out.len());
        self.rx.extend_from_slice(&out);
        let mut got = core::mem::take(&mut self.pending);
        loop {
            match urmqtt_mqtt::v5::decode(&self.rx, &urmqtt_mqtt::v5::Limits::PROTOCOL_MAX) {
                Ok((p, n)) => {
                    got.push(match p {
                        P5::ConnAck(a) => G::ConnAck {
                            present: a.session_present,
                            code: a.reason as u8,
                            props: raw(&a.properties),
                        },
                        P5::Publish(p) => G::Publish {
                            topic: p.topic.into(),
                            payload: p.payload.into(),
                            qos: p.qos as u8,
                            pid: p.packet_id,
                            retain: p.retain,
                            dup: p.dup,
                            props: raw(&p.properties),
                        },
                        P5::PubAck(a) => G::Ack(4, a.packet_id, a.reason as u8),
                        P5::PubRec(a) => G::Ack(5, a.packet_id, a.reason as u8),
                        P5::PubRel(a) => G::Ack(6, a.packet_id, a.reason as u8),
                        P5::PubComp(a) => G::Ack(7, a.packet_id, a.reason as u8),
                        P5::SubAck(s) => G::SubAck(s.packet_id, s.reason_codes.to_vec()),
                        P5::UnsubAck(s) => G::UnsubAck(s.packet_id, s.reason_codes.to_vec()),
                        P5::Disconnect(d) => G::Disconnect(
                            d.reason as u8,
                            d.properties.reason_string().map(Into::into),
                        ),
                        P5::PingResp => G::PingResp,
                        other => panic!("unexpected {other:?}"),
                    });
                    self.rx.drain(..n);
                }
                Err(urmqtt_mqtt::v5::Error::Incomplete(_)) => return got,
                Err(e) => panic!("{e:?}"),
            }
        }
    }

    /// CONNECT with these properties; returns the CONNACK.
    fn connect(
        b: &mut Broker,
        id: &str,
        clean: bool,
        props: &[Prop<'_>],
        will: Option<Will5<'_>>,
        now: u64,
    ) -> (C5, G) {
        Self::connect_as(b, None, id, clean, props, will, now)
    }

    /// The same over "TLS": the certificate's identity bound first.
    fn connect_as(
        b: &mut Broker,
        identity: Option<&str>,
        id: &str,
        clean: bool,
        props: &[Prop<'_>],
        will: Option<Will5<'_>>,
        now: u64,
    ) -> (C5, G) {
        let mut c = C5::open(b, now);
        if let Some(i) = identity {
            b.set_identity(c.c, i, false);
        }
        c.send(
            b,
            &P5::Connect(Connect5 {
                clean_start: clean,
                keep_alive: 0,
                properties: Props::List(props),
                client_id: id,
                will,
                username: None,
                password: None,
            }),
            now,
        );
        let mut got = c.recv(b);
        assert!(!got.is_empty(), "no CONNACK");
        let ack = got.remove(0);
        c.pending = got;
        (c, ack)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        b: &mut Broker,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        retain: bool,
        props: &[Prop<'_>],
        now: u64,
    ) -> Vec<G> {
        let pid = (qos != QoS::AtMostOnce).then_some(9);
        self.publish_id(b, topic, payload, qos, retain, props, pid, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_id(
        &mut self,
        b: &mut Broker,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        retain: bool,
        props: &[Prop<'_>],
        pid: Option<u16>,
        now: u64,
    ) -> Vec<G> {
        self.send(
            b,
            &P5::Publish(Publish5 {
                dup: false,
                qos,
                retain,
                topic,
                packet_id: pid,
                properties: Props::List(props),
                payload,
            }),
            now,
        );
        self.recv(b)
    }

    fn subscribe(&mut self, b: &mut Broker, list: &[(&str, Opts)], now: u64) -> Vec<G> {
        self.subscribe_props(b, list, &[], now)
    }

    fn subscribe_props(
        &mut self,
        b: &mut Broker,
        list: &[(&str, Opts)],
        props: &[Prop<'_>],
        now: u64,
    ) -> Vec<G> {
        self.send(
            b,
            &P5::Subscribe(Sub5 {
                packet_id: 3,
                properties: Props::List(props),
                topics: SubTopics5::List(list),
            }),
            now,
        );
        self.recv(b)
    }

    fn disconnect(&self, b: &mut Broker, code: ReasonCode, props: &[Prop<'_>], now: u64) {
        self.send(
            b,
            &P5::Disconnect(Disconnect5 {
                reason: code,
                properties: Props::List(props),
            }),
            now,
        );
        b.closed(self.c, now);
    }
}

fn q(qos: QoS) -> Opts {
    Opts::qos(qos)
}

/// A 3.1.1 client (the version-neutral core serves both).
fn connect4(b: &mut Broker, id: &str, clean: bool, now: u64) -> ConnId {
    let c = b.open(now).unwrap();
    let p = Packet::Connect(Connect {
        protocol_level: 4,
        clean_session: clean,
        keep_alive: 10,
        client_id: id,
        will: None,
        username: None,
        password: None,
    });
    let mut out = vec![0u8; encoded_len(&p)];
    encode(&p, &mut out).unwrap();
    b.input(c, &out, now);
    let n = b.output(c).len();
    b.consumed(c, n);
    c
}

fn send4(b: &mut Broker, c: ConnId, p: &Packet<'_>, now: u64) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len(p)];
    encode(p, &mut out).unwrap();
    b.input(c, &out, now);
    let o = b.output(c).to_vec();
    b.consumed(c, o.len());
    o
}

fn connack_props(g: &G) -> Props<'_> {
    assert!(matches!(g, G::ConnAck { code: 0, .. }), "{g:?}");
    g.props()
}

// ---- 1. version negotiation, CONNECT/CONNACK ------------------------------

#[test]
fn both_versions_on_one_broker_and_connack_announces_what_is_there() {
    let mut b = Broker::new(cfg());
    let (_, ack) = C5::connect(&mut b, "d5", true, &[], None, 0);
    let p = connack_props(&ack);
    assert_eq!(p.receive_maximum(), Some(32));
    assert_eq!(p.maximum_packet_size(), Some(4096));
    assert_eq!(p.topic_alias_maximum(), Some(10));
    // Retain, wildcards, QoS 2, shared subscriptions and Subscription
    // Identifiers are available: not announced (absent means 1, ADR-275).
    assert_eq!(p.get(Pid::SubscriptionIdentifierAvailable), None);
    assert_eq!(p.get(Pid::SharedSubscriptionAvailable), None);
    assert_eq!(p.get(Pid::RetainAvailable), None);
    assert_eq!(p.get(Pid::MaximumQos), None);
    assert_eq!(p.get(Pid::WildcardSubscriptionAvailable), None);
    assert_eq!(
        p.get(Pid::SessionExpiryInterval),
        None,
        "0 asked, 0 granted"
    );
    assert!(b.is_v5(0));
    let c4 = connect4(&mut b, "d4", true, 0);
    assert!(!b.is_v5(c4));
    let st = b.stats();
    assert_eq!((st.online, st.online_v5), (2, 1));
}

#[test]
fn mqtt5_disabled_answers_0x84_in_a_5_0_connack() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            enabled: false,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (c, ack) = C5::connect(&mut b, "d5", true, &[], None, 0);
    assert_eq!(ack.code(), 0x84);
    assert_eq!(b.close_requested(c.c), Some(CloseReason::Rejected));
    assert_eq!(b.stats().connack_refused[0x04], 1);
    // 3.1.1 is unaffected.
    connect4(&mut b, "d4", true, 0);
    assert_eq!(b.stats().online, 1);
}

#[test]
fn connack_refusals_carry_5_0_codes_and_reason_strings_when_allowed() {
    let mut b = Broker::new(cfg());
    // Certificate says d1, client id d2: 0x85.
    let (c, ack) = C5::connect_as(&mut b, Some("d1"), "d2", true, &[], None, 0);
    assert_eq!(ack.code(), 0x85);
    assert_eq!(
        ack.props().reason_string(),
        Some("client identifier not accepted")
    );
    assert_eq!(b.close_requested(c.c), Some(CloseReason::Rejected));
    // Request Problem Information 0: no reason string.
    let (_, ack) = C5::connect_as(
        &mut b,
        Some("d1"),
        "d2",
        true,
        &[Prop::RequestProblemInformation(0)],
        None,
        0,
    );
    assert_eq!(ack.code(), 0x85);
    assert_eq!(ack.props().reason_string(), None);
    // A Will outside the ACL: 0x87.
    let will = Will5 {
        properties: Props::EMPTY,
        topic: "fleet/x",
        payload: b"w",
        qos: QoS::AtMostOnce,
        retain: false,
    };
    let (_, ack) = C5::connect(&mut b, "d3", true, &[], Some(will), 0);
    assert_eq!(ack.code(), 0x87);
    // Enhanced authentication: 0x8C (rule 15).
    let (_, ack) = C5::connect(
        &mut b,
        "d4",
        true,
        &[Prop::AuthenticationMethod("SCRAM-SHA-256")],
        None,
        0,
    );
    assert_eq!(ack.code(), 0x8c);
    // A malformed CONNECT (reserved flag): CONNACK 0x81.
    let mut c = C5::open(&mut b, 0);
    b.input(
        c.c,
        &[
            0x10, 13, 0, 4, b'M', b'Q', b'T', b'T', 5, 0x03, 0, 10, 0, 0, 0,
        ],
        0,
    );
    let got = c.recv(&mut b);
    assert_eq!(got[0].code(), 0x81);
    let st = b.stats();
    assert_eq!(st.connack_refused[0x05], 2);
    assert_eq!(st.connack_refused[0x07], 1);
    assert_eq!(st.connack_refused[0x0c], 1);
    assert_eq!(st.connack_refused[0x01], 1);
}

#[test]
fn an_empty_client_id_is_assigned_the_certificate_identity_or_a_name() {
    let mut b = Broker::new(cfg());
    let (_, ack) = C5::connect_as(&mut b, Some("d7"), "", true, &[], None, 0);
    assert_eq!(
        connack_props(&ack).get(Pid::AssignedClientIdentifier),
        Some(Prop::AssignedClientIdentifier("d7"))
    );
    assert_eq!(b.client_id(0), Some("d7"));
    // No certificate (the dev plaintext port): a generated name.
    let (c, ack) = C5::connect(&mut b, "", true, &[], None, 0);
    let Some(Prop::AssignedClientIdentifier(id)) =
        connack_props(&ack).get(Pid::AssignedClientIdentifier)
    else {
        panic!("{ack:?}")
    };
    assert!(id.starts_with("auto-"));
    assert_eq!(b.client_id(c.c), Some(id));
    // A plaintext login: the tail of its session name.
    let mut b = Broker::new(Config {
        plain: Some(plain()),
        ..cfg()
    });
    let mut c = C5::open(&mut b, 0);
    assert!(b.set_plain_identity(c.c, "alice"));
    c.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: false,
            keep_alive: 0,
            properties: Props::List(&[Prop::SessionExpiryInterval(300)]),
            client_id: "",
            will: None,
            username: Some("alice"),
            password: Some(b"pw"),
        }),
        0,
    );
    let ack = c.recv(&mut b).remove(0);
    let p = connack_props(&ack);
    assert_eq!(
        p.get(Pid::AssignedClientIdentifier),
        Some(Prop::AssignedClientIdentifier("auto-1"))
    );
    // Plaintext sessions are never kept: granted 0, told so; no retain.
    assert_eq!(p.session_expiry_interval(), Some(0));
    assert_eq!(p.get(Pid::RetainAvailable), Some(Prop::RetainAvailable(0)));
    assert_eq!(p.maximum_packet_size(), Some(512));
    assert_eq!(b.client_id(c.c), Some("$plain/alice/auto-1"));
}

#[test]
fn bootstrap_sessions_are_granted_expiry_0_instead_of_refused() {
    let mut b = Broker::new(cfg());
    let mut c = C5::open(&mut b, 0);
    b.set_identity(c.c, "newdev", true);
    c.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: false,
            keep_alive: 0,
            properties: Props::List(&[Prop::SessionExpiryInterval(60)]),
            client_id: "newdev",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    let ack = c.recv(&mut b).remove(0);
    assert_eq!(connack_props(&ack).session_expiry_interval(), Some(0));
}

#[test]
fn server_keep_alive_caps_the_clients() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            max_keep_alive_s: 60,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let mut c = C5::open(&mut b, 0);
    c.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 120,
            properties: Props::EMPTY,
            client_id: "d1",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    let ack = c.recv(&mut b).remove(0);
    assert_eq!(connack_props(&ack).server_keep_alive(), Some(60));
    // Enforced at 1.5 × 60 s, with DISCONNECT 0x8D.
    b.tick(89_000);
    assert_eq!(b.close_requested(c.c), None);
    b.tick(91_000);
    assert_eq!(b.close_requested(c.c), Some(CloseReason::KeepAliveTimeout));
    assert_eq!(
        c.recv(&mut b),
        [G::Disconnect(0x8d, Some("keep alive timeout".into()))]
    );
    // Keep alive 0 (none) is held to the maximum too.
    let (_, ack) = C5::connect(&mut b, "d2", true, &[], None, 0);
    assert_eq!(connack_props(&ack).server_keep_alive(), Some(60));
    // One within the maximum is not mentioned.
    let mut c = C5::open(&mut b, 0);
    c.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 30,
            properties: Props::EMPTY,
            client_id: "d3",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    let ack = c.recv(&mut b).remove(0);
    assert_eq!(connack_props(&ack).server_keep_alive(), None);
}

// ---- 2. acknowledgement codes and server DISCONNECT -------------------------

#[test]
fn puback_and_pubrec_say_why_a_publish_was_dropped() {
    let mut b = Broker::new(Config {
        rate_tokens: 2,
        ..cfg()
    });
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    assert_eq!(
        d.publish(&mut b, "fleet/x", b"no", QoS::AtLeastOnce, false, &[], 0),
        [G::Ack(4, 9, 0x87)]
    );
    assert_eq!(
        d.publish(
            &mut b,
            "devices/d1/a",
            b"ok",
            QoS::AtLeastOnce,
            false,
            &[],
            0
        ),
        [G::Ack(4, 9, 0)]
    );
    assert_eq!(
        d.publish(
            &mut b,
            "devices/d1/a",
            b"ok",
            QoS::AtLeastOnce,
            false,
            &[],
            0
        ),
        [G::Ack(4, 9, 0)]
    );
    // Rate: 0x97 Quota exceeded.
    assert_eq!(
        d.publish(
            &mut b,
            "devices/d1/a",
            b"r",
            QoS::AtLeastOnce,
            false,
            &[],
            0
        ),
        [G::Ack(4, 9, 0x97)]
    );
    // QoS 2 refused: PUBREC 0x87 and the flow ends (no id kept, so the same
    // id is a new message, not a duplicate).
    assert_eq!(
        d.publish(&mut b, "fleet/x", b"no", QoS::ExactlyOnce, false, &[], 0),
        [G::Ack(5, 9, 0x87)]
    );
    assert_eq!(
        d.publish(&mut b, "fleet/x", b"no", QoS::ExactlyOnce, false, &[], 0),
        [G::Ack(5, 9, 0x87)]
    );
    assert_eq!(b.stats().qos2_duplicates, 0);
    // The reserved namespace: 0x87.
    assert_eq!(
        d.publish(
            &mut b,
            "$urmqtt/control",
            b"x",
            QoS::AtLeastOnce,
            false,
            &[],
            0
        ),
        [G::Ack(4, 9, 0x87)]
    );
}

#[test]
fn qos2_inbound_flow_and_receive_maximum_0x93() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            receive_maximum: 2,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (mut d, ack) = C5::connect(&mut b, "d1", true, &[], None, 0);
    assert_eq!(connack_props(&ack).receive_maximum(), Some(2));
    for pid in [1, 2] {
        assert_eq!(
            d.publish_id(
                &mut b,
                "devices/d1/x",
                b"p",
                QoS::ExactlyOnce,
                false,
                &[],
                Some(pid),
                0
            ),
            [G::Ack(5, pid, 0)]
        );
    }
    // A duplicate is answered again, never routed twice.
    assert_eq!(
        d.publish_id(
            &mut b,
            "devices/d1/x",
            b"p",
            QoS::ExactlyOnce,
            false,
            &[],
            Some(2),
            0
        ),
        [G::Ack(5, 2, 0)]
    );
    d.send(
        &mut b,
        &P5::PubRel(Ack {
            packet_id: 1,
            reason: ReasonCode::Success,
            properties: Props::EMPTY,
        }),
        0,
    );
    assert_eq!(d.recv(&mut b), [G::Ack(7, 1, 0)]);
    assert_eq!(
        d.publish_id(
            &mut b,
            "devices/d1/x",
            b"p",
            QoS::ExactlyOnce,
            false,
            &[],
            Some(3),
            0
        ),
        [G::Ack(5, 3, 0)]
    );
    // Third unreleased: one above the Receive Maximum.
    assert_eq!(
        d.publish_id(
            &mut b,
            "devices/d1/x",
            b"p",
            QoS::ExactlyOnce,
            false,
            &[],
            Some(4),
            0
        ),
        [G::Disconnect(0x93, Some("receive maximum exceeded".into()))]
    );
    assert_eq!(b.stats().disconnects_sent[0x13], 1);
}

#[test]
fn subscribe_and_unsubscribe_reason_codes() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    let got = d.subscribe(
        &mut b,
        &[
            ("devices/d1/cmd/#", q(QoS::ExactlyOnce)),
            ("fleet/#", q(QoS::AtLeastOnce)),
            ("$share/g/devices/d1/cmd/x", q(QoS::AtMostOnce)),
            ("devices/d1/echo/a", q(QoS::AtLeastOnce)),
            ("devices/d1/echo/b", q(QoS::AtLeastOnce)),
            ("devices/d1/echo/c", q(QoS::AtLeastOnce)),
            ("devices/d1/echo/d", q(QoS::AtLeastOnce)),
        ],
        0,
    );
    // Granted QoS 2, ACL 0x87, the shared one QoS 0 (ADR-275), two more
    // within the limit of 4 (the shared one counts), then 0x97
    // (subscription limit).
    assert_eq!(got, [G::SubAck(3, vec![2, 0x87, 0, 1, 1, 0x97, 0x97])]);
    d.send(
        &mut b,
        &P5::Unsubscribe(Unsub5 {
            packet_id: 4,
            properties: Props::EMPTY,
            topics: UnsubTopics5::List(&["devices/d1/cmd/#", "nope/#"]),
        }),
        0,
    );
    assert_eq!(d.recv(&mut b), [G::UnsubAck(4, vec![0, 0x11])]);
}

#[test]
fn server_disconnects_carry_their_reason() {
    let mut b = Broker::new(Config {
        plain: Some(plain()),
        ..cfg()
    });
    // Session taken over: 0x8E to the old connection.
    let (mut old, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    let (_new, ack) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    assert!(matches!(
        ack,
        G::ConnAck {
            present: true,
            code: 0,
            ..
        }
    ));
    assert_eq!(
        old.recv(&mut b),
        [G::Disconnect(0x8e, Some("session taken over".into()))]
    );
    assert_eq!(b.close_requested(old.c), Some(CloseReason::TakenOver));
    // An identity that left the allowlist: 0x98.
    let (mut d2, _) = C5::connect(&mut b, "d2", true, &[], None, 0);
    assert!(b.disconnect_identity("d2", CloseReason::Disallowed));
    assert_eq!(
        d2.recv(&mut b),
        [G::Disconnect(0x98, Some("administrative action".into()))]
    );
    // AUTH from a client: 0x82.
    let (mut d3, _) = C5::connect(&mut b, "d3", true, &[], None, 0);
    d3.send(
        &mut b,
        &P5::Auth(urmqtt_mqtt::v5::Auth {
            reason: ReasonCode::Success,
            properties: Props::EMPTY,
        }),
        0,
    );
    assert_eq!(d3.recv(&mut b)[0].code(), 0x82);
    // A client's Subscription Identifier in PUBLISH: 0x82.
    let (mut d4, _) = C5::connect(&mut b, "d4", true, &[], None, 0);
    let got = d4.publish(
        &mut b,
        "devices/d4/x",
        b"p",
        QoS::AtMostOnce,
        false,
        &[Prop::SubscriptionIdentifier(1)],
        0,
    );
    assert_eq!(got[0].code(), 0x82);
    // A second CONNECT: 0x82.
    let (d5, _) = C5::connect(&mut b, "d5", true, &[], None, 0);
    d5.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 0,
            properties: Props::EMPTY,
            client_id: "d5",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    let mut d5 = d5;
    assert_eq!(d5.recv(&mut b)[0].code(), 0x82);
    // A malformed packet after CONNECT (PUBLISH with QoS 3): 0x81.
    let (mut d6, _) = C5::connect(&mut b, "d6", true, &[], None, 0);
    b.input(d6.c, &[0x36, 3, 0, 1, b'a'], 0);
    assert_eq!(d6.recv(&mut b)[0].code(), 0x81);
    // A packet above the broker's Maximum Packet Size: 0x95.
    let (mut d7, _) = C5::connect(&mut b, "d7", true, &[], None, 0);
    let big = vec![0u8; 5000];
    let got = d7.publish(&mut b, "devices/d7/x", &big, QoS::AtMostOnce, false, &[], 0);
    assert_eq!(got[0].code(), 0x95);
    // Retain on a plaintext login without retain (Retain Available 0): 0x9A.
    let mut p = C5::open(&mut b, 0);
    assert!(b.set_plain_identity(p.c, "bob"));
    p.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 0,
            properties: Props::EMPTY,
            client_id: "x",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    p.recv(&mut b);
    let got = p.publish(&mut b, "lan/bob/x", b"r", QoS::AtMostOnce, true, &[], 0);
    assert_eq!(got[0].code(), 0x9a);
    // A 3.1.1 connection is never sent a DISCONNECT.
    let c4 = connect4(&mut b, "d8", true, 0);
    assert!(b.disconnect_identity("d8", CloseReason::Disallowed));
    assert!(b.output(c4).is_empty());
    let st = b.stats();
    assert_eq!(st.disconnects_sent[0x0e], 1);
    assert_eq!(st.disconnects_sent[0x18], 1);
    assert_eq!(st.disconnects_sent[0x02], 3);
    assert_eq!(st.disconnects_sent[0x01], 1);
    assert_eq!(st.disconnects_sent[0x15], 1);
    assert_eq!(st.disconnects_sent[0x1a], 1);
}

// ---- 3. session expiry -------------------------------------------------------

#[test]
fn session_expiry_keeps_a_session_for_its_interval_then_ends_it() {
    let mut b = Broker::new(cfg());
    let (mut d, ack) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(5)],
        None,
        0,
    );
    assert_eq!(connack_props(&ack).session_expiry_interval(), None);
    d.subscribe(&mut b, &[("devices/d1/cmd/#", q(QoS::AtLeastOnce))], 0);
    b.closed(d.c, 1000);
    // Back within 5 s: present, and what was queued meanwhile arrives.
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 1000);
    svc.publish(
        &mut b,
        "devices/d1/cmd/a",
        b"q",
        QoS::AtLeastOnce,
        false,
        &[],
        2000,
    );
    b.tick(5900);
    let (mut d, ack) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(5)],
        None,
        5900,
    );
    assert!(matches!(ack, G::ConnAck { present: true, .. }));
    let got = d.recv(&mut b);
    assert!(
        matches!(&got[..], [G::Publish { topic, .. }] if topic == "devices/d1/cmd/a"),
        "{got:?}"
    );
    b.closed(d.c, 6000);
    assert_eq!(b.stats().sessions_expiring, 1);
    // Not back: gone at 11 s, counted; reconnecting finds nothing.
    b.tick(10_999);
    assert_eq!(b.stats().sessions, 2);
    b.tick(11_000);
    let st = b.stats();
    assert_eq!(
        (st.sessions, st.sessions_expired, st.sessions_expiring),
        (1, 1, 0)
    );
    let (_, ack) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(5)],
        None,
        12_000,
    );
    assert!(matches!(ack, G::ConnAck { present: false, .. }));
}

#[test]
fn session_expiry_is_capped_and_never_only_when_the_maximum_says_so() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            max_session_expiry_s: 100,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (_, ack) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(u32::MAX)],
        None,
        0,
    );
    assert_eq!(connack_props(&ack).session_expiry_interval(), Some(100));
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            max_session_expiry_s: u32::MAX,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (d, ack) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(u32::MAX)],
        None,
        0,
    );
    assert_eq!(connack_props(&ack).session_expiry_interval(), None);
    b.closed(d.c, 0);
    b.tick(u64::from(u32::MAX) * 1000);
    assert_eq!(b.stats().sessions, 1, "never expires");
    assert_eq!(b.stats().sessions_expiring, 0);
}

#[test]
fn a_3_1_1_persistent_session_expires_after_the_default() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            default_session_expiry_s: 30,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let c = connect4(&mut b, "d1", false, 0);
    b.closed(c, 0);
    b.tick(29_000);
    assert_eq!(b.stats().sessions, 1);
    b.tick(30_000);
    assert_eq!(b.stats().sessions, 0);
    assert_eq!(b.stats().sessions_expired, 1);
    // clean_session=1 ends at close, as always.
    let c = connect4(&mut b, "d2", true, 0);
    b.closed(c, 0);
    assert_eq!(b.stats().sessions, 0);
}

#[test]
fn disconnect_may_change_the_expiry_but_not_raise_it_from_zero() {
    let mut b = Broker::new(cfg());
    // From 0: 0x82.
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.send(
        &mut b,
        &P5::Disconnect(Disconnect5 {
            reason: ReasonCode::Success,
            properties: Props::List(&[Prop::SessionExpiryInterval(10)]),
        }),
        0,
    );
    assert_eq!(d.recv(&mut b)[0].code(), 0x82);
    b.closed(d.c, 0);
    assert_eq!(b.stats().sessions, 0);
    // From 10 to 0: ends at close.
    let (d, _) = C5::connect(
        &mut b,
        "d2",
        true,
        &[Prop::SessionExpiryInterval(10)],
        None,
        0,
    );
    d.disconnect(
        &mut b,
        ReasonCode::Success,
        &[Prop::SessionExpiryInterval(0)],
        0,
    );
    assert_eq!(b.stats().sessions, 0);
    // From 10 to 100: kept past 10 s.
    let (d, _) = C5::connect(
        &mut b,
        "d3",
        true,
        &[Prop::SessionExpiryInterval(10)],
        None,
        0,
    );
    d.disconnect(
        &mut b,
        ReasonCode::Success,
        &[Prop::SessionExpiryInterval(100)],
        0,
    );
    b.tick(50_000);
    assert_eq!(b.stats().sessions, 1);
    b.tick(100_000);
    assert_eq!(b.stats().sessions, 0);
}

#[test]
fn clean_start_discards_and_expiry_zero_on_resume_ends_the_stored_session() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    d.disconnect(&mut b, ReasonCode::Success, &[], 0);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(&ops[0], PersistOp::SessionUpsert { client_id, expiry_s: 60 } if &**client_id == "d1"),
        "{ops:?}"
    );
    assert!(
        matches!(ops.last(), Some(PersistOp::SessionOffline { .. })),
        "{ops:?}"
    );
    // Resumed with expiry 0: the store forgets it at once.
    let (d, ack) = C5::connect(&mut b, "d1", false, &[], None, 0);
    assert!(matches!(ack, G::ConnAck { present: true, .. }));
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(&ops[..], [PersistOp::SessionDelete { .. }]),
        "{ops:?}"
    );
    d.disconnect(&mut b, ReasonCode::Success, &[], 0);
    assert_eq!(b.drain_persist().count(), 0);
    assert_eq!(b.stats().sessions, 0);
}

#[test]
fn restore_drops_sessions_that_expired_while_the_broker_was_down() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let st = |expiry_s, offline_for_s| StoredSession {
        expiry_s,
        offline_for_s,
        now_ms: 5000,
    };
    let subs = [("devices/d1/cmd/#", 0x01u8 | 0x04)];
    assert!(!b.restore_session_v5("d1", st(Some(60), 60), subs, [], []));
    assert!(matches!(
        &b.drain_persist().collect::<Vec<_>>()[..],
        [PersistOp::SessionDelete { .. }]
    ));
    assert_eq!(b.stats().sessions_expired, 1);
    // 40 s left of 60: expires 40 s after the restore.
    assert!(b.restore_session_v5("d2", st(Some(60), 20), [("devices/d2/cmd/#", 0x05)], [], []));
    b.tick(44_999);
    assert_eq!(b.stats().sessions, 1);
    b.tick(45_000);
    assert_eq!(b.stats().sessions, 0);
    // A row from before schema 4 gets the 3.1.1 default (30 days), from
    // now (the broker's clock is at 45 s).
    assert!(b.restore_session_v5("d3", st(None, 0), [], [], []));
    b.tick(45_000 + 2_591_999_000);
    assert_eq!(b.stats().sessions, 1);
    b.tick(45_000 + 2_592_000_000);
    assert_eq!(b.stats().sessions, 0);
    // Expiry 0 stored: gone.
    assert!(!b.restore_session_v5("d4", st(Some(0), 0), [], [], []));
}

#[test]
fn restored_subscription_options_still_apply() {
    let mut b = Broker::new(cfg());
    let st = StoredSession {
        expiry_s: Some(600),
        offline_for_s: 0,
        now_ms: 0,
    };
    // No Local (0x04) at QoS 1 on the device's own echo topic.
    assert!(b.restore_session_v5("d1", st, [("devices/d1/echo/#", 0x05)], [], []));
    let (mut d, ack) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(600)],
        None,
        0,
    );
    assert!(matches!(ack, G::ConnAck { present: true, .. }));
    d.publish(
        &mut b,
        "devices/d1/echo/x",
        b"me",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    assert_eq!(b.stats().delivered, 0, "No Local");
}

// ---- 4. message expiry ------------------------------------------------------

#[test]
fn message_expiry_counts_down_and_expired_messages_are_not_delivered() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(600)],
        None,
        0,
    );
    d.subscribe(&mut b, &[("devices/d1/cmd/#", q(QoS::AtLeastOnce))], 0);
    b.closed(d.c, 0);
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    for (t, e) in [("devices/d1/cmd/short", 2), ("devices/d1/cmd/long", 10)] {
        svc.publish(
            &mut b,
            t,
            b"m",
            QoS::AtLeastOnce,
            false,
            &[Prop::MessageExpiryInterval(e)],
            0,
        );
    }
    // Back after 3 s: the short one expired in the queue; the long one says
    // 7 s left.
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(600)],
        None,
        3000,
    );
    let got = d.recv(&mut b);
    assert_eq!(got.len(), 1, "{got:?}");
    let G::Publish { topic, .. } = &got[0] else {
        panic!()
    };
    assert_eq!(topic, "devices/d1/cmd/long");
    assert_eq!(got[0].props().message_expiry_interval(), Some(7));
    assert_eq!(b.stats().messages_expired, 1);
}

#[test]
fn retained_messages_expire_and_the_cap_bounds_what_a_publisher_asks() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            max_message_expiry_s: 5,
            ..Mqtt5Policy::DEFAULT
        },
        persist: true,
        ..cfg()
    });
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/state",
        b"on",
        QoS::AtLeastOnce,
        true,
        &[Prop::MessageExpiryInterval(3600)],
        0,
    );
    b.drain_persist().for_each(drop);
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 1000);
    let got = s.subscribe(&mut b, &[("devices/#", q(QoS::AtLeastOnce))], 1000);
    assert_eq!(
        got[1].props().message_expiry_interval(),
        Some(4),
        "capped at 5 s"
    );
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 6000);
    b.tick(6000);
    let got = s2.subscribe(&mut b, &[("devices/#", q(QoS::AtLeastOnce))], 6000);
    assert_eq!(got.len(), 1, "expired: only the SUBACK {got:?}");
    // Cleared where it was found, in the store too.
    assert_eq!(b.stats().retained, 0);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        ops.iter()
            .any(|o| matches!(o, PersistOp::Retain { msg, .. } if msg.payload.is_empty())),
        "{ops:?}"
    );
}

// ---- 5. will delay -----------------------------------------------------------

fn will(delay: u32) -> Will5<'static> {
    static DELAYS: [[Prop<'static>; 2]; 4] = [
        [
            Prop::WillDelayInterval(0),
            Prop::UserProperty("why", "lost"),
        ],
        [
            Prop::WillDelayInterval(3),
            Prop::UserProperty("why", "lost"),
        ],
        [
            Prop::WillDelayInterval(30),
            Prop::UserProperty("why", "lost"),
        ],
        [
            Prop::WillDelayInterval(1),
            Prop::UserProperty("why", "lost"),
        ],
    ];
    let i = match delay {
        0 => 0,
        3 => 1,
        30 => 2,
        _ => 3,
    };
    Will5 {
        properties: Props::List(&DELAYS[i]),
        topic: "devices/d1/status",
        payload: b"offline",
        qos: QoS::AtLeastOnce,
        retain: false,
    }
}

fn watcher(b: &mut Broker, now: u64) -> C5 {
    let (mut s, _) = C5::connect(b, "backend", true, &[], None, now);
    s.subscribe(b, &[("devices/+/status", q(QoS::AtLeastOnce))], now);
    s
}

#[test]
fn a_delayed_will_waits_and_is_cancelled_by_a_reconnect() {
    let mut b = Broker::new(cfg());
    let mut s = watcher(&mut b, 0);
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(3)),
        0,
    );
    b.closed(d.c, 0);
    assert_eq!(b.stats().wills_pending, 1);
    b.tick(2000);
    assert!(s.recv(&mut b).is_empty());
    // Back within the delay: no will.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(3)),
        2500,
    );
    b.tick(10_000);
    assert!(s.recv(&mut b).is_empty());
    assert_eq!(b.stats().wills_pending, 0);
    // Gone again, not back: the will after 3 s, with its user property.
    b.closed(d.c, 10_000);
    b.tick(12_999);
    assert!(s.recv(&mut b).is_empty());
    b.tick(13_000);
    let got = s.recv(&mut b);
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].props().user_properties().collect::<Vec<_>>(),
        [("why", "lost")]
    );
    assert_eq!(got[0].props().get(Pid::WillDelayInterval), None);
    assert_eq!(b.stats().wills_published, 1);
}

#[test]
fn a_will_goes_out_when_the_session_ends_before_its_delay() {
    let mut b = Broker::new(cfg());
    let mut s = watcher(&mut b, 0);
    // Session expiry 5 s, will delay 30 s: at 5 s.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(5)],
        Some(will(30)),
        0,
    );
    b.closed(d.c, 0);
    b.tick(4999);
    assert!(s.recv(&mut b).is_empty());
    b.tick(5000);
    assert_eq!(s.recv(&mut b).len(), 1);
    // Session expiry 0: at once, whatever the delay.
    let (d, _) = C5::connect(&mut b, "d1", true, &[], Some(will(30)), 6000);
    b.closed(d.c, 6000);
    assert_eq!(s.recv(&mut b).len(), 1);
    // A clean-start takeover ends the old session: its will goes out when
    // the old connection closes.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(30)),
        7000,
    );
    let (_n, _) = C5::connect(&mut b, "d1", true, &[], None, 7000);
    b.closed(d.c, 7000);
    assert_eq!(s.recv(&mut b).len(), 1);
    // A takeover that resumes the session within the delay cancels it.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(30)),
        8000,
    );
    let (_n, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        8000,
    );
    b.closed(d.c, 8000);
    b.tick(100_000);
    let got = s.recv(&mut b);
    assert!(got.is_empty(), "{got:?}");
}

#[test]
fn disconnect_with_will_publishes_it_and_a_normal_one_does_not() {
    let mut b = Broker::new(cfg());
    let mut s = watcher(&mut b, 0);
    let (d, _) = C5::connect(&mut b, "d1", true, &[], Some(will(0)), 0);
    d.disconnect(&mut b, ReasonCode::DisconnectWithWillMessage, &[], 0);
    assert_eq!(s.recv(&mut b).len(), 1);
    let (d, _) = C5::connect(&mut b, "d1", true, &[], Some(will(0)), 0);
    d.disconnect(&mut b, ReasonCode::Success, &[], 0);
    assert!(s.recv(&mut b).is_empty());
    // Any failure code keeps the will too (§3.1.2.5).
    let (d, _) = C5::connect(&mut b, "d1", true, &[], Some(will(0)), 0);
    d.disconnect(&mut b, ReasonCode::UnspecifiedError, &[], 0);
    assert_eq!(s.recv(&mut b).len(), 1);
}

#[test]
fn a_retained_will_on_a_login_without_retain_is_refused_0x9a() {
    let mut b = Broker::new(Config {
        plain: Some(plain()),
        ..cfg()
    });
    let mut p = C5::open(&mut b, 0);
    assert!(b.set_plain_identity(p.c, "bob"));
    p.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 0,
            properties: Props::EMPTY,
            client_id: "x",
            will: Some(Will5 {
                properties: Props::EMPTY,
                topic: "lan/bob/status",
                payload: b"gone",
                qos: QoS::AtMostOnce,
                retain: true,
            }),
            username: None,
            password: None,
        }),
        0,
    );
    assert_eq!(p.recv(&mut b)[0].code(), 0x9a);
}

// ---- 6. flow control ---------------------------------------------------------

#[test]
fn the_clients_receive_maximum_bounds_what_is_in_flight_to_it() {
    let mut b = Broker::new(cfg()); // max_inflight 8
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::ReceiveMaximum(2), Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    d.subscribe(&mut b, &[("devices/d1/cmd/#", q(QoS::AtLeastOnce))], 0);
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    for i in 0..5u8 {
        svc.publish(
            &mut b,
            "devices/d1/cmd/x",
            &[i],
            QoS::AtLeastOnce,
            false,
            &[],
            0,
        );
    }
    let got = d.recv(&mut b);
    assert_eq!(got.len(), 2, "{got:?}");
    let G::Publish { pid: Some(pid), .. } = got[0] else {
        panic!()
    };
    d.send(
        &mut b,
        &P5::PubAck(Ack {
            packet_id: pid,
            reason: ReasonCode::Success,
            properties: Props::EMPTY,
        }),
        0,
    );
    assert_eq!(d.recv(&mut b).len(), 1, "one more after one PUBACK");
}

#[test]
fn deliveries_above_the_clients_maximum_packet_size_are_dropped_and_counted() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::MaximumPacketSize(64), Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    d.subscribe(&mut b, &[("devices/d1/cmd/#", q(QoS::AtLeastOnce))], 0);
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    svc.publish(
        &mut b,
        "devices/d1/cmd/x",
        &[0u8; 100],
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    svc.publish(
        &mut b,
        "devices/d1/cmd/x",
        &[0u8; 100],
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    svc.publish(
        &mut b,
        "devices/d1/cmd/x",
        b"small",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    let got = d.recv(&mut b);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(b.stats().dropped_too_large, 2);
    // Nothing of the dropped QoS 1 message is left in flight or queued.
    let G::Publish { pid: Some(pid), .. } = got[0] else {
        panic!()
    };
    d.send(
        &mut b,
        &P5::PubAck(Ack {
            packet_id: pid,
            reason: ReasonCode::Success,
            properties: Props::EMPTY,
        }),
        0,
    );
    b.closed(d.c, 0);
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    assert!(d.recv(&mut b).is_empty());
}

// ---- 7. topic aliases ---------------------------------------------------------

#[test]
fn topic_aliases_from_the_client_are_resolved_and_bounded() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            topic_alias_maximum: 2,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    s.subscribe(&mut b, &[("devices/#", q(QoS::AtMostOnce))], 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/a",
        b"1",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(1)],
        0,
    );
    d.publish(
        &mut b,
        "",
        b"2",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(1)],
        0,
    );
    d.publish(
        &mut b,
        "",
        b"3",
        QoS::AtLeastOnce,
        false,
        &[Prop::TopicAlias(1)],
        0,
    );
    let got = s.recv(&mut b);
    assert_eq!(got.len(), 3);
    for g in &got {
        let G::Publish { topic, .. } = g else {
            panic!()
        };
        assert_eq!(topic, "devices/d1/a");
        // The broker never sends aliases.
        assert_eq!(g.props().topic_alias(), None);
    }
    // Unknown alias: 0x94.
    let got = d.publish(
        &mut b,
        "",
        b"4",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(2)],
        0,
    );
    assert_eq!(got[0].code(), 0x94);
    // Above the maximum: 0x94.
    let (mut d2, _) = C5::connect(&mut b, "d2", true, &[], None, 0);
    let got = d2.publish(
        &mut b,
        "devices/d2/a",
        b"",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(3)],
        0,
    );
    assert_eq!(got[0].code(), 0x94);
    // Aliases off (maximum 0): any alias is 0x94, and none is announced.
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            topic_alias_maximum: 0,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (mut d, ack) = C5::connect(&mut b, "d1", true, &[], None, 0);
    assert_eq!(connack_props(&ack).topic_alias_maximum(), None);
    let got = d.publish(
        &mut b,
        "devices/d1/a",
        b"",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(1)],
        0,
    );
    assert_eq!(got[0].code(), 0x94);
}

// ---- 8. subscription options --------------------------------------------------

#[test]
fn no_local_skips_the_publishers_own_session() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    let mut nl = q(QoS::AtMostOnce);
    nl.no_local = true;
    d.subscribe(&mut b, &[("devices/d1/echo/#", nl)], 0);
    d.publish(
        &mut b,
        "devices/d1/echo/x",
        b"me",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    assert!(d.recv(&mut b).is_empty());
    // Another publisher's message arrives.
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    s.subscribe(&mut b, &[("devices/#", q(QoS::AtMostOnce))], 0);
    // (The service may publish to cmd only; use a device-scoped echo via
    // the service's subscription to see the device's own publish arrive.)
    let got = s.recv(&mut b);
    assert!(got.is_empty());
    d.publish(
        &mut b,
        "devices/d1/echo/y",
        b"me2",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    assert!(d.recv(&mut b).is_empty());
    assert_eq!(s.recv(&mut b).len(), 1);
}

#[test]
fn retain_as_published_and_retain_handling() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/state",
        b"on",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let rap = Opts {
        retain_as_published: true,
        ..q(QoS::AtMostOnce)
    };
    // Retain Handling 0: sent on every subscribe, RETAIN set.
    let got = s.subscribe(&mut b, &[("devices/+/state", rap)], 0);
    assert!(
        matches!(&got[1], G::Publish { retain: true, .. }),
        "{got:?}"
    );
    // Live, published with RETAIN: kept (Retain As Published).
    d.publish(
        &mut b,
        "devices/d1/state",
        b"off",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    assert!(matches!(
        &s.recv(&mut b)[0],
        G::Publish { retain: true, .. }
    ));
    // Retain Handling 1: only for a new subscription.
    let rh1 = Opts {
        retain_handling: RetainHandling::SendIfNew,
        ..q(QoS::AtMostOnce)
    };
    let got = s.subscribe(&mut b, &[("devices/+/state", rh1)], 0);
    assert_eq!(got.len(), 1, "exists already: SUBACK only {got:?}");
    let got = s.subscribe(&mut b, &[("devices/d1/#", rh1)], 0);
    assert_eq!(got.len(), 2, "new: SUBACK and the retained message");
    // Live without Retain As Published: RETAIN cleared.
    d.publish(
        &mut b,
        "devices/d1/state",
        b"x",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    let got = s.recv(&mut b);
    assert!(
        got.iter()
            .any(|g| matches!(g, G::Publish { retain: false, .. })),
        "{got:?}"
    );
    // Retain Handling 2: never.
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    let rh2 = Opts {
        retain_handling: RetainHandling::DoNotSend,
        ..q(QoS::AtMostOnce)
    };
    assert_eq!(s2.subscribe(&mut b, &[("devices/#", rh2)], 0).len(), 1);
}

#[test]
fn the_subscriptions_maximum_qos_bounds_deliveries() {
    let mut b = Broker::new(cfg());
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    s.subscribe(&mut b, &[("devices/#", q(QoS::AtLeastOnce))], 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/x",
        b"2",
        QoS::ExactlyOnce,
        false,
        &[],
        0,
    );
    assert!(matches!(&s.recv(&mut b)[0], G::Publish { qos: 1, .. }));
}

// ---- 9. property forwarding ---------------------------------------------------

const FORWARDED: [Prop<'static>; 5] = [
    Prop::PayloadFormatIndicator(1),
    Prop::ContentType("text/plain"),
    Prop::ResponseTopic("devices/d1/reply"),
    Prop::CorrelationData(b"abc"),
    Prop::UserProperty("k", "v"),
];

#[test]
fn properties_reach_5_0_subscribers_and_not_3_1_1_ones() {
    let mut b = Broker::new(cfg());
    let (mut s5, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    s5.subscribe(&mut b, &[("devices/#", q(QoS::AtLeastOnce))], 0);
    let s4 = connect4(&mut b, "backend2", true, 0);
    let sub = Packet::Subscribe(Subscribe {
        packet_id: 1,
        topics: SubscribeTopics::List(&[("devices/#", QoS::AtMostOnce)]),
    });
    send4(&mut b, s4, &sub, 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    let mut props = FORWARDED.to_vec();
    props.push(Prop::TopicAlias(1));
    d.publish(
        &mut b,
        "devices/d1/req",
        b"hi",
        QoS::AtLeastOnce,
        false,
        &props,
        0,
    );
    let got = s5.recv(&mut b);
    let p: Vec<Prop<'_>> = got[0].props().iter().collect();
    assert_eq!(p, FORWARDED, "forwarded unchanged, minus the alias");
    // The 3.1.1 subscriber: topic and payload only.
    let out = b.output(s4).to_vec();
    b.consumed(s4, out.len());
    let (pkt, _) = decode(&out, &Limits::PROTOCOL_MAX).unwrap();
    assert!(matches!(pkt, Packet::Publish(p) if p.payload == b"hi"));
    // A 3.1.1 publisher's message has no properties for 5.0 subscribers.
    let c4 = connect4(&mut b, "d2", true, 0);
    let p = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "devices/d2/x",
        packet_id: None,
        payload: b"x",
    });
    send4(&mut b, c4, &p, 0);
    let got = s5.recv(&mut b);
    assert!(got[0].props().is_empty(), "{got:?}");
}

#[test]
fn retained_messages_and_remote_routes_keep_their_properties() {
    let mut b = Broker::new(Config {
        fanout: true,
        ..cfg()
    });
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/state",
        b"on",
        QoS::AtMostOnce,
        true,
        &FORWARDED,
        0,
    );
    // The route handed to the other shards carries the block.
    let routes: Vec<_> = b.drain_routes().collect();
    assert_eq!(routes.len(), 1);
    let (msg, _, retain, _) = &routes[0];
    assert!(retain);
    assert_eq!(
        Props::Raw(msg.props()).iter().collect::<Vec<_>>(),
        FORWARDED
    );
    // Another shard: the replica keeps them for a later subscriber.
    let mut other = Broker::new(cfg());
    other.route_remote(msg, QoS::AtMostOnce, true);
    let (mut s, _) = C5::connect(&mut other, "backend", true, &[], None, 0);
    let got = s.subscribe(&mut other, &[("devices/#", q(QoS::AtMostOnce))], 0);
    assert_eq!(got[1].props().iter().collect::<Vec<_>>(), FORWARDED);
    // And here, too.
    let (mut s, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let got = s.subscribe(&mut b, &[("devices/#", q(QoS::AtMostOnce))], 0);
    assert_eq!(got[1].props().iter().collect::<Vec<_>>(), FORWARDED);
}

#[test]
fn stored_messages_come_back_with_properties_and_expiry() {
    let mut b = Broker::new(cfg());
    let mut block = vec![0u8; 64];
    let p = P5::Publish(Publish5 {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "t",
        packet_id: None,
        properties: Props::List(&FORWARDED),
        payload: b"",
    });
    let n = urmqtt_mqtt::v5::encode(&p, &mut block).unwrap();
    // fixed header 2 + topic 3 + property length 1
    let props = &block[6..n];
    let st = StoredSession {
        expiry_s: Some(600),
        offline_for_s: 0,
        now_ms: 0,
    };
    let msgs = [
        StoredMsg {
            props: Some(props),
            expires_in_s: Some(9),
            ..StoredMsg::plain("devices/d1/cmd/a", b"1", QoS::AtLeastOnce, None)
        },
        StoredMsg {
            expires_in_s: Some(0),
            ..StoredMsg::plain("devices/d1/cmd/b", b"2", QoS::AtLeastOnce, None)
        },
        // A block that does not validate is dropped, the message kept.
        StoredMsg {
            props: Some(&[0xff, 0]),
            ..StoredMsg::plain("devices/d1/cmd/c", b"3", QoS::AtLeastOnce, None)
        },
    ];
    assert!(b.restore_session_v5("d1", st, [("devices/d1/cmd/#", 1u8)], msgs, []));
    assert_eq!(b.stats().messages_expired, 1);
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(600)],
        None,
        1000,
    );
    let got = d.recv(&mut b);
    assert_eq!(got.len(), 2, "{got:?}");
    let mut want = FORWARDED.to_vec();
    want.push(Prop::MessageExpiryInterval(8));
    assert_eq!(got[0].props().iter().collect::<Vec<_>>(), want);
    assert!(got[1].props().is_empty());
}

// ---- 10. persistence ----------------------------------------------------------

#[test]
fn persist_ops_carry_expiry_and_subscription_options() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (mut d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(90)],
        None,
        0,
    );
    let opts = Opts {
        no_local: true,
        retain_as_published: true,
        retain_handling: RetainHandling::SendIfNew,
        qos: QoS::ExactlyOnce,
    };
    d.subscribe(&mut b, &[("devices/d1/cmd/#", opts)], 0);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(&ops[0], PersistOp::SessionUpsert { expiry_s: 90, .. }),
        "{ops:?}"
    );
    assert!(
        matches!(&ops[1], PersistOp::Subscribe { options, qos: QoS::ExactlyOnce, .. } if *options == opts.to_byte()),
        "{ops:?}"
    );
    b.closed(d.c, 0);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(ops.last(), Some(PersistOp::SessionOffline { .. })),
        "{ops:?}"
    );
    // Back: online again (upsert clears the offline time), queue in RAM.
    C5::connect(
        &mut b,
        "d1",
        false,
        &[Prop::SessionExpiryInterval(90)],
        None,
        0,
    );
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(
            &ops[..],
            [
                PersistOp::SessionUpsert { expiry_s: 90, .. },
                PersistOp::QueueClear { .. }
            ]
        ),
        "{ops:?}"
    );
}

// ---- 11. memory -----------------------------------------------------------------

#[test]
fn the_5_0_state_is_one_small_box_and_aliases_cost_nothing_until_used() {
    assert!(
        core::mem::size_of::<v5::V5State>() <= 32,
        "{}",
        core::mem::size_of::<v5::V5State>()
    );
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    let k = b.conns.get(d.c).unwrap();
    assert!(k.v5().unwrap().aliases.is_none());
    d.publish(
        &mut b,
        "devices/d1/a",
        b"",
        QoS::AtMostOnce,
        false,
        &[Prop::TopicAlias(1)],
        0,
    );
    let k = b.conns.get(d.c).unwrap();
    assert_eq!(k.v5().unwrap().aliases.as_ref().map(|a| a.len()), Some(10));
}

#[test]
fn resends_after_a_reconnect_respect_the_new_receive_maximum() {
    let mut b = Broker::new(cfg());
    let props = |rm| [Prop::ReceiveMaximum(rm), Prop::SessionExpiryInterval(60)];
    let (mut d, _) = C5::connect(&mut b, "d1", true, &props(2), None, 0);
    d.subscribe(&mut b, &[("devices/d1/cmd/#", q(QoS::AtLeastOnce))], 0);
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    for i in 0..3u8 {
        svc.publish(
            &mut b,
            "devices/d1/cmd/x",
            &[i],
            QoS::AtLeastOnce,
            false,
            &[],
            0,
        );
    }
    assert_eq!(d.recv(&mut b).len(), 2);
    b.closed(d.c, 0);
    // Back with Receive Maximum 1: one resend at a time, DUP set.
    let (mut d, _) = C5::connect(&mut b, "d1", false, &props(1), None, 0);
    let got = d.recv(&mut b);
    assert!(
        matches!(&got[..], [G::Publish { dup: true, payload, pid: Some(1), .. }] if payload == &[0]),
        "{got:?}"
    );
    let ack = |pid| {
        P5::PubAck(Ack {
            packet_id: pid,
            reason: ReasonCode::Success,
            properties: Props::EMPTY,
        })
    };
    d.send(&mut b, &ack(1), 0);
    let got = d.recv(&mut b);
    assert!(
        matches!(&got[..], [G::Publish { dup: true, payload, pid: Some(2), .. }] if payload == &[1]),
        "{got:?}"
    );
    d.send(&mut b, &ack(2), 0);
    let got = d.recv(&mut b);
    assert!(
        matches!(&got[..], [G::Publish { dup: false, payload, .. }] if payload == &[2]),
        "{got:?}"
    );
}

// ---- publisher back-pressure (ADR-269) with 5.0 clients -------------------

fn wire5(p: &P5<'_>) -> Vec<u8> {
    let mut out = vec![0u8; urmqtt_mqtt::v5::encoded_len(p).unwrap()];
    urmqtt_mqtt::v5::encode(p, &mut out).unwrap();
    out
}

fn ack5(packet_id: u16) -> Ack<'static> {
    Ack {
        packet_id,
        reason: ReasonCode::Success,
        properties: Props::EMPTY,
    }
}

fn publish5(topic: &str, qos: QoS, pid: Option<u16>, payload: &[u8]) -> Vec<u8> {
    wire5(&P5::Publish(Publish5 {
        dup: false,
        qos,
        retain: false,
        topic,
        packet_id: pid,
        properties: Props::EMPTY,
        payload,
    }))
}

/// A 5.0 publisher paused for its one full QoS 0 subscriber (ADR-269): its
/// PINGREQ, PUBREL and PUBCOMP and two more QoS 2 PUBLISHes wait in the held
/// bytes at most 500 ms, are parsed as 5.0 and answered after, and the
/// Receive Maximum counts exactly what it would have without the pause: the
/// next unreleased one is DISCONNECT 0x93.
#[test]
fn a_paused_5_0_publisher_is_answered_within_the_bound() {
    use crate::flow::PAUSE_MAX_MS;
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            receive_maximum: 2,
            ..Mqtt5Policy::DEFAULT
        },
        rate_tokens: 1_000_000,
        max_outbound_bytes: 1024,
        max_queued: 1000,
        ..cfg()
    });
    let (mut sub, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    sub.subscribe(&mut b, &[("fleet/b", q(QoS::AtMostOnce))], 0);
    let (mut pubr, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    pubr.subscribe(&mut b, &[("fleet/a", q(QoS::ExactlyOnce))], 0);
    // pubr's QoS 2 publish (id 1) waits for its PUBREL.
    assert_eq!(
        pubr.publish_id(
            &mut b,
            "fleet/x",
            b"q2",
            QoS::ExactlyOnce,
            false,
            &[],
            Some(1),
            1
        ),
        [G::Ack(5, 1, 0)]
    );
    // A QoS 2 message to pubr: PUBREC from pubr, PUBREL back, its PUBCOMP
    // still owed.
    sub.publish_id(
        &mut b,
        "fleet/a",
        b"to-a",
        QoS::ExactlyOnce,
        false,
        &[],
        Some(5),
        1,
    );
    sub.send(&mut b, &P5::PubRel(ack5(5)), 1);
    let to_a = pubr
        .recv(&mut b)
        .into_iter()
        .find_map(|g| match g {
            G::Publish { pid: Some(p), .. } => Some(p),
            _ => None,
        })
        .unwrap();
    pubr.send(&mut b, &P5::PubRec(ack5(to_a)), 1);
    assert_eq!(pubr.recv(&mut b), [G::Ack(6, to_a, 0)]);
    // The flood fills sub (which never reads), then the rest is held.
    let mut bytes = Vec::new();
    for i in 0..300u32 {
        let mut payload = i.to_be_bytes().to_vec();
        payload.resize(64, 0);
        bytes.extend(publish5("fleet/b", QoS::AtMostOnce, None, &payload));
    }
    bytes.extend(wire5(&P5::PingReq));
    bytes.extend(wire5(&P5::PubRel(ack5(1))));
    bytes.extend(wire5(&P5::PubComp(ack5(to_a))));
    bytes.extend(publish5("fleet/x", QoS::ExactlyOnce, Some(2), b"q2"));
    bytes.extend(publish5("fleet/x", QoS::ExactlyOnce, Some(3), b"q2"));
    b.input(pubr.c, &bytes, 2);
    assert!(b.input_held(pubr.c));
    assert!(pubr.recv(&mut b).is_empty(), "nothing answered while held");
    b.poll_flow(1 + PAUSE_MAX_MS);
    assert!(b.input_held(pubr.c), "before the bound");
    b.poll_flow(2 + PAUSE_MAX_MS);
    while b.input_held(pubr.c) {
        b.poll_flow(2 + PAUSE_MAX_MS);
    }
    assert_eq!(
        pubr.recv(&mut b),
        [
            G::PingResp,
            G::Ack(7, 1, 0),
            G::Ack(5, 2, 0),
            G::Ack(5, 3, 0)
        ]
    );
    assert_eq!(b.close_requested(pubr.c), None);
    // Ids 2 and 3 unreleased: a third is one above the Receive Maximum.
    assert_eq!(
        pubr.publish_id(
            &mut b,
            "fleet/x",
            b"q2",
            QoS::ExactlyOnce,
            false,
            &[],
            Some(4),
            3
        ),
        [G::Disconnect(0x93, Some("receive maximum exceeded".into()))]
    );
    let fs = b.flow_stats();
    assert_eq!((fs.pauses, fs.timeouts, fs.holding), (1, 1, 0));
}

/// A 5.0 CONNECT for client id `id`, keep alive `ka`.
fn connect5(id: &str, ka: u16) -> P5<'_> {
    P5::Connect(Connect5 {
        clean_start: true,
        keep_alive: ka,
        properties: Props::EMPTY,
        client_id: id,
        will: None,
        username: None,
        password: None,
    })
}

/// Security review v0.6.0, AUTHZ-9 (ADR-362): `disallow` closed the sessions
/// whose identity left the allowlist (`disconnect_unless` walked sessions
/// only), but a connection authenticated as that identity whose CONNECT had
/// not come yet has no session, so it stayed; its later CONNECT was
/// accepted. It is now judged by the role its CONNECT would get.
#[test]
fn disallowing_an_identity_closes_its_connection_that_has_not_sent_connect() {
    let mut b = Broker::new(cfg());
    let mut d = C5::open(&mut b, 0);
    b.set_identity(d.c, "d1", false);
    let other = C5::open(&mut b, 0);
    b.set_identity(other.c, "d2", false);
    let svc = C5::open(&mut b, 0);
    b.set_identity(svc.c, "backend", false);
    let boot = C5::open(&mut b, 0);
    b.set_identity(boot.c, "d1", true);
    // As the kernel's allowlist rule: devices must be admitted, the other
    // roles are not asked.
    let roles = core::cell::RefCell::new(Vec::new());
    let closed = b.disconnect_unless(
        |id, role| {
            roles.borrow_mut().push((id.to_owned(), role));
            role != Role::Device || id != "d1"
        },
        CloseReason::Disallowed,
    );
    assert_eq!(closed, 1);
    assert_eq!(b.close_requested(d.c), Some(CloseReason::Disallowed));
    assert_eq!(b.close_requested(other.c), None);
    assert_eq!(b.close_requested(svc.c), None);
    assert_eq!(b.close_requested(boot.c), None);
    let mut roles = roles.into_inner();
    roles.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(roles.contains(&("backend".to_owned(), Role::Service)));
    assert!(roles.contains(&("d1".to_owned(), Role::Bootstrap)));
    assert!(roles.contains(&("d1".to_owned(), Role::Device)));
    // The CONNECT that follows is not answered: the connection is closing.
    d.send(&mut b, &connect5("d1", 0), 10);
    assert!(d.recv(&mut b).is_empty());
    assert_eq!(b.stats().sessions, 0);
}

/// AUTHZ-9 (ADR-362), the second half: a connection handed to the broker
/// with no CONNECT was never timed (the transport's handshake deadline ends
/// at the hand-over, the keep alive starts with the CONNECT), so it could
/// wait for its CONNECT for ever. It now has CONNECT_TIMEOUT_MS from
/// `open`, which bytes short of a CONNECT do not extend; the keep alive of a
/// CONNECT that comes in time runs from the CONNECT.
#[test]
fn a_connection_without_connect_is_closed_after_the_connect_timeout() {
    let mut b = Broker::new(cfg());
    let idle = C5::open(&mut b, 0);
    b.set_identity(idle.c, "d1", false);
    let drip = C5::open(&mut b, 0);
    b.set_identity(drip.c, "d2", false);
    let mut late = C5::open(&mut b, 0);
    b.set_identity(late.c, "d3", false);
    b.tick(CONNECT_TIMEOUT_MS);
    assert_eq!(b.close_requested(idle.c), None, "within the deadline");
    // One byte of a CONNECT, then nothing more.
    b.input(drip.c, &[0x10], CONNECT_TIMEOUT_MS - 1);
    // A CONNECT just in time, keep alive 5 s.
    late.send(&mut b, &connect5("d3", 5), CONNECT_TIMEOUT_MS - 1);
    assert!(matches!(late.recv(&mut b)[0], G::ConnAck { code: 0, .. }));
    b.tick(CONNECT_TIMEOUT_MS + 1);
    assert_eq!(
        b.close_requested(idle.c),
        Some(CloseReason::KeepAliveTimeout)
    );
    assert_eq!(
        b.close_requested(drip.c),
        Some(CloseReason::KeepAliveTimeout)
    );
    // The keep alive runs from the CONNECT (1.5 x 5 s), not from `open`.
    assert_eq!(b.close_requested(late.c), None);
    b.tick(CONNECT_TIMEOUT_MS - 1 + 7_400);
    assert_eq!(b.close_requested(late.c), None);
    b.tick(CONNECT_TIMEOUT_MS - 1 + 7_600);
    assert_eq!(
        b.close_requested(late.c),
        Some(CloseReason::KeepAliveTimeout)
    );
}

/// Security review v0.6.0, AUTHZ-4 (ADR-364): the Will was checked at
/// CONNECT only, and a close for a revocation (CloseReason::Disallowed)
/// published it, or armed it with its delay: a revoked device's delayed Will
/// went out 30 s after the revocation. It is dropped now.
#[test]
fn a_revoked_devices_delayed_will_is_dropped() {
    let mut b = Broker::new(cfg());
    let mut s = watcher(&mut b, 0);
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(30)),
        0,
    );
    b.disconnect_conn(d.c, CloseReason::Disallowed);
    b.closed(d.c, 100);
    assert_eq!(b.stats().wills_pending, 0, "not armed");
    b.tick(30_100);
    b.tick(60_100);
    assert!(s.recv(&mut b).is_empty());
    assert_eq!(b.stats().wills_published, 0);
    // Any other close still publishes (or arms) the Will.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[Prop::SessionExpiryInterval(60)],
        Some(will(0)),
        61_000,
    );
    b.closed(d.c, 61_100);
    assert_eq!(s.recv(&mut b).len(), 1);
}

/// AUTHZ-4 (ADR-364): a run-time account narrowed to read-only ("no
/// publish, no Will") has its live login closed (Disallowed); that close
/// published the Will it armed while it was `full`.
#[test]
fn a_narrowed_accounts_will_is_dropped_with_its_login() {
    let mut b = Broker::new(Config {
        plain: Some(plain()),
        ..cfg()
    });
    let mut a = C5::open(&mut b, 0);
    assert!(b.set_plain_identity(a.c, "alice"));
    a.send(&mut b, &connect5("a", 0), 0);
    a.recv(&mut b);
    a.subscribe(&mut b, &[("lan/#", q(QoS::AtMostOnce))], 0);
    let mut p = C5::open(&mut b, 0);
    assert!(b.set_plain_identity(p.c, "bob"));
    p.send(
        &mut b,
        &P5::Connect(Connect5 {
            clean_start: true,
            keep_alive: 0,
            properties: Props::EMPTY,
            client_id: "x",
            will: Some(Will5 {
                properties: Props::EMPTY,
                topic: "lan/bob/status",
                payload: b"gone",
                qos: QoS::AtMostOnce,
                retain: false,
            }),
            username: None,
            password: None,
        }),
        0,
    );
    assert_eq!(p.recv(&mut b)[0].code(), 0);
    b.set_login_class(|id| {
        if id == "bob" {
            CLASS_READ_ONLY
        } else {
            CLASS_FULL
        }
    });
    let closed = b.disconnect_unless(|id, _| id != "bob", CloseReason::Disallowed);
    assert_eq!(closed, 1);
    b.closed(p.c, 10);
    let got = a.recv(&mut b);
    assert!(
        !got.iter()
            .any(|g| matches!(g, G::Publish { topic, .. } if topic == "lan/bob/status")),
        "{got:?}"
    );
}

#[path = "shared_tests.rs"]
mod shared_tests;
