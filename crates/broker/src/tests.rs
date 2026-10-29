//! End-to-end broker tests over an in-memory transport.

use super::*;
use urmqtt_mqtt::{Subscribe, SubscribeTopics, Unsubscribe, UnsubscribeTopics, Will as MqttWill};

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/cmd/#"],
    service_ids: &["backend"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    service_subscribe: &["devices/#", "fleet/#", "$SYS/#"],
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
        max_connections: 16,
        max_subscriptions_per_session: 4,
        max_inflight: 2,
        max_queued: 3,
        rate_tokens: 100,
        rate_period_ms: 1000,
        max_outbound_bytes: 64 * 1024,
        acl: ACL,
    }
}

/// A client on the in-memory transport.
struct Client {
    c: ConnId,
    rx: Vec<u8>,
    /// Packets decoded but not yet returned by `recv`.
    pending: Vec<Got>,
}

#[derive(Debug, PartialEq)]
enum Got {
    ConnAck(bool, u8),
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        pid: Option<u16>,
        retain: bool,
        dup: bool,
    },
    PubAck(u16),
    SubAck(u16, Vec<u8>),
    UnsubAck(u16),
    PingResp,
}

impl Client {
    fn raw(b: &mut Broker, bytes: &[u8], now: u64) -> Client {
        let c = b.open(now).unwrap();
        b.input(c, bytes, now);
        Client {
            c,
            rx: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn send(&self, b: &mut Broker, p: &Packet<'_>, now: u64) {
        let mut out = vec![0u8; encoded_len(p)];
        encode(p, &mut out).unwrap();
        // Feed byte by byte half the time to exercise reassembly.
        if out.len() % 2 == 0 {
            for byte in &out {
                b.input(self.c, std::slice::from_ref(byte), now);
            }
        } else {
            b.input(self.c, &out, now);
        }
    }

    fn connect(
        b: &mut Broker,
        id: &str,
        clean: bool,
        will: Option<MqttWill<'_>>,
        now: u64,
    ) -> (Client, Got) {
        let c = Client {
            c: b.open(now).unwrap(),
            rx: Vec::new(),
            pending: Vec::new(),
        };
        c.send(
            b,
            &Packet::Connect(Connect {
                protocol_level: 4,
                clean_session: clean,
                keep_alive: 10,
                client_id: id,
                will,
                username: None,
                password: None,
            }),
            now,
        );
        let mut c = c;
        let mut got = c.recv(b);
        let ack = got.remove(0);
        c.pending = got;
        (c, ack)
    }

    fn recv(&mut self, b: &mut Broker) -> Vec<Got> {
        let out = b.output(self.c).to_vec();
        b.consumed(self.c, out.len());
        self.rx.extend_from_slice(&out);
        let mut got = core::mem::take(&mut self.pending);
        loop {
            match decode(&self.rx, &Limits::PROTOCOL_MAX) {
                Ok((p, n)) => {
                    got.push(match p {
                        Packet::ConnAck(a) => Got::ConnAck(a.session_present, a.code as u8),
                        Packet::Publish(p) => Got::Publish {
                            topic: p.topic.into(),
                            payload: p.payload.into(),
                            qos: p.qos as u8,
                            pid: p.packet_id,
                            retain: p.retain,
                            dup: p.dup,
                        },
                        Packet::PubAck(i) => Got::PubAck(i),
                        Packet::SubAck(s) => Got::SubAck(s.packet_id, s.return_codes.to_vec()),
                        Packet::UnsubAck(i) => Got::UnsubAck(i),
                        Packet::PingResp => Got::PingResp,
                        other => panic!("unexpected {other:?}"),
                    });
                    self.rx.drain(..n);
                }
                Err(urmqtt_mqtt::Error::Incomplete(_)) => return got,
                Err(e) => panic!("{e:?}"),
            }
        }
    }

    fn subscribe(
        &mut self,
        b: &mut Broker,
        pid: u16,
        topics: &[(&str, QoS)],
        now: u64,
    ) -> Vec<Got> {
        self.send(
            b,
            &Packet::Subscribe(Subscribe {
                packet_id: pid,
                topics: SubscribeTopics::List(topics),
            }),
            now,
        );
        self.recv(b)
    }

    fn publish(
        &mut self,
        b: &mut Broker,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        retain: bool,
        now: u64,
    ) -> Vec<Got> {
        let pid = (qos != QoS::AtMostOnce).then_some(7);
        self.send(
            b,
            &Packet::Publish(Publish {
                dup: false,
                qos,
                retain,
                topic,
                packet_id: pid,
                payload,
            }),
            now,
        );
        self.recv(b)
    }

    /// Drops the network connection without DISCONNECT.
    fn kill(self, b: &mut Broker, now: u64) {
        b.closed(self.c, now);
    }

    fn disconnect(self, b: &mut Broker, now: u64) {
        self.send(b, &Packet::Disconnect, now);
        assert_eq!(
            b.close_requested(self.c),
            Some(CloseReason::ClientDisconnect)
        );
        b.closed(self.c, now);
    }
}

fn publish(topic: &str, payload: &[u8], qos: u8, pid: Option<u16>, retain: bool) -> Got {
    Got::Publish {
        topic: topic.into(),
        payload: payload.into(),
        qos,
        pid,
        retain,
        dup: false,
    }
}

#[test]
fn connect_accept_and_identity_rules() {
    let mut b = Broker::new(cfg());
    let (_, ack) = Client::connect(&mut b, "d1", true, None, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
    for bad in ["", "a/b", "x+", "#", "$sys"] {
        let (c, ack) = Client::connect(&mut b, bad, true, None, 0);
        assert_eq!(ack, Got::ConnAck(false, 2), "{bad:?}");
        assert_eq!(b.close_requested(c.c), Some(CloseReason::Rejected));
    }
}

#[test]
fn unsupported_protocol_level_gets_connack_1() {
    let mut b = Broker::new(cfg());
    let v5 = [
        0x10u8, 12, 0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 60, 0, 0,
    ];
    let mut c = Client::raw(&mut b, &v5, 0);
    assert_eq!(c.recv(&mut b), vec![Got::ConnAck(false, 1)]);
    assert_eq!(b.close_requested(c.c), Some(CloseReason::Unsupported));
}

#[test]
fn first_packet_must_be_connect_and_only_once() {
    let mut b = Broker::new(cfg());
    let c = Client::raw(&mut b, &[0xc0, 0], 0);
    assert_eq!(b.close_requested(c.c), Some(CloseReason::ProtocolError));
    let (c, _) = Client::connect(&mut b, "d1", true, None, 0);
    c.send(
        &mut b,
        &Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: true,
            keep_alive: 0,
            client_id: "d1",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    assert_eq!(b.close_requested(c.c), Some(CloseReason::ProtocolError));
    let garbage = Client::raw(&mut b, &[0x10, 2, 0xff, 0xff], 0);
    assert_eq!(
        b.close_requested(garbage.c),
        Some(CloseReason::ProtocolError)
    );
}

#[test]
fn pubsub_with_wildcards_and_acl() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    assert_eq!(
        svc.subscribe(
            &mut b,
            1,
            &[
                ("devices/+/telemetry/#", QoS::AtLeastOnce),
                ("other/#", QoS::AtMostOnce)
            ],
            0
        ),
        vec![Got::SubAck(1, vec![1, 0x80])]
    );
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    // Device may not subscribe outside its cmd tree or with wildcards over ids.
    assert_eq!(
        d1.subscribe(
            &mut b,
            2,
            &[
                ("devices/+/cmd/#", QoS::AtMostOnce),
                ("devices/d1/cmd/#", QoS::ExactlyOnce)
            ],
            0
        ),
        vec![Got::SubAck(2, vec![0x80, 1])],
        "QoS 2 granted as 1"
    );
    assert_eq!(
        d1.publish(
            &mut b,
            "devices/d1/telemetry/temp",
            b"21.5",
            QoS::AtLeastOnce,
            false,
            0
        ),
        vec![Got::PubAck(7)]
    );
    assert_eq!(
        svc.recv(&mut b),
        vec![publish(
            "devices/d1/telemetry/temp",
            b"21.5",
            1,
            Some(1),
            false
        )]
    );
    // Publishing into another device's tree is acknowledged and dropped.
    assert_eq!(
        d1.publish(
            &mut b,
            "devices/d2/telemetry/temp",
            b"x",
            QoS::AtLeastOnce,
            false,
            0
        ),
        vec![Got::PubAck(7)]
    );
    assert_eq!(svc.recv(&mut b), vec![]);
    assert_eq!(b.stats().dropped_acl, 1);
    // Service command to the device; QoS downgraded to the subscription's.
    svc.publish(
        &mut b,
        "devices/d1/cmd/reboot",
        b"now",
        QoS::AtMostOnce,
        false,
        0,
    );
    assert_eq!(
        d1.recv(&mut b),
        vec![publish("devices/d1/cmd/reboot", b"now", 0, None, false)]
    );
}

#[test]
fn retained_set_deliver_and_clear() {
    let mut b = Broker::new(cfg());
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.publish(
        &mut b,
        "devices/d1/status",
        b"online",
        QoS::AtLeastOnce,
        true,
        0,
    );
    d1.publish(&mut b, "devices/d1/fw", b"1.2", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 2);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let got = svc.subscribe(&mut b, 1, &[("devices/#", QoS::AtLeastOnce)], 0);
    assert_eq!(got[0], Got::SubAck(1, vec![1]));
    let mut rest: Vec<_> = got[1..].iter().collect();
    rest.sort_by_key(|g| format!("{g:?}"));
    assert_eq!(rest.len(), 2);
    assert!(rest.contains(&&Got::Publish {
        topic: "devices/d1/status".into(),
        payload: b"online".to_vec(),
        qos: 1,
        pid: Some(1),
        retain: true,
        dup: false
    }));
    assert!(rest.contains(&&publish("devices/d1/fw", b"1.2", 0, None, true)));
    // A live publish of a retained message reaches existing subscribers
    // without the RETAIN flag (§3.3.1.3).
    d1.publish(&mut b, "devices/d1/fw", b"1.3", QoS::AtMostOnce, true, 0);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/fw", b"1.3", 0, None, false)]
    );
    // Empty payload clears it.
    d1.publish(&mut b, "devices/d1/fw", b"", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 1);
}

#[test]
fn dollar_topics_hidden_from_root_wildcards() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("$SYS/#", QoS::AtMostOnce)], 0);
    let mut topics = Topics::new();
    let n = topics.intern("$SYS/x");
    topics.subscribe(n, 9, QoS::AtMostOnce);
    let h = topics.intern("#");
    topics.subscribe(h, 8, QoS::AtMostOnce);
    let mut out = Vec::new();
    topics.subscribers("$SYS/x", &mut out);
    assert_eq!(out, vec![(9, QoS::AtMostOnce)], "'#' must not match $SYS");
    topics.subscribers("a/b", &mut out);
    assert_eq!(out, vec![(8, QoS::AtMostOnce)]);
}

#[test]
fn will_on_unclean_close_not_on_disconnect() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/+/status", QoS::AtLeastOnce)], 0);
    let will = MqttWill {
        topic: "devices/d1/status",
        payload: b"offline",
        qos: QoS::AtLeastOnce,
        retain: true,
    };
    let (d1, _) = Client::connect(&mut b, "d1", true, Some(will), 0);
    d1.kill(&mut b, 0);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/status", b"offline", 1, Some(1), false)]
    );
    assert_eq!(b.stats().retained, 1, "will retain honoured");
    let (d1, _) = Client::connect(&mut b, "d1", true, Some(will), 0);
    d1.disconnect(&mut b, 0);
    assert_eq!(
        svc.recv(&mut b),
        vec![],
        "clean DISCONNECT discards the will"
    );
    // A will outside the device's publish rights is refused at CONNECT.
    let bad = MqttWill {
        topic: "devices/d9/status",
        payload: b"x",
        qos: QoS::AtMostOnce,
        retain: false,
    };
    let (_, ack) = Client::connect(&mut b, "d1", true, Some(bad), 0);
    assert_eq!(ack, Got::ConnAck(false, 5));
}

#[test]
fn keepalive_timeout_closes_and_publishes_will() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/+/status", QoS::AtMostOnce)], 0);
    let will = MqttWill {
        topic: "devices/d1/status",
        payload: b"gone",
        qos: QoS::AtMostOnce,
        retain: false,
    };
    let (mut d1, _) = Client::connect(&mut b, "d1", true, Some(will), 0);
    d1.send(&mut b, &Packet::PingReq, 9_000);
    assert_eq!(d1.recv(&mut b), vec![Got::PingResp]);
    svc.send(&mut b, &Packet::PingReq, 14_000);
    svc.send(&mut b, &Packet::PingReq, 23_000);
    assert_eq!(svc.recv(&mut b), vec![Got::PingResp, Got::PingResp]);
    b.tick(20_000); // 11 s since d1's last packet, keepalive 10 s * 1.5 = 15 s
    assert_eq!(b.close_requested(d1.c), None);
    b.tick(24_001);
    assert_eq!(b.close_requested(d1.c), Some(CloseReason::KeepAliveTimeout));
    d1.kill(&mut b, 24_001);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/status", b"gone", 0, None, false)]
    );
}

#[test]
fn qos1_redelivery_after_reconnect_persistent_session() {
    let mut b = Broker::new(cfg());
    let (mut d2, ack) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
    d2.subscribe(&mut b, 1, &[("devices/d2/cmd/#", QoS::AtLeastOnce)], 0);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    // In flight but never acknowledged, then the device drops.
    svc.publish(&mut b, "devices/d2/cmd/a", b"1", QoS::AtLeastOnce, false, 0);
    assert_eq!(
        d2.recv(&mut b),
        vec![publish("devices/d2/cmd/a", b"1", 1, Some(1), false)]
    );
    d2.kill(&mut b, 0);
    // Published while offline: queued.
    svc.publish(&mut b, "devices/d2/cmd/b", b"2", QoS::AtLeastOnce, false, 0);
    svc.publish(&mut b, "devices/d2/cmd/c", b"3", QoS::AtMostOnce, false, 0);
    let (mut d2, ack) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack, Got::ConnAck(true, 0), "session present");
    let got = d2.recv(&mut b);
    assert_eq!(
        got,
        vec![
            Got::Publish {
                topic: "devices/d2/cmd/a".into(),
                payload: b"1".to_vec(),
                qos: 1,
                pid: Some(1),
                retain: false,
                dup: true
            },
            publish("devices/d2/cmd/b", b"2", 1, Some(2), false),
        ],
        "in-flight resent with DUP, queued QoS 1 delivered, offline QoS 0 dropped"
    );
    d2.send(&mut b, &Packet::PubAck(1), 0);
    d2.send(&mut b, &Packet::PubAck(2), 0);
    // A clean session discards everything.
    d2.kill(&mut b, 0);
    let (_, ack) = Client::connect(&mut b, "d2", true, None, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
}

#[test]
fn inflight_window_and_queue_bounds() {
    let mut b = Broker::new(cfg()); // max_inflight 2, max_queued 3
    let (mut d1, _) = Client::connect(&mut b, "d1", false, None, 0);
    d1.subscribe(&mut b, 1, &[("devices/d1/cmd/#", QoS::AtLeastOnce)], 0);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    for i in 0..7u8 {
        svc.publish(&mut b, "devices/d1/cmd/x", &[i], QoS::AtLeastOnce, false, 0);
    }
    let got = d1.recv(&mut b);
    assert_eq!(got.len(), 2, "window of 2");
    assert_eq!(
        b.stats().dropped_queue_full,
        2,
        "7 = 2 in flight + 3 queued + 2 dropped"
    );
    d1.send(&mut b, &Packet::PubAck(1), 0);
    assert_eq!(
        d1.recv(&mut b),
        vec![publish("devices/d1/cmd/x", &[2], 1, Some(3), false)]
    );
}

#[test]
fn subscription_limit_and_unsubscribe() {
    let mut b = Broker::new(cfg()); // max 4 subscriptions
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let topics = [
        ("fleet/a", QoS::AtMostOnce),
        ("fleet/b", QoS::AtMostOnce),
        ("fleet/c", QoS::AtMostOnce),
        ("fleet/d", QoS::AtMostOnce),
        ("fleet/e", QoS::AtMostOnce),
    ];
    assert_eq!(
        svc.subscribe(&mut b, 1, &topics, 0),
        vec![Got::SubAck(1, vec![0, 0, 0, 0, 0x80])]
    );
    // Re-subscribing to an existing filter replaces it, no new slot needed.
    assert_eq!(
        svc.subscribe(&mut b, 2, &[("fleet/a", QoS::AtLeastOnce)], 0),
        vec![Got::SubAck(2, vec![1])]
    );
    svc.send(
        &mut b,
        &Packet::Unsubscribe(Unsubscribe {
            packet_id: 3,
            topics: UnsubscribeTopics::List(&["fleet/a", "fleet/zzz"]),
        }),
        0,
    );
    assert_eq!(svc.recv(&mut b), vec![Got::UnsubAck(3)]);
    assert_eq!(b.stats().subscriptions, 3);
    svc.publish(&mut b, "fleet/a", b"x", QoS::AtMostOnce, false, 0);
    assert_eq!(svc.recv(&mut b), vec![]);
}

#[test]
fn takeover_closes_old_connection_and_keeps_session() {
    let mut b = Broker::new(cfg());
    let (mut old, _) = Client::connect(&mut b, "d1", false, None, 0);
    old.subscribe(&mut b, 1, &[("devices/d1/cmd/#", QoS::AtLeastOnce)], 0);
    let (mut new, ack) = Client::connect(&mut b, "d1", false, None, 0);
    assert_eq!(ack, Got::ConnAck(true, 0));
    assert_eq!(b.close_requested(old.c), Some(CloseReason::TakenOver));
    let old_c = old.c;
    old.kill(&mut b, 0);
    assert!(b.close_requested(old_c).is_none(), "slot freed");
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.publish(&mut b, "devices/d1/cmd/x", b"!", QoS::AtLeastOnce, false, 0);
    assert_eq!(
        new.recv(&mut b),
        vec![publish("devices/d1/cmd/x", b"!", 1, Some(1), false)]
    );
}

#[test]
fn rate_limit_drops_excess() {
    let mut c = cfg();
    c.rate_tokens = 3;
    let mut b = Broker::new(c);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/#", QoS::AtMostOnce)], 0);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    for _ in 0..5 {
        d1.publish(&mut b, "devices/d1/t", b"x", QoS::AtMostOnce, false, 0);
    }
    assert_eq!(svc.recv(&mut b).len(), 3);
    assert_eq!(b.stats().dropped_rate, 2);
    // A second later the bucket has refilled.
    d1.publish(&mut b, "devices/d1/t", b"x", QoS::AtMostOnce, false, 1000);
    assert_eq!(svc.recv(&mut b).len(), 1);
}

#[test]
fn qos2_publish_is_refused_and_limits_hold() {
    let mut b = Broker::new(cfg());
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.publish(&mut b, "devices/d1/x", b"x", QoS::ExactlyOnce, false, 0);
    assert_eq!(b.close_requested(d1.c), Some(CloseReason::Unsupported));
    // Oversized packets are refused before buffering the body.
    let (d2, _) = Client::connect(&mut b, "d2", true, None, 0);
    b.input(d2.c, &[0x30, 0xff, 0xff, 0x03], 0);
    assert_eq!(b.close_requested(d2.c), Some(CloseReason::ProtocolError));
    // Connection limit.
    let mut b = Broker::new(Config {
        max_connections: 1,
        ..cfg()
    });
    assert!(b.open(0).is_some());
    assert!(b.open(0).is_none());
}

#[test]
fn many_sessions_route_correctly() {
    let mut b = Broker::new(Config {
        max_connections: 300,
        ..cfg()
    });
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/+/telemetry", QoS::AtMostOnce)], 0);
    let mut devs: Vec<Client> = (0..200)
        .map(|i| Client::connect(&mut b, &format!("dev{i}"), true, None, 0).0)
        .collect();
    for (i, d) in devs.iter_mut().enumerate() {
        d.publish(
            &mut b,
            &format!("devices/dev{i}/telemetry"),
            b"v",
            QoS::AtMostOnce,
            false,
            0,
        );
    }
    assert_eq!(svc.recv(&mut b).len(), 200);
    assert_eq!(b.stats().sessions, 201);
}

#[test]
fn client_id_must_match_certificate_identity() {
    let mut b = Broker::new(cfg());
    let c = b.open(0).unwrap();
    b.set_identity(c, "device-001");
    let mut cl = Client {
        c,
        rx: Vec::new(),
        pending: Vec::new(),
    };
    cl.send(
        &mut b,
        &Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: true,
            keep_alive: 0,
            client_id: "device-002",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    assert_eq!(cl.recv(&mut b), vec![Got::ConnAck(false, 2)]);
    let c = b.open(0).unwrap();
    b.set_identity(c, "device-001");
    let mut cl = Client {
        c,
        rx: Vec::new(),
        pending: Vec::new(),
    };
    cl.send(
        &mut b,
        &Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: true,
            keep_alive: 0,
            client_id: "device-001",
            will: None,
            username: None,
            password: None,
        }),
        0,
    );
    assert_eq!(cl.recv(&mut b), vec![Got::ConnAck(false, 0)]);
}
