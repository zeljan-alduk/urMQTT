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
        max_retained_per_device: 4,
        max_retained_bytes: 4096,
        rate_tokens: 100,
        rate_period_ms: 1000,
        max_outbound_bytes: 64 * 1024,
        acl: ACL,
        persist: false,
        telemetry: &["devices/+/telemetry/#"],
        fanout: false,
        control_ids: &["operator"],
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
    b.set_identity(c, "device-001", false);
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
    b.set_identity(c, "device-001", false);
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

/// Stored sessions: subscriptions and queued (topic, payload) messages.
type StoredSessions =
    std::collections::BTreeMap<String, (Vec<(String, QoS)>, Vec<(String, Vec<u8>)>)>;

/// A model of the durable store: applies persist ops like the SQLite store.
#[derive(Default, Debug)]
struct Model {
    retained: std::collections::BTreeMap<String, (Vec<u8>, QoS)>,
    sessions: StoredSessions,
}

impl Model {
    fn apply(&mut self, b: &mut Broker) {
        for op in b.drain_persist() {
            match op {
                PersistOp::Retain { msg, qos } => {
                    if msg.payload.is_empty() {
                        self.retained.remove(&*msg.topic);
                    } else {
                        self.retained
                            .insert(msg.topic.to_string(), (msg.payload.to_vec(), qos));
                    }
                }
                PersistOp::SessionUpsert { client_id } => {
                    self.sessions.entry(client_id.to_string()).or_default();
                }
                PersistOp::SessionDelete { client_id } => {
                    self.sessions.remove(&*client_id);
                }
                PersistOp::Subscribe {
                    client_id,
                    filter,
                    qos,
                } => {
                    let s = self
                        .sessions
                        .get_mut(&*client_id)
                        .expect("FK: session first");
                    s.0.retain(|(f, _)| *f != *filter);
                    s.0.push((filter.to_string(), qos));
                }
                PersistOp::Unsubscribe { client_id, filter } => {
                    if let Some(s) = self.sessions.get_mut(&*client_id) {
                        s.0.retain(|(f, _)| *f != *filter);
                    }
                }
                PersistOp::QueuePush { client_id, msg } => {
                    let s = self
                        .sessions
                        .get_mut(&*client_id)
                        .expect("FK: session first");
                    s.1.push((msg.topic.to_string(), msg.payload.to_vec()));
                }
                PersistOp::QueueClear { client_id } => {
                    if let Some(s) = self.sessions.get_mut(&*client_id) {
                        s.1.clear();
                    }
                }
            }
        }
    }

    fn restore(&self) -> Broker {
        let mut b = Broker::new(Config {
            persist: true,
            ..cfg()
        });
        for (t, (p, q)) in &self.retained {
            b.restore_retained(t, p, *q);
        }
        for (id, (subs, queue)) in &self.sessions {
            b.restore_session(
                id,
                subs.iter().map(|(f, q)| (f.as_str(), *q)),
                queue.iter().map(|(t, p)| (t.as_str(), p.as_slice())),
            );
        }
        b
    }
}

#[test]
fn persisted_state_survives_a_restart() {
    let mut m = Model::default();
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    // A retained message, set then replaced, and one set then cleared.
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.publish(&mut b, "devices/d1/fw", b"1.0", QoS::AtLeastOnce, true, 0);
    d1.publish(&mut b, "devices/d1/fw", b"1.1", QoS::AtLeastOnce, true, 0);
    d1.publish(&mut b, "devices/d1/tmp", b"x", QoS::AtMostOnce, true, 0);
    d1.publish(&mut b, "devices/d1/tmp", b"", QoS::AtMostOnce, true, 0);
    // A persistent device with a command subscription goes offline with one
    // command unacknowledged; another arrives while it is away.
    let (mut d2, ack) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
    d2.subscribe(&mut b, 1, &[("devices/d2/cmd/#", QoS::AtLeastOnce)], 0);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.publish(&mut b, "devices/d2/cmd/a", b"1", QoS::AtLeastOnce, false, 0);
    d2.recv(&mut b);
    d2.kill(&mut b, 0);
    svc.publish(&mut b, "devices/d2/cmd/b", b"2", QoS::AtLeastOnce, false, 0);
    // Clean sessions are never stored.
    let (mut d3, _) = Client::connect(&mut b, "d3", true, None, 0);
    d3.subscribe(&mut b, 1, &[("devices/d3/cmd/#", QoS::AtLeastOnce)], 0);
    m.apply(&mut b);
    assert_eq!(m.retained.len(), 1);
    assert_eq!(m.sessions.len(), 1);
    assert_eq!(m.sessions["d2"].1.len(), 2);

    // "Reboot": a fresh broker restored from the model.
    let mut b = m.restore();
    assert!(b.drain_persist().next().is_none(), "restore writes nothing");
    let (mut d2, ack) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack, Got::ConnAck(true, 0));
    let got = d2.recv(&mut b);
    assert_eq!(
        got,
        vec![
            publish("devices/d2/cmd/a", b"1", 1, Some(1), false),
            publish("devices/d2/cmd/b", b"2", 1, Some(2), false),
        ]
    );
    m.apply(&mut b);
    assert!(
        m.sessions["d2"].1.is_empty(),
        "queue back in RAM after reconnect"
    );
    // The restored subscription routes live traffic.
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.publish(&mut b, "devices/d2/cmd/c", b"3", QoS::AtMostOnce, false, 0);
    assert_eq!(
        d2.recv(&mut b),
        vec![publish("devices/d2/cmd/c", b"3", 0, None, false)]
    );
    // Retained message restored for a new subscriber.
    let got = svc.subscribe(&mut b, 2, &[("devices/+/fw", QoS::AtLeastOnce)], 0);
    assert!(
        got.contains(&publish("devices/d1/fw", b"1.1", 1, Some(1), true)),
        "{got:?}"
    );
    // Reconnecting with a clean session deletes the stored session.
    // d2 never acknowledged a and b: the disconnect snapshot keeps them.
    d2.disconnect(&mut b, 0);
    m.apply(&mut b);
    assert_eq!(m.sessions["d2"].1.len(), 2);
    let _ = Client::connect(&mut b, "d2", true, None, 0);
    m.apply(&mut b);
    assert!(m.sessions.is_empty());
}

#[test]
fn restore_drops_what_the_policy_no_longer_allows() {
    let mut m = Model::default();
    m.sessions.insert(
        "d1".into(),
        (
            vec![
                ("devices/d1/cmd/#".into(), QoS::AtLeastOnce),
                ("devices/d2/cmd/#".into(), QoS::AtLeastOnce),
            ],
            vec![("devices/d1/cmd/x".into(), b"q".to_vec())],
        ),
    );
    m.sessions.insert("bad/id".into(), (vec![], vec![]));
    let mut b = m.restore();
    m.apply(&mut b);
    assert_eq!(
        m.sessions["d1"].0,
        vec![("devices/d1/cmd/#".into(), QoS::AtLeastOnce)]
    );
    assert!(!m.sessions.contains_key("bad/id"));
    let (mut d1, ack) = Client::connect(&mut b, "d1", false, None, 0);
    assert_eq!(ack, Got::ConnAck(true, 0));
    assert_eq!(
        d1.recv(&mut b),
        vec![publish("devices/d1/cmd/x", b"q", 1, Some(1), false)]
    );
}

#[test]
fn telemetry_topics_are_handed_to_the_log() {
    let mut b = Broker::new(cfg());
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.publish(
        &mut b,
        "devices/d1/telemetry/temp",
        b"21.5",
        QoS::AtLeastOnce,
        false,
        0,
    );
    d1.publish(
        &mut b,
        "devices/d1/status",
        b"up",
        QoS::AtMostOnce,
        false,
        0,
    );
    // Outside the ACL: never accepted, never logged.
    d1.publish(
        &mut b,
        "devices/d2/telemetry/temp",
        b"x",
        QoS::AtMostOnce,
        false,
        0,
    );
    let got: Vec<_> = b.drain_telemetry().collect();
    assert_eq!(got.len(), 1);
    assert_eq!(&*got[0].topic, "devices/d1/telemetry/temp");
    assert_eq!(&*got[0].payload, b"21.5");
    assert!(b.drain_telemetry().next().is_none());
}

/// Two shards connected the way the kernel connects them: whatever one
/// routes, the other routes too (subscribers, retained replica).
#[test]
fn shards_fan_out_publishes_and_retained_messages() {
    let shard = || {
        Broker::new(Config {
            fanout: true,
            persist: true,
            ..cfg()
        })
    };
    let (mut a, mut b) = (shard(), shard());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/+/telemetry/#", QoS::AtLeastOnce)], 0);
    let (mut d1, _) = Client::connect(&mut a, "d1", true, None, 0);
    d1.publish(
        &mut a,
        "devices/d1/telemetry/t",
        b"1",
        QoS::AtLeastOnce,
        false,
        0,
    );
    d1.publish(&mut a, "devices/d1/fw", b"9", QoS::AtLeastOnce, true, 0);
    for (m, q, r) in a.drain_routes().collect::<Vec<_>>() {
        b.route_remote(&m, q, r);
    }
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/telemetry/t", b"1", 1, Some(1), false)]
    );
    // The retained replica on shard b serves new subscribers there; only
    // shard a (the origin) persists it.
    let got = svc.subscribe(&mut b, 2, &[("devices/+/fw", QoS::AtLeastOnce)], 0);
    assert!(
        got.contains(&publish("devices/d1/fw", b"9", 1, Some(2), true)),
        "{got:?}"
    );
    assert!(
        a.drain_persist()
            .any(|op| matches!(op, PersistOp::Retain { .. }))
    );
    assert!(
        !b.drain_persist()
            .any(|op| matches!(op, PersistOp::Retain { .. }))
    );
    // Remote routes are not fanned out again.
    assert!(b.drain_routes().next().is_none());
}

/// Device-scoped subscriptions (PROMPT §7.3) behave like ordinary ones but
/// add no trie nodes per device, survive a restart and unsubscribe cleanly.
#[test]
fn device_scoped_subscriptions_share_one_filter() {
    let acl = Acl {
        device_subscribe: &["devices/{id}/#"],
        ..ACL
    };
    let mut b = Broker::new(Config {
        max_connections: 300,
        persist: true,
        acl,
        ..cfg()
    });
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let mut devs: Vec<Client> = (0..100)
        .map(|i| Client::connect(&mut b, &format!("dev{i}"), false, None, 0).0)
        .collect();
    let nodes = b.stats().topic_nodes;
    for (i, d) in devs.iter_mut().enumerate() {
        assert_eq!(
            d.subscribe(
                &mut b,
                1,
                &[(&format!("devices/dev{i}/cmd/#"), QoS::AtLeastOnce)],
                0
            ),
            vec![Got::SubAck(1, vec![1])]
        );
    }
    assert_eq!(b.stats().topic_nodes, nodes, "no per-device trie nodes");
    assert_eq!(b.stats().subscriptions, 100);
    // Stored with the full filter.
    let stored: Vec<String> = b
        .drain_persist()
        .filter_map(|op| match op {
            PersistOp::Subscribe {
                client_id, filter, ..
            } if &*client_id == "dev7" => Some(filter.into()),
            _ => None,
        })
        .collect();
    assert_eq!(stored, vec!["devices/dev7/cmd/#".to_string()]);
    // Delivery: only the named device, the parent level matches `#`.
    svc.publish(
        &mut b,
        "devices/dev7/cmd/reboot",
        b"r",
        QoS::AtLeastOnce,
        false,
        0,
    );
    svc.publish(&mut b, "devices/dev7/cmd", b"c", QoS::AtMostOnce, false, 0);
    svc.publish(
        &mut b,
        "devices/dev7/cmdx",
        b"no",
        QoS::AtMostOnce,
        false,
        0,
    );
    assert_eq!(
        devs[7].recv(&mut b),
        vec![
            publish("devices/dev7/cmd/reboot", b"r", 1, Some(1), false),
            publish("devices/dev7/cmd", b"c", 0, None, false),
        ]
    );
    assert_eq!(devs[8].recv(&mut b), vec![]);
    // A scoped filter and an ordinary one matching the same message: one
    // delivery at the higher QoS.
    assert_eq!(
        devs[8].subscribe(&mut b, 2, &[("devices/dev8/+/x", QoS::AtMostOnce)], 0),
        vec![Got::SubAck(2, vec![0])]
    );
    svc.publish(
        &mut b,
        "devices/dev8/cmd/x",
        b"once",
        QoS::AtLeastOnce,
        false,
        0,
    );
    assert_eq!(
        devs[8].recv(&mut b),
        vec![publish("devices/dev8/cmd/x", b"once", 1, Some(1), false)]
    );
    // Retained messages reach a new scoped subscription (the device also
    // gets the live copy through its `cmd/#`).
    svc.publish(
        &mut b,
        "devices/dev9/cmd/cfg",
        b"v1",
        QoS::AtMostOnce,
        true,
        0,
    );
    assert_eq!(
        devs[9].recv(&mut b),
        vec![publish("devices/dev9/cmd/cfg", b"v1", 0, None, false)]
    );
    assert_eq!(
        devs[9].subscribe(&mut b, 3, &[("devices/dev9/cmd/cfg", QoS::AtMostOnce)], 0),
        vec![
            Got::SubAck(3, vec![0]),
            publish("devices/dev9/cmd/cfg", b"v1", 0, None, true)
        ]
    );
    // Unsubscribe by the full filter.
    devs[7].send(
        &mut b,
        &Packet::Unsubscribe(Unsubscribe {
            packet_id: 4,
            topics: UnsubscribeTopics::List(&["devices/dev7/cmd/#"]),
        }),
        0,
    );
    assert_eq!(devs[7].recv(&mut b), vec![Got::UnsubAck(4)]);
    svc.publish(
        &mut b,
        "devices/dev7/cmd/reboot",
        b"r",
        QoS::AtMostOnce,
        false,
        0,
    );
    assert_eq!(devs[7].recv(&mut b), vec![]);
    // Restored from the store as scoped again.
    let mut r = Broker::new(Config {
        max_connections: 300,
        persist: true,
        acl,
        ..cfg()
    });
    let nodes = r.stats().topic_nodes;
    assert!(r.restore_session("dev3", [("devices/dev3/cmd/#", QoS::AtLeastOnce)], []));
    assert_eq!(r.stats().topic_nodes, nodes);
    let (mut s2, _) = Client::connect(&mut r, "backend", true, None, 0);
    let (mut d3, _) = Client::connect(&mut r, "dev3", false, None, 0);
    s2.publish(
        &mut r,
        "devices/dev3/cmd/a",
        b"a",
        QoS::AtMostOnce,
        false,
        0,
    );
    assert_eq!(
        d3.recv(&mut r),
        vec![publish("devices/dev3/cmd/a", b"a", 0, None, false)]
    );
}

/// Per-connection budget (M15, ADR-034).
#[test]
fn hot_state_stays_small() {
    assert!(
        core::mem::size_of::<Conn>() <= 48,
        "{}",
        core::mem::size_of::<Conn>()
    );
    assert!(
        core::mem::size_of::<Session>() <= 64,
        "{}",
        core::mem::size_of::<Session>()
    );
    assert_eq!(core::mem::size_of::<Sub>(), 8);
}

/// Connects `id` over a "TLS" connection whose certificate came from a
/// bootstrap anchor (`bootstrap`) or an operational one.
fn tls_connect(b: &mut Broker, id: &str, bootstrap: bool, clean: bool, now: u64) -> (Client, Got) {
    let c = Client {
        c: b.open(now).unwrap(),
        rx: Vec::new(),
        pending: Vec::new(),
    };
    b.set_identity(c.c, id, bootstrap);
    c.send(
        b,
        &Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: clean,
            keep_alive: 10,
            client_id: id,
            will: None,
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

/// H1: publishes to the reserved namespace are never routed. Only a
/// control identity's publish to the exact control topic reaches the
/// control handler.
#[test]
fn reserved_namespace_reaches_only_the_control_handler() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    // Even a wildcard over everything does not see `$` topics.
    svc.subscribe(&mut b, 1, &[("#", QoS::AtLeastOnce)], 0);
    let (mut op, ack) = Client::connect(&mut b, "operator", true, None, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
    let (mut dev, _) = Client::connect(&mut b, "device-001", true, None, 0);

    let dropped = [
        dev.publish(&mut b, CONTROL_TOPIC, b"x", QoS::AtLeastOnce, true, 1),
        svc.publish(&mut b, CONTROL_TOPIC, b"x", QoS::AtLeastOnce, true, 1),
        op.publish(&mut b, "$urmqtt/other", b"x", QoS::AtLeastOnce, true, 1),
        op.publish(&mut b, "$urmqtt", b"x", QoS::AtLeastOnce, true, 1),
    ];
    for got in dropped {
        assert_eq!(got, vec![Got::PubAck(7)], "acknowledged and dropped");
    }
    assert_eq!(b.stats().dropped_control, 4);
    assert_eq!(b.drain_control().count(), 0);

    op.publish(&mut b, CONTROL_TOPIC, b"signed", QoS::AtLeastOnce, false, 2);
    let msgs: Vec<ControlMsg> = b.drain_control().collect();
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        (&*msgs[0].from, &*msgs[0].payload),
        ("operator", &b"signed"[..])
    );
    assert_eq!(b.stats().control_received, 1);
    // Nothing was routed or retained anywhere.
    assert!(svc.recv(&mut b).is_empty());
    assert_eq!(b.stats().retained, 0);

    // Nobody may subscribe to the namespace.
    let refused = vec![Got::SubAck(3, vec![SUBACK_FAILURE])];
    assert_eq!(
        svc.subscribe(&mut b, 3, &[("$urmqtt/#", QoS::AtMostOnce)], 3),
        refused
    );
    assert_eq!(
        op.subscribe(&mut b, 3, &[(CONTROL_TOPIC, QoS::AtMostOnce)], 3),
        refused
    );
    assert_eq!(
        dev.subscribe(&mut b, 3, &[("$urmqtt/+", QoS::AtMostOnce)], 3),
        refused
    );
}

/// H1: a bootstrap certificate named like a control service gets no
/// control rights; the backlog is bounded.
#[test]
fn control_rights_need_an_operational_certificate() {
    let mut b = Broker::new(cfg());
    let (mut fake, ack) = tls_connect(&mut b, "operator", true, true, 0);
    assert_eq!(ack, Got::ConnAck(false, 0));
    fake.publish(&mut b, CONTROL_TOPIC, b"x", QoS::AtLeastOnce, false, 1);
    assert_eq!(b.drain_control().count(), 0);
    assert_eq!(b.stats().dropped_control, 1);

    let (mut op, _) = tls_connect(&mut b, "operator", false, true, 2);
    for _ in 0..100 {
        op.publish(&mut b, CONTROL_TOPIC, b"x", QoS::AtMostOnce, false, 3);
    }
    assert_eq!(b.drain_control().count(), 64);
    assert_eq!(b.stats().dropped_control, 1 + 36);
}

/// H1: a bootstrap identity lives in its own session namespace: it can
/// neither take over nor read the operational session of the same id, must
/// use a clean session, and only reaches `provision/{id}/#`.
#[test]
fn bootstrap_sessions_are_isolated_and_provisioning_only() {
    let mut b = Broker::new(cfg());
    // The operational device-001 has a persistent session with a queued
    // command.
    let (mut d, _) = tls_connect(&mut b, "device-001", false, false, 0);
    d.subscribe(
        &mut b,
        1,
        &[("devices/device-001/cmd/#", QoS::AtLeastOnce)],
        0,
    );
    d.kill(&mut b, 1);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 1);
    svc.publish(
        &mut b,
        "devices/device-001/cmd/x",
        b"secret",
        QoS::AtLeastOnce,
        false,
        2,
    );

    // A bootstrap identity with the same id: a persistent session is
    // refused, a clean one gets no session_present and nothing queued.
    let (_, ack) = tls_connect(&mut b, "device-001", true, false, 3);
    assert_eq!(
        ack,
        Got::ConnAck(false, ConnectReturnCode::NotAuthorized as u8)
    );
    let (mut boot, ack) = tls_connect(&mut b, "device-001", true, true, 4);
    assert_eq!(ack, Got::ConnAck(false, 0));
    assert!(boot.recv(&mut b).is_empty(), "queued command leaked");
    assert_eq!(
        boot.subscribe(
            &mut b,
            2,
            &[("devices/device-001/cmd/#", QoS::AtLeastOnce)],
            4
        ),
        vec![Got::SubAck(2, vec![SUBACK_FAILURE])]
    );
    assert_eq!(
        boot.subscribe(
            &mut b,
            3,
            &[("provision/device-001/#", QoS::AtLeastOnce)],
            4
        ),
        vec![Got::SubAck(3, vec![1])]
    );
    boot.publish(
        &mut b,
        "devices/device-001/telemetry/t",
        b"x",
        QoS::AtMostOnce,
        false,
        5,
    );
    assert_eq!(b.stats().dropped_acl, 1);

    // The operational device comes back and still has its session and
    // command: the bootstrap connection did not touch them.
    let (mut d, ack) = tls_connect(&mut b, "device-001", false, false, 6);
    assert_eq!(ack, Got::ConnAck(true, 0));
    let got = d.recv(&mut b);
    assert!(
        got.iter()
            .any(|g| matches!(g, Got::Publish { payload, .. } if payload == b"secret")),
        "{got:?}"
    );
    // Both are online at once; neither was taken over.
    assert!(b.close_requested(boot.c).is_none());
}

/// H1: an identity leaving the allowlist loses its live connection.
#[test]
fn disconnect_identity_closes_operational_and_bootstrap_sessions() {
    let mut b = Broker::new(cfg());
    let (d, _) = tls_connect(&mut b, "device-002", false, true, 0);
    let (bt, _) = tls_connect(&mut b, "device-002", true, true, 0);
    let (other, _) = tls_connect(&mut b, "device-003", false, true, 0);
    assert!(b.disconnect_identity("device-002", CloseReason::Disallowed));
    assert_eq!(b.close_requested(d.c), Some(CloseReason::Disallowed));
    assert_eq!(b.close_requested(bt.c), Some(CloseReason::Disallowed));
    assert_eq!(b.close_requested(other.c), None);
    assert!(!b.disconnect_identity("device-009", CloseReason::Disallowed));
}

/// H1: an allowlist change closes exactly the sessions it no longer admits.
#[test]
fn disconnect_unless_applies_a_predicate_to_online_sessions() {
    let mut b = Broker::new(cfg());
    let (keep, _) = tls_connect(&mut b, "device-001", false, true, 0);
    let (gone, _) = tls_connect(&mut b, "device-002", false, true, 0);
    let (svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let (boot, _) = tls_connect(&mut b, "device-002", true, true, 0);
    let n = b.disconnect_unless(
        |id, role| role != Role::Device || id == "device-001",
        CloseReason::Disallowed,
    );
    assert_eq!(n, 1);
    assert_eq!(b.close_requested(gone.c), Some(CloseReason::Disallowed));
    for c in [&keep, &svc, &boot] {
        assert_eq!(b.close_requested(c.c), None);
    }
}

/// H3 (H0-W1): an identity holds at most `max_retained_per_device`
/// retained messages. Replacing or clearing its own always works; a
/// refused one is still delivered, just not retained.
#[test]
fn retained_per_device_limit_at_the_bound() {
    let mut b = Broker::new(cfg()); // 4 per device
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    for i in 0..4 {
        d1.publish(
            &mut b,
            &format!("devices/d1/r{i}"),
            b"x",
            QoS::AtMostOnce,
            true,
            0,
        );
    }
    assert_eq!(b.stats().retained, 4);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/d1/#", QoS::AtMostOnce)], 0);
    svc.recv(&mut b);
    // The fifth is refused for retention but delivered live.
    d1.publish(&mut b, "devices/d1/r4", b"x", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 4);
    assert_eq!(b.stats().retained_refused_device, 1);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/r4", b"x", 0, None, false)]
    );
    // Replacing one of its own is not a new one.
    d1.publish(&mut b, "devices/d1/r0", b"y", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained_refused_device, 1);
    // Clearing frees a slot.
    d1.publish(&mut b, "devices/d1/r1", b"", QoS::AtMostOnce, true, 0);
    d1.publish(&mut b, "devices/d1/r4", b"x", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 4);
    assert_eq!(b.stats().retained_refused_device, 1);
    // Another identity has its own allowance; a service overwriting a
    // device's retained topic takes it over.
    let (mut d2, _) = Client::connect(&mut b, "d2", true, None, 0);
    d2.publish(&mut b, "devices/d2/r", b"z", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 5);
    svc.publish(&mut b, "devices/d1/cmd/r", b"c", QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained, 6);
}

/// The shard's byte budget bounds retained memory whatever the number of
/// identities: many devices cannot exhaust the heap together.
#[test]
fn retained_byte_budget_at_the_bound() {
    let mut b = Broker::new(Config {
        max_retained_per_device: 1000,
        max_retained_bytes: 4 * crate::topics::retained_cost("devices/d1/rX", 100),
        ..cfg()
    });
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    for i in 0..4 {
        d1.publish(
            &mut b,
            &format!("devices/d1/r{i}"),
            &[1; 100],
            QoS::AtMostOnce,
            true,
            0,
        );
    }
    assert_eq!(b.stats().retained, 4);
    d1.publish(&mut b, "devices/d1/r9", &[1; 100], QoS::AtMostOnce, true, 0);
    assert_eq!(
        (b.stats().retained, b.stats().retained_refused_bytes),
        (4, 1)
    );
    // A replacement that grows past the budget is refused and the old
    // message stays; one that shrinks is fine.
    d1.publish(&mut b, "devices/d1/r0", &[1; 101], QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained_refused_bytes, 2);
    d1.publish(&mut b, "devices/d1/r0", &[1; 10], QoS::AtMostOnce, true, 0);
    assert_eq!(b.stats().retained_refused_bytes, 2);
    assert!(b.stats().retained_bytes <= 4 * crate::topics::retained_cost("devices/d1/rX", 100));
}

/// Clearing a topic that holds nothing creates no trie nodes, and clearing
/// what was retained gives its nodes back (H0-W1: "even clearing creates
/// its trie nodes first").
#[test]
fn clearing_retained_messages_leaves_no_nodes_behind() {
    let mut b = Broker::new(Config {
        max_retained_per_device: 1000,
        max_retained_bytes: 1 << 20,
        rate_tokens: 1_000_000,
        ..cfg()
    });
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    let base = b.stats().topic_nodes;
    for i in 0..500 {
        d1.publish(
            &mut b,
            &format!("devices/d1/a/{i}/b"),
            b"",
            QoS::AtMostOnce,
            true,
            0,
        );
    }
    assert_eq!(
        b.stats().topic_nodes,
        base,
        "clearing nothing created nodes"
    );
    for round in 0..3 {
        for i in 0..200 {
            d1.publish(
                &mut b,
                &format!("devices/d1/x{round}/{i}"),
                b"v",
                QoS::AtMostOnce,
                true,
                0,
            );
        }
        assert!(b.stats().topic_nodes > base);
        for i in 0..200 {
            d1.publish(
                &mut b,
                &format!("devices/d1/x{round}/{i}"),
                b"",
                QoS::AtMostOnce,
                true,
                0,
            );
        }
        assert_eq!(b.stats().topic_nodes, base, "round {round}");
        assert_eq!((b.stats().retained, b.stats().retained_bytes), (0, 0));
    }
}

/// Subscribing to ever new filters and unsubscribing again does not grow
/// the trie either.
#[test]
fn unsubscribed_filters_leave_no_nodes_behind() {
    let mut b = Broker::new(cfg());
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let base = b.stats().topic_nodes;
    for i in 0..300u16 {
        let f = format!("fleet/{i}/x/#");
        svc.subscribe(&mut b, i + 1, &[(&f, QoS::AtMostOnce)], 0);
        svc.send(
            &mut b,
            &Packet::Unsubscribe(urmqtt_mqtt::Unsubscribe {
                packet_id: i + 1,
                topics: urmqtt_mqtt::UnsubscribeTopics::List(&[&f]),
            }),
            0,
        );
        svc.recv(&mut b);
    }
    assert_eq!(b.stats().topic_nodes, base);
}

/// Replicas: a shard retains a remote message only if the origin did, so
/// limits refused at the origin are not undone elsewhere.
#[test]
fn refused_retained_messages_are_not_replicated() {
    let shard = || {
        Broker::new(Config {
            fanout: true,
            ..cfg()
        })
    };
    let (mut a, mut b) = (shard(), shard());
    let (mut d1, _) = Client::connect(&mut a, "d1", true, None, 0);
    for i in 0..5 {
        d1.publish(
            &mut a,
            &format!("devices/d1/r{i}"),
            b"x",
            QoS::AtMostOnce,
            true,
            0,
        );
    }
    for (m, q, r) in a.drain_routes().collect::<Vec<_>>() {
        b.route_remote(&m, q, r);
    }
    assert_eq!((a.stats().retained, b.stats().retained), (4, 4));
}
