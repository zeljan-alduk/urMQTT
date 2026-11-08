//! QoS 2, exactly once (MQTT 3.1.1 4.3.3, ADR-271): every transition of
//! the inbound (method B) and outbound state machines, duplicates,
//! acknowledgements out of order, packet id reuse, reconnects, takeovers,
//! clean sessions, wills, retained replay, the ACL and the rate limit, the
//! bounds, and the persisted snapshot across a restart.

use super::*;

/// A QoS 2 PUBLISH with a chosen packet id and DUP flag.
fn pub2(
    c: &mut Client,
    b: &mut Broker,
    topic: &str,
    payload: &[u8],
    pid: u16,
    dup: bool,
) -> Vec<Got> {
    c.send(
        b,
        &Packet::Publish(Publish {
            dup,
            qos: QoS::ExactlyOnce,
            retain: false,
            topic,
            packet_id: Some(pid),
            payload,
        }),
        0,
    );
    c.recv(b)
}

fn ack(c: &mut Client, b: &mut Broker, p: &Packet<'_>) -> Vec<Got> {
    c.send(b, p, 0);
    c.recv(b)
}

fn publish2(topic: &str, payload: &[u8], pid: u16, dup: bool) -> Got {
    Got::Publish {
        topic: topic.into(),
        payload: payload.into(),
        qos: 2,
        pid: Some(pid),
        retain: false,
        dup,
    }
}

/// The backend, subscribed to every device topic at `qos`.
fn backend(b: &mut Broker, qos: QoS) -> Client {
    let (mut svc, _) = Client::connect(b, "backend", true, None, 0);
    assert_eq!(
        svc.subscribe(b, 1, &[("devices/#", qos)], 0),
        vec![Got::SubAck(1, vec![qos as u8])]
    );
    svc
}

#[test]
fn inbound_publish_is_routed_once_and_its_id_held_until_pubrel() {
    // A window wide enough that the subscriber need not acknowledge.
    let mut b = Broker::new(Config {
        max_inflight: 8,
        ..cfg()
    });
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    // PUBLISH -> PUBREC; the message is routed on arrival (method B).
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"1", 7, false),
        vec![Got::PubRec(7)]
    );
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"1", 1, false)]
    );
    assert_eq!(b.stats().qos2_received, 1);
    // The same id again, with DUP and without: PUBREC again, never routed.
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"1", 7, true),
        vec![Got::PubRec(7)]
    );
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"other", 7, false),
        vec![Got::PubRec(7)]
    );
    assert!(svc.recv(&mut b).is_empty(), "a duplicate is never routed");
    assert_eq!(b.stats().qos2_duplicates, 2);
    assert_eq!(b.stats().published, 1);
    // A second flow beside it, with another id, is independent.
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"2", 8, false),
        vec![Got::PubRec(8)]
    );
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"2", 2, false)]
    );
    // PUBREL -> PUBCOMP, in any order; the id is free afterwards.
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(8)),
        vec![Got::PubComp(8)]
    );
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(7)),
        vec![Got::PubComp(7)]
    );
    // A PUBREL sent again (our PUBCOMP was lost) is answered again.
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(7)),
        vec![Got::PubComp(7)]
    );
    // An unknown id too (4.3.3: PUBREL is always answered).
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(99)),
        vec![Got::PubComp(99)]
    );
    // After PUBREL the id starts a new publication.
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"3", 7, true),
        vec![Got::PubRec(7)]
    );
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"3", 3, false)]
    );
    assert_eq!(b.stats().qos2_received, 3);
    // Nothing is held once every flow is complete.
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(7)),
        vec![Got::PubComp(7)]
    );
    let sid = b.conns.get(d1.c).and_then(|k| k.session).unwrap();
    assert!(b.sessions.get(sid).unwrap().pending.is_none());
}

#[test]
fn qos1_and_qos2_ids_of_a_client_are_independent() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"2", 7, false),
        vec![Got::PubRec(7)]
    );
    // A QoS 1 publish that reuses the id is a QoS 1 publish: routed, PUBACK.
    assert_eq!(
        d1.publish(&mut b, "devices/d1/t", b"1", QoS::AtLeastOnce, false, 0),
        vec![Got::PubAck(7)]
    );
    assert_eq!(svc.recv(&mut b).len(), 2);
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(7)),
        vec![Got::PubComp(7)]
    );
}

#[test]
fn outbound_delivery_takes_four_packets_and_ignores_acks_out_of_order() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    pub2(&mut d1, &mut b, "devices/d1/t", b"x", 3, false);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"x", 1, false)]
    );
    // A PUBACK or a PUBCOMP before the PUBREC changes nothing.
    assert!(ack(&mut svc, &mut b, &Packet::PubAck(1)).is_empty());
    assert!(ack(&mut svc, &mut b, &Packet::PubComp(1)).is_empty());
    assert_eq!(b.stats().qos2_completed, 0);
    // PUBREC -> PUBREL, the message is released.
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    let sid = b.conns.get(svc.c).and_then(|k| k.session).unwrap();
    let f = b.sessions.get(sid).unwrap().inflight().to_vec();
    assert_eq!(
        (f.len(), f[0].flow, f[0].msg.is_none()),
        (1, Flow::Pubcomp, true)
    );
    // A PUBREC sent again gets the PUBREL again; a PUBACK still nothing.
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    assert!(ack(&mut svc, &mut b, &Packet::PubAck(1)).is_empty());
    // PUBCOMP completes; a second PUBCOMP is ignored.
    assert!(ack(&mut svc, &mut b, &Packet::PubComp(1)).is_empty());
    assert!(ack(&mut svc, &mut b, &Packet::PubComp(1)).is_empty());
    assert_eq!(b.stats().qos2_completed, 1);
    assert!(b.sessions.get(sid).unwrap().pending.is_none());
    // A PUBREC for an id not in flight is answered with PUBREL (the client
    // may hold state we lost), and starts nothing.
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubRec(42)),
        vec![Got::PubRel(42)]
    );
    assert!(b.sessions.get(sid).unwrap().pending.is_none());
}

#[test]
fn a_qos1_flight_ignores_the_qos2_acknowledgements() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::AtLeastOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.publish(&mut b, "devices/d1/t", b"x", QoS::AtLeastOnce, false, 0);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish("devices/d1/t", b"x", 1, Some(1), false)]
    );
    assert!(ack(&mut svc, &mut b, &Packet::PubRec(1)).is_empty());
    assert!(ack(&mut svc, &mut b, &Packet::PubComp(1)).is_empty());
    let sid = b.conns.get(svc.c).and_then(|k| k.session).unwrap();
    assert_eq!(b.sessions.get(sid).unwrap().inflight().len(), 1);
    assert!(ack(&mut svc, &mut b, &Packet::PubAck(1)).is_empty());
    assert!(b.sessions.get(sid).unwrap().pending.is_none());
}

#[test]
fn the_delivered_qos_is_the_lower_of_publish_and_subscription() {
    for (pubq, subq, want) in [
        (QoS::ExactlyOnce, QoS::ExactlyOnce, 2),
        (QoS::ExactlyOnce, QoS::AtLeastOnce, 1),
        (QoS::ExactlyOnce, QoS::AtMostOnce, 0),
        (QoS::AtLeastOnce, QoS::ExactlyOnce, 1),
        (QoS::AtMostOnce, QoS::ExactlyOnce, 0),
    ] {
        let mut b = Broker::new(cfg());
        let mut svc = backend(&mut b, subq);
        let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
        if pubq == QoS::ExactlyOnce {
            pub2(&mut d1, &mut b, "devices/d1/t", b"x", 5, false);
        } else {
            d1.publish(&mut b, "devices/d1/t", b"x", pubq, false, 0);
        }
        let got = svc.recv(&mut b);
        assert!(
            matches!(got.as_slice(), [Got::Publish { qos, .. }] if *qos == want),
            "{pubq:?} to a {subq:?} subscription: {got:?}"
        );
    }
}

#[test]
fn the_window_counts_qos2_flights_until_pubcomp() {
    let mut b = Broker::new(cfg()); // max_inflight 2, max_queued 3
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    for (i, pid) in [10u16, 11, 12].into_iter().enumerate() {
        pub2(&mut d1, &mut b, "devices/d1/t", &[i as u8], pid, false);
    }
    assert_eq!(
        svc.recv(&mut b),
        vec![
            publish2("devices/d1/t", &[0], 1, false),
            publish2("devices/d1/t", &[1], 2, false)
        ],
        "a window of 2, the third queued"
    );
    // PUBREC does not free the slot: the flow is not complete.
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    // PUBCOMP does, and the queued message goes out with a new id.
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubComp(1)),
        vec![publish2("devices/d1/t", &[2], 3, false)]
    );
}

#[test]
fn an_id_awaiting_pubcomp_is_not_reused_when_the_ids_wrap() {
    let mut b = Broker::new(Config {
        rate_tokens: u32::MAX,
        ..cfg()
    });
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    // Id 1 stays released and uncompleted.
    pub2(&mut d1, &mut b, "devices/d1/t", b"x", 1, false);
    ack(&mut d1, &mut b, &Packet::PubRel(1));
    svc.recv(&mut b);
    assert_eq!(
        ack(&mut svc, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    // 65 534 more deliveries take the ids 2 to 65 535.
    for n in 2..=u16::MAX {
        pub2(&mut d1, &mut b, "devices/d1/t", b"y", 2, false);
        ack(&mut d1, &mut b, &Packet::PubRel(2));
        let got = svc.recv(&mut b);
        assert!(
            matches!(got.as_slice(), [Got::Publish { pid: Some(p), .. }] if *p == n),
            "{n}: {got:?}"
        );
        svc.send(&mut b, &Packet::PubRec(n), 0);
        svc.send(&mut b, &Packet::PubComp(n), 0);
        svc.recv(&mut b);
    }
    // The ids wrap; 1 is still in flight and skipped.
    pub2(&mut d1, &mut b, "devices/d1/t", b"z", 2, false);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"z", 2, false)]
    );
}

#[test]
fn a_persistent_session_resumes_both_directions_after_a_reconnect() {
    let mut b = Broker::new(cfg());
    let (mut d2, _) = Client::connect(&mut b, "d2", false, None, 0);
    d2.subscribe(&mut b, 1, &[("devices/d2/cmd/#", QoS::ExactlyOnce)], 0);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    let cmd = |svc: &mut Client, b: &mut Broker, p: &[u8], pid: u16| {
        assert_eq!(
            pub2(svc, b, "devices/d2/cmd/x", p, pid, false),
            vec![Got::PubRec(pid)]
        );
        assert_eq!(ack(svc, b, &Packet::PubRel(pid)), vec![Got::PubComp(pid)]);
    };
    cmd(&mut svc, &mut b, b"a", 1);
    cmd(&mut svc, &mut b, b"b", 2);
    assert_eq!(
        d2.recv(&mut b),
        vec![
            publish2("devices/d2/cmd/x", b"a", 1, false),
            publish2("devices/d2/cmd/x", b"b", 2, false)
        ]
    );
    // The device acknowledges the first with PUBREC only, and publishes a
    // QoS 2 message of its own that it never releases; then it drops.
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    assert_eq!(
        pub2(&mut d2, &mut b, "devices/d2/state", b"s", 9, false),
        vec![Got::PubRec(9)]
    );
    d2.kill(&mut b, 0);
    // Back: the PUBREL of 1 and the PUBLISH of 2 again, in the order first
    // sent (4.4), with their ids; 2 with DUP.
    let (mut d2, ack0) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack0, Got::ConnAck(true, 0));
    assert_eq!(
        d2.recv(&mut b),
        vec![Got::PubRel(1), publish2("devices/d2/cmd/x", b"b", 2, true)]
    );
    // Its own id 9 is still held: the PUBLISH again is a duplicate.
    let (mut watcher, _) = Client::connect(&mut b, "backend2", true, None, 0);
    let _ = &mut watcher;
    assert_eq!(
        pub2(&mut d2, &mut b, "devices/d2/state", b"s", 9, true),
        vec![Got::PubRec(9)]
    );
    assert_eq!(b.stats().qos2_duplicates, 1);
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRel(9)),
        vec![Got::PubComp(9)]
    );
    assert!(ack(&mut d2, &mut b, &Packet::PubComp(1)).is_empty());
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRec(2)),
        vec![Got::PubRel(2)]
    );
    assert!(ack(&mut d2, &mut b, &Packet::PubComp(2)).is_empty());
    assert_eq!(b.stats().qos2_completed, 2);
}

#[test]
fn a_takeover_in_the_middle_of_a_flow_keeps_it() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut old, _) = Client::connect(&mut b, "d1", false, None, 0);
    assert_eq!(
        pub2(&mut old, &mut b, "devices/d1/t", b"x", 4, false),
        vec![Got::PubRec(4)]
    );
    assert_eq!(svc.recv(&mut b).len(), 1);
    let (mut new, ack0) = Client::connect(&mut b, "d1", false, None, 0);
    assert_eq!(ack0, Got::ConnAck(true, 0));
    assert_eq!(b.close_requested(old.c), Some(CloseReason::TakenOver));
    old.kill(&mut b, 0);
    assert_eq!(
        pub2(&mut new, &mut b, "devices/d1/t", b"x", 4, true),
        vec![Got::PubRec(4)]
    );
    assert!(
        svc.recv(&mut b).is_empty(),
        "delivered once across the takeover"
    );
    assert_eq!(
        ack(&mut new, &mut b, &Packet::PubRel(4)),
        vec![Got::PubComp(4)]
    );
}

#[test]
fn a_clean_session_discards_the_flows() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", false, None, 0);
    pub2(&mut d1, &mut b, "devices/d1/t", b"x", 4, false);
    assert_eq!(svc.recv(&mut b).len(), 1);
    d1.kill(&mut b, 0);
    // A clean session starts without state (3.1.2.4): id 4 is a new message.
    let (mut d1, ack0) = Client::connect(&mut b, "d1", true, None, 0);
    assert_eq!(ack0, Got::ConnAck(false, 0));
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"x", 4, true),
        vec![Got::PubRec(4)]
    );
    assert_eq!(svc.recv(&mut b).len(), 1);
    // And a clean session's state ends with its connection.
    d1.kill(&mut b, 0);
    assert!(b.find_session("d1").is_none());
    // The subscriber's side: a clean session with a delivery in flight.
    let sid = b.find_session("backend").unwrap();
    assert_eq!(b.sessions.get(sid).unwrap().inflight().len(), 2);
    svc.kill(&mut b, 0);
    assert!(b.find_session("backend").is_none());
}

#[test]
fn a_will_and_a_retained_message_keep_qos_2() {
    let mut b = Broker::new(cfg());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let will = MqttWill {
        topic: "devices/d1/status",
        payload: b"gone",
        qos: QoS::ExactlyOnce,
        retain: true,
    };
    let (d1, ack0) = Client::connect(&mut b, "d1", true, Some(will), 0);
    assert_eq!(ack0, Got::ConnAck(false, 0));
    d1.kill(&mut b, 0);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/status", b"gone", 1, false)]
    );
    // Retained at QoS 2: replayed at QoS 2 to a QoS 2 subscription, at the
    // subscription's QoS below it.
    let (mut s2, _) = Client::connect(&mut b, "backend2", true, None, 0);
    let _ = &mut s2;
    let (mut d2, _) = Client::connect(&mut b, "d2", true, None, 0);
    d2.send(
        &mut b,
        &Packet::Publish(Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: true,
            topic: "devices/d2/fw",
            packet_id: Some(1),
            payload: b"2.0",
        }),
        0,
    );
    assert_eq!(d2.recv(&mut b), vec![Got::PubRec(1)]);
    let (mut late, _) = Client::connect(&mut b, "backend", true, None, 0);
    let got = late.subscribe(
        &mut b,
        2,
        &[
            ("devices/+/fw", QoS::ExactlyOnce),
            ("devices/+/status", QoS::AtLeastOnce),
        ],
        0,
    );
    assert_eq!(
        got,
        vec![
            Got::SubAck(2, vec![2, 1]),
            Got::Publish {
                topic: "devices/d2/fw".into(),
                payload: b"2.0".to_vec(),
                qos: 2,
                pid: Some(1),
                retain: true,
                dup: false
            },
            publish("devices/d1/status", b"gone", 1, Some(2), true),
        ]
    );
}

#[test]
fn a_refused_publish_completes_its_handshake_once() {
    let mut c = cfg();
    c.rate_tokens = 1;
    let mut b = Broker::new(c);
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    // Outside the ACL: PUBREC, dropped, counted once.
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d2/t", b"x", 1, false),
        vec![Got::PubRec(1)]
    );
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d2/t", b"x", 1, true),
        vec![Got::PubRec(1)]
    );
    assert_eq!(b.stats().dropped_acl, 1);
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(1)),
        vec![Got::PubComp(1)]
    );
    // The one token: accepted. The next: over the rate, dropped; its
    // duplicate after the bucket refilled is still a duplicate.
    pub2(&mut d1, &mut b, "devices/d1/t", b"a", 2, false);
    pub2(&mut d1, &mut b, "devices/d1/t", b"b", 3, false);
    assert_eq!(b.stats().dropped_rate, 1);
    d1.send(
        &mut b,
        &Packet::Publish(Publish {
            dup: true,
            qos: QoS::ExactlyOnce,
            retain: false,
            topic: "devices/d1/t",
            packet_id: Some(3),
            payload: b"b",
        }),
        5_000,
    );
    assert_eq!(d1.recv(&mut b), vec![Got::PubRec(3)]);
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"a", 1, false)]
    );
    assert_eq!((b.stats().dropped_rate, b.stats().published), (1, 1));
}

#[test]
fn a_duplicate_control_or_sys_request_is_handled_once() {
    let mut b = Broker::new(cfg());
    let (mut op, _) = Client::connect(&mut b, "operator", true, None, 0);
    pub2(&mut op, &mut b, CONTROL_TOPIC, b"signed", 1, false);
    pub2(&mut op, &mut b, CONTROL_TOPIC, b"signed", 1, true);
    assert_eq!(b.drain_control().count(), 1);
    assert_eq!(b.stats().control_received, 1);
}

#[test]
fn too_many_ids_awaiting_pubrel_close_the_connection() {
    let mut b = Broker::new(cfg()); // max_inflight 2: the floor applies
    assert_eq!(b.qos2_id_limit(), MIN_QOS2_IDS);
    let (mut d1, _) = Client::connect(&mut b, "d1", false, None, 0);
    for pid in 1..=MIN_QOS2_IDS as u16 {
        assert_eq!(
            pub2(&mut d1, &mut b, "devices/d1/t", b"x", pid, false),
            vec![Got::PubRec(pid)]
        );
    }
    // A duplicate is still fine; a new id is one too many.
    pub2(&mut d1, &mut b, "devices/d1/t", b"x", 1, true);
    assert!(b.close_requested(d1.c).is_none());
    let got = pub2(&mut d1, &mut b, "devices/d1/t", b"x", 1000, false);
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(b.close_requested(d1.c), Some(CloseReason::ProtocolError));
    assert_eq!(b.stats().qos2_inbound_full, 1);
    // The session keeps its ids; releasing one makes room after reconnect.
    d1.kill(&mut b, 0);
    let (mut d1, _) = Client::connect(&mut b, "d1", false, None, 0);
    assert_eq!(
        ack(&mut d1, &mut b, &Packet::PubRel(1)),
        vec![Got::PubComp(1)]
    );
    assert_eq!(
        pub2(&mut d1, &mut b, "devices/d1/t", b"x", 1000, false),
        vec![Got::PubRec(1000)]
    );
    // A larger window raises the bound.
    let b = Broker::new(Config {
        max_inflight: 500,
        ..cfg()
    });
    assert_eq!(b.qos2_id_limit(), 500);
}

#[test]
fn qos2_crosses_shards_like_qos1() {
    let shard = || {
        Broker::new(Config {
            fanout: true,
            ..cfg()
        })
    };
    let (mut a, mut b) = (shard(), shard());
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    let (mut d1, _) = Client::connect(&mut a, "d1", true, None, 0);
    pub2(&mut d1, &mut a, "devices/d1/t", b"x", 6, false);
    pub2(&mut d1, &mut a, "devices/d1/t", b"x", 6, true);
    // The home shard routes once; the other delivers with its own ids.
    let routes: Vec<(Msg, QoS, bool, Option<ConnId>)> = a.drain_routes().collect();
    assert_eq!(routes.len(), 1);
    for (m, q, r, _) in routes {
        assert_eq!(q, QoS::ExactlyOnce);
        b.route_remote(&m, q, r);
    }
    assert_eq!(
        svc.recv(&mut b),
        vec![publish2("devices/d1/t", b"x", 1, false)]
    );
}

#[test]
fn an_offline_session_queues_qos2_and_receives_it_at_qos2() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (mut d2, _) = Client::connect(&mut b, "d2", false, None, 0);
    d2.subscribe(&mut b, 1, &[("devices/d2/cmd/#", QoS::ExactlyOnce)], 0);
    d2.disconnect(&mut b, 0);
    b.drain_persist().for_each(drop);
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    pub2(&mut svc, &mut b, "devices/d2/cmd/x", b"q", 1, false);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(
            ops.as_slice(),
            [PersistOp::QueuePush {
                qos: QoS::ExactlyOnce,
                pid: None,
                ..
            }]
        ),
        "{ops:?}"
    );
    let (mut d2, _) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(
        d2.recv(&mut b),
        vec![publish2("devices/d2/cmd/x", b"q", 1, false)]
    );
}

/// The snapshot at disconnect holds every unfinished flow; a restart
/// restored from it resumes each one where it stood.
#[test]
fn the_flows_survive_a_restart_through_the_store() {
    let mut m = Model::default();
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (mut d2, _) = Client::connect(&mut b, "d2", false, None, 0);
    d2.subscribe(
        &mut b,
        1,
        &[
            ("devices/d2/cmd/q2/#", QoS::ExactlyOnce),
            ("devices/d2/cmd/q1/#", QoS::AtLeastOnce),
        ],
        0,
    );
    let (mut svc, _) = Client::connect(&mut b, "backend", true, None, 0);
    for (topic, payload, pid) in [
        ("devices/d2/cmd/q2/a", b"a", 1u16),
        ("devices/d2/cmd/q2/b", b"b", 2),
        ("devices/d2/cmd/q1/c", b"c", 3),
        ("devices/d2/cmd/q2/d", b"d", 4),
    ] {
        pub2(&mut svc, &mut b, topic, payload, pid, false);
        ack(&mut svc, &mut b, &Packet::PubRel(pid));
    }
    // Window 2: a and b in flight, c (QoS 1) and d (QoS 2) queued.
    assert_eq!(d2.recv(&mut b).len(), 2);
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRec(1)),
        vec![Got::PubRel(1)]
    );
    assert_eq!(
        pub2(&mut d2, &mut b, "devices/d2/state", b"s", 77, false),
        vec![Got::PubRec(77)]
    );
    d2.kill(&mut b, 0);
    m.apply(&mut b);
    let s = &m.sessions["d2"];
    assert_eq!(
        s.queue
            .iter()
            .map(|(t, _, q, p)| (t.as_str(), *q, *p))
            .collect::<Vec<_>>(),
        [
            ("devices/d2/cmd/q2/b", QoS::ExactlyOnce, Some(2)),
            ("devices/d2/cmd/q1/c", QoS::AtLeastOnce, None),
            ("devices/d2/cmd/q2/d", QoS::ExactlyOnce, None),
        ]
    );
    assert_eq!(s.ids, [Qos2Id::Released(1), Qos2Id::Received(77)]);

    // Restart from the store.
    let mut b = m.restore();
    assert!(b.drain_persist().next().is_none(), "restore writes nothing");
    let (mut d2, ack0) = Client::connect(&mut b, "d2", false, None, 0);
    assert_eq!(ack0, Got::ConnAck(true, 0));
    assert_eq!(
        d2.recv(&mut b),
        vec![
            Got::PubRel(1),
            publish2("devices/d2/cmd/q2/b", b"b", 2, true)
        ]
    );
    m.apply(&mut b);
    assert_eq!(
        m.sessions["d2"],
        StoredSession {
            subs: m.sessions["d2"].subs.clone(),
            ..StoredSession::default()
        },
        "back in RAM: the stored queue and ids are cleared"
    );
    // Its own id 77 survived: the duplicate is not routed.
    let mut svc = backend(&mut b, QoS::ExactlyOnce);
    assert_eq!(
        pub2(&mut d2, &mut b, "devices/d2/state", b"s", 77, true),
        vec![Got::PubRec(77)]
    );
    assert!(svc.recv(&mut b).is_empty());
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRel(77)),
        vec![Got::PubComp(77)]
    );
    // The flows finish and the queue follows, each at its own QoS, with
    // ids not in flight.
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubComp(1)),
        vec![publish("devices/d2/cmd/q1/c", b"c", 1, Some(1), false)]
    );
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubRec(2)),
        vec![Got::PubRel(2)]
    );
    assert_eq!(
        ack(&mut d2, &mut b, &Packet::PubComp(2)),
        vec![publish2("devices/d2/cmd/q2/d", b"d", 2, false)]
    );
}

#[test]
fn restore_bounds_what_the_store_hands_back() {
    let mut b = Broker::new(cfg()); // max_inflight 2, max_queued 3
    let msg = |pid: Option<u16>| StoredMsg {
        topic: "devices/d1/cmd/x",
        payload: b"p",
        qos: QoS::ExactlyOnce,
        pid,
    };
    let ids = (0..=200u16)
        .map(Qos2Id::Received)
        .chain([Qos2Id::Released(5), Qos2Id::Released(5)]);
    assert!(b.restore_session(
        "d1",
        [("devices/d1/cmd/#", QoS::ExactlyOnce)],
        [
            msg(Some(5)), // the id of a released flow: queued instead
            msg(Some(6)),
            msg(Some(7)), // beyond the window: queued
            msg(None),
            msg(Some(0)), // not an id
            msg(None),    // beyond max_queued
        ],
        ids,
    ));
    let sid = b.find_session("d1").unwrap();
    let s = b.sessions.get(sid).unwrap();
    assert_eq!(
        s.received().len(),
        MIN_QOS2_IDS,
        "id 0 skipped, the rest bounded"
    );
    assert!(!s.received().contains(&0));
    assert_eq!(
        s.inflight()
            .iter()
            .map(|f| (f.pid, f.flow))
            .collect::<Vec<_>>(),
        [(5, Flow::Pubcomp), (6, Flow::Pubrec)]
    );
    assert_eq!(s.queue_len(), 3);
}

/// A retained message replayed for a new subscription keeps RETAIN when it
/// has to wait for the window (3.3.1.3), and when it is sent again after a
/// reconnect. (Before ADR-271 a queued replay lost it, at QoS 1 too.)
#[test]
fn a_retained_replay_that_waits_for_the_window_keeps_retain() {
    let mut b = Broker::new(cfg()); // max_inflight 2
    let (mut d1, _) = Client::connect(&mut b, "d1", true, None, 0);
    d1.send(
        &mut b,
        &Packet::Publish(Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: true,
            topic: "devices/d1/fw",
            packet_id: Some(1),
            payload: b"r",
        }),
        0,
    );
    ack(&mut d1, &mut b, &Packet::PubRel(1));
    let (mut svc, _) = Client::connect(&mut b, "backend", false, None, 0);
    svc.subscribe(&mut b, 1, &[("devices/d1/live", QoS::AtLeastOnce)], 0);
    // Two live messages fill the window.
    for i in 0..2u8 {
        d1.publish(&mut b, "devices/d1/live", &[i], QoS::AtLeastOnce, false, 0);
    }
    assert_eq!(svc.recv(&mut b).len(), 2);
    // The replay waits in the queue.
    assert_eq!(
        svc.subscribe(&mut b, 2, &[("devices/d1/fw", QoS::ExactlyOnce)], 0),
        vec![Got::SubAck(2, vec![2])]
    );
    let replayed = ack(&mut svc, &mut b, &Packet::PubAck(1));
    assert_eq!(
        replayed,
        vec![Got::Publish {
            topic: "devices/d1/fw".into(),
            payload: b"r".to_vec(),
            qos: 2,
            pid: Some(3),
            retain: true,
            dup: false
        }]
    );
    // Sent again after a reconnect: still RETAIN, now with DUP.
    svc.kill(&mut b, 0);
    let (mut svc, _) = Client::connect(&mut b, "backend", false, None, 0);
    let again = svc.recv(&mut b);
    assert!(
        again.contains(&Got::Publish {
            topic: "devices/d1/fw".into(),
            payload: b"r".to_vec(),
            qos: 2,
            pid: Some(3),
            retain: true,
            dup: true
        }),
        "{again:?}"
    );
}
