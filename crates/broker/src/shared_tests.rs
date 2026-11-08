//! MQTT 5.0 part 3 (ADR-275): shared subscriptions, on one shard and across
//! shards, and Subscription Identifiers.

use super::*;

/// The publications among `got`: (topic, payload, qos, Subscription
/// Identifiers).
fn pubs(got: &[G]) -> Vec<(String, Vec<u8>, u8, Vec<u32>)> {
    got.iter()
        .filter_map(|g| match g {
            G::Publish {
                topic,
                payload,
                qos,
                ..
            } => {
                let ids = g
                    .props()
                    .iter()
                    .filter_map(|p| match p {
                        Prop::SubscriptionIdentifier(i) => Some(i),
                        _ => None,
                    })
                    .collect();
                Some((topic.clone(), payload.clone(), *qos, ids))
            }
            _ => None,
        })
        .collect()
}

/// Acknowledges every QoS 1 publication in `got`.
fn ack_all(c: &C5, b: &mut Broker, got: &[G], now: u64) {
    for g in got {
        if let G::Publish {
            qos: 1,
            pid: Some(p),
            ..
        } = g
        {
            c.send(
                b,
                &P5::PubAck(Ack {
                    packet_id: *p,
                    reason: ReasonCode::Success,
                    properties: Props::EMPTY,
                }),
                now,
            );
        }
    }
}

const TELEMETRY: &str = "$share/g/devices/+/telemetry";

// ---- subscription identifiers ----------------------------------------------

#[test]
fn subscription_identifiers_come_back_in_one_publish_per_message() {
    // Paho's test_subscribe_identifiers: two overlapping subscriptions with
    // identifiers 2 and 3, one PUBLISH carrying both.
    let mut b = Broker::new(cfg());
    let (mut svc, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let got = svc.subscribe_props(
        &mut b,
        &[("devices/d1/x", q(QoS::ExactlyOnce))],
        &[Prop::SubscriptionIdentifier(2)],
        0,
    );
    assert_eq!(got, [G::SubAck(3, vec![2])]);
    svc.subscribe_props(
        &mut b,
        &[("devices/d1/x/#", q(QoS::ExactlyOnce))],
        &[Prop::SubscriptionIdentifier(3)],
        0,
    );
    // A third without an identifier: matches too, adds none.
    svc.subscribe(&mut b, &[("devices/+/x", q(QoS::AtMostOnce))], 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/x",
        b"m",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    let got = pubs(&svc.recv(&mut b));
    assert_eq!(got.len(), 1, "{got:?}");
    let mut ids = got[0].3.clone();
    ids.sort_unstable();
    assert_eq!(ids, [2, 3]);
    // Re-subscribing replaces the identifier; without one removes it.
    svc.subscribe_props(
        &mut b,
        &[("devices/d1/x", q(QoS::ExactlyOnce))],
        &[Prop::SubscriptionIdentifier(268_435_455)],
        0,
    );
    svc.subscribe(&mut b, &[("devices/d1/x/#", q(QoS::ExactlyOnce))], 0);
    d.publish(&mut b, "devices/d1/x", b"m", QoS::AtMostOnce, false, &[], 0);
    let got = pubs(&svc.recv(&mut b));
    assert_eq!(got[0].3, [268_435_455]);
    // A 3.1.1 subscriber never sees one; a message matching nothing with
    // an identifier carries none.
    d.publish(&mut b, "devices/d1/y", b"m", QoS::AtMostOnce, false, &[], 0);
    let got = pubs(&svc.recv(&mut b));
    assert!(got.iter().all(|p| p.3.is_empty()), "{got:?}");
    // Unsubscribe forgets it; the session's end forgets them all.
    assert_eq!(b.sub_ids.len(), 1);
    b.closed(svc.c, 0);
    assert!(b.sub_ids.is_empty());
}

#[test]
fn subscription_identifiers_on_retained_replays_and_queued_messages() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/r",
        b"kept",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    let (mut svc, _) = C5::connect(
        &mut b,
        "backend",
        true,
        &[Prop::SessionExpiryInterval(60), Prop::ReceiveMaximum(1)],
        None,
        0,
    );
    let got = svc.subscribe_props(
        &mut b,
        &[("devices/d1/#", q(QoS::AtLeastOnce))],
        &[Prop::SubscriptionIdentifier(9)],
        0,
    );
    let p = pubs(&got);
    assert_eq!(p, [("devices/d1/r".into(), b"kept".to_vec(), 0, vec![9])]);
    // Two QoS 1 messages, a window of one: the second waits in the queue and
    // is sent with its identifier when the first is acknowledged.
    d.publish(
        &mut b,
        "devices/d1/a",
        b"1",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/a",
        b"2",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    let got = svc.recv(&mut b);
    assert_eq!(pubs(&got).len(), 1);
    ack_all(&svc, &mut b, &got, 0);
    let p = pubs(&svc.recv(&mut b));
    assert_eq!(p, [("devices/d1/a".into(), b"2".to_vec(), 1, vec![9])]);
}

#[test]
fn subscription_identifiers_are_persisted_and_restored() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (mut svc, _) = C5::connect(
        &mut b,
        "backend",
        true,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    svc.subscribe_props(
        &mut b,
        &[("fleet/#", q(QoS::AtLeastOnce))],
        &[Prop::SubscriptionIdentifier(77)],
        0,
    );
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        ops.iter()
            .any(|o| matches!(o, PersistOp::Subscribe { sub_id: 77, .. })),
        "{ops:?}"
    );
    // A restart: the store gives it back.
    let mut b = Broker::new(cfg());
    let st = StoredSession {
        expiry_s: Some(60),
        offline_for_s: 0,
        now_ms: 0,
    };
    assert!(b.restore_session5(
        "backend",
        st,
        [StoredSub {
            filter: "fleet/#",
            options: 1,
            sub_id: 77
        }],
        [],
        []
    ));
    let (mut svc, _) = C5::connect(
        &mut b,
        "backend",
        false,
        &[Prop::SessionExpiryInterval(60)],
        None,
        0,
    );
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    s2.publish(&mut b, "fleet/a", b"x", QoS::AtMostOnce, false, &[], 0);
    assert_eq!(pubs(&svc.recv(&mut b))[0].3, [77]);
}

#[test]
fn subscription_identifiers_and_shared_subscriptions_can_be_turned_off() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            shared_subscriptions: false,
            subscription_identifiers: false,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (mut svc, ack) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let p = connack_props(&ack);
    assert_eq!(
        p.get(Pid::SubscriptionIdentifierAvailable),
        Some(Prop::SubscriptionIdentifierAvailable(0))
    );
    assert_eq!(
        p.get(Pid::SharedSubscriptionAvailable),
        Some(Prop::SharedSubscriptionAvailable(0))
    );
    let got = svc.subscribe(
        &mut b,
        &[
            (TELEMETRY, q(QoS::AtMostOnce)),
            ("fleet/#", q(QoS::AtMostOnce)),
        ],
        0,
    );
    assert_eq!(got, [G::SubAck(3, vec![0x9e, 0])]);
    let got = svc.subscribe_props(
        &mut b,
        &[("fleet/#", q(QoS::AtMostOnce))],
        &[Prop::SubscriptionIdentifier(7)],
        0,
    );
    assert_eq!(got, [G::SubAck(3, vec![0xa1])]);
    // 3.1.1 knows only 0x80.
    let c4 = connect4(&mut b, "backend2", true, 0);
    let out = send4(
        &mut b,
        c4,
        &Packet::Subscribe(Subscribe {
            packet_id: 5,
            topics: SubscribeTopics::List(&[(TELEMETRY, QoS::AtMostOnce)]),
        }),
        0,
    );
    assert_eq!(out, [0x90, 3, 0, 5, 0x80]);
}

// ---- shared subscriptions, one shard ------------------------------------------

#[test]
fn a_shared_group_gets_each_message_once_round_robin() {
    let mut b = Broker::new(cfg());
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    assert_eq!(
        s1.subscribe(&mut b, &[(TELEMETRY, q(QoS::AtLeastOnce))], 0),
        [G::SubAck(3, vec![1])]
    );
    assert_eq!(
        s2.subscribe(&mut b, &[(TELEMETRY, q(QoS::AtMostOnce))], 0),
        [G::SubAck(3, vec![0])]
    );
    assert_eq!(b.stats().shared_groups, 1);
    assert_eq!(b.stats().shared_members, 2);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    for i in 0..6u8 {
        d.publish(
            &mut b,
            "devices/d1/telemetry",
            &[i],
            QoS::AtLeastOnce,
            false,
            &[],
            0,
        );
    }
    let a = pubs(&s1.recv(&mut b));
    let c = pubs(&s2.recv(&mut b));
    assert_eq!(a.len() + c.len(), 6, "{a:?} {c:?}");
    assert_eq!((a.len(), c.len()), (3, 3), "round robin");
    // The member's QoS bounds the delivery: s2 subscribed at 0.
    assert!(a.iter().all(|p| p.2 == 1) && c.iter().all(|p| p.2 == 0));
    let mut all: Vec<u8> = a.iter().chain(&c).map(|p| p.1[0]).collect();
    all.sort_unstable();
    assert_eq!(all, [0, 1, 2, 3, 4, 5], "each exactly once");
    assert_eq!(b.stats().shared_delivered, 6);
    // A topic outside the filter: nobody.
    d.publish(
        &mut b,
        "devices/d1/other",
        b"",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    assert!(s1.recv(&mut b).is_empty() && s2.recv(&mut b).is_empty());
    // UNSUBSCRIBE: the other member gets everything.
    s1.send(
        &mut b,
        &P5::Unsubscribe(Unsub5 {
            packet_id: 4,
            properties: Props::EMPTY,
            topics: UnsubTopics5::List(&[TELEMETRY]),
        }),
        0,
    );
    assert_eq!(s1.recv(&mut b), [G::UnsubAck(4, vec![0])]);
    for _ in 0..3 {
        d.publish(
            &mut b,
            "devices/d1/telemetry",
            b"",
            QoS::AtMostOnce,
            false,
            &[],
            0,
        );
    }
    assert!(s1.recv(&mut b).is_empty());
    assert_eq!(pubs(&s2.recv(&mut b)).len(), 3);
    // The last member leaves: the group is gone.
    b.closed(s2.c, 0);
    assert_eq!(b.stats().shared_groups, 0);
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    assert_eq!(b.stats().shared_dropped, 0, "no group, nothing to drop");
}

#[test]
fn a_shared_subscription_gets_no_retained_messages_and_no_local_is_refused() {
    let mut b = Broker::new(cfg());
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"r",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    // §4.8.2: no retained message on a shared subscribe; a plain one in the
    // same SUBSCRIBE gets it.
    let got = s1.subscribe(
        &mut b,
        &[
            (TELEMETRY, q(QoS::AtMostOnce)),
            ("devices/d1/telemetry", q(QoS::AtMostOnce)),
        ],
        0,
    );
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0], G::SubAck(3, vec![0, 0]));
    assert_eq!(pubs(&got[1..]).len(), 1);
    // No Local on a shared subscription is a protocol error [MQTT-3.8.3-4]
    // (the codec refuses it: DISCONNECT 0x82).
    // The encoder will not write it: the bytes by hand.
    let mut raw = vec![0x82, 0, 0, 9, 0];
    raw.extend_from_slice(&(TELEMETRY.len() as u16).to_be_bytes());
    raw.extend_from_slice(TELEMETRY.as_bytes());
    raw.push(0x04);
    raw[1] = (raw.len() - 2) as u8;
    b.input(s1.c, &raw, 0);
    let got = s1.recv(&mut b);
    assert_eq!(got, [G::Disconnect(0x82, Some("protocol error".into()))]);
}

#[test]
fn the_acl_judges_the_filter_inside_the_share_and_groups_never_cross_roles() {
    let mut b = Broker::new(cfg());
    let (mut d1, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    // A device may not take another device's commands through a share.
    let got = d1.subscribe(
        &mut b,
        &[
            ("$share/g/devices/d2/cmd/#", q(QoS::AtMostOnce)),
            // The group name is not a topic: `devices` is just a name.
            ("$share/devices/devices/d1/cmd/#", q(QoS::AtMostOnce)),
        ],
        0,
    );
    assert_eq!(got, [G::SubAck(3, vec![0x87, 0])]);
    // The same group name and filter from a service: another group (its
    // role class), so the device's group takes nothing from the backend.
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    s1.subscribe(
        &mut b,
        &[("$share/devices/devices/d1/cmd/#", q(QoS::AtMostOnce))],
        0,
    );
    assert_eq!(b.stats().shared_groups, 2);
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    for _ in 0..4 {
        s2.publish(
            &mut b,
            "devices/d1/cmd/go",
            b"",
            QoS::AtMostOnce,
            false,
            &[],
            0,
        );
    }
    assert_eq!(pubs(&d1.recv(&mut b)).len(), 4);
    assert_eq!(pubs(&s1.recv(&mut b)).len(), 4);
}

#[test]
fn offline_members_are_skipped_and_queued_for_only_when_none_is_online() {
    let mut b = Broker::new(cfg());
    let persistent = [Prop::SessionExpiryInterval(600)];
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &persistent, None, 0);
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &persistent, None, 0);
    s1.subscribe(&mut b, &[(TELEMETRY, q(QoS::AtLeastOnce))], 0);
    s2.subscribe(&mut b, &[(TELEMETRY, q(QoS::AtLeastOnce))], 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    // s2 goes away (its session stays): s1 gets everything.
    b.closed(s2.c, 0);
    for i in 0..4u8 {
        d.publish(
            &mut b,
            "devices/d1/telemetry",
            &[i],
            QoS::AtLeastOnce,
            false,
            &[],
            0,
        );
    }
    let got = s1.recv(&mut b);
    assert_eq!(pubs(&got).len(), 4);
    ack_all(&s1, &mut b, &got, 0);
    // Both away: QoS 1 is queued for a member in turn, QoS 0 dropped.
    b.closed(s1.c, 0);
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"q1",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"q0",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    assert_eq!(b.stats().shared_dropped, 1);
    let (mut s1, ack) = C5::connect(&mut b, "backend", false, &persistent, None, 0);
    let (mut s2, ack2) = C5::connect(&mut b, "backend2", false, &persistent, None, 0);
    assert!(matches!(ack, G::ConnAck { present: true, .. }));
    assert!(matches!(ack2, G::ConnAck { present: true, .. }));
    let a = pubs(&s1.recv(&mut b));
    let c = pubs(&s2.recv(&mut b));
    assert_eq!(a.len() + c.len(), 1, "{a:?} {c:?}");
    assert_eq!(
        a.iter().chain(&c).next().map(|p| p.1.clone()),
        Some(b"q1".to_vec())
    );
    // Online again: round robin over both.
    for _ in 0..2 {
        d.publish(
            &mut b,
            "devices/d1/telemetry",
            b"",
            QoS::AtMostOnce,
            false,
            &[],
            0,
        );
    }
    assert_eq!(pubs(&s1.recv(&mut b)).len(), 1);
    assert_eq!(pubs(&s2.recv(&mut b)).len(), 1);
}

#[test]
fn a_clean_members_unacknowledged_qos1_goes_to_another_member_qos2_never() {
    let mut b = Broker::new(cfg());
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    let (mut s2, _) = C5::connect(&mut b, "backend2", true, &[], None, 0);
    s1.subscribe(&mut b, &[(TELEMETRY, q(QoS::ExactlyOnce))], 0);
    s2.subscribe(&mut b, &[(TELEMETRY, q(QoS::ExactlyOnce))], 0);
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    // s1 gets the first (QoS 1) and the third (QoS 2); s2 the second.
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"a",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"b",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/telemetry",
        b"c",
        QoS::ExactlyOnce,
        false,
        &[],
        0,
    );
    let a = pubs(&s1.recv(&mut b));
    let got2 = s2.recv(&mut b);
    assert_eq!(a.len(), 2, "{a:?}");
    ack_all(&s2, &mut b, &got2, 0);
    // s1 (expiry 0) goes away without acknowledging: the QoS 1 message goes
    // to s2, the QoS 2 one does not [MQTT-4.8.2-5].
    b.closed(s1.c, 0);
    let again = pubs(&s2.recv(&mut b));
    assert_eq!(
        again,
        [("devices/d1/telemetry".into(), b"a".to_vec(), 1, vec![])]
    );
    assert_eq!(b.stats().shared_redispatched, 1);
}

#[test]
fn takeover_will_limits_and_a_3_1_1_member() {
    let mut b = Broker::new(Config {
        mqtt5: Mqtt5Policy {
            max_shared_groups: 2,
            max_shared_group_members: 2,
            ..Mqtt5Policy::DEFAULT
        },
        ..cfg()
    });
    let (mut s1, _) = C5::connect(&mut b, "backend", true, &[], None, 0);
    // A 3.1.1 client shares too (as other brokers allow).
    let c4 = connect4(&mut b, "backend2", true, 0);
    let out = send4(
        &mut b,
        c4,
        &Packet::Subscribe(Subscribe {
            packet_id: 5,
            topics: SubscribeTopics::List(&[(TELEMETRY, QoS::AtMostOnce)]),
        }),
        0,
    );
    assert_eq!(out, [0x90, 3, 0, 5, 0]);
    s1.subscribe(&mut b, &[(TELEMETRY, q(QoS::AtMostOnce))], 0);
    // Limits: a third member, a third group: 0x97.
    let (mut s3, _) = C5::connect_as(&mut b, Some("ops"), "ops", true, &[], None, 0);
    let got = s1.subscribe(
        &mut b,
        &[
            ("$share/h/devices/+/telemetry", q(QoS::AtMostOnce)),
            ("$share/i/devices/+/telemetry", q(QoS::AtMostOnce)),
        ],
        0,
    );
    assert_eq!(got, [G::SubAck(3, vec![0, 0x97])]);
    assert_eq!(b.stats().shared_refused, 1);
    let got = s3.subscribe(&mut b, &[("$share/g/$SYS/#", q(QoS::AtMostOnce))], 0);
    assert_eq!(got, [G::SubAck(3, vec![0x97])], "a third group");
    // A device's Will reaches one member.
    let (d, _) = C5::connect(
        &mut b,
        "d1",
        true,
        &[],
        Some(Will5 {
            topic: "devices/d1/telemetry",
            payload: b"gone",
            qos: QoS::AtMostOnce,
            retain: false,
            properties: Props::EMPTY,
        }),
        0,
    );
    b.closed(d.c, 0);
    // Group g (s1 or the 3.1.1 member) and group h (s1): two copies.
    let w1 = pubs(&s1.recv(&mut b)).len();
    let w4 = b.output(c4).len() / 28; // one 3.1.1 PUBLISH of the Will
    assert_eq!(w1 + w4, 2, "{w1} {w4}");
    // Takeover that resumes the session: still one member of each group.
    let before = b.stats().shared_members;
    let (_, ack) = C5::connect(&mut b, "backend", false, &[], None, 0);
    assert!(matches!(ack, G::ConnAck { present: true, .. }), "{ack:?}");
    assert_eq!(b.stats().shared_members, before);
    // A clean start ends the session: it leaves both its groups.
    C5::connect(&mut b, "backend", true, &[], None, 0);
    assert_eq!(b.stats().shared_members, before - 2);
}

// ---- shared subscriptions across shards ------------------------------------------

/// Brokers as the kernel runs them, one per shard, with a mesh that moves
/// routes and shared-subscription messages between them.
struct Mesh {
    b: Vec<Broker>,
}

impl Mesh {
    fn new(n: u16) -> Self {
        let b = (0..n)
            .map(|i| {
                let mut b = Broker::new(Config {
                    fanout: true,
                    ..cfg()
                });
                b.set_shards(i, 0, n);
                b
            })
            .collect();
        Mesh { b }
    }

    /// Delivers everything in flight between shards; returns how many
    /// messages moved.
    fn pump(&mut self, now: u64) -> usize {
        let mut moved = 0;
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
                    assert_ne!(usize::from(to), i, "a shard never mails itself");
                    self.b[usize::from(to)].shared_input(i as u16, m, now);
                    moved += 1;
                    any = true;
                }
            }
            if !any {
                return moved;
            }
        }
    }
}

/// A group name whose owner is shard `owner` of `n`, for role class `class`.
fn group_owned_by(owner: u16, n: u16, class: u8, filter: &str) -> String {
    let s = shared::Shards {
        me: 0,
        first: 0,
        count: n,
    };
    (0..)
        .map(|i| format!("g{i}"))
        .find(|g| s.owner(class, g, filter) == owner)
        .unwrap()
}

#[test]
fn across_shards_the_owner_decides_and_the_members_shards_deliver() {
    let mut m = Mesh::new(3);
    let filter = "devices/+/telemetry";
    let g = group_owned_by(2, 3, shared::class(Role::Service), filter);
    let share = format!("$share/{g}/{filter}");
    // Members on shards 0 and 1; the owner is shard 2; the publisher on 2.
    let (mut s1, _) = C5::connect(&mut m.b[0], "backend", true, &[], None, 0);
    let (mut s2, _) = C5::connect(&mut m.b[1], "backend2", true, &[], None, 0);
    // The SUBACK waits for the owner, and so does the next packet.
    s1.send(
        &mut m.b[0],
        &P5::Subscribe(Sub5 {
            packet_id: 3,
            properties: Props::EMPTY,
            topics: SubTopics5::List(&[(&share, q(QoS::AtLeastOnce))]),
        }),
        0,
    );
    s1.send(&mut m.b[0], &P5::PingReq, 0);
    assert!(
        s1.recv(&mut m.b[0]).is_empty(),
        "nothing before the owner answers"
    );
    assert!(m.pump(0) > 0);
    assert_eq!(
        s1.recv(&mut m.b[0]),
        [G::SubAck(3, vec![1]), G::PingResp],
        "then the SUBACK, then the PINGRESP"
    );
    s2.subscribe(&mut m.b[1], &[(&share, q(QoS::AtLeastOnce))], 0);
    m.pump(0);
    assert_eq!(m.b[1].stats().shared_groups, 0);
    assert_eq!(m.b[2].stats().shared_groups, 1);
    assert_eq!(m.b[2].stats().shared_members, 2);
    let (mut d, _) = C5::connect(&mut m.b[2], "d1", true, &[], None, 0);
    for i in 0..8u8 {
        d.publish(
            &mut m.b[2],
            "devices/d1/telemetry",
            &[i],
            QoS::AtLeastOnce,
            false,
            &[],
            0,
        );
        m.pump(0);
    }
    let a = pubs(&s1.recv(&mut m.b[0]));
    let c = pubs(&s2.recv(&mut m.b[1]));
    assert_eq!((a.len(), c.len()), (4, 4), "{a:?} {c:?}");
    let mut all: Vec<u8> = a.iter().chain(&c).map(|p| p.1[0]).collect();
    all.sort_unstable();
    assert_eq!(all, (0..8).collect::<Vec<u8>>());
    // A publisher on a member's shard: still one delivery per message.
    let (mut d2, _) = C5::connect(&mut m.b[0], "d2", true, &[], None, 0);
    d2.publish(
        &mut m.b[0],
        "devices/d2/telemetry",
        b"x",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    m.pump(0);
    let n = pubs(&s1.recv(&mut m.b[0])).len() + pubs(&s2.recv(&mut m.b[1])).len();
    assert_eq!(n, 1);
}

#[test]
fn across_shards_a_member_that_is_gone_hands_the_message_on() {
    let mut m = Mesh::new(3);
    let filter = "devices/+/telemetry";
    let g = group_owned_by(2, 3, shared::class(Role::Service), filter);
    let share = format!("$share/{g}/{filter}");
    let (mut s1, _) = C5::connect(&mut m.b[0], "backend", true, &[], None, 0);
    let (mut s2, _) = C5::connect(&mut m.b[1], "backend2", true, &[], None, 0);
    s1.send(
        &mut m.b[0],
        &P5::Subscribe(Sub5 {
            packet_id: 3,
            properties: Props::EMPTY,
            topics: SubTopics5::List(&[(&share, q(QoS::AtLeastOnce))]),
        }),
        0,
    );
    m.pump(0);
    s2.send(
        &mut m.b[1],
        &P5::Subscribe(Sub5 {
            packet_id: 3,
            properties: Props::EMPTY,
            topics: SubTopics5::List(&[(&share, q(QoS::AtLeastOnce))]),
        }),
        0,
    );
    m.pump(0);
    s1.recv(&mut m.b[0]);
    s2.recv(&mut m.b[1]);
    // s1's session ends on shard 0 while the owner still lists it; its Leave
    // is on the way, after the owner already sent it a message.
    let (mut d, _) = C5::connect(&mut m.b[2], "d1", true, &[], None, 0);
    d.publish(
        &mut m.b[2],
        "devices/d1/telemetry",
        b"a",
        QoS::AtLeastOnce,
        false,
        &[],
        0,
    );
    // Deliver to s1 is queued in shard 2's outbox; s1 closes first.
    m.b[0].closed(s1.c, 0);
    m.pump(0);
    let got = pubs(&s2.recv(&mut m.b[1]));
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(m.b[2].stats().shared_members, 1);
    // A QoS 0 message to a member that is gone is dropped (counted).
    d.publish(
        &mut m.b[2],
        "devices/d1/telemetry",
        b"b",
        QoS::AtMostOnce,
        false,
        &[],
        0,
    );
    m.b[1].closed(s2.c, 0);
    m.pump(0);
    assert_eq!(m.b[1].stats().shared_dropped, 1);
    assert_eq!(m.b[2].stats().shared_groups, 0);
}

#[test]
fn across_shards_a_limit_refuses_the_join_in_the_suback() {
    let mut m = Mesh::new(2);
    for b in &mut m.b {
        b.cfg.mqtt5.max_shared_group_members = 1;
    }
    let filter = "fleet/#";
    let g = group_owned_by(1, 2, shared::class(Role::Service), filter);
    let share = format!("$share/{g}/{filter}");
    let (mut s1, _) = C5::connect(&mut m.b[1], "backend", true, &[], None, 0);
    let (mut s2, _) = C5::connect(&mut m.b[0], "backend2", true, &[], None, 0);
    assert_eq!(
        s1.subscribe(&mut m.b[1], &[(&share, q(QoS::AtMostOnce))], 0),
        [G::SubAck(3, vec![0])]
    );
    s2.send(
        &mut m.b[0],
        &P5::Subscribe(Sub5 {
            packet_id: 3,
            properties: Props::EMPTY,
            topics: SubTopics5::List(&[
                (&share, q(QoS::AtMostOnce)),
                ("fleet/x", q(QoS::AtMostOnce)),
            ]),
        }),
        0,
    );
    m.pump(0);
    assert_eq!(s2.recv(&mut m.b[0]), [G::SubAck(3, vec![0x97, 0])]);
    assert_eq!(
        m.b[0].stats().subscriptions,
        1,
        "the refused share is undone"
    );
}

// ---- retained expiry sweep (ADR-275) -------------------------------------------

#[test]
fn expired_retained_messages_are_swept_even_if_nobody_reads_them() {
    let mut b = Broker::new(Config {
        persist: true,
        ..cfg()
    });
    let (mut d, _) = C5::connect(&mut b, "d1", true, &[], None, 0);
    d.publish(
        &mut b,
        "devices/d1/r",
        b"short",
        QoS::AtMostOnce,
        true,
        &[Prop::MessageExpiryInterval(1)],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/s",
        b"kept",
        QoS::AtMostOnce,
        true,
        &[],
        0,
    );
    // Replaced by a message with a longer life: one entry per topic.
    d.publish(
        &mut b,
        "devices/d1/t",
        b"1",
        QoS::AtMostOnce,
        true,
        &[Prop::MessageExpiryInterval(1)],
        0,
    );
    d.publish(
        &mut b,
        "devices/d1/t",
        b"2",
        QoS::AtMostOnce,
        true,
        &[Prop::MessageExpiryInterval(100)],
        0,
    );
    assert_eq!(b.stats().retained_expiring, 2);
    b.drain_persist().for_each(drop);
    b.tick(999);
    assert_eq!(b.stats().retained, 3);
    b.tick(1000);
    assert_eq!(b.stats().retained, 2);
    assert_eq!(b.stats().retained_expiring, 1);
    let ops: Vec<PersistOp> = b.drain_persist().collect();
    assert!(
        matches!(&ops[..], [PersistOp::Retain { msg, .. }] if &*msg.topic == "devices/d1/r" && msg.payload.is_empty()),
        "{ops:?}"
    );
    b.tick(100_000);
    assert_eq!(b.stats().retained, 1);
}
