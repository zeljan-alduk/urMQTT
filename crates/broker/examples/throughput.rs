//! Host-side routing throughput of the broker core (no network, no TLS):
//! `cargo run --release -p urmqtt-broker --example throughput`.
//!
//! 16 devices (the in-flight window) publish to their own telemetry topic; one backend session
//! subscribes to `devices/#` and acknowledges every QoS 1 or 2 delivery
//! (PUBACK, or PUBREC then PUBCOMP after the broker's PUBREL). Each line
//! is one publish QoS / subscription QoS pair: messages routed per second
//! (best of 5 runs), so a change of the state machine can be compared
//! before and after on the same machine.

use std::time::Instant;

use urmqtt_broker::{Acl, Broker, Config};
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

fn cfg() -> Config {
    Config {
        limits: Limits {
            max_packet_size: 4096,
            max_topic_len: 256,
            max_topic_levels: 16,
            max_client_id_len: 64,
            max_topics_per_packet: 8,
        },
        max_connections: 128,
        max_subscriptions_per_session: 8,
        max_inflight: 16,
        max_queued: 64,
        max_retained_per_device: 4,
        max_retained_bytes: 1 << 20,
        rate_tokens: u32::MAX,
        rate_period_ms: 1,
        max_outbound_bytes: 1 << 20,
        acl: ACL,
        persist: false,
        telemetry: &[],
        fanout: false,
        control_ids: &[],
        plain: None,
        web: None,
    }
}

fn wire(p: &Packet<'_>) -> Vec<u8> {
    let mut v = vec![0u8; encoded_len(p)];
    encode(p, &mut v).unwrap();
    v
}

fn connect(b: &mut Broker, id: &str) -> u32 {
    let c = b.open(0).unwrap();
    b.input(
        c,
        &wire(&Packet::Connect(Connect {
            protocol_level: 4,
            clean_session: true,
            keep_alive: 0,
            client_id: id,
            will: None,
            username: None,
            password: None,
        })),
        0,
    );
    let n = b.output(c).len();
    b.consumed(c, n);
    c
}

/// Reads the backend's output and answers every delivery; returns how many
/// PUBLISHes it held and how many packets in all.
fn drain(b: &mut Broker, c: u32, acks: &mut Vec<u8>) -> (u64, u64) {
    let out = b.output(c).to_vec();
    b.consumed(c, out.len());
    let (mut n, mut all) = (0, 0);
    let mut at = 0;
    acks.clear();
    while let Ok((p, used)) = decode(&out[at..], &Limits::PROTOCOL_MAX) {
        at += used;
        all += 1;
        match p {
            Packet::Publish(p) => {
                n += 1;
                match (p.qos, p.packet_id) {
                    (QoS::AtLeastOnce, Some(id)) => acks.extend(wire(&Packet::PubAck(id))),
                    (QoS::ExactlyOnce, Some(id)) => acks.extend(wire(&Packet::PubRec(id))),
                    _ => {}
                }
            }
            Packet::PubRel(id) => acks.extend(wire(&Packet::PubComp(id))),
            _ => {}
        }
    }
    if !acks.is_empty() {
        let a = std::mem::take(acks);
        b.input(c, &a, 0);
        *acks = a;
    }
    (n, all)
}

fn run(pub_qos: QoS, sub_qos: QoS, total: u64) -> f64 {
    let mut b = Broker::new(cfg());
    let backend = connect(&mut b, "backend");
    let list = [("devices/#", sub_qos)];
    b.input(
        backend,
        &wire(&Packet::Subscribe(Subscribe {
            packet_id: 1,
            topics: SubscribeTopics::List(&list),
        })),
        0,
    );
    let n = b.output(backend).len();
    b.consumed(backend, n);
    let devices: Vec<(u32, String)> = (0..16)
        .map(|i| {
            let id = format!("dev{i}");
            (connect(&mut b, &id), format!("devices/{id}/telemetry"))
        })
        .collect();
    let payload = [0x5au8; 64];
    let mut acks = Vec::new();
    let mut pid = 0u16;
    let mut got = 0u64;
    let t0 = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        for (c, topic) in &devices {
            pid = pid.checked_add(1).unwrap_or(1);
            let p = wire(&Packet::Publish(Publish {
                dup: false,
                qos: pub_qos,
                retain: false,
                topic,
                packet_id: (pub_qos != QoS::AtMostOnce).then_some(pid),
                payload: &payload,
            }));
            b.input(*c, &p, 0);
            // The publisher's own acknowledgement (PUBACK or PUBREC).
            let out = b.output(*c).to_vec();
            b.consumed(*c, out.len());
            if pub_qos == QoS::ExactlyOnce {
                b.input(*c, &wire(&Packet::PubRel(pid)), 0);
                let n = b.output(*c).len();
                b.consumed(*c, n);
            }
            sent += 1;
        }
        // Until the backend has nothing left to answer.
        loop {
            let (n, all) = drain(&mut b, backend, &mut acks);
            got += n;
            if all == 0 {
                break;
            }
        }
    }
    assert!(got >= total, "{got} of {total} delivered");
    total as f64 / t0.elapsed().as_secs_f64()
}

fn main() {
    let total = 1_000_000;
    let mut pairs = vec![
        (QoS::AtMostOnce, QoS::AtMostOnce),
        (QoS::AtLeastOnce, QoS::AtLeastOnce),
    ];
    if std::env::args().any(|a| a == "--qos2") {
        pairs.push((QoS::ExactlyOnce, QoS::ExactlyOnce));
    }
    for (p, s) in pairs {
        let best = (0..5).map(|_| run(p, s, total)).fold(0.0, f64::max);
        println!(
            "publish QoS {} -> subscription QoS {}: {:.0} msg/s",
            p as u8, s as u8, best
        );
    }
}
