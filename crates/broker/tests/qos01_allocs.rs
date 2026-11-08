//! The QoS 0 and QoS 1 path pays nothing for QoS 2 (ADR-271): heap
//! allocations and time per routed message, counted by a global allocator
//! over the broker's publish path (device PUBLISH -> backend delivery ->
//! PUBACK), after a warm-up so that buffers have their size.
//!
//! `cargo test --release -p urmqtt-broker --test qos01_allocs -- --nocapture`
//! prints the figures. The same file, run against the tree before QoS 2,
//! gave the same counts: 9 per QoS 0 message, 15 per QoS 1 message (ADR-271).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use urmqtt_broker::{Acl, Broker, Config};
use urmqtt_mqtt::{
    Connect, Limits, Packet, Publish, QoS, Subscribe, SubscribeTopics, decode, encode, encoded_len,
};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

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
        max_connections: 8,
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

/// (allocations, ns) per message for `n` messages at `qos` to a subscription at `qos`.
const BEFORE_QOS0: f64 = 9.0;
const BEFORE_QOS1: f64 = 15.0;

fn measure(qos: QoS, n: u32) -> (f64, f64) {
    let mut b = Broker::new(cfg());
    let backend = connect(&mut b, "backend");
    let list = [("devices/#", qos)];
    b.input(
        backend,
        &wire(&Packet::Subscribe(Subscribe {
            packet_id: 1,
            topics: SubscribeTopics::List(&list),
        })),
        0,
    );
    let k = b.output(backend).len();
    b.consumed(backend, k);
    let dev = connect(&mut b, "dev1");
    // Prebuilt packets: the measurement is the broker's, not the encoder's.
    let pubs: Vec<Vec<u8>> = (1..=64u16)
        .map(|pid| {
            wire(&Packet::Publish(Publish {
                dup: false,
                qos,
                retain: false,
                topic: "devices/dev1/telemetry",
                packet_id: (qos != QoS::AtMostOnce).then_some(pid),
                payload: &[0x5a; 64],
            }))
        })
        .collect();
    let mut out = Vec::with_capacity(1 << 16);
    let mut acks = Vec::with_capacity(1 << 12);
    let mut step = |b: &mut Broker, i: u32| {
        b.input(dev, &pubs[(i % 64) as usize], 0);
        let k = b.output(dev).len();
        b.consumed(dev, k);
        out.clear();
        out.extend_from_slice(b.output(backend));
        b.consumed(backend, out.len());
        acks.clear();
        let mut at = 0;
        while let Ok((p, used)) = decode(&out[at..], &Limits::PROTOCOL_MAX) {
            at += used;
            if let Packet::Publish(Publish {
                packet_id: Some(id),
                ..
            }) = p
            {
                acks.extend_from_slice(&[0x40, 2, (id >> 8) as u8, id as u8]);
            }
        }
        if !acks.is_empty() {
            b.input(backend, &acks, 0);
        }
    };
    for i in 0..1000 {
        step(&mut b, i);
    }
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let t0 = Instant::now();
    for i in 0..n {
        step(&mut b, i);
    }
    let ns = t0.elapsed().as_nanos() as f64 / f64::from(n);
    let a = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / f64::from(n);
    (a, ns)
}

#[test]
fn qos0_and_qos1_routing_allocate_no_more_than_before_qos2() {
    // Measured with this file on the tree before QoS 2 (cfe9fa1), release
    // build: the message (Arc, topic, payload) and the per-connection
    // buffers, which are released while empty (M15) and so are taken again
    // for every packet.
    let before = [
        (QoS::AtMostOnce, BEFORE_QOS0),
        (QoS::AtLeastOnce, BEFORE_QOS1),
    ];
    let mut got = Vec::new();
    for (qos, _) in before {
        let (allocs, ns) = measure(qos, 20_000);
        println!(
            "QoS {}: {allocs:.2} allocations and {ns:.0} ns per routed message",
            qos as u8
        );
        got.push(allocs);
    }
    for ((qos, want), allocs) in before.iter().zip(got) {
        assert!(
            allocs <= *want + 1e-9,
            "QoS {}: {allocs} allocations per message, {want} before QoS 2",
            *qos as u8
        );
    }
}
