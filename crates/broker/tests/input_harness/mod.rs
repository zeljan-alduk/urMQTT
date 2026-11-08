//! The `broker_input` fuzz harness (M9, M15, M16, ADR-271): the broker
//! behind the codec, driven by arbitrary bytes on several connections with
//! time passing. Shared by the cargo-fuzz target
//! (`fuzz/fuzz_targets/broker_input.rs`) and `tests/input_seeds.rs`, which
//! replays the seeds in `fuzz/seeds/broker_input/` as regressions.

#![allow(dead_code)]

use urmqtt_broker::{Acl, Broker, Config, PlainPolicy, PublisherBackpressure};
use urmqtt_mqtt::Limits;

pub const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/#"],
    service_ids: &["svc"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    service_subscribe: &["devices/#", "fleet/#"],
    operator_ids: &["operator"],
};

pub fn cfg() -> Config {
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
        max_inflight: 2,
        max_queued: 3,
        max_retained_per_device: 4,
        max_retained_bytes: 4096,
        rate_tokens: 50,
        rate_period_ms: 1000,
        max_outbound_bytes: 16 * 1024,
        acl: ACL,
        persist: true,
        telemetry: &["devices/+/telemetry/#"],
        fanout: true,
        control_ids: &["svc"],
        // P1: plaintext sessions, with their own patterns, limits and rate.
        plain: Some(PlainPolicy {
            publish: &["devices/{id}/#"],
            subscribe: &["devices/{id}/cmd/#"],
            max_packet_size: 256,
            rate_tokens: 5,
            rate_period_ms: 1000,
            retain: false,
        }),
        // ADR-272: WebSocket password sessions, with a policy of their own.
        mqtt5: Default::default(),
        web: Some(PlainPolicy {
            publish: &["web/{id}/#"],
            subscribe: &["web/{id}/#", "devices/+/telemetry/#"],
            max_packet_size: 512,
            rate_tokens: 5,
            rate_period_ms: 1000,
            retain: true,
        }),
        // ADR-269: publishers paused for a full single recipient.
        publisher_backpressure: PublisherBackpressure::Single,
    }
}

const IDS: [&str; 3] = ["d1", "d2", "svc"];

/// Feeds `data` to a fresh broker: 64-byte chunks, the first byte of each
/// choosing the operation (close, tick, shrink, input on one of four
/// connections, with a TLS, bootstrap, plaintext or WebSocket identity) and
/// the time step. Panics if the broker panics or its output grows without
/// bound.
pub fn run(data: &[u8]) -> Broker {
    let mut b = Broker::new(cfg());
    let mut conns: Vec<Option<u32>> = vec![None; 4];
    let mut now = 0u64;
    for chunk in data.chunks(64) {
        let Some((&op, body)) = chunk.split_first() else {
            continue;
        };
        let slot = usize::from(op & 3);
        now += u64::from(op >> 2) * 50;
        match op % 7 {
            0 => {
                if let Some(c) = conns.get_mut(slot).and_then(Option::take) {
                    b.closed(c, now);
                }
            }
            1 => {
                b.tick(now);
                b.poll_flow(now);
            }
            2 => b.shrink(),
            _ => {
                let Some(entry) = conns.get_mut(slot) else {
                    continue;
                };
                if entry.is_none() {
                    *entry = b.open(now);
                    if let Some(c) = *entry
                        && op & 0x40 != 0
                    {
                        // Bit 5: a bootstrap certificate (H1).
                        b.set_identity(c, IDS[slot % IDS.len()], op & 0x20 != 0);
                    } else if let Some(c) = *entry
                        && op & 0x80 != 0
                    {
                        // Bit 7 without bit 6: a plaintext connection (P1)
                        // whose identity the listener proved, or with bit 5
                        // a WebSocket password connection (ADR-272).
                        if op & 0x20 != 0 {
                            let _ = b.set_web_identity(c, IDS[slot % 2]);
                        } else {
                            let _ = b.set_plain_identity(c, IDS[slot % 2]);
                        }
                    }
                }
                if let Some(c) = *entry {
                    b.input(c, body, now);
                    let n = b.output(c).len();
                    // A subscriber waited for by another shard's publisher may
                    // take 256 KiB beyond its 16 KiB buffer (ADR-269).
                    assert!(n <= 320 * 1024, "output unbounded: {n}");
                    b.consumed(c, n);
                }
            }
        }
        b.drain_persist().for_each(drop);
        let _ = b.drain_telemetry().count();
        // A few routed messages come back as if from another shard, with their
        // publisher (ADR-269: a full single subscriber asks for a pause).
        let routes: Vec<_> = b.drain_routes().take(4).collect();
        for (m, q, r, o) in routes {
            let _ = b.route_remote_from(&m, q, r, o.map(|c| (1, c)), now);
        }
        let _ = b.drain_routes().count();
        let mut ready = Vec::new();
        b.drain_ready(&mut ready);
        let mut flow = Vec::new();
        b.drain_flow(&mut flow);
        // What other shards say about this shard's publishers (ADR-269):
        // delivered there, full there, drained there.
        if let Some(Some(c)) = conns.get(usize::from(chunk.len() as u8 & 3)) {
            let shard = u16::from(chunk[0] >> 6);
            match chunk.len() % 7 {
                0 => b.note_remote_recipients(*c, shard, u32::from(chunk[0] & 3), now),
                1 => b.remote_full(*c, shard, now),
                2 => b.remote_drained(*c, shard, now),
                _ => {}
            }
        }
        let mut remote = Vec::new();
        b.drain_remote_flow(&mut remote);
    }
    b
}
