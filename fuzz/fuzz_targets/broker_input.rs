//! The broker behind the codec (M9, M15, M16): sessions, subscriptions
//! (device-scoped and ordinary), retained messages, QoS 1, wills,
//! takeovers and limits, driven by arbitrary bytes on several connections
//! with time passing. It must never panic, and output must stay bounded.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_broker::{Acl, Broker, Config};
use urmqtt_mqtt::Limits;

const ACL: Acl = Acl {
    device_publish: &["devices/{id}/#"],
    device_subscribe: &["devices/{id}/#"],
    service_ids: &["svc"],
    service_publish: &["devices/+/cmd/#", "fleet/#"],
    service_subscribe: &["devices/#", "fleet/#"],
    operator_ids: &["operator"],
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
    }
}

const IDS: [&str; 3] = ["d1", "d2", "svc"];

fuzz_target!(|data: &[u8]| {
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
            1 => b.tick(now),
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
                    }
                }
                if let Some(c) = *entry {
                    b.input(c, body, now);
                    let n = b.output(c).len();
                    assert!(n <= 64 * 1024, "output unbounded: {n}");
                    b.consumed(c, n);
                }
            }
        }
        b.drain_persist().for_each(drop);
        let _ = b.drain_telemetry().count();
        let _ = b.drain_routes().count();
        let mut ready = Vec::new();
        b.drain_ready(&mut ready);
    }
});
