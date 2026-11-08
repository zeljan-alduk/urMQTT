//! Publisher back-pressure (NOW-13, ADR-269): scripted connections.

use super::*;
use crate::flow::{COOLDOWN_MS, DRAIN_SLICE, PAUSE_MAX_MS, REMOTE_SEEN_MS};

/// Two services that may publish and subscribe under `fleet/`, small output
/// buffers (high water 512 B, low water 256 B), no rate limit to speak of.
fn flow_cfg() -> Config {
    Config {
        acl: Acl {
            service_ids: &["a", "b", "c"],
            service_publish: &["fleet/#"],
            service_subscribe: &["fleet/#"],
            ..ACL
        },
        rate_tokens: 1_000_000,
        max_outbound_bytes: 1024,
        max_queued: 1000,
        ..cfg()
    }
}

fn wire(p: &Packet<'_>) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len(p)];
    encode(p, &mut out).unwrap();
    out
}

/// `n` QoS 0 PUBLISHes to `topic`, payload = the index (4 bytes) + padding.
fn flood(topic: &str, n: u32, size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let mut payload = i.to_be_bytes().to_vec();
        payload.resize(size.max(4), 0);
        out.extend(wire(&Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic,
            packet_id: None,
            payload: &payload,
        })));
    }
    out
}

fn indexes(got: &[Got]) -> Vec<u32> {
    got.iter()
        .filter_map(|g| match g {
            Got::Publish { payload, .. } => {
                Some(u32::from_be_bytes(payload[..4].try_into().unwrap()))
            }
            _ => None,
        })
        .collect()
}

fn flow_events(b: &mut Broker) -> Vec<(ConnId, bool)> {
    let mut v = Vec::new();
    b.drain_flow(&mut v);
    v
}

/// One publisher, one subscriber that reads slowly: the publisher is paused
/// whenever the subscriber's buffer is over the high-water mark, nothing is
/// dropped, every message arrives in order, and the window events alternate
/// close/open and end open.
#[test]
fn a_single_slow_subscriber_pauses_the_publisher_instead_of_dropping() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.input(pubr.c, &flood("fleet/b", 500, 64), 1);
    assert!(b.input_held(pubr.c));
    assert_eq!(flow_events(&mut b), vec![(pubr.c, true)]);
    assert_eq!(b.stats().dropped_backpressure, 0);
    let mut got = Vec::new();
    let mut now = 1;
    let mut events = Vec::new();
    for _ in 0..10_000 {
        got.extend(indexes(&sub.recv(&mut b)));
        now += 1;
        b.poll_flow(now);
        events.extend(flow_events(&mut b));
        if !b.input_held(pubr.c) && got.len() == 500 {
            break;
        }
    }
    assert_eq!(got, (0..500).collect::<Vec<_>>());
    assert_eq!(b.stats().dropped_backpressure, 0);
    assert_eq!(events.last(), Some(&(pubr.c, false)));
    let fs = b.flow_stats();
    assert!(fs.pauses >= 1);
    assert_eq!((fs.timeouts, fs.holding), (0, 0));
    // Never two closes or two opens in a row.
    let mut closed = true;
    for (c, close) in events {
        assert_eq!(c, pubr.c);
        assert_ne!(close, closed);
        closed = close;
    }
}

/// `limits.publisher_backpressure = "off"`: the old rule, read and drop.
#[test]
fn off_reads_and_drops() {
    let mut b = Broker::new(Config {
        publisher_backpressure: PublisherBackpressure::Off,
        ..flow_cfg()
    });
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.input(pubr.c, &flood("fleet/b", 500, 64), 1);
    assert!(!b.input_held(pubr.c));
    assert!(flow_events(&mut b).is_empty());
    let got = indexes(&sub.recv(&mut b));
    assert!(got.len() < 500);
    assert_eq!(b.stats().dropped_backpressure, 500 - got.len() as u64);
}

/// Fan-out: two recipients, one of them slow; the publisher keeps being
/// read (the fast one must not wait for the slow one) and the slow one
/// loses messages.
#[test]
fn fan_out_keeps_dropping() {
    let mut b = Broker::new(flow_cfg());
    let (mut slow, _) = Client::connect_tls(&mut b, "b", 0);
    slow.subscribe(&mut b, 1, &[("fleet/x", QoS::AtMostOnce)], 0);
    let (mut fast, _) = Client::connect_tls(&mut b, "c", 0);
    fast.subscribe(&mut b, 1, &[("fleet/x", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    let mut fast_got = Vec::new();
    for i in 0..500u32 {
        let mut one = flood("fleet/x", 1, 64);
        // The index of this message.
        let at = one.len() - 64;
        one[at..at + 4].copy_from_slice(&i.to_be_bytes());
        b.input(pubr.c, &one, 1);
        fast_got.extend(indexes(&fast.recv(&mut b)));
    }
    assert!(!b.input_held(pubr.c));
    assert_eq!(fast_got, (0..500).collect::<Vec<_>>());
    assert!(b.stats().dropped_backpressure > 0);
    assert_eq!(b.flow_stats().pauses, 0);
    assert!(indexes(&slow.recv(&mut b)).len() < 500);
}

/// A client that publishes to a topic only it subscribes to is never paused
/// for itself: its own reading would be what stops.
#[test]
fn a_publisher_is_never_paused_for_itself() {
    let mut b = Broker::new(flow_cfg());
    let (mut a, _) = Client::connect_tls(&mut b, "a", 0);
    a.subscribe(&mut b, 1, &[("fleet/a", QoS::AtMostOnce)], 0);
    b.input(a.c, &flood("fleet/a", 500, 64), 1);
    assert!(!b.input_held(a.c));
    assert!(b.stats().dropped_backpressure > 0);
    assert_eq!(b.flow_stats().pauses, 0);
}

/// QoS 1 deliveries have their in-flight window and queue: no pause, and
/// the queue behaves as before (ADR-269 point 3).
#[test]
fn qos1_deliveries_are_not_paused_for() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtLeastOnce)], 0);
    let (mut pubr, _) = Client::connect_tls(&mut b, "a", 0);
    let mut acks = 0;
    for _ in 0..200 {
        let got = pubr.publish(&mut b, "fleet/b", &[0; 64], QoS::AtLeastOnce, false, 1);
        acks += got.iter().filter(|g| matches!(g, Got::PubAck(_))).count();
    }
    assert!(!b.input_held(pubr.c));
    assert_eq!(b.flow_stats().pauses, 0);
    // Every PUBACK was sent at once.
    assert_eq!(acks, 200);
    // max_inflight (2) in flight, the rest queued: nothing dropped.
    let st = b.stats();
    assert_eq!((st.dropped_backpressure, st.dropped_queue_full), (0, 0));
}

/// A publishes to B while B publishes to A, neither reads: A is paused for
/// B, but B is never paused for A (A's input is held), so no cycle of pauses
/// forms; B's messages to A are dropped instead.
#[test]
fn two_publishers_for_each_other_never_both_pause() {
    let mut b = Broker::new(flow_cfg());
    let (mut a, _) = Client::connect_tls(&mut b, "a", 0);
    a.subscribe(&mut b, 1, &[("fleet/a", QoS::AtMostOnce)], 0);
    let (mut bb, _) = Client::connect_tls(&mut b, "b", 0);
    bb.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    b.input(a.c, &flood("fleet/b", 300, 64), 1);
    assert!(b.input_held(a.c));
    b.input(bb.c, &flood("fleet/a", 300, 64), 1);
    assert!(
        !b.input_held(bb.c),
        "B must not wait for A, which waits for B"
    );
    assert!(b.stats().dropped_backpressure > 0);
    // The same in the other order of events: B first.
    let mut b2 = Broker::new(flow_cfg());
    let (mut a, _) = Client::connect_tls(&mut b2, "a", 0);
    a.subscribe(&mut b2, 1, &[("fleet/a", QoS::AtMostOnce)], 0);
    let (mut bb, _) = Client::connect_tls(&mut b2, "b", 0);
    bb.subscribe(&mut b2, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    b2.input(bb.c, &flood("fleet/a", 300, 64), 1);
    b2.input(a.c, &flood("fleet/b", 300, 64), 1);
    assert!(b2.input_held(bb.c) != b2.input_held(a.c));
}

/// A chain A -> B -> C -> A: at most two of the three are ever held.
#[test]
fn a_cycle_of_three_cannot_close() {
    let mut b = Broker::new(flow_cfg());
    let mut cl = Vec::new();
    for id in ["a", "b", "c"] {
        let (mut c, _) = Client::connect_tls(&mut b, id, 0);
        c.subscribe(&mut b, 1, &[(&format!("fleet/{id}"), QoS::AtMostOnce)], 0);
        cl.push(c);
    }
    for round in 0..3 {
        for (i, to) in ["fleet/b", "fleet/c", "fleet/a"].iter().enumerate() {
            b.input(cl[i].c, &flood(to, 100, 64), 1 + round);
        }
        let held = cl.iter().filter(|c| b.input_held(c.c)).count();
        assert!(held <= 2, "round {round}: {held} held");
    }
}

/// The pause is bounded: a subscriber that never reads holds the publisher
/// PAUSE_MAX_MS at most; then the held bytes are parsed (and dropped, as
/// before), the window opens, and the publisher is in cool-down. Keep-alive
/// counts the paused time as alive, and a PINGREQ held behind the pause is
/// answered when it ends.
#[test]
fn the_pause_is_bounded_and_counts_as_alive() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (mut pubr, _) = Client::connect_tls(&mut b, "a", 0);
    let mut bytes = flood("fleet/b", 200, 64);
    bytes.extend(wire(&Packet::PingReq));
    b.input(pubr.c, &bytes, 1);
    assert!(b.input_held(pubr.c));
    assert!(pubr.recv(&mut b).is_empty(), "the PINGREQ waits");
    flow_events(&mut b);
    // Keep-alive is 10 s: 1.5 x that later, a held connection is still open
    // (the subscriber, which is not held, pings).
    sub.send(&mut b, &Packet::PingReq, 19_999);
    b.tick(20_000);
    assert_eq!(b.close_requested(pubr.c), None);
    // Before the bound: still paused.
    b.poll_flow(PAUSE_MAX_MS);
    assert!(b.input_held(pubr.c));
    b.poll_flow(PAUSE_MAX_MS + 1);
    assert!(!b.input_held(pubr.c));
    assert_eq!(flow_events(&mut b), vec![(pubr.c, false)]);
    assert_eq!(pubr.recv(&mut b), vec![Got::PingResp]);
    let fs = b.flow_stats();
    assert_eq!((fs.pauses, fs.timeouts, fs.holding), (1, 1, 0));
    assert_eq!(fs.paused_ms, PAUSE_MAX_MS);
    assert!(b.stats().dropped_backpressure > 0);
    // The held time counted as alive.
    sub.send(&mut b, &Packet::PingReq, PAUSE_MAX_MS + 14_000);
    b.tick(PAUSE_MAX_MS + 1 + 14_000);
    assert_eq!(b.close_requested(pubr.c), None);
    // Cool-down: read and dropped, not paused.
    b.input(pubr.c, &flood("fleet/b", 100, 64), PAUSE_MAX_MS + 2);
    assert!(!b.input_held(pubr.c));
    // After it, paused again.
    let later = PAUSE_MAX_MS + 2 + COOLDOWN_MS;
    b.input(pubr.c, &flood("fleet/b", 100, 64), later);
    assert!(b.input_held(pubr.c));
    assert_eq!(b.flow_stats().pauses, 2);
    let _ = sub;
}

/// The recipient goes away: the publisher is released at once.
#[test]
fn the_recipient_leaving_ends_the_pause() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.input(pubr.c, &flood("fleet/b", 200, 64), 1);
    assert!(b.input_held(pubr.c));
    sub.kill(&mut b, 2);
    b.poll_flow(3);
    assert!(!b.input_held(pubr.c));
    assert_eq!(b.flow_stats().timeouts, 0);
    // The rest went to nobody.
    assert!(b.stats().dropped_offline == 0 && b.stats().published == 200);
}

/// The publisher goes away while paused: nothing of it is left.
#[test]
fn a_paused_publisher_closing_is_forgotten() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.input(pubr.c, &flood("fleet/b", 200, 64), 1);
    assert!(b.input_held(pubr.c));
    pubr.kill(&mut b, 2);
    assert!(flow_events(&mut b).is_empty());
    b.poll_flow(3);
    assert_eq!(b.flow_stats().holding, 0);
    let _ = sub.recv(&mut b);
}

/// The held bytes are parsed in slices of DRAIN_SLICE per pass, and the
/// window opens only once nothing complete is left.
#[test]
fn held_bytes_are_parsed_in_slices() {
    let mut b = Broker::new(Config {
        max_outbound_bytes: 1 << 20,
        ..flow_cfg()
    });
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    // 600 KiB fill the subscriber past 512 KiB, then 400 KiB more wait.
    let bytes = flood("fleet/b", 1000, 1000);
    b.input(pubr.c, &bytes, 1);
    assert!(b.input_held(pubr.c));
    sub.recv(&mut b);
    let mut passes = 0;
    while b.input_held(pubr.c) {
        b.poll_flow(2);
        passes += 1;
        let _ = sub.recv(&mut b);
        assert!(passes < 100);
    }
    assert!(passes >= 400 * 1024 / DRAIN_SLICE, "{passes} passes");
    assert_eq!(b.stats().dropped_backpressure, 0);
}

/// Several shards: a publisher whose messages another shard delivered within
/// REMOTE_SEEN_MS has a consumer this shard cannot see, and is not paused.
#[test]
fn a_consumer_on_another_shard_prevents_the_pause() {
    let mut b = Broker::new(Config {
        fanout: true,
        ..flow_cfg()
    });
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.note_remote_recipients(pubr.c, 1, 1, 1);
    b.input(pubr.c, &flood("fleet/b", 200, 64), 1);
    assert!(!b.input_held(pubr.c));
    let _ = b.drain_routes().count();
    let _ = sub.recv(&mut b);
    // No news from other shards for a while: paused.
    let now = 1 + REMOTE_SEEN_MS;
    b.input(pubr.c, &flood("fleet/b", 200, 64), now);
    assert!(b.input_held(pubr.c));
    // The routes carry the publisher.
    assert!(b.drain_routes().all(|(_, _, _, o)| o == Some(pubr.c)));
}

/// The input of a paused connection is bounded even if the transport does
/// not close its window: past HOLD_CONN (plus a packet), it is released into
/// cool-down.
#[test]
fn held_input_is_bounded_without_a_window() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut b, "a", 0);
    b.input(pubr.c, &flood("fleet/b", 100, 64), 1);
    assert!(b.input_held(pubr.c));
    let chunk = flood("fleet/b", 1000, 1000);
    for _ in 0..3 {
        b.input(pubr.c, &chunk, 2);
    }
    b.poll_flow(3);
    assert_eq!(b.flow_stats().timeouts, 1);
    while b.input_held(pubr.c) {
        b.poll_flow(3);
    }
    let _ = sub.recv(&mut b);
}

/// Two shards, as the kernel connects them: routes carry the publisher, the
/// receiving shard notes what it delivered and asks for pauses and resumes.
struct Mesh {
    a: Broker,
    b: Broker,
}

impl Mesh {
    fn new() -> Self {
        let c = Config {
            fanout: true,
            ..flow_cfg()
        };
        Self {
            a: Broker::new(c),
            b: Broker::new(c),
        }
    }

    /// Shard 0 (`a`) routes to shard 1 (`b`) and back, once.
    fn pump(&mut self, now: u64) {
        let routes: Vec<_> = self.a.drain_routes().collect();
        for (m, q, r, o) in routes {
            let n = self.b.route_remote_from(&m, q, r, o.map(|c| (0, c)), now);
            if let Some(c) = o {
                self.a.note_remote_recipients(c, 1, n as u32, now);
            }
        }
        let _ = self.b.drain_routes().count();
        let mut ev = Vec::new();
        self.b.drain_remote_flow(&mut ev);
        for (shard, c, full) in ev {
            assert_eq!(shard, 0);
            if full {
                self.a.remote_full(c, 1, now);
            } else {
                self.a.remote_drained(c, 1, now);
            }
        }
        self.a.poll_flow(now);
        self.b.poll_flow(now);
    }
}

/// The publisher on one shard, its only subscriber on another: the
/// subscriber's shard asks for the pause and for the resume. Messages
/// already accepted while the request travels can still be dropped; after
/// that none are, and everything accepted later arrives.
#[test]
fn a_single_subscriber_on_another_shard_pauses_the_publisher() {
    let mut m = Mesh::new();
    let (mut sub, _) = Client::connect_tls(&mut m.b, "b", 0);
    sub.subscribe(&mut m.b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut m.a, "a", 0);
    let mut sent = 0u32;
    let mut got = Vec::new();
    let mut paused_once = false;
    for now in 1..2000u64 {
        if !m.a.input_held(pubr.c) && sent < 600 {
            let mut chunk = flood("fleet/b", 10, 64);
            // Number them across chunks.
            let len = chunk.len() / 10;
            for i in 0..10 {
                let at = (i + 1) * len - 64;
                chunk[at..at + 4].copy_from_slice(&(sent + i as u32).to_be_bytes());
            }
            m.a.input(pubr.c, &chunk, now);
            sent += 10;
        }
        m.pump(now);
        paused_once |= m.a.input_held(pubr.c);
        // The subscriber reads every fifth tick.
        if now % 5 == 0 {
            got.extend(indexes(&sub.recv(&mut m.b)));
        }
        m.pump(now);
        if sent >= 600
            && !m.a.input_held(pubr.c)
            && got.len() as u64 + m.b.stats().dropped_backpressure >= 600
        {
            break;
        }
    }
    got.extend(indexes(&sub.recv(&mut m.b)));
    assert!(paused_once, "the publisher was never paused");
    assert!(m.a.flow_stats().pauses >= 1);
    let dropped = m.b.stats().dropped_backpressure;
    assert_eq!(got.len() as u64 + dropped, 600);
    assert_eq!(dropped, 0, "what was on its way fits the overshoot");
    assert_eq!(m.a.flow_stats().timeouts, 0);
    assert!(!m.a.input_held(pubr.c));
    // In order, whatever was dropped.
    assert!(got.windows(2).all(|w| w[0] < w[1]));
}

/// The publisher also has a subscriber on its own shard: a remote request
/// to pause it is refused (two consumers).
#[test]
fn a_remote_request_is_refused_with_a_local_subscriber() {
    let mut m = Mesh::new();
    let (mut sub, _) = Client::connect_tls(&mut m.b, "b", 0);
    sub.subscribe(&mut m.b, 1, &[("fleet/x", QoS::AtMostOnce)], 0);
    let (mut local, _) = Client::connect_tls(&mut m.a, "c", 0);
    local.subscribe(&mut m.a, 1, &[("fleet/x", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut m.a, "a", 0);
    for now in 1..50 {
        m.a.input(pubr.c, &flood("fleet/x", 10, 64), now);
        let _ = local.recv(&mut m.a);
        m.pump(now);
        assert!(!m.a.input_held(pubr.c));
    }
    assert_eq!(m.a.flow_stats().pauses, 0);
}

/// Subscribers on two other shards: the request of one is refused, since
/// the other also delivers the publisher's messages.
#[test]
fn a_remote_request_is_refused_when_a_third_shard_delivers_too() {
    let mut m = Mesh::new();
    let (mut sub, _) = Client::connect_tls(&mut m.b, "b", 0);
    sub.subscribe(&mut m.b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut m.a, "a", 0);
    // Shard 2 said it delivered them a moment ago.
    m.a.note_remote_recipients(pubr.c, 2, 1, 1);
    for now in 1..50 {
        m.a.input(pubr.c, &flood("fleet/b", 10, 64), now);
        m.pump(now);
        assert!(!m.a.input_held(pubr.c));
    }
    // Once shard 2 is quiet for a second, the request is honoured.
    let later = 1 + REMOTE_SEEN_MS;
    for now in later..later + 50 {
        m.a.input(pubr.c, &flood("fleet/b", 10, 64), now);
        m.pump(now);
    }
    assert!(m.a.flow_stats().pauses >= 1);
}

/// The subscriber on the other shard leaves: the publisher is told at once.
#[test]
fn a_remote_subscriber_leaving_releases_the_publisher() {
    let mut m = Mesh::new();
    let (mut sub, _) = Client::connect_tls(&mut m.b, "b", 0);
    sub.subscribe(&mut m.b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut m.a, "a", 0);
    let mut now = 1;
    while !m.a.input_held(pubr.c) {
        m.a.input(pubr.c, &flood("fleet/b", 10, 64), now);
        m.pump(now);
        now += 1;
        assert!(now < 100);
    }
    sub.kill(&mut m.b, now);
    m.pump(now);
    m.pump(now);
    assert!(!m.a.input_held(pubr.c));
    assert_eq!(m.a.flow_stats().timeouts, 0);
}

/// Across shards too: A (shard 0) publishes to B's subscription on shard 1
/// while B publishes to A's, neither reads; at no time are both held.
#[test]
fn across_shards_two_publishers_for_each_other_never_both_pause() {
    let mut m = Mesh::new();
    let (mut a, _) = Client::connect_tls(&mut m.a, "a", 0);
    a.subscribe(&mut m.a, 1, &[("fleet/a", QoS::AtMostOnce)], 0);
    let (mut b, _) = Client::connect_tls(&mut m.b, "b", 0);
    b.subscribe(&mut m.b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    for now in 1..120u64 {
        if !m.a.input_held(a.c) {
            m.a.input(a.c, &flood("fleet/b", 10, 64), now);
        }
        if !m.b.input_held(b.c) {
            m.b.input(b.c, &flood("fleet/a", 10, 64), now);
        }
        // Both directions of the mesh (b -> a first: `pump` discards b's routes).
        let routes: Vec<_> = m.b.drain_routes().collect();
        for (msg, q, r, o) in routes {
            let n = m.a.route_remote_from(&msg, q, r, o.map(|c| (1, c)), now);
            if let Some(c) = o {
                m.b.note_remote_recipients(c, 0, n as u32, now);
            }
        }
        let mut ev = Vec::new();
        m.a.drain_remote_flow(&mut ev);
        for (_, c, full) in ev {
            if full {
                m.b.remote_full(c, 0, now);
            } else {
                m.b.remote_drained(c, 0, now);
            }
        }
        m.pump(now);
        assert!(
            !(m.a.input_held(a.c) && m.b.input_held(b.c)),
            "both held at {now}"
        );
    }
    // Each was paused at some point: the test exercised the requests.
    assert!(m.a.flow_stats().pauses + m.b.flow_stats().pauses >= 1);
}

/// What a waited-for subscriber takes beyond its buffer is bounded: a
/// publisher shard that never stops (its pause refused, the request lost)
/// fills it to OVERSHOOT past `max_outbound_bytes`, then the rest is dropped.
#[test]
fn the_overshoot_of_a_waited_subscriber_is_bounded() {
    let mut m = Mesh::new();
    let (mut sub, _) = Client::connect_tls(&mut m.b, "b", 0);
    sub.subscribe(&mut m.b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (pubr, _) = Client::connect_tls(&mut m.a, "a", 0);
    let mut fed = 0;
    for now in 1..20u64 {
        m.a.input(pubr.c, &flood("fleet/b", 50, 1000), now);
        // Routes go to b; b's requests are never delivered to a.
        let routes: Vec<_> = m.a.drain_routes().collect();
        for (msg, q, r, o) in routes {
            m.b.route_remote_from(&msg, q, r, o.map(|c| (0, c)), now);
            fed += 1;
        }
    }
    assert_eq!(fed, 950);
    let max = flow_cfg().max_outbound_bytes + crate::flow::OVERSHOOT + 1100;
    assert!(
        m.b.output(sub.c).len() <= max,
        "{}",
        m.b.output(sub.c).len()
    );
    assert!(m.b.stats().dropped_backpressure > 0);
    assert!(!m.a.input_held(pubr.c));
}

/// QoS 2 (ADR-271) is never paused for: a QoS 2 delivery has its window and
/// its four-way handshake, as QoS 1.
#[test]
fn qos2_deliveries_are_not_paused_for() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::ExactlyOnce)], 0);
    let (mut pubr, _) = Client::connect_tls(&mut b, "a", 0);
    for i in 0..200u16 {
        pubr.send(
            &mut b,
            &Packet::Publish(Publish {
                dup: false,
                qos: QoS::ExactlyOnce,
                retain: false,
                topic: "fleet/b",
                packet_id: Some(i + 1),
                payload: &[0; 64],
            }),
            1,
        );
        pubr.send(&mut b, &Packet::PubRel(i + 1), 1);
    }
    assert!(!b.input_held(pubr.c));
    assert_eq!(b.flow_stats().pauses, 0);
    let got = pubr.recv(&mut b);
    assert_eq!(
        got.iter().filter(|g| matches!(g, Got::PubComp(_))).count(),
        200
    );
}

/// A paused publisher's own QoS 2 flows complete once the pause ends, within
/// its bound: the PUBREL of a message it published and the PUBREC of one it
/// was sent wait in the held bytes with its other packets, at most 500 ms.
#[test]
fn qos2_flows_of_a_paused_publisher_complete_after_the_pause() {
    let mut b = Broker::new(flow_cfg());
    let (mut sub, _) = Client::connect_tls(&mut b, "b", 0);
    sub.subscribe(&mut b, 1, &[("fleet/b", QoS::AtMostOnce)], 0);
    let (mut pubr, _) = Client::connect_tls(&mut b, "a", 0);
    pubr.subscribe(&mut b, 2, &[("fleet/a", QoS::ExactlyOnce)], 0);
    let (other, _) = Client::connect_tls(&mut b, "c", 0);
    // a publishes at QoS 2 (id 9): PUBREC comes back at once.
    pubr.send(
        &mut b,
        &Packet::Publish(Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            topic: "fleet/x",
            packet_id: Some(9),
            payload: b"q2",
        }),
        1,
    );
    assert_eq!(pubr.recv(&mut b), vec![Got::PubRec(9)]);
    // c sends a QoS 2 message to a: a gets it with an id of the broker's.
    other.send(
        &mut b,
        &Packet::Publish(Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            topic: "fleet/a",
            packet_id: Some(1),
            payload: b"to-a",
        }),
        1,
    );
    other.send(&mut b, &Packet::PubRel(1), 1);
    let to_a = pubr
        .recv(&mut b)
        .into_iter()
        .find_map(|g| match g {
            Got::Publish { pid: Some(p), .. } => Some(p),
            _ => None,
        })
        .unwrap();
    // a floods b, then sends its PUBREL (9) and its PUBREC (to_a): held.
    let mut bytes = flood("fleet/b", 300, 64);
    bytes.extend(wire(&Packet::PubRel(9)));
    bytes.extend(wire(&Packet::PubRec(to_a)));
    b.input(pubr.c, &bytes, 2);
    assert!(b.input_held(pubr.c));
    assert!(pubr.recv(&mut b).is_empty(), "nothing answered while held");
    // The subscriber never reads: the bound ends the pause.
    b.poll_flow(2 + PAUSE_MAX_MS);
    while b.input_held(pubr.c) {
        b.poll_flow(2 + PAUSE_MAX_MS);
    }
    let got = pubr.recv(&mut b);
    assert!(got.contains(&Got::PubComp(9)), "{got:?}");
    assert!(got.contains(&Got::PubRel(to_a)), "{got:?}");
    // a completes the outbound flow.
    pubr.send(&mut b, &Packet::PubComp(to_a), 3);
    assert_eq!(b.close_requested(pubr.c), None);
}
