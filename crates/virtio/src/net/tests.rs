//! Host tests of the virtio-net driver against the fake device (ADR-310).

use super::*;
use crate::fake::{FakeBus, FakeEnv};
use crate::queue::QueueError;

const MQ_ALL: u64 = F_MQ | F_CTRL_VQ | F_RSS;

/// A device configuration: MAC, status (link up), and the multiqueue/RSS
/// fields of §5.1.4.
fn cfg(bus: &FakeBus, max_pairs: u16, key: u8, table: u16, hash: u32) {
    bus.set_cfg(0, &[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    bus.set_cfg(CFG_STATUS, &1u16.to_le_bytes());
    bus.set_cfg(CFG_MAX_PAIRS, &max_pairs.to_le_bytes());
    bus.set_cfg(CFG_RSS_MAX_KEY, &[key]);
    bus.set_cfg(CFG_RSS_MAX_TABLE, &table.to_le_bytes());
    bus.set_cfg(CFG_HASH_TYPES, &hash.to_le_bytes());
}

/// A device with `pairs` queue pairs plus the control queue, 256 entries each.
fn device(offered: u64, pairs: u16) -> FakeBus {
    let queues = vec![256u16; usize::from(2 * pairs + 1)];
    let bus = FakeBus::new(F_VERSION_1 | F_MAC | F_STATUS | offered, &queues, 24);
    cfg(&bus, pairs, 40, 128, HASH_TCPV4 | 1);
    bus
}

fn table(active: u16) -> [u16; RSS_TABLE_LEN] {
    core::array::from_fn(|i| (i % usize::from(active)) as u16)
}

/// Answers every RSS command on the control queue with `ack`, recording the
/// command bytes.
fn answer(bus: &FakeBus, ack: u8, seen: std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>) {
    *bus.responder.borrow_mut() = Some(Box::new(move |b: &FakeBus, q: u16| {
        let ctrl = b.queue_max.len() as u16 - 1;
        if q != ctrl {
            return;
        }
        while let Some((head, segs)) = b.pop(q) {
            seen.borrow_mut().push(FakeBus::read(&segs));
            let n = FakeBus::fill(&segs, &[ack]);
            b.complete(q, u32::from(head), n);
        }
    }));
}

/// Delivers `frame` on receive queue `rx` (with the 12-byte header).
fn deliver(bus: &FakeBus, rx: u16, frame: &[u8]) {
    let (head, segs) = bus.pop(rx).unwrap();
    let mut data = vec![0u8; HDR_LEN];
    data.extend_from_slice(frame);
    let n = FakeBus::fill(&segs, &data);
    bus.complete(rx, u32::from(head), n);
}

#[test]
fn one_pair_is_driven_as_before_and_negotiates_nothing_new() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 4);
    let mut net = VirtioNet::new(&bus, &env).unwrap();
    // One pair asked for: MQ, the control queue and RSS stay off even though
    // the device offers them.
    assert_eq!(bus.accepted.get() & MQ_ALL, 0);
    assert_eq!(
        (net.pairs, net.active, net.single),
        (1, 1, Some(Single::NotAsked))
    );
    assert_eq!(net.mac, [0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    assert!(net.link_up());
    // Only pair 0 is set up; the posted receive buffers were announced.
    let qs = bus.queues.borrow().clone();
    assert!(qs[0].enabled && qs[1].enabled && !qs[2].enabled && !qs[8].enabled);
    assert_eq!(bus.notified.borrow().as_slice(), &[0]);
    deliver(&bus, 0, b"hello frame");
    let mut out = [0u8; MTU_FRAME];
    assert!(net.rx_pending());
    assert_eq!(net.recv(&mut out).unwrap(), Some(11));
    assert_eq!(&out[..11], b"hello frame");
    assert_eq!(net.recv(&mut out).unwrap(), None);
    net.queue(&[7u8; 100]).unwrap();
    net.flush();
    let (_, segs) = bus.pop(1).unwrap();
    let sent = FakeBus::read(&segs);
    assert_eq!(sent.len(), HDR_LEN + 100);
    assert_eq!((net.stats.received, net.stats.sent), (1, 1));
    assert!(net.take_queue(1).is_none());
}

#[test]
fn plan_checks_every_field_the_device_gives() {
    let ok = DeviceLimits {
        max_pairs: 4,
        rss_max_key: 40,
        rss_max_table: 128,
        hash_types: HASH_TCPV4,
    };
    assert_eq!(plan(MQ_ALL, ok, 4), Ok(4));
    assert_eq!(plan(MQ_ALL, ok, 8), Ok(4), "capped by the device");
    let many = DeviceLimits {
        max_pairs: 64,
        ..ok
    };
    assert_eq!(
        plan(MQ_ALL, many, 64),
        Ok(MAX_PAIRS),
        "capped by the driver"
    );
    assert_eq!(plan(MQ_ALL, ok, 1), Err(Single::NotAsked));
    assert_eq!(plan(MQ_ALL, ok, 0), Err(Single::NotAsked));
    assert_eq!(plan(F_CTRL_VQ | F_RSS, ok, 4), Err(Single::NoMq));
    assert_eq!(plan(F_MQ | F_CTRL_VQ, ok, 4), Err(Single::NoRss));
    assert_eq!(plan(F_MQ | F_RSS, ok, 4), Err(Single::NoRss));
    for bad in [0u16, 1, 0x8001, u16::MAX] {
        let l = DeviceLimits {
            max_pairs: bad,
            ..ok
        };
        assert_eq!(plan(MQ_ALL, l, 4), Err(Single::OnePair), "max_pairs {bad}");
    }
    for l in [
        DeviceLimits {
            rss_max_key: 39,
            ..ok
        },
        DeviceLimits {
            rss_max_table: 64,
            ..ok
        },
        DeviceLimits {
            hash_types: !HASH_TCPV4,
            ..ok
        },
    ] {
        assert_eq!(plan(MQ_ALL, l, 4), Err(Single::RssLimits), "{l:?}");
    }
}

#[test]
fn the_rss_command_is_laid_out_as_the_specification_says() {
    let key: [u8; RSS_KEY_LEN] = core::array::from_fn(|i| i as u8 + 1);
    let t = table(3);
    let c = rss_command(&t, 3, &key, HASH_TCPV4);
    assert_eq!(c.len(), 2 + 4 + 2 + 2 + 256 + 2 + 1 + 40);
    assert_eq!(&c[..2], &[4, 1], "VIRTIO_NET_CTRL_MQ, _RSS_CONFIG");
    assert_eq!(&c[2..6], &HASH_TCPV4.to_le_bytes());
    assert_eq!(&c[6..8], &127u16.to_le_bytes(), "indirection_table_mask");
    assert_eq!(&c[8..10], &0u16.to_le_bytes(), "unclassified_queue");
    for i in 0..RSS_TABLE_LEN {
        let at = 10 + 2 * i;
        assert_eq!(u16::from_le_bytes([c[at], c[at + 1]]), (i % 3) as u16);
    }
    assert_eq!(&c[266..268], &3u16.to_le_bytes(), "max_tx_vq");
    assert_eq!(c[268], 40, "hash_key_length");
    assert_eq!(&c[269..], &key);
}

/// NEXT-1, ADR-333: a device that offers TCP/IPv6 hashing is asked for it
/// beside TCP/IPv4 (and for nothing else it offers), so IPv6 flows land on
/// their core's pair as IPv4 ones do.
#[test]
fn tcp_ipv6_hashing_is_asked_for_where_offered() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 4);
    cfg(&bus, 4, 40, 128, HASH_TCPV4 | HASH_TCPV6 | 1 | (1 << 3));
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    answer(&bus, 0, seen.clone());
    let mut net = VirtioNet::new_multi(&bus, &env, 4, Some).unwrap();
    let key = [0x6d; RSS_KEY_LEN];
    net.enable_rss(&env, &table(4), 4, &key).unwrap();
    let c = &seen.borrow()[0];
    assert_eq!(&c[2..6], &(HASH_TCPV4 | HASH_TCPV6).to_le_bytes());
    assert_eq!(
        c,
        &rss_command(&table(4), 4, &key, HASH_TCPV4 | HASH_TCPV6).to_vec()
    );
}

#[test]
fn four_pairs_with_rss_hand_out_their_queues() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 4);
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    answer(&bus, 0, seen.clone());
    let mut net = VirtioNet::new_multi(&bus, &env, 4, Some).unwrap();
    assert_eq!(bus.accepted.get() & MQ_ALL, MQ_ALL);
    assert_eq!((net.pairs, net.active, net.single), (4, 1, None));
    assert_eq!(net.limits.max_pairs, 4);
    // Every queue of the four pairs and the control queue (index 8).
    assert!(bus.queues.borrow().iter().all(|q| q.enabled));
    // Before RSS, no pair leaves the driver.
    assert!(net.take_queue(1).is_none());
    let key = [0x6d; RSS_KEY_LEN];
    net.enable_rss(&env, &table(4), 4, &key).unwrap();
    assert_eq!((net.active, net.single), (4, None));
    assert_eq!(seen.borrow().len(), 1);
    assert_eq!(
        seen.borrow()[0],
        rss_command(&table(4), 4, &key, HASH_TCPV4).to_vec(),
        "the device offers no TCP/IPv6 hashing: only TCP/IPv4 is asked for"
    );
    let mut q2 = net.take_queue(2).unwrap();
    assert_eq!(q2.pair, 2);
    assert!(q2.rx_irq);
    assert!(net.take_queue(2).is_none(), "taken once");
    assert!(net.take_queue(4).is_none() && net.take_queue(0).is_none());
    // The taken pair receives on queue 4 and transmits on queue 5, with its
    // own doorbell.
    deliver(&bus, 4, &[9u8; 64]);
    let mut out = [0u8; MTU_FRAME];
    assert_eq!(q2.recv(&mut out).unwrap(), Some(64));
    q2.queue(&[1u8; 60]).unwrap();
    bus.notified.borrow_mut().clear();
    q2.flush();
    assert_eq!(bus.notified.borrow().as_slice(), &[5, 4]);
    assert!(bus.pop(5).is_some());
    assert!(bus.pop(1).is_none(), "nothing on pair 0's transmit queue");
    assert_eq!(
        q2.stats,
        QueueStats {
            received: 1,
            sent: 1,
            tx_full: 0
        }
    );
}

#[test]
fn a_refusal_or_silence_leaves_one_pair() {
    for ack in [Some(1u8), Some(0xff), None] {
        let env = FakeEnv::default();
        let bus = device(MQ_ALL, 2);
        if let Some(a) = ack {
            answer(&bus, a, std::rc::Rc::default());
        }
        let mut net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
        assert_eq!(net.pairs, 2);
        assert_eq!(
            net.enable_rss(&env, &table(2), 2, &[0; RSS_KEY_LEN]),
            Err(Single::Refused),
            "ack {ack:?}"
        );
        assert_eq!((net.active, net.single), (1, Some(Single::Refused)));
        assert!(net.take_queue(1).is_none());
        // Pair 0 still works.
        deliver(&bus, 0, &[1u8; 70]);
        let mut out = [0u8; MTU_FRAME];
        assert_eq!(net.recv(&mut out).unwrap(), Some(70));
    }
}

#[test]
fn an_answer_for_another_chain_or_without_the_byte_is_a_refusal() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 2);
    *bus.responder.borrow_mut() = Some(Box::new(|b: &FakeBus, q: u16| {
        if q == 4
            && let Some((head, _)) = b.pop(q)
        {
            // OK written nowhere: zero bytes reported.
            b.complete(q, u32::from(head), 0);
        }
    }));
    let mut net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
    assert_eq!(
        net.enable_rss(&env, &table(2), 2, &[0; RSS_KEY_LEN]),
        Err(Single::Refused)
    );
    let bus = device(MQ_ALL, 2);
    *bus.responder.borrow_mut() = Some(Box::new(|b: &FakeBus, q: u16| {
        if q == 4
            && let Some((head, segs)) = b.pop(q)
        {
            FakeBus::fill(&segs, &[0]);
            // An id that is not the head the driver posted.
            b.complete(q, u32::from(head) + 1, 1);
        }
    }));
    let mut net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
    assert_eq!(
        net.enable_rss(&env, &table(2), 2, &[0; RSS_KEY_LEN]),
        Err(Single::Refused)
    );
}

#[test]
fn a_table_that_names_a_pair_not_in_use_is_never_sent() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 4);
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    answer(&bus, 0, seen.clone());
    let mut net = VirtioNet::new_multi(&bus, &env, 4, |_| None).unwrap();
    assert_eq!(
        net.enable_rss(&env, &table(4), 3, &[0; RSS_KEY_LEN]),
        Err(Single::NotAsked)
    );
    assert_eq!(
        net.enable_rss(&env, &table(1), 1, &[0; RSS_KEY_LEN]),
        Err(Single::NotAsked)
    );
    assert!(seen.borrow().is_empty());
}

#[test]
fn fewer_pairs_than_asked_and_devices_without_rss() {
    let env = FakeEnv::default();
    // Asked for 4, the device has 2.
    let bus = device(MQ_ALL, 2);
    let net = VirtioNet::new_multi(&bus, &env, 4, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (2, None));
    // Multiqueue without RSS: one pair, and why.
    let bus = device(F_MQ | F_CTRL_VQ, 4);
    let net = VirtioNet::new_multi(&bus, &env, 4, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::NoRss)));
    assert!(!bus.queues.borrow()[2].enabled);
    // No MQ at all: the device's configuration is not even read.
    let bus = FakeBus::new(F_VERSION_1 | F_MAC, &[256, 256], 6);
    let net = VirtioNet::new_multi(&bus, &env, 4, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::NoMq)));
    assert_eq!(net.limits, DeviceLimits::default());
    // QEMU's user network with mq=on: MQ and RSS offered, one pair.
    let bus = device(MQ_ALL, 1);
    let net = VirtioNet::new_multi(&bus, &env, 4, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::OnePair)));
}

#[test]
fn a_second_pair_that_cannot_be_set_up_leaves_one() {
    let env = FakeEnv::default();
    let mut bus = device(MQ_ALL, 3);
    // Pair 2's transmit queue is absent.
    bus.queue_max[5] = 0;
    let net = VirtioNet::new_multi(&bus, &env, 3, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::QueueSetup)));
    // The control queue is absent.
    let mut bus = device(MQ_ALL, 2);
    bus.queue_max[4] = 0;
    let net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::QueueSetup)));
    // max_virtqueue_pairs = 0x8000 (the specification's maximum): the control
    // queue would be queue 0x10000, which no 16-bit queue number names; it
    // must not wrap to queue 0 (pair 0's receive queue, already set up).
    assert_eq!(ctrl_index(0x8000), None);
    assert_eq!(ctrl_index(0x7fff), Some(0xfffe));
    let bus = device(MQ_ALL, 2);
    cfg(&bus, 0x8000, 40, 128, HASH_TCPV4);
    let mut net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
    assert_eq!((net.pairs, net.single), (1, Some(Single::QueueSetup)));
    assert!(!bus.queues.borrow()[2].enabled, "no pair set up for it");
    assert!(net.take_queue(1).is_none());
    deliver(&bus, 0, &[3u8; 64]);
    let mut out = [0u8; MTU_FRAME];
    assert_eq!(net.recv(&mut out).unwrap(), Some(64));
    // Pair 0 itself absent is an error, as before.
    let mut bus = device(0, 1);
    bus.queue_max[0] = 0;
    assert!(VirtioNet::new(&bus, &env).is_err());
}

#[test]
fn hostile_used_entries_on_a_taken_queue_fail_closed() {
    let env = FakeEnv::default();
    let bus = device(MQ_ALL, 2);
    answer(&bus, 0, std::rc::Rc::default());
    let mut net = VirtioNet::new_multi(&bus, &env, 2, |_| None).unwrap();
    net.enable_rss(&env, &table(2), 2, &[0; RSS_KEY_LEN])
        .unwrap();
    let mut q = net.take_queue(1).unwrap();
    // An id beyond the queue.
    bus.complete(2, 9999, 60);
    let mut out = [0u8; MTU_FRAME];
    assert_eq!(
        q.recv(&mut out),
        Err(VirtioError::Queue(QueueError::DeviceProtocol))
    );
    // A length beyond the buffer is cut to the buffer.
    let bus = device(MQ_ALL, 1);
    let mut net = VirtioNet::new(&bus, &env).unwrap();
    let (head, _) = bus.pop(0).unwrap();
    bus.complete(0, u32::from(head), u32::MAX);
    assert_eq!(net.recv(&mut out).unwrap(), Some(MTU_FRAME));
}

#[test]
fn a_full_transmit_queue_is_counted() {
    let env = FakeEnv::default();
    let bus = FakeBus::new(F_VERSION_1 | F_MAC, &[4, 4], 6);
    let mut net = VirtioNet::new(&bus, &env).unwrap();
    for _ in 0..4 {
        net.queue(&[0u8; 60]).unwrap();
    }
    assert!(net.queue(&[0u8; 60]).is_err());
    assert_eq!((net.tx_full, net.stats.tx_full, net.stats.sent), (1, 1, 4));
    assert_eq!(
        net.queue(&[0u8; MTU_FRAME + 1]),
        Err(VirtioError::OutOfRange)
    );
}
