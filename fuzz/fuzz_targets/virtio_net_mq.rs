//! virtio-net's multiqueue bring-up against a hostile device (NEXT-6,
//! ADR-310): any offered features, any multiqueue and RSS configuration
//! fields, queues of any size or absent, any answer to the RSS command (none,
//! a refusal, a wrong head, no byte written), then completions on any queue
//! for any head and length. Whatever it does: the pairs set up never exceed
//! what was asked, the driver's limit or what the device said; a pair leaves
//! the driver only after the device accepted the table; received frames
//! never exceed the buffer; nothing panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::F_VERSION_1;
use urmqtt_virtio::fake::{FakeBus, FakeEnv};
use urmqtt_virtio::net::{
    F_CTRL_VQ, F_MAC, F_MQ, F_RSS, F_STATUS, MAX_PAIRS, MTU_FRAME, RSS_KEY_LEN, RSS_TABLE_LEN,
    VirtioNet, ctrl_index,
};

fuzz_target!(|data: &[u8]| {
    let mut it = data.iter().copied();
    let mut next = || it.next().unwrap_or(0);
    let flags = next();
    let mut offered = F_VERSION_1 | F_MAC | F_STATUS;
    for (bit, f) in [(1u8, F_MQ), (2, F_CTRL_VQ), (4, F_RSS)] {
        if flags & bit != 0 {
            offered |= f;
        }
    }
    let want = usize::from(next() % 20);
    // Mostly small, sometimes anything (0x8000 and above: a control queue
    // index that does not fit 16 bits).
    let (lo, hi) = (next(), next());
    let max_pairs = u16::from_le_bytes([lo, if hi & 0x80 != 0 { hi } else { hi % 4 }]);
    let key = next();
    let table_max = u16::from_le_bytes([next(), next()]);
    let hash = u32::from_le_bytes([next(), next(), next(), next()]);
    // Queues of the device: 2 per pair up to 18 pairs and the control queue
    // where its max_pairs says; sizes from the input (0: absent).
    let nq = usize::from(next() % 40) + 2;
    let queues: Vec<u16> = (0..nq)
        .map(|_| match next() % 5 {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 256,
            _ => 1024,
        })
        .collect();
    let bus = FakeBus::new(offered, &queues, 24);
    bus.set_cfg(8, &max_pairs.to_le_bytes());
    bus.set_cfg(17, &[key]);
    bus.set_cfg(18, &table_max.to_le_bytes());
    bus.set_cfg(20, &hash.to_le_bytes());
    let ack_mode = next() % 4;
    let ack = next();
    let ctrl = ctrl_index(max_pairs);
    *bus.responder.borrow_mut() = Some(Box::new(move |b: &FakeBus, q: u16| {
        if Some(q) != ctrl || ack_mode == 0 {
            return;
        }
        while let Some((head, segs)) = b.pop(q) {
            match ack_mode {
                1 => {
                    let n = FakeBus::fill(&segs, &[ack]);
                    b.complete(q, u32::from(head), n);
                }
                2 => b.complete(q, u32::from(head) ^ 1, 1),
                _ => b.complete(q, u32::from(head), 0),
            }
        }
    }));
    let env = FakeEnv::default();
    let Ok(mut net) = VirtioNet::new_multi(&bus, &env, want, |k| (k % 2 == 0).then_some(k)) else {
        return;
    };
    let pairs = usize::from(net.pairs);
    assert!(pairs >= 1 && pairs <= MAX_PAIRS);
    if pairs > 1 {
        assert!(pairs <= want && pairs <= usize::from(max_pairs));
        assert!(offered & (F_MQ | F_CTRL_VQ | F_RSS) == F_MQ | F_CTRL_VQ | F_RSS);
        assert!(usize::from(key) >= RSS_KEY_LEN && usize::from(table_max) >= RSS_TABLE_LEN);
        assert!(net.single.is_none());
        assert!(ctrl.is_some(), "a control queue index that fits 16 bits");
    }
    assert!(net.take_queue(1).is_none(), "no pair leaves before RSS");
    let active = u16::from(next() % 18);
    let table: [u16; RSS_TABLE_LEN] =
        core::array::from_fn(|i| (i as u16).wrapping_mul(u16::from(next())) % active.max(1));
    let accepted = net
        .enable_rss(&env, &table, active, &[0x6d; RSS_KEY_LEN])
        .is_ok();
    if accepted {
        assert!(ack_mode == 1 && ack == 0 && active >= 2 && usize::from(active) <= pairs);
        assert_eq!(net.active, active);
    } else {
        assert_eq!(net.active, 1);
        assert!(net.take_queue(1).is_none());
    }
    let mut taken: Vec<_> = (1..net.active).filter_map(|k| net.take_queue(k)).collect();
    assert_eq!(taken.len(), usize::from(net.active) - 1);
    let mut out = [0u8; MTU_FRAME];
    for _ in 0..64 {
        let op = next();
        let q = u16::from(next()) % (nq as u16);
        let head = u32::from(next()) | u32::from(next() & 3) << 8;
        let len = u32::from_le_bytes([next(), next(), 0, 0]);
        match op % 4 {
            0 => bus.complete(q, head, len),
            1 => {
                if let Some((h, segs)) = bus.pop(q) {
                    let n = FakeBus::fill(&segs, &[0xab; 100]);
                    bus.complete(q, u32::from(h), n.max(len % 3000));
                }
            }
            2 => {
                if let Ok(Some(n)) = net.recv(&mut out) {
                    assert!(n <= MTU_FRAME);
                }
                let _ = net.queue(&out[..usize::from(next()) * 6 % (MTU_FRAME + 1)]);
                net.flush();
            }
            _ => {
                let i = usize::from(next()) % taken.len().max(1);
                if let Some(t) = taken.get_mut(i) {
                    if let Ok(Some(n)) = t.recv(&mut out) {
                        assert!(n <= MTU_FRAME);
                    }
                    let _ = t.queue(&out[..60]);
                    t.flush();
                }
            }
        }
    }
});
