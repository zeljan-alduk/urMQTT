//! virtio-balloon against a hostile device (ADR-258): the device changes
//! `num_pages` to anything, returns the statistics buffer or completions
//! for heads it never had. The policy holds whatever it does: `actual`
//! stays 0, nothing is ever put on the inflate queue, and the statistics
//! sent never claim more free or available memory than the total.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::F_VERSION_1;
use urmqtt_virtio::balloon::{
    CFG_ACTUAL, CFG_NUM_PAGES, F_STATS_VQ, MemStats, STAT_LEN, VirtioBalloon,
};
use urmqtt_virtio::bus::Bus;
use urmqtt_virtio::fake::{FakeBus, FakeEnv};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let offered = F_VERSION_1 | if flags & 1 != 0 { F_STATS_VQ } else { 0 };
    let bus = FakeBus::new(offered, &[2, 2, 2], 8);
    let env = FakeEnv::default();
    let mut s = MemStats {
        total: 512 << 20,
        free: 100 << 20,
        available: 90 << 20,
    };
    let Ok(mut b) = VirtioBalloon::new(&bus, &env, &s) else {
        return;
    };
    for op in rest.chunks(5) {
        let [kind, a, b1, c, d] = [0, 1, 2, 3, 4].map(|i| op.get(i).copied().unwrap_or(0));
        match kind % 4 {
            0 => bus.set_cfg(CFG_NUM_PAGES, &[a, b1, c, d]),
            1 => match bus.pop(2) {
                Some((head, segs)) => {
                    let st = FakeBus::read(&segs);
                    for e in st.chunks(STAT_LEN) {
                        let v = u64::from_le_bytes(e[2..10].try_into().unwrap_or([0; 8]));
                        assert!(v <= s.total.max(1 << 40));
                    }
                    bus.complete(2, u32::from(head), 0);
                }
                None => bus.complete(2, u32::from(a), u32::from(b1)),
            },
            2 => {
                s.free = u64::from_le_bytes([a, b1, c, d, 0, 0, 0, 0]) << 8;
                s.available = s.free / 2;
            }
            _ => {
                b.poll(&s);
            }
        }
        assert_eq!(bus.cfg_read32(CFG_ACTUAL), 0);
        assert!(bus.pop(0).is_none(), "the balloon never inflates");
    }
});
