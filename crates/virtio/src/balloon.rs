//! virtio-balloon, the traditional memory balloon (virtio 1.x §5.5), with
//! a fixed policy (ADR-258): **never inflate**, report memory statistics.
//!
//! The kernel's heap is sized once at boot and is not page-granular towards
//! the allocator of the frames under it, so there are no pages it could give
//! back without risking the broker: a host request to inflate
//! (`num_pages`) is recorded and logged, and `actual` stays 0. What the host
//! does get is real numbers: with `VIRTIO_BALLOON_F_STATS_VQ` the driver
//! answers every statistics request with the total, free and available
//! memory. `F_DEFLATE_ON_OOM`, `F_FREE_PAGE_HINT`, `F_PAGE_POISON` and
//! `F_PAGE_REPORTING` are not negotiated (free page reporting would need the
//! allocator to hand whole free pages to the device and take them back on
//! use, which ours does not do): not implemented.

use crate::bus::{Bus, dma_write, make_queue};
use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::{Env, F_VERSION_1, VirtioError};

pub const F_MUST_TELL_HOST: u64 = 1 << 0;
pub const F_STATS_VQ: u64 = 1 << 1;
pub const F_DEFLATE_ON_OOM: u64 = 1 << 2;
pub const F_FREE_PAGE_HINT: u64 = 1 << 3;
pub const F_PAGE_POISON: u64 = 1 << 4;
pub const F_PAGE_REPORTING: u64 = 1 << 5;

// Statistics tags (§5.5.6.3).
pub const STAT_SWAP_IN: u16 = 0;
pub const STAT_SWAP_OUT: u16 = 1;
pub const STAT_MAJFLT: u16 = 2;
pub const STAT_MINFLT: u16 = 3;
pub const STAT_MEMFREE: u16 = 4;
pub const STAT_MEMTOT: u16 = 5;
pub const STAT_AVAIL: u16 = 6;
pub const STAT_CACHES: u16 = 7;

/// Configuration: `num_pages` (device), `actual` (driver), both le32.
pub const CFG_NUM_PAGES: usize = 0;
pub const CFG_ACTUAL: usize = 4;
/// The balloon's page unit.
pub const PAGE: u64 = 4096;

const INFLATEQ: u16 = 0;
const DEFLATEQ: u16 = 1;
const STATSQ: u16 = 2;
/// One statistics entry: tag le16, value le64.
pub const STAT_LEN: usize = 10;
/// Entries we report.
pub const STATS: usize = 3;

/// What the kernel reports, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemStats {
    pub total: u64,
    pub free: u64,
    pub available: u64,
}

/// The statistics buffer as the device reads it. `free` and `available`
/// never exceed `total` (a kernel bug must not tell the host nonsense).
pub fn encode_stats(s: &MemStats, out: &mut [u8; STATS * STAT_LEN]) {
    let free = s.free.min(s.total);
    let entries = [
        (STAT_MEMTOT, s.total),
        (STAT_MEMFREE, free),
        (STAT_AVAIL, s.available.min(s.total)),
    ];
    for (i, (tag, v)) in entries.iter().enumerate() {
        if let Some(e) = out.get_mut(i * STAT_LEN..(i + 1) * STAT_LEN) {
            if let Some(t) = e.get_mut(..2) {
                t.copy_from_slice(&tag.to_le_bytes());
            }
            if let Some(x) = e.get_mut(2..) {
                x.copy_from_slice(&v.to_le_bytes());
            }
        }
    }
}

/// The policy's answer to the device's `num_pages`: how many pages the
/// balloon holds afterwards. Always 0: nothing is ever given away.
pub const fn pages_to_hold(_num_pages: u32) -> u32 {
    0
}

pub struct VirtioBalloon<B: Bus> {
    bus: B,
    // Kept for the device's sake (it expects them set up); never used.
    _inflate: (SplitQueue, usize),
    _deflate: (SplitQueue, usize),
    stats: Option<(SplitQueue, usize, DmaRegion)>,
    /// The device's last `num_pages`.
    pub requested: u32,
    /// Statistics answers sent.
    pub stats_sent: u64,
    pub protocol_errors: u64,
}

impl<B: Bus> VirtioBalloon<B> {
    pub fn new<E: Env>(bus: B, env: &E, now: &MemStats) -> Result<Self, VirtioError> {
        let f = bus.init(env, F_STATS_VQ, F_VERSION_1)?;
        let inflate = make_queue(&bus, env, INFLATEQ, 2)?;
        let deflate = make_queue(&bus, env, DEFLATEQ, 2)?;
        let stats = if f & F_STATS_VQ != 0 {
            let (q, off) = make_queue(&bus, env, STATSQ, 2)?;
            let mem = env.dma_alloc(STATS * STAT_LEN).ok_or(VirtioError::NoDma)?;
            Some((q, off, mem))
        } else {
            None
        };
        bus.cfg_write32(CFG_ACTUAL, pages_to_hold(0));
        let mut b = Self {
            requested: 0,
            bus,
            _inflate: inflate,
            _deflate: deflate,
            stats,
            stats_sent: 0,
            protocol_errors: 0,
        };
        b.bus.driver_ok()?;
        // The first buffer is there from the start (§5.5.6.3): the device
        // takes it and gives it back when it wants fresh numbers.
        b.send_stats(now)?;
        b.requested = b.bus.cfg_read32(CFG_NUM_PAGES);
        Ok(b)
    }

    pub fn has_stats(&self) -> bool {
        self.stats.is_some()
    }

    fn send_stats(&mut self, now: &MemStats) -> Result<(), VirtioError> {
        let Some((q, off, mem)) = self.stats.as_mut() else {
            return Ok(());
        };
        let mut buf = [0u8; STATS * STAT_LEN];
        encode_stats(now, &mut buf);
        if !dma_write(mem, 0, &buf) {
            return Err(VirtioError::NoDma);
        }
        q.add(&[Buf {
            pa: mem.pa,
            len: buf.len() as u32,
            device_writes: false,
        }])?;
        let off = *off;
        self.bus.notify(off, STATSQ);
        self.stats_sent += 1;
        Ok(())
    }

    /// Answers a statistics request if the device made one, and reads the
    /// host's target. Returns the new `num_pages` when it changed (for the
    /// log: the request is never acted on).
    pub fn poll(&mut self, now: &MemStats) -> Option<u32> {
        let wants = match self.stats.as_mut().map(|(q, _, _)| q.pop_used()) {
            Some(Ok(Some(_))) => true,
            Some(Err(_)) => {
                self.protocol_errors += 1;
                false
            }
            _ => false,
        };
        if wants && self.send_stats(now).is_err() {
            self.protocol_errors += 1;
        }
        let n = self.bus.cfg_read32(CFG_NUM_PAGES);
        if n == self.requested {
            return None;
        }
        self.requested = n;
        // The policy: `actual` stays what it was.
        self.bus.cfg_write32(CFG_ACTUAL, pages_to_hold(n));
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeBus, FakeEnv};

    fn parse(b: &[u8]) -> Vec<(u16, u64)> {
        b.chunks(STAT_LEN)
            .map(|e| {
                (
                    u16::from_le_bytes([e[0], e[1]]),
                    u64::from_le_bytes(e[2..10].try_into().unwrap()),
                )
            })
            .collect()
    }

    #[test]
    fn statistics_are_encoded_and_kept_plausible() {
        let mut b = [0u8; STATS * STAT_LEN];
        encode_stats(
            &MemStats {
                total: 512 << 20,
                free: 300 << 20,
                available: 290 << 20,
            },
            &mut b,
        );
        assert_eq!(
            parse(&b),
            [
                (STAT_MEMTOT, 512 << 20),
                (STAT_MEMFREE, 300 << 20),
                (STAT_AVAIL, 290 << 20)
            ]
        );
        encode_stats(
            &MemStats {
                total: 10,
                free: 99,
                available: 99,
            },
            &mut b,
        );
        assert_eq!(parse(&b)[1..], [(STAT_MEMFREE, 10), (STAT_AVAIL, 10)]);
    }

    #[test]
    fn the_host_gets_statistics_on_request_and_no_pages() {
        let bus = FakeBus::new(
            F_VERSION_1 | F_STATS_VQ | F_DEFLATE_ON_OOM,
            &[64, 64, 64],
            8,
        );
        let env = FakeEnv::default();
        let s1 = MemStats {
            total: 100,
            free: 50,
            available: 40,
        };
        let mut b = VirtioBalloon::new(&bus, &env, &s1).unwrap();
        assert_eq!(bus.accepted.get(), F_VERSION_1 | F_STATS_VQ);
        assert!(b.has_stats());
        // The initial buffer.
        let (head, segs) = bus.pop(STATSQ).unwrap();
        assert_eq!(parse(&FakeBus::read(&segs))[1], (STAT_MEMFREE, 50));
        // No request yet: nothing is sent again.
        assert_eq!(b.poll(&s1), None);
        assert!(bus.pop(STATSQ).is_none());
        // The device asks (returns the buffer): fresh numbers follow.
        bus.complete(STATSQ, u32::from(head), 0);
        let s2 = MemStats { free: 20, ..s1 };
        assert_eq!(b.poll(&s2), None);
        let (_, segs) = bus.pop(STATSQ).unwrap();
        assert_eq!(parse(&FakeBus::read(&segs))[1], (STAT_MEMFREE, 20));
        assert_eq!(b.stats_sent, 2);
        // The host asks for 1000 pages: recorded once, `actual` stays 0,
        // and nothing ever appears on the inflate queue.
        bus.set_cfg(CFG_NUM_PAGES, &1000u32.to_le_bytes());
        assert_eq!(b.poll(&s2), Some(1000));
        assert_eq!(b.poll(&s2), None);
        assert_eq!(bus.cfg_read32(CFG_ACTUAL), 0);
        assert!(bus.pop(INFLATEQ).is_none());
        assert_eq!(b.requested, 1000);
    }

    #[test]
    fn without_the_stats_queue_only_the_target_is_watched() {
        let bus = FakeBus::new(F_VERSION_1, &[2, 2], 8);
        let env = FakeEnv::default();
        let mut b = VirtioBalloon::new(&bus, &env, &MemStats::default()).unwrap();
        assert!(!b.has_stats());
        bus.set_cfg(CFG_NUM_PAGES, &7u32.to_le_bytes());
        assert_eq!(b.poll(&MemStats::default()), Some(7));
        // A stats completion out of nowhere on a queue that is not set up
        // is not even looked at.
        assert_eq!(b.protocol_errors, 0);
    }

    #[test]
    fn a_bogus_stats_completion_is_counted() {
        let bus = FakeBus::new(F_VERSION_1 | F_STATS_VQ, &[2, 2, 2], 8);
        let env = FakeEnv::default();
        let mut b = VirtioBalloon::new(&bus, &env, &MemStats::default()).unwrap();
        bus.complete(STATSQ, 1, 0); // head 1 was never posted
        b.poll(&MemStats::default());
        assert_eq!(b.protocol_errors, 1);
    }
}
