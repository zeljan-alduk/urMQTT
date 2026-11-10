//! The physical ranges the kernel lent the IOMMU drivers (`iommu::KEnv`).
//!
//! `urmqtt-iommu` has no `unsafe`: it reads and writes its tables through
//! `Env::read`/`Env::write` by physical address, and the kernel turns that
//! address into an HHDM pointer. The kernel now refuses any address outside
//! the frames `Env::alloc` handed out, so a logic bug in the safe crate
//! cannot become a write to arbitrary kernel memory (ADR-347).

use alloc::vec::Vec;

/// Disjoint `[start, end)` ranges, sorted by start.
#[derive(Default)]
pub(crate) struct OwnedFrames {
    ranges: Vec<(u64, u64)>,
}

impl OwnedFrames {
    /// Records `[pa, pa + len)`. False (nothing recorded) if the range is
    /// empty, wraps, overlaps one already recorded or memory runs out.
    pub(crate) fn add(&mut self, pa: u64, len: u64) -> bool {
        let Some(end) = pa.checked_add(len) else {
            return false;
        };
        if len == 0 {
            return false;
        }
        let i = self.ranges.partition_point(|&(s, _)| s < pa);
        let clear_before = i == 0 || self.ranges.get(i - 1).is_some_and(|&(_, e)| e <= pa);
        let clear_after = self.ranges.get(i).is_none_or(|&(s, _)| end <= s);
        if !(clear_before && clear_after) || self.ranges.try_reserve(1).is_err() {
            return false;
        }
        self.ranges.insert(i, (pa, end));
        true
    }

    /// Whether `[pa, pa + len)` lies inside one recorded range.
    pub(crate) fn contains(&self, pa: u64, len: u64) -> bool {
        let Some(end) = pa.checked_add(len) else {
            return false;
        };
        let i = self.ranges.partition_point(|&(s, _)| s <= pa);
        i > 0 && self.ranges.get(i - 1).is_some_and(|&(_, e)| end <= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-347: before, `KEnv::va` turned any 8-byte-aligned address into an
    /// HHDM pointer; only addresses inside lent frames may pass now.
    #[test]
    fn only_lent_frames_are_reachable() {
        let mut f = OwnedFrames::default();
        assert!(!f.contains(0x1000, 8), "nothing lent yet");
        assert!(f.add(0x10_0000, 0x1000));
        assert!(f.add(0x8000, 0x2000));
        assert!(f.add(0x20_0000, 0x20_0000));
        for (pa, len) in [
            (0x10_0000, 8),
            (0x10_0ff8, 8),
            (0x8000, 0x2000),
            (0x9ff8, 8),
            (0x3f_fff8, 8),
        ] {
            assert!(f.contains(pa, len), "{pa:#x}+{len}");
        }
        for (pa, len) in [
            (0x0, 8),
            (0x7ff8, 8),
            (0xa000, 8),
            (0x10_1000, 8),
            (0x10_0ffc, 8),
            (0x9ff8, 0x10),
            (0x40_0000, 8),
            (u64::MAX - 7, 8),
            (u64::MAX - 3, 8),
        ] {
            assert!(!f.contains(pa, len), "{pa:#x}+{len}");
        }
        // Overlapping, empty and wrapping ranges are not recorded.
        assert!(!f.add(0x10_0800, 0x1000));
        assert!(!f.add(0x7000, 0x1001));
        assert!(!f.add(0x30_0000, 0x1000));
        assert!(!f.add(0x5000, 0));
        assert!(!f.add(u64::MAX - 0xfff, 0x1000));
        assert!(f.add(0x7000, 0x1000), "adjacent is fine");
        assert!(f.contains(0x7ff8, 8));
    }
}
