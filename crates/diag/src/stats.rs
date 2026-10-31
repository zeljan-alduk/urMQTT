//! Statistics of the measurements: percentiles of latency samples and
//! rates. Integer arithmetic only (the kernel has no use for floats here).

/// Order statistics of a set of samples (all in the sample's unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub count: usize,
    pub min: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
    pub mean: u64,
}

/// Nearest-rank percentile of an ascending slice; `permille` is 0..=1000
/// (500 is the median, 990 the 99th percentile). An empty slice gives 0.
pub fn percentile(sorted: &[u64], permille: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as u64;
    // Nearest rank: ceil(p * n), at least 1.
    let rank = (u64::from(permille.min(1000)) * n).div_ceil(1000).max(1);
    sorted
        .get(usize::try_from(rank - 1).unwrap_or(usize::MAX))
        .or(sorted.last())
        .copied()
        .unwrap_or(0)
}

/// Sorts `samples` and summarises them; `None` when there are none.
pub fn summarize(samples: &mut [u64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let sum: u128 = samples.iter().map(|&s| u128::from(s)).sum();
    Some(Summary {
        count: samples.len(),
        min: samples.first().copied().unwrap_or(0),
        p50: percentile(samples, 500),
        p90: percentile(samples, 900),
        p99: percentile(samples, 990),
        max: samples.last().copied().unwrap_or(0),
        mean: u64::try_from(sum / samples.len() as u128).unwrap_or(u64::MAX),
    })
}

/// `units` per second over `ns` nanoseconds (0 if no time passed).
pub fn per_second(units: u64, ns: u64) -> u64 {
    if ns == 0 {
        return 0;
    }
    u64::try_from(u128::from(units) * 1_000_000_000 / u128::from(ns)).unwrap_or(u64::MAX)
}

/// Throughput in MiB/s for `bytes` moved in `ns` nanoseconds.
pub fn mib_per_s(bytes: u64, ns: u64) -> u64 {
    if ns == 0 {
        return 0;
    }
    u64::try_from(u128::from(bytes) * 1_000_000_000 / u128::from(ns) / (1 << 20))
        .unwrap_or(u64::MAX)
}

/// `a / b` in tenths, rounded to nearest (`b == 0` gives 0).
pub fn div_x10(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    u64::try_from((u128::from(a) * 20 + u128::from(b)) / (2 * u128::from(b))).unwrap_or(u64::MAX)
}

/// Converts ticks of a clock at `hz` to nanoseconds (rounded down).
pub fn ticks_to_ns(ticks: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(hz)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_is_nearest_rank() {
        let v: [u64; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&v, 0), 1);
        assert_eq!(percentile(&v, 100), 1);
        assert_eq!(percentile(&v, 500), 5);
        assert_eq!(percentile(&v, 510), 6);
        assert_eq!(percentile(&v, 900), 9);
        assert_eq!(percentile(&v, 990), 10);
        assert_eq!(percentile(&v, 1000), 10);
        assert_eq!(percentile(&v, 5000), 10, "clamped");
        assert_eq!(percentile(&[], 500), 0);
        assert_eq!(percentile(&[7], 990), 7);
    }

    #[test]
    fn summary_sorts_and_averages() {
        let mut s = [9, 1, 5, 3, 7, 2, 8, 4, 6, 10];
        let sm = summarize(&mut s).unwrap();
        assert_eq!(
            sm,
            Summary {
                count: 10,
                min: 1,
                p50: 5,
                p90: 9,
                p99: 10,
                max: 10,
                mean: 5
            }
        );
        assert!(summarize(&mut []).is_none());
    }

    #[test]
    fn a_hundred_samples() {
        let mut s: alloc::vec::Vec<u64> = (1..=100).rev().collect();
        let sm = summarize(&mut s).unwrap();
        assert_eq!((sm.p50, sm.p90, sm.p99, sm.max), (50, 90, 99, 100));
    }

    #[test]
    fn rates() {
        assert_eq!(per_second(1000, 1_000_000_000), 1000);
        assert_eq!(per_second(5, 0), 0);
        assert_eq!(per_second(2000, 500_000_000), 4000);
        assert_eq!(mib_per_s(1 << 20, 1_000_000_000), 1);
        assert_eq!(mib_per_s(100 << 20, 500_000_000), 200);
        assert_eq!(mib_per_s(1, 0), 0);
        // No overflow with huge figures.
        assert!(mib_per_s(u64::MAX, 1) > 0);
        assert_eq!(div_x10(10, 4), 25);
        assert_eq!(div_x10(1, 3), 3);
        assert_eq!(div_x10(1, 0), 0);
        assert_eq!(ticks_to_ns(24_000_000, 24_000_000), 1_000_000_000);
        assert_eq!(ticks_to_ns(5, 0), 0);
    }
}
