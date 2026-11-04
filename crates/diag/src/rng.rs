//! A quick sanity test of raw random bytes (not a certification): the share
//! of one bits and the longest run of equal bits. A source that is stuck,
//! constant or visibly biased fails it; one that passes is not thereby good.

/// What the test saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawTest {
    pub bytes: u32,
    /// Ones per thousand bits (500 expected).
    pub ones_permille: u32,
    /// The longest run of equal bits.
    pub longest_run: u32,
    pub ok: bool,
}

/// Four standard deviations of the count of ones, and a run no random source
/// of this size produces (2^-34 per position).
pub fn raw_test(b: &[u8]) -> RawTest {
    let n = b.len() as u64 * 8;
    if n == 0 {
        return RawTest::default();
    }
    let ones: u64 = b.iter().map(|x| u64::from(x.count_ones())).sum();
    let (mut longest, mut run, mut prev) = (0u32, 0u32, 2u8);
    for byte in b {
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            run = if bit == prev { run + 1 } else { 1 };
            prev = bit;
            longest = longest.max(run);
        }
    }
    let dev = ones.abs_diff(n / 2);
    // |ones - n/2| <= 4 * sqrt(n) / 2 = 2 sqrt(n)  <=>  dev^2 <= 4 n
    let balanced = dev * dev <= 4 * n;
    RawTest {
        bytes: b.len() as u32,
        ones_permille: (ones * 1000 / n) as u32,
        longest_run: longest,
        ok: balanced && longest <= 34,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_and_biased_bytes_fail() {
        assert!(!raw_test(&[0u8; 512]).ok);
        assert!(!raw_test(&[0xffu8; 512]).ok);
        assert!(!raw_test(&[0x55u8; 512]).ok || raw_test(&[0x55u8; 512]).longest_run == 1);
        assert!(!raw_test(&[0x0fu8; 512]).ok || raw_test(&[0x0fu8; 512]).ones_permille == 500);
        // 90 % ones.
        let biased: Vec<u8> = (0..512)
            .map(|i| if i % 10 == 0 { 0 } else { 0xff })
            .collect();
        assert!(!raw_test(&biased).ok);
        assert_eq!(raw_test(&[]), RawTest::default());
    }

    #[test]
    fn a_pseudo_random_stream_passes() {
        // xorshift64*: good enough to look random to this test.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let b: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
            })
            .collect();
        let t = raw_test(&b);
        assert!(t.ok, "{t:?}");
        assert!((480..=520).contains(&t.ones_permille), "{t:?}");
    }
}
