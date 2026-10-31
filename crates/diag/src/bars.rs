//! Bar scaling for the dashboard: how many pixels of a bar a value fills.

/// Pixels of a `width`-pixel bar that `value` fills on a linear scale
/// ending at `max`. A non-zero value always shows at least one pixel; a
/// value at or above `max` fills the bar.
pub fn linear_px(value: u64, max: u64, width: usize) -> usize {
    if width == 0 || value == 0 || max == 0 {
        return 0;
    }
    if value >= max {
        return width;
    }
    let px = u128::from(value) * width as u128 / u128::from(max);
    usize::try_from(px).unwrap_or(width).clamp(1, width)
}

/// `log2(x)` in 1/256ths (`x >= 1`; below that 0), with a linear
/// interpolation inside each octave: monotonic, within 0.09 of the true
/// value, and integer only.
pub fn log2_q8(x: u64) -> u64 {
    if x < 2 {
        return 0;
    }
    let msb = 63 - u64::from(x.leading_zeros());
    let frac = ((x << (63 - msb)) >> 55) & 0xff;
    msb * 256 + frac
}

/// Pixels of a `width`-pixel bar for `value` on a logarithmic scale from
/// `lo` (empty) to `hi` (full): latencies that span three orders of
/// magnitude stay readable. Values at or below `lo` show one pixel (the
/// measurement exists), at or above `hi` fill the bar.
pub fn log_px(value: u64, lo: u64, hi: u64, width: usize) -> usize {
    if width == 0 || value == 0 || hi <= lo {
        return 0;
    }
    if value >= hi {
        return width;
    }
    if value <= lo {
        return 1.min(width);
    }
    let (v, l, h) = (log2_q8(value), log2_q8(lo), log2_q8(hi));
    if h <= l {
        return width;
    }
    let px = (v.saturating_sub(l)) as u128 * width as u128 / (h - l) as u128;
    usize::try_from(px).unwrap_or(width).clamp(1, width)
}

/// The next "round" scale limit at or above `v` (1, 2, 5 times a power of
/// ten): a bar graph of throughputs ends on a number a person can read.
pub fn nice_max(v: u64) -> u64 {
    if v <= 1 {
        return 1;
    }
    let mut unit = 1u64;
    loop {
        for m in [1u64, 2, 5] {
            if let Some(c) = unit.checked_mul(m)
                && c >= v
            {
                return c;
            }
        }
        match unit.checked_mul(10) {
            Some(u) => unit = u,
            None => return u64::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_scaling() {
        assert_eq!(linear_px(0, 100, 200), 0);
        assert_eq!(linear_px(50, 100, 200), 100);
        assert_eq!(linear_px(100, 100, 200), 200);
        assert_eq!(linear_px(5000, 100, 200), 200, "clamped");
        assert_eq!(
            linear_px(1, 1_000_000, 200),
            1,
            "a measurement always shows"
        );
        assert_eq!(linear_px(10, 0, 200), 0);
        assert_eq!(linear_px(10, 100, 0), 0);
        assert_eq!(linear_px(u64::MAX - 1, u64::MAX, 100), 99);
    }

    #[test]
    fn log2_is_monotonic_and_close() {
        assert_eq!(log2_q8(0), 0);
        assert_eq!(log2_q8(1), 0);
        assert_eq!(log2_q8(2), 256);
        assert_eq!(log2_q8(1024), 10 * 256);
        let mut prev = 0;
        for x in 1..5000u64 {
            let l = log2_q8(x);
            assert!(l >= prev, "monotonic at {x}");
            prev = l;
        }
        // 3 is between 2 and 4: 1.5 by interpolation, true value 1.585.
        assert_eq!(log2_q8(3), 256 + 128);
    }

    #[test]
    fn log_scaling() {
        // 1 ns .. 1000 ns over 300 px.
        assert_eq!(log_px(0, 1, 1000, 300), 0);
        assert_eq!(log_px(1, 1, 1000, 300), 1);
        assert_eq!(log_px(1000, 1, 1000, 300), 300);
        assert_eq!(log_px(50_000, 1, 1000, 300), 300);
        let a = log_px(2, 1, 1000, 300);
        let b = log_px(20, 1, 1000, 300);
        let c = log_px(200, 1, 1000, 300);
        assert!(0 < a && a < b && b < c && c < 300, "{a} {b} {c}");
        // Each decade is about a third of the three-decade bar.
        assert!(c.abs_diff(b).abs_diff(b.abs_diff(a)) < 12);
        assert_eq!(log_px(5, 10, 100, 80), 1, "below the floor still shows");
        assert_eq!(log_px(5, 100, 10, 80), 0, "empty scale");
    }

    #[test]
    fn nice_limits() {
        assert_eq!(nice_max(0), 1);
        assert_eq!(nice_max(1), 1);
        assert_eq!(nice_max(3), 5);
        assert_eq!(nice_max(5), 5);
        assert_eq!(nice_max(6), 10);
        assert_eq!(nice_max(812), 1000);
        assert_eq!(nice_max(1001), 2000);
        assert_eq!(nice_max(4200), 5000);
        assert_eq!(nice_max(u64::MAX), u64::MAX);
    }
}
