//! Text formatting for the dashboard: sizes, tenths, times, columns.

use alloc::format;
use alloc::string::String;

/// A value in tenths as `12.3`.
pub fn x10(v: u64) -> String {
    format!("{}.{}", v / 10, v % 10)
}

/// Bytes as `512 B`, `64.0 KiB`, `1.5 GiB` (binary units, one decimal).
pub fn bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if b < 1024 {
        return format!("{b} B");
    }
    // Index of the largest unit that leaves a value of at least 1.
    let mut i = 0usize;
    while i + 1 < UNITS.len() && (b >> (10 * (i + 2))) > 0 {
        i += 1;
    }
    let v = u128::from(b) * 10 / (1u128 << (10 * (i + 1)));
    format!(
        "{}.{} {}",
        v / 10,
        v % 10,
        UNITS.get(i).copied().unwrap_or("?")
    )
}

/// Nanoseconds in tenths (`ns_x10`) as `0.9 ns`, `85.2 ns`, `12.3 us`,
/// `4.5 ms`, `1.20 s` picking the unit that keeps the number short.
pub fn duration_x10(ns_x10: u64) -> String {
    let ns = ns_x10 / 10;
    if ns < 1_000 {
        format!("{} ns", x10(ns_x10))
    } else if ns < 1_000_000 {
        format!("{} us", x10(ns_x10 / 1_000))
    } else if ns < 1_000_000_000 {
        format!("{} ms", x10(ns_x10 / 1_000_000))
    } else {
        format!("{} s", x10(ns_x10 / 1_000_000_000))
    }
}

/// Whole nanoseconds as a duration.
pub fn duration_ns(ns: u64) -> String {
    duration_x10(ns.saturating_mul(10))
}

/// Throughput: `812 MiB/s`, or `1.2 GiB/s` from 10 GiB/s... kept in MiB/s
/// below 10240 so columns stay comparable.
pub fn rate_mib(mib: u64) -> String {
    if mib >= 10_240 {
        format!("{} GiB/s", x10(mib * 10 / 1024))
    } else {
        format!("{mib} MiB/s")
    }
}

/// `a:b:c:d:e:f`.
pub fn mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// `s` padded on the right to `w` characters, or cut to `w`.
pub fn left(s: &str, w: usize) -> String {
    let mut out: String = s.chars().take(w).collect();
    while out.chars().count() < w {
        out.push(' ');
    }
    out
}

/// `s` padded on the left to `w` characters, or its last `w` characters.
pub fn right(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w {
        return s.chars().skip(n - w).collect();
    }
    let mut out: String = core::iter::repeat_n(' ', w - n).collect();
    out.push_str(s);
    out
}

/// `s` cut to `w` characters, ending in `~` if it was cut.
pub fn clip(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return String::from(s);
    }
    let mut out: String = s.chars().take(w.saturating_sub(1)).collect();
    if w > 0 {
        out.push('~');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(64 << 20), "64.0 MiB");
        assert_eq!(bytes(3 << 30), "3.0 GiB");
        assert_eq!(bytes((1 << 30) + (1 << 29)), "1.5 GiB");
        assert_eq!(bytes(1 << 40), "1.0 TiB");
        assert_eq!(bytes(u64::MAX), "16383.9 PiB");
        assert_eq!(bytes((1 << 20) - 1), "1023.9 KiB");
    }

    #[test]
    fn tenths_and_durations() {
        assert_eq!(x10(0), "0.0");
        assert_eq!(x10(123), "12.3");
        assert_eq!(duration_x10(9), "0.9 ns");
        assert_eq!(duration_x10(852), "85.2 ns");
        assert_eq!(duration_ns(1_500), "1.5 us");
        assert_eq!(duration_ns(4_500_000), "4.5 ms");
        assert_eq!(duration_ns(1_200_000_000), "1.2 s");
        assert_eq!(rate_mib(812), "812 MiB/s");
        assert_eq!(rate_mib(20_480), "20.0 GiB/s");
    }

    #[test]
    fn columns() {
        assert_eq!(left("ab", 4), "ab  ");
        assert_eq!(left("abcdef", 4), "abcd");
        assert_eq!(right("ab", 4), "  ab");
        assert_eq!(right("abcdef", 4), "cdef");
        assert_eq!(clip("abcdef", 4), "abc~");
        assert_eq!(clip("abc", 4), "abc");
        assert_eq!(clip("abc", 0), "");
        assert_eq!(mac([0x52, 0x54, 0, 0x12, 0x34, 0xab]), "52:54:00:12:34:ab");
    }
}
