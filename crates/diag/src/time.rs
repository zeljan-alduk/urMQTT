//! Calendar text for the RTC reading.

use alloc::format;
use alloc::string::String;

/// `(year, month, day, hour, minute, second)` of a Unix time (UTC).
pub fn civil(unix: u64) -> (u64, u32, u32, u32, u32, u32) {
    let days = unix / 86_400;
    let rem = unix % 86_400;
    // Howard Hinnant's civil-from-days, for days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + u64::from(month <= 2);
    (
        year,
        month,
        day,
        (rem / 3_600) as u32,
        (rem % 3_600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// `2026-10-31T12:34:56Z`.
pub fn iso8601(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_709_164_800 + 86_399), "2024-02-29T23:59:59Z");
        assert_eq!(iso8601(1_761_913_696), "2025-10-31T12:28:16Z");
        assert_eq!(iso8601(4_102_444_800), "2100-01-01T00:00:00Z");
        assert_eq!(iso8601(4_107_542_400), "2100-03-01T00:00:00Z");
    }
}
