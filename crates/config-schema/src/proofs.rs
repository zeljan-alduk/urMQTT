//! Kani proofs (H5) for configuration validation: the rate and topic-filter
//! checks on any short string never panic, and what they accept has the
//! shape the broker relies on.

use crate::{Limits, Placeholder, Rate, check_topic_filter, parse_rate};

fn any_str<const N: usize>(bytes: &[u8; N], n: usize) -> Option<&str> {
    core::str::from_utf8(&bytes[..n]).ok()
}

#[kani::proof]
#[kani::unwind(8)]
fn parse_rate_any_short_string() {
    let bytes: [u8; 5] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    if let Some(s) = any_str(&bytes, n)
        && let Ok(r) = parse_rate(s)
    {
        assert!(r.tokens > 0);
        assert!(matches!(r.per_ms, 1_000 | 60_000 | 3_600_000));
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn topic_filter_any_short_string() {
    let bytes: [u8; 5] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    let limits = Limits {
        max_connections_per_core: 1,
        max_packet_size: 256,
        max_topic_len: kani::any(),
        max_topic_levels: kani::any(),
        max_subscriptions_per_session: 1,
        max_inflight_qos1: 1,
        max_queued_per_offline_session: 1,
        max_retained_per_device: 1,
        max_retained_bytes: 1,
        publish_rate_per_device: Rate {
            tokens: 1,
            per_ms: 1000,
        },
        handshakes_per_core_per_sec: 1,
        max_handshakes_in_flight_per_core: 1,
        max_handshakes_in_flight_per_ip: 1,
    };
    let ph = if kani::any() {
        Placeholder::Allowed
    } else {
        Placeholder::Forbidden
    };
    if let Some(s) = any_str(&bytes, n)
        && check_topic_filter(s, &limits, ph).is_ok()
    {
        assert!(!s.is_empty() && s.len() <= usize::try_from(limits.max_topic_len).unwrap());
        assert!(!s.contains('\0'));
        // `#` only as the whole last level.
        if let Some(i) = s.find('#') {
            assert!(i + 1 == s.len() && (i == 0 || s.as_bytes()[i - 1] == b'/'));
        }
    }
}
