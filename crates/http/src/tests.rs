//! Host tests: every refusal, the negotiation of the format, the bounds, and
//! properties (no input panics; what is accepted is what the grammar says).

use crate::{
    Format, MAX_HEAD, MAX_HEADERS, MAX_REQUEST, MAX_TARGET, Method, Refusal, Scan, ok_head, parse,
    scan,
};
use proptest::prelude::*;

fn req(lines: &[&str]) -> Vec<u8> {
    let mut s = String::new();
    for l in lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// What Prometheus 2.x sends, give or take.
fn prometheus() -> Vec<&'static str> {
    vec![
        "GET /metrics HTTP/1.1",
        "Host: 10.0.0.5:9100",
        "User-Agent: Prometheus/2.53.0",
        "Accept: application/openmetrics-text;version=1.0.0;q=0.5,text/plain;version=0.0.4;q=0.4,*/*;q=0.1",
        "Accept-Encoding: gzip",
        "X-Prometheus-Scrape-Timeout-Seconds: 10",
    ]
}

#[test]
fn a_scrape_is_accepted() {
    let r = req(&prometheus());
    let q = parse(&r).unwrap();
    assert_eq!(q.method, Method::Get);
    assert_eq!(q.target, "/metrics");
    assert_eq!(q.format, Format::OpenMetrics);
}

#[test]
fn curl_and_head_and_http_1_0() {
    let r = req(&["GET /metrics HTTP/1.1", "Host: x", "Accept: */*"]);
    let q = parse(&r).unwrap();
    assert_eq!(q.format, Format::Prometheus);
    let r = req(&["HEAD /metrics HTTP/1.1"]);
    let q = parse(&r).unwrap();
    assert_eq!((q.method, q.format), (Method::Head, Format::Prometheus));
    assert!(parse(&req(&["GET /metrics HTTP/1.0"])).is_ok());
}

#[test]
fn negotiation_by_quality() {
    let f = |accept: &str| {
        parse(&req(&["GET /m HTTP/1.1", &format!("Accept: {accept}")]))
            .unwrap()
            .format
    };
    use Format::{OpenMetrics as O, Prometheus as P};
    assert_eq!(f("application/openmetrics-text"), O);
    assert_eq!(f("application/openmetrics-text, text/plain"), P);
    assert_eq!(f("text/plain"), P);
    assert_eq!(f("application/openmetrics-text;q=0.9, text/plain;q=0.1"), O);
    assert_eq!(f("application/openmetrics-text;q=0.1, text/plain;q=0.9"), P);
    assert_eq!(f("application/openmetrics-text;q=0"), P);
    assert_eq!(f("application/openmetrics-text;q=0.001, */*;q=0"), O);
    assert_eq!(f("APPLICATION/OpenMetrics-Text"), O);
    // Malformed quality values do not count.
    assert_eq!(f("application/openmetrics-text;q=2"), P);
    assert_eq!(f("application/openmetrics-text;q=1.5"), P);
    assert_eq!(f("application/openmetrics-text;q=x"), P);
    assert_eq!(f("application/openmetrics-text;q=0.1234"), P);
    // Prometheus 3's header.
    assert_eq!(
        f(
            "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.6,application/openmetrics-text;version=0.0.1;q=0.5,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.4,text/plain;version=0.0.4;q=0.3,*/*;q=0.2"
        ),
        O
    );
}

#[test]
fn every_refusal() {
    let bad: Vec<(Vec<u8>, Refusal)> = vec![
        (req(&["POST /metrics HTTP/1.1"]), Refusal::Method),
        (req(&["DELETE / HTTP/1.1"]), Refusal::Method),
        (req(&["GET /metrics HTTP/2.0"]), Refusal::Version),
        (req(&["GET /metrics HTTP/1.2"]), Refusal::Version),
        (
            req(&["GET /metrics HTTP/1.1", "Content-Length: 5"]),
            Refusal::Malformed,
        ),
        (
            req(&[
                "GET /metrics HTTP/1.1",
                "Content-Length: 0",
                "Content-Length: 0",
            ]),
            Refusal::Malformed,
        ),
        (
            req(&["GET /metrics HTTP/1.1", "Transfer-Encoding: chunked"]),
            Refusal::Malformed,
        ),
        (req(&["GET /metrics"]), Refusal::Malformed),
        (req(&["GET  /metrics HTTP/1.1"]), Refusal::Malformed),
        (req(&["GET /metrics HTTP/1.1 x"]), Refusal::Malformed),
        (req(&["GET metrics HTTP/1.1"]), Refusal::Malformed),
        (req(&["GET http://x/metrics HTTP/1.1"]), Refusal::Malformed),
        (req(&["GET /met#rics HTTP/1.1"]), Refusal::Malformed),
        (
            req(&["GET /metrics HTTP/1.1", "Bad Header: x"]),
            Refusal::Malformed,
        ),
        (
            req(&["GET /metrics HTTP/1.1", " folded: x"]),
            Refusal::Malformed,
        ),
        (
            req(&["GET /metrics HTTP/1.1", "NoColon"]),
            Refusal::Malformed,
        ),
        (
            req(&["GET /metrics HTTP/1.1", ": empty-name"]),
            Refusal::Malformed,
        ),
        (
            req(&["GET /metrics HTTP/1.1", "X: a\u{1}b"]),
            Refusal::Malformed,
        ),
        (
            b"GET /metrics HTTP/1.1\nHost: x\r\n\r\n".to_vec(),
            Refusal::Malformed,
        ),
        (
            b"GET /metrics HTTP/1.1\r\nHost: x\rY: z\r\n\r\n".to_vec(),
            Refusal::Malformed,
        ),
        (
            b"GET /metrics HTTP/1.1\r\n\r\n\n".to_vec(),
            Refusal::Malformed,
        ),
        (b"\r\n\r\n".to_vec(), Refusal::Malformed),
        // An empty line in the middle with more behind it: not "the end".
        (b"GET /metrics HTTP/1.1\r\n\r\nx: y\r\n\r\n".to_vec(), Refusal::Malformed),
        // The fuzzer's find: a bare LF as an empty line before the real end.
        (b"GET /metrics HTTP/1.1\r\nHost: x\r\n\n\r\n\r\n".to_vec(), Refusal::Malformed),
        (
            b"GET /metrics HTTP/1.1\r\nHost: x".to_vec(),
            Refusal::Malformed,
        ),
        (b"".to_vec(), Refusal::Malformed),
    ];
    for (r, want) in bad {
        assert_eq!(
            parse(&r).err(),
            Some(want),
            "{:?}",
            String::from_utf8_lossy(&r)
        );
    }
}

#[test]
fn bounds() {
    // Target length.
    let t = format!("GET /{} HTTP/1.1", "a".repeat(MAX_TARGET - 1));
    assert!(parse(&req(&[&t])).is_ok());
    let t = format!("GET /{} HTTP/1.1", "a".repeat(MAX_TARGET));
    assert_eq!(parse(&req(&[&t])).err(), Some(Refusal::Malformed));
    // Header count.
    let mut l = vec!["GET /metrics HTTP/1.1".to_owned()];
    for i in 0..MAX_HEADERS {
        l.push(format!("X-{i}: v"));
    }
    let l: Vec<&str> = l.iter().map(String::as_str).collect();
    assert!(parse(&req(&l)).is_ok());
    let mut l2 = l.clone();
    l2.push("X-more: v");
    assert_eq!(parse(&req(&l2)).err(), Some(Refusal::TooLarge));
    // Total size.
    let big = format!("X: {}", "a".repeat(MAX_REQUEST));
    assert_eq!(
        parse(&req(&["GET /metrics HTTP/1.1", &big])).err(),
        Some(Refusal::TooLarge)
    );
}

#[test]
fn scan_waits_then_completes_then_stops() {
    let r = req(&prometheus());
    for n in 0..r.len() {
        assert_eq!(scan(&r[..n]), Scan::Incomplete, "{n}");
    }
    assert_eq!(scan(&r), Scan::Complete { end: r.len() });
    // Pipelined bytes after the request are not part of it.
    let mut two = r.clone();
    two.extend_from_slice(&r);
    assert_eq!(scan(&two), Scan::Complete { end: r.len() });
    assert_eq!(scan(&vec![b'a'; MAX_REQUEST - 1]), Scan::Incomplete);
    assert_eq!(scan(&vec![b'a'; MAX_REQUEST]), Scan::TooLarge);
    assert_eq!(scan(&vec![b'a'; MAX_REQUEST * 4]), Scan::TooLarge);
    // The end of headers beyond the limit is not looked for.
    let mut late = vec![b'a'; MAX_REQUEST];
    late.extend_from_slice(b"\r\n\r\n");
    assert_eq!(scan(&late), Scan::TooLarge);
}

#[test]
fn responses_are_fixed_and_well_formed() {
    for r in Refusal::ALL {
        let b = r.response();
        assert!(b.starts_with(b"HTTP/1.1 4") || b.starts_with(b"HTTP/1.1 5"));
        assert!(b.ends_with(b"\r\n\r\n"));
        assert!(b.windows(19).any(|w| w == b"Connection: close\r\n"));
        assert!(b.windows(17).any(|w| w == b"Content-Length: 0"));
        assert_eq!(Refusal::ALL[r.index()], r);
    }
    let mut out = [0u8; MAX_HEAD];
    for (format, len) in [
        (Format::Prometheus, 0usize),
        (Format::OpenMetrics, 7),
        (Format::Prometheus, 123_456),
        (Format::OpenMetrics, usize::MAX),
    ] {
        let n = ok_head(format, len, &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Type: "));
        assert!(s.ends_with("\r\n\r\n"));
        assert!(s.contains(&format!("Content-Length: {len}\r\n")), "{s}");
        assert!(s.contains(format.content_type()));
        assert!(s.contains("Connection: close"));
    }
}

proptest! {
    /// No input panics, and what parses is a GET or HEAD for an ASCII target.
    #[test]
    fn any_bytes(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let _ = scan(&data);
        if let Ok(q) = parse(&data) {
            prop_assert!(data.len() <= MAX_REQUEST && data.ends_with(b"\r\n\r\n"));
            prop_assert!(q.target.starts_with('/') && q.target.is_ascii());
        }
    }

    /// Mutating a good request one byte at a time never panics and never
    /// accepts a request that has lost its final CRLF.
    #[test]
    fn mutated_scrape(i in 0usize..400, b in any::<u8>(), cut in 0usize..400) {
        let mut r = req(&prometheus());
        let n = i % r.len();
        r[n] = b;
        let _ = parse(&r);
        let cut = cut % r.len();
        prop_assert!(parse(&r[..cut]).is_err());
    }

    /// Any split of the same bytes ends in the same scan result.
    #[test]
    fn scan_is_prefix_monotone(extra in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut r = req(&prometheus());
        let end = r.len();
        r.extend_from_slice(&extra);
        prop_assert_eq!(scan(&r), Scan::Complete { end });
    }
}
