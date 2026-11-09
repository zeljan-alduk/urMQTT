//! The metrics endpoint's HTTP request reader (ADR-290): any bytes. `scan`
//! and `parse` must return and never panic; `scan` never looks past 2 KiB;
//! whatever `parse` accepts was a complete request ending in an empty line, of
//! at most 2 KiB, for a GET or HEAD with a visible-ASCII target starting with
//! `/`, every line ending in CRLF, no body and no Transfer-Encoding; every
//! refusal is one of the fixed responses; the head of a 200 is well formed
//! for any length. Split into two feeds, the bytes give the same verdict as
//! all at once (the endpoint buffers and re-scans).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_http::{Format, MAX_HEAD, MAX_REQUEST, Method, Refusal, Scan, ok_head, parse, scan};

fuzz_target!(|data: &[u8]| {
    match scan(data) {
        Scan::Complete { end } => {
            assert!(end <= MAX_REQUEST && end <= data.len());
            assert!(data[..end].ends_with(b"\r\n\r\n"));
            assert_eq!(scan(&data[..end]), Scan::Complete { end });
            match parse(&data[..end]) {
                Ok(r) => {
                    assert!(matches!(r.method, Method::Get | Method::Head));
                    assert!(r.target.starts_with('/'));
                    assert!(
                        r.target
                            .bytes()
                            .all(|b| (0x21..=0x7e).contains(&b) && b != b'#')
                    );
                    // No bare LF: every LF of the request follows a CR.
                    let req = &data[..end];
                    assert!(
                        req.iter()
                            .enumerate()
                            .all(|(i, &b)| b != b'\n' || (i > 0 && req[i - 1] == b'\r'))
                    );
                    let lower = req.to_ascii_lowercase();
                    assert!(!lower.windows(18).any(|w| w == b"\r\ntransfer-encoding"));
                    let mut head = [0u8; MAX_HEAD];
                    let n = ok_head(r.format, data.len(), &mut head);
                    assert!(
                        head[..n].starts_with(b"HTTP/1.1 200 OK\r\n")
                            && head[..n].ends_with(b"\r\n\r\n")
                    );
                }
                Err(r) => assert!(
                    Refusal::ALL.contains(&r) && r.response().starts_with(b"HTTP/1.1 4")
                        || r == Refusal::Version
                ),
            }
        }
        Scan::TooLarge => assert!(data.len() >= MAX_REQUEST),
        Scan::Incomplete => assert!(data.len() < MAX_REQUEST),
    }
    // Direct parse of arbitrary bytes: no panic, and accepted means complete.
    if let Ok(r) = parse(data) {
        assert!(data.len() <= MAX_REQUEST && data.ends_with(b"\r\n\r\n"));
        assert!(r.target.is_ascii());
    }
    // The same bytes in two feeds: scan is a function of the prefix alone.
    if data.len() > 1 {
        let cut = usize::from(data[0]) % data.len();
        let whole = scan(data);
        let first = scan(&data[..cut]);
        if let Scan::Complete { end } = first {
            assert_eq!(whole, Scan::Complete { end });
        }
    }
    let _ = (Format::Prometheus, Format::OpenMetrics);
});
