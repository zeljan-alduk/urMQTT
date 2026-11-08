//! The WebSocket opening handshake parser (ADR-272): any bytes, any policy
//! the configuration can express. `scan` and `parse` must return and never
//! panic; `scan` never looks past 4 KiB; whatever `parse` accepts was a
//! complete request ending in an empty line, offered mqtt or mqttv3.1, asked
//! for the configured path, and gets a well-formed 101 whose accept value is
//! 28 base64 characters; every refusal is one of the fixed responses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_ws::upgrade::{self, Policy, Refusal, Scan};

const PATHS: [&str; 3] = ["/mqtt", "/", "/a/b"];
const ORIGINS: [&[&str]; 3] = [&[], &["https://app.example.com"], &["http://localhost:3000", "https://x.y"]];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, req)) = data.split_first() else {
        return;
    };
    let policy = Policy {
        path: PATHS[usize::from(sel) % PATHS.len()],
        origins: ORIGINS[usize::from(sel >> 4) % ORIGINS.len()],
    };
    match upgrade::scan(req) {
        Scan::Complete { end } => {
            assert!(end <= upgrade::MAX_REQUEST && end <= req.len());
            assert!(req[..end].ends_with(b"\r\n\r\n"));
            assert_eq!(upgrade::scan(&req[..end]), Scan::Complete { end });
        }
        Scan::TooLarge => assert!(req.len() >= upgrade::MAX_REQUEST),
        Scan::Incomplete => assert!(req.len() < upgrade::MAX_REQUEST),
    }
    match upgrade::parse(req, &policy) {
        Ok(a) => {
            assert!(req.len() <= upgrade::MAX_REQUEST && req.ends_with(b"\r\n\r\n"));
            let line_end = req.windows(2).position(|w| w == b"\r\n").unwrap();
            let want = format!("GET {} HTTP/1.1", policy.path);
            assert_eq!(&req[..line_end], want.as_bytes());
            let mut out = [0u8; upgrade::MAX_RESPONSE];
            let n = a.response(&mut out);
            assert!(out[..n].starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
            assert!(out[..n].ends_with(b"\r\n\r\n"));
            assert!(a.accept_value().iter().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(c)));
            assert_eq!(a.accept_value()[27], b'=');
        }
        Err(r) => assert!(Refusal::ALL.contains(&r) && r.response().starts_with(b"HTTP/1.1 4")),
    }
});
