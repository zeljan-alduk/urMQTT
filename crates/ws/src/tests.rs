//! Host tests: the RFC 6455 examples, every refusal of the handshake, every
//! violation of the framing, and properties (any split of the input gives the
//! same events; no input panics).

use crate::frame::{self, Config, Decoder, Event, Violation, close, op};
use crate::upgrade::{self, Policy, Protocol, Refusal, Scan};
use proptest::prelude::*;

// ---- the opening handshake --------------------------------------------------

/// RFC 6455 section 1.3 / 4.2.2: the key of the example and its accept value.
#[test]
fn rfc_6455_accept_example() {
    assert_eq!(
        &upgrade::accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
        b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

const POLICY: Policy<'static> = Policy {
    path: "/mqtt",
    origins: &[],
};

fn req(lines: &[&str]) -> Vec<u8> {
    let mut s = String::new();
    for l in lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// What browsers and Paho send, give or take headers that are ignored.
fn good() -> Vec<&'static str> {
    vec![
        "GET /mqtt HTTP/1.1",
        "Host: broker.example.com:8084",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: mqtt",
        "Origin: https://app.example.com",
        "User-Agent: Mozilla/5.0",
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
    ]
}

fn with(replace: &str, by: Option<&str>) -> Vec<u8> {
    let name = replace.split(':').next().unwrap();
    let mut l: Vec<&str> = good()
        .into_iter()
        .filter(|h| !h.starts_with(name))
        .collect();
    if let Some(b) = by {
        l.push(b);
    }
    req(&l)
}

#[test]
fn a_browser_upgrade_is_accepted() {
    let r = req(&good());
    assert_eq!(upgrade::scan(&r), Scan::Complete { end: r.len() });
    let a = upgrade::parse(&r, &POLICY).unwrap();
    assert_eq!(a.protocol, Protocol::Mqtt);
    assert!(a.had_origin);
    let mut out = [0u8; upgrade::MAX_RESPONSE];
    let n = a.response(&mut out);
    assert_eq!(
        &out[..n],
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"
    );
}

#[test]
fn header_names_and_tokens_are_case_insensitive_and_lists_are_read() {
    let r = req(&[
        "GET /mqtt HTTP/1.1",
        "host: x",
        "UPGRADE: WebSocket",
        "connection: keep-alive, Upgrade",
        "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==",
        "SEC-WEBSOCKET-VERSION:13",
        "Sec-WebSocket-Protocol: wamp, MQTT",
    ]);
    let a = upgrade::parse(&r, &POLICY).unwrap();
    assert_eq!(a.protocol, Protocol::Mqtt);
    assert!(!a.had_origin);
}

#[test]
fn the_subprotocol_prefers_mqtt_and_takes_mqttv31() {
    let r = with(
        "Sec-WebSocket-Protocol",
        Some("Sec-WebSocket-Protocol: mqttv3.1"),
    );
    assert_eq!(
        upgrade::parse(&r, &POLICY).unwrap().protocol,
        Protocol::MqttV31
    );
    // The whole response, with the longer name (found by fuzz/ws_upgrade:
    // 163 bytes did not fit the buffer once).
    let a = upgrade::parse(&r, &POLICY).unwrap();
    let mut out = [0u8; upgrade::MAX_RESPONSE];
    let n = a.response(&mut out);
    assert_eq!(n, 163);
    assert!(out[..n].ends_with(b"Sec-WebSocket-Protocol: mqttv3.1\r\n\r\n"));
    let mut l = good();
    l.push("Sec-WebSocket-Protocol: mqttv3.1");
    assert_eq!(
        upgrade::parse(&req(&l), &POLICY).unwrap().protocol,
        Protocol::Mqtt
    );
    for p in ["chat", "mqtt5", "mqttx", ""] {
        let h = format!("Sec-WebSocket-Protocol: {p}");
        let r = with("Sec-WebSocket-Protocol", Some(&h));
        assert_eq!(upgrade::parse(&r, &POLICY), Err(Refusal::Protocol), "{p}");
    }
    let r = with("Sec-WebSocket-Protocol", None);
    assert_eq!(upgrade::parse(&r, &POLICY), Err(Refusal::Protocol));
}

#[test]
fn the_origin_must_be_listed_when_a_list_is_set() {
    let p = Policy {
        path: "/mqtt",
        origins: &["https://app.example.com", "http://localhost:3000"],
    };
    assert!(upgrade::parse(&req(&good()), &p).is_ok());
    let r = with("Origin", Some("Origin: HTTPS://APP.EXAMPLE.COM"));
    assert!(upgrade::parse(&r, &p).is_ok());
    for o in [
        "https://evil.example.com",
        "https://app.example.com.evil.com",
        "https://app.example.com:443",
        "null",
        "http://app.example.com",
        "",
    ] {
        let h = format!("Origin: {o}");
        let r = with("Origin", Some(&h));
        assert_eq!(upgrade::parse(&r, &p), Err(Refusal::Origin), "{o}");
    }
    // No Origin: not a browser, so not a cross-site request.
    let r = with("Origin", None);
    assert!(upgrade::parse(&r, &p).is_ok());
    // An empty list takes any origin.
    let r = with("Origin", Some("Origin: https://anything.example"));
    assert!(upgrade::parse(&r, &POLICY).is_ok());
}

#[test]
fn version_method_and_path_have_their_own_answers() {
    for v in ["8", "12", "14", "13, 8", ""] {
        let h = format!("Sec-WebSocket-Version: {v}");
        let r = with("Sec-WebSocket-Version", Some(&h));
        assert_eq!(upgrade::parse(&r, &POLICY), Err(Refusal::Version), "{v}");
    }
    let r = with("Sec-WebSocket-Version", None);
    assert_eq!(upgrade::parse(&r, &POLICY), Err(Refusal::Version));
    let mut l = good();
    l[0] = "POST /mqtt HTTP/1.1";
    assert_eq!(upgrade::parse(&req(&l), &POLICY), Err(Refusal::Method));
    for target in ["/", "/mqtt/", "/MQTT", "/mqtt?x=1", "http://h/mqtt", "*"] {
        let line = format!("GET {target} HTTP/1.1");
        let mut l = good();
        l[0] = &line;
        assert_eq!(
            upgrade::parse(&req(&l), &POLICY),
            Err(Refusal::Path),
            "{target}"
        );
    }
    assert_eq!(
        Refusal::Version.response(),
        b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
}

#[test]
fn malformed_requests_are_refused() {
    let bad: Vec<Vec<u8>> = vec![
        // Request line.
        with("GET", Some("x")),
        req(&["GET /mqtt HTTP/1.0", "Host: x"]),
        req(&["GET /mqtt HTTP/2", "Host: x"]),
        req(&["GET  /mqtt HTTP/1.1"]),
        req(&["GET /mqtt HTTP/1.1 extra"]),
        req(&["G(T /mqtt HTTP/1.1"]),
        // Headers missing or wrong.
        with("Host", None),
        with("Host", Some("Host:")),
        with("Upgrade", None),
        with("Upgrade", Some("Upgrade: h2c")),
        with("Connection", None),
        with("Connection", Some("Connection: keep-alive")),
        with("Sec-WebSocket-Key", None),
        with("Sec-WebSocket-Key", Some("Sec-WebSocket-Key: short")),
        with(
            "Sec-WebSocket-Key",
            Some("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ"),
        ),
        with(
            "Sec-WebSocket-Key",
            Some("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZR=="),
        ),
        with(
            "Sec-WebSocket-Key",
            Some("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25j!Q=="),
        ),
        // Duplicates.
        {
            let mut l = good();
            l.push("Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==");
            req(&l)
        },
        {
            let mut l = good();
            l.push("Origin: https://app.example.com");
            req(&l)
        },
        {
            let mut l = good();
            l.push("Host: other");
            req(&l)
        },
        // Bodies.
        {
            let mut l = good();
            l.push("Transfer-Encoding: chunked");
            req(&l)
        },
        {
            let mut l = good();
            l.push("Content-Length: 5");
            req(&l)
        },
        // Syntax.
        {
            let mut l = good();
            l.push(" folded: continuation");
            req(&l)
        },
        {
            let mut l = good();
            l.push("Bad Name: x");
            req(&l)
        },
        {
            let mut l = good();
            l.push("Name : x");
            req(&l)
        },
        {
            let mut l = good();
            l.push("NoColon");
            req(&l)
        },
        {
            let mut l = good();
            l.push("X-Ctl: a\u{1}b");
            req(&l)
        },
        good()
            .join("\n")
            .into_bytes()
            .into_iter()
            .chain(*b"\r\n\r\n")
            .collect(),
        {
            let mut r = req(&good());
            r.insert(20, b'\r');
            r
        },
        b"\r\n\r\n".to_vec(),
    ];
    for (i, r) in bad.iter().enumerate() {
        assert_eq!(
            upgrade::parse(r, &POLICY),
            Err(Refusal::Malformed),
            "case {i}: {:?}",
            String::from_utf8_lossy(r)
        );
    }
    let mut l = good();
    l.push("Content-Length: 0");
    assert!(upgrade::parse(&req(&l), &POLICY).is_ok());
}

#[test]
fn size_and_header_count_are_bounded() {
    // 32 header lines pass, 33 do not.
    let mut l = good();
    let extra: Vec<String> = (l.len()..32).map(|i| format!("X-{i}: v")).collect();
    l.extend(extra.iter().map(String::as_str));
    assert_eq!(l.len() - 1, 31);
    l.push("X-last: v");
    assert!(upgrade::parse(&req(&l), &POLICY).is_ok());
    l.push("X-over: v");
    assert_eq!(upgrade::parse(&req(&l), &POLICY), Err(Refusal::Malformed));
    // scan: no end within 4096 bytes is too large, whatever follows.
    let big = vec![b'a'; upgrade::MAX_REQUEST];
    assert_eq!(upgrade::scan(&big), Scan::TooLarge);
    assert_eq!(upgrade::scan(&big[..4095]), Scan::Incomplete);
    let mut late = vec![b'a'; upgrade::MAX_REQUEST - 2];
    late.extend_from_slice(b"\r\n\r\n");
    assert_eq!(upgrade::scan(&late), Scan::TooLarge);
    // Bytes after the request are left to the caller (frames).
    let mut r = req(&good());
    let end = r.len();
    r.extend_from_slice(&[0x82, 0x80, 1, 2, 3, 4]);
    assert_eq!(upgrade::scan(&r), Scan::Complete { end });
}

#[test]
fn every_refusal_is_a_fixed_closing_response() {
    for r in Refusal::ALL {
        let t = r.response();
        assert!(t.starts_with(b"HTTP/1.1 4"));
        assert!(t.ends_with(b"Connection: close\r\nContent-Length: 0\r\n\r\n"));
        assert!(!r.name().is_empty());
    }
}

// ---- framing ---------------------------------------------------------------

const MQTT: Config = Config {
    max_message: 1 << 20,
    text: false,
};

#[derive(Debug, PartialEq, Eq, Clone)]
enum Ev {
    Data(Vec<u8>, bool),
    End(bool),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>, Vec<u8>),
}

/// Feeds `input` in pieces of `step` bytes; the events (adjacent data merged)
/// and the result.
fn run(cfg: Config, input: &[u8], step: usize) -> (Vec<Ev>, Result<(), Violation>) {
    let mut d = Decoder::new(cfg);
    let mut evs: Vec<Ev> = Vec::new();
    let mut buf = input.to_vec();
    let mut res = Ok(());
    for chunk in buf.chunks_mut(step.max(1)) {
        res = d.feed(chunk, &mut |e| {
            let e = match e {
                Event::Data { bytes, text } => {
                    if let Some(Ev::Data(v, t)) = evs.last_mut()
                        && *t == text
                    {
                        v.extend_from_slice(bytes);
                        return;
                    }
                    Ev::Data(bytes.to_vec(), text)
                }
                Event::End { text } => Ev::End(text),
                Event::Ping(p) => Ev::Ping(p.to_vec()),
                Event::Pong(p) => Ev::Pong(p.to_vec()),
                Event::Close { code, reason } => Ev::Close(code, reason.to_vec()),
            };
            evs.push(e);
        });
        if res.is_err() {
            break;
        }
    }
    (evs, res)
}

/// A masked client frame.
fn client(fin: bool, opcode: u8, mask: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
    let n = payload.len();
    if n < 126 {
        f.push(0x80 | n as u8);
    } else if n <= 0xffff {
        f.push(0x80 | 126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(n as u64).to_be_bytes());
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// RFC 6455 section 5.7: "a single-frame masked text message" and "a masked
/// Pong" (both contain "Hello").
#[test]
fn rfc_6455_masking_examples() {
    let text = [
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    let cfg = Config { text: true, ..MQTT };
    assert_eq!(
        run(cfg, &text, 64),
        (
            vec![Ev::Data(b"Hello".to_vec(), true), Ev::End(true)],
            Ok(())
        )
    );
    // The broker refuses text frames: 1003.
    let (_, r) = run(MQTT, &text, 64);
    assert_eq!(r, Err(Violation::Text));
    assert_eq!(Violation::Text.code(), close::UNSUPPORTED_DATA);
    let pong = [
        0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    assert_eq!(
        run(MQTT, &pong, 64),
        (vec![Ev::Pong(b"Hello".to_vec())], Ok(()))
    );
    // The same frames unmasked (as RFC 6455 shows them from a server) are
    // refused from a client.
    for unmasked in [
        &[0x81u8, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f][..],
        &[0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f],
        &[0x82, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f],
    ] {
        let cfg = Config { text: true, ..MQTT };
        assert_eq!(run(cfg, unmasked, 64).1, Err(Violation::Unmasked));
    }
}

/// RFC 6455 section 5.7: the server's 256-byte and 64 KiB binary headers.
#[test]
fn rfc_6455_length_examples_from_the_server() {
    assert_eq!(
        frame::header(op::BINARY, 5),
        ([0x82, 5, 0, 0, 0, 0, 0, 0, 0, 0], 2)
    );
    let (h, n) = frame::header(op::BINARY, 256);
    assert_eq!(&h[..n], &[0x82, 0x7e, 0x01, 0x00]);
    let (h, n) = frame::header(op::BINARY, 65536);
    assert_eq!(&h[..n], &[0x82, 0x7f, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00]);
    let (h, n) = frame::header(op::BINARY, 125);
    assert_eq!(&h[..n], &[0x82, 125]);
    let (h, n) = frame::header(op::BINARY, 126);
    assert_eq!(&h[..n], &[0x82, 126, 0, 126]);
    let (h, n) = frame::header(op::BINARY, 65535);
    assert_eq!(&h[..n], &[0x82, 126, 0xff, 0xff]);
    assert_eq!(frame::close_frame(1000), [0x88, 2, 0x03, 0xe8]);
    let (p, n) = frame::pong_frame(b"Hello");
    assert_eq!(&p[..n], b"\x8a\x05Hello");
}

#[test]
fn binary_messages_stream_through_and_fragments_continue() {
    let m = [9, 8, 7, 6];
    let mut input = client(true, op::BINARY, m, b"\x10\x0c\x00\x04MQTT");
    input.extend(client(false, op::BINARY, m, b"ab"));
    // A ping between fragments is answered at once (RFC 6455 5.4).
    input.extend(client(true, op::PING, m, b"p"));
    input.extend(client(false, op::CONTINUATION, m, b""));
    input.extend(client(true, op::CONTINUATION, m, b"cd"));
    input.extend(client(true, op::CLOSE, m, &[0x03, 0xe8, b'o', b'k']));
    // Ignored: after the close.
    input.extend(client(true, op::BINARY, m, b"late"));
    let want = vec![
        Ev::Data(b"\x10\x0c\x00\x04MQTT".to_vec(), false),
        Ev::End(false),
        Ev::Data(b"ab".to_vec(), false),
        Ev::Ping(b"p".to_vec()),
        Ev::Data(b"cd".to_vec(), false),
        Ev::End(false),
        Ev::Close(Some(1000), b"ok".to_vec()),
    ];
    for step in [1, 2, 3, 7, 1000] {
        assert_eq!(
            run(MQTT, &input, step),
            (want.clone(), Ok(())),
            "step {step}"
        );
    }
}

#[test]
fn every_violation_has_its_close_code() {
    let m = [1, 2, 3, 4];
    let mut ten = client(true, op::BINARY, m, &[0; 200]);
    // 126 written as 16-bit length 125: not the shortest form.
    let mut short16 = vec![0x82, 0xfe, 0, 125];
    short16.extend_from_slice(&m);
    let mut short64 = vec![0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    short64.extend_from_slice(&m);
    let mut top_bit = vec![0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0];
    top_bit.extend_from_slice(&m);
    ten.truncate(4);
    let cases: Vec<(Vec<u8>, Violation)> = vec![
        (vec![0xc2, 0x80, 0, 0, 0, 0], Violation::ReservedBits),
        (vec![0xa2, 0x80, 0, 0, 0, 0], Violation::ReservedBits),
        (vec![0x92, 0x80, 0, 0, 0, 0], Violation::ReservedBits),
        (vec![0x83, 0x80, 0, 0, 0, 0], Violation::UnknownOpcode),
        (vec![0x87, 0x80, 0, 0, 0, 0], Violation::UnknownOpcode),
        (vec![0x8b, 0x80, 0, 0, 0, 0], Violation::UnknownOpcode),
        (vec![0x8f, 0x80, 0, 0, 0, 0], Violation::UnknownOpcode),
        (vec![0x82, 0x00], Violation::Unmasked),
        (vec![0x89, 0xfe, 0, 126], Violation::ControlTooLong),
        (vec![0x09, 0x80, 0, 0, 0, 0], Violation::ControlFragmented),
        (vec![0x08, 0x80, 0, 0, 0, 0], Violation::ControlFragmented),
        (
            client(true, op::CONTINUATION, m, b"x"),
            Violation::StrayContinuation,
        ),
        (
            [
                client(false, op::BINARY, m, b"x"),
                client(true, op::BINARY, m, b"y"),
            ]
            .concat(),
            Violation::MessageInterleaved,
        ),
        (short16, Violation::BadLength),
        (short64, Violation::BadLength),
        (top_bit, Violation::BadLength),
        (client(true, op::CLOSE, m, &[3]), Violation::BadCloseCode),
        (
            client(true, op::CLOSE, m, &[0x03, 0xe7]),
            Violation::BadCloseCode,
        ),
        (
            client(true, op::CLOSE, m, &[0x03, 0xec]),
            Violation::BadCloseCode,
        ),
        (
            client(true, op::CLOSE, m, &[0x03, 0xed]),
            Violation::BadCloseCode,
        ),
        (
            client(true, op::CLOSE, m, &[0x03, 0xee]),
            Violation::BadCloseCode,
        ),
        (
            client(true, op::CLOSE, m, &[0x13, 0x88]),
            Violation::BadCloseCode,
        ),
        (
            client(true, op::CLOSE, m, &[0x03, 0xe8, 0xce, 0xba, 0xe1, 0xbd]),
            Violation::BadCloseReason,
        ),
        (client(true, op::TEXT, m, b"x"), Violation::Text),
    ];
    for (i, (input, want)) in cases.iter().enumerate() {
        for step in [1, 100] {
            assert_eq!(run(MQTT, input, step).1, Err(*want), "case {i} step {step}");
        }
    }
    assert_eq!(Violation::BadCloseReason.code(), close::INVALID_PAYLOAD);
    assert_eq!(Violation::TooBig.code(), close::TOO_BIG);
    for v in Violation::ALL {
        if !matches!(
            v,
            Violation::Text | Violation::BadCloseReason | Violation::TooBig
        ) {
            assert_eq!(v.code(), close::PROTOCOL_ERROR, "{v:?}");
        }
        assert!(!v.text().is_empty());
    }
}

#[test]
fn close_codes_follow_rfc_6455_and_the_registry() {
    for ok in [
        1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000,
        4999,
    ] {
        assert!(frame::valid_close_code(ok), "{ok}");
    }
    for bad in [
        0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535,
    ] {
        assert!(!frame::valid_close_code(bad), "{bad}");
    }
    let m = [0; 4];
    assert_eq!(
        run(MQTT, &client(true, op::CLOSE, m, b""), 9),
        (vec![Ev::Close(None, vec![])], Ok(()))
    );
}

/// The message limit applies to the header's announced length, before any
/// payload, and to the sum of a message's fragments.
#[test]
fn the_message_limit_is_checked_at_the_header() {
    let cfg = Config {
        max_message: 10,
        text: false,
    };
    let m = [5; 4];
    assert_eq!(
        run(cfg, &client(true, op::BINARY, m, &[0; 10]), 3).1,
        Ok(())
    );
    // Eleven announced: refused with only the header fed.
    let mut d = Decoder::new(cfg);
    let mut hdr = vec![0x82, 0x80 | 11, 5, 5, 5, 5];
    assert_eq!(d.feed(&mut hdr, &mut |_| {}), Err(Violation::TooBig));
    assert!(d.is_done());
    // A 2^62-byte frame announced: refused at its header.
    let mut d = Decoder::new(MQTT);
    let mut hdr = vec![0x82, 0xff, 0x40, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
    assert_eq!(d.feed(&mut hdr, &mut |_| {}), Err(Violation::TooBig));
    // Fragments add up.
    let input = [
        client(false, op::BINARY, m, &[0; 6]),
        client(true, op::CONTINUATION, m, &[0; 5]),
    ]
    .concat();
    assert_eq!(run(cfg, &input, 4).1, Err(Violation::TooBig));
    // A new message starts from zero.
    let input = [
        client(true, op::BINARY, m, &[0; 6]),
        client(true, op::BINARY, m, &[0; 6]),
    ]
    .concat();
    assert_eq!(run(cfg, &input, 4).1, Ok(()));
}

#[test]
fn large_frames_use_the_16_and_64_bit_lengths() {
    let m = [0xde, 0xad, 0xbe, 0xef];
    // Miri: the two boundaries only (the long ones take minutes there).
    let sizes: &[usize] = if cfg!(miri) {
        &[126, 65536]
    } else {
        &[126, 1000, 65535, 65536, 200_000]
    };
    for &n in sizes {
        let payload: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        let (evs, r) = run(MQTT, &client(true, op::BINARY, m, &payload), 4093);
        assert_eq!(r, Ok(()));
        assert_eq!(evs, vec![Ev::Data(payload, false), Ev::End(false)], "{n}");
    }
}

#[test]
fn the_decoder_stops_after_a_violation_or_a_close() {
    let mut d = Decoder::new(MQTT);
    let mut bad = vec![0x82, 0x00];
    assert!(d.feed(&mut bad, &mut |_| {}).is_err());
    let mut more = client(true, op::BINARY, [0; 4], b"x");
    let mut n = 0;
    assert_eq!(d.feed(&mut more, &mut |_| n += 1), Ok(()));
    assert_eq!(n, 0);
    assert!(!Decoder::new(MQTT).mid_frame());
}

proptest! {
    /// Any split of a valid stream gives the same events.
    #[test]
    fn any_split_gives_the_same_events(
        frames in prop::collection::vec((0u8..4, prop::collection::vec(any::<u8>(), 0..300), any::<[u8; 4]>()), 0..8),
        step in 1usize..64,
    ) {
        let mut input = Vec::new();
        let mut open = false;
        for (kind, payload, mask) in &frames {
            let f = match kind {
                0 => { let f = client(true, if open { op::CONTINUATION } else { op::BINARY }, *mask, payload); open = false; f }
                1 => { let f = client(false, if open { op::CONTINUATION } else { op::BINARY }, *mask, payload); open = true; f }
                2 => client(true, op::PING, *mask, &payload[..payload.len().min(125)]),
                _ => client(true, op::PONG, *mask, &payload[..payload.len().min(125)]),
            };
            input.extend(f);
        }
        let whole = run(MQTT, &input, usize::MAX);
        prop_assert_eq!(whole.1, Ok(()));
        prop_assert_eq!(run(MQTT, &input, step), whole);
    }

    /// No input panics, whatever the split and the limit.
    #[test]
    fn garbage_never_panics(input in prop::collection::vec(any::<u8>(), 0..512), step in 1usize..32, max in 0u64..2048) {
        let _ = run(Config { max_message: max, text: true }, &input, step);
        let _ = run(Config { max_message: max, text: false }, &input, step);
    }

    /// No request panics; whatever is accepted has a well-formed response.
    #[test]
    fn any_request_is_answered(input in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = upgrade::scan(&input);
        if let Ok(a) = upgrade::parse(&input, &POLICY) {
            let mut out = [0u8; upgrade::MAX_RESPONSE];
            let n = a.response(&mut out);
            prop_assert!(out[..n].ends_with(b"\r\n\r\n"));
        }
    }
}
