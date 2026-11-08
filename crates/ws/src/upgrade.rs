//! The opening handshake (RFC 6455 section 4.2), server side, and nothing
//! else of HTTP.
//!
//! The broker is not a web server. It reads **one** request, which must be a
//! WebSocket upgrade to the configured path offering the `mqtt` subprotocol
//! (MQTT 3.1.1 section 6), and answers it with `101 Switching Protocols` or a
//! fixed refusal and a close. There is no body, no chunked encoding, no
//! keep-alive, no second request, no static file, no CORS preflight, no
//! redirect and no header the client chose is ever echoed back.
//!
//! Bounds, before any parsing work: the request (request line and headers,
//! up to and including the empty line) is at most [`MAX_REQUEST`] bytes and
//! [`MAX_HEADERS`] header lines; the caller stops buffering at that size
//! ([`scan`]). Parsing is a single pass over that buffer without allocation.
//!
//! What is checked (RFC 6455 4.2.1, RFC 9110/9112 for the syntax):
//!
//! - request line `GET <path> HTTP/1.1`, exactly: method `GET`, a path equal
//!   to the configured one (no query, no absolute form), version `HTTP/1.1`;
//! - every line ends in CRLF, no line folding, header names are tokens,
//!   values hold no control characters;
//! - `Host` present once and not empty;
//! - `Upgrade` lists the token `websocket`, `Connection` lists `Upgrade`
//!   (both case-insensitive; Firefox sends `Connection: keep-alive, Upgrade`);
//! - `Sec-WebSocket-Key` is 24 characters of base64 that decode to 16 bytes;
//! - `Sec-WebSocket-Version` is `13` (anything else: 426 naming 13);
//! - `Sec-WebSocket-Protocol` offers `mqtt` (preferred) or `mqttv3.1`;
//! - `Origin`, when sent (every browser sends it), is one of the configured
//!   origins, if any are configured; a client that sends none (a device, a
//!   script) is not a browser and cannot be the victim of cross-site
//!   WebSocket hijacking;
//! - no `Transfer-Encoding`, and `Content-Length` absent or `0`;
//! - the headers that matter appear once (a second `Sec-WebSocket-Key` or
//!   `Origin` is a refusal, not "the last one wins"); other headers are
//!   ignored but counted and bounded.

use crate::sha1;

/// Longest request accepted, request line and headers with the final CRLF.
/// Browsers send 500 to 1500 bytes for an upgrade; cookies of the broker's own
/// site would count too.
pub const MAX_REQUEST: usize = 4096;
/// Most header lines in a request.
pub const MAX_HEADERS: usize = 32;
/// Longest `Sec-WebSocket-Accept` response (`101` with every header).
pub const MAX_RESPONSE: usize = 160;

/// The GUID of RFC 6455 section 1.3.
const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Where a request being received stands ([`scan`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// No end of headers yet and still under the limit: wait for more.
    Incomplete,
    /// The request ends here: the first `end` bytes are the request, anything
    /// after them is already WebSocket data.
    Complete { end: usize },
    /// [`MAX_REQUEST`] bytes without an end of headers.
    TooLarge,
}

/// Looks for the empty line that ends the headers in the bytes received so
/// far. Never reads past [`MAX_REQUEST`].
pub fn scan(buf: &[u8]) -> Scan {
    let window = buf.get(..buf.len().min(MAX_REQUEST)).unwrap_or(&[]);
    match window.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => Scan::Complete { end: i + 4 },
        None if buf.len() >= MAX_REQUEST => Scan::TooLarge,
        None => Scan::Incomplete,
    }
}

/// The subprotocol agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `mqtt`: MQTT 3.1.1 and later (MQTT 3.1.1 section 6).
    Mqtt,
    /// `mqttv3.1`: what MQTT 3.1 clients offer (Paho's older JavaScript
    /// client). The CONNECT inside still decides which MQTT it is.
    MqttV31,
}

impl Protocol {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mqtt => "mqtt",
            Self::MqttV31 => "mqttv3.1",
        }
    }
}

/// Why a request is refused. Each maps to a fixed response
/// ([`Refusal::response`]) and a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not an HTTP/1.1 request we can read: bad syntax, too large, too many
    /// headers, a body, a duplicate header, a missing or bad `Host`, `Upgrade`,
    /// `Connection` or `Sec-WebSocket-Key`. 400.
    Malformed,
    /// A method other than GET. 405 would invite a second request; 400.
    Method,
    /// The path is not the configured one. 404.
    Path,
    /// `Sec-WebSocket-Version` is not 13. 426 with `Sec-WebSocket-Version: 13`.
    Version,
    /// No `mqtt` or `mqttv3.1` subprotocol offered. 400.
    Protocol,
    /// The `Origin` is not on the allowlist. 403.
    Origin,
}

impl Refusal {
    pub const ALL: [Self; 6] = [
        Self::Malformed,
        Self::Method,
        Self::Path,
        Self::Version,
        Self::Protocol,
        Self::Origin,
    ];

    /// Index for counter arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The counter name (`$SYS/broker/websocket/refused/<name>`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malformed => "request",
            Self::Method => "method",
            Self::Path => "path",
            Self::Version => "version",
            Self::Protocol => "protocol",
            Self::Origin => "origin",
        }
    }

    /// The whole response: a fixed text that names nothing the client sent,
    /// with `Connection: close`; the caller closes after it.
    pub const fn response(self) -> &'static [u8] {
        match self {
            Self::Malformed | Self::Method | Self::Protocol => {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::Path => b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Version => {
                b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::Origin => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        }
    }
}

/// What the request must match, from the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// The request target, e.g. `/mqtt`.
    pub path: &'a str,
    /// Allowed origins (`https://app.example.com`, compared without regard to
    /// ASCII case, as origins are lower-cased by browsers anyway). Empty: any
    /// origin, which the configuration only allows with mutual TLS.
    pub origins: &'a [&'a str],
}

/// An accepted upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub protocol: Protocol,
    /// base64(SHA-1(key || GUID)).
    accept: [u8; 28],
    /// The request carried an `Origin` header (a browser).
    pub had_origin: bool,
}

impl Accepted {
    /// The `Sec-WebSocket-Accept` value.
    pub fn accept_value(&self) -> &[u8; 28] {
        &self.accept
    }

    /// The `101 Switching Protocols` response, into `out`; returns its length.
    pub fn response(&self, out: &mut [u8; MAX_RESPONSE]) -> usize {
        let parts: [&[u8]; 5] = [
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
            &self.accept,
            b"\r\nSec-WebSocket-Protocol: ",
            self.protocol.name().as_bytes(),
            b"\r\n\r\n",
        ];
        let mut n = 0;
        for p in parts {
            if let Some(d) = out.get_mut(n..n + p.len()) {
                d.copy_from_slice(p);
                n += p.len();
            }
        }
        n
    }
}

/// The value of `Sec-WebSocket-Accept` for a client's key (RFC 6455 4.2.2
/// item 5.4): base64(SHA-1(key || GUID)).
pub fn accept_key(key: &[u8]) -> [u8; 28] {
    let mut input = [0u8; 24 + 36];
    let k = key.len().min(24);
    if let (Some(d), Some(s)) = (input.get_mut(..k), key.get(..k)) {
        d.copy_from_slice(s);
    }
    if let Some(d) = input.get_mut(k..k + 36) {
        d.copy_from_slice(GUID);
    }
    base64_20(&sha1::digest(input.get(..k + 36).unwrap_or(&[])))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64 of a 20-byte digest: 28 characters, one `=`.
fn base64_20(d: &[u8; 20]) -> [u8; 28] {
    let mut out = [b'='; 28];
    let mut o = 0;
    for chunk in d.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let v = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let six = (v >> (18 - 6 * i)) & 0x3f;
            if let (Some(slot), Some(&c)) = (out.get_mut(o + i), B64.get(six as usize)) {
                *slot = c;
            }
        }
        o += 4;
    }
    out
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// A `Sec-WebSocket-Key`: base64 of 16 bytes is 24 characters ending in
/// `==`, and the last data character carries no stray bits (RFC 4648 3.5:
/// a canonical encoding).
fn valid_key(k: &[u8]) -> bool {
    if k.len() != 24 || !k.ends_with(b"==") {
        return false;
    }
    let data = k.get(..22).unwrap_or(&[]);
    if !data.iter().all(|&c| b64_value(c).is_some()) {
        return false;
    }
    // 16 bytes = 128 bits = 21 characters and 2 bits: the 22nd character's
    // low four bits must be zero.
    data.last()
        .and_then(|&c| b64_value(c))
        .is_some_and(|v| v & 0x0f == 0)
}

/// A token character (RFC 9110 5.6.2).
fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// A header value: visible ASCII, space, tab and obs-text; no control
/// characters (a bare CR or LF inside a value would split it).
fn value_ok(v: &[u8]) -> bool {
    v.iter()
        .all(|&c| c == b'\t' || c == b' ' || (0x21..=0x7e).contains(&c) || c >= 0x80)
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(start, |i| i + 1);
    v.get(start..end.max(start)).unwrap_or(&[])
}

/// Whether the comma-separated list `v` holds `token` (ASCII case-insensitive).
fn list_has(v: &[u8], token: &[u8]) -> bool {
    v.split(|&c| c == b',')
        .any(|t| trim_ows(t).eq_ignore_ascii_case(token))
}

/// The headers that matter, each at most once.
#[derive(Default)]
struct Seen<'a> {
    host: Option<&'a [u8]>,
    upgrade: Option<&'a [u8]>,
    connection: Option<&'a [u8]>,
    key: Option<&'a [u8]>,
    version: Option<&'a [u8]>,
    origin: Option<&'a [u8]>,
    content_length: Option<&'a [u8]>,
    /// `Sec-WebSocket-Protocol` may legally be split over several lines.
    mqtt: bool,
    mqttv31: bool,
}

fn set_once<'a>(slot: &mut Option<&'a [u8]>, v: &'a [u8]) -> Result<(), Refusal> {
    if slot.is_some() {
        return Err(Refusal::Malformed);
    }
    *slot = Some(v);
    Ok(())
}

/// Reads the request `req` (exactly what [`scan`] delimited, ending in the
/// empty line) against `policy`. Syntax is checked over the whole request
/// first, so a malformed request is always [`Refusal::Malformed`] whatever
/// else it says.
pub fn parse(req: &[u8], policy: &Policy<'_>) -> Result<Accepted, Refusal> {
    if req.len() > MAX_REQUEST || !req.ends_with(b"\r\n\r\n") {
        return Err(Refusal::Malformed);
    }
    let head = req.get(..req.len() - 4).unwrap_or(&[]);
    // Every LF follows a CR and every CR precedes an LF: lines end in CRLF
    // only (no bare LF, no bare CR that a proxy might read differently).
    for (i, &c) in head.iter().enumerate() {
        let bad = match c {
            b'\n' => i == 0 || head.get(i - 1) != Some(&b'\r'),
            b'\r' => head.get(i + 1) != Some(&b'\n'),
            _ => false,
        };
        if bad {
            return Err(Refusal::Malformed);
        }
    }
    let mut lines = head
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = lines.next().ok_or(Refusal::Malformed)?;
    let mut parts = request_line.split(|&c| c == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::Malformed);
    };
    if method.is_empty()
        || !method.iter().all(|&c| tchar(c))
        || target.is_empty()
        || !target.iter().all(|&c| (0x21..=0x7e).contains(&c))
        || version != b"HTTP/1.1"
    {
        return Err(Refusal::Malformed);
    }
    let mut seen = Seen::default();
    let mut count = 0usize;
    for line in lines {
        count += 1;
        if count > MAX_HEADERS || line.is_empty() {
            return Err(Refusal::Malformed);
        }
        // Line folding (obs-fold) is refused (RFC 9112 5.2).
        let colon = line
            .iter()
            .position(|&c| c == b':')
            .ok_or(Refusal::Malformed)?;
        let name = line.get(..colon).unwrap_or(&[]);
        let value = line.get(colon + 1..).unwrap_or(&[]);
        // No whitespace in or around the name (RFC 9112 5.1).
        if name.is_empty() || !name.iter().all(|&c| tchar(c)) || !value_ok(value) {
            return Err(Refusal::Malformed);
        }
        let v = trim_ows(value);
        let is = |n: &str| name.eq_ignore_ascii_case(n.as_bytes());
        if is("host") {
            set_once(&mut seen.host, v)?;
        } else if is("upgrade") {
            set_once(&mut seen.upgrade, v)?;
        } else if is("connection") {
            set_once(&mut seen.connection, v)?;
        } else if is("sec-websocket-key") {
            set_once(&mut seen.key, v)?;
        } else if is("sec-websocket-version") {
            set_once(&mut seen.version, v)?;
        } else if is("origin") {
            set_once(&mut seen.origin, v)?;
        } else if is("content-length") {
            set_once(&mut seen.content_length, v)?;
        } else if is("transfer-encoding") {
            // No body of any kind.
            return Err(Refusal::Malformed);
        } else if is("sec-websocket-protocol") {
            seen.mqtt |= list_has(v, b"mqtt");
            seen.mqttv31 |= list_has(v, b"mqttv3.1");
        }
        // Every other header (User-Agent, Cookie, Sec-WebSocket-Extensions,
        // ...) is ignored: no extension is ever agreed on.
    }
    // Semantics, in the order a client can best act on.
    if method != b"GET" {
        return Err(Refusal::Method);
    }
    if target != policy.path.as_bytes() {
        return Err(Refusal::Path);
    }
    let key = match (seen.host, seen.upgrade, seen.connection, seen.key) {
        (Some(h), Some(u), Some(c), Some(k))
            if !h.is_empty()
                && list_has(u, b"websocket")
                && list_has(c, b"upgrade")
                && valid_key(k) =>
        {
            k
        }
        _ => return Err(Refusal::Malformed),
    };
    if seen.content_length.is_some_and(|l| l != b"0") {
        return Err(Refusal::Malformed);
    }
    if seen.version != Some(b"13".as_slice()) {
        return Err(Refusal::Version);
    }
    let protocol = if seen.mqtt {
        Protocol::Mqtt
    } else if seen.mqttv31 {
        Protocol::MqttV31
    } else {
        return Err(Refusal::Protocol);
    };
    if let Some(o) = seen.origin
        && !policy.origins.is_empty()
        && !policy
            .origins
            .iter()
            .any(|a| a.as_bytes().eq_ignore_ascii_case(o))
    {
        return Err(Refusal::Origin);
    }
    Ok(Accepted {
        protocol,
        accept: accept_key(key),
        had_origin: seen.origin.is_some(),
    })
}
