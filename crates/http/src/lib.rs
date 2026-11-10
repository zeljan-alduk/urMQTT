//! The metrics endpoint's HTTP/1.1 request reader (NEXT-9, ADR-290).
//!
//! The broker is not a web server. The Prometheus listener reads **one**
//! request, which must be `GET` or `HEAD` for a path the caller serves,
//! answers it and closes the connection. There is no body, no chunked
//! encoding, no keep-alive, no second request, no query string, no redirect,
//! no static file, and nothing the client sent is ever echoed back.
//!
//! Bounds, before any parsing work: the request (request line and headers,
//! up to and including the empty line) is at most [`MAX_REQUEST`] bytes and
//! [`MAX_HEADERS`] header lines; the caller stops buffering at that size
//! ([`scan`]). Parsing is a single pass over that buffer without allocation.
//!
//! What is checked (RFC 9110 and 9112 for the syntax):
//!
//! - request line `METHOD SP target SP HTTP/1.1` (or `HTTP/1.0`), exactly one
//!   space each; the target is `/` and visible ASCII, at most
//!   [`MAX_TARGET`] bytes, no `#`;
//! - every line ends in CRLF (a bare LF is refused), no line folding, header
//!   names are tokens, values hold no control characters;
//! - no `Transfer-Encoding`, and `Content-Length` absent or `0`, once;
//! - `Accept` is read for one decision only: OpenMetrics or the classic text
//!   format, by quality value ([`Format`]).
//!
//! Everything else in the headers is ignored but counted and bounded.
//!
//! The crate is `no_std`, `forbid(unsafe_code)`, free of panics by lint, and
//! fuzzed (`fuzz/fuzz_targets/http_request`).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

/// Longest request accepted, request line and headers with the final CRLF.
/// Prometheus sends about 300 bytes; a browser with cookies of its own site
/// can send more, and is refused (431) rather than read.
pub const MAX_REQUEST: usize = 2048;
/// Most header lines in a request.
pub const MAX_HEADERS: usize = 24;
/// Longest request target.
pub const MAX_TARGET: usize = 128;
/// Room for the head of a `200` response ([`ok_head`]).
pub const MAX_HEAD: usize = 192;

/// Where a request being received stands ([`scan`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// No end of headers yet and still under the limit: wait for more.
    Incomplete,
    /// The request ends here: the first `end` bytes are the request; anything
    /// after them is ignored (the connection closes after the answer).
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

/// The two request methods served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    /// The same answer without the body.
    Head,
}

/// The exposition format the client prefers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Prometheus text format 0.0.4 (also what a client without `Accept` gets).
    Prometheus,
    /// OpenMetrics 1.0.0 text.
    OpenMetrics,
}

impl Format {
    /// The `Content-Type` of the answer.
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Prometheus => "text/plain; version=0.0.4; charset=utf-8",
            Self::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }
}

/// A request that is well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: Method,
    /// The request target, checked to be `/` followed by visible ASCII.
    pub target: &'a str,
    pub format: Format,
}

/// Why a request is refused. Each maps to a fixed response
/// ([`Refusal::response`]) and a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not an HTTP request we can read: bad syntax, a body, a duplicate
    /// `Content-Length`, `Transfer-Encoding`. 400.
    Malformed,
    /// More than [`MAX_REQUEST`] bytes or [`MAX_HEADERS`] header lines. 431.
    TooLarge,
    /// A method other than GET and HEAD. 405.
    Method,
    /// A version other than HTTP/1.1 and HTTP/1.0. 505.
    Version,
    /// A well-formed request for a path that is not served. 404 (the caller
    /// picks it; [`parse`] never returns it).
    NotFound,
}

impl Refusal {
    pub const ALL: [Self; 5] = [
        Self::Malformed,
        Self::TooLarge,
        Self::Method,
        Self::Version,
        Self::NotFound,
    ];

    /// Index for counter arrays.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The counter's label value.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::Method => "method",
            Self::Version => "version",
            Self::NotFound => "not_found",
        }
    }

    /// The whole response: a fixed text that names nothing the client sent,
    /// with `Connection: close`; the caller closes after it.
    pub const fn response(self) -> &'static [u8] {
        match self {
            Self::Malformed => {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::TooLarge => {
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::Method => {
                b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::Version => {
                b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::NotFound => {
                b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
        }
    }
}

/// The head of a `200` response for a body of `len` bytes, into `out`;
/// returns its length. `Connection: close` always: one request, one answer.
pub fn ok_head(format: Format, len: usize, out: &mut [u8; MAX_HEAD]) -> usize {
    let mut digits = [0u8; 20];
    let mut d = digits.len();
    let mut v = len;
    loop {
        d -= 1;
        if let Some(slot) = digits.get_mut(d) {
            *slot = b'0' + (v % 10) as u8;
        }
        v /= 10;
        if v == 0 || d == 0 {
            break;
        }
    }
    let parts: [&[u8]; 5] = [
        b"HTTP/1.1 200 OK\r\nContent-Type: ",
        format.content_type().as_bytes(),
        b"\r\nConnection: close\r\nContent-Length: ",
        digits.get(d..).unwrap_or(&[]),
        b"\r\n\r\n",
    ];
    let mut n = 0;
    for p in parts {
        if let Some(dst) = out.get_mut(n..n + p.len()) {
            dst.copy_from_slice(p);
            n += p.len();
        }
    }
    n
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

/// The quality value of an `Accept` parameter list in thousandths (`q=0.5`
/// is 500); 1000 when there is none; 0 for anything malformed (the entry then
/// does not count).
fn quality(params: &[u8]) -> u16 {
    for p in params.split(|&c| c == b';') {
        let p = trim_ows(p);
        let Some(rest) = p.strip_prefix(b"q=").or_else(|| p.strip_prefix(b"Q=")) else {
            continue;
        };
        let mut it = rest.split(|&c| c == b'.');
        let int = it.next().unwrap_or(&[]);
        let frac = it.next();
        if it.next().is_some() {
            return 0;
        }
        let base: u16 = match int {
            b"0" => 0,
            b"1" => 1000,
            _ => return 0,
        };
        let Some(frac) = frac else { return base };
        if frac.len() > 3 || !frac.iter().all(u8::is_ascii_digit) {
            return 0;
        }
        let mut v = 0u16;
        for i in 0..3 {
            v = v * 10 + u16::from(frac.get(i).map_or(0, |c| c - b'0'));
        }
        return if base == 1000 && v != 0 { 0 } else { base + v };
    }
    1000
}

/// OpenMetrics when its quality value is above that of every media range
/// that would also take the classic text format (`text/plain`, `text/*`,
/// `*/*`); the classic format otherwise and without an `Accept` header.
fn negotiate(accept: &[u8]) -> Format {
    let (mut open, mut plain) = (0u16, 0u16);
    for range in accept.split(|&c| c == b',') {
        let mut parts = range.splitn(2, |&c| c == b';');
        let media = trim_ows(parts.next().unwrap_or(&[]));
        let q = quality(parts.next().unwrap_or(&[]));
        if media.eq_ignore_ascii_case(b"application/openmetrics-text") {
            open = open.max(q);
        } else if media.eq_ignore_ascii_case(b"text/plain")
            || media.eq_ignore_ascii_case(b"text/*")
            || media == b"*/*"
        {
            plain = plain.max(q);
        }
    }
    if open > plain {
        Format::OpenMetrics
    } else {
        Format::Prometheus
    }
}

fn set_once(slot: &mut bool) -> Result<(), Refusal> {
    if *slot {
        return Err(Refusal::Malformed);
    }
    *slot = true;
    Ok(())
}

/// Reads the request `req` (exactly what [`scan`] delimited, ending in the
/// empty line). Syntax is checked over the whole request first, so a
/// malformed request is always [`Refusal::Malformed`] whatever else it says.
pub fn parse(req: &[u8]) -> Result<Request<'_>, Refusal> {
    if req.len() > MAX_REQUEST {
        return Err(Refusal::TooLarge);
    }
    if !req.ends_with(b"\r\n\r\n") {
        return Err(Refusal::Malformed);
    }
    // Every line ends in CRLF: a lone LF or CR anywhere is a smuggling aid.
    let mut lines = req.split(|&c| c == b'\n');
    let mut method = None;
    let mut target: Option<&[u8]> = None;
    let mut version_ok = true;
    let mut headers = 0usize;
    let mut seen_len = false;
    let mut accept: &[u8] = &[];
    let mut seen_accept = false;
    let mut first = true;
    // The request is its lines up to the empty one; the empty line is the
    // last thing in it (checked after the loop).
    let mut ended = false;
    for raw in &mut lines {
        let Some(line) = raw.strip_suffix(b"\r") else {
            // A line that ends in a bare LF (or the end of the input).
            return Err(Refusal::Malformed);
        };
        if line.contains(&b'\r') {
            return Err(Refusal::Malformed);
        }
        if first {
            first = false;
            let mut p = line.split(|&c| c == b' ');
            let (m, t, v) = (p.next(), p.next(), p.next());
            if p.next().is_some() || m.is_none() || t.is_none() || v.is_none() {
                return Err(Refusal::Malformed);
            }
            let (m, t, v) = (m.unwrap_or(&[]), t.unwrap_or(&[]), v.unwrap_or(&[]));
            if m.is_empty() || !m.iter().all(|&c| tchar(c)) {
                return Err(Refusal::Malformed);
            }
            method = Some(match m {
                b"GET" => Ok(Method::Get),
                b"HEAD" => Ok(Method::Head),
                _ => Err(Refusal::Method),
            });
            if t.first() != Some(&b'/')
                || t.len() > MAX_TARGET
                || !t.iter().all(|&c| (0x21..=0x7e).contains(&c) && c != b'#')
            {
                return Err(Refusal::Malformed);
            }
            target = Some(t);
            version_ok = match v.strip_prefix(b"HTTP/") {
                Some(b"1.1" | b"1.0") => true,
                Some(n) if n.len() == 3 && n.first().is_some_and(u8::is_ascii_digit) => false,
                _ => return Err(Refusal::Malformed),
            };
            continue;
        }
        if line.is_empty() {
            ended = true;
            break;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            return Err(Refusal::TooLarge);
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            // Obsolete line folding (RFC 9112 5.2).
            return Err(Refusal::Malformed);
        }
        let colon = line
            .iter()
            .position(|&c| c == b':')
            .ok_or(Refusal::Malformed)?;
        let (name, value) = (
            line.get(..colon).unwrap_or(&[]),
            line.get(colon + 1..).unwrap_or(&[]),
        );
        if name.is_empty() || !name.iter().all(|&c| tchar(c)) || !value_ok(value) {
            return Err(Refusal::Malformed);
        }
        let value = trim_ows(value);
        if name.eq_ignore_ascii_case(b"content-length") {
            set_once(&mut seen_len)?;
            if value != b"0" {
                return Err(Refusal::Malformed);
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(Refusal::Malformed);
        } else if name.eq_ignore_ascii_case(b"accept") {
            // A second Accept header is a list continuation (RFC 9110 5.3);
            // only the first is read, which at worst picks the classic format.
            if !seen_accept {
                seen_accept = true;
                accept = value;
            }
        }
    }
    // The empty line ends the request: nothing, not even a stray LF, follows
    // it (what `scan` delimited is exactly this).
    if !ended || lines.next() != Some(&[][..]) || lines.next().is_some() {
        return Err(Refusal::Malformed);
    }
    let (Some(method), Some(target)) = (method, target) else {
        return Err(Refusal::Malformed);
    };
    if !version_ok {
        return Err(Refusal::Version);
    }
    let method = method?;
    // Checked ASCII above.
    let target = core::str::from_utf8(target).map_err(|_| Refusal::Malformed)?;
    Ok(Request {
        method,
        target,
        format: negotiate(accept),
    })
}

#[cfg(test)]
mod tests;
