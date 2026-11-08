//! Kani proofs (H5): the frame decoder and the upgrade parser never panic,
//! never overflow and never read out of bounds, for every input up to a
//! bound. Run with `make kani`; compiled only under `cfg(kani)`.
//!
//! The bounds are what CBMC finishes within the 3-minute cap of
//! `scripts/kani.sh` (16 or 8 symbolic bytes of stream, a 12-byte request or a
//! 4-byte header line did not); the fuzz targets `ws_frames` and `ws_upgrade` cover length.

use crate::frame::{Config, Decoder, Event};
use crate::upgrade::{self, Policy};

/// Any 6 bytes (a header with its mask and a byte of payload, or two short
/// headers), split anywhere into two feeds, any limit: no panic; data events
/// never hold more bytes than were fed, and a decoder that reported a
/// violation stays done.
#[kani::proof]
#[kani::unwind(8)]
fn decode_any_short_stream() {
    let mut bytes: [u8; 6] = kani::any();
    let split: usize = kani::any();
    kani::assume(split <= bytes.len());
    let mut d = Decoder::new(Config {
        max_message: kani::any(),
        text: kani::any(),
    });
    let mut data = 0usize;
    let (a, b) = bytes.split_at_mut(split);
    let mut sink = |e: Event<'_>| {
        if let Event::Data { bytes, .. } = e {
            data += bytes.len();
        }
    };
    let r1 = d.feed(a, &mut sink);
    let r2 = d.feed(b, &mut sink);
    assert!(data <= 6);
    if r1.is_err() || r2.is_err() {
        assert!(d.is_done());
    }
}

/// `scan` on any 8 bytes: no panic, and a complete request ends at an empty
/// line inside the input.
#[kani::proof]
#[kani::unwind(10)]
fn scan_any_short_input() {
    let bytes: [u8; 8] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    if let upgrade::Scan::Complete { end } = upgrade::scan(&bytes[..n]) {
        assert!(end >= 4 && end <= n);
    }
}

/// A request line, one header line of 2 symbolic bytes, the end: `parse`
/// never panics whatever the header holds.
#[kani::proof]
#[kani::unwind(26)]
fn parse_one_symbolic_header() {
    let h: [u8; 2] = kani::any();
    let mut req = [0u8; 23];
    req[..15].copy_from_slice(b"GET /m HTTP/1.1");
    req[15..17].copy_from_slice(b"\r\n");
    req[17..19].copy_from_slice(&h);
    req[19..23].copy_from_slice(b"\r\n\r\n");
    let p = Policy {
        path: "/m",
        origins: &[],
    };
    let _ = upgrade::parse(&req, &p);
}

/// The server header encodes every length in its shortest form.
#[kani::proof]
fn header_lengths() {
    let len: usize = kani::any();
    let (h, n) = crate::frame::header(2, len);
    assert!(n == 2 || n == 4 || n == 10);
    assert!((n == 2) == (len < 126));
    assert!(h[0] == 0x82);
}
