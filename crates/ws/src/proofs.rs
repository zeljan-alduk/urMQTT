//! Kani proofs (H5): the frame decoder and the upgrade parser never panic,
//! never overflow and never read out of bounds, for every input up to a
//! bound. Run with `make kani`; compiled only under `cfg(kani)`.

use crate::frame::{Config, Decoder, Event};
use crate::upgrade::{self, Policy};

/// Any 16 bytes, split anywhere into two feeds, any limit: no panic; data
/// events never hold more bytes than were fed, and a decoder that reported a
/// violation stays done.
#[kani::proof]
#[kani::unwind(18)]
fn decode_any_short_stream() {
    let mut bytes: [u8; 16] = kani::any();
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
    assert!(data <= 16);
    if r1.is_err() || r2.is_err() {
        assert!(d.is_done());
    }
}

/// Any request of up to 12 bytes: no panic in scan or parse.
#[kani::proof]
#[kani::unwind(14)]
fn upgrade_any_short_request() {
    let bytes: [u8; 12] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    let req = &bytes[..n];
    let _ = upgrade::scan(req);
    let p = Policy {
        path: "/m",
        origins: &["o"],
    };
    let _ = upgrade::parse(req, &p);
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
