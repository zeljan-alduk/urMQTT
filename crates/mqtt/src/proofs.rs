//! Kani proofs (H5): the decoder never panics and never reads out of bounds
//! for any input up to a bound. Run with `make kani`; compiled only under
//! `cfg(kani)`.
//!
//! Kani checks, for every symbolic input: arithmetic overflow, slice and
//! index bounds, unwrap/expect/panic reachability. The asserts below add
//! the contract of the return value.

use crate::{Error, Limits, Packet, decode};

fn limits() -> Limits {
    Limits {
        max_packet_size: kani::any(),
        max_topic_len: kani::any(),
        max_topic_levels: kani::any(),
        max_client_id_len: kani::any(),
        max_topics_per_packet: kani::any(),
    }
}

/// Any byte string of up to 6 bytes, any limits: no panic, and a decoded
/// packet never claims more bytes than the input holds.
#[kani::proof]
#[kani::unwind(8)]
fn decode_any_short_input() {
    let bytes: [u8; 6] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    let buf = &bytes[..n];
    let l = limits();
    match decode(buf, &l) {
        Ok((p, used)) => {
            assert!(used >= 2 && used <= buf.len());
            assert!(used as u64 <= u64::from(l.max_packet_size));
            // Touch the borrowed parts so any out-of-bounds slice is checked.
            if let Packet::Publish(p) = p {
                let _ = p.topic.len() + p.payload.len();
            }
        }
        Err(Error::Incomplete(want)) => assert!(want > buf.len() || want == 2),
        Err(_) => {}
    }
}

/// The packets with variable content a client sends: PUBLISH, SUBSCRIBE,
/// CONNECT and UNSUBSCRIBE, with a small symbolic remaining length and a
/// symbolic body.
#[kani::proof]
#[kani::unwind(10)]
fn decode_typed_packets() {
    let first: u8 = kani::any();
    kani::assume(matches!(first >> 4, 1 | 3 | 8 | 10));
    let rem: u8 = kani::any();
    kani::assume(rem <= 6);
    let body: [u8; 6] = kani::any();
    let mut buf = [0u8; 8];
    buf[0] = first;
    buf[1] = rem;
    buf[2..].copy_from_slice(&body);
    let total = 2 + usize::from(rem);
    let l = Limits {
        max_packet_size: 64,
        max_topic_len: kani::any(),
        max_topic_levels: kani::any(),
        max_client_id_len: kani::any(),
        max_topics_per_packet: kani::any(),
    };
    if let Ok((p, used)) = decode(&buf[..total], &l) {
        assert_eq!(used, total);
        match p {
            Packet::Publish(p) => {
                assert!(p.topic.len() + p.payload.len() <= total);
                assert!(p.topic.len() <= usize::from(l.max_topic_len));
            }
            Packet::Subscribe(s) => {
                assert!(s.topics.len() <= usize::from(l.max_topics_per_packet));
            }
            Packet::Connect(c) => {
                assert!(c.client_id.len() <= usize::from(l.max_client_id_len));
            }
            _ => {}
        }
    }
}
