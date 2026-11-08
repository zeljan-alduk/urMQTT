//! Kani proofs for the MQTT 5.0 arithmetic (ADR-273): Variable Byte
//! Integers and property-block lengths. Run with `make kani`; compiled only
//! under `cfg(kani)`.

use super::decode::Reader;
use super::{MAX_VARINT, Property, read_varint, varint_len, write_varint};

/// Every value up to the maximum encodes in `varint_len` bytes and decodes
/// back; larger values are refused.
#[kani::proof]
#[kani::unwind(6)]
fn varint_round_trip() {
    let v: u32 = kani::any();
    let mut out = [0u8; 4];
    match write_varint(v, &mut out) {
        Ok(n) => {
            assert!(v <= MAX_VARINT);
            assert_eq!(n, varint_len(v));
            assert_eq!(read_varint(&out[..n]), Ok((v, n)));
        }
        Err(_) => assert!(v > MAX_VARINT),
    }
}

/// Any 5 bytes: an accepted varint is in range, at most 4 bytes, inside the
/// input, and minimal (it re-encodes to the same bytes).
#[kani::proof]
#[kani::unwind(6)]
fn read_varint_any_bytes() {
    let bytes: [u8; 5] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok((v, n)) = read_varint(&bytes[..len]) {
        assert!(v <= MAX_VARINT);
        assert!(n >= 1 && n <= 4 && n <= len);
        let mut out = [0u8; 4];
        assert_eq!(write_varint(v, &mut out), Ok(n));
        assert!(out[..n] == bytes[..n]);
    }
}

/// The UTF-8 validator, replaced for CBMC (which does not finish it within
/// its budget): accepts or refuses at will and keeps the length, which is
/// all the length arithmetic depends on. The validator itself is the 3.1.1
/// one (`core::str::from_utf8` plus the U+0000 check), tested and fuzzed.
fn any_utf8(bytes: &[u8]) -> Result<&str, super::Error> {
    const A: &str = "aaaa";
    match A.get(..bytes.len()) {
        Some(s) if kani::any() => Ok(s),
        _ => Err(super::Error::InvalidUtf8),
    }
}

fn any_topic_name(_: &str) -> bool {
    kani::any()
}

/// One property (identifier and up to 4 value bytes, any bytes, strings
/// included): parsing never panics, and what it consumes is exactly the
/// property's `encoded_len`, so a block's Property Length and the sum over
/// its properties agree (the whole-block statement is also checked by the
/// `mqtt5_props` fuzz target). Needs `-Z stubbing` (scripts/kani.sh).
#[kani::proof]
#[kani::unwind(6)]
#[kani::stub(super::decode::utf8, any_utf8)]
#[kani::stub(crate::validate::is_valid_topic_name, any_topic_name)]
fn property_length_arithmetic() {
    let bytes: [u8; 5] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let mut r = Reader::new(&bytes[..len]);
    if let Ok(p) = Property::parse(&mut r) {
        assert_eq!(len - r.remaining(), p.encoded_len());
    }
}
