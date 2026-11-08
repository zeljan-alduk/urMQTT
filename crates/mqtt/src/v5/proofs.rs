//! Kani proofs for the MQTT 5.0 arithmetic (ADR-273): Variable Byte
//! Integers and property-block lengths. Run with `make kani`; compiled only
//! under `cfg(kani)`.

use super::{
    Limits, MAX_VARINT, PropertyContext, props::RawProps, read_varint, validate_properties,
    varint_len, write_varint,
};

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

/// Any property block of up to 6 bytes in any context: validation never
/// panics, and an accepted block is consumed exactly: the encoded lengths
/// of the properties it holds add up to the Property Length. Response Topic
/// and User Property (topic and UTF-8 checks over two strings) are left out
/// to keep CBMC within its budget; the string arithmetic is the same as
/// Content Type's, which stays in.
#[kani::proof]
#[kani::unwind(8)]
fn property_block_lengths() {
    let bytes: [u8; 6] = kani::any();
    for b in bytes {
        kani::assume(b != 0x08 && b != 0x26);
    }
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let i: usize = kani::any();
    kani::assume(i < PropertyContext::ALL.len());
    let raw = &bytes[..len];
    if validate_properties(raw, PropertyContext::ALL[i], &Limits::PROTOCOL_MAX).is_ok() {
        let mut sum = 0usize;
        for p in RawProps::new(raw) {
            sum += p.encoded_len();
        }
        assert_eq!(sum, len);
    }
}
