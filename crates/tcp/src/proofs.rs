//! Kani proofs (H5) for the segment parser: any segment up to 28 bytes (a
//! header and up to eight option bytes) is parsed or refused without a
//! panic or out-of-bounds access, and an accepted header describes bytes
//! that exist.

use crate::wire::{HEADER, WireError, parse};

#[kani::proof]
#[kani::unwind(32)]
fn parse_any_segment() {
    let bytes: [u8; 28] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    let seg = &bytes[..n];
    let src: [u8; 4] = kani::any();
    let dst: [u8; 4] = kani::any();
    match parse(src, dst, seg) {
        Ok(h) => {
            assert!(n >= HEADER);
            assert!(h.data_off >= HEADER && h.data_off <= n);
            assert!(h.data_off % 4 == 0);
            assert!(h.flags & 0x3f != 0 && h.flags & 0x20 == 0);
        }
        Err(WireError::Truncated) => {}
        Err(_) => assert!(n >= HEADER),
    }
}
