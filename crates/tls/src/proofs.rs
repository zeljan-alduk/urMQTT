//! Kani proofs (H5) for the TLS record header parser.

use crate::record::{HEADER, record_len};

/// `record_len` never panics, answers exactly when the header is complete,
/// and never claims more than a header plus a 16-bit length.
#[kani::proof]
#[kani::unwind(8)]
fn record_len_any_prefix() {
    let bytes: [u8; 6] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= bytes.len());
    let buf = &bytes[..n];
    match record_len(buf) {
        Some(total) => {
            assert!(n >= HEADER);
            assert_eq!(
                total,
                HEADER + (usize::from(buf[3]) << 8 | usize::from(buf[4]))
            );
            assert!(total <= HEADER + usize::from(u16::MAX));
        }
        None => assert!(n < HEADER),
    }
}
