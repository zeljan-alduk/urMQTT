//! CRC-32C with the SSE4.2 `crc32` instruction (X9): 8 bytes per
//! `crc32 r64, r/m64`. SSE4.2 is part of the x86-64-v2 baseline the kernel
//! requires, but the dispatch still gates it (`[cpu] disable = ["crc32"]`)
//! so the table stays selectable for comparison.
//!
//! The instruction only exists on x86_64. On the other hosts that build this
//! crate for the facade's pure parts, the function stops with a message
//! (nothing calls it there: the dispatch never selects it).

#![allow(unsafe_code)]

/// Continues a CRC-32C computation, as `urmqtt_store::crc::update`.
///
/// # Safety
/// The CPU must implement SSE4.2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
pub unsafe fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};
    let mut c = u64::from(!crc);
    let (words, tail) = data.as_chunks::<8>();
    for w in words {
        c = _mm_crc32_u64(c, u64::from_le_bytes(*w));
    }
    let mut c = c as u32;
    for &b in tail {
        c = _mm_crc32_u8(c, b);
    }
    !c
}

/// See the x86_64 version.
///
/// # Safety
/// Never callable: this is not an x86_64 build.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn crc32c_update(_crc: u32, _data: &[u8]) -> u32 {
    unimplemented_until!("an x86_64 build (SSE4.2 CRC-32C)")
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    fn bitwise(crc: u32, data: &[u8]) -> u32 {
        let mut c = !crc;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0x82f6_3b78
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    #[test]
    fn equals_the_bitwise_definition() {
        if !std::arch::is_x86_feature_detected!("sse4.2") {
            return;
        }
        // SAFETY: the feature was detected above.
        let hw = |c, d: &[u8]| unsafe { crc32c_update(c, d) };
        // RFC 3720 appendix B.4 and the usual check value.
        assert_eq!(hw(0, b"123456789"), 0xe306_9283);
        assert_eq!(hw(0, &[0u8; 32]), 0x8a91_36aa);
        assert_eq!(hw(0, &[0xffu8; 32]), 0x62a8_ab43);
        let inc: Vec<u8> = (0..32).collect();
        assert_eq!(hw(0, &inc), 0x46dd_794e);
        let dec: Vec<u8> = (0..32).rev().collect();
        assert_eq!(hw(0, &dec), 0x113f_db5c);
        // Random buffers, unaligned starts, every length around the word size.
        let mut x = 0x1234_5678u32;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        };
        let data: Vec<u8> = (0..4099).map(|_| next()).collect();
        for len in (0..=70).chain([127, 128, 129, 1000, 4096, 4099]) {
            for start in [0, 1, 3, 7] {
                let d = &data[start..start + len.min(4099 - start)];
                assert_eq!(hw(0, d), bitwise(0, d), "len {len} start {start}");
                assert_eq!(hw(0xdead_beef, d), bitwise(0xdead_beef, d));
            }
        }
        // Streaming: splitting the input anywhere gives the same CRC.
        for cut in [0, 1, 5, 8, 100, 4099] {
            let (a, b) = data.split_at(cut);
            assert_eq!(hw(hw(0, a), b), hw(0, &data));
        }
    }
}
