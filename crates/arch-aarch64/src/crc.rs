//! CRC-32C with the ARMv8 CRC32 instructions (FEAT_CRC32, X0b): 8 bytes per
//! `crc32cx`. Built for every aarch64 target, so the host tests compare it
//! with the table on the developer's and CI's ARM machines.

#![allow(unsafe_code)]

use core::arch::aarch64::{__crc32cb, __crc32cd};

/// Continues a CRC-32C computation, as `urmqtt_store::crc::update`.
///
/// # Safety
/// The CPU must implement FEAT_CRC32 (`crc` target feature).
#[target_feature(enable = "crc")]
pub unsafe fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    let (words, tail) = data.as_chunks::<8>();
    for w in words {
        c = __crc32cd(c, u64::from_le_bytes(*w));
    }
    for &b in tail {
        c = __crc32cb(c, b);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(crc: u32, data: &[u8]) -> u32 {
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
        if !std::arch::is_aarch64_feature_detected!("crc") {
            return;
        }
        // SAFETY: the feature was detected above.
        let hw = |c, d: &[u8]| unsafe { crc32c_update(c, d) };
        assert_eq!(hw(0, b"123456789"), 0xe306_9283);
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..4099)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        for len in [0, 1, 7, 8, 9, 63, 64, 65, 4099] {
            for start in [0, 1, 3] {
                let d = &data[start..start + len.min(4099 - start)];
                assert_eq!(hw(0, d), table(0, d), "len {len} start {start}");
                assert_eq!(hw(0xdead_beef, d), table(0xdead_beef, d));
            }
        }
    }
}
