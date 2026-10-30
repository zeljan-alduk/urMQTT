//! The CPU's own random source (RDSEED/RDRAND, X4).
//!
//! Same shape as aarch64's `RNDR` reader: 64 bytes or `None`. RDSEED (the
//! entropy source) is preferred; RDRAND (the on-chip DRBG, reseeded by
//! hardware) is the fallback. Both can report "no data" transiently, so
//! each word is retried; Intel's guidance is ten attempts for RDRAND, and
//! RDSEED under contention needs more with a pause between.

#[cfg(target_os = "none")]
use crate::prim;

/// Attempts per 64-bit word.
#[cfg(target_os = "none")]
const RDRAND_RETRIES: u32 = 10;
#[cfg(target_os = "none")]
const RDSEED_RETRIES: u32 = 100;

/// A health check on a drawn block of 8 words: all-equal words, or all bits
/// clear/set, mean the instruction is returning a constant (a known failure
/// mode of broken firmware and hypervisors), so the caller must not trust it.
pub fn healthy(words: &[u64; 8]) -> bool {
    let first = words[0];
    if words.iter().all(|w| *w == first) {
        return false;
    }
    !(words.iter().all(|w| *w == 0) || words.iter().all(|w| *w == u64::MAX))
}

pub fn to_bytes(words: &[u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    out
}

#[cfg(target_os = "none")]
fn draw(next: impl Fn() -> Option<u64>, retries: u32, pause: bool) -> Option<[u64; 8]> {
    let mut words = [0u64; 8];
    for w in &mut words {
        let mut got = None;
        for _ in 0..retries {
            got = next();
            if got.is_some() {
                break;
            }
            if pause {
                core::hint::spin_loop();
            }
        }
        *w = got?;
    }
    Some(words)
}

/// 64 bytes from RDSEED, else RDRAND, if the CPU has them, every read
/// succeeds within its retries, and the block passes the health check.
#[cfg(target_os = "none")]
pub fn hw_random() -> Option<[u8; 64]> {
    let (max, ..) = prim::cpuid(0, 0);
    let rdrand = prim::cpuid(1, 0).2 & (1 << 30) != 0;
    let rdseed = max >= 7 && prim::cpuid(7, 0).1 & (1 << 18) != 0;
    if rdseed && let Some(w) = draw(prim::rdseed64, RDSEED_RETRIES, true).filter(healthy) {
        return Some(to_bytes(&w));
    }
    if rdrand && let Some(w) = draw(prim::rdrand64, RDRAND_RETRIES, false).filter(healthy) {
        return Some(to_bytes(&w));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_rejects_constants() {
        assert!(!healthy(&[0; 8]));
        assert!(!healthy(&[u64::MAX; 8]));
        assert!(!healthy(&[0x1234; 8]));
        assert!(healthy(&[1, 2, 3, 4, 5, 6, 7, 8]));
        let mut w = [0x1234u64; 8];
        w[7] = 0x1235;
        assert!(healthy(&w));
    }

    #[test]
    fn bytes_are_little_endian_words() {
        let b = to_bytes(&[0x0807_0605_0403_0201, 0, 0, 0, 0, 0, 0, 0xff]);
        assert_eq!(&b[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(b[56], 0xff);
    }
}
