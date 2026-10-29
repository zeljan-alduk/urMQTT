//! The CPU's own random number instruction (`RNDR`, FEAT_RNG).

#![allow(unsafe_code)]

use crate::features::Features;

/// 64 bytes from `RNDR` if the CPU implements FEAT_RNG and every read
/// succeeds.
pub fn hw_random() -> Option<[u8; 64]> {
    if !Features::decode(crate::pac::id_regs()).rndr {
        return None;
    }
    let mut out = [0u8; 64];
    for chunk in out.as_chunks_mut::<8>().0 {
        let (v, ok): (u64, u64);
        // SAFETY: RNDR (S3_3_C2_C4_0) exists (FEAT_RNG); it sets Z on failure.
        unsafe {
            core::arch::asm!(
                "mrs {v}, S3_3_C2_C4_0",
                "cset {ok}, ne",
                v = out(reg) v, ok = out(reg) ok,
                options(nomem, nostack)
            )
        };
        if ok == 0 {
            return None;
        }
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    Some(out)
}
