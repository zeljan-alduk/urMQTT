//! Multiplication and squaring in GF(2^255 - 19) on AArch64 with `mul`,
//! `umulh` and `adds`/`adcs` carry chains (ADR-259).
//!
//! Written for this crate, in the shape of `adx.rs`. Operands are any
//! four-limb values below 2^256; the result is below 2^256, congruent to the
//! product (2^256 = 38 mod p) and bit for bit the result of the portable
//! `mul_portable` (the same exact 512-bit product, folded the same way).
//!
//! - **Product** (`mul`): row by row, `b[i] * a[0..4]`; each row adds its four
//!   low halves at `t[i..i+4]` with one carry chain (the carry out becomes
//!   `t[i+4]`) and then its four high halves at `t[i+1..i+5]` with a second
//!   chain. No limb can overflow: after row `i` the exact partial product is
//!   below 2^(64 (i + 5)), so the top limb of each row holds it.
//! - **Square** (`sqr`): the six cross products once, doubled with one carry
//!   chain into `t[7]`, plus the four squares on the diagonal (10 products
//!   instead of 16).
//! - **Fold**: `t[0..4] + 38 * t[4..8]` (low halves, then high halves, as in
//!   the product; the carry `c` is at most 38), then `+ 38 c` with a carry
//!   chain; a last carry leaves the low limb below 2^11, so the final `+ 38`
//!   (selected with `csel`, not a branch) cannot carry.
//!
//! Only general-purpose registers (no NEON or FP register, no `x18`, no
//! stack, no memory access): the inputs are passed in registers. No branch
//! and no address depends on a value. `mul` and `umulh` are data-independent
//! on the cores this targets as far as their documentation says; PSTATE.DIT
//! is not set anywhere (A255-W2), so the architecture does not guarantee it.
//! Inline assembly has no entry point of its own, so there is no BTI landing
//! pad or return address to protect (the enclosing Rust function gets the
//! compiler's `bti c`/`paciasp` like all other code).

use core::arch::asm;

use crate::Fe;

/// `a * b`.
#[inline]
pub(crate) fn mul(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: register-only arithmetic on the values passed in (no memory
    // access, no stack, no SIMD/FP register, flags declared clobbered by
    // default); every written register is an output or a clobber.
    unsafe {
        asm!(
            // row 0: t0..t4 = a * b0
            "mul {t0}, {a0}, {b0}",
            "mul {t1}, {a1}, {b0}",
            "mul {t2}, {a2}, {b0}",
            "mul {t3}, {a3}, {b0}",
            "umulh {l0}, {a0}, {b0}",
            "umulh {l1}, {a1}, {b0}",
            "umulh {l2}, {a2}, {b0}",
            "umulh {t4}, {a3}, {b0}",
            "adds {t1}, {t1}, {l0}",
            "adcs {t2}, {t2}, {l1}",
            "adcs {t3}, {t3}, {l2}",
            "adc {t4}, {t4}, xzr",
            // row 1: t1..t5 += a * b1
            "mul {l0}, {a0}, {b1}",
            "mul {l1}, {a1}, {b1}",
            "mul {l2}, {a2}, {b1}",
            "mul {l3}, {a3}, {b1}",
            "adds {t1}, {t1}, {l0}",
            "adcs {t2}, {t2}, {l1}",
            "adcs {t3}, {t3}, {l2}",
            "adcs {t4}, {t4}, {l3}",
            "cset {t5}, cs",
            "umulh {l0}, {a0}, {b1}",
            "umulh {l1}, {a1}, {b1}",
            "umulh {l2}, {a2}, {b1}",
            "umulh {l3}, {a3}, {b1}",
            "adds {t2}, {t2}, {l0}",
            "adcs {t3}, {t3}, {l1}",
            "adcs {t4}, {t4}, {l2}",
            "adc {t5}, {t5}, {l3}",
            // row 2: t2..t6 += a * b2
            "mul {l0}, {a0}, {b2}",
            "mul {l1}, {a1}, {b2}",
            "mul {l2}, {a2}, {b2}",
            "mul {l3}, {a3}, {b2}",
            "adds {t2}, {t2}, {l0}",
            "adcs {t3}, {t3}, {l1}",
            "adcs {t4}, {t4}, {l2}",
            "adcs {t5}, {t5}, {l3}",
            "cset {t6}, cs",
            "umulh {l0}, {a0}, {b2}",
            "umulh {l1}, {a1}, {b2}",
            "umulh {l2}, {a2}, {b2}",
            "umulh {l3}, {a3}, {b2}",
            "adds {t3}, {t3}, {l0}",
            "adcs {t4}, {t4}, {l1}",
            "adcs {t5}, {t5}, {l2}",
            "adc {t6}, {t6}, {l3}",
            // row 3: t3..t7 += a * b3
            "mul {l0}, {a0}, {b3}",
            "mul {l1}, {a1}, {b3}",
            "mul {l2}, {a2}, {b3}",
            "mul {l3}, {a3}, {b3}",
            "adds {t3}, {t3}, {l0}",
            "adcs {t4}, {t4}, {l1}",
            "adcs {t5}, {t5}, {l2}",
            "adcs {t6}, {t6}, {l3}",
            "cset {t7}, cs",
            "umulh {l0}, {a0}, {b3}",
            "umulh {l1}, {a1}, {b3}",
            "umulh {l2}, {a2}, {b3}",
            "umulh {l3}, {a3}, {b3}",
            "adds {t4}, {t4}, {l0}",
            "adcs {t5}, {t5}, {l1}",
            "adcs {t6}, {t6}, {l2}",
            "adc {t7}, {t7}, {l3}",
            // fold: t0..t3 + 38 * t4..t7
            "mov {k}, #38",
            "mul {l0}, {t4}, {k}",
            "mul {l1}, {t5}, {k}",
            "mul {l2}, {t6}, {k}",
            "mul {l3}, {t7}, {k}",
            "adds {t0}, {t0}, {l0}",
            "adcs {t1}, {t1}, {l1}",
            "adcs {t2}, {t2}, {l2}",
            "adcs {t3}, {t3}, {l3}",
            "cset {l0}, cs",
            "umulh {l1}, {t4}, {k}",
            "umulh {l2}, {t5}, {k}",
            "umulh {l3}, {t6}, {k}",
            "umulh {t4}, {t7}, {k}",
            "adds {t1}, {t1}, {l1}",
            "adcs {t2}, {t2}, {l2}",
            "adcs {t3}, {t3}, {l3}",
            "adc {t4}, {t4}, {l0}",
            // + 38 * carry (carry <= 38), then + 38 if that carried.
            "mul {t4}, {t4}, {k}",
            "adds {t0}, {t0}, {t4}",
            "adcs {t1}, {t1}, xzr",
            "adcs {t2}, {t2}, xzr",
            "adcs {t3}, {t3}, xzr",
            "csel {t4}, {k}, xzr, cs",
            "add {t0}, {t0}, {t4}",
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
            b0 = in(reg) b[0],
            b1 = in(reg) b[1],
            b2 = in(reg) b[2],
            b3 = in(reg) b[3],
            t0 = out(reg) r0,
            t1 = out(reg) r1,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            t6 = out(reg) _,
            t7 = out(reg) _,
            l0 = out(reg) _,
            l1 = out(reg) _,
            l2 = out(reg) _,
            l3 = out(reg) _,
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a * a`.
#[inline]
pub(crate) fn sqr(a: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as in `mul`.
    unsafe {
        asm!(
            // cross products a_i a_j (i < j) at t1..t6
            "mul {t1}, {a1}, {a0}",
            "umulh {t2}, {a1}, {a0}",
            "mul {l0}, {a2}, {a0}",
            "umulh {t3}, {a2}, {a0}",
            "mul {l1}, {a3}, {a0}",
            "umulh {t4}, {a3}, {a0}",
            "adds {t2}, {t2}, {l0}",
            "adcs {t3}, {t3}, {l1}",
            "adc {t4}, {t4}, xzr",
            "mul {l0}, {a2}, {a1}",
            "umulh {l1}, {a2}, {a1}",
            "mul {l2}, {a3}, {a1}",
            "umulh {t5}, {a3}, {a1}",
            "adds {l1}, {l1}, {l2}",
            "adc {t5}, {t5}, xzr",
            "adds {t3}, {t3}, {l0}",
            "adcs {t4}, {t4}, {l1}",
            "adc {t5}, {t5}, xzr",
            "mul {l0}, {a3}, {a2}",
            "umulh {t6}, {a3}, {a2}",
            "adds {t5}, {t5}, {l0}",
            "adc {t6}, {t6}, xzr",
            // doubled, the carry out into t7
            "adds {t1}, {t1}, {t1}",
            "adcs {t2}, {t2}, {t2}",
            "adcs {t3}, {t3}, {t3}",
            "adcs {t4}, {t4}, {t4}",
            "adcs {t5}, {t5}, {t5}",
            "adcs {t6}, {t6}, {t6}",
            "cset {t7}, cs",
            // + the squares a_i^2 at t(2i), t(2i+1)
            "mul {t0}, {a0}, {a0}",
            "umulh {l0}, {a0}, {a0}",
            "mul {l1}, {a1}, {a1}",
            "umulh {l2}, {a1}, {a1}",
            "mul {l3}, {a2}, {a2}",
            "umulh {k}, {a2}, {a2}",
            "adds {t1}, {t1}, {l0}",
            "adcs {t2}, {t2}, {l1}",
            "adcs {t3}, {t3}, {l2}",
            "adcs {t4}, {t4}, {l3}",
            "adcs {t5}, {t5}, {k}",
            "mul {l0}, {a3}, {a3}",
            "umulh {l1}, {a3}, {a3}",
            "adcs {t6}, {t6}, {l0}",
            "adc {t7}, {t7}, {l1}",
            // fold, as in `mul`
            "mov {k}, #38",
            "mul {l0}, {t4}, {k}",
            "mul {l1}, {t5}, {k}",
            "mul {l2}, {t6}, {k}",
            "mul {l3}, {t7}, {k}",
            "adds {t0}, {t0}, {l0}",
            "adcs {t1}, {t1}, {l1}",
            "adcs {t2}, {t2}, {l2}",
            "adcs {t3}, {t3}, {l3}",
            "cset {l0}, cs",
            "umulh {l1}, {t4}, {k}",
            "umulh {l2}, {t5}, {k}",
            "umulh {l3}, {t6}, {k}",
            "umulh {t4}, {t7}, {k}",
            "adds {t1}, {t1}, {l1}",
            "adcs {t2}, {t2}, {l2}",
            "adcs {t3}, {t3}, {l3}",
            "adc {t4}, {t4}, {l0}",
            "mul {t4}, {t4}, {k}",
            "adds {t0}, {t0}, {t4}",
            "adcs {t1}, {t1}, xzr",
            "adcs {t2}, {t2}, xzr",
            "adcs {t3}, {t3}, xzr",
            "csel {t4}, {k}, xzr, cs",
            "add {t0}, {t0}, {t4}",
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
            t0 = out(reg) r0,
            t1 = out(reg) r1,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            t6 = out(reg) _,
            t7 = out(reg) _,
            l0 = out(reg) _,
            l1 = out(reg) _,
            l2 = out(reg) _,
            l3 = out(reg) _,
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a + b`, folded below 2^256 as the portable `add`.
#[inline]
pub(crate) fn add(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as in `mul`.
    unsafe {
        asm!(
            "adds {r0}, {a0}, {b0}",
            "adcs {r1}, {a1}, {b1}",
            "adcs {r2}, {a2}, {b2}",
            "adcs {r3}, {a3}, {b3}",
            "mov {k}, #38",
            "csel {t}, {k}, xzr, cs",
            "adds {r0}, {r0}, {t}",
            "adcs {r1}, {r1}, xzr",
            "adcs {r2}, {r2}, xzr",
            "adcs {r3}, {r3}, xzr",
            "csel {t}, {k}, xzr, cs",
            "add {r0}, {r0}, {t}",
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
            b0 = in(reg) b[0],
            b1 = in(reg) b[1],
            b2 = in(reg) b[2],
            b3 = in(reg) b[3],
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            k = out(reg) _,
            t = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b`, folded as the portable `sub`: a borrow out of 2^256 subtracts
/// 38, twice; after a second borrow the low limb is at least 2^64 - 38, so
/// the last subtraction cannot borrow.
#[inline]
pub(crate) fn sub(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as in `mul`.
    unsafe {
        asm!(
            "subs {r0}, {a0}, {b0}",
            "sbcs {r1}, {a1}, {b1}",
            "sbcs {r2}, {a2}, {b2}",
            "sbcs {r3}, {a3}, {b3}",
            "mov {k}, #38",
            // carry clear = borrow
            "csel {t}, {k}, xzr, cc",
            "subs {r0}, {r0}, {t}",
            "sbcs {r1}, {r1}, xzr",
            "sbcs {r2}, {r2}, xzr",
            "sbcs {r3}, {r3}, xzr",
            "csel {t}, {k}, xzr, cc",
            "sub {r0}, {r0}, {t}",
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
            b0 = in(reg) b[0],
            b1 = in(reg) b[1],
            b2 = in(reg) b[2],
            b3 = in(reg) b[3],
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            k = out(reg) _,
            t = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a * 121665`, folded as the portable `mul_a24` (the carry limb is below
/// 121665, so `38 * carry` is below 2^23).
#[inline]
pub(crate) fn mul_a24(a: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as in `mul`.
    unsafe {
        asm!(
            "mov {k}, #0xdb41",
            "movk {k}, #0x1, lsl #16",
            "mul {r0}, {a0}, {k}",
            "mul {r1}, {a1}, {k}",
            "mul {r2}, {a2}, {k}",
            "mul {r3}, {a3}, {k}",
            "umulh {h0}, {a0}, {k}",
            "umulh {h1}, {a1}, {k}",
            "umulh {h2}, {a2}, {k}",
            "umulh {h3}, {a3}, {k}",
            "adds {r1}, {r1}, {h0}",
            "adcs {r2}, {r2}, {h1}",
            "adcs {r3}, {r3}, {h2}",
            "adc {h3}, {h3}, xzr",
            "mov {k}, #38",
            "mul {h3}, {h3}, {k}",
            "adds {r0}, {r0}, {h3}",
            "adcs {r1}, {r1}, xzr",
            "adcs {r2}, {r2}, xzr",
            "adcs {r3}, {r3}, xzr",
            "csel {h3}, {k}, xzr, cs",
            "add {r0}, {r0}, {h3}",
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            h0 = out(reg) _,
            h1 = out(reg) _,
            h2 = out(reg) _,
            h3 = out(reg) _,
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}
