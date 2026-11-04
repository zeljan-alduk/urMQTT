//! The AArch64 primitives (ADR-255): `vendor/nistz256/p256-armv8-asm.S`
//! (OpenSSL's `ecp_nistz256-armv8`, through ring), one variant for every
//! ARMv8-A core: `mul`/`umulh` and `adds`/`adcs` carry chains in general-purpose
//! registers only (no NEON or FP register, no `x18`).
//!
//! Upstream's two table-selection functions use NEON and are not vendored;
//! [`select_w5`] and [`select_w7`] below are their constant-time equivalent in
//! Rust: every entry is read and masked, the index never selects a branch or
//! an address.

use core::arch::global_asm;

use super::{Aff, Jac, Limbs, ZERO};

global_asm!(include_str!("../../../vendor/nistz256/p256-armv8-asm.S"));

// SAFETY: symbols of the vendored assembly (vendor/nistz256/p256-armv8-asm.S); each takes pointers
// to 32-byte aligned `#[repr(C)]` values valid for the call and follows AAPCS64 (x19-x29 saved,
// no x18, no SIMD register). Every entry starts with `bti c`; those that save the link register
// sign it with PACIASP and authenticate it with AUTIASP before `ret`.
unsafe extern "C" {
    fn urmqtt_nistz256_neg(res: *mut Limbs, a: *const Limbs);
    fn urmqtt_nistz256_mul_mont(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_sqr_mont(res: *mut Limbs, a: *const Limbs);
    fn urmqtt_nistz256_ord_mul_mont(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_ord_sqr_mont(res: *mut Limbs, a: *const Limbs, rep: u64);
    fn urmqtt_nistz256_point_double(r: *mut Jac, a: *const Jac);
    fn urmqtt_nistz256_point_add(r: *mut Jac, a: *const Jac, b: *const Jac);
    fn urmqtt_nistz256_point_add_affine(r: *mut Jac, a: *const Jac, b: *const Aff);
}

/// The assembly, for API parity with x86_64 (where it names one of two
/// variants); AArch64 has one, which runs on every ARMv8-A core.
#[derive(Clone, Copy)]
pub struct Ops {
    _one_variant: (),
}

impl Ops {
    /// The variant for this CPU (the only one).
    pub const fn detect() -> Self {
        Self { _one_variant: () }
    }

    /// The same variant (runs everywhere); for tests and fallbacks.
    pub const fn portable() -> Self {
        Self::detect()
    }

    /// Always `None`: MULX/ADX is x86_64 only.
    pub const fn adx_if_available() -> Option<Self> {
        None
    }

    /// Always `false` (x86_64 only).
    pub const fn uses_adx(self) -> bool {
        false
    }

    /// The variant's name for the boot log.
    pub const fn name(self) -> &'static str {
        "nistz256-armv8"
    }

    // The pointers below are references converted at the call, valid for the
    // access sizes the assembly documents (4 limbs, or whole points).

    pub(crate) fn mul(self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut r = ZERO;
        // SAFETY: `r`, `a`, `b` are valid 32-byte limb arrays; the assembly
        // reads `a` and `b` and writes `r` only (baseline ARMv8-A integer code).
        unsafe { urmqtt_nistz256_mul_mont(&raw mut r, a, b) };
        r
    }

    pub(crate) fn sqr(self, a: &Limbs) -> Limbs {
        let mut r = ZERO;
        // SAFETY: as in `mul`.
        unsafe { urmqtt_nistz256_sqr_mont(&raw mut r, a) };
        r
    }

    pub(crate) fn ord_mul(self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut r = ZERO;
        // SAFETY: as in `mul`.
        unsafe { urmqtt_nistz256_ord_mul_mont(&raw mut r, a, b) };
        r
    }

    /// `a^(2^rep)` in the Montgomery domain of N, `rep >= 1`.
    pub(crate) fn ord_sqr_rep(self, a: &Limbs, rep: u64) -> Limbs {
        let mut r = ZERO;
        // SAFETY: as in `mul`; `rep >= 1` is the assembly's precondition
        // (it decrements before testing).
        unsafe { urmqtt_nistz256_ord_sqr_mont(&raw mut r, a, rep) };
        r
    }

    pub(crate) fn dbl(self, a: &Jac) -> Jac {
        let mut r = Jac::default();
        // SAFETY: `r` and `a` are valid, aligned `Jac` values.
        unsafe { urmqtt_nistz256_point_double(&raw mut r, a) };
        r
    }

    /// Complete addition (handles infinity operands and equal operands).
    pub(crate) fn add(self, a: &Jac, b: &Jac) -> Jac {
        let mut r = Jac::default();
        // SAFETY: as in `dbl`.
        unsafe { urmqtt_nistz256_point_add(&raw mut r, a, b) };
        r
    }

    /// `a + b` with `b` affine; `a` and `b` must not be the same non-infinity
    /// point.
    pub(crate) fn add_affine(self, a: &Jac, b: &Aff) -> Jac {
        let mut r = Jac::default();
        // SAFETY: as in `dbl`; `b` is a valid, aligned `Aff`.
        unsafe { urmqtt_nistz256_point_add_affine(&raw mut r, a, b) };
        r
    }
}

pub(crate) fn neg(a: &Limbs) -> Limbs {
    let mut r = ZERO;
    // SAFETY: valid 32-byte arrays; the assembly is plain integer code.
    unsafe { urmqtt_nistz256_neg(&raw mut r, a) };
    r
}

/// All ones if `a == b`, else zero, without a data-dependent branch. The
/// `black_box` hides that the intermediate is 0 or 1, so the compiler cannot
/// turn the masking below into a branch on the secret index.
fn eq_mask(a: u64, b: u64) -> u64 {
    let d = a ^ b;
    let nonzero = (d | d.wrapping_neg()) >> 63;
    core::hint::black_box(nonzero).wrapping_sub(1)
}

/// Entry `index - 1` of `table`, or all zeros (infinity) for `index == 0`;
/// reads all 16 entries (upstream's `ecp_nistz256_select_w5`).
pub(crate) fn select_w5(table: &[Jac; 16], index: u64) -> Jac {
    let mut r = Jac::default();
    for (i, e) in (1u64..).zip(table.iter()) {
        let m = eq_mask(i, index);
        for k in 0..4 {
            r.x[k] |= e.x[k] & m;
            r.y[k] |= e.y[k] & m;
            r.z[k] |= e.z[k] & m;
        }
    }
    r
}

/// Entry `index - 1` of `row`, or (0, 0) for `index == 0`; reads all 64
/// entries (upstream's `ecp_nistz256_select_w7`).
pub(crate) fn select_w7(row: &[Aff; 64], index: u64) -> Aff {
    let mut r = Aff::default();
    for (i, e) in (1u64..).zip(row.iter()) {
        let m = eq_mask(i, index);
        for k in 0..4 {
            r.x[k] |= e.x[k] & m;
            r.y[k] |= e.y[k] & m;
        }
    }
    r
}
