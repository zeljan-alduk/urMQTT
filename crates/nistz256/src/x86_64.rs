//! The x86_64 primitives (ADR-130): `vendor/nistz256/p256-x86_64-asm.S`, in
//! a MULX/ADCX/ADOX variant and a plain-`mul` variant chosen once through
//! `cpufeatures` (on bare metal the kernel's sealed dispatch).

use core::arch::global_asm;

use super::{Aff, Jac, Limbs, ZERO};

global_asm!(
    include_str!("../../../vendor/nistz256/p256-x86_64-asm.S"),
    options(att_syntax)
);

// SAFETY: symbols of the vendored assembly (vendor/nistz256/p256-x86_64-asm.S); each takes pointers
// to 32-byte aligned `#[repr(C)]` values valid for the call; `_adx` ones only after `adx_bmi2`.
unsafe extern "C" {
    fn urmqtt_nistz256_neg(res: *mut Limbs, a: *const Limbs);
    fn urmqtt_nistz256_mul_mont_nohw(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_mul_mont_adx(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_sqr_mont_nohw(res: *mut Limbs, a: *const Limbs);
    fn urmqtt_nistz256_sqr_mont_adx(res: *mut Limbs, a: *const Limbs);
    fn urmqtt_nistz256_ord_mul_mont_nohw(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_ord_mul_mont_adx(res: *mut Limbs, a: *const Limbs, b: *const Limbs);
    fn urmqtt_nistz256_ord_sqr_mont_nohw(res: *mut Limbs, a: *const Limbs, rep: u64);
    fn urmqtt_nistz256_ord_sqr_mont_adx(res: *mut Limbs, a: *const Limbs, rep: u64);
    fn urmqtt_nistz256_select_w5_nohw(val: *mut Jac, table: *const Jac, index: i32);
    fn urmqtt_nistz256_select_w7_nohw(val: *mut Aff, table: *const Aff, index: i32);
    fn urmqtt_nistz256_point_double_nohw(r: *mut Jac, a: *const Jac);
    fn urmqtt_nistz256_point_double_adx(r: *mut Jac, a: *const Jac);
    fn urmqtt_nistz256_point_add_nohw(r: *mut Jac, a: *const Jac, b: *const Jac);
    fn urmqtt_nistz256_point_add_adx(r: *mut Jac, a: *const Jac, b: *const Jac);
    fn urmqtt_nistz256_point_add_affine_nohw(r: *mut Jac, a: *const Jac, b: *const Aff);
    fn urmqtt_nistz256_point_add_affine_adx(r: *mut Jac, a: *const Jac, b: *const Aff);
}

cpufeatures::new!(adx_bmi2, "bmi2", "adx");

/// Which assembly variant runs: MULX/ADX or plain `mul`.
#[derive(Clone, Copy)]
pub struct Ops {
    adx: bool,
}

impl Ops {
    /// The variant for this CPU (through the sealed dispatch in the kernel).
    pub fn detect() -> Self {
        Self {
            adx: adx_bmi2::get(),
        }
    }

    /// The plain-`mul` variant (runs everywhere); for tests and fallbacks.
    pub const fn portable() -> Self {
        Self { adx: false }
    }

    /// The MULX/ADX variant if this CPU has it.
    pub fn adx_if_available() -> Option<Self> {
        adx_bmi2::get().then_some(Self { adx: true })
    }

    /// Whether the MULX/ADX variant is in use.
    pub const fn uses_adx(self) -> bool {
        self.adx
    }

    /// The variant's name for the boot log: `nistz256-adx` or `nistz256-mul`.
    pub const fn name(self) -> &'static str {
        if self.adx {
            "nistz256-adx"
        } else {
            "nistz256-mul"
        }
    }

    // The pointers below are references converted at the call, valid for the
    // access sizes the assembly documents (4 limbs, or whole points).

    pub(crate) fn mul(self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut r = ZERO;
        if self.adx {
            // SAFETY: `r`, `a`, `b` are valid 32-byte limb arrays; the assembly
            // reads `a` and `b` and writes `r` only, uses no CPU feature beyond
            // what `self.adx` (checked at construction) implies.
            unsafe { urmqtt_nistz256_mul_mont_adx(&raw mut r, a, b) };
        } else {
            // SAFETY: `r`, `a`, `b` are valid 32-byte limb arrays; the assembly
            // reads `a` and `b` and writes `r` only, uses no CPU feature beyond
            // what `self.adx` (checked at construction) implies.
            unsafe { urmqtt_nistz256_mul_mont_nohw(&raw mut r, a, b) };
        }
        r
    }

    pub(crate) fn sqr(self, a: &Limbs) -> Limbs {
        let mut r = ZERO;
        if self.adx {
            // SAFETY: as in `mul`.
            unsafe { urmqtt_nistz256_sqr_mont_adx(&raw mut r, a) };
        } else {
            // SAFETY: as in `mul`.
            unsafe { urmqtt_nistz256_sqr_mont_nohw(&raw mut r, a) };
        }
        r
    }

    pub(crate) fn ord_mul(self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut r = ZERO;
        if self.adx {
            // SAFETY: as in `mul`.
            unsafe { urmqtt_nistz256_ord_mul_mont_adx(&raw mut r, a, b) };
        } else {
            // SAFETY: as in `mul`.
            unsafe { urmqtt_nistz256_ord_mul_mont_nohw(&raw mut r, a, b) };
        }
        r
    }

    /// `a^(2^rep)` in the Montgomery domain of N, `rep >= 1`.
    pub(crate) fn ord_sqr_rep(self, a: &Limbs, rep: u64) -> Limbs {
        let mut r = ZERO;
        if self.adx {
            // SAFETY: as in `mul`; `rep >= 1` is the assembly's precondition.
            unsafe { urmqtt_nistz256_ord_sqr_mont_adx(&raw mut r, a, rep) };
        } else {
            // SAFETY: as in `mul`; `rep >= 1` is the assembly's precondition.
            unsafe { urmqtt_nistz256_ord_sqr_mont_nohw(&raw mut r, a, rep) };
        }
        r
    }

    pub(crate) fn dbl(self, a: &Jac) -> Jac {
        let mut r = Jac::default();
        if self.adx {
            // SAFETY: `r` and `a` are valid, aligned `Jac` values.
            unsafe { urmqtt_nistz256_point_double_adx(&raw mut r, a) };
        } else {
            // SAFETY: `r` and `a` are valid, aligned `Jac` values.
            unsafe { urmqtt_nistz256_point_double_nohw(&raw mut r, a) };
        }
        r
    }

    /// Complete addition (handles infinity operands and equal operands).
    pub(crate) fn add(self, a: &Jac, b: &Jac) -> Jac {
        let mut r = Jac::default();
        if self.adx {
            // SAFETY: as in `dbl`.
            unsafe { urmqtt_nistz256_point_add_adx(&raw mut r, a, b) };
        } else {
            // SAFETY: as in `dbl`.
            unsafe { urmqtt_nistz256_point_add_nohw(&raw mut r, a, b) };
        }
        r
    }

    /// `a + b` with `b` affine; `a` and `b` must not be the same non-infinity
    /// point.
    pub(crate) fn add_affine(self, a: &Jac, b: &Aff) -> Jac {
        let mut r = Jac::default();
        if self.adx {
            // SAFETY: as in `dbl`; `b` is a valid, aligned `Aff`.
            unsafe { urmqtt_nistz256_point_add_affine_adx(&raw mut r, a, b) };
        } else {
            // SAFETY: as in `dbl`; `b` is a valid, aligned `Aff`.
            unsafe { urmqtt_nistz256_point_add_affine_nohw(&raw mut r, a, b) };
        }
        r
    }
}

pub(crate) fn neg(a: &Limbs) -> Limbs {
    let mut r = ZERO;
    // SAFETY: valid 32-byte arrays; the assembly is plain integer code.
    unsafe { urmqtt_nistz256_neg(&raw mut r, a) };
    r
}

pub(crate) fn select_w5(table: &[Jac; 16], index: u64) -> Jac {
    let mut r = Jac::default();
    // SAFETY: `table` has the 16 entries the assembly scans, `index` is at
    // most 16, `r` is a valid aligned `Jac`; SSE2 only (baseline).
    unsafe { urmqtt_nistz256_select_w5_nohw(&raw mut r, table.as_ptr(), index as i32) };
    r
}

pub(crate) fn select_w7(row: &[Aff; 64], index: u64) -> Aff {
    let mut r = Aff::default();
    // SAFETY: as `select_w5`, with 64 entries and `index <= 64`.
    unsafe { urmqtt_nistz256_select_w7_nohw(&raw mut r, row.as_ptr(), index as i32) };
    r
}
