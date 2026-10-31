//! P-256 ECDSA and ECDH on the OpenSSL/Intel `nistz256` x86_64 assembly
//! (ADR-130, PERF).
//!
//! The field and point arithmetic is the Montgomery 4x64 assembly of Gueron
//! and Krasnov (OpenSSL, Apache-2.0), vendored from the pregenerated GNU
//! assembler output in ring 0.17.14 (`vendor/nistz256`, `vendor/README.md`),
//! in two variants: MULX/ADCX/ADOX (BMI2 and ADX) and plain `mul`. Every entry
//! point picks the variant once, through the kernel's CPU dispatch
//! (`cpufeatures`), and the plain one runs on any x86-64.
//!
//! The scalar multiplication, recoding, ECDSA and ECDH logic around the
//! assembly is written here, after ring's `p256-nistz.c`:
//!
//! - **Secret scalars** (signing nonce, ECDH key, key generation) use signed
//!   Booth windows with constant-time table selection
//!   (`select_w5`/`select_w7` scan the whole table), constant-time
//!   conditional negation, and the complete point addition of the assembly.
//!   The only secret-dependent branch is the assembly's own doubling case in
//!   `point_add` (inputs equal), which cannot arise for a valid scalar below
//!   the group order (the same argument as OpenSSL and ring).
//! - **Public inputs** (verification) use variable-time code.
//!
//! Everything is gated to `x86_64` on Linux or bare metal and not under Miri;
//! elsewhere the crate is empty and the callers keep the portable RustCrypto
//! path. Unsafe code is confined to the calls into the assembly and the
//! reinterpretation of the generator table; each has a SAFETY comment.

#![cfg_attr(not(test), no_std)]
#![cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
))]
#![allow(unsafe_code)]
#![allow(clippy::many_single_char_names)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use core::arch::global_asm;
use zeroize::Zeroize;

global_asm!(
    include_str!("../../../vendor/nistz256/p256-x86_64-asm.S"),
    options(att_syntax)
);

/// A field element or a scalar: four little-endian 64-bit limbs.
type Limbs = [u64; 4];

/// A Jacobian point in the Montgomery domain; infinity has `z == 0`.
#[derive(Clone, Copy, Default)]
#[repr(C, align(32))]
struct Jac {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

/// An affine point in the Montgomery domain; infinity is (0, 0).
#[derive(Clone, Copy, Default)]
#[repr(C, align(32))]
struct Aff {
    x: Limbs,
    y: Limbs,
}

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

/// P, the field prime.
const P: Limbs = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0,
    0xffff_ffff_0000_0001,
];
/// N, the group order.
const N: Limbs = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];
/// N - 2, the exponent of Fermat inversion modulo N.
const N_MINUS_2: Limbs = [
    0xf3b9_cac2_fc63_254f,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];
/// 2^512 mod P (conversion into the Montgomery domain of P).
const RR_P: Limbs = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];
/// 2^512 mod N.
const RR_N: Limbs = [
    0x8324_4c95_be79_eea2,
    0x4699_799c_49bd_6fa6,
    0x2845_b239_2b6b_ec59,
    0x66e1_2d94_f3d9_5620,
];
/// 2^256 mod P: one in the Montgomery domain of P.
const ONE_P: Limbs = [
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
];
/// 2^256 mod N: one in the Montgomery domain of N.
const ONE_N: Limbs = [
    0x0c46_353d_039c_daaf,
    0x4319_0552_58e8_617b,
    0,
    0x0000_0000_ffff_ffff,
];
/// The curve constant b, in the Montgomery domain of P.
const B_MONT: Limbs = [
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
];
const ZERO: Limbs = [0; 4];
const ONE_RAW: Limbs = [1, 0, 0, 0];

/// The generator's comb: 37 rows of 64 affine multiples (OpenSSL/ring layout;
/// row `i`, entry `j` is `(j + 1) * 2^(7 i) * G`, Montgomery domain).
#[repr(C, align(64))]
struct Aligned<T>(T);
static G_TABLE_BYTES: Aligned<[u8; 37 * 64 * 64]> =
    Aligned(*include_bytes!("../../../vendor/nistz256/p256-table.bin"));

fn g_table() -> &'static [[Aff; 64]; 37] {
    // SAFETY: the bytes are 37*64 `Aff` values (64 bytes each, little-endian
    // limbs as x86_64 stores them), the static is aligned to 64 >= align_of::<Aff>(),
    // lives forever and is never mutated; every bit pattern is a valid `Aff`.
    unsafe { &*core::ptr::from_ref(&G_TABLE_BYTES).cast::<[[Aff; 64]; 37]>() }
}

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

    // The pointers below are references converted at the call, valid for the
    // access sizes the assembly documents (4 limbs, or whole points).

    fn mul(self, a: &Limbs, b: &Limbs) -> Limbs {
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

    fn sqr(self, a: &Limbs) -> Limbs {
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

    fn sqr_n(self, a: &Limbs, n: u32) -> Limbs {
        let mut r = *a;
        for _ in 0..n {
            r = self.sqr(&r);
        }
        r
    }

    fn ord_mul(self, a: &Limbs, b: &Limbs) -> Limbs {
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
    fn ord_sqr_rep(self, a: &Limbs, rep: u64) -> Limbs {
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

    fn dbl(self, a: &Jac) -> Jac {
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
    fn add(self, a: &Jac, b: &Jac) -> Jac {
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
    fn add_affine(self, a: &Jac, b: &Aff) -> Jac {
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

fn neg(a: &Limbs) -> Limbs {
    let mut r = ZERO;
    // SAFETY: valid 32-byte arrays; the assembly is plain integer code.
    unsafe { urmqtt_nistz256_neg(&raw mut r, a) };
    r
}

fn select_w5(table: &[Jac; 16], index: u64) -> Jac {
    let mut r = Jac::default();
    // SAFETY: `table` has the 16 entries the assembly scans, `index` is at
    // most 16, `r` is a valid aligned `Jac`; SSE2 only (baseline).
    unsafe { urmqtt_nistz256_select_w5_nohw(&raw mut r, table.as_ptr(), index as i32) };
    r
}

fn select_w7(row: &[Aff; 64], index: u64) -> Aff {
    let mut r = Aff::default();
    // SAFETY: as `select_w5`, with 64 entries and `index <= 64`.
    unsafe { urmqtt_nistz256_select_w7_nohw(&raw mut r, row.as_ptr(), index as i32) };
    r
}

/// `dst = src` if `mv == 1`, unchanged if `mv == 0` (constant time).
fn cmov(dst: &mut Limbs, src: &Limbs, mv: u64) {
    let m1 = 0u64.wrapping_sub(mv);
    for i in 0..4 {
        dst[i] = (src[i] & m1) ^ (dst[i] & !m1);
    }
}

/// 1 if `x != 0`, else 0 (constant time).
fn is_not_zero(x: u64) -> u64 {
    (x | 0u64.wrapping_sub(x)) >> 63
}

/// Constant-time `a >= b`-style helpers on 4-limb integers.
fn sub_borrow(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let mut r = ZERO;
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = u64::from(b1 | b2);
    }
    (r, borrow)
}

fn add_carry(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let mut r = ZERO;
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = u64::from(c1 | c2);
    }
    (r, carry)
}

/// `a mod m` for `a < 2m` (one conditional subtraction), constant time.
fn reduce_once(a: &Limbs, m: &Limbs) -> Limbs {
    let (d, borrow) = sub_borrow(a, m);
    let mut r = d;
    cmov(&mut r, a, borrow);
    r
}

/// `(a + b) mod m` for `a, b < m`, constant time.
fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (s, carry) = add_carry(a, b);
    let (d, borrow) = sub_borrow(&s, m);
    // Subtract when the sum overflowed 2^256 or is at least m.
    let keep_sum = borrow & (carry ^ 1);
    let mut r = d;
    cmov(&mut r, &s, keep_sum);
    r
}

/// `(a - b) mod m` for `a, b < m`.
fn sub_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (d, borrow) = sub_borrow(a, b);
    let (d2, _) = add_carry(&d, m);
    let mut r = d;
    cmov(&mut r, &d2, borrow);
    r
}

fn lt(a: &Limbs, b: &Limbs) -> bool {
    sub_borrow(a, b).1 == 1
}

fn be_to_limbs(b: &[u8; 32]) -> Limbs {
    let mut l = ZERO;
    let (chunks, _) = b.as_chunks::<8>();
    for (i, chunk) in chunks.iter().enumerate() {
        l[3 - i] = u64::from_be_bytes(*chunk);
    }
    l
}

fn limbs_to_be(l: &Limbs) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&l[i].to_be_bytes());
    }
    b
}

/// 33 little-endian bytes of a scalar (the recoding reads one byte past).
fn scalar_bytes(l: &Limbs) -> [u8; 33] {
    let mut s = [0u8; 33];
    for i in 0..4 {
        s[i * 8..(i + 1) * 8].copy_from_slice(&l[i].to_le_bytes());
    }
    s
}

/// Signed-digit recoding of a 6-bit window (ring's `booth_recode_w5`):
/// returns `magnitude << 1 | negative`.
fn booth_recode_w5(inp: u64) -> u64 {
    let s = !((inp >> 5).wrapping_sub(1));
    let mut d = (1u64 << 6).wrapping_sub(inp).wrapping_sub(1);
    d = (d & s) | (inp & !s);
    d = (d >> 1) + (d & 1);
    (d << 1) + (s & 1)
}

fn booth_recode_w7(inp: u64) -> u64 {
    let s = !((inp >> 7).wrapping_sub(1));
    let mut d = (1u64 << 8).wrapping_sub(inp).wrapping_sub(1);
    d = (d & s) | (inp & !s);
    d = (d >> 1) + (d & 1);
    (d << 1) + (s & 1)
}

impl Ops {
    /// Field inversion `a^(P-2)` (Montgomery domain, `a != 0`), by a fixed
    /// addition chain, so constant time.
    fn inv_p(self, a: &Limbs) -> Limbs {
        // e(k) = a^(2^k - 1)
        let mul = |x: &Limbs, y: &Limbs| self.mul(x, y);
        let e2 = mul(&self.sqr(a), a);
        let e3 = mul(&self.sqr(&e2), a);
        let e6 = mul(&self.sqr_n(&e3, 3), &e3);
        let e7 = mul(&self.sqr(&e6), a);
        let e14 = mul(&self.sqr_n(&e7, 7), &e7);
        let e15 = mul(&self.sqr(&e14), a);
        let e30 = mul(&self.sqr_n(&e15, 15), &e15);
        let e32 = mul(&self.sqr_n(&e30, 2), &e2);
        // 32 ones, 31 zeros, 1; then 96 zeros; then 32 ones twice; then
        // 30 ones, 0, 1.
        let mut r = mul(&self.sqr_n(&e32, 32), a);
        r = self.sqr_n(&r, 96);
        r = mul(&self.sqr_n(&r, 32), &e32);
        r = mul(&self.sqr_n(&r, 32), &e32);
        r = mul(&self.sqr_n(&r, 30), &e30);
        mul(&self.sqr_n(&r, 2), a)
    }

    /// Scalar inversion `a^(N-2)` (Montgomery domain of N, `a != 0`); the
    /// exponent is public, so the window pattern leaks nothing.
    fn inv_n(self, a: &Limbs) -> Limbs {
        let mut t = [ONE_N; 16];
        t[1] = *a;
        for i in 2..16 {
            t[i] = self.ord_mul(&t[i - 1], a);
        }
        let nib = |i: usize| -> usize { ((N_MINUS_2[i / 16] >> ((i % 16) * 4)) & 15) as usize };
        let mut r = t[nib(63)];
        for i in (0..63).rev() {
            r = self.ord_sqr_rep(&r, 4);
            r = self.ord_mul(&r, &t[nib(i)]);
        }
        r
    }

    fn to_mont_p(self, a: &Limbs) -> Limbs {
        self.mul(a, &RR_P)
    }

    fn demont_p(self, a: &Limbs) -> Limbs {
        self.mul(a, &ONE_RAW)
    }

    fn to_mont_n(self, a: &Limbs) -> Limbs {
        self.ord_mul(a, &RR_N)
    }

    fn demont_n(self, a: &Limbs) -> Limbs {
        self.ord_mul(a, &ONE_RAW)
    }

    /// Affine Montgomery coordinates of a Jacobian point; `None` at infinity.
    fn to_affine(self, p: &Jac) -> Option<Aff> {
        if (p.z[0] | p.z[1] | p.z[2] | p.z[3]) == 0 {
            return None;
        }
        let zi = self.inv_p(&p.z);
        let zi2 = self.sqr(&zi);
        let zi3 = self.mul(&zi2, &zi);
        Some(Aff {
            x: self.mul(&p.x, &zi2),
            y: self.mul(&p.y, &zi3),
        })
    }

    /// Is the affine point (Montgomery domain) on the curve?
    fn on_curve(self, x: &Limbs, y: &Limbs) -> bool {
        // y^2 == x^3 - 3x + b == x (x^2 - 3) + b
        let y2 = self.sqr(y);
        let x2 = self.sqr(x);
        let three = add_mod(&add_mod(&ONE_P, &ONE_P, &P), &ONE_P, &P);
        let t = self.mul(x, &sub_mod(&x2, &three, &P));
        let rhs = add_mod(&t, &B_MONT, &P);
        y2 == rhs
    }

    /// Montgomery-domain affine point from big-endian bytes, checking the
    /// coordinates are below P and the point is on the curve.
    fn point_from_bytes(self, x: &[u8; 32], y: &[u8; 32]) -> Option<Aff> {
        let (xl, yl) = (be_to_limbs(x), be_to_limbs(y));
        if !lt(&xl, &P) || !lt(&yl, &P) {
            return None;
        }
        let (xm, ym) = (self.to_mont_p(&xl), self.to_mont_p(&yl));
        self.on_curve(&xm, &ym).then_some(Aff { x: xm, y: ym })
    }

    /// `scalar * P` for a secret `scalar` in `1..N` (constant time): signed
    /// 5-bit windows over a table of 1P..16P.
    fn mul_var_ct(self, scalar: &Limbs, p: &Aff) -> Jac {
        const MASK: u64 = (1 << 6) - 1;
        let s = scalar_bytes(scalar);
        let mut table = [Jac::default(); 16];
        table[0] = Jac {
            x: p.x,
            y: p.y,
            z: ONE_P,
        };
        // Entry k-1 holds k*P.
        table[1] = self.dbl(&table[0]);
        table[2] = self.add(&table[1], &table[0]);
        table[3] = self.dbl(&table[1]);
        table[5] = self.dbl(&table[2]);
        table[7] = self.dbl(&table[3]);
        table[11] = self.dbl(&table[5]);
        table[4] = self.add(&table[3], &table[0]);
        table[6] = self.add(&table[5], &table[0]);
        table[8] = self.add(&table[7], &table[0]);
        table[12] = self.add(&table[11], &table[0]);
        table[13] = self.dbl(&table[6]);
        table[9] = self.dbl(&table[4]);
        table[14] = self.add(&table[13], &table[0]);
        table[10] = self.add(&table[9], &table[0]);
        table[15] = self.dbl(&table[7]);

        let mut index: usize = 255;
        let mut w = (u64::from(s[(index - 1) / 8]) >> ((index - 1) % 8)) & MASK;
        let mut r = select_w5(&table, booth_recode_w5(w) >> 1);
        while index >= 5 {
            if index != 255 {
                let off = (index - 1) / 8;
                w = u64::from(s[off]) | (u64::from(s[off + 1]) << 8);
                w = (w >> ((index - 1) % 8)) & MASK;
                w = booth_recode_w5(w);
                let mut h = select_w5(&table, w >> 1);
                let ny = neg(&h.y);
                cmov(&mut h.y, &ny, w & 1);
                r = self.add(&r, &h);
            }
            index -= 5;
            for _ in 0..5 {
                r = self.dbl(&r);
            }
        }
        w = (u64::from(s[0]) << 1) & MASK;
        w = booth_recode_w5(w);
        let mut h = select_w5(&table, w >> 1);
        let ny = neg(&h.y);
        cmov(&mut h.y, &ny, w & 1);
        r = self.add(&r, &h);
        r
    }

    /// `scalar * G` for a secret `scalar` (constant time), from the comb.
    fn mul_base_ct(self, scalar: &Limbs) -> Jac {
        let s = scalar_bytes(scalar);
        let tbl = g_table();
        let mut index: usize = 7;
        let mut w = booth_recode_w7((u64::from(s[0]) << 1) & 0xff);
        let mut t = select_w7(&tbl[0], w >> 1);
        let ny = neg(&t.y);
        cmov(&mut t.y, &ny, w & 1);
        let mut p = Jac {
            x: t.x,
            y: t.y,
            z: ZERO,
        };
        cmov(&mut p.z, &ONE_P, is_not_zero(w >> 1));
        for row in tbl.iter().skip(1) {
            let off = (index - 1) / 8;
            w = u64::from(s[off]) | (u64::from(s[off + 1]) << 8);
            w = (w >> ((index - 1) % 8)) & 0xff;
            index += 7;
            w = booth_recode_w7(w);
            let mut t = select_w7(row, w >> 1);
            let ny = neg(&t.y);
            cmov(&mut t.y, &ny, w & 1);
            p = self.add_affine(&p, &t);
        }
        p
    }

    /// `scalar * G` for a public `scalar` (variable time).
    fn mul_base_vartime(self, scalar: &Limbs) -> Jac {
        self.comb_vartime(g_table(), scalar)
    }

    /// `scalar * B` for a public `scalar` from the 37 x 64 comb of `B`
    /// (variable time).
    fn comb_vartime(self, tbl: &[[Aff; 64]], scalar: &Limbs) -> Jac {
        let s = scalar_bytes(scalar);
        let mut index: usize = 7;
        let w = booth_recode_w7((u64::from(s[0]) << 1) & 0xff);
        let mut p = Jac::default();
        if (w >> 1) != 0 {
            let e = &tbl[0][(w >> 1) as usize - 1];
            p = Jac {
                x: e.x,
                y: e.y,
                z: ONE_P,
            };
            if w & 1 == 1 {
                p.y = neg(&p.y);
            }
        }
        for row in tbl.iter().skip(1) {
            let off = (index - 1) / 8;
            let mut w = u64::from(s[off]) | (u64::from(s[off + 1]) << 8);
            w = (w >> ((index - 1) % 8)) & 0xff;
            index += 7;
            w = booth_recode_w7(w);
            if (w >> 1) == 0 {
                continue;
            }
            let mut t = row[(w >> 1) as usize - 1];
            if w & 1 == 1 {
                t.y = neg(&t.y);
            }
            p = self.add_affine(&p, &t);
        }
        p
    }
}

/// Signs: `(r, s)` of the prehash `z` with private key `d` and nonce `k`
/// (all big-endian 32 bytes, `d` and `k` in `1..N`). Constant time in `d`
/// and `k`. `None` for out-of-range inputs, or when `r` or `s` is zero (the
/// caller then draws the next nonce or takes the portable path).
pub fn sign(ops: Ops, d: &[u8; 32], k: &[u8; 32], z: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let mut dl = be_to_limbs(d);
    let mut kl = be_to_limbs(k);
    let zl = reduce_once(&be_to_limbs(z), &N);
    let ok = (dl != ZERO) & lt(&dl, &N) & (kl != ZERO) & lt(&kl, &N);
    if !ok {
        dl.zeroize();
        kl.zeroize();
        return None;
    }
    let mut big_r = ops.mul_base_ct(&kl);
    let aff = ops.to_affine(&big_r);
    big_r.x.zeroize();
    big_r.y.zeroize();
    big_r.z.zeroize();
    let aff = aff?;
    let x = ops.demont_p(&aff.x);
    let r = reduce_once(&x, &N);
    let mut km = ops.to_mont_n(&kl);
    let mut dm = ops.to_mont_n(&dl);
    let rm = ops.to_mont_n(&r);
    let zm = ops.to_mont_n(&zl);
    let mut kinv = ops.inv_n(&km);
    let rd = ops.ord_mul(&rm, &dm);
    let sum = add_mod(&rd, &zm, &N);
    let sm = ops.ord_mul(&kinv, &sum);
    let s = ops.demont_n(&sm);
    dl.zeroize();
    kl.zeroize();
    km.zeroize();
    dm.zeroize();
    kinv.zeroize();
    if r == ZERO || s == ZERO {
        return None;
    }
    Some((limbs_to_be(&r), limbs_to_be(&s)))
}

/// The public point `d * G` as big-endian affine coordinates (constant time
/// in `d`, `d` in `1..N`).
pub fn public_key(ops: Ops, d: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let mut dl = be_to_limbs(d);
    if dl == ZERO || !lt(&dl, &N) {
        dl.zeroize();
        return None;
    }
    let p = ops.mul_base_ct(&dl);
    dl.zeroize();
    let a = ops.to_affine(&p)?;
    Some((
        limbs_to_be(&ops.demont_p(&a.x)),
        limbs_to_be(&ops.demont_p(&a.y)),
    ))
}

/// ECDH: the x coordinate of `d * Q` for the peer point `(qx, qy)`, which is
/// validated (coordinates below P, on the curve). Constant time in `d`.
/// `None` for an invalid point, an out-of-range `d`, or the point at infinity.
pub fn ecdh(ops: Ops, d: &[u8; 32], qx: &[u8; 32], qy: &[u8; 32]) -> Option<[u8; 32]> {
    let q = ops.point_from_bytes(qx, qy)?;
    let mut dl = be_to_limbs(d);
    if dl == ZERO || !lt(&dl, &N) {
        dl.zeroize();
        return None;
    }
    let mut p = ops.mul_var_ct(&dl, &q);
    dl.zeroize();
    let a = ops.to_affine(&p);
    p.x.zeroize();
    p.y.zeroize();
    p.z.zeroize();
    let a = a?;
    Some(limbs_to_be(&ops.demont_p(&a.x)))
}

/// ECDSA verification (SEC 1 §4.1.4) of `(r, s)` over the prehash `z` with
/// public key `(qx, qy)`. Variable time: every input is public. The key is
/// validated (on the curve).
pub fn verify(
    ops: Ops,
    qx: &[u8; 32],
    qy: &[u8; 32],
    z: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> bool {
    verify_with(ops, KeyMul::Point(qx, qy), z, r, s)
}

/// How `u2 * Q` is computed in verification.
enum KeyMul<'a> {
    /// From the bytes of the key, by a windowed multiplication.
    Point(&'a [u8; 32], &'a [u8; 32]),
    /// From a precomputed comb of the key.
    Table(&'a KeyTable),
}

fn verify_with(ops: Ops, key: KeyMul<'_>, z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let (rl, sl) = (be_to_limbs(r), be_to_limbs(s));
    if rl == ZERO || sl == ZERO || !lt(&rl, &N) || !lt(&sl, &N) {
        return false;
    }
    let q = match key {
        KeyMul::Point(qx, qy) => {
            let Some(q) = ops.point_from_bytes(qx, qy) else {
                return false;
            };
            Some(q)
        }
        KeyMul::Table(_) => None,
    };
    let zl = reduce_once(&be_to_limbs(z), &N);
    let sinv = ops.inv_n(&ops.to_mont_n(&sl));
    let u1 = ops.demont_n(&ops.ord_mul(&ops.to_mont_n(&zl), &sinv));
    let u2 = ops.demont_n(&ops.ord_mul(&ops.to_mont_n(&rl), &sinv));
    let p1 = ops.mul_base_vartime(&u1);
    let p2 = match (&key, &q) {
        (_, _) if u2 == ZERO => Jac::default(),
        (KeyMul::Table(t), _) => ops.comb_vartime(&t.rows, &u2),
        (_, Some(q)) => ops.mul_var_ct(&u2, q),
        _ => return false,
    };
    let sum = ops.add(&p1, &p2);
    if (sum.z[0] | sum.z[1] | sum.z[2] | sum.z[3]) == 0 {
        return false;
    }
    // x(R) = X / Z^2; compare with r (and r + N when that is below P)
    // without inverting: X == r * Z^2.
    let z2 = ops.sqr(&sum.z);
    let hit = |v: &Limbs| ops.mul(&ops.to_mont_p(v), &z2) == sum.x;
    if hit(&rl) {
        return true;
    }
    let (rn, carry) = add_carry(&rl, &N);
    carry == 0 && lt(&rn, &P) && hit(&rn)
}

/// A fixed public key's comb (the same 37 x 64 layout as the generator's, 148
/// KiB on the heap): verification against that key then takes one table walk
/// instead of a windowed multiplication. Built once per trust anchor.
pub struct KeyTable {
    rows: alloc::vec::Vec<[Aff; 64]>,
    qx: [u8; 32],
    qy: [u8; 32],
}

impl KeyTable {
    /// The comb of the point `(qx, qy)` (big-endian), `None` if it is not on
    /// the curve.
    pub fn new(ops: Ops, qx: &[u8; 32], qy: &[u8; 32]) -> Option<Self> {
        let q = ops.point_from_bytes(qx, qy)?;
        let mut jac = alloc::vec::Vec::with_capacity(37 * 64);
        let mut base = Jac {
            x: q.x,
            y: q.y,
            z: ONE_P,
        };
        for _ in 0..37 {
            let mut e = base;
            jac.push(e);
            for _ in 1..64 {
                e = ops.add(&e, &base);
                jac.push(e);
            }
            // e is now 64 * base; 128 * base is the next row's base.
            base = ops.dbl(&e);
        }
        // Batch conversion to affine: one inversion for all points.
        let mut prefix = alloc::vec::Vec::with_capacity(jac.len());
        let mut acc = ONE_P;
        for p in &jac {
            acc = ops.mul(&acc, &p.z);
            prefix.push(acc);
        }
        let mut inv = ops.inv_p(&acc);
        let mut rows = alloc::vec![[Aff::default(); 64]; 37];
        for i in (0..jac.len()).rev() {
            let zinv = if i == 0 {
                inv
            } else {
                ops.mul(&inv, &prefix[i - 1])
            };
            inv = ops.mul(&inv, &jac[i].z);
            let zi2 = ops.sqr(&zinv);
            let zi3 = ops.mul(&zi2, &zinv);
            rows[i / 64][i % 64] = Aff {
                x: ops.mul(&jac[i].x, &zi2),
                y: ops.mul(&jac[i].y, &zi3),
            };
        }
        Some(Self {
            rows,
            qx: *qx,
            qy: *qy,
        })
    }

    /// The key's uncompressed coordinates the table was built from.
    pub fn point(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.qx, &self.qy)
    }

    /// ECDSA verification by this key (variable time; as [`verify`]).
    pub fn verify(&self, ops: Ops, z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        verify_with(ops, KeyMul::Table(self), z, r, s)
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod timing;
