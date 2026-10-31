//! X25519 (RFC 7748) on four 64-bit limbs (ADR-131, PERF).
//!
//! The field is GF(2^255 - 19) with elements held in four little-endian
//! 64-bit limbs, "loosely reduced": any value below 2^256 is accepted and
//! produced between operations (2^256 = 38 mod p), and only the final
//! encoding is canonical. Multiplication has two implementations with
//! identical results: portable Rust on `u128`, and on x86_64 an assembly
//! block using MULX and ADCX/ADOX (BMI2 and ADX), chosen once through
//! `cpufeatures` (the kernel's sealed dispatch on bare metal). Under Miri
//! only the portable one exists.
//!
//! The Montgomery ladder is the one of RFC 7748 §5 with a constant-time
//! conditional swap; there is no secret-dependent branch or memory index.
//! Unsafe code is limited to the inline assembly in `adx.rs`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod adx;

type Fe = [u64; 4];

const A24: u64 = 121_665;

/// Which multiplication runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backend {
    Portable,
    /// x86_64 MULX/ADCX/ADOX assembly.
    Adx,
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
cpufeatures::new!(adx_bmi2, "bmi2", "adx");

impl Backend {
    /// The best backend for this CPU.
    pub fn detect() -> Self {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if adx_bmi2::get() {
            return Self::Adx;
        }
        Self::Portable
    }

    /// The assembly backend, if this CPU can run it (tests, benchmarks).
    pub fn adx_if_available() -> Option<Self> {
        (Self::detect() == Self::Adx).then_some(Self::Adx)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::Adx => "adx",
        }
    }
}

/// 256x256 -> 512 bit product, folded to 256 bits (2^256 = 38 mod p).
fn mul_portable(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let v = u128::from(a[j]) * u128::from(b[i]) + u128::from(t[i + j]) + u128::from(carry);
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        t[i + 4] = carry;
    }
    fold(&t)
}

/// `t_low + 38 * t_high`, twice, to a value below 2^256.
fn fold(t: &[u64; 8]) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let v = u128::from(t[i]) + u128::from(t[i + 4]) * 38 + u128::from(carry);
        r[i] = v as u64;
        carry = (v >> 64) as u64;
    }
    // carry <= 38; fold it once more.
    let mut c = carry * 38;
    for limb in &mut r {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = u64::from(o);
    }
    // A last carry leaves a tiny value in the low limb: absorb 38 safely.
    r[0] = r[0].wrapping_add(c * 38);
    r
}

fn add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut c = 0u64;
    for i in 0..4 {
        let (s1, o1) = a[i].overflowing_add(b[i]);
        let (s2, o2) = s1.overflowing_add(c);
        r[i] = s2;
        c = u64::from(o1 | o2);
    }
    let mut c = c * 38;
    for limb in &mut r {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = u64::from(o);
    }
    r[0] = r[0].wrapping_add(c * 38);
    r
}

fn sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut bw = 0u64;
    for i in 0..4 {
        let (d1, o1) = a[i].overflowing_sub(b[i]);
        let (d2, o2) = d1.overflowing_sub(bw);
        r[i] = d2;
        bw = u64::from(o1 | o2);
    }
    // 2^256 = 38: subtract 38 per borrow, twice (the second cannot recur).
    for _ in 0..2 {
        let mut c = bw * 38;
        bw = 0;
        for limb in &mut r {
            let (d, o) = limb.overflowing_sub(c);
            *limb = d;
            c = u64::from(o);
        }
        bw = bw.max(c);
    }
    r
}

/// `a * 121665` folded.
fn mul_a24(a: &Fe) -> Fe {
    let mut t = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let v = u128::from(a[i]) * u128::from(A24) + u128::from(carry);
        t[i] = v as u64;
        carry = (v >> 64) as u64;
    }
    let mut c = carry * 38;
    for limb in &mut t {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = u64::from(o);
    }
    t[0] = t[0].wrapping_add(c * 38);
    t
}

/// Constant-time swap of `a` and `b` when `swap == 1`.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..4 {
        let x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

/// Everything the ladder needs from a field implementation.
trait Field {
    fn mul(a: &Fe, b: &Fe) -> Fe;
    fn sqr(a: &Fe) -> Fe {
        Self::mul(a, a)
    }
}

struct Soft;
impl Field for Soft {
    fn mul(a: &Fe, b: &Fe) -> Fe {
        mul_portable(a, b)
    }
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
struct Mulx;
#[cfg(all(target_arch = "x86_64", not(miri)))]
impl Field for Mulx {
    fn mul(a: &Fe, b: &Fe) -> Fe {
        adx::mul(a, b)
    }
    fn sqr(a: &Fe) -> Fe {
        adx::sqr(a)
    }
}

fn sqr_n<F: Field>(a: &Fe, n: u32) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = F::sqr(&r);
    }
    r
}

/// `z^(p-2)`.
fn invert<F: Field>(z: &Fe) -> Fe {
    let z2 = F::sqr(z);
    let z8 = sqr_n::<F>(&z2, 2);
    let z9 = F::mul(z, &z8);
    let z11 = F::mul(&z2, &z9);
    let z22 = F::sqr(&z11);
    let e5 = F::mul(&z9, &z22); // 2^5 - 1
    let e10 = F::mul(&sqr_n::<F>(&e5, 5), &e5);
    let e20 = F::mul(&sqr_n::<F>(&e10, 10), &e10);
    let e40 = F::mul(&sqr_n::<F>(&e20, 20), &e20);
    let e50 = F::mul(&sqr_n::<F>(&e40, 10), &e10);
    let e100 = F::mul(&sqr_n::<F>(&e50, 50), &e50);
    let e200 = F::mul(&sqr_n::<F>(&e100, 100), &e100);
    let e250 = F::mul(&sqr_n::<F>(&e200, 50), &e50);
    F::mul(&sqr_n::<F>(&e250, 5), &z11)
}

fn ladder<F: Field>(k: &[u8; 32], u: &Fe) -> Fe {
    let x1 = *u;
    let mut x2: Fe = [1, 0, 0, 0];
    let mut z2: Fe = [0; 4];
    let mut x3 = *u;
    let mut z3: Fe = [1, 0, 0, 0];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = F::sqr(&a);
        let b = sub(&x2, &z2);
        let bb = F::sqr(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = F::mul(&d, &a);
        let cb = F::mul(&c, &b);
        x3 = F::sqr(&add(&da, &cb));
        z3 = F::mul(&x1, &F::sqr(&sub(&da, &cb)));
        x2 = F::mul(&aa, &bb);
        z2 = F::mul(&e, &add(&aa, &mul_a24(&e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    F::mul(&x2, &invert::<F>(&z2))
}

/// Canonical little-endian encoding of a loosely reduced element.
fn encode(v: &Fe) -> [u8; 32] {
    let mut v = *v;
    // Fold the top bit: v = (v mod 2^255) + 19 * (v >> 255)  (< 2^255 + 38).
    let hi = v[3] >> 63;
    v[3] &= 0x7fff_ffff_ffff_ffff;
    let mut c = hi * 19;
    for limb in &mut v {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = u64::from(o);
    }
    // q = 1 iff v >= p (v + 19 reaches 2^255); then v + 19*q mod 2^255.
    let mut q = 19u64;
    let mut t = v;
    for limb in &mut t {
        let (s, o) = limb.overflowing_add(q);
        *limb = s;
        q = u64::from(o);
    }
    let q = t[3] >> 63;
    let mut c = q * 19;
    for limb in &mut v {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = u64::from(o);
    }
    v[3] &= 0x7fff_ffff_ffff_ffff;
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v[i].to_le_bytes());
    }
    out
}

fn decode(u: &[u8; 32]) -> Fe {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&u[i * 8..(i + 1) * 8]);
        r[i] = u64::from_le_bytes(w);
    }
    r[3] &= 0x7fff_ffff_ffff_ffff;
    r
}

/// `X25519(k, u)` of RFC 7748 §5: `k` is clamped here, the top bit of `u` is
/// ignored. Constant time. The all-zero result of a small-order `u` is
/// returned as is; callers that need contributory behaviour check for it.
pub fn x25519(backend: Backend, k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let u = decode(u);
    let r = match backend {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        Backend::Adx => ladder::<Mulx>(&k, &u),
        _ => ladder::<Soft>(&k, &u),
    };
    let out = encode(&r);
    // Clamped copy of the secret scalar.
    for b in &mut k {
        // SAFETY: a volatile write to a valid `&mut u8`, to keep the wipe.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    out
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod timing;
