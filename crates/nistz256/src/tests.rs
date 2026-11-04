//! Differential tests against the portable RustCrypto implementation (the
//! reference) on random and edge inputs, for every assembly variant (x86_64:
//! plain `mul` and MULX/ADX where the CPU has it; AArch64: the ARMv8 code).

use super::*;
use ecdsa::hazmat::{sign_prehashed, verify_prehashed};
use p256::NonZeroScalar;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::ToSec1Point;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn variants() -> std::vec::Vec<Ops> {
    let mut v = std::vec![Ops::portable()];
    if let Some(o) = Ops::adx_if_available() {
        v.push(o);
    }
    v
}

fn rand32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

/// A random scalar in `1..N` as bytes.
fn rand_scalar(rng: &mut ChaCha20Rng) -> [u8; 32] {
    loop {
        let b = rand32(rng);
        let l = be_to_limbs(&b);
        if l != ZERO && lt(&l, &N) {
            return b;
        }
    }
}

/// `a * b mod m` by double-and-add (slow, obviously correct given `add_mod`).
fn ref_mulmod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let mut r = ZERO;
    for i in (0..256).rev() {
        r = add_mod(&r, &r, m);
        if (b[i / 64] >> (i % 64)) & 1 == 1 {
            r = add_mod(&r, a, m);
        }
    }
    r
}

fn edge_values(m: &Limbs) -> std::vec::Vec<Limbs> {
    let m1 = sub_borrow(m, &[1, 0, 0, 0]).0;
    let m2 = sub_borrow(m, &[2, 0, 0, 0]).0;
    let half = [
        m[0] >> 1 | (m[1] << 63),
        m[1] >> 1 | (m[2] << 63),
        m[2] >> 1 | (m[3] << 63),
        m[3] >> 1,
    ];
    std::vec![
        ZERO,
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        m1,
        m2,
        half,
        [u64::MAX, 0, 0, 0],
        [0, u64::MAX, 0, 0],
        [0, 0, u64::MAX, 0],
        [u64::MAX, u64::MAX, 0, 0],
        [0, 0, 0, 0x7fff_ffff_ffff_ffff],
        [u64::MAX, u64::MAX, u64::MAX, 0],
        [
            0x0000_0000_ffff_ffff,
            0xffff_ffff_0000_0000,
            0x0000_0000_ffff_ffff,
            0xffff_ffff_0000_0000
        ],
        ONE_P,
        ONE_N,
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [0, 1, 0, 0],
    ]
}

fn check_field(
    m: &Limbs,
    one_m: &Limbs,
    mul: &dyn Fn(&Limbs, &Limbs) -> Limbs,
    sqr: &dyn Fn(&Limbs) -> Limbs,
    rng: &mut ChaCha20Rng,
) {
    let mut vals: std::vec::Vec<Limbs> = edge_values(m).into_iter().filter(|v| lt(v, m)).collect();
    for _ in 0..300 {
        let v = be_to_limbs(&rand32(rng));
        vals.push(reduce_once(&v, m)); // < m for any 256-bit v when 2m > 2^256
    }
    vals.retain(|v| lt(v, m));
    for a in &vals {
        // sqr(a) * R == a * a
        let s = sqr(a);
        assert!(lt(&s, m), "unreduced square");
        assert_eq!(ref_mulmod(&s, one_m, m), ref_mulmod(a, a, m), "sqr {a:x?}");
    }
    for (i, a) in vals.iter().enumerate() {
        for b in vals.iter().skip(i % 5).step_by(7).take(40) {
            let p = mul(a, b);
            assert!(lt(&p, m), "unreduced product");
            assert_eq!(
                ref_mulmod(&p, one_m, m),
                ref_mulmod(a, b, m),
                "mul {a:x?} {b:x?}"
            );
        }
    }
}

#[test]
fn field_arithmetic_matches_schoolbook_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for ops in variants() {
        check_field(&P, &ONE_P, &|a, b| ops.mul(a, b), &|a| ops.sqr(a), &mut rng);
        check_field(
            &N,
            &ONE_N,
            &|a, b| ops.ord_mul(a, b),
            &|a| ops.ord_sqr_rep(a, 1),
            &mut rng,
        );
        // Repeated squaring.
        let a = reduce_once(&be_to_limbs(&rand32(&mut rng)), &N);
        let mut want = a;
        for rep in 1..=9u64 {
            want = ops.ord_mul(&want, &want);
            assert_eq!(ops.ord_sqr_rep(&a, rep), want, "ord_sqr_rep {rep}");
        }
    }
}

#[test]
fn inversions_invert() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for ops in variants() {
        for _ in 0..100 {
            let a = reduce_once(&be_to_limbs(&rand32(&mut rng)), &P);
            if a == ZERO {
                continue;
            }
            assert_eq!(ops.mul(&ops.inv_p(&a), &a), ONE_P);
            let b = reduce_once(&be_to_limbs(&rand32(&mut rng)), &N);
            if b == ZERO {
                continue;
            }
            assert_eq!(ops.ord_mul(&ops.inv_n(&b), &b), ONE_N);
        }
        let m1 = sub_borrow(&P, &[1, 0, 0, 0]).0;
        assert_eq!(ops.mul(&ops.inv_p(&m1), &m1), ONE_P);
        let n1 = sub_borrow(&N, &[1, 0, 0, 0]).0;
        assert_eq!(ops.ord_mul(&ops.inv_n(&n1), &n1), ONE_N);
        assert_eq!(ops.inv_p(&ONE_P), ONE_P);
        assert_eq!(ops.inv_n(&ONE_N), ONE_N);
    }
}

/// The variable-time scalar inversion of verification gives the Fermat
/// chain's result (both converted to plain form) and refuses 0 and N.
#[test]
fn the_variable_time_scalar_inversion_matches_the_fermat_chain() {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    for ops in variants() {
        let mut cases: std::vec::Vec<Limbs> = std::vec![
            ONE_RAW,
            [2, 0, 0, 0],
            sub_borrow(&N, &[1, 0, 0, 0]).0,
            sub_borrow(&N, &[2, 0, 0, 0]).0,
        ];
        for _ in 0..500 {
            cases.push(be_to_limbs(&rand_scalar(&mut rng)));
        }
        for a in cases {
            let want = ops.demont_n(&ops.inv_n(&ops.to_mont_n(&a)));
            assert_eq!(ops.inv_n_vartime(&a), Some(want), "{a:x?}");
        }
        assert_eq!(ops.inv_n_vartime(&ZERO), None);
        assert_eq!(ops.inv_n_vartime(&N), None);
    }
}

/// The width-5 NAF reconstructs the scalar and has the NAF shape (odd
/// digits in -15..=15, four zeros after each non-zero digit).
#[test]
fn wnaf_digits_reconstruct_the_scalar() {
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    let mut cases: std::vec::Vec<Limbs> = std::vec![ZERO, ONE_RAW, [u64::MAX; 4], N, P];
    for _ in 0..2000 {
        let mut l = be_to_limbs(&rand32(&mut rng));
        if rng.next_u32() % 4 == 0 {
            l[(rng.next_u32() % 4) as usize] = u64::MAX;
        }
        cases.push(l);
    }
    for k in cases {
        let naf = wnaf5(&k);
        // sum naf[i] 2^i, over 5 limbs with signed digits (two's complement).
        let mut acc = [0u64; 5];
        for (i, &d) in naf.iter().enumerate() {
            if d == 0 {
                continue;
            }
            assert!(d % 2 != 0 && (-15..=15).contains(&d), "digit {d}");
            for j in 1..5 {
                if let Some(&e) = naf.get(i + j) {
                    assert_eq!(e, 0, "non-zero digit {j} after {i}");
                }
            }
            let mut add = [0u64; 5];
            let mag = u64::from(d.unsigned_abs());
            add[i / 64] = mag << (i % 64);
            if i % 64 != 0 && i / 64 + 1 < 5 {
                add[i / 64 + 1] = mag >> (64 - i % 64);
            }
            let mut c = 0u64;
            for j in 0..5 {
                if d > 0 {
                    let (v, o1) = acc[j].overflowing_add(add[j]);
                    let (v, o2) = v.overflowing_add(c);
                    acc[j] = v;
                    c = u64::from(o1 | o2);
                } else {
                    let (v, o1) = acc[j].overflowing_sub(add[j]);
                    let (v, o2) = v.overflowing_sub(c);
                    acc[j] = v;
                    c = u64::from(o1 | o2);
                }
            }
        }
        assert_eq!(acc, [k[0], k[1], k[2], k[3], 0], "{k:x?}");
    }
}

/// Verification corners: keys G and -G (d = 1 and d = N - 1, so u1 G and
/// u2 Q can be equal or opposite), u1 = 0 (z = 0 and z = N), small and
/// sparse nonces; every verdict, valid and tampered, equals the stock one.
#[test]
fn verification_corner_cases_agree_with_the_stock_verifier() {
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    let n1 = limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0);
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;
    let mut keys = std::vec![one, two, n1];
    keys.push(rand_scalar(&mut rng));
    let mut nonces = std::vec![one, two, n1];
    nonces.push(rand_scalar(&mut rng));
    let mut msgs = std::vec![[0u8; 32], limbs_to_be(&N), rand32(&mut rng)];
    msgs.push(n1);
    for ops in variants() {
        for d in &keys {
            let (qx, qy) = stock_point(d);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&{
                let mut v = std::vec![4u8];
                v.extend_from_slice(&qx);
                v.extend_from_slice(&qy);
                v
            })
            .unwrap();
            let stock = |z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]| -> bool {
                match (
                    Option::<p256::Scalar>::from(p256::Scalar::from_repr((*r).into())),
                    Option::<p256::Scalar>::from(p256::Scalar::from_repr((*s).into())),
                ) {
                    (Some(rs), Some(ss)) => p256::ecdsa::Signature::from_scalars(rs, ss)
                        .ok()
                        .is_some_and(|sig| {
                            verify_prehashed::<p256::NistP256>(&vk.as_affine().into(), z, &sig)
                                .is_ok()
                        }),
                    _ => false,
                }
            };
            for k in &nonces {
                for z in &msgs {
                    let Some((r, s)) = stock_sign(d, k, z) else {
                        continue;
                    };
                    assert!(
                        verify(ops, &qx, &qy, z, &r, &s),
                        "valid d={d:02x?} k={k:02x?}"
                    );
                    // r = s makes u1 G and u2 Q depend on the same factor;
                    // r and s swapped; z flipped.
                    let mut z2 = *z;
                    z2[31] ^= 1;
                    for (zz, rr, ss) in [(*z, r, r), (*z, s, r), (z2, r, s), (*z, r, n1)] {
                        assert_eq!(verify(ops, &qx, &qy, &zz, &rr, &ss), stock(&zz, &rr, &ss));
                    }
                }
            }
        }
    }
}

#[test]
fn modular_helpers() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for m in [P, N] {
        for _ in 0..200 {
            let a = reduce_once(&be_to_limbs(&rand32(&mut rng)), &m);
            let b = reduce_once(&be_to_limbs(&rand32(&mut rng)), &m);
            let s = add_mod(&a, &b, &m);
            assert!(lt(&s, &m));
            assert_eq!(sub_mod(&s, &b, &m), a);
            assert_eq!(add_mod(&sub_mod(&a, &b, &m), &b, &m), a);
        }
        let m1 = sub_borrow(&m, &[1, 0, 0, 0]).0;
        assert_eq!(add_mod(&m1, &m1, &m), sub_borrow(&m, &[2, 0, 0, 0]).0);
        assert_eq!(add_mod(&m1, &[1, 0, 0, 0], &m), ZERO);
        assert_eq!(sub_mod(&ZERO, &[1, 0, 0, 0], &m), m1);
    }
}

#[test]
fn the_generator_table_is_the_comb_of_the_generator() {
    use p256::elliptic_curve::Group;
    let ops = Ops::portable();
    let g = p256::ProjectivePoint::generator();
    let tbl = g_table();
    // Every entry (j+1) * 2^(7 i) * G, checked against the portable code.
    for (i, row) in tbl.iter().enumerate() {
        let mut base = [0u8; 32];
        // 2^(7 i) as a big-endian scalar (i up to 36 -> bit 252).
        let bit = 7 * i;
        base[31 - bit / 8] = 1 << (bit % 8);
        let step = p256::Scalar::from_repr(base.into()).unwrap();
        for (j, e) in row.iter().enumerate() {
            let k = step * p256::Scalar::from((j + 1) as u64);
            let want = (g * k).to_affine().to_sec1_point(false);
            let (x, y) = (
                limbs_to_be(&ops.demont_p(&e.x)),
                limbs_to_be(&ops.demont_p(&e.y)),
            );
            assert_eq!(&want.as_bytes()[1..33], &x, "x of row {i} entry {j}");
            assert_eq!(&want.as_bytes()[33..], &y, "y of row {i} entry {j}");
        }
    }
}

fn stock_point(d: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sk = p256::SecretKey::from_slice(d).unwrap();
    let e = sk.public_key().to_sec1_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&e.as_bytes()[1..33]);
    y.copy_from_slice(&e.as_bytes()[33..]);
    (x, y)
}

#[test]
fn public_keys_match() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let mut cases: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
    for small in [1u8, 2, 3, 15, 16, 17, 127, 128, 129, 255] {
        let mut b = [0u8; 32];
        b[31] = small;
        cases.push(b);
    }
    // n-1, n-2 and scalars with long runs of ones and zeros.
    let n1 = limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0);
    let n2 = limbs_to_be(&sub_borrow(&N, &[2, 0, 0, 0]).0);
    cases.push(n1);
    cases.push(n2);
    let mut b = [0xffu8; 32];
    b[0] = 0x7f;
    cases.push(b);
    let mut b = [0u8; 32];
    b[0] = 0x80;
    cases.push(b);
    let mut b = [0u8; 32];
    b[16] = 1;
    cases.push(b);
    for _ in 0..300 {
        cases.push(rand_scalar(&mut rng));
    }
    for ops in variants() {
        for d in &cases {
            assert_eq!(public_key(ops, d), Some(stock_point(d)), "d = {d:02x?}");
        }
    }
    assert_eq!(public_key(Ops::portable(), &[0; 32]), None);
    assert_eq!(public_key(Ops::portable(), &limbs_to_be(&N)), None);
}

#[test]
fn ecdh_matches_and_rejects_bad_points() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    for ops in variants() {
        for _ in 0..150 {
            let a = rand_scalar(&mut rng);
            let b = rand_scalar(&mut rng);
            let (qx, qy) = stock_point(&b);
            let sa = p256::SecretKey::from_slice(&a).unwrap();
            let pb = p256::PublicKey::from_sec1_bytes(&{
                let mut v = std::vec![4u8];
                v.extend_from_slice(&qx);
                v.extend_from_slice(&qy);
                v
            })
            .unwrap();
            let want = p256::ecdh::diffie_hellman(sa.to_nonzero_scalar(), pb.as_affine());
            let got = ecdh(ops, &a, &qx, &qy).unwrap();
            assert_eq!(&got[..], want.raw_secret_bytes().as_slice());
            // Off the curve.
            let mut bad = qy;
            bad[31] ^= 1;
            assert_eq!(ecdh(ops, &a, &qx, &bad), None);
            // Coordinate not below P.
            assert_eq!(ecdh(ops, &a, &limbs_to_be(&P), &qy), None);
        }
        // Small and large scalars against the generator itself.
        let (gx, gy) = stock_point(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        });
        for d in [1u8, 2, 3, 31, 32, 33] {
            let mut k = [0u8; 32];
            k[31] = d;
            let want = stock_point(&k).0;
            assert_eq!(ecdh(ops, &k, &gx, &gy), Some(want));
        }
        let n1 = limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0);
        assert_eq!(ecdh(ops, &n1, &gx, &gy), Some(stock_point(&n1).0));
        assert_eq!(ecdh(ops, &[0; 32], &gx, &gy), None);
        assert_eq!(ecdh(ops, &limbs_to_be(&N), &gx, &gy), None);
        assert_eq!(ecdh(ops, &[0; 32], &[0; 32], &[0; 32]), None);
    }
}

fn stock_sign(d: &[u8; 32], k: &[u8; 32], z: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let ds = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr((*d).into())).unwrap();
    let ks = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr((*k).into())).unwrap();
    let (sig, _) = sign_prehashed::<p256::NistP256>(&ds, &ks, z).ok()?;
    let b = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&b[..32]);
    s.copy_from_slice(&b[32..]);
    Some((r, s))
}

#[test]
fn signatures_match_the_stock_implementation_bit_for_bit() {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    for ops in variants() {
        for i in 0..300 {
            let d = rand_scalar(&mut rng);
            let k = rand_scalar(&mut rng);
            let z = match i {
                0 => [0u8; 32],
                1 => [0xff; 32],
                2 => limbs_to_be(&N),
                3 => limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0),
                _ => rand32(&mut rng),
            };
            assert_eq!(sign(ops, &d, &k, &z), stock_sign(&d, &k, &z), "case {i}");
        }
        let mut one = [0u8; 32];
        one[31] = 1;
        let n1 = limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0);
        for (d, k) in [(one, one), (n1, n1), (one, n1), (n1, one)] {
            let z = rand32(&mut rng);
            assert_eq!(sign(ops, &d, &k, &z), stock_sign(&d, &k, &z));
        }
        assert_eq!(sign(ops, &[0; 32], &one, &one), None);
        assert_eq!(sign(ops, &one, &[0; 32], &one), None);
        assert_eq!(sign(ops, &one, &limbs_to_be(&N), &one), None);
    }
}

#[test]
fn verification_agrees_with_the_stock_verifier() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    for ops in variants() {
        let mut accepted = 0;
        for i in 0..300 {
            let d = rand_scalar(&mut rng);
            let k = rand_scalar(&mut rng);
            let z = rand32(&mut rng);
            let (qx, qy) = stock_point(&d);
            let (r, s) = stock_sign(&d, &k, &z).unwrap();
            assert!(verify(ops, &qx, &qy, &z, &r, &s), "valid {i}");
            accepted += 1;
            // Tampered inputs must agree with the stock verdict.
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&{
                let mut v = std::vec![4u8];
                v.extend_from_slice(&qx);
                v.extend_from_slice(&qy);
                v
            })
            .unwrap();
            let stock = |z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]| -> bool {
                let rs = p256::Scalar::from_repr((*r).into());
                let ss = p256::Scalar::from_repr((*s).into());
                match (
                    Option::<p256::Scalar>::from(rs),
                    Option::<p256::Scalar>::from(ss),
                ) {
                    (Some(rs), Some(ss)) => p256::ecdsa::Signature::from_scalars(rs, ss)
                        .ok()
                        .is_some_and(|sig| {
                            verify_prehashed::<p256::NistP256>(&vk.as_affine().into(), z, &sig)
                                .is_ok()
                        }),
                    _ => false,
                }
            };
            let mut z2 = z;
            z2[(i % 32) as usize] ^= 1 << (i % 8);
            let mut r2 = r;
            r2[(i * 7 % 32) as usize] ^= 1 << (i % 8);
            let mut s2 = s;
            s2[(i * 13 % 32) as usize] ^= 1 << ((i + 3) % 8);
            for (zz, rr, ss) in [(z2, r, s), (z, r2, s), (z, r, s2), (z, s, r), (z, r, r)] {
                assert_eq!(
                    verify(ops, &qx, &qy, &zz, &rr, &ss),
                    stock(&zz, &rr, &ss),
                    "case {i}"
                );
            }
            // Another key.
            let (ox, oy) = stock_point(&rand_scalar(&mut rng));
            assert!(!verify(ops, &ox, &oy, &z, &r, &s));
        }
        assert_eq!(accepted, 300);
        // Range and key checks.
        let d = rand_scalar(&mut rng);
        let (qx, qy) = stock_point(&d);
        let z = rand32(&mut rng);
        let (r, s) = stock_sign(&d, &rand_scalar(&mut rng), &z).unwrap();
        assert!(verify(ops, &qx, &qy, &z, &r, &s));
        assert!(!verify(ops, &qx, &qy, &z, &[0; 32], &s));
        assert!(!verify(ops, &qx, &qy, &z, &r, &[0; 32]));
        assert!(!verify(ops, &qx, &qy, &z, &limbs_to_be(&N), &s));
        assert!(!verify(ops, &qx, &qy, &z, &r, &limbs_to_be(&N)));
        let mut bad = qy;
        bad[0] ^= 1;
        assert!(!verify(ops, &qx, &bad, &z, &r, &s));
        // r + N below P: not representable for random r, so craft: the
        // signature with r' = r + N (when r < P - N) must be rejected as
        // r' >= N.
        let (rn, c) = add_carry(&be_to_limbs(&r), &N);
        if c == 0 {
            assert!(!verify(ops, &qx, &qy, &z, &limbs_to_be(&rn), &s));
        }
    }
}

/// Signing with the nonce that makes `u1 G == u2 Q` is not reachable; the
/// doubling case of the complete addition is covered by `mul_var_ct` on tiny
/// scalars above (2P = P + P through the table) and here directly.
#[test]
fn point_addition_handles_equal_opposite_and_infinity() {
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    for ops in variants() {
        let d = rand_scalar(&mut rng);
        let (x, y) = stock_point(&d);
        let q = ops.point_from_bytes(&x, &y).unwrap();
        let j = Jac {
            x: q.x,
            y: q.y,
            z: ONE_P,
        };
        let doubled = ops.to_affine(&ops.add(&j, &j)).unwrap();
        let want = ops.to_affine(&ops.dbl(&j)).unwrap();
        assert_eq!((doubled.x, doubled.y), (want.x, want.y));
        let nj = Jac {
            x: q.x,
            y: neg(&q.y),
            z: ONE_P,
        };
        assert!(ops.to_affine(&ops.add(&j, &nj)).is_none());
        let inf = Jac::default();
        let s1 = ops.to_affine(&ops.add(&inf, &j)).unwrap();
        let s2 = ops.to_affine(&ops.add(&j, &inf)).unwrap();
        assert_eq!((s1.x, s1.y), (q.x, q.y));
        assert_eq!((s2.x, s2.y), (q.x, q.y));
        assert!(ops.to_affine(&ops.add(&inf, &inf)).is_none());
    }
}

#[test]
fn key_tables_verify_like_the_plain_path_and_hold_the_right_points() {
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    for ops in variants() {
        let d = rand_scalar(&mut rng);
        let (qx, qy) = stock_point(&d);
        let table = KeyTable::new(ops, &qx, &qy).unwrap();
        assert_eq!(table.point(), (&qx, &qy));
        // Spot-check entries against the portable arithmetic.
        let q = p256::PublicKey::from_secret_scalar(
            &p256::SecretKey::from_slice(&d).unwrap().to_nonzero_scalar(),
        );
        for (i, j) in [
            (0usize, 0usize),
            (0, 1),
            (0, 63),
            (1, 0),
            (5, 17),
            (36, 0),
            (36, 63),
        ] {
            let mut step = [0u8; 32];
            let bit = 7 * i;
            step[31 - bit / 8] = 1 << (bit % 8);
            let k =
                p256::Scalar::from_repr(step.into()).unwrap() * p256::Scalar::from((j + 1) as u64);
            let want = (q.to_projective() * k).to_affine().to_sec1_point(false);
            let e = &table.rows[i][j];
            assert_eq!(&want.as_bytes()[1..33], &limbs_to_be(&ops.demont_p(&e.x)));
            assert_eq!(&want.as_bytes()[33..], &limbs_to_be(&ops.demont_p(&e.y)));
        }
        for i in 0..100 {
            let k = rand_scalar(&mut rng);
            let z = rand32(&mut rng);
            let (r, s) = stock_sign(&d, &k, &z).unwrap();
            assert!(table.verify(ops, &z, &r, &s), "valid {i}");
            let mut z2 = z;
            z2[i % 32] ^= 1;
            assert!(!table.verify(ops, &z2, &r, &s));
            let mut s2 = s;
            s2[(i * 5) % 32] ^= 0x10;
            assert_eq!(
                table.verify(ops, &z, &r, &s2),
                verify(ops, &qx, &qy, &z, &r, &s2)
            );
            assert!(!table.verify(ops, &z, &s, &r));
        }
        assert!(KeyTable::new(ops, &qx, &[0u8; 32]).is_none());
    }
}

/// The constant-time table scans return exactly entry `index - 1`, and zero
/// for index 0, for every index (on AArch64 these are the Rust scans that
/// replace upstream's NEON functions; on x86_64 the SSE2 assembly).
#[test]
fn table_selection_returns_the_indexed_entry() {
    let mut rng = ChaCha20Rng::seed_from_u64(15);
    let mut limbs = || -> Limbs { be_to_limbs(&rand32(&mut rng)) };
    let mut t5 = [Jac::default(); 16];
    for e in &mut t5 {
        *e = Jac {
            x: limbs(),
            y: limbs(),
            z: limbs(),
        };
    }
    let mut t7 = [Aff::default(); 64];
    for e in &mut t7 {
        *e = Aff {
            x: limbs(),
            y: limbs(),
        };
    }
    let z5 = select_w5(&t5, 0);
    assert_eq!((z5.x, z5.y, z5.z), (ZERO, ZERO, ZERO));
    for i in 1..=16u64 {
        let (got, want) = (select_w5(&t5, i), t5[i as usize - 1]);
        assert_eq!((got.x, got.y, got.z), (want.x, want.y, want.z), "w5 {i}");
    }
    let z7 = select_w7(&t7, 0);
    assert_eq!((z7.x, z7.y), (ZERO, ZERO));
    for i in 1..=64u64 {
        let (got, want) = (select_w7(&t7, i), t7[i as usize - 1]);
        assert_eq!((got.x, got.y), (want.x, want.y), "w7 {i}");
    }
    // The generator's rows too (the production tables).
    for (r, row) in g_table().iter().enumerate().step_by(9) {
        for i in [1u64, 2, 33, 63, 64] {
            let got = select_w7(row, i);
            assert_eq!(
                (got.x, got.y),
                (row[i as usize - 1].x, row[i as usize - 1].y)
            );
        }
        let z = select_w7(row, 0);
        assert_eq!((z.x, z.y), (ZERO, ZERO), "row {r}");
    }
}

/// Negation modulo P, on the edges and random values.
#[test]
fn negation_is_modular() {
    let mut rng = ChaCha20Rng::seed_from_u64(16);
    assert_eq!(neg(&ZERO), ZERO);
    assert_eq!(neg(&[1, 0, 0, 0]), sub_borrow(&P, &[1, 0, 0, 0]).0);
    assert_eq!(neg(&sub_borrow(&P, &[1, 0, 0, 0]).0), [1, 0, 0, 0]);
    for _ in 0..300 {
        let a = reduce_once(&be_to_limbs(&rand32(&mut rng)), &P);
        let n = neg(&a);
        assert!(lt(&n, &P));
        assert_eq!(add_mod(&a, &n, &P), ZERO);
        assert_eq!(n, sub_mod(&ZERO, &a, &P));
    }
}

/// Mixed addition with an infinity on either side (Jacobian `z == 0`, affine
/// (0, 0)), with the opposite point, and agreement with full addition: the
/// comb walks rely on all four.
#[test]
fn mixed_addition_handles_infinity_and_opposites() {
    let mut rng = ChaCha20Rng::seed_from_u64(17);
    for ops in variants() {
        for _ in 0..50 {
            let (ax, ay) = stock_point(&rand_scalar(&mut rng));
            let (bx, by) = stock_point(&rand_scalar(&mut rng));
            let a = ops.point_from_bytes(&ax, &ay).unwrap();
            let b = ops.point_from_bytes(&bx, &by).unwrap();
            let ja = Jac {
                x: a.x,
                y: a.y,
                z: ONE_P,
            };
            let jb = Jac {
                x: b.x,
                y: b.y,
                z: ONE_P,
            };
            // Against the complete addition, and with a non-trivial Z.
            let mixed = ops.to_affine(&ops.add_affine(&ja, &b)).unwrap();
            let full = ops.to_affine(&ops.add(&ja, &jb)).unwrap();
            assert_eq!((mixed.x, mixed.y), (full.x, full.y));
            let ja2 = ops.dbl(&ja);
            let mixed = ops.to_affine(&ops.add_affine(&ja2, &b)).unwrap();
            let full = ops.to_affine(&ops.add(&ja2, &jb)).unwrap();
            assert_eq!((mixed.x, mixed.y), (full.x, full.y));
            // Infinity on the left, on the right, and on both sides.
            let inf = Jac::default();
            let r = ops.to_affine(&ops.add_affine(&inf, &b)).unwrap();
            assert_eq!((r.x, r.y), (b.x, b.y));
            let r = ops
                .to_affine(&ops.add_affine(&ja, &Aff::default()))
                .unwrap();
            assert_eq!((r.x, r.y), (a.x, a.y));
            assert!(
                ops.to_affine(&ops.add_affine(&inf, &Aff::default()))
                    .is_none()
            );
            // P + (-P) is infinity.
            let na = Aff {
                x: a.x,
                y: neg(&a.y),
            };
            assert!(ops.to_affine(&ops.add_affine(&ja, &na)).is_none());
        }
    }
}

/// The backend name the boot log prints for this architecture.
#[test]
fn the_variant_is_named_for_the_boot_log() {
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(Ops::detect().name(), "nistz256-armv8");
        assert!(Ops::adx_if_available().is_none());
        assert!(!Ops::detect().uses_adx());
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(Ops::portable().name(), "nistz256-mul");
        let d = Ops::detect();
        assert_eq!(
            d.name(),
            if d.uses_adx() {
                "nistz256-adx"
            } else {
                "nistz256-mul"
            }
        );
    }
}

/// Multiplication by small, large and structured scalars for a variable base
/// against RustCrypto (the windows' edges: zero digits, the top window, a
/// negative last digit).
#[test]
fn variable_base_multiplication_matches_on_structured_scalars() {
    let mut rng = ChaCha20Rng::seed_from_u64(18);
    for ops in variants() {
        let b = rand_scalar(&mut rng);
        let (qx, qy) = stock_point(&b);
        let q = ops.point_from_bytes(&qx, &qy).unwrap();
        let qpt = p256::PublicKey::from_sec1_bytes(&{
            let mut v = std::vec![4u8];
            v.extend_from_slice(&qx);
            v.extend_from_slice(&qy);
            v
        })
        .unwrap();
        let mut scalars: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
        for small in [1u8, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
            let mut s = [0u8; 32];
            s[31] = small;
            scalars.push(s);
        }
        for bit in [5usize, 6, 127, 250, 254, 255] {
            let mut s = [0u8; 32];
            s[31 - bit / 8] = 1 << (bit % 8);
            scalars.push(s);
        }
        scalars.push(limbs_to_be(&sub_borrow(&N, &[1, 0, 0, 0]).0));
        scalars.push(limbs_to_be(&sub_borrow(&N, &[2, 0, 0, 0]).0));
        let mut alt = [0u8; 32];
        for (i, b) in alt.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0x55 } else { 0xaa };
        }
        scalars.push(alt);
        for s in scalars {
            let k = Option::<p256::Scalar>::from(p256::Scalar::from_repr(s.into())).unwrap();
            let want = (qpt.to_projective() * k).to_affine().to_sec1_point(false);
            for got in [
                ops.mul_var_ct(&be_to_limbs(&s), &q),
                ops.mul_var_vartime(&be_to_limbs(&s), &q),
            ] {
                let got = ops.to_affine(&got).unwrap();
                assert_eq!(
                    &want.as_bytes()[1..33],
                    &limbs_to_be(&ops.demont_p(&got.x)),
                    "{s:02x?}"
                );
                assert_eq!(
                    &want.as_bytes()[33..],
                    &limbs_to_be(&ops.demont_p(&got.y)),
                    "{s:02x?}"
                );
            }
        }
        // Zero and N are the point at infinity; random scalars agree with
        // the constant-time multiplication.
        assert!(ops.to_affine(&ops.mul_var_vartime(&ZERO, &q)).is_none());
        assert!(ops.to_affine(&ops.mul_var_vartime(&N, &q)).is_none());
        for _ in 0..200 {
            let k = be_to_limbs(&rand_scalar(&mut rng));
            let a = ops.to_affine(&ops.mul_var_ct(&k, &q)).unwrap();
            let b = ops.to_affine(&ops.mul_var_vartime(&k, &q)).unwrap();
            assert_eq!((a.x, a.y), (b.x, b.y));
        }
    }
}
