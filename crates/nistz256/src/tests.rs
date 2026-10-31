//! Differential tests against the portable RustCrypto implementation (the
//! reference) on random and edge inputs, for both assembly variants.

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
