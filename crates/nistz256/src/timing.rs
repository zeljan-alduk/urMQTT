//! `cargo test --release -p urmqtt-nistz256 -- --ignored --nocapture timings`

use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
#[ignore = "timing only"]
fn timings() {
    use std::time::Instant;
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b[0] &= 0x7f;
    let d = be_to_limbs(&b);
    let gx = limbs_to_be(&ops_g().0);
    let gy = limbs_to_be(&ops_g().1);
    for ops in [Some(Ops::portable()), Ops::adx_if_available()]
        .into_iter()
        .flatten()
    {
        let q = ops.point_from_bytes(&gx, &gy).unwrap();
        let a = ops.mul(&q.x, &q.y);
        let j = Jac {
            x: q.x,
            y: q.y,
            z: ONE_P,
        };
        let j2 = ops.dbl(&j);
        let report = |name: &str, f: &mut dyn FnMut()| {
            let mut best = u128::MAX;
            for _ in 0..30 {
                let t = Instant::now();
                for _ in 0..50 {
                    f();
                }
                best = best.min(t.elapsed().as_nanos() / 50);
            }
            std::println!("adx={} {name}: {best} ns", ops.uses_adx());
        };
        report("mul", &mut || {
            std::hint::black_box(ops.mul(std::hint::black_box(&a), &q.x));
        });
        report("sqr", &mut || {
            std::hint::black_box(ops.sqr(std::hint::black_box(&a)));
        });
        report("dbl", &mut || {
            std::hint::black_box(ops.dbl(std::hint::black_box(&j)));
        });
        report("add", &mut || {
            std::hint::black_box(ops.add(&j, std::hint::black_box(&j2)));
        });
        report("inv_p", &mut || {
            std::hint::black_box(ops.inv_p(std::hint::black_box(&a)));
        });
        report("inv_n", &mut || {
            std::hint::black_box(ops.inv_n(std::hint::black_box(&a)));
        });
        report("mul_base_ct", &mut || {
            std::hint::black_box(ops.mul_base_ct(std::hint::black_box(&d)));
        });
        report("mul_base_vartime", &mut || {
            std::hint::black_box(ops.mul_base_vartime(std::hint::black_box(&d)));
        });
        let t0 = Instant::now();
        let kt = KeyTable::new(ops, &gx, &gy).unwrap();
        std::println!(
            "adx={} KeyTable::new: {} us",
            ops.uses_adx(),
            t0.elapsed().as_micros()
        );
        let (z, r, s) = ([7u8; 32], [9u8; 32], [11u8; 32]);
        report("KeyTable::verify (bad sig)", &mut || {
            std::hint::black_box(kt.verify(ops, std::hint::black_box(&z), &r, &s));
        });
        report("mul_var_ct", &mut || {
            std::hint::black_box(ops.mul_var_ct(std::hint::black_box(&d), &q));
        });
    }
}

/// The generator's affine coordinates (plain, big-endian limbs order).
fn ops_g() -> (Limbs, Limbs) {
    let ops = Ops::portable();
    let e = &g_table()[0][0];
    (ops.demont_p(&e.x), ops.demont_p(&e.y))
}
