//! Known answers (RFC 7748) and differential tests against `x25519-dalek`
//! and between the two multiplication backends.

use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn backends() -> std::vec::Vec<Backend> {
    let mut v = std::vec![Backend::Portable];
    v.extend(Backend::adx_if_available());
    v
}

fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn rfc7748_section_5_2_vectors() {
    let cases = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for b in backends() {
        for (k, u, want) in cases {
            assert_eq!(x25519(b, &hex(k), &hex(u)), hex(want), "{b:?}");
        }
    }
}

#[test]
fn rfc7748_iterated_1_and_1000() {
    let base = {
        let mut b = [0u8; 32];
        b[0] = 9;
        b
    };
    for be in backends() {
        let (mut k, mut u) = (base, base);
        for i in 1..=1000 {
            let r = x25519(be, &k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }
}

#[test]
fn rfc7748_diffie_hellman() {
    let a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let mut base = [0u8; 32];
    base[0] = 9;
    for be in backends() {
        let pa = x25519(be, &a, &base);
        let pb = x25519(be, &b, &base);
        assert_eq!(
            pa,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            pb,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let want = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(be, &a, &pb), want);
        assert_eq!(x25519(be, &b, &pa), want);
    }
}

fn dalek(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*k, *u)
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[test]
fn field_multiplication_backends_agree_on_edge_values() {
    let Some(_) = Backend::adx_if_available() else {
        return;
    };
    let p = [
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ];
    let vals: std::vec::Vec<Fe> = std::vec![
        [0; 4],
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        [38, 0, 0, 0],
        p,
        sub(&p, &[1, 0, 0, 0]),
        [u64::MAX; 4],
        [u64::MAX, 0, 0, 0],
        [0, u64::MAX, 0, 0],
        [0, 0, u64::MAX, 0],
        [0, 0, 0, u64::MAX],
        [0, 0, 0, 1 << 63],
        [u64::MAX, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff],
        [0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_ffff_ffff, 0],
        [0, 0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_ffff_ffff],
        [0x8000_0000_0000_0000; 4],
        [0x0000_0000_ffff_ffff; 4],
    ];
    for a in &vals {
        for b in &vals {
            assert_eq!(adx::mul(a, b), mul_portable(a, b), "{a:x?} * {b:x?}");
        }
        assert_eq!(adx::sqr(a), mul_portable(a, a), "{a:x?}^2");
    }
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    for _ in 0..20000 {
        let (mut a, mut b) = ([0u64; 4], [0u64; 4]);
        for i in 0..4 {
            a[i] = rng.next_u64();
            b[i] = rng.next_u64();
            // Bias towards all-ones / all-zeros limbs for carry chains.
            match rng.next_u32() % 6 {
                0 => a[i] = u64::MAX,
                1 => b[i] = u64::MAX,
                2 => a[i] = 0,
                3 => b[i] = 0,
                _ => {}
            }
        }
        assert_eq!(adx::mul(&a, &b), mul_portable(&a, &b));
        assert_eq!(adx::sqr(&a), mul_portable(&a, &a));
    }
}

#[test]
fn matches_dalek_on_random_and_edge_inputs() {
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    let mut specials: std::vec::Vec<[u8; 32]> = std::vec::Vec::new();
    let mut u = [0u8; 32];
    specials.push(u); // zero
    u[0] = 1;
    specials.push(u);
    // p - 1, p, p + 1, 2^255 - 1, 2^255 (top bit set), 2^256 - 1.
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    specials.push(p);
    for d in [1u8, 2, 18, 19] {
        let mut q = p;
        q[0] = q[0].wrapping_add(d.wrapping_sub(1)); // p-?.. a few values near p
        specials.push(q);
    }
    specials.push([0xff; 32]);
    let mut top = [0u8; 32];
    top[31] = 0x80;
    specials.push(top);
    // Small-order points (RFC 7748 / libsodium blacklist).
    specials.push(hex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ));
    specials.push(hex(
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    ));
    specials.push(hex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    specials.push(hex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    specials.push(hex(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    let mut scalars: std::vec::Vec<[u8; 32]> =
        std::vec![[0; 32], [0xff; 32], [0x55; 32], [0xaa; 32]];
    for _ in 0..8 {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        scalars.push(k);
    }
    for be in backends() {
        for k in &scalars {
            for u in &specials {
                assert_eq!(
                    x25519(be, k, u),
                    dalek(k, u),
                    "{be:?} k={k:02x?} u={u:02x?}"
                );
            }
        }
        for i in 0..400 {
            let (mut k, mut u) = ([0u8; 32], [0u8; 32]);
            rng.fill_bytes(&mut k);
            rng.fill_bytes(&mut u);
            assert_eq!(x25519(be, &k, &u), dalek(&k, &u), "{be:?} random {i}");
        }
    }
}

#[test]
fn small_order_points_give_zero() {
    let mut k = [0u8; 32];
    k[0] = 0x42;
    for be in backends() {
        assert_eq!(x25519(be, &k, &[0u8; 32]), [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(x25519(be, &k, &one), dalek(&k, &one));
    }
}

#[test]
fn encode_is_canonical() {
    let p = [
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ];
    assert_eq!(encode(&p), [0u8; 32]);
    // 2^256 - 1 = 2p + 37.
    let mut want = [0u8; 32];
    want[0] = 37;
    assert_eq!(encode(&[u64::MAX; 4]), want);
    // 2^255 + 18 = p + 37.
    assert_eq!(encode(&[18, 0, 0, 1 << 63]), want);
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(encode(&[1, 0, 0, 0]), one);
    assert_eq!(
        encode(&[
            0xffff_ffff_ffff_ffee,
            u64::MAX,
            u64::MAX,
            0x7fff_ffff_ffff_ffff
        ]),
        one
    );
}
