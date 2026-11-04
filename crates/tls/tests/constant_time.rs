//! H2: dudect-style timing tests (Reparaz, Balasch, Verbauwhede 2017).
//!
//! Two classes of inputs that differ only in a secret-dependent way (where a
//! forged tag or a compared secret differs) are measured interleaved in
//! random order, and Welch's t-test compares the two timing distributions,
//! after cropping the slowest measurements (interrupts, migrations). A
//! |t| above the threshold means the time depends on the class: a leak.
//!
//! The negative control (`harness_detects_a_leaky_comparison`) runs the
//! same measurement on a byte-by-byte comparison that exits early: the test
//! only counts if the harness sees that leak.
//!
//! Timing tests are noisy on shared machines, so they are `#[ignore]`d in
//! `cargo test` and run by `make ct` (release build, one test at a time).

use std::hint::black_box;
use std::time::Instant;

use urmqtt_tls::record::{RecordLayer, Suite};
use urmqtt_tls::ticket::TicketKeys;

const SAMPLES: usize = 200_000;
/// dudect's bound for "definitely not constant time" is 10; below 4.5 it
/// reports "probably constant time". Ours sits between, for noisy hosts.
const THRESHOLD: f64 = 7.0;

/// A small xorshift, so the class order cannot line up with anything.
struct Rng(u64);

impl Rng {
    fn bit(&mut self) -> bool {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 & 1 == 1
    }
}

/// Welch's t over the fastest `keep` fraction of each class.
fn t_stat(a: &mut [u64], b: &mut [u64], keep: f64) -> f64 {
    let stats = |v: &mut [u64]| {
        v.sort_unstable();
        let n = ((v.len() as f64) * keep) as usize;
        let v = &v[..n.max(2)];
        let n = v.len() as f64;
        let mean = v.iter().map(|&x| x as f64).sum::<f64>() / n;
        let var = v.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var, n)
    };
    let (ma, va, na) = stats(a);
    let (mb, vb, nb) = stats(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// Measures `op` SAMPLES times in random class order; returns the largest
/// |t| over a few crop levels (as dudect does). `prepare(class, state)`
/// runs before each measurement and is not timed: both classes then run
/// `op` on the same state at the same addresses, so only the secret
/// difference can show (separate input buffers per class are a known
/// source of false positives through cache and alignment effects).
///
/// A real leak is there in every run (the control shows |t| in the
/// thousands each time); noise on a shared machine is not. So a case counts
/// as leaking only if three runs all exceed the bound: the smallest |t| of
/// up to three runs is returned.
fn measure<S>(state: &mut S, prepare: impl FnMut(bool, &mut S), op: impl FnMut(&mut S)) -> f64 {
    measure_n(SAMPLES, state, prepare, op)
}

/// [`measure`] with `samples` measurements per run (the P-256 operations
/// take 10-500 us each, so they run fewer).
fn measure_n<S>(
    samples: usize,
    state: &mut S,
    mut prepare: impl FnMut(bool, &mut S),
    mut op: impl FnMut(&mut S),
) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        best = best.min(measure_once(samples, state, &mut prepare, &mut op));
        if best < THRESHOLD {
            break;
        }
    }
    best
}

fn measure_once<S>(
    samples: usize,
    state: &mut S,
    prepare: &mut impl FnMut(bool, &mut S),
    op: &mut impl FnMut(&mut S),
) -> f64 {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut a, mut b) = (Vec::with_capacity(samples), Vec::with_capacity(samples));
    // Warm caches and branch predictors with both classes.
    for i in 0..10_000.min(samples / 4) {
        prepare(i % 2 == 0, state);
        op(state);
    }
    for _ in 0..samples {
        let class = rng.bit();
        prepare(class, state);
        let t0 = Instant::now();
        op(state);
        let dt = t0.elapsed().as_nanos() as u64;
        if class { a.push(dt) } else { b.push(dt) }
    }
    [0.5, 0.75, 0.9]
        .iter()
        .map(|&k| t_stat(&mut a.clone(), &mut b.clone(), k).abs())
        .fold(0.0, f64::max)
}

fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return false;
        }
    }
    a.len() == b.len()
}

const LEN: usize = 4096;

/// A 4 KiB secret and one scratch buffer that, per class, differs from it
/// in the first byte or in the last.
fn flip(class: bool, (secret, scratch): &mut (Vec<u8>, Vec<u8>)) {
    scratch.copy_from_slice(secret);
    flip_at(scratch, 0, LEN - 1, class);
}

/// Changes byte `a` (class true) or byte `b` (class false), writing both in
/// either case: the class must not leave a different cache line dirty.
fn flip_at(buf: &mut [u8], a: usize, b: usize, class: bool) {
    buf[a] ^= u8::from(class);
    buf[b] ^= u8::from(!class);
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn harness_detects_a_leaky_comparison() {
    let mut st = (vec![0x5a; LEN], vec![0; LEN]);
    let t = measure(&mut st, flip, |(s, x)| {
        black_box(leaky_eq(black_box(s), black_box(x)));
    });
    println!("leaky comparison: |t| = {t:.1}");
    assert!(
        t > THRESHOLD * 3.0,
        "the harness cannot see an early exit (|t| = {t:.1})"
    );
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn secret_comparison_is_constant_time() {
    let mut st = (vec![0x5a; LEN], vec![0; LEN]);
    let t = measure(&mut st, flip, |(s, x)| {
        black_box(urmqtt_tls::server::ct_eq(black_box(s), black_box(x)));
    });
    println!("ct_eq: |t| = {t:.1}");
    assert!(
        t < THRESHOLD,
        "ct_eq depends on where the inputs differ (|t| = {t:.1})"
    );
}

/// A record whose tag is wrong in its first byte, or in its last: the
/// rejection must take the same time (the AEAD's tag check).
fn record_case(suite: Suite) -> f64 {
    let mut a = RecordLayer::new(suite, [1; 32], 0, [2; 32], 0).unwrap();
    let mut wire = Vec::new();
    a.send(&[0x42; 1024], &mut wire).unwrap();
    let n = wire.len();
    let fresh = || RecordLayer::new(suite, [2; 32], 0, [1; 32], 0).unwrap();
    let mut st = (fresh(), vec![0u8; n], Vec::new());
    measure(
        &mut st,
        |c, (layer, buf, _)| {
            // A receiver at sequence 0 and the record with one tag byte
            // changed, rebuilt untimed.
            *layer = fresh();
            buf.copy_from_slice(&wire);
            flip_at(buf, n - 16, n - 1, c);
        },
        |(layer, buf, out)| {
            assert!(black_box(layer.open(buf, out)).is_err());
        },
    )
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn forged_record_rejection_is_constant_time() {
    for suite in [Suite::Aes128Gcm, Suite::ChaCha20Poly1305] {
        let t = record_case(suite);
        println!("{suite:?} bad tag, first vs last byte: |t| = {t:.1}");
        assert!(
            t < THRESHOLD,
            "{suite:?}: tag check timing depends on the byte (|t| = {t:.1})"
        );
    }
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn forged_ticket_rejection_is_constant_time() {
    let keys = TicketKeys::new(3600, || 0);
    let mut n = 3u8;
    let mut rng = |b: &mut [u8]| {
        for x in b {
            n = n.wrapping_mul(13).wrapping_add(5);
            *x = n;
        }
        true
    };
    let t = keys.seal_at(0, &mut rng, &[0x33; 200]).unwrap();
    let len = t.len();
    let mut st = vec![0u8; len];
    let tt = measure(
        &mut st,
        |c, buf| {
            buf.copy_from_slice(&t);
            flip_at(buf, len - 16, len - 1, c);
        },
        |buf| {
            assert!(black_box(keys.open_at(1, black_box(buf))).is_err());
        },
    );
    println!("ticket bad tag, first vs last byte: |t| = {tt:.1}");
    assert!(
        tt < THRESHOLD,
        "ticket tag check timing depends on the byte (|t| = {tt:.1})"
    );
}

// ---------------------------------------------------------------- P-256 (ADR-130, ADR-255)
//
// The secret scalar of key generation (the generator's comb), ECDH (the
// variable-base windows) and ECDSA signing (nonce, inversions): one class is
// a fixed scalar with almost every window digit zero (the table scans then
// select "infinity" and the additions take their infinity operand), the
// other a fresh random scalar per measurement, copied into the same slot.
// These run the production paths (`provider::fastec`): the nistz256 assembly
// on x86_64 and AArch64 Linux, RustCrypto elsewhere. Signing also signs a
// fresh random (public) message per measurement in both classes, so that only
// the key differs; the nonce has its own case on the assembly's `sign`.

const P256_SAMPLES: usize = 20_000;

/// 256 random valid secret keys (deterministic).
fn p256_keys() -> Vec<p256::SecretKey> {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut out = Vec::new();
    while out.len() < 256 {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            c.copy_from_slice(&x.to_le_bytes());
        }
        if let Ok(k) = p256::SecretKey::from_slice(&b) {
            out.push(k);
        }
    }
    out
}

/// The scalar 2 (the comb's digits are all zero after the first window,
/// the variable-base windows likewise).
fn sparse_key() -> p256::SecretKey {
    let mut b = [0u8; 32];
    b[31] = 2;
    p256::SecretKey::from_slice(&b).unwrap()
}

/// Attempts per P-256 case. A secret-dependent time shows in every attempt
/// (the leaky control scores |t| of several hundred); a noisy shared runner
/// can spoil one attempt at random, so the case fails only if every attempt is
/// over the bound.
const P256_ATTEMPTS: usize = 3;

/// Fixed (sparse) against random secret, both prepared untimed by `make`
/// into the same slot. `public` then rewrites the public part of the slot
/// (the message to sign) in the same way for both classes, also untimed.
fn p256_case<T: Clone>(
    name: &str,
    make: impl Fn(&p256::SecretKey) -> T,
    mut public: impl FnMut(&mut T),
    op: impl Fn(&T),
) {
    let pool: Vec<T> = p256_keys().iter().map(&make).collect();
    let fixed = make(&sparse_key());
    let mut i = 0usize;
    let mut st = fixed.clone();
    let mut scores = Vec::new();
    for _ in 0..P256_ATTEMPTS {
        let t = measure_n(
            P256_SAMPLES,
            &mut st,
            |c, slot| {
                *slot = if c {
                    fixed.clone()
                } else {
                    i = (i + 1) % pool.len();
                    pool[i].clone()
                };
                public(slot);
            },
            |slot| op(black_box(slot)),
        );
        scores.push(t);
        if t < THRESHOLD {
            break;
        }
    }
    println!(
        "{name} ({}), sparse vs random scalar: |t| = {} (attempts: {})",
        urmqtt_tls::provider::ecc_backend(),
        scores.last().map_or(0.0, |t| (t * 10.0).round() / 10.0),
        scores.len()
    );
    assert!(
        scores.last().is_some_and(|t| *t < THRESHOLD),
        "{name}: timing depends on the secret scalar (|t| = {scores:?} in {P256_ATTEMPTS} attempts)"
    );
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn p256_key_generation_is_constant_time() {
    p256_case(
        "P-256 public key",
        Clone::clone,
        |_| {},
        |k| {
            black_box(urmqtt_tls::provider::fastec::p256_public(k));
        },
    );
}

#[test]
#[ignore = "timing: run with `make ct`"]
fn p256_ecdh_is_constant_time() {
    let peer = urmqtt_tls::provider::fastec::p256_public(&p256_keys()[7]);
    p256_case(
        "P-256 ECDH",
        Clone::clone,
        |_| {},
        |k| {
            black_box(urmqtt_tls::provider::fastec::p256_dh(k, black_box(&peer))).unwrap();
        },
    );
}

/// The signing key is the secret; the message is public and is a fresh
/// random one per measurement in **both** classes. With one fixed message
/// (as this case had until ct-dit) the sparse class signs the same message
/// with the same key every time, so it returns the same signature every
/// time, while the random class returns a different one each time. The
/// time spent on the *output* then differs between the classes: the DER
/// encoding (`to_der`, variable length, leading-zero handling) of one
/// repeated signature is faster than of varying ones (|t| of about 50 on
/// the arm64 runner for the encoding alone). That is a property of the
/// public signature, not of the key, and it was the |t| = 8 to 11 seen on
/// the runner: a dense fixed key scored higher still (14 to 22), and a
/// random message per measurement removed it for both (below 3.5). See
/// ADR-255 (amendment) and A255-W1 in docs/AUDIT.md.
#[test]
#[ignore = "timing: run with `make ct`"]
fn p256_signing_is_constant_time() {
    let mut x = 0x6a09_e667_f3bc_c908u64;
    p256_case(
        "P-256 ECDSA sign",
        |k| (p256::ecdsa::SigningKey::from(k.clone()), [0u8; 32]),
        |(_, msg)| {
            for c in msg.chunks_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                c.copy_from_slice(&x.to_le_bytes());
            }
        },
        |(sk, msg)| {
            black_box(urmqtt_tls::provider::fastec::ecdsa_sign(sk, black_box(msg))).unwrap();
        },
    );
}

/// The signing nonce, the most sensitive secret of ECDSA: a sparse nonce
/// (k = 2) against random nonces, the key and the message fixed, through the
/// assembly's `sign` (the production path draws the nonce by RFC 6979
/// inside `fastec`, so it cannot be chosen there). The output is two fixed-size
/// arrays, with no variable-length encoding after the timed part. Only where
/// the assembly is compiled in (x86_64 and AArch64 Linux).
#[test]
#[ignore = "timing: run with `make ct`"]
fn p256_signing_nonce_is_constant_time() {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    {
        use urmqtt_nistz256 as nistz;
        let ops = nistz::Ops::detect();
        let d: [u8; 32] = p256_keys()[3].to_bytes().into();
        let z = [0x5au8; 32];
        p256_case(
            "P-256 ECDSA sign, nonce",
            |k| -> [u8; 32] { k.to_bytes().into() },
            |_| {},
            |k| {
                black_box(nistz::sign(ops, &d, black_box(k), &z)).unwrap();
            },
        );
    }
    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "linux"
    )))]
    println!("P-256 ECDSA sign, nonce: skipped (no nistz256 assembly on this target)");
}

/// The X25519 shared secret through the ladder the handshake runs
/// (`urmqtt_x25519`, ADR-131 and ADR-259: the `mul`/`umulh` assembly on
/// AArch64, MULX/ADX or portable on x86_64): the all-zero scalar (clamped to
/// 2^254, every ladder bit below the top one zero, so every conditional swap
/// is a no-op) against random scalars, the peer's point fixed. Same samples
/// and attempts as the P-256 cases; the P-256 double-and-add control below
/// shows that this scale of measurement sees a scalar-dependent time.
#[test]
#[ignore = "timing: run with `make ct`"]
fn x25519_ladder_is_constant_time() {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let be = urmqtt_x25519::Backend::detect();
        let mut u = [0u8; 32];
        u[0] = 9;
        let peer = urmqtt_x25519::x25519(be, &[0x17; 32], &u);
        let mut x = 0x510e_527f_ade6_82d1u64;
        let pool: Vec<[u8; 32]> = (0..256)
            .map(|_| {
                let mut k = [0u8; 32];
                for c in k.chunks_mut(8) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    c.copy_from_slice(&x.to_le_bytes());
                }
                k
            })
            .collect();
        let fixed = [0u8; 32];
        let mut i = 0usize;
        let mut st = fixed;
        let mut scores = Vec::new();
        for _ in 0..P256_ATTEMPTS {
            let t = measure_n(
                P256_SAMPLES,
                &mut st,
                |c, slot| {
                    *slot = if c {
                        fixed
                    } else {
                        i = (i + 1) % pool.len();
                        pool[i]
                    };
                },
                |slot| {
                    black_box(urmqtt_x25519::x25519(be, black_box(slot), &peer));
                },
            );
            scores.push(t);
            if t < THRESHOLD {
                break;
            }
        }
        println!(
            "X25519 ladder ({}), sparse vs random scalar: |t| = {} (attempts: {})",
            be.name(),
            scores.last().map_or(0.0, |t| (t * 10.0).round() / 10.0),
            scores.len()
        );
        assert!(
            scores.last().is_some_and(|t| *t < THRESHOLD),
            "X25519: timing depends on the secret scalar (|t| = {scores:?})"
        );
    }
}

/// The control at P-256 scale: a textbook double-and-add that skips the
/// addition for zero bits (the leak a broken window selection or skipped
/// infinity addition would have, larger) must show the sparse/random
/// difference with the same sample count, or the three cases above prove
/// nothing.
#[test]
#[ignore = "timing: run with `make ct`"]
fn harness_detects_a_variable_time_scalar_multiplication() {
    use p256::elliptic_curve::Group;
    use p256::elliptic_curve::PrimeField;
    fn leaky_mul(k: &p256::Scalar) -> p256::ProjectivePoint {
        let g = p256::ProjectivePoint::generator();
        let mut r = p256::ProjectivePoint::IDENTITY;
        for byte in k.to_repr() {
            for bit in (0..8).rev() {
                r = r.double();
                if (byte >> bit) & 1 == 1 {
                    r += g;
                }
            }
        }
        r
    }
    let pool: Vec<p256::Scalar> = p256_keys().iter().map(|k| *k.to_nonzero_scalar()).collect();
    let fixed = *sparse_key().to_nonzero_scalar();
    let mut i = 0usize;
    let mut st = fixed;
    let t = measure_n(
        P256_SAMPLES,
        &mut st,
        |c, slot| {
            *slot = if c {
                fixed
            } else {
                i = (i + 1) % pool.len();
                pool[i]
            };
        },
        |slot| {
            black_box(leaky_mul(black_box(slot)));
        },
    );
    println!("P-256 double-and-add (control), sparse vs random scalar: |t| = {t:.1}");
    assert!(
        t > THRESHOLD * 3.0,
        "the harness cannot see a variable-time scalar multiplication (|t| = {t:.1})"
    );
}
