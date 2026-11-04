//! Temporary diagnosis of the ECDSA signing timing signal on the arm64 CI
//! runner (branch ct-dit). Prints scores, never fails.
#![cfg(all(target_arch = "aarch64", target_os = "linux"))]

use std::hint::black_box;
use std::time::Instant;

use urmqtt_nistz256 as nistz;

const SAMPLES: usize = 20_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

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

/// Returns (max |t| over crops, signed t at 0.5 crop, median a, median b).
fn once<S>(
    st: &mut S,
    prepare: &mut impl FnMut(bool, &mut S),
    op: &mut impl FnMut(&mut S),
) -> (f64, f64, u64, u64) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut a, mut b) = (Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES));
    for i in 0..5_000 {
        prepare(i % 2 == 0, st);
        op(st);
    }
    for _ in 0..SAMPLES {
        let class = rng.next() & 1 == 1;
        prepare(class, st);
        let t0 = Instant::now();
        op(st);
        let dt = t0.elapsed().as_nanos() as u64;
        if class { a.push(dt) } else { b.push(dt) }
    }
    let t = [0.5, 0.75, 0.9]
        .iter()
        .map(|&k| t_stat(&mut a.clone(), &mut b.clone(), k).abs())
        .fold(0.0, f64::max);
    let ts = t_stat(&mut a.clone(), &mut b.clone(), 0.5);
    a.sort_unstable();
    b.sort_unstable();
    (t, ts, a[a.len() / 2], b[b.len() / 2])
}

fn run<S>(
    name: &str,
    st: &mut S,
    mut prepare: impl FnMut(bool, &mut S),
    mut op: impl FnMut(&mut S),
) {
    for dit in [false, true] {
        let g = dit.then(nistz::dit_guard);
        assert_eq!(nistz::dit::enabled(), dit && nistz::dit::available());
        let mut out = Vec::new();
        for _ in 0..3 {
            out.push(once(st, &mut prepare, &mut op));
        }
        drop(g);
        let s: Vec<String> = out
            .iter()
            .map(|(t, ts, ma, mb)| format!("{t:.1} (t50 {ts:+.1}, med {ma}/{mb} ns)"))
            .collect();
        println!("DIAG {name:<44} DIT={}: {}", u8::from(dit), s.join("; "));
    }
}

fn keys() -> Vec<[u8; 32]> {
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    let mut out = Vec::new();
    while out.len() < 256 {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&r.next().to_le_bytes());
        }
        if p256::SecretKey::from_slice(&b).is_ok() {
            out.push(b);
        }
    }
    out
}

fn two() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
}

fn cpuinfo() {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    for l in info.lines() {
        if [
            "CPU implementer",
            "CPU architecture",
            "CPU variant",
            "CPU part",
            "CPU revision",
            "Features",
        ]
        .iter()
        .any(|k| l.starts_with(k))
            && seen.insert(l.to_string())
        {
            println!("DIAG cpuinfo {l}");
        }
    }
    let auxv = std::fs::read("/proc/self/auxv").unwrap_or_default();
    for c in auxv.chunks_exact(16) {
        let k = u64::from_le_bytes(c[..8].try_into().unwrap());
        let v = u64::from_le_bytes(c[8..].try_into().unwrap());
        if k == 16 {
            println!("DIAG AT_HWCAP {v:#x} HWCAP_DIT(bit 24)={}", (v >> 24) & 1);
        }
    }
    println!(
        "DIAG dit available={} enabled(outside guard)={}",
        nistz::dit::available(),
        nistz::dit::enabled()
    );
    {
        let _g = nistz::dit_guard();
        println!("DIAG dit enabled(inside guard)={}", nistz::dit::enabled());
    }
    println!("DIAG dit enabled(after guard)={}", nistz::dit::enabled());
    println!("DIAG nproc {:?}", std::thread::available_parallelism());
}

#[test]
#[ignore = "diagnosis"]
fn diag() {
    cpuinfo();
    let ks = keys();
    let ops = nistz::Ops::detect();
    let z: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(b"constant time").into()
    };
    let msg = b"constant time";

    // 1. Production path, sparse d vs random d (the failing test).
    {
        let pool: Vec<p256::ecdsa::SigningKey> = ks
            .iter()
            .map(|b| p256::ecdsa::SigningKey::from_slice(b).unwrap())
            .collect();
        let fixed = p256::ecdsa::SigningKey::from_slice(&two()).unwrap();
        let mut i = 0;
        let mut st = fixed.clone();
        run(
            "1 fastec sign: d=2 vs random d",
            &mut st,
            |c, s| {
                *s = if c {
                    fixed.clone()
                } else {
                    i = (i + 1) % pool.len();
                    pool[i].clone()
                }
            },
            |s| {
                black_box(urmqtt_tls::provider::fastec::ecdsa_sign(black_box(s), msg)).unwrap();
            },
        );
        // 2. Same, a dense fixed key (not in the pool) vs random d.
        let dense = p256::ecdsa::SigningKey::from_slice(&[0x5c; 32]).unwrap();
        let mut st = dense.clone();
        run(
            "2 fastec sign: dense fixed d vs random d",
            &mut st,
            |c, s| {
                *s = if c {
                    dense.clone()
                } else {
                    i = (i + 1) % pool.len();
                    pool[i].clone()
                }
            },
            |s| {
                black_box(urmqtt_tls::provider::fastec::ecdsa_sign(black_box(s), msg)).unwrap();
            },
        );
    }

    // 1b/2b. Production path with a fresh random message per measurement
    // for both classes (the message is public): the output is random in
    // both classes, only the secret differs.
    {
        let pool: Vec<p256::ecdsa::SigningKey> = ks
            .iter()
            .map(|b| p256::ecdsa::SigningKey::from_slice(b).unwrap())
            .collect();
        for (name, fixed) in [
            (
                "1b fastec sign, random msg: d=2 vs random d",
                p256::ecdsa::SigningKey::from_slice(&two()).unwrap(),
            ),
            (
                "2b fastec sign, random msg: dense d vs random",
                p256::ecdsa::SigningKey::from_slice(&[0x5c; 32]).unwrap(),
            ),
        ] {
            let mut i = 0;
            let mut r = Rng(0x1234_5678_9abc_def1);
            let mut st = (fixed.clone(), [0u8; 32]);
            run(
                name,
                &mut st,
                |c, s| {
                    s.0 = if c {
                        fixed.clone()
                    } else {
                        i = (i + 1) % pool.len();
                        pool[i].clone()
                    };
                    for ch in s.1.chunks_mut(8) {
                        ch.copy_from_slice(&r.next().to_le_bytes());
                    }
                },
                |s| {
                    black_box(urmqtt_tls::provider::fastec::ecdsa_sign(
                        black_box(&s.0),
                        black_box(&s.1),
                    ))
                    .unwrap();
                },
            );
        }
    }

    // nistz::sign directly: (d, k) slots.
    let kfix = ks[200];
    let dense = [0x5c; 32];
    // 3. d=2 vs random d, k fixed: only the d-dependent order-field products differ.
    let mut i = 0;
    let mut st = (two(), kfix);
    run(
        "3 nistz::sign: d=2 vs random d, k fixed",
        &mut st,
        |c, s| {
            s.0 = if c {
                two()
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            black_box(nistz::sign(ops, black_box(&s.0), black_box(&s.1), &z)).unwrap();
        },
    );
    // 4. dense d vs random d, k fixed.
    run(
        "4 nistz::sign: dense d vs random d, k fixed",
        &mut st,
        |c, s| {
            s.0 = if c {
                dense
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            black_box(nistz::sign(ops, black_box(&s.0), black_box(&s.1), &z)).unwrap();
        },
    );
    // 5. k fixed vs k random, d fixed dense.
    let mut st = (dense, kfix);
    run(
        "5 nistz::sign: fixed k vs random k, d fixed",
        &mut st,
        |c, s| {
            s.1 = if c {
                kfix
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            black_box(nistz::sign(ops, black_box(&s.0), black_box(&s.1), &z)).unwrap();
        },
    );
    // 6. k = 2 vs random k (sparse nonce).
    run(
        "6 nistz::sign: k=2 vs random k, d fixed",
        &mut st,
        |c, s| {
            s.1 = if c {
                two()
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            black_box(nistz::sign(ops, black_box(&s.0), black_box(&s.1), &z)).unwrap();
        },
    );
    // 7. public key (mul_base_ct): d=2 vs random.
    let mut st = two();
    run(
        "7 nistz::public_key: d=2 vs random d",
        &mut st,
        |c, s| {
            *s = if c {
                two()
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            black_box(nistz::public_key(ops, black_box(s))).unwrap();
        },
    );
    // 8. RFC 6979 nonce only: d=2 vs random d.
    let order = {
        use p256::elliptic_curve::Curve;
        *p256::NistP256::ORDER.as_ref()
    };
    let mut st = two();
    run(
        "8 rfc6979 KGenerator: d=2 vs random d",
        &mut st,
        |c, s| {
            *s = if c {
                two()
            } else {
                i = (i + 1) % ks.len();
                ks[i]
            };
        },
        |s| {
            let mut kgen =
                rfc6979::KGenerator::<sha2::Sha256, _>::new(black_box(&*s), &z, &[], &order);
            let mut k = [0u8; 32];
            kgen.fill_next_k(&mut k);
            black_box(k);
        },
    );
    // 9. DER encoding + to_vec of a fixed vs random signature.
    let sigs: Vec<p256::ecdsa::Signature> = ks
        .iter()
        .map(|d| {
            let (r, s) = nistz::sign(ops, d, &kfix, &z).unwrap();
            let mut rs = [0u8; 64];
            rs[..32].copy_from_slice(&r);
            rs[32..].copy_from_slice(&s);
            p256::ecdsa::Signature::from_slice(&rs).unwrap()
        })
        .collect();
    let sfix = {
        let (r, s) = nistz::sign(ops, &two(), &kfix, &z).unwrap();
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&r);
        rs[32..].copy_from_slice(&s);
        p256::ecdsa::Signature::from_slice(&rs).unwrap()
    };
    let mut st = sfix;
    run(
        "9 Signature::to_der: fixed vs random sig",
        &mut st,
        |c, s| {
            *s = if c {
                sfix
            } else {
                i = (i + 1) % sigs.len();
                sigs[i]
            };
        },
        |s| {
            black_box(black_box(&*s).to_der().as_bytes().to_vec());
        },
    );
}
