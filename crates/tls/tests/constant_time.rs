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
fn measure<S>(
    state: &mut S,
    mut prepare: impl FnMut(bool, &mut S),
    mut op: impl FnMut(&mut S),
) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        best = best.min(measure_once(state, &mut prepare, &mut op));
        if best < THRESHOLD {
            break;
        }
    }
    best
}

fn measure_once<S>(
    state: &mut S,
    prepare: &mut impl FnMut(bool, &mut S),
    op: &mut impl FnMut(&mut S),
) -> f64 {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut a, mut b) = (Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES));
    // Warm caches and branch predictors with both classes.
    for i in 0..10_000 {
        prepare(i % 2 == 0, state);
        op(state);
    }
    for _ in 0..SAMPLES {
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
