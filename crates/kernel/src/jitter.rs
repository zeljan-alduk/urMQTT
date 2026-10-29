//! CPU-jitter entropy for machines without a hardware source (ADR-038).
//!
//! Ampere Altra (Hetzner CAX, Oracle A1) has no `RNDR`, and a cloud may not
//! offer virtio-rng. With `entropy.fallback = "jitter"` the boot CPU then
//! times a memory workload whose duration varies with cache, TLB, branch
//! predictor and pipeline state and with the host's interference, as
//! jitterentropy does. The finest clock available is used: the PMU cycle
//! counter if the hypervisor exposes a PMU, else the generic timer. The
//! workload grows until a probe shows real spread. Every delta goes into the
//! pool; the estimator's health tests and conservative min-entropy estimate
//! decide whether it counts (`urmqtt_tls::rng::JitterEstimator`).

use alloc::vec;

use urmqtt_arch::time;
use urmqtt_tls::rng::{EntropyPool, JITTER_MIN_BITS, JitterEstimator, Source};

const BUF_WORDS: usize = 4096;
const MAX_SAMPLES: u32 = 1 << 16;
const MIN_SAMPLES: u32 = 1024;
const PROBE: u32 = 256;
const MAX_ITERS: u32 = 1 << 16;

pub struct Report {
    pub clock: &'static str,
    /// The clock's granularity (it counts in steps of 2^shift).
    pub shift: u32,
    pub iters: u32,
    pub samples: u32,
    pub bits_per_sample: u32,
    pub credited: u64,
    pub failed: bool,
}

/// Duration of `iters` steps of a data-dependent read-modify-write walk.
fn sample(now: fn() -> u64, buf: &mut [u64], lfsr: &mut u64, iters: u32) -> u64 {
    let t0 = now();
    for _ in 0..iters {
        // xorshift: next position and value.
        *lfsr ^= *lfsr << 13;
        *lfsr ^= *lfsr >> 7;
        *lfsr ^= *lfsr << 17;
        if let Some(w) = buf.get_mut((*lfsr as usize) % BUF_WORDS) {
            *w = w.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ *lfsr;
        }
    }
    core::hint::black_box(&buf);
    now().wrapping_sub(t0)
}

/// Collects jitter into `pool` and credits what the estimator allows.
pub fn collect(pool: &mut EntropyPool) -> Report {
    let (now, name) = time::finest_clock();
    let mut buf = vec![0u64; BUF_WORDS];
    let mut lfsr = time::now() | 1;
    // Some clocks count in coarse steps (HVF's virtual cycle counter in
    // 128s): the estimator sees deltas divided by the common power of two,
    // which is learned from the probes.
    let mut shift = 63u32;
    // Grow the workload until a probe passes the health tests with at
    // least 2 bits per sample (a coarse timer needs longer samples).
    let mut iters = 64;
    loop {
        let mut deltas = [0u64; PROBE as usize];
        for d in deltas.iter_mut() {
            *d = sample(now, &mut buf, &mut lfsr, iters);
            if *d != 0 {
                shift = shift.min(d.trailing_zeros());
            }
        }
        let mut probe = JitterEstimator::new();
        for d in deltas {
            probe.add(d >> shift);
        }
        if (!probe.failed() && probe.bits_per_sample() >= 2) || iters >= MAX_ITERS {
            break;
        }
        iters *= 2;
    }
    let mut est = JitterEstimator::new();
    let mut batch = [0u8; 512];
    let mut at = 0;
    while est.samples() < MAX_SAMPLES && !est.failed() {
        let d = sample(now, &mut buf, &mut lfsr, iters);
        est.add(d >> shift);
        if let Some(b) = batch.get_mut(at..at + 8) {
            b.copy_from_slice(&d.to_le_bytes());
        }
        at += 8;
        if at == batch.len() {
            pool.add(Source::Jitter, &batch);
            at = 0;
        }
        if est.samples() >= MIN_SAMPLES && est.credited_bits() >= 2 * JITTER_MIN_BITS {
            break;
        }
    }
    pool.add(Source::Jitter, batch.get(..at).unwrap_or(&[]));
    let credited = est.credited_bits();
    pool.credit_jitter(credited);
    Report {
        clock: name,
        shift: if shift == 63 { 0 } else { shift },
        iters,
        samples: est.samples(),
        bits_per_sample: est.bits_per_sample(),
        credited,
        failed: est.failed(),
    }
}
