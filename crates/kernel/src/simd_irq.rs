//! `test=simd-irq` (dev, X0b and PROPOSAL D3): every core runs the crypto
//! known-answer tests in a loop (AES/PMULL, NEON ChaCha20, SHA-2 and CRC32
//! instructions, all in SIMD registers) while every core sends wake-up IPIs
//! to every other core, for 10 s. An interrupt that failed to save and
//! restore the FP/SIMD state (ADR-003) would corrupt a computation and
//! show up as a known-answer mismatch.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use urmqtt_arch::time;
use urmqtt_log::{error, info};

use crate::smp;

const RUN_NS: u64 = 10_000_000_000;

static RUNNING: AtomicBool = AtomicBool::new(false);
static ROUNDS: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static IPIS: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);

fn round() {
    let ok =
        urmqtt_tls::kat::run().is_ok() && urmqtt_store::crc::crc32c(b"123456789") == 0xe306_9283;
    // Relaxed: counters read after every core has finished.
    if !ok {
        FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    ROUNDS.fetch_add(1, Ordering::Relaxed);
}

/// One core's share: KAT rounds, interleaved with IPIs to every other core.
fn work(me: usize) {
    let n = smp::count();
    // Acquire: pairs with the Release in `run`.
    while RUNNING.load(Ordering::Acquire) {
        round();
        for t in (0..n).filter(|&t| t != me) {
            smp::send_wake(t);
            IPIS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Application processor entry (smp work item).
pub fn worker(me: usize) {
    work(me);
    // Release: this core's counts are final.
    DONE.fetch_add(1, Ordering::Release);
}

/// Runs the test on every core; false if any round mismatched.
pub fn run() -> bool {
    let n = smp::count();
    // Release: the APs see RUNNING before they start.
    RUNNING.store(true, Ordering::Release);
    for cpu in 1..n {
        smp::start_simd_irq(cpu);
    }
    let until = time::uptime_ns() + RUN_NS;
    while time::uptime_ns() < until {
        round();
        for t in 1..n {
            smp::send_wake(t);
            IPIS.fetch_add(1, Ordering::Relaxed);
        }
    }
    RUNNING.store(false, Ordering::Release);
    // Acquire: pairs with each AP's Release in `worker`.
    while DONE.load(Ordering::Acquire) < (n - 1) as u64 {
        core::hint::spin_loop();
    }
    let (rounds, fails, ipis) = (
        ROUNDS.load(Ordering::Relaxed),
        FAILURES.load(Ordering::Relaxed),
        IPIS.load(Ordering::Relaxed),
    );
    if fails == 0 {
        info!(
            "simd-irq: {rounds} known-answer rounds on {n} cores in 10 s with {ipis} IPIs and the tick: 0 mismatches"
        );
    } else {
        error!("simd-irq: {fails} of {rounds} known-answer rounds MISMATCHED under interrupts");
    }
    fails == 0
}
