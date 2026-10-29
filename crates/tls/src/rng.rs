//! Kernel CSPRNG: ChaCha20 seeded from a SHA-256 pool of entropy sources.
//!
//! PROMPT §6: never run without entropy. The pool yields a generator once a
//! *hardware* source (virtio-rng, `RNDR`) contributed 32 bytes. Clouds whose
//! CPUs lack `RNDR` and that offer no virtio-rng (possible on Ampere Altra)
//! may opt into a CPU-jitter fallback (`entropy.fallback = "jitter"`): timing
//! samples pass health tests ([`JitterEstimator`]) and count only with a
//! conservative min-entropy estimate of at least [`JITTER_MIN_BITS`].
//! Bootloader-provided values are mixed in but never count on their own.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use urmqtt_arch_aarch64::sync::SpinLock;

/// Minimum bytes a hardware source must deliver to count.
pub const MIN_HW_BYTES: usize = 32;
/// Estimated min-entropy (after the safety factor) jitter must deliver.
pub const JITTER_MIN_BITS: u64 = 256;
/// Only a quarter of the estimated min-entropy is credited.
pub const JITTER_SAFETY: u64 = 4;
/// Repetition count test: this many equal samples in a row fail.
pub const RCT_CUTOFF: u32 = 32;
/// Adaptive proportion test: in a window of `APT_WINDOW` samples, one value
/// seen more than `APT_CUTOFF` times fails.
pub const APT_WINDOW: u32 = 512;
pub const APT_CUTOFF: u32 = 410;

/// Health tests and a min-entropy estimate for timing samples (after
/// NIST SP 800-90B: repetition count, adaptive proportion and the
/// most-common-value estimate, in integer arithmetic). The low byte of each
/// timing delta is the sample.
pub struct JitterEstimator {
    counts: [u32; 256],
    n: u32,
    last: Option<u8>,
    run: u32,
    window: [u32; 256],
    window_n: u32,
    failed: bool,
}

impl Default for JitterEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterEstimator {
    pub const fn new() -> Self {
        Self {
            counts: [0; 256],
            n: 0,
            last: None,
            run: 0,
            window: [0; 256],
            window_n: 0,
            failed: false,
        }
    }

    pub fn add(&mut self, delta: u64) {
        let v = delta as u8;
        if self.last == Some(v) {
            self.run += 1;
            if self.run >= RCT_CUTOFF {
                self.failed = true;
            }
        } else {
            self.last = Some(v);
            self.run = 1;
        }
        if let Some(w) = self.window.get_mut(usize::from(v)) {
            *w += 1;
            if *w > APT_CUTOFF {
                self.failed = true;
            }
        }
        self.window_n += 1;
        if self.window_n == APT_WINDOW {
            self.window = [0; 256];
            self.window_n = 0;
        }
        if let Some(c) = self.counts.get_mut(usize::from(v)) {
            *c += 1;
        }
        self.n += 1;
    }

    /// A health test failed (a stuck or too coarse timer).
    pub fn failed(&self) -> bool {
        self.failed
    }

    pub fn samples(&self) -> u32 {
        self.n
    }

    /// Whole bits of min-entropy per sample: floor(-log2(p_u)), where
    /// p_u bounds the most common value's probability from above (its count
    /// plus 3 standard deviations).
    pub fn bits_per_sample(&self) -> u32 {
        let n = u64::from(self.n);
        let k = u64::from(self.counts.iter().copied().max().unwrap_or(0));
        if n == 0 || k == 0 {
            return 0;
        }
        let upper = (k + 3 * k.isqrt() + 1).min(n);
        (n / upper).ilog2().min(8)
    }

    /// Credited bits so far: the estimate over all samples, divided by
    /// [`JITTER_SAFETY`]; zero once a health test failed.
    pub fn credited_bits(&self) -> u64 {
        if self.failed {
            return 0;
        }
        u64::from(self.n) * u64::from(self.bits_per_sample()) / JITTER_SAFETY
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// virtio-rng (host entropy).
    VirtioRng,
    /// FEAT_RNG `RNDR`.
    Rndr,
    /// Bootloader-provided values (EFI RNG or weaker, best effort).
    Bootloader,
    /// Timing jitter and other low-quality inputs.
    Jitter,
}

impl Source {
    const fn tag(self) -> u8 {
        match self {
            Self::VirtioRng => 1,
            Self::Rndr => 2,
            Self::Bootloader => 3,
            Self::Jitter => 4,
        }
    }

    const fn is_hardware(self) -> bool {
        matches!(self, Self::VirtioRng | Self::Rndr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoHardwareEntropy;

/// Accumulates entropy before the generator exists.
pub struct EntropyPool {
    hash: Sha256,
    hw_bytes: usize,
    jitter_bits: u64,
    sources: u8,
}

impl EntropyPool {
    pub fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"urMQTT entropy pool v1");
        Self {
            hash,
            hw_bytes: 0,
            jitter_bits: 0,
            sources: 0,
        }
    }

    /// Mixes `bytes` from `source` into the pool (domain-separated).
    pub fn add(&mut self, source: Source, bytes: &[u8]) {
        self.hash.update([source.tag()]);
        self.hash.update((bytes.len() as u64).to_le_bytes());
        self.hash.update(bytes);
        self.sources |= 1 << source.tag();
        if source.is_hardware() {
            self.hw_bytes += bytes.len();
        }
    }

    /// Bitmask of contributing sources (bit = `Source` tag).
    pub fn sources(&self) -> u8 {
        self.sources
    }

    /// Whether a hardware source delivered enough to seed on its own.
    pub fn has_hardware(&self) -> bool {
        self.hw_bytes >= MIN_HW_BYTES
    }

    /// Credits jitter whose health tests passed (see [`JitterEstimator`]).
    pub fn credit_jitter(&mut self, bits: u64) {
        self.jitter_bits = self.jitter_bits.saturating_add(bits);
    }

    /// The generator, if a hardware source delivered enough (or, with
    /// `allow_jitter`, credited jitter reached [`JITTER_MIN_BITS`]).
    pub fn finish_with(self, allow_jitter: bool) -> Result<Csprng, NoHardwareEntropy> {
        let jitter_ok = allow_jitter && self.jitter_bits >= JITTER_MIN_BITS;
        if !self.has_hardware() && !jitter_ok {
            return Err(NoHardwareEntropy);
        }
        let seed: [u8; 32] = self.hash.finalize().into();
        Ok(Csprng {
            inner: ChaCha20Rng::from_seed(seed),
        })
    }

    pub fn finish(self) -> Result<Csprng, NoHardwareEntropy> {
        if self.hw_bytes < MIN_HW_BYTES {
            return Err(NoHardwareEntropy);
        }
        let seed: [u8; 32] = self.hash.finalize().into();
        Ok(Csprng {
            inner: ChaCha20Rng::from_seed(seed),
        })
    }
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

/// ChaCha20 generator. Not `Clone`: duplicating state would repeat output.
pub struct Csprng {
    inner: ChaCha20Rng,
}

impl Csprng {
    pub fn fill(&mut self, out: &mut [u8]) {
        self.inner.fill_bytes(out);
    }

    pub fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    /// Derives an independent generator (e.g. one per core) from 32 bytes
    /// of this one's output; the parent continues on a different stream.
    pub fn fork(&mut self) -> Self {
        let mut seed = [0u8; 32];
        self.fill(&mut seed);
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Mixes fresh entropy into the state (forward secrecy on reseed).
    pub fn reseed(&mut self, source: Source, bytes: &[u8]) {
        let mut current = [0u8; 32];
        self.fill(&mut current);
        let mut h = Sha256::new();
        h.update(b"urMQTT reseed v1");
        h.update(current);
        h.update([source.tag()]);
        h.update(bytes);
        let seed: [u8; 32] = h.finalize().into();
        self.inner = ChaCha20Rng::from_seed(seed);
    }
}

/// The generator used by TLS (installed once by the kernel after seeding).
static GLOBAL: SpinLock<Option<Csprng>> = SpinLock::new(None);

/// Makes `rng` the generator behind [`SystemRng`].
pub fn install(rng: Csprng) {
    *GLOBAL.lock() = Some(rng);
}

pub fn is_installed() -> bool {
    GLOBAL.lock().is_some()
}

/// Fills `out` from the installed generator. Fails (rather than returning
/// weak bytes) if none is installed.
pub fn fill_global(out: &mut [u8]) -> Result<(), NoHardwareEntropy> {
    match GLOBAL.lock().as_mut() {
        Some(r) => {
            r.fill(out);
            Ok(())
        }
        None => Err(NoHardwareEntropy),
    }
}

/// `rand_core` view of the installed generator, for RustCrypto APIs.
/// Callers check [`is_installed`] first; without a generator it refuses to
/// produce output by never returning (it cannot fail in this trait).
pub struct SystemRng;

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while fill_global(dest).is_err() {
            core::hint::spin_loop();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_global(dest).map_err(|_| rand_core::Error::from(core::num::NonZeroU32::MIN))
    }
}

impl CryptoRng for SystemRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_without_hardware_entropy() {
        let mut p = EntropyPool::new();
        p.add(Source::Bootloader, &[7; 64]);
        p.add(Source::Jitter, &[1; 64]);
        p.add(Source::VirtioRng, &[9; 16]); // too little
        assert_eq!(p.finish().err(), Some(NoHardwareEntropy));
    }

    #[test]
    fn deterministic_for_equal_input_distinct_otherwise() {
        let make = |b: u8| {
            let mut p = EntropyPool::new();
            p.add(Source::VirtioRng, &[b; 32]);
            let mut r = p.finish().unwrap();
            let mut out = [0u8; 64];
            r.fill(&mut out);
            out
        };
        assert_eq!(make(1), make(1));
        assert_ne!(make(1), make(2));
        // Source tags are domain-separated.
        let mut a = EntropyPool::new();
        a.add(Source::VirtioRng, &[1; 32]);
        let mut b = EntropyPool::new();
        b.add(Source::Rndr, &[1; 32]);
        assert_ne!(
            a.finish().unwrap().next_u64(),
            b.finish().unwrap().next_u64()
        );
    }

    #[test]
    fn fork_and_reseed_change_streams() {
        let mut p = EntropyPool::new();
        p.add(Source::Rndr, &[3; 40]);
        assert_eq!(p.sources(), 1 << 2);
        let mut parent = p.finish().unwrap();
        let mut child = parent.fork();
        assert_ne!(parent.next_u64(), child.next_u64());
        let before = parent.next_u64();
        parent.reseed(Source::VirtioRng, &[0; 32]);
        assert_ne!(parent.next_u64(), before);
    }

    #[test]
    fn jitter_estimator_health_and_credit() {
        // A stuck timer fails the repetition count test.
        let mut e = JitterEstimator::new();
        for _ in 0..100 {
            e.add(48);
        }
        assert!(e.failed());
        assert_eq!(e.credited_bits(), 0);
        // A coarse timer alternating between two values: about 1 bit per
        // sample estimated, but credited only with the safety factor; and
        // no health failure.
        let mut e = JitterEstimator::new();
        for i in 0..4096u64 {
            e.add(48 + (i * 7919 % 3 == 0) as u64);
        }
        assert!(!e.failed());
        assert!(e.bits_per_sample() <= 1, "{}", e.bits_per_sample());
        // Well-spread samples: several bits per sample, enough credit.
        let mut e = JitterEstimator::new();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2048 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            e.add(x);
        }
        assert!(!e.failed());
        assert!(e.bits_per_sample() >= 6, "{}", e.bits_per_sample());
        assert!(e.credited_bits() >= JITTER_MIN_BITS);
        // One dominant value within a window fails the proportion test.
        let mut e = JitterEstimator::new();
        for i in 0..512u64 {
            e.add(if i % 10 == 0 { i } else { 5 + (i % 2) * 256 });
        }
        assert!(e.failed());
    }

    #[test]
    fn pool_needs_hardware_or_credited_jitter() {
        let mut p = EntropyPool::new();
        p.add(Source::Jitter, &[1; 64]);
        p.credit_jitter(JITTER_MIN_BITS);
        assert!(EntropyPool::new().finish_with(true).is_err());
        let mut q = EntropyPool::new();
        q.add(Source::Jitter, &[1; 64]);
        q.credit_jitter(JITTER_MIN_BITS - 1);
        assert!(q.finish_with(true).is_err());
        let mut r = EntropyPool::new();
        r.credit_jitter(JITTER_MIN_BITS);
        assert!(r.finish_with(false).is_err(), "not without opting in");
        assert!(p.finish_with(true).is_ok());
    }
}
