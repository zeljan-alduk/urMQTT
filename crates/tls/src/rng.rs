//! Kernel CSPRNG: ChaCha20 seeded from a SHA-256 pool of entropy sources.
//!
//! PROMPT §6: never run without entropy. The pool only yields a generator
//! once at least one *hardware* source (virtio-rng, `RNDR`) contributed;
//! bootloader-provided values are mixed in but do not count on their own.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use urmqtt_arch_aarch64::sync::SpinLock;

/// Minimum bytes a hardware source must deliver to count.
pub const MIN_HW_BYTES: usize = 32;

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
    sources: u8,
}

impl EntropyPool {
    pub fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"urMQTT entropy pool v1");
        Self {
            hash,
            hw_bytes: 0,
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
}
