//! Exploit-mitigation glue (H4): the boot seed that the allocator keys, the
//! stack guard and the randomised layout are derived from.
//!
//! The seed is built before the CSPRNG exists (the heap and the first
//! stacks come first), from what the bootloader and the CPU offer: Limine's
//! entropy values (EFI RNG or `RNDR`/`RDRAND`), the CPU's own random
//! instruction, and the counter. The CSPRNG is seeded later from the same
//! and from virtio-rng; where a mitigation can wait for it (the stack
//! guard is renewed then), it does.

#![allow(unsafe_code)]

use urmqtt_log::info;

/// SplitMix64's finalizer: a bijective mixer, good enough to spread seed
/// words into independent-looking keys (these keys obfuscate and detect;
/// they are not cryptographic).
pub const fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Key material for the boot, and what it is made of.
#[derive(Clone, Copy)]
pub struct Seed {
    words: [u64; 4],
    /// Bits of entropy credited (at most 256): 64 per non-zero bootloader
    /// value, 256 if the CPU's random instruction answered.
    pub bits: u32,
    pub bootloader_values: u32,
    pub cpu_rng: bool,
}

impl Seed {
    /// Builds the seed from the bootloader's entropy values.
    pub fn new(entropy: &[u64]) -> Self {
        let mut acc = [
            0x243f_6a88_85a3_08d3_u64,
            0x1319_8a2e_0370_7344,
            0xa409_3822_299f_31d0,
            0x082e_fa98_ec4e_6c89,
        ];
        let mut values = 0u32;
        for (i, v) in entropy.iter().enumerate() {
            if *v != 0 {
                values += 1;
            }
            if let Some(a) = acc.get_mut(i % 4) {
                *a = mix(*a ^ v);
            }
        }
        let mut cpu_rng = false;
        if let Some(hw) = urmqtt_arch::entropy::hw_random() {
            cpu_rng = true;
            for (i, c) in hw.as_chunks::<8>().0.iter().enumerate() {
                if let Some(a) = acc.get_mut(i % 4) {
                    *a = mix(*a ^ u64::from_le_bytes(*c));
                }
            }
        }
        // Not entropy, but it keeps two boots with equal inputs apart.
        let t = urmqtt_arch::time::uptime_ns();
        if let Some(a) = acc.first_mut() {
            *a = mix(*a ^ t);
        }
        let bits = if cpu_rng { 256 } else { (values * 64).min(256) };
        Self {
            words: acc,
            bits,
            bootloader_values: values,
            cpu_rng,
        }
    }

    /// An independent key for `domain` (a distinct constant per consumer).
    pub fn key(&self, domain: u64) -> u64 {
        let mut k = mix(domain);
        for w in self.words {
            k = mix(k ^ w);
        }
        k
    }

    pub fn log(&self) {
        info!(
            "hardening: boot seed of {} bit(s): {} bootloader value(s), cpu rng {}",
            self.bits,
            self.bootloader_values,
            if self.cpu_rng { "yes" } else { "no" }
        );
    }
}

/// Domain separators for [`Seed::key`].
pub mod domain {
    pub const GUARD: u64 = 0x4755_4152_4400_0003;
    pub const BUDDY: u64 = 0x4255_4444_5900_0001;
    pub const CACHE: u64 = 0x4341_4348_4500_0002;
}

/// Stack protector (H4, ADR-171).
///
/// The compiler (`-Zstack-protector=strong` for Rust, `-fstack-protector-strong`
/// for SQLite) puts a canary below the saved registers of every function
/// with an array or an address-taken local and compares it with this word
/// before returning. The word is replaced twice while only the boot CPU runs
/// and only `kmain_stage2` (which never returns) is on its stack: first from
/// the boot seed, then from the CSPRNG as soon as it exists. A function that
/// returned after the change would find a different canary and stop the
/// machine, so the change is never made inside a function that returns.
pub mod stack_guard {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// What the first instructions run with, until the seed exists. A
    /// terminator canary (a zero byte stops string copies); not secret.
    const BUILD_TIME: usize = 0x0000_0aff_0d0a_0000;

    /// The symbol the compiler's prologue and epilogue read.
    #[unsafe(no_mangle)]
    #[allow(non_upper_case_globals)]
    pub static __stack_chk_guard: AtomicUsize = AtomicUsize::new(BUILD_TIME);

    /// Called by every protected epilogue whose canary does not match.
    /// Nothing about the frame is printed (ADR-172).
    #[unsafe(no_mangle)]
    #[cold]
    #[inline(never)]
    pub extern "C" fn __stack_chk_fail() -> ! {
        urmqtt_log::emergency(format_args!(
            "\n!!! STACK SMASHING DETECTED: a stack canary was overwritten, stopping\n"
        ));
        crate::power::fatal()
    }

    /// Installs a new canary: 56 random bits and a zero low byte.
    ///
    /// Only from a function that never returns (see the module comment).
    pub fn renew(random: u64) {
        let v = (random & !0xff) as usize;
        // Relaxed: only the boot CPU runs; the other cores start later and
        // synchronise with the boot CPU before they use any protected code.
        __stack_chk_guard.store(v, Ordering::Relaxed);
    }

    /// Whether the canary is still the build-time constant (a test: it must
    /// not be once the kernel runs).
    pub fn is_default() -> bool {
        // Relaxed: a plain read.
        __stack_chk_guard.load(Ordering::Relaxed) == BUILD_TIME
    }
}
