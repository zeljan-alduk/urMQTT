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

/// Where the linker script puts the kernel image (`linker*.ld`); the
/// bootloader's slide is the difference to the address it loaded it at.
pub const LINK_BASE: u64 = 0xffff_ffff_8000_0000;

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

    /// Overwrites the key material (the boot state outlives its use).
    pub fn wipe(&mut self) {
        for w in &mut self.words {
            // SAFETY: a valid, exclusive reference.
            unsafe { core::ptr::write_volatile(w, 0) };
        }
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
    pub const LAYOUT: u64 = 0x4c41_594f_5500_0004;
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
    // SAFETY: the compiler's stack-protector prologue/epilogue reads `__stack_chk_guard` by name;
    // no other item has that name, and it is an atomic, so reads racing a store are defined.
    #[unsafe(no_mangle)]
    #[allow(non_upper_case_globals)]
    pub static __stack_chk_guard: AtomicUsize = AtomicUsize::new(BUILD_TIME);

    /// Called by every protected epilogue whose canary does not match.
    /// Nothing about the frame is printed (ADR-172).
    // SAFETY: the compiler's epilogue calls `__stack_chk_fail` by name with the C ABI when a canary
    // differs; no other item has that name, and it never returns.
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
    #[cfg(feature = "selftest")]
    pub fn is_default() -> bool {
        // Relaxed: a plain read.
        __stack_chk_guard.load(Ordering::Relaxed) == BUILD_TIME
    }
}

/// What a fault or panic report may contain (H4, ADR-172).
///
/// A report is read by whoever has the console (the VPS provider's VNC, a
/// serial log, a screen recording) and, if it outlives the VM, by anyone
/// they pass it to. It must not carry secrets, and it must not carry the
/// layout of the running kernel. In a production image a fault report
/// therefore has: the exception and its decoded cause, the class of the
/// faulting address (guard page, lower half, ...), the program counter as
/// an offset into the kernel image, and, for a panic, the location and a
/// message only if it is a fixed string. It does not have: register values,
/// stack or memory dumps, absolute addresses, formatted panic messages
/// (their arguments are whatever the caller formatted). A dev image prints
/// everything, as before, unless the `redact` test word asks for the
/// production policy (the tests that prove it).
pub mod fault_policy {
    use core::sync::atomic::{AtomicBool, Ordering};

    static FORCED: AtomicBool = AtomicBool::new(false);

    /// Applies the production policy even in a dev image (test word).
    pub fn force() {
        // Relaxed: set once on the boot CPU before any test fault.
        FORCED.store(true, Ordering::Relaxed);
    }

    /// Whether reports are redacted.
    pub fn redact() -> bool {
        // Relaxed: see `force`.
        FORCED.load(Ordering::Relaxed) || !urmqtt_config::CONFIG.dev()
    }

    /// `pc` as `kernel+0xOFFSET` when it is inside the image, else a fixed
    /// phrase: an offset reads against the build's symbols, an address
    /// would tell where a randomised kernel sits.
    pub struct ImageOffset(pub u64);

    impl core::fmt::Display for ImageOffset {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let (lo, hi) = crate::vm::image_range();
            if (lo..hi).contains(&self.0) {
                write!(f, "kernel+{:#x}", self.0 - lo)
            } else {
                f.write_str("outside the kernel image")
            }
        }
    }
}

/// The boot log's account of the randomisation (ADR-173): how many bits
/// each region's placement has, never where anything is. A dev image adds
/// the addresses, which are what a developer needs to read a fault.
pub fn log_placement(p: &crate::layout::Placement, seed: &Seed, image_base: u64, dev: bool) {
    let slide = image_base.wrapping_sub(LINK_BASE);
    info!(
        "kaslr: heap {} bit(s), heap bookkeeping {}, stacks {}, page-table alias {}, mmio {}; \
         kernel image {} (seed {} bit(s))",
        p.heap_bits,
        p.heap_meta_bits,
        p.stacks_bits,
        p.pt_alias_bits,
        p.mmio_bits,
        if slide != 0 {
            "slid by the bootloader"
        } else if cfg!(target_arch = "aarch64") {
            "not slid (this boot's slide was zero)"
        } else {
            "not slid (static image, ADR-173)"
        },
        seed.bits
    );
    if dev {
        info!(
            "kaslr (dev only): image {:#x} (slide {:#x}), heap {:#x}, bookkeeping {:#x}, stacks {:#x}, \
             page-table alias {:#x}, mmio {:#x}",
            image_base,
            slide,
            crate::layout::heap_base(),
            crate::layout::heap_meta_base(),
            crate::layout::stacks_base(),
            crate::layout::pt_alias_base(),
            crate::layout::mmio_base()
        );
    }
}

/// Memory tagging state (ADR-174).
static MTE_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Records that tag checking is on (the boot CPU did it).
pub fn mte_on() {
    // Release: the application processors read it after the boot CPU has
    // set the registers they copy.
    MTE_ON.store(true, core::sync::atomic::Ordering::Release);
}

/// Whether heap allocations are tagged.
pub fn mte_active() -> bool {
    MTE_ON.load(core::sync::atomic::Ordering::Acquire)
}
