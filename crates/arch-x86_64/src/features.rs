//! CPU features from CPUID (pure decoding; the probing arrives in X2).

/// Raw CPUID leaves, read once at boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdRegs {
    /// Leaf 1: ECX, EDX.
    pub l1_ecx: u32,
    pub l1_edx: u32,
    /// Leaf 7 subleaf 0: EBX, ECX.
    pub l7_ebx: u32,
    pub l7_ecx: u32,
    /// XCR0 as the OS enabled it (0 if XSAVE is off).
    pub xcr0: u64,
}

/// Features the kernel cares about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    pub aes: bool,
    pub pclmul: bool,
    pub sha: bool,
    pub sse42: bool,
    pub avx2: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub tsc_deadline: bool,
    pub x2apic: bool,
    // The names the kernel's boot log uses; the first three are the x86
    // counterparts, the rest are AArch64 concepts and stay false. X2 gives
    // x86 its own CPUID summary.
    pub rndr: bool,
    pub pmull: bool,
    pub sha2: bool,
    pub pauth: bool,
    pub fpac: bool,
    pub bti: bool,
    pub lse: bool,
    pub mte: bool,
    pub sve: bool,
}

const fn bit(v: u32, n: u32) -> bool {
    v & (1 << n) != 0
}

impl Features {
    /// The features that select code paths, for `urmqtt-dispatch`.
    pub const fn dispatch(&self) -> urmqtt_dispatch::CpuFeatures {
        use urmqtt_dispatch::{CpuFeatures, Feature};
        CpuFeatures::NONE
            .with(Feature::Aes, self.aes)
            .with(Feature::Pmull, self.pclmul)
            .with(Feature::Sha2, self.sha)
            .with(Feature::Crc32, self.sse42)
    }

    pub const fn decode(r: IdRegs) -> Self {
        // AVX2 is usable only if the OS enabled the YMM state (XCR0 bits 1, 2).
        let ymm = r.xcr0 & 0b110 == 0b110;
        Self {
            aes: bit(r.l1_ecx, 25),
            pclmul: bit(r.l1_ecx, 1),
            sha: bit(r.l7_ebx, 29),
            sse42: bit(r.l1_ecx, 20),
            avx2: bit(r.l7_ebx, 5) && ymm,
            rdrand: bit(r.l1_ecx, 30),
            rdseed: bit(r.l7_ebx, 18),
            tsc_deadline: bit(r.l1_ecx, 24),
            x2apic: bit(r.l1_ecx, 21),
            rndr: bit(r.l1_ecx, 30) || bit(r.l7_ebx, 18),
            pmull: bit(r.l1_ecx, 1),
            sha2: bit(r.l7_ebx, 29),
            pauth: false,
            fpac: false,
            bti: false,
            lse: false,
            mte: false,
            sve: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_leaf_bits() {
        let f = Features::decode(IdRegs {
            l1_ecx: (1 << 25) | (1 << 1) | (1 << 20),
            l7_ebx: (1 << 29) | (1 << 5),
            xcr0: 0b111,
            ..IdRegs::default()
        });
        assert!(f.aes && f.pclmul && f.sha && f.sse42 && f.avx2);
        assert!(!f.rdrand && !f.x2apic);
    }

    #[test]
    fn avx2_needs_the_ymm_state() {
        let f = Features::decode(IdRegs {
            l7_ebx: 1 << 5,
            xcr0: 0b11,
            ..IdRegs::default()
        });
        assert!(!f.avx2);
    }
}
