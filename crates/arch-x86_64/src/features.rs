//! CPU features from CPUID: pure decoding here, the probing (`read`) on
//! bare metal only.

use core::fmt;

/// Raw CPUID leaves, read once at boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdRegs {
    /// Highest standard leaf.
    pub max_leaf: u32,
    /// Leaf 0: the vendor string (EBX, EDX, ECX order).
    pub vendor: [u8; 12],
    /// Leaf 1: EAX (family, model, stepping), ECX, EDX.
    pub l1_eax: u32,
    pub l1_ecx: u32,
    pub l1_edx: u32,
    /// Leaf 7 subleaf 0: EBX, ECX, EDX.
    pub l7_ebx: u32,
    pub l7_ecx: u32,
    pub l7_edx: u32,
    /// Leaf 0x8000_0007: EDX (bit 8: invariant TSC).
    pub l80000007_edx: u32,
    /// Leaf 0x4000_0000: the hypervisor signature (zeros on bare metal).
    pub hypervisor: [u8; 12],
    /// Leaves 0x8000_0002..4: the processor brand string.
    pub brand: [[u8; 16]; 3],
    /// XCR0 as the OS enabled it (0 if XSAVE is off).
    pub xcr0: u64,
}

/// Leaf 1 ECX bits of the x86-64-v2 baseline (PROMPT-x86_64 section 1):
/// SSE3, SSSE3, CMPXCHG16B, SSE4.1, SSE4.2, POPCNT. Long mode already
/// implies SSE2 and FXSR.
pub const BASELINE_ECX: [(u32, &str); 6] = [
    (0, "sse3"),
    (9, "ssse3"),
    (13, "cx16"),
    (19, "sse4.1"),
    (20, "sse4.2"),
    (23, "popcnt"),
];

/// The baseline bits as a mask. The boot assembly (`entry.rs`) checks the
/// same mask before any Rust code runs.
pub const BASELINE_MASK: u32 = {
    let mut m = 0;
    let mut i = 0;
    while i < BASELINE_ECX.len() {
        m |= 1 << BASELINE_ECX[i].0;
        i += 1;
    }
    m
};

/// Baseline features a CPU lacks, as a leaf 1 ECX mask (0: it qualifies).
pub const fn baseline_missing(l1_ecx: u32) -> u32 {
    !l1_ecx & BASELINE_MASK
}

/// Names the baseline features in `missing`, e.g. `ssse3 sse4.1`.
pub struct Missing(pub u32);

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (bit, name) in BASELINE_ECX {
            if self.0 & (1 << bit) != 0 {
                write!(f, "{}{name}", if first { "" } else { " " })?;
                first = false;
            }
        }
        Ok(())
    }
}

/// Features the kernel cares about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    pub aes: bool,
    pub pclmul: bool,
    pub sha: bool,
    pub sse42: bool,
    pub avx2: bool,
    /// BMI2 and ADX (MULX, ADCX, ADOX): general-purpose registers only.
    pub bmi2_adx: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub tsc_deadline: bool,
    pub x2apic: bool,
    // The names the kernel's boot log uses; the first three are the x86
    // counterparts, the rest are AArch64 concepts and stay false. The x86
    // boot path prints its own CPUID summary and census instead.
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
            .with(Feature::Bmi2Adx, self.bmi2_adx)
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
            bmi2_adx: bit(r.l7_ebx, 8) && bit(r.l7_ebx, 19),
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

/// Family, model and stepping from leaf 1 EAX, with the extended fields
/// folded in the way Intel and AMD define for families 6 and 15.
pub const fn family_model_stepping(eax: u32) -> (u32, u32, u32) {
    let stepping = eax & 0xf;
    let base_family = (eax >> 8) & 0xf;
    let base_model = (eax >> 4) & 0xf;
    let ext_family = (eax >> 20) & 0xff;
    let ext_model = (eax >> 16) & 0xf;
    let family = if base_family == 0xf {
        base_family + ext_family
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        (ext_model << 4) | base_model
    } else {
        base_model
    };
    (family, model, stepping)
}

fn ascii(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("?")
}

/// The identity line: vendor, family/model/stepping, hypervisor, brand.
pub struct Identity<'a>(pub &'a IdRegs);

impl fmt::Display for Identity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.0;
        let (fam, model, step) = family_model_stepping(r.l1_eax);
        write!(
            f,
            "vendor={} family={fam} model={model:#x} stepping={step}",
            ascii(&r.vendor)
        )?;
        if bit(r.l1_ecx, 31) {
            write!(
                f,
                " hypervisor={}",
                ascii(&r.hypervisor).trim_end_matches('\0')
            )?;
        } else {
            write!(f, " hypervisor=none")?;
        }
        let brand = r.brand.as_flattened();
        let brand = ascii(brand).trim_matches(|c: char| c == '\0' || c == ' ');
        if !brand.is_empty() {
            write!(f, " brand=\"{brand}\"")?;
        }
        Ok(())
    }
}

/// The optional features the guest sees, for the census line (X2,
/// ADR-046): each present one by name, `xcr0` last.
pub struct Census<'a>(pub &'a IdRegs);

impl fmt::Display for Census<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.0;
        let ymm = r.xcr0 & 0b110 == 0b110;
        let zmm = r.xcr0 & 0xe0 == 0xe0;
        let table: [(&str, bool); 24] = [
            ("aes", bit(r.l1_ecx, 25)),
            ("pclmulqdq", bit(r.l1_ecx, 1)),
            ("sha", bit(r.l7_ebx, 29)),
            ("avx", bit(r.l1_ecx, 28) && ymm),
            ("avx2", bit(r.l7_ebx, 5) && ymm),
            ("vaes", bit(r.l7_ecx, 9)),
            ("vpclmulqdq", bit(r.l7_ecx, 10)),
            ("gfni", bit(r.l7_ecx, 8)),
            ("avx512f", bit(r.l7_ebx, 16) && zmm),
            ("avx512bw", bit(r.l7_ebx, 30) && zmm),
            ("avx512vl", bit(r.l7_ebx, 31) && zmm),
            ("rdrand", bit(r.l1_ecx, 30)),
            ("rdseed", bit(r.l7_ebx, 18)),
            ("fsgsbase", bit(r.l7_ebx, 0)),
            ("x2apic", bit(r.l1_ecx, 21)),
            ("tsc-deadline", bit(r.l1_ecx, 24)),
            ("invariant-tsc", bit(r.l80000007_edx, 8)),
            ("waitpkg", bit(r.l7_ecx, 5)),
            ("cet-ss", bit(r.l7_ecx, 7)),
            ("cet-ibt", bit(r.l7_edx, 20)),
            ("xsave", bit(r.l1_ecx, 26)),
            ("pcid", bit(r.l1_ecx, 17)),
            ("smep", bit(r.l7_ebx, 7)),
            ("smap", bit(r.l7_ebx, 20)),
        ];
        let mut first = true;
        for (name, on) in table {
            if on {
                write!(f, "{}{name}", if first { "" } else { " " })?;
                first = false;
            }
        }
        if first {
            write!(f, "none")?;
        }
        write!(f, " xcr0={:#x}", r.xcr0)
    }
}

/// One CPUID leaf.
#[cfg(target_os = "none")]
pub(crate) fn cpuid(leaf: u32, sub: u32) -> core::arch::x86_64::CpuidResult {
    // CPUID exists in every x86-64 CPU; leaves it does not implement read as
    // zeros or as the highest leaf, and callers check the maxima.
    core::arch::x86_64::__cpuid_count(leaf, sub)
}

/// Reads CPUID. XCR0 is read only if the OS enabled XSAVE (CR4.OSXSAVE,
/// which leaf 1 ECX bit 27 reflects); see `cpu::enable_extended_state`.
#[cfg(target_os = "none")]
pub fn read() -> IdRegs {
    let (l0, l1) = (cpuid(0, 0), cpuid(1, 0));
    let ext_max = cpuid(0x8000_0000, 0).eax;
    let mut r = IdRegs {
        max_leaf: l0.eax,
        l1_eax: l1.eax,
        l1_ecx: l1.ecx,
        l1_edx: l1.edx,
        ..IdRegs::default()
    };
    for (i, reg) in [l0.ebx, l0.edx, l0.ecx].into_iter().enumerate() {
        r.vendor[i * 4..i * 4 + 4].copy_from_slice(&reg.to_le_bytes());
    }
    if r.max_leaf >= 7 {
        let l7 = cpuid(7, 0);
        r.l7_ebx = l7.ebx;
        r.l7_ecx = l7.ecx;
        r.l7_edx = l7.edx;
    }
    if ext_max >= 0x8000_0007 {
        r.l80000007_edx = cpuid(0x8000_0007, 0).edx;
    }
    if ext_max >= 0x8000_0004 {
        for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            let c = cpuid(leaf, 0);
            for (j, reg) in [c.eax, c.ebx, c.ecx, c.edx].into_iter().enumerate() {
                if let Some(chunk) = r.brand.get_mut(i).and_then(|b| b.get_mut(j * 4..j * 4 + 4)) {
                    chunk.copy_from_slice(&reg.to_le_bytes());
                }
            }
        }
    }
    if bit(r.l1_ecx, 31) {
        // The hypervisor-present bit says the 0x4000_0000 range exists.
        let h = cpuid(0x4000_0000, 0);
        for (i, reg) in [h.ebx, h.ecx, h.edx].into_iter().enumerate() {
            r.hypervisor[i * 4..i * 4 + 4].copy_from_slice(&reg.to_le_bytes());
        }
    }
    if bit(r.l1_ecx, 27) {
        r.xcr0 = xgetbv0();
    }
    r
}

/// XCR0.
#[cfg(target_os = "none")]
#[allow(unsafe_code)]
pub(crate) fn xgetbv0() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: only called when CR4.OSXSAVE is set (leaf 1 ECX bit 27), so
    // XGETBV does not fault; ECX = 0 selects XCR0.
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    (u64::from(hi) << 32) | u64::from(lo)
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

    #[test]
    fn baseline_mask_matches_the_documented_bits() {
        // SSE3 0, SSSE3 9, CX16 13, SSE4.1 19, SSE4.2 20, POPCNT 23.
        assert_eq!(BASELINE_MASK, 0x0098_2201);
    }

    #[test]
    fn baseline_missing_names_what_a_qemu64_lacks() {
        // qemu64 (TCG): SSE3 and CX16 only.
        let qemu64 = (1 << 0) | (1 << 13);
        let m = baseline_missing(qemu64);
        assert_eq!(std::format!("{}", Missing(m)), "ssse3 sse4.1 sse4.2 popcnt");
        assert_eq!(baseline_missing(BASELINE_MASK | 1 << 25), 0);
        assert_eq!(std::format!("{}", Missing(0)), "");
    }

    #[test]
    fn family_model_stepping_folds_the_extended_fields() {
        // Skylake-SP: family 6, model 0x55, stepping 4.
        assert_eq!(family_model_stepping(0x0005_0654), (6, 0x55, 4));
        // Zen 3: family 0xf + 0xa = 25, model 0x21.
        assert_eq!(family_model_stepping(0x00a2_0f10), (25, 0x21, 0));
        // An old family-5 part ignores the extended fields.
        assert_eq!(family_model_stepping(0x0001_0543), (5, 4, 3));
    }

    #[test]
    fn identity_and_census_read_well() {
        let mut r = IdRegs {
            vendor: *b"GenuineIntel",
            l1_eax: 0x0005_0654,
            l1_ecx: (1 << 31) | (1 << 25) | (1 << 26) | (1 << 28) | (1 << 21),
            l7_ebx: (1 << 5) | (1 << 29),
            l7_ecx: (1 << 9) | (1 << 7),
            xcr0: 0x7,
            ..IdRegs::default()
        };
        r.hypervisor[..9].copy_from_slice(b"TCGTCGTCG");
        r.brand[0][..8].copy_from_slice(b"  QEMU  ");
        assert_eq!(
            std::format!("{}", Identity(&r)),
            "vendor=GenuineIntel family=6 model=0x55 stepping=4 hypervisor=TCGTCGTCG brand=\"QEMU\""
        );
        assert_eq!(
            std::format!("{}", Census(&r)),
            "aes sha avx avx2 vaes x2apic cet-ss xsave xcr0=0x7"
        );
        assert_eq!(
            std::format!("{}", Census(&IdRegs::default())),
            "none xcr0=0x0"
        );
    }

    #[test]
    fn avx512_needs_the_zmm_state() {
        let r = IdRegs {
            l7_ebx: 1 << 16,
            xcr0: 0x7,
            ..IdRegs::default()
        };
        assert!(!std::format!("{}", Census(&r)).contains("avx512f"));
        let r = IdRegs { xcr0: 0xe7, ..r };
        assert!(std::format!("{}", Census(&r)).contains("avx512f"));
    }
}
