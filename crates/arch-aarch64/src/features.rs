//! CPU feature detection from the `ID_AA64*` registers (pure decoding).

/// Raw ID register values, read once at boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdRegs {
    pub isar0: u64,
    pub isar1: u64,
    pub isar2: u64,
    pub pfr0: u64,
    pub pfr1: u64,
}

/// Features the kernel cares about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    /// Pointer authentication with the A key (any of APA, API, APA3).
    pub pauth: bool,
    /// Faulting PAC (FEAT_FPAC): failed authentication traps immediately.
    pub fpac: bool,
    /// Branch target identification (FEAT_BTI).
    pub bti: bool,
    /// `RNDR`/`RNDRRS` random number instructions (FEAT_RNG).
    pub rndr: bool,
    /// AES instructions (and PMULL if `pmull`).
    pub aes: bool,
    pub pmull: bool,
    pub sha2: bool,
    pub crc32: bool,
    /// Large System Extensions atomics.
    pub lse: bool,
    /// Memory tagging, any level.
    pub mte: bool,
    pub sve: bool,
}

const fn field(reg: u64, shift: u32) -> u64 {
    (reg >> shift) & 0xf
}

impl Features {
    /// The features that select code paths, for `urmqtt-dispatch`.
    pub const fn dispatch(&self) -> urmqtt_dispatch::CpuFeatures {
        use urmqtt_dispatch::{CpuFeatures, Feature};
        CpuFeatures::NONE
            .with(Feature::Aes, self.aes)
            .with(Feature::Pmull, self.pmull)
            .with(Feature::Sha2, self.sha2)
            .with(Feature::Crc32, self.crc32)
    }

    pub const fn decode(r: IdRegs) -> Self {
        let apa = field(r.isar1, 4);
        let api = field(r.isar1, 8);
        let apa3 = field(r.isar2, 12);
        let aes = field(r.isar0, 4);
        Self {
            pauth: apa != 0 || api != 0 || apa3 != 0,
            fpac: apa >= 4 || api >= 4 || apa3 >= 4,
            bti: field(r.pfr1, 0) >= 1,
            rndr: field(r.isar0, 60) >= 1,
            aes: aes >= 1,
            pmull: aes >= 2,
            sha2: field(r.isar0, 12) >= 1,
            crc32: field(r.isar0, 16) >= 1,
            lse: field(r.isar0, 20) >= 2,
            mte: field(r.pfr1, 8) >= 1,
            sve: field(r.pfr0, 32) >= 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_set() {
        assert_eq!(Features::decode(IdRegs::default()), Features::default());
    }

    #[test]
    fn neoverse_n1_like() {
        // AES+PMULL, SHA2, CRC32, LSE; no PAC/BTI (Armv8.2).
        let f = Features::decode(IdRegs {
            isar0: 0x0000_0000_0021_1120,
            ..IdRegs::default()
        });
        assert!(f.aes && f.pmull && f.sha2 && f.crc32 && f.lse);
        assert!(!f.pauth && !f.bti && !f.rndr);
    }

    #[test]
    fn pac_bti_rng() {
        let f = Features::decode(IdRegs {
            isar0: 1 << 60,
            isar1: 0x5 << 4, // APA = FPACCOMBINE
            pfr1: 0x1 | (0x2 << 8),
            ..IdRegs::default()
        });
        assert!(f.pauth && f.fpac && f.bti && f.rndr && f.mte);
        let qarma3 = Features::decode(IdRegs {
            isar2: 0x1 << 12,
            ..IdRegs::default()
        });
        assert!(qarma3.pauth && !qarma3.fpac);
    }
}
