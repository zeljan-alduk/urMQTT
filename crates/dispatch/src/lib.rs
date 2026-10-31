//! Which implementation of each hot primitive runs on this CPU (ADR-041).
//!
//! At boot the architecture's feature detection is turned into a
//! [`CpuFeatures`] set. The `[cpu] disable = [...]` configuration list is
//! taken out of it, and [`select`] picks, per primitive, the first backend
//! in preference order that is compiled into this image and whose features
//! are all present. The result is sealed once ([`SealCell`]) and only read
//! afterwards.
//!
//! Only performance features are listed. Security features (pointer
//! authentication, BTI, W^X) are never switchable: the opt-out exists to
//! work around a slow or broken accelerator, not to weaken the kernel.
//!
//! Since X0b the kernel image builds the ARMv8 backends in (`--cfg
//! aes_armv8 --cfg polyval_armv8`, the vendored `cpufeatures` asking
//! [`Sealed::cpufeatures`], the CRC32 instructions); host builds list them
//! as not built. X9 adds the x86 ones.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use urmqtt_sync::sync::OnceCell;

/// A CPU feature that selects a code path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// AArch64 AES instructions (FEAT_AES).
    Aes,
    /// AArch64 64-bit polynomial multiply (FEAT_PMULL).
    Pmull,
    /// AArch64 SHA-256 instructions (FEAT_SHA256).
    Sha2,
    /// AArch64 CRC-32 and CRC-32C instructions (FEAT_CRC32).
    Crc32,
}

impl Feature {
    pub const ALL: [Feature; 4] = [Self::Aes, Self::Pmull, Self::Sha2, Self::Crc32];

    /// The name used in `[cpu] disable` and in the boot log.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Pmull => "pmull",
            Self::Sha2 => "sha2",
            Self::Crc32 => "crc32",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    const fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// A set of [`Feature`]s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuFeatures(u32);

impl CpuFeatures {
    pub const NONE: Self = Self(0);

    /// `self` with `f` added if `present`.
    #[must_use]
    pub const fn with(self, f: Feature, present: bool) -> Self {
        if present {
            Self(self.0 | f.bit())
        } else {
            self
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn has(self, f: Feature) -> bool {
        self.0 & f.bit() != 0
    }

    pub fn has_all(self, fs: &[Feature]) -> bool {
        fs.iter().all(|&f| self.has(f))
    }
}

/// Lists the features, space separated, or `none`.
impl fmt::Display for CpuFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut any = false;
        for feat in Feature::ALL.into_iter().filter(|&x| self.has(x)) {
            if any {
                f.write_str(" ")?;
            }
            f.write_str(feat.name())?;
            any = true;
        }
        if !any {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// A primitive with more than one possible implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primitive {
    AesGcm,
    Ghash,
    ChaCha20Poly1305,
    Sha256,
    Crc32c,
    Toeplitz,
}

impl Primitive {
    pub const ALL: [Primitive; 6] = [
        Self::AesGcm,
        Self::Ghash,
        Self::ChaCha20Poly1305,
        Self::Sha256,
        Self::Crc32c,
        Self::Toeplitz,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::AesGcm => "aes-gcm",
            Self::Ghash => "ghash",
            Self::ChaCha20Poly1305 => "chacha",
            Self::Sha256 => "sha256",
            Self::Crc32c => "crc32c",
            Self::Toeplitz => "toeplitz",
        }
    }
}

/// One implementation of a primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backend {
    pub name: &'static str,
    /// Features the CPU must have (and not have disabled).
    pub needs: &'static [Feature],
    /// Compiled into this image. A backend that is not cannot be chosen.
    pub built: bool,
}

/// Candidates per primitive, most preferred first; the last one of each
/// row is the portable implementation and needs nothing.
pub type Table = [(Primitive, &'static [Backend]); 6];

const fn soft(name: &'static str) -> Backend {
    Backend {
        name,
        needs: &[],
        built: true,
    }
}

/// The bare-metal aarch64 kernel (the host builds none of the hardware
/// backends: it has its own RustCrypto detection).
const KERNEL_AARCH64: bool = cfg!(all(target_os = "none", target_arch = "aarch64"));

/// The bare-metal x86_64 kernel (X9). It is built for x86-64-v2, so SSE2 to
/// SSE4.2 are always there; AES-NI, PCLMULQDQ, SHA-NI and SSE4.2's CRC32 are
/// detected. The features keep the AArch64 names (`aes`, `pmull`, `sha2`,
/// `crc32`) in `[cpu] disable` and in the log: AES-NI, PCLMULQDQ, SHA
/// extensions and SSE4.2.
const KERNEL_X86: bool = cfg!(all(target_os = "none", target_arch = "x86_64"));

/// The backends of this image. RustCrypto's AES and POLYVAL ask
/// `cpufeatures` for "aes", which covers AES *and* PMULL, so both AES-GCM
/// halves need both features.
pub const TABLE: Table = [
    (
        Primitive::AesGcm,
        &[
            Backend {
                name: "armv8-aes",
                needs: &[Feature::Aes, Feature::Pmull],
                built: KERNEL_AARCH64 && cfg!(aes_armv8),
            },
            Backend {
                name: "aesni",
                needs: &[Feature::Aes, Feature::Pmull],
                built: KERNEL_X86,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::Ghash,
        &[
            Backend {
                name: "armv8-pmull",
                needs: &[Feature::Aes, Feature::Pmull],
                built: KERNEL_AARCH64 && cfg!(polyval_armv8),
            },
            Backend {
                name: "pclmulqdq",
                needs: &[Feature::Pmull],
                built: KERNEL_X86,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::ChaCha20Poly1305,
        &[
            // NEON (Advanced SIMD) is part of every ARMv8-A CPU: forced at
            // build time, nothing to detect.
            Backend {
                name: "neon",
                needs: &[],
                built: KERNEL_AARCH64 && cfg!(chacha20_force_neon),
            },
            // The x86 kernel keeps no AVX state (ADR-042): ChaCha20 runs the
            // SSE2 backend, the baseline. "avx2" is never granted.
            Backend {
                name: "sse2",
                needs: &[],
                built: KERNEL_X86,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::Sha256,
        &[
            Backend {
                name: "armv8-sha2",
                needs: &[Feature::Sha2],
                built: KERNEL_AARCH64,
            },
            Backend {
                name: "sha-ni",
                needs: &[Feature::Sha2],
                built: KERNEL_X86,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::Crc32c,
        &[
            Backend {
                name: "armv8-crc",
                needs: &[Feature::Crc32],
                built: KERNEL_AARCH64,
            },
            Backend {
                name: "sse4.2",
                needs: &[Feature::Crc32],
                built: KERNEL_X86,
            },
            soft("table"),
        ],
    ),
    (Primitive::Toeplitz, &[soft("bitwise")]),
];

/// The chosen backend name of every primitive, in [`Primitive::ALL`] order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection([&'static str; 6]);

impl Selection {
    pub fn backend(&self, p: Primitive) -> &'static str {
        Primitive::ALL
            .iter()
            .position(|&q| q == p)
            .and_then(|i| self.0.get(i).copied())
            .unwrap_or("?")
    }
}

/// `aes-gcm=soft ghash=soft ...`, the boot log form.
impl fmt::Display for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in Primitive::ALL.into_iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{}={}", p.name(), self.backend(p))?;
        }
        Ok(())
    }
}

/// Picks, per primitive, the first built backend whose features `usable`
/// has. A row without a usable entry selects `"none"` (a table bug that
/// the tests rule out for [`TABLE`]).
pub fn select(table: &Table, usable: CpuFeatures) -> Selection {
    let mut out = ["none"; 6];
    for (slot, p) in out.iter_mut().zip(Primitive::ALL) {
        if let Some((_, row)) = table.iter().find(|(q, _)| *q == p)
            && let Some(b) = row.iter().find(|b| b.built && usable.has_all(b.needs))
        {
            *slot = b.name;
        }
    }
    Selection(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableError {
    /// Not a feature name ([`Feature::name`]).
    Unknown,
    /// Listed twice.
    Duplicate,
}

/// Parses the `[cpu] disable` list.
pub fn parse_disable(names: &[&str]) -> Result<CpuFeatures, DisableError> {
    parse_names(names.iter().copied())
}

/// Parses a comma-separated list of feature names (`aes,pmull`).
pub fn parse_disable_csv(csv: &str) -> Result<CpuFeatures, DisableError> {
    parse_names(csv.split(','))
}

fn parse_names<'a>(names: impl Iterator<Item = &'a str>) -> Result<CpuFeatures, DisableError> {
    let mut set = CpuFeatures::NONE;
    for name in names {
        let f = Feature::from_name(name).ok_or(DisableError::Unknown)?;
        if set.has(f) {
            return Err(DisableError::Duplicate);
        }
        set = set.with(f, true);
    }
    Ok(set)
}

/// The sealed outcome of detection, opt-out and selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    /// What the CPU reports.
    pub detected: CpuFeatures,
    /// Taken out by `[cpu] disable`.
    pub disabled: CpuFeatures,
    /// What backends may use: `detected` without `disabled`.
    pub usable: CpuFeatures,
    pub selection: Selection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    Disable(DisableError),
    /// Sealing twice is refused: the first result stays.
    AlreadySealed,
}

impl Sealed {
    /// The answer for RustCrypto's `cpufeatures` (the vendored patch asks
    /// through the kernel's `urmqtt_cpu_has`): may target feature `name` be
    /// used? Only features this image dispatches on; anything else is
    /// refused, so an unknown request falls back to portable code.
    pub fn cpufeatures(&self, name: &str) -> bool {
        let u = self.usable;
        match name {
            // LLVM's "aes" implies PMULL (and RustCrypto's POLYVAL uses it
            // that way).
            "aes" => u.has(Feature::Aes) && u.has(Feature::Pmull),
            "sha2" => u.has(Feature::Sha2),
            // The x86 names (X9): POLYVAL asks for "pclmulqdq", SHA-256 for
            // "sha". Everything else (avx2, avx512*, bmi2, ...) is refused:
            // the kernel keeps no AVX state.
            "pclmulqdq" => u.has(Feature::Pmull),
            "sha" => u.has(Feature::Sha2),
            _ => false,
        }
    }
}

/// Holds the [`Sealed`] result, written exactly once.
pub struct SealCell(OnceCell<Sealed>);

impl SealCell {
    pub const fn new() -> Self {
        Self(OnceCell::new())
    }

    /// Applies `disable` to `detected`, selects from `table` and seals the
    /// result.
    pub fn seal(
        &self,
        table: &Table,
        detected: CpuFeatures,
        disable: &[&str],
    ) -> Result<&Sealed, SealError> {
        let disabled = parse_disable(disable).map_err(SealError::Disable)?;
        self.seal_mask(table, detected, disabled)
    }

    /// As [`Self::seal`], with the opt-out already parsed (the kernel joins
    /// the configuration's list and a dev command-line list).
    pub fn seal_mask(
        &self,
        table: &Table,
        detected: CpuFeatures,
        disabled: CpuFeatures,
    ) -> Result<&Sealed, SealError> {
        let usable = detected.without(disabled);
        let sealed = Sealed {
            detected,
            disabled,
            usable,
            selection: select(table, usable),
        };
        self.0.set(sealed).map_err(|_| SealError::AlreadySealed)?;
        self.0.get().ok_or(SealError::AlreadySealed)
    }

    /// The sealed result, once [`Self::seal`] succeeded.
    pub fn get(&self) -> Option<&Sealed> {
        self.0.get()
    }
}

impl Default for SealCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
