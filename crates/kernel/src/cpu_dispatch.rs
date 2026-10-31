//! The sealed CPU dispatch (ADR-041, X0b): which implementation of each
//! hot primitive runs, decided once on the boot CPU and then immutable.
//!
//! The sealed state lives in `.data.sealed`, a page of its own (`linker.ld`).
//! The bootloader maps it writable, so the seal is written in stage 1. The
//! kernel's own tables map it read-only from the moment they are active, so
//! any later attempt to change the choice faults (smoke `sealed-write`).
//!
//! RustCrypto asks through the vendored `cpufeatures` (vendor/README.md),
//! which calls [`urmqtt_cpu_has`]. CRC-32C gets its backend installed here.

#![allow(unsafe_code)]

use urmqtt_dispatch::{CpuFeatures, Primitive, SealCell, SealError, Sealed, TABLE};

// SAFETY: `.data.sealed` is an ordinary data section with a page of its
// own (`linker.ld`); only its kernel mapping differs (read-only, `vm.rs`).
#[unsafe(link_section = ".data.sealed")]
static CPU: SealCell = SealCell::new();

/// The sealed state (`None` before [`seal`]).
#[cfg_attr(not(feature = "selftest"), allow(dead_code))]
pub fn sealed() -> Option<&'static Sealed> {
    CPU.get()
}

/// Seals the dispatch: `detected` minus `disabled`, then installs the
/// kernel-side backends (CRC-32C).
pub fn seal(detected: CpuFeatures, disabled: CpuFeatures) -> Result<&'static Sealed, SealError> {
    let s = CPU.seal_mask(&TABLE, detected, disabled)?;
    if matches!(
        s.selection.backend(Primitive::Crc32c),
        "armv8-crc" | "sse4.2"
    ) {
        urmqtt_store::crc::set_backend(crc32c_hw);
    }
    Ok(s)
}

fn crc32c_hw(crc: u32, data: &[u8]) -> u32 {
    // SAFETY: installed only when the sealed set has FEAT_CRC32 (AArch64)
    // or SSE4.2 (x86_64).
    unsafe { urmqtt_arch::crc::crc32c_update(crc, data) }
}

/// The address of the sealed state, for the `test=sealed-write` fault.
pub fn sealed_addr() -> u64 {
    core::ptr::from_ref(&CPU) as u64
}

/// Called by the vendored `cpufeatures` (RustCrypto): may target feature
/// `name` be used? `false` before the seal, so nothing latches a hardware
/// path early.
#[unsafe(no_mangle)]
extern "C" fn urmqtt_cpu_has(name: *const u8, len: usize) -> bool {
    if name.is_null() {
        return false;
    }
    // SAFETY: cpufeatures passes a `&'static str` literal's pointer and
    // length (vendor/cpufeatures-*/src/aarch64.rs, `urmqtt::has`).
    let bytes = unsafe { core::slice::from_raw_parts(name, len) };
    match (core::str::from_utf8(bytes), CPU.get()) {
        (Ok(n), Some(s)) => s.cpufeatures(n),
        _ => false,
    }
}
