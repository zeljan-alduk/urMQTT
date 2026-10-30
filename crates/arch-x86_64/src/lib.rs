//! x86_64 support: the facade's items for X1.
//!
//! Every item the kernel reaches through `urmqtt-arch` exists here with the
//! signature the contract (`crates/arch/src/contract.rs`) demands, and
//! calling one that is not implemented yet stops with a message naming the
//! milestone that provides it, rather than doing something plausible. The
//! module layout mirrors `urmqtt-arch-aarch64` so the facade re-exports both
//! the same way. Pure parts (feature decoding, MSI composition) already work.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

/// Stops with the milestone that implements the item.
macro_rules! unimplemented_until {
    ($ms:literal) => {
        panic!(concat!("x86_64: not implemented until ", $ms))
    };
}

pub mod crc;
pub mod features;
pub mod msi;
pub mod paging;
pub mod trap;

#[cfg(target_os = "none")]
pub mod cpu;
#[cfg(target_os = "none")]
pub mod entropy;
#[cfg(target_os = "none")]
pub mod irq;
#[cfg(target_os = "none")]
pub mod percpu;
#[cfg(target_os = "none")]
pub mod pio;
#[cfg(target_os = "none")]
pub mod power;
#[cfg(target_os = "none")]
pub mod time;

// The ELF entry until X2 brings up the real boot path: stop, visibly (the
// debug-exit port is a dev-only QEMU device, X2).
#[cfg(target_os = "none")]
#[allow(unsafe_code)]
mod entry {
    core::arch::global_asm!(
        ".section .text.boot, \"ax\"",
        ".global _start",
        "_start:",
        "    cli",
        "    call urmqtt_kmain",
        "1:  hlt",
        "    jmp 1b",
    );
}
