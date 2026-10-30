//! x86_64 support: the facade's items.
//!
//! Every item the kernel reaches through `urmqtt-arch` exists here with the
//! signature the contract (`crates/arch/src/contract.rs`) demands, and
//! calling one that is not implemented yet stops with a message naming the
//! milestone that provides it, rather than doing something plausible. The
//! module layout mirrors `urmqtt-arch-aarch64` so the facade re-exports both
//! the same way. Pure parts (feature decoding, MSI composition, descriptor
//! encoding, fault decoding) work on the host and are unit tested there.
//!
//! X2 brought up the boot path: `entry` (the ELF entry and the baseline
//! check), `serial` (COM1), `gdt`/`idt`/`isr` (descriptor tables and the
//! exception entry), `cpu`, `power` and the CPUID probing in `features`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

/// Stops with the milestone that implements the item.
macro_rules! unimplemented_until {
    ($ms:literal) => {
        panic!(concat!("x86_64: not implemented until ", $ms))
    };
}

pub mod apic;
pub mod crc;
pub mod entropy;
pub mod features;
pub mod gdt;
pub mod hpet;
pub mod idt;
pub mod ioapic;
pub mod msi;
pub mod paging;
pub mod pat;
pub mod trap;
pub mod tsc;
pub mod vectors;

#[cfg(target_os = "none")]
pub mod cpu;
#[cfg(target_os = "none")]
mod entry;
#[cfg(target_os = "none")]
pub mod irq;
#[cfg(target_os = "none")]
mod isr;
#[cfg(target_os = "none")]
pub mod percpu;
#[cfg(target_os = "none")]
pub mod pic;
#[cfg(target_os = "none")]
pub mod pio;
#[cfg(target_os = "none")]
mod port;
#[cfg(target_os = "none")]
pub mod power;
#[cfg(target_os = "none")]
pub mod prim;
#[cfg(target_os = "none")]
pub mod serial;
#[cfg(target_os = "none")]
pub mod time;
