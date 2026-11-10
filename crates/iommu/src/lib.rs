//! DMA remapping for the devices the kernel drives (H4b, ADR-305 to ADR-307).
//!
//! Three drivers behind one shape: Intel VT-d ([`vtd`], legacy mode with
//! second-level tables), AMD-Vi ([`amdvi`], v1 host page tables) and Arm
//! SMMUv3 ([`smmuv3`], stage 1 with linear stream and context-descriptor
//! tables). Each gives every PCI function the kernel drives a translation
//! domain of its own whose only mappings are the pages the kernel allocated
//! for that device's DMA (identity: I/O virtual address = physical address,
//! [`pt`]); every other device, and every other address, faults. Faults are
//! read by polling, a bounded number per call ([`Fault`]), never by an
//! interrupt (ADR-306).
//!
//! Nothing here touches hardware directly: the register frame is a [`Regs`]
//! and the memory the unit reads (tables, queues) is reached through [`Env`],
//! both implemented by the kernel. So the crate has no `unsafe` and every
//! driver is tested on the host against a model of its unit.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod amdvi;
pub mod pt;
pub mod smmuv3;
pub mod vtd;

#[cfg(test)]
mod model;

/// The page size of every table and mapping.
pub const PAGE: u64 = 4096;

/// A unit's register frame.
pub trait Regs {
    fn read32(&self, off: usize) -> u32;
    fn write32(&mut self, off: usize, v: u32);
    fn read64(&self, off: usize) -> u64;
    fn write64(&mut self, off: usize, v: u64);
}

/// What the drivers need from the kernel besides the registers.
pub trait Env {
    /// `pages` zeroed, physically contiguous pages aligned to `align_pages`
    /// pages, which the unit reads and writes: their physical address.
    fn alloc(&mut self, pages: usize, align_pages: usize) -> Option<u64>;
    /// Reads the doubleword at physical address `pa` (8-byte aligned, in
    /// memory from [`alloc`](Self::alloc)).
    fn read(&self, pa: u64) -> u64;
    /// Writes it.
    fn write(&mut self, pa: u64, v: u64);
    /// Makes the CPU's writes to `[pa, pa + len)` visible to a unit whose
    /// table walks are not cache coherent (a no-op for a coherent one).
    fn flush(&mut self, pa: u64, len: usize);
    /// A monotonic clock, nanoseconds: the bound on every wait for the unit.
    fn now_ns(&self) -> u64;
}

/// How long the drivers wait for a unit to acknowledge a command.
pub const TIMEOUT_NS: u64 = 100_000_000;

/// Why a unit could not be brought up or a device attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The unit did not acknowledge `what` within [`TIMEOUT_NS`].
    Timeout(&'static str),
    /// [`Env::alloc`] failed.
    NoMemory,
    /// The unit lacks something the driver needs.
    Unsupported(&'static str),
    /// The physical address does not fit the unit's address width.
    AddressTooWide,
    /// A device or stream ID beyond what the unit (or its tables) covers.
    IdOutOfRange,
    /// The unit reported a command error.
    CommandError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout(w) => write!(f, "timed out waiting for {w}"),
            Self::NoMemory => f.write_str("out of memory for the tables"),
            Self::Unsupported(w) => write!(f, "unsupported: {w}"),
            Self::AddressTooWide => f.write_str("address wider than the unit translates"),
            Self::IdOutOfRange => f.write_str("device ID beyond the unit's tables"),
            Self::CommandError => f.write_str("the unit reported a command error"),
        }
    }
}

/// One fault (a blocked DMA, or a unit error) as the unit recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fault {
    /// The ID the unit saw (requester ID, device ID, stream ID).
    pub source: u32,
    /// The address the device used (page granular on VT-d).
    pub addr: u64,
    /// A write (else a read, or not stated).
    pub write: bool,
    /// The unit's own reason code (VT-d fault reason, AMD-Vi event code,
    /// SMMUv3 event type).
    pub reason: u8,
}

/// The result of one fault poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Poll {
    /// Faults read (and acknowledged) by this poll.
    pub read: u32,
    /// The unit lost faults because its log was full (counted once per
    /// overflow it reported).
    pub overflowed: bool,
    /// More were pending than the poll's bound: the next poll continues.
    pub more: bool,
}

/// Waits until `done()` or [`TIMEOUT_NS`] passes.
pub(crate) fn wait<E: Env>(
    env: &E,
    what: &'static str,
    mut done: impl FnMut() -> bool,
) -> Result<(), Error> {
    let start = env.now_ns();
    loop {
        if done() {
            return Ok(());
        }
        if env.now_ns().saturating_sub(start) > TIMEOUT_NS {
            return Err(Error::Timeout(what));
        }
        core::hint::spin_loop();
    }
}
