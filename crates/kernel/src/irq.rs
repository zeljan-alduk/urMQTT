//! Interrupt routing: GICv3 setup and the IRQ dispatch table.
//!
//! Handlers run with IRQs masked on the exception stack and must only
//! acknowledge and mark work (PROMPT §4.1); they never log or allocate.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use urmqtt_arch_aarch64::gic::{self, GicError, Gicv3, SPURIOUS};
use urmqtt_arch_aarch64::regs;
use urmqtt_arch_aarch64::sync::OnceCell;
use urmqtt_platform::Gic;

use crate::{memory, smp};

/// An IRQ handler: receives the INTID.
pub type Handler = fn(u32);

const MAX_INTID: usize = 1020;
static HANDLERS: [AtomicUsize; MAX_INTID] = [const { AtomicUsize::new(0) }; MAX_INTID];
static GIC: OnceCell<Gicv3> = OnceCell::new();
static SPURIOUS_COUNT: AtomicU64 = AtomicU64::new(0);
static UNHANDLED_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub enum IrqError {
    Map,
    #[allow(dead_code)] // read through `Debug` in the fatal boot message
    Gic(GicError),
    AlreadyInitialised,
}

/// Maps the GIC frames, initialises the distributor and this CPU's
/// redistributor and CPU interface. Must run before the page tables lock.
pub fn init(gic_info: &Gic, cpus: u64) -> Result<u32, IrqError> {
    let gicd = memory::map_mmio(gic_info.gicd, 0x1_0000).map_err(|_| IrqError::Map)?;
    // Only map the redistributors that can exist (128 KiB each, 256 KiB
    // with VLPI frames), not the whole advertised range.
    let gicr_len = gic_info.gicr.1.min(cpus.max(1) * 0x4_0000);
    let gicr = memory::map_mmio(gic_info.gicr.0, gicr_len).map_err(|_| IrqError::Map)?;
    // SAFETY: both ranges were just mapped as device memory for good.
    let g = unsafe { Gicv3::new(gicd as usize, gicr as usize, gicr_len as usize) };
    g.init_distributor().map_err(IrqError::Gic)?;
    let rd = g
        .redistributor(regs::mpidr_affinity())
        .map_err(IrqError::Gic)?;
    g.init_redistributor(rd).map_err(IrqError::Gic)?;
    gic::init_cpu_interface();
    let lines = g.lines();
    GIC.set(g).map_err(|_| IrqError::AlreadyInitialised)?;
    smp::this()
        .rd
        .set(rd)
        .map_err(|_| IrqError::AlreadyInitialised)?;
    for sgi in [smp::SGI_PING, smp::SGI_PONG, smp::SGI_WAKE] {
        g.enable_private(rd, sgi);
    }
    Ok(lines)
}

/// Per-CPU part on an application processor: its redistributor, the CPU
/// interface and the IPI SGIs.
pub fn init_secondary(me: &smp::PerCpu) -> Result<(), IrqError> {
    let g = GIC.get().ok_or(IrqError::Map)?;
    let rd = g
        .redistributor(regs::mpidr_affinity())
        .map_err(IrqError::Gic)?;
    g.init_redistributor(rd).map_err(IrqError::Gic)?;
    gic::init_cpu_interface();
    for sgi in [smp::SGI_PING, smp::SGI_PONG, smp::SGI_WAKE] {
        g.enable_private(rd, sgi);
    }
    me.rd.set(rd).map_err(|_| IrqError::AlreadyInitialised)
}

pub fn register(intid: u32, h: Handler) {
    if let Some(slot) = HANDLERS.get(intid as usize) {
        // Release: a core that observes the pointer may call it.
        slot.store(h as usize, Ordering::Release);
    }
}

/// Enables a private interrupt (SGI/PPI) on the executing CPU.
pub fn enable_private(intid: u32) {
    if let (Some(g), Some(rd)) = (GIC.get(), smp::this().rd.get()) {
        g.enable_private(*rd, intid);
    }
}

/// Routes SPI `intid` (edge-triggered, as MSIs are) to the CPU `mpidr`.
pub fn enable_spi(intid: u32, mpidr: u64) {
    if let Some(g) = GIC.get() {
        g.enable_spi(intid, mpidr, true);
    }
}

/// Handles every pending interrupt. Called from the IRQ vector.
pub fn dispatch() {
    loop {
        let intid = gic::ack();
        if intid >= SPURIOUS {
            if intid == 1023 {
                // Relaxed: statistics only.
                SPURIOUS_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // Acquire: pairs with the Release in `register`.
        let raw = HANDLERS
            .get(intid as usize)
            .map_or(0, |s| s.load(Ordering::Acquire));
        if raw == 0 {
            // Relaxed: statistics only.
            UNHANDLED_COUNT.fetch_add(1, Ordering::Relaxed);
        } else {
            // SAFETY: only `register` stores into the table, always a `Handler`.
            let h: Handler = unsafe { core::mem::transmute::<usize, Handler>(raw) };
            h(intid);
        }
        gic::eoi(intid);
    }
}

/// (spurious, unhandled) interrupt counts.
pub fn stats() -> (u64, u64) {
    // Relaxed: statistics only.
    (
        SPURIOUS_COUNT.load(Ordering::Relaxed),
        UNHANDLED_COUNT.load(Ordering::Relaxed),
    )
}
