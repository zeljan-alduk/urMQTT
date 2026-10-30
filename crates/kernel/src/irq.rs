//! Interrupt routing: GIC setup (v3, or v2 on GIC-400 hosts; on x86 the
//! local APIC and I/O APIC) and the IRQ dispatch table.
//!
//! Handlers run with IRQs masked on the exception stack and must only
//! acknowledge and mark work (PROMPT §4.1); they never log or allocate.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use urmqtt_arch::irq::{Controller, Error as GicError};
#[cfg(target_arch = "aarch64")]
use urmqtt_platform::{Gic, GicCpu};
use urmqtt_sync::sync::OnceCell;

use crate::{memory, smp};

pub use urmqtt_arch::irq::Local;

/// An IRQ handler: receives the INTID.
pub type Handler = fn(u32);

const MAX_INTID: usize = 1020;
static HANDLERS: [AtomicUsize; MAX_INTID] = [const { AtomicUsize::new(0) }; MAX_INTID];
/// The platform's interrupt controller (a GIC, or the local and I/O APICs).
static GIC: OnceCell<Controller> = OnceCell::new();

static SPURIOUS_COUNT: AtomicU64 = AtomicU64::new(0);
static UNHANDLED_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub enum IrqError {
    Map,
    #[allow(dead_code)] // read through `Debug` in the fatal boot message
    Gic(GicError),
    AlreadyInitialised,
}

#[cfg(target_arch = "aarch64")]
/// Maps the GIC frames, initialises the distributor and this CPU's
/// redistributor (v3) or banked registers (v2) and CPU interface. Must run
/// before the page tables lock. Returns the number of interrupt lines.
pub fn init(gic_info: &Gic, cpus: u64) -> Result<u32, IrqError> {
    let gicd = memory::map_mmio(gic_info.gicd, 0x1_0000).map_err(|_| IrqError::Map)?;
    let g = match gic_info.cpu {
        GicCpu::V3 { gicr } => {
            // Only map the redistributors that can exist (128 KiB each,
            // 256 KiB with VLPI frames), not the whole advertised range.
            let len = gicr.1.min(cpus.max(1) * 0x4_0000);
            let va = memory::map_mmio(gicr.0, len).map_err(|_| IrqError::Map)?;
            // SAFETY: both ranges were just mapped as device memory for good.
            unsafe { Controller::v3(gicd as usize, va as usize, len as usize) }
                .map_err(IrqError::Gic)?
        }
        GicCpu::V2 { gicc } => {
            let va = memory::map_mmio(gicc, 0x2000).map_err(|_| IrqError::Map)?;
            // SAFETY: both ranges were just mapped as device memory for good.
            unsafe { Controller::v2(gicd as usize, va as usize) }
        }
    };
    let lines = g.lines();
    GIC.set(g).map_err(|_| IrqError::AlreadyInitialised)?;
    init_local(smp::this())?;
    Ok(lines)
}

/// Per-CPU part on an application processor.
pub fn init_secondary(me: &smp::PerCpu) -> Result<(), IrqError> {
    init_local(me)
}

/// This CPU's redistributor or banked registers, its CPU interface and the
/// IPI SGIs.
fn init_local(me: &smp::PerCpu) -> Result<(), IrqError> {
    let local = GIC
        .get()
        .ok_or(IrqError::Map)?
        .init_local()
        .map_err(IrqError::Gic)?;
    me.gic
        .set(local)
        .map_err(|_| IrqError::AlreadyInitialised)?;
    for sgi in [smp::SGI_PING, smp::SGI_PONG, smp::SGI_WAKE] {
        enable_private(sgi);
    }
    Ok(())
}

/// Maps the local and I/O APIC windows, masks the 8259s and brings up the
/// boot CPU's local APIC. Must run before the page tables lock. Returns the
/// boot log description.
#[cfg(target_arch = "x86_64")]
pub fn init_apic(
    x86: &urmqtt_platform::x86::X86Info,
    _cpus: u64,
) -> Result<alloc::string::String, IrqError> {
    use urmqtt_arch::irq::Config;
    let lapic = memory::map_mmio(x86.lapic_addr, 0x1000).map_err(|_| IrqError::Map)?;
    let mut ioapics = [(0usize, 0u32); 8];
    let mut n = 0;
    for (slot, io) in ioapics.iter_mut().zip(x86.ioapics.as_slice()) {
        let va = memory::map_mmio(u64::from(io.address), 0x1000).map_err(|_| IrqError::Map)?;
        *slot = (va as usize, io.gsi_base);
        n += 1;
    }
    let cfg = Config {
        lapic_mmio: Some(lapic as usize),
        ioapics: ioapics.get(..n).unwrap_or(&[]),
        prefer_x2apic: true,
    };
    let c = Controller::apic(&cfg).map_err(IrqError::Gic)?;
    GIC.set(c).map_err(|_| IrqError::AlreadyInitialised)?;
    init_local(smp::this())?;
    Ok(alloc::format!(
        "apic: {} mode, lapic at {:#x}, {} I/O APIC(s), msi to the local APIC",
        urmqtt_arch::irq::mode_name(),
        x86.lapic_addr,
        n
    ))
}

/// True on a GICv2.
#[cfg(target_arch = "aarch64")]
pub fn is_v2() -> bool {
    GIC.get().is_some_and(Controller::is_v2)
}

/// CPUs the controller can route interrupts to (8 on a GICv2).
pub fn max_cpus() -> usize {
    GIC.get().map_or(usize::MAX, Controller::max_cpus)
}

pub fn register(intid: u32, h: Handler) {
    if let Some(slot) = HANDLERS.get(intid as usize) {
        // Release: a core that observes the pointer may call it.
        slot.store(h as usize, Ordering::Release);
    }
}

/// Enables a private interrupt (SGI/PPI) on the executing CPU.
pub fn enable_private(intid: u32) {
    if let Some(g) = GIC.get() {
        g.enable_private(smp::this().gic.get(), intid);
    }
}

/// Routes SPI `intid` (edge-triggered, as MSIs are) to logical CPU `cpu`.
pub fn enable_spi(intid: u32, cpu: usize) {
    let (Some(g), Some(pc)) = (GIC.get(), smp::CPUS.get(cpu)) else {
        return;
    };
    // Relaxed: written before the CPU was started.
    g.enable_spi(intid, pc.mpidr.load(Ordering::Relaxed), pc.gic.get());
}

/// Sends SGI `intid` to logical CPU `cpu`; prior stores are visible to its
/// handler. A CPU whose GIC setup has not run yet is not reachable on a
/// GICv2 and the SGI is dropped.
pub fn send_sgi(intid: u32, cpu: usize) {
    let (Some(g), Some(pc)) = (GIC.get(), smp::CPUS.get(cpu)) else {
        return;
    };
    // Relaxed: written before the CPU was started.
    g.send_ipi(intid, pc.mpidr.load(Ordering::Relaxed), pc.gic.get());
}

/// Handles every pending interrupt. Called from the IRQ vector.
pub fn dispatch() {
    let Some(g) = GIC.get() else { return };
    loop {
        let ack = g.ack();
        if ack.is_none() {
            if ack.is_spurious() {
                // Relaxed: statistics only.
                SPURIOUS_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let intid = ack.intid;
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
        g.eoi(ack);
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
