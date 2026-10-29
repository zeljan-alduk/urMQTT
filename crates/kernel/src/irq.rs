//! Interrupt routing: GIC setup (v3, or v2 on GIC-400 hosts) and the IRQ
//! dispatch table.
//!
//! Handlers run with IRQs masked on the exception stack and must only
//! acknowledge and mark work (PROMPT §4.1); they never log or allocate.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use urmqtt_arch_aarch64::gic::{self, GicError, Gicv2, Gicv3, Redistributor, SPURIOUS};
use urmqtt_arch_aarch64::regs;
use urmqtt_arch_aarch64::sync::OnceCell;
use urmqtt_platform::{Gic, GicCpu};

use crate::{memory, smp};

/// An IRQ handler: receives the INTID.
pub type Handler = fn(u32);

const MAX_INTID: usize = 1020;
static HANDLERS: [AtomicUsize; MAX_INTID] = [const { AtomicUsize::new(0) }; MAX_INTID];
static GIC: OnceCell<Controller> = OnceCell::new();

#[derive(Clone, Copy)]
enum Controller {
    V3(Gicv3),
    V2(Gicv2),
}

/// A CPU's handle on the GIC: its redistributor (v3) or its target mask
/// (v2, the bit SPIs and SGIs are routed to).
#[derive(Debug, Clone, Copy)]
pub enum Local {
    V3(Redistributor),
    V2(u8),
}

/// GICv2 addresses at most 8 CPUs by target mask.
pub const GICV2_MAX_CPUS: usize = 8;
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
            let g = unsafe { Gicv3::new(gicd as usize, va as usize, len as usize) };
            g.init_distributor().map_err(IrqError::Gic)?;
            Controller::V3(g)
        }
        GicCpu::V2 { gicc } => {
            let va = memory::map_mmio(gicc, 0x2000).map_err(|_| IrqError::Map)?;
            // SAFETY: both ranges were just mapped as device memory for good.
            let g = unsafe { Gicv2::new(gicd as usize, va as usize) };
            g.init_distributor();
            Controller::V2(g)
        }
    };
    let lines = match g {
        Controller::V3(g) => g.lines(),
        Controller::V2(g) => g.lines(),
    };
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
    let local = match GIC.get().ok_or(IrqError::Map)? {
        Controller::V3(g) => {
            let rd = g
                .redistributor(regs::mpidr_affinity())
                .map_err(IrqError::Gic)?;
            g.init_redistributor(rd).map_err(IrqError::Gic)?;
            gic::init_cpu_interface();
            Local::V3(rd)
        }
        Controller::V2(g) => Local::V2(g.init_cpu()),
    };
    me.gic
        .set(local)
        .map_err(|_| IrqError::AlreadyInitialised)?;
    for sgi in [smp::SGI_PING, smp::SGI_PONG, smp::SGI_WAKE] {
        enable_private(sgi);
    }
    Ok(())
}

/// True on a GICv2, which caps the usable CPUs at `GICV2_MAX_CPUS`.
pub fn is_v2() -> bool {
    matches!(GIC.get(), Some(Controller::V2(_)))
}

pub fn register(intid: u32, h: Handler) {
    if let Some(slot) = HANDLERS.get(intid as usize) {
        // Release: a core that observes the pointer may call it.
        slot.store(h as usize, Ordering::Release);
    }
}

/// Enables a private interrupt (SGI/PPI) on the executing CPU.
pub fn enable_private(intid: u32) {
    match (GIC.get(), smp::this().gic.get()) {
        (Some(Controller::V3(g)), Some(Local::V3(rd))) => g.enable_private(*rd, intid),
        (Some(Controller::V2(g)), _) => g.enable_private(intid),
        _ => {}
    }
}

/// Routes SPI `intid` (edge-triggered, as MSIs are) to logical CPU `cpu`.
pub fn enable_spi(intid: u32, cpu: usize) {
    let Some(pc) = smp::CPUS.get(cpu) else { return };
    match GIC.get() {
        // Relaxed: written before the CPU was started.
        Some(Controller::V3(g)) => g.enable_spi(intid, pc.mpidr.load(Ordering::Relaxed), true),
        Some(Controller::V2(g)) => {
            if let Some(Local::V2(mask)) = pc.gic.get() {
                g.enable_spi(intid, *mask, true);
            }
        }
        None => {}
    }
}

/// Sends SGI `intid` to logical CPU `cpu`; prior stores are visible to its
/// handler. A CPU whose GIC setup has not run yet is not reachable on a
/// GICv2 and the SGI is dropped.
pub fn send_sgi(intid: u32, cpu: usize) {
    let Some(pc) = smp::CPUS.get(cpu) else { return };
    match GIC.get() {
        // Relaxed: written before the CPU was started.
        Some(Controller::V3(_)) => gic::send_sgi(intid, pc.mpidr.load(Ordering::Relaxed)),
        Some(Controller::V2(g)) => {
            if let Some(Local::V2(mask)) = pc.gic.get() {
                g.send_sgi(intid, *mask);
            }
        }
        None => {}
    }
}

/// Handles every pending interrupt. Called from the IRQ vector.
pub fn dispatch() {
    let v2 = match GIC.get() {
        Some(Controller::V2(g)) => Some(*g),
        _ => None,
    };
    loop {
        // GICv2 needs the raw IAR value (with the SGI source) back in EOIR.
        let (iar, intid) = match v2 {
            Some(g) => {
                let iar = g.ack();
                (iar, iar & 0x3ff)
            }
            None => {
                let intid = gic::ack();
                (intid, intid)
            }
        };
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
        match v2 {
            Some(g) => g.eoi(iar),
            None => gic::eoi(intid),
        }
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
