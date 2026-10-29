//! The interrupt controller as the kernel sees it: one GIC, v3 or v2
//! (GIC-400 hosts), behind a single type.
//!
//! The kernel maps the frames, keeps the handler table and stores each
//! CPU's [`Local`] handle; this module knows which GIC is which.

#![allow(unsafe_code)]

use crate::gic::{self, GicError, Gicv2, Gicv3, Redistributor, SPURIOUS};
use crate::regs;

#[derive(Clone, Copy)]
pub enum Controller {
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

/// An acknowledged interrupt. GICv2 needs the raw IAR value (with the SGI
/// source) back at end of interrupt.
#[derive(Debug, Clone, Copy)]
pub struct Ack {
    raw: u32,
    pub intid: u32,
}

impl Ack {
    /// No interrupt is pending (or a special INTID): stop dispatching.
    pub fn is_none(&self) -> bool {
        self.intid >= SPURIOUS
    }

    /// The controller reported a spurious interrupt (INTID 1023).
    pub fn is_spurious(&self) -> bool {
        self.intid == 1023
    }
}

impl Controller {
    /// A GICv3 with its distributor initialised.
    ///
    /// # Safety
    /// As [`Gicv3::new`]: both ranges are device mappings for good.
    pub unsafe fn v3(gicd: usize, gicr: usize, gicr_len: usize) -> Result<Self, GicError> {
        // SAFETY: forwarded to the caller.
        let g = unsafe { Gicv3::new(gicd, gicr, gicr_len) };
        g.init_distributor()?;
        Ok(Self::V3(g))
    }

    /// A GICv2 with its distributor initialised.
    ///
    /// # Safety
    /// As [`Gicv2::new`]: both ranges are device mappings for good.
    pub unsafe fn v2(gicd: usize, gicc: usize) -> Self {
        // SAFETY: forwarded to the caller.
        let g = unsafe { Gicv2::new(gicd, gicc) };
        g.init_distributor();
        Self::V2(g)
    }

    /// Number of interrupt lines.
    pub fn lines(&self) -> u32 {
        match self {
            Self::V3(g) => g.lines(),
            Self::V2(g) => g.lines(),
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2(_))
    }

    /// CPUs this controller can route to.
    pub fn max_cpus(&self) -> usize {
        match self {
            Self::V3(_) => usize::MAX,
            Self::V2(_) => GICV2_MAX_CPUS,
        }
    }

    /// Sets up the executing CPU: its redistributor (v3) or banked
    /// registers (v2) and its CPU interface.
    pub fn init_local(&self) -> Result<Local, GicError> {
        Ok(match self {
            Self::V3(g) => {
                let rd = g.redistributor(regs::mpidr_affinity())?;
                g.init_redistributor(rd)?;
                gic::init_cpu_interface();
                Local::V3(rd)
            }
            Self::V2(g) => Local::V2(g.init_cpu()),
        })
    }

    /// Enables a private interrupt (SGI/PPI) on the executing CPU, whose
    /// handle is `local`.
    pub fn enable_private(&self, local: Option<&Local>, intid: u32) {
        match (self, local) {
            (Self::V3(g), Some(Local::V3(rd))) => g.enable_private(*rd, intid),
            (Self::V2(g), _) => g.enable_private(intid),
            _ => {}
        }
    }

    /// Routes SPI `intid` (edge-triggered, as MSIs are) to the CPU with
    /// firmware id `hw_id` and handle `local`. A GICv2 CPU without a handle
    /// is not reachable.
    pub fn enable_spi(&self, intid: u32, hw_id: u64, local: Option<&Local>) {
        match self {
            Self::V3(g) => g.enable_spi(intid, hw_id, true),
            Self::V2(g) => {
                if let Some(Local::V2(mask)) = local {
                    g.enable_spi(intid, *mask, true);
                }
            }
        }
    }

    /// Sends SGI `intid` to the CPU with firmware id `hw_id` and handle
    /// `local`; prior stores are visible to its handler. On a GICv2 a CPU
    /// without a handle is not reachable and the SGI is dropped.
    pub fn send_ipi(&self, intid: u32, hw_id: u64, local: Option<&Local>) {
        match self {
            Self::V3(_) => gic::send_sgi(intid, hw_id),
            Self::V2(g) => {
                if let Some(Local::V2(mask)) = local {
                    g.send_sgi(intid, *mask);
                }
            }
        }
    }

    /// Acknowledges the highest-priority pending interrupt.
    pub fn ack(&self) -> Ack {
        match self {
            Self::V2(g) => {
                let raw = g.ack();
                Ack {
                    raw,
                    intid: raw & 0x3ff,
                }
            }
            Self::V3(_) => {
                let intid = gic::ack();
                Ack { raw: intid, intid }
            }
        }
    }

    /// Ends an interrupt returned by [`Self::ack`].
    pub fn eoi(&self, ack: Ack) {
        match self {
            Self::V2(g) => g.eoi(ack.raw),
            Self::V3(_) => gic::eoi(ack.intid),
        }
    }
}
