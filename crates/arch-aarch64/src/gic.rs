//! GICv3 driver: distributor and redistributors via MMIO, CPU interface via
//! system registers (`ICC_*_EL1`). All interrupts are non-secure group 1
//! with affinity routing.

#![allow(unsafe_code)]

use core::arch::asm;

// Distributor.
const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ICPENDR: usize = 0x0280;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_ICFGR: usize = 0x0c00;
const GICD_IROUTER: usize = 0x6000;
const GICD_CTLR_RWP: u32 = 1 << 31;
/// ARE_NS | EnableGrp1A | EnableGrp1 (NS view); ARE | Grp1 | Grp0 when DS=1.
const GICD_CTLR_ENABLE: u32 = (1 << 4) | (1 << 1) | 1;

// Redistributor (RD_base frame).
const GICR_CTLR: usize = 0x0000;
const GICR_TYPER: usize = 0x0008;
const GICR_WAKER: usize = 0x0014;
const GICR_CTLR_RWP: u32 = 1 << 3;
const GICR_TYPER_LAST: u64 = 1 << 4;
const GICR_TYPER_VLPIS: u64 = 1 << 1;
const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
// SGI_base frame = RD_base + 64 KiB.
const SGI_FRAME: usize = 0x1_0000;
const GICR_IGROUPR0: usize = SGI_FRAME + 0x0080;
const GICR_ISENABLER0: usize = SGI_FRAME + 0x0100;
const GICR_ICENABLER0: usize = SGI_FRAME + 0x0180;
const GICR_ICPENDR0: usize = SGI_FRAME + 0x0280;
const GICR_IPRIORITYR: usize = SGI_FRAME + 0x0400;

/// Bounded register polling so a broken GIC cannot hang boot.
const SPIN_LIMIT: u32 = 10_000_000;
/// Default priority for everything (lower value = higher priority).
pub const DEFAULT_PRIORITY: u8 = 0xa0;
/// INTIDs 1020-1023 are special (spurious etc.).
pub const SPURIOUS: u32 = 1020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicError {
    Timeout,
    NoRedistributor(u64),
}

#[derive(Clone, Copy)]
pub struct Gicv3 {
    gicd: usize,
    gicr: usize,
    gicr_len: usize,
}

/// One CPU's redistributor (RD_base virtual address).
#[derive(Debug, Clone, Copy)]
pub struct Redistributor {
    base: usize,
}

fn rd32(addr: usize) -> u32 {
    // SAFETY: callers only pass addresses inside the mapped GIC frames.
    unsafe { (addr as *const u32).read_volatile() }
}

fn wr32(addr: usize, v: u32) {
    // SAFETY: as in `rd32`.
    unsafe { (addr as *mut u32).write_volatile(v) }
}

fn rd64(addr: usize) -> u64 {
    // SAFETY: as in `rd32`; GICR_TYPER and GICD_IROUTER are 64-bit registers.
    unsafe { (addr as *const u64).read_volatile() }
}

fn wr64(addr: usize, v: u64) {
    // SAFETY: as in `rd64`.
    unsafe { (addr as *mut u64).write_volatile(v) }
}

fn wait_clear(addr: usize, mask: u32) -> Result<(), GicError> {
    for _ in 0..SPIN_LIMIT {
        if rd32(addr) & mask == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(GicError::Timeout)
}

impl Gicv3 {
    /// # Safety
    /// `gicd` (64 KiB) and `gicr` (`gicr_len` bytes) must be virtual
    /// addresses of the GIC frames, mapped as device memory for the kernel's
    /// lifetime.
    pub const unsafe fn new(gicd: usize, gicr: usize, gicr_len: usize) -> Self {
        Self {
            gicd,
            gicr,
            gicr_len,
        }
    }

    /// Number of SPI-capable interrupt lines (INTIDs 32..lines).
    pub fn lines(&self) -> u32 {
        let n = rd32(self.gicd + GICD_TYPER) & 0x1f;
        (32 * (n + 1)).min(1020)
    }

    /// Distributor setup, once per system: every SPI group 1, default
    /// priority, level-triggered, disabled, not pending; then enable.
    pub fn init_distributor(&self) -> Result<(), GicError> {
        wr32(self.gicd + GICD_CTLR, 0);
        wait_clear(self.gicd + GICD_CTLR, GICD_CTLR_RWP)?;
        let lines = self.lines();
        for i in (32..lines).step_by(32) {
            let w = (i / 32) as usize * 4;
            wr32(self.gicd + GICD_ICENABLER + w, u32::MAX);
            wr32(self.gicd + GICD_ICPENDR + w, u32::MAX);
            wr32(self.gicd + GICD_IGROUPR + w, u32::MAX);
        }
        let prio = u32::from_ne_bytes([DEFAULT_PRIORITY; 4]);
        for i in (32..lines).step_by(4) {
            wr32(self.gicd + GICD_IPRIORITYR + i as usize, prio);
        }
        for i in (32..lines).step_by(16) {
            wr32(self.gicd + GICD_ICFGR + (i / 16) as usize * 4, 0);
        }
        wr32(self.gicd + GICD_CTLR, GICD_CTLR_ENABLE);
        wait_clear(self.gicd + GICD_CTLR, GICD_CTLR_RWP)
    }

    /// Finds the redistributor whose affinity matches `mpidr_aff`
    /// (Aff3.Aff2.Aff1.Aff0 as in MPIDR).
    pub fn redistributor(&self, mpidr_aff: u64) -> Result<Redistributor, GicError> {
        let want = ((mpidr_aff >> 8) & 0xff00_0000) | (mpidr_aff & 0x00ff_ffff);
        let mut off = 0usize;
        while off + SGI_FRAME * 2 <= self.gicr_len {
            let base = self.gicr + off;
            let typer = rd64(base + GICR_TYPER);
            if (typer >> 32) == want {
                return Ok(Redistributor { base });
            }
            if typer & GICR_TYPER_LAST != 0 {
                break;
            }
            off += if typer & GICR_TYPER_VLPIS != 0 {
                0x4_0000
            } else {
                0x2_0000
            };
        }
        Err(GicError::NoRedistributor(mpidr_aff))
    }

    /// Wakes and configures this CPU's redistributor: SGIs and PPIs group 1,
    /// default priority, all disabled.
    pub fn init_redistributor(&self, rd: Redistributor) -> Result<(), GicError> {
        let waker = rd32(rd.base + GICR_WAKER);
        wr32(rd.base + GICR_WAKER, waker & !WAKER_PROCESSOR_SLEEP);
        wait_clear(rd.base + GICR_WAKER, WAKER_CHILDREN_ASLEEP)?;
        wr32(rd.base + GICR_ICENABLER0, u32::MAX);
        wr32(rd.base + GICR_ICPENDR0, u32::MAX);
        wr32(rd.base + GICR_IGROUPR0, u32::MAX);
        let prio = u32::from_ne_bytes([DEFAULT_PRIORITY; 4]);
        for i in (0..32).step_by(4) {
            wr32(rd.base + GICR_IPRIORITYR + i, prio);
        }
        wait_clear(rd.base + GICR_CTLR, GICR_CTLR_RWP)
    }

    /// Enables SGI/PPI `intid` (< 32) on the CPU owning `rd`.
    pub fn enable_private(&self, rd: Redistributor, intid: u32) {
        if intid < 32 {
            wr32(rd.base + GICR_ISENABLER0, 1 << intid);
        }
    }

    pub fn disable_private(&self, rd: Redistributor, intid: u32) {
        if intid < 32 {
            wr32(rd.base + GICR_ICENABLER0, 1 << intid);
        }
    }

    /// Routes SPI `intid` to the CPU with affinity `mpidr_aff` and enables it.
    pub fn enable_spi(&self, intid: u32, mpidr_aff: u64, edge: bool) {
        if !(32..self.lines()).contains(&intid) {
            return;
        }
        // GICD_IROUTER uses the MPIDR affinity layout (Aff3 at [39:32]).
        let route = mpidr_aff & 0xff_00ff_ffff;
        wr64(self.gicd + GICD_IROUTER + intid as usize * 8, route);
        let cfg = self.gicd + GICD_ICFGR + (intid / 16) as usize * 4;
        let shift = (intid % 16) * 2 + 1;
        let v = rd32(cfg);
        wr32(
            cfg,
            if edge {
                v | (1 << shift)
            } else {
                v & !(1 << shift)
            },
        );
        wr32(
            self.gicd + GICD_ISENABLER + (intid / 32) as usize * 4,
            1 << (intid % 32),
        );
    }
}

/// Enables the system-register CPU interface on this core: all priorities
/// allowed, group 1 on, EOI both drops priority and deactivates.
pub fn init_cpu_interface() {
    // SAFETY: ICC_* accesses only affect this core's interrupt delivery;
    // the vector table is installed before IRQs are unmasked.
    unsafe {
        asm!(
            "mrs {t}, S3_0_C12_C12_5", // ICC_SRE_EL1
            "orr {t}, {t}, #0x7",      // SRE | DFB | DIB
            "msr S3_0_C12_C12_5, {t}",
            "isb",
            "mov {t}, #0xff",
            "msr S3_0_C4_C6_0, {t}",   // ICC_PMR_EL1
            "msr S3_0_C12_C12_3, xzr", // ICC_BPR1_EL1
            "msr S3_0_C12_C12_4, xzr", // ICC_CTLR_EL1: EOImode 0
            "mov {t}, #1",
            "msr S3_0_C12_C12_7, {t}", // ICC_IGRPEN1_EL1
            "isb",
            t = out(reg) _,
            options(nostack)
        );
    }
}

/// Acknowledges the highest-priority pending interrupt (ICC_IAR1_EL1).
#[inline]
pub fn ack() -> u32 {
    let v: u64;
    // SAFETY: reading IAR1 acknowledges one interrupt; the caller must EOI it.
    unsafe { asm!("mrs {}, S3_0_C12_C12_0", out(reg) v, options(nomem, nostack)) };
    (v & 0x00ff_ffff) as u32
}

/// Signals end of interrupt (ICC_EOIR1_EL1).
#[inline]
pub fn eoi(intid: u32) {
    // SAFETY: completes an interrupt previously returned by `ack`.
    unsafe {
        asm!("msr S3_0_C12_C12_1, {}", "isb", in(reg) u64::from(intid), options(nomem, nostack))
    };
}

/// Sends SGI `intid` (0-15) to the CPUs in `target_list` (bit n = Aff0 = n)
/// of cluster `aff1`/`aff2`/`aff3`, or to all other CPUs if `all_others`.
pub fn send_sgi(intid: u32, aff3: u8, aff2: u8, aff1: u8, target_list: u16, all_others: bool) {
    let mut v = (u64::from(intid & 0xf) << 24) | u64::from(target_list);
    v |= (u64::from(aff1) << 16) | (u64::from(aff2) << 32) | (u64::from(aff3) << 48);
    if all_others {
        v = (u64::from(intid & 0xf) << 24) | (1 << 40);
    }
    // SAFETY: generating an SGI only signals other cores' interrupt state.
    unsafe { asm!("dsb ishst", "msr S3_0_C12_C11_5, {}", "isb", in(reg) v, options(nostack)) };
}
