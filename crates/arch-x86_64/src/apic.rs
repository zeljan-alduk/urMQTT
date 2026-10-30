//! The local APIC: register encodings (pure, host-tested) and, on the
//! kernel target, xAPIC (MMIO) and x2APIC (MSR) register access.

#![allow(unsafe_code)]

// Register offsets from the APIC base (xAPIC). x2APIC addresses the same
// registers at MSR 0x800 + (offset >> 4).
pub const REG_ID: u32 = 0x20;
pub const REG_VERSION: u32 = 0x30;
pub const REG_TPR: u32 = 0x80;
pub const REG_EOI: u32 = 0xb0;
pub const REG_SVR: u32 = 0xf0;
pub const REG_ISR0: u32 = 0x100;
pub const REG_ESR: u32 = 0x280;
pub const REG_ICR_LO: u32 = 0x300;
pub const REG_ICR_HI: u32 = 0x310;
pub const REG_LVT_TIMER: u32 = 0x320;
pub const REG_LVT_LINT0: u32 = 0x350;
pub const REG_LVT_LINT1: u32 = 0x360;
pub const REG_LVT_ERROR: u32 = 0x370;
pub const REG_TIMER_INIT: u32 = 0x380;
pub const REG_TIMER_CUR: u32 = 0x390;
pub const REG_TIMER_DIV: u32 = 0x3e0;

/// IA32_APIC_BASE.
pub const MSR_APIC_BASE: u32 = 0x1b;
/// IA32_TSC_DEADLINE.
pub const MSR_TSC_DEADLINE: u32 = 0x6e0;
const MSR_X2APIC_BASE: u32 = 0x800;

pub const APIC_BASE_EXTD: u64 = 1 << 10;
pub const APIC_BASE_EN: u64 = 1 << 11;

/// The MSR of an x2APIC register given its xAPIC offset.
pub const fn x2apic_msr(offset: u32) -> u32 {
    MSR_X2APIC_BASE + (offset >> 4)
}

/// Physical base address held in IA32_APIC_BASE.
pub const fn apic_base_addr(msr: u64) -> u64 {
    msr & 0x000f_ffff_ffff_f000
}

/// The IA32_APIC_BASE value that enables xAPIC (`x2 = false`) or x2APIC.
pub const fn apic_base_enable(msr: u64, x2: bool) -> u64 {
    if x2 {
        msr | APIC_BASE_EN | APIC_BASE_EXTD
    } else {
        (msr | APIC_BASE_EN) & !APIC_BASE_EXTD
    }
}

/// Spurious-interrupt vector register: software-enable bit 8 and the vector.
pub const fn svr(vector: u32, enable: bool) -> u32 {
    (vector & 0xff) | if enable { 1 << 8 } else { 0 }
}

const LVT_MASKED: u32 = 1 << 16;

/// The LVT timer's mode field (bits 18:17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

/// LVT timer entry.
pub const fn lvt_timer(vector: u32, mode: TimerMode, masked: bool) -> u32 {
    let m = match mode {
        TimerMode::OneShot => 0,
        TimerMode::Periodic => 1,
        TimerMode::TscDeadline => 2,
    };
    (vector & 0xff) | (m << 17) | if masked { LVT_MASKED } else { 0 }
}

/// A fixed-delivery LVT entry for the error source.
pub const fn lvt_fixed(vector: u32, masked: bool) -> u32 {
    (vector & 0xff) | if masked { LVT_MASKED } else { 0 }
}

/// LVT LINT entry delivering an NMI (delivery mode 100b).
pub const fn lvt_nmi(masked: bool) -> u32 {
    (0b100 << 8) | if masked { LVT_MASKED } else { 0 }
}

/// Divide Configuration Register encoding for a power-of-two divisor
/// (1..=128). Any other value maps to divide-by-1.
pub const fn timer_divide(div: u32) -> u32 {
    match div {
        2 => 0b0000,
        4 => 0b0001,
        8 => 0b0010,
        16 => 0b0011,
        32 => 0b1000,
        64 => 0b1001,
        128 => 0b1010,
        _ => 0b1011,
    }
}

/// ICR delivery modes the kernel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Fixed,
    Init,
    Startup,
}

/// Which CPUs an IPI reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The CPU with this APIC ID.
    Cpu(u32),
    SelfOnly,
    AllExcludingSelf,
}

/// The ICR as one 64-bit value in the x2APIC layout (destination in bits
/// 63:32): physical destination mode, level assert, edge triggered.
pub const fn icr(target: Target, vector: u32, delivery: Delivery) -> u64 {
    let mode: u64 = match delivery {
        Delivery::Fixed => 0b000,
        Delivery::Init => 0b101,
        Delivery::Startup => 0b110,
    };
    let (shorthand, dest): (u64, u64) = match target {
        Target::Cpu(id) => (0b00, id as u64),
        Target::SelfOnly => (0b01, 0),
        Target::AllExcludingSelf => (0b11, 0),
    };
    // Bit 14 is level "assert"; INIT de-assert is not used.
    (vector as u64 & 0xff) | (mode << 8) | (1 << 14) | (shorthand << 18) | (dest << 32)
}

/// Splits an x2APIC-layout ICR into the xAPIC (ICR_HI, ICR_LO) pair: the
/// destination moves to bits 31:24 of the high word (8-bit IDs only).
pub const fn icr_xapic(v: u64) -> (u32, u32) {
    (((v >> 32) as u32) << 24, v as u32)
}

/// True if `id` can be addressed by an xAPIC ICR / an MSI (8-bit IDs).
pub const fn xapic_reachable(id: u32) -> bool {
    id <= 0xfe
}

/// The highest vector set in the eight 32-bit in-service (or request)
/// register words `isr[0]` (vectors 0-31) .. `isr[7]` (224-255).
pub fn highest_vector(isr: &[u32; 8]) -> Option<u32> {
    for (i, w) in isr.iter().enumerate().rev() {
        if *w != 0 {
            return Some(i as u32 * 32 + (31 - w.leading_zeros()));
        }
    }
    None
}

/// The APIC ID from the ID register: 8 bits at 31:24 in xAPIC mode.
pub const fn xapic_id(reg: u32) -> u32 {
    reg >> 24
}

#[cfg(target_os = "none")]
pub use hw::*;

#[cfg(target_os = "none")]
mod hw {
    use super::*;
    use crate::prim;
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    const MODE_OFF: u8 = 0;
    const MODE_XAPIC: u8 = 1;
    const MODE_X2APIC: u8 = 2;

    static MODE: AtomicU8 = AtomicU8::new(MODE_OFF);
    static MMIO: AtomicUsize = AtomicUsize::new(0);

    /// Which register interface is in use.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Mode {
        Off,
        XApic,
        X2Apic,
    }

    pub fn mode() -> Mode {
        match MODE.load(Ordering::Relaxed) {
            MODE_XAPIC => Mode::XApic,
            MODE_X2APIC => Mode::X2Apic,
            _ => Mode::Off,
        }
    }

    /// Records the register interface and, for xAPIC, the mapped base. The
    /// per-CPU enable (`enable_this_cpu`) must run on each CPU afterwards.
    pub fn select(x2: bool, mmio_va: usize) {
        MMIO.store(mmio_va, Ordering::Relaxed);
        MODE.store(if x2 { MODE_X2APIC } else { MODE_XAPIC }, Ordering::Release);
    }

    /// Turns this CPU's APIC on in the selected mode (IA32_APIC_BASE).
    pub fn enable_this_cpu() {
        let x2 = mode() == Mode::X2Apic;
        let cur = prim::rdmsr(MSR_APIC_BASE);
        // From x2APIC the only way back is a disable first; entering x2APIC
        // from xAPIC is allowed directly.
        if x2 || cur & APIC_BASE_EXTD == 0 {
            prim::wrmsr(MSR_APIC_BASE, apic_base_enable(cur, x2));
        }
    }

    pub fn read(reg: u32) -> u32 {
        match mode() {
            Mode::X2Apic => prim::rdmsr(x2apic_msr(reg)) as u32,
            Mode::XApic => prim::mmio_read32(MMIO.load(Ordering::Relaxed) + reg as usize),
            Mode::Off => 0,
        }
    }

    pub fn write(reg: u32, val: u32) {
        match mode() {
            Mode::X2Apic => prim::wrmsr(x2apic_msr(reg), val as u64),
            Mode::XApic => prim::mmio_write32(MMIO.load(Ordering::Relaxed) + reg as usize, val),
            Mode::Off => {}
        }
    }

    /// This CPU's APIC ID (32 bits in x2APIC mode, 8 in xAPIC).
    pub fn id() -> u32 {
        match mode() {
            Mode::X2Apic => read(REG_ID),
            _ => xapic_id(read(REG_ID)),
        }
    }

    /// Signals end-of-interrupt for the vector in service.
    pub fn eoi() {
        write(REG_EOI, 0);
    }

    /// The highest vector in service on this CPU.
    pub fn in_service() -> Option<u32> {
        let mut isr = [0u32; 8];
        for (i, w) in isr.iter_mut().enumerate() {
            *w = read(REG_ISR0 + 0x10 * i as u32);
        }
        highest_vector(&isr)
    }

    /// Sends an IPI. Prior stores are visible to the target's handler.
    ///
    /// In xAPIC mode this waits for the previous IPI to be accepted first
    /// and the two halves of the ICR are written with interrupts off, so a
    /// handler that sends an IPI cannot interleave between them.
    pub fn send(target: Target, vector: u32, delivery: Delivery) {
        let v = icr(target, vector, delivery);
        prim::mfence();
        match mode() {
            Mode::X2Apic => prim::wrmsr(x2apic_msr(REG_ICR_LO), v),
            Mode::XApic => {
                let (hi, lo) = icr_xapic(v);
                let flags = prim::save_flags_cli();
                // Delivery status (bit 12) set means the last IPI is pending.
                while read(REG_ICR_LO) & (1 << 12) != 0 {
                    core::hint::spin_loop();
                }
                write(REG_ICR_HI, hi);
                write(REG_ICR_LO, lo);
                prim::restore_flags(flags);
            }
            Mode::Off => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x2apic_msrs() {
        assert_eq!(x2apic_msr(REG_ID), 0x802);
        assert_eq!(x2apic_msr(REG_EOI), 0x80b);
        assert_eq!(x2apic_msr(REG_SVR), 0x80f);
        assert_eq!(x2apic_msr(REG_ICR_LO), 0x830);
        assert_eq!(x2apic_msr(REG_LVT_TIMER), 0x832);
        assert_eq!(x2apic_msr(REG_TIMER_DIV), 0x83e);
    }

    #[test]
    fn apic_base_bits() {
        assert_eq!(apic_base_addr(0xfee0_0900), 0xfee0_0000);
        let x2 = apic_base_enable(0xfee0_0100, true);
        assert_eq!(
            x2 & (APIC_BASE_EN | APIC_BASE_EXTD),
            APIC_BASE_EN | APIC_BASE_EXTD
        );
        assert_eq!(x2 & 0x100, 0x100, "BSP flag kept");
        let x1 = apic_base_enable(x2, false);
        assert_eq!(x1 & APIC_BASE_EXTD, 0);
        assert_ne!(x1 & APIC_BASE_EN, 0);
    }

    #[test]
    fn lvt_encodings() {
        assert_eq!(svr(0xff, true), 0x1ff);
        assert_eq!(svr(0xff, false), 0xff);
        assert_eq!(lvt_timer(0x20, TimerMode::OneShot, false), 0x20);
        assert_eq!(lvt_timer(0x20, TimerMode::Periodic, false), 0x2_0020);
        assert_eq!(lvt_timer(0x20, TimerMode::TscDeadline, false), 0x4_0020);
        assert_eq!(lvt_timer(0x20, TimerMode::TscDeadline, true), 0x5_0020);
        assert_eq!(lvt_fixed(0xfe, true), 0x1_00fe);
        assert_eq!(lvt_nmi(false), 0x400);
        assert_eq!(lvt_nmi(true), 0x1_0400);
    }

    #[test]
    fn divide_register() {
        assert_eq!(timer_divide(1), 0b1011);
        assert_eq!(timer_divide(2), 0);
        assert_eq!(timer_divide(16), 0b0011);
        assert_eq!(timer_divide(128), 0b1010);
        assert_eq!(timer_divide(3), 0b1011);
    }

    #[test]
    fn icr_layouts() {
        let v = icr(Target::Cpu(5), 0xf1, Delivery::Fixed);
        assert_eq!(v, (5u64 << 32) | (1 << 14) | 0xf1);
        let (hi, lo) = icr_xapic(v);
        assert_eq!(hi, 5 << 24);
        assert_eq!(lo, 0x40f1);
        let init = icr(Target::Cpu(1), 0, Delivery::Init);
        assert_eq!((init >> 8) & 7, 0b101);
        let sipi = icr(Target::Cpu(1), 0x08, Delivery::Startup);
        assert_eq!((sipi >> 8) & 7, 0b110);
        assert_eq!(sipi & 0xff, 0x08);
        let all = icr(Target::AllExcludingSelf, 0xf3, Delivery::Fixed);
        assert_eq!((all >> 18) & 3, 0b11);
        assert_eq!(all >> 32, 0);
        assert_eq!((icr(Target::SelfOnly, 1, Delivery::Fixed) >> 18) & 3, 0b01);
        // x2APIC IDs keep all 32 destination bits.
        assert_eq!(
            icr(Target::Cpu(0x1234_5678), 0x20, Delivery::Fixed) >> 32,
            0x1234_5678
        );
        assert!(xapic_reachable(0xfe));
        assert!(!xapic_reachable(0xff));
        assert!(!xapic_reachable(0x100));
    }

    #[test]
    fn highest_in_service_vector() {
        let mut isr = [0u32; 8];
        assert_eq!(highest_vector(&isr), None);
        isr[1] = 1; // vector 32
        assert_eq!(highest_vector(&isr), Some(32));
        isr[7] = 1 << 1; // vector 225
        assert_eq!(highest_vector(&isr), Some(225));
        isr[0] = 0x8000_0000;
        assert_eq!(highest_vector(&isr), Some(225));
        isr[7] = 0;
        isr[1] = 0;
        assert_eq!(highest_vector(&isr), Some(31));
        let mut top = [0u32; 8];
        top[7] = 0x8000_0000;
        assert_eq!(highest_vector(&top), Some(255));
    }

    #[test]
    fn id_registers() {
        assert_eq!(xapic_id(0x0300_0000), 3);
    }
}
