//! Decoding of `ESR_ELx` (Exception Syndrome Register), Arm ARM D24.2.

use core::fmt;

/// Raw syndrome value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Esr(pub u64);

/// Exception class (`ESR_ELx.EC`, bits \[31:26\]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClass {
    Unknown,
    WfiWfe,
    FpSimdAccess,
    BranchTarget,
    IllegalState,
    Svc64,
    Hvc64,
    Smc64,
    SysReg,
    Sve,
    PacFailure,
    InstrAbortLower,
    InstrAbortSame,
    PcAlignment,
    DataAbortLower,
    DataAbortSame,
    SpAlignment,
    FpException,
    SError,
    BreakpointLower,
    BreakpointSame,
    SoftStepLower,
    SoftStepSame,
    WatchpointLower,
    WatchpointSame,
    Brk64,
    Other(u8),
}

impl ExceptionClass {
    pub const fn from_ec(ec: u8) -> Self {
        match ec {
            0x00 => Self::Unknown,
            0x01 => Self::WfiWfe,
            0x07 => Self::FpSimdAccess,
            0x0d => Self::BranchTarget,
            0x0e => Self::IllegalState,
            0x15 => Self::Svc64,
            0x16 => Self::Hvc64,
            0x17 => Self::Smc64,
            0x18 => Self::SysReg,
            0x19 => Self::Sve,
            0x1c => Self::PacFailure,
            0x20 => Self::InstrAbortLower,
            0x21 => Self::InstrAbortSame,
            0x22 => Self::PcAlignment,
            0x24 => Self::DataAbortLower,
            0x25 => Self::DataAbortSame,
            0x26 => Self::SpAlignment,
            0x2c => Self::FpException,
            0x2f => Self::SError,
            0x30 => Self::BreakpointLower,
            0x31 => Self::BreakpointSame,
            0x32 => Self::SoftStepLower,
            0x33 => Self::SoftStepSame,
            0x34 => Self::WatchpointLower,
            0x35 => Self::WatchpointSame,
            0x3c => Self::Brk64,
            other => Self::Other(other),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown reason (undefined instruction)",
            Self::WfiWfe => "trapped WFI/WFE",
            Self::FpSimdAccess => "trapped FP/SIMD access",
            Self::BranchTarget => "branch target exception (BTI)",
            Self::IllegalState => "illegal execution state",
            Self::Svc64 => "SVC",
            Self::Hvc64 => "HVC",
            Self::Smc64 => "SMC",
            Self::SysReg => "trapped system register access",
            Self::Sve => "trapped SVE access",
            Self::PacFailure => "pointer authentication failure",
            Self::InstrAbortLower => "instruction abort (lower EL)",
            Self::InstrAbortSame => "instruction abort (same EL)",
            Self::PcAlignment => "PC alignment fault",
            Self::DataAbortLower => "data abort (lower EL)",
            Self::DataAbortSame => "data abort (same EL)",
            Self::SpAlignment => "SP alignment fault",
            Self::FpException => "floating-point exception",
            Self::SError => "SError",
            Self::BreakpointLower => "breakpoint (lower EL)",
            Self::BreakpointSame => "breakpoint (same EL)",
            Self::SoftStepLower => "software step (lower EL)",
            Self::SoftStepSame => "software step (same EL)",
            Self::WatchpointLower => "watchpoint (lower EL)",
            Self::WatchpointSame => "watchpoint (same EL)",
            Self::Brk64 => "BRK instruction",
            Self::Other(_) => "unrecognised exception class",
        }
    }

    /// Whether ISS carries a data/instruction fault status code.
    pub const fn is_abort(self) -> bool {
        matches!(
            self,
            Self::InstrAbortLower
                | Self::InstrAbortSame
                | Self::DataAbortLower
                | Self::DataAbortSame
        )
    }

    pub const fn is_data_abort(self) -> bool {
        matches!(self, Self::DataAbortLower | Self::DataAbortSame)
    }
}

/// Fault status code (`DFSC`/`IFSC`, ISS bits \[5:0\]) of an abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultStatus {
    AddressSize(u8),
    Translation(u8),
    AccessFlag(u8),
    Permission(u8),
    SyncExternal,
    Alignment,
    TlbConflict,
    Other(u8),
}

impl FaultStatus {
    pub const fn from_fsc(fsc: u8) -> Self {
        let level = fsc & 0b11;
        match fsc & 0b11_1111 {
            0b00_0000..=0b00_0011 => Self::AddressSize(level),
            0b00_0100..=0b00_0111 => Self::Translation(level),
            0b00_1000..=0b00_1011 => Self::AccessFlag(level),
            0b00_1100..=0b00_1111 => Self::Permission(level),
            0b01_0000 => Self::SyncExternal,
            0b10_0001 => Self::Alignment,
            0b11_0000 => Self::TlbConflict,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for FaultStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressSize(l) => write!(f, "address size fault, level {l}"),
            Self::Translation(l) => write!(f, "translation fault, level {l}"),
            Self::AccessFlag(l) => write!(f, "access flag fault, level {l}"),
            Self::Permission(l) => write!(f, "permission fault, level {l}"),
            Self::SyncExternal => write!(f, "synchronous external abort"),
            Self::Alignment => write!(f, "alignment fault"),
            Self::TlbConflict => write!(f, "TLB conflict abort"),
            Self::Other(c) => write!(f, "fault status {c:#04x}"),
        }
    }
}

impl Esr {
    pub const fn ec(self) -> u8 {
        ((self.0 >> 26) & 0x3f) as u8
    }

    pub const fn class(self) -> ExceptionClass {
        ExceptionClass::from_ec(self.ec())
    }

    /// Instruction length: true for a 32-bit instruction.
    pub const fn il(self) -> bool {
        self.0 & (1 << 25) != 0
    }

    pub const fn iss(self) -> u32 {
        (self.0 & 0x01ff_ffff) as u32
    }

    /// Fault status for aborts, `None` for other classes.
    pub const fn fault_status(self) -> Option<FaultStatus> {
        if self.class().is_abort() {
            Some(FaultStatus::from_fsc((self.iss() & 0x3f) as u8))
        } else {
            None
        }
    }

    /// `WnR` for data aborts: true if the access was a write.
    pub const fn is_write(self) -> Option<bool> {
        if self.class().is_data_abort() {
            Some(self.iss() & (1 << 6) != 0)
        } else {
            None
        }
    }

    /// Immediate of a BRK/SVC/HVC/SMC instruction.
    pub const fn imm16(self) -> Option<u16> {
        match self.class() {
            ExceptionClass::Brk64
            | ExceptionClass::Svc64
            | ExceptionClass::Hvc64
            | ExceptionClass::Smc64 => Some((self.iss() & 0xffff) as u16),
            _ => None,
        }
    }
}

impl fmt::Display for Esr {
    /// One-line human-readable decoding, e.g.
    /// `EC=0x25 data abort (same EL), read, translation fault, level 0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = self.class();
        write!(f, "EC={:#04x} {}", self.ec(), class.name())?;
        if let Some(w) = self.is_write() {
            f.write_str(if w { ", write" } else { ", read" })?;
        }
        if let Some(fs) = self.fault_status() {
            write!(f, ", {fs}")?;
        }
        if let Some(imm) = self.imm16() {
            write!(f, ", imm={imm:#06x}")?;
        }
        write!(f, " (ISS={:#09x}, IL={})", self.iss(), u8::from(self.il()))
    }
}

/// The 16 entries of the EL1 vector table, in table order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Vector {
    CurrentSp0Sync = 0,
    CurrentSp0Irq,
    CurrentSp0Fiq,
    CurrentSp0SError,
    CurrentSpxSync,
    CurrentSpxIrq,
    CurrentSpxFiq,
    CurrentSpxSError,
    Lower64Sync,
    Lower64Irq,
    Lower64Fiq,
    Lower64SError,
    Lower32Sync,
    Lower32Irq,
    Lower32Fiq,
    Lower32SError,
}

impl Vector {
    pub const fn from_index(i: u64) -> Option<Self> {
        Some(match i {
            0 => Self::CurrentSp0Sync,
            1 => Self::CurrentSp0Irq,
            2 => Self::CurrentSp0Fiq,
            3 => Self::CurrentSp0SError,
            4 => Self::CurrentSpxSync,
            5 => Self::CurrentSpxIrq,
            6 => Self::CurrentSpxFiq,
            7 => Self::CurrentSpxSError,
            8 => Self::Lower64Sync,
            9 => Self::Lower64Irq,
            10 => Self::Lower64Fiq,
            11 => Self::Lower64SError,
            12 => Self::Lower32Sync,
            13 => Self::Lower32Irq,
            14 => Self::Lower32Fiq,
            15 => Self::Lower32SError,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::CurrentSp0Sync => "synchronous, current EL, SP0",
            Self::CurrentSp0Irq => "IRQ, current EL, SP0",
            Self::CurrentSp0Fiq => "FIQ, current EL, SP0",
            Self::CurrentSp0SError => "SError, current EL, SP0",
            Self::CurrentSpxSync => "synchronous, current EL, SPx",
            Self::CurrentSpxIrq => "IRQ, current EL, SPx",
            Self::CurrentSpxFiq => "FIQ, current EL, SPx",
            Self::CurrentSpxSError => "SError, current EL, SPx",
            Self::Lower64Sync => "synchronous, lower EL, AArch64",
            Self::Lower64Irq => "IRQ, lower EL, AArch64",
            Self::Lower64Fiq => "FIQ, lower EL, AArch64",
            Self::Lower64SError => "SError, lower EL, AArch64",
            Self::Lower32Sync => "synchronous, lower EL, AArch32",
            Self::Lower32Irq => "IRQ, lower EL, AArch32",
            Self::Lower32Fiq => "FIQ, lower EL, AArch32",
            Self::Lower32SError => "SError, lower EL, AArch32",
        }
    }

    /// Whether the syndrome registers (ESR/FAR) describe this exception.
    pub const fn is_synchronous(self) -> bool {
        matches!(
            self,
            Self::CurrentSp0Sync | Self::CurrentSpxSync | Self::Lower64Sync | Self::Lower32Sync
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_abort_translation_fault_read() {
        // EC=0x25, IL=1, DFSC=0b000100 (translation, level 0), WnR=0.
        let esr = Esr(0x9600_0004);
        assert_eq!(esr.class(), ExceptionClass::DataAbortSame);
        assert!(esr.il());
        assert_eq!(esr.fault_status(), Some(FaultStatus::Translation(0)));
        assert_eq!(esr.is_write(), Some(false));
        let s = esr.to_string();
        assert!(s.starts_with("EC=0x25 data abort (same EL), read, translation fault, level 0"));
    }

    #[test]
    fn data_abort_permission_fault_write_level3() {
        let esr = Esr(0x9600_004f);
        assert_eq!(esr.fault_status(), Some(FaultStatus::Permission(3)));
        assert_eq!(esr.is_write(), Some(true));
    }

    #[test]
    fn instruction_abort_has_fault_status_but_no_wnr() {
        let esr = Esr(0x8600_000f);
        assert_eq!(esr.class(), ExceptionClass::InstrAbortSame);
        assert_eq!(esr.fault_status(), Some(FaultStatus::Permission(3)));
        assert_eq!(esr.is_write(), None);
    }

    #[test]
    fn brk_immediate() {
        let esr = Esr(0xf200_1234);
        assert_eq!(esr.class(), ExceptionClass::Brk64);
        assert_eq!(esr.imm16(), Some(0x1234));
        assert!(esr.to_string().contains("imm=0x1234"));
    }

    #[test]
    fn undefined_instruction() {
        let esr = Esr(0x0200_0000);
        assert_eq!(esr.class(), ExceptionClass::Unknown);
        assert_eq!(esr.fault_status(), None);
    }

    #[test]
    fn unknown_ec_is_preserved() {
        assert_eq!(Esr(0x3f << 26).class(), ExceptionClass::Other(0x3f));
    }

    #[test]
    fn misc_fault_codes() {
        assert_eq!(FaultStatus::from_fsc(0b10_0001), FaultStatus::Alignment);
        assert_eq!(FaultStatus::from_fsc(0b00_1001), FaultStatus::AccessFlag(1));
        assert_eq!(FaultStatus::from_fsc(0b01_0000), FaultStatus::SyncExternal);
        assert_eq!(FaultStatus::from_fsc(0b11_1111), FaultStatus::Other(0x3f));
    }

    #[test]
    fn vectors_roundtrip() {
        for i in 0..16 {
            let v = Vector::from_index(i).unwrap();
            assert_eq!(v as u64, i);
        }
        assert_eq!(Vector::from_index(16), None);
        assert!(Vector::CurrentSpxSync.is_synchronous());
        assert!(!Vector::CurrentSpxIrq.is_synchronous());
    }
}
