//! Exception entry, the trap frame and the decoded fault reports (X2).
//!
//! The decoding is pure and tested on the host. The entry stubs, the IDT
//! and the test faults are bare metal only (`isr.rs`, `idt.rs`).

use core::fmt;

/// IDT vectors the kernel names. Every architectural exception has a
/// variant; the vectors from 32 up (interrupts) are [`Vector::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Vector {
    DivideError = 0,
    Debug = 1,
    Nmi = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRange = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    InvalidTss = 10,
    SegmentNotPresent = 11,
    StackFault = 12,
    GeneralProtection = 13,
    PageFault = 14,
    X87Fault = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SimdFault = 19,
    Virtualization = 20,
    ControlProtection = 21,
    Other = 255,
}

impl Vector {
    pub const fn from_index(i: u64) -> Option<Self> {
        Some(match i {
            0 => Self::DivideError,
            1 => Self::Debug,
            2 => Self::Nmi,
            3 => Self::Breakpoint,
            4 => Self::Overflow,
            5 => Self::BoundRange,
            6 => Self::InvalidOpcode,
            7 => Self::DeviceNotAvailable,
            8 => Self::DoubleFault,
            10 => Self::InvalidTss,
            11 => Self::SegmentNotPresent,
            12 => Self::StackFault,
            13 => Self::GeneralProtection,
            14 => Self::PageFault,
            16 => Self::X87Fault,
            17 => Self::AlignmentCheck,
            18 => Self::MachineCheck,
            19 => Self::SimdFault,
            20 => Self::Virtualization,
            21 => Self::ControlProtection,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DivideError => "#DE divide error",
            Self::Debug => "#DB debug",
            Self::Nmi => "NMI non-maskable interrupt",
            Self::Breakpoint => "#BP breakpoint",
            Self::Overflow => "#OF overflow",
            Self::BoundRange => "#BR bound range exceeded",
            Self::InvalidOpcode => "#UD invalid opcode",
            Self::DeviceNotAvailable => "#NM device not available",
            Self::DoubleFault => "#DF double fault",
            Self::InvalidTss => "#TS invalid TSS",
            Self::SegmentNotPresent => "#NP segment not present",
            Self::StackFault => "#SS stack-segment fault",
            Self::GeneralProtection => "#GP general protection",
            Self::PageFault => "#PF page fault",
            Self::X87Fault => "#MF x87 floating-point exception",
            Self::AlignmentCheck => "#AC alignment check",
            Self::MachineCheck => "#MC machine check",
            Self::SimdFault => "#XM SIMD floating-point exception",
            Self::Virtualization => "#VE virtualization exception",
            Self::ControlProtection => "#CP control protection",
            Self::Other => "interrupt or exception",
        }
    }
}

/// The names of the general-purpose registers in [`TrapFrame::gpr`] order.
pub const GPR_NAMES: [&str; 15] = [
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
    "R15",
];

/// Register state at the moment of the exception: what the entry stub
/// pushed (lowest address first) followed by the CPU's own frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TrapFrame {
    pub gpr: [u64; 15],
    pub cr2: u64,
    pub vector: u64,
    /// The error code, or 0 for exceptions that push none.
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// How the kernel's handler treats an exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Irq,
    ResumableBreakpoint,
    Fatal,
}

/// Register dump of a [`TrapFrame`].
pub struct Registers<'a>(&'a TrapFrame);

impl fmt::Display for Registers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        writeln!(
            f,
            "    RIP={:#018x} RSP={:#018x} RFLAGS={:#010x} CR2={:#018x} ERR={:#x}",
            t.rip, t.rsp, t.rflags, t.cr2, t.error_code
        )?;
        // The frame sits on the stack the exception arrived on. An IST stack
        // shows that #DF, NMI, #MC and #PF do not depend on the stack that
        // was in use (a smashed or overflowed one).
        let at = core::ptr::from_ref(t) as u64;
        #[cfg(target_os = "none")]
        let ist = crate::gdt::which_ist(at);
        #[cfg(not(target_os = "none"))]
        let ist: Option<u8> = None;
        write!(
            f,
            "    CS={:#06x} SS={:#06x} vector={}",
            t.cs, t.ss, t.vector
        )?;
        match ist {
            Some(slot) => writeln!(f, " frame at {at:#x} on IST stack {slot}")?,
            None => writeln!(f, " frame at {at:#x} on the interrupted stack")?,
        }
        for (row, regs) in t.gpr.chunks(4).enumerate() {
            write!(f, "   ")?;
            for (i, v) in regs.iter().enumerate() {
                let name = GPR_NAMES.get(row * 4 + i).copied().unwrap_or("?");
                write!(f, " {name:<3}={v:#018x}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl TrapFrame {
    pub fn classify(&self, _vector: Vector) -> Event {
        match self.vector {
            3 => Event::ResumableBreakpoint,
            v if v >= 32 => Event::Irq,
            _ => Event::Fatal,
        }
    }

    pub fn pc(&self) -> u64 {
        self.rip
    }

    /// Nothing to do: `int3` is a trap, so the saved RIP already points
    /// past it.
    pub fn skip_breakpoint(&mut self) {}

    pub fn fault_address(&self, vector: Vector) -> Option<u64> {
        (vector == Vector::PageFault).then_some(self.cr2)
    }

    /// A decoded description of the exception, if it has one.
    pub fn cause(&self, vector: Vector) -> Option<Cause> {
        matches!(
            vector,
            Vector::PageFault
                | Vector::GeneralProtection
                | Vector::InvalidTss
                | Vector::SegmentNotPresent
                | Vector::StackFault
                | Vector::DoubleFault
                | Vector::AlignmentCheck
        )
        .then_some(Cause {
            vector,
            code: self.error_code,
        })
    }

    pub fn registers(&self) -> Registers<'_> {
        Registers(self)
    }
}

/// The error code of an exception, decoded by the exception's meaning.
pub struct Cause {
    pub vector: Vector,
    pub code: u64,
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.code;
        match self.vector {
            Vector::PageFault => {
                write!(f, "page fault error code {c:#x}: ")?;
                write_page_fault_bits(f, c)
            }
            Vector::InvalidTss
            | Vector::SegmentNotPresent
            | Vector::StackFault
            | Vector::GeneralProtection => {
                write!(f, "error code {c:#x}: ")?;
                write_selector_error(f, c)
            }
            Vector::DoubleFault => write!(f, "double fault error code {c:#x} (always 0)"),
            _ => write!(f, "error code {c:#x}"),
        }
    }
}

/// #PF error code bits (SDM 4.7): P, W/R, U/S, RSVD, I/D, PK, SS, SGX.
fn write_page_fault_bits(f: &mut fmt::Formatter<'_>, c: u64) -> fmt::Result {
    f.write_str(if c & 1 != 0 {
        "protection violation"
    } else {
        "page not present"
    })?;
    f.write_str(if c & 2 != 0 { ", write" } else { ", read" })?;
    f.write_str(if c & 4 != 0 {
        ", user mode"
    } else {
        ", supervisor mode"
    })?;
    for (bit, what) in [
        (3, ", reserved bit set in a page-table entry"),
        (4, ", instruction fetch"),
        (5, ", protection-key violation"),
        (6, ", shadow-stack access"),
        (15, ", SGX violation"),
    ] {
        if c & (1 << bit) != 0 {
            f.write_str(what)?;
        }
    }
    Ok(())
}

/// The selector error code of #GP, #TS, #NP and #SS: zero means no
/// selector was involved (a privileged instruction, a non-canonical
/// address, a misaligned SSE operand ...).
fn write_selector_error(f: &mut fmt::Formatter<'_>, c: u64) -> fmt::Result {
    if c == 0 {
        return f.write_str("no selector (non-canonical address or privileged operation)");
    }
    let table = match (c >> 1) & 3 {
        0 => "GDT",
        1 | 3 => "IDT",
        _ => "LDT",
    };
    write!(f, "selector index {} in the {table}", (c >> 3) & 0x1fff)?;
    if c & 1 != 0 {
        f.write_str(", external event")?;
    }
    Ok(())
}

pub type Handler = fn(&mut TrapFrame, Vector);

/// The opcode the test fault writes (aarch64 `ret`); on x86 `ret` is 0xc3.
pub const RET_INSN: u32 = 0xc3;

#[cfg(target_os = "none")]
pub use crate::isr::{
    breakpoint, double_fault, general_protection, install, set_handler, undefined_instruction,
};

#[cfg(target_os = "none")]
pub fn forged_return() -> bool {
    unimplemented_until!("X3 (CET shadow stacks)")
}

#[cfg(target_os = "none")]
pub fn branch_to_non_landing_pad() -> bool {
    unimplemented_until!("X3 (CET IBT)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(vector: u64, error_code: u64) -> TrapFrame {
        TrapFrame {
            gpr: core::array::from_fn(|i| 0x1111_1111 * (i as u64 + 1)),
            cr2: 0xdead_0000,
            vector,
            error_code,
            rip: 0xffff_ffff_8000_1234,
            cs: 8,
            rflags: 0x202,
            rsp: 0xffff_ffff_8010_0000,
            ss: 0x10,
        }
    }

    #[test]
    fn layout_matches_the_entry_stub() {
        // 15 pushed GPRs, CR2, vector, error code, then the CPU's frame.
        assert_eq!(core::mem::size_of::<TrapFrame>(), 23 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, cr2), 15 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, vector), 16 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, rip), 18 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, ss), 22 * 8);
    }

    #[test]
    fn vectors_round_trip_and_have_names() {
        for i in 0..32 {
            if let Some(v) = Vector::from_index(i) {
                assert_eq!(v as u64, i);
                assert!(v.name().starts_with('#') || v == Vector::Nmi);
            }
        }
        assert_eq!(Vector::from_index(9), None, "reserved");
        assert_eq!(Vector::from_index(32), None);
    }

    #[test]
    fn classifies_by_vector() {
        let f = frame(3, 0);
        assert_eq!(f.classify(Vector::Breakpoint), Event::ResumableBreakpoint);
        assert_eq!(frame(14, 0).classify(Vector::PageFault), Event::Fatal);
        assert_eq!(frame(0x30, 0).classify(Vector::Other), Event::Irq);
    }

    #[test]
    fn page_fault_bits_are_decoded() {
        let f = frame(14, 0);
        let show = |code| {
            std::format!(
                "{}",
                Cause {
                    vector: Vector::PageFault,
                    code
                }
            )
        };
        assert_eq!(
            show(0),
            "page fault error code 0x0: page not present, read, supervisor mode"
        );
        assert_eq!(
            show(0b10011),
            "page fault error code 0x13: protection violation, write, supervisor mode, instruction fetch"
        );
        assert!(show(0b1_0100).contains("user mode"));
        assert!(show(1 << 3).contains("reserved bit"));
        assert!(show(1 << 5).contains("protection-key"));
        assert!(show(1 << 6).contains("shadow-stack"));
        assert_eq!(f.fault_address(Vector::PageFault), Some(0xdead_0000));
        assert_eq!(f.fault_address(Vector::InvalidOpcode), None);
    }

    #[test]
    fn selector_errors_are_decoded() {
        let show = |code| {
            std::format!(
                "{}",
                Cause {
                    vector: Vector::GeneralProtection,
                    code
                }
            )
        };
        assert!(show(0).contains("no selector (non-canonical"));
        // Index 3 in the IDT, external.
        assert_eq!(
            show((3 << 3) | (1 << 1) | 1),
            "error code 0x1b: selector index 3 in the IDT, external event"
        );
        assert!(show(0x28).contains("index 5 in the GDT"));
    }

    #[test]
    fn only_vectors_with_codes_have_a_cause() {
        let f = frame(6, 0);
        assert!(f.cause(Vector::InvalidOpcode).is_none());
        assert!(f.cause(Vector::GeneralProtection).is_some());
    }

    #[test]
    fn register_dump_names_every_register() {
        let dump = std::format!("{}", frame(13, 0).registers());
        for name in [
            "RIP=", "RSP=", "RFLAGS=", "CR2=", "RAX=", "RBX=", "RSI=", "RDI=", "RBP=", "R8 =",
            "R15=",
        ] {
            assert!(dump.contains(name), "{name} missing from:\n{dump}");
        }
        assert!(dump.contains("0xffffffff80001234"));
    }
}
