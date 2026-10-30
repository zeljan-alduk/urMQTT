//! Exception entry and the trap frame (X2). X1: the types and the
//! operations the kernel performs on them.

/// IDT vectors the kernel names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Vector {
    DivideError = 0,
    Breakpoint = 3,
    InvalidOpcode = 6,
    DoubleFault = 8,
    GeneralProtection = 13,
    PageFault = 14,
    MachineCheck = 18,
    Other = 255,
}

impl Vector {
    pub const fn from_index(i: u64) -> Option<Self> {
        Some(match i {
            0 => Self::DivideError,
            3 => Self::Breakpoint,
            6 => Self::InvalidOpcode,
            8 => Self::DoubleFault,
            13 => Self::GeneralProtection,
            14 => Self::PageFault,
            18 => Self::MachineCheck,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DivideError => "#DE divide error",
            Self::Breakpoint => "#BP breakpoint",
            Self::InvalidOpcode => "#UD invalid opcode",
            Self::DoubleFault => "#DF double fault",
            Self::GeneralProtection => "#GP general protection",
            Self::PageFault => "#PF page fault",
            Self::MachineCheck => "#MC machine check",
            Self::Other => "interrupt or exception",
        }
    }
}

/// Register state at the moment of the exception.
#[repr(C)]
pub struct TrapFrame {
    pub gpr: [u64; 16],
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub cr2: u64,
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

impl core::fmt::Display for Registers<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let t = self.0;
        writeln!(
            f,
            "    RIP={:#018x} RSP={:#018x} RFLAGS={:#010x} CR2={:#018x} ERR={:#x}",
            t.rip, t.rsp, t.rflags, t.cr2, t.error_code
        )
    }
}

impl TrapFrame {
    pub fn classify(&self, _vector: Vector) -> Event {
        unimplemented_until!("X2 (exceptions)")
    }

    pub fn pc(&self) -> u64 {
        self.rip
    }

    pub fn skip_breakpoint(&mut self) {
        // `int3` is one byte.
        self.rip += 1;
    }

    pub fn fault_address(&self, vector: Vector) -> Option<u64> {
        (vector == Vector::PageFault).then_some(self.cr2)
    }

    /// A decoded description of the exception, if it has one.
    pub fn cause(&self, vector: Vector) -> Option<Cause> {
        matches!(vector, Vector::PageFault | Vector::GeneralProtection)
            .then_some(Cause(self.error_code))
    }

    pub fn registers(&self) -> Registers<'_> {
        Registers(self)
    }
}

/// The error code of a #PF or #GP.
pub struct Cause(pub u64);

impl core::fmt::Display for Cause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error code {:#x}", self.0)
    }
}

pub type Handler = fn(&mut TrapFrame, Vector);

#[cfg(target_os = "none")]
pub fn set_handler(_h: Handler) {
    unimplemented_until!("X2 (exceptions)")
}

/// Loads the IDT on this core.
#[cfg(target_os = "none")]
pub fn install() {
    unimplemented_until!("X2 (exceptions)")
}

/// The opcode the test fault writes (aarch64 `ret`); on x86 `ret` is 0xc3.
pub const RET_INSN: u32 = 0xc3;

#[cfg(target_os = "none")]
pub fn breakpoint() {
    unimplemented_until!("X2 (exceptions)")
}

#[cfg(target_os = "none")]
pub fn undefined_instruction() {
    unimplemented_until!("X2 (exceptions)")
}

#[cfg(target_os = "none")]
pub fn forged_return() -> bool {
    unimplemented_until!("X3 (CET shadow stacks)")
}

#[cfg(target_os = "none")]
pub fn branch_to_non_landing_pad() -> bool {
    unimplemented_until!("X3 (CET IBT)")
}
