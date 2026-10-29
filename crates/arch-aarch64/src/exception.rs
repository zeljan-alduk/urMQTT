//! EL1 exception vector table and trap frame.
//!
//! Every vector saves the full general-purpose and FP/SIMD state (ADR-003),
//! calls the registered Rust handler and restores the state with `eret`.
//! Under VHE (entry at EL2) the `*_el1` mnemonics transparently address the
//! EL2 registers, so the same code works at both levels.

#![allow(unsafe_code)]

use core::mem::offset_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::esr::{Esr, ExceptionClass, Vector};

/// Register state at the moment of the exception.
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
    _pad: u64,
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

const FRAME_SIZE: usize = 816;
const _: () = {
    assert!(core::mem::size_of::<TrapFrame>() == FRAME_SIZE);
    assert!(offset_of!(TrapFrame, elr) == 248);
    assert!(offset_of!(TrapFrame, esr) == 264);
    assert!(offset_of!(TrapFrame, q) == 288);
    assert!(offset_of!(TrapFrame, fpcr) == 800);
};

impl TrapFrame {
    pub fn esr(&self) -> Esr {
        Esr(self.esr)
    }

    /// What the kernel must do with this exception.
    pub fn classify(&self, vector: Vector) -> Event {
        if matches!(vector, Vector::CurrentSp0Irq | Vector::CurrentSpxIrq) {
            return Event::Irq;
        }
        let esr = self.esr();
        if vector.is_synchronous()
            && esr.class() == ExceptionClass::Brk64
            && esr.imm16() == Some(crate::faults::BRK_RESUME)
        {
            return Event::ResumableBreakpoint;
        }
        Event::Fatal
    }

    /// Address of the instruction that trapped (or is resumed).
    pub fn pc(&self) -> u64 {
        self.elr
    }

    /// Resumes after the breakpoint instead of re-executing it.
    pub fn skip_breakpoint(&mut self) {
        self.elr += crate::faults::BRK_LEN;
    }

    /// The decoded cause of a synchronous exception, printable.
    pub fn cause(&self, vector: Vector) -> Option<Esr> {
        vector.is_synchronous().then(|| self.esr())
    }

    /// The faulting data or instruction address of an abort.
    pub fn fault_address(&self, vector: Vector) -> Option<u64> {
        (vector.is_synchronous() && self.esr().class().is_abort()).then_some(self.far)
    }

    /// The syndrome and general-purpose registers, printable (one line of
    /// syndrome, then four registers per line).
    pub fn registers(&self) -> Registers<'_> {
        Registers(self)
    }
}

/// How the kernel's handler treats an exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// An interrupt: dispatch it and return.
    Irq,
    /// The test-mode breakpoint: report, skip it and return.
    ResumableBreakpoint,
    /// Anything else: report and stop.
    Fatal,
}

/// Register dump of a [`TrapFrame`].
pub struct Registers<'a>(&'a TrapFrame);

impl core::fmt::Display for Registers<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let t = self.0;
        writeln!(
            f,
            "    ESR={:#018x} ELR={:#018x} FAR={:#018x} SPSR={:#010x}",
            t.esr, t.elr, t.far, t.spsr
        )?;
        for (i, quad) in t.x.chunks(4).enumerate() {
            f.write_str("   ")?;
            for (j, r) in quad.iter().enumerate() {
                write!(f, " x{:<2}={r:#018x}", i * 4 + j)?;
            }
            f.write_str("\n")?;
        }
        Ok(())
    }
}

/// Signature of the kernel's exception handler. Returning resumes at
/// `frame.elr` with the (possibly modified) frame.
pub type Handler = fn(&mut TrapFrame, Vector);

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Registers the handler for all vectors.
pub fn set_handler(h: Handler) {
    // Release: the handler is a plain function pointer; Release pairs with
    // the Acquire in the entry path so a core that observes it can call it.
    HANDLER.store(h as usize, Ordering::Release);
}

/// Points `VBAR_EL1` at the vector table on this core.
pub fn install() {
    // SAFETY: the table is 2 KiB aligned, lives in kernel text and every
    // entry ends in a valid handler path.
    unsafe {
        crate::regs::set_vbar_el1(core::ptr::addr_of!(urmqtt_vectors) as u64);
    }
    crate::cpu::isb();
}

unsafe extern "C" {
    static urmqtt_vectors: u8;
}

#[unsafe(no_mangle)]
extern "C" fn urmqtt_arch_exception_entry(frame: &mut TrapFrame, index: u64) {
    // Acquire: pairs with the Release in `set_handler`.
    let raw = HANDLER.load(Ordering::Acquire);
    let vector = Vector::from_index(index);
    match (raw, vector) {
        (0, _) | (_, None) => crate::cpu::halt(),
        (raw, Some(v)) => {
            // SAFETY: `raw` was produced from a `Handler` in `set_handler`
            // and function pointers round-trip through usize on AArch64.
            let h: Handler = unsafe { core::mem::transmute::<usize, Handler>(raw) };
            h(frame, v);
        }
    }
}

macro_rules! vector_entry {
    ($idx:literal) => {
        concat!(
            ".balign 0x80\n",
            "sub sp, sp, #816\n",
            "stp x0, x1, [sp, #0]\n",
            "mov x0, #",
            $idx,
            "\n",
            "b urmqtt_exception_common\n",
        )
    };
}

core::arch::global_asm!(
    ".section .text.vectors, \"ax\"",
    ".balign 0x800",
    ".global urmqtt_vectors",
    "urmqtt_vectors:",
    vector_entry!("0"),
    vector_entry!("1"),
    vector_entry!("2"),
    vector_entry!("3"),
    vector_entry!("4"),
    vector_entry!("5"),
    vector_entry!("6"),
    vector_entry!("7"),
    vector_entry!("8"),
    vector_entry!("9"),
    vector_entry!("10"),
    vector_entry!("11"),
    vector_entry!("12"),
    vector_entry!("13"),
    vector_entry!("14"),
    vector_entry!("15"),
    "",
    "urmqtt_exception_common:",
    "stp x2, x3, [sp, #16]",
    "stp x4, x5, [sp, #32]",
    "stp x6, x7, [sp, #48]",
    "stp x8, x9, [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30, [sp, #240]",
    "mrs x1, elr_el1",
    "mrs x2, spsr_el1",
    "stp x1, x2, [sp, #248]",
    "mrs x3, esr_el1",
    "mrs x4, far_el1",
    "stp x3, x4, [sp, #264]",
    "add x5, sp, #288",
    "stp q0, q1, [x5, #0]",
    "stp q2, q3, [x5, #32]",
    "stp q4, q5, [x5, #64]",
    "stp q6, q7, [x5, #96]",
    "stp q8, q9, [x5, #128]",
    "stp q10, q11, [x5, #160]",
    "stp q12, q13, [x5, #192]",
    "stp q14, q15, [x5, #224]",
    "stp q16, q17, [x5, #256]",
    "stp q18, q19, [x5, #288]",
    "stp q20, q21, [x5, #320]",
    "stp q22, q23, [x5, #352]",
    "stp q24, q25, [x5, #384]",
    "stp q26, q27, [x5, #416]",
    "stp q28, q29, [x5, #448]",
    "stp q30, q31, [x5, #480]",
    "mrs x6, fpcr",
    "mrs x7, fpsr",
    "add x5, x5, #512",
    "stp x6, x7, [x5]",
    "mov x1, x0",
    "mov x0, sp",
    "bl urmqtt_arch_exception_entry",
    "add x5, sp, #288",
    "ldp q0, q1, [x5, #0]",
    "ldp q2, q3, [x5, #32]",
    "ldp q4, q5, [x5, #64]",
    "ldp q6, q7, [x5, #96]",
    "ldp q8, q9, [x5, #128]",
    "ldp q10, q11, [x5, #160]",
    "ldp q12, q13, [x5, #192]",
    "ldp q14, q15, [x5, #224]",
    "ldp q16, q17, [x5, #256]",
    "ldp q18, q19, [x5, #288]",
    "ldp q20, q21, [x5, #320]",
    "ldp q22, q23, [x5, #352]",
    "ldp q24, q25, [x5, #384]",
    "ldp q26, q27, [x5, #416]",
    "ldp q28, q29, [x5, #448]",
    "ldp q30, q31, [x5, #480]",
    "add x5, x5, #512",
    "ldp x6, x7, [x5]",
    "msr fpcr, x6",
    "msr fpsr, x7",
    "ldp x1, x2, [sp, #248]",
    "msr elr_el1, x1",
    "msr spsr_el1, x2",
    "ldp x0, x1, [sp, #0]",
    "ldp x2, x3, [sp, #16]",
    "ldp x4, x5, [sp, #32]",
    "ldp x6, x7, [sp, #48]",
    "ldp x8, x9, [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",
    "add sp, sp, #816",
    "eret",
    ".text",
);
