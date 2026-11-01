//! Running an unprivileged program at EL0 (ADR-210): entering it, taking
//! its system calls, interrupts and faults, and leaving it.
//!
//! The kernel calls [`enter`] like a function. The worker runs until it
//! executes the exit system call, faults, or the kernel gives up on it
//! ([`leave`], from the exception handler); every one of these ends with an
//! ordinary return of [`enter`], because the kernel's callee-saved registers
//! and stack pointer were saved at entry and are restored by the long jump
//! in [`leave`]. System calls and interrupts that do not end the call are
//! handled inside the exception handler and resumed with `eret`: the vector
//! code saves and restores the whole register file, FP/SIMD included.
//!
//! Hardware state while the worker runs: `TTBR0_EL1` holds the worker's
//! tables and `TCR_EL1.EPD0` is clear; the moment [`enter`] returns, `EPD0`
//! is set again and the lower half is unreachable (ADR-173). `PAN` is on
//! for the kernel from the first call on, so an access to a user page by
//! kernel code faults even while the tables are installed. The kernel
//! reaches the worker's memory only through its own alias of the frames.

#![allow(unsafe_code)]

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::esr::{Esr, ExceptionClass, Vector};
use crate::exception::TrapFrame;
use crate::{cpu, regs};

const TCR_EPD0: u64 = 1 << 7;
/// The worker's ASID. Its pages are non-global, tagged with it.
const ASID: u64 = 1;
const SCTLR_SA0: u64 = 1 << 4;
const SCTLR_UMA: u64 = 1 << 9;
const SCTLR_DZE: u64 = 1 << 14;
const SCTLR_UCT: u64 = 1 << 15;
const SCTLR_NTWI: u64 = 1 << 16;
const SCTLR_NTWE: u64 = 1 << 18;
const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_E0E: u64 = 1 << 24;
const SCTLR_UCI: u64 = 1 << 26;
const SCTLR_BT0: u64 = 1 << 35;
const SCTLR_BT1: u64 = 1 << 36;

/// Why a call into the worker ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The worker executed the exit system call with this code.
    Done(u64),
    /// The worker took an exception the kernel does not serve.
    Fault(FaultInfo),
    /// The kernel ended the call because its time budget ran out.
    Timeout,
}

/// What the hardware reported about a fault of the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultInfo {
    pub esr: u64,
    pub far: u64,
    pub pc: u64,
}

impl fmt::Display for FaultInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at pc {:#x}, address {:#x}",
            Esr(self.esr),
            self.pc,
            self.far
        )
    }
}

/// What an exception taken from the worker is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserEvent {
    /// A system call: number and the six argument registers.
    Syscall { nr: u64, args: [u64; 6] },
    /// An interrupt: serve it and resume the worker.
    Irq,
    /// Anything else.
    Fault(FaultInfo),
}

/// Registers saved at entry, restored by the long jump in `leave`.
#[repr(C)]
struct Resume {
    /// x19..x30.
    x: [u64; 12],
    sp: u64,
    /// d8..d15.
    d: [u64; 8],
    daif: u64,
    fpcr: u64,
    /// `SPSel` of the caller, and `SP_EL1` at entry.
    spsel: u64,
    sp_el1: u64,
}

struct ResumeCell(core::cell::UnsafeCell<Resume>);
// SAFETY: written by `enter` and read by `leave`, both on the one core that
// runs the single call at a time (the kernel serialises calls).
unsafe impl Sync for ResumeCell {}

static RESUME: ResumeCell = ResumeCell(core::cell::UnsafeCell::new(Resume {
    x: [0; 12],
    sp: 0,
    d: [0; 8],
    daif: 0,
    fpcr: 0,
    spsel: 0,
    sp_el1: 0,
}));
static RUNNING: AtomicBool = AtomicBool::new(false);
/// The reason the call ended, set by `leave`, taken by `enter`.
static LAST: ExitCell = ExitCell(core::cell::UnsafeCell::new(Exit::Timeout));

struct ExitCell(core::cell::UnsafeCell<Exit>);
// SAFETY: as for `ResumeCell`.
unsafe impl Sync for ExitCell {}

unsafe extern "C" {
    fn urmqtt_user_enter(pc: u64, sp: u64, resume: *mut Resume) -> u64;
    fn urmqtt_user_leave(resume: *const Resume, code: u64) -> !;
}

/// Whether the current call is executing the worker (the exception handler
/// uses this to tell the worker's exceptions from the kernel's own).
pub fn running() -> bool {
    // Relaxed: set and read on the one core running the call.
    RUNNING.load(Ordering::Relaxed)
}

/// Makes code just written through the kernel's alias visible to the
/// instruction fetch of EL0 (after loading the image).
pub fn sync_code() {
    // SAFETY: cache maintenance by the inner-shareable domain; no memory is
    // touched.
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack)) };
}

/// Whether `PSTATE.PAN` is set on this core.
pub fn pan_active() -> bool {
    let v: u64;
    // SAFETY: reads PSTATE.PAN (`mrs x, pan`, encoded by hand: the assembler
    // needs `+pan`).
    unsafe { core::arch::asm!(".inst 0xd5384260", out("x0") v, options(nomem, nostack)) };
    v & (1 << 22) != 0
}

/// The hardware separation of kernel and user memory in force on this core,
/// for the boot log and the smoke test.
pub fn protections() -> &'static str {
    if !pan_supported() {
        "NONE (this CPU lacks PAN)"
    } else if pan_active() {
        "PAN"
    } else {
        "PAN supported but OFF"
    }
}

/// Whether the CPU implements `FEAT_PAN` (ID_AA64MMFR1_EL1.PAN).
pub fn pan_supported() -> bool {
    let v: u64;
    // SAFETY: reads an ID register.
    unsafe { core::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) v, options(nomem, nostack)) };
    (v >> 20) & 0xf != 0
}

fn set_pan() {
    // SAFETY: `msr pan, #1` (encoded by hand); only restricts the kernel.
    unsafe { core::arch::asm!(".inst 0xd500419f", options(nomem, nostack)) };
}

/// Runs the program at `pc` with stack pointer `sp` in the address space
/// rooted at `root` (a physical `TTBR0` base), until the call ends.
///
/// # Safety
/// `root` must be a valid translation table whose user mappings contain
/// `pc` and `sp`; no other call may be in progress; the caller keeps the
/// kernel's own tables unchanged during the call.
pub unsafe fn enter(root: u64, pc: u64, sp: u64) -> Exit {
    let supported = pan_supported();
    let sctlr = regs::sctlr_el1();
    let mut s = sctlr;
    // EL0 may not touch the cache, the counter-type register, DAIF, DC ZVA;
    // WFI and WFE trap; little endian; stack alignment checked.
    s &= !(SCTLR_UCI | SCTLR_UCT | SCTLR_UMA | SCTLR_DZE | SCTLR_E0E | SCTLR_NTWI | SCTLR_NTWE);
    s |= SCTLR_SA0;
    if supported {
        // SPAN clear: PAN is set on every exception entry.
        s &= !SCTLR_SPAN;
    }
    if sctlr & SCTLR_BT1 != 0 {
        s |= SCTLR_BT0;
    }
    if s != sctlr {
        // SAFETY: only user-facing bits and PAN behaviour change.
        unsafe { regs::set_sctlr_el1(s) };
    }
    if supported {
        set_pan();
    }
    // SAFETY: the caller's tables; the ASID in the high bits.
    unsafe { regs::set_ttbr0_el1(root | (ASID << 48)) };
    // SAFETY: opens the lower half for the duration of the call only.
    unsafe { regs::set_tcr_el1(regs::tcr_el1() & !TCR_EPD0) };
    cpu::isb();
    // Relaxed: the exception handler runs on this core.
    RUNNING.store(true, Ordering::Relaxed);
    // SAFETY: saves our callee-saved state and drops to EL0; control comes
    // back here through `leave`.
    unsafe { urmqtt_user_enter(pc, sp, RESUME.0.get()) };
    RUNNING.store(false, Ordering::Relaxed);
    // SAFETY: closes the lower half again.
    unsafe { regs::set_tcr_el1(regs::tcr_el1() | TCR_EPD0) };
    cpu::isb();
    // SAFETY: `leave` wrote the reason before the long jump.
    unsafe { *LAST.0.get() }
}

/// Ends the call in progress with `exit`: returns from [`enter`].
///
/// # Safety
/// Only from the exception handler, for an exception taken from the worker
/// ([`running`]).
pub unsafe fn leave(exit: Exit) -> ! {
    // SAFETY: single call at a time; `enter` reads it after the jump.
    unsafe { *LAST.0.get() = exit };
    // SAFETY: the record `enter` filled; discards the exception frame.
    unsafe { urmqtt_user_leave(RESUME.0.get(), 0) }
}

/// Decodes an exception taken from the worker.
pub fn decode(frame: &TrapFrame, vector: Vector) -> UserEvent {
    match vector {
        Vector::Lower64Irq => UserEvent::Irq,
        Vector::Lower64Sync => {
            if frame.esr().class() == ExceptionClass::Svc64 {
                UserEvent::Syscall {
                    nr: frame.x[8],
                    args: [
                        frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
                    ],
                }
            } else {
                UserEvent::Fault(FaultInfo {
                    esr: frame.esr,
                    far: frame.far,
                    pc: frame.elr,
                })
            }
        }
        _ => UserEvent::Fault(FaultInfo {
            esr: frame.esr,
            far: frame.far,
            pc: frame.elr,
        }),
    }
}

/// Sets the result register of a system call.
pub fn set_return(frame: &mut TrapFrame, value: u64) {
    frame.x[0] = value;
}

core::arch::global_asm!(
    ".text",
    ".balign 16",
    ".global urmqtt_user_enter",
    "urmqtt_user_enter:",
    "hint #34", // bti c
    "stp x19, x20, [x2, #0]",
    "stp x21, x22, [x2, #16]",
    "stp x23, x24, [x2, #32]",
    "stp x25, x26, [x2, #48]",
    "stp x27, x28, [x2, #64]",
    "stp x29, x30, [x2, #80]",
    "mov x9, sp",
    "str x9, [x2, #96]",
    "stp d8, d9, [x2, #104]",
    "stp d10, d11, [x2, #120]",
    "stp d12, d13, [x2, #136]",
    "stp d14, d15, [x2, #152]",
    "mrs x9, daif",
    "str x9, [x2, #168]",
    "mrs x9, fpcr",
    "str x9, [x2, #176]",
    // The kernel runs on SP_EL0 (EL1t) or on SP_EL1 (EL1h); exceptions from
    // EL0 always arrive on SP_EL1. Remember which one the kernel uses and
    // where SP_EL1 stands, so `leave` can discard what the exception pushed.
    "mrs x10, spsel",
    "str x10, [x2, #184]",
    "msr spsel, #1",
    "mov x9, sp",
    "str x9, [x2, #192]",
    "msr spsel, x10",
    "msr elr_el1, x0",
    "tbnz x10, #0, 3f",
    "mov sp, x1", // EL1t: the stack pointer register is SP_EL0
    "b 4f",
    "3:",
    "msr sp_el0, x1",
    "4:",
    "msr spsr_el1, xzr", // EL0t, all of DAIF clear
    "msr fpcr, xzr",
    // Nothing of the kernel's registers reaches the worker.
    "mov x0, xzr",
    "mov x1, xzr",
    "mov x2, xzr",
    "mov x3, xzr",
    "mov x4, xzr",
    "mov x5, xzr",
    "mov x6, xzr",
    "mov x7, xzr",
    "mov x8, xzr",
    "mov x9, xzr",
    "mov x10, xzr",
    "mov x11, xzr",
    "mov x12, xzr",
    "mov x13, xzr",
    "mov x14, xzr",
    "mov x15, xzr",
    "mov x16, xzr",
    "mov x17, xzr",
    "mov x18, xzr",
    "mov x19, xzr",
    "mov x20, xzr",
    "mov x21, xzr",
    "mov x22, xzr",
    "mov x23, xzr",
    "mov x24, xzr",
    "mov x25, xzr",
    "mov x26, xzr",
    "mov x27, xzr",
    "mov x28, xzr",
    "mov x29, xzr",
    "mov x30, xzr",
    "movi v0.2d, #0",
    "movi v1.2d, #0",
    "movi v2.2d, #0",
    "movi v3.2d, #0",
    "movi v4.2d, #0",
    "movi v5.2d, #0",
    "movi v6.2d, #0",
    "movi v7.2d, #0",
    "movi v8.2d, #0",
    "movi v9.2d, #0",
    "movi v10.2d, #0",
    "movi v11.2d, #0",
    "movi v12.2d, #0",
    "movi v13.2d, #0",
    "movi v14.2d, #0",
    "movi v15.2d, #0",
    "movi v16.2d, #0",
    "movi v17.2d, #0",
    "movi v18.2d, #0",
    "movi v19.2d, #0",
    "movi v20.2d, #0",
    "movi v21.2d, #0",
    "movi v22.2d, #0",
    "movi v23.2d, #0",
    "movi v24.2d, #0",
    "movi v25.2d, #0",
    "movi v26.2d, #0",
    "movi v27.2d, #0",
    "movi v28.2d, #0",
    "movi v29.2d, #0",
    "movi v30.2d, #0",
    "movi v31.2d, #0",
    "eret",
    "dsb nsh", // never reached; stops straight-line speculation past eret
    "isb",
    ".balign 16",
    ".global urmqtt_user_leave",
    "urmqtt_user_leave:",
    "hint #34",
    "ldp x19, x20, [x0, #0]",
    "ldp x21, x22, [x0, #16]",
    "ldp x23, x24, [x0, #32]",
    "ldp x25, x26, [x0, #48]",
    "ldp x27, x28, [x0, #64]",
    "ldp x29, x30, [x0, #80]",
    // Discard the exception frame: SP_EL1 back to where it stood at entry,
    // then return to the mode the kernel called from.
    "ldr x9, [x0, #192]",
    "mov sp, x9",
    "ldr x9, [x0, #96]",
    "ldr x10, [x0, #184]",
    "tbnz x10, #0, 5f",
    "msr sp_el0, x9",
    "msr spsel, #0",
    "b 6f",
    "5:",
    "mov sp, x9",
    "6:",
    "ldp d8, d9, [x0, #104]",
    "ldp d10, d11, [x0, #120]",
    "ldp d12, d13, [x0, #136]",
    "ldp d14, d15, [x0, #152]",
    "ldr x9, [x0, #168]",
    "msr daif, x9",
    "ldr x9, [x0, #176]",
    "msr fpcr, x9",
    "mov x0, x1",
    "ret",
);
