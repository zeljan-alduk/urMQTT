//! Running an unprivileged program in ring 3 (ADR-210): entering it, taking
//! its system calls, interrupts and faults, and leaving it. The same shape
//! as the aarch64 module.
//!
//! The kernel calls [`enter`] like a function. The worker runs until it
//! executes the exit system call, faults, or the kernel gives up on it
//! ([`leave`], from the exception handler); every one of these ends with an
//! ordinary return of [`enter`], because the kernel's callee-saved registers
//! and stack pointer were saved at entry and are restored by the long jump
//! in [`leave`]. System calls (`int 0xf0`) and interrupts that do not end
//! the call are handled in the exception handler and resumed with `iretq`.
//!
//! Hardware state while the worker runs: `CR3` is the worker's root (the
//! kernel's upper half is shared, supervisor-only); SMEP and SMAP are on
//! (set by `paging::activate`), so ring 0 can neither execute nor touch a
//! user page; the entry stack is `TSS.rsp0`; `swapgs` makes the per-CPU
//! `GS` valid in the kernel and the program's own in ring 3; I/O ports are
//! closed (no I/O bitmap) and `UMIP` hides the descriptor tables.

#![allow(unsafe_code)]

use core::arch::{asm, global_asm};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::trap::{TrapFrame, Vector};
use crate::{gdt, paging, percpu, prim};

const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

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
    pub vector: u64,
    pub error_code: u64,
    pub cr2: u64,
    pub pc: u64,
}

impl fmt::Display for FaultInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = Vector::from_index(self.vector).map_or("exception", Vector::name);
        write!(
            f,
            "{name} (vector {}, error code {:#x}) at rip {:#x}",
            self.vector, self.error_code, self.pc
        )?;
        if self.vector == 14 {
            write!(f, ", address {:#x}", self.cr2)?;
        }
        Ok(())
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
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    /// The stack pointer at the call: it points at the return address.
    rsp: u64,
    rflags: u64,
    mxcsr: u32,
    fcw: u16,
}

struct ResumeCell(core::cell::UnsafeCell<Resume>);
// SAFETY: written by `enter` and read by `leave`, both on the one core that
// runs the single call at a time (the kernel serialises calls).
unsafe impl Sync for ResumeCell {}

static RESUME: ResumeCell = ResumeCell(core::cell::UnsafeCell::new(Resume {
    rbx: 0,
    rbp: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    rsp: 0,
    rflags: 0,
    mxcsr: 0,
    fcw: 0,
}));
static RUNNING: AtomicBool = AtomicBool::new(false);

struct ExitCell(core::cell::UnsafeCell<Exit>);
// SAFETY: as for `ResumeCell`.
unsafe impl Sync for ExitCell {}

/// The reason the call ended, set by `leave`, taken by `enter`.
static LAST: ExitCell = ExitCell(core::cell::UnsafeCell::new(Exit::Timeout));

unsafe extern "C" {
    fn urmqtt_user_enter(pc: u64, sp: u64, resume: *mut Resume, rsp0: *mut u64);
    fn urmqtt_user_leave(resume: *const Resume) -> !;
}

/// Whether the current call is executing the worker.
pub fn running() -> bool {
    // Relaxed: set and read on the one core running the call.
    RUNNING.load(Ordering::Relaxed)
}

/// The hardware separation of kernel and user memory in force, for the
/// boot log and the smoke test.
pub fn protections() -> &'static str {
    let p = paging::protections();
    match (p.smep, p.smap) {
        (true, true) => "SMEP+SMAP",
        (true, false) => "SMEP only (this CPU lacks SMAP)",
        (false, true) => "SMAP only (this CPU lacks SMEP)",
        (false, false) => "NONE (this CPU lacks SMEP and SMAP)",
    }
}

/// Code written through the kernel's alias is visible to instruction fetch
/// at once on x86: nothing to do.
pub fn sync_code() {}

fn write_cr3(v: u64) {
    // SAFETY: the caller passes a root that maps the running kernel at the
    // same addresses (the user roots share the kernel's upper half).
    unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) };
}

/// Runs the program at `pc` with stack pointer `sp` in the address space
/// rooted at `root` (a physical CR3 value), until the call ends.
///
/// # Safety
/// `root` must be a valid root whose user mappings contain `pc` and `sp`
/// and whose upper half is the kernel's; no other call may be in progress;
/// the caller keeps the kernel's own tables unchanged during the call.
pub unsafe fn enter(root: u64, pc: u64, sp: u64) -> Exit {
    let slot = gdt::rsp0_slot(percpu::current());
    let kernel_root = paging::kernel_root();
    // The program's GS base lives in KERNEL_GS_BASE while the kernel runs;
    // every entry starts it at zero.
    prim::wrmsr(MSR_KERNEL_GS_BASE, 0);
    // Relaxed: the exception handler runs on this core.
    RUNNING.store(true, Ordering::Relaxed);
    write_cr3(root);
    // SAFETY: saves our callee-saved state and drops to ring 3; control
    // comes back here through `leave`.
    unsafe { urmqtt_user_enter(pc, sp, RESUME.0.get(), slot) };
    RUNNING.store(false, Ordering::Relaxed);
    write_cr3(kernel_root);
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
    // SAFETY: the record `enter` filled.
    unsafe { urmqtt_user_leave(RESUME.0.get()) }
}

/// Decodes an exception taken from the worker.
pub fn decode(frame: &TrapFrame, _vector: Vector) -> UserEvent {
    let v = frame.vector;
    if v == u64::from(crate::vectors::SYSCALL) {
        // gpr order: rax rbx rcx rdx rsi rdi rbp r8 r9 r10 ...
        let g = &frame.gpr;
        UserEvent::Syscall {
            nr: g[0],
            args: [g[5], g[4], g[3], g[9], g[7], g[8]],
        }
    } else if v >= 32 {
        UserEvent::Irq
    } else {
        UserEvent::Fault(FaultInfo {
            vector: v,
            error_code: frame.error_code,
            cr2: frame.cr2,
            pc: frame.rip,
        })
    }
}

/// Sets the result register of a system call.
pub fn set_return(frame: &mut TrapFrame, value: u64) {
    frame.gpr[0] = value;
}

static DEFAULT_MXCSR: u32 = 0x1f80;

global_asm!(
    r#"
    .text
    .balign 16
    .global urmqtt_user_enter
urmqtt_user_enter:
    # rdi = pc, rsi = user sp, rdx = resume record, rcx = &TSS.rsp0
    mov [rdx + 0], rbx
    mov [rdx + 8], rbp
    mov [rdx + 16], r12
    mov [rdx + 24], r13
    mov [rdx + 32], r14
    mov [rdx + 40], r15
    mov [rdx + 48], rsp
    pushfq
    pop qword ptr [rdx + 56]
    stmxcsr [rdx + 64]
    fnstcw [rdx + 68]
    # Interrupts that arrive in ring 3 use the stack below this call.
    mov [rcx], rsp
    # The iretq frame: ss, rsp, rflags (IF), cs, rip.
    push {user_ds}
    push rsi
    push 0x202
    push {user_cs}
    push rdi
    mov eax, {user_ds}
    mov ds, ax
    mov es, ax
    ldmxcsr [rip + {mxcsr}]
    fninit
    # Nothing of the kernel's registers or vector state reaches the worker.
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    cli
    swapgs
    iretq

    .balign 16
    .global urmqtt_user_leave
urmqtt_user_leave:
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]
    ldmxcsr [rdi + 64]
    fldcw [rdi + 68]
    mov rsp, [rdi + 48]
    push qword ptr [rdi + 56]
    popfq
    xor eax, eax
    ret
    "#,
    user_ds = const gdt::USER_DS as u32,
    user_cs = const gdt::USER_CS as u32,
    mxcsr = sym DEFAULT_MXCSR,
);
