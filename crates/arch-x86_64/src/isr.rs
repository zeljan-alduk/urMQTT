//! Exception entry (X2): 256 stubs, the common save/restore path and the
//! hand-over to the kernel's handler. Bare metal only.
//!
//! Every stub makes the stack look the same: an error code (the CPU's, or
//! a zero) and the vector number below the CPU's frame. The common path
//! then saves CR2 and the 15 general registers (the [`TrapFrame`] layout),
//! saves the x87/SSE state with FXSAVE (the handler is hard-float Rust and
//! may clobber it; `int3` resumes), and calls [`urmqtt_trap_dispatch`] on
//! the stack the exception arrived on (an IST stack for #DF, NMI, #MC and
//! #PF). Interrupts stay disabled for the whole exception: the gates are
//! interrupt gates.
//!
//! XSAVE-sized state (AVX and later) is not saved here: kernel code is
//! built for x86-64-v2, so only dispatched AVX functions touch the upper
//! halves, and X4 saves that state when interrupts can reach them.

#![allow(unsafe_code)]

use core::fmt::Write;

use urmqtt_sync::sync::OnceCell;

use crate::trap::{Handler, TrapFrame, Vector};

core::arch::global_asm!(
    r#"
    .section .text.vectors, "ax"
    .balign 16
    .global urmqtt_isr_stubs
urmqtt_isr_stubs:
    .altmacro
    .macro ISR n
    .balign 16
    .if (\n == 8) | ((\n >= 10) & (\n <= 14)) | (\n == 17) | (\n == 21) | (\n == 29) | (\n == 30)
    .else
    push 0
    .endif
    push \n
    jmp urmqtt_isr_common
    .endm
    .set vec, 0
    .rept 256
    ISR %vec
    .set vec, vec + 1
    .endr
    .noaltmacro

    .balign 16
urmqtt_isr_common:
    cld
    sub rsp, 8
    push r15
    mov r15, cr2
    mov [rsp + 8], r15
    pop r15
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    mov rdi, rsp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 512
    fxsave64 [rsp]
    call urmqtt_trap_dispatch
    fxrstor64 [rsp]
    mov rsp, rbp
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    add rsp, 24
    iretq
    "#
);

/// The kernel's exception handler.
static HANDLER: OnceCell<Handler> = OnceCell::new();

pub fn set_handler(h: Handler) {
    // A second call keeps the first handler: the kernel installs it once.
    let _ = HANDLER.set(h);
}

/// Called by the common path with the saved state. Runs with interrupts
/// off; returns to resume (only `int3` does).
#[unsafe(no_mangle)]
extern "C" fn urmqtt_trap_dispatch(frame: &mut TrapFrame) {
    let vector = Vector::from_index(frame.vector).unwrap_or(Vector::Other);
    match HANDLER.get() {
        Some(h) => h(frame, vector),
        None => {
            // Before the kernel installed its handler: say what we can.
            let _ = write!(
                crate::serial::Writer,
                "\n!!! EXCEPTION before the handler was installed: {}\n{}",
                vector.name(),
                frame.registers()
            );
            crate::cpu::halt();
        }
    }
}

/// Builds the GDT/TSS and the IDT on the boot CPU, loads them, and masks
/// the legacy 8259 PICs so they cannot raise vectors 8-15.
pub fn install() {
    // SAFETY: called once on the boot CPU, interrupts are off (Limine
    // enters with IF=0 and nothing enables them before the APIC code).
    unsafe { crate::gdt::init() };
    // SAFETY: as above; the GDT with the kernel code segment is loaded.
    unsafe { crate::idt::init() };
    for port in [0x21, 0xa1] {
        // SAFETY: the PICs' mask registers; masking every line is always safe.
        unsafe { crate::port::outb(port, 0xff) };
    }
}

/// Executes `int3`: the handler resumes after it.
pub fn breakpoint() {
    // SAFETY: a breakpoint trap; the handler resumes after it.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}

/// Executes `ud2`: #UD, never resumed.
pub fn undefined_instruction() {
    // SAFETY: deliberately faulting instruction in test mode; the handler
    // reports it and does not return here.
    unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
}

/// A load from a non-canonical address: #GP(0).
pub fn general_protection() {
    let p = core::hint::black_box(0x8000_0000_0000_0000u64) as *const u64;
    // SAFETY: deliberately faulting access in test mode; the handler
    // reports it and does not return here.
    let v = unsafe { p.read_volatile() };
    core::hint::black_box(v);
}

/// A #GP whose gate is not present: delivering it raises #NP, and two
/// contributory exceptions in a row are a #DF, taken on its own IST stack.
pub fn double_fault() {
    // SAFETY: boot CPU, interrupts off, the IDT is loaded; the double
    // fault that follows is the point of the test.
    unsafe { crate::idt::set_present(13, false) };
    general_protection();
}
