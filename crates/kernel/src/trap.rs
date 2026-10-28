//! Exception reports and the panic handler.

#![allow(unsafe_code)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use urmqtt_arch_aarch64::esr::{ExceptionClass, Vector};
use urmqtt_arch_aarch64::exception::TrapFrame;
use urmqtt_log::emergency;

use crate::power;

/// `brk` immediate the handler treats as "report and resume" (test mode).
const BRK_RESUME: u16 = 0x5155;

static IN_FATAL: AtomicBool = AtomicBool::new(false);

pub fn handle(frame: &mut TrapFrame, vector: Vector) {
    let esr = frame.esr();
    if vector.is_synchronous()
        && esr.class() == ExceptionClass::Brk64
        && esr.imm16() == Some(BRK_RESUME)
    {
        emergency(format_args!(
            "exception: resumable brk at {:#x}, continuing\n",
            frame.elr
        ));
        frame.elr += 4;
        return;
    }
    // Relaxed swap: single flag, only detects re-entry on this core.
    if IN_FATAL.swap(true, Ordering::Relaxed) {
        emergency(format_args!("!!! nested exception, giving up\n"));
        power::fatal();
    }
    emergency(format_args!("\n!!! EXCEPTION: {}\n", vector.name()));
    if vector.is_synchronous() {
        emergency(format_args!("    {esr}\n"));
    }
    emergency(format_args!(
        "    ESR={:#018x} ELR={:#018x} FAR={:#018x} SPSR={:#010x}\n",
        frame.esr, frame.elr, frame.far, frame.spsr
    ));
    for (i, pair) in frame.x.chunks(4).enumerate() {
        emergency(format_args!("   "));
        for (j, r) in pair.iter().enumerate() {
            emergency(format_args!(" x{:<2}={r:#018x}", i * 4 + j));
        }
        emergency(format_args!("\n"));
    }
    emergency(format_args!("!!! fatal exception, stopping\n"));
    power::fatal();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Relaxed: see `handle`.
    if !IN_FATAL.swap(true, Ordering::Relaxed) {
        emergency(format_args!("\n!!! PANIC: {info}\n"));
    }
    power::fatal()
}

/// Reads from `va` (test mode: expected to fault).
pub fn probe_read(va: u64) {
    // SAFETY: deliberately faulting access in test mode; the exception
    // handler reports it and never returns here.
    let v = unsafe { (va as *const u64).read_volatile() };
    core::hint::black_box(v);
}

/// Executes the resumable `brk`.
pub fn brk_resume() {
    // SAFETY: the handler recognises this immediate and skips it.
    unsafe { core::arch::asm!("brk #0x5155", options(nomem, nostack)) };
}

/// Executes a permanently undefined instruction (test mode).
pub fn undefined_instruction() {
    // SAFETY: deliberately faulting instruction in test mode.
    unsafe { core::arch::asm!("udf #0", options(nomem, nostack)) };
}
