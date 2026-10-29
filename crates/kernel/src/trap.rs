//! Exception reports and the panic handler.

#![allow(unsafe_code)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use urmqtt_arch::trap::{self, Event, TrapFrame, Vector};
use urmqtt_log::emergency;

use crate::power;

static IN_FATAL: AtomicBool = AtomicBool::new(false);

pub fn handle(frame: &mut TrapFrame, vector: Vector) {
    match frame.classify(vector) {
        Event::Irq => {
            crate::irq::dispatch();
            return;
        }
        Event::ResumableBreakpoint => {
            emergency(format_args!(
                "exception: resumable brk at {:#x}, continuing\n",
                frame.pc()
            ));
            frame.skip_breakpoint();
            return;
        }
        Event::Fatal => {}
    }
    // Relaxed swap: single flag, only detects re-entry on this core.
    if IN_FATAL.swap(true, Ordering::Relaxed) {
        emergency(format_args!("!!! nested exception, giving up\n"));
        power::fatal();
    }
    emergency(format_args!("\n!!! EXCEPTION: {}\n", vector.name()));
    if let Some(cause) = frame.cause(vector) {
        emergency(format_args!("    {cause}\n"));
    }
    if let Some((what, cpu)) = frame
        .fault_address(vector)
        .and_then(crate::layout::describe)
    {
        emergency(format_args!("    FAR is in: {what} (cpu {cpu})\n"));
    }
    emergency(format_args!("{}", frame.registers()));
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

/// Executes the resumable breakpoint.
pub fn brk_resume() {
    trap::breakpoint();
}

/// Executes a permanently undefined instruction (test mode).
pub fn undefined_instruction() {
    trap::undefined_instruction();
}
