//! Entry point, panic handler and the operations of the hello worker.

#![allow(unsafe_code)]

use core::panic::PanicInfo;

use urmqtt_usys::abi::{MAGIC, hdr, op, sys};
use urmqtt_usys::layout::{SHM_BASE, SHM_HEADER};
use urmqtt_usys::stub::{privileged, syscall};

/// The stack protector's guard (`-Zstack-protector`); the kernel gives a
/// fresh seed at every start.
#[unsafe(no_mangle)]
pub static mut __stack_chk_guard: u64 = 0x0000_0a0d_5a5a_0000;

#[unsafe(no_mangle)]
pub extern "C" fn __stack_chk_fail() -> ! {
    exit(0xdead_0001)
}

fn exit(code: u64) -> ! {
    // SAFETY: the exit call ends the worker's current call.
    unsafe { syscall(sys::EXIT, [code, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(0xdead_0002)
}

fn word(off: usize) -> *mut u64 {
    (SHM_BASE as usize + off) as *mut u64
}

fn read(off: usize) -> u64 {
    // SAFETY: the shared window is mapped for the life of the worker.
    unsafe { word(off).read_volatile() }
}

fn write(off: usize, v: u64) {
    // SAFETY: as above.
    unsafe { word(off).write_volatile(v) }
}

fn log(msg: &[u8]) {
    let io = (SHM_BASE as usize + SHM_HEADER) as *mut u8;
    // SAFETY: the I/O area is mapped and far larger than any message here.
    unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), io, msg.len()) };
    // SAFETY: the log call reads `len` bytes of the I/O area.
    unsafe { syscall(sys::LOG, [msg.len() as u64, 0, 0, 0, 0, 0]) };
}

static mut SCRATCH: [u8; 64] = [0; 64];

/// The worker's entry: the kernel starts every call here with a fresh
/// stack and the request in the shared window.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start() -> ! {
    let seed = read(hdr::SEED);
    if seed != 0 {
        // SAFETY: single-threaded, before any function with a protector runs again.
        unsafe { core::ptr::addr_of_mut!(__stack_chk_guard).write_volatile(seed) };
    }
    let a0 = read(hdr::ARG);
    match read(hdr::OP) {
        op::HELLO => {
            log(b"dbworker: hello from user mode");
            write(hdr::RET, a0 ^ MAGIC);
        }
        op::FAULT_READ_KERNEL => {
            // SAFETY: deliberately faulting access (test).
            let v = unsafe { (a0 as *const u64).read_volatile() };
            write(hdr::RET, v);
        }
        op::FAULT_WRITE_KERNEL => {
            // SAFETY: deliberately faulting access (test).
            unsafe { (a0 as *mut u64).write_volatile(0x4141_4141) };
        }
        op::FAULT_EXEC_KERNEL => {
            // SAFETY: deliberately faulting jump (test).
            let f: extern "C" fn() = unsafe { core::mem::transmute(a0 as usize) };
            f();
        }
        op::FAULT_PRIVILEGED => {
            // SAFETY: deliberately privileged instruction (test).
            unsafe { privileged() };
        }
        op::SPIN => loop {
            core::hint::spin_loop();
        },
        op::FAULT_WRITE_TEXT => {
            let p = _start as usize as *mut u32;
            // SAFETY: deliberately faulting write to read-only code (test).
            unsafe { p.write_volatile(0) };
        }
        op::FAULT_EXEC_DATA => {
            let p = core::ptr::addr_of_mut!(SCRATCH).cast::<u8>();
            // SAFETY: deliberately faulting jump to non-executable data (test).
            let f: extern "C" fn() = unsafe { core::mem::transmute(p) };
            f();
        }
        op::FAULT_NULL => {
            // SAFETY: deliberately faulting access (test).
            let v = unsafe { core::ptr::null::<u64>().read_volatile() };
            write(hdr::RET, v);
        }
        _ => exit(0xdead_0003),
    }
    exit(0)
}
