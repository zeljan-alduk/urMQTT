//! Entry point, panic handler and the operations of the hello worker.

#![allow(unsafe_code)]

use core::panic::PanicInfo;

use urmqtt_store::worker::{self, Ops};
#[cfg(feature = "selftest")]
use urmqtt_usys::abi::{MAGIC, op};
use urmqtt_usys::abi::{hdr, sys};
use urmqtt_usys::layout::SHM_BASE;
#[cfg(feature = "selftest")]
use urmqtt_usys::layout::SHM_HEADER;
#[cfg(feature = "selftest")]
use urmqtt_usys::stub::privileged;
use urmqtt_usys::stub::syscall;

/// The worker has no allocator: SQLite has its own heap and the dispatcher
/// uses fixed tables. The store crate's other modules (the disk layer and so
/// on) are linked in unused and name the `alloc` crate; this makes any
/// allocation that did happen fail instead of corrupting memory.
struct NoHeap;

// SAFETY: allocation always fails (null), deallocation is never called for a
// block this allocator did not return.
unsafe impl core::alloc::GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[global_allocator]
static HEAP: NoHeap = NoHeap;

/// The stack protector's guard (`-Zstack-protector`); the kernel gives a
/// fresh seed at every start.
// SAFETY: the compiler's stack-protector code reads `__stack_chk_guard` by name; no other item has
// it, and only `_start` writes it (once, single-threaded, before protected code runs again).
#[unsafe(no_mangle)]
pub static mut __stack_chk_guard: u64 = 0x0000_0a0d_5a5a_0000;

// SAFETY: the compiler's epilogue calls `__stack_chk_fail` by name with the C ABI; no other item
// has that name, and it never returns.
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

fn system_call(nr: u64, a: [u64; 6]) -> u64 {
    // SAFETY: the kernel validates every argument of its system calls.
    unsafe { syscall(nr, a) }
}

fn word(off: usize) -> *mut u64 {
    (SHM_BASE as usize + off) as *mut u64
}

fn read(off: usize) -> u64 {
    // SAFETY: the shared window is mapped for the life of the worker.
    unsafe { word(off).read_volatile() }
}

#[cfg(feature = "selftest")]
fn write(off: usize, v: u64) {
    // SAFETY: as above.
    unsafe { word(off).write_volatile(v) }
}

#[cfg(feature = "selftest")]
fn log(msg: &[u8]) {
    let io = (SHM_BASE as usize + SHM_HEADER) as *mut u8;
    // SAFETY: the I/O area is mapped and far larger than any message here.
    unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), io, msg.len()) };
    // SAFETY: the log call reads `len` bytes of the I/O area.
    unsafe { syscall(sys::LOG, [msg.len() as u64, 0, 0, 0, 0, 0]) };
}

#[cfg(feature = "selftest")]
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
    let o = read(hdr::OP);
    if o >= 32 {
        // The store's operations (ADR-211).
        // SAFETY: the shared window is mapped for the life of the worker and
        // used only by this program and the kernel, never at the same time.
        unsafe {
            worker::install(Ops {
                shm: SHM_BASE as *mut u8,
                sys: system_call,
            });
        }
        exit(worker::dispatch());
    }
    #[cfg(feature = "selftest")]
    selftest(o, read(hdr::ARG));
    #[cfg(not(feature = "selftest"))]
    exit(0xdead_0003)
}

/// The operations of the dev self-tests (`test=worker-contain`,
/// `test=worker-fault`): a round trip and every way a worker can misbehave.
#[cfg(feature = "selftest")]
fn selftest(o: u64, a0: u64) -> ! {
    match o {
        op::NOP => {}
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
            let entry: extern "C" fn() -> ! = _start;
            let p = entry as usize as *mut u32;
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
