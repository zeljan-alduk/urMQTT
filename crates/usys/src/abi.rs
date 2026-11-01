//! System calls and the request header.
//!
//! A call into the worker is: the kernel fills the header of the shared
//! window (`op`, six arguments, then optionally bytes in the I/O area),
//! enters the worker at the image's entry point, and the worker answers with
//! the *exit* system call after writing its results (`ret`, `ret2`, bytes in
//! the I/O area). The worker calls the kernel back with the system calls
//! below, in registers (aarch64: `svc #0`, number in x8, arguments in x0 to
//! x5, result in x0; x86_64: `int 0xf0`, number in rax, arguments in rdi,
//! rsi, rdx, r10, r8, r9, result in rax). All other registers are preserved.

/// Header word offsets (in bytes) inside the shared window.
pub mod hdr {
    pub const OP: usize = 0;
    pub const ARG: usize = 8; // 6 words
    pub const RET: usize = 56;
    pub const RET2: usize = 64;
    /// Length of the data the last side put in the I/O area.
    pub const LEN: usize = 72;
    /// Random seed the kernel gives at each start (stack guard, etc.).
    pub const SEED: usize = 80;
}

/// Operations the kernel asks of the worker.
pub mod op {
    /// Echo: `ret = arg0 ^ MAGIC`. Proves a round trip.
    pub const HELLO: u64 = 1;
    /// Test: read a kernel address (data abort expected).
    pub const FAULT_READ_KERNEL: u64 = 2;
    /// Test: write a kernel address.
    pub const FAULT_WRITE_KERNEL: u64 = 3;
    /// Test: jump to a kernel address.
    pub const FAULT_EXEC_KERNEL: u64 = 4;
    /// Test: execute a privileged instruction.
    pub const FAULT_PRIVILEGED: u64 = 5;
    /// Test: loop forever (the time budget must end it).
    pub const SPIN: u64 = 6;
    /// Test: write to its own read-only code.
    pub const FAULT_WRITE_TEXT: u64 = 7;
    /// Test: jump to its own data (W^X, no-execute).
    pub const FAULT_EXEC_DATA: u64 = 8;
    /// Test: read through the null pointer.
    pub const FAULT_NULL: u64 = 9;
}

pub const MAGIC: u64 = 0x5552_4d51_5454_0001;

/// System calls the worker makes.
pub mod sys {
    /// `exit(code)`: ends the current call.
    pub const EXIT: u64 = 0;
    /// `log(len)`: the worker's message is the first `len` bytes of the I/O
    /// area. Used by the hello worker and for SQLite's error log.
    pub const LOG: u64 = 1;
}
