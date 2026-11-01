//! The worker's side of the system-call convention (see [`crate::abi`]).

#![allow(unsafe_code)]

/// One system call with up to six arguments.
///
/// # Safety
/// The kernel validates every argument; the call itself has no memory
/// preconditions. It is `unsafe` because `exit` never returns and the
/// others have effects outside the program.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn syscall(nr: u64, a: [u64; 6]) -> u64 {
    let ret: u64;
    // SAFETY: `svc` enters the kernel, which preserves every register but x0.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a[0] => ret,
            in("x1") a[1], in("x2") a[2], in("x3") a[3], in("x4") a[4], in("x5") a[5],
            options(nostack)
        );
    }
    ret
}

/// Executes an instruction only the kernel may execute (fault-containment
/// test): reading `SCTLR_EL1` on aarch64, `hlt` on x86_64.
///
/// # Safety
/// Traps into the kernel, which ends the worker's call.
#[cfg(target_arch = "aarch64")]
pub unsafe fn privileged() {
    // SAFETY: `mrs x0, sctlr_el1` (encoded by hand) traps at EL0.
    unsafe { core::arch::asm!(".inst 0xd5381000", out("x0") _, options(nostack)) };
}

/// Executes an instruction only the kernel may execute (fault-containment
/// test): reading `SCTLR_EL1` on aarch64, `hlt` on x86_64.
///
/// # Safety
/// Traps into the kernel, which ends the worker's call.
#[cfg(target_arch = "x86_64")]
pub unsafe fn privileged() {
    // SAFETY: `hlt` is privileged and raises #GP in ring 3.
    unsafe { core::arch::asm!("hlt", options(nostack)) };
}

/// One system call with up to six arguments.
///
/// # Safety
/// As on aarch64.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall(nr: u64, a: [u64; 6]) -> u64 {
    let ret: u64;
    // SAFETY: `int 0xf0` enters the kernel, which preserves every register
    // but rax.
    unsafe {
        core::arch::asm!(
            "int 0xf0",
            inlateout("rax") nr => ret,
            in("rdi") a[0], in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
            options(nostack)
        );
    }
    ret
}
