//! Port I/O (`in`/`out`), for the legacy devices X2 touches: the 16550
//! UART, the 8259 PICs, the reset and power-off ports.

#![allow(unsafe_code)]

use core::arch::asm;

/// # Safety
/// Writing `port` must be harmless for the machine in the way the caller
/// intends (the legacy ports used here are inert on every PC and QEMU).
#[inline]
pub unsafe fn outb(port: u16, v: u8) {
    // SAFETY: forwarded to the caller; no memory is touched.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags))
    };
}

/// # Safety
/// See [`outb`].
#[inline]
pub unsafe fn outw(port: u16, v: u16) {
    // SAFETY: forwarded to the caller; no memory is touched.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags))
    };
}

/// # Safety
/// See [`outb`].
#[inline]
pub unsafe fn outl(port: u16, v: u32) {
    // SAFETY: forwarded to the caller; no memory is touched.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags))
    };
}

/// # Safety
/// Reading `port` must have no side effect the caller cannot accept.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: forwarded to the caller; no memory is touched.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags))
    };
    v
}
