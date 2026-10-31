//! The 16550 UART at COM1 (X2). Output for the log; input is polled and used
//! only by the diagnostic entry's confirmation prompt (O4). SPCR/ACPI discovery of other ports
//! comes with X6; COM1 is where QEMU, KVM guests and most PCs have it.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};

use crate::port::{inb, outb};

/// COM1's I/O base.
pub const COM1: u16 = 0x3f8;

const TX: u16 = 0; // transmit data / divisor low (DLAB)
const IER: u16 = 1; // interrupt enable / divisor high (DLAB)
const FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const SCR: u16 = 7;
const LSR_RX_READY: u8 = 1 << 0;
const LSR_TX_EMPTY: u8 = 1 << 5;
const LSR_IDLE: u8 = 1 << 6;
/// Bounded wait so a wedged or absent UART can never hang the kernel.
const SPIN_LIMIT: u32 = 1_000_000;

// Relaxed: set once on the boot CPU before the first line is logged.
static PRESENT: AtomicBool = AtomicBool::new(false);

fn out(reg: u16, v: u8) {
    // SAFETY: COM1's registers; programming an absent UART is a no-op.
    unsafe { outb(COM1 + reg, v) };
}

fn read(reg: u16) -> u8 {
    // SAFETY: COM1's registers; reading them has no side effect that
    // matters here (LSR is only polled, SCR is scratch).
    unsafe { inb(COM1 + reg) }
}

/// Programs COM1 for 115200 8N1 with the FIFO on and interrupts off, and
/// reports whether a UART answered (the scratch register reads back what
/// was written). A machine without one logs to the framebuffer only.
pub fn init() -> bool {
    out(IER, 0); // no interrupts
    out(LCR, 0x80); // DLAB
    out(TX, 1); // divisor 1: 115200 baud
    out(IER, 0);
    out(LCR, 0x03); // 8N1, DLAB off
    out(FCR, 0xc7); // FIFO on, cleared, 14-byte trigger
    out(MCR, 0x0b); // DTR, RTS, OUT2
    out(SCR, 0xa5);
    let a = read(SCR);
    out(SCR, 0x5a);
    let present = a == 0xa5 && read(SCR) == 0x5a;
    // Relaxed: see PRESENT.
    PRESENT.store(present, Ordering::Relaxed);
    present
}

pub fn write_byte(b: u8) {
    // Relaxed: see PRESENT.
    if !PRESENT.load(Ordering::Relaxed) {
        return;
    }
    for _ in 0..SPIN_LIMIT {
        if read(LSR) & LSR_TX_EMPTY != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    out(TX, b);
}

/// One received byte, if any is waiting (never blocks).
pub fn read_byte() -> Option<u8> {
    // Relaxed: see PRESENT.
    if !PRESENT.load(Ordering::Relaxed) || read(LSR) & LSR_RX_READY == 0 {
        return None;
    }
    Some(read(TX))
}

/// Writes `s`, turning every `\n` into `\r\n` as the terminal expects.
pub fn write_bytes(s: &[u8]) {
    for &b in s {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// `fmt::Write` over [`write_bytes`], for reports that cannot take the
/// log lock.
pub struct Writer;

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

/// Waits until everything queued has left the shift register.
pub fn flush() {
    // Relaxed: see PRESENT.
    if !PRESENT.load(Ordering::Relaxed) {
        return;
    }
    for _ in 0..SPIN_LIMIT {
        if read(LSR) & LSR_IDLE != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}
