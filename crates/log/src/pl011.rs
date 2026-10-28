//! Output-only PL011 UART driver (no receive path by design: no console input).

#![allow(unsafe_code)]

const DR: usize = 0x000;
const FR: usize = 0x018;
const FR_TXFF: u32 = 1 << 5;
const FR_BUSY: u32 = 1 << 3;
/// Bounded wait so a wedged UART can never hang the kernel.
const SPIN_LIMIT: u32 = 1_000_000;

/// A PL011 mapped at a kernel virtual address.
#[derive(Clone, Copy)]
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// # Safety
    /// `base` must be the virtual address of a PL011 register block mapped as
    /// device memory for the lifetime of the kernel. The firmware is expected
    /// to have configured line settings (QEMU and cloud firmware do).
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    fn reg(&self, off: usize) -> *mut u32 {
        (self.base + off) as *mut u32
    }

    pub fn write_byte(&self, b: u8) {
        for _ in 0..SPIN_LIMIT {
            // SAFETY: FR is a read-only status register inside the mapped block.
            if unsafe { self.reg(FR).read_volatile() } & FR_TXFF == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: DR is the transmit data register inside the mapped block.
        unsafe { self.reg(DR).write_volatile(u32::from(b)) };
    }

    pub fn write_bytes(&self, s: &[u8]) {
        for &b in s {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    /// Waits until everything queued has left the shift register.
    pub fn flush(&self) {
        for _ in 0..SPIN_LIMIT {
            // SAFETY: FR is a read-only status register inside the mapped block.
            if unsafe { self.reg(FR).read_volatile() } & FR_BUSY == 0 {
                return;
            }
            core::hint::spin_loop();
        }
    }
}

impl core::fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}
