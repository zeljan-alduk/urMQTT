//! Polled access to the i8042 PS/2 controller's output buffer, for the
//! diagnostic entry's confirmation prompt (O4). Nothing is written to the
//! controller: the firmware has already enabled the keyboard.

#![allow(unsafe_code)]

use crate::port::inb;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const OBF: u8 = 1 << 0;
const AUX: u8 = 1 << 5;

/// One byte from the keyboard (a scancode), if one is waiting. A status of
/// 0xff means no controller answers (the bus floats high). Mouse bytes are
/// left alone.
pub fn poll() -> Option<u8> {
    // SAFETY: reading the controller's status port has no side effect.
    let st = unsafe { inb(STATUS) };
    if st == 0xff || st & OBF == 0 || st & AUX != 0 {
        return None;
    }
    // SAFETY: the output buffer is full and holds a keyboard byte.
    Some(unsafe { inb(DATA) })
}
