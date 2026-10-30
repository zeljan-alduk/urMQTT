//! The legacy 8259 PIC pair: remapped out of the exception range and fully
//! masked, so only the APIC delivers interrupts.

#![allow(unsafe_code)]

use crate::prim::{inb, io_wait, outb};
use crate::vectors::{PIC_MASTER_BASE, PIC_SLAVE_BASE};

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;

/// Runs the ICW sequence (so a spurious IRQ7/15 arrives at a known, unused
/// vector rather than inside the exception range), then masks every line.
pub fn disable() {
    // ICW1: edge triggered, cascade, ICW4 needed.
    outb(MASTER_CMD, 0x11);
    io_wait();
    outb(SLAVE_CMD, 0x11);
    io_wait();
    outb(MASTER_DATA, PIC_MASTER_BASE as u8);
    io_wait();
    outb(SLAVE_DATA, PIC_SLAVE_BASE as u8);
    io_wait();
    // ICW3: the slave hangs off master line 2; its cascade identity is 2.
    outb(MASTER_DATA, 4);
    io_wait();
    outb(SLAVE_DATA, 2);
    io_wait();
    // ICW4: 8086 mode.
    outb(MASTER_DATA, 0x01);
    io_wait();
    outb(SLAVE_DATA, 0x01);
    io_wait();
    outb(MASTER_DATA, 0xff);
    outb(SLAVE_DATA, 0xff);
}

/// True if both PICs report every line masked.
pub fn all_masked() -> bool {
    inb(MASTER_DATA) == 0xff && inb(SLAVE_DATA) == 0xff
}
