//! The kernel's first instructions on the boot CPU.
//!
//! Entry from Limine: MMU on, interrupts masked, FP/SIMD disabled (base
//! revision 6), SPSel = 0. FP is enabled before any compiled code can use
//! SIMD registers (ADR-003), and the CPU switches to SP_ELx so exceptions to
//! this EL share the boot stack. Then it calls the kernel's
//! `urmqtt_kmain`, which never returns.

#![allow(unsafe_code)]

core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    "_start:",
    "hint #34", // bti c
    "mrs x9, cpacr_el1",
    "orr x9, x9, #(3 << 20)",
    "msr cpacr_el1, x9",
    "isb",
    "mov x9, sp",
    "msr spsel, #1",
    "mov sp, x9",
    "mov x29, xzr",
    "mov x30, xzr",
    "bl urmqtt_kmain",
    "1: wfi",
    "b 1b",
    ".text",
);
