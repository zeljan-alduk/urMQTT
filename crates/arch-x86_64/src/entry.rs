//! The ELF entry point (X2).
//!
//! Limine enters in 64-bit long mode, ring 0, interrupts off, with the
//! kernel and the memory map in its page tables (HHDM) and a bootloader
//! stack. `_start` does what must happen before any Rust code runs:
//!
//! 1. switches to a stack of the kernel's own (the bootloader's memory is
//!    reclaimed later);
//! 2. checks the x86-64-v2 baseline with CPUID, in assembly, because the
//!    kernel is compiled for it and could fault anywhere on a CPU without
//!    it. A CPU that fails prints which features are missing and how to fix
//!    the VM's CPU type on COM1, then powers off (QEMU) or halts;
//! 3. turns on the FPU/SSE state the hard-float kernel needs (CR0.MP/NE/WP,
//!    clear CR0.EM, CR4.OSFXSR/OSXMMEXCPT, default MXCSR);
//! 4. calls the kernel's `urmqtt_kmain`.
//!
//! The text of the refusal is PROMPT-x86_64 section 1's.

#![allow(unsafe_code)]

use crate::features::BASELINE_ECX;

/// Bytes of the boot CPU's first stack.
const BOOT_STACK_SIZE: usize = 128 * 1024;

core::arch::global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
_start:
    cli
    cld
    lea rsp, [rip + urmqtt_boot_stack + {stack_size}]
    xor ebp, ebp

    // x86-64-v2 baseline: every bit of the table must be in CPUID.1:ECX.
    mov eax, 1
    cpuid
    mov r8d, ecx
    lea rdi, [rip + urmqtt_baseline_table]
    mov r9d, {features}
    xor r10d, r10d
.Lscan:
    test r8d, [rdi]
    jnz .Lhave
    inc r10d
.Lhave:
    add rdi, 16
    dec r9d
    jnz .Lscan
    test r10d, r10d
    jnz .Lrefuse

    // x87/SSE for the hard-float kernel.
    mov rax, cr0
    and rax, -5
    or rax, (1 << 1) | (1 << 5) | (1 << 16)
    mov cr0, rax
    mov rax, cr4
    or rax, (1 << 9) | (1 << 10)
    mov cr4, rax
    fninit
    push 0x1f80
    ldmxcsr [rsp]
    add rsp, 8

    call urmqtt_kmain
.Lhalt:
    cli
    hlt
    jmp .Lhalt

    // The CPU is below the baseline: say so on COM1, then power off.
.Lrefuse:
    mov dx, 0x3f9
    xor eax, eax
    out dx, al
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 1
    out dx, al
    mov dx, 0x3f9
    xor eax, eax
    out dx, al
    mov dx, 0x3fb
    mov al, 3
    out dx, al
    mov dx, 0x3fa
    mov al, 0xc7
    out dx, al
    mov dx, 0x3fc
    mov al, 0x0b
    out dx, al
    lea rsi, [rip + urmqtt_baseline_head]
    call .Lputs
    lea rdi, [rip + urmqtt_baseline_table]
    mov r9d, {features}
.Lname:
    test r8d, [rdi]
    jnz .Lnext
    lea rsi, [rdi + 4]
    call .Lputs
.Lnext:
    add rdi, 16
    dec r9d
    jnz .Lname
    lea rsi, [rip + urmqtt_baseline_tail]
    call .Lputs
    // QEMU/KVM ACPI power-off (q35 and pc), then the Bochs/old-QEMU port.
    mov dx, 0x604
    mov ax, 0x2000
    out dx, ax
    mov dx, 0xb004
    mov ax, 0x2000
    out dx, ax
    jmp .Lhalt

    // Prints the NUL-terminated string at rsi to COM1 (polling, bounded).
.Lputs:
    lodsb
    test al, al
    jz .Ldone
    mov ah, al
    mov ecx, 1000000
.Lwait:
    mov dx, 0x3fd
    in al, dx
    test al, 0x20
    jnz .Lsend
    dec ecx
    jnz .Lwait
.Lsend:
    mov al, ah
    mov dx, 0x3f8
    out dx, al
    jmp .Lputs
.Ldone:
    ret

    .section .rodata.boot, "a"
    .balign 16
urmqtt_baseline_table:
    .macro FEAT bit, name
    .balign 16
    .long (1 << \bit)
    .asciz "\name"
    .endm
    FEAT {b0}, " sse3"
    FEAT {b1}, " ssse3"
    FEAT {b2}, " cx16"
    FEAT {b3}, " sse4.1"
    FEAT {b4}, " sse4.2"
    FEAT {b5}, " popcnt"
    .balign 16
urmqtt_baseline_head:
    .asciz "\r\nURMQTT: this CPU does not implement the x86-64-v2 baseline. Missing:"
urmqtt_baseline_tail:
    .asciz "\r\nVM CPU type too old: use `host`, `x86-64-v2-AES` or newer in Proxmox/QEMU (libvirt: host-passthrough). Powering off.\r\n"

    .section .bss.boot_stack, "aw", @nobits
    .balign 16
urmqtt_boot_stack:
    .skip {stack_size}
    "#,
    stack_size = const BOOT_STACK_SIZE,
    features = const BASELINE_ECX.len(),
    b0 = const BASELINE_ECX[0].0,
    b1 = const BASELINE_ECX[1].0,
    b2 = const BASELINE_ECX[2].0,
    b3 = const BASELINE_ECX[3].0,
    b4 = const BASELINE_ECX[4].0,
    b5 = const BASELINE_ECX[5].0,
);
