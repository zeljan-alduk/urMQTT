/* urMQTT kernel layout: higher half, one PT_LOAD per permission class (W^X). */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* R X */
    rodata PT_LOAD FLAGS((1 << 2));            /* R   */
    data   PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* R W */
    /* Limine slides a position-independent kernel (KASLR, ADR-173) and finds
     * its relocations through this header. */
    dynamic PT_DYNAMIC;
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    .text : {
        __text_start = .;
        KEEP(*(.text.boot))
        KEEP(*(.text.vectors))
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        /* Read-only after the bootloader has relocated it. */
        *(.data.rel.ro .data.rel.ro.*)
    } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash : { *(.hash) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .rela.dyn : { *(.rela.dyn) *(.rela.*) } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    /* The sealed CPU dispatch (ADR-041): a page of its own, written by the
     * boot CPU through the bootloader's mapping, read-only in the kernel's. */
    .sealed : {
        __sealed_start = .;
        KEEP(*(.data.sealed))
        . = ALIGN(4096);
        __sealed_end = .;
    } :data

    .data : {
        __data_start = .;
        /* Limine requests: the bootloader writes response pointers here. */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
        *(.data .data.*)
        /* GOT entries: the stack protector reaches __stack_chk_guard through one (ADR-171). */
        *(.got .got.*)
    } :data

    .dynamic : { *(.dynamic) } :data :dynamic

    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(4096);
    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
