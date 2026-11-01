/* The dbworker: a static user program in the lower half (ADR-210). One
 * PT_LOAD per permission class (W^X); the kernel maps each with the
 * matching user permissions. Nothing here is shared with the kernel image. */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* R X */
    rodata PT_LOAD FLAGS((1 << 2));            /* R   */
    data   PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* R W */
}

SECTIONS
{
    . = 0x400000;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text
    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :rodata
    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
        *(.dynamic)
    }
}
