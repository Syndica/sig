/*
 * SBPF v3 linker script (SIMD-0189: stricter ELF headers).
 *
 * Per SIMD-0189 the v3 virtual memory layout is:
 *   .rodata  at  0x0_0000_0000  (slot 0 — MM_RODATA_START)
 *   .text    at  0x1_0000_0000  (slot 1 — MM_BYTECODE_START)
 *   .stack   at  0x2_0000_0000
 *   .heap    at  0x3_0000_0000
 *
 * This swaps the placement of .text and .rodata relative to v0/v1/v2, where
 * .text lives at vaddr 0 and .rodata is appended into the bytecode region.
 * For v3, SIMD-0189 also requires exactly two PT_LOAD segments in this order
 * (rodata then text) — the PHDRS ordering below mirrors that.
 */
SECTIONS
{
  .rodata 0x000000000 : {
    *(.rodata*)
    *(.data.rel.ro*)
    BYTE(0);
    . = ALIGN(8);
  } :rodata
  .text 0x100000000 : {
     *(.text*)
  } :text
  .bss.stack 0x200000000 (NOLOAD) : {
      _stack_start = .;
      . = . + 0x1000;
      _stack_end = .;
      . = ALIGN(8);
   } :stack
  .bss.heap 0x300000000 (NOLOAD) : {
        _heap_start = .;
        . = . + 0x1000;
        _heap_end = .;
        . = ALIGN(8);
   } :heap
   .strtab : { *(.strtab) } :other
  /DISCARD/ : {
      *(.comment*)
      *(.eh_frame*)
      *(*hash*)
      *(.bss*)
      *(.data*)
      *(.rel.dyn*)
      *(.dynamic)
      *(.dynsym)
      *(.dynstr)
    }
}

PHDRS
{
  /* SIMD-0189: rodata segment must precede text in program-header order. */
  rodata PT_LOAD FLAGS(4);
  text PT_LOAD FLAGS(1);
  stack PT_LOAD FLAGS(6);
  heap PT_LOAD FLAGS(6);
  dynsym PT_NULL FLAGS(0);
  other PT_NULL FLAGS(0);
}
