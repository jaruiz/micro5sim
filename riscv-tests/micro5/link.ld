OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
  . = 0x80000000;
  .text.init : { *(.text.init) }
  .text : { *(.text) }

  . = 0x80004000;
  .data : { *(.data) }
  .data.string : { *(.data.string)}
  .tohost : { *(.tohost) }
  .bss : { *(.bss) }
  _end = .;
}

