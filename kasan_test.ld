/*
 * Copyright 2024 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifdef TARGET_ARCH_arm
OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
OUTPUT_ARCH(arm)
#endif

#ifdef TARGET_ARCH_aarch64
OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
#endif

#ifdef TARGET_ARCH_riscv32
OUTPUT_FORMAT("elf32-littleriscv", "elf32-littleriscv", "elf32-littleriscv")
OUTPUT_ARCH(riscv)
#endif

#ifdef TARGET_ARCH_riscv64
OUTPUT_FORMAT("elf64-littleriscv", "elf64-littleriscv", "elf64-littleriscv")
OUTPUT_ARCH(riscv)
#endif

#ifdef TARGET_ARCH_x86
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
#endif

ENTRY(reset_handler)
SECTIONS
{
  . = TARGET_DRAM_START;

  .start : { *(.reset) }
  .text : { *(.text) }
  .rodata : { *(.rodata*) }

  .init_array : {
    __global_ctors_start = .;
    *(.init_array*)
    __global_ctors_end = .;
 }

  .data : { *(.data) }
  .bss : { *(.bss COMMON) }

  . = ALIGN(0x1000);
  __heap_start = .;
  . = . + 0x10000;
  __heap_end = .;

  . = . + 0x1000;
  __stack_top = .;

  . = KASAN_SHADOW_MEMORY_START;
  __kasan_shadow_memory_start = .;
  . = . + KASAN_SHADOW_MEMORY_SIZE;
  __kasan_shadow_memory_end = .;
}