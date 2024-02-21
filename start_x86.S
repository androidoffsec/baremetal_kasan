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

#define MULTIBOOT_HEADER_MAGIC      0x1BADB002
#define MULTIBOOT_FLAG_PAGE_ALIGN   1
#define MULTIBOOT_FLAG_MEMORY_INFO  2
#define MULTIBOOT_HEADER_FLAGS      (MULTIBOOT_FLAG_PAGE_ALIGN | \
                                     MULTIBOOT_FLAG_MEMORY_INFO)
#define MULTIBOOT_HEADER_CHECKSUM   (0 - MULTIBOOT_HEADER_MAGIC - \
                                     MULTIBOOT_HEADER_FLAGS)

.section .reset, "ax"
    // Start with a multiboot header
    .long MULTIBOOT_HEADER_MAGIC
    .long MULTIBOOT_HEADER_FLAGS
    .long MULTIBOOT_HEADER_CHECKSUM

.global reset_handler
reset_handler:
    mov $__stack_top, %esp
    call main
wait:
    jmp wait