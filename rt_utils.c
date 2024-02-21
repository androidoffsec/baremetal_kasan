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

#include "common.h"

void my_memset(void *dest, int c, unsigned long n) {
  unsigned char *ptr = (unsigned char *)dest;
  for (size_t i = 0; i < n; i++) ptr[i] = (unsigned char)c;
}

void my_memcpy(void *dest, const void *src, unsigned long n) {
  unsigned char *ptr_dest = (unsigned char *)dest;
  const unsigned char *ptr_src = (const unsigned char *)src;
  for (size_t i = 0; i < n; i++) ptr_dest[i] = ptr_src[i];
}

#ifdef TARGET_ARCH_arm

void __aeabi_memset(void *dest, unsigned long n, int c) {
  my_memset(dest, c, n);
}

void __aeabi_memclr(void *dest, unsigned long n) { my_memset(dest, 0, n); }

void __aeabi_memcpy(void *dest, const void *src, unsigned long n) {
  my_memcpy(dest, src, n);
}

#endif  // TARGET_ARCH_arm

void *memset(void *dest, int c, unsigned long n) {
  my_memset(dest, c, n);
  return dest;
}

void *memcpy(void *dest, const void *src, unsigned long n) {
  my_memcpy(dest, src, n);
  return dest;
}

typedef void (*global_ctor)(void);

// These symbols are defined in the linker script.
extern char __global_ctors_start;
extern char __global_ctors_end;

void call_global_ctors(void) {
  global_ctor *ctor = (global_ctor *)&__global_ctors_start;

  while (ctor != (global_ctor *)&__global_ctors_end) {
    (*ctor)();
    ctor++;
  }
}

#ifdef TARGET_ARCH_x86

void _putchar(char c) {
  uint16_t com1_port = 0x3f8;
  asm("outb %0, %1" : : "a"(c), "Nd"(com1_port));
}

#else  // TARGET_ARCH_x86

// Macro UART_BASE_ADDRESS is defined in Makefile.$(ARCH) file
void _putchar(char character) {
  volatile unsigned int *UART0DR_ADDRESS =
      (volatile unsigned int *)UART_BASE_ADDRESS;
  *UART0DR_ADDRESS = (unsigned int)character;
}

#endif  // TARGET_ARCH_x86