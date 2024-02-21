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
#include "heap.h"
#include "printf.h"

void test_heap_overflow(void) {
  int oob_index = 18;
  int size = 17;
  unsigned char *ptr = malloc(size);
  printf("\nKASan test: heap OOB write\n");
  printf("Writing 1 byte at offset %d in %d-byte heap buffer allocated at %x\n",
         oob_index, size, ptr);
  ptr[oob_index] = 0;
}

char oob_value;

void test_stack_overflow(void) {
  char buffer[17];
  int oob_index = 18;
  printf("\nKASan test: stack OOB read\n");
  printf("Reading 1 byte at offset %d in %d-byte stack buffer at %x\n",
         oob_index, sizeof(buffer), buffer);
  oob_value = buffer[oob_index];
}

int global_array[17];

void test_globals_overflow(void) {
  int oob_index = 18;
  printf("\nKASan test: global OOB write\n");
  printf(
      "Writing an integer at index %d in %d-element global integer array at "
      "%x\n",
      oob_index, sizeof(global_array) / sizeof(int), global_array);
  global_array[oob_index] = 0;
}

char global_char_buffer[17];

void test_memset_overflow(void) {
  int oob_size = 18;
  printf("\nKASan test: memset OOB write in globals\n");
  printf("Memsetting global %d-byte buffer at %x with %d values of 0xaa\n",
         sizeof(global_char_buffer), global_char_buffer, oob_size);
  memset(global_char_buffer, 0xaa, oob_size);
}

void test_memcpy_overflow(void) {
  char buffer[18];
  int oob_size = sizeof(buffer);
  printf("\nKASan test: memcpy OOB read from globals\n");
  printf("Memcopying %d bytes from %d-byte global buffer into local array\n",
         oob_size, sizeof(global_char_buffer));
  memcpy(buffer, global_char_buffer, oob_size);
}