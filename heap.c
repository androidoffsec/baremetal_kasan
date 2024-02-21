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
#include "kasan.h"

// These symbols are defined in the linker script.
extern char __heap_start;
extern char __heap_end;

static void *heap_head;
static size_t heap_size;

void initialize_heap(void) {
  heap_head = (void *)&__heap_start;
  heap_size = (void *)&__heap_end - (void *)&__heap_start;
}

void *allocate_chunk(unsigned long size) {
  void *result = heap_head;
  if (size > heap_size) return NULL;

  size = (size + 7) & (~7UL);
  heap_head += size;
  heap_size -= size;
  return result;
}

void free_chunk(void *ptr) { (void)ptr; }

void *malloc(unsigned long size) { return kasan_malloc_hook(size); }

void free(void *ptr) { return kasan_free_hook(ptr); }