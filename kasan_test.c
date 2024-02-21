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

#include "kasan.h"

#include "heap.h"
#include "printf.h"
#include "rt_utils.h"
#include "sanitized_lib.h"

int main(void) {
  printf("Starting bare-metal KASan test driver.\n");

  // Needed to invoke KASan globals instrumentation.
  call_global_ctors();

  initialize_heap();

  initialize_kasan();

  test_heap_overflow();
  test_stack_overflow();
  test_globals_overflow();
  test_memset_overflow();
  test_memcpy_overflow();

  printf("Press ctrl + a then x to exit.\n");

  return 0;
}
