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

#ifndef __SANITIZED_LIB_H__
#define __SANITIZED_LIB_H__

void test_heap_overflow(void);
void test_stack_overflow(void);
void test_globals_overflow(void);
void test_memset_overflow(void);
void test_memcpy_overflow(void);

#endif  // __SANITIZED_LIB_H__
