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

#ifndef __KASAN_HEAP_H__
#define __KASAN_HEAP_H__

void initialize_heap(void);

void *allocate_chunk(unsigned long size);
void free_chunk(void *ptr);

void *malloc(unsigned long size);
void free(void *ptr);

#endif  // __KASAN_HEAP_H__