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

#define KASAN_SHADOW_SHIFT 3
#define KASAN_SHADOW_GRANULE_SIZE (1UL << KASAN_SHADOW_SHIFT)
#define KASAN_SHADOW_MASK (KASAN_SHADOW_GRANULE_SIZE - 1)

#define ASAN_SHADOW_UNPOISONED_MAGIC 0x00
#define ASAN_SHADOW_RESERVED_MAGIC 0xff
#define ASAN_SHADOW_GLOBAL_REDZONE_MAGIC 0xf9
#define ASAN_SHADOW_HEAP_HEAD_REDZONE_MAGIC 0xfa
#define ASAN_SHADOW_HEAP_TAIL_REDZONE_MAGIC 0xfb
#define ASAN_SHADOW_HEAP_FREE_MAGIC 0xfd

#define KASAN_HEAP_HEAD_REDZONE_SIZE 0x20
#define KASAN_HEAP_TAIL_REDZONE_SIZE 0x20

#define KASAN_MEM_TO_SHADOW(addr) \
  (((addr) >> KASAN_SHADOW_SHIFT) + KASAN_SHADOW_MAPPING_OFFSET)
#define KASAN_SHADOW_TO_MEM(shadow) \
  (((shadow) - KASAN_SHADOW_MAPPING_OFFSET) << KASAN_SHADOW_SHIFT)

void kasan_bug_report(unsigned long addr, size_t size,
                      unsigned long buggy_shadow_address, uint8_t is_write,
                      unsigned long ip);

static inline unsigned long get_poisoned_shadow_address(unsigned long addr,
                                                        size_t size) {
  unsigned long addr_shadow_start = KASAN_MEM_TO_SHADOW(addr);
  unsigned long addr_shadow_end = KASAN_MEM_TO_SHADOW(addr + size - 1) + 1;
  unsigned long non_zero_shadow_addr = 0;

  for (unsigned long i = 0; i < addr_shadow_end - addr_shadow_start; i++) {
    if (*(uint8_t *)(addr_shadow_start + i) != 0) {
      non_zero_shadow_addr = addr_shadow_start + i;
      break;
    }
  }

  if (non_zero_shadow_addr) {
    unsigned long last_byte = addr + size - 1;
    int8_t *last_shadow_byte = (int8_t *)KASAN_MEM_TO_SHADOW(last_byte);

    // Non-zero bytes in shadow memory may indicate either:
    //  1) invalid memory access (0xff, 0xfa, ...)
    //  2) access to a 8-byte region which isn't entirely accessible, i.e. only
    //     n bytes can be read/written in the 8-byte region, where n < 8
    //     (in this case shadow byte encodes how much bytes in an 8-byte region
    //     are accessible).
    // Thus, if there is a non-zero shadow byte we need to check if it
    // corresponds to the last byte in the checked region:
    //   not last - OOB memory access
    //   last - check if we don't access beyond what's encoded in the shadow
    //          byte.
    if (non_zero_shadow_addr != (unsigned long)last_shadow_byte ||
        ((int8_t)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow_byte))
      return non_zero_shadow_addr;
  }

  return 0;
}

// Both `address` and `size` must be 8-byte aligned.
static void poison_shadow(unsigned long address, size_t size, uint8_t value) {
  unsigned long shadow_start, shadow_end;
  size_t shadow_length = 0;

  shadow_start = KASAN_MEM_TO_SHADOW(address);
  shadow_end = KASAN_MEM_TO_SHADOW(address + size - 1) + 1;
  shadow_length = shadow_end - shadow_start;

  memset((void *)shadow_start, value, shadow_length);
}

// `address` must be 8-byte aligned
static void unpoison_shadow(unsigned long address, size_t size) {
  poison_shadow(address, size & (~KASAN_SHADOW_MASK),
                ASAN_SHADOW_UNPOISONED_MAGIC);

  if (size & KASAN_SHADOW_MASK) {
    uint8_t *shadow = (uint8_t *)KASAN_MEM_TO_SHADOW(address + size);
    *shadow = size & KASAN_SHADOW_MASK;
  }
}

static inline int kasan_check_memory(unsigned long addr, size_t size,
                                     uint8_t write, unsigned long pc) {
  int buggy_shadow_address;
  if (size == 0) return 1;

  // there is 256 MB of RAM starting at 0x40000000
  if (addr < TARGET_DRAM_START || addr > TARGET_DRAM_END) return 1;

  buggy_shadow_address = get_poisoned_shadow_address(addr, size);
  if (buggy_shadow_address == 0) return 1;

  kasan_bug_report(addr, size, buggy_shadow_address, write, pc);
  return 0;
}

// Implement necessary routines for KASan sanitization of globals.

// See struct __asan_global definition at
// https://github.com/llvm-mirror/compiler-rt/blob/master/lib/asan/asan_interface_internal.h.
struct kasan_global_info {
  // Starting address of the variable
  const void *start;
  // Variable size
  size_t size;
  // 32-bit aligned size of global including the redzone
  size_t size_with_redzone;
  // Symbol name
  const void *name;
  const void *module_name;
  unsigned long has_dynamic_init;
  void *location;
  unsigned int odr_indicator;
};

static void asan_register_global(struct kasan_global_info *global) {
  unpoison_shadow((unsigned long)global->start, global->size);

  size_t aligned_size = (global->size + KASAN_SHADOW_MASK) & ~KASAN_SHADOW_MASK;
  poison_shadow((unsigned long)global->start + aligned_size,
                global->size_with_redzone - aligned_size,
                ASAN_SHADOW_GLOBAL_REDZONE_MAGIC);
}

void __asan_register_globals(struct kasan_global_info *globals, size_t size) {
  for (size_t i = 0; i < size; i++) asan_register_global(&globals[i]);
}

void __asan_unregister_globals(void *globals, size_t size) {}

// Empty placeholder implementation to supress linker error for undefined symbol
void __asan_handle_no_return(void) {}

// KASan memcpy/memset hooks.

void *__kasan_memcpy(void *dst, const void *src, unsigned int size,
                     unsigned long pc) {
  kasan_check_memory((unsigned long)dst, size, /*is_write*/ true, pc);
  kasan_check_memory((unsigned long)src, size, /*is_write*/ false, pc);

  return memcpy(dst, src, size);
}

void *__kasan_memset(void *buf, int c, unsigned int size, unsigned long pc) {
  kasan_check_memory((unsigned long)buf, size, /*is_write*/ true, pc);

  return memset(buf, c, size);
}

// Implement KASan heap management hooks.

struct KASAN_HEAP_HEADER {
  unsigned int aligned_size;
};

void *kasan_malloc_hook(unsigned int size) {
  struct KASAN_HEAP_HEADER *kasan_heap_hdr = NULL;
  unsigned int algined_size = (size + KASAN_SHADOW_MASK) & (~KASAN_SHADOW_MASK);
  unsigned int total_size = algined_size + KASAN_HEAP_HEAD_REDZONE_SIZE +
                            KASAN_HEAP_TAIL_REDZONE_SIZE;

  void *ptr = allocate_chunk(total_size);
  if (ptr == NULL) return NULL;

  kasan_heap_hdr = (struct KASAN_HEAP_HEADER *)ptr;
  kasan_heap_hdr->aligned_size = algined_size;

  unpoison_shadow((unsigned long)(ptr + KASAN_HEAP_HEAD_REDZONE_SIZE), size);
  poison_shadow((unsigned long)ptr, KASAN_HEAP_HEAD_REDZONE_SIZE,
                ASAN_SHADOW_HEAP_HEAD_REDZONE_MAGIC);
  poison_shadow(
      (unsigned long)(ptr + KASAN_HEAP_HEAD_REDZONE_SIZE + algined_size),
      KASAN_HEAP_TAIL_REDZONE_SIZE, ASAN_SHADOW_HEAP_TAIL_REDZONE_MAGIC);

  return ptr + KASAN_HEAP_HEAD_REDZONE_SIZE;
}

void kasan_free_hook(void *ptr) {
  struct KASAN_HEAP_HEADER *kasan_heap_hdr = NULL;
  unsigned int aligned_size = 0;

  if (ptr == NULL) return;

  kasan_heap_hdr =
      (struct KASAN_HEAP_HEADER *)(ptr - KASAN_HEAP_HEAD_REDZONE_SIZE);
  aligned_size = kasan_heap_hdr->aligned_size;

  free_chunk(kasan_heap_hdr);
  poison_shadow((unsigned long)ptr, aligned_size, ASAN_SHADOW_HEAP_FREE_MAGIC);

  return;
}

// Implement KAsan error reporting routines.

static void kasan_print_16_bytes_no_bug(const char *prefix,
                                        unsigned long address) {
  printf("%s0x%X:", prefix, address);
  for (int i = 0; i < 16; i++) printf(" %02X", *(uint8_t *)(address + i));
  printf("\n");
}

static void kasan_print_16_bytes_with_bug(const char *prefix,
                                          unsigned long address,
                                          int buggy_offset) {
  printf("%s0x%X:", prefix, address);
  for (int i = 0; i < buggy_offset; i++)
    printf(" %02X", *(uint8_t *)(address + i));
  printf("[%02X]", *(uint8_t *)(address + buggy_offset));
  if (buggy_offset < 15)
    printf("%02X", *(uint8_t *)(address + buggy_offset + 1));
  for (int i = buggy_offset + 2; i < 16; i++)
    printf(" %02X", *(uint8_t *)(address + i));
  printf("\n");
}

static void kasan_print_shadow_memory(unsigned long address, int range_before,
                                      int range_after) {
  unsigned long shadow_address = KASAN_MEM_TO_SHADOW(address);
  unsigned long aligned_shadow = shadow_address & 0xfffffff0;
  int buggy_offset = shadow_address - aligned_shadow;

  printf("[KASan] Shadow bytes around the buggy address 0x%X (shadow 0x%X):\n",
         address, shadow_address);

  for (int i = range_before; i > 0; i--) {
    kasan_print_16_bytes_no_bug("[KASan]   ", aligned_shadow - i * 16);
  }

  kasan_print_16_bytes_with_bug("[KASan] =>", aligned_shadow, buggy_offset);

  for (int i = 1; i <= range_after; i++) {
    kasan_print_16_bytes_no_bug("[KASan]   ", aligned_shadow + i * 16);
  }
}

void kasan_bug_report(unsigned long addr, size_t size,
                      unsigned long buggy_shadow_address, uint8_t is_write,
                      unsigned long ip) {
  unsigned long buggy_address = KASAN_SHADOW_TO_MEM(buggy_shadow_address);
  printf("[KASan] ===================================================\n");
  printf(
      "[KASan] ERROR: Invalid memory access: address 0x%X, size 0x%X, is_write "
      "%d, ip 0x%X\n",
      addr, size, is_write, ip);

  kasan_print_shadow_memory(buggy_address, 3, 3);
}

void initialize_kasan(void) {
  // Mark shadow memory region not accessible by the sanitized code.
  poison_shadow(KASAN_SHADOW_MEMORY_START, KASAN_SHADOW_MEMORY_SIZE,
                ASAN_SHADOW_RESERVED_MAGIC);
}

// Define KASan handlers exposed used by the compiler instrumentation.

void __asan_loadN_noabort(unsigned int addr, unsigned int size) {
  kasan_check_memory(addr, size, /*is_write*/ false, CALLER_PC);
}

void __asan_storeN_noabort(unsigned int addr, size_t size) {
  kasan_check_memory(addr, size, /*is_write*/ true, CALLER_PC);
}

#define DEFINE_KASAN_LOAD_STORE_ROUTINES(size)                     \
  void __asan_load##size##_noabort(unsigned long addr) {           \
    kasan_check_memory(addr, size, /*is_write*/ false, CALLER_PC); \
  }                                                                \
  void __asan_store##size##_noabort(unsigned long addr) {          \
    kasan_check_memory(addr, size, /*is_write*/ true, CALLER_PC);  \
  }

DEFINE_KASAN_LOAD_STORE_ROUTINES(1)
DEFINE_KASAN_LOAD_STORE_ROUTINES(2)
DEFINE_KASAN_LOAD_STORE_ROUTINES(4)
DEFINE_KASAN_LOAD_STORE_ROUTINES(8)
DEFINE_KASAN_LOAD_STORE_ROUTINES(16)

// Local variable KASan instrumentation
#define DEFINE_KASAN_SET_SHADOW_ROUTINE(byte)              \
  void __asan_set_shadow_##byte(void *addr, size_t size) { \
    memset(addr, 0x##byte, size);                          \
  }

DEFINE_KASAN_SET_SHADOW_ROUTINE(00)  // addressable memory
DEFINE_KASAN_SET_SHADOW_ROUTINE(f1)  // stack left redzone
DEFINE_KASAN_SET_SHADOW_ROUTINE(f2)  // stack mid redzone
DEFINE_KASAN_SET_SHADOW_ROUTINE(f3)  // stack right redzone