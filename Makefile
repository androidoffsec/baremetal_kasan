# Copyright 2024 Google LLC
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

CC := clang
LD := ld.lld

ARCH ?= arm
SUPPORTED_ARCH := arm aarch64 riscv32 riscv64 x86

ifeq ($(findstring $(ARCH),$(SUPPORTED_ARCH)),)
$(error Unsupported architecture $(ARCH), choose one from $(SUPPORTED_ARCH))
endif

include Makefile.$(ARCH)

CFLAGS := $(CFLAGS_ARCH)
CFLAGS += -ffreestanding

CFLAGS += -DTARGET_ARCH_$(ARCH)
CFLAGS += -DKASAN_SHADOW_MAPPING_OFFSET=$(KASAN_SHADOW_MAPPING_OFFSET)
CFLAGS += -DKASAN_SHADOW_MEMORY_START=$(KASAN_SHADOW_MEMORY_START)
CFLAGS += -DKASAN_SHADOW_MEMORY_SIZE=$(KASAN_SHADOW_MEMORY_SIZE)
CFLAGS += -DTARGET_DRAM_START=$(TARGET_DRAM_START)
CFLAGS += -DTARGET_DRAM_END=$(TARGET_DRAM_END)

CFLAGS += -DPRINTF_DISABLE_SUPPORT_FLOAT
CFLAGS += -DPRINTF_DISABLE_SUPPORT_EXPONENTIAL
CFLAGS += -DPRINTF_DISABLE_SUPPORT_PTRDIFF_T
CFLAGS += -DPRINTF_DISABLE_SUPPORT_LONG_LONG

CFLAGS += -Wno-incompatible-library-redeclaration

CFLAGS += -Ithird_party/printf -I./

LDFLAGS := -nostdlib

# KASan-specific compiler options
KASAN_SANITIZE_STACK := 1
KASAN_SANITIZE_GLOBALS := 1

KASAN_CC_FLAGS := -fsanitize=kernel-address
KASAN_CC_FLAGS += -fno-builtin
KASAN_CC_FLAGS += -mllvm -asan-mapping-offset=$(KASAN_SHADOW_MAPPING_OFFSET)
KASAN_CC_FLAGS += -mllvm -asan-instrumentation-with-call-threshold=0
KASAN_CC_FLAGS += -mllvm -asan-stack=$(KASAN_SANITIZE_STACK)
KASAN_CC_FLAGS += -mllvm -asan-globals=$(KASAN_SANITIZE_GLOBALS)
KASAN_CC_FLAGS += -DKASAN_ENABLED

SRCS := kasan.c \
        heap.c \
        kasan_test.c \
        sanitized_lib.c \
        rt_utils.c \
        start_$(ARCH).S \
        third_party/printf/printf.c

OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.S=.o)

LD_SCRIPT := kasan_test.ld
LD_SCRIPT_GEN := kasan_test.lds

# Use KASAN_CC_FLAGS for the code we would like to cover with KASan
sanitized_lib.o: CFLAGS := $(CFLAGS) $(KASAN_CC_FLAGS)

# This workaround is not needed if you build the project with the LLVM
# toolchain of version 18 and higher (i.e. which includes
# https://github.com/llvm/llvm-project/pull/72933)
sanitized_lib.o: CFLAGS := $(subst $(ARCH_TARGET),$(KASAN_TARGET),$(CFLAGS))

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

$(LD_SCRIPT_GEN): $(LD_SCRIPT)
	$(CC) -E -P -x c $(CFLAGS) $< >> $@

kasan_test: $(LD_SCRIPT_GEN) $(OBJS)
	$(LD) -T $(LD_SCRIPT_GEN) $(LDFLAGS) $(OBJS) -o $@

.PHONY: run
run: kasan_test
	$(QEMU) $<

.PHONY: clean
clean:
	rm -rf kasan_test $(OBJS) $(LD_SCRIPT_GEN)
	rm -rf $(foreach arch,$(SUPPORTED_ARCH),start_$(arch).o)
