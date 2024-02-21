# Bare-metal KASan implementation

*This is not an officially supported Google product.*

This project demonstrates how to enable Kernel Address Sanitizer (KASan) for
bare-metal code running on ARM, RISC-V and x86 architectures. It implements a
set of KASan test cases that catch various classes of memory corruption bugs
at runtime.

The implementation of KASan run-time routines in this project is inspired by
the corresponding implementation of
[KASan](https://www.kernel.org/doc/html/v4.14/dev-tools/kasan.html) in Linux
kernel.

## Prerequisites

To build and run the program you would need to use LLVM toolchain (`clang` and
`ld.lld`) for cross complitation and QEMU system emulator for supported
architectures.

For example, here are the necessary Debian package names needed to build and
run the project:

```
sudo apt-get install build-essential gcc-multilib llvm clang lld \
                     qemu-system-arm qemu-system-misc qemu-system-x86
```

## Project layout

The project constists of the following components:

* `kasan_test.c` -- main test driver which runs KASan test cases
* `sanitized_lib.c` -- this module implements the test cases and is built with
                    the KASan instrumentation
* `kasan.c` -- implementation of runtime routines needed for KASan sanitizer
* `heap.c` -- simple implementation of heap management routines for testing
              KASan
* `third_party/printf.c` -- a compact implementation of `printf` function
* `rt_utils.c` -- run-time utility functions
* `start_arch.S` -- architecture-specific low-level entry point in assembly
                    for the bare-metal program
* `kasan_test.ld` -- linker script for the program
* `Makefile` -- in addition to instructions on how to build and run the project
              this file contains definitions of some important parameters,
              such as KASan shadow memory address, DRAM start address and KASan
              configuration options.
* `Makefile.arch` -- Makefile fragments whith architecture-specific parameters
                     for building and running the project in the emulator


## Running

To build and execute the test suite run `ARCH=target_arch make clean run`
where `target_arch` is one of the supported architectures: `arm`, `aarch64`,
`riscv32`, `riscv64` and `x86`. If the target architecture isn't specified
(i.e. `make clean run`) then `arm` is assumed as default option.

As an example, running `make clean run` should build the bare-metal program
and execute it in QEMU ARM system emulator with the following expected output:

```
qemu-system-arm -M virt-8.2 -cpu cortex-a7 -m 256M -nographic -kernel kasan_test
Starting bare-metal KASan test driver.

KASan test: heap OOB write
Writing 1 byte at offset 18 in 17-byte heap buffer allocated at 40004020
[KASan] ===================================================
[KASan] ERROR: Invalid memory access: address 0x40004032, size 0x1, is_write 1, ip 0x40000D98
[KASan] Shadow bytes around the buggy address 0x40004030 (shadow 0x4A700806):
[KASan]   0x4A7007D0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7007E0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7007F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan] =>0x4A700800: FA FA FA FA 00 00[01]FB FB FB FB 00 00 00 00 00
[KASan]   0x4A700810: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A700820: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A700830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

KASan test: stack OOB read
Reading 1 byte at offset 18 in 17-byte stack buffer at 40014f90
[KASan] ===================================================
[KASan] ERROR: Invalid memory access: address 0x40014FA2, size 0x1, is_write 0, ip 0x40000E6C
[KASan] Shadow bytes around the buggy address 0x40014FA0 (shadow 0x4A7029F4):
[KASan]   0x4A7029C0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7029D0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7029E0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan] =>0x4A7029F0: F1 F1 00 00[01]F3 F3 F3 F3 F3 00 00 00 00 00 00
[KASan]   0x4A702A00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A702A10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A702A20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

KASan test: global OOB write
Writing an integer at index 18 in 17-element global integer array at 400035a0
[KASan] ===================================================
[KASan] ERROR: Invalid memory access: address 0x400035E8, size 0x4, is_write 1, ip 0x40000F38
[KASan] Shadow bytes around the buggy address 0x400035E8 (shadow 0x4A7006BD):
[KASan]   0x4A700680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A700690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006A0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan] =>0x4A7006B0: 01 F9 F9 F9 00 00 00 00 00 00 00 00 04[F9]F9 F9
[KASan]   0x4A7006C0: F9 F9 F9 F9 00 00 01 F9 F9 F9 F9 F9 00 00 00 00
[KASan]   0x4A7006D0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006E0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

KASan test: memset OOB write in globals
Memsetting global 17-byte buffer at 40003620 with 18 values of 0xaa
[KASan] ===================================================
[KASan] ERROR: Invalid memory access: address 0x40003620, size 0x12, is_write 1, ip 0x40000D1C
[KASan] Shadow bytes around the buggy address 0x40003630 (shadow 0x4A7006C6):
[KASan]   0x4A700690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006A0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006B0: 01 F9 F9 F9 00 00 00 00 00 00 00 00 04 F9 F9 F9
[KASan] =>0x4A7006C0: F9 F9 F9 F9 00 00[01]F9 F9 F9 F9 F9 00 00 00 00
[KASan]   0x4A7006D0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006E0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

KASan test: memcpy OOB read from globals
Memcopying 18 bytes from 17-byte global buffer into local array
[KASan] ===================================================
[KASan] ERROR: Invalid memory access: address 0x40003620, size 0x12, is_write 0, ip 0x40000D20
[KASan] Shadow bytes around the buggy address 0x40003630 (shadow 0x4A7006C6):
[KASan]   0x4A700690: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006A0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006B0: 01 F9 F9 F9 00 00 00 00 00 00 00 00 04 F9 F9 F9
[KASan] =>0x4A7006C0: F9 F9 F9 F9 00 00[01]F9 F9 F9 F9 F9 00 00 00 00
[KASan]   0x4A7006D0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006E0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[KASan]   0x4A7006F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Press ctrl + a then x to exit.
```