#!/bin/bash

CC="${HOME}/local/llvm18-sbpf/bin/clang"
LD="${HOME}/local/llvm18-sbpf/bin/ld.lld"
ZIG="zig"

C_FLAGS="
    -target sbf-solana-solana \
    -mcpu=v1 \
    -fno-builtin \
    -fPIC -fno-unwind-tables \
    -fomit-frame-pointer -fno-exceptions\
    -fno-asynchronous-unwind-tables \
    -std=c23 \
    -O2 \
    -Werror \
    -Wno-override-module"
LD_FLAGS="-z notext -shared --Bdynamic --script data/test-elfs/elf.ld"

CC="${CC} ${C_FLAGS}"
LD="${LD} ${LD_FLAGS}"

$ZIG build-obj data/test-elfs/reloc_64_relative.zig -OReleaseFast -fno-emit-bin -femit-llvm-bc=data/test-elfs/reloc_64_relative.bc

$CC data/test-elfs/reloc_64_relative.bc -c -o data/test-elfs/reloc_64_relative.o
$LD data/test-elfs/reloc_64_relative.o     -o data/test-elfs/reloc_64_relative_sbpfv1.so
