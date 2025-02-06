#!/bin/bash

CC="../toolchain/llvm/bin/clang"
LD="../toolchain/llvm/bin/ld.lld"
ZIG="zig"


LD_FLAGS="-z notext -shared --Bdynamic --script data/test-elfs/elf.ld"
C_BASE_FLAGS="-target sbf-solana-solana \
    -fno-builtin \
    -fPIC -fno-unwind-tables \
    -fomit-frame-pointer -fno-exceptions \
    -fno-asynchronous-unwind-tables \
    -std=c23 \
    -O2 \
    -Werror \
    -Wno-override-module"
C_FLAGS="${C_BASE_FLAGS} -mcpu=v1"
C_FLAGS_V2="${C_BASE_FLAGS} -mcpu=sbfv2"

CC_V1="${CC} ${C_FLAGS}"
CC_V2="${CC} ${C_FLAGS_V2}"

LD_V1="${LD} ${LD_FLAGS}"
LD_V2="${LD_V1} --section-start=.text=0x100000000"

V1_FILES=(reloc_64_64 reloc_64_relative reloc_64_relative_data rodata_section)

for ZIG_FILE in data/test-elfs/*.zig; do
    BASE_NAME=$(basename "$ZIG_FILE" .zig)
    
    $ZIG build-obj "$ZIG_FILE" -OReleaseSmall -fstrip -fno-emit-bin -femit-llvm-bc="data/test-elfs/${BASE_NAME}.bc"
    $CC_V2 "data/test-elfs/${BASE_NAME}.bc" -c -o "data/test-elfs/${BASE_NAME}.o"
    $LD_V2 "data/test-elfs/${BASE_NAME}.o" -o "data/test-elfs/${BASE_NAME}.so"
    
    if [[ " ${V1_FILES[@]} " =~ " ${BASE_NAME} " ]]; then
        $CC_V1 "data/test-elfs/${BASE_NAME}.bc" -c -o "data/test-elfs/${BASE_NAME}_sbpfv1.o"
        $LD_V1 "data/test-elfs/${BASE_NAME}_sbpfv1.o" -o "data/test-elfs/${BASE_NAME}_sbpfv1.so"
    fi
done

rm data/test-elfs/*.o
rm data/test-elfs/*.bc
