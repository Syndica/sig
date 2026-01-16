#!/bin/bash

CC="../toolchain/llvm/bin/clang"
LD="../toolchain/llvm/bin/ld.lld"
ZIG=${ZIG:-zig}

if [ "$($ZIG version)" != "0.14.1" ]; then
    echo "Need Zig 0.14.1 to compile these tests"
    exit 1
fi

LD_FLAGS="${LD} -z notext -shared --Bdynamic -entry entrypoint"
C_FLAGS="-Werror -target sbf -O2 -fno-builtin -fPIC -Wno-override-module"
C_FLAGS_V3="${C_FLAGS} -mcpu=v3"

CC_V0="${CC} ${C_FLAGS}"
CC_V2="${CC} ${C_FLAGS_V3}"

LD_V0="${LD_FLAGS} --script data/test-elfs/elf_sbpfv0.ld"
LD_V2="${LD_FLAGS} -Bsymbolic --script data/test-elfs/elf.ld"

V0_FILES=(reloc_64_64 
          reloc_64_relative 
          reloc_64_relative_data 
          rodata_section 
          bss_section 
          data_section 
          syscall_reloc_64_32
          struct_func_pointer
          hash_collision
          relative_call)
          
EXCLUDE_V2=(bss_section data_section 
            syscall_reloc_64_32
            hash_collision
            relative_call)

for ZIG_FILE in data/test-elfs/*.zig; do
    BASE_NAME=$(basename "$ZIG_FILE" .zig)
    
    $ZIG build-obj "$ZIG_FILE" -target bpfel-freestanding -OReleaseSmall -fstrip -fno-emit-bin -femit-llvm-bc="data/test-elfs/${BASE_NAME}.bc"
    if [[ ! " ${EXCLUDE_V2[@]} " =~ " ${BASE_NAME} " ]]; then
        $CC_V2 "data/test-elfs/${BASE_NAME}.bc" -c -o "data/test-elfs/${BASE_NAME}.o"
        $LD_V2 "data/test-elfs/${BASE_NAME}.o" -o "data/test-elfs/${BASE_NAME}.so"
    fi
    
    if [[ " ${V0_FILES[@]} " =~ " ${BASE_NAME} " ]]; then
        $CC_V0 "data/test-elfs/${BASE_NAME}.bc" -c -o "data/test-elfs/${BASE_NAME}_sbpfv0.o"
        $LD_V0 "data/test-elfs/${BASE_NAME}_sbpfv0.o" -o "data/test-elfs/${BASE_NAME}_sbpfv0.so"
    fi
done

rm data/test-elfs/*.o
rm data/test-elfs/*.bc
