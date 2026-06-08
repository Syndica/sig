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

# SIMD-0189 mandates `e_machine = EM_BPF (0xF7)` in the ELF header for SBPF v3,
# and the strict parser in src/vm/elf.zig (parseStrict) rejects anything else,
# matching Agave's load_with_strict_parser:
#   https://github.com/anza-xyz/sbpf/blob/sbpf-v0.14.4-patches/src/elf.rs#L440
#   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0189-sbpf-static-syscalls.md
#
# Our build pipeline goes Zig source -> `zig build-obj -target bpfel-freestanding`
# (LLVM bitcode) -> `clang -target sbf -mcpu=v3` -> ld.lld. The target triple
# baked into the bitcode by Zig wins over clang's later `-target sbf`, so the
# linker writes the legacy `EM_SBPF (0x107)` constant instead of the spec value.
#
# Agave's own test-ELF gen script does not need this patch because it compiles
# Rust sources directly with `rustc --target sbpfv3-solana-solana`, which emits
# `EM_BPF (0xF7)` natively (verified against sbpf/tests/elfs/strict_header.so):
#   https://github.com/anza-xyz/sbpf/blob/sbpf-v0.14.4-patches/tests/elfs/elfs.sh
#
# Until we either (a) move these fixtures to Rust + the sbpfv3 rustc target, or
# (b) get the Zig/LLVM toolchain to stop pinning the machine type through
# bitcode, post-process every v3 (`e_flags == 3`) ELF and rewrite e_machine
# in-place so the produced fixtures are SIMD-0189 compliant.
python3 -c "
import struct, os
for fn in os.listdir('data/test-elfs'):
    if not fn.endswith('.so'): continue
    path = f'data/test-elfs/{fn}'
    with open(path, 'rb') as f:
        e = bytearray(f.read())
    if e[:4] != b'\x7fELF': continue
    e_machine = struct.unpack_from('<H', e, 0x12)[0]
    e_flags = struct.unpack_from('<I', e, 0x30)[0]
    if e_flags == 3 and e_machine == 0x107:
        struct.pack_into('<H', e, 0x12, 0xF7)
        with open(path, 'wb') as f:
            f.write(e)
"
