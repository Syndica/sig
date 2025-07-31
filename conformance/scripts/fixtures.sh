#!/bin/bash

PASSING_DIRS=(
    "elf_loader/fixtures"

    "syscall/fixtures/abort"
    "syscall/fixtures/alt_bn128"
    "syscall/fixtures/blake3"
    "syscall/fixtures/cpi"
    "syscall/fixtures/create_program_address"
    "syscall/fixtures/curve25519"
    "syscall/fixtures/get_epoch_schedule"
    "syscall/fixtures/get_return_data"
    "syscall/fixtures/keccak256"
    "syscall/fixtures/log"
    "syscall/fixtures/log_data"
    "syscall/fixtures/memcmp"
    "syscall/fixtures/memcpy"
    "syscall/fixtures/memmove"
    "syscall/fixtures/memset"
    "syscall/fixtures/panic"
    "syscall/fixtures/poseidon"
    "syscall/fixtures/sha256"
    "syscall/fixtures/sol_get_sysvar"
    "syscall/fixtures/stack_height"
    "syscall/fixtures/try_find_program_address"
    "syscall/fixtures/vm"

    # Unimplemented
    # "syscall/fixtures/secp256k1"

    "instr/fixtures/zk_sdk"
    "instr/fixtures/unknown"
    "instr/fixtures/compute-budget"

    "instr/fixtures/bpf-address-lookup-table"
    "instr/fixtures/bpf-config"
    "instr/fixtures/bpf-loader"
    "instr/fixtures/bpf-loader-v1-programs"
    "instr/fixtures/bpf-loader-v2"
    "instr/fixtures/bpf-loader-v2-programs"
    "instr/fixtures/bpf-loader-v3"

    # Passed: 0, Failed: 6934, Skipped: 0 (unimplemented)
    # "instr/fixtures/stake"

    # Passed: 7750, Failed: 5, Skipped: 0
    # "instr/fixtures/vote"

    # Passed: 5077, Failed: 248, Skipped: 0 (also takes a long time to run)
    # "instr/fixtures/system"

    # Passed: 461, Failed: 48, Skipped: 0
    # "instr/fixtures/bpf-loader-v3-programs"

    # Passed: 369, Failed: 2, Skipped: 0
    # "instr/fixtures/bpf-loader-upgradeable-v1-programs"

    # Passed: 19, Failed: 20, Skipped: 0
    # "vm_interp/fixtures/latest"

    "vm_interp/fixtures/v0"
    "vm_interp/fixtures/v1"
    "vm_interp/fixtures/v2"

    # Passed: 36252, Failed: 9, Skipped: 0 
    # "vm_interp/fixtures/v3"
)

PASSING_TXN_FIXTURES=(
    "./test-vectors/txn/fixtures/programs/00c2dcfbd00415d3c531a19ef26901f64261e339_265678.fix"
    "./test-vectors/txn/fixtures/programs/010e42e1d45c642f8739cf5aead3d7574d9047ed_265678.fix"
    "./test-vectors/txn/fixtures/programs/012c43064dff9a35dc033f7a83bc755574b0a255_265678.fix"
    "./test-vectors/txn/fixtures/programs/0103115bd3ec4f27fcf4dbd7cee22a530e68f797_2135631.fix"
    "./test-vectors/txn/fixtures/programs/0183b6cda71f09f58bcb5164828a9597a839869d_2211742.fix"
    "./test-vectors/txn/fixtures/programs/019cd344312d03b3abd6414315b0ccf5dd722cad_265678.fix"
    "./test-vectors/txn/fixtures/programs/01c457becc9df90ae0e14a274b1d803b343a9e86_265678.fix"
    "./test-vectors/txn/fixtures/programs/01d7494b4d7dd492421e8267de2a5a70ab86ab22_553257.fix"
)

FIXTURES=("${PASSING_TXN_FIXTURES[@]}")

for dir in "${PASSING_DIRS[@]}"; do
  while IFS= read -r -d '' file; do
    FIXTURES+=("$file")
  done < <(find "./test-vectors/$dir" -type f -name '*.fix' -print0)
done

mkdir -p test-inputs/
printf "%s\n" "${FIXTURES[@]}" \
  | circleci tests split \
  | xargs -d '\n' -I{} cp "{}" test-inputs/

cd solana-conformance
source test_suite_env/bin/activate

export LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8
export ASAN_OPTIONS=detect_leaks=0

echo "Generating fixtures"
solana-test-suite create-fixtures \
-s ../libsolfuzz_agave.so \
-i "../test-inputs"

echo "Running fixtures"
solana-test-suite exec-fixtures \
-t ../conformance/zig-out/lib/libsolfuzz_sig.so \
-i test_fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
