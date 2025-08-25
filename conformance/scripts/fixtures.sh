#!/bin/bash

PASSING_DIRS=(
    "elf_loader/fixtures"

    # Passed: 35322, Failed: 939, Skipped: 0
    # "vm_interp/fixtures/v0"

    # Passed: 35880, Failed: 381, Skipped: 0
    # "vm_interp/fixtures/v1"

    # Passed: 35958, Failed: 303, Skipped: 0
    # "vm_interp/fixtures/v2"
    
    # Passed: 20, Failed: 8, Skipped: 0
    # "vm_interp/fixtures/latest"

    "syscall/fixtures/abort"
    "syscall/fixtures/alt_bn128"
    "syscall/fixtures/blake3"

    # Passed: 325, Failed: 238, Skipped: 0
    #"syscall/fixtures/cpi"

    "syscall/fixtures/create_program_address"
    "syscall/fixtures/curve25519"
    "syscall/fixtures/get_epoch_schedule"

    # Passed: 0, Failed: 1, Skipped: 0
    # "syscall/fixtures/get_return_data"

    "syscall/fixtures/keccak256"
    "syscall/fixtures/log"
    "syscall/fixtures/log_data"
    "syscall/fixtures/memcmp"

    # Passed: 71, Failed: 3, Skipped: 0
    # "syscall/fixtures/memcpy"

    # Passed: 45, Failed: 9, Skipped: 0
    # "syscall/fixtures/memmove"

    "syscall/fixtures/memset"
    "syscall/fixtures/panic"
    "syscall/fixtures/poseidon"
    "syscall/fixtures/sha256"

    # Passed: 234, Failed: 2, Skipped: 0
    # "syscall/fixtures/sol_get_sysvar"

    "syscall/fixtures/stack_height"
    "syscall/fixtures/try_find_program_address"

    # Passed: 1, Failed: 1, Skipped: 0
    # "syscall/fixtures/vm"
    
    "syscall/fixtures/secp256k1"

    "instr/fixtures/zk_sdk"
    
    # Passed: 27, Failed: 1, Skipped: 0
    # "instr/fixtures/unknown"
    
    "instr/fixtures/compute-budget"
    "instr/fixtures/stake"
    "instr/fixtures/vote"
    "instr/fixtures/system"

    "instr/fixtures/bpf-address-lookup-table"
    "instr/fixtures/bpf-config"
    "instr/fixtures/bpf-loader"
    "instr/fixtures/bpf-loader-v1-programs"
    "instr/fixtures/bpf-loader-v2"
    "instr/fixtures/bpf-loader-v2-programs"

    # Passed: 42, Failed: 304, Skipped: 0
    # "instr/fixtures/bpf-loader-v3"

    "instr/fixtures/bpf-loader-v3-programs"
    "instr/fixtures/bpf-loader-upgradeable-v1-programs"


    # Passed: 4091, Failed: 63, Skipped: 0
    # "txn/fixtures/programs"

    "txn/fixtures/precompile/ed25519"
    "txn/fixtures/precompile/secp256k1"
    "txn/fixtures/precompile/secp256r1"
)

mapfile -t PASSING_TXN_FIXTURES < ./conformance/scripts/passing_txn_fixtures.txt
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
-i "../test-inputs" \
-o "test_fixtures/"

echo "Running fixtures"
solana-test-suite exec-fixtures \
-t ../conformance/zig-out/lib/libsolfuzz_sig.so \
-o "test_results/" \
-i test_fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
