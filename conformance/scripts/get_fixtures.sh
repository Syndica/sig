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

for dir in "${PASSING_DIRS[@]}"; do
  find "./test-vectors/$dir" -type f -name '*.fix'
done
