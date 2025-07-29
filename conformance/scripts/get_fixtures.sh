#!/bin/bash

PASSING_DIRS=(
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

    "instr/fixtures/zk_sdk"

    # "vm_interp/fixtures/latest"
    "vm_interp/fixtures/v0"
    "vm_interp/fixtures/v1"
    # "vm_interp/fixtures/v2"
    # "vm_interp/fixtures/v3"

    # Unimplemented
    # "syscall/fixtures/secp256k1"
)

for dir in "${PASSING_DIRS[@]}"; do
  find "./test-vectors/$dir" -type f -name '*.fix'
done
