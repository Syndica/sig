#!/bin/bash

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
-i test_fixtures/
