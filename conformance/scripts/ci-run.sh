#!/bin/bash

PASSING_DIRS=()

while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        PASSING_DIRS+=("$line")
    fi
done < "$(dirname "${BASH_SOURCE[0]}")/fixtures.txt"

FIXTURES=()

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
