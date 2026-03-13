#!/usr/bin/env bash
# This script runs the `solana_conformance` step in CI.
set -euxo pipefail

PREBUILT_LIB_DIR=${PREBUILT_LIB_DIR:-../workspace/conformance-release/lib}
NUM_THREADS=${NUM_THREADS:-$(nproc || sysctl -n hw.ncpu || echo 1)}

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir
. commits.env

echo Setup solana-conformance
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt install -y python3.11 python3.11-dev python3.11-venv rename gcc
scripts/setup-env.sh get-solana-conformance
scripts/setup-env.sh get-test-vectors

echo Parse fixture lists
PASSING_DIRS=()

set +x
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        PASSING_DIRS+=("$line")
    fi
done < "scripts/fixtures.txt"

FIXTURES=()

for dir in "${PASSING_DIRS[@]}"; do
    while IFS= read -r -d '' file; do
        FIXTURES+=("$file")
    done < <(find "test-vectors/$dir" -type f -name '*.fix' -print0)
done

mkdir -p split-fixtures/
printf "%s\n" "${FIXTURES[@]}" \
    | circleci tests split \
    | xargs -d '\n' -I{} cp "{}" split-fixtures/
set -x

export LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8
export ASAN_OPTIONS=detect_leaks=0

echo "Running fixtures"
env/pyvenv/bin/solana-conformance exec-fixtures \
    --num-processes $NUM_THREADS \
    -t ${PREBUILT_LIB_DIR}/libsolfuzz_sig.so \
    -o test_results/ \
    -i split-fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
