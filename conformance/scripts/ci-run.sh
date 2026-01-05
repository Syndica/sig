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
. env/pyvenv/bin/activate

echo Get test fixtures
wget https://github.com/Syndica/conformance-fixtures/releases/download/test-vectors-$TEST_VECTORS_COMMIT-solfuzz-agave-$SOLFUZZ_AGAVE_COMMIT/fixtures.tar.zst
tar xf fixtures.tar.zst
# We need each fixture file to have a unique name so that we can put them into the test-inputs directory
# in a "flat" manner. The problem is that there are just too many files and it exceeds ARG_MAX for a single
# "rename" invocation. So we need to go the round-about method of first finding the files then using "xargs"
# to chunk it MAX-ARGS. Testing shows that just using the maximum number from xargs is around twice as fast
# as specifying an arg limit manually.
find test-fixtures/vm_interp/fixtures/v0 -type f -name '*.fix' -print0 | xargs -0 rename "s/\.fix\$/-v0.fix/"
find test-fixtures/vm_interp/fixtures/v1 -type f -name '*.fix' -print0 | xargs -0 rename "s/\.fix\$/-v1.fix/"
find test-fixtures/vm_interp/fixtures/v2 -type f -name '*.fix' -print0 | xargs -0 rename "s/\.fix\$/-v2.fix/"

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
    done < <(find "test-fixtures/$dir" -type f -name '*.fix' -print0)
done

mkdir -p split-fixtures/
printf "%s\n" "${FIXTURES[@]}" \
    | circleci tests split \
    | xargs -d '\n' -I{} cp "{}" split-fixtures/
set -x

export LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8
export ASAN_OPTIONS=detect_leaks=0

echo "Running fixtures"
solana-test-suite exec-fixtures \
    -t ${PREBUILT_LIB_DIR}/libsolfuzz_sig.so \
    -o "test_results/" \
    -i split-fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
