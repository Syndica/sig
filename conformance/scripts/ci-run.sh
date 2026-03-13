#!/usr/bin/env bash
#
# This script runs the `solana_conformance` step in CI.
#
# To run locally, set these variables:
#   export SPLIT_TESTS=false
#   export PREBUILT_LIB_DIR=zig-out/lib
#
set -euxo pipefail

SPLIT_TESTS=${SPLIT_TESTS:-true}
PREBUILT_LIB_DIR=${PREBUILT_LIB_DIR:-../workspace/conformance-release/lib}
NUM_THREADS=${NUM_THREADS:-$(nproc || sysctl -n hw.ncpu || echo 1)}

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

echo Getting dependencies
if command -v apt &> /dev/null; then
    sudo add-apt-repository ppa:deadsnakes/ppa -y
    sudo apt install -y python3.11 python3.11-dev python3.11-venv rename gcc
fi
scripts/setup-env.sh

echo Selecting a subset of fixtures to run
rm -rf env/split-fixtures/
mkdir -p env/split-fixtures/
# Finds all .fix files in test-vectors, excludes known failures, splits across
# CI nodes, and links the selected subset into split-fixtures
comm -23 \
    <(find "env/test-vectors/" \
        -path 'env/test-vectors/block/*' -prune \
        -o -type f -name '*.fix' -printf '%P\n' | sort) \
    <(sort scripts/failing.txt) \
    | if [ "$SPLIT_TESTS" == "true" ]; then circleci tests split; else cat; fi \
    | sed 's_^_env/test-vectors/_' \
    | xargs -d '\n' ln -t env/split-fixtures/

echo Running fixtures
env/pyvenv/bin/solana-conformance exec-fixtures \
    --num-processes $NUM_THREADS \
    -t ${PREBUILT_LIB_DIR}/libsolfuzz_sig.so \
    -o test_results/ \
    -i env/split-fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
