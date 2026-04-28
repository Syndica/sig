#!/usr/bin/env bash
#
# This script runs the `solana_conformance` step in CI.

set -euxo pipefail

SPLIT_TESTS=${SPLIT_TESTS:-false}
PREBUILT_BIN=${PREBUILT_BIN:-zig-out/bin/run}

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

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
    | sed 's_^_env/test-vectors/_' \
    | xargs -d '\n' cp -t env/split-fixtures/

echo Running fixtures
${PREBUILT_BIN} env/split-fixtures/ | tee /dev/tty | grep -q "Failed: 0,"
