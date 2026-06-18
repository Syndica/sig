#!/usr/bin/env bash
#
# This script runs the `solana_conformance` step in CI.

set -euxo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

echo Selecting a subset of fixtures to run
rm -rf env/split-fixtures/
mkdir -p env/split-fixtures/
comm -23 \
    <(find env/test-vectors/ -type f -name '*.fix' -printf '%P\n' | sort) \
    <(sort scripts/misc_failures.txt) \
    | grep -vE "^$(grep -vE '^\s*(#|$)' scripts/unimplemented_harnesses.txt | paste -sd'|')" \
    | sed "s_^_$PWD/env/test-vectors/_" \
    | xargs -d '\n' ln -s -t env/split-fixtures/

echo Running fixtures
zig-out/bin/run env/split-fixtures/ 2>&1 | tee /dev/stderr | grep -qE "Failed:\s+0$"
