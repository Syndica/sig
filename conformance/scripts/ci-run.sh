#!/usr/bin/env bash
#
# This script runs the `solana_conformance` step in CI.

set -euxo pipefail

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

echo Selecting a subset of fixtures to run
rm -rf env/split-fixtures/
mkdir -p env/split-fixtures/
# Build `find` prune args from scripts/excluded.txt (directory-level denylist,
# shared with run.py). Blank lines and `#` comments are ignored.
prune_args=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    if [ "${#prune_args[@]}" -gt 0 ]; then
        prune_args+=(-o)
    fi
    prune_args+=(-path "env/test-vectors/$line")
done < scripts/excluded.txt
if [ "${#prune_args[@]}" -gt 0 ]; then
    prune_args=(\( "${prune_args[@]}" \) -prune -o)
fi
# Finds all .fix files in test-vectors, excludes pruned directories and known
# failing files, then links the selected subset into split-fixtures.
comm -23 \
    <(find "env/test-vectors/" \
        "${prune_args[@]}" \
        -type f -name '*.fix' -printf '%P\n' | sort) \
    <(sort scripts/failing.txt) \
    | sed "s_^_$PWD/env/test-vectors/_" \
    | xargs -d '\n' ln -s -t env/split-fixtures/

echo Running fixtures
zig-out/bin/run env/split-fixtures/ 2>&1 | tee /dev/stderr | grep -qE "Failed:\s+0$"
