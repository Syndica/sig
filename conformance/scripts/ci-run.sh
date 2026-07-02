#!/usr/bin/env bash
#
# This script runs the `solana_conformance` step in CI.
#
# Usage: ci-run.sh <v1|v2>
#
# The version arg selects which backend's denylists to apply:
#   scripts/unimplemented_harnesses.<version>.txt   (directory-level skip list)
#   scripts/misc_failures.<version>.txt             (file-level failure list)
#
# It must match the backend that produced zig-out/lib/libsolfuzz_sig.{so,dylib}
# (i.e. `zig build -Dversion=<version>` was run before this).

set -euxo pipefail

version="${1:?usage: ci-run.sh <v1|v2>}"
case "$version" in
    v1|v2) ;;
    *) echo "unknown version '$version' (expected v1 or v2)" >&2; exit 2 ;;
esac

conformance_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $conformance_dir

unimplemented="scripts/unimplemented_harnesses.${version}.txt"
misc_failures="scripts/misc_failures.${version}.txt"

echo "Selecting a subset of fixtures to run for ${version}"
rm -rf env/split-fixtures/
mkdir -p env/split-fixtures/
comm -23 \
    <(find env/test-vectors/ -type f -name '*.fix' -printf '%P\n' | sort) \
    <(sort "$misc_failures") \
    | grep -vE "^$(grep -vE '^\s*(#|$)' "$unimplemented" | paste -sd'|')" \
    | sed "s_^_$PWD/env/test-vectors/_" \
    | xargs -d '\n' ln -s -t env/split-fixtures/

echo Running fixtures
# Pass the built dylib explicitly so `run` dispatches through whichever backend
# was compiled by `-Dversion=<version>`. Without this, `zig-out/bin/run` uses
# its baked-in entrypoints table, which imports src/lib.zig (v1) regardless of
# the version flag.
zig-out/bin/run env/split-fixtures/ zig-out/lib/libsolfuzz_sig.so 2>&1 | tee /dev/stderr | grep -qE "Failed:\s+0$"
