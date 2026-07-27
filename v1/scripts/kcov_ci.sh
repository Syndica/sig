#!/usr/bin/env bash

set -exo pipefail

mkdir kcov-output 

echo "=> Running kcov on tests" 
kcov \
    --collect-only \
    --include-pattern=src/ \
    --exclude-pattern=$HOME/.cache,fuzz.zig \
    kcov-output \
    zig-out/bin/test
kcov --merge kcov-merged kcov-output/
echo "=> Done"
