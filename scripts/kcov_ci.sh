#!/usr/bin/env bash

set -exo pipefail

mkdir kcov-output 

cd /opt/kcov-source

echo "=> Running kcov on tests" 
kcov \
    --collect-only \
    --include-pattern=src/ \
    --exclude-pattern=$HOME/.cache \
    kcov-output \
    zig-out-notsan/bin/test
kcov --merge kcov-merged kcov-output/
echo "=> Done"