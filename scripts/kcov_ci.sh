#!/usr/bin/env bash

set -exo pipefail

cd /home/circleci/project
mkdir kcov-output 

echo "=> Running kcov on tests" 
kcov \
    --collect-only \
    --exclude-pattern=$HOME/.cache \
    --exclude-pattern=src/fuzz.zig \
    --exclude-pattern=src/ledger/fuzz.zig \
    --exclude-pattern=src/accountsdb/fuzz.zig \
    --exclude-pattern=src/accountsdb/snapshot/fuzz.zig \
    --exclude-pattern=src/gossip/fuzz_table.zig \
    --exclude-pattern=src/gossip/fuzz_service.zig \
    --include-pattern=src/ \
    kcov-output \
    zig-out/bin/test
kcov --merge kcov-merged kcov-output/
echo "=> Done"