#!/usr/bin/env bash
set -euo pipefail

bin=env/agave/target/release
identity=env/identity.json

mkdir -p agave-ledger

$bin/agave-validator \
    --identity $identity \
    --ledger agave-ledger \
    --log "-" \
    --entrypoint entrypoint.testnet.solana.com:8001 \
    --entrypoint entrypoint2.testnet.solana.com:8001 \
    --entrypoint entrypoint3.testnet.solana.com:8001 \
    --no-incremental-snapshots \
    init \
    2> agave-ledger/setup.log 

$bin/agave-validator \
    --identity $identity \
    --ledger agave-ledger \
    --log "-" \
    --entrypoint entrypoint.testnet.solana.com:8001 \
    --entrypoint entrypoint2.testnet.solana.com:8001 \
    --entrypoint entrypoint3.testnet.solana.com:8001 \
    --rpc-port 9899 \
    --gossip-port 9001 \
    --dynamic-port-range 9002-9898 \
    --no-voting \
    --no-snapshots \
    --no-snapshot-fetch \
    2> agave-ledger/setup.log \
    | tee agave-ledger/setup-slot-hashes.log