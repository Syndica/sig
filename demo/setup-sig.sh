#!/usr/bin/env bash
set -euo pipefail

snapshot_path="$(ls agave-ledger/remote/snapshot-* 2>/dev/null | head -n1)"
[[ -n "$snapshot_path" ]] || { echo "No snapshot found."; exit 1; }
basename="$(basename "$snapshot_path")"
snapshot_slot="${basename#*-}"; snapshot_slot="${snapshot_slot%%-*}"

mkdir -p env/sig/validator
ln -sfn env/sig/validator sig-ledger

rm -rf sig-ledger/*
mkdir -p sig-ledger/accounts_db
cp $snapshot_path sig-ledger/accounts_db/

cd env/sig
./zig-out/bin/sig shred-network \
    -c testnet \
    --test-repair-for-slot $snapshot_slot \
    --max-shreds 100100100100 \
    | tee sig-ledger/setup.log