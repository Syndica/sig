#!/usr/bin/env bash
set -euo pipefail

bin=env/agave/target/release
identity=env/identity.json
num_slots=300

snapshot_dir="$(ls agave-ledger/remote/snapshot-* 2>/dev/null | head -n1)"
[[ -n "$snapshot_dir" ]] || { echo "No snapshot found."; exit 1; }
basename="$(basename "$snapshot_dir")"
snapshot_slot="${basename#*-}"; snapshot_slot="${snapshot_slot%%-*}"
stop_at_slot=$((snapshot_slot + num_slots + 1))

rm -rf agave-ledger/run-offline*.log

$bin/agave-ledger-tool \
    --ledger agave-ledger \
    blockstore purge $stop_at_slot \
    2> agave-ledger/run-offline.log \
    || true

$bin/agave-ledger-tool \
    --ledger agave-ledger \
    verify \
    2> agave-ledger/run-offline.log \
    | tee agave-ledger/run-offline-slot-hashes.log 