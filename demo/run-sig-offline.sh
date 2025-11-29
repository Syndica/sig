#!/usr/bin/env bash
set -euo pipefail

num_slots=300

snapshot_path="$(ls agave-ledger/remote/snapshot-* 2>/dev/null | head -n1)"
[[ -n "$snapshot_path" ]] || { echo "No snapshot found."; exit 1; }
basename="$(basename "$snapshot_path")"
snapshot_slot="${basename#*-}"; snapshot_slot="${snapshot_slot%%-*}"
stop_at_slot=$((snapshot_slot + num_slots))

rm -rf sig-ledger/run-offline*.log

cd env/sig
./zig-out/bin/sig replay-offline \
    -c testnet \
    --replay-threads 1 \
    --disable-consensus \
    --use-disk-index \
    --skip-snapshot-validation \
    --max-shreds 100100100100 \
    --stop-at-slot $stop_at_slot \
    --disable-consensus \
    2> validator/run-offline.log \
    | egrep --line-buffered "^(slot=)" \
    | tee validator/run-offline-slot-hashes.log
