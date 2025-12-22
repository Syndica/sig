#!/usr/bin/env bash
set -euo pipefail

# kill spawned child processes
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

cur_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $cur_dir

# Make sure agave is present
AGAVE_DIR=${AGAVE_DIR:="$cur_dir/agave"}
AGAVE_COMMIT=${AGAVE_COMMIT:="v3.0.0"}
if [[ ! -d "$AGAVE_DIR" ]]; then
    AGAVE_REPO=https://github.com/anza-xyz/agave.git
    echo "Cloning $AGAVE_REPO at $AGAVE_COMMIT"
    git clone $AGAVE_REPO $AGAVE_DIR
    echo "Resetting $AGAVE_DIR to $AGAVE_COMMIT"
    git reset --hard $AGAVE_COMMIT
fi

# Buid agave
pushd $AGAVE_DIR
    # echo "Applying agave patch to print slot hashes"
    # git apply --check "$cur_dir/agave-slot-hash.patch"
    echo "Building agave"
    cargo build --release
popd

# Setup agave
agave_bin=$AGAVE_DIR/target/release/
identity=$cur_dir/identity.json
if [[ ! -d "agave-ledger" ]]; then
    rm $identity
    $agave_bin/solana-keygen new -o $identity --no-passphrase --silent
    mkdir -p agave-ledger

    echo "Initializing agave-ledger.."
    $agave_bin/agave-validator \
        --identity $identity \
        --ledger agave-ledger \
        --log "-" \
        --entrypoint entrypoint.testnet.solana.com:8001 \
        --entrypoint entrypoint2.testnet.solana.com:8001 \
        --entrypoint entrypoint3.testnet.solana.com:8001 \
        --no-snapshots \
        --no-snapshot-fetch \
        init \
        2> agave-ledger/setup.log 
fi

# Build sig
ZIG_EXE=${ZIG_EXE:="zig"}
SIG_DIR=${SIG_DIR:="$(realpath $cur_dir/..)"}
pushd $SIG_DIR
    echo "Building sig"
    "$ZIG_EXE" build sig -Dno-run -Doptimize=ReleaseSafe
popd

# Setup sig
mkdir -p $SIG_DIR/validator
ln -sfn $SIG_DIR/validator sig-ledger

# Get snapshot file
# snapshot_path=$(find $SIG_DIR/validator/accounts_db/ -type f -name "snapshot-*.tar.zst")
snapshot_path=$(find agave-ledger/ -type f -name "snapshot-*.tar.zst")
if [[ -z $snapshot_path ]]; then
    echo "Fetching snapshot into agave-ledger/remote.."
    $agave_bin/agave-validator \
        --identity $identity \
        --ledger agave-ledger \
        --log "-" \
        --entrypoint entrypoint.testnet.solana.com:8001 \
        --entrypoint entrypoint2.testnet.solana.com:8001 \
        --entrypoint entrypoint3.testnet.solana.com:8001 \
        --no-incremental-snapshots \
        init \
        2> agave-ledger/setup.log 

    snapshot_path=$(find agave-ledger/ -type f -name "snapshot-*.tar.zst")


    # snapshot_finder_dir=$cur_dir/snapshot-finder
    # if [[ ! -d "$snapshot_finder_dir" ]]; then
    #     echo "Cloning snapshot finder tool"
    #     git clone https://github.com/dnut/solana-snapshot-finder $snapshot_finder_dir
    # fi

    # pushd $snapshot_finder_dir
    #     echo "Fetching snapshot into $SIG_DIR/validator/accounts_db/"
    #     if [[ ! -d "./venv" ]]; then
    #         python3 -m venv venv
    #     fi
    #     source ./venv/bin/activate
    #     python3 -m pip install -r requirements.txt
    #     python3 snapshot-finder.py --rpc_address https://api.testnet.solana.com --snapshot_path $SIG_DIR/validator/accounts_db/
    #     snapshot_path=$(find $SIG_DIR/validator/accounts_db/ -type f -name "snapshot-*.tar.zst")
    # popd
fi

echo "Snapshot at $snapshot_path"
snapshot_basename="$(basename "$snapshot_path")"
# ln -sfn $snapshot_path agave-ledger/remote/$snapshot_basename

num_slots=100
snapshot_slot="${snapshot_basename#*-}"; snapshot_slot="${snapshot_slot%%-*}"
stop_at_slot=$((snapshot_slot + num_slots + 1))

# # Fetch legders

# # echo "Running shred-network in the background.."
# # cd $SIG_DIR && ./zig-out/bin/sig shred-network \
# #     -c testnet \
# #     --test-repair-for-slot $snapshot_slot \
# #     --max-shreds 100100100100 \
# #     | tee sig-ledger/setup.log \
# #     & # spawn in background
# # shred_network_pid=$!

# echo "Populating agave ledger for $num_slots slots ($snapshot_slot .. $stop_at_slot).."
# rm -rf agave-ledger/setup*.log
# $agave_bin/agave-validator \
#     --identity $identity \
#     --ledger agave-ledger \
#     --log "-" \
#     --entrypoint entrypoint.testnet.solana.com:8001 \
#     --entrypoint entrypoint2.testnet.solana.com:8001 \
#     --entrypoint entrypoint3.testnet.solana.com:8001 \
#     --rpc-port 9899 \
#     --gossip-port 9001 \
#     --dynamic-port-range 9002-9898 \
#     --no-voting \
#     --no-incremental-snapshots \
#     --no-snapshot-fetch \
#     2> agave-ledger/setup.log \
#     | tee agave-ledger/setup-slot-hashes.log
#     & # spawn in background

# agave_shred_network_pid=$!
# grep -q "slot_stats_tracking_complete" <(tail -f agave-ledger/setup.log)
# kill $agave_shred_network_pid

# # kill $shred_network_pid

# # Running agave offline to record slot hashes
echo "Running agave offline"
rm -rf agave-ledger/run-offline*.log
# $agave_bin/agave-ledger-tool \
#     --ledger agave-ledger \
#     blockstore purge $stop_at_slot \
#     2> agave-ledger/run-offline.log \
#     || true
$agave_bin/agave-ledger-tool \
    --ledger agave-ledger \
    verify \
    2> agave-ledger/run-offline.log \
    | tee agave-ledger/run-offline-slot-hashes.log 

# # Running sig offline to record slot hashes
# # rm -rf sig-ledger/run-offline*.log
# # cd $SIG_DIR && ./zig-out/bin/sig replay-offline \
# #     -c testnet \
# #     --replay-threads 1 \
# #     --disable-consensus \
# #     --use-disk-index \
# #     --skip-snapshot-validation \
# #     --max-shreds 100100100100 \
# #     --stop-at-slot $stop_at_slot \
# #     2> validator/run-offline.log \
# #     | egrep --line-buffered "^(slot=)" \
# #     | tee validator/run-offline-slot-hashes.log

