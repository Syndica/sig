#!/bin/bash

# validator:                     runs the validator on a given network  
# --snapshot-metadata-only:      skips loading and indexing accounts, only loads snapshot metadata
# --overwrite-stake-for-testing: manually add our validator to the epoch staked nodes when building the turbine tree
# --test-repair-for-slot:        start shred collector at the given slot
# --exit-after-n-shreds:         exit after processing n shreds

# Refresh state from previous run if present
[ -e "validator/accounts_db/accounts/" ]   && echo "removing accounts"    && rm -rf validator/accounts_db/accounts/
[ -e "validator/accounts_db/snapshots/" ]  && echo "removing snapshots"   && rm -rf validator/accounts_db/snapshots/
[ -e "validator/blockstore/" ]            && echo "removing blockstore"  && rm -rf validator/blockstore/

# start the validator with stake override enabled
zig-out/bin/sig validator --network testnet --snapshot-metadata-only --overwrite-stake-for-testing --exit-after-n-shreds $1 --test-repair-for-slot $(solana -ut slot) --num-retransmit-sockets 1 --num-retransmit-threads 1 2>&1 | tee demo/turbine-retransmit-demo.log | grep turbine_demo.
