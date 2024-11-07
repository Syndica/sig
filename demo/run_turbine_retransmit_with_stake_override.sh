#!/bin/bash

# validator:                     runs the validator on a given network  
# --snapshot-metadata-only:      skips loading and indexing accounts, only loads snapshot metadata
# --overwrite-stake-for-testing: manually add our validator to the epoch staked nodes when building the turbine tree
# --test-repair-for-slot:        start shred collector at the given slot
# --exit-after-n-shreds:         exit after processing n shreds

# start the validator with stake override enabled
zig-out/bin/sig validator --network testnet --snapshot-metadata-only --overwrite-stake-for-testing --exit-after-n-shreds $1 --test-repair-for-slot $(solana -ut slot) 2>&1 | tee demo/turbine-retransmit-demo-$2.log | grep turbine_demo.
