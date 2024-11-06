#!/bin/bash

[ -e "validator/accounts_db/accounts/" ]  && echo "removing accounts"    && rm -rf validator/accounts_db/accounts/
[ -e "validator/accounts_db/snapshots/" ] && echo "removing snapshots"   && rm -rf validator/accounts_db/snapshots/
[ -e "validator/blockstore/" ]            && echo "removing blockstore"  && rm -rf validator/blockstore/

zig-out/bin/sig validator -n testnet --snapshot-metadata-only --overwrite-stake-for-testing --test-repair-for-slot $(solana -ut slot) 2>&1 | tee demo/turbine-demo.log 
