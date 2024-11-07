#!/bin/bash

# test-transaction-sender: runs mock transfer generator and transaction sender on a given network
# t: number of transactions to send from the generator
# l: number of lamports to send in each transaction

zig-out/bin/sig test-transaction-sender --network testnet --n-transactions 5 --n-lamports-per-tx 1000000  2>&1 | tee demo/gulfstream-demo.log | grep gulfstream_demo.