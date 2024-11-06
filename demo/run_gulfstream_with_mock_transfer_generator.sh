#!/bin/bash

zig-out/bin/sig test-transaction-sender -n testnet -t 5 -l 1000000  2>&1 | tee demo/gulfstream-demo.log | grep demo.