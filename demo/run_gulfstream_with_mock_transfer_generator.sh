#!/bin/bash

zig-out/bin/sig test-transaction-sender -n testnet -t 10 -l 1000000  2>&1 | tee demo/gulfstream-demo.log | grep demo.