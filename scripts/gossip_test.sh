#!/bin/bash
echo "Running gossip test for $1 seconds"

# build and run gossip
zig build -Doptimize=ReleaseSafe && \
./zig-out/bin/sig gossip \
    -e entrypoint.testnet.solana.com:8001 \
    -e entrypoint2.testnet.solana.com:8001 &

# Get the process ID of the last background command
PID=$!

# Sleep for 30 seconds
sleep $1

# Kill the process
kill $PID
