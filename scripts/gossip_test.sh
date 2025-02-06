#!/bin/bash
usage() {
    echo "Usage: $0 <duration_in_seconds>"
    exit 1
}

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Error: No duration provided."
    usage
fi

# Check if the argument is a valid number
if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "Error: Duration must be a positive integer."
    usage
fi

sig_path="./zig-out/bin/sig"
if [ ! -z "$2" ]; then
    sig_path=$2
fi

echo "Running gossip test for $1 seconds"

# build and run gossip
$sig_path gossip \
    -e entrypoint.testnet.solana.com:8001 \
    -e entrypoint2.testnet.solana.com:8001 2>&1 &

# Get the process ID of the last background command
PID=$!

# Sleep for N seconds
sleep $1

# Kill the process
kill $PID
