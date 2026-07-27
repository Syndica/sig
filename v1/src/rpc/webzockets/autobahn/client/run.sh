#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Cleanup any previous run
docker stop fuzzingserver 2>/dev/null || true
trap "docker stop fuzzingserver 2>/dev/null || true" EXIT

# Start fuzzingserver in background
echo "Starting Autobahn fuzzingserver on port 9001..."
bash "$SCRIPT_DIR/start_server.sh" &

# Build
cd "$PROJECT_DIR"
echo "Building Autobahn client runner..."
zig build -Doptimize=ReleaseSafe

# Run client (it has its own retry loop for server startup)
echo "Running Autobahn client..."
"$PROJECT_DIR/zig-out/bin/autobahn-client"

echo ""
echo "Autobahn client testsuite complete."

# Give fuzzingserver time to flush report files to disk
sleep 3

echo "Open $SCRIPT_DIR/reports/index.html to view results."

# Check for failures
if [ -f "$SCRIPT_DIR/reports/index.json" ]; then
    if grep -q "FAILED" "$SCRIPT_DIR/reports/index.json"; then
        echo ""
        echo "WARNING: Some tests FAILED! Check the report for details."
        exit 1
    else
        echo "All tests passed!"
    fi
fi
