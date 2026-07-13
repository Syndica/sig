#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Build
cd "$PROJECT_DIR"
echo "Building echo server..."
zig build -Doptimize=ReleaseSafe

# Start server in background
SERVER_LOG="$SCRIPT_DIR/server.log"
echo "Starting echo server on port 9001 (logging to $SERVER_LOG)..."
"$PROJECT_DIR/zig-out/bin/autobahn-server" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: Echo server failed to start"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

# Run Autobahn fuzzingclient
echo "Starting Autobahn fuzzingclient..."
docker run --rm \
    -v "$SCRIPT_DIR:/ab" \
    --name fuzzingclient \
    crossbario/autobahn-testsuite \
    /opt/pypy/bin/wstest --mode fuzzingclient --spec /ab/config.json

echo ""
echo "Autobahn server testsuite complete."
echo "Open $SCRIPT_DIR/reports/index.html to view results."
