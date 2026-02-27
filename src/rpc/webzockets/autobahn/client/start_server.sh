#!/bin/bash
# Start the Autobahn fuzzingserver in Docker (foreground, Ctrl-C to stop)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

docker run --rm \
  -v "$SCRIPT_DIR:/ab" \
  -p 9001:9001 \
  --name fuzzingserver \
  crossbario/autobahn-testsuite \
  /opt/pypy/bin/wstest --mode fuzzingserver --spec /ab/config.json
