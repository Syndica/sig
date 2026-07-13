#!/usr/bin/env bash

BASE_DIR=/home/sig/sig
# `sig` reads validator state, logs, and pinned test/data fixtures via paths
# that are relative to its cwd. The data/ folder now lives under v1/ (moved
# there along with the v1 source tree), so `cd` there before invoking the
# binary so those relative paths keep resolving.
RUN_DIR=$BASE_DIR/v1

# Rotate log file if it contains entries from a previous day
if [ -f "$BASE_DIR/logs/sig.log" ]; then
    first_timestamp=$(grep -oP 'time=\K\d{4}-\d{2}-\d{2}' "$BASE_DIR/logs/sig.log" | head -n1)
    current_date=$(date -u +"%Y-%m-%d")
    if [ -n "$first_timestamp" ] && [ "$first_timestamp" != "$current_date" ]; then
        mv "$BASE_DIR/logs/sig.log" "$BASE_DIR/logs/sig.$first_timestamp.log"
    fi
fi

# Delete log files older than 1 month
find "$BASE_DIR/logs" -name "sig.*.log" -type f -mtime +30 -delete

# Sig is unable to resume from existing validator state, so clear it before starting.
# The validator/ directory is created relative to the run cwd (v1/).
if [ -d "$RUN_DIR/validator" ]; then
    # We make an effort to save the old state in case it is needed for
    # debugging, but only save the latest instance to avoid running out of disk
    # space. There is already handle-exit.sh which uploads crash artifacts to
    # S3, so this is only a last resort to deal with cascading failures.
    rm -rf "$RUN_DIR/validator-archive"
    mv "$RUN_DIR/validator" "$RUN_DIR/validator-archive"
fi

# Clear out old archives to avoid running out of disk space. They should have
# been uploaded to S3 and then deleted right away. If not, we must be flooding
# the disk with archives on failed uploads, and we're going to run out of disk
# space.
rm -f "$RUN_DIR/validator-*.tar.zst"

cd "$RUN_DIR"
"$RUN_DIR/zig-out/bin/sig" $@ 2>>"$BASE_DIR/logs/sig.log" >>"$BASE_DIR/logs/sig.log"
