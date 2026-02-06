#!/usr/bin/env bash

BASE_DIR=/home/sig/sig

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

"$BASE_DIR/zig-out/bin/sig" $@ 2>>"$BASE_DIR/logs/sig.log" >>"$BASE_DIR/logs/sig.log"
