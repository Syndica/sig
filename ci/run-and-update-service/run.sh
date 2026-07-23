#!/usr/bin/env bash

mkdir -p logs

# Rotate log file if it contains entries from a previous day
if [ -f logs/sig.log ]; then
    first_timestamp=$(grep -oP 'time=\K\d{4}-\d{2}-\d{2}' logs/sig.log | head -n1)
    current_date=$(date -u +"%Y-%m-%d")
    if [ -n "$first_timestamp" ] && [ "$first_timestamp" != "$current_date" ]; then
        mv logs/sig.log "logs/sig.$first_timestamp.log"
    fi
fi

# Delete log files older than 1 month
find logs -name 'sig.*.log' -type f -mtime +30 -delete

# Sig is unable to resume from existing validator state, so clear it before starting.
if [ -d validator ]; then
    # We make an effort to save the old state in case it is needed for
    # debugging, but only save the latest instance to avoid running out of disk
    # space. There is already handle-exit.sh which uploads crash artifacts to
    # S3, so this is only a last resort to deal with cascading failures.
    rm -rf validator-archive
    mv validator validator-archive
fi

# Clear out old archives to avoid running out of disk space. They should have
# been uploaded to S3 and then deleted right away. If not, we must be flooding
# the disk with archives on failed uploads, and we're going to run out of disk
# space.
rm -f validator-*.tar.zst

zig-out/bin/sig $@ 2>>logs/sig.log >>logs/sig.log
