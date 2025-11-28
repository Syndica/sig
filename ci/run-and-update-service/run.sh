#!/usr/bin/env bash

# Rotate log file if it contains entries from a previous day
if [ -f /home/sig/sig/logs/sig.log ]; then
    first_timestamp=$(grep -oP 'time=\K\d{4}-\d{2}-\d{2}' /home/sig/sig/logs/sig.log | head -n1)
    current_date=$(date -u +"%Y-%m-%d")
    if [ -n "$first_timestamp" ] && [ "$first_timestamp" != "$current_date" ]; then
        mv /home/sig/sig/logs/sig.log "/home/sig/sig/logs/sig.$first_timestamp.log"
    fi
fi

# Delete log files older than 1 month
find /home/sig/sig/logs -name "sig.*.log" -type f -mtime +30 -delete

/home/sig/sig/zig-out/bin/sig $@ 2>>/home/sig/sig/logs/sig.log >>/home/sig/sig/logs/sig.log
