#!/usr/bin/env bash

if [[ $SERVICE_RESULT == "success" ]]; then
    exit 0
fi

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
echo "time=$timestamp scope=handle-exit level=error message=\"exited unexpectedly\"" >>/home/sig/sig/logs/sig.log

# Sig crashed, so we want to preserve the state for debugging, but we also want
# to clear it out from "validator" so the next run can start fresh.
if [ -d /home/sig/sig/validator ]; then
    mkdir -p /home/sig/sig/validator-archive
    # Delete folders older than 4 days to avoid filling up the disk.
    find /home/sig/sig/validator-archive -mindepth 1 -maxdepth 1 -type d -mtime +4 -exec rm -rf {} \;
    mv /home/sig/sig/validator "/home/sig/sig/validator-archive/$(date -u +"%Y-%m-%dT%H:%M:%S")"
fi
