#!/usr/bin/env bash

if [[ "$SERVICE_RESULT $EXIT_CODE $EXIT_STATUS" == "success killed TERM" ]]; then
    # During upgrades, we use `systemctl stop` which signals TERM to the
    # process. This is expected and not something we want an error alert for.
    exit 0
fi

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
message="exited unexpectedly with SERVICE_RESULT=$SERVICE_RESULT EXIT_CODE=$EXIT_CODE EXIT_STATUS=$EXIT_STATUS"
echo "time=$timestamp level=error scope=handle-exit message=\"$message\"" >>/home/sig/sig/logs/sig.log

# Sig crashed, so we want to preserve the state for debugging, but we also want
# to clear it out from "validator" so the next run can start fresh.
if [ -d /home/sig/sig/validator ]; then
    mkdir -p /home/sig/validator-archive
    # Delete folders older than 4 days to avoid filling up the disk.
    find /home/sig/validator-archive -mindepth 1 -maxdepth 1 -type d -mtime +4 -exec rm -rf {} \;
    mv /home/sig/sig/validator "/home/sig/validator-archive/$(date -u +"%Y-%m-%dT%H:%M:%S")"
fi
