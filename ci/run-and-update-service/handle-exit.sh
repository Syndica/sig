#!/usr/bin/env bash

BASE_DIR=/home/sig/sig

if [[ "$SERVICE_RESULT $EXIT_CODE $EXIT_STATUS" == "success killed TERM" ]]; then
    # During upgrades, we use `systemctl stop` which signals TERM to the
    # process. This is expected and not something we want an error alert for.
    exit 0
fi

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
message="exited unexpectedly with SERVICE_RESULT=$SERVICE_RESULT EXIT_CODE=$EXIT_CODE EXIT_STATUS=$EXIT_STATUS"
echo "time=$timestamp level=error scope=handle-exit message=\"$message\"" >>"$BASE_DIR/logs/sig.log"

# Sig crashed, so we want to preserve the state for debugging, but we also want
# to clear it out from "validator" so the next run can start fresh.
if [ -d "$BASE_DIR/validator" ]; then
    . /etc/sig.conf  # get S3_BUCKET
    if [ -z "$S3_BUCKET" ]; then
        echo "time=$timestamp level=error scope=handle-exit message=\"S3_BUCKET is not set, cannot upload validator archive\"" >>"$BASE_DIR/logs/sig.log"
        exit 1
    fi
    cp "$BASE_DIR/logs/sig.log" "$BASE_DIR/validator/"
    tar --zstd -cf "$BASE_DIR/validator-${timestamp}.tar.zst" -C "$BASE_DIR" validator
    aws s3 cp "$BASE_DIR/validator-${timestamp}.tar.zst" "s3://$S3_BUCKET/ci-crashes/validator-${timestamp}.tar.zst"
    rm -rf "$BASE_DIR/validator" "$BASE_DIR/validator-${timestamp}.tar.zst"
fi
