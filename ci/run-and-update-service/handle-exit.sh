#!/usr/bin/env bash
set -euxo pipefail

BASE_DIR=/home/sig/sig

log() { local level=$1; local message=$2;
    local timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
    echo "time=$timestamp level=$level scope=handle-exit message=\"$message\"" >>"$BASE_DIR/logs/sig.log"
}

trap 'e=$?; [ $e -ne 0 ] && log error "handle-exit.sh exited with code $e. see sig.service logs"' EXIT

if [[ "${SERVICE_RESULT:=unknown} ${EXIT_CODE:=unknown} ${EXIT_STATUS:=unknown}" == "success killed TERM" ]]; then
    # During upgrades, we use `systemctl stop` which signals TERM to the
    # process. This is expected and not something we want an error alert for.
    exit 0
fi

log error "exited unexpectedly with SERVICE_RESULT=$SERVICE_RESULT EXIT_CODE=$EXIT_CODE EXIT_STATUS=$EXIT_STATUS"

upload_file() { local file_path=$1;
    # upload artifact to S3 and clean up local state
    . /etc/sig.conf  # get S3_BUCKET
    if [ -z "${S3_BUCKET:-}" ]; then
        log error "S3_BUCKET is not set, cannot upload validator archive"
        exit 1
    fi
    aws s3 cp $file_path "s3://$S3_BUCKET/ci-crashes/$(basename $file_path)" || log error "failed to upload validator archive to s3 bucket"
}

# Sig crashed, so we want to preserve the state for debugging, but we also want
# to clear it out from "validator" so the next run can start fresh.
if [ -d "$BASE_DIR/validator" ]; then

    # compress validator state to a tarball
    cp "$BASE_DIR/logs/sig.log" "$BASE_DIR/validator/"
    local timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
    local archive_name="validator-${timestamp}.tar.zst";
    local archive_path="$BASE_DIR/$archive_name"
    tar --zstd -cf $archive_path -C "$BASE_DIR" validator
    rm -rf "$BASE_DIR/validator"
    upload_file $archive_path || true
    rm $archive_path
fi
