#!/bin/bash

git_hash=$1

git fetch --all
git checkout $git_hash
zig build -Doptimize=ReleaseSafe benchmark -- all --telemetry=$git_hash
