#!/usr/bin/env bash

/home/sig/sig/zig-out/bin/sig $@ 2>>/home/sig/sig/logs/sig.log >>/home/sig/sig/logs/sig.log

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")"
echo "time=$timestamp level=error message=\"exited unexpectedly\"" >>/home/sig/sig/logs/sig.log
