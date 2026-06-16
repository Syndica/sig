#!/usr/bin/env python3
"""Resolve scripts/excluded.txt into a clean list of directory paths.

Single source of truth for parsing the directory-level denylist. Both run.py
and scripts/ci-run.sh consume this script's output so they always agree on
how comments, whitespace, and trailing slashes are handled.

Usage:
    python3 scripts/list_excluded.py        # prints one path per line
"""
import os
import sys


def load_excluded(excluded_path):
    """Parse excluded.txt: strip `#` comments, whitespace, and trailing `/`."""
    entries = []
    with open(excluded_path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip().rstrip("/")
            if line:
                entries.append(line)
    return entries


def default_path():
    here = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(here, "excluded.txt")


if __name__ == "__main__":
    for entry in load_excluded(default_path()):
        print(entry)
