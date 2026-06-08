#!/usr/bin/env python3
"""Pre-fetch Zig package dependencies into ~/.cache/zig/p/<hash>.

This is a workaround for issues with zig's HTTP client, which frequently fails
to fetch dependencies in CI.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from urllib.parse import urlparse
import urllib.request
from pathlib import Path
from typing import TypeVar


SCRIPT_DIR = Path(__file__).resolve().parent
ZON_TO_JSON = SCRIPT_DIR / "zon-deps-to-json.zig"
CACHE = Path.home() / ".cache/zig/p"
RETRIES = 3


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--force", action="store_true")
    parser.add_argument("-z", "--zig-path", default="zig")
    parser.add_argument("zonfiles", nargs="*", metavar="build.zig.zon")
    args = parser.parse_args()

    for zonfile in args.zonfiles or ["build.zig.zon"]:
        fetch(zonfile, args.zig_path, args.force)


def fetch(zonfile: str | Path, zig_path: str, force: bool) -> None:
    zonfile = Path(zonfile)
    for dep in parse_zon(zonfile, zig_path).values():
        if "path" in dep:
            nested = zonfile.parent / dep["path"] / "build.zig.zon"
            if nested.exists():
                fetch(nested, zig_path, force)
            continue

        url = dep.get("url")
        if not url:
            continue
        expected = dep.get("hash")

        if expected and not force and (CACHE / expected).exists():
            print(f"Cached:   {url}", flush=True)
            h = expected
        else:
            print(f"Fetching: {url}", flush=True)
            h = cache_dep(url, expected, zig_path)

        nested = CACHE / h / "build.zig.zon"
        if nested.exists():
            fetch(nested, zig_path, force)


def parse_zon(zonfile: Path, zig_path: str) -> dict[str, dict[str, str]]:
    """Return {name: {url?, hash?, path?}} for the given zon file."""
    out = subprocess.check_output(
        [zig_path, "run", str(ZON_TO_JSON), "--", str(zonfile)],
        text=True,
    )
    return json.loads(out)


def cache_dep(url: str, expected: str | None, zig_path: str) -> str:
    """Fetch url, verify its hash, and ensure it is in the package cache."""
    with tempfile.TemporaryDirectory() as tmp:
        if url.startswith("git+"):
            git_url, _, commit = url.removeprefix("git+").partition("#")
            staged = Path(tmp) / "repo"
            zig_git_clone(git_url, commit, staged)
        else:
            staged = Path(tmp) / Path(urlparse(url).path).name
            retry(lambda: urllib.request.urlretrieve(url, staged), f"download {url}")

        out = subprocess.check_output([zig_path, "fetch", "--debug-hash", str(staged)], text=True)
        actual = [line for line in out.splitlines() if line.strip()][-1]

        if expected and actual != expected:
            sys.exit(f"Hash mismatch for {url}: got {actual}, expected {expected}")
        # zig fetch --debug-hash caches archives, but not local directories.
        if staged.is_dir():
            CACHE.mkdir(parents=True, exist_ok=True)
            shutil.rmtree(CACHE / actual, ignore_errors=True)
            shutil.move(str(staged), CACHE / actual)
    return actual


def zig_git_clone(git_url: str, commit: str, dest: Path) -> None:
    """Write a git tree the way zig hashes it: raw blobs, no checkout filters."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    git = ["git", "-C", str(dest)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "remote", "add", "origin", git_url], check=True)
    cmd = [*git, "-c", "protocol.version=2", "fetch", "--quiet", "--depth", "1", "origin", commit]
    retry(lambda: subprocess.run(cmd, check=True), f"git fetch {git_url}")

    tree = subprocess.check_output([*git, "ls-tree", "-r", commit], text=True)
    for line in tree.splitlines():
        meta, _, name = line.partition("\t")
        mode, _kind, oid = meta.split()
        out = dest / name
        out.parent.mkdir(parents=True, exist_ok=True)
        if mode == "120000":
            target = subprocess.check_output([*git, "cat-file", "blob", oid], text=True)
            out.symlink_to(target)
        elif mode == "160000":
            # gitlink/submodule: zig's git fetcher creates an empty dir.
            out.mkdir(exist_ok=True)
        else:
            blob = subprocess.check_output([*git, "cat-file", "blob", oid])
            out.write_bytes(blob)
            if mode == "100755":
                out.chmod(0o755)
    shutil.rmtree(dest / ".git")


T = TypeVar("T")


def retry(fn: Callable[[], T], label: str) -> T:
    backoff = 10
    for attempt in range(1, RETRIES):
        try:
            return fn()
        except Exception as e:
            print(f"{label} failed: {e} ({attempt}/{RETRIES}). waiting {backoff}s", flush=True)
            time.sleep(backoff)
            backoff *= 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
