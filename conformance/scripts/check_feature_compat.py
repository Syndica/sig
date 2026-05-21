#!/usr/bin/env python3
"""Validate feature compatibility across one or more solfuzz target libraries.

This script loads each target `.so` and retrieves its hardcoded and supported
feature IDs via the sol_compat C API. It then computes the union of hardcoded
features required by all targets and reports any target that can neither
hardcode nor support every required feature.

Exit status is `0` when all targets are compatible and `1` when incompatibilities
are found.
"""

import argparse
import ctypes
from dataclasses import dataclass
import os
import sys


class SolCompatFeatures(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_size_t),
        ("hardcoded_features", ctypes.POINTER(ctypes.c_uint64)),
        ("hardcoded_feature_cnt", ctypes.c_size_t),
        ("supported_features", ctypes.POINTER(ctypes.c_uint64)),
        ("supported_feature_cnt", ctypes.c_size_t),
    ]


@dataclass(frozen=True)
class TargetFeatures:
    path: str
    hardcoded: set[int]
    supported: set[int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check solfuzz target feature-set compatibility."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Paths to target shared libraries. If omitted, reads SOLFUZZ_TARGETS.",
    )
    parser.add_argument(
        "--log-level",
        type=int,
        default=5,
        help="Log level passed to sol_compat_init (default: 5).",
    )
    return parser.parse_args()


def resolve_targets(raw_targets: list[str]) -> list[str]:
    if raw_targets:
        return [target for target in (item.strip() for item in raw_targets) if target]

    env_targets = os.environ.get("SOLFUZZ_TARGETS", "")
    targets = [item.strip() for item in env_targets.split(",") if item.strip()]
    if targets:
        return targets

    raise SystemExit(
        "No targets specified. Pass .so paths as arguments or set SOLFUZZ_TARGETS."
    )


def read_feature_array(ptr: ctypes.POINTER(ctypes.c_uint64), count: int) -> list[int]:
    if not ptr or count <= 0:
        return []
    return [int(ptr[index]) for index in range(count)]


def load_target_features(path: str, log_level: int) -> TargetFeatures:
    lib = ctypes.CDLL(path)

    init = lib.sol_compat_init
    init.argtypes = [ctypes.c_int]
    init.restype = None

    fini = lib.sol_compat_fini
    fini.argtypes = []
    fini.restype = None

    get_features = lib.sol_compat_get_features_v1
    get_features.argtypes = []
    get_features.restype = ctypes.POINTER(SolCompatFeatures)

    init(log_level)
    try:
        features_ptr = get_features()
        if not features_ptr:
            raise RuntimeError(f"{path}: sol_compat_get_features_v1 returned null")

        features = features_ptr.contents
        if features.struct_size < ctypes.sizeof(SolCompatFeatures):
            raise RuntimeError(f"{path}: SolCompatFeatures.struct_size too small")

        return TargetFeatures(
            path=path,
            hardcoded=set(
                read_feature_array(features.hardcoded_features, features.hardcoded_feature_cnt)
            ),
            supported=set(
                read_feature_array(features.supported_features, features.supported_feature_cnt)
            ),
        )
    finally:
        fini()


def format_features(features: set[int]) -> str:
    return " ".join(f"{feature:016x}" for feature in sorted(features))


def main() -> int:
    args = parse_args()
    targets = resolve_targets(args.targets)
    pools = [load_target_features(path, args.log_level) for path in targets]

    required_hardcoded = set().union(*(pool.hardcoded for pool in pools))

    compatible = True
    for pool in pools:
        missing = required_hardcoded - (pool.hardcoded | pool.supported)
        if missing:
            compatible = False
            print(f"Target incompatible: {pool.path}")
            print(f"Missing {len(missing)} required feature(s): {format_features(missing)}")

    if compatible:
        print("All targets compatible:")
        for index, path in enumerate(targets):
            print(f"  {path}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
