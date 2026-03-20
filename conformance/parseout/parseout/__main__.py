"""Command-line interface for parseout.

Subcommands:
    parse [input-file]         — generic parse to JSON on stdout
    diff [expected] [actual]   — generic diff producing diff.csv, diff-category.json, diff-combo.json
    txn [expected] [actual]    — transaction diff producing txn.csv, txn-category.json, txn-combo.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from glob import glob
from pathlib import Path

from .parser import parse_file as _generic_parse_file
from .differ import diff_files as _generic_diff_files
from .transaction import diff_files as _txn_diff_files, Category


_TXN_FIXTURES = Path("env/test-outputs/txn/fixtures")
_TXN_EXPECTED_GLOB = str(_TXN_FIXTURES / "expected" / "*.txt")
_TXN_ACTUAL_GLOB = str(_TXN_FIXTURES / "actual" / "*.txt")


def main(argv: list[str] | None = None) -> None:
    """Entry point for the CLI."""
    top = argparse.ArgumentParser(prog="parseout", description="parseout CLI")
    subs = top.add_subparsers(dest="command")

    # --- parse ---
    p_parse = subs.add_parser("parse", help="Generic parse to JSON on stdout")
    p_parse.add_argument("input_file", help="Path to the input text file")

    # --- diff ---
    p_diff = subs.add_parser("diff", help="Generic diff producing diff.csv, diff-category.json, diff-combo.json")
    p_diff.add_argument("expected", help="Path to the expected file")
    p_diff.add_argument("actual", help="Path to the actual file")

    # --- txn ---
    p_txn = subs.add_parser("txn", help="Transaction diff producing txn.csv, txn-category.json, txn-combo.json")
    p_txn.add_argument("expected", nargs="?", default=None, help="Path to the expected file (default: first match in env/test-outputs/txn/fixtures/expected/*.txt)")
    p_txn.add_argument("actual", nargs="?", default=None, help="Path to the actual file (default: first match in env/test-outputs/txn/fixtures/actual/*.txt)")

    args = top.parse_args(argv)

    if args.command == "parse":
        _cmd_parse(args)
    elif args.command == "diff":
        _cmd_diff(args)
    elif args.command == "txn":
        _cmd_txn(args)
    else:
        top.print_help()
        sys.exit(1)


def _cmd_parse(args: argparse.Namespace) -> None:
    """Generic parse: file -> JSON on stdout."""
    result = _generic_parse_file(args.input_file)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _cmd_diff(args: argparse.Namespace) -> None:
    """Generic diff: two files -> diff.csv + diff-category.json + diff-combo.json."""
    out_dir = Path(".")
    mismatches = _generic_diff_files(args.expected, args.actual)

    # --- diff.csv (sorted by combo so same-category rows are adjacent) ---
    sorted_mismatches = sorted(
        mismatches,
        key=lambda m: "+".join(sorted(m.categories)),
    )
    csv_path = out_dir / "diff.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["header", "categories"])
        for m in sorted_mismatches:
            cats = sorted(m.categories)
            writer.writerow([m.header, ",".join(cats)])

    # --- diff-category.json ---
    by_category: dict[str, list] = {}
    for m in mismatches:
        entry = _generic_mismatch_to_dict(m)
        for cat in m.categories:
            by_category.setdefault(cat, []).append(entry)

    ordered = dict(sorted(by_category.items()))

    cat_path = out_dir / "diff-category.json"
    with open(cat_path, "w") as f:
        json.dump(ordered, f, indent=2)
        f.write("\n")

    # --- diff-combo.json ---
    from collections import Counter

    by_combo: dict[str, list] = {}
    combo_counts: Counter[str] = Counter()
    for m in mismatches:
        key = " + ".join(sorted(m.categories))
        by_combo.setdefault(key, []).append(_generic_mismatch_to_dict(m))
        combo_counts[key] += 1

    combo_ordered = {k: by_combo[k] for k, _ in combo_counts.most_common()}

    combo_path = out_dir / "diff-combo.json"
    with open(combo_path, "w") as f:
        json.dump(combo_ordered, f, indent=2)
        f.write("\n")

    total = len(mismatches)
    print(f"{total} mismatches written to {csv_path}, {cat_path}, {combo_path}")

    # --- per-category counts ---
    print("\nCategories:")
    for cat in sorted(by_category.keys()):
        print(f"  {cat}: {len(by_category[cat])}")

    # --- combination counts ---
    print("\nCombinations:")
    for combo, count in combo_counts.most_common():
        print(f"  {combo}: {count}")


def _cmd_txn(args: argparse.Namespace) -> None:
    """Transaction diff: two files -> txn.csv + txn-category.json + txn-combo.json."""
    use_fixtures = args.expected is None or args.actual is None

    expected = args.expected or _resolve_glob(_TXN_EXPECTED_GLOB, "expected")
    actual = args.actual or _resolve_glob(_TXN_ACTUAL_GLOB, "actual")

    # When using fixture defaults, write output alongside the fixtures
    out_dir = Path(_TXN_FIXTURES) if use_fixtures else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    mismatches = _txn_diff_files(expected, actual)

    # --- txn.csv (sorted by combo so same-category rows are adjacent) ---
    sorted_mismatches = sorted(
        mismatches,
        key=lambda m: "+".join(sorted(c.name for c in m.categories)),
    )
    csv_path = out_dir / "txn.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_id", "categories"])
        for m in sorted_mismatches:
            cats = sorted(c.name for c in m.categories)
            writer.writerow([m.test_id, ",".join(cats)])

    # --- txn-category.json ---
    by_category: dict[str, list] = {}
    for m in mismatches:
        entry = _mismatch_to_dict(m)
        for cat in m.categories:
            by_category.setdefault(cat.name, []).append(entry)

    # Sort keys to match Category enum order
    ordered = {c.name: by_category[c.name] for c in Category if c.name in by_category}

    cat_path = out_dir / "txn-category.json"
    with open(cat_path, "w") as f:
        json.dump(ordered, f, indent=2)
        f.write("\n")

    # --- txn-combo.json ---
    from collections import Counter

    by_combo: dict[str, list] = {}
    combo_counts: Counter[str] = Counter()
    for m in mismatches:
        key = " + ".join(sorted(c.name for c in m.categories))
        by_combo.setdefault(key, []).append(_mismatch_to_dict(m))
        combo_counts[key] += 1

    # Sort keys by frequency (most common first)
    combo_ordered = {k: by_combo[k] for k, _ in combo_counts.most_common()}

    combo_path = out_dir / "txn-combo.json"
    with open(combo_path, "w") as f:
        json.dump(combo_ordered, f, indent=2)
        f.write("\n")

    total = len(mismatches)
    print(f"{total} mismatches written to {csv_path}, {cat_path}, {combo_path}")

    # --- per-category counts ---
    print("\nCategories:")
    for c in Category:
        if c.name in by_category:
            print(f"  {c.name}: {len(by_category[c.name])}")

    # --- combination counts ---
    print("\nCombinations:")
    for combo, count in combo_counts.most_common():
        print(f"  {combo}: {count}")


def _resolve_glob(pattern: str, label: str) -> str:
    """Resolve a glob pattern to a single file path, or exit with an error."""
    matches = sorted(glob(pattern))
    if not matches:
        print(f"error: no {label} file found matching {pattern}. Are you in the conformance directory?", file=sys.stderr)
        sys.exit(1)
    return matches[0]


def _mismatch_to_dict(m) -> dict:
    """Convert a transaction Mismatch to a JSON-serialisable dict."""
    d = asdict(m)
    d["categories"] = sorted(c.name for c in m.categories)
    return d


def _generic_mismatch_to_dict(m) -> dict:
    """Convert a generic Mismatch to a JSON-serialisable dict."""
    return {
        "header": m.header,
        "categories": sorted(m.categories),
        "left": m.left,
        "right": m.right,
    }


if __name__ == "__main__":
    main()
