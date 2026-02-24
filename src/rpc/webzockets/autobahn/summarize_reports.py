#!/usr/bin/env python3
"""
Summarize Autobahn WebSocket test suite reports.

Usage:
    python3 summarize_reports.py client [--verbose] [--json]
    python3 summarize_reports.py server [--verbose] [--json]

Reads the index.json produced by the Autobahn test suite and prints a
human-readable summary of pass/fail/non-strict/informational results
grouped by test category.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Autobahn test category descriptions
CATEGORY_NAMES = {
    "1": "Framing",
    "2": "Pings/Pongs",
    "3": "Reserved Bits",
    "4": "Opcodes",
    "5": "Fragmentation",
    "6": "UTF-8 Handling",
    "7": "Close Handling",
    "9": "Limits/Performance",
    "10": "Misc",
    "12": "WebSocket Compression (different payloads)",
    "13": "WebSocket Compression (different parameters)",
}

# Behavior result ordering (best to worst)
BEHAVIOR_ORDER = ["OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED", "FAILED"]


def load_index(reports_dir: Path) -> dict:
    index_path = reports_dir / "index.json"
    if not index_path.exists():
        print(f"Error: {index_path} not found", file=sys.stderr)
        sys.exit(1)
    with open(index_path) as f:
        data = json.load(f)
    # The index has agent names as top-level keys; pick the first one
    agents = list(data.keys())
    if len(agents) == 0:
        print("Error: empty index.json", file=sys.stderr)
        sys.exit(1)
    agent_name = agents[0]
    return agent_name, data[agent_name]


def case_sort_key(case_id: str):
    return [int(p) for p in case_id.split(".")]


def summarize(cases: dict, verbose: bool = False):
    total = len(cases)
    behaviors = Counter(c["behavior"] for c in cases.values())
    close_behaviors = Counter(c["behaviorClose"] for c in cases.values())

    # Group by category
    categories = defaultdict(lambda: defaultdict(int))
    for case_id, c in cases.items():
        cat = case_id.split(".")[0]
        categories[cat]["total"] += 1
        categories[cat][c["behavior"]] += 1

    # Collect non-OK cases
    non_ok = []
    for case_id, c in sorted(cases.items(), key=lambda x: case_sort_key(x[0])):
        if c["behavior"] != "OK":
            non_ok.append((case_id, c))

    return {
        "total": total,
        "behaviors": dict(behaviors),
        "close_behaviors": dict(close_behaviors),
        "categories": dict(categories),
        "non_ok": non_ok,
    }


def print_summary(agent_name: str, summary: dict, verbose: bool = False):
    total = summary["total"]
    behaviors = summary["behaviors"]
    non_ok = summary["non_ok"]
    categories = summary["categories"]

    ok_count = behaviors.get("OK", 0)
    failed_count = behaviors.get("FAILED", 0)
    non_strict_count = behaviors.get("NON-STRICT", 0)
    info_count = behaviors.get("INFORMATIONAL", 0)

    # Header
    print("=" * 70)
    print(f"  Autobahn WebSocket Test Report — {agent_name}")
    print("=" * 70)
    print()

    # Overall pass rate
    strict_pass = ok_count
    pass_rate = (strict_pass / total * 100) if total else 0
    loose_pass = ok_count + non_strict_count + info_count
    loose_rate = (loose_pass / total * 100) if total else 0

    print(f"  Total cases:    {total}")
    print(f"  Passed (OK):    {ok_count}")
    print(f"  Non-strict:     {non_strict_count}")
    print(f"  Informational:  {info_count}")
    print(f"  Failed:         {failed_count}")
    print()
    print(f"  Strict pass rate:  {pass_rate:.1f}%  ({strict_pass}/{total})")
    print(f"  Effective rate:    {loose_rate:.1f}%  ({loose_pass}/{total}  — OK + NON-STRICT + INFO)")
    print()

    # Per-category breakdown
    print("-" * 70)
    print(f"  {'Category':<35} {'OK':>5} {'N-S':>5} {'INFO':>5} {'FAIL':>5} {'Total':>6}")
    print("-" * 70)

    for cat in sorted(categories.keys(), key=int):
        c = categories[cat]
        name = CATEGORY_NAMES.get(cat, "Unknown")
        label = f"{cat}. {name}"
        cat_ok = c.get("OK", 0)
        cat_ns = c.get("NON-STRICT", 0)
        cat_info = c.get("INFORMATIONAL", 0)
        cat_fail = c.get("FAILED", 0)
        cat_total = c["total"]
        marker = ""
        if cat_fail > 0:
            marker = " ✗"
        elif cat_ns > 0:
            marker = " ~"
        print(f"  {label:<35} {cat_ok:>5} {cat_ns:>5} {cat_info:>5} {cat_fail:>5} {cat_total:>6}{marker}")

    print("-" * 70)
    print()

    # Non-OK details
    if non_ok:
        print("Non-OK test cases:")
        print()
        for case_id, c in non_ok:
            status = c["behavior"]
            close = c["behaviorClose"]
            duration = c["duration"]
            icon = {"NON-STRICT": "~", "INFORMATIONAL": "ℹ", "FAILED": "✗"}.get(status, "?")
            print(f"  [{icon}] Case {case_id}: {status} (close: {close}, {duration}ms)")

        if verbose:
            print()
            print("Detailed descriptions of non-OK cases:")
            print()
    else:
        print("All test cases passed with OK! 🎉")

    print()


def print_verbose_details(reports_dir: Path, non_ok: list):
    """Print detailed descriptions for non-OK cases by reading individual report files."""
    for case_id, c in non_ok:
        report_file = reports_dir / c.get("reportfile", "")
        if report_file.exists():
            with open(report_file) as f:
                detail = json.load(f)
            desc = detail.get("description", "N/A")
            # Strip HTML tags for readability
            import re
            desc = re.sub(r"<[^>]+>", " ", desc).strip()
            desc = re.sub(r"\s+", " ", desc)
            expectation = detail.get("expectation", "N/A")
            expectation = re.sub(r"<[^>]+>", " ", expectation).strip()
            expectation = re.sub(r"\s+", " ", expectation)
            print(f"  Case {case_id}:")
            print(f"    Description: {desc}")
            print(f"    Expectation: {expectation}")
            print()


def print_json_summary(agent_name: str, summary: dict):
    output = {
        "agent": agent_name,
        "total": summary["total"],
        "behaviors": summary["behaviors"],
        "close_behaviors": summary["close_behaviors"],
        "categories": {},
        "non_ok": [],
    }
    for cat in sorted(summary["categories"].keys(), key=int):
        c = summary["categories"][cat]
        name = CATEGORY_NAMES.get(cat, "Unknown")
        output["categories"][cat] = {"name": name, **dict(c)}
    for case_id, c in summary["non_ok"]:
        output["non_ok"].append({"case": case_id, **c})
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Summarize Autobahn WebSocket test reports")
    parser.add_argument(
        "mode",
        choices=["client", "server"],
        help="Which report to summarize: client or server",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed descriptions of non-OK cases")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON instead of human-readable text")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    reports_dir = script_dir / args.mode / "reports"

    agent_name, cases = load_index(reports_dir)
    summary = summarize(cases, verbose=args.verbose)

    if args.json:
        print_json_summary(agent_name, summary)
    else:
        print_summary(agent_name, summary, verbose=args.verbose)
        if args.verbose and summary["non_ok"]:
            print_verbose_details(reports_dir, summary["non_ok"])


if __name__ == "__main__":
    main()
