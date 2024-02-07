import csv
import sys
from dataclasses import asdict, dataclass
from pprint import pprint
from collections import defaultdict, OrderedDict

left_filename, right_filename = sys.argv[1:3]


@dataclass
class CrdsValue:
    variant: str
    pubkey: str
    hash: str
    wallclock: int
    gossip_addr: str
    shred_version: int


@dataclass
class Comparison:
    name: str
    left_only: list
    right_only: list
    shared: list


with open(left_filename) as f:
    f.readline()
    left_vals = [CrdsValue(*row) for row in csv.reader(f)]

with open(right_filename) as f:
    f.readline()
    right_vals = [CrdsValue(*row) for row in csv.reader(f)]


def compare(name, accessor):
    left_items = set(accessor(c) for c in left_vals)
    right_items = set(accessor(c) for c in right_vals)
    return Comparison(
        name,
        left_items - right_items,
        right_items - left_items,
        right_items & left_items,
    )


def min_max(crds_values):
    minimum = 10**100
    maximum = -(10**100)
    for c in crds_values:
        minimum = min(minimum, int(c.wallclock))
        maximum = max(maximum, int(c.wallclock))
    return minimum, maximum


def count(items, accessor):
    counter = defaultdict(int)
    for item in items:
        counter[accessor(item)] += 1
    return sorted([(k, v) for (k, v) in counter.items()])


def compare_counts(left_vals, right_vals, accessor):
    left_counts = dict(count(left_vals, accessor))
    right_counts = dict(count(right_vals, accessor))
    left_keys = set(left_counts.keys())
    right_keys = set(right_counts.keys())
    same = {}
    diff = {}
    for key in left_keys & right_keys:
        if left_counts[key] == right_counts[key]:
            same[key] = left_counts[key]
        else:
            diff[key] = left_counts[key], right_counts[key]
    for key in left_keys - right_keys:
        diff[key] = left_counts[key], 0
    for key in right_keys - left_keys:
        diff[key] = 0, right_counts[key]
    return same, diff


def summarize_counts(name, left_vals, right_vals, accessor):
    same, diff = compare_counts(left_vals, right_vals, accessor)
    print(name + " counts:")
    pprint(("same:", same))
    pprint(("diff:", diff))
    print()


def summarize_existence_with_counts(name, accessor):
    comparison = compare(name, accessor)
    print(name + ":")
    print(" - left_only:", len(comparison.left_only))
    print(" - right_only:", len(comparison.right_only))
    print(" - shared:", len(comparison.shared))
    print()


summarize_existence_with_counts("hash", lambda crds_value: crds_value.hash)
summarize_existence_with_counts("pubkey", lambda crds_value: crds_value.pubkey)

print("left time range", min_max(left_vals))
print("right time range", min_max(right_vals))
print()

summarize_counts("variant", left_vals, right_vals, lambda c: c.variant)
summarize_counts("shred_version", left_vals, right_vals, lambda c: c.shred_version)
