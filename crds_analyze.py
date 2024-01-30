import csv
from dataclasses import asdict, dataclass
from pprint import pprint
from collections import defaultdict


@dataclass
class CrdsValue:
    variant: str
    pubkey: str
    hash: str
    wallclock: int


@dataclass
class Comparison:
    name: str
    sig_only: list
    rust_only: list
    shared: list


with open("crds-dump-sig.csv") as f:
    sig_vals = [CrdsValue(*row) for row in csv.reader(f)]

with open("crds-dump-rust.csv") as f:
    rust_vals = [CrdsValue(*row) for row in csv.reader(f)]


def compare(name, accessor):
    sig_items = set(accessor(c) for c in sig_vals)
    rust_items = set(accessor(c) for c in rust_vals)
    return Comparison(
        name, sig_items - rust_items, rust_items - sig_items, rust_items & sig_items
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
    return counter


pprint(asdict(compare("pubkey", lambda crds_value: crds_value.pubkey)))
# pprint(asdict(compare("hash", lambda crds_value: crds_value.hash)))
# pprint(asdict(compare("variant", lambda crds_value: crds_value.variant)))

print("rst", min_max(rust_vals))
print("sig", min_max(sig_vals))

print(count(rust_vals, lambda c: c.variant))
print(count(sig_vals, lambda c: c.variant))
