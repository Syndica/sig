"""Generic differ: compare two parsed files and categorise mismatches.

Built on top of ``parseout.parser``.  Compares two
``OrderedDict[str, Block]`` collections by their shared headers
and tags every mismatch with dynamically generated category strings
based on the field path where differences occur.

Category naming:
    - ``field.subfield`` — values differ at that path
    - ``field.0.subfield`` — values differ at list index 0, subfield
    - ``field-missing`` — field exists in expected but not actual
    - ``field-unexpected`` — field exists in actual but not expected
    - ``field`` (for lists) — list lengths differ

Public API:
    ``diff(a, b)``                 — two OrderedDicts -> list[Mismatch]
    ``diff_files(path_a, path_b)`` — two file paths -> list[Mismatch]
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from .parser import Block, Value, parse_file as _parse_file


@dataclass
class Mismatch:
    """A single mismatched record between two parsed files.

    Attributes:
        header: The shared record header.
        categories: Set of category path strings describing what differs.
        left: The Block from the first (expected) file.
        right: The Block from the second (actual) file.
    """

    header: str
    categories: set[str] = field(default_factory=set)
    left: Block = field(default_factory=dict)
    right: Block = field(default_factory=dict)


def diff(
    a: OrderedDict[str, Block],
    b: OrderedDict[str, Block],
) -> list[Mismatch]:
    """Compare two parsed OrderedDicts and return categorised mismatches.

    Only records whose headers appear in *both* dicts are compared.
    Records that match exactly are omitted from the result.
    """
    result: list[Mismatch] = []
    for header in a:
        if header not in b:
            continue
        left, right = a[header], b[header]
        if left == right:
            continue
        cats = _compare(left, right, "")
        result.append(Mismatch(header=header, categories=cats, left=left, right=right))
    return result


def diff_files(path_a: str | Path, path_b: str | Path) -> list[Mismatch]:
    """Parse two files and return categorised mismatches."""
    return diff(_parse_file(path_a), _parse_file(path_b))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_Node = Union[Value, Block, list]


def _compare(left: _Node, right: _Node, path: str) -> set[str]:
    """Recursively compare two parsed values and return category paths."""
    cats: set[str] = set()

    if isinstance(left, dict) and isinstance(right, dict):
        left_keys = set(left.keys())
        right_keys = set(right.keys())

        for key in left_keys - right_keys:
            subpath = f"{path}.{key}" if path else key
            cats.add(f"{subpath}-missing")

        for key in right_keys - left_keys:
            subpath = f"{path}.{key}" if path else key
            cats.add(f"{subpath}-unexpected")

        for key in left_keys & right_keys:
            subpath = f"{path}.{key}" if path else key
            cats.update(_compare(left[key], right[key], subpath))

    elif isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            cats.add(path)
        else:
            for i, (lv, rv) in enumerate(zip(left, right)):
                subpath = f"{path}.{i}"
                cats.update(_compare(lv, rv, subpath))

    else:
        # Scalars or type mismatch (e.g., dict vs scalar).
        if left != right:
            cats.add(path)

    return cats


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from .parser import TestParse  # noqa: E402


class TestCompare:
    """Tests for _compare."""

    def test_identical_dicts(self):
        assert _compare({"a": 1}, {"a": 1}, "") == set()

    def test_scalar_diff(self):
        assert _compare({"a": 1}, {"a": 2}, "") == {"a"}

    def test_nested_dict_diff(self):
        assert _compare({"o": {"i": 1}}, {"o": {"i": 2}}, "") == {"o.i"}

    def test_list_same_length_diff(self):
        left = {"items": [{"n": 1}, {"n": 2}]}
        right = {"items": [{"n": 1}, {"n": 3}]}
        assert _compare(left, right, "") == {"items.1.n"}

    def test_list_length_mismatch(self):
        left = {"items": [{"n": 1}]}
        right = {"items": [{"n": 1}, {"n": 2}]}
        assert _compare(left, right, "") == {"items"}

    def test_missing_field(self):
        assert _compare({"a": 1, "b": 2}, {"a": 1}, "") == {"b-missing"}

    def test_unexpected_field(self):
        assert _compare({"a": 1}, {"a": 1, "b": 2}, "") == {"b-unexpected"}

    def test_nested_missing(self):
        assert _compare({"o": {"a": 1, "b": 2}}, {"o": {"a": 1}}, "") == {"o.b-missing"}

    def test_nested_unexpected(self):
        assert _compare({"o": {"a": 1}}, {"o": {"a": 1, "b": 2}}, "") == {"o.b-unexpected"}

    def test_type_mismatch_dict_vs_scalar(self):
        assert _compare({"a": {"x": 1}}, {"a": 42}, "") == {"a"}

    def test_multiple_diffs(self):
        assert _compare({"a": 1, "b": 2, "c": 3}, {"a": 1, "b": 99, "c": 100}, "") == {"b", "c"}

    def test_deep_nesting(self):
        left = {"a": {"b": {"c": {"d": 1}}}}
        right = {"a": {"b": {"c": {"d": 2}}}}
        assert _compare(left, right, "") == {"a.b.c.d"}

    def test_list_element_path(self):
        left = {"items": [{"x": 1}, {"x": 2}, {"x": 3}]}
        right = {"items": [{"x": 1}, {"x": 99}, {"x": 3}]}
        assert _compare(left, right, "") == {"items.1.x"}

    def test_empty_dicts(self):
        assert _compare({}, {}, "") == set()

    def test_both_empty_lists(self):
        assert _compare({"a": []}, {"a": []}, "") == set()

    def test_list_vs_dict_type_mismatch(self):
        assert _compare({"a": [1, 2]}, {"a": {"x": 1}}, "") == {"a"}

    def test_bool_diff(self):
        assert _compare({"f": True}, {"f": False}, "") == {"f"}

    def test_string_diff(self):
        assert _compare({"s": "hello"}, {"s": "world"}, "") == {"s"}

    def test_mixed_missing_and_diff(self):
        left = {"a": 1, "b": 2}
        right = {"a": 99}
        assert _compare(left, right, "") == {"a", "b-missing"}

    def test_mixed_unexpected_and_diff(self):
        left = {"a": 1}
        right = {"a": 99, "b": 2}
        assert _compare(left, right, "") == {"a", "b-unexpected"}


class TestDiffEmpty:
    """Two identical or empty inputs."""

    def test_empty(self):
        assert diff(OrderedDict(), OrderedDict()) == []

    def test_identical(self):
        a = OrderedDict(h={"x": 1, "y": 2})
        b = OrderedDict(h={"x": 1, "y": 2})
        assert diff(a, b) == []


class TestDiffBasic:
    """Basic diff scenarios."""

    def test_single_scalar_diff(self):
        a = OrderedDict(h={"x": 1})
        b = OrderedDict(h={"x": 2})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].header == "h"
        assert ms[0].categories == {"x"}

    def test_nested_diff(self):
        a = OrderedDict(h={"outer": {"inner": 1}})
        b = OrderedDict(h={"outer": {"inner": 2}})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"outer.inner"}

    def test_missing_field(self):
        a = OrderedDict(h={"a": 1, "b": 2})
        b = OrderedDict(h={"a": 1})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"b-missing"}

    def test_unexpected_field(self):
        a = OrderedDict(h={"a": 1})
        b = OrderedDict(h={"a": 1, "b": 2})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"b-unexpected"}

    def test_list_length_mismatch(self):
        a = OrderedDict(h={"items": [{"n": 1}]})
        b = OrderedDict(h={"items": [{"n": 1}, {"n": 2}]})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"items"}

    def test_list_element_diff(self):
        a = OrderedDict(h={"items": [{"n": 1}, {"n": 2}]})
        b = OrderedDict(h={"items": [{"n": 1}, {"n": 99}]})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"items.1.n"}


class TestDiffHeadersOnlyInOne:
    """Headers that exist in only one dict are skipped."""

    def test_extra_in_a(self):
        a = OrderedDict(h1={"x": 1}, h2={"x": 2})
        b = OrderedDict(h1={"x": 1})
        assert diff(a, b) == []

    def test_extra_in_b(self):
        a = OrderedDict(h1={"x": 1})
        b = OrderedDict(h1={"x": 1}, h2={"x": 2})
        assert diff(a, b) == []


class TestDiffPreservesOrder:
    """Mismatches are returned in iteration order of first dict."""

    def test_order(self):
        a = OrderedDict(bb={"x": 1}, aa={"x": 2}, cc={"x": 3})
        b = OrderedDict(bb={"x": 10}, aa={"x": 20}, cc={"x": 30})
        ms = diff(a, b)
        assert [m.header for m in ms] == ["bb", "aa", "cc"]


class TestDiffLeftRight:
    """Mismatch exposes left/right blocks."""

    def test_left_right(self):
        left_block = {"x": 1}
        right_block = {"x": 2}
        a = OrderedDict(h=left_block)
        b = OrderedDict(h=right_block)
        ms = diff(a, b)
        assert ms[0].left is left_block
        assert ms[0].right is right_block


class TestDiffMultipleCategories:
    """Mismatches can have several categories."""

    def test_two_fields(self):
        a = OrderedDict(h={"a": 1, "b": 2})
        b = OrderedDict(h={"a": 10, "b": 20})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"a", "b"}

    def test_diff_and_missing(self):
        a = OrderedDict(h={"a": 1, "b": 2})
        b = OrderedDict(h={"a": 10})
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {"a", "b-missing"}

    def test_nested_multiple(self):
        a = OrderedDict(h={"outer": {"x": 1, "y": 2}, "z": 3})
        b = OrderedDict(h={"outer": {"x": 10, "y": 20}, "z": 30})
        ms = diff(a, b)
        assert ms[0].categories == {"outer.x", "outer.y", "z"}


class TestDiffFiles:
    """Integration test against actual data files."""

    def test_self_vs_self(self):
        ms = diff_files(TestParse.expected(), TestParse.expected())
        assert len(ms) == 0

    def test_expected_vs_actual(self):
        ms = diff_files(TestParse.expected(), TestParse.actual())
        assert len(ms) > 0
        for m in ms:
            assert len(m.categories) >= 1
            assert m.header != ""
