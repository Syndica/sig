"""Transaction differ: compare two parsed transaction files and categorise mismatches.

Built on top of ``parseout.transaction_parser``.  Compares two
``OrderedDict[str, Record]`` collections by their shared headers
and tags every mismatch with one or more ``Category`` values.

Public API:
    ``diff(a, b)``            — two OrderedDicts -> list[Mismatch]
    ``diff_files(path_a, path_b)`` — two file paths -> list[Mismatch]
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Union

from .parser import (
    AccountEntry,
    ExecutedError,
    ExecutedSuccess,
    FeeDetails,
    Record,
    SanitizationError,
    parse_file as _parse_file,
)


class Category(Enum):
    """Mismatch categories."""

    result_type = auto()
    status = auto()
    instruction_error = auto()
    instruction_error_index = auto()
    custom_error = auto()
    fee_details = auto()
    executed_units = auto()
    loaded_accounts_data_size = auto()
    return_data = auto()
    modified_accounts = auto()
    rollback_accounts = auto()


@dataclass
class Mismatch:
    """A single mismatched record between two parsed files.

    Attributes:
        test_id: The shared record test_id.
        categories: Set of ``Category`` values describing what differs.
        programs: Sorted list of base58 program addresses invoked by the
            transaction.  Populated when fixture data is available.
        left: The Record from the first file.
        right: The Record from the second file.
    """

    test_id: str
    categories: set[Category] = field(default_factory=set)
    programs: list[str] = field(default_factory=list)
    left: Record = field(default_factory=Record)
    right: Record = field(default_factory=Record)


def diff(
    a: OrderedDict[str, Record],
    b: OrderedDict[str, Record],
    programs: dict[str, list[str]] | None = None,
) -> list[Mismatch]:
    """Compare two parsed transaction OrderedDicts and return categorised mismatches.

    Only records whose test_ids appear in *both* dicts are compared.
    Records that match exactly are omitted from the result.

    Args:
        a: First parsed result (``transaction_parser.parse`` output).
        b: Second parsed result.
        programs: Optional mapping from test_id to list of invoked program
            addresses (base58).  When provided, each ``Mismatch`` is
            annotated with the programs for its test_id.

    Returns:
        List of ``Mismatch`` objects, one per differing test_id, in the
        iteration order of *a*.
    """
    result: list[Mismatch] = []
    for test_id in a:
        if test_id not in b:
            continue
        rec_a, rec_b = a[test_id], b[test_id]
        if rec_a.result == rec_b.result:
            continue
        cats = _categorize(rec_a.result, rec_b.result)
        progs = programs.get(test_id, []) if programs else []
        result.append(Mismatch(test_id=test_id, categories=cats, programs=progs, left=rec_a, right=rec_b))
    return result


def diff_files(
    path_a: str | Path,
    path_b: str | Path,
    fixture_dir: str | Path | None = None,
) -> list[Mismatch]:
    """Parse two files and return categorised mismatches.

    Convenience wrapper around ``diff(parse_file(a), parse_file(b))``.

    Args:
        path_a: Path to the expected output file.
        path_b: Path to the actual output file.
        fixture_dir: Optional path to directory containing ``.fix`` protobuf
            fixtures.  When provided, each mismatch is annotated with the
            invoked program addresses extracted from the fixture inputs.
    """
    programs: dict[str, list[str]] | None = None
    if fixture_dir is not None:
        from .fixture import programs_for_fixtures

        programs = programs_for_fixtures(fixture_dir)
    return diff(_parse_file(path_a), _parse_file(path_b), programs=programs)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

#: The result union for type hints.
_Result = Union[SanitizationError, ExecutedSuccess, ExecutedError]


def _categorize(left: _Result, right: _Result) -> set[Category]:
    """Determine which categories of difference exist between two results."""
    if type(left) is not type(right):
        return {Category.result_type}

    # Same type — compare field by field.  Every Category except result_type
    # shares its name with the corresponding dataclass field.
    cats: set[Category] = set()
    for cat in Category:
        if cat is Category.result_type:
            continue
        attr = cat.name
        if hasattr(left, attr) and getattr(left, attr) != getattr(right, attr):
            cats.add(cat)
    return cats


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

import pytest
from ..parser import TestParse

class TestCategory:
    """Ensure the Category enum has all expected members."""

    def test_all_categories_exist(self):
        names = {c.name for c in Category}
        assert names == {
            "result_type",
            "status",
            "instruction_error",
            "instruction_error_index",
            "custom_error",
            "fee_details",
            "executed_units",
            "loaded_accounts_data_size",
            "return_data",
            "modified_accounts",
            "rollback_accounts",
        }


class TestDiffIdentical:
    """Two identical inputs should produce no mismatches."""

    def test_empty(self):
        assert diff(OrderedDict(), OrderedDict()) == []

    def test_identical_sanitization_error(self):
        rec = Record(test_id="h", result=SanitizationError(status=9))
        a = OrderedDict(h=rec)
        b = OrderedDict(h=rec)
        assert diff(a, b) == []

    def test_identical_executed_success(self):
        rec = Record(
            test_id="h",
            result=ExecutedSuccess(
                fee_details=FeeDetails(transaction_fee=5000),
                modified_accounts=[AccountEntry(address="A", owner="O")],
            ),
        )
        a = OrderedDict(h=rec)
        b = OrderedDict(h=rec)
        assert diff(a, b) == []


class TestDiffResultType:
    """Cross-variant mismatches should be tagged result_type only."""

    def test_sanitization_vs_executed_success(self):
        a = OrderedDict(h=Record(test_id="h", result=SanitizationError(status=9)))
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.result_type}

    def test_executed_success_vs_executed_error(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.result_type}

    def test_sanitization_vs_executed_error(self):
        a = OrderedDict(h=Record(test_id="h", result=SanitizationError(status=9)))
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(status=4, fee_details=FeeDetails(transaction_fee=5000)),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.result_type}


class TestDiffStatus:
    """Same variant, different status code."""

    def test_sanitization_error_status(self):
        a = OrderedDict(h=Record(test_id="h", result=SanitizationError(status=9)))
        b = OrderedDict(h=Record(test_id="h", result=SanitizationError(status=27)))
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.status}

    def test_executed_error_status(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(status=4, fee_details=FeeDetails(transaction_fee=5000)),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(status=9, fee_details=FeeDetails(transaction_fee=5000)),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.status}


class TestDiffInstructionError:
    """Same variant, different instruction_error fields."""

    def test_instruction_error_only(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=3,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.instruction_error}

    def test_instruction_error_index(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    instruction_error_index=0,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    instruction_error_index=2,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.instruction_error_index}

    def test_custom_error(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    custom_error=7,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    custom_error=42,
                    fee_details=FeeDetails(transaction_fee=5000),
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.custom_error}


class TestDiffFeeDetails:
    """Same variant, different fee_details."""

    def test_transaction_fee(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=10000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.fee_details}

    def test_prioritization_fee(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000, prioritization_fee=100),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000, prioritization_fee=200),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.fee_details}


class TestDiffExecutionFields:
    """Same variant, different execution-related scalar fields."""

    def test_executed_units(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    executed_units=1000,
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    executed_units=2000,
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.executed_units}

    def test_loaded_accounts_data_size(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    loaded_accounts_data_size=100,
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    loaded_accounts_data_size=200,
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.loaded_accounts_data_size}

    def test_return_data(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    return_data="aa",
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                    return_data="bb",
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.return_data}


class TestDiffAccounts:
    """Same variant, different account lists."""

    def test_modified_accounts_count(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[
                        AccountEntry(address="A", owner="O"),
                        AccountEntry(address="B", owner="O"),
                    ],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.modified_accounts}

    def test_modified_accounts_lamports(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", lamports=100, owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", lamports=200, owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.modified_accounts}

    def test_modified_accounts_data(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", data="aa", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedSuccess(
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", data="bb", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.modified_accounts}

    def test_rollback_accounts(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    fee_details=FeeDetails(transaction_fee=5000),
                    rollback_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    fee_details=FeeDetails(transaction_fee=5000),
                    rollback_accounts=[],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.rollback_accounts}


class TestDiffMultipleCategories:
    """Mismatches can be tagged with several categories at once."""

    def test_status_and_instruction_error(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=SanitizationError(status=9, instruction_error=3),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=SanitizationError(status=27, instruction_error=8),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {Category.status, Category.instruction_error}

    def test_three_categories(self):
        a = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=3,
                    fee_details=FeeDetails(transaction_fee=5000),
                    modified_accounts=[AccountEntry(address="A", owner="O")],
                ),
            )
        )
        b = OrderedDict(
            h=Record(
                test_id="h",
                result=ExecutedError(
                    status=9,
                    instruction_error=8,
                    fee_details=FeeDetails(transaction_fee=10000),
                    modified_accounts=[AccountEntry(address="B", owner="O")],
                ),
            )
        )
        ms = diff(a, b)
        assert len(ms) == 1
        assert ms[0].categories == {
            Category.instruction_error,
            Category.fee_details,
            Category.modified_accounts,
        }


class TestDiffTestIdsOnlyInOne:
    """Test_ids that exist in only one dict are skipped (not errors)."""

    def test_extra_in_a(self):
        a = OrderedDict(
            h1=Record(test_id="h1", result=SanitizationError(status=9)),
            h2=Record(test_id="h2", result=SanitizationError(status=4)),
        )
        b = OrderedDict(
            h1=Record(test_id="h1", result=SanitizationError(status=9)),
        )
        ms = diff(a, b)
        assert len(ms) == 0

    def test_extra_in_b(self):
        a = OrderedDict(
            h1=Record(test_id="h1", result=SanitizationError(status=9)),
        )
        b = OrderedDict(
            h1=Record(test_id="h1", result=SanitizationError(status=9)),
            h2=Record(test_id="h2", result=SanitizationError(status=4)),
        )
        ms = diff(a, b)
        assert len(ms) == 0


class TestDiffPreservesOrder:
    """Mismatches are returned in the iteration order of the first dict."""

    def test_order(self):
        a = OrderedDict(
            bb=Record(test_id="bb", result=SanitizationError(status=1)),
            aa=Record(test_id="aa", result=SanitizationError(status=2)),
            cc=Record(test_id="cc", result=SanitizationError(status=3)),
        )
        b = OrderedDict(
            bb=Record(test_id="bb", result=SanitizationError(status=10)),
            aa=Record(test_id="aa", result=SanitizationError(status=20)),
            cc=Record(test_id="cc", result=SanitizationError(status=30)),
        )
        ms = diff(a, b)
        assert [m.test_id for m in ms] == ["bb", "aa", "cc"]


class TestDiffMismatchFields:
    """The Mismatch object exposes left/right records."""

    def test_left_right(self):
        rec_a = Record(test_id="h", result=SanitizationError(status=9))
        rec_b = Record(test_id="h", result=SanitizationError(status=27))
        a = OrderedDict(h=rec_a)
        b = OrderedDict(h=rec_b)
        ms = diff(a, b)
        assert ms[0].left is rec_a
        assert ms[0].right is rec_b


class TestDiffFiles:
    """Integration test against the actual data files."""

    def test_parseme1_vs_parseme2(self):
        ms = diff_files(
            TestParse.expected(),
            TestParse.actual(),
        )
        assert len(ms) == 1818
        # Every mismatch has at least one category
        for m in ms:
            assert len(m.categories) >= 1
            assert m.test_id != ""
            assert m.left.result is not None
            assert m.right.result is not None

    def test_parseme1_vs_parseme2_category_counts(self):
        ms = diff_files(
            TestParse.expected(),
            TestParse.actual(),
        )
        from collections import Counter

        counts = Counter()
        for m in ms:
            for c in m.categories:
                counts[c] += 1

        # Verified counts from manual analysis
        assert counts[Category.result_type] == 1194
        assert counts[Category.status] == 233
        assert counts[Category.instruction_error] == 312
        assert counts[Category.modified_accounts] > 0
        assert counts[Category.rollback_accounts] > 0

    def test_parseme1_vs_self(self):
        ms = diff_files(
            TestParse.expected(),
            TestParse.expected(),
        )
        assert len(ms) == 0
