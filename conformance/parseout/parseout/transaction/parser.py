"""Transaction-level parser: raw dicts -> typed dataclasses.

Layer 2 of the parser stack.  Takes the generic ``Block`` dicts produced
by ``parseout.parser.parse`` (Layer 1) and converts them into the
domain-specific transaction dataclass hierarchy.

Public API:
    ``parse(text)``       — text -> OrderedDict[str, Record]
    ``parse_file(path)``  — file path -> OrderedDict[str, Record]
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, Union

from .. import parser
from ..parser import Block


def parse(text: str) -> OrderedDict[str, Record]:
    """Parse text into an ordered mapping of test_id -> Record.

    Wires Layer 1 (generic parser) and Layer 2 (typed conversion) together.

    Args:
        text: Full file content.

    Returns:
        OrderedDict keyed by record test_id, values are typed Record objects.
    """
    return _records_from_raw(parser.parse(text))


def parse_file(path: str) -> OrderedDict[str, Record]:
    """Parse a file into an ordered mapping of test_id -> Record.

    Args:
        path: Path to the text file.

    Returns:
        OrderedDict keyed by record test_id, values are typed Record objects.
    """
    return _records_from_raw(parser.parse_file(path))


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass
class FeeDetails:
    """Fee breakdown for a transaction.

    Attributes:
        transaction_fee: The base transaction fee.
        prioritization_fee: Optional priority fee for faster processing.
    """

    transaction_fee: int = 0
    prioritization_fee: Optional[int] = None


@dataclass
class AccountEntry:
    """An account that was modified or needs rollback.

    Attributes:
        address: Base58-encoded Solana account address.
        lamports: Account balance in lamports (u64).  Absent in ~1.7% of entries.
        data: Optional hex-encoded account data.
        executable: Whether the account is executable. Absent means False.
        owner: Base58-encoded owner program address.
    """

    address: str = ""
    lamports: Optional[int] = None
    data: Optional[str] = None
    executable: bool = False
    owner: str = ""


@dataclass
class SanitizationError:
    """The transaction failed sanitization before execution.

    Invariants (enforced by data, not by constructor):
        - ``status`` is always present.
        - ``instruction_error`` may be present; when absent,
          ``instruction_error_index`` is also absent.
        - ``custom_error`` never appears.
        - No fee or account data.
    """

    status: int = 0
    instruction_error: Optional[int] = None
    instruction_error_index: Optional[int] = None


@dataclass
class ExecutedSuccess:
    """The transaction was executed and succeeded (``is_ok=True``).

    Invariants:
        - ``fee_details`` is always present.
        - ``modified_accounts`` is always non-empty.
        - No ``status``, ``instruction_error``, ``rollback_accounts``.
    """

    fee_details: FeeDetails = field(default_factory=FeeDetails)
    modified_accounts: list[AccountEntry] = field(default_factory=list)
    executed_units: Optional[int] = None
    loaded_accounts_data_size: Optional[int] = None
    return_data: Optional[str] = None


@dataclass
class ExecutedError:
    """The transaction was executed but failed (``is_ok=False``).

    Invariants:
        - ``fee_details`` is always present.
        - ``status`` is always present.
        - ``instruction_error`` only when ``status == 9``.
        - ``instruction_error_index`` and ``custom_error`` only when
          ``instruction_error`` is present.
    """

    status: int = 0
    fee_details: FeeDetails = field(default_factory=FeeDetails)
    instruction_error: Optional[int] = None
    instruction_error_index: Optional[int] = None
    custom_error: Optional[int] = None
    modified_accounts: list[AccountEntry] = field(default_factory=list)
    rollback_accounts: list[AccountEntry] = field(default_factory=list)
    executed_units: Optional[int] = None
    loaded_accounts_data_size: Optional[int] = None
    return_data: Optional[str] = None


#: Union of all result variants.
RecordResult = Union[SanitizationError, ExecutedSuccess, ExecutedError]


@dataclass
class Record:
    """A single parsed record from the configuration file.

    Each record starts with a header line (the record identifier) followed by
    a colon.  The ``result`` field holds the variant-specific data.  Use
    ``isinstance(record.result, ...)`` to discriminate:

        >>> if isinstance(record.result, ExecutedSuccess):
        ...     print(record.result.fee_details)

    Attributes:
        test_id: The full header string (without trailing colon).
        result: One of ``SanitizationError``, ``ExecutedSuccess``, or
            ``ExecutedError``.
    """

    test_id: str = ""
    result: Optional[RecordResult] = None


# ---------------------------------------------------------------------------
# Conversion: raw Block dicts -> dataclasses
# ---------------------------------------------------------------------------


def _records_from_raw(raw: OrderedDict[str, Block]) -> OrderedDict[str, Record]:
    """Convert an entire parsed OrderedDict into an OrderedDict of Records."""
    result: OrderedDict[str, Record] = OrderedDict()
    for test_id, block in raw.items():
        result[test_id] = _record_from_entry(test_id, block)
    return result


def _record_from_entry(test_id: str, block: Block) -> Record:
    """Convert a single (test_id, block) pair into a Record."""
    record = Record(test_id=test_id)

    if block.get("sanitization_error") is True:
        record.result = SanitizationError(
            status=block.get("status", 0),
            instruction_error=block.get("instruction_error"),
            instruction_error_index=block.get("instruction_error_index"),
        )
    elif block.get("executed") is True and block.get("is_ok") is True:
        record.result = ExecutedSuccess(
            fee_details=_fee_details(block.get("fee_details", {})),
            modified_accounts=_account_list(block.get("modified_accounts", [])),
            executed_units=block.get("executed_units"),
            loaded_accounts_data_size=block.get("loaded_accounts_data_size"),
            return_data=block.get("return_data"),
        )
    else:
        record.result = ExecutedError(
            status=block.get("status", 0),
            fee_details=_fee_details(block.get("fee_details", {})),
            instruction_error=block.get("instruction_error"),
            instruction_error_index=block.get("instruction_error_index"),
            custom_error=block.get("custom_error"),
            modified_accounts=_account_list(block.get("modified_accounts", [])),
            rollback_accounts=_account_list(block.get("rollback_accounts", [])),
            executed_units=block.get("executed_units"),
            loaded_accounts_data_size=block.get("loaded_accounts_data_size"),
            return_data=block.get("return_data"),
        )

    return record


def _fee_details(raw: Block | dict) -> FeeDetails:
    """Convert a fee_details dict into a FeeDetails."""
    return FeeDetails(
        transaction_fee=raw.get("transaction_fee", 0),
        prioritization_fee=raw.get("prioritization_fee"),
    )


def _account_list(raw: list | dict) -> list[AccountEntry]:
    """Convert account entries — handles single dict or list of dicts."""
    if isinstance(raw, dict):
        return [_account_entry(raw)]
    if isinstance(raw, list):
        return [_account_entry(item) for item in raw if isinstance(item, dict)]
    return []


def _account_entry(raw: dict) -> AccountEntry:
    """Convert an account dict into an AccountEntry."""
    return AccountEntry(
        address=raw.get("address", ""),
        lamports=raw.get("lamports"),
        data=raw.get("data"),
        executable=raw.get("executable", False),
        owner=raw.get("owner", ""),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

import pytest
from ..parser import TestParse


class TestHeaderVariants:
    """Test that all header formats are correctly parsed."""

    def test_hex_hash_slot_header(self):
        text = "00dc63d6f5824efa900302649eeca7983e5d3f5a_1834424:\nstatus: 9\n"
        records = parse(text)
        assert len(records) == 1
        r = records["00dc63d6f5824efa900302649eeca7983e5d3f5a_1834424"]
        assert r.test_id == "00dc63d6f5824efa900302649eeca7983e5d3f5a_1834424"

    def test_crash_header(self):
        text = "crash-0ae873089c62df6e15d3fc0a271485da355874c8:\nsanitization_error: true\nstatus: 9\n"
        records = parse(text)
        assert "crash-0ae873089c62df6e15d3fc0a271485da355874c8" in records

    def test_uuid_header(self):
        text = "aa7aa005-ba12-4d08-935d-18ed0bc1a54f:\nexecuted: true\nstatus: 9\n"
        records = parse(text)
        assert "aa7aa005-ba12-4d08-935d-18ed0bc1a54f" in records

    def test_name_header(self):
        text = "is_signer_err_handling:\nexecuted: true\n"
        records = parse(text)
        assert "is_signer_err_handling" in records


class TestParseMinimal:
    """Test parsing of minimal records."""

    def test_sanitization_error_only(self):
        text = """header1:
sanitization_error: true
status: 9
instruction_error: 3
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, SanitizationError)
        assert r.result.status == 9
        assert r.result.instruction_error == 3
        assert r.result.instruction_error_index is None

    def test_status_only(self):
        text = "header1:\nsanitization_error: true\nstatus: 27\n"
        r = parse(text)["header1"]
        assert isinstance(r.result, SanitizationError)
        assert r.result.status == 27

    def test_empty_text(self):
        assert parse("") == OrderedDict()
        assert parse("   \n\n  ") == OrderedDict()


class TestParseWithFeeDetails:
    """Test parsing of records with fee_details blocks."""

    def test_fee_details_basic(self):
        text = """header1:
executed: true
status: 9
instruction_error: 3
fee_details {
  transaction_fee: 15000
}
loaded_accounts_data_size: 26626
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedError)
        assert r.result.fee_details.transaction_fee == 15000
        assert r.result.fee_details.prioritization_fee is None
        assert r.result.loaded_accounts_data_size == 26626

    def test_fee_details_with_prioritization(self):
        text = """header1:
executed: true
is_ok: true
executed_units: 27829
fee_details {
  transaction_fee: 15000
  prioritization_fee: 1152604553296817704
}
loaded_accounts_data_size: 20198
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.executed_units == 27829
        assert r.result.fee_details.transaction_fee == 15000
        assert r.result.fee_details.prioritization_fee == 1152604553296817704


class TestParseModifiedAccounts:
    """Test parsing of records with modified_accounts blocks."""

    def test_single_account(self):
        text = """header1:
executed: true
is_ok: true
fee_details {
  transaction_fee: 10000
}
modified_accounts {
  address: "8fi2Typkf4m1z9miGfZQGRXDimBTVQqWHciMA9aZGXpN"
  lamports: 10733753813112760225
  owner: "11111111111111111111111111111111"
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        acct = r.result.modified_accounts[0]
        assert acct.address == "8fi2Typkf4m1z9miGfZQGRXDimBTVQqWHciMA9aZGXpN"
        assert acct.lamports == 10733753813112760225
        assert acct.owner == "11111111111111111111111111111111"
        assert acct.executable is False
        assert acct.data is None

    def test_multiple_accounts(self):
        text = """header1:
executed: true
is_ok: true
fee_details {
  transaction_fee: 5000
}
modified_accounts {
  address: "Addr1"
  executable: true
  owner: "Owner1"
}
modified_accounts {
  address: "Addr2"
  owner: "Owner2"
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        assert len(r.result.modified_accounts) == 2
        assert r.result.modified_accounts[0].executable is True
        assert r.result.modified_accounts[1].executable is False

    def test_account_with_data(self):
        text = """header1:
executed: true
is_ok: true
fee_details {
  transaction_fee: 5000
}
modified_accounts {
  address: "Addr1"
  data: "...137 zeros..."
  owner: "Owner1"
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.modified_accounts[0].data == "...137 zeros..."

    def test_account_without_lamports(self):
        text = """header1:
executed: true
is_ok: true
fee_details {
  transaction_fee: 5000
}
modified_accounts {
  address: "Addr1"
  owner: "Owner1"
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.modified_accounts[0].lamports is None


class TestParseRollbackAccounts:
    """Test parsing of rollback_accounts blocks."""

    def test_rollback_accounts(self):
        text = """header1:
executed: true
status: 4
fee_details {
  transaction_fee: 10000
}
rollback_accounts {
  address: "Addr1"
  lamports: 4295215558015524241
  executable: true
  owner: "Owner1"
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedError)
        assert len(r.result.rollback_accounts) == 1
        assert r.result.rollback_accounts[0].executable is True


class TestParseReturnData:
    """Test parsing of return_data fields."""

    def test_return_data(self):
        text = """header1:
executed: true
is_ok: true
fee_details {
  transaction_fee: 5000
}
modified_accounts {
  address: "Addr1"
  owner: "Owner1"
}
return_data: "a500000000000000"
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.return_data == "a500000000000000"


class TestParseCustomError:
    """Test parsing of custom_error field."""

    def test_custom_error(self):
        text = """header1:
executed: true
status: 9
instruction_error: 8
instruction_error_index: 2
custom_error: 7
fee_details {
  transaction_fee: 5000
}
"""
        r = parse(text)["header1"]
        assert isinstance(r.result, ExecutedError)
        assert r.result.custom_error == 7
        assert r.result.instruction_error_index == 2


class TestMultipleRecords:
    """Test parsing of multiple records separated by dashes."""

    def test_two_records(self):
        text = """header_a:
sanitization_error: true
status: 9

--------------------
header_b:
executed: true
status: 4
"""
        records = parse(text)
        assert len(records) == 2
        assert isinstance(records["header_a"].result, SanitizationError)
        assert isinstance(records["header_b"].result, ExecutedError)

    def test_three_records_with_trailing_separator(self):
        text = """a:\nsanitization_error: true\nstatus: 1\n
--------------------
b:\nsanitization_error: true\nstatus: 2\n
--------------------
c:\nsanitization_error: true\nstatus: 3\n
--------------------
"""
        records = parse(text)
        assert len(records) == 3

    def test_preserves_order(self):
        text = "bbb:\nsanitization_error: true\nstatus: 1\n\n--------------------\naaa:\nsanitization_error: true\nstatus: 2\n"
        records = parse(text)
        assert list(records.keys()) == ["bbb", "aaa"]


class TestVariantDiscrimination:
    """Test that the correct result variant is constructed."""

    def test_sanitization_error_variant(self):
        text = "h:\nsanitization_error: true\nstatus: 9\ninstruction_error: 3\n"
        r = parse(text)["h"]
        assert isinstance(r.result, SanitizationError)
        assert r.result.status == 9
        assert r.result.instruction_error == 3

    def test_executed_success_variant(self):
        text = """h:
executed: true
is_ok: true
executed_units: 1000
fee_details {
  transaction_fee: 5000
}
modified_accounts {
  address: "Addr1"
  owner: "Owner1"
}
"""
        r = parse(text)["h"]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.fee_details.transaction_fee == 5000
        assert r.result.executed_units == 1000
        assert len(r.result.modified_accounts) == 1

    def test_executed_error_variant(self):
        text = """h:
executed: true
status: 9
instruction_error: 8
custom_error: 42
fee_details {
  transaction_fee: 15000
}
"""
        r = parse(text)["h"]
        assert isinstance(r.result, ExecutedError)
        assert r.result.status == 9
        assert r.result.instruction_error == 8
        assert r.result.custom_error == 42

    def test_sanitization_error_has_no_fee_or_accounts(self):
        text = "h:\nsanitization_error: true\nstatus: 27\n"
        r = parse(text)["h"]
        assert isinstance(r.result, SanitizationError)
        assert not hasattr(r.result, "fee_details")
        assert not hasattr(r.result, "modified_accounts")


class TestParseFile:
    """Test file parsing against the actual data files."""

    def test_parse_parseme1_record_count(self):
        records = parse_file(TestParse.expected())
        assert len(records) == 5244
        for header, r in records.items():
            assert header != ""
            assert r.test_id == header
            assert r.result is not None

    def test_parse_parseme2_record_count(self):
        records = parse_file(TestParse.actual())
        assert len(records) == 5244

    def test_parseme1_first_record(self):
        records = parse_file(TestParse.expected())
        first_key = next(iter(records))
        assert first_key == "00dc63d6f5824efa900302649eeca7983e5d3f5a_1834424"
        r = records[first_key]
        assert isinstance(r.result, SanitizationError)
        assert r.result.status == 9
        assert r.result.instruction_error == 3

    def test_parseme1_second_record(self):
        records = parse_file(TestParse.expected())
        keys = list(records.keys())
        r = records[keys[1]]
        assert isinstance(r.result, ExecutedError)
        assert r.result.status == 9
        assert r.result.fee_details.transaction_fee == 15000
        assert r.result.loaded_accounts_data_size == 26626
        assert len(r.result.modified_accounts) == 7
        assert r.result.modified_accounts[0].address == "AgzPoim5Zy7s9YaGEvxUzGg5UbrSgsPXMRfebjixXBv4"
        assert r.result.modified_accounts[5].data == "...137 zeros..."
        assert len(r.result.rollback_accounts) == 1

    def test_parseme1_third_record_is_ok(self):
        records = parse_file(TestParse.expected())
        keys = list(records.keys())
        r = records[keys[2]]
        assert isinstance(r.result, ExecutedSuccess)
        assert r.result.executed_units == 1306
        assert r.result.fee_details.transaction_fee == 10000

    def test_parseme1_fourth_record_prioritization_fee(self):
        records = parse_file(TestParse.expected())
        keys = list(records.keys())
        r = records[keys[3]]
        assert isinstance(r.result, (ExecutedSuccess, ExecutedError))
        assert r.result.fee_details.prioritization_fee == 1152604553296817704

    def test_parseme1_has_all_header_types(self):
        records = parse_file(TestParse.expected())
        assert "crash-0ae873089c62df6e15d3fc0a271485da355874c8" in records
        assert "aa7aa005-ba12-4d08-935d-18ed0bc1a54f" in records
        assert "is_signer_err_handling" in records

    def test_parseme1_variant_counts(self):
        records = parse_file(TestParse.expected())
        san = sum(1 for r in records.values() if isinstance(r.result, SanitizationError))
        ok = sum(1 for r in records.values() if isinstance(r.result, ExecutedSuccess))
        err = sum(1 for r in records.values() if isinstance(r.result, ExecutedError))
        assert san + ok + err == len(records)
        assert san > 0 and ok > 0 and err > 0

    def test_parseme1_all_success_have_modified_accounts(self):
        records = parse_file(TestParse.expected())
        for r in records.values():
            if isinstance(r.result, ExecutedSuccess):
                assert len(r.result.modified_accounts) > 0
