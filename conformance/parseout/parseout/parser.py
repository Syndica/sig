"""Generic parser for the protobuf-text-like serialization format.

Converts raw text into ``OrderedDict[str, dict]`` where each key is a
record header and each value is a nested dict of fields.  Knows nothing
about domain-specific types.

Value types produced:
    - ``bool`` for ``true`` / ``false``
    - ``int`` for bare integer literals
    - ``str`` for quoted strings (quotes stripped)
    - ``dict`` for nested ``{ }`` blocks
    - ``list`` when the same key appears more than once in a block
"""

from __future__ import annotations

from collections import OrderedDict
import os
from pathlib import Path
from typing import Union

# 20 hyphens exactly, the record separator
_SEPARATOR = "-" * 20

#: The scalar types the parser produces.
Value = Union[bool, int, str]

#: A parsed block: keys map to scalars, nested dicts, or lists thereof.
Block = dict[str, "Value | Block | list[Value | Block]"]


def parse(text: str) -> OrderedDict[str, Block]:
    """Parse *text* into an ordered mapping of header -> fields dict.

    Args:
        text: Full file content.

    Returns:
        OrderedDict keyed by record header (str), values are nested dicts.
    """
    result: OrderedDict[str, Block] = OrderedDict()
    lines = text.splitlines()
    chunk: list[str] = []

    for line in lines:
        if line.strip() == _SEPARATOR:
            if chunk:
                header, block = _parse_chunk(chunk)
                if header is not None:
                    result[header] = block
                chunk = []
        else:
            chunk.append(line)

    if chunk:
        header, block = _parse_chunk(chunk)
        if header is not None:
            result[header] = block

    return result


def parse_file(path: str | Path) -> OrderedDict[str, Block]:
    """Parse a file into an ordered mapping of header -> fields dict.

    Args:
        path: Path to the text file.

    Returns:
        OrderedDict keyed by record header (str), values are nested dicts.
    """
    return parse(Path(path).read_text())


def _parse_chunk(lines: list[str]) -> tuple[str | None, Block]:
    """Parse a single record chunk into (header, fields dict)."""
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]

    if not lines:
        return None, {}

    header = lines[0].strip()
    if header.endswith(":"):
        header = header[:-1]

    block = _parse_block_lines(lines[1:])
    return header, block


def _parse_block_lines(lines: list[str]) -> Block:
    """Parse lines within a block (or at record top level) into a dict.

    If the same key appears more than once, the values are collected into
    a list.
    """
    result: Block = {}
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            i += 1
            continue

        # Block opening: "field_name {"
        if stripped.endswith("{"):
            name = stripped[:-1].rstrip()
            if name and name.replace("_", "").isalnum():
                inner_lines, end_idx = _collect_brace_block(lines, i + 1)
                value = _parse_block_lines(inner_lines)
                _insert(result, name, value)
                i = end_idx + 1
                continue

        # Key: value pair
        kv = _split_kv(stripped)
        if kv is not None:
            key, raw = kv
            _insert(result, key, _parse_scalar(raw))
            i += 1
            continue

        i += 1

    return result


def _collect_brace_block(lines: list[str], start: int) -> tuple[list[str], int]:
    """Collect lines inside matching braces, handling nesting."""
    depth = 1
    collected: list[str] = []
    i = start
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "}":
            depth -= 1
            if depth == 0:
                return collected, i
        elif stripped.endswith("{"):
            depth += 1
            collected.append(lines[i])
        else:
            collected.append(lines[i])
        i += 1
    return collected, len(lines) - 1


def _split_kv(line: str) -> tuple[str, str] | None:
    """Split ``key: value`` into (key, raw_value), or None."""
    colon = line.find(":")
    if colon < 1:
        return None
    key = line[:colon]
    if not key.replace("_", "").isalnum():
        return None
    rest = line[colon + 1:]
    if not rest or rest[0] != " ":
        return None
    value = rest.lstrip(" ")
    if not value:
        return None
    return key, value


def _parse_scalar(raw: str) -> Value:
    """Parse a raw scalar string into bool, int, or str."""
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        return raw


def _insert(block: Block, key: str, value: Value | Block) -> None:
    """Insert a value into a block dict, promoting to list on duplicates."""
    if key not in block:
        block[key] = value
    else:
        existing = block[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            block[key] = [existing, value]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

from pathlib import Path


class TestParse:
    """Tests for the generic text -> OrderedDict parser."""

    @staticmethod
    def expected():
        print("Running this test requires some conformance outputs to already be generated.")
        return os.path.join(
            "../env/test-outputs/txn/fixtures/expected", 
            list(Path("../env/test-outputs/txn/fixtures/expected").glob("*.txt"))[0].name,
        )

    @staticmethod
    def actual():
        print("Running this test requires some conformance outputs to already be generated.")
        return os.path.join(
            "../env/test-outputs/txn/fixtures/actual",
        list(Path("../env/test-outputs/txn/fixtures/actual").glob("*.txt"))[0].name,
    )

    def test_single_record(self):
        raw = parse("my_header:\nstatus: 9\n")
        assert list(raw.keys()) == ["my_header"]
        assert raw["my_header"] == {"status": 9}

    def test_preserves_order(self):
        raw = parse("bbb:\nx: 1\n\n--------------------\naaa:\nx: 2\n")
        assert list(raw.keys()) == ["bbb", "aaa"]

    def test_bool_values(self):
        raw = parse("h:\nflag_a: true\nflag_b: false\n")
        assert raw["h"]["flag_a"] is True
        assert raw["h"]["flag_b"] is False

    def test_int_values(self):
        raw = parse("h:\ncount: 42\nbig: 1152604553296817704\n")
        assert raw["h"]["count"] == 42
        assert raw["h"]["big"] == 1152604553296817704

    def test_quoted_string_values(self):
        raw = parse('h:\naddr: "abc123"\n')
        assert raw["h"]["addr"] == "abc123"

    def test_nested_block(self):
        raw = parse("h:\ninner {\n  x: 1\n}\n")
        assert raw["h"]["inner"] == {"x": 1}

    def test_repeated_blocks_become_list(self):
        raw = parse("h:\nitems {\n  n: 1\n}\nitems {\n  n: 2\n}\n")
        assert isinstance(raw["h"]["items"], list)
        assert len(raw["h"]["items"]) == 2
        assert raw["h"]["items"][0] == {"n": 1}
        assert raw["h"]["items"][1] == {"n": 2}

    def test_single_block_is_not_list(self):
        raw = parse("h:\nitems {\n  n: 1\n}\n")
        assert isinstance(raw["h"]["items"], dict)

    def test_empty_text(self):
        assert parse("") == {}
        assert parse("   \n\n  ") == {}

    def test_multiple_records_with_separator(self):
        raw = parse("a:\nx: 1\n\n--------------------\nb:\ny: 2\n\n--------------------\n")
        assert len(raw) == 2
        assert raw["a"] == {"x": 1}
        assert raw["b"] == {"y": 2}

    def test_header_without_colon(self):
        raw = parse("bare_header\nval: 1\n")
        assert "bare_header" in raw

    def test_full_file_parseme1(self):
        raw = parse(open(TestParse.expected()).read())
        assert len(raw) == 5244

    def test_full_file_parseme2(self):
        raw = parse(open(TestParse.actual()).read())
        assert len(raw) == 5244
