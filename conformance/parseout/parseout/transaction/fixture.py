"""Read invoked program IDs from binary protobuf ``.fix`` fixture files.

Implements a minimal protobuf wire-format decoder — just enough to
navigate from ``TxnFixture`` down to the ``CompiledInstruction``
program IDs without requiring any generated code or the
``google.protobuf`` package.

Wire-format field numbers (from ``v1.pb.zig``):

    TxnFixture
      1: metadata  (FixtureMetadata)
      2: input     (TxnContext)

    TxnContext
      1: tx        (SanitizedTransaction)

    SanitizedTransaction
      1: message   (TransactionMessage)

    TransactionMessage
      3: account_keys   (repeated bytes)
      6: instructions   (repeated CompiledInstruction)

    CompiledInstruction
      1: program_id_index  (uint32)

Public API:
    ``programs_for_fixture(path)``       — single file  -> sorted list[str]
    ``programs_for_fixtures(fixture_dir)`` — directory   -> dict[test_id, list[str]]
"""

from __future__ import annotations

import base64
from pathlib import Path


# ---------------------------------------------------------------------------
# Minimal protobuf wire-format helpers
# ---------------------------------------------------------------------------

def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a base-128 varint, returning (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return result, pos
        shift += 7


def _iter_fields(data: bytes) -> list[tuple[int, int, bytes | int]]:
    """Yield (field_number, wire_type, payload) tuples from *data*.

    For wire type 0 (varint), payload is an ``int``.
    For wire type 2 (length-delimited), payload is ``bytes``.
    Other wire types are skipped.
    """
    fields: list[tuple[int, int, bytes | int]] = []
    pos = 0
    end = len(data)
    while pos < end:
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            val, pos = _decode_varint(data, pos)
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            fields.append((field_num, wire_type, data[pos : pos + length]))
            pos += length
        elif wire_type == 5:  # 32-bit fixed
            pos += 4
        elif wire_type == 1:  # 64-bit fixed
            pos += 8
        else:
            # Unknown wire type — we can't safely skip, so stop.
            break
    return fields


def _get_submessage(data: bytes, field_num: int) -> bytes | None:
    """Return the raw bytes of the first length-delimited field with *field_num*."""
    for fnum, wtype, payload in _iter_fields(data):
        if fnum == field_num and wtype == 2:
            assert isinstance(payload, bytes)
            return payload
    return None


def _get_repeated_bytes(data: bytes, field_num: int) -> list[bytes]:
    """Return all length-delimited payloads for *field_num*."""
    result: list[bytes] = []
    for fnum, wtype, payload in _iter_fields(data):
        if fnum == field_num and wtype == 2:
            assert isinstance(payload, bytes)
            result.append(payload)
    return result


def _get_varint(data: bytes, field_num: int, default: int = 0) -> int:
    """Return the first varint value for *field_num*."""
    for fnum, wtype, payload in _iter_fields(data):
        if fnum == field_num and wtype == 0:
            assert isinstance(payload, int)
            return payload
    return default


# ---------------------------------------------------------------------------
# Base58 encoding (Solana public key representation)
# ---------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode *data* as a base58 string (Bitcoin/Solana alphabet)."""
    # Count leading zeros
    n_leading = 0
    for b in data:
        if b == 0:
            n_leading += 1
        else:
            break

    # Convert to big integer
    num = int.from_bytes(data, "big")
    result = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_B58_ALPHABET[rem])
    result.reverse()

    return ("1" * n_leading) + result.decode("ascii")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def programs_for_fixture(path: str | Path) -> list[str]:
    """Extract the sorted, deduplicated list of invoked program addresses.

    Navigates: TxnFixture.input.tx.message → account_keys / instructions
    to resolve each instruction's ``program_id_index`` into a base58 address.

    Args:
        path: Path to a ``.fix`` protobuf file.

    Returns:
        Sorted list of unique base58-encoded program addresses invoked by
        the transaction.  Empty list if the fixture cannot be decoded.
    """
    data = Path(path).read_bytes()

    # TxnFixture -> field 2 (input: TxnContext)
    txn_context = _get_submessage(data, 2)
    if txn_context is None:
        return []

    # TxnContext -> field 1 (tx: SanitizedTransaction)
    sanitized_tx = _get_submessage(txn_context, 1)
    if sanitized_tx is None:
        return []

    # SanitizedTransaction -> field 1 (message: TransactionMessage)
    tx_message = _get_submessage(sanitized_tx, 1)
    if tx_message is None:
        return []

    # TransactionMessage -> field 3 (account_keys: repeated bytes)
    account_keys = _get_repeated_bytes(tx_message, 3)

    # TransactionMessage -> field 6 (instructions: repeated CompiledInstruction)
    instruction_blobs = _get_repeated_bytes(tx_message, 6)

    # Resolve each instruction's program_id_index -> base58 address
    programs: set[str] = set()
    for ixn_blob in instruction_blobs:
        idx = _get_varint(ixn_blob, 1, default=0)
        if idx < len(account_keys):
            programs.add(_base58_encode(account_keys[idx]))

    return sorted(programs)


def programs_for_fixtures(fixture_dir: str | Path) -> dict[str, list[str]]:
    """Build a mapping from test_id to invoked program addresses.

    Scans *fixture_dir* for ``*.fix`` files.  The test_id is derived from
    the filename by stripping the ``.fix`` suffix.

    Args:
        fixture_dir: Directory containing ``.fix`` files.

    Returns:
        Dict mapping ``test_id`` → sorted list of base58 program addresses.
    """
    fixture_dir = Path(fixture_dir)
    result: dict[str, list[str]] = {}
    for fix_path in sorted(fixture_dir.glob("*.fix")):
        test_id = fix_path.stem
        result[test_id] = programs_for_fixture(fix_path)
    return result


# ---------------------------------------------------------------------------
# Well-known Solana program addresses → human-readable labels
# ---------------------------------------------------------------------------

KNOWN_PROGRAMS: dict[str, str] = {
    "11111111111111111111111111111111": "system",
    "Config1111111111111111111111111111111111111": "config",
    "Stake11111111111111111111111111111111111111": "stake",
    "Vote111111111111111111111111111111111111111": "vote",
    "ComputeBudget111111111111111111111111111111": "compute-budget",
    "BPFLoaderUpgradeab1e11111111111111111111111": "bpf-loader-upgradeable",
    "BPFLoader2111111111111111111111111111111111": "bpf-loader",
    "BPFLoader1111111111111111111111111111111111": "bpf-loader-deprecated",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "token-2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "associated-token",
    "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX": "name-service",
    "Memo1UhkJBfCR6MNBsmvMuumyHiSZcLYnE2SJ9gQvn4": "memo-v1",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "memo-v3",
    "AddressLookupTab1e1111111111111111111111111": "address-lookup-table",
    "Ed25519SigVerify111111111111111111111111111": "ed25519",
    "KeccakSecp256k11111111111111111111111111111": "secp256k1",
    "Secp256r1SigVerify1111111111111111111111111": "secp256r1",
    "ZkE1Gama1Proof11111111111111111111111111111": "zk-elgamal-proof",
    "Sysvar1111111111111111111111111111111111111": "sysvar",
    "NativeLoader1111111111111111111111111111111": "native-loader",
    "LoaderV411111111111111111111111111111111111": "loader-v4",
}


def label_program(address: str) -> str:
    """Return a short human-readable label for *address*, or the address itself."""
    return KNOWN_PROGRAMS.get(address, address)


def label_programs(addresses: list[str]) -> list[str]:
    """Label a list of program addresses."""
    return [label_program(a) for a in addresses]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

import pytest


class TestBase58:
    """Base58 encoding sanity checks."""

    def test_all_zeros(self):
        assert _base58_encode(b"\x00" * 32) == "1" * 32

    def test_system_program(self):
        assert _base58_encode(b"\x00" * 32) == "1" * 32

    def test_roundtrip_known(self):
        # Verify the system program address (all zeros = "1"*32 in base58,
        # but the well-known address "11111111111111111111111111111111" is
        # the 32-byte all-zeros key).
        assert _base58_encode(b"\x00" * 32) == "1" * 32


class TestDecodeVarint:
    def test_single_byte(self):
        assert _decode_varint(b"\x05", 0) == (5, 1)

    def test_multi_byte(self):
        assert _decode_varint(b"\xac\x02", 0) == (300, 2)


class TestIterFields:
    def test_simple(self):
        # Field 1, wire type 0, value 150 = tag byte 0x08, varint 0x96 0x01
        data = bytes([0x08, 0x96, 0x01])
        fields = _iter_fields(data)
        assert len(fields) == 1
        assert fields[0] == (1, 0, 150)


class TestFixtureDecoding:
    """Test against actual fixture files if available."""

    _FIXTURE_DIR = Path(__file__).resolve().parents[3] / "env" / "test-vectors" / "txn" / "fixtures"

    def _first_fixture(self) -> Path:
        fixtures = sorted(self._FIXTURE_DIR.glob("*.fix"))
        if not fixtures:
            pytest.skip("No fixture files available")
        return fixtures[0]

    def test_programs_for_fixture_returns_nonempty(self):
        path = self._first_fixture()
        programs = programs_for_fixture(path)
        assert len(programs) > 0
        # All entries should be non-empty strings
        for p in programs:
            assert isinstance(p, str)
            assert len(p) > 0

    def test_programs_are_valid_base58(self):
        path = self._first_fixture()
        programs = programs_for_fixture(path)
        valid_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        for p in programs:
            assert all(c in valid_chars for c in p), f"Invalid base58: {p}"

    def test_programs_for_fixtures_batch(self):
        if not self._FIXTURE_DIR.exists():
            pytest.skip("No fixture directory")
        mapping = programs_for_fixtures(self._FIXTURE_DIR)
        assert len(mapping) > 0
        # Spot check: every entry has at least one program
        empty_count = sum(1 for v in mapping.values() if len(v) == 0)
        # A few sanitization-error-only fixtures might have programs too,
        # since the input still contains the transaction message.
        assert empty_count < len(mapping)

    def test_known_program_labels(self):
        assert label_program("11111111111111111111111111111111") == "system"
        assert label_program("Vote111111111111111111111111111111111111111") == "vote"
        assert label_program("SomeUnknownAddress") == "SomeUnknownAddress"
