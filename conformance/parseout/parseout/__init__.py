"""parseout - A parser for protobuf-text-like files.

Two layers:
    - ``parseout.parser``: text -> ``OrderedDict[str, dict]`` (format-level)
    - ``parseout.differ``: generic recursive diff on parsed dicts
    - ``parseout.transaction``: typed dataclasses, parsing, and diffing

Top-level ``parse`` / ``parse_file`` are the generic Layer 1 functions.
Top-level ``diff`` / ``diff_files`` are the generic differ functions.
Domain-specific modules live in subpackages (e.g. ``parseout.transaction``).
"""

from .parser import parse, parse_file, Block, Value
from .differ import diff, diff_files, Mismatch

# Make subpackage accessible as parseout.transaction
from . import transaction

__all__ = [
    "parse",
    "parse_file",
    "Block",
    "Value",
    "diff",
    "diff_files",
    "Mismatch",
    "transaction",
]
