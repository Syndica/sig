# parseout

A parser and differ for the conformance test outputs. Useful for categorizing or
interpreting a large number of failed tests. Compares expected and actual
results, identifies mismatches, and categorizes them based on the types of
mismatches.

## Quick start

```bash
parseout diff expected.txt actual.txt
```

or for a smarter version that handles transaction harness failures better than `diff`:

```bash
parseout txn
```

This produces three output files prints a summary
to stdout:

- **\*.csv:** one row per mismatch (`header, categories`), sorted so rows
  with the same category combination are adjacent.
- **\*-category.json:** mismatches grouped by individual category. A
  mismatch appears under every category it belongs to.
- **\*-combo.json:** mismatches grouped by their exact combination of
  categories. Each mismatch appears under exactly one key.

### Example stdout summary

```
1818 mismatches written to txn.csv, txn-category.json, txn-combo.json

Categories:
  result_type: 1194
  status: 233
  instruction_error: 312
  ...

Combinations:
  result_type: 1194
  modified_accounts+rollback_accounts: 185
  instruction_error+status: 155
  ...
```

**Categories** lists every individual category with the total number of
mismatches it appears in (a mismatch can be counted under multiple
categories).

**Combinations** lists every unique set of categories as a single entry,
with the count of mismatches that have exactly that combination.

## Subcommands

### `diff` -- generic diff

```bash
parseout diff <expected> <actual>
```

Uses the generic parser only. Recursively compares every field in each record
and generates diff categories dynamically from the field path where differences
occur. Category naming:

- `field.subfield` -- values differ at that path
- `field.0.subfield` -- values differ at list index 0, subfield
- `field-missing` -- field exists in expected but not actual
- `field-unexpected` -- field exists in actual but not expected
- `field` (for lists) -- list lengths differ

Outputs `diff.csv`, `diff-category.json`, `diff-combo.json` to the current
directory.

### `txn` -- transaction diff

```bash
parseout txn [expected] [actual]
```

A domain-specific differ for transaction conformance outputs.

The generic differ makes a best effort at detecting differences in fields, but it
doesn't encode any domain-specific knowledge. For the transaction harness, the
mismatch categories from `diff` can be confusing. That's where this `txn` command comes in handy.

This parses both files into typed records with known fields (status, fee_details,
modified_accounts, etc.) and compares them using a fixed set of categories
tailored to transaction semantics.

`<expected>` and `<actual>` are optional. If omitted, it will locate files in
`env/test-outputs/txn/fixtures/` and place the outputs there as well.

Outputs `txn.csv`, `txn-category.json`, `txn-combo.json`.

### `parse` -- generic parse

```bash
parseout parse <input-file>
```

Converts a single test output file from the protobuf text format into JSON
using the generic parser. Prints to stdout. Useful if you'd like to interpret
the results in a separate program that is able to parse json.

## Architecture

The parser is split into two layers. The layers are composable and you can import
them as a library into python scripts for custom interpretations of test results.

There are also two differs that each operate on the two parsing layers.

### Parse Layer 1: generic parser (`parseout.parser`)

Parses the protobuf-text-like format into `OrderedDict[str, dict]`. Handles
record headers, key-value pairs, nested `{ }` blocks, and record separators
(lines of 20 hyphens). No regex -- uses only string operations.

### Parse Layer 2: transaction parser (`parseout.transaction.parser`)

Converts the generic dicts into a typed dataclass hierarchy:

- **Record:** wraps a `test_id` and a result variant.
- **SanitizationError:** the transaction failed before execution.
- **ExecutedSuccess:** the transaction executed and succeeded.
- **ExecutedError:** the transaction executed but failed.
- **FeeDetails:** fee breakdown (transaction fee, prioritization fee).
- **AccountEntry:** a modified or rollback account.

The result variant is a tagged union discriminated by the `sanitization_error`,
`executed`, and `is_ok` fields in the raw data.

### Generic differ (`parseout.differ`) - Layer 1 diff

Compares two parsed `OrderedDict[str, Block]` collections by shared headers.
Recursively walks every field and generates categories from the path where
values diverge. Works on any file the generic parser can read.

### Transaction differ (`parseout.transaction.differ`) - Layer 2 diff

Compares two parsed `OrderedDict[str, Record]` collections by shared test IDs.
Each mismatch is tagged with one or more `Category` values from a fixed enum:

| Category                    | Description                                     |
| --------------------------- | ----------------------------------------------- |
| `result_type`               | Different variant types (e.g. success vs error) |
| `status`                    | Different status codes                          |
| `instruction_error`         | Different instruction error codes               |
| `instruction_error_index`   | Different instruction error indices             |
| `custom_error`              | Different custom error codes                    |
| `fee_details`               | Different fee breakdowns                        |
| `executed_units`            | Different compute unit counts                   |
| `loaded_accounts_data_size` | Different loaded account data sizes             |
| `return_data`               | Different return data                           |
| `modified_accounts`         | Different modified account lists                |
| `rollback_accounts`         | Different rollback account lists                |

When two records have different variant types, only `result_type` is reported.

## Input format

Each file contains records separated by lines of exactly 20 hyphens
(`--------------------`). Each record starts with a header line (the test ID)
followed by a colon, then key-value pairs and nested blocks:

```
some_test_id:
executed: true
is_ok: true
executed_units: 27829
fee_details {
  transaction_fee: 15000
  prioritization_fee: 500
}
modified_accounts {
  address: "8fi2Typkf4m1z9miGfZQGRXDimBTVQqWHciMA9aZGXpN"
  lamports: 10733753813112760225
  owner: "11111111111111111111111111111111"
}
--------------------
another_test_id:
sanitization_error: true
status: 9
```

## Tests

```bash
pytest
```

151 tests run inline in the source files (parser, generic differ, transaction
parser, transaction differ).

## Python API

```python
# Generic diff -- works on any file, dynamic categories
from parseout import diff_files

mismatches = diff_files("expected.txt", "actual.txt")
for m in mismatches:
    print(m.header, m.categories)

# Transaction diff -- typed records, fixed categories
from parseout.transaction import parse_file, diff_files, Category

expected = parse_file("expected.txt")
actual = parse_file("actual.txt")

mismatches = diff_files("expected.txt", "actual.txt")
for m in mismatches:
    print(m.test_id, m.categories)
```
