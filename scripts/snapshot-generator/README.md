# Snapshot Generator

Uses agave code to construct an artificial Solana snapshot with fake data for testing.

Goals:
- very small file that can be committed into a git repo
- snapshot itself is internally consistent and passes agave validations

The output is not deterministic and will vary from run to run due to (at least)
the use of timestamps in the blockhash queue and the random seeds in rust
hashmaps that are determined at runtime.

## Build & run

```
cargo run -- PREFIX
```

- Requires `zstd` on `$PATH`.

## Output

Writes two files:

- `PREFIX.tar.zst`: the snapshot.
- `PREFIX.json`: decoded values for checking parser output.

Maps in the JSON summary are sorted by key for stable display.

## JSON layout

The JSON has five top-level sections:

- `bank_fields`: values from the main bank snapshot body.
- `extra_fields`: values from the extra-fields tail at the end of the bank snapshot.
- `merged_fields`: the effective bank state after applying `extra_fields`.
- `accounts`: append-vec files, all account records, and the live account subset.
- `status_cache`: decoded `snapshots/status_cache` contents.

The three field sections are intentionally separate:

- `bank_fields` is for testing parsers that read the main bank body.
- `extra_fields` is for testing parsers that read the trailing extra fields.
- `merged_fields` is for testing the final model a parser should expose.

Some values intentionally differ across sections. For example,
`bank_fields.fee_rate_governor.lamports_per_signature` differs from
`extra_fields.lamports_per_signature`. Agave uses the extra-field value, so
`merged_fields.fee_rate_governor.lamports_per_signature` matches
`extra_fields.lamports_per_signature`.

`merged_fields.slot_history_found_slots` is the decoded meaning of the slot
history sysvar bitset. `accounts.live_indices` identifies which records in
`accounts.entries` are live after duplicate account resolution.

## Snapshot Contents

The contents are described in detail by the produced JSON file, but here's the high-level overview:

- 8 total accounts represented with 9 account records across 3 append-vec
  files. One account has an old version at slot 98 and a live version at slot
  100.
- `accounts_lt_hash` computed from the live accounts.
- 2 blockhashes, 2 hard forks, 2 stake history entries.
- 2 vote accounts and 2 stake delegations in the current `Stakes`.
- 2 epochs in `versioned_epoch_stakes`, each with 2 vote accounts and
  2 stake delegations.
- Non-default scalars. Mainnet defaults for `EpochSchedule`, `Inflation`,
  `FeeRateGovernor`.
- Used `Option<T>` fields in `ExtraFieldsToSerialize` set to `Some`. Ignored
  fields are `None`.
- Non-empty `status_cache`: 3 slot deltas, each with 1 blockhash bucket
  holding one `Ok` and one `Err(InstructionError(3, Custom(9)))`.

## Tar layout

```
version                        "1.2.0"
snapshots/
snapshots/status_cache         3 slot deltas
snapshots/<slot>/
snapshots/<slot>/<slot>        agave-serialized manifest
accounts/
accounts/98.1                  1 AppendVec entry
accounts/99.2                  1 AppendVec entry
accounts/100.3                 7 AppendVec entries
```

## Format drift

Bank/manifest layout is defined by agave and this tool tracks it
automatically. A few things are hand-encoded and can drift independently:

- 136-byte AppendVec header with a zero hash field
  (agave/accounts-db/src/accounts_file/meta.rs).
- Status cache wire format. See `build_status_cache`.
