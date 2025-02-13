---
sidebar_position: 1
title: LMDB for Accounts DB
---

# Experiment - using LMDB for Accounts DB ([#348](https://github.com/Syndica/sig/pull/348))

## Rationale

LMDB has some great properties which make it interesting for use with accountsdb:

- amazing read performance in pretty much every benchmark
- fully parallel reads (linear scaling with thread count)
- only one writer, but it never blocks reads
- zero-copy querying within transactions - no (de)serialisation/copies/allocations necessary

## Data layout

I came across a design with two maps:

1. A map from a Pubkey to Slot(s)
2. A map from a Pubkey and a Slot to a stored Account.

This allows for small key sizes and quickly finding all slots (especially the latest slot) for any given subkey.

## Initial results

Initial results, benchmarking with 100,000 simulated accounts, showed promising read performance. Read performance was slightly below our benchmark using memory-mapped accountfiles. Write performance was strangely slow.

## Findings

Some interesting things found along the way:

- Cursor and transaction objects given to us by lmdb are heap-allocated. This means that some extra performance can be squeezed out by reusing them. I did not implement this over concerns that it would complicate the API, and would only reduce (read) CPU time by around 10%, which wasn't nearly enough.

  - With `MDB_NOTLS` (and being careful), I believe we wouldn't have complicated our API much. Nonetheless, I decided against it.

- The time spent reading was dominated by CPU time in "mdb_get" and "mdb_cursor_get", which is the lmdb searching for the keys.

- Our initially bad write speed could be overcome by some flags:

  - `MDB_NOSYNC` can be safely used on most filesystems (with a small risk of losing some of the most recent writes - a non-issue for us). This dramatically improved write speed (~35x), becoming more than usable.
  - `MDB_NOLOCK` can also be safely used if we make sure to only have one writer - this could save some time.

- Read speed unfortunately could not be greatly improved; the read speed was bad because of the lookups, and this only got worse with larger key sizes. One optimisation not attempted is zero-copy reads, however, this complicates API usage (and wouldn't have meaningfully helped us).

- I did briefly consider sharding the database, which would dramatically improve our read speeds by having cheaper lookups and more parallel writers, however, this came with a large number of downsides:
  - Some consistency is lost, making it harder to recover from a crash - transactions cannot exist across databases.
  - Complicates our usage substantially.

## The heart of the issue

LMDB seems to be amazing for sorted data. For some of our queries, sorting is helpful. For example, if we need to get all pubkeys for a slot, we can look over the data by slot; this would mean only one expensive lookup and from there only a few iterations to get the rest of the pubkeys.

However, for most of our queries, sorting is not meaningful; pubkeys are the largest part of all of our keys, and they're completely unordered. This means that the final lookup of (Pubkey, Slot) -> Account-Data will never use lmdb's fast path.

This meant eating the cost of an O(logn) lookup (or two) for almost every query, and when N in the real world is approaching a billion this is suddenly a big problem; performance degraded far beyond the point of usefulness when approaching 10 million keys in testing.

Because of this, we decided not to move forward with using LMDB. See #348 for more details.
