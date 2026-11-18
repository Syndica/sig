# Upstream issue validation & TODO

Cross-validation of the external research report *"Additional Unresolved Issues (beyond those already
cited) in Syndica/sig"* against this checkout and the live upstream state.

- Checked-out commit: `b5026c60` (`lint: conformed runtime to v2 lints (#1772)`)
- Issue states read from the GitHub API on 2026-11-17
- Verified on Ubuntu 24.04 (WSL) with Zig 0.15.2, Agave CLI 4.3.2

## Verdict summary

| # | Report claim | Report's status | Verified status | Verdict |
|---|---|---|---|---|
| 1727 | v2 skips `accounts_lt_hash` verification | open, no PR, v2 | open; v2 also has no `LtHash` type and verifies no accounts hash at all | **Confirmed** (worse than reported) |
| 1564 | Gossip `BitVec` null-bits panic, v2 | open bug, no PR, v2 | **closed** 2026-07-29 as `not_planned`; the code is **v1**, not v2; v2 cannot hit it | **Report wrong on status and location**, bug real in v1 |
| 1729 | Snapshot `block_id` deserialization offsets | open, no detail | open but **empty body**; `block_id` is read last and is covered by an Agave-fixture test | **Not reproducible at HEAD** |
| 1712 | AccountsDB grows unbounded, no compaction | open, v2 | open; `TODO: The ring aspect is not implemented` in `v2/components/accounts_db/rooted.zig` | **Confirmed** (fixed on this branch) |
| — | Other SVM syscalls may leak stale pointers | speculative | v2 translates addresses per syscall; no stale-pointer pattern | **Refuted for v2** |

Issue **states** the report gets right: 1727 and 1712 are open with no linked PR. It gets 1564 wrong
(closed) and overstates 1729 (no body, and a mechanism that contradicts the code).

## Evidence per claim

### 1727 — `accounts_lt_hash` is not verified (v2)

- `v2/lib/solana/snapshot.zig:484` discarded the field outright:
  `if (is_some) try r.discardAll(2048); // LtHash = [1024]u16`
- `AccountsDbFields.read` also discards `_unused_accounts_delta_hash` and `_unused_accounts_hash`
  (`snapshot.zig:336-346`), so **no account checksum of any kind is validated** on the v2 load path.
- There was no lattice-hash implementation anywhere in `v2/` — only the feature-flag names in
  `v2/lib/solana/features.zon`.
- v1 is **not** affected: `v1/src/accountsdb/snapshot/load.zig:155-215` verifies both full and
  incremental `accounts_lt_hash` and rejects mismatches.

Compatibility nuance that the report misses, and that changes the fix: Agave's `accounts_lt_hash`
covers the **live** account set. Snapshot append-vecs contain superseded versions of the same
pubkey. In the repo's own Agave fixture there are 9 stored accounts but only 8 live ones
(`data/test-data/test-snapshot-v4.2.0-beta.1.json`), and summing all 9 gives the wrong hash. A naive
"hash every account as you stream it" check would therefore reject valid mainnet snapshots.

### 1564 — null `BitVec` panic

- Location is `v1/src/gossip/data.zig:899`, not `v2/lib/gossip/data.zig`; v2 has no such file and no
  `BitVec` type shaped like that.
- v2's equivalent (`v2/components/gossip/bincode.zig:143`) stores `words: []T` — non-nullable — and
  maps the wire's absent vec to an empty slice, so the eviction panic cannot occur.
- The bug was real in v1 and still present at HEAD: `allocator.free(self.bits.?)` with
  `bits: ?[]T`, reachable because `Uncompressed.sanitize` still has `// TODO: check BitVec.capacity()`.
- Fixed here (see below). v2 needs no change.

### 1729 — snapshot `block_id` offsets

- The issue has no body; the report's "loader isn't advancing past `block_id`" and "off by a fixed
  offset" are invented from the title.
- In the code, `block_id` is the **last** field read in `ExtraFields.read`, preceded by explicit
  discards for `lamports_per_signature`, incremental-snapshot persistence, epoch accounts hash,
  versioned epoch stakes and `accounts_lt_hash`. There is no trailing field to misalign.
- `test "deserialized snapshot matches generated snapshot json"` (`snapshot.zig:816`) deserializes a
  snapshot produced by Agave v4.2.0-beta.1 and asserts `block_id`, slot, blockhash queue and account
  entries against Agave's own JSON. It passes at HEAD. That commit (#1734) landed five days after
  this issue was opened, which is the likely resolution.
- Residual risk: the fixture is v4.2.0-beta.1 while the installed CLI is 4.3.2. Fixtures should be
  regenerated periodically (the test's own header says so).

### 1712 — unbounded AccountsDB growth

- Confirmed in `v2/components/accounts_db/rooted.zig:22-23`:
  `TODO: The ring aspect is not implemented, so for now it grows indefinitely.`
- Refinement: the growth is in the on-disk journal / append-vec file that is mapped into the process,
  not in an allocator. Impact is the same for long-running nodes: disk and page-cache growth.
- v1 uses a different accounts-db layout and is not subject to this specific TODO.
- Implemented on this branch: the file has an explicit fixed capacity, data lives in
  `[1 MiB, capacity)`, and compaction runs between transactions to drop stale sectors and relocate
  live ones before the head wraps. See the P1 entries under "Changes made".

### Speculative "stale pointer" syscalls

v2 syscalls translate guest addresses on every call and never retain host pointers:

- `memops.memcpy` (`v2/components/runtime/vm/syscalls/memops.zig:54`) — `translateSlice` for source
  and destination plus an overlap check before `@memcpy`.
- `memops.memcmp` (`:96`) — result is written through `translateType`, not a cached pointer.
- `getReturnData` (`vm/syscalls/lib.zig:533`) — both pointers translated, overlap-checked, then copied.

No action needed for v2.

## Changes made in this branch

1. **`v2/lib/solana/lt_hash.zig` (new)** — Agave-compatible lattice hash: `[1024]u16` elements,
   wrapping add/sub, `checksum`, and `hashAccount` using blake3 in extendable-output mode
   (2048 bytes). Field order is `lamports (u64 LE) || data || executable || owner || pubkey`;
   `rent_epoch` is excluded and zero-lamport accounts hash to the identity. `AccountHasher` is the
   streaming form of `hashAccount` (init → update data → final) used by the loader so account data
   never has to be buffered.
2. **`v2/lib/solana/snapshot.zig`** — `ExtraFields` now parses and retains `accounts_lt_hash`
   instead of discarding it, and no longer silently drops a corrupt field.
3. **`v2/components/accounts_db/table.zig`** — added `Table.iterator` / `Table.Item`, which yield
   each live entry exactly once (including the special-cased zero pubkey), so the live account set
   can be scanned without exposing the table's internals.
4. **`v2/components/accounts_db/rooted.zig`** — `loadSnapshot` now verifies the manifest against the
   loaded accounts:
   - `verifyAccountsLtHash` recomputes the lattice hash over the live table and returns
     `error.AccountsLtHashMismatch` on disagreement. It runs **before** `commitTransaction`, so a
     bad snapshot is never recorded as a valid database.
   - `hashAccountAt` reads an account's on-disk header/data (streaming in 64 KiB chunks, using the
     buffered fd) and hashes it, rather than buffering accounts up to 10 MiB.
   - Live-set semantics match Agave: the table holds the highest-slot version of each pubkey and
     superseded journal entries are deliberately not mixed in (this is the subtlety the report
     missed — see the compatibility note above).
5. **Tests** — `accounts_lt_hash matches agave snapshot` checks every account's digest prefix and the
   aggregate live-set hash against Agave's own values; `hashAccountAt matches the one-shot account
   hash` covers the on-disk layout, chunked streaming and corruption; the table iterator tests cover
   superseded entries and the zero pubkey. All pass.
6. **`v1/src/gossip/data.zig`** — `BitVec.deinit` frees only when `bits` is non-null, plus a
   regression test covering both the direct and the `CompressedSlots` eviction path (verified to fail
   without the fix).
7. **`v2/lib/fio/writer.zig`** — `FileWriter` can be constrained to a ring with `setRing(start, end)`;
   `advance` wraps `offset` from `ring_end` back to `ring_start` on block boundaries.
8. **`v2/lib/fio/reader.zig`** — `initAt(file, start_offset)` and `skip(n)` let recovery start reading
   at a non-block-aligned tail and scan a wrapped committed range.
9. **`v2/components/accounts_db/rooted.zig`** — fixed-size rooted database:
   - The journal now lives in two 16 KiB slots at offsets `0` and `16 KiB`, each with an incrementing
     `seq` and CRC32. The highest valid `seq` wins on recovery, so tearing one slot falls back to the
     previous commit. The journal records `state`, `committed_offset` (ring head), `tail_offset`,
     `ring_end`, `metadata_offset`, `block_id` and `blockhash_max_age`.
   - Records never cross `ring_end`; when one would, a padding sector fills the remainder and the head
     wraps. The two committed ranges of a wrapped ring are recovered independently.
   - `compactIfNeeded` runs between transactions (before `beginTransaction` publishes the new head):
     it scans `[tail, committed_offset)` oldest-first, drops sectors whose table entry points
     elsewhere, copies live account sectors and the live `block_metadata` sector to the head, repoints
     the table, and advances the tail. It triggers below a low-water mark and reclaims up to a
     high-water target, never past the last committed head.
   - Compaction is deliberately **not** run mid-transaction: the reclaimed range is only safe to reuse
     after the compacted state has been published in the next journal write. A crash during
     compaction leaves the previous committed range untouched.
   - `Rooted.init` takes an explicit `capacity`, validates the minimum size and the `u40` offset limit,
     and starts a fresh db when the journal's capacity does not match.
   - `ringUsage()` exposes `capacity` / `used` / `free` (plus `percentFull()`). After each commit, a log gauge
     emits one entry per 75% / 90% threshold crossing (including downward crossings after compaction),
     so operators can alert before a wrap without logging on every commit.
10. **`v2/components/accounts_db/api.zig`, `v2/services/accounts_db.zig`, `v2/main.zig`,
    `config/example.zon`** — `AccountsDb.disk` (a `MemorySize`) is plumbed to the rooted capacity.
11. **Tests** — `rooted ring distance and journal validation` covers ring arithmetic and journal
    checksum/capacity/offset rejection. `rooted ring wraps, compacts, recovers, and survives a torn
    journal` uses an 8 MiB ring with 128 accounts over 48 transactions to force a wrap, then verifies
    the live set in memory, recovers it from an intact file copy, and finally corrupts the newest
    journal slot and checks that recovery falls back to the previous commit.

Validation: `zig build unit-test` (Zig 0.15.2, Ubuntu 24.04) reports **115/117 steps succeeded,
1012/1014 tests passed, 1 skipped, 1 failed**; the failure is `lint-tests`' *dirty preflight rejects
tracked and untracked changes unless force is set*, which runs `git` inside a `.zig-cache/tmp` directory
and fails with `fatal: not in a git directory` under WSL. It is environmental and unrelated to these
changes. The v1 gossip filter test also passes.

## TODO

### P0 — remaining #1727 work

Verification is implemented and covered by tests. The remaining items are refinements:

- [ ] Avoid the second read pass: hash account data while it is written
      (`Rooted.put` / `writeAccountData`) and account for superseded versions, as Agave does
      (`mixIn(new)` + `mixOut(previous)`). Today's scan re-reads the whole journal, roughly doubling
      snapshot-load IO.
- [ ] Parallelize the scan across the existing IO writer workers if the write-path change above is
      not taken, matching the concurrency requirement stated in the issue.
- [ ] Apply the same check to incremental snapshots once the delta path exists.
- [ ] Add an end-to-end negative test: flip one bit in a fixture account (not just the manifest) and
      assert `loadSnapshot` returns `AccountsLtHashMismatch`. Today the corruption path is covered at
      the `hashAccountAt` level, not through a full load.
- [ ] Decide policy for manifests without the field (`null`): warn, or require it for snapshots from
      a feature-activated epoch (`accounts_lt_hash` feature, see `features.zon:1357`). Current
      behaviour is to log and skip verification.

### P1 — #1712 ring buffer + compaction

- [x] Give the rooted journal a fixed maximum size and treat it as a ring buffer
      (`rooted.zig:22`, `api.zig:34` documents the intended read order).
- [x] Compact ahead of wrap: drop stale sectors, relocate live ones, keep the journal header
      (`writing_slot`/`committed_offset`) consistent on crash recovery.
- [x] Add a test that forces wrap-around and asserts old entries are reclaimed and the DB still
      serves the live set.
- [x] Expose high-water-mark / used-bytes telemetry so operators can alert before a wrap.
      `Rooted.ringUsage()` exposes capacity/used/free, and commits log one entry per 75% / 90%
      threshold crossing. A first-class metric (rather than a log gauge) can be added when the
      accounts-db service gets a metrics region.
- [x] Run `loadSnapshot` end-to-end against a real Agave snapshot and recover it from disk.
      `rooted loads a real agave snapshot and recovers it` uses the repo fixture and exercises the
      full path, including lt-hash verification and journal recovery.
- [ ] Run a long-running validator against a production capacity target (e.g. 64 GiB). The tests use
      an 8 MiB ring; they validate the mechanics, not production sizing or IO behaviour at 64 GiB.

### P2 — #1729 / snapshot format drift

- [ ] Comment on or close #1729 as resolved-in-practice by #1734, linking the passing test.
- [ ] Regenerate `data/test-data/test-snapshot-*` with Agave ≥ the CLI version we run (4.3.2), add
      the generator invocation to `tools/snapshot-generator`, and add a `commits.env`-style pin so
      drift is caught in CI.

### P3 — v1 hardening (maintenance only)

- [ ] Consider implementing the `// TODO: check BitVec.capacity()` guard in
      `v1/src/gossip/data.zig:882` for Agave parity (zero-capacity entries rejected at sanitize
      time). This changes what gossip messages are accepted, so it needs a differential check
      against Agave before landing; the crash itself is already fixed.

## Method notes / limits

- Static claims were verified by reading the cited code at `b5026c60` and, where possible, by running
  tests. The `accounts_lt_hash` algorithm, the snapshot verification path's unit-level pieces and the
  v1 crash were exercised; the full v2 unit suite passes.
- The complete `loadSnapshot` path was exercised against the Agave v4.2.0-beta.1 fixture, including
  lt-hash verification and recovery. #1712 was **not** runtime-validated at production capacity or
  under a long-running node, which this environment does not have.
- The report's references (#1722, #1721, #1717 "have no fixes") were not re-checked in this pass.
