//! Tick verification for a deshredded slot.
//!
//! A Solana slot is a tick window: entries must include exactly
//! `max_tick_height - tick_height` ticks, the final entry must be a tick once
//! the window is full, and inter-tick hash counts must equal
//! `hashes_per_tick` (when non-zero).
//!
//! Lives in `v2/lib/solana/` because the v2 `Entry` uses
//! `bincode.Vec(VersionedTransaction)` for the transactions field rather than
//! v1's `[]const Transaction`. Once both layouts converge, this module
//! should move under `shared/core/`.

const lib = @import("../lib.zig");
const Entry = lib.solana.transaction.Entry;

/// Errors a block may fail with during validation. Not every variant is
/// produced by `verifyTicks` — the rest are reserved for higher-layer
/// validation (entry-batch hashing, duplicate-slot detection, ...).
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/ledger/src/block_error.rs#L3-L39
pub const BlockError = error{
    Incomplete,
    InvalidEntryHash,
    InvalidLastTick,
    TooFewTicks,
    TooManyTicks,
    InvalidTickHashCount,
    TrailingEntry,
    DuplicateBlock,
};

pub const VerifyTicksParams = struct {
    hashes_per_tick: u64,
    slot: u64,
    max_tick_height: u64,
    tick_height: u64,
    /// True if the slot's last data shred carried the LAST_SHRED_IN_SLOT flag,
    /// i.e. all entries for the slot are present.
    slot_is_full: bool,
    /// Running hash count carried across batches. `verifyTicks` writes the
    /// trailing partial count back through this pointer so the next call on
    /// the same slot resumes correctly. Point at a caller-owned `u64`
    /// initialised to `0` at the start of the slot; for a single-batch call
    /// point at a local `u64 = 0`.
    tick_hash_count: *u64,
};

/// Count how many entries in `entries` are ticks (zero transactions).
pub fn tickCount(entries: []const Entry) u64 {
    var n: u64 = 0;
    for (entries) |e| {
        if (e.isTick()) n += 1;
    }
    return n;
}

/// Verify that the supplied entries fit cleanly into the slot's tick window.
///
/// Returns the first `BlockError` detected, or success.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/ledger/src/blockstore_processor.rs#L1057-L1104
pub fn verifyTicks(entries: []const Entry, params: VerifyTicksParams) BlockError!void {
    const tick_count_in_entries = tickCount(entries);
    const next_tick_height = params.tick_height +| tick_count_in_entries;

    if (next_tick_height > params.max_tick_height) {
        return error.TooManyTicks;
    }

    if (next_tick_height < params.max_tick_height and params.slot_is_full) {
        return error.TooFewTicks;
    }

    if (next_tick_height == params.max_tick_height) {
        if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
            return error.TrailingEntry;
        }
        if (!params.slot_is_full) return error.InvalidLastTick;
    }

    // Verify inter-tick hash counts. When `hashes_per_tick == 0`, hashing is
    // disabled and any count is acceptable.
    //
    // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/entry/src/entry.rs#L675-L698
    if (params.hashes_per_tick > 0) {
        for (entries) |entry| {
            params.tick_hash_count.* +|= entry.num_hashes;
            if (entry.isTick()) {
                if (params.tick_hash_count.* != params.hashes_per_tick) {
                    return error.InvalidTickHashCount;
                }
                params.tick_hash_count.* = 0;
            }
        }
        if (params.tick_hash_count.* >= params.hashes_per_tick) return error.InvalidTickHashCount;
    }
}
