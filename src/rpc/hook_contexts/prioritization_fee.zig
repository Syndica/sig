//! RPC hook context for getRecentPrioritizationFees method.
//! Defines the PrioritizationFeeCache used by getRecentPrioritizationFees.
const std = @import("std");
const sig = @import("../../sig.zig");
const methods = @import("../methods.zig");

const Allocator = std.mem.Allocator;
const GetRecentPrioritizationFees = methods.GetRecentPrioritizationFees;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Slot = sig.core.Slot;

pub const PrioritizationFeeHookContext = struct {
    cache: *PrioritizationFeeCache,

    pub fn getRecentPrioritizationFees(
        self: PrioritizationFeeHookContext,
        arena: Allocator,
        params: GetRecentPrioritizationFees,
    ) !GetRecentPrioritizationFees.Response {
        const account_keys = params.account_keys orelse &.{};

        if (account_keys.len > sig.runtime.account_loader.MAX_TX_ACCOUNT_LOCKS) {
            return error.InvalidParams;
        }

        return try self.cache.getRecentFees(arena, account_keys);
    }
};

pub const PrioritizationFeeCache = struct {
    data: RwMux(Inner),

    /// The maximum number of finalized blocks to keep in the cache.
    /// Matches Agave's MAX_NUM_RECENT_BLOCKS.
    pub const NUM_RECENT_BLOCKS: usize = 150;

    /// Per-slot prioritization fee tracking data.
    pub const SlotFeeEntry = struct {
        slot: Slot,
        /// Minimum compute_unit_price (micro-lamports/CU) across all non-vote
        /// transactions in this slot. Starts at maxInt(u64); reported as 0 if no
        /// non-vote transactions landed.
        min_compute_unit_price: u64,
        /// Per-writable-account minimum compute_unit_price. After finalization,
        /// only accounts with fees strictly greater than the block minimum are retained.
        writable_account_fees: std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        /// Whether this slot has been finalized (block complete).
        is_finalized: bool,

        fn deinit(self: *SlotFeeEntry, allocator: Allocator) void {
            self.writable_account_fees.deinit(allocator);
        }
    };

    const Inner = struct {
        /// Finalized slot entries stored as a ring buffer.
        entries: [NUM_RECENT_BLOCKS]?SlotFeeEntry = .{null} ** NUM_RECENT_BLOCKS,
        /// Index of the oldest entry (next to be evicted when full).
        head: usize = 0,
        /// Number of valid finalized entries.
        len: usize = 0,
        /// In-progress (unfinalized) slot data, keyed by slot.
        unfinalized: std.AutoArrayHashMapUnmanaged(Slot, SlotFeeEntry) = .{},
    };

    pub const EMPTY: PrioritizationFeeCache = .{
        .data = RwMux(Inner).init(.{}),
    };

    pub fn deinit(self: *PrioritizationFeeCache, allocator: Allocator) void {
        const inner, var wlock = self.data.writeWithLock();
        defer wlock.unlock();

        // Free only the valid entries in the ring buffer
        for (0..inner.len) |i| {
            const idx = (inner.head + i) % NUM_RECENT_BLOCKS;
            if (inner.entries[idx]) |*entry| {
                entry.deinit(allocator);
                inner.entries[idx] = null;
            }
        }
        for (inner.unfinalized.values()) |*entry| entry.deinit(allocator);
        inner.unfinalized.deinit(allocator);
    }

    /// Called from the Committer for each non-vote transaction.
    /// Updates the per-slot tracking data for the given slot.
    pub fn update(
        self: *PrioritizationFeeCache,
        allocator: Allocator,
        slot: Slot,
        compute_unit_price: u64,
        writable_accounts: []const Pubkey,
    ) !void {
        var wlock = self.data.write();
        defer wlock.unlock();
        const inner = wlock.mut();

        const gop = try inner.unfinalized.getOrPut(allocator, slot);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .slot = slot,
                .min_compute_unit_price = std.math.maxInt(u64),
                .writable_account_fees = .{},
                .is_finalized = false,
            };
        }
        const entry = gop.value_ptr;

        // Update block-level minimum
        entry.min_compute_unit_price = @min(entry.min_compute_unit_price, compute_unit_price);

        // Update per-account minimums
        for (writable_accounts) |pubkey| {
            const acc_gop = try entry.writable_account_fees.getOrPut(allocator, pubkey);
            acc_gop.value_ptr.* = if (acc_gop.found_existing)
                @min(acc_gop.value_ptr.*, compute_unit_price)
            else
                compute_unit_price;
        }
    }

    /// Called when a slot is finalized (frozen/confirmed).
    /// Prunes irrelevant per-account data and moves the slot from the
    /// unfinalized map to the finalized ring buffer.
    pub fn finalizeSlot(
        self: *PrioritizationFeeCache,
        allocator: Allocator,
        slot: Slot,
    ) void {
        var wlock = self.data.write();
        defer wlock.unlock();
        const inner = wlock.mut();

        // Prune stale unfinalized entries (slots older than the finalization window).
        // These are likely skipped/abandoned slots that will never be finalized.
        const prune_threshold = slot -| NUM_RECENT_BLOCKS;
        var j: usize = 0;
        while (j < inner.unfinalized.count()) {
            const entry_slot = inner.unfinalized.keys()[j];
            if (entry_slot < prune_threshold) {
                var entry = inner.unfinalized.values()[j];
                entry.deinit(allocator);
                inner.unfinalized.swapRemoveAt(j);
            } else {
                j += 1;
            }
        }

        const fetched = inner.unfinalized.fetchSwapRemove(slot) orelse return;
        var fee_entry = fetched.value;
        fee_entry.is_finalized = true;

        // Prune accounts whose fees <= block minimum (like Agave).
        // These are redundant because the block minimum already covers them.
        const block_min = fee_entry.min_compute_unit_price;
        var i: usize = 0;
        while (i < fee_entry.writable_account_fees.count()) {
            const value = fee_entry.writable_account_fees.values()[i];
            if (value <= block_min) {
                fee_entry.writable_account_fees.swapRemoveAt(i);
            } else {
                i += 1;
            }
        }

        // Add to finalized entries, evicting oldest if full
        if (inner.len == NUM_RECENT_BLOCKS) {
            // Evict oldest entry at head, insert new entry there
            if (inner.entries[inner.head]) |*old| old.deinit(allocator);
            inner.entries[inner.head] = fee_entry;
            inner.head = (inner.head + 1) % NUM_RECENT_BLOCKS;
        } else {
            const insert_idx = (inner.head + inner.len) % NUM_RECENT_BLOCKS;
            inner.entries[insert_idx] = fee_entry;
            inner.len += 1;
        }
    }

    /// Query the cache for recent prioritization fees.
    /// If account_keys is empty, returns the block-level minimum for each slot.
    /// If account_keys is provided, returns max(block_min, max(per_account_fees...))
    /// for each slot.
    pub fn getRecentFees(
        self: *PrioritizationFeeCache,
        allocator: Allocator,
        account_keys: []const Pubkey,
    ) ![]const GetRecentPrioritizationFees.FeeResult {
        var rlock = self.data.read();
        defer rlock.unlock();
        const inner = rlock.get();

        var results: std.ArrayList(GetRecentPrioritizationFees.FeeResult) = try .initCapacity(
            allocator,
            inner.len,
        );

        // Iterate ring buffer from oldest (head) to newest
        for (0..inner.len) |i| {
            const idx = (inner.head + i) % NUM_RECENT_BLOCKS;
            const entry = inner.entries[idx] orelse continue;
            if (!entry.is_finalized) continue;

            const block_min: u64 = if (entry.min_compute_unit_price == std.math.maxInt(u64))
                0
            else
                entry.min_compute_unit_price;

            var fee: u64 = block_min;
            for (account_keys) |key| {
                if (entry.writable_account_fees.get(key)) |account_fee| {
                    fee = @max(fee, account_fee);
                }
            }

            results.appendAssumeCapacity(.{
                .slot = entry.slot,
                .prioritizationFee = fee,
            });
        }

        return results.items;
    }

    /// Returns the number of finalized blocks currently in the cache.
    pub fn availableBlockCount(self: *PrioritizationFeeCache) usize {
        var rlock = self.data.read();
        defer rlock.unlock();
        return rlock.get().len;
    }
};

test "empty cache returns empty results" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    const results = try cache.getRecentFees(std.testing.allocator, &.{});
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "single slot with multiple transactions tracks minimums" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    const acct_a = Pubkey.ZEROES;
    const acct_b = Pubkey{ .data = .{1} ** 32 };

    // Tx 1: price 1000, writable accounts: [A, B]
    try cache.update(std.testing.allocator, 100, 1000, &.{ acct_a, acct_b });
    // Tx 2: price 500, writable accounts: [A]
    try cache.update(std.testing.allocator, 100, 500, &.{acct_a});
    // Tx 3: price 2000, writable accounts: [B]
    try cache.update(std.testing.allocator, 100, 2000, &.{acct_b});

    cache.finalizeSlot(std.testing.allocator, 100);

    // Block minimum should be 500 (min of 1000, 500, 2000)
    {
        const results = try cache.getRecentFees(std.testing.allocator, &.{});
        defer std.testing.allocator.free(results);
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqual(@as(u64, 100), results[0].slot);
        try std.testing.expectEqual(@as(u64, 500), results[0].prioritizationFee);
    }

    // Query for account A: min(A) = min(1000, 500) = 500 == block_min, so pruned.
    // Result should be block_min = 500.
    {
        const results = try cache.getRecentFees(std.testing.allocator, &.{acct_a});
        defer std.testing.allocator.free(results);
        try std.testing.expectEqual(@as(u64, 500), results[0].prioritizationFee);
    }

    // Query for account B: min(B) = min(1000, 2000) = 1000 > block_min (500).
    // Result should be max(500, 1000) = 1000.
    {
        const results = try cache.getRecentFees(std.testing.allocator, &.{acct_b});
        defer std.testing.allocator.free(results);
        try std.testing.expectEqual(@as(u64, 1000), results[0].prioritizationFee);
    }
}

test "finalization prunes accounts at or below block minimum" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    const acct_a = Pubkey.ZEROES;

    // Single tx: price 100, writable: [A]
    try cache.update(std.testing.allocator, 50, 100, &.{acct_a});

    cache.finalizeSlot(std.testing.allocator, 50);

    // Account A's fee (100) == block minimum (100), so it should be pruned.
    // Querying for A should return block_min = 100.
    const results = try cache.getRecentFees(std.testing.allocator, &.{acct_a});
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(u64, 100), results[0].prioritizationFee);
}

test "ring buffer eviction at capacity" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    // Fill cache with NUM_RECENT_BLOCKS + 1 slots
    for (0..PrioritizationFeeCache.NUM_RECENT_BLOCKS + 1) |i| {
        const slot: u64 = @intCast(i);
        try cache.update(std.testing.allocator, slot, @intCast(i * 10), &.{});
        cache.finalizeSlot(std.testing.allocator, slot);
    }

    try std.testing.expectEqual(
        @as(usize, PrioritizationFeeCache.NUM_RECENT_BLOCKS),
        cache.availableBlockCount(),
    );

    // Oldest slot (0) should have been evicted
    const results = try cache.getRecentFees(std.testing.allocator, &.{});
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, PrioritizationFeeCache.NUM_RECENT_BLOCKS), results.len);
    // First entry should be slot 1 (slot 0 was evicted)
    try std.testing.expectEqual(@as(u64, 1), results[0].slot);
    // Last entry should be slot NUM_RECENT_BLOCKS
    try std.testing.expectEqual(
        @as(u64, PrioritizationFeeCache.NUM_RECENT_BLOCKS),
        results[results.len - 1].slot,
    );
}

test "slot with no updates reports fee 0" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    // Create an entry with no transactions (e.g. empty block)
    try cache.update(std.testing.allocator, 200, std.math.maxInt(u64), &.{});

    // Actually, let's test the case where a slot gets finalized but had
    // compute_unit_price of 0 (non-prioritized transactions)
    try cache.update(std.testing.allocator, 201, 0, &.{Pubkey.ZEROES});
    cache.finalizeSlot(std.testing.allocator, 201);

    const results = try cache.getRecentFees(std.testing.allocator, &.{});
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(u64, 0), results[0].prioritizationFee);
}

test "unfinalized slots are not returned" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    try cache.update(std.testing.allocator, 300, 1000, &.{Pubkey.ZEROES});
    // Don't finalize

    const results = try cache.getRecentFees(std.testing.allocator, &.{});
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "finalizing nonexistent slot is a no-op" {
    var cache = PrioritizationFeeCache.EMPTY;
    defer cache.deinit(std.testing.allocator);

    // Should not crash
    cache.finalizeSlot(std.testing.allocator, 999);

    try std.testing.expectEqual(@as(usize, 0), cache.availableBlockCount());
}
