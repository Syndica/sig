const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const StakeAndVoteAccountsMap = sig.core.vote_accounts.StakeAndVoteAccountsMap;

const SortedMap = sig.utils.collections.SortedMap;

/// Analogous to [MaxAllowableDrift](https://github.com/anza-xyz/agave/blob/e0bd9224fe60d8caa35bcca8daf6c8103ce424ec/runtime/src/stake_weighted_timestamp.rs#L21)
pub const MaxAllowableDrift = struct {
    fast: u32,
    slow: u32,

    pub const MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST: u32 = 25;
    pub const MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2: u32 = 150;

    pub const DEFAULT: MaxAllowableDrift = .{
        .fast = MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST,
        .slow = MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2,
    };
};

pub const EpochStartTimestamp = struct {
    slot: Slot,
    timestamp: i64,
};

pub fn calculateStakeWeightedTimestamp(
    allocator: Allocator,
    recent_timestamps: []const struct { Pubkey, Slot, i64 },
    vote_accounts: *const StakeAndVoteAccountsMap,
    slot: Slot,
    ns_per_slot: u64,
    epoch_start_timstamp: ?EpochStartTimestamp,
    max_allowable_drift: MaxAllowableDrift,
    fix_estimate_into_u64: bool,
) Allocator.Error!?i64 {
    var stakes_per_timestamp: SortedMap(
        i64,
        u128,
        .{},
    ) = .empty;
    defer stakes_per_timestamp.deinit(allocator);
    var total_stake: u128 = 0;

    for (recent_timestamps) |timestamp_entry| {
        const vote_pubkey, const timestamp_slot, const timestamp = timestamp_entry;

        const offset_s = (ns_per_slot *| (slot -| timestamp_slot)) / 1_000_000_000;
        const estimate_s = timestamp +| @as(i64, @intCast(offset_s));
        const stake = if (vote_accounts.getPtr(vote_pubkey)) |vote_account_entry|
            vote_account_entry.stake
        else
            0;

        if (estimate_s == std.math.maxInt(i64)) unreachable;

        const entry = try stakes_per_timestamp.getOrPut(allocator, estimate_s);
        if (entry.found_existing)
            entry.value_ptr.* +|= stake
        else
            entry.value_ptr.* = stake;
        total_stake +|= stake;
    }

    if (total_stake == 0) return null;

    var stake_accumulator: u128 = 0;
    var estimate_s: i64 = 0;

    var iter = stakes_per_timestamp.iterator();
    while (iter.next()) |entry| {
        const stake = entry.value_ptr.*;
        stake_accumulator +|= stake;
        if (stake_accumulator > total_stake / 2) {
            estimate_s = entry.key_ptr.*;
            break;
        }
    }

    if (epoch_start_timstamp) |epoch_timestamp| {
        const poh_estimate_offset_ns = (ns_per_slot *| (slot -| epoch_timestamp.slot));
        const poh_estimate_offset_s = poh_estimate_offset_ns / 1_000_000_000;
        const estimate_offset_s = if (fix_estimate_into_u64)
            @as(u64, @intCast(estimate_s)) -| @as(u64, @intCast(epoch_timestamp.timestamp))
        else
            // Executed if WARP_TIMESTAMP_AGAIN feature is not active.
            @as(u64, @bitCast(estimate_s -| epoch_timestamp.timestamp));

        const max_allowable_drift_fast_s = poh_estimate_offset_s *| max_allowable_drift.fast / 100;
        const max_allowable_drift_slow_s = poh_estimate_offset_s *| max_allowable_drift.slow / 100;

        if (estimate_offset_s > poh_estimate_offset_s and
            (estimate_offset_s -| poh_estimate_offset_s) > max_allowable_drift_slow_s)
        {
            estimate_s = epoch_timestamp.timestamp +|
                @as(i64, @intCast(poh_estimate_offset_s)) +|
                @as(i64, @intCast(max_allowable_drift_slow_s));
        } else if (estimate_offset_s < poh_estimate_offset_s and
            (poh_estimate_offset_s -| estimate_offset_s) > max_allowable_drift_fast_s)
        {
            estimate_s = epoch_timestamp.timestamp +|
                @as(i64, @intCast(poh_estimate_offset_s)) -|
                @as(i64, @intCast(max_allowable_drift_fast_s));
        }
    }

    return estimate_s;
}

test "uses median: low-staked outliers" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const recent_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 5;
    const ns_per_slot: u64 = 400_000_000;
    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);
    const pubkey_3 = Pubkey.initRandom(random);
    const pubkey_4 = Pubkey.initRandom(random);
    const max_allowable_drift = MaxAllowableDrift{ .fast = 25, .slow = 25 };

    var vote_accounts = StakeAndVoteAccountsMap{};
    defer denintMapAndValues(allocator, vote_accounts);

    try vote_accounts.put(allocator, pubkey_0, .{
        .stake = 1 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_1, .{
        .stake = 1 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_2, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_3, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_4, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, 0 },
            .{ pubkey_1, slot, 0 },
            .{ pubkey_2, slot, recent_timestamp },
            .{ pubkey_3, slot, recent_timestamp },
            .{ pubkey_4, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp, actual);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, 0 },
            .{ pubkey_1, slot, recent_timestamp },
            .{ pubkey_2, slot, recent_timestamp },
            .{ pubkey_3, slot, recent_timestamp },
            .{ pubkey_4, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp, actual);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, recent_timestamp },
            .{ pubkey_1, slot, std.math.maxInt(i64) - 1 },
            .{ pubkey_2, slot, recent_timestamp },
            .{ pubkey_3, slot, recent_timestamp },
            .{ pubkey_4, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp, actual);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, 0 },
            .{ pubkey_1, slot, std.math.maxInt(i64) - 1 },
            .{ pubkey_2, slot, recent_timestamp },
            .{ pubkey_3, slot, recent_timestamp },
            .{ pubkey_4, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp, actual);
    }
}

test "uses median: high-staked outliers" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const recent_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 5;
    const ns_per_slot: u64 = 400_000_000;
    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);
    const max_allowable_drift = MaxAllowableDrift{ .fast = 25, .slow = 25 };

    {
        var vote_accounts = StakeAndVoteAccountsMap{};
        defer denintMapAndValues(allocator, vote_accounts);

        try vote_accounts.put(allocator, pubkey_0, .{
            .stake = 1_000_000 * LAMPORTS_PER_SOL,
            .account = try VoteAccount.initRandom(allocator, random, null),
        });
        try vote_accounts.put(allocator, pubkey_1, .{
            .stake = 1_000_000 * LAMPORTS_PER_SOL,
            .account = try VoteAccount.initRandom(allocator, random, null),
        });
        try vote_accounts.put(allocator, pubkey_2, .{
            .stake = 1_000_000 * LAMPORTS_PER_SOL,
            .account = try VoteAccount.initRandom(allocator, random, null),
        });

        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, 0 },
            .{ pubkey_1, slot, std.math.maxInt(i64) - 1 },
            .{ pubkey_2, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp, actual);
    }

    {
        var vote_accounts = StakeAndVoteAccountsMap{};
        defer denintMapAndValues(allocator, vote_accounts);

        try vote_accounts.put(allocator, pubkey_0, .{
            .stake = 1_000_001 * LAMPORTS_PER_SOL,
            .account = try VoteAccount.initRandom(allocator, random, null),
        });
        try vote_accounts.put(allocator, pubkey_1, .{
            .stake = 1_000_000 * LAMPORTS_PER_SOL,
            .account = try VoteAccount.initRandom(allocator, random, null),
        });

        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, 0 },
            .{ pubkey_1, slot, recent_timestamp },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            null,
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(recent_timestamp - actual.?, 1_578_909_061);
    }
}

test "poh" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_start_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 20;
    const ns_per_slot: u64 = 400_000_000;
    const poh_offset: u64 = slot * ns_per_slot / 1_000_000_000;
    const max_allowable_drift_pct: u32 = 25;
    const max_allowable_drift = MaxAllowableDrift{
        .fast = max_allowable_drift_pct,
        .slow = max_allowable_drift_pct,
    };
    const acceptable_delta: i64 = (max_allowable_drift_pct * poh_offset / 100);
    const poh_estimate: i64 = epoch_start_timestamp + poh_offset;
    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);

    var vote_accounts = StakeAndVoteAccountsMap{};
    defer denintMapAndValues(allocator, vote_accounts);

    try vote_accounts.put(allocator, pubkey_0, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_1, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_2, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta + 1 },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta + 1 },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta + 1 },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta, actual.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate - acceptable_delta - 1 },
            .{ pubkey_1, slot, poh_estimate - acceptable_delta - 1 },
            .{ pubkey_2, slot, poh_estimate - acceptable_delta - 1 },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate - acceptable_delta, actual.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta, actual.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate - acceptable_delta },
            .{ pubkey_1, slot, poh_estimate - acceptable_delta },
            .{ pubkey_2, slot, poh_estimate - acceptable_delta },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate - acceptable_delta, actual.?);
    }
}

test "levels" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_start_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 20;
    const ns_per_slot: u64 = 400_000_000;
    const poh_offset: u64 = slot * ns_per_slot / 1_000_000_000;
    const poh_estimate: i64 = epoch_start_timestamp + poh_offset;

    const max_allowable_drift_pct_25: u32 = 25;
    const max_allowable_drift_25 = MaxAllowableDrift{
        .fast = max_allowable_drift_pct_25,
        .slow = max_allowable_drift_pct_25,
    };
    const acceptable_delta_25: i64 = (max_allowable_drift_pct_25 * poh_offset / 100);

    const max_allowable_drift_pct_50: u32 = 50;
    const max_allowable_drift_50 = MaxAllowableDrift{
        .fast = max_allowable_drift_pct_50,
        .slow = max_allowable_drift_pct_50,
    };
    const acceptable_delta_50: i64 = (max_allowable_drift_pct_50 * poh_offset / 100);

    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);

    var vote_accounts = StakeAndVoteAccountsMap{};
    defer denintMapAndValues(allocator, vote_accounts);

    try vote_accounts.put(allocator, pubkey_0, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_1, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_2, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta_25 + 1 },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta_25 + 1 },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta_25 + 1 },
        };

        const actual_25 = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift_25,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_25, actual_25.?);

        const actual_50 = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift_50,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_25 + 1, actual_50.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta_50 + 1 },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta_50 + 1 },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta_50 + 1 },
        };

        const actual_25 = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift_25,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_25, actual_25.?);

        const actual_50 = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift_50,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_50, actual_50.?);
    }
}

test "fast slow" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_start_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 20;
    const ns_per_slot: u64 = 400_000_000;
    const poh_offset: u64 = slot * ns_per_slot / 1_000_000_000;
    const poh_estimate: i64 = epoch_start_timestamp + poh_offset;

    const max_allowable_drift_pct_25: u32 = 25;
    const max_allowable_drift_pct_50: u32 = 50;
    const max_allowable_drift = MaxAllowableDrift{
        .fast = max_allowable_drift_pct_25,
        .slow = max_allowable_drift_pct_50,
    };
    const acceptable_delta_fast: i64 = (max_allowable_drift_pct_25 * poh_offset / 100);
    const acceptable_delta_slow: i64 = (max_allowable_drift_pct_50 * poh_offset / 100);

    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);

    var vote_accounts = StakeAndVoteAccountsMap{};
    defer denintMapAndValues(allocator, vote_accounts);

    try vote_accounts.put(allocator, pubkey_0, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_1, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_2, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate - acceptable_delta_fast - 1 },
            .{ pubkey_1, slot, poh_estimate - acceptable_delta_fast - 1 },
            .{ pubkey_2, slot, poh_estimate - acceptable_delta_fast - 1 },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate - acceptable_delta_fast, actual.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta_fast + 1 },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta_fast + 1 },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta_fast + 1 },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_fast + 1, actual.?);
    }

    {
        const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
            .{ pubkey_0, slot, poh_estimate + acceptable_delta_slow + 1 },
            .{ pubkey_1, slot, poh_estimate + acceptable_delta_slow + 1 },
            .{ pubkey_2, slot, poh_estimate + acceptable_delta_slow + 1 },
        };

        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta_slow, actual.?);
    }
}

test "early" {
    const VoteAccount = sig.core.vote_accounts.VoteAccount;
    const denintMapAndValues = sig.utils.collections.deinitMapAndValues;
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_start_timestamp: i64 = 1_578_909_061;
    const slot: Slot = 20;
    const ns_per_slot: u64 = 400_000_000;
    const poh_offset: u64 = slot * ns_per_slot / 1_000_000_000;
    const poh_estimate: i64 = epoch_start_timestamp + poh_offset;

    const max_allowable_drift_pct: u32 = 50;
    const max_allowable_drift = MaxAllowableDrift{
        .fast = max_allowable_drift_pct,
        .slow = max_allowable_drift_pct,
    };
    const acceptable_delta: i64 = (max_allowable_drift_pct * poh_offset / 100);

    const pubkey_0 = Pubkey.initRandom(random);
    const pubkey_1 = Pubkey.initRandom(random);
    const pubkey_2 = Pubkey.initRandom(random);

    var vote_accounts = StakeAndVoteAccountsMap{};
    defer denintMapAndValues(allocator, vote_accounts);

    try vote_accounts.put(allocator, pubkey_0, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_1, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });
    try vote_accounts.put(allocator, pubkey_2, .{
        .stake = 1_000_000 * LAMPORTS_PER_SOL,
        .account = try VoteAccount.initRandom(allocator, random, null),
    });

    const recent_timestamps = [_]struct { Pubkey, Slot, i64 }{
        .{ pubkey_0, slot, poh_estimate - acceptable_delta - 20 },
        .{ pubkey_1, slot, poh_estimate - acceptable_delta - 20 },
        .{ pubkey_2, slot, poh_estimate - acceptable_delta - 20 },
    };

    {
        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            false,
        );

        try std.testing.expectEqual(poh_estimate + acceptable_delta, actual.?);
    }

    {
        const actual = try calculateStakeWeightedTimestamp(
            allocator,
            &recent_timestamps,
            &vote_accounts,
            slot,
            ns_per_slot,
            .{ .slot = 0, .timestamp = epoch_start_timestamp },
            max_allowable_drift,
            true,
        );

        try std.testing.expectEqual(poh_estimate - acceptable_delta, actual.?);
    }
}
