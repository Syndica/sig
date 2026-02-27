//! Types for parsing a stake account for RPC responses using the `jsonParsed` encoding.
//! [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs
const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;

const Allocator = std.mem.Allocator;
const ParseError = account_codec.ParseError;
const Pubkey = sig.core.Pubkey;
const RyuF64 = account_codec.RyuF64;
const StakeStateV2 = sig.runtime.program.stake.state.StakeStateV2;
const Stringified = account_codec.Stringified;

/// Parses a stake account's data into a `StakeAccountType` for JSON encoding in RPC responses.
pub fn parseStake(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
) ParseError!StakeAccountType {
    const stake_state = sig.bincode.read(
        allocator,
        StakeStateV2,
        reader,
        .{},
    ) catch return ParseError.InvalidAccountData;

    return switch (stake_state) {
        .uninitialized => .uninitialized,
        .initialized => |meta| .{
            .initialized = UiStakeAccount{
                .meta = UiMeta.fromStakeStateMeta(meta),
                .stake = null,
            },
        },
        .stake => |s| .{
            .delegated = UiStakeAccount{
                .meta = UiMeta.fromStakeStateMeta(s.meta),
                .stake = UiStake{
                    .delegation = UiDelegation{
                        .voter = s.stake.delegation.voter_pubkey,
                        .stake = .init(s.stake.delegation.stake),
                        .activationEpoch = .init(s.stake.delegation.activation_epoch),
                        .deactivationEpoch = .init(s.stake.delegation.deactivation_epoch),
                        .warmupCooldownRate = RyuF64.init(
                            s.stake.delegation.deprecated_warmup_cooldown_rate,
                        ),
                    },
                    .creditsObserved = s.stake.credits_observed,
                },
            },
        },
        .rewards_pool => .rewards_pool,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L30
pub const StakeAccountType = union(enum) {
    uninitialized,
    initialized: UiStakeAccount,
    delegated: UiStakeAccount,
    rewards_pool,

    pub fn jsonStringify(self: StakeAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            inline else => |v, tag| {
                try jw.write(comptime typeNameFromTag(tag));
                if (@TypeOf(v) != void) {
                    try jw.objectField("info");
                    try jw.write(v);
                }
            },
        }
        try jw.endObject();
    }

    fn typeNameFromTag(tag: std.meta.Tag(StakeAccountType)) []const u8 {
        return switch (tag) {
            .uninitialized => "uninitialized",
            .initialized => "initialized",
            .delegated => "delegated",
            .rewards_pool => "rewardsPool",
        };
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L41
pub const UiStakeAccount = struct {
    meta: UiMeta,
    stake: ?UiStake,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L48
pub const UiMeta = struct {
    rentExemptReserve: Stringified(u64),
    authorized: UiAuthorized,
    lockup: UiLockup,

    fn fromStakeStateMeta(meta: StakeStateV2.Meta) UiMeta {
        return .{
            .rentExemptReserve = .init(meta.rent_exempt_reserve),
            .authorized = .{
                .staker = meta.authorized.staker,
                .withdrawer = meta.authorized.withdrawer,
            },
            .lockup = .{
                .unixTimestamp = meta.lockup.unix_timestamp,
                .epoch = meta.lockup.epoch,
                .custodian = meta.lockup.custodian,
            },
        };
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L72
pub const UiAuthorized = struct {
    staker: Pubkey,
    withdrawer: Pubkey,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L85
pub const UiLockup = struct {
    unixTimestamp: i64,
    epoch: u64,
    custodian: Pubkey,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L100
pub const UiStake = struct {
    delegation: UiDelegation,
    creditsObserved: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L113
pub const UiDelegation = struct {
    voter: Pubkey,
    stake: Stringified(u64),
    activationEpoch: Stringified(u64),
    deactivationEpoch: Stringified(u64),
    warmupCooldownRate: RyuF64,
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L142-L209
test "rpc.account_codec.parse_stake: parse stake accounts" {
    const allocator = std.testing.allocator;

    // Uninitialized state
    {
        const stake_state = StakeStateV2{ .uninitialized = {} };
        const serialized = try sig.bincode.writeAlloc(allocator, stake_state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseStake(allocator, stream.reader());

        try std.testing.expect(result == .uninitialized);
    }

    // Initialized state
    {
        const pubkey = Pubkey{ .data = [_]u8{1} ** 32 };
        const custodian = Pubkey{ .data = [_]u8{2} ** 32 };

        const meta = StakeStateV2.Meta{
            .rent_exempt_reserve = 42,
            .authorized = .{
                .staker = pubkey,
                .withdrawer = pubkey,
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 1,
                .custodian = custodian,
            },
        };

        const stake_state = StakeStateV2{ .initialized = meta };
        const serialized = try sig.bincode.writeAlloc(allocator, stake_state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseStake(allocator, stream.reader());

        try std.testing.expect(result == .initialized);

        const ui_account = result.initialized;
        try std.testing.expectEqual(@as(u64, 42), ui_account.meta.rentExemptReserve.value);
        try std.testing.expectEqualStrings(
            pubkey.base58String().constSlice(),
            ui_account.meta.authorized.staker.base58String().constSlice(),
        );
        try std.testing.expectEqualStrings(
            pubkey.base58String().constSlice(),
            ui_account.meta.authorized.withdrawer.base58String().constSlice(),
        );
        try std.testing.expectEqual(@as(i64, 0), ui_account.meta.lockup.unixTimestamp);
        try std.testing.expectEqual(@as(u64, 1), ui_account.meta.lockup.epoch);
        try std.testing.expectEqualStrings(
            custodian.base58String().constSlice(),
            ui_account.meta.lockup.custodian.base58String().constSlice(),
        );
        try std.testing.expect(ui_account.stake == null);
    }

    // Delegated (Stake) state
    {
        const pubkey = Pubkey{ .data = [_]u8{1} ** 32 };
        const custodian = Pubkey{ .data = [_]u8{2} ** 32 };
        const voter_pubkey = Pubkey{ .data = [_]u8{3} ** 32 };

        const meta = StakeStateV2.Meta{
            .rent_exempt_reserve = 42,
            .authorized = .{
                .staker = pubkey,
                .withdrawer = pubkey,
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 1,
                .custodian = custodian,
            },
        };

        const stake_data = StakeStateV2.Stake{
            .delegation = .{
                .voter_pubkey = voter_pubkey,
                .stake = 20,
                .activation_epoch = 2,
                .deactivation_epoch = std.math.maxInt(u64),
                .deprecated_warmup_cooldown_rate = 0.25,
            },
            .credits_observed = 10,
        };

        const stake_state = StakeStateV2{
            .stake = .{
                .meta = meta,
                .stake = stake_data,
                .flags = StakeStateV2.StakeFlags.EMPTY,
            },
        };
        const serialized = try sig.bincode.writeAlloc(allocator, stake_state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseStake(allocator, stream.reader());

        try std.testing.expect(result == .delegated);

        const ui_account = result.delegated;

        // Verify meta
        try std.testing.expectEqual(@as(u64, 42), ui_account.meta.rentExemptReserve.value);
        try std.testing.expectEqualStrings(
            pubkey.base58String().constSlice(),
            ui_account.meta.authorized.staker.base58String().constSlice(),
        );

        // Verify stake
        try std.testing.expect(ui_account.stake != null);
        const ui_stake = ui_account.stake.?;
        try std.testing.expectEqualStrings(
            voter_pubkey.base58String().constSlice(),
            ui_stake.delegation.voter.base58String().constSlice(),
        );
        try std.testing.expectEqual(@as(u64, 20), ui_stake.delegation.stake.value);
        try std.testing.expectEqual(@as(u64, 2), ui_stake.delegation.activationEpoch.value);
        const deact = ui_stake.delegation.deactivationEpoch.value;
        try std.testing.expectEqual(std.math.maxInt(u64), deact);
        try std.testing.expectEqual(@as(f64, 0.25), ui_stake.delegation.warmupCooldownRate.value);
        try std.testing.expectEqual(@as(u64, 10), ui_stake.creditsObserved);
    }

    // RewardsPool state
    {
        const stake_state = StakeStateV2{ .rewards_pool = {} };
        const serialized = try sig.bincode.writeAlloc(allocator, stake_state, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseStake(allocator, stream.reader());

        try std.testing.expect(result == .rewards_pool);
    }

    // Bad data returns error
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L208
    {
        const bad_data = [_]u8{ 1, 2, 3, 4 };
        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseStake(allocator, stream.reader());

        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }
}
