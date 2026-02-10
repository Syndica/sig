/// Types for parsing a stake account for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const StakeStateV2 = sig.runtime.program.stake.state.StakeStateV2;
const ParseError = account_decoder.ParseError;

/// Parses a stake account's data into a `StakeAccountType` for JSON encoding in RPC responses.
pub fn parse_stake(
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
                .maybe_stake = null,
            },
        },
        .stake => |s| .{
            .delegated = UiStakeAccount{
                .meta = UiMeta.fromStakeStateMeta(s.meta),
                .maybe_stake = UiStake{
                    .delegation = UiDelegation{
                        .voter = s.stake.delegation.voter_pubkey.base58String(),
                        .stake = s.stake.delegation.stake,
                        .activation_epoch = s.stake.delegation.activation_epoch,
                        .deactivation_epoch = s.stake.delegation.deactivation_epoch,
                        .warmup_cooldown_rate = s.stake.delegation.deprecated_warmup_cooldown_rate,
                    },
                    .credits_observed = s.stake.credits_observed,
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
            .uninitialized => try jw.write("uninitialized"),
            .initialized => |account| {
                try jw.write("initialized");
                try jw.objectField("info");
                try account.jsonStringify(jw);
            },
            .delegated => |account| {
                try jw.write("delegated");
                try jw.objectField("info");
                try account.jsonStringify(jw);
            },
            .rewards_pool => try jw.write("rewardsPool"),
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L41
pub const UiStakeAccount = struct {
    meta: UiMeta,
    maybe_stake: ?UiStake,

    pub fn jsonStringify(self: UiStakeAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("meta");
        try self.meta.jsonStringify(jw);
        if (self.maybe_stake) |stake| {
            try jw.objectField("stake");
            try stake.jsonStringify(jw);
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L48
pub const UiMeta = struct {
    rent_exempt_reserve: u64,
    authorized: UiAuthorized,
    lockup: UiLockup,

    fn fromStakeStateMeta(meta: StakeStateV2.Meta) UiMeta {
        return .{
            .rent_exempt_reserve = meta.rent_exempt_reserve,
            .authorized = .{
                .staker = meta.authorized.staker.base58String(),
                .withdrawer = meta.authorized.withdrawer.base58String(),
            },
            .lockup = .{
                .unix_timestamp = meta.lockup.unix_timestamp,
                .epoch = meta.lockup.epoch,
                .custodian = meta.lockup.custodian.base58String(),
            },
        };
    }

    pub fn jsonStringify(self: UiMeta, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("rentExemptReserve");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.rent_exempt_reserve});
        try jw.objectField("authorized");
        try self.authorized.jsonStringify(jw);
        try jw.objectField("lockup");
        try self.lockup.jsonStringify(jw);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L72
pub const UiAuthorized = struct {
    staker: Pubkey.Base58String,
    withdrawer: Pubkey.Base58String,

    pub fn jsonStringify(self: UiAuthorized, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("staker");
        try jw.write(self.staker.slice());
        try jw.objectField("withdrawer");
        try jw.write(self.withdrawer.slice());
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L85
pub const UiLockup = struct {
    unix_timestamp: i64,
    epoch: u64,
    custodian: Pubkey.Base58String,

    pub fn jsonStringify(self: UiLockup, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("unixTimestamp");
        try jw.write(self.unix_timestamp);
        try jw.objectField("epoch");
        try jw.write(self.epoch);
        try jw.objectField("custodian");
        try jw.write(self.custodian.slice());
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L100
pub const UiStake = struct {
    delegation: UiDelegation,
    credits_observed: u64,

    pub fn jsonStringify(self: UiStake, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("delegation");
        try self.delegation.jsonStringify(jw);
        try jw.objectField("creditsObserved");
        try jw.write(self.credits_observed);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_stake.rs#L113
pub const UiDelegation = struct {
    voter: Pubkey.Base58String,
    stake: u64,
    activation_epoch: u64,
    deactivation_epoch: u64,
    warmup_cooldown_rate: f64,

    pub fn jsonStringify(self: UiDelegation, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("voter");
        try jw.write(self.voter.slice());
        try jw.objectField("stake");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.stake});
        try jw.objectField("activationEpoch");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.activation_epoch});
        try jw.objectField("deactivationEpoch");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.deactivation_epoch});
        try jw.objectField("warmupCooldownRate");
        try jw.write(self.warmup_cooldown_rate);
        try jw.endObject();
    }
};
