const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const FeeCalculator = sig.runtime.sysvar.Fees.FeeCalculator;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L10-L11
const DURABLE_NONCE_HASH_PREFIX = "DURABLE_NONCE";

/// Current variants have durable nonce and blockhash domains separated.\
///
/// Must support `bincode` and `serializedSize` methods for writing to the account data.\
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/mod.rs#L12
pub const Versions = union(enum) {
    legacy: State,
    current: State,

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/51e1da20ab83511563bd400cb448c2fee4ac4db6/nonce/src/state.rs#L104
    pub const SERIALIZED_SIZE = 80;

    pub fn getState(self: Versions) State {
        switch (self) {
            .legacy => |state| return state,
            .current => |state| return state,
        }
    }

    pub fn verify(
        self: Versions,
        durable_nonce: Hash,
    ) ?Data {
        switch (self) {
            .legacy => |_| return null,
            .current => |state| switch (state) {
                .unintialized => return null,
                .initialized => |data| {
                    return if (durable_nonce.eql(data.durable_nonce)) data else null;
                },
            },
        }
    }

    pub fn upgrade(self: Versions) ?Versions {
        switch (self) {
            .legacy => |state| switch (state) {
                .unintialized => return null,
                .initialized => |data| {
                    var new_data = data;
                    new_data.durable_nonce = initDurableNonceFromHash(data.durable_nonce);
                    return Versions{ .current = .{ .initialized = new_data } };
                },
            },
            .current => |_| return null,
        }
    }
};

/// The state of a durable transaction nonce account.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L71
pub const State = union(enum) {
    unintialized,
    initialized: Data,
};

/// Initialized data of a durable transaction nonce account
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/nonce/state/current.rs#L19
pub const Data = struct {
    /// Address of the account that signs transactions using the nonce account.
    authority: Pubkey,
    /// Durable nonce value derived from a valid previous blockhash.
    durable_nonce: Hash,
    /// The fee calculator associated with the blockhash.
    fee_calculator: FeeCalculator,

    pub fn init(
        authority: Pubkey,
        durable_nonce: Hash,
        lamports_per_signature: u64,
    ) Data {
        return .{
            .authority = authority,
            .durable_nonce = durable_nonce,
            .fee_calculator = .{ .lamports_per_signature = lamports_per_signature },
        };
    }
};

pub fn initDurableNonceFromHash(blockhash: Hash) Hash {
    return sig.core.Hash.generateSha256(.{ DURABLE_NONCE_HASH_PREFIX, &blockhash.data });
}

test "verify_durable_nonce" {
    var prng = std.Random.DefaultPrng.init(0);

    const blockhash = Hash{ .data = [_]u8{171} ** 32 };

    {
        const versions = Versions{ .legacy = .unintialized };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
    }

    {
        const versions = Versions{ .current = .unintialized };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
    }

    {
        const durable_nonce = initDurableNonceFromHash(blockhash);
        const data = Data{
            .authority = Pubkey.initRandom(prng.random()),
            .durable_nonce = durable_nonce,
            .fee_calculator = FeeCalculator{ .lamports_per_signature = 2718 },
        };
        const versions = Versions{ .legacy = .{ .initialized = data } };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
        try std.testing.expectEqual(null, versions.verify(data.durable_nonce));
    }

    {
        const durable_nonce = initDurableNonceFromHash(blockhash);
        const data = Data{
            .authority = Pubkey.initRandom(prng.random()),
            .durable_nonce = durable_nonce,
            .fee_calculator = FeeCalculator{ .lamports_per_signature = 2718 },
        };
        const versions = Versions{ .current = .{ .initialized = data } };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
        try std.testing.expectEqual(data, versions.verify(data.durable_nonce));
    }
}

test "upgrade_nonce_version" {
    var prng = std.Random.DefaultPrng.init(0);

    {
        const versions = Versions{ .legacy = .unintialized };
        try std.testing.expectEqual(null, versions.upgrade());
    }

    {
        const blockhash = Hash{ .data = [_]u8{171} ** 32 };

        const initial_durable_nonce = initDurableNonceFromHash(blockhash);
        const initial_data = Data{
            .authority = Pubkey.initRandom(prng.random()),
            .durable_nonce = initial_durable_nonce,
            .fee_calculator = FeeCalculator{ .lamports_per_signature = 2718 },
        };

        const versions = Versions{ .legacy = .{ .initialized = initial_data } };
        const actual = versions.upgrade() orelse return error.UpgradeFailed;

        const expected_durable_nonce = initDurableNonceFromHash(initial_durable_nonce);
        const expected_data = Data{
            .authority = initial_data.authority,
            .durable_nonce = expected_durable_nonce,
            .fee_calculator = initial_data.fee_calculator,
        };
        const expected = Versions{ .current = .{ .initialized = expected_data } };

        try std.testing.expectEqual(expected, actual);
        try std.testing.expectEqual(null, actual.upgrade());
    }
}
