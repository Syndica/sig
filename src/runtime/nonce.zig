const std = @import("std");
const shared_nonce = @import("shared").runtime.nonce;

const Hash = @import("../sig.zig").core.Hash;
const Pubkey = @import("../sig.zig").core.Pubkey;

pub const Versions = shared_nonce.Versions;
pub const State = shared_nonce.State;
pub const Data = shared_nonce.Data;
pub const initDurableNonceFromHash = shared_nonce.initDurableNonceFromHash;

test "verify_durable_nonce" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const blockhash: Hash = .{ .data = @splat(171) };

    {
        const versions = Versions{ .legacy = .uninitialized };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
    }

    {
        const versions = Versions{ .current = .uninitialized };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
    }

    {
        const durable_nonce = initDurableNonceFromHash(blockhash);
        const data = Data{
            .authority = Pubkey.initRandom(prng.random()),
            .durable_nonce = durable_nonce,
            .lamports_per_signature = 2718,
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
            .lamports_per_signature = 2718,
        };
        const versions = Versions{ .current = .{ .initialized = data } };
        try std.testing.expectEqual(null, versions.verify(blockhash));
        try std.testing.expectEqual(null, versions.verify(Hash.ZEROES));
        try std.testing.expectEqual(data, versions.verify(data.durable_nonce));
    }
}

test "upgrade_nonce_version" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    {
        const versions = Versions{ .legacy = .uninitialized };
        try std.testing.expectEqual(null, versions.upgrade());
    }

    {
        const blockhash: Hash = .{ .data = @splat(171) };

        const initial_durable_nonce = initDurableNonceFromHash(blockhash);
        const initial_data = Data{
            .authority = Pubkey.initRandom(prng.random()),
            .durable_nonce = initial_durable_nonce,
            .lamports_per_signature = 2718,
        };

        const versions = Versions{ .legacy = .{ .initialized = initial_data } };
        const actual = versions.upgrade() orelse return error.UpgradeFailed;

        const expected_durable_nonce = initDurableNonceFromHash(initial_durable_nonce);
        const expected_data = Data{
            .authority = initial_data.authority,
            .durable_nonce = expected_durable_nonce,
            .lamports_per_signature = initial_data.lamports_per_signature,
        };
        const expected = Versions{ .current = .{ .initialized = expected_data } };

        try std.testing.expectEqual(expected, actual);
        try std.testing.expectEqual(null, actual.upgrade());
    }
}
