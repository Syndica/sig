const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

// TODO: Consider moving the below to the pubkey module

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L26
const MAX_SEED_LEN = 32;

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L44-L45
pub const MAX_SEEDS: usize = 16;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L32
const PDA_MARKER = "ProgramDerivedAddress";

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L35
pub const PubkeyError = error{
    MaxSeedLenExceeded,
    InvalidSeeds,
    IllegalOwner,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L200
pub fn createWithSeed(
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) PubkeyError!Pubkey {
    if (seed.len > MAX_SEED_LEN) {
        return PubkeyError.MaxSeedLenExceeded;
    }

    const offset = owner.data.len - PDA_MARKER.len;
    if (std.mem.eql(u8, owner.data[offset..], PDA_MARKER))
        return PubkeyError.IllegalOwner;

    return .{
        .data = sig.runtime.tmp_utils.hashv(&.{ &base.data, seed, &owner.data }).data,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L633
pub fn findProgramAddress(
    seeds: []const []const u8,
    program_id: Pubkey,
) ?struct { Pubkey, u8 } {
    var bump_seed = [_]u8{std.math.maxInt(u8)};

    for (0..std.math.maxInt(u8)) |_| {
        defer bump_seed[0] -= 1;
        const derived_key = createProgramAddress(
            seeds,
            &bump_seed,
            program_id,
        ) catch |err| {
            switch (err) {
                PubkeyError.InvalidSeeds => continue,
                else => break,
            }
        };
        return .{ derived_key, bump_seed[0] };
    }

    return null;
}

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L721
pub fn createProgramAddress(
    seeds: []const []const u8,
    bump_seed: []const u8,
    program_id: Pubkey,
) PubkeyError!Pubkey {
    if (seeds.len + 1 > MAX_SEEDS) {
        return PubkeyError.MaxSeedLenExceeded;
    }

    for (seeds) |seed| {
        if (seed.len > MAX_SEED_LEN) return PubkeyError.MaxSeedLenExceeded;
    }

    if (bump_seed.len > MAX_SEED_LEN) {
        return PubkeyError.MaxSeedLenExceeded;
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (seeds) |seed| hasher.update(seed);
    hasher.update(bump_seed);
    hasher.update(&program_id.data);
    hasher.update(PDA_MARKER);
    const hash = hasher.finalResult();

    if (bytesAreCurvePoint(&hash)) {
        return PubkeyError.InvalidSeeds;
    }

    return .{ .data = hash };
}

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L289-L290
pub fn bytesAreCurvePoint(_: []const u8) bool {
    // TODO: Implement
    return false;
}

// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L1336
test "findProgramAddress" {
    var prng = std.Random.DefaultPrng.init(5083);
    for (0..1_000) |_| {
        const program_id = Pubkey.initRandom(prng.random());

        const derived_key, const bump_seed = findProgramAddress(
            &.{ "Lil'", "Bits" },
            program_id,
        ) orelse unreachable;

        try std.testing.expectEqual(
            derived_key,
            createProgramAddress(
                &.{ "Lil'", "Bits" },
                &.{bump_seed},
                program_id,
            ),
        );
    }
}
