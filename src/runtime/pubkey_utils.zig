const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

// TODO: Consider moving the below to the pubkey module

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L26
pub const MAX_SEED_LEN = 32;

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

/// Maps the `PubkeyError` to a `u8` to match Agave's `PubkeyError` enum.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L35
pub fn mapError(err: PubkeyError) u8 {
    return switch (err) {
        error.MaxSeedLenExceeded => 0,
        error.InvalidSeeds => 1,
        error.IllegalOwner => 2,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L200
pub fn createWithSeed(
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) PubkeyError!Pubkey {
    if (seed.len > MAX_SEED_LEN) return PubkeyError.MaxSeedLenExceeded;

    const offset = owner.data.len - PDA_MARKER.len;
    if (std.mem.eql(u8, owner.data[offset..], PDA_MARKER))
        return PubkeyError.IllegalOwner;

    return .{ .data = sig.core.Hash.initMany(&.{
        &base.data,
        seed,
        &owner.data,
    }).data };
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
    for (seeds) |seed| if (seed.len > MAX_SEED_LEN) {
        return PubkeyError.MaxSeedLenExceeded;
    };
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

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L289
pub fn bytesAreCurvePoint(bytes: []const u8) bool {
    const encoded_length = std.crypto.ecc.Edwards25519.encoded_length;
    if (encoded_length != bytes.len) return false;
    _ = std.crypto.ecc.Edwards25519.fromBytes(bytes[0..encoded_length].*) catch return false;
    return true;
}

test mapError {
    try std.testing.expectEqual(mapError(PubkeyError.MaxSeedLenExceeded), 0);
    try std.testing.expectEqual(mapError(PubkeyError.InvalidSeeds), 1);
    try std.testing.expectEqual(mapError(PubkeyError.IllegalOwner), 2);
}

// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/pubkey/src/lib.rs#L1336
test findProgramAddress {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

test createProgramAddress {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

test "bytesAreCurvePoint" {
    const bytes_on_curve: []const []const u8 = &.{ &.{
        184, 122, 70,  205, 215, 194, 55,  219,
        159, 56,  94,  18,  203, 78,  63,  11,
        107, 126, 107, 223, 96,  94,  9,   49,
        122, 31,  227, 26,  152, 243, 124, 42,
    }, &.{
        39,  213, 147, 248, 112, 167, 66,  184,
        142, 235, 171, 216, 255, 29,  177, 139,
        57,  136, 93,  197, 146, 244, 176, 247,
        83,  139, 174, 167, 38,  112, 156, 202,
    } };

    const bytes_off_curve: []const []const u8 = &.{ &.{
        184, 122, 70,  205, 215, 194, 55,  219,
        159, 56,  94,  18,  203, 78,  63,  11,
        107, 126, 107, 223, 96,  94,  9,   49,
        122, 31,  227, 26,  152, 243, 124, 0,
    }, &.{
        39,  213, 147, 248, 112, 167, 66,  184,
        142, 235, 171, 216, 255, 29,  177, 139,
        57,  136, 93,  197, 146, 244, 176, 247,
        83,  139, 174, 167, 38,  112, 156, 0,
    } };

    for (bytes_on_curve, bytes_off_curve) |on_curve, off_curve| {
        try std.testing.expect(bytesAreCurvePoint(on_curve));
        try std.testing.expect(!bytesAreCurvePoint(off_curve));
    }
}
