const Hash = @import("hash.zig").Hash;
const std = @import("std");
const HardForks = @import("hard_forks.zig").HardForks;

pub const Nonce = u32;

pub const ShredVersion = struct {
    value: u16,

    pub fn versionFromHash(hash: Hash) u16 {
        const hash_bytes = hash.data;
        var accum: [2]u8 = .{ 0, 0 };
        var chunks = std.mem.window(u8, &hash_bytes, 2, 2);

        while (chunks.next()) |chunk| {
            accum[0] ^= chunk[0];
            accum[1] ^= chunk[1];
        }

        const version = (@as(u16, accum[0]) << 8) | accum[1];
        return version +| 1;
    }

    pub fn computeShredVersion(genesis_hash: Hash, maybe_hard_forks: ?HardForks) u16 {
        var hash = genesis_hash;
        if (maybe_hard_forks) |hard_forks| {
            for (hard_forks.forks.items) |*hard_fork| {
                hash = Hash.extendAndHash(
                    hash,
                    std.mem.asBytes(hard_fork),
                );
            }
        }
        return versionFromHash(hash);
    }
};

test ShredVersion {
    const allocator = std.testing.allocator;
    const hash: Hash = .{ .data = .{
        180, 194, 54, 239, 216, 26,  164, 170, 3,   72,  104, 87,
        32,  189, 12, 254, 9,   103, 99,  155, 117, 158, 241, 0,
        95,  128, 64, 174, 42,  158, 205, 26,
    } };
    const version = ShredVersion.versionFromHash(hash);
    try std.testing.expect(version == 44810);

    const shred_version_one = ShredVersion.computeShredVersion(Hash.ZEROES, null);
    try std.testing.expect(shred_version_one == 1);

    var hard_forks: HardForks = .{};
    defer _ = hard_forks.deinit(allocator);

    const shred_version_two = ShredVersion.computeShredVersion(Hash.ZEROES, hard_forks);
    try std.testing.expect(shred_version_two == 1);

    try hard_forks.register(allocator, 1);
    const shred_version_three = ShredVersion.computeShredVersion(Hash.ZEROES, hard_forks);
    try std.testing.expect(shred_version_three == 55551);

    try hard_forks.register(allocator, 1);
    const shred_version_four = ShredVersion.computeShredVersion(Hash.ZEROES, hard_forks);
    try std.testing.expect(shred_version_four == 46353);
}
