const Hash = @import("hash.zig").Hash;
const std = @import("std");
const HardForks = @import("hard_forks.zig").HardForks;
const Allocator = std.mem.Allocator;

pub const Nonce = u32;

pub const ShredVersion = struct {
    value: u16,

    const Self = @This();

    pub fn init_manually_set(version: u16) Self {
        return Self{ .value = version };
    }

    pub fn version_from_hash(hash: *const Hash) u16 {
        const hash_bytes = hash.data;
        var accum: [2]u8 = .{ 0, 0 };
        var chunks = std.mem.window(u8, &hash_bytes, 2, 2);

        while (chunks.next()) |chunk| {
            accum[0] ^= chunk[0];
            accum[1] ^= chunk[1];
        }
        var version = (@as(u16, accum[0]) << 8) | accum[1];
        return version +| 1;
    }

    pub fn compute_shred_version(alloc: Allocator, genesis_hash: Hash, maybe_hard_forks: ?HardForks) Allocator.Error!u16 {
        var hash = genesis_hash;
        if (maybe_hard_forks) |hard_forks| {
            var buf: [16]u8 = undefined;
            for (hard_forks.get_forks()) |hard_fork| {
                std.mem.writeIntLittle(u64, buf[0..8], hard_fork.slot);
                std.mem.writeIntLittle(u64, buf[8..], @as(u64, hard_fork.count));
                hash = try Hash.extend_and_hash(alloc, hash, &buf);
            }
        }
        return version_from_hash(&hash);
    }
};

test "core.shred: test ShredVersion" {
    var hash = Hash{ .data = [_]u8{ 180, 194, 54, 239, 216, 26, 164, 170, 3, 72, 104, 87, 32, 189, 12, 254, 9, 103, 99, 155, 117, 158, 241, 0, 95, 128, 64, 174, 42, 158, 205, 26 } };
    const version = ShredVersion.version_from_hash(&hash);
    try std.testing.expect(version == 44810);

    const testing_alloc = std.testing.allocator;

    var shred_version_one = try ShredVersion.compute_shred_version(testing_alloc, Hash.default(), null);
    try std.testing.expect(shred_version_one == 1);
    std.debug.print("shred_version_one: {}\n", .{shred_version_one});

    var hard_forks = HardForks.default(testing_alloc);
    defer _ = hard_forks.deinit();

    var shred_version_two = try ShredVersion.compute_shred_version(testing_alloc, Hash.default(), hard_forks);
    try std.testing.expect(shred_version_two == 1);
    std.debug.print("shred_version_two: {}\n", .{shred_version_two});

    try hard_forks.register(1);
    var shred_version_three = try ShredVersion.compute_shred_version(
        testing_alloc,
        Hash.default(),
        hard_forks,
    );
    try std.testing.expect(shred_version_three == 55551);
    std.debug.print("shred_version_three: {}\n", .{shred_version_three});

    try hard_forks.register(1);
    var shred_version_four = try ShredVersion.compute_shred_version(testing_alloc, Hash.default(), hard_forks);
    try std.testing.expect(shred_version_four == 46353);
    std.debug.print("shred_version_three: {}\n", .{shred_version_four});
}
