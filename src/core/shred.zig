const Hash = @import("hash.zig").Hash;
const std = @import("std");
const HardForks = @import("hard_forks.zig").HardForks;

pub const Nonce = u32;

pub const ShredVersion = struct {
    value: u16,

    const Self = @This();

    pub fn versionFromHash(hash: *const Hash) u16 {
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
            var buf: [16]u8 = undefined;
            for (hard_forks.get_forks()) |hard_fork| {
                std.mem.writeInt(u64, buf[0..8], hard_fork.slot, .little);
                std.mem.writeInt(u64, buf[8..], @as(u64, hard_fork.count), .little);
                hash = Hash.extendAndHash(hash, &buf);
            }
        }
        return versionFromHash(&hash);
    }
};

test "core.shred: test ShredVersion" {
    const Logger = @import("../trace/log.zig").Logger;
    const TestingLogger = @import("../trace/log.zig").TestingLogger;

    var hash = Hash{ .data = [_]u8{ 180, 194, 54, 239, 216, 26, 164, 170, 3, 72, 104, 87, 32, 189, 12, 254, 9, 103, 99, 155, 117, 158, 241, 0, 95, 128, 64, 174, 42, 158, 205, 26 } };
    const version = ShredVersion.versionFromHash(&hash);
    try std.testing.expect(version == 44810);

    const testing_alloc = std.testing.allocator;

    const test_logger = TestingLogger.init(.{
        .allocator = testing_alloc,
        .max_level = Logger.TEST_DEFAULT_LEVEL,
    });
    defer test_logger.deinit();

    const logger = test_logger.logger();

    const shred_version_one = ShredVersion.computeShredVersion(Hash.default(), null);
    try std.testing.expect(shred_version_one == 1);
    logger.debugf("shred_version_one: {}", .{shred_version_one});

    var hard_forks = HardForks.default(testing_alloc);
    defer _ = hard_forks.deinit();

    const shred_version_two = ShredVersion.computeShredVersion(Hash.default(), hard_forks);
    try std.testing.expect(shred_version_two == 1);
    logger.debugf("shred_version_two: {}", .{shred_version_two});

    try hard_forks.register(1);
    const shred_version_three = ShredVersion.computeShredVersion(Hash.default(), hard_forks);
    try std.testing.expect(shred_version_three == 55551);
    logger.debugf("shred_version_three: {}", .{shred_version_three});

    try hard_forks.register(1);
    const shred_version_four = ShredVersion.computeShredVersion(Hash.default(), hard_forks);
    try std.testing.expect(shred_version_four == 46353);
    logger.debugf("shred_version_three: {}", .{shred_version_four});
}
