const Hash = @import("hash.zig").Hash;
const std = @import("std");
const HardForks = @import("hard_forks.zig").HardForks;
const Slot = @import("slot.zig").Slot;
const Allocator = std.mem.Allocator;
pub const ShredVersion = struct {
    value: u16,

    const Self = @This();

    pub fn init_manually_set(version: u16) Self {
        return Self{ .value = version };
    }

    pub fn version_from_hash(hash: *Hash) u16 {
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
    pub fn compute_shred_version(genesis_hash: Hash, hard_forks: ?HardForks, alloc: Allocator) u16 {
        var hash = genesis_hash;
        if (hard_forks != null) {
            for (hard_forks.?.get_forks()) |hard_fork| {
                var buf = [_]u8{0} ** 16;
                std.mem.writeIntLittle(u64, buf[0..8], hard_fork[0].value);
                std.mem.writeIntLittle(u64, buf[8..], @as(u64, hard_fork[1]));
                hash = Hash.extend_and_hash(genesis_hash, buf[0..], alloc) catch genesis_hash;
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
    var hard_forks = HardForks.default(testing_alloc);
    defer _ = hard_forks.deinit();
    try hard_forks.register(Slot.init(1));

    var shred_version = ShredVersion.compute_shred_version(Hash.default(), hard_forks, testing_alloc);
    try std.testing.expect(shred_version == 55551);

    std.debug.print("shred_version: {}\n", .{shred_version});

    try hard_forks.register(Slot.init(1));
    var shred_version_two = ShredVersion.compute_shred_version(Hash.default(), hard_forks, testing_alloc);
    try std.testing.expect(shred_version_two == 46353);

    std.debug.print("shred_version_two: {}\n", .{shred_version_two});
}
