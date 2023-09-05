/// ***ShredVersion***
/// Currently it's being manually set.
///
/// TODO: use bankforks to calculate shred version
/// ```
const Hash = @import("hash.zig").Hash;
const std = @import("std");
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
            for (chunk, accum[0..chunk.len]) |ch, *acc| {
                acc.* ^= ch;
            }
        }
        var version = (@as(u16, accum[0]) << 8) | accum[1];
        return version +| 1;
    }
};

test "computes version from raw hash" {
    var hash = Hash{ .data = [_]u8{ 180, 194, 54, 239, 216, 26, 164, 170, 3, 72, 104, 87, 32, 189, 12, 254, 9, 103, 99, 155, 117, 158, 241, 0, 95, 128, 64, 174, 42, 158, 205, 26 } };
    const version = ShredVersion.version_from_hash(&hash);
    try std.testing.expect(version == 44810);
}
