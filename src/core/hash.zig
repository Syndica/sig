const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;
pub const HASH_SIZE: usize = 32;

pub const CompareResult = enum {
    Greater,
    Less,
    Equal,
};

pub const Hash = struct {
    data: [HASH_SIZE]u8,

    const Self = @This();

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** HASH_SIZE };
    }
    // used in tests
    pub fn random() Self {
        var seed = @as(u64, @intCast(std.time.milliTimestamp()));
        var rand = std.rand.DefaultPrng.init(seed);
        var data: [HASH_SIZE]u8 = undefined;

        for (0..HASH_SIZE) |i| {
            data[i] = rand.random().int(u8);
        }
        return Self{
            .data = data,
        };
    }

    pub fn generateSha256Hash(bytes: []const u8) Self {
        var hash = Hash{
            .data = undefined,
        };
        Sha256.hash(bytes, &hash.data, .{});
        return hash;
    }

    pub fn cmp(a: *const Self, b: *const Self) CompareResult {
        for (0..HASH_SIZE) |i| {
            if (a.data[i] > b.data[i]) {
                return CompareResult.Greater;
            } else if (a.data[i] < b.data[i]) {
                return CompareResult.Less;
            }
        }
        return CompareResult.Equal;
    }

    pub fn extend_and_hash(id: Hash, val: []u8, alloc: Allocator) !Self {
        var hash_data = try std.ArrayList(u8).initCapacity(alloc, val.len + id.data.len);
        defer hash_data.deinit();
        hash_data.appendSliceAssumeCapacity(id.data[0..]);
        try hash_data.appendSlice(val);
        const hash = generateSha256Hash(hash_data.items);
        return hash;
    }
};
