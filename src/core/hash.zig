const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HASH_SIZE: usize = 32;

pub const CompareResult = enum {
    Greater,
    Less,
    Equal,
};

pub const Hash = struct {
    data: [HASH_SIZE]u8,

    const Self = @This();

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
};
