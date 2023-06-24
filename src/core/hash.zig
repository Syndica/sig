const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HASH_SIZE: usize = 32;

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
};
