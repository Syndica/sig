const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const LEAF_PREFIX: [1]u8 = [_]u8{0};

pub const INTERMEDIATE_PREFIX: [1]u8 = [_]u8{1};

pub fn hash_leaf(digest: []const u8) Hash {
    const data = [_][]const u8{ LEAF_PREFIX[0..], digest[0..] };

    return hashv(&data);
}

pub fn hashv(vals: []const []const u8) Hash {
    var h = Sha256.init(.{});
    for (vals) |val| h.update(val);
    var hash: [32]u8 = undefined;
    h.final(&hash);
    return Hash{ .data = hash };
}

test "merkle-tree.hash_leaf: Hash a valid leaf" {
    const leaf = "Lorem Ipsum Dolor";
    var hashed_leaf = hash_leaf(leaf);
    std.debug.print("hashed_leaf: {}\n", .{hashed_leaf});
}
