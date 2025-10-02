const std = @import("std");
const sig = @import("../sig.zig");
const Hash = sig.core.Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn search(tree: []const []Hash, index: u64) *Hash {
    var search_index: usize = 0;
    for (tree) |slice| {
        if (search_index + slice.len > index) {
            const index_in_nested = index - search_index;
            return &slice[index_in_nested];
        } else {
            search_index += slice.len;
        }
    }
    unreachable;
}

pub fn computeMerkleRoot(tree: []const []Hash, fanout: usize) !Hash {
    var length: u64 = 0;
    for (tree) |level| length += level.len;

    if (length == 0) return comptime empty: {
        @setEvalBranchQuota(3187);
        var hasher = Sha256.init(.{});
        break :empty .{ .data = hasher.finalResult() };
    };

    while (true) {
        const chunks = try std.math.divCeil(usize, length, fanout);

        var index: usize = 0;
        for (0..chunks) |i| {
            const start = i * fanout;
            const end = @min(start + fanout, length);

            var hasher = Sha256.init(.{});
            for (start..end) |j| {
                const h = search(tree, j);
                hasher.update(&h.data);
            }
            const hash = hasher.finalResult();
            search(tree, index).data = hash;
            index += 1;
        }

        length = index;
        if (length == 1) return search(tree, 0).*;
    }
}

test "common.merkle_tree: test nested impl" {
    const init_length: usize = 10;
    var hashes: [init_length]Hash = undefined;
    for (&hashes, 0..) |*hash, i| hash.* = .{ .data = @splat(@intCast(i)) };

    const root = try computeMerkleRoot(&.{&hashes}, 3);
    const expected_root: [32]u8 = .{
        56, 239, 163, 39,  169, 252, 144, 195, 85,  228, 99,
        82, 225, 185, 237, 141, 186, 90,  36,  220, 86,  140,
        59, 47,  18,  172, 250, 231, 79,  178, 51,  100,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}

test "common.merkle_tree: test nested impl deeper" {
    var hashes: [4]Hash = undefined;
    for (&hashes, 0..) |*hash, i| hash.* = .{ .data = @splat(@intCast(i)) };

    var hashes2: [4]Hash = undefined;
    for (&hashes2, 4..) |*hash, i| hash.* = .{ .data = @splat(@intCast(i)) };

    var hashes3: [2]Hash = undefined;
    for (&hashes3, 8..) |*hash, i| hash.* = .{ .data = @splat(@intCast(i)) };

    const root = try computeMerkleRoot(&.{ &hashes, &hashes2, &hashes3 }, 3);
    const expected_root: [32]u8 = .{
        56,  239, 163, 39,  169, 252, 144, 195, 85,  228, 99, 82, 225,
        185, 237, 141, 186, 90,  36,  220, 86,  140, 59,  47, 18, 172,
        250, 231, 79,  178, 51,  100,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}
