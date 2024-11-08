const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn merkleTreeHash(hashes: []Hash, fanout: usize) !*Hash {
    var length = hashes.len;
    if (length == 0) return error.EmptyHashList;

    while (true) {
        const chunks = try std.math.divCeil(usize, length, fanout);
        var index: usize = 0;
        for (0..chunks) |i| {
            const start = i * fanout;
            const end = @min(start + fanout, length);

            var hasher = Sha256.init(.{});
            for (start..end) |j| {
                hasher.update(&hashes[j].data);
            }
            const hash = hasher.finalResult();
            hashes[index] = Hash{ .data = hash };
            index += 1;
        }
        length = index;
        if (length == 1) {
            return &hashes[0];
        }
    }
}

pub fn NestedList(comptime T: type) type {
    return struct {
        items: []const []T,
        const Self = @This();

        pub fn getValue(self: *const Self, index: u64) *T {
            std.debug.assert(index < self.len());
            var search_index: usize = 0;
            for (self.items) |slice| {
                if (search_index + slice.len > index) {
                    const index_in_nested = index - search_index;
                    return &slice[index_in_nested];
                } else {
                    search_index += slice.len;
                }
            }
            unreachable;
        }

        pub fn getSlice(self: *const Self, index: u64, length: u64) []T {
            std.debug.assert(index < self.len());
            var search_index: usize = 0;
            for (self.items) |slice| {
                if (search_index + slice.len > index) {
                    const index_in_nested = index - search_index;
                    return slice[index_in_nested..][0..length];
                } else {
                    search_index += slice.len;
                }
            }
            unreachable;
        }

        pub fn len(self: *const Self) u64 {
            var length: u64 = 0;
            for (self.items) |*slice| {
                length += slice.len;
            }
            return length;
        }
    };
}

pub const NestedHashTree = NestedList(Hash);

pub fn computeMerkleRoot(self: *const NestedHashTree, fanout: usize) !*Hash {
    var length = self.len();
    if (length == 0) return error.EmptyHashList;

    while (true) {
        const chunks = try std.math.divCeil(usize, length, fanout);

        var index: usize = 0;
        for (0..chunks) |i| {
            const start = i * fanout;
            const end = @min(start + fanout, length);

            var hasher = Sha256.init(.{});
            for (start..end) |j| {
                const h = self.getValue(j);
                hasher.update(&h.data);
            }
            const hash = hasher.finalResult();
            self.getValue(index).data = hash;
            index += 1;
        }
        length = index;
        if (length == 1) {
            return self.getValue(0);
        }
    }
}

test "common.merkle_tree: test nested impl" {
    const init_length: usize = 10;
    var hashes: [init_length]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }
    const nested_hashes = NestedHashTree{
        .items = &.{&hashes},
    };

    const root = try computeMerkleRoot(&nested_hashes, 3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}

test "common.merkle_tree: test nested impl deeper" {
    var hashes: [4]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }

    var hashes2: [4]Hash = undefined;
    for (&hashes2, 4..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }

    var hashes3: [2]Hash = undefined;
    for (&hashes3, 8..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }

    const nested_hashes = NestedHashTree{
        .items = &.{ &hashes, &hashes2, &hashes3 },
    };

    const root = try computeMerkleRoot(&nested_hashes, 3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}

test "common.merkle_tree: test tree impl" {
    const init_length: usize = 10;
    var hashes: [init_length]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }

    const root = try merkleTreeHash(&hashes, 3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}
